//! The RAND layer (`RAND_bytes(3)`, `RAND_get0_primary(3)`, `RAND_set_DRBG_type(3)`,
//! `RAND_set_rand_method(3)`; `rand_lib.c`, `rand_meth.c`): each library context's DRBG
//! hierarchy, and the functions over it.
//!
//! As in OpenSSL, a context's random generators are made on first use: a seed source
//! (SEED-SRC, or what `RAND_set_seed_source_type` names), the primary DRBG under it
//! (CTR-DRBG over AES-256-CTR, or what `RAND_set_DRBG_type` names; reseeded every 256 requests
//! and every hour), and, per thread, a public and a private DRBG under the primary (every 65536
//! requests and every 7 minutes). `RAND_bytes` draws on the public one, `RAND_priv_bytes` on the
//! private one, unless a random provider was set (`RAND_set1_random_provider`, or a loaded
//! provider named as the context's random provider, `fips` by default, that offers
//! `random_bytes`), or an application's `RAND_METHOD` replaced the library's. A thread's DRBGs
//! are freed when it stops (`OPENSSL_thread_stop`, its context's `OPENSSL_thread_stop_ex`, or
//! its exit), a context's when it's freed. The seed source, once made, also gives the entropy
//! and nonces of the DRBGs without a parent (the core's `get_user_entropy` and
//! `get_user_nonce`).
//!
//! ENGINEs aren't supported: `RAND_set_rand_engine` takes only NULL (no ENGINE can be had).

use core::cell::{RefCell, UnsafeCell};
use core::ffi::{CStr, c_char, c_double, c_int, c_uchar, c_uint, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    ENGINE, ERR_LIB_EVP, ERR_LIB_RAND, EVP_R_UNABLE_TO_ENABLE_LOCKING, EVP_RAND_CTX,
    EVP_RAND_STATE_READY, OSSL_ALG_PARAM_MAC, OSSL_DRBG_PARAM_CIPHER, OSSL_DRBG_PARAM_DIGEST,
    OSSL_DRBG_PARAM_PROPERTIES, OSSL_DRBG_PARAM_RESEED_REQUESTS,
    OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, OSSL_DRBG_PARAM_USE_DF, OSSL_LIB_CTX, OSSL_PARAM,
    OSSL_PROV_RANDOM_PRIVATE, OSSL_PROV_RANDOM_PUBLIC, OSSL_PROVIDER, RAND_DRBG_STRENGTH,
    RAND_METHOD, RAND_R_ALREADY_INSTANTIATED, RAND_R_ERROR_INSTANTIATING_DRBG,
    RAND_R_FUNC_NOT_IMPLEMENTED, RAND_R_UNABLE_TO_CREATE_DRBG, RAND_R_UNABLE_TO_FETCH_DRBG,
};

use crate::err::{self, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::rand::{
    EVP_RAND_CTX_free, EVP_RAND_CTX_new, EVP_RAND_CTX_settable_params, EVP_RAND_CTX_up_ref,
    EVP_RAND_enable_locking, EVP_RAND_fetch, EVP_RAND_free, EVP_RAND_generate, EVP_RAND_get_state,
    EVP_RAND_instantiate, EVP_RAND_reseed,
};
use crate::ffi::{ffi_callback, ffi_export};
use crate::handle::Held;
use crate::libctx::{self, LibCtx};
use crate::params::{
    OSSL_PARAM_construct_int, OSSL_PARAM_construct_time_t, OSSL_PARAM_construct_uint,
    OSSL_PARAM_construct_utf8_string, OSSL_PARAM_locate_const, end,
};
use crate::provider::{OSSL_PROVIDER_get0_name, Ptr};

/// `PRIMARY_RESEED_INTERVAL` and `PRIMARY_RESEED_TIME_INTERVAL`.
const PRIMARY_RESEED: (c_uint, i64) = (1 << 8, 60 * 60);
/// `SECONDARY_RESEED_INTERVAL` and `SECONDARY_RESEED_TIME_INTERVAL`.
const SECONDARY_RESEED: (c_uint, i64) = (1 << 16, 7 * 60);

/// Numbers each context's generators, so a thread's never mix up two contexts (even one freed
/// and another made at its address).
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// `RAND_GLOBAL`'s settings and generators.
struct State {
    seed: Ptr<EVP_RAND_CTX>,
    primary: Ptr<EVP_RAND_CTX>,
    /// The random provider, without a reference (as in OpenSSL; it's dropped when unloaded).
    random_provider: Ptr<OSSL_PROVIDER>,
    random_provider_name: Option<CString>,
    rng_name: Option<CString>,
    rng_cipher: Option<CString>,
    rng_digest: Option<CString>,
    rng_propq: Option<CString>,
    seed_name: Option<CString>,
    seed_propq: Option<CString>,
}

/// A library context's RAND state (`RAND_GLOBAL`).
pub(crate) struct Global {
    id: u64,
    state: Mutex<State>,
}

impl Default for Global {
    fn default() -> Self {
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            state: Mutex::new(State {
                seed: Ptr(ptr::null_mut()),
                primary: Ptr(ptr::null_mut()),
                random_provider: Ptr(ptr::null_mut()),
                random_provider_name: Some(c"fips".to_owned()),
                rng_name: None,
                rng_cipher: None,
                rng_digest: None,
                rng_propq: None,
                seed_name: None,
                seed_propq: None,
            }),
        }
    }
}

impl Drop for Global {
    fn drop(&mut self) {
        self.release();
    }
}

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Global {
    /// Frees the context's generators as it goes ([`crate::handle::Handle::teardown`]), with
    /// no lock held: their providers' functions run.
    pub(crate) fn release(&self) {
        let (primary, seed) = {
            let mut s = self.lock();
            (
                core::mem::replace(&mut s.primary, Ptr(ptr::null_mut())),
                core::mem::replace(&mut s.seed, Ptr(ptr::null_mut())),
            )
        };
        // SAFETY: the generators this context held, or NULL.
        unsafe { EVP_RAND_CTX_free(primary.0) };
        // SAFETY: as above.
        unsafe { EVP_RAND_CTX_free(seed.0) };
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        guard(&self.state)
    }

    /// `ossl_rand_get0_seed_noncreating`, with a reference for the caller.
    fn seed_held(&self) -> *mut EVP_RAND_CTX {
        let seed = self.lock().seed.0;
        // SAFETY: the context's live seed source, or NULL.
        if !seed.is_null() && unsafe { EVP_RAND_CTX_up_ref(seed) } == 0 {
            return ptr::null_mut();
        }
        seed
    }
}

/// A context (NULL for the calling thread's default), held while used.
///
/// # Safety
/// `ctx` is NULL or a live library context.
unsafe fn context(ctx: *mut OSSL_LIB_CTX) -> Option<Held<OSSL_LIB_CTX>> {
    // SAFETY: the caller's guarantee.
    unsafe { libctx::resolve(ctx) }
}

/// The context a provider was loaded into: NULL is the global default (a provider's NULL
/// never means a thread's default).
pub(crate) fn provider_context(libctx: *mut OSSL_LIB_CTX) -> *mut OSSL_LIB_CTX {
    if libctx.is_null() {
        libctx::global()
    } else {
        libctx
    }
}

// -------------------------------------------------------------------------------------------
// Each thread's generators

/// A thread's public and private DRBGs of one context.
struct Local {
    id: u64,
    public: *mut EVP_RAND_CTX,
    private: *mut EVP_RAND_CTX,
    /// Whether a context's thread stop (`OPENSSL_thread_stop_ex`) frees them
    /// (`ossl_init_thread_start` registered `rand_delete_thread_state`): only once one was
    /// made by `RAND_get0_public`/`_private` while the other was unset. There, DRBGs only ever
    /// set with `RAND_set0_*` stay, as in OpenSSL.
    registered: bool,
}

/// A thread's DRBGs, freed when it exits.
struct Locals(Vec<Local>);

impl Drop for Locals {
    fn drop(&mut self) {
        for l in self.0.drain(..) {
            free_local(l);
        }
    }
}

/// `rand_delete_thread_state` for one context.
fn free_local(l: Local) {
    // SAFETY: the thread's generators, each with the reference it held.
    unsafe { EVP_RAND_CTX_free(l.public) };
    // SAFETY: as above.
    unsafe { EVP_RAND_CTX_free(l.private) };
}

thread_local! {
    static LOCALS: RefCell<Locals> = const { RefCell::new(Locals(Vec::new())) };
}

/// The thread's public (or private) DRBG of the context `id`, or NULL.
fn get_local(id: u64, private: bool) -> *mut EVP_RAND_CTX {
    LOCALS
        .try_with(|l| {
            l.borrow()
                .0
                .iter()
                .find(|x| x.id == id)
                .map_or(
                    ptr::null_mut(),
                    |x| if private { x.private } else { x.public },
                )
        })
        .unwrap_or(ptr::null_mut())
}

/// Sets the thread's public (or private) DRBG of the context `id`; returns the old one (the
/// caller frees it), or `None` if the thread is exiting.
fn set_local(id: u64, private: bool, rand: *mut EVP_RAND_CTX) -> Option<*mut EVP_RAND_CTX> {
    LOCALS
        .try_with(|l| {
            let mut l = l.borrow_mut();
            let at = match l.0.iter().position(|x| x.id == id) {
                Some(i) => i,
                None => {
                    l.0.push(Local {
                        id,
                        public: ptr::null_mut(),
                        private: ptr::null_mut(),
                        registered: false,
                    });
                    l.0.len() - 1
                }
            };
            l.0.get_mut(at).map(|x| {
                core::mem::replace(
                    if private {
                        &mut x.private
                    } else {
                        &mut x.public
                    },
                    rand,
                )
            })
        })
        .ok()
        .flatten()
}

/// `ossl_init_thread_start` with `rand_delete_thread_state`: the thread's stop will free its
/// DRBGs of the context `id`.
fn register(id: u64) {
    let _ = LOCALS.try_with(|l| {
        if let Some(x) = l.borrow_mut().0.iter_mut().find(|x| x.id == id) {
            x.registered = true;
        }
    });
}

/// The thread's stop: `OPENSSL_thread_stop_ex` (`id`) frees its DRBGs of that context whose
/// freeing was registered; `OPENSSL_thread_stop` (`None`) drops every one, of every context,
/// as 3.6 does (`CRYPTO_THREAD_clean_local` forgets the thread's values after the handlers run,
/// so a DRBG set with `RAND_set0_*` goes too; 3.6 leaks the thread's reference to it, which
/// rustyssl releases).
pub(crate) fn stop_thread(id: Option<u64>) {
    let taken: Vec<Local> = LOCALS
        .try_with(|l| {
            let mut l = l.borrow_mut();
            let (gone, kept): (Vec<Local>, Vec<Local>) =
                l.0.drain(..)
                    .partition(|x| id.is_none_or(|i| x.registered && i == x.id));
            l.0 = kept;
            gone
        })
        .unwrap_or_default();
    for l in taken {
        free_local(l);
    }
}

/// The context's id, for `OPENSSL_thread_stop_ex` and `OSSL_LIB_CTX_free`.
pub(crate) fn id_of(ctx: &LibCtx) -> u64 {
    ctx.rand.id
}

// -------------------------------------------------------------------------------------------
// The hierarchy

/// A setting as a C string, or NULL.
fn c(s: Option<&CString>) -> *const c_char {
    s.map_or(ptr::null(), |s| s.as_ptr())
}

/// `rand_new_seed`: the seed source, instantiated.
fn new_seed(libctx: *mut OSSL_LIB_CTX, g: &Global) -> *mut EVP_RAND_CTX {
    let (name, propq) = {
        let s = g.lock();
        (
            s.seed_name
                .clone()
                .unwrap_or_else(|| c"SEED-SRC".to_owned()),
            s.seed_propq.clone(),
        )
    };
    // SAFETY: the context; the name and query.
    let rand = unsafe { EVP_RAND_fetch(libctx, name.as_ptr(), c(propq.as_ref())) };
    if rand.is_null() {
        err::raise(ERR_LIB_RAND, RAND_R_UNABLE_TO_FETCH_DRBG, "rand_new_seed");
        return ptr::null_mut();
    }
    // SAFETY: the method just fetched.
    let ctx = unsafe { EVP_RAND_CTX_new(rand, ptr::null_mut()) };
    // SAFETY: as above.
    unsafe { EVP_RAND_free(rand) };
    if ctx.is_null() {
        err::raise(ERR_LIB_RAND, RAND_R_UNABLE_TO_CREATE_DRBG, "rand_new_seed");
        return ptr::null_mut();
    }
    // SAFETY: the context just made.
    if unsafe { EVP_RAND_instantiate(ctx, 0, 0, ptr::null(), 0, ptr::null()) } == 0 {
        err::raise(
            ERR_LIB_RAND,
            RAND_R_ERROR_INSTANTIATING_DRBG,
            "rand_new_seed",
        );
        // SAFETY: as above.
        unsafe { EVP_RAND_CTX_free(ctx) };
        return ptr::null_mut();
    }
    ctx
}

/// `rand_new_drbg`: a DRBG of the context's type under `parent`, instantiated with the
/// context's cipher, digest, and query and the reseed intervals.
fn new_drbg(
    libctx: *mut OSSL_LIB_CTX,
    g: &Global,
    parent: *mut EVP_RAND_CTX,
    reseed: (c_uint, i64),
) -> *mut EVP_RAND_CTX {
    const F: &str = "rand_new_drbg";
    let (name, cipher, digest, propq) = {
        let s = g.lock();
        (
            s.rng_name.clone().unwrap_or_else(|| c"CTR-DRBG".to_owned()),
            s.rng_cipher.clone(),
            s.rng_digest.clone(),
            s.rng_propq.clone(),
        )
    };
    // SAFETY: the context; the name and query.
    let rand = unsafe { EVP_RAND_fetch(libctx, name.as_ptr(), c(propq.as_ref())) };
    if rand.is_null() {
        err::raise(ERR_LIB_RAND, RAND_R_UNABLE_TO_FETCH_DRBG, F);
        return ptr::null_mut();
    }
    // SAFETY: the method just fetched; the caller's parent.
    let ctx = unsafe { EVP_RAND_CTX_new(rand, parent) };
    // SAFETY: as above.
    unsafe { EVP_RAND_free(rand) };
    if ctx.is_null() {
        err::raise(ERR_LIB_RAND, RAND_R_UNABLE_TO_CREATE_DRBG, F);
        return ptr::null_mut();
    }
    // SAFETY: the context just made.
    let settables = unsafe { EVP_RAND_CTX_settable_params(ctx) };
    let settable = |key: &CStr| {
        // SAFETY: the algorithm's list (or NULL); a static key.
        !unsafe { OSSL_PARAM_locate_const(settables, key.as_ptr()) }.is_null()
    };
    let default_cipher = c"AES-256-CTR";
    let (mut use_df, mut interval, mut time): (c_int, c_uint, libc::time_t) =
        (1, reseed.0, reseed.1);
    let mut params: Vec<OSSL_PARAM> = Vec::with_capacity(9);
    let utf8 = |key: &CStr, value: *const c_char| {
        // SAFETY: a static key; a string that outlives the instantiation.
        unsafe { OSSL_PARAM_construct_utf8_string(key.as_ptr(), value.cast_mut(), 0) }
    };
    if settable(OSSL_DRBG_PARAM_CIPHER) {
        params.push(utf8(
            OSSL_DRBG_PARAM_CIPHER,
            cipher
                .as_ref()
                .map_or(default_cipher.as_ptr(), |s| s.as_ptr()),
        ));
    }
    if digest.is_some() && settable(OSSL_DRBG_PARAM_DIGEST) {
        params.push(utf8(OSSL_DRBG_PARAM_DIGEST, c(digest.as_ref())));
    }
    if propq.is_some() {
        params.push(utf8(OSSL_DRBG_PARAM_PROPERTIES, c(propq.as_ref())));
    }
    if settable(OSSL_ALG_PARAM_MAC) {
        params.push(utf8(OSSL_ALG_PARAM_MAC, c"HMAC".as_ptr()));
    }
    if settable(OSSL_DRBG_PARAM_USE_DF) {
        // SAFETY: a static key; a local that outlives the instantiation.
        params.push(unsafe {
            OSSL_PARAM_construct_int(OSSL_DRBG_PARAM_USE_DF.as_ptr(), &raw mut use_df)
        });
    }
    // SAFETY: as above.
    params.push(unsafe {
        OSSL_PARAM_construct_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS.as_ptr(), &raw mut interval)
    });
    // SAFETY: as above.
    params.push(unsafe {
        OSSL_PARAM_construct_time_t(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL.as_ptr(), &raw mut time)
    });
    params.push(end());
    // SAFETY: the context; the parameters above.
    if unsafe { EVP_RAND_instantiate(ctx, 0, 0, ptr::null(), 0, params.as_ptr()) } == 0 {
        err::raise(ERR_LIB_RAND, RAND_R_ERROR_INSTANTIATING_DRBG, F);
        // SAFETY: as above.
        unsafe { EVP_RAND_CTX_free(ctx) };
        return ptr::null_mut();
    }
    ctx
}

/// `rand_get0_primary`: the primary DRBG, made (with the seed source, if it can be) on first
/// use.
fn get0_primary(libctx: *mut OSSL_LIB_CTX, g: &Global) -> *mut EVP_RAND_CTX {
    let (ret, mut seed) = {
        let s = g.lock();
        (s.primary.0, s.seed.0)
    };
    if !ret.is_null() {
        return ret;
    }
    let mut newseed = ptr::null_mut();
    if seed.is_null() {
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        newseed = new_seed(libctx, g);
        seed = newseed;
        // SAFETY: the mark set above.
        unsafe { ERR_pop_to_mark() };
    }
    let mut ret = new_drbg(libctx, g, seed, PRIMARY_RESEED);
    // SAFETY: the DRBG just made, or NULL.
    if ret.is_null() || unsafe { EVP_RAND_enable_locking(ret) } == 0 {
        if !ret.is_null() {
            err::raise(
                ERR_LIB_EVP,
                EVP_R_UNABLE_TO_ENABLE_LOCKING,
                "rand_get0_primary",
            );
            // SAFETY: as above.
            unsafe { EVP_RAND_CTX_free(ret) };
        }
        if newseed.is_null() {
            return ptr::null_mut();
        }
        ret = ptr::null_mut();
    }
    let mut s = g.lock();
    if !s.primary.0.is_null() {
        let primary = s.primary.0;
        drop(s);
        // SAFETY: the generators made here, which another thread beat.
        unsafe { EVP_RAND_CTX_free(ret) };
        // SAFETY: as above.
        unsafe { EVP_RAND_CTX_free(newseed) };
        return primary;
    }
    if !newseed.is_null() {
        s.seed = Ptr(newseed);
    }
    s.primary = Ptr(ret);
    ret
}

/// `rand_get0_public`/`rand_get0_private`: the thread's DRBG, made under the primary on first
/// use.
fn get0_local(libctx: *mut OSSL_LIB_CTX, g: &Global, private: bool) -> *mut EVP_RAND_CTX {
    let rand = get_local(g.id, private);
    if !rand.is_null() {
        return rand;
    }
    let primary = get0_primary(libctx, g);
    if primary.is_null() {
        return ptr::null_mut();
    }
    let other_unset = get_local(g.id, !private).is_null();
    let rand = new_drbg(libctx, g, primary, SECONDARY_RESEED);
    match set_local(g.id, private, rand) {
        Some(old) => {
            // SAFETY: the old one (NULL, as there was none).
            unsafe { EVP_RAND_CTX_free(old) };
            if other_unset {
                register(g.id);
            }
            rand
        }
        None => {
            // SAFETY: the DRBG made here, which the exiting thread can't keep.
            unsafe { EVP_RAND_CTX_free(rand) };
            ptr::null_mut()
        }
    }
}

/// Runs `f` with the context's RAND state (NULL for the default context).
///
/// # Safety
/// `ctx` is NULL or a live library context.
unsafe fn with_global<R>(
    ctx: *mut OSSL_LIB_CTX,
    failure: R,
    f: impl FnOnce(*mut OSSL_LIB_CTX, &Global) -> R,
) -> R {
    // SAFETY: the caller's guarantee.
    let Some(held) = (unsafe { context(ctx) }) else {
        return failure;
    };
    let concrete = if ctx.is_null() {
        libctx::current()
    } else {
        ctx
    };
    f(concrete, &held.rand)
}

ffi_export! {
    /// The context's primary DRBG (made on first use); NULL if it can't be made.
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context.
    pub unsafe extern "C" fn RAND_get0_primary(ctx: *mut OSSL_LIB_CTX) -> *mut EVP_RAND_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_RAND
    {
        // SAFETY: the caller's guarantee.
        unsafe { with_global(ctx, ptr::null_mut(), get0_primary) }
    }
}

ffi_export! {
    /// The calling thread's public DRBG of the context (made on first use).
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context.
    pub unsafe extern "C" fn RAND_get0_public(ctx: *mut OSSL_LIB_CTX) -> *mut EVP_RAND_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_RAND
    {
        // SAFETY: the caller's guarantee.
        unsafe { with_global(ctx, ptr::null_mut(), |l, g| get0_local(l, g, false)) }
    }
}

ffi_export! {
    /// The calling thread's private DRBG of the context (made on first use).
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context.
    pub unsafe extern "C" fn RAND_get0_private(ctx: *mut OSSL_LIB_CTX) -> *mut EVP_RAND_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_RAND
    {
        // SAFETY: the caller's guarantee.
        unsafe { with_global(ctx, ptr::null_mut(), |l, g| get0_local(l, g, true)) }
    }
}

/// `RAND_set0_public`/`RAND_set0_private`: the thread's DRBG replaced (the old one freed).
///
/// # Safety
/// `ctx` is NULL or a live library context; `rand` is NULL or a random context whose reference
/// the thread takes.
unsafe fn set0(ctx: *mut OSSL_LIB_CTX, rand: *mut EVP_RAND_CTX, private: bool) -> c_int {
    let set = |_: *mut OSSL_LIB_CTX, g: &Global| match set_local(g.id, private, rand) {
        Some(old) => {
            // SAFETY: the thread's old DRBG, with the reference it held.
            unsafe { EVP_RAND_CTX_free(old) };
            1
        }
        None => 0,
    };
    // SAFETY: the caller's guarantee.
    unsafe { with_global(ctx, 0, set) }
}

ffi_export! {
    /// Makes `rand` the calling thread's public DRBG of the context, taking its reference (the
    /// one before is freed). Returns 1, or 0 for a context that can't be had.
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context; `rand` is NULL or a random context.
    pub unsafe extern "C" fn RAND_set0_public(ctx: *mut OSSL_LIB_CTX, rand: *mut EVP_RAND_CTX) -> c_int
    where failure = 0, library = ERR_LIB_RAND
    {
        // SAFETY: the caller's guarantee.
        unsafe { set0(ctx, rand, false) }
    }
}

ffi_export! {
    /// Makes `rand` the calling thread's private DRBG of the context, as `RAND_set0_public`.
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context; `rand` is NULL or a random context.
    pub unsafe extern "C" fn RAND_set0_private(ctx: *mut OSSL_LIB_CTX, rand: *mut EVP_RAND_CTX) -> c_int
    where failure = 0, library = ERR_LIB_RAND
    {
        // SAFETY: the caller's guarantee.
        unsafe { set0(ctx, rand, true) }
    }
}

/// A C string argument copied, `None` for NULL.
///
/// # Safety
/// `s` is NULL or a string.
unsafe fn owned(s: *const c_char) -> Option<CString> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) }.to_owned())
}

/// A setting the configuration's `random` section names.
#[derive(Clone, Copy)]
pub(crate) enum ConfSetting {
    /// `random`: the generator's name.
    Random,
    /// `cipher`.
    Cipher,
    /// `digest`.
    Digest,
    /// `properties`.
    Properties,
    /// `seed`: the seed source's name.
    Seed,
    /// `seed_properties`.
    SeedProperties,
    /// `random_provider`, for a provider not loaded.
    RandomProviderName,
}

/// `random_set_string` (or `set_random_provider_name`) for the configuration: sets the
/// context's setting to `value`, whether or not its generators exist yet. False without a
/// context.
///
/// # Safety
/// `ctx` is NULL or a live library context.
pub(crate) unsafe fn set_from_conf(
    ctx: *mut OSSL_LIB_CTX,
    setting: ConfSetting,
    value: &CStr,
) -> bool {
    let value = value.to_owned();
    // SAFETY: the caller's guarantee.
    unsafe {
        with_global(ctx, false, |_, g| {
            let mut s = g.lock();
            let slot = match setting {
                ConfSetting::Random => &mut s.rng_name,
                ConfSetting::Cipher => &mut s.rng_cipher,
                ConfSetting::Digest => &mut s.rng_digest,
                ConfSetting::Properties => &mut s.rng_propq,
                ConfSetting::Seed => &mut s.seed_name,
                ConfSetting::SeedProperties => &mut s.seed_propq,
                ConfSetting::RandomProviderName => {
                    let same = s
                        .random_provider_name
                        .as_ref()
                        .is_some_and(|n| n.as_bytes().eq_ignore_ascii_case(value.as_bytes()));
                    if !same {
                        s.random_provider_name = Some(value);
                    }
                    return true;
                }
            };
            *slot = Some(value);
            true
        })
    }
}

ffi_export! {
    /// Sets the DRBG type, query, cipher, and digest the context's DRBGs are made with: 0 with
    /// `RAND_R_ALREADY_INSTANTIATED` once its primary exists.
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context; the strings are NULL or strings.
    pub unsafe extern "C" fn RAND_set_DRBG_type(ctx: *mut OSSL_LIB_CTX, drbg: *const c_char, propq: *const c_char, cipher: *const c_char, digest: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_RAND
    {
        // SAFETY: the caller's guarantee.
        let drbg = unsafe { owned(drbg) };
        // SAFETY: as above.
        let propq = unsafe { owned(propq) };
        // SAFETY: as above.
        let cipher = unsafe { owned(cipher) };
        // SAFETY: as above.
        let digest = unsafe { owned(digest) };
        let set = |_: *mut OSSL_LIB_CTX, g: &Global| {
            let mut s = g.lock();
            if !s.primary.0.is_null() {
                err::raise(ERR_LIB_RAND, RAND_R_ALREADY_INSTANTIATED, "RAND_set_DRBG_type");
                return 0;
            }
            (s.rng_name, s.rng_propq, s.rng_cipher, s.rng_digest) = (drbg, propq, cipher, digest);
            1
        };
        // SAFETY: the caller's guarantee.
        unsafe { with_global(ctx, 0, set) }
    }
}

ffi_export! {
    /// Sets the seed source the context's primary DRBG is made over: 0 with
    /// `RAND_R_ALREADY_INSTANTIATED` once it exists.
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context; the strings are NULL or strings.
    pub unsafe extern "C" fn RAND_set_seed_source_type(ctx: *mut OSSL_LIB_CTX, seed: *const c_char, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_RAND
    {
        // SAFETY: the caller's guarantee.
        let seed = unsafe { owned(seed) };
        // SAFETY: as above.
        let propq = unsafe { owned(propq) };
        let set = |_: *mut OSSL_LIB_CTX, g: &Global| {
            let mut s = g.lock();
            if !s.seed.0.is_null() {
                err::raise(ERR_LIB_RAND, RAND_R_ALREADY_INSTANTIATED, "RAND_set_seed_source_type");
                return 0;
            }
            (s.seed_name, s.seed_propq) = (seed, propq);
            1
        };
        // SAFETY: the caller's guarantee.
        unsafe { with_global(ctx, 0, set) }
    }
}

ffi_export! {
    /// Makes `prov` the context's random provider (its `random_bytes` serves `RAND_bytes` and
    /// `RAND_priv_bytes`); NULL goes back to the DRBGs, and to no provider name.
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context; `prov` is NULL or a live provider.
    pub unsafe extern "C" fn RAND_set1_random_provider(ctx: *mut OSSL_LIB_CTX, prov: *mut OSSL_PROVIDER) -> c_int
    where failure = 0, library = ERR_LIB_RAND
    {
        let name = if prov.is_null() {
            None
        } else {
            // SAFETY: the caller's guarantee.
            let n = unsafe { OSSL_PROVIDER_get0_name(prov) };
            // SAFETY: the provider's name, a string, or NULL.
            Some(unsafe { owned(n) })
        };
        // SAFETY: the caller's guarantee.
        unsafe {
            with_global(ctx, 0, |_, g| {
                let mut s = g.lock();
                match name {
                    None => {
                        s.random_provider_name = None;
                        s.random_provider = Ptr(ptr::null_mut());
                    }
                    Some(_) if s.random_provider.0 == prov => {}
                    Some(n) => {
                        let same = match (&s.random_provider_name, &n) {
                            (Some(a), Some(b)) => a.as_bytes().eq_ignore_ascii_case(b.as_bytes()),
                            _ => false,
                        };
                        if !same {
                            s.random_provider_name = n;
                        }
                        s.random_provider = Ptr(prov);
                    }
                }
                1
            })
        }
    }
}

/// `ossl_rand_check_random_provider_on_load`: a provider loaded under the context's random
/// provider name becomes its random provider.
pub(crate) fn check_random_provider_on_load(
    libctx: *mut OSSL_LIB_CTX,
    prov: *mut OSSL_PROVIDER,
) -> bool {
    // SAFETY: a live provider's context.
    let Some(held) = (unsafe { context(provider_context(libctx)) }) else {
        return false;
    };
    let mut s = held.rand.lock();
    if s.random_provider_name.is_none() || !s.random_provider.0.is_null() {
        return true;
    }
    // SAFETY: a live provider.
    let n = unsafe { OSSL_PROVIDER_get0_name(prov) };
    // SAFETY: its name.
    let name = (!n.is_null()).then(|| unsafe { CStr::from_ptr(n) });
    if name.is_some_and(|n| s.random_provider_name.as_deref() == Some(n)) {
        s.random_provider = Ptr(prov);
    }
    true
}

/// `ossl_rand_check_random_provider_on_unload`.
pub(crate) fn check_random_provider_on_unload(libctx: *mut OSSL_LIB_CTX, prov: *mut OSSL_PROVIDER) {
    // SAFETY: a live provider's context.
    if let Some(held) = unsafe { context(provider_context(libctx)) } {
        let mut s = held.rand.lock();
        if s.random_provider.0 == prov {
            s.random_provider = Ptr(ptr::null_mut());
        }
    }
}

/// The seed source of the context a provider was loaded into, with a reference, or NULL.
pub(crate) fn seed_of(libctx: *mut OSSL_LIB_CTX) -> *mut EVP_RAND_CTX {
    // SAFETY: a live provider's context.
    unsafe { context(provider_context(libctx)) }.map_or(ptr::null_mut(), |h| h.rand.seed_held())
}

// -------------------------------------------------------------------------------------------
// The library's RAND_METHOD and the application's

/// A `RAND_METHOD` the application may write to, as OpenSSL's `ossl_rand_meth` is writable.
struct MethodCell(UnsafeCell<RAND_METHOD>);

// SAFETY: the table holds function pointers; writes are the application's, as in OpenSSL.
unsafe impl Sync for MethodCell {}

ffi_callback! {
    /// `drbg_add`: the primary DRBG reseeded with the octets as additional input.
    ///
    /// # Safety
    /// `buf` holds `num` octets.
    pub(crate) unsafe extern "C" fn drbg_add(buf: *const c_void, num: c_int, _randomness: c_double) -> c_int
    where failure = 0, library = ERR_LIB_RAND
    {
        // SAFETY: the default context.
        let drbg = unsafe { RAND_get0_primary(ptr::null_mut()) };
        let Ok(n) = usize::try_from(num) else { return 0 };
        if drbg.is_null() || n == 0 {
            return 0;
        }
        // SAFETY: the primary DRBG; the caller's octets.
        unsafe { EVP_RAND_reseed(drbg, 0, ptr::null(), 0, buf.cast(), n) }
    }
}

ffi_callback! {
    /// `drbg_seed`: as `drbg_add`.
    ///
    /// # Safety
    /// `buf` holds `num` octets.
    pub(crate) unsafe extern "C" fn drbg_seed(buf: *const c_void, num: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RAND
    {
        // SAFETY: the caller's guarantee.
        unsafe { drbg_add(buf, num, f64::from(num)) }
    }
}

ffi_callback! {
    /// `drbg_status`: whether the primary DRBG is ready.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn drbg_status() -> c_int
    where failure = 0, library = ERR_LIB_RAND
    {
        // SAFETY: the default context.
        let drbg = unsafe { RAND_get0_primary(ptr::null_mut()) };
        // SAFETY: the primary DRBG.
        c_int::from(!drbg.is_null() && unsafe { EVP_RAND_get_state(drbg) } == EVP_RAND_STATE_READY as c_int)
    }
}

ffi_callback! {
    /// `drbg_bytes`: the public DRBG's output. A negative count fails (the reference generates
    /// the huge length it converts to; docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `out` has room for `count` octets.
    pub(crate) unsafe extern "C" fn drbg_bytes(out: *mut c_uchar, count: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RAND
    {
        let Ok(n) = usize::try_from(count) else { return 0 };
        // SAFETY: the default context.
        let drbg = unsafe { RAND_get0_public(ptr::null_mut()) };
        if drbg.is_null() {
            return 0;
        }
        // SAFETY: the public DRBG; the caller's room.
        unsafe { EVP_RAND_generate(drbg, out, n, 0, 0, ptr::null(), 0) }
    }
}

/// `ossl_rand_meth`.
static OPENSSL_METH: MethodCell = MethodCell(UnsafeCell::new(RAND_METHOD {
    seed: Some(drbg_seed),
    bytes: Some(drbg_bytes),
    cleanup: None,
    add: Some(drbg_add),
    pseudorand: Some(drbg_bytes),
    status: Some(drbg_status),
}));

/// `default_RAND_meth`: the application's method, or NULL for the library's.
static DEFAULT_METH: AtomicPtr<RAND_METHOD> = AtomicPtr::new(ptr::null_mut());

fn openssl_meth() -> *mut RAND_METHOD {
    OPENSSL_METH.0.get()
}

/// `RAND_get_rand_method`'s result: the method in force.
fn method() -> *const RAND_METHOD {
    let m = DEFAULT_METH.load(Ordering::Acquire);
    if m.is_null() { openssl_meth() } else { m }
}

/// The method in force, if it isn't the library's.
fn other_method<'a>() -> Option<&'a RAND_METHOD> {
    let m = method();
    if ptr::eq(m, openssl_meth()) {
        return None;
    }
    // SAFETY: the application's method, which it keeps valid while it's set.
    unsafe { m.as_ref() }
}

/// The method in force, the library's too.
fn any_method<'a>() -> Option<&'a RAND_METHOD> {
    // SAFETY: the library's static table, or the application's method, kept valid while set.
    unsafe { method().as_ref() }
}

ffi_export! {
    /// The library's `RAND_METHOD` (over the DRBGs).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn RAND_OpenSSL() -> *mut RAND_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_RAND
    {
        openssl_meth()
    }
}

ffi_export! {
    /// The `RAND_METHOD` in force: the application's, or the library's.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn RAND_get_rand_method() -> *const RAND_METHOD
    where failure = ptr::null(), library = ERR_LIB_RAND
    {
        method()
    }
}

ffi_export! {
    /// Makes `meth` the method `RAND_*` use (NULL goes back to the library's). Returns 1.
    ///
    /// # Safety
    /// `meth` is NULL or a method the application keeps valid while it's set.
    pub unsafe extern "C" fn RAND_set_rand_method(meth: *const RAND_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_RAND
    {
        DEFAULT_METH.store(meth.cast_mut(), Ordering::Release);
        1
    }
}

ffi_export! {
    /// With NULL, goes back to the library's method and returns 1. An ENGINE fails (0): none
    /// can be had, as rustyssl has no ENGINE support.
    ///
    /// # Safety
    /// `engine` is NULL.
    pub unsafe extern "C" fn RAND_set_rand_engine(engine: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_RAND
    {
        if !engine.is_null() {
            return 0;
        }
        DEFAULT_METH.store(ptr::null_mut(), Ordering::Release);
        1
    }
}

/// `ossl_rand_cleanup_int`: the method's `cleanup`, then the library's method again; and the
/// default context's generators freed (`OPENSSL_cleanup`).
pub(crate) fn cleanup() {
    if let Some(cleanup) = any_method().and_then(|m| m.cleanup) {
        // SAFETY: the method's function.
        unsafe { cleanup() };
    }
    DEFAULT_METH.store(ptr::null_mut(), Ordering::Release);
    // SAFETY: the global context is never freed.
    if let Some(g) = unsafe { context(libctx::global()) } {
        let (primary, seed) = {
            let mut s = g.rand.lock();
            (
                core::mem::replace(&mut s.primary, Ptr(ptr::null_mut())),
                core::mem::replace(&mut s.seed, Ptr(ptr::null_mut())),
            )
        };
        // SAFETY: the generators the context held.
        unsafe { EVP_RAND_CTX_free(primary.0) };
        // SAFETY: as above.
        unsafe { EVP_RAND_CTX_free(seed.0) };
    }
}

// -------------------------------------------------------------------------------------------
// RAND_bytes and the rest

/// `RAND_bytes_ex`/`RAND_priv_bytes_ex`.
///
/// # Safety
/// `ctx` is NULL or a live library context; `buf` has room for `num` octets.
unsafe fn bytes_ex(
    ctx: *mut OSSL_LIB_CTX,
    buf: *mut c_uchar,
    num: usize,
    strength: c_uint,
    private: bool,
) -> c_int {
    if let Some(m) = other_method() {
        let Some(bytes) = m.bytes else {
            err::raise(
                ERR_LIB_RAND,
                RAND_R_FUNC_NOT_IMPLEMENTED,
                if private {
                    "RAND_priv_bytes_ex"
                } else {
                    "RAND_bytes_ex"
                },
            );
            return -1;
        };
        // The reference passes the length as an `int`; one past `INT_MAX` fails here.
        let Ok(n) = c_int::try_from(num) else {
            return 0;
        };
        // SAFETY: the application's method with the caller's buffer.
        return unsafe { bytes(buf, n) };
    }
    let generate = |l: *mut OSSL_LIB_CTX, g: &Global| {
        let prov = g.lock().random_provider.0;
        if !prov.is_null() {
            let which = if private {
                OSSL_PROV_RANDOM_PRIVATE
            } else {
                OSSL_PROV_RANDOM_PUBLIC
            };
            // SAFETY: the context's random provider; the caller's room.
            return unsafe {
                crate::provider::random_bytes(prov, which, buf.cast(), num, strength)
            };
        }
        let rand = get0_local(l, g, private);
        if rand.is_null() {
            return 0;
        }
        // SAFETY: the thread's DRBG; the caller's room.
        unsafe { EVP_RAND_generate(rand, buf, num, strength, 0, ptr::null(), 0) }
    };
    // SAFETY: the caller's guarantee.
    unsafe { with_global(ctx, 0, generate) }
}

ffi_export! {
    /// `num` random octets into `buf` from the context's public DRBG (or its random provider,
    /// or the application's method), at `strength` bits or more. 1, or 0 (-1 for a method
    /// without `bytes`).
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context; `buf` has room for `num` octets.
    pub unsafe extern "C" fn RAND_bytes_ex(ctx: *mut OSSL_LIB_CTX, buf: *mut c_uchar, num: usize, strength: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_RAND
    {
        // SAFETY: the caller's guarantee.
        unsafe { bytes_ex(ctx, buf, num, strength, false) }
    }
}

ffi_export! {
    /// As `RAND_bytes_ex`, from the private DRBG (for secrets).
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context; `buf` has room for `num` octets.
    pub unsafe extern "C" fn RAND_priv_bytes_ex(ctx: *mut OSSL_LIB_CTX, buf: *mut c_uchar, num: usize, strength: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_RAND
    {
        // SAFETY: the caller's guarantee.
        unsafe { bytes_ex(ctx, buf, num, strength, true) }
    }
}

ffi_export! {
    /// `RAND_bytes_ex` of the default context; 0 for a negative count.
    ///
    /// # Safety
    /// `buf` has room for `num` octets.
    pub unsafe extern "C" fn RAND_bytes(buf: *mut c_uchar, num: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RAND
    {
        let Ok(n) = usize::try_from(num) else { return 0 };
        // SAFETY: the caller's guarantee.
        unsafe { bytes_ex(ptr::null_mut(), buf, n, 0, false) }
    }
}

ffi_export! {
    /// `RAND_priv_bytes_ex` of the default context; 0 for a negative count.
    ///
    /// # Safety
    /// `buf` has room for `num` octets.
    pub unsafe extern "C" fn RAND_priv_bytes(buf: *mut c_uchar, num: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RAND
    {
        let Ok(n) = usize::try_from(num) else { return 0 };
        // SAFETY: the caller's guarantee.
        unsafe { bytes_ex(ptr::null_mut(), buf, n, 0, true) }
    }
}

ffi_export! {
    /// The method's `pseudorand` (the library's: the public DRBG); -1 with
    /// `RAND_R_FUNC_NOT_IMPLEMENTED` if it has none.
    ///
    /// # Safety
    /// `buf` has room for `num` octets.
    pub unsafe extern "C" fn RAND_pseudo_bytes(buf: *mut c_uchar, num: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RAND
    {
        match any_method().and_then(|m| m.pseudorand) {
            // SAFETY: the method's function with the caller's buffer.
            Some(f) => unsafe { f(buf, num) },
            None => {
                err::raise(ERR_LIB_RAND, RAND_R_FUNC_NOT_IMPLEMENTED, "RAND_pseudo_bytes");
                -1
            }
        }
    }
}

ffi_export! {
    /// Mixes `num` octets into the primary DRBG (a reseed with them as additional input), or
    /// gives them to the method's `seed`.
    ///
    /// # Safety
    /// `buf` holds `num` octets.
    pub unsafe extern "C" fn RAND_seed(buf: *const c_void, num: c_int)
    where failure = (), library = ERR_LIB_RAND
    {
        if let Some(seed) = any_method().and_then(|m| m.seed) {
            // SAFETY: the method's function with the caller's octets.
            unsafe { seed(buf, num) };
            return;
        }
        // SAFETY: the caller's guarantee.
        unsafe { add_to_primary(buf, num) };
    }
}

/// The primary DRBG reseeded with `num` octets as additional input.
///
/// # Safety
/// `buf` holds `num` octets.
unsafe fn add_to_primary(buf: *const c_void, num: c_int) {
    // SAFETY: the default context.
    let drbg = unsafe { RAND_get0_primary(ptr::null_mut()) };
    if let Ok(n) = usize::try_from(num)
        && !drbg.is_null()
        && n > 0
    {
        // SAFETY: the primary DRBG; the caller's octets.
        unsafe { EVP_RAND_reseed(drbg, 0, ptr::null(), 0, buf.cast(), n) };
    }
}

ffi_export! {
    /// As `RAND_seed` (the entropy estimate isn't used), or the method's `add`.
    ///
    /// # Safety
    /// `buf` holds `num` octets.
    pub unsafe extern "C" fn RAND_add(buf: *const c_void, num: c_int, randomness: c_double)
    where failure = (), library = ERR_LIB_RAND
    {
        if let Some(add) = any_method().and_then(|m| m.add) {
            // SAFETY: the method's function with the caller's octets.
            unsafe { add(buf, num, randomness) };
            return;
        }
        // SAFETY: the caller's guarantee.
        unsafe { add_to_primary(buf, num) };
    }
}

ffi_export! {
    /// Whether the generator is seeded: the primary DRBG ready, or the method's `status` (0
    /// without one).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn RAND_status() -> c_int
    where failure = 0, library = ERR_LIB_RAND
    {
        if let Some(m) = other_method() {
            // SAFETY: the method's function.
            return m.status.map_or(0, |f| unsafe { f() });
        }
        // SAFETY: the default context.
        let rand = unsafe { RAND_get0_primary(ptr::null_mut()) };
        // SAFETY: the primary DRBG.
        c_int::from(!rand.is_null() && unsafe { EVP_RAND_get_state(rand) } == EVP_RAND_STATE_READY as c_int)
    }
}

ffi_export! {
    /// Seeds the generator: the library's mixes in "polling" (1); another method is given
    /// `RAND_DRBG_STRENGTH` bits of the operating system's entropy through its `add`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn RAND_poll() -> c_int
    where failure = 0, library = ERR_LIB_RAND
    {
        const SALT: &[u8] = b"polling\0";
        let m = method();
        if m.is_null() {
            return 0;
        }
        if let Some(m) = other_method() {
            let strength = RAND_DRBG_STRENGTH;
            let min = usize::try_from(strength + 7).unwrap_or(0) / 8;
            let mut pool = crate::rand::Pool::new(strength, min, usize::MAX);
            if pool.acquire_entropy() == 0 {
                return 0;
            }
            let Some(add) = m.add else { return 0 };
            let octets = pool.octets();
            let Ok(n) = c_int::try_from(octets.len()) else { return 0 };
            let randomness = f64::from(u32::try_from(pool.entropy()).unwrap_or(u32::MAX)) / 8.0;
            // SAFETY: the method's function with the pool's octets.
            return c_int::from(unsafe { add(octets.as_ptr().cast(), n, randomness) } != 0);
        }
        // SAFETY: a static salt with its NUL, as the reference's `sizeof`.
        unsafe { RAND_seed(SALT.as_ptr().cast(), c_int::try_from(SALT.len()).unwrap_or(0)) };
        1
    }
}

ffi_export! {
    /// Keeps the random devices open between uses: nothing to do, as the operating system's
    /// entropy comes from its system call (`getrandom`/`getentropy`), not a device.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn RAND_keep_random_devices_open(keep: c_int)
    where failure = (), library = ERR_LIB_RAND
    {
        let _ = keep;
    }
}

/// The random source a provider's algorithm context draws on: `RAND_bytes_ex` (or
/// `RAND_priv_bytes_ex`) of the context the provider was loaded into, as the reference's
/// algorithms call with their `libctx`.
pub(crate) fn random_source(
    libctx: *mut OSSL_LIB_CTX,
    private: bool,
) -> rustyssl_crypto::rand::Random {
    let ctx = Ptr(provider_context(libctx));
    std::sync::Arc::new(move |out: &mut [u8]| {
        let ctx = ctx;
        // SAFETY: the provider's context, live while its algorithms are; room for the octets.
        unsafe { bytes_ex(ctx.0, out.as_mut_ptr(), out.len(), 0, private) > 0 }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: the library's `RAND_pseudo_bytes` (its method's `pseudorand`) with
    /// a negative count fails (the reference generates the huge length it converts to).
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn negative_pseudo_bytes_fail() {
        let mut buf = [0u8; 4];
        // SAFETY: room for the octets; the negative count is the case under test. (The method
        // is called directly: another test sets one of its own.)
        assert_eq!(unsafe { drbg_bytes(buf.as_mut_ptr(), -1) }, 0);
    }

    /// The application's method under test: fills with 0x42.
    unsafe extern "C" fn fill(buf: *mut c_uchar, num: c_int) -> c_int {
        if let Ok(n) = usize::try_from(num) {
            // SAFETY: the caller's room.
            unsafe { ptr::write_bytes(buf, 0x42, n) };
        }
        1
    }

    /// docs/DEVIATIONS.md: `RAND_bytes_ex` through an application's method with a length past
    /// `INT_MAX` fails (the reference passes its method the length cut to an `int`).
    #[test]
    fn method_lengths_past_int_max_fail() {
        static METH: MethodCell = MethodCell(UnsafeCell::new(RAND_METHOD {
            seed: None,
            bytes: Some(fill),
            cleanup: None,
            add: None,
            pseudorand: None,
            status: None,
        }));
        let mut buf = [0u8; 4];
        // SAFETY: a method that stays valid.
        unsafe { RAND_set_rand_method(METH.0.get()) };
        assert_eq!(
            // SAFETY: room for 4 octets.
            unsafe { RAND_bytes_ex(ptr::null_mut(), buf.as_mut_ptr(), 4, 0) },
            1
        );
        let long = usize::try_from(c_int::MAX).unwrap_or(0) + 1;
        assert_eq!(
            // SAFETY: the method is never called for this length.
            unsafe { RAND_bytes_ex(ptr::null_mut(), buf.as_mut_ptr(), long, 0) },
            0
        );
        assert_eq!(
            // SAFETY: as above.
            unsafe { RAND_priv_bytes_ex(ptr::null_mut(), buf.as_mut_ptr(), long, 0) },
            0
        );
        // SAFETY: back to the library's.
        unsafe { RAND_set_rand_method(ptr::null()) };
        assert_eq!(buf, [0x42; 4]);
    }
}
