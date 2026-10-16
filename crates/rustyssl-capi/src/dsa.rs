//! DSA keys (`DSA`; `crypto/dsa/dsa_lib.c`): domain parameters (`crate::ffc::Params`) and the
//! key pair, with their method, flags, application data, and references.
//!
//! As with `DH`, the numbers the application sees (`DSA_get0_*`) or gives (`DSA_set0_*`) are
//! kept as the key's own `BIGNUM`s from then on, so a `get0` pointer lives as long as the key
//! and reads (and writes) its number.

use core::cell::UnsafeCell;
use core::ffi::{c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    BIGNUM, CRYPTO_EX_DATA, CRYPTO_EX_INDEX_DSA, DSA, DSA_FLAG_NON_FIPS_ALLOW, DSA_METHOD, ENGINE,
    ERR_LIB_DSA, ERR_R_INIT_FAIL, OSSL_LIB_CTX,
};
use rustyssl_crypto::bn::BigNum;

use crate::bn::{BN_clear_free, BN_security_bits, new_bignum, store, value};
use crate::err;
use crate::ex_data::{
    CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data, CRYPTO_set_ex_data,
};
use crate::ffc;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::provider::Ptr;

/// A DSA key's state: its parameters and key pair.
#[derive(Clone, Default)]
pub(crate) struct DsaState {
    pub(crate) params: ffc::Params,
    /// DSAPrivateKey's version (`int32_t version`), kept from decoding for encoding.
    pub(crate) version: i32,
    pub(crate) pub_key: Option<BigNum>,
    pub(crate) priv_key: Option<BigNum>,
}

/// One of a DSA key's numbers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Field {
    P,
    Q,
    G,
    Pub,
    Priv,
}

impl Field {
    const ALL: [Self; 5] = [Self::P, Self::Q, Self::G, Self::Pub, Self::Priv];

    /// The state's number `f`.
    pub(crate) fn of(self, st: &mut DsaState) -> &mut Option<BigNum> {
        match self {
            Self::P => &mut st.params.p,
            Self::Q => &mut st.params.q,
            Self::G => &mut st.params.g,
            Self::Pub => &mut st.pub_key,
            Self::Priv => &mut st.priv_key,
        }
    }

    fn index(self) -> usize {
        match self {
            Self::P => 0,
            Self::Q => 1,
            Self::G => 2,
            Self::Pub => 3,
            Self::Priv => 4,
        }
    }
}

/// The `BIGNUM`s the application has seen or given: the key's numbers from then on.
/// Replaced ones are kept until the key is freed, so no `get0` pointer dangles.
#[derive(Default)]
pub(crate) struct Numbers {
    slots: [Ptr<BIGNUM>; 5],
    retired: Vec<Ptr<BIGNUM>>,
}

impl Numbers {
    pub(crate) fn slot(&mut self, f: Field) -> &mut Ptr<BIGNUM> {
        let i = f.index();
        // Five slots, one per field.
        #[expect(clippy::indexing_slicing, reason = "an index below the array's length")]
        &mut self.slots[i]
    }

    fn retire(&mut self, old: Ptr<BIGNUM>) {
        if !old.0.is_null() {
            self.retired.push(old);
        }
    }

    /// Reads the numbers the application holds into `st`.
    pub(crate) fn read(&mut self, st: &mut DsaState) {
        for f in Field::ALL {
            let h = *self.slot(f);
            if !h.0.is_null() {
                // SAFETY: the key's own number, live until the key is freed.
                *f.of(st) = unsafe { value(h.0) };
            }
        }
    }

    /// Stores `st`'s numbers in the handles the application holds; a handle whose number the
    /// key no longer has is retired.
    pub(crate) fn write(&mut self, st: &mut DsaState) {
        for f in Field::ALL {
            let slot = self.slot(f);
            if slot.0.is_null() {
                continue;
            }
            match f.of(st) {
                // SAFETY: the key's own number.
                Some(v) => unsafe {
                    store(slot.0, v.clone());
                },
                None => {
                    let old = core::mem::take(slot);
                    self.retire(old);
                }
            }
        }
    }
}

/// The parts of a `DSA` the legacy functions see: its method, flags, and numbers' handles.
pub(crate) struct Legacy {
    pub(crate) meth: Ptr<DSA_METHOD>,
    pub(crate) flags: c_int,
    pub(crate) numbers: Numbers,
}

/// The key's application data, at a fixed address for the `CRYPTO_*_ex_data` functions.
struct ExData(UnsafeCell<CRYPTO_EX_DATA>);

// SAFETY: the ex_data functions are the only users, and OpenSSL leaves serializing them to the
// application.
unsafe impl Send for ExData {}
// SAFETY: as above.
unsafe impl Sync for ExData {}

/// A DSA key (`DSA`), shared by reference.
pub(crate) struct Dsa {
    pub(crate) libctx: Ptr<OSSL_LIB_CTX>,
    /// Made in a library context (OpenSSL's non-NULL `libctx`: by a provider, or from a key
    /// that was), which signs through OpenSSL's own code rather than the key's method.
    pub(crate) in_libctx: bool,
    references: AtomicI32,
    /// `dirty_cnt`.
    dirty: AtomicUsize,
    state: Mutex<DsaState>,
    legacy: Mutex<Legacy>,
    ex_data: ExData,
}

handle_type!(DSA => Dsa);

impl Drop for Dsa {
    fn drop(&mut self) {
        let lg = self
            .legacy
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        let mut all = core::mem::take(&mut lg.numbers.retired);
        all.extend(lg.numbers.slots);
        for b in all.into_iter().filter(|b| !b.0.is_null()) {
            // SAFETY: the key's own numbers, freed once.
            unsafe { BN_clear_free(b.0) };
        }
    }
}

impl Dsa {
    /// `dsa_new_intern`: an empty key in `libctx` with the default method (whose `init` it
    /// runs) and its flags but `DSA_FLAG_NON_FIPS_ALLOW`, or NULL with the error raised.
    pub(crate) fn new_handle_in(libctx: *mut OSSL_LIB_CTX) -> *mut DSA {
        Self::make(libctx, false)
    }

    /// `ossl_dsa_new`: as `new_handle_in`, for a key made in a library context.
    pub(crate) fn new_handle_provided(libctx: *mut OSSL_LIB_CTX) -> *mut DSA {
        Self::make(libctx, true)
    }

    /// `dsa_new_intern`.
    fn make(libctx: *mut OSSL_LIB_CTX, in_libctx: bool) -> *mut DSA {
        let meth = crate::dsa_meth::default_or_builtin();
        // SAFETY: a live method.
        let mflags = unsafe { crate::dsa_meth::flags(meth) };
        let h = DSA::new_handle(Dsa {
            libctx: Ptr(libctx),
            in_libctx,
            references: AtomicI32::new(1),
            dirty: AtomicUsize::new(0),
            state: Mutex::new(DsaState::default()),
            legacy: Mutex::new(Legacy {
                meth: Ptr(meth.cast_mut()),
                flags: mflags & !DSA_FLAG_NON_FIPS_ALLOW,
                numbers: Numbers::default(),
            }),
            ex_data: ExData(UnsafeCell::new(CRYPTO_EX_DATA {
                ctx: ptr::null_mut(),
                sk: ptr::null_mut(),
            })),
        });
        // SAFETY: just made.
        let Some(d) = (unsafe { dsa(h) }) else {
            return ptr::null_mut();
        };
        // SAFETY: the key's own ex_data.
        if unsafe { CRYPTO_new_ex_data(CRYPTO_EX_INDEX_DSA, h.cast(), d.ex_data()) } == 0 {
            // SAFETY: the only reference.
            unsafe { free(h) };
            return ptr::null_mut();
        }
        // SAFETY: the method is live; no lock is held while it runs.
        if let Some(init) = unsafe { crate::dsa_meth::fns_of(meth) }.and_then(|f| f.init)
            // SAFETY: the method's function takes the key.
            && unsafe { init(h) } == 0
        {
            err::raise(ERR_LIB_DSA, ERR_R_INIT_FAIL, "dsa_new_intern");
            // SAFETY: as above.
            unsafe { free(h) };
            return ptr::null_mut();
        }
        h
    }

    /// The key's application data.
    pub(crate) fn ex_data(&self) -> *mut CRYPTO_EX_DATA {
        self.ex_data.0.get()
    }

    /// The state, locked.
    pub(crate) fn lock(&self) -> MutexGuard<'_, DsaState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The legacy parts, locked (after the state, when both are).
    pub(crate) fn legacy(&self) -> MutexGuard<'_, Legacy> {
        self.legacy.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A copy of the state, with the numbers the application holds read in.
    pub(crate) fn snapshot(&self) -> DsaState {
        let mut st = self.lock().clone();
        self.legacy().numbers.read(&mut st);
        st
    }

    /// Replaces the state (its numbers stored in the application's handles too).
    pub(crate) fn replace(&self, mut new: DsaState) {
        let mut st = self.lock();
        self.legacy().numbers.write(&mut new);
        *st = new;
        drop(st);
        self.touch();
    }

    /// Bumps the dirty count.
    pub(crate) fn touch(&self) {
        self.dirty.fetch_add(1, Ordering::AcqRel);
    }

    /// The dirty count (`dirty_cnt`).
    pub(crate) fn dirty_count(&self) -> usize {
        self.dirty.load(Ordering::Acquire)
    }

    /// The method.
    pub(crate) fn meth(&self) -> *const DSA_METHOD {
        self.legacy().meth.0
    }

    /// The flags.
    pub(crate) fn flags(&self) -> c_int {
        self.legacy().flags
    }

    /// Sets the flags.
    pub(crate) fn set_flags_to(&self, flags: c_int) {
        self.legacy().flags = flags;
    }

    /// The key's number `f` as its own `BIGNUM`, made the first time (NULL if it has none).
    fn get0(&self, f: Field) -> *const BIGNUM {
        let mut st = self.lock();
        let mut lg = self.legacy();
        lg.numbers.read(&mut st);
        let Some(v) = f.of(&mut st).clone() else {
            return ptr::null();
        };
        let slot = lg.numbers.slot(f);
        if slot.0.is_null() {
            *slot = Ptr(new_bignum(v, false));
        }
        slot.0
    }

    /// `DSA_set0_*`'s step: the key takes `b` as its number `f` (keeping the old one alive).
    ///
    /// # Safety
    /// `b` is a live `BIGNUM` the caller gives up.
    unsafe fn set0(&self, st: &mut DsaState, lg: &mut Legacy, f: Field, b: *mut BIGNUM) {
        // SAFETY: the caller's guarantee.
        *f.of(st) = unsafe { value(b) };
        let slot = lg.numbers.slot(f);
        let old = core::mem::replace(slot, Ptr(b));
        if old.0 != b {
            lg.numbers.retire(old);
        }
    }

    /// Takes `BIGNUM`s as the key's numbers (each non-NULL one; the key owns it from then on,
    /// keeping a replaced one alive).
    ///
    /// # Safety
    /// Each `BIGNUM` is NULL or live, given up by the caller.
    pub(crate) unsafe fn adopt(&self, fields: &[(Field, *mut BIGNUM)]) {
        let mut st = self.lock();
        let mut lg = self.legacy();
        lg.numbers.read(&mut st);
        for &(f, b) in fields {
            if !b.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { self.set0(&mut st, &mut lg, f, b) };
            }
        }
        drop(lg);
        drop(st);
        self.touch();
    }
}

/// The key behind a `DSA` pointer.
///
/// # Safety
/// `d` is NULL or a live handle.
pub(crate) unsafe fn dsa<'a>(d: *const DSA) -> Option<&'a Dsa> {
    // SAFETY: the caller's guarantee.
    unsafe { DSA::get(d) }
}

/// `DSA_free`: drops a reference; at the last, runs the method's `finish` and frees the
/// ex_data, then the key.
///
/// # Safety
/// `d` is NULL or a live key whose reference the caller gives up.
pub(crate) unsafe fn free(d: *mut DSA) {
    // SAFETY: the caller's guarantee.
    let Some(held) = (unsafe { DSA::hold(d) }) else {
        return;
    };
    let left = held
        .references
        .fetch_sub(1, Ordering::AcqRel)
        .saturating_sub(1);
    if left != 0 {
        return;
    }
    let meth = held.meth();
    // SAFETY: the key's method, live; no lock is held while it runs.
    if let Some(finish) = unsafe { crate::dsa_meth::fns_of(meth) }.and_then(|f| f.finish) {
        // SAFETY: the method's function takes the key.
        unsafe { finish(d) };
    }
    // SAFETY: the key's own ex_data; its last reference.
    unsafe { CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DSA, d.cast(), held.ex_data()) };
    // SAFETY: the last reference; the hold keeps the key until this returns.
    unsafe { DSA::free(d) };
}

/// Adds a reference.
///
/// # Safety
/// `d` is NULL or a live key.
pub(crate) unsafe fn up_ref(d: *const DSA) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { dsa(d) }) else {
        return false;
    };
    k.references.fetch_add(1, Ordering::AcqRel);
    true
}

/// Puts `v` where `out` points, if it does.
///
/// # Safety
/// `out` is NULL or writable.
unsafe fn put(out: *mut *const BIGNUM, v: *const BIGNUM) {
    if !out.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { out.write(v) };
    }
}

ffi_export! {
    /// A new empty key with the default method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn DSA_new() -> *mut DSA
    where failure = ptr::null_mut(), library = ERR_LIB_DSA
    {
        Dsa::new_handle_in(ptr::null_mut())
    }
}

ffi_export! {
    /// `DSA_new` with an engine: NULL only (rustyssl has no engines; another pointer aborts).
    ///
    /// # Safety
    /// `engine` is NULL.
    pub unsafe extern "C" fn DSA_new_method(engine: *mut ENGINE) -> *mut DSA
    where failure = ptr::null_mut(), library = ERR_LIB_DSA
    {
        if !engine.is_null() {
            crate::stub::unimplemented("DSA_new_method with an engine (rustyssl has none)");
        }
        Dsa::new_handle_in(ptr::null_mut())
    }
}

ffi_export! {
    /// Drops a reference; at the last, the method's `finish` runs and the key is freed. NULL
    /// does nothing.
    ///
    /// # Safety
    /// `r` is NULL or a live key whose reference the caller gives up.
    pub unsafe extern "C" fn DSA_free(r: *mut DSA)
    where failure = (), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { free(r) };
    }
}

ffi_export! {
    /// Adds a reference. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn DSA_up_ref(r: *mut DSA) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { up_ref(r) })
    }
}

ffi_export! {
    /// Replaces the key's method: the old one's `finish` runs, then the new one's `init`. 1.
    ///
    /// # Safety
    /// `dsa` is a live key; `meth` is a live method that outlives its use.
    pub unsafe extern "C" fn DSA_set_method(dsa: *mut DSA, meth: *const DSA_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dsa(dsa) }) else { return 0 };
        let old = k.meth();
        // SAFETY: the key's method, live; no lock is held while it runs.
        if let Some(finish) = unsafe { crate::dsa_meth::fns_of(old) }.and_then(|f| f.finish) {
            // SAFETY: the method's function takes the key.
            unsafe { finish(dsa) };
        }
        k.legacy().meth = Ptr(meth.cast_mut());
        // SAFETY: the caller's method.
        if let Some(init) = unsafe { crate::dsa_meth::fns_of(meth) }.and_then(|f| f.init) {
            // SAFETY: as above.
            unsafe { init(dsa) };
        }
        1
    }
}

ffi_export! {
    /// The key's method.
    ///
    /// # Safety
    /// `d` is a live key.
    pub unsafe extern "C" fn DSA_get_method(d: *mut DSA) -> *const DSA_METHOD
    where failure = ptr::null(), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { dsa(d) }.map_or(ptr::null(), Dsa::meth)
    }
}

ffi_export! {
    /// The key's engine: always NULL (rustyssl has no engines).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn DSA_get0_engine(_d: *mut DSA) -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_DSA
    {
        ptr::null_mut()
    }
}

ffi_export! {
    /// Sets the key's application data at `idx`.
    ///
    /// # Safety
    /// `d` is a live key.
    pub unsafe extern "C" fn DSA_set_ex_data(d: *mut DSA, idx: c_int, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { dsa(d) }) else { return 0 };
        // SAFETY: the key's own ex_data.
        unsafe { CRYPTO_set_ex_data(k.ex_data(), idx, arg) }
    }
}

ffi_export! {
    /// The key's application data at `idx`, or NULL.
    ///
    /// # Safety
    /// `d` is a live key.
    pub unsafe extern "C" fn DSA_get_ex_data(d: *const DSA, idx: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { dsa(d) }) else { return ptr::null_mut() };
        // SAFETY: the key's own ex_data.
        unsafe { CRYPTO_get_ex_data(k.ex_data(), idx) }
    }
}

ffi_export! {
    /// The prime's bits, or -1 without one.
    ///
    /// # Safety
    /// `dsa` is a live key.
    pub unsafe extern "C" fn DSA_bits(dsa: *const DSA) -> c_int
    where failure = -1, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dsa(dsa) }) else { return -1 };
        k.snapshot().params.p.map_or(-1, |p| c_int::try_from(p.num_bits()).unwrap_or(c_int::MAX))
    }
}

ffi_export! {
    /// The security strength of p's and q's bits, or -1 without them.
    ///
    /// # Safety
    /// `d` is a live key.
    pub unsafe extern "C" fn DSA_security_bits(d: *const DSA) -> c_int
    where failure = -1, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { dsa(d) }) else { return -1 };
        let st = k.snapshot();
        let (Some(p), Some(q)) = (st.params.p, st.params.q) else { return -1 };
        let bits = |b: &BigNum| c_int::try_from(b.num_bits()).unwrap_or(c_int::MAX);
        // SAFETY: no preconditions.
        unsafe { BN_security_bits(bits(&p), bits(&q)) }
    }
}

ffi_export! {
    /// The parameters (each where asked; NULL for a missing one).
    ///
    /// # Safety
    /// `d` is a live key; each output is NULL or writable.
    pub unsafe extern "C" fn DSA_get0_pqg(d: *const DSA, p: *mut *const BIGNUM, q: *mut *const BIGNUM, g: *mut *const BIGNUM)
    where failure = (), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { dsa(d) }) else { return };
        for (out, f) in [(p, Field::P), (q, Field::Q), (g, Field::G)] {
            if !out.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { put(out, k.get0(f)) };
            }
        }
    }
}

ffi_export! {
    /// Sets the parameters: the key takes each number that isn't NULL (p, q, and g must end up
    /// set). 0 when it would lack one.
    ///
    /// # Safety
    /// `d` is a live key; each number is NULL or a live `BIGNUM` the caller gives up.
    pub unsafe extern "C" fn DSA_set0_pqg(d: *mut DSA, p: *mut BIGNUM, q: *mut BIGNUM, g: *mut BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { dsa(d) }) else { return 0 };
        let mut st = k.lock();
        let mut lg = k.legacy();
        lg.numbers.read(&mut st);
        if (st.params.p.is_none() && p.is_null())
            || (st.params.q.is_none() && q.is_null())
            || (st.params.g.is_none() && g.is_null())
        {
            return 0;
        }
        for (f, b) in [(Field::P, p), (Field::Q, q), (Field::G, g)] {
            if !b.is_null() {
                // SAFETY: the caller's number.
                unsafe { k.set0(&mut st, &mut lg, f, b) };
            }
        }
        drop(lg);
        drop(st);
        k.touch();
        1
    }
}

ffi_export! {
    /// The key pair (each where asked; NULL for a missing one).
    ///
    /// # Safety
    /// `d` is a live key; each output is NULL or writable.
    pub unsafe extern "C" fn DSA_get0_key(d: *const DSA, pub_key: *mut *const BIGNUM, priv_key: *mut *const BIGNUM)
    where failure = (), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { dsa(d) }) else { return };
        for (out, f) in [(pub_key, Field::Pub), (priv_key, Field::Priv)] {
            if !out.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { put(out, k.get0(f)) };
            }
        }
    }
}

ffi_export! {
    /// Sets the key pair: the key takes each number that isn't NULL. 1.
    ///
    /// # Safety
    /// `d` is a live key; each number is NULL or a live `BIGNUM` the caller gives up.
    pub unsafe extern "C" fn DSA_set0_key(d: *mut DSA, pub_key: *mut BIGNUM, priv_key: *mut BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { dsa(d) }) else { return 0 };
        // SAFETY: the caller's numbers.
        unsafe { k.adopt(&[(Field::Pub, pub_key), (Field::Priv, priv_key)]) };
        1
    }
}

/// `DSA_get0_*`: the key's number `f`, or NULL.
///
/// # Safety
/// `d` is NULL or a live key.
unsafe fn get0(d: *const DSA, f: Field) -> *const BIGNUM {
    // SAFETY: the caller's guarantee.
    unsafe { dsa(d) }.map_or(ptr::null(), |k| k.get0(f))
}

ffi_export! {
    /// The prime p, or NULL.
    ///
    /// # Safety
    /// `d` is a live key.
    pub unsafe extern "C" fn DSA_get0_p(d: *const DSA) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0(d, Field::P) }
    }
}

ffi_export! {
    /// The subgroup order q, or NULL.
    ///
    /// # Safety
    /// `d` is a live key.
    pub unsafe extern "C" fn DSA_get0_q(d: *const DSA) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0(d, Field::Q) }
    }
}

ffi_export! {
    /// The generator g, or NULL.
    ///
    /// # Safety
    /// `d` is a live key.
    pub unsafe extern "C" fn DSA_get0_g(d: *const DSA) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0(d, Field::G) }
    }
}

ffi_export! {
    /// The public key, or NULL.
    ///
    /// # Safety
    /// `d` is a live key.
    pub unsafe extern "C" fn DSA_get0_pub_key(d: *const DSA) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0(d, Field::Pub) }
    }
}

ffi_export! {
    /// The private key, or NULL.
    ///
    /// # Safety
    /// `d` is a live key.
    pub unsafe extern "C" fn DSA_get0_priv_key(d: *const DSA) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0(d, Field::Priv) }
    }
}

ffi_export! {
    /// Clears `flags`.
    ///
    /// # Safety
    /// `d` is a live key.
    pub unsafe extern "C" fn DSA_clear_flags(d: *mut DSA, flags: c_int)
    where failure = (), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        if let Some(k) = unsafe { dsa(d) } {
            k.set_flags_to(k.flags() & !flags);
        }
    }
}

ffi_export! {
    /// The flags among `flags` that are set.
    ///
    /// # Safety
    /// `d` is a live key.
    pub unsafe extern "C" fn DSA_test_flags(d: *const DSA, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { dsa(d) }.map_or(0, |k| k.flags() & flags)
    }
}

ffi_export! {
    /// Sets `flags`.
    ///
    /// # Safety
    /// `d` is a live key.
    pub unsafe extern "C" fn DSA_set_flags(d: *mut DSA, flags: c_int)
    where failure = (), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        if let Some(k) = unsafe { dsa(d) } {
            k.set_flags_to(k.flags() | flags);
        }
    }
}

ffi_export! {
    /// A DH key with the DSA key's parameters (all of them, the seed and counters too) and its
    /// key pair (a private key only with the public key), or NULL (also for NULL, and for a
    /// private key without a public key).
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn DSA_dup_DH(r: *const DSA) -> *mut rustyssl_abi::DH
    where failure = ptr::null_mut(), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { dsa(r) }) else { return ptr::null_mut() };
        let st = k.snapshot();
        if st.pub_key.is_none() && st.priv_key.is_some() {
            return ptr::null_mut();
        }
        let out = crate::dh::Dh::new_handle_in(ptr::null_mut());
        // SAFETY: just made, or NULL.
        let Some(d) = (unsafe { crate::dh::dh(out) }) else { return ptr::null_mut() };
        let mut ds = d.snapshot();
        ds.params = st.params;
        ds.pub_key = st.pub_key;
        if ds.pub_key.is_some() {
            ds.priv_key = st.priv_key;
        }
        d.replace(ds);
        out
    }
}
