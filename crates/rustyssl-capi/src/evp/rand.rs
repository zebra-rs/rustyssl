//! Random generator methods and contexts (`EVP_RAND(3)`; `evp_rand.c`): an `EVP_RAND` made from
//! a provider's random algorithm (`evp_rand_from_algorithm`), fetched by name and properties,
//! and an `EVP_RAND_CTX` running it, with a reference to its parent (whose algorithm context
//! and dispatch table the algorithm is given): instantiation, generation (in chunks of at most
//! the context's request limit), reseeding, nonces, parameters, locking, and the seed calls the
//! RAND layer makes of a seed source.
//!
//! As in OpenSSL, a random algorithm must offer `newctx`, `freectx`, `get_ctx_params`,
//! `instantiate`, `uninstantiate`, and `generate`, and `lock` and `unlock` together if either.
//! Each context call takes the algorithm's lock (`lock` and `unlock`) around it. The functions
//! given a NULL method or context fail here where the reference would crash
//! (docs/DEVIATIONS.md); those the reference lets take NULL (`EVP_RAND_up_ref`, `_free`,
//! `_is_a`, `EVP_RAND_CTX_free`, `EVP_RAND_nonce`) do as it does.

use core::ffi::{CStr, c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    ERR_LIB_EVP, ERR_R_EVP_LIB, ERR_R_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER,
    EVP_R_GENERATE_ERROR, EVP_R_INVALID_NULL_ALGORITHM, EVP_R_INVALID_PROVIDER_FUNCTIONS,
    EVP_R_LOCKING_NOT_SUPPORTED, EVP_R_UNABLE_TO_GET_MAXIMUM_REQUEST_SIZE, EVP_RAND, EVP_RAND_CTX,
    EVP_RAND_STATE_ERROR, OSSL_ALGORITHM, OSSL_DISPATCH, OSSL_FUNC_RAND_CLEAR_SEED,
    OSSL_FUNC_RAND_ENABLE_LOCKING, OSSL_FUNC_RAND_FREECTX, OSSL_FUNC_RAND_GENERATE,
    OSSL_FUNC_RAND_GET_CTX_PARAMS, OSSL_FUNC_RAND_GET_PARAMS, OSSL_FUNC_RAND_GET_SEED,
    OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, OSSL_FUNC_RAND_GETTABLE_PARAMS, OSSL_FUNC_RAND_INSTANTIATE,
    OSSL_FUNC_RAND_LOCK, OSSL_FUNC_RAND_NEWCTX, OSSL_FUNC_RAND_NONCE, OSSL_FUNC_RAND_RESEED,
    OSSL_FUNC_RAND_SET_CTX_PARAMS, OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_RAND_UNINSTANTIATE, OSSL_FUNC_RAND_UNLOCK, OSSL_FUNC_RAND_VERIFY_ZEROIZATION,
    OSSL_LIB_CTX, OSSL_OP_RAND, OSSL_PARAM, OSSL_PROVIDER, OSSL_RAND_PARAM_MAX_REQUEST,
    OSSL_RAND_PARAM_STATE, OSSL_RAND_PARAM_STRENGTH,
};

use super::fetch::{self, Kind};
use crate::err;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::params::{
    OSSL_PARAM_construct_int, OSSL_PARAM_construct_size_t, OSSL_PARAM_construct_uint, end,
};
use crate::provider::Ptr;

type AnyFn = unsafe extern "C" fn();
pub(crate) type NewCtxFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *const OSSL_DISPATCH) -> *mut c_void;
pub(crate) type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
pub(crate) type InstantiateFn = unsafe extern "C" fn(
    *mut c_void,
    c_uint,
    c_int,
    *const c_uchar,
    usize,
    *const OSSL_PARAM,
) -> c_int;
pub(crate) type UninstantiateFn = unsafe extern "C" fn(*mut c_void) -> c_int;
pub(crate) type GenerateFn = unsafe extern "C" fn(
    *mut c_void,
    *mut c_uchar,
    usize,
    c_uint,
    c_int,
    *const c_uchar,
    usize,
) -> c_int;
pub(crate) type ReseedFn =
    unsafe extern "C" fn(*mut c_void, c_int, *const c_uchar, usize, *const c_uchar, usize) -> c_int;
pub(crate) type NonceFn =
    unsafe extern "C" fn(*mut c_void, *mut c_uchar, c_uint, usize, usize) -> usize;
pub(crate) type LockingFn = unsafe extern "C" fn(*mut c_void) -> c_int;
pub(crate) type UnlockFn = unsafe extern "C" fn(*mut c_void);
pub(crate) type GettableFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
pub(crate) type CtxParamsListFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;
pub(crate) type GetParamsFn = unsafe extern "C" fn(*mut OSSL_PARAM) -> c_int;
pub(crate) type GetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
pub(crate) type SetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
pub(crate) type VerifyZeroizationFn = unsafe extern "C" fn(*mut c_void) -> c_int;
pub(crate) type GetSeedFn = unsafe extern "C" fn(
    *mut c_void,
    *mut *mut c_uchar,
    c_int,
    usize,
    usize,
    c_int,
    *const c_uchar,
    usize,
) -> usize;
pub(crate) type ClearSeedFn = unsafe extern "C" fn(*mut c_void, *mut c_uchar, usize);

/// A random algorithm's functions, as its dispatch table gave them.
#[derive(Default, Clone, Copy)]
struct Funcs {
    newctx: Option<NewCtxFn>,
    freectx: Option<FreeCtxFn>,
    instantiate: Option<InstantiateFn>,
    uninstantiate: Option<UninstantiateFn>,
    generate: Option<GenerateFn>,
    reseed: Option<ReseedFn>,
    nonce: Option<NonceFn>,
    enable_locking: Option<LockingFn>,
    lock: Option<LockingFn>,
    unlock: Option<UnlockFn>,
    gettable_params: Option<GettableFn>,
    gettable_ctx_params: Option<CtxParamsListFn>,
    settable_ctx_params: Option<CtxParamsListFn>,
    get_params: Option<GetParamsFn>,
    get_ctx_params: Option<GetCtxParamsFn>,
    set_ctx_params: Option<SetCtxParamsFn>,
    verify_zeroization: Option<VerifyZeroizationFn>,
    get_seed: Option<GetSeedFn>,
    clear_seed: Option<ClearSeedFn>,
}

/// A random method (`EVP_RAND`).
pub(crate) struct Rand {
    name_id: u32,
    type_name: CString,
    /// The provider's description, a static string of its, or NULL.
    description: Ptr<c_char>,
    /// The provider, with a reference.
    prov: Ptr<OSSL_PROVIDER>,
    /// The algorithm's dispatch table, which a child is given as its parent's.
    dispatch: Ptr<OSSL_DISPATCH>,
    funcs: Funcs,
}

impl Rand {
    /// The provider's context, which the provider functions take.
    fn provider_ctx(&self) -> *mut c_void {
        // SAFETY: the method holds a reference to its live provider.
        unsafe { crate::provider::OSSL_PROVIDER_get0_provider_ctx(self.prov.0) }
    }
}

handle_type!(EVP_RAND => Rand);

impl Drop for Rand {
    fn drop(&mut self) {
        // SAFETY: the provider reference the method holds.
        unsafe { OSSL_PROVIDER::free(self.prov.0) };
    }
}

/// A dispatch table's function as the type its id stands for.
///
/// # Safety
/// `F` is the function pointer type `f` really has.
unsafe fn cast<F: Copy>(f: AnyFn) -> F {
    // SAFETY: the caller's guarantee; function pointers all have one size.
    unsafe { core::mem::transmute_copy(&f) }
}

/// `evp_rand_from_algorithm`: a random method from the provider's algorithm, with one
/// reference, or NULL with an error.
///
/// # Safety
/// `algo`'s names, description, and table are the provider's, valid while it lives; `prov` is
/// a live provider.
unsafe fn from_algorithm(
    name_id: u32,
    algo: &OSSL_ALGORITHM,
    prov: *mut OSSL_PROVIDER,
) -> *mut c_void {
    const F: &str = "evp_rand_from_algorithm";
    // SAFETY: the caller's guarantee.
    let names = unsafe { CStr::from_ptr(algo.algorithm_names) }.to_bytes();
    let first = names.split(|&c| c == b':').next().unwrap_or(names);
    let Ok(type_name) = CString::new(first) else {
        err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, F);
        return ptr::null_mut();
    };
    let mut funcs = Funcs::default();
    let (mut fnrandcnt, mut fnctxcnt, mut fnlockcnt, mut fnenablelockcnt) = (0, 0, 0, 0);
    let mut at = algo.implementation;
    // SAFETY: the caller's guarantee: the table is ended by a zero id.
    while let Some(d) = unsafe { at.as_ref() } {
        if d.function_id == 0 {
            break;
        }
        at = at.wrapping_add(1);
        let Some(f) = d.function else { continue };
        /// Stores `f` as the function its id stands for, the first of each id only.
        macro_rules! set {
            ($field:ident) => {{
                if funcs.$field.is_some() {
                    continue;
                }
                // SAFETY: the provider's guarantee of the function type for this id.
                funcs.$field = Some(unsafe { cast(f) });
            }};
        }
        match d.function_id {
            OSSL_FUNC_RAND_NEWCTX => {
                set!(newctx);
                fnctxcnt += 1;
            }
            OSSL_FUNC_RAND_FREECTX => {
                set!(freectx);
                fnctxcnt += 1;
            }
            OSSL_FUNC_RAND_INSTANTIATE => {
                set!(instantiate);
                fnrandcnt += 1;
            }
            OSSL_FUNC_RAND_UNINSTANTIATE => {
                set!(uninstantiate);
                fnrandcnt += 1;
            }
            OSSL_FUNC_RAND_GENERATE => {
                set!(generate);
                fnrandcnt += 1;
            }
            OSSL_FUNC_RAND_RESEED => set!(reseed),
            OSSL_FUNC_RAND_NONCE => set!(nonce),
            OSSL_FUNC_RAND_ENABLE_LOCKING => {
                set!(enable_locking);
                fnenablelockcnt += 1;
            }
            OSSL_FUNC_RAND_LOCK => {
                set!(lock);
                fnlockcnt += 1;
            }
            OSSL_FUNC_RAND_UNLOCK => {
                set!(unlock);
                fnlockcnt += 1;
            }
            OSSL_FUNC_RAND_GETTABLE_PARAMS => set!(gettable_params),
            OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS => set!(gettable_ctx_params),
            OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS => set!(settable_ctx_params),
            OSSL_FUNC_RAND_GET_PARAMS => set!(get_params),
            OSSL_FUNC_RAND_GET_CTX_PARAMS => {
                set!(get_ctx_params);
                fnctxcnt += 1;
            }
            OSSL_FUNC_RAND_SET_CTX_PARAMS => set!(set_ctx_params),
            OSSL_FUNC_RAND_VERIFY_ZEROIZATION => set!(verify_zeroization),
            OSSL_FUNC_RAND_GET_SEED => set!(get_seed),
            OSSL_FUNC_RAND_CLEAR_SEED => set!(clear_seed),
            _ => {}
        }
    }
    if fnrandcnt != 3 || fnctxcnt != 3 || fnenablelockcnt > 1 || (fnlockcnt != 0 && fnlockcnt != 2)
    {
        err::raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS, F);
        return ptr::null_mut();
    }
    // SAFETY: the caller's live provider; the method holds the reference.
    if !unsafe { OSSL_PROVIDER::up_ref(prov) } {
        err::raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR, F);
        return ptr::null_mut();
    }
    EVP_RAND::new_handle(Rand {
        name_id,
        type_name,
        description: Ptr(algo.algorithm_description.cast_mut()),
        prov: Ptr(prov),
        dispatch: Ptr(algo.implementation.cast_mut()),
        funcs,
    })
    .cast()
}

/// Adds a reference to a random method in a store.
unsafe fn up_ref(m: *mut c_void) {
    // SAFETY: a live method.
    unsafe { EVP_RAND::up_ref(m.cast()) };
}

/// Drops a reference to a random method in a store.
unsafe fn free(m: *mut c_void) {
    // SAFETY: a reference the store held.
    unsafe { EVP_RAND::free(m.cast()) };
}

/// Random methods to fetching.
static RANDS: Kind = Kind {
    operation: OSSL_OP_RAND,
    style: crate::evp::fetch::Style::Evp,
    from_algorithm,
    up_ref,
    free,
};

/// The method behind `rand`, or `None` for NULL.
///
/// # Safety
/// `rand` is NULL or a live random method.
unsafe fn method<'a>(rand: *const EVP_RAND) -> Option<&'a Rand> {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_RAND::get(rand) }
}

/// A C string argument, `None` for NULL.
///
/// # Safety
/// `s` is NULL or a string.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a CStr> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) })
}

ffi_export! {
    /// The random algorithm `algorithm` from the providers of `libctx` (the default context for
    /// NULL) that best matches `properties`, with a reference; NULL with an error if none does.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `algorithm` and `properties` are NULL or
    /// strings.
    pub unsafe extern "C" fn EVP_RAND_fetch(libctx: *mut OSSL_LIB_CTX, algorithm: *const c_char, properties: *const c_char) -> *mut EVP_RAND
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let name = unsafe { text(algorithm) };
        // SAFETY: as above.
        let props = unsafe { text(properties) };
        // SAFETY: the caller's guarantee.
        unsafe { fetch::fetch(libctx, &RANDS, name, props) }.cast()
    }
}

ffi_export! {
    /// Adds a reference. Returns 1, for NULL too (which has none to add).
    ///
    /// # Safety
    /// `rand` is NULL or a live random method.
    pub unsafe extern "C" fn EVP_RAND_up_ref(rand: *mut EVP_RAND) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if unsafe { method(rand) }.is_some() {
            // SAFETY: as above.
            unsafe { EVP_RAND::up_ref(rand) };
        }
        1
    }
}

ffi_export! {
    /// Drops a reference; NULL does nothing.
    ///
    /// # Safety
    /// `rand` is NULL or a random method the caller holds, not used afterwards.
    pub unsafe extern "C" fn EVP_RAND_free(rand: *mut EVP_RAND)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if unsafe { method(rand) }.is_some() {
            // SAFETY: as above.
            unsafe { EVP_RAND::free(rand) };
        }
    }
}

ffi_export! {
    /// The algorithm's first name, as its provider gave it; NULL for NULL.
    ///
    /// # Safety
    /// `rand` is NULL or a live random method.
    pub unsafe extern "C" fn EVP_RAND_get0_name(rand: *const EVP_RAND) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(rand) }.map_or(ptr::null(), |m| m.type_name.as_ptr())
    }
}

ffi_export! {
    /// The provider's description of the algorithm, or NULL.
    ///
    /// # Safety
    /// `rand` is NULL or a live random method.
    pub unsafe extern "C" fn EVP_RAND_get0_description(rand: *const EVP_RAND) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(rand) }.map_or(ptr::null(), |m| m.description.0.cast_const())
    }
}

ffi_export! {
    /// The provider the method came from (NULL for NULL).
    ///
    /// # Safety
    /// `rand` is NULL or a live random method.
    pub unsafe extern "C" fn EVP_RAND_get0_provider(rand: *const EVP_RAND) -> *const OSSL_PROVIDER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(rand) }.map_or(ptr::null(), |m| m.prov.0.cast_const())
    }
}

ffi_export! {
    /// Whether `name` is one of the algorithm's names. 0 for NULL.
    ///
    /// # Safety
    /// `rand` is NULL or a live random method; `name` is NULL or a string.
    pub unsafe extern "C" fn EVP_RAND_is_a(rand: *const EVP_RAND, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(rand) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        let n = unsafe { text(name) }.map_or(&b""[..], CStr::to_bytes);
        c_int::from(fetch::number_in(m.prov.0, n) == m.name_id)
    }
}

/// A names callback.
type NameFn = unsafe extern "C" fn(*const c_char, *mut c_void);

ffi_export! {
    /// Calls `fn_` with each of the algorithm's names. Returns 1 if it has any (0 for NULL).
    ///
    /// # Safety
    /// `rand` is NULL or a live random method; `fn_` is a function of the documented type.
    pub unsafe extern "C" fn EVP_RAND_names_do_all(rand: *const EVP_RAND, fn_: Option<NameFn>, data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(rand) }) else { return 0 };
        let names = fetch::c_names_of(m.prov.0, m.name_id);
        for &n in &names {
            if let Some(f) = fn_ {
                // SAFETY: the caller's callback with a string the context keeps, and its data.
                unsafe { f(n, data) };
            }
        }
        c_int::from(!names.is_empty())
    }
}

/// `EVP_RAND_do_all_provided`'s callback.
type DoAllFn = unsafe extern "C" fn(*mut EVP_RAND, *mut c_void);

ffi_export! {
    /// Calls `fn_` with each random method the active providers of `libctx` offer.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `fn_` is a function of the documented type.
    pub unsafe extern "C" fn EVP_RAND_do_all_provided(libctx: *mut OSSL_LIB_CTX, fn_: Option<DoAllFn>, arg: *mut c_void)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let all = unsafe { fetch::all(libctx, &RANDS) };
        for m in &all {
            if let Some(f) = fn_ {
                // SAFETY: the caller's callback with a method held for the call.
                unsafe { f(m.as_ptr().cast(), arg) };
            }
        }
    }
}

ffi_export! {
    /// Asks the algorithm for `params`: its result, or 1 when it has no `get_params` (0 for
    /// NULL).
    ///
    /// # Safety
    /// `rand` is NULL or a live random method; `params` is an array the algorithm may fill.
    pub unsafe extern "C" fn EVP_RAND_get_params(rand: *mut EVP_RAND, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(rand) }) else { return 0 };
        match m.funcs.get_params {
            // SAFETY: the provider's function with the caller's array.
            Some(get) => unsafe { get(params) },
            None => 1,
        }
    }
}

ffi_export! {
    /// The parameters the algorithm can report, or NULL.
    ///
    /// # Safety
    /// `rand` is NULL or a live random method.
    pub unsafe extern "C" fn EVP_RAND_gettable_params(rand: *const EVP_RAND) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(rand) }) else { return ptr::null() };
        match m.funcs.gettable_params {
            // SAFETY: the provider's function with its context.
            Some(f) => unsafe { f(m.provider_ctx()) },
            None => ptr::null(),
        }
    }
}

ffi_export! {
    /// The context parameters the algorithm can report (asked without a context), or NULL.
    ///
    /// # Safety
    /// `rand` is NULL or a live random method.
    pub unsafe extern "C" fn EVP_RAND_gettable_ctx_params(rand: *const EVP_RAND) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(rand) }) else { return ptr::null() };
        match m.funcs.gettable_ctx_params {
            // SAFETY: the provider's function with no context and its own.
            Some(f) => unsafe { f(ptr::null_mut(), m.provider_ctx()) },
            None => ptr::null(),
        }
    }
}

ffi_export! {
    /// The context parameters the algorithm can be given (asked without a context), or NULL.
    ///
    /// # Safety
    /// `rand` is NULL or a live random method.
    pub unsafe extern "C" fn EVP_RAND_settable_ctx_params(rand: *const EVP_RAND) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(rand) }) else { return ptr::null() };
        match m.funcs.settable_ctx_params {
            // SAFETY: the provider's function with no context and its own.
            Some(f) => unsafe { f(ptr::null_mut(), m.provider_ctx()) },
            None => ptr::null(),
        }
    }
}

// -------------------------------------------------------------------------------------------
// EVP_RAND_CTX

/// A random context (`EVP_RAND_CTX`): the method and the parent, each with a reference, and
/// the algorithm's context.
pub(crate) struct RandCtx {
    meth: Ptr<EVP_RAND>,
    parent: Ptr<EVP_RAND_CTX>,
    algctx: Ptr<c_void>,
}

handle_type!(EVP_RAND_CTX => RandCtx);

impl RandCtx {
    fn rand(&self) -> Option<&Rand> {
        // SAFETY: the context holds a reference to its method.
        unsafe { method(self.meth.0) }
    }

    fn funcs(&self) -> Funcs {
        self.rand().map(|m| m.funcs).unwrap_or_default()
    }

    /// `evp_rand_lock`: the algorithm's lock, if it has one.
    fn lock(&self) -> bool {
        match self.funcs().lock {
            // SAFETY: the provider's function with its context.
            Some(lock) => (unsafe { lock(self.algctx.0) }) != 0,
            None => true,
        }
    }

    /// `evp_rand_unlock`.
    fn unlock(&self) {
        if let Some(unlock) = self.funcs().unlock {
            // SAFETY: the provider's function with its context.
            unsafe { unlock(self.algctx.0) };
        }
    }

    /// Runs `f` under the algorithm's lock; `None` if it can't be taken.
    fn locked<R>(&self, f: impl FnOnce(&Self) -> R) -> Option<R> {
        if !self.lock() {
            return None;
        }
        let r = f(self);
        self.unlock();
        Some(r)
    }

    /// `evp_rand_get_ctx_params_locked`.
    fn get_ctx_params(&self, params: *mut OSSL_PARAM) -> c_int {
        match self.funcs().get_ctx_params {
            // SAFETY: the provider's function with its context and the caller's array.
            Some(get) => unsafe { get(self.algctx.0, params) },
            None => 0,
        }
    }

    /// `evp_rand_strength_locked`.
    fn strength(&self) -> c_uint {
        let mut strength: c_uint = 0;
        // SAFETY: a static key and a local.
        let mut params = [
            unsafe {
                OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH.as_ptr(), &raw mut strength)
            },
            end(),
        ];
        if self.get_ctx_params(params.as_mut_ptr()) == 0 {
            return 0;
        }
        strength
    }

    /// `evp_rand_generate_locked`: the output in chunks of at most the request limit,
    /// prediction resistance asked for the first only.
    ///
    /// # Safety
    /// `out` has room for `outlen` octets; `addin` holds `addin_len` (or is NULL).
    unsafe fn generate(
        &self,
        out: *mut c_uchar,
        outlen: usize,
        strength: c_uint,
        prediction_resistance: c_int,
        addin: *const c_uchar,
        addin_len: usize,
    ) -> c_int {
        const F: &str = "evp_rand_generate_locked";
        let mut max_request = 0usize;
        // SAFETY: a static key and a local.
        let mut params = [
            unsafe {
                OSSL_PARAM_construct_size_t(
                    OSSL_RAND_PARAM_MAX_REQUEST.as_ptr(),
                    &raw mut max_request,
                )
            },
            end(),
        ];
        if self.get_ctx_params(params.as_mut_ptr()) == 0 || max_request == 0 {
            err::raise(ERR_LIB_EVP, EVP_R_UNABLE_TO_GET_MAXIMUM_REQUEST_SIZE, F);
            return 0;
        }
        let Some(generate) = self.funcs().generate else {
            return 0;
        };
        let (mut done, mut pr) = (0usize, prediction_resistance);
        while done < outlen {
            let chunk = (outlen - done).min(max_request);
            // SAFETY: the provider's function with its context, room for `chunk` more octets
            // of the caller's, and the caller's additional input.
            if unsafe {
                generate(
                    self.algctx.0,
                    out.wrapping_add(done),
                    chunk,
                    strength,
                    pr,
                    addin,
                    addin_len,
                )
            } == 0
            {
                err::raise(ERR_LIB_EVP, EVP_R_GENERATE_ERROR, F);
                return 0;
            }
            pr = 0;
            done += chunk;
        }
        1
    }
}

impl Drop for RandCtx {
    fn drop(&mut self) {
        if let Some(free) = self.funcs().freectx {
            // SAFETY: the algorithm's context, freed once, by its own function.
            unsafe { free(self.algctx.0) };
        }
        // SAFETY: the method reference the context holds.
        unsafe { EVP_RAND_free(self.meth.0) };
        // SAFETY: the parent reference the context holds, or NULL.
        unsafe { EVP_RAND_CTX_free(self.parent.0) };
    }
}

/// The context behind `ctx`, or `None` for NULL.
///
/// # Safety
/// `ctx` is NULL or a live random context.
unsafe fn context<'a>(ctx: *const EVP_RAND_CTX) -> Option<&'a RandCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_RAND_CTX::get(ctx) }
}

ffi_export! {
    /// A context for `rand` under `parent` (which it holds a reference to, as to `rand`): the
    /// algorithm is given the parent's context and dispatch table. NULL with an error for a
    /// NULL method, or if the algorithm can't make one.
    ///
    /// # Safety
    /// `rand` is NULL or a live random method; `parent` is NULL or a live random context.
    pub unsafe extern "C" fn EVP_RAND_CTX_new(rand: *mut EVP_RAND, parent: *mut EVP_RAND_CTX) -> *mut EVP_RAND_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        const F: &str = "EVP_RAND_CTX_new";
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(rand) }) else {
            err::raise(ERR_LIB_EVP, EVP_R_INVALID_NULL_ALGORITHM, F);
            return ptr::null_mut();
        };
        let (mut parent_ctx, mut parent_dispatch) = (ptr::null_mut(), ptr::null());
        if !parent.is_null() {
            // SAFETY: the caller's guarantee.
            let Some(p) = (unsafe { context(parent) }) else {
                err::raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR, F);
                return ptr::null_mut();
            };
            // SAFETY: as above; the new context holds the reference.
            unsafe { EVP_RAND_CTX::up_ref(parent) };
            parent_ctx = p.algctx.0;
            parent_dispatch = p.rand().map_or(ptr::null(), |pm| pm.dispatch.0.cast_const());
        }
        let algctx = match m.funcs.newctx {
            // SAFETY: the provider's function with its context and the parent's.
            Some(new) => unsafe { new(m.provider_ctx(), parent_ctx, parent_dispatch) },
            None => ptr::null_mut(),
        };
        if algctx.is_null() {
            err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, F);
            // SAFETY: the reference taken above, or NULL.
            unsafe { EVP_RAND_CTX_free(parent) };
            return ptr::null_mut();
        }
        // SAFETY: the caller's live method; the context holds the reference.
        unsafe { EVP_RAND::up_ref(rand) };
        EVP_RAND_CTX::new_handle(RandCtx { meth: Ptr(rand), parent: Ptr(parent), algctx: Ptr(algctx) })
    }
}

ffi_export! {
    /// Drops a reference; with the last, frees the algorithm context and drops the method and
    /// the parent. NULL does nothing.
    ///
    /// # Safety
    /// `ctx` is NULL or a random context the caller holds, not used afterwards.
    pub unsafe extern "C" fn EVP_RAND_CTX_free(ctx: *mut EVP_RAND_CTX)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if unsafe { context(ctx) }.is_some() {
            // SAFETY: as above.
            unsafe { EVP_RAND_CTX::free(ctx) };
        }
    }
}

ffi_export! {
    /// Adds a reference. Returns 1 (0 for NULL, where OpenSSL would crash).
    ///
    /// # Safety
    /// `ctx` is NULL or a live random context.
    pub unsafe extern "C" fn EVP_RAND_CTX_up_ref(ctx: *mut EVP_RAND_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { EVP_RAND_CTX::up_ref(ctx) })
    }
}

ffi_export! {
    /// The context's method (NULL for NULL, where OpenSSL would crash).
    ///
    /// # Safety
    /// `ctx` is NULL or a live random context.
    pub unsafe extern "C" fn EVP_RAND_CTX_get0_rand(ctx: *mut EVP_RAND_CTX) -> *mut EVP_RAND
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(ctx) }.map_or(ptr::null_mut(), |c| c.meth.0)
    }
}

ffi_export! {
    /// Asks the context for `params`, under its lock. 0 for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live random context; `params` is an array the algorithm may fill.
    pub unsafe extern "C" fn EVP_RAND_CTX_get_params(ctx: *mut EVP_RAND_CTX, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        c.locked(|c| c.get_ctx_params(params)).unwrap_or(0)
    }
}

ffi_export! {
    /// Gives the context `params`, under its lock: the algorithm's result, or 1 when it takes
    /// none. 0 for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live random context; `params` is NULL or a parameter array.
    pub unsafe extern "C" fn EVP_RAND_CTX_set_params(ctx: *mut EVP_RAND_CTX, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        c.locked(|c| match c.funcs().set_ctx_params {
            // SAFETY: the provider's function with its context and the caller's array.
            Some(set) => unsafe { set(c.algctx.0, params) },
            None => 1,
        })
        .unwrap_or(0)
    }
}

ffi_export! {
    /// The parameters the context can report, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live random context.
    pub unsafe extern "C" fn EVP_RAND_CTX_gettable_params(ctx: *mut EVP_RAND_CTX) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null() };
        let Some(m) = c.rand() else { return ptr::null() };
        match m.funcs.gettable_ctx_params {
            // SAFETY: the provider's function with the contexts.
            Some(f) => unsafe { f(c.algctx.0, m.provider_ctx()) },
            None => ptr::null(),
        }
    }
}

ffi_export! {
    /// The parameters the context can be given, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live random context.
    pub unsafe extern "C" fn EVP_RAND_CTX_settable_params(ctx: *mut EVP_RAND_CTX) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null() };
        let Some(m) = c.rand() else { return ptr::null() };
        match m.funcs.settable_ctx_params {
            // SAFETY: the provider's function with the contexts.
            Some(f) => unsafe { f(c.algctx.0, m.provider_ctx()) },
            None => ptr::null(),
        }
    }
}

ffi_export! {
    /// Makes the context lock itself (and its parents) for use by many threads: 1, or 0 with
    /// `EVP_R_LOCKING_NOT_SUPPORTED` if the algorithm can't. 0 for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live random context.
    pub unsafe extern "C" fn EVP_RAND_enable_locking(ctx: *mut EVP_RAND_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        match c.funcs().enable_locking {
            // SAFETY: the provider's function with its context.
            Some(enable) => unsafe { enable(c.algctx.0) },
            None => {
                err::raise(ERR_LIB_EVP, EVP_R_LOCKING_NOT_SUPPORTED, "EVP_RAND_enable_locking");
                0
            }
        }
    }
}

ffi_export! {
    /// Instantiates the generator at `strength` (or more) with the personalization string,
    /// after setting `params`, under its lock. 0 for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live random context; `pstr` holds `pstr_len` octets (or is NULL);
    /// `params` is NULL or a parameter array.
    pub unsafe extern "C" fn EVP_RAND_instantiate(ctx: *mut EVP_RAND_CTX, strength: c_uint, prediction_resistance: c_int, pstr: *const c_uchar, pstr_len: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        c.locked(|c| match c.funcs().instantiate {
            // SAFETY: the provider's function with its context and the caller's arguments.
            Some(f) => unsafe { f(c.algctx.0, strength, prediction_resistance, pstr, pstr_len, params) },
            None => 0,
        })
        .unwrap_or(0)
    }
}

ffi_export! {
    /// Uninstantiates the generator, under its lock. 0 for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live random context.
    pub unsafe extern "C" fn EVP_RAND_uninstantiate(ctx: *mut EVP_RAND_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        c.locked(|c| match c.funcs().uninstantiate {
            // SAFETY: the provider's function with its context.
            Some(f) => unsafe { f(c.algctx.0) },
            None => 0,
        })
        .unwrap_or(0)
    }
}

ffi_export! {
    /// Fills `out` with `outlen` octets at `strength`, in chunks of at most the generator's
    /// request limit, under its lock. 0 for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live random context; `out` has room for `outlen` octets; `addin`
    /// holds `addin_len` octets (or is NULL).
    pub unsafe extern "C" fn EVP_RAND_generate(ctx: *mut EVP_RAND_CTX, out: *mut c_uchar, outlen: usize, strength: c_uint, prediction_resistance: c_int, addin: *const c_uchar, addin_len: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        c.locked(|c| unsafe { c.generate(out, outlen, strength, prediction_resistance, addin, addin_len) })
            .unwrap_or(0)
    }
}

ffi_export! {
    /// Reseeds the generator (from `ent` if given), under its lock: 1 when the algorithm can't
    /// reseed. 0 for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live random context; `ent` and `addin` hold their lengths (or are
    /// NULL).
    pub unsafe extern "C" fn EVP_RAND_reseed(ctx: *mut EVP_RAND_CTX, prediction_resistance: c_int, ent: *const c_uchar, ent_len: usize, addin: *const c_uchar, addin_len: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        c.locked(|c| match c.funcs().reseed {
            // SAFETY: the provider's function with its context and the caller's arguments.
            Some(f) => unsafe { f(c.algctx.0, prediction_resistance, ent, ent_len, addin, addin_len) },
            None => 1,
        })
        .unwrap_or(0)
    }
}

ffi_export! {
    /// The generator's strength in bits (0 if it can't say, or for NULL), under its lock.
    ///
    /// # Safety
    /// `ctx` is NULL or a live random context.
    pub unsafe extern "C" fn EVP_RAND_get_strength(ctx: *mut EVP_RAND_CTX) -> c_uint
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        c.locked(RandCtx::strength).unwrap_or(0)
    }
}

ffi_export! {
    /// Fills `out` with a nonce of `outlen` octets: the algorithm's nonce (at its strength), or
    /// output. 0 with `ERR_R_PASSED_NULL_PARAMETER` for a NULL context or output, or none.
    ///
    /// # Safety
    /// `ctx` is NULL or a live random context; `out` is NULL or has room for `outlen` octets.
    pub unsafe extern "C" fn EVP_RAND_nonce(ctx: *mut EVP_RAND_CTX, out: *mut c_uchar, outlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let c = unsafe { context(ctx) };
        let Some(c) = c.filter(|_| !out.is_null() && outlen != 0) else {
            err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, "EVP_RAND_nonce");
            return 0;
        };
        c.locked(|c| {
            let strength = c.strength();
            match c.funcs().nonce {
                // SAFETY: the provider's function with its context and the caller's room.
                Some(f) => c_int::from(unsafe { f(c.algctx.0, out, strength, outlen, outlen) } > 0),
                // SAFETY: the caller's room.
                None => unsafe { c.generate(out, outlen, strength, 0, ptr::null(), 0) },
            }
        })
        .unwrap_or(0)
    }
}

ffi_export! {
    /// The generator's state (`EVP_RAND_STATE_*`): `EVP_RAND_STATE_ERROR` if it can't say (or
    /// for NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live random context.
    pub unsafe extern "C" fn EVP_RAND_get_state(ctx: *mut EVP_RAND_CTX) -> c_int
    where failure = EVP_RAND_STATE_ERROR as c_int, library = ERR_LIB_EVP
    {
        let mut state: c_int = 0;
        // SAFETY: a static key and a local.
        let mut params = [unsafe { OSSL_PARAM_construct_int(OSSL_RAND_PARAM_STATE.as_ptr(), &raw mut state) }, end()];
        // SAFETY: the caller's guarantee; a local array.
        if unsafe { EVP_RAND_CTX_get_params(ctx, params.as_mut_ptr()) } == 0 {
            return EVP_RAND_STATE_ERROR as c_int;
        }
        state
    }
}

ffi_export! {
    /// Whether the generator's secrets are all zero (after uninstantiating), under its lock: 0
    /// if the algorithm can't say, or for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live random context.
    pub unsafe extern "C" fn EVP_RAND_verify_zeroization(ctx: *mut EVP_RAND_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        c.locked(|c| match c.funcs().verify_zeroization {
            // SAFETY: the provider's function with its context.
            Some(f) => unsafe { f(c.algctx.0) },
            None => 0,
        })
        .unwrap_or(0)
    }
}

/// `evp_rand_can_seed`: whether the context's algorithm gives seeds.
///
/// # Safety
/// `ctx` is NULL or a live random context.
#[allow(
    dead_code,
    reason = "the RAND layer's seed source (step 3.7b) calls it"
)]
pub(crate) unsafe fn can_seed(ctx: *const EVP_RAND_CTX) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { context(ctx) }.is_some_and(|c| c.funcs().get_seed.is_some())
}

/// `evp_rand_get_seed`: a seed of `min_len` to `max_len` octets with `entropy` bits from the
/// context, under its lock, into `*buffer` (which `clear_seed` gives back); its length, or 0.
///
/// # Safety
/// `ctx` is NULL or a live random context; `adin` holds `adin_len` octets (or is NULL).
#[allow(
    dead_code,
    reason = "the RAND layer's seed source (step 3.7b) calls it"
)]
pub(crate) unsafe fn get_seed(
    ctx: *const EVP_RAND_CTX,
    buffer: *mut *mut c_uchar,
    entropy: c_int,
    min_len: usize,
    max_len: usize,
    adin: *const c_uchar,
    adin_len: usize,
) -> usize {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    c.locked(|c| match c.funcs().get_seed {
        // SAFETY: the provider's function with its context and the caller's arguments.
        Some(f) => unsafe {
            f(
                c.algctx.0, buffer, entropy, min_len, max_len, 0, adin, adin_len,
            )
        },
        None => 0,
    })
    .unwrap_or(0)
}

/// `evp_rand_clear_seed`: gives a seed back to the context that made it, under its lock.
///
/// # Safety
/// `ctx` is NULL or a live random context; `buffer` is a seed of `len` octets from it.
#[allow(
    dead_code,
    reason = "the RAND layer's seed source (step 3.7b) calls it"
)]
pub(crate) unsafe fn clear_seed(ctx: *const EVP_RAND_CTX, buffer: *mut c_uchar, len: usize) {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(ctx) }) else {
        return;
    };
    c.locked(|c| {
        if let Some(f) = c.funcs().clear_seed {
            // SAFETY: the provider's function with its context and its own seed.
            unsafe { f(c.algctx.0, buffer, len) };
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: the method accessors with a NULL method, and the context functions
    /// with a NULL context, fail (the reference dereferences NULL).
    #[test]
    fn null_methods_and_contexts_are_refused() {
        let (m, c): (*mut EVP_RAND, *mut EVP_RAND_CTX) = (ptr::null_mut(), ptr::null_mut());
        let mut out = [0u8; 4];
        // SAFETY: NULL is the case under test.
        assert!(unsafe { EVP_RAND_get0_name(m) }.is_null());
        // SAFETY: NULL is the case under test.
        assert!(unsafe { EVP_RAND_get0_description(m) }.is_null());
        // SAFETY: NULL is the case under test.
        assert!(unsafe { EVP_RAND_get0_provider(m) }.is_null());
        // SAFETY: NULL is the case under test.
        assert_eq!(unsafe { EVP_RAND_get_params(m, ptr::null_mut()) }, 0);
        // SAFETY: NULL is the case under test.
        assert!(unsafe { EVP_RAND_gettable_params(m) }.is_null());
        // SAFETY: NULL is the case under test.
        assert!(unsafe { EVP_RAND_gettable_ctx_params(m) }.is_null());
        // SAFETY: NULL is the case under test.
        assert!(unsafe { EVP_RAND_settable_ctx_params(m) }.is_null());
        assert_eq!(
            // SAFETY: NULL is the case under test.
            unsafe { EVP_RAND_names_do_all(m, None, ptr::null_mut()) },
            0
        );
        // SAFETY: NULL is the case under test.
        assert_eq!(unsafe { EVP_RAND_CTX_up_ref(c) }, 0);
        // SAFETY: NULL is the case under test.
        assert!(unsafe { EVP_RAND_CTX_get0_rand(c) }.is_null());
        // SAFETY: NULL is the case under test.
        assert_eq!(unsafe { EVP_RAND_CTX_get_params(c, ptr::null_mut()) }, 0);
        // SAFETY: NULL is the case under test.
        assert_eq!(unsafe { EVP_RAND_CTX_set_params(c, ptr::null()) }, 0);
        // SAFETY: NULL is the case under test.
        assert!(unsafe { EVP_RAND_CTX_gettable_params(c) }.is_null());
        // SAFETY: NULL is the case under test.
        assert!(unsafe { EVP_RAND_CTX_settable_params(c) }.is_null());
        // SAFETY: NULL is the case under test.
        assert_eq!(unsafe { EVP_RAND_enable_locking(c) }, 0);
        assert_eq!(
            // SAFETY: NULL is the case under test.
            unsafe { EVP_RAND_instantiate(c, 0, 0, ptr::null(), 0, ptr::null()) },
            0
        );
        // SAFETY: NULL is the case under test.
        assert_eq!(unsafe { EVP_RAND_uninstantiate(c) }, 0);
        assert_eq!(
            // SAFETY: NULL is the case under test.
            unsafe { EVP_RAND_generate(c, out.as_mut_ptr(), 4, 0, 0, ptr::null(), 0) },
            0
        );
        assert_eq!(
            // SAFETY: NULL is the case under test.
            unsafe { EVP_RAND_reseed(c, 0, ptr::null(), 0, ptr::null(), 0) },
            0
        );
        // SAFETY: NULL is the case under test.
        assert_eq!(unsafe { EVP_RAND_get_strength(c) }, 0);
        assert_eq!(
            // SAFETY: NULL is the case under test.
            unsafe { EVP_RAND_get_state(c) },
            EVP_RAND_STATE_ERROR as c_int
        );
        // SAFETY: NULL is the case under test.
        assert_eq!(unsafe { EVP_RAND_verify_zeroization(c) }, 0);
        crate::err::take_all();
    }
}
