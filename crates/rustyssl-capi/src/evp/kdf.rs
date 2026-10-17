//! KDF methods and contexts (`EVP_KDF(3)`; `kdf_meth.c`, `kdf_lib.c`): an `EVP_KDF` made from
//! a provider's KDF algorithm (`evp_kdf_from_algorithm`), fetched by name and properties, and an
//! `EVP_KDF_CTX` running it: parameters, derivation, reset, size, and copies.
//!
//! As in OpenSSL, a KDF algorithm must offer `newctx`, `freectx`, and `derive`. The functions
//! given a NULL method or context fail here where the reference would crash
//! (docs/DEVIATIONS.md); those the reference lets take NULL (`EVP_KDF_CTX_new`, `_free`,
//! `_dup`, `_reset`, `_get_kdf_size`, `EVP_KDF_derive`) do as it does.

use core::ffi::{CStr, c_char, c_int, c_uchar, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    ERR_LIB_EVP, ERR_R_EVP_LIB, EVP_KDF, EVP_KDF_CTX, EVP_MD, EVP_R_INVALID_PROVIDER_FUNCTIONS,
    EVP_R_PARAMETER_TOO_LARGE, OSSL_ALGORITHM, OSSL_FUNC_KDF_DERIVE, OSSL_FUNC_KDF_DUPCTX,
    OSSL_FUNC_KDF_FREECTX, OSSL_FUNC_KDF_GET_CTX_PARAMS, OSSL_FUNC_KDF_GET_PARAMS,
    OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, OSSL_FUNC_KDF_GETTABLE_PARAMS, OSSL_FUNC_KDF_NEWCTX,
    OSSL_FUNC_KDF_RESET, OSSL_FUNC_KDF_SET_CTX_PARAMS, OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
    OSSL_KDF_PARAM_DIGEST, OSSL_KDF_PARAM_ITER, OSSL_KDF_PARAM_PASSWORD, OSSL_KDF_PARAM_PKCS5,
    OSSL_KDF_PARAM_SALT, OSSL_KDF_PARAM_SCRYPT_MAXMEM, OSSL_KDF_PARAM_SCRYPT_N,
    OSSL_KDF_PARAM_SCRYPT_P, OSSL_KDF_PARAM_SCRYPT_R, OSSL_KDF_PARAM_SIZE, OSSL_LIB_CTX,
    OSSL_OP_KDF, OSSL_PARAM, OSSL_PROVIDER,
};

use super::fetch::{self, Kind};
use crate::err;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::params::{
    OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_uint64,
    OSSL_PARAM_construct_utf8_string, construct, end,
};
use crate::provider::Ptr;

type AnyFn = unsafe extern "C" fn();
type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type DupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type ResetFn = unsafe extern "C" fn(*mut c_void);
type DeriveFn = unsafe extern "C" fn(*mut c_void, *mut c_uchar, usize, *const OSSL_PARAM) -> c_int;
type GetParamsFn = unsafe extern "C" fn(*mut OSSL_PARAM) -> c_int;
type GettableFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type GetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type SetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type CtxParamsListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;

/// A KDF algorithm's functions, as its dispatch table gave them.
#[derive(Default, Clone, Copy)]
struct Funcs {
    newctx: Option<NewCtxFn>,
    dupctx: Option<DupCtxFn>,
    freectx: Option<FreeCtxFn>,
    reset: Option<ResetFn>,
    derive: Option<DeriveFn>,
    get_params: Option<GetParamsFn>,
    gettable_params: Option<GettableFn>,
    get_ctx_params: Option<GetCtxParamsFn>,
    set_ctx_params: Option<SetCtxParamsFn>,
    gettable_ctx_params: Option<CtxParamsListFn>,
    settable_ctx_params: Option<CtxParamsListFn>,
}

/// A KDF method (`EVP_KDF`).
pub(crate) struct Kdf {
    name_id: u32,
    type_name: CString,
    /// The provider's description, a static string of its, or NULL.
    description: Ptr<c_char>,
    /// The provider, with a reference.
    prov: Ptr<OSSL_PROVIDER>,
    funcs: Funcs,
}

impl Kdf {
    /// The provider's context, which the provider functions take.
    fn provider_ctx(&self) -> *mut c_void {
        // SAFETY: the method holds a reference to its live provider.
        unsafe { crate::provider::OSSL_PROVIDER_get0_provider_ctx(self.prov.0) }
    }
}

handle_type!(EVP_KDF => Kdf);

impl Drop for Kdf {
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

/// `evp_kdf_from_algorithm`: a KDF method from the provider's algorithm, with one reference,
/// or NULL with an error.
///
/// # Safety
/// `algo`'s names, description, and table are the provider's, valid while it lives; `prov` is
/// a live provider.
unsafe fn from_algorithm(
    name_id: u32,
    algo: &OSSL_ALGORITHM,
    prov: *mut OSSL_PROVIDER,
) -> *mut c_void {
    const F: &str = "evp_kdf_from_algorithm";
    // SAFETY: the caller's guarantee.
    let names = unsafe { CStr::from_ptr(algo.algorithm_names) }.to_bytes();
    let first = names.split(|&c| c == b':').next().unwrap_or(names);
    let Ok(type_name) = CString::new(first) else {
        err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, F);
        return ptr::null_mut();
    };
    let mut funcs = Funcs::default();
    let (mut fnkdfcnt, mut fnctxcnt) = (0, 0);
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
            OSSL_FUNC_KDF_NEWCTX => {
                set!(newctx);
                fnctxcnt += 1;
            }
            OSSL_FUNC_KDF_DUPCTX => set!(dupctx),
            OSSL_FUNC_KDF_FREECTX => {
                set!(freectx);
                fnctxcnt += 1;
            }
            OSSL_FUNC_KDF_RESET => set!(reset),
            OSSL_FUNC_KDF_DERIVE => {
                set!(derive);
                fnkdfcnt += 1;
            }
            OSSL_FUNC_KDF_GETTABLE_PARAMS => set!(gettable_params),
            OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS => set!(gettable_ctx_params),
            OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS => set!(settable_ctx_params),
            OSSL_FUNC_KDF_GET_PARAMS => set!(get_params),
            OSSL_FUNC_KDF_GET_CTX_PARAMS => set!(get_ctx_params),
            OSSL_FUNC_KDF_SET_CTX_PARAMS => set!(set_ctx_params),
            _ => {}
        }
    }
    if fnkdfcnt != 1 || fnctxcnt != 2 {
        err::raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS, F);
        return ptr::null_mut();
    }
    // SAFETY: the caller's live provider; the method holds the reference.
    if !unsafe { OSSL_PROVIDER::up_ref(prov) } {
        return ptr::null_mut();
    }
    EVP_KDF::new_handle(Kdf {
        name_id,
        type_name,
        description: Ptr(algo.algorithm_description.cast_mut()),
        prov: Ptr(prov),
        funcs,
    })
    .cast()
}

/// Adds a reference to a KDF method in a store.
unsafe fn up_ref(m: *mut c_void) {
    // SAFETY: a live method.
    unsafe { EVP_KDF::up_ref(m.cast()) };
}

/// Drops a reference to a KDF method in a store.
unsafe fn free(m: *mut c_void) {
    // SAFETY: a reference the store held.
    unsafe { EVP_KDF::free(m.cast()) };
}

/// KDF methods to fetching.
static KDFS: Kind = Kind {
    operation: OSSL_OP_KDF,
    style: crate::evp::fetch::Style::Evp,
    from_algorithm,
    up_ref,
    free,
};

/// The method behind `kdf`, or `None` for NULL.
///
/// # Safety
/// `kdf` is NULL or a live KDF method.
unsafe fn method<'a>(kdf: *const EVP_KDF) -> Option<&'a Kdf> {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_KDF::get(kdf) }
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
    /// The KDF `algorithm` from the providers of `libctx` (the default context for NULL) that
    /// best matches `properties`, with a reference; NULL with an error if none does.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `algorithm` and `properties` are NULL or
    /// strings.
    pub unsafe extern "C" fn EVP_KDF_fetch(libctx: *mut OSSL_LIB_CTX, algorithm: *const c_char, properties: *const c_char) -> *mut EVP_KDF
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let name = unsafe { text(algorithm) };
        // SAFETY: as above.
        let props = unsafe { text(properties) };
        // SAFETY: the caller's guarantee.
        unsafe { fetch::fetch(libctx, &KDFS, name, props) }.cast()
    }
}

ffi_export! {
    /// Adds a reference. Returns 1 (0 for NULL, where OpenSSL would crash).
    ///
    /// # Safety
    /// `kdf` is NULL or a live KDF method.
    pub unsafe extern "C" fn EVP_KDF_up_ref(kdf: *mut EVP_KDF) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if unsafe { method(kdf) }.is_none() {
            return 0;
        }
        // SAFETY: as above.
        unsafe { EVP_KDF::up_ref(kdf) };
        1
    }
}

ffi_export! {
    /// Drops a reference; NULL does nothing.
    ///
    /// # Safety
    /// `kdf` is NULL or a KDF method the caller holds, not used afterwards.
    pub unsafe extern "C" fn EVP_KDF_free(kdf: *mut EVP_KDF)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if unsafe { method(kdf) }.is_some() {
            // SAFETY: as above.
            unsafe { EVP_KDF::free(kdf) };
        }
    }
}

ffi_export! {
    /// The algorithm's first name, as its provider gave it; NULL for NULL.
    ///
    /// # Safety
    /// `kdf` is NULL or a live KDF method.
    pub unsafe extern "C" fn EVP_KDF_get0_name(kdf: *const EVP_KDF) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(kdf) }.map_or(ptr::null(), |m| m.type_name.as_ptr())
    }
}

ffi_export! {
    /// The provider's description of the algorithm, or NULL.
    ///
    /// # Safety
    /// `kdf` is NULL or a live KDF method.
    pub unsafe extern "C" fn EVP_KDF_get0_description(kdf: *const EVP_KDF) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(kdf) }.map_or(ptr::null(), |m| m.description.0.cast_const())
    }
}

ffi_export! {
    /// The provider the method came from (NULL for NULL).
    ///
    /// # Safety
    /// `kdf` is NULL or a live KDF method.
    pub unsafe extern "C" fn EVP_KDF_get0_provider(kdf: *const EVP_KDF) -> *const OSSL_PROVIDER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(kdf) }.map_or(ptr::null(), |m| m.prov.0.cast_const())
    }
}

ffi_export! {
    /// Whether `name` is one of the algorithm's names. 0 for NULL.
    ///
    /// # Safety
    /// `kdf` is NULL or a live KDF method; `name` is NULL or a string.
    pub unsafe extern "C" fn EVP_KDF_is_a(kdf: *const EVP_KDF, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(kdf) }) else { return 0 };
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
    /// `kdf` is NULL or a live KDF method; `fn_` is a function of the documented type.
    pub unsafe extern "C" fn EVP_KDF_names_do_all(kdf: *const EVP_KDF, fn_: Option<NameFn>, data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(kdf) }) else { return 0 };
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

/// `EVP_KDF_do_all_provided`'s callback.
type DoAllFn = unsafe extern "C" fn(*mut EVP_KDF, *mut c_void);

ffi_export! {
    /// Calls `fn_` with each KDF method the active providers of `libctx` offer.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `fn_` is a function of the documented type.
    pub unsafe extern "C" fn EVP_KDF_do_all_provided(libctx: *mut OSSL_LIB_CTX, fn_: Option<DoAllFn>, arg: *mut c_void)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let all = unsafe { fetch::all(libctx, &KDFS) };
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
    /// `kdf` is NULL or a live KDF method; `params` is an array the algorithm may fill.
    pub unsafe extern "C" fn EVP_KDF_get_params(kdf: *mut EVP_KDF, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(kdf) }) else { return 0 };
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
    /// `kdf` is NULL or a live KDF method.
    pub unsafe extern "C" fn EVP_KDF_gettable_params(kdf: *const EVP_KDF) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(kdf) }) else { return ptr::null() };
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
    /// `kdf` is NULL or a live KDF method.
    pub unsafe extern "C" fn EVP_KDF_gettable_ctx_params(kdf: *const EVP_KDF) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(kdf) }) else { return ptr::null() };
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
    /// `kdf` is NULL or a live KDF method.
    pub unsafe extern "C" fn EVP_KDF_settable_ctx_params(kdf: *const EVP_KDF) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(kdf) }) else { return ptr::null() };
        match m.funcs.settable_ctx_params {
            // SAFETY: the provider's function with no context and its own.
            Some(f) => unsafe { f(ptr::null_mut(), m.provider_ctx()) },
            None => ptr::null(),
        }
    }
}

// -------------------------------------------------------------------------------------------
// EVP_KDF_CTX

/// A KDF context (`EVP_KDF_CTX`): the method, with a reference, and the algorithm's context.
pub(crate) struct KdfCtx {
    meth: Ptr<EVP_KDF>,
    algctx: Ptr<c_void>,
}

handle_type!(EVP_KDF_CTX => KdfCtx);

impl KdfCtx {
    fn kdf(&self) -> Option<&Kdf> {
        // SAFETY: the context holds a reference to its method.
        unsafe { method(self.meth.0) }
    }
}

impl Drop for KdfCtx {
    fn drop(&mut self) {
        if let Some(free) = self.kdf().and_then(|m| m.funcs.freectx) {
            // SAFETY: the algorithm's context, freed once, by its own function.
            unsafe { free(self.algctx.0) };
        }
        // SAFETY: the method reference the context holds.
        unsafe { EVP_KDF_free(self.meth.0) };
    }
}

/// The context behind `ctx`, or `None` for NULL.
///
/// # Safety
/// `ctx` is NULL or a live KDF context.
unsafe fn context<'a>(ctx: *const EVP_KDF_CTX) -> Option<&'a KdfCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_KDF_CTX::get(ctx) }
}

ffi_export! {
    /// A context for `kdf`, holding a reference to it; NULL for NULL, or with an error if the
    /// algorithm can't make one.
    ///
    /// # Safety
    /// `kdf` is NULL or a live KDF method.
    pub unsafe extern "C" fn EVP_KDF_CTX_new(kdf: *mut EVP_KDF) -> *mut EVP_KDF_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(kdf) }) else { return ptr::null_mut() };
        let algctx = match m.funcs.newctx {
            // SAFETY: the provider's function with its context.
            Some(new) => unsafe { new(m.provider_ctx()) },
            None => ptr::null_mut(),
        };
        if algctx.is_null() {
            err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, "EVP_KDF_CTX_new");
            return ptr::null_mut();
        }
        // SAFETY: the caller's live method; the context holds the reference.
        unsafe { EVP_KDF::up_ref(kdf) };
        EVP_KDF_CTX::new_handle(KdfCtx { meth: Ptr(kdf), algctx: Ptr(algctx) })
    }
}

ffi_export! {
    /// Frees the context and its algorithm context; NULL does nothing.
    ///
    /// # Safety
    /// `ctx` is NULL or a live KDF context, not used afterwards.
    pub unsafe extern "C" fn EVP_KDF_CTX_free(ctx: *mut EVP_KDF_CTX)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if unsafe { context(ctx) }.is_some() {
            // SAFETY: as above.
            unsafe { EVP_KDF_CTX::free(ctx) };
        }
    }
}

ffi_export! {
    /// A copy of the context, through the algorithm's `dupctx`; NULL if it can't be copied.
    ///
    /// # Safety
    /// `src` is NULL or a live KDF context.
    pub unsafe extern "C" fn EVP_KDF_CTX_dup(src: *const EVP_KDF_CTX) -> *mut EVP_KDF_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(src) }) else { return ptr::null_mut() };
        let Some(m) = c.kdf() else { return ptr::null_mut() };
        if c.algctx.0.is_null() {
            return ptr::null_mut();
        }
        let Some(dup) = m.funcs.dupctx else { return ptr::null_mut() };
        // SAFETY: the provider's function with its context.
        let algctx = unsafe { dup(c.algctx.0) };
        if algctx.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the context's live method; the copy holds a reference too.
        unsafe { EVP_KDF::up_ref(c.meth.0) };
        EVP_KDF_CTX::new_handle(KdfCtx { meth: c.meth, algctx: Ptr(algctx) })
    }
}

ffi_export! {
    /// The context's method (NULL for NULL, where OpenSSL would crash).
    ///
    /// # Safety
    /// `ctx` is NULL or a live KDF context.
    pub unsafe extern "C" fn EVP_KDF_CTX_kdf(ctx: *mut EVP_KDF_CTX) -> *const EVP_KDF
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(ctx) }.map_or(ptr::null(), |c| c.meth.0.cast_const())
    }
}

ffi_export! {
    /// Resets the algorithm context, if the algorithm can; NULL does nothing.
    ///
    /// # Safety
    /// `ctx` is NULL or a live KDF context.
    pub unsafe extern "C" fn EVP_KDF_CTX_reset(ctx: *mut EVP_KDF_CTX)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return };
        if let Some(reset) = c.kdf().and_then(|m| m.funcs.reset) {
            // SAFETY: the provider's function with its context.
            unsafe { reset(c.algctx.0) };
        }
    }
}

ffi_export! {
    /// The size the KDF derives (`size` from the context, else the algorithm), 0 if it has
    /// none, or `SIZE_MAX` for any.
    ///
    /// # Safety
    /// `ctx` is NULL or a live KDF context.
    pub unsafe extern "C" fn EVP_KDF_CTX_get_kdf_size(ctx: *mut EVP_KDF_CTX) -> usize
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        let Some(m) = c.kdf() else { return 0 };
        let mut s = 0usize;
        let mut params = [
            construct(
                OSSL_KDF_PARAM_SIZE.as_ptr(),
                rustyssl_crypto::params::UNSIGNED_INTEGER,
                (&raw mut s).cast(),
                size_of::<usize>(),
            ),
            end(),
        ];
        if let Some(get) = m.funcs.get_ctx_params {
            // SAFETY: the provider's function with its context and a local array.
            if unsafe { get(c.algctx.0, params.as_mut_ptr()) } != 0 {
                return s;
            }
        }
        if let Some(get) = m.funcs.get_params {
            // SAFETY: the provider's function with a local array.
            if unsafe { get(params.as_mut_ptr()) } != 0 {
                return s;
            }
        }
        0
    }
}

ffi_export! {
    /// Derives `keylen` octets into `key`, after setting `params`. Returns 1, or 0 (for NULL
    /// too).
    ///
    /// # Safety
    /// `ctx` is NULL or a live KDF context; `key` has room for `keylen` octets; `params` is
    /// NULL or a parameter array.
    pub unsafe extern "C" fn EVP_KDF_derive(ctx: *mut EVP_KDF_CTX, key: *mut c_uchar, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        let Some(derive) = c.kdf().and_then(|m| m.funcs.derive) else { return 0 };
        // SAFETY: the provider's function with its context and the caller's arguments.
        unsafe { derive(c.algctx.0, key, keylen, params) }
    }
}

ffi_export! {
    /// Asks the context for `params`: the algorithm's result, or 1 when it has no
    /// `get_ctx_params` (0 for NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live KDF context; `params` is an array the algorithm may fill.
    pub unsafe extern "C" fn EVP_KDF_CTX_get_params(ctx: *mut EVP_KDF_CTX, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        match c.kdf().and_then(|m| m.funcs.get_ctx_params) {
            // SAFETY: the provider's function with its context and the caller's array.
            Some(get) => unsafe { get(c.algctx.0, params) },
            None => 1,
        }
    }
}

ffi_export! {
    /// Gives the context `params`: the algorithm's result, or 1 when it has no
    /// `set_ctx_params` (0 for NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live KDF context; `params` is NULL or a parameter array.
    pub unsafe extern "C" fn EVP_KDF_CTX_set_params(ctx: *mut EVP_KDF_CTX, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        match c.kdf().and_then(|m| m.funcs.set_ctx_params) {
            // SAFETY: the provider's function with its context and the caller's array.
            Some(set) => unsafe { set(c.algctx.0, params) },
            None => 1,
        }
    }
}

ffi_export! {
    /// The parameters the context can report, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live KDF context.
    pub unsafe extern "C" fn EVP_KDF_CTX_gettable_params(ctx: *mut EVP_KDF_CTX) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null() };
        let Some(m) = c.kdf() else { return ptr::null() };
        match m.funcs.gettable_ctx_params {
            // SAFETY: the provider's function with its context and the provider's.
            Some(f) => unsafe { f(c.algctx.0, m.provider_ctx()) },
            None => ptr::null(),
        }
    }
}

ffi_export! {
    /// The parameters the context can be given, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live KDF context.
    pub unsafe extern "C" fn EVP_KDF_CTX_settable_params(ctx: *mut EVP_KDF_CTX) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null() };
        let Some(m) = c.kdf() else { return ptr::null() };
        match m.funcs.settable_ctx_params {
            // SAFETY: the provider's function with its context and the provider's.
            Some(f) => unsafe { f(c.algctx.0, m.provider_ctx()) },
            None => ptr::null(),
        }
    }
}

// -------------------------------------------------------------------------------------------
// PKCS5_PBKDF2_HMAC (`p5_crpt2.c`)

/// `ossl_pkcs5_pbkdf2_hmac_ex`: PBKDF2 through the KDF, in PKCS#5 mode (no lower bounds).
///
/// # Safety
/// As for `PKCS5_PBKDF2_HMAC`.
#[expect(
    clippy::too_many_arguments,
    reason = "the reference's function, one to one"
)]
unsafe fn pbkdf2_hmac(
    pass: *const c_char,
    passlen: c_int,
    salt: *const c_uchar,
    saltlen: c_int,
    iter: c_int,
    digest: *const EVP_MD,
    keylen: c_int,
    out: *mut c_uchar,
) -> c_int {
    let empty = c"";
    let (mut pass, mut passlen) = (pass, passlen);
    if pass.is_null() {
        pass = empty.as_ptr();
        passlen = 0;
    } else if passlen == -1 {
        // SAFETY: the caller's guarantee: a C string when its length is -1.
        passlen =
            c_int::try_from(unsafe { CStr::from_ptr(pass) }.count_bytes()).unwrap_or(c_int::MAX);
    }
    let salt = if salt.is_null() && saltlen == 0 {
        empty.as_ptr().cast()
    } else {
        salt
    };
    // Negative lengths are the huge `size_t`s they convert to in C, which it would read and
    // write past (docs/DEVIATIONS.md).
    let (Ok(passlen), Ok(saltlen), Ok(keylen)) = (
        usize::try_from(passlen),
        usize::try_from(saltlen),
        usize::try_from(keylen),
    ) else {
        return 0;
    };
    // SAFETY: a static name.
    let kdf = unsafe { EVP_KDF_fetch(ptr::null_mut(), c"PBKDF2".as_ptr(), ptr::null()) };
    if kdf.is_null() {
        return 0;
    }
    // SAFETY: the method just fetched.
    let kctx = unsafe { EVP_KDF_CTX_new(kdf) };
    // SAFETY: as above; the context holds its own reference.
    unsafe { EVP_KDF_free(kdf) };
    if kctx.is_null() {
        return 0;
    }
    let mut mode: c_int = 1;
    let mut iter = iter;
    // SAFETY: the caller's digest.
    let mdname = unsafe { super::digest::EVP_MD_get0_name(digest) };
    let params = [
        // SAFETY: the caller's buffers and locals, which outlive the derivation.
        unsafe {
            OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_PASSWORD.as_ptr(),
                pass.cast_mut().cast(),
                passlen,
            )
        },
        // SAFETY: as above.
        unsafe { OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS5.as_ptr(), &raw mut mode) },
        // SAFETY: as above.
        unsafe {
            OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SALT.as_ptr(),
                salt.cast_mut().cast(),
                saltlen,
            )
        },
        // SAFETY: as above.
        unsafe { OSSL_PARAM_construct_int(OSSL_KDF_PARAM_ITER.as_ptr(), &raw mut iter) },
        // SAFETY: as above.
        unsafe {
            OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST.as_ptr(), mdname.cast_mut(), 0)
        },
        end(),
    ];
    // SAFETY: the context made here; the caller's room; the array above.
    let rv = c_int::from(unsafe { EVP_KDF_derive(kctx, out, keylen, params.as_ptr()) } == 1);
    // SAFETY: the context made here.
    unsafe { EVP_KDF_CTX_free(kctx) };
    rv
}

ffi_export! {
    /// PBKDF2 (PKCS #5 v2) with HMAC over `digest`: `keylen` octets into `out` from `passlen`
    /// octets of `pass` (a C string for -1; empty for NULL) and `saltlen` of `salt`, with
    /// `iter` iterations. Returns 1, or 0.
    ///
    /// # Safety
    /// `pass` is NULL, a C string (`passlen` -1), or holds `passlen` octets; `salt` is NULL
    /// (for 0) or holds `saltlen` octets; `digest` is a live digest; `out` has room for
    /// `keylen` octets.
    pub unsafe extern "C" fn PKCS5_PBKDF2_HMAC(pass: *const c_char, passlen: c_int, salt: *const c_uchar, saltlen: c_int, iter: c_int, digest: *const EVP_MD, keylen: c_int, out: *mut c_uchar) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { pbkdf2_hmac(pass, passlen, salt, saltlen, iter, digest, keylen, out) }
    }
}

ffi_export! {
    /// `PKCS5_PBKDF2_HMAC` over SHA-1.
    ///
    /// # Safety
    /// As for `PKCS5_PBKDF2_HMAC`.
    pub unsafe extern "C" fn PKCS5_PBKDF2_HMAC_SHA1(pass: *const c_char, passlen: c_int, salt: *const c_uchar, saltlen: c_int, iter: c_int, keylen: c_int, out: *mut c_uchar) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: a static name.
        let digest = unsafe { super::digest::EVP_MD_fetch(ptr::null_mut(), c"SHA1".as_ptr(), ptr::null()) };
        let r = if digest.is_null() {
            0
        } else {
            // SAFETY: the caller's guarantee; the digest just fetched.
            unsafe { pbkdf2_hmac(pass, passlen, salt, saltlen, iter, digest, keylen, out) }
        };
        // SAFETY: the digest fetched here, or NULL.
        unsafe { super::digest::EVP_MD_free(digest) };
        r
    }
}

// -------------------------------------------------------------------------------------------
// EVP_PBE_scrypt (`pbe_scrypt.c`)

/// `SCRYPT_MAX_MEM`: the memory limit when the caller gives none (32 MiB).
const SCRYPT_MAX_MEM: u64 = 1024 * 1024 * 32;

ffi_export! {
    /// scrypt through the SCRYPT KDF of `ctx` (with `propq`): `keylen` octets into `key` from
    /// the password and salt (empty for NULL), with cost `n`, block size `r`, parallelism `p`,
    /// and at most `maxmem` octets of memory (32 MiB for 0). With NULL `key`, checks the
    /// parameters only. Returns 1, or 0.
    ///
    /// # Safety
    /// `pass` and `salt` are NULL or hold their lengths; `key` is NULL or has room for `keylen`
    /// octets; `ctx` is NULL or a live library context; `propq` is NULL or a string.
    pub unsafe extern "C" fn EVP_PBE_scrypt_ex(pass: *const c_char, passlen: usize, salt: *const c_uchar, saltlen: usize, n: u64, r: u64, p: u64, maxmem: u64, key: *mut c_uchar, keylen: usize, ctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if r > u64::from(u32::MAX) || p > u64::from(u32::MAX) {
            err::raise(ERR_LIB_EVP, EVP_R_PARAMETER_TOO_LARGE, "EVP_PBE_scrypt_ex");
            return 0;
        }
        let empty = c"";
        let (pass, passlen) = if pass.is_null() { (empty.as_ptr(), 0) } else { (pass, passlen) };
        let (salt, saltlen) = if salt.is_null() { (empty.as_ptr().cast(), 0) } else { (salt, saltlen) };
        let mut maxmem = if maxmem == 0 { SCRYPT_MAX_MEM } else { maxmem };
        let (mut n, mut r, mut p) = (n, r, p);
        // SAFETY: the caller's library context and query; a static name.
        let kdf = unsafe { EVP_KDF_fetch(ctx, c"SCRYPT".as_ptr(), propq) };
        // SAFETY: the method just fetched, or NULL.
        let kctx = unsafe { EVP_KDF_CTX_new(kdf) };
        // SAFETY: as above; the context holds its own reference.
        unsafe { EVP_KDF_free(kdf) };
        if kctx.is_null() {
            return 0;
        }
        let params = [
            // SAFETY: the caller's buffers and locals, which outlive the derivation.
            unsafe { OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD.as_ptr(), pass.cast_mut().cast(), passlen) },
            // SAFETY: as above.
            unsafe { OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT.as_ptr(), salt.cast_mut().cast(), saltlen) },
            // SAFETY: as above.
            unsafe { OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N.as_ptr(), &raw mut n) },
            // SAFETY: as above.
            unsafe { OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_R.as_ptr(), &raw mut r) },
            // SAFETY: as above.
            unsafe { OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_P.as_ptr(), &raw mut p) },
            // SAFETY: as above.
            unsafe { OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_MAXMEM.as_ptr(), &raw mut maxmem) },
            end(),
        ];
        // SAFETY: the context made here; the caller's room; the array above.
        let rv = c_int::from(unsafe { EVP_KDF_derive(kctx, key, keylen, params.as_ptr()) } == 1);
        // SAFETY: the context made here.
        unsafe { EVP_KDF_CTX_free(kctx) };
        rv
    }
}

ffi_export! {
    /// `EVP_PBE_scrypt_ex` in the default library context.
    ///
    /// # Safety
    /// As for `EVP_PBE_scrypt_ex`.
    pub unsafe extern "C" fn EVP_PBE_scrypt(pass: *const c_char, passlen: usize, salt: *const c_uchar, saltlen: usize, n: u64, r: u64, p: u64, maxmem: u64, key: *mut c_uchar, keylen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_PBE_scrypt_ex(pass, passlen, salt, saltlen, n, r, p, maxmem, key, keylen, ptr::null_mut(), ptr::null()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: a NULL method or context is refused where the reference crashes.
    #[test]
    fn null_methods_and_contexts_are_refused() {
        let (kdf, ctx) = (ptr::null_mut(), ptr::null_mut());
        // SAFETY: NULL is the case under test, here and below.
        assert_eq!(unsafe { EVP_KDF_up_ref(kdf) }, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_KDF_get0_name(kdf) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_KDF_get_params(kdf, ptr::null_mut()) }, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_KDF_gettable_ctx_params(kdf) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { EVP_KDF_CTX_kdf(ctx) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_KDF_CTX_get_params(ctx, ptr::null_mut()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_KDF_CTX_set_params(ctx, ptr::null()) }, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_KDF_CTX_settable_params(ctx) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { EVP_KDF_CTX_gettable_params(ctx) }.is_null());
    }

    /// docs/DEVIATIONS.md: negative lengths (but a password's -1) are refused, where the
    /// reference reads and writes the huge sizes they convert to.
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn negative_pbkdf2_lengths_are_refused() {
        let mut out = [0u8; 16];
        // SAFETY: no preconditions.
        let md = unsafe { crate::evp::legacy_md::EVP_sha256() };
        for (passlen, saltlen, keylen) in [(-2, 4, 16), (4, -1, 16), (4, 4, -16)] {
            // SAFETY: the buffers above; a static digest.
            let r = unsafe {
                PKCS5_PBKDF2_HMAC(
                    c"pass".as_ptr(),
                    passlen,
                    b"salt".as_ptr(),
                    saltlen,
                    1,
                    md,
                    keylen,
                    out.as_mut_ptr(),
                )
            };
            assert_eq!(r, 0);
        }
        // SAFETY: as above, with the C string's length.
        let r = unsafe {
            PKCS5_PBKDF2_HMAC(
                c"pass".as_ptr(),
                -1,
                b"salt".as_ptr(),
                4,
                1,
                md,
                16,
                out.as_mut_ptr(),
            )
        };
        assert_eq!(r, 1);
    }
}
