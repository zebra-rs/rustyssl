//! MAC methods and contexts (`EVP_MAC(3)`; `mac_meth.c`, `mac_lib.c`): an `EVP_MAC` made from
//! a provider's MAC algorithm (`evp_mac_from_algorithm`), fetched by name and properties, and an
//! `EVP_MAC_CTX` running it: init with a key and parameters, update, final (or XOF final), the
//! sizes, parameters, and copies. Also `EVP_Q_mac`, the one-shot MAC.
//!
//! As in OpenSSL, a MAC algorithm must offer `newctx` and `freectx`, `update` and `final`, and
//! `init` (or `init_skey`). The functions given a NULL method or context fail here where the
//! reference would crash (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_uchar, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    ERR_LIB_EVP, ERR_R_EVP_LIB, ERR_R_PASSED_INVALID_ARGUMENT, ERR_R_PASSED_NULL_PARAMETER,
    ERR_R_UNSUPPORTED, EVP_MAC, EVP_MAC_CTX, EVP_R_BUFFER_TOO_SMALL, EVP_R_FINAL_ERROR,
    EVP_R_INVALID_NULL_ALGORITHM, EVP_R_INVALID_PROVIDER_FUNCTIONS, EVP_R_SETTING_XOF_FAILED,
    OSSL_ALGORITHM, OSSL_FUNC_MAC_DUPCTX, OSSL_FUNC_MAC_FINAL, OSSL_FUNC_MAC_FREECTX,
    OSSL_FUNC_MAC_GET_CTX_PARAMS, OSSL_FUNC_MAC_GET_PARAMS, OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
    OSSL_FUNC_MAC_GETTABLE_PARAMS, OSSL_FUNC_MAC_INIT, OSSL_FUNC_MAC_INIT_SKEY,
    OSSL_FUNC_MAC_NEWCTX, OSSL_FUNC_MAC_SET_CTX_PARAMS, OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_MAC_UPDATE, OSSL_LIB_CTX, OSSL_MAC_PARAM_BLOCK_SIZE, OSSL_MAC_PARAM_CIPHER,
    OSSL_MAC_PARAM_DIGEST, OSSL_MAC_PARAM_SIZE, OSSL_MAC_PARAM_XOF, OSSL_OP_MAC, OSSL_PARAM,
    OSSL_PROVIDER,
};

use super::fetch::{self, Kind};
use crate::err;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::params::{OSSL_PARAM_construct_utf8_string, OSSL_PARAM_locate_const, construct, end};
use crate::provider::Ptr;

type AnyFn = unsafe extern "C" fn();
type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type DupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type InitFn = unsafe extern "C" fn(*mut c_void, *const c_uchar, usize, *const OSSL_PARAM) -> c_int;
type UpdateFn = unsafe extern "C" fn(*mut c_void, *const c_uchar, usize) -> c_int;
type FinalFn = unsafe extern "C" fn(*mut c_void, *mut c_uchar, *mut usize, usize) -> c_int;
type GetParamsFn = unsafe extern "C" fn(*mut OSSL_PARAM) -> c_int;
type GettableFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type GetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type SetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type CtxParamsListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;

/// A MAC algorithm's functions, as its dispatch table gave them.
#[derive(Default, Clone, Copy)]
struct Funcs {
    newctx: Option<NewCtxFn>,
    dupctx: Option<DupCtxFn>,
    freectx: Option<FreeCtxFn>,
    init: Option<InitFn>,
    init_skey: Option<AnyFn>,
    update: Option<UpdateFn>,
    final_: Option<FinalFn>,
    get_params: Option<GetParamsFn>,
    gettable_params: Option<GettableFn>,
    get_ctx_params: Option<GetCtxParamsFn>,
    set_ctx_params: Option<SetCtxParamsFn>,
    gettable_ctx_params: Option<CtxParamsListFn>,
    settable_ctx_params: Option<CtxParamsListFn>,
}

/// A MAC method (`EVP_MAC`).
pub(crate) struct Mac {
    name_id: u32,
    type_name: CString,
    /// The provider's description, a static string of its, or NULL.
    description: Ptr<c_char>,
    /// The provider, with a reference.
    prov: Ptr<OSSL_PROVIDER>,
    funcs: Funcs,
}

impl Mac {
    /// The provider's context, which the provider functions take.
    fn provider_ctx(&self) -> *mut c_void {
        // SAFETY: the method holds a reference to its live provider.
        unsafe { crate::provider::OSSL_PROVIDER_get0_provider_ctx(self.prov.0) }
    }
}

handle_type!(EVP_MAC => Mac);

impl Drop for Mac {
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

/// `evp_mac_from_algorithm`: a MAC method from the provider's algorithm, with one reference,
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
    const F: &str = "evp_mac_from_algorithm";
    // SAFETY: the caller's guarantee.
    let names = unsafe { CStr::from_ptr(algo.algorithm_names) }.to_bytes();
    let first = names.split(|&c| c == b':').next().unwrap_or(names);
    let Ok(type_name) = CString::new(first) else {
        err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, F);
        return ptr::null_mut();
    };
    let mut funcs = Funcs::default();
    let (mut fnmaccnt, mut fnctxcnt, mut init_found) = (0, 0, false);
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
            OSSL_FUNC_MAC_NEWCTX => {
                set!(newctx);
                fnctxcnt += 1;
            }
            OSSL_FUNC_MAC_DUPCTX => set!(dupctx),
            OSSL_FUNC_MAC_FREECTX => {
                set!(freectx);
                fnctxcnt += 1;
            }
            OSSL_FUNC_MAC_INIT => {
                set!(init);
                init_found = true;
            }
            OSSL_FUNC_MAC_UPDATE => {
                set!(update);
                fnmaccnt += 1;
            }
            OSSL_FUNC_MAC_FINAL => {
                set!(final_);
                fnmaccnt += 1;
            }
            OSSL_FUNC_MAC_GETTABLE_PARAMS => set!(gettable_params),
            OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS => set!(gettable_ctx_params),
            OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS => set!(settable_ctx_params),
            OSSL_FUNC_MAC_GET_PARAMS => set!(get_params),
            OSSL_FUNC_MAC_GET_CTX_PARAMS => set!(get_ctx_params),
            OSSL_FUNC_MAC_SET_CTX_PARAMS => set!(set_ctx_params),
            OSSL_FUNC_MAC_INIT_SKEY => {
                if funcs.init_skey.is_none() {
                    funcs.init_skey = Some(f);
                }
                init_found = true;
            }
            _ => {}
        }
    }
    if fnmaccnt + usize::from(init_found) != 3 || fnctxcnt != 2 {
        err::raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS, F);
        return ptr::null_mut();
    }
    // SAFETY: the caller's live provider; the method holds the reference.
    if !unsafe { OSSL_PROVIDER::up_ref(prov) } {
        return ptr::null_mut();
    }
    EVP_MAC::new_handle(Mac {
        name_id,
        type_name,
        description: Ptr(algo.algorithm_description.cast_mut()),
        prov: Ptr(prov),
        funcs,
    })
    .cast()
}

/// Adds a reference to a MAC method in a store.
unsafe fn up_ref(m: *mut c_void) {
    // SAFETY: a live method.
    unsafe { EVP_MAC::up_ref(m.cast()) };
}

/// Drops a reference to a MAC method in a store.
unsafe fn free(m: *mut c_void) {
    // SAFETY: a reference the store held.
    unsafe { EVP_MAC::free(m.cast()) };
}

/// MAC methods to fetching.
static MACS: Kind = Kind {
    operation: OSSL_OP_MAC,
    from_algorithm,
    up_ref,
    free,
};

/// The method behind `mac`, or `None` for NULL.
///
/// # Safety
/// `mac` is NULL or a live MAC method.
unsafe fn method<'a>(mac: *const EVP_MAC) -> Option<&'a Mac> {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_MAC::get(mac) }
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
    /// The MAC `algorithm` from the providers of `libctx` (the default context for NULL) that
    /// best matches `properties`, with a reference; NULL with an error if none does.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `algorithm` and `properties` are NULL or
    /// strings.
    pub unsafe extern "C" fn EVP_MAC_fetch(libctx: *mut OSSL_LIB_CTX, algorithm: *const c_char, properties: *const c_char) -> *mut EVP_MAC
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let name = unsafe { text(algorithm) };
        // SAFETY: as above.
        let props = unsafe { text(properties) };
        // SAFETY: the caller's guarantee.
        unsafe { fetch::fetch(libctx, &MACS, name, props) }.cast()
    }
}

ffi_export! {
    /// Adds a reference. Returns 1 (0 for NULL, where OpenSSL would crash).
    ///
    /// # Safety
    /// `mac` is NULL or a live MAC method.
    pub unsafe extern "C" fn EVP_MAC_up_ref(mac: *mut EVP_MAC) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if unsafe { method(mac) }.is_none() {
            return 0;
        }
        // SAFETY: as above.
        unsafe { EVP_MAC::up_ref(mac) };
        1
    }
}

ffi_export! {
    /// Drops a reference; NULL does nothing.
    ///
    /// # Safety
    /// `mac` is NULL or a MAC method the caller holds, not used afterwards.
    pub unsafe extern "C" fn EVP_MAC_free(mac: *mut EVP_MAC)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if unsafe { method(mac) }.is_some() {
            // SAFETY: as above.
            unsafe { EVP_MAC::free(mac) };
        }
    }
}

ffi_export! {
    /// The algorithm's first name, as its provider gave it; NULL for NULL.
    ///
    /// # Safety
    /// `mac` is NULL or a live MAC method.
    pub unsafe extern "C" fn EVP_MAC_get0_name(mac: *const EVP_MAC) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(mac) }.map_or(ptr::null(), |m| m.type_name.as_ptr())
    }
}

ffi_export! {
    /// The provider's description of the algorithm, or NULL.
    ///
    /// # Safety
    /// `mac` is NULL or a live MAC method.
    pub unsafe extern "C" fn EVP_MAC_get0_description(mac: *const EVP_MAC) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(mac) }.map_or(ptr::null(), |m| m.description.0.cast_const())
    }
}

ffi_export! {
    /// The provider the method came from (NULL for NULL).
    ///
    /// # Safety
    /// `mac` is NULL or a live MAC method.
    pub unsafe extern "C" fn EVP_MAC_get0_provider(mac: *const EVP_MAC) -> *const OSSL_PROVIDER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(mac) }.map_or(ptr::null(), |m| m.prov.0.cast_const())
    }
}

ffi_export! {
    /// Whether `name` is one of the algorithm's names. 0 for NULL.
    ///
    /// # Safety
    /// `mac` is NULL or a live MAC method; `name` is NULL or a string.
    pub unsafe extern "C" fn EVP_MAC_is_a(mac: *const EVP_MAC, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(mac) }) else { return 0 };
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
    /// `mac` is NULL or a live MAC method; `fn_` is a function of the documented type.
    pub unsafe extern "C" fn EVP_MAC_names_do_all(mac: *const EVP_MAC, fn_: Option<NameFn>, data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(mac) }) else { return 0 };
        let names = fetch::names_of(m.prov.0, m.name_id);
        for n in &names {
            let Ok(c) = CString::new(n.clone()) else { continue };
            if let Some(f) = fn_ {
                // SAFETY: the caller's callback with a string and its data.
                unsafe { f(c.as_ptr(), data) };
            }
        }
        c_int::from(!names.is_empty())
    }
}

/// `EVP_MAC_do_all_provided`'s callback.
type DoAllFn = unsafe extern "C" fn(*mut EVP_MAC, *mut c_void);

ffi_export! {
    /// Calls `fn_` with each MAC method the active providers of `libctx` offer.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `fn_` is a function of the documented type.
    pub unsafe extern "C" fn EVP_MAC_do_all_provided(libctx: *mut OSSL_LIB_CTX, fn_: Option<DoAllFn>, arg: *mut c_void)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let all = unsafe { fetch::all(libctx, &MACS) };
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
    /// `mac` is NULL or a live MAC method; `params` is an array the algorithm may fill.
    pub unsafe extern "C" fn EVP_MAC_get_params(mac: *mut EVP_MAC, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(mac) }) else { return 0 };
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
    /// `mac` is NULL or a live MAC method.
    pub unsafe extern "C" fn EVP_MAC_gettable_params(mac: *const EVP_MAC) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(mac) }) else { return ptr::null() };
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
    /// `mac` is NULL or a live MAC method.
    pub unsafe extern "C" fn EVP_MAC_gettable_ctx_params(mac: *const EVP_MAC) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(mac) }) else { return ptr::null() };
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
    /// `mac` is NULL or a live MAC method.
    pub unsafe extern "C" fn EVP_MAC_settable_ctx_params(mac: *const EVP_MAC) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(mac) }) else { return ptr::null() };
        match m.funcs.settable_ctx_params {
            // SAFETY: the provider's function with no context and its own.
            Some(f) => unsafe { f(ptr::null_mut(), m.provider_ctx()) },
            None => ptr::null(),
        }
    }
}

// -------------------------------------------------------------------------------------------
// EVP_MAC_CTX

/// A MAC context (`EVP_MAC_CTX`): the method, with a reference, and the algorithm's context.
pub(crate) struct MacCtx {
    meth: Ptr<EVP_MAC>,
    algctx: Ptr<c_void>,
}

handle_type!(EVP_MAC_CTX => MacCtx);

impl MacCtx {
    fn mac(&self) -> Option<&Mac> {
        // SAFETY: the context holds a reference to its method.
        unsafe { method(self.meth.0) }
    }
}

impl Drop for MacCtx {
    fn drop(&mut self) {
        if let Some(free) = self.mac().and_then(|m| m.funcs.freectx) {
            // SAFETY: the algorithm's context, freed once, by its own function.
            unsafe { free(self.algctx.0) };
        }
        // SAFETY: the method reference the context holds.
        unsafe { EVP_MAC_free(self.meth.0) };
    }
}

/// The context behind `ctx`, or `None` for NULL.
///
/// # Safety
/// `ctx` is NULL or a live MAC context.
unsafe fn context<'a>(ctx: *const EVP_MAC_CTX) -> Option<&'a MacCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_MAC_CTX::get(ctx) }
}

ffi_export! {
    /// A context for `mac`, holding a reference to it; NULL with an error if the algorithm
    /// can't make one.
    ///
    /// # Safety
    /// `mac` is NULL or a live MAC method.
    pub unsafe extern "C" fn EVP_MAC_CTX_new(mac: *mut EVP_MAC) -> *mut EVP_MAC_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(mac) }) else {
            err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, "EVP_MAC_CTX_new");
            return ptr::null_mut();
        };
        let algctx = match m.funcs.newctx {
            // SAFETY: the provider's function with its context.
            Some(new) => unsafe { new(m.provider_ctx()) },
            None => ptr::null_mut(),
        };
        if algctx.is_null() {
            err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, "EVP_MAC_CTX_new");
            return ptr::null_mut();
        }
        // SAFETY: the caller's live method; the context holds the reference.
        unsafe { EVP_MAC::up_ref(mac) };
        EVP_MAC_CTX::new_handle(MacCtx { meth: Ptr(mac), algctx: Ptr(algctx) })
    }
}

ffi_export! {
    /// Frees the context and its algorithm context; NULL does nothing.
    ///
    /// # Safety
    /// `ctx` is NULL or a live MAC context, not used afterwards.
    pub unsafe extern "C" fn EVP_MAC_CTX_free(ctx: *mut EVP_MAC_CTX)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if unsafe { context(ctx) }.is_some() {
            // SAFETY: as above.
            unsafe { EVP_MAC_CTX::free(ctx) };
        }
    }
}

ffi_export! {
    /// A copy of the context, through the algorithm's `dupctx`; NULL if it can't be copied.
    ///
    /// # Safety
    /// `src` is NULL or a live MAC context.
    pub unsafe extern "C" fn EVP_MAC_CTX_dup(src: *const EVP_MAC_CTX) -> *mut EVP_MAC_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(src) }) else { return ptr::null_mut() };
        let Some(m) = c.mac() else { return ptr::null_mut() };
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
        unsafe { EVP_MAC::up_ref(c.meth.0) };
        EVP_MAC_CTX::new_handle(MacCtx { meth: c.meth, algctx: Ptr(algctx) })
    }
}

ffi_export! {
    /// The context's method (NULL for NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live MAC context.
    pub unsafe extern "C" fn EVP_MAC_CTX_get0_mac(ctx: *mut EVP_MAC_CTX) -> *mut EVP_MAC
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(ctx) }.map_or(ptr::null_mut(), |c| c.meth.0)
    }
}

/// `get_size_t_ctx_param`: a size the context (or else the algorithm) reports, 0 if it
/// reports none.
///
/// # Safety
/// `ctx` is NULL or a live MAC context.
unsafe fn size_param(ctx: *const EVP_MAC_CTX, key: &CStr) -> usize {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    let Some(m) = c.mac() else { return 0 };
    if c.algctx.0.is_null() {
        return 0;
    }
    let mut sz = 0usize;
    let mut params = [
        construct(
            key.as_ptr(),
            rustyssl_crypto::params::UNSIGNED_INTEGER,
            (&raw mut sz).cast(),
            size_of::<usize>(),
        ),
        end(),
    ];
    let ok = if let Some(get) = m.funcs.get_ctx_params {
        // SAFETY: the provider's function with its context and a local array.
        unsafe { get(c.algctx.0, params.as_mut_ptr()) }
    } else if let Some(get) = m.funcs.get_params {
        // SAFETY: the provider's function with a local array.
        unsafe { get(params.as_mut_ptr()) }
    } else {
        0
    };
    if ok != 0 { sz } else { 0 }
}

ffi_export! {
    /// The MAC's size, as the context reports it (0 if it can't yet).
    ///
    /// # Safety
    /// `ctx` is NULL or a live MAC context.
    pub unsafe extern "C" fn EVP_MAC_CTX_get_mac_size(ctx: *mut EVP_MAC_CTX) -> usize
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { size_param(ctx, OSSL_MAC_PARAM_SIZE) }
    }
}

ffi_export! {
    /// The MAC's block size, as the context reports it (0 if it can't).
    ///
    /// # Safety
    /// `ctx` is NULL or a live MAC context.
    pub unsafe extern "C" fn EVP_MAC_CTX_get_block_size(ctx: *mut EVP_MAC_CTX) -> usize
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { size_param(ctx, OSSL_MAC_PARAM_BLOCK_SIZE) }
    }
}

ffi_export! {
    /// Starts a MAC with `keylen` octets of `key` (none for NULL) and `params`. Returns the
    /// algorithm's result.
    ///
    /// # Safety
    /// `ctx` is NULL or a live MAC context; `key` is NULL or holds `keylen` octets; `params`
    /// is NULL or a parameter array.
    pub unsafe extern "C" fn EVP_MAC_init(ctx: *mut EVP_MAC_CTX, key: *const c_uchar, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        let Some(init) = c.mac().and_then(|m| m.funcs.init) else {
            err::raise(ERR_R_EVP_LIB, ERR_R_UNSUPPORTED, "EVP_MAC_init");
            return 0;
        };
        // SAFETY: the provider's function with its context and the caller's arguments.
        unsafe { init(c.algctx.0, key, keylen, params) }
    }
}

/// A MAC's `init_skey`: its context, the key's data, and parameters.
type InitSkeyFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;

ffi_export! {
    /// Initializes the MAC with the opaque key `skey`, which must be the MAC's provider's, and
    /// `params`. Returns the algorithm's result, or 0 (with `ERR_R_UNSUPPORTED`) if the MAC
    /// doesn't take key objects (none of the default provider's do) or the key is another
    /// provider's.
    ///
    /// # Safety
    /// `ctx` is NULL or a live MAC context; `skey` is NULL or a live key; `params` is NULL or a
    /// parameter array.
    pub unsafe extern "C" fn EVP_MAC_init_SKEY(ctx: *mut EVP_MAC_CTX, skey: *mut rustyssl_abi::EVP_SKEY, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_MAC_init_SKEY";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        let Some(m) = c.mac() else { return 0 };
        let Some(init_skey) = m.funcs.init_skey else {
            err::raise(ERR_R_EVP_LIB, ERR_R_UNSUPPORTED, F);
            return 0;
        };
        // SAFETY: the caller's guarantee.
        let Some(key) = (unsafe { super::skey::key(skey) }) else {
            // OpenSSL reads through the NULL key and crashes.
            err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        };
        if key.skeymgmt.get().prov.0 != m.prov.0 {
            err::raise(ERR_R_EVP_LIB, ERR_R_UNSUPPORTED, F);
            return 0;
        }
        // SAFETY: the provider's guarantee of the function type for `OSSL_FUNC_MAC_INIT_SKEY`.
        let init_skey: InitSkeyFn = unsafe { core::mem::transmute(init_skey) };
        // SAFETY: the provider's function with its context, the key's data (its own
        // provider's), and the caller's array.
        unsafe { init_skey(c.algctx.0, key.keydata.0, params) }
    }
}

ffi_export! {
    /// Adds `datalen` octets of `data` to the MAC. Returns the algorithm's result.
    ///
    /// # Safety
    /// `ctx` is NULL or a live MAC context; `data` holds `datalen` octets.
    pub unsafe extern "C" fn EVP_MAC_update(ctx: *mut EVP_MAC_CTX, data: *const c_uchar, datalen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        let Some(update) = c.mac().and_then(|m| m.funcs.update) else { return 0 };
        // SAFETY: the provider's function with its context and the caller's data.
        unsafe { update(c.algctx.0, data, datalen) }
    }
}

/// `evp_mac_final`.
///
/// # Safety
/// `ctx` is NULL or a live MAC context; `out` is NULL or has room for `outsize` octets;
/// `outl` is NULL or valid for a write.
unsafe fn mac_final(
    ctx: *mut EVP_MAC_CTX,
    xof: bool,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
) -> c_int {
    const F: &str = "evp_mac_final";
    // SAFETY: the caller's guarantee.
    let Some((c, m)) = (unsafe { context(ctx) }).and_then(|c| c.mac().map(|m| (c, m))) else {
        err::raise(ERR_LIB_EVP, EVP_R_INVALID_NULL_ALGORITHM, F);
        return 0;
    };
    let Some(final_) = m.funcs.final_ else {
        err::raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR, F);
        return 0;
    };
    // SAFETY: the caller's guarantee.
    let macsize = unsafe { EVP_MAC_CTX_get_mac_size(ctx) };
    if out.is_null() {
        if outl.is_null() {
            err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { outl.write(macsize) };
        return 1;
    }
    if outsize < macsize {
        err::raise(ERR_LIB_EVP, EVP_R_BUFFER_TOO_SMALL, F);
        return 0;
    }
    if xof {
        let mut one: c_int = 1;
        let params = [
            construct(
                OSSL_MAC_PARAM_XOF.as_ptr(),
                rustyssl_crypto::params::INTEGER,
                (&raw mut one).cast(),
                size_of::<c_int>(),
            ),
            end(),
        ];
        // SAFETY: the caller's context; a local array.
        if unsafe { EVP_MAC_CTX_set_params(ctx, params.as_ptr()) } <= 0 {
            err::raise(ERR_LIB_EVP, EVP_R_SETTING_XOF_FAILED, F);
            return 0;
        }
    }
    let mut l = 0usize;
    // SAFETY: the provider's function with its context, the caller's room, and a local.
    let res = unsafe { final_(c.algctx.0, out, &raw mut l, outsize) };
    if !outl.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { outl.write(l) };
    }
    res
}

ffi_export! {
    /// Writes the MAC to `out` (room for `outsize` octets), its length to `*outl`; with a NULL
    /// `out`, only the length. Returns 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live MAC context; `out` is NULL or has room for `outsize` octets;
    /// `outl` is NULL or valid for a write.
    pub unsafe extern "C" fn EVP_MAC_final(ctx: *mut EVP_MAC_CTX, out: *mut c_uchar, outl: *mut usize, outsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { mac_final(ctx, false, out, outl, outsize) }
    }
}

ffi_export! {
    /// Writes `outsize` octets of an XOF MAC to `out` (setting `xof` first). Returns 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live MAC context; `out` has room for `outsize` octets.
    pub unsafe extern "C" fn EVP_MAC_finalXOF(ctx: *mut EVP_MAC_CTX, out: *mut c_uchar, outsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { mac_final(ctx, true, out, ptr::null_mut(), outsize) }
    }
}

ffi_export! {
    /// Asks the context for `params`: the algorithm's result, or 1 when it has none (0 for
    /// NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live MAC context; `params` is an array the algorithm may fill.
    pub unsafe extern "C" fn EVP_MAC_CTX_get_params(ctx: *mut EVP_MAC_CTX, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        match c.mac().and_then(|m| m.funcs.get_ctx_params) {
            // SAFETY: the provider's function with its context and the caller's array.
            Some(get) => unsafe { get(c.algctx.0, params) },
            None => 1,
        }
    }
}

ffi_export! {
    /// Gives the context `params`: the algorithm's result, or 1 when it takes none (0 for
    /// NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live MAC context; `params` is NULL or a parameter array.
    pub unsafe extern "C" fn EVP_MAC_CTX_set_params(ctx: *mut EVP_MAC_CTX, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        match c.mac().and_then(|m| m.funcs.set_ctx_params) {
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
    /// `ctx` is NULL or a live MAC context.
    pub unsafe extern "C" fn EVP_MAC_CTX_gettable_params(ctx: *mut EVP_MAC_CTX) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null() };
        let Some(m) = c.mac() else { return ptr::null() };
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
    /// `ctx` is NULL or a live MAC context.
    pub unsafe extern "C" fn EVP_MAC_CTX_settable_params(ctx: *mut EVP_MAC_CTX) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null() };
        let Some(m) = c.mac() else { return ptr::null() };
        match m.funcs.settable_ctx_params {
            // SAFETY: the provider's function with the contexts.
            Some(f) => unsafe { f(c.algctx.0, m.provider_ctx()) },
            None => ptr::null(),
        }
    }
}

ffi_export! {
    /// The MAC `name` of `datalen` octets of `data` under `keylen` octets of `key` (the data's
    /// address, as a dummy, for NULL and 0), with `subalg` as its digest or cipher and
    /// `params`, into `out` (room for `outsize`) or else a new buffer; its length through
    /// `*outlen`. Returns the MAC's address, or NULL.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; the strings are NULL or strings; `params`
    /// is NULL or a parameter array; `key` and `data` hold their lengths; `out` is NULL or has
    /// room for `outsize` octets; `outlen` is NULL or valid for a write.
    pub unsafe extern "C" fn EVP_Q_mac(libctx: *mut OSSL_LIB_CTX, name: *const c_char, propq: *const c_char, subalg: *const c_char, params: *const OSSL_PARAM, key: *const c_void, keylen: usize, data: *const c_uchar, datalen: usize, out: *mut c_uchar, outsize: usize, outlen: *mut usize) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        if !outlen.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { outlen.write(0) };
        }
        // SAFETY: the caller's guarantee.
        let mac = unsafe { EVP_MAC_fetch(libctx, name, propq) };
        if mac.is_null() {
            return ptr::null_mut();
        }
        let mut subalg_param = [end(), end()];
        let mut res = ptr::null_mut();
        'run: {
            if !subalg.is_null() {
                // SAFETY: the method fetched above.
                let defined = unsafe { EVP_MAC_settable_ctx_params(mac) };
                // The algorithm may take a digest or a cipher: whichever it lists.
                let mut key_name = OSSL_MAC_PARAM_DIGEST;
                // SAFETY: the method's list (or NULL) and a static key.
                if unsafe { OSSL_PARAM_locate_const(defined, key_name.as_ptr()) }.is_null() {
                    key_name = OSSL_MAC_PARAM_CIPHER;
                    // SAFETY: as above.
                    if unsafe { OSSL_PARAM_locate_const(defined, key_name.as_ptr()) }.is_null() {
                        err::raise(ERR_LIB_EVP, ERR_R_PASSED_INVALID_ARGUMENT, "EVP_Q_mac");
                        break 'run;
                    }
                }
                // SAFETY: a static key and the caller's string.
                subalg_param[0] = unsafe { OSSL_PARAM_construct_utf8_string(key_name.as_ptr(), subalg.cast_mut(), 0) };
            }
            // A NULL key of no length: the data's address as a dummy, for the init.
            let key = if key.is_null() && keylen == 0 { data.cast::<c_void>() } else { key };
            // SAFETY: the method fetched above.
            let ctx = unsafe { EVP_MAC_CTX_new(mac) };
            let mut len = 0usize;
            let ok = !ctx.is_null()
                // SAFETY: the context made here; a local array.
                && unsafe { EVP_MAC_CTX_set_params(ctx, subalg_param.as_ptr()) } != 0
                // SAFETY: the context; the caller's array.
                && unsafe { EVP_MAC_CTX_set_params(ctx, params) } != 0
                // SAFETY: the context; the caller's key and array.
                && unsafe { EVP_MAC_init(ctx, key.cast(), keylen, params) } != 0
                // SAFETY: the context; the caller's data.
                && unsafe { EVP_MAC_update(ctx, data, datalen) } != 0
                // SAFETY: the context; the caller's room (or NULL) and a local.
                && unsafe { EVP_MAC_final(ctx, out, &raw mut len, outsize) } != 0;
            if ok {
                let mut o = out;
                if o.is_null() {
                    o = crate::mem::alloc(len).cast();
                    // SAFETY: the context; the buffer made with `len` octets.
                    if !o.is_null() && unsafe { EVP_MAC_final(ctx, o, ptr::null_mut(), len) } == 0 {
                        // SAFETY: the buffer made above.
                        unsafe { crate::mem::release(o.cast()) };
                        o = ptr::null_mut();
                    }
                }
                res = o;
                if !res.is_null() && !outlen.is_null() {
                    // SAFETY: the caller's guarantee.
                    unsafe { outlen.write(len) };
                }
            }
            // SAFETY: the context made here, or NULL.
            unsafe { EVP_MAC_CTX_free(ctx) };
        }
        // SAFETY: the method fetched above.
        unsafe { EVP_MAC_free(mac) };
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: a NULL method or context is refused (the reference crashes).
    #[test]
    fn null_methods_and_contexts_are_refused() {
        let mut out = [0u8; 64];
        let mut outl = 7usize;
        let (mac, ctx) = (ptr::null_mut(), ptr::null_mut());
        // SAFETY: NULL is the case under test, here and below.
        assert!(unsafe { EVP_MAC_CTX_new(mac) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_MAC_up_ref(mac) }, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_MAC_get0_name(mac) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_MAC_is_a(mac, c"HMAC".as_ptr()) }, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_MAC_CTX_dup(ctx) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { EVP_MAC_CTX_get0_mac(ctx) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_MAC_CTX_get_mac_size(ctx) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_MAC_CTX_get_block_size(ctx) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_MAC_init(ctx, ptr::null(), 0, ptr::null()) }, 0);
        // SAFETY: as above; one octet of the buffer.
        assert_eq!(unsafe { EVP_MAC_update(ctx, out.as_ptr(), 1) }, 0);
        // SAFETY: as above; the buffers above.
        let r = unsafe { EVP_MAC_final(ctx, out.as_mut_ptr(), &raw mut outl, out.len()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_MAC_finalXOF(ctx, out.as_mut_ptr(), 16) }, 0);
        // SAFETY: as above.
        unsafe { EVP_MAC_CTX_free(ctx) };
        // SAFETY: as above.
        unsafe { EVP_MAC_free(mac) };
        crate::err::take_all();
    }
}
