//! The built-in providers OpenSSL predefines (`crypto/provider_predefined.c`): `default` (the
//! fallback), `base`, and `null`, each an init function and dispatch tables in the form an
//! external provider has (`providers/defltprov.c`, `baseprov.c`, `nullprov.c`).
//!
//! Each reports its name, version, build information, and status. The algorithms they offer
//! come with the algorithm steps; until then their `query_operation` offers none. `legacy` is
//! a module in OpenSSL's default build, and comes with module loading.

use core::ffi::{CStr, c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_CRYPTO, OPENSSL_CORE_CTX, OPENSSL_FULL_VERSION_STRING, OPENSSL_VERSION_STR,
    OSSL_ALGORITHM, OSSL_CORE_HANDLE, OSSL_DISPATCH, OSSL_FUNC_CORE_GET_LIBCTX,
    OSSL_FUNC_PROVIDER_GET_PARAMS, OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
    OSSL_FUNC_PROVIDER_QUERY_OPERATION, OSSL_FUNC_PROVIDER_TEARDOWN, OSSL_PARAM,
    OSSL_PARAM_INTEGER, OSSL_PARAM_UTF8_PTR, OSSL_PROV_PARAM_BUILDINFO, OSSL_PROV_PARAM_NAME,
    OSSL_PROV_PARAM_STATUS, OSSL_PROV_PARAM_VERSION, OSSL_provider_init_fn,
};

use crate::ffi::ffi_callback;
use crate::params::{OSSL_PARAM_locate, OSSL_PARAM_set_int, OSSL_PARAM_set_utf8_ptr};
use crate::version::OpenSSL_version;

/// The predefined providers: name, init function, and whether it's a fallback.
pub(crate) static PREDEFINED: &[(&CStr, OSSL_provider_init_fn, bool)] = &[
    (c"default", Some(default_init), true),
    (c"base", Some(base_init), false),
    (c"null", Some(null_init), false),
];

/// The context of `default` and `base`: what OpenSSL's `PROV_CTX` holds so far.
struct ProvCtx {
    /// The library context the provider was loaded into.
    #[expect(dead_code, reason = "the algorithms (Phase 3 onwards) use it")]
    libctx: *mut OPENSSL_CORE_CTX,
    /// The provider's handle.
    #[expect(dead_code, reason = "the algorithms (Phase 3 onwards) use it")]
    handle: *const OSSL_CORE_HANDLE,
}

/// The parameters each built-in reports (`OSSL_PARAM_DEFN`s), ended by an empty one.
struct Gettable([OSSL_PARAM; 5]);

// SAFETY: the keys are static strings; the array is never written.
unsafe impl Sync for Gettable {}

const fn defn(key: &'static CStr, data_type: c_int) -> OSSL_PARAM {
    OSSL_PARAM {
        key: key.as_ptr(),
        data_type: data_type.cast_unsigned(),
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    }
}

static GETTABLE: Gettable = Gettable([
    defn(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR),
    defn(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR),
    defn(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR),
    defn(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER),
    OSSL_PARAM {
        key: ptr::null(),
        data_type: 0,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
]);

ffi_callback! {
    /// `deflt_gettable_params` (and base's and null's): the parameters a built-in reports.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn gettable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_CRYPTO
    {
        GETTABLE.0.as_ptr()
    }
}

/// `deflt_get_params`: fills the parameters a built-in named `name` reports.
///
/// # Safety
/// `params` is an array ended by a NULL key whose entries may be written.
unsafe fn get_params(name: &'static CStr, params: *mut OSSL_PARAM) -> c_int {
    // SAFETY: the version text is a static string.
    let buildinfo = unsafe { OpenSSL_version(OPENSSL_FULL_VERSION_STRING) };
    for (key, value) in [
        (OSSL_PROV_PARAM_NAME, name.as_ptr()),
        (OSSL_PROV_PARAM_VERSION, OPENSSL_VERSION_STR.as_ptr()),
        (OSSL_PROV_PARAM_BUILDINFO, buildinfo),
    ] {
        // SAFETY: the caller's guarantee.
        let p = unsafe { OSSL_PARAM_locate(params, key.as_ptr()) };
        // SAFETY: a parameter of the array; the value is a static string.
        if !p.is_null() && unsafe { OSSL_PARAM_set_utf8_ptr(p, value) } == 0 {
            return 0;
        }
    }
    // SAFETY: the caller's guarantee.
    let p = unsafe { OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS.as_ptr()) };
    // SAFETY: as above. A built-in provider is always running (`ossl_prov_is_running`).
    if !p.is_null() && unsafe { OSSL_PARAM_set_int(p, 1) } == 0 {
        return 0;
    }
    1
}

ffi_callback! {
    /// `deflt_get_params`.
    ///
    /// # Safety
    /// `params` is an array ended by a NULL key whose entries may be written.
    pub(crate) unsafe extern "C" fn default_get_params(_provctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { get_params(c"OpenSSL Default Provider", params) }
    }
}

ffi_callback! {
    /// `base_get_params`.
    ///
    /// # Safety
    /// As for `default_get_params`.
    pub(crate) unsafe extern "C" fn base_get_params(_provctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { get_params(c"OpenSSL Base Provider", params) }
    }
}

ffi_callback! {
    /// `null_get_params`.
    ///
    /// # Safety
    /// As for `default_get_params`.
    pub(crate) unsafe extern "C" fn null_get_params(_provctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { get_params(c"OpenSSL Null Provider", params) }
    }
}

ffi_callback! {
    /// `deflt_query` (and the others) until the algorithms arrive: none, cacheable.
    ///
    /// # Safety
    /// `no_cache` is NULL or valid for a write.
    pub(crate) unsafe extern "C" fn query_operation(_provctx: *mut c_void, _operation_id: c_int, no_cache: *mut c_int) -> *const OSSL_ALGORITHM
    where failure = ptr::null(), library = ERR_LIB_CRYPTO
    {
        if !no_cache.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { no_cache.write(0) };
        }
        ptr::null()
    }
}

ffi_callback! {
    /// `deflt_teardown` and `base_teardown`: frees the context.
    ///
    /// # Safety
    /// `provctx` is a context `default_init` or `base_init` made, not used afterwards.
    pub(crate) unsafe extern "C" fn teardown(provctx: *mut c_void)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if !provctx.is_null() {
            // SAFETY: the caller's guarantee: a box from the init function.
            drop(unsafe { Box::from_raw(provctx.cast::<ProvCtx>()) });
        }
    }
}

/// A function as a dispatch table holds it.
macro_rules! entry {
    ($id:expr, $f:expr, $ty:ty) => {
        OSSL_DISPATCH {
            function_id: $id,
            // SAFETY: function pointers all have one representation; the core casts it back to
            // the type its id stands for before calling it.
            function: Some(unsafe { core::mem::transmute::<$ty, unsafe extern "C" fn()>($f) }),
        }
    };
}

type TeardownFn = unsafe extern "C" fn(*mut c_void);
type Gettable_ = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type QueryFn = unsafe extern "C" fn(*mut c_void, c_int, *mut c_int) -> *const OSSL_ALGORITHM;

const END: OSSL_DISPATCH = OSSL_DISPATCH {
    function_id: 0,
    function: None,
};

static DEFAULT_DISPATCH: [OSSL_DISPATCH; 5] = [
    entry!(OSSL_FUNC_PROVIDER_TEARDOWN, teardown, TeardownFn),
    entry!(
        OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
        gettable_params,
        Gettable_
    ),
    entry!(
        OSSL_FUNC_PROVIDER_GET_PARAMS,
        default_get_params,
        GetParamsFn
    ),
    entry!(OSSL_FUNC_PROVIDER_QUERY_OPERATION, query_operation, QueryFn),
    END,
];

static BASE_DISPATCH: [OSSL_DISPATCH; 5] = [
    entry!(OSSL_FUNC_PROVIDER_TEARDOWN, teardown, TeardownFn),
    entry!(
        OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
        gettable_params,
        Gettable_
    ),
    entry!(OSSL_FUNC_PROVIDER_GET_PARAMS, base_get_params, GetParamsFn),
    entry!(OSSL_FUNC_PROVIDER_QUERY_OPERATION, query_operation, QueryFn),
    END,
];

static NULL_DISPATCH: [OSSL_DISPATCH; 4] = [
    entry!(
        OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
        gettable_params,
        Gettable_
    ),
    entry!(OSSL_FUNC_PROVIDER_GET_PARAMS, null_get_params, GetParamsFn),
    entry!(OSSL_FUNC_PROVIDER_QUERY_OPERATION, query_operation, QueryFn),
    END,
];

type GetLibctx = unsafe extern "C" fn(*const OSSL_CORE_HANDLE) -> *mut OPENSSL_CORE_CTX;

/// The core's `core_get_libctx`, from its dispatch table.
///
/// # Safety
/// `in_` is NULL or a dispatch table ended by a zero id.
unsafe fn core_get_libctx(mut in_: *const OSSL_DISPATCH) -> Option<GetLibctx> {
    // SAFETY: the caller's guarantee: the table goes on to its end.
    while let Some(d) = unsafe { in_.as_ref() } {
        if d.function_id == 0 {
            break;
        }
        if d.function_id == OSSL_FUNC_CORE_GET_LIBCTX {
            let f = d.function?;
            // SAFETY: the core's guarantee: this id's function has this type.
            return Some(unsafe { core::mem::transmute::<unsafe extern "C" fn(), GetLibctx>(f) });
        }
        in_ = in_.wrapping_add(1);
    }
    None
}

/// `ossl_default_provider_init` and `ossl_base_provider_init`: a context with the library
/// context the core gives, and the provider's dispatch table. 0 if the core can't give it.
///
/// # Safety
/// The arguments are as a core passes them to `OSSL_provider_init`.
unsafe fn init_with(
    handle: *const OSSL_CORE_HANDLE,
    in_: *const OSSL_DISPATCH,
    out: *mut *const OSSL_DISPATCH,
    provctx: *mut *mut c_void,
    table: &'static [OSSL_DISPATCH],
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(get_libctx) = (unsafe { core_get_libctx(in_) }) else {
        return 0;
    };
    // SAFETY: the core's function with this provider's handle.
    let libctx = unsafe { get_libctx(handle) };
    let ctx = Box::into_raw(Box::new(ProvCtx { libctx, handle }));
    // SAFETY: the caller's guarantee: both are valid for writes.
    unsafe { provctx.write(ctx.cast()) };
    // SAFETY: as above.
    unsafe { out.write(table.as_ptr()) };
    1
}

ffi_callback! {
    /// The default provider's init function.
    ///
    /// # Safety
    /// The arguments are as a core passes them to `OSSL_provider_init`.
    pub(crate) unsafe extern "C" fn default_init(handle: *const OSSL_CORE_HANDLE, in_: *const OSSL_DISPATCH, out: *mut *const OSSL_DISPATCH, provctx: *mut *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { init_with(handle, in_, out, provctx, &DEFAULT_DISPATCH) }
    }
}

ffi_callback! {
    /// The base provider's init function.
    ///
    /// # Safety
    /// As for `default_init`.
    pub(crate) unsafe extern "C" fn base_init(handle: *const OSSL_CORE_HANDLE, in_: *const OSSL_DISPATCH, out: *mut *const OSSL_DISPATCH, provctx: *mut *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { init_with(handle, in_, out, provctx, &BASE_DISPATCH) }
    }
}

ffi_callback! {
    /// The null provider's init function: its context is its handle, as OpenSSL's is.
    ///
    /// # Safety
    /// As for `default_init`.
    pub(crate) unsafe extern "C" fn null_init(handle: *const OSSL_CORE_HANDLE, _in: *const OSSL_DISPATCH, out: *mut *const OSSL_DISPATCH, provctx: *mut *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee: both are valid for writes.
        unsafe { out.write(NULL_DISPATCH.as_ptr()) };
        // SAFETY: as above.
        unsafe { provctx.write(handle.cast_mut().cast()) };
        1
    }
}
