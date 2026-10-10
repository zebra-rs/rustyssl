//! The core's dispatch table (`provider-base(7)`): the functions a provider's init function
//! gets to call back into the library, with the provider's handle (its `OSSL_PROVIDER`).
//!
//! So far it offers `core_get_libctx`, which the built-in providers need; the parameters, error,
//! BIO, memory, and other services come with step 3.1d-b, and a provider looks for what it
//! needs and must cope with what's missing, as with any core.

use rustyssl_abi::{
    ERR_LIB_CRYPTO, OPENSSL_CORE_CTX, OSSL_CORE_HANDLE, OSSL_DISPATCH, OSSL_FUNC_CORE_GET_LIBCTX,
    OSSL_PROVIDER,
};

use super::Provider;
use crate::ffi::ffi_callback;
use crate::handle::Handle;

ffi_callback! {
    /// `core_get_libctx`: the library context the provider was loaded into, as given (NULL
    /// for the default).
    ///
    /// # Safety
    /// `handle` is a provider's handle.
    pub(crate) unsafe extern "C" fn core_get_libctx(handle: *const OSSL_CORE_HANDLE) -> *mut OPENSSL_CORE_CTX
    where failure = core::ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee: the handle is a provider.
        let prov: Option<&Provider> = unsafe { OSSL_PROVIDER::get(handle.cast()) };
        prov.map_or(core::ptr::null_mut(), |p| p.libctx().cast())
    }
}

/// A function as a dispatch table holds it.
const fn entry(function_id: i32, f: unsafe extern "C" fn()) -> OSSL_DISPATCH {
    OSSL_DISPATCH {
        function_id,
        function: Some(f),
    }
}

/// `core_get_libctx` as a dispatch table's function.
const GET_LIBCTX: unsafe extern "C" fn() = {
    let f: unsafe extern "C" fn(*const OSSL_CORE_HANDLE) -> *mut OPENSSL_CORE_CTX = core_get_libctx;
    // SAFETY: function pointers all have one representation; the provider casts it back to
    // `OSSL_FUNC_core_get_libctx_fn` before calling it.
    unsafe {
        core::mem::transmute::<
            unsafe extern "C" fn(*const OSSL_CORE_HANDLE) -> *mut OPENSSL_CORE_CTX,
            unsafe extern "C" fn(),
        >(f)
    }
};

/// The core's dispatch table, ended by a zero function id.
pub(crate) static DISPATCH: [OSSL_DISPATCH; 2] = [
    entry(OSSL_FUNC_CORE_GET_LIBCTX, GET_LIBCTX),
    OSSL_DISPATCH {
        function_id: 0,
        function: None,
    },
];
