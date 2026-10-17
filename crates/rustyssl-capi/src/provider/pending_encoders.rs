//! The MSBLOB and PVK encoders (`encode_key2ms.c`), placeholders until step 4.7e: their
//! contexts and parameters are OpenSSL's, but making a key from another provider's and
//! encoding one abort.

use core::ffi::{c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PROV, OSSL_CORE_BIO, OSSL_ENCODER_PARAM_ENCRYPT_LEVEL,
    OSSL_FUNC_ENCODER_DOES_SELECTION, OSSL_FUNC_ENCODER_ENCODE, OSSL_FUNC_ENCODER_FREE_OBJECT,
    OSSL_FUNC_ENCODER_FREECTX, OSSL_FUNC_ENCODER_IMPORT_OBJECT, OSSL_FUNC_ENCODER_NEWCTX,
    OSSL_FUNC_ENCODER_SET_CTX_PARAMS, OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
    OSSL_KEYMGMT_SELECT_KEYPAIR, OSSL_PARAM, OSSL_PARAM_INTEGER, OSSL_PASSPHRASE_CALLBACK,
};

use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::ffi::ffi_callback;
use crate::params::{OSSL_PARAM_get_int, OSSL_PARAM_locate_const};
use crate::passphrase::PwData;

type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type ListFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type DoesSelectionFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type ImportObjectFn = unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_PARAM) -> *mut c_void;
type FreeObjectFn = unsafe extern "C" fn(*mut c_void);
type EncodeFn = unsafe extern "C" fn(
    *mut c_void,
    *mut OSSL_CORE_BIO,
    *const c_void,
    *const OSSL_PARAM,
    c_int,
    OSSL_PASSPHRASE_CALLBACK,
    *mut c_void,
) -> c_int;

/// `struct key2ms_ctx_st`.
struct Key2Ms {
    #[allow(dead_code, reason = "the encoders (4.7e) write with it")]
    provctx: *mut c_void,
    pvk_encr_level: c_int,
    pwdata: PwData,
}

ffi_callback! {
    /// `key2ms_newctx`: encryption level 2.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn key2ms_newctx(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        Box::into_raw(Box::new(Key2Ms { provctx, pvk_encr_level: 2, pwdata: PwData::default() })).cast()
    }
}

ffi_callback! {
    /// `key2ms_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context from `key2ms_newctx` the caller gives up.
    pub(crate) unsafe extern "C" fn key2ms_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        if !vctx.is_null() {
            // SAFETY: the caller's guarantee.
            let mut c = unsafe { Box::from_raw(vctx.cast::<Key2Ms>()) };
            c.pwdata.clear();
        }
    }
}

/// `key2pvk_settable_ctx_params`'s table.
static SETTABLE: Params<2> = Params([
    defn(
        OSSL_ENCODER_PARAM_ENCRYPT_LEVEL,
        OSSL_PARAM_INTEGER,
        size_of::<c_int>(),
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `key2pvk_settable_ctx_params`: the encryption level.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn key2pvk_settable_ctx_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `key2pvk_set_ctx_params`: the encryption level.
    ///
    /// # Safety
    /// `vctx` is a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn key2pvk_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { vctx.cast::<Key2Ms>().as_mut() }) else { return 0 };
        // SAFETY: the caller's array; a static name.
        let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_ENCRYPT_LEVEL.as_ptr()) };
        // SAFETY: a parameter of the array.
        if !p.is_null() && unsafe { OSSL_PARAM_get_int(p, &raw mut c.pvk_encr_level) } == 0 {
            return 0;
        }
        1
    }
}

ffi_callback! {
    /// `key2ms_does_selection`: a key pair's part.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn key2ms_does_selection(_vctx: *mut c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        c_int::from(selection & OSSL_KEYMGMT_SELECT_KEYPAIR != 0)
    }
}

ffi_callback! {
    /// The encoders' `import_object`, which comes with step 4.7e.
    ///
    /// # Safety
    /// No preconditions: it aborts.
    pub(crate) unsafe extern "C" fn key2ms_import_object(_vctx: *mut c_void, _selection: c_int, _params: *const OSSL_PARAM) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        crate::stub::unimplemented("the MSBLOB and PVK encoders (step 4.7e)")
    }
}

ffi_callback! {
    /// The encoders' `encode`, which comes with step 4.7e.
    ///
    /// # Safety
    /// No preconditions: it aborts.
    pub(crate) unsafe extern "C" fn key2ms_encode(_vctx: *mut c_void, _cout: *mut OSSL_CORE_BIO, _key: *const c_void, _key_abstract: *const OSSL_PARAM, _selection: c_int, _cb: OSSL_PASSPHRASE_CALLBACK, _cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        crate::stub::unimplemented("the MSBLOB and PVK encoders (step 4.7e)")
    }
}

/// An MSBLOB encoder's table (`MAKE_MS_ENCODER(impl, msblob, type)`).
macro_rules! msblob {
    ($table:ident, $free:path) => {
        pub(super) static $table: Dispatch<7> = Dispatch([
            entry!(OSSL_FUNC_ENCODER_NEWCTX, key2ms_newctx, NewCtxFn),
            entry!(OSSL_FUNC_ENCODER_FREECTX, key2ms_freectx, FreeCtxFn),
            entry!(
                OSSL_FUNC_ENCODER_DOES_SELECTION,
                key2ms_does_selection,
                DoesSelectionFn
            ),
            entry!(
                OSSL_FUNC_ENCODER_IMPORT_OBJECT,
                key2ms_import_object,
                ImportObjectFn
            ),
            entry!(OSSL_FUNC_ENCODER_FREE_OBJECT, $free, FreeObjectFn),
            entry!(OSSL_FUNC_ENCODER_ENCODE, key2ms_encode, EncodeFn),
            END,
        ]);
    };
}

/// A PVK encoder's table (`MAKE_MS_ENCODER(impl, pvk, type)`), with its parameters.
macro_rules! pvk {
    ($table:ident, $free:path) => {
        pub(super) static $table: Dispatch<9> = Dispatch([
            entry!(OSSL_FUNC_ENCODER_NEWCTX, key2ms_newctx, NewCtxFn),
            entry!(OSSL_FUNC_ENCODER_FREECTX, key2ms_freectx, FreeCtxFn),
            entry!(
                OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                key2pvk_settable_ctx_params,
                ListFn
            ),
            entry!(
                OSSL_FUNC_ENCODER_SET_CTX_PARAMS,
                key2pvk_set_ctx_params,
                SetParamsFn
            ),
            entry!(
                OSSL_FUNC_ENCODER_DOES_SELECTION,
                key2ms_does_selection,
                DoesSelectionFn
            ),
            entry!(
                OSSL_FUNC_ENCODER_IMPORT_OBJECT,
                key2ms_import_object,
                ImportObjectFn
            ),
            entry!(OSSL_FUNC_ENCODER_FREE_OBJECT, $free, FreeObjectFn),
            entry!(OSSL_FUNC_ENCODER_ENCODE, key2ms_encode, EncodeFn),
            END,
        ]);
    };
}

pvk!(DSA_TO_PVK, super::dsa_kmgmt::dsa_freedata);
msblob!(DSA_TO_MSBLOB, super::dsa_kmgmt::dsa_freedata);
pvk!(RSA_TO_PVK, super::rsa_kmgmt::rsa_freedata);
msblob!(RSA_TO_MSBLOB, super::rsa_kmgmt::rsa_freedata);
