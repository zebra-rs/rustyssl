//! The MSBLOB and PVK encoders (`encode_key2ms.c`): RSA and DSA keys written by `pvkfmt`'s
//! writers, a PVK encrypted to the context's level with the passphrase the callback gives.

use core::ffi::{c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT, EVP_PKEY, OSSL_CORE_BIO, OSSL_DISPATCH,
    OSSL_ENCODER_PARAM_ENCRYPT_LEVEL, OSSL_FUNC_ENCODER_DOES_SELECTION, OSSL_FUNC_ENCODER_ENCODE,
    OSSL_FUNC_ENCODER_FREE_OBJECT, OSSL_FUNC_ENCODER_FREECTX, OSSL_FUNC_ENCODER_IMPORT_OBJECT,
    OSSL_FUNC_ENCODER_NEWCTX, OSSL_FUNC_ENCODER_SET_CTX_PARAMS,
    OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, OSSL_KEYMGMT_SELECT_KEYPAIR,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_PARAM,
    OSSL_PARAM_INTEGER, OSSL_PASSPHRASE_CALLBACK,
};

use super::builtin::libctx_of;
use super::encoders::import_key;
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::decoder::ctx::bio_new_from_core_bio;
use crate::err;
use crate::ffi::ffi_callback;
use crate::params::{OSSL_PARAM_get_int, OSSL_PARAM_locate_const};
use crate::passphrase::{PwData, pw_pvk_password};

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

/// A key's `EVP_PKEY_set1_*`.
type Set1Fn = unsafe fn(*mut EVP_PKEY, *mut c_void) -> c_int;

/// `EVP_PKEY_set1_RSA`, for the encoders.
///
/// # Safety
/// `pkey` is a live key; `key` is a live RSA key.
unsafe fn rsa_set1(pkey: *mut EVP_PKEY, key: *mut c_void) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { crate::evp::pkey::rsa::EVP_PKEY_set1_RSA(pkey, key.cast()) }
}

/// `EVP_PKEY_set1_DSA`, for the encoders.
///
/// # Safety
/// `pkey` is a live key; `key` is a live DSA key.
unsafe fn dsa_set1(pkey: *mut EVP_PKEY, key: *mut c_void) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { crate::evp::pkey::dsa::EVP_PKEY_set1_DSA(pkey, key.cast()) }
}

/// The encoder ctx behind `vctx`.
///
/// # Safety
/// `vctx` is NULL or a live context from `key2ms_newctx`.
unsafe fn mctx<'a>(vctx: *mut c_void) -> Option<&'a mut Key2Ms> {
    // SAFETY: the caller's guarantee.
    unsafe { vctx.cast::<Key2Ms>().as_mut() }
}

/// `key2msblob_encode` and `key2pvk_encode`: the key written as a blob (its private key for a
/// selection with one, else its public key) or a PVK (a private key only): what the writer
/// returns (a PVK's -1 for failure included, as OpenSSL returns it), or 0.
///
/// # Safety
/// `c` is the encoder's context; `cout` is a live core BIO; `key` is a live key of `set1`'s
/// type; the callback takes its argument.
#[allow(clippy::too_many_arguments, reason = "key2ms's")]
unsafe fn encode(
    c: &mut Key2Ms,
    cout: *mut OSSL_CORE_BIO,
    key: *const c_void,
    key_abstract: *const OSSL_PARAM,
    selection: c_int,
    set1: Set1Fn,
    pvk: bool,
    pw_cb: OSSL_PASSPHRASE_CALLBACK,
    pw_cbarg: *mut c_void,
) -> c_int {
    if !key_abstract.is_null() {
        err::raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT, "key2ms_encode");
        return 0;
    }
    let ispub = if pvk {
        if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY == 0 {
            return 0;
        }
        false
    } else if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0 {
        false
    } else if selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY != 0 {
        true
    } else {
        return 0;
    };
    // SAFETY: no preconditions.
    let pkey = unsafe { crate::evp::pkey::EVP_PKEY_new() };
    // SAFETY: the new key; the caller's key (not changed: a reference is taken).
    let mut ok = !pkey.is_null() && unsafe { set1(pkey, key.cast_mut()) } != 0;
    if pvk {
        ok = ok && (pw_cb.is_none() || c.pwdata.set_ossl_passphrase_cb(pw_cb, pw_cbarg));
    }
    let ret = if ok {
        // SAFETY: the caller's guarantee.
        let out = unsafe { bio_new_from_core_bio(cout) };
        if out.is_null() {
            0
        } else {
            let r = if pvk {
                // SAFETY: the provider's context, live while the provider is.
                let libctx = unsafe { libctx_of(c.provctx) };
                // SAFETY: the BIO and key made above; the password callback over the
                // context's data.
                unsafe {
                    crate::pvkfmt::i2b_PVK_bio_ex(
                        out,
                        pkey,
                        c.pvk_encr_level,
                        Some(pw_pvk_password),
                        (&raw mut c.pwdata).cast(),
                        libctx,
                        ptr::null(),
                    )
                }
            } else if ispub {
                // SAFETY: as above.
                unsafe { crate::pvkfmt::i2b_PublicKey_bio(out, pkey) }
            } else {
                // SAFETY: as above.
                unsafe { crate::pvkfmt::i2b_PrivateKey_bio(out, pkey) }
            };
            // SAFETY: made above.
            unsafe { crate::bio::BIO_free(out) };
            r
        }
    } else {
        0
    };
    // SAFETY: made above, or NULL.
    unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
    ret
}

/// An encoder's `import_object` and `encode` (`MAKE_MS_ENCODER`'s).
macro_rules! ms_fns {
    ($import:ident, $encode:ident, $kmgmt:expr, $set1:ident, $pvk:expr) => {
        ffi_callback! {
            /// The encoder's `import_object`: a key of its type (`ossl_prov_import_key`).
            ///
            /// # Safety
            /// `vctx` is a live context; `params` is NULL or an array.
            pub(crate) unsafe extern "C" fn $import(vctx: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
            where failure = ptr::null_mut(), library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                let Some(c) = (unsafe { mctx(vctx) }) else { return ptr::null_mut() };
                let fns: &[OSSL_DISPATCH] = &$kmgmt.0;
                // SAFETY: a built-in table; the provider's context; the caller's array.
                unsafe { import_key(fns, c.provctx, selection, params) }
            }
        }

        ffi_callback! {
            /// The encoder's `encode`.
            ///
            /// # Safety
            /// As for an encoder's `encode`.
            pub(crate) unsafe extern "C" fn $encode(vctx: *mut c_void, cout: *mut OSSL_CORE_BIO, key: *const c_void, key_abstract: *const OSSL_PARAM, selection: c_int, cb: OSSL_PASSPHRASE_CALLBACK, cbarg: *mut c_void) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                let Some(c) = (unsafe { mctx(vctx) }) else { return 0 };
                // SAFETY: as above.
                unsafe { encode(c, cout, key, key_abstract, selection, $set1, $pvk, cb, cbarg) }
            }
        }
    };
}

/// An MSBLOB encoder's table (`MAKE_MS_ENCODER(impl, msblob, type)`).
macro_rules! msblob {
    ($table:ident, $import:ident, $encode:ident, $free:path) => {
        pub(super) static $table: Dispatch<7> = Dispatch([
            entry!(OSSL_FUNC_ENCODER_NEWCTX, key2ms_newctx, NewCtxFn),
            entry!(OSSL_FUNC_ENCODER_FREECTX, key2ms_freectx, FreeCtxFn),
            entry!(
                OSSL_FUNC_ENCODER_DOES_SELECTION,
                key2ms_does_selection,
                DoesSelectionFn
            ),
            entry!(OSSL_FUNC_ENCODER_IMPORT_OBJECT, $import, ImportObjectFn),
            entry!(OSSL_FUNC_ENCODER_FREE_OBJECT, $free, FreeObjectFn),
            entry!(OSSL_FUNC_ENCODER_ENCODE, $encode, EncodeFn),
            END,
        ]);
    };
}

/// A PVK encoder's table (`MAKE_MS_ENCODER(impl, pvk, type)`), with its parameters.
macro_rules! pvk {
    ($table:ident, $import:ident, $encode:ident, $free:path) => {
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
            entry!(OSSL_FUNC_ENCODER_IMPORT_OBJECT, $import, ImportObjectFn),
            entry!(OSSL_FUNC_ENCODER_FREE_OBJECT, $free, FreeObjectFn),
            entry!(OSSL_FUNC_ENCODER_ENCODE, $encode, EncodeFn),
            END,
        ]);
    };
}

ms_fns!(
    dsa2pvk_import_object,
    dsa2pvk_encode,
    super::dsa_kmgmt::DSA_KEYMGMT,
    dsa_set1,
    true
);
ms_fns!(
    dsa2msblob_import_object,
    dsa2msblob_encode,
    super::dsa_kmgmt::DSA_KEYMGMT,
    dsa_set1,
    false
);
ms_fns!(
    rsa2pvk_import_object,
    rsa2pvk_encode,
    super::rsa_kmgmt::RSA_KEYMGMT,
    rsa_set1,
    true
);
ms_fns!(
    rsa2msblob_import_object,
    rsa2msblob_encode,
    super::rsa_kmgmt::RSA_KEYMGMT,
    rsa_set1,
    false
);

pvk!(
    DSA_TO_PVK,
    dsa2pvk_import_object,
    dsa2pvk_encode,
    super::dsa_kmgmt::dsa_freedata
);
msblob!(
    DSA_TO_MSBLOB,
    dsa2msblob_import_object,
    dsa2msblob_encode,
    super::dsa_kmgmt::dsa_freedata
);
pvk!(
    RSA_TO_PVK,
    rsa2pvk_import_object,
    rsa2pvk_encode,
    super::rsa_kmgmt::rsa_freedata
);
msblob!(
    RSA_TO_MSBLOB,
    rsa2msblob_import_object,
    rsa2msblob_encode,
    super::rsa_kmgmt::rsa_freedata
);
