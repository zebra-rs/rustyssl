//! The default provider's key exchanges, asymmetric ciphers, and KEMs (`deflt_keyexch`,
//! `deflt_asym_cipher`, and `deflt_asym_kem` in `providers/defltprov.c`): so far the KDF
//! exchanges of TLS1-PRF, HKDF, and SCRYPT (`kdf_exch.c`), which derive through an
//! `EVP_KDF_CTX` of the KDF. The exchanges, ciphers, and KEMs of the key types come with them
//! (4.3 onwards); their names are registered in order (see [`super::tables::pending`]).
//!
//! As in OpenSSL, a KDF exchange's context holds an `EVP_KDF_CTX` (fetched without
//! properties) and a reference to the key's (empty) data; the context's parameters are the
//! KDF's, and a KDF of unbounded output derives as many octets as asked.

use core::ffi::{CStr, c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PROV, EVP_KDF_CTX, OSSL_ALGORITHM, OSSL_FUNC_KEYEXCH_DERIVE, OSSL_FUNC_KEYEXCH_DUPCTX,
    OSSL_FUNC_KEYEXCH_FREECTX, OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
    OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, OSSL_FUNC_KEYEXCH_INIT, OSSL_FUNC_KEYEXCH_NEWCTX,
    OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, OSSL_PARAM,
    PROV_R_OUTPUT_BUFFER_TOO_SMALL,
};

use super::builtin::libctx_of;
use super::keymgmt::{kdf_data_up_ref, kdf_freedata};
use super::tables::{ALG_END, Algorithms, Dispatch, END, alg, entry, pending};
use crate::err;
use crate::evp::kdf::{
    EVP_KDF_CTX_dup, EVP_KDF_CTX_free, EVP_KDF_CTX_get_kdf_size, EVP_KDF_CTX_get_params,
    EVP_KDF_CTX_new, EVP_KDF_CTX_set_params, EVP_KDF_derive, EVP_KDF_fetch, EVP_KDF_free,
    EVP_KDF_gettable_ctx_params, EVP_KDF_settable_ctx_params,
};
use crate::ffi::ffi_callback;
use crate::provider::Ptr;

/// A KDF exchange's context (`PROV_KDF_CTX`).
struct KdfExchCtx {
    kdfctx: Ptr<EVP_KDF_CTX>,
    /// The key's data, with a reference (`KDF_DATA *`), or NULL.
    kdfdata: Ptr<c_void>,
}

impl Drop for KdfExchCtx {
    fn drop(&mut self) {
        // SAFETY: the context's own KDF context, or NULL.
        unsafe { EVP_KDF_CTX_free(self.kdfctx.0) };
        // SAFETY: the context's reference to the data, or NULL.
        unsafe { kdf_freedata(self.kdfdata.0) };
    }
}

/// The context behind `vctx`, or `None` for NULL.
///
/// # Safety
/// `vctx` is NULL or a context from `kdf_newctx`, used by one caller at a time.
unsafe fn context<'a>(vctx: *mut c_void) -> Option<&'a mut KdfExchCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { vctx.cast::<KdfExchCtx>().as_mut() }
}

/// `kdf_newctx`: a context deriving with the KDF `kdfname`; NULL if it can't be fetched.
///
/// # Safety
/// `provctx` is the default provider's context.
unsafe fn kdf_newctx(kdfname: &CStr, provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let libctx = unsafe { libctx_of(provctx) };
    // SAFETY: the provider's context; a static name.
    let kdf = unsafe { EVP_KDF_fetch(libctx, kdfname.as_ptr(), ptr::null()) };
    if kdf.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the method fetched above.
    let kdfctx = unsafe { EVP_KDF_CTX_new(kdf) };
    // SAFETY: the reference fetched above (the context holds its own).
    unsafe { EVP_KDF_free(kdf) };
    if kdfctx.is_null() {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new(KdfExchCtx {
        kdfctx: Ptr(kdfctx),
        kdfdata: Ptr(ptr::null_mut()),
    }))
    .cast()
}

macro_rules! kdf_fns {
    ($newctx:ident, $settable:ident, $gettable:ident, $kdf:expr) => {
        ffi_callback! {
            /// `kdf_*_newctx`.
            ///
            /// # Safety
            /// `provctx` is the default provider's context.
            pub(crate) unsafe extern "C" fn $newctx(provctx: *mut c_void) -> *mut c_void
            where failure = ptr::null_mut(), library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { kdf_newctx($kdf, provctx) }
            }
        }

        ffi_callback! {
            /// `kdf_*_settable_ctx_params`: the KDF's.
            ///
            /// # Safety
            /// `provctx` is the default provider's context.
            pub(crate) unsafe extern "C" fn $settable(_vctx: *mut c_void, provctx: *mut c_void) -> *const OSSL_PARAM
            where failure = ptr::null(), library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { kdf_list(provctx, $kdf, true) }
            }
        }

        ffi_callback! {
            /// `kdf_*_gettable_ctx_params`: the KDF's.
            ///
            /// # Safety
            /// `provctx` is the default provider's context.
            pub(crate) unsafe extern "C" fn $gettable(_vctx: *mut c_void, provctx: *mut c_void) -> *const OSSL_PARAM
            where failure = ptr::null(), library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { kdf_list(provctx, $kdf, false) }
            }
        }
    };
}

kdf_fns!(
    kdf_tls1_prf_newctx,
    kdf_tls1_prf_settable,
    kdf_tls1_prf_gettable,
    c"TLS1-PRF"
);
kdf_fns!(
    kdf_hkdf_newctx,
    kdf_hkdf_settable,
    kdf_hkdf_gettable,
    c"HKDF"
);
kdf_fns!(
    kdf_scrypt_newctx,
    kdf_scrypt_settable,
    kdf_scrypt_gettable,
    c"SCRYPT"
);

/// The KDF's settable (or gettable) context parameters, a static list of its.
///
/// # Safety
/// `provctx` is the default provider's context.
unsafe fn kdf_list(provctx: *mut c_void, kdfname: &CStr, settable: bool) -> *const OSSL_PARAM {
    // SAFETY: the caller's guarantee.
    let libctx = unsafe { libctx_of(provctx) };
    // SAFETY: the provider's context; a static name.
    let kdf = unsafe { EVP_KDF_fetch(libctx, kdfname.as_ptr(), ptr::null()) };
    if kdf.is_null() {
        return ptr::null();
    }
    let list = if settable {
        // SAFETY: the method fetched above.
        unsafe { EVP_KDF_settable_ctx_params(kdf) }
    } else {
        // SAFETY: as above.
        unsafe { EVP_KDF_gettable_ctx_params(kdf) }
    };
    // SAFETY: the reference fetched above.
    unsafe { EVP_KDF_free(kdf) };
    list
}

ffi_callback! {
    /// `kdf_init`: takes a reference to the key's data and the parameters.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `vkdf` is NULL or live KDF key data; `params` is NULL
    /// or an array.
    pub(crate) unsafe extern "C" fn kdf_init(vctx: *mut c_void, vkdf: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(vctx) }) else { return 0 };
        if vkdf.is_null() {
            return 0;
        }
        // SAFETY: the caller's live data; the context takes a reference.
        unsafe { kdf_data_up_ref(vkdf) };
        let old = core::mem::replace(&mut c.kdfdata, Ptr(vkdf));
        // SAFETY: the context's old reference, or NULL.
        unsafe { kdf_freedata(old.0) };
        // SAFETY: the KDF context; the caller's array.
        unsafe { EVP_KDF_CTX_set_params(c.kdfctx.0, params) }
    }
}

ffi_callback! {
    /// `kdf_derive`: the KDF's size with a NULL `secret`; else derives `outlen` octets (the
    /// KDF's size if it has one, which `outlen` must reach).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `secret` is NULL or has room for `outlen` octets;
    /// `secretlen` is room for a size.
    pub(crate) unsafe extern "C" fn kdf_derive(vctx: *mut c_void, secret: *mut u8, secretlen: *mut usize, outlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(vctx) }) else { return 0 };
        // SAFETY: the KDF context.
        let kdfsize = unsafe { EVP_KDF_CTX_get_kdf_size(c.kdfctx.0) };
        if secret.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { secretlen.write(kdfsize) };
            return 1;
        }
        let mut outlen = outlen;
        if kdfsize != usize::MAX {
            if outlen < kdfsize {
                err::raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL, "kdf_derive");
                return 0;
            }
            outlen = kdfsize;
        }
        // SAFETY: the KDF context; the caller's buffer of `outlen` octets.
        if unsafe { EVP_KDF_derive(c.kdfctx.0, secret, outlen, ptr::null()) } <= 0 {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { secretlen.write(outlen) };
        1
    }
}

ffi_callback! {
    /// `kdf_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context, not used afterwards.
    pub(crate) unsafe extern "C" fn kdf_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        if !vctx.is_null() {
            // SAFETY: the box `kdf_newctx` made, freed once.
            drop(unsafe { Box::from_raw(vctx.cast::<KdfExchCtx>()) });
        }
    }
}

ffi_callback! {
    /// `kdf_dupctx`: a copy with a copy of the KDF context and its own reference to the data.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn kdf_dupctx(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(src) = (unsafe { context(vctx) }) else { return ptr::null_mut() };
        // SAFETY: the source's KDF context.
        let kdfctx = unsafe { EVP_KDF_CTX_dup(src.kdfctx.0) };
        if kdfctx.is_null() {
            return ptr::null_mut();
        }
        if src.kdfdata.0.is_null() {
            // SAFETY: the copy, freed once.
            unsafe { EVP_KDF_CTX_free(kdfctx) };
            return ptr::null_mut();
        }
        // SAFETY: the source's live data; the copy takes a reference.
        unsafe { kdf_data_up_ref(src.kdfdata.0) };
        Box::into_raw(Box::new(KdfExchCtx {
            kdfctx: Ptr(kdfctx),
            kdfdata: src.kdfdata,
        }))
        .cast()
    }
}

ffi_callback! {
    /// `kdf_set_ctx_params`: the KDF context's.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn kdf_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(vctx) }) else { return 0 };
        // SAFETY: the KDF context; the caller's array.
        unsafe { EVP_KDF_CTX_set_params(c.kdfctx.0, params) }
    }
}

ffi_callback! {
    /// `kdf_get_ctx_params`: the KDF context's.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn kdf_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(vctx) }) else { return 0 };
        // SAFETY: the KDF context; the caller's array.
        unsafe { EVP_KDF_CTX_get_params(c.kdfctx.0, params) }
    }
}

type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type InitFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;
type DeriveFn = unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize) -> c_int;
type FreeFn = unsafe extern "C" fn(*mut c_void);
type DupFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type SetFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type GetFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;

macro_rules! kdf_keyexch {
    ($table:ident, $newctx:ident, $settable:ident, $gettable:ident) => {
        /// `ossl_kdf_*_keyexch_functions`.
        static $table: Dispatch<10> = Dispatch([
            entry!(OSSL_FUNC_KEYEXCH_NEWCTX, $newctx, NewCtxFn),
            entry!(OSSL_FUNC_KEYEXCH_INIT, kdf_init, InitFn),
            entry!(OSSL_FUNC_KEYEXCH_DERIVE, kdf_derive, DeriveFn),
            entry!(OSSL_FUNC_KEYEXCH_FREECTX, kdf_freectx, FreeFn),
            entry!(OSSL_FUNC_KEYEXCH_DUPCTX, kdf_dupctx, DupFn),
            entry!(OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, kdf_set_ctx_params, SetFn),
            entry!(OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, kdf_get_ctx_params, GetFn),
            entry!(OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, $settable, ListFn),
            entry!(OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, $gettable, ListFn),
            END,
        ]);
    };
}

kdf_keyexch!(
    TLS1_PRF_KEYEXCH,
    kdf_tls1_prf_newctx,
    kdf_tls1_prf_settable,
    kdf_tls1_prf_gettable
);
kdf_keyexch!(
    HKDF_KEYEXCH,
    kdf_hkdf_newctx,
    kdf_hkdf_settable,
    kdf_hkdf_gettable
);
kdf_keyexch!(
    SCRYPT_KEYEXCH,
    kdf_scrypt_newctx,
    kdf_scrypt_settable,
    kdf_scrypt_gettable
);

/// The default provider's key exchanges, in `deflt_keyexch`'s order; those of later steps'
/// key types are pending.
static DEFAULT_KEYEXCH: Algorithms<8> = Algorithms([
    pending(c"DH:dhKeyAgreement:1.2.840.113549.1.3.1"),
    alg(c"ECDH", &super::ecdh_exch::ECDH_KEYEXCH),
    alg(c"X25519:1.3.101.110", &super::ecx_exch::X25519_KEYEXCH),
    alg(c"X448:1.3.101.111", &super::ecx_exch::X448_KEYEXCH),
    alg(c"TLS1-PRF", &TLS1_PRF_KEYEXCH),
    alg(c"HKDF", &HKDF_KEYEXCH),
    alg(c"SCRYPT:id-scrypt:1.3.6.1.4.1.11591.4.11", &SCRYPT_KEYEXCH),
    ALG_END,
]);

/// The default provider's asymmetric ciphers (`deflt_asym_cipher`).
static DEFAULT_ASYM_CIPHERS: Algorithms<3> = Algorithms([
    alg(
        c"RSA:rsaEncryption:1.2.840.113549.1.1.1",
        &super::rsa_enc::RSA_ASYM_CIPHER,
    ),
    alg(c"SM2:1.2.156.10197.1.301", &super::sm2_enc::SM2_ASYM_CIPHER),
    ALG_END,
]);

/// The default provider's KEMs (`deflt_asym_kem`); those of later steps are pending.
static DEFAULT_KEMS: Algorithms<12> = Algorithms([
    alg(
        c"RSA:rsaEncryption:1.2.840.113549.1.1.1",
        &super::rsa_kem::RSA_KEM,
    ),
    pending(c"X25519:1.3.101.110"),
    pending(c"X448:1.3.101.111"),
    pending(c"EC:id-ecPublicKey:1.2.840.10045.2.1"),
    pending(c"ML-KEM-512:MLKEM512:id-alg-ml-kem-512:2.16.840.1.101.3.4.4.1"),
    pending(c"ML-KEM-768:MLKEM768:id-alg-ml-kem-768:2.16.840.1.101.3.4.4.2"),
    pending(c"ML-KEM-1024:MLKEM1024:id-alg-ml-kem-1024:2.16.840.1.101.3.4.4.3"),
    pending(c"X25519MLKEM768"),
    pending(c"X448MLKEM1024"),
    pending(c"SecP256r1MLKEM768"),
    pending(c"SecP384r1MLKEM1024"),
    ALG_END,
]);

/// The default provider's key exchanges, for `OSSL_OP_KEYEXCH`.
pub(crate) fn default_keyexch() -> *const OSSL_ALGORITHM {
    DEFAULT_KEYEXCH.0.as_ptr()
}

/// The default provider's asymmetric ciphers, for `OSSL_OP_ASYM_CIPHER`.
pub(crate) fn default_asym_ciphers() -> *const OSSL_ALGORITHM {
    DEFAULT_ASYM_CIPHERS.0.as_ptr()
}

/// The default provider's KEMs, for `OSSL_OP_KEM`.
pub(crate) fn default_kems() -> *const OSSL_ALGORITHM {
    DEFAULT_KEMS.0.as_ptr()
}
