//! ECDSA and ECDH as the library's `EC_KEY_METHOD` performs them (`ecdsa_ossl.c`,
//! `ecdh_ossl.c`). Until step 4.4c3 implements them, each fails closed: it names itself and
//! aborts, as every unimplemented export does, so nothing reports a signature or a shared
//! secret it didn't compute.

use core::ffi::{c_int, c_uchar, c_uint};

use rustyssl_abi::{BIGNUM, BN_CTX, EC_KEY, EC_POINT, ECDSA_SIG, ERR_LIB_EC};

use crate::ffi::ffi_callback;

ffi_callback! {
    /// `ossl_ecdh_compute_key` (step 4.4c3).
    ///
    /// # Safety
    /// Never returns.
    pub(crate) unsafe extern "C" fn ossl_ecdh_compute_key(psec: *mut *mut c_uchar, pseclen: *mut usize, pub_key: *const EC_POINT, ecdh: *const EC_KEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let _ = (psec, pseclen, pub_key, ecdh);
        crate::stub::unimplemented("ossl_ecdh_compute_key")
    }
}

ffi_callback! {
    /// `ossl_ecdsa_sign` (step 4.4c3).
    ///
    /// # Safety
    /// Never returns.
    pub(crate) unsafe extern "C" fn ossl_ecdsa_sign(type_: c_int, dgst: *const c_uchar, dlen: c_int, sig: *mut c_uchar, siglen: *mut c_uint, kinv: *const BIGNUM, r: *const BIGNUM, eckey: *mut EC_KEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let _ = (type_, dgst, dlen, sig, siglen, kinv, r, eckey);
        crate::stub::unimplemented("ossl_ecdsa_sign")
    }
}

ffi_callback! {
    /// `ossl_ecdsa_sign_setup` (step 4.4c3).
    ///
    /// # Safety
    /// Never returns.
    pub(crate) unsafe extern "C" fn ossl_ecdsa_sign_setup(eckey: *mut EC_KEY, ctx_in: *mut BN_CTX, kinvp: *mut *mut BIGNUM, rp: *mut *mut BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let _ = (eckey, ctx_in, kinvp, rp);
        crate::stub::unimplemented("ossl_ecdsa_sign_setup")
    }
}

ffi_callback! {
    /// `ossl_ecdsa_sign_sig` (step 4.4c3).
    ///
    /// # Safety
    /// Never returns.
    pub(crate) unsafe extern "C" fn ossl_ecdsa_sign_sig(dgst: *const c_uchar, dgst_len: c_int, in_kinv: *const BIGNUM, in_r: *const BIGNUM, eckey: *mut EC_KEY) -> *mut ECDSA_SIG
    where failure = core::ptr::null_mut(), library = ERR_LIB_EC
    {
        let _ = (dgst, dgst_len, in_kinv, in_r, eckey);
        crate::stub::unimplemented("ossl_ecdsa_sign_sig")
    }
}

ffi_callback! {
    /// `ossl_ecdsa_verify` (step 4.4c3).
    ///
    /// # Safety
    /// Never returns.
    pub(crate) unsafe extern "C" fn ossl_ecdsa_verify(type_: c_int, dgst: *const c_uchar, dgst_len: c_int, sigbuf: *const c_uchar, sig_len: c_int, eckey: *mut EC_KEY) -> c_int
    where failure = -1, library = ERR_LIB_EC
    {
        let _ = (type_, dgst, dgst_len, sigbuf, sig_len, eckey);
        crate::stub::unimplemented("ossl_ecdsa_verify")
    }
}

ffi_callback! {
    /// `ossl_ecdsa_verify_sig` (step 4.4c3).
    ///
    /// # Safety
    /// Never returns.
    pub(crate) unsafe extern "C" fn ossl_ecdsa_verify_sig(dgst: *const c_uchar, dgst_len: c_int, sig: *const ECDSA_SIG, eckey: *mut EC_KEY) -> c_int
    where failure = -1, library = ERR_LIB_EC
    {
        let _ = (dgst, dgst_len, sig, eckey);
        crate::stub::unimplemented("ossl_ecdsa_verify_sig")
    }
}
