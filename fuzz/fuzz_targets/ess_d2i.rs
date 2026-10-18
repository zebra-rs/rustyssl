//! Fuzzes ESS's decoders on untrusted input: the input decoded as a SigningCertificate and
//! as a SigningCertificateV2 (as a signer's attributes carry them), encoded again, and
//! checked against an empty chain. Nothing may crash or read out of bounds (ASan).

#![no_main]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{ESS_SIGNING_CERT, ESS_SIGNING_CERT_V2};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_ESS_SIGNING_CERT(a: *mut *mut ESS_SIGNING_CERT, pp: *mut *const c_uchar, len: c_long) -> *mut ESS_SIGNING_CERT;
    fn i2d_ESS_SIGNING_CERT(a: *const ESS_SIGNING_CERT, out: *mut *mut c_uchar) -> c_int;
    fn ESS_SIGNING_CERT_free(a: *mut ESS_SIGNING_CERT);
    fn d2i_ESS_SIGNING_CERT_V2(a: *mut *mut ESS_SIGNING_CERT_V2, pp: *mut *const c_uchar, len: c_long) -> *mut ESS_SIGNING_CERT_V2;
    fn i2d_ESS_SIGNING_CERT_V2(a: *const ESS_SIGNING_CERT_V2, out: *mut *mut c_uchar) -> c_int;
    fn ESS_SIGNING_CERT_V2_free(a: *mut ESS_SIGNING_CERT_V2);
    fn OSSL_ESS_check_signing_certs(ss: *const ESS_SIGNING_CERT, ssv2: *const ESS_SIGNING_CERT_V2, chain: *const c_void, require: c_int) -> c_int;
    fn OPENSSL_sk_new_null() -> *mut c_void;
    fn OPENSSL_sk_free(sk: *mut c_void);
    fn CRYPTO_free(p: *mut c_void, file: *const core::ffi::c_char, line: c_int);
    fn ERR_clear_error();
}

fuzz_target!(|data: &[u8]| {
    let Ok(len) = c_long::try_from(data.len()) else {
        return;
    };
    // SAFETY: no preconditions.
    let chain = unsafe { OPENSSL_sk_new_null() };
    let mut p = data.as_ptr();
    // SAFETY: the input's octets.
    let sc = unsafe { d2i_ESS_SIGNING_CERT(ptr::null_mut(), &mut p, len) };
    if !sc.is_null() {
        let mut der: *mut c_uchar = ptr::null_mut();
        // SAFETY: a decoded value.
        unsafe { i2d_ESS_SIGNING_CERT(sc, &mut der) };
        // SAFETY: the encoding, or NULL.
        unsafe { CRYPTO_free(der.cast(), ptr::null(), 0) };
        // SAFETY: a decoded value; an empty chain.
        unsafe { OSSL_ESS_check_signing_certs(sc, ptr::null(), chain, 1) };
        // SAFETY: as above, freed once.
        unsafe { ESS_SIGNING_CERT_free(sc) };
    }
    let mut p = data.as_ptr();
    // SAFETY: the input's octets.
    let sc2 = unsafe { d2i_ESS_SIGNING_CERT_V2(ptr::null_mut(), &mut p, len) };
    if !sc2.is_null() {
        let mut der: *mut c_uchar = ptr::null_mut();
        // SAFETY: a decoded value.
        unsafe { i2d_ESS_SIGNING_CERT_V2(sc2, &mut der) };
        // SAFETY: the encoding, or NULL.
        unsafe { CRYPTO_free(der.cast(), ptr::null(), 0) };
        // SAFETY: a decoded value; an empty chain.
        unsafe { OSSL_ESS_check_signing_certs(ptr::null(), sc2, chain, 1) };
        // SAFETY: as above, freed once.
        unsafe { ESS_SIGNING_CERT_V2_free(sc2) };
    }
    // SAFETY: the list made here.
    unsafe { OPENSSL_sk_free(chain) };
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
