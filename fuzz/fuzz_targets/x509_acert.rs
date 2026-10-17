//! Fuzzes attribute certificate decoding on untrusted input: d2i_X509_ACERT, then everything
//! that reads one: the re-encoding, a copy, the holder (its base certificate ID and object
//! digest information), the issuer, the validity, the attributes, the extensions, and a
//! verification. Nothing may crash or read out of bounds (ASan).

#![no_main]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_INTEGER, EVP_PKEY, GENERAL_NAMES, OSSL_ISSUER_SERIAL,
    OSSL_OBJECT_DIGEST_INFO, X509_ACERT, X509_ALGOR, X509_ATTRIBUTE, X509_NAME,
};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_X509_ACERT(a: *mut *mut X509_ACERT, pp: *mut *const c_uchar, len: c_long) -> *mut X509_ACERT;
    fn i2d_X509_ACERT(a: *const X509_ACERT, out: *mut *mut c_uchar) -> c_int;
    fn X509_ACERT_dup(a: *const X509_ACERT) -> *mut X509_ACERT;
    fn X509_ACERT_free(a: *mut X509_ACERT);
    fn X509_ACERT_get_version(x: *const X509_ACERT) -> c_long;
    fn X509_ACERT_get0_holder_entityName(x: *const X509_ACERT) -> *const GENERAL_NAMES;
    fn X509_ACERT_get0_holder_baseCertId(x: *const X509_ACERT) -> *const OSSL_ISSUER_SERIAL;
    fn X509_ACERT_get0_holder_digest(x: *const X509_ACERT) -> *const OSSL_OBJECT_DIGEST_INFO;
    fn X509_ACERT_get0_issuerName(x: *const X509_ACERT) -> *const X509_NAME;
    fn X509_ACERT_get0_serialNumber(x: *const X509_ACERT) -> *const ASN1_INTEGER;
    fn X509_ACERT_get_attr_count(x: *const X509_ACERT) -> c_int;
    fn X509_ACERT_get_attr(x: *const X509_ACERT, loc: c_int) -> *mut X509_ATTRIBUTE;
    fn X509_ACERT_get_ext_d2i(x: *const X509_ACERT, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void;
    fn X509_ACERT_verify(x: *mut X509_ACERT, k: *mut EVP_PKEY) -> c_int;
    fn OSSL_ISSUER_SERIAL_get0_issuer(i: *const OSSL_ISSUER_SERIAL) -> *const X509_NAME;
    fn OSSL_ISSUER_SERIAL_get0_serial(i: *const OSSL_ISSUER_SERIAL) -> *const ASN1_INTEGER;
    fn OSSL_OBJECT_DIGEST_INFO_get0_digest(o: *const OSSL_OBJECT_DIGEST_INFO, t: *mut c_int, a: *mut *const X509_ALGOR, d: *mut *const ASN1_BIT_STRING);
    fn ASN1_INTEGER_get(a: *const ASN1_INTEGER) -> c_long;
    fn ASN1_OCTET_STRING_free(a: *mut c_void);
    fn CRYPTO_free(p: *mut c_void, file: *const core::ffi::c_char, line: c_int);
    fn ERR_clear_error();
}

fuzz_target!(|data: &[u8]| {
    let Ok(len) = c_long::try_from(data.len()) else { return };
    // SAFETY: the input, read within its length; the certificates and encodings made here, freed.
    unsafe {
        let mut p = data.as_ptr();
        let a = d2i_X509_ACERT(ptr::null_mut(), &mut p, len);
        if a.is_null() {
            ERR_clear_error();
            return;
        }
        let mut der = ptr::null_mut();
        if i2d_X509_ACERT(a, &mut der) > 0 {
            CRYPTO_free(der.cast(), c"".as_ptr(), 0);
        }
        X509_ACERT_free(X509_ACERT_dup(a));
        X509_ACERT_get_version(a);
        X509_ACERT_get0_holder_entityName(a);
        let bcid = X509_ACERT_get0_holder_baseCertId(a);
        if !bcid.is_null() {
            OSSL_ISSUER_SERIAL_get0_issuer(bcid);
            ASN1_INTEGER_get(OSSL_ISSUER_SERIAL_get0_serial(bcid));
        }
        let odi = X509_ACERT_get0_holder_digest(a);
        if !odi.is_null() {
            let (mut t, mut alg, mut dig) = (0, ptr::null(), ptr::null());
            OSSL_OBJECT_DIGEST_INFO_get0_digest(odi, &mut t, &mut alg, &mut dig);
        }
        X509_ACERT_get0_issuerName(a);
        ASN1_INTEGER_get(X509_ACERT_get0_serialNumber(a));
        for i in 0..X509_ACERT_get_attr_count(a) {
            X509_ACERT_get_attr(a, i);
        }
        ASN1_OCTET_STRING_free(X509_ACERT_get_ext_d2i(a, rustyssl_abi::NID_ac_auditIdentity, ptr::null_mut(), ptr::null_mut()));
        X509_ACERT_verify(a, ptr::null_mut());
        X509_ACERT_free(a);
        ERR_clear_error();
    }
});
