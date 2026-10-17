//! Fuzzes certificate decoding on untrusted input: d2i_X509_AUX (a certificate and, if more
//! follows, its auxiliary data), then everything that reads a decoded certificate without the
//! extension cache: the re-encodings (as decoded, the trusted form, and the TBSCertificate
//! afresh), a copy, the getters, the extension list, the fingerprints and hashes, the key, a
//! verification with its own key, and the time comparisons. Nothing may crash or read out of
//! bounds (ASan).

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_INTEGER, ASN1_OCTET_STRING, ASN1_TIME, EVP_MD, EVP_PKEY, X509,
    X509_ALGOR, X509_EXTENSION, X509_NAME,
};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_X509_AUX(a: *mut *mut X509, pp: *mut *const c_uchar, len: c_long) -> *mut X509;
    fn i2d_X509(a: *const X509, out: *mut *mut c_uchar) -> c_int;
    fn i2d_X509_AUX(a: *const X509, out: *mut *mut c_uchar) -> c_int;
    fn i2d_re_X509_tbs(x: *mut X509, out: *mut *mut c_uchar) -> c_int;
    fn X509_free(a: *mut X509);
    fn X509_dup(a: *const X509) -> *mut X509;
    fn X509_get_version(x: *const X509) -> c_long;
    fn X509_get0_serialNumber(x: *const X509) -> *const ASN1_INTEGER;
    fn X509_get_issuer_name(x: *const X509) -> *mut X509_NAME;
    fn X509_get_subject_name(x: *const X509) -> *mut X509_NAME;
    fn X509_get0_notBefore(x: *const X509) -> *const ASN1_TIME;
    fn X509_get0_notAfter(x: *const X509) -> *const ASN1_TIME;
    fn X509_get_signature_nid(x: *const X509) -> c_int;
    fn X509_get_signature_type(x: *const X509) -> c_int;
    fn X509_get0_signature(psig: *mut *const ASN1_BIT_STRING, palg: *mut *const X509_ALGOR, x: *const X509);
    fn X509_get0_pubkey(x: *const X509) -> *mut EVP_PKEY;
    fn X509_get0_pubkey_bitstr(x: *const X509) -> *mut ASN1_BIT_STRING;
    fn X509_get_ext_count(x: *const X509) -> c_int;
    fn X509_get_ext(x: *const X509, loc: c_int) -> *mut X509_EXTENSION;
    fn X509_get_ext_by_NID(x: *const X509, nid: c_int, lastpos: c_int) -> c_int;
    fn X509_get_ext_by_critical(x: *const X509, crit: c_int, lastpos: c_int) -> c_int;
    fn X509_delete_ext(x: *mut X509, loc: c_int) -> *mut X509_EXTENSION;
    fn X509_EXTENSION_free(e: *mut X509_EXTENSION);
    fn X509_digest(x: *const X509, md: *const EVP_MD, out: *mut c_uchar, len: *mut c_uint) -> c_int;
    fn X509_pubkey_digest(x: *const X509, md: *const EVP_MD, out: *mut c_uchar, len: *mut c_uint) -> c_int;
    fn X509_digest_sig(x: *const X509, md_used: *mut *mut EVP_MD, fallback: *mut c_int) -> *mut ASN1_OCTET_STRING;
    fn X509_issuer_name_hash(x: *mut X509) -> c_ulong;
    fn X509_subject_name_hash_old(x: *mut X509) -> c_ulong;
    fn X509_issuer_and_serial_hash(x: *mut X509) -> c_ulong;
    fn X509_issuer_and_serial_cmp(a: *const X509, b: *const X509) -> c_int;
    fn X509_verify(x: *mut X509, k: *mut EVP_PKEY) -> c_int;
    fn X509_cmp_time(t: *const ASN1_TIME, cmp: *mut libc::time_t) -> c_int;
    fn ASN1_OCTET_STRING_free(a: *mut ASN1_OCTET_STRING);
    fn EVP_MD_free(md: *mut EVP_MD);
    fn EVP_sha256() -> *const EVP_MD;
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn ERR_clear_error();
}

/// Encodes with `f` and frees the encoding.
///
/// # Safety
/// `f` is an `i2d` function for `x`.
unsafe fn encode(f: unsafe extern "C" fn(*const X509, *mut *mut c_uchar) -> c_int, x: *const X509) {
    let mut der = ptr::null_mut();
    // SAFETY: the caller's guarantee.
    if unsafe { f(x, &mut der) } > 0 {
        // SAFETY: the encoder's allocation.
        unsafe { CRYPTO_free(der.cast(), c"".as_ptr(), 0) };
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(len) = c_long::try_from(data.len()) else { return };
    // SAFETY: the input, read within its length; the certificates, encodings, and strings made
    // here, freed.
    unsafe {
        let mut p = data.as_ptr();
        let x = d2i_X509_AUX(ptr::null_mut(), &mut p, len);
        if x.is_null() {
            ERR_clear_error();
            return;
        }
        encode(i2d_X509, x);
        encode(i2d_X509_AUX, x);
        let copy = X509_dup(x);
        X509_get_version(x);
        X509_get0_serialNumber(x);
        X509_get_issuer_name(x);
        X509_get_subject_name(x);
        X509_get_signature_nid(x);
        X509_get_signature_type(x);
        let (mut sig, mut alg) = (ptr::null(), ptr::null());
        X509_get0_signature(&mut sig, &mut alg, x);
        X509_get0_pubkey_bitstr(x);
        for i in 0..X509_get_ext_count(x) {
            X509_get_ext(x, i);
        }
        X509_get_ext_by_NID(x, 87, -1);
        X509_get_ext_by_critical(x, 1, -1);
        let mut md = [0u8; 64];
        let mut mdlen = 0;
        X509_digest(x, EVP_sha256(), md.as_mut_ptr(), &mut mdlen);
        X509_pubkey_digest(x, EVP_sha256(), md.as_mut_ptr(), &mut mdlen);
        let mut used = ptr::null_mut();
        let mut fallback = 0;
        ASN1_OCTET_STRING_free(X509_digest_sig(x, &mut used, &mut fallback));
        EVP_MD_free(used);
        X509_issuer_name_hash(x);
        X509_subject_name_hash_old(x);
        X509_issuer_and_serial_hash(x);
        X509_issuer_and_serial_cmp(x, copy);
        let key = X509_get0_pubkey(x);
        if !key.is_null() {
            X509_verify(x, key);
        }
        let mut now: libc::time_t = 1_700_000_000;
        X509_cmp_time(X509_get0_notBefore(x), &mut now);
        X509_cmp_time(X509_get0_notAfter(x), ptr::null_mut());
        if !copy.is_null() {
            X509_EXTENSION_free(X509_delete_ext(copy, 0));
            let mut der = ptr::null_mut();
            if i2d_re_X509_tbs(copy, &mut der) > 0 {
                CRYPTO_free(der.cast(), c"".as_ptr(), 0);
            }
            encode(i2d_X509, copy);
        }
        X509_free(copy);
        X509_free(x);
        ERR_clear_error();
    }
});
