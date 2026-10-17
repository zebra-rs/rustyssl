//! Fuzzes CRL decoding on untrusted input: d2i_X509_CRL (which caches the issuing distribution
//! point, key identifier, CRL numbers, and each entry's issuer and reason), then everything that
//! reads a decoded CRL: the re-encodings (as decoded and the TBSCertList afresh), a copy, the
//! getters, the extensions of the CRL and its entries, the fingerprints, a lookup of each
//! entry's serial number (which sorts the entries), the comparisons, a verification, sorting,
//! and a delta CRL against its copy. Nothing may crash or read out of bounds (ASan).

#![no_main]

use core::ffi::{c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{self as abi, ASN1_INTEGER, EVP_MD, EVP_PKEY, X509_CRL, X509_EXTENSION, X509_REVOKED};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_X509_CRL(a: *mut *mut X509_CRL, pp: *mut *const c_uchar, len: c_long) -> *mut X509_CRL;
    fn i2d_X509_CRL(a: *const X509_CRL, out: *mut *mut c_uchar) -> c_int;
    fn i2d_re_X509_CRL_tbs(x: *mut X509_CRL, out: *mut *mut c_uchar) -> c_int;
    fn X509_CRL_free(a: *mut X509_CRL);
    fn X509_CRL_dup(a: *const X509_CRL) -> *mut X509_CRL;
    fn X509_CRL_get_version(x: *const X509_CRL) -> c_long;
    fn X509_CRL_get_ext_count(x: *const X509_CRL) -> c_int;
    fn X509_CRL_get_ext(x: *const X509_CRL, loc: c_int) -> *mut X509_EXTENSION;
    fn X509_CRL_get_ext_d2i(x: *const X509_CRL, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void;
    fn X509_CRL_get_REVOKED(x: *mut X509_CRL) -> *mut abi::stack_st_X509_REVOKED;
    fn X509_CRL_get0_by_serial(crl: *mut X509_CRL, ret: *mut *mut X509_REVOKED, serial: *const ASN1_INTEGER) -> c_int;
    fn X509_CRL_digest(x: *const X509_CRL, md: *const EVP_MD, out: *mut c_uchar, len: *mut c_uint) -> c_int;
    fn X509_CRL_match(a: *const X509_CRL, b: *const X509_CRL) -> c_int;
    fn X509_CRL_cmp(a: *const X509_CRL, b: *const X509_CRL) -> c_int;
    fn X509_CRL_verify(x: *mut X509_CRL, k: *mut EVP_PKEY) -> c_int;
    fn X509_CRL_sort(x: *mut X509_CRL) -> c_int;
    fn X509_CRL_diff(base: *mut X509_CRL, newer: *mut X509_CRL, skey: *mut EVP_PKEY, md: *const EVP_MD, flags: c_uint) -> *mut X509_CRL;
    fn X509_REVOKED_get0_serialNumber(x: *const X509_REVOKED) -> *const ASN1_INTEGER;
    fn X509_REVOKED_get_ext_count(x: *const X509_REVOKED) -> c_int;
    fn X509_REVOKED_get_ext_d2i(x: *const X509_REVOKED, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void;
    fn OPENSSL_sk_num(sk: *const c_void) -> c_int;
    fn OPENSSL_sk_value(sk: *const c_void, i: c_int) -> *mut c_void;
    fn ASN1_item_free(v: *mut c_void, it: *const abi::ASN1_ITEM);
    fn X509V3_EXT_get_nid(nid: c_int) -> *const abi::X509V3_EXT_METHOD;
    fn EVP_sha256() -> *const EVP_MD;
    fn EVP_sha1() -> *const EVP_MD;
    fn CRYPTO_free(p: *mut c_void, file: *const core::ffi::c_char, line: c_int);
    fn ERR_clear_error();
}

/// Encodes with `f`, freeing the encoding.
unsafe fn encode(f: unsafe extern "C" fn(*const X509_CRL, *mut *mut c_uchar) -> c_int, x: *const X509_CRL) {
    let mut der = ptr::null_mut();
    // SAFETY: the caller's CRL; the encoding, freed.
    unsafe {
        if f(x, &mut der) > 0 {
            CRYPTO_free(der.cast(), c"".as_ptr(), 0);
        }
    }
}

/// Decodes an extension with its method and frees what it gets.
unsafe fn decoded(v: *mut c_void, nid: c_int) {
    if v.is_null() {
        return;
    }
    // SAFETY: a value of the NID's built-in method, which has an item.
    unsafe {
        if let Some(it) = (*X509V3_EXT_get_nid(nid)).it {
            ASN1_item_free(v, it());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(len) = c_long::try_from(data.len()) else { return };
    // SAFETY: the input, read within its length; the CRLs, encodings, and values made here,
    // freed.
    unsafe {
        let mut p = data.as_ptr();
        let x = d2i_X509_CRL(ptr::null_mut(), &mut p, len);
        if x.is_null() {
            ERR_clear_error();
            return;
        }
        encode(i2d_X509_CRL, x);
        let copy = X509_CRL_dup(x);
        X509_CRL_get_version(x);
        for i in 0..X509_CRL_get_ext_count(x) {
            X509_CRL_get_ext(x, i);
        }
        for nid in [abi::NID_issuing_distribution_point, abi::NID_authority_key_identifier, abi::NID_crl_number, abi::NID_delta_crl] {
            decoded(X509_CRL_get_ext_d2i(x, nid, ptr::null_mut(), ptr::null_mut()), nid);
        }
        let revs = X509_CRL_get_REVOKED(x);
        for i in 0..OPENSSL_sk_num(revs.cast()) {
            let r = OPENSSL_sk_value(revs.cast(), i).cast::<X509_REVOKED>();
            X509_REVOKED_get_ext_count(r);
            for nid in [abi::NID_crl_reason, abi::NID_certificate_issuer, abi::NID_invalidity_date] {
                decoded(X509_REVOKED_get_ext_d2i(r, nid, ptr::null_mut(), ptr::null_mut()), nid);
            }
        }
        if !copy.is_null() {
            let crevs = X509_CRL_get_REVOKED(copy);
            for i in 0..OPENSSL_sk_num(crevs.cast()) {
                let r = OPENSSL_sk_value(crevs.cast(), i).cast::<X509_REVOKED>();
                let mut found = ptr::null_mut();
                X509_CRL_get0_by_serial(x, &mut found, X509_REVOKED_get0_serialNumber(r));
            }
        }
        let mut md = [0u8; 64];
        let mut mdlen = 0;
        X509_CRL_digest(x, EVP_sha256(), md.as_mut_ptr(), &mut mdlen);
        X509_CRL_digest(x, EVP_sha1(), md.as_mut_ptr(), &mut mdlen);
        X509_CRL_match(x, copy);
        X509_CRL_cmp(x, copy);
        X509_CRL_verify(x, ptr::null_mut());
        if !copy.is_null() {
            X509_CRL_free(X509_CRL_diff(x, copy, ptr::null_mut(), ptr::null(), 0));
            X509_CRL_sort(copy);
            let mut der = ptr::null_mut();
            if i2d_re_X509_CRL_tbs(copy, &mut der) > 0 {
                CRYPTO_free(der.cast(), c"".as_ptr(), 0);
            }
            encode(i2d_X509_CRL, copy);
        }
        X509_CRL_free(copy);
        X509_CRL_free(x);
        ERR_clear_error();
    }
});
