//! Fuzzes PKCS #12 on untrusted input: the input decoded as a PFX (`d2i_PKCS12`), encoded
//! again (decoding to the same encoding), its MAC checked, its contents and bags unpacked
//! (decrypting with the password "pw") and read, and `PKCS12_parse` run on it. Nothing may
//! crash or read out of bounds (ASan).

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{EVP_PKEY, PKCS12, PKCS12_SAFEBAG, X509};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_PKCS12(a: *mut *mut PKCS12, pp: *mut *const c_uchar, len: c_long) -> *mut PKCS12;
    fn i2d_PKCS12(a: *const PKCS12, out: *mut *mut c_uchar) -> c_int;
    fn PKCS12_free(a: *mut PKCS12);
    fn PKCS12_verify_mac(p12: *mut PKCS12, pass: *const c_char, passlen: c_int) -> c_int;
    fn PKCS12_parse(p12: *mut PKCS12, pass: *const c_char, pkey: *mut *mut EVP_PKEY, cert: *mut *mut X509, ca: *mut *mut c_void) -> c_int;
    fn PKCS12_unpack_authsafes(p12: *const PKCS12) -> *mut c_void;
    fn PKCS12_unpack_p7data(p7: *mut c_void) -> *mut c_void;
    fn PKCS12_unpack_p7encdata(p7: *mut c_void, pass: *const c_char, passlen: c_int) -> *mut c_void;
    fn PKCS12_SAFEBAG_get_nid(bag: *const PKCS12_SAFEBAG) -> c_int;
    fn PKCS12_SAFEBAG_get_bag_nid(bag: *const PKCS12_SAFEBAG) -> c_int;
    fn PKCS12_SAFEBAG_get0_bag_obj(bag: *const PKCS12_SAFEBAG) -> *const c_void;
    fn PKCS12_SAFEBAG_get1_cert(bag: *const PKCS12_SAFEBAG) -> *mut X509;
    fn PKCS12_SAFEBAG_get1_crl(bag: *const PKCS12_SAFEBAG) -> *mut c_void;
    fn PKCS12_get_friendlyname(bag: *mut PKCS12_SAFEBAG) -> *mut c_char;
    fn PKCS12_decrypt_skey(bag: *const PKCS12_SAFEBAG, pass: *const c_char, passlen: c_int) -> *mut c_void;
    fn PKCS12_SAFEBAG_free(bag: *mut PKCS12_SAFEBAG);
    fn PKCS7_free(p7: *mut c_void);
    fn PKCS8_PRIV_KEY_INFO_free(p8: *mut c_void);
    fn X509_free(x: *mut X509);
    fn X509_CRL_free(x: *mut c_void);
    fn EVP_PKEY_free(k: *mut EVP_PKEY);
    fn OSSL_STACK_OF_X509_free(sk: *mut c_void);
    fn OPENSSL_sk_num(sk: *const c_void) -> c_int;
    fn OPENSSL_sk_value(sk: *const c_void, i: c_int) -> *mut c_void;
    fn OPENSSL_sk_pop_free(sk: *mut c_void, f: Option<unsafe extern "C" fn(*mut c_void)>);
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn ERR_clear_error();
}

unsafe extern "C" fn bag_free(p: *mut c_void) {
    // SAFETY: an element of a list of bags.
    unsafe { PKCS12_SAFEBAG_free(p.cast()) };
}

unsafe extern "C" fn p7_free(p: *mut c_void) {
    // SAFETY: an element of a list of contents.
    unsafe { PKCS7_free(p) };
}

/// Reads each bag as the API offers.
///
/// # Safety
/// `bags` is NULL or a live list of bags.
unsafe fn read_bags(bags: *mut c_void) {
    let pass = c"pw".as_ptr();
    // SAFETY: the list, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(bags) } {
        // SAFETY: an index within it.
        let bag = unsafe { OPENSSL_sk_value(bags, i) }.cast::<PKCS12_SAFEBAG>();
        // SAFETY: a bag of the list.
        unsafe { PKCS12_SAFEBAG_get_nid(bag) };
        // SAFETY: as above.
        unsafe { PKCS12_SAFEBAG_get_bag_nid(bag) };
        // SAFETY: as above.
        unsafe { PKCS12_SAFEBAG_get0_bag_obj(bag) };
        // SAFETY: as above.
        unsafe { X509_free(PKCS12_SAFEBAG_get1_cert(bag)) };
        // SAFETY: as above.
        unsafe { X509_CRL_free(PKCS12_SAFEBAG_get1_crl(bag)) };
        // SAFETY: as above.
        let name = unsafe { PKCS12_get_friendlyname(bag) };
        // SAFETY: the name, or NULL.
        unsafe { CRYPTO_free(name.cast(), ptr::null(), 0) };
        if unsafe { PKCS12_SAFEBAG_get_nid(bag) } == rustyssl_abi::NID_pkcs8ShroudedKeyBag {
            // SAFETY: a shrouded key bag; the password.
            unsafe { PKCS8_PRIV_KEY_INFO_free(PKCS12_decrypt_skey(bag, pass, -1)) };
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(len) = c_long::try_from(data.len()) else {
        return;
    };
    let mut p = data.as_ptr();
    // SAFETY: the input's octets.
    let p12 = unsafe { d2i_PKCS12(ptr::null_mut(), &mut p, len) };
    if p12.is_null() {
        // SAFETY: no preconditions.
        unsafe { ERR_clear_error() };
        return;
    }
    let mut der: *mut c_uchar = ptr::null_mut();
    // SAFETY: a live PFX.
    let n = unsafe { i2d_PKCS12(p12, &mut der) };
    if n > 0 {
        let mut q = der.cast_const();
        // SAFETY: the encoding's `n` octets.
        let again = unsafe { d2i_PKCS12(ptr::null_mut(), &mut q, c_long::from(n)) };
        assert!(!again.is_null(), "an encoding that doesn't decode");
        let mut der2: *mut c_uchar = ptr::null_mut();
        // SAFETY: as above.
        let n2 = unsafe { i2d_PKCS12(again, &mut der2) };
        assert_eq!(n, n2, "the encoding changed");
        // SAFETY: both encodings' `n` octets.
        let (a, b) = unsafe { (core::slice::from_raw_parts(der, n as usize), core::slice::from_raw_parts(der2, n as usize)) };
        assert_eq!(a, b, "the encoding changed");
        // SAFETY: as above, freed once.
        unsafe { CRYPTO_free(der2.cast(), ptr::null(), 0) };
        // SAFETY: as above.
        unsafe { PKCS12_free(again) };
    }
    // SAFETY: the encoding, or NULL.
    unsafe { CRYPTO_free(der.cast(), ptr::null(), 0) };
    let pass = c"pw".as_ptr();
    // SAFETY: a live PFX; the password.
    unsafe { PKCS12_verify_mac(p12, pass, -1) };
    // SAFETY: as above.
    let safes = unsafe { PKCS12_unpack_authsafes(p12) };
    // SAFETY: the contents, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(safes) } {
        // SAFETY: an index within them.
        let p7 = unsafe { OPENSSL_sk_value(safes, i) };
        // SAFETY: a content.
        let bags = unsafe { PKCS12_unpack_p7data(p7) };
        // SAFETY: the bags, or NULL.
        unsafe { read_bags(bags) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_pop_free(bags, Some(bag_free)) };
        // SAFETY: a content; the password.
        let bags = unsafe { PKCS12_unpack_p7encdata(p7, pass, -1) };
        // SAFETY: as above.
        unsafe { read_bags(bags) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_pop_free(bags, Some(bag_free)) };
    }
    // SAFETY: the contents, or NULL.
    unsafe { OPENSSL_sk_pop_free(safes, Some(p7_free)) };
    let mut pkey: *mut EVP_PKEY = ptr::null_mut();
    let mut cert: *mut X509 = ptr::null_mut();
    let mut ca: *mut c_void = ptr::null_mut();
    // SAFETY: a live PFX; the password; room for each.
    unsafe { PKCS12_parse(p12, pass, &mut pkey, &mut cert, &mut ca) };
    // SAFETY: the key, or NULL.
    unsafe { EVP_PKEY_free(pkey) };
    // SAFETY: the certificate, or NULL.
    unsafe { X509_free(cert) };
    // SAFETY: the others, or NULL.
    unsafe { OSSL_STACK_OF_X509_free(ca) };
    // SAFETY: the PFX decoded, freed once.
    unsafe { PKCS12_free(p12) };
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
