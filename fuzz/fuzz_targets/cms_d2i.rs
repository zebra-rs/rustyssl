//! Fuzzes the CMS decoder on untrusted input: the input decoded as a ContentInfo
//! (`d2i_CMS_ContentInfo`), printed, encoded again (decoding to the same encoding), and its
//! content type, content, certificates, and CRLs read. Nothing may crash or read out of
//! bounds (ASan).

#![no_main]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{ASN1_OBJECT, ASN1_OCTET_STRING, ASN1_PCTX, BIO, BIO_METHOD, CMS_ContentInfo};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_CMS_ContentInfo(a: *mut *mut CMS_ContentInfo, pp: *mut *const c_uchar, len: c_long) -> *mut CMS_ContentInfo;
    fn i2d_CMS_ContentInfo(a: *const CMS_ContentInfo, out: *mut *mut c_uchar) -> c_int;
    fn CMS_ContentInfo_free(a: *mut CMS_ContentInfo);
    fn CMS_ContentInfo_print_ctx(out: *mut BIO, x: *const CMS_ContentInfo, indent: c_int, pctx: *const ASN1_PCTX) -> c_int;
    fn CMS_get0_type(cms: *const CMS_ContentInfo) -> *const ASN1_OBJECT;
    fn CMS_get0_eContentType(cms: *mut CMS_ContentInfo) -> *const ASN1_OBJECT;
    fn CMS_get0_content(cms: *mut CMS_ContentInfo) -> *mut *mut ASN1_OCTET_STRING;
    fn CMS_get1_certs(cms: *mut CMS_ContentInfo) -> *mut c_void;
    fn CMS_get1_crls(cms: *mut CMS_ContentInfo) -> *mut c_void;
    fn OSSL_STACK_OF_X509_free(sk: *mut c_void);
    fn OPENSSL_sk_pop_free(sk: *mut c_void, f: Option<unsafe extern "C" fn(*mut c_void)>);
    fn X509_CRL_free(crl: *mut c_void);
    fn CRYPTO_free(p: *mut c_void, file: *const core::ffi::c_char, line: c_int);
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn ERR_clear_error();
}

fuzz_target!(|data: &[u8]| {
    let Ok(len) = c_long::try_from(data.len()) else {
        return;
    };
    let mut p = data.as_ptr();
    // SAFETY: the input's octets.
    let cms = unsafe { d2i_CMS_ContentInfo(ptr::null_mut(), &mut p, len) };
    if !cms.is_null() {
        // SAFETY: the built-in method.
        let out = unsafe { BIO_new(BIO_s_mem()) };
        // SAFETY: live objects.
        unsafe { CMS_ContentInfo_print_ctx(out, cms, 0, ptr::null()) };
        // SAFETY: as above.
        unsafe { BIO_free(out) };
        let mut der: *mut c_uchar = ptr::null_mut();
        // SAFETY: as above.
        let n = unsafe { i2d_CMS_ContentInfo(cms, &mut der) };
        if n > 0 {
            let mut q = der.cast_const();
            // SAFETY: the encoding's `n` octets.
            let again = unsafe { d2i_CMS_ContentInfo(ptr::null_mut(), &mut q, c_long::from(n)) };
            // OpenSSL writes an ANY of universal tag 0 (`20 00`, a constructed end-of-contents) as
            // `00 00`, which no decoder takes back; the reference does the same. Any other
            // encoding must decode.
            // SAFETY: the encoding's `n` octets.
            let eoc = unsafe { core::slice::from_raw_parts(der, n as usize) }.windows(2).any(|w| w == [0, 0]);
            assert!(!again.is_null() || eoc, "an encoding that doesn't decode");
            if !again.is_null() {
                let mut der2: *mut c_uchar = ptr::null_mut();
                // SAFETY: as above.
                let n2 = unsafe { i2d_CMS_ContentInfo(again, &mut der2) };
                assert_eq!(n, n2, "the encoding changed");
                // SAFETY: both encodings' `n` octets.
                let (a, b) = unsafe { (core::slice::from_raw_parts(der, n as usize), core::slice::from_raw_parts(der2, n as usize)) };
                assert_eq!(a, b, "the encoding changed");
                // SAFETY: as above, freed once.
                unsafe { CRYPTO_free(der2.cast(), ptr::null(), 0) };
                // SAFETY: as above.
                unsafe { CMS_ContentInfo_free(again) };
            }
        }
        // SAFETY: the encoding, or NULL.
        unsafe { CRYPTO_free(der.cast(), ptr::null(), 0) };
        // SAFETY: a live object.
        unsafe { CMS_get0_type(cms) };
        // SAFETY: as above.
        unsafe { CMS_get0_eContentType(cms) };
        // SAFETY: as above.
        unsafe { CMS_get0_content(cms) };
        // SAFETY: as above.
        let certs = unsafe { CMS_get1_certs(cms) };
        // SAFETY: the certificates, or NULL.
        unsafe { OSSL_STACK_OF_X509_free(certs) };
        // SAFETY: as above.
        let crls = unsafe { CMS_get1_crls(cms) };
        // SAFETY: the CRLs, or NULL, with their references.
        unsafe { OPENSSL_sk_pop_free(crls, Some(X509_CRL_free)) };
        // SAFETY: the object decoded, freed once.
        unsafe { CMS_ContentInfo_free(cms) };
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
