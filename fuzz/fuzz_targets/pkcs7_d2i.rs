//! Fuzzes PKCS#7 decoding on untrusted input: the input is decoded as a ContentInfo
//! (`d2i_PKCS7`), and what decodes is encoded again (definite and indefinite lengths), its
//! signer infos and their attributes read, and printed. Nothing may crash or read out of bounds
//! (ASan).

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{ASN1_PCTX, ASN1_TYPE, BIO, BIO_METHOD, NID_pkcs9_messageDigest, PKCS7, PKCS7_SIGNER_INFO};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_PKCS7(a: *mut *mut PKCS7, pp: *mut *const c_uchar, len: c_long) -> *mut PKCS7;
    fn i2d_PKCS7(a: *const PKCS7, out: *mut *mut c_uchar) -> c_int;
    fn i2d_PKCS7_NDEF(a: *const PKCS7, out: *mut *mut c_uchar) -> c_int;
    fn PKCS7_free(p7: *mut PKCS7);
    fn PKCS7_get_signer_info(p7: *mut PKCS7) -> *mut c_void;
    fn PKCS7_get_signed_attribute(si: *const PKCS7_SIGNER_INFO, nid: c_int) -> *mut ASN1_TYPE;
    fn PKCS7_get_smimecap(si: *mut PKCS7_SIGNER_INFO) -> *mut c_void;
    fn PKCS7_print_ctx(out: *mut BIO, x: *const PKCS7, indent: c_int, pctx: *const ASN1_PCTX) -> c_int;
    fn OPENSSL_sk_num(sk: *const c_void) -> c_int;
    fn OPENSSL_sk_value(sk: *const c_void, i: c_int) -> *mut c_void;
    fn OPENSSL_sk_pop_free(sk: *mut c_void, f: Option<unsafe extern "C" fn(*mut c_void)>);
    fn X509_ALGOR_free(a: *mut c_void);
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn ERR_clear_error();
}

unsafe extern "C" fn algor_free(p: *mut c_void) {
    // SAFETY: an algorithm the stack owned.
    unsafe { X509_ALGOR_free(p) };
}

fuzz_target!(|data: &[u8]| {
    // SAFETY: the input's octets; objects and encodings made and freed here.
    unsafe {
        let mut p = data.as_ptr();
        let len = c_long::try_from(data.len()).unwrap_or(0);
        let p7 = d2i_PKCS7(ptr::null_mut(), &mut p, len);
        if !p7.is_null() {
            for enc in [i2d_PKCS7 as unsafe extern "C" fn(_, _) -> _, i2d_PKCS7_NDEF] {
                let mut out = ptr::null_mut();
                enc(p7, &mut out);
                CRYPTO_free(out.cast(), ptr::null(), 0);
            }
            let sis = PKCS7_get_signer_info(p7);
            for i in 0..OPENSSL_sk_num(sis) {
                let si = OPENSSL_sk_value(sis, i).cast::<PKCS7_SIGNER_INFO>();
                PKCS7_get_signed_attribute(si, NID_pkcs9_messageDigest);
                OPENSSL_sk_pop_free(PKCS7_get_smimecap(si), Some(algor_free));
            }
            let b = BIO_new(BIO_s_mem());
            PKCS7_print_ctx(b, p7, 0, ptr::null());
            BIO_free(b);
            PKCS7_free(p7);
        }
        ERR_clear_error();
    }
});
