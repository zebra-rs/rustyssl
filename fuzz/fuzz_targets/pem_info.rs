//! Fuzzes PEM bundle reading on untrusted input: PEM_X509_INFO_read_bio_ex of the input (its
//! certificates, CRLs, and keys, encrypted ones kept encrypted, with a passphrase callback that
//! gives one), then each entry written back. Nothing may crash or read out of bounds (ASan).

#![no_main]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIO, BIO_METHOD, EVP_CIPHER, OSSL_LIB_CTX, X509_INFO, pem_password_cb, stack_st_X509_INFO};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut BIO;
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn PEM_X509_INFO_read_bio_ex(bp: *mut BIO, sk: *mut stack_st_X509_INFO, cb: pem_password_cb, u: *mut c_void, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut stack_st_X509_INFO;
    fn PEM_X509_INFO_write_bio(bp: *mut BIO, xi: *const X509_INFO, enc: *mut EVP_CIPHER, kstr: *const u8, klen: c_int, cb: pem_password_cb, u: *mut c_void) -> c_int;
    fn X509_INFO_free(x: *mut X509_INFO);
    fn OPENSSL_sk_num(sk: *const c_void) -> c_int;
    fn OPENSSL_sk_value(sk: *const c_void, i: c_int) -> *mut c_void;
    fn OPENSSL_sk_free(sk: *mut c_void);
    fn ERR_clear_error();
}

/// A passphrase callback that gives "secret".
unsafe extern "C" fn pass(buf: *mut c_char, size: c_int, _rwflag: c_int, _u: *mut c_void) -> c_int {
    let p = b"secret";
    let Ok(n) = usize::try_from(size) else { return 0 };
    if n < p.len() {
        return 0;
    }
    // SAFETY: the caller's buffer of `size` octets.
    unsafe { ptr::copy_nonoverlapping(p.as_ptr(), buf.cast(), p.len()) };
    6
}

fuzz_target!(|data: &[u8]| {
    let Ok(len) = c_int::try_from(data.len()) else { return };
    // SAFETY: the input, read within its length; the BIOs and entries made here, freed.
    unsafe {
        let b = BIO_new_mem_buf(data.as_ptr().cast(), len);
        let sk = PEM_X509_INFO_read_bio_ex(b, ptr::null_mut(), Some(pass), ptr::null_mut(), ptr::null_mut(), ptr::null());
        BIO_free(b);
        if !sk.is_null() {
            let out = BIO_new(BIO_s_mem());
            for i in 0..OPENSSL_sk_num(sk.cast()) {
                let xi = OPENSSL_sk_value(sk.cast(), i).cast::<X509_INFO>();
                PEM_X509_INFO_write_bio(out, xi, ptr::null_mut(), ptr::null(), 0, None, ptr::null_mut());
                X509_INFO_free(xi);
            }
            OPENSSL_sk_free(sk.cast());
            BIO_free(out);
        }
        ERR_clear_error();
    }
});
