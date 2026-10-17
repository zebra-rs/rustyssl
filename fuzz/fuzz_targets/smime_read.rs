//! Fuzzes the S/MIME reader on untrusted input: the input read as a message
//! (`SMIME_read_PKCS7`), opaque or multipart/signed, with the content's part asked for, and
//! what reads is written again as S/MIME. Nothing may crash or read out of bounds (ASan).

#![no_main]

use core::ffi::{c_int, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIO, BIO_METHOD, PKCS7};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn SMIME_read_PKCS7(bio: *mut BIO, bcont: *mut *mut BIO) -> *mut PKCS7;
    fn SMIME_write_PKCS7(bio: *mut BIO, p7: *mut PKCS7, data: *mut BIO, flags: c_int) -> c_int;
    fn PKCS7_free(p7: *mut PKCS7);
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn ERR_clear_error();
}

fuzz_target!(|data: &[u8]| {
    let Ok(len) = c_int::try_from(data.len()) else {
        return;
    };
    // SAFETY: the input's octets, outliving the BIO.
    let src = unsafe { BIO_new_mem_buf(data.as_ptr().cast(), len) };
    let mut bcont: *mut BIO = ptr::null_mut();
    // SAFETY: a live BIO; room for the content's.
    let p7 = unsafe { SMIME_read_PKCS7(src, &mut bcont) };
    if !p7.is_null() {
        // SAFETY: the built-in method.
        let out = unsafe { BIO_new(BIO_s_mem()) };
        // SAFETY: live BIOs and the object read.
        unsafe { SMIME_write_PKCS7(out, p7, ptr::null_mut(), 0) };
        // SAFETY: as above.
        unsafe { BIO_free(out) };
        // SAFETY: the object read, freed once.
        unsafe { PKCS7_free(p7) };
    }
    // SAFETY: NULL or the content's BIO, ours.
    unsafe { BIO_free(bcont) };
    // SAFETY: as above.
    unsafe { BIO_free(src) };
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
