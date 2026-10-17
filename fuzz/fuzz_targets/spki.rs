//! Fuzzes Netscape SPKI decoding on untrusted input: NETSCAPE_SPKI_b64_decode of the input as
//! base64 text, and d2i_NETSCAPE_SPKI of it as DER, then the SPKI printed, its key read, its
//! signature checked with it, and encoded back to base64. Nothing may crash or read out of
//! bounds (ASan).

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIO, BIO_METHOD, EVP_PKEY, NETSCAPE_SPKI};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn NETSCAPE_SPKI_b64_decode(s: *const c_char, len: c_int) -> *mut NETSCAPE_SPKI;
    fn NETSCAPE_SPKI_b64_encode(spki: *mut NETSCAPE_SPKI) -> *mut c_char;
    fn d2i_NETSCAPE_SPKI(a: *mut *mut NETSCAPE_SPKI, pp: *mut *const c_uchar, len: c_long) -> *mut NETSCAPE_SPKI;
    fn NETSCAPE_SPKI_free(a: *mut NETSCAPE_SPKI);
    fn NETSCAPE_SPKI_print(out: *mut BIO, spki: *mut NETSCAPE_SPKI) -> c_int;
    fn NETSCAPE_SPKI_get_pubkey(spki: *mut NETSCAPE_SPKI) -> *mut EVP_PKEY;
    fn NETSCAPE_SPKI_verify(spki: *mut NETSCAPE_SPKI, k: *mut EVP_PKEY) -> c_int;
    fn EVP_PKEY_free(k: *mut EVP_PKEY);
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn ERR_clear_error();
}

/// Everything that reads a decoded SPKI.
unsafe fn read(spki: *mut NETSCAPE_SPKI) {
    if spki.is_null() {
        return;
    }
    // SAFETY: a decoded SPKI; a BIO, the key, and the encoding made here, freed.
    unsafe {
        let bio = BIO_new(BIO_s_mem());
        NETSCAPE_SPKI_print(bio, spki);
        BIO_free(bio);
        let k = NETSCAPE_SPKI_get_pubkey(spki);
        NETSCAPE_SPKI_verify(spki, k);
        EVP_PKEY_free(k);
        let b64 = NETSCAPE_SPKI_b64_encode(spki);
        CRYPTO_free(b64.cast(), c"".as_ptr(), 0);
        NETSCAPE_SPKI_free(spki);
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(len) = c_int::try_from(data.len()) else { return };
    if len == 0 {
        return;
    }
    // SAFETY: the input, read within its length.
    unsafe {
        read(NETSCAPE_SPKI_b64_decode(data.as_ptr().cast(), len));
        let mut p = data.as_ptr();
        read(d2i_NETSCAPE_SPKI(ptr::null_mut(), &mut p, c_long::from(len)));
        ERR_clear_error();
    }
});
