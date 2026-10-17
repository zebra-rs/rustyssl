//! Fuzzes reading keys from PEM, which key files bring from untrusted sources:
//! PEM_read_bio_PrivateKey, PEM_read_bio_PUBKEY, and PEM_read_bio_Parameters, read again until
//! they fail, through the decoders and the legacy reading. Nothing may crash or read out of
//! bounds (ASan), and a key read must answer for its sizes.
//!
//! Encrypted keys need step 4.7d (asking for a passphrase through a password callback aborts
//! until then), so inputs naming PEM's encryption are skipped.

#![no_main]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIO, EVP_PKEY};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

type PemPasswordCb = Option<unsafe extern "C" fn(*mut c_char, c_int, c_int, *mut c_void) -> c_int>;

unsafe extern "C" {
    fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut BIO;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn PEM_read_bio_PrivateKey(b: *mut BIO, x: *mut *mut EVP_PKEY, cb: PemPasswordCb, u: *mut c_void) -> *mut EVP_PKEY;
    fn PEM_read_bio_PUBKEY(b: *mut BIO, x: *mut *mut EVP_PKEY, cb: PemPasswordCb, u: *mut c_void) -> *mut EVP_PKEY;
    fn PEM_read_bio_Parameters(b: *mut BIO, x: *mut *mut EVP_PKEY) -> *mut EVP_PKEY;
    fn EVP_PKEY_get_bits(k: *const EVP_PKEY) -> c_int;
    fn EVP_PKEY_get_size(k: *const EVP_PKEY) -> c_int;
    fn EVP_PKEY_free(k: *mut EVP_PKEY);
    fn ERR_clear_error();
}

/// A password callback that refuses.
unsafe extern "C" fn refuse(_b: *mut c_char, _n: c_int, _r: c_int, _u: *mut c_void) -> c_int {
    -1
}

fuzz_target!(|input: &[u8]| {
    let Some((&how, text)) = input.split_first() else {
        return;
    };
    if text.windows(9).any(|w| w == b"ENCRYPTED") || text.windows(9).any(|w| w == b"Proc-Type") {
        return;
    }
    let Ok(len) = c_int::try_from(text.len()) else {
        return;
    };
    // SAFETY: the input's octets, read-only for the BIO's life; the keys made here, freed once.
    unsafe {
        let b = BIO_new_mem_buf(text.as_ptr().cast(), len);
        for _ in 0..4 {
            let k = match how % 3 {
                0 => PEM_read_bio_PrivateKey(b, ptr::null_mut(), Some(refuse), ptr::null_mut()),
                1 => PEM_read_bio_PUBKEY(b, ptr::null_mut(), Some(refuse), ptr::null_mut()),
                _ => PEM_read_bio_Parameters(b, ptr::null_mut()),
            };
            if k.is_null() {
                break;
            }
            core::hint::black_box((EVP_PKEY_get_bits(k), EVP_PKEY_get_size(k)));
            EVP_PKEY_free(k);
        }
        BIO_free(b);
        ERR_clear_error();
    }
});
