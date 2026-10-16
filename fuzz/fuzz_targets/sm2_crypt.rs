//! Fuzzes SM2 decryption (`EVP_PKEY_decrypt` through the SM2 asymmetric cipher), as a peer's
//! ciphertext reaches it: the `SM2_Ciphertext` DER (two INTEGERs and two OCTET STRINGs, read
//! by the template engine), the point it names, and the hash check. Nothing may crash or read
//! out of bounds (ASan); a failed decryption leaves the buffer cleared; the size query's
//! message length is what a successful decryption gives; and the input, encrypted, decrypts
//! to itself.

#![no_main]

use core::ffi::{c_int, c_uchar};
use core::ptr;
use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{EC_KEY, EVP_PKEY, EVP_PKEY_CTX};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn EC_KEY_new_by_curve_name(nid: c_int) -> *mut EC_KEY;
    fn EC_KEY_generate_key(k: *mut EC_KEY) -> c_int;
    fn EVP_PKEY_new() -> *mut EVP_PKEY;
    fn EVP_PKEY_set1_EC_KEY(p: *mut EVP_PKEY, k: *mut EC_KEY) -> c_int;
    fn EVP_PKEY_CTX_new(p: *mut EVP_PKEY, e: *mut core::ffi::c_void) -> *mut EVP_PKEY_CTX;
    fn EVP_PKEY_CTX_free(c: *mut EVP_PKEY_CTX);
    fn EVP_PKEY_encrypt_init(c: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_decrypt_init(c: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_encrypt(
        c: *mut EVP_PKEY_CTX,
        out: *mut c_uchar,
        outlen: *mut usize,
        inp: *const c_uchar,
        inlen: usize,
    ) -> c_int;
    fn EVP_PKEY_decrypt(
        c: *mut EVP_PKEY_CTX,
        out: *mut c_uchar,
        outlen: *mut usize,
        inp: *const c_uchar,
        inlen: usize,
    ) -> c_int;
    fn ERR_clear_error();
}

/// An SM2 key (a legacy EC_KEY on SM2's curve), made once.
struct Pkey(*mut EVP_PKEY);
// SAFETY: the key is only read after it's made.
unsafe impl Sync for Pkey {}
// SAFETY: as above.
unsafe impl Send for Pkey {}

static KEY: LazyLock<Pkey> = LazyLock::new(|| {
    // SAFETY: 1172 is sm2.
    let k = unsafe { EC_KEY_new_by_curve_name(1172) };
    // SAFETY: a live key.
    assert_eq!(unsafe { EC_KEY_generate_key(k) }, 1);
    // SAFETY: no preconditions.
    let p = unsafe { EVP_PKEY_new() };
    // SAFETY: a live key and EC key.
    assert_eq!(unsafe { EVP_PKEY_set1_EC_KEY(p, k) }, 1);
    Pkey(p)
});

/// Decrypts `ct` into a buffer of `room` octets: the result, and the octets written.
fn decrypt(ct: &[u8], room: usize) -> (c_int, Vec<u8>) {
    // SAFETY: a live key.
    let c = unsafe { EVP_PKEY_CTX_new(KEY.0, ptr::null_mut()) };
    let mut out = vec![0x77u8; room];
    let mut len = room;
    // SAFETY: the context; the buffer; the input.
    let r = unsafe {
        EVP_PKEY_decrypt_init(c);
        EVP_PKEY_decrypt(c, out.as_mut_ptr(), &mut len, ct.as_ptr(), ct.len())
    };
    // SAFETY: made above.
    unsafe { EVP_PKEY_CTX_free(c) };
    if r == 1 {
        assert!(len <= room, "the message fits the buffer");
        out.truncate(len);
    }
    (r, out)
}

fuzz_target!(|input: &[u8]| {
    let room = input.len().saturating_add(16);
    let (r, out) = decrypt(input, room);
    if r != 1 {
        assert!(
            out.iter().all(|&b| b == 0),
            "a failed decryption clears the buffer"
        );
    } else {
        // SAFETY: a live key; NULL output for the size.
        let c = unsafe { EVP_PKEY_CTX_new(KEY.0, ptr::null_mut()) };
        let mut size = 0;
        // SAFETY: the context; the input.
        let q = unsafe {
            EVP_PKEY_decrypt_init(c);
            EVP_PKEY_decrypt(c, ptr::null_mut(), &mut size, input.as_ptr(), input.len())
        };
        // SAFETY: made above.
        unsafe { EVP_PKEY_CTX_free(c) };
        assert_eq!((q, size), (1, out.len()), "the size query agrees");
    }
    if !input.is_empty() && input.len() <= 512 {
        // SAFETY: a live key.
        let c = unsafe { EVP_PKEY_CTX_new(KEY.0, ptr::null_mut()) };
        let mut ct = vec![0u8; input.len() + 200];
        let mut len = ct.len();
        // SAFETY: the context; the buffer; the input.
        let e = unsafe {
            EVP_PKEY_encrypt_init(c);
            EVP_PKEY_encrypt(c, ct.as_mut_ptr(), &mut len, input.as_ptr(), input.len())
        };
        // SAFETY: made above.
        unsafe { EVP_PKEY_CTX_free(c) };
        assert_eq!(e, 1, "the input encrypts");
        let (d, back) = decrypt(&ct[..len], input.len());
        assert_eq!((d, back.as_slice()), (1, input), "and decrypts to itself");
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
