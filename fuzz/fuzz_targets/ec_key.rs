//! Fuzzes decoding EC private keys (`d2i_ECPrivateKey`), which reads key files and PKCS #8
//! contents: the version, the private key's octets, the optional parameters (any
//! ECPKParameters) and public key, and the public key computed when it's absent. Nothing may
//! crash or read out of bounds (ASan), and a key it makes must check (or fail to) cleanly; unless
//! its private key is longer than the order (which, as in OpenSSL, decodes but doesn't fit the
//! order's length again), it must also encode, decode back to the same keys, and print.

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIO, BIO_METHOD, BN_CTX, EC_KEY};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_ECPrivateKey(
        a: *mut *mut EC_KEY,
        input: *mut *const c_uchar,
        len: c_long,
    ) -> *mut EC_KEY;
    fn i2d_ECPrivateKey(a: *const EC_KEY, out: *mut *mut c_uchar) -> c_int;
    fn EC_KEY_free(k: *mut EC_KEY);
    fn EC_KEY_check_key(k: *const EC_KEY) -> c_int;
    fn EC_KEY_priv2buf(k: *const EC_KEY, pbuf: *mut *mut c_uchar) -> usize;
    fn EC_KEY_key2buf(
        k: *const EC_KEY,
        form: u32,
        pbuf: *mut *mut c_uchar,
        ctx: *mut BN_CTX,
    ) -> usize;
    fn EC_KEY_print(bp: *mut BIO, x: *const EC_KEY, off: c_int) -> c_int;
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn ERR_clear_error();
}

/// Octets a function put in a new buffer, copied out and the buffer freed.
fn take(p: *mut c_uchar, n: usize) -> Vec<u8> {
    if p.is_null() {
        return Vec::new();
    }
    // SAFETY: the buffer holds `n` octets.
    let v = unsafe { core::slice::from_raw_parts(p, n) }.to_vec();
    // SAFETY: a buffer from the allocator.
    unsafe { CRYPTO_free(p.cast(), ptr::null(), 0) };
    v
}

/// The key's private and public keys' octets.
fn parts(k: *const EC_KEY) -> (Vec<u8>, Vec<u8>) {
    let (mut a, mut b): (*mut c_uchar, *mut c_uchar) = (ptr::null_mut(), ptr::null_mut());
    // SAFETY: a live key; locals.
    let na = unsafe { EC_KEY_priv2buf(k, &mut a) };
    // SAFETY: as above (4: uncompressed).
    let nb = unsafe { EC_KEY_key2buf(k, 4, &mut b, ptr::null_mut()) };
    (take(a, na), take(b, nb))
}

/// Decodes `der`; the key and how much was consumed.
fn decode(der: &[u8]) -> (*mut EC_KEY, usize) {
    let mut p = der.as_ptr();
    let len = c_long::try_from(der.len()).unwrap();
    // SAFETY: `der` holds `len` octets.
    let k = unsafe { d2i_ECPrivateKey(ptr::null_mut(), &mut p, len) };
    (k, p as usize - der.as_ptr() as usize)
}

fuzz_target!(|input: &[u8]| {
    let (k, used) = decode(input);
    if k.is_null() {
        assert_eq!(used, 0, "a failed decode moved the input");
    } else {
        assert!(used <= input.len(), "consumed past the input");
        let mut der: *mut c_uchar = ptr::null_mut();
        // SAFETY: a live key; a local.
        let n = unsafe { i2d_ECPrivateKey(k, &mut der) };
        let der = take(der, usize::try_from(n).unwrap_or(0));
        // A private key longer than the order decodes but doesn't fit the order's length when
        // encoded, in OpenSSL too; any other key encodes and decodes back.
        if n > 0 {
            let (back, _) = decode(&der);
            assert!(!back.is_null(), "its encoding decodes");
            assert_eq!(parts(k), parts(back), "to the same keys");
            // SAFETY: freed once.
            unsafe { EC_KEY_free(back) };
        }
        // SAFETY: a live key.
        let _ = unsafe { EC_KEY_check_key(k) };
        // SAFETY: no preconditions.
        let bio = unsafe { BIO_new(BIO_s_mem()) };
        // SAFETY: a live BIO and key.
        let printed = unsafe { EC_KEY_print(bio, k, 2) };
        assert!(n <= 0 || printed == 1, "it prints");
        // SAFETY: freed once each.
        unsafe { BIO_free(bio) };
        // SAFETY: as above.
        unsafe { EC_KEY_free(k) };
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
