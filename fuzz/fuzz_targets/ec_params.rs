//! Fuzzes decoding EC parameters (`d2i_ECPKParameters`), which certificates' and keys'
//! algorithm identifiers carry from untrusted peers: the field, basis, curve, base point,
//! order, and cofactor checks, and the lookup of a named curve. Nothing may crash or read out
//! of bounds (ASan), the decoder may consume only the input, and a group it makes must encode
//! again, decode back to the same group, pass `EC_GROUP_check` or fail it cleanly, and print.

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIO, BIO_METHOD, BN_CTX, EC_GROUP};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_ECPKParameters(
        a: *mut *mut EC_GROUP,
        input: *mut *const c_uchar,
        len: c_long,
    ) -> *mut EC_GROUP;
    fn i2d_ECPKParameters(a: *const EC_GROUP, out: *mut *mut c_uchar) -> c_int;
    fn EC_GROUP_free(g: *mut EC_GROUP);
    fn EC_GROUP_cmp(a: *const EC_GROUP, b: *const EC_GROUP, ctx: *mut BN_CTX) -> c_int;
    fn EC_GROUP_check(g: *const EC_GROUP, ctx: *mut BN_CTX) -> c_int;
    fn ECPKParameters_print(bp: *mut BIO, x: *const EC_GROUP, off: c_int) -> c_int;
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn ERR_clear_error();
}

/// The group's encoding, or `None`.
fn encode(g: *const EC_GROUP) -> Option<Vec<u8>> {
    let mut der: *mut c_uchar = ptr::null_mut();
    // SAFETY: a live group.
    let n = unsafe { i2d_ECPKParameters(g, &mut der) };
    if n <= 0 {
        return None;
    }
    // SAFETY: the buffer holds `n` octets.
    let out = unsafe { core::slice::from_raw_parts(der, usize::try_from(n).unwrap()) }.to_vec();
    // SAFETY: a buffer from the allocator.
    unsafe { CRYPTO_free(der.cast(), ptr::null(), 0) };
    Some(out)
}

/// Decodes `der`; the group and how much was consumed.
fn decode(der: &[u8]) -> (*mut EC_GROUP, usize) {
    let mut p = der.as_ptr();
    let len = c_long::try_from(der.len()).unwrap();
    // SAFETY: `der` holds `len` octets.
    let g = unsafe { d2i_ECPKParameters(ptr::null_mut(), &mut p, len) };
    (g, p as usize - der.as_ptr() as usize)
}

fuzz_target!(|input: &[u8]| {
    let (g, used) = decode(input);
    if g.is_null() {
        assert_eq!(used, 0, "a failed decode moved the input");
    } else {
        assert!(used <= input.len(), "consumed past the input");
        let der = encode(g).expect("a decoded group encodes");
        let (back, _) = decode(&der);
        assert!(!back.is_null(), "its encoding decodes");
        // SAFETY: live groups.
        assert_eq!(
            unsafe { EC_GROUP_cmp(g, back, ptr::null_mut()) },
            0,
            "to the same group"
        );
        // SAFETY: as above.
        let _ = unsafe { EC_GROUP_check(g, ptr::null_mut()) };
        // SAFETY: no preconditions.
        let bio = unsafe { BIO_new(BIO_s_mem()) };
        // SAFETY: a live BIO and group.
        assert_eq!(unsafe { ECPKParameters_print(bio, g, 4) }, 1, "it prints");
        // SAFETY: freed once each.
        unsafe { BIO_free(bio) };
        // SAFETY: as above.
        unsafe { EC_GROUP_free(back) };
        // SAFETY: as above.
        unsafe { EC_GROUP_free(g) };
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
