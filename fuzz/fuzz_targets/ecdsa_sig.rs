//! Fuzzes reading ECDSA signatures (`d2i_ECDSA_SIG`, `ECDSA_verify`), which come from peers:
//! the DER reader's tags, lengths (one, two, and three octets), and INTEGERs. Nothing may crash
//! or read out of bounds (ASan); a signature it reads must encode, and its encoding read back
//! to the same numbers; and `ECDSA_verify` must refuse anything that isn't exactly DER.

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;
use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIGNUM, EC_KEY, ECDSA_SIG};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_ECDSA_SIG(
        a: *mut *mut ECDSA_SIG,
        input: *mut *const c_uchar,
        len: c_long,
    ) -> *mut ECDSA_SIG;
    fn i2d_ECDSA_SIG(a: *const ECDSA_SIG, out: *mut *mut c_uchar) -> c_int;
    fn ECDSA_SIG_free(s: *mut ECDSA_SIG);
    fn ECDSA_SIG_get0_r(s: *const ECDSA_SIG) -> *const BIGNUM;
    fn ECDSA_SIG_get0_s(s: *const ECDSA_SIG) -> *const BIGNUM;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> c_int;
    fn ECDSA_verify(
        t: c_int,
        d: *const c_uchar,
        dl: c_int,
        sig: *const c_uchar,
        sl: c_int,
        k: *mut EC_KEY,
    ) -> c_int;
    fn EC_KEY_new_by_curve_name(nid: c_int) -> *mut EC_KEY;
    fn EC_KEY_generate_key(k: *mut EC_KEY) -> c_int;
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn ERR_clear_error();
}

/// A P-256 key to verify against, made once.
struct Key(*mut EC_KEY);
// SAFETY: the key is only read after it's made.
unsafe impl Sync for Key {}
// SAFETY: as above.
unsafe impl Send for Key {}

static KEY: LazyLock<Key> = LazyLock::new(|| {
    // SAFETY: 415 is prime256v1.
    let k = unsafe { EC_KEY_new_by_curve_name(415) };
    // SAFETY: a live key.
    assert_eq!(unsafe { EC_KEY_generate_key(k) }, 1);
    Key(k)
});

fuzz_target!(|input: &[u8]| {
    let mut p = input.as_ptr();
    let len = c_long::try_from(input.len()).unwrap();
    // SAFETY: `input` holds `len` octets.
    let s = unsafe { d2i_ECDSA_SIG(ptr::null_mut(), &mut p, len) };
    if !s.is_null() {
        assert!(
            p as usize - input.as_ptr() as usize <= input.len(),
            "consumed past the input"
        );
        let mut der: *mut c_uchar = ptr::null_mut();
        // SAFETY: a live signature; a local.
        let n = unsafe { i2d_ECDSA_SIG(s, &mut der) };
        assert!(n > 0, "a signature read encodes");
        let mut q = der.cast_const();
        // SAFETY: the encoding's `n` octets.
        let back = unsafe { d2i_ECDSA_SIG(ptr::null_mut(), &mut q, c_long::from(n)) };
        assert!(!back.is_null(), "its encoding reads back");
        // SAFETY: live signatures.
        let same = unsafe {
            BN_cmp(ECDSA_SIG_get0_r(s), ECDSA_SIG_get0_r(back)) == 0
                && BN_cmp(ECDSA_SIG_get0_s(s), ECDSA_SIG_get0_s(back)) == 0
        };
        assert!(same, "to the same numbers");
        // SAFETY: freed once each.
        unsafe { ECDSA_SIG_free(back) };
        // SAFETY: as above.
        unsafe { CRYPTO_free(der.cast(), ptr::null(), 0) };
        // SAFETY: as above.
        unsafe { ECDSA_SIG_free(s) };
    }
    let digest = [0x5au8; 32];
    let sl = c_int::try_from(input.len()).unwrap_or(c_int::MAX);
    // SAFETY: a digest, the input, and the key.
    let v = unsafe { ECDSA_verify(0, digest.as_ptr(), 32, input.as_ptr(), sl, KEY.0) };
    assert!(v == -1 || v == 0, "a random signature never verifies");
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
