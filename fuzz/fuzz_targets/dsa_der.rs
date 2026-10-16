//! Fuzzes DSA's decoders (`d2i_DSAPrivateKey`, `d2i_DSAparams`, `d2i_DSAPublicKey`), which
//! traditional key files and certificates' parameters carry from untrusted sources, then a
//! verification with the key. Nothing may crash or read out of bounds (ASan), a decoder may
//! consume only the input, and a key it makes must encode again and decode back to the same
//! numbers.

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIGNUM, DSA, DSA_SIG};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

type D2i = unsafe extern "C" fn(*mut *mut DSA, *mut *const c_uchar, c_long) -> *mut DSA;
type I2d = unsafe extern "C" fn(*const DSA, *mut *mut c_uchar) -> c_int;

unsafe extern "C" {
    fn d2i_DSAPrivateKey(a: *mut *mut DSA, input: *mut *const c_uchar, len: c_long) -> *mut DSA;
    fn i2d_DSAPrivateKey(a: *const DSA, out: *mut *mut c_uchar) -> c_int;
    fn d2i_DSAparams(a: *mut *mut DSA, input: *mut *const c_uchar, len: c_long) -> *mut DSA;
    fn i2d_DSAparams(a: *const DSA, out: *mut *mut c_uchar) -> c_int;
    fn d2i_DSAPublicKey(a: *mut *mut DSA, input: *mut *const c_uchar, len: c_long) -> *mut DSA;
    fn i2d_DSAPublicKey(a: *const DSA, out: *mut *mut c_uchar) -> c_int;
    fn DSA_free(d: *mut DSA);
    fn DSA_get0_p(d: *const DSA) -> *const BIGNUM;
    fn DSA_get0_q(d: *const DSA) -> *const BIGNUM;
    fn DSA_get0_g(d: *const DSA) -> *const BIGNUM;
    fn DSA_get0_pub_key(d: *const DSA) -> *const BIGNUM;
    fn DSA_size(d: *const DSA) -> c_int;
    fn DSA_do_verify(dgst: *const c_uchar, len: c_int, sig: *mut DSA_SIG, d: *mut DSA) -> c_int;
    fn DSA_SIG_new() -> *mut DSA_SIG;
    fn DSA_SIG_set0(sig: *mut DSA_SIG, r: *mut BIGNUM, s: *mut BIGNUM) -> c_int;
    fn DSA_SIG_free(sig: *mut DSA_SIG);
    fn BN_new() -> *mut BIGNUM;
    fn BN_set_word(b: *mut BIGNUM, w: u64) -> c_int;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> c_int;
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn ERR_clear_error();
}

/// Whether two numbers are equal (or both missing).
fn same(a: *const BIGNUM, b: *const BIGNUM) -> bool {
    match (a.is_null(), b.is_null()) {
        (true, true) => true,
        // SAFETY: live numbers.
        (false, false) => (unsafe { BN_cmp(a, b) }) == 0,
        _ => false,
    }
}

fn number(w: u64) -> *mut BIGNUM {
    // SAFETY: no preconditions; the new number.
    unsafe {
        let b = BN_new();
        BN_set_word(b, w);
        b
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((&flags, input)) = input.split_first() else {
        return;
    };
    let (d2i, i2d): (D2i, I2d) = match flags % 3 {
        0 => (d2i_DSAPrivateKey, i2d_DSAPrivateKey),
        1 => (d2i_DSAparams, i2d_DSAparams),
        _ => (d2i_DSAPublicKey, i2d_DSAPublicKey),
    };
    let mut p = input.as_ptr();
    let len = c_long::try_from(input.len()).unwrap();
    // SAFETY: `input` holds `len` octets.
    let d = unsafe { d2i(ptr::null_mut(), &mut p, len) };
    let used = p as usize - input.as_ptr() as usize;
    if d.is_null() {
        assert_eq!(used, 0, "a failed decode moved the input");
    } else {
        assert!(used <= input.len(), "consumed past the input");
        let mut der: *mut c_uchar = ptr::null_mut();
        // SAFETY: a live key.
        let n = unsafe { i2d(d, &mut der) };
        assert!(n > 0, "a decoded key encodes");
        let mut q = der.cast_const();
        // SAFETY: the encoding of `n` octets.
        let back = unsafe { d2i(ptr::null_mut(), &mut q, c_long::from(n)) };
        assert!(!back.is_null(), "its encoding decodes");
        // SAFETY: live keys; a signature made here; a digest.
        unsafe {
            assert!(same(DSA_get0_p(d), DSA_get0_p(back)), "to the same p");
            assert!(same(DSA_get0_q(d), DSA_get0_q(back)), "q");
            assert!(same(DSA_get0_g(d), DSA_get0_g(back)), "g");
            assert!(
                same(DSA_get0_pub_key(d), DSA_get0_pub_key(back)),
                "and public key"
            );
            DSA_size(d);
            if !DSA_get0_pub_key(d).is_null() {
                let sig = DSA_SIG_new();
                DSA_SIG_set0(sig, number(3), number(5));
                let dgst = [7u8; 20];
                DSA_do_verify(dgst.as_ptr(), 20, sig, d);
                DSA_SIG_free(sig);
            }
            CRYPTO_free(der.cast(), ptr::null(), 0);
            DSA_free(back);
            DSA_free(d);
        }
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
