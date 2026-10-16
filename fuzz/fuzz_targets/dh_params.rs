//! Fuzzes decoding DH parameters (`d2i_DHparams`, PKCS #3, and `d2i_DHxparams`, X9.42), which
//! keys' algorithm identifiers and TLS-era parameter files carry from untrusted sources. Nothing
//! may crash or read out of bounds (ASan), the decoder may consume only the input, and
//! parameters it makes must encode again, decode back to the same numbers, check cleanly, and
//! print.

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIGNUM, BIO, BIO_METHOD, DH};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_DHparams(a: *mut *mut DH, input: *mut *const c_uchar, len: c_long) -> *mut DH;
    fn i2d_DHparams(a: *const DH, out: *mut *mut c_uchar) -> c_int;
    fn d2i_DHxparams(a: *mut *mut DH, input: *mut *const c_uchar, len: c_long) -> *mut DH;
    fn i2d_DHxparams(a: *const DH, out: *mut *mut c_uchar) -> c_int;
    fn DH_free(d: *mut DH);
    fn DH_get0_p(d: *const DH) -> *const BIGNUM;
    fn DH_get0_q(d: *const DH) -> *const BIGNUM;
    fn DH_get0_g(d: *const DH) -> *const BIGNUM;
    fn DH_check_params(d: *const DH, ret: *mut c_int) -> c_int;
    fn DHparams_print(bp: *mut BIO, x: *const DH) -> c_int;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> c_int;
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn ERR_clear_error();
}

/// The parameters' encoding (PKCS #3, or X9.42), or `None`.
fn encode(d: *const DH, x942: bool) -> Option<Vec<u8>> {
    let mut der: *mut c_uchar = ptr::null_mut();
    // SAFETY: live parameters.
    let n = unsafe {
        if x942 {
            i2d_DHxparams(d, &mut der)
        } else {
            i2d_DHparams(d, &mut der)
        }
    };
    if n <= 0 {
        return None;
    }
    // SAFETY: the buffer holds `n` octets.
    let out = unsafe { core::slice::from_raw_parts(der, usize::try_from(n).unwrap()) }.to_vec();
    // SAFETY: a buffer from the allocator.
    unsafe { CRYPTO_free(der.cast(), ptr::null(), 0) };
    Some(out)
}

/// Decodes `der`; the parameters and how much was consumed.
fn decode(der: &[u8], x942: bool) -> (*mut DH, usize) {
    let mut p = der.as_ptr();
    let len = c_long::try_from(der.len()).unwrap();
    // SAFETY: `der` holds `len` octets.
    let d = unsafe {
        if x942 {
            d2i_DHxparams(ptr::null_mut(), &mut p, len)
        } else {
            d2i_DHparams(ptr::null_mut(), &mut p, len)
        }
    };
    (d, p as usize - der.as_ptr() as usize)
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

fuzz_target!(|input: &[u8]| {
    let Some((&flags, input)) = input.split_first() else {
        return;
    };
    let x942 = flags & 1 != 0;
    let (d, used) = decode(input, x942);
    if d.is_null() {
        assert_eq!(used, 0, "a failed decode moved the input");
    } else {
        assert!(used <= input.len(), "consumed past the input");
        let der = encode(d, x942).expect("decoded parameters encode");
        let (back, _) = decode(&der, x942);
        assert!(!back.is_null(), "their encoding decodes");
        // SAFETY: live parameters.
        unsafe {
            assert!(same(DH_get0_p(d), DH_get0_p(back)), "to the same p");
            assert!(same(DH_get0_g(d), DH_get0_g(back)), "and g");
            assert!(same(DH_get0_q(d), DH_get0_q(back)), "and q");
            let mut ret = 0;
            assert_eq!(DH_check_params(d, &mut ret), 1, "the parameters check");
            let bio = BIO_new(BIO_s_mem());
            assert_eq!(DHparams_print(bio, d), 1, "they print");
            BIO_free(bio);
            DH_free(back);
            DH_free(d);
        }
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
