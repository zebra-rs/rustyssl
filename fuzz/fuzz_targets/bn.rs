//! Fuzzes BIGNUM through the C ABI. The parsers (`BN_hex2bn`, `BN_dec2bn`, `BN_asc2bn`,
//! `BN_mpi2bn`, and the octet readers, signed or not, either way round) take the input as it
//! is; then the input becomes two numbers, whose arithmetic must agree with `i128` when they're
//! small and satisfy the identities (`q * d + rem == a`, `(a + b) - b == a`, shifts as products
//! by powers of two) when they're not, and whose conversions (hex, decimal, MPI, octets, ASN.1
//! integers) must round-trip. Nothing may panic or go out of bounds (ASan).

#![no_main]

use core::ffi::{CStr, c_char, c_int, c_uchar, c_ulong, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

type Bn = c_void;

unsafe extern "C" {
    fn BN_new() -> *mut Bn;
    fn BN_free(a: *mut Bn);
    fn BN_CTX_new() -> *mut c_void;
    fn BN_CTX_free(c: *mut c_void);
    fn BN_hex2bn(a: *mut *mut Bn, s: *const c_char) -> c_int;
    fn BN_dec2bn(a: *mut *mut Bn, s: *const c_char) -> c_int;
    fn BN_asc2bn(a: *mut *mut Bn, s: *const c_char) -> c_int;
    fn BN_bn2hex(a: *const Bn) -> *mut c_char;
    fn BN_bn2dec(a: *const Bn) -> *mut c_char;
    fn BN_mpi2bn(s: *const c_uchar, len: c_int, ret: *mut Bn) -> *mut Bn;
    fn BN_bn2mpi(a: *const Bn, to: *mut c_uchar) -> c_int;
    fn BN_bin2bn(s: *const c_uchar, len: c_int, ret: *mut Bn) -> *mut Bn;
    fn BN_signed_bin2bn(s: *const c_uchar, len: c_int, ret: *mut Bn) -> *mut Bn;
    fn BN_signed_lebin2bn(s: *const c_uchar, len: c_int, ret: *mut Bn) -> *mut Bn;
    fn BN_lebin2bn(s: *const c_uchar, len: c_int, ret: *mut Bn) -> *mut Bn;
    fn BN_signed_bn2bin(a: *const Bn, to: *mut c_uchar, tolen: c_int) -> c_int;
    fn BN_bn2binpad(a: *const Bn, to: *mut c_uchar, tolen: c_int) -> c_int;
    fn BN_num_bits(a: *const Bn) -> c_int;
    fn BN_cmp(a: *const Bn, b: *const Bn) -> c_int;
    fn BN_is_zero(a: *const Bn) -> c_int;
    fn BN_is_negative(a: *const Bn) -> c_int;
    fn BN_set_negative(a: *mut Bn, n: c_int);
    fn BN_add(r: *mut Bn, a: *const Bn, b: *const Bn) -> c_int;
    fn BN_sub(r: *mut Bn, a: *const Bn, b: *const Bn) -> c_int;
    fn BN_mul(r: *mut Bn, a: *const Bn, b: *const Bn, ctx: *mut c_void) -> c_int;
    fn BN_div(dv: *mut Bn, rem: *mut Bn, a: *const Bn, d: *const Bn, ctx: *mut c_void) -> c_int;
    fn BN_nnmod(r: *mut Bn, a: *const Bn, d: *const Bn, ctx: *mut c_void) -> c_int;
    fn BN_lshift(r: *mut Bn, a: *const Bn, n: c_int) -> c_int;
    fn BN_rshift(r: *mut Bn, a: *const Bn, n: c_int) -> c_int;
    fn BN_set_bit(a: *mut Bn, n: c_int) -> c_int;
    fn BN_div_word(a: *mut Bn, w: c_ulong) -> c_ulong;
    fn BN_mod_word(a: *const Bn, w: c_ulong) -> c_ulong;
    fn BN_mul_word(a: *mut Bn, w: c_ulong) -> c_int;
    fn BN_add_word(a: *mut Bn, w: c_ulong) -> c_int;
    fn BN_copy(a: *mut Bn, b: *const Bn) -> *mut Bn;
    fn BN_to_ASN1_INTEGER(a: *const Bn, ai: *mut c_void) -> *mut c_void;
    fn ASN1_INTEGER_to_BN(ai: *const c_void, a: *mut Bn) -> *mut Bn;
    fn ASN1_INTEGER_free(ai: *mut c_void);
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
}

/// `BN_num_bytes`, a macro in C.
///
/// # Safety
/// `a` is a live number.
unsafe fn num_bytes(a: *const Bn) -> c_int {
    // SAFETY: the caller's guarantee.
    (unsafe { BN_num_bits(a) } + 7) / 8
}

/// A C string from the library, as text, freed.
///
/// # Safety
/// `s` is NULL or a string from `OPENSSL_malloc`.
unsafe fn take(s: *mut c_char) -> String {
    if s.is_null() {
        return String::new();
    }
    // SAFETY: the caller's guarantee.
    let text = unsafe { CStr::from_ptr(s) }.to_string_lossy().into_owned();
    // SAFETY: as above.
    unsafe { CRYPTO_free(s.cast(), ptr::null(), 0) };
    text
}

/// A new number from hex text.
fn from_hex(text: &str) -> *mut Bn {
    let c = std::ffi::CString::new(text).unwrap();
    let mut b = ptr::null_mut();
    // SAFETY: a string, and a pointer to fill.
    assert!(unsafe { BN_hex2bn(&mut b, c.as_ptr()) } > 0, "{text}");
    b
}

/// A number's value if it fits an `i128`.
fn small(b: *const Bn) -> Option<i128> {
    // SAFETY: a live number.
    if unsafe { BN_num_bits(b) } > 126 {
        return None;
    }
    // SAFETY: as above.
    let h = unsafe { take(BN_bn2hex(b)) };
    let (neg, digits) = h
        .strip_prefix('-')
        .map_or((false, h.as_str()), |d| (true, d));
    let v = i128::from_str_radix(digits, 16).ok()?;
    Some(if neg { -v } else { v })
}

/// Whether two numbers are equal.
fn eq(a: *const Bn, b: *const Bn) -> bool {
    // SAFETY: live numbers.
    unsafe { BN_cmp(a, b) == 0 }
}

/// The parsers on the raw input.
fn parse(data: &[u8]) {
    let text = std::ffi::CString::new(
        data.iter()
            .map(|&b| b.max(1))
            .take(4096)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    for f in [BN_hex2bn, BN_dec2bn, BN_asc2bn] {
        let mut b = ptr::null_mut();
        // SAFETY: a string, and a pointer to fill.
        let n = unsafe { f(&mut b, text.as_ptr()) };
        assert!(n >= 0);
        // SAFETY: NULL or the number made.
        unsafe { BN_free(b) };
    }
    let len = c_int::try_from(data.len()).unwrap();
    for f in [
        BN_mpi2bn,
        BN_bin2bn,
        BN_signed_bin2bn,
        BN_lebin2bn,
        BN_signed_lebin2bn,
    ] {
        // SAFETY: the input's octets.
        let b = unsafe { f(data.as_ptr(), len, ptr::null_mut()) };
        // SAFETY: NULL or the number made.
        unsafe { BN_free(b) };
    }
}

fuzz_target!(|data: &[u8]| {
    parse(data);
    let (Some(&split), Some(rest)) = (data.first(), data.get(1..)) else {
        return;
    };
    let at = usize::from(split).min(rest.len());
    let (x, y) = rest.split_at(at);
    // SAFETY: the octets, read into new numbers.
    let a = unsafe {
        BN_signed_bin2bn(
            x.as_ptr(),
            c_int::try_from(x.len()).unwrap(),
            ptr::null_mut(),
        )
    };
    // SAFETY: as above.
    let b = unsafe {
        BN_signed_lebin2bn(
            y.as_ptr(),
            c_int::try_from(y.len()).unwrap(),
            ptr::null_mut(),
        )
    };
    assert!(!a.is_null() && !b.is_null());
    // SAFETY: no preconditions.
    let ctx = unsafe { BN_CTX_new() };
    // SAFETY: no preconditions, here and below.
    let (r, q, m) = unsafe { (BN_new(), BN_new(), BN_new()) };

    // Arithmetic, against i128 when the operands are small.
    // SAFETY: live numbers, here and below.
    assert_eq!(unsafe { BN_add(r, a, b) }, 1);
    let operand = |n: *const Bn| small(n).filter(|v| v.unsigned_abs() < 1 << 120);
    if let (Some(x), Some(y)) = (operand(a), operand(b)) {
        assert_eq!(small(r), Some(x + y));
        // SAFETY: as above.
        unsafe { BN_sub(r, a, b) };
        assert_eq!(small(r), Some(x - y));
        if x.unsigned_abs() < 1 << 62 && y.unsigned_abs() < 1 << 62 {
            // SAFETY: as above.
            unsafe { BN_mul(r, a, b, ctx) };
            assert_eq!(small(r), Some(x * y));
        }
        if y != 0 {
            // SAFETY: as above.
            assert_eq!(unsafe { BN_div(q, m, a, b, ctx) }, 1);
            assert_eq!((small(q), small(m)), (Some(x / y), Some(x % y)));
            // SAFETY: as above.
            unsafe { BN_nnmod(m, a, b, ctx) };
            assert_eq!(small(m), Some(x.rem_euclid(y)));
        }
    } else {
        // SAFETY: as above.
        unsafe { BN_sub(r, r, b) };
        assert!(eq(r, a), "(a + b) - b");
    }
    // SAFETY: as above.
    if unsafe { BN_is_zero(b) } == 0 {
        // SAFETY: as above.
        assert_eq!(unsafe { BN_div(q, m, a, b, ctx) }, 1);
        // SAFETY: as above.
        unsafe { BN_mul(r, q, b, ctx) };
        // SAFETY: as above.
        unsafe { BN_add(r, r, m) };
        assert!(eq(r, a), "q * d + rem");
    }
    let shift = c_int::from(split % 130);
    // SAFETY: as above.
    unsafe { BN_lshift(r, a, shift) };
    // SAFETY: no preconditions.
    let pow = unsafe { BN_new() };
    // SAFETY: as above.
    unsafe { BN_set_bit(pow, shift) };
    // SAFETY: as above.
    unsafe { BN_mul(q, a, pow, ctx) };
    assert!(eq(r, q), "shift as a product");
    // SAFETY: as above.
    unsafe { BN_rshift(r, r, shift) };
    assert!(eq(r, a), "shift back");
    // SAFETY: as above.
    unsafe { BN_copy(r, a) };
    let w = c_ulong::from(split) | 1;
    // SAFETY: as above.
    let rem = unsafe { BN_mod_word(a, w) };
    // SAFETY: as above.
    assert_eq!(unsafe { BN_div_word(r, w) }, rem);
    // SAFETY: as above.
    unsafe { BN_mul_word(r, w) };
    // SAFETY: as above.
    let neg = unsafe { BN_is_negative(a) } != 0;
    // SAFETY: as above.
    unsafe { BN_set_negative(r, 0) };
    // SAFETY: as above.
    unsafe { BN_add_word(r, rem) };
    // SAFETY: as above.
    unsafe { BN_set_negative(r, c_int::from(neg)) };
    assert!(eq(r, a), "div_word");

    // Conversions round-trip.
    for x in [a, b] {
        // SAFETY: as above.
        let hex = unsafe { take(BN_bn2hex(x)) };
        let back = from_hex(&hex);
        assert!(eq(back, x), "hex {hex}");
        // SAFETY: as above.
        let dec = std::ffi::CString::new(unsafe { take(BN_bn2dec(x)) }).unwrap();
        let mut d = ptr::null_mut();
        // SAFETY: a string, and a pointer to fill.
        unsafe { BN_dec2bn(&mut d, dec.as_ptr()) };
        assert!(eq(d, x), "decimal");
        // SAFETY: as above.
        let n = unsafe { BN_bn2mpi(x, ptr::null_mut()) };
        let mut mpi = vec![0u8; usize::try_from(n).unwrap()];
        // SAFETY: room for the MPI.
        assert_eq!(unsafe { BN_bn2mpi(x, mpi.as_mut_ptr()) }, n);
        // SAFETY: the MPI's octets.
        let m2 = unsafe { BN_mpi2bn(mpi.as_ptr(), n, d) };
        assert!(m2 == d && eq(d, x), "mpi");
        // SAFETY: as above.
        let len = unsafe { num_bytes(x) } + 2;
        let mut buf = vec![0u8; usize::try_from(len).unwrap()];
        // SAFETY: room for `len` octets.
        assert_eq!(unsafe { BN_signed_bn2bin(x, buf.as_mut_ptr(), len) }, len);
        // SAFETY: the octets.
        unsafe { BN_signed_bin2bn(buf.as_ptr(), len, d) };
        assert!(eq(d, x), "signed octets");
        // SAFETY: room for `len` octets.
        assert_eq!(unsafe { BN_bn2binpad(x, buf.as_mut_ptr(), len) }, len);
        // SAFETY: as above.
        let ai = unsafe { BN_to_ASN1_INTEGER(x, ptr::null_mut()) };
        // SAFETY: the integer just made.
        unsafe { ASN1_INTEGER_to_BN(ai, d) };
        assert!(eq(d, x), "ASN.1");
        // SAFETY: ours to free.
        unsafe { ASN1_INTEGER_free(ai) };
        // SAFETY: as above.
        unsafe { BN_free(d) };
        // SAFETY: as above.
        unsafe { BN_free(back) };
    }

    for x in [a, b, r, q, m, pow] {
        // SAFETY: ours to free.
        unsafe { BN_free(x) };
    }
    // SAFETY: as above.
    unsafe { BN_CTX_free(ctx) };
});
