//! Fuzzes binary fields and primality through the C ABI. Two inputs become elements of
//! GF(2^163) (sect163's pentanomial) and GF(2^233) (sect233's trinomial), by number and by
//! array: a product must commute and agree between the two forms and with repeated sums, an
//! inverse must multiply back to one, a square root must square back, a quotient must multiply
//! back, and a solution of `z^2 + z = a` must satisfy it. A word of input is tested for
//! primality and must agree with trial division. Nothing may panic or go out of bounds (ASan).

#![no_main]

use core::ffi::{c_int, c_uchar, c_ulong, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

type Bn = c_void;
type Ctx = c_void;

unsafe extern "C" {
    fn BN_new() -> *mut Bn;
    fn BN_free(a: *mut Bn);
    fn BN_CTX_new() -> *mut Ctx;
    fn BN_CTX_free(c: *mut Ctx);
    fn BN_bin2bn(s: *const c_uchar, len: c_int, ret: *mut Bn) -> *mut Bn;
    fn BN_set_word(a: *mut Bn, w: c_ulong) -> c_int;
    fn BN_is_zero(a: *const Bn) -> c_int;
    fn BN_is_one(a: *const Bn) -> c_int;
    fn BN_ucmp(a: *const Bn, b: *const Bn) -> c_int;
    fn BN_check_prime(p: *const Bn, ctx: *mut Ctx, cb: *mut c_void) -> c_int;
    fn BN_GF2m_arr2poly(p: *const c_int, a: *mut Bn) -> c_int;
    fn BN_GF2m_add(r: *mut Bn, a: *const Bn, b: *const Bn) -> c_int;
    fn BN_GF2m_mod(r: *mut Bn, a: *const Bn, p: *const Bn) -> c_int;
    fn BN_GF2m_mod_mul(
        r: *mut Bn,
        a: *const Bn,
        b: *const Bn,
        p: *const Bn,
        ctx: *mut Ctx,
    ) -> c_int;
    fn BN_GF2m_mod_mul_arr(
        r: *mut Bn,
        a: *const Bn,
        b: *const Bn,
        p: *const c_int,
        ctx: *mut Ctx,
    ) -> c_int;
    fn BN_GF2m_mod_sqr(r: *mut Bn, a: *const Bn, p: *const Bn, ctx: *mut Ctx) -> c_int;
    fn BN_GF2m_mod_inv(r: *mut Bn, a: *const Bn, p: *const Bn, ctx: *mut Ctx) -> c_int;
    fn BN_GF2m_mod_div(
        r: *mut Bn,
        y: *const Bn,
        x: *const Bn,
        p: *const Bn,
        ctx: *mut Ctx,
    ) -> c_int;
    fn BN_GF2m_mod_sqrt(r: *mut Bn, a: *const Bn, p: *const Bn, ctx: *mut Ctx) -> c_int;
    fn BN_GF2m_mod_solve_quad(r: *mut Bn, a: *const Bn, p: *const Bn, ctx: *mut Ctx) -> c_int;
    fn ERR_clear_error();
}

/// Whether two numbers' magnitudes are equal.
fn eq(a: *const Bn, b: *const Bn) -> bool {
    // SAFETY: live numbers.
    unsafe { BN_ucmp(a, b) == 0 }
}

/// Whether `n` is prime, by trial division.
fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    let mut d = 2u64;
    while d.saturating_mul(d) <= n {
        if n % d == 0 {
            return false;
        }
        d += 1;
    }
    true
}

fuzz_target!(|data: &[u8]| {
    // SAFETY: no preconditions, here and below.
    let ctx = unsafe { BN_CTX_new() };

    // Primality of a word below 2^32 (fast enough to divide).
    let mut w = [0u8; 4];
    for (d, s) in w.iter_mut().zip(data) {
        *d = *s;
    }
    let word = u64::from(u32::from_le_bytes(w));
    // SAFETY: as above.
    let n = unsafe { BN_new() };
    // SAFETY: a live number.
    unsafe { BN_set_word(n, word) };
    // SAFETY: as above.
    let got = unsafe { BN_check_prime(n, ctx, ptr::null_mut()) };
    assert_eq!(got == 1, is_prime(word), "{word}");

    let half = data.len() / 2;
    let (x, y) = data.split_at(half);
    let fields: [&[c_int]; 2] = [&[163, 7, 6, 3, 0, -1], &[233, 74, 0, -1]];
    for arr in fields {
        // SAFETY: as above.
        let (p, a, b, r, s, t) =
            unsafe { (BN_new(), BN_new(), BN_new(), BN_new(), BN_new(), BN_new()) };
        // SAFETY: a terminated array and a live number.
        assert_eq!(unsafe { BN_GF2m_arr2poly(arr.as_ptr(), p) }, 1);
        // SAFETY: the octets, into live numbers.
        unsafe { BN_bin2bn(x.as_ptr(), c_int::try_from(x.len()).unwrap(), a) };
        // SAFETY: as above.
        unsafe { BN_bin2bn(y.as_ptr(), c_int::try_from(y.len()).unwrap(), b) };
        // Products commute and agree with the array form.
        // SAFETY: live numbers and the array, here and below.
        assert_eq!(unsafe { BN_GF2m_mod_mul(r, a, b, p, ctx) }, 1);
        // SAFETY: as above.
        assert_eq!(unsafe { BN_GF2m_mod_mul(s, b, a, p, ctx) }, 1);
        assert!(eq(r, s), "commutes");
        // SAFETY: as above.
        assert_eq!(
            unsafe { BN_GF2m_mod_mul_arr(s, a, b, arr.as_ptr(), ctx) },
            1
        );
        assert!(eq(r, s), "the array form");
        // (a + b)^2 = a^2 + b^2.
        // SAFETY: as above.
        unsafe { BN_GF2m_add(t, a, b) };
        // SAFETY: as above.
        unsafe { BN_GF2m_mod_sqr(t, t, p, ctx) };
        // SAFETY: as above.
        unsafe { BN_GF2m_mod_sqr(r, a, p, ctx) };
        // SAFETY: as above.
        unsafe { BN_GF2m_mod_sqr(s, b, p, ctx) };
        // SAFETY: as above.
        unsafe { BN_GF2m_add(r, r, s) };
        assert!(eq(r, t), "the square of a sum");
        // A root squares back to the reduced value.
        // SAFETY: as above.
        unsafe { BN_GF2m_mod(t, a, p) };
        // SAFETY: as above.
        assert_eq!(unsafe { BN_GF2m_mod_sqrt(r, a, p, ctx) }, 1);
        // SAFETY: as above.
        unsafe { BN_GF2m_mod_sqr(r, r, p, ctx) };
        assert!(eq(r, t), "square root");
        // SAFETY: as above.
        if unsafe { BN_is_zero(t) } == 0 {
            // An inverse multiplies back to one; a quotient multiplies back.
            // SAFETY: as above.
            assert_eq!(unsafe { BN_GF2m_mod_inv(r, a, p, ctx) }, 1);
            // SAFETY: as above.
            unsafe { BN_GF2m_mod_mul(s, r, a, p, ctx) };
            // SAFETY: as above.
            assert_eq!(unsafe { BN_is_one(s) }, 1, "inverse");
            // SAFETY: as above.
            assert_eq!(unsafe { BN_GF2m_mod_div(r, b, a, p, ctx) }, 1);
            // SAFETY: as above.
            unsafe { BN_GF2m_mod_mul(s, r, a, p, ctx) };
            // SAFETY: as above.
            unsafe { BN_GF2m_mod(t, b, p) };
            assert!(eq(s, t), "quotient");
        }
        // A solution of z^2 + z = a, where there is one.
        // SAFETY: as above.
        if unsafe { BN_GF2m_mod_solve_quad(r, a, p, ctx) } == 1 {
            // SAFETY: as above.
            unsafe { BN_GF2m_mod_sqr(s, r, p, ctx) };
            // SAFETY: as above.
            unsafe { BN_GF2m_add(s, s, r) };
            // SAFETY: as above.
            unsafe { BN_GF2m_mod(t, a, p) };
            assert!(eq(s, t), "quadratic");
        }
        for v in [p, a, b, r, s, t] {
            // SAFETY: ours to free.
            unsafe { BN_free(v) };
        }
    }
    // SAFETY: ours to free.
    unsafe { BN_free(n) };
    // SAFETY: as above.
    unsafe { BN_CTX_free(ctx) };
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
