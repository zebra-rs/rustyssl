//! Fuzzes BIGNUM's modular arithmetic through the C ABI. The input becomes a base, an exponent,
//! and a modulus; every exponentiation that takes the modulus (Montgomery's, constant-time, by
//! word, reciprocal, simple) must agree, and with square and multiply by `BN_mod_mul` for
//! short exponents; an inverse must multiply back to one (and exist exactly when the gcd is
//! one, the gcd agreeing with Euclid's by `BN_div`); a Montgomery round trip must give the
//! reduced base back; the quick forms must agree with `BN_nnmod` on reduced operands; and a
//! square root modulo the prime 2^127 - 1 must square back. Nothing may panic or go out of
//! bounds (ASan).

#![no_main]

use core::ffi::{c_int, c_uchar, c_ulong, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

type Bn = c_void;
type Ctx = c_void;
type Mont = c_void;

unsafe extern "C" {
    fn BN_new() -> *mut Bn;
    fn BN_free(a: *mut Bn);
    fn BN_CTX_new() -> *mut Ctx;
    fn BN_CTX_free(c: *mut Ctx);
    fn BN_bin2bn(s: *const c_uchar, len: c_int, ret: *mut Bn) -> *mut Bn;
    fn BN_signed_bin2bn(s: *const c_uchar, len: c_int, ret: *mut Bn) -> *mut Bn;
    fn BN_cmp(a: *const Bn, b: *const Bn) -> c_int;
    fn BN_is_zero(a: *const Bn) -> c_int;
    fn BN_is_one(a: *const Bn) -> c_int;
    fn BN_is_odd(a: *const Bn) -> c_int;
    fn BN_num_bits(a: *const Bn) -> c_int;
    fn BN_get_word(a: *const Bn) -> c_ulong;
    fn BN_set_word(a: *mut Bn, w: c_ulong) -> c_int;
    fn BN_set_negative(a: *mut Bn, n: c_int);
    fn BN_copy(a: *mut Bn, b: *const Bn) -> *mut Bn;
    fn BN_set_bit(a: *mut Bn, n: c_int) -> c_int;
    fn BN_sub_word(a: *mut Bn, w: c_ulong) -> c_int;
    fn BN_div(dv: *mut Bn, rem: *mut Bn, a: *const Bn, d: *const Bn, ctx: *mut Ctx) -> c_int;
    fn BN_nnmod(r: *mut Bn, a: *const Bn, m: *const Bn, ctx: *mut Ctx) -> c_int;
    fn BN_add(r: *mut Bn, a: *const Bn, b: *const Bn) -> c_int;
    fn BN_mod_add(r: *mut Bn, a: *const Bn, b: *const Bn, m: *const Bn, ctx: *mut Ctx) -> c_int;
    fn BN_mod_add_quick(r: *mut Bn, a: *const Bn, b: *const Bn, m: *const Bn) -> c_int;
    fn BN_mod_sub(r: *mut Bn, a: *const Bn, b: *const Bn, m: *const Bn, ctx: *mut Ctx) -> c_int;
    fn BN_mod_sub_quick(r: *mut Bn, a: *const Bn, b: *const Bn, m: *const Bn) -> c_int;
    fn BN_mod_mul(r: *mut Bn, a: *const Bn, b: *const Bn, m: *const Bn, ctx: *mut Ctx) -> c_int;
    fn BN_mod_exp(r: *mut Bn, a: *const Bn, p: *const Bn, m: *const Bn, ctx: *mut Ctx) -> c_int;
    fn BN_mod_exp_mont(
        r: *mut Bn,
        a: *const Bn,
        p: *const Bn,
        m: *const Bn,
        ctx: *mut Ctx,
        mont: *mut Mont,
    ) -> c_int;
    fn BN_mod_exp_mont_consttime(
        r: *mut Bn,
        a: *const Bn,
        p: *const Bn,
        m: *const Bn,
        ctx: *mut Ctx,
        mont: *mut Mont,
    ) -> c_int;
    fn BN_mod_exp_mont_word(
        r: *mut Bn,
        a: c_ulong,
        p: *const Bn,
        m: *const Bn,
        ctx: *mut Ctx,
        mont: *mut Mont,
    ) -> c_int;
    fn BN_mod_exp_recp(
        r: *mut Bn,
        a: *const Bn,
        p: *const Bn,
        m: *const Bn,
        ctx: *mut Ctx,
    ) -> c_int;
    fn BN_mod_exp_simple(
        r: *mut Bn,
        a: *const Bn,
        p: *const Bn,
        m: *const Bn,
        ctx: *mut Ctx,
    ) -> c_int;
    fn BN_mod_inverse(r: *mut Bn, a: *const Bn, n: *const Bn, ctx: *mut Ctx) -> *mut Bn;
    fn BN_gcd(r: *mut Bn, a: *const Bn, b: *const Bn, ctx: *mut Ctx) -> c_int;
    fn BN_mod_sqrt(r: *mut Bn, a: *const Bn, p: *const Bn, ctx: *mut Ctx) -> *mut Bn;
    fn BN_MONT_CTX_new() -> *mut Mont;
    fn BN_MONT_CTX_free(m: *mut Mont);
    fn BN_MONT_CTX_set(m: *mut Mont, n: *const Bn, ctx: *mut Ctx) -> c_int;
    fn BN_to_montgomery(r: *mut Bn, a: *const Bn, m: *mut Mont, ctx: *mut Ctx) -> c_int;
    fn BN_from_montgomery(r: *mut Bn, a: *const Bn, m: *mut Mont, ctx: *mut Ctx) -> c_int;
    fn ERR_clear_error();
}

/// Whether two numbers are equal.
fn eq(a: *const Bn, b: *const Bn) -> bool {
    // SAFETY: live numbers.
    unsafe { BN_cmp(a, b) == 0 }
}

/// A new number from octets.
fn number(bytes: &[u8], signed: bool) -> *mut Bn {
    let len = c_int::try_from(bytes.len()).unwrap();
    // SAFETY: the octets, into a new number.
    let n = unsafe {
        if signed {
            BN_signed_bin2bn(bytes.as_ptr(), len, ptr::null_mut())
        } else {
            BN_bin2bn(bytes.as_ptr(), len, ptr::null_mut())
        }
    };
    assert!(!n.is_null());
    n
}

fuzz_target!(|data: &[u8]| {
    let [la, lp, lm, rest @ ..] = data else {
        return;
    };
    let la = usize::from(*la % 48).min(rest.len());
    let (abytes, rest) = rest.split_at(la);
    let lp = usize::from(*lp % 24).min(rest.len());
    let (pbytes, rest) = rest.split_at(lp);
    let lm = usize::from(*lm % 40).min(rest.len());
    let (mbytes, _) = rest.split_at(lm);
    let a = number(abytes, true);
    let p = number(pbytes, false);
    let m = number(mbytes, true);
    // SAFETY: no preconditions, here and below.
    let ctx = unsafe { BN_CTX_new() };
    // SAFETY: as above.
    let (r, s, t, u) = unsafe { (BN_new(), BN_new(), BN_new(), BN_new()) };

    // SAFETY: live numbers, here and below.
    if unsafe { BN_is_zero(m) } == 0 {
        // The exponentiations agree.
        // SAFETY: as above.
        assert_eq!(unsafe { BN_mod_exp_recp(r, a, p, m, ctx) }, 1);
        // SAFETY: as above.
        assert_eq!(unsafe { BN_mod_exp_simple(s, a, p, m, ctx) }, 1);
        assert!(eq(r, s), "recp and simple");
        // SAFETY: as above.
        assert_eq!(unsafe { BN_mod_exp(s, a, p, m, ctx) }, 1);
        assert!(eq(r, s), "BN_mod_exp");
        // SAFETY: as above.
        if unsafe { BN_is_odd(m) } == 1 {
            // SAFETY: as above.
            assert_eq!(
                unsafe { BN_mod_exp_mont(s, a, p, m, ctx, ptr::null_mut()) },
                1
            );
            assert!(eq(r, s), "mont");
            // SAFETY: as above.
            assert_eq!(
                unsafe { BN_mod_exp_mont_consttime(s, a, p, m, ctx, ptr::null_mut()) },
                1
            );
            assert!(eq(r, s), "consttime");
            // SAFETY: as above.
            if unsafe { BN_num_bits(a) } <= 64 {
                let w = unsafe { BN_get_word(a) };
                // SAFETY: as above.
                let neg = unsafe { BN_cmp(a, u) } < 0;
                if !neg {
                    // SAFETY: as above.
                    assert_eq!(
                        unsafe { BN_mod_exp_mont_word(s, w, p, m, ctx, ptr::null_mut()) },
                        1
                    );
                    assert!(eq(r, s), "word");
                }
            }
            // Montgomery's round trip of the reduced base.
            // SAFETY: as above.
            let mont = unsafe { BN_MONT_CTX_new() };
            // SAFETY: as above.
            assert_eq!(unsafe { BN_MONT_CTX_set(mont, m, ctx) }, 1);
            // SAFETY: as above.
            unsafe { BN_nnmod(t, a, m, ctx) };
            // SAFETY: as above.
            assert_eq!(unsafe { BN_to_montgomery(s, t, mont, ctx) }, 1);
            // SAFETY: as above.
            assert_eq!(unsafe { BN_from_montgomery(s, s, mont, ctx) }, 1);
            assert!(eq(s, t), "Montgomery round trip");
            // SAFETY: ours to free.
            unsafe { BN_MONT_CTX_free(mont) };
        }
        // Square and multiply for short exponents.
        // SAFETY: as above.
        if unsafe { BN_num_bits(p) } <= 16 {
            // SAFETY: as above.
            let e = unsafe { BN_get_word(p) };
            // SAFETY: as above.
            unsafe { BN_set_word(s, 1) };
            // SAFETY: as above.
            unsafe { BN_nnmod(s, s, m, ctx) };
            for _ in 0..e {
                // SAFETY: as above.
                unsafe { BN_mod_mul(s, s, a, m, ctx) };
            }
            assert!(eq(r, s), "repeated multiplication");
        }

        // Inverses and gcds.
        // SAFETY: as above.
        unsafe { BN_gcd(t, a, m, ctx) };
        // Euclid's, by BN_div.
        // SAFETY: as above.
        unsafe { BN_copy(r, a) };
        // SAFETY: as above.
        unsafe { BN_copy(s, m) };
        // SAFETY: as above.
        unsafe { BN_set_negative(r, 0) };
        // SAFETY: as above.
        unsafe { BN_set_negative(s, 0) };
        // SAFETY: as above.
        while unsafe { BN_is_zero(s) } == 0 {
            // SAFETY: as above.
            unsafe { BN_div(ptr::null_mut(), u, r, s, ctx) };
            // SAFETY: as above.
            unsafe { BN_copy(r, s) };
            // SAFETY: as above.
            unsafe { BN_copy(s, u) };
        }
        assert!(eq(t, r), "gcd");
        // SAFETY: as above.
        let inv = unsafe { BN_mod_inverse(ptr::null_mut(), a, m, ctx) };
        // SAFETY: as above.
        let invertible = unsafe { BN_is_one(t) } == 1 && unsafe { BN_num_bits(m) } > 1;
        assert_eq!(
            !inv.is_null(),
            invertible,
            "an inverse exactly when coprime"
        );
        if !inv.is_null() {
            // SAFETY: as above.
            unsafe { BN_mod_mul(r, inv, a, m, ctx) };
            // SAFETY: as above.
            assert_eq!(unsafe { BN_is_one(r) }, 1, "inverse");
            // SAFETY: ours to free.
            unsafe { BN_free(inv) };
        }

        // The quick forms agree with BN_nnmod on reduced operands.
        // SAFETY: as above.
        unsafe { BN_copy(u, m) };
        // SAFETY: as above.
        unsafe { BN_set_negative(u, 0) };
        // SAFETY: as above.
        unsafe { BN_nnmod(r, a, u, ctx) };
        // SAFETY: as above.
        unsafe { BN_nnmod(s, p, u, ctx) };
        // SAFETY: as above.
        unsafe { BN_mod_add_quick(t, r, s, u) };
        // SAFETY: as above.
        unsafe { BN_mod_add(r, r, s, u, ctx) };
        assert!(eq(t, r), "add quick");
        // SAFETY: as above.
        unsafe { BN_nnmod(r, a, u, ctx) };
        // SAFETY: as above.
        unsafe { BN_mod_sub_quick(t, r, s, u) };
        // SAFETY: as above.
        unsafe { BN_mod_sub(r, r, s, u, ctx) };
        assert!(eq(t, r), "sub quick");
    }

    // A square root modulo 2^127 - 1 (3 mod 4) of a square.
    // SAFETY: as above.
    let prime = unsafe { BN_new() };
    // SAFETY: as above.
    unsafe { BN_set_bit(prime, 127) };
    // SAFETY: as above.
    unsafe { BN_sub_word(prime, 1) };
    // SAFETY: as above.
    unsafe { BN_mod_mul(r, a, a, prime, ctx) };
    // SAFETY: as above.
    let root = unsafe { BN_mod_sqrt(ptr::null_mut(), r, prime, ctx) };
    assert!(!root.is_null(), "a square has a root");
    // SAFETY: as above.
    unsafe { BN_mod_mul(s, root, root, prime, ctx) };
    assert!(eq(s, r), "the root squares back");
    // SAFETY: ours to free.
    unsafe { BN_free(root) };
    // SAFETY: as above.
    let _ = unsafe { BN_add(t, t, t) };

    for x in [a, p, m, r, s, t, u, prime] {
        // SAFETY: ours to free.
        unsafe { BN_free(x) };
    }
    // SAFETY: as above.
    unsafe { BN_CTX_free(ctx) };
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
