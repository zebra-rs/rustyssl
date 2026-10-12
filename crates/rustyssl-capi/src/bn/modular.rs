//! Modular arithmetic (`BN_mod_add(3)`, `BN_mod_exp_mont(3)`, `BN_mod_inverse(3)`,
//! `BN_kronecker`, `BN_mod_sqrt`, `BN_get0_nist_prime_256`, `BN_get_rfc3526_prime_2048(3)`,
//! `BN_generate_dsa_nonce(3)`; `bn_mod.c`, `bn_exp.c`, `bn_exp2.c`, `bn_gcd.c`, `bn_kron.c`,
//! `bn_sqrt.c`, `bn_nist.c`, `bn_const.c`, `bn_rand.c`).
//!
//! The functions OpenSSL composes from others are composed the same way here, so their
//! aliasing rules and errors are OpenSSL's: `BN_mod_add` is `BN_add` then `BN_nnmod`, which
//! refuses a result that is the modulus. The exponentiations compute their value with
//! [`exp_mod`] (constant time for an odd modulus), after each function's own checks; the
//! inverse and the gcd are always constant time.

use core::cmp::Ordering;
use core::ffi::{c_int, c_uchar, c_ulong};
use core::ptr;

use rustyssl_abi::{
    BIGNUM, BN_CTX, BN_FLG_CONSTTIME, BN_MONT_CTX, BN_R_CALLED_WITH_EVEN_MODULUS,
    BN_R_NO_SUITABLE_DIGEST, BN_R_PRIVATE_KEY_TOO_LARGE, ERR_LIB_BN, ERR_R_INTERNAL_ERROR,
    ERR_R_PASSED_INVALID_ARGUMENT, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,
};
use rustyssl_crypto::bn::modular::{self, exp_by_zero, exp_mod};
use rustyssl_crypto::bn::{self as core_bn, BigNum, Endian, Error};

use super::arith::{BN_add, BN_div, BN_lshift1, BN_nnmod, BN_sqr, BN_sub};
use super::mont::{montgomery, new_montgomery};
use super::{
    BN_cmp, BN_copy, BN_set_flags, Bignum, Owner, bignum, libctx_of, new_bignum, new_handle, raise,
    set_result, store, value,
};
use crate::err;
use crate::ffi::ffi_export;

/// Whether any of `numbers` is flagged `BN_FLG_CONSTTIME`.
fn consttime(numbers: &[&Bignum]) -> bool {
    numbers.iter().any(|b| b.flags() & BN_FLG_CONSTTIME != 0)
}

ffi_export! {
    /// `r = (a + b) mod m`, in `[0, |m|)` (`BN_add` then `BN_nnmod`). Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, `b`, and `m` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_mod_add(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        if unsafe { BN_add(r, a, b) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        unsafe { BN_nnmod(r, r, m, ctx) }
    }
}

ffi_export! {
    /// `r = (a - b) mod m`, in `[0, |m|)`. Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, `b`, and `m` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_mod_sub(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        if unsafe { BN_sub(r, a, b) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        unsafe { BN_nnmod(r, r, m, ctx) }
    }
}

ffi_export! {
    /// `r = (a * b) mod m`, in `[0, |m|)`. `r` may not be `m`. Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, `b`, and `m` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_mod_mul(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(y)) = (unsafe { value(a) }, unsafe { value(b) }) else { return 0 };
        let t = match core_bn::mul(&x, &y) {
            Ok(t) => t,
            Err(e) => {
                raise(e);
                return 0;
            }
        };
        let tmp = new_bignum(t, false);
        // SAFETY: as above; `tmp` is ours.
        let ret = unsafe { BN_nnmod(r, tmp, m, ctx) };
        // SAFETY: ours to free.
        unsafe { super::BN_free(tmp) };
        ret
    }
}

ffi_export! {
    /// `r = a^2 mod m` (`BN_sqr` then `BN_mod`, so `BN_div`'s remainder). Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, and `m` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_mod_sqr(r: *mut BIGNUM, a: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        if unsafe { BN_sqr(r, a, ctx) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        unsafe { BN_div(ptr::null_mut(), r, r, m, ctx) }
    }
}

ffi_export! {
    /// `r = 2a mod m`, in `[0, |m|)`. Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, and `m` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_mod_lshift1(r: *mut BIGNUM, a: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        if unsafe { BN_lshift1(r, a) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        unsafe { BN_nnmod(r, r, m, ctx) }
    }
}

ffi_export! {
    /// `r = 2a`, less `m` if that reaches it (for `a` in `[0, m)`). Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, and `m` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_mod_lshift1_quick(r: *mut BIGNUM, a: *const BIGNUM, m: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        if unsafe { BN_lshift1(r, a) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        if unsafe { BN_cmp(r, m) } >= 0 {
            // SAFETY: as above.
            return unsafe { BN_sub(r, r, m) };
        }
        1
    }
}

/// `BN_mod_lshift_quick` on values: `r` gets the shifted value, or on the error (a number
/// longer than `m`) what the shifts had come to, as OpenSSL's does.
///
/// # Safety
/// `r` is NULL or a live `BIGNUM`.
unsafe fn lshift_quick(r: *mut BIGNUM, a: BigNum, n: c_int, m: &BigNum) -> c_int {
    match modular::mod_lshift_quick(&a, i64::from(n), m) {
        // SAFETY: the caller's guarantee.
        Ok(v) => c_int::from(unsafe { store(r, v) }),
        Err((e, partial)) => {
            // OpenSSL's result holds what the shifts had come to.
            // SAFETY: as above.
            unsafe { store(r, partial) };
            raise(e);
            0
        }
    }
}

ffi_export! {
    /// `r = a * 2^n`, subtracting `m` whenever a shift reaches it, for `a` in `[0, m)`
    /// (`BN_R_INPUT_NOT_REDUCED` if `a` has more bits than `m`). A negative `n` copies `a`.
    /// Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, and `m` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_mod_lshift_quick(r: *mut BIGNUM, a: *const BIGNUM, n: c_int, m: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(mv)) = (unsafe { value(a) }, unsafe { value(m) }) else { return 0 };
        // SAFETY: as above.
        unsafe { lshift_quick(r, x, n, &mv) }
    }
}

ffi_export! {
    /// `r = (a * 2^n) mod m`, in `[0, |m|)`. Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, and `m` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_mod_lshift(r: *mut BIGNUM, a: *const BIGNUM, n: c_int, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        if unsafe { BN_nnmod(r, a, m, ctx) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let (Some(x), Some(mv)) = (unsafe { value(r) }, unsafe { value(m) }) else { return 0 };
        // SAFETY: as above.
        unsafe { lshift_quick(r, x, n, &mv.abs()) }
    }
}

ffi_export! {
    /// `r = (a + b) mod m` for `a` and `b` in `[0, m)`, in constant time: the sum over `m`'s
    /// words, less `m` once. Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, `b`, and `m` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_mod_add_quick(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, m: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(y), Some(mv)) = (unsafe { value(a) }, unsafe { value(b) }, unsafe { value(m) }) else {
            return 0;
        };
        // SAFETY: as above.
        c_int::from(unsafe { store(r, modular::mod_add_quick(&x, &y, &mv)) })
    }
}

ffi_export! {
    /// `r = a - b`, plus `m` if that's negative (for `a` and `b` in `[0, m)`). `r` may not be
    /// `m`. Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, `b`, and `m` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_mod_sub_quick(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, m: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        if ptr::eq(r, m) {
            err::raise(ERR_LIB_BN, ERR_R_PASSED_INVALID_ARGUMENT, "BN_mod_sub_quick");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        if unsafe { BN_sub(r, a, b) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        if unsafe { bignum(r) }.is_some_and(|x| x.value().is_negative()) {
            // SAFETY: as above.
            return unsafe { BN_add(r, r, m) };
        }
        1
    }
}

/// The three numbers of an exponentiation, and whether any is flagged constant-time.
struct Operands {
    a: BigNum,
    p: BigNum,
    m: BigNum,
    consttime: bool,
}

/// Reads `a`, `p`, and `m`.
///
/// # Safety
/// Each is NULL or a live `BIGNUM`.
unsafe fn operands(a: *const BIGNUM, p: *const BIGNUM, m: *const BIGNUM) -> Option<Operands> {
    // SAFETY: the caller's guarantee.
    let x = unsafe { bignum(a) }?;
    // SAFETY: as above.
    let y = unsafe { bignum(p) }?;
    // SAFETY: as above.
    let z = unsafe { bignum(m) }?;
    Some(Operands {
        consttime: consttime(&[x, y, z]),
        a: x.value(),
        p: y.value(),
        m: z.value(),
    })
}

/// The base OpenSSL's Montgomery exponentiations start from: `a`, or `a mod m` if it's
/// negative or not below `m`.
fn reduced(a: &BigNum, m: &BigNum) -> Result<BigNum, Error> {
    if a.is_negative() || core_bn::ucmp(a, m) != Ordering::Less {
        core_bn::nnmod(a, m)
    } else {
        Ok(a.clone())
    }
}

/// `BN_mod_exp_mont`'s value once its modulus is known odd: `a^|p|` modulo `mont`'s modulus
/// (or `|m|`), or `None` for an unset context.
///
/// # Safety
/// `in_mont` is NULL or a live `BN_MONT_CTX`.
unsafe fn mont_exp(o: &Operands, in_mont: *const BN_MONT_CTX) -> Option<Result<BigNum, Error>> {
    if o.p.is_zero() {
        return Some(Ok(exp_by_zero(&o.m)));
    }
    let n = if in_mont.is_null() {
        new_montgomery(&o.m)?.modulus().clone()
    } else {
        // SAFETY: the caller's guarantee.
        let mont = unsafe { montgomery(in_mont) }?;
        if mont.limbs() == 0 {
            return None;
        }
        mont.modulus().clone()
    };
    Some(reduced(&o.a, &o.m).and_then(|base| exp_mod(&base, &o.p, &n)))
}

/// Stores an exponentiation's outcome in `r`.
///
/// # Safety
/// `r` is NULL or a live `BIGNUM`.
unsafe fn finish(r: *mut BIGNUM, result: Option<Result<BigNum, Error>>) -> c_int {
    match result {
        // SAFETY: the caller's guarantee.
        Some(v) => unsafe { set_result(r, v) },
        None => 0,
    }
}

ffi_export! {
    /// `rr = a^|p| mod |m|` for an odd `m` (`BN_R_CALLED_WITH_EVEN_MODULUS` otherwise), with
    /// Montgomery multiplication in `in_mont` if given; constant time if any operand is flagged
    /// `BN_FLG_CONSTTIME`. Returns 1, or 0.
    ///
    /// # Safety
    /// `rr`, `a`, `p`, and `m` are NULL or live `BIGNUM`s; `in_mont` is NULL or a live
    /// `BN_MONT_CTX`.
    pub unsafe extern "C" fn BN_mod_exp_mont(rr: *mut BIGNUM, a: *const BIGNUM, p: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX, in_mont: *mut BN_MONT_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(o) = (unsafe { operands(a, p, m) }) else { return 0 };
        if !o.m.is_odd() {
            err::raise(ERR_LIB_BN, BN_R_CALLED_WITH_EVEN_MODULUS, "BN_mod_exp_mont");
            return 0;
        }
        if o.consttime {
            // SAFETY: as above.
            return unsafe { BN_mod_exp_mont_consttime(rr, a, p, m, ctx, in_mont) };
        }
        // SAFETY: as above.
        let v = unsafe { mont_exp(&o, in_mont) };
        // SAFETY: as above.
        unsafe { finish(rr, v) }
    }
}

ffi_export! {
    /// `rr = a^|p| mod |m|` for an odd `m`, in time that depends only on the operands'
    /// lengths in words. Returns 1, or 0.
    ///
    /// # Safety
    /// `rr`, `a`, `p`, and `m` are NULL or live `BIGNUM`s; `in_mont` is NULL or a live
    /// `BN_MONT_CTX`.
    pub unsafe extern "C" fn BN_mod_exp_mont_consttime(rr: *mut BIGNUM, a: *const BIGNUM, p: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX, in_mont: *mut BN_MONT_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let Some(o) = (unsafe { operands(a, p, m) }) else { return 0 };
        if !o.m.is_odd() {
            err::raise(ERR_LIB_BN, BN_R_CALLED_WITH_EVEN_MODULUS, "bn_mod_exp_mont_fixed_top");
            return 0;
        }
        // SAFETY: as above.
        let v = unsafe { mont_exp(&o, in_mont) };
        // SAFETY: as above.
        unsafe { finish(rr, v) }
    }
}

ffi_export! {
    /// `BN_mod_exp_mont_consttime` twice: `rr1 = a1^p1 mod m1` and `rr2 = a2^p2 mod m2`.
    /// Returns 1, or 0.
    ///
    /// # Safety
    /// The numbers are NULL or live `BIGNUM`s; the contexts NULL or live `BN_MONT_CTX`s.
    pub unsafe extern "C" fn BN_mod_exp_mont_consttime_x2(rr1: *mut BIGNUM, a1: *const BIGNUM, p1: *const BIGNUM, m1: *const BIGNUM, in_mont1: *mut BN_MONT_CTX, rr2: *mut BIGNUM, a2: *const BIGNUM, p2: *const BIGNUM, m2: *const BIGNUM, in_mont2: *mut BN_MONT_CTX, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let first = unsafe { BN_mod_exp_mont_consttime(rr1, a1, p1, m1, ctx, in_mont1) };
        // SAFETY: as above.
        c_int::from(first != 0 && unsafe { BN_mod_exp_mont_consttime(rr2, a2, p2, m2, ctx, in_mont2) } != 0)
    }
}

ffi_export! {
    /// `rr = a^|p| mod |m|` for a word `a` and an odd `m`. Neither `p` nor `m` may be flagged
    /// `BN_FLG_CONSTTIME`. Returns 1, or 0.
    ///
    /// # Safety
    /// `rr`, `p`, and `m` are NULL or live `BIGNUM`s; `in_mont` is NULL or a live
    /// `BN_MONT_CTX`.
    pub unsafe extern "C" fn BN_mod_exp_mont_word(rr: *mut BIGNUM, a: c_ulong, p: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX, in_mont: *mut BN_MONT_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let (Some(pb), Some(mb)) = (unsafe { bignum(p) }, unsafe { bignum(m) }) else { return 0 };
        if consttime(&[pb, mb]) {
            err::raise(ERR_LIB_BN, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, "BN_mod_exp_mont_word");
            return 0;
        }
        let (pv, mv) = (pb.value(), mb.value());
        if !mv.is_odd() {
            err::raise(ERR_LIB_BN, BN_R_CALLED_WITH_EVEN_MODULUS, "BN_mod_exp_mont_word");
            return 0;
        }
        let mut a = a;
        if let [w] = mv.limbs() {
            a %= *w;
        }
        if pv.is_zero() {
            // SAFETY: as above.
            return unsafe { set_result(rr, Ok(exp_by_zero(&mv))) };
        }
        if a == 0 {
            // SAFETY: as above.
            return unsafe { set_result(rr, Ok(BigNum::zero())) };
        }
        let o = Operands { a: BigNum::from_word(a), p: pv, m: mv, consttime: false };
        // SAFETY: as above.
        let v = unsafe { mont_exp(&o, in_mont) };
        // SAFETY: as above.
        unsafe { finish(rr, v) }
    }
}

/// The checks `BN_mod_exp_recp` and `BN_mod_exp_simple` share, then the value.
fn exp_plain(o: &Operands, function: &str) -> Option<Result<BigNum, Error>> {
    if o.consttime {
        err::raise(ERR_LIB_BN, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, function);
        return None;
    }
    if o.p.is_zero() {
        return Some(Ok(exp_by_zero(&o.m)));
    }
    Some(core_bn::nnmod(&o.a, &o.m).and_then(|base| exp_mod(&base, &o.p, &o.m)))
}

ffi_export! {
    /// `r = a^|p| mod |m|` by reciprocal reduction (any modulus). No operand may be flagged
    /// `BN_FLG_CONSTTIME`. Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, `p`, and `m` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_mod_exp_recp(r: *mut BIGNUM, a: *const BIGNUM, p: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let Some(o) = (unsafe { operands(a, p, m) }) else { return 0 };
        // A zero modulus fails in `BN_RECP_CTX_set`, without an error, before any reduction.
        if !o.consttime && !o.p.is_zero() && o.m.is_zero() {
            return 0;
        }
        // SAFETY: as above.
        unsafe { finish(r, exp_plain(&o, "BN_mod_exp_recp")) }
    }
}

ffi_export! {
    /// `r = a^|p| mod |m|` by plain modular multiplication. `r` may not be `m`, and no operand
    /// may be flagged `BN_FLG_CONSTTIME`. Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, `p`, and `m` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_mod_exp_simple(r: *mut BIGNUM, a: *const BIGNUM, p: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let Some(o) = (unsafe { operands(a, p, m) }) else { return 0 };
        if o.consttime {
            err::raise(ERR_LIB_BN, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, "BN_mod_exp_simple");
            return 0;
        }
        if ptr::eq(r, m) {
            err::raise(ERR_LIB_BN, ERR_R_PASSED_INVALID_ARGUMENT, "BN_mod_exp_simple");
            return 0;
        }
        // SAFETY: as above.
        unsafe { finish(r, exp_plain(&o, "BN_mod_exp_simple")) }
    }
}

ffi_export! {
    /// `r = a^|p| mod |m|`: Montgomery's for an odd modulus (by word for a one-word `a`),
    /// reciprocal reduction otherwise. Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, `p`, and `m` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_mod_exp(r: *mut BIGNUM, a: *const BIGNUM, p: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(o) = (unsafe { operands(a, p, m) }) else { return 0 };
        if !o.m.is_odd() {
            // SAFETY: as above.
            return unsafe { BN_mod_exp_recp(r, a, p, m, ctx) };
        }
        if let [w] = o.a.limbs()
            && !o.a.is_negative()
            && !o.consttime
        {
            // SAFETY: as above.
            return unsafe { BN_mod_exp_mont_word(r, *w, p, m, ctx, ptr::null_mut()) };
        }
        // SAFETY: as above.
        unsafe { BN_mod_exp_mont(r, a, p, m, ctx, ptr::null_mut()) }
    }
}

ffi_export! {
    /// `rr = a1^p1 * a2^p2 mod m` for an odd `m`, reducing each base with `BN_mod` (so a
    /// negative base gives a negative result for an odd power, as in OpenSSL). Returns 1, or 0.
    ///
    /// # Safety
    /// The numbers are NULL or live `BIGNUM`s; `in_mont` is NULL or a live `BN_MONT_CTX`.
    pub unsafe extern "C" fn BN_mod_exp2_mont(rr: *mut BIGNUM, a1: *const BIGNUM, p1: *const BIGNUM, a2: *const BIGNUM, p2: *const BIGNUM, m: *const BIGNUM, ctx: *mut BN_CTX, in_mont: *mut BN_MONT_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let (Some(x1), Some(y1), Some(x2), Some(y2), Some(mv)) =
            (unsafe { value(a1) }, unsafe { value(p1) }, unsafe { value(a2) }, unsafe { value(p2) }, unsafe { value(m) })
        else {
            return 0;
        };
        if !mv.is_odd() {
            err::raise(ERR_LIB_BN, BN_R_CALLED_WITH_EVEN_MODULUS, "BN_mod_exp2_mont");
            return 0;
        }
        if y1.is_zero() && y2.is_zero() {
            // SAFETY: as above.
            return unsafe { set_result(rr, Ok(BigNum::one())) };
        }
        let n = if in_mont.is_null() {
            let Some(mont) = new_montgomery(&mv) else { return 0 };
            mont.modulus().clone()
        } else {
            // SAFETY: as above.
            let Some(mont) = (unsafe { montgomery(in_mont) }) else { return 0 };
            mont.modulus().clone()
        };
        // A base that reduces to zero answers 0 before an unset context fails.
        if n.is_zero() {
            let zero_base = |a: &BigNum| core_bn::div_rem(a, &mv).is_ok_and(|(_, r)| r.is_zero());
            if zero_base(&x1) || zero_base(&x2) {
                // SAFETY: as above.
                return unsafe { set_result(rr, Ok(BigNum::zero())) };
            }
            return 0;
        }
        // SAFETY: as above.
        unsafe { set_result(rr, modular::exp2_mod(&x1, &y1, &x2, &y2, &mv, &n)) }
    }
}

ffi_export! {
    /// The inverse of `a` modulo `|n|`, in `[0, |n|)`, into `in` (or a new number if NULL),
    /// computed in constant time. NULL with `BN_R_NO_INVERSE` if there's none (for `n` 0 or
    /// ±1 too).
    ///
    /// # Safety
    /// `in_`, `a`, and `n` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_mod_inverse(in_: *mut BIGNUM, a: *const BIGNUM, n: *const BIGNUM, ctx: *mut BN_CTX) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(nv)) = (unsafe { value(a) }, unsafe { value(n) }) else { return ptr::null_mut() };
        let modulus = nv.abs();
        let inverse = if nv.abs_is_word(1) || nv.is_zero() {
            None
        } else {
            match reduced(&x, &modulus) {
                Ok(b) => core_bn::ct::inverse(&b, &modulus),
                Err(e) => {
                    raise(e);
                    return ptr::null_mut();
                }
            }
        };
        let Some(v) = inverse else {
            raise(Error::NoInverse);
            return ptr::null_mut();
        };
        if in_.is_null() {
            return new_bignum(v, false);
        }
        // SAFETY: as above.
        if unsafe { store(in_, v) } { in_ } else { ptr::null_mut() }
    }
}

ffi_export! {
    /// `r = gcd(|a|, |b|)`, in constant time (OpenSSL's steps, whose swaps may move `r`'s
    /// `BN_FLG_CONSTTIME` to a temporary). Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, and `b` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_gcd(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(y)) = (unsafe { value(a) }, unsafe { value(b) }) else { return 0 };
        let (g, keep) = if y.is_zero() {
            (x.abs(), true)
        } else if x.is_zero() {
            (y.abs(), true)
        } else {
            core_bn::ct::gcd(&x, &y)
        };
        // SAFETY: as above.
        if !unsafe { store(r, g) } {
            return 0;
        }
        // OpenSSL's swaps may have traded the result's BN_FLG_CONSTTIME for a temporary's
        // (which has none).
        if !keep
            // SAFETY: as above.
            && let Some(b) = unsafe { bignum(r) }
        {
            b.lock().flags &= !BN_FLG_CONSTTIME;
        }
        1
    }
}

ffi_export! {
    /// Whether `a` and `b` are coprime (1) or not (0), leaving the error queue as it was. Flags
    /// `a` `BN_FLG_CONSTTIME`, as OpenSSL does.
    ///
    /// # Safety
    /// `a` and `b` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_are_coprime(a: *mut BIGNUM, b: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        unsafe { BN_set_flags(a, BN_FLG_CONSTTIME) };
        // SAFETY: as above.
        let (Some(x), Some(y)) = (unsafe { value(a) }, unsafe { value(b) }) else { return 0 };
        if y.abs_is_word(1) || y.is_zero() {
            return 0;
        }
        let m = y.abs();
        let Ok(x) = reduced(&x, &m) else { return 0 };
        c_int::from(core_bn::ct::inverse(&x, &m).is_some())
    }
}

ffi_export! {
    /// The Kronecker symbol `(a | b)`: -1, 0, or 1, or -2 on failure.
    ///
    /// # Safety
    /// `a` and `b` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_kronecker(a: *const BIGNUM, b: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = -2, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(y)) = (unsafe { value(a) }, unsafe { value(b) }) else { return -2 };
        match modular::kronecker(&x, &y) {
            Ok(k) => k,
            Err(e) => {
                raise(e);
                -2
            }
        }
    }
}

ffi_export! {
    /// A square root of `a` modulo the prime `p`, into `in` (or a new number if NULL); NULL
    /// with `BN_R_P_IS_NOT_PRIME`, `BN_R_NOT_A_SQUARE`, or `BN_R_TOO_MANY_ITERATIONS`. When the
    /// final check fails, `in` holds the candidate, as in OpenSSL.
    ///
    /// # Safety
    /// `in_`, `a`, and `p` are NULL or live `BIGNUM`s; `ctx` is NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn BN_mod_sqrt(in_: *mut BIGNUM, a: *const BIGNUM, p: *const BIGNUM, ctx: *mut BN_CTX) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(pv)) = (unsafe { value(a) }, unsafe { value(p) }) else { return ptr::null_mut() };
        let mut random = |bits: usize| -> Option<BigNum> {
            let t = new_bignum(BigNum::zero(), false);
            let bits = c_int::try_from(bits).ok()?;
            // SAFETY: the number just made; the caller's context.
            let ok = unsafe { super::rand::BN_priv_rand_ex(t, bits, 0, 0, 0, ctx) } == 1;
            // SAFETY: as above.
            let v = unsafe { value(t) };
            // SAFETY: ours to free.
            unsafe { super::BN_free(t) };
            v.filter(|_| ok)
        };
        let (result, written) = match modular::mod_sqrt(&x, &pv, &mut random) {
            Ok(v) => (Ok(()), Some(v)),
            Err(f) => (Err(f.error), f.written),
        };
        let target = if in_.is_null() { written.as_ref().map(|_| new_bignum(BigNum::zero(), false)) } else { Some(in_) };
        if let (Some(t), Some(v)) = (target, written) {
            // SAFETY: the caller's number, or ours.
            if !unsafe { store(t, v) } {
                return ptr::null_mut();
            }
        }
        match result {
            Ok(()) => target.unwrap_or(ptr::null_mut()),
            Err(e) => {
                raise(e);
                if in_.is_null()
                    && let Some(t) = target
                {
                    // SAFETY: ours to free.
                    unsafe { super::BN_free(t) };
                }
                ptr::null_mut()
            }
        }
    }
}

/// The NIST primes' handles, made on first use and never freed: P-192, P-224, P-256, P-384,
/// P-521.
static NIST: [std::sync::atomic::AtomicPtr<BIGNUM>; 5] = [
    std::sync::atomic::AtomicPtr::new(ptr::null_mut()),
    std::sync::atomic::AtomicPtr::new(ptr::null_mut()),
    std::sync::atomic::AtomicPtr::new(ptr::null_mut()),
    std::sync::atomic::AtomicPtr::new(ptr::null_mut()),
    std::sync::atomic::AtomicPtr::new(ptr::null_mut()),
];

/// The bit lengths of the NIST primes, in `NIST`'s order.
const NIST_BITS: [usize; 5] = [192, 224, 256, 384, 521];

/// The read-only handle of the NIST prime at `index`.
fn nist(index: usize) -> *const BIGNUM {
    use std::sync::atomic::Ordering::{AcqRel, Acquire};
    let (Some(slot), Some(&bits)) = (NIST.get(index), NIST_BITS.get(index)) else {
        return ptr::null();
    };
    let current = slot.load(Acquire);
    if !current.is_null() {
        return current;
    }
    let Some(v) = modular::nist_prime(bits) else {
        return ptr::null();
    };
    let h = new_handle(Owner::Static, 0);
    // SAFETY: just made, not yet static data.
    unsafe { store(h, v) };
    // SAFETY: as above.
    if let Some(b) = unsafe { bignum(h) } {
        b.lock().flags = rustyssl_abi::BN_FLG_STATIC_DATA;
    }
    match slot.compare_exchange(ptr::null_mut(), h, AcqRel, Acquire) {
        Ok(_) => h,
        Err(winner) => {
            // SAFETY: ours lost the race and was never shared.
            unsafe { <BIGNUM as crate::handle::Handle>::free(h) };
            winner
        }
    }
}

/// `BN_nist_mod_*`: `r = a mod p` for the NIST prime at `index` (`field` is ignored, as in
/// OpenSSL). A negative `a` or one past `p^2` goes through `BN_nnmod`; one between `p` and `p^2`
/// takes OpenSSL's fast reduction, which leaves `r`'s sign as it was.
///
/// # Safety
/// `r` and `a` are NULL or live `BIGNUM`s.
unsafe fn nist_mod(index: usize, r: *mut BIGNUM, a: *const BIGNUM, ctx: *mut BN_CTX) -> c_int {
    let field = nist(index);
    // SAFETY: the caller's guarantee; the prime is live.
    let (Some(x), Some(p)) = (unsafe { value(a) }, unsafe { value(field) }) else {
        return 0;
    };
    let Ok(p2) = core_bn::sqr(&p) else { return 0 };
    if x.is_negative() || core_bn::ucmp(&x, &p2) != Ordering::Less {
        // SAFETY: as above.
        return unsafe { BN_nnmod(r, a, field, ctx) };
    }
    match core_bn::ucmp(&p, &x) {
        // SAFETY: as above.
        Ordering::Equal => c_int::from(unsafe { store(r, BigNum::zero()) }),
        Ordering::Greater if ptr::eq(r, a) => 1,
        // SAFETY: as above.
        Ordering::Greater => c_int::from(!unsafe { BN_copy(r, a) }.is_null()),
        Ordering::Less => {
            // OpenSSL's fast reduction never sets the result's sign: it keeps the one it had.
            // SAFETY: as above.
            let neg = unsafe { value(r) }.is_some_and(|v| v.is_negative());
            let v = core_bn::nnmod(&x, &p).map(|mut v| {
                v.set_negative(neg);
                v
            });
            // SAFETY: as above.
            unsafe { set_result(r, v) }
        }
    }
}

/// Defines the NIST prime getters and reductions.
macro_rules! nist {
    ($( $index:literal: $(#[$g:meta])* pub unsafe extern "C" fn $get:ident; $(#[$m:meta])* pub unsafe extern "C" fn $red:ident; )*) => {$(
        ffi_export! {
            $(#[$g])*
            ///
            /// # Safety
            /// No preconditions.
            pub unsafe extern "C" fn $get() -> *const BIGNUM
            where failure = ptr::null(), library = ERR_LIB_BN
            {
                nist($index)
            }
        }

        ffi_export! {
            $(#[$m])*
            /// Returns 1, or 0.
            ///
            /// # Safety
            /// `r`, `a`, and `field` are NULL or live `BIGNUM`s.
            pub unsafe extern "C" fn $red(r: *mut BIGNUM, a: *const BIGNUM, field: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
            where failure = 0, library = ERR_LIB_BN
            {
                let _ = field;
                // SAFETY: the caller's guarantee.
                unsafe { nist_mod($index, r, a, ctx) }
            }
        }
    )*};
}

nist! {
    0:
    /// The prime of P-192, read-only.
    pub unsafe extern "C" fn BN_get0_nist_prime_192;
    /// `r = a mod p192`.
    pub unsafe extern "C" fn BN_nist_mod_192;
    1:
    /// The prime of P-224, read-only.
    pub unsafe extern "C" fn BN_get0_nist_prime_224;
    /// `r = a mod p224`.
    pub unsafe extern "C" fn BN_nist_mod_224;
    2:
    /// The prime of P-256, read-only.
    pub unsafe extern "C" fn BN_get0_nist_prime_256;
    /// `r = a mod p256`.
    pub unsafe extern "C" fn BN_nist_mod_256;
    3:
    /// The prime of P-384, read-only.
    pub unsafe extern "C" fn BN_get0_nist_prime_384;
    /// `r = a mod p384`.
    pub unsafe extern "C" fn BN_nist_mod_384;
    4:
    /// The prime of P-521, read-only.
    pub unsafe extern "C" fn BN_get0_nist_prime_521;
    /// `r = a mod p521`.
    pub unsafe extern "C" fn BN_nist_mod_521;
}

/// A NIST reduction function.
type NistMod =
    unsafe extern "C" fn(*mut BIGNUM, *const BIGNUM, *const BIGNUM, *mut BN_CTX) -> c_int;

ffi_export! {
    /// The reduction function for a NIST prime whose magnitude is `p`, or NULL.
    ///
    /// # Safety
    /// `p` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_nist_mod_func(p: *const BIGNUM) -> Option<NistMod>
    where failure = None, library = ERR_LIB_BN
    {
        const FUNCS: [NistMod; 5] = [BN_nist_mod_192, BN_nist_mod_224, BN_nist_mod_256, BN_nist_mod_384, BN_nist_mod_521];
        // SAFETY: the caller's guarantee.
        let v = unsafe { value(p) }?;
        (0..5).find_map(|i| {
            // SAFETY: the prime is live.
            let prime = unsafe { value(nist(i)) }?;
            if core_bn::ucmp(&prime, &v) == Ordering::Equal { FUNCS.get(i).copied() } else { None }
        })
    }
}

/// The RFC prime of `bits` bits from `table`, into `bn` or a new number.
///
/// # Safety
/// `bn` is NULL or a live `BIGNUM`.
unsafe fn rfc_prime(bn: *mut BIGNUM, table: &[(usize, &str)], bits: usize) -> *mut BIGNUM {
    let Some(&(_, hex)) = table.iter().find(|(b, _)| *b == bits) else {
        return ptr::null_mut();
    };
    let Ok(v) = BigNum::from_hex_digits(hex.as_bytes()) else {
        return ptr::null_mut();
    };
    if bn.is_null() {
        return new_bignum(v, false);
    }
    // SAFETY: the caller's guarantee.
    if unsafe { store(bn, v) } {
        bn
    } else {
        ptr::null_mut()
    }
}

/// Defines the RFC prime getters.
macro_rules! rfc {
    ($( $(#[$attr:meta])* pub unsafe extern "C" fn $name:ident = ($table:ident, $bits:literal); )*) => {$(
        ffi_export! {
            $(#[$attr])*
            /// Into `bn`, or a new number if it's NULL; NULL on failure.
            ///
            /// # Safety
            /// `bn` is NULL or a live `BIGNUM`.
            pub unsafe extern "C" fn $name(bn: *mut BIGNUM) -> *mut BIGNUM
            where failure = ptr::null_mut(), library = ERR_LIB_BN
            {
                // SAFETY: the caller's guarantee.
                unsafe { rfc_prime(bn, core_bn::rfc_primes::$table, $bits) }
            }
        }
    )*};
}

rfc! {
    /// The 768-bit MODP prime of RFC 2409 (group 1).
    pub unsafe extern "C" fn BN_get_rfc2409_prime_768 = (RFC2409, 768);
    /// The 1024-bit MODP prime of RFC 2409 (group 2).
    pub unsafe extern "C" fn BN_get_rfc2409_prime_1024 = (RFC2409, 1024);
    /// The 1536-bit MODP prime of RFC 3526 (group 5).
    pub unsafe extern "C" fn BN_get_rfc3526_prime_1536 = (RFC3526, 1536);
    /// The 2048-bit MODP prime of RFC 3526 (group 14).
    pub unsafe extern "C" fn BN_get_rfc3526_prime_2048 = (RFC3526, 2048);
    /// The 3072-bit MODP prime of RFC 3526 (group 15).
    pub unsafe extern "C" fn BN_get_rfc3526_prime_3072 = (RFC3526, 3072);
    /// The 4096-bit MODP prime of RFC 3526 (group 16).
    pub unsafe extern "C" fn BN_get_rfc3526_prime_4096 = (RFC3526, 4096);
    /// The 6144-bit MODP prime of RFC 3526 (group 17).
    pub unsafe extern "C" fn BN_get_rfc3526_prime_6144 = (RFC3526, 6144);
    /// The 8192-bit MODP prime of RFC 3526 (group 18).
    pub unsafe extern "C" fn BN_get_rfc3526_prime_8192 = (RFC3526, 8192);
}

ffi_export! {
    /// A random `out` in `[0, range)` for a DSA or ECDSA nonce, mixing `priv` and the message
    /// with the private generator through SHA-512, as OpenSSL does (so a failing generator alone
    /// doesn't expose the key). Flags `out` `BN_FLG_CONSTTIME`. Returns 1, or 0.
    ///
    /// # Safety
    /// `out`, `range`, and `priv_` are NULL or live `BIGNUM`s; `message` holds `message_len`
    /// octets; `ctx` is NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn BN_generate_dsa_nonce(out: *mut BIGNUM, range: *const BIGNUM, priv_: *const BIGNUM, message: *const c_uchar, message_len: usize, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free};
        use crate::evp::md_ctx::{EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new};
        const F: &str = "ossl_bn_gen_dsa_nonce_fixed_top";
        // SAFETY: the caller's guarantee.
        let (Some(o), Some(rv), Some(pv)) = (unsafe { bignum(out) }, unsafe { value(range) }, unsafe { value(priv_) }) else {
            return 0;
        };
        // SAFETY: as above.
        let libctx = unsafe { libctx_of(ctx) };
        let num_k_bytes = rv.num_bytes().saturating_add(1);
        let Some(private) = pv.to_bin(Some(96), Endian::Big, false) else {
            err::raise(ERR_LIB_BN, BN_R_PRIVATE_KEY_TOO_LARGE, F);
            return 0;
        };
        // SAFETY: no preconditions.
        let mdctx = unsafe { EVP_MD_CTX_new() };
        // SAFETY: a name.
        let md = unsafe { EVP_MD_fetch(libctx, c"SHA512".as_ptr(), ptr::null()) };
        let mut ret = 0;
        'work: {
            if mdctx.is_null() {
                break 'work;
            }
            if md.is_null() {
                err::raise(ERR_LIB_BN, BN_R_NO_SUITABLE_DIGEST, F);
                break 'work;
            }
            let mut k = rustyssl_crypto::bn::Zeroizing::new(vec![0u8; num_k_bytes]);
            if let Some(first) = k.first_mut() {
                *first = 0xff;
            }
            let msg: &[u8] = if message.is_null() || message_len == 0 {
                &[]
            } else {
                // SAFETY: the caller's guarantee.
                unsafe { core::slice::from_raw_parts(message, message_len) }
            };
            for _ in 0..64 {
                let mut i: u8 = 0;
                let mut done = 1usize;
                while done < num_k_bytes {
                    let mut random = rustyssl_crypto::bn::Zeroizing::new([0u8; 64]);
                    // SAFETY: room for 64 octets.
                    if unsafe { crate::rand_lib::RAND_priv_bytes_ex(libctx, random.as_mut_ptr(), 64, 0) } <= 0 {
                        break 'work;
                    }
                    let mut digest = rustyssl_crypto::bn::Zeroizing::new([0u8; 64]);
                    // SAFETY: the context and digest made above; each buffer holds its length.
                    let ok = unsafe {
                        EVP_DigestInit_ex(mdctx, md, ptr::null_mut()) != 0
                    } && unsafe { EVP_DigestUpdate(mdctx, (&raw const i).cast(), 1) } != 0
                        // SAFETY: as above.
                        && unsafe { EVP_DigestUpdate(mdctx, private.as_ptr().cast(), private.len()) } != 0
                        // SAFETY: as above.
                        && unsafe { EVP_DigestUpdate(mdctx, msg.as_ptr().cast(), msg.len()) } != 0
                        // SAFETY: as above.
                        && unsafe { EVP_DigestUpdate(mdctx, random.as_ptr().cast(), random.len()) } != 0
                        // SAFETY: as above.
                        && unsafe { EVP_DigestFinal_ex(mdctx, digest.as_mut_ptr(), ptr::null_mut()) } != 0;
                    if !ok {
                        break 'work;
                    }
                    let todo = (num_k_bytes - done).min(64);
                    if let (Some(dst), Some(src)) = (k.get_mut(done..done + todo), digest.get(..todo)) {
                        dst.copy_from_slice(src);
                    }
                    done += todo;
                    i = i.wrapping_add(1);
                }
                let Ok(mut v) = BigNum::from_bin(&k, Endian::Big, false) else { break 'work };
                v.mask_bits(rv.num_bits());
                let less = core_bn::ucmp(&v, &rv) == Ordering::Less;
                {
                    let mut s = o.lock();
                    s.flags |= BN_FLG_CONSTTIME;
                }
                if !o.store(v) {
                    break 'work;
                }
                if less {
                    ret = 1;
                    break 'work;
                }
            }
            err::raise(ERR_LIB_BN, ERR_R_INTERNAL_ERROR, F);
        }
        // SAFETY: ours to free.
        unsafe { EVP_MD_CTX_free(mdctx) };
        // SAFETY: as above.
        unsafe { EVP_MD_free(md) };
        ret
    }
}
