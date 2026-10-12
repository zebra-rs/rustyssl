//! Binary fields (`BN_GF2m_add(3)`; `bn_gf2m.c`): polynomials over GF(2) held in numbers, and
//! arithmetic modulo an irreducible polynomial given as a number or as the exponents of its
//! terms (`int p[]`, highest first, ending with 0 and then -1).
//!
//! OpenSSL ignores signs here but doesn't clear them: a result reduced into `r` keeps `r`'s own
//! sign (so does a sum), while one copied from a temporary is non-negative; both are kept. A
//! modulus given as a number must be odd, of degree at most 661, and for `BN_GF2m_mod` (and so
//! the inverse) of at most five terms (`BN_R_INVALID_LENGTH`), as OpenSSL requires.

use core::ffi::c_int;

use rustyssl_abi::{
    BIGNUM, BN_CTX, BN_R_INVALID_LENGTH, BN_R_NO_SOLUTION, BN_R_TOO_MANY_ITERATIONS,
    BN_RAND_BOTTOM_ANY, BN_RAND_TOP_ANY, BN_RAND_TOP_ONE, ERR_LIB_BN, OPENSSL_ECC_MAX_FIELD_BITS,
};
use rustyssl_crypto::bn::{BigNum, gf2m};

use super::rand::BN_priv_rand_ex;
use super::{BN_free, bignum, new_bignum, store, value};
use crate::err;
use crate::ffi::ffi_export;

/// The most terms read from an application's `int p[]`.
const MAX_TERMS: usize = 4096;

/// Stores `v` in `r` with `r`'s own sign (OpenSSL's reductions into `r` keep it).
///
/// # Safety
/// `r` is NULL or a live `BIGNUM`.
unsafe fn store_keeping_sign(r: *mut BIGNUM, mut v: BigNum) -> c_int {
    // SAFETY: the caller's guarantee.
    let neg = unsafe { value(r) }.is_some_and(|x| x.is_negative());
    v.set_negative(neg);
    // SAFETY: as above.
    c_int::from(unsafe { store(r, v) })
}

/// The terms of an application's polynomial, up to and including its 0 (or up to its -1);
/// negative entries other than the -1 are skipped.
///
/// # Safety
/// `p` points to an array ending with -1.
unsafe fn terms(p: *const c_int) -> Option<Vec<usize>> {
    if p.is_null() {
        return None;
    }
    let mut out = Vec::new();
    for i in 0..MAX_TERMS {
        // SAFETY: the caller's guarantee: the array reaches its -1.
        let t = unsafe { p.wrapping_add(i).read() };
        if t == -1 {
            break;
        }
        if let Ok(t) = usize::try_from(t) {
            out.push(t);
            if t == 0 {
                break;
            }
        }
    }
    Some(out)
}

/// `BN_GF2m_poly2arr` with OpenSSL's check `!ret || ret > max`: the terms, or
/// `BN_R_INVALID_LENGTH` (raised for `function`).
fn field(p: &BigNum, max: usize, function: &str) -> Option<Vec<usize>> {
    let limit = usize::try_from(OPENSSL_ECC_MAX_FIELD_BITS).unwrap_or(0);
    match gf2m::poly2arr(p, limit) {
        Some((t, n)) if n <= max => Some(t),
        _ => {
            err::raise(ERR_LIB_BN, BN_R_INVALID_LENGTH, function);
            None
        }
    }
}

/// The terms of `p` as the functions taking a number check it (`max` = its bits plus one).
///
/// # Safety
/// `p` is NULL or a live `BIGNUM`.
unsafe fn field_of(p: *const BIGNUM, function: &str) -> Option<Vec<usize>> {
    // SAFETY: the caller's guarantee.
    let v = unsafe { value(p) }?;
    field(&v, v.num_bits().saturating_add(1), function)
}

ffi_export! {
    /// `r = a + b` (exclusive or of the magnitudes; `r` keeps its sign). Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, and `b` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_GF2m_add(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(y)) = (unsafe { value(a) }, unsafe { value(b) }) else { return 0 };
        // SAFETY: as above.
        unsafe { store_keeping_sign(r, gf2m::add(&x, &y)) }
    }
}

ffi_export! {
    /// `r = a mod p` for `p` as its terms. Returns 1, or 0.
    ///
    /// # Safety
    /// `r` and `a` are NULL or live `BIGNUM`s; `p` is an array ending with 0 and -1.
    pub unsafe extern "C" fn BN_GF2m_mod_arr(r: *mut BIGNUM, a: *const BIGNUM, p: *const c_int) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(t)) = (unsafe { value(a) }, unsafe { terms(p) }) else { return 0 };
        // SAFETY: as above.
        unsafe { store_keeping_sign(r, gf2m::reduce(&x, &t)) }
    }
}

ffi_export! {
    /// `r = a mod p` for a polynomial `p` of at most five terms. Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, and `p` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_GF2m_mod(r: *mut BIGNUM, a: *const BIGNUM, p: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(pv)) = (unsafe { value(a) }, unsafe { value(p) }) else { return 0 };
        let Some(t) = field(&pv, 6, "BN_GF2m_mod") else { return 0 };
        // SAFETY: as above.
        unsafe { store_keeping_sign(r, gf2m::reduce(&x, &t)) }
    }
}

/// `r = a * b mod p` (a square for `a` the same number as `b`), keeping `r`'s sign.
///
/// # Safety
/// The numbers are live (or NULL).
unsafe fn mul_into(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, t: &[usize]) -> c_int {
    // SAFETY: the caller's guarantee.
    let (Some(x), Some(y)) = (unsafe { value(a) }, unsafe { value(b) }) else {
        return 0;
    };
    // SAFETY: as above.
    unsafe { store_keeping_sign(r, gf2m::mul(&x, &y, t)) }
}

ffi_export! {
    /// `r = a * b mod p` for `p` as its terms. Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, and `b` are NULL or live `BIGNUM`s; `p` is an array ending with 0 and -1.
    pub unsafe extern "C" fn BN_GF2m_mod_mul_arr(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, p: *const c_int, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { terms(p) }) else { return 0 };
        // SAFETY: as above.
        unsafe { mul_into(r, a, b, &t) }
    }
}

ffi_export! {
    /// `r = a * b mod p`. Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, `b`, and `p` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_GF2m_mod_mul(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, p: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { field_of(p, "BN_GF2m_mod_mul") }) else { return 0 };
        // SAFETY: as above.
        unsafe { mul_into(r, a, b, &t) }
    }
}

ffi_export! {
    /// `r = a^2 mod p` for `p` as its terms. Returns 1, or 0.
    ///
    /// # Safety
    /// `r` and `a` are NULL or live `BIGNUM`s; `p` is an array ending with 0 and -1.
    pub unsafe extern "C" fn BN_GF2m_mod_sqr_arr(r: *mut BIGNUM, a: *const BIGNUM, p: *const c_int, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { terms(p) }) else { return 0 };
        // SAFETY: as above.
        unsafe { mul_into(r, a, a, &t) }
    }
}

ffi_export! {
    /// `r = a^2 mod p`. Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, and `p` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_GF2m_mod_sqr(r: *mut BIGNUM, a: *const BIGNUM, p: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { field_of(p, "BN_GF2m_mod_sqr") }) else { return 0 };
        // SAFETY: as above.
        unsafe { mul_into(r, a, a, &t) }
    }
}

ffi_export! {
    /// `r = a^-1 mod p`, blinded by a random factor from the private generator, as OpenSSL
    /// does (so `r` holds the blinded product when there's no inverse). `p` may have at most
    /// five terms. Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, and `p` are NULL or live `BIGNUM`s; `ctx` is NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn BN_GF2m_mod_inv(r: *mut BIGNUM, a: *const BIGNUM, p: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(pv) = (unsafe { value(p) }) else { return 0 };
        let numbits = pv.num_bits();
        if numbits <= 1 {
            return 0;
        }
        let bits = c_int::try_from(numbits - 1).unwrap_or(c_int::MAX);
        let b = new_bignum(BigNum::zero(), false);
        let ret = 'work: {
            loop {
                // SAFETY: ours; the caller's context.
                if unsafe { BN_priv_rand_ex(b, bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, ctx) } == 0 {
                    break 'work 0;
                }
                // SAFETY: as above.
                if !unsafe { value(b) }.is_some_and(|v| v.is_zero()) {
                    break;
                }
            }
            // r = a * b; r = 1 / r; r = r * b.
            // SAFETY: as above.
            if unsafe { BN_GF2m_mod_mul(r, a, b, p, ctx) } == 0 {
                break 'work 0;
            }
            let Some(t5) = field(&pv, 6, "BN_GF2m_mod") else { break 'work 0 };
            // SAFETY: as above.
            let Some(rv) = (unsafe { value(r) }) else { break 'work 0 };
            let Some(inv) = gf2m::inverse(&rv, &pv, &t5) else { break 'work 0 };
            // SAFETY: as above.
            if !unsafe { store(r, inv) } {
                break 'work 0;
            }
            // SAFETY: as above.
            unsafe { BN_GF2m_mod_mul(r, r, b, p, ctx) }
        };
        // SAFETY: ours to free.
        unsafe { BN_free(b) };
        ret
    }
}

/// An application's polynomial as a number (`BN_GF2m_arr2poly`), in a new number.
///
/// # Safety
/// `p` is an array ending with -1.
unsafe fn arr_field(p: *const c_int) -> Option<*mut BIGNUM> {
    let f = new_bignum(BigNum::zero(), false);
    // SAFETY: the caller's guarantee; the number just made.
    if unsafe { BN_GF2m_arr2poly(p, f) } == 0 {
        // SAFETY: ours to free.
        unsafe { BN_free(f) };
        return None;
    }
    Some(f)
}

ffi_export! {
    /// `BN_GF2m_mod_inv` for `p` as its terms. Returns 1, or 0.
    ///
    /// # Safety
    /// `r` and `xx` are NULL or live `BIGNUM`s; `p` is an array ending with -1; `ctx` is NULL
    /// or a live `BN_CTX`.
    pub unsafe extern "C" fn BN_GF2m_mod_inv_arr(r: *mut BIGNUM, xx: *const BIGNUM, p: *const c_int, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(f) = (unsafe { arr_field(p) }) else { return 0 };
        // SAFETY: as above; `f` is ours.
        let ret = unsafe { BN_GF2m_mod_inv(r, xx, f, ctx) };
        // SAFETY: ours to free.
        unsafe { BN_free(f) };
        ret
    }
}

ffi_export! {
    /// `r = y / x mod p` (`y` times `x`'s inverse; `r` keeps its sign). Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `y`, `x`, and `p` are NULL or live `BIGNUM`s; `ctx` is NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn BN_GF2m_mod_div(r: *mut BIGNUM, y: *const BIGNUM, x: *const BIGNUM, p: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let xinv = new_bignum(BigNum::zero(), false);
        // SAFETY: the caller's guarantee; `xinv` is ours.
        let ret = c_int::from(unsafe { BN_GF2m_mod_inv(xinv, x, p, ctx) } != 0 && unsafe { BN_GF2m_mod_mul(r, y, xinv, p, ctx) } != 0);
        // SAFETY: ours to free.
        unsafe { BN_free(xinv) };
        ret
    }
}

ffi_export! {
    /// `BN_GF2m_mod_div` for `p` as its terms. Returns 1, or 0.
    ///
    /// # Safety
    /// As for `BN_GF2m_mod_inv_arr`, with `yy` NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_GF2m_mod_div_arr(r: *mut BIGNUM, yy: *const BIGNUM, xx: *const BIGNUM, p: *const c_int, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(f) = (unsafe { arr_field(p) }) else { return 0 };
        // SAFETY: as above; `f` is ours.
        let ret = unsafe { BN_GF2m_mod_div(r, yy, xx, f, ctx) };
        // SAFETY: ours to free.
        unsafe { BN_free(f) };
        ret
    }
}

/// `BN_GF2m_mod_exp_arr`: `a^|b| mod p`, but 1 for `b` zero and `a` itself (unreduced, with its
/// sign) for `|b|` one.
///
/// # Safety
/// `r`, `a`, and `b` are NULL or live `BIGNUM`s.
unsafe fn exp(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, t: &[usize]) -> c_int {
    // SAFETY: the caller's guarantee.
    let (Some(x), Some(e)) = (unsafe { value(a) }, unsafe { value(b) }) else {
        return 0;
    };
    let v = if e.is_zero() {
        BigNum::one()
    } else if e.abs_is_word(1) {
        x
    } else {
        let mut u = gf2m::reduce(&x, t);
        for i in (0..e.num_bits().saturating_sub(1)).rev() {
            u = gf2m::sqr(&u, t);
            if e.is_bit_set(i) {
                u = gf2m::mul(&u, &x, t);
            }
        }
        u
    };
    // SAFETY: as above.
    c_int::from(unsafe { store(r, v) })
}

ffi_export! {
    /// `r = a^|b| mod p` for `p` as its terms (1 for `b` zero, `a` as it is for `|b|` one).
    /// Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, and `b` are NULL or live `BIGNUM`s; `p` is an array ending with 0 and -1.
    pub unsafe extern "C" fn BN_GF2m_mod_exp_arr(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, p: *const c_int, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { terms(p) }) else { return 0 };
        // SAFETY: as above.
        unsafe { exp(r, a, b, &t) }
    }
}

ffi_export! {
    /// `r = a^|b| mod p`, as `BN_GF2m_mod_exp_arr`. Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, `b`, and `p` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_GF2m_mod_exp(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, p: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { field_of(p, "BN_GF2m_mod_exp") }) else { return 0 };
        // SAFETY: as above.
        unsafe { exp(r, a, b, &t) }
    }
}

/// `BN_GF2m_mod_sqrt_arr`: `a^(2^(m-1))`, or zero modulo 1.
///
/// # Safety
/// `r` and `a` are NULL or live `BIGNUM`s.
unsafe fn sqrt(r: *mut BIGNUM, a: *const BIGNUM, t: &[usize]) -> c_int {
    let deg = t.first().copied().unwrap_or(0);
    if deg == 0 {
        // SAFETY: the caller's guarantee.
        return c_int::from(unsafe { store(r, BigNum::zero()) });
    }
    let mut u = BigNum::zero();
    if u.set_bit(deg - 1).is_err() {
        return 0;
    }
    let ub = new_bignum(u, false);
    // SAFETY: as above; `ub` is ours.
    let ret = unsafe { exp(r, a, ub, t) };
    // SAFETY: ours to free.
    unsafe { BN_free(ub) };
    ret
}

ffi_export! {
    /// `r = sqrt(a) mod p` for `p` as its terms. Returns 1, or 0.
    ///
    /// # Safety
    /// `r` and `a` are NULL or live `BIGNUM`s; `p` is an array ending with 0 and -1.
    pub unsafe extern "C" fn BN_GF2m_mod_sqrt_arr(r: *mut BIGNUM, a: *const BIGNUM, p: *const c_int, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { terms(p) }) else { return 0 };
        // SAFETY: as above.
        unsafe { sqrt(r, a, &t) }
    }
}

ffi_export! {
    /// `r = sqrt(a) mod p`. Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, and `p` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_GF2m_mod_sqrt(r: *mut BIGNUM, a: *const BIGNUM, p: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { field_of(p, "BN_GF2m_mod_sqrt") }) else { return 0 };
        // SAFETY: as above.
        unsafe { sqrt(r, a, &t) }
    }
}

/// `BN_GF2m_mod_solve_quad_arr`: a `z` with `z^2 + z = a`; for an even degree, from random
/// `rho` drawn from the private generator (at most 50 tries).
///
/// # Safety
/// `r` and `a_` are NULL or live `BIGNUM`s; `ctx` is NULL or a live `BN_CTX`.
unsafe fn solve_quad(r: *mut BIGNUM, a_: *const BIGNUM, t: &[usize], ctx: *mut BN_CTX) -> c_int {
    const F: &str = "BN_GF2m_mod_solve_quad_arr";
    let deg = t.first().copied().unwrap_or(0);
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { value(a_) }) else {
        return 0;
    };
    if deg == 0 {
        // SAFETY: as above.
        return c_int::from(unsafe { store(r, BigNum::zero()) });
    }
    let a = gf2m::reduce(&x, t);
    if a.is_zero() {
        // SAFETY: as above.
        return c_int::from(unsafe { store(r, BigNum::zero()) });
    }
    let z = if deg % 2 == 1 {
        // The half-trace.
        let mut z = a.clone();
        for _ in 1..=(deg - 1) / 2 {
            z = gf2m::sqr(&gf2m::sqr(&z, t), t);
            z = gf2m::add(&z, &a);
        }
        z
    } else {
        let rho_n = new_bignum(BigNum::zero(), false);
        let bits = c_int::try_from(deg).unwrap_or(c_int::MAX);
        let mut found = None;
        for _ in 0..50 {
            // SAFETY: ours; the caller's context.
            if unsafe { BN_priv_rand_ex(rho_n, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY, 0, ctx) }
                == 0
            {
                // SAFETY: ours to free.
                unsafe { BN_free(rho_n) };
                return 0;
            }
            // SAFETY: as above.
            let rho = gf2m::reduce(&unsafe { value(rho_n) }.unwrap_or_default(), t);
            let mut z = BigNum::zero();
            let mut w = rho.clone();
            for _ in 1..deg {
                z = gf2m::sqr(&z, t);
                let w2 = gf2m::sqr(&w, t);
                z = gf2m::add(&z, &gf2m::mul(&w2, &a, t));
                w = gf2m::add(&w2, &rho);
            }
            if !w.is_zero() {
                found = Some(z);
                break;
            }
        }
        // SAFETY: ours to free.
        unsafe { BN_free(rho_n) };
        let Some(z) = found else {
            err::raise(ERR_LIB_BN, BN_R_TOO_MANY_ITERATIONS, F);
            return 0;
        };
        z
    };
    let w = gf2m::add(&z, &gf2m::sqr(&z, t));
    if !rustyssl_crypto::bn::ucmp(&w, &a).is_eq() {
        err::raise(ERR_LIB_BN, BN_R_NO_SOLUTION, F);
        return 0;
    }
    // SAFETY: as above.
    c_int::from(unsafe { store(r, z) })
}

ffi_export! {
    /// A solution `r` of `r^2 + r = a` modulo `p` as its terms. Returns 1, or 0
    /// (`BN_R_NO_SOLUTION`).
    ///
    /// # Safety
    /// `r` and `a` are NULL or live `BIGNUM`s; `p` is an array ending with 0 and -1; `ctx` is
    /// NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn BN_GF2m_mod_solve_quad_arr(r: *mut BIGNUM, a: *const BIGNUM, p: *const c_int, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { terms(p) }) else { return 0 };
        // SAFETY: as above.
        unsafe { solve_quad(r, a, &t, ctx) }
    }
}

ffi_export! {
    /// A solution `r` of `r^2 + r = a` modulo `p`. Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `a`, and `p` are NULL or live `BIGNUM`s; `ctx` is NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn BN_GF2m_mod_solve_quad(r: *mut BIGNUM, a: *const BIGNUM, p: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { field_of(p, "BN_GF2m_mod_solve_quad") }) else { return 0 };
        // SAFETY: as above.
        unsafe { solve_quad(r, a, &t, ctx) }
    }
}

ffi_export! {
    /// The exponents of `a`'s terms, highest first, into `p` (at most `max`, then -1 if there's
    /// room). Returns the number of terms plus one, or 0 for an even polynomial or one of degree
    /// past 661.
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`; `p` has room for `max` ints.
    pub unsafe extern "C" fn BN_GF2m_poly2arr(a: *const BIGNUM, p: *mut c_int, max: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { value(a) }) else { return 0 };
        let limit = usize::try_from(OPENSSL_ECC_MAX_FIELD_BITS).unwrap_or(0);
        let Some((t, n)) = gf2m::poly2arr(&v, limit) else { return 0 };
        let max = usize::try_from(max).unwrap_or(0);
        if !p.is_null() {
            for (i, &e) in t.iter().take(max).enumerate() {
                // SAFETY: the caller's room for `max` ints.
                unsafe { p.wrapping_add(i).write(c_int::try_from(e).unwrap_or(c_int::MAX)) };
            }
            if t.len() < max {
                // SAFETY: as above.
                unsafe { p.wrapping_add(t.len()).write(-1) };
            }
        }
        c_int::try_from(n).unwrap_or(0)
    }
}

ffi_export! {
    /// The polynomial whose terms' exponents are `p` (ending with -1) into `a`. Returns 1, or 0
    /// (a negative or too large exponent, with the terms before it set).
    ///
    /// # Safety
    /// `p` is an array ending with -1; `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_GF2m_arr2poly(p: *const c_int, a: *mut BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { bignum(a) }) else { return 0 };
        if p.is_null() || b.update(|v| *v = BigNum::zero()).is_none() {
            return 0;
        }
        for i in 0..MAX_TERMS {
            // SAFETY: the caller's guarantee: the array reaches its -1.
            let t = unsafe { p.wrapping_add(i).read() };
            if t == -1 {
                return 1;
            }
            let Ok(bit) = usize::try_from(t) else { return 0 };
            match b.update(|v| v.set_bit(bit)) {
                Some(Ok(())) => {}
                Some(Err(e)) => {
                    super::raise(e);
                    return 0;
                }
                None => return 0,
            }
        }
        1
    }
}
