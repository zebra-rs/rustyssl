//! Modular arithmetic (`bn_mod.c`, `bn_exp.c`, `bn_exp2.c`, `bn_kron.c`, `bn_sqrt.c`,
//! `bn_recp.c`, `bn_nist.c`): the forms OpenSSL computes with their quirks, and the values its
//! exponentiations come to.
//!
//! Every `BN_mod_exp*` comes to `a^|p| mod M` (`M` the modulus's magnitude, in `[0, M)`), with
//! `p = 0` giving 1 (0 for `M = 1`); [`exp_mod`] computes it, in constant time for an odd
//! modulus (Montgomery's, with a fixed window) and by square and multiply for an even one.

use core::cmp::Ordering;

use super::mont::Montgomery;
use super::{
    BigNum, Error, LIMB_BITS, Limb, add, cmp, div_rem, lshift, lshift1, mul, nnmod, rshift, sqr,
    sub, ucmp,
};

/// What an exponentiation by zero gives: 0 modulo 1 (or -1), else 1.
pub fn exp_by_zero(m: &BigNum) -> BigNum {
    if m.abs_is_word(1) {
        BigNum::zero()
    } else {
        BigNum::one()
    }
}

/// `base^|p| mod |m|` for a non-negative `base` and a nonzero `m`; `p = 0` as [`exp_by_zero`].
pub fn exp_mod(base: &BigNum, p: &BigNum, m: &BigNum) -> Result<BigNum, Error> {
    if p.is_zero() {
        return Ok(exp_by_zero(m));
    }
    let base = if ucmp(base, m) == Ordering::Less && !base.is_negative() {
        base.clone()
    } else {
        nnmod(base, m)?
    };
    if m.is_odd() {
        let mont = Montgomery::new(m).map_err(|_| Error::NoInverse)?;
        return Ok(mont.exp_consttime(&base, p.limbs()));
    }
    let m = m.abs();
    let mut r = BigNum::one();
    for i in (0..p.num_bits()).rev() {
        r = div_rem(&sqr(&r)?, &m)?.1;
        if p.is_bit_set(i) {
            r = div_rem(&mul(&r, &base)?, &m)?.1;
        }
    }
    Ok(div_rem(&r, &m)?.1)
}

/// `BN_mod_exp2_mont`'s value for an odd `m`: `(a1 mod m)^|p1| * (a2 mod m)^|p2|` reduced
/// modulo `n` (the Montgomery modulus), where each `a mod m` is `BN_mod`'s (signed, so a
/// negative base gives a negative result for an odd power); 1 when both powers are 0, and 0
/// when either base is a multiple of `m`, as OpenSSL answers before multiplying.
pub fn exp2_mod(
    a1: &BigNum,
    p1: &BigNum,
    a2: &BigNum,
    p2: &BigNum,
    m: &BigNum,
    n: &BigNum,
) -> Result<BigNum, Error> {
    if p1.is_zero() && p2.is_zero() {
        return Ok(BigNum::one());
    }
    let reduce = |a: &BigNum| -> Result<BigNum, Error> {
        if a.is_negative() || ucmp(a, m) != Ordering::Less {
            Ok(div_rem(a, m)?.1)
        } else {
            Ok(a.clone())
        }
    };
    let (x1, x2) = (reduce(a1)?, reduce(a2)?);
    if x1.is_zero() || x2.is_zero() {
        return Ok(BigNum::zero());
    }
    let y1 = exp_mod(&x1.abs(), p1, n)?;
    let y2 = exp_mod(&x2.abs(), p2, n)?;
    let (_, mut r) = div_rem(&mul(&y1, &y2)?, n)?;
    let neg = (x1.is_negative() && p1.is_odd()) != (x2.is_negative() && p2.is_odd());
    r.set_negative(neg);
    Ok(r)
}

/// `BN_mod_add_quick`: OpenSSL's fixed-length sum of magnitudes cut to `m`'s length, less `m`
/// once (a mix of the two when only the sum carries, for operands that weren't reduced).
pub fn mod_add_quick(a: &BigNum, b: &BigNum, m: &BigNum) -> BigNum {
    let n = m.top();
    let mut t = vec![0; n];
    let mut carry = false;
    for (i, slot) in t.iter_mut().enumerate() {
        let x = a.limbs().get(i).copied().unwrap_or(0);
        let y = b.limbs().get(i).copied().unwrap_or(0);
        let (s1, c1) = x.overflowing_add(y);
        let (s2, c2) = s1.overflowing_add(Limb::from(carry));
        *slot = s2;
        carry = c1 || c2;
    }
    let mut d = vec![0; n];
    let mut borrow = false;
    for ((slot, &x), &y) in d.iter_mut().zip(&t).zip(m.limbs()) {
        let (d1, b1) = x.overflowing_sub(y);
        let (d2, b2) = d1.overflowing_sub(Limb::from(borrow));
        *slot = d2;
        borrow = b1 || b2;
    }
    let sel = Limb::from(carry).wrapping_sub(Limb::from(borrow));
    let r = d
        .iter()
        .zip(&t)
        .map(|(&x, &y)| (sel & y) | (!sel & x))
        .collect();
    BigNum::from_limbs(false, r).unwrap_or_default()
}

/// `BN_mod_lshift_quick`: `a * 2^n`, subtracting `m` after each shift that reaches it. Once
/// the number has more bits than `m` it fails (`InputNotReduced`) with what it had come to,
/// which OpenSSL leaves in the result. A negative `n` shifts nothing.
pub fn mod_lshift_quick(a: &BigNum, n: i64, m: &BigNum) -> Result<BigNum, (Error, BigNum)> {
    let mut r = a.clone();
    let mut n = n;
    while n > 0 {
        let max = i64::try_from(m.num_bits())
            .unwrap_or(i64::MAX)
            .saturating_sub(i64::try_from(r.num_bits()).unwrap_or(i64::MAX));
        if max < 0 {
            return Err((Error::InputNotReduced, r));
        }
        let step = max.min(n);
        let shifted = if step > 0 {
            n = n.saturating_sub(step);
            lshift(&r, usize::try_from(step).unwrap_or(0))
        } else {
            n = n.saturating_sub(1);
            lshift1(&r)
        };
        r = shifted.map_err(|e| (e, r.clone()))?;
        if cmp(&r, m) != Ordering::Less {
            r = sub(&r, m).map_err(|e| (e, r.clone()))?;
        }
    }
    Ok(r)
}

/// `BN_mod_lshift1_quick`: `2a`, less `m` if that reaches it.
pub fn mod_lshift1_quick(a: &BigNum, m: &BigNum) -> Result<BigNum, Error> {
    let r = lshift1(a)?;
    if cmp(&r, m) != Ordering::Less {
        sub(&r, m)
    } else {
        Ok(r)
    }
}

/// `BN_mod_mul`: `a * b` reduced into `[0, |m|)`.
pub fn mod_mul(a: &BigNum, b: &BigNum, m: &BigNum) -> Result<BigNum, Error> {
    nnmod(&mul(a, b)?, m)
}

/// `BN_mod_sqr`: `a^2` modulo `m`, as `BN_mod` leaves it.
pub fn mod_sqr(a: &BigNum, m: &BigNum) -> Result<BigNum, Error> {
    Ok(div_rem(&sqr(a)?, m)?.1)
}

/// The low limb, as OpenSSL's `BN_lsw` reads it (0 for zero).
fn lsw(a: &BigNum) -> Limb {
    a.limbs().first().copied().unwrap_or(0)
}

/// The lowest set bit of a nonzero number.
fn trailing_zeros(a: &BigNum) -> usize {
    let mut i = 0;
    while !a.is_bit_set(i) {
        i = i.saturating_add(1);
    }
    i
}

/// `BN_kronecker`: the Kronecker symbol `(a | b)`, OpenSSL's way (negative `a` read from its
/// magnitude's bits, as `BN_lsw` does).
pub fn kronecker(a: &BigNum, b: &BigNum) -> Result<i32, Error> {
    const TAB: [i32; 8] = [0, 1, 0, -1, 0, -1, 0, 1];
    let tab = |w: Limb| {
        TAB.get(usize::try_from(w & 7).unwrap_or(0))
            .copied()
            .unwrap_or(0)
    };
    let mut a = a.clone();
    let mut b = b.clone();
    if b.is_zero() {
        return Ok(i32::from(a.abs_is_word(1)));
    }
    if !a.is_odd() && !b.is_odd() {
        return Ok(0);
    }
    let i = trailing_zeros(&b);
    b = rshift(&b, i);
    let mut ret = if i & 1 == 1 { tab(lsw(&a)) } else { 1 };
    if b.is_negative() {
        b.set_negative(false);
        if a.is_negative() {
            ret = ret.wrapping_neg();
        }
    }
    loop {
        if a.is_zero() {
            return Ok(if b.is_one() { ret } else { 0 });
        }
        let i = trailing_zeros(&a);
        a = rshift(&a, i);
        if i & 1 == 1 {
            ret = ret.wrapping_mul(tab(lsw(&b)));
        }
        let aw = if a.is_negative() { !lsw(&a) } else { lsw(&a) };
        if aw & lsw(&b) & 2 != 0 {
            ret = ret.wrapping_neg();
        }
        b = nnmod(&b, &a)?;
        core::mem::swap(&mut a, &mut b);
        b.set_negative(false);
    }
}

/// `BN_mod_sqrt`'s outcome: the root, or the error and what it had written to the result
/// (OpenSSL's result holds the candidate when the final check fails).
pub struct SqrtFailure {
    pub error: Error,
    pub written: Option<BigNum>,
}

impl From<Error> for SqrtFailure {
    fn from(error: Error) -> Self {
        Self {
            error,
            written: None,
        }
    }
}

/// `BN_mod_sqrt`: a square root of `a` modulo the prime `p` (Tonelli and Shanks), drawing
/// `bits`-bit candidates from `random` after 20 small ones fail. The loop is bounded as the
/// CVE-2022-0778 fix bounds it.
pub fn mod_sqrt(
    a: &BigNum,
    p: &BigNum,
    random: &mut dyn FnMut(usize) -> Option<BigNum>,
) -> Result<BigNum, SqrtFailure> {
    if !p.is_odd() || p.abs_is_word(1) {
        if p.abs_is_word(2) {
            return Ok(BigNum::from_word(Limb::from(a.is_bit_set(0))));
        }
        return Err(Error::PIsNotPrime.into());
    }
    if a.is_zero() || a.is_one() {
        return Ok(BigNum::from_word(Limb::from(a.is_one())));
    }
    let big_a = nnmod(a, p)?;
    let mut e = 1usize;
    while !p.is_bit_set(e) {
        e = e.saturating_add(1);
    }
    let verify = |ret: BigNum| -> Result<BigNum, SqrtFailure> {
        let x = mod_sqr(&ret, p)?;
        if cmp(&x, &big_a) != Ordering::Equal {
            return Err(SqrtFailure {
                error: Error::NotASquare,
                written: Some(ret),
            });
        }
        Ok(ret)
    };
    if e == 1 {
        // p = 3 (mod 4): A^((p+1)/4).
        let mut q = rshift(p, 2);
        q.set_negative(false);
        q.add_word(1)?;
        return verify(exp_mod(&big_a, &q, p)?);
    }
    if e == 2 {
        // p = 5 (mod 8): Atkin's formula.
        let t = mod_lshift1_quick(&big_a, p)?;
        let mut q = rshift(p, 3);
        q.set_negative(false);
        let b = exp_mod(&t, &q, p)?;
        let y = mod_sqr(&b, p)?;
        let mut t = mod_mul(&t, &y, p)?;
        t.sub_word(1)?;
        let x = mod_mul(&big_a, &b, p)?;
        let x = mod_mul(&x, &t, p)?;
        return verify(x);
    }
    let mut q = p.abs();
    // A non-residue y: 2, 3, ..., then random ones.
    let mut i: Limb = 2;
    let mut y;
    let mut r;
    loop {
        if i < 22 {
            y = BigNum::from_word(i);
        } else {
            y = random(p.num_bits()).ok_or(Error::Rand)?;
            if ucmp(&y, p) != Ordering::Less {
                y = if p.is_negative() {
                    add(&y, p)?
                } else {
                    sub(&y, p)?
                };
            }
            if y.is_zero() {
                y = BigNum::from_word(i);
            }
        }
        r = kronecker(&y, &q)?;
        if r == 0 {
            return Err(Error::PIsNotPrime.into());
        }
        i = i.saturating_add(1);
        if !(r == 1 && i < 82) {
            break;
        }
    }
    if r != -1 {
        return Err(Error::TooManyIterations.into());
    }
    q = rshift(&q, e);
    let mut y = exp_mod(&y, &q, p)?;
    if y.is_one() {
        return Err(Error::PIsNotPrime.into());
    }
    let t = rshift(&q, 1);
    let mut x;
    if t.is_zero() {
        // p = 2^e + 1
        if nnmod(&big_a, p)?.is_zero() {
            return Ok(BigNum::zero());
        }
        x = BigNum::one();
    } else {
        x = exp_mod(&big_a, &t, p)?;
        if x.is_zero() {
            return Ok(BigNum::zero());
        }
    }
    let mut b = mod_sqr(&x, p)?;
    b = mod_mul(&b, &big_a, p)?;
    x = mod_mul(&x, &big_a, p)?;
    loop {
        if b.is_one() {
            return verify(x);
        }
        let mut i = 1usize;
        let mut t = BigNum::zero();
        while i < e {
            t = if i == 1 {
                mod_sqr(&b, p)?
            } else {
                mod_mul(&t, &t, p)?
            };
            if t.is_one() {
                break;
            }
            i = i.saturating_add(1);
        }
        if i >= e {
            return Err(Error::NotASquare.into());
        }
        let mut t = y.clone();
        for _ in 0..e.saturating_sub(i).saturating_sub(1) {
            t = mod_sqr(&t, p)?;
        }
        y = mod_mul(&t, &t, p)?;
        x = mod_mul(&x, &t, p)?;
        b = mod_mul(&b, &y, p)?;
        e = i;
    }
}

/// `BN_reciprocal`: `2^len / m`, truncated (signed as `BN_div` signs it).
pub fn reciprocal(m: &BigNum, len: usize) -> Result<BigNum, Error> {
    let mut t = BigNum::zero();
    t.set_bit(len)?;
    Ok(div_rem(&t, m)?.0)
}

/// The NIST primes (`BN_get0_nist_prime_*`), by their definitions in FIPS 186-4: p192 =
/// 2^192 - 2^64 - 1, p224 = 2^224 - 2^96 + 1, p256 = 2^256 - 2^224 + 2^192 + 2^96 - 1,
/// p384 = 2^384 - 2^128 - 2^96 + 2^32 - 1, p521 = 2^521 - 1.
pub fn nist_prime(bits: usize) -> Option<BigNum> {
    let terms: &[(bool, usize)] = match bits {
        192 => &[(true, 192), (false, 64), (false, 0)],
        224 => &[(true, 224), (false, 96), (true, 0)],
        256 => &[
            (true, 256),
            (false, 224),
            (true, 192),
            (true, 96),
            (false, 0),
        ],
        384 => &[
            (true, 384),
            (false, 128),
            (false, 96),
            (true, 32),
            (false, 0),
        ],
        521 => &[(true, 521), (false, 0)],
        _ => return None,
    };
    let mut p = BigNum::zero();
    for &(plus, k) in terms {
        let mut term = BigNum::zero();
        term.set_bit(k).ok()?;
        p = if plus {
            add(&p, &term).ok()?
        } else {
            sub(&p, &term).ok()?
        };
    }
    Some(p)
}

/// Keeps `LIMB_BITS` in use for the windows' arithmetic.
const _: usize = LIMB_BITS;
