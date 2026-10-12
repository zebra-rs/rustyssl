//! Polynomials over GF(2) (`bn_gf2m.c`): a number's bits are a polynomial's coefficients, and
//! a field GF(2^m) is the polynomials modulo an irreducible one, given as a number or as the
//! list of its terms' exponents (highest first, as `BN_GF2m_poly2arr` makes it). Signs are no
//! part of these values; which sign a result gets is the caller's (OpenSSL's rules are odd).

use super::{BigNum, LIMB_BITS, Limb, shl, shr, trimmed};

/// The bits of `a`'s magnitude.
fn bits(a: &BigNum) -> &[Limb] {
    a.limbs()
}

/// A polynomial from limbs.
fn poly(limbs: Vec<Limb>) -> BigNum {
    BigNum::from_limbs(false, limbs).unwrap_or_default()
}

/// `a + b` (exclusive or).
pub fn add(a: &BigNum, b: &BigNum) -> BigNum {
    let (x, y) = (bits(a), bits(b));
    let n = x.len().max(y.len());
    poly(
        (0..n)
            .map(|i| x.get(i).copied().unwrap_or(0) ^ y.get(i).copied().unwrap_or(0))
            .collect(),
    )
}

/// `a` reduced by the polynomial whose terms are `p` (`p[0]` its degree; the list may hold
/// other exponents in any order). Degree 0 reduces everything to zero.
pub fn reduce(a: &BigNum, p: &[usize]) -> BigNum {
    let Some(&deg) = p.first() else {
        return BigNum::zero();
    };
    if deg == 0 {
        return BigNum::zero();
    }
    let mut z = bits(a).to_vec();
    let top_bit = z.len().saturating_mul(LIMB_BITS);
    for i in (deg..top_bit).rev() {
        let (w, b) = (i / LIMB_BITS, i % LIMB_BITS);
        if z.get(w).is_some_and(|l| shr(*l, b) & 1 == 1) {
            let shift = i.wrapping_sub(deg);
            // x^i = x^shift * (p - x^deg): flip each other term's bit, clear this one.
            if let Some(l) = z.get_mut(w) {
                *l ^= shl(1, b);
            }
            for &t in p.iter().skip(1) {
                let j = t.saturating_add(shift);
                if let Some(l) = z.get_mut(j / LIMB_BITS) {
                    *l ^= shl(1, j % LIMB_BITS);
                }
            }
        }
    }
    poly(trimmed(z))
}

/// The carry-less product of two limbs.
fn clmul(a: Limb, b: Limb) -> (Limb, Limb) {
    let (mut lo, mut hi) = (0, 0);
    for i in 0..LIMB_BITS {
        if shr(b, i) & 1 == 1 {
            lo ^= shl(a, i);
            hi ^= if i == 0 {
                0
            } else {
                shr(a, LIMB_BITS.wrapping_sub(i))
            };
        }
    }
    (lo, hi)
}

/// `a * b`, unreduced.
pub fn mul_raw(a: &BigNum, b: &BigNum) -> BigNum {
    let (x, y) = (bits(a), bits(b));
    let mut r = vec![0; x.len().saturating_add(y.len()).saturating_add(1)];
    for (i, &u) in x.iter().enumerate() {
        for (j, &v) in y.iter().enumerate() {
            let (lo, hi) = clmul(u, v);
            let k = i.saturating_add(j);
            if let Some(l) = r.get_mut(k) {
                *l ^= lo;
            }
            if let Some(l) = r.get_mut(k.saturating_add(1)) {
                *l ^= hi;
            }
        }
    }
    poly(trimmed(r))
}

/// `a * b mod p`.
pub fn mul(a: &BigNum, b: &BigNum, p: &[usize]) -> BigNum {
    reduce(&mul_raw(a, b), p)
}

/// `a^2 mod p`.
pub fn sqr(a: &BigNum, p: &[usize]) -> BigNum {
    reduce(&mul_raw(a, a), p)
}

/// `BN_GF2m_mod_inv_vartime`: the inverse of `a` modulo the polynomial `p` (a number), or
/// `None` if `a` reduces to zero or shares a factor with `p`.
pub fn inverse(a: &BigNum, p: &BigNum, terms: &[usize]) -> Option<BigNum> {
    let mut u = reduce(a, terms);
    if u.is_zero() {
        return None;
    }
    let mut v = p.abs();
    let (mut b, mut c) = (BigNum::one(), BigNum::zero());
    loop {
        while !u.is_zero() && !u.is_odd() {
            u = super::rshift1(&u);
            if b.is_odd() {
                b = add(&b, p);
            }
            b = super::rshift1(&b);
        }
        if u.is_zero() {
            return None;
        }
        if u.is_one() {
            return Some(b);
        }
        if u.num_bits() < v.num_bits() {
            core::mem::swap(&mut u, &mut v);
            core::mem::swap(&mut b, &mut c);
        }
        u = add(&u, &v);
        b = add(&b, &c);
    }
}

/// `BN_GF2m_poly2arr`: the exponents of `a`'s terms, highest first, and the count OpenSSL
/// returns (terms plus one), or `None` for an even polynomial or one past `max_bits`.
pub fn poly2arr(a: &BigNum, max_bits: usize) -> Option<(Vec<usize>, usize)> {
    if !a.is_odd() {
        return None;
    }
    let mut terms = Vec::new();
    for i in (0..a.num_bits()).rev() {
        if a.is_bit_set(i) {
            terms.push(i);
        }
    }
    if terms.first().is_some_and(|&d| d > max_bits) {
        return None;
    }
    let n = terms.len().saturating_add(1);
    Some((terms, n))
}
