//! Constant-time greatest common divisors and modular inverses (`BN_gcd`, `BN_mod_inverse`).
//!
//! Both run on limb strings of a fixed length, chosen from the operands' public lengths, with
//! every step masked rather than branched on, so their time depends only on those lengths. The
//! inverse is the binary algorithm for an odd modulus; an even modulus (whose inverse needs an
//! odd operand) is inverted through the operand's own inverse of the modulus and an exact
//! division done as a product with a 2-adic inverse.

use super::{BigNum, LIMB_BITS, Limb, hi, lo};

/// `a - b` in place over equal lengths, returning the borrow (0 or 1).
fn sub_borrow(a: &mut [Limb], b: &[Limb]) -> Limb {
    let mut borrow: Limb = 0;
    for (x, &y) in a.iter_mut().zip(b) {
        let (d1, b1) = x.overflowing_sub(y);
        let (d2, b2) = d1.overflowing_sub(borrow);
        *x = d2;
        borrow = Limb::from(b1 | b2);
    }
    borrow
}

/// `a mod m` for limbs `a` of any length and a nonzero modulus of `m.len()` limbs (its top
/// limb nonzero): bit by bit from the top, doubling and subtracting `m` under a mask. The time
/// depends on `a.len()` and `m.len()` only. `m.len()` limbs.
pub fn reduce_limbs(a: &[Limb], m: &[Limb]) -> Vec<Limb> {
    let k = m.len();
    // One limb more than the modulus: the remainder doubled fits.
    let mut r = vec![0; k.saturating_add(1)];
    let mut mm = m.to_vec();
    mm.push(0);
    let mut t = vec![0; k.saturating_add(1)];
    for &limb in a.iter().rev() {
        for bit in (0..LIMB_BITS).rev() {
            // r = 2r + bit
            let mut carry = (limb >> bit) & 1;
            for x in r.iter_mut() {
                let top = *x >> (LIMB_BITS - 1);
                *x = (*x << 1) | carry;
                carry = top;
            }
            // r -= m unless that borrows.
            t.copy_from_slice(&r);
            let borrow = sub_borrow(&mut t, &mm);
            let keep = borrow.wrapping_neg();
            for (x, &y) in r.iter_mut().zip(&t) {
                *x = (*x & keep) | (y & !keep);
            }
        }
    }
    r.truncate(k);
    r
}

/// All ones if `c`, else zero.
fn mask(c: Limb) -> Limb {
    c.wrapping_neg()
}

/// `a` padded (or cut) to `len` limbs.
fn padded(a: &BigNum, len: usize) -> Vec<Limb> {
    let mut v = a.limbs().to_vec();
    v.resize(len, 0);
    v
}

/// `a - (b & m)` in place, returning the borrow (0 or 1).
fn sub_masked(a: &mut [Limb], b: &[Limb], m: Limb) -> Limb {
    let mut borrow: Limb = 0;
    for (x, &y) in a.iter_mut().zip(b) {
        let (d1, b1) = x.overflowing_sub(y & m);
        let (d2, b2) = d1.overflowing_sub(borrow);
        *x = d2;
        borrow = Limb::from(b1 || b2);
    }
    borrow
}

/// `a + (b & m)` in place, returning the carry (0 or 1).
fn add_masked(a: &mut [Limb], b: &[Limb], m: Limb) -> Limb {
    let mut carry: Limb = 0;
    for (x, &y) in a.iter_mut().zip(b) {
        let (s1, c1) = x.overflowing_add(y & m);
        let (s2, c2) = s1.overflowing_add(carry);
        *x = s2;
        carry = Limb::from(c1 || c2);
    }
    carry
}

/// All ones if `a < b` (equal lengths), else zero.
fn lt_mask(a: &[Limb], b: &[Limb]) -> Limb {
    let mut borrow: Limb = 0;
    for (&x, &y) in a.iter().zip(b) {
        let (d1, b1) = x.overflowing_sub(y);
        let (_, b2) = d1.overflowing_sub(borrow);
        borrow = Limb::from(b1 || b2);
    }
    mask(borrow)
}

/// Swaps `a` and `b` where `m` is all ones.
fn swap_masked(a: &mut [Limb], b: &mut [Limb], m: Limb) {
    for (x, y) in a.iter_mut().zip(b.iter_mut()) {
        let t = (*x ^ *y) & m;
        *x ^= t;
        *y ^= t;
    }
}

/// `a >> 1`, with `top` shifted into the top bit.
fn shr1(a: &mut [Limb], top: Limb) {
    let mut carry = top & 1;
    for x in a.iter_mut().rev() {
        let next = *x & 1;
        *x = (*x >> 1) | (carry << (LIMB_BITS - 1));
        carry = next;
    }
}

/// `a << 1` where `m` is all ones (the top bit is lost).
fn shl1_masked(a: &mut [Limb], m: Limb) {
    let mut carry: Limb = 0;
    for x in a.iter_mut() {
        let shifted = (*x << 1) | carry;
        carry = *x >> (LIMB_BITS - 1);
        *x = (shifted & m) | (*x & !m);
    }
}

/// `w` limbs of two's complement for `x`.
fn twos(x: &BigNum, w: usize) -> Vec<Limb> {
    let mut v = padded(x, w);
    let neg = mask(Limb::from(x.is_negative()));
    // Negate where negative: invert and add one.
    for l in v.iter_mut() {
        *l ^= neg;
    }
    let mut carry = neg & 1;
    for l in v.iter_mut() {
        let (s, c) = l.overflowing_add(carry);
        *l = s;
        carry = Limb::from(c);
    }
    v
}

/// Negates two's complement `v` where `m` is all ones.
fn negate_masked(v: &mut [Limb], m: Limb) {
    let mut carry = m & 1;
    for l in v.iter_mut() {
        let (s, c) = (*l ^ m).overflowing_add(carry);
        *l = s;
        carry = Limb::from(c);
    }
}

/// Arithmetic `v >> 1` of two's complement `v`.
fn sar1(v: &mut [Limb]) {
    let sign = v.last().map_or(0, |l| l >> (LIMB_BITS - 1));
    shr1(v, sign);
}

/// All ones if `v` is zero.
fn zero_mask(v: &[Limb]) -> Limb {
    let any = v.iter().fold(0, |acc, &l| acc | l);
    mask(((any | any.wrapping_neg()) >> (LIMB_BITS - 1)) ^ 1)
}

/// `BN_gcd`: `gcd(|a|, |b|)` for nonzero `a` and `b` by OpenSSL's constant-time division steps
/// (Bernstein and Yang's), with whether the result object keeps its own `BN_FLG_CONSTTIME`:
/// OpenSSL's swaps move the flag between the result and its two temporaries along with the
/// digits, so the result ends with it exactly when the steps leave the result's own object in
/// place. Constant time for the operands' lengths.
pub fn gcd(a: &BigNum, b: &BigNum) -> (BigNum, bool) {
    crate::dit::with(|| gcd_dit(a, b))
}

/// [`gcd`]'s work.
fn gcd_dit(a: &BigNum, b: &BigNum) -> (BigNum, bool) {
    // r = 2a and g = 2b, then both shifted right past their common low zero bits.
    let (Ok(r2), Ok(g2)) = (super::lshift1(a), super::lshift1(b)) else {
        return (BigNum::zero(), true);
    };
    let words = r2.top().max(g2.top());
    let low_or = |i: usize| -> Limb {
        r2.limbs().get(i).copied().unwrap_or(0) | g2.limbs().get(i).copied().unwrap_or(0)
    };
    let mut shifts: Limb = 0;
    let mut flag: Limb = 1;
    let mut bits: Limb = 0;
    for i in 0..words {
        let w = low_or(i);
        let take = mask(flag);
        flag &= Limb::from(w == 0);
        shifts = shifts.wrapping_add(flag);
        bits = (bits & !take) | (w & take);
    }
    shifts = shifts.wrapping_mul(LIMB_BITS as Limb);
    let mut nb = !bits;
    let mut f: Limb = 1;
    for _ in 0..LIMB_BITS {
        f &= nb;
        shifts = shifts.wrapping_add(f & 1);
        nb >>= 1;
    }
    let s = usize::try_from(shifts).unwrap_or(0);
    let r1 = super::rshift(&r2, s);
    let g1 = super::rshift(&g2, s);
    let top = r1.top().max(g1.top()).saturating_add(1);
    let mut r = twos(&r1, top);
    let mut g = twos(&g1, top);
    let mut temp = vec![0; top];
    // Which objects hold the result's own flag: r's, then wherever the swaps take it.
    let (mut fr, mut fg, mut ft): (Limb, Limb, Limb) = (mask(1), 0, 0);
    // Make r odd.
    let r_even = mask(!r.first().copied().unwrap_or(0) & 1);
    swap_masked(&mut r, &mut g, r_even);
    let t = (fr ^ fg) & r_even;
    fr ^= t;
    fg ^= t;
    let bitlen = |v: &[Limb]| -> usize {
        let mut m = v.to_vec();
        let neg = mask(v.last().map_or(0, |l| l >> (LIMB_BITS - 1)));
        negate_masked(&mut m, neg);
        BigNum::from_limbs(false, m).map_or(0, |n| n.num_bits())
    };
    let steps = bitlen(&r)
        .max(bitlen(&g))
        .saturating_mul(3)
        .saturating_add(4);
    let mut delta: i64 = 1;
    for _ in 0..steps {
        let g_odd = g.first().copied().unwrap_or(0) & 1;
        let g_nonzero = !zero_mask(&g) & 1;
        let positive = Limb::from(delta > 0);
        let cond = mask(positive & g_odd & g_nonzero);
        let c = i64::from(u8::from(cond != 0));
        delta = (delta.wrapping_neg() & c.wrapping_neg()) | (delta & c.wrapping_sub(1));
        // r = -r where cond, then swap r and g.
        negate_masked(&mut r, cond);
        swap_masked(&mut r, &mut g, cond);
        let t = (fr ^ fg) & cond;
        fr ^= t;
        fg ^= t;
        delta = delta.wrapping_add(1);
        // temp = g + r; g = temp where g is odd; g >>= 1.
        temp.copy_from_slice(&g);
        add_masked(&mut temp, &r, mask(1));
        let odd = mask(g.first().copied().unwrap_or(0) & 1 & (!zero_mask(&g) & 1));
        swap_masked(&mut g, &mut temp, odd);
        let t = (fg ^ ft) & odd;
        fg ^= t;
        ft ^= t;
        sar1(&mut g);
    }
    // r is ±gcd * 2^(s-1)... after the shift back: |r| << s >> 1.
    let neg = mask(r.last().map_or(0, |l| l >> (LIMB_BITS - 1)));
    negate_masked(&mut r, neg);
    let out = BigNum::from_limbs(false, r).unwrap_or_default();
    let out = super::lshift(&out, s).map_or_else(|_| BigNum::zero(), |v| super::rshift1(&v));
    let _ = ft;
    (out, fr & 1 == 1)
}

/// The inverse of `x` modulo an odd `m` (`x` in `[0, m)`), or `None` if they aren't coprime.
fn inverse_odd(x: &[Limb], m: &[Limb]) -> Option<Vec<Limb>> {
    let len = m.len();
    let bits = len.saturating_mul(LIMB_BITS);
    let mut a = x.to_vec();
    a.resize(len, 0);
    let mut b = m.to_vec();
    let mut u = vec![0; len];
    if let Some(first) = u.first_mut() {
        *first = 1;
    }
    let mut v = vec![0; len];
    for _ in 0..bits.saturating_mul(2) {
        let odd = mask(a.first().copied().unwrap_or(0) & 1);
        let smaller = lt_mask(&a, &b) & odd;
        swap_masked(&mut a, &mut b, smaller);
        swap_masked(&mut u, &mut v, smaller);
        sub_masked(&mut a, &b, odd);
        // u -= v (mod m) where odd.
        let borrow = sub_masked(&mut u, &v, odd);
        add_masked(&mut u, m, mask(borrow));
        shr1(&mut a, 0);
        // u /= 2 (mod m): add m first if u is odd.
        let u_odd = mask(u.first().copied().unwrap_or(0) & 1);
        let carry = add_masked(&mut u, m, u_odd);
        shr1(&mut u, carry);
    }
    // b is the gcd: one means v is the inverse.
    let one = b.first() == Some(&1) && b.iter().skip(1).all(|&l| l == 0);
    one.then_some(v)
}

/// `x mod d` (bit by bit, constant time for the lengths), for a nonzero `d` of at most `len`
/// limbs.
fn reduce(x: &[Limb], d: &[Limb], len: usize) -> Vec<Limb> {
    let mut r = vec![0; len.saturating_add(1)];
    let mut dd = d.to_vec();
    dd.resize(len.saturating_add(1), 0);
    for i in (0..x.len().saturating_mul(LIMB_BITS)).rev() {
        let bit = x
            .get(i / LIMB_BITS)
            .map_or(0, |l| (l >> (i % LIMB_BITS)) & 1);
        shl1_masked(&mut r, mask(1));
        if let Some(first) = r.first_mut() {
            *first |= bit;
        }
        let ge = !lt_mask(&r, &dd);
        sub_masked(&mut r, &dd, ge);
    }
    r.truncate(len);
    r
}

/// The inverse of `x` modulo `2^(64 len)` for an odd `x` (Newton's iteration).
fn inverse_2adic(x: &[Limb], len: usize) -> Vec<Limb> {
    let x0 = x.first().copied().unwrap_or(1);
    let mut w: Limb = x0;
    for _ in 0..5 {
        w = w.wrapping_mul(2u64.wrapping_sub(x0.wrapping_mul(w)));
    }
    let mut z = vec![0; len];
    if let Some(first) = z.first_mut() {
        *first = w;
    }
    let mut xs = x.to_vec();
    xs.resize(len, 0);
    let mut precision = LIMB_BITS;
    while precision < len.saturating_mul(LIMB_BITS) {
        // z = z * (2 - x z) mod 2^(64 len)
        let xz = mul_low(&xs, &z, len);
        let mut two_minus = vec![0; len];
        if let Some(first) = two_minus.first_mut() {
            *first = 2;
        }
        sub_masked(&mut two_minus, &xz, mask(1));
        z = mul_low(&z, &two_minus, len);
        precision = precision.saturating_mul(2);
    }
    z
}

/// The low `len` limbs of `a * b`.
fn mul_low(a: &[Limb], b: &[Limb], len: usize) -> Vec<Limb> {
    let mut r = vec![0; len];
    for (i, &x) in a.iter().enumerate().take(len) {
        let Some(row) = r.get_mut(i..) else { break };
        let mut carry: Limb = 0;
        for (slot, &y) in row.iter_mut().zip(b) {
            let t = u128::from(x)
                .wrapping_mul(u128::from(y))
                .wrapping_add(u128::from(*slot))
                .wrapping_add(u128::from(carry));
            *slot = lo(t);
            carry = hi(t);
        }
    }
    r
}

/// The inverse of `x` modulo `|m|` for `x` in `[0, |m|)` and `|m| > 1`, or `None` if there's
/// none. Constant time for the lengths, except that an even modulus with an even `x` (which
/// has no inverse) answers at once.
pub fn inverse(x: &BigNum, m: &BigNum) -> Option<BigNum> {
    crate::dit::with(|| inverse_dit(x, m))
}

/// [`inverse`]'s work.
fn inverse_dit(x: &BigNum, m: &BigNum) -> Option<BigNum> {
    let len = m.top();
    let ml = m.limbs();
    if m.is_odd() {
        let v = inverse_odd(&padded(x, len), ml)?;
        return BigNum::from_limbs(false, v).ok();
    }
    if !x.is_odd() {
        return None;
    }
    // One is its own inverse (and the formula below needs x > 1).
    if x.is_one() {
        return Some(BigNum::one());
    }
    // x is odd and below m: y = m^-1 mod x, then x^-1 mod m = m - (m y - 1) / x.
    let xl = padded(x, len);
    let m_mod_x = reduce(ml, &xl, len);
    let y = inverse_odd(&m_mod_x, &xl)?;
    let mut my = mul_low(ml, &y, len.saturating_mul(2));
    let mut one = vec![0; my.len()];
    if let Some(first) = one.first_mut() {
        *first = 1;
    }
    sub_masked(&mut my, &one, mask(1));
    let k = mul_low(&my, &inverse_2adic(&xl, len), len);
    let mut out = ml.to_vec();
    sub_masked(&mut out, &k, mask(1));
    BigNum::from_limbs(false, out).ok()
}
