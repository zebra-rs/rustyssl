//! Arbitrary-precision integers, as OpenSSL's `BIGNUM` holds them (`crypto/bn`): a sign and a
//! magnitude of 64-bit limbs, least significant first. A number is always normalized (no zero
//! limbs at the top, and zero is never negative), as `bn_correct_top` leaves one.
//!
//! The arithmetic is our own, on `u64` limbs with `u128` products. It is variable-time, like
//! OpenSSL's general arithmetic; secret-dependent operations go through constant-time code of
//! their own. Limbs are zeroized when they're dropped.
//!
//! The functions follow OpenSSL's semantics, including its quirks: `uadd`/`usub` work on the
//! magnitudes, division truncates (the remainder takes the dividend's sign), and a result may
//! have at most [`MAX_LIMBS`] limbs, as `bn_expand_internal` allows.

mod conv;
pub mod ct;
mod div;
pub mod gf2m;
pub mod modular;
pub mod mont;
pub mod prime;
pub mod rand;
pub mod rfc_primes;

use core::cmp::Ordering;

use zeroize::Zeroize;

pub use conv::Endian;
pub use zeroize::Zeroizing;

/// A limb: OpenSSL's `BN_ULONG` on every 64-bit target.
pub type Limb = u64;

/// Bits in a limb (`BN_BITS2`).
pub const LIMB_BITS: usize = 64;

/// Octets in a limb (`BN_BYTES`).
pub const LIMB_BYTES: usize = 8;

/// The most limbs a number may have: `bn_expand_internal` refuses more than
/// `INT_MAX / (4 * BN_BITS2)`.
pub const MAX_LIMBS: usize = (core::ffi::c_int::MAX.unsigned_abs() as usize) / (4 * LIMB_BITS);

/// Why an operation failed, as OpenSSL's `BN_R_*` reasons say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// `BN_R_BIGNUM_TOO_LONG`: the result would have more than [`MAX_LIMBS`] limbs.
    TooLong,
    /// `BN_R_DIV_BY_ZERO`.
    DivByZero,
    /// `BN_R_ARG2_LT_ARG3`: `usub` of a shorter number from a longer one.
    Arg2LtArg3,
    /// `BN_R_INVALID_LENGTH`: an MPI shorter than its header, or with the header's top bit set.
    InvalidLength,
    /// `BN_R_ENCODING_ERROR`: an MPI whose header disagrees with its length.
    EncodingError,
    /// `BN_R_INPUT_NOT_REDUCED`: `BN_mod_lshift_quick` of a number longer than the modulus.
    InputNotReduced,
    /// `BN_R_P_IS_NOT_PRIME`: `BN_mod_sqrt` found the modulus composite.
    PIsNotPrime,
    /// `BN_R_NOT_A_SQUARE`: `BN_mod_sqrt` of a non-residue.
    NotASquare,
    /// `BN_R_TOO_MANY_ITERATIONS`: `BN_mod_sqrt` found no non-residue.
    TooManyIterations,
    /// `BN_R_NO_INVERSE`.
    NoInverse,
    /// The random generator failed (and raised its own error).
    Rand,
}

/// A number's limbs, zeroized when dropped or replaced.
#[derive(Default)]
struct Limbs(Vec<Limb>);

impl Clone for Limbs {
    fn clone(&self) -> Self {
        Limbs(self.0.clone())
    }
}

impl Drop for Limbs {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// An integer, normalized.
#[derive(Clone, Default)]
pub struct BigNum {
    neg: bool,
    d: Limbs,
}

impl core::fmt::Debug for BigNum {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl PartialEq for BigNum {
    fn eq(&self, other: &Self) -> bool {
        self.neg == other.neg && self.d.0 == other.d.0
    }
}

impl Eq for BigNum {}

/// The low limb of a double limb.
#[expect(
    clippy::cast_possible_truncation,
    reason = "keeps the low limb on purpose"
)]
const fn lo(x: u128) -> Limb {
    x as Limb
}

/// The high limb of a double limb.
const fn hi(x: u128) -> Limb {
    (x >> 64) as Limb
}

/// Two limbs as a double limb.
const fn join(high: Limb, low: Limb) -> u128 {
    ((high as u128) << 64) | low as u128
}

/// `limbs` without its zero limbs at the top.
fn trimmed(mut limbs: Vec<Limb>) -> Vec<Limb> {
    while limbs.last() == Some(&0) {
        limbs.pop();
    }
    limbs
}

/// `BN_num_bits_word`.
pub const fn num_bits_word(l: Limb) -> usize {
    Limb::BITS.wrapping_sub(l.leading_zeros()) as usize
}

/// `l << s`, 0 once `s` reaches the limb's width.
fn shl(l: Limb, s: usize) -> Limb {
    u32::try_from(s)
        .ok()
        .and_then(|s| l.checked_shl(s))
        .unwrap_or(0)
}

/// `l >> s`, 0 once `s` reaches the limb's width.
fn shr(l: Limb, s: usize) -> Limb {
    u32::try_from(s)
        .ok()
        .and_then(|s| l.checked_shr(s))
        .unwrap_or(0)
}

impl BigNum {
    /// Zero.
    pub fn zero() -> Self {
        Self::default()
    }

    /// The value `w` (`BN_set_word`).
    pub fn from_word(w: Limb) -> Self {
        let mut n = Self::zero();
        if w != 0 {
            n.d.0 = vec![w];
        }
        n
    }

    /// One (`BN_one`).
    pub fn one() -> Self {
        Self::from_word(1)
    }

    /// A number from its sign and limbs (least significant first), normalized; `TooLong` if
    /// it has more than [`MAX_LIMBS`] significant limbs.
    pub fn from_limbs(neg: bool, limbs: Vec<Limb>) -> Result<Self, Error> {
        let d = Limbs(trimmed(limbs));
        if d.0.len() > MAX_LIMBS {
            return Err(Error::TooLong);
        }
        let neg = neg && !d.0.is_empty();
        Ok(Self { neg, d })
    }

    /// The limbs, least significant first (`bn_get_words`); none for zero.
    pub fn limbs(&self) -> &[Limb] {
        &self.d.0
    }

    /// The number of limbs (`top`).
    pub fn top(&self) -> usize {
        self.d.0.len()
    }

    /// `BN_is_negative`.
    pub fn is_negative(&self) -> bool {
        self.neg
    }

    /// `BN_is_zero`.
    pub fn is_zero(&self) -> bool {
        self.d.0.is_empty()
    }

    /// `BN_is_odd`.
    pub fn is_odd(&self) -> bool {
        self.d.0.first().is_some_and(|l| l & 1 == 1)
    }

    /// `BN_abs_is_word`.
    pub fn abs_is_word(&self, w: Limb) -> bool {
        match self.d.0.as_slice() {
            [] => w == 0,
            [l] => *l == w,
            _ => false,
        }
    }

    /// `BN_is_one`.
    pub fn is_one(&self) -> bool {
        self.abs_is_word(1) && !self.neg
    }

    /// `BN_is_word`.
    pub fn is_word(&self, w: Limb) -> bool {
        self.abs_is_word(w) && (w == 0 || !self.neg)
    }

    /// `BN_get_word`: the value if it fits a limb, else all ones (the sign is ignored).
    pub fn get_word(&self) -> Limb {
        match self.d.0.as_slice() {
            [] => 0,
            [l] => *l,
            _ => Limb::MAX,
        }
    }

    /// `BN_num_bits`: the magnitude's length in bits.
    pub fn num_bits(&self) -> usize {
        match self.d.0.last() {
            None => 0,
            Some(&top) => self
                .top()
                .saturating_sub(1)
                .saturating_mul(LIMB_BITS)
                .saturating_add(num_bits_word(top)),
        }
    }

    /// `BN_num_bytes`.
    pub fn num_bytes(&self) -> usize {
        self.num_bits().div_ceil(8)
    }

    /// `BN_set_negative`: negative if `neg` and the number isn't zero.
    pub fn set_negative(&mut self, neg: bool) {
        self.neg = neg && !self.is_zero();
    }

    /// The magnitude (the number made non-negative).
    pub fn abs(&self) -> Self {
        let mut a = self.clone();
        a.neg = false;
        a
    }

    /// `BN_is_bit_set`.
    pub fn is_bit_set(&self, n: usize) -> bool {
        let (i, j) = (n / LIMB_BITS, n % LIMB_BITS);
        self.d.0.get(i).is_some_and(|&l| shr(l, j) & 1 == 1)
    }

    /// `BN_set_bit`: sets bit `n` of the magnitude, growing it if need be.
    pub fn set_bit(&mut self, n: usize) -> Result<(), Error> {
        let (i, j) = (n / LIMB_BITS, n % LIMB_BITS);
        if self.top() <= i {
            if i >= MAX_LIMBS {
                return Err(Error::TooLong);
            }
            let mut d = Vec::with_capacity(i.saturating_add(1));
            d.extend_from_slice(&self.d.0);
            d.resize(i.saturating_add(1), 0);
            self.d = Limbs(d);
        }
        if let Some(l) = self.d.0.get_mut(i) {
            *l |= shl(1, j);
        }
        Ok(())
    }

    /// `BN_clear_bit`: clears bit `n`; `false` if it's beyond the top limb.
    pub fn clear_bit(&mut self, n: usize) -> bool {
        let (i, j) = (n / LIMB_BITS, n % LIMB_BITS);
        let Some(l) = self.d.0.get_mut(i) else {
            return false;
        };
        *l &= !shl(1, j);
        self.normalize();
        true
    }

    /// `BN_mask_bits`: keeps the low `n` bits; `false` (unchanged) if `n` reaches past the top
    /// limb.
    pub fn mask_bits(&mut self, n: usize) -> bool {
        let (w, b) = (n / LIMB_BITS, n % LIMB_BITS);
        if w >= self.top() {
            return false;
        }
        if b == 0 {
            self.d.0.truncate(w);
        } else {
            self.d.0.truncate(w.saturating_add(1));
            if let Some(l) = self.d.0.get_mut(w) {
                *l &= !shl(Limb::MAX, b);
            }
        }
        self.normalize();
        true
    }

    /// Drops zero limbs from the top and the sign from zero (`bn_correct_top`).
    fn normalize(&mut self) {
        while self.d.0.last() == Some(&0) {
            self.d.0.pop();
        }
        if self.d.0.is_empty() {
            self.neg = false;
        }
    }

    /// `BN_add_word`.
    pub fn add_word(&mut self, w: Limb) -> Result<(), Error> {
        if w == 0 {
            return Ok(());
        }
        if self.is_zero() {
            *self = Self::from_word(w);
            return Ok(());
        }
        if self.neg {
            self.neg = false;
            self.sub_word(w)?;
            if !self.is_zero() {
                self.neg = !self.neg;
            }
            return Ok(());
        }
        let r = add_mag(&self.d.0, &[w])?;
        self.d = Limbs(r);
        Ok(())
    }

    /// `BN_sub_word`.
    pub fn sub_word(&mut self, w: Limb) -> Result<(), Error> {
        if w == 0 {
            return Ok(());
        }
        if self.is_zero() {
            *self = Self::from_word(w);
            self.neg = true;
            return Ok(());
        }
        if self.neg {
            self.neg = false;
            self.add_word(w)?;
            self.neg = true;
            return Ok(());
        }
        if let [l] = self.d.0.as_mut_slice()
            && *l < w
        {
            *l = w.wrapping_sub(*l);
            self.neg = true;
            return Ok(());
        }
        let r = sub_mag(&self.d.0, &[w]);
        self.d = Limbs(r);
        self.normalize();
        Ok(())
    }

    /// `BN_mul_word`.
    pub fn mul_word(&mut self, w: Limb) -> Result<(), Error> {
        if self.is_zero() {
            return Ok(());
        }
        if w == 0 {
            *self = Self::zero();
            return Ok(());
        }
        let neg = self.neg;
        let r = mul_mag(&self.d.0, &[w]);
        *self = Self::from_limbs(neg, r)?;
        Ok(())
    }

    /// `BN_div_word`: divides by `w` and returns the remainder (of the magnitude), or all ones
    /// (unchanged) for a zero divisor.
    pub fn div_word(&mut self, w: Limb) -> Limb {
        if w == 0 {
            return Limb::MAX;
        }
        if self.is_zero() {
            return 0;
        }
        let (q, r) = div::div_rem_word(&self.d.0, w);
        self.d = Limbs(trimmed(q));
        self.normalize();
        r
    }

    /// `BN_mod_word`: the magnitude's remainder by `w`, or all ones for a zero divisor.
    pub fn mod_word(&self, w: Limb) -> Limb {
        if w == 0 {
            return Limb::MAX;
        }
        self.d.0.iter().rev().fold(0, |r, &l| {
            lo(join(r, l).checked_rem(u128::from(w)).unwrap_or(0))
        })
    }
}

/// `BN_ucmp`: the magnitudes compared.
pub fn ucmp(a: &BigNum, b: &BigNum) -> Ordering {
    cmp_mag(&a.d.0, &b.d.0)
}

/// `BN_cmp`.
pub fn cmp(a: &BigNum, b: &BigNum) -> Ordering {
    match (a.neg, b.neg) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => ucmp(a, b),
        (true, true) => ucmp(b, a),
    }
}

/// Normalized magnitudes compared.
fn cmp_mag(a: &[Limb], b: &[Limb]) -> Ordering {
    a.len()
        .cmp(&b.len())
        .then_with(|| a.iter().rev().cmp(b.iter().rev()))
}

/// `a + b` on magnitudes, at most one limb longer than the longer one.
fn add_mag(a: &[Limb], b: &[Limb]) -> Result<Vec<Limb>, Error> {
    let (long, short) = if a.len() >= b.len() { (a, b) } else { (b, a) };
    // `BN_uadd` expands to the longer length plus one.
    if long.len() >= MAX_LIMBS {
        return Err(Error::TooLong);
    }
    let mut r = Vec::with_capacity(long.len().saturating_add(1));
    let mut carry = false;
    for (i, &x) in long.iter().enumerate() {
        let y = short.get(i).copied().unwrap_or(0);
        let (s1, c1) = x.overflowing_add(y);
        let (s2, c2) = s1.overflowing_add(Limb::from(carry));
        r.push(s2);
        carry = c1 || c2;
    }
    if carry {
        r.push(1);
    }
    Ok(r)
}

/// `a - b` on magnitudes, wrapping as `bn_sub_words` does if `b` is the larger, at `a`'s length.
fn sub_mag(a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    let mut r = Vec::with_capacity(a.len());
    let mut borrow = false;
    for (i, &x) in a.iter().enumerate() {
        let y = b.get(i).copied().unwrap_or(0);
        let (d1, b1) = x.overflowing_sub(y);
        let (d2, b2) = d1.overflowing_sub(Limb::from(borrow));
        r.push(d2);
        borrow = b1 || b2;
    }
    trimmed(r)
}

/// `a * b` on magnitudes (schoolbook).
fn mul_mag(a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    let mut r = vec![0; a.len().saturating_add(b.len())];
    for (i, &x) in a.iter().enumerate() {
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
        if let Some(slot) = row.get_mut(b.len()) {
            *slot = carry;
        }
    }
    trimmed(r)
}

/// `BN_uadd`: `|a| + |b|`, non-negative.
pub fn uadd(a: &BigNum, b: &BigNum) -> Result<BigNum, Error> {
    BigNum::from_limbs(false, add_mag(&a.d.0, &b.d.0)?)
}

/// `BN_usub`: `|a| - |b|`, non-negative. `Arg2LtArg3` if `b` has more limbs; a larger `b` of
/// the same length wraps, as OpenSSL's does.
pub fn usub(a: &BigNum, b: &BigNum) -> Result<BigNum, Error> {
    if a.top() < b.top() {
        return Err(Error::Arg2LtArg3);
    }
    BigNum::from_limbs(false, sub_mag(&a.d.0, &b.d.0))
}

/// `BN_add`.
pub fn add(a: &BigNum, b: &BigNum) -> Result<BigNum, Error> {
    if a.neg == b.neg {
        let mut r = uadd(a, b)?;
        r.set_negative(a.neg);
        return Ok(r);
    }
    match ucmp(a, b) {
        Ordering::Greater => {
            let mut r = usub(a, b)?;
            r.set_negative(a.neg);
            Ok(r)
        }
        Ordering::Less => {
            let mut r = usub(b, a)?;
            r.set_negative(b.neg);
            Ok(r)
        }
        Ordering::Equal => Ok(BigNum::zero()),
    }
}

/// `BN_sub`.
pub fn sub(a: &BigNum, b: &BigNum) -> Result<BigNum, Error> {
    if a.neg != b.neg {
        let mut r = uadd(a, b)?;
        r.set_negative(a.neg);
        return Ok(r);
    }
    match ucmp(a, b) {
        Ordering::Greater => {
            let mut r = usub(a, b)?;
            r.set_negative(a.neg);
            Ok(r)
        }
        Ordering::Less => {
            let mut r = usub(b, a)?;
            r.set_negative(!b.neg);
            Ok(r)
        }
        Ordering::Equal => Ok(BigNum::zero()),
    }
}

/// `BN_mul`.
pub fn mul(a: &BigNum, b: &BigNum) -> Result<BigNum, Error> {
    if a.is_zero() || b.is_zero() {
        return Ok(BigNum::zero());
    }
    if a.top().saturating_add(b.top()) > MAX_LIMBS {
        return Err(Error::TooLong);
    }
    BigNum::from_limbs(a.neg != b.neg, mul_mag(&a.d.0, &b.d.0))
}

/// `BN_sqr`: `a * a`, non-negative.
pub fn sqr(a: &BigNum) -> Result<BigNum, Error> {
    if a.is_zero() {
        return Ok(BigNum::zero());
    }
    if a.top().saturating_mul(2) > MAX_LIMBS {
        return Err(Error::TooLong);
    }
    BigNum::from_limbs(false, mul_mag(&a.d.0, &a.d.0))
}

/// `BN_div`: the quotient and remainder of `num / d`, truncated toward zero; the remainder
/// takes `num`'s sign.
pub fn div_rem(num: &BigNum, d: &BigNum) -> Result<(BigNum, BigNum), Error> {
    if d.is_zero() {
        return Err(Error::DivByZero);
    }
    if ucmp(num, d) == Ordering::Less {
        return Ok((BigNum::zero(), num.clone()));
    }
    let (q, r) = div::div_rem_mag(&num.d.0, &d.d.0);
    let q = BigNum::from_limbs(num.neg != d.neg, q)?;
    let r = BigNum::from_limbs(num.neg, r)?;
    Ok((q, r))
}

/// `BN_nnmod`: `a mod |m|`, in `[0, |m|)`.
pub fn nnmod(a: &BigNum, m: &BigNum) -> Result<BigNum, Error> {
    let (_, r) = div_rem(a, m)?;
    if !r.neg {
        return Ok(r);
    }
    if m.neg { sub(&r, m) } else { add(&r, m) }
}

/// `BN_exp`: `a` to the power `|p|`, by OpenSSL's left-to-right square and multiply.
pub fn exp(a: &BigNum, p: &BigNum) -> Result<BigNum, Error> {
    let mut v = a.clone();
    let bits = p.num_bits();
    let mut rr = if p.is_odd() { a.clone() } else { BigNum::one() };
    for i in 1..bits {
        v = sqr(&v)?;
        if p.is_bit_set(i) {
            rr = mul(&rr, &v)?;
        }
    }
    Ok(rr)
}

/// `BN_lshift`: `a * 2^n`. Like OpenSSL, it needs room for `a`'s limbs, the shift's, and one
/// more, even for zero.
pub fn lshift(a: &BigNum, n: usize) -> Result<BigNum, Error> {
    let (nw, lb) = (n / LIMB_BITS, n % LIMB_BITS);
    if a.top().saturating_add(nw).saturating_add(1) > MAX_LIMBS {
        return Err(Error::TooLong);
    }
    if a.is_zero() {
        return Ok(BigNum::zero());
    }
    let mut r = Vec::with_capacity(a.top().saturating_add(nw).saturating_add(1));
    r.resize(nw, 0);
    let mut carry: Limb = 0;
    for &l in &a.d.0 {
        r.push(shl(l, lb) | carry);
        carry = shr(l, LIMB_BITS.wrapping_sub(lb));
    }
    r.push(carry);
    BigNum::from_limbs(a.neg, r)
}

/// `BN_lshift1`: `a * 2`.
pub fn lshift1(a: &BigNum) -> Result<BigNum, Error> {
    lshift(a, 1)
}

/// `BN_rshift`: `a / 2^n`, truncated (the magnitude shifted, the sign kept unless zero).
pub fn rshift(a: &BigNum, n: usize) -> BigNum {
    let (nw, rb) = (n / LIMB_BITS, n % LIMB_BITS);
    let Some(rest) = a.d.0.get(nw..).filter(|r| !r.is_empty()) else {
        return BigNum::zero();
    };
    let mut r = Vec::with_capacity(rest.len());
    for (i, &l) in rest.iter().enumerate() {
        let next = rest.get(i.wrapping_add(1)).copied().unwrap_or(0);
        r.push(shr(l, rb) | shl(next, LIMB_BITS.wrapping_sub(rb)));
    }
    let r = Limbs(trimmed(r));
    let neg = a.neg && !r.0.is_empty();
    BigNum { neg, d: r }
}

/// `BN_rshift1`: `a / 2`, truncated.
pub fn rshift1(a: &BigNum) -> BigNum {
    rshift(a, 1)
}

/// `BN_consttime_swap`'s effect on two numbers of at most `nwords` limbs: swapped if `swap`,
/// with every limb of both touched either way.
pub fn consttime_swap(swap: bool, a: &mut BigNum, b: &mut BigNum, nwords: usize) {
    let mask = Limb::from(swap).wrapping_neg();
    let n = nwords.max(a.top()).max(b.top());
    let mut x = core::mem::take(&mut a.d.0);
    let mut y = core::mem::take(&mut b.d.0);
    x.resize(n, 0);
    y.resize(n, 0);
    for (p, q) in x.iter_mut().zip(y.iter_mut()) {
        let t = (*p ^ *q) & mask;
        *p ^= t;
        *q ^= t;
    }
    let t = (a.neg ^ b.neg) & swap;
    a.neg ^= t;
    b.neg ^= t;
    a.d.0 = x;
    b.d.0 = y;
    a.normalize();
    b.normalize();
}

#[cfg(test)]
mod tests;
