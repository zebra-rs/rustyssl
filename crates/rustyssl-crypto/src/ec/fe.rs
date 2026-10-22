//! Constant-time arithmetic modulo a public prime, for the curve-specific methods' ladder.
//!
//! An element is the modulus's number of limbs, in Montgomery form and fully reduced, held in a
//! fixed array (fields have at most `OPENSSL_ECC_MAX_FIELD_BITS`, 661 bits), so no operation
//! allocates. Products are Montgomery's interleaved multiplication and reduction
//! ([`Montgomery::mul_into`]); sums and differences correct with a masked subtraction or
//! addition of the modulus. Nothing branches on, or indexes by, an element's value, and every
//! operation works on the modulus's number of limbs, so its time depends only on that length.
//! Inversion raises to `p - 2`, whose bits are public.

use crate::bn::mont::{self, Montgomery};
use crate::bn::{BigNum, Limb};
use std::sync::{Arc, Mutex, PoisonError};

/// How many fields [`cached`] keeps (a few curves' primes and orders).
const CACHED_FIELDS: usize = 16;

/// The field of `p` (as [`Fp::new`]), made once and kept for the process: the named curves'
/// primes and orders are used over and over, and making a field divides to find `R^2`. The
/// moduli are public; the most recently made fields are kept.
pub fn cached(p: &BigNum) -> Option<Arc<Fp>> {
    static FIELDS: Mutex<Vec<Arc<Fp>>> = Mutex::new(Vec::new());
    let same = |f: &Fp| crate::bn::cmp(f.mont.modulus(), p).is_eq();
    {
        let kept = FIELDS.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(f) = kept.iter().find(|f| same(f)) {
            return Some(Arc::clone(f));
        }
    }
    let made = Arc::new(Fp::new(p)?);
    let mut kept = FIELDS.lock().unwrap_or_else(PoisonError::into_inner);
    if kept.len() >= CACHED_FIELDS {
        kept.remove(0);
    }
    kept.push(Arc::clone(&made));
    Some(made)
}

/// The limbs of the largest field: `OPENSSL_ECC_MAX_FIELD_BITS` (661) in 64-bit limbs.
const FE_LIMBS: usize = 11;

/// A field element: Montgomery form, below the modulus, in the first `n` limbs.
#[derive(Clone, Copy, Debug)]
pub struct Fe([Limb; FE_LIMBS]);

/// A prime field: its Montgomery context and the modulus and `R^2` as `n` limbs.
pub struct Fp {
    mont: Montgomery,
    n: usize,
    p: [Limb; FE_LIMBS],
    rr: [Limb; FE_LIMBS],
    /// `p - 2`, the inverse's exponent.
    p_minus_2: BigNum,
}

/// All ones if `c` is 1, zero if 0.
fn mask(c: Limb) -> Limb {
    c.wrapping_neg()
}

/// `a + b` in place, returning the carry (0 or 1).
fn add_in(a: &mut [Limb], b: &[Limb]) -> Limb {
    let mut carry: Limb = 0;
    for (x, &y) in a.iter_mut().zip(b) {
        let (s1, c1) = x.overflowing_add(y);
        let (s2, c2) = s1.overflowing_add(carry);
        *x = s2;
        carry = Limb::from(c1 | c2);
    }
    carry
}

/// `a - b` in place, returning the borrow (0 or 1).
fn sub_in(a: &mut [Limb], b: &[Limb]) -> Limb {
    let mut borrow: Limb = 0;
    for (x, &y) in a.iter_mut().zip(b) {
        let (d1, b1) = x.overflowing_sub(y);
        let (d2, b2) = d1.overflowing_sub(borrow);
        *x = d2;
        borrow = Limb::from(b1 | b2);
    }
    borrow
}

/// `b` where `m` is all ones, else `a`, limb by limb, into `a`.
fn select_into(a: &mut [Limb], b: &[Limb], m: Limb) {
    for (x, &y) in a.iter_mut().zip(b) {
        *x = (*x & !m) | (y & m);
    }
}

/// `v`'s limbs in a fixed array (`None` if it has more than fit).
fn limbs_of(v: &[Limb]) -> Option<[Limb; FE_LIMBS]> {
    let mut out = [0; FE_LIMBS];
    out.get_mut(..v.len())?.copy_from_slice(v);
    Some(out)
}

impl Fp {
    /// The field of an odd modulus above 2, or `None`.
    pub fn new(p: &BigNum) -> Option<Self> {
        if p.is_negative() || !p.is_odd() || p.num_bits() < 2 {
            return None;
        }
        let mont = Montgomery::new(p).ok()?;
        let n = mont.limbs();
        let mut rr = mont.rr().limbs().to_vec();
        rr.resize(n, 0);
        let p_minus_2 = crate::bn::sub(p, &BigNum::from_word(2)).ok()?;
        Some(Self {
            p: limbs_of(p.limbs())?,
            rr: limbs_of(&rr)?,
            n,
            p_minus_2,
            mont,
        })
    }

    /// The modulus's length in limbs.
    fn n(&self) -> usize {
        self.n
    }

    /// The first `n` limbs of `a`.
    fn l<'a>(&self, a: &'a [Limb; FE_LIMBS]) -> &'a [Limb] {
        a.get(..self.n).unwrap_or(&[])
    }

    /// `a * b / R mod p`, for `a` and `b` of `n` limbs: unrolled for the named curves'
    /// lengths (P-256's 4 limbs, P-384's 6, P-521's 9), the generic loop otherwise.
    fn mont_mul(&self, a: &[Limb], b: &[Limb]) -> Fe {
        let mut out = [0; FE_LIMBS];
        let done = match self.n {
            4 => self.mul_fixed::<4>(&mut out, a, b),
            6 => self.mul_fixed::<6>(&mut out, a, b),
            9 => self.mul_fixed::<9>(&mut out, a, b),
            _ => false,
        };
        if !done {
            let mut t = [0; 2 * FE_LIMBS + 2];
            if let (Some(o), Some(t)) = (
                out.get_mut(..self.n),
                t.get_mut(..self.n.saturating_mul(2).saturating_add(2)),
            ) {
                self.mont.mul_into(o, a, b, t);
            }
        }
        Fe(out)
    }

    /// [`mont::mul_n`] for `N` limbs into `out`: false if the lengths aren't `N`.
    fn mul_fixed<const N: usize>(
        &self,
        out: &mut [Limb; FE_LIMBS],
        a: &[Limb],
        b: &[Limb],
    ) -> bool {
        let (Ok(a), Ok(b), Ok(p)) = (
            <&[Limb; N]>::try_from(a),
            <&[Limb; N]>::try_from(b),
            <&[Limb; N]>::try_from(self.l(&self.p)),
        ) else {
            return false;
        };
        let Some(o) = out
            .get_mut(..N)
            .and_then(|o| <&mut [Limb; N]>::try_from(o).ok())
        else {
            return false;
        };
        mont::mul_n(o, a, b, p, self.mont.n0());
        true
    }

    /// An element of the `n` limbs `l` (any value below `R`): `l * R^2 / R`, reduced.
    fn element(&self, l: &[Limb]) -> Option<Fe> {
        let mut a = [0; FE_LIMBS];
        a.get_mut(..l.len().min(self.n))?
            .copy_from_slice(l.get(..l.len().min(self.n))?);
        Some(self.mont_mul(self.l(&a), self.l(&self.rr)))
    }

    /// An element of `a`, which must be in `[0, p)`; `None` otherwise.
    pub fn from_bn(&self, a: &BigNum) -> Option<Fe> {
        if a.is_negative() || crate::bn::cmp(a, self.mont.modulus()).is_ge() {
            return None;
        }
        self.element(a.limbs())
    }

    /// An element of a non-negative `a` of at most the modulus's limbs, reduced: `a * R^2 / R`,
    /// which Montgomery reduction brings below the modulus for any `a` below `R`. `None` for a
    /// negative or longer `a`.
    pub fn from_bn_unreduced(&self, a: &BigNum) -> Option<Fe> {
        if a.is_negative() || a.top() > self.n() {
            return None;
        }
        self.element(a.limbs())
    }

    /// The number an element stands for.
    pub fn to_bn(&self, a: &Fe) -> BigNum {
        BigNum::from_limbs(false, self.mont.redc(self.l(&a.0))).unwrap_or_default()
    }

    /// Zero.
    pub fn zero(&self) -> Fe {
        Fe([0; FE_LIMBS])
    }

    /// One.
    pub fn one(&self) -> Fe {
        self.element(&[1]).unwrap_or_else(|| self.zero())
    }

    /// `a * b`.
    pub fn mul(&self, a: &Fe, b: &Fe) -> Fe {
        self.mont_mul(self.l(&a.0), self.l(&b.0))
    }

    /// `a^2`.
    pub fn sqr(&self, a: &Fe) -> Fe {
        self.mul(a, a)
    }

    /// `a + b`.
    pub fn add(&self, a: &Fe, b: &Fe) -> Fe {
        let n = self.n;
        let mut s = a.0;
        let mut t = [0; FE_LIMBS];
        if let (Some(sl), Some(tl)) = (s.get_mut(..n), t.get_mut(..n)) {
            let carry = add_in(sl, self.l(&b.0));
            tl.copy_from_slice(sl);
            let borrow = sub_in(tl, self.l(&self.p));
            // The difference when the sum carried out or didn't go below p.
            select_into(sl, tl, mask(carry | (borrow ^ 1)));
        }
        Fe(s)
    }

    /// `a - b`.
    pub fn sub(&self, a: &Fe, b: &Fe) -> Fe {
        let n = self.n;
        let mut d = a.0;
        if let Some(dl) = d.get_mut(..n) {
            let borrow = sub_in(dl, self.l(&b.0));
            let m = mask(borrow);
            let mut masked = [0; FE_LIMBS];
            for (x, &y) in masked.iter_mut().zip(self.l(&self.p)) {
                *x = y & m;
            }
            add_in(dl, masked.get(..n).unwrap_or(&[]));
        }
        Fe(d)
    }

    /// `2a`.
    pub fn dbl(&self, a: &Fe) -> Fe {
        self.add(a, a)
    }

    /// `2^k a`.
    pub fn shl(&self, a: &Fe, k: u32) -> Fe {
        (0..k).fold(*a, |x, _| self.dbl(&x))
    }

    /// `a^-1` (zero for zero), by Fermat's little theorem.
    pub fn inv(&self, a: &Fe) -> Fe {
        self.pow(a, &self.p_minus_2)
    }

    /// Whether `a` is zero (the time doesn't depend on it; what's done with the answer may).
    pub fn is_zero(&self, a: &Fe) -> bool {
        self.l(&a.0).iter().fold(0, |acc, &x| acc | x) == 0
    }

    /// An element of the little-endian octets `b`, of at most the modulus's limbs' octets,
    /// reduced (as [`Fp::from_bn_unreduced`]), in time that depends only on `b`'s length.
    /// `None` for a longer `b`.
    pub fn from_le_bytes(&self, b: &[u8]) -> Option<Fe> {
        if b.len() > self.n().saturating_mul(8) {
            return None;
        }
        let mut l = [0; FE_LIMBS];
        for (limb, chunk) in l.iter_mut().zip(b.chunks(8)) {
            let mut w = [0u8; 8];
            w.get_mut(..chunk.len())?.copy_from_slice(chunk);
            *limb = Limb::from_le_bytes(w);
        }
        self.element(self.l(&l))
    }

    /// The number an element stands for, as `len` little-endian octets (cut to `len`), in time
    /// that depends only on `len`.
    pub fn to_le_bytes(&self, a: &Fe, len: usize) -> Vec<u8> {
        let mut out: Vec<u8> = self
            .mont
            .redc(self.l(&a.0))
            .iter()
            .flat_map(|l| l.to_le_bytes())
            .collect();
        out.resize(len, 0);
        out
    }

    /// Whether `a` and `b` are equal (the time doesn't depend on them).
    pub fn eq(&self, a: &Fe, b: &Fe) -> bool {
        self.l(&a.0)
            .iter()
            .zip(self.l(&b.0))
            .fold(0, |acc, (&x, &y)| acc | (x ^ y))
            == 0
    }

    /// Whether the number an element stands for is odd.
    pub fn is_odd(&self, a: &Fe) -> bool {
        self.mont
            .redc(self.l(&a.0))
            .first()
            .is_some_and(|&l| l & 1 == 1)
    }

    /// `-a`.
    pub fn neg(&self, a: &Fe) -> Fe {
        self.sub(&self.zero(), a)
    }

    /// `a^e` for a public exponent `e`.
    pub fn pow(&self, a: &Fe, e: &BigNum) -> Fe {
        let mut r = self.one();
        for i in (0..e.num_bits()).rev() {
            r = self.sqr(&r);
            // The exponent is public.
            if e.is_bit_set(i) {
                r = self.mul(&r, a);
            }
        }
        r
    }

    /// `src` into `dst` where `m` is all ones (zero: `dst` as it was), in constant time.
    pub fn cmov(m: Limb, dst: &mut Fe, src: &Fe) {
        let m = core::hint::black_box(m);
        for (d, &s) in dst.0.iter_mut().zip(src.0.iter()) {
            *d = (*d & !m) | (s & m);
        }
    }

    /// Swaps `a` and `b` when `c`, in constant time.
    pub fn cswap(c: bool, a: &mut Fe, b: &mut Fe) {
        let m = mask(Limb::from(c));
        for (x, y) in a.0.iter_mut().zip(b.0.iter_mut()) {
            let t = (*x ^ *y) & m;
            *x ^= t;
            *y ^= t;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn;

    fn num(hex: &str) -> BigNum {
        BigNum::from_hex_digits(hex.as_bytes()).unwrap_or_default()
    }

    /// Every operation agrees with BIGNUM's modular arithmetic, near the modulus too.
    #[test]
    fn agrees_with_bignum() {
        for p in [
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            "DB7C2ABF62E35E668076BEAD208B",
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        ] {
            let pb = num(p);
            let f = Fp::new(&pb).unwrap_or_else(|| panic!("a field"));
            let pm1 = bn::sub(&pb, &BigNum::one()).unwrap_or_default();
            let vals = [
                BigNum::zero(),
                BigNum::one(),
                BigNum::from_word(2),
                pm1.clone(),
                bn::sub(&pm1, &BigNum::from_word(5)).unwrap_or_default(),
                num("123456789ABCDEF0FEDCBA9876543210"),
            ]
            .map(|v| bn::nnmod(&v, &pb).unwrap_or_default());
            for a in &vals {
                for b in &vals {
                    let (fa, fb) = (
                        f.from_bn(a).unwrap_or_else(|| f.zero()),
                        f.from_bn(b).unwrap_or_else(|| f.zero()),
                    );
                    let m = |x: Result<BigNum, bn::Error>| {
                        bn::nnmod(&x.unwrap_or_default(), &pb).unwrap_or_default()
                    };
                    assert!(bn::cmp(&f.to_bn(&f.mul(&fa, &fb)), &m(bn::mul(a, b))).is_eq());
                    assert!(bn::cmp(&f.to_bn(&f.add(&fa, &fb)), &m(bn::add(a, b))).is_eq());
                    assert!(bn::cmp(&f.to_bn(&f.sub(&fa, &fb)), &m(bn::sub(a, b))).is_eq());
                }
                let fa = f.from_bn(a).unwrap_or_else(|| f.zero());
                if !a.is_zero() {
                    let prod = f.mul(&fa, &f.inv(&fa));
                    assert!(
                        bn::cmp(&f.to_bn(&prod), &BigNum::one()).is_eq(),
                        "p={} a={} got {}",
                        pb.to_hex(),
                        a.to_hex(),
                        f.to_bn(&prod).to_hex()
                    );
                }
            }
            assert!(f.from_bn(&pb).is_none());
        }
    }
}
