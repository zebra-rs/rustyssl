//! Constant-time arithmetic modulo a public prime, for the curve-specific methods' ladder.
//!
//! An element is a string of exactly the modulus's number of limbs, in Montgomery form and
//! fully reduced. Products are [`mont::mul_fixed`] then [`Montgomery::redc`]; sums and
//! differences correct with a masked subtraction or addition of the modulus. Nothing branches
//! on, or indexes by, an element's value, and every string has the modulus's length, so the time
//! of each operation depends only on that length. Inversion raises to `p - 2`, whose bits are
//! public.

use crate::bn::mont::{self, Montgomery};
use crate::bn::{BigNum, Limb};

/// A field element: `n` limbs, Montgomery form, below the modulus.
#[derive(Clone, Debug)]
pub struct Fe(Vec<Limb>);

/// A prime field: its Montgomery context and the modulus and `R^2` as `n` limbs.
pub struct Fp {
    mont: Montgomery,
    p: Vec<Limb>,
    rr: Vec<Limb>,
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

impl Fp {
    /// The field of an odd modulus above 2, or `None`.
    pub fn new(p: &BigNum) -> Option<Self> {
        if p.is_negative() || !p.is_odd() || p.num_bits() < 2 {
            return None;
        }
        let mont = Montgomery::new(p).ok()?;
        let n = mont.limbs();
        let pad = |v: &BigNum| {
            let mut l = v.limbs().to_vec();
            l.resize(n, 0);
            l
        };
        let rr = pad(mont.rr());
        let p_minus_2 = crate::bn::sub(p, &BigNum::from_word(2)).ok()?;
        Some(Self {
            p: pad(p),
            rr,
            p_minus_2,
            mont,
        })
    }

    /// The modulus's length in limbs.
    fn n(&self) -> usize {
        self.p.len()
    }

    /// `a * b / R mod p`.
    fn redc_mul(&self, a: &[Limb], b: &[Limb]) -> Vec<Limb> {
        self.mont.redc(&mont::mul_fixed(a, b))
    }

    /// An element of `a`, which must be in `[0, p)`; `None` otherwise.
    pub fn from_bn(&self, a: &BigNum) -> Option<Fe> {
        if a.is_negative() || crate::bn::cmp(a, &self.mont_modulus()).is_ge() {
            return None;
        }
        let mut l = a.limbs().to_vec();
        l.resize(self.n(), 0);
        Some(Fe(self.redc_mul(&l, &self.rr)))
    }

    fn mont_modulus(&self) -> BigNum {
        self.mont.modulus().clone()
    }

    /// The number an element stands for.
    pub fn to_bn(&self, a: &Fe) -> BigNum {
        BigNum::from_limbs(false, self.mont.redc(&a.0)).unwrap_or_default()
    }

    /// Zero.
    pub fn zero(&self) -> Fe {
        Fe(vec![0; self.n()])
    }

    /// One.
    pub fn one(&self) -> Fe {
        let mut l = vec![0; self.n()];
        if let Some(first) = l.first_mut() {
            *first = 1;
        }
        Fe(self.redc_mul(&l, &self.rr))
    }

    /// `a * b`.
    pub fn mul(&self, a: &Fe, b: &Fe) -> Fe {
        Fe(self.redc_mul(&a.0, &b.0))
    }

    /// `a^2`.
    pub fn sqr(&self, a: &Fe) -> Fe {
        self.mul(a, a)
    }

    /// `a + b`.
    pub fn add(&self, a: &Fe, b: &Fe) -> Fe {
        let mut s = a.0.clone();
        let carry = add_in(&mut s, &b.0);
        let mut t = s.clone();
        let borrow = sub_in(&mut t, &self.p);
        // The difference when the sum carried out or didn't go below p.
        select_into(&mut s, &t, mask(carry | (borrow ^ 1)));
        Fe(s)
    }

    /// `a - b`.
    pub fn sub(&self, a: &Fe, b: &Fe) -> Fe {
        let mut d = a.0.clone();
        let borrow = sub_in(&mut d, &b.0);
        let m = mask(borrow);
        let masked: Vec<Limb> = self.p.iter().map(|&x| x & m).collect();
        add_in(&mut d, &masked);
        Fe(d)
    }

    /// `2a`.
    pub fn dbl(&self, a: &Fe) -> Fe {
        self.add(a, a)
    }

    /// `2^k a`.
    pub fn shl(&self, a: &Fe, k: u32) -> Fe {
        (0..k).fold(a.clone(), |x, _| self.dbl(&x))
    }

    /// `a^-1` (zero for zero), by Fermat's little theorem.
    pub fn inv(&self, a: &Fe) -> Fe {
        let e = &self.p_minus_2;
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

    /// Whether `a` is zero (the time doesn't depend on it; what's done with the answer may).
    pub fn is_zero(&self, a: &Fe) -> bool {
        a.0.iter().fold(0, |acc, &x| acc | x) == 0
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
