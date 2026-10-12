//! Montgomery arithmetic (`bn_mont.c`) and constant-time modular exponentiation
//! (`BN_mod_exp_mont_consttime`).
//!
//! [`Montgomery`] holds a modulus `N` of `nl` limbs, `n0 = -N^-1 mod 2^64`, and `RR = R^2 mod N`
//! for `R = 2^(64 nl)`. [`Montgomery::redc`] is OpenSSL's word-by-word reduction
//! (`bn_from_montgomery_word`): it takes any value of up to `2 nl` limbs (more are cut off, as
//! OpenSSL's are) and subtracts `N` at most once, so an input that isn't reduced gives a result
//! that may not be either, exactly as OpenSSL's does. It runs in time that depends only on
//! `nl`.
//!
//! [`Montgomery::exp_consttime`] raises a base to a power with a fixed window, reading the
//! whole table for every window and multiplying whatever the exponent's bits are, so its time
//! depends only on the modulus's and the exponent's lengths in limbs.

use super::{BigNum, Error, LIMB_BITS, Limb, hi, lo};

/// A Montgomery context: the modulus, `n0`, and `RR`.
#[derive(Clone, Default)]
pub struct Montgomery {
    n: BigNum,
    n0: Limb,
    rr: BigNum,
    /// `RR`'s length in limbs as OpenSSL keeps it: padded to the modulus's.
    rr_top: usize,
}

/// All ones if `c`, else zero.
fn mask(c: bool) -> Limb {
    Limb::from(c).wrapping_neg()
}

/// All ones if `a == b`, else zero, without a branch on either.
fn eq_mask(a: usize, b: usize) -> Limb {
    let d = u64::try_from(a ^ b).unwrap_or(1);
    ((d | d.wrapping_neg()) >> 63).wrapping_sub(1)
}

/// `a - b` over equal lengths into `out`, returning the borrow.
fn sub_into(out: &mut [Limb], a: &[Limb], b: &[Limb]) -> bool {
    let mut borrow = false;
    for ((o, &x), &y) in out.iter_mut().zip(a).zip(b) {
        let (d1, b1) = x.overflowing_sub(y);
        let (d2, b2) = d1.overflowing_sub(Limb::from(borrow));
        *o = d2;
        borrow = b1 || b2;
    }
    borrow
}

/// `n0 = -n^-1 mod 2^64` for an odd `n` (Newton's iteration, five steps from three bits).
fn neg_inverse(n: Limb) -> Limb {
    let mut x: Limb = n; // correct to 3 bits for odd n
    for _ in 0..5 {
        x = x.wrapping_mul(2u64.wrapping_sub(n.wrapping_mul(x)));
    }
    x.wrapping_neg()
}

impl Montgomery {
    /// `BN_MONT_CTX_set` for a nonzero modulus (its magnitude is used): `NoInverse` if it's
    /// even, as OpenSSL's inversion of `2^64` modulo its low word fails.
    pub fn new(modulus: &BigNum) -> Result<Self, MontError> {
        if modulus.is_zero() {
            return Err(MontError::Zero);
        }
        let n = modulus.abs();
        let low = n.limbs().first().copied().unwrap_or(0);
        if low & 1 == 0 {
            return Err(MontError::NoInverse);
        }
        let nl = n.top();
        let mut r2 = BigNum::zero();
        r2.set_bit(nl.saturating_mul(2).saturating_mul(LIMB_BITS))
            .map_err(MontError::Bn)?;
        let (_, rr) = super::div_rem(&r2, &n).map_err(MontError::Bn)?;
        let rr_top = n.top();
        Ok(Self {
            n0: neg_inverse(low),
            n,
            rr,
            rr_top,
        })
    }

    /// The modulus (non-negative).
    pub fn modulus(&self) -> &BigNum {
        &self.n
    }

    /// `RR = R^2 mod N`.
    pub fn rr(&self) -> &BigNum {
        &self.rr
    }

    /// The modulus's length in limbs (`nl`), 0 for an unset context.
    pub fn limbs(&self) -> usize {
        self.n.top()
    }

    /// OpenSSL's `bn_from_montgomery_word` on the magnitude `t` (cut to `2 nl` limbs): `t / R mod
    /// N`, with `N` subtracted at most once. `nl` limbs, not normalized.
    pub fn redc(&self, t: &[Limb]) -> Vec<Limb> {
        let np = self.n.limbs();
        let nl = np.len();
        if nl == 0 {
            return Vec::new();
        }
        let max = nl.saturating_mul(2);
        let mut rp = vec![0; max];
        for (r, &x) in rp.iter_mut().zip(t) {
            *r = x;
        }
        let mut carry = false;
        for i in 0..nl {
            let Some(window) = rp.get_mut(i..) else { break };
            let m = window.first().copied().unwrap_or(0).wrapping_mul(self.n0);
            // window[..nl] += m * np, carry out in `c`.
            let mut c: Limb = 0;
            for (w, &d) in window.iter_mut().zip(np) {
                let t = u128::from(m)
                    .wrapping_mul(u128::from(d))
                    .wrapping_add(u128::from(*w))
                    .wrapping_add(u128::from(c));
                *w = lo(t);
                c = hi(t);
            }
            if let Some(top) = window.get_mut(nl) {
                let v = c.wrapping_add(Limb::from(carry)).wrapping_add(*top);
                // OpenSSL's carry: set if the sum wrapped.
                carry = (carry || v != *top) && v <= *top;
                *top = v;
            }
        }
        let ap = rp.get(nl..).unwrap_or(&[]);
        let mut out = vec![0; nl];
        let borrow = sub_into(&mut out, ap, np);
        // OpenSSL's `carry - borrow` as a mask: keep `ap` when it's all ones (no carry, a
        // borrow), take the difference when 0, and mix the two (as OpenSSL does, though no
        // input can reach it) when 1.
        let sel = Limb::from(carry).wrapping_sub(Limb::from(borrow));
        for (o, &a) in out.iter_mut().zip(ap) {
            *o = (sel & a) | (!sel & *o);
        }
        out
    }

    /// `bn_mul_mont_fixed_top`'s value: `a * b / R mod N` (signs multiplied), or `None` when
    /// the operands have more than `2 nl` limbs between them (OpenSSL fails then, raising
    /// nothing).
    pub fn mul(&self, a: &BigNum, b: &BigNum) -> Option<BigNum> {
        let nl = self.limbs();
        if a.top().saturating_add(b.top()) > nl.saturating_mul(2) {
            return None;
        }
        let t = super::mul_mag(a.limbs(), b.limbs());
        let neg = a.is_negative() != b.is_negative();
        BigNum::from_limbs(neg, self.redc(&t)).ok()
    }

    /// `BN_to_montgomery`: `a * RR / R`, or `None` when `a` is longer than the modulus.
    pub fn to_mont(&self, a: &BigNum) -> Option<BigNum> {
        if a.top().saturating_add(self.rr_top) > self.limbs().saturating_mul(2) {
            return None;
        }
        let t = super::mul_mag(a.limbs(), self.rr.limbs());
        BigNum::from_limbs(a.is_negative(), self.redc(&t)).ok()
    }

    /// `BN_from_montgomery`: `a / R mod N` (`a` cut to `2 nl` limbs).
    pub fn from_mont(&self, a: &BigNum) -> BigNum {
        BigNum::from_limbs(a.is_negative(), self.redc(a.limbs())).unwrap_or_default()
    }

    /// `base^exp mod N` in constant time (for a given modulus length and exponent length in
    /// limbs), for a non-negative `base` below `R`. The modulus must be set.
    pub fn exp_consttime(&self, base: &BigNum, exp: &[Limb]) -> BigNum {
        let nl = self.limbs();
        let np = self.n.limbs();
        // One limb more than the modulus for the product's top, as REDC's input is 2 nl.
        let ct_mul = |x: &[Limb], y: &[Limb]| -> Vec<Limb> {
            let t = mul_fixed(x, y);
            self.redc(&t)
        };
        let pad = |v: &BigNum| -> Vec<Limb> {
            let mut l = v.limbs().to_vec();
            l.resize(nl, 0);
            l
        };
        // The base in Montgomery form, and one.
        let b = self.redc(&mul_fixed(&pad(base), &pad(&self.rr)));
        let one = self.redc(&pad(&self.rr));
        let bits = exp.len().saturating_mul(LIMB_BITS);
        let window = window_ct(bits);
        let size = 1usize << window;
        let mut table: Vec<Vec<Limb>> = Vec::with_capacity(size);
        table.push(one.clone());
        table.push(b.clone());
        for i in 2..size {
            let prev = table.get(i.wrapping_sub(1)).cloned().unwrap_or_default();
            table.push(ct_mul(&prev, &b));
        }
        let mut acc = one;
        let mut pos = bits;
        // The windows from the top; the first may be shorter.
        let first = bits.checked_rem(window).unwrap_or(0);
        let mut step = if first == 0 { window } else { first };
        while pos > 0 {
            for _ in 0..step {
                acc = ct_mul(&acc, &acc);
            }
            pos = pos.saturating_sub(step);
            let w = bits_at(exp, pos, step);
            let mut entry = vec![0; nl];
            for (i, t) in table.iter().enumerate() {
                let m = eq_mask(i, w);
                for (e, &x) in entry.iter_mut().zip(t) {
                    *e |= x & m;
                }
            }
            acc = ct_mul(&acc, &entry);
            step = window;
        }
        let out = self.redc(&acc);
        // A final subtraction makes the result fully reduced, as OpenSSL's is.
        let mut reduced = vec![0; nl];
        let borrow = sub_into(&mut reduced, &out, np);
        let keep = mask(borrow);
        for (r, &o) in reduced.iter_mut().zip(&out) {
            *r = (keep & o) | (!keep & *r);
        }
        BigNum::from_limbs(false, reduced).unwrap_or_default()
    }
}

/// `BN_window_bits_for_ctime_exponent_size`.
fn window_ct(bits: usize) -> usize {
    match bits {
        938.. => 6,
        307.. => 5,
        90.. => 4,
        23.. => 3,
        _ => 1,
    }
}

/// `n` bits of `e` from bit `pos`, as a number.
fn bits_at(e: &[Limb], pos: usize, n: usize) -> usize {
    let mut v = 0usize;
    for k in (0..n).rev() {
        let i = pos.saturating_add(k);
        let bit = e
            .get(i / LIMB_BITS)
            .map_or(0, |l| super::shr(*l, i % LIMB_BITS) & 1);
        v = v.wrapping_shl(1) | usize::try_from(bit).unwrap_or(0);
    }
    v
}

/// The full product of two limb strings (no trimming, so lengths stay public).
fn mul_fixed(a: &[Limb], b: &[Limb]) -> Vec<Limb> {
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
    r
}

/// Why a Montgomery context couldn't be set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MontError {
    /// A zero modulus: `BN_MONT_CTX_set` fails without an error.
    Zero,
    /// An even modulus: `BN_R_NO_INVERSE`.
    NoInverse,
    /// A failure of the arithmetic.
    Bn(Error),
}
