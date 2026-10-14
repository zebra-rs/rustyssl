//! Constant-time helpers: masks over octets and limbs, and arithmetic on limb strings of
//! fixed, public lengths (every operation's time depends on those lengths only).

use crate::bn::{BigNum, LIMB_BITS, Limb};

/// All ones if `c` is 1, zero if 0.
pub(super) fn mask_u8(c: u8) -> u8 {
    c.wrapping_neg()
}

/// 1 if `a == b`, else 0.
pub(super) fn eq_u8(a: u8, b: u8) -> u8 {
    let d = u32::from(a ^ b);
    u8::try_from(d.wrapping_sub(1) >> 31).unwrap_or(0)
}

/// 1 if `a == b`, else 0.
pub(super) fn eq_usize(a: usize, b: usize) -> usize {
    let d = a ^ b;
    (!d & d.wrapping_sub(1)) >> (usize::BITS - 1)
}

/// 1 if `a < b`, else 0.
pub(super) fn lt_usize(a: usize, b: usize) -> usize {
    (a ^ ((a ^ b) | (a.wrapping_sub(b) ^ b))) >> (usize::BITS - 1)
}

/// 1 if `a >= b`, else 0.
pub(super) fn ge_usize(a: usize, b: usize) -> usize {
    1 ^ lt_usize(a, b)
}

/// All ones if `c` is 1, zero if 0.
pub(super) fn mask_usize(c: usize) -> usize {
    c.wrapping_neg()
}

/// `c ? a : b` for a 0/1 `c`.
pub(super) fn select_usize(c: usize, a: usize, b: usize) -> usize {
    let m = mask_usize(c);
    (a & m) | (b & !m)
}

/// `c ? a : b` for a 0/1 `c`.
pub(super) fn select_u8(c: u8, a: u8, b: u8) -> u8 {
    let m = mask_u8(c);
    (a & m) | (b & !m)
}

/// A 0/1 value as an octet.
pub(super) fn bit_u8(c: usize) -> u8 {
    u8::try_from(c & 1).unwrap_or(0)
}

/// `a`'s magnitude as exactly `len` limbs (cut or zero-padded).
pub(super) fn fixed(a: &BigNum, len: usize) -> Vec<Limb> {
    let mut v = a.limbs().to_vec();
    v.resize(len, 0);
    v
}

/// `a - b` in place over equal lengths, returning the borrow (0 or 1).
fn sub_in_place(a: &mut [Limb], b: &[Limb]) -> Limb {
    let mut borrow: Limb = 0;
    for (x, &y) in a.iter_mut().zip(b) {
        let (d1, b1) = x.overflowing_sub(y);
        let (d2, b2) = d1.overflowing_sub(borrow);
        *x = d2;
        borrow = Limb::from(b1 | b2);
    }
    borrow
}

/// `a + (b & m)` in place over equal lengths, returning the carry.
fn add_masked(a: &mut [Limb], b: &[Limb], m: Limb) -> Limb {
    let mut carry: Limb = 0;
    for (x, &y) in a.iter_mut().zip(b) {
        let (s1, c1) = x.overflowing_add(y & m);
        let (s2, c2) = s1.overflowing_add(carry);
        *x = s2;
        carry = Limb::from(c1 | c2);
    }
    carry
}

pub(super) use crate::bn::ct::reduce_limbs as reduce;

/// `(a - b) mod m` for `a` and `b` already below `m` (`m.len()` limbs each).
pub(super) fn sub_mod(a: &[Limb], b: &[Limb], m: &[Limb]) -> Vec<Limb> {
    let mut r = a.to_vec();
    let borrow = sub_in_place(&mut r, b);
    add_masked(&mut r, m, borrow.wrapping_neg());
    r
}

/// `a + b` over fixed lengths: `max(a.len(), b.len()) + 1` limbs.
pub(super) fn add(a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    let len = a.len().max(b.len()).saturating_add(1);
    let mut r = a.to_vec();
    r.resize(len, 0);
    let mut bb = b.to_vec();
    bb.resize(len, 0);
    add_masked(&mut r, &bb, Limb::MAX);
    r
}

/// Whether `a` equals `b` (equal lengths), as all ones or zero.
pub(super) fn eq_limbs(a: &[Limb], b: &[Limb]) -> Limb {
    let mut d: Limb = 0;
    for (&x, &y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    // Zero when equal: all ones; else zero.
    ((d | d.wrapping_neg()) >> (LIMB_BITS - 1)).wrapping_sub(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks() {
        assert_eq!((eq_u8(3, 3), eq_u8(3, 4), eq_u8(0, 255)), (1, 0, 0));
        assert_eq!((eq_usize(7, 7), eq_usize(7, 8)), (1, 0));
        assert_eq!(
            (lt_usize(1, 2), lt_usize(2, 2), lt_usize(usize::MAX, 0)),
            (1, 0, 0)
        );
        assert_eq!((ge_usize(2, 2), ge_usize(1, 2)), (1, 0));
        assert_eq!((select_usize(1, 5, 9), select_usize(0, 5, 9)), (5, 9));
        assert_eq!((select_u8(1, 5, 9), select_u8(0, 5, 9)), (5, 9));
    }

    #[test]
    fn reduction() {
        let m = [0xffff_ffff_ffff_ffc5, 0x7];
        let a = [3u64, 0x1234, 0x9999, 0];
        let want = {
            let a = BigNum::from_limbs(false, a.to_vec()).unwrap();
            let m = BigNum::from_limbs(false, m.to_vec()).unwrap();
            crate::bn::nnmod(&a, &m).unwrap()
        };
        assert_eq!(reduce(&a, &m), fixed(&want, 2));
        assert_eq!(sub_mod(&[1, 0], &[2, 0], &m), [0xffff_ffff_ffff_ffc4, 7]);
        assert_eq!(add(&[Limb::MAX], &[1]), [0, 1]);
        assert_eq!(
            (eq_limbs(&[1, 2], &[1, 2]), eq_limbs(&[1, 2], &[1, 3])),
            (Limb::MAX, 0)
        );
    }
}
