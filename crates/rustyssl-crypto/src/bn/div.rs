//! Division of magnitudes (`BN_div`, `BN_div_word`): Knuth's algorithm D on limbs, with
//! `u128` estimates.

use super::{LIMB_BITS, Limb, hi, join, lo, shl, shr, trimmed};

/// `u / w` and the remainder, for a nonzero `w`; the quotient has `u`'s length.
pub(super) fn div_rem_word(u: &[Limb], w: Limb) -> (Vec<Limb>, Limb) {
    let mut q = vec![0; u.len()];
    let mut r: Limb = 0;
    let w = u128::from(w);
    for (qi, &ui) in q.iter_mut().zip(u).rev() {
        let n = join(r, ui);
        *qi = lo(n.checked_div(w).unwrap_or(0));
        r = lo(n.checked_rem(w).unwrap_or(0));
    }
    (q, r)
}

/// `a << s` for `s` below a limb's width, with one more limb on top if `extra`.
fn shift_left(a: &[Limb], s: usize, extra: bool) -> Vec<Limb> {
    let back = LIMB_BITS.wrapping_sub(s);
    let mut r = Vec::with_capacity(a.len().saturating_add(1));
    let mut below: Limb = 0;
    for &l in a {
        r.push(shl(l, s) | shr(below, back));
        below = l;
    }
    if extra {
        r.push(shr(below, back));
    }
    r
}

/// The limb at `i`, or 0 past the end.
fn at(a: &[Limb], i: usize) -> Limb {
    a.get(i).copied().unwrap_or(0)
}

/// The quotient and remainder of magnitudes `u / v`, for a normalized, nonzero `v` no longer
/// than `u`.
pub(super) fn div_rem_mag(u: &[Limb], v: &[Limb]) -> (Vec<Limb>, Vec<Limb>) {
    let n = v.len();
    if let [w] = v {
        let (q, r) = div_rem_word(u, *w);
        return (trimmed(q), trimmed(vec![r]));
    }
    let s = v.last().map_or(0, |l| l.leading_zeros() as usize);
    let vn = shift_left(v, s, false);
    let mut un = shift_left(u, s, true);
    let m = u.len().saturating_sub(n);
    let mut q = vec![0; m.saturating_add(1)];
    let vtop = u128::from(at(&vn, n.wrapping_sub(1)));
    let vnext = u128::from(at(&vn, n.wrapping_sub(2)));
    let base = u128::from(Limb::MAX).wrapping_add(1);
    for j in (0..=m).rev() {
        let Some(win) = un.get_mut(j..=j.wrapping_add(n)) else {
            break;
        };
        // Estimate the quotient limb from the top two limbs, then correct it at most twice.
        let num = join(at(win, n), at(win, n.wrapping_sub(1)));
        let mut qhat = num.checked_div(vtop).unwrap_or(0);
        let mut rhat = num.checked_rem(vtop).unwrap_or(0);
        while qhat >= base || qhat.wrapping_mul(vnext) > join(lo(rhat), at(win, n.wrapping_sub(2)))
        {
            qhat = qhat.wrapping_sub(1);
            rhat = rhat.wrapping_add(vtop);
            if rhat >= base {
                break;
            }
        }
        // Subtract `qhat * vn` from the window.
        let mut carry: Limb = 0;
        let mut borrow = false;
        for (slot, &d) in win.iter_mut().zip(&vn) {
            let p = qhat
                .wrapping_mul(u128::from(d))
                .wrapping_add(u128::from(carry));
            carry = hi(p);
            let (d1, b1) = slot.overflowing_sub(lo(p));
            let (d2, b2) = d1.overflowing_sub(Limb::from(borrow));
            *slot = d2;
            borrow = b1 || b2;
        }
        let mut qj = lo(qhat);
        if let Some(top) = win.last_mut() {
            let (d1, b1) = top.overflowing_sub(carry);
            let (d2, b2) = d1.overflowing_sub(Limb::from(borrow));
            *top = d2;
            if b1 || b2 {
                // The estimate was one too large: add the divisor back.
                qj = qj.wrapping_sub(1);
                let mut c = false;
                let len = win.len().wrapping_sub(1);
                if let Some(low) = win.get_mut(..len) {
                    for (slot, &d) in low.iter_mut().zip(&vn) {
                        let (s1, c1) = slot.overflowing_add(d);
                        let (s2, c2) = s1.overflowing_add(Limb::from(c));
                        *slot = s2;
                        c = c1 || c2;
                    }
                }
                if let Some(top) = win.last_mut() {
                    *top = top.wrapping_add(Limb::from(c));
                }
            }
        }
        if let Some(slot) = q.get_mut(j) {
            *slot = qj;
        }
    }
    // The remainder is the low `n` limbs, shifted back.
    let back = LIMB_BITS.wrapping_sub(s);
    let low = un.get(..n).unwrap_or(&[]);
    let r = low
        .iter()
        .enumerate()
        .map(|(i, &l)| shr(l, s) | shl(at(low, i.wrapping_add(1)), back))
        .collect();
    (trimmed(q), trimmed(r))
}
