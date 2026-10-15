//! The random numbers OpenSSL's `bn_rand.c` draws, from the caller's octets: `bnrand` (a number
//! of given bits) and `bnrand_range` (one below a bound), each drawn as OpenSSL draws it, so a
//! known generator gives OpenSSL's numbers and leaves the generator where OpenSSL's leaves it.

use super::{BigNum, Endian};
use zeroize::Zeroizing;

/// The caller's random octets (`RAND_priv_bytes_ex` or `RAND_bytes_ex`): fills the buffer, or
/// says it couldn't.
pub type Random<'a> = dyn FnMut(&mut [u8]) -> bool + 'a;

/// `bnrand` with `BN_RAND_TOP_ANY` and `BN_RAND_BOTTOM_ANY`: a random number below `2^bits`,
/// or `None` (and for 0 bits, zero).
pub fn rand_bits(bits: usize, rng: &mut Random<'_>) -> Option<BigNum> {
    draw_bits(bits, false, rng)
}

/// `bnrand` with `BN_RAND_TOP_ONE` and `BN_RAND_BOTTOM_ANY`: a random number of exactly
/// `bits` bits (at least one), or `None`.
pub fn rand_bits_top_one(bits: usize, rng: &mut Random<'_>) -> Option<BigNum> {
    if bits == 0 {
        return None;
    }
    draw_bits(bits, true, rng)
}

/// `bnrand`'s drawing and masking.
fn draw_bits(bits: usize, top_one: bool, rng: &mut Random<'_>) -> Option<BigNum> {
    if bits == 0 {
        return Some(BigNum::zero());
    }
    let bytes = bits.div_ceil(8);
    let top_bit = bits.saturating_sub(1) % 8;
    let mut buf = Zeroizing::new(vec![0u8; bytes]);
    if !rng(&mut buf) {
        return None;
    }
    if let Some(b) = buf.first_mut() {
        if top_one {
            *b |= 1u8.checked_shl(u32::try_from(top_bit).ok()?).unwrap_or(0);
        }
        *b &= !0xffu8
            .checked_shl(u32::try_from(top_bit).ok()?.saturating_add(1))
            .unwrap_or(0);
    }
    BigNum::from_bin(&buf, Endian::Big, false).ok()
}

/// `ossl_bn_priv_rand_range_fixed_top`: a number in `[0, range)` drawn as `range`'s bits plus
/// one with the top one set, then cut to `range`'s bits, until it's below `range` (at most 100
/// draws), as OpenSSL draws ECDSA's nonce for `ECDSA_sign_setup`. `None` for an empty range, a
/// failing generator, or too many draws.
pub fn rand_range_fixed_top(range: &BigNum, rng: &mut Random<'_>) -> Option<BigNum> {
    if range.is_negative() || range.is_zero() {
        return None;
    }
    let n = range.num_bits();
    if n == 1 {
        return Some(BigNum::zero());
    }
    for _ in 0..99 {
        let mut r = draw_bits(n.saturating_add(1), true, rng)?;
        r.mask_bits(n);
        if super::ucmp(&r, range).is_lt() {
            return Some(r);
        }
    }
    None
}

/// `bnrand_range` over the private generator: a random number in `[0, range)`, drawn as
/// OpenSSL draws it (so a known generator gives OpenSSL's number and leaves it where
/// OpenSSL's does), or `None`.
pub fn rand_range(range: &BigNum, rng: &mut Random<'_>) -> Option<BigNum> {
    if range.is_zero() || range.is_negative() {
        return None;
    }
    let n = range.num_bits();
    if n == 1 {
        return Some(BigNum::zero());
    }
    // A range of 100...: draw a bit more and reduce by up to twice the range.
    let three = !range.is_bit_set(n.wrapping_sub(2)) && !range.is_bit_set(n.wrapping_sub(3));
    let bits = if three { n.saturating_add(1) } else { n };
    let bytes = bits.div_ceil(8);
    let top_bit = bits.saturating_sub(1) % 8;
    // OpenSSL draws up to 100 times and gives up on the 100th, unchecked.
    for attempt in 0..100 {
        let mut buf = Zeroizing::new(vec![0u8; bytes]);
        if !rng(&mut buf) {
            return None;
        }
        if let Some(b) = buf.first_mut() {
            *b &= !0xffu8
                .checked_shl(u32::try_from(top_bit).ok()?.saturating_add(1))
                .unwrap_or(0);
        }
        let mut v = BigNum::from_bin(&buf, Endian::Big, false).ok()?;
        if three {
            for _ in 0..2 {
                if super::cmp(&v, range).is_ge() {
                    v = super::sub(&v, range).ok()?;
                }
            }
        }
        if attempt == 99 {
            return None;
        }
        if super::cmp(&v, range).is_lt() {
            return Some(v);
        }
    }
    None
}
