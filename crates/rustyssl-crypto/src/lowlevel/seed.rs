//! SEED (`SEED_set_key(3)`, `SEED_encrypt`): OpenSSL's round keys and rounds (RFC 4269), for
//! the 128-bit modes through [`Block128`].
//!
//! A `SEED_KEY_SCHEDULE` holds the 32 round keys, which applications can see. The G function
//! reads the two S-boxes ([`tables`], extracted from OpenSSL's sources) at secret octets; each
//! read scans the whole S-box and keeps the entry by a mask, so no secret picks an address
//! (OpenSSL's code indexes four 1 KiB tables directly). G is OpenSSL's small-footprint form,
//! which spreads the S-box octets with masks.

mod tables;

use tables::{KC, SBOX};
use zeroize::Zeroize;

use super::legacy::ct_get8;
use super::modes::{BLOCK, Block128};

/// A SEED key schedule (`SEED_KEY_SCHEDULE`): the round keys, two per round.
#[derive(Clone)]
pub struct SeedKey(pub [u32; 32]);

impl Drop for SeedKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The S-box `n` (0 or 1) at `x`.
fn s(n: usize, x: u32) -> u32 {
    let table = SBOX.as_chunks::<256>().0.get(n).map_or(&[][..], |t| &t[..]);
    u32::from(ct_get8(table, usize::try_from(x & 0xff).unwrap_or(0)))
}

/// SEED's G function.
fn g(v: u32) -> u32 {
    let s0 = s(0, v);
    let s1 = s(1, v >> 8);
    let s2 = s(0, v >> 16);
    let s3 = s(1, v >> 24);
    ((s0 & 0xfc) ^ (s1 & 0xf3) ^ (s2 & 0xcf) ^ (s3 & 0x3f))
        | (((s0 & 0xf3) ^ (s1 & 0xcf) ^ (s2 & 0x3f) ^ (s3 & 0xfc)) << 8)
        | (((s0 & 0xcf) ^ (s1 & 0x3f) ^ (s2 & 0xfc) ^ (s3 & 0xf3)) << 16)
        | (((s0 & 0x3f) ^ (s1 & 0xfc) ^ (s2 & 0xf3) ^ (s3 & 0xcf)) << 24)
}

/// Four big-endian words.
fn words(b: &[u8; BLOCK]) -> [u32; 4] {
    let mut w = [0u32; 4];
    for (d, c) in w.iter_mut().zip(b.as_chunks::<4>().0) {
        *d = u32::from_be_bytes(*c);
    }
    w
}

/// `SEED_set_key`: the round keys of a 16-octet key.
pub fn set_key(key: &[u8; 16]) -> SeedKey {
    let [mut x1, mut x2, mut x3, mut x4] = words(key);
    let mut ks = [0u32; 32];
    let kc = |i: usize| KC.get(i).copied().unwrap_or(0);
    let mut t0 = x1.wrapping_add(x3).wrapping_sub(kc(0));
    let mut t1 = x2.wrapping_sub(x4).wrapping_add(kc(0));
    for (i, pair) in ks.as_chunks_mut::<2>().0.iter_mut().enumerate() {
        if i > 0 {
            if i % 2 == 1 {
                let t = x1;
                x1 = (x1 >> 8) ^ (x2 << 24);
                x2 = (x2 >> 8) ^ (t << 24);
            } else {
                let t = x3;
                x3 = (x3 << 8) ^ (x4 >> 24);
                x4 = (x4 << 8) ^ (t >> 24);
            }
            t0 = x1.wrapping_add(x3).wrapping_sub(kc(i));
            t1 = x2.wrapping_add(kc(i)).wrapping_sub(x4);
        }
        *pair = [g(t0), g(t1)];
    }
    x1.zeroize();
    x2.zeroize();
    x3.zeroize();
    x4.zeroize();
    SeedKey(ks)
}

impl SeedKey {
    /// One round: the round keys at `r` mix `c` and `d` into `a` and `b`.
    fn round(&self, r: usize, a: &mut u32, b: &mut u32, c: u32, d: u32) {
        let k = |i: usize| self.0.get(i).copied().unwrap_or(0);
        let mut t0 = c ^ k(r);
        let mut t1 = d ^ k(r.wrapping_add(1));
        t1 = g(t1 ^ t0);
        t0 = g(t0.wrapping_add(t1));
        t1 = g(t1.wrapping_add(t0));
        t0 = t0.wrapping_add(t1);
        *a ^= t0;
        *b ^= t1;
    }

    /// The rounds in the order `order` gives, then the halves swapped.
    fn rounds(&self, block: &[u8; BLOCK], order: impl Iterator<Item = usize>) -> [u8; BLOCK] {
        let [mut x1, mut x2, mut x3, mut x4] = words(block);
        for (i, r) in order.enumerate() {
            if i % 2 == 0 {
                self.round(r, &mut x1, &mut x2, x3, x4);
            } else {
                self.round(r, &mut x3, &mut x4, x1, x2);
            }
        }
        let mut out = [0u8; BLOCK];
        for (d, w) in out.as_chunks_mut::<4>().0.iter_mut().zip([x3, x4, x1, x2]) {
            *d = w.to_be_bytes();
        }
        for x in [&mut x1, &mut x2, &mut x3, &mut x4] {
            x.zeroize();
        }
        out
    }

    /// `SEED_encrypt`.
    pub fn encrypt(&self, block: &[u8; BLOCK]) -> [u8; BLOCK] {
        self.rounds(block, (0..32).step_by(2))
    }

    /// `SEED_decrypt`.
    pub fn decrypt(&self, block: &[u8; BLOCK]) -> [u8; BLOCK] {
        self.rounds(block, (0..32).step_by(2).rev())
    }
}

/// SEED encryption as a block function.
pub struct Encrypt<'a>(pub &'a SeedKey);

impl Block128 for Encrypt<'_> {
    fn block(&self, input: &[u8; BLOCK]) -> [u8; BLOCK] {
        self.0.encrypt(input)
    }
}

/// SEED decryption as a block function.
pub struct Decrypt<'a>(pub &'a SeedKey);

impl Block128 for Decrypt<'_> {
    fn block(&self, input: &[u8; BLOCK]) -> [u8; BLOCK] {
        self.0.decrypt(input)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        reason = "test arithmetic on small known values"
    )]

    use super::*;

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
    }

    /// RFC 4269, appendix B.
    #[test]
    fn known_answers() {
        for (key, pt, ct) in [
            (
                "00000000000000000000000000000000",
                "000102030405060708090a0b0c0d0e0f",
                "5ebac6e0054e166819aff1cc6d346cdb",
            ),
            (
                "000102030405060708090a0b0c0d0e0f",
                "00000000000000000000000000000000",
                "c11f22f20140505084483597e4370f43",
            ),
            (
                "4706480851e61be85d74bfb3fd956185",
                "83a2f8a288641fb9a4e9a5cc2f131c7d",
                "ee54d13ebcae706d226bc3142cd40d4a",
            ),
            (
                "28dbc3bc49ffd87dcfa509b11d422be7",
                "b41e6be2eba84a148e2eed84593c5ec7",
                "9b9b7bfcd1813cb95d0b3618f40f5122",
            ),
        ] {
            let k = set_key(&unhex(key));
            assert_eq!(k.encrypt(&unhex(pt)), unhex::<16>(ct));
            assert_eq!(k.decrypt(&unhex(ct)), unhex::<16>(pt));
        }
    }
}
