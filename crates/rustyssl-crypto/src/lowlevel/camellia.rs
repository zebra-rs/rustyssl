//! Camellia (`Camellia_set_key(3)`, `Camellia_encrypt`): OpenSSL's key table and rounds
//! (RFC 3713), for the 128-bit modes through [`Block128`].
//!
//! A `CAMELLIA_KEY` holds the key table's words and the number of "grand rounds" (three for
//! 128-bit keys, four for longer ones), which applications can see; [`CamelliaKey`] keeps the
//! words in the order OpenSSL's C code does (its x86_64 assembly swaps each pair, which the
//! caller of this module handles). The rounds read the S-boxes ([`tables`], extracted from
//! OpenSSL's sources) at secret octets; each read scans the whole table and keeps the entry by
//! a mask, so no secret picks an address (OpenSSL's code indexes them directly).

mod tables;

use tables::{SBOX, SIGMA};
use zeroize::Zeroize;

use super::legacy::ct_get;
use super::modes::{BLOCK, Block128};

/// The key table's words.
pub const WORDS: usize = 68;

/// A Camellia key: the key table, in OpenSSL's C order, and its grand rounds (1 to 4).
#[derive(Clone)]
pub struct CamelliaKey {
    /// The key table's words.
    pub words: [u32; WORDS],
    /// The grand rounds: 3 or 4 from a key setter; 1 or 2 run fewer rounds over the same
    /// table, as OpenSSL's do. The rounds use words up to `16 * grand_rounds + 3`.
    pub grand_rounds: usize,
}

impl Drop for CamelliaKey {
    fn drop(&mut self) {
        self.words.zeroize();
    }
}

/// The number of words of the key table a key with `grand_rounds` fills: OpenSSL leaves the
/// rest as they were.
pub fn filled_words(grand_rounds: usize) -> usize {
    if grand_rounds == 3 { 52 } else { WORDS }
}

/// The spread S-box `n` (`SBOX1_1110`, `SBOX4_4404`, `SBOX2_0222`, `SBOX3_3033`) at the octet
/// of `x` that `shift` selects.
fn sbox(n: usize, x: u32, shift: u32) -> u32 {
    let table = SBOX.as_chunks::<256>().0.get(n).map_or(&[][..], |t| &t[..]);
    ct_get(table, usize::try_from((x >> shift) & 0xff).unwrap_or(0))
}

const SBOX1_1110: usize = 0;
const SBOX4_4404: usize = 1;
const SBOX2_0222: usize = 2;
const SBOX3_3033: usize = 3;

/// `Camellia_Feistel`: one round with the key words `k0` and `k1`, from `s0` and `s1` into
/// `s2` and `s3`.
fn feistel(s0: u32, s1: u32, s2: &mut u32, s3: &mut u32, k0: u32, k1: u32) {
    let t0 = s0 ^ k0;
    let t1 = s1 ^ k1;
    let mut t3 = sbox(SBOX4_4404, t0, 0)
        ^ sbox(SBOX3_3033, t0, 8)
        ^ sbox(SBOX2_0222, t0, 16)
        ^ sbox(SBOX1_1110, t0, 24);
    let mut t2 = sbox(SBOX1_1110, t1, 0)
        ^ sbox(SBOX4_4404, t1, 8)
        ^ sbox(SBOX3_3033, t1, 16)
        ^ sbox(SBOX2_0222, t1, 24);
    t2 ^= t3;
    t3 = t3.rotate_right(8);
    *s3 ^= t3;
    *s2 ^= t2;
    *s3 ^= t2;
}

/// Rotates the 128 bits `s` (most significant word first) left by `n`.
fn rot128(s: &mut [u32; 4], n: u32) {
    let v = s
        .iter()
        .fold(0u128, |v, w| (v << 32) | u128::from(*w))
        .rotate_left(n);
    *s = core::array::from_fn(|i| {
        let shift = 96u32.wrapping_sub(u32::try_from(i).unwrap_or(0).wrapping_mul(32));
        u32::try_from((v >> shift) & 0xffff_ffff).unwrap_or(0)
    });
}

/// Writes the four words of `s`, in the order `perm` picks them, at `at`.
fn store(k: &mut [u32; WORDS], at: usize, s: &[u32; 4], perm: [usize; 4], count: usize) {
    for (i, p) in perm.iter().enumerate().take(count) {
        if let (Some(d), Some(v)) = (k.get_mut(at.wrapping_add(i)), s.get(*p)) {
            *d = *v;
        }
    }
}

/// The two Feistel rounds of the key schedule with the Sigma pair starting at `sigma`.
fn scramble(s: &mut [u32; 4], sigma: usize) {
    let sg = |i: usize| SIGMA.get(i).copied().unwrap_or(0);
    let [mut s0, mut s1, mut s2, mut s3] = *s;
    feistel(
        s0,
        s1,
        &mut s2,
        &mut s3,
        sg(sigma),
        sg(sigma.wrapping_add(1)),
    );
    feistel(
        s2,
        s3,
        &mut s0,
        &mut s1,
        sg(sigma.wrapping_add(2)),
        sg(sigma.wrapping_add(3)),
    );
    *s = [s0, s1, s2, s3];
}

/// XORs four words of the table from `at` into `s`.
fn xor_from(s: &mut [u32; 4], k: &[u32; WORDS], at: usize) {
    for (i, v) in s.iter_mut().enumerate() {
        *v ^= k.get(at.wrapping_add(i)).copied().unwrap_or(0);
    }
}

/// Four words of the table from `at`.
fn load(k: &[u32; WORDS], at: usize) -> [u32; 4] {
    core::array::from_fn(|i| k.get(at.wrapping_add(i)).copied().unwrap_or(0))
}

/// `Camellia_Ekeygen`: the key table of a 16-, 24-, or 32-octet key (`None` for another
/// length). Only its first [`filled_words`] words are the key's (the rest are zero).
pub fn set_key(key: &[u8]) -> Option<CamelliaKey> {
    if !matches!(key.len(), 16 | 24 | 32) {
        return None;
    }
    let mut k = [0u32; WORDS];
    let w = |i: usize| {
        let mut b = [0u8; 4];
        for (j, d) in b.iter_mut().enumerate() {
            *d = key
                .get(i.wrapping_mul(4).wrapping_add(j))
                .copied()
                .unwrap_or(0);
        }
        u32::from_be_bytes(b)
    };
    const ID: [usize; 4] = [0, 1, 2, 3];
    let mut s = [w(0), w(1), w(2), w(3)];
    store(&mut k, 0, &s, ID, 4);
    if key.len() != 16 {
        s = if key.len() == 24 {
            [w(4), w(5), !w(4), !w(5)]
        } else {
            [w(4), w(5), w(6), w(7)]
        };
        store(&mut k, 8, &s, ID, 4);
        xor_from(&mut s, &k, 0);
    }
    scramble(&mut s, 0);
    xor_from(&mut s, &k, 0);
    scramble(&mut s, 4);

    // The rotations, as OpenSSL writes them: `perm` is the order of the four words it stores
    // (it rotates by 32 or more by starting from another word).
    const R1: [usize; 4] = [1, 2, 3, 0];
    const R2: [usize; 4] = [2, 3, 0, 1];
    let grand_rounds = if key.len() == 16 {
        store(&mut k, 4, &s, ID, 4); // KA
        rot128(&mut s, 15);
        store(&mut k, 12, &s, ID, 4); // KA <<< 15
        rot128(&mut s, 15);
        store(&mut k, 16, &s, ID, 4); // KA <<< 30
        rot128(&mut s, 15);
        store(&mut k, 24, &s, ID, 2); // KA <<< 45
        rot128(&mut s, 15);
        store(&mut k, 28, &s, ID, 4); // KA <<< 60
        let mut r = [s[1], s[2], s[3], s[0]];
        rot128(&mut r, 2);
        store(&mut k, 40, &r, ID, 4); // KA <<< 94
        rot128(&mut r, 17);
        store(&mut k, 48, &r, ID, 4); // KA <<< 111

        s = load(&k, 0);
        rot128(&mut s, 15);
        store(&mut k, 8, &s, ID, 4); // KL <<< 15
        rot128(&mut s, 30);
        store(&mut k, 20, &s, ID, 4); // KL <<< 45
        rot128(&mut s, 15);
        store(&mut k, 26, &s, R2, 2); // KL <<< 60
        rot128(&mut s, 17);
        store(&mut k, 32, &s, ID, 4); // KL <<< 77
        rot128(&mut s, 17);
        store(&mut k, 36, &s, ID, 4); // KL <<< 94
        rot128(&mut s, 17);
        store(&mut k, 44, &s, ID, 4); // KL <<< 111
        r.zeroize();
        3
    } else {
        store(&mut k, 12, &s, ID, 4); // KA
        xor_from(&mut s, &k, 8);
        scramble(&mut s, 8);
        store(&mut k, 4, &s, ID, 4); // KB
        rot128(&mut s, 30);
        store(&mut k, 20, &s, ID, 4); // KB <<< 30
        rot128(&mut s, 30);
        store(&mut k, 40, &s, ID, 4); // KB <<< 60
        let mut r = [s[1], s[2], s[3], s[0]];
        rot128(&mut r, 19);
        store(&mut k, 64, &r, ID, 4); // KB <<< 111

        s = load(&k, 8);
        rot128(&mut s, 15);
        store(&mut k, 8, &s, ID, 4); // KR <<< 15
        rot128(&mut s, 15);
        store(&mut k, 16, &s, ID, 4); // KR <<< 30
        rot128(&mut s, 30);
        store(&mut k, 36, &s, ID, 4); // KR <<< 60
        r = [s[1], s[2], s[3], s[0]];
        rot128(&mut r, 2);
        store(&mut k, 52, &r, ID, 4); // KR <<< 94

        s = load(&k, 12);
        rot128(&mut s, 15);
        store(&mut k, 12, &s, ID, 4); // KA <<< 15
        rot128(&mut s, 30);
        store(&mut k, 28, &s, ID, 4); // KA <<< 45
        store(&mut k, 48, &s, R1, 4); // KA <<< 77
        r = [s[1], s[2], s[3], s[0]];
        rot128(&mut r, 17);
        store(&mut k, 56, &r, ID, 4); // KA <<< 94

        s = load(&k, 0);
        r = [s[1], s[2], s[3], s[0]];
        rot128(&mut r, 13);
        store(&mut k, 24, &r, ID, 4); // KL <<< 45
        rot128(&mut r, 15);
        store(&mut k, 32, &r, ID, 4); // KL <<< 60
        rot128(&mut r, 17);
        store(&mut k, 44, &r, ID, 4); // KL <<< 77
        let mut q = [r[1], r[2], r[3], r[0]];
        rot128(&mut q, 2);
        store(&mut k, 60, &q, ID, 4); // KL <<< 111
        r.zeroize();
        q.zeroize();
        4
    };
    s.zeroize();
    Some(CamelliaKey {
        words: k,
        grand_rounds,
    })
}

impl CamelliaKey {
    fn k(&self, i: usize) -> u32 {
        self.words.get(i).copied().unwrap_or(0)
    }

    /// Six Feistel rounds with the twelve key words from `at`, forward or backward.
    fn six(&self, s: &mut [u32; 4], at: usize, forward: bool) {
        let [mut s0, mut s1, mut s2, mut s3] = *s;
        for j in 0..3usize {
            let (a, b) = if forward {
                (j.wrapping_mul(4), j.wrapping_mul(4).wrapping_add(2))
            } else {
                (
                    10usize.wrapping_sub(j.wrapping_mul(4)),
                    8usize.wrapping_sub(j.wrapping_mul(4)),
                )
            };
            let a = at.wrapping_add(a);
            let b = at.wrapping_add(b);
            feistel(
                s0,
                s1,
                &mut s2,
                &mut s3,
                self.k(a),
                self.k(a.wrapping_add(1)),
            );
            feistel(
                s2,
                s3,
                &mut s0,
                &mut s1,
                self.k(b),
                self.k(b.wrapping_add(1)),
            );
        }
        *s = [s0, s1, s2, s3];
    }

    /// `Camellia_EncryptBlock_Rounds`.
    pub fn encrypt(&self, block: &[u8; BLOCK]) -> [u8; BLOCK] {
        let end = self.grand_rounds.wrapping_mul(16);
        let mut s = words(block);
        xor_from(&mut s, &self.words, 0);
        let mut k = 4usize;
        loop {
            self.six(&mut s, k, true);
            k = k.wrapping_add(12);
            if k >= end {
                break;
            }
            let [s0, s1, s2, s3] = &mut s;
            *s1 ^= (*s0 & self.k(k)).rotate_left(1);
            *s2 ^= *s3 | self.k(k.wrapping_add(3));
            *s0 ^= *s1 | self.k(k.wrapping_add(1));
            *s3 ^= (*s2 & self.k(k.wrapping_add(2))).rotate_left(1);
            k = k.wrapping_add(4);
        }
        finish(s, &self.words, k)
    }

    /// `Camellia_DecryptBlock_Rounds`.
    pub fn decrypt(&self, block: &[u8; BLOCK]) -> [u8; BLOCK] {
        let mut k = self.grand_rounds.wrapping_mul(16);
        let mut s = words(block);
        xor_from(&mut s, &self.words, k);
        loop {
            k = k.wrapping_sub(12);
            self.six(&mut s, k, false);
            if k <= 4 {
                break;
            }
            k = k.wrapping_sub(4);
            let [s0, s1, s2, s3] = &mut s;
            *s1 ^= (*s0 & self.k(k.wrapping_add(2))).rotate_left(1);
            *s2 ^= *s3 | self.k(k.wrapping_add(1));
            *s0 ^= *s1 | self.k(k.wrapping_add(3));
            *s3 ^= (*s2 & self.k(k)).rotate_left(1);
        }
        finish(s, &self.words, 0)
    }
}

/// Four big-endian words.
fn words(b: &[u8; BLOCK]) -> [u32; 4] {
    let mut w = [0u32; 4];
    for (d, c) in w.iter_mut().zip(b.as_chunks::<4>().0) {
        *d = u32::from_be_bytes(*c);
    }
    w
}

/// The last whitening, from the key words at `at`, and the halves swapped.
fn finish(mut s: [u32; 4], k: &[u32; WORDS], at: usize) -> [u8; BLOCK] {
    let [s0, s1, s2, s3] = s;
    let mut t = [s2, s3, s0, s1];
    xor_from(&mut t, k, at);
    let mut out = [0u8; BLOCK];
    for (d, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(t) {
        *d = w.to_be_bytes();
    }
    s.zeroize();
    t.zeroize();
    out
}

/// Camellia encryption as a block function.
pub struct Encrypt<'a>(pub &'a CamelliaKey);

impl Block128 for Encrypt<'_> {
    fn block(&self, input: &[u8; BLOCK]) -> [u8; BLOCK] {
        self.0.encrypt(input)
    }
}

/// Camellia decryption as a block function.
pub struct Decrypt<'a>(pub &'a CamelliaKey);

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

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 3713, appendix A.
    #[test]
    fn known_answers() {
        let pt: [u8; 16] = unhex("0123456789abcdeffedcba9876543210")
            .try_into()
            .unwrap();
        for (key, ct, rounds) in [
            (
                "0123456789abcdeffedcba9876543210",
                "67673138549669730857065648eabe43",
                3,
            ),
            (
                "0123456789abcdeffedcba98765432100011223344556677",
                "b4993401b3e996f84ee5cee7d79b09b9",
                4,
            ),
            (
                "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
                "9acc237dff16d76c20ef7c919e3a7509",
                4,
            ),
        ] {
            let k = set_key(&unhex(key)).unwrap();
            assert_eq!(k.grand_rounds, rounds);
            let c = k.encrypt(&pt);
            assert_eq!(c.to_vec(), unhex(ct));
            assert_eq!(k.decrypt(&c), pt);
        }
    }

    /// A 128-bit key fills 52 words.
    #[test]
    fn short_keys_fill_52_words() {
        let k = set_key(&[7; 16]).unwrap();
        assert!(k.words[52..].iter().all(|w| *w == 0));
        assert_eq!(filled_words(3), 52);
        assert_eq!(filled_words(4), WORDS);
        assert!(set_key(&[7; 20]).is_none());
    }
}
