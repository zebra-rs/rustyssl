//! IDEA (`IDEA_set_encrypt_key(3)`, `IDEA_encrypt`): OpenSSL's key schedules and its rounds,
//! for the 64-bit modes through [`Block64`].
//!
//! An `IDEA_KEY_SCHEDULE` is 54 words that applications keep and can see. OpenSSL computes on
//! them as `unsigned long`s, and a schedule's words reach the multiplication whole, so a
//! schedule no key setter leaves (words past 16 bits) gives what OpenSSL's gives: the rounds
//! here compute in 64 bits, wrapping, as its code does on the targets it runs on. Its
//! multiplication branches on a zero product and its inverse is Euclid's algorithm, both on
//! key words; here the product's two cases are both computed and one kept by a mask, and the
//! inverse is a fixed chain of multiplications (Fermat), with OpenSSL's answers for every word.

use zeroize::Zeroize;

use super::{Block64, be_block, be_words};

/// The schedule's words.
pub const WORDS: usize = 54;

/// The modulus of IDEA's multiplication, 2^16 + 1.
const M: u64 = 0x10001;

/// An IDEA key schedule (`IDEA_KEY_SCHEDULE`), for encryption or decryption: its nine rows of
/// six words, one after another.
#[derive(Clone)]
pub struct IdeaKey(pub [u32; WORDS]);

impl Drop for IdeaKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// All ones if `x` is zero, else zero.
fn zero_mask(x: u64) -> u64 {
    ((x | x.wrapping_neg()) >> 63).wrapping_sub(1)
}

/// `idea_mul`: `a` (at most 16 bits) times the key word `b` modulo 2^16 + 1, where a zero
/// stands for 2^16, as OpenSSL's `unsigned long` arithmetic leaves it (the high bits are
/// never used).
fn mul(a: u64, b: u32) -> u64 {
    let ul = a.wrapping_mul(u64::from(b));
    let mut r = (ul & 0xffff).wrapping_sub(ul >> 16);
    r = r.wrapping_sub(r >> 16);
    // A product of zero (one side zero): `-(int)a - b + 1` in `unsigned int`.
    let low = u32::try_from(a & 0xffff).unwrap_or(0);
    let z = u64::from(0u32.wrapping_sub(low).wrapping_sub(b).wrapping_add(1));
    let m = zero_mask(ul);
    (r & !m) | (z & m)
}

/// `x * y` modulo 2^16 + 1, for both below 2^17.
fn mulmod(x: u64, y: u64) -> u64 {
    x.wrapping_mul(y) % M
}

/// OpenSSL's `inverse` (`i_skey.c`): the inverse of `x` modulo 2^16 + 1 as Euclid's algorithm
/// finds it from `x` itself, which comes to the inverse of `x mod 65537` (0 for none), but 1
/// for 65537 itself.
fn inverse(x: u32) -> u32 {
    let y = u64::from(x) % M;
    // y^(65537 - 2) = y^0xffff: fifteen squarings, each followed by a multiplication.
    let mut r = y;
    for _ in 0..15 {
        r = mulmod(mulmod(r, r), y);
    }
    let one = zero_mask(u64::from(x) ^ M);
    let v = (r & !one) | (1 & one);
    u32::try_from(v).unwrap_or(0)
}

/// `IDEA_set_encrypt_key`: the encryption schedule of a 16-octet key.
pub fn set_encrypt_key(key: &[u8; 16]) -> IdeaKey {
    crate::dit::with(|| {
        let mut k = [0u32; WORDS];
        for (w, b) in k.iter_mut().zip(key.as_chunks::<2>().0) {
            *w = u32::from(u16::from_be_bytes(*b));
        }
        // Each row of eight is the previous one rotated left by 25 bits.
        let at = |k: &[u32; WORDS], i: usize| k.get(i).copied().unwrap_or(0);
        let mut from = 0usize;
        let mut to = 8usize;
        for i in 0..6 {
            let order = [1usize, 2, 3, 4, 5, 6, 7, 0, 1];
            let count = if i < 5 { 8 } else { 6 };
            for j in 0..count {
                let hi = at(&k, from.wrapping_add(order.get(j).copied().unwrap_or(0)));
                let lo = at(
                    &k,
                    from.wrapping_add(order.get(j.wrapping_add(1)).copied().unwrap_or(0)),
                );
                if let Some(w) = k.get_mut(to) {
                    *w = ((hi << 9) | (lo >> 7)) & 0xffff;
                }
                to = to.wrapping_add(1);
            }
            from = from.wrapping_add(8);
        }
        IdeaKey(k)
    })
}

/// `IDEA_set_decrypt_key` over one memory: the decryption schedule of the words at `e`
/// written from `d`, in OpenSSL's order (so when the two are the same, later words are read
/// after earlier ones are written, as there).
fn set_decrypt_key_at(mem: &mut [u32], e: usize, d: usize) {
    let get = |mem: &[u32], i: usize| mem.get(i).copied().unwrap_or(0);
    let neg = |x: u32| x.wrapping_neg() & 0xffff;
    let mut tp = d;
    let mut fp = e.wrapping_add(48);
    let mut put = |mem: &mut [u32], v: u32| {
        if let Some(w) = mem.get_mut(tp) {
            *w = v;
        }
        tp = tp.wrapping_add(1);
    };
    for r in 0..9 {
        let v = inverse(get(mem, fp));
        put(mem, v);
        let v = neg(get(mem, fp.wrapping_add(2)));
        put(mem, v);
        let v = neg(get(mem, fp.wrapping_add(1)));
        put(mem, v);
        let v = inverse(get(mem, fp.wrapping_add(3)));
        put(mem, v);
        if r == 8 {
            break;
        }
        fp = fp.wrapping_sub(6);
        let v = get(mem, fp.wrapping_add(4));
        put(mem, v);
        let v = get(mem, fp.wrapping_add(5));
        put(mem, v);
    }
    for i in [1usize, 49] {
        if let Some([a, b]) = mem.get_mut(d.wrapping_add(i)..d.wrapping_add(i).wrapping_add(2)) {
            core::mem::swap(a, b);
        }
    }
}

/// The words `IDEA_set_decrypt_key` writes: the last two keep their values.
pub const DECRYPT_WORDS: usize = 52;

/// `IDEA_set_decrypt_key` from one schedule into another: its first [`DECRYPT_WORDS`] words
/// (the rest are zero).
pub fn set_decrypt_key(ek: &[u32; WORDS]) -> IdeaKey {
    crate::dit::with(|| {
        let mut mem = [0u32; 2 * WORDS];
        if let Some(a) = mem.get_mut(..WORDS) {
            a.copy_from_slice(ek);
        }
        set_decrypt_key_at(&mut mem, 0, WORDS);
        let mut dk = IdeaKey([0; WORDS]);
        for (d, s) in
            dk.0.iter_mut()
                .zip(mem.iter().skip(WORDS))
                .take(DECRYPT_WORDS)
        {
            *d = *s;
        }
        mem.zeroize();
        dk
    })
}

/// `IDEA_set_decrypt_key` with the same schedule for both, as OpenSSL computes it in place.
pub fn set_decrypt_key_in_place(k: &mut [u32; WORDS]) {
    set_decrypt_key_at(k, 0, 0);
}

impl IdeaKey {
    /// `IDEA_encrypt`: two words (the low 32 bits of each `unsigned long`; OpenSSL ignores
    /// the rest), through the schedule.
    pub fn encrypt_words(&self, d: [u32; 2]) -> [u32; 2] {
        let k = |i: usize| self.0.get(i).copied().unwrap_or(0);
        let mut x2 = u64::from(d[0]);
        let mut x1 = x2 >> 16;
        let mut x4 = u64::from(d[1]);
        let mut x3 = x4 >> 16;
        let mut p = 0usize;
        for _ in 0..8 {
            x1 = mul(x1 & 0xffff, k(p));
            x2 = x2.wrapping_add(u64::from(k(p.wrapping_add(1))));
            x3 = x3.wrapping_add(u64::from(k(p.wrapping_add(2))));
            x4 = mul(x4 & 0xffff, k(p.wrapping_add(3)));
            let mut t0 = mul((x1 ^ x3) & 0xffff, k(p.wrapping_add(4)));
            let t1 = mul(t0.wrapping_add(x2 ^ x4) & 0xffff, k(p.wrapping_add(5)));
            p = p.wrapping_add(6);
            t0 = t0.wrapping_add(t1);
            x1 ^= t1;
            x4 ^= t0;
            let swap = x2 ^ t0;
            x2 = x3 ^ t1;
            x3 = swap;
        }
        x1 = mul(x1 & 0xffff, k(p));
        let t0 = x3.wrapping_add(u64::from(k(p.wrapping_add(1))));
        let t1 = x2.wrapping_add(u64::from(k(p.wrapping_add(2))));
        x4 = mul(x4 & 0xffff, k(p.wrapping_add(3)));
        let w =
            |hi: u64, lo: u64| u32::try_from(((hi & 0xffff) << 16) | (lo & 0xffff)).unwrap_or(0);
        [w(x1, t0), w(t1, x4)]
    }
}

/// IDEA has one function, which decrypts with a decryption schedule.
impl Block64 for IdeaKey {
    fn encrypt(&self, block: &[u8; 8]) -> [u8; 8] {
        be_block(self.encrypt_words(be_words(block)))
    }

    fn decrypt(&self, block: &[u8; 8]) -> [u8; 8] {
        self.encrypt(block)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "a direct port of OpenSSL's arithmetic, for comparison"
    )]

    use super::*;

    /// OpenSSL's `inverse`, as it is.
    fn euclid(xin: u32) -> u32 {
        if xin == 0 {
            return 0;
        }
        let (mut n1, mut n2, mut b1, mut b2): (i64, i64, i64, i64) =
            (0x10001, i64::from(xin), 0, 1);
        loop {
            let r = n1 % n2;
            let q = (n1 - r) / n2;
            if r == 0 {
                if b2 < 0 {
                    b2 += 0x10001;
                }
                return b2 as u32;
            }
            n1 = n2;
            n2 = r;
            let t = b2;
            b2 = b1 - q * b2;
            b1 = t;
        }
    }

    /// OpenSSL's `idea_mul`, as it is.
    fn branchy_mul(a: u64, b: u32) -> u64 {
        let ul = a.wrapping_mul(u64::from(b));
        if ul != 0 {
            let r = (ul & 0xffff).wrapping_sub(ul >> 16);
            r.wrapping_sub(r >> 16)
        } else {
            u64::from((-(a as i32) as u32).wrapping_sub(b).wrapping_add(1))
        }
    }

    #[test]
    fn inverse_matches_euclid() {
        for x in 0..=0x30000u32 {
            assert_eq!(inverse(x), euclid(x), "{x:#x}");
        }
        for x in [
            0x7fff_ffffu32,
            0xffff_ffff,
            0x8000_0000,
            0x10001 * 9,
            0x10001 * 9 + 1,
        ] {
            assert_eq!(inverse(x), euclid(x), "{x:#x}");
        }
        let mut x = 1u32;
        for _ in 0..100_000 {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            assert_eq!(inverse(x), euclid(x), "{x:#x}");
        }
    }

    #[test]
    fn mul_matches_openssl() {
        for a in [0u64, 1, 2, 0x7fff, 0x8000, 0xfffe, 0xffff] {
            for b in [
                0u32,
                1,
                2,
                0xffff,
                0x10000,
                0x10001,
                0xffff_ffff,
                0x8000_0000,
            ] {
                assert_eq!(mul(a, b), branchy_mul(a, b), "{a:#x} {b:#x}");
            }
        }
    }

    /// The vector from Lai's thesis (as in the original IDEA paper).
    #[test]
    fn known_answer() {
        let key: [u8; 16] =
            core::array::from_fn(|i| if i % 2 == 1 { (i / 2 + 1) as u8 } else { 0 });
        let ek = set_encrypt_key(&key);
        let ct = ek.encrypt_words([0x0000_0001, 0x0002_0003]);
        assert_eq!(ct, [0x11fb_ed2b, 0x0198_6de5]);
        let dk = set_decrypt_key(&ek.0);
        assert_eq!(dk.encrypt_words(ct), [0x0000_0001, 0x0002_0003]);
        let mut same = ek.0;
        set_decrypt_key_in_place(&mut same);
        assert_ne!(same[..DECRYPT_WORDS], dk.0[..DECRYPT_WORDS]);
    }
}
