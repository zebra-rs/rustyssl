//! The AEAD helpers of `modes.h`: GCM ([`Gcm`]), CCM ([`Ccm`]), OCB ([`Ocb`]), and XTS
//! ([`xts`]), over the block function (and, for their bulk forms, the CTR, CCM, or OCB
//! function) the caller passes (`gcm128.c`, `ccm128.c`, `ocb128.c`, `xts128.c`).
//!
//! The steps are OpenSSL's, so every result, and what's left in each context, is what OpenSSL
//! computes, its quirks included: GCM keeps the ciphertext of a partial block (and the AAD's
//! hash when the message starts) in a buffer it hashes at block boundaries and at the end, and
//! its `finish` doesn't reset that, so a second `finish` (or a `tag` after one) hashes it
//! again; a CCM operation with the wrong length leaves the nonce block half reset. GHASH is the
//! `ghash` crate's (constant time); the tags compare in constant time.

use universal_hash::{KeyInit, UniversalHash};
use zeroize::Zeroize;

use super::modes::{BLOCK, Block128, Ctr128};

/// The block at `at` of `data`, zero-filled past its end.
fn block_at(data: &[u8], at: usize) -> [u8; BLOCK] {
    let mut b = [0u8; BLOCK];
    for (d, s) in b.iter_mut().zip(data.iter().skip(at)) {
        *d = *s;
    }
    b
}

/// The octet at `i`, or 0 past the end.
fn at(data: &[u8], i: usize) -> u8 {
    data.get(i).copied().unwrap_or(0)
}

/// Copies `src` into `out` from octet `at` on, as far as `out` reaches.
fn put(out: &mut [u8], at: usize, src: &[u8]) {
    for (d, s) in out.iter_mut().skip(at).zip(src) {
        *d = *s;
    }
}

/// XORs `b` into `a`.
fn xor_into(a: &mut [u8; BLOCK], b: &[u8; BLOCK]) {
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= y;
    }
}

/// `CRYPTO_memcmp` of the first `len` octets: 0 if equal, 1 if not, in constant time.
fn memcmp(a: &[u8], b: &[u8], len: usize) -> i32 {
    let d = a.iter().zip(b).take(len).fold(0u8, |d, (x, y)| d | (x ^ y));
    i32::from(d != 0)
}

/// The GCM message length limit, 2^36 - 32 octets.
const GCM_MAX_MESSAGE: u64 = (1 << 36) - 32;
/// The GCM AAD length limit, 2^61 octets.
const GCM_MAX_AAD: u64 = 1 << 61;
/// OpenSSL's stride for hashing and its CTR function's calls, 3 KiB.
const GHASH_CHUNK: usize = 3 * 1024;

/// A GCM context: the hash key, the counter block, the current keystream block, the first
/// counter block's encryption, the running hash, the buffered octets yet to hash and their
/// count, the AAD's partial-block count, and the AAD and message lengths.
#[derive(Clone)]
pub struct Gcm {
    h: [u8; BLOCK],
    yi: [u8; BLOCK],
    eki: [u8; BLOCK],
    ek0: [u8; BLOCK],
    xi: [u8; BLOCK],
    xn: [u8; 3 * BLOCK],
    mres: usize,
    ares: usize,
    alen: u64,
    mlen: u64,
}

impl core::fmt::Debug for Gcm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Gcm").finish_non_exhaustive()
    }
}

impl Drop for Gcm {
    fn drop(&mut self) {
        self.h.zeroize();
        self.yi.zeroize();
        self.eki.zeroize();
        self.ek0.zeroize();
        self.xi.zeroize();
        self.xn.zeroize();
    }
}

/// How an encryption or decryption starts: the code to return now, or the buffered count and
/// the counter.
enum Start {
    Return(i32),
    Go(usize, u32),
}

impl Gcm {
    /// `CRYPTO_gcm128_init`: the hash key is the block function's encryption of zeros.
    pub fn new(b: &impl Block128) -> Self {
        crate::dit::with(|| Self {
            h: b.block(&[0; BLOCK]),
            yi: [0; BLOCK],
            eki: [0; BLOCK],
            ek0: [0; BLOCK],
            xi: [0; BLOCK],
            xn: [0; 3 * BLOCK],
            mres: 0,
            ares: 0,
            alen: 0,
            mlen: 0,
        })
    }

    /// Hashes `data` (whole blocks) into the running hash.
    fn ghash(&mut self, data: &[u8]) {
        let Ok(mut g) = ghash::GHash::new_from_slice(&self.h) else {
            return;
        };
        let mut first = block_at(data, 0);
        xor_into(&mut first, &self.xi);
        g.update_padded(&first);
        g.update_padded(data.get(BLOCK..).unwrap_or_default());
        first.zeroize();
        self.xi = g.finalize().into();
    }

    /// Multiplies the running hash by the key (`GCM_MUL`).
    fn mul(&mut self) {
        self.ghash(&[0; BLOCK]);
    }

    /// Hashes the first `n` buffered octets.
    fn ghash_xn(&mut self, n: usize) {
        let xn = self.xn;
        self.ghash(xn.get(..n).unwrap_or_default());
    }

    /// The counter, the counter block's last 32 bits.
    fn ctr(&self) -> u32 {
        u32::from_be_bytes([
            at(&self.yi, 12),
            at(&self.yi, 13),
            at(&self.yi, 14),
            at(&self.yi, 15),
        ])
    }

    /// Sets the counter.
    fn set_ctr(&mut self, ctr: u32) {
        put(&mut self.yi, 12, &ctr.to_be_bytes());
    }

    /// `CRYPTO_gcm128_setiv`: a 12-octet IV with a counter of 1, any other length hashed;
    /// the lengths and the hash start again.
    pub fn setiv(&mut self, iv: &[u8], b: &impl Block128) {
        crate::dit::with(|| {
            self.alen = 0;
            self.mlen = 0;
            self.ares = 0;
            self.mres = 0;
            let ctr;
            if iv.len() == 12 {
                self.yi = [0; BLOCK];
                put(&mut self.yi, 0, iv);
                self.yi[15] = 1;
                ctr = 1u32;
            } else {
                self.xi = [0; BLOCK];
                let (blocks, rest) = iv.as_chunks::<BLOCK>();
                for block in blocks {
                    xor_into(&mut self.xi, block);
                    self.mul();
                }
                if !rest.is_empty() {
                    xor_into(&mut self.xi, &block_at(rest, 0));
                    self.mul();
                }
                let bits = u64::try_from(iv.len()).unwrap_or(u64::MAX).wrapping_shl(3);
                let mut len = [0u8; BLOCK];
                put(&mut len, 8, &bits.to_be_bytes());
                xor_into(&mut self.xi, &len);
                self.mul();
                ctr = self.ctr_of_xi();
                self.yi = self.xi;
            }
            self.xi = [0; BLOCK];
            self.ek0 = b.block(&self.yi);
            self.set_ctr(ctr.wrapping_add(1));
        })
    }

    /// The running hash's last 32 bits, as a counter.
    fn ctr_of_xi(&self) -> u32 {
        u32::from_be_bytes([
            at(&self.xi, 12),
            at(&self.xi, 13),
            at(&self.xi, 14),
            at(&self.xi, 15),
        ])
    }

    /// `CRYPTO_gcm128_aad`: 0, -1 past 2^61 octets of AAD, or -2 after the message has started.
    pub fn aad(&mut self, aad: &[u8]) -> i32 {
        crate::dit::with(|| {
            if self.mlen != 0 {
                return -2;
            }
            let len = u64::try_from(aad.len()).unwrap_or(u64::MAX);
            let alen = self.alen.wrapping_add(len);
            if alen > GCM_MAX_AAD || alen < len {
                return -1;
            }
            self.alen = alen;
            let mut aad = aad;
            let mut n = self.ares;
            if n != 0 {
                while n != 0 && !aad.is_empty() {
                    if let (Some(x), Some(a)) = (self.xi.get_mut(n), aad.first()) {
                        *x ^= a;
                    }
                    aad = aad.get(1..).unwrap_or_default();
                    n = n.wrapping_add(1) % BLOCK;
                }
                if n == 0 {
                    self.mul();
                } else {
                    self.ares = n;
                    return 0;
                }
            }
            let whole = aad.len() & !(BLOCK - 1);
            if whole != 0 {
                self.ghash(aad.get(..whole).unwrap_or_default());
                aad = aad.get(whole..).unwrap_or_default();
            }
            if !aad.is_empty() {
                n = aad.len();
                xor_into(&mut self.xi, &block_at(aad, 0));
            }
            self.ares = n;
            0
        })
    }

    /// The start of an encryption or decryption of `len` octets: the length check, and the
    /// AAD's hash finished (into the buffer, unless there's no data, when it's hashed now).
    fn start(&mut self, len: usize) -> Start {
        let len = u64::try_from(len).unwrap_or(u64::MAX);
        let mlen = self.mlen.wrapping_add(len);
        if mlen > GCM_MAX_MESSAGE || mlen < len {
            return Start::Return(-1);
        }
        self.mlen = mlen;
        let mut mres = self.mres;
        if self.ares != 0 {
            if len == 0 {
                self.mul();
                self.ares = 0;
                return Start::Return(0);
            }
            put(&mut self.xn, 0, &self.xi);
            self.xi = [0; BLOCK];
            mres = BLOCK;
            self.ares = 0;
        }
        Start::Go(mres, self.ctr())
    }

    /// The next keystream block: the counter block's encryption, the counter counting up.
    fn next_keystream(&mut self, ctr: &mut u32, b: &impl Block128) {
        self.eki = b.block(&self.yi);
        *ctr = ctr.wrapping_add(1);
        self.set_ctr(*ctr);
    }

    /// Encrypts (`enc`) or decrypts with the block function, or, with `stream`, the whole
    /// blocks with a CTR function: `CRYPTO_gcm128_{en,de}crypt[_ctr32]`. Returns 0, or -1
    /// past the message length limit.
    fn crypt(
        &mut self,
        input: &[u8],
        out: &mut [u8],
        b: &impl Block128,
        stream: Option<&dyn Ctr128>,
        enc: bool,
    ) -> i32 {
        let len = input.len();
        let (mut mres, mut ctr) = match self.start(len) {
            Start::Return(r) => return r,
            Start::Go(m, c) => (m, c),
        };
        let mut i = 0usize;
        let mut n = mres % BLOCK;
        if n != 0 {
            while n != 0 && i < len {
                let x = at(input, i);
                let y = x ^ at(&self.eki, n);
                if let Some(o) = out.get_mut(i) {
                    *o = y;
                }
                if let Some(slot) = self.xn.get_mut(mres) {
                    *slot = if enc { y } else { x };
                }
                mres = mres.wrapping_add(1);
                i = i.wrapping_add(1);
                n = n.wrapping_add(1) % BLOCK;
            }
            if n == 0 {
                self.ghash_xn(mres);
                mres = 0;
            } else {
                self.mres = mres;
                return 0;
            }
        }
        if len.saturating_sub(i) >= BLOCK && mres != 0 {
            self.ghash_xn(mres);
            mres = 0;
        }
        // Whole blocks: in strides of GHASH_CHUNK, then the rest.
        while len.saturating_sub(i) >= BLOCK {
            let rest = len.saturating_sub(i) & !(BLOCK - 1);
            let take = if rest >= GHASH_CHUNK {
                GHASH_CHUNK
            } else {
                rest
            };
            let end = i.saturating_add(take);
            let chunk = input.get(i..end).unwrap_or_default();
            if !enc {
                self.ghash(chunk);
            }
            if let Some(f) = stream {
                let blocks = take / BLOCK;
                if let Some(o) = out.get_mut(i..end) {
                    f.ctr(chunk, o, blocks, &self.yi);
                }
                ctr = ctr.wrapping_add(u32::try_from(blocks).unwrap_or(0));
                self.set_ctr(ctr);
            } else {
                for k in (i..end).step_by(BLOCK) {
                    self.next_keystream(&mut ctr, b);
                    for (j, e) in self.eki.iter().enumerate() {
                        if let Some(o) = out.get_mut(k.saturating_add(j)) {
                            *o = at(input, k.saturating_add(j)) ^ e;
                        }
                    }
                }
            }
            if enc {
                let written = out.get(i..end).unwrap_or_default().to_vec();
                self.ghash(&written);
            }
            i = end;
        }
        if i < len {
            self.next_keystream(&mut ctr, b);
            while i < len {
                let x = at(input, i);
                let y = x ^ at(&self.eki, n);
                if let Some(o) = out.get_mut(i) {
                    *o = y;
                }
                if let Some(slot) = self.xn.get_mut(mres) {
                    *slot = if enc { y } else { x };
                }
                mres = mres.wrapping_add(1);
                n = n.wrapping_add(1);
                i = i.wrapping_add(1);
            }
        }
        self.mres = mres;
        0
    }

    /// `CRYPTO_gcm128_encrypt`.
    pub fn encrypt(&mut self, input: &[u8], out: &mut [u8], b: &impl Block128) -> i32 {
        crate::dit::with(|| self.crypt(input, out, b, None, true))
    }

    /// `CRYPTO_gcm128_decrypt`.
    pub fn decrypt(&mut self, input: &[u8], out: &mut [u8], b: &impl Block128) -> i32 {
        crate::dit::with(|| self.crypt(input, out, b, None, false))
    }

    /// `CRYPTO_gcm128_encrypt_ctr32`: whole blocks through `stream`.
    pub fn encrypt_ctr32(
        &mut self,
        input: &[u8],
        out: &mut [u8],
        b: &impl Block128,
        stream: &impl Ctr128,
    ) -> i32 {
        crate::dit::with(|| self.crypt(input, out, b, Some(stream), true))
    }

    /// `CRYPTO_gcm128_decrypt_ctr32`: whole blocks through `stream`.
    pub fn decrypt_ctr32(
        &mut self,
        input: &[u8],
        out: &mut [u8],
        b: &impl Block128,
        stream: &impl Ctr128,
    ) -> i32 {
        crate::dit::with(|| self.crypt(input, out, b, Some(stream), false))
    }

    /// `CRYPTO_gcm128_finish`: hashes what's buffered and the lengths into the tag, then
    /// compares the first `tag.len()` (at most 16) octets with `tag`: 0 if equal, 1 if not, -1
    /// with no tag or a longer one. Nothing is reset, so another `finish` hashes again.
    pub fn finish(&mut self, tag: Option<&[u8]>) -> i32 {
        crate::dit::with(|| {
            let mut mres = self.mres;
            if mres != 0 {
                let blocks = mres.next_multiple_of(BLOCK);
                for x in self.xn.iter_mut().take(blocks).skip(mres) {
                    *x = 0;
                }
                mres = blocks;
                if mres == self.xn.len() {
                    self.ghash_xn(mres);
                    mres = 0;
                }
            } else if self.ares != 0 {
                self.mul();
            }
            put(&mut self.xn, mres, &self.alen.wrapping_shl(3).to_be_bytes());
            put(
                &mut self.xn,
                mres.saturating_add(8),
                &self.mlen.wrapping_shl(3).to_be_bytes(),
            );
            self.ghash_xn(mres.saturating_add(BLOCK));
            let ek0 = self.ek0;
            xor_into(&mut self.xi, &ek0);
            match tag {
                Some(t) if t.len() <= BLOCK => memcmp(&self.xi, t, t.len()),
                _ => -1,
            }
        })
    }

    /// `CRYPTO_gcm128_tag`: a `finish` without a tag, then the first `out.len()` (at most 16)
    /// octets of the tag.
    pub fn tag(&mut self, out: &mut [u8]) {
        crate::dit::with(|| {
            self.finish(None);
            put(out, 0, &self.xi);
        })
    }
}

/// A whole-block CCM function (`ccm128_f`): `blocks` blocks of `input` encrypted or decrypted
/// into `out` under the counter block `ivec` (which it leaves as it was), the plaintext folded
/// into `cmac`.
pub trait Ccm128 {
    /// Processes `blocks` blocks.
    fn ccm(
        &self,
        input: &[u8],
        out: &mut [u8],
        blocks: usize,
        ivec: &[u8; BLOCK],
        cmac: &mut [u8; BLOCK],
    );
}

/// `CCM128_CONTEXT` (`modes_local.h`): the nonce block (flags, nonce, and length or counter),
/// the CBC-MAC, and the count of blocks the key has processed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ccm {
    /// The nonce block.
    pub nonce: [u8; BLOCK],
    /// The CBC-MAC.
    pub cmac: [u8; BLOCK],
    /// The blocks encrypted under the key so far.
    pub blocks: u64,
}

/// The CCM limit on blocks under one key, 2^61.
const CCM_MAX_BLOCKS: u64 = 1 << 61;

impl Ccm {
    /// `CRYPTO_ccm128_init`: the flags for an `m`-octet tag and an `l`-octet length field (the
    /// CBC-MAC keeps its octets).
    pub fn init(&mut self, m: u32, l: u32) {
        self.nonce = [0; BLOCK];
        let l_bits = l.wrapping_sub(1) & 7;
        let m_bits = (m.wrapping_sub(2) / 2) & 7;
        self.nonce[0] = u8::try_from(l_bits | (m_bits << 3)).unwrap_or(0);
        self.blocks = 0;
    }

    /// The length field's size, from the flags.
    fn l(&self) -> usize {
        usize::from(self.nonce[0] & 7)
    }

    /// `CRYPTO_ccm128_setiv`: the nonce (its first `14 - L` octets) and the message length.
    /// Returns 0, or -1 for a nonce too short.
    pub fn setiv(&mut self, nonce: &[u8], mlen: usize) -> i32 {
        crate::dit::with(|| {
            let l = self.l();
            let need = 14usize.saturating_sub(l);
            if nonce.len() < need {
                return -1;
            }
            let m = u64::try_from(mlen).unwrap_or(u64::MAX).to_be_bytes();
            if l >= 3 {
                put(&mut self.nonce, 8, m.get(..4).unwrap_or_default());
            } else {
                put(&mut self.nonce, 8, &[0; 4]);
            }
            put(&mut self.nonce, 12, m.get(4..).unwrap_or_default());
            self.nonce[0] &= !0x40;
            put(&mut self.nonce, 1, nonce.get(..need).unwrap_or_default());
            0
        })
    }

    /// `CRYPTO_ccm128_aad`: starts the CBC-MAC with the nonce block (the Adata flag set) and
    /// absorbs the AAD with its length encoding. Nothing for no AAD.
    pub fn aad(&mut self, aad: &[u8], b: &impl Block128) {
        crate::dit::with(|| {
            let alen = aad.len();
            if alen == 0 {
                return;
            }
            self.nonce[0] |= 0x40;
            self.cmac = b.block(&self.nonce);
            self.blocks = self.blocks.wrapping_add(1);
            let a = u64::try_from(alen).unwrap_or(u64::MAX).to_be_bytes();
            let mut head = [0u8; 10];
            let i = if alen < 0x10000 - 0x100 {
                put(&mut head, 0, a.get(6..).unwrap_or_default());
                2
            } else if alen >= 1 << 32 {
                head[0] = 0xff;
                head[1] = 0xff;
                put(&mut head, 2, &a);
                10
            } else {
                head[0] = 0xff;
                head[1] = 0xfe;
                put(&mut head, 2, a.get(4..).unwrap_or_default());
                6
            };
            for (c, h) in self.cmac.iter_mut().zip(head.iter().take(i)) {
                *c ^= h;
            }
            let mut i = i;
            let mut aad = aad;
            loop {
                while i < BLOCK && !aad.is_empty() {
                    if let (Some(c), Some(x)) = (self.cmac.get_mut(i), aad.first()) {
                        *c ^= x;
                    }
                    aad = aad.get(1..).unwrap_or_default();
                    i = i.wrapping_add(1);
                }
                self.cmac = b.block(&self.cmac);
                self.blocks = self.blocks.wrapping_add(1);
                i = 0;
                if aad.is_empty() {
                    break;
                }
            }
        })
    }

    /// The common start: the CBC-MAC's first block (without AAD), the counter set to 1, and
    /// the length checked against the nonce block's. Returns the flags and the length field's
    /// size, or `Err` for a length mismatch (leaving the nonce block as OpenSSL does).
    fn start(&mut self, len: usize, b: &impl Block128, count: bool) -> Result<(u8, usize), i32> {
        let flags0 = self.nonce[0];
        if flags0 & 0x40 == 0 {
            self.cmac = b.block(&self.nonce);
            if count {
                self.blocks = self.blocks.wrapping_add(1);
            }
        }
        let l = usize::from(flags0 & 7);
        self.nonce[0] = flags0 & 7;
        let mut n: u64 = 0;
        for i in 15usize.saturating_sub(l)..15 {
            n |= u64::from(at(&self.nonce, i));
            if let Some(x) = self.nonce.get_mut(i) {
                *x = 0;
            }
            n = n.wrapping_shl(8);
        }
        n |= u64::from(self.nonce[15]);
        self.nonce[15] = 1;
        if n != u64::try_from(len).unwrap_or(u64::MAX) {
            return Err(-1);
        }
        Ok((flags0, l))
    }

    /// Increments the counter, the nonce block's last 8 octets.
    fn ctr64_inc(&mut self) {
        for x in self.nonce.iter_mut().skip(8).rev() {
            *x = x.wrapping_add(1);
            if *x != 0 {
                return;
            }
        }
    }

    /// Adds `inc` to the counter.
    fn ctr64_add(&mut self, inc: usize) {
        let mut c = u64::from_be_bytes(
            block_at(&self.nonce, 8)
                .get(..8)
                .and_then(|s| s.try_into().ok())
                .unwrap_or([0; 8]),
        );
        c = c.wrapping_add(u64::try_from(inc).unwrap_or(0));
        put(&mut self.nonce, 8, &c.to_be_bytes());
    }

    /// The end: the counter block 0's keystream into the CBC-MAC, making the tag, and the
    /// flags back.
    fn end(&mut self, flags0: u8, l: usize, b: &impl Block128) {
        for x in self.nonce.iter_mut().skip(15usize.saturating_sub(l)) {
            *x = 0;
        }
        let s = b.block(&self.nonce);
        xor_into(&mut self.cmac, &s);
        self.nonce[0] = flags0;
    }

    /// Encrypts (`enc`) or decrypts, the whole blocks through `stream` if given:
    /// `CRYPTO_ccm128_{en,de}crypt[_ccm64]`. Returns 0, -1 for a length other than the one set,
    /// or -2 (encrypting) past 2^61 blocks under the key.
    fn crypt(
        &mut self,
        input: &[u8],
        out: &mut [u8],
        b: &impl Block128,
        stream: Option<&dyn Ccm128>,
        enc: bool,
    ) -> i32 {
        let len = input.len();
        let (flags0, l) = match self.start(len, b, enc) {
            Ok(x) => x,
            Err(r) => return r,
        };
        if enc {
            let add = u64::try_from(len.saturating_add(15) >> 3).unwrap_or(u64::MAX) | 1;
            self.blocks = self.blocks.wrapping_add(add);
            if self.blocks > CCM_MAX_BLOCKS {
                return -2;
            }
        }
        let mut i = 0;
        if let Some(f) = stream {
            let blocks = len / BLOCK;
            if blocks != 0 {
                let end = blocks.saturating_mul(BLOCK);
                if let Some(o) = out.get_mut(..end) {
                    f.ccm(
                        input.get(..end).unwrap_or_default(),
                        o,
                        blocks,
                        &self.nonce,
                        &mut self.cmac,
                    );
                }
                i = end;
                if i < len {
                    self.ctr64_add(blocks);
                }
            }
        } else {
            while len.saturating_sub(i) >= BLOCK {
                let x = block_at(input, i);
                if enc {
                    xor_into(&mut self.cmac, &x);
                    self.cmac = b.block(&self.cmac);
                    let s = b.block(&self.nonce);
                    self.ctr64_inc();
                    let mut y = x;
                    xor_into(&mut y, &s);
                    put(out, i, &y);
                } else {
                    let s = b.block(&self.nonce);
                    self.ctr64_inc();
                    let mut y = x;
                    xor_into(&mut y, &s);
                    put(out, i, &y);
                    xor_into(&mut self.cmac, &y);
                    self.cmac = b.block(&self.cmac);
                }
                i = i.saturating_add(BLOCK);
            }
        }
        let rest = len.saturating_sub(i);
        if rest != 0 {
            if enc {
                for k in 0..rest {
                    if let Some(c) = self.cmac.get_mut(k) {
                        *c ^= at(input, i.saturating_add(k));
                    }
                }
                self.cmac = b.block(&self.cmac);
                let s = b.block(&self.nonce);
                for k in 0..rest {
                    if let Some(o) = out.get_mut(i.saturating_add(k)) {
                        *o = at(&s, k) ^ at(input, i.saturating_add(k));
                    }
                }
            } else {
                let s = b.block(&self.nonce);
                for k in 0..rest {
                    let y = at(&s, k) ^ at(input, i.saturating_add(k));
                    if let Some(o) = out.get_mut(i.saturating_add(k)) {
                        *o = y;
                    }
                    if let Some(c) = self.cmac.get_mut(k) {
                        *c ^= y;
                    }
                }
                self.cmac = b.block(&self.cmac);
            }
        }
        self.end(flags0, l, b);
        0
    }

    /// `CRYPTO_ccm128_encrypt`.
    pub fn encrypt(&mut self, input: &[u8], out: &mut [u8], b: &impl Block128) -> i32 {
        crate::dit::with(|| self.crypt(input, out, b, None, true))
    }

    /// `CRYPTO_ccm128_decrypt`.
    pub fn decrypt(&mut self, input: &[u8], out: &mut [u8], b: &impl Block128) -> i32 {
        crate::dit::with(|| self.crypt(input, out, b, None, false))
    }

    /// `CRYPTO_ccm128_encrypt_ccm64`.
    pub fn encrypt_ccm64(
        &mut self,
        input: &[u8],
        out: &mut [u8],
        b: &impl Block128,
        stream: &impl Ccm128,
    ) -> i32 {
        crate::dit::with(|| self.crypt(input, out, b, Some(stream), true))
    }

    /// `CRYPTO_ccm128_decrypt_ccm64`.
    pub fn decrypt_ccm64(
        &mut self,
        input: &[u8],
        out: &mut [u8],
        b: &impl Block128,
        stream: &impl Ccm128,
    ) -> i32 {
        crate::dit::with(|| self.crypt(input, out, b, Some(stream), false))
    }

    /// `CRYPTO_ccm128_tag`: the tag into `tag` if `len` is the configured size; returns that
    /// size, or 0.
    pub fn tag(&self, tag: &mut [u8], len: usize) -> usize {
        crate::dit::with(|| {
            let m = usize::from((self.nonce[0] >> 3) & 7)
                .saturating_mul(2)
                .saturating_add(2);
            if len != m {
                return 0;
            }
            put(tag, 0, self.cmac.get(..m).unwrap_or_default());
            m
        })
    }
}

/// XTS (`CRYPTO_xts128_encrypt`) of `input` into `out` with the data block function `b1` and
/// the tweak block function `b2`, a partial last block by ciphertext stealing. Returns 0, or
/// -1 for less than a block.
pub fn xts(
    iv: &[u8; BLOCK],
    input: &[u8],
    out: &mut [u8],
    enc: bool,
    b1: &impl Block128,
    b2: &impl Block128,
) -> i32 {
    crate::dit::with(|| {
        let total = input.len();
        if total < BLOCK {
            return -1;
        }
        let mut tweak = b2.block(iv);
        let mut len = total;
        if !enc && !total.is_multiple_of(BLOCK) {
            len = len.saturating_sub(BLOCK);
        }
        let mut scratch = [0u8; BLOCK];
        let mut i = 0;
        while len >= BLOCK {
            scratch = block_at(input, i);
            xor_into(&mut scratch, &tweak);
            scratch = b1.block(&scratch);
            xor_into(&mut scratch, &tweak);
            put(out, i, &scratch);
            i = i.saturating_add(BLOCK);
            len = len.saturating_sub(BLOCK);
            if len == 0 {
                return 0;
            }
            tweak = xts_double(&tweak);
        }
        if enc {
            for k in 0..len {
                let c = at(input, i.saturating_add(k));
                if let Some(o) = out.get_mut(i.saturating_add(k)) {
                    *o = at(&scratch, k);
                }
                if let Some(s) = scratch.get_mut(k) {
                    *s = c;
                }
            }
            xor_into(&mut scratch, &tweak);
            scratch = b1.block(&scratch);
            xor_into(&mut scratch, &tweak);
            put(out, i.saturating_sub(BLOCK), &scratch);
        } else {
            let tweak1 = xts_double(&tweak);
            scratch = block_at(input, i);
            xor_into(&mut scratch, &tweak1);
            scratch = b1.block(&scratch);
            xor_into(&mut scratch, &tweak1);
            for k in 0..len {
                let c = at(input, i.saturating_add(BLOCK).saturating_add(k));
                if let Some(o) = out.get_mut(i.saturating_add(BLOCK).saturating_add(k)) {
                    *o = at(&scratch, k);
                }
                if let Some(s) = scratch.get_mut(k) {
                    *s = c;
                }
            }
            xor_into(&mut scratch, &tweak);
            scratch = b1.block(&scratch);
            xor_into(&mut scratch, &tweak);
            put(out, i, &scratch);
        }
        scratch.zeroize();
        0
    })
}

/// XTS's tweak times x in GF(2^128), little-endian.
fn xts_double(t: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut out = [0u8; BLOCK];
    let mut carry = 0u8;
    for (o, x) in out.iter_mut().zip(t) {
        *o = (x << 1) | carry;
        carry = x >> 7;
    }
    out[0] ^= 0x87 & 0u8.wrapping_sub(carry);
    out
}

/// A whole-block OCB function (`ocb128_f`): `blocks` blocks from block number `start`,
/// updating the offset and the checksum, with the table of `L_i`.
pub trait Ocb128 {
    /// Processes `blocks` blocks.
    #[allow(clippy::too_many_arguments)]
    fn ocb(
        &self,
        input: &[u8],
        out: &mut [u8],
        blocks: usize,
        start: usize,
        offset: &mut [u8; BLOCK],
        l: &[[u8; BLOCK]],
        checksum: &mut [u8; BLOCK],
    );
}

/// The most `L_i` an OCB context needs: one per bit of a 64-bit block count.
pub const OCB_MAX_L: usize = 64;

/// An OCB context: `L_*`, `L_$`, the `L_i` computed so far, and the session's block counts,
/// offsets, sum, and checksum.
#[derive(Clone)]
pub struct Ocb {
    l_star: [u8; BLOCK],
    l_dollar: [u8; BLOCK],
    l: [[u8; BLOCK]; OCB_MAX_L],
    l_index: usize,
    blocks_hashed: u64,
    blocks_processed: u64,
    offset_aad: [u8; BLOCK],
    sum: [u8; BLOCK],
    offset: [u8; BLOCK],
    checksum: [u8; BLOCK],
}

impl core::fmt::Debug for Ocb {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ocb").finish_non_exhaustive()
    }
}

impl Drop for Ocb {
    fn drop(&mut self) {
        self.l_star.zeroize();
        self.l_dollar.zeroize();
        self.l.zeroize();
        self.offset_aad.zeroize();
        self.sum.zeroize();
        self.offset.zeroize();
        self.checksum.zeroize();
    }
}

/// OCB's doubling in GF(2^128), big-endian.
fn ocb_double(x: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mask = 0x87 & 0u8.wrapping_sub(x[0] >> 7);
    let mut out = [0u8; BLOCK];
    let mut carry = 0u8;
    for (o, v) in out.iter_mut().zip(x).rev() {
        *o = (v << 1) | carry;
        carry = v >> 7;
    }
    out[15] ^= mask;
    out
}

/// The trailing zero bits of `n` (nonzero).
fn ntz(n: u64) -> usize {
    usize::try_from(n.trailing_zeros()).unwrap_or(0)
}

impl Ocb {
    /// `CRYPTO_ocb128_init`: `L_*` is the encryption of zeros, `L_$` and `L_0`..`L_4` its
    /// doublings.
    pub fn new(e: &impl Block128) -> Self {
        crate::dit::with(|| {
            let l_star = e.block(&[0; BLOCK]);
            let l_dollar = ocb_double(&l_star);
            let mut l = [[0u8; BLOCK]; OCB_MAX_L];
            let mut prev = l_dollar;
            for slot in l.iter_mut().take(5) {
                prev = ocb_double(&prev);
                *slot = prev;
            }
            Self {
                l_star,
                l_dollar,
                l,
                l_index: 4,
                blocks_hashed: 0,
                blocks_processed: 0,
                offset_aad: [0; BLOCK],
                sum: [0; BLOCK],
                offset: [0; BLOCK],
                checksum: [0; BLOCK],
            }
        })
    }

    /// `L_idx`, computing the ones up to it.
    fn lookup(&mut self, idx: usize) -> [u8; BLOCK] {
        let idx = idx.min(OCB_MAX_L - 1);
        while self.l_index < idx {
            let next = ocb_double(&self.l.get(self.l_index).copied().unwrap_or_default());
            self.l_index = self.l_index.saturating_add(1);
            if let Some(slot) = self.l.get_mut(self.l_index) {
                *slot = next;
            }
        }
        self.l.get(idx).copied().unwrap_or_default()
    }

    /// `CRYPTO_ocb128_setiv`: a nonce of 1 to 15 octets and a tag of 1 to 16. Returns 1, or
    /// -1.
    pub fn setiv(&mut self, iv: &[u8], taglen: usize, e: &impl Block128) -> i32 {
        crate::dit::with(|| {
            let len = iv.len();
            if !(1..=15).contains(&len) || !(1..=16).contains(&taglen) {
                return -1;
            }
            self.blocks_hashed = 0;
            self.blocks_processed = 0;
            self.offset_aad = [0; BLOCK];
            self.sum = [0; BLOCK];
            self.offset = [0; BLOCK];
            self.checksum = [0; BLOCK];
            let mut nonce = [0u8; BLOCK];
            nonce[0] = u8::try_from((taglen.saturating_mul(8) % 128) << 1).unwrap_or(0);
            put(&mut nonce, BLOCK.saturating_sub(len), iv);
            if let Some(x) = nonce.get_mut(15usize.saturating_sub(len)) {
                *x |= 1;
            }
            let mut tmp = nonce;
            tmp[15] &= 0xc0;
            let mut ktop = e.block(&tmp);
            let mut stretch = [0u8; 24];
            put(&mut stretch, 0, &ktop);
            for (k, s) in stretch.iter_mut().skip(BLOCK).enumerate() {
                *s = at(&ktop, k) ^ at(&ktop, k.saturating_add(1));
            }
            let bottom = usize::from(nonce[15] & 0x3f);
            let shift = bottom % 8;
            let base = bottom / 8;
            for k in 0..BLOCK {
                let hi = at(&stretch, base.saturating_add(k));
                let lo = if k == 15 {
                    0
                } else {
                    at(&stretch, base.saturating_add(k).saturating_add(1))
                };
                let v = if shift == 0 {
                    hi
                } else {
                    (hi << shift) | (lo >> 8usize.wrapping_sub(shift))
                };
                if let Some(o) = self.offset.get_mut(k) {
                    *o = v;
                }
            }
            if shift != 0 {
                let back = 8usize.wrapping_sub(shift);
                let mask = 0xffu8 << back;
                self.offset[15] |= (at(&stretch, base.saturating_add(16)) & mask) >> back;
            }
            ktop.zeroize();
            stretch.zeroize();
            1
        })
    }

    /// `CRYPTO_ocb128_aad`: whole blocks into the sum, and a partial last block (which only
    /// the last call may have). Returns 1.
    pub fn aad(&mut self, aad: &[u8], e: &impl Block128) -> i32 {
        crate::dit::with(|| {
            let (blocks, rest) = aad.as_chunks::<BLOCK>();
            for block in blocks {
                self.blocks_hashed = self.blocks_hashed.wrapping_add(1);
                let li = self.lookup(ntz(self.blocks_hashed));
                xor_into(&mut self.offset_aad, &li);
                let mut tmp = *block;
                xor_into(&mut tmp, &self.offset_aad);
                let enc = e.block(&tmp);
                xor_into(&mut self.sum, &enc);
            }
            if !rest.is_empty() {
                let ls = self.l_star;
                xor_into(&mut self.offset_aad, &ls);
                let mut tmp = block_at(rest, 0);
                if let Some(x) = tmp.get_mut(rest.len()) {
                    *x = 0x80;
                }
                xor_into(&mut tmp, &self.offset_aad);
                let enc = e.block(&tmp);
                xor_into(&mut self.sum, &enc);
            }
            1
        })
    }

    /// Encrypts (`enc`, with `e`) or decrypts (with `d`), the whole blocks through `stream`
    /// if given (from block number `blocks_processed + 1`, the table computed far enough).
    /// Returns 1.
    #[allow(clippy::too_many_arguments)]
    fn crypt(
        &mut self,
        input: &[u8],
        out: &mut [u8],
        e: &impl Block128,
        d: &impl Block128,
        stream: Option<&dyn Ocb128>,
        enc: bool,
    ) -> i32 {
        let num_blocks = input.len() / BLOCK;
        let all = self
            .blocks_processed
            .wrapping_add(u64::try_from(num_blocks).unwrap_or(u64::MAX));
        let mut i = 0;
        if let Some(f) = stream.filter(|_| num_blocks != 0) {
            let mut top = all;
            let mut max_idx: usize = 0;
            while top > 1 {
                top >>= 1;
                max_idx = max_idx.saturating_add(1);
            }
            self.lookup(max_idx);
            let end = num_blocks.saturating_mul(BLOCK);
            let start = usize::try_from(self.blocks_processed)
                .unwrap_or(usize::MAX)
                .wrapping_add(1);
            let table = self.l;
            if let Some(o) = out.get_mut(..end) {
                f.ocb(
                    input.get(..end).unwrap_or_default(),
                    o,
                    num_blocks,
                    start,
                    &mut self.offset,
                    &table,
                    &mut self.checksum,
                );
            }
            i = end;
        } else {
            let mut n = self.blocks_processed;
            for _ in 0..num_blocks {
                n = n.wrapping_add(1);
                let li = self.lookup(ntz(n));
                xor_into(&mut self.offset, &li);
                let x = block_at(input, i);
                let y = if enc {
                    xor_into(&mut self.checksum, &x);
                    let mut t = x;
                    xor_into(&mut t, &self.offset);
                    let mut c = e.block(&t);
                    xor_into(&mut c, &self.offset);
                    c
                } else {
                    let mut t = x;
                    xor_into(&mut t, &self.offset);
                    let mut p = d.block(&t);
                    xor_into(&mut p, &self.offset);
                    xor_into(&mut self.checksum, &p);
                    p
                };
                put(out, i, &y);
                i = i.saturating_add(BLOCK);
            }
        }
        let last = input.len() % BLOCK;
        if last != 0 {
            let ls = self.l_star;
            xor_into(&mut self.offset, &ls);
            let pad = e.block(&self.offset);
            let mut plain = [0u8; BLOCK];
            for k in 0..last {
                let x = at(input, i.saturating_add(k));
                let y = x ^ at(&pad, k);
                if let Some(o) = out.get_mut(i.saturating_add(k)) {
                    *o = y;
                }
                if let Some(p) = plain.get_mut(k) {
                    *p = if enc { x } else { y };
                }
            }
            if let Some(p) = plain.get_mut(last) {
                *p = 0x80;
            }
            xor_into(&mut self.checksum, &plain);
        }
        self.blocks_processed = all;
        1
    }

    /// `CRYPTO_ocb128_encrypt`.
    pub fn encrypt(
        &mut self,
        input: &[u8],
        out: &mut [u8],
        e: &impl Block128,
        d: &impl Block128,
        stream: Option<&dyn Ocb128>,
    ) -> i32 {
        crate::dit::with(|| self.crypt(input, out, e, d, stream, true))
    }

    /// `CRYPTO_ocb128_decrypt`.
    pub fn decrypt(
        &mut self,
        input: &[u8],
        out: &mut [u8],
        e: &impl Block128,
        d: &impl Block128,
        stream: Option<&dyn Ocb128>,
    ) -> i32 {
        crate::dit::with(|| self.crypt(input, out, e, d, stream, false))
    }

    /// The tag: `ENCIPHER(Checksum xor Offset xor L_$) xor Sum`.
    fn compute_tag(&self, e: &impl Block128) -> [u8; BLOCK] {
        let mut t = self.checksum;
        xor_into(&mut t, &self.offset);
        xor_into(&mut t, &self.l_dollar);
        let mut tag = e.block(&t);
        xor_into(&mut tag, &self.sum);
        tag
    }

    /// `CRYPTO_ocb128_finish`: compares the first `tag.len()` (1 to 16) octets of the tag with
    /// `tag`: 0 if equal, 1 if not, -1 for another length.
    pub fn finish(&self, tag: &[u8], e: &impl Block128) -> i32 {
        crate::dit::with(|| {
            if !(1..=BLOCK).contains(&tag.len()) {
                return -1;
            }
            let mut t = self.compute_tag(e);
            let r = memcmp(&t, tag, tag.len());
            t.zeroize();
            r
        })
    }

    /// `CRYPTO_ocb128_tag`: the first `out.len()` (1 to 16) octets of the tag. Returns 1, or
    /// -1 for another length.
    pub fn tag(&self, out: &mut [u8], e: &impl Block128) -> i32 {
        crate::dit::with(|| {
            if !(1..=BLOCK).contains(&out.len()) {
                return -1;
            }
            let mut t = self.compute_tag(e);
            put(out, 0, &t);
            t.zeroize();
            1
        })
    }
}

#[cfg(test)]
mod tests;
