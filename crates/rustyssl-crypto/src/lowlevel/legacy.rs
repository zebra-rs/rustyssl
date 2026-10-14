//! The deprecated low-level legacy ciphers: Blowfish (`BF_set_key(3)`), CAST-128
//! (`CAST_set_key`), RC2 (`RC2_set_key`), and RC4 (`RC4_set_key(3)`), with the 64-bit block
//! modes they share (ECB, CBC, CFB-64, OFB-64).
//!
//! Applications keep the key structs themselves and can see them, so the key schedules are
//! OpenSSL's, over its tables ([`tables`], extracted from its sources), and RC4's state is its
//! permutation as OpenSSL keeps it. These ciphers index tables (or, for Blowfish and RC4,
//! key-dependent state) by secret values; every such read and write here scans the whole table
//! and keeps or changes the entry by a mask, so no secret picks an address (OpenSSL's, and the
//! RustCrypto crates', index directly).
//!
//! The modes follow OpenSSL's steps (`bf_enc.c`'s `BF_cbc_encrypt`, `bf_cfb64.c`, ...), which
//! are the same for each cipher but for how a block's octets become words; they act on
//! octets here, through [`Block64`].

mod tables;

use tables::{BF_P, BF_S, CAST_S, RC2_PITABLE};
use zeroize::Zeroize;

/// The entry at `idx`, reading every entry and keeping the one at `idx` by a mask.
fn ct_get(table: &[u32], idx: usize) -> u32 {
    let mut r = 0u32;
    for (i, v) in table.iter().enumerate() {
        let d = i ^ idx;
        let hit = ((d | d.wrapping_neg()) >> (usize::BITS - 1)) ^ 1;
        r |= v & 0u32.wrapping_sub(u32::try_from(hit).unwrap_or(0));
    }
    r
}

/// Sets the entry at `idx`, writing every entry (each its own value but the one at `idx`).
fn ct_set(table: &mut [u32], idx: usize, value: u32) {
    for (i, v) in table.iter_mut().enumerate() {
        let d = i ^ idx;
        let hit = ((d | d.wrapping_neg()) >> (usize::BITS - 1)) ^ 1;
        let mask = 0u32.wrapping_sub(u32::try_from(hit).unwrap_or(0));
        *v = (*v & !mask) | (value & mask);
    }
}

/// The octet table entry at `idx`, by a scan.
fn ct_get8(table: &[u8], idx: usize) -> u8 {
    let mut r = 0u8;
    for (i, v) in table.iter().enumerate() {
        let d = i ^ idx;
        let hit = ((d | d.wrapping_neg()) >> (usize::BITS - 1)) ^ 1;
        r |= v & 0u8.wrapping_sub(u8::try_from(hit).unwrap_or(0));
    }
    r
}

/// A 64-bit block cipher for the modes.
pub trait Block64 {
    /// Encrypts one block.
    fn encrypt(&self, block: &[u8; 8]) -> [u8; 8];
    /// Decrypts one block.
    fn decrypt(&self, block: &[u8; 8]) -> [u8; 8];
}

/// The block at `at`, zero-filled past the end.
fn block_at(data: &[u8], at: usize) -> [u8; 8] {
    core::array::from_fn(|i| data.get(at.saturating_add(i)).copied().unwrap_or(0))
}

/// Copies `src` into `out` from `at`, as far as `out` reaches.
fn put(out: &mut [u8], at: usize, src: &[u8]) {
    for (d, s) in out.iter_mut().skip(at).zip(src) {
        *d = *s;
    }
}

/// XOR of two blocks.
fn xor8(a: &[u8; 8], b: &[u8; 8]) -> [u8; 8] {
    let mut o = *a;
    for (x, y) in o.iter_mut().zip(b) {
        *x ^= y;
    }
    o
}

/// ECB: one block.
pub fn ecb(input: &[u8; 8], c: &impl Block64, enc: bool) -> [u8; 8] {
    if enc {
        c.encrypt(input)
    } else {
        c.decrypt(input)
    }
}

/// CBC over `len` octets, updating the IV (`BF_cbc_encrypt` and the others): encryption reads
/// `len` and writes it rounded up to whole blocks (a partial last block padded with zeros);
/// decryption reads it rounded up and writes `len`.
pub fn cbc(
    input: &[u8],
    out: &mut [u8],
    len: usize,
    c: &impl Block64,
    iv: &mut [u8; 8],
    enc: bool,
) {
    let blocks = len.div_ceil(8);
    for i in 0..blocks {
        let at = i.saturating_mul(8);
        let n = len.saturating_sub(at).min(8);
        if enc {
            let mut x = [0u8; 8];
            put(
                &mut x,
                0,
                input.get(at..at.saturating_add(n)).unwrap_or_default(),
            );
            *iv = c.encrypt(&xor8(&x, iv));
            put(out, at, iv);
        } else {
            let x = block_at(input, at);
            let p = xor8(&c.decrypt(&x), iv);
            put(out, at, p.get(..n).unwrap_or_default());
            *iv = x;
        }
    }
}

/// CFB-64 by octets: `num`'s low three bits are the position in the IV, which becomes the
/// ciphertext as it goes.
pub fn cfb64(
    input: &[u8],
    out: &mut [u8],
    c: &impl Block64,
    iv: &mut [u8; 8],
    num: &mut i32,
    enc: bool,
) {
    let mut n = usize::try_from(*num & 7).unwrap_or(0);
    for (i, x) in input.iter().enumerate() {
        if n == 0 {
            *iv = c.encrypt(iv);
        }
        let k = iv.get(n).copied().unwrap_or(0);
        let (o, keep) = if enc { (x ^ k, x ^ k) } else { (x ^ k, *x) };
        if let Some(d) = out.get_mut(i) {
            *d = o;
        }
        if let Some(v) = iv.get_mut(n) {
            *v = keep;
        }
        n = n.wrapping_add(1) & 7;
    }
    *num = i32::try_from(n).unwrap_or(0);
}

/// OFB-64 by octets: `num`'s low three bits are the position in the keystream block, which
/// goes back into the IV only if a new one was made.
pub fn ofb64(input: &[u8], out: &mut [u8], c: &impl Block64, iv: &mut [u8; 8], num: &mut i32) {
    let mut n = usize::try_from(*num & 7).unwrap_or(0);
    let mut d = *iv;
    let mut made = false;
    for (i, x) in input.iter().enumerate() {
        if n == 0 {
            d = c.encrypt(&d);
            made = true;
        }
        if let Some(o) = out.get_mut(i) {
            *o = x ^ d.get(n).copied().unwrap_or(0);
        }
        n = n.wrapping_add(1) & 7;
    }
    if made {
        *iv = d;
    }
    d.zeroize();
    *num = i32::try_from(n).unwrap_or(0);
}

/// A block as two big-endian words.
fn be_words(b: &[u8; 8]) -> [u32; 2] {
    [
        u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
    ]
}

/// Two big-endian words as a block.
fn be_block(w: [u32; 2]) -> [u8; 8] {
    let [a, b] = w.map(u32::to_be_bytes);
    [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]]
}

/// A Blowfish key (`BF_KEY`): the P-array and the four S-boxes.
#[derive(Clone)]
pub struct BfKey {
    /// The P-array.
    pub p: [u32; 18],
    /// The S-boxes, one after another.
    pub s: [u32; 1024],
}

impl Drop for BfKey {
    fn drop(&mut self) {
        self.p.zeroize();
        self.s.zeroize();
    }
}

impl BfKey {
    /// Blowfish's F: the S-boxes at each octet of `x`.
    fn f(&self, x: u32) -> u32 {
        let [a, b, c, d] = x.to_be_bytes();
        let s = |k: usize, i: u8| {
            ct_get(
                self.s
                    .as_chunks::<256>()
                    .0
                    .get(k)
                    .map_or(&[][..], |t| &t[..]),
                usize::from(i),
            )
        };
        (s(0, a).wrapping_add(s(1, b)) ^ s(2, c)).wrapping_add(s(3, d))
    }

    /// `BF_encrypt`: two words.
    pub fn encrypt_words(&self, data: &mut [u32; 2]) {
        let p = |i: usize| self.p.get(i).copied().unwrap_or(0);
        let [mut l, mut r] = *data;
        l ^= p(0);
        for i in (1..=16).step_by(2) {
            r ^= p(i) ^ self.f(l);
            l ^= p(i.wrapping_add(1)) ^ self.f(r);
        }
        r ^= p(17);
        *data = [r, l];
    }

    /// `BF_decrypt`: two words.
    pub fn decrypt_words(&self, data: &mut [u32; 2]) {
        let p = |i: usize| self.p.get(i).copied().unwrap_or(0);
        let [mut l, mut r] = *data;
        l ^= p(17);
        for i in (1..=16).rev().step_by(2) {
            r ^= p(i) ^ self.f(l);
            l ^= p(i.wrapping_sub(1)) ^ self.f(r);
        }
        r ^= p(0);
        *data = [r, l];
    }
}

impl Block64 for BfKey {
    fn encrypt(&self, block: &[u8; 8]) -> [u8; 8] {
        let mut w = be_words(block);
        self.encrypt_words(&mut w);
        be_block(w)
    }

    fn decrypt(&self, block: &[u8; 8]) -> [u8; 8] {
        let mut w = be_words(block);
        self.decrypt_words(&mut w);
        be_block(w)
    }
}

/// `BF_set_key`: the key's first 72 octets (repeated as needed) into the P-array, then the
/// array and S-boxes by encrypting zeros. An empty key is a single zero octet.
pub fn bf_set_key(key: &[u8]) -> BfKey {
    let key = key.get(..key.len().min(72)).unwrap_or(key);
    let key: &[u8] = if key.is_empty() { &[0] } else { key };
    let mut k = BfKey { p: BF_P, s: BF_S };
    let mut bytes = key.iter().cycle();
    for p in k.p.iter_mut() {
        let mut ri = 0u32;
        for _ in 0..4 {
            ri = (ri << 8) | u32::from(bytes.next().copied().unwrap_or(0));
        }
        *p ^= ri;
    }
    let mut d = [0u32; 2];
    for i in 0..9 {
        k.encrypt_words(&mut d);
        if let Some(pair) = k.p.as_chunks_mut::<2>().0.get_mut(i) {
            *pair = d;
        }
    }
    for i in 0..512 {
        k.encrypt_words(&mut d);
        if let Some(pair) = k.s.as_chunks_mut::<2>().0.get_mut(i) {
            *pair = d;
        }
    }
    k
}

/// A CAST-128 key (`CAST_KEY`): each round's masking and rotation keys, and whether the key
/// had 10 octets or fewer (12 rounds instead of 16).
#[derive(Clone)]
pub struct CastKey {
    /// `data`: masking key, rotation key, for each round.
    pub data: [u32; 32],
    /// `short_key`.
    pub short_key: bool,
}

impl Drop for CastKey {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// A CAST S-box at an octet.
fn cast_s(k: usize, i: u32) -> u32 {
    ct_get(
        CAST_S.get(k).map_or(&[][..], |t| &t[..]),
        usize::try_from(i & 0xff).unwrap_or(0),
    )
}

/// The CAST round function's three operations, by round.
#[derive(Clone, Copy)]
enum Op {
    Add,
    Xor,
    Sub,
}

impl Op {
    fn apply(self, a: u32, b: u32) -> u32 {
        match self {
            Op::Add => a.wrapping_add(b),
            Op::Xor => a ^ b,
            Op::Sub => a.wrapping_sub(b),
        }
    }
}

impl CastKey {
    /// One round (`E_CAST`) of round `n` into `l` from `r`.
    fn round(&self, n: usize, l: &mut u32, r: u32) {
        let (op1, op2, op3) = match n % 3 {
            0 => (Op::Add, Op::Xor, Op::Sub),
            1 => (Op::Xor, Op::Sub, Op::Add),
            _ => (Op::Sub, Op::Add, Op::Xor),
        };
        let km = self.data.get(n.saturating_mul(2)).copied().unwrap_or(0);
        let kr = self
            .data
            .get(n.saturating_mul(2).saturating_add(1))
            .copied()
            .unwrap_or(0);
        let t = op1.apply(km, r).rotate_left(kr & 31);
        let a = cast_s(0, t >> 8);
        let b = cast_s(1, t);
        let c = cast_s(2, t >> 24);
        let d = cast_s(3, t >> 16);
        *l ^= op1.apply(op3.apply(op2.apply(a, b), c), d);
    }

    /// `CAST_encrypt`: two words.
    pub fn encrypt_words(&self, data: &mut [u32; 2]) {
        let [mut l, mut r] = *data;
        let rounds = if self.short_key { 12 } else { 16 };
        for n in 0..rounds {
            if n % 2 == 0 {
                self.round(n, &mut l, r);
            } else {
                self.round(n, &mut r, l);
            }
        }
        *data = [r, l];
    }

    /// `CAST_decrypt`: two words.
    pub fn decrypt_words(&self, data: &mut [u32; 2]) {
        let [mut l, mut r] = *data;
        let rounds = if self.short_key { 12 } else { 16 };
        for (i, n) in (0..rounds).rev().enumerate() {
            if i % 2 == 0 {
                self.round(n, &mut l, r);
            } else {
                self.round(n, &mut r, l);
            }
        }
        *data = [r, l];
    }
}

impl Block64 for CastKey {
    fn encrypt(&self, block: &[u8; 8]) -> [u8; 8] {
        let mut w = be_words(block);
        self.encrypt_words(&mut w);
        be_block(w)
    }

    fn decrypt(&self, block: &[u8; 8]) -> [u8; 8] {
        let mut w = be_words(block);
        self.decrypt_words(&mut w);
        be_block(w)
    }
}

/// `CAST_exp`: `l` as the word `big[n / 4]` and the octets `small[n..n + 4]`.
fn cast_exp(l: u32, big: &mut [u32; 4], small: &mut [u8; 16], n: usize) {
    if let Some(w) = big.get_mut(n / 4) {
        *w = l;
    }
    put(small, n, &l.to_be_bytes());
}

/// `CAST_set_key`: the key's first 16 octets (zero-padded); 10 or fewer make a short key.
#[allow(clippy::many_single_char_names)]
pub fn cast_set_key(key: &[u8]) -> CastKey {
    let len = key.len().min(16);
    let mut x = [0u8; 16];
    put(&mut x, 0, key.get(..len).unwrap_or_default());
    let mut z = [0u8; 16];
    let mut xx = [0u32; 4];
    let mut zz = [0u32; 4];
    for (w, b) in xx.iter_mut().zip(x.as_chunks::<4>().0) {
        *w = u32::from_be_bytes(*b);
    }
    let s4 = |i: u8| cast_s(4, u32::from(i));
    let s5 = |i: u8| cast_s(5, u32::from(i));
    let s6 = |i: u8| cast_s(6, u32::from(i));
    let s7 = |i: u8| cast_s(7, u32::from(i));
    let mut k = [0u32; 32];
    for half in 0..2 {
        let mut kh = [0u32; 16];
        let l = xx[0] ^ s4(x[13]) ^ s5(x[15]) ^ s6(x[12]) ^ s7(x[14]) ^ s6(x[8]);
        cast_exp(l, &mut zz, &mut z, 0);
        let l = xx[2] ^ s4(z[0]) ^ s5(z[2]) ^ s6(z[1]) ^ s7(z[3]) ^ s7(x[10]);
        cast_exp(l, &mut zz, &mut z, 4);
        let l = xx[3] ^ s4(z[7]) ^ s5(z[6]) ^ s6(z[5]) ^ s7(z[4]) ^ s4(x[9]);
        cast_exp(l, &mut zz, &mut z, 8);
        let l = xx[1] ^ s4(z[10]) ^ s5(z[9]) ^ s6(z[11]) ^ s7(z[8]) ^ s5(x[11]);
        cast_exp(l, &mut zz, &mut z, 12);
        kh[0] = s4(z[8]) ^ s5(z[9]) ^ s6(z[7]) ^ s7(z[6]) ^ s4(z[2]);
        kh[1] = s4(z[10]) ^ s5(z[11]) ^ s6(z[5]) ^ s7(z[4]) ^ s5(z[6]);
        kh[2] = s4(z[12]) ^ s5(z[13]) ^ s6(z[3]) ^ s7(z[2]) ^ s6(z[9]);
        kh[3] = s4(z[14]) ^ s5(z[15]) ^ s6(z[1]) ^ s7(z[0]) ^ s7(z[12]);
        let l = zz[2] ^ s4(z[5]) ^ s5(z[7]) ^ s6(z[4]) ^ s7(z[6]) ^ s6(z[0]);
        cast_exp(l, &mut xx, &mut x, 0);
        let l = zz[0] ^ s4(x[0]) ^ s5(x[2]) ^ s6(x[1]) ^ s7(x[3]) ^ s7(z[2]);
        cast_exp(l, &mut xx, &mut x, 4);
        let l = zz[1] ^ s4(x[7]) ^ s5(x[6]) ^ s6(x[5]) ^ s7(x[4]) ^ s4(z[1]);
        cast_exp(l, &mut xx, &mut x, 8);
        let l = zz[3] ^ s4(x[10]) ^ s5(x[9]) ^ s6(x[11]) ^ s7(x[8]) ^ s5(z[3]);
        cast_exp(l, &mut xx, &mut x, 12);
        kh[4] = s4(x[3]) ^ s5(x[2]) ^ s6(x[12]) ^ s7(x[13]) ^ s4(x[8]);
        kh[5] = s4(x[1]) ^ s5(x[0]) ^ s6(x[14]) ^ s7(x[15]) ^ s5(x[13]);
        kh[6] = s4(x[7]) ^ s5(x[6]) ^ s6(x[8]) ^ s7(x[9]) ^ s6(x[3]);
        kh[7] = s4(x[5]) ^ s5(x[4]) ^ s6(x[10]) ^ s7(x[11]) ^ s7(x[7]);
        let l = xx[0] ^ s4(x[13]) ^ s5(x[15]) ^ s6(x[12]) ^ s7(x[14]) ^ s6(x[8]);
        cast_exp(l, &mut zz, &mut z, 0);
        let l = xx[2] ^ s4(z[0]) ^ s5(z[2]) ^ s6(z[1]) ^ s7(z[3]) ^ s7(x[10]);
        cast_exp(l, &mut zz, &mut z, 4);
        let l = xx[3] ^ s4(z[7]) ^ s5(z[6]) ^ s6(z[5]) ^ s7(z[4]) ^ s4(x[9]);
        cast_exp(l, &mut zz, &mut z, 8);
        let l = xx[1] ^ s4(z[10]) ^ s5(z[9]) ^ s6(z[11]) ^ s7(z[8]) ^ s5(x[11]);
        cast_exp(l, &mut zz, &mut z, 12);
        kh[8] = s4(z[3]) ^ s5(z[2]) ^ s6(z[12]) ^ s7(z[13]) ^ s4(z[9]);
        kh[9] = s4(z[1]) ^ s5(z[0]) ^ s6(z[14]) ^ s7(z[15]) ^ s5(z[12]);
        kh[10] = s4(z[7]) ^ s5(z[6]) ^ s6(z[8]) ^ s7(z[9]) ^ s6(z[2]);
        kh[11] = s4(z[5]) ^ s5(z[4]) ^ s6(z[10]) ^ s7(z[11]) ^ s7(z[6]);
        let l = zz[2] ^ s4(z[5]) ^ s5(z[7]) ^ s6(z[4]) ^ s7(z[6]) ^ s6(z[0]);
        cast_exp(l, &mut xx, &mut x, 0);
        let l = zz[0] ^ s4(x[0]) ^ s5(x[2]) ^ s6(x[1]) ^ s7(x[3]) ^ s7(z[2]);
        cast_exp(l, &mut xx, &mut x, 4);
        let l = zz[1] ^ s4(x[7]) ^ s5(x[6]) ^ s6(x[5]) ^ s7(x[4]) ^ s4(z[1]);
        cast_exp(l, &mut xx, &mut x, 8);
        let l = zz[3] ^ s4(x[10]) ^ s5(x[9]) ^ s6(x[11]) ^ s7(x[8]) ^ s5(z[3]);
        cast_exp(l, &mut xx, &mut x, 12);
        kh[12] = s4(x[8]) ^ s5(x[9]) ^ s6(x[7]) ^ s7(x[6]) ^ s4(x[3]);
        kh[13] = s4(x[10]) ^ s5(x[11]) ^ s6(x[5]) ^ s7(x[4]) ^ s5(x[7]);
        kh[14] = s4(x[12]) ^ s5(x[13]) ^ s6(x[3]) ^ s7(x[2]) ^ s6(x[8]);
        kh[15] = s4(x[14]) ^ s5(x[15]) ^ s6(x[1]) ^ s7(x[0]) ^ s7(x[13]);
        if let Some(dst) = k.as_chunks_mut::<16>().0.get_mut(half) {
            *dst = kh;
        }
        kh.zeroize();
    }
    let mut out = CastKey {
        data: [0; 32],
        short_key: len <= 10,
    };
    let (km, kr) = k.split_at(16);
    for ((pair, m), r) in out.data.as_chunks_mut::<2>().0.iter_mut().zip(km).zip(kr) {
        *pair = [*m, r.wrapping_add(16) & 0x1f];
    }
    x.zeroize();
    z.zeroize();
    xx.zeroize();
    zz.zeroize();
    k.zeroize();
    out
}

/// An RC2 key (`RC2_KEY`): 64 16-bit words.
#[derive(Clone)]
pub struct Rc2Key(pub [u32; 64]);

impl Drop for Rc2Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// `RC2_set_key`: the key's first 128 octets expanded through PITABLE, then reduced to `bits`
/// effective bits (1 to 1024; 0 or less, or more, is 1024). An empty key expands from a last
/// octet of 0.
pub fn rc2_set_key(key: &[u8], bits: i32) -> Rc2Key {
    let len = key.len().min(128);
    let bits = if bits <= 0 || bits > 1024 { 1024 } else { bits };
    let mut k = [0u8; 128];
    put(&mut k, 0, key.get(..len).unwrap_or_default());
    let mut d = key.get(len.wrapping_sub(1)).copied().unwrap_or(0);
    let at = |k: &[u8; 128], i: usize| k.get(i).copied().unwrap_or(0);
    for (j, i) in (len..128).enumerate() {
        let idx = usize::from(at(&k, j).wrapping_add(d));
        d = ct_get8(&RC2_PITABLE, idx);
        if let Some(b) = k.get_mut(i) {
            *b = d;
        }
    }
    let j = usize::try_from(bits.saturating_add(7) >> 3).unwrap_or(128);
    let mut i = 128usize.saturating_sub(j);
    let c = 0xffu8 >> (bits.wrapping_neg() & 7);
    d = ct_get8(&RC2_PITABLE, usize::from(at(&k, i) & c));
    if let Some(b) = k.get_mut(i) {
        *b = d;
    }
    while i > 0 {
        i = i.saturating_sub(1);
        d = ct_get8(&RC2_PITABLE, usize::from(at(&k, i.saturating_add(j)) ^ d));
        if let Some(b) = k.get_mut(i) {
            *b = d;
        }
    }
    let mut out = Rc2Key([0; 64]);
    for (w, b) in out.0.iter_mut().zip(k.as_chunks::<2>().0) {
        *w = u32::from(b[0]) | (u32::from(b[1]) << 8);
    }
    k.zeroize();
    out
}

impl Rc2Key {
    /// The key word at a secret index (the mashing rounds').
    fn mash(&self, x: u32) -> u32 {
        ct_get(&self.0, usize::try_from(x & 0x3f).unwrap_or(0))
    }

    /// `RC2_encrypt`: two words of 32 bits (from `c2l`).
    pub fn encrypt_words(&self, data: &mut [u32; 2]) {
        let mut x0 = data[0] & 0xffff;
        let mut x1 = data[0] >> 16;
        let mut x2 = data[1] & 0xffff;
        let mut x3 = data[1] >> 16;
        let mut p = self.0.iter().copied();
        let mut next = || p.next().unwrap_or(0);
        for round in 0..16 {
            let t = x0
                .wrapping_add(x1 & !x3)
                .wrapping_add(x2 & x3)
                .wrapping_add(next())
                & 0xffff;
            x0 = (t << 1) | (t >> 15);
            let t = x1
                .wrapping_add(x2 & !x0)
                .wrapping_add(x3 & x0)
                .wrapping_add(next())
                & 0xffff;
            x1 = (t << 2) | (t >> 14);
            let t = x2
                .wrapping_add(x3 & !x1)
                .wrapping_add(x0 & x1)
                .wrapping_add(next())
                & 0xffff;
            x2 = (t << 3) | (t >> 13);
            let t = x3
                .wrapping_add(x0 & !x2)
                .wrapping_add(x1 & x2)
                .wrapping_add(next())
                & 0xffff;
            x3 = (t << 5) | (t >> 11);
            if round == 4 || round == 10 {
                x0 = x0.wrapping_add(self.mash(x3));
                x1 = x1.wrapping_add(self.mash(x0));
                x2 = x2.wrapping_add(self.mash(x1));
                x3 = x3.wrapping_add(self.mash(x2));
            }
        }
        *data = [
            (x0 & 0xffff) | ((x1 & 0xffff) << 16),
            (x2 & 0xffff) | ((x3 & 0xffff) << 16),
        ];
    }

    /// `RC2_decrypt`: two words of 32 bits.
    pub fn decrypt_words(&self, data: &mut [u32; 2]) {
        let mut x0 = data[0] & 0xffff;
        let mut x1 = data[0] >> 16;
        let mut x2 = data[1] & 0xffff;
        let mut x3 = data[1] >> 16;
        let mut p = self.0.iter().rev().copied();
        let mut next = || p.next().unwrap_or(0);
        for round in 0..16 {
            let t = ((x3 << 11) | (x3 >> 5)) & 0xffff;
            x3 = t
                .wrapping_sub(x0 & !x2)
                .wrapping_sub(x1 & x2)
                .wrapping_sub(next())
                & 0xffff;
            let t = ((x2 << 13) | (x2 >> 3)) & 0xffff;
            x2 = t
                .wrapping_sub(x3 & !x1)
                .wrapping_sub(x0 & x1)
                .wrapping_sub(next())
                & 0xffff;
            let t = ((x1 << 14) | (x1 >> 2)) & 0xffff;
            x1 = t
                .wrapping_sub(x2 & !x0)
                .wrapping_sub(x3 & x0)
                .wrapping_sub(next())
                & 0xffff;
            let t = ((x0 << 15) | (x0 >> 1)) & 0xffff;
            x0 = t
                .wrapping_sub(x1 & !x3)
                .wrapping_sub(x2 & x3)
                .wrapping_sub(next())
                & 0xffff;
            if round == 4 || round == 10 {
                x3 = x3.wrapping_sub(self.mash(x2)) & 0xffff;
                x2 = x2.wrapping_sub(self.mash(x1)) & 0xffff;
                x1 = x1.wrapping_sub(self.mash(x0)) & 0xffff;
                x0 = x0.wrapping_sub(self.mash(x3)) & 0xffff;
            }
        }
        *data = [
            (x0 & 0xffff) | ((x1 & 0xffff) << 16),
            (x2 & 0xffff) | ((x3 & 0xffff) << 16),
        ];
    }
}

/// A block as two little-endian words (RC2's `c2l`).
fn le_words(b: &[u8; 8]) -> [u32; 2] {
    [
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
    ]
}

/// Two little-endian words as a block.
fn le_block(w: [u32; 2]) -> [u8; 8] {
    let [a, b] = w.map(u32::to_le_bytes);
    [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]]
}

impl Block64 for Rc2Key {
    fn encrypt(&self, block: &[u8; 8]) -> [u8; 8] {
        let mut w = le_words(block);
        self.encrypt_words(&mut w);
        le_block(w)
    }

    fn decrypt(&self, block: &[u8; 8]) -> [u8; 8] {
        let mut w = le_words(block);
        self.decrypt_words(&mut w);
        le_block(w)
    }
}

/// An RC4 state (`RC4_KEY`): the two indexes and the permutation, as words (OpenSSL keeps
/// them as `unsigned int` or `unsigned char` by platform; the values are octets unless an
/// application wrote others).
#[derive(Clone)]
pub struct Rc4 {
    /// `x`.
    pub x: u32,
    /// `y`.
    pub y: u32,
    /// `data`.
    pub data: [u32; 256],
}

impl Drop for Rc4 {
    fn drop(&mut self) {
        self.data.zeroize();
        self.x = 0;
        self.y = 0;
    }
}

/// `RC4_set_key`: the key schedule over `key` (not empty).
pub fn rc4_set_key(key: &[u8]) -> Rc4 {
    let mut s = Rc4 {
        x: 0,
        y: 0,
        data: core::array::from_fn(|i| u32::try_from(i).unwrap_or(0)),
    };
    let mut id2 = 0usize;
    let mut kb = key.iter().cycle();
    for n in 0..256usize {
        let tmp = s.data.get(n).copied().unwrap_or(0);
        let kv = u32::from(kb.next().copied().unwrap_or(0));
        id2 = usize::try_from(
            kv.wrapping_add(tmp)
                .wrapping_add(u32::try_from(id2).unwrap_or(0))
                & 0xff,
        )
        .unwrap_or(0);
        let other = ct_get(&s.data, id2);
        if let Some(d) = s.data.get_mut(n) {
            *d = other;
        }
        ct_set(&mut s.data, id2, tmp);
    }
    s
}

impl Rc4 {
    /// `RC4`: the keystream XORed into `input`.
    pub fn apply(&mut self, input: &[u8], out: &mut [u8]) {
        let mut x = self.x;
        let mut y = self.y;
        for (i, b) in input.iter().enumerate() {
            x = x.wrapping_add(1) & 0xff;
            let xi = usize::try_from(x).unwrap_or(0);
            let tx = self.data.get(xi).copied().unwrap_or(0);
            y = tx.wrapping_add(y) & 0xff;
            let yi = usize::try_from(y).unwrap_or(0);
            let ty = ct_get(&self.data, yi);
            if let Some(d) = self.data.get_mut(xi) {
                *d = ty;
            }
            ct_set(&mut self.data, yi, tx);
            let k = ct_get(
                &self.data,
                usize::try_from(tx.wrapping_add(ty) & 0xff).unwrap_or(0),
            );
            if let Some(o) = out.get_mut(i) {
                *o = b ^ k.to_le_bytes()[0];
            }
        }
        self.x = x;
        self.y = y;
    }
}

#[cfg(test)]
mod tests;
