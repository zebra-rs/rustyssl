//! The deprecated DES functions (`DES_set_key(3)`, `DES_ecb_encrypt(3)`, the CBC, PCBC, XCBC,
//! CFB, and OFB modes, the checksums, `DES_string_to_key`, and `DES_fcrypt`).
//!
//! A `DES_key_schedule` holds OpenSSL's own form of the sixteen round keys (each as two words
//! rotated for its rounds), which applications can see, so the key schedule and the rounds are
//! OpenSSL's, over its tables ([`tables`], extracted from its sources). Every table read is a
//! constant-time scan of the whole table, so no key or data bit picks a memory address (OpenSSL
//! indexes them directly). The modes follow OpenSSL's steps, so the IV and the position hold
//! what OpenSSL leaves there.
//!
//! Lengths are OpenSSL's `long`s, taken here only when they aren't negative (OpenSSL reads and
//! writes a block, or loops without end, for a negative one); a partial last block is read and
//! written as OpenSSL does (`c2ln`, `l2cn`).

mod tables;

use tables::{CON_SALT, COV_2CHAR, SKB, SP_TRANS};
use zeroize::Zeroize;

/// A key schedule: sixteen rounds of two words each (`DES_key_schedule`'s `deslong`s).
pub type Schedule = [u32; 32];

/// A table entry, read by scanning the whole table: every entry is loaded, and the one at
/// `idx` kept by a mask.
fn ct_lookup(table: &[u32; 64], idx: u32) -> u32 {
    let mut r = 0u32;
    for (i, v) in (0u32..).zip(table) {
        let d = i ^ idx;
        // 1 when `d` is zero, 0 otherwise, without a branch.
        let is_eq = ((d | d.wrapping_neg()) >> 31) ^ 1;
        r |= v & 0u32.wrapping_sub(is_eq);
    }
    r
}

/// A row of a table.
fn row(table: &[[u32; 64]; 8], k: usize) -> &[u32; 64] {
    table.get(k).unwrap_or(&[0; 64])
}

/// `c2l`: four octets as a little-endian word.
fn c2l(b: &[u8], at: usize) -> u32 {
    let g = |i: usize| u32::from(b.get(at.saturating_add(i)).copied().unwrap_or(0));
    g(0) | (g(1) << 8) | (g(2) << 16) | (g(3) << 24)
}

/// `l2c`: a word as four little-endian octets.
fn l2c(w: u32, out: &mut [u8], at: usize) {
    for (i, b) in w.to_le_bytes().into_iter().enumerate() {
        if let Some(o) = out.get_mut(at.saturating_add(i)) {
            *o = b;
        }
    }
}

/// A block's two words.
fn load(b: &[u8], at: usize) -> [u32; 2] {
    [c2l(b, at), c2l(b, at.saturating_add(4))]
}

/// Writes a block's two words.
fn store(w: [u32; 2], out: &mut [u8], at: usize) {
    l2c(w[0], out, at);
    l2c(w[1], out, at.saturating_add(4));
}

/// `c2ln`: the first `n` (up to 8) octets as two words, the rest zero.
fn load_n(b: &[u8], at: usize, n: usize) -> [u32; 2] {
    let mut block = [0u8; 8];
    for (i, d) in block.iter_mut().enumerate().take(n.min(8)) {
        *d = b.get(at.saturating_add(i)).copied().unwrap_or(0);
    }
    load(&block, 0)
}

/// `l2cn`: the first `n` (up to 8) octets of two words.
fn store_n(w: [u32; 2], out: &mut [u8], at: usize, n: usize) {
    let mut block = [0u8; 8];
    store(w, &mut block, 0);
    for (i, s) in block.iter().enumerate().take(n.min(8)) {
        if let Some(o) = out.get_mut(at.saturating_add(i)) {
            *o = *s;
        }
    }
}

/// `PERM_OP`: swaps the bits of `b` selected by `m` with those of `a` `n` places up.
fn perm_op(a: &mut u32, b: &mut u32, n: u32, m: u32) {
    let t = ((*a >> n) ^ *b) & m;
    *b ^= t;
    *a ^= t << n;
}

/// `HPERM_OP` with OpenSSL's only shift, -2.
fn hperm_op(a: &mut u32, m: u32) {
    let t = ((*a << 18) ^ *a) & m;
    *a = *a ^ t ^ (t >> 18);
}

/// The initial permutation.
fn ip(l: &mut u32, r: &mut u32) {
    perm_op(r, l, 4, 0x0f0f_0f0f);
    perm_op(l, r, 16, 0x0000_ffff);
    perm_op(r, l, 2, 0x3333_3333);
    perm_op(l, r, 8, 0x00ff_00ff);
    perm_op(r, l, 1, 0x5555_5555);
}

/// The final permutation.
fn fp(l: &mut u32, r: &mut u32) {
    perm_op(l, r, 1, 0x5555_5555);
    perm_op(r, l, 8, 0x00ff_00ff);
    perm_op(l, r, 2, 0x3333_3333);
    perm_op(r, l, 16, 0x0000_ffff);
    perm_op(l, r, 4, 0x0f0f_0f0f);
}

/// `DES_set_key_unchecked`: the schedule in OpenSSL's form (PC-1 by bit swaps, the
/// rotations, PC-2 through its tables).
pub fn set_key_unchecked(key: &[u8; 8]) -> Schedule {
    crate::dit::with(|| {
        const SHIFTS2: [bool; 16] = [
            false, false, true, true, true, true, true, true, false, true, true, true, true, true,
            true, false,
        ];
        let mut c = c2l(key, 0);
        let mut d = c2l(key, 4);
        perm_op(&mut d, &mut c, 4, 0x0f0f_0f0f);
        hperm_op(&mut c, 0xcccc_0000);
        hperm_op(&mut d, 0xcccc_0000);
        perm_op(&mut d, &mut c, 1, 0x5555_5555);
        perm_op(&mut c, &mut d, 8, 0x00ff_00ff);
        perm_op(&mut d, &mut c, 1, 0x5555_5555);
        d = ((d & 0x0000_00ff) << 16)
            | (d & 0x0000_ff00)
            | ((d & 0x00ff_0000) >> 16)
            | ((c & 0xf000_0000) >> 4);
        c &= 0x0fff_ffff;
        let mut ks = [0u32; 32];
        for (i, pair) in ks.as_chunks_mut::<2>().0.iter_mut().enumerate() {
            if SHIFTS2.get(i).copied().unwrap_or(false) {
                c = (c >> 2) | (c << 26);
                d = (d >> 2) | (d << 26);
            } else {
                c = (c >> 1) | (c << 27);
                d = (d >> 1) | (d << 27);
            }
            c &= 0x0fff_ffff;
            d &= 0x0fff_ffff;
            let s = ct_lookup(row(&SKB, 0), c & 0x3f)
                | ct_lookup(row(&SKB, 1), ((c >> 6) & 0x03) | ((c >> 7) & 0x3c))
                | ct_lookup(row(&SKB, 2), ((c >> 13) & 0x0f) | ((c >> 14) & 0x30))
                | ct_lookup(
                    row(&SKB, 3),
                    ((c >> 20) & 0x01) | ((c >> 21) & 0x06) | ((c >> 22) & 0x38),
                );
            let t = ct_lookup(row(&SKB, 4), d & 0x3f)
                | ct_lookup(row(&SKB, 5), ((d >> 7) & 0x03) | ((d >> 8) & 0x3c))
                | ct_lookup(row(&SKB, 6), (d >> 15) & 0x3f)
                | ct_lookup(row(&SKB, 7), ((d >> 21) & 0x0f) | ((d >> 22) & 0x30));
            pair[0] = ((t << 16) | (s & 0x0000_ffff)).rotate_right(30);
            pair[1] = ((s >> 16) | (t & 0xffff_0000)).rotate_right(26);
        }
        ks
    })
}

/// `D_ENCRYPT`: one round into `ll` from `r` with the round keys at `s` (and, for
/// `crypt(3)`, the salt's E-box swaps).
fn d_encrypt(ll: &mut u32, r: u32, ks: &Schedule, s: usize, swap: Option<(u32, u32)>) {
    let k0 = ks.get(s).copied().unwrap_or(0);
    let k1 = ks.get(s.saturating_add(1)).copied().unwrap_or(0);
    let (u, t) = match swap {
        None => (r ^ k0, r ^ k1),
        Some((e0, e1)) => {
            let t = r ^ (r >> 16);
            let u = t & e0;
            let t = t & e1;
            ((u ^ (u << 16)) ^ r ^ k0, (t ^ (t << 16)) ^ r ^ k1)
        }
    };
    let t = t.rotate_right(4);
    *ll ^= ct_lookup(row(&SP_TRANS, 0), (u >> 2) & 0x3f)
        ^ ct_lookup(row(&SP_TRANS, 2), (u >> 10) & 0x3f)
        ^ ct_lookup(row(&SP_TRANS, 4), (u >> 18) & 0x3f)
        ^ ct_lookup(row(&SP_TRANS, 6), (u >> 26) & 0x3f)
        ^ ct_lookup(row(&SP_TRANS, 1), (t >> 2) & 0x3f)
        ^ ct_lookup(row(&SP_TRANS, 3), (t >> 10) & 0x3f)
        ^ ct_lookup(row(&SP_TRANS, 5), (t >> 18) & 0x3f)
        ^ ct_lookup(row(&SP_TRANS, 7), (t >> 26) & 0x3f);
}

/// The sixteen rounds on rotated halves, forwards for encryption, backwards for decryption.
fn rounds(l: &mut u32, r: &mut u32, ks: &Schedule, enc: bool) {
    for i in 0..8usize {
        let (a, b) = if enc {
            (i.saturating_mul(4), i.saturating_mul(4).saturating_add(2))
        } else {
            (
                30usize.saturating_sub(i.saturating_mul(4)),
                28usize.saturating_sub(i.saturating_mul(4)),
            )
        };
        d_encrypt(l, *r, ks, a, None);
        d_encrypt(r, *l, ks, b, None);
    }
}

/// `DES_encrypt1`: one block (two words, from `c2l`) with the permutations.
pub fn encrypt1(data: &mut [u32; 2], ks: &Schedule, enc: bool) {
    let mut r = data[0];
    let mut l = data[1];
    ip(&mut r, &mut l);
    r = r.rotate_right(29);
    l = l.rotate_right(29);
    rounds(&mut l, &mut r, ks, enc);
    l = l.rotate_right(3);
    r = r.rotate_right(3);
    fp(&mut r, &mut l);
    *data = [l, r];
}

/// `DES_encrypt2`: one block without the permutations (for triple DES).
pub fn encrypt2(data: &mut [u32; 2], ks: &Schedule, enc: bool) {
    let mut r = data[0].rotate_right(29);
    let mut l = data[1].rotate_right(29);
    rounds(&mut l, &mut r, ks, enc);
    *data = [l.rotate_right(3), r.rotate_right(3)];
}

/// `DES_encrypt3`: encrypt-decrypt-encrypt with three schedules.
pub fn encrypt3(data: &mut [u32; 2], ks1: &Schedule, ks2: &Schedule, ks3: &Schedule) {
    let [mut l, mut r] = *data;
    ip(&mut l, &mut r);
    *data = [l, r];
    encrypt2(data, ks1, true);
    encrypt2(data, ks2, false);
    encrypt2(data, ks3, true);
    let [mut l, mut r] = *data;
    fp(&mut r, &mut l);
    *data = [l, r];
}

/// `DES_decrypt3`: decrypt-encrypt-decrypt, the schedules in reverse.
pub fn decrypt3(data: &mut [u32; 2], ks1: &Schedule, ks2: &Schedule, ks3: &Schedule) {
    let [mut l, mut r] = *data;
    ip(&mut l, &mut r);
    *data = [l, r];
    encrypt2(data, ks3, false);
    encrypt2(data, ks2, true);
    encrypt2(data, ks1, false);
    let [mut l, mut r] = *data;
    fp(&mut r, &mut l);
    *data = [l, r];
}

/// A cipher for the modes: DES with one schedule, or triple DES with three.
#[derive(Clone, Copy)]
pub enum Cipher<'a> {
    /// DES.
    Single(&'a Schedule),
    /// Triple DES (EDE).
    Triple(&'a Schedule, &'a Schedule, &'a Schedule),
}

impl Cipher<'_> {
    fn encrypt(self, d: &mut [u32; 2]) {
        match self {
            Cipher::Single(k) => encrypt1(d, k, true),
            Cipher::Triple(a, b, c) => encrypt3(d, a, b, c),
        }
    }

    fn decrypt(self, d: &mut [u32; 2]) {
        match self {
            Cipher::Single(k) => encrypt1(d, k, false),
            Cipher::Triple(a, b, c) => decrypt3(d, a, b, c),
        }
    }
}

/// `DES_ecb_encrypt` (and with three schedules `DES_ecb3_encrypt`): one block.
pub fn ecb(input: &[u8; 8], c: Cipher<'_>, enc: bool) -> [u8; 8] {
    let mut d = load(input, 0);
    if enc {
        c.encrypt(&mut d);
    } else {
        c.decrypt(&mut d);
    }
    let mut out = [0u8; 8];
    store(d, &mut out, 0);
    out
}

/// CBC (`DES_ncbc_encrypt`, `DES_ede3_cbc_encrypt`, and `DES_cbc_encrypt`, which leaves the IV
/// as it was) over `len` octets: encryption reads `len` and writes it rounded up to whole
/// blocks; decryption reads it rounded up and writes `len`.
pub fn cbc(
    input: &[u8],
    out: &mut [u8],
    len: usize,
    c: Cipher<'_>,
    iv: &mut [u8; 8],
    enc: bool,
    update_iv: bool,
) {
    crate::dit::with(|| {
        let whole = len.saturating_sub(len % 8);
        let rest = len % 8;
        if enc {
            let mut t = load(iv, 0);
            let mut at = 0;
            while at < whole || (at == whole && rest != 0) {
                let n = if at < whole { 8 } else { rest };
                let x = load_n(input, at, n);
                t = [x[0] ^ t[0], x[1] ^ t[1]];
                c.encrypt(&mut t);
                store(t, out, at);
                at = at.saturating_add(8);
            }
            if update_iv {
                store(t, iv, 0);
            }
        } else {
            let mut x = load(iv, 0);
            let mut at = 0;
            while at < whole || (at == whole && rest != 0) {
                let tin = load(input, at);
                let mut d = tin;
                c.decrypt(&mut d);
                let o = [d[0] ^ x[0], d[1] ^ x[1]];
                if at < whole {
                    store(o, out, at);
                    x = tin;
                } else {
                    store_n(o, out, at, rest);
                    // `DES_cbc_encrypt` doesn't take the last partial block into the chain.
                    if update_iv {
                        x = tin;
                    }
                }
                at = at.saturating_add(8);
            }
            if update_iv {
                store(x, iv, 0);
            }
        }
    })
}

/// `DES_xcbc_encrypt`: CBC with whitening blocks `inw` (in) and `outw` (out), the IV updated.
#[allow(clippy::too_many_arguments)]
pub fn xcbc(
    input: &[u8],
    out: &mut [u8],
    len: usize,
    ks: &Schedule,
    iv: &mut [u8; 8],
    inw: &[u8; 8],
    outw: &[u8; 8],
    enc: bool,
) {
    crate::dit::with(|| {
        let inw = load(inw, 0);
        let outw = load(outw, 0);
        let whole = len.saturating_sub(len % 8);
        let rest = len % 8;
        if enc {
            let mut t = load(iv, 0);
            let mut at = 0;
            while at < whole || (at == whole && rest != 0) {
                let n = if at < whole { 8 } else { rest };
                let x = load_n(input, at, n);
                let mut d = [x[0] ^ t[0] ^ inw[0], x[1] ^ t[1] ^ inw[1]];
                encrypt1(&mut d, ks, true);
                t = [d[0] ^ outw[0], d[1] ^ outw[1]];
                store(t, out, at);
                at = at.saturating_add(8);
            }
            store(t, iv, 0);
        } else {
            let mut x = load(iv, 0);
            // OpenSSL's loop stops a block early ("l > 0"); its tail takes the last block,
            // whole or not.
            let blocks = len.div_ceil(8);
            for i in 0..blocks {
                let at = i.saturating_mul(8);
                let tin = load(input, at);
                let mut d = [tin[0] ^ outw[0], tin[1] ^ outw[1]];
                encrypt1(&mut d, ks, false);
                let o = [d[0] ^ x[0] ^ inw[0], d[1] ^ x[1] ^ inw[1]];
                store_n(o, out, at, len.saturating_sub(at).min(8));
                x = tin;
            }
            store(x, iv, 0);
        }
    })
}

/// `DES_pcbc_encrypt`: propagating CBC; the IV stays as it was. Encryption reads `len` and
/// writes it rounded up; decryption reads it rounded up and writes `len`.
pub fn pcbc(input: &[u8], out: &mut [u8], len: usize, ks: &Schedule, iv: &[u8; 8], enc: bool) {
    crate::dit::with(|| {
        let mut x = load(iv, 0);
        let mut at = 0;
        while at < len {
            let left = len.saturating_sub(at);
            if enc {
                let s = if left >= 8 {
                    load(input, at)
                } else {
                    load_n(input, at, left)
                };
                let mut d = [s[0] ^ x[0], s[1] ^ x[1]];
                encrypt1(&mut d, ks, true);
                x = [s[0] ^ d[0], s[1] ^ d[1]];
                store(d, out, at);
            } else {
                let s = load(input, at);
                let mut d = s;
                encrypt1(&mut d, ks, false);
                let o = [d[0] ^ x[0], d[1] ^ x[1]];
                store_n(o, out, at, left.min(8));
                x = [o[0] ^ s[0], o[1] ^ s[1]];
            }
            at = at.saturating_add(8);
        }
    })
}

/// CFB with `numbits` (1 to 64) bits a step (`DES_cfb_encrypt`, `DES_ede3_cfb_encrypt`):
/// `len` octets, `(numbits + 7) / 8` a step, whole steps only; the IV shifts the ciphertext
/// bits in.
#[allow(clippy::too_many_arguments)]
pub fn cfb(
    input: &[u8],
    out: &mut [u8],
    numbits: u32,
    len: usize,
    c: Cipher<'_>,
    iv: &mut [u8; 8],
    enc: bool,
) {
    crate::dit::with(|| {
        if numbits == 0 || numbits > 64 {
            return;
        }
        let n = usize::try_from(numbits.div_ceil(8)).unwrap_or(8);
        let num = usize::try_from(numbits / 8).unwrap_or(8);
        let rem = numbits % 8;
        let mut v = load(iv, 0);
        let mut at = 0;
        while len.saturating_sub(at) >= n {
            let mut ti = v;
            c.encrypt(&mut ti);
            let d_in = load_n(input, at, n);
            let d = [d_in[0] ^ ti[0], d_in[1] ^ ti[1]];
            store_n(d, out, at, n);
            let ct = if enc { d } else { d_in };
            if numbits == 32 {
                v = [v[1], ct[0]];
            } else if numbits == 64 {
                v = ct;
            } else {
                let mut ovec = [0u8; 17];
                store(v, &mut ovec, 0);
                store(ct, &mut ovec, 8);
                let mut shifted = [0u8; 8];
                for (i, s) in shifted.iter_mut().enumerate() {
                    let hi = ovec.get(i.saturating_add(num)).copied().unwrap_or(0);
                    *s = if rem == 0 {
                        hi
                    } else {
                        (hi << rem)
                            | (ovec
                                .get(i.saturating_add(num).saturating_add(1))
                                .copied()
                                .unwrap_or(0)
                                >> 8u32.wrapping_sub(rem))
                    };
                }
                v = load(&shifted, 0);
            }
            at = at.saturating_add(n);
        }
        store(v, iv, 0);
    })
}

/// CFB-64 by octets (`DES_cfb64_encrypt`, `DES_ede3_cfb64_encrypt`): `num` (its low three
/// bits) is the position in the IV, which becomes the ciphertext as it goes.
pub fn cfb64(
    input: &[u8],
    out: &mut [u8],
    c: Cipher<'_>,
    iv: &mut [u8; 8],
    num: &mut i32,
    enc: bool,
) {
    crate::dit::with(|| {
        let mut n = usize::try_from(*num & 7).unwrap_or(0);
        for (i, x) in input.iter().enumerate() {
            if n == 0 {
                let mut ti = load(iv, 0);
                c.encrypt(&mut ti);
                store(ti, iv, 0);
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
    })
}

/// OFB with `numbits` (1 to 64) bits a step (`DES_ofb_encrypt`): `steps` steps (not octets) of
/// `(numbits + 7) / 8` octets each.
pub fn ofb(
    input: &[u8],
    out: &mut [u8],
    numbits: u32,
    steps: usize,
    ks: &Schedule,
    iv: &mut [u8; 8],
) {
    crate::dit::with(|| {
        if numbits == 0 || numbits > 64 {
            return;
        }
        let n = usize::try_from(numbits.div_ceil(8)).unwrap_or(8);
        let (mask0, mask1) = if numbits > 32 {
            (
                u32::MAX,
                if numbits >= 64 {
                    u32::MAX
                } else {
                    (1u32 << numbits.wrapping_sub(32)).wrapping_sub(1)
                },
            )
        } else if numbits == 32 {
            (u32::MAX, 0)
        } else {
            ((1u32 << numbits).wrapping_sub(1), 0)
        };
        let mut v = load(iv, 0);
        for step in 0..steps {
            let at = step.saturating_mul(n);
            let mut ti = v;
            encrypt1(&mut ti, ks, true);
            let d_in = load_n(input, at, n);
            let d = [(d_in[0] ^ ti[0]) & mask0, (d_in[1] ^ ti[1]) & mask1];
            store_n(d, out, at, n);
            v = if numbits == 32 {
                [v[1], ti[0]]
            } else if numbits == 64 {
                ti
            } else if numbits > 32 {
                let s = numbits.wrapping_sub(32);
                [
                    (v[1] >> s) | (ti[0] << 32u32.wrapping_sub(s)),
                    (ti[0] >> s) | (ti[1] << 32u32.wrapping_sub(s)),
                ]
            } else {
                [
                    (v[0] >> numbits) | (v[1] << 32u32.wrapping_sub(numbits)),
                    (v[1] >> numbits) | (ti[0] << 32u32.wrapping_sub(numbits)),
                ]
            };
        }
        store(v, iv, 0);
    })
}

/// OFB-64 by octets (`DES_ofb64_encrypt`, `DES_ede3_ofb64_encrypt`): `num` (its low three
/// bits) is the position in the keystream block, which goes back into the IV only if a new
/// one was made.
pub fn ofb64(input: &[u8], out: &mut [u8], c: Cipher<'_>, iv: &mut [u8; 8], num: &mut i32) {
    crate::dit::with(|| {
        let mut n = usize::try_from(*num & 7).unwrap_or(0);
        let mut ti = load(iv, 0);
        let mut d = *iv;
        let mut made = false;
        for (i, x) in input.iter().enumerate() {
            if n == 0 {
                c.encrypt(&mut ti);
                store(ti, &mut d, 0);
                made = true;
            }
            if let Some(o) = out.get_mut(i) {
                *o = x ^ d.get(n).copied().unwrap_or(0);
            }
            n = n.wrapping_add(1) & 7;
        }
        if made {
            store(ti, iv, 0);
        }
        d.zeroize();
        *num = i32::try_from(n).unwrap_or(0);
    })
}

/// `DES_cbc_cksum`: the CBC-MAC of `len` octets (a partial last block padded with zeros), as
/// a block, and its second word byte-swapped (MIT Kerberos's checksum).
pub fn cbc_cksum(input: &[u8], len: usize, ks: &Schedule, iv: &[u8; 8]) -> ([u8; 8], u32) {
    crate::dit::with(|| {
        let mut t = load(iv, 0);
        let mut at = 0;
        while at < len {
            let left = len.saturating_sub(at);
            let x = if left >= 8 {
                load(input, at)
            } else {
                load_n(input, at, left)
            };
            t = [x[0] ^ t[0], x[1] ^ t[1]];
            encrypt1(&mut t, ks, true);
            at = at.saturating_add(8);
        }
        let mut out = [0u8; 8];
        store(t, &mut out, 0);
        (out, t[1].swap_bytes())
    })
}

/// `DES_quad_cksum`: Kerberos's quadratic checksum of `len` octets from `seed`, repeated over
/// the data `out_count` times (at least 1, at most 4); each round's two words, and the last
/// first word.
pub fn quad_cksum(
    input: &[u8],
    len: usize,
    out_count: i32,
    seed: &[u8; 8],
) -> (Vec<[u32; 2]>, u32) {
    crate::dit::with(|| {
        const NOISE: u32 = 83_653_421;
        let rounds = usize::try_from(out_count.clamp(1, 4)).unwrap_or(1);
        let mut z0 = c2l(seed, 0);
        let mut z1 = c2l(seed, 4);
        let mut outs = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            let mut at = 0;
            while at < len {
                let left = len.saturating_sub(at);
                let b0 = u32::from(input.get(at).copied().unwrap_or(0));
                let t0 = if left > 1 {
                    let b1 = u32::from(input.get(at.saturating_add(1)).copied().unwrap_or(0));
                    at = at.saturating_add(2);
                    b0 | (b1 << 8)
                } else {
                    at = at.saturating_add(1);
                    b0
                };
                let t0 = t0.wrapping_add(z0);
                let t1 = z1;
                z0 = (t0.wrapping_mul(t0).wrapping_add(t1.wrapping_mul(t1))) % 0x7fff_ffff;
                z1 = t0.wrapping_mul(t1.wrapping_add(NOISE)) % 0x7fff_ffff;
            }
            outs.push([z0, z1]);
        }
        (outs, z0)
    })
}

/// OpenSSL's odd-parity form of an octet: its low bit set so the octet has an odd number of
/// set bits.
fn odd_parity(b: u8) -> u8 {
    let high = b & 0xfe;
    let ones = high.count_ones();
    high | u8::from(ones.is_multiple_of(2))
}

/// `DES_set_odd_parity`.
pub fn set_odd_parity(key: &mut [u8; 8]) {
    for b in key.iter_mut() {
        *b = odd_parity(*b);
    }
}

/// `DES_check_key_parity`: whether every octet has odd parity (constant time).
pub fn check_key_parity(key: &[u8; 8]) -> bool {
    let mut res = 1u8;
    for b in key {
        let mut x = *b;
        x ^= x >> 4;
        x ^= x >> 2;
        x ^= x >> 1;
        res &= x & 1;
    }
    res == 1
}

/// The weak and semi-weak keys (Davies and Price).
const WEAK_KEYS: [[u8; 8]; 16] = [
    [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
    [0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe],
    [0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e],
    [0xe0, 0xe0, 0xe0, 0xe0, 0xf1, 0xf1, 0xf1, 0xf1],
    [0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe],
    [0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01],
    [0x1f, 0xe0, 0x1f, 0xe0, 0x0e, 0xf1, 0x0e, 0xf1],
    [0xe0, 0x1f, 0xe0, 0x1f, 0xf1, 0x0e, 0xf1, 0x0e],
    [0x01, 0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1],
    [0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1, 0x01],
    [0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e, 0xfe],
    [0xfe, 0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e],
    [0x01, 0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e],
    [0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e, 0x01],
    [0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1, 0xfe],
    [0xfe, 0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1],
];

/// `DES_is_weak_key`: whether the key is one of the weak or semi-weak ones (constant time,
/// parity bits included as OpenSSL compares them).
pub fn is_weak_key(key: &[u8; 8]) -> bool {
    let mut found = 0u8;
    for w in &WEAK_KEYS {
        let d = w.iter().zip(key).fold(0u8, |d, (a, b)| d | (a ^ b));
        found |= u8::from(d == 0);
    }
    found != 0
}

/// Reverses an octet's bits.
fn reverse_bits(j: u8) -> u8 {
    j.reverse_bits()
}

/// `DES_string_to_key`: the string folded into a key, odd parity, then its CBC checksum under
/// itself.
pub fn string_to_key(s: &[u8]) -> [u8; 8] {
    crate::dit::with(|| {
        let mut key = [0u8; 8];
        for (i, &j) in s.iter().enumerate() {
            if i % 16 < 8 {
                if let Some(k) = key.get_mut(i % 8) {
                    *k ^= j << 1;
                }
            } else if let Some(k) = key.get_mut(7usize.saturating_sub(i % 8)) {
                *k ^= reverse_bits(j);
            }
        }
        set_odd_parity(&mut key);
        let mut ks = set_key_unchecked(&key);
        let (mac, _) = cbc_cksum(s, s.len(), &ks, &key);
        ks.zeroize();
        key = mac;
        set_odd_parity(&mut key);
        key
    })
}

/// `DES_string_to_2keys`: two keys, folded alternately (the second the first's for up to 8
/// octets), each then checksummed under itself.
pub fn string_to_2keys(s: &[u8]) -> ([u8; 8], [u8; 8]) {
    crate::dit::with(|| {
        let mut k1 = [0u8; 8];
        let mut k2 = [0u8; 8];
        for (i, &j) in s.iter().enumerate() {
            let target = if i % 16 < 8 { &mut k1 } else { &mut k2 };
            if i % 32 < 16 {
                if let Some(k) = target.get_mut(i % 8) {
                    *k ^= j << 1;
                }
            } else if let Some(k) = target.get_mut(7usize.saturating_sub(i % 8)) {
                *k ^= reverse_bits(j);
            }
        }
        if s.len() <= 8 {
            k2 = k1;
        }
        set_odd_parity(&mut k1);
        set_odd_parity(&mut k2);
        let mut ks = set_key_unchecked(&k1);
        k1 = cbc_cksum(s, s.len(), &ks, &k1).0;
        ks = set_key_unchecked(&k2);
        k2 = cbc_cksum(s, s.len(), &ks, &k2).0;
        ks.zeroize();
        set_odd_parity(&mut k1);
        set_odd_parity(&mut k2);
        (k1, k2)
    })
}

/// `fcrypt_body`: 25 DES encryptions of zeros with the salt's E-box swaps.
fn fcrypt_body(ks: &Schedule, e0: u32, e1: u32) -> [u32; 2] {
    let mut l = 0u32;
    let mut r = 0u32;
    for _ in 0..25 {
        for i in 0..8usize {
            d_encrypt(&mut l, r, ks, i.saturating_mul(4), Some((e0, e1)));
            d_encrypt(
                &mut r,
                l,
                ks,
                i.saturating_mul(4).saturating_add(2),
                Some((e0, e1)),
            );
        }
        core::mem::swap(&mut l, &mut r);
    }
    l = l.rotate_right(3);
    r = r.rotate_right(3);
    perm_op(&mut l, &mut r, 1, 0x5555_5555);
    perm_op(&mut r, &mut l, 8, 0x00ff_00ff);
    perm_op(&mut l, &mut r, 2, 0x3333_3333);
    perm_op(&mut r, &mut l, 16, 0x0000_ffff);
    perm_op(&mut l, &mut r, 4, 0x0f0f_0f0f);
    [r, l]
}

/// What `DES_fcrypt` writes: the salt's two characters (as far as it got), and the 13
/// characters of the result, or `None` for a salt character that's NUL or past 127.
pub struct Fcrypt {
    /// The octets OpenSSL writes into the result before it checks them.
    pub salt_written: usize,
    /// The result (the salt, eleven characters, and a NUL), if the salt was good.
    pub out: Option<[u8; 14]>,
}

/// `DES_fcrypt`: traditional `crypt(3)` of the first 8 octets of `password` (up to a NUL) with
/// the two salt characters.
pub fn fcrypt(password: &[u8], salt: [u8; 2]) -> Fcrypt {
    let check = |x: u8| x != 0 && usize::from(x) < CON_SALT.len();
    if !check(salt[0]) {
        return Fcrypt {
            salt_written: 1,
            out: None,
        };
    }
    if !check(salt[1]) {
        return Fcrypt {
            salt_written: 2,
            out: None,
        };
    }
    let e0 = u32::from(CON_SALT.get(usize::from(salt[0])).copied().unwrap_or(0)) << 2;
    let e1 = u32::from(CON_SALT.get(usize::from(salt[1])).copied().unwrap_or(0)) << 6;
    let mut key = [0u8; 8];
    for (k, &c) in key.iter_mut().zip(password.iter().take_while(|&&c| c != 0)) {
        *k = c << 1;
    }
    let mut ks = set_key_unchecked(&key);
    key.zeroize();
    let out = fcrypt_body(&ks, e0, e1);
    ks.zeroize();
    let mut bb = [0u8; 9];
    store(out, &mut bb, 0);
    let mut res = [0u8; 14];
    res[0] = salt[0];
    res[1] = salt[1];
    let mut y = 0usize;
    let mut u = 0x80u8;
    for r in res.iter_mut().take(13).skip(2) {
        let mut c = 0u8;
        for _ in 0..6 {
            c <<= 1;
            if bb.get(y).copied().unwrap_or(0) & u != 0 {
                c |= 1;
            }
            u >>= 1;
            if u == 0 {
                y = y.saturating_add(1);
                u = 0x80;
            }
        }
        *r = COV_2CHAR.get(usize::from(c)).copied().unwrap_or(0);
    }
    bb.zeroize();
    Fcrypt {
        salt_written: 2,
        out: Some(res),
    }
}

#[cfg(test)]
mod tests;
