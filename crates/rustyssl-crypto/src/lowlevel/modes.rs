//! The 128-bit block modes behind `modes.h` and the `AES_*` mode functions: CBC, CTR, OFB,
//! CFB (by octets, by 8 bits, and by single bits), ciphertext stealing (CTS and NIST's
//! CBC-CS3), and the RFC 3394 and RFC 5649 key wraps, over a block function the caller passes
//! (`cbc128.c`, `ctr128.c`, `ofb128.c`, `cfb128.c`, `cts128.c`, `wrap128.c`, and `aes_ige.c`'s
//! IGE and bi-IGE).
//!
//! The steps are OpenSSL's, so the IV, the keystream buffer, and the position in it hold what
//! OpenSSL leaves there, and the variants that take a whole-buffer CBC or CTR function call it
//! with the same lengths, in the same order. Input and output are separate slices: a caller
//! with one buffer for both copies the input first (which is what OpenSSL computes for the
//! same buffer). A position past the block is refused where OpenSSL reads out of bounds.

use zeroize::Zeroize;

/// The block size.
pub const BLOCK: usize = 16;

/// A block function: one block in, one out (`block128_f`).
pub trait Block128 {
    /// Transforms `input`.
    fn block(&self, input: &[u8; BLOCK]) -> [u8; BLOCK];
}

/// A whole-buffer CBC function (`cbc128_f`): `input.len()` octets (a multiple of the block
/// size) into `out`, chaining from and updating `iv`.
pub trait Cbc128 {
    /// Encrypts (`enc`) or decrypts.
    fn cbc(&self, input: &[u8], out: &mut [u8], iv: &mut [u8; BLOCK], enc: bool);
}

/// A whole-buffer CTR function (`ctr128_f`): `blocks` blocks of `input` into `out` under the
/// counter block `iv`, whose last 32 bits count up; it leaves `iv` as it was.
pub trait Ctr128 {
    /// Encrypts (or decrypts) `blocks` blocks.
    fn ctr(&self, input: &[u8], out: &mut [u8], blocks: usize, iv: &[u8; BLOCK]);

    /// [`Ctr128::ctr`] on `data` in place: the input there, the output there too.
    fn ctr_in_place(&self, data: &mut [u8], blocks: usize, iv: &[u8; BLOCK]) {
        let input = zeroize::Zeroizing::new(data.to_vec());
        self.ctr(&input, data, blocks, iv);
    }
}

/// A position in the current block past its end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Corrupt;

/// The block at `at` of `data`, zero-filled past its end.
fn block_at(data: &[u8], at: usize) -> [u8; BLOCK] {
    let mut b = [0u8; BLOCK];
    for (d, s) in b.iter_mut().zip(data.iter().skip(at)) {
        *d = *s;
    }
    b
}

/// Copies `src` into `out` from octet `at` on, as far as `out` reaches.
fn put(out: &mut [u8], at: usize, src: &[u8]) {
    for (d, s) in out.iter_mut().skip(at).zip(src) {
        *d = *s;
    }
}

/// XOR of two blocks.
fn xor(a: &[u8; BLOCK], b: &[u8; BLOCK]) -> [u8; BLOCK] {
    core::array::from_fn(|i| a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0))
}

/// The octet at `i`, or 0 past the end.
fn at(data: &[u8], i: usize) -> u8 {
    data.get(i).copied().unwrap_or(0)
}

/// CBC encryption (`CRYPTO_cbc128_encrypt`). A partial last block is padded with the chain's
/// own octets (as zeros under the XOR) and encrypted whole, so `out` takes `input.len()`
/// rounded up to the block size.
pub fn cbc_encrypt(input: &[u8], out: &mut [u8], iv: &mut [u8; BLOCK], b: &impl Block128) {
    crate::dit::with(|| {
        let mut chain = *iv;
        for (i, chunk) in input.chunks(BLOCK).enumerate() {
            let plain = block_at(chunk, 0);
            let mut mixed = [0u8; BLOCK];
            for (n, m) in mixed.iter_mut().enumerate() {
                *m = if n < chunk.len() {
                    at(&plain, n) ^ at(&chain, n)
                } else {
                    at(&chain, n)
                };
            }
            chain = b.block(&mixed);
            put(out, i.saturating_mul(BLOCK), &chain);
        }
        *iv = chain;
    })
}

/// CBC decryption (`CRYPTO_cbc128_decrypt`) of `len` octets: a partial last block is read
/// whole (so `input` holds `len` rounded up to the block size) and only `len` octets written;
/// the IV ends as the last ciphertext block.
pub fn cbc_decrypt(
    input: &[u8],
    out: &mut [u8],
    len: usize,
    iv: &mut [u8; BLOCK],
    b: &impl Block128,
) {
    crate::dit::with(|| {
        let mut done = 0;
        while done < len {
            let c = block_at(input, done);
            let mut p = xor(&b.block(&c), iv);
            let n = len.saturating_sub(done).min(BLOCK);
            put(out, done, p.get(..n).unwrap_or_default());
            p.zeroize();
            *iv = c;
            done = done.saturating_add(BLOCK);
        }
    })
}

/// Increments a big-endian counter of the first `n` octets of `counter`.
fn increment(counter: &mut [u8; BLOCK], n: usize) {
    let mut carry = 1u16;
    for b in counter.iter_mut().take(n).rev() {
        carry = carry.saturating_add(u16::from(*b));
        *b = carry.to_le_bytes()[0];
        carry >>= 8;
    }
}

/// CTR mode with a block function (`CRYPTO_ctr128_encrypt`): `ecount` holds the keystream
/// block and `num` the position in it, carried between calls; the whole IV counts up.
pub fn ctr_encrypt(
    input: &[u8],
    out: &mut [u8],
    iv: &mut [u8; BLOCK],
    ecount: &mut [u8; BLOCK],
    num: &mut u32,
    b: &impl Block128,
) -> Result<(), Corrupt> {
    crate::dit::with(|| {
        let mut n = usize::try_from(*num)
            .ok()
            .filter(|&n| n < BLOCK)
            .ok_or(Corrupt)?;
        for (i, x) in input.iter().enumerate() {
            if n == 0 {
                *ecount = b.block(iv);
                increment(iv, BLOCK);
            }
            if let Some(o) = out.get_mut(i) {
                *o = x ^ at(ecount, n);
            }
            n = n.wrapping_add(1) % BLOCK;
        }
        *num = u32::try_from(n).unwrap_or(0);
        Ok(())
    })
}

/// CTR mode with a whole-buffer function that counts in the IV's last 32 bits
/// (`CRYPTO_ctr128_encrypt_ctr32`): the carry out of them goes into the first 96 bits between
/// calls, at most 2^28 blocks each; a partial last block's keystream comes from encrypting
/// zeros.
pub fn ctr32_encrypt(
    input: &[u8],
    out: &mut [u8],
    iv: &mut [u8; BLOCK],
    ecount: &mut [u8; BLOCK],
    num: &mut u32,
    f: &impl Ctr128,
) -> Result<(), Corrupt> {
    crate::dit::with(|| {
        let mut n = usize::try_from(*num)
            .ok()
            .filter(|&n| n < BLOCK)
            .ok_or(Corrupt)?;
        let mut done = 0;
        let len = input.len();
        while n != 0 && done < len {
            if let Some(o) = out.get_mut(done) {
                *o = at(input, done) ^ at(ecount, n);
            }
            done = done.wrapping_add(1);
            n = n.wrapping_add(1) % BLOCK;
        }
        let read_ctr =
            |iv: &[u8; BLOCK]| u32::from_be_bytes([at(iv, 12), at(iv, 13), at(iv, 14), at(iv, 15)]);
        let write_ctr = |iv: &mut [u8; BLOCK], c: u32| put(iv, 12, &c.to_be_bytes());
        let mut ctr32 = read_ctr(iv);
        while len.saturating_sub(done) >= BLOCK {
            let mut blocks = len.saturating_sub(done) / BLOCK;
            if blocks > 1 << 28 {
                blocks = 1 << 28;
            }
            let low = u32::try_from(blocks).unwrap_or(u32::MAX);
            ctr32 = ctr32.wrapping_add(low);
            if usize::try_from(ctr32).unwrap_or(usize::MAX) < blocks {
                blocks = blocks.saturating_sub(usize::try_from(ctr32).unwrap_or(0));
                ctr32 = 0;
            }
            let bytes = blocks.saturating_mul(BLOCK);
            let end = done.saturating_add(bytes);
            if let (Some(i), Some(o)) = (input.get(done..end), out.get_mut(done..end)) {
                f.ctr(i, o, blocks, iv);
            }
            write_ctr(iv, ctr32);
            if ctr32 == 0 {
                increment(iv, 12);
            }
            done = end;
        }
        if done < len {
            let zero = [0u8; BLOCK];
            *ecount = [0; BLOCK];
            f.ctr(&zero, ecount, 1, iv);
            ctr32 = ctr32.wrapping_add(1);
            write_ctr(iv, ctr32);
            if ctr32 == 0 {
                increment(iv, 12);
            }
            while done < len {
                if let Some(o) = out.get_mut(done) {
                    *o = at(input, done) ^ at(ecount, n);
                }
                n = n.wrapping_add(1);
                done = done.wrapping_add(1);
            }
        }
        *num = u32::try_from(n).unwrap_or(0);
        Ok(())
    })
}

/// The position in an OFB or CFB block: negative is refused as OpenSSL does (it sets -1 and
/// does nothing), past the block as corrupt.
fn position(num: &mut i32) -> Option<Result<usize, Corrupt>> {
    if *num < 0 {
        *num = -1;
        return None;
    }
    Some(
        usize::try_from(*num)
            .ok()
            .filter(|&n| n < BLOCK)
            .ok_or(Corrupt),
    )
}

/// OFB mode (`CRYPTO_ofb128_encrypt`): the IV is the keystream block, `num` the position in it.
pub fn ofb_encrypt(
    input: &[u8],
    out: &mut [u8],
    iv: &mut [u8; BLOCK],
    num: &mut i32,
    b: &impl Block128,
) -> Result<(), Corrupt> {
    crate::dit::with(|| {
        let Some(n) = position(num) else {
            return Ok(());
        };
        let mut n = n?;
        for (i, x) in input.iter().enumerate() {
            if n == 0 {
                *iv = b.block(iv);
            }
            if let Some(o) = out.get_mut(i) {
                *o = x ^ at(iv, n);
            }
            n = n.wrapping_add(1) % BLOCK;
        }
        *num = i32::try_from(n).unwrap_or(0);
        Ok(())
    })
}

/// CFB mode by octets (`CRYPTO_cfb128_encrypt`): the IV becomes the ciphertext as it goes,
/// `num` the position in it.
pub fn cfb_encrypt(
    input: &[u8],
    out: &mut [u8],
    iv: &mut [u8; BLOCK],
    num: &mut i32,
    enc: bool,
    b: &impl Block128,
) -> Result<(), Corrupt> {
    crate::dit::with(|| {
        let Some(n) = position(num) else {
            return Ok(());
        };
        let mut n = n?;
        for (i, x) in input.iter().enumerate() {
            if n == 0 {
                *iv = b.block(iv);
            }
            let k = at(iv, n);
            let (o, c) = if enc { (x ^ k, x ^ k) } else { (x ^ k, *x) };
            if let Some(d) = out.get_mut(i) {
                *d = o;
            }
            if let Some(v) = iv.get_mut(n) {
                *v = c;
            }
            n = n.wrapping_add(1) % BLOCK;
        }
        *num = i32::try_from(n).unwrap_or(0);
        Ok(())
    })
}

/// One CFB step of `nbits` bits (1 to 128): `input`'s first `(nbits + 7) / 8` octets in, as
/// many out (the bits past `nbits` in the last octet are whatever falls out), and the IV
/// shifted left by `nbits` with the ciphertext bits coming in (`cfbr_encrypt_block`).
fn cfbr_block(
    input: &[u8],
    out: &mut [u8],
    nbits: usize,
    iv: &mut [u8; BLOCK],
    enc: bool,
    b: &impl Block128,
) {
    if nbits == 0 || nbits > 128 {
        return;
    }
    let mut ovec = [0u8; 2 * BLOCK + 1];
    put(&mut ovec, 0, iv);
    *iv = b.block(iv);
    let num = nbits.div_ceil(8);
    for n in 0..num {
        let x = at(input, n);
        let k = at(iv, n);
        let (o, c) = if enc { (x ^ k, x ^ k) } else { (x ^ k, x) };
        if let Some(d) = out.get_mut(n) {
            *d = o;
        }
        if let Some(v) = ovec.get_mut(BLOCK.saturating_add(n)) {
            *v = c;
        }
    }
    let rem = nbits % 8;
    let num = nbits / 8;
    for (n, v) in iv.iter_mut().enumerate() {
        let hi = at(&ovec, n.saturating_add(num));
        *v = if rem == 0 {
            hi
        } else {
            (hi << rem)
                | (at(&ovec, n.saturating_add(num).saturating_add(1)) >> 8usize.wrapping_sub(rem))
        };
    }
}

/// CFB-1 (`CRYPTO_cfb128_1_encrypt`): `bits` bits, most significant first, each a CFB step;
/// the other bits of `out`'s last octet keep their values.
pub fn cfb1_encrypt(
    input: &[u8],
    out: &mut [u8],
    bits: usize,
    iv: &mut [u8; BLOCK],
    enc: bool,
    b: &impl Block128,
) {
    crate::dit::with(|| {
        for n in 0..bits {
            let mask = 0x80u8 >> (n % 8);
            let c = if at(input, n / 8) & mask != 0 {
                0x80
            } else {
                0
            };
            let mut d = [0u8; 1];
            cfbr_block(&[c], &mut d, 1, iv, enc, b);
            if let Some(o) = out.get_mut(n / 8) {
                *o = (*o & !mask) | ((d[0] & 0x80) >> (n % 8));
            }
        }
    })
}

/// CFB-8 (`CRYPTO_cfb128_8_encrypt`): a CFB step per octet.
pub fn cfb8_encrypt(
    input: &[u8],
    out: &mut [u8],
    iv: &mut [u8; BLOCK],
    enc: bool,
    b: &impl Block128,
) {
    crate::dit::with(|| {
        for (i, x) in input.iter().enumerate() {
            let mut d = [0u8; 1];
            cfbr_block(&[*x], &mut d, 8, iv, enc, b);
            if let Some(o) = out.get_mut(i) {
                *o = d[0];
            }
        }
    })
}

/// CTS encryption with a block function (`CRYPTO_cts128_encrypt_block`): returns the length
/// written, or 0 for 16 octets or fewer.
pub fn cts_encrypt_block(
    input: &[u8],
    out: &mut [u8],
    iv: &mut [u8; BLOCK],
    b: &impl Block128,
) -> usize {
    crate::dit::with(|| {
        let len = input.len();
        if len <= BLOCK {
            return 0;
        }
        let residue = match len % BLOCK {
            0 => BLOCK,
            r => r,
        };
        let head = len.saturating_sub(residue);
        cbc_encrypt(input.get(..head).unwrap_or_default(), out, iv, b);
        let tail = input.get(head..).unwrap_or_default();
        for (v, x) in iv.iter_mut().zip(tail) {
            *v ^= x;
        }
        *iv = b.block(iv);
        let prev = block_at(out, head.saturating_sub(BLOCK));
        put(out, head, prev.get(..residue).unwrap_or_default());
        put(out, head.saturating_sub(BLOCK), iv);
        len
    })
}

/// NIST CBC-CS3 encryption with a block function (`CRYPTO_nistcts128_encrypt_block`): returns
/// the length written, or 0 for fewer than 16 octets.
pub fn nistcts_encrypt_block(
    input: &[u8],
    out: &mut [u8],
    iv: &mut [u8; BLOCK],
    b: &impl Block128,
) -> usize {
    crate::dit::with(|| {
        let len = input.len();
        if len < BLOCK {
            return 0;
        }
        let residue = len % BLOCK;
        let head = len.saturating_sub(residue);
        cbc_encrypt(input.get(..head).unwrap_or_default(), out, iv, b);
        if residue == 0 {
            return head;
        }
        for (v, x) in iv.iter_mut().zip(input.get(head..).unwrap_or_default()) {
            *v ^= x;
        }
        *iv = b.block(iv);
        put(out, head.saturating_sub(BLOCK).saturating_add(residue), iv);
        len
    })
}

/// CTS encryption with a CBC function (`CRYPTO_cts128_encrypt`).
pub fn cts_encrypt(input: &[u8], out: &mut [u8], iv: &mut [u8; BLOCK], f: &impl Cbc128) -> usize {
    crate::dit::with(|| {
        let len = input.len();
        if len <= BLOCK {
            return 0;
        }
        let residue = match len % BLOCK {
            0 => BLOCK,
            r => r,
        };
        let head = len.saturating_sub(residue);
        if let Some(o) = out.get_mut(..head) {
            f.cbc(input.get(..head).unwrap_or_default(), o, iv, true);
        }
        let tmp = block_at(input.get(head..).unwrap_or_default(), 0);
        let prev = block_at(out, head.saturating_sub(BLOCK));
        put(out, head, prev.get(..residue).unwrap_or_default());
        let mut last = [0u8; BLOCK];
        f.cbc(&tmp, &mut last, iv, true);
        put(out, head.saturating_sub(BLOCK), &last);
        len
    })
}

/// NIST CBC-CS3 encryption with a CBC function (`CRYPTO_nistcts128_encrypt`).
pub fn nistcts_encrypt(
    input: &[u8],
    out: &mut [u8],
    iv: &mut [u8; BLOCK],
    f: &impl Cbc128,
) -> usize {
    crate::dit::with(|| {
        let len = input.len();
        if len < BLOCK {
            return 0;
        }
        let residue = len % BLOCK;
        let head = len.saturating_sub(residue);
        if let Some(o) = out.get_mut(..head) {
            f.cbc(input.get(..head).unwrap_or_default(), o, iv, true);
        }
        if residue == 0 {
            return head;
        }
        let tmp = block_at(input.get(head..).unwrap_or_default(), 0);
        let mut last = [0u8; BLOCK];
        f.cbc(&tmp, &mut last, iv, true);
        put(
            out,
            head.saturating_sub(BLOCK).saturating_add(residue),
            &last,
        );
        len
    })
}

/// CTS decryption with a block function (`CRYPTO_cts128_decrypt_block`): returns the length
/// plus 16, as OpenSSL does, or 0 for 16 octets or fewer.
pub fn cts_decrypt_block(
    input: &[u8],
    out: &mut [u8],
    iv: &mut [u8; BLOCK],
    b: &impl Block128,
) -> usize {
    crate::dit::with(|| {
        let len = input.len();
        if len <= BLOCK {
            return 0;
        }
        let residue = match len % BLOCK {
            0 => BLOCK,
            r => r,
        };
        let head = len.saturating_sub(BLOCK).saturating_sub(residue);
        if head != 0 {
            cbc_decrypt(input, out, head, iv, b);
        }
        let c1 = block_at(input, head);
        let mut tmp = [0u8; 2 * BLOCK];
        let d1 = b.block(&c1);
        put(&mut tmp, 0, &d1);
        put(&mut tmp, BLOCK, &d1);
        put(
            &mut tmp,
            0,
            input
                .get(head.saturating_add(BLOCK)..len)
                .unwrap_or_default(),
        );
        let first = b.block(&block_at(&tmp, 0));
        put(&mut tmp, 0, &first);
        for n in 0..BLOCK {
            let c = at(input, head.saturating_add(n));
            if let Some(o) = out.get_mut(head.saturating_add(n)) {
                *o = at(&tmp, n) ^ at(iv, n);
            }
            if let Some(v) = iv.get_mut(n) {
                *v = c;
            }
        }
        for n in BLOCK..BLOCK.saturating_add(residue) {
            if let Some(o) = out.get_mut(head.saturating_add(n)) {
                *o = at(&tmp, n) ^ at(input, head.saturating_add(n));
            }
        }
        tmp.zeroize();
        // OpenSSL's count includes the last block twice: it adds the block size to the residue
        // before adding the residue in.
        len.saturating_add(BLOCK)
    })
}

/// NIST CBC-CS3 decryption with a block function (`CRYPTO_nistcts128_decrypt_block`): returns
/// the length (plus 16, as OpenSSL does, unless it's whole blocks), or 0 for fewer than 16
/// octets.
pub fn nistcts_decrypt_block(
    input: &[u8],
    out: &mut [u8],
    iv: &mut [u8; BLOCK],
    b: &impl Block128,
) -> usize {
    crate::dit::with(|| {
        let len = input.len();
        if len < BLOCK {
            return 0;
        }
        let residue = len % BLOCK;
        if residue == 0 {
            cbc_decrypt(input, out, len, iv, b);
            return len;
        }
        let head = len.saturating_sub(BLOCK).saturating_sub(residue);
        if head != 0 {
            cbc_decrypt(input, out, head, iv, b);
        }
        let mut tmp = [0u8; 2 * BLOCK];
        let d = b.block(&block_at(input, head.saturating_add(residue)));
        put(&mut tmp, 0, &d);
        put(&mut tmp, BLOCK, &d);
        put(
            &mut tmp,
            0,
            input
                .get(head..head.saturating_add(residue))
                .unwrap_or_default(),
        );
        let first = b.block(&block_at(&tmp, 0));
        put(&mut tmp, 0, &first);
        for n in 0..BLOCK {
            let c = at(input, head.saturating_add(n));
            if let Some(o) = out.get_mut(head.saturating_add(n)) {
                *o = at(&tmp, n) ^ at(iv, n);
            }
            if let Some(v) = iv.get_mut(n) {
                *v = at(input, head.saturating_add(n).saturating_add(residue));
            }
            if let Some(t) = tmp.get_mut(n) {
                *t = c;
            }
        }
        for n in BLOCK..BLOCK.saturating_add(residue) {
            if let Some(o) = out.get_mut(head.saturating_add(n)) {
                *o = at(&tmp, n) ^ at(&tmp, n.saturating_sub(BLOCK));
            }
        }
        tmp.zeroize();
        // OpenSSL's count includes the last block twice: it adds the block size to the residue
        // before adding the residue in.
        len.saturating_add(BLOCK)
    })
}

/// CTS decryption with a CBC function (`CRYPTO_cts128_decrypt`).
pub fn cts_decrypt(input: &[u8], out: &mut [u8], iv: &mut [u8; BLOCK], f: &impl Cbc128) -> usize {
    crate::dit::with(|| {
        let len = input.len();
        if len <= BLOCK {
            return 0;
        }
        let residue = match len % BLOCK {
            0 => BLOCK,
            r => r,
        };
        let head = len.saturating_sub(BLOCK).saturating_sub(residue);
        if head != 0
            && let Some(o) = out.get_mut(..head)
        {
            f.cbc(input.get(..head).unwrap_or_default(), o, iv, false);
        }
        cts_decrypt_tail(
            input,
            out,
            head,
            BLOCK.saturating_add(residue),
            iv,
            f,
            head,
            head.saturating_add(BLOCK),
        );
        len
    })
}

/// NIST CBC-CS3 decryption with a CBC function (`CRYPTO_nistcts128_decrypt`).
pub fn nistcts_decrypt(
    input: &[u8],
    out: &mut [u8],
    iv: &mut [u8; BLOCK],
    f: &impl Cbc128,
) -> usize {
    crate::dit::with(|| {
        let len = input.len();
        if len < BLOCK {
            return 0;
        }
        let residue = len % BLOCK;
        if residue == 0 {
            if let Some(o) = out.get_mut(..len) {
                f.cbc(input, o, iv, false);
            }
            return len;
        }
        let head = len.saturating_sub(BLOCK).saturating_sub(residue);
        if head != 0
            && let Some(o) = out.get_mut(..head)
        {
            f.cbc(input.get(..head).unwrap_or_default(), o, iv, false);
        }
        cts_decrypt_tail(
            input,
            out,
            head,
            BLOCK.saturating_add(residue),
            iv,
            f,
            head.saturating_add(residue),
            head,
        );
        len
    })
}

/// The last two blocks of a CTS decryption through a CBC function: the block at `full`
/// decrypted alone (under a zero IV, which the function leaves as that block), the partial
/// block at `partial` laid over its start, and the two decrypted together into the `n` octets
/// of `out` from `head`.
#[allow(clippy::too_many_arguments)]
fn cts_decrypt_tail(
    input: &[u8],
    out: &mut [u8],
    head: usize,
    n: usize,
    iv: &mut [u8; BLOCK],
    f: &impl Cbc128,
    full: usize,
    partial: usize,
) {
    let residue = n.saturating_sub(BLOCK);
    let mut tmp = [0u8; 2 * BLOCK];
    let mut first = [0u8; BLOCK];
    let mut zero_iv = [0u8; BLOCK];
    f.cbc(&block_at(input, full), &mut first, &mut zero_iv, false);
    put(&mut tmp, 0, &first);
    put(&mut tmp, BLOCK, &zero_iv);
    put(
        &mut tmp,
        0,
        input
            .get(partial..partial.saturating_add(residue))
            .unwrap_or_default(),
    );
    let mut both = [0u8; 2 * BLOCK];
    f.cbc(&tmp, &mut both, iv, false);
    put(out, head, both.get(..n).unwrap_or_default());
    tmp.zeroize();
    both.zeroize();
    first.zeroize();
}

/// RFC 3394's default IV.
const DEFAULT_IV: [u8; 8] = [0xa6; 8];
/// RFC 5649's alternative IV prefix.
const DEFAULT_AIV: [u8; 4] = [0xa6, 0x59, 0x59, 0xa6];
/// The longest input the wraps take.
const WRAP_MAX: usize = 1 << 31;

/// Constant-time equality of two octet strings of one length.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// XORs the step counter into `a`'s last octets, as OpenSSL does (the low octet always, the
/// next three only past 255).
fn xor_t(a: &mut [u8; BLOCK], t: usize) {
    let t = t.to_be_bytes();
    let [.., t3, t2, t1, t0] = t;
    a[7] ^= t0;
    if t3 != 0 || t2 != 0 || t1 != 0 {
        a[6] ^= t1;
        a[5] ^= t2;
        a[4] ^= t3;
    }
}

/// RFC 3394 wrapping (`CRYPTO_128_wrap`) into `out` (`input.len() + 8` octets): returns that
/// length, or 0 for an input that isn't 16 octets or more in 8-octet steps.
pub fn wrap(iv: Option<&[u8; 8]>, input: &[u8], out: &mut [u8], b: &impl Block128) -> usize {
    crate::dit::with(|| {
        let inlen = input.len();
        if !inlen.is_multiple_of(8) || !(16..=WRAP_MAX).contains(&inlen) {
            return 0;
        }
        let mut r = input.to_vec();
        let mut buf = [0u8; BLOCK];
        put(&mut buf, 0, iv.unwrap_or(&DEFAULT_IV));
        let mut t = 1usize;
        for _ in 0..6 {
            for chunk in r.chunks_mut(8) {
                put(&mut buf, 8, chunk);
                buf = b.block(&buf);
                xor_t(&mut buf, t);
                put(chunk, 0, buf.get(8..).unwrap_or_default());
                t = t.wrapping_add(1);
            }
        }
        put(out, 0, buf.get(..8).unwrap_or_default());
        put(out, 8, &r);
        r.zeroize();
        buf.zeroize();
        inlen.saturating_add(8)
    })
}

/// RFC 3394 unwrapping without the IV check: `out` takes `input.len() - 8` octets; returns
/// that length and the recovered IV, or `None` for a bad length.
fn unwrap_raw(input: &[u8], out: &mut [u8], b: &impl Block128) -> Option<(usize, [u8; 8])> {
    let inlen = input.len().wrapping_sub(8);
    if !inlen.is_multiple_of(8) || !(16..=WRAP_MAX).contains(&inlen) {
        return None;
    }
    let mut buf = [0u8; BLOCK];
    put(&mut buf, 0, input.get(..8).unwrap_or_default());
    let mut r = input.get(8..).unwrap_or_default().to_vec();
    let mut t = (inlen / 8).saturating_mul(6);
    for _ in 0..6 {
        for chunk in r.chunks_mut(8).rev() {
            xor_t(&mut buf, t);
            put(&mut buf, 8, chunk);
            buf = b.block(&buf);
            put(chunk, 0, buf.get(8..).unwrap_or_default());
            t = t.saturating_sub(1);
        }
    }
    put(out, 0, &r);
    r.zeroize();
    let mut a = [0u8; 8];
    put(&mut a, 0, buf.get(..8).unwrap_or_default());
    buf.zeroize();
    Some((inlen, a))
}

/// RFC 3394 unwrapping (`CRYPTO_128_unwrap`): returns the length (`input.len() - 8`), or 0 for
/// a bad length or an IV that doesn't match (after zeroing what it wrote).
pub fn unwrap(iv: Option<&[u8; 8]>, input: &[u8], out: &mut [u8], b: &impl Block128) -> usize {
    crate::dit::with(|| {
        let Some((ret, got)) = unwrap_raw(input, out, b) else {
            return 0;
        };
        if !ct_eq(&got, iv.unwrap_or(&DEFAULT_IV)) {
            for o in out.iter_mut().take(ret) {
                *o = 0;
            }
            return 0;
        }
        ret
    })
}

/// RFC 5649 wrapping with padding (`CRYPTO_128_wrap_pad`): returns the length written (16 for
/// up to 8 octets, else the input padded to 8-octet steps plus 8), or 0 for no input or too
/// much.
pub fn wrap_pad(icv: Option<&[u8; 4]>, input: &[u8], out: &mut [u8], b: &impl Block128) -> usize {
    crate::dit::with(|| {
        let inlen = input.len();
        if inlen == 0 || inlen >= WRAP_MAX {
            return 0;
        }
        let padded = inlen.div_ceil(8).saturating_mul(8);
        let mut aiv = [0u8; 8];
        put(&mut aiv, 0, icv.unwrap_or(&DEFAULT_AIV));
        put(
            &mut aiv,
            4,
            &u32::try_from(inlen).unwrap_or(0).to_be_bytes(),
        );
        let mut data = input.to_vec();
        data.resize(padded, 0);
        let ret = if padded == 8 {
            let mut buf = [0u8; BLOCK];
            put(&mut buf, 0, &aiv);
            put(&mut buf, 8, &data);
            let c = b.block(&buf);
            put(out, 0, &c);
            buf.zeroize();
            BLOCK
        } else {
            wrap(Some(&aiv), &data, out, b)
        };
        data.zeroize();
        ret
    })
}

/// RFC 5649 unwrapping (`CRYPTO_128_unwrap_pad`): returns the unpadded length, or 0 for a bad
/// length, IV, length field, or padding (after zeroing the `input.len() - 8` octets it wrote).
pub fn unwrap_pad(icv: Option<&[u8; 4]>, input: &[u8], out: &mut [u8], b: &impl Block128) -> usize {
    crate::dit::with(|| {
        let inlen = input.len();
        if !inlen.is_multiple_of(8) || !(16..WRAP_MAX).contains(&inlen) {
            return 0;
        }
        let n = (inlen / 8).saturating_sub(1);
        let padded = inlen.saturating_sub(8);
        let mut aiv = [0u8; 8];
        if inlen == 16 {
            let mut buf = b.block(&block_at(input, 0));
            put(&mut aiv, 0, buf.get(..8).unwrap_or_default());
            put(out, 0, buf.get(8..).unwrap_or_default());
            buf.zeroize();
        } else {
            match unwrap_raw(input, out, b) {
                Some((ret, got)) if ret == padded => aiv = got,
                _ => return fail(out, padded),
            }
        }
        let prefix = aiv.get(..4).unwrap_or_default();
        if !ct_eq(prefix, icv.unwrap_or(&DEFAULT_AIV)) {
            return fail(out, padded);
        }
        let ptext = usize::try_from(u32::from_be_bytes([aiv[4], aiv[5], aiv[6], aiv[7]]))
            .unwrap_or(usize::MAX);
        if n.saturating_sub(1).saturating_mul(8) >= ptext || ptext > n.saturating_mul(8) {
            return fail(out, padded);
        }
        let zeros = [0u8; 8];
        let pad = out.get(ptext..padded).unwrap_or_default();
        if !ct_eq(pad, zeros.get(..pad.len()).unwrap_or_default()) {
            return fail(out, padded);
        }
        ptext
    })
}

/// Zeroes the first `n` octets of `out` and returns 0.
fn fail(out: &mut [u8], n: usize) -> usize {
    for o in out.iter_mut().take(n) {
        *o = 0;
    }
    0
}

/// IGE mode (`AES_ige_encrypt`): `input.len()` is a multiple of the block size; `iv` is two
/// blocks, the previous ciphertext and plaintext, and ends as the last ones.
pub fn ige(input: &[u8], out: &mut [u8], iv: &mut [u8; 2 * BLOCK], enc: bool, b: &impl Block128) {
    crate::dit::with(|| {
        let mut first = block_at(iv, 0);
        let mut second = block_at(iv, BLOCK);
        for (i, chunk) in input.chunks(BLOCK).enumerate() {
            let x = block_at(chunk, 0);
            let y = if enc {
                let y = xor(&b.block(&xor(&x, &first)), &second);
                first = y;
                second = x;
                y
            } else {
                let y = xor(&b.block(&xor(&x, &second)), &first);
                first = x;
                second = y;
                y
            };
            put(out, i.saturating_mul(BLOCK), &y);
        }
        put(iv, 0, &first);
        put(iv, BLOCK, &second);
    })
}

/// Bi-directional IGE (`AES_bi_ige_encrypt`): IGE forwards under the IV's first two blocks,
/// then backwards under its last two, all with the one key (OpenSSL never uses the second it's
/// given); decryption runs the passes the other way round. `input.len()` is a multiple of the
/// block size.
pub fn bi_ige(input: &[u8], out: &mut [u8], iv: &[u8; 4 * BLOCK], enc: bool, b: &impl Block128) {
    crate::dit::with(|| {
        let blocks: Vec<[u8; BLOCK]> = input.chunks(BLOCK).map(|c| block_at(c, 0)).collect();
        let front = (block_at(iv, 0), block_at(iv, BLOCK));
        let back = (block_at(iv, 2 * BLOCK), block_at(iv, 3 * BLOCK));
        let pass =
            |data: &[[u8; BLOCK]], (mut p, mut q): ([u8; BLOCK], [u8; BLOCK]), reverse: bool| {
                let mut res = vec![[0u8; BLOCK]; data.len()];
                let order: Vec<usize> = if reverse {
                    (0..data.len()).rev().collect()
                } else {
                    (0..data.len()).collect()
                };
                for i in order {
                    let x = data.get(i).copied().unwrap_or_default();
                    let y = if enc {
                        let y = xor(&b.block(&xor(&x, &p)), &q);
                        p = y;
                        q = x;
                        y
                    } else {
                        let y = xor(&b.block(&xor(&x, &q)), &p);
                        p = x;
                        q = y;
                        y
                    };
                    if let Some(r) = res.get_mut(i) {
                        *r = y;
                    }
                }
                res
            };
        let result = if enc {
            let mid = pass(&blocks, front, false);
            pass(&mid, back, true)
        } else {
            let mid = pass(&blocks, back, true);
            pass(&mid, front, false)
        };
        for (i, y) in result.iter().enumerate() {
            put(out, i.saturating_mul(BLOCK), y);
        }
    })
}

#[cfg(test)]
mod tests;
