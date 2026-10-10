//! Message authentication codes: the computations behind the built-in providers' MACs (HMAC,
//! CMAC, GMAC, KMAC128/256, Poly1305, SipHash, BLAKE2BMAC and BLAKE2SMAC), behind one trait.
//!
//! Most are ours, composed from the digest backend (`md`) and the cipher primitives (`sym`):
//! HMAC (RFC 2104) over any fixed-size digest, CMAC (SP 800-38B) over any 64- or 128-bit block
//! cipher, GMAC (SP 800-38D) over any 128-bit one, KMAC (SP 800-185) over our Keccak sponge,
//! Poly1305 over the `poly1305` crate's universal hash, and SipHash, which no vetted crate
//! offers with OpenSSL's choice of rounds and 128-bit output. The BLAKE2 MACs run the `blake2`
//! crate's core with the key, salt, personalization (OpenSSL's "custom"), and output size in
//! its parameter block.
//!
//! The limits are OpenSSL's: HMAC refuses XOF digests; KMAC takes keys of 4 to 512 octets,
//! customization strings of at most 512, and at most 2^21 - 1 octets of output; SipHash takes
//! a 16-octet key and 8 or 16 octets of output; the BLAKE2 MACs take keys of 1 to the digest's
//! size and salts and customization strings of at most a quarter block. GMAC needs an IV (when
//! an application doesn't set one, OpenSSL's GCM makes up a random IV; the EVP layer decides).
//!
//! A MAC absorbs data, then is finalized once into exactly its size. `reset` starts it again
//! with the same key and parameters (`EVP_MAC_init` without a key), and `clone_box` copies it
//! (`EVP_MAC_CTX_dup`). Keys and every key-derived state are wiped when dropped.

use blake2::digest::{
    Output,
    block_api::{Buffer, BufferKindUser, UpdateCore, VariableOutputCore},
    block_buffer::{Lazy, LazyBuffer},
    typenum::Unsigned,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{md, sym};

/// Why a MAC was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A key of a length the MAC doesn't take.
    KeyLength,
    /// An output size the MAC doesn't offer, or finalizing into another length.
    OutputSize,
    /// A customization string that's too long.
    CustomLength,
    /// A salt that's too long.
    SaltLength,
    /// An empty IV.
    IvLength,
    /// A digest HMAC can't use: an XOF.
    Digest,
    /// A block cipher of a size the MAC can't use.
    BlockSize,
    /// The MAC was finalized: reset it first.
    Finalized,
}

/// A keyed MAC computation.
pub trait Mac: Send + Sync {
    /// The MAC's size in octets.
    fn size(&self) -> usize;
    /// Absorbs `data`.
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;
    /// Finishes into `out`, exactly [`Mac::size`] octets.
    fn finalize(&mut self, out: &mut [u8]) -> Result<(), Error>;
    /// Starts again with the same key and parameters.
    fn reset(&mut self);
    /// A copy of the computation so far.
    fn clone_box(&self) -> Box<dyn Mac>;
}

/// Whether `out` fits a MAC of `size` that isn't finalized yet.
fn check_final(done: bool, size: usize, out: &[u8]) -> Result<(), Error> {
    if done {
        Err(Error::Finalized)
    } else if out.len() != size {
        Err(Error::OutputSize)
    } else {
        Ok(())
    }
}

/// A MAC that finished can't absorb more.
fn check_update(done: bool) -> Result<(), Error> {
    if done { Err(Error::Finalized) } else { Ok(()) }
}

// ---------------------------------------------------------------------------------------------
// HMAC

/// HMAC: the inner and outer digests keyed once, copied for each message.
struct Hmac {
    algorithm: md::Algorithm,
    /// The digest after absorbing the key XOR ipad, and after the key XOR opad.
    keyed_inner: Box<dyn md::Context>,
    keyed_outer: Box<dyn md::Context>,
    inner: Box<dyn md::Context>,
    done: bool,
}

/// `key` XORed with `pad`, as a digest's first block.
fn keyed_digest(algorithm: md::Algorithm, block: &[u8], pad: u8) -> Box<dyn md::Context> {
    let mut padded = Zeroizing::new(block.to_vec());
    padded.iter_mut().for_each(|b| *b ^= pad);
    let mut ctx = md::context(algorithm);
    // A new context accepts data.
    let _ = ctx.update(&padded);
    ctx
}

/// HMAC with `digest` (any but an XOF) and `key`; a key longer than a block is hashed first.
pub fn hmac(digest: md::Algorithm, key: &[u8]) -> Result<Box<dyn Mac>, Error> {
    if digest.is_xof() {
        return Err(Error::Digest);
    }
    let block_size = digest.block_size();
    let mut block = Zeroizing::new(vec![0u8; block_size]);
    if key.len() > block_size {
        let mut hashed = Zeroizing::new(vec![0u8; digest.output_size()]);
        let mut ctx = md::context(digest);
        ctx.update(key).map_err(|_| Error::Digest)?;
        ctx.finalize(&mut hashed).map_err(|_| Error::Digest)?;
        block
            .iter_mut()
            .zip(hashed.iter())
            .for_each(|(b, &h)| *b = h);
    } else {
        block.iter_mut().zip(key).for_each(|(b, &k)| *b = k);
    }
    let keyed_inner = keyed_digest(digest, &block, 0x36);
    let keyed_outer = keyed_digest(digest, &block, 0x5c);
    Ok(Box::new(Hmac {
        algorithm: digest,
        inner: keyed_inner.clone_box(),
        keyed_inner,
        keyed_outer,
        done: false,
    }))
}

impl Mac for Hmac {
    fn size(&self) -> usize {
        self.algorithm.output_size()
    }

    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        check_update(self.done)?;
        self.inner.update(data).map_err(|_| Error::Finalized)
    }

    fn finalize(&mut self, out: &mut [u8]) -> Result<(), Error> {
        check_final(self.done, self.size(), out)?;
        let mut inner = Zeroizing::new(vec![0u8; self.size()]);
        self.inner
            .finalize(&mut inner)
            .map_err(|_| Error::Finalized)?;
        let mut outer = self.keyed_outer.clone_box();
        outer.update(&inner).map_err(|_| Error::Finalized)?;
        outer.finalize(out).map_err(|_| Error::Finalized)?;
        self.done = true;
        Ok(())
    }

    fn reset(&mut self) {
        self.inner = self.keyed_inner.clone_box();
        self.done = false;
    }

    fn clone_box(&self) -> Box<dyn Mac> {
        Box::new(Self {
            algorithm: self.algorithm,
            keyed_inner: self.keyed_inner.clone_box(),
            keyed_outer: self.keyed_outer.clone_box(),
            inner: self.inner.clone_box(),
            done: self.done,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// CMAC

/// Doubling in GF(2^n) (SP 800-38B's subkeys), without branching on the secret's top bit.
fn double(block: &[u8]) -> Zeroizing<Vec<u8>> {
    let rb: u8 = if block.len() == 16 { 0x87 } else { 0x1b };
    let carry = block.first().map_or(0, |&b| b >> 7);
    let mut out = Zeroizing::new(vec![0u8; block.len()]);
    let next = block.iter().skip(1).map(|&b| b >> 7).chain([0]);
    for ((o, &b), low) in out.iter_mut().zip(block).zip(next) {
        *o = (b << 1) | low;
    }
    if let Some(last) = out.last_mut() {
        *last ^= rb & 0u8.wrapping_sub(carry);
    }
    out
}

/// CMAC: the chaining value and up to a block held back, as the last block is treated
/// differently.
struct Cmac {
    cipher: Box<dyn sym::BlockCipher>,
    k1: Zeroizing<Vec<u8>>,
    k2: Zeroizing<Vec<u8>>,
    x: Zeroizing<Vec<u8>>,
    pending: Zeroizing<Vec<u8>>,
    done: bool,
}

/// CMAC over a keyed block cipher of 8 or 16 octets.
pub fn cmac(cipher: Box<dyn sym::BlockCipher>) -> Result<Box<dyn Mac>, Error> {
    let n = cipher.block_size();
    if n != 8 && n != 16 {
        return Err(Error::BlockSize);
    }
    let mut l = Zeroizing::new(vec![0u8; n]);
    cipher
        .encrypt_blocks(&mut l)
        .map_err(|_| Error::BlockSize)?;
    let k1 = double(&l);
    let k2 = double(&k1);
    Ok(Box::new(Cmac {
        cipher,
        k1,
        k2,
        x: Zeroizing::new(vec![0u8; n]),
        pending: Zeroizing::new(Vec::with_capacity(n)),
        done: false,
    }))
}

impl Cmac {
    /// Chains one block: X = E(X ^ block).
    fn chain(&mut self, block: &[u8]) {
        self.x.iter_mut().zip(block).for_each(|(x, &b)| *x ^= b);
        // The chaining value is exactly one block.
        let _ = self.cipher.encrypt_blocks(&mut self.x);
    }
}

impl Mac for Cmac {
    fn size(&self) -> usize {
        self.x.len()
    }

    fn update(&mut self, mut data: &[u8]) -> Result<(), Error> {
        check_update(self.done)?;
        let n = self.x.len();
        while !data.is_empty() {
            // A full pending block is chained only once more data follows it.
            if self.pending.len() == n {
                let block = self.pending.clone();
                self.chain(&block);
                self.pending.clear();
            }
            let take = n.saturating_sub(self.pending.len()).min(data.len());
            let (head, rest) = data.split_at(take);
            self.pending.extend_from_slice(head);
            data = rest;
        }
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8]) -> Result<(), Error> {
        check_final(self.done, self.size(), out)?;
        let n = self.x.len();
        let mut last = Zeroizing::new(vec![0u8; n]);
        let subkey = if self.pending.len() == n {
            last.copy_from_slice(&self.pending);
            &self.k1
        } else {
            last.iter_mut()
                .zip(self.pending.iter().copied().chain([0x80]))
                .for_each(|(l, p)| *l = p);
            &self.k2
        };
        last.iter_mut()
            .zip(subkey.iter())
            .for_each(|(l, &k)| *l ^= k);
        self.chain(&last);
        out.copy_from_slice(&self.x);
        self.done = true;
        Ok(())
    }

    fn reset(&mut self) {
        self.x.iter_mut().for_each(|x| *x = 0);
        self.pending.clear();
        self.done = false;
    }

    fn clone_box(&self) -> Box<dyn Mac> {
        Box::new(Self {
            cipher: self.cipher.clone_box(),
            k1: self.k1.clone(),
            k2: self.k2.clone(),
            x: self.x.clone(),
            pending: self.pending.clone(),
            done: self.done,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// GMAC

/// A 128-bit block of two big-endian bit counts, as GCM ends its GHASH input.
fn length_block(a: usize, c: usize) -> Option<[u8; 16]> {
    let bits = |n: usize| u64::try_from(n).ok()?.checked_mul(8);
    let mut block = [0u8; 16];
    let (high, low) = block.split_at_mut(8);
    high.copy_from_slice(&bits(a)?.to_be_bytes());
    low.copy_from_slice(&bits(c)?.to_be_bytes());
    Some(block)
}

/// GHASH fed in pieces: whole blocks go in as they fill.
struct Ghash {
    hash: Box<dyn sym::UniversalHash>,
    pending: Zeroizing<Vec<u8>>,
}

impl Ghash {
    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = 16usize.saturating_sub(self.pending.len()).min(data.len());
            let (head, rest) = data.split_at(take);
            self.pending.extend_from_slice(head);
            data = rest;
            if self.pending.len() == 16 {
                self.hash.update_padded(&self.pending);
                self.pending.clear();
            }
        }
    }

    /// The hash of everything fed, zero-padded, then `lengths`.
    fn finalize(&mut self, lengths: &[u8; 16]) -> [u8; 16] {
        self.hash.update_padded(&self.pending);
        self.pending.clear();
        self.hash.finalize(lengths)
    }

    fn clone(&self) -> Self {
        Self {
            hash: self.hash.clone_box(),
            pending: self.pending.clone(),
        }
    }
}

/// GMAC: GCM's tag over AAD alone.
struct Gmac {
    h: Zeroizing<[u8; 16]>,
    /// E(K, J0), XORed into the tag.
    mask: Zeroizing<[u8; 16]>,
    ghash: Ghash,
    length: usize,
    done: bool,
}

/// GHASH keyed with `h` (any 16 octets, so it isn't refused).
fn ghash(h: &[u8; 16]) -> Result<Ghash, Error> {
    Ok(Ghash {
        hash: sym::universal_hash(sym::HashAlgorithm::Ghash, h).map_err(|_| Error::KeyLength)?,
        pending: Zeroizing::new(Vec::with_capacity(16)),
    })
}

/// GMAC over a keyed 128-bit block cipher and a non-empty IV of any length (12 octets are
/// used as they are; others through GHASH, as GCM does).
pub fn gmac(cipher: Box<dyn sym::BlockCipher>, iv: &[u8]) -> Result<Box<dyn Mac>, Error> {
    if cipher.block_size() != 16 {
        return Err(Error::BlockSize);
    }
    if iv.is_empty() {
        return Err(Error::IvLength);
    }
    let mut h = Zeroizing::new([0u8; 16]);
    cipher
        .encrypt_blocks(&mut *h)
        .map_err(|_| Error::BlockSize)?;
    let mut j0 = Zeroizing::new([0u8; 16]);
    if iv.len() == 12 {
        j0.iter_mut().zip(iv).for_each(|(j, &v)| *j = v);
        if let Some(last) = j0.last_mut() {
            *last = 1;
        }
    } else {
        let mut g = ghash(&h)?;
        g.update(iv);
        *j0 = g.finalize(&length_block(0, iv.len()).ok_or(Error::IvLength)?);
    }
    let mut mask = j0;
    cipher
        .encrypt_blocks(&mut *mask)
        .map_err(|_| Error::BlockSize)?;
    Ok(Box::new(Gmac {
        ghash: ghash(&h)?,
        h,
        mask,
        length: 0,
        done: false,
    }))
}

impl Mac for Gmac {
    fn size(&self) -> usize {
        16
    }

    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        check_update(self.done)?;
        self.length = self
            .length
            .checked_add(data.len())
            .ok_or(Error::OutputSize)?;
        self.ghash.update(data);
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8]) -> Result<(), Error> {
        check_final(self.done, 16, out)?;
        let lengths = length_block(self.length, 0).ok_or(Error::OutputSize)?;
        let mut tag = Zeroizing::new(self.ghash.finalize(&lengths));
        tag.iter_mut()
            .zip(self.mask.iter())
            .for_each(|(t, &m)| *t ^= m);
        out.copy_from_slice(&*tag);
        self.done = true;
        Ok(())
    }

    fn reset(&mut self) {
        if let Ok(g) = ghash(&self.h) {
            self.ghash = g;
        }
        self.length = 0;
        self.done = false;
    }

    fn clone_box(&self) -> Box<dyn Mac> {
        Box::new(Self {
            h: self.h.clone(),
            mask: self.mask.clone(),
            ghash: self.ghash.clone(),
            length: self.length,
            done: self.done,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// KMAC

/// The KMAC variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KmacAlgorithm {
    /// KMAC128 (cSHAKE128; 32 octets by default).
    Kmac128,
    /// KMAC256 (cSHAKE256; 64 octets by default).
    Kmac256,
}

impl KmacAlgorithm {
    /// OpenSSL's default output size.
    pub const fn default_size(self) -> usize {
        match self {
            Self::Kmac128 => 32,
            Self::Kmac256 => 64,
        }
    }

    const fn digest(self) -> md::Algorithm {
        match self {
            Self::Kmac128 => md::Algorithm::KeccakKmac128,
            Self::Kmac256 => md::Algorithm::KeccakKmac256,
        }
    }
}

/// OpenSSL's KMAC limits (`KMAC_MIN_KEY`, `KMAC_MAX_KEY`, `KMAC_MAX_CUSTOM`,
/// `KMAC_MAX_OUTPUT_LEN`).
const KMAC_MIN_KEY: usize = 4;
const KMAC_MAX_KEY: usize = 512;
const KMAC_MAX_CUSTOM: usize = 512;
const KMAC_MAX_OUTPUT: usize = 0xff_ffff / 8;

/// SP 800-185's `left_encode` (`right` false) or `right_encode` of `x`.
fn encode(x: usize, right: bool) -> Vec<u8> {
    let bytes = u64::try_from(x).unwrap_or(u64::MAX).to_be_bytes();
    let skip = bytes.iter().take(7).take_while(|&&b| b == 0).count();
    let digits = bytes.get(skip..).unwrap_or(&[]);
    let n = u8::try_from(digits.len()).unwrap_or(8);
    let mut out = Vec::with_capacity(9);
    if !right {
        out.push(n);
    }
    out.extend_from_slice(digits);
    if right {
        out.push(n);
    }
    out
}

/// `encode_string`: the length in bits, then the string.
fn encode_string(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = encode(s.len().checked_mul(8)?, false);
    out.extend_from_slice(s);
    Some(out)
}

/// `bytepad(x, w)`: `left_encode(w)`, `x`, then zeros to a multiple of `w`.
fn bytepad(parts: &[&[u8]], w: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(encode(w, false));
    for part in parts {
        out.extend_from_slice(part);
    }
    let rem = out.len().checked_rem(w).unwrap_or(0);
    if rem != 0 {
        let len = out.len().saturating_add(w.saturating_sub(rem));
        out.resize(len, 0);
    }
    out
}

/// KMAC: the sponge after absorbing the customization and the key, copied for each message.
struct Kmac {
    keyed: Box<dyn md::Context>,
    sponge: Box<dyn md::Context>,
    size: usize,
    xof: bool,
    done: bool,
}

/// KMAC with `key` (4 to 512 octets), the customization string `custom` (at most 512),
/// `size` octets of output (at most 2^21 - 1), and, if `xof`, as an XOF (KMACXOF: the output
/// length isn't bound into the result).
pub fn kmac(
    algorithm: KmacAlgorithm,
    key: &[u8],
    custom: &[u8],
    size: usize,
    xof: bool,
) -> Result<Box<dyn Mac>, Error> {
    if !(KMAC_MIN_KEY..=KMAC_MAX_KEY).contains(&key.len()) {
        return Err(Error::KeyLength);
    }
    if custom.len() > KMAC_MAX_CUSTOM {
        return Err(Error::CustomLength);
    }
    if size > KMAC_MAX_OUTPUT {
        return Err(Error::OutputSize);
    }
    let digest = algorithm.digest();
    let rate = digest.block_size();
    let name = encode_string(b"KMAC").ok_or(Error::CustomLength)?;
    let custom = encode_string(custom).ok_or(Error::CustomLength)?;
    let key = Zeroizing::new(encode_string(key).ok_or(Error::KeyLength)?);
    let mut keyed = md::context(digest);
    keyed
        .update(&bytepad(&[&name, &custom], rate))
        .map_err(|_| Error::Finalized)?;
    keyed
        .update(&bytepad(&[&key], rate))
        .map_err(|_| Error::Finalized)?;
    Ok(Box::new(Kmac {
        sponge: keyed.clone_box(),
        keyed,
        size,
        xof,
        done: false,
    }))
}

impl Mac for Kmac {
    fn size(&self) -> usize {
        self.size
    }

    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        check_update(self.done)?;
        self.sponge.update(data).map_err(|_| Error::Finalized)
    }

    fn finalize(&mut self, out: &mut [u8]) -> Result<(), Error> {
        check_final(self.done, self.size, out)?;
        let bits = if self.xof {
            0
        } else {
            self.size.checked_mul(8).ok_or(Error::OutputSize)?
        };
        self.sponge
            .update(&encode(bits, true))
            .map_err(|_| Error::Finalized)?;
        self.sponge.finalize(out).map_err(|_| Error::Finalized)?;
        self.done = true;
        Ok(())
    }

    fn reset(&mut self) {
        self.sponge = self.keyed.clone_box();
        self.done = false;
    }

    fn clone_box(&self) -> Box<dyn Mac> {
        Box::new(Self {
            keyed: self.keyed.clone_box(),
            sponge: self.sponge.clone_box(),
            size: self.size,
            xof: self.xof,
            done: self.done,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Poly1305

/// Poly1305: whole blocks absorbed as they fill, the rest with Poly1305's final padding.
struct Poly1305 {
    key: Zeroizing<[u8; 32]>,
    hash: Box<dyn sym::UniversalHash>,
    pending: Zeroizing<Vec<u8>>,
    done: bool,
}

/// Poly1305 with a 32-octet one-time key (r, then s).
pub fn poly1305(key: &[u8]) -> Result<Box<dyn Mac>, Error> {
    let key: [u8; 32] = key.try_into().map_err(|_| Error::KeyLength)?;
    let hash =
        sym::universal_hash(sym::HashAlgorithm::Poly1305, &key).map_err(|_| Error::KeyLength)?;
    Ok(Box::new(Poly1305 {
        key: Zeroizing::new(key),
        hash,
        pending: Zeroizing::new(Vec::with_capacity(16)),
        done: false,
    }))
}

impl Mac for Poly1305 {
    fn size(&self) -> usize {
        16
    }

    fn update(&mut self, mut data: &[u8]) -> Result<(), Error> {
        check_update(self.done)?;
        while !data.is_empty() {
            // A full pending block waits until more data shows it isn't the last.
            if self.pending.len() == 16 {
                self.hash.update_padded(&self.pending);
                self.pending.clear();
            }
            let take = 16usize.saturating_sub(self.pending.len()).min(data.len());
            let (head, rest) = data.split_at(take);
            self.pending.extend_from_slice(head);
            data = rest;
        }
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8]) -> Result<(), Error> {
        check_final(self.done, 16, out)?;
        let tag = Zeroizing::new(self.hash.finalize(&self.pending));
        out.copy_from_slice(&*tag);
        self.pending.clear();
        self.done = true;
        Ok(())
    }

    fn reset(&mut self) {
        if let Ok(hash) = sym::universal_hash(sym::HashAlgorithm::Poly1305, &*self.key) {
            self.hash = hash;
        }
        self.pending.clear();
        self.done = false;
    }

    fn clone_box(&self) -> Box<dyn Mac> {
        Box::new(Self {
            key: self.key.clone(),
            hash: self.hash.clone_box(),
            pending: self.pending.clone(),
            done: self.done,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// SipHash

/// SipHash-c-d with a 64- or 128-bit output (the reference's `siphash.c` design, our code).
#[derive(Clone)]
struct SipHash {
    key: [u64; 2],
    v: [u64; 4],
    c_rounds: u32,
    d_rounds: u32,
    size: usize,
    pending: [u8; 8],
    pending_len: usize,
    /// The message length modulo 256, as the last word carries it.
    total: u8,
    done: bool,
}

impl Drop for SipHash {
    fn drop(&mut self) {
        self.key.zeroize();
        self.v.zeroize();
        self.pending.zeroize();
    }
}

/// SipHash with a 16-octet key, `size` 8 or 16, and `c_rounds` and `d_rounds` rounds per word
/// and at the end (OpenSSL's defaults are 2 and 4).
pub fn siphash(
    key: &[u8],
    size: usize,
    c_rounds: u32,
    d_rounds: u32,
) -> Result<Box<dyn Mac>, Error> {
    let key: &[u8; 16] = key.try_into().map_err(|_| Error::KeyLength)?;
    if size != 8 && size != 16 {
        return Err(Error::OutputSize);
    }
    let (k0, k1) = key.split_at(8);
    let word = |b: &[u8]| u64::from_le_bytes(b.try_into().unwrap_or([0; 8]));
    let mut s = SipHash {
        key: [word(k0), word(k1)],
        v: [0; 4],
        c_rounds,
        d_rounds,
        size,
        pending: [0; 8],
        pending_len: 0,
        total: 0,
        done: false,
    };
    s.start();
    Ok(Box::new(s))
}

impl SipHash {
    fn start(&mut self) {
        let [k0, k1] = self.key;
        self.v = [
            k0 ^ 0x736f_6d65_7073_6575,
            k1 ^ 0x646f_7261_6e64_6f6d,
            k0 ^ 0x6c79_6765_6e65_7261,
            k1 ^ 0x7465_6462_7974_6573,
        ];
        if self.size == 16 {
            self.v[1] ^= 0xee;
        }
        self.pending = [0; 8];
        self.pending_len = 0;
        self.total = 0;
        self.done = false;
    }

    fn round(&mut self) {
        let [mut v0, mut v1, mut v2, mut v3] = self.v;
        v0 = v0.wrapping_add(v1);
        v1 = v1.rotate_left(13) ^ v0;
        v0 = v0.rotate_left(32);
        v2 = v2.wrapping_add(v3);
        v3 = v3.rotate_left(16) ^ v2;
        v0 = v0.wrapping_add(v3);
        v3 = v3.rotate_left(21) ^ v0;
        v2 = v2.wrapping_add(v1);
        v1 = v1.rotate_left(17) ^ v2;
        v2 = v2.rotate_left(32);
        self.v = [v0, v1, v2, v3];
    }

    fn compress(&mut self, m: u64) {
        self.v[3] ^= m;
        for _ in 0..self.c_rounds {
            self.round();
        }
        self.v[0] ^= m;
    }

    /// One finalization half: `d_rounds` rounds, then the XOR of the state.
    fn half(&mut self) -> u64 {
        for _ in 0..self.d_rounds {
            self.round();
        }
        let [v0, v1, v2, v3] = self.v;
        v0 ^ v1 ^ v2 ^ v3
    }
}

impl Mac for SipHash {
    fn size(&self) -> usize {
        self.size
    }

    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        check_update(self.done)?;
        for &b in data {
            if let Some(p) = self.pending.get_mut(self.pending_len) {
                *p = b;
            }
            self.pending_len = self.pending_len.saturating_add(1);
            self.total = self.total.wrapping_add(1);
            if self.pending_len == 8 {
                let m = u64::from_le_bytes(self.pending);
                self.compress(m);
                self.pending_len = 0;
            }
        }
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8]) -> Result<(), Error> {
        check_final(self.done, self.size, out)?;
        let mut last = [0u8; 8];
        last.iter_mut()
            .zip(self.pending.iter().take(self.pending_len))
            .for_each(|(l, &p)| *l = p);
        if let Some(top) = last.last_mut() {
            *top = self.total;
        }
        self.compress(u64::from_le_bytes(last));
        self.v[2] ^= if self.size == 16 { 0xee } else { 0xff };
        let first = self.half();
        let mut tag = [0u8; 16];
        let (lo, hi) = tag.split_at_mut(8);
        lo.copy_from_slice(&first.to_le_bytes());
        if self.size == 16 {
            self.v[1] ^= 0xdd;
            hi.copy_from_slice(&self.half().to_le_bytes());
        }
        out.iter_mut().zip(tag).for_each(|(o, t)| *o = t);
        tag.zeroize();
        self.done = true;
        Ok(())
    }

    fn reset(&mut self) {
        self.start();
    }

    fn clone_box(&self) -> Box<dyn Mac> {
        Box::new(self.clone())
    }
}

// ---------------------------------------------------------------------------------------------
// BLAKE2 MACs

/// The BLAKE2 MACs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Blake2Algorithm {
    /// BLAKE2BMAC: keys and output of up to 64 octets; salt and custom up to 16.
    Blake2b,
    /// BLAKE2SMAC: keys and output of up to 32 octets; salt and custom up to 8.
    Blake2s,
}

impl Blake2Algorithm {
    /// The largest key and output, and OpenSSL's default output size.
    pub const fn max_size(self) -> usize {
        match self {
            Self::Blake2b => 64,
            Self::Blake2s => 32,
        }
    }
}

/// A BLAKE2 core with its buffer, which holds the last block back as BLAKE2 finalizes it.
struct Blake2Mac<C>
where
    C: BufferKindUser<BufferKind = Lazy>,
{
    initial: (C, Buffer<C>),
    core: C,
    buffer: Buffer<C>,
    size: usize,
    done: bool,
}

/// A BLAKE2 MAC of `size` octets (1 to the maximum) with `key` (1 to the maximum), and a
/// `salt` and `custom` personalization of at most a quarter block each.
pub fn blake2(
    algorithm: Blake2Algorithm,
    key: &[u8],
    size: usize,
    custom: &[u8],
    salt: &[u8],
) -> Result<Box<dyn Mac>, Error> {
    let max = algorithm.max_size();
    if key.is_empty() || key.len() > max {
        return Err(Error::KeyLength);
    }
    if size == 0 || size > max {
        return Err(Error::OutputSize);
    }
    if custom.len() > max / 4 {
        return Err(Error::CustomLength);
    }
    if salt.len() > max / 4 {
        return Err(Error::SaltLength);
    }
    // The lengths are within what the cores assert.
    Ok(match algorithm {
        Blake2Algorithm::Blake2b => Box::new(Blake2Mac::new(
            blake2::Blake2bVarCore::new_with_params(salt, custom, key.len(), size),
            key,
            size,
        )),
        Blake2Algorithm::Blake2s => Box::new(Blake2Mac::new(
            blake2::Blake2sVarCore::new_with_params(salt, custom, key.len(), size),
            key,
            size,
        )),
    })
}

/// Unkeyed BLAKE2b with a digest of `size` octets (1 to 64) in its parameter block, as
/// Argon2's variable-length hash uses it.
pub(crate) fn blake2b_unkeyed(size: usize) -> Result<Box<dyn Mac>, Error> {
    if size == 0 || size > Blake2Algorithm::Blake2b.max_size() {
        return Err(Error::OutputSize);
    }
    Ok(Box::new(Blake2Mac::new(
        blake2::Blake2bVarCore::new_with_params(&[], &[], 0, size),
        &[],
        size,
    )))
}

impl<C> Blake2Mac<C>
where
    C: VariableOutputCore + UpdateCore + BufferKindUser<BufferKind = Lazy> + Clone,
{
    fn new(core: C, key: &[u8], size: usize) -> Self {
        // The key, zero-padded to a block, is the first block; unkeyed, there's none.
        let buffer = if key.is_empty() {
            LazyBuffer::default()
        } else {
            let mut block = blake2::digest::block_api::Block::<C>::default();
            block.iter_mut().zip(key).for_each(|(b, &k)| *b = k);
            let buffer = LazyBuffer::new(&block);
            block.zeroize();
            buffer
        };
        Self {
            initial: (core.clone(), buffer.clone()),
            core,
            buffer,
            size,
            done: false,
        }
    }
}

impl<C> Mac for Blake2Mac<C>
where
    C: VariableOutputCore
        + UpdateCore
        + BufferKindUser<BufferKind = Lazy>
        + Clone
        + Send
        + Sync
        + 'static,
{
    fn size(&self) -> usize {
        self.size
    }

    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        check_update(self.done)?;
        let Self { core, buffer, .. } = self;
        buffer.digest_blocks(data, |blocks| core.update_blocks(blocks));
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8]) -> Result<(), Error> {
        check_final(self.done, self.size, out)?;
        let mut full = Output::<C>::default();
        self.core
            .finalize_variable_core(&mut self.buffer, &mut full);
        let n = C::OutputSize::USIZE.min(self.size);
        out.copy_from_slice(full.get(..n).ok_or(Error::OutputSize)?);
        full.zeroize();
        self.done = true;
        Ok(())
    }

    fn reset(&mut self) {
        self.core = self.initial.0.clone();
        self.buffer = self.initial.1.clone();
        self.done = false;
    }

    fn clone_box(&self) -> Box<dyn Mac> {
        Box::new(Self {
            initial: self.initial.clone(),
            core: self.core.clone(),
            buffer: self.buffer.clone(),
            size: self.size,
            done: self.done,
        })
    }
}
