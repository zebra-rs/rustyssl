//! The default provider's MAC contexts that don't run over the EVP layer, with the reference
//! providers' semantics (`providers/implementations/macs/`): Poly1305, SipHash (OpenSSL's own
//! `SIPHASH` state, ported, since its provider reaches into it), and BLAKE2BMAC/BLAKE2SMAC;
//! and HMAC's TLS record MAC (`ssl3_cbc_digest_record`), computed in constant time over the
//! record's public length whatever its secret one.
//!
//! The states are OpenSSL's, quirks included: SipHash runs (with no rounds) before it has a key
//! and changes its output size in place; a BLAKE2 MAC before its init or after its final is all
//! zeros, and finishes into nothing; Poly1305 can't be initialized again without a new key once
//! it has been used. Where the reference crashes (Poly1305 used after its final) these fail.

use digest::block_api::VariableOutputCore;
use digest::common::hazmat::SerializableState;
use zeroize::{Zeroize, Zeroizing};

use crate::mac::{self as backend, Blake2Algorithm, Mac};
use crate::md;

/// Why a MAC operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// `PROV_R_INVALID_KEY_LENGTH`.
    InvalidKeyLength,
    /// `PROV_R_NO_KEY_SET`.
    NoKeySet,
    /// `PROV_R_NOT_XOF_OR_INVALID_LENGTH`.
    InvalidLength,
    /// `PROV_R_INVALID_CUSTOM_LENGTH`.
    InvalidCustomLength,
    /// `PROV_R_INVALID_SALT_LENGTH`.
    InvalidSaltLength,
    /// Used after its final (the reference crashes).
    Finished,
    /// Failed without an error of its own.
    Silent,
}

// ---------------------------------------------------------------------------------------------
// Poly1305

/// `struct poly1305_data_st`.
pub struct Poly1305 {
    updated: bool,
    key_set: bool,
    /// The computation; `None` once finished (the reference's state is then zeroed).
    mac: Option<Box<dyn Mac>>,
}

impl Clone for Poly1305 {
    fn clone(&self) -> Self {
        Self {
            updated: self.updated,
            key_set: self.key_set,
            mac: self.mac.as_ref().map(|m| m.clone_box()),
        }
    }
}

impl Default for Poly1305 {
    fn default() -> Self {
        Self::new()
    }
}

impl Poly1305 {
    /// The MAC's size.
    pub const SIZE: usize = 16;

    /// `poly1305_new`.
    pub fn new() -> Self {
        Self {
            updated: false,
            key_set: false,
            mac: None,
        }
    }

    /// `poly1305_setkey`: a 32-octet key (`None` for NULL).
    pub fn set_key(&mut self, key: Option<&[u8]>) -> Result<(), Error> {
        let key = key.ok_or(Error::InvalidKeyLength)?;
        self.mac = Some(backend::poly1305(key).map_err(|_| Error::InvalidKeyLength)?);
        self.updated = false;
        self.key_set = true;
        Ok(())
    }

    /// `poly1305_init` without a key: allowed only before the context is used.
    pub fn restart(&self) -> bool {
        !self.updated
    }

    /// `poly1305_update`.
    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        if !self.key_set {
            return Err(Error::NoKeySet);
        }
        self.updated = true;
        if data.is_empty() {
            return Ok(());
        }
        let mac = self.mac.as_mut().ok_or(Error::Finished)?;
        mac.update(data).map_err(|_| Error::Finished)
    }

    /// `poly1305_final`: the tag.
    pub fn finalize(&mut self) -> Result<[u8; 16], Error> {
        if !self.key_set {
            return Err(Error::NoKeySet);
        }
        self.updated = true;
        let mut mac = self.mac.take().ok_or(Error::Finished)?;
        let mut out = [0u8; 16];
        mac.finalize(&mut out).map_err(|_| Error::Finished)?;
        Ok(out)
    }
}

// ---------------------------------------------------------------------------------------------
// SipHash

const SIPHASH_BLOCK_SIZE: usize = 8;
const SIPHASH_MIN_DIGEST_SIZE: u32 = 8;
const SIPHASH_MAX_DIGEST_SIZE: u32 = 16;
const SIPHASH_C_ROUNDS: u32 = 2;
const SIPHASH_D_ROUNDS: u32 = 4;

/// OpenSSL's `SIPHASH` (`struct siphash_st`), all zero to start.
#[derive(Clone, Default)]
struct SipState {
    total_inlen: u64,
    v: [u64; 4],
    len: usize,
    hash_size: u32,
    crounds: u32,
    drounds: u32,
    leavings: [u8; SIPHASH_BLOCK_SIZE],
}

impl Drop for SipState {
    fn drop(&mut self) {
        self.v.zeroize();
        self.leavings.zeroize();
    }
}

fn sipround(v: &mut [u64; 4]) {
    let [mut v0, mut v1, mut v2, mut v3] = *v;
    v0 = v0.wrapping_add(v1);
    v1 = v1.rotate_left(13);
    v1 ^= v0;
    v0 = v0.rotate_left(32);
    v2 = v2.wrapping_add(v3);
    v3 = v3.rotate_left(16);
    v3 ^= v2;
    v0 = v0.wrapping_add(v3);
    v3 = v3.rotate_left(21);
    v3 ^= v0;
    v2 = v2.wrapping_add(v1);
    v1 = v1.rotate_left(17);
    v1 ^= v2;
    v2 = v2.rotate_left(32);
    *v = [v0, v1, v2, v3];
}

/// `siphash_adjust_hash_size`.
fn adjust(hash_size: u32) -> u32 {
    if hash_size == 0 {
        SIPHASH_MAX_DIGEST_SIZE
    } else {
        hash_size
    }
}

fn le64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    for (d, s) in a.iter_mut().zip(b) {
        *d = *s;
    }
    u64::from_le_bytes(a)
}

impl SipState {
    /// `SipHash_set_hash_size`.
    fn set_hash_size(&mut self, hash_size: usize) -> bool {
        let Ok(size) = u32::try_from(hash_size) else {
            return false;
        };
        let size = adjust(size);
        if size != SIPHASH_MIN_DIGEST_SIZE && size != SIPHASH_MAX_DIGEST_SIZE {
            return false;
        }
        self.hash_size = adjust(self.hash_size);
        if self.hash_size != size {
            self.v[1] ^= 0xee;
            self.hash_size = size;
        }
        true
    }

    /// `SipHash_Init` with a 16-octet key.
    fn init(&mut self, k: &[u8; 16], crounds: u32, drounds: u32) {
        let k0 = le64(&k[..8]);
        let k1 = le64(&k[8..]);
        self.hash_size = adjust(self.hash_size);
        self.crounds = if crounds == 0 {
            SIPHASH_C_ROUNDS
        } else {
            crounds
        };
        self.drounds = if drounds == 0 {
            SIPHASH_D_ROUNDS
        } else {
            drounds
        };
        self.len = 0;
        self.total_inlen = 0;
        self.v = [
            0x736f_6d65_7073_6575 ^ k0,
            0x646f_7261_6e64_6f6d ^ k1,
            0x6c79_6765_6e65_7261 ^ k0,
            0x7465_6462_7974_6573 ^ k1,
        ];
        if self.hash_size == SIPHASH_MAX_DIGEST_SIZE {
            self.v[1] ^= 0xee;
        }
    }

    fn compress(&mut self, m: u64) {
        self.v[3] ^= m;
        for _ in 0..self.crounds {
            sipround(&mut self.v);
        }
        self.v[0] ^= m;
    }

    /// `SipHash_Update`.
    fn update(&mut self, mut input: &[u8]) {
        // (`total_inlen` is a `uint64_t`; a `usize` fits it.)
        self.total_inlen = self
            .total_inlen
            .wrapping_add(u64::try_from(input.len()).unwrap_or(u64::MAX));
        if self.len > 0 {
            let available = SIPHASH_BLOCK_SIZE.saturating_sub(self.len);
            if input.len() < available {
                let end = self.len.saturating_add(input.len());
                if let Some(d) = self.leavings.get_mut(self.len..end) {
                    d.copy_from_slice(input);
                }
                self.len = end;
                return;
            }
            let (head, rest) = input.split_at(available);
            if let Some(d) = self.leavings.get_mut(self.len..) {
                d.copy_from_slice(head);
            }
            input = rest;
            let m = u64::from_le_bytes(self.leavings);
            self.compress(m);
        }
        let (blocks, left) = input.as_chunks::<SIPHASH_BLOCK_SIZE>();
        for b in blocks {
            self.compress(u64::from_le_bytes(*b));
        }
        if let Some(d) = self.leavings.get_mut(..left.len()) {
            d.copy_from_slice(left);
        }
        self.len = left.len();
    }

    /// `SipHash_Final` into `out` (of exactly the hash size), which it doesn't change.
    fn finalize(&self, out: &mut [u8]) -> bool {
        if self.crounds == 0 || out.is_empty() || u32::try_from(out.len()) != Ok(self.hash_size) {
            return false;
        }
        let mut b = self.total_inlen << 56;
        for (i, &l) in (0u32..)
            .step_by(8)
            .zip(self.leavings.iter())
            .take(self.len.min(7))
        {
            b |= u64::from(l) << i;
        }
        let mut v = self.v;
        v[3] ^= b;
        for _ in 0..self.crounds {
            sipround(&mut v);
        }
        v[0] ^= b;
        v[2] ^= if self.hash_size == SIPHASH_MAX_DIGEST_SIZE {
            0xee
        } else {
            0xff
        };
        for _ in 0..self.drounds {
            sipround(&mut v);
        }
        let first = (v[0] ^ v[1] ^ v[2] ^ v[3]).to_le_bytes();
        let (lo, hi) = out.split_at_mut(8.min(out.len()));
        lo.copy_from_slice(first.get(..lo.len()).unwrap_or_default());
        if self.hash_size == SIPHASH_MIN_DIGEST_SIZE {
            return true;
        }
        v[1] ^= 0xdd;
        for _ in 0..self.drounds {
            sipround(&mut v);
        }
        let second = (v[0] ^ v[1] ^ v[2] ^ v[3]).to_le_bytes();
        hi.copy_from_slice(second.get(..hi.len()).unwrap_or_default());
        v.zeroize();
        true
    }
}

/// `struct siphash_data_st`: the state, its copy for reinitialization, and the rounds asked
/// for (0 for the defaults).
#[derive(Clone, Default)]
pub struct SipHash {
    siphash: SipState,
    sipcopy: SipState,
    crounds: u32,
    drounds: u32,
}

impl SipHash {
    /// `siphash_new`.
    pub fn new() -> Self {
        Self::default()
    }

    /// `siphash_size`: 0 before a key or size.
    pub fn size(&self) -> usize {
        self.siphash.hash_size as usize
    }

    /// The compression rounds (`crounds()`).
    pub fn c_rounds(&self) -> u32 {
        if self.crounds != 0 {
            self.crounds
        } else {
            SIPHASH_C_ROUNDS
        }
    }

    /// The finalization rounds (`drounds()`).
    pub fn d_rounds(&self) -> u32 {
        if self.drounds != 0 {
            self.drounds
        } else {
            SIPHASH_D_ROUNDS
        }
    }

    /// The `c-rounds` parameter.
    pub fn set_c_rounds(&mut self, n: u32) {
        self.crounds = n;
    }

    /// The `d-rounds` parameter.
    pub fn set_d_rounds(&mut self, n: u32) {
        self.drounds = n;
    }

    /// The `size` parameter: on the state and its copy. False if it isn't 8 or 16 (0 is 16).
    pub fn set_size(&mut self, size: usize) -> bool {
        self.siphash.set_hash_size(size) && self.sipcopy.set_hash_size(size)
    }

    /// `siphash_setkey`: a 16-octet key. False for another length.
    pub fn set_key(&mut self, key: &[u8]) -> bool {
        let Ok(k) = <&[u8; 16]>::try_from(key) else {
            return false;
        };
        let (c, d) = (self.c_rounds(), self.d_rounds());
        self.siphash.init(k, c, d);
        self.sipcopy = self.siphash.clone();
        true
    }

    /// `siphash_init` without a key: back to the state after the last key.
    pub fn restart(&mut self) {
        self.siphash = self.sipcopy.clone();
    }

    /// `siphash_update`.
    pub fn update(&mut self, data: &[u8]) {
        if !data.is_empty() {
            self.siphash.update(data);
        }
    }

    /// `siphash_final` into `out` (exactly [`SipHash::size`] octets). False if it can't.
    pub fn finalize(&self, out: &mut [u8]) -> bool {
        self.siphash.finalize(out)
    }
}

// ---------------------------------------------------------------------------------------------
// BLAKE2 MACs

/// `struct blake2_mac_data_st`: the parameter block's settings, the key, and the context.
pub struct Blake2Mac {
    algorithm: Blake2Algorithm,
    digest_length: usize,
    key_length: usize,
    key: Zeroizing<[u8; 64]>,
    salt: Vec<u8>,
    personal: Vec<u8>,
    /// The computation and the size it was started with; `None` while the reference's context
    /// is all zeros (before an init, after a final).
    ctx: Option<(Box<dyn Mac>, usize)>,
}

impl Clone for Blake2Mac {
    fn clone(&self) -> Self {
        Self {
            algorithm: self.algorithm,
            digest_length: self.digest_length,
            key_length: self.key_length,
            key: self.key.clone(),
            salt: self.salt.clone(),
            personal: self.personal.clone(),
            ctx: self.ctx.as_ref().map(|(m, n)| (m.clone_box(), *n)),
        }
    }
}

impl Blake2Mac {
    /// `blake2_mac_new`: the default parameter block (the largest output, no key).
    pub fn new(algorithm: Blake2Algorithm) -> Self {
        Self {
            algorithm,
            digest_length: algorithm.max_size(),
            key_length: 0,
            key: Zeroizing::new([0; 64]),
            salt: Vec::new(),
            personal: Vec::new(),
            ctx: None,
        }
    }

    /// `blake2_mac_size`: the output size set.
    pub fn size(&self) -> usize {
        self.digest_length
    }

    /// The block size.
    pub fn block_size(&self) -> usize {
        self.algorithm.max_size().saturating_mul(2)
    }

    /// The `size` parameter: 1 to the largest output.
    pub fn set_size(&mut self, size: usize) -> Result<(), Error> {
        if size < 1 || size > self.algorithm.max_size() {
            return Err(Error::InvalidLength);
        }
        self.digest_length = size;
        Ok(())
    }

    /// `blake2_setkey`: 1 to the largest output's length.
    pub fn set_key(&mut self, key: &[u8]) -> Result<(), Error> {
        if key.is_empty() || key.len() > self.algorithm.max_size() {
            return Err(Error::InvalidKeyLength);
        }
        self.key.fill(0);
        if let Some(k) = self.key.get_mut(..key.len()) {
            k.copy_from_slice(key);
        }
        self.key_length = key.len();
        Ok(())
    }

    /// The `custom` parameter: at most a quarter of the largest output.
    pub fn set_custom(&mut self, custom: &[u8]) -> Result<(), Error> {
        if custom.len() > self.algorithm.max_size() / 4 {
            return Err(Error::InvalidCustomLength);
        }
        self.personal = custom.to_vec();
        Ok(())
    }

    /// The `salt` parameter: at most a quarter of the largest output.
    pub fn set_salt(&mut self, salt: &[u8]) -> Result<(), Error> {
        if salt.len() > self.algorithm.max_size() / 4 {
            return Err(Error::InvalidSaltLength);
        }
        self.salt = salt.to_vec();
        Ok(())
    }

    /// The init after the key: the computation with the settings as they are now.
    pub fn start(&mut self) -> Result<(), Error> {
        if self.key_length == 0 {
            return Err(Error::NoKeySet);
        }
        let key = self.key.get(..self.key_length).unwrap_or_default();
        let mac = backend::blake2(
            self.algorithm,
            key,
            self.digest_length,
            &self.personal,
            &self.salt,
        )
        .map_err(|_| Error::Silent)?;
        self.ctx = Some((mac, self.digest_length));
        Ok(())
    }

    /// `blake2_mac_update`: nothing to do on the zeroed context.
    pub fn update(&mut self, data: &[u8]) {
        if let Some((mac, _)) = self.ctx.as_mut() {
            // The backend refuses only after a final, which `ctx` doesn't outlive.
            let _ = mac.update(data);
        }
    }

    /// `blake2_mac_final`: the output of the size the computation started with (none from the
    /// zeroed context), which leaves the context zeroed.
    pub fn finalize(&mut self) -> Zeroizing<Vec<u8>> {
        let Some((mut mac, n)) = self.ctx.take() else {
            return Zeroizing::new(Vec::new());
        };
        let mut out = Zeroizing::new(vec![0u8; n]);
        if mac.finalize(&mut out).is_err() {
            out.clear();
        }
        out
    }
}

// ---------------------------------------------------------------------------------------------
// HMAC's TLS record MAC

/// The digests a TLS CBC record MAC can use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordDigest {
    /// MD5.
    Md5,
    /// SHA-1.
    Sha1,
    /// SHA-224.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

/// A digest's chaining state, compressed a block at a time.
enum RawState {
    Md5([u32; 4]),
    Sha1([u32; 5]),
    Sha256([u32; 8]),
    Sha512([u64; 8]),
}

/// The words of a core's serialized state (little-endian words first).
fn words32<const N: usize>(serialized: &[u8]) -> [u32; N] {
    let mut w = [0u32; N];
    for (d, c) in w.iter_mut().zip(serialized.as_chunks::<4>().0) {
        *d = u32::from_le_bytes(*c);
    }
    w
}

fn words64(serialized: &[u8]) -> [u64; 8] {
    let mut w = [0u64; 8];
    for (d, c) in w.iter_mut().zip(serialized.as_chunks::<8>().0) {
        *d = u64::from_le_bytes(*c);
    }
    w
}

impl RecordDigest {
    /// The digest's initial state (from the crate's own core, so its constants aren't retyped),
    /// output size, block size, and length-field size.
    fn start(self) -> Option<(RawState, usize, usize, usize)> {
        Some(match self {
            Self::Md5 => (
                RawState::Md5(words32(&md5::block_api::Md5Core::default().serialize())),
                16,
                64,
                8,
            ),
            Self::Sha1 => (
                RawState::Sha1(words32(&sha1::block_api::Sha1Core::default().serialize())),
                20,
                64,
                8,
            ),
            Self::Sha224 | Self::Sha256 => {
                let size = if self == Self::Sha224 { 28 } else { 32 };
                let core = sha2::block_api::Sha256VarCore::new(size).ok()?;
                (RawState::Sha256(words32(&core.serialize())), size, 64, 8)
            }
            Self::Sha384 | Self::Sha512 => {
                let size = if self == Self::Sha384 { 48 } else { 64 };
                let core = sha2::block_api::Sha512VarCore::new(size).ok()?;
                (RawState::Sha512(words64(&core.serialize())), size, 128, 16)
            }
        })
    }

    fn algorithm(self) -> md::Algorithm {
        match self {
            Self::Md5 => md::Algorithm::Md5,
            Self::Sha1 => md::Algorithm::Sha1,
            Self::Sha224 => md::Algorithm::Sha224,
            Self::Sha256 => md::Algorithm::Sha256,
            Self::Sha384 => md::Algorithm::Sha384,
            Self::Sha512 => md::Algorithm::Sha512,
        }
    }
}

impl RawState {
    /// `md_transform` of one block (of the digest's block size).
    fn transform(&mut self, block: &[u8]) {
        match self {
            Self::Md5(s) => {
                if let Ok(b) = <[u8; 64]>::try_from(block) {
                    md5::block_api::compress(s, &[b]);
                }
            }
            Self::Sha1(s) => {
                if let Ok(b) = <[u8; 64]>::try_from(block) {
                    sha1::block_api::compress(s, &[b]);
                }
            }
            Self::Sha256(s) => {
                if let Ok(b) = <[u8; 64]>::try_from(block) {
                    sha2::block_api::compress256(s, &[b]);
                }
            }
            Self::Sha512(s) => {
                if let Ok(b) = <[u8; 128]>::try_from(block) {
                    sha2::block_api::compress512(s, &[b]);
                }
            }
        }
    }

    /// `md_final_raw`: the state's words in the digest's byte order (MD5's little-endian).
    fn final_raw(&self, out: &mut [u8; 128]) {
        match self {
            Self::Md5(s) => {
                for (d, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(s) {
                    d.copy_from_slice(&w.to_le_bytes());
                }
            }
            Self::Sha1(s) => {
                for (d, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(s) {
                    d.copy_from_slice(&w.to_be_bytes());
                }
            }
            Self::Sha256(s) => {
                for (d, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(s) {
                    d.copy_from_slice(&w.to_be_bytes());
                }
            }
            Self::Sha512(s) => {
                for (d, w) in out.as_chunks_mut::<8>().0.iter_mut().zip(s) {
                    d.copy_from_slice(&w.to_be_bytes());
                }
            }
        }
    }
}

impl Drop for RawState {
    fn drop(&mut self) {
        match self {
            Self::Md5(s) => s.zeroize(),
            Self::Sha1(s) => s.zeroize(),
            Self::Sha256(s) => s.zeroize(),
            Self::Sha512(s) => s.zeroize(),
        }
    }
}

/// All ones if `a`'s top bit is set, else zero.
fn msb_mask(a: usize) -> usize {
    0usize.wrapping_sub(a >> (usize::BITS - 1))
}

/// `constant_time_eq_8_s`: 0xff if `a == b`, else 0.
fn ct_eq_8(a: usize, b: usize) -> u8 {
    let x = a ^ b;
    u8::try_from(msb_mask(!x & x.wrapping_sub(1)) & 0xff).unwrap_or(0)
}

/// `constant_time_ge_8_s`: 0xff if `a >= b`, else 0.
fn ct_ge_8(a: usize, b: usize) -> u8 {
    let lt = msb_mask(a ^ ((a ^ b) | (a.wrapping_sub(b) ^ b)));
    u8::try_from(!lt & 0xff).unwrap_or(0)
}

/// `constant_time_select_8`.
fn ct_select_8(mask: u8, a: u8, b: u8) -> u8 {
    (mask & a) | (!mask & b)
}

/// `ssl3_cbc_digest_record` for TLS: the HMAC, keyed by `secret`, of the 13-octet `header`
/// and the first `data_size` octets of `data`, a decrypted record whose public length (data,
/// MAC, and padding) is `data.len()`. The time it takes depends on `data.len()` alone, never on
/// `data_size`, which the padding decided. `None` if the lengths are beyond what it handles.
pub fn tls_cbc_record_mac(
    digest: RecordDigest,
    header: &[u8; 13],
    data: &[u8],
    data_size: usize,
    secret: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let total = data.len();
    if total >= 1024 * 1024 {
        return None;
    }
    let (mut state, md_size, md_block_size, md_length_size) = digest.start()?;
    let little_endian = digest == RecordDigest::Md5;
    let header_length = 13usize;
    // Every length here is under 2^21 (the record under 1 MiB, the blocks at most 128 octets),
    // so the wrapping arithmetic below never wraps but where C's does, as noted.
    let variance_blocks = md_size
        .wrapping_add(256)
        .div_ceil(md_block_size)
        .wrapping_add(1);
    let len = total.wrapping_add(header_length);
    // (This wraps in C for a record shorter than a MAC; the reference's callers never pass
    // one, and what follows stays in range either way.)
    let max_mac_bytes = len.wrapping_sub(md_size.wrapping_add(1));
    let num_blocks = max_mac_bytes
        .wrapping_add(md_length_size)
        .wrapping_add(md_block_size)
        .checked_div(md_block_size)?;
    let mut num_starting_blocks = 0;
    let mut k = 0usize;
    let mac_end_offset = data_size.checked_add(header_length)?;
    let c = mac_end_offset.checked_rem(md_block_size)?;
    let index_a = mac_end_offset.checked_div(md_block_size)?;
    let index_b = mac_end_offset
        .wrapping_add(md_length_size)
        .checked_div(md_block_size)?;
    if num_blocks > variance_blocks {
        num_starting_blocks = num_blocks.wrapping_sub(variance_blocks);
        k = md_block_size.wrapping_mul(num_starting_blocks);
    }
    let bits = mac_end_offset.wrapping_add(md_block_size).wrapping_mul(8);
    if secret.len() > 128 {
        return None;
    }
    let mut hmac_pad = Zeroizing::new([0u8; 128]);
    hmac_pad.get_mut(..secret.len())?.copy_from_slice(secret);
    for b in hmac_pad.iter_mut().take(md_block_size) {
        *b ^= 0x36;
    }
    state.transform(hmac_pad.get(..md_block_size)?);

    let mut length_bytes = [0u8; 16];
    let bits32 = u32::try_from(bits & 0xffff_ffff).ok()?;
    if little_endian {
        length_bytes
            .get_mut(..4)?
            .copy_from_slice(&bits32.to_le_bytes());
    } else {
        length_bytes
            .get_mut(md_length_size.wrapping_sub(4)..md_length_size)?
            .copy_from_slice(&bits32.to_be_bytes());
    }

    if k > 0 {
        let mut first = Zeroizing::new([0u8; 128]);
        first.get_mut(..13)?.copy_from_slice(header);
        first
            .get_mut(13..md_block_size)?
            .copy_from_slice(data.get(..md_block_size.wrapping_sub(13))?);
        state.transform(first.get(..md_block_size)?);
        for i in 1..k.checked_div(md_block_size)? {
            let at = md_block_size.wrapping_mul(i).wrapping_sub(13);
            state.transform(data.get(at..at.wrapping_add(md_block_size))?);
        }
    }

    let mut mac_out = Zeroizing::new([0u8; 64]);
    let mut raw = Zeroizing::new([0u8; 128]);
    let mut block = Zeroizing::new([0u8; 128]);
    let length_at = md_block_size.wrapping_sub(md_length_size);
    for i in num_starting_blocks..=num_starting_blocks.wrapping_add(variance_blocks) {
        let is_block_a = ct_eq_8(i, index_a);
        let is_block_b = ct_eq_8(i, index_b);
        for j in 0..md_block_size {
            // The header, then the record, then zeros: which one by public positions only.
            let mut b = if k < header_length {
                header.get(k).copied().unwrap_or(0)
            } else {
                data.get(k.wrapping_sub(header_length))
                    .copied()
                    .unwrap_or(0)
            };
            k = k.wrapping_add(1);
            let is_past_c = is_block_a & ct_ge_8(j, c);
            let is_past_cp1 = is_block_a & ct_ge_8(j, c.wrapping_add(1));
            b = ct_select_8(is_past_c, 0x80, b);
            b &= !is_past_cp1;
            b &= !is_block_b | is_block_a;
            if j >= length_at {
                let l = length_bytes
                    .get(j.wrapping_sub(length_at))
                    .copied()
                    .unwrap_or(0);
                b = ct_select_8(is_block_b, l, b);
            }
            if let Some(d) = block.get_mut(j) {
                *d = b;
            }
        }
        state.transform(block.get(..md_block_size)?);
        state.final_raw(&mut raw);
        for (o, r) in mac_out.iter_mut().zip(raw.iter()).take(md_size) {
            *o |= r & is_block_b;
        }
    }

    // The outer hash, in the standard manner.
    for b in hmac_pad.iter_mut().take(md_block_size) {
        *b ^= 0x6a;
    }
    let mut outer = md::context(digest.algorithm());
    outer.update(hmac_pad.get(..md_block_size)?).ok()?;
    outer.update(mac_out.get(..md_size)?).ok()?;
    let mut out = Zeroizing::new(vec![0u8; md_size]);
    outer.finalize(&mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The record MAC is HMAC over the header and the data, whatever the padding after it.
    #[test]
    fn record_macs_are_hmacs() {
        let header: [u8; 13] = core::array::from_fn(|i| u8::try_from(i * 7).unwrap());
        let secret = [0x5au8; 20];
        for digest in [
            RecordDigest::Md5,
            RecordDigest::Sha1,
            RecordDigest::Sha224,
            RecordDigest::Sha256,
            RecordDigest::Sha384,
            RecordDigest::Sha512,
        ] {
            for (data_size, total) in [(0, 300), (17, 64), (100, 400), (250, 256 + 64)] {
                let data: Vec<u8> = (0..total)
                    .map(|i: usize| u8::try_from((i * 31 + 3) % 256).unwrap())
                    .collect();
                let got = tls_cbc_record_mac(digest, &header, &data, data_size, &secret).unwrap();
                let mut want = backend::hmac(digest.algorithm(), &secret).unwrap();
                want.update(&header).unwrap();
                want.update(&data[..data_size]).unwrap();
                let mut w = vec![0u8; want.size()];
                want.finalize(&mut w).unwrap();
                assert_eq!(&got[..], &w[..], "{digest:?} {data_size} {total}");
            }
        }
    }

    /// RFC 7693's test vector: BLAKE2b-512 keyed with 0..63 of the empty message.
    #[test]
    fn blake2_lifecycle() {
        let mut m = Blake2Mac::new(Blake2Algorithm::Blake2b);
        assert_eq!(m.start(), Err(Error::NoKeySet));
        assert!(m.finalize().is_empty());
        let key: Vec<u8> = (0..64).collect();
        m.set_key(&key).unwrap();
        m.start().unwrap();
        let out = m.finalize();
        assert_eq!(out.len(), 64);
        assert_eq!(out[..4], [0x10, 0xeb, 0xb6, 0x77]);
        assert!(m.finalize().is_empty());
    }

    /// docs/DEVIATIONS.md: Poly1305 used after its final fails (the reference's state is zeroed,
    /// assembly function pointers too, and it crashes).
    #[test]
    fn poly1305_after_its_final_fails() {
        let mut p = Poly1305::new();
        p.set_key(Some(&[7; 32])).unwrap();
        p.update(b"data").unwrap();
        p.finalize().unwrap();
        assert_eq!(p.update(b"more"), Err(Error::Finished));
        assert_eq!(p.update(b""), Ok(()));
        assert_eq!(p.finalize(), Err(Error::Finished));
        assert!(!p.restart());
        p.set_key(Some(&[7; 32])).unwrap();
        assert!(p.restart());
    }

    /// The SipHash paper's vector (2-4, 64-bit output, 15 octets) and the 128-bit one's start.
    #[test]
    fn siphash_vectors() {
        let key: Vec<u8> = (0..16).collect();
        let data: Vec<u8> = (0..15).collect();
        let mut s = SipHash::new();
        assert_eq!(s.size(), 0);
        assert!(s.set_size(8));
        assert!(s.set_key(&key));
        s.update(&data);
        let mut out = [0u8; 8];
        assert!(s.finalize(&mut out));
        assert_eq!(u64::from_le_bytes(out), 0xa129_ca61_49be_45e5);
        assert!(!s.finalize(&mut [0u8; 16]));
    }
}
