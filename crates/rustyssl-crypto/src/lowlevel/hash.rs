//! The deprecated low-level hashes: `MD4_*`, `MD5_*`, `RIPEMD160_*`, `SHA1_*`, `SHA224_*`,
//! `SHA256_*` (all [`Md32`]), `SHA384_*` and `SHA512_*` ([`Sha512`]), `MDC2_*` ([`Mdc2`]), and
//! `WHIRLPOOL_*` ([`Whirlpool`]).
//!
//! The framing follows OpenSSL's (`md32_common.h`, `sha512.c`, `mdc2dgst.c`, `wp_dgst.c`), so
//! each field holds after each call what OpenSSL leaves in it: the buffered octets, the bit
//! counts, a final's leftovers. The compression functions are the RustCrypto crates' (MDC2's is
//! two DES encryptions).
//!
//! A context whose count of buffered octets or bits is past its buffer (never initialized, or
//! overwritten) is refused with [`Error::Corrupt`] where OpenSSL reads and writes out of bounds.

use cipher::{BlockCipherEncrypt, KeyInit};
use digest::array::Array;
use digest::block_api::{BlockSizeUser, UpdateCore};
use digest::common::hazmat::{SerializableState, SerializedState};
use digest::consts::U64;
use zeroize::Zeroize;

use super::{clear_from, put};

/// Why a call on a context failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The context's count of buffered octets or bits is past its buffer.
    Corrupt,
    /// The context's digest length is one the function doesn't produce.
    Length,
    /// Fewer input octets than the bit count needs.
    Input,
}

/// The block size of the [`Md32`] hashes, MDC2's excepted.
pub const MD32_BLOCK: usize = 64;

/// A hash built like MD4: 32-bit words, 64-octet blocks, a 64-bit bit count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Md32Kind {
    /// MD4 (`MD4_CTX`).
    Md4,
    /// MD5 (`MD5_CTX`).
    Md5,
    /// RIPEMD-160 (`RIPEMD160_CTX`).
    Ripemd160,
    /// SHA-1 (`SHA_CTX`).
    Sha1,
    /// SHA-224 and SHA-256 (`SHA256_CTX`).
    Sha256,
}

impl Md32Kind {
    /// Whether words and the bit count are big-endian (SHA) or little-endian (MD4, MD5,
    /// RIPEMD).
    fn big_endian(self) -> bool {
        matches!(self, Self::Sha1 | Self::Sha256)
    }

    /// Runs the compression function over `blocks`, on the first words of `h`.
    fn compress(self, h: &mut [u32; 8], blocks: &[[u8; MD32_BLOCK]]) {
        match self {
            Self::Md4 => through_core::<md4::block_api::Md4Core>(h, blocks),
            Self::Ripemd160 => through_core::<ripemd::block_api::Ripemd160Core>(h, blocks),
            Self::Md5 => {
                if let Some((state, _)) = h.split_first_chunk_mut::<4>() {
                    md5::block_api::compress(state, blocks);
                }
            }
            Self::Sha1 => {
                if let Some((state, _)) = h.split_first_chunk_mut::<5>() {
                    sha1::block_api::compress(state, blocks);
                }
            }
            Self::Sha256 => sha2::block_api::compress256(h, blocks),
        }
    }
}

/// Runs a crate's compression function that it only offers through its block-level core:
/// loads the chaining words into the core's serialized state, absorbs `blocks`, and reads the
/// words back. (The serialized state is the words, little-endian, then a block count that
/// only the crate's own finalization reads.)
fn through_core<C>(h: &mut [u32], blocks: &[[u8; 64]])
where
    C: UpdateCore + SerializableState + BlockSizeUser<BlockSize = U64>,
{
    let mut serialized = SerializedState::<C>::default();
    for (word, chunk) in h.iter().zip(serialized.as_chunks_mut::<4>().0) {
        *chunk = word.to_le_bytes();
    }
    let core = C::deserialize(&serialized);
    serialized.as_mut_slice().zeroize();
    let Ok(mut core) = core else { return };
    core.update_blocks(Array::cast_slice_from_core(blocks));
    let mut out = core.serialize();
    for (word, chunk) in h.iter_mut().zip(out.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*chunk);
    }
    out.as_mut_slice().zeroize();
}

/// `MD4_CTX`, `MD5_CTX`, `RIPEMD160_CTX`, `SHA_CTX`, or `SHA256_CTX`: the chaining words (the
/// first 4, 5, or 8 used), the bit count's low and high words, the buffered octets, and how
/// many there are. (`SHA256_CTX`'s `md_len` stays with the caller: see
/// [`sha256_output_len`].)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Md32 {
    /// The chaining words (`h`, or `A`..`E`).
    pub h: [u32; 8],
    /// The bit count's low word (`Nl`).
    pub nl: u32,
    /// The bit count's high word (`Nh`).
    pub nh: u32,
    /// The buffered octets (`data`, an array of words used as octets).
    pub data: [u8; MD32_BLOCK],
    /// How many octets are buffered (`num`).
    pub num: u32,
}

impl Md32 {
    /// A context as `MD4_Init` leaves it.
    pub fn md4() -> Self {
        Self::with([
            0x6745_2301,
            0xefcd_ab89,
            0x98ba_dcfe,
            0x1032_5476,
            0,
            0,
            0,
            0,
        ])
    }

    /// A context as `MD5_Init` leaves it.
    pub fn md5() -> Self {
        Self::md4()
    }

    /// A context as `RIPEMD160_Init` leaves it.
    pub fn ripemd160() -> Self {
        Self::sha1()
    }

    /// A context as `SHA1_Init` leaves it.
    pub fn sha1() -> Self {
        Self::with([
            0x6745_2301,
            0xefcd_ab89,
            0x98ba_dcfe,
            0x1032_5476,
            0xc3d2_e1f0,
            0,
            0,
            0,
        ])
    }

    /// A context as `SHA224_Init` leaves it (its `md_len` is 28).
    pub fn sha224() -> Self {
        Self::with([
            0xc105_9ed8,
            0x367c_d507,
            0x3070_dd17,
            0xf70e_5939,
            0xffc0_0b31,
            0x6858_1511,
            0x64f9_8fa7,
            0xbefa_4fa4,
        ])
    }

    /// A context as `SHA256_Init` leaves it (its `md_len` is 32).
    pub fn sha256() -> Self {
        Self::with([
            0x6a09_e667,
            0xbb67_ae85,
            0x3c6e_f372,
            0xa54f_f53a,
            0x510e_527f,
            0x9b05_688c,
            0x1f83_d9ab,
            0x5be0_cd19,
        ])
    }

    /// A zeroed context with chaining words `h`.
    fn with(h: [u32; 8]) -> Self {
        Self {
            h,
            nl: 0,
            nh: 0,
            data: [0; MD32_BLOCK],
            num: 0,
        }
    }

    /// The buffered octet count, if it's within the buffer.
    fn buffered(&self) -> Result<usize, Error> {
        usize::try_from(self.num)
            .ok()
            .filter(|&n| n < MD32_BLOCK)
            .ok_or(Error::Corrupt)
    }

    /// Absorbs `input` (`MD5_Update` and the others). Nothing changes for no input.
    pub fn update(&mut self, kind: Md32Kind, input: &[u8]) -> Result<(), Error> {
        if input.is_empty() {
            return Ok(());
        }
        let num = self.buffered()?;
        let len = input.len();
        // OpenSSL's count: the length as a 32-bit word, times 8, into the low word, carrying
        // into the high word, which also takes the length's bits from bit 29 up.
        let low = u32::try_from(len & 0x1fff_ffff)
            .unwrap_or(0)
            .wrapping_shl(3);
        let l = self.nl.wrapping_add(low);
        if l < self.nl {
            self.nh = self.nh.wrapping_add(1);
        }
        let high = u32::try_from(len.wrapping_shr(29) & 0xffff_ffff).unwrap_or(0);
        self.nh = self.nh.wrapping_add(high);
        self.nl = l;

        let mut input = input;
        if num != 0 {
            let room = MD32_BLOCK.saturating_sub(num);
            if len < room {
                put(&mut self.data, num, input);
                self.num = self.num.wrapping_add(u32::try_from(len).unwrap_or(0));
                return Ok(());
            }
            let (head, rest) = input.split_at(room);
            put(&mut self.data, num, head);
            let block = self.data;
            kind.compress(&mut self.h, &[block]);
            self.num = 0;
            self.data = [0; MD32_BLOCK];
            input = rest;
        }
        let (blocks, rest) = input.as_chunks::<MD32_BLOCK>();
        if !blocks.is_empty() {
            kind.compress(&mut self.h, blocks);
        }
        if !rest.is_empty() {
            put(&mut self.data, 0, rest);
            self.num = u32::try_from(rest.len()).unwrap_or(0);
        }
        Ok(())
    }

    /// Runs the compression function over one block, touching nothing else
    /// (`MD5_Transform` and the others).
    pub fn transform(&mut self, kind: Md32Kind, block: &[u8; MD32_BLOCK]) {
        kind.compress(&mut self.h, &[*block]);
    }

    /// Pads and compresses the last blocks, then empties and zeroes the buffer, leaving the
    /// digest in the chaining words (read it with [`Md32::output`]). The bit count stays.
    pub fn finish(&mut self, kind: Md32Kind) -> Result<(), Error> {
        let mut n = self.buffered()?;
        if let Some(b) = self.data.get_mut(n) {
            *b = 0x80;
        }
        n = n.saturating_add(1);
        if n > MD32_BLOCK - 8 {
            clear_from(&mut self.data, n);
            n = 0;
            let block = self.data;
            kind.compress(&mut self.h, &[block]);
        }
        clear_from(&mut self.data, n);
        let (first, second) = if kind.big_endian() {
            (self.nh.to_be_bytes(), self.nl.to_be_bytes())
        } else {
            (self.nl.to_le_bytes(), self.nh.to_le_bytes())
        };
        put(&mut self.data, MD32_BLOCK - 8, &first);
        put(&mut self.data, MD32_BLOCK - 4, &second);
        let block = self.data;
        kind.compress(&mut self.h, &[block]);
        self.num = 0;
        self.data.zeroize();
        Ok(())
    }

    /// Writes the chaining words into `out`, a word per 4 octets, in the hash's byte order.
    pub fn output(&self, kind: Md32Kind, out: &mut [u8]) {
        for (word, chunk) in self.h.iter().zip(out.as_chunks_mut::<4>().0) {
            *chunk = if kind.big_endian() {
                word.to_be_bytes()
            } else {
                word.to_le_bytes()
            };
        }
    }
}

/// How many octets `SHA256_Final` writes for a context's `md_len`: whole words up to its
/// value, or none at all (`SHA256_Final` fails) past 32.
pub fn sha256_output_len(md_len: u32) -> Option<usize> {
    if md_len > 32 {
        return None;
    }
    usize::try_from(md_len & !3).ok()
}

/// The block size of SHA-384 and SHA-512.
pub const SHA512_BLOCK: usize = 128;

/// `SHA512_CTX`, which SHA-384 shares: the chaining words, the 128-bit bit count's low and
/// high words, the buffered octets, and how many there are. (`md_len` stays with the caller:
/// see [`sha512_output_len`].)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sha512 {
    /// The chaining words (`h`).
    pub h: [u64; 8],
    /// The bit count's low word (`Nl`).
    pub nl: u64,
    /// The bit count's high word (`Nh`).
    pub nh: u64,
    /// The buffered octets (`u`).
    pub data: [u8; SHA512_BLOCK],
    /// How many octets are buffered (`num`).
    pub num: u32,
}

/// SHA-384's initial chaining words.
const SHA384_H: [u64; 8] = [
    0xcbbb_9d5d_c105_9ed8,
    0x629a_292a_367c_d507,
    0x9159_015a_3070_dd17,
    0x152f_ecd8_f70e_5939,
    0x6733_2667_ffc0_0b31,
    0x8eb4_4a87_6858_1511,
    0xdb0c_2e0d_64f9_8fa7,
    0x47b5_481d_befa_4fa4,
];

/// SHA-512's initial chaining words.
const SHA512_H: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

impl Sha512 {
    /// `SHA384_Init`: SHA-384's chaining words, nothing counted or buffered (its `md_len` is
    /// 48). The buffer keeps its octets.
    pub fn init_sha384(&mut self) {
        self.h = SHA384_H;
        self.nl = 0;
        self.nh = 0;
        self.num = 0;
    }

    /// `SHA512_Init`: as [`Sha512::init_sha384`], with SHA-512's chaining words (its `md_len`
    /// is 64).
    pub fn init_sha512(&mut self) {
        self.init_sha384();
        self.h = SHA512_H;
    }

    /// The buffered octet count, if it's within the buffer.
    fn buffered(&self) -> Result<usize, Error> {
        usize::try_from(self.num)
            .ok()
            .filter(|&n| n < SHA512_BLOCK)
            .ok_or(Error::Corrupt)
    }

    /// Runs the compression function over `blocks`.
    fn compress(&mut self, blocks: &[[u8; SHA512_BLOCK]]) {
        sha2::block_api::compress512(&mut self.h, blocks);
    }

    /// Absorbs `input` (`SHA512_Update`, `SHA384_Update`). Unlike the [`Md32`] hashes, a
    /// filled buffer isn't zeroed after it's compressed.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        if input.is_empty() {
            return Ok(());
        }
        let num = self.buffered()?;
        let len = u64::try_from(input.len()).unwrap_or(u64::MAX);
        let l = self.nl.wrapping_add(len.wrapping_shl(3));
        if l < self.nl {
            self.nh = self.nh.wrapping_add(1);
        }
        self.nh = self.nh.wrapping_add(len.wrapping_shr(61));
        self.nl = l;

        let mut input = input;
        if num != 0 {
            let room = SHA512_BLOCK.saturating_sub(num);
            if input.len() < room {
                put(&mut self.data, num, input);
                self.num = self
                    .num
                    .wrapping_add(u32::try_from(input.len()).unwrap_or(0));
                return Ok(());
            }
            let (head, rest) = input.split_at(room);
            put(&mut self.data, num, head);
            self.num = 0;
            let block = self.data;
            self.compress(&[block]);
            input = rest;
        }
        let (blocks, rest) = input.as_chunks::<SHA512_BLOCK>();
        if !blocks.is_empty() {
            self.compress(blocks);
        }
        if !rest.is_empty() {
            put(&mut self.data, 0, rest);
            self.num = u32::try_from(rest.len()).unwrap_or(0);
        }
        Ok(())
    }

    /// Runs the compression function over one block (`SHA512_Transform`).
    pub fn transform(&mut self, block: &[u8; SHA512_BLOCK]) {
        self.compress(&[*block]);
    }

    /// Pads and compresses the last blocks, leaving the digest in the chaining words (read it
    /// with [`Sha512::output`]). As in OpenSSL, the buffer keeps the padding and `num` keeps its
    /// value.
    pub fn finish(&mut self) -> Result<(), Error> {
        let mut n = self.buffered()?;
        if let Some(b) = self.data.get_mut(n) {
            *b = 0x80;
        }
        n = n.saturating_add(1);
        if n > SHA512_BLOCK - 16 {
            clear_from(&mut self.data, n);
            n = 0;
            let block = self.data;
            self.compress(&[block]);
        }
        clear_from(&mut self.data, n);
        put(&mut self.data, SHA512_BLOCK - 16, &self.nh.to_be_bytes());
        put(&mut self.data, SHA512_BLOCK - 8, &self.nl.to_be_bytes());
        let block = self.data;
        self.compress(&[block]);
        Ok(())
    }

    /// Writes the chaining words big-endian into `out`, as far as it reaches.
    pub fn output(&self, out: &mut [u8]) {
        let mut all = [0u8; 64];
        for (word, chunk) in self.h.iter().zip(all.as_chunks_mut::<8>().0) {
            *chunk = word.to_be_bytes();
        }
        put(out, 0, &all);
        all.zeroize();
    }
}

/// How many octets `SHA512_Final` writes for a context's `md_len`: SHA-512/224's,
/// SHA-512/256's, SHA-384's, or SHA-512's, or none at all (`SHA512_Final` fails) for any other.
pub fn sha512_output_len(md_len: u32) -> Option<usize> {
    match md_len {
        28 | 32 | 48 | 64 => usize::try_from(md_len).ok(),
        _ => None,
    }
}

/// MDC2's block size, and the size of each of its halves.
pub const MDC2_BLOCK: usize = 8;

/// `MDC2_CTX`: the buffered octets and their count, the two DES-keyed halves, and the padding
/// (2 for a `0x80` octet before the zeros; anything else for zeros only, and none for a whole
/// last block).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mdc2 {
    /// How many octets are buffered (`num`).
    pub num: u32,
    /// The buffered octets (`data`).
    pub data: [u8; MDC2_BLOCK],
    /// The first half (`h`).
    pub h: [u8; MDC2_BLOCK],
    /// The second half (`hh`).
    pub hh: [u8; MDC2_BLOCK],
    /// The padding (`pad_type`).
    pub pad_type: u32,
}

impl Mdc2 {
    /// `MDC2_Init`: no octets buffered, padding 1, and the halves' initial values. The buffer
    /// keeps its octets.
    pub fn init(&mut self) {
        self.num = 0;
        self.pad_type = 1;
        self.h = [0x52; MDC2_BLOCK];
        self.hh = [0x25; MDC2_BLOCK];
    }

    /// The buffered octet count, if it's within the buffer.
    fn buffered(&self) -> Result<usize, Error> {
        usize::try_from(self.num)
            .ok()
            .filter(|&n| n < MDC2_BLOCK)
            .ok_or(Error::Corrupt)
    }

    /// Absorbs one block: each half, with two bits of its first octet fixed, keys a DES
    /// encryption of the block, and the halves swap their encryptions' right halves.
    fn body(&mut self, block: &[u8; MDC2_BLOCK]) {
        let mut key_h = self.h;
        let mut key_hh = self.hh;
        if let Some(b) = key_h.first_mut() {
            *b = (*b & 0x9f) | 0x40;
        }
        if let Some(b) = key_hh.first_mut() {
            *b = (*b & 0x9f) | 0x20;
        }
        let mut e = Array::from(*block);
        let mut ee = Array::from(*block);
        if let (Ok(des_h), Ok(des_hh)) = (
            des::Des::new_from_slice(&key_h),
            des::Des::new_from_slice(&key_hh),
        ) {
            des_h.encrypt_block(&mut e);
            des_hh.encrypt_block(&mut ee);
        }
        key_h.zeroize();
        key_hh.zeroize();
        for (i, ((h, hh), x)) in self.h.iter_mut().zip(&mut self.hh).zip(block).enumerate() {
            let (left, right) = (e.get(i).copied(), ee.get(i).copied());
            let (mine, theirs) = if i < MDC2_BLOCK / 2 {
                (left, right)
            } else {
                (right, left)
            };
            *h = x ^ mine.unwrap_or(0);
            *hh = x ^ theirs.unwrap_or(0);
        }
        e.as_mut_slice().zeroize();
        ee.as_mut_slice().zeroize();
    }

    /// Absorbs `input` (`MDC2_Update`). Nothing changes for no input.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        if input.is_empty() {
            return Ok(());
        }
        let num = self.buffered()?;
        let mut input = input;
        if num != 0 {
            let room = MDC2_BLOCK.saturating_sub(num);
            if input.len() < room {
                put(&mut self.data, num, input);
                self.num = self
                    .num
                    .wrapping_add(u32::try_from(input.len()).unwrap_or(0));
                return Ok(());
            }
            let (head, rest) = input.split_at(room);
            put(&mut self.data, num, head);
            self.num = 0;
            let block = self.data;
            self.body(&block);
            input = rest;
        }
        let (blocks, rest) = input.as_chunks::<MDC2_BLOCK>();
        for block in blocks {
            self.body(block);
        }
        if !rest.is_empty() {
            put(&mut self.data, 0, rest);
            self.num = u32::try_from(rest.len()).unwrap_or(0);
        }
        Ok(())
    }

    /// `MDC2_Final`: pads and absorbs a last partial block (or, with padding 2, always a last
    /// block), then returns the halves. `num` keeps its value.
    pub fn finish(&mut self) -> Result<[u8; 2 * MDC2_BLOCK], Error> {
        let mut i = self.buffered()?;
        if i > 0 || self.pad_type == 2 {
            if self.pad_type == 2 {
                if let Some(b) = self.data.get_mut(i) {
                    *b = 0x80;
                }
                i = i.saturating_add(1);
            }
            clear_from(&mut self.data, i);
            let block = self.data;
            self.body(&block);
        }
        let mut md = [0u8; 2 * MDC2_BLOCK];
        put(&mut md, 0, &self.h);
        put(&mut md, MDC2_BLOCK, &self.hh);
        Ok(md)
    }
}

/// Whirlpool's block size in octets.
pub const WHIRLPOOL_BLOCK: usize = 64;

/// Whirlpool's block size in bits.
const WHIRLPOOL_BITS: usize = WHIRLPOOL_BLOCK * 8;

/// `WHIRLPOOL_CTX`: the chaining state (as octets, the digest's order), the buffered bits, how
/// many there are, and the 256-bit bit count as 64-bit words, least significant first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Whirlpool {
    /// The chaining state (`H`).
    pub h: [u8; WHIRLPOOL_BLOCK],
    /// The buffered bits, most significant first (`data`).
    pub data: [u8; WHIRLPOOL_BLOCK],
    /// How many bits are buffered (`bitoff`).
    pub bitoff: u32,
    /// The bit count (`bitlen`).
    pub bitlen: [u64; 4],
}

impl Default for Whirlpool {
    fn default() -> Self {
        Self::new()
    }
}

impl Whirlpool {
    /// A context as `WHIRLPOOL_Init` leaves it: all zeros.
    pub fn new() -> Self {
        Self {
            h: [0; WHIRLPOOL_BLOCK],
            data: [0; WHIRLPOOL_BLOCK],
            bitoff: 0,
            bitlen: [0; 4],
        }
    }

    /// The buffered bit count, if it's within the buffer.
    fn buffered(&self) -> Result<usize, Error> {
        usize::try_from(self.bitoff)
            .ok()
            .filter(|&n| n < WHIRLPOOL_BITS)
            .ok_or(Error::Corrupt)
    }

    /// Runs the compression function over `blocks`.
    fn compress(&mut self, blocks: &[[u8; WHIRLPOOL_BLOCK]]) {
        let mut serialized = SerializedState::<whirlpool::block_api::WhirlpoolCore>::default();
        put(&mut serialized, 0, &self.h);
        let core = whirlpool::block_api::WhirlpoolCore::deserialize(&serialized);
        serialized.as_mut_slice().zeroize();
        let Ok(mut core) = core else { return };
        core.update_blocks(Array::cast_slice_from_core(blocks));
        let mut out = core.serialize();
        for (h, o) in self.h.iter_mut().zip(out.iter()) {
            *h = *o;
        }
        out.as_mut_slice().zeroize();
    }

    /// Compresses the buffer.
    fn compress_buffer(&mut self) {
        let block = self.data;
        self.compress(&[block]);
    }

    /// Absorbs the last `bits` bits of the first `bits.div_ceil(8)` octets of `input`
    /// (`WHIRLPOOL_BitUpdate`): when `bits` isn't a multiple of 8, the first octet gives only
    /// its low-order bits. `WHIRLPOOL_Update` is this with whole octets.
    ///
    /// The steps are OpenSSL's, so the buffer's octets past the bits it holds are what
    /// OpenSSL leaves there, with one exception: where OpenSSL's last step for an input that
    /// ends inside an octet runs past the block's end (it then writes past the buffer and keeps
    /// more bits than a block holds), the block is compressed, as in OpenSSL's other steps.
    pub fn bit_update(&mut self, input: &[u8], bits: usize) -> Result<(), Error> {
        if input.len() < bits.div_ceil(8) {
            return Err(Error::Input);
        }
        if bits == 0 {
            return Ok(());
        }
        let mut bitoff = self.buffered()?;
        let added = u64::try_from(bits).unwrap_or(u64::MAX);
        let (first, carry) = self.bitlen[0].overflowing_add(added);
        self.bitlen[0] = first;
        if carry {
            for word in self.bitlen.iter_mut().skip(1) {
                *word = word.wrapping_add(1);
                if *word != 0 {
                    break;
                }
            }
        }

        let mut bits = bits;
        let mut bitrem = bitoff % 8;
        let mut inpgap = 8usize.wrapping_sub(bits % 8) & 7;
        let mut inp = input;
        // The octet at `i` of the input left, or 0 past its end.
        let at = |inp: &[u8], i: usize| inp.get(i).copied().unwrap_or(0);
        'reconsider: loop {
            if inpgap == 0 && bitrem == 0 {
                // Whole octets onto a whole-octet buffer.
                while bits > 0 {
                    let blocks = bits / WHIRLPOOL_BITS;
                    if bitoff == 0 && blocks > 0 {
                        let n = blocks.saturating_mul(WHIRLPOOL_BLOCK).min(inp.len());
                        let (whole, rest) = inp.split_at(n);
                        self.compress(whole.as_chunks::<WHIRLPOOL_BLOCK>().0);
                        inp = rest;
                        bits %= WHIRLPOOL_BITS;
                    } else {
                        let byteoff = bitoff / 8;
                        let room = WHIRLPOOL_BITS.saturating_sub(bitoff);
                        if bits >= room {
                            bits = bits.saturating_sub(room);
                            let (head, rest) = inp.split_at(room / 8);
                            put(&mut self.data, byteoff, head);
                            inp = rest;
                            self.compress_buffer();
                            bitoff = 0;
                        } else {
                            put(&mut self.data, byteoff, inp.get(..bits / 8).unwrap_or(inp));
                            bitoff = bitoff.saturating_add(bits);
                            bits = 0;
                        }
                        self.bitoff = u32::try_from(bitoff).unwrap_or(0);
                    }
                }
                break 'reconsider;
            }
            // Bit by bit: the next 8 input bits (or the last few) as `b`, its high bits onto
            // the buffer's partial octet and the rest into the next octet.
            while bits > 0 {
                let mut byteoff = bitoff / 8;
                if bitrem == inpgap {
                    if let Some(d) = self.data.get_mut(byteoff) {
                        *d |= at(inp, 0) & (0xff >> inpgap);
                    }
                    inpgap = 8usize.wrapping_sub(inpgap);
                    bitoff = bitoff.saturating_add(inpgap);
                    bitrem = 0;
                    bits = bits.saturating_sub(inpgap);
                    inpgap = 0;
                    inp = inp.get(1..).unwrap_or(&[]);
                    if bitoff == WHIRLPOOL_BITS {
                        self.compress_buffer();
                        bitoff = 0;
                    }
                    self.bitoff = u32::try_from(bitoff).unwrap_or(0);
                    continue 'reconsider;
                }
                let (b, taken) = if bits > 8 {
                    let next = u32::from(at(inp, 1))
                        .checked_shr(8u32.wrapping_sub(u32::try_from(inpgap).unwrap_or(0)));
                    let b = (u32::from(at(inp, 0)) << inpgap) | next.unwrap_or(0);
                    (u8::try_from(b & 0xff).unwrap_or(0), 8)
                } else {
                    let b = u32::from(at(inp, 0)) << inpgap;
                    (u8::try_from(b & 0xff).unwrap_or(0), bits)
                };
                if let Some(d) = self.data.get_mut(byteoff) {
                    if bitrem != 0 {
                        *d |= b >> bitrem;
                    } else {
                        *d = b;
                    }
                }
                byteoff = byteoff.saturating_add(1);
                bitoff = bitoff.saturating_add(taken);
                bits = bits.saturating_sub(taken);
                if taken == 8 {
                    inp = inp.get(1..).unwrap_or(&[]);
                }
                if bitoff >= WHIRLPOOL_BITS {
                    self.compress_buffer();
                    byteoff = 0;
                    bitoff %= WHIRLPOOL_BITS;
                }
                if bitrem != 0
                    && let Some(d) = self.data.get_mut(byteoff)
                {
                    *d = b << 8usize.wrapping_sub(bitrem);
                }
                self.bitoff = u32::try_from(bitoff).unwrap_or(0);
            }
            break 'reconsider;
        }
        self.bitoff = u32::try_from(bitoff).unwrap_or(0);
        Ok(())
    }

    /// Pads, appends the bit count, and compresses the last blocks, leaving the digest in the
    /// chaining state (`WHIRLPOOL_Final`, which then zeroes the whole context, but only when
    /// given somewhere to write the digest).
    pub fn finish(&mut self) -> Result<(), Error> {
        let bitoff = self.buffered()?;
        let mut byteoff = bitoff / 8;
        let rem = bitoff % 8;
        if let Some(d) = self.data.get_mut(byteoff) {
            if rem != 0 {
                *d |= 0x80 >> rem;
            } else {
                *d = 0x80;
            }
        }
        byteoff = byteoff.saturating_add(1);
        const COUNTER: usize = 32;
        if byteoff > WHIRLPOOL_BLOCK - COUNTER {
            clear_from(&mut self.data, byteoff);
            self.compress_buffer();
            byteoff = 0;
        }
        for d in self
            .data
            .iter_mut()
            .take(WHIRLPOOL_BLOCK - COUNTER)
            .skip(byteoff)
        {
            *d = 0;
        }
        for (i, word) in self.bitlen.iter().enumerate() {
            let at = WHIRLPOOL_BLOCK.saturating_sub(i.saturating_add(1).saturating_mul(8));
            put(&mut self.data, at, &word.to_be_bytes());
        }
        self.compress_buffer();
        Ok(())
    }
}

impl Drop for Md32 {
    fn drop(&mut self) {
        self.h.zeroize();
        self.data.zeroize();
    }
}

impl Drop for Sha512 {
    fn drop(&mut self) {
        self.h.zeroize();
        self.data.zeroize();
    }
}

impl Drop for Mdc2 {
    fn drop(&mut self) {
        self.data.zeroize();
        self.h.zeroize();
        self.hh.zeroize();
    }
}

impl Drop for Whirlpool {
    fn drop(&mut self) {
        self.h.zeroize();
        self.data.zeroize();
    }
}

#[cfg(test)]
mod tests;
