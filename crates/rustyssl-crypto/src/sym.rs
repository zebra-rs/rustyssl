//! Symmetric primitives behind the cipher modes: block ciphers, key streams, and the universal
//! hashes AEADs are built from (GHASH, POLYVAL, Poly1305), from the vetted RustCrypto crates
//! (docs/DEPENDENCIES.md), behind traits so each can be replaced.
//!
//! The modes themselves (CBC, CFB, OFB, CTR, GCM, CCM, ChaCha20-Poly1305, ...) are ours, in
//! the cipher step (3.4): OpenSSL's API feeds them data and AAD in pieces and exposes their
//! partial-block state, which the crates' one-shot AEADs don't.
//!
//! Key lengths are OpenSSL's where they vary: Blowfish takes 1 to 72 octets, CAST5 1 to 16
//! (shorter keys are zero-padded, and up to 10 octets mean 12 rounds), RC2 1 to 128 with an
//! effective key length of 1 to 1024 bits, RC4 1 to 256. ChaCha20 takes OpenSSL's 16-octet IV:
//! a 64-bit little-endian block counter and a 64-bit nonce, the counter carrying across its
//! first word as OpenSSL's does. AES uses AES-NI or the ARMv8 AES instructions when the CPU has
//! them (detected at run time), and a constant-time bitsliced implementation otherwise.

use cipher::{
    BlockCipherDecrypt, BlockCipherEncrypt, KeyInit, KeyIvInit, StreamCipher, StreamCipherSeek,
};
use hybrid_array::Array;
use universal_hash::UniversalHash as _;
use zeroize::{Zeroize, Zeroizing};

/// The block ciphers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockAlgorithm {
    /// AES (128-, 192-, or 256-bit keys).
    Aes,
    /// ARIA (128, 192, or 256 bits).
    Aria,
    /// Camellia (128, 192, or 256 bits).
    Camellia,
    /// SM4.
    Sm4,
    /// DES.
    Des,
    /// Triple DES, EDE: two keys (16 octets) or three (24).
    TripleDes,
    /// Blowfish (1 to 72 octets).
    Blowfish,
    /// CAST5 (1 to 16 octets).
    Cast5,
    /// IDEA.
    Idea,
    /// RC2 (1 to 128 octets, with an effective key length).
    Rc2,
    /// SEED (16 octets).
    Seed,
    /// DESX (24 octets: the DES key, then the input and output whitening keys).
    DesX,
}

impl BlockAlgorithm {
    /// The block size in octets.
    pub const fn block_size(self) -> usize {
        match self {
            Self::Aes | Self::Aria | Self::Camellia | Self::Sm4 | Self::Seed => 16,
            Self::Des
            | Self::TripleDes
            | Self::Blowfish
            | Self::Cast5
            | Self::Idea
            | Self::Rc2
            | Self::DesX => 8,
        }
    }
}

/// Why a primitive was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A key of a length the algorithm doesn't take.
    KeyLength,
    /// An IV of the wrong length.
    IvLength,
    /// An RC2 effective key length outside 1 to 1024 bits.
    EffectiveBits,
    /// Data that isn't a whole number of blocks.
    BlockLength,
}

/// A keyed block cipher.
pub trait BlockCipher: Send + Sync {
    /// The block size in octets.
    fn block_size(&self) -> usize;
    /// Encrypts whole blocks in place.
    fn encrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error>;
    /// Decrypts whole blocks in place.
    fn decrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error>;
    /// CBC encryption of whole blocks in place, chained from `iv` (left as the last block).
    fn cbc_encrypt(&self, iv: &mut [u8], data: &mut [u8]) -> Result<(), Error> {
        let bs = iv.len();
        if bs == 0 || !data.len().is_multiple_of(bs) {
            return Err(Error::BlockLength);
        }
        for block in data.chunks_exact_mut(bs) {
            for (b, v) in block.iter_mut().zip(iv.iter()) {
                *b ^= v;
            }
            self.encrypt_blocks(block)?;
            iv.copy_from_slice(block);
        }
        Ok(())
    }
    /// A copy, for a copied context.
    fn clone_box(&self) -> Box<dyn BlockCipher>;
}

/// A RustCrypto block cipher.
#[derive(Clone)]
struct Block<C>(C);

impl<C> BlockCipher for Block<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone + Send + Sync + 'static,
{
    fn block_size(&self) -> usize {
        C::block_size()
    }

    fn encrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        let (blocks, rest) = Array::slice_as_chunks_mut(data);
        if !rest.is_empty() {
            return Err(Error::BlockLength);
        }
        self.0.encrypt_blocks(blocks);
        Ok(())
    }

    fn decrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        let (blocks, rest) = Array::slice_as_chunks_mut(data);
        if !rest.is_empty() {
            return Err(Error::BlockLength);
        }
        self.0.decrypt_blocks(blocks);
        Ok(())
    }

    fn cbc_encrypt(&self, iv: &mut [u8], data: &mut [u8]) -> Result<(), Error> {
        // The chain without a call through the trait object per block.
        let mut chain = Array::<u8, C::BlockSize>::default();
        if iv.len() != chain.len() {
            return Err(Error::BlockLength);
        }
        chain.copy_from_slice(iv);
        let (blocks, rest) = Array::<u8, C::BlockSize>::slice_as_chunks_mut(data);
        if !rest.is_empty() {
            return Err(Error::BlockLength);
        }
        for block in blocks {
            for (b, v) in block.iter_mut().zip(chain.iter()) {
                *b ^= v;
            }
            self.0.encrypt_block(block);
            chain.copy_from_slice(block);
        }
        iv.copy_from_slice(&chain);
        Ok(())
    }

    fn clone_box(&self) -> Box<dyn BlockCipher> {
        Box::new(self.clone())
    }
}

/// A RustCrypto block cipher keyed with `key`.
fn keyed<C>(key: &[u8]) -> Result<Box<dyn BlockCipher>, Error>
where
    C: KeyInit + BlockCipherEncrypt + BlockCipherDecrypt + Clone + Send + Sync + 'static,
{
    C::new_from_slice(key)
        .map(|c| Box::new(Block(c)) as Box<dyn BlockCipher>)
        .map_err(|_| Error::KeyLength)
}

/// A block cipher keyed with `key`. `rc2_effective_bits` is RC2's effective key length (the
/// key's length in bits if `None`); other algorithms ignore it.
pub fn block_cipher(
    algorithm: BlockAlgorithm,
    key: &[u8],
    rc2_effective_bits: Option<usize>,
) -> Result<Box<dyn BlockCipher>, Error> {
    crate::dit::with(|| -> Result<Box<dyn BlockCipher>, Error> {
        match (algorithm, key.len()) {
            (BlockAlgorithm::Aes, 16) => keyed::<aes::Aes128>(key),
            (BlockAlgorithm::Aes, 24) => keyed::<aes::Aes192>(key),
            (BlockAlgorithm::Aes, 32) => keyed::<aes::Aes256>(key),
            (BlockAlgorithm::Aria, 16) => keyed::<aria::Aria128>(key),
            (BlockAlgorithm::Aria, 24) => keyed::<aria::Aria192>(key),
            (BlockAlgorithm::Aria, 32) => keyed::<aria::Aria256>(key),
            (BlockAlgorithm::Camellia, 16) => keyed::<camellia::Camellia128>(key),
            (BlockAlgorithm::Camellia, 24) => keyed::<camellia::Camellia192>(key),
            (BlockAlgorithm::Camellia, 32) => keyed::<camellia::Camellia256>(key),
            (BlockAlgorithm::Sm4, 16) => keyed::<sm4::Sm4>(key),
            (BlockAlgorithm::Des, 8) => keyed::<des::Des>(key),
            (BlockAlgorithm::TripleDes, 16) => keyed::<des::TdesEde2>(key),
            (BlockAlgorithm::TripleDes, 24) => keyed::<des::TdesEde3>(key),
            (BlockAlgorithm::Idea, 16) => keyed::<idea::Idea>(key),
            (BlockAlgorithm::Blowfish, 1..=72) => {
                // The crate takes 4 to 56 octets through `KeyInit`; its key schedule itself takes
                // any length, as OpenSSL's does.
                let mut bf = blowfish::Blowfish::bc_init_state();
                bf.bc_expand_key(key);
                Ok(Box::new(Block(bf)))
            }
            (BlockAlgorithm::Cast5, 1..=16) => {
                // The crate takes 5 to 16 octets. A shorter key padded with zeros to 5 is the same
                // key (the schedule pads to 16) with the same 12 rounds (for up to 10 octets).
                let mut padded = [0u8; 5];
                let key = if key.len() < 5 {
                    padded
                        .get_mut(..key.len())
                        .ok_or(Error::KeyLength)?
                        .copy_from_slice(key);
                    &padded[..]
                } else {
                    key
                };
                keyed::<cast5::Cast5>(key)
            }
            (BlockAlgorithm::Seed, 16) => {
                let k: &[u8; 16] = key.try_into().map_err(|_| Error::KeyLength)?;
                Ok(Box::new(Seed(crate::lowlevel::seed::set_key(k))))
            }
            (BlockAlgorithm::DesX, 24) => {
                let (des_key, whitening) = key.split_at(8);
                let (inw, outw) = whitening.split_at(8);
                Ok(Box::new(DesX {
                    des: des::Des::new_from_slice(des_key).map_err(|_| Error::KeyLength)?,
                    inw: Zeroizing::new(inw.try_into().map_err(|_| Error::KeyLength)?),
                    outw: Zeroizing::new(outw.try_into().map_err(|_| Error::KeyLength)?),
                }))
            }
            (BlockAlgorithm::Rc2, 1..=128) => {
                let bits = match rc2_effective_bits {
                    Some(b) if (1..=1024).contains(&b) => b,
                    Some(_) => return Err(Error::EffectiveBits),
                    None => key.len().saturating_mul(8),
                };
                Ok(Box::new(Block(rc2::Rc2::new_with_eff_key_len(key, bits))))
            }
            _ => Err(Error::KeyLength),
        }
    })
}

/// SEED, over the low-level key schedule.
#[derive(Clone)]
struct Seed(crate::lowlevel::seed::SeedKey);

impl Seed {
    fn each(&self, data: &mut [u8], enc: bool) -> Result<(), Error> {
        let (blocks, rest) = data.as_chunks_mut::<16>();
        if !rest.is_empty() {
            return Err(Error::BlockLength);
        }
        for b in blocks {
            *b = if enc {
                self.0.encrypt(b)
            } else {
                self.0.decrypt(b)
            };
        }
        Ok(())
    }
}

impl BlockCipher for Seed {
    fn block_size(&self) -> usize {
        16
    }

    fn encrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        self.each(data, true)
    }

    fn decrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        self.each(data, false)
    }

    fn clone_box(&self) -> Box<dyn BlockCipher> {
        Box::new(self.clone())
    }
}

/// DESX (`DES_xcbc_encrypt`'s block function): DES of the block XORed with the input
/// whitening key, XORed with the output whitening key.
#[derive(Clone)]
struct DesX {
    des: des::Des,
    inw: Zeroizing<[u8; 8]>,
    outw: Zeroizing<[u8; 8]>,
}

impl BlockCipher for DesX {
    fn block_size(&self) -> usize {
        8
    }

    fn encrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        let (blocks, rest) = Array::slice_as_chunks_mut(data);
        if !rest.is_empty() {
            return Err(Error::BlockLength);
        }
        for b in blocks {
            for (x, w) in b.iter_mut().zip(self.inw.iter()) {
                *x ^= w;
            }
            self.des.encrypt_block(b);
            for (x, w) in b.iter_mut().zip(self.outw.iter()) {
                *x ^= w;
            }
        }
        Ok(())
    }

    fn decrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        let (blocks, rest) = Array::slice_as_chunks_mut(data);
        if !rest.is_empty() {
            return Err(Error::BlockLength);
        }
        for b in blocks {
            for (x, w) in b.iter_mut().zip(self.outw.iter()) {
                *x ^= w;
            }
            self.des.decrypt_block(b);
            for (x, w) in b.iter_mut().zip(self.inw.iter()) {
                *x ^= w;
            }
        }
        Ok(())
    }

    fn clone_box(&self) -> Box<dyn BlockCipher> {
        Box::new(self.clone())
    }
}

/// A key stream XORed into data.
pub trait KeyStream: Send + Sync {
    /// XORs the next `data.len()` octets of the stream into `data`.
    fn apply(&mut self, data: &mut [u8]);
    /// A copy at the same position, for a copied context.
    fn clone_box(&self) -> Result<Box<dyn KeyStream>, Error>;
}

/// ChaCha20 (RFC 7539's block function with DJB's 64-bit counter and nonce): the crate's
/// cipher, which can't be copied, rebuilt from the key at the same position for a copy.
struct ChaCha {
    key: Zeroizing<[u8; 32]>,
    nonce: [u8; 8],
    cipher: chacha20::ChaCha20Legacy,
}

impl ChaCha {
    fn new(key: &[u8; 32], nonce: [u8; 8], position: u128) -> Result<Self, Error> {
        let mut cipher =
            chacha20::ChaCha20Legacy::new_from_slices(key, &nonce).map_err(|_| Error::IvLength)?;
        cipher.try_seek(position).map_err(|_| Error::IvLength)?;
        Ok(Self {
            key: Zeroizing::new(*key),
            nonce,
            cipher,
        })
    }
}

impl KeyStream for ChaCha {
    fn apply(&mut self, data: &mut [u8]) {
        crate::dit::with(|| {
            // Past the end of the 64-bit counter's stream (2^70 octets) the crate refuses; the
            // data is left as it is, which no caller can reach.
            let _ = self.cipher.try_apply_keystream(data);
        })
    }

    fn clone_box(&self) -> Result<Box<dyn KeyStream>, Error> {
        let position: u128 = self.cipher.current_pos();
        Ok(Box::new(Self::new(&self.key, self.nonce, position)?))
    }
}

/// ChaCha20 keyed with a 32-octet `key` and OpenSSL's 16-octet `iv`: the starting block counter
/// (64 bits, little-endian) then the 64-bit nonce.
pub fn chacha20(key: &[u8], iv: &[u8]) -> Result<Box<dyn KeyStream>, Error> {
    crate::dit::with(|| -> Result<Box<dyn KeyStream>, Error> {
        let key: &[u8; 32] = key.try_into().map_err(|_| Error::KeyLength)?;
        let iv: &[u8; 16] = iv.try_into().map_err(|_| Error::IvLength)?;
        let (counter, nonce) = iv.split_at(8);
        let counter = u64::from_le_bytes(counter.try_into().map_err(|_| Error::IvLength)?);
        let nonce: [u8; 8] = nonce.try_into().map_err(|_| Error::IvLength)?;
        let position = u128::from(counter).checked_mul(64).ok_or(Error::IvLength)?;
        Ok(Box::new(ChaCha::new(key, nonce, position)?))
    })
}

/// XORs ChaCha20's key stream into whole 64-octet blocks of `data`, starting at block
/// `counter` of the stream for `key` and the 64-bit `nonce`. The block counter wraps at 2^64
/// as OpenSSL's does (its second word carries from the first, and nothing carries from the
/// second), where the crate's stream refuses to go on. Returns the next block's counter.
pub fn chacha20_blocks(
    key: &[u8; 32],
    nonce: [u8; 8],
    counter: u64,
    data: &mut [u8],
) -> Result<u64, Error> {
    crate::dit::with(|| {
        use cipher::StreamCipherCore;

        let (mut blocks, rest) = Array::slice_as_chunks_mut(data);
        if !rest.is_empty() {
            return Err(Error::BlockLength);
        }
        let mut core = chacha20::ChaCha20LegacyCore::new(key.into(), (&nonce).into());
        let mut counter = counter;
        while !blocks.is_empty() {
            // Up to the wrap, so no backend has to carry past the counter's end.
            let to_wrap = u64::MAX.wrapping_sub(counter).saturating_add(1);
            let n = usize::try_from(to_wrap).map_or(blocks.len(), |w| w.min(blocks.len()));
            let (now, later) = blocks.split_at_mut(n);
            core.set_block_pos(counter);
            core.apply_keystream_blocks(now);
            counter = counter.wrapping_add(u64::try_from(n).map_err(|_| Error::BlockLength)?);
            blocks = later;
        }
        Ok(counter)
    })
}

/// RC4: the crate's can't be copied, and RC4 is a few lines, so it's ours. **Not constant
/// time:** its state lookups depend on the key and the stream, as every RC4's do.
#[derive(Clone)]
struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// A keyed state (the key-scheduling algorithm).
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (n, v) in s.iter_mut().enumerate() {
            *v = u8::try_from(n).unwrap_or(0);
        }
        let mut j = 0u8;
        for (n, &k) in (0..256).zip(key.iter().cycle()) {
            j = j
                .wrapping_add(s.get(n).copied().unwrap_or(0))
                .wrapping_add(k);
            s.swap(n, usize::from(j));
        }
        Self { s, i: 0, j: 0 }
    }
}

impl Drop for Rc4 {
    fn drop(&mut self) {
        self.s.zeroize();
        self.i.zeroize();
        self.j.zeroize();
    }
}

impl KeyStream for Rc4 {
    fn apply(&mut self, data: &mut [u8]) {
        crate::dit::with(|| {
            for b in data {
                self.i = self.i.wrapping_add(1);
                let si = self.s.get(usize::from(self.i)).copied().unwrap_or(0);
                self.j = self.j.wrapping_add(si);
                self.s.swap(usize::from(self.i), usize::from(self.j));
                let sj = self.s.get(usize::from(self.i)).copied().unwrap_or(0);
                let sk = self.s.get(usize::from(self.j)).copied().unwrap_or(0);
                *b ^= self
                    .s
                    .get(usize::from(sj.wrapping_add(sk)))
                    .copied()
                    .unwrap_or(0);
            }
        })
    }

    fn clone_box(&self) -> Result<Box<dyn KeyStream>, Error> {
        Ok(Box::new(self.clone()))
    }
}

/// RC4 keyed with 1 to 256 octets.
pub fn rc4(key: &[u8]) -> Result<Box<dyn KeyStream>, Error> {
    if key.is_empty() || key.len() > 256 {
        return Err(Error::KeyLength);
    }
    Ok(Box::new(Rc4::new(key)))
}

/// The universal hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// GHASH (GCM), keyed with H (16 octets).
    Ghash,
    /// POLYVAL (GCM-SIV), keyed with H (16 octets).
    Polyval,
    /// Poly1305, keyed with r and s (32 octets).
    Poly1305,
}

/// A keyed universal hash over 16-octet blocks.
pub trait UniversalHash: Send + Sync {
    /// Absorbs `data`, the last partial block padded with zeros (as GCM and ChaCha20-Poly1305
    /// pad their AAD and ciphertext).
    fn update_padded(&mut self, data: &[u8]);
    /// The tag: for Poly1305, of the data absorbed then `last` (at most a block) with
    /// Poly1305's own padding of a final partial block, as the MAC computes it; the others
    /// absorb `last` padded with zeros.
    fn finalize(&mut self, last: &[u8]) -> [u8; 16];
    /// A copy, for a copied context.
    fn clone_box(&self) -> Box<dyn UniversalHash>;
}

#[derive(Clone)]
struct Uhf<U>(Option<U>);

impl<U> UniversalHash for Uhf<U>
where
    U: universal_hash::UniversalHash + Clone + Send + Sync + 'static,
{
    fn update_padded(&mut self, data: &[u8]) {
        crate::dit::with(|| {
            if let Some(u) = &mut self.0 {
                u.update_padded(data);
            }
        })
    }

    fn finalize(&mut self, last: &[u8]) -> [u8; 16] {
        crate::dit::with(|| {
            let Some(mut u) = self.0.take() else {
                return [0; 16];
            };
            u.update_padded(last);
            let tag = u.finalize();
            let mut out = [0u8; 16];
            if let Some(t) = tag.get(..16) {
                out.copy_from_slice(t);
            }
            out
        })
    }

    fn clone_box(&self) -> Box<dyn UniversalHash> {
        Box::new(self.clone())
    }
}

/// Poly1305, whose final partial block takes its own padding.
#[derive(Clone)]
struct Poly(Option<poly1305::Poly1305>);

impl UniversalHash for Poly {
    fn update_padded(&mut self, data: &[u8]) {
        crate::dit::with(|| {
            if let Some(p) = &mut self.0 {
                p.update_padded(data);
            }
        })
    }

    fn finalize(&mut self, last: &[u8]) -> [u8; 16] {
        crate::dit::with(|| {
            let Some(p) = self.0.take() else {
                return [0; 16];
            };
            let tag = p.compute_unpadded(last);
            let mut out = [0u8; 16];
            if let Some(t) = tag.get(..16) {
                out.copy_from_slice(t);
            }
            out
        })
    }

    fn clone_box(&self) -> Box<dyn UniversalHash> {
        Box::new(self.clone())
    }
}

/// A universal hash keyed with `key`.
pub fn universal_hash(
    algorithm: HashAlgorithm,
    key: &[u8],
) -> Result<Box<dyn UniversalHash>, Error> {
    crate::dit::with(|| -> Result<Box<dyn UniversalHash>, Error> {
        Ok(match algorithm {
            HashAlgorithm::Ghash => Box::new(Uhf(Some(
                ghash::GHash::new_from_slice(key).map_err(|_| Error::KeyLength)?,
            ))),
            HashAlgorithm::Polyval => Box::new(Uhf(Some(
                polyval::Polyval::new_from_slice(key).map_err(|_| Error::KeyLength)?,
            ))),
            HashAlgorithm::Poly1305 => Box::new(Poly(Some(
                poly1305::Poly1305::new_from_slice(key).map_err(|_| Error::KeyLength)?,
            ))),
        })
    })
}
