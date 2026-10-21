//! Random generators: the mechanisms of SP 800-90A's DRBGs (CTR-DRBG over AES with or without
//! its derivation function, Hash-DRBG, and HMAC-DRBG) as the reference implements them, and the
//! operating system's entropy for the seed source.
//!
//! A mechanism is instantiated from entropy, a nonce, and a personalization string, generates
//! output with optional additional input, and is reseeded from entropy and additional input.
//! Everything around it is the RAND layer's (3.7): where entropy and nonces come from, the
//! default personalization string, reseeding on intervals, after a fork, or for prediction
//! resistance, the parent and child hierarchy, locking, and the limits each DRBG publishes,
//! which [`Drbg::limits`] reports and these mechanisms don't enforce themselves (HMAC-DRBG-KDF
//! generates past the request limit, as the reference's does).
//!
//! The reference's details, reproduced:
//! - CTR-DRBG's counter is the whole 128-bit V; with the derivation function, generating with
//!   additional input derives it once and reuses the result for the final update; without it,
//!   inputs are XORed into the key, then V, truncated to the seed length; an empty request
//!   still advances V twice and updates (the EVP layer never makes one: it calls the mechanism
//!   only for output, in chunks of at most the request limit).
//! - Hash-DRBG's seed length is 55 octets for digests of up to 32, 111 otherwise; its
//!   reseed counter starts at 1 after instantiating or reseeding and counts each generate.
//!
//! Secrets (keys, V, C, and the derivation function's state) are wiped when dropped.

use zeroize::{Zeroize, Zeroizing};

use crate::{mac, md, sym};

/// Why a random generator failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Generating or reseeding before instantiating.
    NotInstantiated,
    /// A digest a DRBG can't use: an XOF, or one of no size.
    Digest,
    /// A CTR-DRBG key length other than 16, 24, or 32 octets.
    KeyLength,
    /// The operating system's entropy source failed.
    Entropy,
}

/// The limits a DRBG publishes (`drbg->min_entropylen` and the rest), for the RAND layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The security strength in bits.
    pub strength: u32,
    /// The seed length in octets.
    pub seed_length: usize,
    /// Entropy octets per instantiation or reseed.
    pub min_entropy: usize,
    /// At most this much entropy.
    pub max_entropy: usize,
    /// Nonce octets (0 and 0 when the DRBG takes none).
    pub min_nonce: usize,
    /// At most this much nonce.
    pub max_nonce: usize,
    /// The longest personalization string.
    pub max_personalization: usize,
    /// The longest additional input.
    pub max_additional_input: usize,
    /// The most octets one request may generate.
    pub max_request: usize,
}

/// `DRBG_MAX_LENGTH`.
const MAX_LENGTH: usize = 0x7fff_ffff;
/// The reference's request limit, 2^16 octets.
const MAX_REQUEST: usize = 1 << 16;

/// A DRBG mechanism.
pub trait Drbg: Send + Sync {
    /// Instantiates from `entropy`, `nonce`, and `personalization` (each possibly empty).
    fn instantiate(&mut self, entropy: &[u8], nonce: &[u8], personalization: &[u8]);
    /// Reseeds from `entropy` and `additional_input`.
    fn reseed(&mut self, entropy: &[u8], additional_input: &[u8]) -> Result<(), Error>;
    /// Fills `out`, with `additional_input` (possibly empty).
    fn generate(&mut self, out: &mut [u8], additional_input: &[u8]) -> Result<(), Error>;
    /// Wipes the state; it must be instantiated again.
    fn uninstantiate(&mut self);
    /// The limits the RAND layer applies.
    fn limits(&self) -> Limits;
}

/// The strength of a Hash- or HMAC-DRBG over a digest of `size` octets (SP 800-57).
fn digest_strength(size: usize) -> u32 {
    u32::try_from((size / 8).saturating_mul(64)).map_or(256, |s| s.min(256))
}

/// The digest's size, if a DRBG can use it.
fn drbg_digest(digest: md::Algorithm) -> Result<usize, Error> {
    match digest.output_size() {
        0 => Err(Error::Digest),
        _ if digest.is_xof() => Err(Error::Digest),
        n => Ok(n),
    }
}

/// Limits of a Hash- or HMAC-DRBG.
fn digest_limits(strength: u32, seed_length: usize) -> Limits {
    let min_entropy = usize::try_from(strength / 8).unwrap_or(0);
    Limits {
        strength,
        seed_length,
        min_entropy,
        max_entropy: MAX_LENGTH,
        min_nonce: min_entropy / 2,
        max_nonce: MAX_LENGTH,
        max_personalization: MAX_LENGTH,
        max_additional_input: MAX_LENGTH,
        max_request: MAX_REQUEST,
    }
}

// ---------------------------------------------------------------------------------------------
// CTR-DRBG

/// The derivation function's fixed key: octets 0, 1, 2, ...
const DF_KEY: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

/// CTR-DRBG over AES.
pub struct CtrDrbg {
    key_length: usize,
    use_df: bool,
    key: Zeroizing<Vec<u8>>,
    v: Zeroizing<[u8; 16]>,
    cipher: Box<dyn sym::BlockCipher>,
    df_cipher: Box<dyn sym::BlockCipher>,
    /// The derivation function's last output, reused for the update after generating.
    kx: Zeroizing<[u8; 48]>,
    instantiated: bool,
}

/// What a CTR-DRBG update mixes in.
enum Provided<'a> {
    /// Nothing.
    None,
    /// Inputs: through the derivation function (entropy or additional input, nonce,
    /// personalization or additional input), or XORed in without it.
    Inputs(&'a [u8], &'a [u8], &'a [u8]),
    /// The derivation function's previous output again (generate's final update).
    Previous,
}

impl CtrDrbg {
    /// A CTR-DRBG over AES with a `key_length` of 16, 24, or 32 octets, with or without the
    /// derivation function.
    pub fn new(key_length: usize, use_df: bool) -> Result<Self, Error> {
        if !matches!(key_length, 16 | 24 | 32) {
            return Err(Error::KeyLength);
        }
        let zero = vec![0u8; key_length];
        let aes = |key: &[u8]| {
            sym::block_cipher(sym::BlockAlgorithm::Aes, key, None).map_err(|_| Error::KeyLength)
        };
        Ok(Self {
            key_length,
            use_df,
            cipher: aes(&zero)?,
            df_cipher: aes(DF_KEY.get(..key_length).ok_or(Error::KeyLength)?)?,
            key: Zeroizing::new(zero),
            v: Zeroizing::new([0; 16]),
            kx: Zeroizing::new([0; 48]),
            instantiated: false,
        })
    }

    fn seed_length(&self) -> usize {
        self.key_length.saturating_add(16)
    }

    fn increment(&mut self) {
        let v = u128::from_be_bytes(*self.v).wrapping_add(1);
        *self.v = v.to_be_bytes();
    }

    fn encrypt(cipher: &dyn sym::BlockCipher, blocks: &mut [u8]) {
        // AES takes any whole number of blocks.
        let _ = cipher.encrypt_blocks(blocks);
    }

    /// XORs `input`, truncated to the seed length, into the key and then V.
    fn xor(&mut self, input: &[u8]) {
        let (k, v) = input.split_at(input.len().min(self.key_length));
        self.key.iter_mut().zip(k).for_each(|(a, &b)| *a ^= b);
        self.v.iter_mut().zip(v).for_each(|(a, &b)| *a ^= b);
    }

    /// The derivation function (SP 800-90A 10.3.2) over the concatenated inputs, into `kx`.
    fn df(&mut self, inputs: [&[u8]; 3]) {
        let blocks: usize = if self.key_length == 16 { 2 } else { 3 };
        let width = blocks.wrapping_mul(16);
        // BCC's chaining values, one per output block, start from E(IV i).
        let mut chain = Zeroizing::new([0u8; 48]);
        for (i, block) in chain.chunks_mut(16).take(blocks).enumerate() {
            if let Some(b) = block.get_mut(3) {
                *b = u8::try_from(i).unwrap_or(0);
            }
        }
        Self::encrypt(&*self.df_cipher, chain.get_mut(..width).unwrap_or(&mut []));
        let total: usize = inputs
            .iter()
            .map(|i| i.len())
            .fold(0, usize::saturating_add);
        // L (the input length, as the reference's 32-bit field) and N (the seed length).
        let l = u32::try_from(total & 0xffff_ffff)
            .unwrap_or(0)
            .to_be_bytes();
        let n = u32::try_from(self.seed_length() & 0xff)
            .unwrap_or(0)
            .to_be_bytes();
        let header: Vec<u8> = l.into_iter().chain(n).collect();
        let mut stream = Zeroizing::new(Vec::with_capacity(total.saturating_add(25)));
        stream.extend_from_slice(&header);
        for input in inputs {
            stream.extend_from_slice(input);
        }
        stream.push(0x80);
        let padded = stream.len().div_ceil(16).saturating_mul(16);
        stream.resize(padded, 0);
        for block in stream.chunks(16) {
            for value in chain.chunks_mut(16).take(blocks) {
                value.iter_mut().zip(block).for_each(|(c, &b)| *c ^= b);
            }
            Self::encrypt(&*self.df_cipher, chain.get_mut(..width).unwrap_or(&mut []));
        }
        // K' and X from the chaining values, then E(K', X), E(K', that), ...
        let Ok(cipher) = sym::block_cipher(
            sym::BlockAlgorithm::Aes,
            chain.get(..self.key_length).unwrap_or(&[]),
            None,
        ) else {
            return;
        };
        let mut x = [0u8; 16];
        x.copy_from_slice(
            chain
                .get(self.key_length..self.key_length.saturating_add(16))
                .unwrap_or(&[0; 16]),
        );
        for out in self.kx.chunks_mut(16).take(blocks) {
            Self::encrypt(&*cipher, &mut x);
            out.copy_from_slice(&x);
        }
        x.zeroize();
    }

    /// CTR_DRBG_Update, as the reference orders it: the caller has already advanced V once.
    fn update(&mut self, provided: Provided<'_>) {
        let blocks: usize = if self.key_length == 16 { 2 } else { 3 };
        let mut temp = Zeroizing::new([0u8; 48]);
        for (i, block) in temp.chunks_mut(16).take(blocks).enumerate() {
            if i > 0 {
                self.increment();
            }
            block.copy_from_slice(&*self.v);
        }
        Self::encrypt(
            &*self.cipher,
            temp.get_mut(..blocks.wrapping_mul(16)).unwrap_or(&mut []),
        );
        self.key
            .copy_from_slice(temp.get(..self.key_length).unwrap_or(&[]));
        self.v.copy_from_slice(
            temp.get(self.key_length..self.key_length.saturating_add(16))
                .unwrap_or(&[0; 16]),
        );
        match provided {
            Provided::None => {}
            Provided::Inputs(a, b, c) if self.use_df => {
                self.df([a, b, c]);
                if !a.is_empty() {
                    let kx = *self.kx;
                    self.xor(kx.get(..self.seed_length()).unwrap_or(&[]));
                }
            }
            Provided::Inputs(a, _, c) => {
                self.xor(a);
                self.xor(c);
            }
            Provided::Previous => {
                let kx = *self.kx;
                self.xor(kx.get(..self.seed_length()).unwrap_or(&[]));
            }
        }
        if let Ok(cipher) = sym::block_cipher(sym::BlockAlgorithm::Aes, &self.key, None) {
            self.cipher = cipher;
        }
    }
}

impl Drbg for CtrDrbg {
    fn instantiate(&mut self, entropy: &[u8], nonce: &[u8], personalization: &[u8]) {
        self.key.iter_mut().for_each(|k| *k = 0);
        *self.v = [0; 16];
        if let Ok(cipher) = sym::block_cipher(sym::BlockAlgorithm::Aes, &self.key, None) {
            self.cipher = cipher;
        }
        self.increment();
        // The derivation function takes entropy || nonce || personalization.
        self.update(Provided::Inputs(entropy, nonce, personalization));
        self.instantiated = true;
    }

    fn reseed(&mut self, entropy: &[u8], additional_input: &[u8]) -> Result<(), Error> {
        if !self.instantiated {
            return Err(Error::NotInstantiated);
        }
        self.increment();
        self.update(Provided::Inputs(entropy, &[], additional_input));
        Ok(())
    }

    fn generate(&mut self, out: &mut [u8], additional_input: &[u8]) -> Result<(), Error> {
        if !self.instantiated {
            return Err(Error::NotInstantiated);
        }
        let mut last = Provided::None;
        if !additional_input.is_empty() {
            self.increment();
            self.update(Provided::Inputs(additional_input, &[], &[]));
            last = if self.use_df {
                Provided::Previous
            } else {
                Provided::Inputs(additional_input, &[], &[])
            };
        }
        self.increment();
        if out.is_empty() {
            self.increment();
            self.update(last);
            return Ok(());
        }
        // The blocks E(V), E(V + 1), ... many at a time: their counters encrypted in one call,
        // which lets the cipher work on several at once.
        const BATCH: usize = 32;
        // Wiped as far as it was used (a whole wipe would cost a short call more than its work).
        let mut stream = [0u8; BATCH * 16];
        let mut used = 0usize;
        for run in out.chunks_mut(BATCH * 16) {
            let blocks = run.len().div_ceil(16);
            used = used.max(blocks.saturating_mul(16));
            let buf = stream
                .get_mut(..blocks.saturating_mul(16))
                .unwrap_or(&mut []);
            for slot in buf.chunks_mut(16) {
                slot.copy_from_slice(&*self.v);
                self.increment();
            }
            Self::encrypt(&*self.cipher, buf);
            run.copy_from_slice(buf.get(..run.len()).unwrap_or(&[]));
        }
        stream.get_mut(..used).unwrap_or_default().zeroize();
        self.update(last);
        Ok(())
    }

    fn uninstantiate(&mut self) {
        self.key.zeroize();
        self.key.resize(self.key_length, 0);
        self.v.zeroize();
        self.kx.zeroize();
        self.instantiated = false;
    }

    fn limits(&self) -> Limits {
        let seed = self.seed_length();
        let strength = u32::try_from(self.key_length.saturating_mul(8)).unwrap_or(0);
        if self.use_df {
            Limits {
                strength,
                seed_length: seed,
                min_entropy: self.key_length,
                max_entropy: MAX_LENGTH,
                min_nonce: self.key_length / 2,
                max_nonce: MAX_LENGTH,
                max_personalization: MAX_LENGTH,
                max_additional_input: MAX_LENGTH,
                max_request: MAX_REQUEST,
            }
        } else {
            Limits {
                strength,
                seed_length: seed,
                min_entropy: seed,
                max_entropy: seed,
                min_nonce: 0,
                max_nonce: 0,
                max_personalization: seed,
                max_additional_input: seed,
                max_request: MAX_REQUEST,
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Hash-DRBG

/// Hash-DRBG.
pub struct HashDrbg {
    digest: md::Algorithm,
    size: usize,
    seed_length: usize,
    v: Zeroizing<Vec<u8>>,
    c: Zeroizing<Vec<u8>>,
    reseed_counter: u32,
    instantiated: bool,
}

/// `dst = (dst + src) mod 2^(8 * dst.len())`, both big-endian, `src` no longer than `dst`.
fn add_into(dst: &mut [u8], src: &[u8]) {
    let mut carry = 0u16;
    let mut src = src.iter().rev();
    for d in dst.iter_mut().rev() {
        let s = src.next().copied().unwrap_or(0);
        let sum = u16::from(*d).wrapping_add(u16::from(s)).wrapping_add(carry);
        *d = sum.to_le_bytes()[0];
        carry = sum >> 8;
    }
}

impl HashDrbg {
    /// A Hash-DRBG over `digest` (any but an XOF).
    pub fn new(digest: md::Algorithm) -> Result<Self, Error> {
        let size = drbg_digest(digest)?;
        let seed_length = if size > 32 { 111 } else { 55 };
        Ok(Self {
            digest,
            size,
            seed_length,
            v: Zeroizing::new(vec![0; seed_length]),
            c: Zeroizing::new(vec![0; seed_length]),
            reseed_counter: 0,
            instantiated: false,
        })
    }

    fn hash(&self, parts: &[&[u8]], out: &mut [u8]) {
        let mut ctx = md::context(self.digest);
        for part in parts {
            let _ = ctx.update(part);
        }
        let _ = ctx.finalize(out);
    }

    /// Hash_df to the seed length, with an optional leading input octet.
    fn hash_df(&self, inbyte: Option<u8>, inputs: &[&[u8]]) -> Zeroizing<Vec<u8>> {
        let bits = u32::try_from(self.seed_length.saturating_mul(8)).unwrap_or(0);
        let mut prefix = vec![1u8];
        prefix.extend_from_slice(&bits.to_be_bytes());
        prefix.extend(inbyte);
        let mut out = Zeroizing::new(vec![0u8; self.seed_length]);
        let mut block = Zeroizing::new(vec![0u8; self.size]);
        for chunk in out.chunks_mut(self.size) {
            let mut parts: Vec<&[u8]> = vec![&prefix];
            parts.extend_from_slice(inputs);
            self.hash(&parts, &mut block);
            chunk.copy_from_slice(block.get(..chunk.len()).unwrap_or(&[]));
            if let Some(counter) = prefix.first_mut() {
                *counter = counter.wrapping_add(1);
            }
        }
        out
    }

    /// V = V + Hash(inbyte || V || input).
    fn add_hash(&mut self, inbyte: u8, input: &[u8]) {
        let mut h = Zeroizing::new(vec![0u8; self.size]);
        self.hash(&[&[inbyte], &self.v, input], &mut h);
        add_into(&mut self.v, &h);
    }
}

impl Drbg for HashDrbg {
    fn instantiate(&mut self, entropy: &[u8], nonce: &[u8], personalization: &[u8]) {
        self.v = self.hash_df(None, &[entropy, nonce, personalization]);
        self.c = self.hash_df(Some(0), &[&self.v]);
        self.reseed_counter = 1;
        self.instantiated = true;
    }

    fn reseed(&mut self, entropy: &[u8], additional_input: &[u8]) -> Result<(), Error> {
        if !self.instantiated {
            return Err(Error::NotInstantiated);
        }
        self.v = self.hash_df(Some(1), &[&self.v, entropy, additional_input]);
        self.c = self.hash_df(Some(0), &[&self.v]);
        self.reseed_counter = 1;
        Ok(())
    }

    fn generate(&mut self, out: &mut [u8], additional_input: &[u8]) -> Result<(), Error> {
        if !self.instantiated {
            return Err(Error::NotInstantiated);
        }
        if !additional_input.is_empty() {
            self.add_hash(2, additional_input);
        }
        // Hashgen: Hash(data), data + 1, ... from data = V.
        let mut data = self.v.clone();
        let mut block = Zeroizing::new(vec![0u8; self.size]);
        for chunk in out.chunks_mut(self.size) {
            self.hash(&[&data], &mut block);
            chunk.copy_from_slice(block.get(..chunk.len()).unwrap_or(&[]));
            add_into(&mut data, &[1]);
        }
        self.add_hash(3, &[]);
        let c = self.c.clone();
        add_into(&mut self.v, &c);
        add_into(&mut self.v, &self.reseed_counter.to_be_bytes());
        self.reseed_counter = self.reseed_counter.wrapping_add(1);
        Ok(())
    }

    fn uninstantiate(&mut self) {
        self.v.iter_mut().for_each(|b| *b = 0);
        self.c.iter_mut().for_each(|b| *b = 0);
        self.reseed_counter = 0;
        self.instantiated = false;
    }

    fn limits(&self) -> Limits {
        digest_limits(digest_strength(self.size), self.seed_length)
    }
}

// ---------------------------------------------------------------------------------------------
// HMAC-DRBG

/// HMAC-DRBG (also the core of HMAC-DRBG-KDF).
pub struct HmacDrbg {
    digest: md::Algorithm,
    k: Zeroizing<Vec<u8>>,
    v: Zeroizing<Vec<u8>>,
    instantiated: bool,
}

impl HmacDrbg {
    /// An HMAC-DRBG over `digest` (any but an XOF).
    pub fn new(digest: md::Algorithm) -> Result<Self, Error> {
        let size = drbg_digest(digest)?;
        Ok(Self {
            digest,
            k: Zeroizing::new(vec![0; size]),
            v: Zeroizing::new(vec![0; size]),
            instantiated: false,
        })
    }

    /// HMAC(K, parts...) into `out` (the digest's size).
    fn hmac(&self, parts: &[&[u8]], out: &mut [u8]) {
        if let Ok(mut m) = mac::hmac(self.digest, &self.k) {
            for part in parts {
                let _ = m.update(part);
            }
            let _ = m.finalize(out);
        }
    }

    /// K = HMAC(K, V || inbyte || inputs); V = HMAC(K, V).
    fn step(&mut self, inbyte: u8, inputs: &[&[u8]]) {
        let mut parts: Vec<&[u8]> = vec![&self.v, std::slice::from_ref(&inbyte)];
        parts.extend_from_slice(inputs);
        let mut k = Zeroizing::new(vec![0u8; self.k.len()]);
        self.hmac(&parts, &mut k);
        self.k = k;
        let mut v = Zeroizing::new(vec![0u8; self.v.len()]);
        self.hmac(&[&self.v], &mut v);
        self.v = v;
    }

    /// HMAC_DRBG_Update.
    fn update(&mut self, inputs: &[&[u8]]) {
        self.step(0, inputs);
        if inputs.iter().any(|i| !i.is_empty()) {
            self.step(1, inputs);
        }
    }
}

impl Drbg for HmacDrbg {
    fn instantiate(&mut self, entropy: &[u8], nonce: &[u8], personalization: &[u8]) {
        self.k.iter_mut().for_each(|b| *b = 0);
        self.v.iter_mut().for_each(|b| *b = 1);
        self.update(&[entropy, nonce, personalization]);
        self.instantiated = true;
    }

    fn reseed(&mut self, entropy: &[u8], additional_input: &[u8]) -> Result<(), Error> {
        if !self.instantiated {
            return Err(Error::NotInstantiated);
        }
        self.update(&[entropy, additional_input]);
        Ok(())
    }

    fn generate(&mut self, out: &mut [u8], additional_input: &[u8]) -> Result<(), Error> {
        if !self.instantiated {
            return Err(Error::NotInstantiated);
        }
        if !additional_input.is_empty() {
            self.update(&[additional_input]);
        }
        for chunk in out.chunks_mut(self.v.len().max(1)) {
            let mut v = Zeroizing::new(vec![0u8; self.v.len()]);
            self.hmac(&[&self.v], &mut v);
            self.v = v;
            chunk.copy_from_slice(self.v.get(..chunk.len()).unwrap_or(&[]));
        }
        self.update(&[additional_input]);
        Ok(())
    }

    fn uninstantiate(&mut self) {
        self.k.iter_mut().for_each(|b| *b = 0);
        self.v.iter_mut().for_each(|b| *b = 0);
        self.instantiated = false;
    }

    fn limits(&self) -> Limits {
        digest_limits(digest_strength(self.v.len()), self.v.len())
    }
}

// ---------------------------------------------------------------------------------------------
// The seed source

/// Fills `out` from the operating system's entropy source (`getrandom` on Linux, waiting
/// until the kernel's pool is initialized; `getentropy` on macOS), as the seed source polls it.
pub fn os_entropy(out: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(out).map_err(|_| Error::Entropy)
}

/// A source of random octets a context draws on (the library's generators, `RAND_bytes_ex`,
/// in the C layer): fills its argument, false if it can't.
pub type Random = std::sync::Arc<dyn Fn(&mut [u8]) -> bool + Send + Sync>;

/// Fills `out` from `source`, or from the operating system without one.
pub fn fill(source: Option<&Random>, out: &mut [u8]) -> bool {
    match source {
        Some(r) => r(out),
        None => os_entropy(out).is_ok(),
    }
}
