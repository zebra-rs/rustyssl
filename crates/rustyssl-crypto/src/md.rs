//! Message digests: the algorithms the built-in providers offer, behind a backend trait so each
//! implementation can be replaced, and the default backend over the vetted RustCrypto crates
//! (docs/DEPENDENCIES.md).
//!
//! The SHA-3 family (SHA3-*, SHAKE, and OpenSSL's KECCAK-KMAC digests, which are the raw sponge
//! with KMAC's padding) is a sponge of our own over the `keccak` crate's permutation, because
//! KECCAK-KMAC needs a padding byte no hash crate exposes. Composites (MD5-SHA1) and NULL are
//! ours too.
//!
//! A context absorbs data, then is finalized once (a fixed-size digest into exactly its size,
//! an XOF into any length); an XOF can instead be squeezed any number of times before that
//! (`EVP_DigestSqueeze`). After finalizing, only a reset makes it usable again. The CPU
//! features the crates detect at run time (SHA-NI, the ARMv8 SHA-1, SHA-2, and SHA-3
//! instructions) need no configuration.

use digest::Digest;

/// The digests the built-in providers offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
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
    /// SHA-512/224.
    Sha512_224,
    /// SHA-512/256.
    Sha512_256,
    /// SHA3-224.
    Sha3_224,
    /// SHA3-256.
    Sha3_256,
    /// SHA3-384.
    Sha3_384,
    /// SHA3-512.
    Sha3_512,
    /// SHAKE128 (an XOF).
    Shake128,
    /// SHAKE256 (an XOF).
    Shake256,
    /// KECCAK-KMAC-128: Keccak[256] with KMAC's padding (an XOF), the core of KMAC128.
    KeccakKmac128,
    /// KECCAK-KMAC-256: Keccak[512] with KMAC's padding (an XOF), the core of KMAC256.
    KeccakKmac256,
    /// MD5.
    Md5,
    /// MD5 and SHA-1 side by side (TLS 1.0 and 1.1 signatures).
    Md5Sha1,
    /// SM3.
    Sm3,
    /// BLAKE2s-256.
    Blake2s256,
    /// BLAKE2b-512.
    Blake2b512,
    /// RIPEMD-160.
    Ripemd160,
    /// MD4 (legacy provider).
    Md4,
    /// Whirlpool (legacy provider).
    Whirlpool,
    /// The empty digest.
    Null,
}

impl Algorithm {
    /// Every algorithm.
    pub const ALL: [Self; 24] = [
        Self::Sha1,
        Self::Sha224,
        Self::Sha256,
        Self::Sha384,
        Self::Sha512,
        Self::Sha512_224,
        Self::Sha512_256,
        Self::Sha3_224,
        Self::Sha3_256,
        Self::Sha3_384,
        Self::Sha3_512,
        Self::Shake128,
        Self::Shake256,
        Self::KeccakKmac128,
        Self::KeccakKmac256,
        Self::Md5,
        Self::Md5Sha1,
        Self::Sm3,
        Self::Blake2s256,
        Self::Blake2b512,
        Self::Ripemd160,
        Self::Md4,
        Self::Whirlpool,
        Self::Null,
    ];

    /// The digest's size in octets: an XOF's default output, as OpenSSL reports it.
    pub const fn output_size(self) -> usize {
        match self {
            Self::Null => 0,
            Self::Md4 | Self::Md5 => 16,
            Self::Sha1 | Self::Ripemd160 => 20,
            Self::Sha224 | Self::Sha512_224 | Self::Sha3_224 => 28,
            Self::Sha256
            | Self::Sha512_256
            | Self::Sha3_256
            | Self::Sm3
            | Self::Blake2s256
            | Self::Shake256 => 32,
            Self::Md5Sha1 => 36,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 | Self::Blake2b512 | Self::Whirlpool => 64,
            Self::Shake128 => 16,
            Self::KeccakKmac128 => 32,
            Self::KeccakKmac256 => 64,
        }
    }

    /// The digest's block size in octets (a sponge's rate).
    pub const fn block_size(self) -> usize {
        match self {
            Self::Null => 0,
            Self::Sha384
            | Self::Sha512
            | Self::Sha512_224
            | Self::Sha512_256
            | Self::Blake2b512 => 128,
            Self::Sha3_224 => 144,
            Self::Sha3_256 | Self::Shake256 | Self::KeccakKmac256 => 136,
            Self::Sha3_384 => 104,
            Self::Sha3_512 => 72,
            Self::Shake128 | Self::KeccakKmac128 => 168,
            Self::Md4
            | Self::Md5
            | Self::Md5Sha1
            | Self::Sha1
            | Self::Sha224
            | Self::Sha256
            | Self::Sm3
            | Self::Blake2s256
            | Self::Ripemd160
            | Self::Whirlpool => 64,
        }
    }

    /// Whether it's an extendable-output function.
    pub const fn is_xof(self) -> bool {
        matches!(
            self,
            Self::Shake128 | Self::Shake256 | Self::KeccakKmac128 | Self::KeccakKmac256
        )
    }
}

/// Why a digest operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The context was finalized: reset it first.
    Finalized,
    /// A fixed-size digest finalized into the wrong length.
    OutputSize,
    /// Squeezing a digest that isn't an XOF.
    NotXof,
}

/// A digest computation in progress.
pub trait Context: Send + Sync {
    /// Absorbs `data`.
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;
    /// Finishes: a fixed-size digest into `out` of exactly its size, an XOF into any length.
    fn finalize(&mut self, out: &mut [u8]) -> Result<(), Error>;
    /// Squeezes an XOF's next `out.len()` octets (`EVP_DigestSqueeze`), repeatably.
    fn squeeze(&mut self, out: &mut [u8]) -> Result<(), Error>;
    /// Starts again, as new.
    fn reset(&mut self);
    /// A copy of the computation so far (`EVP_MD_CTX_copy`).
    fn clone_box(&self) -> Box<dyn Context>;
}

/// A source of digest implementations.
pub trait Backend: Sync {
    /// A new context for `algorithm`, or `None` if this backend doesn't implement it.
    fn context(&self, algorithm: Algorithm) -> Option<Box<dyn Context>>;
}

/// The default backend: the RustCrypto crates and our sponge.
pub struct RustCrypto;

impl Backend for RustCrypto {
    fn context(&self, algorithm: Algorithm) -> Option<Box<dyn Context>> {
        Some(match algorithm {
            Algorithm::Sha1 => Box::new(Fixed::<sha1::Sha1>::default()),
            Algorithm::Sha224 => Box::new(Fixed::<sha2::Sha224>::default()),
            Algorithm::Sha256 => Box::new(Fixed::<sha2::Sha256>::default()),
            Algorithm::Sha384 => Box::new(Fixed::<sha2::Sha384>::default()),
            Algorithm::Sha512 => Box::new(Fixed::<sha2::Sha512>::default()),
            Algorithm::Sha512_224 => Box::new(Fixed::<sha2::Sha512_224>::default()),
            Algorithm::Sha512_256 => Box::new(Fixed::<sha2::Sha512_256>::default()),
            Algorithm::Md5 => Box::new(Fixed::<md5::Md5>::default()),
            Algorithm::Md4 => Box::new(Fixed::<md4::Md4>::default()),
            Algorithm::Sm3 => Box::new(Fixed::<sm3::Sm3>::default()),
            Algorithm::Blake2s256 => Box::new(Fixed::<blake2::Blake2s256>::default()),
            Algorithm::Blake2b512 => Box::new(Fixed::<blake2::Blake2b512>::default()),
            Algorithm::Ripemd160 => Box::new(Fixed::<ripemd::Ripemd160>::default()),
            Algorithm::Whirlpool => Box::new(Fixed::<whirlpool::Whirlpool>::default()),
            Algorithm::Md5Sha1 => Box::new(Md5Sha1::default()),
            Algorithm::Null => Box::new(Null::default()),
            Algorithm::Sha3_224
            | Algorithm::Sha3_256
            | Algorithm::Sha3_384
            | Algorithm::Sha3_512
            | Algorithm::Shake128
            | Algorithm::Shake256
            | Algorithm::KeccakKmac128
            | Algorithm::KeccakKmac256 => Box::new(Sponge::new(algorithm)),
        })
    }
}

/// A new context for `algorithm` from the default backend.
pub fn context(algorithm: Algorithm) -> Box<dyn Context> {
    // The default backend implements every algorithm.
    RustCrypto
        .context(algorithm)
        .unwrap_or_else(|| Box::new(Null::default()))
}

/// A fixed-size RustCrypto digest.
#[derive(Clone, Default)]
struct Fixed<D> {
    inner: D,
    done: bool,
}

impl<D> Context for Fixed<D>
where
    D: Digest + digest::FixedOutputReset + Clone + Default + Send + Sync + 'static,
{
    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.done {
            return Err(Error::Finalized);
        }
        Digest::update(&mut self.inner, data);
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8]) -> Result<(), Error> {
        if self.done {
            return Err(Error::Finalized);
        }
        if out.len() != <D as Digest>::output_size() {
            return Err(Error::OutputSize);
        }
        let digest = self.inner.finalize_reset();
        out.copy_from_slice(&digest);
        self.done = true;
        Ok(())
    }

    fn squeeze(&mut self, _out: &mut [u8]) -> Result<(), Error> {
        Err(Error::NotXof)
    }

    fn reset(&mut self) {
        self.inner = D::default();
        self.done = false;
    }

    fn clone_box(&self) -> Box<dyn Context> {
        Box::new(self.clone())
    }
}

/// MD5 and SHA-1 of the same data, concatenated.
#[derive(Clone, Default)]
struct Md5Sha1 {
    md5: Fixed<md5::Md5>,
    sha1: Fixed<sha1::Sha1>,
}

impl Context for Md5Sha1 {
    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.md5.update(data)?;
        self.sha1.update(data)
    }

    fn finalize(&mut self, out: &mut [u8]) -> Result<(), Error> {
        if out.len() != 36 {
            return Err(Error::OutputSize);
        }
        let (a, b) = out.split_at_mut(16);
        self.md5.finalize(a)?;
        self.sha1.finalize(b)
    }

    fn squeeze(&mut self, _out: &mut [u8]) -> Result<(), Error> {
        Err(Error::NotXof)
    }

    fn reset(&mut self) {
        self.md5.reset();
        self.sha1.reset();
    }

    fn clone_box(&self) -> Box<dyn Context> {
        Box::new(self.clone())
    }
}

/// The empty digest.
#[derive(Clone, Default)]
struct Null {
    done: bool,
}

impl Context for Null {
    fn update(&mut self, _data: &[u8]) -> Result<(), Error> {
        if self.done {
            Err(Error::Finalized)
        } else {
            Ok(())
        }
    }

    fn finalize(&mut self, out: &mut [u8]) -> Result<(), Error> {
        if self.done {
            return Err(Error::Finalized);
        }
        if !out.is_empty() {
            return Err(Error::OutputSize);
        }
        self.done = true;
        Ok(())
    }

    fn squeeze(&mut self, _out: &mut [u8]) -> Result<(), Error> {
        Err(Error::NotXof)
    }

    fn reset(&mut self) {
        self.done = false;
    }

    fn clone_box(&self) -> Box<dyn Context> {
        Box::new(self.clone())
    }
}

/// Where a sponge is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Absorbing,
    Squeezing,
    Done,
}

/// The Keccak sponge (FIPS 202): `rate` octets of the 200-octet state absorbed and squeezed,
/// the message padded with `delimiter` then a final `0x80`.
#[derive(Clone)]
struct Sponge {
    algorithm: Algorithm,
    state: [u64; 25],
    rate: usize,
    delimiter: u8,
    /// Octets absorbed into, or squeezed from, the current block.
    position: usize,
    phase: Phase,
}

impl Sponge {
    fn new(algorithm: Algorithm) -> Self {
        let delimiter = match algorithm {
            Algorithm::Shake128 | Algorithm::Shake256 => 0x1f,
            Algorithm::KeccakKmac128 | Algorithm::KeccakKmac256 => 0x04,
            _ => 0x06,
        };
        Self {
            algorithm,
            state: [0; 25],
            rate: algorithm.block_size(),
            delimiter,
            position: 0,
            phase: Phase::Absorbing,
        }
    }

    fn permute(&mut self) {
        keccak::Keccak::new().with_f1600(|f| f(&mut self.state));
    }

    /// XORs `byte` into octet `i` of the state (lanes are little-endian).
    fn xor(&mut self, i: usize, byte: u8) {
        if let Some(lane) = self.state.get_mut(i / 8) {
            let mut octets = lane.to_le_bytes();
            if let Some(o) = octets.get_mut(i % 8) {
                *o ^= byte;
            }
            *lane = u64::from_le_bytes(octets);
        }
    }

    /// Octet `i` of the state.
    fn octet(&self, i: usize) -> u8 {
        self.state
            .get(i / 8)
            .and_then(|lane| lane.to_le_bytes().get(i % 8).copied())
            .unwrap_or(0)
    }

    /// Pads the message and permutes: absorbing ends.
    fn pad(&mut self) {
        self.xor(self.position, self.delimiter);
        self.xor(self.rate.saturating_sub(1), 0x80);
        self.permute();
        self.position = 0;
        self.phase = Phase::Squeezing;
    }

    fn read(&mut self, out: &mut [u8]) {
        if self.phase == Phase::Absorbing {
            self.pad();
        }
        for o in out {
            if self.position == self.rate {
                self.permute();
                self.position = 0;
            }
            *o = self.octet(self.position);
            self.position = self.position.saturating_add(1);
        }
    }
}

impl Context for Sponge {
    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.phase != Phase::Absorbing {
            return Err(Error::Finalized);
        }
        for &b in data {
            self.xor(self.position, b);
            self.position = self.position.saturating_add(1);
            if self.position == self.rate {
                self.permute();
                self.position = 0;
            }
        }
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8]) -> Result<(), Error> {
        if self.phase == Phase::Done {
            return Err(Error::Finalized);
        }
        if !self.algorithm.is_xof() && out.len() != self.algorithm.output_size() {
            return Err(Error::OutputSize);
        }
        self.read(out);
        self.phase = Phase::Done;
        Ok(())
    }

    fn squeeze(&mut self, out: &mut [u8]) -> Result<(), Error> {
        if !self.algorithm.is_xof() {
            return Err(Error::NotXof);
        }
        if self.phase == Phase::Done {
            return Err(Error::Finalized);
        }
        self.read(out);
        Ok(())
    }

    fn reset(&mut self) {
        *self = Self::new(self.algorithm);
    }

    fn clone_box(&self) -> Box<dyn Context> {
        Box::new(self.clone())
    }
}
