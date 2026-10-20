//! The cryptography QUIC needs beyond TLS's: header protection (RFC 9001, section 5.4).
//! `rustyssl-capi` implements [`Provider`] with EVP (`ssl/quic_provider.rs`); the tests use
//! `rustyssl-crypto` directly.

use rustyssl_tls::crypto::{AeadAlg, HashAlg};
use rustyssl_tls::suites::{Cipher, Protection};

use crate::error::{Error, Result};

/// A header-protection algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HpAlg {
    /// AES-128 in ECB mode, one block.
    Aes128,
    /// AES-256 in ECB mode, one block.
    Aes256,
    /// ChaCha20's raw keystream, counter and nonce from the sample.
    ChaCha20,
}

impl HpAlg {
    /// The key length in octets.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 | Self::ChaCha20 => 32,
        }
    }
}

/// A keyed header-protection function.
pub trait HeaderProtection: Send {
    /// The five-octet mask for a 16-octet `sample` of the ciphertext.
    ///
    /// # Errors
    /// The provider failed.
    fn mask(&self, sample: &[u8; 16]) -> rustyssl_tls::error::Result<[u8; 5]>;
}

/// The cryptography of one QUIC connection: TLS's, plus header protection.
pub trait Provider: rustyssl_tls::crypto::Provider {
    /// A header-protection function for `alg` keyed with `key`.
    ///
    /// # Errors
    /// The algorithm isn't available, or the key is wrong.
    fn header_protection(
        &self,
        alg: HpAlg,
        key: &[u8],
    ) -> rustyssl_tls::error::Result<Box<dyn HeaderProtection>>;
}

/// What packet protection uses for one TLS 1.3 suite: the AEAD, the header protection, and
/// the hash the key derivation uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Suite {
    pub aead: AeadAlg,
    pub hp: HpAlg,
    pub hash: HashAlg,
}

impl Suite {
    /// The Initial packets' suite (RFC 9001, section 5.2): AES-128-GCM with SHA-256.
    pub const INITIAL: Self = Self {
        aead: AeadAlg::Aes128Gcm,
        hp: HpAlg::Aes128,
        hash: HashAlg::Sha256,
    };

    /// The suite for a negotiated TLS 1.3 cipher. As OpenSSL's QUIC (`quic_tls.c`), only
    /// AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 are supported; anything else (a CCM
    /// suite) is INTERNAL_ERROR, which the caller reports as OpenSSL does.
    ///
    /// # Errors
    /// The suite isn't one QUIC can use here.
    pub fn from_cipher(c: &Cipher) -> Result<Self> {
        let hash = c
            .handshake_hash()
            .ok_or_else(|| Error::internal("unknown cipher type"))?;
        let (aead, hp) = match c.protection() {
            Protection::Aead(AeadAlg::Aes128Gcm) => (AeadAlg::Aes128Gcm, HpAlg::Aes128),
            Protection::Aead(AeadAlg::Aes256Gcm) => (AeadAlg::Aes256Gcm, HpAlg::Aes256),
            Protection::Aead(AeadAlg::ChaCha20Poly1305) => {
                (AeadAlg::ChaCha20Poly1305, HpAlg::ChaCha20)
            }
            _ => return Err(Error::internal("unknown cipher type")),
        };
        Ok(Self { aead, hp, hash })
    }

    /// The most packets one key may protect (RFC 9001, section 6.6), the confidentiality
    /// limit; OpenSSL starts a key update well before it.
    #[must_use]
    pub const fn confidentiality_limit(&self) -> u64 {
        match self.aead {
            AeadAlg::ChaCha20Poly1305 => u64::MAX,
            _ => 1 << 23,
        }
    }

    /// The most packets that may fail authentication under one key (RFC 9001, section 6.6),
    /// the integrity limit, after which the connection closes with AEAD_LIMIT_REACHED.
    #[must_use]
    pub const fn integrity_limit(&self) -> u64 {
        match self.aead {
            AeadAlg::ChaCha20Poly1305 => 1 << 36,
            _ => 1 << 52,
        }
    }
}
