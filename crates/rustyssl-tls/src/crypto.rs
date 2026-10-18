//! The cryptography a connection needs, supplied by its caller (ADR 0002). `rustyssl-capi`
//! implements [`Provider`] with the `SSL_CTX`'s library context and property query, so every
//! algorithm comes from the providers as in OpenSSL; the core's tests implement it with
//! `rustyssl-crypto` directly.
//!
//! Keys and certificates stay with the caller: the core holds [`KeyId`]s and certificate
//! encodings, and asks the provider to sign or verify with them.

use crate::error::Result;

/// A hash function, by its role in TLS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashAlg {
    /// MD5 and SHA-1 concatenated (TLS 1.0 and 1.1's PRF and signatures).
    Md5Sha1,
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
    /// SM3.
    Sm3,
}

impl HashAlg {
    /// The output length in octets.
    #[must_use]
    pub const fn len(self) -> usize {
        match self {
            Self::Md5Sha1 => 36,
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 | Self::Sm3 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Whether the output is empty (never: every hash has output).
    #[must_use]
    pub const fn is_empty(self) -> bool {
        false
    }
}

/// An incremental hash, as the transcript keeps it.
pub trait Hash: Send {
    /// Adds `data`.
    fn update(&mut self, data: &[u8]);
    /// The hash of everything added so far, leaving the state as it is.
    fn current(&self) -> Vec<u8>;
    /// A copy of the state, to continue separately.
    fn fork(&self) -> Box<dyn Hash>;
}

/// An HMAC (or other MAC) over one key.
pub trait Mac: Send {
    /// Adds `data`.
    fn update(&mut self, data: &[u8]);
    /// The tag of everything added, and the state reset to the key.
    fn finish(&mut self) -> Vec<u8>;
}

/// An AEAD for record protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AeadAlg {
    /// AES-128-GCM.
    Aes128Gcm,
    /// AES-256-GCM.
    Aes256Gcm,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305,
    /// AES-128-CCM (16-octet tag).
    Aes128Ccm,
    /// AES-256-CCM (16-octet tag).
    Aes256Ccm,
    /// AES-128-CCM with an 8-octet tag.
    Aes128Ccm8,
    /// AES-256-CCM with an 8-octet tag.
    Aes256Ccm8,
    /// ARIA-128-GCM.
    Aria128Gcm,
    /// ARIA-256-GCM.
    Aria256Gcm,
    /// SM4-GCM.
    Sm4Gcm,
    /// SM4-CCM.
    Sm4Ccm,
}

impl AeadAlg {
    /// The key length in octets.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm
            | Self::Aes128Ccm
            | Self::Aes128Ccm8
            | Self::Aria128Gcm
            | Self::Sm4Gcm
            | Self::Sm4Ccm => 16,
            Self::Aes256Gcm
            | Self::ChaCha20Poly1305
            | Self::Aes256Ccm
            | Self::Aes256Ccm8
            | Self::Aria256Gcm => 32,
        }
    }

    /// The tag length in octets.
    #[must_use]
    pub const fn tag_len(self) -> usize {
        match self {
            Self::Aes128Ccm8 | Self::Aes256Ccm8 => 8,
            _ => 16,
        }
    }
}

/// A keyed AEAD.
pub trait Aead: Send {
    /// Encrypts `data` in place and appends the tag.
    ///
    /// # Errors
    /// The provider failed.
    fn seal(&mut self, nonce: &[u8], aad: &[u8], data: &mut Vec<u8>) -> Result<()>;
    /// Checks the tag at the end of `data`, removes it, and decrypts in place; a bad tag is an
    /// error (decided in constant time).
    ///
    /// # Errors
    /// The tag doesn't verify, or the provider failed.
    fn open(&mut self, nonce: &[u8], aad: &[u8], data: &mut Vec<u8>) -> Result<()>;
}

/// A block or stream cipher for TLS 1.2 and earlier's MAC-then-encrypt and encrypt-then-MAC
/// suites.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CipherAlg {
    /// AES-128-CBC.
    Aes128Cbc,
    /// AES-256-CBC.
    Aes256Cbc,
    /// Camellia-128-CBC.
    Camellia128Cbc,
    /// Camellia-256-CBC.
    Camellia256Cbc,
    /// ARIA-128-CBC (not used by any suite OpenSSL offers, kept for completeness).
    Aria128Cbc,
    /// ARIA-256-CBC.
    Aria256Cbc,
    /// Triple-DES (EDE3) CBC.
    DesEde3Cbc,
    /// SEED-CBC.
    SeedCbc,
    /// SM4-CBC.
    Sm4Cbc,
    /// No encryption (the NULL suites).
    Null,
}

impl CipherAlg {
    /// The key length in octets.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Cbc
            | Self::Camellia128Cbc
            | Self::Aria128Cbc
            | Self::SeedCbc
            | Self::Sm4Cbc => 16,
            Self::Aes256Cbc | Self::Camellia256Cbc | Self::Aria256Cbc => 32,
            Self::DesEde3Cbc => 24,
            Self::Null => 0,
        }
    }

    /// The block (and IV) length in octets; 0 for no encryption.
    #[must_use]
    pub const fn block_len(self) -> usize {
        match self {
            Self::DesEde3Cbc => 8,
            Self::Null => 0,
            _ => 16,
        }
    }
}

/// A keyed CBC cipher in one direction. The IV is passed with each call: TLS 1.0 chains it
/// from the previous record, later versions send it explicitly.
pub trait Cipher: Send {
    /// Encrypts or decrypts `data` (a whole number of blocks) in place with `iv`.
    ///
    /// # Errors
    /// The provider failed.
    fn crypt(&mut self, iv: &[u8], data: &mut [u8]) -> Result<()>;
}

/// A group the providers offer (their `TLS-GROUP` capability).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupInfo {
    /// The name OpenSSL lists it by (`x25519`, `secp256r1`, `X25519MLKEM768`, ...).
    pub name: String,
    /// The name the providers know its algorithm by.
    pub internal_name: String,
    /// Its aliases in group lists.
    pub aliases: Vec<String>,
    /// The code point.
    pub id: u16,
    /// Its security in bits.
    pub security_bits: u32,
    /// The lowest TLS version it may be used with (0 for any), and the highest (0 for any;
    /// -1 for none, as for a group only DTLS may use).
    pub min_tls: i32,
    /// See `min_tls`.
    pub max_tls: i32,
    /// The DTLS versions, as OpenSSL numbers them (`DTLS1_VERSION` and so on).
    pub min_dtls: i32,
    /// See `min_dtls`.
    pub max_dtls: i32,
    /// Whether the group is a KEM: the server encapsulates rather than sending its own share.
    pub is_kem: bool,
}

/// A signature algorithm the providers offer (built in, or their `TLS-SIGALG` capability).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigalgInfo {
    /// The IANA name (`ecdsa_secp256r1_sha256`, `rsa_pss_rsae_sha256`, ...).
    pub name: String,
    /// The code point.
    pub id: u16,
    /// Its security in bits.
    pub security_bits: u32,
    /// The lowest and highest TLS versions it may be used with (0 for any).
    pub min_tls: i32,
    /// See `min_tls`.
    pub max_tls: i32,
}

/// A key share made for one group: the public value sent, and the secret derived once the
/// peer's share arrives.
pub trait KeyShare: Send {
    /// The encoded public value.
    fn public(&self) -> &[u8];
    /// The shared secret with the peer's encoded share (for a KEM, the server's ciphertext).
    ///
    /// # Errors
    /// The peer's share is invalid, or the provider failed.
    fn derive(self: Box<Self>, peer: &[u8]) -> Result<Secret>;
}

/// Secret octets, erased when dropped.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret(zeroize::Zeroizing<Vec<u8>>);

impl Secret {
    /// Takes `v` as secret.
    #[must_use]
    pub fn new(v: Vec<u8>) -> Self {
        Self(zeroize::Zeroizing::new(v))
    }

    /// The octets.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    /// How many octets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether it holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Secret({} octets)", self.0.len())
    }
}

/// The caller's handle for a private key (an `EVP_PKEY` in `rustyssl-capi`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyId(pub usize);

/// The cryptography of one connection.
pub trait Provider {
    /// A new hash.
    ///
    /// # Errors
    /// The algorithm isn't available.
    fn hash(&self, alg: HashAlg) -> Result<Box<dyn Hash>>;

    /// An HMAC keyed with `key`.
    ///
    /// # Errors
    /// The algorithm isn't available.
    fn hmac(&self, alg: HashAlg, key: &[u8]) -> Result<Box<dyn Mac>>;

    /// An AEAD keyed with `key`.
    ///
    /// # Errors
    /// The algorithm isn't available, or the key is wrong.
    fn aead(&self, alg: AeadAlg, key: &[u8]) -> Result<Box<dyn Aead>>;

    /// A CBC cipher keyed with `key`, encrypting or decrypting.
    ///
    /// # Errors
    /// The algorithm isn't available, or the key is wrong.
    fn cipher(&self, alg: CipherAlg, key: &[u8], encrypt: bool) -> Result<Box<dyn Cipher>>;

    /// The groups available, in the providers' order.
    fn groups(&self) -> Vec<GroupInfo>;

    /// The signature algorithms available beyond the built-in ones.
    fn sigalgs(&self) -> Vec<SigalgInfo>;

    /// A new key share for group `id` (for a KEM, the client's encapsulation key).
    ///
    /// # Errors
    /// The group isn't available.
    fn key_share(&self, id: u16) -> Result<Box<dyn KeyShare>>;

    /// The server's answer to the client's share for group `id`: its own share (for a KEM, the
    /// ciphertext) and the shared secret.
    ///
    /// # Errors
    /// The client's share is invalid, or the group isn't available.
    fn respond(&self, id: u16, peer: &[u8]) -> Result<(Vec<u8>, Secret)>;

    /// Fills `out` with random octets (`RAND_bytes_ex`, or `RAND_priv_bytes_ex` when `private`).
    ///
    /// # Errors
    /// The random generator failed.
    fn random(&self, out: &mut [u8], private: bool) -> Result<()>;

    /// Signs `msg` with key `key` under signature scheme `scheme` (an IANA code point; for TLS
    /// 1.1 and earlier, OpenSSL's MD5+SHA-1 RSA or SHA-1 ECDSA/DSA signatures are passed as the
    /// legacy pseudo-schemes in [`crate::consts`]).
    ///
    /// # Errors
    /// The key can't sign with that scheme, or the provider failed.
    fn sign(&self, key: KeyId, scheme: u16, msg: &[u8]) -> Result<Vec<u8>>;

    /// Whether `sig` is a valid signature of `msg` under `scheme` by the key of the certificate
    /// `cert` (its DER).
    ///
    /// # Errors
    /// The certificate's key doesn't fit the scheme, or the provider failed.
    fn verify(&self, cert: &[u8], scheme: u16, msg: &[u8], sig: &[u8]) -> Result<bool>;

    /// TLS 1.2's RSA key exchange, client side: the premaster secret encrypted with the server
    /// certificate's key (PKCS #1 v1.5).
    ///
    /// # Errors
    /// The certificate's key isn't RSA, or the provider failed.
    fn rsa_encrypt(&self, cert: &[u8], pms: &[u8]) -> Result<Vec<u8>>;

    /// TLS 1.2's RSA key exchange, server side: the premaster secret from the client's
    /// ciphertext, with implicit rejection (RFC 5246, section 7.4.7.1, and the Marvin lessons):
    /// any failure, including the wrong version in the first two octets, yields a random
    /// secret, decided in constant time. `client_version` is the version the ClientHello
    /// offered.
    ///
    /// # Errors
    /// The key isn't RSA, or the provider failed (not a padding failure, which is never seen).
    fn rsa_decrypt_pms(&self, key: KeyId, ciphertext: &[u8], client_version: u16)
    -> Result<Secret>;
}
