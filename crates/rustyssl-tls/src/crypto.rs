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
    /// The hash of everything added, ending the hash (`EVP_DigestFinal_ex` on the context
    /// itself, where [`Hash::current`] finishes a copy). A provider that holds a resource for a
    /// running hash, such as a PKCS#11 session's digest operation, sees it end.
    fn finish(self: Box<Self>) -> Vec<u8> {
        self.current()
    }
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

    /// Whether the cipher can process several records at once (OpenSSL's
    /// `EVP_CIPH_FLAG_PIPELINE`, which only an engine's ciphers have): with it, writes are split
    /// over pipelines and reads take several buffered records (`SSL_set_max_pipelines`).
    fn pipeline(&self) -> bool {
        false
    }
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
    /// The key type the providers implement it with (`EC`, `X25519`, `X448`, `DH`, `ML-KEM-768`,
    /// ...; the capability's `TLS_GROUP_ALG`): TLS 1.2's ECDHE only uses `EC`, `X25519`, and
    /// `X448` groups (`tls_valid_group`'s `isec`).
    pub algorithm: String,
}

/// A signature algorithm the providers offer (their `TLS-SIGALG` capability; the built-in ones
/// are in [`crate::conn::common::sigalgs`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigalgInfo {
    /// The IANA name (`mldsa65`, ...).
    pub name: String,
    /// The code point.
    pub id: u16,
    /// Its security in bits.
    pub security_bits: u32,
    /// The lowest and highest TLS versions it may be used with (0 for any).
    pub min_tls: i32,
    /// See `min_tls`.
    pub max_tls: i32,
    /// The key type it signs with (the capability's key type, or its signature or sigalg name:
    /// `inferred_keytype`), as [`KeyKind::Other`] names it.
    pub key_type: String,
    /// Its signature algorithm's NID (`OBJ_txt2nid` of the capability's sigalg name: what a
    /// certificate signed with it reports), or `NID_undef`.
    pub sig_nid: i32,
    /// Its hash's NID (the capability's hash name), or `NID_undef` for none.
    pub hash_nid: i32,
}

/// A public key's algorithm, as the signature-algorithm checks tell them apart
/// (`EVP_PKEY_get_id`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyKind {
    /// RSA (`rsaEncryption`).
    Rsa,
    /// RSA-PSS (`id-RSASSA-PSS` keys).
    RsaPss,
    /// DSA.
    Dsa,
    /// EC.
    Ec,
    /// Ed25519.
    Ed25519,
    /// Ed448.
    Ed448,
    /// A provider's key type, by name (`ML-DSA-65`, ...).
    Other(String),
}

/// What the signature checks need to know about a peer's key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerKey {
    /// The key's algorithm.
    pub kind: KeyKind,
    /// An EC key's curve as a NID (`ssl_get_EC_curve_nid`), or `NID_undef`.
    pub curve_nid: i32,
    /// The key's signature size in octets (`EVP_PKEY_get_size`).
    pub size: usize,
    /// Its security in bits (`EVP_PKEY_get_security_bits`).
    pub security_bits: i32,
    /// The certificate's key usage bits (`X509_get_key_usage`: all set without the
    /// extension, or for a raw public key).
    pub key_usage: u32,
}

/// A key share made for one group: the public value sent, and the secret derived once the
/// peer's share arrives.
pub trait KeyShare: Send {
    /// The encoded public value.
    fn public(&self) -> &[u8];
    /// The shared secret with the peer's encoded share (for a KEM, the server's ciphertext).
    /// Diffie-Hellman secrets come padded to the prime's length (TLS 1.3's form).
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

    /// TLS 1.0–1.2's MAC of a decrypted MAC-then-encrypt CBC record, in constant time: the HMAC
    /// keyed with `key` of the 13-octet `header` (sequence number, type, version, length) and
    /// the first `data_size` octets of `data`, where `data` is the record's plaintext with its
    /// MAC and padding (the public length) and `data_size` the length the padding gave (secret).
    /// The time taken depends on `data.len()` only (OpenSSL's `ssl3_cbc_digest_record`, which
    /// its HMAC computes when given `OSSL_MAC_PARAM_TLS_DATA_SIZE`).
    ///
    /// # Errors
    /// The hash isn't one the constant-time MAC supports, or the provider failed.
    fn tls_cbc_mac(
        &self,
        alg: HashAlg,
        key: &[u8],
        header: &[u8; 13],
        data: &[u8],
        data_size: usize,
    ) -> Result<Vec<u8>>;

    /// The groups available, in the providers' order.
    fn groups(&self) -> Vec<GroupInfo>;

    /// The signature algorithms available beyond the built-in ones.
    fn sigalgs(&self) -> Vec<SigalgInfo>;

    /// Whether the digest with NID `nid` can be fetched (`ssl_digest_methods`): a built-in
    /// signature algorithm whose hash can't is unavailable, and a TLS 1.0/1.1 handshake needs
    /// MD5-SHA1. Asking leaves no error behind.
    fn digest_available(&self, nid: i32) -> bool {
        let _ = nid;
        true
    }

    /// Whether a key manager of the key type `name` (`RSA`, `RSA-PSS`, `EC`, ...) can be
    /// fetched (`EVP_PKEY_CTX_new_from_pkey` of a key of that type): a built-in signature
    /// algorithm whose key type can't is unavailable. Asking leaves no error behind.
    fn keytype_available(&self, name: &str) -> bool {
        let _ = name;
        true
    }

    /// A new key share for group `id` (for a KEM, the client's encapsulation key).
    ///
    /// # Errors
    /// The group isn't available.
    fn key_share(&self, id: u16) -> Result<Box<dyn KeyShare>>;

    /// A Diffie-Hellman key share over explicit parameters (TLS 1.2's DHE, whose
    /// ServerKeyExchange carries the prime `p` and generator `g`, big-endian). The public value
    /// and the secret are padded to the prime's length; TLS 1.2 strips the secret's leading
    /// zeros itself (OpenSSL pads only for TLS 1.3).
    ///
    /// # Errors
    /// The parameters are unusable, or the provider failed.
    fn dh_share(&self, p: &[u8], g: &[u8]) -> Result<Box<dyn KeyShare>>;

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
    /// legacy schemes in [`crate::consts::sigscheme`]: `RSA_PKCS1_MD5_SHA1`, `ECDSA_SHA1`,
    /// `DSA_SHA1`).
    ///
    /// # Errors
    /// The key can't sign with that scheme, or the provider failed.
    fn sign(&self, key: KeyId, scheme: u16, msg: &[u8]) -> Result<Vec<u8>>;

    /// Whether `sig` is a valid signature of `msg` under `scheme` by the key of the certificate
    /// `cert` (its DER; for a raw public key (RFC 7250), the SubjectPublicKeyInfo's DER).
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

    /// The public key of a certificate (DER), or of a raw public key's SubjectPublicKeyInfo
    /// when `spki` is set.
    ///
    /// # Errors
    /// The encoding doesn't parse, or its key type isn't known.
    fn peer_key(&self, der: &[u8], spki: bool) -> Result<PeerKey>;

    /// Whether `der` decodes as an `OCSPResponse` (`d2i_OCSP_RESPONSE`), which 3.6's client
    /// requires of a stapled response.
    fn ocsp_response_ok(&self, der: &[u8]) -> bool {
        let _ = der;
        true
    }
}
