//! RSA as OpenSSL's built-in method computes it (`crypto/rsa/`): the four raw operations of
//! `rsa_ossl.c` (public and private encryption and decryption), the paddings they apply
//! (PKCS #1 v1.5 with implicit rejection, OAEP, PSS, X9.31, none), and PKCS #1 v1.5
//! signatures' DigestInfo (`rsa_sign.c`).
//!
//! The module is sans-IO: digests ([`Hash`]) and random octets come from the caller, which
//! fetches them as OpenSSL does (with a library context and properties). Failures are the
//! error entries OpenSSL leaves ([`Entry`]), in order; some are pushed whatever happens and
//! cleared, in constant time, when the operation succeeded, exactly as the reference's
//! `err_clear_last_constant_time` does.
//!
//! Secrets are handled in constant time: the private exponentiations (Montgomery, fixed
//! window, every table entry read), the reductions modulo the primes (bit by bit with masked
//! subtractions), the CRT recombination, blinding (every private operation), and the padding
//! checks of decryption (masks, never branches, on the decrypted octets).

mod ct;
mod digest_info;
mod key;
mod pad;
mod sign;
mod strength;

pub use digest_info::{digest_info, digest_size};
pub use key::{ExtraPrime, Key, MAX_PRIMES};
pub use pad::{
    PssSaltLen, add_none, add_oaep, add_pkcs1_type1, add_pkcs1_type2, add_pss, add_x931,
    check_none, check_oaep, check_pkcs1_type1, check_pkcs1_type2, check_pkcs1_type2_implicit,
    check_pkcs1_type2_tls, check_x931, mgf1, prf, verify_pss, x931_hash_id,
};
pub use sign::{sign, sign_octet_string, verify};
pub use strength::ifc_ffc_security_bits;

/// `OPENSSL_RSA_MAX_MODULUS_BITS`.
pub const MAX_MODULUS_BITS: usize = 16384;
/// `OPENSSL_RSA_SMALL_MODULUS_BITS`.
pub const SMALL_MODULUS_BITS: usize = 3072;
/// `OPENSSL_RSA_MAX_PUBEXP_BITS`.
pub const MAX_PUBEXP_BITS: usize = 64;
/// `RSA_PKCS1_PADDING_SIZE`.
pub const PKCS1_PADDING_SIZE: usize = 11;

/// A digest, as the caller fetched it: OAEP, PSS, MGF1, and implicit rejection's HMAC-SHA256
/// run over it.
pub trait Hash {
    /// The digest's size in octets (`EVP_MD_get_size`): 0 or less makes the paddings fail.
    fn size(&self) -> usize;
    /// The block size in octets, for HMAC.
    fn block_size(&self) -> usize;
    /// The digest of the parts' concatenation, or `None` if the digest failed.
    fn digest(&self, parts: &[&[u8]]) -> Option<Vec<u8>>;
}

/// The caller's random octets (`RAND_bytes_ex`): fills the buffer, or says it couldn't.
pub type Random<'a> = dyn FnMut(&mut [u8]) -> bool + 'a;

/// An error OpenSSL raises in RSA: an `RSA_R_*` reason, or an `ERR_R_*` one in the RSA
/// library.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    ModulusTooLarge,
    BadEValue,
    UnknownPaddingType,
    DataTooLargeForModulus,
    DataTooLargeForKeySize,
    DataTooSmallForKeySize,
    DataGreaterThanModLen,
    DataTooSmall,
    DataTooLarge,
    MissingPrivateKey,
    NoPublicExponent,
    PaddingCheckFailed,
    PkcsDecodingError,
    OaepDecodingError,
    InvalidPadding,
    BlockTypeIsNot01,
    BadFixedHeaderDecrypt,
    NullBeforeBlockMissing,
    BadPadByteCount,
    InvalidLength,
    KeySizeTooSmall,
    /// `RSA_R_SLEN_CHECK_FAILED`, with the "expected: %d retrieved: %d" data when verifying.
    SlenCheckFailed(Option<(i32, i32)>),
    FirstOctetInvalid,
    LastOctetInvalid,
    SlenRecoveryFailed,
    BadSignature,
    InvalidHeader,
    InvalidTrailer,
    WrongSignatureLength,
    InvalidMessageLength,
    InvalidDigestLength,
    UnknownAlgorithmType,
    AsnObjectNotKnownForMd,
    DigestTooBigForRsaKey,
    /// `ERR_R_INTERNAL_ERROR`.
    Internal,
    /// `ERR_R_FETCH_FAILED`: SHA-256 for implicit rejection couldn't be fetched.
    FetchFailed,
    /// `ERR_R_BN_LIB`.
    BnLib,
}

/// An error entry to raise: the OpenSSL function that raises it, its reason, and whether it
/// is then cleared (1) or left (0), chosen without a branch on secret data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub func: &'static str,
    pub reason: Reason,
    pub clear: u8,
}

impl Entry {
    /// An entry that stays.
    pub const fn raised(func: &'static str, reason: Reason) -> Self {
        Self {
            func,
            reason,
            clear: 0,
        }
    }
}

/// What an operation raised: the entries in order (OpenSSL's code paths push the same ones
/// whatever the secret data, so their number doesn't leak it).
pub type Raised = Vec<Entry>;

/// A failed operation's entries (`Err`) or a result with the entries it left (`Ok`).
pub type Outcome<T> = (Result<T, ()>, Raised);

/// A failure raising `reason` in `func`.
fn fail<T>(func: &'static str, reason: Reason) -> Outcome<T> {
    (Err(()), vec![Entry::raised(func, reason)])
}

/// A failure raising nothing.
fn silent<T>() -> Outcome<T> {
    (Err(()), Vec::new())
}

/// The padding modes (`RSA_*_PADDING`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Padding {
    Pkcs1,
    None,
    Oaep,
    X931,
    Pss,
    Pkcs1WithTls,
    Pkcs1NoImplicitReject,
    /// Any other number.
    Other(i32),
}

impl Padding {
    /// The mode for `RSA_*_PADDING`'s number.
    pub fn from_number(n: i32) -> Self {
        match n {
            1 => Self::Pkcs1,
            3 => Self::None,
            4 => Self::Oaep,
            5 => Self::X931,
            6 => Self::Pss,
            7 => Self::Pkcs1WithTls,
            8 => Self::Pkcs1NoImplicitReject,
            other => Self::Other(other),
        }
    }

    /// The mode's number.
    pub fn number(self) -> i32 {
        match self {
            Self::Pkcs1 => 1,
            Self::None => 3,
            Self::Oaep => 4,
            Self::X931 => 5,
            Self::Pss => 6,
            Self::Pkcs1WithTls => 7,
            Self::Pkcs1NoImplicitReject => 8,
            Self::Other(n) => n,
        }
    }
}

#[cfg(test)]
mod tests;
