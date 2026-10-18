//! Signature algorithms (`t1_lib.c`): OpenSSL's table (`sigalg_lookup_tbl`, plus the
//! providers' `TLS-SIGALG` capabilities), the lists each end sends, the shared list, the
//! checks on the peer's choice, and the selection of this end's scheme and certificate
//! (`tls_choose_sigalg`).

use core::ffi::c_int;

use rustyssl_abi as abi;

use super::groups;
use super::security::{self, SecOther};
use super::version;
use crate::conn::Connection;
use crate::consts::sigscheme as s;
use crate::crypto::{KeyKind, PeerKey, Provider};
use crate::error::{Error, InFunc, Result};
use crate::suites::masks::{
    SSL_MD_GOST12_256_IDX, SSL_MD_GOST12_512_IDX, SSL_MD_GOST94_IDX, SSL_MD_MD5_IDX,
    SSL_MD_MD5_SHA1_IDX, SSL_MD_SHA1_IDX, SSL_MD_SHA224_IDX, SSL_MD_SHA256_IDX, SSL_MD_SHA384_IDX,
    SSL_MD_SHA512_IDX, SSL_aCERT, SSL_aDSS, SSL_aECDSA, SSL_aGOST01, SSL_aGOST12, SSL_aRSA,
    SSL_kRSA,
};

/// `SSL_PKEY_RSA`: OpenSSL's certificate slots (`ssl_local.h`).
pub const PKEY_RSA: usize = 0;
/// `SSL_PKEY_RSA_PSS_SIGN`.
pub const PKEY_RSA_PSS_SIGN: usize = 1;
/// `SSL_PKEY_DSA_SIGN`.
pub const PKEY_DSA_SIGN: usize = 2;
/// `SSL_PKEY_ECC`.
pub const PKEY_ECC: usize = 3;
/// `SSL_PKEY_GOST01`.
pub const PKEY_GOST01: usize = 4;
/// `SSL_PKEY_GOST12_256`.
pub const PKEY_GOST12_256: usize = 5;
/// `SSL_PKEY_GOST12_512`.
pub const PKEY_GOST12_512: usize = 6;
/// `SSL_PKEY_ED25519`.
pub const PKEY_ED25519: usize = 7;
/// `SSL_PKEY_ED448`.
pub const PKEY_ED448: usize = 8;
/// `SSL_PKEY_NUM`: providers' key types take the slots from here on, in their order.
pub const PKEY_NUM: usize = 9;

pub use crate::consts::sigscheme::RSA_PKCS1_MD5_SHA1;

/// The key type a slot holds (`ssl_cert_info`), and the authentication it serves.
#[must_use]
pub fn slot_amask(slot: usize) -> u32 {
    match slot {
        PKEY_RSA | PKEY_RSA_PSS_SIGN => SSL_aRSA,
        PKEY_DSA_SIGN => SSL_aDSS,
        PKEY_ECC | PKEY_ED25519 | PKEY_ED448 => SSL_aECDSA,
        PKEY_GOST01 => SSL_aGOST01,
        PKEY_GOST12_256 | PKEY_GOST12_512 => SSL_aGOST12,
        _ => 0,
    }
}

/// A key kind's slot (`ssl_cert_lookup_by_pkey`): an RSA-PSS key has its own slot; a
/// provider's key type its slot after the built-in ones.
#[must_use]
pub fn slot_of(c: &Connection, kind: &KeyKind) -> Option<usize> {
    match kind {
        KeyKind::Rsa => Some(PKEY_RSA),
        KeyKind::RsaPss => Some(PKEY_RSA_PSS_SIGN),
        KeyKind::Dsa => Some(PKEY_DSA_SIGN),
        KeyKind::Ec => Some(PKEY_ECC),
        KeyKind::Ed25519 => Some(PKEY_ED25519),
        KeyKind::Ed448 => Some(PKEY_ED448),
        KeyKind::Other(name) => c.hs.sh.sigalgs.provider_slot(name),
    }
}

/// The signature type of a [`SigAlg`] (`lu->sig`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sig {
    /// `EVP_PKEY_RSA` (PKCS #1 v1.5).
    Rsa,
    /// `EVP_PKEY_RSA_PSS`.
    RsaPss,
    /// `EVP_PKEY_DSA`.
    Dsa,
    /// `EVP_PKEY_EC`.
    Ec,
    /// `EVP_PKEY_ED25519`.
    Ed25519,
    /// `EVP_PKEY_ED448`.
    Ed448,
    /// A GOST type (never available in the default build).
    Gost,
    /// A provider's signature algorithm, by its key type.
    Other(String),
}

impl Sig {
    /// Whether a peer key of `kind` fits this signature type (`pkeyid != lu->sig` with RSA keys
    /// allowed for RSA-PSS).
    fn fits(&self, kind: &KeyKind) -> bool {
        matches!(
            (self, kind),
            (Self::Rsa, KeyKind::Rsa)
                | (Self::RsaPss, KeyKind::RsaPss | KeyKind::Rsa)
                | (Self::Dsa, KeyKind::Dsa)
                | (Self::Ec, KeyKind::Ec)
                | (Self::Ed25519, KeyKind::Ed25519)
                | (Self::Ed448, KeyKind::Ed448)
        ) || matches!((self, kind), (Self::Other(a), KeyKind::Other(b)) if a.eq_ignore_ascii_case(b))
    }
}

/// A signature algorithm (`SIGALG_LOOKUP`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigAlg {
    /// The IANA name (`SSL_get_sigalgs` and the sigalgs lists).
    pub name: std::borrow::Cow<'static, str>,
    /// OpenSSL's TLS 1.2-style name (`RSA+SHA256`), if it has one.
    pub name12: Option<&'static str>,
    /// The code point.
    pub sigalg: u16,
    /// The hash's NID (`NID_undef` for none: EdDSA, ML-DSA).
    pub hash: c_int,
    /// The hash's index in OpenSSL's digest table, or -1.
    pub hash_idx: i32,
    /// The signature type.
    pub sig: Sig,
    /// The certificate slot it signs with.
    pub sig_idx: usize,
    /// The combined signature-and-hash NID (`NID_ecdsa_with_SHA256`, ...), or `NID_undef`.
    pub sigandhash: c_int,
    /// The curve an ECDSA scheme requires (TLS 1.3), or `NID_undef`.
    pub curve: c_int,
    /// The TLS versions it may be used with (0: any; -1: none).
    pub mintls: c_int,
    /// See `mintls`.
    pub maxtls: c_int,
    /// The DTLS versions it may be used with (0: any; -1: none).
    pub mindtls: c_int,
    /// See `mindtls`.
    pub maxdtls: c_int,
    /// Whether the providers can do it (`available`).
    pub available: bool,
    /// The security bits a provider gave it (0: from the hash).
    pub provider_bits: u32,
}

/// One built-in entry.
#[allow(clippy::too_many_arguments, reason = "the table's columns")]
const fn e(
    name: &'static str,
    name12: Option<&'static str>,
    sigalg: u16,
    hash: c_int,
    hash_idx: i32,
    sig: SigKindConst,
    sig_idx: usize,
    sigandhash: c_int,
    curve: c_int,
    mintls: c_int,
    maxtls: c_int,
) -> BuiltIn {
    BuiltIn {
        name,
        name12,
        sigalg,
        hash,
        hash_idx,
        sig,
        sig_idx,
        sigandhash,
        curve,
        mintls,
        maxtls,
    }
}

/// [`Sig`] for the const table.
#[derive(Clone, Copy)]
enum SigKindConst {
    Rsa,
    RsaPss,
    Dsa,
    Ec,
    Ed25519,
    Ed448,
    Gost,
}

/// A built-in table row.
struct BuiltIn {
    name: &'static str,
    name12: Option<&'static str>,
    sigalg: u16,
    hash: c_int,
    hash_idx: i32,
    sig: SigKindConst,
    sig_idx: usize,
    sigandhash: c_int,
    curve: c_int,
    mintls: c_int,
    maxtls: c_int,
}

/// A digest index as `i32`.
const fn ix(v: u32) -> i32 {
    #[expect(clippy::cast_possible_wrap, reason = "the indices are below 16")]
    let r = v as i32;
    r
}

const T12: c_int = abi::TLS1_2_VERSION;
const T13: c_int = abi::TLS1_3_VERSION;

/// `sigalg_lookup_tbl`, in its order.
const BUILTIN: [BuiltIn; 32] = [
    e(
        "ecdsa_secp256r1_sha256",
        Some("ECDSA+SHA256"),
        s::ECDSA_SECP256R1_SHA256,
        abi::NID_sha256,
        ix(SSL_MD_SHA256_IDX),
        SigKindConst::Ec,
        PKEY_ECC,
        abi::NID_ecdsa_with_SHA256,
        abi::NID_X9_62_prime256v1,
        T12,
        0,
    ),
    e(
        "ecdsa_secp384r1_sha384",
        Some("ECDSA+SHA384"),
        s::ECDSA_SECP384R1_SHA384,
        abi::NID_sha384,
        ix(SSL_MD_SHA384_IDX),
        SigKindConst::Ec,
        PKEY_ECC,
        abi::NID_ecdsa_with_SHA384,
        abi::NID_secp384r1,
        T12,
        0,
    ),
    e(
        "ecdsa_secp521r1_sha512",
        Some("ECDSA+SHA512"),
        s::ECDSA_SECP521R1_SHA512,
        abi::NID_sha512,
        ix(SSL_MD_SHA512_IDX),
        SigKindConst::Ec,
        PKEY_ECC,
        abi::NID_ecdsa_with_SHA512,
        abi::NID_secp521r1,
        T12,
        0,
    ),
    e(
        "ed25519",
        None,
        s::ED25519,
        abi::NID_undef,
        -1,
        SigKindConst::Ed25519,
        PKEY_ED25519,
        abi::NID_undef,
        abi::NID_undef,
        T12,
        0,
    ),
    e(
        "ed448",
        None,
        s::ED448,
        abi::NID_undef,
        -1,
        SigKindConst::Ed448,
        PKEY_ED448,
        abi::NID_undef,
        abi::NID_undef,
        T12,
        0,
    ),
    e(
        "ecdsa_sha224",
        Some("ECDSA+SHA224"),
        s::ECDSA_SHA224,
        abi::NID_sha224,
        ix(SSL_MD_SHA224_IDX),
        SigKindConst::Ec,
        PKEY_ECC,
        abi::NID_ecdsa_with_SHA224,
        abi::NID_undef,
        T12,
        T12,
    ),
    e(
        "ecdsa_sha1",
        Some("ECDSA+SHA1"),
        s::ECDSA_SHA1,
        abi::NID_sha1,
        ix(SSL_MD_SHA1_IDX),
        SigKindConst::Ec,
        PKEY_ECC,
        abi::NID_ecdsa_with_SHA1,
        abi::NID_undef,
        T12,
        T12,
    ),
    e(
        "ecdsa_brainpoolP256r1tls13_sha256",
        Some("ecdsa_brainpoolP256r1_sha256"),
        s::ECDSA_BRAINPOOLP256R1_SHA256,
        abi::NID_sha256,
        ix(SSL_MD_SHA256_IDX),
        SigKindConst::Ec,
        PKEY_ECC,
        abi::NID_ecdsa_with_SHA256,
        abi::NID_brainpoolP256r1,
        T13,
        0,
    ),
    e(
        "ecdsa_brainpoolP384r1tls13_sha384",
        Some("ecdsa_brainpoolP384r1_sha384"),
        s::ECDSA_BRAINPOOLP384R1_SHA384,
        abi::NID_sha384,
        ix(SSL_MD_SHA384_IDX),
        SigKindConst::Ec,
        PKEY_ECC,
        abi::NID_ecdsa_with_SHA384,
        abi::NID_brainpoolP384r1,
        T13,
        0,
    ),
    e(
        "ecdsa_brainpoolP512r1tls13_sha512",
        Some("ecdsa_brainpoolP512r1_sha512"),
        s::ECDSA_BRAINPOOLP512R1_SHA512,
        abi::NID_sha512,
        ix(SSL_MD_SHA512_IDX),
        SigKindConst::Ec,
        PKEY_ECC,
        abi::NID_ecdsa_with_SHA512,
        abi::NID_brainpoolP512r1,
        T13,
        0,
    ),
    e(
        "rsa_pss_rsae_sha256",
        Some("PSS+SHA256"),
        s::RSA_PSS_RSAE_SHA256,
        abi::NID_sha256,
        ix(SSL_MD_SHA256_IDX),
        SigKindConst::RsaPss,
        PKEY_RSA,
        abi::NID_undef,
        abi::NID_undef,
        T12,
        0,
    ),
    e(
        "rsa_pss_rsae_sha384",
        Some("PSS+SHA384"),
        s::RSA_PSS_RSAE_SHA384,
        abi::NID_sha384,
        ix(SSL_MD_SHA384_IDX),
        SigKindConst::RsaPss,
        PKEY_RSA,
        abi::NID_undef,
        abi::NID_undef,
        T12,
        0,
    ),
    e(
        "rsa_pss_rsae_sha512",
        Some("PSS+SHA512"),
        s::RSA_PSS_RSAE_SHA512,
        abi::NID_sha512,
        ix(SSL_MD_SHA512_IDX),
        SigKindConst::RsaPss,
        PKEY_RSA,
        abi::NID_undef,
        abi::NID_undef,
        T12,
        0,
    ),
    e(
        "rsa_pss_pss_sha256",
        None,
        s::RSA_PSS_PSS_SHA256,
        abi::NID_sha256,
        ix(SSL_MD_SHA256_IDX),
        SigKindConst::RsaPss,
        PKEY_RSA_PSS_SIGN,
        abi::NID_undef,
        abi::NID_undef,
        T12,
        0,
    ),
    e(
        "rsa_pss_pss_sha384",
        None,
        s::RSA_PSS_PSS_SHA384,
        abi::NID_sha384,
        ix(SSL_MD_SHA384_IDX),
        SigKindConst::RsaPss,
        PKEY_RSA_PSS_SIGN,
        abi::NID_undef,
        abi::NID_undef,
        T12,
        0,
    ),
    e(
        "rsa_pss_pss_sha512",
        None,
        s::RSA_PSS_PSS_SHA512,
        abi::NID_sha512,
        ix(SSL_MD_SHA512_IDX),
        SigKindConst::RsaPss,
        PKEY_RSA_PSS_SIGN,
        abi::NID_undef,
        abi::NID_undef,
        T12,
        0,
    ),
    e(
        "rsa_pkcs1_sha256",
        Some("RSA+SHA256"),
        s::RSA_PKCS1_SHA256,
        abi::NID_sha256,
        ix(SSL_MD_SHA256_IDX),
        SigKindConst::Rsa,
        PKEY_RSA,
        abi::NID_sha256WithRSAEncryption,
        abi::NID_undef,
        T12,
        0,
    ),
    e(
        "rsa_pkcs1_sha384",
        Some("RSA+SHA384"),
        s::RSA_PKCS1_SHA384,
        abi::NID_sha384,
        ix(SSL_MD_SHA384_IDX),
        SigKindConst::Rsa,
        PKEY_RSA,
        abi::NID_sha384WithRSAEncryption,
        abi::NID_undef,
        T12,
        0,
    ),
    e(
        "rsa_pkcs1_sha512",
        Some("RSA+SHA512"),
        s::RSA_PKCS1_SHA512,
        abi::NID_sha512,
        ix(SSL_MD_SHA512_IDX),
        SigKindConst::Rsa,
        PKEY_RSA,
        abi::NID_sha512WithRSAEncryption,
        abi::NID_undef,
        T12,
        0,
    ),
    e(
        "rsa_pkcs1_sha224",
        Some("RSA+SHA224"),
        s::RSA_PKCS1_SHA224,
        abi::NID_sha224,
        ix(SSL_MD_SHA224_IDX),
        SigKindConst::Rsa,
        PKEY_RSA,
        abi::NID_sha224WithRSAEncryption,
        abi::NID_undef,
        T12,
        T12,
    ),
    e(
        "rsa_pkcs1_sha1",
        Some("RSA+SHA1"),
        s::RSA_PKCS1_SHA1,
        abi::NID_sha1,
        ix(SSL_MD_SHA1_IDX),
        SigKindConst::Rsa,
        PKEY_RSA,
        abi::NID_sha1WithRSAEncryption,
        abi::NID_undef,
        T12,
        T12,
    ),
    e(
        "dsa_sha256",
        Some("DSA+SHA256"),
        s::DSA_SHA256,
        abi::NID_sha256,
        ix(SSL_MD_SHA256_IDX),
        SigKindConst::Dsa,
        PKEY_DSA_SIGN,
        abi::NID_dsa_with_SHA256,
        abi::NID_undef,
        T12,
        T12,
    ),
    e(
        "dsa_sha384",
        Some("DSA+SHA384"),
        s::DSA_SHA384,
        abi::NID_sha384,
        ix(SSL_MD_SHA384_IDX),
        SigKindConst::Dsa,
        PKEY_DSA_SIGN,
        abi::NID_undef,
        abi::NID_undef,
        T12,
        T12,
    ),
    e(
        "dsa_sha512",
        Some("DSA+SHA512"),
        s::DSA_SHA512,
        abi::NID_sha512,
        ix(SSL_MD_SHA512_IDX),
        SigKindConst::Dsa,
        PKEY_DSA_SIGN,
        abi::NID_undef,
        abi::NID_undef,
        T12,
        T12,
    ),
    e(
        "dsa_sha224",
        Some("DSA+SHA224"),
        s::DSA_SHA224,
        abi::NID_sha224,
        ix(SSL_MD_SHA224_IDX),
        SigKindConst::Dsa,
        PKEY_DSA_SIGN,
        abi::NID_undef,
        abi::NID_undef,
        T12,
        T12,
    ),
    e(
        "dsa_sha1",
        Some("DSA+SHA1"),
        s::DSA_SHA1,
        abi::NID_sha1,
        ix(SSL_MD_SHA1_IDX),
        SigKindConst::Dsa,
        PKEY_DSA_SIGN,
        abi::NID_dsaWithSHA1,
        abi::NID_undef,
        T12,
        T12,
    ),
    e(
        "gost2012_256",
        Some("gostr34102012_256"),
        s::GOSTR34102012_256_INTRINSIC,
        abi::NID_id_GostR3411_2012_256,
        ix(SSL_MD_GOST12_256_IDX),
        SigKindConst::Gost,
        PKEY_GOST12_256,
        abi::NID_undef,
        abi::NID_undef,
        T12,
        T12,
    ),
    e(
        "gost2012_256",
        Some("gostr34102012_256"),
        s::GOSTR34102012_512_INTRINSIC,
        abi::NID_id_GostR3411_2012_512,
        ix(SSL_MD_GOST12_512_IDX),
        SigKindConst::Gost,
        PKEY_GOST12_512,
        abi::NID_undef,
        abi::NID_undef,
        T12,
        T12,
    ),
    e(
        "gost2012_256",
        None,
        s::GOSTR34102012_256_GOSTR34112012_256,
        abi::NID_id_GostR3411_2012_256,
        ix(SSL_MD_GOST12_256_IDX),
        SigKindConst::Gost,
        PKEY_GOST12_256,
        abi::NID_undef,
        abi::NID_undef,
        T12,
        T12,
    ),
    e(
        "gost2012_512",
        None,
        s::GOSTR34102012_512_GOSTR34112012_512,
        abi::NID_id_GostR3411_2012_512,
        ix(SSL_MD_GOST12_512_IDX),
        SigKindConst::Gost,
        PKEY_GOST12_512,
        abi::NID_undef,
        abi::NID_undef,
        T12,
        T12,
    ),
    e(
        "gost2001_gost94",
        None,
        s::GOSTR34102001_GOSTR3411,
        abi::NID_id_GostR3411_94,
        ix(SSL_MD_GOST94_IDX),
        SigKindConst::Gost,
        PKEY_GOST01,
        abi::NID_undef,
        abi::NID_undef,
        T12,
        T12,
    ),
    // `legacy_rsa_sigalg`, under its pseudo code point.
    e(
        "rsa_pkcs1_md5_sha1",
        None,
        RSA_PKCS1_MD5_SHA1,
        abi::NID_md5_sha1,
        ix(SSL_MD_MD5_SHA1_IDX),
        SigKindConst::Rsa,
        PKEY_RSA,
        abi::NID_undef,
        abi::NID_undef,
        abi::TLS1_VERSION,
        T12,
    ),
];

/// The default list (`tls12_sigalgs`), before the providers' additions.
const DEFAULT: [u16; 34] = [
    s::MLDSA65,
    s::MLDSA87,
    s::MLDSA44,
    s::ECDSA_SECP256R1_SHA256,
    s::ECDSA_SECP384R1_SHA384,
    s::ECDSA_SECP521R1_SHA512,
    s::ED25519,
    s::ED448,
    s::ECDSA_BRAINPOOLP256R1_SHA256,
    s::ECDSA_BRAINPOOLP384R1_SHA384,
    s::ECDSA_BRAINPOOLP512R1_SHA512,
    s::RSA_PSS_PSS_SHA256,
    s::RSA_PSS_PSS_SHA384,
    s::RSA_PSS_PSS_SHA512,
    s::RSA_PSS_RSAE_SHA256,
    s::RSA_PSS_RSAE_SHA384,
    s::RSA_PSS_RSAE_SHA512,
    s::RSA_PKCS1_SHA256,
    s::RSA_PKCS1_SHA384,
    s::RSA_PKCS1_SHA512,
    s::ECDSA_SHA224,
    s::ECDSA_SHA1,
    s::RSA_PKCS1_SHA224,
    s::RSA_PKCS1_SHA1,
    s::DSA_SHA224,
    s::DSA_SHA1,
    s::DSA_SHA256,
    s::DSA_SHA384,
    s::DSA_SHA512,
    s::GOSTR34102012_256_INTRINSIC,
    s::GOSTR34102012_512_INTRINSIC,
    s::GOSTR34102012_256_GOSTR34112012_256,
    s::GOSTR34102012_512_GOSTR34112012_512,
    s::GOSTR34102001_GOSTR3411,
];

/// Suite B's schemes (`suiteb_sigalgs`).
const SUITEB: [u16; 2] = [s::ECDSA_SECP256R1_SHA256, s::ECDSA_SECP384R1_SHA384];

/// The default scheme of each built-in slot when the peer sent no signature_algorithms
/// (`tls_default_sigalg`, RFC 5246); 0 for none.
const LEGACY_DEFAULT: [u16; PKEY_NUM] = [
    s::RSA_PKCS1_SHA1,
    0,
    s::DSA_SHA1,
    s::ECDSA_SHA1,
    s::GOSTR34102001_GOSTR3411,
    s::GOSTR34102012_256_INTRINSIC,
    s::GOSTR34102012_512_INTRINSIC,
    0,
    0,
];

/// The connection's table: the built-in algorithms and the providers' (`sigalg_lookup_cache`),
/// and the default list (`ctx->tls12_sigalgs`).
#[derive(Clone, Debug, Default)]
pub struct Cache {
    /// Every algorithm, built-in first.
    pub table: Vec<SigAlg>,
    /// The default list, in order: the built-in defaults available, then the providers' others.
    pub defaults: Vec<u16>,
    /// The providers' key types, in slot order from [`PKEY_NUM`].
    pub provider_key_types: Vec<String>,
}

impl Cache {
    /// The table for the provider's algorithms (`ssl_setup_sigalgs`). The built-in ones are
    /// available except GOST (no GOST provider in the default build); the providers' ones are
    /// TLS 1.3 only.
    #[must_use]
    pub fn new(p: &dyn Provider) -> Self {
        let mut table: Vec<SigAlg> = BUILTIN
            .iter()
            .map(|b| SigAlg {
                name: std::borrow::Cow::Borrowed(b.name),
                name12: b.name12,
                sigalg: b.sigalg,
                hash: b.hash,
                hash_idx: b.hash_idx,
                sig: match b.sig {
                    SigKindConst::Rsa => Sig::Rsa,
                    SigKindConst::RsaPss => Sig::RsaPss,
                    SigKindConst::Dsa => Sig::Dsa,
                    SigKindConst::Ec => Sig::Ec,
                    SigKindConst::Ed25519 => Sig::Ed25519,
                    SigKindConst::Ed448 => Sig::Ed448,
                    SigKindConst::Gost => Sig::Gost,
                },
                sig_idx: b.sig_idx,
                sigandhash: b.sigandhash,
                curve: b.curve,
                mintls: b.mintls,
                maxtls: b.maxtls,
                mindtls: dtls_of(b.mintls),
                maxdtls: dtls_of(b.maxtls),
                available: !matches!(b.sig, SigKindConst::Gost),
                provider_bits: 0,
            })
            .collect();
        let mut provider_key_types = Vec::new();
        let builtin_len = table.len();
        for info in p.sigalgs() {
            // Provider algorithms are TLS 1.3 only: one whose range leaves TLS 1.3 out (or
            // that is unusable, -1) is skipped.
            let (mintls, maxtls) = (info.min_tls, info.max_tls);
            if mintls == -1
                || (mintls != 0 && mintls > T13)
                || (maxtls != 0 && maxtls != -1 && maxtls < T13)
            {
                continue;
            }
            let slot = match provider_key_types
                .iter()
                .position(|k: &String| k.eq_ignore_ascii_case(&info.key_type))
            {
                Some(i) => PKEY_NUM.saturating_add(i),
                None => {
                    provider_key_types.push(info.key_type.clone());
                    PKEY_NUM.saturating_add(provider_key_types.len().saturating_sub(1))
                }
            };
            // `ssl_get_md_idx` of the hash: a built-in algorithm's index for the same hash.
            let hash_idx = BUILTIN
                .iter()
                .find(|b| info.hash_nid != abi::NID_undef && b.hash == info.hash_nid)
                .map_or(-1, |b| b.hash_idx);
            table.push(SigAlg {
                name: std::borrow::Cow::Owned(info.name.clone()),
                name12: None,
                sigalg: info.id,
                hash: info.hash_nid,
                hash_idx,
                sig: Sig::Other(info.key_type),
                sig_idx: slot,
                sigandhash: info.sig_nid,
                curve: abi::NID_undef,
                mintls: T13,
                maxtls: T13,
                // Provider algorithms are TLS 1.3 only, so never DTLS 1.2.
                mindtls: -1,
                maxdtls: -1,
                available: true,
                provider_bits: info.security_bits,
            });
        }
        let mut defaults = Vec::new();
        for d in DEFAULT {
            if let Some(lu) = table.iter().find(|l| l.sigalg == d)
                && lu.available
                && !defaults.contains(&d)
            {
                defaults.push(d);
            }
        }
        for lu in table.iter().skip(builtin_len) {
            if lu.available && !defaults.contains(&lu.sigalg) {
                defaults.push(lu.sigalg);
            }
        }
        Self {
            table,
            defaults,
            provider_key_types,
        }
    }

    /// `tls1_lookup_sigalg`: an available algorithm by code point.
    #[must_use]
    pub fn lookup(&self, code: u16) -> Option<&SigAlg> {
        self.table
            .iter()
            .find(|l| l.sigalg == code)
            .filter(|l| l.available)
    }

    /// The slot of a provider's key type.
    #[must_use]
    pub fn provider_slot(&self, key_type: &str) -> Option<usize> {
        self.provider_key_types
            .iter()
            .position(|k| k.eq_ignore_ascii_case(key_type))
            .map(|i| PKEY_NUM.saturating_add(i))
    }
}

/// `SSL_USE_SIGALGS`: TLS 1.2 and later carry signature algorithms.
#[must_use]
pub fn use_sigalgs(c: &Connection) -> bool {
    version::tls_level(c.neg.version) >= version::of(abi::TLS1_2_VERSION)
}

/// `sigalg_security_bits`: half the hash's bits (SHA-1 64, MD5+SHA-1 67, MD5 39), EdDSA's
/// RFC 8032 values, or the provider's number.
#[must_use]
pub fn security_bits(lu: &SigAlg) -> c_int {
    let by_hash = if lu.hash == abi::NID_sha1 {
        64
    } else if lu.hash == abi::NID_md5_sha1 {
        67
    } else if lu.hash == abi::NID_md5 {
        39
    } else if lu.hash == abi::NID_sha224 {
        112
    } else if lu.hash == abi::NID_sha256 {
        128
    } else if lu.hash == abi::NID_sha384 {
        192
    } else if lu.hash == abi::NID_sha512 {
        256
    } else if lu.hash == abi::NID_id_GostR3411_2012_256 || lu.hash == abi::NID_id_GostR3411_94 {
        128
    } else if lu.hash == abi::NID_id_GostR3411_2012_512 {
        256
    } else if lu.sigalg == s::ED25519 {
        128
    } else if lu.sigalg == s::ED448 {
        224
    } else {
        0
    };
    if by_hash == 0 {
        c_int::try_from(lu.provider_bits).unwrap_or(0)
    } else {
        by_hash
    }
}

/// `tls12_sigalg_allowed`: whether `lu` may be used now for `op`.
#[must_use]
pub fn allowed(c: &Connection, op: c_int, lu: &SigAlg) -> bool {
    if !lu.available {
        return false;
    }
    if c.is_tls13() && lu.sig == Sig::Dsa {
        return false;
    }
    if !c.cfg.server
        && !c.cfg.dtls
        && c.hs.sh.min_ver >= version::of(T13)
        && (lu.sig == Sig::Dsa
            || lu.hash_idx == ix(SSL_MD_SHA1_IDX)
            || lu.hash_idx == ix(SSL_MD_MD5_IDX)
            || lu.hash_idx == ix(SSL_MD_SHA224_IDX))
    {
        return false;
    }
    if lu.sig == Sig::Gost {
        // GOST is never available here; OpenSSL's further rules don't come into play.
        return false;
    }
    let bits = security_bits(lu);
    security::check(
        c,
        op,
        bits,
        lu.hash,
        SecOther::CodePoint(lu.sigalg.to_be_bytes()),
    )
}

/// The built-in table's DTLS column from its TLS column: TLS 1.2 (or any) is DTLS 1.2 (or
/// any), and the TLS 1.3-only schemes have no DTLS (`sigalg_lookup_tbl`).
const fn dtls_of(tls: c_int) -> c_int {
    match tls {
        0 => 0,
        abi::TLS1_2_VERSION => abi::DTLS1_2_VERSION,
        _ => -1,
    }
}

/// `tls_sigalg_compat`: whether `lu` fits the versions this end may negotiate.
#[must_use]
pub fn compat(c: &Connection, lu: &SigAlg) -> bool {
    if !lu.available {
        return false;
    }
    let (minproto, maxproto) = if c.cfg.method_version == version::ANY {
        (
            c_int::from(c.cfg.min_version),
            c_int::from(c.cfg.max_version),
        )
    } else {
        (c_int::from(c.neg.version), c_int::from(c.neg.version))
    };
    let (minv, maxv) = if c.cfg.dtls {
        (lu.mindtls, lu.maxdtls)
    } else {
        (lu.mintls, lu.maxtls)
    };
    let vc = super::ciphers::vcmp;
    !(minv == -1
        || maxv == -1
        || (minv != 0 && maxproto != 0 && vc(minv, maxproto).is_gt())
        || (maxv != 0 && minproto != 0 && vc(maxv, minproto).is_lt())
        || !allowed(c, abi::SSL_SECOP_SIGALG_SUPPORTED, lu))
}

/// `tls12_get_psigalgs`: this end's list. `sent`: the list this end sends (a server's
/// CertificateRequest uses the client sigalgs, if set); otherwise the list it signs from.
#[must_use]
pub fn psigalgs(c: &Connection, sent: bool) -> Vec<u16> {
    let sb = version::suiteb(c);
    if sb == u32::try_from(abi::SSL_CERT_FLAG_SUITEB_128_LOS).unwrap_or(0) {
        return SUITEB.to_vec();
    }
    if sb == u32::try_from(abi::SSL_CERT_FLAG_SUITEB_128_LOS_ONLY).unwrap_or(0) {
        return SUITEB.get(..1).unwrap_or_default().to_vec();
    }
    if sb == u32::try_from(abi::SSL_CERT_FLAG_SUITEB_192_LOS).unwrap_or(0) {
        return SUITEB.get(1..).unwrap_or_default().to_vec();
    }
    if c.cfg.server == sent && !c.cfg.client_sigalgs.is_empty() {
        c.cfg.client_sigalgs.clone()
    } else if !c.cfg.sigalgs.is_empty() {
        c.cfg.sigalgs.clone()
    } else {
        c.hs.sh.sigalgs.defaults.clone()
    }
}

/// `tls12_copy_sigalgs`: the list for a signature_algorithms extension: the compatible ones
/// of `list`. In TLS 1.3 at least one must be usable for TLS 1.3 signatures.
///
/// # Errors
/// None usable: `SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM`, raised without an alert (the caller
/// decides).
pub fn copy_sigalgs(c: &Connection, list: &[u16]) -> Result<Vec<u16>> {
    copy_sigalgs_inner(c, list).in_func("tls12_copy_sigalgs")
}

/// See [`copy_sigalgs`].
fn copy_sigalgs_inner(c: &Connection, list: &[u16]) -> Result<Vec<u16>> {
    let mut out = Vec::new();
    let mut ok = false;
    for &code in list {
        let Some(lu) = c.hs.sh.sigalgs.lookup(code) else {
            continue;
        };
        if !compat(c, lu) {
            continue;
        }
        out.push(code);
        if !ok
            && (!c.is_tls13()
                || (lu.sig != Sig::Rsa && lu.hash != abi::NID_sha1 && lu.hash != abi::NID_sha224))
        {
            ok = true;
        }
    }
    if ok {
        Ok(out)
    } else {
        Err(Error::quiet(abi::SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM))
    }
}

/// `tls1_check_sigalg_curve` (`tls_check_sigalg_curve`, servers): whether this end's list
/// has an ECDSA scheme for `curve`.
#[must_use]
pub fn check_sigalg_curve(c: &Connection, curve: c_int) -> bool {
    let list = if c.cfg.sigalgs.is_empty() {
        &c.hs.sh.sigalgs.defaults
    } else {
        &c.cfg.sigalgs
    };
    list.iter()
        .filter_map(|&x| c.hs.sh.sigalgs.lookup(x))
        .any(|lu| lu.sig == Sig::Ec && lu.curve != abi::NID_undef && lu.curve == curve)
}

/// `tls1_save_sigalgs`: keeps the peer's signature_algorithms (or, with `cert`, its
/// signature_algorithms_cert); ignored below TLS 1.2. `false` for an empty or odd list.
#[must_use]
pub fn save(c: &mut Connection, body: &[u8], cert: bool) -> bool {
    if !use_sigalgs(c) {
        return true;
    }
    let Some(list) = crate::msgs::ext::u16_list(body) else {
        return false;
    };
    if cert {
        c.hs.sh.peer_cert_sigalgs = Some(list);
    } else {
        // `SSL_get_sigalgs` reads it (`s3.tmp.peer_sigalgs`).
        c.neg.peer_sigalgs.clone_from(&list);
        c.hs.sh.peer_sigalgs = Some(list);
    }
    true
}

/// `tls12_shared_sigalgs`: the shared list in `pref`'s order.
fn shared(c: &Connection, pref: &[u16], allow: &[u16]) -> Vec<u16> {
    pref.iter()
        .copied()
        .filter(|&p| {
            c.hs.sh
                .sigalgs
                .lookup(p)
                .is_some_and(|lu| allowed(c, abi::SSL_SECOP_SIGALG_SHARED, lu))
                && allow.contains(&p)
        })
        .collect()
}

/// `tls1_set_shared_sigalgs`.
fn set_shared(c: &mut Connection) {
    let is_suiteb = version::suiteb(c) != 0;
    let conf = if !c.cfg.server && !c.cfg.client_sigalgs.is_empty() && !is_suiteb {
        c.cfg.client_sigalgs.clone()
    } else if !c.cfg.sigalgs.is_empty() && !is_suiteb {
        c.cfg.sigalgs.clone()
    } else {
        psigalgs(c, false)
    };
    let peer = c.hs.sh.peer_sigalgs.clone().unwrap_or_default();
    let list = if c.cfg.options & abi::SSL_OP_CIPHER_SERVER_PREFERENCE != 0 || is_suiteb {
        shared(c, &conf, &peer)
    } else {
        shared(c, &peer, &conf)
    };
    c.neg.shared_sigalgs = list;
}

/// The slot count (built-in plus the providers').
fn slots(c: &Connection) -> usize {
    PKEY_NUM.saturating_add(c.hs.sh.sigalgs.provider_key_types.len())
}

/// The validity flags of a slot.
fn valid_flag(c: &Connection, slot: usize) -> u32 {
    c.hs.sh.valid_flags.get(slot).copied().unwrap_or(0)
}

/// Sets a slot's validity flags.
fn set_valid_flag(c: &mut Connection, slot: usize, v: u32) {
    let n = slots(c);
    if c.hs.sh.valid_flags.len() < n {
        c.hs.sh.valid_flags.resize(n, 0);
    }
    if let Some(f) = c.hs.sh.valid_flags.get_mut(slot) {
        *f = v;
    }
}

/// A `CERT_PKEY_*` flag as `u32`.
fn flag(v: c_int) -> u32 {
    u32::try_from(v).unwrap_or(0)
}

/// `tls1_process_sigalgs`: the shared list, and which slots can sign explicitly.
pub fn process(c: &mut Connection) {
    set_shared(c);
    let n = slots(c);
    c.hs.sh.valid_flags = vec![0; n];
    let shared = c.neg.shared_sigalgs.clone();
    for code in shared {
        let Some(lu) = c.hs.sh.sigalgs.lookup(code) else {
            continue;
        };
        if c.is_tls13() && lu.sig == Sig::Rsa {
            continue;
        }
        let idx = lu.sig_idx;
        if valid_flag(c, idx) == 0 {
            set_valid_flag(
                c,
                idx,
                flag(abi::CERT_PKEY_EXPLICIT_SIGN) | flag(abi::CERT_PKEY_SIGN),
            );
        }
    }
}

/// `tls1_set_server_sigalgs`: the server's shared list, or (when the client sent none) which
/// slots' default schemes it offered.
///
/// # Errors
/// No shared algorithms: `SSL_R_NO_SHARED_SIGNATURE_ALGORITHMS` with handshake_failure.
pub fn set_server_sigalgs(c: &mut Connection) -> Result<()> {
    set_server_sigalgs_inner(c).in_func("tls1_set_server_sigalgs")
}

/// See [`set_server_sigalgs`].
fn set_server_sigalgs_inner(c: &mut Connection) -> Result<()> {
    c.neg.shared_sigalgs.clear();
    c.hs.sh.valid_flags = vec![0; slots(c)];
    if c.hs.sh.peer_cert_sigalgs.is_none() && c.hs.sh.peer_sigalgs.is_none() {
        let sent = psigalgs(c, true);
        for i in 0..slots(c) {
            let Some(code) = legacy_sigalg(c, Some(i)).map(|l| l.sigalg) else {
                continue;
            };
            if sent.contains(&code) {
                set_valid_flag(c, i, flag(abi::CERT_PKEY_SIGN));
            }
        }
        return Ok(());
    }
    process(c);
    if !c.neg.shared_sigalgs.is_empty() {
        return Ok(());
    }
    Err(Error::alert(
        abi::SSL_AD_HANDSHAKE_FAILURE,
        abi::SSL_R_NO_SHARED_SIGNATURE_ALGORITHMS,
    ))
}

/// The certificate (index into the configuration) in slot `slot`.
#[must_use]
pub fn cert_in_slot(c: &Connection, slot: usize) -> Option<usize> {
    c.cfg.certs.iter().position(|k| k.slot == slot)
}

/// Whether a raw public key was negotiated for this end's certificate.
fn own_rpk(c: &Connection) -> bool {
    let t = if c.cfg.server {
        c.neg.server_cert_type
    } else {
        c.neg.client_cert_type
    };
    t == crate::conn::statem::msgs_type(abi::TLSEXT_cert_type_rpk)
}

/// `tls12_rpk_and_privkey`: a raw public key negotiated for this end, and a key with no
/// certificate in `slot`.
fn rpk_and_privkey(c: &Connection, slot: usize) -> bool {
    own_rpk(c)
        && cert_in_slot(c, slot)
            .and_then(|i| c.cfg.certs.get(i))
            .is_some_and(|k| k.chain.is_empty() && k.raw_public_key.is_some())
}

/// `ssl_has_cert_type(s, TLSEXT_cert_type_rpk)`: this end offers raw public keys for its own
/// certificate (configured, whatever is negotiated).
fn rpk_configured(c: &Connection) -> bool {
    let types = if c.cfg.server {
        &c.cfg.server_cert_types
    } else {
        &c.cfg.client_cert_types
    };
    types.contains(&crate::conn::statem::msgs_type(abi::TLSEXT_cert_type_rpk))
}

/// `ssl_has_cert`: a certificate in `slot` (or, with raw public keys configured for this end,
/// a key alone).
#[must_use]
pub fn has_cert(c: &Connection, slot: usize) -> bool {
    cert_in_slot(c, slot)
        .and_then(|i| c.cfg.certs.get(i))
        .is_some_and(|k| !k.chain.is_empty() || (rpk_configured(c) && k.raw_public_key.is_some()))
}

/// The client's current certificate's slot (`s->cert->key`).
fn current_slot(c: &Connection) -> Option<usize> {
    c.cfg
        .current_cert
        .and_then(|i| c.cfg.certs.get(i))
        .or_else(|| c.cfg.certs.first())
        .map(|k| k.slot)
}

/// `tls1_get_legacy_sigalg`: the scheme a slot uses when the peer sent no signature
/// algorithms (`None`: the cipher's slot for a server, the current certificate's for a
/// client): RFC 5246's defaults, or TLS 1.0–1.1's MD5+SHA-1 for RSA.
#[must_use]
pub fn legacy_sigalg(c: &Connection, idx: Option<usize>) -> Option<&SigAlg> {
    let idx = match idx {
        Some(i) => i,
        None if c.cfg.server => {
            let auth = c.hs.new_cipher.map_or(0, |x| x.auth);
            (0..PKEY_NUM).find(|&i| slot_amask(i) & auth != 0)?
        }
        None => current_slot(c)?,
    };
    let def = LEGACY_DEFAULT.get(idx).copied()?;
    if use_sigalgs(c) || idx != PKEY_RSA {
        let lu = c.hs.sh.sigalgs.lookup(def)?;
        if !allowed(c, abi::SSL_SECOP_SIGALG_SUPPORTED, lu) {
            return None;
        }
        return Some(lu);
    }
    let lu = c.hs.sh.sigalgs.lookup(RSA_PKCS1_MD5_SHA1)?;
    allowed(c, abi::SSL_SECOP_SIGALG_SUPPORTED, lu).then_some(lu)
}

/// `tls1_set_peer_legacy_sigalg`: the peer's scheme for a key of `kind` when it sent none.
/// `false` if there is none.
pub fn set_peer_legacy_sigalg(c: &mut Connection, kind: &KeyKind) -> bool {
    let Some(idx) = slot_of(c, kind) else {
        return false;
    };
    let Some(code) = legacy_sigalg(c, Some(idx)).map(|l| l.sigalg) else {
        return false;
    };
    c.hs.sh.peer_sigalg = Some(code);
    true
}

/// `tls12_check_peer_sigalg`: checks the scheme `sig` the peer signed with against its key,
/// the version, and the list this end sent, and records it.
///
/// # Errors
/// OpenSSL's alert and reason (`SSL_R_WRONG_SIGNATURE_TYPE`, `SSL_R_WRONG_CURVE`,
/// `SSL_R_UNKNOWN_DIGEST`).
pub fn check_peer_sigalg(c: &mut Connection, sig: u16, key: &PeerKey) -> Result<()> {
    check_peer_sigalg_inner(c, sig, key).in_func("tls12_check_peer_sigalg")
}

/// See [`check_peer_sigalg`].
fn check_peer_sigalg_inner(c: &mut Connection, sig: u16, key: &PeerKey) -> Result<()> {
    let wrong = Error::alert(
        abi::SSL_AD_ILLEGAL_PARAMETER,
        abi::SSL_R_WRONG_SIGNATURE_TYPE,
    );
    let mut kind = key.kind.clone();
    if c.is_tls13() {
        if kind == KeyKind::Dsa {
            return Err(wrong);
        }
        if kind == KeyKind::Rsa {
            kind = KeyKind::RsaPss;
        }
    }
    let Some(lu) = c.hs.sh.sigalgs.lookup(sig).cloned() else {
        return Err(wrong);
    };
    if !compat(c, &lu) {
        return Err(wrong);
    }
    if (c.is_tls13() && (lu.hash == abi::NID_sha1 || lu.hash == abi::NID_sha224))
        || !lu.sig.fits(&kind)
    {
        return Err(wrong);
    }
    // The key's own type (an RSA key used for RSA-PSS is still in the RSA slot) must be the
    // scheme's slot.
    let key_slot = slot_of(
        c,
        if kind == KeyKind::RsaPss {
            &key.kind
        } else {
            &kind
        },
    );
    if key_slot != Some(lu.sig_idx) {
        return Err(wrong);
    }
    if kind == KeyKind::Ec {
        if (c.is_tls13() || version::suiteb(c) != 0)
            && lu.curve != abi::NID_undef
            && key.curve_nid != lu.curve
        {
            return Err(Error::alert(
                abi::SSL_AD_ILLEGAL_PARAMETER,
                abi::SSL_R_WRONG_CURVE,
            ));
        }
        if !c.is_tls13() {
            if !groups::check_group_id(c, groups::nid_to_group(key.curve_nid), true) {
                return Err(Error::alert(
                    abi::SSL_AD_ILLEGAL_PARAMETER,
                    abi::SSL_R_WRONG_CURVE,
                ));
            }
            if version::suiteb(c) != 0
                && sig != s::ECDSA_SECP256R1_SHA256
                && sig != s::ECDSA_SECP384R1_SHA384
            {
                return Err(Error::alert(
                    abi::SSL_AD_HANDSHAKE_FAILURE,
                    abi::SSL_R_WRONG_SIGNATURE_TYPE,
                ));
            }
        }
    } else if version::suiteb(c) != 0 {
        return Err(Error::alert(
            abi::SSL_AD_HANDSHAKE_FAILURE,
            abi::SSL_R_WRONG_SIGNATURE_TYPE,
        ));
    }
    let sent = psigalgs(c, true);
    let strict = c.cfg.cert_flags & abi::SSL_CERT_FLAG_TLS_STRICT != 0;
    if !sent.contains(&sig) && (lu.hash != abi::NID_sha1 || strict) {
        return Err(Error::alert(
            abi::SSL_AD_HANDSHAKE_FAILURE,
            abi::SSL_R_WRONG_SIGNATURE_TYPE,
        ));
    }
    let bits = security_bits(&lu);
    if bits == 0
        || !security::check(
            c,
            abi::SSL_SECOP_SIGALG_CHECK,
            bits,
            lu.hash,
            SecOther::CodePoint(sig.to_be_bytes()),
        )
    {
        return Err(Error::alert(
            abi::SSL_AD_HANDSHAKE_FAILURE,
            abi::SSL_R_WRONG_SIGNATURE_TYPE,
        ));
    }
    c.hs.sh.peer_sigalg = Some(sig);
    c.neg.peer_scheme = Some(sig);
    Ok(())
}

/// `check_cert_usable`: whether the certificate in `idx` can sign with `lu`: its key can
/// (`EVP_PKEY_digestsign_supports_digest`, which capi gives as
/// [`crate::conn::CertKey::unsupported_digests`], and the RSA-PSS size check, which it folds
/// into [`crate::conn::CertKey::schemes`]), and its own signature meets the peer's
/// signature_algorithms_cert, if sent.
fn cert_usable(c: &Connection, lu: &SigAlg, idx: usize) -> bool {
    let Some(k) = cert_in_slot(c, idx).and_then(|i| c.cfg.certs.get(i)) else {
        return false;
    };
    if !k.schemes.is_empty() && !k.schemes.contains(&lu.sigalg) {
        return false;
    }
    if k.unsupported_digests.contains(&lu.hash) {
        return false;
    }
    if own_rpk(c) {
        return true;
    }
    if k.chain.is_empty() {
        return false;
    }
    let Some(peer) = &c.hs.sh.peer_cert_sigalgs else {
        return true;
    };
    let Some((mdnid, pknid)) = k.cert_sig else {
        return false;
    };
    peer.iter()
        .filter_map(|&x| c.hs.sh.sigalgs.lookup(x))
        .any(|l| l.hash == mdnid && sig_nid(&l.sig) == pknid)
}

/// The key NID a signature type checks against (`lu->sig`).
fn sig_nid(sig: &Sig) -> c_int {
    match sig {
        Sig::Rsa => abi::NID_rsaEncryption,
        Sig::RsaPss => abi::NID_rsassaPss,
        Sig::Dsa => abi::NID_dsa,
        Sig::Ec => abi::NID_X9_62_id_ecPublicKey,
        Sig::Ed25519 => abi::NID_ED25519,
        Sig::Ed448 => abi::NID_ED448,
        Sig::Gost | Sig::Other(_) => abi::NID_undef,
    }
}

/// `has_usable_cert`.
fn has_usable_cert(c: &Connection, lu: &SigAlg, idx: Option<usize>) -> bool {
    let idx = idx.unwrap_or(lu.sig_idx);
    has_cert(c, idx) && cert_usable(c, lu, idx)
}

/// `find_sig_alg` with no certificate given (TLS 1.3): the first shared scheme this end has a
/// usable certificate for (no SHA-1, SHA-224, DSA, or PKCS #1).
fn find_sig_alg(c: &Connection) -> Option<SigAlg> {
    let mut curve: Option<c_int> = None;
    for &code in &c.neg.shared_sigalgs {
        let Some(lu) = c.hs.sh.sigalgs.lookup(code) else {
            continue;
        };
        if lu.hash == abi::NID_sha1
            || lu.hash == abi::NID_sha224
            || lu.sig == Sig::Dsa
            || lu.sig == Sig::Rsa
            || !compat(c, lu)
        {
            continue;
        }
        if !has_usable_cert(c, lu, None) {
            continue;
        }
        if lu.sig == Sig::Ec {
            let cur = *curve.get_or_insert_with(|| {
                cert_in_slot(c, lu.sig_idx)
                    .and_then(|i| c.cfg.certs.get(i))
                    .map_or(abi::NID_undef, |k| k.curve_nid)
            });
            if lu.curve != abi::NID_undef && cur != lu.curve {
                continue;
            }
        }
        return Some(lu.clone());
    }
    None
}

/// `tls12_get_cert_sigalg_idx` (servers): the slot for `lu` if the cipher allows it and the
/// certificate there is valid.
fn cert_sigalg_idx(c: &Connection, lu: &SigAlg) -> Option<usize> {
    let idx = lu.sig_idx;
    let nc = c.hs.new_cipher?;
    if slot_amask(idx) & nc.auth == 0 || (idx == PKEY_RSA_PSS_SIGN && nc.mkey & SSL_kRSA != 0) {
        return None;
    }
    let f = valid_flag(c, idx);
    let want = if rpk_and_privkey(c, idx) {
        flag(abi::CERT_PKEY_RPK)
    } else {
        flag(abi::CERT_PKEY_VALID)
    };
    (f & want != 0).then_some(idx)
}

/// `tls_choose_sigalg`: this end's scheme and certificate for the handshake. With `fatal`
/// (servers) failing to find one is an error; otherwise (clients) the client sends no
/// certificate.
///
/// # Errors
/// No suitable scheme or certificate (OpenSSL's alert and reason).
pub fn choose(c: &mut Connection, fatal: bool) -> Result<()> {
    choose_inner(c, fatal).in_func("tls_choose_sigalg")
}

/// See [`choose`].
fn choose_inner(c: &mut Connection, fatal: bool) -> Result<()> {
    c.hs.sh.cert = None;
    c.hs.sh.sigalg = None;
    let fail = |a, r| {
        if fatal {
            Err(Error::alert(a, r))
        } else {
            Ok(())
        }
    };
    let mut sig_idx: Option<usize> = None;
    let lu: SigAlg;
    if c.is_tls13() {
        match find_sig_alg(c) {
            Some(l) => lu = l,
            None => {
                return fail(
                    abi::SSL_AD_HANDSHAKE_FAILURE,
                    abi::SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM,
                );
            }
        }
    } else {
        let Some(nc) = c.hs.new_cipher else {
            return Ok(());
        };
        if nc.auth & SSL_aCERT == 0 {
            return Ok(());
        }
        if !c.cfg.server && !current_slot(c).is_some_and(|sl| has_cert(c, sl)) {
            return Ok(());
        }
        if use_sigalgs(c) {
            if c.hs.sh.peer_sigalgs.is_some() {
                let curve = if version::suiteb(c) != 0 {
                    cert_in_slot(c, PKEY_ECC)
                        .and_then(|i| c.cfg.certs.get(i))
                        .map(|k| k.curve_nid)
                } else {
                    None
                };
                let mut found = None;
                for &code in &c.neg.shared_sigalgs {
                    let Some(l) = c.hs.sh.sigalgs.lookup(code) else {
                        continue;
                    };
                    if !compat(c, l) {
                        continue;
                    }
                    let idx = if c.cfg.server {
                        match cert_sigalg_idx(c, l) {
                            Some(i) => i,
                            None => continue,
                        }
                    } else {
                        if current_slot(c) != Some(l.sig_idx) {
                            continue;
                        }
                        l.sig_idx
                    };
                    if !has_usable_cert(c, l, Some(idx)) {
                        continue;
                    }
                    if curve.is_none_or(|cv| l.curve == cv) {
                        found = Some((l.clone(), idx));
                        break;
                    }
                }
                match found {
                    Some((l, idx)) => {
                        lu = l;
                        sig_idx = Some(idx);
                    }
                    None => {
                        return fail(
                            abi::SSL_AD_HANDSHAKE_FAILURE,
                            abi::SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM,
                        );
                    }
                }
            } else {
                let Some(l) = legacy_sigalg(c, None).cloned() else {
                    return fail(
                        abi::SSL_AD_HANDSHAKE_FAILURE,
                        abi::SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM,
                    );
                };
                let sent = psigalgs(c, true);
                if !sent
                    .iter()
                    .any(|&x| x == l.sigalg && has_usable_cert(c, &l, Some(l.sig_idx)))
                {
                    return fail(
                        abi::SSL_AD_HANDSHAKE_FAILURE,
                        abi::SSL_R_WRONG_SIGNATURE_TYPE,
                    );
                }
                lu = l;
            }
        } else {
            let Some(l) = legacy_sigalg(c, None).cloned() else {
                return fail(
                    abi::SSL_AD_INTERNAL_ERROR,
                    abi::SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM,
                );
            };
            lu = l;
        }
    }
    let idx = sig_idx.unwrap_or(lu.sig_idx);
    c.hs.sh.cert = cert_in_slot(c, idx);
    c.hs.sh.sigalg = Some(lu.sigalg);
    c.neg.own_scheme = Some(lu.sigalg);
    c.neg.own_cert = c.hs.sh.cert;
    Ok(())
}

/// `ssl_set_sig_mask`: the authentication types no sent scheme (allowed for `op`) can serve.
#[must_use]
pub fn sig_mask(c: &Connection, op: c_int) -> u32 {
    let mut disabled = SSL_aRSA | SSL_aDSS | SSL_aECDSA;
    for code in psigalgs(c, true) {
        let Some(lu) = c.hs.sh.sigalgs.lookup(code) else {
            continue;
        };
        let a = slot_amask(lu.sig_idx);
        if a & disabled != 0 && allowed(c, op, lu) {
            disabled &= !a;
        }
    }
    disabled
}

/// `tls1_set_cert_validity`: in the default mode each slot's certificate is valid unless an EC
/// certificate's curve is unacceptable (`tls1_check_cert_param`); in strict mode
/// ([`check_slot_strict`]) the chain's signatures, parameters, certificate type, and issuer
/// names must suit the peer too. A key-only slot with a raw public key negotiated is
/// `CERT_PKEY_RPK`. TLS 1.2's explicit-sign flags are kept, earlier versions sign implicitly.
pub fn set_cert_validity(c: &mut Connection) {
    let strict = c.cfg.cert_flags & abi::SSL_CERT_FLAG_TLS_STRICT != 0;
    for slot in 0..slots(c) {
        let prev = valid_flag(c, slot);
        let Some(k) = cert_in_slot(c, slot).and_then(|i| c.cfg.certs.get(i)) else {
            set_valid_flag(
                c,
                slot,
                prev & (flag(abi::CERT_PKEY_EXPLICIT_SIGN) | flag(abi::CERT_PKEY_SIGN)),
            );
            continue;
        };
        if rpk_and_privkey(c, slot) {
            set_valid_flag(c, slot, flag(abi::CERT_PKEY_RPK));
            continue;
        }
        if k.chain.is_empty() {
            set_valid_flag(
                c,
                slot,
                prev & (flag(abi::CERT_PKEY_EXPLICIT_SIGN) | flag(abi::CERT_PKEY_SIGN)),
            );
            continue;
        }
        if strict {
            let v = k
                .strict
                .as_ref()
                .map_or(0, |cand| check_slot_strict(c, cand, slot));
            let sign = flag(abi::CERT_PKEY_EXPLICIT_SIGN) | flag(abi::CERT_PKEY_SIGN);
            let signs = if use_sigalgs(c) { prev & sign } else { sign };
            // An invalid chain keeps only the signing flags (`*pvalid &= ...`).
            let v = if v & flag(abi::CERT_PKEY_VALID) != 0 {
                v | signs
            } else {
                prev & sign
            };
            set_valid_flag(c, slot, v);
            continue;
        }
        let param_ok = k.slot != PKEY_ECC
            || k.ec_group
                .is_some_and(|g| groups::check_group_id(c, g, !c.cfg.server));
        if !param_ok {
            set_valid_flag(
                c,
                slot,
                prev & (flag(abi::CERT_PKEY_EXPLICIT_SIGN) | flag(abi::CERT_PKEY_SIGN)),
            );
            continue;
        }
        let mut rv = flag(abi::CERT_PKEY_EE_PARAM)
            | flag(abi::CERT_PKEY_ISSUER_NAME)
            | flag(abi::CERT_PKEY_CERT_TYPE)
            | flag(abi::CERT_PKEY_VALID);
        if !c.cfg.server {
            rv |= flag(abi::CERT_PKEY_CA_PARAM);
        }
        if use_sigalgs(c) {
            rv |= prev & (flag(abi::CERT_PKEY_EXPLICIT_SIGN) | flag(abi::CERT_PKEY_SIGN));
        } else {
            rv |= flag(abi::CERT_PKEY_SIGN) | flag(abi::CERT_PKEY_EXPLICIT_SIGN);
        }
        set_valid_flag(c, slot, rv);
    }
}

/// `tls1_check_chain` on a slot in strict mode (`check_flags` 0): the `CERT_PKEY_*` flags,
/// with `CERT_PKEY_VALID` only when every check passed (the first failure ends it). Suite B's
/// chain check isn't made: with Suite B flags no chain is valid.
fn check_slot_strict(c: &Connection, cand: &ChainCandidate, idx: usize) -> u32 {
    if c.cfg.cert_flags & abi::SSL_CERT_FLAG_SUITEB_128_LOS.cast_unsigned() != 0 {
        return 0;
    }
    let mut rv = 0u32;
    if super::version::tls_level(c.neg.version) >= crate::consts::version::TLS1_2 || c.is_tls13() {
        let (default_nid, rsign) =
            if c.hs.sh.peer_cert_sigalgs.is_some() || c.hs.sh.peer_sigalgs.is_some() {
                (0, None)
            } else {
                match idx {
                    PKEY_RSA => (abi::NID_sha1WithRSAEncryption, Some(Sig::Rsa)),
                    PKEY_DSA_SIGN => (abi::NID_dsaWithSHA1, Some(Sig::Dsa)),
                    PKEY_ECC => (abi::NID_ecdsa_with_SHA1, Some(Sig::Ec)),
                    _ => (-1, None),
                }
            };
        // With no signature_algorithms, configured schemes must include the SHA-1 one.
        if default_nid > 0
            && !c.cfg.sigalgs.is_empty()
            && !c.cfg.sigalgs.iter().any(|&code| {
                c.hs.sh
                    .sigalgs
                    .lookup(code)
                    .is_some_and(|lu| lu.hash == abi::NID_sha1 && Some(lu.sig.clone()) == rsign)
            })
        {
            return 0;
        }
        if c.is_tls13() {
            if find_sig_alg_for(c, cand) {
                rv |= flag(abi::CERT_PKEY_EE_SIGNATURE);
            }
        } else if check_sig_alg(c, &cand.leaf, default_nid) {
            rv |= flag(abi::CERT_PKEY_EE_SIGNATURE);
        } else {
            return 0;
        }
        if !cand.chain.iter().all(|x| check_sig_alg(c, x, default_nid)) {
            return 0;
        }
        rv |= flag(abi::CERT_PKEY_CA_SIGNATURE);
    }
    if !check_cert_param(c, &cand.leaf) {
        return 0;
    }
    rv |= flag(abi::CERT_PKEY_EE_PARAM);
    if c.cfg.server && !cand.chain.iter().all(|x| check_cert_param(c, x)) {
        return 0;
    }
    rv |= flag(abi::CERT_PKEY_CA_PARAM);
    if c.cfg.server {
        rv |= flag(abi::CERT_PKEY_ISSUER_NAME) | flag(abi::CERT_PKEY_CERT_TYPE);
    } else {
        // An RSA, DSA, or ECDSA key must be of a type the CertificateRequest listed (TLS 1.3's
        // has none).
        if cand.cert_type != 0
            && !c
                .certificate_types()
                .is_some_and(|t| t.contains(&cand.cert_type))
        {
            return 0;
        }
        rv |= flag(abi::CERT_PKEY_CERT_TYPE);
        let names = c.neg.peer_ca_names.as_deref().unwrap_or_default();
        if !names.is_empty()
            && !core::iter::once(&cand.leaf)
                .chain(cand.chain.iter())
                .any(|x| names.contains(&x.issuer))
        {
            return 0;
        }
        rv |= flag(abi::CERT_PKEY_ISSUER_NAME);
    }
    rv | flag(abi::CERT_PKEY_VALID)
}

/// Whether a slot's certificate passed [`set_cert_validity`] (`CERT_PKEY_VALID`).
#[must_use]
pub fn slot_valid(c: &Connection, slot: usize) -> bool {
    valid_flag(c, slot) & flag(abi::CERT_PKEY_VALID) != 0
}

/// One certificate of what [`check_chain`] checks.
#[derive(Clone, Debug, Default)]
pub struct ChainCert {
    /// `X509_get_signature_nid`.
    pub sig_nid: c_int,
    /// `OBJ_find_sigid_algs` of that: the digest's and the key's NIDs, if known.
    pub sig_algs: Option<(c_int, c_int)>,
    /// `X509_self_signed(x, 0)`.
    pub self_signed: bool,
    /// The issuer name (DER).
    pub issuer: Vec<u8>,
    /// Whether its public key decodes (`X509_get0_pubkey`).
    pub has_key: bool,
    /// An EC key's group (`tls1_get_group_id`: 0 for a curve without one); `None` for other
    /// keys.
    pub ec_group: Option<u16>,
}

/// A certificate, its key, and its chain, as `SSL_check_chain` gets them.
#[derive(Clone, Debug, Default)]
pub struct ChainCandidate {
    /// The certificate.
    pub leaf: ChainCert,
    /// The rest of the chain.
    pub chain: Vec<ChainCert>,
    /// The private key's slot (`ssl_cert_lookup_by_pkey`), `None` for a key no slot takes.
    pub slot: Option<usize>,
    /// The key's `TLS_CT_*` certificate type (RSA, DSS, or ECDSA sign), 0 for others.
    pub cert_type: u8,
    /// The key's curve (`ssl_get_EC_curve_nid`), or `NID_undef`.
    pub curve_nid: c_int,
    /// The certificate's `X509_get_signature_info` (digest and key NIDs).
    pub sig_info: Option<(c_int, c_int)>,
}

/// `tls1_check_sig_alg`: whether a certificate's signature is one the peer accepts (a
/// self-signed one always is; with no signature_algorithms the RFC 5246 default; RSA PKCS #1
/// is accepted where RSA-PSS with its digest is).
fn check_sig_alg(c: &Connection, x: &ChainCert, default_nid: c_int) -> bool {
    if default_nid == -1 || x.self_signed {
        return true;
    }
    if default_nid != 0 {
        return x.sig_nid == default_nid;
    }
    let list: Vec<u16> = match &c.hs.sh.peer_cert_sigalgs {
        Some(pc) if c.is_tls13() => pc.clone(),
        _ => c.neg.shared_sigalgs.clone(),
    };
    list.iter()
        .filter_map(|&code| c.hs.sh.sigalgs.lookup(code))
        .any(|lu| {
            lu.sigandhash == x.sig_nid
                || (lu.sig == Sig::RsaPss
                    && x.sig_algs
                        .is_some_and(|(md, pk)| pk == abi::NID_rsaEncryption && md == lu.hash))
        })
}

/// `tls1_check_cert_param` (no Suite B digest check): an EC key's group must be one in use.
fn check_cert_param(c: &Connection, x: &ChainCert) -> bool {
    if !x.has_key {
        return false;
    }
    match x.ec_group {
        None => true,
        Some(g) => groups::check_group_id(c, g, !c.cfg.server),
    }
}

/// `find_sig_alg` for a given certificate and key (TLS 1.3): whether a shared scheme (not
/// SHA-1, SHA-224, DSA, or PKCS #1) can sign with them, within the peer's
/// signature_algorithms_cert.
fn find_sig_alg_for(c: &Connection, cand: &ChainCandidate) -> bool {
    c.neg.shared_sigalgs.iter().any(|&code| {
        let Some(lu) = c.hs.sh.sigalgs.lookup(code) else {
            return false;
        };
        if lu.hash == abi::NID_sha1
            || lu.hash == abi::NID_sha224
            || lu.sig == Sig::Dsa
            || lu.sig == Sig::Rsa
            || !compat(c, lu)
            || cand.slot != Some(lu.sig_idx)
        {
            return false;
        }
        if !own_rpk(c)
            && let Some(peer) = &c.hs.sh.peer_cert_sigalgs
        {
            let Some((mdnid, pknid)) = cand.sig_info else {
                return false;
            };
            let ok = peer
                .iter()
                .filter_map(|&x| c.hs.sh.sigalgs.lookup(x))
                .any(|l| l.hash == mdnid && sig_nid(&l.sig) == pknid);
            if !ok {
                return false;
            }
        }
        !(lu.sig == Sig::Ec && lu.curve != abi::NID_undef && cand.curve_nid != lu.curve)
    })
}

/// `tls1_check_chain` as `SSL_check_chain` runs it (`idx == -1`): the `CERT_PKEY_*` flags of
/// a certificate, key, and chain against what the handshake negotiated so far, with
/// `CERT_PKEY_VALID` when the flags strict mode (`SSL_CERT_FLAG_TLS_STRICT`) or the default
/// requires are all there. Suite B's chain check isn't made: with Suite B flags set the chain
/// never has `CERT_PKEY_SUITEB`, so it isn't valid.
#[must_use]
pub fn check_chain(c: &Connection, cand: &ChainCandidate) -> u32 {
    let Some(idx) = cand.slot else {
        return 0;
    };
    let suiteb = c.cfg.cert_flags & abi::SSL_CERT_FLAG_SUITEB_128_LOS.cast_unsigned() != 0;
    let strict_flags = flag(abi::CERT_PKEY_EE_SIGNATURE)
        | flag(abi::CERT_PKEY_EE_PARAM)
        | flag(abi::CERT_PKEY_CA_SIGNATURE)
        | flag(abi::CERT_PKEY_CA_PARAM)
        | flag(abi::CERT_PKEY_ISSUER_NAME)
        | flag(abi::CERT_PKEY_CERT_TYPE);
    let mut check_flags = if c.cfg.cert_flags & abi::SSL_CERT_FLAG_TLS_STRICT != 0 || suiteb {
        strict_flags
    } else {
        flag(abi::CERT_PKEY_EE_SIGNATURE) | flag(abi::CERT_PKEY_EE_PARAM)
    };
    if suiteb {
        check_flags |= flag(abi::CERT_PKEY_SUITEB);
    }
    let mut rv = 0u32;
    let tls12 =
        super::version::tls_level(c.neg.version) >= crate::consts::version::TLS1_2 || c.is_tls13();
    if tls12 {
        let (default_nid, rsign) =
            if c.hs.sh.peer_cert_sigalgs.is_some() || c.hs.sh.peer_sigalgs.is_some() {
                (0, None)
            } else {
                match idx {
                    PKEY_RSA => (abi::NID_sha1WithRSAEncryption, Some(Sig::Rsa)),
                    PKEY_DSA_SIGN => (abi::NID_dsaWithSHA1, Some(Sig::Dsa)),
                    PKEY_ECC => (abi::NID_ecdsa_with_SHA1, Some(Sig::Ec)),
                    _ => (-1, None),
                }
            };
        // With no signature_algorithms, configured schemes must include the SHA-1 one.
        let skip_sigs = default_nid > 0
            && !c.cfg.sigalgs.is_empty()
            && !c.cfg.sigalgs.iter().any(|&code| {
                c.hs.sh
                    .sigalgs
                    .lookup(code)
                    .is_some_and(|lu| lu.hash == abi::NID_sha1 && Some(lu.sig.clone()) == rsign)
            });
        if !skip_sigs {
            let ee = if c.is_tls13() {
                find_sig_alg_for(c, cand)
            } else {
                check_sig_alg(c, &cand.leaf, default_nid)
            };
            if ee {
                rv |= flag(abi::CERT_PKEY_EE_SIGNATURE);
            }
            if cand.chain.iter().all(|x| check_sig_alg(c, x, default_nid)) {
                rv |= flag(abi::CERT_PKEY_CA_SIGNATURE);
            }
        }
    } else {
        rv |= flag(abi::CERT_PKEY_EE_SIGNATURE) | flag(abi::CERT_PKEY_CA_SIGNATURE);
    }
    if check_cert_param(c, &cand.leaf) {
        rv |= flag(abi::CERT_PKEY_EE_PARAM);
    }
    if !c.cfg.server || cand.chain.iter().all(|x| check_cert_param(c, x)) {
        rv |= flag(abi::CERT_PKEY_CA_PARAM);
    }
    if c.cfg.server {
        rv |= flag(abi::CERT_PKEY_ISSUER_NAME) | flag(abi::CERT_PKEY_CERT_TYPE);
    } else {
        if cand.cert_type == 0
            || c.certificate_types()
                .is_some_and(|t| t.contains(&cand.cert_type))
        {
            rv |= flag(abi::CERT_PKEY_CERT_TYPE);
        }
        // None (nothing sent) and an empty list both match (`!sk_X509_NAME_num(ca_dn)`).
        let names = c.neg.peer_ca_names.as_deref().unwrap_or_default();
        if names.is_empty()
            || core::iter::once(&cand.leaf)
                .chain(cand.chain.iter())
                .any(|x| names.contains(&x.issuer))
        {
            rv |= flag(abi::CERT_PKEY_ISSUER_NAME);
        }
    }
    if rv & check_flags == check_flags {
        rv |= flag(abi::CERT_PKEY_VALID);
    }
    let sign = flag(abi::CERT_PKEY_EXPLICIT_SIGN) | flag(abi::CERT_PKEY_SIGN);
    if tls12 {
        rv |= valid_flag(c, idx) & sign;
    } else {
        rv |= sign;
    }
    rv
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testprov::TestProvider;

    #[test]
    fn the_default_list_is_openssls_without_ml_dsa_or_gost() {
        let p = TestProvider::new(b"sigalgs");
        let cache = Cache::new(&p);
        assert_eq!(
            cache.defaults,
            [
                s::ECDSA_SECP256R1_SHA256,
                s::ECDSA_SECP384R1_SHA384,
                s::ECDSA_SECP521R1_SHA512,
                s::ED25519,
                s::ED448,
                s::ECDSA_BRAINPOOLP256R1_SHA256,
                s::ECDSA_BRAINPOOLP384R1_SHA384,
                s::ECDSA_BRAINPOOLP512R1_SHA512,
                s::RSA_PSS_PSS_SHA256,
                s::RSA_PSS_PSS_SHA384,
                s::RSA_PSS_PSS_SHA512,
                s::RSA_PSS_RSAE_SHA256,
                s::RSA_PSS_RSAE_SHA384,
                s::RSA_PSS_RSAE_SHA512,
                s::RSA_PKCS1_SHA256,
                s::RSA_PKCS1_SHA384,
                s::RSA_PKCS1_SHA512,
                s::ECDSA_SHA224,
                s::ECDSA_SHA1,
                s::RSA_PKCS1_SHA224,
                s::RSA_PKCS1_SHA1,
                s::DSA_SHA224,
                s::DSA_SHA1,
                s::DSA_SHA256,
                s::DSA_SHA384,
                s::DSA_SHA512,
            ]
        );
        assert!(cache.lookup(s::GOSTR34102001_GOSTR3411).is_none());
        assert_eq!(security_bits(cache.lookup(s::RSA_PKCS1_SHA1).unwrap()), 64);
        assert_eq!(security_bits(cache.lookup(s::ED448).unwrap()), 224);
    }
}
