//! OpenSSL's cipher suites (`SSL_CIPHER`): every suite libssl 3.5.9 knows in its default build,
//! with OpenSSL's names, algorithm bits, strengths, and versions, the lookups libssl makes, the
//! values the `SSL_CIPHER_get_*` functions report, and what the record layer needs to protect
//! records with each.

#![allow(
    non_upper_case_globals,
    reason = "OpenSSL's algorithm bits keep their names (masks.rs)"
)]

use core::ffi::{CStr, c_int};
use std::sync::OnceLock;

use rustyssl_abi as abi;

use crate::crypto::{AeadAlg, CipherAlg, HashAlg};

pub mod masks;
mod table;

use masks::*;

/// A cipher suite, as OpenSSL describes it (`struct ssl_cipher_st`).
#[derive(Debug, PartialEq, Eq)]
pub struct Cipher {
    /// Whether it is a real suite (not a signalling value such as the SCSVs).
    pub valid: bool,
    /// OpenSSL's name (`ECDHE-RSA-AES128-GCM-SHA256`).
    pub name: &'static CStr,
    /// The RFC name (`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`); `None` for the GOST suites,
    /// which have none.
    pub stdname: Option<&'static CStr>,
    /// OpenSSL's id: `0x0300` followed by the two octets on the wire.
    pub id: u32,
    /// The key exchange bits (`SSL_k*`).
    pub mkey: u32,
    /// The authentication bits (`SSL_a*`).
    pub auth: u32,
    /// The encryption bits (`SSL_enc*`).
    pub enc: u32,
    /// The MAC bits (`SSL_mac*`, or [`SSL_AEAD`]).
    pub mac: u32,
    /// The lowest TLS version it may be used with (0: none).
    pub min_tls: c_int,
    /// The highest TLS version (0: none).
    pub max_tls: c_int,
    /// The lowest DTLS version (0: none).
    pub min_dtls: c_int,
    /// The highest DTLS version (0: none).
    pub max_dtls: c_int,
    /// The strength class and default bits (`SSL_HIGH`, `SSL_NOT_DEFAULT`, ...).
    pub strength: u32,
    /// The handshake digest and PRF indexes, and flags (`algorithm2`).
    pub algorithm2: u32,
    /// The bits of security (`SSL_CIPHER_get_bits`'s result).
    pub strength_bits: i32,
    /// The bits of the algorithm's key (`SSL_CIPHER_get_bits`'s `alg_bits`).
    pub alg_bits: i32,
}

/// A suite id from its `c_int` constant (all fit: they are `0x03000000` and two octets).
#[expect(clippy::cast_sign_loss, reason = "every suite id constant is positive")]
pub(crate) const fn cid(v: c_int) -> u32 {
    v as u32
}

/// How a suite protects records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    /// An AEAD.
    Aead(AeadAlg),
    /// A CBC cipher with an HMAC (MAC-then-encrypt, or encrypt-then-MAC when negotiated).
    Cbc {
        /// The cipher.
        cipher: CipherAlg,
        /// The HMAC's hash.
        mac: HashAlg,
    },
    /// No encryption, only the HMAC: TLS 1.2's NULL suites, and TLS 1.3's integrity-only
    /// suites (RFC 9150).
    Null {
        /// The HMAC's hash.
        mac: HashAlg,
    },
    /// An algorithm the core doesn't implement (GOST, IDEA, SEED in a provider-less build...).
    Unsupported,
}

impl Cipher {
    /// OpenSSL's name, as text.
    #[must_use]
    pub fn name_str(&self) -> &'static str {
        self.name.to_str().unwrap_or_default()
    }

    /// The RFC name, as text, if it has one.
    #[must_use]
    pub fn stdname_str(&self) -> Option<&'static str> {
        self.stdname.and_then(|s| s.to_str().ok())
    }

    /// The two octets on the wire (`SSL_CIPHER_get_protocol_id`).
    #[must_use]
    pub fn protocol_id(&self) -> u16 {
        u16::try_from(self.id & 0xFFFF).unwrap_or_default()
    }

    /// Whether it is a TLS 1.3 suite.
    #[must_use]
    pub fn is_tls13(&self) -> bool {
        self.min_tls == abi::TLS1_3_VERSION
    }

    /// Whether it is an AEAD suite (`SSL_CIPHER_is_aead`).
    #[must_use]
    pub const fn is_aead(&self) -> bool {
        self.mac & SSL_AEAD != 0
    }

    /// `SSL_CIPHER_get_version`: the version it was introduced in, with OpenSSL's spelling
    /// (`TLSv1.0` here, where elsewhere OpenSSL says `TLSv1`).
    #[must_use]
    pub fn version_str(&self) -> &'static str {
        if self.min_tls == abi::TLS1_VERSION {
            "TLSv1.0"
        } else {
            protocol_str(self.min_tls)
        }
    }

    /// `SSL_CIPHER_description`: a line of fixed-width columns, ending in a newline.
    #[must_use]
    pub fn description(&self) -> String {
        format!(
            "{:<30} {:<7} Kx={:<8} Au={:<5} Enc={:<22} Mac={:<4}\n",
            self.name_str(),
            protocol_str(self.min_tls),
            kx_str(self.mkey),
            au_str(self.auth),
            enc_str(self.enc),
            mac_str(self.mac),
        )
    }

    /// `SSL_CIPHER_get_cipher_nid`: the encryption's NID, or `NID_undef`.
    #[must_use]
    pub fn cipher_nid(&self) -> c_int {
        CIPHER_NIDS
            .iter()
            .find(|(m, _)| *m == self.enc)
            .map_or(abi::NID_undef, |&(_, n)| n)
    }

    /// `SSL_CIPHER_get_digest_nid`: the MAC's NID, or `NID_undef` (for an AEAD).
    #[must_use]
    pub fn digest_nid(&self) -> c_int {
        MAC_NIDS
            .iter()
            .find(|(m, _)| *m == self.mac)
            .map_or(abi::NID_undef, |&(_, n)| n)
    }

    /// `SSL_CIPHER_get_kx_nid`: the key exchange's NID, or `NID_undef`.
    #[must_use]
    pub fn kx_nid(&self) -> c_int {
        KX_NIDS
            .iter()
            .find(|(m, _)| *m == self.mkey)
            .map_or(abi::NID_undef, |&(_, n)| n)
    }

    /// `SSL_CIPHER_get_auth_nid`: the authentication's NID, or `NID_undef`.
    #[must_use]
    pub fn auth_nid(&self) -> c_int {
        AUTH_NIDS
            .iter()
            .find(|(m, _)| *m == self.auth)
            .map_or(abi::NID_undef, |&(_, n)| n)
    }

    /// The digest index of the handshake hash (`algorithm2 & SSL_HANDSHAKE_MAC_MASK`).
    #[must_use]
    pub const fn handshake_digest_index(&self) -> u32 {
        self.algorithm2 & SSL_HANDSHAKE_MAC_MASK
    }

    /// The digest index of the TLS 1.2 PRF.
    #[must_use]
    pub const fn prf_digest_index(&self) -> u32 {
        (self.algorithm2 >> TLS1_PRF_DGST_SHIFT) & SSL_HANDSHAKE_MAC_MASK
    }

    /// `SSL_CIPHER_get_handshake_digest`'s digest, as a NID (`NID_undef` if none).
    #[must_use]
    pub fn handshake_digest_nid(&self) -> c_int {
        digest_index_nid(self.handshake_digest_index())
    }

    /// The handshake (transcript) hash, if the core implements it.
    #[must_use]
    pub fn handshake_hash(&self) -> Option<HashAlg> {
        digest_index_hash(self.handshake_digest_index())
    }

    /// The TLS 1.2 PRF's hash (`MD5+SHA-1` for TLS 1.0 and 1.1's suites), if implemented.
    #[must_use]
    pub fn prf_hash(&self) -> Option<HashAlg> {
        digest_index_hash(self.prf_digest_index())
    }

    /// How records are protected with this suite.
    #[must_use]
    pub fn protection(&self) -> Protection {
        let aead = match self.enc {
            SSL_AES128GCM => Some(AeadAlg::Aes128Gcm),
            SSL_AES256GCM => Some(AeadAlg::Aes256Gcm),
            SSL_AES128CCM => Some(AeadAlg::Aes128Ccm),
            SSL_AES256CCM => Some(AeadAlg::Aes256Ccm),
            SSL_AES128CCM8 => Some(AeadAlg::Aes128Ccm8),
            SSL_AES256CCM8 => Some(AeadAlg::Aes256Ccm8),
            SSL_CHACHA20POLY1305 => Some(AeadAlg::ChaCha20Poly1305),
            SSL_ARIA128GCM => Some(AeadAlg::Aria128Gcm),
            SSL_ARIA256GCM => Some(AeadAlg::Aria256Gcm),
            _ => None,
        };
        if let Some(a) = aead {
            return Protection::Aead(a);
        }
        let Some(mac) = mac_hash(self.mac) else {
            return Protection::Unsupported;
        };
        let cipher = match self.enc {
            SSL_eNULL => return Protection::Null { mac },
            SSL_AES128 => CipherAlg::Aes128Cbc,
            SSL_AES256 => CipherAlg::Aes256Cbc,
            SSL_CAMELLIA128 => CipherAlg::Camellia128Cbc,
            SSL_CAMELLIA256 => CipherAlg::Camellia256Cbc,
            SSL_SEED => CipherAlg::SeedCbc,
            SSL_IDEA => CipherAlg::IdeaCbc,
            SSL_3DES => CipherAlg::DesEde3Cbc,
            _ => return Protection::Unsupported,
        };
        Protection::Cbc { cipher, mac }
    }

    /// For a TLS 1.2 AEAD suite, the implicit part of the nonce taken from the key block
    /// (`fixed_iv_length`) and the explicit part sent in each record: 4 and 8 for GCM and
    /// CCM (RFC 5288, RFC 6655), 12 and 0 for ChaCha20-Poly1305 (RFC 7905).
    #[must_use]
    pub const fn tls12_aead_iv_lengths(&self) -> (usize, usize) {
        if self.enc == SSL_CHACHA20POLY1305 {
            (12, 0)
        } else {
            (4, 8)
        }
    }
}

/// `ssl_protocol_to_string`: a version's name (`TLSv1.2`, `DTLSv1`, ...), or `unknown`.
#[must_use]
pub fn protocol_str(version: c_int) -> &'static str {
    match version {
        abi::TLS1_3_VERSION => "TLSv1.3",
        abi::TLS1_2_VERSION => "TLSv1.2",
        abi::TLS1_1_VERSION => "TLSv1.1",
        abi::TLS1_VERSION => "TLSv1",
        abi::SSL3_VERSION => "SSLv3",
        abi::DTLS1_BAD_VER => "DTLSv0.9",
        abi::DTLS1_VERSION => "DTLSv1",
        abi::DTLS1_2_VERSION => "DTLSv1.2",
        _ => "unknown",
    }
}

fn kx_str(m: u32) -> &'static str {
    match m {
        SSL_kRSA => "RSA",
        SSL_kDHE => "DH",
        SSL_kECDHE => "ECDH",
        SSL_kPSK => "PSK",
        SSL_kRSAPSK => "RSAPSK",
        SSL_kECDHEPSK => "ECDHEPSK",
        SSL_kDHEPSK => "DHEPSK",
        SSL_kSRP => "SRP",
        SSL_kGOST => "GOST",
        SSL_kGOST18 => "GOST18",
        SSL_kANY => "any",
        _ => "unknown",
    }
}

fn au_str(a: u32) -> &'static str {
    const GOST12: u32 = SSL_aGOST12 | SSL_aGOST01;
    match a {
        SSL_aRSA => "RSA",
        SSL_aDSS => "DSS",
        SSL_aNULL => "None",
        SSL_aECDSA => "ECDSA",
        SSL_aPSK => "PSK",
        SSL_aSRP => "SRP",
        SSL_aGOST01 => "GOST01",
        GOST12 => "GOST12",
        SSL_aANY => "any",
        _ => "unknown",
    }
}

fn enc_str(e: u32) -> &'static str {
    match e {
        SSL_DES => "DES(56)",
        SSL_3DES => "3DES(168)",
        SSL_RC4 => "RC4(128)",
        SSL_RC2 => "RC2(128)",
        SSL_IDEA => "IDEA(128)",
        SSL_eNULL => "None",
        SSL_AES128 => "AES(128)",
        SSL_AES256 => "AES(256)",
        SSL_AES128GCM => "AESGCM(128)",
        SSL_AES256GCM => "AESGCM(256)",
        SSL_AES128CCM => "AESCCM(128)",
        SSL_AES256CCM => "AESCCM(256)",
        SSL_AES128CCM8 => "AESCCM8(128)",
        SSL_AES256CCM8 => "AESCCM8(256)",
        SSL_CAMELLIA128 => "Camellia(128)",
        SSL_CAMELLIA256 => "Camellia(256)",
        SSL_ARIA128GCM => "ARIAGCM(128)",
        SSL_ARIA256GCM => "ARIAGCM(256)",
        SSL_SEED => "SEED(128)",
        SSL_eGOST2814789CNT | SSL_eGOST2814789CNT12 => "GOST89(256)",
        SSL_MAGMA => "MAGMA",
        SSL_KUZNYECHIK => "KUZNYECHIK",
        SSL_CHACHA20POLY1305 => "CHACHA20/POLY1305(256)",
        _ => "unknown",
    }
}

fn mac_str(m: u32) -> &'static str {
    match m {
        SSL_MD5 => "MD5",
        SSL_SHA1 => "SHA1",
        SSL_SHA256 => "SHA256",
        SSL_SHA384 => "SHA384",
        SSL_AEAD => "AEAD",
        SSL_GOST89MAC | SSL_GOST89MAC12 => "GOST89",
        SSL_GOST94 => "GOST94",
        SSL_GOST12_256 | SSL_GOST12_512 => "GOST2012",
        _ => "unknown",
    }
}

/// `ssl_cipher_table_cipher`: each encryption bit's NID.
const CIPHER_NIDS: [(u32, c_int); 24] = [
    (SSL_DES, abi::NID_des_cbc),
    (SSL_3DES, abi::NID_des_ede3_cbc),
    (SSL_RC4, abi::NID_rc4),
    (SSL_RC2, abi::NID_rc2_cbc),
    (SSL_IDEA, abi::NID_idea_cbc),
    (SSL_eNULL, abi::NID_undef),
    (SSL_AES128, abi::NID_aes_128_cbc),
    (SSL_AES256, abi::NID_aes_256_cbc),
    (SSL_CAMELLIA128, abi::NID_camellia_128_cbc),
    (SSL_CAMELLIA256, abi::NID_camellia_256_cbc),
    (SSL_eGOST2814789CNT, abi::NID_gost89_cnt),
    (SSL_SEED, abi::NID_seed_cbc),
    (SSL_AES128GCM, abi::NID_aes_128_gcm),
    (SSL_AES256GCM, abi::NID_aes_256_gcm),
    (SSL_AES128CCM, abi::NID_aes_128_ccm),
    (SSL_AES256CCM, abi::NID_aes_256_ccm),
    (SSL_AES128CCM8, abi::NID_aes_128_ccm),
    (SSL_AES256CCM8, abi::NID_aes_256_ccm),
    (SSL_eGOST2814789CNT12, abi::NID_gost89_cnt_12),
    (SSL_CHACHA20POLY1305, abi::NID_chacha20_poly1305),
    (SSL_ARIA128GCM, abi::NID_aria_128_gcm),
    (SSL_ARIA256GCM, abi::NID_aria_256_gcm),
    (SSL_MAGMA, abi::NID_magma_ctr_acpkm),
    (SSL_KUZNYECHIK, abi::NID_kuznyechik_ctr_acpkm),
];

/// `ssl_cipher_table_mac`: each digest index's MAC bit and NID (the index is the position).
pub const MAC_NIDS: [(u32, c_int); 14] = [
    (SSL_MD5, abi::NID_md5),
    (SSL_SHA1, abi::NID_sha1),
    (SSL_GOST94, abi::NID_id_GostR3411_94),
    (SSL_GOST89MAC, abi::NID_id_Gost28147_89_MAC),
    (SSL_SHA256, abi::NID_sha256),
    (SSL_SHA384, abi::NID_sha384),
    (SSL_GOST12_256, abi::NID_id_GostR3411_2012_256),
    (SSL_GOST89MAC12, abi::NID_gost_mac_12),
    (SSL_GOST12_512, abi::NID_id_GostR3411_2012_512),
    (0, abi::NID_md5_sha1),
    (0, abi::NID_sha224),
    (0, abi::NID_sha512),
    (SSL_MAGMAOMAC, abi::NID_magma_mac),
    (SSL_KUZNYECHIKOMAC, abi::NID_kuznyechik_mac),
];

/// `ssl_cipher_table_kx`.
const KX_NIDS: [(u32, c_int); 11] = [
    (SSL_kRSA, abi::NID_kx_rsa),
    (SSL_kECDHE, abi::NID_kx_ecdhe),
    (SSL_kDHE, abi::NID_kx_dhe),
    (SSL_kECDHEPSK, abi::NID_kx_ecdhe_psk),
    (SSL_kDHEPSK, abi::NID_kx_dhe_psk),
    (SSL_kRSAPSK, abi::NID_kx_rsa_psk),
    (SSL_kPSK, abi::NID_kx_psk),
    (SSL_kSRP, abi::NID_kx_srp),
    (SSL_kGOST, abi::NID_kx_gost),
    (SSL_kGOST18, abi::NID_kx_gost18),
    (SSL_kANY, abi::NID_kx_any),
];

/// `ssl_cipher_table_auth`.
const AUTH_NIDS: [(u32, c_int); 9] = [
    (SSL_aRSA, abi::NID_auth_rsa),
    (SSL_aECDSA, abi::NID_auth_ecdsa),
    (SSL_aPSK, abi::NID_auth_psk),
    (SSL_aDSS, abi::NID_auth_dss),
    (SSL_aGOST01, abi::NID_auth_gost01),
    (SSL_aGOST12, abi::NID_auth_gost12),
    (SSL_aSRP, abi::NID_auth_srp),
    (SSL_aNULL, abi::NID_auth_null),
    (SSL_aANY, abi::NID_auth_any),
];

/// The NID of digest index `idx` (`NID_undef` past the table).
#[must_use]
pub fn digest_index_nid(idx: u32) -> c_int {
    usize::try_from(idx)
        .ok()
        .and_then(|i| MAC_NIDS.get(i))
        .map_or(abi::NID_undef, |&(_, n)| n)
}

/// The core's hash for digest index `idx`, if it is one the core implements.
#[must_use]
pub fn digest_index_hash(idx: u32) -> Option<HashAlg> {
    match idx {
        SSL_MD_MD5_IDX => Some(HashAlg::Md5),
        SSL_MD_SHA1_IDX => Some(HashAlg::Sha1),
        SSL_MD_SHA256_IDX => Some(HashAlg::Sha256),
        SSL_MD_SHA384_IDX => Some(HashAlg::Sha384),
        SSL_MD_MD5_SHA1_IDX => Some(HashAlg::Md5Sha1),
        SSL_MD_SHA224_IDX => Some(HashAlg::Sha224),
        SSL_MD_SHA512_IDX => Some(HashAlg::Sha512),
        _ => None,
    }
}

/// The core's hash for a MAC bit, if implemented.
fn mac_hash(m: u32) -> Option<HashAlg> {
    match m {
        SSL_MD5 => Some(HashAlg::Md5),
        SSL_SHA1 => Some(HashAlg::Sha1),
        SSL_SHA256 => Some(HashAlg::Sha256),
        SSL_SHA384 => Some(HashAlg::Sha384),
        _ => None,
    }
}

/// The TLS 1.3 suites, in OpenSSL's table order.
#[must_use]
pub fn tls13() -> &'static [Cipher] {
    &table::TLS13
}

/// The TLS 1.2-and-earlier suites (`ssl3_ciphers`), in OpenSSL's source order.
#[must_use]
pub fn ssl3() -> &'static [Cipher] {
    &table::SSL3
}

/// The signalling suites (`TLS_EMPTY_RENEGOTIATION_INFO_SCSV`, `TLS_FALLBACK_SCSV`).
#[must_use]
pub fn scsvs() -> &'static [Cipher] {
    &table::SCSVS
}

/// Every suite: TLS 1.3, then the others, then the signalling values.
pub fn all() -> impl Iterator<Item = &'static Cipher> {
    tls13().iter().chain(ssl3()).chain(scsvs())
}

/// The TLS 1.2-and-earlier suites in the order a method hands them to the cipher-list builder
/// (`ssl3_get_cipher(0..n)`): OpenSSL sorts its table by id at start-up and the method returns
/// it from the end, so by descending id.
#[must_use]
pub fn ssl3_by_descending_id() -> &'static [&'static Cipher] {
    static SORTED: OnceLock<Vec<&'static Cipher>> = OnceLock::new();
    SORTED.get_or_init(|| {
        let mut v: Vec<&'static Cipher> = ssl3().iter().collect();
        v.sort_by_key(|c| core::cmp::Reverse(c.id));
        v
    })
}

/// `ssl3_get_cipher_by_id`: the suite with OpenSSL id `id` (TLS 1.3 first, then the others,
/// then the signalling values).
#[must_use]
pub fn by_id(id: u32) -> Option<&'static Cipher> {
    all().find(|c| c.id == id)
}

/// `ssl3_get_cipher_by_char`: the suite with these two octets on the wire.
#[must_use]
pub fn by_protocol_id(id: u16) -> Option<&'static Cipher> {
    by_id(0x0300_0000 | u32::from(id))
}

/// `ssl3_get_cipher_by_std_name`: the suite with this RFC name.
#[must_use]
pub fn by_std_name(name: &str) -> Option<&'static Cipher> {
    all().find(|c| c.stdname_str() == Some(name))
}

/// The suite with this OpenSSL name.
#[must_use]
pub fn by_name(name: &str) -> Option<&'static Cipher> {
    all().find(|c| c.name_str() == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tables_have_openssls_sizes() {
        assert_eq!(tls13().len(), 7);
        assert_eq!(ssl3().len(), 167);
        assert_eq!(scsvs().len(), 2);
    }

    #[test]
    fn ids_and_names_are_unique() {
        let mut ids: Vec<u32> = all().map(|c| c.id).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n);
        let mut names: Vec<&str> = all().map(Cipher::name_str).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), n);
    }

    #[test]
    fn lookups() {
        let c = by_protocol_id(0xC02F).unwrap();
        assert_eq!(c.name_str(), "ECDHE-RSA-AES128-GCM-SHA256");
        assert_eq!(
            c.stdname_str(),
            Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        );
        assert_eq!(
            by_std_name("TLS_AES_128_GCM_SHA256").unwrap().protocol_id(),
            0x1301
        );
        assert_eq!(by_name("AES128-SHA").unwrap().id, 0x0300_002F);
        assert!(!by_protocol_id(0x00FF).unwrap().valid);
        assert!(by_protocol_id(0x0000).is_none());
        assert_eq!(c.version_str(), "TLSv1.2");
        assert_eq!(by_name("AES128-SHA").unwrap().version_str(), "SSLv3");
        assert_eq!(
            by_name("ECDHE-RSA-AES128-SHA").unwrap().version_str(),
            "TLSv1.0"
        );
    }

    #[test]
    fn protection() {
        assert_eq!(
            by_name("ECDHE-RSA-AES128-GCM-SHA256").unwrap().protection(),
            Protection::Aead(AeadAlg::Aes128Gcm)
        );
        assert_eq!(
            by_name("AES256-SHA256").unwrap().protection(),
            Protection::Cbc {
                cipher: CipherAlg::Aes256Cbc,
                mac: HashAlg::Sha256
            }
        );
        assert_eq!(
            by_std_name("TLS_SHA384_SHA384").unwrap().protection(),
            Protection::Null {
                mac: HashAlg::Sha384
            }
        );
        let c = by_name("ECDHE-RSA-CHACHA20-POLY1305").unwrap();
        assert_eq!(c.tls12_aead_iv_lengths(), (12, 0));
        assert_eq!(c.prf_hash(), Some(HashAlg::Sha256));
        assert_eq!(
            by_name("AES128-SHA").unwrap().prf_hash(),
            Some(HashAlg::Md5Sha1)
        );
        assert_eq!(
            by_std_name("TLS_AES_256_GCM_SHA384")
                .unwrap()
                .handshake_hash(),
            Some(HashAlg::Sha384)
        );
    }
}
