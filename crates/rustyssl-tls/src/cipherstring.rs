//! OpenSSL's cipher-string language (`ssl_ciph.c`): the list `SSL_CTX_set_cipher_list` builds
//! from a string such as `DEFAULT:!aNULL:@STRENGTH`, and the TLS 1.3 list
//! `SSL_CTX_set_ciphersuites` takes.
//!
//! The order of the result is OpenSSL's exactly. The builder starts from the suites in
//! descending id order, arranges them by OpenSSL's preferences (ECDHE first, AEADs and AES
//! preferred, strength-sorted, TLS 1.2 suites bumped up), and then applies each rule of the
//! string to that ordered list: adding a suite appends it at the end, `+` moves matches to the
//! end, `-` takes them out (keeping their place for a later add), and `!` removes them for good.
//! The rules run over a linked list whose iteration stops at the node that was last when the
//! rule started, so a suite moved to the end isn't visited twice; this port keeps that list.

#![allow(
    non_upper_case_globals,
    reason = "OpenSSL's algorithm bits keep their names (masks.rs)"
)]

use core::ffi::{CStr, c_int};
use std::collections::BTreeSet;

use rustyssl_abi as abi;

use crate::error::Error;
use crate::suites::masks::*;
use crate::suites::{self, Cipher, MAC_NIDS};

/// `OSSL_default_cipher_list`: the TLS 1.2-and-earlier part of the default list.
pub const DEFAULT_CIPHER_LIST: &CStr = abi::SSL_DEFAULT_CIPHER_LIST;

/// `OSSL_default_ciphersuites`: the default TLS 1.3 suites.
pub const DEFAULT_CIPHERSUITES: &CStr = abi::TLS_DEFAULT_CIPHERSUITES;

/// Which algorithm bits are unavailable (`SSL_CTX`'s `disabled_*_mask`, from `ssl_load_ciphers`):
/// a suite using any of them is never listed, and an alias naming only them matches nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Available {
    /// Unavailable key exchanges.
    pub disabled_mkey: u32,
    /// Unavailable authentications.
    pub disabled_auth: u32,
    /// Unavailable encryptions.
    pub disabled_enc: u32,
    /// Unavailable MACs.
    pub disabled_mac: u32,
}

/// What the providers offer, as `ssl_load_ciphers` asks it.
pub trait Offers {
    /// Whether the cipher with this NID can be fetched.
    fn cipher(&self, nid: c_int) -> bool;
    /// Whether the digest with this NID can be fetched.
    fn digest(&self, nid: c_int) -> bool;
    /// Whether the signature algorithm (`DSA`, `ECDSA`) can be fetched.
    fn signature(&self, name: &str) -> bool;
    /// Whether the key exchange (`DH`, `ECDH`) can be fetched.
    fn key_exchange(&self, name: &str) -> bool;
    /// Whether a public key type is known (the GOST keys and MACs, by NID).
    fn pkey(&self, nid: c_int) -> bool;
}

impl Available {
    /// `ssl_load_ciphers`: the masks for what `offers` says is available.
    #[must_use]
    pub fn from_offers(offers: &dyn Offers) -> Self {
        let mut a = Self::default();
        for (mask, nid) in CIPHER_TABLE {
            if nid != abi::NID_undef && !offers.cipher(nid) {
                a.disabled_enc |= mask;
            }
        }
        for (mask, nid) in MAC_NIDS {
            if !offers.digest(nid) {
                a.disabled_mac |= mask;
            }
        }
        if !offers.signature("DSA") {
            a.disabled_auth |= SSL_aDSS;
        }
        if !offers.key_exchange("DH") {
            a.disabled_mkey |= SSL_kDHE | SSL_kDHEPSK;
        }
        if !offers.key_exchange("ECDH") {
            a.disabled_mkey |= SSL_kECDHE | SSL_kECDHEPSK;
        }
        if !offers.signature("ECDSA") {
            a.disabled_auth |= SSL_aECDSA;
        }
        for (mask, nid) in [
            (SSL_GOST89MAC, abi::NID_id_Gost28147_89_MAC),
            (SSL_GOST89MAC12, abi::NID_gost_mac_12),
            (SSL_MAGMAOMAC, abi::NID_magma_mac),
            (SSL_KUZNYECHIKOMAC, abi::NID_kuznyechik_mac),
        ] {
            if !offers.pkey(nid) {
                a.disabled_mac |= mask;
            }
        }
        if !offers.pkey(abi::NID_id_GostR3410_2001) {
            a.disabled_auth |= SSL_aGOST01 | SSL_aGOST12;
        }
        if !offers.pkey(abi::NID_id_GostR3410_2012_256)
            || !offers.pkey(abi::NID_id_GostR3410_2012_512)
        {
            a.disabled_auth |= SSL_aGOST12;
        }
        if a.disabled_auth & (SSL_aGOST01 | SSL_aGOST12) == (SSL_aGOST01 | SSL_aGOST12) {
            a.disabled_mkey |= SSL_kGOST;
        }
        if a.disabled_auth & SSL_aGOST12 == SSL_aGOST12 {
            a.disabled_mkey |= SSL_kGOST18;
        }
        a
    }

    /// What OpenSSL 3.5's default provider (the default build, no engines) offers: no DES, RC2,
    /// RC4, IDEA, or SEED (those are the legacy provider's), and no GOST.
    #[must_use]
    pub fn default_provider() -> Self {
        Self::from_offers(&DefaultProvider)
    }

    /// Whether a suite uses nothing unavailable.
    #[must_use]
    pub const fn allows(&self, c: &Cipher) -> bool {
        c.mkey & self.disabled_mkey == 0
            && c.auth & self.disabled_auth == 0
            && c.enc & self.disabled_enc == 0
            && c.mac & self.disabled_mac == 0
    }

    /// Whether a TLS 1.3 suite is usable: its encryption and its handshake digest's MAC bit
    /// (as `ssl_create_cipher_list` checks them).
    #[must_use]
    pub fn allows_tls13(&self, c: &Cipher) -> bool {
        let mac_mask = usize::try_from(c.handshake_digest_index())
            .ok()
            .and_then(|i| MAC_NIDS.get(i))
            .map_or(0, |&(m, _)| m);
        c.enc & self.disabled_enc == 0 && mac_mask & self.disabled_mac == 0
    }
}

/// `ssl_cipher_table_cipher`'s masks and NIDs (as in [`suites`]).
const CIPHER_TABLE: [(u32, c_int); 24] = [
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

/// OpenSSL 3.5's default provider, as `ssl_load_ciphers` sees it.
struct DefaultProvider;

impl Offers for DefaultProvider {
    fn cipher(&self, nid: c_int) -> bool {
        !matches!(
            nid,
            abi::NID_des_cbc
                | abi::NID_rc4
                | abi::NID_rc2_cbc
                | abi::NID_idea_cbc
                | abi::NID_seed_cbc
                | abi::NID_gost89_cnt
                | abi::NID_gost89_cnt_12
                | abi::NID_magma_ctr_acpkm
                | abi::NID_kuznyechik_ctr_acpkm
        )
    }

    fn digest(&self, nid: c_int) -> bool {
        !matches!(
            nid,
            abi::NID_id_GostR3411_94
                | abi::NID_id_Gost28147_89_MAC
                | abi::NID_id_GostR3411_2012_256
                | abi::NID_gost_mac_12
                | abi::NID_id_GostR3411_2012_512
                | abi::NID_magma_mac
                | abi::NID_kuznyechik_mac
        )
    }

    fn signature(&self, _: &str) -> bool {
        true
    }

    fn key_exchange(&self, _: &str) -> bool {
        true
    }

    fn pkey(&self, _: c_int) -> bool {
        false
    }
}

/// The method a list is built for (`SSL_METHOD`'s `ssl3_enc->enc_flags`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Method {
    /// A DTLS method: suites without a DTLS version are left out (otherwise those without a
    /// TLS version are).
    pub dtls: bool,
    /// The method can use TLS 1.2's suites (`SSL_ENC_FLAG_TLS1_2_CIPHERS`), which Suite B
    /// requires.
    pub tls12_ciphers: bool,
}

impl Method {
    /// `TLS_method()` and its client and server forms.
    pub const TLS: Self = Self {
        dtls: false,
        tls12_ciphers: true,
    };
    /// `DTLS_method()` and its client and server forms.
    pub const DTLS: Self = Self {
        dtls: true,
        tls12_ciphers: true,
    };
}

/// What a cipher string may change beyond the list (the `CERT`'s fields): `@SECLEVEL=n` sets
/// the security level, and a `SUITEB*` prefix the Suite B flags. They change even when the
/// string then fails, as in OpenSSL.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CertSettings {
    /// The security level.
    pub sec_level: c_int,
    /// The certificate flags (`SSL_CERT_FLAG_SUITEB_*` among them).
    pub cert_flags: u32,
}

/// A rule string failed: OpenSSL's reasons, in the order its errors are raised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    /// The `SSL_R_*` reasons raised.
    pub raised: Vec<c_int>,
}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        Error::quiet(
            e.raised
                .last()
                .copied()
                .unwrap_or(abi::SSL_R_INVALID_COMMAND),
        )
    }
}

/// `ssl_create_cipher_list`: the list for `rule`, the usable TLS 1.3 suites of `tls13` first.
/// Unusable TLS 1.3 suites are deleted from `tls13` itself, as OpenSSL deletes them from the
/// `SSL_CTX`'s or `SSL`'s list. An empty result isn't an error here: `SSL_CTX_set_cipher_list`
/// installs it and then fails with `SSL_R_NO_CIPHER_MATCH` when it has no TLS 1.2-and-earlier
/// suite ([`count_tls12`]).
///
/// # Errors
/// The string has a character that is neither a separator, an operator, nor part of a name
/// (`SSL_R_INVALID_COMMAND`), an unknown `@` command or level (the same), or asks for Suite B
/// with a method without TLS 1.2 suites (`SSL_R_AT_LEAST_TLS_1_2_NEEDED_IN_SUITEB_MODE`).
pub fn build(
    available: &Available,
    method: Method,
    tls13: &mut Vec<&'static Cipher>,
    rule: &str,
    cert: &mut CertSettings,
) -> Result<Vec<&'static Cipher>, ParseError> {
    let rule = check_suiteb(method, cert, rule)?;
    let mut list = List::collect(available, method);
    list.initial_order();
    let aliases: Vec<Entry> = list
        .order()
        .map(Entry::Cipher)
        .chain(
            ALIASES
                .iter()
                .filter(|a| a.usable(available))
                .map(Entry::Alias),
        )
        .collect();

    let mut raised = Vec::new();
    let mut rest = rule.as_bytes();
    let mut ok = true;
    if rest.starts_with(b"DEFAULT") {
        ok = list.process(DEFAULT_CIPHER_LIST.to_bytes(), &aliases, cert, &mut raised);
        rest = rest.get(7..).unwrap_or_default();
        if let Some(r) = rest.strip_prefix(b":") {
            rest = r;
        }
    }
    if ok && !rest.is_empty() {
        ok = list.process(rest, &aliases, cert, &mut raised);
    }
    if !ok {
        return Err(ParseError { raised });
    }

    tls13.retain(|c| available.allows_tls13(c));
    let mut out: Vec<&'static Cipher> = tls13.clone();
    out.extend(
        list.order()
            .filter(|&i| list.active(i))
            .filter_map(|i| list.cipher(i)),
    );
    Ok(out)
}

/// How many suites of `list` are TLS 1.2 or earlier (`cipher_list_tls12_num`).
#[must_use]
pub fn count_tls12(list: &[&Cipher]) -> usize {
    list.iter()
        .filter(|c| c.min_tls < abi::TLS1_3_VERSION)
        .count()
}

/// `update_cipher_list`: `list` with its leading TLS 1.3 suites replaced by the usable ones of
/// `tls13` (as `SSL_CTX_set_ciphersuites` does to an existing list). Only the leading run is
/// replaced, as in OpenSSL.
#[must_use]
pub fn replace_tls13(
    available: &Available,
    list: &[&'static Cipher],
    tls13: &[&'static Cipher],
) -> Vec<&'static Cipher> {
    let skip = list
        .iter()
        .take_while(|c| c.min_tls == abi::TLS1_3_VERSION)
        .count();
    let mut out: Vec<&'static Cipher> = tls13
        .iter()
        .copied()
        .filter(|c| available.allows_tls13(c))
        .collect();
    out.extend(list.iter().skip(skip).copied());
    out
}

/// `set_ciphersuites`: the suites named, colon-separated by RFC name with spaces around names
/// ignored. Unknown names, and names of 80 characters or more, are skipped; an empty string is
/// an empty list. Any suite may be named (OpenSSL looks the name up in every table), so a TLS
/// 1.2 suite named here joins the list too.
///
/// # Errors
/// The string isn't empty but names no suite (`SSL_R_NO_CIPHER_MATCH`).
pub fn parse_ciphersuites(s: &str) -> Result<Vec<&'static Cipher>, Error> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    let found: Vec<&'static Cipher> = s
        .split(':')
        .map(|e| e.trim_matches(|c: char| c.is_ascii_whitespace()))
        .filter(|e| !e.is_empty() && e.len() < 80)
        .filter_map(suites::by_std_name)
        .collect();
    if found.is_empty() {
        return Err(Error::quiet(abi::SSL_R_NO_CIPHER_MATCH));
    }
    Ok(found)
}

/// `check_suiteb_cipher_list`: a `SUITEB*` prefix sets the Suite B flags; with Suite B on
/// (now or from before), the whole string is replaced by Suite B's suites.
fn check_suiteb<'a>(
    method: Method,
    cert: &mut CertSettings,
    rule: &'a str,
) -> Result<&'a str, ParseError> {
    const ONLY: u32 = cbits(abi::SSL_CERT_FLAG_SUITEB_128_LOS_ONLY);
    const B192: u32 = cbits(abi::SSL_CERT_FLAG_SUITEB_192_LOS);
    const B128: u32 = cbits(abi::SSL_CERT_FLAG_SUITEB_128_LOS);
    let (mut flags, mut comb2) = (0, false);
    if rule.starts_with("SUITEB128ONLY") {
        flags = ONLY;
    } else if rule.starts_with("SUITEB128C2") {
        comb2 = true;
        flags = B128;
    } else if rule.starts_with("SUITEB128") {
        flags = B128;
    } else if rule.starts_with("SUITEB192") {
        flags = B192;
    }
    if flags != 0 {
        cert.cert_flags &= !B128;
        cert.cert_flags |= flags;
    } else {
        flags = cert.cert_flags & B128;
    }
    if flags == 0 {
        return Ok(rule);
    }
    if !method.tls12_ciphers {
        return Err(ParseError {
            raised: vec![abi::SSL_R_AT_LEAST_TLS_1_2_NEEDED_IN_SUITEB_MODE],
        });
    }
    Ok(match flags {
        B128 if !comb2 => "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384",
        ONLY => "ECDHE-ECDSA-AES128-GCM-SHA256",
        _ => "ECDHE-ECDSA-AES256-GCM-SHA384",
    })
}

/// A flag constant's bits.
#[expect(clippy::cast_sign_loss, reason = "the Suite B flags are positive")]
const fn cbits(v: c_int) -> u32 {
    v as u32
}

/// An alias of the cipher-string language (`cipher_aliases[]`).
struct Alias {
    name: &'static str,
    mkey: u32,
    auth: u32,
    enc: u32,
    mac: u32,
    min_tls: c_int,
    strength: u32,
}

impl Alias {
    /// `ssl_cipher_collect_aliases`: an alias naming algorithms is usable if one of them is
    /// available in each category it names.
    const fn usable(&self, a: &Available) -> bool {
        (self.mkey == 0 || self.mkey & !a.disabled_mkey != 0)
            && (self.auth == 0 || self.auth & !a.disabled_auth != 0)
            && (self.enc == 0 || self.enc & !a.disabled_enc != 0)
            && (self.mac == 0 || self.mac & !a.disabled_mac != 0)
    }
}

/// An alias's name from its header constant.
const fn txt(c: &'static CStr) -> &'static str {
    match c.to_str() {
        Ok(s) => s,
        Err(_) => "",
    }
}

/// An alias that selects by algorithms.
const fn alg(name: &'static CStr, mkey: u32, auth: u32, enc: u32, mac: u32) -> Alias {
    Alias {
        name: txt(name),
        mkey,
        auth,
        enc,
        mac,
        min_tls: 0,
        strength: 0,
    }
}

/// An alias that selects by strength.
const fn strength(name: &'static CStr, enc: u32, s: u32) -> Alias {
    Alias {
        name: txt(name),
        mkey: 0,
        auth: 0,
        enc,
        mac: 0,
        min_tls: 0,
        strength: s,
    }
}

/// An alias that selects by the version a suite was introduced in.
const fn version(name: &'static str, v: c_int) -> Alias {
    Alias {
        name,
        mkey: 0,
        auth: 0,
        enc: 0,
        mac: 0,
        min_tls: v,
        strength: 0,
    }
}

/// `cipher_aliases[]`, in OpenSSL's order.
static ALIASES: &[Alias] = &[
    alg(abi::SSL_TXT_ALL, 0, 0, !SSL_eNULL, 0),
    alg(abi::SSL_TXT_CMPALL, 0, 0, SSL_eNULL, 0),
    strength(abi::SSL_TXT_CMPDEF, 0, SSL_NOT_DEFAULT),
    alg(abi::SSL_TXT_kRSA, SSL_kRSA, 0, 0, 0),
    alg(abi::SSL_TXT_kEDH, SSL_kDHE, 0, 0, 0),
    alg(abi::SSL_TXT_kDHE, SSL_kDHE, 0, 0, 0),
    alg(abi::SSL_TXT_DH, SSL_kDHE, 0, 0, 0),
    alg(abi::SSL_TXT_kEECDH, SSL_kECDHE, 0, 0, 0),
    alg(abi::SSL_TXT_kECDHE, SSL_kECDHE, 0, 0, 0),
    alg(abi::SSL_TXT_ECDH, SSL_kECDHE, 0, 0, 0),
    alg(abi::SSL_TXT_kPSK, SSL_kPSK, 0, 0, 0),
    alg(abi::SSL_TXT_kRSAPSK, SSL_kRSAPSK, 0, 0, 0),
    alg(abi::SSL_TXT_kECDHEPSK, SSL_kECDHEPSK, 0, 0, 0),
    alg(abi::SSL_TXT_kDHEPSK, SSL_kDHEPSK, 0, 0, 0),
    alg(abi::SSL_TXT_kSRP, SSL_kSRP, 0, 0, 0),
    alg(abi::SSL_TXT_kGOST, SSL_kGOST, 0, 0, 0),
    alg(abi::SSL_TXT_kGOST18, SSL_kGOST18, 0, 0, 0),
    alg(abi::SSL_TXT_aRSA, 0, SSL_aRSA, 0, 0),
    alg(abi::SSL_TXT_aDSS, 0, SSL_aDSS, 0, 0),
    alg(abi::SSL_TXT_DSS, 0, SSL_aDSS, 0, 0),
    alg(abi::SSL_TXT_aNULL, 0, SSL_aNULL, 0, 0),
    alg(abi::SSL_TXT_aECDSA, 0, SSL_aECDSA, 0, 0),
    alg(abi::SSL_TXT_ECDSA, 0, SSL_aECDSA, 0, 0),
    alg(abi::SSL_TXT_aPSK, 0, SSL_aPSK, 0, 0),
    alg(abi::SSL_TXT_aGOST01, 0, SSL_aGOST01, 0, 0),
    alg(abi::SSL_TXT_aGOST12, 0, SSL_aGOST12, 0, 0),
    alg(abi::SSL_TXT_aGOST, 0, SSL_aGOST01 | SSL_aGOST12, 0, 0),
    alg(abi::SSL_TXT_aSRP, 0, SSL_aSRP, 0, 0),
    alg(abi::SSL_TXT_EDH, SSL_kDHE, !SSL_aNULL, 0, 0),
    alg(abi::SSL_TXT_DHE, SSL_kDHE, !SSL_aNULL, 0, 0),
    alg(abi::SSL_TXT_EECDH, SSL_kECDHE, !SSL_aNULL, 0, 0),
    alg(abi::SSL_TXT_ECDHE, SSL_kECDHE, !SSL_aNULL, 0, 0),
    alg(abi::SSL_TXT_NULL, 0, 0, SSL_eNULL, 0),
    alg(abi::SSL_TXT_RSA, SSL_kRSA, SSL_aRSA, 0, 0),
    alg(abi::SSL_TXT_ADH, SSL_kDHE, SSL_aNULL, 0, 0),
    alg(abi::SSL_TXT_AECDH, SSL_kECDHE, SSL_aNULL, 0, 0),
    alg(abi::SSL_TXT_PSK, SSL_PSK, 0, 0, 0),
    alg(abi::SSL_TXT_SRP, SSL_kSRP, 0, 0, 0),
    alg(abi::SSL_TXT_3DES, 0, 0, SSL_3DES, 0),
    alg(abi::SSL_TXT_RC4, 0, 0, SSL_RC4, 0),
    alg(abi::SSL_TXT_RC2, 0, 0, SSL_RC2, 0),
    alg(abi::SSL_TXT_IDEA, 0, 0, SSL_IDEA, 0),
    alg(abi::SSL_TXT_SEED, 0, 0, SSL_SEED, 0),
    alg(abi::SSL_TXT_eNULL, 0, 0, SSL_eNULL, 0),
    alg(
        abi::SSL_TXT_GOST,
        0,
        0,
        SSL_eGOST2814789CNT | SSL_eGOST2814789CNT12 | SSL_MAGMA | SSL_KUZNYECHIK,
        0,
    ),
    alg(
        abi::SSL_TXT_AES128,
        0,
        0,
        SSL_AES128 | SSL_AES128GCM | SSL_AES128CCM | SSL_AES128CCM8,
        0,
    ),
    alg(
        abi::SSL_TXT_AES256,
        0,
        0,
        SSL_AES256 | SSL_AES256GCM | SSL_AES256CCM | SSL_AES256CCM8,
        0,
    ),
    alg(abi::SSL_TXT_AES, 0, 0, SSL_AES, 0),
    alg(abi::SSL_TXT_AES_GCM, 0, 0, SSL_AES128GCM | SSL_AES256GCM, 0),
    alg(
        abi::SSL_TXT_AES_CCM,
        0,
        0,
        SSL_AES128CCM | SSL_AES256CCM | SSL_AES128CCM8 | SSL_AES256CCM8,
        0,
    ),
    alg(
        abi::SSL_TXT_AES_CCM_8,
        0,
        0,
        SSL_AES128CCM8 | SSL_AES256CCM8,
        0,
    ),
    alg(abi::SSL_TXT_CAMELLIA128, 0, 0, SSL_CAMELLIA128, 0),
    alg(abi::SSL_TXT_CAMELLIA256, 0, 0, SSL_CAMELLIA256, 0),
    alg(abi::SSL_TXT_CAMELLIA, 0, 0, SSL_CAMELLIA, 0),
    alg(abi::SSL_TXT_CHACHA20, 0, 0, SSL_CHACHA20, 0),
    alg(
        abi::SSL_TXT_GOST2012_GOST8912_GOST8912,
        0,
        0,
        SSL_eGOST2814789CNT12,
        0,
    ),
    alg(abi::SSL_TXT_ARIA, 0, 0, SSL_ARIA, 0),
    alg(
        abi::SSL_TXT_ARIA_GCM,
        0,
        0,
        SSL_ARIA128GCM | SSL_ARIA256GCM,
        0,
    ),
    alg(abi::SSL_TXT_ARIA128, 0, 0, SSL_ARIA128GCM, 0),
    alg(abi::SSL_TXT_ARIA256, 0, 0, SSL_ARIA256GCM, 0),
    alg(abi::SSL_TXT_CBC, 0, 0, SSL_CBC, 0),
    alg(abi::SSL_TXT_MD5, 0, 0, 0, SSL_MD5),
    alg(abi::SSL_TXT_SHA1, 0, 0, 0, SSL_SHA1),
    alg(abi::SSL_TXT_SHA, 0, 0, 0, SSL_SHA1),
    alg(abi::SSL_TXT_GOST94, 0, 0, 0, SSL_GOST94),
    alg(
        abi::SSL_TXT_GOST89MAC,
        0,
        0,
        0,
        SSL_GOST89MAC | SSL_GOST89MAC12,
    ),
    alg(abi::SSL_TXT_SHA256, 0, 0, 0, SSL_SHA256),
    alg(abi::SSL_TXT_SHA384, 0, 0, 0, SSL_SHA384),
    alg(abi::SSL_TXT_GOST12, 0, 0, 0, SSL_GOST12_256),
    version(txt(abi::SSL_TXT_SSLV3), abi::SSL3_VERSION),
    version(txt(abi::SSL_TXT_TLSV1), abi::TLS1_VERSION),
    version("TLSv1.0", abi::TLS1_VERSION),
    version(txt(abi::SSL_TXT_TLSV1_2), abi::TLS1_2_VERSION),
    strength(abi::SSL_TXT_LOW, 0, SSL_LOW),
    strength(abi::SSL_TXT_MEDIUM, 0, SSL_MEDIUM),
    strength(abi::SSL_TXT_HIGH, 0, SSL_HIGH),
    strength(abi::SSL_TXT_FIPS, !SSL_eNULL, SSL_FIPS),
    Alias {
        name: txt(abi::SSL3_TXT_EDH_DSS_DES_192_CBC3_SHA),
        mkey: SSL_kDHE,
        auth: SSL_aDSS,
        enc: SSL_3DES,
        mac: SSL_SHA1,
        min_tls: 0,
        strength: SSL_HIGH | SSL_FIPS,
    },
    Alias {
        name: txt(abi::SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA),
        mkey: SSL_kDHE,
        auth: SSL_aRSA,
        enc: SSL_3DES,
        mac: SSL_SHA1,
        min_tls: 0,
        strength: SSL_HIGH | SSL_FIPS,
    },
];

/// A name the rules can use: a suite (matching itself, by either name) or an alias.
#[derive(Clone, Copy)]
enum Entry {
    /// A suite of the list, by its node.
    Cipher(usize),
    /// An alias.
    Alias(&'static Alias),
}

/// What a rule does (`ssl_cipher_apply_rule`'s operation).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    /// Append at the end if not yet active (`CIPHER_ADD`, no operator).
    Add,
    /// Remove for good (`CIPHER_KILL`, `!`).
    Kill,
    /// Deactivate, moving to the front for a later add (`CIPHER_DEL`, `-`).
    Del,
    /// Move active ones to the end (`CIPHER_ORD`, `+`).
    Ord,
    /// Move active ones to the front (`CIPHER_BUMP`, internal only).
    Bump,
}

/// What a rule selects: suites matching every non-zero part.
#[derive(Clone, Copy, Default)]
struct Select {
    cipher_id: u32,
    mkey: u32,
    auth: u32,
    enc: u32,
    mac: u32,
    min_tls: c_int,
    strength: u32,
}

impl Select {
    fn matches(&self, c: &Cipher) -> bool {
        (self.cipher_id == 0 || self.cipher_id == c.id)
            && (self.mkey == 0 || self.mkey & c.mkey != 0)
            && (self.auth == 0 || self.auth & c.auth != 0)
            && (self.enc == 0 || self.enc & c.enc != 0)
            && (self.mac == 0 || self.mac & c.mac != 0)
            && (self.min_tls == 0 || self.min_tls == c.min_tls)
            && (self.strength & SSL_STRONG_MASK == 0
                || self.strength & SSL_STRONG_MASK & c.strength != 0)
            && (self.strength & SSL_DEFAULT_MASK == 0
                || self.strength & SSL_DEFAULT_MASK & c.strength != 0)
    }
}

/// A node of the list (`CIPHER_ORDER`).
struct Node {
    cipher: &'static Cipher,
    active: bool,
    prev: Option<usize>,
    next: Option<usize>,
}

/// The doubly linked list the rules rearrange.
struct List {
    nodes: Vec<Node>,
    head: Option<usize>,
    tail: Option<usize>,
}

/// `ITEM_SEP`.
const fn is_sep(b: u8) -> bool {
    matches!(b, b':' | b' ' | b';' | b',')
}

/// A character of a name in a rule.
const fn is_name(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'=')
}

impl List {
    /// `ssl_cipher_collect_ciphers`: the method's suites, in descending id order, without those
    /// using anything unavailable or without a version for the method.
    fn collect(available: &Available, method: Method) -> Self {
        let mut nodes: Vec<Node> = suites::ssl3_by_descending_id()
            .iter()
            .copied()
            .filter(|c| c.valid && available.allows(c))
            .filter(|c| {
                if method.dtls {
                    c.min_dtls != 0
                } else {
                    c.min_tls != 0
                }
            })
            .map(|cipher| Node {
                cipher,
                active: false,
                prev: None,
                next: None,
            })
            .collect();
        let n = nodes.len();
        for (i, node) in nodes.iter_mut().enumerate() {
            node.prev = i.checked_sub(1);
            node.next = i.checked_add(1).filter(|&j| j < n);
        }
        let head = if n > 0 { Some(0) } else { None };
        Self {
            nodes,
            head,
            tail: n.checked_sub(1),
        }
    }

    fn cipher(&self, i: usize) -> Option<&'static Cipher> {
        self.nodes.get(i).map(|n| n.cipher)
    }

    fn active(&self, i: usize) -> bool {
        self.nodes.get(i).is_some_and(|n| n.active)
    }

    fn next_of(&self, i: usize) -> Option<usize> {
        self.nodes.get(i).and_then(|n| n.next)
    }

    fn prev_of(&self, i: usize) -> Option<usize> {
        self.nodes.get(i).and_then(|n| n.prev)
    }

    fn set_next(&mut self, i: usize, v: Option<usize>) {
        if let Some(n) = self.nodes.get_mut(i) {
            n.next = v;
        }
    }

    fn set_prev(&mut self, i: usize, v: Option<usize>) {
        if let Some(n) = self.nodes.get_mut(i) {
            n.prev = v;
        }
    }

    fn set_active(&mut self, i: usize, v: bool) {
        if let Some(n) = self.nodes.get_mut(i) {
            n.active = v;
        }
    }

    /// The nodes from head to tail.
    fn order(&self) -> impl Iterator<Item = usize> + '_ {
        core::iter::successors(self.head, |&i| self.next_of(i))
    }

    /// Takes `i` out of the chain, mending its neighbors' links.
    fn unlink_neighbors(&mut self, i: usize) {
        let (prev, next) = (self.prev_of(i), self.next_of(i));
        if let Some(p) = prev {
            self.set_next(p, next);
        }
        if let Some(n) = next {
            self.set_prev(n, prev);
        }
    }

    /// `ll_append_tail`.
    fn append_tail(&mut self, i: usize) {
        if self.tail == Some(i) {
            return;
        }
        if self.head == Some(i) {
            self.head = self.next_of(i);
        }
        self.unlink_neighbors(i);
        if let Some(t) = self.tail {
            self.set_next(t, Some(i));
        }
        self.set_prev(i, self.tail);
        self.set_next(i, None);
        self.tail = Some(i);
    }

    /// `ll_append_head`.
    fn append_head(&mut self, i: usize) {
        if self.head == Some(i) {
            return;
        }
        if self.tail == Some(i) {
            self.tail = self.prev_of(i);
        }
        self.unlink_neighbors(i);
        if let Some(h) = self.head {
            self.set_prev(h, Some(i));
        }
        self.set_next(i, self.head);
        self.set_prev(i, None);
        self.head = Some(i);
    }

    /// `CIPHER_KILL`'s removal.
    fn remove(&mut self, i: usize) {
        if self.head == Some(i) {
            self.head = self.next_of(i);
        }
        if self.tail == Some(i) {
            self.tail = self.prev_of(i);
        }
        self.set_active(i, false);
        self.unlink_neighbors(i);
        self.set_next(i, None);
        self.set_prev(i, None);
    }

    /// `ssl_cipher_apply_rule`. The walk ends at the node that was last when it started (for
    /// `-` and the internal bump, which walk backwards, the first), so a node moved past it
    /// isn't visited again.
    fn apply(&mut self, sel: &Select, op: Op, strength_bits: Option<i32>) {
        let reverse = matches!(op, Op::Del | Op::Bump);
        let (mut next, last) = if reverse {
            (self.tail, self.head)
        } else {
            (self.head, self.tail)
        };
        let mut curr: Option<usize> = None;
        loop {
            if curr == last {
                break;
            }
            curr = next;
            let Some(c) = curr else { break };
            next = if reverse {
                self.prev_of(c)
            } else {
                self.next_of(c)
            };
            let Some(cp) = self.cipher(c) else { break };
            let hit = match strength_bits {
                Some(bits) => bits == cp.strength_bits,
                None => sel.matches(cp),
            };
            if !hit {
                continue;
            }
            match op {
                Op::Add => {
                    if !self.active(c) {
                        self.append_tail(c);
                        self.set_active(c, true);
                    }
                }
                Op::Ord => {
                    if self.active(c) {
                        self.append_tail(c);
                    }
                }
                Op::Del => {
                    if self.active(c) {
                        self.append_head(c);
                        self.set_active(c, false);
                    }
                }
                Op::Bump => {
                    if self.active(c) {
                        self.append_head(c);
                    }
                }
                Op::Kill => self.remove(c),
            }
        }
    }

    /// `ssl_cipher_strength_sort`: the active suites by descending strength, keeping the order
    /// within each strength.
    fn strength_sort(&mut self) {
        let used: BTreeSet<i32> = self
            .order()
            .filter(|&i| self.active(i))
            .filter_map(|i| self.cipher(i).map(|c| c.strength_bits))
            .collect();
        for bits in used.into_iter().rev() {
            self.apply(&Select::default(), Op::Ord, Some(bits));
        }
    }

    /// `ssl_create_cipher_list`'s preference order, before the rules (every suite inactive).
    fn initial_order(&mut self) {
        let k = |mkey, auth| Select {
            mkey,
            auth,
            ..Select::default()
        };
        let e = |enc| Select {
            enc,
            ..Select::default()
        };
        let m = |mac| Select {
            mac,
            ..Select::default()
        };
        // Prefer ECDHE, and ECDSA over RSA within it.
        self.apply(&k(SSL_kECDHE, SSL_aECDSA), Op::Add, None);
        self.apply(&k(SSL_kECDHE, 0), Op::Add, None);
        self.apply(&k(SSL_kECDHE, 0), Op::Del, None);
        // GCM over ChaCha, and AES generally.
        self.apply(&e(SSL_AESGCM), Op::Add, None);
        self.apply(&e(SSL_CHACHA20), Op::Add, None);
        self.apply(&e(SSL_AES ^ SSL_AESGCM), Op::Add, None);
        // Everything else, for sorting.
        self.apply(&Select::default(), Op::Add, None);
        // MD5, anonymous, RSA and PSK key exchange, RC4: last.
        self.apply(&m(SSL_MD5), Op::Ord, None);
        self.apply(&k(0, SSL_aNULL), Op::Ord, None);
        self.apply(&k(SSL_kRSA, 0), Op::Ord, None);
        self.apply(&k(SSL_kPSK, 0), Op::Ord, None);
        self.apply(&e(SSL_RC4), Op::Ord, None);
        self.strength_sort();
        // TLS 1.2's suites and PRFs over legacy ones.
        let tls12 = Select {
            min_tls: abi::TLS1_2_VERSION,
            ..Select::default()
        };
        self.apply(&tls12, Op::Bump, None);
        // (EC)DHE + AEAD > (EC)DHE > rest of AEAD > rest, bumped in reverse.
        self.apply(&m(SSL_AEAD), Op::Bump, None);
        self.apply(&k(SSL_kDHE | SSL_kECDHE, 0), Op::Bump, None);
        let dhe_aead = Select {
            mkey: SSL_kDHE | SSL_kECDHE,
            mac: SSL_AEAD,
            ..Select::default()
        };
        self.apply(&dhe_aead, Op::Bump, None);
        // All inactive again, keeping the order.
        self.apply(&Select::default(), Op::Del, None);
    }

    /// `ssl_cipher_process_rulestr`: applies each rule of `rule`. False if it failed; the
    /// reasons raised are pushed to `raised`.
    fn process(
        &mut self,
        rule: &[u8],
        names: &[Entry],
        cert: &mut CertSettings,
        raised: &mut Vec<c_int>,
    ) -> bool {
        let at = |l: usize| rule.get(l).copied().unwrap_or(0);
        let mut ok = true;
        let mut l = 0usize;
        loop {
            let ch = at(l);
            if ch == 0 {
                break;
            }
            let op = match ch {
                b'-' => Some(Op::Del),
                b'+' => Some(Op::Ord),
                b'!' => Some(Op::Kill),
                b'@' => None,
                _ => Some(Op::Add),
            };
            if matches!(ch, b'-' | b'+' | b'!' | b'@') {
                l = l.saturating_add(1);
            } else if is_sep(ch) {
                l = l.saturating_add(1);
                continue;
            }

            let mut sel = Select::default();
            let mut found = false;
            let mut word: &[u8];
            loop {
                let start = l;
                while is_name(at(l)) {
                    l = l.saturating_add(1);
                }
                word = rule.get(start..l).unwrap_or_default();
                if word.is_empty() {
                    raised.push(abi::SSL_R_INVALID_COMMAND);
                    return false;
                }
                if op.is_none() {
                    break;
                }
                let multi = at(l) == b'+';
                if multi {
                    l = l.saturating_add(1);
                }
                let Some(entry) = self.lookup(names, word) else {
                    found = false;
                    break;
                };
                found = combine(&mut sel, entry, self);
                if !found || !multi {
                    break;
                }
            }

            match op {
                None => {
                    if !self.special(word, cert, raised) {
                        ok = false;
                    }
                    while at(l) != 0 && !is_sep(at(l)) {
                        l = l.saturating_add(1);
                    }
                }
                Some(op) if found => self.apply(&sel, op, None),
                Some(_) => {
                    while at(l) != 0 && !is_sep(at(l)) {
                        l = l.saturating_add(1);
                    }
                }
            }
            if at(l) == 0 {
                break;
            }
        }
        ok
    }

    /// An `@` command: `@STRENGTH`, or `@SECLEVEL=n` for n in 0 to 5. False (with
    /// `SSL_R_INVALID_COMMAND` raised) for anything else.
    fn special(&mut self, word: &[u8], cert: &mut CertSettings, raised: &mut Vec<c_int>) -> bool {
        if word == b"STRENGTH" {
            self.strength_sort();
            return true;
        }
        if let Some(&[d]) = word.strip_prefix(b"SECLEVEL=") {
            let level = c_int::from(d).saturating_sub(c_int::from(b'0'));
            if (0..=5).contains(&level) {
                cert.sec_level = level;
                return true;
            }
        }
        raised.push(abi::SSL_R_INVALID_COMMAND);
        false
    }

    /// The first entry named `word` (a suite by either of its names, or an alias).
    fn lookup(&self, names: &[Entry], word: &[u8]) -> Option<Entry> {
        names.iter().copied().find(|e| match *e {
            Entry::Cipher(i) => self.cipher(i).is_some_and(|c| {
                c.name.to_bytes() == word || c.stdname.is_some_and(|s| s.to_bytes() == word)
            }),
            Entry::Alias(a) => a.name.as_bytes() == word,
        })
    }
}

/// Adds an entry to a multi-part selection (`AES+SHA1`): each category it names is ANDed with
/// what the earlier parts named. False if a category becomes empty (the rule then matches
/// nothing). A suite named explicitly selects itself by id; an alias's version joins the
/// selection, and must agree with an earlier one.
fn combine(sel: &mut Select, entry: Entry, list: &List) -> bool {
    let (mkey, auth, enc, mac, strength, min_tls, id) = match entry {
        Entry::Cipher(i) => match list.cipher(i) {
            Some(c) => (c.mkey, c.auth, c.enc, c.mac, c.strength, 0, Some(c.id)),
            None => return false,
        },
        Entry::Alias(a) => (a.mkey, a.auth, a.enc, a.mac, a.strength, a.min_tls, None),
    };
    for (have, add) in [
        (&mut sel.mkey, mkey),
        (&mut sel.auth, auth),
        (&mut sel.enc, enc),
        (&mut sel.mac, mac),
    ] {
        if add != 0 {
            if *have == 0 {
                *have = add;
            } else {
                *have &= add;
                if *have == 0 {
                    return false;
                }
            }
        }
    }
    if strength & SSL_STRONG_MASK != 0 {
        if sel.strength & SSL_STRONG_MASK == 0 {
            // OpenSSL assigns here, so a not-default bit from an earlier part is dropped
            // (`COMPLEMENTOFDEFAULT+HIGH` selects all HIGH suites).
            sel.strength = strength & SSL_STRONG_MASK;
        } else {
            sel.strength &= (strength & SSL_STRONG_MASK) | !SSL_STRONG_MASK;
            if sel.strength & SSL_STRONG_MASK == 0 {
                return false;
            }
        }
    }
    if strength & SSL_DEFAULT_MASK != 0 {
        if sel.strength & SSL_DEFAULT_MASK == 0 {
            sel.strength |= strength & SSL_DEFAULT_MASK;
        } else {
            sel.strength &= (strength & SSL_DEFAULT_MASK) | !SSL_DEFAULT_MASK;
            if sel.strength & SSL_DEFAULT_MASK == 0 {
                return false;
            }
        }
    }
    match id {
        Some(id) => sel.cipher_id = id,
        None => {
            if min_tls != 0 {
                if sel.min_tls != 0 && sel.min_tls != min_tls {
                    return false;
                }
                sel.min_tls = min_tls;
            }
        }
    }
    true
}
