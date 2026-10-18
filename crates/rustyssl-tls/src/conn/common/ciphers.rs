//! Cipher suites in the handshake: which a client may offer (`ssl_set_client_disabled`,
//! `ssl_cipher_disabled`, `ssl_cipher_list_to_bytes`), what a server reads
//! (`ossl_bytes_to_cipher_list`), which it can serve (`ssl_set_masks`), and its choice
//! (`ssl3_choose_cipher`).

use core::cmp::Ordering;
use core::ffi::c_int;

use rustyssl_abi as abi;

use super::security::{self, SecOther};
use super::sigalgs::{
    self, PKEY_DSA_SIGN, PKEY_ECC, PKEY_ED448, PKEY_ED25519, PKEY_RSA, PKEY_RSA_PSS_SIGN,
};
use super::{groups, version};
use crate::codec::{Reader, Writer};
use crate::conn::Connection;
use crate::error::{Error, Result};
use crate::suites::masks::{
    SSL_CHACHA20POLY1305, SSL_PSK, SSL_aDSS, SSL_aECDSA, SSL_aNULL, SSL_aPSK, SSL_aRSA, SSL_aSRP,
    SSL_kDHE, SSL_kDHEPSK, SSL_kECDHE, SSL_kECDHEPSK, SSL_kPSK, SSL_kRSA, SSL_kRSAPSK, SSL_kSRP,
};
use crate::suites::{self, Cipher};

/// `ssl_set_client_disabled`: the client's masks of key exchanges and authentications it can't
/// do (no signature algorithm for the authentication; PSK without a callback; SRP without a
/// username), and its version range.
///
/// # Errors
/// No version enabled (the reason).
pub fn set_client_disabled(c: &mut Connection) -> core::result::Result<(), c_int> {
    let mut mask_a = sigalgs::sig_mask(c, abi::SSL_SECOP_SIGALG_MASK);
    let mut mask_k = 0;
    let (min, max, _) = version::min_max(c)?;
    c.hs.sh.min_ver = min;
    c.hs.sh.max_ver = max;
    if !c.cfg.callbacks.psk {
        mask_a |= SSL_aPSK;
        mask_k |= SSL_PSK;
    }
    if !c.cfg.srp {
        mask_a |= SSL_aSRP;
        mask_k |= SSL_kSRP;
    }
    c.hs.sh.mask_a = mask_a;
    c.hs.sh.mask_k = mask_k;
    Ok(())
}

/// `ssl_cipher_disabled`: whether suite `cp` is out for this end: masked, outside the version
/// range, or refused by the security level for `op`. With `ecdhe`, a client allows TLS 1.0
/// ECDHE suites in SSLv3 (as OpenSSL does "for historical reasons").
#[must_use]
pub fn disabled(c: &Connection, cp: &Cipher, op: c_int, ecdhe: bool) -> bool {
    let sh = &c.hs.sh;
    if cp.mkey & sh.mask_k != 0 || cp.auth & sh.mask_a != 0 {
        return true;
    }
    if sh.max_ver == 0 {
        return true;
    }
    if c.cfg.quic {
        let id = cp.id;
        let ok = [
            abi::TLS1_3_CK_AES_128_GCM_SHA256,
            abi::TLS1_3_CK_AES_256_GCM_SHA384,
            abi::TLS1_3_CK_CHACHA20_POLY1305_SHA256,
        ]
        .iter()
        .any(|&x| suites::cid(x) == id);
        if !ok {
            return true;
        }
    }
    let mut minv = cp.min_tls;
    let maxv = cp.max_tls;
    if minv == abi::TLS1_VERSION && ecdhe && cp.mkey & (SSL_kECDHE | SSL_kECDHEPSK) != 0 {
        minv = abi::SSL3_VERSION;
    }
    if minv > c_int::from(sh.max_ver) || maxv < c_int::from(sh.min_ver) {
        return true;
    }
    !security::check(c, op, cp.strength_bits, 0, SecOther::Cipher(cp))
}

/// `ssl_cipher_list_to_bytes`: the ClientHello's cipher_suites: the enabled suites of the
/// cipher list, then `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` (first handshake, TLS 1.0 allowed)
/// and `TLS_FALLBACK_SCSV` (`SSL_MODE_SEND_FALLBACK_SCSV`). Sets the client's masks first.
///
/// # Errors
/// No version (`SSL_R_NO_PROTOCOLS_AVAILABLE`), or no suite for the highest version
/// (`SSL_R_NO_CIPHERS_AVAILABLE`), both with internal_error.
pub fn cipher_list_to_bytes(c: &mut Connection) -> Result<Vec<u8>> {
    let reneg_scsv = !c.renegotiate
        && security::check(
            c,
            abi::SSL_SECOP_VERSION,
            0,
            abi::TLS1_VERSION,
            SecOther::None,
        )
        && c_int::from(c.cfg.min_version) <= abi::TLS1_VERSION;
    if set_client_disabled(c).is_err() {
        return Err(Error::alert(
            abi::SSL_AD_INTERNAL_ERROR,
            abi::SSL_R_NO_PROTOCOLS_AVAILABLE,
        ));
    }
    let fallback = c.cfg.mode & u64::from(abi::SSL_MODE_SEND_FALLBACK_SCSV) != 0;
    let mut maxlen: usize = 0xfffe;
    if reneg_scsv {
        maxlen = maxlen.saturating_sub(2);
    }
    if fallback {
        maxlen = maxlen.saturating_sub(2);
    }
    let mut w = Writer::new();
    let mut maxverok = false;
    let max_ver = c_int::from(c.hs.sh.max_ver);
    for cp in &c.cfg.ciphers {
        if w.len() >= maxlen {
            break;
        }
        if disabled(c, cp, abi::SSL_SECOP_CIPHER_SUPPORTED, false) {
            continue;
        }
        w.u16(cp.protocol_id());
        if !maxverok && cp.max_tls >= max_ver && cp.min_tls <= max_ver {
            maxverok = true;
        }
    }
    if w.is_empty() || !maxverok {
        let e = Error::alert(abi::SSL_AD_INTERNAL_ERROR, abi::SSL_R_NO_CIPHERS_AVAILABLE);
        return Err(if maxverok {
            e
        } else {
            e.with_data("No ciphers enabled for max supported SSL/TLS version")
        });
    }
    if reneg_scsv {
        w.u16(proto(abi::SSL3_CK_SCSV));
    }
    if fallback {
        w.u16(proto(abi::SSL3_CK_FALLBACK_SCSV));
    }
    Ok(w.into_bytes())
}

/// A suite constant's two wire octets.
fn proto(id: c_int) -> u16 {
    u16::try_from(id & 0xffff).unwrap_or(0)
}

/// `ossl_bytes_to_cipher_list`: a received cipher_suites list (2-octet entries, or 3-octet
/// ones from an SSLv2-format ClientHello, where entries with a non-zero first octet are
/// SSLv2's and skipped): the known suites in order, and the signalling values separately.
/// Unknown values are dropped. With `fatal`, failures carry OpenSSL's alerts; without it
/// (`SSL_bytes_to_cipher_list`) they are only raised.
///
/// # Errors
/// Empty (`SSL_R_NO_CIPHERS_SPECIFIED`), a partial entry
/// (`SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST`).
pub fn bytes_to_cipher_list(
    raw: &[u8],
    sslv2: bool,
    fatal: bool,
) -> Result<(Vec<&'static Cipher>, Vec<&'static Cipher>)> {
    let n = if sslv2 { 3 } else { 2 };
    let err = |alert: c_int, reason: c_int| {
        if fatal {
            Error::alert(alert, reason)
        } else {
            Error::quiet(reason)
        }
    };
    if raw.is_empty() {
        return Err(err(
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_R_NO_CIPHERS_SPECIFIED,
        ));
    }
    if !raw.len().is_multiple_of(n) {
        return Err(err(
            abi::SSL_AD_DECODE_ERROR,
            abi::SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST,
        ));
    }
    let mut sk = Vec::new();
    let mut scsvs = Vec::new();
    let mut rd = Reader::new(raw);
    while let Ok(entry) = rd.take(n) {
        let mut e = Reader::new(entry);
        if sslv2 && e.u8().unwrap_or(1) != 0 {
            continue;
        }
        let Ok(id) = e.u16() else { continue };
        if let Some(cp) = suites::by_protocol_id(id) {
            if cp.valid {
                sk.push(cp)
            } else {
                scsvs.push(cp)
            }
        }
    }
    Ok((sk, scsvs))
}

/// `ssl_cache_cipherlist`'s checks and conversion: a server keeps the raw list in TLS form
/// (`SSL_client_hello_get0_ciphers`). An SSLv2 list's SSLv2-only entries are dropped.
///
/// # Errors
/// Empty (`SSL_R_NO_CIPHERS_SPECIFIED`), partial entries
/// (`SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST`), all with decode_error.
pub fn cache_cipherlist(raw: &[u8], sslv2: bool) -> Result<Vec<u8>> {
    let n = if sslv2 { 3 } else { 2 };
    if raw.is_empty() {
        return Err(Error::decode(abi::SSL_R_NO_CIPHERS_SPECIFIED));
    }
    if !raw.len().is_multiple_of(n) {
        return Err(Error::decode(abi::SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST));
    }
    if !sslv2 {
        return Ok(raw.to_vec());
    }
    let mut out = Vec::new();
    let mut rd = Reader::new(raw);
    while let Ok(entry) = rd.take(3) {
        if let Some((&0, rest)) = entry.split_first() {
            out.extend_from_slice(rest);
        }
    }
    Ok(out)
}

/// A flag of the validity flags.
fn flag(v: c_int) -> u32 {
    u32::try_from(v).unwrap_or(0)
}

/// `ssl_set_masks` (servers): the key exchanges and authentications this end can serve with
/// its certificates and settings.
pub fn set_masks(c: &mut Connection) {
    let pv = |slot: usize| c.hs.sh.valid_flags.get(slot).copied().unwrap_or(0);
    let valid = flag(abi::CERT_PKEY_VALID);
    let rpk = flag(abi::CERT_PKEY_RPK);
    let rsa_enc = pv(PKEY_RSA) & valid != 0;
    let dsa_sign = pv(PKEY_DSA_SIGN) & valid != 0;
    let have_ecc = pv(PKEY_ECC) & valid != 0;
    let tls12 = c.neg.version == version::of(abi::TLS1_2_VERSION);
    let mut mask_k = 0;
    let mut mask_a = 0;
    if rsa_enc {
        mask_k |= SSL_kRSA;
    }
    if c.cfg.dh_tmp {
        mask_k |= SSL_kDHE;
    }
    if rsa_enc
        || (sigalgs::has_cert(c, PKEY_RSA_PSS_SIGN)
            && pv(PKEY_RSA_PSS_SIGN) & flag(abi::CERT_PKEY_EXPLICIT_SIGN) != 0
            && tls12)
    {
        mask_a |= SSL_aRSA;
    }
    if dsa_sign {
        mask_a |= SSL_aDSS;
    }
    mask_a |= SSL_aNULL;
    if pv(PKEY_RSA) & rpk != 0 {
        mask_a |= SSL_aRSA;
        mask_k |= SSL_kRSA;
    }
    if pv(PKEY_ECC) & rpk != 0 {
        mask_a |= SSL_aECDSA;
    }
    if tls12 {
        if pv(PKEY_RSA_PSS_SIGN) & rpk != 0 {
            mask_a |= SSL_aRSA;
        }
        if pv(PKEY_ED25519) & rpk != 0 || pv(PKEY_ED448) & rpk != 0 {
            mask_a |= SSL_aECDSA;
        }
    }
    if have_ecc {
        let can_sign = sigalgs::cert_in_slot(c, PKEY_ECC)
            .and_then(|i| c.cfg.certs.get(i))
            .is_some_and(|k| k.can_sign);
        if can_sign && pv(PKEY_ECC) & flag(abi::CERT_PKEY_SIGN) != 0 {
            mask_a |= SSL_aECDSA;
        }
    }
    for slot in [PKEY_ED25519, PKEY_ED448] {
        if mask_a & SSL_aECDSA == 0
            && sigalgs::has_cert(c, slot)
            && pv(slot) & flag(abi::CERT_PKEY_EXPLICIT_SIGN) != 0
            && tls12
        {
            mask_a |= SSL_aECDSA;
        }
    }
    mask_k |= SSL_kECDHE;
    mask_k |= SSL_kPSK;
    mask_a |= SSL_aPSK;
    if mask_k & SSL_kRSA != 0 {
        mask_k |= SSL_kRSAPSK;
    }
    if mask_k & SSL_kDHE != 0 {
        mask_k |= SSL_kDHEPSK;
    }
    if mask_k & SSL_kECDHE != 0 {
        mask_k |= SSL_kECDHEPSK;
    }
    c.hs.sh.mask_k = mask_k;
    c.hs.sh.mask_a = mask_a;
}

/// `ssl3_choose_cipher`: the server's suite from the client's list and its own. Suite B
/// and `SSL_OP_CIPHER_SERVER_PREFERENCE` take the server's order (with
/// `SSL_OP_PRIORITIZE_CHACHA`, its ChaCha20 suites first when the client prefers ChaCha20);
/// otherwise the client's. Below TLS 1.3 the certificates' validity and the masks are set
/// first, and a suite needs its key exchange and authentication served (PSK suites a PSK
/// callback, ECDHE a shared group). A Safari-like client's ECDHE-ECDSA suites are passed
/// over unless nothing else matches; with only a TLS 1.2-style PSK callback and no
/// certificate, TLS 1.3 prefers a SHA-256 suite.
#[must_use]
pub fn choose(
    c: &mut Connection,
    client: &[&'static Cipher],
    server: &[&'static Cipher],
) -> Option<&'static Cipher> {
    let suiteb = version::suiteb(c) != 0;
    let server_pref = suiteb || c.cfg.options & abi::SSL_OP_CIPHER_SERVER_PREFERENCE != 0;
    let mut prio: Vec<&'static Cipher> = if server_pref {
        server.to_vec()
    } else {
        client.to_vec()
    };
    let allow: &[&'static Cipher] = if server_pref { client } else { server };
    if !suiteb
        && server_pref
        && c.cfg.options & abi::SSL_OP_PRIORITIZE_CHACHA != 0
        && client
            .first()
            .is_some_and(|x| x.enc == SSL_CHACHA20POLY1305)
        && server.iter().any(|x| x.enc == SSL_CHACHA20POLY1305)
    {
        let (mut chacha, rest): (Vec<_>, Vec<_>) =
            server.iter().partition(|x| x.enc == SSL_CHACHA20POLY1305);
        chacha.extend(rest);
        prio = chacha;
    }
    let mut prefer_sha256 = false;
    if c.is_tls13() {
        if c.cfg.callbacks.psk && !(0..sigalgs::PKEY_NUM).any(|i| sigalgs::has_cert(c, i)) {
            prefer_sha256 = true;
        }
    } else {
        sigalgs::set_cert_validity(c);
        set_masks(c);
    }
    let v = c_int::from(c.neg.version);
    let mut ret: Option<&'static Cipher> = None;
    for cp in prio {
        if v.cmp(&cp.min_tls) == Ordering::Less || v.cmp(&cp.max_tls) == Ordering::Greater {
            continue;
        }
        let (alg_k, alg_a) = (cp.mkey, cp.auth);
        if !c.is_tls13() {
            let mut mask_k = c.hs.sh.mask_k;
            let mut mask_a = c.hs.sh.mask_a;
            if c.cfg.srp {
                mask_k |= SSL_kSRP;
                mask_a |= SSL_aSRP;
            }
            if alg_k & SSL_PSK != 0 && !c.cfg.callbacks.psk {
                continue;
            }
            let mut ok = alg_k & mask_k != 0 && alg_a & mask_a != 0;
            if alg_k & SSL_kECDHE != 0 {
                ok = ok && groups::check_ec_tmp_key(c, cp.id);
            }
            if !ok {
                continue;
            }
        }
        let Some(found) = allow.iter().find(|x| core::ptr::eq(**x, cp)).copied() else {
            continue;
        };
        if !security::check(
            c,
            abi::SSL_SECOP_CIPHER_SHARED,
            cp.strength_bits,
            0,
            SecOther::Cipher(cp),
        ) {
            continue;
        }
        if alg_k & SSL_kECDHE != 0 && alg_a & SSL_aECDSA != 0 && c.hs.sh.is_probably_safari {
            if ret.is_none() {
                ret = Some(found);
            }
            continue;
        }
        if prefer_sha256 {
            if found.handshake_hash() == Some(crate::crypto::HashAlg::Sha256) {
                return Some(found);
            }
            if ret.is_none() {
                ret = Some(found);
            }
            continue;
        }
        return Some(found);
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn received_lists_split_off_the_signalling_values() {
        let raw = [0x13, 0x01, 0x00, 0xff, 0xc0, 0x2f, 0x56, 0x00, 0x12, 0x34];
        let (sk, scsv) = bytes_to_cipher_list(&raw, false, true).unwrap();
        let names: Vec<_> = sk.iter().map(|c| c.name_str()).collect();
        assert_eq!(
            names,
            ["TLS_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256"]
        );
        assert_eq!(scsv.len(), 2);
        assert_eq!(
            bytes_to_cipher_list(&[], false, true).unwrap_err(),
            Error::alert(
                abi::SSL_AD_ILLEGAL_PARAMETER,
                abi::SSL_R_NO_CIPHERS_SPECIFIED
            )
        );
        assert_eq!(
            bytes_to_cipher_list(&[1, 2, 3], false, false).unwrap_err(),
            Error::quiet(abi::SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST)
        );
        // SSLv2 form: a non-zero first octet is SSLv2's.
        let (sk, _) =
            bytes_to_cipher_list(&[0x01, 0x00, 0x80, 0x00, 0x00, 0x2f], true, true).unwrap();
        assert_eq!(sk.first().map(|c| c.name_str()), Some("AES128-SHA"));
        assert_eq!(
            cache_cipherlist(&[0x01, 0x00, 0x80, 0x00, 0x00, 0x2f], true).unwrap(),
            [0x00, 0x2f]
        );
    }
}
