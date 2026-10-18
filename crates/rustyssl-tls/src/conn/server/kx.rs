//! TLS 1.2's key exchange on the server (`tls_construct_server_key_exchange`,
//! `tls_process_client_key_exchange` with its `tls_process_cke_*`,
//! `tls_post_process_client_key_exchange`, and `ssl_generate_master_secret`): ECDHE, DHE
//! (configured parameters, `SSL_set_dh_auto`'s, or the `tmp_dh_callback`'s), RSA (with the
//! provider's implicit rejection), and PSK with each.

use rustyssl_abi as abi;

use super::{digest_cached_records, received_client_cert, state, state_ref};
use crate::codec::{Reader, Writer};
use crate::conn::common::security::{self, SecOther};
use crate::conn::common::{ask_once, groups, keys, sigalgs};
use crate::conn::statem::{Construct, MsgProcess, Work};
use crate::conn::{Answer, Connection, Request};
use crate::crypto::{Provider, Secret};
use crate::error::{Error, InFunc, Result};
use crate::suites::masks::{
    SSL_PSK, SSL_aNULL, SSL_aSRP, SSL_kDHE, SSL_kDHEPSK, SSL_kECDHE, SSL_kECDHEPSK, SSL_kPSK,
    SSL_kRSA, SSL_kRSAPSK,
};

/// `NAMED_CURVE_TYPE`.
const NAMED_CURVE_TYPE: u8 = 3;

/// `BN_num_bytes`' form: no leading zeros.
fn strip(b: &[u8]) -> &[u8] {
    let n = b.iter().take_while(|&&x| x == 0).count();
    b.get(n..).unwrap_or_default()
}

/// The security bits of a finite-field group with a prime of `bits` bits
/// (`ossl_ifc_ffc_compute_security_bits`, as `EVP_PKEY_get_security_bits` gives them).
fn ffc_security_bits(bits: usize) -> i32 {
    match bits {
        b if b >= 15360 => 256,
        b if b >= 7680 => 192,
        b if b >= 3072 => 128,
        b if b >= 2048 => 112,
        b if b >= 1024 => 80,
        _ => 0,
    }
}

/// An RFC 3526 (or RFC 2409) prime of `bits` bits, big-endian.
fn modp_prime(bits: usize) -> Option<Vec<u8>> {
    use rustyssl_crypto::bn::rfc_primes::{RFC2409, RFC3526};
    let hex = RFC3526
        .iter()
        .chain(RFC2409.iter())
        .find(|(b, _)| *b == bits)?
        .1;
    let digits: Vec<u8> = hex.bytes().collect();
    digits
        .chunks(2)
        .map(|pair| {
            let s = core::str::from_utf8(pair).ok()?;
            u8::from_str_radix(s, 16).ok()
        })
        .collect()
}

/// `ssl_get_auto_dh`: the prime for the suite (an anonymous or PSK suite: by its strength) or
/// the certificate's key (by its security), at least the security level's bits.
fn auto_dh(c: &Connection, p: &dyn Provider) -> Option<(Vec<u8>, Vec<u8>)> {
    let nc = c.hs.new_cipher?;
    let mut secbits = if nc.auth & (SSL_aNULL | crate::suites::masks::SSL_aPSK) != 0 {
        if nc.strength_bits == 256 { 128 } else { 80 }
    } else {
        let cert = c.hs.sh.cert.and_then(|i| c.cfg.certs.get(i))?;
        let leaf = cert.chain.first()?;
        p.peer_key(leaf, false).ok()?.security_bits
    };
    let (_, level) = security::level_bits(c.cfg.security_level);
    secbits = secbits.max(level);
    let prime = if secbits >= 192 {
        modp_prime(8192)
    } else if secbits >= 152 {
        modp_prime(4096)
    } else if secbits >= 128 {
        modp_prime(3072)
    } else if secbits >= 112 {
        modp_prime(2048)
    } else {
        modp_prime(1024)
    }?;
    Some((prime, vec![2]))
}

/// The DH parameters a DHE ServerKeyExchange uses: `SSL_set_dh_auto`'s, the configured ones,
/// or the `tmp_dh_callback`'s ([`Request::TmpDh`], as OpenSSL calls it, for 1024 bits). `None`
/// while waiting.
fn dh_params(c: &mut Connection, p: &dyn Provider) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    if c.cfg.dh_auto {
        return auto_dh(c, p).map(Some).ok_or_else(Error::internal);
    }
    if let Some(params) = c.cfg.dh_params.clone() {
        return Ok(Some(params));
    }
    if c.cfg.callbacks.tmp_dh {
        return match ask_once(c, Request::TmpDh { bits: 1024 }, 0) {
            None => Ok(None),
            Some(Answer::TmpDh(Some(params))) => Ok(Some(params)),
            Some(_) => Err(Error::internal()),
        };
    }
    Err(Error::alert(
        abi::SSL_AD_INTERNAL_ERROR,
        abi::SSL_R_MISSING_TMP_DH_KEY,
    ))
}

/// `tls_construct_server_key_exchange`: the PSK identity hint (PSK suites), the ephemeral key
/// (DHE: the prime, the generator, and the public value padded to the prime's length; ECDHE:
/// the named curve and the point), and, for an authenticated suite, the signature over both
/// randoms and the parameters (with the scheme, from TLS 1.2).
///
/// # Errors
/// No parameters or group (`SSL_R_MISSING_TMP_DH_KEY`, `SSL_R_DH_KEY_TOO_SMALL`,
/// `SSL_R_UNSUPPORTED_ELLIPTIC_CURVE`), or the key or signature couldn't be made.
pub(crate) fn construct_server_key_exchange(
    c: &mut Connection,
    p: &dyn Provider,
) -> Result<Construct> {
    let nc = c.hs.new_cipher.ok_or_else(Error::internal)?;
    let k = nc.mkey;
    let mut params = Writer::new();
    let tl = |_| Error::internal();
    if k & SSL_PSK != 0 {
        let hint = c.cfg.psk_identity_hint.clone().unwrap_or_default();
        let max = usize::try_from(abi::PSK_MAX_IDENTITY_LEN).unwrap_or(256);
        if hint.len() > max {
            return Err(Error::internal());
        }
        params.vec(2, &hint).map_err(tl)?;
    }
    if k & (SSL_kPSK | SSL_kRSAPSK) != 0 {
        // No key: the hint alone.
    } else if k & (SSL_kDHE | SSL_kDHEPSK) != 0 {
        let Some((dp, dg)) = dh_params(c, p)? else {
            return Ok(Construct::Ask);
        };
        let (dp, dg) = (strip(&dp).to_vec(), strip(&dg).to_vec());
        let bits = ffc_security_bits(dp.len().saturating_mul(8));
        if !security::check(c, abi::SSL_SECOP_TMP_DH, bits, 0, SecOther::None) {
            return Err(Error::alert(
                abi::SSL_AD_HANDSHAKE_FAILURE,
                abi::SSL_R_DH_KEY_TOO_SMALL,
            ));
        }
        if state_ref(c).is_some_and(|s| s.kx_key.is_some()) {
            return Err(Error::internal());
        }
        let share = p.dh_share(&dp, &dg).map_err(|_| Error::internal())?;
        let public = share.public().to_vec();
        params.vec(2, &dp).map_err(tl)?;
        params.vec(2, &dg).map_err(tl)?;
        let pad = dp.len().saturating_sub(strip(&public).len());
        let mut padded = vec![0u8; pad];
        padded.extend_from_slice(strip(&public));
        params.vec(2, &padded).map_err(tl)?;
        state(c)?.kx_key = Some(share);
        c.hs.sh.own_dh = Some((dp, dg, public));
    } else if k & (SSL_kECDHE | SSL_kECDHEPSK) != 0 {
        if state_ref(c).is_some_and(|s| s.kx_key.is_some()) {
            return Err(Error::internal());
        }
        let curve = groups::shared_group(c, -2);
        if curve == 0 {
            return Err(Error::alert(
                abi::SSL_AD_HANDSHAKE_FAILURE,
                abi::SSL_R_UNSUPPORTED_ELLIPTIC_CURVE,
            ));
        }
        c.neg.group = Some(curve);
        let share = p.key_share(curve).map_err(|_| Error::internal())?;
        params.u8(NAMED_CURVE_TYPE);
        params.u8(0);
        params.u8(u8::try_from(curve & 0xff).map_err(|_| Error::internal())?);
        params.vec(1, share.public()).map_err(tl)?;
        c.hs.sh.own_tmp = Some((curve, share.public().to_vec()));
        let s = state(c)?;
        s.kx_key = Some(share);
        s.kx_group = curve;
    } else {
        return Err(Error::alert(
            abi::SSL_AD_INTERNAL_ERROR,
            abi::SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE,
        ));
    }
    let params = params.into_bytes();
    let mut w = Writer::new();
    w.put(&params);
    let anonymous = nc.auth & (SSL_aNULL | SSL_aSRP) != 0 || k & SSL_PSK != 0;
    if !anonymous {
        let (Some(scheme), Some(idx)) = (c.hs.sh.sigalg, c.hs.sh.cert) else {
            return Err(Error::alert_lib(
                abi::SSL_AD_DECODE_ERROR,
                abi::ERR_R_INTERNAL_ERROR,
            ));
        };
        let key = c
            .cfg
            .certs
            .get(idx)
            .map(|k| k.key)
            .ok_or_else(Error::internal)?;
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&c.hs.client_random);
        tbs.extend_from_slice(&c.hs.server_random);
        tbs.extend_from_slice(&params);
        let sig = p.sign(key, scheme, &tbs).map_err(|_| Error::internal())?;
        if sigalgs::use_sigalgs(c) {
            w.u16(scheme);
        }
        w.vec(2, &sig).map_err(tl)?;
    }
    Ok(Construct::Send(w.into_bytes()))
}

/// `tls_process_cke_psk_preamble`: the client's PSK identity (at most `PSK_MAX_IDENTITY_LEN`,
/// `SSL_R_DATA_LENGTH_TOO_LONG`), and its key from the PSK callback ([`Request::Psk`]); an
/// unknown identity is `SSL_R_PSK_IDENTITY_NOT_FOUND` with unknown-psk-identity. `None` while
/// waiting.
fn psk_preamble(c: &mut Connection, rd: &mut Reader<'_>) -> Result<Option<Secret>> {
    psk_preamble_inner(c, rd).in_func("tls_process_cke_psk_preamble")
}

/// See [`psk_preamble`].
fn psk_preamble_inner(c: &mut Connection, rd: &mut Reader<'_>) -> Result<Option<Secret>> {
    let id = rd
        .vec16()
        .map_err(|_| Error::decode(abi::SSL_R_LENGTH_MISMATCH))?;
    let max = usize::try_from(abi::PSK_MAX_IDENTITY_LEN).unwrap_or(256);
    if id.len() > max {
        return Err(Error::decode(abi::SSL_R_DATA_LENGTH_TOO_LONG));
    }
    if !c.cfg.callbacks.psk {
        return Err(Error::alert(
            abi::SSL_AD_INTERNAL_ERROR,
            abi::SSL_R_PSK_NO_SERVER_CB,
        ));
    }
    let identity = id.rest().to_vec();
    state(c)?.psk_identity = Some(identity.clone());
    let r = Request::Psk {
        hint_or_identity: identity,
    };
    let key = match ask_once(c, r, 0) {
        None => return Ok(None),
        Some(Answer::Psk(Some(e))) => e.key,
        Some(_) => Vec::new(),
    };
    let max = usize::try_from(abi::PSK_MAX_PSK_LEN).unwrap_or(512);
    if key.len() > max {
        return Err(Error::internal());
    }
    if key.is_empty() {
        return Err(Error::alert(
            abi::SSL_AD_UNKNOWN_PSK_IDENTITY,
            abi::SSL_R_PSK_IDENTITY_NOT_FOUND,
        ));
    }
    Ok(Some(Secret::new(key)))
}

/// `tls_process_client_key_exchange`: the premaster secret from the client's share (DHE:
/// `SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG`; ECDHE: `SSL_R_LENGTH_MISMATCH`; a share that
/// doesn't work is `SSL_R_BAD_KEY_SHARE`), its RSA-encrypted secret (decrypted with implicit
/// rejection: a padding or version failure gives a random secret, never an error), or the PSK
/// alone, then the master secret.
///
/// # Errors
/// As above.
pub(crate) fn process_client_key_exchange(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
) -> Result<MsgProcess> {
    let nc = c.hs.new_cipher.ok_or_else(Error::internal)?;
    let k = nc.mkey;
    let mut rd = Reader::new(body);
    let mut psk = None;
    if k & SSL_PSK != 0 {
        match psk_preamble(c, &mut rd)? {
            None => return Ok(MsgProcess::Ask),
            Some(s) => psk = Some(s),
        }
    }
    let mm = Error::decode(abi::SSL_R_LENGTH_MISMATCH);
    let pms: Option<Secret> = if k & SSL_kPSK != 0 {
        if !rd.is_empty() {
            return Err(mm);
        }
        None
    } else if k & (SSL_kRSA | SSL_kRSAPSK) != 0 {
        let idx = sigalgs::cert_in_slot(c, sigalgs::PKEY_RSA).ok_or(Error::alert(
            abi::SSL_AD_INTERNAL_ERROR,
            abi::SSL_R_MISSING_RSA_CERTIFICATE,
        ))?;
        let key = c
            .cfg
            .certs
            .get(idx)
            .map(|k| k.key)
            .ok_or_else(Error::internal)?;
        let enc = rd.vec16().map_err(|_| mm)?;
        rd.end().map_err(|_| mm)?;
        let failed = Error::alert(abi::SSL_AD_DECRYPT_ERROR, abi::SSL_R_DECRYPTION_FAILED);
        let pms = p
            .rsa_decrypt_pms(key, enc.rest(), c.hs.sh.client_version)
            .map_err(|_| failed)?;
        let n = usize::try_from(abi::SSL_MAX_MASTER_KEY_LENGTH).unwrap_or(48);
        if pms.len() != n {
            return Err(failed);
        }
        Some(pms)
    } else if k & (SSL_kDHE | SSL_kDHEPSK) != 0 {
        let wrong = Error::decode(abi::SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG);
        let n = rd.u16().map_err(|_| wrong)?;
        if rd.len() != usize::from(n) {
            return Err(wrong);
        }
        let share = state(c)?.kx_key.take().ok_or(Error::alert(
            abi::SSL_AD_INTERNAL_ERROR,
            abi::SSL_R_MISSING_TMP_DH_KEY,
        ))?;
        if rd.is_empty() {
            return Err(Error::decode(abi::SSL_R_MISSING_TMP_DH_KEY));
        }
        let secret = share
            .derive(rd.rest())
            .map_err(|_| Error::alert(abi::SSL_AD_ILLEGAL_PARAMETER, abi::SSL_R_BAD_KEY_SHARE))?;
        // The ephemeral key is freed once used.
        c.hs.sh.own_dh = None;
        // TLS 1.2 strips the secret's leading zeros (OpenSSL pads only for TLS 1.3).
        Some(Secret::new(strip(secret.bytes()).to_vec()))
    } else if k & (SSL_kECDHE | SSL_kECDHEPSK) != 0 {
        if rd.is_empty() {
            return Err(Error::alert(
                abi::SSL_AD_HANDSHAKE_FAILURE,
                abi::SSL_R_MISSING_TMP_ECDH_KEY,
            ));
        }
        let point = rd.vec8().map_err(|_| mm)?;
        rd.end().map_err(|_| mm)?;
        let share = state(c)?.kx_key.take().ok_or(Error::alert(
            abi::SSL_AD_INTERNAL_ERROR,
            abi::SSL_R_MISSING_TMP_ECDH_KEY,
        ))?;
        if point.is_empty() {
            return Err(Error::alert(
                abi::SSL_AD_ILLEGAL_PARAMETER,
                abi::SSL_R_BAD_KEY_SHARE,
            ));
        }
        let secret = share
            .derive(point.rest())
            .map_err(|_| Error::alert(abi::SSL_AD_ILLEGAL_PARAMETER, abi::SSL_R_BAD_KEY_SHARE))?;
        c.hs.sh.own_tmp = None;
        Some(secret)
    } else {
        return Err(Error::alert(
            abi::SSL_AD_INTERNAL_ERROR,
            abi::SSL_R_UNKNOWN_CIPHER_TYPE,
        ));
    };
    generate_master_secret(c, p, pms, psk)?;
    Ok(MsgProcess::ContinueProcessing)
}

/// `ssl_generate_master_secret`: a PSK suite's premaster secret is the other secret (the key
/// exchange's, or zeros for plain PSK) and the PSK, each with its length; then the master
/// secret (with the Extended Master Secret's session hash when negotiated), kept in the
/// session.
fn generate_master_secret(
    c: &mut Connection,
    p: &dyn Provider,
    pms: Option<Secret>,
    psk: Option<Secret>,
) -> Result<()> {
    generate_master_secret_inner(c, p, pms, psk).in_func("ssl_generate_master_secret")
}

/// See [`generate_master_secret`].
fn generate_master_secret_inner(
    c: &mut Connection,
    p: &dyn Provider,
    pms: Option<Secret>,
    psk: Option<Secret>,
) -> Result<()> {
    let k = c.hs.new_cipher.map_or(0, |x| x.mkey);
    let pms = if k & SSL_PSK != 0 {
        let psk = psk.ok_or_else(Error::internal)?;
        let other = match &pms {
            Some(s) if k & SSL_kPSK == 0 => s.bytes().to_vec(),
            _ => vec![0u8; psk.len()],
        };
        let mut w = Writer::new();
        w.vec(2, &other).map_err(|_| Error::internal())?;
        w.vec(2, psk.bytes()).map_err(|_| Error::internal())?;
        Secret::new(w.into_bytes())
    } else {
        pms.ok_or_else(Error::internal)?
    };
    c.neg.ems = c.neg.session.ems;
    c.neg.etm = c.hs.sh.use_etm;
    if c.neg.ems {
        // The session hash covers the ClientKeyExchange (`ssl3_digest_cached_records(s, 1)`).
        digest_cached_records(c, p, true)?;
    }
    keys::generate_master_secret12(c, p, pms.bytes())?;
    c.neg.session.master_key.clone_from(&c.neg.master_secret);
    Ok(())
}

/// `tls_post_process_client_key_exchange`: the messages are kept for the client's
/// CertificateVerify, or (without one to come) only their hash.
///
/// # Errors
/// The transcript couldn't be hashed.
pub(crate) fn post_process_client_key_exchange(
    c: &mut Connection,
    p: &dyn Provider,
    _wst: Work,
) -> Result<Work> {
    if c.st.no_cert_verify || !received_client_cert(c) {
        digest_cached_records(c, p, false)?;
    } else {
        if c.hs.transcript.buffered().is_none() {
            return Err(Error::internal());
        }
        digest_cached_records(c, p, true)?;
    }
    Ok(Work::FinishedContinue)
}
