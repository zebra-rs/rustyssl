//! The server's flights after its hello: its Certificate (or raw public key) and the
//! verification of its chain, CertificateStatus, TLS 1.2's ServerKeyExchange and
//! ServerHelloDone, CertificateRequest, the checks of the whole first flight, NewSessionTicket,
//! and HelloRequest.

use core::ffi::c_int;

use rustyssl_abi as abi;

use super::{Connection, Kx12, state, state_ref, x509err2alert};
use crate::codec::Reader;
use crate::conn::common::{ask_once, cert, ext, keys, security, sigalgs};
use crate::conn::common::{groups, security::SecOther};
use crate::conn::statem::{MsgProcess, Work};
use crate::conn::{Answer, Event, Request};
use crate::consts::context as cx;
use crate::consts::version as v;
use crate::crypto::{HashAlg, PeerKey, Provider, Secret};
use crate::error::{Error, InFunc, Result};
use crate::keysched;
use crate::msgs::cert::{CertificateReader, CertificateStatus, RpkReader};
use crate::msgs::kx::ske;
use crate::msgs::misc::NewSessionTicket;
use crate::suites::masks::{
    SSL_PSK, SSL_aCERT, SSL_aDSS, SSL_aECDSA, SSL_aNULL, SSL_aRSA, SSL_aSRP, SSL_kDHE, SSL_kDHEPSK,
    SSL_kECDHE, SSL_kECDHEPSK, SSL_kPSK, SSL_kRSA, SSL_kRSAPSK, SSL_kSRP,
};

/// `TLSEXT_cert_type_x509` and `_rpk` as octets.
fn cert_type(v: c_int) -> u8 {
    u8::try_from(v).unwrap_or(0)
}

/// Whether `der` decodes as one DER element filling it, a SEQUENCE (what `d2i_X509` needs
/// first): `Err(true)` when octets are left over, `Err(false)` when it doesn't decode.
fn check_x509(der: &[u8]) -> core::result::Result<(), bool> {
    let e = rustyssl_asn1::der::element(der).map_err(|_| false)?;
    if e.header.class != 0 || e.header.tag != 16 || !e.header.constructed {
        return Err(false);
    }
    // The certificate's three parts: tbsCertificate, signatureAlgorithm, signature.
    let mut rest = e.content;
    for _ in 0..3 {
        let part = rustyssl_asn1::der::element(rest).map_err(|_| false)?;
        rest = rest.get(part.raw.len()..).unwrap_or_default();
    }
    if !rest.is_empty() {
        return Err(false);
    }
    if e.raw.len() != der.len() {
        return Err(true);
    }
    Ok(())
}

/// `tls_process_server_certificate`: the server's chain (each certificate's TLS 1.3
/// extensions parsed in turn), or its raw public key (`tls_process_server_rpk`).
///
/// # Errors
/// OpenSSL's alert and reason.
pub(super) fn process_server_certificate(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
) -> Result<MsgProcess> {
    let sct = c.neg.server_cert_type;
    if sct == cert_type(abi::TLSEXT_cert_type_rpk) {
        return process_server_rpk(c, p, body);
    }
    if sct != cert_type(abi::TLSEXT_cert_type_x509) {
        return Err(Error::alert(
            abi::SSL_AD_UNSUPPORTED_CERTIFICATE,
            abi::SSL_R_UNKNOWN_CERTIFICATE_TYPE,
        ));
    }
    let tls13 = c.is_tls13();
    let mut rd = CertificateReader::new(body, tls13, true)?;
    let mut chain = Vec::new();
    let mut idx = 0usize;
    while let Some(der) = rd.next_certificate() {
        let der = der?;
        match check_x509(der) {
            Ok(()) => {}
            Err(true) => return Err(Error::decode(abi::SSL_R_CERT_LENGTH_MISMATCH)),
            Err(false) => {
                return Err(Error::alert_lib(
                    abi::SSL_AD_BAD_CERTIFICATE,
                    abi::ERR_R_ASN1_LIB,
                ));
            }
        }
        if tls13 {
            let exts = rd.extensions()?;
            ext::collect(c, exts, cx::TLS1_3_CERTIFICATE, idx, idx == 0)?;
            let last = rd.is_empty();
            c.ext_cert = Some(der.to_vec());
            let step = ext::parse_all(c, p, cx::TLS1_3_CERTIFICATE, idx, last);
            c.ext_cert = None;
            if step? == ext::Step::Wait {
                return Ok(MsgProcess::Ask);
            }
        }
        chain.push(der.to_vec());
        idx = idx.saturating_add(1);
    }
    c.neg.peer_chain = chain;
    Ok(MsgProcess::ContinueProcessing)
}

/// `tls_process_server_rpk` (with `tls_process_rpk`).
fn process_server_rpk(c: &mut Connection, p: &dyn Provider, body: &[u8]) -> Result<MsgProcess> {
    let tls13 = c.is_tls13();
    let rd = RpkReader::new(body, tls13)?;
    if rd.context.is_some_and(|x| !x.is_empty()) {
        return Err(Error::decode(abi::SSL_R_INVALID_CONTEXT));
    }
    let Some(spki) = rd.spki else {
        return Err(Error::decode(abi::SSL_R_BAD_CERTIFICATE));
    };
    let spki = spki.to_vec();
    if p.peer_key(&spki, true).is_err() || check_spki(&spki).is_err() {
        return Err(Error::decode(abi::SSL_R_LENGTH_MISMATCH));
    }
    if tls13 {
        let exts = rd.extensions()?.to_vec();
        ext::collect(c, &exts, cx::TLS1_3_RAW_PUBLIC_KEY, 0, true)?;
        if ext::parse_all(c, p, cx::TLS1_3_RAW_PUBLIC_KEY, 0, true)? == ext::Step::Wait {
            return Ok(MsgProcess::Ask);
        }
    }
    c.neg.peer_rpk = Some(spki);
    Ok(MsgProcess::ContinueProcessing)
}

/// A SubjectPublicKeyInfo's DER fills its octets.
fn check_spki(der: &[u8]) -> core::result::Result<(), ()> {
    let e = rustyssl_asn1::der::element(der).map_err(|_| ())?;
    if e.raw.len() == der.len() {
        Ok(())
    } else {
        Err(())
    }
}

/// `tls_post_process_server_certificate` (and `_rpk`): verifies the chain
/// ([`Request::Verify`]; with a raw public key the chain is the key's SubjectPublicKeyInfo
/// alone), then checks the key suits the suite, and keeps the transcript hash for the TLS
/// 1.3 CertificateVerify.
///
/// # Errors
/// A verification failure when verifying (`SSL_R_CERTIFICATE_VERIFY_FAILED` with the result's
/// alert), or the key's type.
pub(super) fn post_process_server_certificate(
    c: &mut Connection,
    p: &dyn Provider,
    _wst: Work,
) -> Result<Work> {
    let rpk = c.neg.server_cert_type == cert_type(abi::TLSEXT_cert_type_rpk);
    if rpk && c.neg.peer_rpk.is_none() {
        return Err(Error::alert(
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_R_INVALID_RAW_PUBLIC_KEY,
        ));
    }
    let chain = if rpk {
        vec![c.neg.peer_rpk.clone().unwrap_or_default()]
    } else {
        c.neg.peer_chain.clone()
    };
    let Some(a) = ask_once(c, Request::Verify { chain, rpk }, 0) else {
        return Ok(Work::MoreA);
    };
    let (result, proceed, verified) = match a {
        Answer::Verified {
            result,
            proceed,
            verified_chain,
        } => (result, proceed, verified_chain),
        Answer::Continue => (i64::from(abi::X509_V_OK), true, Vec::new()),
        Answer::Fail { alert, reason } => {
            let al = alert.map_or(abi::SSL_AD_INTERNAL_ERROR, c_int::from);
            return Err(Error::alert(al, reason));
        }
        _ => return Err(Error::internal()),
    };
    c.neg.verify_result = result;
    c.neg.verified_chain = verified;
    if !proceed && c.cfg.verify_mode != abi::SSL_VERIFY_NONE {
        return Err(Error::alert(
            x509err2alert(result),
            abi::SSL_R_CERTIFICATE_VERIFY_FAILED,
        ));
    }
    let key = if rpk {
        let spki = c.neg.peer_rpk.clone().unwrap_or_default();
        p.peer_key(&spki, true)
    } else {
        let leaf = c.neg.peer_chain.first().cloned().unwrap_or_default();
        p.peer_key(&leaf, false)
    }
    .map_err(|_| {
        Error::alert(
            abi::SSL_AD_INTERNAL_ERROR,
            abi::SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS,
        )
    })?;
    let Some(slot) = sigalgs::slot_of(c, &key.kind) else {
        return Err(Error::alert(
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_R_UNKNOWN_CERTIFICATE_TYPE,
        ));
    };
    if !c.is_tls13() {
        let auth = c.hs.new_cipher.map_or(0, |cp| cp.auth);
        if sigalgs::slot_amask(slot) & auth == 0 {
            return Err(Error::alert(
                abi::SSL_AD_ILLEGAL_PARAMETER,
                if rpk {
                    abi::SSL_R_WRONG_RPK_TYPE
                } else {
                    abi::SSL_R_WRONG_CERTIFICATE_TYPE
                },
            ));
        }
    }
    if rpk {
        c.neg.peer_chain.clear();
    } else {
        c.neg.peer_rpk = None;
    }
    c.neg.session.peer_chain.clone_from(&c.neg.peer_chain);
    c.neg.session.peer_rpk.clone_from(&c.neg.peer_rpk);
    c.neg.session.verify_result = result;
    if c.is_tls13() {
        cert::save_cert_verify_hash(c)?;
    }
    Ok(Work::FinishedContinue)
}

/// `tls_process_cert_status` (TLS 1.2): the stapled OCSP response.
///
/// # Errors
/// `SSL_R_UNSUPPORTED_STATUS_TYPE` or `SSL_R_LENGTH_MISMATCH`, decode-error.
pub(super) fn process_cert_status(c: &mut Connection, body: &[u8]) -> Result<MsgProcess> {
    let s = CertificateStatus::parse(body)?;
    c.neg.ocsp_response = Some(s.response);
    Ok(MsgProcess::ContinueReading)
}

/// `BN_security_bits` for a finite-field group of `bits` (no subgroup size known).
fn ffdh_security_bits(bits: usize) -> c_int {
    match bits {
        15360.. => 256,
        7680.. => 192,
        3072.. => 128,
        2048.. => 112,
        1024.. => 80,
        _ => 0,
    }
}

/// The bit length of a big-endian number.
fn bit_len(n: &[u8]) -> usize {
    let n = match n.iter().position(|&b| b != 0) {
        Some(i) => n.get(i..).unwrap_or_default(),
        None => return 0,
    };
    let lead = n
        .first()
        .map_or(0, |b| 8usize.saturating_sub(b.leading_zeros() as usize));
    n.len()
        .saturating_sub(1)
        .saturating_mul(8)
        .saturating_add(lead)
}

/// The peer's key (`tls_get_peer_pkey`): its DER, whether it's a SubjectPublicKeyInfo, and
/// what the checks need; `None` without a certificate.
fn peer_pkey(c: &Connection, p: &dyn Provider) -> Option<(Vec<u8>, PeerKey)> {
    cert::peer_key(c, p).ok().map(|(der, _, k)| (der, k))
}

/// `tls_process_key_exchange`: TLS 1.2's ServerKeyExchange: the PSK hint, the server's
/// share (the client's own share and the premaster secret are made here, which checks the
/// server's), and the signature over the randoms and the parameters.
///
/// # Errors
/// OpenSSL's alert and reason.
pub(super) fn process_key_exchange(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
) -> Result<MsgProcess> {
    let cp = c.hs.new_cipher.ok_or_else(Error::internal)?;
    let (mkey, auth) = (cp.mkey, cp.auth);
    let mut rd = Reader::new(body);
    state(c)?.kx12 = None;
    if mkey & SSL_PSK != 0 {
        let hint = ske::psk_hint(&mut rd)?;
        state(c)?.psk_hint = (!hint.is_empty()).then_some(hint);
    }
    let mut signer = None;
    if mkey & (SSL_kPSK | SSL_kRSAPSK) != 0 {
    } else if mkey & SSL_kSRP != 0 {
        let crate::msgs::kx::ServerParams::Srp { n, g, s, b } = ske::srp(&mut rd)? else {
            return Err(Error::internal());
        };
        let params = crate::conn::SrpParams { n, g, s, b };
        if !crate::conn::common::srp::verify_server_param(c, &params)? {
            return Ok(MsgProcess::Ask);
        }
        if auth & (SSL_aRSA | SSL_aDSS) != 0 {
            signer = peer_pkey(c, p);
        }
    } else if mkey & (SSL_kDHE | SSL_kDHEPSK) != 0 {
        let crate::msgs::kx::ServerParams::Dhe { p: prime, g, ys } = ske::dhe(&mut rd)? else {
            return Err(Error::internal());
        };
        let bad = Error::alert(abi::SSL_AD_ILLEGAL_PARAMETER, abi::SSL_R_BAD_DH_VALUE);
        let share = p.dh_share(&prime, &g).map_err(|_| bad)?;
        let public = share.public().to_vec();
        let secret = share.derive(&ys).map_err(|_| bad)?;
        let bits = ffdh_security_bits(bit_len(&prime));
        if !security::check(c, abi::SSL_SECOP_TMP_DH, bits, 0, SecOther::None) {
            return Err(Error::alert(
                abi::SSL_AD_HANDSHAKE_FAILURE,
                abi::SSL_R_DH_KEY_TOO_SMALL,
            ));
        }
        // TLS 1.2's DH premaster secret has no leading zeros.
        let lead = secret.bytes().iter().take_while(|&&b| b == 0).count();
        let pms = Secret::new(secret.bytes().get(lead..).unwrap_or_default().to_vec());
        state(c)?.kx12 = Some(Kx12 { public, pms });
        c.hs.sh.peer_dh = Some((prime.to_vec(), g.to_vec(), ys.to_vec()));
        if auth & (SSL_aRSA | SSL_aDSS) != 0 {
            signer = peer_pkey(c, p);
        }
    } else if mkey & (SSL_kECDHE | SSL_kECDHEPSK) != 0 {
        let (curve_type, group) = ske::ecdhe_group(&mut rd)?;
        if curve_type != 3 || !groups::check_group_id(c, group, true) {
            return Err(Error::alert(
                abi::SSL_AD_ILLEGAL_PARAMETER,
                abi::SSL_R_WRONG_CURVE,
            ));
        }
        let share = p.key_share(group).map_err(|_| {
            Error::alert(
                abi::SSL_AD_INTERNAL_ERROR,
                abi::SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS,
            )
        })?;
        let point = ske::ecdhe_point(&mut rd)?;
        let public = share.public().to_vec();
        let pms = share
            .derive(&point)
            .map_err(|_| Error::alert(abi::SSL_AD_ILLEGAL_PARAMETER, abi::SSL_R_BAD_ECPOINT))?;
        state(c)?.kx12 = Some(Kx12 { public, pms });
        // Fork M: the server's point is the peer's temporary key (`SSL_get_peer_tmp_key`).
        c.hs.sh.peer_tmp = Some((group, point.to_vec()));
        if auth & (SSL_aECDSA | SSL_aRSA) != 0 {
            signer = peer_pkey(c, p);
        }
        c.neg.group = Some(group);
    } else if mkey != 0 {
        return Err(Error::alert(
            abi::SSL_AD_UNEXPECTED_MESSAGE,
            abi::SSL_R_UNEXPECTED_MESSAGE,
        ));
    }
    let Some((der, key)) = signer else {
        if auth & (SSL_aNULL | SSL_aSRP) == 0 && mkey & SSL_PSK == 0 {
            check_cert_and_algorithm(c, p)?;
            return Err(Error::decode(abi::SSL_R_BAD_DATA));
        }
        ske::end_unsigned(&rd)?;
        return Ok(MsgProcess::ContinueReading);
    };
    let params = body
        .get(..body.len().saturating_sub(rd.len()))
        .unwrap_or_default()
        .to_vec();
    if sigalgs::use_sigalgs(c) {
        let sig = ske::sigalg(&mut rd)?;
        sigalgs::check_peer_sigalg(c, sig, &key)?;
    } else if !sigalgs::set_peer_legacy_sigalg(c, &key.kind) {
        return Err(Error::alert(
            abi::SSL_AD_INTERNAL_ERROR,
            abi::SSL_R_LEGACY_SIGALG_DISALLOWED_OR_UNSUPPORTED,
        ));
    }
    let scheme = c.hs.sh.peer_sigalg.ok_or_else(Error::internal)?;
    let signature = ske::signature(&mut rd)?;
    let mut tbs = c.hs.client_random.to_vec();
    tbs.extend_from_slice(&c.hs.server_random);
    tbs.extend_from_slice(&params);
    let bad = Error::alert(abi::SSL_AD_DECRYPT_ERROR, abi::SSL_R_BAD_SIGNATURE);
    if !p.verify(&der, scheme, &tbs, &signature).map_err(|_| bad)? {
        return Err(bad);
    }
    c.neg.peer_scheme = Some(scheme);
    Ok(MsgProcess::ContinueReading)
}

/// `tls_process_certificate_request`: TLS 1.3's (its context and extensions; after the
/// handshake, for post-handshake authentication) or TLS 1.2's (the certificate types, the
/// signature schemes, the CA names).
///
/// # Errors
/// OpenSSL's alert and reason.
pub(super) fn process_certificate_request(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
) -> Result<MsgProcess> {
    c.hs.sh.valid_flags.fill(0);
    let mut rd = Reader::new(body);
    if c.is_tls13() {
        if c.shutdown & crate::conn::SENT_SHUTDOWN != 0 {
            return Ok(MsgProcess::FinishedReading);
        }
        state(c)?.ctype.clear();
        let ctx = rd
            .vec8()
            .map_err(|_| Error::decode(abi::SSL_R_LENGTH_MISMATCH))?
            .rest()
            .to_vec();
        c.hs.sh.pha_context = Some(ctx);
        let exts = rd
            .vec16()
            .map_err(|_| Error::decode(abi::SSL_R_BAD_LENGTH))?
            .rest()
            .to_vec();
        ext::collect(c, &exts, cx::TLS1_3_CERTIFICATE_REQUEST, 0, true)?;
        if ext::parse_all(c, p, cx::TLS1_3_CERTIFICATE_REQUEST, 0, true)? == ext::Step::Wait {
            return Ok(MsgProcess::Ask);
        }
        sigalgs::process(c);
    } else {
        let ctypes = rd
            .vec8()
            .map_err(|_| Error::decode(abi::SSL_R_LENGTH_MISMATCH))?
            .rest()
            .to_vec();
        state(c)?.ctype = ctypes;
        if sigalgs::use_sigalgs(c) {
            let list = rd
                .vec16()
                .map_err(|_| Error::decode(abi::SSL_R_LENGTH_MISMATCH))?
                .rest()
                .to_vec();
            if !sigalgs::save(c, &list, false) {
                return Err(Error::alert(
                    abi::SSL_AD_INTERNAL_ERROR,
                    abi::SSL_R_SIGNATURE_ALGORITHMS_ERROR,
                ));
            }
            sigalgs::process(c);
        }
        cert::parse_ca_names(c, &mut rd)?;
    }
    if !rd.is_empty() {
        return Err(Error::decode(abi::SSL_R_LENGTH_MISMATCH));
    }
    c.hs.sh.cert_req = 1;
    if c.is_tls13() && c.hs.sh.pha != crate::conn::common::Pha::Requested {
        return Ok(MsgProcess::ContinueReading);
    }
    Ok(MsgProcess::ContinueProcessing)
}

/// `tls_process_server_done`.
///
/// # Errors
/// A body (`SSL_R_LENGTH_MISMATCH`), or the first flight's checks.
pub(super) fn process_server_done(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
) -> Result<MsgProcess> {
    if !body.is_empty() {
        return Err(Error::decode(abi::SSL_R_LENGTH_MISMATCH));
    }
    if c.hs.new_cipher.is_some_and(|cp| cp.mkey & SSL_kSRP != 0) {
        match ask_once(c, Request::SrpClientA, 0) {
            None => return Ok(MsgProcess::Ask),
            Some(Answer::SrpValue(Some(a))) => state(c)?.srp_a = Some(a),
            Some(_) => {
                return Err(Error::alert(
                    abi::SSL_AD_INTERNAL_ERROR,
                    abi::SSL_R_SRP_A_CALC,
                ));
            }
        }
    }
    if !initial_server_flight(c, p)? {
        return Ok(MsgProcess::Ask);
    }
    Ok(MsgProcess::FinishedReading)
}

/// `ssl3_check_cert_and_algorithm`: the server's key suits the suite, and an ECDSA
/// certificate's key usage, if present, allows signing (`ssl_check_srvr_ecc_cert_and_alg`).
///
/// # Errors
/// `SSL_R_MISSING_SIGNING_CERT`, `SSL_R_MISSING_RSA_ENCRYPTING_CERT`, `SSL_R_BAD_ECC_CERT`
/// (after `SSL_R_ECC_CERT_NOT_FOR_SIGNING`) (handshake-failure).
fn check_cert_and_algorithm(c: &Connection, p: &dyn Provider) -> Result<()> {
    check_cert_and_algorithm_inner(c, p).in_func("ssl3_check_cert_and_algorithm")
}

/// See [`check_cert_and_algorithm`].
fn check_cert_and_algorithm_inner(c: &Connection, p: &dyn Provider) -> Result<()> {
    let cp = c.hs.new_cipher.ok_or_else(Error::internal)?;
    if cp.auth & SSL_aCERT == 0 {
        return Ok(());
    }
    let key = peer_pkey(c, p);
    let slot = key.as_ref().and_then(|(_, k)| sigalgs::slot_of(c, &k.kind));
    let Some(slot) = slot.filter(|&s| cp.auth & sigalgs::slot_amask(s) != 0) else {
        return Err(Error::alert(
            abi::SSL_AD_HANDSHAKE_FAILURE,
            abi::SSL_R_MISSING_SIGNING_CERT,
        ));
    };
    if cp.mkey & (SSL_kRSA | SSL_kRSAPSK) != 0 && slot != sigalgs::PKEY_RSA {
        return Err(Error::alert(
            abi::SSL_AD_HANDSHAKE_FAILURE,
            abi::SSL_R_MISSING_RSA_ENCRYPTING_CERT,
        ));
    }
    if cp.mkey & SSL_kDHE != 0 && state_ref(c).is_none_or(|s| s.kx12.is_none()) {
        return Err(Error::internal());
    }
    // A raw public key has no key usage to check.
    if c.neg.peer_rpk.is_some() {
        return Ok(());
    }
    let signing = u32::try_from(abi::X509v3_KU_DIGITAL_SIGNATURE).unwrap_or(0);
    if sigalgs::slot_amask(slot) & SSL_aECDSA != 0
        && cp.auth & SSL_aECDSA != 0
        && key.is_some_and(|(_, k)| k.key_usage & signing == 0)
    {
        return Err(Error::alert(
            abi::SSL_AD_HANDSHAKE_FAILURE,
            abi::SSL_R_BAD_ECC_CERT,
        )
        .caused_by(crate::error::Cause {
            lib: abi::ERR_LIB_SSL,
            reason: abi::SSL_R_ECC_CERT_NOT_FOR_SIGNING,
            func: "ssl_check_srvr_ecc_cert_and_alg",
        }));
    }
    Ok(())
}

/// Whether the OCSP status callback runs (a status was asked for and the callback is set).
fn status_wanted(c: &Connection) -> bool {
    c.hs.sh.status_type != crate::conn::common::STATUSTYPE_NOTHING && c.cfg.callbacks.status
}

/// The status callback's verdict on its answer.
fn status_result(a: &Answer) -> Result<()> {
    let ret = match a {
        Answer::Status { ret, .. } => *ret,
        Answer::Continue => 1,
        Answer::Fail { .. } => -1,
        _ => return Err(Error::internal()),
    };
    if ret == 0 {
        return Err(Error::alert(
            abi::SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE,
            abi::SSL_R_INVALID_STATUS_RESPONSE,
        ));
    }
    if ret < 0 {
        return Err(Error::alert(
            abi::SSL_AD_INTERNAL_ERROR,
            abi::SSL_R_OCSP_CALLBACK_FAILURE,
        ));
    }
    Ok(())
}

/// `tls_process_initial_server_flight`: the certificate suits the suite, the OCSP status
/// callback accepts the stapled response ([`Request::Status`]), and the SCTs pass CT
/// validation ([`Request::CtValidate`]). `Ok(false)` while an answer is awaited.
///
/// # Errors
/// OpenSSL's alert and reason.
pub(super) fn initial_server_flight(c: &mut Connection, p: &dyn Provider) -> Result<bool> {
    check_cert_and_algorithm(c, p)?;
    if status_wanted(c) {
        let req = Request::Status {
            ocsp_ids: Vec::new(),
            ocsp_exts: Vec::new(),
        };
        let Some(a) = ask_once(c, req, 0) else {
            return Ok(false);
        };
        status_result(&a)?;
    }
    if c.cfg.request_scts {
        let Some(a) = ask_once(c, Request::CtValidate, 0) else {
            return Ok(false);
        };
        ct_result(c, &a)?;
    }
    Ok(true)
}

/// The CT validation's verdict on its answer: a failure counts with `SSL_VERIFY_PEER`, and
/// is recorded as the verification result either way (`ssl_validate_ct`, fork M).
fn ct_result(c: &mut Connection, a: &Answer) -> Result<()> {
    if matches!(a, Answer::Fail { .. } | Answer::Allowed(false)) {
        c.neg.verify_result = i64::from(abi::X509_V_ERR_NO_VALID_SCTS);
    }
    match a {
        Answer::Continue | Answer::Allowed(true) => Ok(()),
        Answer::Fail { alert, reason } => {
            if c.cfg.verify_mode & abi::SSL_VERIFY_PEER == 0 {
                return Ok(());
            }
            let al = alert.map_or(abi::SSL_AD_HANDSHAKE_FAILURE, c_int::from);
            Err(Error::alert(al, *reason))
        }
        Answer::Allowed(false) => {
            if c.cfg.verify_mode & abi::SSL_VERIFY_PEER == 0 {
                return Ok(());
            }
            Err(Error::alert(
                abi::SSL_AD_HANDSHAKE_FAILURE,
                abi::SSL_R_CALLBACK_FAILED,
            ))
        }
        _ => Err(Error::internal()),
    }
}

/// Before a TLS 1.3 server Finished is processed: asks the status callback and the CT
/// validation when processing it will (a Finished that checks out, a certificate that suits
/// the suite), as the Finished's processing can't wait for the answers. `Ok(false)` while one
/// is awaited.
///
/// # Errors
/// Never; `Result` for the caller.
pub(super) fn initial_flight_answers(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
) -> Result<bool> {
    use subtle::ConstantTimeEq;
    if !(status_wanted(c) || c.cfg.request_scts) || !c.hs_in.is_empty() {
        return Ok(true);
    }
    let md = &c.hs.peer_finish_md;
    if md.len() != body.len() || !bool::from(md.as_slice().ct_eq(body)) {
        return Ok(true);
    }
    if check_cert_and_algorithm(c, p).is_err() {
        return Ok(true);
    }
    if status_wanted(c) {
        let req = Request::Status {
            ocsp_ids: Vec::new(),
            ocsp_exts: Vec::new(),
        };
        match ask_once(c, req, 0) {
            None => return Ok(false),
            Some(a) if status_result(&a).is_err() => return Ok(true),
            Some(_) => {}
        }
    }
    if c.cfg.request_scts {
        return Ok(ask_once(c, Request::CtValidate, 0).is_some());
    }
    Ok(true)
}

/// `tls_process_new_session_ticket`: a TLS 1.2 ticket, or a TLS 1.3 ticket with its PSK
/// (from the resumption master secret and the nonce) and extensions; the session gets the
/// ticket's SHA-256 as its ID. A TLS 1.3 ticket updates the session cache
/// ([`Event::UpdateCache`]).
///
/// # Errors
/// A malformed message (`SSL_R_LENGTH_MISMATCH`), an extension's error, or a failed hash.
pub(super) fn process_new_session_ticket(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
) -> Result<MsgProcess> {
    let tls13 = c.is_tls13();
    let (lifetime, age_add, nonce, ticket, exts) = match NewSessionTicket::parse(body, tls13)? {
        NewSessionTicket::Tls12(m) => (m.lifetime_hint, 0, Vec::new(), m.ticket, None),
        NewSessionTicket::Tls13(m) => {
            (m.lifetime, m.age_add, m.nonce, m.ticket, Some(m.extensions))
        }
    };
    if ticket.is_empty() {
        return Ok(MsgProcess::ContinueReading);
    }
    let now = super::now(c);
    let renewed = !tls13 && !c.neg.session.session_id.is_empty();
    {
        let s = &mut c.neg.session;
        s.time = now;
        s.ticket = Some(ticket.clone());
        s.ticket_lifetime_hint = u64::from(lifetime);
        s.ticket_age_add = age_add;
    }
    if let Some(exts) = &exts {
        if lifetime > 604_800 {
            c.neg.session.ticket_lifetime_hint = 604_800;
        }
        ext::collect(c, exts, cx::TLS1_3_NEW_SESSION_TICKET, 0, true)?;
        if ext::parse_all(c, p, cx::TLS1_3_NEW_SESSION_TICKET, 0, true)? == ext::Step::Wait {
            return Ok(MsgProcess::Ask);
        }
    }
    let id = keysched::hash_of(p, HashAlg::Sha256, &ticket)
        .map_err(|_| Error::alert_lib(abi::SSL_AD_INTERNAL_ERROR, abi::ERR_R_EVP_LIB))?;
    c.neg.session.session_id = id;
    if tls13 {
        let hash = keys::handshake_md(c)?;
        let rms = c.hs.sh.keys.resumption_master.clone();
        let psk = keysched::resumption_psk(p, hash, rms.bytes(), &nonce)?;
        let s = &mut c.neg.session;
        s.master_key = psk.bytes().to_vec();
        s.version = v::TLS1_3;
        if let Some(cp) = c.neg.cipher.or(c.hs.new_cipher) {
            s.cipher_id = cp.id;
        }
        c.notify(Event::UpdateCache { server: false });
        return Ok(MsgProcess::FinishedReading);
    }
    if renewed {
        c.notify(super::super::Event::SessionRenewed);
    }
    Ok(MsgProcess::ContinueReading)
}

/// `tls_process_hello_req`: a renegotiation request, refused with a no_renegotiation
/// warning under `SSL_OP_NO_RENEGOTIATION`, otherwise an abbreviated renegotiation
/// (`SSL_renegotiate_abbreviated`).
///
/// # Errors
/// A body (`SSL_R_LENGTH_MISMATCH`), or the alert couldn't be sent.
pub(super) fn process_hello_req(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
) -> Result<MsgProcess> {
    if !body.is_empty() {
        return Err(Error::decode(abi::SSL_R_LENGTH_MISMATCH));
    }
    if c.cfg.options & abi::SSL_OP_NO_RENEGOTIATION != 0 {
        let level = u8::try_from(abi::SSL3_AL_WARNING).map_err(|_| Error::internal())?;
        let desc = u8::try_from(abi::SSL_AD_NO_RENEGOTIATION).map_err(|_| Error::internal())?;
        c.send_alert(p, level, desc)?;
        return Ok(MsgProcess::FinishedReading);
    }
    // `SSL_renegotiate_abbreviated`.
    c.renegotiate = true;
    c.s3_renegotiate = true;
    // A TLS client answers with an abbreviated handshake, a DTLS client with a full one
    // (`SSL_renegotiate` rather than `SSL_renegotiate_abbreviated`, a historical discrepancy).
    c.hs.sh.new_session = c.cfg.dtls;
    Ok(MsgProcess::FinishedReading)
}
