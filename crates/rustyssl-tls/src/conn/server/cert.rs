//! The server's certificate messages (`tls_construct_server_certificate`,
//! `tls_construct_certificate_request`, `tls_process_client_certificate`,
//! `tls_process_client_rpk`), and `ssl_x509err2alert`.

use core::ffi::c_int;

use rustyssl_abi as abi;

use super::{digest_cached_records, octet, state};
use crate::codec::{Reader, Writer};
use crate::conn::common::ext::{self, Step};
use crate::conn::common::{self, Pha, ask_once, finished, sigalgs};
use crate::conn::statem::{Construct, MsgProcess};
use crate::conn::{Answer, Connection, Request};
use crate::consts::context as cx;
use crate::crypto::Provider;
use crate::error::{Error, Result};
use crate::suites::masks::{SSL_aDSS, SSL_aECDSA, SSL_aRSA};

/// `ssl_x509err2alert`: the alert for a verification error (`x509table`), certificate-unknown
/// for any other.
#[must_use]
pub(crate) fn x509err2alert(err: i64) -> c_int {
    const TABLE: [(c_int, c_int); 40] = [
        (
            abi::X509_V_ERR_APPLICATION_VERIFICATION,
            abi::SSL_AD_HANDSHAKE_FAILURE,
        ),
        (
            abi::X509_V_ERR_CA_KEY_TOO_SMALL,
            abi::SSL_AD_BAD_CERTIFICATE,
        ),
        (
            abi::X509_V_ERR_EC_KEY_EXPLICIT_PARAMS,
            abi::SSL_AD_BAD_CERTIFICATE,
        ),
        (abi::X509_V_ERR_CA_MD_TOO_WEAK, abi::SSL_AD_BAD_CERTIFICATE),
        (abi::X509_V_ERR_CERT_CHAIN_TOO_LONG, abi::SSL_AD_UNKNOWN_CA),
        (
            abi::X509_V_ERR_CERT_HAS_EXPIRED,
            abi::SSL_AD_CERTIFICATE_EXPIRED,
        ),
        (
            abi::X509_V_ERR_CERT_NOT_YET_VALID,
            abi::SSL_AD_BAD_CERTIFICATE,
        ),
        (abi::X509_V_ERR_CERT_REJECTED, abi::SSL_AD_BAD_CERTIFICATE),
        (
            abi::X509_V_ERR_CERT_REVOKED,
            abi::SSL_AD_CERTIFICATE_REVOKED,
        ),
        (
            abi::X509_V_ERR_CERT_SIGNATURE_FAILURE,
            abi::SSL_AD_DECRYPT_ERROR,
        ),
        (abi::X509_V_ERR_CERT_UNTRUSTED, abi::SSL_AD_BAD_CERTIFICATE),
        (
            abi::X509_V_ERR_CRL_HAS_EXPIRED,
            abi::SSL_AD_CERTIFICATE_EXPIRED,
        ),
        (
            abi::X509_V_ERR_CRL_NOT_YET_VALID,
            abi::SSL_AD_BAD_CERTIFICATE,
        ),
        (
            abi::X509_V_ERR_CRL_SIGNATURE_FAILURE,
            abi::SSL_AD_DECRYPT_ERROR,
        ),
        (abi::X509_V_ERR_DANE_NO_MATCH, abi::SSL_AD_BAD_CERTIFICATE),
        (
            abi::X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
            abi::SSL_AD_UNKNOWN_CA,
        ),
        (
            abi::X509_V_ERR_EE_KEY_TOO_SMALL,
            abi::SSL_AD_BAD_CERTIFICATE,
        ),
        (abi::X509_V_ERR_EMAIL_MISMATCH, abi::SSL_AD_BAD_CERTIFICATE),
        (
            abi::X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD,
            abi::SSL_AD_BAD_CERTIFICATE,
        ),
        (
            abi::X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD,
            abi::SSL_AD_BAD_CERTIFICATE,
        ),
        (
            abi::X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD,
            abi::SSL_AD_BAD_CERTIFICATE,
        ),
        (
            abi::X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD,
            abi::SSL_AD_BAD_CERTIFICATE,
        ),
        (
            abi::X509_V_ERR_HOSTNAME_MISMATCH,
            abi::SSL_AD_BAD_CERTIFICATE,
        ),
        (abi::X509_V_ERR_INVALID_CA, abi::SSL_AD_UNKNOWN_CA),
        (abi::X509_V_ERR_INVALID_CALL, abi::SSL_AD_INTERNAL_ERROR),
        (
            abi::X509_V_ERR_INVALID_PURPOSE,
            abi::SSL_AD_UNSUPPORTED_CERTIFICATE,
        ),
        (
            abi::X509_V_ERR_IP_ADDRESS_MISMATCH,
            abi::SSL_AD_BAD_CERTIFICATE,
        ),
        (abi::X509_V_ERR_OUT_OF_MEM, abi::SSL_AD_INTERNAL_ERROR),
        (abi::X509_V_ERR_PATH_LENGTH_EXCEEDED, abi::SSL_AD_UNKNOWN_CA),
        (
            abi::X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN,
            abi::SSL_AD_UNKNOWN_CA,
        ),
        (abi::X509_V_ERR_STORE_LOOKUP, abi::SSL_AD_INTERNAL_ERROR),
        (
            abi::X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY,
            abi::SSL_AD_BAD_CERTIFICATE,
        ),
        (
            abi::X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE,
            abi::SSL_AD_BAD_CERTIFICATE,
        ),
        (
            abi::X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE,
            abi::SSL_AD_BAD_CERTIFICATE,
        ),
        (abi::X509_V_ERR_UNABLE_TO_GET_CRL, abi::SSL_AD_UNKNOWN_CA),
        (
            abi::X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER,
            abi::SSL_AD_UNKNOWN_CA,
        ),
        (
            abi::X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
            abi::SSL_AD_UNKNOWN_CA,
        ),
        (
            abi::X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
            abi::SSL_AD_UNKNOWN_CA,
        ),
        (
            abi::X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
            abi::SSL_AD_UNKNOWN_CA,
        ),
        (abi::X509_V_ERR_UNSPECIFIED, abi::SSL_AD_INTERNAL_ERROR),
    ];
    TABLE
        .iter()
        .find(|(e, _)| i64::from(*e) == err)
        .map_or(abi::SSL_AD_CERTIFICATE_UNKNOWN, |(_, a)| *a)
}

/// `tls_construct_server_certificate`: TLS 1.3's empty context, then the chain of the
/// certificate chosen (or its raw public key, when negotiated).
///
/// # Errors
/// No certificate chosen, or an entry's extension failed.
pub(crate) fn construct_server_certificate(
    c: &mut Connection,
    p: &dyn Provider,
) -> Result<Construct> {
    let cert = c.hs.sh.cert.ok_or_else(Error::internal)?;
    let mut body = Vec::new();
    if c.is_tls13() {
        body.push(0);
    }
    let t = c.neg.server_cert_type;
    let list = if t == octet(abi::TLSEXT_cert_type_rpk) {
        common::cert::output_rpk(c, p, Some(cert))?
    } else if t == octet(abi::TLSEXT_cert_type_x509) {
        common::cert::output_cert_chain(c, p, Some(cert))?
    } else {
        return Err(Error::internal());
    };
    let Some(list) = list else {
        return Ok(Construct::Ask);
    };
    body.extend_from_slice(&list);
    Ok(Construct::Send(body))
}

/// `ssl3_get_req_cert_type`: the certificate types a TLS 1.2 CertificateRequest accepts: the
/// configured list (`SSL_set1_client_certificate_types`), or else by the signature algorithms
/// this end allows (`ssl_set_sig_mask`): RSA, DSS, and ECDSA signing.
fn req_cert_types(c: &Connection) -> Vec<u8> {
    if let Some(t) = &c.cfg.req_cert_types {
        return t.clone();
    }
    let alg_a = sigalgs::sig_mask(c, abi::SSL_SECOP_SIGALG_MASK);
    let mut out = Vec::new();
    if alg_a & SSL_aRSA == 0 {
        out.push(octet(abi::SSL3_CT_RSA_SIGN));
    }
    if alg_a & SSL_aDSS == 0 {
        out.push(octet(abi::SSL3_CT_DSS_SIGN));
    }
    if alg_a & SSL_aECDSA == 0 {
        out.push(octet(abi::TLS_CT_ECDSA_SIGN));
    }
    out
}

/// `tls_construct_certificate_request`. TLS 1.3: a random 32-octet context for
/// post-handshake authentication (whose transcript continues from the client's Finished),
/// otherwise an empty one, and the CertificateRequest extensions. TLS 1.2: the certificate
/// types, the signature algorithms (TLS 1.2), and the CA names.
///
/// # Errors
/// An extension failed, or no signature algorithm is left to offer.
pub(crate) fn construct_certificate_request(
    c: &mut Connection,
    p: &dyn Provider,
) -> Result<Construct> {
    let mut w = Writer::new();
    if c.is_tls13() {
        let context = if c.hs.sh.pha == Pha::RequestPending {
            let mut ctx = vec![0u8; 32];
            p.random(&mut ctx, false)
                .map_err(|_| Error::alert(abi::SSL_AD_INTERNAL_ERROR, abi::ERR_R_INTERNAL_ERROR))?;
            c.hs.sh.pha_context = Some(ctx.clone());
            finished::restore_handshake_digest_for_pha(c)?;
            ctx
        } else {
            Vec::new()
        };
        let Some(block) = ext::construct(c, p, cx::TLS1_3_CERTIFICATE_REQUEST, 0)? else {
            return Ok(Construct::Ask);
        };
        w.vec(1, &context).map_err(|_| Error::internal())?;
        w.put(&block);
    } else {
        w.vec(1, &req_cert_types(c))
            .map_err(|_| Error::internal())?;
        if sigalgs::use_sigalgs(c) {
            let list = sigalgs::psigalgs(c, true);
            let schemes = sigalgs::copy_sigalgs(c, &list).map_err(|_| Error::internal())?;
            if schemes.is_empty() {
                return Err(Error::internal());
            }
            let o = w.open(2);
            for s in schemes {
                w.u16(s);
            }
            w.close(o).map_err(|_| Error::internal())?;
        }
        let names = c.cfg.ca_names.clone();
        w.put(&common::cert::construct_ca_names(c, &names)?);
    }
    let s = state(c)?;
    s.certreqs_sent = s.certreqs_sent.saturating_add(1);
    c.hs.sh.cert_request = true;
    Ok(Construct::Send(w.into_bytes()))
}

/// The client didn't send a certificate: an error if one is required
/// (`SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE`, certificate-required).
fn check_required(c: &Connection) -> Result<()> {
    let vm = c.cfg.verify_mode;
    if vm & abi::SSL_VERIFY_PEER != 0 && vm & abi::SSL_VERIFY_FAIL_IF_NO_PEER_CERT != 0 {
        return Err(Error::alert(
            abi::SSL_AD_CERTIFICATE_REQUIRED,
            abi::SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE,
        ));
    }
    Ok(())
}

/// TLS 1.3's certificate_request_context must be the one sent (empty during the handshake;
/// `SSL_R_INVALID_CONTEXT`, decode-error).
fn check_context(c: &Connection, ctx: &[u8]) -> Result<()> {
    let ok = match &c.hs.sh.pha_context {
        None => ctx.is_empty(),
        Some(pc) => pc.as_slice() == ctx,
    };
    if ok {
        Ok(())
    } else {
        Err(Error::decode(abi::SSL_R_INVALID_CONTEXT))
    }
}

/// The verification of the client's chain ([`Request::Verify`]): `None` while waiting.
fn verify(c: &mut Connection, chain: Vec<Vec<u8>>) -> Result<Option<i64>> {
    let r = ask_once(c, Request::Verify { chain }, 0);
    match r {
        None => Ok(None),
        Some(Answer::Verified {
            result,
            proceed,
            verified_chain,
        }) => {
            c.neg.verify_result = result;
            c.neg.verified_chain = verified_chain;
            if !proceed {
                return Err(Error::alert(
                    x509err2alert(result),
                    abi::SSL_R_CERTIFICATE_VERIFY_FAILED,
                ));
            }
            Ok(Some(result))
        }
        Some(_) => Err(Error::internal()),
    }
}

/// What a received certificate leaves behind: the session's peer, and in TLS 1.3 the
/// transcript hash for the CertificateVerify, with the tickets sent again after it.
fn finish_peer(
    c: &mut Connection,
    p: &dyn Provider,
    chain: Vec<Vec<u8>>,
    rpk: Option<Vec<u8>>,
) -> Result<()> {
    c.neg.session.peer_chain.clone_from(&chain);
    c.neg.peer_chain = chain;
    c.neg.peer_rpk = rpk;
    c.neg.session.verify_result = c.neg.verify_result;
    if c.is_tls13() {
        digest_cached_records(c, p, true)?;
        common::cert::save_cert_verify_hash(c)?;
        state(c)?.sent_tickets = 0;
    }
    Ok(())
}

/// `tls_process_client_certificate`: the client's chain (each entry DER that fills it: a
/// decoding failure is `ERR_R_ASN1_LIB`, a short one `SSL_R_CERT_LENGTH_MISMATCH`, both
/// decode-error; in TLS 1.3 each with its extensions), verified ([`Request::Verify`]; a
/// failure that isn't overridden is `SSL_R_CERTIFICATE_VERIFY_FAILED` with the error's
/// alert). An empty one is fine unless a certificate is required. A raw public key goes to
/// [`process_client_rpk`].
///
/// # Errors
/// As above.
pub(crate) fn process_client_certificate(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
) -> Result<MsgProcess> {
    c.rr.allow_plain_alerts = false;
    let t = c.neg.client_cert_type;
    if t == octet(abi::TLSEXT_cert_type_rpk) {
        return process_client_rpk(c, p, body);
    }
    if t != octet(abi::TLSEXT_cert_type_x509) {
        return Err(Error::alert(
            abi::SSL_AD_UNSUPPORTED_CERTIFICATE,
            abi::SSL_R_UNKNOWN_CERTIFICATE_TYPE,
        ));
    }
    let tls13 = c.is_tls13();
    let mut rd = Reader::new(body);
    if tls13 {
        let ctx = rd
            .vec8()
            .map_err(|_| Error::decode(abi::SSL_R_INVALID_CONTEXT))?;
        check_context(c, ctx.rest())?;
    }
    let mm = Error::decode(abi::SSL_R_LENGTH_MISMATCH);
    let mut list = rd.vec24().map_err(|_| mm)?;
    rd.end().map_err(|_| mm)?;
    let mut chain = Vec::new();
    let mut idx = 0usize;
    while !list.is_empty() {
        let cl = Error::decode(abi::SSL_R_CERT_LENGTH_MISMATCH);
        let n = usize::try_from(list.u24().map_err(|_| cl)?).map_err(|_| cl)?;
        let der = list.take(n).map_err(|_| cl)?;
        match rustyssl_asn1::der::element(der) {
            Ok(e) if e.header.class == 0 && e.header.tag == 16 && e.header.constructed => {
                if e.raw.len() != der.len() {
                    return Err(cl);
                }
            }
            _ => {
                return Err(Error::alert_lib(
                    abi::SSL_AD_DECODE_ERROR,
                    abi::ERR_R_ASN1_LIB,
                ));
            }
        }
        if tls13 {
            let exts = list
                .vec16()
                .map_err(|_| Error::decode(abi::SSL_R_BAD_LENGTH))?;
            ext::collect(c, exts.rest(), cx::TLS1_3_CERTIFICATE, idx, idx == 0)?;
            c.ext_cert = Some(der.to_vec());
            let step = ext::parse_all(c, p, cx::TLS1_3_CERTIFICATE, idx, list.is_empty());
            c.ext_cert = None;
            if step? == Step::Wait {
                return Ok(MsgProcess::Ask);
            }
        }
        chain.push(der.to_vec());
        idx = idx.saturating_add(1);
    }
    if chain.is_empty() {
        check_required(c)?;
        if c.hs.transcript.buffered().is_some() {
            digest_cached_records(c, p, false)?;
        }
    } else {
        if verify(c, chain.clone())?.is_none() {
            return Ok(MsgProcess::Ask);
        }
        if chain
            .first()
            .is_none_or(|leaf| p.peer_key(leaf, false).is_err())
        {
            return Err(Error::alert(
                abi::SSL_AD_HANDSHAKE_FAILURE,
                abi::SSL_R_UNKNOWN_CERTIFICATE_TYPE,
            ));
        }
    }
    finish_peer(c, p, chain, None)?;
    Ok(MsgProcess::ContinueReading)
}

/// `tls_process_client_rpk`: the client's raw public key (RFC 7250), verified as a chain of
/// one SubjectPublicKeyInfo ([`Request::Verify`], with the client certificate type telling
/// capi it is a key).
///
/// # Errors
/// The message doesn't decode, a key is required and missing, or verification failed.
fn process_client_rpk(c: &mut Connection, p: &dyn Provider, body: &[u8]) -> Result<MsgProcess> {
    let tls13 = c.is_tls13();
    let rd = crate::msgs::cert::RpkReader::new(body, tls13)?;
    if let Some(ctx) = rd.context {
        check_context(c, ctx)?;
    }
    let Some(spki) = rd.spki.map(<[u8]>::to_vec) else {
        check_required(c)?;
        finish_peer(c, p, Vec::new(), None)?;
        return Ok(MsgProcess::ContinueReading);
    };
    if p.peer_key(&spki, true).is_err() {
        return Err(Error::decode(abi::SSL_R_LENGTH_MISMATCH));
    }
    if tls13 {
        let exts = rd.extensions()?;
        ext::collect(c, exts, cx::TLS1_3_RAW_PUBLIC_KEY, 0, true)?;
        if ext::parse_all(c, p, cx::TLS1_3_RAW_PUBLIC_KEY, 0, true)? == Step::Wait {
            return Ok(MsgProcess::Ask);
        }
    }
    if verify(c, vec![spki.clone()])?.is_none() {
        return Ok(MsgProcess::Ask);
    }
    finish_peer(c, p, Vec::new(), Some(spki))?;
    Ok(MsgProcess::ContinueReading)
}
