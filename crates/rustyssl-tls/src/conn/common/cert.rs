//! The certificate messages both sides send alike (`statem_lib.c`): the certificate list
//! (`ssl3_output_cert_chain`, `tls_output_rpk`), CertificateVerify, and the CA names
//! (`parse_ca_names`, `construct_ca_names`).
//!
//! The chain to send is the configuration's ([`crate::conn::CertKey::chain`]): capi builds it
//! (`ssl_add_cert_chain`'s chain store and extra certificates) and checks it against the
//! security level (`ssl_security_cert_chain`) when it fills in the configuration.

use rustyssl_abi as abi;

use super::ext;
use super::sigalgs;
use crate::codec::{Reader, Writer};
use crate::conn::Connection;
use crate::conn::statem::MsgProcess;
use crate::consts::context as cx;
use crate::crypto::{PeerKey, Provider};
use crate::error::{Error, InFunc, Result};
use crate::msgs::cert::CertificateVerify;
use crate::msgs::ext::certificate_authorities;

/// The 64 spaces that start TLS 1.3's signed content (`TLS13_TBS_START_SIZE`).
const TBS_START: [u8; 64] = [0x20; 64];
/// The server's CertificateVerify context string, with its terminating zero.
const SERVER_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify\0";
/// The client's.
const CLIENT_CONTEXT: &[u8] = b"TLS 1.3, client CertificateVerify\0";

/// The certificate list (with its 3-octet length) for the certificate at `cert` in the
/// configuration (`ssl3_output_cert_chain`): each certificate with, in TLS 1.3, its extension
/// block (`SSL_EXT_TLS1_3_CERTIFICATE`, for its index in the chain). An empty list when there
/// is no certificate. `None` while an extension waits for an answer.
///
/// # Errors
/// A certificate is too long, or an extension failed.
pub fn output_cert_chain(
    c: &mut Connection,
    p: &dyn Provider,
    cert: Option<usize>,
) -> Result<Option<Vec<u8>>> {
    output_cert_chain_inner(c, p, cert).in_func("ssl3_output_cert_chain")
}

/// See [`output_cert_chain`].
fn output_cert_chain_inner(
    c: &mut Connection,
    p: &dyn Provider,
    cert: Option<usize>,
) -> Result<Option<Vec<u8>>> {
    // `ssl_add_cert_chain`'s security check of the chain to send.
    if let Some(reason) = cert
        .and_then(|i| c.cfg.certs.get(i))
        .and_then(|k| k.chain_security)
    {
        return Err(Error::alert(abi::SSL_AD_INTERNAL_ERROR, reason).in_func("ssl_add_cert_chain"));
    }
    let chain = cert
        .and_then(|i| c.cfg.certs.get(i))
        .map(|k| k.chain.clone())
        .unwrap_or_default();
    let mut w = Writer::new();
    let o = w.open(3);
    for (i, der) in chain.iter().enumerate() {
        w.vec(3, der).map_err(|_| Error::internal())?;
        if c.is_tls13() {
            c.ext_cert = Some(der.clone());
            let block = ext::construct(c, p, cx::TLS1_3_CERTIFICATE, i);
            c.ext_cert = None;
            let Some(block) = block? else {
                return Ok(None);
            };
            w.put(&block);
        }
    }
    w.close(o).map_err(|_| Error::internal())?;
    Ok(Some(w.into_bytes()))
}

/// The raw public key list (RFC 7250, `tls_output_rpk`) for the certificate at `cert`: TLS
/// 1.2's key alone, TLS 1.3's key with its extension block (`SSL_EXT_TLS1_3_RAW_PUBLIC_KEY`)
/// in a 3-octet-length entry. A client without a key sends an empty list. `None` while an
/// extension waits for an answer.
///
/// # Errors
/// A server without a key, a key too long, or an extension failed.
pub fn output_rpk(
    c: &mut Connection,
    p: &dyn Provider,
    cert: Option<usize>,
) -> Result<Option<Vec<u8>>> {
    let key = cert
        .and_then(|i| c.cfg.certs.get(i))
        .and_then(|k| k.raw_public_key.clone());
    let mut w = Writer::new();
    let Some(spki) = key else {
        if c.cfg.server {
            return Err(Error::internal());
        }
        w.u24(0);
        return Ok(Some(w.into_bytes()));
    };
    if spki.is_empty() {
        return Err(Error::internal());
    }
    if c.is_tls13() {
        let Some(block) = ext::construct(c, p, cx::TLS1_3_RAW_PUBLIC_KEY, 0)? else {
            return Ok(None);
        };
        let o = w.open(3);
        w.vec(3, &spki).map_err(|_| Error::internal())?;
        w.put(&block);
        w.close(o).map_err(|_| Error::internal())?;
    } else {
        w.vec(3, &spki).map_err(|_| Error::internal())?;
    }
    Ok(Some(w.into_bytes()))
}

/// Whether `der` decodes as an X.509 Name filling it, as `d2i_X509_NAME` does: a SEQUENCE of
/// SETs of SEQUENCEs that each start with an OBJECT IDENTIFIER. `Err(true)` when it decodes
/// but leaves octets over.
fn check_name(der: &[u8]) -> core::result::Result<(), bool> {
    use rustyssl_asn1::der::element;
    let seq = element(der).map_err(|_| false)?;
    let universal = |e: &rustyssl_asn1::der::Element<'_>, tag: i32, constructed: bool| {
        e.header.class == 0 && e.header.tag == tag && e.header.constructed == constructed
    };
    if !universal(&seq, 16, true) {
        return Err(false);
    }
    let mut rdns = seq.content;
    while !rdns.is_empty() {
        let set = element(rdns).map_err(|_| false)?;
        if !universal(&set, 17, true) {
            return Err(false);
        }
        let mut atvs = set.content;
        while !atvs.is_empty() {
            let atv = element(atvs).map_err(|_| false)?;
            if !universal(&atv, 16, true) {
                return Err(false);
            }
            let oid = element(atv.content).map_err(|_| false)?;
            if !universal(&oid, 6, false) || oid.raw.len() >= atv.content.len() {
                return Err(false);
            }
            element(atv.content.get(oid.raw.len()..).unwrap_or_default()).map_err(|_| false)?;
            atvs = atvs.get(atv.raw.len()..).unwrap_or_default();
        }
        rdns = rdns.get(set.raw.len()..).unwrap_or_default();
    }
    if seq.raw.len() != der.len() {
        return Err(true);
    }
    Ok(())
}

/// `parse_ca_names`: the peer's CA names (a CertificateRequest's, or the
/// certificate_authorities extension's), read from `rd` into the negotiated `peer_ca_names`.
/// A broken list is `SSL_R_LENGTH_MISMATCH`, a name that doesn't decode `ERR_R_ASN1_LIB`, one
/// with octets over `SSL_R_CA_DN_LENGTH_MISMATCH`; all decode-error.
///
/// # Errors
/// As above.
pub fn parse_ca_names(c: &mut Connection, rd: &mut Reader<'_>) -> Result<()> {
    parse_ca_names_inner(c, rd).in_func("parse_ca_names")
}

/// See [`parse_ca_names`].
fn parse_ca_names_inner(c: &mut Connection, rd: &mut Reader<'_>) -> Result<()> {
    let names = certificate_authorities::read(rd)?;
    for n in &names {
        match check_name(n) {
            Ok(()) => {}
            Err(true) => return Err(Error::decode(abi::SSL_R_CA_DN_LENGTH_MISMATCH)),
            Err(false) => {
                return Err(Error::alert_lib(
                    abi::SSL_AD_DECODE_ERROR,
                    abi::ERR_R_ASN1_LIB,
                ));
            }
        }
    }
    c.neg.peer_ca_names = Some(names);
    Ok(())
}

/// `construct_ca_names`: the list of `names` (with its 2-octet length), empty with
/// `SSL_OP_DISABLE_TLSEXT_CA_NAMES`.
///
/// # Errors
/// The list is too long.
pub fn construct_ca_names(c: &Connection, names: &[Vec<u8>]) -> Result<Vec<u8>> {
    construct_ca_names_inner(c, names).in_func("construct_ca_names")
}

/// See [`construct_ca_names`].
fn construct_ca_names_inner(c: &Connection, names: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    let none: &[Vec<u8>] = &[];
    let list = if c.cfg.options & abi::SSL_OP_DISABLE_TLSEXT_CA_NAMES != 0 {
        none
    } else {
        names
    };
    certificate_authorities::write(&mut w, list).map_err(|_| Error::internal())?;
    Ok(w.into_bytes())
}

/// Keeps the transcript hash for the peer's TLS 1.3 CertificateVerify, after its Certificate
/// (`s->cert_verify_hash`, saved in the role's Certificate processing).
///
/// # Errors
/// The transcript hash hasn't started.
pub fn save_cert_verify_hash(c: &mut Connection) -> Result<()> {
    c.hs.sh.cert_verify_hash = c.hs.transcript.current()?;
    Ok(())
}

/// `get_cert_verify_tbs_data`: what a CertificateVerify signs. TLS 1.3: 64 spaces, the
/// signer's context string, and the transcript hash (`reading`: the one saved before the
/// peer's CertificateVerify). Earlier: every handshake message so far, as buffered.
///
/// # Errors
/// No transcript.
pub fn cert_verify_tbs(c: &Connection, signer_is_server: bool, reading: bool) -> Result<Vec<u8>> {
    cert_verify_tbs_inner(c, signer_is_server, reading).in_func("get_cert_verify_tbs_data")
}

/// See [`cert_verify_tbs`].
fn cert_verify_tbs_inner(c: &Connection, signer_is_server: bool, reading: bool) -> Result<Vec<u8>> {
    if c.is_tls13() {
        let hash = if reading {
            c.hs.sh.cert_verify_hash.clone()
        } else {
            c.hs.transcript.current()?
        };
        let mut tbs = TBS_START.to_vec();
        tbs.extend_from_slice(if signer_is_server {
            SERVER_CONTEXT
        } else {
            CLIENT_CONTEXT
        });
        tbs.extend_from_slice(&hash);
        return Ok(tbs);
    }
    match c.hs.transcript.buffered() {
        Some(b) if !b.is_empty() => Ok(b.to_vec()),
        _ => Err(Error::internal()),
    }
}

/// `ssl3_digest_cached_records(s, 0)`: the transcript is hashed from now on and the buffer
/// dropped.
fn digest_cached_records(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    digest_cached_records_inner(c, p).in_func("ssl3_digest_cached_records")
}

/// See [`digest_cached_records`].
fn digest_cached_records_inner(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    if c.hs.transcript.alg().is_some() {
        c.hs.transcript.drop_buffer();
        return Ok(());
    }
    let alg = super::keys::handshake_md(c)?;
    c.hs.transcript.start_hash(p, alg, false)
}

/// `tls_construct_cert_verify`: this end's CertificateVerify, signed with the chosen
/// certificate's key and scheme ([`super::Shared::cert`], [`super::Shared::sigalg`]); then the
/// handshake buffer is dropped.
///
/// # Errors
/// No certificate or scheme chosen (an internal error), or the signature failed
/// (`ERR_R_EVP_LIB`, internal-error).
pub fn construct_cert_verify(c: &mut Connection, p: &dyn Provider) -> Result<Vec<u8>> {
    let (Some(scheme), Some(idx)) = (c.hs.sh.sigalg, c.hs.sh.cert) else {
        return Err(Error::internal());
    };
    let key = c
        .cfg
        .certs
        .get(idx)
        .map(|k| k.key)
        .ok_or_else(Error::internal)?;
    let tbs = cert_verify_tbs(c, c.cfg.server, false)?;
    let signature = p
        .sign(key, scheme, &tbs)
        .map_err(|_| Error::alert_lib(abi::SSL_AD_INTERNAL_ERROR, abi::ERR_R_EVP_LIB))?;
    let body = CertificateVerify {
        scheme: sigalgs::use_sigalgs(c).then_some(scheme),
        signature,
    }
    .encode()?;
    digest_cached_records(c, p)?;
    Ok(body)
}

/// `tls_get_peer_pkey`: the peer's key (its raw public key or its leaf certificate's) as DER,
/// whether it is a SubjectPublicKeyInfo, and what the checks need to know about it.
///
/// # Errors
/// No key, or the provider can't read it (internal errors).
pub fn peer_key(c: &Connection, p: &dyn Provider) -> Result<(Vec<u8>, bool, PeerKey)> {
    let (der, spki) = match (&c.neg.peer_rpk, c.neg.peer_chain.first()) {
        (Some(k), _) => (k.clone(), true),
        (None, Some(leaf)) => (leaf.clone(), false),
        (None, None) => return Err(Error::internal()),
    };
    let info = p.peer_key(&der, spki).map_err(|_| Error::internal())?;
    Ok((der, spki, info))
}

/// `tls_process_cert_verify`: checks the peer's CertificateVerify: its key must be a signing
/// type (`SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE`), the scheme must suit it and this
/// end's list ([`sigalgs::check_peer_sigalg`]; below TLS 1.2 the legacy scheme,
/// `SSL_R_LEGACY_SIGALG_DISALLOWED_OR_UNSUPPORTED`), and the signature must verify
/// (`SSL_R_BAD_SIGNATURE`, decrypt-error). A TLS 1.3 client that was asked for a certificate
/// continues processing (to prepare it after the server's key is known).
///
/// # Errors
/// As above, or the message doesn't decode.
pub fn process_cert_verify(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
) -> Result<MsgProcess> {
    let r = verify(c, p, body);
    c.hs.transcript.drop_buffer();
    r?;
    if !c.cfg.server && c.is_tls13() && c.hs.sh.cert_req == 1 {
        Ok(MsgProcess::ContinueProcessing)
    } else {
        Ok(MsgProcess::ContinueReading)
    }
}

/// [`process_cert_verify`]'s checks.
fn verify(c: &mut Connection, p: &dyn Provider, body: &[u8]) -> Result<()> {
    let (der, _, key) = peer_key(c, p)?;
    if sigalgs::slot_of(c, &key.kind).is_none() {
        return Err(Error::alert(
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE,
        ));
    }
    let use_sigalgs = sigalgs::use_sigalgs(c);
    if use_sigalgs {
        let scheme = CertificateVerify::scheme_of(body)?;
        sigalgs::check_peer_sigalg(c, scheme, &key)?;
    } else if !sigalgs::set_peer_legacy_sigalg(c, &key.kind) {
        return Err(Error::alert(
            abi::SSL_AD_INTERNAL_ERROR,
            abi::SSL_R_LEGACY_SIGALG_DISALLOWED_OR_UNSUPPORTED,
        ));
    }
    let scheme = c.hs.sh.peer_sigalg.ok_or_else(Error::internal)?;
    let cv = CertificateVerify::parse(body, use_sigalgs)?;
    let tbs = cert_verify_tbs(c, !c.cfg.server, true)?;
    let bad = Error::alert(abi::SSL_AD_DECRYPT_ERROR, abi::SSL_R_BAD_SIGNATURE);
    if !p
        .verify(&der, scheme, &tbs, &cv.signature)
        .map_err(|_| bad)?
    {
        return Err(bad);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_name_shapes() {
        // SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8String "a" } } }
        let name = [
            0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x01, b'a',
        ];
        assert_eq!(check_name(&name), Ok(()));
        let empty = [0x30, 0x00];
        assert_eq!(check_name(&empty), Ok(()));
        let mut over = name.to_vec();
        over.push(0);
        assert_eq!(check_name(&over), Err(true));
        assert_eq!(check_name(&[0x31, 0x00]), Err(false));
        assert_eq!(check_name(&[0x30, 0x02, 0x31, 0x01]), Err(false));
        // An attribute without a value.
        assert_eq!(
            check_name(&[0x30, 0x07, 0x31, 0x05, 0x30, 0x03, 0x06, 0x01, 0x55]),
            Err(false)
        );
    }

    #[test]
    fn tls13_signed_content() {
        let mut c = Connection::new(crate::conn::Config::default());
        c.neg.version = super::super::version::of(abi::TLS1_3_VERSION);
        c.hs.sh.cert_verify_hash = vec![0xaa; 32];
        let tbs = cert_verify_tbs(&c, true, true).unwrap();
        assert_eq!(tbs.len(), 64 + 34 + 32);
        assert!(tbs.starts_with(&[0x20; 64]));
        assert_eq!(tbs.get(64..98), Some(SERVER_CONTEXT));
        assert_eq!(tbs.get(98..), Some(&[0xaa; 32][..]));
        let tbs = cert_verify_tbs(&c, false, true).unwrap();
        assert_eq!(tbs.get(64..98), Some(CLIENT_CONTEXT));
    }
}
