//! What the client sends besides its hello and Finished: TLS 1.2's ClientKeyExchange (with
//! the master secret made after it), and its certificate (chosen by the certificate callbacks:
//! `tls_prepare_client_certificate`, `tls_construct_client_certificate`).

use rustyssl_abi as abi;

use super::{Connection, digest_cached_records, middlebox, state};
use crate::codec::Writer;
use crate::conn::common::{EarlyDataState, Pha, ask_once, cert, finished, keys, sigalgs};
use crate::conn::statem::{Construct, Work};
use crate::conn::{Answer, Event, Request};
use crate::crypto::{Provider, Secret};
use crate::error::{Error, InFunc, Result};
use crate::keysched::keylog;
use crate::suites::masks::{
    SSL_PSK, SSL_kDHE, SSL_kDHEPSK, SSL_kECDHE, SSL_kECDHEPSK, SSL_kPSK, SSL_kRSA, SSL_kRSAPSK,
    SSL_kSRP,
};

/// `PSK_MAX_PSK_LEN` and `PSK_MAX_IDENTITY_LEN`.
fn psk_limits() -> (usize, usize) {
    (
        usize::try_from(abi::PSK_MAX_PSK_LEN).unwrap_or(512),
        usize::try_from(abi::PSK_MAX_IDENTITY_LEN).unwrap_or(128),
    )
}

/// `tls_construct_cke_psk_preamble`: the PSK callback's identity (written) and key (kept).
fn psk_preamble(c: &mut Connection, w: &mut Writer) -> Result<Option<Construct>> {
    psk_preamble_inner(c, w).in_func("tls_construct_cke_psk_preamble")
}

/// See [`psk_preamble`].
fn psk_preamble_inner(c: &mut Connection, w: &mut Writer) -> Result<Option<Construct>> {
    if !c.cfg.callbacks.psk {
        return Err(Error::alert(
            abi::SSL_AD_INTERNAL_ERROR,
            abi::SSL_R_PSK_NO_CLIENT_CB,
        ));
    }
    let hint = state(c)?.psk_hint.clone().unwrap_or_default();
    let Some(a) = ask_once(
        c,
        Request::Psk {
            hint_or_identity: hint,
        },
        0,
    ) else {
        return Ok(Some(Construct::Ask));
    };
    let psk = match a {
        Answer::Psk(p) => p,
        Answer::Fail { .. } => None,
        _ => return Err(Error::internal()),
    };
    let (max_psk, max_id) = psk_limits();
    let Some(psk) = psk.filter(|x| !x.key.is_empty()) else {
        return Err(Error::alert(
            abi::SSL_AD_HANDSHAKE_FAILURE,
            abi::SSL_R_PSK_IDENTITY_NOT_FOUND,
        ));
    };
    if psk.key.len() > max_psk {
        return Err(Error::alert_lib(
            abi::SSL_AD_HANDSHAKE_FAILURE,
            abi::ERR_R_INTERNAL_ERROR,
        ));
    }
    if psk.identity.len() > max_id {
        return Err(Error::internal());
    }
    state(c)?.psk = Some(Secret::new(psk.key.clone()));
    w.vec(2, &psk.identity).map_err(|_| Error::internal())?;
    Ok(None)
}

/// `tls_construct_client_key_exchange`: the PSK identity, then the method's value: RSA's
/// encrypted premaster secret (the version offered and 46 random octets, logged as an `RSA`
/// key log line), or the client's DHE or ECDHE share made with the ServerKeyExchange.
///
/// # Errors
/// OpenSSL's alert and reason.
pub(super) fn construct_client_key_exchange(
    c: &mut Connection,
    p: &dyn Provider,
) -> Result<Construct> {
    let cp = c.hs.new_cipher.ok_or_else(Error::internal)?;
    let mkey = cp.mkey;
    let mut w = Writer::new();
    if mkey & SSL_PSK != 0
        && let Some(ask) = psk_preamble(c, &mut w)?
    {
        return Ok(ask);
    }
    if mkey & (SSL_kRSA | SSL_kRSAPSK) != 0 {
        let Some(leaf) = c.neg.peer_chain.first().cloned() else {
            return Err(Error::internal());
        };
        let len = usize::try_from(abi::SSL_MAX_MASTER_KEY_LENGTH).unwrap_or(48);
        let mut pms = vec![0u8; len];
        let [hi, lo] = c.hs.sh.client_version.to_be_bytes();
        if let Some(b) = pms.get_mut(..2) {
            b.copy_from_slice(&[hi, lo]);
        }
        p.random(pms.get_mut(2..).unwrap_or_default(), false)
            .map_err(|_| Error::alert_lib(abi::SSL_AD_INTERNAL_ERROR, abi::ERR_R_RAND_LIB))?;
        let enc = p
            .rsa_encrypt(&leaf, &pms)
            .map_err(|_| Error::alert(abi::SSL_AD_INTERNAL_ERROR, abi::SSL_R_BAD_RSA_ENCRYPT))?;
        w.vec(2, &enc).map_err(|_| Error::internal())?;
        if c.cfg.callbacks.keylog {
            c.notify(Event::Keylog(keylog::rsa_line(&enc, &pms)));
        }
        state(c)?.pms = Some(Secret::new(pms));
    } else if mkey & (SSL_kDHE | SSL_kDHEPSK) != 0 {
        let kx = state(c)?.kx12.take().ok_or_else(Error::internal)?;
        w.vec(2, &kx.public).map_err(|_| Error::internal())?;
        state(c)?.pms = Some(kx.pms);
    } else if mkey & (SSL_kECDHE | SSL_kECDHEPSK) != 0 {
        let kx = state(c)?.kx12.take().ok_or_else(Error::internal)?;
        w.vec(1, &kx.public).map_err(|_| Error::internal())?;
        state(c)?.pms = Some(kx.pms);
    } else if mkey & SSL_kSRP != 0 {
        let a = state(c)?.srp_a.clone().ok_or_else(Error::internal)?;
        w.vec(2, &a).map_err(|_| Error::internal())?;
        // The session's `srp_username` (`tls_construct_cke_srp`).
        c.neg.session.srp_username.clone_from(&c.cfg.srp_login);
        let Some(pms) = srp_client_secret(c)? else {
            return Ok(Construct::Ask);
        };
        state(c)?.pms = Some(pms);
    } else if mkey & SSL_kPSK == 0 {
        return Err(Error::internal());
    }
    Ok(Construct::Send(w.into_bytes()))
}

/// `srp_generate_client_master_secret`'s premaster secret ([`Request::SrpClientSecret`]):
/// `SSL_R_CALLBACK_FAILED` when the password callback gives none, else internal-error when
/// it can't be made. `None` while waiting.
fn srp_client_secret(c: &mut Connection) -> Result<Option<Secret>> {
    srp_client_secret_inner(c).in_func("srp_generate_client_master_secret")
}

/// See [`srp_client_secret`].
fn srp_client_secret_inner(c: &mut Connection) -> Result<Option<Secret>> {
    match ask_once(c, Request::SrpClientSecret, 0) {
        None => Ok(None),
        Some(Answer::SrpValue(Some(k))) => Ok(Some(Secret::new(k))),
        Some(Answer::Fail { alert, reason }) => Err(Error::alert(
            alert.map_or(abi::SSL_AD_INTERNAL_ERROR, core::ffi::c_int::from),
            reason,
        )),
        Some(_) => Err(Error::alert_lib(
            abi::SSL_AD_INTERNAL_ERROR,
            abi::ERR_R_INTERNAL_ERROR,
        )),
    }
}

/// `tls_client_key_exchange_post_work`: the master secret (`ssl_generate_master_secret`,
/// which wraps the premaster secret with the PSK for PSK suites), over the transcript so far
/// with the Extended Master Secret.
///
/// # Errors
/// No premaster secret, or the key derivation failed.
pub(super) fn key_exchange_post_work(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    let cp = c.hs.new_cipher.ok_or_else(Error::internal)?;
    let pms = state(c)?.pms.take();
    let pms = if cp.mkey & SSL_PSK != 0 {
        let psk = state(c)?.psk.take().ok_or_else(Error::internal)?;
        let other = if cp.mkey & SSL_kPSK != 0 {
            vec![0u8; psk.len()]
        } else {
            pms.ok_or_else(Error::internal)?.bytes().to_vec()
        };
        let mut w = Writer::new();
        w.vec(2, &other).map_err(|_| Error::internal())?;
        w.vec(2, psk.bytes()).map_err(|_| Error::internal())?;
        Secret::new(w.into_bytes())
    } else {
        pms.ok_or_else(|| {
            Error::alert_lib(
                abi::SSL_AD_INTERNAL_ERROR,
                abi::ERR_R_PASSED_INVALID_ARGUMENT,
            )
        })?
    };
    if c.neg.ems {
        digest_cached_records(c, p, true)?;
    }
    keys::generate_master_secret12(c, p, pms.bytes())?;
    c.neg.session.master_key.clone_from(&c.neg.master_secret);
    c.neg.session.ems = c.neg.ems;
    Ok(())
}

/// The slot of this end's current certificate (`s->cert->key`).
fn current_slot(c: &Connection) -> Option<usize> {
    c.cfg.current_cert.or(if c.cfg.certs.is_empty() {
        None
    } else {
        Some(0)
    })
}

/// `ssl3_check_client_certificate`: a certificate with a usable signature scheme, and in
/// strict mode a chain that suits the server (`tls1_check_chain`).
fn check_client_certificate(c: &mut Connection) -> Result<bool> {
    sigalgs::set_cert_validity(c);
    sigalgs::choose(c, false)?;
    if c.hs.sh.sigalg.is_none() || c.hs.sh.cert.is_none() {
        return Ok(false);
    }
    if c.cfg.cert_flags & abi::SSL_CERT_FLAG_TLS_STRICT != 0
        && !current_slot(c).is_some_and(|i| {
            c.cfg
                .certs
                .get(i)
                .is_some_and(|k| sigalgs::slot_valid(c, k.slot))
        })
    {
        return Ok(false);
    }
    Ok(true)
}

/// `tls_prepare_client_certificate`: the certificate callback (`cert_cb`, at `MoreA`), then
/// the client certificate callback when no usable certificate is configured (at `MoreB`).
/// Without one the client sends an empty Certificate (`cert_req` 2). A post-handshake request
/// stops reading here (`WORK_FINISHED_STOP`).
///
/// # Errors
/// The certificate callback failed (`SSL_R_CALLBACK_FAILED`).
pub(super) fn prepare_client_certificate(
    c: &mut Connection,
    p: &dyn Provider,
    wst: Work,
) -> Result<Work> {
    let done = |c: &Connection| {
        if c.hs.sh.pha == Pha::Requested {
            Work::FinishedStop
        } else {
            Work::FinishedContinue
        }
    };
    let mut wst = wst;
    if wst == Work::MoreA {
        if c.cfg.callbacks.cert {
            match ask_once(c, Request::Cert, 0) {
                None => return Ok(Work::MoreA),
                Some(Answer::Continue | Answer::Allowed(true)) => {}
                Some(Answer::Fail { .. } | Answer::Allowed(false)) => {
                    return Err(Error::alert(
                        abi::SSL_AD_INTERNAL_ERROR,
                        abi::SSL_R_CALLBACK_FAILED,
                    ));
                }
                Some(_) => return Err(Error::internal()),
            }
        }
        if current_slot(c).is_some() && check_client_certificate(c)? {
            return Ok(done(c));
        }
        wst = Work::MoreB;
    }
    if wst == Work::MoreB {
        let mut ok = false;
        if c.cfg.callbacks.client_cert {
            match ask_once(c, Request::ClientCert, 1) {
                None => return Ok(Work::MoreB),
                Some(Answer::Continue | Answer::Allowed(true)) => ok = true,
                Some(_) => {}
            }
        }
        if ok && !(current_slot(c).is_some() && check_client_certificate(c)?) {
            ok = false;
        }
        if !ok {
            c.hs.sh.cert_req = 2;
            c.hs.sh.cert = None;
            c.hs.sh.sigalg = None;
            digest_cached_records(c, p, false)?;
        }
        return Ok(done(c));
    }
    Err(Error::internal())
}

/// `tls_construct_client_certificate`: the TLS 1.3 context (a post-handshake request's), then
/// the chain (none with `cert_req` 2) or raw public key. A TLS 1.3 client that deferred its
/// handshake write keys (early data, middlebox compatibility) installs them now.
///
/// # Errors
/// An extension's error, or the key change failed (`SSL_R_CANNOT_CHANGE_CIPHER`, no alert).
pub(super) fn construct_client_certificate(
    c: &mut Connection,
    p: &dyn Provider,
) -> Result<Construct> {
    let mut w = Writer::new();
    if c.is_tls13() {
        let ctx = c.hs.sh.pha_context.clone().unwrap_or_default();
        w.vec(1, &ctx).map_err(|_| Error::internal())?;
    }
    let cpk = if c.hs.sh.cert_req == 2 {
        None
    } else {
        c.hs.sh.cert.or(current_slot(c))
    };
    let rpk = c.neg.client_cert_type == u8::try_from(abi::TLSEXT_cert_type_rpk).unwrap_or(2);
    let list = if rpk {
        cert::output_rpk(c, p, cpk)?
    } else if c.neg.client_cert_type == 0 {
        cert::output_cert_chain(c, p, cpk)?
    } else {
        return Err(Error::internal());
    };
    let Some(list) = list else {
        return Ok(Construct::Ask);
    };
    w.put(&list);
    if c.is_tls13()
        && !c.cfg.quic
        && finished::is_first_handshake(c)
        && (c.hs.sh.early_data_state != EarlyDataState::None || middlebox(c))
    {
        keys::change_cipher_state13(
            c,
            p,
            abi::SSL3_CC_HANDSHAKE | abi::SSL3_CHANGE_CIPHER_CLIENT_WRITE,
            None,
        )
        .map_err(|_| Error {
            alert: None,
            reason: abi::SSL_R_CANNOT_CHANGE_CIPHER,
            library_reason: false,
            data: None,
            func: None,
            follow_up: None,
            cause: None,
        })?;
    }
    Ok(Construct::Send(w.into_bytes()))
}
