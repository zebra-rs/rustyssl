//! The messages both sides send alike (`statem_lib.c`): Finished, ChangeCipherSpec,
//! KeyUpdate, and the end of a handshake (`tls_finish_handshake`).

use core::ffi::c_int;

use rustyssl_abi as abi;
use subtle::ConstantTimeEq;

use super::keys;
use super::{EarlyDataState, Pha};
use crate::conn::statem::{MsgProcess, Work};
use crate::conn::{Connection, Event};
use crate::crypto::Provider;
use crate::error::{Error, InFunc, Result};
use crate::keysched;

/// `final_finish_mac`: the Finished value for this end's (`server_label`: the server's) side:
/// TLS 1.3's HMAC with the side's Finished key (after a first handshake, a client's
/// post-handshake authentication uses its application secret), or TLS 1.0–1.2's PRF.
///
/// # Errors
/// Missing state, or the provider failed.
pub fn final_finish_mac(c: &Connection, p: &dyn Provider, server_label: bool) -> Result<Vec<u8>> {
    final_finish_mac_inner(c, p, server_label).in_func("tls1_final_finish_mac")
}

/// See [`final_finish_mac`].
fn final_finish_mac_inner(c: &Connection, p: &dyn Provider, server_label: bool) -> Result<Vec<u8>> {
    let cp = c.hs.new_cipher.ok_or_else(Error::internal)?;
    let (hash, prf) = keys::hashes(c.neg.version, cp);
    let transcript = c.hs.transcript.current()?;
    if c.is_tls13() {
        let k = &c.hs.sh.keys;
        let base = if server_label {
            k.server_hs_secret.bytes()
        } else if is_first_handshake(c) {
            k.client_hs_secret.bytes()
        } else {
            k.client_app_secret.bytes()
        };
        return keysched::verify_data_13(p, hash, base, &transcript);
    }
    keysched::verify_data_12(p, prf, &c.neg.master_secret, !server_label, &transcript)
}

/// `tls1_final_finish_mac`'s `ssl3_digest_cached_records(s, 0)`: below TLS 1.3 the messages
/// still buffered (a resumed handshake under `SSL_VERIFY_PEER` never learns there is no
/// CertificateVerify) are hashed now, and the buffer is let go.
///
/// # Errors
/// The provider failed.
fn digest_for_finished(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    if c.is_tls13() {
        return Ok(());
    }
    let r = if c.hs.transcript.alg().is_some() {
        c.hs.transcript.drop_buffer();
        Ok(())
    } else {
        keys::handshake_md(c).and_then(|alg| c.hs.transcript.start_hash(p, alg, false))
    };
    r.in_func("tls1_final_finish_mac")
}

/// `SSL_IS_FIRST_HANDSHAKE`: a Finished hasn't gone both ways yet.
#[must_use]
pub fn is_first_handshake(c: &Connection) -> bool {
    c.hs.finish_md.is_empty() || c.hs.peer_finish_md.is_empty()
}

/// `ssl3_take_mac`:the Finished value the peer must send, before its Finished goes into the
/// transcript.
///
/// # Errors
/// As [`final_finish_mac`].
pub fn take_mac(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    digest_for_finished(c, p)?;
    let md = final_finish_mac(c, p, !c.cfg.server)?;
    c.hs.peer_finish_md = md;
    Ok(())
}

/// `tls_construct_finished`: this end's Finished. A TLS 1.3 client that deferred its
/// handshake write keys (early data, or middlebox compatibility) installs them first, unless
/// it already did for its certificate. Below TLS 1.3 the master secret is logged.
///
/// # Errors
/// Missing state, or the provider failed.
pub fn construct_finished(c: &mut Connection, p: &dyn Provider) -> Result<Vec<u8>> {
    if !c.cfg.server && c.hs.sh.pha != Pha::Requested {
        c.st.cleanuphand = true;
    }
    if c.is_tls13()
        && !c.cfg.server
        && !c.cfg.quic
        && (c.hs.sh.early_data_state != EarlyDataState::None
            || c.cfg.options & abi::SSL_OP_ENABLE_MIDDLEBOX_COMPAT != 0)
        && c.hs.sh.cert_req == 0
    {
        keys::change_cipher_state13(
            c,
            p,
            abi::SSL3_CC_HANDSHAKE | abi::SSL3_CHANGE_CIPHER_CLIENT_WRITE,
            None,
        )?;
    }
    digest_for_finished(c, p)?;
    let md = final_finish_mac(c, p, c.cfg.server)?;
    c.hs.finish_md = md.clone();
    if !c.is_tls13() {
        let ms = c.neg.master_secret.clone();
        keys::log_secret(c, keysched::keylog::CLIENT_RANDOM, &ms);
    }
    if c.cfg.server {
        c.neg.server_finished = md.clone();
    } else {
        c.neg.client_finished = md.clone();
    }
    Ok(md)
}

/// `tls_process_finished`: checks the peer's Finished (in constant time), keeps it for
/// renegotiation and `SSL_get_peer_finished`, and in TLS 1.3 changes keys: a server to the
/// client's application keys, a client to its master secret and application read keys, then
/// the client's checks of the server's first flight (`tls_process_initial_server_flight`).
///
/// # Errors
/// OpenSSL's alert and reason.
pub fn process_finished(c: &mut Connection, p: &dyn Provider, body: &[u8]) -> Result<MsgProcess> {
    let was_first = is_first_handshake(c);
    if c.cfg.server {
        c.rr.allow_plain_alerts = false;
        if c.hs.sh.pha != Pha::Requested {
            c.st.cleanuphand = true;
        }
        if c.is_tls13() {
            save_handshake_digest_for_pha(c);
        }
    }
    if c.is_tls13() && !c.hs_in.is_empty() {
        return Err(Error::alert(
            abi::SSL_AD_UNEXPECTED_MESSAGE,
            abi::SSL_R_NOT_ON_RECORD_BOUNDARY,
        ));
    }
    if !c.is_tls13() && !c.change_cipher_spec {
        return Err(Error::alert(
            abi::SSL_AD_UNEXPECTED_MESSAGE,
            abi::SSL_R_GOT_A_FIN_BEFORE_A_CCS,
        ));
    }
    c.change_cipher_spec = false;
    let expected = c.hs.peer_finish_md.clone();
    if expected.len() != body.len() {
        return Err(Error::decode(abi::SSL_R_BAD_DIGEST_LENGTH));
    }
    if !bool::from(expected.as_slice().ct_eq(body)) {
        return Err(Error::alert(
            abi::SSL_AD_DECRYPT_ERROR,
            abi::SSL_R_DIGEST_CHECK_FAILED,
        ));
    }
    if c.cfg.server {
        c.neg.client_finished = expected;
    } else {
        c.neg.server_finished = expected;
    }
    if c.is_tls13() {
        if c.cfg.server {
            if c.hs.sh.pha != Pha::Requested {
                keys::change_cipher_state13(
                    c,
                    p,
                    abi::SSL3_CC_APPLICATION | abi::SSL3_CHANGE_CIPHER_SERVER_READ,
                    None,
                )?;
            }
        } else {
            keys::generate_master_secret(c, p)?;
            keys::store_server_finished_hash(c)?;
            if !c.cfg.quic {
                keys::change_cipher_state13(
                    c,
                    p,
                    abi::SSL3_CC_APPLICATION | abi::SSL3_CHANGE_CIPHER_CLIENT_READ,
                    None,
                )?;
            }
            crate::conn::client::process_initial_server_flight(c, p)?;
        }
    }
    if was_first && !is_first_handshake(c) {
        c.rr.first_handshake = false;
    }
    Ok(MsgProcess::FinishedReading)
}

/// `tls_process_change_cipher_spec` (TLS 1.0–1.2): a ChangeCipherSpec, after which the peer's
/// records are protected (`ssl3_do_change_cipher_spec`: the key block is made and the read
/// side switched).
///
/// # Errors
/// A body (`SSL_R_BAD_CHANGE_CIPHER_SPEC`), no suite yet (`SSL_R_CCS_RECEIVED_EARLY`), or a key
/// change failure.
pub fn process_change_cipher_spec(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
) -> Result<MsgProcess> {
    if !body.is_empty() {
        return Err(Error::decode(abi::SSL_R_BAD_CHANGE_CIPHER_SPEC));
    }
    if c.hs.new_cipher.is_none() {
        return Err(Error::alert(
            abi::SSL_AD_UNEXPECTED_MESSAGE,
            abi::SSL_R_CCS_RECEIVED_EARLY,
        ));
    }
    c.change_cipher_spec = true;
    do_change_cipher_spec(c, p)?;
    Ok(MsgProcess::ContinueReading)
}

/// `ssl3_do_change_cipher_spec`: makes the key block unless it was made when this end sent its
/// ChangeCipherSpec, and switches the read side to it.
///
/// # Errors
/// No master secret yet (OpenSSL raises `SSL_R_CCS_RECEIVED_EARLY`, then fails the handshake
/// with an internal error), or the key change failed.
pub fn do_change_cipher_spec(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    if c.hs.sh.keys.key_block.is_none() {
        if c.neg.master_secret.is_empty() {
            return Err(Error::internal());
        }
        keys::setup_key_block(c, p)?;
    }
    let which = if c.cfg.server {
        abi::SSL3_CHANGE_CIPHER_SERVER_READ
    } else {
        abi::SSL3_CHANGE_CIPHER_CLIENT_READ
    };
    keys::change_cipher_state12(c, p, which)
}

/// `tls_construct_key_update`: the KeyUpdate's body, the pending request type
/// (`SSL_KEY_UPDATE_REQUESTED` or `_NOT_REQUESTED`); the request is cleared.
#[must_use]
pub fn construct_key_update(c: &mut Connection) -> Vec<u8> {
    let t = u8::try_from(c.hs.sh.key_update.max(0)).unwrap_or(0);
    c.hs.sh.key_update = abi::SSL_KEY_UPDATE_NONE;
    vec![t]
}

/// `tls_process_key_update`: the peer updated its keys (and may ask this end to update too).
///
/// # Errors
/// Not on a record boundary, a malformed or unknown type (`SSL_R_BAD_KEY_UPDATE`), or the key
/// change failed.
pub fn process_key_update(c: &mut Connection, p: &dyn Provider, body: &[u8]) -> Result<MsgProcess> {
    if !c.hs_in.is_empty() {
        return Err(Error::alert(
            abi::SSL_AD_UNEXPECTED_MESSAGE,
            abi::SSL_R_NOT_ON_RECORD_BOUNDARY,
        ));
    }
    let [t] = body else {
        return Err(Error::decode(abi::SSL_R_BAD_KEY_UPDATE));
    };
    let t = c_int::from(*t);
    if t != abi::SSL_KEY_UPDATE_NOT_REQUESTED && t != abi::SSL_KEY_UPDATE_REQUESTED {
        return Err(Error::alert(
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_R_BAD_KEY_UPDATE,
        ));
    }
    if t == abi::SSL_KEY_UPDATE_REQUESTED {
        c.hs.sh.key_update = abi::SSL_KEY_UPDATE_NOT_REQUESTED;
    }
    keys::update_key(c, p, false)?;
    Ok(MsgProcess::FinishedReading)
}

/// `tls13_save_handshake_digest_for_pha`: keeps the transcript at the client's Finished, from
/// which post-handshake authentication continues (once: a later Finished doesn't move it).
pub fn save_handshake_digest_for_pha(c: &mut Connection) {
    if c.hs.sh.pha_transcript.is_none() {
        c.hs.sh.pha_transcript = Some(c.hs.transcript.fork());
    }
}

/// `tls13_restore_handshake_digest_for_pha`.
///
/// # Errors
/// Nothing was saved.
pub fn restore_handshake_digest_for_pha(c: &mut Connection) -> Result<()> {
    let t =
        c.hs.sh
            .pha_transcript
            .as_ref()
            .ok_or_else(Error::internal)?;
    c.hs.transcript = t.fork();
    Ok(())
}

/// `tls_finish_handshake`: the end of a handshake (or a post-handshake exchange): the cleanup
/// after a real handshake (the session cache update, which capi performs on
/// [`Event::UpdateCache`] and [`Event::RemoveSession`]), then `SSL_CB_HANDSHAKE_DONE` (after
/// leaving init), and either back into init (`stop` false) or the end.
///
/// # Errors
/// Never; `Result` for the state machine's signature.
pub fn finish_handshake(
    c: &mut Connection,
    _wst: Work,
    clearbufs: bool,
    stop: bool,
) -> Result<Work> {
    let cleanuphand = c.st.cleanuphand;
    if c.cfg.dtls {
        // `ssl_free_wbio_buffer`, and DTLS's sequence numbers restart for the next handshake.
        c.dtls_finish(cleanuphand, clearbufs);
    }
    if c.is_tls13() && !c.cfg.server && c.hs.sh.pha == Pha::Requested {
        c.hs.sh.pha = Pha::ExtSent;
    }
    if cleanuphand {
        c.renegotiate = false;
        c.hs.sh.new_session = false;
        c.st.cleanuphand = false;
        c.hs.sh.ticket_expected = false;
        c.hs.sh.keys.key_block = None;
        if c.cfg.server {
            if !c.is_tls13() {
                c.notify(Event::UpdateCache { server: true });
            }
        } else if c.is_tls13() {
            c.notify(Event::RemoveSession);
        } else {
            c.notify(Event::UpdateCache { server: false });
        }
    }
    c.st.in_init = false;
    if c.cfg.callbacks.info && (cleanuphand || !c.is_tls13() || is_first_handshake(c)) {
        c.notify(Event::Info {
            where_: abi::SSL_CB_HANDSHAKE_DONE,
            ret: 1,
        });
    }
    if !stop {
        c.st.in_init = true;
        return Ok(Work::FinishedContinue);
    }
    Ok(Work::FinishedStop)
}
