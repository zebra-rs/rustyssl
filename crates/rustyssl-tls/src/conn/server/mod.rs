//! The server's state machine (OpenSSL's `statem_srvr.c` and `extensions_srvr.c`, with the
//! server's parts of `ssl_sess.c` and `t1_lib.c`: session lookup, the session cache hook, and
//! session tickets).
//!
//! The transitions, the work before and after each message, and the messages are here; the
//! ClientHello and the hello messages are in [`hello`], the extension handlers in [`ext`], the
//! certificate messages in [`cert`], TLS 1.2's key exchange in [`kx`], and sessions and
//! tickets in [`ticket`].

mod cert;
mod ext;
mod hello;
mod kx;
mod ticket;

#[cfg(test)]
mod tests;

use core::ffi::c_int;

use rustyssl_abi as abi;

pub(crate) use self::ext::*;
pub(crate) use self::hello::handle_alpn;

use super::common::{self, EarlyDataState, Hrr, Pha, finished};
use super::statem::{Construct, MsgProcess, Work, WriteTran, msgs_type, st};
use super::{Connection, RoleState};
use crate::consts::handshake as ht;
use crate::crypto::{KeyShare, Provider, Secret};
use crate::error::{Error, Result};
use crate::msgs::hello::ClientHello;
use crate::suites::Cipher;
use crate::suites::masks::{SSL_aNULL, SSL_aPSK, SSL_aSRP};

/// `CLIENT_HELLO_MAX_LENGTH` (`statem_srvr.c`).
const CLIENT_HELLO_MAX_LENGTH: usize = 131_396;
/// `CLIENT_KEY_EXCH_MAX_LENGTH`.
const CLIENT_KEY_EXCH_MAX_LENGTH: usize = 2048;
/// `NEXT_PROTO_MAX_LENGTH`.
const NEXT_PROTO_MAX_LENGTH: usize = 514;
/// `END_OF_EARLY_DATA_MAX_LENGTH` (`statem_local.h`).
const END_OF_EARLY_DATA_MAX_LENGTH: usize = 0;
/// `CERTIFICATE_VERIFY_MAX_LENGTH`.
const CERTIFICATE_VERIFY_MAX_LENGTH: usize = 65_539;
/// `CCS_MAX_LENGTH`.
const CCS_MAX_LENGTH: usize = 1;
/// `FINISHED_MAX_LENGTH`.
const FINISHED_MAX_LENGTH: usize = 64;
/// `KEY_UPDATE_MAX_LENGTH`.
const KEY_UPDATE_MAX_LENGTH: usize = 1;

/// The server's handshake state: what OpenSSL keeps for a server in `SSL_CONNECTION` beyond
/// the state both roles share. The per-handshake part is reset by [`setup`]; the counters
/// (`certreqs_sent`, the tickets') live as long as the connection.
#[derive(Default)]
pub struct State {
    /// The ClientHello being processed (`s->clienthello`), from its processing until
    /// post-processing is done.
    pub(crate) hello: Option<ClientHello>,
    /// The raw message body of that ClientHello (for the PSK binders).
    pub(crate) hello_body: Vec<u8>,
    /// How far `tls_early_post_process_client_hello` got: it stops at the client hello
    /// callback and the session lookups, and resumes after the answer without repeating what
    /// it did.
    pub(crate) early_stage: u8,
    /// The client's suites (`s->peer_ciphers`), known ones in its order.
    pub(crate) peer_ciphers: Vec<&'static Cipher>,
    /// The signalling values received with them.
    pub(crate) scsvs: Vec<&'static Cipher>,
    /// The client's cipher list in TLS form (`s->s3.tmp.ciphers_raw`,
    /// `SSL_get0_raw_cipherlist`).
    pub(crate) ciphers_raw: Vec<u8>,
    /// The session ID echoed in a TLS 1.3 ServerHello (`s->tmp_session_id`).
    pub(crate) tmp_session_id: Vec<u8>,
    /// Whether renegotiation_info is sent (`s->s3.send_connection_binding`).
    pub(crate) send_connection_binding: bool,
    /// Whether an OCSP response will be sent (`s->ext.status_expected`).
    pub(crate) status_expected: bool,
    /// The OCSP response the status callback gave (`s->ext.ocsp.resp`).
    pub(crate) ocsp_response: Option<Vec<u8>>,
    /// CertificateRequests sent on this connection (`s->certreqs_sent`).
    pub(crate) certreqs_sent: u32,
    /// TLS 1.3 tickets sent since the handshake or the last post-handshake authentication
    /// (`s->sent_tickets`).
    pub(crate) sent_tickets: usize,
    /// The next ticket's nonce (`s->next_ticket_nonce`).
    pub(crate) next_ticket_nonce: u64,
    /// Tickets `SSL_new_session_ticket` asked for (`s->ext.extra_tickets_expected`).
    pub(crate) extra_tickets_expected: usize,
    /// The PSK identity resumed (`s->ext.tick_identity`).
    pub(crate) tick_identity: u16,
    /// The server's TLS 1.3 key share (or KEM ciphertext) and the shared secret, made when
    /// the client's share is accepted.
    pub(crate) share: Option<(Vec<u8>, Secret)>,
    /// TLS 1.2's ephemeral key (`s->s3.tmp.pkey`), from the ServerKeyExchange until the
    /// ClientKeyExchange.
    pub(crate) kx_key: Option<Box<dyn KeyShare>>,
    /// The group (ECDHE) or the prime (DHE) of that key, as sent.
    pub(crate) kx_group: u16,
    /// The TLS 1.2-style PSK identity received (`s->session->psk_identity`).
    pub(crate) psk_identity: Option<Vec<u8>>,
    /// The PSK the server's PSK callback gave for it.
    pub(crate) psk: Option<Secret>,
    /// Whether a ClientHello that arrived after a handshake must set the handshake up first
    /// (the `tls_setup_handshake` of the `TLS_ST_OK` write transition).
    pub(crate) setup_pending: bool,
    /// The session found by the TLS 1.3 PSK parse, kept while a request is answered.
    pub(crate) psk_found: Option<ticket::Found>,
    /// The OCSP responder IDs and request extensions the client sent
    /// (`SSL_get_tlsext_status_ids`, `_exts`).
    pub(crate) ocsp_ids: Vec<Vec<u8>>,
    /// See `ocsp_ids`.
    pub(crate) ocsp_exts: Vec<u8>,
    /// Whether the TLS 1.3 handshake secret was derived (`s->s3.did_kex`), so that a
    /// construction run again doesn't derive it twice.
    pub(crate) did_kex: bool,
    /// The TLS 1.3 ticket being made (its session, age_add, and nonce), kept while a request
    /// is answered.
    pub(crate) pending_ticket: Option<(crate::conn::Session, u32, [u8; 8])>,
}

impl core::fmt::Debug for State {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("server::State")
            .field("early_stage", &self.early_stage)
            .field("sent_tickets", &self.sent_tickets)
            .finish_non_exhaustive()
    }
}

/// The server's state.
///
/// # Errors
/// The connection isn't set up as a server (an internal error).
pub(crate) fn state(c: &mut Connection) -> Result<&mut State> {
    match &mut c.hs.role {
        RoleState::Server(s) => Ok(s),
        _ => Err(Error::internal()),
    }
}

/// The server's state, to read.
pub(crate) fn state_ref(c: &Connection) -> Option<&State> {
    match &c.hs.role {
        RoleState::Server(s) => Some(s),
        _ => None,
    }
}

/// A flag of the server's state, or its default before set-up.
fn flag(c: &Connection, f: impl Fn(&State) -> bool) -> bool {
    state_ref(c).is_some_and(f)
}

/// Sets up a handshake: the server's part of `tls_setup_handshake` (the common checks are
/// made first, in `common::setup_handshake`): the per-handshake state starts afresh.
pub(crate) fn setup(c: &mut Connection, _p: &dyn Provider) -> Result<()> {
    if !matches!(c.hs.role, RoleState::Server(_)) {
        c.hs.role = RoleState::Server(Box::default());
        // `SSL_new`'s `key_update`: none pending (the shared state's default, 0, would be
        // `SSL_KEY_UPDATE_NOT_REQUESTED`).
        c.hs.sh.key_update = abi::SSL_KEY_UPDATE_NONE;
    }
    // Fork M: a flexible method isn't TLS 1.3 until a version is chosen.
    if c.first_handshake && c.cfg.method_version == 0 {
        c.version_pending = true;
    }
    let s = state(c)?;
    s.hello = None;
    s.hello_body.clear();
    s.early_stage = 0;
    s.peer_ciphers.clear();
    s.scsvs.clear();
    s.ciphers_raw.clear();
    s.tmp_session_id.clear();
    s.status_expected = false;
    s.ocsp_response = None;
    s.tick_identity = 0;
    s.share = None;
    s.kx_key = None;
    s.kx_group = 0;
    s.psk_identity = None;
    s.psk = None;
    s.setup_pending = false;
    s.psk_found = None;
    s.ocsp_ids.clear();
    s.ocsp_exts.clear();
    s.did_kex = false;
    s.pending_ticket = None;
    Ok(())
}

/// `received_client_cert`: the client sent a certificate (or a raw public key).
pub(crate) fn received_client_cert(c: &Connection) -> bool {
    !c.neg.session.peer_chain.is_empty() || c.neg.peer_rpk.is_some()
}

/// `SSL_NO_EOED`: QUIC has no EndOfEarlyData.
fn no_eoed(c: &Connection) -> bool {
    c.cfg.quic
}

/// The unexpected-message failure of a read transition.
fn unexpected() -> Error {
    Error::alert(
        abi::SSL3_AD_UNEXPECTED_MESSAGE,
        abi::SSL_R_UNEXPECTED_MESSAGE,
    )
}

/// `ossl_statem_server13_read_transition`.
fn read_transition13(c: &Connection, mt: u8) -> Option<u32> {
    let to_cert_or_finished = |c: &Connection| {
        if c.hs.sh.cert_request {
            (mt == ht::CERTIFICATE).then_some(abi::TLS_ST_SR_CERT)
        } else {
            (mt == ht::FINISHED).then_some(abi::TLS_ST_SR_FINISHED)
        }
    };
    match c.st.hand_state {
        abi::TLS_ST_EARLY_DATA => {
            if c.hs.sh.hrr == Hrr::Pending {
                return (mt == ht::CLIENT_HELLO).then_some(abi::TLS_ST_SR_CLNT_HELLO);
            }
            if c.neg.early_data_status == abi::SSL_EARLY_DATA_ACCEPTED && !no_eoed(c) {
                return (mt == ht::END_OF_EARLY_DATA).then_some(abi::TLS_ST_SR_END_OF_EARLY_DATA);
            }
            to_cert_or_finished(c)
        }
        abi::TLS_ST_SR_END_OF_EARLY_DATA | abi::TLS_ST_SW_FINISHED => to_cert_or_finished(c),
        abi::TLS_ST_SR_COMP_CERT | abi::TLS_ST_SR_CERT => {
            if received_client_cert(c) {
                (mt == ht::CERTIFICATE_VERIFY).then_some(abi::TLS_ST_SR_CERT_VRFY)
            } else {
                (mt == ht::FINISHED).then_some(abi::TLS_ST_SR_FINISHED)
            }
        }
        abi::TLS_ST_SR_CERT_VRFY => (mt == ht::FINISHED).then_some(abi::TLS_ST_SR_FINISHED),
        abi::TLS_ST_OK => {
            if c.hs.sh.early_data_state == EarlyDataState::Reading {
                return None;
            }
            if c.hs.sh.pha == Pha::Requested && mt == ht::CERTIFICATE {
                return Some(abi::TLS_ST_SR_CERT);
            }
            (mt == ht::KEY_UPDATE && !c.cfg.quic).then_some(abi::TLS_ST_SR_KEY_UPDATE)
        }
        _ => None,
    }
}

/// `ossl_statem_server_read_transition` below TLS 1.3.
fn read_transition12(c: &Connection, mt: u8) -> Option<u32> {
    match c.st.hand_state {
        abi::TLS_ST_BEFORE | abi::TLS_ST_OK => {
            (mt == ht::CLIENT_HELLO).then_some(abi::TLS_ST_SR_CLNT_HELLO)
        }
        abi::TLS_ST_SW_SRVR_DONE => {
            // SSLv3's missing-certificate case is compiled out: with a request outstanding the
            // client must send a Certificate, even an empty one.
            if mt == ht::CLIENT_KEY_EXCHANGE {
                (!c.hs.sh.cert_request).then_some(abi::TLS_ST_SR_KEY_EXCH)
            } else {
                (c.hs.sh.cert_request && mt == ht::CERTIFICATE).then_some(abi::TLS_ST_SR_CERT)
            }
        }
        abi::TLS_ST_SR_CERT => (mt == ht::CLIENT_KEY_EXCHANGE).then_some(abi::TLS_ST_SR_KEY_EXCH),
        abi::TLS_ST_SR_KEY_EXCH => {
            if !received_client_cert(c) || c.st.no_cert_verify {
                c.st.ccs.then_some(abi::TLS_ST_SR_CHANGE)
            } else {
                (mt == ht::CERTIFICATE_VERIFY).then_some(abi::TLS_ST_SR_CERT_VRFY)
            }
        }
        abi::TLS_ST_SR_CERT_VRFY => c.st.ccs.then_some(abi::TLS_ST_SR_CHANGE),
        abi::TLS_ST_SR_CHANGE => {
            if c.hs.sh.npn_seen {
                (mt == ht::NEXT_PROTO).then_some(abi::TLS_ST_SR_NEXT_PROTO)
            } else {
                (mt == ht::FINISHED).then_some(abi::TLS_ST_SR_FINISHED)
            }
        }
        abi::TLS_ST_SR_NEXT_PROTO => (mt == ht::FINISHED).then_some(abi::TLS_ST_SR_FINISHED),
        abi::TLS_ST_SW_FINISHED => c.st.ccs.then_some(abi::TLS_ST_SR_CHANGE),
        _ => None,
    }
}

/// The read transition for message type `mt` (`ossl_statem_server_read_transition`); an
/// unexpected message is `SSL_R_UNEXPECTED_MESSAGE` with unexpected-message. A ClientHello
/// after a handshake (renegotiation) has the handshake set up first, when it is processed.
pub(crate) fn read_transition(c: &mut Connection, mt: u8) -> Result<()> {
    let next = if c.is_tls13() {
        read_transition13(c, mt)
    } else {
        read_transition12(c, mt)
    };
    let Some(next) = next else {
        return Err(unexpected());
    };
    if c.st.hand_state == st(abi::TLS_ST_OK) && next == abi::TLS_ST_SR_CLNT_HELLO {
        state(c)?.setup_pending = true;
    }
    c.st.hand_state = next;
    Ok(())
}

/// The largest message allowed in the current state (`ossl_statem_server_max_message_size`).
pub(crate) fn max_message_size(c: &Connection) -> usize {
    match c.st.hand_state {
        abi::TLS_ST_SR_CLNT_HELLO => CLIENT_HELLO_MAX_LENGTH,
        abi::TLS_ST_SR_END_OF_EARLY_DATA => END_OF_EARLY_DATA_MAX_LENGTH,
        abi::TLS_ST_SR_COMP_CERT | abi::TLS_ST_SR_CERT => c.cfg.max_cert_list,
        abi::TLS_ST_SR_KEY_EXCH => CLIENT_KEY_EXCH_MAX_LENGTH,
        abi::TLS_ST_SR_CERT_VRFY => CERTIFICATE_VERIFY_MAX_LENGTH,
        abi::TLS_ST_SR_NEXT_PROTO => NEXT_PROTO_MAX_LENGTH,
        abi::TLS_ST_SR_CHANGE => CCS_MAX_LENGTH,
        abi::TLS_ST_SR_FINISHED => FINISHED_MAX_LENGTH,
        abi::TLS_ST_SR_KEY_UPDATE => KEY_UPDATE_MAX_LENGTH,
        _ => 0,
    }
}

/// Processes a message's body (`ossl_statem_server_process_message`).
///
/// # Errors
/// The message's processing failed (OpenSSL's alert and reason).
pub(crate) fn process_message(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
) -> Result<MsgProcess> {
    match c.st.hand_state {
        abi::TLS_ST_SR_CLNT_HELLO => hello::process_client_hello(c, p, body),
        abi::TLS_ST_SR_END_OF_EARLY_DATA => process_end_of_early_data(c, p, body),
        abi::TLS_ST_SR_CERT => cert::process_client_certificate(c, p, body),
        abi::TLS_ST_SR_KEY_EXCH => kx::process_client_key_exchange(c, p, body),
        abi::TLS_ST_SR_CERT_VRFY => common::cert::process_cert_verify(c, p, body),
        abi::TLS_ST_SR_NEXT_PROTO => process_next_proto(c, body),
        abi::TLS_ST_SR_CHANGE => {
            // `ssl3_do_change_cipher_spec`: a new session takes the suite now.
            if c.neg.session.cipher_id == 0
                && let Some(nc) = c.hs.new_cipher
            {
                c.neg.session.cipher_id = nc.id;
            }
            finished::process_change_cipher_spec(c, p, body)
        }
        abi::TLS_ST_SR_FINISHED => finished::process_finished(c, p, body),
        abi::TLS_ST_SR_KEY_UPDATE => finished::process_key_update(c, p, body),
        _ => Err(Error::internal()),
    }
}

/// The work after processing a message (`ossl_statem_server_post_process_message`).
///
/// # Errors
/// The work failed.
pub(crate) fn post_process_message(
    c: &mut Connection,
    p: &dyn Provider,
    wst: Work,
) -> Result<Work> {
    match c.st.hand_state {
        abi::TLS_ST_SR_CLNT_HELLO => hello::post_process_client_hello(c, p, wst),
        abi::TLS_ST_SR_KEY_EXCH => kx::post_process_client_key_exchange(c, p, wst),
        _ => Err(Error::internal()),
    }
}

/// `send_certificate_request`: whether to ask for the client's certificate.
pub(crate) fn send_certificate_request(c: &Connection) -> bool {
    let vm = c.cfg.verify_mode;
    let Some(nc) = c.hs.new_cipher else {
        return false;
    };
    let once = flag(c, |s| s.certreqs_sent >= 1);
    vm & abi::SSL_VERIFY_PEER != 0
        && (!c.is_tls13()
            || vm & abi::SSL_VERIFY_POST_HANDSHAKE == 0
            || c.hs.sh.pha == Pha::RequestPending)
        && (!once || vm & abi::SSL_VERIFY_CLIENT_ONCE == 0)
        && (nc.auth & SSL_aNULL == 0 || vm & abi::SSL_VERIFY_FAIL_IF_NO_PEER_CERT != 0)
        && nc.auth & SSL_aSRP == 0
        && nc.auth & SSL_aPSK == 0
}

/// `do_compressed_cert`: never, as the default build has no certificate compression.
fn do_compressed_cert(_c: &Connection) -> bool {
    false
}

/// `ossl_statem_server13_write_transition`.
fn write_transition13(c: &mut Connection) -> Result<WriteTran> {
    let next = match c.st.hand_state {
        abi::TLS_ST_OK => {
            if c.hs.sh.key_update != abi::SSL_KEY_UPDATE_NONE {
                abi::TLS_ST_SW_KEY_UPDATE
            } else if c.hs.sh.pha == Pha::RequestPending {
                abi::TLS_ST_SW_CERT_REQ
            } else if flag(c, |s| s.extra_tickets_expected > 0) {
                abi::TLS_ST_SW_SESSION_TICKET
            } else {
                return Ok(WriteTran::Finished);
            }
        }
        abi::TLS_ST_SR_CLNT_HELLO => abi::TLS_ST_SW_SRVR_HELLO,
        abi::TLS_ST_SW_SRVR_HELLO => {
            if c.cfg.options & abi::SSL_OP_ENABLE_MIDDLEBOX_COMPAT != 0
                && c.hs.sh.hrr != Hrr::Complete
            {
                abi::TLS_ST_SW_CHANGE
            } else if c.hs.sh.hrr == Hrr::Pending {
                abi::TLS_ST_EARLY_DATA
            } else {
                abi::TLS_ST_SW_ENCRYPTED_EXTENSIONS
            }
        }
        abi::TLS_ST_SW_CHANGE => {
            if c.hs.sh.hrr == Hrr::Pending {
                abi::TLS_ST_EARLY_DATA
            } else {
                abi::TLS_ST_SW_ENCRYPTED_EXTENSIONS
            }
        }
        abi::TLS_ST_SW_ENCRYPTED_EXTENSIONS => {
            if c.neg.reused {
                abi::TLS_ST_SW_FINISHED
            } else if send_certificate_request(c) {
                abi::TLS_ST_SW_CERT_REQ
            } else if do_compressed_cert(c) {
                abi::TLS_ST_SW_COMP_CERT
            } else {
                abi::TLS_ST_SW_CERT
            }
        }
        abi::TLS_ST_SW_CERT_REQ => {
            if c.hs.sh.pha == Pha::RequestPending {
                c.hs.sh.pha = Pha::Requested;
                abi::TLS_ST_OK
            } else if do_compressed_cert(c) {
                abi::TLS_ST_SW_COMP_CERT
            } else {
                abi::TLS_ST_SW_CERT
            }
        }
        abi::TLS_ST_SW_COMP_CERT | abi::TLS_ST_SW_CERT => abi::TLS_ST_SW_CERT_VRFY,
        abi::TLS_ST_SW_CERT_VRFY => abi::TLS_ST_SW_FINISHED,
        abi::TLS_ST_SW_FINISHED => abi::TLS_ST_EARLY_DATA,
        abi::TLS_ST_EARLY_DATA => return Ok(WriteTran::Finished),
        abi::TLS_ST_SR_FINISHED => {
            if c.hs.sh.pha == Pha::Requested {
                c.hs.sh.pha = Pha::ExtReceived;
            } else if !c.hs.sh.ticket_expected {
                c.st.hand_state = abi::TLS_ST_OK;
                return Ok(WriteTran::Continue);
            }
            let (num, sent) = (c.cfg.num_tickets, flag_count(c, |s| s.sent_tickets));
            if num > sent {
                abi::TLS_ST_SW_SESSION_TICKET
            } else {
                abi::TLS_ST_OK
            }
        }
        abi::TLS_ST_SR_KEY_UPDATE | abi::TLS_ST_SW_KEY_UPDATE => abi::TLS_ST_OK,
        abi::TLS_ST_SW_SESSION_TICKET => {
            let extra = flag_count(c, |s| s.extra_tickets_expected);
            if !finished::is_first_handshake(c) && extra > 0 {
                return Ok(WriteTran::Continue);
            }
            if c.neg.reused || c.cfg.num_tickets <= flag_count(c, |s| s.sent_tickets) {
                c.st.hand_state = abi::TLS_ST_OK;
            }
            return Ok(WriteTran::Continue);
        }
        _ => return Err(Error::internal()),
    };
    c.st.hand_state = next;
    Ok(WriteTran::Continue)
}

/// A count of the server's state, or 0 before set-up.
fn flag_count(c: &Connection, f: impl Fn(&State) -> usize) -> usize {
    state_ref(c).map_or(0, f)
}

/// `send_server_key_exchange`: whether a TLS 1.2 ServerKeyExchange is sent.
fn send_server_key_exchange(c: &Connection) -> bool {
    use crate::suites::masks::{
        SSL_PSK, SSL_kDHE, SSL_kDHEPSK, SSL_kECDHE, SSL_kECDHEPSK, SSL_kPSK, SSL_kRSAPSK, SSL_kSRP,
    };
    let Some(nc) = c.hs.new_cipher else {
        return false;
    };
    let k = nc.mkey;
    k & (SSL_kDHE | SSL_kECDHE) != 0
        || (k & (SSL_kPSK | SSL_kRSAPSK) != 0 && c.cfg.psk_identity_hint.is_some())
        || k & (SSL_PSK & (SSL_kDHEPSK | SSL_kECDHEPSK)) != 0
        || k & SSL_kSRP != 0
}

/// `ossl_statem_server_write_transition` below TLS 1.3.
fn write_transition12(c: &mut Connection) -> Result<WriteTran> {
    let hs = c.st.hand_state;
    let next = match hs {
        abi::TLS_ST_OK => {
            if c.st.request_state == abi::TLS_ST_SW_HELLO_REQ {
                c.st.request_state = abi::TLS_ST_BEFORE;
                abi::TLS_ST_SW_HELLO_REQ
            } else {
                // An incoming ClientHello: the handshake is set up when it is processed.
                state(c)?.setup_pending = true;
                return Ok(WriteTran::Finished);
            }
        }
        abi::TLS_ST_BEFORE => return Ok(WriteTran::Finished),
        abi::TLS_ST_SW_HELLO_REQ => abi::TLS_ST_OK,
        abi::TLS_ST_SR_CLNT_HELLO => {
            if !c.renegotiate && !finished::is_first_handshake(c) {
                // The renegotiation was refused.
                abi::TLS_ST_OK
            } else {
                abi::TLS_ST_SW_SRVR_HELLO
            }
        }
        abi::TLS_ST_SW_SRVR_HELLO => {
            if c.neg.reused {
                if c.hs.sh.ticket_expected {
                    abi::TLS_ST_SW_SESSION_TICKET
                } else {
                    abi::TLS_ST_SW_CHANGE
                }
            } else {
                let auth = c.hs.new_cipher.map_or(0, |x| x.auth);
                if auth & (SSL_aNULL | SSL_aSRP | SSL_aPSK) == 0 {
                    abi::TLS_ST_SW_CERT
                } else if send_server_key_exchange(c) {
                    abi::TLS_ST_SW_KEY_EXCH
                } else if send_certificate_request(c) {
                    abi::TLS_ST_SW_CERT_REQ
                } else {
                    abi::TLS_ST_SW_SRVR_DONE
                }
            }
        }
        abi::TLS_ST_SW_CERT | abi::TLS_ST_SW_CERT_STATUS | abi::TLS_ST_SW_KEY_EXCH => {
            if hs == abi::TLS_ST_SW_CERT && flag(c, |s| s.status_expected) {
                abi::TLS_ST_SW_CERT_STATUS
            } else if hs != abi::TLS_ST_SW_KEY_EXCH && send_server_key_exchange(c) {
                abi::TLS_ST_SW_KEY_EXCH
            } else if send_certificate_request(c) {
                abi::TLS_ST_SW_CERT_REQ
            } else {
                abi::TLS_ST_SW_SRVR_DONE
            }
        }
        abi::TLS_ST_SW_CERT_REQ => abi::TLS_ST_SW_SRVR_DONE,
        abi::TLS_ST_SW_SRVR_DONE => return Ok(WriteTran::Finished),
        abi::TLS_ST_SR_FINISHED => {
            if c.neg.reused {
                abi::TLS_ST_OK
            } else if c.hs.sh.ticket_expected {
                abi::TLS_ST_SW_SESSION_TICKET
            } else {
                abi::TLS_ST_SW_CHANGE
            }
        }
        abi::TLS_ST_SW_SESSION_TICKET => abi::TLS_ST_SW_CHANGE,
        abi::TLS_ST_SW_CHANGE => abi::TLS_ST_SW_FINISHED,
        abi::TLS_ST_SW_FINISHED => {
            if c.neg.reused {
                return Ok(WriteTran::Finished);
            }
            abi::TLS_ST_OK
        }
        _ => return Err(Error::internal()),
    };
    c.st.hand_state = next;
    Ok(WriteTran::Continue)
}

/// The write transition (`ossl_statem_server_write_transition`).
///
/// # Errors
/// No transition from the current state (an internal error).
pub(crate) fn write_transition(c: &mut Connection) -> Result<WriteTran> {
    if c.is_tls13() {
        write_transition13(c)
    } else {
        write_transition12(c)
    }
}

/// The work before constructing a message (`ossl_statem_server_pre_work`).
///
/// # Errors
/// The work failed.
pub(crate) fn pre_work(c: &mut Connection, p: &dyn Provider, wst: Work) -> Result<Work> {
    match c.st.hand_state {
        abi::TLS_ST_SW_HELLO_REQ => {
            c.shutdown = 0;
        }
        abi::TLS_ST_SW_SESSION_TICKET => {
            if c.is_tls13()
                && flag_count(c, |s| {
                    s.sent_tickets.saturating_add(s.extra_tickets_expected)
                }) == 0
            {
                // The end of the handshake, going straight on to the tickets.
                return finished::finish_handshake(c, wst, false, false);
            }
        }
        abi::TLS_ST_SW_CHANGE => {
            if c.is_tls13() {
                return Ok(Work::FinishedContinue);
            }
            let nc = c.hs.new_cipher.ok_or_else(Error::internal)?;
            let s = &mut c.neg.session;
            if s.cipher_id == 0 {
                s.cipher_id = nc.id;
            } else if s.cipher_id != nc.id {
                return Err(Error::internal());
            }
            common::keys::setup_key_block(c, p)?;
        }
        abi::TLS_ST_EARLY_DATA => {
            if c.hs.sh.early_data_state != EarlyDataState::Accepting
                && c.hs.sh.flags & abi::TLS1_FLAGS_STATELESS == 0
            {
                return Ok(Work::FinishedContinue);
            }
            return finished::finish_handshake(c, wst, true, true);
        }
        abi::TLS_ST_OK => return finished::finish_handshake(c, wst, true, true),
        _ => {}
    }
    Ok(Work::FinishedContinue)
}

/// The work after sending a message (`ossl_statem_server_post_work`): the flush points wait
/// for the output to be taken, and the key changes.
///
/// # Errors
/// A key change failed.
pub(crate) fn post_work(c: &mut Connection, p: &dyn Provider, _wst: Work) -> Result<Work> {
    let tls13 = c.is_tls13();
    let compat = c.cfg.options & abi::SSL_OP_ENABLE_MIDDLEBOX_COMPAT != 0;
    match c.st.hand_state {
        abi::TLS_ST_SW_HELLO_REQ => {
            if !c.flushed() {
                return Ok(Work::MoreA);
            }
            // `ssl3_init_finished_mac`: the HelloRequest isn't part of any transcript.
            c.hs.transcript = crate::keysched::Transcript::new();
        }
        abi::TLS_ST_SW_SRVR_HELLO => {
            if tls13 && c.hs.sh.hrr == Hrr::Pending {
                if !compat && !c.flushed() {
                    return Ok(Work::MoreA);
                }
            } else if tls13 && !(compat && c.hs.sh.hrr != Hrr::Complete) {
                return change_after_server_hello(c, p);
            } else if !tls13 {
                // TLS 1.2's write keys change at the ChangeCipherSpec.
            }
        }
        abi::TLS_ST_SW_CHANGE => {
            if c.hs.sh.hrr == Hrr::Pending {
                if !c.flushed() {
                    return Ok(Work::MoreA);
                }
            } else if tls13 {
                return change_after_server_hello(c, p);
            } else {
                common::keys::change_cipher_state12(c, p, abi::SSL3_CHANGE_CIPHER_SERVER_WRITE)?;
            }
        }
        abi::TLS_ST_SW_SRVR_DONE => {
            if !c.flushed() {
                return Ok(Work::MoreA);
            }
        }
        abi::TLS_ST_SW_FINISHED => {
            if !c.flushed() {
                return Ok(Work::MoreA);
            }
            if tls13 {
                common::keys::generate_master_secret(c, p)?;
                common::keys::store_server_finished_hash(c)?;
                common::keys::change_cipher_state13(
                    c,
                    p,
                    abi::SSL3_CC_APPLICATION | abi::SSL3_CHANGE_CIPHER_SERVER_WRITE,
                    None,
                )?;
            }
        }
        abi::TLS_ST_SW_CERT_REQ => {
            if c.hs.sh.pha == Pha::RequestPending && !c.flushed() {
                return Ok(Work::MoreA);
            }
        }
        abi::TLS_ST_SW_KEY_UPDATE => {
            if !c.flushed() {
                return Ok(Work::MoreA);
            }
            common::keys::update_key(c, p, true)?;
        }
        abi::TLS_ST_SW_SESSION_TICKET if tls13 && !c.flushed() => return Ok(Work::MoreA),
        _ => {}
    }
    Ok(Work::FinishedContinue)
}

/// TLS 1.3's key change after the ServerHello (or the middlebox ChangeCipherSpec): the
/// server's handshake write keys, its handshake read keys unless early data was accepted
/// (they wait for the EndOfEarlyData), and plaintext alerts tolerated for now.
fn change_after_server_hello(c: &mut Connection, p: &dyn Provider) -> Result<Work> {
    common::keys::store_handshake_traffic_hash(c)?;
    common::keys::change_cipher_state13(
        c,
        p,
        abi::SSL3_CC_HANDSHAKE | abi::SSL3_CHANGE_CIPHER_SERVER_WRITE,
        None,
    )?;
    if c.neg.early_data_status == abi::SSL_EARLY_DATA_ACCEPTED {
        // Installed at the EndOfEarlyData, after the master secret.
        common::keys::keep_client_handshake_secret(c, p)?;
    } else {
        common::keys::change_cipher_state13(
            c,
            p,
            abi::SSL3_CC_HANDSHAKE | abi::SSL3_CHANGE_CIPHER_SERVER_READ,
            None,
        )?;
    }
    c.rr.allow_plain_alerts = true;
    Ok(Work::FinishedContinue)
}

/// Constructs the message for the current state (`ossl_statem_server_construct_message` and
/// the construction functions): its type and body.
///
/// # Errors
/// The construction failed (OpenSSL's alert and reason), or no message belongs to the state.
pub(crate) fn construct_message(c: &mut Connection, p: &dyn Provider) -> Result<(u8, Construct)> {
    let send = |b: Vec<u8>| Construct::Send(b);
    Ok(match c.st.hand_state {
        abi::TLS_ST_SW_CHANGE => (
            msgs_type(abi::SSL3_MT_CHANGE_CIPHER_SPEC),
            Construct::Send(Vec::new()),
        ),
        abi::TLS_ST_SW_HELLO_REQ => (ht::HELLO_REQUEST, Construct::Send(Vec::new())),
        abi::TLS_ST_SW_SRVR_HELLO => (ht::SERVER_HELLO, hello::construct_server_hello(c, p)?),
        abi::TLS_ST_SW_CERT => (ht::CERTIFICATE, cert::construct_server_certificate(c, p)?),
        abi::TLS_ST_SW_CERT_VRFY => (
            ht::CERTIFICATE_VERIFY,
            send(common::cert::construct_cert_verify(c, p)?),
        ),
        abi::TLS_ST_SW_KEY_EXCH => (
            ht::SERVER_KEY_EXCHANGE,
            kx::construct_server_key_exchange(c, p)?,
        ),
        abi::TLS_ST_SW_CERT_REQ => (
            ht::CERTIFICATE_REQUEST,
            cert::construct_certificate_request(c, p)?,
        ),
        abi::TLS_ST_SW_SRVR_DONE => (ht::SERVER_HELLO_DONE, construct_server_done(c, p)?),
        abi::TLS_ST_SW_SESSION_TICKET => (
            ht::NEW_SESSION_TICKET,
            ticket::construct_new_session_ticket(c, p)?,
        ),
        abi::TLS_ST_SW_CERT_STATUS => (ht::CERTIFICATE_STATUS, construct_cert_status(c)?),
        abi::TLS_ST_SW_FINISHED => (ht::FINISHED, send(finished::construct_finished(c, p)?)),
        abi::TLS_ST_EARLY_DATA => (0, Construct::Dummy),
        abi::TLS_ST_SW_ENCRYPTED_EXTENSIONS => (
            ht::ENCRYPTED_EXTENSIONS,
            hello::construct_encrypted_extensions(c, p)?,
        ),
        abi::TLS_ST_SW_KEY_UPDATE => (ht::KEY_UPDATE, send(finished::construct_key_update(c))),
        _ => {
            return Err(Error::alert(
                abi::SSL_AD_INTERNAL_ERROR,
                abi::SSL_R_BAD_HANDSHAKE_STATE,
            ));
        }
    })
}

/// `ssl3_digest_cached_records`: the transcript is hashed from now on with the suite's hash;
/// the buffer of messages is kept (`keep`) for a client's TLS 1.2 CertificateVerify, or
/// dropped.
///
/// # Errors
/// No suite, or the provider has no such hash.
pub(crate) fn digest_cached_records(
    c: &mut Connection,
    p: &dyn Provider,
    keep: bool,
) -> Result<()> {
    if c.hs.transcript.alg().is_some() {
        if !keep {
            c.hs.transcript.drop_buffer();
        }
        return Ok(());
    }
    let alg = common::keys::handshake_md(c)?;
    c.hs.transcript.start_hash(p, alg, keep)
}

/// `tls_construct_server_done`: empty; without a certificate request the messages needn't
/// be kept any more.
fn construct_server_done(c: &mut Connection, p: &dyn Provider) -> Result<Construct> {
    if !c.hs.sh.cert_request {
        digest_cached_records(c, p, false)?;
    }
    Ok(Construct::Send(Vec::new()))
}

/// `tls_construct_cert_status_body`: the status type and the OCSP response.
///
/// # Errors
/// The response is too long.
pub(crate) fn cert_status_body(c: &Connection) -> Result<Vec<u8>> {
    let resp = state_ref(c)
        .and_then(|s| s.ocsp_response.clone())
        .unwrap_or_default();
    let mut w = crate::codec::Writer::new();
    w.u8(u8::try_from(c.hs.sh.status_type).map_err(|_| Error::internal())?);
    w.vec(3, &resp).map_err(|_| Error::internal())?;
    Ok(w.into_bytes())
}

/// `tls_construct_cert_status`: TLS 1.2's CertificateStatus.
fn construct_cert_status(c: &Connection) -> Result<Construct> {
    Ok(Construct::Send(cert_status_body(c)?))
}

/// `tls_process_next_proto`: the client's NextProtocol, its protocol and padding filling
/// the body (`SSL_R_LENGTH_MISMATCH`, decode-error).
fn process_next_proto(c: &mut Connection, body: &[u8]) -> Result<MsgProcess> {
    let mm = Error::decode(abi::SSL_R_LENGTH_MISMATCH);
    let mut rd = crate::codec::Reader::new(body);
    let proto = rd.vec8().map_err(|_| mm)?;
    rd.vec8().map_err(|_| mm)?;
    if !rd.is_empty() {
        return Err(mm);
    }
    c.neg.npn = Some(proto.rest().to_vec());
    Ok(MsgProcess::ContinueReading)
}

/// `tls_process_end_of_early_data`: empty, while early data is being read, ending on a record
/// boundary; then the client's handshake keys are read.
fn process_end_of_early_data(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
) -> Result<MsgProcess> {
    if !body.is_empty() {
        return Err(Error::decode(abi::SSL_R_LENGTH_MISMATCH));
    }
    if !matches!(
        c.hs.sh.early_data_state,
        EarlyDataState::Reading | EarlyDataState::ReadRetry
    ) {
        return Err(Error::internal());
    }
    if !c.hs_in.is_empty() {
        return Err(Error::alert(
            abi::SSL_AD_UNEXPECTED_MESSAGE,
            abi::SSL_R_NOT_ON_RECORD_BOUNDARY,
        ));
    }
    c.hs.sh.early_data_state = EarlyDataState::FinishedReading;
    common::keys::change_cipher_state13(
        c,
        p,
        abi::SSL3_CC_HANDSHAKE | abi::SSL3_CHANGE_CIPHER_SERVER_READ,
        None,
    )?;
    Ok(MsgProcess::ContinueReading)
}

/// A `c_int` constant as an octet.
pub(crate) fn octet(v: c_int) -> u8 {
    msgs_type(v)
}
