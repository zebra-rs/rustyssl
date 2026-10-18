//! The ClientHello and the server's hello messages (`tls_process_client_hello`,
//! `tls_early_post_process_client_hello`, `tls_post_process_client_hello`,
//! `tls_construct_server_hello`, `tls_construct_encrypted_extensions`), with the ALPN and
//! status request callbacks.
//!
//! Post-processing yields at every callback (the client hello callback, the session lookups,
//! the servername, ALPN, and early data callbacks, the certificate callback, and the status
//! callback); each stage it completes is recorded in [`super::State::early_stage`] so that
//! running it again after an answer carries on where it stopped.

use rustyssl_abi as abi;

use super::{digest_cached_records, state, state_ref, ticket};
use crate::codec::Reader;
use crate::conn::common::ext::{self, Step};
use crate::conn::common::{
    self, Hrr, STATUSTYPE_NOTHING, ask_once, ciphers, finished, sigalgs, version,
};
use crate::conn::statem::{Construct, MsgProcess, Work, msgs_type};
use crate::conn::{Answer, Connection, Request};
use crate::consts::context as cx;
use crate::consts::ext as t;
use crate::consts::handshake as ht;
use crate::consts::{HRR_RANDOM, RANDOM_LEN, version as v};
use crate::crypto::Provider;
use crate::error::{Error, InFunc, Result};
use crate::keysched::{Transcript, hash_of};
use crate::msgs::hello::{ClientHello, ServerHello};

/// The stages of ClientHello post-processing ([`State::early_stage`]).
mod stage {
    /// The client hello callback.
    pub const CALLBACK: u8 = 0;
    /// The version, the suites, and (TLS 1.3) the suite choice.
    pub const VERSION: u8 = 1;
    /// The session lookup.
    pub const SESSION: u8 = 2;
    /// The checks on the resumption and the compression methods.
    pub const CHECKS: u8 = 3;
    /// The extensions.
    pub const EXTENSIONS: u8 = 4;
    /// The server's random and signature algorithms.
    pub const RANDOM: u8 = 5;
    /// The session secret callback (EAP-FAST).
    pub const SECRET: u8 = 6;
    /// The certificate callback.
    pub const CERT_CB: u8 = 7;
    /// TLS 1.2's suite choice, and the signature algorithm.
    pub const CHOOSE: u8 = 8;
    /// The status request callback.
    pub const STATUS: u8 = 9;
    /// TLS 1.2's ALPN callback.
    pub const ALPN: u8 = 10;
    /// Done.
    pub const DONE: u8 = 11;
}

/// `RENEG_OPTIONS_OK`: the options allow a client to renegotiate.
fn reneg_options_ok(options: u64) -> bool {
    options & abi::SSL_OP_NO_RENEGOTIATION == 0
        && options & abi::SSL_OP_ALLOW_CLIENT_RENEGOTIATION != 0
}

impl Connection {
    /// The ClientHello being processed (for the client hello callback's
    /// `SSL_client_hello_get0_*`), from when it is read until its processing is done.
    #[must_use]
    pub fn client_hello(&self) -> Option<&ClientHello> {
        state_ref(self).and_then(|s| s.hello.as_ref())
    }
}

/// `tls_process_client_hello`: a renegotiation the options or the peer don't allow is refused
/// with a warning no_renegotiation alert (`MSG_PROCESS_FINISHED_READING`); otherwise the
/// message is decoded and its extensions collected for post-processing.
///
/// # Errors
/// The message doesn't decode, an SSLv2-format hello isn't the first message, or the
/// extensions are malformed (OpenSSL's alerts and reasons).
pub(crate) fn process_client_hello(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
) -> Result<MsgProcess> {
    if state(c)?.setup_pending {
        // The `TLS_ST_OK` write transition's `tls_setup_handshake`, which starts a fresh
        // transcript: this ClientHello is its first message.
        common::setup_handshake(c, p)?;
        if !c.sslv2_record {
            let msg = crate::msgs::frame(ht::CLIENT_HELLO, body)?;
            c.hs.transcript.add(&msg);
        }
    }
    let first = finished::is_first_handshake(c);
    if !c.renegotiate && !first {
        if c.is_tls13() {
            return Err(Error::internal());
        }
        let o = c.cfg.options;
        let binding = state(c)?.send_connection_binding;
        if !reneg_options_ok(o)
            || (!binding && o & abi::SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION == 0)
        {
            c.send_alert(
                p,
                msgs_type(abi::SSL3_AL_WARNING),
                msgs_type(abi::SSL_AD_NO_RENEGOTIATION),
            )?;
            return Ok(MsgProcess::FinishedReading);
        }
        c.renegotiate = true;
        c.hs.sh.new_session = true;
    }
    let hello = if c.sslv2_record {
        if !first || c.hs.sh.hrr != Hrr::None {
            return Err(Error::alert(
                abi::SSL_AD_UNEXPECTED_MESSAGE,
                abi::SSL_R_UNEXPECTED_MESSAGE,
            ));
        }
        ClientHello::parse_v2(body)?
    } else {
        ClientHello::parse(body, false)?
    };
    let contents = hello.extensions.clone().unwrap_or_default();
    ext::collect(c, &contents, cx::CLIENT_HELLO, 0, true)?;
    let s = state(c)?;
    s.hello = Some(hello);
    s.hello_body = body.to_vec();
    s.early_stage = stage::CALLBACK;
    Ok(MsgProcess::ContinueProcessing)
}

/// The received ClientHello.
fn hello(c: &Connection) -> Result<&ClientHello> {
    state_ref(c)
        .and_then(|s| s.hello.as_ref())
        .ok_or_else(Error::internal)
}

/// The session ID the client sent.
pub(crate) fn client_session_id(c: &Connection) -> Result<Vec<u8>> {
    Ok(hello(c)?.session_id.clone())
}

/// The stage reached.
fn stage_of(c: &Connection) -> u8 {
    state_ref(c).map_or(stage::DONE, |s| s.early_stage)
}

/// Records a stage as reached.
fn set_stage(c: &mut Connection, n: u8) -> Result<()> {
    state(c)?.early_stage = n;
    Ok(())
}

/// The body of the ClientHello extension `typ`, if received.
pub(crate) fn received_body(c: &Connection, typ: u16) -> Option<Vec<u8>> {
    ext::received(c, cx::CLIENT_HELLO, 0)
        .and_then(|r| r.get(typ))
        .map(|e| e.body.clone())
}

/// `tls_early_post_process_client_hello`, in stages. `false` while waiting for an answer.
fn early_post_process(c: &mut Connection, p: &dyn Provider) -> Result<bool> {
    early_post_process_inner(c, p).in_func("tls_early_post_process_client_hello")
}

/// See [`early_post_process`].
fn early_post_process_inner(c: &mut Connection, p: &dyn Provider) -> Result<bool> {
    if stage_of(c) == stage::CALLBACK {
        if c.cfg.callbacks.client_hello {
            match ask_once(c, Request::ClientHello, 0) {
                None => return Ok(false),
                Some(Answer::Continue) => {}
                Some(Answer::Fail { alert, .. }) => {
                    let al = alert.map_or(abi::SSL_AD_INTERNAL_ERROR, core::ffi::c_int::from);
                    return Err(Error::alert(al, abi::SSL_R_CALLBACK_FAILED));
                }
                Some(_) => return Err(Error::internal()),
            }
        }
        set_stage(c, stage::VERSION)?;
    }
    if stage_of(c) == stage::VERSION {
        choose_version_and_suite(c, p)?;
        set_stage(c, stage::SESSION)?;
    }
    if stage_of(c) == stage::SESSION {
        let isv2 = hello(c)?.sslv2;
        let fresh = isv2
            || (c.hs.sh.new_session
                && c.cfg.options & abi::SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION != 0);
        let hit = if fresh {
            false
        } else {
            match ticket::get_prev_session(c, p)? {
                None => return Ok(false),
                Some(h) => h,
            }
        };
        if hit {
            c.neg.reused = true;
        } else {
            ticket::new_session(c, p)?;
        }
        set_stage(c, stage::CHECKS)?;
    }
    if stage_of(c) == stage::CHECKS {
        resumption_and_compression_checks(c)?;
        set_stage(c, stage::EXTENSIONS)?;
    }
    if stage_of(c) == stage::EXTENSIONS {
        if ext::parse_all(c, p, cx::CLIENT_HELLO, 0, true)? == Step::Wait {
            return Ok(false);
        }
        set_stage(c, stage::RANDOM)?;
    }
    if stage_of(c) == stage::RANDOM {
        let d = c.hs.sh.downgrade.unwrap_or_default();
        c.hs.server_random = fill_server_random(c, p, d)?;
        if !c.neg.reused {
            sigalgs::set_server_sigalgs(c)?;
        }
        if c.is_tls13() && hello(c)?.compression_methods.len() != 1 {
            return Err(Error::alert(
                abi::SSL_AD_ILLEGAL_PARAMETER,
                abi::SSL_R_INVALID_COMPRESSION_ALGORITHM,
            ));
        }
        set_stage(c, stage::SECRET)?;
    }
    if stage_of(c) == stage::SECRET {
        if !session_secret(c)? {
            return Ok(false);
        }
        set_stage(c, stage::CERT_CB)?;
    }
    Ok(true)
}

/// `SSL_set_session_secret_cb` (EAP-FAST): a TLS 1.0-1.2 server not resuming may resume with
/// the callback's master secret, with its preferred suite (or one chosen from the client's).
/// `false` while waiting.
fn session_secret(c: &mut Connection) -> Result<bool> {
    if c.neg.reused || c.neg.version < v::TLS1 || c.is_tls13() || !c.cfg.callbacks.session_secret {
        return Ok(true);
    }
    let peer = state_ref(c)
        .map(|s| s.peer_ciphers.clone())
        .unwrap_or_default();
    let r = Request::SessionSecret {
        peer_ciphers: Some(peer.iter().map(|x| x.id).collect()),
    };
    let (master, pref) = match ask_once(c, r, 0) {
        None => return Ok(false),
        Some(Answer::SessionSecret(Some(x))) => x,
        Some(_) => return Ok(true),
    };
    c.neg.session.master_key = master;
    c.neg.reused = true;
    c.neg.session.verify_result = i64::from(abi::X509_V_OK);
    // RFC 4851 3.2.2: the client's session ID is echoed.
    let sid = client_session_id(c)?;
    if !sid.is_empty() {
        c.neg.session.session_id = sid;
    }
    let cp = match pref.and_then(crate::suites::by_id) {
        Some(cp) => Some(cp),
        None => {
            let server = c.cfg.ciphers.clone();
            ciphers::choose(c, &peer, &server)
        }
    };
    let Some(cp) = cp else {
        return Err(Error::alert(
            abi::SSL_AD_HANDSHAKE_FAILURE,
            abi::SSL_R_NO_SHARED_CIPHER,
        ));
    };
    c.neg.session.cipher_id = cp.id;
    Ok(true)
}

/// The version, the suites, the signalling values, and TLS 1.3's suite (the first part of
/// `tls_early_post_process_client_hello`).
fn choose_version_and_suite(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    let h = hello(c)?.clone();
    c.hs.client_random = h.random;
    if h.sslv2 {
        let lv = core::ffi::c_int::from(h.legacy_version);
        if lv == abi::SSL2_VERSION || lv & 0xff00 != abi::SSL3_VERSION_MAJOR << 8 {
            return Err(Error::alert(
                abi::SSL_AD_PROTOCOL_VERSION,
                abi::SSL_R_UNKNOWN_PROTOCOL,
            ));
        }
        c.hs.sh.client_version = h.legacy_version;
    }
    let sv = received_body(c, t::SUPPORTED_VERSIONS);
    let hrr = c.hs.sh.hrr != Hrr::None;
    match version::choose_server(c, h.legacy_version, sv.as_deref(), hrr) {
        Ok(d) => c.hs.sh.downgrade = Some(d),
        Err(reason) => {
            if finished::is_first_handshake(c) {
                // Like the record layer, the alert goes out with the client's version.
                c.neg.version = h.legacy_version;
                c.hs.sh.client_version = h.legacy_version;
                c.rw.version = h.legacy_version;
            }
            return Err(Error::alert(abi::SSL_AD_PROTOCOL_VERSION, reason));
        }
    }
    if c.is_tls13() && !c.hs_in.is_empty() {
        return Err(Error::alert(
            abi::SSL_AD_UNEXPECTED_MESSAGE,
            abi::SSL_R_NOT_ON_RECORD_BOUNDARY,
        ));
    }
    c.neg.reused = false;
    let raw = ciphers::cache_cipherlist(&h.cipher_suites, h.sslv2)?;
    let (list, scsvs) = ciphers::bytes_to_cipher_list(&h.cipher_suites, h.sslv2, true)?;
    let renegotiate = c.renegotiate;
    let mut binding = false;
    for scsv in &scsvs {
        if scsv.id == crate::suites::cid(abi::SSL3_CK_SCSV) {
            if renegotiate {
                return Err(Error::alert(
                    abi::SSL_AD_HANDSHAKE_FAILURE,
                    abi::SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING,
                ));
            }
            binding = true;
        } else if scsv.id == crate::suites::cid(abi::SSL3_CK_FALLBACK_SCSV)
            && !version::is_highest(c)
        {
            return Err(Error::alert(
                abi::SSL_AD_INAPPROPRIATE_FALLBACK,
                abi::SSL_R_INAPPROPRIATE_FALLBACK,
            ));
        }
    }
    {
        let s = state(c)?;
        s.send_connection_binding = binding;
        s.ciphers_raw = raw;
        s.peer_ciphers.clone_from(&list);
        s.scsvs = scsvs;
    }
    if c.is_tls13() {
        let server = c.cfg.ciphers.clone();
        let Some(cp) = ciphers::choose(c, &list, &server) else {
            return Err(Error::alert(
                abi::SSL_AD_HANDSHAKE_FAILURE,
                abi::SSL_R_NO_SHARED_CIPHER,
            ));
        };
        if c.hs.sh.hrr == Hrr::Pending && c.hs.new_cipher.is_none_or(|x| x.id != cp.id) {
            return Err(Error::alert(
                abi::SSL_AD_ILLEGAL_PARAMETER,
                abi::SSL_R_BAD_CIPHER,
            ));
        }
        c.hs.new_cipher = Some(cp);
    }
    // Extended Master Secret is needed before the session lookup.
    let ems = ext::index_of(t::EXTENDED_MASTER_SECRET).ok_or_else(Error::internal)?;
    if ext::parse_extension(c, p, ems, cx::CLIENT_HELLO, 0)? == Step::Wait {
        return Err(Error::internal());
    }
    Ok(())
}

/// The checks after the session lookup: a resumed TLS 1.2 session's suite must be offered
/// again, the null compression must be, and (with `SSL_OP_SAFARI_ECDHE_ECDSA_BUG`) Safari is
/// recognised.
fn resumption_and_compression_checks(c: &mut Connection) -> Result<()> {
    let h = hello(c)?.clone();
    if c.is_tls13() {
        state(c)?.tmp_session_id.clone_from(&h.session_id);
    }
    if !c.is_tls13() && c.neg.reused {
        let id = c.neg.session.cipher_id;
        let offered = state_ref(c).is_some_and(|s| s.peer_ciphers.iter().any(|x| x.id == id));
        if !offered {
            return Err(Error::alert(
                abi::SSL_AD_ILLEGAL_PARAMETER,
                abi::SSL_R_REQUIRED_CIPHER_MISSING,
            ));
        }
    }
    if h.compression_methods.is_empty() {
        return Err(Error::decode(abi::SSL_R_NO_COMPRESSION_SPECIFIED));
    }
    if !h.compression_methods.contains(&0) {
        return Err(Error::alert(
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_R_REQUIRED_COMPRESSION_ALGORITHM_MISSING,
        ));
    }
    if c.cfg.options & abi::SSL_OP_SAFARI_ECDHE_ECDSA_BUG != 0 {
        check_for_safari(c, &h);
    }
    Ok(())
}

/// Safari's ClientHello extensions as OpenSSL compares them (`kSafariExtensionsBlock`).
const SAFARI_EXTENSIONS: [u8; 34] = [
    0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x02,
    0x01, 0x00, 0x00, 0x0d, 0x00, 0x0c, 0x00, 0x0a, 0x05, 0x01, 0x04, 0x01, 0x02, 0x01, 0x04, 0x03,
    0x02, 0x03,
];
/// The length of its part before signature_algorithms.
const SAFARI_COMMON_LENGTH: usize = 18;

/// `ssl_check_for_safari`, as OpenSSL reads the extension block: two octets skipped, a type
/// that must be server_name's, a 2-octet-length vector, and then exactly Safari's extensions.
fn check_for_safari(c: &mut Connection, h: &ClientHello) {
    let contents = h.extensions.as_deref().unwrap_or_default();
    let mut rd = Reader::new(contents);
    let ok =
        rd.take(2).is_ok() && rd.u16().is_ok_and(|typ| typ == t::SERVER_NAME) && rd.vec16().is_ok();
    if !ok {
        return;
    }
    let n = if c.hs.sh.client_version >= v::TLS1_2 {
        SAFARI_EXTENSIONS.len()
    } else {
        SAFARI_COMMON_LENGTH
    };
    c.hs.sh.is_probably_safari = SAFARI_EXTENSIONS.get(..n) == Some(rd.rest());
}

/// `ssl_fill_hello_random` for the server: random octets (with `SSL_MODE_SEND_SERVERHELLO_TIME`
/// the time first), ending with the downgrade sentinel when one applies.
///
/// # Errors
/// The random generator failed.
fn fill_server_random(
    c: &Connection,
    p: &dyn Provider,
    d: version::Downgrade,
) -> Result<[u8; RANDOM_LEN]> {
    let mut r = [0u8; RANDOM_LEN];
    if c.cfg.mode & u64::from(abi::SSL_MODE_SEND_SERVERHELLO_TIME) != 0 {
        let now = u32::try_from(c.cfg.now & 0xffff_ffff).unwrap_or(0);
        let (head, tail) = r.split_at_mut(4);
        head.copy_from_slice(&now.to_be_bytes());
        p.random(tail, false)
            .map_err(|_| Error::alert(abi::SSL_AD_INTERNAL_ERROR, abi::ERR_R_INTERNAL_ERROR))?;
    } else {
        p.random(&mut r, false)
            .map_err(|_| Error::alert(abi::SSL_AD_INTERNAL_ERROR, abi::ERR_R_INTERNAL_ERROR))?;
    }
    if let Some(s) = version::sentinel(d)
        && let Some(tail) = r.get_mut(RANDOM_LEN.saturating_sub(s.len())..)
    {
        tail.copy_from_slice(&s);
    }
    Ok(r)
}

/// `tls_post_process_client_hello`: the early post-processing, then the certificate callback,
/// TLS 1.2's suite, the signature algorithm, the status request callback, and TLS 1.2's ALPN.
/// The handshake then turns to writing.
///
/// # Errors
/// A callback failed, or nothing could be chosen (OpenSSL's alerts and reasons).
pub(crate) fn post_process_client_hello(
    c: &mut Connection,
    p: &dyn Provider,
    wst: Work,
) -> Result<Work> {
    if !early_post_process(c, p)? {
        return Ok(wst);
    }
    let tls13 = c.is_tls13();
    let hit = c.neg.reused;
    if stage_of(c) == stage::CERT_CB {
        if !hit && c.cfg.callbacks.cert {
            match ask_once(c, Request::Cert, 0) {
                None => return Ok(Work::MoreB),
                Some(Answer::Continue) => {}
                Some(_) => {
                    return Err(Error::alert(
                        abi::SSL_AD_INTERNAL_ERROR,
                        abi::SSL_R_CERT_CB_ERROR,
                    ));
                }
            }
        }
        set_stage(c, stage::CHOOSE)?;
    }
    if stage_of(c) == stage::CHOOSE {
        if !hit || tls13 {
            if !tls13 {
                let client = state_ref(c)
                    .map(|s| s.peer_ciphers.clone())
                    .unwrap_or_default();
                let server = c.cfg.ciphers.clone();
                let Some(cp) = ciphers::choose(c, &client, &server) else {
                    return Err(Error::alert(
                        abi::SSL_AD_HANDSHAKE_FAILURE,
                        abi::SSL_R_NO_SHARED_CIPHER,
                    ));
                };
                c.hs.new_cipher = Some(cp);
            }
            if !hit {
                sigalgs::choose(c, true)?;
            }
        } else {
            // Resuming TLS 1.2: the session's suite and master secret.
            c.hs.new_cipher = crate::suites::by_id(c.neg.session.cipher_id);
            if c.hs.new_cipher.is_none() {
                return Err(Error::internal());
            }
            c.neg.master_secret.clone_from(&c.neg.session.master_key);
            c.neg.ems = c.neg.session.ems;
            c.neg.etm = c.hs.sh.use_etm;
        }
        if tls13 && !hit {
            c.neg.session.cipher_id = c.hs.new_cipher.map_or(0, |x| x.id);
        }
        c.neg.cipher = c.hs.new_cipher;
        c.neg.secure_renegotiation = state_ref(c).is_some_and(|s| s.send_connection_binding);
        set_stage(c, stage::STATUS)?;
    }
    if stage_of(c) == stage::STATUS {
        if !handle_status_request(c)? {
            return Ok(Work::MoreB);
        }
        set_stage(c, stage::ALPN)?;
    }
    if stage_of(c) == stage::ALPN {
        if !tls13 && handle_alpn(c, p)? == Step::Wait {
            return Ok(Work::MoreB);
        }
        set_stage(c, stage::DONE)?;
    }
    // SRP (`ssl_check_srp_ext_ClientHello`): SRP suites are only chosen with SRP configured,
    // which a server can't be here.
    if let Some(s) = super::state_ref(c)
        && s.hello.is_some()
    {
        state(c)?.hello = None;
    }
    // OpenSSL's WORK_FINISHED_STOP from post-processing turns to writing.
    Ok(Work::FinishedSwap)
}

/// `tls_handle_status_request`: with a status request and a status callback, the callback
/// ([`Request::Status`]) decides whether the OCSP response it set is sent. `false` while
/// waiting for the answer.
fn handle_status_request(c: &mut Connection) -> Result<bool> {
    handle_status_request_inner(c).in_func("tls_handle_status_request")
}

/// See [`handle_status_request`].
fn handle_status_request_inner(c: &mut Connection) -> Result<bool> {
    state(c)?.status_expected = false;
    if c.hs.sh.status_type == STATUSTYPE_NOTHING || !c.cfg.callbacks.status {
        return Ok(true);
    }
    let Some(cert) = c.hs.sh.cert else {
        return Ok(true);
    };
    c.cfg.current_cert = Some(cert);
    let req = {
        let s = state_ref(c).ok_or_else(Error::internal)?;
        Request::Status {
            ocsp_ids: s.ocsp_ids.clone(),
            ocsp_exts: s.ocsp_exts.clone(),
        }
    };
    let (ret, response) = match ask_once(c, req, 0) {
        None => return Ok(false),
        Some(Answer::Status { ret, response }) => (ret, response),
        Some(_) => (abi::SSL_TLSEXT_ERR_ALERT_FATAL, None),
    };
    match ret {
        abi::SSL_TLSEXT_ERR_NOACK => {}
        abi::SSL_TLSEXT_ERR_OK => {
            let resp =
                response.or_else(|| c.cfg.certs.get(cert).and_then(|k| k.ocsp_response.clone()));
            let s = state(c)?;
            s.status_expected = resp.is_some();
            s.ocsp_response = resp;
        }
        _ => {
            return Err(Error::alert(
                abi::SSL_AD_INTERNAL_ERROR,
                abi::SSL_R_CLIENTHELLO_TLSEXT,
            ));
        }
    }
    Ok(true)
}

/// `tls_handle_alpn`: the server's ALPN selection (the ALPN callback, with
/// [`Request::AlpnSelect`]): a protocol chosen is used (and NPN dropped); early data needs it
/// to match the session's, and a new session records it. No acknowledgement goes on as if
/// there were no callback; anything else fails with `SSL_R_NO_APPLICATION_PROTOCOL`.
///
/// # Errors
/// As above.
pub(crate) fn handle_alpn(c: &mut Connection, _p: &dyn Provider) -> Result<Step> {
    handle_alpn_inner(c, _p).in_func("tls_handle_alpn")
}

/// See [`handle_alpn`].
fn handle_alpn_inner(c: &mut Connection, _p: &dyn Provider) -> Result<Step> {
    if c.cfg.callbacks.alpn_select
        && let Some(protos) = c.hs.sh.alpn_proposed.clone()
    {
        match ask_once(c, Request::AlpnSelect { protos }, 0) {
            None => return Ok(Step::Wait),
            // Copying an empty selection fails (`OPENSSL_memdup` of nothing).
            Some(Answer::Alpn(Some(sel))) if sel.is_empty() => return Err(Error::internal()),
            Some(Answer::Alpn(Some(sel))) => {
                c.neg.alpn = Some(sel.clone());
                c.hs.sh.npn_seen = false;
                if c.neg.session.alpn.as_deref() != Some(&sel) {
                    c.hs.sh.early_data_ok = false;
                    if !c.neg.reused {
                        if c.neg.session.alpn.is_some() {
                            return Err(Error::internal());
                        }
                        c.neg.session.alpn = Some(sel);
                    }
                }
                return Ok(Step::Done);
            }
            Some(Answer::Alpn(None)) => {}
            Some(_) => {
                return Err(Error::alert(
                    abi::SSL_AD_NO_APPLICATION_PROTOCOL,
                    abi::SSL_R_NO_APPLICATION_PROTOCOL,
                ));
            }
        }
    }
    if c.neg.session.alpn.is_some() {
        c.hs.sh.early_data_ok = false;
    }
    Ok(Step::Done)
}

/// `tls_construct_server_hello`, and the HelloRetryRequest: the version (TLS 1.2's number for
/// TLS 1.3), the random (the fixed one for a HelloRetryRequest), the session ID (TLS 1.3
/// echoes the client's; a new TLS 1.2 session without a server cache sends none), the suite,
/// no compression, and the extensions. After a HelloRetryRequest the session is dropped and
/// the transcript starts again from ClientHello1's hash; otherwise, without client
/// authentication, the messages needn't be kept beyond the transcript hash.
///
/// # Errors
/// An extension failed, or the transcript couldn't be started.
pub(crate) fn construct_server_hello(c: &mut Connection, p: &dyn Provider) -> Result<Construct> {
    let hrr = c.hs.sh.hrr == Hrr::Pending;
    let tls13 = c.is_tls13();
    let usetls13 = tls13 || hrr;
    let legacy_version = if usetls13 { v::TLS1_2 } else { c.neg.version };
    let random = if hrr { HRR_RANDOM } else { c.hs.server_random };
    if c.cfg.session_cache_mode & i64::from(abi::SSL_SESS_CACHE_SERVER) == 0 && !c.neg.reused {
        c.neg.session.session_id.clear();
    }
    let session_id = if usetls13 {
        state(c)?.tmp_session_id.clone()
    } else {
        c.neg.session.session_id.clone()
    };
    let cp = c.hs.new_cipher.ok_or_else(Error::internal)?;
    let context = if hrr {
        cx::TLS1_3_HELLO_RETRY_REQUEST
    } else if tls13 {
        cx::TLS1_3_SERVER_HELLO
    } else {
        cx::TLS1_2_SERVER_HELLO
    };
    let Some(block) = ext::construct(c, p, context, 0)? else {
        return Ok(Construct::Ask);
    };
    let extensions = block.get(2..).map(<[u8]>::to_vec);
    let body = ServerHello {
        legacy_version,
        random,
        session_id,
        cipher_suite: cp.protocol_id(),
        compression: 0,
        extensions,
        hrr,
    }
    .encode()?;
    if hrr {
        c.neg.session = crate::conn::Session::default();
        c.neg.reused = false;
        synthetic_message_hash(c, p)?;
    } else {
        let verify_peer = c.cfg.verify_mode & abi::SSL_VERIFY_PEER != 0;
        if !verify_peer {
            digest_cached_records(c, p, false)?;
        } else if tls13 {
            // TLS 1.3 needs the hash from here on (`ssl_handshake_hash` keeps the buffer).
            digest_cached_records(c, p, true)?;
        }
    }
    Ok(Construct::Send(body))
}

/// `create_synthetic_message_hash`: the transcript starts again with a message_hash of
/// ClientHello1 (RFC 8446, section 4.4.1), buffering what follows.
fn synthetic_message_hash(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    let alg = common::keys::handshake_md(c)?;
    let ch1 = match c.hs.transcript.buffered() {
        Some(b) => hash_of(p, alg, b)?,
        None => c.hs.transcript.current()?,
    };
    let msg = crate::msgs::message_hash(&ch1)?;
    let mut fresh = Transcript::new();
    fresh.add(&msg);
    c.hs.transcript = fresh;
    Ok(())
}

/// `tls_construct_encrypted_extensions`.
///
/// # Errors
/// An extension failed.
pub(crate) fn construct_encrypted_extensions(
    c: &mut Connection,
    p: &dyn Provider,
) -> Result<Construct> {
    Ok(
        match ext::construct(c, p, cx::TLS1_3_ENCRYPTED_EXTENSIONS, 0)? {
            Some(block) => Construct::Send(block),
            None => Construct::Ask,
        },
    )
}
