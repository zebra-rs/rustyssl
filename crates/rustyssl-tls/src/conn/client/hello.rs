//! The hellos: the ClientHello (`tls_construct_client_hello`, with the PSK binders filled in
//! once the message is complete), the ServerHello and HelloRetryRequest
//! (`tls_process_server_hello`, `tls_process_as_hello_retry_request`), and TLS 1.3's
//! EncryptedExtensions.

use rustyssl_abi as abi;

use super::{Connection, State, digest_cached_records, middlebox, state};
use crate::conn::Session;
use crate::conn::common::{EarlyDataState, Hrr, ciphers, ext, keys, version};
use crate::conn::statem::{Construct, MsgProcess};
use crate::consts::context as cx;
use crate::consts::ext as t;
use crate::consts::{HRR_RANDOM, handshake as hm, version as v};
use crate::crypto::Provider;
use crate::error::{Error, Result};
use crate::keysched::{self, Transcript};
use crate::msgs::{self, ext::EXT_DEFS, hello::ClientHello, hello::ServerHello};
use crate::suites::{self, Cipher};

/// `SSL_SESSION_is_resumable` for a client's session: it has a session ID or a ticket.
fn resumable(s: &Session) -> bool {
    !s.session_id.is_empty() || s.ticket.as_ref().is_some_and(|t| !t.is_empty())
}

/// `ssl_get_new_session` for a client: a fresh session at the version in use.
fn new_session(c: &Connection) -> Session {
    Session {
        version: c.neg.version,
        sid_ctx: c.cfg.sid_ctx.clone(),
        time: super::now(c),
        timeout: c.neg.session.timeout,
        ..Session::default()
    }
}

/// The first part of `tls_construct_client_hello`, once per ClientHello: the version, the
/// session to offer, the random, and the legacy_session_id.
fn prepare(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    version::set_client_hello_version(c)
        .map_err(|r| Error::alert(abi::SSL_AD_INTERNAL_ERROR, r))?;
    if c.first_handshake && c.cfg.method_version == version::ANY {
        c.version_pending = true;
    }
    let hrr = c.hs.sh.hrr;
    let offered = if c.first_handshake {
        c.cfg.session.clone()
    } else {
        Some(c.neg.session.clone())
    };
    let usable = offered.filter(|s| version::supported(c, s.version) && resumable(s));
    if hrr == Hrr::None {
        c.neg.session = match usable {
            Some(s) => s,
            None => new_session(c),
        };
    }
    if hrr == Hrr::None {
        let mut r = [0u8; 32];
        p.random(&mut r, false)
            .map_err(|_| Error::alert_lib(abi::SSL_AD_INTERNAL_ERROR, abi::ERR_R_INTERNAL_ERROR))?;
        c.hs.client_random = r;
    }
    let tls13 = c.neg.version == v::TLS1_3;
    if c.hs.sh.new_session || c.neg.session.version == v::TLS1_3 {
        if tls13 && middlebox(c) {
            if hrr == Hrr::None {
                let mut id = vec![0u8; 32];
                p.random(&mut id, false).map_err(|_| {
                    Error::alert_lib(abi::SSL_AD_INTERNAL_ERROR, abi::ERR_R_INTERNAL_ERROR)
                })?;
                state(c)?.tmp_session_id = id;
            }
        } else {
            // OpenSSL sends none and keeps what it had to compare the echo against.
        }
    } else if tls13 {
        let id = c.neg.session.session_id.clone();
        state(c)?.tmp_session_id = id;
    }
    state(c)?.hello_ready = true;
    Ok(())
}

/// The legacy_session_id the ClientHello carries (after [`prepare`]).
fn hello_session_id(c: &Connection, st: &State) -> Vec<u8> {
    if c.hs.sh.new_session || c.neg.session.version == v::TLS1_3 {
        if c.neg.version == v::TLS1_3 && middlebox(c) {
            st.tmp_session_id.clone()
        } else {
            Vec::new()
        }
    } else {
        c.neg.session.session_id.clone()
    }
}

/// `tls_construct_client_hello`: the ClientHello's body, with its PSK binders computed over
/// the message up to them (`tls_construct_ctos_psk`'s second half). `Construct::Ask` while an
/// extension waits for an answer.
///
/// # Errors
/// OpenSSL's alert and reason.
pub(super) fn construct_client_hello(c: &mut Connection, p: &dyn Provider) -> Result<Construct> {
    if !state(c)?.hello_ready {
        prepare(c, p)?;
    }
    let session_id = {
        let st = super::state_ref(c).ok_or_else(Error::internal)?;
        hello_session_id(c, st)
    };
    let cipher_suites = ciphers::cipher_list_to_bytes(c)?;
    let head = ClientHello {
        legacy_version: c.hs.sh.client_version,
        random: c.hs.client_random,
        session_id,
        cookie: None,
        cipher_suites,
        compression_methods: vec![0],
        extensions: None,
        extensions_offset: 0,
        sslv2: false,
    }
    .encode()?;
    state(c)?.hello_prefix_len = head.len();
    let Some(block) = ext::construct(c, p, cx::CLIENT_HELLO, 0)? else {
        return Ok(Construct::Ask);
    };
    let mut body = head;
    body.extend_from_slice(&block);
    fill_binders(c, p, &mut body)?;
    #[cfg(test)]
    if !state(c)?.hello_override.is_empty() {
        let st = state(c)?;
        st.made.push(body);
        return Ok(Construct::Send(st.hello_override.remove(0)));
    }
    Ok(Construct::Send(body))
}

/// Fills in the PSK binders the pre_shared_key extension left as zeros at the end of `body`
/// (`tls_psk_do_binder` for each identity), keeping the early secret of the resumption PSK
/// (`s->early_secret`) and of an external one (`psksession->early_secret`).
fn fill_binders(c: &mut Connection, p: &dyn Provider, body: &mut [u8]) -> Result<()> {
    let binders = state(c)?.binders.clone();
    if binders.is_empty() {
        return Ok(());
    }
    let total = binders.iter().fold(2usize, |n, (h, _, _)| {
        n.saturating_add(1).saturating_add(h.len())
    });
    let msg = msgs::frame(hm::CLIENT_HELLO, body)?;
    let cut = msg.len().checked_sub(total).ok_or_else(Error::internal)?;
    let prefix = msg.get(..cut).ok_or_else(Error::internal)?.to_vec();
    let mut at = body
        .len()
        .checked_sub(total)
        .and_then(|a| a.checked_add(2))
        .ok_or_else(Error::internal)?;
    for (hash, psk, external) in binders {
        let (sched, binder) = ext::psk_do_binder(c, p, hash, &prefix, &psk, external, None)?;
        let start = at.checked_add(1).ok_or_else(Error::internal)?;
        let end = start
            .checked_add(binder.len())
            .ok_or_else(Error::internal)?;
        body.get_mut(start..end)
            .ok_or_else(Error::internal)?
            .copy_from_slice(&binder);
        at = end;
        if external {
            c.hs.sh.keys.psk_early = Some(sched);
        } else {
            c.hs.sh.keys.schedule = Some(sched);
        }
    }
    Ok(())
}

/// `set_client_ciphersuite`: checks the suite the server chose.
fn set_client_ciphersuite(c: &mut Connection, id: u16) -> Result<()> {
    let ill = |r| Error::alert(abi::SSL_AD_ILLEGAL_PARAMETER, r);
    let Some(cp) = suites::by_protocol_id(id) else {
        return Err(ill(abi::SSL_R_UNKNOWN_CIPHER_RETURNED));
    };
    if ciphers::disabled(c, cp, abi::SSL_SECOP_CIPHER_CHECK, true) {
        return Err(ill(abi::SSL_R_WRONG_CIPHER_RETURNED));
    }
    if !c.cfg.ciphers.iter().any(|x| x.id == cp.id) {
        return Err(ill(abi::SSL_R_WRONG_CIPHER_RETURNED));
    }
    if c.is_tls13() && c.hs.new_cipher.is_some_and(|n| n.id != cp.id) {
        return Err(ill(abi::SSL_R_WRONG_CIPHER_RETURNED));
    }
    if c.neg.reused && c.neg.session.cipher_id != cp.id {
        if c.is_tls13() {
            let old = suites::by_id(c.neg.session.cipher_id).ok_or_else(Error::internal)?;
            if cp.handshake_hash().is_none() || hash13(cp) != hash13(old) {
                return Err(ill(abi::SSL_R_CIPHERSUITE_DIGEST_HAS_CHANGED));
            }
        } else {
            return Err(ill(abi::SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED));
        }
    }
    c.hs.new_cipher = Some(cp);
    Ok(())
}

/// A TLS 1.3 suite's hash.
pub(super) fn hash13(cp: &Cipher) -> crate::crypto::HashAlg {
    keys::hashes(v::TLS1_3, cp).0
}

/// `tls_validate_all_contexts`: every extension received may appear in `thisctx` (and isn't
/// DTLS-only).
fn validate_all_contexts(c: &Connection, thisctx: u32, collected: u32) -> bool {
    let Some(r) = ext::received(c, collected, 0) else {
        return true;
    };
    for (i, e) in r.exts.iter().enumerate() {
        let Some(e) = e else { continue };
        let context = match EXT_DEFS.get(i) {
            Some(d) => d.context,
            None => {
                match c
                    .cfg
                    .custom_exts
                    .iter()
                    .find(|m| m.typ == e.typ && m.server != Some(true))
                {
                    Some(m) => m.context,
                    None => return false,
                }
            }
        };
        if context & thisctx == 0 || context & cx::DTLS_ONLY != 0 {
            return false;
        }
    }
    true
}

/// Re-files the ServerHello's collected block under the context the version decided, as
/// OpenSSL then parses it (`SSL_EXT_TLS1_3_SERVER_HELLO` or `SSL_EXT_TLS1_2_SERVER_HELLO`).
fn refile(c: &mut Connection, from: u32, to: u32) {
    if let Some(r) =
        c.hs.sh
            .received
            .iter_mut()
            .find(|r| r.context == from && r.chainidx == 0)
    {
        r.context = to;
    }
}

/// `tls_process_server_hello`.
///
/// # Errors
/// OpenSSL's alert and reason.
pub(super) fn process_server_hello(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
) -> Result<MsgProcess> {
    let both = cx::TLS1_2_SERVER_HELLO | cx::TLS1_3_SERVER_HELLO;
    if !state(c)?.sh_stage {
        let tls13_possible = c.neg.version == v::TLS1_3;
        let looks_hrr = tls13_possible
            && body.get(..2) == Some(&v::TLS1_2.to_be_bytes()[..])
            && body.get(2..34) == Some(&HRR_RANDOM[..]);
        if looks_hrr && c.hs.sh.hrr != Hrr::None {
            return Err(Error::alert(
                abi::SSL_AD_UNEXPECTED_MESSAGE,
                abi::SSL_R_UNEXPECTED_MESSAGE,
            ));
        }
        let sh = ServerHello::parse(body, tls13_possible)?;
        if sh.hrr {
            c.hs.sh.hrr = Hrr::Pending;
            version::set_record_version(c, c.neg.version);
        } else {
            c.hs.server_random = sh.random;
        }
        let exts = sh.extensions.clone().unwrap_or_default();
        if !sh.hrr {
            ext::collect(c, &exts, both, 0, true)?;
            choose_version(c, p, sh.legacy_version)?;
        }
        if c.is_tls13() || sh.hrr {
            if sh.compression != 0 {
                return Err(Error::alert(
                    abi::SSL_AD_ILLEGAL_PARAMETER,
                    abi::SSL_R_INVALID_COMPRESSION_ALGORITHM,
                ));
            }
            if sh.session_id != state(c)?.tmp_session_id {
                return Err(Error::alert(
                    abi::SSL_AD_ILLEGAL_PARAMETER,
                    abi::SSL_R_INVALID_SESSION_ID,
                ));
            }
        }
        if sh.hrr {
            set_client_ciphersuite(c, sh.cipher_suite)?;
            let st = state(c)?;
            st.sh_stage = true;
            st.sh_hrr = true;
            return process_as_hrr(c, p, &exts, body);
        }
        let context = if c.is_tls13() {
            cx::TLS1_3_SERVER_HELLO
        } else {
            cx::TLS1_2_SERVER_HELLO
        };
        if !validate_all_contexts(c, context, both) {
            return Err(Error::alert(
                abi::SSL_AD_ILLEGAL_PARAMETER,
                abi::SSL_R_BAD_EXTENSION,
            ));
        }
        refile(c, both, context);
        c.neg.reused = false;
        if c.is_tls13() {
            if !c.hs_in.is_empty() {
                return Err(Error::alert(
                    abi::SSL_AD_UNEXPECTED_MESSAGE,
                    abi::SSL_R_NOT_ON_RECORD_BOUNDARY,
                ));
            }
            let idx = ext::index_of(t::PRE_SHARED_KEY).ok_or_else(Error::internal)?;
            if ext::parse_extension(c, p, idx, context, 0)? == ext::Step::Wait {
                return Err(Error::internal());
            }
        } else if !sh.session_id.is_empty() && sh.session_id == c.neg.session.session_id {
            c.neg.reused = true;
        }
        session_after_hello(c, &sh)?;
        set_client_ciphersuite(c, sh.cipher_suite)?;
        compression(c, sh.compression)?;
        if c.is_tls13() {
            // `tls13_setup_key_block`.
            c.neg.cipher = c.hs.new_cipher;
            if let Some(cp) = c.hs.new_cipher {
                c.neg.session.cipher_id = cp.id;
            }
        }
        state(c)?.sh_stage = true;
    }
    if state(c)?.sh_hrr {
        // A HelloRetryRequest whose processing waited for an answer.
        let exts = ServerHello::parse(body, true)?
            .extensions
            .unwrap_or_default();
        return process_as_hrr(c, p, &exts, body);
    }
    let context = if c.is_tls13() {
        cx::TLS1_3_SERVER_HELLO
    } else {
        cx::TLS1_2_SERVER_HELLO
    };
    if ext::parse_all(c, p, context, 0, true)? == ext::Step::Wait {
        return Ok(MsgProcess::Ask);
    }
    state(c)?.sh_stage = false;
    if c.is_tls13() {
        digest_cached_records(c, p, true)?;
        keys::store_handshake_traffic_hash(c)?;
        if c.cfg.quic || (c.hs.sh.early_data_state == EarlyDataState::None && !middlebox(c)) {
            keys::change_cipher_state13(
                c,
                p,
                abi::SSL3_CC_HANDSHAKE | abi::SSL3_CHANGE_CIPHER_CLIENT_WRITE,
                None,
            )?;
        }
        keys::change_cipher_state13(
            c,
            p,
            abi::SSL3_CC_HANDSHAKE | abi::SSL3_CHANGE_CIPHER_CLIENT_READ,
            None,
        )?;
    } else {
        c.neg.ems = c.hs.sh.flags & abi::TLS1_FLAGS_RECEIVED_EXTMS != 0;
        c.neg.etm = c.hs.sh.use_etm;
        if c.neg.reused {
            c.neg.master_secret = c.neg.session.master_key.clone();
            c.neg.ems = c.neg.session.ems;
        }
    }
    Ok(MsgProcess::ContinueReading)
}

/// `ssl_choose_client_version`'s first part: the supported_versions extension may replace the
/// legacy version, then the choice is checked.
fn choose_version(c: &mut Connection, p: &dyn Provider, legacy: u16) -> Result<()> {
    let both = cx::TLS1_2_SERVER_HELLO | cx::TLS1_3_SERVER_HELLO;
    let origv = c.neg.version;
    c.neg.version = legacy;
    let idx = ext::index_of(t::SUPPORTED_VERSIONS).ok_or_else(Error::internal)?;
    match ext::parse_extension(c, p, idx, both, 0) {
        Ok(_) => {}
        Err(e) => {
            c.neg.version = origv;
            return Err(e);
        }
    }
    let chosen = c.neg.version;
    c.neg.version = origv;
    let hrr = c.hs.sh.hrr != Hrr::None;
    version::choose_client(c, chosen, hrr)?;
    c.version_pending = false;
    Ok(())
}

/// The session after the ServerHello: a resumed one must have been made in this context; a
/// new one replaces the offer and records the version and (TLS 1.2) the session ID.
fn session_after_hello(c: &mut Connection, sh: &ServerHello) -> Result<()> {
    if c.neg.reused {
        if c.cfg.sid_ctx != c.neg.session.sid_ctx {
            return Err(Error::alert(
                abi::SSL_AD_ILLEGAL_PARAMETER,
                abi::SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT,
            ));
        }
    } else {
        if !c.neg.session.session_id.is_empty() {
            c.neg.session = new_session(c);
        }
        c.neg.session.version = c.neg.version;
        if !c.is_tls13() {
            c.neg.session.session_id.clone_from(&sh.session_id);
        }
    }
    if c.neg.version != c.neg.session.version {
        return Err(Error::alert(
            abi::SSL_AD_PROTOCOL_VERSION,
            abi::SSL_R_SSL_SESSION_VERSION_MISMATCH,
        ));
    }
    c.hs.sh.min_ver = c.neg.version;
    c.hs.sh.max_ver = c.neg.version;
    Ok(())
}

/// The compression method: only none is ever used (sessions never have compression, and the
/// default build registers no methods).
fn compression(c: &Connection, method: u8) -> Result<()> {
    if method == 0 {
        return Ok(());
    }
    let ill = |r| Error::alert(abi::SSL_AD_ILLEGAL_PARAMETER, r);
    if c.neg.reused {
        return Err(ill(
            abi::SSL_R_OLD_SESSION_COMPRESSION_ALGORITHM_NOT_RETURNED,
        ));
    }
    let allowed = c.cfg.options & abi::SSL_OP_NO_COMPRESSION == 0
        && crate::conn::common::security::check(
            c,
            abi::SSL_SECOP_COMPRESSION,
            0,
            0,
            crate::conn::common::security::SecOther::None,
        );
    if !allowed {
        return Err(ill(abi::SSL_R_COMPRESSION_DISABLED));
    }
    Err(ill(abi::SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM))
}

/// `tls_process_as_hello_retry_request`: the HelloRetryRequest's extensions (the group to send
/// a share for, a cookie), then the transcript restarts with the synthetic message_hash of the
/// first ClientHello, followed by the HelloRetryRequest.
fn process_as_hrr(
    c: &mut Connection,
    p: &dyn Provider,
    exts: &[u8],
    body: &[u8],
) -> Result<MsgProcess> {
    if c.hs.sh.early_data_state == EarlyDataState::FinishedWriting {
        c.rw.set_protection(
            crate::record::Mode::Plain(None),
            crate::record::Protection::Null,
        );
    }
    c.rw.version = v::TLS1_2;
    ext::collect(c, exts, cx::TLS1_3_HELLO_RETRY_REQUEST, 0, true)?;
    if ext::parse_all(c, p, cx::TLS1_3_HELLO_RETRY_REQUEST, 0, true)? == ext::Step::Wait {
        return Ok(MsgProcess::Ask);
    }
    let st = state(c)?;
    st.sh_stage = false;
    st.sh_hrr = false;
    if st.cookie.is_empty() && st.pkey {
        return Err(Error::alert(
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_R_NO_CHANGE_FOLLOWING_HRR,
        ));
    }
    // `create_synthetic_message_hash`.
    let alg = keys::handshake_md(c)?;
    let ch1 =
        c.hs.transcript
            .buffered()
            .filter(|b| !b.is_empty())
            .ok_or(Error::alert(
                abi::SSL_AD_INTERNAL_ERROR,
                abi::SSL_R_BAD_HANDSHAKE_LENGTH,
            ))?
            .to_vec();
    let hash = keysched::hash_of(p, alg, &ch1)?;
    let mut tr = Transcript::new();
    tr.add(&msgs::message_hash(&hash)?);
    tr.add(&msgs::frame(hm::SERVER_HELLO, body)?);
    c.hs.transcript = tr;
    Ok(MsgProcess::FinishedReading)
}

/// `tls_process_encrypted_extensions`.
///
/// # Errors
/// A malformed message (`SSL_R_LENGTH_MISMATCH`), or an extension's error.
pub(super) fn process_encrypted_extensions(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
) -> Result<MsgProcess> {
    let ee = msgs::misc::EncryptedExtensions::parse(body)?;
    ext::collect(c, &ee.extensions, cx::TLS1_3_ENCRYPTED_EXTENSIONS, 0, true)?;
    if ext::parse_all(c, p, cx::TLS1_3_ENCRYPTED_EXTENSIONS, 0, true)? == ext::Step::Wait {
        return Ok(MsgProcess::Ask);
    }
    Ok(MsgProcess::ContinueReading)
}
