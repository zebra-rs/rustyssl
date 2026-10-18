//! The client's state machine (OpenSSL's `statem_clnt.c` and `extensions_clnt.c`): the
//! transitions, the work around each message, and the messages a client sends and receives.
//!
//! The submodules hold the messages: [`hello`] the ClientHello, ServerHello, HelloRetryRequest,
//! and EncryptedExtensions; [`flight`] the rest of the server's flights (its certificate and
//! its verification, TLS 1.2's key exchange, CertificateRequest, NewSessionTicket, the
//! HelloRequest); [`send`] the client's ClientKeyExchange and certificate; [`exts`] the
//! extension handlers `common::ext` dispatches to.
//!
//! As everywhere in the core (ADR 0002), a callback is a [`Request`]: a function that needs an
//! answer returns its "not yet" state ([`MsgProcess::Ask`], a `Work::More*` state,
//! [`Construct::Ask`], [`Step::Wait`]) and runs again once the answer is there; what it did
//! before asking is either repeated harmlessly or recorded in [`State`].

mod exts;
mod flight;
mod hello;
mod send;

#[cfg(test)]
mod tests;

use core::ffi::c_int;

use rustyssl_abi as abi;

pub(crate) use self::exts::*;
use super::common::{self, EarlyDataState, Hrr, Pha, finished, keys};
use super::statem::{Construct, MsgProcess, Work, WriteTran, msgs_type, st};
use super::{Connection, RoleState, Session};
use crate::consts::handshake as hm;
use crate::crypto::{KeyShare, Provider, Secret};
use crate::error::{Error, Result};

/// OpenSSL's message size limits (`statem_local.h`).
mod limits {
    /// `SERVER_HELLO_MAX_LENGTH`.
    pub const SERVER_HELLO: usize = 65607;
    /// `CERTIFICATE_VERIFY_MAX_LENGTH`.
    pub const CERTIFICATE_VERIFY: usize = 65539;
    /// `SSL3_RT_MAX_PLAIN_LENGTH`, for CertificateStatus.
    pub const CERT_STATUS: usize = 16384;
    /// `SERVER_KEY_EXCH_MAX_LENGTH`.
    pub const SERVER_KEY_EXCH: usize = 102_400;
    /// `SERVER_HELLO_DONE_MAX_LENGTH`.
    pub const SERVER_HELLO_DONE: usize = 0;
    /// `CCS_MAX_LENGTH`.
    pub const CCS: usize = 1;
    /// `SESSION_TICKET_MAX_LENGTH_TLS13`.
    pub const SESSION_TICKET_13: usize = 131_338;
    /// `SESSION_TICKET_MAX_LENGTH_TLS12`.
    pub const SESSION_TICKET_12: usize = 65541;
    /// `FINISHED_MAX_LENGTH`.
    pub const FINISHED: usize = 64;
    /// `ENCRYPTED_EXTENSIONS_MAX_LENGTH`.
    pub const ENCRYPTED_EXTENSIONS: usize = 20000;
    /// `KEY_UPDATE_MAX_LENGTH`.
    pub const KEY_UPDATE: usize = 1;
}

/// A TLS 1.2 key exchange's outcome, made when the ServerKeyExchange is read (the server's
/// share is checked then, as OpenSSL checks it when it decodes the key): the client's public
/// value to send and the premaster secret.
pub(super) struct Kx12 {
    /// The client's encoded share (ECDHE point, or DHE public value padded to the prime).
    public: Vec<u8>,
    /// The premaster secret (DHE's without its leading zeros).
    pms: Secret,
}

/// The client's handshake state (what OpenSSL keeps for the client in `s->s3.tmp`, `s->ext`,
/// and `s->session` while a handshake runs).
#[derive(Default)]
#[expect(clippy::struct_excessive_bools, reason = "one flag per OpenSSL field")]
pub struct State {
    /// The key shares sent (`s->s3.tmp.ks_pkey`, `ks_group_id`), in the order sent.
    ks: Vec<(u16, Box<dyn KeyShare>)>,
    /// Whether the shares are current (`s->s3.tmp.pkey != NULL`): a HelloRetryRequest asking
    /// for another group drops them.
    pkey: bool,
    /// Whether the server's key share was used (`s->s3.peer_tmp != NULL`).
    peer_share: bool,
    /// The HelloRetryRequest's cookie (`s->ext.tls13_cookie`), sent once.
    cookie: Vec<u8>,
    /// The legacy_session_id sent in a TLS 1.3 ClientHello (`s->tmp_session_id`).
    tmp_session_id: Vec<u8>,
    /// Whether ALPN was offered (`s->s3.alpn_sent`).
    alpn_sent: bool,
    /// How many PSK identities were offered (`s->ext.tick_identity`).
    tick_identity: u16,
    /// An external PSK offered (`s->psksession`), its identity, and its key's suite.
    psk_session: Option<(Session, Vec<u8>)>,
    /// The PSK binders still to fill in after the ClientHello is complete: the hash, the
    /// PSK, and whether it is an external one, in the order offered.
    binders: Vec<(crate::crypto::HashAlg, Vec<u8>, bool)>,
    /// The extensions made for this ClientHello whose work happens once
    /// ([`exts`]'s memo).
    ext_memo: Vec<(u16, super::common::ext::ExtReturn)>,
    /// Whether this ClientHello's random, session and version are chosen (a construction
    /// re-run after a request keeps them).
    hello_ready: bool,
    /// The ClientHello's octets before its extension block, for the padding extension.
    hello_prefix_len: usize,
    /// Whether a CertificateStatus may follow the server's Certificate
    /// (`s->ext.status_expected`).
    status_expected: bool,
    /// The certificate types of a TLS 1.2 CertificateRequest (`s->s3.tmp.ctype`).
    ctype: Vec<u8>,
    /// TLS 1.2's key exchange, once the ServerKeyExchange gave the server's share.
    kx12: Option<Kx12>,
    /// The premaster secret made with the ClientKeyExchange (`s->s3.tmp.pms`).
    pms: Option<Secret>,
    /// The PSK identity hint (`s->session->psk_identity_hint`).
    psk_hint: Option<Vec<u8>>,
    /// TLS 1.2's PSK (`s->s3.tmp.psk`).
    psk: Option<Secret>,
    /// The early data the session allows (`s->max_early_data`).
    max_early_data: u32,
    /// The suite of the session that early data is sent under.
    early_cipher: Option<&'static crate::suites::Cipher>,
    /// Whether the ServerHello's processing got past its first stage (the version, suite, and
    /// session), so a run resumed after a request doesn't repeat it.
    sh_stage: bool,
    /// Whether that ServerHello was a HelloRetryRequest.
    sh_hrr: bool,
    /// A renegotiation the server asked for must set up a new handshake before the ClientHello
    /// (`tls_setup_handshake` in the write transition, which runs without a provider here).
    needs_setup: bool,
    /// ClientHellos to send in place of the ones made, in turn (tests replaying RFC 8448,
    /// whose extensions come in another order than OpenSSL's), once their state is made.
    #[cfg(test)]
    pub(super) hello_override: Vec<Vec<u8>>,
    /// The ClientHellos made in their place.
    #[cfg(test)]
    pub(super) made: Vec<Vec<u8>>,
}

impl core::fmt::Debug for State {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("client::State")
            .field(
                "key_shares",
                &self.ks.iter().map(|k| k.0).collect::<Vec<_>>(),
            )
            .field("tick_identity", &self.tick_identity)
            .finish_non_exhaustive()
    }
}

impl State {
    /// The certificate types of the server's TLS 1.2 CertificateRequest
    /// (`SSL_get0_certificate_types`); none in TLS 1.3.
    #[must_use]
    pub fn certificate_types(&self) -> &[u8] {
        &self.ctype
    }
}

/// The client's state.
///
/// # Errors
/// The handshake wasn't set up as a client's (an internal error).
fn state(c: &mut Connection) -> Result<&mut State> {
    match &mut c.hs.role {
        RoleState::Client(s) => Ok(s),
        _ => Err(Error::internal()),
    }
}

/// The client's state, read-only.
fn state_ref(c: &Connection) -> Option<&State> {
    match &c.hs.role {
        RoleState::Client(s) => Some(s),
        _ => None,
    }
}

/// The time in seconds since the epoch (the configuration's, or the system clock's).
pub(crate) fn now(c: &Connection) -> i64 {
    if let Some(t) = c.cfg.now {
        return t;
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// A `TLS_ST_*` comparison.
fn at(c: &Connection, s: abi::OSSL_HANDSHAKE_STATE) -> bool {
    c.st.hand_state == st(s)
}

/// Moves to `s`.
fn go(c: &mut Connection, s: abi::OSSL_HANDSHAKE_STATE) {
    c.st.hand_state = st(s);
}

/// Whether the message read is a ChangeCipherSpec (the state machine gives it the type
/// `SSL3_MT_CHANGE_CIPHER_SPEC`, whose octet is HelloRequest's: a CCS comes with its body
/// already taken, and OpenSSL's size of 1).
fn is_ccs(c: &Connection) -> bool {
    c.st.message_type == msgs_type(abi::SSL3_MT_CHANGE_CIPHER_SPEC)
        && c.st.message_size == 1
        && c.cur_msg.as_ref().is_some_and(|m| m.1.is_empty())
}

/// Whether the middlebox compatibility mode is on (`SSL_OP_ENABLE_MIDDLEBOX_COMPAT`).
fn middlebox(c: &Connection) -> bool {
    c.cfg.options & abi::SSL_OP_ENABLE_MIDDLEBOX_COMPAT != 0
}

/// `ssl3_digest_cached_records`: starts hashing the transcript with the suite's hash (keeping
/// the buffer with `keep`, for TLS 1.2's CertificateVerify), or drops the buffer if hashing
/// has started and `keep` is false.
///
/// # Errors
/// No suite yet, or the provider has no such hash.
pub(super) fn digest_cached_records(
    c: &mut Connection,
    p: &dyn Provider,
    keep: bool,
) -> Result<()> {
    if c.hs.transcript.alg().is_none() {
        if c.hs.transcript.buffered().is_none_or(<[u8]>::is_empty) {
            return Err(Error::alert(
                abi::SSL_AD_INTERNAL_ERROR,
                abi::SSL_R_BAD_HANDSHAKE_LENGTH,
            ));
        }
        let alg = keys::handshake_md(c)?;
        return c.hs.transcript.start_hash(p, alg, keep);
    }
    if !keep {
        c.hs.transcript.drop_buffer();
    }
    Ok(())
}

/// `ssl_x509err2alert`: the alert for a verification result.
pub(crate) fn x509err2alert(result: i64) -> c_int {
    let table: [(c_int, c_int); 40] = [
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
    table
        .iter()
        .find(|(e, _)| i64::from(*e) == result)
        .map_or(abi::SSL_AD_CERTIFICATE_UNKNOWN, |(_, a)| *a)
}

/// Sets up a handshake: the client's part of `tls_setup_handshake` (the common checks are
/// made first, in `common::setup_handshake`): a fresh client state, the status request
/// (`SSL_set_tlsext_status_type`), and the record layer's first-handshake flag.
///
/// # Errors
/// Never; `Result` for the caller.
pub(crate) fn setup(c: &mut Connection, _p: &dyn Provider) -> Result<()> {
    #[cfg(test)]
    let overrides = match &mut c.hs.role {
        RoleState::Client(s) => (
            core::mem::take(&mut s.hello_override),
            core::mem::take(&mut s.made),
        ),
        _ => (Vec::new(), Vec::new()),
    };
    c.hs.role = RoleState::Client(Box::default());
    #[cfg(test)]
    {
        let st = state(c)?;
        (st.hello_override, st.made) = overrides;
    }
    c.hs.sh.status_type = if c.cfg.status_request {
        abi::TLSEXT_STATUSTYPE_ocsp
    } else {
        common::STATUSTYPE_NOTHING
    };
    if c.first_handshake {
        c.hs.sh.hrr = Hrr::None;
    }
    Ok(())
}

/// The TLS 1.3 read transitions (`ossl_statem_client13_read_transition`).
fn read_transition13(c: &mut Connection, mt: u8) -> Result<bool> {
    let ccs = is_ccs(c);
    let to = match c.st.hand_state {
        s if s == st(abi::TLS_ST_CW_CLNT_HELLO) && mt == hm::SERVER_HELLO && !ccs => {
            abi::TLS_ST_CR_SRVR_HELLO
        }
        s if s == st(abi::TLS_ST_CR_SRVR_HELLO) && mt == hm::ENCRYPTED_EXTENSIONS => {
            abi::TLS_ST_CR_ENCRYPTED_EXTENSIONS
        }
        s if s == st(abi::TLS_ST_CR_ENCRYPTED_EXTENSIONS) => {
            if c.neg.reused {
                if mt != hm::FINISHED {
                    return Ok(false);
                }
                abi::TLS_ST_CR_FINISHED
            } else if mt == hm::CERTIFICATE_REQUEST {
                abi::TLS_ST_CR_CERT_REQ
            } else if mt == hm::CERTIFICATE {
                abi::TLS_ST_CR_CERT
            } else {
                return Ok(false);
            }
        }
        s if s == st(abi::TLS_ST_CR_CERT_REQ) && mt == hm::CERTIFICATE => abi::TLS_ST_CR_CERT,
        s if s == st(abi::TLS_ST_CR_CERT) && mt == hm::CERTIFICATE_VERIFY => {
            abi::TLS_ST_CR_CERT_VRFY
        }
        s if s == st(abi::TLS_ST_CR_CERT_VRFY) && mt == hm::FINISHED => abi::TLS_ST_CR_FINISHED,
        s if s == st(abi::TLS_ST_OK) => {
            if mt == hm::NEW_SESSION_TICKET {
                abi::TLS_ST_CR_SESSION_TICKET
            } else if mt == hm::KEY_UPDATE && !c.cfg.quic {
                abi::TLS_ST_CR_KEY_UPDATE
            } else if mt == hm::CERTIFICATE_REQUEST && c.hs.sh.pha == Pha::ExtSent && !ccs {
                c.hs.sh.pha = Pha::Requested;
                // Before the message goes into the transcript.
                finished::restore_handshake_digest_for_pha(c)?;
                abi::TLS_ST_CR_CERT_REQ
            } else {
                return Ok(false);
            }
        }
        _ => return Ok(false),
    };
    go(c, to);
    Ok(true)
}

/// Whether the suite's key exchange always has a ServerKeyExchange (`key_exchange_expected`).
fn key_exchange_expected(c: &Connection) -> bool {
    use crate::suites::masks::{SSL_kDHE, SSL_kDHEPSK, SSL_kECDHE, SSL_kECDHEPSK, SSL_kSRP};
    c.hs.new_cipher.is_some_and(|cp| {
        cp.mkey & (SSL_kDHE | SSL_kECDHE | SSL_kDHEPSK | SSL_kECDHEPSK | SSL_kSRP) != 0
    })
}

/// Whether a CertificateRequest may come (`cert_req_allowed`): not with anonymous, SRP, or PSK
/// authentication.
fn cert_req_allowed(c: &Connection) -> bool {
    use crate::suites::masks::{SSL_aNULL, SSL_aPSK, SSL_aSRP};
    let Some(cp) = c.hs.new_cipher else {
        return false;
    };
    !((c_int::from(c.neg.version) > abi::SSL3_VERSION && cp.auth & SSL_aNULL != 0)
        || cp.auth & (SSL_aSRP | SSL_aPSK) != 0)
}

/// Whether the suite is a PSK one and the message a ServerKeyExchange (optional there).
fn psk_ske(c: &Connection, mt: u8, ccs: bool) -> bool {
    !ccs && mt == hm::SERVER_KEY_EXCHANGE
        && c.hs
            .new_cipher
            .is_some_and(|cp| cp.mkey & crate::suites::masks::SSL_PSK != 0)
}

/// The read transition for message type `mt` (`ossl_statem_client_read_transition`).
///
/// # Errors
/// No transition: `SSL_R_UNEXPECTED_MESSAGE` with an unexpected-message alert.
pub(crate) fn read_transition(c: &mut Connection, mt: u8) -> Result<()> {
    let ok = if c.is_tls13() {
        read_transition13(c, mt)?
    } else {
        read_transition12(c, mt)
    };
    if ok {
        Ok(())
    } else {
        Err(Error::alert(
            abi::SSL3_AD_UNEXPECTED_MESSAGE,
            abi::SSL_R_UNEXPECTED_MESSAGE,
        ))
    }
}

/// The read transitions before TLS 1.3 is chosen, and in TLS 1.2 and earlier.
fn read_transition12(c: &mut Connection, mt: u8) -> bool {
    use crate::suites::masks::{SSL_aNULL, SSL_aPSK, SSL_aSRP};
    let ccs = is_ccs(c);
    let hs = c.st.hand_state;
    let is = |s: abi::OSSL_HANDSHAKE_STATE| hs == st(s);
    let to = if is(abi::TLS_ST_CW_CLNT_HELLO) || is(abi::TLS_ST_EARLY_DATA) {
        (mt == hm::SERVER_HELLO && !ccs).then_some(abi::TLS_ST_CR_SRVR_HELLO)
    } else if is(abi::TLS_ST_CR_SRVR_HELLO) {
        if c.neg.reused {
            if c.hs.sh.ticket_expected {
                (mt == hm::NEW_SESSION_TICKET && !ccs).then_some(abi::TLS_ST_CR_SESSION_TICKET)
            } else {
                ccs.then_some(abi::TLS_ST_CR_CHANGE)
            }
        } else if c
            .hs
            .new_cipher
            .is_some_and(|cp| cp.auth & (SSL_aNULL | SSL_aSRP | SSL_aPSK) == 0)
        {
            (mt == hm::CERTIFICATE && !ccs).then_some(abi::TLS_ST_CR_CERT)
        } else if key_exchange_expected(c) || psk_ske(c, mt, ccs) {
            (mt == hm::SERVER_KEY_EXCHANGE && !ccs).then_some(abi::TLS_ST_CR_KEY_EXCH)
        } else if mt == hm::CERTIFICATE_REQUEST && !ccs && cert_req_allowed(c) {
            Some(abi::TLS_ST_CR_CERT_REQ)
        } else if mt == hm::SERVER_HELLO_DONE && !ccs {
            Some(abi::TLS_ST_CR_SRVR_DONE)
        } else {
            None
        }
    } else if is(abi::TLS_ST_CR_CERT)
        || is(abi::TLS_ST_CR_CERT_STATUS)
        || is(abi::TLS_ST_CR_KEY_EXCH)
        || is(abi::TLS_ST_CR_CERT_REQ)
    {
        after_server_certificate(c, mt, ccs)
    } else if is(abi::TLS_ST_CW_FINISHED) {
        if c.hs.sh.ticket_expected {
            (mt == hm::NEW_SESSION_TICKET && !ccs).then_some(abi::TLS_ST_CR_SESSION_TICKET)
        } else {
            ccs.then_some(abi::TLS_ST_CR_CHANGE)
        }
    } else if is(abi::TLS_ST_CR_SESSION_TICKET) {
        ccs.then_some(abi::TLS_ST_CR_CHANGE)
    } else if is(abi::TLS_ST_CR_CHANGE) {
        (mt == hm::FINISHED && !ccs).then_some(abi::TLS_ST_CR_FINISHED)
    } else if is(abi::TLS_ST_OK) {
        (mt == hm::HELLO_REQUEST && !ccs).then_some(abi::TLS_ST_CR_HELLO_REQ)
    } else {
        None
    };
    match to {
        Some(s) => {
            go(c, s);
            true
        }
        None => false,
    }
}

/// The TLS 1.2 transitions from the server's Certificate on, with OpenSSL's fall-through:
/// CertificateStatus, ServerKeyExchange, CertificateRequest, ServerHelloDone.
fn after_server_certificate(
    c: &Connection,
    mt: u8,
    ccs: bool,
) -> Option<abi::OSSL_HANDSHAKE_STATE> {
    let hs = c.st.hand_state;
    let mut stage = if hs == st(abi::TLS_ST_CR_CERT) {
        0
    } else if hs == st(abi::TLS_ST_CR_CERT_STATUS) {
        1
    } else if hs == st(abi::TLS_ST_CR_KEY_EXCH) {
        2
    } else {
        3
    };
    if stage == 0 {
        let expected = state_ref(c).is_some_and(|s| s.status_expected);
        if expected && mt == hm::CERTIFICATE_STATUS && !ccs {
            return Some(abi::TLS_ST_CR_CERT_STATUS);
        }
        stage = 1;
    }
    if stage == 1 {
        if key_exchange_expected(c) || psk_ske(c, mt, ccs) {
            return (mt == hm::SERVER_KEY_EXCHANGE && !ccs).then_some(abi::TLS_ST_CR_KEY_EXCH);
        }
        stage = 2;
    }
    if stage == 2 && mt == hm::CERTIFICATE_REQUEST && !ccs {
        return cert_req_allowed(c).then_some(abi::TLS_ST_CR_CERT_REQ);
    }
    (mt == hm::SERVER_HELLO_DONE && !ccs).then_some(abi::TLS_ST_CR_SRVR_DONE)
}

/// The largest message allowed in the current state (`ossl_statem_client_max_message_size`).
pub(crate) fn max_message_size(c: &Connection) -> usize {
    let s = c.st.hand_state;
    let is = |x: abi::OSSL_HANDSHAKE_STATE| s == st(x);
    if is(abi::TLS_ST_CR_SRVR_HELLO) {
        limits::SERVER_HELLO
    } else if is(abi::TLS_ST_CR_CERT) || is(abi::TLS_ST_CR_COMP_CERT) || is(abi::TLS_ST_CR_CERT_REQ)
    {
        c.cfg.max_cert_list
    } else if is(abi::TLS_ST_CR_CERT_VRFY) {
        limits::CERTIFICATE_VERIFY
    } else if is(abi::TLS_ST_CR_CERT_STATUS) {
        limits::CERT_STATUS
    } else if is(abi::TLS_ST_CR_KEY_EXCH) {
        limits::SERVER_KEY_EXCH
    } else if is(abi::TLS_ST_CR_SRVR_DONE) {
        limits::SERVER_HELLO_DONE
    } else if is(abi::TLS_ST_CR_CHANGE) {
        limits::CCS
    } else if is(abi::TLS_ST_CR_SESSION_TICKET) {
        if c.is_tls13() {
            limits::SESSION_TICKET_13
        } else {
            limits::SESSION_TICKET_12
        }
    } else if is(abi::TLS_ST_CR_FINISHED) {
        limits::FINISHED
    } else if is(abi::TLS_ST_CR_ENCRYPTED_EXTENSIONS) {
        limits::ENCRYPTED_EXTENSIONS
    } else if is(abi::TLS_ST_CR_KEY_UPDATE) {
        limits::KEY_UPDATE
    } else {
        0
    }
}

/// Processes a message's body (`ossl_statem_client_process_message`).
///
/// # Errors
/// OpenSSL's alert and reason for the message.
pub(crate) fn process_message(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
) -> Result<MsgProcess> {
    let s = c.st.hand_state;
    let is = |x: abi::OSSL_HANDSHAKE_STATE| s == st(x);
    if is(abi::TLS_ST_CR_SRVR_HELLO) {
        hello::process_server_hello(c, p, body)
    } else if is(abi::TLS_ST_CR_CERT) {
        flight::process_server_certificate(c, p, body)
    } else if is(abi::TLS_ST_CR_CERT_VRFY) {
        common::cert::process_cert_verify(c, p, body)
    } else if is(abi::TLS_ST_CR_CERT_STATUS) {
        flight::process_cert_status(c, body)
    } else if is(abi::TLS_ST_CR_KEY_EXCH) {
        flight::process_key_exchange(c, p, body)
    } else if is(abi::TLS_ST_CR_CERT_REQ) {
        flight::process_certificate_request(c, p, body)
    } else if is(abi::TLS_ST_CR_SRVR_DONE) {
        flight::process_server_done(c, p, body)
    } else if is(abi::TLS_ST_CR_CHANGE) {
        if c.hs.transcript.alg().is_none() {
            // The server's Finished (resumption) is hashed with the suite's hash.
            digest_cached_records(c, p, false)?;
        }
        if c.neg.cipher.is_none() || c.neg.reused {
            c.neg.cipher = c.hs.new_cipher;
        }
        finished::process_change_cipher_spec(c, p, body)
    } else if is(abi::TLS_ST_CR_SESSION_TICKET) {
        flight::process_new_session_ticket(c, p, body)
    } else if is(abi::TLS_ST_CR_FINISHED) {
        if c.is_tls13() && !flight::initial_flight_answers(c, p, body)? {
            return Ok(MsgProcess::Ask);
        }
        finished::process_finished(c, p, body)
    } else if is(abi::TLS_ST_CR_HELLO_REQ) {
        flight::process_hello_req(c, p, body)
    } else if is(abi::TLS_ST_CR_ENCRYPTED_EXTENSIONS) {
        hello::process_encrypted_extensions(c, p, body)
    } else if is(abi::TLS_ST_CR_KEY_UPDATE) {
        finished::process_key_update(c, p, body)
    } else {
        Err(Error::internal())
    }
}

/// The work after processing a message (`ossl_statem_client_post_process_message`). OpenSSL's
/// `WORK_FINISHED_STOP` from preparing a post-handshake certificate swaps to writing, as
/// OpenSSL's reading sub-machine treats it.
///
/// # Errors
/// OpenSSL's alert and reason.
pub(crate) fn post_process_message(
    c: &mut Connection,
    p: &dyn Provider,
    wst: Work,
) -> Result<Work> {
    if at(c, abi::TLS_ST_CR_CERT) {
        return flight::post_process_server_certificate(c, p, wst);
    }
    if at(c, abi::TLS_ST_CR_CERT_VRFY) || at(c, abi::TLS_ST_CR_CERT_REQ) {
        let w = send::prepare_client_certificate(c, p, wst)?;
        return Ok(if w == Work::FinishedStop {
            Work::FinishedSwap
        } else {
            w
        });
    }
    Err(Error::internal())
}

/// The TLS 1.3 write transitions (`ossl_statem_client13_write_transition`).
fn write_transition13(c: &mut Connection) -> Result<WriteTran> {
    let s = c.st.hand_state;
    let is = |x: abi::OSSL_HANDSHAKE_STATE| s == st(x);
    let cert_req = c.hs.sh.cert_req;
    let to = if is(abi::TLS_ST_CR_CERT_REQ) {
        if c.hs.sh.pha == Pha::Requested {
            abi::TLS_ST_CW_CERT
        } else if c.shutdown & super::SENT_SHUTDOWN != 0 {
            abi::TLS_ST_OK
        } else {
            return Err(Error::internal());
        }
    } else if is(abi::TLS_ST_CR_FINISHED) {
        let eds = c.hs.sh.early_data_state;
        if eds == EarlyDataState::WriteRetry || eds == EarlyDataState::FinishedWriting {
            abi::TLS_ST_PENDING_EARLY_DATA_END
        } else if middlebox(c) && c.hs.sh.hrr == Hrr::None {
            abi::TLS_ST_CW_CHANGE
        } else if cert_req == 0 {
            abi::TLS_ST_CW_FINISHED
        } else {
            abi::TLS_ST_CW_CERT
        }
    } else if is(abi::TLS_ST_PENDING_EARLY_DATA_END)
        && c.neg.early_data_status == abi::SSL_EARLY_DATA_ACCEPTED
        && !c.cfg.quic
    {
        abi::TLS_ST_CW_END_OF_EARLY_DATA
    } else if is(abi::TLS_ST_PENDING_EARLY_DATA_END)
        || is(abi::TLS_ST_CW_END_OF_EARLY_DATA)
        || is(abi::TLS_ST_CW_CHANGE)
    {
        if cert_req == 0 {
            abi::TLS_ST_CW_FINISHED
        } else {
            abi::TLS_ST_CW_CERT
        }
    } else if is(abi::TLS_ST_CW_CERT) {
        if cert_req == 1 {
            abi::TLS_ST_CW_CERT_VRFY
        } else {
            abi::TLS_ST_CW_FINISHED
        }
    } else if is(abi::TLS_ST_CW_CERT_VRFY) {
        abi::TLS_ST_CW_FINISHED
    } else if is(abi::TLS_ST_CR_KEY_UPDATE)
        || is(abi::TLS_ST_CW_KEY_UPDATE)
        || is(abi::TLS_ST_CR_SESSION_TICKET)
        || is(abi::TLS_ST_CW_FINISHED)
    {
        abi::TLS_ST_OK
    } else if is(abi::TLS_ST_OK) {
        if c.hs.sh.key_update != abi::SSL_KEY_UPDATE_NONE {
            abi::TLS_ST_CW_KEY_UPDATE
        } else {
            return Ok(WriteTran::Finished);
        }
    } else {
        return Err(Error::internal());
    };
    go(c, to);
    Ok(WriteTran::Continue)
}

/// The write transition (`ossl_statem_client_write_transition`).
///
/// # Errors
/// No transition from the current state (an internal error).
pub(crate) fn write_transition(c: &mut Connection) -> Result<WriteTran> {
    if c.is_tls13() {
        return write_transition13(c);
    }
    let s = c.st.hand_state;
    let is = |x: abi::OSSL_HANDSHAKE_STATE| s == st(x);
    let eds = c.hs.sh.early_data_state;
    let to = if is(abi::TLS_ST_OK) && !c.renegotiate {
        return Ok(WriteTran::Finished);
    } else if is(abi::TLS_ST_OK) || is(abi::TLS_ST_BEFORE) {
        abi::TLS_ST_CW_CLNT_HELLO
    } else if is(abi::TLS_ST_CW_CLNT_HELLO) {
        if eds == EarlyDataState::Connecting && !c.cfg.quic {
            if middlebox(c) {
                abi::TLS_ST_CW_CHANGE
            } else {
                abi::TLS_ST_EARLY_DATA
            }
        } else {
            return Ok(WriteTran::Finished);
        }
    } else if is(abi::TLS_ST_CR_SRVR_HELLO) {
        // Only after a HelloRetryRequest.
        if middlebox(c) && eds != EarlyDataState::FinishedWriting {
            abi::TLS_ST_CW_CHANGE
        } else {
            abi::TLS_ST_CW_CLNT_HELLO
        }
    } else if is(abi::TLS_ST_EARLY_DATA) {
        return Ok(WriteTran::Finished);
    } else if is(abi::TLS_ST_CR_SRVR_DONE) {
        if c.hs.sh.cert_req != 0 {
            abi::TLS_ST_CW_CERT
        } else {
            abi::TLS_ST_CW_KEY_EXCH
        }
    } else if is(abi::TLS_ST_CW_CERT) {
        abi::TLS_ST_CW_KEY_EXCH
    } else if is(abi::TLS_ST_CW_KEY_EXCH) {
        if c.hs.sh.cert_req == 1 && c.hs.sh.flags & abi::TLS1_FLAGS_SKIP_CERT_VERIFY == 0 {
            abi::TLS_ST_CW_CERT_VRFY
        } else {
            abi::TLS_ST_CW_CHANGE
        }
    } else if is(abi::TLS_ST_CW_CERT_VRFY) {
        abi::TLS_ST_CW_CHANGE
    } else if is(abi::TLS_ST_CW_CHANGE) {
        if c.hs.sh.hrr == Hrr::Pending {
            abi::TLS_ST_CW_CLNT_HELLO
        } else if eds == EarlyDataState::Connecting {
            abi::TLS_ST_EARLY_DATA
        } else if c.hs.sh.npn_seen {
            abi::TLS_ST_CW_NEXT_PROTO
        } else {
            abi::TLS_ST_CW_FINISHED
        }
    } else if is(abi::TLS_ST_CW_NEXT_PROTO) {
        abi::TLS_ST_CW_FINISHED
    } else if is(abi::TLS_ST_CW_FINISHED) {
        if c.neg.reused {
            abi::TLS_ST_OK
        } else {
            return Ok(WriteTran::Finished);
        }
    } else if is(abi::TLS_ST_CR_FINISHED) {
        if c.neg.reused {
            abi::TLS_ST_CW_CHANGE
        } else {
            abi::TLS_ST_OK
        }
    } else if is(abi::TLS_ST_CR_HELLO_REQ) {
        // `ssl3_renegotiate_check`: a renegotiation the HelloRequest asked for starts now
        // (its set-up runs before the ClientHello, in pre-work).
        if c.renegotiate {
            state(c)?.needs_setup = true;
            abi::TLS_ST_CW_CLNT_HELLO
        } else {
            abi::TLS_ST_OK
        }
    } else {
        return Err(Error::internal());
    };
    go(c, to);
    Ok(WriteTran::Continue)
}

/// The work before constructing a message (`ossl_statem_client_pre_work`).
///
/// # Errors
/// A renegotiation's set-up failed.
pub(crate) fn pre_work(c: &mut Connection, p: &dyn Provider, wst: Work) -> Result<Work> {
    let s = c.st.hand_state;
    let is = |x: abi::OSSL_HANDSHAKE_STATE| s == st(x);
    if is(abi::TLS_ST_CW_CLNT_HELLO) {
        if state(c)?.needs_setup {
            common::setup_handshake(c, p)?;
        }
        c.shutdown = 0;
        if c.neg.early_data_status == abi::SSL_EARLY_DATA_REJECTED {
            // A second ClientHello after early data was refused goes out in plaintext.
            c.rw.set_protection(
                crate::record::Mode::Plain(None),
                crate::record::Protection::Null,
            );
        }
    } else if is(abi::TLS_ST_PENDING_EARLY_DATA_END) {
        let eds = c.hs.sh.early_data_state;
        if eds == EarlyDataState::FinishedWriting || eds == EarlyDataState::None {
            return Ok(Work::FinishedContinue);
        }
        return finished::finish_handshake(c, wst, false, true);
    } else if is(abi::TLS_ST_EARLY_DATA) {
        return finished::finish_handshake(c, wst, false, true);
    } else if is(abi::TLS_ST_OK) {
        return finished::finish_handshake(c, wst, true, true);
    }
    Ok(Work::FinishedContinue)
}

/// The work after sending a message (`ossl_statem_client_post_work`); a flush point waits
/// until the output is taken.
///
/// # Errors
/// A key change failed.
pub(crate) fn post_work(c: &mut Connection, p: &dyn Provider, _wst: Work) -> Result<Work> {
    let s = c.st.hand_state;
    let is = |x: abi::OSSL_HANDSHAKE_STATE| s == st(x);
    if is(abi::TLS_ST_CW_CLNT_HELLO) {
        let st = state(c)?;
        st.hello_ready = false;
        st.ext_memo.clear();
        st.binders.clear();
        let max_early = state(c)?.max_early_data;
        if c.hs.sh.early_data_state == EarlyDataState::Connecting && max_early > 0 {
            if !middlebox(c) {
                install_early_keys(c, p)?;
            }
        } else if !c.flushed() {
            return Ok(Work::MoreA);
        }
    } else if is(abi::TLS_ST_CW_KEY_EXCH) {
        send::key_exchange_post_work(c, p)?;
    } else if is(abi::TLS_ST_CW_CHANGE) {
        if c.is_tls13() || c.hs.sh.hrr == Hrr::Pending {
            return Ok(Work::FinishedContinue);
        }
        let max_early = state(c)?.max_early_data;
        if c.hs.sh.early_data_state == EarlyDataState::Connecting && max_early > 0 {
            install_early_keys(c, p)?;
            return Ok(Work::FinishedContinue);
        }
        c.neg.cipher = c.hs.new_cipher;
        if let Some(cp) = c.hs.new_cipher {
            c.neg.session.cipher_id = cp.id;
        }
        keys::setup_key_block(c, p)?;
        keys::change_cipher_state12(c, p, abi::SSL3_CHANGE_CIPHER_CLIENT_WRITE)?;
    } else if is(abi::TLS_ST_CW_FINISHED) {
        if !c.flushed() {
            return Ok(Work::MoreB);
        }
        if c.is_tls13() {
            finished::save_handshake_digest_for_pha(c);
            if c.hs.sh.pha != Pha::Requested {
                keys::change_cipher_state13(
                    c,
                    p,
                    abi::SSL3_CC_APPLICATION | abi::SSL3_CHANGE_CIPHER_CLIENT_WRITE,
                    None,
                )?;
                if c.cfg.quic {
                    keys::change_cipher_state13(
                        c,
                        p,
                        abi::SSL3_CC_APPLICATION | abi::SSL3_CHANGE_CIPHER_CLIENT_READ,
                        None,
                    )?;
                }
            }
        }
    } else if is(abi::TLS_ST_CW_KEY_UPDATE) {
        if !c.flushed() {
            return Ok(Work::MoreA);
        }
        keys::update_key(c, p, true)?;
    }
    Ok(Work::FinishedContinue)
}

/// Installs the early data write keys (`tls13_change_cipher_state` with `SSL3_CC_EARLY`).
fn install_early_keys(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    let cp = state(c)?.early_cipher;
    keys::change_cipher_state13(
        c,
        p,
        abi::SSL3_CC_EARLY | abi::SSL3_CHANGE_CIPHER_CLIENT_WRITE,
        cp,
    )
}

/// Constructs the message for the current state: its type and body
/// (`ossl_statem_client_construct_message` and the construction functions).
///
/// # Errors
/// OpenSSL's alert and reason; an unknown state is `SSL_R_BAD_HANDSHAKE_STATE`.
pub(crate) fn construct_message(c: &mut Connection, p: &dyn Provider) -> Result<(u8, Construct)> {
    let s = c.st.hand_state;
    let is = |x: abi::OSSL_HANDSHAKE_STATE| s == st(x);
    if is(abi::TLS_ST_CW_CHANGE) {
        return Ok((
            msgs_type(abi::SSL3_MT_CHANGE_CIPHER_SPEC),
            Construct::Send(Vec::new()),
        ));
    }
    if is(abi::TLS_ST_CW_CLNT_HELLO) {
        return Ok((hm::CLIENT_HELLO, hello::construct_client_hello(c, p)?));
    }
    if is(abi::TLS_ST_CW_END_OF_EARLY_DATA) {
        let eds = c.hs.sh.early_data_state;
        if eds != EarlyDataState::WriteRetry && eds != EarlyDataState::FinishedWriting {
            return Err(Error::alert_lib(
                abi::SSL_AD_INTERNAL_ERROR,
                abi::ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,
            ));
        }
        c.hs.sh.early_data_state = EarlyDataState::FinishedWriting;
        return Ok((hm::END_OF_EARLY_DATA, Construct::Send(Vec::new())));
    }
    if is(abi::TLS_ST_PENDING_EARLY_DATA_END) {
        return Ok((0, Construct::Dummy));
    }
    if is(abi::TLS_ST_CW_CERT) {
        return Ok((hm::CERTIFICATE, send::construct_client_certificate(c, p)?));
    }
    if is(abi::TLS_ST_CW_KEY_EXCH) {
        return Ok((
            hm::CLIENT_KEY_EXCHANGE,
            send::construct_client_key_exchange(c, p)?,
        ));
    }
    if is(abi::TLS_ST_CW_CERT_VRFY) {
        let body = common::cert::construct_cert_verify(c, p)?;
        return Ok((hm::CERTIFICATE_VERIFY, Construct::Send(body)));
    }
    if is(abi::TLS_ST_CW_NEXT_PROTO) {
        let npn = c.neg.npn.clone().unwrap_or_default();
        let body = crate::msgs::misc::NextProtocol::build(&npn)?.encode()?;
        return Ok((hm::NEXT_PROTO, Construct::Send(body)));
    }
    if is(abi::TLS_ST_CW_FINISHED) {
        if !c.is_tls13() {
            digest_cached_records(c, p, false)?;
        }
        let body = finished::construct_finished(c, p)?;
        return Ok((hm::FINISHED, Construct::Send(body)));
    }
    if is(abi::TLS_ST_CW_KEY_UPDATE) {
        let body = finished::construct_key_update(c);
        return Ok((hm::KEY_UPDATE, Construct::Send(body)));
    }
    Err(Error::alert(
        abi::SSL_AD_INTERNAL_ERROR,
        abi::SSL_R_BAD_HANDSHAKE_STATE,
    ))
}

/// `tls_process_initial_server_flight`: the client's checks once the server's first flight is
/// complete (after its TLS 1.3 Finished, or TLS 1.2's ServerHelloDone): the certificate suits
/// the suite, the OCSP status callback accepts the stapled response, and CT validation passes.
/// In TLS 1.3 the answers were asked for before the Finished was processed
/// ([`flight::initial_flight_answers`]), as `tls_process_finished` can't wait.
///
/// # Errors
/// OpenSSL's alert and reason.
pub(crate) fn process_initial_server_flight(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    match flight::initial_server_flight(c, p)? {
        true => Ok(()),
        false => Err(Error::internal()),
    }
}
