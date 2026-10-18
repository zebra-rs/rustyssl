//! What the client and server state machines share (OpenSSL's `statem_lib.c`, `extensions.c`,
//! `extensions_cust.c`, `t1_lib.c`, `t1_enc.c`, `tls13_enc.c`, and parts of `ssl_lib.c`,
//! `ssl_cert.c`, and `s3_lib.c`): handshake set-up, versions, ciphers, groups, signature
//! algorithms, the security level, the extension framework, the certificate messages,
//! Finished, ChangeCipherSpec, KeyUpdate, and the key changes.
//!
//! The state they share lives in [`Shared`], the handshake's `sh` field: what OpenSSL keeps in
//! `s->s3.tmp`, `s->s3`, and `s->ext` that both roles read.

pub mod cert;
pub mod ciphers;
pub mod ext;
pub mod finished;
pub mod groups;
pub mod keys;
pub mod security;
pub mod sigalgs;
pub mod version;

use core::ffi::c_int;

use rustyssl_abi as abi;

use super::statem::{MsgFlow, ReadState, st};
use super::{Answer, Connection, Request};
use crate::crypto::{GroupInfo, HashAlg, Provider};
use crate::error::{Error, Result};
use crate::keysched::Transcript;

pub use security::SecurityHook;

/// The early-data state (`SSL_EARLY_DATA_STATE` in `ssl_local.h`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EarlyDataState {
    /// `SSL_EARLY_DATA_NONE`.
    #[default]
    None,
    /// `SSL_EARLY_DATA_CONNECT_RETRY`.
    ConnectRetry,
    /// `SSL_EARLY_DATA_CONNECTING`.
    Connecting,
    /// `SSL_EARLY_DATA_WRITE_RETRY`.
    WriteRetry,
    /// `SSL_EARLY_DATA_WRITING`.
    Writing,
    /// `SSL_EARLY_DATA_WRITE_FLUSH`.
    WriteFlush,
    /// `SSL_EARLY_DATA_UNAUTH_WRITING`.
    UnauthWriting,
    /// `SSL_EARLY_DATA_FINISHED_WRITING`.
    FinishedWriting,
    /// `SSL_EARLY_DATA_ACCEPT_RETRY`.
    AcceptRetry,
    /// `SSL_EARLY_DATA_ACCEPTING`.
    Accepting,
    /// `SSL_EARLY_DATA_READ_RETRY`.
    ReadRetry,
    /// `SSL_EARLY_DATA_READING`.
    Reading,
    /// `SSL_EARLY_DATA_FINISHED_READING`.
    FinishedReading,
}

/// TLS 1.3 post-handshake authentication's state (`SSL_PHA_STATE` in `ssl_local.h`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Pha {
    /// `SSL_PHA_NONE`.
    #[default]
    None,
    /// `SSL_PHA_EXT_SENT`: the client offered it.
    ExtSent,
    /// `SSL_PHA_EXT_RECEIVED`: the server saw the offer.
    ExtReceived,
    /// `SSL_PHA_REQUEST_PENDING`: the server will send a CertificateRequest.
    RequestPending,
    /// `SSL_PHA_REQUESTED`: a CertificateRequest was sent or received.
    Requested,
}

/// Whether a HelloRetryRequest happened (`s->hello_retry_request`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Hrr {
    /// `SSL_HRR_NONE`.
    #[default]
    None,
    /// `SSL_HRR_PENDING`: one is being sent or processed.
    Pending,
    /// `SSL_HRR_COMPLETE`: the second ClientHello has been handled.
    Complete,
}

/// `TLSEXT_KEX_MODE_FLAG_NONE` (`ssl_local.h`): the PSK key exchange modes the client allows.
pub const KEX_MODE_FLAG_NONE: u8 = 0;
/// `TLSEXT_KEX_MODE_FLAG_KE`: psk_ke.
pub const KEX_MODE_FLAG_KE: u8 = 1;
/// `TLSEXT_KEX_MODE_FLAG_KE_DHE`: psk_dhe_ke.
pub const KEX_MODE_FLAG_KE_DHE: u8 = 2;

/// `TLSEXT_STATUSTYPE_nothing` (`ssl_local.h`): no status request.
pub const STATUSTYPE_NOTHING: c_int = -1;

/// `OSSL_CERT_TYPE_CTOS_NONE` (`ssl_local.h`): the client's cert-type extension not seen.
pub const CERT_TYPE_CTOS_NONE: u8 = 0;
/// `OSSL_CERT_TYPE_CTOS_GOOD`: seen, and a type in common.
pub const CERT_TYPE_CTOS_GOOD: u8 = 1;
/// `OSSL_CERT_TYPE_CTOS_ERROR`: seen, and no type in common.
pub const CERT_TYPE_CTOS_ERROR: u8 = 2;

/// The state the client and server share across a handshake.
#[derive(Default)]
#[expect(clippy::struct_excessive_bools, reason = "one flag per OpenSSL field")]
pub struct Shared {
    /// The groups the providers implement (`ctx->group_list`), loaded at set-up.
    pub groups: Vec<GroupInfo>,
    /// The signature algorithms (`ctx->sigalg_lookup_cache`), loaded at set-up.
    pub sigalgs: sigalgs::Cache,
    /// The key schedule.
    pub keys: keys::State,
    /// The client's legacy_version (`s->client_version`): what a server received, or what a
    /// client sent.
    pub client_version: u16,
    /// The versions a client offers (`s->s3.tmp.min_ver`, `max_ver`; 0 before
    /// [`ciphers::set_client_disabled`]).
    pub min_ver: u16,
    /// See `min_ver`.
    pub max_ver: u16,
    /// The key exchange and authentication this end can't use (client,
    /// `s->s3.tmp.mask_k`/`mask_a` from `ssl_set_client_disabled`), or can (server, from
    /// `ssl_set_masks`).
    pub mask_k: u32,
    /// See `mask_k`.
    pub mask_a: u32,
    /// The certificate slots' validity flags (`s->s3.tmp.valid_flags`, `CERT_PKEY_*`).
    pub valid_flags: Vec<u32>,
    /// The peer's signature_algorithms (`peer_sigalgs`), if received.
    pub peer_sigalgs: Option<Vec<u16>>,
    /// The peer's signature_algorithms_cert (`peer_cert_sigalgs`), if received.
    pub peer_cert_sigalgs: Option<Vec<u16>>,
    /// The scheme the peer signs with (`s->s3.tmp.peer_sigalg`).
    pub peer_sigalg: Option<u16>,
    /// The scheme this end signs with (`s->s3.tmp.sigalg`).
    pub sigalg: Option<u16>,
    /// The certificate this end uses (`s->s3.tmp.cert`), an index into the configuration's
    /// `certs`.
    pub cert: Option<usize>,
    /// Whether the client looks like Safari (`s->s3.is_probably_safari`, server).
    pub is_probably_safari: bool,
    /// The client's certificate request state (`s->s3.tmp.cert_req`): 0 none, 1 requested
    /// (and a certificate will be sent), 2 requested with none to send.
    pub cert_req: u8,
    /// Whether the server requests a certificate (`s->s3.tmp.cert_request`).
    pub cert_request: bool,
    /// The early data state (`s->early_data_state`).
    pub early_data_state: EarlyDataState,
    /// Whether early data may be used (`s->ext.early_data_ok`).
    pub early_data_ok: bool,
    /// A KeyUpdate to send (`s->key_update`: `SSL_KEY_UPDATE_*`).
    pub key_update: c_int,
    /// Post-handshake authentication (`s->post_handshake_auth`).
    pub pha: Pha,
    /// The transcript at the client's Finished (`s->pha_dgst`).
    pub pha_transcript: Option<Transcript>,
    /// The certificate_request_context of a post-handshake CertificateRequest
    /// (`s->pha_context`).
    pub pha_context: Option<Vec<u8>>,
    /// Whether a new session is being made (`s->new_session`).
    pub new_session: bool,
    /// Whether the server will send a TLS 1.2 NewSessionTicket (`s->ext.ticket_expected`).
    pub ticket_expected: bool,
    /// A HelloRetryRequest's state.
    pub hrr: Hrr,
    /// `s->s3.flags` (`TLS1_FLAGS_*`).
    pub flags: c_int,
    /// The extensions sent and received (`s->ext.extflags`, the custom extensions' flags).
    pub ext: ext::Flags,
    /// The extension blocks of the message being processed (`RAW_EXTENSION` arrays), kept
    /// while it is processed so that a parse resumed after a request isn't repeated.
    pub received: Vec<ext::Received>,
    /// Answers already given while making or processing the current message, so that work
    /// re-run after a later request doesn't ask again ([`ask_once`]).
    pub answers: Vec<(Request, usize, Answer)>,
    /// The client's PSK key exchange modes (`s->ext.psk_kex_mode`, `KEX_MODE_FLAG_*`).
    pub psk_kex_mode: u8,
    /// Whether the server acknowledged the name (`s->servername_done`).
    pub servername_done: bool,
    /// Whether the servername callback turned tickets off, so a server that isn't resuming
    /// must make a new session ID (`ssl_generate_session_id` in `final_server_name`).
    pub regenerate_session_id: bool,
    /// Whether tickets were on before the servername callback ran (`final_server_name`'s
    /// `was_ticket`), kept while the callback is pending.
    pub was_ticket: Option<bool>,
    /// Whether encrypt-then-MAC was negotiated (`s->ext.use_etm`).
    pub use_etm: bool,
    /// The status request received (`s->ext.status_type`: `TLSEXT_STATUSTYPE_ocsp`, or
    /// [`STATUSTYPE_NOTHING`]).
    pub status_type: c_int,
    /// Whether NPN was seen (`s->s3.npn_seen`).
    pub npn_seen: bool,
    /// The client's ALPN list (`s->s3.alpn_proposed`, server), wire format.
    pub alpn_proposed: Option<Vec<u8>>,
    /// The SRP login (`s->srp_ctx.login`, server).
    pub srp_login: Option<Vec<u8>>,
    /// The peer's ec_point_formats (`s->ext.peer_ecpointformats`).
    pub peer_ecpointformats: Option<Vec<u8>>,
    /// The SRTP profile chosen (`s->srtp_profile`).
    pub srtp_profile: Option<u16>,
    /// The certificate compression algorithms the peer accepts (`compress_certificate_from_peer`).
    pub compress_certificate_from_peer: Vec<u16>,
    /// What the client's client_certificate_type and server_certificate_type said
    /// (`s->ext.client_cert_type_ctos`, `server_cert_type_ctos`; `CERT_TYPE_CTOS_*`).
    pub client_cert_type_ctos: u8,
    /// See `client_cert_type_ctos`.
    pub server_cert_type_ctos: u8,
    /// The client's key share the server will use (`s->s3.peer_tmp`): its group and octets.
    pub peer_tmp: Option<(u16, Vec<u8>)>,
    /// This end's TLS 1.3 key share, kept after the handshake as OpenSSL keeps
    /// `s->s3.tmp.pkey` (`SSL_get_tmp_key`): its group and public octets. A server answering
    /// a KEM has none; TLS 1.2 frees its ephemeral key once used, so there is none either.
    pub own_tmp: Option<(u16, Vec<u8>)>,
    /// A TLS 1.2 DHE server's key (`s->s3.peer_tmp`, for `SSL_get_peer_tmp_key`): the prime,
    /// the generator, and its public value, big-endian.
    pub peer_dh: Option<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    /// The group negotiated, or asked for in a HelloRetryRequest (`s->s3.group_id`).
    pub group_id: u16,
    /// A group the server could ask for in a HelloRetryRequest (`s->s3.group_id_candidate`).
    pub group_id_candidate: u16,
    /// Whether a stateless server's cookie checked out (`s->ext.cookieok`).
    pub cookie_ok: bool,
    /// The transcript hash before the peer's CertificateVerify (`s->cert_verify_hash`).
    pub cert_verify_hash: Vec<u8>,
    /// The server's downgrade protection to apply to its random (TLS 1.3 servers).
    pub downgrade: Option<version::Downgrade>,
}

impl core::fmt::Debug for Shared {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Shared")
            .field("client_version", &self.client_version)
            .field("hrr", &self.hrr)
            .field("pha", &self.pha)
            .finish_non_exhaustive()
    }
}

/// Asks `r` once per message: an answer already given for `r` (with `tag`, such as a
/// certificate's index in its chain) while making or processing the current message is
/// returned again, so work re-run after a later request doesn't repeat earlier ones. The
/// state machine forgets the answers when a message is finished.
pub(crate) fn ask_once(c: &mut Connection, r: Request, tag: usize) -> Option<Answer> {
    if let Some((_, _, a)) =
        c.hs.sh
            .answers
            .iter()
            .find(|(q, t, _)| *q == r && *t == tag)
    {
        return Some(a.clone());
    }
    let a = c.ask(r.clone())?;
    c.hs.sh.answers.push((r, tag, a.clone()));
    Some(a)
}

/// Sets up a handshake (`tls_setup_handshake`): a fresh transcript and extension flags, the
/// providers' groups and signature algorithms, a version to use (and MD5+SHA-1 for TLS 1.1 and
/// earlier), a server's ciphers for its highest version, then the role's set-up.
///
/// # Errors
/// `SSL_R_NO_PROTOCOLS_AVAILABLE` (protocol-version), `SSL_R_NO_SUITABLE_DIGEST_ALGORITHM` or
/// `SSL_R_NO_CIPHERS_AVAILABLE` (handshake-failure), or the role's.
pub(crate) fn setup_handshake(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    c.hs.transcript = Transcript::new();
    c.hs.sh.ext = ext::Flags::new(c.cfg.custom_exts.len());
    if c.hs.sh.groups.is_empty() {
        c.hs.sh.groups = p.groups();
    }
    if c.hs.sh.sigalgs.table.is_empty() {
        c.hs.sh.sigalgs = sigalgs::Cache::new(p);
    }
    let (min, max, _) = version::min_max(c).map_err(|_| {
        Error::alert(
            abi::SSL_AD_PROTOCOL_VERSION,
            abi::SSL_R_NO_PROTOCOLS_AVAILABLE,
        )
    })?;
    if p.hash(HashAlg::Md5Sha1).is_err() {
        if version::cmp(max, version::of(abi::TLS1_1_VERSION)).is_le() {
            return Err(Error::alert(
                abi::SSL_AD_HANDSHAKE_FAILURE,
                abi::SSL_R_NO_SUITABLE_DIGEST_ALGORITHM,
            )
            .with_data(
                "The max supported SSL/TLS version needs the MD5-SHA1 digest but it is not \
                         available in the loaded providers. Use (D)TLSv1.2 or above, or load \
                         different providers",
            ));
        }
        let tls12 = version::of(abi::TLS1_2_VERSION);
        if version::cmp(min, tls12).is_lt() {
            c.cfg.min_version = tls12;
        }
    }
    if c.cfg.server {
        let max_i = c_int::from(max);
        let ok = c
            .cfg
            .ciphers
            .iter()
            .any(|cp| max_i >= cp.min_tls && (cp.max_tls == 0 || max_i <= cp.max_tls));
        if !ok {
            return Err(Error::alert(
                abi::SSL_AD_HANDSHAKE_FAILURE,
                abi::SSL_R_NO_CIPHERS_AVAILABLE,
            )
            .with_data("No ciphers enabled for max supported SSL/TLS version"));
        }
        if !finished::is_first_handshake(c) {
            c.hs.sh.cert_request = false;
        }
        super::server::setup(c, p)
    } else {
        c.hs.client_random = [0; 32];
        c.neg.reused = false;
        c.hs.sh.cert_req = 0;
        super::client::setup(c, p)
    }
}

/// Takes the Finished MAC the peer must send (`ssl3_take_mac`).
///
/// # Errors
/// The MAC couldn't be computed.
pub(crate) fn take_mac(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    finished::take_mac(c, p)
}

/// Goes back into the state machine to read a handshake message after the handshake
/// (renegotiation, or TLS 1.3's NewSessionTicket, KeyUpdate, and CertificateRequest).
///
/// Before TLS 1.3, as `ossl_statem_set_in_init` before `handshake_func`: the state machine
/// starts again from `MSG_FLOW_FINISHED` (the start notification, a write transition with
/// nothing to write, then the read), so a renegotiation is set up and traced as OpenSSL's is
/// (fork M). TLS 1.3's post-handshake messages go straight to the read.
pub(crate) fn enter_post_handshake(c: &mut Connection) {
    c.st.in_init = true;
    if c.is_tls13() {
        c.st.state = MsgFlow::Reading;
    } else if c.st.state != MsgFlow::Uninited {
        c.st.state = MsgFlow::Finished;
    }
    c.st.read_state = ReadState::Header;
    c.st.loop_reported = false;
    c.st.header_done = false;
    if c.st.hand_state == st(abi::TLS_ST_BEFORE) {
        c.st.hand_state = st(abi::TLS_ST_OK);
    }
}

#[cfg(test)]
mod tests;
