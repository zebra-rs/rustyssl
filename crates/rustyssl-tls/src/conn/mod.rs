//! A TLS connection (ADR 0002): the handshake state machine over the record layer, application
//! data, alerts, and shutdown, yielding at every observable event.
//!
//! `rustyssl-capi` drives it: [`Connection::feed`] network input, [`Connection::step`] until an
//! event, act on the event (call the application with no lock held, answer a request, send the
//! output), and repeat.

pub mod config;
pub mod event;
pub mod statem;

pub(crate) mod client;
/// What the client and server share (`statem_lib.c`, `t1_lib.c`, ...): public for
/// `rustyssl-capi`'s configuration functions (the group and signature algorithm tables, the
/// security framework).
pub mod common;
pub(crate) mod funcs;
#[cfg(test)]
pub(crate) mod pair;
mod requests;
pub(crate) mod server;

use std::collections::VecDeque;

use rustyssl_abi as abi;

pub use config::{CertKey, Config, ExternalPsk, Session, TicketKeys};
pub use event::{Answer, Callbacks, Event, Request, SrpParams};

use self::statem::{HsBytes, MsgFlow, Statem, msgs_type, st};
use crate::crypto::Provider;
use crate::error::{Error, InFunc, Result};
use crate::keysched::Transcript;
use crate::record::{self, Read, RecordReader, RecordWriter};
use crate::suites::Cipher;

/// `SSL_SENT_SHUTDOWN`.
pub const SENT_SHUTDOWN: u32 = 1;
/// `SSL_RECEIVED_SHUTDOWN`.
pub const RECEIVED_SHUTDOWN: u32 = 2;

/// OpenSSL's limit on consecutive warning alerts (`MAX_WARN_ALERT_COUNT`, ssl/record).
const MAX_WARN_ALERT_COUNT: u32 = 5;

/// The per-handshake state (OpenSSL's `s->s3.tmp` and the handshake parts of `s->s3`, `s->ext`).
/// The client and server state machines add what they need.
#[derive(Default)]
pub struct Handshake {
    /// The transcript.
    pub transcript: Transcript,
    /// The client's random.
    pub client_random: [u8; 32],
    /// The server's random.
    pub server_random: [u8; 32],
    /// The cipher being negotiated (`s->s3.tmp.new_cipher`).
    pub new_cipher: Option<&'static Cipher>,
    /// The Finished MAC expected from the peer (`s->s3.tmp.peer_finish_md`).
    pub peer_finish_md: Vec<u8>,
    /// The Finished MAC sent (`s->s3.tmp.finish_md`).
    pub finish_md: Vec<u8>,
    /// Role-specific state (the client's or server's).
    pub role: RoleState,
    /// The state both roles share.
    pub sh: common::Shared,
}

impl core::fmt::Debug for Handshake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Handshake")
            .field("new_cipher", &self.new_cipher.map(Cipher::name_str))
            .finish_non_exhaustive()
    }
}

/// The client's or the server's own handshake state.
#[derive(Default)]
pub enum RoleState {
    /// Not yet set up.
    #[default]
    None,
    /// The client's.
    Client(Box<client::State>),
    /// The server's.
    Server(Box<server::State>),
}

/// What the handshake negotiated, as the `SSL_get_*` functions report it.
#[derive(Clone, Debug, Default)]
pub struct Negotiated {
    /// The protocol version (`SSL_version`); before negotiation, the method's.
    pub version: u16,
    /// The cipher (`SSL_get_current_cipher`).
    pub cipher: Option<&'static Cipher>,
    /// The session (established or resumed).
    pub session: Session,
    /// Whether the session was resumed (`SSL_session_reused`).
    pub reused: bool,
    /// The peer's certificate chain as received (DER, leaf first).
    pub peer_chain: Vec<Vec<u8>>,
    /// The chain verification built (`SSL_get0_verified_chain`).
    pub verified_chain: Vec<Vec<u8>>,
    /// The verification result (`SSL_get_verify_result`).
    pub verify_result: i64,
    /// The ALPN protocol selected (`SSL_get0_alpn_selected`).
    pub alpn: Option<Vec<u8>>,
    /// The NPN protocol (`SSL_get0_next_proto_negotiated`).
    pub npn: Option<Vec<u8>>,
    /// The server name (`SSL_get_servername`).
    pub servername: Option<Vec<u8>>,
    /// The Finished messages' verify data (`SSL_get_finished`, `SSL_get_peer_finished`).
    pub client_finished: Vec<u8>,
    /// See `client_finished`.
    pub server_finished: Vec<u8>,
    /// The signature scheme the peer signed with (`SSL_get_peer_signature_type_nid` and
    /// friends), and the one this end signed with.
    pub peer_scheme: Option<u16>,
    /// See `peer_scheme`.
    pub own_scheme: Option<u16>,
    /// The group negotiated (`SSL_get_negotiated_group`).
    pub group: Option<u16>,
    /// Whether Extended Master Secret (TLS 1.2) and encrypt-then-MAC are in use.
    pub ems: bool,
    /// See `ems`.
    pub etm: bool,
    /// Whether the peer supports secure renegotiation (`SSL_get_secure_renegotiation_support`).
    pub secure_renegotiation: bool,
    /// The certificate this end sent (an index into the configuration's `certs`).
    pub own_cert: Option<usize>,
    /// The peer's raw public key (RFC 7250), when negotiated.
    pub peer_rpk: Option<Vec<u8>>,
    /// The negotiated certificate types (RFC 7250).
    pub client_cert_type: u8,
    /// See `client_cert_type`.
    pub server_cert_type: u8,
    /// TLS 1.3's early data status (`SSL_get_early_data_status`).
    pub early_data_status: i32,
    /// The OCSP response the server stapled (`SSL_get_tlsext_status_ocsp_resp`).
    pub ocsp_response: Option<Vec<u8>>,
    /// The SCTs received (raw extension body), for CT validation.
    pub scts: Option<Vec<u8>>,
    /// The peer's signature algorithms (`SSL_get_sigalgs`) and the shared ones.
    pub peer_sigalgs: Vec<u16>,
    /// See `peer_sigalgs`.
    pub shared_sigalgs: Vec<u16>,
    /// The peer's supported groups (`SSL_get1_groups`, server side).
    pub peer_groups: Vec<u16>,
    /// The CA names the peer sent (`SSL_get0_peer_CA_list`, `SSL_get_client_CA_list` on a
    /// client): `None` until a list arrives (NULL there), maybe an empty one.
    pub peer_ca_names: Option<Vec<Vec<u8>>>,
    /// TLS 1.2's master secret (`SSL_SESSION_get_master_key`).
    pub master_secret: Vec<u8>,
    /// The exporter secrets (TLS 1.3), for `SSL_export_keying_material(_early)`.
    pub exporter_master: Vec<u8>,
    /// See `exporter_master`.
    pub early_exporter_master: Vec<u8>,
    /// The suite the early secrets were made for (the PSK's), whose hash the early exporter
    /// uses until a suite is negotiated.
    pub early_cipher: Option<&'static Cipher>,
}

/// A ClientHello and its collected extensions (type, body) in received order
/// ([`Connection::client_hello_exts`]).
pub type ClientHelloView<'a> = (&'a crate::msgs::hello::ClientHello, Vec<(u16, &'a [u8])>);

/// TLS 1.3 early data's ciphertext allowance for a record that is skipped
/// (`EARLY_DATA_CIPHERTEXT_OVERHEAD`, `ssl_local.h`).
fn early_data_ciphertext_overhead() -> u64 {
    let tag = u64::try_from(abi::EVP_GCM_TLS_TAG_LEN).unwrap_or(0);
    tag.saturating_add(1).saturating_mul(6).saturating_add(2)
}

/// The early data accounting of a server's read keys (the record layer's).
#[derive(Clone, Copy, Debug)]
pub(crate) struct EarlyRead {
    /// Whether these are the early keys (their application data is counted as it is read).
    pub(crate) early: bool,
    /// The limit (`max_early_data`; 0: none may arrive).
    pub(crate) max: u32,
    /// What has been counted.
    pub(crate) count: u64,
}

/// `rlayer_early_data_count_ok` / `ossl_early_data_count_ok`: `length` more octets (plus
/// `overhead` for ciphertext) within `max`, counted in `count`.
fn early_data_count_ok(
    count: &mut u64,
    max: u32,
    length: usize,
    overhead: u64,
    send: bool,
) -> Result<()> {
    let alert = if send {
        abi::SSL_AD_INTERNAL_ERROR
    } else {
        abi::SSL_AD_UNEXPECTED_MESSAGE
    };
    let too_much = Error::alert(alert, abi::SSL_R_TOO_MUCH_EARLY_DATA);
    if max == 0 {
        return Err(too_much);
    }
    let limit = u64::from(max).saturating_add(overhead);
    let total = count.saturating_add(u64::try_from(length).unwrap_or(u64::MAX));
    if total > limit {
        return Err(too_much);
    }
    *count = total;
    Ok(())
}

/// A TLS connection.
pub struct Connection {
    /// The settings.
    pub(crate) cfg: Config,
    /// The state machine.
    pub(crate) st: Statem,
    /// The read side of the record layer.
    pub(crate) rr: RecordReader,
    /// The write side.
    pub(crate) rw: RecordWriter,
    /// The per-handshake state.
    pub(crate) hs: Handshake,
    /// What was negotiated.
    pub(crate) neg: Negotiated,
    /// Network input not yet read into records.
    input: Vec<u8>,
    /// How many undecryptable early data records were skipped (see
    /// [`Connection::skipped_records`]).
    skipped: u64,
    /// Network output not yet taken.
    output: Vec<u8>,
    /// Handshake octets read from records and not yet taken as messages
    /// (`s->rlayer.handshake_fragment` and the message buffer).
    pub(crate) hs_in: Vec<u8>,
    /// The message being processed (its type and body), kept while processing waits for an
    /// answer.
    pub(crate) cur_msg: Option<(u8, Vec<u8>)>,
    /// Events to report before anything else happens.
    events: VecDeque<(Event, bool)>,
    /// Whether the connection was in init when the event [`Connection::step`] last returned from
    /// the queue was raised (`None`: the last event is current).
    event_in_init: Option<bool>,
    /// The request waiting for an answer.
    pending: Option<Request>,
    /// The answer, waiting for the code that asked.
    answer: Option<Answer>,
    /// A construction that asked for an answer and runs again after it.
    pub(crate) pending_construct: bool,
    /// Application data received and not yet read.
    app_in: VecDeque<u8>,
    /// `SSL_get_shutdown`'s flags.
    pub(crate) shutdown: u32,
    /// The fatal error, once one happened.
    pub(crate) failed: Option<Error>,
    /// Whether the first handshake hasn't finished yet (`SSL_IS_FIRST_HANDSHAKE`).
    pub(crate) first_handshake: bool,
    /// Whether a renegotiation was requested.
    pub(crate) renegotiate: bool,
    /// Whether `SSL_renegotiate` asked for one that hasn't started (`s->s3.renegotiate`), and
    /// the renegotiations started since `SSL_clear_num_renegotiations` and in all
    /// (`num_renegotiations`, `total_renegotiations`). Shared addition (fork M).
    pub(crate) s3_renegotiate: bool,
    /// See `s3_renegotiate`.
    pub(crate) num_renegotiations: u32,
    /// See `s3_renegotiate`.
    pub(crate) total_renegotiations: u32,
    /// Whether the next record read is the first of the handshake (`s->first_packet`).
    pub(crate) first_packet: bool,
    /// Whether the record being read was an SSLv2-format ClientHello.
    pub(crate) sslv2_record: bool,
    /// Whether a ChangeCipherSpec was received and the Finished not yet
    /// (`s->s3.change_cipher_spec`).
    pub(crate) change_cipher_spec: bool,
    /// Consecutive warning alerts received.
    alert_count: u32,
    /// The last warning alert received (`s->s3.warn_alert`), and fatal one (`fatal_alert`).
    pub(crate) warn_alert: u8,
    /// See `warn_alert`.
    pub(crate) fatal_alert: u8,
    /// The last alert sent (level, description), for `SSL_alert_desc_string`.
    pub(crate) sent_alert: Option<(u8, u8)>,
    /// How often the handshake passed the points where OpenSSL takes its round-trip timestamps
    /// (`ts_msg_write`, `ts_msg_read`): the caller, which has the clock, notes the time when
    /// each changes ([`Connection::rtt_marks`]).
    pub(crate) rtt_write: u32,
    /// See `rtt_write`.
    pub(crate) rtt_read: u32,
    /// Whether the step failing now only interrupts the call ([`Event::Interrupted`]).
    interrupted: bool,
    /// The certificate whose TLS 1.3 Certificate entry extensions are being made or read (for
    /// the custom extension callbacks' `x`).
    pub(crate) ext_cert: Option<Vec<u8>>,
    /// The early data counted against the limit outside the record layer (`s->early_data_count`:
    /// a client's early writes, a server's skipped plaintext records after a HelloRetryRequest).
    pub(crate) early_data_count: u64,
    /// A server's early data accounting for the read keys in force (the record layer's
    /// `max_early_data` and `early_data_count`, set with the early and handshake keys).
    pub(crate) early_read: Option<EarlyRead>,
    /// Whether the record layer needs more input to make progress.
    needs_input: bool,
    /// Whether the caller wants application data (an `SSL_read` is in progress).
    reading: bool,
    /// The application's security callback, as capi runs it (`SSL_CTX_set_security_callback`;
    /// used when the configuration says a custom one is set).
    pub(crate) security_hook: Option<common::SecurityHook>,
    /// Whether a client with a flexible method hasn't learnt the version yet (shared fix, fork
    /// F): OpenSSL's method is still `TLS_ANY_VERSION` then, so `SSL_CONNECTION_IS_TLS13` is
    /// false although `s->version` (here `neg.version`) is the highest version offered. The
    /// client's state machine sets it with its first ClientHello and clears it once the
    /// ServerHello chose the version.
    pub(crate) version_pending: bool,
}

impl core::fmt::Debug for Connection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Connection")
            .field("server", &self.cfg.server)
            .field("hand_state", &self.st.hand_state)
            .field("version", &self.neg.version)
            .finish_non_exhaustive()
    }
}

impl Connection {
    /// A connection with `cfg`, before any handshake (`TLS_ST_BEFORE`).
    #[must_use]
    pub fn new(cfg: Config) -> Self {
        // Shared fix (fork M): a flexible method's connection reports TLS 1.3 until a version
        // is negotiated (`tls1_clear`: TLS_MAX_VERSION_INTERNAL), with is_tls13 false until
        // then (the method isn't switched yet); its first records carry TLS 1.0.
        let flexible = cfg.method_version == 0;
        let (version, record_version) = if flexible {
            (if cfg.server { tls1_3() } else { tls1_0() }, tls1_0())
        } else {
            (cfg.method_version, cfg.method_version)
        };
        let server = cfg.server;
        let mut rw = RecordWriter::new(record_version);
        // `ssl_get_max_send_fragment` (0: unset, the default).
        if cfg.max_send_fragment > 0 {
            rw.max_frag_len = cfg.max_send_fragment.min(rw.max_frag_len);
        }
        // `SSL_CTX_set_block_padding_ex`, for TLS 1.3's protected records.
        let (app, hs) = cfg.block_padding;
        if app > 0 || hs > 0 {
            rw.padding = record::Padding::Block(app, hs);
        }
        Self {
            cfg,
            st: Statem::default(),
            rr: RecordReader::new(server),
            rw,
            hs: Handshake {
                // `SSL_new`'s `key_update`: none pending, on either side (fork M).
                sh: common::Shared {
                    key_update: abi::SSL_KEY_UPDATE_NONE,
                    ..common::Shared::default()
                },
                ..Handshake::default()
            },
            neg: Negotiated {
                version,
                ..Negotiated::default()
            },
            input: Vec::new(),
            output: Vec::new(),
            hs_in: Vec::new(),
            cur_msg: None,
            events: VecDeque::new(),
            event_in_init: None,
            pending: None,
            answer: None,
            pending_construct: false,
            app_in: VecDeque::new(),
            shutdown: 0,
            failed: None,
            first_handshake: true,
            renegotiate: false,
            s3_renegotiate: false,
            num_renegotiations: 0,
            total_renegotiations: 0,
            first_packet: false,
            sslv2_record: false,
            change_cipher_spec: false,
            alert_count: 0,
            warn_alert: 0,
            fatal_alert: 0,
            sent_alert: None,
            rtt_write: 0,
            rtt_read: 0,
            ext_cert: None,
            interrupted: false,
            early_data_count: 0,
            early_read: None,
            skipped: 0,
            needs_input: false,
            reading: false,
            security_hook: None,
            version_pending: false,
        }
    }

    /// The settings.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// The ClientHello the server is processing (`s->clienthello`, until its processing ends)
    /// and the extensions OpenSSL collects from it (`pre_proc_exts`: the recognised ones and the
    /// custom ones, not unknown ones), in received order; for the client hello callback's
    /// getters (`SSL_client_hello_get0_*`). Shared addition (fork M).
    #[must_use]
    pub fn client_hello_exts(&self) -> Option<ClientHelloView<'_>> {
        let RoleState::Server(s) = &self.hs.role else {
            return None;
        };
        let hello = s.hello.as_ref()?;
        let mut exts: Vec<(usize, u16, &[u8])> =
            common::ext::received(self, crate::consts::context::CLIENT_HELLO, 0)
                .map(|r| {
                    r.exts
                        .iter()
                        .flatten()
                        .map(|e| (e.received_order, e.typ, e.body.as_slice()))
                        .collect()
                })
                .unwrap_or_default();
        exts.sort_by_key(|e| e.0);
        Some((hello, exts.into_iter().map(|(_, t, b)| (t, b)).collect()))
    }

    /// The settings, to update mid-handshake (after a callback changed the `SSL`).
    pub fn config_mut(&mut self) -> &mut Config {
        &mut self.cfg
    }

    /// `SSL_set_max_send_fragment` on a running connection: the records written from now on
    /// carry at most `n` octets, or the negotiated maximum fragment length if that's less.
    pub fn set_max_send_fragment(&mut self, n: usize) {
        self.cfg.max_send_fragment = n;
        let negotiated =
            crate::conn::common::ext::max_fragment_length(self.neg.session.max_fragment_len_mode);
        self.rw.max_frag_len = negotiated
            .map_or(n, |len| n.min(len))
            .clamp(1, crate::record::MAX_PLAIN);
    }

    /// Installs the application's security callback (`SSL_CTX_set_security_callback`), which
    /// the core calls in place, synchronously, wherever OpenSSL calls `ssl_security`; it is
    /// used while the configuration's `custom_security_callback` is set. The hook must not
    /// call back into this connection.
    pub fn set_security_hook(&mut self, hook: Option<common::SecurityHook>) {
        self.security_hook = hook;
    }

    /// Installs the application's record padding callback
    /// (`SSL_CTX_set_record_padding_callback`), which the record layer calls in place for
    /// each protected TLS 1.3 record. The hook must not call back into this connection.
    pub fn set_padding_hook(&mut self, hook: Option<record::PaddingHook>) {
        self.rw.pad_hook = hook;
    }

    /// What was negotiated so far.
    #[must_use]
    pub fn negotiated(&self) -> &Negotiated {
        &self.neg
    }

    /// The handshake in progress.
    #[must_use]
    pub fn handshake(&self) -> &Handshake {
        &self.hs
    }

    /// The client's cipher list as it sent it, in TLS form (a server's
    /// `s->s3.tmp.ciphers_raw`, for `SSL_get0_raw_cipherlist`); `None` on a client or before a
    /// ClientHello.
    #[must_use]
    pub fn raw_cipherlist(&self) -> Option<&[u8]> {
        match &self.hs.role {
            RoleState::Server(s) if !s.ciphers_raw.is_empty() => Some(&s.ciphers_raw),
            _ => None,
        }
    }

    /// The certificate types of the server's TLS 1.2 CertificateRequest
    /// (`SSL_get0_certificate_types`): `None` on a server or when no certificate was requested;
    /// empty in TLS 1.3, whose request carries none.
    #[must_use]
    pub fn certificate_types(&self) -> Option<&[u8]> {
        match &self.hs.role {
            RoleState::Client(s) if self.hs.sh.cert_req != 0 => Some(s.certificate_types()),
            _ => None,
        }
    }

    /// The round-trip marks: how often the handshake passed OpenSSL's `ts_msg_write` and
    /// `ts_msg_read` points (shared addition, fork O: `SSL_get_handshake_rtt`).
    #[must_use]
    pub fn rtt_marks(&self) -> (u32, u32) {
        (self.rtt_write, self.rtt_read)
    }

    /// The handshake state (`SSL_get_state`).
    #[must_use]
    pub fn state(&self) -> u32 {
        self.st.hand_state
    }

    /// Whether a handshake is in progress or not yet started (`SSL_in_init`).
    #[must_use]
    pub fn in_init(&self) -> bool {
        self.st.in_init || self.st.state == MsgFlow::Uninited
    }

    /// [`Connection::in_init`] as of the event [`Connection::step`] last returned: an event
    /// raised before the state machine moved on (`SSL_CB_HANDSHAKE_DONE` out of init, the
    /// tickets after it back in) reports the state it was raised in, as OpenSSL's callbacks see.
    #[must_use]
    pub fn event_in_init(&self) -> bool {
        self.event_in_init.unwrap_or_else(|| self.in_init())
    }

    /// Whether no handshake has started (`SSL_in_before`).
    #[must_use]
    pub fn before(&self) -> bool {
        self.st.hand_state == st(abi::TLS_ST_BEFORE) && self.st.state == MsgFlow::Uninited
    }

    /// Whether the connection failed.
    #[must_use]
    pub fn error(&self) -> Option<Error> {
        self.failed
    }

    /// `SSL_get_shutdown`'s flags.
    #[must_use]
    pub fn shutdown_state(&self) -> u32 {
        self.shutdown
    }

    /// Sets `SSL_set_shutdown`'s flags.
    pub fn set_shutdown_state(&mut self, flags: u32) {
        self.shutdown = flags;
    }

    /// The last alert sent (level, description) and the last fatal and warning alerts
    /// received.
    #[must_use]
    pub fn alerts(&self) -> (Option<(u8, u8)>, u8, u8) {
        (self.sent_alert, self.fatal_alert, self.warn_alert)
    }

    /// Whether the negotiated (or, before negotiation, the attempted) version is TLS 1.3.
    #[must_use]
    pub fn is_tls13(&self) -> bool {
        self.neg.version == tls1_3() && !self.version_pending
    }

    /// Adds network input.
    pub fn feed(&mut self, data: &[u8]) {
        self.input.extend_from_slice(data);
        self.needs_input = false;
    }

    /// How much network input is buffered (`SSL_has_pending` counts it).
    #[must_use]
    pub fn buffered_input(&self) -> usize {
        self.input.len()
    }

    /// Whether output is waiting.
    #[must_use]
    pub fn has_output(&self) -> bool {
        !self.output.is_empty()
    }

    /// Takes the network output.
    pub fn take_output(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.output)
    }

    /// The ClientHello's legacy_version (`s->client_version`): what a server received, or what a
    /// client sent (TLS 1.2's number for TLS 1.3); 0 before either.
    #[must_use]
    pub fn client_version(&self) -> u16 {
        self.hs.sh.client_version
    }

    /// Whether the record layer has a record's header and awaits its body
    /// (`SSL_rstate_string`'s "RB").
    #[must_use]
    pub fn reading_record_body(&self) -> bool {
        self.rr.reading_body()
    }

    /// Application data received and not yet read (`SSL_pending`).
    #[must_use]
    pub fn pending_app(&self) -> usize {
        self.app_in.len()
    }

    /// Copies up to `buf.len()` octets of received application data into `buf`, removing them
    /// unless `peek`; returns how many.
    pub fn read_app(&mut self, buf: &mut [u8], peek: bool) -> usize {
        let n = buf.len().min(self.app_in.len());
        for (d, s) in buf.iter_mut().zip(self.app_in.iter()) {
            *d = *s;
        }
        if !peek {
            self.app_in.drain(..n);
        }
        n
    }

    /// Answers the pending [`Request`].
    pub fn answer(&mut self, a: Answer) {
        self.answer = Some(a);
    }

    /// Starts a handshake on an idle connection (`SSL_do_handshake` after `SSL_clear`, or a
    /// renegotiation already arranged).
    pub fn start(&mut self) {
        if self.st.state == MsgFlow::Finished || self.st.state == MsgFlow::Uninited {
            self.st.in_init = true;
        }
    }

    /// Runs until the next event. `reading` says whether the caller wants application data
    /// (`SSL_read`); without it, a finished handshake yields [`Event::Idle`].
    ///
    /// # Errors
    /// The connection failed: the alert (if any) is in the output, and the error says why.
    pub fn step(&mut self, p: &dyn Provider, reading: bool) -> Result<Event> {
        self.event_in_init = None;
        if let Some(e) = self.pop_event() {
            return Ok(e);
        }
        if let Some(e) = self.failed {
            return Err(e);
        }
        if let Some(r) = &self.pending
            && self.answer.is_none()
        {
            return Ok(Event::Request(r.clone()));
        }
        self.reading = reading;
        let r = self.advance(p);
        match r {
            Ok(Some(e)) => {
                if let Some(q) = self.pop_event() {
                    let in_init = self.in_init();
                    self.events.push_back((e, in_init));
                    return Ok(q);
                }
                Ok(e)
            }
            Ok(None) => {
                if let Some(q) = self.pop_event() {
                    return Ok(q);
                }
                if self.answer.is_some() {
                    // The machine moved on without taking the answer (the callback's flag
                    // changed while it waited): the request is stale. Asking again would loop.
                    self.pending = None;
                    self.answer = None;
                } else if let Some(r) = &self.pending {
                    return Ok(Event::Request(r.clone()));
                }
                if !self.output.is_empty() {
                    return Ok(Event::Output);
                }
                Ok(Event::NeedInput)
            }
            Err(_) if self.interrupted => {
                self.interrupted = false;
                Ok(Event::Interrupted)
            }
            Err(e) => {
                self.fatal(p, e);
                match self.pop_event() {
                    Some(q) => Ok(q),
                    None => Err(e),
                }
            }
        }
    }

    /// One advance: `Some` event, or `None` to report what's queued or wait.
    fn advance(&mut self, p: &dyn Provider) -> Result<Option<Event>> {
        if self.hs.sh.early_data_state == common::EarlyDataState::UnauthWriting {
            // A server writing to an unauthenticated client between its Finished and the
            // client's doesn't run the handshake (`ssl3_write_bytes`).
            if !self.output.is_empty() {
                return Ok(Some(Event::Output));
            }
            return Ok(Some(Event::Idle));
        }
        if self.in_init() {
            if self.state_machine(p)? {
                self.st.in_init = false;
                // A stop for early data isn't the handshake's end (`SSL_IS_FIRST_HANDSHAKE`
                // goes by the Finished messages).
                let early_stop = self.st.hand_state == st(abi::TLS_ST_EARLY_DATA)
                    || self.st.hand_state == st(abi::TLS_ST_PENDING_EARLY_DATA_END);
                if !early_stop {
                    self.first_handshake = false;
                }
                if !self.output.is_empty() {
                    self.notify(Event::Output);
                }
                return Ok(Some(Event::HandshakeDone));
            }
            return Ok(None);
        }
        if !self.reading {
            if !self.output.is_empty() {
                return Ok(Some(Event::Output));
            }
            return Ok(Some(Event::Idle));
        }
        if !self.app_in.is_empty() {
            return Ok(Some(Event::AppData));
        }
        if self.shutdown & RECEIVED_SHUTDOWN != 0 {
            return Ok(Some(Event::Closed));
        }
        self.read_application_data(p)
    }

    /// Queues an event.
    pub(crate) fn notify(&mut self, e: Event) {
        let in_init = self.in_init();
        self.events.push_back((e, in_init));
    }

    /// The next queued event, noting whether the connection was in init when it was raised.
    fn pop_event(&mut self) -> Option<Event> {
        let (e, in_init) = self.events.pop_front()?;
        self.event_in_init = Some(in_init);
        Some(e)
    }

    /// Whether events are queued.
    pub(crate) fn has_events(&self) -> bool {
        !self.events.is_empty() || self.pending.is_some() && self.answer.is_none()
    }

    /// Asks for a decision: the answer if it has arrived (taking it), or `None` after making
    /// `r` the pending request (the caller returns its current work state, and runs again
    /// after the answer).
    pub(crate) fn ask(&mut self, r: Request) -> Option<Answer> {
        if self.pending.as_ref() == Some(&r)
            && let Some(a) = self.answer.take()
        {
            self.pending = None;
            return Some(a);
        }
        self.pending = Some(r);
        self.answer = None;
        None
    }

    /// Whether output is waiting to be taken: a flush point (`statem_flush`) waits for it.
    pub(crate) fn flushed(&self) -> bool {
        self.output.is_empty()
    }

    /// Reports a message to the message callback with the connection's version.
    pub(crate) fn report_message(
        &mut self,
        write: bool,
        content_type: core::ffi::c_int,
        bytes: &[u8],
    ) {
        let v = i32::from(self.neg.version);
        self.report_message_v(write, v, content_type, bytes);
    }

    /// Reports a message to the message callback with a given version.
    pub(crate) fn report_message_v(
        &mut self,
        write: bool,
        version: i32,
        content_type: core::ffi::c_int,
        bytes: &[u8],
    ) {
        if self.cfg.callbacks.msg {
            self.notify(Event::Message {
                write,
                version,
                content_type,
                bytes: bytes.to_vec(),
            });
        }
    }

    /// Writes `data` as records of type `ty` (`ssl3_write_bytes`), reporting each record's
    /// header (and TLS 1.3's inner content type) to the message callback.
    pub(crate) fn write_record(&mut self, p: &dyn Provider, ty: u8, data: &[u8]) -> Result<()> {
        let start = self.output.len();
        self.rw.write(p, ty, data, &mut self.output)?;
        if self.cfg.callbacks.msg {
            let protected13 = self.rw.mode() == record::Mode::Tls13;
            let mut at = start;
            let mut headers = Vec::new();
            while let Some(h) = self.output.get(at..at.saturating_add(record::HEADER_LEN)) {
                let byte = |i: usize| usize::from(h.get(i).copied().unwrap_or(0));
                let len = (byte(3) << 8) | byte(4);
                headers.push(h.to_vec());
                at = at.saturating_add(record::HEADER_LEN).saturating_add(len);
            }
            // The header with the record's own version, then (TLS 1.3 protection) the inner
            // content type with the same version (`tls_write_records`).
            for h in headers {
                let v = i32::from(u16::from_be_bytes([
                    h.get(1).copied().unwrap_or(0),
                    h.get(2).copied().unwrap_or(0),
                ]));
                self.report_message_v(true, v, abi::SSL3_RT_HEADER, &h);
                if protected13 {
                    self.report_message_v(true, v, abi::SSL3_RT_INNER_CONTENT_TYPE, &[ty]);
                }
            }
        }
        Ok(())
    }

    /// Reads the next record (`read_record`), reporting its header (and TLS 1.3's inner
    /// content type) to the message callback. `None`: more input is needed.
    fn fetch_record(&mut self, p: &dyn Provider) -> Result<Option<record::Record>> {
        loop {
            self.rr.skip_undecryptable = self.skip_early_data();
            // A fatal record-layer error that sends an alert is followed by
            // `SSL_R_RECORD_LAYER_FAILURE` (`ossl_tls_handle_rlayer_return`).
            let read = self.rr.read(p, &self.input).map_err(|mut e| {
                if e.alert.is_some() {
                    e.follow_up = Some(abi::SSL_R_RECORD_LAYER_FAILURE);
                }
                e
            });
            match read? {
                Read::NeedMore(_) => {
                    self.needs_input = true;
                    return Ok(None);
                }
                Read::Skipped {
                    consumed,
                    header,
                    len,
                } => {
                    self.input.drain(..consumed.min(self.input.len()));
                    self.skipped = self.skipped.wrapping_add(1);
                    let v = i32::from(u16::from_be_bytes([
                        header.get(1).copied().unwrap_or(0),
                        header.get(2).copied().unwrap_or(0),
                    ]));
                    self.report_message_v(false, v, abi::SSL3_RT_HEADER, &header);
                    let (mut count, max) = self.early_read.map_or((0, 0), |e| (e.count, e.max));
                    early_data_count_ok(
                        &mut count,
                        max,
                        len,
                        early_data_ciphertext_overhead(),
                        false,
                    )
                    .map_err(Error::in_record_layer)?;
                    if let Some(e) = self.early_read.as_mut() {
                        e.count = count;
                    }
                }
                Read::IgnoredCcs { consumed, header } => {
                    self.input.drain(..consumed.min(self.input.len()));
                    // The header with its own version, then the CCS's octet as TLS 1.3's
                    // (`tls_get_more_records`).
                    let v = i32::from(u16::from_be_bytes([
                        header.get(1).copied().unwrap_or(0),
                        header.get(2).copied().unwrap_or(0),
                    ]));
                    self.report_message_v(false, v, abi::SSL3_RT_HEADER, &header);
                    let ccs = [msgs_type(abi::SSL3_MT_CCS)];
                    self.report_message_v(
                        false,
                        abi::TLS1_3_VERSION,
                        abi::SSL3_RT_CHANGE_CIPHER_SPEC,
                        &ccs,
                    );
                }
                Read::Record { consumed, record } => {
                    self.input.drain(..consumed.min(self.input.len()));
                    self.sslv2_record = record.version == record::SSL2_VERSION;
                    if !self.sslv2_record {
                        let v = i32::from(record.version);
                        self.report_message_v(false, v, abi::SSL3_RT_HEADER, &record.header);
                    }
                    if record.inner {
                        self.report_message(
                            false,
                            abi::SSL3_RT_INNER_CONTENT_TYPE,
                            &[record.content_type],
                        );
                    }
                    if let Some(e) = self.early_read.as_mut()
                        && e.early
                        && record.content_type == app_data()
                    {
                        early_data_count_ok(&mut e.count, e.max, record.data.len(), 0, false)
                            .map_err(Error::in_record_layer)?;
                    }
                    return Ok(Some(record));
                }
            }
        }
    }

    /// Reads handshake octets into `hs_in` during a handshake (`ssl3_read_bytes` for
    /// `SSL3_RT_HANDSHAKE`): handles alerts and the record types that may arrive instead.
    pub(crate) fn read_handshake_bytes(&mut self, p: &dyn Provider) -> Result<HsBytes> {
        self.read_handshake_bytes_inner(p)
            .in_func("ssl3_read_bytes")
    }

    /// See [`Connection::read_handshake_bytes`].
    fn read_handshake_bytes_inner(&mut self, p: &dyn Provider) -> Result<HsBytes> {
        loop {
            let Some(rec) = self.fetch_record(p)? else {
                return Ok(HsBytes::Yield);
            };
            let ty = rec.content_type;
            if !self.hs_in.is_empty() && ty != handshake() && self.is_tls13() {
                return Err(Error::alert(
                    abi::SSL_AD_UNEXPECTED_MESSAGE,
                    abi::SSL_R_MIXED_HANDSHAKE_AND_NON_HANDSHAKE_DATA,
                ));
            }
            if ty != alert() && !rec.data.is_empty() {
                self.alert_count = 0;
            }
            if self.change_cipher_spec && ty != handshake() {
                return Err(Error::alert(
                    abi::SSL_AD_UNEXPECTED_MESSAGE,
                    abi::SSL_R_DATA_BETWEEN_CCS_AND_FINISHED,
                ));
            }
            if self.shutdown & RECEIVED_SHUTDOWN != 0 {
                continue;
            }
            if ty == handshake() {
                self.hs_in.extend_from_slice(&rec.data);
                if self.has_events() {
                    // Report the record's header before using its contents.
                    return Ok(HsBytes::Got);
                }
                return Ok(HsBytes::Got);
            }
            if ty == ccs()
                && self.cfg.server
                && self.hs.sh.flags & abi::TLS1_FLAGS_STATELESS != 0
                && self.st.hand_state == st(abi::TLS_ST_BEFORE)
                && self.hs_in.is_empty()
                && rec.data == [msgs_type(abi::SSL3_MT_CCS)]
            {
                // A stateless server reading the client's ChangeCipherSpec between its two
                // ClientHellos: ignored, but the call fails (with no error recorded) until the
                // second ClientHello comes (`tls_get_message_header`).
                self.interrupted = true;
                return Err(Error::quiet(0));
            }
            // Only while the version is undecided: a renegotiation has one (fork M). Before the
            // alert is processed: a server takes no alert before the ClientHello
            // (`ssl3_read_bytes`).
            if self.cfg.method_version == 0
                && self.first_handshake
                && (self.cfg.server || ty != alert())
                && self.before_version()
            {
                return Err(Error::alert(
                    abi::SSL_AD_UNEXPECTED_MESSAGE,
                    abi::SSL_R_UNEXPECTED_MESSAGE,
                ));
            }
            if ty == ccs() && !self.is_tls13() {
                if !self.hs_in.is_empty() {
                    return Err(Error::alert(
                        abi::SSL_AD_UNEXPECTED_MESSAGE,
                        abi::SSL_R_CCS_RECEIVED_EARLY,
                    ));
                }
                if rec.data.len() != 1 || rec.data.first() != Some(&msgs_type(abi::SSL3_MT_CCS)) {
                    return Err(Error::alert(
                        abi::SSL_AD_UNEXPECTED_MESSAGE,
                        abi::SSL_R_BAD_CHANGE_CIPHER_SPEC,
                    ));
                }
                // TLS doesn't report a received ChangeCipherSpec to the message callback (only
                // DTLS does).
                return Ok(HsBytes::Ccs);
            }
            if ty == alert() {
                match self.process_alert(&rec.data)? {
                    AlertOutcome::Continue => continue,
                    AlertOutcome::Closed => {
                        // close_notify mid-handshake: the read fails (`SSL_ERROR_ZERO_RETURN`
                        // or SYSCALL, as capi decides from the shutdown flags).
                        return Ok(HsBytes::Yield);
                    }
                }
            }
            if ty == app_data() && self.skip_early_data() {
                // Early data sent before a HelloRetryRequest arrives where the second
                // ClientHello should: in plaintext it looks like application data, and is
                // skipped (`ssl3_read_bytes`).
                let max = self.max_early_data();
                let mut count = self.early_data_count;
                early_data_count_ok(
                    &mut count,
                    max,
                    rec.data.len(),
                    early_data_ciphertext_overhead(),
                    false,
                )?;
                self.early_data_count = count;
                continue;
            }
            if ty == app_data() {
                if self.first_handshake {
                    return Err(Error::alert(
                        abi::SSL_AD_UNEXPECTED_MESSAGE,
                        abi::SSL_R_APP_DATA_IN_HANDSHAKE,
                    ));
                }
                // Renegotiation in progress: data allowed before the peer's hello.
                if self.app_data_allowed() {
                    self.app_in.extend(rec.data.iter());
                    continue;
                }
                return Err(Error::alert(
                    abi::SSL_AD_UNEXPECTED_MESSAGE,
                    abi::SSL_R_UNEXPECTED_RECORD,
                ));
            }
            return Err(Error::alert(
                abi::SSL_AD_UNEXPECTED_MESSAGE,
                abi::SSL_R_UNEXPECTED_RECORD,
            ));
        }
    }

    /// Whether the version is still undecided (a flexible method before the hello exchange).
    fn before_version(&self) -> bool {
        self.st.hand_state == st(abi::TLS_ST_BEFORE)
            || self.st.hand_state == st(abi::TLS_ST_CW_CLNT_HELLO)
            || self.st.hand_state == st(abi::TLS_ST_SR_CLNT_HELLO) && self.neg.cipher.is_none()
    }

    /// `ossl_statem_app_data_allowed`.
    fn app_data_allowed(&self) -> bool {
        if self.cfg.server {
            self.st.hand_state == st(abi::TLS_ST_BEFORE)
                || self.st.hand_state == st(abi::TLS_ST_SR_CLNT_HELLO)
        } else {
            self.st.hand_state == st(abi::TLS_ST_CW_CLNT_HELLO)
        }
    }

    /// An alert record (the alert part of `ssl3_read_bytes`).
    fn process_alert(&mut self, data: &[u8]) -> Result<AlertOutcome> {
        let (&[level, desc], true) = (
            <&[u8; 2]>::try_from(data).unwrap_or(&[0, 0]),
            data.len() == 2,
        ) else {
            return Err(Error::alert(
                abi::SSL_AD_UNEXPECTED_MESSAGE,
                abi::SSL_R_INVALID_ALERT,
            ));
        };
        self.report_message(false, abi::SSL3_RT_ALERT, data);
        if self.cfg.callbacks.info {
            let v = (i32::from(level) << 8) | i32::from(desc);
            self.notify(Event::Info {
                where_: abi::SSL_CB_READ_ALERT,
                ret: v,
            });
        }
        let tls13 = self.is_tls13();
        let warning = level == msgs_type(abi::SSL3_AL_WARNING);
        let user_cancelled = desc == msgs_type(abi::SSL_AD_USER_CANCELLED);
        if (!tls13 && warning) || (tls13 && user_cancelled) {
            self.warn_alert = desc;
            self.alert_count = self.alert_count.saturating_add(1);
            if self.alert_count == MAX_WARN_ALERT_COUNT {
                return Err(Error::alert(
                    abi::SSL_AD_UNEXPECTED_MESSAGE,
                    abi::SSL_R_TOO_MANY_WARN_ALERTS,
                ));
            }
        }
        if tls13 && user_cancelled {
            return Ok(AlertOutcome::Continue);
        }
        if desc == msgs_type(abi::SSL_AD_CLOSE_NOTIFY) && (tls13 || warning) {
            self.shutdown |= RECEIVED_SHUTDOWN;
            return Ok(AlertOutcome::Closed);
        }
        if level == msgs_type(abi::SSL3_AL_FATAL) || tls13 {
            self.fatal_alert = desc;
            self.shutdown |= RECEIVED_SHUTDOWN;
            return Err(Error {
                alert: None,
                reason: abi::SSL_AD_REASON_OFFSET.saturating_add(i32::from(desc)),
                library_reason: false,
                data: None,
                func: Some("ssl3_read_bytes"),
                follow_up: None,
                cause: None,
            });
        }
        if desc == msgs_type(abi::SSL_AD_NO_RENEGOTIATION) {
            return Err(Error::alert(
                abi::SSL_AD_HANDSHAKE_FAILURE,
                abi::SSL_R_NO_RENEGOTIATION,
            ));
        }
        if warning {
            return Ok(AlertOutcome::Continue);
        }
        Err(Error::alert(
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_R_UNKNOWN_ALERT_TYPE,
        ))
    }

    /// Reads after the handshake (`ssl3_read_bytes` for application data): application data
    /// is buffered, a post-handshake message goes back into the state machine, alerts are
    /// handled.
    fn read_application_data(&mut self, p: &dyn Provider) -> Result<Option<Event>> {
        self.read_application_data_inner(p)
            .in_func("ssl3_read_bytes")
    }

    /// See [`Connection::read_application_data`].
    fn read_application_data_inner(&mut self, p: &dyn Provider) -> Result<Option<Event>> {
        // A handshake message that arrived with the record before (TLS 1.3 post-handshake).
        if self.hs_in.len() >= msgs::HEADER_LEN {
            common::enter_post_handshake(self);
            return Ok(None);
        }
        let Some(rec) = self.fetch_record(p)? else {
            return Ok(None);
        };
        let ty = rec.content_type;
        if ty != alert() && !rec.data.is_empty() {
            self.alert_count = 0;
        }
        if self.shutdown & RECEIVED_SHUTDOWN != 0 {
            return Ok(None);
        }
        if ty == app_data() {
            self.app_in.extend(rec.data.iter());
            return Ok(if self.app_in.is_empty() {
                None
            } else {
                Some(Event::AppData)
            });
        }
        if ty == alert() {
            return match self.process_alert(&rec.data)? {
                AlertOutcome::Continue => Ok(None),
                AlertOutcome::Closed => Ok(Some(Event::Closed)),
            };
        }
        if self.shutdown & SENT_SHUTDOWN != 0 && ty == handshake() && !self.is_tls13() {
            // Handshake messages are ignored after sending close_notify (TLS 1.2).
            return Ok(None);
        }
        if ty == handshake() {
            self.hs_in.extend_from_slice(&rec.data);
            if self.hs_in.len() >= msgs::HEADER_LEN {
                // Back into the handshake (renegotiation, or TLS 1.3 post-handshake messages);
                // the next step runs it.
                common::enter_post_handshake(self);
            }
            return Ok(None);
        }
        if ty == ccs() {
            return Err(Error::alert(
                abi::SSL_AD_UNEXPECTED_MESSAGE,
                abi::SSL_R_CCS_RECEIVED_EARLY,
            ));
        }
        Err(Error::alert(
            abi::SSL_AD_UNEXPECTED_MESSAGE,
            abi::SSL_R_UNEXPECTED_RECORD,
        ))
    }

    /// Writes application data (`ssl3_write_bytes` after the handshake); returns how much was
    /// taken (all of it).
    ///
    /// # Errors
    /// The handshake isn't done, the connection failed or was shut down, or protection failed.
    pub fn write_app(&mut self, p: &dyn Provider, data: &[u8]) -> Result<usize> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        if self.shutdown & SENT_SHUTDOWN != 0 {
            return Err(Error::quiet(abi::SSL_R_PROTOCOL_IS_SHUTDOWN));
        }
        let eds = self.hs.sh.early_data_state;
        if self.in_init() && eds != common::EarlyDataState::UnauthWriting {
            return Err(Error::internal());
        }
        if eds == common::EarlyDataState::Writing {
            let max = self.max_early_data();
            let mut count = self.early_data_count;
            if let Err(e) = early_data_count_ok(&mut count, max, data.len(), 0, true) {
                self.fatal(p, e);
                return Err(e);
            }
            self.early_data_count = count;
        }
        self.write_record(p, app_data(), data)?;
        Ok(data.len())
    }

    /// Sets or clears `TLS1_FLAGS_STATELESS` (`SSL_stateless`): a TLS 1.3 server that keeps no
    /// state across a HelloRetryRequest, sending its state in a cookie.
    pub fn set_stateless(&mut self, on: bool) {
        if on {
            self.hs.sh.flags |= abi::TLS1_FLAGS_STATELESS;
        } else {
            self.hs.sh.flags &= !abi::TLS1_FLAGS_STATELESS;
        }
    }

    /// Whether a stateless server's cookie checked out (`s->ext.cookieok`).
    #[must_use]
    pub fn cookie_ok(&self) -> bool {
        self.hs.sh.cookie_ok
    }

    /// Whether a HelloRetryRequest is pending (`SSL_HRR_PENDING`).
    #[must_use]
    pub fn hrr_pending(&self) -> bool {
        self.hs.sh.hrr == common::Hrr::Pending
    }

    /// How many early data records the server skipped because they didn't decrypt (the early
    /// data it rejected). A decryption failure is normal then, and the caller drops what the
    /// failed decryption reported (`ERR_pop_to_mark` in OpenSSL's record layer).
    #[must_use]
    pub fn skipped_records(&self) -> u64 {
        self.skipped
    }

    /// TLS 1.3's early data state (`s->early_data_state`), which `SSL_write_early_data` and
    /// `SSL_read_early_data` move along.
    #[must_use]
    pub fn early_data_state(&self) -> common::EarlyDataState {
        self.hs.sh.early_data_state
    }

    /// Sets the early data state (see [`Connection::early_data_state`]).
    pub fn set_early_data_state(&mut self, s: common::EarlyDataState) {
        self.hs.sh.early_data_state = s;
    }

    /// `ossl_statem_check_finish_init`: before a read (`sending` 0), a write (1), or a
    /// handshake call (-1), whether a handshake stopped for early data goes on.
    pub fn check_finish_init(&mut self, sending: i32) {
        use common::EarlyDataState as E;
        let hs = self.st.hand_state;
        let early = hs == st(abi::TLS_ST_EARLY_DATA);
        let pending_end = hs == st(abi::TLS_ST_PENDING_EARLY_DATA_END);
        let eds = self.hs.sh.early_data_state;
        if sending == -1 {
            if pending_end || early {
                self.st.in_init = true;
                if eds == E::WriteRetry {
                    // The handshake was called directly: no more early data.
                    self.hs.sh.early_data_state = E::FinishedWriting;
                }
            }
        } else if !self.cfg.server {
            let sending = sending != 0;
            if (sending && (pending_end || early) && eds != E::Writing) || (!sending && early) {
                self.st.in_init = true;
                if sending && eds == E::WriteRetry {
                    // A plain write: no more early data.
                    self.hs.sh.early_data_state = E::FinishedWriting;
                }
            }
        } else if eds == E::FinishedReading && early {
            self.st.in_init = true;
        }
    }

    /// `ossl_get_max_early_data`: a client's limit is its session's; a server's is
    /// `recv_max_early_data`, or with early data accepted the smaller of that and the
    /// session's.
    pub(crate) fn max_early_data(&self) -> u32 {
        if !self.cfg.server {
            return client::early_limit(self);
        }
        let recv = self.cfg.recv_max_early_data;
        if self.neg.early_data_status == abi::SSL_EARLY_DATA_ACCEPTED {
            recv.min(self.neg.session.max_early_data)
        } else {
            recv
        }
    }

    /// `ossl_statem_skip_early_data`: a server that rejected early data, waiting for the rest
    /// of the client's flight (and not after a second ClientHello), skips what it can't read.
    fn skip_early_data(&self) -> bool {
        self.neg.early_data_status == abi::SSL_EARLY_DATA_REJECTED
            && self.cfg.server
            && self.st.hand_state == st(abi::TLS_ST_EARLY_DATA)
            && self.hs.sh.hrr != common::Hrr::Complete
    }

    /// Sends close_notify (`ssl3_shutdown`'s first part), once.
    ///
    /// # Errors
    /// Protection failed.
    pub fn send_close_notify(&mut self, p: &dyn Provider) -> Result<()> {
        if self.shutdown & SENT_SHUTDOWN == 0 {
            self.shutdown |= SENT_SHUTDOWN;
            self.send_alert(
                p,
                msgs_type(abi::SSL3_AL_WARNING),
                msgs_type(abi::SSL_AD_CLOSE_NOTIFY),
            )?;
        }
        Ok(())
    }

    /// Sends an alert (`ssl3_send_alert` / `ssl3_dispatch_alert`).
    pub(crate) fn send_alert(&mut self, p: &dyn Provider, level: u8, desc: u8) -> Result<()> {
        // Shared fix (fork M): `ssl3_send_alert`'s mapping to the version's alerts
        // (`tls13_alert_code` / `tls1_alert_code`): an alert the version doesn't have isn't
        // sent, TLS 1.3's certificate_required and missing_extension become handshake_failure
        // before TLS 1.3; after close_notify, only close_notify goes out.
        let Some(desc) = self.alert_value(desc) else {
            return Ok(());
        };
        if self.shutdown & SENT_SHUTDOWN != 0 && desc != msgs_type(abi::SSL_AD_CLOSE_NOTIFY) {
            return Ok(());
        }
        // TLS 1.3 alerts are all fatal except close_notify and user_cancelled
        // (`ssl3_send_alert`'s level adjustment).
        let level = if self.is_tls13()
            && desc != msgs_type(abi::SSL_AD_CLOSE_NOTIFY)
            && desc != msgs_type(abi::SSL_AD_USER_CANCELLED)
        {
            msgs_type(abi::SSL3_AL_FATAL)
        } else {
            level
        };
        let a = [level, desc];
        self.write_record(p, alert(), &a)?;
        self.sent_alert = Some((level, desc));
        self.report_message(true, abi::SSL3_RT_ALERT, &a);
        if self.cfg.callbacks.info {
            let v = (i32::from(level) << 8) | i32::from(desc);
            self.notify(Event::Info {
                where_: abi::SSL_CB_WRITE_ALERT,
                ret: v,
            });
        }
        Ok(())
    }

    /// `tls13_alert_code` / `tls1_alert_code`: the alert to send for `desc`, or `None` when
    /// the version has none.
    fn alert_value(&self, desc: u8) -> Option<u8> {
        use crate::conn::common::{EarlyDataState as E, Hrr};
        let d = i32::from(desc);
        let as13 = self.is_tls13()
            || matches!(
                self.hs.sh.early_data_state,
                E::Connecting | E::ConnectRetry | E::Writing | E::WriteRetry
            )
            || self.hs.sh.hrr == Hrr::Pending;
        if d == abi::SSL_AD_CERTIFICATE_REQUIRED || d == abi::SSL_AD_MISSING_EXTENSION {
            return Some(if as13 {
                desc
            } else {
                msgs_type(abi::SSL_AD_HANDSHAKE_FAILURE)
            });
        }
        let known = [
            abi::SSL_AD_CLOSE_NOTIFY,
            abi::SSL_AD_UNEXPECTED_MESSAGE,
            abi::SSL_AD_BAD_RECORD_MAC,
            abi::SSL_AD_DECRYPTION_FAILED,
            abi::SSL_AD_RECORD_OVERFLOW,
            abi::SSL_AD_DECOMPRESSION_FAILURE,
            abi::SSL_AD_HANDSHAKE_FAILURE,
            abi::SSL_AD_BAD_CERTIFICATE,
            abi::SSL_AD_UNSUPPORTED_CERTIFICATE,
            abi::SSL_AD_CERTIFICATE_REVOKED,
            abi::SSL_AD_CERTIFICATE_EXPIRED,
            abi::SSL_AD_CERTIFICATE_UNKNOWN,
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_AD_UNKNOWN_CA,
            abi::SSL_AD_ACCESS_DENIED,
            abi::SSL_AD_DECODE_ERROR,
            abi::SSL_AD_DECRYPT_ERROR,
            abi::SSL_AD_EXPORT_RESTRICTION,
            abi::SSL_AD_PROTOCOL_VERSION,
            abi::SSL_AD_INSUFFICIENT_SECURITY,
            abi::SSL_AD_INTERNAL_ERROR,
            abi::SSL_AD_USER_CANCELLED,
            abi::SSL_AD_NO_RENEGOTIATION,
            abi::SSL_AD_UNSUPPORTED_EXTENSION,
            abi::SSL_AD_CERTIFICATE_UNOBTAINABLE,
            abi::SSL_AD_UNRECOGNIZED_NAME,
            abi::SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE,
            abi::SSL_AD_BAD_CERTIFICATE_HASH_VALUE,
            abi::SSL_AD_UNKNOWN_PSK_IDENTITY,
            abi::SSL_AD_INAPPROPRIATE_FALLBACK,
            abi::SSL_AD_NO_APPLICATION_PROTOCOL,
        ];
        known.contains(&d).then_some(desc)
    }

    /// Fails the connection from outside the state machine, as OpenSSL's `SSLfatal` does in
    /// the record layer and the I/O functions (an unexpected EOF, a bad write retry): sends the
    /// error's alert (if any) into the output, and every later step reports the error. Shared
    /// addition (fork M).
    pub fn fail(&mut self, p: &dyn Provider, e: Error) {
        self.fatal(p, e);
    }

    /// Fails the connection (`ossl_statem_fatal`): sends the alert, once.
    fn fatal(&mut self, p: &dyn Provider, e: Error) {
        if self.failed.is_some() {
            return;
        }
        self.failed = Some(e);
        self.st.state = MsgFlow::Error;
        self.st.in_init = true;
        self.pending = None;
        if let Some(desc) = e.alert {
            // Sending can't fail in a way that matters any more.
            let _ = self.send_alert(p, msgs_type(abi::SSL3_AL_FATAL), desc);
        }
    }

    /// Sets up a new handshake (`tls_setup_handshake`).
    fn setup_handshake(&mut self, p: &dyn Provider) -> Result<()> {
        common::setup_handshake(self, p)
    }

    /// Takes the Finished MAC the peer must send (`ssl3_take_mac`).
    pub(crate) fn take_mac(&mut self, p: &dyn Provider) -> Result<()> {
        common::take_mac(self, p)
    }
}

/// What an alert did.
enum AlertOutcome {
    /// Ignored (a warning, or TLS 1.3's user_cancelled).
    Continue,
    /// close_notify.
    Closed,
}

use crate::msgs;

fn tls1_0() -> u16 {
    u16::try_from(abi::TLS1_VERSION).unwrap_or(0x0301)
}

fn tls1_3() -> u16 {
    u16::try_from(abi::TLS1_3_VERSION).unwrap_or(0x0304)
}

fn handshake() -> u8 {
    msgs_type(abi::SSL3_RT_HANDSHAKE)
}

fn alert() -> u8 {
    msgs_type(abi::SSL3_RT_ALERT)
}

fn ccs() -> u8 {
    msgs_type(abi::SSL3_RT_CHANGE_CIPHER_SPEC)
}

fn app_data() -> u8 {
    msgs_type(abi::SSL3_RT_APPLICATION_DATA)
}

#[cfg(test)]
mod stale_answer_tests {
    use super::{Answer, Config, Connection, Event, Request};
    use crate::testprov::TestProvider;

    /// An answer the machine never takes (its callback's flag went off while it waited) is
    /// dropped: the connection waits for input instead of asking again forever.
    #[test]
    fn an_unconsumed_answer_is_dropped() {
        let p = TestProvider::new(b"stale-answer");
        let cfg = Config {
            min_version: crate::consts::version::TLS1_3,
            max_version: crate::consts::version::TLS1_3,
            ciphers: vec![crate::suites::by_protocol_id(0x1301).unwrap()],
            groups: vec![0x001d],
            key_share_groups: vec![0x001d],
            max_send_fragment: 16384,
            ..Config::default()
        };
        let mut c = Connection::new(cfg);
        let mut steps = 0;
        loop {
            steps += 1;
            assert!(steps < 100, "no progress");
            match c.step(&p, false).unwrap() {
                Event::Output => drop(c.take_output()),
                Event::NeedInput => break,
                _ => {}
            }
        }
        // A request answered after the machine stopped needing it.
        c.pending = Some(Request::AllowEarlyData);
        c.answer(Answer::Allowed(true));
        assert_eq!(c.step(&p, false).unwrap(), Event::NeedInput);
        assert!(c.pending.is_none() && c.answer.is_none());
        assert_eq!(c.step(&p, false).unwrap(), Event::NeedInput);
    }
}
