//! One QUIC connection (after OpenSSL's `quic_channel.c`, `quic_rx_depack.c` and `quic_txp.c`):
//! it drives the handshake, protects and unprotects packets, processes frames with OpenSSL's
//! checks, assembles packets, runs loss detection, key updates, the idle timeout, and closing
//! and draining.
//!
//! As OpenSSL's QUIC: one local connection ID, no active migration (a client drops packets from
//! another address; a server keeps answering the address it started with), no 0-RTT, and the
//! datagram size is the minimum, 1200 octets.

use std::collections::VecDeque;

use crate::ackm::{Ackm, SentPacket, Timeout};
use crate::cid::{self, RemoteCids};
use crate::crypto::{Provider, Suite};
use crate::error::{Error, Result};
use crate::packet::{self, Keys, Located, Outgoing, PacketType, Space, TAG_LEN};
use crate::stream::{CryptoStream, StreamEvent, StreamLimits, StreamMap};
use crate::time::{Duration, Time, earliest};
use crate::tls::{Answer, Direction, Event, Handshake, HsEvent, Level, Request};
use crate::txp::{PayloadBuilder, SentFrame, SentInfo};
use crate::wire::{self, ConnId, Frame, TransportParams, frame_type as ft};

/// A peer's address: the `BIO_ADDR` octets, compared and never interpreted.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerAddr(pub Vec<u8>);

/// The datagram size (OpenSSL's `QUIC_MIN_INITIAL_DGRAM_LEN`; it does no path MTU discovery).
pub const MAX_DGRAM: usize = packet::MIN_INITIAL_DGRAM_LEN;
/// OpenSSL's default idle timeout, in milliseconds.
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 30_000;
/// The longest keepalive interval (OpenSSL's `MAX_NAT_INTERVAL`).
pub const MAX_NAT_INTERVAL: Duration = Duration::from_millis(25_000);
/// PATH_RESPONSE frames queued at once (OpenSSL's `QUIC_PATH_RESPONSE_QLEN`).
pub const PATH_RESPONSE_QLEN: usize = 32;
/// The length of a client's random initial DCID (OpenSSL's `INIT_DCID_LEN`).
pub const INIT_DCID_LEN: usize = 8;
/// Packets kept until their keys arrive (OpenSSL's QRX `max_deferred`).
pub const MAX_DEFERRED: usize = 32;
/// A TLS alert (`SSL_AD_*`) the transport raises itself, as CRYPTO_ERROR 0x100 plus it.
fn alert(a: core::ffi::c_int) -> u8 {
    u8::try_from(a).unwrap_or(u8::MAX)
}

/// The ack-eliciting probes a PTO sends.
const PROBES_PER_PTO: u8 = 2;
/// The smallest room worth starting another coalesced packet in.
const MIN_PACKET_ROOM: usize = 48;

/// Why a connection ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminateCause {
    /// The peer closed it.
    pub remote: bool,
    /// An application close (CONNECTION_CLOSE type 0x1d).
    pub app: bool,
    pub code: u64,
    pub frame_type: u64,
    pub reason: Vec<u8>,
}

/// What a channel tells its owner.
#[derive(Debug)]
pub enum ChannelEvent {
    /// A TLS decision for the application; answer it with [`Channel::tls_answer`].
    TlsRequest(Request),
    /// TLS information for the application's callbacks.
    TlsInfo(Event),
    HandshakeComplete,
    IncomingStream(u64),
    StreamReadable(u64),
    StreamWritable(u64),
    /// A NEW_TOKEN token from the server, to cache for this peer.
    NewToken(Vec<u8>),
    /// The connection started terminating (closing, draining or at once); [`Channel::state`]
    /// says which.
    Terminated(TerminateCause),
}

/// The channel's state (OpenSSL's `QUIC_CHANNEL_STATE_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Active,
    Closing,
    Draining,
    Terminated,
}

/// A channel's settings.
#[derive(Clone, Debug)]
pub struct ChannelConfig {
    /// Our max_idle_timeout in milliseconds (0: none).
    pub idle_timeout_ms: u64,
    /// A client's address-validation token (from a NEW_TOKEN), sent in its Initials.
    pub token: Vec<u8>,
    /// A client's own connection ID length: 0, except on a port that also listens (OpenSSL's
    /// `SSL_new_from_listener`), which routes by it.
    pub local_cid_len: usize,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            idle_timeout_ms: DEFAULT_IDLE_TIMEOUT_MS,
            token: Vec::new(),
            local_cid_len: 0,
        }
    }
}

/// What a server's port knows when it creates a channel.
#[derive(Clone, Debug)]
pub struct ServerInit {
    /// The client's address.
    pub peer: PeerAddr,
    /// The client's source connection ID.
    pub client_scid: ConnId,
    /// The DCID of the client's Initial (the Initial keys').
    pub dcid: ConnId,
    /// The client's original DCID (before a Retry; otherwise `dcid`).
    pub odcid: ConnId,
    /// Our connection ID.
    pub local_cid: ConnId,
    /// Whether a Retry was done (`dcid` is then its SCID).
    pub retried: bool,
    /// Whether the client's address was validated by a token.
    pub validated: bool,
    /// Send the client a NEW_TOKEN once the handshake completes.
    pub new_token: Option<Vec<u8>>,
}

/// A connection.
pub struct Channel {
    is_server: bool,
    state: State,
    hs: Box<dyn Handshake>,
    hs_failed: bool,
    /// Packets that arrived before their space's keys, to process once they come (OpenSSL's
    /// deferred URXEs).
    deferred: VecDeque<Vec<u8>>,
    peer: PeerAddr,
    local_cid: ConnId,
    /// Client: the DCID of its first Initial. Server: the client's original DCID.
    init_dcid: ConnId,
    /// Server: the DCID of the client's Initial, routed until the handshake is confirmed.
    initial_dcid: ConnId,
    rcid: RemoteCids,
    /// Client: the server's SCID from its first Initial.
    peer_scid: Option<ConnId>,
    retry_scid: Option<ConnId>,
    token: Vec<u8>,
    got_enc_packet: bool,
    have_processed_any: bool,
    initial_keys: Option<(Keys, Keys)>,
    hs_rx: Option<Keys>,
    hs_tx: Option<Keys>,
    app_rx: Option<Keys>,
    app_rx_next: Option<Keys>,
    app_rx_prev: Option<Keys>,
    app_rx_phase: bool,
    app_tx: Option<Keys>,
    app_tx_phase: bool,
    discarded: [bool; 3],
    tx_epoch_pkts: u64,
    forged: u64,
    rxku_in_progress: bool,
    rxku_pending_confirm: bool,
    rxku_trigger_pn: u64,
    rxku_update_end: Option<Time>,
    txku_in_progress: bool,
    txku_pn: u64,
    txku_cooldown: Time,
    ku_locally_initiated: bool,
    crypto: [CryptoStream; 3],
    ackm: Ackm<SentInfo>,
    streams: StreamMap,
    local_tp: TransportParams,
    peer_tp: Option<TransportParams>,
    idle_timeout_ms: u64,
    idle_deadline: Option<Time>,
    ping_deadline: Option<Time>,
    sent_eliciting_since_rx: bool,
    handshake_complete: bool,
    handshake_confirmed: bool,
    handshake_done_pending: bool,
    address_validated: bool,
    bytes_rx: u64,
    bytes_tx: u64,
    new_token: Option<Vec<u8>>,
    path_responses: VecDeque<[u8; 8]>,
    seen_path_challenge: bool,
    probes: [u8; 3],
    ping_now: bool,
    close_send: bool,
    terminate_deadline: Option<Time>,
    terminate_cause: Option<TerminateCause>,
    have_sent_any: bool,
    /// The last time the caller gave us.
    last_now: Time,
    events: VecDeque<ChannelEvent>,
}

impl core::fmt::Debug for Channel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Channel")
            .field("is_server", &self.is_server)
            .field("state", &self.state)
            .field("local_cid", &self.local_cid)
            .finish_non_exhaustive()
    }
}

fn space_index(s: Space) -> usize {
    s.index()
}

fn random_cid(p: &dyn Provider, len: usize) -> Result<ConnId> {
    let mut b = [0u8; wire::MAX_CID_LEN];
    let b = b
        .get_mut(..len)
        .ok_or_else(|| Error::internal("cid length"))?;
    p.random(b, false).map_err(|_| Error::internal("random"))?;
    ConnId::new(b)
}

impl Channel {
    #[allow(
        clippy::too_many_arguments,
        reason = "one constructor shared by both roles"
    )]
    fn base(
        is_server: bool,
        hs: Box<dyn Handshake>,
        peer: PeerAddr,
        cfg: &ChannelConfig,
        local_cid: ConnId,
        init_dcid: ConnId,
        remote: ConnId,
        initial_keys: (Keys, Keys),
    ) -> Self {
        let streams = StreamMap::new(is_server);
        let (bidi, uni) = streams.local_max_streams();
        let local_tp = TransportParams {
            max_idle_timeout: cfg.idle_timeout_ms,
            max_udp_payload_size: u64::try_from(MAX_DGRAM).unwrap_or(1200),
            initial_max_data: streams.conn_rx.cwm(),
            initial_max_stream_data_bidi_local: streams.stream_window,
            initial_max_stream_data_bidi_remote: streams.stream_window,
            initial_max_stream_data_uni: streams.stream_window,
            initial_max_streams_bidi: bidi,
            initial_max_streams_uni: uni,
            disable_active_migration: true,
            active_connection_id_limit: cid::ACTIVE_CONN_ID_LIMIT,
            initial_scid: Some(local_cid.clone()),
            ..TransportParams::default()
        };
        Self {
            is_server,
            state: State::Active,
            hs,
            hs_failed: false,
            deferred: VecDeque::new(),
            peer,
            local_cid,
            init_dcid: init_dcid.clone(),
            initial_dcid: init_dcid,
            rcid: RemoteCids::new(remote),
            peer_scid: None,
            retry_scid: None,
            token: Vec::new(),
            got_enc_packet: false,
            have_processed_any: false,
            initial_keys: Some(initial_keys),
            hs_rx: None,
            hs_tx: None,
            app_rx: None,
            app_rx_next: None,
            app_rx_prev: None,
            app_rx_phase: false,
            app_tx: None,
            app_tx_phase: false,
            discarded: [false; 3],
            tx_epoch_pkts: 0,
            forged: 0,
            rxku_in_progress: false,
            rxku_pending_confirm: false,
            rxku_trigger_pn: 0,
            rxku_update_end: None,
            txku_in_progress: false,
            txku_pn: 0,
            txku_cooldown: Time::ZERO,
            ku_locally_initiated: false,
            crypto: [
                CryptoStream::default(),
                CryptoStream::default(),
                CryptoStream::default(),
            ],
            ackm: Ackm::new(MAX_DGRAM),
            streams,
            local_tp,
            peer_tp: None,
            idle_timeout_ms: cfg.idle_timeout_ms,
            idle_deadline: None,
            ping_deadline: None,
            sent_eliciting_since_rx: false,
            handshake_complete: false,
            handshake_confirmed: false,
            handshake_done_pending: false,
            address_validated: !is_server,
            bytes_rx: 0,
            bytes_tx: 0,
            new_token: None,
            path_responses: VecDeque::new(),
            seen_path_challenge: false,
            probes: [0; 3],
            ping_now: false,
            close_send: false,
            terminate_deadline: None,
            terminate_cause: None,
            have_sent_any: false,
            last_now: Time::ZERO,
            events: VecDeque::new(),
        }
    }

    /// A client connecting to `peer` with handshake `hs` (not yet started).
    ///
    /// # Errors
    /// The provider failed.
    pub fn connect(
        p: &dyn Provider,
        hs: Box<dyn Handshake>,
        peer: PeerAddr,
        cfg: &ChannelConfig,
        now: Time,
    ) -> Result<Self> {
        let dcid = random_cid(p, INIT_DCID_LEN)?;
        let keys = packet::initial_keys(p, dcid.as_bytes())?;
        let local_cid = if cfg.local_cid_len == 0 {
            ConnId::default()
        } else {
            random_cid(p, cfg.local_cid_len)?
        };
        // (tx, rx): a client writes with the client's keys and reads with the server's.
        let mut ch = Self::base(false, hs, peer, cfg, local_cid, dcid.clone(), dcid, keys);
        ch.token = cfg.token.clone();
        if !ch.hs.alpn_configured() {
            // quic_tls.c refuses to start a client without ALPN.
            ch.hs_failed = true;
            ch.raise(
                Error::crypto(
                    alert(rustyssl_abi::SSL_AD_NO_APPLICATION_PROTOCOL),
                    "ALPN must be configured when using QUIC",
                ),
                now,
            );
            return Ok(ch);
        }
        let tp = ch.local_tp.encode()?;
        ch.hs.set_transport_params(tp);
        ch.hs.start();
        ch.reset_idle(now);
        ch.pump_tls(p, now);
        Ok(ch)
    }

    /// A server's channel for a client's first Initial (the port then hands it the datagram).
    ///
    /// # Errors
    /// The provider failed.
    pub fn accept(
        p: &dyn Provider,
        hs: Box<dyn Handshake>,
        init: ServerInit,
        cfg: &ChannelConfig,
        now: Time,
    ) -> Result<Self> {
        let (c, s) = packet::initial_keys(p, init.dcid.as_bytes())?;
        let mut ch = Self::base(
            true,
            hs,
            init.peer,
            cfg,
            init.local_cid,
            init.odcid.clone(),
            init.client_scid.clone(),
            (s, c),
        );
        ch.initial_dcid = init.dcid.clone();
        ch.peer_scid = Some(init.client_scid);
        ch.local_tp.original_dcid = Some(init.odcid);
        if init.retried {
            ch.local_tp.retry_scid = Some(init.dcid);
        }
        ch.address_validated = init.validated;
        ch.new_token = init.new_token;
        ch.reset_idle(now);
        if !ch.hs.alpn_configured() {
            // A server without an ALPN selection callback: internal error (quic_tls.c).
            ch.hs_failed = true;
            ch.raise(
                Error::crypto(alert(rustyssl_abi::SSL_AD_INTERNAL_ERROR), "internal error"),
                now,
            );
            return Ok(ch);
        }
        // Our parameters are known now: a handshake that answers the client's at once (as
        // OpenSSL's, which runs to its EncryptedExtensions in one go) sends these.
        let tp = ch.local_tp.encode()?;
        ch.hs.set_transport_params(tp);
        ch.hs.start();
        Ok(ch)
    }

    /// Whether this end is the server.
    #[must_use]
    pub fn is_server(&self) -> bool {
        self.is_server
    }

    /// The state.
    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    /// Whether it's active (not terminating).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state == State::Active
    }

    /// Why it ended, once terminating.
    #[must_use]
    pub fn terminate_cause(&self) -> Option<&TerminateCause> {
        self.terminate_cause.as_ref()
    }

    /// Whether the handshake completed.
    #[must_use]
    pub fn is_handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    /// Whether the handshake is confirmed.
    #[must_use]
    pub fn is_handshake_confirmed(&self) -> bool {
        self.handshake_confirmed
    }

    /// The peer's address.
    #[must_use]
    pub fn peer(&self) -> &PeerAddr {
        &self.peer
    }

    /// Our connection ID.
    #[must_use]
    pub fn local_cid(&self) -> &ConnId {
        &self.local_cid
    }

    /// The connection IDs a port routes to this channel: ours, and (a server, until the
    /// handshake is confirmed) the DCID of the client's Initial.
    #[must_use]
    pub fn routing_cids(&self) -> Vec<ConnId> {
        let mut v = vec![self.local_cid.clone()];
        if self.is_server && !self.handshake_confirmed {
            v.push(self.initial_dcid.clone());
        }
        v
    }

    /// Whether `token` is one of the peer's stateless reset tokens.
    #[must_use]
    pub fn is_stateless_reset(&self, token: &[u8; wire::RESET_TOKEN_LEN]) -> bool {
        self.rcid.is_reset_token(token)
    }

    /// The peer's transport parameters, once received.
    #[must_use]
    pub fn peer_transport_params(&self) -> Option<&TransportParams> {
        self.peer_tp.as_ref()
    }

    /// The streams (read-only).
    #[must_use]
    pub fn streams(&self) -> &StreamMap {
        &self.streams
    }

    /// The RTT estimate.
    #[must_use]
    pub fn rtt(&self) -> crate::ackm::Rtt {
        self.ackm.rtt
    }

    /// The next event.
    pub fn poll_event(&mut self) -> Option<ChannelEvent> {
        if let Some(e) = self.events.pop_front() {
            return Some(e);
        }
        self.streams.poll_event().map(|e| match e {
            StreamEvent::Incoming(id) => ChannelEvent::IncomingStream(id),
            StreamEvent::Readable(id) => ChannelEvent::StreamReadable(id),
            StreamEvent::Writable(id) => ChannelEvent::StreamWritable(id),
        })
    }

    // ---- termination ----

    fn effective_idle(&self) -> Option<Duration> {
        if self.idle_timeout_ms == 0 {
            return None;
        }
        Some(Duration::from_millis(self.idle_timeout_ms).max(self.ackm.pto_duration().mul(3)))
    }

    fn reset_idle(&mut self, now: Time) {
        self.idle_deadline = self.effective_idle().map(|d| now.add(d));
    }

    fn reset_ping(&mut self, now: Time) {
        self.ping_deadline = self
            .effective_idle()
            .map(|d| now.add(d.div(2).min(MAX_NAT_INTERVAL)));
    }

    fn set_state(&mut self, s: State) {
        self.state = s;
        if s != State::Active {
            self.probes = [0; 3];
        }
    }

    fn start_terminating(&mut self, cause: TerminateCause, force_immediate: bool, now: Time) {
        let force = force_immediate || !self.have_sent_any;
        match self.state {
            State::Active => {
                self.terminate_cause = Some(cause.clone());
                self.events
                    .push_back(ChannelEvent::Terminated(cause.clone()));
                if force {
                    self.set_state(State::Terminated);
                } else {
                    self.set_state(if cause.remote {
                        State::Draining
                    } else {
                        State::Closing
                    });
                    self.terminate_deadline = Some(now.add(self.ackm.pto_duration().mul(3)));
                    self.close_send = !cause.remote;
                }
            }
            State::Closing => {
                if force {
                    self.set_state(State::Terminated);
                } else if cause.remote {
                    self.set_state(State::Draining);
                }
            }
            State::Draining => {
                if force {
                    self.set_state(State::Terminated);
                }
            }
            State::Terminated => {}
        }
    }

    /// Raises a protocol error: we close with it.
    fn raise(&mut self, e: Error, now: Time) {
        self.start_terminating(
            TerminateCause {
                remote: false,
                app: false,
                code: e.code,
                frame_type: e.frame_type,
                reason: e.reason.as_bytes().to_vec(),
            },
            false,
            now,
        );
    }

    /// The peer reset the connection statelessly: drain, as OpenSSL (a remote NO_ERROR).
    pub fn on_stateless_reset(&mut self) {
        let now = self.last_now;
        self.start_terminating(
            TerminateCause {
                remote: true,
                app: false,
                code: 0,
                frame_type: 0,
                reason: Vec::new(),
            },
            false,
            now,
        );
    }

    /// Closes the connection with an application error (`SSL_shutdown_ex`).
    pub fn shutdown(&mut self, app_error: u64, reason: &[u8], now: Time) {
        self.start_terminating(
            TerminateCause {
                remote: false,
                app: true,
                code: app_error,
                frame_type: 0,
                reason: reason.to_vec(),
            },
            false,
            now,
        );
    }

    /// Closes with a transport error (`NO_ERROR` when OpenSSL's shutdown flush ends without an
    /// application close set: `ossl_quic_channel_notify_flush_done`).
    pub fn close_transport(&mut self, code: u64, reason: &[u8], now: Time) {
        self.start_terminating(
            TerminateCause {
                remote: false,
                app: false,
                code,
                frame_type: 0,
                reason: reason.to_vec(),
            },
            false,
            now,
        );
    }

    // ---- TLS ----

    /// Answers the last [`ChannelEvent::TlsRequest`].
    pub fn tls_answer(&mut self, p: &dyn Provider, a: Answer, now: Time) {
        self.hs.answer(a);
        self.pump_tls(p, now);
    }

    fn pump_tls(&mut self, p: &dyn Provider, now: Time) {
        for _ in 0..8 {
            self.pump_tls_once(p, now);
            if !self.retry_deferred(p, now) {
                break;
            }
        }
    }

    /// Whether a space's packets can be read now.
    fn has_rx_keys(&self, s: Space) -> bool {
        match s {
            Space::Initial => self.initial_keys.is_some(),
            Space::Handshake => self.hs_rx.is_some(),
            Space::Application => self.app_rx.is_some(),
        }
    }

    /// Processes the deferred packets whose keys arrived; whether any was.
    fn retry_deferred(&mut self, p: &dyn Provider, now: Time) -> bool {
        if self.deferred.is_empty() || matches!(self.state, State::Terminated | State::Draining) {
            return false;
        }
        let waiting = core::mem::take(&mut self.deferred);
        let mut any = false;
        let cid_len = self.local_cid.len();
        for d in waiting {
            let Ok((pkt, _)) = packet::locate(&d, cid_len) else {
                continue;
            };
            let ready = pkt.ty.space().is_some_and(|s| self.has_rx_keys(s));
            if !ready {
                if self.deferred.len() < MAX_DEFERRED {
                    self.deferred.push_back(d.clone());
                }
                continue;
            }
            if self.handle_packet(p, now, &pkt) {
                any = true;
            }
            if self.state == State::Terminated {
                break;
            }
        }
        any
    }

    fn pump_tls_once(&mut self, p: &dyn Provider, now: Time) {
        if self.hs_failed || self.state != State::Active {
            return;
        }
        loop {
            match self.hs.step(p) {
                Err(e) => {
                    self.hs_failed = true;
                    self.raise(e, now);
                    break;
                }
                Ok(None) => break,
                Ok(Some(ev)) => {
                    if let Err(e) = self.on_hs_event(p, ev, now) {
                        self.hs_failed = true;
                        self.raise(e, now);
                        break;
                    }
                }
            }
        }
        for (level, data) in self.hs.take_quic_crypto() {
            if let Some(s) = level.space()
                && let Some(cs) = self.crypto.get_mut(space_index(s))
            {
                cs.send.write(&data);
            }
        }
    }

    fn on_hs_event(&mut self, p: &dyn Provider, ev: HsEvent, now: Time) -> Result<()> {
        match ev {
            HsEvent::Secret(s) => {
                // OpenSSL's QUIC supports only the GCM suites and ChaCha20-Poly1305; any other
                // fails at the first secret with internal_error (quic_tls.c).
                let suite = Suite::from_cipher(s.cipher).map_err(|_| {
                    Error::crypto(
                        alert(rustyssl_abi::SSL_AD_INTERNAL_ERROR),
                        "unknown cipher type",
                    )
                })?;
                let keys = Keys::new(p, suite, s.secret.bytes())?;
                match (s.level, s.direction) {
                    (Level::Handshake, Direction::Read) => self.hs_rx = Some(keys),
                    (Level::Handshake, Direction::Write) => self.hs_tx = Some(keys),
                    (Level::Application, Direction::Read) => {
                        self.app_rx_next = Some(keys.next_phase(p)?);
                        self.app_rx = Some(keys);
                    }
                    (Level::Application, Direction::Write) => self.app_tx = Some(keys),
                    // No 0-RTT (as OpenSSL's QUIC); Initial never comes from TLS.
                    (Level::Early | Level::Initial, _) => {}
                }
            }
            HsEvent::PeerTransportParams(b) => {
                self.on_transport_params(&b)?;
                self.reset_idle(now);
                if self.is_server {
                    let tp = self.local_tp.encode()?;
                    self.hs.set_transport_params(tp);
                }
                self.hs.answer(Answer::Continue);
            }
            HsEvent::Request(r) => self.events.push_back(ChannelEvent::TlsRequest(r)),
            HsEvent::Info(e) => self.events.push_back(ChannelEvent::TlsInfo(e)),
            HsEvent::Complete => {
                // What OpenSSL's QUIC layer, not libssl, requires of the handshake: the peer's
                // transport parameters (t1_lib.c) and a negotiated protocol (quic_tls.c).
                if self.peer_tp.is_none() {
                    return Err(Error::crypto(
                        alert(rustyssl_abi::SSL_AD_MISSING_EXTENSION),
                        "missing transport parameters",
                    ));
                }
                if self.hs.alpn_selected().is_none_or(|a| a.is_empty()) {
                    return Err(Error::crypto(
                        alert(rustyssl_abi::SSL_AD_NO_APPLICATION_PROTOCOL),
                        "no application protocol negotiated",
                    ));
                }
                self.handshake_complete = true;
                self.events.push_back(ChannelEvent::HandshakeComplete);
                if self.is_server {
                    self.handshake_done_pending = true;
                    self.on_handshake_confirmed(now);
                }
            }
        }
        Ok(())
    }

    fn on_transport_params(&mut self, b: &[u8]) -> Result<()> {
        let tp = TransportParams::decode(b, !self.is_server)?;
        let expect = |ok: bool, what: &'static str| -> Result<()> {
            if ok {
                Ok(())
            } else {
                Err(Error::transport_param(what))
            }
        };
        match &tp.initial_scid {
            None => {
                return Err(Error::transport_param(
                    "INITIAL_SCID was not sent but is required",
                ));
            }
            Some(s) => expect(
                self.peer_scid.as_ref() == Some(s),
                "INITIAL_SCID does not match expected value",
            )?,
        }
        if !self.is_server {
            match &tp.original_dcid {
                None => {
                    return Err(Error::transport_param(
                        "ORIG_DCID was not sent but is required",
                    ));
                }
                Some(o) => expect(
                    *o == self.init_dcid,
                    "ORIG_DCID does not match expected value",
                )?,
            }
            match (&tp.retry_scid, &self.retry_scid) {
                (None, Some(_)) => {
                    return Err(Error::transport_param(
                        "RETRY_SCID was not sent but is required",
                    ));
                }
                (Some(_), None) => {
                    return Err(Error::transport_param(
                        "RETRY_SCID sent when not performing a retry",
                    ));
                }
                (Some(a), Some(b)) => expect(a == b, "RETRY_SCID does not match expected value")?,
                (None, None) => {}
            }
            if let Some(t) = tp.stateless_reset_token {
                self.rcid.set_initial_reset_token(t);
            }
        }
        let limits = StreamLimits {
            peer_bidi_local: tp.initial_max_stream_data_bidi_local,
            peer_bidi_remote: tp.initial_max_stream_data_bidi_remote,
            peer_uni: tp.initial_max_stream_data_uni,
        };
        self.streams.set_peer_params(
            tp.initial_max_data,
            limits,
            tp.initial_max_streams_bidi,
            tp.initial_max_streams_uni,
        );
        self.ackm.peer_max_ack_delay = Duration::from_millis(tp.max_ack_delay);
        self.ackm.peer_ack_delay_exponent = u32::try_from(tp.ack_delay_exponent).unwrap_or(20);
        self.idle_timeout_ms = match (self.idle_timeout_ms, tp.max_idle_timeout) {
            (0, x) | (x, 0) => x,
            (a, b) => a.min(b),
        };
        self.peer_tp = Some(tp);
        Ok(())
    }

    fn on_handshake_confirmed(&mut self, now: Time) {
        if self.handshake_confirmed {
            return;
        }
        self.handshake_confirmed = true;
        self.ackm.handshake_confirmed = true;
        self.discard_space(Space::Handshake);
        self.reset_ping(now);
    }

    fn discard_space(&mut self, s: Space) {
        let i = space_index(s);
        if self.discarded.get(i).copied().unwrap_or(true) {
            return;
        }
        if let Some(d) = self.discarded.get_mut(i) {
            *d = true;
        }
        match s {
            Space::Initial => self.initial_keys = None,
            Space::Handshake => {
                self.hs_rx = None;
                self.hs_tx = None;
            }
            Space::Application => {}
        }
        self.ackm.discard_space(s);
        if let Some(c) = self.crypto.get_mut(i) {
            *c = CryptoStream::default();
        }
        if let Some(n) = self.probes.get_mut(i) {
            *n = 0;
        }
    }

    // ---- receiving ----

    /// One datagram from `from` at `now` (possibly several coalesced packets).
    pub fn handle_datagram(&mut self, p: &dyn Provider, now: Time, from: &PeerAddr, data: &[u8]) {
        self.last_now = self.last_now.max(now);
        if matches!(self.state, State::Terminated | State::Draining) {
            return;
        }
        // No migration: a client drops packets from elsewhere.
        if !self.is_server && !self.peer.0.is_empty() && !from.0.is_empty() && *from != self.peer {
            return;
        }
        self.bytes_rx = self
            .bytes_rx
            .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        self.seen_path_challenge = false;
        let mut rest = data;
        let mut first_dcid: Option<ConnId> = None;
        let mut any = false;
        while !rest.is_empty() {
            let Ok((pkt, r)) = packet::locate(rest, self.local_cid.len()) else {
                break;
            };
            rest = r;
            // Every packet of a datagram has the first one's DCID (RFC 9000, 12.2).
            match &first_dcid {
                None => first_dcid = Some(pkt.dcid.clone()),
                Some(d) if *d != pkt.dcid => continue,
                Some(_) => {}
            }
            if self.handle_packet(p, now, &pkt) {
                any = true;
            }
            if self.state == State::Terminated {
                return;
            }
        }
        if any {
            if self.state == State::Closing {
                self.close_send = true;
            }
            self.pump_tls(p, now);
        }
    }

    /// Returns whether the packet was processed.
    fn handle_packet(&mut self, p: &dyn Provider, now: Time, pkt: &Located<'_>) -> bool {
        match pkt.ty {
            PacketType::VersionNegotiation => {
                self.on_version_negotiation(pkt, now);
                return false;
            }
            PacketType::Retry => {
                self.on_retry(p, pkt, now);
                return false;
            }
            PacketType::ZeroRtt => return false,
            _ => {}
        }
        if pkt.version != packet::VERSION_1 {
            return false;
        }
        let Some(space) = pkt.ty.space() else {
            return false;
        };
        if self
            .discarded
            .get(space_index(space))
            .copied()
            .unwrap_or(true)
        {
            return false;
        }
        // A client keeps to the server's SCID from its first Initial.
        if !self.is_server
            && self.got_enc_packet
            && pkt.ty != PacketType::OneRtt
            && self.peer_scid.as_ref() != Some(&pkt.scid)
        {
            return false;
        }
        let largest = self.ackm.largest_received(space);
        let opened = match self.unprotect(p, pkt, space, largest, now) {
            Ok(Some(o)) => o,
            Ok(None) => {
                if !self.has_rx_keys(space) && self.deferred.len() < MAX_DEFERRED {
                    self.deferred.push_back(pkt.bytes.to_vec());
                }
                return false;
            }
            Err(e) => {
                self.raise(e, now);
                return false;
            }
        };
        if !self.ackm.is_processable(space, opened.pn) {
            return false;
        }
        if !self.got_enc_packet && !self.is_server {
            self.got_enc_packet = true;
            self.peer_scid = Some(pkt.scid.clone());
            self.rcid.set_initial(pkt.scid.clone());
        }
        self.have_processed_any = true;
        if self.is_server && pkt.ty == PacketType::Handshake {
            // A Handshake packet validates the client's address and ends Initial.
            self.address_validated = true;
            self.discard_space(Space::Initial);
        }
        let eliciting = match self.process_frames(p, pkt.ty, space, &opened.payload, now) {
            Ok(e) => e,
            Err(e) => {
                self.raise(e, now);
                return true;
            }
        };
        if self.state == State::Active || self.state == State::Closing {
            self.ackm
                .on_packet_received(space, opened.pn, eliciting, now);
        }
        self.reset_idle(now);
        self.sent_eliciting_since_rx = false;
        true
    }

    fn unprotect(
        &mut self,
        p: &dyn Provider,
        pkt: &Located<'_>,
        space: Space,
        largest: Option<u64>,
        now: Time,
    ) -> Result<Option<packet::Opened>> {
        match space {
            Space::Initial => match self.initial_keys.as_mut() {
                Some((_, rx)) => packet::unprotect(rx, pkt.bytes, pkt.pn_offset, largest),
                None => Ok(None),
            },
            Space::Handshake => match self.hs_rx.as_mut() {
                Some(rx) => packet::unprotect(rx, pkt.bytes, pkt.pn_offset, largest),
                None => Ok(None),
            },
            Space::Application => self.unprotect_app(p, pkt, largest, now),
        }
    }

    fn unprotect_app(
        &mut self,
        p: &dyn Provider,
        pkt: &Located<'_>,
        largest: Option<u64>,
        now: Time,
    ) -> Result<Option<packet::Opened>> {
        let Some(cur) = self.app_rx.as_mut() else {
            return Ok(None);
        };
        // Learn the key phase bit under header protection (the same key in every phase).
        let Ok((_, header)) = packet::remove_header_protection(cur.hp(), pkt.bytes, pkt.pn_offset)
        else {
            return Ok(None);
        };
        let phase = header.first().is_some_and(|f| f & 0x04 != 0);
        let opened = if phase == self.app_rx_phase {
            packet::unprotect(cur, pkt.bytes, pkt.pn_offset, largest)?
        } else if let Some(prev) = self.app_rx_prev.as_mut() {
            // Still updating: the old phase's packets.
            packet::unprotect(prev, pkt.bytes, pkt.pn_offset, largest)?
        } else if let Some(next) = self.app_rx_next.as_mut() {
            let o = packet::unprotect(next, pkt.bytes, pkt.pn_offset, largest)?;
            if let Some(o) = &o {
                self.on_rxku(p, o.pn, now)?;
            }
            o
        } else {
            None
        };
        if opened.is_none() {
            self.forged = self.forged.saturating_add(1);
            let limit = self
                .app_rx
                .as_ref()
                .map_or(u64::MAX, |k| k.suite.integrity_limit());
            if self.forged >= limit {
                return Err(Error::new(
                    rustyssl_abi::OSSL_QUIC_ERR_AEAD_LIMIT_REACHED,
                    0,
                    "forgery limit",
                ));
            }
        }
        Ok(opened)
    }

    fn on_rxku(&mut self, p: &dyn Provider, pn: u64, now: Time) -> Result<()> {
        if !self.handshake_confirmed || self.rxku_pending_confirm {
            return Err(Error::new(
                rustyssl_abi::OSSL_QUIC_ERR_KEY_UPDATE_ERROR,
                0,
                "RX key update again too soon",
            ));
        }
        let next = self.app_rx_next.take();
        self.app_rx_prev = self.app_rx.take();
        self.app_rx = next;
        self.app_rx_phase = !self.app_rx_phase;
        self.rxku_in_progress = true;
        self.rxku_pending_confirm = true;
        self.rxku_trigger_pn = pn;
        self.rxku_update_end = Some(now.add(self.ackm.pto_duration()));
        if !self.ku_locally_initiated {
            self.trigger_txku(p)?;
        }
        self.ku_locally_initiated = false;
        // Treat the update as ACK-eliciting so the peer learns of it soon (as OpenSSL).
        self.ackm.force_ack(Space::Application);
        Ok(())
    }

    fn rxku_tick(&mut self, p: &dyn Provider, now: Time) -> Result<()> {
        if self.rxku_in_progress && self.rxku_update_end.is_some_and(|d| now >= d) {
            self.rxku_in_progress = false;
            self.rxku_update_end = None;
            self.app_rx_prev = None;
            if let Some(cur) = &self.app_rx {
                self.app_rx_next = Some(cur.next_phase(p)?);
            }
        }
        Ok(())
    }

    fn txku_in_progress(&mut self, now: Time) -> bool {
        if self.txku_in_progress
            && self
                .ackm
                .largest_acked(Space::Application)
                .is_some_and(|l| l >= self.txku_pn)
        {
            self.txku_in_progress = false;
            self.txku_cooldown = now.add(self.ackm.pto_duration().mul(3));
        }
        self.txku_in_progress
    }

    fn trigger_txku(&mut self, p: &dyn Provider) -> Result<()> {
        let Some(tx) = &self.app_tx else {
            return Err(Error::internal("key update"));
        };
        let next = tx.next_phase(p)?;
        self.app_tx = Some(next);
        self.app_tx_phase = !self.app_tx_phase;
        self.tx_epoch_pkts = 0;
        self.txku_in_progress = true;
        self.txku_pn = self.ackm.next_pn(Space::Application);
        Ok(())
    }

    /// Starts a key update (`SSL_key_update`): only once the handshake is confirmed and no
    /// update is in progress.
    ///
    /// # Errors
    /// An update isn't allowed now.
    pub fn key_update(&mut self, p: &dyn Provider, now: Time) -> Result<()> {
        if !self.handshake_confirmed || self.app_tx.is_none() || self.txku_in_progress(now) {
            return Err(Error::internal("key update not allowed"));
        }
        self.ku_locally_initiated = true;
        self.trigger_txku(p)
    }

    fn maybe_spontaneous_txku(&mut self, p: &dyn Provider, now: Time) -> Result<()> {
        let Some(tx) = &self.app_tx else {
            return Ok(());
        };
        let threshold = tx.suite.confidentiality_limit() / 2;
        if self.handshake_confirmed
            && !self.txku_in_progress(now)
            && now >= self.txku_cooldown
            && !self.rxku_in_progress
            && !self.rxku_pending_confirm
            && self.tx_epoch_pkts >= threshold
        {
            self.ku_locally_initiated = true;
            self.trigger_txku(p)?;
        }
        Ok(())
    }

    fn on_version_negotiation(&mut self, pkt: &Located<'_>, now: Time) {
        if self.is_server || self.have_processed_any {
            return;
        }
        self.have_processed_any = true;
        let offers_v1 = pkt
            .token
            .as_chunks::<4>()
            .0
            .iter()
            .any(|v| *v == packet::VERSION_1.to_be_bytes());
        if offers_v1 {
            // We sent v1 already: nothing to restart to (OpenSSL restarts with the same version).
            return;
        }
        self.raise(
            Error::new(
                rustyssl_abi::OSSL_QUIC_ERR_CONNECTION_REFUSED,
                0,
                "unsupported protocol version",
            ),
            now,
        );
    }

    fn on_retry(&mut self, p: &dyn Provider, pkt: &Located<'_>, now: Time) {
        // A client takes one Retry, before any other packet from the server.
        if self.is_server || self.retry_scid.is_some() || self.got_enc_packet {
            return;
        }
        if pkt.token.is_empty() || !packet::retry_tag_valid(p, &self.init_dcid, pkt.bytes) {
            return;
        }
        // A Retry whose SCID is the DCID we used is dropped (RFC 9000, 17.2.5.2).
        if pkt.scid == self.rcid.cur {
            return;
        }
        let Ok(keys) = packet::initial_keys(p, pkt.scid.as_bytes()) else {
            self.raise(Error::internal("retry keys"), now);
            return;
        };
        self.initial_keys = Some(keys);
        self.retry_scid = Some(pkt.scid.clone());
        self.rcid.set_initial(pkt.scid.clone());
        self.token = pkt.token.to_vec();
        // Everything sent in Initial goes again, under the new keys (OpenSSL's pseudo-loss).
        for sp in self.ackm.pseudo_lose_all(Space::Initial) {
            self.on_frames_lost(Space::Initial, &sp.info);
        }
    }

    /// Processes a packet's frames; returns whether any was ACK-eliciting.
    #[allow(
        clippy::too_many_lines,
        reason = "one match over every frame type, as OpenSSL's"
    )]
    fn process_frames(
        &mut self,
        p: &dyn Provider,
        ty: PacketType,
        space: Space,
        payload: &[u8],
        now: Time,
    ) -> Result<bool> {
        if payload.is_empty() {
            return Err(Error::protocol(0, "empty packet payload"));
        }
        let one_rtt = ty == PacketType::OneRtt;
        let app = matches!(ty, PacketType::OneRtt | PacketType::ZeroRtt);
        let mut r = rustyssl_tls::codec::Reader::new(payload);
        let mut eliciting = false;
        while !r.is_empty() {
            let (t, minimal) = wire::peek_frame_type(&r)
                .map_err(|_| Error::protocol(0, "malformed frame header"))?;
            if !minimal {
                return Err(Error::protocol(t, "non-minimal frame type encoding"));
            }
            let only_app = |what: &'static str| -> Result<()> {
                if app {
                    Ok(())
                } else {
                    Err(Error::protocol(t, what))
                }
            };
            let only_1rtt = |what: &'static str| -> Result<()> {
                if one_rtt {
                    Ok(())
                } else {
                    Err(Error::protocol(t, what))
                }
            };
            // Permission checks come before decoding, as OpenSSL's.
            match t {
                ft::RESET_STREAM => only_app("RESET_STREAM not valid in INITIAL/HANDSHAKE")?,
                ft::STOP_SENDING => only_app("STOP_SENDING not valid in INITIAL/HANDSHAKE")?,
                ft::NEW_TOKEN => only_1rtt("NEW_TOKEN valid only in 1-RTT")?,
                ft::STREAM..=ft::STREAM_MAX => only_app("STREAM valid only in 0/1-RTT")?,
                ft::MAX_DATA => only_app("MAX_DATA valid only in 0/1-RTT")?,
                ft::MAX_STREAM_DATA => only_app("MAX_STREAM_DATA valid only in 0/1-RTT")?,
                ft::MAX_STREAMS_BIDI | ft::MAX_STREAMS_UNI => {
                    only_app("MAX_STREAMS valid only in 0/1-RTT")?;
                }
                ft::DATA_BLOCKED => only_app("DATA_BLOCKED valid only in 0/1-RTT")?,
                ft::STREAM_DATA_BLOCKED => {
                    only_app("STREAM_DATA_BLOCKED valid only in 0/1-RTT")?;
                }
                ft::STREAMS_BLOCKED_BIDI | ft::STREAMS_BLOCKED_UNI => {
                    only_app("STREAMS valid only in 0/1-RTT")?;
                }
                ft::NEW_CONNECTION_ID => only_app("NEW_CONN_ID valid only in 0/1-RTT")?,
                ft::RETIRE_CONNECTION_ID => only_app("RETIRE_CONN_ID valid only in 0/1-RTT")?,
                ft::PATH_CHALLENGE => only_app("PATH_CHALLENGE valid only in 0/1-RTT")?,
                // OpenSSL's text for PATH_RESPONSE.
                ft::PATH_RESPONSE => only_1rtt("PATH_CHALLENGE valid only in 1-RTT")?,
                ft::CONNECTION_CLOSE_APP => only_app("CONN_CLOSE (APP) valid only in 0/1-RTT")?,
                ft::HANDSHAKE_DONE => only_1rtt("HANDSHAKE_DONE valid only in 1-RTT")?,
                ft::ACK | ft::ACK_ECN if ty == PacketType::ZeroRtt => {
                    return Err(Error::protocol(t, "ACK not valid in 0-RTT"));
                }
                ft::CRYPTO if ty == PacketType::ZeroRtt => {
                    return Err(Error::protocol(t, "CRYPTO frame not valid in 0-RTT"));
                }
                ft::PADDING
                | ft::PING
                | ft::ACK
                | ft::ACK_ECN
                | ft::CRYPTO
                | ft::CONNECTION_CLOSE => {}
                _ => {
                    return Err(Error::new(
                        rustyssl_abi::OSSL_QUIC_ERR_FRAME_ENCODING_ERROR,
                        t,
                        "Unknown frame type received",
                    ));
                }
            }
            let f = wire::decode_frame(&mut r)?;
            if f.is_ack_eliciting() {
                eliciting = true;
            }
            self.on_frame(p, f, space, now)?;
            if self.state != State::Active {
                break;
            }
        }
        Ok(eliciting)
    }

    fn on_frame(&mut self, p: &dyn Provider, f: Frame<'_>, space: Space, now: Time) -> Result<()> {
        match f {
            Frame::Padding(_) | Frame::Ping | Frame::PathResponse(_) => {}
            Frame::Ack {
                ranges, ack_delay, ..
            } => {
                let out = self
                    .ackm
                    .on_ack_received(space, &ranges, ack_delay, ft::ACK, now)?;
                for sp in &out.acked {
                    self.on_frames_acked(space, &sp.info);
                }
                for sp in &out.lost {
                    self.on_frames_lost(space, &sp.info);
                }
            }
            Frame::Crypto { offset, data } => {
                let i = space_index(space);
                let cs = self
                    .crypto
                    .get_mut(i)
                    .ok_or_else(|| Error::internal("crypto stream"))?;
                cs.on_frame(offset, data)?;
                let readable = cs.take_readable(now);
                if !readable.is_empty() && !self.hs_failed {
                    if let Err(e) = self.hs.feed_quic_crypto(Level::of_space(space), &readable) {
                        self.hs_failed = true;
                        return Err(e);
                    }
                    self.pump_tls(p, now);
                }
            }
            Frame::NewToken { token } => {
                if self.is_server {
                    return Err(Error::protocol(
                        ft::NEW_TOKEN,
                        "NEW_TOKEN can only be sent by a server",
                    ));
                }
                if token.is_empty() {
                    return Err(Error::new(
                        rustyssl_abi::OSSL_QUIC_ERR_FRAME_ENCODING_ERROR,
                        ft::NEW_TOKEN,
                        "zero-length NEW_TOKEN",
                    ));
                }
                self.events
                    .push_back(ChannelEvent::NewToken(token.to_vec()));
            }
            Frame::ResetStream {
                id,
                code,
                final_size,
            } => self.streams.on_reset_stream(id, code, final_size)?,
            Frame::StopSending { id, code } => self.streams.on_stop_sending(id, code)?,
            Frame::Stream {
                id,
                offset,
                data,
                fin,
            } => {
                let t = ft::STREAM | if offset != 0 { 0x04 } else { 0 } | 0x02 | u64::from(fin);
                self.streams.on_stream(t, id, offset, data, fin)?;
            }
            Frame::MaxData(m) => self.streams.on_max_data(m),
            Frame::MaxStreamData { id, max } => self.streams.on_max_stream_data(id, max)?,
            Frame::MaxStreams { bidi, max } => self.streams.on_max_streams(bidi, max)?,
            Frame::DataBlocked(_) => {}
            Frame::StreamDataBlocked { id, .. } => self.streams.on_stream_data_blocked(id)?,
            Frame::StreamsBlocked { bidi, limit } => {
                self.streams.on_streams_blocked(bidi, limit)?
            }
            Frame::NewConnectionId {
                seq,
                retire_prior_to,
                cid,
                reset_token,
            } => self
                .rcid
                .on_new_conn_id(seq, retire_prior_to, cid, reset_token)?,
            Frame::RetireConnectionId(_) => cid::on_retire_conn_id(self.is_server)?,
            Frame::PathChallenge(d) => {
                if !self.seen_path_challenge && self.path_responses.len() < PATH_RESPONSE_QLEN {
                    self.path_responses.push_back(d);
                    self.seen_path_challenge = true;
                }
            }
            Frame::ConnectionClose {
                app,
                code,
                frame_type,
                reason,
            } => {
                self.start_terminating(
                    TerminateCause {
                        remote: true,
                        app,
                        code,
                        frame_type,
                        reason: reason.to_vec(),
                    },
                    false,
                    now,
                );
            }
            Frame::HandshakeDone => {
                if !self.handshake_complete {
                    return Err(Error::protocol(
                        ft::HANDSHAKE_DONE,
                        "handshake cannot be confirmed before it is completed",
                    ));
                }
                self.on_handshake_confirmed(now);
            }
        }
        Ok(())
    }

    fn on_frames_acked(&mut self, space: Space, info: &SentInfo) {
        for f in &info.frames {
            match f {
                SentFrame::Crypto { offset, len } => {
                    if let Some(cs) = self.crypto.get_mut(space_index(space)) {
                        cs.send.on_acked(*offset, *len, false);
                    }
                }
                SentFrame::Stream {
                    id,
                    offset,
                    len,
                    fin,
                } => self.streams.on_stream_acked(*id, *offset, *len, *fin),
                SentFrame::ResetStream(id) => self.streams.on_reset_acked(*id),
                SentFrame::StopSending(id) => self.streams.on_stop_sending_acked(*id),
                _ => {}
            }
        }
    }

    fn on_frames_lost(&mut self, space: Space, info: &SentInfo) {
        for f in &info.frames {
            match f {
                SentFrame::Crypto { offset, len } => {
                    if let Some(cs) = self.crypto.get_mut(space_index(space)) {
                        cs.send.on_lost(*offset, *len, false);
                    }
                }
                SentFrame::Stream {
                    id,
                    offset,
                    len,
                    fin,
                } => self.streams.on_stream_lost(*id, *offset, *len, *fin),
                SentFrame::ResetStream(id) => self.streams.on_reset_lost(*id),
                SentFrame::StopSending(id) => self.streams.on_stop_sending_lost(*id),
                SentFrame::MaxData => self.streams.lost_max_data(),
                SentFrame::MaxStreamData(id) => self.streams.on_max_stream_data_lost(*id),
                SentFrame::MaxStreams { bidi } => self.streams.lost_max_streams(*bidi),
                SentFrame::RetireConnectionId(seq) => self.rcid.retire_lost(*seq),
                SentFrame::NewToken(t) => {
                    if self.new_token.is_none() {
                        self.new_token = Some(t.clone());
                    }
                }
                SentFrame::HandshakeDone => self.handshake_done_pending = true,
                SentFrame::Ack(_)
                | SentFrame::DataBlocked
                | SentFrame::StreamDataBlocked(_)
                | SentFrame::StreamsBlocked { .. }
                | SentFrame::Unreliable => {}
            }
        }
    }

    // ---- timers ----

    /// When [`Channel::handle_timeout`] next needs to run.
    #[must_use]
    pub fn next_timeout(&self, now: Time) -> Option<Time> {
        match self.state {
            State::Terminated => return None,
            State::Closing | State::Draining => return self.terminate_deadline,
            State::Active => {}
        }
        let mut t = earliest(self.idle_deadline, self.ackm.loss_detection_deadline(now));
        for s in Space::ALL {
            if self.has_tx_keys(s) {
                t = earliest(t, self.ackm.ack_deadline(s));
            }
        }
        if self.app_tx.is_some() && self.handshake_complete {
            t = earliest(t, self.ping_deadline);
        }
        earliest(t, self.rxku_update_end)
    }

    /// Runs the timers due at `now`.
    pub fn handle_timeout(&mut self, p: &dyn Provider, now: Time) {
        self.last_now = self.last_now.max(now);
        match self.state {
            State::Terminated => return,
            State::Closing | State::Draining => {
                if self.terminate_deadline.is_some_and(|d| now >= d) {
                    self.set_state(State::Terminated);
                }
                return;
            }
            State::Active => {}
        }
        if self.idle_deadline.is_some_and(|d| now >= d) {
            let cause = TerminateCause {
                remote: false,
                app: false,
                code: crate::error::local_err_idle_timeout(),
                frame_type: 0,
                reason: Vec::new(),
            };
            self.terminate_cause = Some(cause.clone());
            self.events.push_back(ChannelEvent::Terminated(cause));
            self.set_state(State::Terminated);
            return;
        }
        if let Err(e) = self.rxku_tick(p, now) {
            self.raise(e, now);
            return;
        }
        if self
            .ackm
            .loss_detection_deadline(now)
            .is_some_and(|d| now >= d)
        {
            match self.ackm.on_timeout(now) {
                Timeout::Lost(space, lost) => {
                    for sp in &lost {
                        self.on_frames_lost(space, &sp.info);
                    }
                }
                Timeout::Probe(s) => {
                    let i = space_index(s);
                    if let Some(n) = self.probes.get_mut(i) {
                        *n = PROBES_PER_PTO;
                    }
                    // Send the unacknowledged data again in the probes.
                    for sp in self.ackm.unacked(s) {
                        self.on_frames_lost(s, &sp.info);
                    }
                }
                Timeout::None => {}
            }
        }
        if self.ping_deadline.is_some_and(|d| now >= d) && self.handshake_complete {
            self.ping_now = true;
            self.ping_deadline = None;
        }
    }

    fn has_tx_keys(&self, s: Space) -> bool {
        match s {
            Space::Initial => self.initial_keys.is_some(),
            Space::Handshake => self.hs_tx.is_some(),
            Space::Application => self.app_tx.is_some(),
        }
    }

    // ---- the application's streams ----

    /// Opens a stream; `None` when the peer's limit is reached.
    pub fn stream_open(&mut self, bidi: bool) -> Option<u64> {
        if self.state != State::Active {
            return None;
        }
        self.streams.open(bidi)
    }

    /// Writes to a stream.
    ///
    /// # Errors
    /// The stream can't be written.
    pub fn stream_send(&mut self, id: u64, data: &[u8], fin: bool) -> Result<usize> {
        if self.state != State::Active {
            return Err(Error::internal("connection terminating"));
        }
        self.streams.send(id, data, fin)
    }

    /// Reads from a stream: the octets read and whether its end was reached.
    ///
    /// # Errors
    /// The stream can't be read, or was reset.
    pub fn stream_recv(&mut self, id: u64, buf: &mut [u8], now: Time) -> Result<(usize, bool)> {
        let rtt = self.ackm.rtt.smoothed;
        self.streams.recv(id, buf, now, rtt)
    }

    /// Resets a stream's sending part.
    ///
    /// # Errors
    /// The stream has no sending part.
    pub fn stream_reset(&mut self, id: u64, code: u64) -> Result<()> {
        self.streams.reset(id, code)
    }

    /// Asks the peer to stop sending on a stream.
    ///
    /// # Errors
    /// The stream has no receiving part.
    pub fn stream_stop_sending(&mut self, id: u64, code: u64) -> Result<()> {
        self.streams.stop_sending(id, code)
    }

    /// Lets go of a stream (`SSL_free` on a stream object).
    pub fn stream_release(&mut self, id: u64) {
        self.streams.release(id);
    }

    /// The next incoming stream.
    pub fn accept_stream(&mut self, now: Time) -> Option<u64> {
        self.streams.accept(now)
    }

    /// The streams, mutably (for the API's per-stream settings).
    pub fn streams_mut(&mut self) -> &mut StreamMap {
        &mut self.streams
    }

    /// Our max_idle_timeout request, in milliseconds.
    #[must_use]
    pub fn idle_timeout_request(&self) -> u64 {
        self.local_tp.max_idle_timeout
    }

    /// The peer's max_idle_timeout request, once its parameters arrived.
    #[must_use]
    pub fn idle_timeout_peer_request(&self) -> Option<u64> {
        self.peer_tp.as_ref().map(|t| t.max_idle_timeout)
    }

    /// The idle timeout in force (negotiated once the peer's parameters arrived), in
    /// milliseconds; 0 for none.
    #[must_use]
    pub fn idle_timeout_actual(&self) -> u64 {
        self.idle_timeout_ms
    }

    /// The next incoming stream of one direction.
    pub fn accept_stream_of(&mut self, uni: bool, now: Time) -> Option<u64> {
        self.streams.accept_of(uni, now)
    }

    /// Takes an incoming stream out of the accept queue (it became the default stream).
    pub fn remove_from_accept_queue(&mut self, id: u64, now: Time) {
        self.streams.remove_from_accept_queue(id, now);
    }

    /// Copies what [`Channel::stream_recv`] would read, leaving it.
    ///
    /// # Errors
    /// The stream can't be read, or was reset.
    pub fn stream_peek(&self, id: u64, buf: &mut [u8]) -> Result<(usize, bool)> {
        self.streams.peek(id, buf)
    }

    // ---- sending ----

    fn amplification_room(&self) -> usize {
        if self.address_validated {
            return usize::MAX;
        }
        let allowed = self
            .bytes_rx
            .saturating_mul(3)
            .saturating_sub(self.bytes_tx);
        usize::try_from(allowed).unwrap_or(usize::MAX)
    }

    /// The next datagram to send, if any.
    pub fn poll_transmit(&mut self, p: &dyn Provider, now: Time) -> Option<Vec<u8>> {
        match self.state {
            State::Terminated | State::Draining => return None,
            State::Closing if !self.close_send => return None,
            _ => {}
        }
        if let Err(e) = self.maybe_spontaneous_txku(p, now) {
            self.raise(e, now);
        }
        match self.build_datagram(now) {
            Ok(d) => d,
            Err(e) => {
                self.raise(e, now);
                None
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the packetiser's one pass over the spaces"
    )]
    fn build_datagram(&mut self, now: Time) -> Result<Option<Vec<u8>>> {
        let limit = MAX_DGRAM.min(self.amplification_room());
        if limit < MIN_PACKET_ROOM {
            return Ok(None);
        }
        let closing = self.state == State::Closing;
        let cc_ok = self.ackm.cc.tx_allowance() >= u64::try_from(MAX_DGRAM).unwrap_or(u64::MAX);
        let dcid = self.rcid.cur.clone();
        let scid = self.local_cid.clone();
        let client_token = if self.is_server {
            Vec::new()
        } else {
            self.token.clone()
        };
        struct Built {
            space: Space,
            ty: PacketType,
            pn: u64,
            pn_len: usize,
            payload: PayloadBuilder,
        }
        let mut built: Vec<Built> = Vec::new();
        let mut used = 0usize;
        for s in Space::ALL {
            if !self.has_tx_keys(s) {
                continue;
            }
            let ty = match s {
                Space::Initial => PacketType::Initial,
                Space::Handshake => PacketType::Handshake,
                Space::Application => PacketType::OneRtt,
            };
            // 1-RTT only once the handshake completed (a server may send 0.5-RTT, but has
            // nothing to send then; a client must wait).
            if s == Space::Application && !self.handshake_complete && !closing {
                continue;
            }
            let pn = self.ackm.next_pn(s);
            let pn_len = packet::pn_len(pn, self.ackm.largest_acked(s));
            let token: &[u8] = if s == Space::Initial {
                &client_token
            } else {
                &[]
            };
            let o = Outgoing {
                ty,
                dcid: &dcid,
                scid: &scid,
                token,
                pn,
                pn_len,
                key_phase: self.app_tx_phase,
            };
            let room = limit.saturating_sub(used);
            let hdr = packet::header_len(&o, room);
            let payload_room = room.saturating_sub(hdr).saturating_sub(TAG_LEN);
            if payload_room < 8 {
                break;
            }
            let mut b = PayloadBuilder::new(payload_room);
            self.fill(&mut b, s, now, closing, cc_ok)?;
            if b.is_empty() {
                continue;
            }
            // Room to sample: packet number plus payload at least 4 octets.
            if pn_len.saturating_add(b.len()) < 4 {
                b.pad_to(4usize.saturating_sub(pn_len));
            }
            used = used
                .saturating_add(packet::header_len(&o, b.len()))
                .saturating_add(b.len())
                .saturating_add(TAG_LEN);
            built.push(Built {
                space: s,
                ty,
                pn,
                pn_len,
                payload: b,
            });
            if ty == PacketType::OneRtt {
                break;
            }
        }
        if built.is_empty() {
            return Ok(None);
        }
        // Datagrams with a client's Initial, or a server's ack-eliciting Initial, are padded to
        // 1200 octets (RFC 9000, 14.1); the last packet takes the padding.
        let needs_pad = built
            .iter()
            .any(|b| b.ty == PacketType::Initial && (!self.is_server || b.payload.ack_eliciting));
        if needs_pad
            && used < MAX_DGRAM
            && limit >= MAX_DGRAM
            && let Some(last) = built.last_mut()
        {
            {
                let token: &[u8] = if last.space == Space::Initial {
                    &client_token
                } else {
                    &[]
                };
                let o = Outgoing {
                    ty: last.ty,
                    dcid: &dcid,
                    scid: &scid,
                    token,
                    pn: last.pn,
                    pn_len: last.pn_len,
                    key_phase: self.app_tx_phase,
                };
                let before = packet::header_len(&o, last.payload.len())
                    .saturating_add(last.payload.len())
                    .saturating_add(TAG_LEN);
                let others = used.saturating_sub(before);
                let mut target = last
                    .payload
                    .len()
                    .saturating_add(MAX_DGRAM.saturating_sub(used));
                // A longer payload can lengthen the Length field; settle it.
                loop {
                    let total = others
                        .saturating_add(packet::header_len(&o, target))
                        .saturating_add(target)
                        .saturating_add(TAG_LEN);
                    if total > MAX_DGRAM && target > last.payload.len() {
                        target = target.saturating_sub(1);
                    } else {
                        break;
                    }
                }
                last.payload.grow_limit(target);
                last.payload.pad_to(target);
            }
        }
        let mut out = Vec::with_capacity(MAX_DGRAM);
        let mut sent_handshake = false;
        for b in built {
            let start = out.len();
            let (payload, info, eliciting, in_flight) = b.payload.into_parts();
            let token: &[u8] = if b.space == Space::Initial {
                &client_token
            } else {
                &[]
            };
            let o = Outgoing {
                ty: b.ty,
                dcid: &dcid,
                scid: &scid,
                token,
                pn: b.pn,
                pn_len: b.pn_len,
                key_phase: self.app_tx_phase,
            };
            let keys = match b.space {
                Space::Initial => self.initial_keys.as_mut().map(|(tx, _)| tx),
                Space::Handshake => self.hs_tx.as_mut(),
                Space::Application => self.app_tx.as_mut(),
            }
            .ok_or_else(|| Error::internal("no keys"))?;
            packet::protect(keys, &o, &payload, &mut out)?;
            if b.space == Space::Application {
                self.tx_epoch_pkts = self.tx_epoch_pkts.saturating_add(1);
            }
            if b.space == Space::Handshake {
                sent_handshake = true;
            }
            let ack_largest = info.frames.iter().find_map(|f| match f {
                SentFrame::Ack(l) => Some(*l),
                _ => None,
            });
            let size = u64::try_from(out.len().saturating_sub(start)).unwrap_or(u64::MAX);
            if !closing {
                self.ackm.on_packet_sent(
                    b.space,
                    SentPacket {
                        pn: b.pn,
                        time: now,
                        size,
                        ack_eliciting: eliciting,
                        in_flight,
                        ack_largest,
                        info,
                    },
                )?;
            }
            if eliciting {
                if !self.sent_eliciting_since_rx {
                    self.reset_idle(now);
                    self.sent_eliciting_since_rx = true;
                }
                if self.handshake_complete {
                    self.reset_ping(now);
                }
            }
        }
        self.have_sent_any = true;
        self.bytes_tx = self
            .bytes_tx
            .saturating_add(u64::try_from(out.len()).unwrap_or(u64::MAX));
        if closing {
            self.close_send = false;
        }
        // A client discards its Initial keys once it sends a Handshake packet.
        if sent_handshake && !self.is_server {
            self.discard_space(Space::Initial);
        }
        Ok(Some(out))
    }

    /// Fills one packet's payload for space `s`.
    #[allow(
        clippy::too_many_lines,
        reason = "every frame source in OpenSSL's order"
    )]
    fn fill(
        &mut self,
        b: &mut PayloadBuilder,
        s: Space,
        now: Time,
        closing: bool,
        cc_ok: bool,
    ) -> Result<()> {
        let i = space_index(s);
        let probing = self.probes.get(i).copied().unwrap_or(0) > 0;
        // ACK first: when one is due, or alongside anything else we send.
        let ack_due = self.ackm.ack_desired(s, now);
        let crypto_pending = self
            .crypto
            .get(i)
            .is_some_and(|c| c.send.has_pending(u64::MAX));
        let others_pending = crypto_pending
            || probing
            || (s == Space::Application && (self.app_frames_pending() || self.ping_now));
        if self.ackm.has_ack(s) && (ack_due || (others_pending && (cc_ok || probing))) {
            let exp = u32::try_from(self.local_tp.ack_delay_exponent).unwrap_or(3);
            if let Some((ranges, delay)) = self.ackm.ack_frame(s, now, exp) {
                let largest = ranges.first().map_or(0, |r| r.end);
                let f = Frame::Ack {
                    ranges,
                    ack_delay: delay,
                    ecn: None,
                };
                b.push(&f, SentFrame::Ack(largest))?;
                if s == Space::Application
                    && self.rxku_pending_confirm
                    && largest >= self.rxku_trigger_pn
                {
                    self.rxku_pending_confirm = false;
                }
            }
        }
        if closing {
            if let Some(c) = self.terminate_cause.clone() {
                // Before 1-RTT an application close goes as APPLICATION_ERROR (RFC 9000, 10.2.3).
                let (app, code, reason) = if c.app && s != Space::Application {
                    (
                        false,
                        crate::error::code(rustyssl_abi::OSSL_QUIC_ERR_APPLICATION_ERROR),
                        Vec::new(),
                    )
                } else {
                    (c.app, c.code, c.reason.clone())
                };
                let max_reason = b.room().saturating_sub(24);
                let reason = reason.get(..reason.len().min(max_reason)).unwrap_or(&[]);
                b.push(
                    &Frame::ConnectionClose {
                        app,
                        code,
                        frame_type: if app { 0 } else { c.frame_type },
                        reason,
                    },
                    SentFrame::Unreliable,
                )?;
            }
            return Ok(());
        }
        if !cc_ok && !probing {
            return Ok(());
        }
        if s == Space::Application {
            self.fill_app_control(b)?;
        }
        // CRYPTO.
        if let Some(cs) = self.crypto.get_mut(i) {
            loop {
                let room = b.room();
                if room < 16 {
                    break;
                }
                let max = room.saturating_sub(wire::crypto_header_len(cs.send.sent_end(), room));
                let Some(c) = cs.send.next_chunk(max, u64::MAX) else {
                    break;
                };
                if c.data.is_empty() {
                    break;
                }
                let len = u64::try_from(c.data.len()).unwrap_or(u64::MAX);
                let f = Frame::Crypto {
                    offset: c.offset,
                    data: &c.data,
                };
                if !b.push(
                    &f,
                    SentFrame::Crypto {
                        offset: c.offset,
                        len,
                    },
                )? {
                    cs.send.on_lost(c.offset, len, false);
                    break;
                }
            }
        }
        if s == Space::Application {
            self.fill_streams(b)?;
            if self.ping_now && !b.ack_eliciting {
                b.push(&Frame::Ping, SentFrame::Unreliable)?;
            }
            if b.ack_eliciting {
                self.ping_now = false;
            }
        }
        if probing && !b.ack_eliciting {
            b.push(&Frame::Ping, SentFrame::Unreliable)?;
        }
        if b.ack_eliciting
            && let Some(n) = self.probes.get_mut(i)
            && *n > 0
        {
            *n = n.saturating_sub(1);
        }
        Ok(())
    }

    fn app_frames_pending(&self) -> bool {
        self.handshake_done_pending
            || self.new_token.is_some()
            || !self.path_responses.is_empty()
            || self.rcid.has_retire()
            || !self.streams.active().is_empty()
    }

    fn fill_app_control(&mut self, b: &mut PayloadBuilder) -> Result<()> {
        if self.handshake_done_pending && b.push(&Frame::HandshakeDone, SentFrame::HandshakeDone)? {
            self.handshake_done_pending = false;
        }
        while let Some(d) = self.path_responses.front().copied() {
            if !b.push(&Frame::PathResponse(d), SentFrame::Unreliable)? {
                break;
            }
            self.path_responses.pop_front();
        }
        if let Some(m) = self.streams.take_max_data()
            && !b.push(&Frame::MaxData(m), SentFrame::MaxData)?
        {
            self.streams.lost_max_data();
        }
        for bidi in [true, false] {
            if let Some(m) = self.streams.take_max_streams(bidi)
                && !b.push(
                    &Frame::MaxStreams { bidi, max: m },
                    SentFrame::MaxStreams { bidi },
                )?
            {
                self.streams.lost_max_streams(bidi);
            }
            if let Some(l) = self.streams.take_streams_blocked(bidi) {
                b.push(
                    &Frame::StreamsBlocked { bidi, limit: l },
                    SentFrame::StreamsBlocked { bidi },
                )?;
            }
        }
        if let Some(l) = self.streams.take_data_blocked() {
            b.push(&Frame::DataBlocked(l), SentFrame::DataBlocked)?;
        }
        while let Some(seq) = self.rcid.take_retire() {
            if !b.push(
                &Frame::RetireConnectionId(seq),
                SentFrame::RetireConnectionId(seq),
            )? {
                self.rcid.retire_lost(seq);
                break;
            }
        }
        if let Some(t) = self.new_token.take()
            && !b.push(
                &Frame::NewToken { token: &t },
                SentFrame::NewToken(t.clone()),
            )?
        {
            self.new_token = Some(t);
        }
        Ok(())
    }

    fn fill_streams(&mut self, b: &mut PayloadBuilder) -> Result<()> {
        for id in self.streams.active() {
            if let Some((code, final_size)) = self.streams.take_reset(id)
                && !b.push(
                    &Frame::ResetStream {
                        id,
                        code,
                        final_size,
                    },
                    SentFrame::ResetStream(id),
                )?
            {
                self.streams.on_reset_lost(id);
            }
            if let Some(code) = self.streams.take_stop_sending(id)
                && !b.push(&Frame::StopSending { id, code }, SentFrame::StopSending(id))?
            {
                self.streams.on_stop_sending_lost(id);
            }
            if let Some(max) = self.streams.take_max_stream_data(id)
                && !b.push(
                    &Frame::MaxStreamData { id, max },
                    SentFrame::MaxStreamData(id),
                )?
            {
                self.streams.on_max_stream_data_lost(id);
            }
            if let Some(limit) = self.streams.take_stream_data_blocked(id) {
                b.push(
                    &Frame::StreamDataBlocked { id, limit },
                    SentFrame::StreamDataBlocked(id),
                )?;
            }
            loop {
                let offset = self
                    .streams
                    .get(id)
                    .and_then(|s| s.send.as_ref())
                    .map_or(0, |p| p.buf.sent_end());
                let room = b.stream_room(id, offset.saturating_add(1 << 30));
                if room == 0 && b.room() < 8 {
                    return Ok(());
                }
                let Some(c) = self.streams.next_chunk(id, room) else {
                    break;
                };
                b.push_stream(id, c.offset, &c.data, c.fin)?;
                if c.data.is_empty() {
                    break;
                }
            }
            if b.room() < 8 {
                break;
            }
        }
        Ok(())
    }
}
