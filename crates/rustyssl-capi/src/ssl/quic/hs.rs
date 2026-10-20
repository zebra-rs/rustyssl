//! The handshake layer of a QUIC connection (`quic_tls.c` over libssl): the connection object's
//! own TLS state runs in QUIC mode, driven by the TLS driver with no lock held, and talks to the
//! transport through [`Shared`], which is both the driver's [`Sink`] and, as [`Hs`], the
//! transport's [`Handshake`].
//!
//! The transport (under the engine's lock) only queues: CRYPTO octets in, octets, secrets and
//! events out. Between ticks the engine runs the driver ([`super::drive_tls`]) for each
//! connection whose handshake has input, unlocked, so the application's callbacks (verify, ALPN,
//! servername, info, msg, keylog, ...) run as they do over TCP, and then lets the transport take
//! what the driver made.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rustyssl_quic::crypto::Provider as QuicProvider;
use rustyssl_quic::error::{Error as QError, Result as QResult};
use rustyssl_quic::tls::{Answer, Direction, Handshake, HsEvent, HsSecret, Level};
use rustyssl_tls::conn::{Direction as TlsDirection, QuicLevel, QuicSecret};

use super::super::quic_tls::Sink;

pub(crate) const fn to_tls(l: Level) -> QuicLevel {
    match l {
        Level::Initial => QuicLevel::Initial,
        Level::Early => QuicLevel::Early,
        Level::Handshake => QuicLevel::Handshake,
        Level::Application => QuicLevel::Application,
    }
}

const fn from_tls(l: QuicLevel) -> Level {
    match l {
        QuicLevel::Initial => Level::Initial,
        QuicLevel::Early => Level::Early,
        QuicLevel::Handshake => Level::Handshake,
        QuicLevel::Application => Level::Application,
    }
}

/// What passes between the transport and the driver.
#[derive(Debug, Default)]
pub(crate) struct Queues {
    /// CRYPTO octets received, by level, for the driver.
    input: VecDeque<(Level, Vec<u8>)>,
    /// Octets the driver made, at the write level current then, for the transport.
    output: Vec<(Level, Vec<u8>)>,
    /// What the transport steps through.
    events: VecDeque<QResult<HsEvent>>,
    write_level: Option<Level>,
    /// The transport started the handshake or gave it input: the driver should run.
    pub(crate) need_drive: bool,
    /// The transport's parameters for the peer, until the driver gives them to the core.
    pub(crate) local_params: Option<Vec<u8>>,
    /// The protocol negotiated, once the handshake completed.
    pub(crate) alpn: Option<Vec<u8>>,
    /// Completion was reported to the transport.
    pub(crate) completed: bool,
    /// The handshake failed (reported to the transport).
    pub(crate) failed: bool,
}

/// The queues of one connection's handshake.
#[derive(Debug, Default)]
pub(crate) struct Shared {
    q: Mutex<Queues>,
    /// Whether the handshake has an ALPN setting (fixed when the channel is made).
    alpn_configured: bool,
}

impl Shared {
    pub(crate) fn new(alpn_configured: bool) -> Arc<Self> {
        Arc::new(Self {
            q: Mutex::new(Queues::default()),
            alpn_configured,
        })
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, Queues> {
        self.q.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The handshake failed with `alert` (the transport closes with CRYPTO_ERROR).
    pub(crate) fn fail(&self, alert: u8) {
        let mut q = self.lock();
        if !q.failed {
            q.failed = true;
            q.events
                .push_back(Err(QError::crypto(alert, "handshake alert")));
        }
    }

    /// The handshake completed, negotiating `alpn`.
    pub(crate) fn complete(&self, alpn: Option<Vec<u8>>) {
        let mut q = self.lock();
        if !q.completed && !q.failed {
            q.completed = true;
            q.alpn = alpn;
            q.events.push_back(Ok(HsEvent::Complete));
        }
    }

    /// Whether the transport has events or octets to take.
    pub(crate) fn has_output(&self) -> bool {
        let q = self.lock();
        !q.events.is_empty() || !q.output.is_empty()
    }
}

impl Sink for Shared {
    fn send(&self, data: &[u8]) {
        let mut q = self.lock();
        let level = q.write_level.unwrap_or(Level::Initial);
        q.output.push((level, data.to_vec()));
    }

    fn secret(&self, s: QuicSecret) -> bool {
        let level = from_tls(s.level);
        let direction = match s.direction {
            TlsDirection::Read => Direction::Read,
            TlsDirection::Write => Direction::Write,
        };
        let mut q = self.lock();
        if direction == Direction::Write {
            q.write_level = Some(level);
        }
        q.events.push_back(Ok(HsEvent::Secret(HsSecret {
            level,
            direction,
            cipher: s.suite,
            secret: s.secret,
        })));
        true
    }

    fn alert(&self, a: u8) {
        self.fail(a);
    }

    fn recv(&self) -> Option<(QuicLevel, Vec<u8>)> {
        let mut q = self.lock();
        q.input.pop_front().map(|(l, d)| (to_tls(l), d))
    }

    fn got_params(&self, params: &[u8]) {
        self.lock()
            .events
            .push_back(Ok(HsEvent::PeerTransportParams(params.to_vec())));
    }
}

/// The transport's side of [`Shared`].
pub(crate) struct Hs(pub(crate) Arc<Shared>);

impl Handshake for Hs {
    fn start(&mut self) {
        self.0.lock().need_drive = true;
    }

    fn feed_quic_crypto(&mut self, level: Level, data: &[u8]) -> QResult<()> {
        let mut q = self.0.lock();
        q.input.push_back((level, data.to_vec()));
        q.need_drive = true;
        Ok(())
    }

    fn take_quic_crypto(&mut self) -> Vec<(Level, Vec<u8>)> {
        core::mem::take(&mut self.0.lock().output)
    }

    fn alpn_configured(&self) -> bool {
        self.0.alpn_configured
    }

    fn alpn_selected(&self) -> Option<Vec<u8>> {
        self.0.lock().alpn.clone()
    }

    fn step(&mut self, _p: &dyn QuicProvider) -> QResult<Option<HsEvent>> {
        self.0.lock().events.pop_front().transpose()
    }

    fn answer(&mut self, _a: Answer) {
        // The driver answered the peer's parameters itself; nothing waits.
    }

    fn set_transport_params(&mut self, params: Vec<u8>) {
        self.0.lock().local_params = Some(params);
    }
}
