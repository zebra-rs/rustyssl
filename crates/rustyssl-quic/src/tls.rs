//! The handshake as the transport sees it (ADR 0006): CRYPTO bytes in and out per level,
//! secrets as events, the peer's transport parameters, and the TLS requests and events that
//! pass through to the application. `rustyssl-tls`'s QUIC mode implements [`Handshake`];
//! [`TestHandshake`] is a double that runs the same message flow without TLS, for this crate's
//! tests and fuzz targets.

use rustyssl_tls::crypto::Secret;
use rustyssl_tls::suites::Cipher;

pub use rustyssl_tls::conn::{Answer, Event, Request};

use crate::crypto::Provider;
#[cfg(any(test, feature = "test-provider"))]
use crate::error::Error;
use crate::error::Result;
use crate::packet::Space;

/// A protection level (OpenSSL's `OSSL_RECORD_PROTECTION_LEVEL_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    Initial,
    Early,
    Handshake,
    Application,
}

impl Level {
    /// The packet-number space whose CRYPTO frames carry this level (none for 0-RTT, which
    /// carries no CRYPTO).
    #[must_use]
    pub const fn space(self) -> Option<Space> {
        match self {
            Self::Initial => Some(Space::Initial),
            Self::Handshake => Some(Space::Handshake),
            Self::Application => Some(Space::Application),
            Self::Early => None,
        }
    }

    /// The level of a packet-number space's CRYPTO frames.
    #[must_use]
    pub const fn of_space(s: Space) -> Self {
        match s {
            Space::Initial => Self::Initial,
            Space::Handshake => Self::Handshake,
            Space::Application => Self::Application,
        }
    }
}

/// Which way a secret protects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    Read,
    Write,
}

/// A traffic secret for one level and direction.
#[derive(Debug)]
pub struct HsSecret {
    pub level: Level,
    pub direction: Direction,
    /// The negotiated (or early) TLS 1.3 suite.
    pub cipher: &'static Cipher,
    pub secret: Secret,
}

/// What the handshake reports.
#[derive(Debug)]
pub enum HsEvent {
    /// Keys for a level and direction.
    Secret(HsSecret),
    /// The peer's transport parameters: the channel checks them and answers with
    /// [`Handshake::answer`] (`Continue`, or `Fail`).
    PeerTransportParams(Vec<u8>),
    /// A decision for the application (verify, ALPN, ...), answered through the channel.
    Request(Request),
    /// Information for the application's callbacks.
    Info(Event),
    /// The handshake completed.
    Complete,
}

/// A QUIC-mode TLS handshake.
pub trait Handshake: Send {
    /// Starts it (a client writes its ClientHello).
    fn start(&mut self);

    /// Handshake bytes received at `level` (`Connection::feed_quic_crypto`).
    ///
    /// # Errors
    /// The level isn't the current read level, or the bytes are refused (a CRYPTO_ERROR).
    fn feed_quic_crypto(&mut self, level: Level, data: &[u8]) -> Result<()>;

    /// Handshake bytes to send, each tagged with its level (`Connection::take_quic_crypto`;
    /// the tags make the order relative to secrets immaterial here).
    fn take_quic_crypto(&mut self) -> Vec<(Level, Vec<u8>)>;

    /// Whether ALPN is configured: a client must offer protocols, a server must have a
    /// selection callback (checked before starting, as `ossl_quic_tls_tick`).
    fn alpn_configured(&self) -> bool;

    /// The protocol ALPN selected, once known.
    fn alpn_selected(&self) -> Option<Vec<u8>>;

    /// Runs until it has something to report (`Some`) or must wait for input or an answer
    /// (`None`).
    ///
    /// # Errors
    /// The handshake failed: CRYPTO_ERROR with the alert it would send, or another error.
    fn step(&mut self, p: &dyn Provider) -> Result<Option<HsEvent>>;

    /// Answers the last request or transport parameters.
    fn answer(&mut self, a: Answer);

    /// Our transport parameters (set before `start` for a client, and before answering the
    /// peer's for a server).
    fn set_transport_params(&mut self, params: Vec<u8>);
}

/// TLS alert unexpected_message.
#[cfg(any(test, feature = "test-provider"))]
const UNEXPECTED_MESSAGE: u8 = 10;
/// TLS alert internal_error.
#[cfg(any(test, feature = "test-provider"))]
const INTERNAL_ERROR: u8 = 80;

#[cfg(any(test, feature = "test-provider"))]
const MSG_CLIENT_HELLO: u8 = 1;
#[cfg(any(test, feature = "test-provider"))]
const MSG_SERVER_HELLO: u8 = 2;
#[cfg(any(test, feature = "test-provider"))]
const MSG_TICKET: u8 = 4;
#[cfg(any(test, feature = "test-provider"))]
const MSG_EE: u8 = 8;
#[cfg(any(test, feature = "test-provider"))]
const MSG_FINISHED: u8 = 20;

#[cfg(any(test, feature = "test-provider"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestState {
    Start,
    /// Client: waiting for ServerHello. Server: waiting for ClientHello.
    WaitHello,
    /// Waiting for the answer to the peer's parameters.
    WaitAnswer,
    /// Client: waiting for EncryptedExtensions.
    WaitEe,
    /// Waiting for Finished.
    WaitFinished,
    Done,
    Failed,
}

/// The handshake double: the message flow of a TLS 1.3 handshake in QUIC (ClientHello and
/// ServerHello at Initial; EncryptedExtensions with the parameters and Finished at Handshake;
/// the client's Finished; a ticket at Application), each message a type, a 16-bit length and a
/// body, with fixed secrets. Never use it outside tests.
#[cfg(any(test, feature = "test-provider"))]
#[doc(hidden)]
#[derive(Debug)]
pub struct TestHandshake {
    server: bool,
    state: TestState,
    cipher: &'static Cipher,
    params: Vec<u8>,
    read_level: Level,
    input: Vec<u8>,
    output: Vec<(Level, Vec<u8>)>,
    events: std::collections::VecDeque<HsEvent>,
    /// Fail with this alert when the peer's parameters arrive (to test CRYPTO_ERROR).
    pub fail_alert: Option<u8>,
    /// The protocol ALPN configures and selects (`None`: not configured).
    pub alpn: Option<Vec<u8>>,
    error: Option<u8>,
}

#[cfg(any(test, feature = "test-provider"))]
impl TestHandshake {
    /// A double with `cipher` (a TLS 1.3 suite).
    #[must_use]
    pub fn new(server: bool, cipher: &'static Cipher) -> Self {
        Self {
            server,
            state: TestState::Start,
            cipher,
            params: Vec::new(),
            read_level: Level::Initial,
            input: Vec::new(),
            output: Vec::new(),
            events: std::collections::VecDeque::new(),
            fail_alert: None,
            alpn: Some(b"test".to_vec()),
            error: None,
        }
    }

    /// The TLS 1.3 suite whose AEAD is `aead`.
    #[must_use]
    pub fn suite(aead: rustyssl_tls::crypto::AeadAlg) -> Option<&'static Cipher> {
        rustyssl_tls::suites::tls13()
            .iter()
            .find(|c| c.protection() == rustyssl_tls::suites::Protection::Aead(aead))
    }

    fn write(&mut self, level: Level, ty: u8, body: &[u8]) {
        let len = u16::try_from(body.len()).unwrap_or(u16::MAX);
        let mut m = vec![ty];
        m.extend_from_slice(&len.to_be_bytes());
        m.extend_from_slice(body.get(..usize::from(len)).unwrap_or(&[]));
        self.output.push((level, m));
    }

    fn secret(&mut self, level: Level, direction: Direction) {
        // The sender's role and the level make the secret, so both ends agree.
        let sender_client = (direction == Direction::Write) != self.server;
        let lb: u8 = match level {
            Level::Initial => 0,
            Level::Early => 1,
            Level::Handshake => 2,
            Level::Application => 3,
        };
        let tag = lb.saturating_mul(2).saturating_add(u8::from(sender_client));
        let len = self.cipher.handshake_hash().map_or(32, |h| h.len());
        self.events.push_back(HsEvent::Secret(HsSecret {
            level,
            direction,
            cipher: self.cipher,
            secret: Secret::new(vec![tag.wrapping_add(0x40); len]),
        }));
    }

    fn fail(&mut self, alert: u8, reason: &'static str) -> Error {
        self.state = TestState::Failed;
        Error::crypto(alert, reason)
    }

    /// The next whole message in the input.
    fn message(&mut self) -> Option<(u8, Vec<u8>)> {
        let [ty, a, b, ..] = *self.input.as_slice() else {
            return None;
        };
        let len = usize::from(u16::from_be_bytes([a, b]));
        let end = len.checked_add(3)?;
        let body = self.input.get(3..end)?.to_vec();
        self.input.drain(..end);
        Some((ty, body))
    }

    fn after_answer(&mut self) {
        if self.server {
            let params = self.params.clone();
            self.write(Level::Initial, MSG_SERVER_HELLO, &[]);
            self.secret(Level::Handshake, Direction::Write);
            self.secret(Level::Handshake, Direction::Read);
            self.write(Level::Handshake, MSG_EE, &params);
            self.write(Level::Handshake, MSG_FINISHED, &[]);
            self.secret(Level::Application, Direction::Write);
            self.read_level = Level::Handshake;
            self.state = TestState::WaitFinished;
        } else {
            self.state = TestState::WaitFinished;
        }
    }
}

#[cfg(any(test, feature = "test-provider"))]
impl Handshake for TestHandshake {
    fn start(&mut self) {
        if self.state != TestState::Start {
            return;
        }
        if !self.server {
            let params = self.params.clone();
            self.write(Level::Initial, MSG_CLIENT_HELLO, &params);
        }
        self.state = TestState::WaitHello;
    }

    fn feed_quic_crypto(&mut self, level: Level, data: &[u8]) -> Result<()> {
        if level != self.read_level {
            return Err(self.fail(UNEXPECTED_MESSAGE, "handshake data at the wrong level"));
        }
        self.input.extend_from_slice(data);
        Ok(())
    }

    fn take_quic_crypto(&mut self) -> Vec<(Level, Vec<u8>)> {
        core::mem::take(&mut self.output)
    }

    fn alpn_configured(&self) -> bool {
        self.alpn.is_some()
    }

    fn alpn_selected(&self) -> Option<Vec<u8>> {
        if self.state == TestState::Done {
            self.alpn.clone()
        } else {
            None
        }
    }

    fn step(&mut self, _p: &dyn Provider) -> Result<Option<HsEvent>> {
        loop {
            if let Some(alert) = self.error.take() {
                return Err(Error::crypto(alert, "handshake failed"));
            }
            if let Some(e) = self.events.pop_front() {
                return Ok(Some(e));
            }
            if matches!(
                self.state,
                TestState::WaitAnswer | TestState::Failed | TestState::Start
            ) {
                return Ok(None);
            }
            let Some((ty, body)) = self.message() else {
                return Ok(None);
            };
            match (self.state, self.server, ty) {
                (TestState::WaitHello, true, MSG_CLIENT_HELLO) => {
                    self.state = TestState::WaitAnswer;
                    self.events.push_back(HsEvent::PeerTransportParams(body));
                }
                (TestState::WaitHello, false, MSG_SERVER_HELLO) => {
                    self.secret(Level::Handshake, Direction::Read);
                    self.secret(Level::Handshake, Direction::Write);
                    self.read_level = Level::Handshake;
                    self.state = TestState::WaitEe;
                }
                (TestState::WaitEe, false, MSG_EE) => {
                    self.state = TestState::WaitAnswer;
                    self.events.push_back(HsEvent::PeerTransportParams(body));
                }
                (TestState::WaitFinished, false, MSG_FINISHED) => {
                    self.write(Level::Handshake, MSG_FINISHED, &[]);
                    self.secret(Level::Application, Direction::Read);
                    self.secret(Level::Application, Direction::Write);
                    self.read_level = Level::Application;
                    self.state = TestState::Done;
                    self.events.push_back(HsEvent::Complete);
                }
                (TestState::WaitFinished, true, MSG_FINISHED) => {
                    self.secret(Level::Application, Direction::Read);
                    self.read_level = Level::Application;
                    self.state = TestState::Done;
                    self.events.push_back(HsEvent::Complete);
                    self.write(Level::Application, MSG_TICKET, &[]);
                }
                (TestState::Done, false, MSG_TICKET) => {
                    self.events.push_back(HsEvent::Info(Event::Idle));
                }
                _ => return Err(self.fail(UNEXPECTED_MESSAGE, "unexpected message")),
            }
        }
    }

    fn answer(&mut self, a: Answer) {
        if self.state != TestState::WaitAnswer {
            return;
        }
        match a {
            Answer::Continue if self.fail_alert.is_none() => self.after_answer(),
            _ => {
                self.state = TestState::Failed;
                self.events.clear();
                self.error = Some(self.fail_alert.unwrap_or(INTERNAL_ERROR));
            }
        }
    }

    fn set_transport_params(&mut self, params: Vec<u8>) {
        self.params = params;
    }
}

#[cfg(any(test, feature = "test-provider"))]
impl TestHandshake {
    /// Whether it failed (after a refused answer).
    #[must_use]
    pub fn failed(&self) -> bool {
        self.state == TestState::Failed
    }
}
