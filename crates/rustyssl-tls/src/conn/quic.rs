//! QUIC mode (ADR 0006, section 1): TLS 1.3's handshake carried by a QUIC stack in CRYPTO
//! frames (RFC 9001), as `ssl/quic/quic_tls.c` makes libssl behave.
//!
//! There is no record layer. Handshake octets come in with [`Connection::feed_quic_crypto`] at
//! the current read level and go out through [`Connection::take_quic_crypto`], tagged with the
//! write level current when they were made. Where TLS over TCP would install keys, the core
//! raises [`Event::QuicSecret`] instead. Alerts aren't written: their descriptions wait in
//! [`Connection::take_quic_alerts`], and the error `step` returns carries the fatal one. The
//! transport parameters travel in extension 57 (`quic_transport_parameters`).
//!
//! What the mode changes elsewhere: no middlebox compatibility, ChangeCipherSpec or
//! EndOfEarlyData; a received KeyUpdate is an unexpected message; the client installs its
//! handshake write keys with the read keys, and its application read keys after its write keys;
//! a NewSessionTicket must allow 0xffffffff octets of early data (RFC 9001, section 4.6.1).

use std::collections::VecDeque;

#[cfg(test)]
mod tests;

use rustyssl_abi as abi;

use super::{Connection, Event};
use crate::consts::version;
use crate::crypto::{HashAlg, Provider, Secret};
use crate::error::{Error, Result};
use crate::record::{self, content_type};
use crate::suites::Cipher;

/// A protection level: OpenSSL's `OSSL_RECORD_PROTECTION_LEVEL_*`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QuicLevel {
    /// Initial packets (`OSSL_RECORD_PROTECTION_LEVEL_NONE`): their keys come from the
    /// connection ID, never from TLS.
    #[default]
    Initial,
    /// 0-RTT.
    Early,
    /// Handshake packets.
    Handshake,
    /// 1-RTT.
    Application,
}

impl QuicLevel {
    /// The level's `OSSL_RECORD_PROTECTION_LEVEL_*` number.
    #[must_use]
    pub const fn protection_level(self) -> core::ffi::c_int {
        match self {
            Self::Initial => abi::OSSL_RECORD_PROTECTION_LEVEL_NONE,
            Self::Early => abi::OSSL_RECORD_PROTECTION_LEVEL_EARLY,
            Self::Handshake => abi::OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE,
            Self::Application => abi::OSSL_RECORD_PROTECTION_LEVEL_APPLICATION,
        }
    }
}

/// A secret's direction (`yield_secret`'s 0 and 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Protecting what the peer sends.
    Read,
    /// Protecting what this end sends.
    Write,
}

/// QUIC mode's settings ([`super::Config::quic`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QuicTlsConfig {
    /// The local transport parameters (`SSL_set_quic_tls_transport_params`): the body of
    /// extension 57 in the ClientHello or the EncryptedExtensions (`None`: sent empty).
    pub transport_params: Option<Vec<u8>>,
    /// Whether 0-RTT is on (`SSL_set_quic_tls_early_data_enabled`): a server accepts it and
    /// issues tickets that allow it, a client offers it with a session that allows it.
    pub early_data: bool,
}

/// A secret to install at a level, in a direction ([`Event::QuicSecret`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuicSecret {
    /// The level.
    pub level: QuicLevel,
    /// The direction.
    pub direction: Direction,
    /// The negotiated suite (the session's for early secrets).
    pub suite: &'static Cipher,
    /// The suite's hash.
    pub hash: HashAlg,
    /// The traffic secret.
    pub secret: Secret,
}

/// The mode's state in a connection.
#[derive(Debug, Default)]
pub(crate) struct State {
    /// The levels the peer's and this end's handshake octets are protected at.
    pub(crate) read_level: QuicLevel,
    /// See `read_level`.
    pub(crate) write_level: QuicLevel,
    /// Octets fed and not yet read.
    input: Vec<u8>,
    /// Octets made and not yet taken: a write each (`quic_write_records`' template), numbered.
    out: VecDeque<(u64, QuicLevel, Vec<u8>)>,
    /// How many writes were made.
    made: u64,
    /// For each write secret raised and not yet handed out by
    /// [`Connection::take_quic_crypto_before_secret`], how many writes came before it.
    marks: VecDeque<u64>,
    /// The descriptions of the alerts sent.
    alerts: Vec<u8>,
    /// Whether the transport parameters were sent (`local_transport_params_consumed`).
    pub(crate) params_consumed: bool,
}

impl State {
    /// Whether handshake octets or alerts wait to be taken.
    pub(crate) fn has_output(&self) -> bool {
        !self.out.is_empty() || !self.alerts.is_empty()
    }
}

/// The context of the transport parameters extension (`ossl_quic_tls_configure`).
pub const PARAMS_CONTEXT: u32 = crate::consts::context::TLS1_3_ONLY
    | crate::consts::context::CLIENT_HELLO
    | crate::consts::context::TLS1_3_ENCRYPTED_EXTENSIONS;

impl Connection {
    /// Whether the connection is in QUIC mode.
    #[must_use]
    pub fn is_quic(&self) -> bool {
        self.cfg.quic.is_some()
    }

    /// Adds handshake octets the peer sent at `level` (a CRYPTO frame's data, in order).
    ///
    /// # Errors
    /// The connection isn't in QUIC mode or has failed, or `level` isn't the read level (RFC
    /// 9001, section 4.1.3).
    pub fn feed_quic_crypto(&mut self, level: QuicLevel, data: &[u8]) -> Result<()> {
        if self.cfg.quic.is_none() {
            return Err(Error::internal());
        }
        if let Some(e) = self.failed {
            return Err(e);
        }
        if level != self.quic.read_level {
            return Err(Error::alert(
                abi::SSL_AD_UNEXPECTED_MESSAGE,
                abi::SSL_R_UNEXPECTED_MESSAGE,
            ));
        }
        self.quic.input.extend_from_slice(data);
        self.needs_input = false;
        Ok(())
    }

    /// Takes the handshake octets made, each write tagged with the write level current when it
    /// was made.
    pub fn take_quic_crypto(&mut self) -> Vec<(QuicLevel, Vec<u8>)> {
        self.quic.marks.clear();
        self.quic.out.drain(..).map(|(_, l, d)| (l, d)).collect()
    }

    /// Takes the handshake octets made before the oldest write secret not yet handled this way:
    /// for a caller that sends each write as it handles the events in order, as libssl calls
    /// `crypto_send` and `yield_secret` (call it on each [`Event::QuicSecret`] with
    /// [`Direction::Write`], before using that secret).
    pub fn take_quic_crypto_before_secret(&mut self) -> Vec<(QuicLevel, Vec<u8>)> {
        let Some(mark) = self.quic.marks.pop_front() else {
            return Vec::new();
        };
        let mut taken = Vec::new();
        while self.quic.out.front().is_some_and(|(n, _, _)| *n < mark) {
            if let Some((_, l, d)) = self.quic.out.pop_front() {
                taken.push((l, d));
            }
        }
        taken
    }

    /// Takes the descriptions of the alerts sent (the level octet isn't kept), oldest first.
    pub fn take_quic_alerts(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.quic.alerts)
    }

    /// The level the peer's handshake octets are expected at.
    #[must_use]
    pub fn read_level(&self) -> QuicLevel {
        self.quic.read_level
    }

    /// The level this end's handshake octets are made at.
    #[must_use]
    pub fn write_level(&self) -> QuicLevel {
        self.quic.write_level
    }

    /// Whether the local transport parameters were sent (they can't be changed then).
    #[must_use]
    pub fn quic_transport_params_consumed(&self) -> bool {
        self.quic.params_consumed
    }

    /// Fails the connection because the caller couldn't use a secret it was given (a failed
    /// `yield_secret`): what followed that secret is dropped, its events and its writes, as
    /// libssl stops where the record layer failed. Then `e`'s alert is sent.
    pub fn fail_quic_secret(&mut self, p: &dyn Provider, e: Error) {
        self.events.clear();
        self.quic.out.clear();
        self.quic.marks.clear();
        self.fatal(p, e);
    }

    /// `quic_write_records`: a handshake message's octets become writes at the write level
    /// (one per `max_send_fragment`), an alert's description is kept, anything else fails. The
    /// message callback sees a made-up record header (and inner content type) as OpenSSL
    /// reports them.
    pub(crate) fn quic_write(&mut self, ty: u8, data: &[u8]) -> Result<()> {
        let level = self.quic.write_level;
        let max = self.rw.max_frag_len.clamp(1, record::MAX_PLAIN);
        let pieces: Vec<&[u8]> = if ty == content_type::alert() {
            vec![data]
        } else {
            data.chunks(max).collect()
        };
        for piece in pieces {
            if self.cfg.callbacks.msg {
                let hdr_ty = if level == QuicLevel::Initial {
                    ty
                } else {
                    content_type::application_data()
                };
                let [v0, v1] = self.rw.version.to_be_bytes();
                let [l0, l1] = u16::try_from(piece.len()).unwrap_or(u16::MAX).to_be_bytes();
                let header = [hdr_ty, v0, v1, l0, l1];
                self.report_message_v(true, abi::TLS1_3_VERSION, abi::SSL3_RT_HEADER, &header);
                if level != QuicLevel::Initial {
                    self.report_message_v(
                        true,
                        abi::TLS1_3_VERSION,
                        abi::SSL3_RT_INNER_CONTENT_TYPE,
                        &[ty],
                    );
                }
            }
            if ty == content_type::alert() {
                let [_, desc] = <[u8; 2]>::try_from(piece)
                    .map_err(|_| Error::alert(abi::SSL_AD_INTERNAL_ERROR, abi::SSL_R_BAD_VALUE))?;
                self.quic.alerts.push(desc);
            } else if ty == content_type::handshake() {
                let n = self.quic.made;
                self.quic.made = n.wrapping_add(1);
                self.quic.out.push_back((n, level, piece.to_vec()));
            } else {
                return Err(Error::internal());
            }
        }
        Ok(())
    }

    /// `quic_read_record`: what was fed, as one handshake record (`None`: nothing yet). The
    /// message callback sees a made-up record header and inner content type.
    pub(crate) fn quic_fetch(&mut self) -> Option<record::Record> {
        if self.quic.input.is_empty() {
            self.needs_input = true;
            return None;
        }
        let data = core::mem::take(&mut self.quic.input);
        let hdr_ty = if self.quic.read_level == QuicLevel::Initial {
            content_type::handshake()
        } else {
            content_type::application_data()
        };
        let [v0, v1] = version::TLS1_2.to_be_bytes();
        let [l0, l1] = u16::try_from(data.len()).unwrap_or(u16::MAX).to_be_bytes();
        let header = vec![hdr_ty, v0, v1, l0, l1];
        self.report_message_v(false, abi::TLS1_3_VERSION, abi::SSL3_RT_HEADER, &header);
        self.report_message_v(
            false,
            abi::TLS1_3_VERSION,
            abi::SSL3_RT_INNER_CONTENT_TYPE,
            &[content_type::handshake()],
        );
        Some(record::Record {
            content_type: content_type::handshake(),
            version: version::TLS1_3,
            header,
            data,
            inner: false,
        })
    }

    /// Raises the secret of one direction at `level` in place of installing keys
    /// (`quic_new_record_layer`), and moves that direction to the level.
    pub(crate) fn quic_secret(
        &mut self,
        read: bool,
        level: QuicLevel,
        suite: &'static Cipher,
        hash: HashAlg,
        secret: &Secret,
    ) {
        let direction = if read {
            self.quic.read_level = level;
            Direction::Read
        } else {
            self.quic.write_level = level;
            self.quic.marks.push_back(self.quic.made);
            Direction::Write
        };
        self.notify(Event::QuicSecret(QuicSecret {
            level,
            direction,
            suite,
            hash,
            secret: secret.clone(),
        }));
    }

    /// The local transport parameters for extension 57, which are then sent
    /// (`add_transport_params_cb`).
    pub(crate) fn quic_params_to_send(&mut self) -> Vec<u8> {
        self.quic.params_consumed = true;
        self.cfg
            .quic
            .as_ref()
            .and_then(|q| q.transport_params.clone())
            .unwrap_or_default()
    }
}
