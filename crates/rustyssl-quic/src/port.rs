//! A port: one socket's connections (after OpenSSL's `quic_port.c` and `quic_demux.c`). It
//! routes datagrams by destination connection ID, recognises stateless resets, answers unknown
//! versions with version negotiation (QUIC v1 only), and, listening, validates new clients'
//! addresses with Retry and tokens before making them a channel, as OpenSSL does by default.

use std::collections::{BTreeMap, VecDeque};

use crate::channel::{Channel, ChannelConfig, PeerAddr, ServerInit, State};
use crate::cid::LOCAL_CID_LEN;
use crate::crypto::Provider;
use crate::error::{Error, Result};
use crate::packet::{self, PacketType};
use crate::time::{Time, earliest};
use crate::tls::Handshake;
use crate::token::TokenKey;
use crate::wire::{ConnId, RESET_TOKEN_LEN};

/// A channel's handle within its port.
pub type ChannelId = u64;

/// The most connections waiting to be accepted (OpenSSL's `DEFAULT_MAX_PENDING_CONNS`).
pub const DEFAULT_MAX_PENDING: usize = 256;
/// The shortest DCID a client's first Initial may have (OpenSSL's `QUIC_MIN_ODCID_LEN`).
pub const MIN_ODCID_LEN: usize = 8;
/// Port-level datagrams (Retry, version negotiation) queued at once (ours: OpenSSL sends them
/// at once and drops them when the socket would block).
pub const MAX_PORT_TX_QUEUE: usize = 64;
/// The most channels one port holds (ours: OpenSSL bounds incoming ones by the accept queue
/// only; this also bounds accepted ones the application never frees).
pub const MAX_CHANNELS: usize = 4096;

/// A port's settings.
pub struct PortConfig {
    /// Accept incoming connections (a listener).
    pub listen: bool,
    /// Validate new clients' addresses with Retry (OpenSSL's default; off with
    /// `SSL_LISTENER_FLAG_NO_VALIDATE`).
    pub validate_addr: bool,
    /// The accept queue's bound.
    pub max_pending: usize,
    /// Each channel's settings.
    pub channel: ChannelConfig,
    /// Makes the handshake of a connection a listener accepts.
    pub new_handshake: Option<Box<dyn FnMut() -> Box<dyn Handshake> + Send>>,
}

impl Default for PortConfig {
    fn default() -> Self {
        Self {
            listen: false,
            validate_addr: true,
            max_pending: DEFAULT_MAX_PENDING,
            channel: ChannelConfig::default(),
            new_handshake: None,
        }
    }
}

impl core::fmt::Debug for PortConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PortConfig")
            .field("listen", &self.listen)
            .field("validate_addr", &self.validate_addr)
            .field("max_pending", &self.max_pending)
            .finish_non_exhaustive()
    }
}

/// What a port tells its owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortEvent {
    /// A listener made a channel for a new client (it's in the accept queue).
    Incoming(ChannelId),
    /// A channel has events ([`Channel::poll_event`]).
    Channel(ChannelId),
}

/// A port.
pub struct Port {
    cfg: PortConfig,
    token_key: Option<TokenKey>,
    channels: BTreeMap<ChannelId, Channel>,
    routes: BTreeMap<ConnId, ChannelId>,
    routes_of: BTreeMap<ChannelId, Vec<ConnId>>,
    next_id: ChannelId,
    accept: VecDeque<ChannelId>,
    tx: VecDeque<(PeerAddr, Vec<u8>)>,
    events: VecDeque<PortEvent>,
    /// The channel to poll first for transmission (round robin).
    tx_cursor: ChannelId,
}

impl core::fmt::Debug for Port {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Port")
            .field("channels", &self.channels.len())
            .finish_non_exhaustive()
    }
}

impl Port {
    /// A port.
    #[must_use]
    pub fn new(cfg: PortConfig) -> Self {
        Self {
            cfg,
            token_key: None,
            channels: BTreeMap::new(),
            routes: BTreeMap::new(),
            routes_of: BTreeMap::new(),
            next_id: 1,
            accept: VecDeque::new(),
            tx: VecDeque::new(),
            events: VecDeque::new(),
            tx_cursor: 0,
        }
    }

    fn short_dcid_len(&self) -> usize {
        if self.cfg.listen { LOCAL_CID_LEN } else { 0 }
    }

    /// Starts a client connection to `peer`.
    ///
    /// # Errors
    /// The port listens, or already has a connection, or the provider failed.
    pub fn connect(
        &mut self,
        p: &dyn Provider,
        hs: Box<dyn Handshake>,
        peer: PeerAddr,
        now: Time,
    ) -> Result<ChannelId> {
        if self.cfg.listen || !self.channels.is_empty() {
            return Err(Error::internal("port cannot connect"));
        }
        let ch = Channel::connect(p, hs, peer, &self.cfg.channel, now)?;
        let id = self.insert(ch);
        Ok(id)
    }

    fn insert(&mut self, ch: Channel) -> ChannelId {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.channels.insert(id, ch);
        self.refresh_routes(id);
        id
    }

    fn refresh_routes(&mut self, id: ChannelId) {
        if let Some(old) = self.routes_of.remove(&id) {
            for c in old {
                if self.routes.get(&c) == Some(&id) {
                    self.routes.remove(&c);
                }
            }
        }
        let Some(ch) = self.channels.get(&id) else {
            return;
        };
        if ch.state() == State::Terminated {
            return;
        }
        let cids = ch.routing_cids();
        for c in &cids {
            self.routes.insert(c.clone(), id);
        }
        self.routes_of.insert(id, cids);
    }

    /// A channel.
    pub fn channel(&mut self, id: ChannelId) -> Option<&mut Channel> {
        self.channels.get_mut(&id)
    }

    /// The channels' handles.
    #[must_use]
    pub fn channel_ids(&self) -> Vec<ChannelId> {
        self.channels.keys().copied().collect()
    }

    /// Takes the next connection from the accept queue.
    pub fn accept(&mut self) -> Option<ChannelId> {
        self.accept.pop_front()
    }

    /// Connections waiting to be accepted.
    #[must_use]
    pub fn accept_queue_len(&self) -> usize {
        self.accept.len()
    }

    /// Forgets a channel (its owner freed it).
    pub fn remove(&mut self, id: ChannelId) {
        self.channels.remove(&id);
        self.refresh_routes(id);
        self.routes_of.remove(&id);
        self.accept.retain(|&a| a != id);
    }

    /// The next event.
    pub fn poll_event(&mut self) -> Option<PortEvent> {
        self.events.pop_front()
    }

    fn queue_tx(&mut self, to: &PeerAddr, d: Vec<u8>) {
        if self.tx.len() < MAX_PORT_TX_QUEUE {
            self.tx.push_back((to.clone(), d));
        }
    }

    fn stateless_reset(&mut self, data: &[u8]) -> bool {
        // RFC 9000, 10.3: a short-header-looking datagram of at least 21 octets ending in a
        // token the peer gave us.
        if data.len() < RESET_TOKEN_LEN.saturating_add(5)
            || data.first().is_none_or(|b| b & 0x40 == 0)
        {
            return false;
        }
        let Some(tail) = data.get(data.len().saturating_sub(RESET_TOKEN_LEN)..) else {
            return false;
        };
        let Ok(token) = <[u8; RESET_TOKEN_LEN]>::try_from(tail) else {
            return false;
        };
        let hit: Vec<ChannelId> = self
            .channels
            .iter()
            .filter(|(_, c)| c.is_stateless_reset(&token))
            .map(|(&id, _)| id)
            .collect();
        for id in &hit {
            if let Some(ch) = self.channels.get_mut(id) {
                ch.on_stateless_reset();
                self.events.push_back(PortEvent::Channel(*id));
            }
            self.refresh_routes(*id);
        }
        !hit.is_empty()
    }

    /// A datagram from `from` at `now`.
    pub fn handle_datagram(&mut self, p: &dyn Provider, now: Time, from: &PeerAddr, data: &[u8]) {
        let Ok((first, _)) = packet::locate(data, self.short_dcid_len()) else {
            let _ = self.stateless_reset(data);
            return;
        };
        let target = if self.cfg.listen {
            self.routes.get(&first.dcid).copied()
        } else {
            self.channels.keys().next().copied()
        };
        if let Some(id) = target {
            if first.ty == PacketType::OneRtt && self.stateless_reset(data) {
                return;
            }
            if let Some(ch) = self.channels.get_mut(&id) {
                ch.handle_datagram(p, now, from, data);
                self.events.push_back(PortEvent::Channel(id));
            }
            self.refresh_routes(id);
            return;
        }
        if self.stateless_reset(data) || !self.cfg.listen {
            return;
        }
        self.on_new(p, now, from, data, &first);
    }

    fn on_new(
        &mut self,
        p: &dyn Provider,
        now: Time,
        from: &PeerAddr,
        data: &[u8],
        first: &packet::Located<'_>,
    ) {
        // Only long headers can start a connection.
        if first.ty == PacketType::OneRtt || first.ty == PacketType::VersionNegotiation {
            return;
        }
        if first.version != packet::VERSION_1 {
            // Version negotiation, for datagrams of at least 1200 octets (RFC 9000, 6 and 14.1).
            if data.len() >= packet::MIN_INITIAL_DGRAM_LEN {
                let mut rb = [0u8; 1];
                if p.random(&mut rb, false).is_ok()
                    && let Ok(vn) = packet::build_version_negotiation(
                        first.dcid.as_bytes(),
                        first.scid.as_bytes(),
                        rb[0],
                    )
                {
                    self.queue_tx(from, vn);
                }
            }
            return;
        }
        if first.ty != PacketType::Initial
            || data.len() < packet::MIN_INITIAL_DGRAM_LEN
            || first.dcid.len() < MIN_ODCID_LEN
        {
            return;
        }
        if self.cfg.max_pending > 0 && self.accept.len() >= self.cfg.max_pending {
            return;
        }
        if self.channels.len() >= MAX_CHANNELS {
            return;
        }
        // The packet must authenticate under the Initial keys of its DCID.
        let Ok((mut client_keys, _)) = packet::initial_keys(p, first.dcid.as_bytes()) else {
            return;
        };
        if !matches!(
            packet::unprotect(&mut client_keys, first.bytes, first.pn_offset, None),
            Ok(Some(_))
        ) {
            return;
        }
        if self.token_key.is_none() {
            match TokenKey::new(p) {
                Ok(k) => self.token_key = Some(k),
                Err(_) => return,
            }
        }
        let Some(key) = self.token_key.as_mut() else {
            return;
        };
        let addr = from.0.as_slice();
        let validated = if first.token.is_empty() {
            None
        } else {
            key.validate(first.token, now, addr, &first.dcid)
        };
        if self.cfg.validate_addr && validated.is_none() {
            // Retry: a new SCID, and a token holding the client's original DCID.
            let mut rb = [0u8; 1];
            let Ok(rscid) = random_cid(p) else {
                return;
            };
            let Ok(token) = key.retry_token(p, now, addr, &first.dcid, &rscid) else {
                return;
            };
            if p.random(&mut rb, false).is_err() {
                return;
            }
            if let Ok(r) = packet::build_retry(p, &first.dcid, &first.scid, &rscid, &token, rb[0]) {
                self.queue_tx(from, r);
            }
            return;
        }
        let (odcid, retried) = match &validated {
            Some(v) if v.is_retry => (v.odcid.clone().unwrap_or_default(), true),
            _ => (first.dcid.clone(), false),
        };
        let new_token = if validated.as_ref().is_some_and(|v| v.gen_new_token) {
            key.new_token(p, now, addr).ok()
        } else {
            None
        };
        let Ok(local_cid) = random_cid(p) else {
            return;
        };
        let Some(factory) = self.cfg.new_handshake.as_mut() else {
            return;
        };
        let hs = factory();
        let init = ServerInit {
            peer: from.clone(),
            client_scid: first.scid.clone(),
            dcid: first.dcid.clone(),
            odcid,
            local_cid,
            retried,
            validated: validated.is_some(),
            new_token,
        };
        let Ok(ch) = Channel::accept(p, hs, init, &self.cfg.channel, now) else {
            return;
        };
        let id = self.insert(ch);
        self.accept.push_back(id);
        self.events.push_back(PortEvent::Incoming(id));
        if let Some(ch) = self.channels.get_mut(&id) {
            ch.handle_datagram(p, now, from, data);
        }
        self.events.push_back(PortEvent::Channel(id));
        self.refresh_routes(id);
    }

    /// The next datagram to send.
    pub fn poll_transmit(&mut self, p: &dyn Provider, now: Time) -> Option<(PeerAddr, Vec<u8>)> {
        if let Some(d) = self.tx.pop_front() {
            return Some(d);
        }
        let ids: Vec<ChannelId> = self
            .channels
            .range(self.tx_cursor..)
            .chain(self.channels.range(..self.tx_cursor))
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            let Some(ch) = self.channels.get_mut(&id) else {
                continue;
            };
            if let Some(d) = ch.poll_transmit(p, now) {
                let peer = ch.peer().clone();
                self.tx_cursor = id.saturating_add(1);
                self.refresh_routes(id);
                return Some((peer, d));
            }
        }
        None
    }

    /// When [`Port::handle_timeout`] next needs to run.
    #[must_use]
    pub fn next_timeout(&self, now: Time) -> Option<Time> {
        if !self.tx.is_empty() {
            return Some(now);
        }
        self.channels
            .values()
            .fold(None, |t, c| earliest(t, c.next_timeout(now)))
    }

    /// Runs the timers due at `now`.
    pub fn handle_timeout(&mut self, p: &dyn Provider, now: Time) {
        let ids: Vec<ChannelId> = self.channels.keys().copied().collect();
        for id in ids {
            if let Some(ch) = self.channels.get_mut(&id)
                && ch.next_timeout(now).is_some_and(|t| t <= now)
            {
                ch.handle_timeout(p, now);
                self.events.push_back(PortEvent::Channel(id));
            }
            self.refresh_routes(id);
        }
    }
}

fn random_cid(p: &dyn Provider) -> Result<ConnId> {
    let mut b = [0u8; LOCAL_CID_LEN];
    p.random(&mut b, false)
        .map_err(|_| Error::internal("random"))?;
    ConnId::new(&b)
}

#[cfg(test)]
mod tests;
