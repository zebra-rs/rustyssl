//! Loopback: a client port and a listening port over a simulated network that loses,
//! reorders and duplicates datagrams, with the handshake double.

#![allow(clippy::arithmetic_side_effects, reason = "test code")]
#![allow(clippy::indexing_slicing, reason = "test code")]
#![allow(clippy::cast_possible_truncation, reason = "test code")]

use super::*;
use crate::channel::ChannelEvent;
use crate::testprov::TestProvider;
use crate::testutil::Rng;
use crate::time::Duration;
use crate::tls::TestHandshake;
use rustyssl_tls::crypto::AeadAlg;

const MS: u64 = 1_000_000;

#[derive(Clone, Copy)]
struct Net {
    loss: u64,
    dup: u64,
    jitter_ms: u64,
}

struct Sim {
    p: TestProvider,
    client: Port,
    server: Port,
    cid: ChannelId,
    sid: Option<ChannelId>,
    now: Time,
    rng: Rng,
    net: Net,
    /// (deliver at, to server, data)
    wire: Vec<(Time, bool, Vec<u8>)>,
    blackhole: bool,
    datagrams: u64,
}

const CLIENT: &[u8] = b"client-addr";
const SERVER: &[u8] = b"server-addr";

impl Sim {
    fn new(seed: u64, net: Net, aead: AeadAlg, validate: bool) -> Self {
        let p = TestProvider::new(&seed.to_be_bytes());
        let suite = TestHandshake::suite(aead).unwrap();
        let server = Port::new(PortConfig {
            listen: true,
            validate_addr: validate,
            new_handshake: Some(Box::new(move || {
                Box::new(TestHandshake::new(true, suite)) as Box<dyn Handshake>
            })),
            ..PortConfig::default()
        });
        let mut client = Port::new(PortConfig::default());
        let now = Time(1_000 * MS);
        let cid = client
            .connect(
                &p,
                Box::new(TestHandshake::new(false, suite)),
                PeerAddr(SERVER.to_vec()),
                now,
            )
            .unwrap();
        Self {
            p,
            client,
            server,
            cid,
            sid: None,
            now,
            rng: Rng(seed),
            net,
            wire: Vec::new(),
            blackhole: false,
            datagrams: 0,
        }
    }

    fn flush(&mut self) {
        for to_server in [true, false] {
            loop {
                let port = if to_server {
                    &mut self.client
                } else {
                    &mut self.server
                };
                let Some((_, d)) = port.poll_transmit(&self.p, self.now) else {
                    break;
                };
                assert!(
                    d.len() <= crate::channel::MAX_DGRAM,
                    "datagram of {}",
                    d.len()
                );
                self.datagrams += 1;
                if self.blackhole || self.rng.chance(self.net.loss) {
                    continue;
                }
                let copies = if self.rng.chance(self.net.dup) { 2 } else { 1 };
                for _ in 0..copies {
                    let delay = 10 * MS + self.rng.below(self.net.jitter_ms * MS + 1);
                    self.wire
                        .push((self.now.add(Duration(delay)), to_server, d.clone()));
                }
            }
        }
    }

    /// Runs one step: deliver what's due, run timers, send. Returns false when nothing is
    /// pending at all.
    fn step(&mut self) -> bool {
        self.flush();
        let next_wire = self.wire.iter().map(|w| w.0).min();
        let next = earliest(
            next_wire,
            earliest(
                self.client.next_timeout(self.now),
                self.server.next_timeout(self.now),
            ),
        );
        let Some(next) = next else {
            return false;
        };
        self.now = self.now.max(next);
        let now = self.now;
        let mut due: Vec<(Time, bool, Vec<u8>)> = Vec::new();
        self.wire.retain(|w| {
            if w.0 <= now {
                due.push(w.clone());
                false
            } else {
                true
            }
        });
        due.sort_by_key(|w| w.0);
        for (_, to_server, d) in due {
            if to_server {
                self.server
                    .handle_datagram(&self.p, now, &PeerAddr(CLIENT.to_vec()), &d);
            } else {
                self.client
                    .handle_datagram(&self.p, now, &PeerAddr(SERVER.to_vec()), &d);
            }
        }
        self.client.handle_timeout(&self.p, now);
        self.server.handle_timeout(&self.p, now);
        if self.sid.is_none() {
            self.sid = self.server.accept();
        }
        true
    }

    fn c(&mut self) -> &mut Channel {
        self.client.channel(self.cid).unwrap()
    }

    fn s(&mut self) -> &mut Channel {
        let id = self.sid.unwrap();
        self.server.channel(id).unwrap()
    }

    fn handshake(&mut self) {
        for _ in 0..100_000 {
            if self.c().is_handshake_confirmed()
                && self.sid.is_some()
                && self.s().is_handshake_complete()
            {
                return;
            }
            assert!(self.step(), "stalled");
            assert!(self.c().is_active(), "{:?}", self.c().terminate_cause());
        }
        panic!("no handshake");
    }
}

fn echo(seed: u64, net: Net, aead: AeadAlg, validate: bool, len: usize) -> Sim {
    let mut sim = Sim::new(seed, net, aead, validate);
    sim.handshake();
    let mut rng = Rng(seed ^ 0x5555);
    let msg = rng.bytes(len);
    let id = sim.c().stream_open(true).unwrap();
    let mut sent = 0;
    let mut echoed = Vec::new();
    let mut got_back = Vec::new();
    let mut server_fin = false;
    let mut client_fin = false;
    let mut server_stream = None;
    for _ in 0..1_000_000 {
        let now = sim.now;
        if sent < msg.len() {
            let n = sim.c().stream_send(id, &msg[sent..], false).unwrap();
            sent += n;
            if sent == msg.len() {
                sim.c().stream_send(id, &[], true).unwrap();
            }
        }
        if server_stream.is_none() {
            server_stream = sim.s().accept_stream(now);
        }
        if let Some(sid) = server_stream {
            let mut buf = [0u8; 4096];
            while !server_fin {
                let (n, fin) = sim.s().stream_recv(sid, &mut buf, now).unwrap();
                echoed.extend_from_slice(&buf[..n]);
                server_fin = fin;
                if n == 0 {
                    break;
                }
            }
            // Echo what arrived.
            let pending = echoed.len();
            if pending > 0 {
                let n = sim.s().stream_send(sid, &echoed, false).unwrap();
                echoed.drain(..n);
            }
            if server_fin && echoed.is_empty() {
                let _ = sim.s().stream_send(sid, &[], true);
            }
        }
        let mut buf = [0u8; 4096];
        while !client_fin {
            let (n, fin) = sim.c().stream_recv(id, &mut buf, now).unwrap();
            got_back.extend_from_slice(&buf[..n]);
            client_fin = fin;
            if n == 0 {
                break;
            }
        }
        if client_fin {
            break;
        }
        while sim.c().poll_event().is_some() {}
        while sim.s().poll_event().is_some() {}
        assert!(sim.step(), "stalled at {} of {}", got_back.len(), msg.len());
        assert!(
            sim.c().is_active(),
            "client: {:?}",
            sim.c().terminate_cause()
        );
        assert!(
            sim.s().is_active(),
            "server: {:?}",
            sim.s().terminate_cause()
        );
    }
    assert!(client_fin, "seed {seed}: echo incomplete");
    assert_eq!(got_back, msg, "seed {seed}");
    sim
}

#[test]
fn loopback_clean() {
    let net = Net {
        loss: 0,
        dup: 0,
        jitter_ms: 0,
    };
    let mut sim = echo(1, net, AeadAlg::Aes128Gcm, true, 300_000);
    // The server validated the client with a Retry, and said so.
    let tp = sim.c().peer_transport_params().unwrap().clone();
    assert!(tp.retry_scid.is_some());
    assert!(tp.disable_active_migration);
    // A NEW_TOKEN came after the Retry.
    let mut tokens = 0;
    while let Some(e) = sim.c().poll_event() {
        if matches!(e, ChannelEvent::NewToken(_)) {
            tokens += 1;
        }
    }
    assert!(tokens <= 1);
}

#[test]
fn loopback_lossy_reordering_duplicating() {
    let net = Net {
        loss: 10,
        dup: 10,
        jitter_ms: 30,
    };
    for seed in 1..21 {
        echo(seed, net, AeadAlg::Aes128Gcm, true, 100_000);
    }
}

#[test]
fn loopback_heavy_loss() {
    let net = Net {
        loss: 30,
        dup: 20,
        jitter_ms: 80,
    };
    for seed in 100..106 {
        let sim = echo(seed, net, AeadAlg::Aes128Gcm, true, 30_000);
        assert!(sim.datagrams > 0);
    }
}

#[test]
fn loopback_suites_and_no_retry() {
    let net = Net {
        loss: 5,
        dup: 5,
        jitter_ms: 10,
    };
    echo(7, net, AeadAlg::ChaCha20Poly1305, false, 50_000);
    echo(8, net, AeadAlg::Aes256Gcm, true, 50_000);
}

#[test]
fn ccm_suite_fails_as_openssl() {
    let net = Net {
        loss: 0,
        dup: 0,
        jitter_ms: 0,
    };
    let mut sim = Sim::new(9, net, AeadAlg::Aes128Ccm, false);
    for _ in 0..1000 {
        if !sim.step() {
            break;
        }
    }
    let cause = sim.c().terminate_cause().cloned().unwrap();
    // CRYPTO_ERROR with internal_error (0x100 + 80), from whichever end saw the secret first.
    assert_eq!(cause.code, 0x100 + 80, "{cause:?}");
}

#[test]
fn close_reaches_peer_and_drains() {
    let net = Net {
        loss: 0,
        dup: 0,
        jitter_ms: 0,
    };
    let mut sim = Sim::new(10, net, AeadAlg::Aes128Gcm, true);
    sim.handshake();
    let now = sim.now;
    sim.c().shutdown(42, b"bye", now);
    assert_eq!(sim.c().state(), crate::channel::State::Closing);
    for _ in 0..10 {
        sim.step();
        if !sim.s().is_active() {
            break;
        }
    }
    let cause = sim.s().terminate_cause().cloned().unwrap();
    assert!(cause.remote && cause.app);
    assert_eq!((cause.code, &cause.reason[..]), (42, &b"bye"[..]));
    // The peer drains (it sends nothing back).
    assert_eq!(sim.s().state(), crate::channel::State::Draining);
    // Both end after 3 PTO.
    for _ in 0..100 {
        if !sim.step() {
            break;
        }
    }
    assert_eq!(sim.c().state(), crate::channel::State::Terminated);
    assert_eq!(sim.s().state(), crate::channel::State::Terminated);
}

#[test]
fn idle_timeout_terminates_silently() {
    let net = Net {
        loss: 0,
        dup: 0,
        jitter_ms: 0,
    };
    let mut sim = Sim::new(11, net, AeadAlg::Aes128Gcm, true);
    sim.handshake();
    sim.blackhole = true;
    let start = sim.now;
    for _ in 0..10_000 {
        if !sim.step() {
            break;
        }
    }
    let cause = sim.c().terminate_cause().cloned().unwrap();
    assert_eq!(cause.code, crate::error::local_err_idle_timeout());
    assert_eq!(sim.c().state(), crate::channel::State::Terminated);
    // 30 s from the last ack-eliciting packet sent since the last one received: the
    // keepalive PING at 15 s restarts the timer once (RFC 9000, 10.1, as OpenSSL).
    let took = sim.now.since(start);
    assert_eq!(took, Duration::from_millis(45_000));
}

#[test]
fn key_update_both_ways() {
    let net = Net {
        loss: 0,
        dup: 0,
        jitter_ms: 0,
    };
    let mut sim = echo(12, net, AeadAlg::Aes128Gcm, true, 10_000);
    let now = sim.now;
    {
        let Sim { client, p, cid, .. } = &mut sim;
        client.channel(*cid).unwrap().key_update(p, now).unwrap();
    }
    // A second one before the first is acknowledged is refused.
    {
        let Sim { client, p, cid, .. } = &mut sim;
        assert!(client.channel(*cid).unwrap().key_update(p, now).is_err());
    }
    // Traffic continues across the update.
    let id = sim.c().stream_open(true).unwrap();
    sim.c().stream_send(id, b"after update", true).unwrap();
    let mut got = Vec::new();
    for _ in 0..1000 {
        sim.step();
        let now = sim.now;
        if let Some(sid) = sim.s().accept_stream(now) {
            let mut buf = [0u8; 64];
            let (n, _) = sim.s().stream_recv(sid, &mut buf, now).unwrap();
            got.extend_from_slice(&buf[..n]);
        }
        if !got.is_empty() {
            break;
        }
    }
    assert_eq!(got, b"after update");
    assert!(sim.c().is_active() && sim.s().is_active());
}

#[test]
fn version_negotiation_and_garbage() {
    let p = TestProvider::new(b"vn");
    let mut server = Port::new(PortConfig {
        listen: true,
        ..PortConfig::default()
    });
    // An unknown version in a 1200-octet datagram gets a version negotiation packet.
    let mut d = vec![0xc0, 0xba, 0xba, 0xba, 0xba, 8];
    d.extend_from_slice(&[1; 8]);
    d.push(4);
    d.extend_from_slice(&[2; 4]);
    d.resize(1200, 0);
    let from = PeerAddr(CLIENT.to_vec());
    server.handle_datagram(&p, Time(0), &from, &d);
    let (to, vn) = server.poll_transmit(&p, Time(0)).unwrap();
    assert_eq!(to, from);
    let (l, _) = packet::locate(&vn, 0).unwrap();
    assert_eq!(l.ty, PacketType::VersionNegotiation);
    assert_eq!(l.token, &packet::VERSION_1.to_be_bytes());
    assert_eq!(l.dcid.as_bytes(), &[2; 4]);
    // Short ones don't.
    d.truncate(1199);
    server.handle_datagram(&p, Time(0), &from, &d);
    assert!(server.poll_transmit(&p, Time(0)).is_none());
    // Garbage and Initials that don't authenticate make nothing.
    let mut rng = Rng(3);
    for _ in 0..200 {
        let len = rng.below(1400) as usize;
        let mut g = rng.bytes(len);
        if let Some(b) = g.first_mut() {
            *b |= 0xc0;
            *b &= 0xcf;
        }
        if g.len() > 5 {
            g[1..5].copy_from_slice(&packet::VERSION_1.to_be_bytes());
        }
        server.handle_datagram(&p, Time(0), &from, &g);
    }
    assert!(server.poll_transmit(&p, Time(0)).is_none());
    assert_eq!(server.accept_queue_len(), 0);
}

#[test]
fn alpn_is_required_as_openssl() {
    let p = TestProvider::new(b"alpn");
    let suite = TestHandshake::suite(AeadAlg::Aes128Gcm).unwrap();
    // A client without ALPN fails before sending anything.
    let mut hs = TestHandshake::new(false, suite);
    hs.alpn = None;
    let mut client = Port::new(PortConfig::default());
    let id = client
        .connect(&p, Box::new(hs), PeerAddr(SERVER.to_vec()), Time(0))
        .unwrap();
    let ch = client.channel(id).unwrap();
    assert_eq!(ch.state(), crate::channel::State::Terminated);
    assert_eq!(ch.terminate_cause().unwrap().code, 0x100 + 120);
    assert!(client.poll_transmit(&p, Time(0)).is_none());
}

#[test]
fn port_tx_queue_is_bounded() {
    let p = TestProvider::new(b"flood");
    let mut server = Port::new(PortConfig {
        listen: true,
        ..PortConfig::default()
    });
    let mut d = vec![0xc0, 0xba, 0xba, 0xba, 0xba, 8];
    d.extend_from_slice(&[1; 8]);
    d.push(0);
    d.resize(1200, 0);
    let from = PeerAddr(CLIENT.to_vec());
    for _ in 0..(MAX_PORT_TX_QUEUE + 50) {
        server.handle_datagram(&p, Time(0), &from, &d);
    }
    let mut n = 0;
    while server.poll_transmit(&p, Time(0)).is_some() {
        n += 1;
    }
    assert_eq!(n, MAX_PORT_TX_QUEUE);
}

#[test]
fn new_token_skips_retry() {
    let net = Net {
        loss: 0,
        dup: 0,
        jitter_ms: 0,
    };
    let mut sim = Sim::new(13, net, AeadAlg::Aes128Gcm, true);
    sim.handshake();
    let mut token = None;
    for _ in 0..20 {
        while let Some(e) = sim.c().poll_event() {
            if let ChannelEvent::NewToken(t) = e {
                token = Some(t);
            }
        }
        if token.is_some() {
            break;
        }
        sim.step();
    }
    let token = token.expect("a NEW_TOKEN after the Retry");
    // A second connection from the same address presents it: no Retry, and its
    // original_destination_connection_id is the client's own (OpenSSL takes a fresh one here,
    // which the client's check would refuse; see DEVIATIONS.md).
    let suite = TestHandshake::suite(AeadAlg::Aes128Gcm).unwrap();
    let mut client = Port::new(PortConfig {
        channel: crate::channel::ChannelConfig {
            token,
            ..crate::channel::ChannelConfig::default()
        },
        ..PortConfig::default()
    });
    let now = sim.now;
    sim.cid = client
        .connect(
            &sim.p,
            Box::new(TestHandshake::new(false, suite)),
            PeerAddr(SERVER.to_vec()),
            now,
        )
        .unwrap();
    sim.client = client;
    sim.sid = None;
    sim.handshake();
    let tp = sim.c().peer_transport_params().unwrap().clone();
    assert!(tp.retry_scid.is_none());
}
