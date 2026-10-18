//! Tests of the client's state machine with the test provider: RFC 8448's handshakes replayed
//! (the server's flights encrypted here from the RFC's messages, the client's answers compared
//! octet for octet), and malformed or unexpected server messages.
//!
//! The RFC's ClientHellos were made by another implementation, whose extensions come in
//! another order than OpenSSL's, so the client is made to send the RFC's (its own state, the
//! random and key share, is made as usual from the RFC's random values); what OpenSSL's
//! ClientHello holds is checked separately.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use rustyssl_abi as abi;

use super::State;
use crate::conn::common::{EarlyDataState, Hrr};
use crate::conn::{Answer, Config, Connection, Event, Request, RoleState, Session};
use crate::consts::{handshake as hm, version as v};
use crate::crypto::{AeadAlg, HashAlg};
use crate::error::Error;
use crate::keysched::{self, Schedule13};
use crate::msgs::rfc8448::VECTORS;
use crate::record::{Mode, Protection, RecordWriter};
use crate::suites;
use crate::testprov::TestProvider;

fn h(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// RFC 8448's `nth` message called `name` in `section`, with its header.
fn rfc(section: &str, name: &str, nth: usize) -> &'static [u8] {
    VECTORS
        .iter()
        .filter(|(s, n, _)| *s == section && *n == name)
        .nth(nth)
        .unwrap_or_else(|| panic!("{section} {name} {nth}"))
        .2
}

/// A plaintext record.
fn record(ty: u8, body: &[u8]) -> Vec<u8> {
    let mut r = vec![ty, 3, 3];
    r.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    r.extend_from_slice(body);
    r
}

/// A TLS 1.3 record writer with the traffic secret `secret` (TLS_AES_128_GCM_SHA256).
fn writer13(p: &TestProvider, secret: &[u8]) -> RecordWriter {
    let k = keysched::traffic_keys(p, HashAlg::Sha256, secret, 16, 12).unwrap();
    let mut w = RecordWriter::new(v::TLS1_2);
    w.set_protection(
        Mode::Tls13,
        Protection::tls13(p, AeadAlg::Aes128Gcm, k.key.bytes(), k.iv.bytes()).unwrap(),
    );
    w
}

/// Encrypts handshake `msgs` with `w`.
fn seal(p: &TestProvider, w: &mut RecordWriter, msgs: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    w.write(p, 22, &msgs.concat(), &mut out).unwrap();
    out
}

fn sha256(p: &TestProvider, data: &[u8]) -> Vec<u8> {
    keysched::hash_of(p, HashAlg::Sha256, data).unwrap()
}

/// What a run of [`drive`] saw.
#[derive(Default)]
struct Seen {
    /// The handshake messages written (the message callback's).
    written: Vec<Vec<u8>>,
    /// The network output.
    output: Vec<u8>,
    /// The other events.
    events: Vec<Event>,
    /// The requests answered.
    requests: Vec<Request>,
}

/// Steps `c` until it needs input, finishes the handshake, or idles, answering requests with
/// `answer`.
fn drive(
    c: &mut Connection,
    p: &TestProvider,
    reading: bool,
    answer: &mut dyn FnMut(&Request) -> Answer,
    seen: &mut Seen,
) -> Result<Event, Error> {
    for _ in 0..10_000 {
        let e = c.step(p, reading)?;
        match e {
            Event::Request(r) => {
                let a = answer(&r);
                seen.requests.push(r);
                c.answer(a);
            }
            Event::Output => seen.output.extend(c.take_output()),
            Event::Message {
                write: true,
                content_type: 22,
                bytes,
                ..
            } => seen.written.push(bytes),
            Event::NeedInput | Event::HandshakeDone | Event::Idle | Event::AppData => {
                seen.output.extend(c.take_output());
                return Ok(e);
            }
            other => seen.events.push(other),
        }
    }
    panic!("no progress");
}

/// Accepts every chain.
fn accept(r: &Request) -> Answer {
    match r {
        Request::Verify { chain } => Answer::Verified {
            result: i64::from(abi::X509_V_OK),
            proceed: true,
            verified_chain: chain.clone(),
        },
        _ => Answer::Continue,
    }
}

/// A TLS 1.3-only client like RFC 8448's: its suites, groups, and name.
fn rfc_client() -> Config {
    Config {
        min_version: v::TLS1_3,
        max_version: v::TLS1_3,
        ciphers: [0x1301, 0x1303, 0x1302]
            .iter()
            .map(|&id| suites::by_protocol_id(id).unwrap())
            .collect(),
        groups: vec![0x001d, 0x0017, 0x0018],
        key_share_groups: vec![0x001d],
        hostname: Some(b"server".to_vec()),
        max_cert_list: 102_400,
        max_send_fragment: 16384,
        verify_mode: abi::SSL_VERIFY_PEER,
        num_tickets: 2,
        now: Some(1_700_000_000),
        callbacks: crate::conn::Callbacks {
            msg: true,
            ..Default::default()
        },
        ..Config::default()
    }
}

/// A connection that will send `hellos` (RFC 8448's) in place of its own.
fn with_hellos(cfg: Config, hellos: &[&[u8]]) -> Connection {
    let mut c = Connection::new(cfg);
    c.hs.role = RoleState::Client(Box::new(State {
        hello_override: hellos.iter().map(|m| m[4..].to_vec()).collect(),
        ..State::default()
    }));
    c
}

const S3_CLIENT_RANDOM: &str = "cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7";
const S3_CLIENT_PRIVATE: &str = "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005";

fn x25519(private: &str, peer: &[u8]) -> Vec<u8> {
    let k: [u8; 32] = h(private).try_into().unwrap();
    let pk: [u8; 32] = peer.try_into().unwrap();
    rustyssl_crypto::ecx::x25519(&k, &pk).unwrap().to_vec()
}

/// The server's side of RFC 8448's section 3, from the RFC's messages.
struct Server3 {
    sched: Schedule13,
    transcript: Vec<u8>,
}

impl Server3 {
    fn new(p: &TestProvider, psk: Option<&[u8]>, shared: &[u8], hellos: &[&[u8]]) -> Self {
        let mut sched = Schedule13::new(p, HashAlg::Sha256, psk).unwrap();
        sched.into_handshake(p, Some(shared)).unwrap();
        Self {
            sched,
            transcript: hellos.concat(),
        }
    }

    /// The handshake flight after the ServerHello, encrypted.
    fn flight(&mut self, p: &TestProvider, msgs: &[&[u8]]) -> Vec<u8> {
        let th = sha256(p, &self.transcript);
        let secret = self.sched.server_handshake_traffic(p, &th).unwrap();
        let mut w = writer13(p, secret.bytes());
        for m in msgs {
            self.transcript.extend_from_slice(m);
        }
        seal(p, &mut w, msgs)
    }

    /// Application data records (a NewSessionTicket) after the server's Finished.
    fn app(&mut self, p: &TestProvider, msgs: &[&[u8]]) -> Vec<u8> {
        let th = sha256(p, &self.transcript);
        let mut s = Schedule13::new(p, HashAlg::Sha256, None).unwrap();
        core::mem::swap(&mut s, &mut self.sched);
        s.into_master(p).unwrap();
        let secret = s.server_application_traffic(p, &th).unwrap();
        let mut w = writer13(p, secret.bytes());
        seal(p, &mut w, msgs)
    }
}

/// Section 3's client up to its Finished: the ClientHello, then the server's flight.
fn section3(p: &TestProvider, cfg: Config) -> (Connection, Seen, Server3) {
    p.queue_random(&h(S3_CLIENT_RANDOM));
    p.queue_random(&h(S3_CLIENT_PRIVATE));
    let ch = rfc("3", "ClientHello", 0);
    let mut c = with_hellos(cfg, &[ch]);
    let mut seen = Seen::default();
    assert_eq!(
        drive(&mut c, p, false, &mut accept, &mut seen).unwrap(),
        Event::NeedInput
    );
    assert_eq!(seen.written, [ch.to_vec()]);
    assert_eq!(c.state(), abi::TLS_ST_CW_CLNT_HELLO);
    let sh = rfc("3", "ServerHello", 0);
    let shared = x25519(S3_CLIENT_PRIVATE, &sh[sh.len() - 38..sh.len() - 6]);
    let mut server = Server3::new(p, None, &shared, &[ch, sh]);
    let flight = server.flight(
        p,
        &[
            rfc("3", "EncryptedExtensions", 0),
            rfc("3", "Certificate", 0),
            rfc("3", "CertificateVerify", 0),
            rfc("3", "Finished", 0),
        ],
    );
    c.feed(&record(22, sh));
    c.feed(&flight);
    seen.written.clear();
    (c, seen, server)
}

#[test]
fn rfc8448_section3_full_handshake() {
    let p = TestProvider::new(b"rfc8448-3");
    let (mut c, mut seen, mut server) = section3(&p, rfc_client());
    assert_eq!(
        drive(&mut c, &p, false, &mut accept, &mut seen).unwrap(),
        Event::HandshakeDone
    );
    // The client's second flight is the RFC's Finished.
    assert_eq!(seen.written, [rfc("3", "Finished", 1).to_vec()]);
    assert_eq!(c.state(), abi::TLS_ST_OK);
    assert!(c.is_tls13());
    let n = c.negotiated();
    assert_eq!(n.cipher.unwrap().protocol_id(), 0x1301);
    assert_eq!(n.group, Some(0x001d));
    assert_eq!(n.peer_chain.len(), 1);
    assert_eq!(n.session.hostname.as_deref(), Some(&b"server"[..]));
    assert!(!n.reused);
    assert!(
        seen.requests
            .iter()
            .any(|r| matches!(r, Request::Verify { chain } if chain.len() == 1))
    );
    assert!(seen.events.contains(&Event::RemoveSession));

    // The NewSessionTicket, after the handshake (under the keys from the server's Finished).
    let nst = server.app(&p, &[rfc("3", "NewSessionTicket", 0)]);
    c.feed(&nst);
    seen.events.clear();
    // The ticket goes through the state machine again (which reports the handshake done).
    while drive(&mut c, &p, true, &mut accept, &mut seen).unwrap() != Event::NeedInput {}
    assert!(seen.events.contains(&Event::UpdateCache { server: false }));
    let s = &c.negotiated().session;
    assert_eq!(s.version, v::TLS1_3);
    assert_eq!(s.ticket_lifetime_hint, 30);
    assert_eq!(s.ticket_age_add, 0xfad6_aac5);
    assert_eq!(s.max_early_data, 1024);
    // RFC 8448's resumption PSK.
    assert_eq!(
        s.master_key,
        h("4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3")
    );
    assert_eq!(s.session_id, sha256(&p, s.ticket.as_ref().unwrap()));
}

#[test]
fn openssls_client_hello() {
    let p = TestProvider::new(b"client-hello");
    p.queue_random(&h(S3_CLIENT_RANDOM));
    p.queue_random(&h(S3_CLIENT_PRIVATE));
    let mut c = Connection::new(rfc_client());
    let mut seen = Seen::default();
    drive(&mut c, &p, false, &mut accept, &mut seen).unwrap();
    let [ch] = &seen.written[..] else {
        panic!("{:?}", seen.written)
    };
    let rfc_ch = rfc("3", "ClientHello", 0);
    // Version, random, empty session ID (no middlebox compatibility), and suites as the RFC's.
    assert_eq!(
        ch[4..4 + 2 + 32 + 1 + 2 + 6 + 2],
        rfc_ch[4..4 + 2 + 32 + 1 + 2 + 6 + 2]
    );
    let body = crate::msgs::hello::ClientHello::parse(&ch[4..], false).unwrap();
    let exts = body.extensions().unwrap();
    let types: Vec<u16> = exts.iter().map(|e| e.typ).collect();
    // OpenSSL's order (ext_defs[]); offering TLS 1.3 only it leaves out renegotiation_info
    // but still sends the TLS 1.2 ones (its version is undecided while it writes).
    assert_eq!(
        types,
        [
            0x0000, 0x000b, 0x000a, 0x0023, 0x0016, 0x0017, 0x000d, 0x002b, 0x002d, 0x0033
        ]
    );
    let rfc_exts = crate::msgs::hello::ClientHello::parse(&rfc_ch[4..], false)
        .unwrap()
        .extensions()
        .unwrap();
    for t in [0x0000u16, 0x002b, 0x002d, 0x0033] {
        let ours = exts.iter().find(|e| e.typ == t).unwrap();
        let theirs = rfc_exts.iter().find(|e| e.typ == t).unwrap();
        assert_eq!(ours.body, theirs.body, "extension {t:#06x}");
    }
}
