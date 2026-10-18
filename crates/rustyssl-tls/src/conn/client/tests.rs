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
        let e = c.step(p, reading).inspect_err(|_| {
            eprintln!(
                "DEBUG state {} {:?}",
                c.state(),
                seen.written.iter().map(|m| m[0]).collect::<Vec<_>>()
            )
        })?;
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

/// The server's side of an RFC 8448 handshake, from the RFC's messages: the key schedule and
/// the transcript, to encrypt the server's flights and check the client's.
struct Server3 {
    sched: Schedule13,
    transcript: Vec<u8>,
    /// The transcript hash after the ServerHello.
    hs_hash: Vec<u8>,
    /// The transcript hash after the server's Finished, once the master secret is made.
    sf_hash: Vec<u8>,
}

impl Server3 {
    fn new(p: &TestProvider, psk: Option<&[u8]>, shared: &[u8], hellos: &[&[u8]]) -> Self {
        let mut sched = Schedule13::new(p, HashAlg::Sha256, psk).unwrap();
        sched.into_handshake(p, Some(shared)).unwrap();
        let transcript = hellos.concat();
        Self {
            sched,
            hs_hash: sha256(p, &transcript),
            transcript,
            sf_hash: Vec::new(),
        }
    }

    /// The handshake flight after the ServerHello, encrypted.
    fn flight(&mut self, p: &TestProvider, msgs: &[&[u8]]) -> Vec<u8> {
        let secret = self
            .sched
            .server_handshake_traffic(p, &self.hs_hash)
            .unwrap();
        let mut w = writer13(p, secret.bytes());
        for m in msgs {
            self.transcript.extend_from_slice(m);
        }
        seal(p, &mut w, msgs)
    }

    /// The Finished the client must send after `msgs` (its certificate messages).
    fn client_finished(&mut self, p: &TestProvider, msgs: &[Vec<u8>]) -> Vec<u8> {
        for m in msgs {
            self.transcript.extend_from_slice(m);
        }
        let base = self
            .sched
            .client_handshake_traffic(p, &self.hs_hash)
            .unwrap();
        let th = sha256(p, &self.transcript);
        let vd = keysched::verify_data_13(p, HashAlg::Sha256, base.bytes(), &th).unwrap();
        crate::msgs::frame(hm::FINISHED, &vd).unwrap()
    }

    /// Moves to the master secret, after the server's Finished.
    fn master(&mut self, p: &TestProvider) {
        if self.sf_hash.is_empty() {
            self.sf_hash = sha256(p, &self.transcript);
            self.sched.into_master(p).unwrap();
        }
    }

    /// Application data records (a NewSessionTicket) after the server's Finished.
    fn app(&mut self, p: &TestProvider, msgs: &[&[u8]]) -> Vec<u8> {
        self.master(p);
        let secret = self
            .sched
            .server_application_traffic(p, &self.sf_hash)
            .unwrap();
        let mut w = writer13(p, secret.bytes());
        seal(p, &mut w, msgs)
    }

    /// The client's first application traffic secret.
    fn client_app(&mut self, p: &TestProvider) -> Vec<u8> {
        self.master(p);
        self.sched
            .client_application_traffic(p, &self.sf_hash)
            .unwrap()
            .bytes()
            .to_vec()
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

/// A ClientHello's random.
fn random_of(ch: &[u8]) -> &[u8] {
    &ch[6..38]
}

/// A ServerHello's key share (its encoded public value).
fn server_share(sh: &[u8]) -> Vec<u8> {
    let m = crate::msgs::hello::ServerHello::parse(&sh[4..], false).unwrap();
    let exts = crate::msgs::ext::split(&m.extensions.unwrap()).unwrap();
    let ks = exts.iter().find(|e| e.typ == 0x0033).unwrap();
    crate::msgs::ext::key_share::parse_server(&ks.body)
        .unwrap()
        .key
}

/// The shared secret of `group` from the client's private key (`private`, drawn as the
/// provider generates it) and the server's share.
fn shared_of(p: &TestProvider, group: u16, private: &str, server: &[u8]) -> Vec<u8> {
    use crate::crypto::Provider;
    p.queue_random(&h(private));
    let share = p.key_share(group).unwrap();
    share.derive(server).unwrap().bytes().to_vec()
}

/// An extension's body in a ClientHello's body.
fn hello_ext(body: &[u8], typ: u16) -> Option<Vec<u8>> {
    crate::msgs::hello::ClientHello::parse(body, false)
        .unwrap()
        .extensions()
        .unwrap()
        .into_iter()
        .find(|e| e.typ == typ)
        .map(|e| e.body)
}

const S5_X25519_PRIVATE: &str = "0ed02f8e8117efc75ca7ac32aa7e34eda64cdc0ddad154a5e85289f959f63204";
const S5_P256_PRIVATE: &str = "ab5473467e19346ceb0a0414e41da21d4d2445bc3025afe97c4e8dc8d513da39";

#[test]
fn rfc8448_section5_hello_retry_request() {
    let p = TestProvider::new(b"rfc8448-5");
    let ch1 = rfc("5", "ClientHello", 0);
    let hrr = rfc("5", "ServerHello", 0);
    let ch2 = rfc("5", "ClientHello", 1);
    let sh = rfc("5", "ServerHello", 1);
    p.queue_random(random_of(ch1));
    p.queue_random(&h(S5_X25519_PRIVATE));
    let mut c = with_hellos(rfc_client(), &[ch1, ch2]);
    let mut seen = Seen::default();
    assert_eq!(
        drive(&mut c, &p, false, &mut accept, &mut seen).unwrap(),
        Event::NeedInput
    );
    assert_eq!(seen.written, [ch1.to_vec()]);
    // The HelloRetryRequest asks for P-256 and gives a cookie.
    p.queue_random(&h(S5_P256_PRIVATE));
    c.feed(&record(22, hrr));
    seen.written.clear();
    assert_eq!(
        drive(&mut c, &p, false, &mut accept, &mut seen).unwrap(),
        Event::NeedInput
    );
    assert_eq!(seen.written, [ch2.to_vec()]);
    assert_eq!(c.handshake().sh.hrr, Hrr::Pending);
    // The ClientHello the client made itself has the RFC's new share, its cookie, and its
    // random.
    let made = super::state_ref(&c).unwrap().made.clone();
    let ours = &made[1];
    assert_eq!(ours[2..34], *random_of(ch2));
    assert_eq!(hello_ext(ours, 0x0033), hello_ext(&ch2[4..], 0x0033));
    assert_eq!(hello_ext(ours, 0x002c), hello_ext(&ch2[4..], 0x002c));
    // The transcript starts again with the first ClientHello's hash.
    let msghash = crate::msgs::message_hash(&sha256(&p, ch1)).unwrap();
    let shared = shared_of(&p, 0x0017, S5_P256_PRIVATE, &server_share(sh));
    let mut server = Server3::new(&p, None, &shared, &[&msghash, hrr, ch2, sh]);
    let flight = server.flight(
        &p,
        &[
            rfc("5", "EncryptedExtensions", 0),
            rfc("5", "Certificate", 0),
            rfc("5", "CertificateVerify", 0),
            rfc("5", "Finished", 0),
        ],
    );
    c.feed(&record(22, sh));
    c.feed(&flight);
    seen.written.clear();
    assert_eq!(
        drive(&mut c, &p, false, &mut accept, &mut seen).unwrap(),
        Event::HandshakeDone
    );
    assert_eq!(seen.written, [rfc("5", "Finished", 1).to_vec()]);
    assert_eq!(c.negotiated().group, Some(0x0017));
}

const S4_CLIENT_PRIVATE: &str = "bff91188283846dd6a2134ef7180ca2b0b14fb10dce707b5098c0dddc813b2df";

/// Section 3's session, from its NewSessionTicket.
fn section3_session(p: &TestProvider) -> Session {
    let (mut c, mut seen, mut server) = section3(p, rfc_client());
    drive(&mut c, p, false, &mut accept, &mut seen).unwrap();
    let nst = server.app(p, &[rfc("3", "NewSessionTicket", 0)]);
    c.feed(&nst);
    while drive(&mut c, p, true, &mut accept, &mut seen).unwrap() != Event::NeedInput {}
    c.negotiated().session.clone()
}

#[test]
fn rfc8448_section4_resumption_with_early_data() {
    let p = TestProvider::new(b"rfc8448-4");
    let session = section3_session(&p);
    let ch = rfc("4", "ClientHello", 0);
    let sh = rfc("4", "ServerHello", 0);
    p.queue_random(random_of(ch));
    p.queue_random(&h(S4_CLIENT_PRIVATE));
    let mut cfg = rfc_client();
    cfg.session = Some(session.clone());
    let mut c = with_hellos(cfg, &[ch]);
    c.hs.sh.early_data_state = EarlyDataState::Connecting;
    let mut seen = Seen::default();
    // The ClientHello, then the handshake pauses for the early data.
    assert_eq!(
        drive(&mut c, &p, false, &mut accept, &mut seen).unwrap(),
        Event::HandshakeDone
    );
    assert_eq!(seen.written, [ch.to_vec()]);
    assert_eq!(c.state(), abi::TLS_ST_EARLY_DATA);
    // The client's own ClientHello offered the ticket with an early_data extension; its binder
    // over the RFC's ClientHello is the RFC's.
    let made = super::state_ref(&c).unwrap().made[0].clone();
    assert_eq!(hello_ext(&made, 0x002a), Some(Vec::new()));
    let ours = crate::msgs::ext::psk::Strict::parse(&hello_ext(&made, 0x0029).unwrap()).unwrap();
    let theirs =
        crate::msgs::ext::psk::Strict::parse(&hello_ext(&ch[4..], 0x0029).unwrap()).unwrap();
    assert_eq!(ours.identities[0].identity, theirs.identities[0].identity);
    let cut = ch.len() - theirs.binders_len();
    let (_, binder) = crate::conn::common::ext::psk_do_binder(
        &c,
        &p,
        HashAlg::Sha256,
        &ch[..cut],
        &session.master_key,
        false,
        None,
    )
    .unwrap();
    assert_eq!(binder, theirs.binders[0]);
    // The early data is written; the handshake goes on.
    c.write_app(&p, b"early").unwrap();
    c.hs.sh.early_data_state = EarlyDataState::FinishedWriting;
    c.start();
    let shared = x25519(S4_CLIENT_PRIVATE, &server_share(sh));
    let mut server = Server3::new(&p, Some(&session.master_key), &shared, &[ch, sh]);
    let flight = server.flight(
        &p,
        &[rfc("4", "EncryptedExtensions", 0), rfc("4", "Finished", 0)],
    );
    c.feed(&record(22, sh));
    c.feed(&flight);
    seen.written.clear();
    assert_eq!(
        drive(&mut c, &p, false, &mut accept, &mut seen).unwrap(),
        Event::HandshakeDone
    );
    // EndOfEarlyData and the Finished, as the RFC's.
    assert_eq!(
        seen.written,
        [
            rfc("4", "EndOfEarlyData", 0).to_vec(),
            rfc("4", "Finished", 1).to_vec()
        ]
    );
    assert!(c.negotiated().reused);
    assert_eq!(
        c.negotiated().early_data_status,
        abi::SSL_EARLY_DATA_ACCEPTED
    );
}

const S7_CLIENT_PRIVATE: &str = "dea00b45695dc781f19d34a62c1afd31ab4369af1e855a3bbb258d8442cde6d7";

#[test]
fn rfc8448_section7_compatibility_mode() {
    let p = TestProvider::new(b"rfc8448-7");
    let ch = rfc("7", "ClientHello", 0);
    let sh = rfc("7", "ServerHello", 0);
    p.queue_random(random_of(ch));
    // The legacy_session_id, then the key share.
    p.queue_random(&ch[39..71]);
    p.queue_random(&h(S7_CLIENT_PRIVATE));
    let mut cfg = rfc_client();
    cfg.options |= abi::SSL_OP_ENABLE_MIDDLEBOX_COMPAT;
    let mut c = with_hellos(cfg, &[ch]);
    let mut seen = Seen::default();
    drive(&mut c, &p, false, &mut accept, &mut seen).unwrap();
    let made = super::state_ref(&c).unwrap().made[0].clone();
    assert_eq!(made[34], 32);
    assert_eq!(made[35..67], ch[39..71]);
    let shared = x25519(S7_CLIENT_PRIVATE, &server_share(sh));
    let mut server = Server3::new(&p, None, &shared, &[ch, sh]);
    let flight = server.flight(
        &p,
        &[
            rfc("7", "EncryptedExtensions", 0),
            rfc("7", "Certificate", 0),
            rfc("7", "CertificateVerify", 0),
            rfc("7", "Finished", 0),
        ],
    );
    c.feed(&record(22, sh));
    // The server's compatibility ChangeCipherSpec is ignored.
    c.feed(&record(20, &[1]));
    c.feed(&flight);
    seen.written.clear();
    seen.output.clear();
    assert_eq!(
        drive(&mut c, &p, false, &mut accept, &mut seen).unwrap(),
        Event::HandshakeDone
    );
    assert_eq!(seen.written, [rfc("7", "Finished", 1).to_vec()]);
    // The client's ChangeCipherSpec went first, in plaintext.
    assert_eq!(seen.output[..6], [20, 3, 3, 0, 1, 1]);
}

/// An ECDSA P-256 certificate and key for the client.
fn client_cert(p: &TestProvider) -> crate::conn::CertKey {
    use crate::testprov::keys::PrivateKey;
    let k = PrivateKey::ec(abi::NID_X9_62_prime256v1, p).unwrap();
    let cert = k.public(p).unwrap().cert("client");
    crate::conn::CertKey {
        chain: vec![cert],
        key: p.add_key(k),
        slot: crate::conn::common::sigalgs::PKEY_ECC,
        schemes: vec![0x0403],
        auth: crate::suites::masks::SSL_aECDSA,
        ec_group: Some(0x0017),
        curve_nid: abi::NID_X9_62_prime256v1,
        can_sign: true,
        cert_sig: None,
        raw_public_key: None,
        ocsp_response: None,
    }
}

const S6_CLIENT_PRIVATE: &str = "c040b2bb8f3addd20fd4058c547003a3c6f9c1cd915d5e535c87d8d191aaf071";

#[test]
fn rfc8448_section6_client_authentication() {
    let p = TestProvider::new(b"rfc8448-6");
    let ch = rfc("6", "ClientHello", 0);
    let sh = rfc("6", "ServerHello", 0);
    let mut cfg = rfc_client();
    cfg.certs = vec![client_cert(&p)];
    p.queue_random(random_of(ch));
    p.queue_random(&h(S6_CLIENT_PRIVATE));
    let mut c = with_hellos(cfg, &[ch]);
    let mut seen = Seen::default();
    drive(&mut c, &p, false, &mut accept, &mut seen).unwrap();
    let shared = x25519(S6_CLIENT_PRIVATE, &server_share(sh));
    let mut server = Server3::new(&p, None, &shared, &[ch, sh]);
    let flight = server.flight(
        &p,
        &[
            rfc("6", "EncryptedExtensions", 0),
            rfc("6", "CertificateRequest", 0),
            rfc("6", "Certificate", 0),
            rfc("6", "CertificateVerify", 0),
            rfc("6", "Finished", 0),
        ],
    );
    c.feed(&record(22, sh));
    c.feed(&flight);
    seen.written.clear();
    assert_eq!(
        drive(&mut c, &p, false, &mut accept, &mut seen).unwrap(),
        Event::HandshakeDone
    );
    // The server's ECDSA certificate verified; the client sent its own chain, signed with
    // ECDSA, and a Finished over them.
    let [cert, cv, fin] = &seen.written[..] else {
        panic!("{:?}", seen.written.len())
    };
    assert_eq!(cert[0], hm::CERTIFICATE);
    assert_eq!(cert[4], 0, "an empty certificate_request_context");
    let chain = &c.config().certs[0].chain[0];
    assert_eq!(
        cert[4..],
        [
            &[0][..],
            &u32::try_from(chain.len() + 5).unwrap().to_be_bytes()[1..],
            &u32::try_from(chain.len()).unwrap().to_be_bytes()[1..],
            chain,
            &[0, 0]
        ]
        .concat()
    );
    assert_eq!(cv[..6], [hm::CERTIFICATE_VERIFY, 0, 0, cv[3], 0x04, 0x03]);
    let expected = server.client_finished(&p, &[cert.clone(), cv.clone()]);
    assert_eq!(*fin, expected);
    assert_eq!(c.negotiated().own_scheme, Some(0x0403));
}

#[test]
fn rfc8448_section6_without_a_certificate() {
    let p = TestProvider::new(b"rfc8448-6b");
    let ch = rfc("6", "ClientHello", 0);
    let sh = rfc("6", "ServerHello", 0);
    p.queue_random(random_of(ch));
    p.queue_random(&h(S6_CLIENT_PRIVATE));
    let mut cfg = rfc_client();
    cfg.callbacks.client_cert = true;
    let mut c = with_hellos(cfg, &[ch]);
    let mut seen = Seen::default();
    drive(&mut c, &p, false, &mut accept, &mut seen).unwrap();
    let shared = x25519(S6_CLIENT_PRIVATE, &server_share(sh));
    let mut server = Server3::new(&p, None, &shared, &[ch, sh]);
    let flight = server.flight(
        &p,
        &[
            rfc("6", "EncryptedExtensions", 0),
            rfc("6", "CertificateRequest", 0),
            rfc("6", "Certificate", 0),
            rfc("6", "CertificateVerify", 0),
            rfc("6", "Finished", 0),
        ],
    );
    c.feed(&record(22, sh));
    c.feed(&flight);
    seen.written.clear();
    // The client certificate callback has nothing to give.
    let mut none = |r: &Request| match r {
        Request::ClientCert => Answer::Allowed(false),
        _ => accept(r),
    };
    assert_eq!(
        drive(&mut c, &p, false, &mut none, &mut seen).unwrap(),
        Event::HandshakeDone
    );
    assert!(seen.requests.contains(&Request::ClientCert));
    // An empty Certificate, no CertificateVerify.
    let empty = vec![hm::CERTIFICATE, 0, 0, 4, 0, 0, 0, 0];
    assert_eq!(seen.written[0], empty);
    let expected = server.client_finished(&p, &[empty]);
    assert_eq!(seen.written[1..], [expected]);
}

/// Section 3's handshake done, with the server's state.
fn section3_done(p: &TestProvider, cfg: Config) -> (Connection, Seen, Server3) {
    let (mut c, mut seen, mut server) = section3(p, cfg);
    assert_eq!(
        drive(&mut c, p, false, &mut accept, &mut seen).unwrap(),
        Event::HandshakeDone
    );
    server.master(p);
    server.transcript.extend_from_slice(&seen.written[0]);
    seen.written.clear();
    (c, seen, server)
}

#[test]
fn post_handshake_authentication() {
    let p = TestProvider::new(b"pha");
    let mut cfg = rfc_client();
    cfg.post_handshake_auth = true;
    cfg.certs = vec![client_cert(&p)];
    let (mut c, mut seen, mut server) = section3_done(&p, cfg);
    assert_eq!(c.handshake().sh.pha, crate::conn::common::Pha::ExtSent);
    // The transcript the request continues from: the handshake's, through the client's
    // Finished.
    let at_finished = server.transcript.clone();
    let cr = crate::msgs::frame(
        hm::CERTIFICATE_REQUEST,
        &[
            &[3, b'a', b'b', b'c'][..],
            &[0, 8, 0, 13, 0, 4, 0, 2, 4, 3][..],
        ]
        .concat(),
    )
    .unwrap();
    let rec = server.app(&p, &[&cr]);
    c.feed(&rec);
    while drive(&mut c, &p, true, &mut accept, &mut seen).unwrap() != Event::NeedInput {}
    let [cert, cv, fin] = &seen.written[..] else {
        panic!("{:?}", seen.written.len())
    };
    assert_eq!(cert[4..8], [3, b'a', b'b', b'c']);
    assert_eq!(cv[4..6], [0x04, 0x03]);
    // The Finished uses the client's application secret, over the handshake, the request, and
    // the client's answer.
    let base = server.client_app(&p);
    let th = sha256(&p, &[&at_finished[..], &cr, cert, cv].concat());
    let vd = keysched::verify_data_13(&p, HashAlg::Sha256, &base, &th).unwrap();
    assert_eq!(fin[4..], vd);
    assert_eq!(c.handshake().sh.pha, crate::conn::common::Pha::ExtSent);
}

#[test]
fn key_update_requested_by_the_server() {
    let p = TestProvider::new(b"key-update");
    let (mut c, mut seen, mut server) = section3_done(&p, rfc_client());
    let ku = crate::msgs::frame(hm::KEY_UPDATE, &[1]).unwrap();
    let rec = server.app(&p, &[&ku]);
    c.feed(&rec);
    while drive(&mut c, &p, true, &mut accept, &mut seen).unwrap() != Event::NeedInput {}
    // The read keys moved on; the client owes a KeyUpdate of its own.
    assert_eq!(
        c.handshake().sh.key_update,
        abi::SSL_KEY_UPDATE_NOT_REQUESTED
    );
    let old = server.client_app(&p);
    let next = keysched::next_traffic_secret(&p, HashAlg::Sha256, &old).unwrap();
    // Data under the server's next keys reads.
    let s_next = keysched::next_traffic_secret(
        &p,
        HashAlg::Sha256,
        server
            .sched
            .server_application_traffic(&p, &server.sf_hash)
            .unwrap()
            .bytes(),
    )
    .unwrap();
    let mut w = writer13(&p, s_next.bytes());
    let mut data = Vec::new();
    w.write(&p, 23, b"hi", &mut data).unwrap();
    c.feed(&data);
    assert_eq!(
        drive(&mut c, &p, true, &mut accept, &mut seen).unwrap(),
        Event::AppData
    );
    let mut buf = [0u8; 2];
    assert_eq!(c.read_app(&mut buf, false), 2);
    assert_eq!(&buf, b"hi");
    // When the write side runs again (as `SSL_write` arranges), the KeyUpdate goes out and the
    // write keys move on.
    c.st.in_init = true;
    c.st.state = crate::conn::statem::MsgFlow::Writing;
    c.st.write_state = crate::conn::statem::WriteState::Transition;
    seen.written.clear();
    drive(&mut c, &p, false, &mut accept, &mut seen).unwrap();
    assert_eq!(seen.written, [vec![hm::KEY_UPDATE, 0, 0, 1, 0]]);
    assert_eq!(
        c.handshake().sh.keys.client_app_secret.bytes(),
        next.bytes()
    );
}
