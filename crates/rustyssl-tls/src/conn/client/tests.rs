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
        Request::Verify { chain, .. } => Answer::Verified {
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
        now: 1_700_000_000,
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
            .any(|r| matches!(r, Request::Verify { chain, .. } if chain.len() == 1))
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
        chain_security: None,
        unsupported_digests: Vec::new(),
        strict: None,
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

/// Section 3's ServerHello, changed by `f`.
fn sh3(f: impl FnOnce(&mut crate::msgs::hello::ServerHello)) -> Vec<u8> {
    let mut m =
        crate::msgs::hello::ServerHello::parse(&rfc("3", "ServerHello", 0)[4..], false).unwrap();
    f(&mut m);
    crate::msgs::frame(hm::SERVER_HELLO, &m.encode().unwrap()).unwrap()
}

/// An extension block's contents.
fn ext_block(exts: &[(u16, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (t, b) in exts {
        out.extend_from_slice(&t.to_be_bytes());
        out.extend_from_slice(&u16::try_from(b.len()).unwrap().to_be_bytes());
        out.extend_from_slice(b);
    }
    out
}

/// The error a section 3 client stops with after its ClientHello, given `input`.
fn hello_error(cfg: Config, input: &[u8]) -> Error {
    let p = TestProvider::new(b"negative");
    p.queue_random(&h(S3_CLIENT_RANDOM));
    p.queue_random(&h(S3_CLIENT_PRIVATE));
    let mut c = with_hellos(cfg, &[rfc("3", "ClientHello", 0)]);
    let mut seen = Seen::default();
    drive(&mut c, &p, false, &mut accept, &mut seen).unwrap();
    c.feed(input);
    let e = loop {
        match drive(&mut c, &p, false, &mut accept, &mut seen) {
            Err(e) => break e,
            Ok(Event::NeedInput) => panic!("no error"),
            Ok(_) => {}
        }
    };
    // The alert went out.
    if let Some(a) = e.alert {
        assert_eq!(c.alerts().0, Some((2, a)));
    }
    e
}

fn ill(r: core::ffi::c_int) -> Error {
    Error::alert(abi::SSL_AD_ILLEGAL_PARAMETER, r)
}

#[test]
fn malformed_and_unacceptable_server_hellos() {
    let sh = rfc("3", "ServerHello", 0);
    let rec = |m: &[u8]| record(22, m);
    // Truncated.
    let short = crate::msgs::frame(hm::SERVER_HELLO, &sh[4..20]).unwrap();
    assert_eq!(
        hello_error(rfc_client(), &rec(&short)),
        Error::decode(abi::SSL_R_LENGTH_MISMATCH)
    );
    // A suite nobody knows, one not offered, a session ID that isn't the echo, compression.
    let e = hello_error(rfc_client(), &rec(&sh3(|m| m.cipher_suite = 0x13ff)));
    assert_eq!(e, ill(abi::SSL_R_UNKNOWN_CIPHER_RETURNED));
    let mut only = rfc_client();
    only.ciphers.truncate(1);
    let e = hello_error(only, &rec(&sh3(|m| m.cipher_suite = 0x1302)));
    assert_eq!(e, ill(abi::SSL_R_WRONG_CIPHER_RETURNED));
    let e = hello_error(rfc_client(), &rec(&sh3(|m| m.session_id = vec![1; 32])));
    assert_eq!(e, ill(abi::SSL_R_INVALID_SESSION_ID));
    let e = hello_error(rfc_client(), &rec(&sh3(|m| m.compression = 1)));
    assert_eq!(e, ill(abi::SSL_R_INVALID_COMPRESSION_ALGORITHM));
    // TLS 1.2 from a TLS 1.3-only client; a supported_versions other than TLS 1.3.
    let e = hello_error(
        rfc_client(),
        &rec(&sh3(|m| m.extensions = Some(Vec::new()))),
    );
    assert_eq!(
        e,
        Error::alert(
            abi::SSL_AD_PROTOCOL_VERSION,
            abi::SSL_R_UNSUPPORTED_PROTOCOL
        )
    );
    let e = hello_error(
        rfc_client(),
        &rec(&sh3(|m| {
            m.extensions = Some(ext_block(&[(0x002b, &[3, 3])]));
        })),
    );
    assert_eq!(e, ill(abi::SSL_R_BAD_PROTOCOL_VERSION_NUMBER));
    // A share for a group no share was sent for; no share at all.
    let p256 = [&[0x00, 0x17, 0x00, 0x41, 0x04][..], &[7; 64][..]].concat();
    let e = hello_error(
        rfc_client(),
        &rec(&sh3(|m| {
            m.extensions = Some(ext_block(&[(0x0033, &p256), (0x002b, &[3, 4])]));
        })),
    );
    assert_eq!(e, ill(abi::SSL_R_BAD_KEY_SHARE));
    let e = hello_error(
        rfc_client(),
        &rec(&sh3(|m| {
            m.extensions = Some(ext_block(&[(0x002b, &[3, 4])]));
        })),
    );
    assert_eq!(e, ill(abi::SSL_R_NO_SUITABLE_KEY_SHARE));
    // An extension the client didn't offer.
    let e = hello_error(
        rfc_client(),
        &rec(&sh3(|m| {
            let mut x = m.extensions.clone().unwrap();
            x.extend_from_slice(&ext_block(&[(0x0010, &[0, 3, 2, b'h', b'2'])]));
            m.extensions = Some(x);
        })),
    );
    assert_eq!(
        e,
        Error::alert(
            abi::SSL_AD_UNSUPPORTED_EXTENSION,
            abi::SSL_R_UNSOLICITED_EXTENSION
        )
    );
    // Not a ServerHello at all.
    let e = hello_error(rfc_client(), &rec(rfc("3", "Certificate", 0)));
    assert_eq!(
        e,
        Error::alert(
            abi::SSL3_AD_UNEXPECTED_MESSAGE,
            abi::SSL_R_UNEXPECTED_MESSAGE
        )
    );
}

#[test]
fn unacceptable_hello_retry_requests() {
    let hrr = rfc("5", "ServerHello", 0);
    let hrr_with = |exts: Vec<u8>| {
        let mut m = crate::msgs::hello::ServerHello::parse(&hrr[4..], true).unwrap();
        m.extensions = Some(exts);
        crate::msgs::frame(hm::SERVER_HELLO, &m.encode().unwrap()).unwrap()
    };
    // Asking for the group a share was sent for.
    let again = hrr_with(ext_block(&[(0x0033, &[0, 0x1d]), (0x002b, &[3, 4])]));
    let e = hello_error(rfc_client(), &record(22, &again));
    assert_eq!(e, ill(abi::SSL_R_BAD_KEY_SHARE));
    // Asking for nothing new.
    let nothing = hrr_with(ext_block(&[(0x002b, &[3, 4])]));
    let e = hello_error(rfc_client(), &record(22, &nothing));
    assert_eq!(e, ill(abi::SSL_R_NO_CHANGE_FOLLOWING_HRR));
    // Without supported_versions.
    let bare = hrr_with(ext_block(&[(0x0033, &[0, 0x17])]));
    let e = hello_error(rfc_client(), &record(22, &bare));
    assert_eq!(
        e,
        Error::alert(
            abi::TLS13_AD_MISSING_EXTENSION,
            abi::SSL_R_MISSING_SUPPORTED_VERSIONS_EXTENSION
        )
    );
    // A second HelloRetryRequest.
    let ok = hrr_with(ext_block(&[(0x0033, &[0, 0x17]), (0x002b, &[3, 4])]));
    let e = hello_error(rfc_client(), &[record(22, &ok), record(22, &ok)].concat());
    assert_eq!(
        e,
        Error::alert(
            abi::SSL_AD_UNEXPECTED_MESSAGE,
            abi::SSL_R_UNEXPECTED_MESSAGE
        )
    );
}

/// The error a section 3 client stops with when the server's encrypted flight is `msgs`,
/// with requests answered by `answer`.
fn flight_error(msgs: &[&[u8]], answer: &mut dyn FnMut(&Request) -> Answer) -> (Error, Connection) {
    let p = TestProvider::new(b"negative-flight");
    let ch = rfc("3", "ClientHello", 0);
    let sh = rfc("3", "ServerHello", 0);
    p.queue_random(&h(S3_CLIENT_RANDOM));
    p.queue_random(&h(S3_CLIENT_PRIVATE));
    let mut c = with_hellos(rfc_client(), &[ch]);
    let mut seen = Seen::default();
    drive(&mut c, &p, false, answer, &mut seen).unwrap();
    let shared = x25519(S3_CLIENT_PRIVATE, &server_share(sh));
    let mut server = Server3::new(&p, None, &shared, &[ch, sh]);
    let flight = server.flight(&p, msgs);
    c.feed(&record(22, sh));
    c.feed(&flight);
    let e = loop {
        match drive(&mut c, &p, false, answer, &mut seen) {
            Err(e) => break e,
            Ok(Event::NeedInput) => panic!("no error"),
            Ok(_) => {}
        }
    };
    (e, c)
}

#[test]
fn bad_server_flights() {
    let ee = rfc("3", "EncryptedExtensions", 0);
    let cert = rfc("3", "Certificate", 0);
    let cv = rfc("3", "CertificateVerify", 0);
    let fin = rfc("3", "Finished", 0);
    // A Finished that doesn't check out.
    let mut bad_fin = fin.to_vec();
    bad_fin[10] ^= 1;
    let (e, _) = flight_error(&[ee, cert, cv, &bad_fin], &mut accept);
    assert_eq!(
        e,
        Error::alert(abi::SSL_AD_DECRYPT_ERROR, abi::SSL_R_DIGEST_CHECK_FAILED)
    );
    // A CertificateVerify whose signature doesn't verify.
    let mut bad_cv = cv.to_vec();
    let last = bad_cv.len() - 1;
    bad_cv[last] ^= 1;
    let (e, _) = flight_error(&[ee, cert, &bad_cv, fin], &mut accept);
    assert_eq!(
        e,
        Error::alert(abi::SSL_AD_DECRYPT_ERROR, abi::SSL_R_BAD_SIGNATURE)
    );
    // A scheme the client didn't offer.
    let mut odd_cv = cv.to_vec();
    odd_cv[4..6].copy_from_slice(&[0x02, 0x01]);
    let (e, _) = flight_error(&[ee, cert, &odd_cv, fin], &mut accept);
    assert_eq!(e.reason, abi::SSL_R_WRONG_SIGNATURE_TYPE);
    // A chain that doesn't verify.
    let mut expired = |r: &Request| match r {
        Request::Verify { .. } => Answer::Verified {
            result: i64::from(abi::X509_V_ERR_CERT_HAS_EXPIRED),
            proceed: false,
            verified_chain: Vec::new(),
        },
        _ => Answer::Continue,
    };
    let (e, c) = flight_error(&[ee, cert, cv, fin], &mut expired);
    assert_eq!(
        e,
        Error::alert(
            abi::SSL_AD_CERTIFICATE_EXPIRED,
            abi::SSL_R_CERTIFICATE_VERIFY_FAILED
        )
    );
    assert_eq!(
        c.negotiated().verify_result,
        i64::from(abi::X509_V_ERR_CERT_HAS_EXPIRED)
    );
    // Malformed EncryptedExtensions; a Certificate that isn't one; messages out of order.
    let bad_ee = [8, 0, 0, 2, 0, 1];
    let (e, _) = flight_error(&[&bad_ee, cert, cv, fin], &mut accept);
    assert_eq!(e, Error::decode(abi::SSL_R_LENGTH_MISMATCH));
    let junk_cert = [11, 0, 0, 9, 0, 0, 0, 5, 0, 0, 2, 0x31, 0x00];
    let (e, _) = flight_error(&[ee, &junk_cert, cv, fin], &mut accept);
    assert_eq!(
        e,
        Error::alert_lib(abi::SSL_AD_BAD_CERTIFICATE, abi::ERR_R_ASN1_LIB)
    );
    let long_cert = [11, 0, 0, 9, 0, 0, 0, 5, 0, 0, 9, 0x30, 0x00];
    let (e, _) = flight_error(&[ee, &long_cert, cv, fin], &mut accept);
    assert_eq!(e, Error::decode(abi::SSL_R_CERT_LENGTH_MISMATCH));
    let (e, _) = flight_error(&[ee, cv, cert, fin], &mut accept);
    assert_eq!(e.reason, abi::SSL_R_UNEXPECTED_MESSAGE);
    let (e, _) = flight_error(&[ee, cert, fin], &mut accept);
    assert_eq!(e.reason, abi::SSL_R_UNEXPECTED_MESSAGE);
}

// TLS 1.2: a scripted server (its messages made here with the test provider), the client's
// messages checked against what the server computes.

use crate::crypto::{KeyId, KeyShare, Provider};
use crate::keysched::{KeyBlock, PrfHash};

/// A TLS 1.2 server, scripted.
struct Server12<'a> {
    p: &'a TestProvider,
    transcript: Vec<u8>,
    client_random: Vec<u8>,
    server_random: [u8; 32],
    key: KeyId,
    cert: Vec<u8>,
    share: Option<Box<dyn KeyShare>>,
    dh: Option<Box<dyn KeyShare>>,
    ms: Vec<u8>,
    ems: bool,
    /// AES-128-CBC with HMAC-SHA1 and encrypt-then-MAC instead of AES-128-GCM.
    cbc: bool,
    /// A plain PSK suite's key.
    psk: Option<Vec<u8>>,
}

impl<'a> Server12<'a> {
    fn new(p: &'a TestProvider, ch: &[u8]) -> Self {
        let k = crate::testprov::keys_rsa::rfc8448_server();
        let cert = k.public(p).unwrap().cert("server");
        Self {
            cert,
            p,
            transcript: ch.to_vec(),
            client_random: ch[6..38].to_vec(),
            server_random: [0x5a; 32],
            key: p.add_key(k),
            share: None,
            dh: None,
            ms: Vec::new(),
            ems: false,
            cbc: false,
            psk: None,
        }
    }

    /// Adds a message to the transcript and frames it into a record.
    fn msg(&mut self, typ: u8, body: &[u8]) -> Vec<u8> {
        let m = crate::msgs::frame(typ, body).unwrap();
        self.transcript.extend_from_slice(&m);
        record(22, &m)
    }

    fn hello(&mut self, suite: u16, session_id: &[u8], exts: &[(u16, &[u8])]) -> Vec<u8> {
        self.ems = exts.iter().any(|e| e.0 == 0x0017);
        let mut b = vec![3, 3];
        b.extend_from_slice(&self.server_random);
        b.push(u8::try_from(session_id.len()).unwrap());
        b.extend_from_slice(session_id);
        b.extend_from_slice(&suite.to_be_bytes());
        b.push(0);
        let block = ext_block(exts);
        b.extend_from_slice(&u16::try_from(block.len()).unwrap().to_be_bytes());
        b.extend_from_slice(&block);
        self.msg(hm::SERVER_HELLO, &b)
    }

    fn certificate(&mut self) -> Vec<u8> {
        let cert = self.cert.clone();
        let n = cert.len();
        let mut b = (u32::try_from(n + 3).unwrap().to_be_bytes()[1..]).to_vec();
        b.extend_from_slice(&u32::try_from(n).unwrap().to_be_bytes()[1..]);
        b.extend_from_slice(&cert);
        self.msg(hm::CERTIFICATE, &b)
    }

    /// A signed ServerKeyExchange over `params`.
    fn ske(&mut self, params: &[u8], scheme: u16) -> Vec<u8> {
        let tbs = [&self.client_random[..], &self.server_random, params].concat();
        let sig = self.p.sign(self.key, scheme, &tbs).unwrap();
        let mut b = params.to_vec();
        b.extend_from_slice(&scheme.to_be_bytes());
        b.extend_from_slice(&u16::try_from(sig.len()).unwrap().to_be_bytes());
        b.extend_from_slice(&sig);
        self.msg(hm::SERVER_KEY_EXCHANGE, &b)
    }

    fn ecdhe_params(&mut self, group: u16) -> Vec<u8> {
        let share = self.p.key_share(group).unwrap();
        let mut params = vec![3];
        params.extend_from_slice(&group.to_be_bytes());
        params.push(u8::try_from(share.public().len()).unwrap());
        params.extend_from_slice(share.public());
        self.share = Some(share);
        params
    }

    fn dhe_params(&mut self) -> Vec<u8> {
        use rustyssl_crypto::bn::Endian;
        let g = rustyssl_crypto::ffc::by_name("ffdhe2048").unwrap();
        let pb = g.p.to_bin(None, Endian::Big, false).unwrap().to_vec();
        let gb = g.g.to_bin(None, Endian::Big, false).unwrap().to_vec();
        let share = self.p.dh_share(&pb, &gb).unwrap();
        let mut params = Vec::new();
        for v in [&pb[..], &gb[..], share.public()] {
            params.extend_from_slice(&u16::try_from(v.len()).unwrap().to_be_bytes());
            params.extend_from_slice(v);
        }
        self.dh = Some(share);
        params
    }

    fn done(&mut self) -> Vec<u8> {
        self.msg(hm::SERVER_HELLO_DONE, &[])
    }

    /// Takes the client's ClientKeyExchange (with its key exchange) and makes the master
    /// secret.
    fn client_key_exchange(&mut self, cke: &[u8], rsa: bool) {
        let body = &cke[4..];
        let pms = if let Some(psk) = &self.psk {
            let n = u16::try_from(psk.len()).unwrap().to_be_bytes();
            [&n[..], &vec![0; psk.len()], &n, psk].concat()
        } else if rsa {
            let ct = &body[2..];
            self.p
                .rsa_decrypt_pms(self.key, ct, v::TLS1_2)
                .unwrap()
                .bytes()
                .to_vec()
        } else if let Some(dh) = self.dh.take() {
            let s = dh.derive(&body[2..]).unwrap();
            let lead = s.bytes().iter().take_while(|&&b| b == 0).count();
            s.bytes()[lead..].to_vec()
        } else {
            let share = self.share.take().unwrap();
            share.derive(&body[1..]).unwrap().bytes().to_vec()
        };
        self.transcript.extend_from_slice(cke);
        self.ms = if self.ems {
            let h = sha256(self.p, &self.transcript);
            keysched::extended_master_secret(self.p, PrfHash::Sha256, &pms, &h)
        } else {
            keysched::master_secret(
                self.p,
                PrfHash::Sha256,
                &pms,
                &self.client_random,
                &self.server_random,
            )
        }
        .unwrap()
        .bytes()
        .to_vec();
    }

    /// The Finished `client` (or the server) sends now.
    fn finished(&self, client: bool) -> Vec<u8> {
        let h = sha256(self.p, &self.transcript);
        let vd = keysched::verify_data_12(self.p, PrfHash::Sha256, &self.ms, client, &h).unwrap();
        crate::msgs::frame(hm::FINISHED, &vd).unwrap()
    }

    /// The server's ChangeCipherSpec and Finished, protected with AES-128-GCM.
    fn change_and_finish(&mut self) -> Vec<u8> {
        let fin = self.finished(false);
        self.transcript.extend_from_slice(&fin);
        let (mac, iv) = if self.cbc { (20, 16) } else { (0, 4) };
        let kb = KeyBlock::new(
            self.p,
            PrfHash::Sha256,
            &self.ms,
            &self.server_random,
            &self.client_random,
            mac,
            16,
            iv,
        )
        .unwrap();
        let mut w = RecordWriter::new(v::TLS1_2);
        let prot = if self.cbc {
            Protection::cbc12(
                self.p,
                crate::crypto::CipherAlg::Aes128Cbc,
                kb.server_key.bytes(),
                kb.server_iv.bytes(),
                HashAlg::Sha1,
                kb.server_mac.bytes(),
                v::TLS1_2,
                true,
                true,
            )
        } else {
            Protection::aead12(
                self.p,
                AeadAlg::Aes128Gcm,
                kb.server_key.bytes(),
                kb.server_iv.bytes(),
                0,
            )
        }
        .unwrap();
        w.set_protection(Mode::Tls12(v::TLS1_2), prot);
        let mut out = record(20, &[1]);
        w.write(self.p, 22, &fin, &mut out).unwrap();
        out
    }
}

/// A client offering TLS 1.2 and 1.3 with TLS 1.2 suites.
fn client12() -> Config {
    Config {
        ciphers: [0x1301, 0xc02f, 0x009e, 0x009c]
            .iter()
            .map(|&id| suites::by_protocol_id(id).unwrap())
            .collect(),
        hostname: Some(b"server".to_vec()),
        max_cert_list: 102_400,
        max_send_fragment: 16384,
        verify_mode: abi::SSL_VERIFY_PEER,
        now: 1_700_000_000,
        callbacks: crate::conn::Callbacks {
            msg: true,
            ..Default::default()
        },
        ..Config::default()
    }
}

/// A client's first flight, and the scripted server that got it.
fn hello12<'a>(p: &'a TestProvider, cfg: Config) -> (Connection, Seen, Server12<'a>) {
    let mut c = Connection::new(cfg);
    let mut seen = Seen::default();
    assert_eq!(
        drive(&mut c, p, false, &mut accept, &mut seen).unwrap(),
        Event::NeedInput
    );
    let ch = seen.written.remove(0);
    let server = Server12::new(p, &ch);
    (c, seen, server)
}

/// The extensions a TLS 1.2 server answers a fresh client with.
const RI: (u16, &[u8]) = (0xff01, &[0]);
const EMS: (u16, &[u8]) = (0x0017, &[]);

/// A full TLS 1.2 handshake with `suite`'s key exchange; returns the client after it.
fn full12(p: &TestProvider, cfg: Config, suite: u16, ticket: bool) -> (Connection, Seen) {
    let (mut c, mut seen, mut s) = hello12(p, cfg);
    let mut exts = vec![RI, EMS];
    if ticket {
        exts.push((0x0023, &[]));
    }
    let mut input = s.hello(suite, &[7; 32], &exts);
    input.extend(s.certificate());
    let rsa = suite == 0x009c;
    if suite == 0xc02f {
        let params = s.ecdhe_params(0x001d);
        input.extend(s.ske(&params, 0x0804));
    } else if suite == 0x009e {
        let params = s.dhe_params();
        input.extend(s.ske(&params, 0x0804));
    }
    input.extend(s.done());
    c.feed(&input);
    assert_eq!(
        drive(&mut c, p, false, &mut accept, &mut seen).unwrap(),
        Event::NeedInput
    );
    let [cke, fin] = &seen.written[..] else {
        panic!("{}", seen.written.len())
    };
    s.client_key_exchange(cke, rsa);
    assert_eq!(*fin, s.finished(true), "the client's Finished");
    s.transcript.extend_from_slice(fin);
    let mut tail = Vec::new();
    if ticket {
        let nst = crate::msgs::frame(
            hm::NEW_SESSION_TICKET,
            &[0, 0, 0x1c, 0x20, 0, 4, 1, 2, 3, 4],
        )
        .unwrap();
        s.transcript.extend_from_slice(&nst);
        tail.extend(record(22, &nst));
    }
    tail.extend(s.change_and_finish());
    c.feed(&tail);
    seen.written.clear();
    assert_eq!(
        drive(&mut c, p, false, &mut accept, &mut seen).unwrap(),
        Event::HandshakeDone
    );
    assert!(c.negotiated().ems);
    assert!(c.negotiated().secure_renegotiation);
    assert_eq!(c.negotiated().version, v::TLS1_2);
    (c, seen)
}

#[test]
fn tls12_ecdhe_rsa() {
    let p = TestProvider::new(b"tls12-ecdhe");
    let (c, seen) = full12(&p, client12(), 0xc02f, false);
    assert_eq!(c.negotiated().cipher.unwrap().protocol_id(), 0xc02f);
    assert_eq!(c.negotiated().group, Some(0x001d));
    assert_eq!(c.negotiated().peer_scheme, Some(0x0804));
    assert_eq!(c.negotiated().session.session_id, [7; 32]);
    assert!(seen.events.contains(&Event::UpdateCache { server: false }));
}

#[test]
fn tls12_rsa_and_dhe_key_exchange() {
    let p = TestProvider::new(b"tls12-rsa");
    let (c, _) = full12(&p, client12(), 0x009c, false);
    assert_eq!(c.negotiated().cipher.unwrap().protocol_id(), 0x009c);
    let p = TestProvider::new(b"tls12-dhe");
    let (c, _) = full12(&p, client12(), 0x009e, false);
    assert_eq!(c.negotiated().cipher.unwrap().protocol_id(), 0x009e);
}

#[test]
fn tls12_resumption_by_session_id_and_ticket() {
    let p = TestProvider::new(b"tls12-resume");
    let (c, _) = full12(&p, client12(), 0xc02f, true);
    let session = c.negotiated().session.clone();
    assert_eq!(session.ticket.as_deref(), Some(&[1, 2, 3, 4][..]));
    assert_eq!(session.ticket_lifetime_hint, 0x1c20);
    // The ticket's hash is the session's ID now.
    assert_eq!(session.session_id, sha256(&p, &[1, 2, 3, 4]));
    let mut cfg = client12();
    cfg.session = Some(session.clone());
    let (mut c2, mut seen, mut s) = hello12(&p, cfg);
    // The ClientHello offers the ticket and the session ID.
    let ch = s.transcript.clone();
    assert_eq!(ch[38], 32);
    assert_eq!(ch[39..71], session.session_id[..]);
    let body = &ch[4..];
    assert_eq!(hello_ext(body, 0x0023), Some(vec![1, 2, 3, 4]));
    // The server resumes: its ChangeCipherSpec and Finished come first.
    s.ms.clone_from(&session.master_key);
    let mut input = s.hello(0xc02f, &session.session_id, &[RI, EMS]);
    input.extend(s.change_and_finish());
    c2.feed(&input);
    assert_eq!(
        drive(&mut c2, &p, false, &mut accept, &mut seen).unwrap(),
        Event::HandshakeDone
    );
    assert!(c2.negotiated().reused);
    assert_eq!(seen.written, [s.finished(true)]);
}

#[test]
fn tls12_client_certificate() {
    let p = TestProvider::new(b"tls12-cert");
    let mut cfg = client12();
    cfg.certs = vec![client_cert(&p)];
    let (mut c, mut seen, mut s) = hello12(&p, cfg);
    let mut input = s.hello(0xc02f, &[7; 32], &[RI, EMS]);
    input.extend(s.certificate());
    let params = s.ecdhe_params(0x001d);
    input.extend(s.ske(&params, 0x0804));
    // CertificateRequest: ECDSA and RSA signing, ecdsa_secp256r1_sha256, no CA names.
    input.extend(s.msg(hm::CERTIFICATE_REQUEST, &[2, 1, 64, 0, 2, 4, 3, 0, 0]));
    input.extend(s.done());
    c.feed(&input);
    drive(&mut c, &p, false, &mut accept, &mut seen).unwrap();
    let [cert, cke, cv, fin] = &seen.written[..] else {
        panic!("{}", seen.written.len())
    };
    assert_eq!(cert[0], hm::CERTIFICATE);
    assert_eq!(cv[0], hm::CERTIFICATE_VERIFY);
    s.transcript.extend_from_slice(cert);
    s.client_key_exchange(cke, false);
    // The CertificateVerify signs the messages through the ClientKeyExchange.
    let sig = &cv[8..];
    let ok = p
        .verify(&c.config().certs[0].chain[0], 0x0403, &s.transcript, sig)
        .unwrap();
    assert!(ok);
    s.transcript.extend_from_slice(cv);
    assert_eq!(*fin, s.finished(true));
}

#[test]
fn tls12_renegotiation() {
    let p = TestProvider::new(b"tls12-reneg");
    let (mut c, mut seen) = full12(&p, client12(), 0xc02f, false);
    let client_fin = c.negotiated().client_finished.clone();
    assert_eq!(client_fin.len(), 12);
    // A HelloRequest under the connection's keys: the client renegotiates, binding the new
    // handshake to the old one's Finished.
    let ms = c.negotiated().master_secret.clone();
    let kb = KeyBlock::new(
        &p,
        PrfHash::Sha256,
        &ms,
        &c.handshake().server_random,
        &c.handshake().client_random,
        0,
        16,
        4,
    )
    .unwrap();
    let mut w = RecordWriter::new(v::TLS1_2);
    w.set_protection(
        Mode::Tls12(v::TLS1_2),
        Protection::aead12(
            &p,
            AeadAlg::Aes128Gcm,
            kb.server_key.bytes(),
            kb.server_iv.bytes(),
            1,
        )
        .unwrap(),
    );
    // The record sequence continues after the server's Finished.
    let mut skip = Vec::new();
    w.write(&p, 22, &[20, 0, 0, 0], &mut skip).unwrap();
    let mut hr = Vec::new();
    w.write(&p, 22, &[0, 0, 0, 0], &mut hr).unwrap();
    c.feed(&hr);
    seen.written.clear();
    loop {
        let e = drive(&mut c, &p, true, &mut accept, &mut seen).unwrap();
        if e == Event::NeedInput {
            break;
        }
    }
    let [ch] = &seen.written[..] else {
        panic!("{:?}", seen.written.len())
    };
    assert_eq!(ch[0], hm::CLIENT_HELLO);
    let ri = hello_ext(&ch[4..], 0xff01).unwrap();
    assert_eq!(ri, [&[12][..], &client_fin].concat());
}

#[test]
fn tls12_refuses_renegotiation_when_told_to() {
    let p = TestProvider::new(b"tls12-noreneg");
    let mut cfg = client12();
    cfg.options |= abi::SSL_OP_NO_RENEGOTIATION;
    let (mut c, mut seen) = full12(&p, cfg, 0xc02f, false);
    let ms = c.negotiated().master_secret.clone();
    let kb = KeyBlock::new(
        &p,
        PrfHash::Sha256,
        &ms,
        &c.handshake().server_random,
        &c.handshake().client_random,
        0,
        16,
        4,
    )
    .unwrap();
    let mut w = RecordWriter::new(v::TLS1_2);
    w.set_protection(
        Mode::Tls12(v::TLS1_2),
        Protection::aead12(
            &p,
            AeadAlg::Aes128Gcm,
            kb.server_key.bytes(),
            kb.server_iv.bytes(),
            1,
        )
        .unwrap(),
    );
    let mut skip = Vec::new();
    w.write(&p, 22, &[20, 0, 0, 0], &mut skip).unwrap();
    let mut hr = Vec::new();
    w.write(&p, 22, &[0, 0, 0, 0], &mut hr).unwrap();
    c.feed(&hr);
    loop {
        if drive(&mut c, &p, true, &mut accept, &mut seen).unwrap() == Event::NeedInput {
            break;
        }
    }
    // A no_renegotiation warning.
    assert_eq!(c.alerts().0, Some((1, 100)));
}

#[test]
fn tls12_bad_server_messages() {
    let fail = |f: &dyn Fn(&mut Server12<'_>) -> Vec<u8>, cfg: Config| -> Error {
        let p = TestProvider::new(b"tls12-bad");
        let (mut c, mut seen, mut s) = hello12(&p, cfg);
        c.feed(&f(&mut s));
        loop {
            match drive(&mut c, &p, false, &mut accept, &mut seen) {
                Err(e) => return e,
                Ok(Event::NeedInput) => panic!("no error"),
                Ok(_) => {}
            }
        }
    };
    // No renegotiation_info.
    let e = fail(&|s| s.hello(0xc02f, &[], &[EMS]), client12());
    assert_eq!(
        e,
        Error::alert(
            abi::SSL_AD_HANDSHAKE_FAILURE,
            abi::SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED
        )
    );
    // A TLS 1.3 server's downgrade sentinel.
    let e = fail(
        &|s| {
            s.server_random[24..].copy_from_slice(&crate::consts::TLS12_DOWNGRADE);
            s.hello(0xc02f, &[], &[RI, EMS])
        },
        client12(),
    );
    assert_eq!(
        e,
        Error::alert(
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_R_INAPPROPRIATE_FALLBACK
        )
    );
    // A curve the client didn't offer, and a signature that doesn't verify.
    let e = fail(
        &|s| {
            let mut m = s.hello(0xc02f, &[], &[RI, EMS]);
            m.extend(s.certificate());
            let mut params = s.ecdhe_params(0x001d);
            params[1..3].copy_from_slice(&0x0019u16.to_be_bytes());
            m.extend(s.ske(&params, 0x0804));
            m
        },
        Config {
            groups: vec![0x001d, 0x0017],
            ..client12()
        },
    );
    assert_eq!(e, ill(abi::SSL_R_WRONG_CURVE));
    let e = fail(
        &|s| {
            let mut m = s.hello(0xc02f, &[], &[RI, EMS]);
            m.extend(s.certificate());
            let params = s.ecdhe_params(0x001d);
            let mut ske = s.ske(&params, 0x0804);
            let last = ske.len() - 1;
            ske[last] ^= 1;
            m.extend(ske);
            m
        },
        client12(),
    );
    assert_eq!(
        e,
        Error::alert(abi::SSL_AD_DECRYPT_ERROR, abi::SSL_R_BAD_SIGNATURE)
    );
    // A ServerHelloDone straight after the Certificate of an ECDHE suite.
    let e = fail(
        &|s| {
            let mut m = s.hello(0xc02f, &[], &[RI, EMS]);
            m.extend(s.certificate());
            m.extend(s.done());
            m
        },
        client12(),
    );
    assert_eq!(e.reason, abi::SSL_R_UNEXPECTED_MESSAGE);
    // A suite the session had to resume with, and didn't.
    let e = fail(&|s| s.hello(0x1399, &[], &[RI, EMS]), client12());
    assert_eq!(e, ill(abi::SSL_R_UNKNOWN_CIPHER_RETURNED));
}

#[test]
fn tls12_ocsp_stapling() {
    let p = TestProvider::new(b"tls12-ocsp");
    let mut cfg = client12();
    cfg.status_request = true;
    cfg.callbacks.status = true;
    let (mut c, mut seen, mut s) = hello12(&p, cfg);
    assert_eq!(
        hello_ext(&s.transcript[4..], 0x0005),
        Some(vec![1, 0, 0, 0, 0])
    );
    let mut input = s.hello(0xc02f, &[7; 32], &[RI, EMS, (0x0005, &[])]);
    input.extend(s.certificate());
    input.extend(s.msg(hm::CERTIFICATE_STATUS, &[1, 0, 0, 3, 0x30, 1, 0]));
    let params = s.ecdhe_params(0x001d);
    input.extend(s.ske(&params, 0x0804));
    input.extend(s.done());
    c.feed(&input);
    let mut reject = |r: &Request| match r {
        Request::Status { .. } => Answer::Status {
            ret: 0,
            response: None,
        },
        _ => accept(r),
    };
    let e = loop {
        match drive(&mut c, &p, false, &mut reject, &mut seen) {
            Err(e) => break e,
            Ok(Event::NeedInput) => panic!("no error"),
            Ok(_) => {}
        }
    };
    assert_eq!(c.negotiated().ocsp_response, Some(vec![0x30, 1, 0]));
    assert!(
        seen.requests
            .iter()
            .any(|r| matches!(r, Request::Status { .. }))
    );
    assert_eq!(
        e,
        Error::alert(
            abi::SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE,
            abi::SSL_R_INVALID_STATUS_RESPONSE
        )
    );
}

impl Server3 {
    /// A flight of the server's own after the RFC's ServerHello: EncryptedExtensions with
    /// `exts`, then (with `cert`) its certificate and signature, then its Finished.
    fn own_flight(
        &mut self,
        p: &TestProvider,
        exts: &[(u16, &[u8])],
        cert: Option<(KeyId, &[u8])>,
    ) -> Vec<u8> {
        let block = ext_block(exts);
        let ee = crate::msgs::frame(
            hm::ENCRYPTED_EXTENSIONS,
            &[
                &u16::try_from(block.len()).unwrap().to_be_bytes()[..],
                &block,
            ]
            .concat(),
        )
        .unwrap();
        let mut msgs = vec![ee];
        self.transcript.extend_from_slice(&msgs[0]);
        if let Some((key, der)) = cert {
            let n = der.len();
            let body = [
                &[0u8][..],
                &u32::try_from(n + 5).unwrap().to_be_bytes()[1..],
                &u32::try_from(n).unwrap().to_be_bytes()[1..],
                der,
                &[0, 0],
            ]
            .concat();
            let m = crate::msgs::frame(hm::CERTIFICATE, &body).unwrap();
            self.transcript.extend_from_slice(&m);
            msgs.push(m);
            let tbs = [
                &[0x20u8; 64][..],
                b"TLS 1.3, server CertificateVerify\0",
                &sha256(p, &self.transcript),
            ]
            .concat();
            let sig = p.sign(key, 0x0804, &tbs).unwrap();
            let body = [
                &[0x08u8, 0x04][..],
                &u16::try_from(sig.len()).unwrap().to_be_bytes(),
                &sig,
            ]
            .concat();
            let m = crate::msgs::frame(hm::CERTIFICATE_VERIFY, &body).unwrap();
            self.transcript.extend_from_slice(&m);
            msgs.push(m);
        }
        let base = self
            .sched
            .server_handshake_traffic(p, &self.hs_hash)
            .unwrap();
        let th = sha256(p, &self.transcript);
        let vd = keysched::verify_data_13(p, HashAlg::Sha256, base.bytes(), &th).unwrap();
        let fin = crate::msgs::frame(hm::FINISHED, &vd).unwrap();
        self.transcript.extend_from_slice(&fin);
        msgs.push(fin);
        let mut w = writer13(p, base.bytes());
        let refs: Vec<&[u8]> = msgs.iter().map(Vec::as_slice).collect();
        seal(p, &mut w, &refs)
    }
}

/// An RSA server certificate and its key, registered with `p`.
fn server_cert(p: &TestProvider) -> (KeyId, Vec<u8>) {
    let k = crate::testprov::keys_rsa::rfc8448_server();
    let cert = k.public(p).unwrap().cert("server");
    (p.add_key(k), cert)
}

/// A section 3 client (with `cfg`, after its ClientHello) given the server's own flight with
/// `exts` in its EncryptedExtensions: the outcome, with the connection.
fn custom13(
    cfg: Config,
    exts: &[(u16, &[u8])],
    answer: &mut dyn FnMut(&Request) -> Answer,
) -> (Result<Event, Error>, Connection, Seen) {
    let p = TestProvider::new(b"custom13");
    let (key, cert) = server_cert(&p);
    let ch = rfc("3", "ClientHello", 0);
    let sh = rfc("3", "ServerHello", 0);
    p.queue_random(&h(S3_CLIENT_RANDOM));
    p.queue_random(&h(S3_CLIENT_PRIVATE));
    let mut c = with_hellos(cfg, &[ch]);
    let mut seen = Seen::default();
    drive(&mut c, &p, false, answer, &mut seen).unwrap();
    let shared = x25519(S3_CLIENT_PRIVATE, &server_share(sh));
    let mut server = Server3::new(&p, None, &shared, &[ch, sh]);
    let flight = server.own_flight(&p, exts, Some((key, &cert)));
    c.feed(&record(22, sh));
    c.feed(&flight);
    seen.written.clear();
    let r = loop {
        match drive(&mut c, &p, false, answer, &mut seen) {
            Ok(Event::NeedInput) => break Ok(Event::NeedInput),
            Ok(Event::HandshakeDone) => break Ok(Event::HandshakeDone),
            Ok(_) => {}
            Err(e) => break Err(e),
        }
    };
    (r, c, seen)
}

#[test]
fn encrypted_extensions() {
    // ALPN: one offered is selected; the session records it.
    let mut cfg = rfc_client();
    cfg.alpn = b"\x02h2\x08http/1.1".to_vec();
    let alpn: &[u8] = &[0, 9, 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'];
    let (r, c, _) = custom13(cfg.clone(), &[(0x0010, alpn)], &mut accept);
    assert_eq!(r.unwrap(), Event::HandshakeDone);
    assert_eq!(c.negotiated().alpn.as_deref(), Some(&b"http/1.1"[..]));
    assert_eq!(c.negotiated().session.alpn, c.negotiated().alpn);
    // One that wasn't offered.
    let (r, _, _) = custom13(cfg, &[(0x0010, &[0, 3, 2, b'h', b'3'])], &mut accept);
    assert_eq!(r.unwrap_err(), Error::decode(abi::SSL_R_BAD_EXTENSION));
    // The server_name acknowledgement records the name in the session.
    let (r, c, _) = custom13(rfc_client(), &[(0x0000, &[])], &mut accept);
    assert_eq!(r.unwrap(), Event::HandshakeDone);
    assert_eq!(
        c.negotiated().session.hostname.as_deref(),
        Some(&b"server"[..])
    );
    // A non-empty one is malformed.
    let (r, _, _) = custom13(rfc_client(), &[(0x0000, &[0])], &mut accept);
    assert_eq!(r.unwrap_err(), Error::decode(abi::SSL_R_BAD_EXTENSION));
    // max_fragment_length: the mode asked for becomes binding; another one is refused.
    let mut cfg = rfc_client();
    cfg.max_fragment_len_mode = 2;
    let (r, c, _) = custom13(cfg.clone(), &[(0x0001, &[2])], &mut accept);
    assert_eq!(r.unwrap(), Event::HandshakeDone);
    assert_eq!(c.negotiated().session.max_fragment_len_mode, 2);
    let (r, _, _) = custom13(cfg, &[(0x0001, &[3])], &mut accept);
    assert_eq!(
        r.unwrap_err(),
        ill(abi::SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH)
    );
    // Early data accepted without any being offered.
    let (r, _, _) = custom13(rfc_client(), &[(0x002a, &[])], &mut accept);
    assert_eq!(
        r.unwrap_err(),
        Error::alert(
            abi::SSL_AD_UNSUPPORTED_EXTENSION,
            abi::SSL_R_UNSOLICITED_EXTENSION
        )
    );
    // An extension that doesn't belong in EncryptedExtensions.
    let (r, _, _) = custom13(rfc_client(), &[(0x002b, &[3, 4])], &mut accept);
    assert_eq!(r.unwrap_err().reason, abi::SSL_R_BAD_EXTENSION);
}

#[test]
fn ocsp_and_scts_in_tls13() {
    let p = TestProvider::new(b"status13");
    let (key, cert) = server_cert(&p);
    let mut cfg = rfc_client();
    cfg.status_request = true;
    cfg.callbacks.status = true;
    let ch = rfc("3", "ClientHello", 0);
    let sh = rfc("3", "ServerHello", 0);
    p.queue_random(&h(S3_CLIENT_RANDOM));
    p.queue_random(&h(S3_CLIENT_PRIVATE));
    let mut c = with_hellos(cfg, &[ch]);
    let mut seen = Seen::default();
    drive(&mut c, &p, false, &mut accept, &mut seen).unwrap();
    // The ClientHello the client made asked for OCSP.
    let made = super::state_ref(&c).unwrap().made[0].clone();
    assert_eq!(hello_ext(&made, 0x0005), Some(vec![1, 0, 0, 0, 0]));
    let shared = x25519(S3_CLIENT_PRIVATE, &server_share(sh));
    let mut server = Server3::new(&p, None, &shared, &[ch, sh]);
    // The leaf's status_request entry extension staples a response.
    let n = cert.len();
    let status = [1u8, 0, 0, 2, 0x30, 0];
    let ext = ext_block(&[(0x0005, &status)]);
    let body = [
        &[0u8][..],
        &u32::try_from(n + 5 + ext.len()).unwrap().to_be_bytes()[1..],
        &u32::try_from(n).unwrap().to_be_bytes()[1..],
        &cert,
        &u16::try_from(ext.len()).unwrap().to_be_bytes(),
        &ext,
    ]
    .concat();
    let ee = crate::msgs::frame(hm::ENCRYPTED_EXTENSIONS, &[0, 0]).unwrap();
    let cm = crate::msgs::frame(hm::CERTIFICATE, &body).unwrap();
    server.transcript.extend_from_slice(&ee);
    server.transcript.extend_from_slice(&cm);
    let tbs = [
        &[0x20u8; 64][..],
        b"TLS 1.3, server CertificateVerify\0",
        &sha256(&p, &server.transcript),
    ]
    .concat();
    let sig = p.sign(key, 0x0804, &tbs).unwrap();
    let cv = crate::msgs::frame(
        hm::CERTIFICATE_VERIFY,
        &[
            &[8u8, 4][..],
            &u16::try_from(sig.len()).unwrap().to_be_bytes(),
            &sig,
        ]
        .concat(),
    )
    .unwrap();
    server.transcript.extend_from_slice(&cv);
    let base = server
        .sched
        .server_handshake_traffic(&p, &server.hs_hash)
        .unwrap();
    let vd = keysched::verify_data_13(
        &p,
        HashAlg::Sha256,
        base.bytes(),
        &sha256(&p, &server.transcript),
    )
    .unwrap();
    let fin = crate::msgs::frame(hm::FINISHED, &vd).unwrap();
    let mut w = writer13(&p, base.bytes());
    let flight = seal(&p, &mut w, &[&ee, &cm, &cv, &fin]);
    c.feed(&record(22, sh));
    c.feed(&flight);
    // The status callback is asked before the Finished is processed, and accepts.
    let mut ok = |r: &Request| match r {
        Request::Status { .. } => Answer::Status {
            ret: 1,
            response: None,
        },
        _ => accept(r),
    };
    assert_eq!(
        drive(&mut c, &p, false, &mut ok, &mut seen).unwrap(),
        Event::HandshakeDone
    );
    assert!(
        seen.requests
            .iter()
            .any(|r| matches!(r, Request::Status { .. }))
    );
    assert_eq!(c.negotiated().ocsp_response, Some(vec![0x30, 0]));
}

#[test]
fn tls13_external_psk() {
    let p = TestProvider::new(b"psk13");
    let mut cfg = rfc_client();
    cfg.callbacks.psk_session = true;
    let psk = vec![0x11; 32];
    let mut c = Connection::new(cfg);
    let mut seen = Seen::default();
    let ext = crate::conn::ExternalPsk {
        identity: b"id".to_vec(),
        key: psk.clone(),
        cipher_id: suites::by_protocol_id(0x1301).unwrap().id,
    };
    let mut give = |r: &Request| match r {
        Request::PskSession { .. } => Answer::Psk(Some(ext.clone())),
        _ => accept(r),
    };
    drive(&mut c, &p, false, &mut give, &mut seen).unwrap();
    let ch = seen.written.remove(0);
    // The identity, its zero age, and a binder over the ClientHello up to the binders.
    let offer =
        crate::msgs::ext::psk::Strict::parse(&hello_ext(&ch[4..], 0x0029).unwrap()).unwrap();
    assert_eq!(offer.identities[0].identity, b"id");
    assert_eq!(offer.identities[0].obfuscated_ticket_age, 0);
    let cut = ch.len() - offer.binders_len();
    let sched = Schedule13::new(&p, HashAlg::Sha256, Some(&psk)).unwrap();
    let th = sha256(&p, &ch[..cut]);
    assert_eq!(offer.binders[0], sched.binder(&p, false, &th).unwrap());
    // The server accepts it with a new key exchange.
    let share = server_share_for(&ch, 0x001d).unwrap();
    use crate::crypto::Provider as _;
    let (spub, shared) = p.respond(0x001d, &share).unwrap();
    let ks = [
        &[0u8, 0x1d][..],
        &u16::try_from(spub.len()).unwrap().to_be_bytes(),
        &spub,
    ]
    .concat();
    let shb = {
        let mut b = vec![3, 3];
        b.extend_from_slice(&[0x33; 32]);
        b.push(0);
        b.extend_from_slice(&[0x13, 0x01, 0]);
        let block = ext_block(&[(0x0029, &[0, 0]), (0x0033, &ks), (0x002b, &[3, 4])]);
        b.extend_from_slice(&u16::try_from(block.len()).unwrap().to_be_bytes());
        b.extend_from_slice(&block);
        crate::msgs::frame(hm::SERVER_HELLO, &b).unwrap()
    };
    let mut server = Server3::new(&p, Some(&psk), shared.bytes(), &[&ch, &shb]);
    let flight = server.own_flight(&p, &[], None);
    c.feed(&record(22, &shb));
    c.feed(&flight);
    assert_eq!(
        drive(&mut c, &p, false, &mut give, &mut seen).unwrap(),
        Event::HandshakeDone
    );
    assert!(c.negotiated().reused);
    assert!(c.negotiated().peer_chain.is_empty());
    let fin = seen.written.last().unwrap().clone();
    assert_eq!(fin, server.client_finished(&p, &[]));
}

/// The client's key share for `group` in a ClientHello message.
fn server_share_for(ch: &[u8], group: u16) -> Option<Vec<u8>> {
    let ks = hello_ext(&ch[4..], 0x0033)?;
    crate::msgs::ext::key_share::parse_client(&ks)
        .ok()?
        .into_iter()
        .find(|e| e.group == group)
        .map(|e| e.key)
}

/// A server configuration with an RSA certificate.
fn server_config(p: &TestProvider) -> Config {
    let (key, cert) = server_cert(p);
    Config {
        server: true,
        ciphers: client12().ciphers,
        certs: vec![crate::conn::CertKey {
            chain: vec![cert],
            key,
            slot: crate::conn::common::sigalgs::PKEY_RSA,
            schemes: vec![0x0804, 0x0401],
            auth: crate::suites::masks::SSL_aRSA,
            ec_group: None,
            curve_nid: abi::NID_undef,
            can_sign: true,
            cert_sig: None,
            raw_public_key: None,
            ocsp_response: None,
            chain_security: None,
            unsupported_digests: Vec::new(),
            strict: None,
        }],
        max_cert_list: 102_400,
        max_send_fragment: 16384,
        num_tickets: 2,
        now: 1_700_000_000,
        ticket_keys: Some(crate::conn::TicketKeys {
            name: [7; 16],
            hmac_key: crate::crypto::Secret::new(vec![8; 32]),
            aes_key: crate::crypto::Secret::new(vec![9; 32]),
        }),
        ..Config::default()
    }
}

#[test]
fn loopback_with_the_server() {
    use crate::conn::pair::{self, End};
    for (max, suite) in [(v::TLS1_3, 0x1301), (v::TLS1_2, 0xc02f)] {
        let p = TestProvider::new(b"loopback");
        let mut ccfg = client12();
        ccfg.max_version = max;
        ccfg.callbacks.info = true;
        ccfg.callbacks.msg = true;
        let mut scfg = server_config(&p);
        scfg.callbacks.info = true;
        scfg.callbacks.msg = true;
        let mut client = Connection::new(ccfg);
        let mut server = Connection::new(scfg);
        let mut log = pair::Log::default();
        let mut answer = |_: End, r: &Request| accept(r);
        let r = pair::handshake(&p, &mut client, &mut server, true, &mut answer, &mut log);
        assert!(
            r.is_ok(),
            "{r:?}: server state {}, client state {}\nserver: {:?}\nclient: {:?}",
            server.state(),
            client.state(),
            log.server,
            log.client
        );
        assert_eq!(client.negotiated().version, max);
        assert_eq!(client.negotiated().cipher.unwrap().protocol_id(), suite);
        assert_eq!(
            client.negotiated().client_finished,
            server.negotiated().client_finished
        );
    }
}

#[test]
fn tls13_post_handshake_fragment_then_app_data_fails() {
    // Part of a KeyUpdate (its type octet) and then application data: TLS 1.3 doesn't
    // interleave them (`ssl3_read_bytes`; tlsfuzzer's "1/4 fragmented keyupdate msg, appdata
    // between").
    use crate::conn::pair::{self, End};
    let p = TestProvider::new(b"mixed");
    let mut ccfg = client12();
    ccfg.max_version = v::TLS1_3;
    let mut client = Connection::new(ccfg);
    let mut server = Connection::new(server_config(&p));
    let mut log = pair::Log::default();
    let mut answer = |_: End, r: &Request| accept(r);
    pair::handshake(&p, &mut client, &mut server, true, &mut answer, &mut log).unwrap();
    client
        .write_record(
            &p,
            crate::record::content_type::handshake(),
            &[hm::KEY_UPDATE],
        )
        .unwrap();
    client.write_app(&p, b"between").unwrap();
    server.feed(&client.take_output());
    // One record per step: the fragment, then the application data.
    let e = (0..8)
        .find_map(|_| server.step(&p, true).err())
        .expect("the server took the records");
    assert_eq!(e.alert.map(i32::from), Some(abi::SSL_AD_UNEXPECTED_MESSAGE));
    assert_eq!(e.reason, abi::SSL_R_MIXED_HANDSHAKE_AND_NON_HANDSHAKE_DATA);
}

#[test]
fn tls12_cbc_with_encrypt_then_mac() {
    let p = TestProvider::new(b"tls12-etm");
    let mut cfg = client12();
    cfg.max_version = v::TLS1_2;
    cfg.ciphers = vec![suites::by_protocol_id(0xc013).unwrap()];
    let (mut c, mut seen, mut s) = hello12(&p, cfg);
    assert_eq!(hello_ext(&s.transcript[4..], 0x0016), Some(Vec::new()));
    s.cbc = true;
    let mut input = s.hello(0xc013, &[7; 32], &[RI, EMS, (0x0016, &[])]);
    input.extend(s.certificate());
    let params = s.ecdhe_params(0x001d);
    input.extend(s.ske(&params, 0x0804));
    input.extend(s.done());
    c.feed(&input);
    drive(&mut c, &p, false, &mut accept, &mut seen).unwrap();
    let [cke, fin] = &seen.written[..] else {
        panic!("{}", seen.written.len())
    };
    s.client_key_exchange(cke, false);
    assert_eq!(*fin, s.finished(true));
    s.transcript.extend_from_slice(fin);
    c.feed(&s.change_and_finish());
    assert_eq!(
        drive(&mut c, &p, false, &mut accept, &mut seen).unwrap(),
        Event::HandshakeDone
    );
    assert!(c.negotiated().etm);
}

#[test]
fn tls12_psk() {
    let p = TestProvider::new(b"tls12-psk");
    let mut cfg = client12();
    cfg.max_version = v::TLS1_2;
    cfg.ciphers = vec![suites::by_protocol_id(0x00a8).unwrap()];
    cfg.callbacks.psk = true;
    let (mut c, mut seen, mut s) = hello12(&p, cfg);
    let key = vec![0x42; 16];
    s.psk = Some(key.clone());
    let mut input = s.hello(0x00a8, &[7; 32], &[RI, EMS]);
    input.extend(s.msg(hm::SERVER_KEY_EXCHANGE, &[0, 4, b'h', b'i', b'n', b't']));
    input.extend(s.done());
    c.feed(&input);
    let mut give = |r: &Request| match r {
        Request::Psk { hint_or_identity } => {
            assert_eq!(hint_or_identity, b"hint");
            Answer::Psk(Some(crate::conn::ExternalPsk {
                identity: b"me".to_vec(),
                key: key.clone(),
                cipher_id: 0,
            }))
        }
        _ => accept(r),
    };
    drive(&mut c, &p, false, &mut give, &mut seen).unwrap();
    let [cke, fin] = &seen.written[..] else {
        panic!("{}", seen.written.len())
    };
    assert_eq!(cke[4..], [0, 2, b'm', b'e']);
    s.client_key_exchange(cke, false);
    assert_eq!(*fin, s.finished(true));
    s.transcript.extend_from_slice(fin);
    c.feed(&s.change_and_finish());
    assert_eq!(
        drive(&mut c, &p, false, &mut give, &mut seen).unwrap(),
        Event::HandshakeDone
    );
    // Without an answer from the callback there is no identity to send.
    let mut cfg = client12();
    cfg.max_version = v::TLS1_2;
    cfg.ciphers = vec![suites::by_protocol_id(0x00a8).unwrap()];
    cfg.callbacks.psk = true;
    let (mut c, mut seen, mut s) = hello12(&p, cfg);
    let mut input = s.hello(0x00a8, &[7; 32], &[RI, EMS]);
    input.extend(s.done());
    c.feed(&input);
    let mut none = |r: &Request| match r {
        Request::Psk { .. } => Answer::Psk(None),
        _ => accept(r),
    };
    let e = loop {
        match drive(&mut c, &p, false, &mut none, &mut seen) {
            Err(e) => break e,
            Ok(Event::NeedInput) => panic!("no error"),
            Ok(_) => {}
        }
    };
    assert_eq!(
        e,
        Error::alert(
            abi::SSL_AD_HANDSHAKE_FAILURE,
            abi::SSL_R_PSK_IDENTITY_NOT_FOUND
        )
    );
}

#[test]
fn tls12_next_protocol_negotiation() {
    let p = TestProvider::new(b"tls12-npn");
    let mut cfg = client12();
    cfg.callbacks.npn = true;
    let (mut c, mut seen, mut s) = hello12(&p, cfg);
    assert_eq!(hello_ext(&s.transcript[4..], 0x3374), Some(Vec::new()));
    let mut input = s.hello(
        0xc02f,
        &[7; 32],
        &[RI, EMS, (0x3374, b"\x02h2\x08http/1.1")],
    );
    input.extend(s.certificate());
    let params = s.ecdhe_params(0x001d);
    input.extend(s.ske(&params, 0x0804));
    input.extend(s.done());
    c.feed(&input);
    let mut pick = |r: &Request| match r {
        Request::Npn { protos } => {
            assert_eq!(protos, b"\x02h2\x08http/1.1");
            Answer::Npn(Some(b"h2".to_vec()))
        }
        _ => accept(r),
    };
    drive(&mut c, &p, false, &mut pick, &mut seen).unwrap();
    let [cke, np, fin] = &seen.written[..] else {
        panic!("{}", seen.written.len())
    };
    // The protocol, then padding to make the two vectors' contents and lengths a multiple of
    // 32 octets (`32 - (len + 2) % 32`).
    assert_eq!(np[..8], [hm::NEXT_PROTO, 0, 0, 32, 2, b'h', b'2', 28]);
    s.client_key_exchange(cke, false);
    s.transcript.extend_from_slice(np);
    assert_eq!(*fin, s.finished(true));
    assert_eq!(c.negotiated().npn.as_deref(), Some(&b"h2"[..]));
}

#[test]
fn tls12_certificate_transparency() {
    for (verify, fails) in [(abi::SSL_VERIFY_PEER, true), (abi::SSL_VERIFY_NONE, false)] {
        let p = TestProvider::new(b"tls12-ct");
        let mut cfg = client12();
        cfg.request_scts = true;
        cfg.verify_mode = verify;
        let (mut c, mut seen, mut s) = hello12(&p, cfg);
        assert_eq!(hello_ext(&s.transcript[4..], 0x0012), Some(Vec::new()));
        let mut input = s.hello(0xc02f, &[7; 32], &[RI, EMS, (0x0012, &[0, 2, 0, 0])]);
        input.extend(s.certificate());
        let params = s.ecdhe_params(0x001d);
        input.extend(s.ske(&params, 0x0804));
        input.extend(s.done());
        c.feed(&input);
        let mut refuse = |r: &Request| match r {
            Request::CtValidate => Answer::Fail {
                alert: Some(40),
                reason: abi::SSL_R_CALLBACK_FAILED,
            },
            _ => accept(r),
        };
        let r = drive(&mut c, &p, false, &mut refuse, &mut seen);
        assert!(seen.requests.contains(&Request::CtValidate));
        assert_eq!(c.negotiated().scts, Some(vec![0, 2, 0, 0]));
        if fails {
            assert_eq!(
                r.unwrap_err(),
                Error::alert(abi::SSL_AD_HANDSHAKE_FAILURE, abi::SSL_R_CALLBACK_FAILED)
            );
        } else {
            assert_eq!(r.unwrap(), Event::NeedInput);
            assert_eq!(seen.written.len(), 2);
        }
    }
}

#[test]
fn client_hello_padding() {
    let p = TestProvider::new(b"padding");
    let mut cfg = rfc_client();
    cfg.key_share_groups = vec![0x001d, 0x0017];
    cfg.options |= abi::SSL_OP_TLSEXT_PADDING;
    let mut c = Connection::new(cfg.clone());
    let mut seen = Seen::default();
    drive(&mut c, &p, false, &mut accept, &mut seen).unwrap();
    let ch = &seen.written[0];
    // Between 256 and 511 octets without it, so padded to 512 (the padding extension last).
    assert_eq!(ch.len(), 512);
    let pad = hello_ext(&ch[4..], 0x0015).unwrap();
    assert!(pad.iter().all(|&b| b == 0));
    let mut plain = cfg;
    plain.options &= !abi::SSL_OP_TLSEXT_PADDING;
    let mut c = Connection::new(plain);
    let mut seen2 = Seen::default();
    drive(&mut c, &p, false, &mut accept, &mut seen2).unwrap();
    assert_eq!(seen2.written[0].len(), 512 - 4 - pad.len());
}

#[test]
fn a_hello_waiting_for_an_answer_is_made_once() {
    let p = TestProvider::new(b"rerun");
    let mut cfg = rfc_client();
    cfg.callbacks.psk_session = true;
    let mut c = Connection::new(cfg);
    let mut written = Vec::new();
    // The PSK session callback suspends twice before answering.
    let mut asked = 0;
    loop {
        match c.step(&p, false).unwrap() {
            Event::Request(Request::PskSession { .. }) => {
                asked += 1;
                if asked == 3 {
                    c.answer(Answer::Session(None));
                }
            }
            Event::Message {
                write: true,
                content_type: 22,
                bytes,
                ..
            } => written.push(bytes),
            Event::NeedInput => break,
            Event::Output => {
                c.take_output();
            }
            _ => {}
        }
    }
    assert_eq!(asked, 3);
    let [ch] = &written[..] else { panic!() };
    // One key share, made once: the one the state holds.
    let st = super::state_ref(&c).unwrap();
    assert_eq!(st.ks.len(), 1);
    assert_eq!(
        server_share_for(ch, 0x001d),
        Some(st.ks[0].1.public().to_vec())
    );
}

#[test]
fn tls12_resumption_must_agree() {
    let p = TestProvider::new(b"tls12-agree");
    let (c, _) = full12(&p, client12(), 0xc02f, false);
    let session = c.negotiated().session.clone();
    let resume = |f: &dyn Fn(&mut Server12<'_>, &Session) -> Vec<u8>| -> Error {
        let mut cfg = client12();
        cfg.session = Some(session.clone());
        let (mut c, mut seen, mut s) = hello12(&p, cfg);
        c.feed(&f(&mut s, &session));
        loop {
            match drive(&mut c, &p, false, &mut accept, &mut seen) {
                Err(e) => return e,
                Ok(Event::NeedInput) => panic!("no error"),
                Ok(_) => {}
            }
        }
    };
    // Another suite for the session.
    let e = resume(&|s, sess| s.hello(0x009c, &sess.session_id, &[RI, EMS]));
    assert_eq!(e, ill(abi::SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED));
    // The session used the Extended Master Secret; the resumption doesn't.
    let e = resume(&|s, sess| s.hello(0xc02f, &sess.session_id, &[RI]));
    assert_eq!(
        e,
        Error::alert(abi::SSL_AD_HANDSHAKE_FAILURE, abi::SSL_R_INCONSISTENT_EXTMS)
    );
}

/// SRP's numbers for the loopback test: the requests carry them between the ends and the
/// application's side (the math is libcrypto's, so made-up values stand in).
fn srp_answer(end: crate::conn::pair::End, r: &Request, b: &[u8]) -> Answer {
    use crate::conn::SrpParams;
    use crate::conn::pair::End;
    let params = SrpParams {
        n: vec![0xff; 64],
        g: vec![2],
        s: vec![1, 2, 3],
        b: b.to_vec(),
    };
    match (end, r) {
        (End::Server, Request::SrpUsername { login }) => {
            assert_eq!(login, b"user");
            Answer::SrpUsername { ret: 0, alert: 0 }
        }
        (End::Server, Request::SrpServerParams) => Answer::SrpParams(Some(params)),
        (End::Client, Request::SrpVerifyParams(p)) => {
            assert_eq!(*p, params);
            Answer::SrpVerified(1)
        }
        (End::Client, Request::SrpClientA) => Answer::SrpValue(Some(vec![7; 32])),
        (End::Server, Request::SrpServerSecret { a }) => {
            assert_eq!(a, &vec![7; 32]);
            Answer::SrpValue(Some(vec![9; 32]))
        }
        (End::Client, Request::SrpClientSecret) => Answer::SrpValue(Some(vec![9; 32])),
        _ => accept(r),
    }
}

/// Client and server configurations for SRP-AES-128-CBC-SHA, the client with login "user".
fn srp_configs(p: &TestProvider) -> (Config, Config) {
    let srp = vec![suites::by_protocol_id(0xc01d).unwrap()];
    let mut ccfg = client12();
    ccfg.max_version = v::TLS1_2;
    ccfg.ciphers.clone_from(&srp);
    ccfg.srp = true;
    ccfg.srp_login = Some(b"user".to_vec());
    let mut scfg = server_config(p);
    scfg.ciphers = srp;
    scfg.max_version = v::TLS1_2;
    scfg.srp = true;
    scfg.callbacks.srp_username = true;
    (ccfg, scfg)
}

#[test]
fn loopback_srp() {
    use crate::conn::pair::{self, End};
    let p = TestProvider::new(b"loopback-srp");
    let (ccfg, scfg) = srp_configs(&p);
    let mut client = Connection::new(ccfg);
    let mut server = Connection::new(scfg);
    let mut log = pair::Log::default();
    let mut answer = |end: End, r: &Request| srp_answer(end, r, &[5; 32]);
    let r = pair::handshake(&p, &mut client, &mut server, false, &mut answer, &mut log);
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(client.negotiated().cipher.unwrap().protocol_id(), 0xc01d);
    // Without a certificate: none was sent.
    assert!(client.negotiated().peer_chain.is_empty());

    // B not below N: illegal-parameter.
    let (ccfg, scfg) = srp_configs(&p);
    let mut client = Connection::new(ccfg);
    let mut server = Connection::new(scfg);
    let mut answer = |end: End, r: &Request| srp_answer(end, r, &[0xff; 64]);
    let r = pair::handshake(&p, &mut client, &mut server, false, &mut answer, &mut log);
    let Err((End::Client, e)) = r else {
        panic!("{r:?}")
    };
    assert_eq!(
        e,
        Error::alert(abi::SSL_AD_ILLEGAL_PARAMETER, abi::SSL_R_BAD_DATA)
            .in_func("srp_verify_server_param")
    );

    // Without a login the server refuses.
    let (mut ccfg, scfg) = srp_configs(&p);
    ccfg.srp_login = None;
    let mut client = Connection::new(ccfg);
    let mut server = Connection::new(scfg);
    let mut answer = |end: End, r: &Request| srp_answer(end, r, &[5; 32]);
    let r = pair::handshake(&p, &mut client, &mut server, false, &mut answer, &mut log);
    let Err((End::Server, e)) = r else {
        panic!("{r:?}")
    };
    assert_eq!(e.reason, abi::SSL_R_PSK_IDENTITY_NOT_FOUND);
}

/// A DTLS configuration from a TLS one.
fn dtls(mut cfg: Config, version: u16) -> Config {
    cfg.dtls = true;
    cfg.method_version = 0;
    cfg.max_version = version;
    cfg.min_version = 0;
    cfg.dtls_mtu = 1400;
    cfg
}

#[test]
fn dtls_loopback() {
    use crate::conn::pair::{self, End};
    for (version, suite) in [(v::DTLS1_2, 0xc02f), (v::DTLS1, 0xc013)] {
        let p = TestProvider::new(b"dtls-loopback");
        let both = vec![
            suites::by_protocol_id(0xc02f).unwrap(),
            suites::by_protocol_id(0xc013).unwrap(),
        ];
        let mut ccfg = dtls(client12(), version);
        ccfg.security_level = 0;
        ccfg.callbacks.msg = true;
        ccfg.ciphers.clone_from(&both);
        let mut scfg = dtls(server_config(&p), version);
        scfg.security_level = 0;
        scfg.callbacks.info = true;
        scfg.ciphers = both;
        let mut client = Connection::new(ccfg);
        let mut server = Connection::new(scfg);
        let mut log = pair::Log::default();
        let mut answer = |_: End, r: &Request| accept(r);
        let mut keep = |_: End, _: usize| true;
        let r = pair::handshake_dtls(
            &p,
            &mut client,
            &mut server,
            &mut answer,
            &mut keep,
            0,
            &mut log,
        );
        assert!(
            r.is_ok(),
            "{r:?}: server state {}, client state {}\nsigalg {:?} cipher {:?}",
            server.state(),
            client.state(),
            server.hs.sh.sigalg,
            server.hs.new_cipher.map(|c| c.name),
        );
        assert_eq!(client.negotiated().version, version);
        assert_eq!(server.negotiated().version, version);
        assert_eq!(client.negotiated().cipher.unwrap().protocol_id(), suite);
        // Application data both ways.
        client.write_app(&p, b"ping").unwrap();
        for d in client.take_datagrams() {
            server.feed_datagram(&d);
        }
        assert_eq!(server.step(&p, true).unwrap(), Event::AppData);
        let mut buf = [0u8; 16];
        assert_eq!(server.read_app(&mut buf, false), 4);
        assert_eq!(&buf[..4], b"ping");
    }
}

#[test]
fn dtls_survives_lost_datagrams() {
    use crate::conn::pair::{self, End};
    let p = TestProvider::new(b"dtls-loss");
    let mut ccfg = dtls(client12(), v::DTLS1_2);
    ccfg.dtls_mtu = 256;
    let mut scfg = dtls(server_config(&p), v::DTLS1_2);
    scfg.dtls_mtu = 256;
    let mut client = Connection::new(ccfg);
    let mut server = Connection::new(scfg);
    let mut log = pair::Log::default();
    let mut answer = |_: End, r: &Request| accept(r);
    // Lose the server's second datagram and the client's third once each.
    let mut keep = |e: End, n: usize| !matches!((e, n), (End::Server, 1) | (End::Client, 2));
    let r = pair::handshake_dtls(
        &p,
        &mut client,
        &mut server,
        &mut answer,
        &mut keep,
        4,
        &mut log,
    );
    assert!(
        r.is_ok(),
        "{r:?}: server {:?}\nclient {:?}",
        log.server,
        log.client
    );
    assert_eq!(
        client.negotiated().client_finished,
        server.negotiated().client_finished
    );
}
