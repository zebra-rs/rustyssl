//! QUIC mode's handshake between two connections, as a QUIC stack drives it (RFC 9001,
//! section 4): CRYPTO data carried by level, secrets yielded in OpenSSL's order, transport
//! parameters exchanged in extension 57.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "tests"
)]

use rustyssl_abi as abi;

use super::{Direction, QuicLevel, QuicTlsConfig};
use crate::conn::{Answer, Config, Connection, Event, Request};
use crate::consts::version as v;
use crate::error::Error;
use crate::testprov::TestProvider;

/// A QUIC client: TLS 1.3 with `suite`, its transport parameters set.
fn client(suite: u16) -> Config {
    Config {
        min_version: v::TLS1_3,
        max_version: v::TLS1_3,
        ciphers: vec![crate::suites::by_protocol_id(suite).unwrap()],
        groups: vec![0x001d],
        key_share_groups: vec![0x001d],
        hostname: Some(b"server".to_vec()),
        max_cert_list: 102_400,
        max_send_fragment: 16384,
        now: 1_700_000_000,
        quic: Some(QuicTlsConfig {
            transport_params: Some(b"client tp".to_vec()),
            early_data: false,
        }),
        ..Config::default()
    }
}

/// A QUIC server, its transport parameters set.
fn server(p: &TestProvider) -> Config {
    let mut c = crate::conn::server::tests::server_config(p);
    c.quic = Some(QuicTlsConfig {
        transport_params: Some(b"server tp".to_vec()),
        early_data: false,
    });
    c
}

/// One end: its connection, the CRYPTO data the peer sent it by level, what it saw, and the
/// secrets it was given.
struct End {
    name: &'static str,
    c: Connection,
    inbox: Vec<(QuicLevel, Vec<u8>)>,
    seen: Vec<String>,
    secrets: Vec<(QuicLevel, Direction, Vec<u8>)>,
    /// What `got_transport_params` returns.
    accept_params: bool,
    done: bool,
}

impl End {
    fn new(name: &'static str, cfg: Config) -> Self {
        Self {
            name,
            c: Connection::new(cfg),
            inbox: Vec::new(),
            seen: Vec::new(),
            secrets: Vec::new(),
            accept_params: true,
            done: false,
        }
    }

    /// Notes what a write carries (its messages' types) and hands it to the peer.
    fn send(&mut self, chunks: Vec<(QuicLevel, Vec<u8>)>, to: &mut Vec<(QuicLevel, Vec<u8>)>) {
        for (level, data) in chunks {
            let mut at = 0;
            let mut types = Vec::new();
            while at + 4 <= data.len() {
                types.push(data[at]);
                let len = usize::from(data[at + 1]) << 16
                    | usize::from(data[at + 2]) << 8
                    | usize::from(data[at + 3]);
                at += 4 + len;
            }
            self.seen.push(format!("send {level:?} {types:?}"));
            to.push((level, data));
        }
    }

    /// Steps until the end waits for input it doesn't have.
    fn run(&mut self, p: &TestProvider, to: &mut Vec<(QuicLevel, Vec<u8>)>) -> Result<(), Error> {
        for _ in 0..1000 {
            match self.c.step(p, false)? {
                Event::QuicSecret(s) => {
                    if s.direction == Direction::Write {
                        let before = self.c.take_quic_crypto_before_secret();
                        self.send(before, to);
                    }
                    self.seen
                        .push(format!("yield {:?} {:?}", s.level, s.direction));
                    assert_eq!(s.secret.bytes().len(), s.hash.len());
                    self.secrets
                        .push((s.level, s.direction, s.secret.bytes().to_vec()));
                }
                Event::Request(Request::QuicTransportParams { params }) => {
                    self.seen
                        .push(format!("params {}", String::from_utf8_lossy(&params)));
                    self.c.answer(if self.accept_params {
                        Answer::Continue
                    } else {
                        Answer::Fail {
                            alert: Some(0),
                            reason: 0,
                        }
                    });
                }
                Event::Request(Request::Verify { chain, .. }) => {
                    self.c.answer(Answer::Verified {
                        result: i64::from(abi::X509_V_OK),
                        proceed: true,
                        verified_chain: chain,
                    });
                }
                Event::Request(_) => self.c.answer(Answer::Continue),
                Event::HandshakeDone => self.done = true,
                Event::Output => {
                    let rest = self.c.take_quic_crypto();
                    self.send(rest, to);
                    for a in self.c.take_quic_alerts() {
                        self.seen.push(format!("alert {a}"));
                    }
                }
                Event::NeedInput | Event::Idle => {
                    let level = self.c.read_level();
                    if let Some(i) = self.inbox.iter().position(|(l, _)| *l == level) {
                        let (_, data) = self.inbox.remove(i);
                        self.c.feed_quic_crypto(level, &data)?;
                        continue;
                    }
                    let rest = self.c.take_quic_crypto();
                    self.send(rest, to);
                    return Ok(());
                }
                _ => {}
            }
        }
        panic!("{} doesn't stop", self.name);
    }
}

/// Runs both ends until neither moves; the end that failed, if one did.
fn handshake(p: &TestProvider, c: &mut End, s: &mut End) -> Result<(), (&'static str, Error)> {
    for _ in 0..20 {
        let mut to_s = Vec::new();
        c.run(p, &mut to_s).map_err(|e| ("client", e))?;
        s.inbox.extend(to_s.iter().cloned());
        let mut to_c = Vec::new();
        s.run(p, &mut to_c).map_err(|e| ("server", e))?;
        c.inbox.extend(to_c.iter().cloned());
        if to_s.is_empty() && to_c.is_empty() {
            break;
        }
    }
    Ok(())
}

/// Whether each secret one end wrote with is the one the other read with.
fn agree(a: &End, b: &End) -> bool {
    a.secrets.iter().all(|(l, d, s)| {
        let other = if *d == Direction::Write {
            Direction::Read
        } else {
            Direction::Write
        };
        b.secrets
            .iter()
            .any(|(l2, d2, s2)| l2 == l && *d2 == other && s2 == s)
    })
}

#[test]
fn rfc9001_handshake_flow() {
    let p = TestProvider::new(b"quic");
    let mut c = End::new("client", client(0x1301));
    let mut s = End::new("server", server(&p));
    handshake(&p, &mut c, &mut s).unwrap();
    assert!(c.done && s.done);
    // OpenSSL's order (`ssl_quic_tls.c`): the server's handshake write secret before its
    // handshake read secret, the client's handshake write secret with its read secret, its
    // application read secret after its write secret (statem_clnt.c, statem_lib.c).
    assert_eq!(
        c.seen,
        [
            "send Initial [1]",
            "yield Handshake Write",
            "yield Handshake Read",
            "params server tp",
            "send Handshake [20]",
            "yield Application Write",
            "yield Application Read",
        ]
    );
    assert_eq!(
        s.seen,
        [
            "params client tp",
            "send Initial [2]",
            "yield Handshake Write",
            "yield Handshake Read",
            "send Handshake [8]",
            "send Handshake [11]",
            "send Handshake [15]",
            "send Handshake [20]",
            "yield Application Write",
            "yield Application Read",
            "send Application [4]",
            "send Application [4]",
        ]
    );
    assert_eq!(c.secrets.len(), 4);
    assert!(agree(&c, &s) && agree(&s, &c));
    assert_eq!(c.c.read_level(), QuicLevel::Application);
    assert_eq!(s.c.write_level(), QuicLevel::Application);
    assert!(c.c.quic_transport_params_consumed() && s.c.quic_transport_params_consumed());
    // No ChangeCipherSpec, no record layer: nothing went out as TLS.
    assert!(!c.c.has_output() && !s.c.has_output());
}

#[test]
fn any_suite_passes_through() {
    // The third-party API doesn't filter suites (OpenSSL's own QUIC never negotiates CCM).
    for suite in [0x1302, 0x1303, 0x1304] {
        let p = TestProvider::new(b"suites");
        let mut c = End::new("client", client(suite));
        let mut scfg = server(&p);
        scfg.ciphers = vec![crate::suites::by_protocol_id(suite).unwrap()];
        let mut s = End::new("server", scfg);
        handshake(&p, &mut c, &mut s).unwrap();
        assert!(c.done && s.done, "{suite:x}");
        assert_eq!(c.c.negotiated().cipher.unwrap().protocol_id(), suite);
        assert!(agree(&c, &s) && agree(&s, &c));
    }
}

#[test]
fn crypto_data_at_another_level_is_refused() {
    let p = TestProvider::new(b"levels");
    let mut c = End::new("client", client(0x1301));
    let mut to_s = Vec::new();
    c.run(&p, &mut to_s).unwrap();
    assert_eq!(c.c.read_level(), QuicLevel::Initial);
    let e =
        c.c.feed_quic_crypto(QuicLevel::Handshake, b"x")
            .unwrap_err();
    assert_eq!(e.reason, abi::SSL_R_UNEXPECTED_MESSAGE);
}

#[test]
fn transport_params_refused_is_fatal() {
    // `got_transport_params` returning 0: `custom_ext_parse`'s bad_extension with its alert.
    let p = TestProvider::new(b"params");
    let mut c = End::new("client", client(0x1301));
    let mut s = End::new("server", server(&p));
    s.accept_params = false;
    let (who, e) = handshake(&p, &mut c, &mut s).unwrap_err();
    assert_eq!(who, "server");
    assert_eq!(e.reason, abi::SSL_R_BAD_EXTENSION);
    assert_eq!(s.c.take_quic_alerts(), [0]);
}

#[test]
fn a_failed_secret_stops_the_handshake() {
    // A `yield_secret` that fails: nothing after that secret happens, internal_error goes out.
    let p = TestProvider::new(b"yield");
    let mut c = End::new("client", client(0x1301));
    let mut s = End::new("server", server(&p));
    let mut to_s = Vec::new();
    c.run(&p, &mut to_s).unwrap();
    s.c.feed_quic_crypto(QuicLevel::Initial, &to_s[0].1)
        .unwrap();
    let sent;
    loop {
        match s.c.step(&p, false).unwrap() {
            Event::Request(_) => s.c.answer(Answer::Continue),
            Event::QuicSecret(q) => {
                assert_eq!(
                    (q.level, q.direction),
                    (QuicLevel::Handshake, Direction::Write)
                );
                sent = s.c.take_quic_crypto_before_secret();
                s.c.fail_quic_secret(&p, Error::internal());
                break;
            }
            e => panic!("{e:?}"),
        }
    }
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, QuicLevel::Initial);
    let mut rest = Vec::new();
    loop {
        match s.c.step(&p, false) {
            Ok(e) => rest.push(e),
            Err(e) => {
                assert_eq!(e.reason, abi::ERR_R_INTERNAL_ERROR);
                break;
            }
        }
    }
    assert!(
        !rest.iter().any(|e| matches!(e, Event::QuicSecret(_))),
        "{rest:?}"
    );
    assert!(s.c.take_quic_crypto().is_empty());
    assert_eq!(
        s.c.take_quic_alerts(),
        [u8::try_from(abi::SSL_AD_INTERNAL_ERROR).unwrap()]
    );
}

#[test]
fn key_update_is_refused() {
    // A KeyUpdate isn't a valid transition over QUIC (statem_srvr.c): unexpected_message.
    let p = TestProvider::new(b"keyupdate");
    let mut c = End::new("client", client(0x1301));
    let mut s = End::new("server", server(&p));
    handshake(&p, &mut c, &mut s).unwrap();
    let ku = crate::msgs::frame(crate::consts::handshake::KEY_UPDATE, &[0]).unwrap();
    s.c.feed_quic_crypto(QuicLevel::Application, &ku).unwrap();
    let mut seen = Vec::new();
    let e = loop {
        match s.c.step(&p, true) {
            // The message read, the state machine takes it on the next step.
            Ok(Event::NeedInput) if s.c.in_init() => {}
            Ok(Event::NeedInput) => panic!("waits after a KeyUpdate: {seen:?}"),
            Ok(e) => seen.push(e),
            Err(e) => break e,
        }
    };
    assert_eq!(e.reason, abi::SSL_R_UNEXPECTED_MESSAGE);
    assert_eq!(
        s.c.take_quic_alerts(),
        [u8::try_from(abi::SSL_AD_UNEXPECTED_MESSAGE).unwrap()]
    );
}

#[test]
fn transport_params_extension_is_registered_once() {
    let mut cfg = client(0x1301);
    cfg.custom_exts.push(crate::conn::config::CustomExt {
        typ: crate::consts::ext::QUIC_TRANSPORT_PARAMETERS,
        context: 0,
        server: Some(false),
        has_add: false,
        has_parse: false,
    });
    let c = Connection::new(cfg);
    let exts = &c.config().custom_exts;
    assert_eq!(exts.len(), 1);
    assert_eq!(exts[0].context, super::PARAMS_CONTEXT);
    assert!(exts[0].has_add && exts[0].has_parse);
}
