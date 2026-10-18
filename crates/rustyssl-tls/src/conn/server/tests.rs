//! Tests of the server with the test provider: RFC 8448's client flights replayed against the
//! server (section 3's simple 1-RTT handshake, section 5's HelloRetryRequest), a scripted
//! client that checks the server's flight and answers it, and the alerts and reasons of
//! malformed and unexpected messages.
//!
//! RFC 8448's server is NSS, not OpenSSL: its ServerHello puts key_share before
//! supported_versions (OpenSSL's `ext_defs` order is the reverse), its EncryptedExtensions
//! carry record_size_limit (which OpenSSL doesn't implement), and its HelloRetryRequest a
//! cookie (which only a stateless OpenSSL server sends). So the server's messages are compared
//! with the RFC's in OpenSSL's order and contents; the transcript then differs from the RFC's,
//! and the scripted client checks the rest of the flight (the CertificateVerify signature with
//! the RFC's certificate, the Finished) with the key schedule over the actual transcript.

#![allow(clippy::arithmetic_side_effects, reason = "test code")]
#![allow(clippy::indexing_slicing, reason = "test code")]

use rustyssl_abi as abi;

use super::*;
use crate::codec::Reader;
use crate::conn::common::{finished, keys};
use crate::conn::{CertKey, Config, Event, Request, TicketKeys};
use crate::consts::{ext as t, group, sigscheme, version as v};
use crate::crypto::{HashAlg, Provider as _};
use crate::msgs::rfc8448::VECTORS;
use crate::record::{self, Read};
use crate::testprov::TestProvider;
use crate::testprov::keys::PublicKey;

fn h(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// RFC 8448's message `name` (the `nth` of that name) in `section`, with its header.
fn rfc(section: &str, name: &str, nth: usize) -> &'static [u8] {
    VECTORS
        .iter()
        .filter(|(s, n, _)| *s == section && *n == name)
        .nth(nth)
        .unwrap()
        .2
}

/// Section 3's ephemeral X25519 keys.
const CLIENT_PRIVATE: &str = "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005";
const SERVER_PRIVATE: &str = "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e";

/// A plaintext record of type `ty`.
pub(crate) fn plain_record(ty: u8, payload: &[u8]) -> Vec<u8> {
    let mut r = vec![ty, 0x03, 0x01];
    r.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    r.extend_from_slice(payload);
    r
}

/// Steps `c` until it needs input, finishes, or asks: the output, and the last event.
pub(crate) fn drive(
    c: &mut Connection,
    p: &dyn Provider,
) -> (Vec<u8>, crate::error::Result<Event>) {
    let mut out = Vec::new();
    for _ in 0..1000 {
        let e = c.step(p, false);
        out.extend(c.take_output());
        match e {
            Ok(Event::Output | Event::Info { .. } | Event::Message { .. } | Event::Keylog(_)) => {}
            Ok(Event::UpdateCache { .. } | Event::RemoveSession) => {}
            other => return (out, other),
        }
    }
    panic!("no progress");
}

/// RFC 8448's server RSA key (section 3), as the RFC gives it. (The test provider's
/// `rfc8448_server` key is another, 2048-bit, key.)
fn rfc8448_rsa_key() -> crate::testprov::keys::PrivateKey {
    let n = h(concat!(
        "b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af1",
        "9eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8c",
        "a9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f"
    ));
    let d = h(concat!(
        "04dea705d43a6ea7209dd8072111a83c81e322a59278b33480641eaf7c0a6985b8e31c44f6de62e1b4c2309f6126e77b",
        "7c41e923314bbfa3881305dc1217f16c819ce538e922f369828d0e57195d8c8488460207b2faa726bcf708bbd7db7f67",
        "9f893492fc2a622e08970aac441ce4e0c3088df25ae679233df8a3bda2ff9941"
    ));
    let p = h(concat!(
        "e435fb7cc83737756dacea96ab7f59a2cc1069db7deb190e17e33a532b273f30",
        "a327aa0aaabc58cd67466af9845fadc675fe094af92c4bd1f2c1bc33dd2e0515"
    ));
    let q = h(concat!(
        "cabd3bc0e0438664c8d4cc9f99977a94d9bbfead8e43870abae3f7eb8b4e0eee",
        "8af1d9b4719ba6196cf2cbbaeeebf8b3490afe9e9ffa74a88aa51fc645629303"
    ));
    let dp = h(concat!(
        "3f57345c27fe1b687e6e761627b78b1b826433dd760fa0bea6a6acf39490aa1b",
        "47cda4869d68f584dd5b5029bd32093b8258661fe715025e5d70a45a08d3d319"
    ));
    let dq = h(concat!(
        "183da01363bd2f2885cacbdc9964bf4764f1517636f86401286f71893c52ccfe",
        "40a6c23d0d086b47c6fb10d8fd1041e04def7e9a40ce957c417794e10412d139"
    ));
    let qi = h(concat!(
        "839ca9a085e4286b2c90e466997a2c681f21339aa3477814e4dec11833050ed5",
        "0dd13cc038048a43c59b2acc416889c037665fe5afa605969f8c01dfa5ca969d"
    ));
    crate::testprov::keys::PrivateKey::rsa(&n, &[1, 0, 1], &d, &p, &q, &dp, &dq, &qi)
}

/// The RFC's RSA certificate and its key.
fn rsa_cert(p: &TestProvider) -> CertKey {
    let cert_msg = rfc("3", "Certificate", 0);
    let cm = crate::msgs::cert::Certificate::parse(&cert_msg[4..], true, true).unwrap();
    let der = cm.entries[0].data.clone();
    let key = rfc8448_rsa_key();
    // The key is the certificate's.
    assert_eq!(
        PublicKey::from_cert(&der).unwrap().spki(),
        key.public(p).unwrap().spki()
    );
    CertKey {
        chain: vec![der],
        key: p.add_key(key),
        slot: common::sigalgs::PKEY_RSA,
        schemes: vec![
            sigscheme::RSA_PSS_RSAE_SHA256,
            sigscheme::RSA_PSS_RSAE_SHA384,
            sigscheme::RSA_PSS_RSAE_SHA512,
            sigscheme::RSA_PKCS1_SHA256,
            sigscheme::RSA_PKCS1_SHA384,
            sigscheme::RSA_PKCS1_SHA512,
        ],
        auth: crate::suites::masks::SSL_aRSA,
        ec_group: None,
        curve_nid: abi::NID_undef,
        can_sign: true,
        cert_sig: Some((abi::NID_sha256, abi::NID_rsaEncryption)),
        raw_public_key: None,
        ocsp_response: None,
    }
}

/// A TLS 1.3-capable server with OpenSSL's default suites and the RFC's certificate.
pub(crate) fn server_config(p: &TestProvider) -> Config {
    let ciphers = [
        0x1302, 0x1303, 0x1301, 0xc030, 0xc02f, 0x009f, 0x009e, 0x009d, 0x009c,
    ]
    .iter()
    .map(|&id| crate::suites::by_protocol_id(id).unwrap())
    .collect();
    Config {
        server: true,
        ciphers,
        certs: vec![rsa_cert(p)],
        num_tickets: 2,
        max_send_fragment: 16384,
        split_send_fragment: 16384,
        max_cert_list: 102_400,
        verify_depth: -1,
        session_cache_mode: i64::from(abi::SSL_SESS_CACHE_SERVER),
        now: 1_700_000_000,
        ticket_keys: Some(TicketKeys {
            name: [7; 16],
            hmac_key: crate::crypto::Secret::new(vec![8; 32]),
            aes_key: crate::crypto::Secret::new(vec![9; 32]),
        }),
        ..Config::default()
    }
}

/// Splits handshake octets into messages (with their headers).
fn messages(b: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rd = Reader::new(b);
    while !rd.is_empty() {
        let at = b.len() - rd.len();
        rd.u8().unwrap();
        let body = rd.vec24().unwrap();
        out.push(b[at..at + 4 + body.len()].to_vec());
    }
    out
}

/// A scripted TLS 1.3 client: the key schedule over the transcript, with the record layer of
/// a client-role connection, to read the server's flight and answer it.
struct Client {
    c: Connection,
    input: Vec<u8>,
    hs: Vec<u8>,
}

impl Client {
    /// A client that sent `client_hellos` (and, between them, received a HelloRetryRequest).
    fn new() -> Self {
        let mut c = Connection::new(Config::default());
        c.neg.version = v::TLS1_3;
        c.hs.transcript = crate::keysched::Transcript::new();
        Self {
            c,
            input: Vec::new(),
            hs: Vec::new(),
        }
    }

    /// The next record's content type and data.
    fn record(&mut self, p: &dyn Provider) -> Option<(u8, Vec<u8>)> {
        loop {
            match self.c.rr.read(p, &self.input).unwrap() {
                Read::NeedMore(_) => return None,
                Read::IgnoredCcs { consumed, .. } => {
                    self.input.drain(..consumed);
                }
                Read::Record { consumed, record } => {
                    self.input.drain(..consumed);
                    return Some((record.content_type, record.data));
                }
            }
        }
    }

    /// The next handshake message.
    fn message(&mut self, p: &dyn Provider) -> Vec<u8> {
        loop {
            if self.hs.len() >= 4 {
                let n = usize::from(self.hs[1]) << 16
                    | usize::from(self.hs[2]) << 8
                    | usize::from(self.hs[3]);
                if self.hs.len() >= 4 + n {
                    return self.hs.drain(..4 + n).collect();
                }
            }
            let (ty, data) = self.record(p).expect("a record");
            assert_eq!(ty, record::content_type::handshake(), "{data:02x?}");
            self.hs.extend_from_slice(&data);
        }
    }

    /// Takes the ServerHello in `out`, with `transcript` (the messages before it), and installs
    /// the handshake keys from `shared`.
    fn hello(
        &mut self,
        p: &dyn Provider,
        out: &[u8],
        transcript: &[Vec<u8>],
        shared: &[u8],
    ) -> Vec<u8> {
        self.input.extend_from_slice(out);
        let sh = self.message(p);
        let c = &mut self.c;
        let cs = u16::from_be_bytes([
            sh[4 + 2 + 32 + 1 + usize::from(sh[4 + 2 + 32])],
            sh[4 + 2 + 32 + 2 + usize::from(sh[4 + 2 + 32])],
        ]);
        c.hs.new_cipher = crate::suites::by_protocol_id(cs);
        let hash = keys::handshake_md(c).unwrap();
        for m in transcript {
            c.hs.transcript.add(m);
        }
        c.hs.transcript.start_hash(p, hash, false).unwrap();
        c.hs.transcript.add(&sh);
        let cp = c.hs.new_cipher.unwrap();
        keys::generate_early(c, p, cp, None).unwrap();
        keys::generate_handshake_secret(c, p, Some(shared)).unwrap();
        keys::store_handshake_traffic_hash(c).unwrap();
        keys::change_cipher_state13(
            c,
            p,
            abi::SSL3_CC_HANDSHAKE | abi::SSL3_CHANGE_CIPHER_CLIENT_READ,
            None,
        )
        .unwrap();
        keys::change_cipher_state13(
            c,
            p,
            abi::SSL3_CC_HANDSHAKE | abi::SSL3_CHANGE_CIPHER_CLIENT_WRITE,
            None,
        )
        .unwrap();
        sh
    }

    /// Reads EncryptedExtensions, Certificate, CertificateVerify, and Finished, checking the
    /// signature (with `cert`) and the Finished; returns the four messages.
    fn server_flight(&mut self, p: &dyn Provider, cert: &[u8]) -> Vec<Vec<u8>> {
        let ee = self.message(p);
        assert_eq!(ee[0], crate::consts::handshake::ENCRYPTED_EXTENSIONS);
        self.c.hs.transcript.add(&ee);
        let ct = self.message(p);
        assert_eq!(ct[0], crate::consts::handshake::CERTIFICATE);
        self.c.hs.transcript.add(&ct);
        let th = self.c.hs.transcript.current().unwrap();
        let cv = self.message(p);
        assert_eq!(cv[0], crate::consts::handshake::CERTIFICATE_VERIFY);
        let scheme = u16::from_be_bytes([cv[4], cv[5]]);
        let sig = &cv[8..];
        let mut tbs = vec![0x20; 64];
        tbs.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
        tbs.extend_from_slice(&th);
        assert!(p.verify(cert, scheme, &tbs, sig).unwrap(), "the signature");
        self.c.hs.transcript.add(&cv);
        let fin = self.message(p);
        assert_eq!(fin[0], crate::consts::handshake::FINISHED);
        let want = finished::final_finish_mac(&self.c, p, true).unwrap();
        assert_eq!(&fin[4..], &want[..], "the server's Finished");
        self.c.hs.transcript.add(&fin);
        vec![ee, ct, cv, fin]
    }

    /// The client's Finished, protected.
    fn finished(&mut self, p: &dyn Provider) -> Vec<u8> {
        let md = finished::final_finish_mac(&self.c, p, false).unwrap();
        let msg = crate::msgs::frame(crate::consts::handshake::FINISHED, &md).unwrap();
        self.c.hs.transcript.add(&msg);
        self.c
            .write_record(p, record::content_type::handshake(), &msg)
            .unwrap();
        self.c.take_output()
    }
}

/// The ServerHello OpenSSL sends for the RFC's: the same fields, with supported_versions and
/// key_share in OpenSSL's order.
fn openssl_order(sh: &[u8], drop: &[u16]) -> Vec<u8> {
    let parsed = crate::msgs::hello::ServerHello::parse(&sh[4..], true).unwrap();
    let mut exts = parsed.extensions().unwrap();
    exts.retain(|e| !drop.contains(&e.typ));
    let order = |typ: u16| crate::conn::common::ext::index_of(typ).unwrap();
    exts.sort_by_key(|e| order(e.typ));
    let contents = crate::msgs::ext::encode_contents(&exts).unwrap();
    let body = crate::msgs::hello::ServerHello {
        extensions: Some(contents),
        ..parsed
    }
    .encode()
    .unwrap();
    crate::msgs::frame(crate::consts::handshake::SERVER_HELLO, &body).unwrap()
}

#[test]
fn rfc8448_simple_1rtt() {
    let p = TestProvider::new(b"rfc8448-server");
    let mut c = Connection::new(server_config(&p));
    let ch = rfc("3", "ClientHello", 0);
    let sh_rfc = rfc("3", "ServerHello", 0);
    // The server's X25519 key, then its random.
    p.queue_random(&h(SERVER_PRIVATE));
    p.queue_random(&sh_rfc[6..38]);
    c.feed(&plain_record(22, ch));
    let (out, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::NeedInput);
    assert_eq!(c.state(), abi::TLS_ST_EARLY_DATA);

    let shared = {
        let cpriv: [u8; 32] = h(CLIENT_PRIVATE).try_into().unwrap();
        let spub = crate::testprov::x25519_public(&h(SERVER_PRIVATE).try_into().unwrap());
        rustyssl_crypto::ecx::x25519(&cpriv, &spub)
            .unwrap()
            .to_vec()
    };
    let mut client = Client::new();
    let sh = client.hello(&p, &out, &[ch.to_vec()], &shared);
    assert_eq!(sh, openssl_order(sh_rfc, &[]), "the ServerHello");
    // The handshake secret is the RFC's (it doesn't depend on the transcript).
    assert_eq!(
        client
            .c
            .hs
            .sh
            .keys
            .schedule
            .as_ref()
            .unwrap()
            .secret()
            .bytes(),
        h("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
    );
    let cert = c.cfg.certs[0].chain[0].clone();
    let flight = client.server_flight(&p, &cert);
    // EncryptedExtensions: the server's groups (the client's share isn't for its first,
    // X25519MLKEM768), nothing else.
    let ee = &flight[0];
    let exts = crate::msgs::ext::split(&ee[6..]).unwrap();
    let types: Vec<u16> = exts.iter().map(|e| e.typ).collect();
    assert_eq!(types, [t::SUPPORTED_GROUPS]);
    // The Certificate is the RFC's.
    assert_eq!(flight[1], rfc("3", "Certificate", 0));
    assert_eq!(
        u16::from_be_bytes([flight[2][4], flight[2][5]]),
        sigscheme::RSA_PSS_RSAE_SHA256
    );

    // The client's application read keys, for the tickets.
    keys::generate_master_secret(&mut client.c, &p).unwrap();
    keys::store_server_finished_hash(&mut client.c).unwrap();
    let fin = client.finished(&p);
    keys::change_cipher_state13(
        &mut client.c,
        &p,
        abi::SSL3_CC_APPLICATION | abi::SSL3_CHANGE_CIPHER_CLIENT_READ,
        None,
    )
    .unwrap();
    c.feed(&fin);
    let (out, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::HandshakeDone);
    assert_eq!(c.state(), abi::TLS_ST_OK);
    assert_eq!(c.neg.client_finished.len(), 32);
    // Two tickets, under the application keys: a week's lifetime at most (the default
    // timeout, 7200 seconds), nonces 0 and 1, and the early data limit only if set.
    client.input.extend_from_slice(&out);
    for nonce in 0u8..2 {
        let nst = client.message(&p);
        assert_eq!(nst[0], crate::consts::handshake::NEW_SESSION_TICKET);
        let crate::msgs::misc::NewSessionTicket::Tls13(t) =
            crate::msgs::misc::NewSessionTicket::parse(&nst[4..], true).unwrap()
        else {
            panic!("a TLS 1.3 ticket");
        };
        assert_eq!(t.lifetime, 7200);
        assert_eq!(t.nonce, [0, 0, 0, 0, 0, 0, 0, nonce]);
        assert!(t.extensions.is_empty());
        // The ticket decrypts to the session with the resumption PSK.
        assert_eq!(&t.ticket[..16], &[7; 16]);
    }
    assert!(client.record(&p).is_none());
}
