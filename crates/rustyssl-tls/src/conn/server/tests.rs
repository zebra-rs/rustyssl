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
        chain_security: None,
        unsupported_digests: Vec::new(),
        strict: None,
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

/// A scripted TLS 1.3 client: the key schedule over the transcript, with the record layer of
/// a client-role connection, to read the server's flight and answer it.
struct Client {
    c: Connection,
    input: Vec<u8>,
    hs: Vec<u8>,
    ccs: usize,
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
            ccs: 0,
        }
    }

    /// The next record's content type and data.
    fn record(&mut self, p: &dyn Provider) -> Option<(u8, Vec<u8>)> {
        loop {
            match self.c.rr.read(p, &self.input).unwrap() {
                Read::NeedMore(_) => return None,
                Read::IgnoredCcs { consumed, .. } => {
                    self.ccs = self.ccs.saturating_add(1);
                    self.input.drain(..consumed);
                }
                Read::Skipped { consumed, .. } => {
                    self.input.drain(..consumed);
                }
                Read::Record { consumed, record } => {
                    self.input.drain(..consumed);
                    if record.content_type == record::content_type::change_cipher_spec() {
                        // The middlebox compatibility ChangeCipherSpec.
                        assert_eq!(record.data, [1]);
                        self.ccs = self.ccs.saturating_add(1);
                        continue;
                    }
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

    /// A resumption's ServerHello: like [`Client::hello`], from the early secret of `psk` (or
    /// the one already made, for early data, when the ClientHello is already in the
    /// transcript), with `shared` if a key was exchanged. The client's handshake write keys
    /// wait when `early` (they follow the EndOfEarlyData).
    fn hello_psk(
        &mut self,
        p: &dyn Provider,
        out: &[u8],
        transcript: &[Vec<u8>],
        shared: Option<&[u8]>,
        psk: Option<&[u8]>,
        early: bool,
    ) -> Vec<u8> {
        self.input.extend_from_slice(out);
        let sh = self.message(p);
        let c = &mut self.c;
        let at = 4 + 2 + 32 + 1 + usize::from(sh[4 + 2 + 32]);
        c.hs.new_cipher = crate::suites::by_protocol_id(u16::from_be_bytes([sh[at], sh[at + 1]]));
        let hash = keys::handshake_md(c).unwrap();
        for m in transcript {
            c.hs.transcript.add(m);
        }
        c.hs.transcript.start_hash(p, hash, false).unwrap();
        c.hs.transcript.add(&sh);
        let cp = c.hs.new_cipher.unwrap();
        if let Some(psk) = psk {
            keys::generate_early(c, p, cp, Some(psk)).unwrap();
        }
        keys::generate_handshake_secret(c, p, shared).unwrap();
        keys::store_handshake_traffic_hash(c).unwrap();
        keys::change_cipher_state13(
            c,
            p,
            abi::SSL3_CC_HANDSHAKE | abi::SSL3_CHANGE_CIPHER_CLIENT_READ,
            None,
        )
        .unwrap();
        if !early {
            self.handshake_write(p);
        }
        sh
    }

    /// The client's handshake write keys.
    fn handshake_write(&mut self, p: &dyn Provider) {
        keys::change_cipher_state13(
            &mut self.c,
            p,
            abi::SSL3_CC_HANDSHAKE | abi::SSL3_CHANGE_CIPHER_CLIENT_WRITE,
            None,
        )
        .unwrap();
    }

    /// Reads EncryptedExtensions, Certificate, CertificateVerify, and Finished, checking the
    /// signature (with `cert`) and the Finished; returns the four messages.
    fn server_flight(&mut self, p: &dyn Provider, cert: &[u8]) -> Vec<Vec<u8>> {
        use crate::consts::handshake as ht;
        let ee = self.message(p);
        assert_eq!(ee[0], ht::ENCRYPTED_EXTENSIONS);
        self.c.hs.transcript.add(&ee);
        let mut flight = vec![ee];
        let mut th = Vec::new();
        loop {
            let m = self.message(p);
            match m[0] {
                ht::CERTIFICATE_REQUEST | ht::CERTIFICATE => {
                    self.c.hs.transcript.add(&m);
                    th = self.c.hs.transcript.current().unwrap();
                }
                ht::CERTIFICATE_VERIFY => {
                    let scheme = u16::from_be_bytes([m[4], m[5]]);
                    let sig = &m[8..];
                    let mut tbs = vec![0x20; 64];
                    tbs.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
                    tbs.extend_from_slice(&th);
                    assert!(p.verify(cert, scheme, &tbs, sig).unwrap(), "the signature");
                    self.c.hs.transcript.add(&m);
                }
                ht::FINISHED => {
                    let want = finished::final_finish_mac(&self.c, p, true).unwrap();
                    assert_eq!(&m[4..], &want[..], "the server's Finished");
                    self.c.hs.transcript.add(&m);
                    flight.push(m);
                    return flight;
                }
                other => panic!("unexpected message {other}"),
            }
            flight.push(m);
        }
    }

    /// A handshake message of the client's, protected, added to the transcript.
    fn send(&mut self, p: &dyn Provider, typ: u8, body: &[u8]) -> Vec<u8> {
        let msg = crate::msgs::frame(typ, body).unwrap();
        self.c.hs.transcript.add(&msg);
        self.c
            .write_record(p, record::content_type::handshake(), &msg)
            .unwrap();
        self.c.take_output()
    }

    /// The application keys after the server's Finished: reading the server's, and (after
    /// the client's Finished) writing.
    fn application_read(&mut self, p: &dyn Provider) {
        keys::generate_master_secret(&mut self.c, p).unwrap();
        keys::store_server_finished_hash(&mut self.c).unwrap();
        keys::change_cipher_state13(
            &mut self.c,
            p,
            abi::SSL3_CC_APPLICATION | abi::SSL3_CHANGE_CIPHER_CLIENT_READ,
            None,
        )
        .unwrap();
    }

    /// See [`Client::application_read`].
    fn application_write(&mut self, p: &dyn Provider) {
        keys::change_cipher_state13(
            &mut self.c,
            p,
            abi::SSL3_CC_APPLICATION | abi::SSL3_CHANGE_CIPHER_CLIENT_WRITE,
            None,
        )
        .unwrap();
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

/// A ClientHello built from its parts (TLS 1.3 unless changed).
#[derive(Clone)]
struct Hello {
    legacy_version: u16,
    random: [u8; 32],
    session_id: Vec<u8>,
    ciphers: Vec<u16>,
    exts: Vec<(u16, Vec<u8>)>,
}

impl Hello {
    /// A TLS 1.3 ClientHello with these groups and shares.
    fn tls13(groups: &[u16], shares: &[(u16, Vec<u8>)]) -> Self {
        use crate::msgs::ext as mx;
        let entries: Vec<mx::key_share::Entry> = shares
            .iter()
            .map(|(g, k)| mx::key_share::Entry {
                group: *g,
                key: k.clone(),
            })
            .collect();
        Self {
            legacy_version: v::TLS1_2,
            random: [0x11; 32],
            session_id: Vec::new(),
            ciphers: vec![0x1301],
            exts: vec![
                (
                    t::SUPPORTED_VERSIONS,
                    mx::supported_versions::encode_client(&[v::TLS1_3]).unwrap(),
                ),
                (
                    t::SUPPORTED_GROUPS,
                    mx::supported_groups::encode(groups).unwrap(),
                ),
                (
                    t::KEY_SHARE,
                    mx::key_share::encode_client(&entries).unwrap(),
                ),
                (
                    t::SIGNATURE_ALGORITHMS,
                    mx::signature_algorithms::encode(&[
                        sigscheme::RSA_PSS_RSAE_SHA256,
                        sigscheme::ECDSA_SECP256R1_SHA256,
                        sigscheme::ED25519,
                    ])
                    .unwrap(),
                ),
            ],
        }
    }

    /// With extension `typ` set to `body` (replaced, or added at the end).
    fn with(mut self, typ: u16, body: Vec<u8>) -> Self {
        match self.exts.iter_mut().find(|e| e.0 == typ) {
            Some(e) => e.1 = body,
            None => self.exts.push((typ, body)),
        }
        self
    }

    /// Without extension `typ`.
    fn without(mut self, typ: u16) -> Self {
        self.exts.retain(|e| e.0 != typ);
        self
    }

    /// The message, with its header.
    fn msg(&self) -> Vec<u8> {
        let exts: Vec<_> = self
            .exts
            .iter()
            .map(|(t, b)| crate::msgs::ext::Extension::new(*t, b.clone()))
            .collect();
        let body = crate::msgs::hello::ClientHello {
            legacy_version: self.legacy_version,
            random: self.random,
            session_id: self.session_id.clone(),
            cookie: None,
            cipher_suites: self.ciphers.iter().flat_map(|c| c.to_be_bytes()).collect(),
            compression_methods: vec![0],
            extensions: Some(crate::msgs::ext::encode_contents(&exts).unwrap()),
            extensions_offset: 0,
            sslv2: false,
        }
        .encode()
        .unwrap();
        crate::msgs::frame(crate::consts::handshake::CLIENT_HELLO, &body).unwrap()
    }
}

/// The server's key share in a ServerHello.
fn server_share(sh: &[u8]) -> (u16, Vec<u8>) {
    let parsed = crate::msgs::hello::ServerHello::parse(&sh[4..], true).unwrap();
    let e = parsed
        .extensions()
        .unwrap()
        .into_iter()
        .find(|e| e.typ == t::KEY_SHARE)
        .unwrap();
    let entry = crate::msgs::ext::key_share::parse_server(&e.body).unwrap();
    (entry.group, entry.key)
}

/// The first record's payload in `out` (a plaintext ServerHello).
fn first_record(out: &[u8]) -> Vec<u8> {
    let n = usize::from(out[3]) << 8 | usize::from(out[4]);
    out[5..5 + n].to_vec()
}

/// Steps `c`, answering its requests with `answer`, until it needs input or finishes.
fn drive_answering(
    c: &mut Connection,
    p: &dyn Provider,
    answer: &mut dyn FnMut(&Request) -> crate::conn::Answer,
) -> (Vec<u8>, crate::error::Result<Event>) {
    let mut out = Vec::new();
    loop {
        let (o, e) = drive(c, p);
        out.extend(o);
        match e {
            Ok(Event::Request(r)) => {
                let a = answer(&r);
                c.answer(a);
            }
            other => return (out, other),
        }
    }
}

/// The TLS alert record at the end of `out`: its level and description.
fn last_alert(out: &[u8]) -> (u8, u8) {
    assert!(out.len() >= 7, "an alert");
    let a = &out[out.len() - 7..];
    assert_eq!(a[0], 21, "an alert record: {out:02x?}");
    (a[5], a[6])
}

/// Feeds `msgs` to a fresh server in plaintext records, and expects it to fail with `alert`
/// and `reason`.
fn expect_failure(cfg: Config, p: &TestProvider, msgs: &[Vec<u8>], alert: c_int, reason: c_int) {
    let mut c = Connection::new(cfg);
    for m in msgs {
        c.feed(&plain_record(22, m));
    }
    let (out, last) = drive(&mut c, p);
    assert_eq!(last.unwrap_err(), Error::alert(alert, reason));
    assert_eq!(last_alert(&out).1, octet(alert));
}

/// A full TLS 1.3 handshake with the scripted client, up to the server's flight checked: the
/// server, the client, and the flight.
fn handshake13(
    p: &TestProvider,
    cfg: Config,
    ch: impl Fn(Vec<u8>) -> Hello,
) -> (Connection, Client, Vec<Vec<u8>>) {
    let mut c = Connection::new(cfg);
    let x = p.key_share(group::X25519).unwrap();
    let hello = ch(x.public().to_vec());
    c.feed(&plain_record(22, &hello.msg()));
    let (out, last) = drive(&mut c, p);
    assert_eq!(last.unwrap(), Event::NeedInput);
    let mut client = Client::new();
    let (_, sk) = server_share(&first_record(&out));
    let shared = x.derive(&sk).unwrap();
    client.hello(p, &out, &[hello.msg()], shared.bytes());
    let cert = c.cfg.certs[0].chain[0].clone();
    let flight = client.server_flight(p, &cert);
    (c, client, flight)
}

/// A plain X25519 ClientHello.
fn x25519_hello(share: Vec<u8>) -> Hello {
    Hello::tls13(&[group::X25519], &[(group::X25519, share)])
}

#[test]
fn rfc8448_hello_retry_request() {
    let p = TestProvider::new(b"rfc8448-hrr");
    let mut cfg = server_config(&p);
    cfg.groups = vec![group::SECP256R1];
    cfg.key_share_groups = vec![group::SECP256R1];
    cfg.group_tuples = vec![0];
    let mut c = Connection::new(cfg);
    c.feed(&plain_record(22, rfc("5", "ClientHello", 0)));
    let (out, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::NeedInput);
    assert_eq!(c.state(), abi::TLS_ST_EARLY_DATA);
    assert_eq!(c.hs.sh.hrr, Hrr::Pending);
    // The RFC's HelloRetryRequest, without the cookie (which a stateful OpenSSL server
    // doesn't send), in OpenSSL's order.
    let hrr = first_record(&out);
    assert_eq!(hrr, openssl_order(rfc("5", "ServerHello", 0), &[t::COOKIE]));
    // The transcript starts again with ClientHello1's hash.
    let ch1_hash = crate::testprov::digest(HashAlg::Sha256, rfc("5", "ClientHello", 0));
    let mut want = crate::msgs::message_hash(&ch1_hash).unwrap();
    want.extend_from_slice(&hrr);
    assert_eq!(c.hs.transcript.buffered(), Some(&want[..]));
}

#[test]
fn hello_retry_request_then_handshake() {
    let p = TestProvider::new(b"hrr-full");
    let mut cfg = server_config(&p);
    cfg.groups = vec![group::SECP256R1];
    cfg.group_tuples = vec![0];
    let mut c = Connection::new(cfg);
    let x = p.key_share(group::X25519).unwrap();
    let groups = [group::X25519, group::SECP256R1];
    let ch1 = Hello::tls13(&groups, &[(group::X25519, x.public().to_vec())]);
    c.feed(&plain_record(22, &ch1.msg()));
    let (out, _) = drive(&mut c, &p);
    let hrr = first_record(&out);
    assert_eq!(&hrr[6..38], &crate::consts::HRR_RANDOM[..]);
    let ec = p.key_share(group::SECP256R1).unwrap();
    let ch2 = ch1.clone().with(
        t::KEY_SHARE,
        crate::msgs::ext::key_share::encode_client(&[crate::msgs::ext::key_share::Entry {
            group: group::SECP256R1,
            key: ec.public().to_vec(),
        }])
        .unwrap(),
    );
    c.feed(&plain_record(22, &ch2.msg()));
    let (out, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::NeedInput);
    let mut client = Client::new();
    let (g, server_key) = server_share(&first_record(&out));
    assert_eq!(g, group::SECP256R1);
    let shared = ec.derive(&server_key).unwrap();
    let mh =
        crate::msgs::message_hash(&crate::testprov::digest(HashAlg::Sha256, &ch1.msg())).unwrap();
    client.hello(&p, &out, &[mh, hrr, ch2.msg()], shared.bytes());
    let cert = c.cfg.certs[0].chain[0].clone();
    client.server_flight(&p, &cert);
    c.feed(&client.finished(&p));
    let (_, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::HandshakeDone);
    assert_eq!(c.hs.sh.hrr, Hrr::Complete);
    assert_eq!(c.neg.group, Some(group::SECP256R1));
}

#[test]
fn second_client_hello_must_keep_the_suite_and_send_the_share() {
    let p = TestProvider::new(b"hrr-bad");
    let mut cfg = server_config(&p);
    cfg.groups = vec![group::SECP256R1];
    cfg.group_tuples = vec![0];
    let x = p.key_share(group::X25519).unwrap();
    let groups = [group::X25519, group::SECP256R1];
    let ch1 = Hello::tls13(&groups, &[(group::X25519, x.public().to_vec())]);
    let mut ch2 = ch1.clone();
    ch2.ciphers = vec![0x1302];
    expect_failure(
        cfg.clone(),
        &p,
        &[ch1.msg(), ch2.msg()],
        abi::SSL_AD_ILLEGAL_PARAMETER,
        abi::SSL_R_BAD_CIPHER,
    );
    // Still the X25519 share, not the group asked for.
    expect_failure(
        cfg,
        &p,
        &[ch1.msg(), ch1.msg()],
        abi::SSL_AD_ILLEGAL_PARAMETER,
        abi::SSL_R_BAD_KEY_SHARE,
    );
}

/// A client certificate: an Ed25519 key's, registered with the provider.
fn client_cert(p: &TestProvider) -> (Vec<u8>, crate::crypto::KeyId) {
    let key = crate::testprov::keys::PrivateKey::ed25519(p);
    let der = key.public(p).unwrap().cert("client");
    (der, p.add_key(key))
}

/// The client's TLS 1.3 Certificate with these entries.
fn certificate13(chain: &[Vec<u8>]) -> Vec<u8> {
    let mut w = crate::codec::Writer::new();
    w.u8(0);
    let o = w.open(3);
    for c in chain {
        w.vec(3, c).unwrap();
        w.u16(0);
    }
    w.close(o).unwrap();
    w.into_bytes()
}

/// The client's TLS 1.3 CertificateVerify with Ed25519 key `key`.
fn client_cert_verify(p: &TestProvider, client: &Client, key: crate::crypto::KeyId) -> Vec<u8> {
    let mut tbs = vec![0x20; 64];
    tbs.extend_from_slice(b"TLS 1.3, client CertificateVerify\0");
    tbs.extend_from_slice(&client.c.hs.transcript.current().unwrap());
    let sig = p.sign(key, sigscheme::ED25519, &tbs).unwrap();
    crate::msgs::cert::CertificateVerify {
        scheme: Some(sigscheme::ED25519),
        signature: sig,
    }
    .encode()
    .unwrap()
}

#[test]
fn tls13_client_authentication() {
    use crate::consts::handshake as ht;
    let p = TestProvider::new(b"client-auth");
    let mut cfg = server_config(&p);
    cfg.verify_mode = abi::SSL_VERIFY_PEER | abi::SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    cfg.sid_ctx = b"ctx".to_vec();
    let (mut c, mut client, flight) = handshake13(&p, cfg, x25519_hello);
    // EncryptedExtensions, CertificateRequest (empty context, signature_algorithms),
    // Certificate, CertificateVerify, Finished.
    let cr = &flight[1];
    assert_eq!(cr[0], ht::CERTIFICATE_REQUEST);
    assert_eq!(cr[4], 0, "an empty context");
    let exts = crate::msgs::ext::split(&cr[7..]).unwrap();
    assert!(exts.iter().any(|e| e.typ == t::SIGNATURE_ALGORITHMS));
    client.application_read(&p);
    let (der, key) = client_cert(&p);
    let mut out = client.send(
        &p,
        ht::CERTIFICATE,
        &certificate13(std::slice::from_ref(&der)),
    );
    let cv = client_cert_verify(&p, &client, key);
    out.extend(client.send(&p, ht::CERTIFICATE_VERIFY, &cv));
    out.extend(client.finished(&p));
    c.feed(&out);
    let mut asked = Vec::new();
    let (_, last) = drive_answering(&mut c, &p, &mut |r| {
        asked.push(r.clone());
        crate::conn::Answer::Verified {
            result: 0,
            proceed: true,
            verified_chain: vec![der.clone()],
        }
    });
    assert_eq!(last.unwrap(), Event::HandshakeDone);
    assert_eq!(
        asked,
        [Request::Verify {
            chain: vec![der.clone()],
            rpk: false,
        }]
    );
    assert_eq!(c.neg.peer_chain, std::slice::from_ref(&der));
    assert_eq!(c.neg.session.peer_chain, [der]);
    assert_eq!(c.hs.sh.peer_sigalg, Some(sigscheme::ED25519));
}

/// A client-authenticating TLS 1.3 handshake up to the client's Certificate, which is
/// `chain`: the server, and the client's flight so far.
fn up_to_client_certificate(
    p: &TestProvider,
    vm: c_int,
    chain: &[Vec<u8>],
) -> (Connection, Vec<u8>) {
    let mut cfg = server_config(p);
    cfg.verify_mode = vm;
    let (c, mut client, _) = handshake13(p, cfg, x25519_hello);
    let out = client.send(
        p,
        crate::consts::handshake::CERTIFICATE,
        &certificate13(chain),
    );
    (c, out)
}

#[test]
fn client_certificate_required_and_verified() {
    let p = TestProvider::new(b"client-auth-fail");
    let vm = abi::SSL_VERIFY_PEER | abi::SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    // None sent, one required.
    let (mut c, out) = up_to_client_certificate(&p, vm, &[]);
    c.feed(&out);
    let (out, last) = drive(&mut c, &p);
    assert_eq!(
        last.unwrap_err(),
        Error::alert(
            abi::SSL_AD_CERTIFICATE_REQUIRED,
            abi::SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE
        )
    );
    assert!(!out.is_empty());
    // One sent, and verification fails: the error's alert.
    let (der, _) = client_cert(&p);
    let (mut c, out) = up_to_client_certificate(&p, vm, &[der]);
    c.feed(&out);
    let (_, last) = drive_answering(&mut c, &p, &mut |_| crate::conn::Answer::Verified {
        result: i64::from(abi::X509_V_ERR_CERT_HAS_EXPIRED),
        proceed: false,
        verified_chain: Vec::new(),
    });
    assert_eq!(
        last.unwrap_err(),
        Error::alert(
            abi::SSL_AD_CERTIFICATE_EXPIRED,
            abi::SSL_R_CERTIFICATE_VERIFY_FAILED
        )
    );
    assert_eq!(
        c.neg.verify_result,
        i64::from(abi::X509_V_ERR_CERT_HAS_EXPIRED)
    );
    // An optional certificate not sent: the Finished comes next.
    let (mut c, out) = up_to_client_certificate(&p, abi::SSL_VERIFY_PEER, &[]);
    c.feed(&out);
    let (_, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::NeedInput);
    assert_eq!(c.state(), abi::TLS_ST_SR_CERT);
}

#[test]
fn malformed_and_unexpected_client_hellos() {
    let p = TestProvider::new(b"bad-hellos");
    let cfg = server_config(&p);
    let x = p.key_share(group::X25519).unwrap();
    let good = x25519_hello(x.public().to_vec());
    // A Finished first.
    let fin = crate::msgs::frame(crate::consts::handshake::FINISHED, &[0; 32]).unwrap();
    expect_failure(
        cfg.clone(),
        &p,
        &[fin],
        abi::SSL_AD_UNEXPECTED_MESSAGE,
        abi::SSL_R_UNEXPECTED_MESSAGE,
    );
    // A truncated random.
    let short =
        crate::msgs::frame(crate::consts::handshake::CLIENT_HELLO, &[3, 3, 1, 2, 3]).unwrap();
    expect_failure(
        cfg.clone(),
        &p,
        &[short],
        abi::SSL_AD_DECODE_ERROR,
        abi::SSL_R_LENGTH_MISMATCH,
    );
    // TLS 1.3 needs signature_algorithms.
    expect_failure(
        cfg.clone(),
        &p,
        &[good.clone().without(t::SIGNATURE_ALGORITHMS).msg()],
        abi::TLS13_AD_MISSING_EXTENSION,
        abi::SSL_R_MISSING_SIGALGS_EXTENSION,
    );
    // No suite in common.
    let mut none = good.clone();
    none.ciphers = vec![0x1304];
    expect_failure(
        cfg.clone(),
        &p,
        &[none.msg()],
        abi::SSL_AD_HANDSHAKE_FAILURE,
        abi::SSL_R_NO_SHARED_CIPHER,
    );
    // A share for a group the client didn't list.
    let bad_share = Hello::tls13(&[group::SECP256R1], &[(group::X25519, x.public().to_vec())]);
    expect_failure(
        cfg.clone(),
        &p,
        &[bad_share.msg()],
        abi::SSL_AD_ILLEGAL_PARAMETER,
        abi::SSL_R_BAD_KEY_SHARE,
    );
    // A share that isn't a point.
    let not_a_point = Hello::tls13(&[group::SECP256R1], &[(group::SECP256R1, vec![4, 1, 2])]);
    expect_failure(
        cfg.clone(),
        &p,
        &[not_a_point.msg()],
        abi::SSL_AD_ILLEGAL_PARAMETER,
        abi::SSL_R_BAD_ECPOINT,
    );
    // A point that is on the curve but compressed (P-256's generator), which TLS 1.3 forbids.
    let mut compressed = vec![0x03];
    compressed.extend_from_slice(&[
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
    ]);
    let compressed = Hello::tls13(&[group::SECP256R1], &[(group::SECP256R1, compressed)]);
    expect_failure(
        cfg.clone(),
        &p,
        &[compressed.msg()],
        abi::SSL_AD_ILLEGAL_PARAMETER,
        abi::SSL_R_BAD_ECPOINT,
    );
    // Only TLS 1.3 enabled, and the client offers TLS 1.2.
    let mut only13 = cfg.clone();
    only13.min_version = v::TLS1_3;
    expect_failure(
        only13,
        &p,
        &[good.clone().without(t::SUPPORTED_VERSIONS).msg()],
        abi::SSL_AD_PROTOCOL_VERSION,
        abi::SSL_R_UNSUPPORTED_PROTOCOL,
    );
    // The null compression is required.
    let mut c = Connection::new(cfg.clone());
    let mut body = good.msg()[4..].to_vec();
    let at = 2 + 32 + 1 + 2 + 2;
    assert_eq!(&body[at..at + 2], &[1, 0]);
    body[at + 1] = 1;
    c.feed(&plain_record(22, &crate::msgs::frame(1, &body).unwrap()));
    let (_, last) = drive(&mut c, &p);
    assert_eq!(
        last.unwrap_err(),
        Error::alert(
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_R_REQUIRED_COMPRESSION_ALGORITHM_MISSING
        )
    );
    // A non-empty early_data.
    expect_failure(
        cfg,
        &p,
        &[good.with(t::EARLY_DATA, vec![0]).msg()],
        abi::SSL_AD_DECODE_ERROR,
        abi::SSL_R_BAD_EXTENSION,
    );
}

#[test]
fn callbacks_in_openssl_order() {
    use crate::conn::Answer;
    let p = TestProvider::new(b"callbacks");
    let mut cfg = server_config(&p);
    cfg.callbacks.client_hello = true;
    cfg.callbacks.servername = true;
    cfg.callbacks.alpn_select = true;
    cfg.callbacks.cert = true;
    let ch = |share: Vec<u8>| {
        x25519_hello(share)
            .with(
                t::SERVER_NAME,
                crate::msgs::ext::server_name::encode_client(b"example.com").unwrap(),
            )
            .with(
                t::ALPN,
                crate::msgs::ext::alpn::encode_client(&[b"h2".to_vec(), b"http/1.1".to_vec()])
                    .unwrap(),
            )
    };
    let mut c = Connection::new(cfg.clone());
    let x = p.key_share(group::X25519).unwrap();
    let hello = ch(x.public().to_vec());
    c.feed(&plain_record(22, &hello.msg()));
    let mut asked = Vec::new();
    let (out, last) = drive_answering(&mut c, &p, &mut |r| {
        asked.push(r.clone());
        match r {
            Request::Servername => Answer::Tlsext {
                ret: abi::SSL_TLSEXT_ERR_OK,
                alert: abi::SSL_AD_UNRECOGNIZED_NAME,
            },
            Request::AlpnSelect { .. } => Answer::Alpn(Some(b"h2".to_vec())),
            _ => Answer::Continue,
        }
    });
    assert_eq!(last.unwrap(), Event::NeedInput);
    let protos = crate::msgs::ext::alpn::parse_client(
        &crate::msgs::ext::alpn::encode_client(&[b"h2".to_vec(), b"http/1.1".to_vec()]).unwrap(),
    )
    .unwrap();
    // The client hello callback, the servername callback, ALPN (in TLS 1.3, while the
    // extensions are parsed), then the certificate callback.
    assert_eq!(
        asked,
        [
            Request::ClientHello,
            Request::Servername,
            Request::AlpnSelect { protos },
            Request::Cert
        ]
    );
    assert_eq!(c.neg.alpn.as_deref(), Some(&b"h2"[..]));
    assert_eq!(c.neg.servername.as_deref(), Some(&b"example.com"[..]));
    assert_eq!(c.neg.session.hostname.as_deref(), Some(&b"example.com"[..]));
    // EncryptedExtensions acknowledges the name and carries the protocol.
    let mut client = Client::new();
    let (_, sk) = server_share(&first_record(&out));
    let shared = x.derive(&sk).unwrap();
    client.hello(&p, &out, &[hello.msg()], shared.bytes());
    let cert = c.cfg.certs[0].chain[0].clone();
    let flight = client.server_flight(&p, &cert);
    let exts = crate::msgs::ext::split(&flight[0][6..]).unwrap();
    let types: Vec<u16> = exts.iter().map(|e| e.typ).collect();
    assert_eq!(types, [t::SERVER_NAME, t::SUPPORTED_GROUPS, t::ALPN]);
    // A refused protocol is no_application_protocol.
    let mut cfg = server_config(&p);
    cfg.callbacks.alpn_select = true;
    let mut c = Connection::new(cfg);
    c.feed(&plain_record(22, &hello.msg()));
    let (out, last) = drive_answering(&mut c, &p, &mut |_| Answer::Fail {
        alert: None,
        reason: 0,
    });
    assert_eq!(
        last.unwrap_err(),
        Error::alert(
            abi::SSL_AD_NO_APPLICATION_PROTOCOL,
            abi::SSL_R_NO_APPLICATION_PROTOCOL
        )
    );
    assert_eq!(last_alert(&out).1, 120);
    // A client hello callback that fails, with its alert.
    let mut cfg = server_config(&p);
    cfg.callbacks.client_hello = true;
    let mut c = Connection::new(cfg);
    c.feed(&plain_record(22, &hello.msg()));
    let (_, last) = drive_answering(&mut c, &p, &mut |_| Answer::Fail {
        alert: Some(octet(abi::SSL_AD_ACCESS_DENIED)),
        reason: 0,
    });
    assert_eq!(
        last.unwrap_err(),
        Error::alert(abi::SSL_AD_ACCESS_DENIED, abi::SSL_R_CALLBACK_FAILED)
    );
}

#[test]
fn key_update_after_the_handshake() {
    use crate::consts::handshake as ht;
    let p = TestProvider::new(b"key-update");
    let (mut c, mut client, _) = handshake13(&p, server_config(&p), x25519_hello);
    client.application_read(&p);
    let fin = client.finished(&p);
    client.application_write(&p);
    c.feed(&fin);
    let (out, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::HandshakeDone);
    client.input.extend_from_slice(&out);
    for _ in 0..2 {
        assert_eq!(client.message(&p)[0], ht::NEW_SESSION_TICKET);
    }
    // The client updates its keys and asks the server to do the same.
    let ku = crate::msgs::frame(ht::KEY_UPDATE, &[1]).unwrap();
    client
        .c
        .write_record(&p, record::content_type::handshake(), &ku)
        .unwrap();
    keys::update_key(&mut client.c, &p, true).unwrap();
    c.feed(&client.c.take_output());
    // Reading finds the handshake message and goes back into the state machine.
    assert_eq!(c.step(&p, true).unwrap(), Event::NeedInput);
    let (out, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::HandshakeDone);
    assert!(out.is_empty());
    // The reply goes out before the next write (`ssl3_write_bytes` runs the handshake for a
    // pending KeyUpdate).
    assert_eq!(c.hs.sh.key_update, abi::SSL_KEY_UPDATE_NOT_REQUESTED);
    c.start();
    let (out, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::HandshakeDone);
    assert_eq!(c.hs.sh.key_update, abi::SSL_KEY_UPDATE_NONE);
    client.input.extend_from_slice(&out);
    let reply = client.message(&p);
    assert_eq!(reply, [ht::KEY_UPDATE, 0, 0, 1, 0]);
    keys::update_key(&mut client.c, &p, false).unwrap();
    // Application data under the new keys.
    c.write_app(&p, b"ping").unwrap();
    client.input.extend_from_slice(&c.take_output());
    let (ty, data) = client.record(&p).unwrap();
    assert_eq!(ty, record::content_type::application_data());
    assert_eq!(data, b"ping");
    assert_eq!(super::state_ref(&c).unwrap().sent_tickets, 2);
}

#[test]
fn ticket_session_encoding_round_trips() {
    let s = crate::conn::Session {
        version: v::TLS1_3,
        cipher_id: 0x0300_1301,
        session_id: vec![1; 32],
        sid_ctx: b"ctx".to_vec(),
        master_key: vec![2; 32],
        ems: true,
        ticket: None,
        ticket_age_add: 7,
        ticket_lifetime_hint: 9,
        time: 1_700_000_000,
        timeout: -1,
        max_early_data: 16384,
        hostname: Some(b"a".to_vec()),
        alpn: None,
        peer_chain: vec![vec![3; 10], vec![4; 3]],
        peer_rpk: Some(vec![5; 4]),
        verify_result: 10,
        max_fragment_len_mode: 2,
        ext_flags: 1,
        ticket_appdata: Some(b"app".to_vec()),
        kex_group: 0x001d,
        srp_username: Some(b"user".to_vec()),
    };
    let enc = ticket::encode_session(&s).unwrap();
    assert_eq!(enc.first(), Some(&15));
    assert_eq!(ticket::decode_session(&enc), Some(s.clone()));
    assert_eq!(ticket::decode_session(&enc[..enc.len() - 1]), None);
    let mut over = enc.clone();
    over.push(0);
    assert_eq!(ticket::decode_session(&over), None);
    assert_eq!(ticket::decode_session(&[2]), None);
    // Each optional field alone, and none (format 1, the length the trace shows).
    for (appdata, rpk, srp, format) in [
        (false, false, false, 1),
        (true, false, false, 3),
        (false, true, false, 5),
        (false, false, true, 9),
    ] {
        let mut t = s.clone();
        if !appdata {
            t.ticket_appdata = None;
        }
        if !rpk {
            t.peer_rpk = None;
        }
        if !srp {
            t.srp_username = None;
        }
        let enc = ticket::encode_session(&t).unwrap();
        assert_eq!(enc.first(), Some(&format));
        assert_eq!(ticket::decode_session(&enc), Some(t));
    }
    let mut unknown = enc;
    if let Some(f) = unknown.first_mut() {
        *f |= 16;
    }
    assert_eq!(ticket::decode_session(&unknown), None);
}

#[test]
fn x509_errors_become_openssls_alerts() {
    use super::cert::x509err2alert;
    assert_eq!(
        x509err2alert(i64::from(abi::X509_V_ERR_CERT_REVOKED)),
        abi::SSL_AD_CERTIFICATE_REVOKED
    );
    assert_eq!(
        x509err2alert(i64::from(abi::X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)),
        abi::SSL_AD_UNKNOWN_CA
    );
    assert_eq!(x509err2alert(12345), abi::SSL_AD_CERTIFICATE_UNKNOWN);
}

#[test]
fn middlebox_compatibility_change_cipher_spec() {
    let p = TestProvider::new(b"middlebox");
    let mut cfg = server_config(&p);
    cfg.options |= abi::SSL_OP_ENABLE_MIDDLEBOX_COMPAT;
    let (mut c, mut client, _) = handshake13(&p, cfg, |share| {
        let mut h = x25519_hello(share);
        h.session_id = vec![0x5a; 32];
        h
    });
    // One ChangeCipherSpec, after the ServerHello; the session ID is echoed.
    assert_eq!(client.ccs, 1);
    assert_eq!(super::state_ref(&c).unwrap().tmp_session_id, [0x5a; 32]);
    client.application_read(&p);
    c.feed(&client.finished(&p));
    let (_, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::HandshakeDone);
}

#[test]
fn post_handshake_authentication() {
    use crate::consts::handshake as ht;
    let p = TestProvider::new(b"pha");
    let mut cfg = server_config(&p);
    cfg.verify_mode = abi::SSL_VERIFY_PEER | abi::SSL_VERIFY_POST_HANDSHAKE;
    let (mut c, mut client, flight) = handshake13(&p, cfg, |share| {
        x25519_hello(share).with(t::POST_HANDSHAKE_AUTH, Vec::new())
    });
    // No CertificateRequest during the handshake.
    assert!(flight.iter().all(|m| m[0] != ht::CERTIFICATE_REQUEST));
    assert_eq!(c.hs.sh.pha, Pha::ExtReceived);
    client.application_read(&p);
    let fin = client.finished(&p);
    client.application_write(&p);
    c.feed(&fin);
    let (out, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::HandshakeDone);
    client.input.extend_from_slice(&out);
    for _ in 0..2 {
        assert_eq!(client.message(&p)[0], ht::NEW_SESSION_TICKET);
    }
    // `SSL_verify_client_post_handshake`.
    c.hs.sh.pha = Pha::RequestPending;
    c.start();
    let (out, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::HandshakeDone);
    assert_eq!(c.hs.sh.pha, Pha::Requested);
    client.input.extend_from_slice(&out);
    let cr = client.message(&p);
    assert_eq!(cr[0], ht::CERTIFICATE_REQUEST);
    assert_eq!(cr[4], 32, "a 32-octet context");
    let context = cr[5..37].to_vec();
    assert_eq!(c.hs.sh.pha_context.as_deref(), Some(&context[..]));
    // The client answers: Certificate (with the context), CertificateVerify, and Finished
    // (keyed with its application secret), continuing from its Finished.
    client.c.hs.transcript.add(&cr);
    let (der, key) = client_cert(&p);
    let mut body = vec![32];
    body.extend_from_slice(&context);
    body.extend_from_slice(&certificate13(std::slice::from_ref(&der))[1..]);
    let mut out = client.send(&p, ht::CERTIFICATE, &body);
    let cv = client_cert_verify(&p, &client, key);
    out.extend(client.send(&p, ht::CERTIFICATE_VERIFY, &cv));
    let th = client.c.hs.transcript.current().unwrap();
    let md = crate::keysched::verify_data_13(
        &p,
        HashAlg::Sha256,
        client.c.hs.sh.keys.client_app_secret.bytes(),
        &th,
    )
    .unwrap();
    out.extend(client.send(&p, ht::FINISHED, &md));
    c.feed(&out);
    assert_eq!(c.step(&p, true).unwrap(), Event::NeedInput);
    let (out, last) = drive_answering(&mut c, &p, &mut |_| crate::conn::Answer::Verified {
        result: 0,
        proceed: true,
        verified_chain: Vec::new(),
    });
    assert_eq!(last.unwrap(), Event::HandshakeDone);
    assert_eq!(c.hs.sh.pha, Pha::ExtReceived);
    assert_eq!(c.neg.peer_chain, std::slice::from_ref(&der));
    // New tickets follow, for the session with the client's certificate.
    client.input.extend_from_slice(&out);
    for _ in 0..2 {
        assert_eq!(client.message(&p)[0], ht::NEW_SESSION_TICKET);
    }
    assert_eq!(c.neg.session.peer_chain, [der]);
}

/// A TLS 1.2 ClientHello offering `ciphers`, X25519 and P-256, the RSA schemes, Extended
/// Master Secret, the renegotiation SCSV, and an empty session ticket.
fn hello12(ciphers: &[u16]) -> Hello {
    use crate::msgs::ext as mx;
    let mut cs = ciphers.to_vec();
    cs.push(0x00ff);
    Hello {
        legacy_version: v::TLS1_2,
        random: [0x22; 32],
        session_id: Vec::new(),
        ciphers: cs,
        exts: vec![
            (
                t::SUPPORTED_GROUPS,
                mx::supported_groups::encode(&[group::X25519, group::SECP256R1]).unwrap(),
            ),
            (
                t::EC_POINT_FORMATS,
                mx::ec_point_formats::encode(&[0]).unwrap(),
            ),
            (
                t::SIGNATURE_ALGORITHMS,
                mx::signature_algorithms::encode(&[
                    sigscheme::RSA_PSS_RSAE_SHA256,
                    sigscheme::RSA_PKCS1_SHA256,
                ])
                .unwrap(),
            ),
            (t::EXTENDED_MASTER_SECRET, Vec::new()),
            (t::SESSION_TICKET, Vec::new()),
        ],
    }
}

/// A scripted TLS 1.2 client over a client-role connection's key schedule and record layer.
struct Client12 {
    c: Connection,
    input: Vec<u8>,
    hs: Vec<u8>,
    ccs: bool,
}

impl Client12 {
    fn new(hello: &Hello) -> Self {
        let mut c = Connection::new(Config::default());
        c.neg.version = v::TLS1_2;
        c.rw.version = v::TLS1_2;
        c.hs.transcript = crate::keysched::Transcript::new();
        c.hs.client_random = hello.random;
        c.hs.transcript.add(&hello.msg());
        Self {
            c,
            input: Vec::new(),
            hs: Vec::new(),
            ccs: false,
        }
    }

    /// The next handshake message (a ChangeCipherSpec turns the read keys on).
    fn message(&mut self, p: &dyn Provider) -> Option<Vec<u8>> {
        loop {
            if self.hs.len() >= 4 {
                let n = usize::from(self.hs[1]) << 16
                    | usize::from(self.hs[2]) << 8
                    | usize::from(self.hs[3]);
                if self.hs.len() >= 4 + n {
                    return Some(self.hs.drain(..4 + n).collect());
                }
            }
            match self.c.rr.read(p, &self.input).unwrap() {
                Read::NeedMore(_) => return None,
                Read::IgnoredCcs { .. } | Read::Skipped { .. } => panic!("TLS 1.2"),
                Read::Record { consumed, record } => {
                    self.input.drain(..consumed);
                    if record.content_type == record::content_type::change_cipher_spec() {
                        assert_eq!(record.data, [1]);
                        self.ccs = true;
                        keys::setup_key_block(&mut self.c, p).unwrap();
                        keys::change_cipher_state12(
                            &mut self.c,
                            p,
                            abi::SSL3_CHANGE_CIPHER_CLIENT_READ,
                        )
                        .unwrap();
                        continue;
                    }
                    assert_eq!(
                        record.content_type,
                        record::content_type::handshake(),
                        "{:02x?}",
                        record.data
                    );
                    self.hs.extend_from_slice(&record.data);
                }
            }
        }
    }

    /// Reads the ServerHello and the rest of the flight to ServerHelloDone (or, resuming, to
    /// the server's Finished, with any NewSessionTicket): the messages.
    fn server_flight(&mut self, p: &dyn Provider, out: &[u8]) -> Vec<Vec<u8>> {
        use crate::consts::handshake as ht;
        self.input.extend_from_slice(out);
        let mut msgs = Vec::new();
        while let Some(m) = self.message(p) {
            if m[0] == ht::SERVER_HELLO {
                self.c.hs.server_random.copy_from_slice(&m[6..38]);
                let sid = usize::from(m[38]);
                let cs = u16::from_be_bytes([m[39 + sid], m[40 + sid]]);
                self.c.hs.new_cipher = crate::suites::by_protocol_id(cs);
                self.c.hs.transcript.add(&m);
                let hash = keys::handshake_md(&self.c).unwrap();
                self.c.hs.transcript.start_hash(p, hash, false).unwrap();
            } else if m[0] == ht::FINISHED {
                let want = finished::final_finish_mac(&self.c, p, true).unwrap();
                assert_eq!(&m[4..], &want[..], "the server's Finished");
                self.c.hs.transcript.add(&m);
            } else {
                self.c.hs.transcript.add(&m);
            }
            msgs.push(m);
        }
        msgs
    }

    /// A plaintext or protected handshake message, added to the transcript.
    fn send(&mut self, p: &dyn Provider, typ: u8, body: &[u8]) -> Vec<u8> {
        let msg = crate::msgs::frame(typ, body).unwrap();
        self.c.hs.transcript.add(&msg);
        self.c
            .write_record(p, record::content_type::handshake(), &msg)
            .unwrap();
        self.c.take_output()
    }

    /// ChangeCipherSpec and Finished, after the master secret is known (or resumed).
    fn ccs_finished(&mut self, p: &dyn Provider) -> Vec<u8> {
        self.c
            .write_record(p, record::content_type::change_cipher_spec(), &[1])
            .unwrap();
        keys::setup_key_block(&mut self.c, p).unwrap();
        keys::change_cipher_state12(&mut self.c, p, abi::SSL3_CHANGE_CIPHER_CLIENT_WRITE).unwrap();
        let md = finished::final_finish_mac(&self.c, p, false).unwrap();
        self.c.neg.client_finished.clone_from(&md);
        let mut out = self.c.take_output();
        out.extend(self.send(p, crate::consts::handshake::FINISHED, &md));
        out
    }

    /// The master secret from `pms` (with Extended Master Secret when `ems`).
    fn master(&mut self, p: &dyn Provider, pms: &[u8], ems: bool) {
        self.c.neg.ems = ems;
        keys::generate_master_secret12(&mut self.c, p, pms).unwrap();
    }
}

/// The ServerKeyExchange's ECDHE point, after checking its signature with `cert`.
fn ske_point(client: &Client12, p: &dyn Provider, ske: &[u8], cert: &[u8]) -> (u16, Vec<u8>) {
    let body = &ske[4..];
    assert_eq!(body[0], 3, "a named curve");
    let curve = u16::from_be_bytes([body[1], body[2]]);
    let n = usize::from(body[3]);
    let params = &body[..4 + n];
    let point = body[4..4 + n].to_vec();
    let scheme = u16::from_be_bytes([body[4 + n], body[5 + n]]);
    let sig = &body[8 + n..];
    let mut tbs = client.c.hs.client_random.to_vec();
    tbs.extend_from_slice(&client.c.hs.server_random);
    tbs.extend_from_slice(params);
    assert!(
        p.verify(cert, scheme, &tbs, sig).unwrap(),
        "the ServerKeyExchange signature"
    );
    (curve, point)
}

/// A TLS 1.2 ECDHE-RSA handshake to the end: the server, the client, and the server's last
/// flight (NewSessionTicket, ChangeCipherSpec, Finished).
fn handshake12(
    p: &TestProvider,
    cfg: Config,
    hello: &Hello,
) -> (Connection, Client12, Vec<Vec<u8>>) {
    use crate::consts::handshake as ht;
    let mut c = Connection::new(cfg);
    c.feed(&plain_record(22, &hello.msg()));
    let (out, last) = drive(&mut c, p);
    assert_eq!(last.unwrap(), Event::NeedInput);
    let mut client = Client12::new(hello);
    let flight = client.server_flight(p, &out);
    let types: Vec<u8> = flight.iter().map(|m| m[0]).collect();
    assert_eq!(
        types,
        [
            ht::SERVER_HELLO,
            ht::CERTIFICATE,
            ht::SERVER_KEY_EXCHANGE,
            ht::SERVER_HELLO_DONE
        ]
    );
    let cert = c.cfg.certs[0].chain[0].clone();
    let (curve, point) = ske_point(&client, p, &flight[2], &cert);
    assert_eq!(curve, group::X25519);
    let share = p.key_share(curve).unwrap();
    let public = share.public().to_vec();
    let pms = share.derive(&point).unwrap();
    let mut out = client.send(p, ht::CLIENT_KEY_EXCHANGE, &{
        let mut b = vec![u8::try_from(public.len()).unwrap()];
        b.extend_from_slice(&public);
        b
    });
    client.master(p, pms.bytes(), true);
    out.extend(client.ccs_finished(p));
    c.feed(&out);
    let (out, last) = drive(&mut c, p);
    assert_eq!(last.unwrap(), Event::HandshakeDone);
    let last_flight = client.server_flight(p, &out);
    assert!(client.ccs);
    (c, client, last_flight)
}

#[test]
fn tls12_ecdhe_rsa_handshake_with_ticket() {
    use crate::consts::handshake as ht;
    let p = TestProvider::new(b"tls12");
    let hello = hello12(&[0xc02f]);
    let (c, client, last) = handshake12(&p, server_config(&p), &hello);
    // The server answered renegotiation_info (for the SCSV), ec_point_formats, the empty
    // session_ticket, and Extended Master Secret, in OpenSSL's order.
    let types: Vec<u8> = last.iter().map(|m| m[0]).collect();
    assert_eq!(types, [ht::NEW_SESSION_TICKET, ht::FINISHED]);
    assert_eq!(c.neg.version, v::TLS1_2);
    assert_eq!(c.neg.cipher.map(|x| x.protocol_id()), Some(0xc02f));
    assert!(c.neg.ems);
    assert!(c.neg.secure_renegotiation);
    assert_eq!(c.neg.master_secret, client.c.neg.master_secret);
    // The ticket: a lifetime hint, and OpenSSL's format under the configured key name.
    let nst = &last[0];
    let crate::msgs::misc::NewSessionTicket::Tls12(t) =
        crate::msgs::misc::NewSessionTicket::parse(&nst[4..], false).unwrap()
    else {
        panic!("a TLS 1.2 ticket");
    };
    assert_eq!(t.lifetime_hint, 7200);
    assert_eq!(&t.ticket[..16], &[7; 16]);
}

#[test]
fn tls12_server_hello_extensions_in_openssl_order() {
    let p = TestProvider::new(b"tls12-sh");
    let mut c = Connection::new(server_config(&p));
    c.feed(&plain_record(22, &hello12(&[0xc02f]).msg()));
    let (out, _) = drive(&mut c, &p);
    let sh = first_record(&out);
    let parsed = crate::msgs::hello::ServerHello::parse(&sh[4..], false).unwrap();
    let types: Vec<u16> = parsed.extensions().unwrap().iter().map(|e| e.typ).collect();
    assert_eq!(
        types,
        [
            t::RENEGOTIATE,
            t::EC_POINT_FORMATS,
            t::SESSION_TICKET,
            t::EXTENDED_MASTER_SECRET
        ]
    );
    // A ticket is coming, so no session ID (`ssl_generate_session_id`); without the
    // session_ticket extension a new session gets one, as the server caches sessions.
    assert!(parsed.session_id.is_empty());
    let mut c = Connection::new(server_config(&p));
    c.feed(&plain_record(
        22,
        &hello12(&[0xc02f]).without(t::SESSION_TICKET).msg(),
    ));
    let (out, _) = drive(&mut c, &p);
    let parsed = crate::msgs::hello::ServerHello::parse(&first_record(&out)[4..], false).unwrap();
    assert_eq!(parsed.session_id.len(), 32);
    assert_eq!(parsed.session_id, c.neg.session.session_id);
}

#[test]
fn tls12_resumes_a_ticket_and_a_cached_session() {
    use crate::consts::handshake as ht;
    let p = TestProvider::new(b"tls12-resume");
    let hello = hello12(&[0xc02f]);
    let (c1, client1, last) = handshake12(&p, server_config(&p), &hello);
    let crate::msgs::misc::NewSessionTicket::Tls12(t) =
        crate::msgs::misc::NewSessionTicket::parse(&last[0][4..], false).unwrap()
    else {
        panic!("a TLS 1.2 ticket");
    };
    // Resumption with the ticket: an abbreviated handshake.
    let mut again = hello.clone().with(t::SESSION_TICKET, t.ticket.clone());
    again.random = [0x33; 32];
    again.session_id = vec![0x44; 32];
    let mut c = Connection::new(server_config(&p));
    c.feed(&plain_record(22, &again.msg()));
    let (out, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::NeedInput);
    assert!(c.neg.reused);
    let mut client = Client12::new(&again);
    client
        .c
        .neg
        .master_secret
        .clone_from(&client1.c.neg.master_secret);
    client.c.neg.ems = true;
    let flight = client.server_flight(&p, &out);
    let types: Vec<u8> = flight.iter().map(|m| m[0]).collect();
    assert_eq!(types, [ht::SERVER_HELLO, ht::FINISHED]);
    // The client's session ID is echoed.
    assert_eq!(&flight[0][39..71], &[0x44; 32]);
    c.feed(&client.ccs_finished(&p));
    let (_, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::HandshakeDone);
    assert_eq!(c.neg.master_secret, c1.neg.master_secret);

    // Resumption by session ID: the cache gives the session (made without a ticket).
    let plain = hello.clone().without(t::SESSION_TICKET);
    let (c2, client2, _) = handshake12(&p, server_config(&p), &plain);
    let session = c2.neg.session.clone();
    assert_eq!(session.session_id.len(), 32);
    let mut by_id = plain.clone();
    by_id.random = [0x55; 32];
    by_id.session_id = session.session_id.clone();
    let mut cfg = server_config(&p);
    cfg.options |= abi::SSL_OP_NO_TICKET;
    let mut c = Connection::new(cfg);
    c.feed(&plain_record(22, &by_id.msg()));
    let mut asked = Vec::new();
    let (out, last) = drive_answering(&mut c, &p, &mut |r| {
        asked.push(r.clone());
        crate::conn::Answer::Session(Some(session.clone()))
    });
    assert_eq!(last.unwrap(), Event::NeedInput);
    assert_eq!(
        asked,
        [Request::GetSession {
            id: session.session_id.clone()
        }]
    );
    assert!(c.neg.reused);
    let mut client = Client12::new(&by_id);
    client
        .c
        .neg
        .master_secret
        .clone_from(&client2.c.neg.master_secret);
    client.c.neg.ems = true;
    let flight = client.server_flight(&p, &out);
    assert_eq!(flight.len(), 2);
    assert_eq!(&flight[0][39..71], &session.session_id[..]);
    c.feed(&client.ccs_finished(&p));
    let (_, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::HandshakeDone);

    // A session without Extended Master Secret isn't resumed by a client that sends it.
    let mut old = session;
    old.ems = false;
    let mut c = Connection::new(server_config(&p));
    c.feed(&plain_record(22, &by_id.msg()));
    let (_, last) = drive_answering(&mut c, &p, &mut |_| {
        crate::conn::Answer::Session(Some(old.clone()))
    });
    assert_eq!(last.unwrap(), Event::NeedInput);
    assert!(!c.neg.reused);
}

#[test]
fn tls12_rsa_and_dhe_key_exchanges() {
    use crate::consts::handshake as ht;
    let p = TestProvider::new(b"tls12-kx");
    // RSA: the client's secret, encrypted to the certificate.
    let hello = hello12(&[0x009c]);
    let mut c = Connection::new(server_config(&p));
    c.feed(&plain_record(22, &hello.msg()));
    let (out, _) = drive(&mut c, &p);
    let mut client = Client12::new(&hello);
    let flight = client.server_flight(&p, &out);
    let types: Vec<u8> = flight.iter().map(|m| m[0]).collect();
    assert_eq!(
        types,
        [ht::SERVER_HELLO, ht::CERTIFICATE, ht::SERVER_HELLO_DONE]
    );
    let cert = c.cfg.certs[0].chain[0].clone();
    let mut pms = vec![3, 3];
    pms.extend_from_slice(&[0x5c; 46]);
    let enc = p.rsa_encrypt(&cert, &pms).unwrap();
    let mut body = Vec::new();
    body.extend_from_slice(&u16::try_from(enc.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&enc);
    let mut out = client.send(&p, ht::CLIENT_KEY_EXCHANGE, &body);
    client.master(&p, &pms, true);
    out.extend(client.ccs_finished(&p));
    c.feed(&out);
    let (out, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::HandshakeDone);
    client.server_flight(&p, &out);
    assert_eq!(c.neg.master_secret, client.c.neg.master_secret);

    // DHE with SSL_set_dh_auto: the RSA key's 112 bits give RFC 3526's 2048-bit prime.
    let hello = hello12(&[0x009e]);
    let mut cfg = server_config(&p);
    cfg.dh_auto = true;
    cfg.dh_tmp = true;
    let mut c = Connection::new(cfg);
    c.feed(&plain_record(22, &hello.msg()));
    let (out, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::NeedInput);
    let mut client = Client12::new(&hello);
    let flight = client.server_flight(&p, &out);
    assert_eq!(flight[2][0], ht::SERVER_KEY_EXCHANGE);
    let mut rd = crate::codec::Reader::new(&flight[2][4..]);
    let dp = rd.vec16().unwrap().rest().to_vec();
    let dg = rd.vec16().unwrap().rest().to_vec();
    let ys = rd.vec16().unwrap().rest().to_vec();
    assert_eq!(
        dp.len(),
        128,
        "RFC 3526's 2048-bit prime: the RSA key's 80 bits round up"
    );
    assert_eq!(dg, [2]);
    assert_eq!(
        ys.len(),
        dp.len(),
        "the public value padded to the prime's length"
    );
    let share = p.dh_share(&dp, &dg).unwrap();
    let public = share.public().to_vec();
    let secret = share.derive(&ys).unwrap();
    let pms = strip_zeros(secret.bytes());
    let mut body = Vec::new();
    body.extend_from_slice(&u16::try_from(public.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&public);
    let mut out = client.send(&p, ht::CLIENT_KEY_EXCHANGE, &body);
    client.master(&p, pms, true);
    out.extend(client.ccs_finished(&p));
    c.feed(&out);
    let (_, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::HandshakeDone);
}

fn strip_zeros(b: &[u8]) -> &[u8] {
    let n = b.iter().take_while(|&&x| x == 0).count();
    &b[n..]
}

#[test]
fn tls12_handshake_message_is_not_a_change_cipher_spec() {
    use crate::consts::handshake as ht;
    let p = TestProvider::new(b"hr-ccs");
    let hello = hello12(&[0xc02f]);
    let mut c = Connection::new(server_config(&p));
    c.feed(&plain_record(22, &hello.msg()));
    let (out, _) = drive(&mut c, &p);
    let mut client = Client12::new(&hello);
    let flight = client.server_flight(&p, &out);
    let cert = c.cfg.certs[0].chain[0].clone();
    let (curve, point) = ske_point(&client, &p, &flight[2], &cert);
    let share = p.key_share(curve).unwrap();
    let public = share.public().to_vec();
    let mut b = vec![u8::try_from(public.len()).unwrap()];
    b.extend_from_slice(&public);
    let mut out = client.send(&p, ht::CLIENT_KEY_EXCHANGE, &b);
    // A HelloRequest (type 0, as the CCS pseudo-type becomes) where the ChangeCipherSpec
    // must come.
    client
        .c
        .write_record(&p, record::content_type::handshake(), &[0, 0, 0, 0])
        .unwrap();
    out.extend(client.c.take_output());
    let _ = point;
    c.feed(&out);
    let (_, last) = drive(&mut c, &p);
    assert_eq!(
        last.unwrap_err(),
        Error::alert(
            abi::SSL_AD_UNEXPECTED_MESSAGE,
            abi::SSL_R_UNEXPECTED_MESSAGE
        )
    );
}

/// After a TLS 1.2 handshake, a renegotiating ClientHello under the handshake's keys.
fn renegotiate(
    p: &TestProvider,
    options: u64,
    hello: impl Fn(&Client12) -> Hello,
) -> (Connection, Vec<u8>, crate::error::Result<Event>) {
    let first = hello12(&[0xc02f]);
    let mut cfg = server_config(p);
    cfg.options |= options;
    let (mut c, mut client, _) = handshake12(p, cfg, &first);
    let h = hello(&client);
    let msg = h.msg();
    client
        .c
        .write_record(p, record::content_type::handshake(), &msg)
        .unwrap();
    c.feed(&client.c.take_output());
    assert_eq!(c.step(p, true).unwrap(), Event::NeedInput);
    let (out, last) = drive(&mut c, p);
    (c, out, last)
}

#[test]
fn tls12_client_renegotiation_refused_by_default() {
    let p = TestProvider::new(b"reneg-refused");
    let (c, out, last) = renegotiate(&p, 0, |client| {
        no_scsv(hello12(&[0xc02f])).with(
            t::RENEGOTIATE,
            crate::msgs::ext::renegotiate::encode(&client.c.neg.client_finished).unwrap(),
        )
    });
    // A warning no_renegotiation, and the connection carries on.
    assert_eq!(last.unwrap(), Event::HandshakeDone);
    assert!(!out.is_empty());
    assert!(c.error().is_none());
    assert_eq!(c.state(), abi::TLS_ST_OK);
    assert_eq!(c.alerts().0, Some((1, 100)));
}

#[test]
fn a_client_renegotiation_asks_for_fresh_settings() {
    let p = TestProvider::new(b"reneg-refresh");
    let mut cfg = server_config(&p);
    cfg.options |= abi::SSL_OP_ALLOW_CLIENT_RENEGOTIATION;
    cfg.callbacks.renegotiating = true;
    let (mut c, mut client, _) = handshake12(&p, cfg, &hello12(&[0xc02f]));
    let h = no_scsv(hello12(&[0xc02f])).with(
        t::RENEGOTIATE,
        crate::msgs::ext::renegotiate::encode(&client.c.neg.client_finished).unwrap(),
    );
    client
        .c
        .write_record(&p, record::content_type::handshake(), &h.msg())
        .unwrap();
    c.feed(&client.c.take_output());
    assert_eq!(c.step(&p, true).unwrap(), Event::NeedInput);
    let (_, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::Request(Request::Renegotiating));
    // Renegotiation turned off since the first handshake: the server now refuses it.
    c.config_mut().options |= abi::SSL_OP_NO_RENEGOTIATION;
    c.answer(crate::conn::Answer::Continue);
    let (out, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::HandshakeDone);
    assert!(!out.is_empty());
    assert_eq!(c.alerts().0, Some((1, 100)));
}

#[test]
fn cve_2021_3449_renegotiation_without_signature_algorithms() {
    // OpenSSL 1.1.1h-j crashed on a renegotiating ClientHello that left out
    // signature_algorithms but kept signature_algorithms_cert: the old list was freed, its
    // length kept. Here each handshake starts with no peer list, and the server finds none
    // shared.
    let p = TestProvider::new(b"cve-2021-3449");
    let (c, out, last) = renegotiate(&p, abi::SSL_OP_ALLOW_CLIENT_RENEGOTIATION, |client| {
        no_scsv(hello12(&[0xc02f]))
            .without(t::SIGNATURE_ALGORITHMS)
            .with(
                t::SIGNATURE_ALGORITHMS_CERT,
                crate::msgs::ext::signature_algorithms::encode(&[sigscheme::RSA_PKCS1_SHA256])
                    .unwrap(),
            )
            .with(
                t::RENEGOTIATE,
                crate::msgs::ext::renegotiate::encode(&client.c.neg.client_finished).unwrap(),
            )
    });
    assert_eq!(
        last.unwrap_err(),
        Error::alert(
            abi::SSL_AD_HANDSHAKE_FAILURE,
            abi::SSL_R_NO_SHARED_SIGNATURE_ALGORITHMS
        )
    );
    assert!(!out.is_empty());
    assert!(c.hs.sh.peer_sigalgs.is_none());
}

#[test]
fn tls12_renegotiation_binding_must_match() {
    let p = TestProvider::new(b"reneg-binding");
    let (_, _, last) = renegotiate(&p, abi::SSL_OP_ALLOW_CLIENT_RENEGOTIATION, |_| {
        no_scsv(hello12(&[0xc02f])).with(
            t::RENEGOTIATE,
            crate::msgs::ext::renegotiate::encode(&[0; 12]).unwrap(),
        )
    });
    assert_eq!(
        last.unwrap_err(),
        Error::alert(
            abi::SSL_AD_HANDSHAKE_FAILURE,
            abi::SSL_R_RENEGOTIATION_MISMATCH
        )
    );
    // The SCSV is refused while renegotiating.
    let (_, _, last) = renegotiate(&p, abi::SSL_OP_ALLOW_CLIENT_RENEGOTIATION, |_| {
        hello12(&[0xc02f])
    });
    assert_eq!(
        last.unwrap_err(),
        Error::alert(
            abi::SSL_AD_HANDSHAKE_FAILURE,
            abi::SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING
        )
    );
    // Without the binding at all: unsafe legacy renegotiation.
    let (_, _, last) = renegotiate(&p, abi::SSL_OP_ALLOW_CLIENT_RENEGOTIATION, |_| {
        no_scsv(hello12(&[0xc02f]))
    });
    assert_eq!(
        last.unwrap_err(),
        Error::alert(
            abi::SSL_AD_HANDSHAKE_FAILURE,
            abi::SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED
        )
    );
}

/// A ClientHello without the renegotiation SCSV.
fn no_scsv(mut h: Hello) -> Hello {
    h.ciphers.retain(|&c| c != 0x00ff);
    h
}

/// The client's OCSP status request (no responder IDs or extensions).
fn ocsp_request() -> Vec<u8> {
    crate::msgs::ext::status_request::encode(&crate::msgs::ext::status_request::Request::Ocsp {
        responder_ids: Vec::new(),
        extensions: Vec::new(),
    })
    .unwrap()
}

#[test]
fn ocsp_stapling_tls12_and_tls13() {
    use crate::conn::Answer;
    use crate::consts::handshake as ht;
    let p = TestProvider::new(b"ocsp");
    let mut cfg = server_config(&p);
    cfg.callbacks.status = true;
    let response = b"an OCSP response".to_vec();
    // TLS 1.2: a CertificateStatus after the Certificate, and an empty status_request.
    let hello = hello12(&[0xc02f]).with(t::STATUS_REQUEST, ocsp_request());
    let mut c = Connection::new(cfg.clone());
    c.feed(&plain_record(22, &hello.msg()));
    let (out, last) = drive_answering(&mut c, &p, &mut |r| {
        assert!(matches!(r, Request::Status { .. }));
        Answer::Status {
            ret: abi::SSL_TLSEXT_ERR_OK,
            response: Some(response.clone()),
        }
    });
    assert_eq!(last.unwrap(), Event::NeedInput);
    let mut client = Client12::new(&hello);
    let flight = client.server_flight(&p, &out);
    let types: Vec<u8> = flight.iter().map(|m| m[0]).collect();
    assert_eq!(
        types,
        [
            ht::SERVER_HELLO,
            ht::CERTIFICATE,
            ht::CERTIFICATE_STATUS,
            ht::SERVER_KEY_EXCHANGE,
            ht::SERVER_HELLO_DONE
        ]
    );
    let status = crate::msgs::cert::CertificateStatus::parse(&flight[2][4..]).unwrap();
    assert_eq!(status.response, response);
    let sh = crate::msgs::hello::ServerHello::parse(&flight[0][4..], false).unwrap();
    let e = sh.extensions().unwrap();
    assert!(
        e.iter()
            .any(|x| x.typ == t::STATUS_REQUEST && x.body.is_empty())
    );
    // The callback declines: nothing stapled.
    let mut c = Connection::new(cfg.clone());
    c.feed(&plain_record(22, &hello.msg()));
    let (out, _) = drive_answering(&mut c, &p, &mut |_| Answer::Status {
        ret: abi::SSL_TLSEXT_ERR_NOACK,
        response: None,
    });
    let mut client = Client12::new(&hello);
    let flight = client.server_flight(&p, &out);
    assert!(flight.iter().all(|m| m[0] != ht::CERTIFICATE_STATUS));
    // A fatal answer is SSL_R_CLIENTHELLO_TLSEXT.
    let mut c = Connection::new(cfg.clone());
    c.feed(&plain_record(22, &hello.msg()));
    let (_, last) = drive_answering(&mut c, &p, &mut |_| Answer::Status {
        ret: abi::SSL_TLSEXT_ERR_ALERT_FATAL,
        response: None,
    });
    assert_eq!(
        last.unwrap_err(),
        Error::alert(abi::SSL_AD_INTERNAL_ERROR, abi::SSL_R_CLIENTHELLO_TLSEXT)
    );
    // TLS 1.3: the status in the leaf's Certificate entry.
    let mut c = Connection::new(cfg);
    let x = p.key_share(group::X25519).unwrap();
    let h13 = x25519_hello(x.public().to_vec()).with(t::STATUS_REQUEST, ocsp_request());
    c.feed(&plain_record(22, &h13.msg()));
    let (out, last) = drive_answering(&mut c, &p, &mut |_| Answer::Status {
        ret: abi::SSL_TLSEXT_ERR_OK,
        response: Some(response.clone()),
    });
    assert_eq!(last.unwrap(), Event::NeedInput);
    let mut client = Client::new();
    let (_, sk) = server_share(&first_record(&out));
    let shared = x.derive(&sk).unwrap();
    client.hello(&p, &out, &[h13.msg()], shared.bytes());
    let cert = c.cfg.certs[0].chain[0].clone();
    let flight = client.server_flight(&p, &cert);
    let cm = crate::msgs::cert::Certificate::parse(&flight[1][4..], true, true).unwrap();
    let exts = crate::msgs::ext::split(cm.entries[0].extensions.as_ref().unwrap()).unwrap();
    assert_eq!(exts.len(), 1);
    assert_eq!(exts[0].typ, t::STATUS_REQUEST);
    let mut want = vec![1, 0, 0, u8::try_from(response.len()).unwrap()];
    want.extend_from_slice(&response);
    assert_eq!(exts[0].body, want);
}

#[test]
fn tls12_encrypt_then_mac() {
    let p = TestProvider::new(b"etm");
    let hello = hello12(&[0xc027]).with(t::ENCRYPT_THEN_MAC, Vec::new());
    let mut cfg = server_config(&p);
    cfg.ciphers
        .push(crate::suites::by_protocol_id(0xc027).unwrap());
    let mut c = Connection::new(cfg);
    c.feed(&plain_record(22, &hello.msg()));
    let (out, _) = drive(&mut c, &p);
    let mut client = Client12::new(&hello);
    let flight = client.server_flight(&p, &out);
    let sh = crate::msgs::hello::ServerHello::parse(&flight[0][4..], false).unwrap();
    assert!(
        sh.extensions()
            .unwrap()
            .iter()
            .any(|e| e.typ == t::ENCRYPT_THEN_MAC)
    );
    let cert = c.cfg.certs[0].chain[0].clone();
    let (curve, point) = ske_point(&client, &p, &flight[2], &cert);
    let share = p.key_share(curve).unwrap();
    let public = share.public().to_vec();
    let pms = share.derive(&point).unwrap();
    let mut b = vec![u8::try_from(public.len()).unwrap()];
    b.extend_from_slice(&public);
    let mut out = client.send(&p, crate::consts::handshake::CLIENT_KEY_EXCHANGE, &b);
    client.master(&p, pms.bytes(), true);
    client.c.neg.etm = true;
    out.extend(client.ccs_finished(&p));
    c.feed(&out);
    let (out, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::HandshakeDone);
    client.server_flight(&p, &out);
    assert!(c.neg.etm);
    // With an AEAD suite it isn't used.
    let hello = hello12(&[0xc02f]).with(t::ENCRYPT_THEN_MAC, Vec::new());
    let mut c = Connection::new(server_config(&p));
    c.feed(&plain_record(22, &hello.msg()));
    let (out, _) = drive(&mut c, &p);
    let sh = crate::msgs::hello::ServerHello::parse(&first_record(&out)[4..], false).unwrap();
    assert!(
        sh.extensions()
            .unwrap()
            .iter()
            .all(|e| e.typ != t::ENCRYPT_THEN_MAC)
    );
    assert!(!c.hs.sh.use_etm);
}

/// A first TLS 1.3 handshake: its first ticket, and the PSK that ticket carries (from the
/// client's resumption master secret).
fn first_ticket(p: &TestProvider, cfg: Config) -> (crate::msgs::misc::NewSessionTicket13, Vec<u8>) {
    let (mut c, mut client, _) = handshake13(p, cfg, x25519_hello);
    client.application_read(p);
    let fin = client.finished(p);
    client.application_write(p);
    c.feed(&fin);
    let (out, last) = drive(&mut c, p);
    assert_eq!(last.unwrap(), Event::HandshakeDone);
    client.input.extend_from_slice(&out);
    let nst = client.message(p);
    let crate::msgs::misc::NewSessionTicket::Tls13(t) =
        crate::msgs::misc::NewSessionTicket::parse(&nst[4..], true).unwrap()
    else {
        panic!("a TLS 1.3 ticket");
    };
    let psk = crate::keysched::resumption_psk(
        p,
        HashAlg::Sha256,
        client.c.hs.sh.keys.resumption_master.bytes(),
        &t.nonce,
    )
    .unwrap();
    (t, psk.bytes().to_vec())
}

/// A ClientHello offering `identity` (with its PSK and age), psk_dhe_ke, an X25519 share,
/// and (with `early`) early data; its binder computed over the hello.
fn psk_hello(
    p: &TestProvider,
    share: Vec<u8>,
    identity: &[u8],
    age: u32,
    psk: &[u8],
    external: bool,
    early: bool,
) -> Hello {
    use crate::msgs::ext::psk;
    let mut h = x25519_hello(share).with(
        t::PSK_KEY_EXCHANGE_MODES,
        crate::msgs::ext::psk_key_exchange_modes::encode(&[1]).unwrap(),
    );
    if early {
        h = h.with(t::EARLY_DATA, Vec::new());
    }
    let mut offer = psk::Strict {
        identities: vec![psk::Identity {
            identity: identity.to_vec(),
            obfuscated_ticket_age: age,
        }],
        binders: vec![vec![0; 32]],
    };
    let draft = h
        .clone()
        .with(t::PRE_SHARED_KEY, offer.encode().unwrap())
        .msg();
    let prefix = &draft[..draft.len() - offer.binders_len()];
    let th = crate::testprov::digest(HashAlg::Sha256, prefix);
    let sched = crate::keysched::Schedule13::new(p, HashAlg::Sha256, Some(psk)).unwrap();
    offer.binders = vec![sched.binder(p, !external, &th).unwrap()];
    h.with(t::PRE_SHARED_KEY, offer.encode().unwrap())
}

/// The extension types of a message's extension block at `at`.
fn ext_types(block: &[u8]) -> Vec<u16> {
    crate::msgs::ext::split(block)
        .unwrap()
        .iter()
        .map(|e| e.typ)
        .collect()
}

#[test]
fn tls13_resumption_with_a_ticket() {
    use crate::consts::handshake as ht;
    let p = TestProvider::new(b"resume13");
    let (ticket, psk) = first_ticket(&p, server_config(&p));
    let x = p.key_share(group::X25519).unwrap();
    let xpub = x.public().to_vec();
    let age = ticket.age_add.wrapping_add(500);
    let hello = psk_hello(&p, xpub.clone(), &ticket.ticket, age, &psk, false, false);
    let mut c = Connection::new(server_config(&p));
    c.feed(&plain_record(22, &hello.msg()));
    let (out, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::NeedInput);
    assert!(c.neg.reused);
    let sh = first_record(&out);
    let parsed = crate::msgs::hello::ServerHello::parse(&sh[4..], true).unwrap();
    let types: Vec<u16> = parsed.extensions().unwrap().iter().map(|e| e.typ).collect();
    assert_eq!(
        types,
        [t::SUPPORTED_VERSIONS, t::KEY_SHARE, t::PRE_SHARED_KEY]
    );
    let (_, sk) = server_share(&sh);
    let shared = x.derive(&sk).unwrap();
    let mut client = Client::new();
    client.hello_psk(
        &p,
        &out,
        &[hello.msg()],
        Some(shared.bytes()),
        Some(&psk),
        false,
    );
    // EncryptedExtensions and Finished: no certificate when resuming.
    let ee = client.message(&p);
    assert_eq!(ee[0], ht::ENCRYPTED_EXTENSIONS);
    client.c.hs.transcript.add(&ee);
    let fin = client.message(&p);
    assert_eq!(fin[0], ht::FINISHED);
    assert_eq!(
        &fin[4..],
        &finished::final_finish_mac(&client.c, &p, true).unwrap()[..]
    );
    client.c.hs.transcript.add(&fin);
    client.application_read(&p);
    c.feed(&client.finished(&p));
    let (out, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::HandshakeDone);
    // One new ticket after a resumption.
    client.input.extend_from_slice(&out);
    assert_eq!(client.message(&p)[0], ht::NEW_SESSION_TICKET);
    assert!(client.record(&p).is_none());

    // A binder that doesn't verify.
    let mut bad = psk.clone();
    bad[0] ^= 1;
    let hello = psk_hello(&p, xpub.clone(), &ticket.ticket, age, &bad, false, false);
    expect_failure(
        server_config(&p),
        &p,
        &[hello.msg()],
        abi::SSL_AD_DECRYPT_ERROR,
        abi::SSL_R_BINDER_DOES_NOT_VERIFY,
    );
    // A ticket under another key isn't used: a full handshake.
    let mut other = server_config(&p);
    other.ticket_keys.as_mut().unwrap().name = [1; 16];
    let hello = psk_hello(&p, xpub.clone(), &ticket.ticket, age, &psk, false, false);
    let mut c = Connection::new(other);
    c.feed(&plain_record(22, &hello.msg()));
    let (_, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::NeedInput);
    assert!(!c.neg.reused);
    // pre_shared_key without psk_key_exchange_modes.
    let hello = psk_hello(&p, xpub.clone(), &ticket.ticket, age, &psk, false, false)
        .without(t::PSK_KEY_EXCHANGE_MODES);
    let mut c = Connection::new(server_config(&p));
    c.feed(&plain_record(22, &hello.msg()));
    let (_, last) = drive(&mut c, &p);
    // The extension is ignored without a mode, then its absence is the error.
    assert_eq!(
        last.unwrap_err(),
        Error::alert(
            abi::TLS13_AD_MISSING_EXTENSION,
            abi::SSL_R_MISSING_PSK_KEX_MODES_EXTENSION
        )
    );
}

/// A ticket for a TLS 1.0 session (an MD5-SHA1 suite) offered as a TLS 1.3 PSK: its suite's
/// hash isn't the TLS 1.3 suite's, so the server ignores it and runs a full handshake (it
/// doesn't check the binder).
#[test]
fn tls13_ignores_an_older_versions_ticket() {
    let p = TestProvider::new(b"old ticket");
    let old = crate::conn::Session {
        version: v::TLS1,
        // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.
        cipher_id: 0x0300_c013,
        session_id: vec![1; 32],
        master_key: vec![2; 48],
        time: server_config(&p).now,
        timeout: 7200,
        ..crate::conn::Session::default()
    };
    let mut sealer = Connection::new(server_config(&p));
    let ticket = super::ticket::seal_for_test(&mut sealer, &p, &old);
    let x = p.key_share(group::X25519).unwrap();
    // The binder as a client keeping the session's own hash makes it: MD5-SHA1's 36 octets.
    let offer = crate::msgs::ext::psk::Strict {
        identities: vec![crate::msgs::ext::psk::Identity {
            identity: ticket,
            obfuscated_ticket_age: 0,
        }],
        binders: vec![vec![0; 36]],
    };
    let hello = x25519_hello(x.public().to_vec())
        .with(
            t::PSK_KEY_EXCHANGE_MODES,
            crate::msgs::ext::psk_key_exchange_modes::encode(&[1]).unwrap(),
        )
        .with(t::PRE_SHARED_KEY, offer.encode().unwrap());
    let mut c = Connection::new(server_config(&p));
    c.feed(&plain_record(22, &hello.msg()));
    let (_, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::NeedInput);
    assert!(!c.neg.reused);
}

#[test]
fn tls13_external_psk() {
    use crate::conn::Answer;
    let p = TestProvider::new(b"external-psk");
    let key = vec![0x42; 32];
    let mut cfg = server_config(&p);
    cfg.callbacks.psk_session = true;
    let x = p.key_share(group::X25519).unwrap();
    let hello = psk_hello(&p, x.public().to_vec(), b"client1", 0, &key, true, false);
    let mut c = Connection::new(cfg);
    c.feed(&plain_record(22, &hello.msg()));
    let mut asked = Vec::new();
    let (out, last) = drive_answering(&mut c, &p, &mut |r| {
        asked.push(r.clone());
        // As capi gives it: an SSL_SESSION_new's time and timeout.
        Answer::Session(Some(crate::conn::Session {
            version: v::TLS1_3,
            cipher_id: crate::suites::cid(abi::TLS1_3_CK_AES_128_GCM_SHA256),
            master_key: key.clone(),
            time: 1_700_000_000,
            timeout: 304,
            ..crate::conn::Session::default()
        }))
    });
    assert_eq!(last.unwrap(), Event::NeedInput);
    assert_eq!(
        asked,
        [Request::PskSession {
            identity: b"client1".to_vec(),
            md: None,
        }]
    );
    assert!(c.neg.reused);
    let sh = first_record(&out);
    let (_, sk) = server_share(&sh);
    let shared = x.derive(&sk).unwrap();
    let mut client = Client::new();
    client.hello_psk(
        &p,
        &out,
        &[hello.msg()],
        Some(shared.bytes()),
        Some(&key),
        false,
    );
    let ee = client.message(&p);
    client.c.hs.transcript.add(&ee);
    let fin = client.message(&p);
    assert_eq!(
        &fin[4..],
        &finished::final_finish_mac(&client.c, &p, true).unwrap()[..]
    );
}

#[test]
fn tls13_early_data_accepted() {
    use crate::consts::handshake as ht;
    let p = TestProvider::new(b"early-data");
    let mut cfg = server_config(&p);
    cfg.max_early_data = 16384;
    cfg.recv_max_early_data = 16384;
    cfg.options |= abi::SSL_OP_NO_ANTI_REPLAY;
    let (ticket, psk) = first_ticket(&p, cfg.clone());
    // The ticket allows early data.
    assert_eq!(ext_types(&ticket.extensions), [t::EARLY_DATA]);
    let x = p.key_share(group::X25519).unwrap();
    let age = ticket.age_add.wrapping_add(100);
    let hello = psk_hello(
        &p,
        x.public().to_vec(),
        &ticket.ticket,
        age,
        &psk,
        false,
        true,
    );
    // The client: its early data under the early keys, then EndOfEarlyData.
    let mut client = Client::new();
    let ch = hello.msg();
    client.c.hs.transcript.add(&ch);
    let cp = crate::suites::by_protocol_id(0x1301).unwrap();
    client.c.hs.new_cipher = Some(cp);
    keys::generate_early(&mut client.c, &p, cp, Some(&psk)).unwrap();
    keys::change_cipher_state13(
        &mut client.c,
        &p,
        abi::SSL3_CC_EARLY | abi::SSL3_CHANGE_CIPHER_CLIENT_WRITE,
        Some(cp),
    )
    .unwrap();
    client
        .c
        .write_record(&p, record::content_type::application_data(), b"early")
        .unwrap();
    let early = client.c.take_output();
    // `SSL_read_early_data`.
    let mut c = Connection::new(cfg);
    c.hs.sh.early_data_state = common::EarlyDataState::Accepting;
    c.feed(&plain_record(22, &ch));
    c.feed(&early);
    let (out, last) = drive(&mut c, &p);
    // The handshake stops after the server's flight, to read the early data.
    assert_eq!(last.unwrap(), Event::HandshakeDone);
    assert_eq!(c.neg.early_data_status, abi::SSL_EARLY_DATA_ACCEPTED);
    assert_eq!(c.state(), abi::TLS_ST_EARLY_DATA);
    c.hs.sh.early_data_state = common::EarlyDataState::Reading;
    assert_eq!(c.step(&p, true).unwrap(), Event::AppData);
    let mut buf = [0u8; 16];
    let n = c.read_app(&mut buf, false);
    assert_eq!(&buf[..n], b"early");
    // The server's flight accepts it in EncryptedExtensions.
    let sh = first_record(&out);
    let (_, sk) = server_share(&sh);
    let shared = x.derive(&sk).unwrap();
    client.hello_psk(&p, &out, &[], Some(shared.bytes()), None, true);
    let ee = client.message(&p);
    assert!(ext_types(&ee[6..]).contains(&t::EARLY_DATA));
    client.c.hs.transcript.add(&ee);
    let fin = client.message(&p);
    assert_eq!(fin[0], ht::FINISHED);
    client.c.hs.transcript.add(&fin);
    keys::store_server_finished_hash(&mut client.c).unwrap();
    // EndOfEarlyData under the early keys, then the Finished under the handshake keys.
    let mut out = client.send(&p, ht::END_OF_EARLY_DATA, &[]);
    client.handshake_write(&p);
    out.extend(client.finished(&p));
    c.feed(&out);
    assert_eq!(c.step(&p, true).unwrap(), Event::NeedInput);
    let (_, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::HandshakeDone);
    assert_eq!(
        c.hs.sh.early_data_state,
        common::EarlyDataState::FinishedReading
    );
    assert_eq!(c.state(), abi::TLS_ST_OK);
}

#[test]
fn tls13_early_data_rejected_without_the_server_allowing_it() {
    let p = TestProvider::new(b"early-rejected");
    let mut cfg = server_config(&p);
    cfg.max_early_data = 16384;
    cfg.recv_max_early_data = 16384;
    cfg.options |= abi::SSL_OP_NO_ANTI_REPLAY;
    let (ticket, psk) = first_ticket(&p, cfg.clone());
    let x = p.key_share(group::X25519).unwrap();
    let age = ticket.age_add.wrapping_add(100);
    let hello = psk_hello(
        &p,
        x.public().to_vec(),
        &ticket.ticket,
        age,
        &psk,
        false,
        true,
    );
    // The application isn't reading early data: it is rejected, the resumption goes on.
    let mut c = Connection::new(cfg.clone());
    c.feed(&plain_record(22, &hello.msg()));
    let (_, last) = drive(&mut c, &p);
    assert_eq!(last.unwrap(), Event::NeedInput);
    assert!(c.neg.reused);
    assert_eq!(c.neg.early_data_status, abi::SSL_EARLY_DATA_REJECTED);
    // The allow_early_data callback refuses it.
    let mut cfg2 = cfg;
    cfg2.callbacks.allow_early_data = true;
    let mut c = Connection::new(cfg2);
    c.hs.sh.early_data_state = common::EarlyDataState::Accepting;
    c.feed(&plain_record(22, &hello.msg()));
    let (_, last) = drive_answering(&mut c, &p, &mut |r| {
        assert_eq!(r, &Request::AllowEarlyData);
        crate::conn::Answer::Allowed(false)
    });
    assert_eq!(last.unwrap(), Event::HandshakeDone);
    assert_eq!(c.neg.early_data_status, abi::SSL_EARLY_DATA_REJECTED);
}

#[test]
fn tls13_single_use_tickets_with_anti_replay() {
    use crate::conn::Answer;
    let p = TestProvider::new(b"anti-replay");
    let mut cfg = server_config(&p);
    cfg.max_early_data = 16384;
    cfg.recv_max_early_data = 16384;
    // Anti-replay (the default): stateful tickets, each a session ID in the cache.
    let (mut c, mut client, _) = handshake13(&p, cfg.clone(), x25519_hello);
    client.application_read(&p);
    let fin = client.finished(&p);
    client.application_write(&p);
    c.feed(&fin);
    let mut cached = Vec::new();
    let mut out = Vec::new();
    loop {
        let e = c.step(&p, false).unwrap();
        out.extend(c.take_output());
        match e {
            Event::UpdateCache { server: true } => cached.push(c.neg.session.clone()),
            Event::HandshakeDone => break,
            _ => {}
        }
    }
    assert_eq!(cached.len(), 2);
    client.input.extend_from_slice(&out);
    let nst = client.message(&p);
    let crate::msgs::misc::NewSessionTicket::Tls13(ticket) =
        crate::msgs::misc::NewSessionTicket::parse(&nst[4..], true).unwrap()
    else {
        panic!("a TLS 1.3 ticket");
    };
    assert_eq!(ticket.ticket, cached[0].session_id, "a stateful ticket");
    let psk = crate::keysched::resumption_psk(
        &p,
        HashAlg::Sha256,
        client.c.hs.sh.keys.resumption_master.bytes(),
        &ticket.nonce,
    )
    .unwrap();
    assert_eq!(psk.bytes(), &cached[0].master_key[..]);
    let x = p.key_share(group::X25519).unwrap();
    let hello = psk_hello(
        &p,
        x.public().to_vec(),
        &ticket.ticket,
        ticket.age_add,
        psk.bytes(),
        false,
        false,
    );
    // The cache has it once: the first use removes it, a replay finds nothing.
    for (removed, reused) in [(true, true), (false, false)] {
        let mut c = Connection::new(cfg.clone());
        c.feed(&plain_record(22, &hello.msg()));
        let (_, last) = drive_answering(&mut c, &p, &mut |r| match r {
            Request::GetSession { id } => {
                assert_eq!(id, &ticket.ticket);
                Answer::Session(Some(cached[0].clone()))
            }
            Request::RemoveSession { id } => {
                assert_eq!(id, &ticket.ticket);
                Answer::Allowed(removed)
            }
            other => panic!("{other:?}"),
        });
        assert_eq!(last.unwrap(), Event::NeedInput);
        assert_eq!(c.neg.reused, reused);
    }
}
