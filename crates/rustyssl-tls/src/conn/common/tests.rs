//! Tests of the shared handshake code with the test provider: RFC 8448's simple 1-RTT
//! handshake (section 3) for the TLS 1.3 key changes, Finished, and CertificateVerify; version
//! selection; cipher choice; KeyUpdate; and the handshake set-up's checks.

#![allow(clippy::arithmetic_side_effects, reason = "test code")]

use rustyssl_abi as abi;

use super::{cert, ciphers, finished, keys, sigalgs, version};
use crate::conn::statem::MsgProcess;
use crate::conn::{Config, Connection};
use crate::consts::version as v;
use crate::crypto::HashAlg;
use crate::error::Error;
use crate::msgs::rfc8448::VECTORS;
use crate::suites::{self, Cipher};
use crate::testprov::TestProvider;

fn h(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The section 3 messages, in order, with their handshake headers.
fn section3() -> Vec<(&'static str, &'static [u8])> {
    VECTORS
        .iter()
        .filter(|(s, _, _)| *s == "3")
        .map(|(_, n, m)| (*n, *m))
        .collect()
}

fn msg(name: &str, nth: usize) -> &'static [u8] {
    section3()
        .into_iter()
        .filter(|(n, _)| *n == name)
        .nth(nth)
        .unwrap()
        .1
}

const CLIENT_PRIVATE: &str = "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005";
const SERVER_PRIVATE: &str = "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e";

/// The X25519 shared secret of section 3, checked against both hellos' key shares.
fn shared_secret() -> Vec<u8> {
    let c: [u8; 32] = h(CLIENT_PRIVATE).try_into().unwrap();
    let s: [u8; 32] = h(SERVER_PRIVATE).try_into().unwrap();
    let cp = crate::testprov::x25519_public(&c);
    let sp = crate::testprov::x25519_public(&s);
    let ch = msg("ClientHello", 0);
    let sh = msg("ServerHello", 0);
    assert!(ch.windows(32).any(|w| w == cp), "the client's share");
    assert!(sh.windows(32).any(|w| w == sp), "the server's share");
    rustyssl_crypto::ecx::x25519(&c, &sp).unwrap().to_vec()
}

fn tls13(server: bool) -> Connection {
    let mut c = Connection::new(Config {
        server,
        ..Config::default()
    });
    c.neg.version = v::TLS1_3;
    c.hs.new_cipher = suites::by_protocol_id(0x1301);
    c.hs.transcript = crate::keysched::Transcript::new();
    c
}

fn body(m: &[u8]) -> &[u8] {
    &m[4..]
}

/// Runs a TLS 1.3 server through section 3 up to the client's Finished.
fn server_through_finished(p: &TestProvider) -> Connection {
    let mut c = tls13(true);
    c.hs.transcript.add(msg("ClientHello", 0));
    c.hs.transcript
        .start_hash(p, HashAlg::Sha256, false)
        .unwrap();
    c.hs.transcript.add(msg("ServerHello", 0));
    let cp = c.hs.new_cipher.unwrap();
    keys::generate_early(&mut c, p, cp, None).unwrap();
    keys::generate_handshake_secret(&mut c, p, Some(&shared_secret())).unwrap();
    keys::store_handshake_traffic_hash(&mut c).unwrap();
    keys::change_cipher_state13(
        &mut c,
        p,
        abi::SSL3_CC_HANDSHAKE | abi::SSL3_CHANGE_CIPHER_SERVER_WRITE,
        None,
    )
    .unwrap();
    keys::change_cipher_state13(
        &mut c,
        p,
        abi::SSL3_CC_HANDSHAKE | abi::SSL3_CHANGE_CIPHER_SERVER_READ,
        None,
    )
    .unwrap();
    for name in ["EncryptedExtensions", "Certificate", "CertificateVerify"] {
        c.hs.transcript.add(msg(name, 0));
    }
    c
}

#[test]
fn rfc8448_server_finished_and_key_changes() {
    let p = TestProvider::new(b"rfc8448");
    let mut c = server_through_finished(&p);
    // RFC 8448's handshake secret; the traffic secrets are checked through the Finished
    // messages, which are the RFC's.
    assert_eq!(
        c.hs.sh.keys.schedule.as_ref().unwrap().secret().bytes(),
        h("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
    );
    let server_fin = msg("Finished", 0);
    let md = finished::construct_finished(&mut c, &p).unwrap();
    assert_eq!(md, body(server_fin));
    assert_eq!(c.neg.server_finished, body(server_fin));
    c.hs.transcript.add(server_fin);
    keys::generate_master_secret(&mut c, &p).unwrap();
    keys::store_server_finished_hash(&mut c).unwrap();
    keys::change_cipher_state13(
        &mut c,
        &p,
        abi::SSL3_CC_APPLICATION | abi::SSL3_CHANGE_CIPHER_SERVER_WRITE,
        None,
    )
    .unwrap();
    assert_eq!(c.hs.sh.keys.server_app_secret.bytes().len(), 32);
    // The client's Finished: expected before it goes into the transcript, then checked.
    let client_fin = msg("Finished", 1);
    finished::take_mac(&mut c, &p).unwrap();
    assert_eq!(c.hs.peer_finish_md, body(client_fin));
    c.hs.transcript.add(client_fin);
    let mut bad = body(client_fin).to_vec();
    bad[3] ^= 1;
    let mut c2 = server_through_finished(&p);
    finished::construct_finished(&mut c2, &p).unwrap();
    c2.hs.peer_finish_md = c.hs.peer_finish_md.clone();
    assert_eq!(
        finished::process_finished(&mut c2, &p, &bad).unwrap_err(),
        Error::alert(abi::SSL_AD_DECRYPT_ERROR, abi::SSL_R_DIGEST_CHECK_FAILED)
    );
    assert_eq!(
        finished::process_finished(&mut c2, &p, &bad[1..]).unwrap_err(),
        Error::decode(abi::SSL_R_BAD_DIGEST_LENGTH)
    );
    assert_eq!(
        finished::process_finished(&mut c, &p, body(client_fin)).unwrap(),
        MsgProcess::FinishedReading
    );
    assert_eq!(c.hs.sh.keys.client_app_secret.bytes().len(), 32);
    assert_eq!(c.neg.client_finished, body(client_fin));
    assert!(c.st.cleanuphand);
    assert!(c.hs.sh.pha_transcript.is_some());
    // The exporter master secret came with the server's application keys.
    assert_eq!(c.neg.exporter_master.len(), 32);
}

#[test]
fn rfc8448_certificate_verify() {
    let p = TestProvider::new(b"rfc8448-cv");
    let mut c = tls13(false);
    c.hs.sh.sigalgs = sigalgs::Cache::new(&p);
    c.hs.sh.groups = crate::testprov::keys::groups();
    c.hs.sh.client_version = v::TLS1_2;
    c.hs.transcript.add(msg("ClientHello", 0));
    c.hs.transcript
        .start_hash(&p, HashAlg::Sha256, false)
        .unwrap();
    for name in ["ServerHello", "EncryptedExtensions", "Certificate"] {
        c.hs.transcript.add(msg(name, 0));
    }
    let cm =
        crate::msgs::cert::Certificate::parse(body(msg("Certificate", 0)), true, true).unwrap();
    c.neg.peer_chain = cm.entries.into_iter().map(|e| e.data).collect();
    cert::save_cert_verify_hash(&mut c).unwrap();
    let cv = msg("CertificateVerify", 0);
    c.hs.transcript.add(cv);
    assert_eq!(
        cert::process_cert_verify(&mut c, &p, body(cv)).unwrap(),
        MsgProcess::ContinueReading
    );
    assert_eq!(
        c.neg.peer_scheme,
        Some(crate::consts::sigscheme::RSA_PSS_RSAE_SHA256)
    );
    // A flipped signature octet fails.
    let mut bad = body(cv).to_vec();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert_eq!(
        cert::process_cert_verify(&mut c, &p, &bad).unwrap_err(),
        Error::alert(abi::SSL_AD_DECRYPT_ERROR, abi::SSL_R_BAD_SIGNATURE)
    );
    // A scheme the key can't make.
    let mut wrong = body(cv).to_vec();
    wrong[0..2].copy_from_slice(&crate::consts::sigscheme::ECDSA_SECP256R1_SHA256.to_be_bytes());
    assert_eq!(
        cert::process_cert_verify(&mut c, &p, &wrong).unwrap_err(),
        Error::alert(
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_R_WRONG_SIGNATURE_TYPE
        )
    );
}

#[test]
fn key_update_messages() {
    let p = TestProvider::new(b"ku");
    let mut c = server_through_finished(&p);
    c.hs.sh.keys.client_app_secret = crate::crypto::Secret::new(vec![7; 32]);
    assert_eq!(
        finished::process_key_update(&mut c, &p, &[2]).unwrap_err(),
        Error::alert(abi::SSL_AD_ILLEGAL_PARAMETER, abi::SSL_R_BAD_KEY_UPDATE)
    );
    assert_eq!(
        finished::process_key_update(&mut c, &p, &[1, 0]).unwrap_err(),
        Error::decode(abi::SSL_R_BAD_KEY_UPDATE)
    );
    let before = c.hs.sh.keys.client_app_secret.bytes().to_vec();
    assert_eq!(
        finished::process_key_update(&mut c, &p, &[1]).unwrap(),
        MsgProcess::FinishedReading
    );
    assert_ne!(c.hs.sh.keys.client_app_secret.bytes(), before);
    // The peer asked for an update in return.
    assert_eq!(c.hs.sh.key_update, abi::SSL_KEY_UPDATE_NOT_REQUESTED);
    assert_eq!(finished::construct_key_update(&mut c), [0]);
    assert_eq!(c.hs.sh.key_update, abi::SSL_KEY_UPDATE_NONE);
    c.hs_in.push(0);
    assert_eq!(
        finished::process_key_update(&mut c, &p, &[0]).unwrap_err(),
        Error::alert(
            abi::SSL_AD_UNEXPECTED_MESSAGE,
            abi::SSL_R_NOT_ON_RECORD_BOUNDARY
        )
    );
}

#[test]
fn change_cipher_spec_checks() {
    let p = TestProvider::new(b"ccs");
    let mut c = Connection::new(Config::default());
    c.neg.version = v::TLS1_2;
    assert_eq!(
        finished::process_change_cipher_spec(&mut c, &p, &[1]).unwrap_err(),
        Error::decode(abi::SSL_R_BAD_CHANGE_CIPHER_SPEC)
    );
    assert_eq!(
        finished::process_change_cipher_spec(&mut c, &p, &[]).unwrap_err(),
        Error::alert(
            abi::SSL_AD_UNEXPECTED_MESSAGE,
            abi::SSL_R_CCS_RECEIVED_EARLY
        )
    );
    // A Finished before the ChangeCipherSpec.
    c.hs.new_cipher = suites::by_name("ECDHE-RSA-AES128-GCM-SHA256");
    assert_eq!(
        finished::process_finished(&mut c, &p, &[0; 12]).unwrap_err(),
        Error::alert(
            abi::SSL_AD_UNEXPECTED_MESSAGE,
            abi::SSL_R_GOT_A_FIN_BEFORE_A_CCS
        )
    );
    // With a master secret, the key block is made and the read side switched.
    c.neg.master_secret = vec![1; 48];
    finished::process_change_cipher_spec(&mut c, &p, &[]).unwrap();
    assert!(c.change_cipher_spec);
    assert!(c.hs.sh.keys.key_block.is_some());
}

fn tls_any(server: bool) -> Connection {
    let mut c = Connection::new(Config {
        server,
        ciphers: suites::by_name("TLS_AES_128_GCM_SHA256")
            .into_iter()
            .chain(suites::by_name("ECDHE-RSA-AES128-GCM-SHA256"))
            .collect(),
        ..Config::default()
    });
    c.neg.version = v::TLS1;
    c
}

#[test]
fn version_ranges_and_server_choice() {
    let mut c = tls_any(true);
    assert_eq!(version::min_max(&c), Ok((v::TLS1, v::TLS1_3, v::TLS1_3)));
    c.cfg.options = abi::SSL_OP_NO_TLSv1_2;
    // A hole at TLS 1.2: OpenSSL takes the range below it.
    assert_eq!(
        version::min_max(&c).map(|r| (r.0, r.1)),
        Ok((v::TLS1, v::TLS1_1))
    );
    c.cfg.options = 0;
    c.cfg.max_version = v::TLS1_2;
    c.cfg.min_version = v::TLS1_2;
    assert_eq!(version::min_max(&c), Ok((v::TLS1_2, v::TLS1_2, v::TLS1_3)));
    c.cfg.options = abi::SSL_OP_NO_TLSv1_2;
    assert_eq!(version::min_max(&c), Err(abi::SSL_R_NO_PROTOCOLS_AVAILABLE));

    // supported_versions picks the highest the server has.
    let mut s = tls_any(true);
    s.cfg.max_version = v::TLS1_2;
    let d = version::choose_server(&mut s, v::TLS1_2, Some(&[4, 3, 4, 3, 3]), false).unwrap();
    assert_eq!(s.neg.version, v::TLS1_2);
    // A TLS 1.3-capable server negotiating TLS 1.2 would signal a downgrade; capped by
    // configuration it doesn't.
    assert_eq!(d, version::Downgrade::None);
    let mut s = tls_any(true);
    s.cfg.min_version = v::TLS1_3;
    assert_eq!(
        version::choose_server(&mut s, v::TLS1_2, None, false),
        Err(abi::SSL_R_UNSUPPORTED_PROTOCOL)
    );
    assert_eq!(
        version::sentinel(version::Downgrade::To12),
        Some(crate::consts::TLS12_DOWNGRADE)
    );
}

#[test]
fn setup_checks_versions_and_ciphers() {
    let p = TestProvider::new(b"setup");
    let mut c = tls_any(true);
    c.cfg.options = abi::SSL_OP_NO_TLSv1
        | abi::SSL_OP_NO_TLSv1_1
        | abi::SSL_OP_NO_TLSv1_2
        | abi::SSL_OP_NO_TLSv1_3;
    assert_eq!(
        super::setup_handshake(&mut c, &p).unwrap_err(),
        Error::alert(
            abi::SSL_AD_PROTOCOL_VERSION,
            abi::SSL_R_NO_PROTOCOLS_AVAILABLE
        )
    );
    // A server whose ciphers are all TLS 1.2 ones while TLS 1.3 is its maximum.
    let mut c = tls_any(true);
    c.cfg.ciphers = suites::by_name("ECDHE-RSA-AES128-GCM-SHA256")
        .into_iter()
        .collect();
    let e = super::setup_handshake(&mut c, &p).unwrap_err();
    assert_eq!(e.reason, abi::SSL_R_NO_CIPHERS_AVAILABLE);
    assert_eq!(
        e.data,
        Some("No ciphers enabled for max supported SSL/TLS version")
    );
    let mut c = tls_any(true);
    super::setup_handshake(&mut c, &p).unwrap();
    assert!(!c.hs.sh.groups.is_empty());
    assert!(!c.hs.sh.sigalgs.table.is_empty());
}

fn names(list: &[&'static Cipher]) -> Vec<&'static str> {
    list.iter().map(|c| c.name_str()).collect()
}

#[test]
fn tls13_cipher_choice_follows_the_preference() {
    let mut c = tls13(true);
    let a = suites::by_name("TLS_AES_256_GCM_SHA384").unwrap();
    let b = suites::by_name("TLS_CHACHA20_POLY1305_SHA256").unwrap();
    let g = suites::by_name("TLS_AES_128_GCM_SHA256").unwrap();
    let client = [b, a, g];
    let server = [a, g, b];
    assert_eq!(
        ciphers::choose(&mut c, &client, &server).map(Cipher::name_str),
        Some(b.name_str())
    );
    c.cfg.options = abi::SSL_OP_CIPHER_SERVER_PREFERENCE;
    assert_eq!(
        ciphers::choose(&mut c, &client, &server).map(Cipher::name_str),
        Some(a.name_str())
    );
    // ChaCha20 first when the client prefers it.
    c.cfg.options |= abi::SSL_OP_PRIORITIZE_CHACHA;
    assert_eq!(
        ciphers::choose(&mut c, &client, &server).map(Cipher::name_str),
        Some(b.name_str())
    );
    // TLS 1.2 suites aren't TLS 1.3's.
    let old = suites::by_name("ECDHE-RSA-AES128-GCM-SHA256").unwrap();
    assert_eq!(ciphers::choose(&mut c, &[old], &[old]), None);
    assert_eq!(names(&[a]), ["TLS_AES_256_GCM_SHA384"]);
}
