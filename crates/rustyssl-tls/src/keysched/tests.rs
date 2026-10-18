//! Known answers: the TLS 1.3 schedule against the vectors OpenSSL's `tls13secretstest` uses
//! (draft-ietf-tls-tls13-vectors' simple 1-RTT handshake, with the final labels), and the TLS
//! PRFs against the reference OpenSSL's `openssl kdf TLS1-PRF`.

#![allow(clippy::arithmetic_side_effects, reason = "test code")]

use super::*;
use crate::testprov::TestProvider;

fn h(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const HS_START_HASH: &str = "c6c918ad2f4199d5598eaf0116cb7a5c2c14cb54781218888db7030dd50d5e6d";
const HS_FULL_HASH: &str = "f8c19e8c77c03879bbc8eb6d56e00dd5d86ef55927eefc08e1b002b6ece05dbf";
const EARLY_SECRET: &str = "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a";
const ECDHE: &str = "8151d1464c1b55533623b9c2246a6a0e6e7e185063e14afdaff0b6e1c61a8642";
const HANDSHAKE_SECRET: &str = "5b4f965df03c682c46e6ee86c311636615a1d2bbb24345c25205953c879e8d06";
const CLIENT_HTS: &str = "e2e23207bd93fb7fe4fc2e297afeab160e522b5ab75d64a86e75bcac3f3e5103";
const CLIENT_HTS_KEY: &str = "2679a43e1d76784034ea1797d5ad2649";
const CLIENT_HTS_IV: &str = "5482405290dd0d2f81c0d942";
const SERVER_HTS: &str = "3b7a839c239ef2bf0b7305a0e0c4e5a8c6c69330a753b308f5e3a83aa2ef6979";
const SERVER_HTS_KEY: &str = "c66cb1aec519df44c91e10995511ac8b";
const SERVER_HTS_IV: &str = "f7f6884c4981716c2d0d29a4";
const MASTER_SECRET: &str = "5c79d169424e262b563203627be4eb51033f588c43c9ce0373372dbcbc0185a7";
const CLIENT_ATS: &str = "e2f0db6a82e88280fc26f73c89854ee8615e25df28b2207962fa782226b23626";
const CLIENT_ATS_KEY: &str = "88b96ad686c84be55ace18a59cce5c87";
const CLIENT_ATS_IV: &str = "b99dc58cd5ff5ab082fdad19";
const SERVER_ATS: &str = "5b73b108d9ac1b9b0c8248ca3926ec6e7bc47e41170696398 7ec11435d305719";
const SERVER_ATS_KEY: &str = "a688ebb5ac826d6f42d45c0cc44b9b7d";
const SERVER_ATS_IV: &str = "c1cad4425a438b5de714830a";

fn hx(s: &str) -> Vec<u8> {
    h(&s.replace(' ', ""))
}

#[test]
fn tls13_schedule_matches_the_vectors() {
    let p = TestProvider::new(b"keysched");
    let mut s = Schedule13::new(&p, HashAlg::Sha256, None).unwrap();
    assert_eq!(s.secret().bytes(), hx(EARLY_SECRET));
    s.into_handshake(&p, Some(&hx(ECDHE))).unwrap();
    assert_eq!(s.secret().bytes(), hx(HANDSHAKE_SECRET));

    let start = hx(HS_START_HASH);
    let c = s.client_handshake_traffic(&p, &start).unwrap();
    assert_eq!(c.bytes(), hx(CLIENT_HTS));
    let k = traffic_keys(&p, HashAlg::Sha256, c.bytes(), 16, 12).unwrap();
    assert_eq!(k.key.bytes(), hx(CLIENT_HTS_KEY));
    assert_eq!(k.iv.bytes(), hx(CLIENT_HTS_IV));
    let sv = s.server_handshake_traffic(&p, &start).unwrap();
    assert_eq!(sv.bytes(), hx(SERVER_HTS));
    let k = traffic_keys(&p, HashAlg::Sha256, sv.bytes(), 16, 12).unwrap();
    assert_eq!(k.key.bytes(), hx(SERVER_HTS_KEY));
    assert_eq!(k.iv.bytes(), hx(SERVER_HTS_IV));

    // Out of order: no master-stage secret before the master secret.
    assert!(s.client_application_traffic(&p, &start).is_err());
    s.into_master(&p).unwrap();
    assert_eq!(s.secret().bytes(), hx(MASTER_SECRET));
    let full = hx(HS_FULL_HASH);
    let c = s.client_application_traffic(&p, &full).unwrap();
    assert_eq!(c.bytes(), hx(CLIENT_ATS));
    let k = traffic_keys(&p, HashAlg::Sha256, c.bytes(), 16, 12).unwrap();
    assert_eq!(k.key.bytes(), hx(CLIENT_ATS_KEY));
    assert_eq!(k.iv.bytes(), hx(CLIENT_ATS_IV));
    let sv = s.server_application_traffic(&p, &full).unwrap();
    assert_eq!(sv.bytes(), hx(SERVER_ATS));
    let k = traffic_keys(&p, HashAlg::Sha256, sv.bytes(), 16, 12).unwrap();
    assert_eq!(k.key.bytes(), hx(SERVER_ATS_KEY));
    assert_eq!(k.iv.bytes(), hx(SERVER_ATS_IV));
    // Early secrets belong to the early stage only.
    assert!(s.client_early_traffic(&p, &full).is_err());
    assert!(s.binder_key(&p, true).is_err());
}

#[test]
fn hkdf_matches_rfc_5869() {
    // RFC 5869, test case 1.
    let p = TestProvider::new(b"hkdf");
    let prk = hkdf_extract(
        &p,
        HashAlg::Sha256,
        &h("000102030405060708090a0b0c"),
        &[0x0b; 22],
    )
    .unwrap();
    assert_eq!(
        prk.bytes(),
        h("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
    );
    let okm = hkdf_expand(
        &p,
        HashAlg::Sha256,
        prk.bytes(),
        &h("f0f1f2f3f4f5f6f7f8f9"),
        42,
    )
    .unwrap();
    assert_eq!(
        okm.bytes(),
        h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    );
    // RFC 5869, test case 3: no salt and no info.
    let prk = hkdf_extract(&p, HashAlg::Sha256, &[], &[0x0b; 22]).unwrap();
    let okm = hkdf_expand(&p, HashAlg::Sha256, prk.bytes(), &[], 42).unwrap();
    assert_eq!(
        okm.bytes(),
        h("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
    );
    assert!(hkdf_expand(&p, HashAlg::Sha256, prk.bytes(), &[], 255 * 32 + 1).is_err());
}

#[test]
fn prfs_match_the_reference() {
    let p = TestProvider::new(b"prf");
    let secret = h("9bbe436ba940f017b17652849a71db35");
    let seed = h("a0ba9f936cda311827a6f796ffd5198c");
    let want = [
        (
            PrfHash::Sha256,
            "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66",
        ),
        (
            PrfHash::Sha384,
            "dd88775cd827187b67a3f7652b5c13f715791cc46e0274a6d3fb16651103defc544cd8afb68369a219bb918b8b21ddb1764af0a70339e6dec085e574f655851ba69251320353 6bdfc3675e53768210f0a2389dd324311a440c7c30ef44b391d914c3b0c7",
        ),
        (
            PrfHash::Md5Sha1,
            "661740e6f98bc901efd2738502a71c03f76dd2f86298549b1148eff06714cf0f6b7c532cd8c69f1530e0bb680eec34c495fa75a8bfcc9c335484c0d3d194ab6e32975903c50ebcdbe9d67c0591bdbd80dddcc36d33ccd58adf96caae173f48dc40f983e2",
        ),
    ];
    for (hash, out) in want {
        let got = prf(&p, hash, &secret, b"test label", &[&seed], 100).unwrap();
        assert_eq!(got.bytes(), hx(out), "{hash:?}");
    }
    // An odd-length secret: the halves share the middle octet.
    let got = prf(
        &p,
        PrfHash::Md5Sha1,
        &h("0102030405060708090a0b0c0d0e0f1011121314151617"),
        b"master secret",
        &[&h("aabbcc")],
        48,
    )
    .unwrap();
    assert_eq!(
        got.bytes(),
        h(
            "96c0de6f1058fc59ea773f510644a16b902d81f208d133ecb342184c31c6b7d5c5838e36eec254c7e90ddb810c4fe9c5"
        )
    );
}

#[test]
fn key_block_splits_in_order() {
    let p = TestProvider::new(b"kb");
    let kb = KeyBlock::new(&p, PrfHash::Sha256, &[7; 48], &[1; 32], &[2; 32], 20, 16, 4).unwrap();
    let all = key_block(&p, PrfHash::Sha256, &[7; 48], &[1; 32], &[2; 32], 80).unwrap();
    let cat = [
        kb.client_mac.bytes(),
        kb.server_mac.bytes(),
        kb.client_key.bytes(),
        kb.server_key.bytes(),
        kb.client_iv.bytes(),
        kb.server_iv.bytes(),
    ]
    .concat();
    assert_eq!(cat, all.bytes());
}

#[test]
fn transcript_buffers_then_hashes_and_replaces_after_hrr() {
    let p = TestProvider::new(b"t");
    let mut t = Transcript::new();
    t.add(b"\x01\x00\x00\x01a");
    assert!(t.current().is_err());
    assert_eq!(t.buffered(), Some(&b"\x01\x00\x00\x01a"[..]));
    t.start_hash(&p, HashAlg::Sha256, false).unwrap();
    assert!(t.buffered().is_none());
    let ch1 = t.current().unwrap();
    assert_eq!(
        ch1,
        hash_of(&p, HashAlg::Sha256, b"\x01\x00\x00\x01a").unwrap()
    );
    t.replace_with_message_hash(&p).unwrap();
    let mut synthetic = vec![254, 0, 0, 32];
    synthetic.extend_from_slice(&ch1);
    assert_eq!(
        t.current().unwrap(),
        hash_of(&p, HashAlg::Sha256, &synthetic).unwrap()
    );
    t.add(b"more");
    synthetic.extend_from_slice(b"more");
    assert_eq!(
        t.current().unwrap(),
        hash_of(&p, HashAlg::Sha256, &synthetic).unwrap()
    );
    assert_eq!(
        t.current_with(b"x").unwrap(),
        hash_of(&p, HashAlg::Sha256, &[&synthetic[..], b"x"].concat()).unwrap()
    );
    // Kept for client authentication.
    let mut t = Transcript::new();
    t.add(b"abc");
    t.start_hash(&p, HashAlg::Sha384, true).unwrap();
    t.add(b"def");
    assert_eq!(t.buffered(), Some(&b"abcdef"[..]));
    t.drop_buffer();
    assert!(t.buffered().is_none());
}

#[test]
fn exporters_and_ticket_psks_follow_their_definitions() {
    let p = TestProvider::new(b"e");
    let em = [5u8; 32];
    let e = export_13(&p, HashAlg::Sha256, &em, b"EXPERIMENTAL", b"ctx", 20).unwrap();
    let inner = derive_secret(
        &p,
        HashAlg::Sha256,
        &em,
        b"EXPERIMENTAL",
        &hash_of(&p, HashAlg::Sha256, &[]).unwrap(),
    )
    .unwrap();
    let want = expand_label(
        &p,
        HashAlg::Sha256,
        inner.bytes(),
        b"exporter",
        &hash_of(&p, HashAlg::Sha256, b"ctx").unwrap(),
        20,
    )
    .unwrap();
    assert_eq!(e, want);
    let master = [9u8; 48];
    let with = export_12(
        &p,
        PrfHash::Sha256,
        &master,
        b"L",
        &[1; 32],
        &[2; 32],
        Some(b"c"),
        16,
    )
    .unwrap();
    let seed = [&[1u8; 32][..], &[2; 32], &[0, 1], b"c"].concat();
    assert_eq!(
        with,
        prf(&p, PrfHash::Sha256, &master, b"L", &[&seed], 16).unwrap()
    );
    let without = export_12(
        &p,
        PrfHash::Sha256,
        &master,
        b"L",
        &[1; 32],
        &[2; 32],
        None,
        16,
    )
    .unwrap();
    assert_ne!(with, without);
    let psk = resumption_psk(&p, HashAlg::Sha256, &[3; 32], &[0, 1]).unwrap();
    assert_eq!(
        psk,
        expand_label(&p, HashAlg::Sha256, &[3; 32], b"resumption", &[0, 1], 32).unwrap()
    );
    let next = next_traffic_secret(&p, HashAlg::Sha256, &[4; 32]).unwrap();
    assert_eq!(
        next,
        expand_label(&p, HashAlg::Sha256, &[4; 32], b"traffic upd", &[], 32).unwrap()
    );
}

#[test]
fn binders_and_finished_use_the_finished_key() {
    let p = TestProvider::new(b"b");
    let s = Schedule13::new(&p, HashAlg::Sha256, Some(&[1; 32])).unwrap();
    let th = [2u8; 32];
    let b = s.binder(&p, true, &th).unwrap();
    let key = s.binder_key(&p, true).unwrap();
    let fk = finished_key(&p, HashAlg::Sha256, key.bytes()).unwrap();
    assert_eq!(b, hmac(&p, HashAlg::Sha256, fk.bytes(), &[&th]).unwrap());
    assert_ne!(b, s.binder(&p, false, &th).unwrap());
    let vd = verify_data_12(&p, PrfHash::Sha256, &[0; 48], true, &th).unwrap();
    assert_eq!(vd.len(), 12);
    assert_ne!(
        vd,
        verify_data_12(&p, PrfHash::Sha256, &[0; 48], false, &th).unwrap()
    );
}

#[test]
fn keylog_lines_are_nss_format() {
    assert_eq!(
        keylog::line(keylog::CLIENT_RANDOM, &[0xab, 0x01], &[0xff]),
        "CLIENT_RANDOM ab01 ff"
    );
    assert_eq!(
        keylog::rsa_line(&[1, 2, 3, 4, 5, 6, 7, 8, 9], &[0x10]),
        "RSA 0102030405060708 10"
    );
}
