#![allow(clippy::arithmetic_side_effects, reason = "test code")]

use rustyssl_tls::crypto::{AeadAlg, HashAlg};

use super::*;
use crate::crypto::HpAlg;
use crate::testprov::TestProvider;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

#[test]
fn rfc9001_a1_initial_keys() {
    let p = TestProvider::new(b"a1");
    let (c, s) = initial_secrets(&p, &DCID).unwrap();
    assert_eq!(
        c.bytes(),
        hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
    );
    assert_eq!(
        s.bytes(),
        hex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
    );
    let (k, iv, hp) = derive_key_material(&p, Suite::INITIAL, c.bytes()).unwrap();
    assert_eq!(k.bytes(), hex("1f369613dd76d5467730efcbe3b1a22d"));
    assert_eq!(iv.bytes(), hex("fa044b2f42a3fd3b46fb255c"));
    assert_eq!(hp.bytes(), hex("9f50449e04a0e810283a1e9933adedd2"));
    let (k, iv, hp) = derive_key_material(&p, Suite::INITIAL, s.bytes()).unwrap();
    assert_eq!(k.bytes(), hex("cf3a5331653c364c88f0f379b6067e37"));
    assert_eq!(iv.bytes(), hex("0ac1493ca1905853b0bba03e"));
    assert_eq!(hp.bytes(), hex("c206b8d9b9f0f37644430b490eeaa314"));
}

#[test]
fn rfc9001_a2_client_header_protection_sample() {
    // A.2: the client Initial's sample and mask.
    let p = TestProvider::new(b"a2");
    let (_, _, hp) = {
        let (c, _) = initial_secrets(&p, &DCID).unwrap();
        derive_key_material(&p, Suite::INITIAL, c.bytes()).unwrap()
    };
    let f = p.header_protection(HpAlg::Aes128, hp.bytes()).unwrap();
    let sample: [u8; 16] = hex("d1b1c98dd7689fb8ec11d242b123dc9b").try_into().unwrap();
    assert_eq!(f.mask(&sample).unwrap().to_vec(), hex("437b9aec36"));
}

const SERVER_INITIAL: &str = "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a\
    5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df354\
    8e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d\
    20398c276456cbc42158407dd074ee";

const SERVER_INITIAL_BODY: &str = "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825dd\
    f73988cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c\
    144eca684d1081287c834d5311bcf32bb9da1a002b00020304";

#[test]
fn rfc9001_a3_server_initial() {
    let p = TestProvider::new(b"a3");
    let pkt = hex(SERVER_INITIAL);
    let (loc, rest) = locate(&pkt, 0).unwrap();
    assert!(rest.is_empty());
    assert_eq!(loc.ty, PacketType::Initial);
    assert!(loc.dcid.is_empty());
    assert_eq!(loc.scid.as_bytes(), hex("f067a5502a4262b5"));
    let (_, mut server) = initial_keys(&p, &DCID).unwrap();
    let opened = unprotect(&mut server, loc.bytes, loc.pn_offset, Some(0))
        .unwrap()
        .unwrap();
    assert_eq!(opened.pn, 1);
    assert_eq!(opened.payload, hex(SERVER_INITIAL_BODY));

    // Protecting the same payload with the same packet number gives the same packet.
    let (_, mut server) = initial_keys(&p, &DCID).unwrap();
    let scid = ConnId::new(&hex("f067a5502a4262b5")).unwrap();
    let dcid = ConnId::default();
    let o = Outgoing {
        ty: PacketType::Initial,
        dcid: &dcid,
        scid: &scid,
        token: &[],
        pn: 1,
        pn_len: 2,
        key_phase: false,
    };
    let mut out = Vec::new();
    protect(&mut server, &o, &opened.payload, &mut out).unwrap();
    assert_eq!(out, pkt);
}

#[test]
fn rfc9001_a4_retry_integrity_tag() {
    let p = TestProvider::new(b"a4");
    let odcid = ConnId::new(&DCID).unwrap();
    let retry = hex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
    assert!(retry_tag_valid(&p, &odcid, &retry));
    let mut bad = retry.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(!retry_tag_valid(&p, &odcid, &bad));
    let (loc, _) = locate(&retry, 0).unwrap();
    assert_eq!(loc.ty, PacketType::Retry);
    assert_eq!(loc.token, b"token");
    let built = build_retry(&p, &odcid, &ConnId::default(), &loc.scid, b"token", 0x0f).unwrap();
    assert_eq!(built, retry);
}

#[test]
fn rfc9001_a5_chacha20_short_header() {
    let p = TestProvider::new(b"a5");
    let secret = hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    let suite = Suite {
        aead: AeadAlg::ChaCha20Poly1305,
        hp: HpAlg::ChaCha20,
        hash: HashAlg::Sha256,
    };
    let (k, iv, hp) = derive_key_material(&p, suite, &secret).unwrap();
    assert_eq!(
        k.bytes(),
        hex("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8")
    );
    assert_eq!(iv.bytes(), hex("e0459b3474bdd0e44a41c144"));
    assert_eq!(
        hp.bytes(),
        hex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
    );
    let mut keys = Keys::new(&p, suite, &secret).unwrap();
    let pkt = hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb");
    let (loc, _) = locate(&pkt, 0).unwrap();
    assert_eq!(loc.ty, PacketType::OneRtt);
    let opened = unprotect(&mut keys, loc.bytes, loc.pn_offset, Some(654_360_560))
        .unwrap()
        .unwrap();
    assert_eq!(opened.pn, 654_360_564);
    assert_eq!(opened.payload, [0x01]);
    assert!(!opened.key_phase);
    // The key update secret ("quic ku").
    let next =
        rustyssl_tls::keysched::expand_label(&p, HashAlg::Sha256, &secret, b"quic ku", &[], 32)
            .unwrap();
    assert_eq!(
        next.bytes(),
        hex("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")
    );
}

#[test]
fn packet_numbers() {
    // RFC 9000, Appendix A.3's example.
    assert_eq!(decode_pn(Some(0xa82f_30ea), 0x9b32, 2), 0xa82f_9b32);
    assert_eq!(decode_pn(None, 0, 1), 0);
    assert_eq!(decode_pn(Some(0xff), 0x00, 1), 0x100);
    // Appendix A.2: 0xac5c02 with 0xabe8b3 acknowledged needs 2 octets, 0xace8fe needs 3.
    assert_eq!(pn_len(0x00ac_5c02, Some(0x00ab_e8b3)), 2);
    assert_eq!(pn_len(0x00ac_e8fe, Some(0x00ab_e8b3)), 3);
}

#[test]
fn protect_round_trips_and_key_phases() {
    let p = TestProvider::new(b"rt");
    let secret = [7u8; 32];
    let suite = Suite {
        aead: AeadAlg::Aes128Gcm,
        hp: HpAlg::Aes128,
        hash: HashAlg::Sha256,
    };
    let dcid = ConnId::new(&[1, 2, 3, 4]).unwrap();
    let scid = ConnId::new(&[5, 6]).unwrap();
    for (ty, short_len) in [
        (PacketType::OneRtt, 4),
        (PacketType::Handshake, 0),
        (PacketType::ZeroRtt, 0),
        (PacketType::Initial, 0),
    ] {
        for pn in [0u64, 300, 70_000] {
            let mut tx = Keys::new(&p, suite, &secret).unwrap();
            let mut rx = Keys::new(&p, suite, &secret).unwrap();
            let o = Outgoing {
                ty,
                dcid: &dcid,
                scid: &scid,
                token: b"tk",
                pn,
                pn_len: pn_len(pn, pn.checked_sub(1)),
                key_phase: true,
            };
            let mut out = Vec::new();
            protect(&mut tx, &o, b"\x01\x00\x00\x00hello", &mut out).unwrap();
            // A second packet coalesced after a long header one.
            let (loc, rest) = locate(&out, short_len).unwrap();
            assert!(rest.is_empty());
            assert_eq!(loc.ty, ty);
            let got = unprotect(&mut rx, loc.bytes, loc.pn_offset, pn.checked_sub(1))
                .unwrap()
                .unwrap();
            assert_eq!(got.pn, pn);
            assert_eq!(got.payload, b"\x01\x00\x00\x00hello");
            assert_eq!(got.key_phase, ty == PacketType::OneRtt);
            // A flipped bit in the payload doesn't authenticate.
            let mut bad = out.clone();
            *bad.last_mut().unwrap() ^= 1;
            let (loc, _) = locate(&bad, short_len).unwrap();
            let mut rx = Keys::new(&p, suite, &secret).unwrap();
            assert_eq!(
                unprotect(&mut rx, loc.bytes, loc.pn_offset, None).unwrap(),
                None
            );
        }
    }
    // The next phase decrypts what the next phase encrypts, and not the old one's.
    let k0 = Keys::new(&p, suite, &secret).unwrap();
    let mut k1 = k0.next_phase(&p).unwrap();
    let mut rx1 = Keys::new(&p, suite, &secret)
        .unwrap()
        .next_phase(&p)
        .unwrap();
    let o = Outgoing {
        ty: PacketType::OneRtt,
        dcid: &dcid,
        scid: &scid,
        token: &[],
        pn: 9,
        pn_len: 1,
        key_phase: true,
    };
    let mut out = Vec::new();
    protect(&mut k1, &o, b"\x01\x01\x01\x01", &mut out).unwrap();
    let (loc, _) = locate(&out, 4).unwrap();
    assert!(
        unprotect(&mut rx1, loc.bytes, loc.pn_offset, Some(8))
            .unwrap()
            .is_some()
    );
    let mut rx0 = Keys::new(&p, suite, &secret).unwrap();
    assert!(
        unprotect(&mut rx0, loc.bytes, loc.pn_offset, Some(8))
            .unwrap()
            .is_none()
    );
}

#[test]
fn coalesced_datagrams_and_version_negotiation() {
    let p = TestProvider::new(b"co");
    let suite = Suite::INITIAL;
    let dcid = ConnId::new(&[9; 8]).unwrap();
    let scid = ConnId::new(&[8; 8]).unwrap();
    let mut dgram = Vec::new();
    for ty in [
        PacketType::Initial,
        PacketType::Handshake,
        PacketType::OneRtt,
    ] {
        let mut k = Keys::new(&p, suite, &[1; 32]).unwrap();
        let o = Outgoing {
            ty,
            dcid: &dcid,
            scid: &scid,
            token: &[],
            pn: 0,
            pn_len: 1,
            key_phase: false,
        };
        protect(&mut k, &o, &[0x01, 0, 0, 0], &mut dgram).unwrap();
    }
    let (a, rest) = locate(&dgram, 8).unwrap();
    let (b, rest) = locate(rest, 8).unwrap();
    let (c, rest) = locate(rest, 8).unwrap();
    assert_eq!(
        (a.ty, b.ty, c.ty),
        (
            PacketType::Initial,
            PacketType::Handshake,
            PacketType::OneRtt
        )
    );
    assert!(rest.is_empty());

    // OpenSSL's test's version negotiation packet.
    let vn = hex("c7 00000000 00 0c 353c1b97caf8991139ad791f 00000001 aa9a3a9a");
    let (v, _) = locate(&vn, 0).unwrap();
    assert_eq!(v.ty, PacketType::VersionNegotiation);
    assert_eq!(v.scid.len(), 12);
    assert_eq!(v.token, hex("00000001aa9a3a9a"));
    let built = build_version_negotiation(&[1, 2], &[3], 0x47).unwrap();
    let (v, _) = locate(&built, 0).unwrap();
    assert_eq!(v.ty, PacketType::VersionNegotiation);
    assert_eq!(v.dcid.as_bytes(), [3]);
    assert_eq!(v.scid.as_bytes(), [1, 2]);

    // Malformed headers are refused: a long header cut short, a short header without its
    // fixed bit, a connection ID longer than 20.
    assert!(locate(&[0xc0, 0, 0, 0, 1, 5, 1], 0).is_err());
    assert!(locate(&[0x00, 1, 2, 3], 2).is_err());
    let mut long_cid = vec![0xc0, 0, 0, 0, 1, 21];
    long_cid.extend_from_slice(&[0; 21]);
    long_cid.push(0);
    assert!(locate(&long_cid, 0).is_err());
}
