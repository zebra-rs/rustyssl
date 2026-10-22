//! The codec's known-answer tests (RFC 8448's handshake messages, decoded and re-encoded byte
//! for byte), its malformed-input tests, and round trips of generated values.

use super::*;
use crate::consts::{ext as et, group, sigscheme, version};
use crate::msgs::cert::RpkReader;
use crate::msgs::ext::{key_share, psk, supported_versions};
use crate::msgs::rfc8448::VECTORS;

/// The vectors of `section` named `name`, in order.
fn vectors(section: &str, name: &str) -> Vec<&'static [u8]> {
    VECTORS
        .iter()
        .filter(|(s, n, _)| *s == section && *n == name)
        .map(|(_, _, b)| *b)
        .collect()
}

fn one(section: &str, name: &str) -> &'static [u8] {
    vectors(section, name).first().copied().unwrap()
}

fn tls13() -> Context {
    Context {
        tls13: true,
        sigalgs: true,
        ..Context::default()
    }
}

/// Decodes a framed message and checks it re-encodes to the same octets.
fn round_trip(msg: &[u8], cx: &Context) -> HandshakeMessage {
    let (typ, body) = unframe(msg).unwrap();
    let m = HandshakeMessage::decode(typ, body, cx).unwrap();
    assert_eq!(m.encode().unwrap(), msg, "{m:?} doesn't re-encode");
    m
}

#[test]
fn every_rfc8448_message_round_trips() {
    for (section, name, msg) in VECTORS {
        if *name == "ClientHelloPrefix" {
            continue;
        }
        // Every Certificate in the traces has an empty context and certificates, which both
        // directions' forms read the same way.
        let cx = Context {
            from_server: true,
            ..tls13()
        };
        let m = round_trip(msg, &cx);
        let expected = match *name {
            "ClientHello" => ht::CLIENT_HELLO,
            "ServerHello" => ht::SERVER_HELLO,
            "EncryptedExtensions" => ht::ENCRYPTED_EXTENSIONS,
            "Certificate" => ht::CERTIFICATE,
            "CertificateRequest" => ht::CERTIFICATE_REQUEST,
            "CertificateVerify" => ht::CERTIFICATE_VERIFY,
            "Finished" => ht::FINISHED,
            "NewSessionTicket" => ht::NEW_SESSION_TICKET,
            "EndOfEarlyData" => ht::END_OF_EARLY_DATA,
            _ => unreachable!("{name}"),
        };
        assert_eq!(m.typ(), expected, "section {section} {name}");
    }
}

#[test]
fn the_simple_handshakes_client_hello() {
    let (_, body) = unframe(one("3", "ClientHello")).unwrap();
    let ch = ClientHello::parse(body, false).unwrap();
    assert_eq!(ch.legacy_version, version::TLS1_2);
    assert!(ch.session_id.is_empty());
    assert_eq!(ch.cipher_suites, [0x13, 0x01, 0x13, 0x03, 0x13, 0x02]);
    assert_eq!(ch.compression_methods, [0]);
    let exts = ch.extensions().unwrap();
    let types: Vec<u16> = exts.iter().map(|e| e.typ).collect();
    assert_eq!(
        types,
        [
            et::SERVER_NAME,
            et::RENEGOTIATE,
            et::SUPPORTED_GROUPS,
            et::SESSION_TICKET,
            et::KEY_SHARE,
            et::SUPPORTED_VERSIONS,
            et::SIGNATURE_ALGORITHMS,
            et::PSK_KEY_EXCHANGE_MODES,
            0x001c, // record_size_limit: not one OpenSSL handles
        ]
    );
    let get = |t| exts.iter().find(|e| e.typ == t).unwrap();
    assert_eq!(
        ext::server_name::parse_client(&get(et::SERVER_NAME).body).unwrap(),
        b"server"
    );
    assert_eq!(
        ext::supported_groups::parse(&get(et::SUPPORTED_GROUPS).body).unwrap(),
        [
            group::X25519,
            group::SECP256R1,
            group::SECP384R1,
            group::SECP521R1,
            group::FFDHE2048,
            group::FFDHE3072,
            group::FFDHE4096,
            group::FFDHE6144,
            group::FFDHE8192
        ]
    );
    let shares = key_share::parse_client(&get(et::KEY_SHARE).body).unwrap();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].group, group::X25519);
    assert_eq!(shares[0].key.len(), 32);
    assert_eq!(
        supported_versions::parse_client(&get(et::SUPPORTED_VERSIONS).body).unwrap(),
        [version::TLS1_3]
    );
    let sigs = ext::signature_algorithms::parse(&get(et::SIGNATURE_ALGORITHMS).body).unwrap();
    let sigs = ext::u16_list(&sigs).unwrap();
    assert_eq!(sigs.first(), Some(&sigscheme::ECDSA_SECP256R1_SHA256));
    assert_eq!(
        ext::psk_key_exchange_modes::parse(&get(et::PSK_KEY_EXCHANGE_MODES).body).unwrap(),
        [1]
    );
    // The policy check passes for the hello, record_size_limit being unknown to OpenSSL.
    let none = |_: u16| None;
    let policy = ext::Policy {
        dtls: false,
        custom: &none,
        sent: None,
    };
    ext::check(&exts, crate::consts::context::CLIENT_HELLO, &policy).unwrap();
}

#[test]
fn the_simple_handshakes_server_flight() {
    let (_, body) = unframe(one("3", "ServerHello")).unwrap();
    let sh = ServerHello::parse(body, true).unwrap();
    assert!(!sh.hrr);
    assert_eq!(sh.cipher_suite, 0x1301);
    assert_eq!(sh.downgrade(), None);
    let exts = sh.extensions().unwrap();
    let ks = exts.iter().find(|e| e.typ == et::KEY_SHARE).unwrap();
    assert_eq!(
        key_share::parse_server(&ks.body).unwrap().group,
        group::X25519
    );
    let sv = exts
        .iter()
        .find(|e| e.typ == et::SUPPORTED_VERSIONS)
        .unwrap();
    assert_eq!(
        supported_versions::parse_server(&sv.body).unwrap(),
        version::TLS1_3
    );

    let (_, body) = unframe(one("3", "EncryptedExtensions")).unwrap();
    let ee = EncryptedExtensions::parse(body).unwrap();
    let types: Vec<u16> = ee.split().unwrap().iter().map(|e| e.typ).collect();
    assert_eq!(types, [et::SUPPORTED_GROUPS, 0x001c, et::SERVER_NAME]);

    let (_, body) = unframe(one("3", "Certificate")).unwrap();
    let mut rd = CertificateReader::new(body, true, true).unwrap();
    assert_eq!(rd.context(), Some(&[][..]));
    let der = rd.next_certificate().unwrap().unwrap();
    assert_eq!(der.first(), Some(&0x30));
    assert!(rd.extensions().unwrap().is_empty());
    assert!(rd.next_certificate().is_none());

    let (_, body) = unframe(one("3", "CertificateVerify")).unwrap();
    assert_eq!(
        CertificateVerify::scheme_of(body).unwrap(),
        sigscheme::RSA_PSS_RSAE_SHA256
    );
    let cv = CertificateVerify::parse(body, true).unwrap();
    assert_eq!(cv.signature.len(), 128);

    let (_, body) = unframe(one("3", "NewSessionTicket")).unwrap();
    let NewSessionTicket::Tls13(nst) = NewSessionTicket::parse(body, true).unwrap() else {
        unreachable!()
    };
    assert_eq!(nst.lifetime, 30);
    assert_eq!(nst.nonce, [0, 0]);
    let exts = ext::split(&nst.extensions).unwrap();
    assert_eq!(exts.len(), 1);
    assert_eq!(ext::early_data::parse_ticket(&exts[0].body).unwrap(), 0x400);
}

#[test]
fn the_hello_retry_request_trace() {
    let shs = vectors("5", "ServerHello");
    let (_, body) = unframe(shs[0]).unwrap();
    let hrr = ServerHello::parse(body, true).unwrap();
    assert!(hrr.hrr);
    let exts = hrr.extensions().unwrap();
    let ks = exts.iter().find(|e| e.typ == et::KEY_SHARE).unwrap();
    assert_eq!(key_share::parse_hrr(&ks.body).unwrap(), group::SECP256R1);
    let cookie = exts.iter().find(|e| e.typ == et::COOKIE).unwrap();
    assert!(!ext::cookie::parse(&cookie.body).unwrap().is_empty());
    // Without TLS 1.3 offered, the same octets are a plain ServerHello.
    assert!(!ServerHello::parse(body, false).unwrap().hrr);
    let (_, body) = unframe(shs[1]).unwrap();
    assert!(!ServerHello::parse(body, true).unwrap().hrr);
    // The second ClientHello carries the cookie and the new share.
    let chs = vectors("5", "ClientHello");
    let (_, body) = unframe(chs[1]).unwrap();
    let ch = ClientHello::parse(body, false).unwrap();
    let exts = ch.extensions().unwrap();
    let ks = exts.iter().find(|e| e.typ == et::KEY_SHARE).unwrap();
    assert_eq!(
        key_share::parse_client(&ks.body).unwrap()[0].group,
        group::SECP256R1
    );
    assert!(exts.iter().any(|e| e.typ == et::COOKIE));
}

#[test]
fn the_resumption_trace_offers_a_psk() {
    let (_, body) = unframe(one("4", "ClientHello")).unwrap();
    let ch = ClientHello::parse(body, false).unwrap();
    let exts = ch.extensions().unwrap();
    let last = exts.last().unwrap();
    assert_eq!(last.typ, et::PRE_SHARED_KEY);
    let offer = psk::Offer::parse(&last.body).unwrap();
    let ids: Vec<_> = offer.identities().collect::<Result<_>>().unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].identity.len(), 178);
    let binder = offer.binder(0).unwrap();
    assert_eq!(binder.len(), 32);
    // The binders are the last octets of the hello.
    let binders_at = ch.extensions_offset + last.offset + offer.binders_offset();
    assert_eq!(body.len() - binders_at, 2 + 1 + 32);
    assert_eq!(body.get(binders_at + 3..), Some(&binder[..]));
    // The RFC's prefix (what the binder is computed over) is the message up to the binders.
    let prefix = one("4", "ClientHelloPrefix");
    assert_eq!(prefix.len(), HEADER_LEN + binders_at);
    assert_eq!(one("4", "ClientHello").get(..prefix.len()), Some(prefix));
    let strict = psk::Strict::parse(&last.body).unwrap();
    assert_eq!(strict.encode().unwrap(), last.body);
    assert!(exts.iter().any(|e| e.typ == et::EARLY_DATA));
}

#[test]
fn the_client_authentication_trace() {
    let (_, body) = unframe(one("6", "CertificateRequest")).unwrap();
    let CertificateRequest::Tls13(cr) = CertificateRequest::parse(body, true, true).unwrap() else {
        unreachable!()
    };
    assert!(cr.context.is_empty());
    let types: Vec<u16> = cr
        .split_extensions()
        .unwrap()
        .iter()
        .map(|e| e.typ)
        .collect();
    assert_eq!(types, [et::SIGNATURE_ALGORITHMS]);
    let certs = vectors("6", "Certificate");
    let (_, body) = unframe(certs[1]).unwrap();
    let client = Certificate::parse(body, true, false).unwrap();
    assert_eq!(client.context, Some(vec![]));
    assert_eq!(client.entries.len(), 1);
}

#[test]
fn hello_faults() {
    let mm = Error::decode(r::LENGTH_MISMATCH);
    assert_eq!(
        ClientHello::parse(&[3], false).unwrap_err(),
        Error::decode(r::LENGTH_TOO_SHORT)
    );
    let mut b = vec![3, 3];
    b.extend_from_slice(&[0; 32]);
    assert_eq!(ClientHello::parse(&b, false).unwrap_err(), mm);
    b.push(33);
    b.extend_from_slice(&[0; 33]);
    assert_eq!(ClientHello::parse(&b, false).unwrap_err(), mm);
    let mut ok = vec![3, 3];
    ok.extend_from_slice(&[0; 32]);
    ok.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
    let ch = ClientHello::parse(&ok, false).unwrap();
    assert_eq!(ch.extensions, None);
    assert_eq!(ch.encode().unwrap(), ok);
    let mut bad_block = ok.clone();
    bad_block.extend_from_slice(&[0, 4, 0, 0]);
    assert_eq!(ClientHello::parse(&bad_block, false).unwrap_err(), mm);
    let mut trailing = ok.clone();
    trailing.extend_from_slice(&[0, 0, 9]);
    assert_eq!(ClientHello::parse(&trailing, false).unwrap_err(), mm);
    // DTLS: the cookie sits after the session ID.
    let mut d = vec![0xfe, 0xfd];
    d.extend_from_slice(&[0; 32]);
    d.extend_from_slice(&[0, 3, 1, 2, 3, 0, 2, 0xc0, 0x2b, 1, 0]);
    let ch = ClientHello::parse(&d, true).unwrap();
    assert_eq!(ch.cookie, Some(vec![1, 2, 3]));
    assert_eq!(ClientHello::dtls_cookie(&d).unwrap(), [1, 2, 3]);
    assert_eq!(ch.encode().unwrap(), d);

    let mut sh = vec![3, 3];
    sh.extend_from_slice(&[1; 32]);
    sh.push(33);
    sh.extend_from_slice(&[0; 33]);
    let e = ServerHello::parse(&sh, true).unwrap_err();
    assert_eq!((e.alert, e.reason), (Some(47), r::SSL3_SESSION_ID_TOO_LONG));
    let mut sh = vec![3, 3];
    sh.extend_from_slice(&crate::consts::HRR_RANDOM);
    sh.extend_from_slice(&[0, 0x13, 0x01, 0]);
    // A HelloRetryRequest must have an extension block.
    assert_eq!(
        ServerHello::parse(&sh, true).unwrap_err(),
        Error::decode(r::BAD_LENGTH)
    );
    assert!(ServerHello::parse(&sh, false).is_ok());
    sh.extend_from_slice(&[0, 2, 0]);
    assert_eq!(
        ServerHello::parse(&sh, false).unwrap_err(),
        Error::decode(r::BAD_LENGTH)
    );
}

#[test]
fn sslv2_hellos() {
    // CLIENT-HELLO, version 3.1, 3 octets of cipher specs, no session ID, 16 octets of
    // challenge.
    let mut v2 = vec![1, 3, 1, 0, 3, 0, 0, 0, 16, 0x00, 0x00, 0x2f];
    v2.extend_from_slice(&[0xaa; 16]);
    let ch = ClientHello::parse_v2(&v2).unwrap();
    assert!(ch.sslv2);
    assert_eq!(ch.cipher_suites, [0, 0, 0x2f]);
    assert_eq!(ch.random[..16], [0; 16]);
    assert_eq!(ch.random[16..], [0xaa; 16]);
    assert_eq!(ch.compression_methods, [0]);
    let mut short = v2.clone();
    short.pop();
    assert_eq!(
        ClientHello::parse_v2(&short).unwrap_err(),
        Error::decode(r::RECORD_LENGTH_MISMATCH)
    );
    let long_sid = [1, 3, 1, 0, 0, 0, 33, 0, 0];
    let e = ClientHello::parse_v2(&long_sid).unwrap_err();
    assert_eq!((e.alert, e.reason), (Some(47), r::LENGTH_MISMATCH));
    assert_eq!(ClientHello::parse_v2(&[4]).unwrap_err(), Error::internal());
}

#[test]
fn certificate_faults() {
    let mm = Error::decode(r::LENGTH_MISMATCH);
    // From a server: an empty list, a non-empty context, a length that doesn't fill.
    assert_eq!(
        CertificateReader::new(&[0, 0, 0, 0], true, true).unwrap_err(),
        mm
    );
    assert_eq!(
        CertificateReader::new(&[1, 9, 0, 0, 0], true, true).unwrap_err(),
        mm
    );
    assert_eq!(
        CertificateReader::new(&[0, 0, 0, 5, 1], false, true).unwrap_err(),
        mm
    );
    // From a client: empty is fine, a broken context isn't.
    assert!(
        CertificateReader::new(&[0, 0, 0, 0], true, false)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        CertificateReader::new(&[2, 1], true, false).unwrap_err(),
        Error::decode(r::INVALID_CONTEXT)
    );
    // A truncated entry, and a broken entry extension block.
    let mut rd = CertificateReader::new(&[0, 0, 4, 0, 0, 9, 1], false, true).unwrap();
    assert_eq!(
        rd.next_certificate().unwrap().unwrap_err(),
        Error::decode(r::CERT_LENGTH_MISMATCH)
    );
    let mut rd = CertificateReader::new(&[0, 0, 0, 6, 0, 0, 1, 0x30, 0, 5], true, true).unwrap();
    assert_eq!(rd.next_certificate().unwrap().unwrap(), [0x30]);
    assert_eq!(rd.extensions().unwrap_err(), Error::decode(r::BAD_LENGTH));
    // TLS 1.2's list form round trips.
    let c = Certificate {
        context: None,
        entries: vec![
            CertificateEntry {
                data: vec![0x30, 1, 2],
                extensions: None,
            },
            CertificateEntry {
                data: vec![0x30, 0],
                extensions: None,
            },
        ],
    };
    let b = c.encode().unwrap();
    assert_eq!(Certificate::parse(&b, false, true).unwrap(), c);
}

#[test]
fn raw_public_keys() {
    let k = RawPublicKey {
        context: Some(vec![]),
        spki: Some(vec![0x30, 3, 1, 2, 3]),
        extensions: Some(vec![]),
    };
    let b = k.encode().unwrap();
    assert_eq!(RawPublicKey::parse(&b, true).unwrap(), k);
    let k12 = RawPublicKey {
        context: None,
        spki: Some(vec![0x30, 0]),
        extensions: None,
    };
    let b = k12.encode().unwrap();
    assert_eq!(RawPublicKey::parse(&b, false).unwrap(), k12);
    let none = RawPublicKey {
        context: Some(vec![]),
        spki: None,
        extensions: None,
    };
    assert_eq!(
        RawPublicKey::parse(&none.encode().unwrap(), true).unwrap(),
        none
    );
    assert_eq!(
        RpkReader::new(&[0, 0, 0, 3, 0, 0, 0], true).unwrap_err(),
        Error::decode(r::EMPTY_RAW_PUBLIC_KEY)
    );
    // Octets between the key and the block that the entry's length doesn't account for.
    let bad = [0, 0, 0, 8, 0, 0, 2, 0x30, 0, 0, 0, 7];
    let rd = RpkReader::new(&bad, true).unwrap();
    assert_eq!(
        rd.extensions().unwrap_err(),
        Error::decode(r::LENGTH_MISMATCH)
    );
    let worse = [0, 0, 0, 9, 0, 0, 2, 0x30, 0, 0, 0, 0, 9];
    let rd = RpkReader::new(&worse, true).unwrap();
    assert_eq!(
        rd.extensions().unwrap_err(),
        Error::decode(r::LENGTH_MISMATCH)
    );
}

#[test]
fn certificate_requests() {
    let m = CertificateRequest::Tls12(CertificateRequest12 {
        certificate_types: vec![1, 64],
        sigalgs: Some(vec![0x0804, 0x0403]),
        ca_names: vec![vec![0x30, 0]],
    });
    let b = m.encode().unwrap();
    assert_eq!(CertificateRequest::parse(&b, false, true).unwrap(), m);
    let e = CertificateRequest::parse(&[0, 0, 1, 4, 0, 0], false, true).unwrap_err();
    assert_eq!(
        (e.alert, e.reason),
        (Some(80), r::SIGNATURE_ALGORITHMS_ERROR)
    );
    // Without signature algorithms (TLS 1.1), the list isn't there.
    let old = CertificateRequest::Tls12(CertificateRequest12 {
        certificate_types: vec![1],
        sigalgs: None,
        ca_names: vec![],
    });
    assert_eq!(
        CertificateRequest::parse(&old.encode().unwrap(), false, false).unwrap(),
        old
    );
    assert_eq!(
        CertificateRequest::parse(&[1, 1, 0, 0, 9], false, false).unwrap_err(),
        Error::decode(r::LENGTH_MISMATCH)
    );
    // TLS 1.3: trailing octets are found only at the end.
    let (m, rest) = CertificateRequest13::read(&[0, 0, 0, 7]).unwrap();
    assert!(m.extensions.is_empty());
    assert_eq!(
        CertificateRequest13::check_end(rest).unwrap_err(),
        Error::decode(r::LENGTH_MISMATCH)
    );
    assert_eq!(
        CertificateRequest13::read(&[0, 0, 5]).unwrap_err(),
        Error::decode(r::BAD_LENGTH)
    );
}

#[test]
fn small_messages() {
    let cv = CertificateVerify {
        scheme: None,
        signature: vec![1; 64],
    };
    assert_eq!(
        CertificateVerify::parse(&cv.encode().unwrap(), false).unwrap(),
        cv
    );
    assert_eq!(
        CertificateVerify::parse(&[8], true).unwrap_err(),
        Error::decode(r::BAD_PACKET)
    );
    assert_eq!(
        CertificateVerify::parse(&[8, 4, 0, 2, 1], true).unwrap_err(),
        Error::decode(r::LENGTH_MISMATCH)
    );
    let st = CertificateStatus {
        response: vec![0x30, 0],
    };
    assert_eq!(CertificateStatus::parse(&st.encode().unwrap()).unwrap(), st);
    assert_eq!(
        CertificateStatus::parse(&[2, 0, 0, 0]).unwrap_err(),
        Error::decode(r::UNSUPPORTED_STATUS_TYPE)
    );
    assert_eq!(
        CertificateStatus::parse(&[1, 0, 0, 2, 0]).unwrap_err(),
        Error::decode(r::LENGTH_MISMATCH)
    );
    assert_eq!(KeyUpdate::parse(&[1]).unwrap().request_update, 1);
    assert_eq!(
        KeyUpdate::parse(&[1, 0]).unwrap_err(),
        Error::decode(r::BAD_KEY_UPDATE)
    );
    assert_eq!(KeyUpdate::parse(&[2]).unwrap_err().alert, Some(47));
    assert_eq!(
        misc::empty(&[0]).unwrap_err(),
        Error::decode(r::LENGTH_MISMATCH)
    );
    let np = NextProtocol::build(b"h2").unwrap();
    assert_eq!(np.encode().unwrap().len() % 32, 0);
    assert_eq!(NextProtocol::parse(&np.encode().unwrap()).unwrap(), np);
    let t12 = NewSessionTicket::Tls12(NewSessionTicket12 {
        lifetime_hint: 300,
        ticket: vec![],
    });
    assert_eq!(
        NewSessionTicket::parse(&t12.encode().unwrap(), false).unwrap(),
        t12
    );
    assert_eq!(
        NewSessionTicket::parse(&[0, 0, 0, 1, 0, 2, 1], false).unwrap_err(),
        Error::decode(r::LENGTH_MISMATCH)
    );
    // An empty TLS 1.3 ticket is an error.
    assert_eq!(
        NewSessionTicket::parse(&[0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0], true).unwrap_err(),
        Error::decode(r::LENGTH_MISMATCH)
    );
    let cc = CompressedCertificate {
        algorithm: 1,
        uncompressed_length: 100,
        compressed_length: 3,
        compressed: vec![1, 2, 3],
    };
    let b = cc.encode().unwrap();
    let back = CompressedCertificate::parse(&b).unwrap();
    back.check().unwrap();
    assert_eq!(back, cc);
    let e = CompressedCertificate::algorithm_of(&[1]).unwrap_err();
    assert_eq!((e.alert, e.library_reason), (Some(42), true));
    assert_eq!(
        CompressedCertificate::parse(&[0, 1, 0]).unwrap_err().reason,
        r::BAD_DECOMPRESSION
    );
    let empty = CompressedCertificate::parse(&[0, 1, 0, 0, 9, 0, 0, 0]).unwrap();
    assert_eq!(
        empty.check().unwrap_err(),
        Error::decode(r::BAD_DECOMPRESSION)
    );
    let hvr = HelloVerifyRequest {
        server_version: version::DTLS1_2,
        cookie: vec![7; 20],
    };
    assert_eq!(
        HelloVerifyRequest::parse(&hvr.encode().unwrap()).unwrap(),
        hvr
    );
    assert_eq!(
        HelloVerifyRequest::parse(&[0xfe, 0xff, 3, 1]).unwrap_err(),
        Error::decode(r::LENGTH_MISMATCH)
    );
}

#[test]
fn headers() {
    let h = Header::peek(&[1, 0, 0, 5, 9]).unwrap();
    assert_eq!(h, Header { typ: 1, len: 5 });
    assert_eq!(Header::peek(&[1, 0, 0]), None);
    let d = DtlsHeader {
        typ: 1,
        len: 300,
        message_seq: 2,
        fragment_offset: 100,
        fragment_length: 50,
    };
    let mut w = crate::codec::Writer::new();
    d.write(&mut w);
    assert_eq!(w.len(), DTLS_HEADER_LEN);
    assert_eq!(DtlsHeader::peek(w.bytes()), Some(d));
    assert_eq!(
        unframe(&[20, 0, 0, 2, 1]).unwrap_err(),
        Error::decode(r::LENGTH_MISMATCH)
    );
    let mh = message_hash(&[7; 32]).unwrap();
    assert_eq!(mh.get(..4), Some(&[254, 0, 0, 32][..]));
}

/// A small deterministic generator for the round-trip properties.
struct Gen(u64);

impl Gen {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn byte(&mut self) -> u8 {
        u8::try_from(self.next() & 0xff).unwrap()
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let bound = u64::try_from(max).unwrap().saturating_add(1);
        let n = usize::try_from(self.next().checked_rem(bound).unwrap()).unwrap();
        (0..n).map(|_| self.byte()).collect()
    }
    fn u16(&mut self) -> u16 {
        u16::try_from(self.next() & 0xffff).unwrap()
    }
    fn u32(&mut self) -> u32 {
        u32::try_from(self.next() >> 32).unwrap()
    }
}

#[test]
fn generated_messages_round_trip() {
    let mut g = Gen(0x9e37_79b9_7f4a_7c15);
    for _ in 0..500 {
        let mut random = [0u8; 32];
        random.iter_mut().for_each(|b| *b = g.byte());
        let exts: Vec<ext::Extension> = (0..g.next() % 6)
            .map(|_| ext::Extension::new(g.u16(), g.bytes(40)))
            .collect();
        let contents = ext::encode_contents(&exts).unwrap();
        let ch = ClientHello {
            legacy_version: g.u16(),
            random,
            session_id: g.bytes(32),
            cookie: None,
            cipher_suites: g.bytes(60),
            compression_methods: g.bytes(4),
            extensions: Some(contents.clone()),
            extensions_offset: 0,
            sslv2: false,
        };
        let back = ClientHello::parse(&ch.encode().unwrap(), false).unwrap();
        assert_eq!(
            back.extensions()
                .unwrap()
                .iter()
                .map(|e| (e.typ, e.body.clone()))
                .collect::<Vec<_>>(),
            exts.iter()
                .map(|e| (e.typ, e.body.clone()))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            ClientHello {
                extensions_offset: 0,
                ..back
            },
            ch
        );
        let sh = ServerHello {
            legacy_version: version::TLS1_2,
            random,
            session_id: g.bytes(32),
            cipher_suite: g.u16(),
            compression: g.byte(),
            extensions: Some(contents),
            hrr: false,
        };
        assert_eq!(
            ServerHello::parse(&sh.encode().unwrap(), false).unwrap(),
            sh
        );
        let nst = NewSessionTicket::Tls13(NewSessionTicket13 {
            lifetime: g.u32(),
            age_add: g.u32(),
            nonce: g.bytes(8),
            ticket: {
                let mut t = g.bytes(100);
                t.push(1);
                t
            },
            extensions: ext::encode_contents(&[ext::Extension::new(
                et::EARLY_DATA,
                vec![0, 0, 4, 0],
            )])
            .unwrap(),
        });
        assert_eq!(
            NewSessionTicket::parse(&nst.encode().unwrap(), true).unwrap(),
            nst
        );
        let entries: Vec<CertificateEntry> = (0..1 + g.next() % 3)
            .map(|_| CertificateEntry {
                data: {
                    let mut d = g.bytes(50);
                    d.push(0);
                    d
                },
                extensions: Some(g.bytes(10)),
            })
            .collect();
        let c = Certificate {
            context: Some(vec![]),
            entries,
        };
        assert_eq!(
            Certificate::parse(&c.encode().unwrap(), true, true).unwrap(),
            c
        );
        let ks: Vec<key_share::Entry> = (0..g.next() % 4)
            .map(|_| key_share::Entry {
                group: g.u16(),
                key: {
                    let mut k = g.bytes(64);
                    k.push(1);
                    k
                },
            })
            .collect();
        assert_eq!(
            key_share::parse_client(&key_share::encode_client(&ks).unwrap()).unwrap(),
            ks
        );
    }
}

/// A CertificateStatus of only its type (3.6 reads it as no response) round-trips: found by
/// ClusterFuzzLite's `tls_msgs` (the encoder wrote an empty length, which is `SSL_R_BAD_PACKET`).
#[test]
fn certificate_status_without_response_round_trips() {
    let cx = Context {
        tls13: true,
        dtls: false,
        sigalgs: false,
        from_server: false,
        rpk: false,
        kx: kx::Kx::default(),
    };
    let m = HandshakeMessage::decode(ht::CERTIFICATE_STATUS, &[1], &cx).unwrap();
    assert_eq!(
        m,
        HandshakeMessage::CertificateStatus(CertificateStatus {
            response: Vec::new()
        })
    );
    let enc = m.encode_body().unwrap();
    assert_eq!(enc, [1]);
    assert_eq!(
        HandshakeMessage::decode(ht::CERTIFICATE_STATUS, &enc, &cx).unwrap(),
        m
    );
    // An explicit empty response stays refused.
    assert!(CertificateStatus::parse(&[1, 0, 0, 0]).is_err());
}
