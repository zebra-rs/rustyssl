//! Fuzzes the TLS core's message and extension codecs on untrusted input: the first octet picks
//! the decoding context (TLS 1.3 or not, DTLS, signature algorithms, the sender, raw public
//! keys, and the key exchange), and the rest is decoded as every handshake message type, as an
//! extension block, and as the body of every extension with a typed parser. Whatever decodes
//! must encode and decode back to the same value. Nothing may panic or read out of bounds.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyssl_tls::msgs::ext::{
    self, alpn, cert_type, certificate_authorities, compress_certificate, cookie, early_data,
    ec_point_formats, key_share, psk, psk_key_exchange_modes, renegotiate, server_name,
    status_request, supported_groups, supported_versions, use_srtp,
};
use rustyssl_tls::msgs::kx::{Kx, KxMethod};
use rustyssl_tls::msgs::{CertificateReader, ClientHello, Context, HandshakeMessage};

const METHODS: [KxMethod; 10] = [
    KxMethod::None,
    KxMethod::Rsa,
    KxMethod::Dhe,
    KxMethod::Ecdhe,
    KxMethod::Psk,
    KxMethod::RsaPsk,
    KxMethod::DhePsk,
    KxMethod::EcdhePsk,
    KxMethod::Srp,
    KxMethod::Gost,
];

/// The context the first octet selects.
fn context(sel: u8) -> Context {
    let method = METHODS
        .get(usize::from(sel >> 4) % METHODS.len())
        .copied()
        .unwrap_or_default();
    Context {
        tls13: sel & 1 != 0,
        dtls: sel & 2 != 0,
        sigalgs: sel & 4 != 0,
        from_server: sel & 8 != 0,
        rpk: sel & 0x80 != 0 && sel & 0x40 != 0,
        kx: Kx {
            method,
            signed: sel & 0x20 != 0,
            ssl3: sel & 0x60 == 0x60,
        },
    }
}

/// `parse(encode(v)) == v` for a typed extension value.
fn again<T: PartialEq + core::fmt::Debug>(
    v: T,
    encode: impl Fn(&T) -> Vec<u8>,
    parse: impl Fn(&[u8]) -> Option<T>,
) {
    let back = parse(&encode(&v));
    assert_eq!(
        back.as_ref(),
        Some(&v),
        "an extension that doesn't survive re-encoding"
    );
}

fn extensions(b: &[u8]) {
    if let Ok(exts) = ext::split(b) {
        let contents = ext::encode_contents(&exts).expect("encodable");
        let back = ext::split(&contents).expect("decodable");
        assert_eq!(back.len(), exts.len());
        let none = |_: u16| None;
        let policy = ext::Policy {
            dtls: false,
            custom: &none,
            sent: None,
        };
        let _ = ext::check(&exts, rustyssl_tls::consts::context::CLIENT_HELLO, &policy);
    }
    if let Ok(h) = server_name::parse_client(b) {
        again(
            h,
            |h| server_name::encode_client(h).unwrap(),
            |b| server_name::parse_client(b).ok(),
        );
    }
    if let Ok(l) = alpn::parse_client(b) {
        let names = alpn::names(&l);
        assert_eq!(
            alpn::parse_client(&alpn::encode_client(&names).unwrap()).ok(),
            Some(l)
        );
    }
    if let Ok(p) = alpn::parse_server(b) {
        again(
            p,
            |p| alpn::encode_server(p).unwrap(),
            |b| alpn::parse_server(b).ok(),
        );
    }
    if let Ok(g) = supported_groups::parse(b) {
        again(
            g,
            |g| supported_groups::encode(g).unwrap(),
            |b| supported_groups::parse(b).ok(),
        );
    }
    if let Ok(k) = key_share::parse_client(b) {
        again(
            k,
            |k| key_share::encode_client(k).unwrap(),
            |b| key_share::parse_client(b).ok(),
        );
    }
    if let Ok(k) = key_share::parse_server(b) {
        again(
            k,
            |k| key_share::encode_server(k).unwrap(),
            |b| key_share::parse_server(b).ok(),
        );
    }
    if let Ok(v) = supported_versions::parse_client(b) {
        again(
            v,
            |v| supported_versions::encode_client(v).unwrap(),
            |b| supported_versions::parse_client(b).ok(),
        );
    }
    if let Ok(s) = psk::Strict::parse(b) {
        again(s, |s| s.encode().unwrap(), |b| psk::Strict::parse(b).ok());
    }
    if let Ok(o) = psk::Offer::parse(b) {
        let n = o.identities().take(64).filter(Result::is_ok).count();
        let _ = o.binder(n);
    }
    if let Ok(r) = status_request::parse(b) {
        again(
            r,
            |r| status_request::encode(r).unwrap(),
            |b| status_request::parse(b).ok(),
        );
    }
    if let Ok(o) = use_srtp::parse_client(b) {
        again(
            o,
            |o| use_srtp::encode_client(o).unwrap(),
            |b| use_srtp::parse_client(b).ok(),
        );
    }
    if let Ok(t) = cert_type::parse_client(b) {
        again(
            t,
            |t| cert_type::encode_client(t).unwrap(),
            |b| cert_type::parse_client(b).ok(),
        );
    }
    if let Ok(a) = compress_certificate::parse(b) {
        again(
            a,
            |a| compress_certificate::encode(a).unwrap(),
            |b| compress_certificate::parse(b).ok(),
        );
    }
    if let Ok(f) = ec_point_formats::parse_client(b) {
        again(
            f,
            |f| ec_point_formats::encode(f).unwrap(),
            |b| ec_point_formats::parse_client(b).ok(),
        );
    }
    if let Ok(c) = cookie::parse(b) {
        again(c, |c| cookie::encode(c).unwrap(), |b| cookie::parse(b).ok());
    }
    if let Ok(f) = renegotiate::parse_server(b) {
        again(
            f,
            |f| renegotiate::encode(f).unwrap(),
            |b| renegotiate::parse_server(b).ok(),
        );
    }
    if let Ok(m) = early_data::parse_ticket(b) {
        again(
            m,
            |m| early_data::encode_ticket(*m).unwrap(),
            |b| early_data::parse_ticket(b).ok(),
        );
    }
    if let Ok(m) = psk_key_exchange_modes::parse(b) {
        again(
            m,
            |m| psk_key_exchange_modes::encode(m).unwrap(),
            |b| psk_key_exchange_modes::parse(b).ok(),
        );
    }
    if let Ok(n) = certificate_authorities::parse(b) {
        again(
            n,
            |n| certificate_authorities::encode(n).unwrap(),
            |b| certificate_authorities::parse(b).ok(),
        );
    }
    if let Ok(raw) = ext::signature_algorithms::parse(b) {
        if let Some(list) = ext::u16_list(&raw) {
            let enc = ext::signature_algorithms::encode(&list).unwrap();
            assert_eq!(ext::signature_algorithms::parse(&enc).ok(), Some(raw));
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    let cx = context(sel);
    for typ in 0..=u8::MAX {
        let Ok(m) = HandshakeMessage::decode(typ, body, &cx) else {
            continue;
        };
        let enc = m.encode_body().expect("a decoded message encodes");
        let back = HandshakeMessage::decode(typ, &enc, &cx).expect("a re-encoded message decodes");
        assert_eq!(back, m, "a message that doesn't survive re-encoding");
    }
    // The step-wise certificate reader, to its end.
    if let Ok(mut rd) = CertificateReader::new(body, cx.tls13, cx.from_server) {
        while let Some(Ok(_)) = rd.next_certificate() {
            if cx.tls13 && rd.extensions().is_err() {
                break;
            }
        }
    }
    let _ = ClientHello::parse_v2(body);
    let _ = ClientHello::dtls_cookie(body);
    extensions(body);
});
