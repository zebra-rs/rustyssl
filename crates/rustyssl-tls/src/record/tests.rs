//! The record layer against OpenSSL's TLS 1.3 record vectors, its header checks and their
//! errors, TLS 1.2's AEADs and CBC (every padding length, bad padding and bad MACs failing
//! alike), encrypt-then-MAC, fragmentation, and padding.

#![allow(clippy::arithmetic_side_effects, reason = "test code")]

use super::*;
use crate::testprov::TestProvider;

#[path = "vectors.rs"]
mod vectors;

fn h(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn reason(e: Error) -> (Option<u8>, core::ffi::c_int) {
    (e.alert, e.reason)
}

fn al(a: core::ffi::c_int) -> Option<u8> {
    Some(u8::try_from(a).unwrap())
}

fn tls13_reader(p: &TestProvider, key: &[u8], iv: &[u8]) -> RecordReader {
    let mut r = RecordReader::new(false);
    r.set_protection(
        Mode::Tls13,
        Protection::tls13(p, AeadAlg::Aes128Gcm, key, iv).unwrap(),
    );
    r
}

fn tls13_writer(p: &TestProvider, key: &[u8], iv: &[u8]) -> RecordWriter {
    let mut w = RecordWriter::new(0x0303);
    w.set_protection(
        Mode::Tls13,
        Protection::tls13(p, AeadAlg::Aes128Gcm, key, iv).unwrap(),
    );
    w
}

#[test]
fn tls13_records_match_openssls_vectors_both_ways() {
    let p = TestProvider::new(b"r");
    for (pt, ct, key, iv, seq) in vectors::RECORDS {
        let seq = u64::from_str_radix(seq, 16).unwrap();
        let (pt, ct, key, iv) = (h(pt), h(ct), h(key), h(iv));
        let (ty, data) = pt.split_last().unwrap();
        let mut w = tls13_writer(&p, &key, &iv);
        w.seq = seq;
        let mut out = Vec::new();
        w.write(&p, *ty, data, &mut out).unwrap();
        let mut want = vec![23, 3, 3];
        want.extend_from_slice(&u16::try_from(ct.len()).unwrap().to_be_bytes());
        want.extend_from_slice(&ct);
        assert_eq!(out, want);

        let mut r = tls13_reader(&p, &key, &iv);
        r.seq = seq;
        let Read::Record { consumed, record } = r.read(&p, &out).unwrap() else {
            panic!()
        };
        assert_eq!(consumed, out.len());
        assert_eq!(record.content_type, *ty);
        assert_eq!(record.data, data);
        assert!(record.inner);
        assert_eq!(record.header, &want[..5]);
    }
}

#[test]
fn tls13_tampering_fails_as_a_bad_record_mac() {
    let p = TestProvider::new(b"t");
    let (key, iv) = ([7u8; 16], [9u8; 12]);
    let mut w = tls13_writer(&p, &key, &iv);
    let mut rec = Vec::new();
    w.write(&p, handshake(), b"hello", &mut rec).unwrap();
    let bad = (
        Some(octet(abi::SSL_AD_BAD_RECORD_MAC)),
        abi::SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC,
    );
    for i in 5..rec.len() {
        let mut t = rec.clone();
        t[i] ^= 1;
        assert_eq!(
            reason(tls13_reader(&p, &key, &iv).read(&p, &t).unwrap_err()),
            bad,
            "octet {i}"
        );
    }
    // The header is the AAD.
    let mut t = rec.clone();
    t[1] = 3;
    t[2] = 3;
    t[4] ^= 0;
    assert!(tls13_reader(&p, &key, &iv).read(&p, &t).is_ok());
    // Shorter than a tag and a type.
    let short = [23, 3, 3, 0, 16]
        .iter()
        .chain(&[0u8; 16])
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(
        reason(tls13_reader(&p, &key, &iv).read(&p, &short).unwrap_err()),
        bad
    );
    // The wrong sequence number: the second record read first.
    let mut two = Vec::new();
    w.write(&p, handshake(), b"next", &mut two).unwrap();
    assert_eq!(
        reason(tls13_reader(&p, &key, &iv).read(&p, &two).unwrap_err()),
        bad
    );
}

#[test]
fn tls13_inner_types_and_padding() {
    let p = TestProvider::new(b"i");
    let (key, iv) = ([1u8; 16], [2u8; 12]);
    let mut w = tls13_writer(&p, &key, &iv);
    w.padding = Padding::Block(64, 32);
    let mut out = Vec::new();
    w.write(&p, application_data(), b"abc", &mut out).unwrap();
    // 3 octets of data and the type, padded to 64, plus the tag.
    assert_eq!(out.len(), 5 + 64 + 16);
    w.write(&p, handshake(), b"x", &mut out).unwrap();
    let mut r = tls13_reader(&p, &key, &iv);
    let Read::Record { consumed, record } = r.read(&p, &out).unwrap() else {
        panic!()
    };
    assert_eq!(
        (record.content_type, &record.data[..]),
        (application_data(), &b"abc"[..])
    );
    let Read::Record { record, .. } = r.read(&p, &out[consumed..]).unwrap() else {
        panic!()
    };
    assert_eq!(
        (record.content_type, &record.data[..]),
        (handshake(), &b"x"[..])
    );

    // Exact padding (a callback's answer), capped at the fragment limit.
    let mut w = tls13_writer(&p, &key, &iv);
    w.padding = Padding::Exact(10);
    let mut out = Vec::new();
    w.write(&p, application_data(), b"abc", &mut out).unwrap();
    assert_eq!(out.len(), 5 + 4 + 10 + 16);

    // An all-zero plaintext has no type: OpenSSL takes the first octet, 0.
    let mut w = tls13_writer(&p, &key, &iv);
    let mut out = Vec::new();
    w.write(&p, 0, &[0, 0], &mut out).unwrap();
    let e = tls13_reader(&p, &key, &iv).read(&p, &out).unwrap_err();
    assert_eq!(
        reason(e),
        (
            al(abi::SSL_AD_UNEXPECTED_MESSAGE),
            abi::SSL_R_BAD_RECORD_TYPE
        )
    );
    // An empty handshake record.
    let mut w = tls13_writer(&p, &key, &iv);
    let mut out = Vec::new();
    w.write(&p, handshake(), &[], &mut out).unwrap();
    let e = tls13_reader(&p, &key, &iv).read(&p, &out).unwrap_err();
    assert_eq!(
        reason(e),
        (al(abi::SSL_AD_UNEXPECTED_MESSAGE), abi::SSL_R_BAD_LENGTH)
    );
    // An inner type that isn't allowed (ChangeCipherSpec).
    let mut w = tls13_writer(&p, &key, &iv);
    let mut out = Vec::new();
    w.write(&p, change_cipher_spec(), &[1], &mut out).unwrap();
    let e = tls13_reader(&p, &key, &iv).read(&p, &out).unwrap_err();
    assert_eq!(
        reason(e),
        (
            al(abi::SSL_AD_UNEXPECTED_MESSAGE),
            abi::SSL_R_BAD_RECORD_TYPE
        )
    );
    // Empty application data is fine, up to 32 in a row.
    let mut w = tls13_writer(&p, &key, &iv);
    let mut out = Vec::new();
    for _ in 0..33 {
        w.write(&p, application_data(), &[], &mut out).unwrap();
    }
    let mut r = tls13_reader(&p, &key, &iv);
    let mut off = 0;
    for _ in 0..32 {
        let Read::Record { consumed, record } = r.read(&p, &out[off..]).unwrap() else {
            panic!()
        };
        assert!(record.data.is_empty());
        off += consumed;
    }
    let e = r.read(&p, &out[off..]).unwrap_err();
    assert_eq!(
        reason(e),
        (
            al(abi::SSL_AD_UNEXPECTED_MESSAGE),
            abi::SSL_R_RECORD_TOO_SMALL
        )
    );
}

#[test]
fn tls13_outer_header_checks() {
    let p = TestProvider::new(b"o");
    let mut r = tls13_reader(&p, &[0; 16], &[0; 12]);
    let e = r.read(&p, &[22, 3, 3, 0, 1, 0]).unwrap_err();
    assert_eq!(
        reason(e),
        (
            al(abi::SSL_AD_UNEXPECTED_MESSAGE),
            abi::SSL_R_BAD_RECORD_TYPE
        )
    );
    let e = r.read(&p, &[23, 3, 1, 0, 1, 0]).unwrap_err();
    assert_eq!(
        reason(e),
        (
            al(abi::SSL_AD_DECODE_ERROR),
            abi::SSL_R_WRONG_VERSION_NUMBER
        )
    );
    let e = r.read(&p, &[23, 3, 3, 0x41, 0x01]).unwrap_err();
    assert_eq!(
        reason(e),
        (
            al(abi::SSL_AD_RECORD_OVERFLOW),
            abi::SSL_R_ENCRYPTED_LENGTH_TOO_LONG
        )
    );
    // A plaintext alert where one is allowed.
    let e = r.read(&p, &[21, 3, 3, 0, 2, 2, 40]).unwrap_err();
    assert_eq!(
        reason(e),
        (
            al(abi::SSL_AD_UNEXPECTED_MESSAGE),
            abi::SSL_R_BAD_RECORD_TYPE
        )
    );
    r.allow_plain_alerts = true;
    let Read::Record { record, .. } = r.read(&p, &[21, 3, 3, 0, 2, 2, 40]).unwrap() else {
        panic!()
    };
    assert_eq!(
        (record.content_type, &record.data[..]),
        (alert(), &[2u8, 40][..])
    );

    // Compatibility ChangeCipherSpec: exactly one octet 0x01, ignored, while the handshake runs.
    let mut r = tls13_reader(&p, &[0; 16], &[0; 12]);
    assert_eq!(
        r.read(&p, &[20, 3, 3, 0, 1, 1]).unwrap(),
        Read::IgnoredCcs {
            consumed: 6,
            header: vec![20, 3, 3, 0, 1]
        }
    );
    let e = r.read(&p, &[20, 3, 3, 0, 1, 2]).unwrap_err();
    assert_eq!(
        reason(e),
        (
            al(abi::SSL_AD_UNEXPECTED_MESSAGE),
            abi::SSL_R_INVALID_CCS_MESSAGE
        )
    );
    let mut r = tls13_reader(&p, &[0; 16], &[0; 12]);
    for _ in 0..32 {
        r.read(&p, &[20, 3, 3, 0, 1, 1]).unwrap();
    }
    let e = r.read(&p, &[20, 3, 3, 0, 1, 1]).unwrap_err();
    assert_eq!(
        reason(e),
        (
            al(abi::SSL_AD_UNEXPECTED_MESSAGE),
            abi::SSL_R_UNEXPECTED_CCS_MESSAGE
        )
    );
    let mut r = tls13_reader(&p, &[0; 16], &[0; 12]);
    r.first_handshake = false;
    let e = r.read(&p, &[20, 3, 3, 0, 1, 1]).unwrap_err();
    assert_eq!(
        reason(e),
        (
            al(abi::SSL_AD_UNEXPECTED_MESSAGE),
            abi::SSL_R_BAD_RECORD_TYPE
        )
    );
}

#[test]
fn plaintext_header_checks() {
    let p = TestProvider::new(b"h");
    let mut r = RecordReader::new(true);
    assert_eq!(r.read(&p, &[22, 3, 1]).unwrap(), Read::NeedMore(5));
    assert_eq!(r.read(&p, &[22, 3, 1, 0, 4, 1]).unwrap(), Read::NeedMore(9));
    for (input, want) in [
        (&b"GET / HTTP/1.1"[..], abi::SSL_R_HTTP_REQUEST),
        (b"POST /x", abi::SSL_R_HTTP_REQUEST),
        (b"PUT /x", abi::SSL_R_HTTP_REQUEST),
        (b"CONNECT host", abi::SSL_R_HTTPS_PROXY_REQUEST),
        (b"\x16\x04\x01\x00\x01", abi::SSL_R_WRONG_VERSION_NUMBER),
    ] {
        let e = RecordReader::new(true).read(&p, input).unwrap_err();
        assert_eq!(reason(e), (None, want), "{input:?}");
    }
    // Not the first record: an alert this time.
    let mut r = RecordReader::new(true);
    r.read(&p, &[22, 3, 1, 0, 1, 1]).unwrap();
    let e = r.read(&p, &[22, 4, 1, 0, 1, 1]).unwrap_err();
    assert_eq!(
        reason(e),
        (
            al(abi::SSL_AD_PROTOCOL_VERSION),
            abi::SSL_R_WRONG_VERSION_NUMBER
        )
    );
    // Version 0x0002 in a TLS header.
    let e = RecordReader::new(false)
        .read(&p, &[22, 0, 2, 0, 1, 1])
        .unwrap_err();
    assert_eq!(
        reason(e),
        (
            al(abi::SSL_AD_PROTOCOL_VERSION),
            abi::SSL_R_WRONG_VERSION_NUMBER
        )
    );
    // Over 2^14 in the clear.
    let e = RecordReader::new(false)
        .read(&p, &[22, 3, 1, 0x40, 0x01])
        .unwrap_err();
    assert_eq!(
        reason(e),
        (
            al(abi::SSL_AD_RECORD_OVERFLOW),
            abi::SSL_R_DATA_LENGTH_TOO_LONG
        )
    );
    // Once the version is known, it must match; a mismatched alert ends quietly.
    let mut r = RecordReader::new(false);
    r.set_plain_version(Some(0x0303));
    let e = r.read(&p, &[22, 3, 1, 0, 1, 1]).unwrap_err();
    assert_eq!(
        reason(e),
        (
            al(abi::SSL_AD_PROTOCOL_VERSION),
            abi::SSL_R_WRONG_VERSION_NUMBER
        )
    );
    let e = r.read(&p, &[21, 3, 1, 0, 2, 2, 70]).unwrap_err();
    assert_eq!(reason(e), (None, abi::SSL_R_WRONG_VERSION_NUMBER));
    // After a HelloRetryRequest (TLS 1.3 plaintext), the version is ignored.
    let mut r = RecordReader::new(true);
    r.set_plain_version(Some(0x0304));
    assert!(matches!(
        r.read(&p, &[22, 3, 1, 0, 1, 1]).unwrap(),
        Read::Record { .. }
    ));
}

#[test]
fn sslv2_client_hellos_are_recognised_on_a_server_only() {
    let p = TestProvider::new(b"v2");
    let mut v2 = vec![0x80, 11, 1, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    let Read::Record { consumed, record } = RecordReader::new(true).read(&p, &v2).unwrap() else {
        panic!()
    };
    assert_eq!(consumed, 13);
    assert_eq!(record.version, SSL2_VERSION);
    assert_eq!(record.content_type, handshake());
    assert_eq!(record.data, &v2[2..]);
    // Too short for a ClientHello.
    v2[1] = 8;
    let e = RecordReader::new(true).read(&p, &v2).unwrap_err();
    assert_eq!(
        reason(e),
        (al(abi::SSL_AD_DECODE_ERROR), abi::SSL_R_LENGTH_TOO_SHORT)
    );
    // A client takes it as a TLS header with a bad version.
    let e = RecordReader::new(false).read(&p, &v2).unwrap_err();
    assert_eq!(reason(e), (None, abi::SSL_R_WRONG_VERSION_NUMBER));
}

#[test]
fn a_small_fragment_limit_caps_what_is_read() {
    let p = TestProvider::new(b"m");
    let mut r = RecordReader::new(false);
    r.max_frag_len = 512;
    // 512 + 332 octets of buffer leave room for 839.
    let e = r.read(&p, &[22, 3, 1, 0x03, 0x48]).unwrap_err();
    assert_eq!(
        reason(e),
        (
            al(abi::SSL_AD_RECORD_OVERFLOW),
            abi::SSL_R_PACKET_LENGTH_TOO_LONG
        )
    );
    let mut rec = vec![22, 3, 1, 0x02, 0x01];
    rec.extend_from_slice(&[0; 513]);
    let e = r.read(&p, &rec).unwrap_err();
    assert_eq!(
        reason(e),
        (
            al(abi::SSL_AD_RECORD_OVERFLOW),
            abi::SSL_R_DATA_LENGTH_TOO_LONG
        )
    );
    r.default_read_len = 20000;
    assert!(r.read(&p, &[22, 3, 1, 0x03, 0x48]).unwrap() == Read::NeedMore(845));
}

/// A TLS 1.2 writer and reader pair over the same keys.
fn pair12(
    _p: &TestProvider,
    make: &dyn Fn(bool) -> Protection,
    version: u16,
) -> (RecordWriter, RecordReader) {
    let mut w = RecordWriter::new(version);
    w.set_protection(Mode::Tls12(version), make(true));
    let mut r = RecordReader::new(true);
    r.set_protection(Mode::Tls12(version), make(false));
    (w, r)
}

fn round_trip(p: &TestProvider, w: &mut RecordWriter, r: &mut RecordReader, data: &[u8]) {
    let mut out = Vec::new();
    w.write(p, application_data(), data, &mut out).unwrap();
    let mut off = 0;
    let mut got = Vec::new();
    while off < out.len() {
        let Read::Record { consumed, record } = r.read(p, &out[off..]).unwrap() else {
            panic!()
        };
        got.extend_from_slice(&record.data);
        off += consumed;
    }
    assert_eq!(got, data);
}

#[test]
fn tls12_aeads_round_trip_and_fail_on_tampering() {
    let p = TestProvider::new(b"a");
    for alg in [
        AeadAlg::Aes128Gcm,
        AeadAlg::Aes256Gcm,
        AeadAlg::ChaCha20Poly1305,
        AeadAlg::Aes128Ccm,
        AeadAlg::Aes128Ccm8,
        AeadAlg::Aes256Ccm,
    ] {
        let key = vec![3u8; alg.key_len()];
        let iv = if alg == AeadAlg::ChaCha20Poly1305 {
            vec![4u8; 12]
        } else {
            vec![4u8; 4]
        };
        let make = |_| Protection::aead12(&p, alg, &key, &iv, 0x0102_0304_0506_0708).unwrap();
        let (mut w, mut r) = pair12(&p, &make, 0x0303);
        for len in [0usize, 1, 100, 16384] {
            round_trip(&p, &mut w, &mut r, &vec![0x5a; len]);
        }
        let (mut w, _) = pair12(&p, &make, 0x0303);
        let mut out = Vec::new();
        w.write(&p, application_data(), b"data", &mut out).unwrap();
        let explicit = if alg == AeadAlg::ChaCha20Poly1305 {
            0
        } else {
            8
        };
        assert_eq!(out.len(), 5 + explicit + 4 + alg.tag_len(), "{alg:?}");
        for i in 5..out.len() {
            let mut t = out.clone();
            t[i] ^= 0x80;
            let (_, mut r2) = pair12(&p, &make, 0x0303);
            let e = r2.read(&p, &t).unwrap_err();
            assert_eq!(
                reason(e),
                (
                    al(abi::SSL_AD_BAD_RECORD_MAC),
                    abi::SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC
                ),
                "{alg:?} {i}"
            );
        }
        // Too short for the explicit nonce and the tag.
        let mut short = vec![
            23,
            3,
            3,
            0,
            u8::try_from(explicit + alg.tag_len() - 1).unwrap(),
        ];
        short.resize(5 + explicit + alg.tag_len() - 1, 0);
        let mut r2 = RecordReader::new(true);
        r2.set_protection(Mode::Tls12(0x0303), make(false));
        let e = r2.read(&p, &short).unwrap_err();
        assert_eq!(e.reason, abi::SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
    }
}

#[test]
fn tls12_protected_headers_must_carry_the_version() {
    let p = TestProvider::new(b"v");
    let make = |_| Protection::aead12(&p, AeadAlg::Aes128Gcm, &[1; 16], &[2; 4], 0).unwrap();
    let (_, mut r) = pair12(&p, &make, 0x0303);
    let e = r.read(&p, &[23, 3, 1, 0, 1, 0]).unwrap_err();
    assert_eq!(
        reason(e),
        (
            al(abi::SSL_AD_PROTOCOL_VERSION),
            abi::SSL_R_WRONG_VERSION_NUMBER
        )
    );
    let e = r.read(&p, &[23, 3, 3, 0x41, 0x41]).unwrap_err();
    assert_eq!(
        reason(e),
        (
            al(abi::SSL_AD_RECORD_OVERFLOW),
            abi::SSL_R_ENCRYPTED_LENGTH_TOO_LONG
        )
    );
    // 16704 is the limit (no compression overhead).
    assert_eq!(
        r.read(&p, &[23, 3, 3, 0x41, 0x40]).unwrap(),
        Read::NeedMore(5 + 0x4140)
    );
}

/// The CBC suites' shapes: cipher, MAC hash.
const CBC: [(CipherAlg, HashAlg); 5] = [
    (CipherAlg::Aes128Cbc, HashAlg::Sha1),
    (CipherAlg::Aes256Cbc, HashAlg::Sha384),
    (CipherAlg::Aes128Cbc, HashAlg::Sha256),
    (CipherAlg::DesEde3Cbc, HashAlg::Sha1),
    (CipherAlg::Camellia128Cbc, HashAlg::Sha256),
];

fn cbc_make<'a>(
    p: &'a TestProvider,
    alg: CipherAlg,
    mac: HashAlg,
    version: u16,
    etm: bool,
) -> impl Fn(bool) -> Protection + 'a {
    move |enc| {
        let key = vec![0x11u8; alg.key_len()];
        let iv = vec![0x22u8; alg.block_len()];
        Protection::cbc12(
            p,
            alg,
            &key,
            &iv,
            mac,
            &[0x33; 48][..mac.len()],
            version,
            etm,
            enc,
        )
        .unwrap()
    }
}

#[test]
fn cbc_round_trips_in_every_version_and_mode() {
    let p = TestProvider::new(b"c");
    for (alg, mac) in CBC {
        for version in [0x0301u16, 0x0302, 0x0303] {
            for etm in [false, true] {
                let make = cbc_make(&p, alg, mac, version, etm);
                let (mut w, mut r) = pair12(&p, &make, version);
                for len in [0usize, 1, 15, 16, 17, 1000, 16384] {
                    round_trip(&p, &mut w, &mut r, &vec![0xa5; len]);
                }
            }
        }
    }
    // The NULL cipher (a MAC only).
    let make = |_| {
        Protection::cbc12(
            &p,
            CipherAlg::Null,
            &[],
            &[],
            HashAlg::Sha256,
            &[9; 32],
            0x0303,
            false,
            true,
        )
        .unwrap()
    };
    let (mut w, mut r) = pair12(&p, &make, 0x0303);
    round_trip(&p, &mut w, &mut r, b"in the clear");
    let mut out = Vec::new();
    w.write(&p, application_data(), b"plain", &mut out).unwrap();
    assert_eq!(&out[5..10], b"plain");
    out[6] ^= 1;
    assert_eq!(
        r.read(&p, &out).unwrap_err().reason,
        abi::SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC
    );
}

/// A MAC-then-encrypt record built by hand: `data`, its MAC (corrupted if `bad_mac`), and
/// `pad` octets of padding whose values are `pad - 1` except where `bad_pad_at` says.
fn mte_record(
    p: &TestProvider,
    alg: CipherAlg,
    mac: HashAlg,
    data: &[u8],
    bad_mac: bool,
    pad: usize,
    bad_pad_at: Option<usize>,
) -> Vec<u8> {
    let header = mac_header(0, application_data(), 0x0303, data.len()).unwrap();
    let mut tag =
        crate::keysched::hmac(p, mac, &[0x33; 48][..mac.len()], &[&header, data]).unwrap();
    if bad_mac {
        tag[0] ^= 1;
    }
    let mut plain = [data, &tag].concat();
    let v = u8::try_from(pad - 1).unwrap();
    plain.extend(std::iter::repeat_n(v, pad));
    if let Some(i) = bad_pad_at {
        let n = plain.len();
        plain[n - 1 - i] ^= 0x40;
    }
    let iv = vec![0x44u8; alg.block_len()];
    let mut c = p.cipher(alg, &vec![0x11u8; alg.key_len()], true).unwrap();
    c.crypt(&iv, &mut plain).unwrap();
    let body = [iv, plain].concat();
    let mut rec = vec![23, 3, 3];
    rec.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    rec.extend_from_slice(&body);
    rec
}

#[test]
fn cbc_padding_of_every_length_and_every_failure_look_alike() {
    let p = TestProvider::new(b"pad");
    let bad = (
        al(abi::SSL_AD_BAD_RECORD_MAC),
        abi::SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC,
    );
    for (alg, mac) in [
        (CipherAlg::Aes128Cbc, HashAlg::Sha1),
        (CipherAlg::Aes256Cbc, HashAlg::Sha384),
        (CipherAlg::DesEde3Cbc, HashAlg::Sha256),
    ] {
        let bs = alg.block_len();
        let make = cbc_make(&p, alg, mac, 0x0303, false);
        let reader = || {
            let mut r = RecordReader::new(true);
            r.set_protection(Mode::Tls12(0x0303), make(false));
            r
        };
        for data_len in [0usize, 5, 40] {
            let data = vec![0x61u8; data_len];
            let base = data_len + mac.len();
            // Every padding length that fills to a block boundary, up to 256.
            for pad in (1..=256).filter(|pad| (base + pad) % bs == 0) {
                let rec = mte_record(&p, alg, mac, &data, false, pad, None);
                let Read::Record { record, .. } = reader().read(&p, &rec).unwrap() else {
                    panic!()
                };
                assert_eq!(record.data, data, "{alg:?} pad {pad}");
                // A bad MAC, and a bad padding octet at each position: the same error.
                assert_eq!(
                    reason(
                        reader()
                            .read(&p, &mte_record(&p, alg, mac, &data, true, pad, None))
                            .unwrap_err()
                    ),
                    bad
                );
                for at in [0, pad / 2, pad - 1] {
                    let rec = mte_record(&p, alg, mac, &data, false, pad, Some(at));
                    assert_eq!(
                        reason(reader().read(&p, &rec).unwrap_err()),
                        bad,
                        "{alg:?} pad {pad} at {at}"
                    );
                }
            }
        }
        // Publicly invalid: not whole blocks, or no room for the MAC.
        let mut rec = mte_record(&p, alg, mac, b"x", false, bs - (1 + mac.len()) % bs, None);
        rec.pop();
        let n = u16::try_from(rec.len() - 5).unwrap().to_be_bytes();
        rec[3] = n[0];
        rec[4] = n[1];
        assert_eq!(reason(reader().read(&p, &rec).unwrap_err()), bad);
        let mut tiny = vec![23, 3, 3, 0, u8::try_from(2 * bs).unwrap()];
        tiny.resize(5 + 2 * bs, 0);
        assert_eq!(reason(reader().read(&p, &tiny).unwrap_err()), bad);
    }
}

#[test]
fn encrypt_then_mac_checks_the_mac_first() {
    let p = TestProvider::new(b"etm");
    let make = cbc_make(&p, CipherAlg::Aes128Cbc, HashAlg::Sha256, 0x0303, true);
    let (mut w, mut r) = pair12(&p, &make, 0x0303);
    let mut out = Vec::new();
    w.write(&p, application_data(), b"etm data", &mut out)
        .unwrap();
    // IV, one block of ciphertext (8 + padding), MAC.
    assert_eq!(out.len(), 5 + 16 + 16 + 32);
    let mut t = out.clone();
    t[20] ^= 1;
    assert_eq!(
        r.read(&p, &t).unwrap_err().reason,
        abi::SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC
    );
    // Shorter than the MAC.
    let mut r2 = RecordReader::new(true);
    r2.set_protection(Mode::Tls12(0x0303), make(false));
    let e = r2.read(&p, &[23, 3, 3, 0, 4, 1, 2, 3, 4]).unwrap_err();
    assert_eq!(
        reason(e),
        (al(abi::SSL_AD_DECODE_ERROR), abi::SSL_R_LENGTH_TOO_SHORT)
    );
    let mut r3 = RecordReader::new(true);
    r3.set_protection(Mode::Tls12(0x0303), make(false));
    assert!(r3.read(&p, &out).is_ok());
    let _ = &mut r;
}

#[test]
fn writes_fragment_and_tls10_cbc_sends_an_empty_fragment_first() {
    let p = TestProvider::new(b"f");
    let mut w = RecordWriter::new(0x0303);
    let mut out = Vec::new();
    w.write(&p, application_data(), &vec![1u8; 40000], &mut out)
        .unwrap();
    assert_eq!(out.len(), 3 * 5 + 40000);
    assert_eq!(&out[3..5], &16384u16.to_be_bytes());
    let mut w = RecordWriter::new(0x0303);
    w.max_frag_len = 512;
    let mut out = Vec::new();
    w.write(&p, handshake(), &vec![1u8; 1025], &mut out)
        .unwrap();
    assert_eq!(out.len(), 3 * 5 + 1025);
    let mut out = Vec::new();
    w.write(&p, alert(), &[], &mut out).unwrap();
    assert_eq!(out, [21, 3, 3, 0, 0]);

    let make = cbc_make(&p, CipherAlg::Aes128Cbc, HashAlg::Sha1, 0x0301, false);
    let (mut w, mut r) = pair12(&p, &make, 0x0301);
    w.empty_fragments = true;
    let mut out = Vec::new();
    w.write(&p, application_data(), b"hi", &mut out).unwrap();
    // An empty record (MAC + padding: 32 octets), then the data's (2 + 20 + padding: 32).
    assert_eq!(out.len(), 5 + 32 + 5 + 32);
    let Read::Record { consumed, record } = r.read(&p, &out).unwrap() else {
        panic!()
    };
    assert!(record.data.is_empty());
    let Read::Record { record, .. } = r.read(&p, &out[consumed..]).unwrap() else {
        panic!()
    };
    assert_eq!(record.data, b"hi");
}

#[test]
fn integrity_only_tls13_records_carry_their_plaintext() {
    let p = TestProvider::new(b"int");
    let prot = || Protection::Tls13Integrity {
        hash: HashAlg::Sha256,
        key: Secret::new(vec![5; 32]),
        iv: Secret::new(vec![6; 32]),
    };
    let mut w = RecordWriter::new(0x0303);
    w.set_protection(Mode::Tls13, prot());
    let mut out = Vec::new();
    w.write(&p, application_data(), b"visible", &mut out)
        .unwrap();
    assert_eq!(&out[5..12], b"visible");
    assert_eq!(out.len(), 5 + 7 + 1 + 32);
    let mut r = RecordReader::new(false);
    r.set_protection(Mode::Tls13, prot());
    let Read::Record { record, .. } = r.read(&p, &out).unwrap() else {
        panic!()
    };
    assert_eq!(
        (record.content_type, &record.data[..]),
        (application_data(), &b"visible"[..])
    );
    out[6] ^= 1;
    let mut r = RecordReader::new(false);
    r.set_protection(Mode::Tls13, prot());
    assert_eq!(
        r.read(&p, &out).unwrap_err().reason,
        abi::SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC
    );
}

#[test]
fn the_sequence_number_never_wraps() {
    let p = TestProvider::new(b"s");
    let mut w = tls13_writer(&p, &[0; 16], &[0; 12]);
    w.seq = u64::MAX;
    let e = w
        .write(&p, application_data(), b"x", &mut Vec::new())
        .unwrap_err();
    assert_eq!(
        reason(e),
        (
            al(abi::SSL_AD_INTERNAL_ERROR),
            abi::SSL_R_SEQUENCE_CTR_WRAPPED
        )
    );
}

#[test]
fn constant_time_masks() {
    for (a, b) in [
        (0usize, 0usize),
        (1, 0),
        (0, 1),
        (usize::MAX, 0),
        (5, 5),
        (300, 256),
    ] {
        assert_eq!(ct_ge(a, b) == usize::MAX, a >= b, "{a} {b}");
        assert_eq!(ct_lt(a, b) == usize::MAX, a < b);
        assert_eq!(ct_eq_s(a, b) == usize::MAX, a == b);
    }
}

#[test]
fn errors_name_the_record_layer_function_openssl_raises_them_from() {
    let p = TestProvider::new(b"f");
    let first = |input: &[u8]| RecordReader::new(true).read(&p, input).unwrap_err();
    // The plaintext method's header checks (`tlsany_meth`).
    assert_eq!(
        first(b"GET / HTTP/1.1").func,
        Some("tls_validate_record_header")
    );
    assert_eq!(
        first(&[22, 3, 1, 0x40, 0x01]).func,
        Some("tls_validate_record_header")
    );
    // SSLv2's version in a TLS header is the driver's.
    let e = RecordReader::new(false)
        .read(&p, &[22, 0, 2, 0, 1, 1])
        .unwrap_err();
    assert_eq!(e.func, Some("tls_get_more_records"));
    // TLS 1.2's and TLS 1.3's header checks.
    let make = |_| Protection::aead12(&p, AeadAlg::Aes128Gcm, &[1; 16], &[2; 4], 0).unwrap();
    let (_, mut r) = pair12(&p, &make, 0x0303);
    let e = r.read(&p, &[23, 3, 1, 0, 1, 0]).unwrap_err();
    assert_eq!(e.func, Some("tls_default_validate_record_header"));
    let mut r = tls13_reader(&p, &[1; 16], &[2; 12]);
    let e = r.read(&p, &[23, 3, 1, 0, 1, 0]).unwrap_err();
    assert_eq!(e.func, Some("tls13_validate_record_header"));
    // A bad tag is the driver's, under the provider's entry for GCM and CCM (TLS 1.2) only.
    for (alg, cause) in [
        (AeadAlg::Aes128Gcm, Some("ossl_gcm_stream_update")),
        (AeadAlg::Aes128Ccm, Some("ossl_ccm_stream_update")),
        (AeadAlg::ChaCha20Poly1305, None),
    ] {
        let key = vec![3u8; alg.key_len()];
        let iv = vec![
            4u8;
            if alg == AeadAlg::ChaCha20Poly1305 {
                12
            } else {
                4
            }
        ];
        let make = |_| Protection::aead12(&p, alg, &key, &iv, 7).unwrap();
        let (mut w, mut r) = pair12(&p, &make, 0x0303);
        let mut out = Vec::new();
        w.write(&p, application_data(), b"data", &mut out).unwrap();
        *out.last_mut().unwrap() ^= 1;
        let e = r.read(&p, &out).unwrap_err();
        assert_eq!(e.func, Some("tls_get_more_records"), "{alg:?}");
        let want = cause.map(|func| Cause {
            lib: abi::ERR_LIB_PROV,
            reason: abi::PROV_R_CIPHER_OPERATION_FAILED,
            func,
        });
        assert_eq!(e.cause, want, "{alg:?}");
    }
    // TLS 1.3 checks the tag in the final step, which raises nothing of its own.
    let mut r = tls13_reader(&p, &[1; 16], &[2; 12]);
    let mut bad = vec![23, 3, 3, 0, 17];
    bad.resize(22, 0);
    let e = r.read(&p, &bad).unwrap_err();
    assert_eq!((e.func, e.cause), (Some("tls_get_more_records"), None));
}

/// A stitched cipher that encrypts nothing, as OpenSSL's ossltest engine's: sealing writes a
/// known MAC and real padding; opening accepts anything, so the record layer's own length
/// checks are what stand.
struct FakeStitched {
    payload: Option<usize>,
}

impl crate::crypto::Stitched for FakeStitched {
    fn seal(&mut self, header: &[u8; 13], body: &mut Vec<u8>) -> Result<()> {
        let len = usize::from(u16::from_be_bytes([header[11], header[12]]));
        assert_eq!(len, body.len());
        let total = (len + 20 + 16) & !15;
        let pad = u8::try_from(total - len - 20 - 1).unwrap();
        body.extend_from_slice(&[0xaa; 20]);
        body.resize(total, pad);
        self.payload = Some(len);
        Ok(())
    }

    fn open(&mut self, _header: &[u8; 13], _body: &mut [u8]) -> Result<usize> {
        Ok(20)
    }
}

fn stitched(version: u16) -> impl Fn(bool) -> Protection {
    move |_| Protection::Stitched12 {
        stitched: Box::new(FakeStitched { payload: None }),
        block_len: 16,
        mac_len: 20,
        explicit_iv: version >= 0x0302,
    }
}

#[test]
fn a_stitched_cipher_carries_records_in_every_version() {
    let p = TestProvider::new(b"s");
    for version in [0x0301u16, 0x0302, 0x0303] {
        let make = stitched(version);
        let (mut w, mut r) = pair12(&p, &make, version);
        for len in [0usize, 1, 15, 16, 17, 1000, 16384] {
            round_trip(&p, &mut w, &mut r, &vec![0x5a; len]);
        }
    }
}

#[test]
fn a_stitched_records_lengths_are_checked_where_openssl_trusts_the_cipher() {
    // Padding that claims more than the record holds: OpenSSL subtracts it unchecked (the
    // cipher verified it); here the subtraction is checked, and the record is a bad MAC.
    let p = TestProvider::new(b"s");
    let mut r = RecordReader::new(true);
    r.set_protection(Mode::Tls12(0x0303), stitched(0x0303)(false));
    let mut rec = vec![23, 3, 3, 0, 32];
    rec.extend_from_slice(&[0xff; 32]);
    let e = r.read(&p, &rec).unwrap_err();
    assert_eq!(
        reason(e),
        (
            al(abi::SSL_AD_BAD_RECORD_MAC),
            abi::SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC
        )
    );
    // A body that isn't whole blocks is publicly invalid.
    let mut r = RecordReader::new(true);
    r.set_protection(Mode::Tls12(0x0303), stitched(0x0303)(false));
    let mut rec = vec![23, 3, 3, 0, 17];
    rec.extend_from_slice(&[0; 17]);
    let e = r.read(&p, &rec).unwrap_err();
    assert_eq!(reason(e).0, al(abi::SSL_AD_BAD_RECORD_MAC));
}
