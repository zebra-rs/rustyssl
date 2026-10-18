//! Fuzzes the TLS record layer: the input read as a stream of records under every protection
//! (none, TLS 1.3's AEAD and integrity-only protection, TLS 1.2's AEADs, CBC with
//! MAC-then-encrypt and encrypt-then-MAC in each version, the NULL cipher), for a client and a
//! server, until it needs more input or fails; and the input written as records and read back,
//! which must give it again. Nothing may panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyssl_tls::crypto::{AeadAlg, CipherAlg, HashAlg, Secret};
use rustyssl_tls::record::{Mode, Padding, Protection, Read, RecordReader, RecordWriter};
use rustyssl_tls::testprov::TestProvider;

/// The protections tried, by index, and the mode reading them.
fn protection(p: &TestProvider, which: u8, encrypt: bool) -> (Mode, Protection) {
    let aead = |alg: AeadAlg, iv: usize| {
        Protection::aead12(p, alg, &vec![1u8; alg.key_len()], &vec![2u8; iv], 7).ok()
    };
    let cbc = |alg: CipherAlg, mac: HashAlg, version: u16, etm: bool| {
        Protection::cbc12(
            p,
            alg,
            &vec![3u8; alg.key_len()],
            &vec![4u8; alg.block_len()],
            mac,
            &vec![5u8; mac.len()],
            version,
            etm,
            encrypt,
        )
        .ok()
    };
    let (mode, prot) = match which % 12 {
        0 => (Mode::Plain(None), Some(Protection::Null)),
        1 => (
            Mode::Tls13,
            Protection::tls13(p, AeadAlg::Aes128Gcm, &[6; 16], &[7; 12]).ok(),
        ),
        2 => (
            Mode::Tls13,
            Protection::tls13(p, AeadAlg::ChaCha20Poly1305, &[6; 32], &[7; 12]).ok(),
        ),
        3 => (
            Mode::Tls13,
            Some(Protection::Tls13Integrity {
                hash: HashAlg::Sha256,
                key: Secret::new(vec![8; 32]),
                iv: Secret::new(vec![9; 32]),
            }),
        ),
        4 => (Mode::Tls12(0x0303), aead(AeadAlg::Aes128Gcm, 4)),
        5 => (Mode::Tls12(0x0303), aead(AeadAlg::ChaCha20Poly1305, 12)),
        6 => (Mode::Tls12(0x0303), aead(AeadAlg::Aes128Ccm8, 4)),
        7 => (
            Mode::Tls12(0x0303),
            cbc(CipherAlg::Aes128Cbc, HashAlg::Sha1, 0x0303, false),
        ),
        8 => (
            Mode::Tls12(0x0303),
            cbc(CipherAlg::Aes256Cbc, HashAlg::Sha384, 0x0303, true),
        ),
        9 => (
            Mode::Tls12(0x0301),
            cbc(CipherAlg::DesEde3Cbc, HashAlg::Sha1, 0x0301, false),
        ),
        10 => (
            Mode::Tls12(0x0302),
            cbc(CipherAlg::Camellia128Cbc, HashAlg::Sha256, 0x0302, false),
        ),
        _ => (
            Mode::Tls12(0x0303),
            cbc(CipherAlg::Null, HashAlg::Sha256, 0x0303, false),
        ),
    };
    (mode, prot.unwrap_or(Protection::Null))
}

fuzz_target!(|data: &[u8]| {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    let p = TestProvider::new(b"fuzz");

    // Read the input as it is.
    for server in [false, true] {
        let (mode, prot) = protection(&p, which, false);
        let mut r = RecordReader::new(server);
        if which & 0x80 != 0 {
            r.max_frag_len = 512;
        }
        r.allow_plain_alerts = which & 0x40 != 0;
        r.set_protection(mode, prot);
        let mut off = 0;
        while let Some(input) = rest.get(off..) {
            match r.read(&p, input) {
                Ok(Read::Record { consumed, .. } | Read::IgnoredCcs { consumed, .. })
                    if consumed > 0 =>
                {
                    off += consumed
                }
                _ => break,
            }
        }
    }

    // Write it and read it back.
    let (mode, prot) = protection(&p, which, true);
    let version = match mode {
        Mode::Tls12(v) => v,
        _ => 0x0303,
    };
    let mut w = RecordWriter::new(version);
    w.set_protection(mode, prot);
    w.padding = if which & 0x20 != 0 {
        Padding::Block(32, 16)
    } else {
        Padding::None
    };
    let ty = 23;
    let mut out = Vec::new();
    if w.write(&p, ty, rest, &mut out).is_err() {
        return;
    }
    let (mode, prot) = protection(&p, which, false);
    let mut r = RecordReader::new(true);
    r.set_protection(mode, prot);
    let mut got = Vec::new();
    let mut off = 0;
    while off < out.len() {
        match r.read(&p, &out[off..]) {
            Ok(Read::Record { consumed, record }) => {
                got.extend_from_slice(&record.data);
                off += consumed;
            }
            other => panic!("a record written doesn't read back: {other:?}"),
        }
    }
    assert_eq!(got, rest, "the data changed");
});
