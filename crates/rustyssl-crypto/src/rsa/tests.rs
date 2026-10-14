//! Known answers (`kat.txt`, from the reference OpenSSL and its test data) and round trips.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "test arithmetic on small known values"
)]

use rustyssl_abi::{NID_md4, NID_sha256, NID_sm3};

use super::*;
use crate::bn::{BigNum, Endian};
use crate::md::{self, Algorithm};

/// A digest from the default backend.
struct Md(Algorithm, usize, usize);

impl Hash for Md {
    fn size(&self) -> usize {
        self.1
    }
    fn block_size(&self) -> usize {
        self.2
    }
    fn digest(&self, parts: &[&[u8]]) -> Option<Vec<u8>> {
        let mut c = md::context(self.0);
        for p in parts {
            c.update(p).ok()?;
        }
        let mut out = vec![0; self.1];
        c.finalize(&mut out).ok()?;
        Some(out)
    }
}

const SHA1: Md = Md(Algorithm::Sha1, 20, 64);
const SHA256: Md = Md(Algorithm::Sha256, 32, 64);

/// The entries' reasons and clear flags.
fn rc(raised: &[Entry]) -> Vec<(Reason, u8)> {
    raised.iter().map(|e| (e.reason, e.clear)).collect()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn kat(name: &str) -> String {
    include_str!("kat.txt")
        .lines()
        .find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix(' ')))
        .unwrap()
        .to_owned()
}

fn num(name: &str) -> BigNum {
    let mut h = kat(name);
    if h.len() % 2 == 1 {
        h.insert(0, '0');
    }
    BigNum::from_bin(&hex(&h), Endian::Big, false).unwrap()
}

fn key() -> Key {
    let mut k = Key::new();
    k.n = Some(num("N"));
    k.e = Some(num("E"));
    k.d = Some(num("D"));
    k.p = Some(num("P"));
    k.q = Some(num("Q"));
    k.dmp1 = Some(num("DMP1"));
    k.dmq1 = Some(num("DMQ1"));
    k.iqmp = Some(num("IQMP"));
    k
}

/// A deterministic "random" source.
fn rng() -> impl FnMut(&mut [u8]) -> bool {
    let mut x: u8 = 7;
    move |buf: &mut [u8]| {
        for b in buf.iter_mut() {
            x = x.wrapping_mul(31).wrapping_add(11);
            *b = x;
        }
        true
    }
}

#[test]
fn pkcs1_signature_known_answer() {
    let k = key();
    let mut from = digest_info(NID_sha256).unwrap();
    from.extend_from_slice(&hex(&kat("H256")));
    let mut sig = vec![0; 256];
    let (r, raised) = k.private_encrypt(&from, &mut sig, Padding::Pkcs1, &mut rng());
    assert_eq!((r, rc(&raised)), (Ok(256), vec![]));
    assert_eq!(sig, hex(&kat("SIG_PKCS1")));
    // Verifying recovers the DigestInfo.
    let mut out = vec![0; 256];
    let (r, _) = k.public_decrypt(&sig, &mut out, Padding::Pkcs1);
    assert_eq!(r, Ok(from.len()));
    assert_eq!(&out[..from.len()], &from[..]);
}

#[test]
fn raw_and_x931_known_answers() {
    let k = key();
    let mut sig = vec![0; 256];
    let (r, _) = k.private_encrypt(&[1; 256], &mut sig, Padding::None, &mut rng());
    assert_eq!(r, Ok(256));
    assert_eq!(sig, hex(&kat("SIG_RAW")));
    // Without blinding, and through d alone, the same.
    let mut plain = k.clone();
    plain.blinding = false;
    plain.p = None;
    let mut sig2 = vec![0; 256];
    plain
        .private_encrypt(&[1; 256], &mut sig2, Padding::None, &mut rng())
        .0
        .unwrap();
    assert_eq!(sig2, sig);

    let mut from = hex(&kat("H256"));
    from.push(pad::x931_hash_id(NID_sha256) as u8);
    let (r, _) = k.private_encrypt(&from, &mut sig, Padding::X931, &mut rng());
    assert_eq!(r, Ok(256));
    assert_eq!(sig, hex(&kat("SIG_X931")));
    let mut out = vec![0; 256];
    let (r, _) = k.public_decrypt(&sig, &mut out, Padding::X931);
    assert_eq!(r, Ok(33));
    assert_eq!(&out[..33], &from[..]);
}

#[test]
fn oaep_and_pss_from_the_reference() {
    let k = key();
    let mut out = vec![0xaa; 256];
    let (r, raised) = k.private_decrypt(
        &hex(&kat("CT_OAEP")),
        &mut out,
        Padding::Oaep,
        Some(&SHA1),
        Some(&SHA256),
        &mut rng(),
    );
    assert_eq!(r, 3);
    assert_eq!(&out[..3], b"abc");
    // Both entries are there, cleared.
    assert_eq!(
        raised.iter().map(|e| e.clear).collect::<Vec<_>>(),
        [1, 1],
        "{raised:?}"
    );

    let mut em = vec![0; 256];
    let (r, _) = k.public_decrypt(&hex(&kat("SIG_PSS")), &mut em, Padding::None);
    assert_eq!(r, Ok(256));
    let h = hex(&kat("H256"));
    for slen in [
        32,
        PssSaltLen::AUTO,
        PssSaltLen::DIGEST,
        PssSaltLen::AUTO_DIGEST_MAX,
    ] {
        assert_eq!(verify_pss(&h, &SHA256, &SHA256, &em, 2048, slen).0, Ok(32));
    }
    assert_eq!(
        rc(&verify_pss(&h, &SHA256, &SHA256, &em, 2048, 20).1),
        [(Reason::SlenCheckFailed(Some((20, 32))), 0)]
    );
    let mut bad = h.clone();
    bad[0] ^= 1;
    assert_eq!(
        rc(&verify_pss(&bad, &SHA256, &SHA256, &em, 2048, -2).1),
        [(Reason::BadSignature, 0)]
    );
}

#[test]
fn implicit_rejection_known_answers() {
    let k = key();
    let mut count = 0;
    for line in include_str!("kat.txt").lines() {
        let Some(rest) = line.strip_prefix("DECRYPT ") else {
            continue;
        };
        let (ct, want) = rest.split_once(' ').unwrap();
        let want = if want == "-" { vec![] } else { hex(want) };
        let mut out = vec![0x55; 256];
        let (r, raised) = k.private_decrypt(
            &hex(ct),
            &mut out,
            Padding::Pkcs1,
            Some(&SHA1),
            Some(&SHA256),
            &mut rng(),
        );
        assert_eq!(r, want.len() as isize, "{ct}");
        assert_eq!(&out[..want.len()], &want[..], "{ct}");
        // Never a failure: the check's entry is cleared.
        assert_eq!(rc(&raised), [(Reason::PaddingCheckFailed, 1)]);
        assert_eq!(raised[0].func, "rsa_ossl_private_decrypt");
        count += 1;
    }
    assert_eq!(count, 23);
}

#[test]
fn round_trips() {
    let k = key();
    let msg = b"rustyssl";
    for padding in [
        Padding::Pkcs1,
        Padding::Oaep,
        Padding::Pkcs1NoImplicitReject,
    ] {
        let enc_padding = if padding == Padding::Pkcs1NoImplicitReject {
            Padding::Pkcs1
        } else {
            padding
        };
        let mut ct = vec![0; 256];
        let (r, _) = k.public_encrypt(msg, &mut ct, enc_padding, Some(&SHA1), &mut rng());
        assert_eq!(r, Ok(256));
        let mut out = vec![0; 256];
        let (r, _) = k.private_decrypt(
            &ct,
            &mut out,
            padding,
            Some(&SHA1),
            Some(&SHA256),
            &mut rng(),
        );
        assert_eq!(r, 8, "{padding:?}");
        assert_eq!(&out[..8], msg);
    }
    // PSS with each salt length.
    let h = [7u8; 32];
    for slen in [
        0,
        20,
        PssSaltLen::DIGEST,
        PssSaltLen::AUTO,
        PssSaltLen::MAX,
        PssSaltLen::AUTO_DIGEST_MAX,
    ] {
        let mut em = vec![0; 256];
        let (r, _) = add_pss(&mut em, 2048, &h, &SHA256, &SHA1, slen, &mut rng());
        let used = r.unwrap();
        let back = verify_pss(&h, &SHA256, &SHA1, &em, 2048, PssSaltLen::AUTO).0;
        assert_eq!(back, Ok(used), "{slen}");
    }
    // An odd-sized key: the encoding's top octet is forced.
    let mut em = vec![0; 129];
    let (r, _) = add_pss(
        &mut em,
        1025,
        &h,
        &SHA256,
        &SHA256,
        PssSaltLen::MAX,
        &mut rng(),
    );
    assert_eq!(r, Ok(128 - 32 - 2));
    assert_eq!(em[0], 0);
}

#[test]
fn bad_padding_without_implicit_rejection() {
    let k = key();
    // A ciphertext of the number 2: decrypts to garbage.
    let mut ct = vec![0; 256];
    ct[255] = 2;
    let mut out = vec![0x5a; 256];
    let (r, raised) = k.private_decrypt(
        &ct,
        &mut out,
        Padding::Pkcs1NoImplicitReject,
        Some(&SHA1),
        Some(&SHA256),
        &mut rng(),
    );
    assert_eq!(r, -1);
    assert_eq!(out, vec![0x5a; 256], "the output is untouched");
    assert_eq!(
        rc(&raised),
        [
            (Reason::PkcsDecodingError, 0),
            (Reason::PaddingCheckFailed, 0),
        ]
    );
    assert_eq!(
        raised.iter().map(|e| e.func).collect::<Vec<_>>(),
        ["RSA_padding_check_PKCS1_type_2", "rsa_ossl_private_decrypt"]
    );
    let (r, raised) = k.private_decrypt(
        &ct,
        &mut out,
        Padding::Oaep,
        Some(&SHA1),
        Some(&SHA256),
        &mut rng(),
    );
    assert_eq!(r, -1);
    assert_eq!(rc(&raised)[0], (Reason::OaepDecodingError, 0));
}

#[test]
fn input_and_key_checks() {
    let k = key();
    let mut to = vec![0; 256];
    let r = |o: Outcome<usize>| rc(&o.1);
    assert_eq!(
        r(k.public_encrypt(&[0; 246], &mut to, Padding::Pkcs1, None, &mut rng())),
        [(Reason::DataTooLargeForKeySize, 0)]
    );
    assert_eq!(
        r(k.public_encrypt(&[0xff; 256], &mut to, Padding::None, None, &mut rng())),
        [(Reason::DataTooLargeForModulus, 0)]
    );
    assert_eq!(
        r(k.public_encrypt(&[0; 10], &mut to, Padding::X931, None, &mut rng())),
        [(Reason::UnknownPaddingType, 0)]
    );
    assert_eq!(
        rc(&k
            .private_decrypt(&[0; 257], &mut to, Padding::Pkcs1, None, None, &mut rng())
            .1),
        [(Reason::DataGreaterThanModLen, 0)]
    );
    assert_eq!(
        rc(&k
            .private_decrypt(&[], &mut to, Padding::Pkcs1, None, None, &mut rng())
            .1),
        [(Reason::DataTooSmall, 0)]
    );
    // An unknown padding fails after the private operation, with that error only.
    assert_eq!(
        rc(&k
            .private_decrypt(&[5; 10], &mut to, Padding::X931, None, None, &mut rng())
            .1),
        [(Reason::UnknownPaddingType, 0)]
    );
    let mut small = Key::new();
    small.n = Some(BigNum::from_word(100));
    small.e = Some(BigNum::from_word(101));
    assert_eq!(
        r(small.public_encrypt(&[1], &mut to, Padding::None, None, &mut rng())),
        [(Reason::BadEValue, 0)]
    );
}

#[test]
fn digest_info_prefixes() {
    // SHA-256's, and OpenSSL's MD4 and SM3 quirks.
    assert_eq!(
        digest_info(NID_sha256).unwrap(),
        hex("3031300d060960864801650304020105000420")
    );
    assert_eq!(
        digest_info(NID_md4).unwrap(),
        hex("3020300c06082a864886f70d020305000410")
    );
    assert_eq!(
        digest_info(NID_sm3).unwrap(),
        hex("3030300c06082a811ccf5501837805000420")
    );
    assert_eq!((digest_size(NID_sm3), digest_size(NID_sha256)), (0, 32));
}

#[test]
fn x931_and_none_layouts() {
    let mut to = [0u8; 8];
    add_x931(&mut to, &[1, 2, 3]).0.unwrap();
    assert_eq!(to, [0x6b, 0xbb, 0xbb, 0xba, 1, 2, 3, 0xcc]);
    let mut out = [0u8; 8];
    assert_eq!(check_x931(&mut out, &to, 8).0, Ok(3));
    let mut to = [0u8; 5];
    add_x931(&mut to, &[1, 2, 3]).0.unwrap();
    assert_eq!(to, [0x6a, 1, 2, 3, 0xcc]);
    // No BA: the BBs run to the limit, the trailer is read there, and there's no data.
    let mut out = [0u8; 8];
    assert_eq!(
        rc(&check_x931(&mut out, &[0x6b, 0xbb, 0xbb, 0xcc], 4).1),
        [(Reason::InvalidTrailer, 0)]
    );
    assert_eq!(check_x931(&mut out, &[0x6b, 0xbb, 0xcc, 0xcc], 4).0, Ok(0));
    let mut to = [9u8; 4];
    assert_eq!(check_none(&mut to, &[1, 2]).0, Ok(4));
    assert_eq!(to, [0, 0, 1, 2]);
}

#[test]
fn rsa_sign_and_verify() {
    let k = key();
    let h = hex(&kat("H256"));
    let mut sig = vec![0; 256];
    let (r, _) = sign(&k, NID_sha256, &h, &mut sig, &mut rng());
    assert_eq!(r, Ok(256));
    assert_eq!(sig, hex(&kat("SIG_PKCS1")));
    assert_eq!(verify(&k, NID_sha256, Some(&h), &sig).0, Ok(h.clone()));
    assert_eq!(verify(&k, NID_sha256, None, &sig).0, Ok(h.clone()));
    let mut bad = h.clone();
    bad[0] ^= 1;
    assert_eq!(
        rc(&verify(&k, NID_sha256, Some(&bad), &sig).1),
        [(Reason::BadSignature, 0)]
    );
    assert_eq!(
        rc(&verify(&k, NID_sha256, None, &sig[1..]).1),
        [(Reason::WrongSignatureLength, 0)]
    );
    assert_eq!(
        rc(&sign(&k, rustyssl_abi::NID_undef, &h, &mut sig, &mut rng()).1),
        [(Reason::UnknownAlgorithmType, 0)]
    );
}
