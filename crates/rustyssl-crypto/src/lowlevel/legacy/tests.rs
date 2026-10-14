#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test arithmetic on small known values"
)]

use super::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn block(s: &str) -> [u8; 8] {
    unhex(s).try_into().unwrap()
}

/// Schneier's Blowfish vectors.
#[test]
fn blowfish_known_answers() {
    for (key, pt, ct) in [
        ("0000000000000000", "0000000000000000", "4ef997456198dd78"),
        ("ffffffffffffffff", "ffffffffffffffff", "51866fd5b85ecb8a"),
        ("fedcba9876543210", "0123456789abcdef", "0aceab0fc6a0a28d"),
    ] {
        let k = bf_set_key(&unhex(key));
        let c = ecb(&block(pt), &k, true);
        assert_eq!(hex(&c), ct);
        assert_eq!(ecb(&c, &k, false), block(pt));
    }
}

/// RFC 2144 B.1: CAST-128 with 128-, 80-, and 40-bit keys.
#[test]
fn cast_known_answers() {
    for (key, ct) in [
        ("0123456712345678234567893456789a", "238b4fe5847e44b2"),
        ("01234567123456782345", "eb6a711a2c02271b"),
        ("0123456712", "7ac816d16e9b302e"),
    ] {
        let k = cast_set_key(&unhex(key));
        let c = ecb(&block("0123456789abcdef"), &k, true);
        assert_eq!(hex(&c), ct);
        assert_eq!(hex(&ecb(&c, &k, false)), "0123456789abcdef");
    }
}

/// RFC 2268 section 5: RC2 with effective key lengths.
#[test]
fn rc2_known_answers() {
    for (key, bits, pt, ct) in [
        (
            "0000000000000000",
            63,
            "0000000000000000",
            "ebb773f993278eff",
        ),
        (
            "ffffffffffffffff",
            64,
            "ffffffffffffffff",
            "278b27e42e2f0d49",
        ),
        (
            "3000000000000000",
            64,
            "1000000000000001",
            "30649edf9be7d2c2",
        ),
        ("88", 64, "0000000000000000", "61a8a244adacccf0"),
        ("88bca90e90875a", 64, "0000000000000000", "6ccf4308974c267f"),
        (
            "88bca90e90875a7f0f79c384627bafb2",
            128,
            "0000000000000000",
            "2269552ab0f85ca6",
        ),
    ] {
        let k = rc2_set_key(&unhex(key), bits);
        let c = ecb(&block(pt), &k, true);
        assert_eq!(hex(&c), ct, "{key} {bits}");
        assert_eq!(hex(&ecb(&c, &k, false)), pt);
    }
}

/// RFC 6229's first keystream octets for a 40-bit key, and the classic "Key"/"Plaintext".
#[test]
fn rc4_known_answers() {
    let mut s = rc4_set_key(&unhex("0102030405"));
    let mut ks = [0u8; 16];
    s.apply(&[0; 16], &mut ks);
    assert_eq!(hex(&ks), "b2396305f03dc027ccc3524a0a1118a8");
    let mut s = rc4_set_key(b"Key");
    let mut out = [0u8; 9];
    s.apply(b"Plaintext", &mut out);
    assert_eq!(hex(&out), "bbf316e8d940af0ad3");
}

/// The modes invert for each cipher and every length to 40.
#[test]
fn modes_invert() {
    let data: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(3))
        .collect();
    let bf = bf_set_key(b"blowfish key");
    let cast = cast_set_key(b"cast key");
    let rc2 = rc2_set_key(b"rc2 key", 64);
    fn check(c: &impl Block64, data: &[u8]) {
        for len in 0..=40 {
            let iv = [5u8; 8];
            let mut out = vec![0u8; 48];
            let mut v = iv;
            cbc(data, &mut out, len, c, &mut v, true);
            let mut back = vec![0u8; 48];
            let mut w = iv;
            cbc(&out, &mut back, len, c, &mut w, false);
            assert_eq!(&back[..len], &data[..len]);
            assert_eq!(v, w);
            let mut out = vec![0u8; len];
            let (mut v, mut n) = (iv, 3);
            cfb64(&data[..len], &mut out, c, &mut v, &mut n, true);
            let mut back = vec![0u8; len];
            let (mut v, mut n) = (iv, 3);
            cfb64(&out, &mut back, c, &mut v, &mut n, false);
            assert_eq!(back, &data[..len]);
            let mut out = vec![0u8; len];
            let (mut v, mut n) = (iv, 3);
            ofb64(&data[..len], &mut out, c, &mut v, &mut n);
            let mut back = vec![0u8; len];
            let (mut v, mut n) = (iv, 3);
            ofb64(&out, &mut back, c, &mut v, &mut n);
            assert_eq!(back, &data[..len]);
        }
    }
    check(&bf, &data);
    check(&cast, &data);
    check(&rc2, &data);
}
