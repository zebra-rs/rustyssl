#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test arithmetic on small known values"
)]

use super::super::aes::{Schedule, decrypt_schedule, encrypt_schedule};
use super::*;

struct Enc(Schedule);
struct Dec(Schedule);

impl Block128 for Enc {
    fn block(&self, input: &[u8; BLOCK]) -> [u8; BLOCK] {
        self.0.encrypt(input)
    }
}

impl Block128 for Dec {
    fn block(&self, input: &[u8; BLOCK]) -> [u8; BLOCK] {
        self.0.decrypt(input)
    }
}

/// A whole-buffer CBC function over the block functions.
struct Cbc(Schedule, Schedule);

impl Cbc128 for Cbc {
    fn cbc(&self, input: &[u8], out: &mut [u8], iv: &mut [u8; BLOCK], enc: bool) {
        if enc {
            cbc_encrypt(input, out, iv, &Enc(self.0.clone()));
        } else {
            cbc_decrypt(input, out, input.len(), iv, &Dec(self.1.clone()));
        }
    }
}

/// A whole-buffer CTR function that counts in the last 32 bits only.
struct Ctr(Schedule);

impl Ctr128 for Ctr {
    fn ctr(&self, input: &[u8], out: &mut [u8], blocks: usize, iv: &[u8; BLOCK]) {
        let mut counter = *iv;
        for i in 0..blocks {
            let k = self.0.encrypt(&counter);
            for n in 0..BLOCK {
                out[i * BLOCK + n] = input[i * BLOCK + n] ^ k[n];
            }
            let c = u32::from_be_bytes(counter[12..].try_into().unwrap()).wrapping_add(1);
            counter[12..].copy_from_slice(&c.to_be_bytes());
        }
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const IV: &str = "000102030405060708090a0b0c0d0e0f";
const PLAIN: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51";

fn enc() -> Enc {
    Enc(encrypt_schedule(&unhex(KEY)).unwrap())
}

fn dec() -> Dec {
    Dec(decrypt_schedule(&unhex(KEY)).unwrap())
}

fn iv(s: &str) -> [u8; BLOCK] {
    unhex(s).try_into().unwrap()
}

/// NIST SP 800-38A, F.2.1/F.2.2: AES-128 CBC; and a partial last block.
#[test]
fn cbc_known_answers() {
    let p = unhex(PLAIN);
    let mut out = vec![0; 32];
    let mut v = iv(IV);
    cbc_encrypt(&p, &mut out, &mut v, &enc());
    assert_eq!(
        hex(&out),
        "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
    );
    assert_eq!(v.as_slice(), &out[16..]);
    let mut back = vec![0; 32];
    let mut v = iv(IV);
    cbc_decrypt(&out, &mut back, 32, &mut v, &dec());
    assert_eq!(back, p);
    // 20 octets: the last block padded with zeros under the XOR, written whole.
    let mut out2 = vec![0xee; 32];
    let mut v = iv(IV);
    cbc_encrypt(&p[..20], &mut out2, &mut v, &enc());
    let mut padded = p[..20].to_vec();
    padded.resize(32, 0);
    let mut out3 = vec![0; 32];
    let mut v3 = iv(IV);
    cbc_encrypt(&padded, &mut out3, &mut v3, &enc());
    assert_eq!(out2, out3);
    assert_eq!(v, v3);
    // Decrypting 20 octets reads both blocks and writes 20.
    let mut back = vec![0xee; 32];
    let mut v = iv(IV);
    cbc_decrypt(&out2, &mut back, 20, &mut v, &dec());
    assert_eq!(&back[..20], &p[..20]);
    assert_eq!(&back[20..], &[0xee; 12]);
    assert_eq!(v.as_slice(), &out2[16..]);
}

/// SP 800-38A F.5.1, F.4.1, F.3.13, F.3.7, F.3.1: CTR, OFB, CFB-128, CFB-8, CFB-1, each in
/// pieces of every size carrying the position between calls.
#[test]
fn stream_modes_known_answers_in_pieces() {
    let p = unhex(PLAIN);
    for piece in 1..=33 {
        let mut out = vec![0; 32];
        let mut v = iv("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let mut ecount = [0; BLOCK];
        let mut num = 0u32;
        let mut ofb = vec![0; 32];
        let mut ov = iv(IV);
        let mut onum = 0;
        let mut cfb = vec![0; 32];
        let mut cv = iv(IV);
        let mut cnum = 0;
        let mut c32 = vec![0; 32];
        let mut v32 = iv("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let mut e32 = [0; BLOCK];
        let mut n32 = 0u32;
        for (i, chunk) in p.chunks(piece).enumerate() {
            let o = &mut out[i * piece..i * piece + chunk.len()];
            ctr_encrypt(chunk, o, &mut v, &mut ecount, &mut num, &enc()).unwrap();
            ofb_encrypt(
                chunk,
                &mut ofb[i * piece..i * piece + chunk.len()],
                &mut ov,
                &mut onum,
                &enc(),
            )
            .unwrap();
            cfb_encrypt(
                chunk,
                &mut cfb[i * piece..i * piece + chunk.len()],
                &mut cv,
                &mut cnum,
                true,
                &enc(),
            )
            .unwrap();
            ctr32_encrypt(
                chunk,
                &mut c32[i * piece..i * piece + chunk.len()],
                &mut v32,
                &mut e32,
                &mut n32,
                &Ctr(enc().0),
            )
            .unwrap();
        }
        assert_eq!(
            hex(&out),
            "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff",
            "{piece}"
        );
        assert_eq!(
            hex(&ofb),
            "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825",
            "{piece}"
        );
        assert_eq!(
            hex(&cfb),
            "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b",
            "{piece}"
        );
        assert_eq!(c32, out, "{piece}");
        // The keystream buffer only holds a partial block's keystream there.
        assert_eq!((v32, n32), (v, num), "{piece}");
        if num != 0 {
            assert_eq!(e32, ecount, "{piece}");
        }
        let mut back = vec![0; 32];
        let mut cv = iv(IV);
        let mut cnum = 0;
        cfb_encrypt(&cfb, &mut back, &mut cv, &mut cnum, false, &enc()).unwrap();
        assert_eq!(back, p);
    }
    let mut out = vec![0; 18];
    let mut v = iv(IV);
    cfb8_encrypt(&p[..18], &mut out, &mut v, true, &enc());
    assert_eq!(hex(&out), "3b79424c9c0dd436bace9e0ed4586a4f32b9");
    let mut back = vec![0; 18];
    let mut v = iv(IV);
    cfb8_encrypt(&out, &mut back, &mut v, false, &enc());
    assert_eq!(back, &p[..18]);
    // CFB-1 of 16 bits, 0x6bc1; the output octets' other bits stay.
    let mut out = vec![0xff; 3];
    let mut v = iv(IV);
    cfb1_encrypt(&[0x6b, 0xc1, 0xbe], &mut out, 16, &mut v, true, &enc());
    assert_eq!(hex(&out), "68b3ff");
    let mut back = vec![0; 2];
    let mut v = iv(IV);
    cfb1_encrypt(&out, &mut back, 16, &mut v, false, &enc());
    assert_eq!(hex(&back), "6bc1");
}

/// Negative and corrupt positions.
#[test]
fn positions() {
    let mut v = iv(IV);
    let mut num = -5;
    let mut out = [7u8; 4];
    assert_eq!(
        ofb_encrypt(&[1, 2, 3, 4], &mut out, &mut v, &mut num, &enc()),
        Ok(())
    );
    assert_eq!((num, out), (-1, [7; 4]));
    let mut num = 16;
    assert_eq!(
        cfb_encrypt(&[1], &mut out, &mut v, &mut num, true, &enc()),
        Err(Corrupt)
    );
    let mut num = 16u32;
    let mut e = [0; BLOCK];
    assert_eq!(
        ctr_encrypt(&[1], &mut out, &mut v, &mut e, &mut num, &enc()),
        Err(Corrupt)
    );
}

/// The 32-bit counter carries into the first 96 bits between calls.
#[test]
fn ctr32_carries() {
    let p = vec![0x5a; 64];
    let start = iv("000102030405060708090a0bfffffffe");
    let mut a = vec![0; 64];
    let mut v = start;
    let mut e = [0; BLOCK];
    let mut n = 0;
    ctr32_encrypt(&p, &mut a, &mut v, &mut e, &mut n, &Ctr(enc().0)).unwrap();
    let mut b = vec![0; 64];
    let mut w = start;
    let mut f = [0; BLOCK];
    let mut m = 0;
    ctr_encrypt(&p, &mut b, &mut w, &mut f, &mut m, &enc()).unwrap();
    assert_eq!(a, b);
    assert_eq!(v, w);
    assert_eq!(hex(&v), "000102030405060708090a0c00000002");
}

/// Ciphertext stealing: each form inverts, and the block-function and CBC-function forms
/// agree.
#[test]
fn cts_round_trips() {
    let data: Vec<u8> = (0..80u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(3))
        .collect();
    let cbc = Cbc(enc().0, dec().0);
    for len in 0..=80 {
        let input = &data[..len];
        let mut a = vec![0; len];
        let mut va = iv(IV);
        let ra = cts_encrypt_block(input, &mut a, &mut va, &enc());
        let mut b = vec![0; len];
        let mut vb = iv(IV);
        let rb = cts_encrypt(input, &mut b, &mut vb, &cbc);
        assert_eq!((ra, &a, va), (rb, &b, vb), "cts {len}");
        assert_eq!(ra, if len <= 16 { 0 } else { len });
        if ra != 0 {
            let mut back = vec![0; len];
            let mut v = iv(IV);
            assert_eq!(cts_decrypt_block(&a, &mut back, &mut v, &dec()), len + 16);
            assert_eq!(back, input, "cts back {len}");
            let mut back2 = vec![0; len];
            let mut v2 = iv(IV);
            assert_eq!(cts_decrypt(&a, &mut back2, &mut v2, &cbc), len);
            assert_eq!((back2, v2), (back, v), "cts back cbc {len}");
        }
        let mut c = vec![0; len];
        let mut vc = iv(IV);
        let rc = nistcts_encrypt_block(input, &mut c, &mut vc, &enc());
        let mut d = vec![0; len];
        let mut vd = iv(IV);
        let rd = nistcts_encrypt(input, &mut d, &mut vd, &cbc);
        assert_eq!((rc, &c, vc), (rd, &d, vd), "nist {len}");
        assert_eq!(rc, if len < 16 { 0 } else { len });
        if rc != 0 {
            let mut back = vec![0; len];
            let mut v = iv(IV);
            assert_eq!(
                nistcts_decrypt_block(&c, &mut back, &mut v, &dec()),
                if len % 16 == 0 { len } else { len + 16 }
            );
            assert_eq!(back, input, "nist back {len}");
            let mut back2 = vec![0; len];
            let mut v2 = iv(IV);
            assert_eq!(nistcts_decrypt(&c, &mut back2, &mut v2, &cbc), len);
            assert_eq!((back2, v2), (back, v), "nist back cbc {len}");
        }
        // CBC-CS3 with whole blocks is CBC, and differs from CTS only in the last two blocks'
        // order.
        if len >= 32 && len % 16 == 0 {
            let mut plain = vec![0; len];
            let mut v = iv(IV);
            cbc_encrypt(input, &mut plain, &mut v, &enc());
            assert_eq!(c, plain);
            assert_eq!(&a[..len - 32], &plain[..len - 32]);
            assert_eq!(&a[len - 32..len - 16], &plain[len - 16..]);
        }
    }
}

/// RFC 3394 4.1 and RFC 5649 section 6.
#[test]
fn key_wraps_known_answers() {
    let kek = unhex("000102030405060708090a0b0c0d0e0f");
    let e = Enc(encrypt_schedule(&kek).unwrap());
    let d = Dec(decrypt_schedule(&kek).unwrap());
    let key = unhex("00112233445566778899aabbccddeeff");
    let mut out = vec![0; 24];
    assert_eq!(wrap(None, &key, &mut out, &e), 24);
    assert_eq!(
        hex(&out),
        "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"
    );
    let mut back = vec![0; 16];
    assert_eq!(unwrap(None, &out, &mut back, &d), 16);
    assert_eq!(back, key);
    out[0] ^= 1;
    assert_eq!(unwrap(None, &out, &mut back, &d), 0);
    assert_eq!(back, vec![0; 16]);
    assert_eq!(wrap(None, &key[..8], &mut out, &e), 0);

    let kek = unhex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
    let e = Enc(encrypt_schedule(&kek).unwrap());
    let d = Dec(decrypt_schedule(&kek).unwrap());
    let key = unhex("c37b7e6492584340bed12207808941155068f738");
    let mut out = vec![0; 32];
    assert_eq!(wrap_pad(None, &key, &mut out, &e), 32);
    assert_eq!(
        hex(&out),
        "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"
    );
    let mut back = vec![0; 24];
    assert_eq!(unwrap_pad(None, &out, &mut back, &d), 20);
    assert_eq!(&back[..20], key.as_slice());
    let mut out = vec![0; 16];
    assert_eq!(wrap_pad(None, &unhex("466f7250617369"), &mut out, &e), 16);
    assert_eq!(hex(&out), "afbeb0f07dfbf5419200f2ccb50bb24f");
    let mut back = vec![0; 8];
    assert_eq!(unwrap_pad(None, &out, &mut back, &d), 7);
    assert_eq!(hex(&back[..7]), "466f7250617369");
    out[15] ^= 1;
    assert_eq!(unwrap_pad(None, &out, &mut back, &d), 0);
    assert_eq!(back, vec![0; 8]);
}

/// IGE: the test vector from OpenSSL's igetest.c (Ben Laurie's), and the IV left as the last
/// blocks.
#[test]
fn ige_known_answer() {
    let key = unhex("000102030405060708090a0b0c0d0e0f");
    let e = Enc(encrypt_schedule(&key).unwrap());
    let d = Dec(decrypt_schedule(&key).unwrap());
    let mut v: [u8; 32] = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .try_into()
        .unwrap();
    let mut out = vec![0; 32];
    ige(&[0; 32], &mut out, &mut v, true, &e);
    assert_eq!(
        hex(&out),
        "1a8519a6557be652e9da8e43da4ef4453cf456b4ca488aa383c79c98b34797cb"
    );
    assert_eq!(&v[..16], &out[16..]);
    assert_eq!(&v[16..], &[0; 16]);
    let mut v: [u8; 32] = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .try_into()
        .unwrap();
    let mut back = vec![0; 32];
    ige(&out, &mut back, &mut v, false, &d);
    assert_eq!(back, vec![0; 32]);
    let iv4: [u8; 64] = core::array::from_fn(|i| i as u8);
    let data: Vec<u8> = (0..48u8).collect();
    let mut c = vec![0; 48];
    bi_ige(&data, &mut c, &iv4, true, &e);
    let mut p = vec![0; 48];
    bi_ige(&c, &mut p, &iv4, false, &d);
    assert_eq!(p, data);
}
