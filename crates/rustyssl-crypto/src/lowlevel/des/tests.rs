#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test arithmetic on small known values"
)]

use cipher::{BlockCipherEncrypt, KeyInit};

use super::*;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The classic vector: "Now is t" under 0123456789abcdef.
#[test]
fn known_answer() {
    let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let ks = set_key_unchecked(&key);
    let c = ecb(b"Now is t", Cipher::Single(&ks), true);
    assert_eq!(hex(&c), "3fa40e8a984d4815");
    assert_eq!(&ecb(&c, Cipher::Single(&ks), false), b"Now is t");
}

/// Single and triple DES match the `des` crate for many keys and blocks.
#[test]
fn blocks_match_the_crate() {
    for seed in 0..40u8 {
        let k: [u8; 8] = core::array::from_fn(|i| seed.wrapping_mul(37).wrapping_add(i as u8 * 11));
        let k2: [u8; 8] = core::array::from_fn(|i| k[i] ^ 0x5a);
        let k3: [u8; 8] = core::array::from_fn(|i| k[i].wrapping_add(3));
        let block: [u8; 8] = core::array::from_fn(|i| seed ^ (i as u8 * 29));
        let ks = set_key_unchecked(&k);
        let mut want = cipher::Array::from(block);
        des::Des::new_from_slice(&k)
            .unwrap()
            .encrypt_block(&mut want);
        assert_eq!(
            ecb(&block, Cipher::Single(&ks), true).as_slice(),
            want.as_slice()
        );
        let (ks2, ks3) = (set_key_unchecked(&k2), set_key_unchecked(&k3));
        let mut want3 = cipher::Array::from(block);
        let key3: Vec<u8> = [k, k2, k3].concat();
        des::TdesEde3::new_from_slice(&key3)
            .unwrap()
            .encrypt_block(&mut want3);
        let got3 = ecb(&block, Cipher::Triple(&ks, &ks2, &ks3), true);
        assert_eq!(got3.as_slice(), want3.as_slice());
        assert_eq!(ecb(&got3, Cipher::Triple(&ks, &ks2, &ks3), false), block);
    }
}

/// Each mode inverts, for every length to 40 and each bit width.
#[test]
fn modes_invert() {
    let ks = set_key_unchecked(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let ks2 = set_key_unchecked(&[8, 7, 6, 5, 4, 3, 2, 1]);
    let data: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(3))
        .collect();
    let iv = [9u8; 8];
    for len in 0..=40 {
        for c in [Cipher::Single(&ks), Cipher::Triple(&ks, &ks2, &ks)] {
            let mut out = vec![0u8; 48];
            let mut v = iv;
            cbc(&data, &mut out, len, c, &mut v, true, true);
            let mut back = vec![0u8; 48];
            let mut w = iv;
            cbc(&out, &mut back, len, c, &mut w, false, true);
            assert_eq!(&back[..len], &data[..len]);
            let mut out = vec![0u8; len];
            let (mut v, mut n) = (iv, 0);
            cfb64(&data[..len], &mut out, c, &mut v, &mut n, true);
            let mut back = vec![0u8; len];
            let (mut v, mut n) = (iv, 0);
            cfb64(&out, &mut back, c, &mut v, &mut n, false);
            assert_eq!(back, &data[..len]);
            let mut out = vec![0u8; len];
            let (mut v, mut n) = (iv, 0);
            ofb64(&data[..len], &mut out, c, &mut v, &mut n);
            let mut back = vec![0u8; len];
            let (mut v, mut n) = (iv, 0);
            ofb64(&out, &mut back, c, &mut v, &mut n);
            assert_eq!(back, &data[..len]);
        }
        let mut out = vec![0u8; 48];
        pcbc(&data, &mut out, len, &ks, &iv, true);
        let mut back = vec![0u8; 48];
        pcbc(&out, &mut back, len, &ks, &iv, false);
        assert_eq!(&back[..len], &data[..len]);
        let (inw, outw) = ([3u8; 8], [4u8; 8]);
        let mut out = vec![0u8; 48];
        let mut v = iv;
        xcbc(&data, &mut out, len, &ks, &mut v, &inw, &outw, true);
        let mut back = vec![0u8; 48];
        let mut w = iv;
        xcbc(&out, &mut back, len, &ks, &mut w, &inw, &outw, false);
        assert_eq!(&back[..len], &data[..len]);
        for bits in [1u32, 7, 8, 12, 32, 40, 63, 64] {
            let mut out = vec![0u8; 48];
            let mut v = iv;
            cfb(
                &data,
                &mut out,
                bits,
                len,
                Cipher::Single(&ks),
                &mut v,
                true,
            );
            let mut back = vec![0u8; 48];
            let mut w = iv;
            cfb(
                &out,
                &mut back,
                bits,
                len,
                Cipher::Single(&ks),
                &mut w,
                false,
            );
            let step = bits.div_ceil(8) as usize;
            let done = len / step * step;
            assert_eq!(&back[..done], &data[..done], "cfb {bits} {len}");
            if bits % 8 == 0 {
                let steps = len / step;
                let mut out = vec![0u8; 48];
                let mut v = iv;
                ofb(&data, &mut out, bits, steps, &ks, &mut v);
                let mut back = vec![0u8; 48];
                let mut w = iv;
                ofb(&out, &mut back, bits, steps, &ks, &mut w);
                assert_eq!(&back[..done], &data[..done], "ofb {bits} {len}");
            }
        }
    }
}

/// Parity, weak keys, and `crypt(3)`.
#[test]
fn keys_and_crypt() {
    let mut k = [0u8; 8];
    set_odd_parity(&mut k);
    assert_eq!(k, [1; 8]);
    assert!(check_key_parity(&k));
    assert!(is_weak_key(&k));
    assert!(!check_key_parity(&[0; 8]));
    assert!(!is_weak_key(&[1, 2, 3, 4, 5, 6, 7, 8]));
    let r = fcrypt(b"password", *b"ab");
    assert_eq!(&r.out.unwrap()[..13], b"abJnggxhB/yWI");
    assert!(fcrypt(b"x", [0, b'a']).out.is_none());
    assert_eq!(fcrypt(b"x", [b'a', 200]).salt_written, 2);
}
