//! Fuzzes the low-level DES functions (`rustyssl_crypto::lowlevel::des`) with arbitrary keys,
//! IVs, positions, bit widths, lengths, data, and schedules. Nothing may panic, and: blocks
//! match the cipher backend's (the `des` crate's) for single and triple DES; every mode inverts (CBC, NCBC, XCBC,
//! PCBC, triple-DES CBC, CFB and OFB by bits, CFB-64 and OFB-64); CFB-64 and OFB-64 give the
//! same output in pieces as at once, carrying the position; and crypt(3), the checksums, and
//! the string to key functions take any input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyssl_crypto::lowlevel::des::{self, Cipher};
use rustyssl_crypto::sym::{self, BlockAlgorithm};

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn byte(&mut self) -> u8 {
        let (&b, rest) = self.0.split_first().unwrap_or((&0, &[]));
        self.0 = rest;
        b
    }

    fn block(&mut self) -> [u8; 8] {
        core::array::from_fn(|_| self.byte())
    }
}

fuzz_target!(|input: &[u8]| {
    let mut r = Reader(input);
    let (k1, k2, k3, iv) = (r.block(), r.block(), r.block(), r.block());
    let num = i32::from(r.byte() as i8);
    let bits = u32::from(r.byte() % 66);
    let mode = r.byte();
    let cut = usize::from(r.byte() % 17) + 1;
    let data = r.0.to_vec();
    let len = data.len();
    let (s1, s2, s3) = (des::set_key_unchecked(&k1), des::set_key_unchecked(&k2), des::set_key_unchecked(&k3));

    // Blocks against the crate.
    let b: [u8; 8] = core::array::from_fn(|i| data.get(i).copied().unwrap_or(0));
    let mut want = b;
    sym::block_cipher(BlockAlgorithm::Des, &k1, None).unwrap().encrypt_blocks(&mut want).unwrap();
    assert_eq!(des::ecb(&b, Cipher::Single(&s1), true), want);
    let mut want3 = b;
    sym::block_cipher(BlockAlgorithm::TripleDes, &[k1, k2, k3].concat(), None)
        .unwrap()
        .encrypt_blocks(&mut want3)
        .unwrap();
    assert_eq!(des::ecb(&b, Cipher::Triple(&s1, &s2, &s3), true), want3);

    // The CBC family inverts.
    let c = if mode & 1 == 0 { Cipher::Single(&s1) } else { Cipher::Triple(&s1, &s2, &s3) };
    let w = len.div_ceil(8) * 8;
    let mut out = vec![0u8; w];
    let mut v = iv;
    des::cbc(&data, &mut out, len, c, &mut v, true, mode & 2 == 0);
    let mut back = vec![0u8; w];
    let mut v2 = iv;
    des::cbc(&out, &mut back, len, c, &mut v2, false, mode & 2 == 0);
    assert_eq!(&back[..len], data.as_slice());
    let (inw, outw) = (k2, k3);
    let mut out = vec![0u8; w];
    let mut v = iv;
    des::xcbc(&data, &mut out, len, &s1, &mut v, &inw, &outw, true);
    let mut back = vec![0u8; w];
    let mut v2 = iv;
    des::xcbc(&out, &mut back, len, &s1, &mut v2, &inw, &outw, false);
    assert_eq!(&back[..len], data.as_slice());
    let mut out = vec![0u8; w];
    des::pcbc(&data, &mut out, len, &s1, &iv, true);
    let mut back = vec![0u8; w];
    des::pcbc(&out, &mut back, len, &s1, &iv, false);
    assert_eq!(&back[..len], data.as_slice());

    // CFB and OFB by bits invert (whole steps).
    if (1..=64).contains(&bits) {
        let step = bits.div_ceil(8) as usize;
        let done = len / step * step;
        let mut out = vec![0u8; len];
        let mut v = iv;
        des::cfb(&data, &mut out, bits, len, c, &mut v, true);
        let mut back = vec![0u8; len];
        let mut v2 = iv;
        des::cfb(&out, &mut back, bits, len, c, &mut v2, false);
        assert_eq!(&back[..done], &data[..done]);
        assert_eq!(v, v2);
        if bits % 8 == 0 {
            let steps = len / step;
            let mut out = vec![0u8; len];
            let mut v = iv;
            des::ofb(&data, &mut out, bits, steps, &s1, &mut v);
            let mut back = vec![0u8; len];
            let mut v2 = iv;
            des::ofb(&out, &mut back, bits, steps, &s1, &mut v2);
            assert_eq!(&back[..done], &data[..done]);
        }
    } else {
        let mut out = vec![0u8; len];
        let mut v = iv;
        des::cfb(&data, &mut out, bits, len, c, &mut v, true);
        assert_eq!(v, iv);
    }

    // CFB-64 and OFB-64: in pieces as at once, and inverting.
    for ofb in [false, true] {
        let mut whole = vec![0u8; len];
        let (mut v, mut n) = (iv, num);
        if ofb {
            des::ofb64(&data, &mut whole, c, &mut v, &mut n);
        } else {
            des::cfb64(&data, &mut whole, c, &mut v, &mut n, true);
        }
        let mut split = vec![0u8; len];
        let (mut v2, mut n2) = (iv, num);
        for (i, piece) in data.chunks(cut).enumerate() {
            let o = &mut split[i * cut..i * cut + piece.len()];
            if ofb {
                des::ofb64(piece, o, c, &mut v2, &mut n2);
            } else {
                des::cfb64(piece, o, c, &mut v2, &mut n2, true);
            }
        }
        if len == 0 {
            n2 = num & 7;
        }
        assert_eq!((&whole, v, n & 7), (&split, v2, n2 & 7));
        let mut back = vec![0u8; len];
        let (mut v3, mut n3) = (iv, num);
        if ofb {
            des::ofb64(&whole, &mut back, c, &mut v3, &mut n3);
        } else {
            des::cfb64(&whole, &mut back, c, &mut v3, &mut n3, false);
        }
        assert_eq!(back, data);
    }

    // The rest take anything.
    let _ = des::cbc_cksum(&data, len, &s1, &iv);
    let _ = des::quad_cksum(&data, len, num, &iv);
    let _ = des::string_to_key(&data);
    let _ = des::string_to_2keys(&data);
    let _ = des::fcrypt(&data, [k1[0], k1[1]]);
    let _ = des::is_weak_key(&k2);
    let _ = des::check_key_parity(&k3);
    // Any 32 words are a schedule.
    let junk: des::Schedule = core::array::from_fn(|i| u32::from_le_bytes([k1[i % 8], k2[i % 8], k3[i % 8], iv[i % 8]]));
    let mut d = [1u32, 2];
    des::encrypt1(&mut d, &junk, true);
    des::encrypt2(&mut d, &junk, false);
});
