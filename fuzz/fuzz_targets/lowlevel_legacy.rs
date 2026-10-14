//! Fuzzes the low-level Blowfish, CAST, RC2, and RC4 functions
//! (`rustyssl_crypto::lowlevel::legacy`) with arbitrary keys, effective bit counts, IVs,
//! positions, lengths, and data. Nothing may panic, and: blocks match the cipher backend's (the
//! RustCrypto crates') for each key length the backend takes; every mode inverts; CFB-64 and
//! OFB-64 give the same output in pieces as at once; RC4 in pieces matches RC4 at once and
//! undoes itself.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyssl_crypto::lowlevel::legacy::{self, Block64};
use rustyssl_crypto::sym::{self, BlockAlgorithm};

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn byte(&mut self) -> u8 {
        let (&b, rest) = self.0.split_first().unwrap_or((&0, &[]));
        self.0 = rest;
        b
    }

    fn take(&mut self, n: usize) -> &'a [u8] {
        let (head, tail) = self.0.split_at(n.min(self.0.len()));
        self.0 = tail;
        head
    }
}

/// The modes invert, and CFB-64 and OFB-64 chunk.
fn modes(c: &impl Block64, data: &[u8], iv: [u8; 8], num: i32, cut: usize) {
    let len = data.len();
    let w = len.div_ceil(8) * 8;
    let mut out = vec![0u8; w];
    let mut v = iv;
    legacy::cbc(data, &mut out, len, c, &mut v, true);
    let mut back = vec![0u8; w];
    let mut v2 = iv;
    legacy::cbc(&out, &mut back, len, c, &mut v2, false);
    assert_eq!(&back[..len], data);
    assert_eq!(v, v2);
    for ofb in [false, true] {
        let mut whole = vec![0u8; len];
        let (mut v, mut n) = (iv, num);
        if ofb {
            legacy::ofb64(data, &mut whole, c, &mut v, &mut n);
        } else {
            legacy::cfb64(data, &mut whole, c, &mut v, &mut n, true);
        }
        let mut split = vec![0u8; len];
        let (mut v2, mut n2) = (iv, num & 7);
        for (i, piece) in data.chunks(cut).enumerate() {
            let o = &mut split[i * cut..i * cut + piece.len()];
            if ofb {
                legacy::ofb64(piece, o, c, &mut v2, &mut n2);
            } else {
                legacy::cfb64(piece, o, c, &mut v2, &mut n2, true);
            }
        }
        assert_eq!((&whole, v, n & 7), (&split, v2, n2 & 7));
        let mut back = vec![0u8; len];
        let (mut v3, mut n3) = (iv, num);
        if ofb {
            legacy::ofb64(&whole, &mut back, c, &mut v3, &mut n3);
        } else {
            legacy::cfb64(&whole, &mut back, c, &mut v3, &mut n3, false);
        }
        assert_eq!(back, data);
    }
}

fuzz_target!(|input: &[u8]| {
    let mut r = Reader(input);
    let which = r.byte() % 4;
    let klen = usize::from(r.byte());
    let key = r.take(klen).to_vec();
    let bits = i32::from(r.byte()) * 5 - 100;
    let iv: [u8; 8] = core::array::from_fn(|_| r.byte());
    let num = i32::from(r.byte() as i8);
    let cut = usize::from(r.byte() % 17) + 1;
    let data = r.take(300).to_vec();
    let block: [u8; 8] = core::array::from_fn(|i| data.get(i).copied().unwrap_or(0));
    match which {
        0 => {
            let k = legacy::bf_set_key(&key);
            if (1..=72).contains(&key.len()) {
                let mut want = block;
                sym::block_cipher(BlockAlgorithm::Blowfish, &key, None).unwrap().encrypt_blocks(&mut want).unwrap();
                assert_eq!(k.encrypt(&block), want);
            }
            modes(&k, &data, iv, num, cut);
        }
        1 => {
            let k = legacy::cast_set_key(&key);
            if (1..=16).contains(&key.len()) {
                let mut want = block;
                sym::block_cipher(BlockAlgorithm::Cast5, &key, None).unwrap().encrypt_blocks(&mut want).unwrap();
                assert_eq!(k.encrypt(&block), want);
            }
            modes(&k, &data, iv, num, cut);
        }
        2 => {
            let k = legacy::rc2_set_key(&key, bits);
            let eff = if bits <= 0 || bits > 1024 { 1024 } else { bits };
            if (1..=128).contains(&key.len()) {
                let mut want = block;
                sym::block_cipher(BlockAlgorithm::Rc2, &key, Some(usize::try_from(eff).unwrap()))
                    .unwrap()
                    .encrypt_blocks(&mut want)
                    .unwrap();
                assert_eq!(k.encrypt(&block), want);
            }
            modes(&k, &data, iv, num, cut);
        }
        _ => {
            if key.is_empty() {
                return;
            }
            let mut a = legacy::rc4_set_key(&key);
            let mut whole = vec![0u8; data.len()];
            a.apply(&data, &mut whole);
            let mut b = legacy::rc4_set_key(&key);
            let mut split = vec![0u8; data.len()];
            for (i, piece) in data.chunks(cut).enumerate() {
                b.apply(piece, &mut split[i * cut..i * cut + piece.len()]);
            }
            assert_eq!(whole, split);
            assert_eq!((a.x, a.y, a.data), (b.x, b.y, b.data));
            let mut c = legacy::rc4_set_key(&key);
            let mut back = vec![0u8; data.len()];
            c.apply(&whole, &mut back);
            assert_eq!(back, data);
        }
    }
});
