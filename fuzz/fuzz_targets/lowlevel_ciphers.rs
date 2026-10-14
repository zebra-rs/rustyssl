//! Fuzzes the low-level IDEA, SEED, and Camellia functions
//! (`rustyssl_crypto::lowlevel::legacy::idea`, `lowlevel::seed`, `lowlevel::camellia`) with
//! arbitrary keys, schedules, IVs, positions, lengths, and data. Nothing may panic, and: IDEA's
//! and Camellia's blocks match the cipher backend's (the RustCrypto crates'); decryption undoes
//! encryption (IDEA through the decryption schedule, also computed in place); CBC inverts;
//! CFB-128 and OFB-128 give the same output in pieces as at once and invert; and an IDEA
//! schedule of arbitrary words encrypts and inverts without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyssl_crypto::lowlevel::camellia;
use rustyssl_crypto::lowlevel::legacy::idea::{self, IdeaKey};
use rustyssl_crypto::lowlevel::legacy::{self, Block64};
use rustyssl_crypto::lowlevel::modes::{self, BLOCK, Block128};
use rustyssl_crypto::lowlevel::seed;
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

/// CBC, CFB-128, and OFB-128 over a 128-bit cipher: CBC inverts; CFB and OFB chunk and invert.
fn modes128(e: &impl Block128, d: &impl Block128, data: &[u8], iv: [u8; BLOCK], num: i32, cut: usize) {
    let len = data.len();
    let mut out = vec![0u8; len.div_ceil(BLOCK) * BLOCK];
    let mut v = iv;
    modes::cbc_encrypt(data, &mut out, &mut v, e);
    let mut back = vec![0u8; len];
    let mut v2 = iv;
    modes::cbc_decrypt(&out, &mut back, len, &mut v2, d);
    assert_eq!(back, data);
    if len % BLOCK == 0 {
        assert_eq!(v, v2);
    }
    let num = num.rem_euclid(16);
    for ofb in [false, true] {
        let run = |input: &[u8], out: &mut [u8], v: &mut [u8; BLOCK], n: &mut i32, enc: bool| {
            if ofb {
                modes::ofb_encrypt(input, out, v, n, e).unwrap();
            } else {
                modes::cfb_encrypt(input, out, v, n, enc, e).unwrap();
            }
        };
        let mut whole = vec![0u8; len];
        let (mut v, mut n) = (iv, num);
        run(data, &mut whole, &mut v, &mut n, true);
        let mut split = vec![0u8; len];
        let (mut v2, mut n2) = (iv, num);
        for (i, piece) in data.chunks(cut).enumerate() {
            run(piece, &mut split[i * cut..i * cut + piece.len()], &mut v2, &mut n2, true);
        }
        assert_eq!((&whole, v, n), (&split, v2, n2));
        let mut back = vec![0u8; len];
        let (mut v3, mut n3) = (iv, num);
        run(&whole, &mut back, &mut v3, &mut n3, false);
        assert_eq!(back, data);
    }
}

fuzz_target!(|input: &[u8]| {
    let mut r = Reader(input);
    let which = r.byte() % 4;
    let klen = usize::from(r.byte() % 40);
    let key = r.take(klen).to_vec();
    let iv: [u8; BLOCK] = core::array::from_fn(|_| r.byte());
    let num = i32::from(r.byte() as i8);
    let cut = usize::from(r.byte() % 33) + 1;
    let data = r.take(300).to_vec();
    let key16: [u8; 16] = core::array::from_fn(|i| key.get(i).copied().unwrap_or(0));
    match which {
        0 => {
            let ek = idea::set_encrypt_key(&key16);
            let dk = idea::set_decrypt_key(&ek.0);
            let mut same = ek.0;
            idea::set_decrypt_key_in_place(&mut same);
            let block: [u8; 8] = core::array::from_fn(|i| data.get(i).copied().unwrap_or(0));
            let mut want = block;
            sym::block_cipher(BlockAlgorithm::Idea, &key16, None).unwrap().encrypt_blocks(&mut want).unwrap();
            let c = ek.encrypt(&block);
            assert_eq!(c, want);
            assert_eq!(dk.encrypt(&c), block);
            let len = data.len();
            let mut out = vec![0u8; len.div_ceil(8) * 8];
            let mut v: [u8; 8] = core::array::from_fn(|i| iv[i]);
            legacy::cbc(&data, &mut out, len, &ek, &mut v, true);
            let mut back = vec![0u8; len];
            let mut v2: [u8; 8] = core::array::from_fn(|i| iv[i]);
            legacy::cbc(&out, &mut back, len, &dk, &mut v2, false);
            assert_eq!(back, data);
            let _ = IdeaKey(same).encrypt(&block);
        }
        1 => {
            // A schedule of arbitrary words: no panics, and decryption of its inverse is total.
            let mut words = [0u32; idea::WORDS];
            for (i, w) in words.iter_mut().enumerate() {
                let b: [u8; 4] = core::array::from_fn(|j| data.get(i * 4 + j).copied().unwrap_or(0));
                *w = u32::from_be_bytes(b);
            }
            let k = IdeaKey(words);
            let dk = idea::set_decrypt_key(&k.0);
            let _ = dk.encrypt_words(k.encrypt_words([u32::from_be_bytes(key16[..4].try_into().unwrap()), 7]));
            let mut same = words;
            idea::set_decrypt_key_in_place(&mut same);
            // Words below 2^16 make a true schedule, which the inverse undoes.
            let small = IdeaKey(words.map(|w| w & 0xffff));
            let d = idea::set_decrypt_key(&small.0);
            let x = [0x0123_4567, 0x89ab_cdef];
            assert_eq!(d.encrypt_words(small.encrypt_words(x)), x);
        }
        2 => {
            let k = seed::set_key(&key16);
            let block: [u8; 16] = core::array::from_fn(|i| data.get(i).copied().unwrap_or(0));
            assert_eq!(k.decrypt(&k.encrypt(&block)), block);
            modes128(&seed::Encrypt(&k), &seed::Decrypt(&k), &data, iv, num, cut);
        }
        _ => {
            let Some(k) = camellia::set_key(&key) else {
                assert!(!matches!(key.len(), 16 | 24 | 32));
                return;
            };
            let block: [u8; 16] = core::array::from_fn(|i| data.get(i).copied().unwrap_or(0));
            let mut want = block;
            sym::block_cipher(BlockAlgorithm::Camellia, &key, None).unwrap().encrypt_blocks(&mut want).unwrap();
            let c = k.encrypt(&block);
            assert_eq!(c, want);
            assert_eq!(k.decrypt(&c), block);
            modes128(&camellia::Encrypt(&k), &camellia::Decrypt(&k), &data, iv, num, cut);
        }
    }
});
