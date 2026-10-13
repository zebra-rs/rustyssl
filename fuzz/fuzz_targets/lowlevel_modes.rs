//! Fuzzes the low-level AES key schedules and the block modes (`rustyssl_crypto::lowlevel::aes`
//! and `::modes`) with arbitrary keys, IVs, positions, lengths, and data. Nothing may panic,
//! and: decrypting with the decryption schedule undoes encrypting with the encryption one;
//! CBC, IGE, bi-IGE, ciphertext stealing (each
//! form, both functions), and the key wraps invert; the block-function and CBC-function forms
//! of ciphertext stealing agree; CTR, OFB, and CFB give the same output in pieces as at once,
//! carrying the position; and a position past the block is refused.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyssl_crypto::lowlevel::aes::{Schedule, decrypt_schedule, encrypt_schedule};
use rustyssl_crypto::lowlevel::modes::{self, BLOCK, Block128, Cbc128, Corrupt};

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

struct Cbc(Schedule, Schedule);

impl Cbc128 for Cbc {
    fn cbc(&self, input: &[u8], out: &mut [u8], iv: &mut [u8; BLOCK], enc: bool) {
        if enc {
            modes::cbc_encrypt(input, out, iv, &Enc(self.0.clone()));
        } else {
            modes::cbc_decrypt(input, out, input.len(), iv, &Dec(self.1.clone()));
        }
    }
}

/// Reads argument octets, zero once they run out.
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

    fn block(&mut self) -> [u8; BLOCK] {
        let mut b = [0u8; BLOCK];
        b.iter_mut().zip(self.take(BLOCK)).for_each(|(d, s)| *d = *s);
        b
    }
}

/// Runs a stream mode over `data` at once and in the given pieces, checking they agree.
fn pieces<S: Clone + PartialEq + core::fmt::Debug>(
    data: &[u8],
    cuts: &[u8],
    state: S,
    mut run: impl FnMut(&[u8], &mut [u8], &mut S) -> Result<(), Corrupt>,
) {
    let mut whole = vec![0u8; data.len()];
    let mut s1 = state.clone();
    let r1 = run(data, &mut whole, &mut s1);
    let mut split = vec![0u8; data.len()];
    let mut s2 = state;
    let mut at = 0;
    // At least one call, as for the whole: even an empty one sets a negative position to -1.
    let mut r2 = run(&[], &mut [], &mut s2);
    for &c in cuts.iter().chain(core::iter::once(&255)) {
        if at >= data.len() {
            break;
        }
        let n = (usize::from(c) % 40 + 1).min(data.len() - at);
        r2 = r2.and(run(&data[at..at + n], &mut split[at..at + n], &mut s2));
        at += n;
    }
    if at < data.len() {
        r2 = r2.and(run(&data[at..], &mut split[at..], &mut s2));
    }
    assert_eq!(r1.is_ok(), r2.is_ok());
    if r1.is_ok() {
        assert_eq!(whole, split);
        assert_eq!(s1, s2);
    }
}

fuzz_target!(|input: &[u8]| {
    let mut r = Reader(input);
    let key_len = [16, 24, 32, 20][usize::from(r.byte() % 4)];
    let key = r.take(key_len).to_vec();
    let (Ok(es), Ok(ds)) = (encrypt_schedule(&key), decrypt_schedule(&key)) else {
        assert!(key.len() != 16 && key.len() != 24 && key.len() != 32);
        return;
    };
    let enc = Enc(es.clone());
    let dec = Dec(ds.clone());
    let iv = r.block();
    let pos = r.byte();
    let len = usize::from(r.byte()) * 2 + usize::from(r.byte() % 2);
    let cuts = r.take(8).to_vec();
    let data = r.take(len).to_vec();
    let len = data.len();

    // A block, and back.
    let b = r.block();
    assert_eq!(dec.block(&enc.block(&b)), b);

    // CBC, a partial last block written whole, and back.
    let mut c = vec![0u8; len.next_multiple_of(BLOCK)];
    let mut v = iv;
    modes::cbc_encrypt(&data, &mut c, &mut v, &enc);
    let mut p = vec![0u8; len];
    let mut w = iv;
    modes::cbc_decrypt(&c, &mut p, len, &mut w, &dec);
    if len % BLOCK == 0 {
        assert_eq!(p, data);
    }
    assert_eq!(v, w);

    // The stream modes in pieces, from any position (past the block refused).
    let n = u32::from(pos % 20);
    pieces(&data, &cuts, (iv, [0u8; BLOCK], n), |i, o, (v, e, n)| modes::ctr_encrypt(i, o, v, e, n, &enc));
    let n = i32::from(pos % 20) - 2;
    pieces(&data, &cuts, (iv, n), |i, o, (v, n)| modes::ofb_encrypt(i, o, v, n, &enc));
    pieces(&data, &cuts, (iv, n), |i, o, (v, n)| modes::cfb_encrypt(i, o, v, n, pos & 1 == 0, &enc));
    let mut e = [0u8; BLOCK];
    let mut m = u32::from(pos % 20);
    let mut o = vec![0u8; len];
    let mut v = iv;
    let result = modes::ctr_encrypt(&data, &mut o, &mut v, &mut e, &mut m, &enc);
    assert_eq!(result.is_err(), pos % 20 >= 16);

    // CFB-8 and CFB-1 invert.
    let mut o = vec![0u8; len];
    let mut v = iv;
    modes::cfb8_encrypt(&data, &mut o, &mut v, true, &enc);
    let mut back = vec![0u8; len];
    let mut v = iv;
    modes::cfb8_encrypt(&o, &mut back, &mut v, false, &enc);
    assert_eq!(back, data);
    let bits = (len * 8).min(200);
    let mut o = vec![0u8; len];
    let mut v = iv;
    modes::cfb1_encrypt(&data, &mut o, bits, &mut v, true, &enc);
    let mut back = data.clone();
    let mut v = iv;
    modes::cfb1_encrypt(&o, &mut back, bits, &mut v, false, &enc);
    assert_eq!(back, data);

    // Ciphertext stealing: the forms agree and invert.
    let cbc = Cbc(es, ds);
    for nist in [false, true] {
        let mut a = vec![0u8; len];
        let mut b = vec![0u8; len];
        let (mut va, mut vb) = (iv, iv);
        let (ra, rb) = if nist {
            (modes::nistcts_encrypt_block(&data, &mut a, &mut va, &enc), modes::nistcts_encrypt(&data, &mut b, &mut vb, &cbc))
        } else {
            (modes::cts_encrypt_block(&data, &mut a, &mut va, &enc), modes::cts_encrypt(&data, &mut b, &mut vb, &cbc))
        };
        assert_eq!((ra, &a, va), (rb, &b, vb));
        if ra != 0 {
            let mut x = vec![0u8; len];
            let mut y = vec![0u8; len];
            let (mut vx, mut vy) = (iv, iv);
            if nist {
                modes::nistcts_decrypt_block(&a, &mut x, &mut vx, &dec);
                modes::nistcts_decrypt(&a, &mut y, &mut vy, &cbc);
            } else {
                modes::cts_decrypt_block(&a, &mut x, &mut vx, &dec);
                modes::cts_decrypt(&a, &mut y, &mut vy, &cbc);
            }
            assert_eq!(x, data);
            assert_eq!((y, vy), (x, vx));
        }
    }

    // IGE and bi-IGE over whole blocks invert.
    let whole = &data[..len - len % BLOCK];
    let mut iv2 = [0u8; 2 * BLOCK];
    iv2[..BLOCK].copy_from_slice(&iv);
    iv2[BLOCK..].copy_from_slice(&b);
    let mut o = vec![0u8; whole.len()];
    let mut v = iv2;
    modes::ige(whole, &mut o, &mut v, true, &enc);
    let mut back = vec![0u8; whole.len()];
    let mut v = iv2;
    modes::ige(&o, &mut back, &mut v, false, &dec);
    assert_eq!(back, whole);
    let iv4: [u8; 4 * BLOCK] = core::array::from_fn(|i| iv[i % BLOCK] ^ (i as u8));
    let mut o = vec![0u8; whole.len()];
    modes::bi_ige(whole, &mut o, &iv4, true, &enc);
    let mut back = vec![0u8; whole.len()];
    modes::bi_ige(&o, &mut back, &iv4, false, &dec);
    assert_eq!(back, whole);

    // The key wraps invert, and unwrapping arbitrary data never panics.
    let icv8: [u8; 8] = iv[..8].try_into().unwrap();
    let icv4: [u8; 4] = iv[..4].try_into().unwrap();
    let use_iv = pos & 2 == 0;
    let mut wrapped = vec![0u8; len + 16];
    let w = modes::wrap(use_iv.then_some(&icv8), &data, &mut wrapped, &enc);
    if w != 0 {
        let mut back = vec![0u8; len];
        assert_eq!(modes::unwrap(use_iv.then_some(&icv8), &wrapped[..w], &mut back, &dec), len);
        assert_eq!(back, data);
    }
    let w = modes::wrap_pad(use_iv.then_some(&icv4), &data, &mut wrapped, &enc);
    if w != 0 {
        let mut back = vec![0u8; w - 8];
        assert_eq!(modes::unwrap_pad(use_iv.then_some(&icv4), &wrapped[..w], &mut back, &dec), len);
        assert_eq!(&back[..len], data.as_slice());
    }
    let mut junk = vec![0u8; len];
    let _ = modes::unwrap(None, &data, &mut junk, &dec);
    let _ = modes::unwrap_pad(None, &data, &mut junk, &dec);
});
