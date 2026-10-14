//! Fuzzes the AEAD helpers' state machines (`rustyssl_crypto::lowlevel::aead`) with arbitrary
//! keys, nonces, lengths, data, and splits. Nothing may panic, and: GCM gives the same output
//! and tag in pieces as at once, through the block function and through the CTR function, and
//! decryption inverts it with a matching tag (a changed one fails); CCM (any tag and length
//! field sizes) inverts, its two forms agree, and a wrong length is refused; OCB in pieces
//! (whole blocks until the last) matches at once, with and without its bulk function, and
//! inverts; XTS inverts for a block or more. A script of arbitrary GCM, CCM, and OCB calls in
//! any order never panics.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyssl_crypto::lowlevel::aead::{self, Ccm, Ccm128, Gcm, Ocb, Ocb128};
use rustyssl_crypto::lowlevel::aes::{Schedule, decrypt_schedule, encrypt_schedule};
use rustyssl_crypto::lowlevel::modes::{BLOCK, Block128, Ctr128};

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

struct Ctr<'a>(&'a Enc);

impl Ctr128 for Ctr<'_> {
    fn ctr(&self, input: &[u8], out: &mut [u8], blocks: usize, iv: &[u8; BLOCK]) {
        let mut c = *iv;
        for i in 0..blocks {
            let k = self.0.block(&c);
            for n in 0..BLOCK {
                out[i * BLOCK + n] = input[i * BLOCK + n] ^ k[n];
            }
            let v = u32::from_be_bytes(c[12..].try_into().unwrap()).wrapping_add(1);
            c[12..].copy_from_slice(&v.to_be_bytes());
        }
    }
}

struct CcmFn<'a>(&'a Enc, bool);

impl Ccm128 for CcmFn<'_> {
    fn ccm(&self, input: &[u8], out: &mut [u8], blocks: usize, ivec: &[u8; BLOCK], cmac: &mut [u8; BLOCK]) {
        let mut c = *ivec;
        for i in 0..blocks {
            let k = self.0.block(&c);
            for n in 0..BLOCK {
                let x = input[i * BLOCK + n];
                let y = x ^ k[n];
                out[i * BLOCK + n] = y;
                cmac[n] ^= if self.1 { x } else { y };
            }
            *cmac = self.0.block(cmac);
            let v = u64::from_be_bytes(c[8..].try_into().unwrap()).wrapping_add(1);
            c[8..].copy_from_slice(&v.to_be_bytes());
        }
    }
}

struct OcbFn<'a>(&'a Enc, &'a Dec, bool);

impl Ocb128 for OcbFn<'_> {
    fn ocb(&self, input: &[u8], out: &mut [u8], blocks: usize, start: usize, offset: &mut [u8; BLOCK], l: &[[u8; BLOCK]], checksum: &mut [u8; BLOCK]) {
        for i in 0..blocks {
            let z = (start + i).trailing_zeros() as usize;
            let mut t = [0u8; BLOCK];
            for n in 0..BLOCK {
                offset[n] ^= l[z][n];
                t[n] = input[i * BLOCK + n] ^ offset[n];
            }
            let t = if self.2 { self.1.block(&t) } else { self.0.block(&t) };
            for n in 0..BLOCK {
                out[i * BLOCK + n] = t[n] ^ offset[n];
                checksum[n] ^= if self.2 { out[i * BLOCK + n] } else { input[i * BLOCK + n] };
            }
        }
    }
}

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

/// Splits `len` into pieces from `cuts`: 1 to 40 octets each, or with `blocks`, whole blocks
/// with any partial block alone at the end.
fn pieces(len: usize, cuts: &[u8], blocks: bool) -> Vec<usize> {
    let mut out = Vec::new();
    let mut left = if blocks { len - len % BLOCK } else { len };
    let mut i = 0;
    while left > 0 {
        let c = usize::from(cuts.get(i % cuts.len().max(1)).copied().unwrap_or(7));
        let n = if blocks { (c % 4 + 1) * BLOCK } else { c % 40 + 1 }.min(left);
        out.push(n);
        left -= n;
        i += 1;
    }
    if blocks && len % BLOCK != 0 {
        out.push(len % BLOCK);
    }
    out
}

fuzz_target!(|input: &[u8]| {
    let mut r = Reader(input);
    let key = r.take(16).to_vec();
    let (Ok(es), Ok(ds)) = (encrypt_schedule(&[key.as_slice(), &[0; 16]].concat()[..16]), decrypt_schedule(&[key.as_slice(), &[0; 16]].concat()[..16])) else {
        return;
    };
    let (e, d) = (Enc(es), Dec(ds));
    let ivlen = usize::from(r.byte() % 70);
    let iv = r.take(ivlen).to_vec();
    let alen = usize::from(r.byte());
    let aad = r.take(alen).to_vec();
    let len = usize::from(r.byte()) * 3;
    let cuts = r.take(6).to_vec();
    let mode = r.byte();
    let data = r.take(len).to_vec();
    let len = data.len();

    // GCM: at once, in pieces, through the CTR function; decryption with the tag.
    let mut g = Gcm::new(&e);
    g.setiv(&iv, &e);
    assert_eq!(g.aad(&aad), 0);
    let mut c1 = vec![0u8; len];
    assert_eq!(g.encrypt(&data, &mut c1, &e), 0);
    let mut t1 = [0u8; 16];
    g.tag(&mut t1);
    for use_ctr in [false, true] {
        let mut g = Gcm::new(&e);
        g.setiv(&iv, &e);
        let mut at = 0;
        for n in pieces(aad.len(), &cuts, false) {
            assert_eq!(g.aad(&aad[at..at + n]), 0);
            at += n;
        }
        let mut c2 = vec![0u8; len];
        let mut at = 0;
        for n in pieces(len, &cuts, false) {
            let rr = if use_ctr { g.encrypt_ctr32(&data[at..at + n], &mut c2[at..at + n], &e, &Ctr(&e)) } else { g.encrypt(&data[at..at + n], &mut c2[at..at + n], &e) };
            assert_eq!(rr, 0);
            at += n;
        }
        let mut t2 = [0u8; 16];
        g.tag(&mut t2);
        assert_eq!((&c1, t1), (&c2, t2));
    }
    let mut g = Gcm::new(&e);
    g.setiv(&iv, &e);
    g.aad(&aad);
    let mut p = vec![0u8; len];
    assert_eq!(g.decrypt_ctr32(&c1, &mut p, &e, &Ctr(&e)), 0);
    assert_eq!(p, data);
    let mut bad = t1;
    bad[usize::from(mode % 16)] ^= 1;
    assert_eq!(g.finish(Some(&t1)), 0);
    assert_eq!(g.finish(Some(&bad)) == 0, false);

    // CCM: any tag and length field sizes.
    let m = u32::from(mode >> 4);
    let l = u32::from(mode & 7);
    let new_ccm = || Ccm { nonce: [0; 16], cmac: [0; 16], blocks: 0 };
    let mut tags = Vec::new();
    for stream in [false, true] {
        let mut c = new_ccm();
        c.init(m, l);
        let mut out = vec![0u8; len];
        let set = c.setiv(&iv, len);
        c.aad(&aad, &e);
        let rr = if stream { c.encrypt_ccm64(&data, &mut out, &e, &CcmFn(&e, true)) } else { c.encrypt(&data, &mut out, &e) };
        let mut tag = [0u8; 16];
        let tl = c.tag(&mut tag, (m as usize).wrapping_sub(2) / 2 % 8 * 2 + 2);
        tags.push((set, rr, out.clone(), tag, tl));
        if set == 0 && rr == 0 {
            let mut c = new_ccm();
            c.init(m, l);
            c.setiv(&iv, len);
            c.aad(&aad, &e);
            let mut back = vec![0u8; len];
            let rd = if stream { c.decrypt_ccm64(&out, &mut back, &e, &CcmFn(&e, false)) } else { c.decrypt(&out, &mut back, &e) };
            assert_eq!(rd, 0);
            let mut tag2 = [0u8; 16];
            c.tag(&mut tag2, tl);
            assert_eq!(tag2, tag);
            assert_eq!(back, data);
        }
    }
    assert_eq!(tags[0], tags[1]);
    let mut c = new_ccm();
    c.init(m, l);
    if c.setiv(&iv, len) == 0 {
        let mut out = vec![0u8; len + 1];
        let mut longer = data.clone();
        longer.push(0);
        assert_eq!(c.encrypt(&longer, &mut out, &e), -1);
    }

    // OCB: whole blocks in pieces then the rest, with and without the bulk function.
    if (1..=15).contains(&iv.len()) {
        let mut results = Vec::new();
        for stream in [false, true] {
            let mut o = Ocb::new(&e);
            assert_eq!(o.setiv(&iv, 16, &e), 1);
            o.aad(&aad, &e);
            let mut c = vec![0u8; len];
            let mut at = 0;
            for n in pieces(len, &cuts, true) {
                let f = OcbFn(&e, &d, false);
                o.encrypt(&data[at..at + n], &mut c[at..at + n], &e, &d, stream.then_some(&f as &dyn Ocb128));
                at += n;
            }
            let mut tag = [0u8; 16];
            o.tag(&mut tag, &e);
            let mut o = Ocb::new(&e);
            o.setiv(&iv, 16, &e);
            o.aad(&aad, &e);
            let mut p = vec![0u8; len];
            let f = OcbFn(&e, &d, true);
            o.decrypt(&c, &mut p, &e, &d, stream.then_some(&f as &dyn Ocb128));
            assert_eq!(p, data);
            assert_eq!(o.finish(&tag, &e), 0);
            results.push((c, tag));
        }
        assert_eq!(results[0], results[1]);
    }

    // XTS.
    let tweak: [u8; 16] = core::array::from_fn(|i| iv.get(i).copied().unwrap_or(0));
    let mut c = vec![0u8; len];
    let rr = aead::xts(&tweak, &data, &mut c, true, &e, &e);
    assert_eq!(rr == 0, len >= 16);
    if rr == 0 {
        let mut p = vec![0u8; len];
        assert_eq!(aead::xts(&tweak, &c, &mut p, false, &d, &e), 0);
        assert_eq!(p, data);
    }

    // A script of arbitrary calls.
    let mut g = Gcm::new(&e);
    let mut c = new_ccm();
    let mut o = Ocb::new(&e);
    let mut buf = vec![0u8; 64];
    for (i, &op) in cuts.iter().chain(r.0.iter()).enumerate().take(64) {
        let n = usize::from(op >> 3) % 64;
        let chunk = &data[..n.min(len)];
        let out = &mut buf[..chunk.len()];
        match op % 12 {
            0 => g.setiv(chunk, &e),
            1 => _ = g.aad(chunk),
            2 => _ = g.encrypt(chunk, out, &e),
            3 => _ = g.decrypt_ctr32(chunk, out, &e, &Ctr(&e)),
            4 => _ = g.finish(Some(&chunk[..chunk.len().min(17)])),
            5 => c.init(u32::from(op), u32::from(op >> 4)),
            6 => _ = c.setiv(chunk, i),
            7 => c.aad(chunk, &e),
            8 => _ = c.encrypt(chunk, out, &e),
            9 => _ = o.setiv(chunk, n % 18, &e),
            10 => _ = o.encrypt(chunk, out, &e, &d, None),
            _ => _ = o.finish(&chunk[..chunk.len().min(17)], &e),
        }
    }
});
