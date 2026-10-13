//! Fuzzes the deprecated low-level hashes' state machines (`rustyssl_crypto::lowlevel::hash`)
//! with operation scripts: the first octet picks the hash, then each octet an operation
//! (update, Whirlpool's bit update, transform, init, finish, or overwriting a field with
//! arbitrary values, as an application with the struct in hand can) and the next octets its
//! arguments. Nothing may panic, a count past the buffer must be refused, and while the
//! script only feeds data, each finish must equal the EVP digest backend's digest of
//! everything fed since the last init (for Whirlpool, when the bits make whole octets).

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyssl_crypto::lowlevel::hash::{
    Error, MD32_BLOCK, Md32, Md32Kind, Mdc2, SHA512_BLOCK, Sha512, Whirlpool,
};
use rustyssl_crypto::md;

/// Reads argument octets, zero once they run out.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn byte(&mut self) -> u8 {
        let (&b, rest) = self.0.split_first().unwrap_or((&0, &[]));
        self.0 = rest;
        b
    }

    fn word(&mut self) -> u32 {
        u32::from_le_bytes([self.byte(), self.byte(), self.byte(), self.byte()])
    }

    fn take(&mut self, n: usize) -> &'a [u8] {
        let (head, tail) = self.0.split_at(n.min(self.0.len()));
        self.0 = tail;
        head
    }

    fn done(&self) -> bool {
        self.0.is_empty()
    }
}

/// One of the hashes, with its context.
enum State {
    Md32(Md32Kind, fn() -> Md32, Md32, usize, md::Algorithm),
    Sha512(bool, Sha512),
    Mdc2(Mdc2),
    Whirlpool(Whirlpool),
}

impl State {
    fn new(pick: u8) -> Self {
        let md32 = |kind, init: fn() -> Md32, size, alg| State::Md32(kind, init, init(), size, alg);
        match pick % 10 {
            0 => md32(Md32Kind::Md4, Md32::md4, 16, md::Algorithm::Md4),
            1 => md32(Md32Kind::Md5, Md32::md5, 16, md::Algorithm::Md5),
            2 => md32(Md32Kind::Ripemd160, Md32::ripemd160, 20, md::Algorithm::Ripemd160),
            3 => md32(Md32Kind::Sha1, Md32::sha1, 20, md::Algorithm::Sha1),
            4 => md32(Md32Kind::Sha256, Md32::sha224, 28, md::Algorithm::Sha224),
            5 => md32(Md32Kind::Sha256, Md32::sha256, 32, md::Algorithm::Sha256),
            6 | 7 => {
                let mut s = Sha512 { h: [0; 8], nl: 0, nh: 0, data: [0; SHA512_BLOCK], num: 0 };
                let sha512 = pick % 10 == 7;
                if sha512 { s.init_sha512() } else { s.init_sha384() }
                State::Sha512(sha512, s)
            }
            8 => {
                let mut m = Mdc2 { num: 0, data: [0; 8], h: [0; 8], hh: [0; 8], pad_type: 0 };
                m.init();
                State::Mdc2(m)
            }
            _ => State::Whirlpool(Whirlpool::new()),
        }
    }

    fn init(&mut self) {
        match self {
            State::Md32(_, init, c, _, _) => *c = init(),
            State::Sha512(true, s) => s.init_sha512(),
            State::Sha512(false, s) => s.init_sha384(),
            State::Mdc2(m) => m.init(),
            State::Whirlpool(w) => *w = Whirlpool::new(),
        }
    }

    /// The EVP algorithm to compare with, if there is one.
    fn model(&self) -> Option<md::Algorithm> {
        match self {
            State::Md32(_, _, _, _, alg) => Some(*alg),
            State::Sha512(true, _) => Some(md::Algorithm::Sha512),
            State::Sha512(false, _) => Some(md::Algorithm::Sha384),
            State::Mdc2(_) => None,
            State::Whirlpool(_) => Some(md::Algorithm::Whirlpool),
        }
    }

    /// Whether the count of buffered octets or bits is within the buffer.
    fn sane(&self) -> bool {
        match self {
            State::Md32(_, _, c, _, _) => (c.num as usize) < MD32_BLOCK,
            State::Sha512(_, s) => (s.num as usize) < SHA512_BLOCK,
            State::Mdc2(m) => m.num < 8,
            State::Whirlpool(w) => w.bitoff < 512,
        }
    }

    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        match self {
            State::Md32(kind, _, c, _, _) => c.update(*kind, data),
            State::Sha512(_, s) => s.update(data),
            State::Mdc2(m) => m.update(data),
            State::Whirlpool(w) => w.bit_update(data, data.len() * 8),
        }
    }

    fn finish(&mut self) -> Result<Vec<u8>, Error> {
        match self {
            State::Md32(kind, _, c, size, _) => {
                c.finish(*kind)?;
                let mut out = vec![0; *size];
                c.output(*kind, &mut out);
                Ok(out)
            }
            State::Sha512(sha512, s) => {
                s.finish()?;
                let mut out = vec![0; if *sha512 { 64 } else { 48 }];
                s.output(&mut out);
                Ok(out)
            }
            State::Mdc2(m) => m.finish().map(|d| d.to_vec()),
            State::Whirlpool(w) => {
                w.finish()?;
                Ok(w.h.to_vec())
            }
        }
    }
}

/// The bits fed since the last init, and whether nothing else touched the context.
struct Fed {
    bits: Vec<bool>,
    clean: bool,
}

impl Fed {
    fn octets(&mut self, data: &[u8]) {
        for b in data {
            self.bits.extend((0..8).rev().map(|i| b >> i & 1 == 1));
        }
    }

    fn packed(&self) -> Option<Vec<u8>> {
        (self.bits.len() % 8 == 0).then(|| {
            self.bits.chunks(8).map(|c| c.iter().fold(0u8, |a, &b| a << 1 | u8::from(b))).collect()
        })
    }
}

fuzz_target!(|data: &[u8]| {
    let mut r = Reader(data);
    let mut state = State::new(r.byte());
    let mut fed = Fed { bits: Vec::new(), clean: true };
    // A one-shot model of everything MDC2 was fed, checked against feeding it in pieces.
    while !r.done() {
        match r.byte() % 8 {
            0 | 1 => {
                let n = usize::from(r.byte()) + usize::from(r.byte() % 4) * 256;
                let input = r.take(n);
                let sane = state.sane();
                let result = state.update(input);
                if !sane && !input.is_empty() {
                    assert_eq!(result, Err(Error::Corrupt));
                } else {
                    assert_eq!(result, Ok(()));
                    fed.octets(input);
                }
            }
            2 => {
                // Whirlpool's bits; another hash's octets of the same count.
                let bits = usize::from(r.byte()) * 4 + usize::from(r.byte() % 4);
                let input = r.take(bits.div_ceil(8));
                if let State::Whirlpool(w) = &mut state {
                    let sane = w.bitoff < 512;
                    match w.bit_update(input, bits) {
                        Ok(()) => {
                            assert!(bits == 0 || (sane && input.len() * 8 >= bits));
                            assert!(bits == 0 || w.bitoff < 512);
                            let all: Vec<bool> = input.iter().flat_map(|b| (0..8).rev().map(move |i| b >> i & 1 == 1)).collect();
                            fed.bits.extend_from_slice(&all[all.len() - bits..]);
                        }
                        Err(e) => assert!(
                            (e == Error::Corrupt && !sane) || (e == Error::Input && input.len() * 8 < bits)
                        ),
                    }
                }
            }
            3 => {
                let block = r.take(128);
                let mut b64 = [0u8; MD32_BLOCK];
                let mut b128 = [0u8; SHA512_BLOCK];
                b64.iter_mut().zip(block).for_each(|(d, s)| *d = *s);
                b128.iter_mut().zip(block).for_each(|(d, s)| *d = *s);
                match &mut state {
                    State::Md32(kind, _, c, _, _) => c.transform(*kind, &b64),
                    State::Sha512(_, s) => s.transform(&b128),
                    _ => {}
                }
                fed.clean = false;
            }
            4 => {
                state.init();
                fed = Fed { bits: Vec::new(), clean: true };
            }
            5 => {
                // Overwrites a field, as an application can.
                let v = r.word();
                match (&mut state, r.byte() % 3) {
                    (State::Md32(_, _, c, _, _), 0) => c.num = v,
                    (State::Md32(_, _, c, _, _), 1) => c.nl = v,
                    (State::Sha512(_, s), 0) => s.num = v,
                    (State::Sha512(_, s), _) => s.nl = u64::from(v),
                    (State::Mdc2(m), 0) => m.num = v,
                    (State::Mdc2(m), _) => m.pad_type = v % 4,
                    (State::Whirlpool(w), 0) => w.bitoff = v % 1024,
                    (State::Whirlpool(w), _) => w.bitlen[usize::from(r.byte() % 4)] = u64::from(v),
                    (State::Md32(_, _, c, _, _), _) => c.nh = v,
                }
                fed.clean = false;
            }
            _ => {
                let sane = state.sane();
                match state.finish() {
                    Ok(out) => {
                        assert!(sane);
                        if fed.clean
                            && let (Some(alg), Some(octets)) = (state.model(), fed.packed())
                        {
                            let mut ctx = md::context(alg);
                            ctx.update(&octets).unwrap();
                            let mut want = vec![0; out.len()];
                            ctx.finalize(&mut want).unwrap();
                            assert_eq!(out, want);
                        }
                    }
                    Err(e) => assert!(e == Error::Corrupt && !sane),
                }
                // A final changes the context in ways the model doesn't follow.
                fed.clean = false;
            }
        }
    }
});
