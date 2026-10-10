//! Fuzzes the provider AEAD contexts (GCM, CCM, OCB, ChaCha20-Poly1305) with arbitrary
//! operations: the first octets pick the context and the direction, and the rest is a script
//! of AAD and data updates (of lengths read from it, over its own octets), finals, `cipher`
//! calls, tag and IV-length sets, TLS AAD and fixed IVs, and re-inits. Nothing may panic and
//! every output must fit the room it was given; then the script, encrypted in pieces with an
//! AAD, must decrypt back under its tag and fail under a changed one.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyssl_crypto::provided::aead::{Ccm, ChaChaPoly, Gcm, Io, Ocb};
use rustyssl_crypto::provided::cipher::Output;
use rustyssl_crypto::sym::BlockAlgorithm;

enum Aead {
    Gcm(Gcm),
    Ccm(Ccm),
    Ocb(Ocb),
    ChaChaPoly(ChaChaPoly),
}

fn make(n: u8) -> Aead {
    match n % 7 {
        0 => Aead::Gcm(Gcm::new(BlockAlgorithm::Aes, 16)),
        1 => Aead::Gcm(Gcm::new(BlockAlgorithm::Aria, 32)),
        2 => Aead::Ccm(Ccm::new(BlockAlgorithm::Aes, 16)),
        3 => Aead::Ccm(Ccm::new(BlockAlgorithm::Sm4, 16)),
        4 => Aead::Ocb(Ocb::new(16)),
        5 => Aead::Ocb(Ocb::new(32)),
        _ => Aead::ChaChaPoly(ChaChaPoly::new()),
    }
}

impl Aead {
    fn key_len(&self) -> usize {
        match self {
            Aead::Gcm(g) => g.key_len(),
            Aead::Ccm(g) => g.key_len(),
            Aead::Ocb(g) => g.key_len(),
            Aead::ChaChaPoly(_) => 32,
        }
    }

    fn iv_len(&self) -> usize {
        match self {
            Aead::Gcm(g) => g.iv_len(),
            Aead::Ccm(g) => g.iv_len(),
            Aead::Ocb(g) => g.iv_len(),
            Aead::ChaChaPoly(_) => 12,
        }
    }

    fn init(&mut self, enc: bool, key: Option<&[u8]>, iv: Option<&[u8]>) -> bool {
        match self {
            Aead::Gcm(g) => g.init(enc, key, iv),
            Aead::Ccm(g) => g.init(enc, key, iv),
            Aead::Ocb(g) => g.init(enc, key, iv),
            Aead::ChaChaPoly(g) => g.init(enc, key, iv),
        }
        .is_ok()
    }

    fn update(&mut self, io: Io<'_>) -> Option<Output> {
        match self {
            Aead::Gcm(g) => g.update(io).ok(),
            Aead::Ccm(g) => g.update(io).ok(),
            Aead::Ocb(g) => g.update(io).ok(),
            Aead::ChaChaPoly(g) => g.update(io).ok(),
        }
    }

    fn cipher(&mut self, io: Io<'_>) -> Option<Output> {
        match self {
            Aead::Gcm(g) => g.cipher(io).ok(),
            Aead::Ccm(g) => g.cipher(io).ok(),
            Aead::Ocb(g) => g.cipher(io).ok(),
            Aead::ChaChaPoly(g) => g.cipher(io).ok(),
        }
    }

    fn finalize(&mut self) -> Option<Output> {
        match self {
            Aead::Gcm(g) => g.finalize().ok(),
            Aead::Ccm(g) => g.finalize().ok(),
            Aead::Ocb(g) => g.finalize().ok(),
            Aead::ChaChaPoly(g) => g.finalize().ok(),
        }
    }

    fn tag(&mut self, n: usize) -> Option<Vec<u8>> {
        match self {
            Aead::Gcm(g) => g.tag(n).ok().map(<[u8]>::to_vec),
            Aead::Ccm(g) => g.tag(n).ok(),
            Aead::Ocb(g) => g.tag(n).ok().map(<[u8]>::to_vec),
            Aead::ChaChaPoly(g) => g.tag(n).ok().map(<[u8]>::to_vec),
        }
    }

    fn set_tag(&mut self, tag: Option<&[u8]>, size: usize) -> bool {
        match self {
            Aead::Gcm(g) => tag.is_some_and(|t| g.set_tag(t).is_ok()),
            Aead::Ccm(g) => g.set_tag(tag, size).is_ok(),
            Aead::Ocb(g) => g.set_tag(tag, size).is_ok(),
            Aead::ChaChaPoly(g) => g.set_tag(tag, size).is_ok(),
        }
    }

    fn set_iv_len(&mut self, n: usize) {
        let _ = match self {
            Aead::Gcm(g) => g.set_iv_len(n),
            Aead::Ccm(g) => g.set_iv_len(n),
            Aead::Ocb(g) => g.set_iv_len(n),
            Aead::ChaChaPoly(_) => Ok(()),
        };
    }

    fn tls_init(&mut self, aad: &[u8]) -> Option<usize> {
        match self {
            Aead::Gcm(g) => g.tls_init(aad),
            Aead::Ccm(g) => g.tls_init(aad),
            Aead::Ocb(_) => None,
            Aead::ChaChaPoly(g) => g.tls_init(aad),
        }
    }

    fn tls_iv_fixed(&mut self, fixed: &[u8]) {
        let _ = match self {
            Aead::Gcm(g) => g.tls_iv_fixed(fixed, fixed.len() == g.iv_len()),
            Aead::Ccm(g) => g.tls_iv_fixed(fixed),
            Aead::Ocb(_) => Ok(()),
            Aead::ChaChaPoly(g) => g.tls_iv_fixed(fixed),
        };
    }

    fn is_ccm(&self) -> bool {
        matches!(self, Aead::Ccm(_))
    }
}

fn io(input: Option<&[u8]>, inl: usize, out: bool) -> Io<'_> {
    Io {
        input,
        inl,
        out,
        in_place: false,
        outsize: inl + 16,
    }
}

fn fits(o: Option<Output>, inl: usize) {
    if let Some(o) = o {
        assert!(o.data.len() <= inl + 16, "{} > {}", o.data.len(), inl + 16);
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&head, script)) = data.split_first() else {
        return;
    };
    let key = [0x5au8; 32];
    let iv = [0xa5u8; 16];

    // A script of arbitrary steps on one context: no panics, outputs within their room.
    let mut a = make(head);
    let key = &key[..a.key_len()];
    let ivl = a.iv_len();
    a.init(head & 0x10 != 0, Some(key), Some(&iv[..ivl]));
    let mut rest = script;
    while let Some((&op, tail)) = rest.split_first() {
        let len = usize::from(tail.first().copied().unwrap_or(0));
        let input = &tail[..len.min(tail.len())];
        let inl = input.len();
        match op % 10 {
            0 => fits(a.update(io(Some(input), inl, false)), 0),
            1 | 2 => fits(a.update(io(Some(input), inl, true)), inl),
            3 => fits(a.update(io(None, inl, false)), 0),
            4 => fits(a.finalize(), 0),
            5 => fits(a.cipher(io(Some(input), inl, op & 0x80 != 0)), inl),
            6 => {
                let n = usize::from(op >> 4);
                if op & 0x08 != 0 {
                    let _ = a.tag(n);
                } else {
                    a.set_tag((op & 0x04 != 0).then_some(input), n.max(inl));
                }
            }
            7 => a.set_iv_len(usize::from(op >> 4)),
            8 => {
                if op & 0x80 != 0 {
                    let _ = a.tls_init(input);
                } else {
                    a.tls_iv_fixed(input);
                }
            }
            _ => {
                let ivl = a.iv_len().min(iv.len());
                a.init(
                    op & 0x80 != 0,
                    (op & 0x40 != 0).then_some(key),
                    (op & 0x20 != 0).then_some(&iv[..ivl]),
                );
            }
        }
        rest = tail.get(len.min(tail.len())..).unwrap_or_default();
    }

    // Encrypt the script with an AAD, in pieces; it decrypts back under its tag only.
    let piece = usize::from(head >> 3) + 1;
    let aad = &script[..script.len().min(usize::from(head % 23))];
    let run = |enc: bool, input: &[u8], tag: Option<&[u8]>| -> (Vec<u8>, bool, Vec<u8>) {
        let mut a = make(head);
        let ivl = a.iv_len();
        if a.is_ccm() || matches!(a, Aead::Ocb(_)) {
            assert!(a.set_tag(None, 16));
        }
        assert!(a.init(enc, Some(key), Some(&iv[..ivl])));
        if let Some(t) = tag {
            assert!(a.set_tag(Some(t), t.len()));
        }
        let mut out = Vec::new();
        if a.is_ccm() {
            a.update(io(None, input.len(), false)).unwrap();
            if !aad.is_empty() {
                a.update(io(Some(aad), aad.len(), false)).unwrap();
            }
            let o = a.update(io(Some(input), input.len(), true)).unwrap();
            if o.failed.is_some() {
                return (o.data.to_vec(), false, Vec::new());
            }
            out.extend_from_slice(&o.data);
        } else {
            for c in aad.chunks(piece) {
                a.update(io(Some(c), c.len(), false)).unwrap();
            }
            for c in input.chunks(piece) {
                out.extend_from_slice(&a.update(io(Some(c), c.len(), true)).unwrap().data);
            }
        }
        let ok = match a.finalize() {
            Some(o) => {
                out.extend_from_slice(&o.data);
                o.failed.is_none()
            }
            None => false,
        };
        let t = if enc { a.tag(16).unwrap() } else { Vec::new() };
        (out, ok, t)
    };
    let (ct, ok, tag) = run(true, script, None);
    assert!(ok);
    assert_eq!(ct.len(), script.len());
    let (pt, ok, _) = run(false, &ct, Some(&tag));
    assert!(ok);
    assert_eq!(pt, script);
    let mut bad = tag;
    bad[usize::from(head) % 16] ^= 1;
    let (_, ok, _) = run(false, &ct, Some(&bad));
    assert!(!ok);
});
