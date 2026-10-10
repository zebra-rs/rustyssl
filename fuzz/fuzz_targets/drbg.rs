//! Fuzzes the DRBG mechanisms: the first octet picks CTR-DRBG (key length, derivation
//! function), Hash-DRBG, or HMAC-DRBG (digest); the rest is a sequence of operations
//! (instantiate, reseed, generate, uninstantiate) with inputs of arbitrary lengths. Nothing may
//! panic, two instances fed the same operations must stay identical, and a generator must
//! refuse to run before it's instantiated.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyssl_crypto::md::Algorithm;
use rustyssl_crypto::rand::{CtrDrbg, Drbg, Error, HashDrbg, HmacDrbg};

fn make(kind: u8) -> Option<Box<dyn Drbg>> {
    let digests = [
        Algorithm::Sha1,
        Algorithm::Sha256,
        Algorithm::Sha512,
        Algorithm::Sha3_384,
        Algorithm::Md5Sha1,
    ];
    let digest = digests[usize::from(kind / 8) % digests.len()];
    Some(match kind % 8 {
        0..=5 => Box::new(CtrDrbg::new([16, 24, 32][usize::from(kind % 3)], kind % 8 < 3).ok()?),
        6 => Box::new(HashDrbg::new(digest).ok()?),
        _ => Box::new(HmacDrbg::new(digest).ok()?),
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&kind, mut rest)) = data.split_first() else {
        return;
    };
    let (Some(mut a), Some(mut b)) = (make(kind), make(kind)) else {
        return;
    };
    let mut instantiated = false;
    while let Some((&op, tail)) = rest.split_first() {
        let len = usize::from(op >> 2);
        let (input, tail) = tail.split_at(len.min(tail.len()));
        rest = tail;
        let (x, y) = input.split_at(input.len() / 2);
        match op & 3 {
            0 => {
                a.instantiate(x, y, input);
                b.instantiate(x, y, input);
                instantiated = true;
            }
            1 => {
                let r = a.reseed(x, y);
                assert_eq!(r, b.reseed(x, y));
                assert_eq!(r.is_ok(), instantiated);
            }
            2 => {
                let (mut oa, mut ob) = (vec![0u8; len * 7], vec![0u8; len * 7]);
                let r = a.generate(&mut oa, input);
                assert_eq!(r, b.generate(&mut ob, input));
                assert_eq!(r == Err(Error::NotInstantiated), !instantiated);
                assert_eq!(oa, ob);
            }
            _ => {
                a.uninstantiate();
                b.uninstantiate();
                instantiated = false;
            }
        }
    }
});
