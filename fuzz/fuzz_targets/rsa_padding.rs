//! Fuzzes RSA's padding checks, which see what a private-key operation recovers from an
//! attacker's ciphertext or a public-key operation from an attacker's signature. The first
//! octet picks the check, the next ones the sizes, and the rest is the encoded block (and,
//! where one is needed, a label, a key-derivation key, or a salt). No check may panic, and
//! each must agree with a plain model of its encoding:
//!
//! - PKCS #1 v1.5 type 2 and OAEP decode exactly what a straightforward (not constant-time)
//!   decoder decodes, and implicit rejection gives that message when the padding is good;
//! - PKCS #1 v1.5 type 1, X9.31, and no padding give back what was padded, and PSS verifies
//!   what it encoded, with the salt length given and detected.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyssl_crypto::md::{self, Algorithm};
use rustyssl_crypto::rsa::{self, Hash, PssSaltLen};

/// A digest from the default backend.
struct Md(Algorithm, usize, usize);

impl Hash for Md {
    fn size(&self) -> usize {
        self.1
    }
    fn block_size(&self) -> usize {
        self.2
    }
    fn digest(&self, parts: &[&[u8]]) -> Option<Vec<u8>> {
        let mut c = md::context(self.0);
        for p in parts {
            c.update(p).ok()?;
        }
        let mut out = vec![0; self.1];
        c.finalize(&mut out).ok()?;
        Some(out)
    }
}

const DIGESTS: [Md; 3] = [
    Md(Algorithm::Sha1, 20, 64),
    Md(Algorithm::Sha256, 32, 64),
    Md(Algorithm::Sha512, 64, 128),
];

/// `from` left-padded with zeros to `num` octets.
fn left_padded(from: &[u8], num: usize) -> Vec<u8> {
    let mut em = vec![0u8; num - from.len()];
    em.extend_from_slice(from);
    em
}

/// PKCS #1 v1.5 type 2, plainly: `00 02 PS 00 M` with at least eight octets of PS.
fn model_type2(em: &[u8]) -> Option<Vec<u8>> {
    if em.len() < 11 || em[0] != 0 || em[1] != 2 {
        return None;
    }
    let zero = em.iter().skip(2).position(|&b| b == 0)? + 2;
    (zero >= 10).then(|| em[zero + 1..].to_vec())
}

/// OAEP, plainly: `00 || maskedSeed || maskedDB`, DB = `lHash || 00.. || 01 || M`.
fn model_oaep(em: &[u8], label: &[u8], md: &Md) -> Option<Vec<u8>> {
    let h = md.size();
    if em.len() < 2 * h + 2 || em[0] != 0 {
        return None;
    }
    let (masked_seed, masked_db) = em[1..].split_at(h);
    let seed_mask = rsa::mgf1(h, masked_db, md)?;
    let seed: Vec<u8> = masked_seed.iter().zip(&seed_mask).map(|(a, b)| a ^ b).collect();
    let db_mask = rsa::mgf1(masked_db.len(), &seed, md)?;
    let db: Vec<u8> = masked_db.iter().zip(&db_mask).map(|(a, b)| a ^ b).collect();
    if db[..h] != md.digest(&[label])?[..] {
        return None;
    }
    let one = db[h..].iter().position(|&b| b != 0)? + h;
    (db[one] == 1).then(|| db[one + 1..].to_vec())
}

/// The check's result as an option.
fn decoded(r: isize, to: &[u8]) -> Option<Vec<u8>> {
    usize::try_from(r).ok().map(|n| to[..n].to_vec())
}

fuzz_target!(|data: &[u8]| {
    let [mode, size, tlen, pick, rest @ ..] = data else {
        return;
    };
    // An encoded block of 11 to 266 octets: room for every padding with small digests.
    let num = 11 + usize::from(*size);
    let md = &DIGESTS[usize::from(*pick) % DIGESTS.len()];
    let tlen = usize::from(*tlen) + 1;
    let (block, extra) = rest.split_at(rest.len().min(num));
    let mut to = vec![0u8; tlen];
    match mode % 6 {
        0 => {
            // Type 2, as `from` (without its leading zero, as RSA's decryption gives it).
            let em = left_padded(block, num);
            let (r, _) = rsa::check_pkcs1_type2(&mut to, block, num);
            let want = model_type2(&em).filter(|m| m.len() <= tlen);
            assert_eq!(decoded(r, &to), want, "type 2");
        }
        1 => {
            // Implicit rejection: the message when the padding is good, else a synthetic one.
            if block.len() != num {
                return;
            }
            let kdk = extra.get(..32).unwrap_or(&[0u8; 32]);
            let (r, _) = rsa::check_pkcs1_type2_implicit(&mut to, block, num, kdk, &DIGESTS[1]);
            let got = decoded(r, &to);
            match model_type2(block).filter(|m| m.len() <= tlen) {
                Some(m) => assert_eq!(got, Some(m), "implicit rejection, good padding"),
                None => {
                    if let Some(g) = got {
                        assert!(g.len() <= num - 11 && g.len() <= tlen, "synthetic length");
                    }
                }
            }
        }
        2 => {
            let em = left_padded(block, num);
            let (r, _) = rsa::check_oaep(&mut to, block, num, extra, md, md);
            let want = model_oaep(&em, extra, md).filter(|m| m.len() <= tlen);
            assert_eq!(decoded(r, &to), want, "OAEP");
        }
        3 => {
            // Type 1 and X9.31: arbitrary input, then a round trip of the input as a message.
            let _ = rsa::check_pkcs1_type1(&mut to, block, num);
            let _ = rsa::check_x931(&mut to, block, num);
            let _ = rsa::check_none(&mut to, block);
            let m = &block[..block.len().min(num - 11)];
            let mut em = vec![0u8; num];
            if rsa::add_pkcs1_type1(&mut em, m).0.is_ok() {
                let mut out = vec![0u8; num];
                let (r, _) = rsa::check_pkcs1_type1(&mut out, &em[1..], num);
                assert_eq!(r.ok().map(|n| out[..n].to_vec()), Some(m.to_vec()), "type 1");
            }
            // OpenSSL's check rejects two blocks its padding makes (and rustyssl keeps that):
            // an empty message's, whose BA its scan never reaches, and one of `num - 3`
            // octets, `6B BA` with no BB between.
            let m = &block[..block.len().min(num - 2)];
            let returns = !m.is_empty() && m.len() != num - 3;
            if returns && rsa::add_x931(&mut em, m).0.is_ok() {
                let mut out = vec![0u8; num];
                let (r, _) = rsa::check_x931(&mut out, &em, num);
                assert_eq!(r.ok().map(|n| out[..n].to_vec()), Some(m.to_vec()), "X9.31");
            }
        }
        4 => {
            // PSS verification of an arbitrary block: never a panic.
            let bits = num * 8 - usize::from(extra.first().copied().unwrap_or(0) % 8);
            let mhash = extra.get(1..1 + md.size()).unwrap_or(&[0u8; 64][..md.size()]);
            for slen in [PssSaltLen::AUTO, PssSaltLen::DIGEST, 0, 20] {
                let _ = rsa::verify_pss(mhash, md, md, block, bits, slen);
            }
        }
        _ => {
            // PSS round trip with the salt from the input.
            let bits = num * 8 - usize::from(extra.first().copied().unwrap_or(0) % 8);
            let mhash = md.digest(&[block]).unwrap_or_default();
            let mut salt = extra.iter().copied().cycle();
            let mut rng = |out: &mut [u8]| {
                for b in out.iter_mut() {
                    *b = salt.next().unwrap_or(0x5a);
                }
                true
            };
            let slen = i32::try_from(tlen % 70).unwrap_or(0) - 4;
            let mut em = vec![0u8; num];
            if let (Ok(used), _) = rsa::add_pss(&mut em, bits, &mhash, md, md, slen, &mut rng) {
                for check in [used, PssSaltLen::AUTO] {
                    let (r, _) = rsa::verify_pss(&mhash, md, md, &em, bits, check);
                    assert!(r.is_ok(), "PSS round trip, salt length {used} checked as {check}");
                }
            }
        }
    }
});
