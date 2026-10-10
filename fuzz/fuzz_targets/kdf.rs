//! Fuzzes the KDF backend with arbitrary parameters: the first octet picks the KDF, the next
//! few its digest, sizes, and options (kept small so memory-hard KDFs stay fast), and the rest
//! splits into its byte inputs. A derivation must never panic. For the KDFs whose output is a
//! stream of blocks, a shorter output must be a prefix of a longer one, and every derivation
//! must be deterministic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyssl_crypto::kdf::{self, Argon2, Argon2Variant, KbkdfMode, X942Info};
use rustyssl_crypto::{mac, md, sym};

/// Reads parameter octets, zero once they run out.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn byte(&mut self) -> u8 {
        let (&b, rest) = self.0.split_first().unwrap_or((&0, &[]));
        self.0 = rest;
        b
    }

    /// The rest, split into `n` inputs at the given octets' positions.
    fn inputs(self, n: usize) -> Vec<&'a [u8]> {
        let mut out = Vec::with_capacity(n);
        let mut rest = self.0;
        for _ in 1..n {
            let at = rest.first().map_or(0, |&b| usize::from(b)).min(rest.len());
            let (head, tail) = rest.split_at(at);
            out.push(head.get(1..).unwrap_or_default());
            rest = tail;
        }
        out.push(rest);
        out
    }
}

/// Derives `len` octets, or `None` if refused.
fn derive(
    kind: u8,
    digest: md::Algorithm,
    opts: [u8; 4],
    inputs: &[&[u8]],
    len: usize,
) -> Option<Vec<u8>> {
    let [a, b, c, d] = [0, 1, 2, 3].map(|i| inputs.get(i).copied().unwrap_or_default());
    let mut out = vec![0u8; len];
    let ok = match kind % 18 {
        0 => kdf::hkdf(digest, a, b, c, &mut out),
        1 => kdf::hkdf_expand(digest, a, b, &mut out),
        2 => kdf::tls13_expand(digest, a, b, c, d, &mut out),
        3 => kdf::tls13_extract(
            digest,
            (opts[0] & 1 == 1).then_some(a),
            (opts[0] & 2 == 2).then_some(b),
            c,
            d,
            &mut out,
        ),
        4 => kdf::pbkdf1(digest, a, b, u64::from(opts[0] % 4), &mut out),
        5 => kdf::pbkdf2(digest, a, b, u64::from(opts[0] % 4), &mut out),
        6 => kdf::pkcs12(digest, a, b, opts[1], u64::from(opts[0] % 4), &mut out),
        7 => kdf::sskdf_hash(digest, a, b, &mut out),
        8 => kdf::x963(digest, a, b, &mut out),
        9 => {
            let info = X942Info {
                cek_oid: a,
                kek_length: usize::from(opts[0]),
                acvp: (opts[1] & 1 == 1).then_some(b),
                party_u: (opts[1] & 2 == 2).then_some(c),
                party_v: (opts[1] & 4 == 4).then_some(d),
                supp_pub: (opts[1] & 8 == 8).then_some(a),
                supp_priv: (opts[1] & 16 == 16).then_some(b),
            };
            kdf::x942(digest, c, &info, &mut out)
        }
        10 => {
            let m = mac::hmac(digest, a).ok()?;
            let mode = if opts[0] & 1 == 1 {
                KbkdfMode::Feedback(b)
            } else {
                KbkdfMode::Counter
            };
            let bits = u32::from(opts[1] % 5) * 8;
            kdf::kbkdf(
                &*m,
                mode,
                bits,
                c,
                d,
                opts[2] & 1 == 1,
                opts[2] & 2 == 2,
                &mut out,
            )
        }
        11 => kdf::tls1_prf(digest, a, b, &mut out),
        12 => kdf::sshkdf(digest, a, b, opts[0], c, &mut out),
        13 => {
            let alg = [
                sym::BlockAlgorithm::Aes,
                sym::BlockAlgorithm::TripleDes,
                sym::BlockAlgorithm::Camellia,
            ][usize::from(opts[0] % 3)];
            let key = [16, 24, 16][usize::from(opts[0] % 3)];
            let cipher = sym::block_cipher(alg, &[opts[1]; 32][..key], None).ok()?;
            kdf::krb5kdf(&*cipher, a, opts[2] & 1 == 1, &mut out)
        }
        14 => kdf::scrypt(
            a,
            b,
            1 << (opts[0] % 7),
            u64::from(opts[1] % 4),
            u64::from(opts[2] % 3),
            1 << 20,
            &mut out,
        ),
        15 => {
            let params = Argon2 {
                variant: [Argon2Variant::D, Argon2Variant::I, Argon2Variant::Id]
                    [usize::from(opts[0] % 3)],
                version: if opts[0] & 4 == 4 { 0x10 } else { 0x13 },
                passes: u32::from(opts[1] % 4),
                memory: u32::from(opts[2] % 64),
                lanes: u32::from(opts[3] % 5),
                password: a,
                salt: b,
                secret: c,
                ad: d,
            };
            kdf::argon2(&params, &mut out)
        }
        16 => kdf::pvk(digest, a, b, &mut out),
        _ => {
            let split = usize::from(opts[0]).min(len);
            let (key, iv) = out.split_at_mut(split);
            kdf::bytes_to_key(
                digest,
                (opts[1] & 1 == 1).then_some(a),
                b,
                u32::from(opts[2] % 4),
                key,
                iv,
            )
        }
    };
    ok.ok().map(|()| out)
}

fuzz_target!(|data: &[u8]| {
    let mut r = Reader(data);
    let kind = r.byte();
    let digest = md::Algorithm::ALL[usize::from(r.byte()) % md::Algorithm::ALL.len()];
    let opts = [r.byte(), r.byte(), r.byte(), r.byte()];
    let (short, long) = (usize::from(r.byte()), usize::from(r.byte()) * 2);
    let inputs = r.inputs(4);

    let one = derive(kind, digest, opts, &inputs, long);
    assert_eq!(
        one,
        derive(kind, digest, opts, &inputs, long),
        "deterministic"
    );
    // Block-stream KDFs: a shorter output is a prefix of a longer one. (KBKDF's L and the
    // output-sized MAC lengths bind the length in; the others don't.)
    let streams = matches!(kind % 18, 0 | 1 | 5 | 6 | 7 | 8 | 9 | 11 | 12)
        || (kind % 18 == 10 && opts[2] & 2 == 0);
    if streams && short <= long && short > 0 {
        if let (Some(long), Some(short)) = (one, derive(kind, digest, opts, &inputs, short)) {
            assert_eq!(&long[..short.len()], &short[..], "prefix");
        }
    }
});
