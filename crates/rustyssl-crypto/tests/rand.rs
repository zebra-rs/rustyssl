//! DRBG mechanisms against vectors from the reference OpenSSL's EVP_RAND API
//! (`tests/data/drbg_vectors.txt`), with a TEST-RAND parent supplying fixed entropy and nonce:
//! CTR-DRBG over AES-128/192/256 with and without the derivation function, Hash-DRBG and
//! HMAC-DRBG over several digests, each through a schedule of generates (with and without
//! additional input, an empty request, prediction resistance) and reseeds (from the parent, and
//! with the caller's entropy); and HMAC-DRBG-KDF. The test drives the mechanisms as the RAND
//! layer (3.7) will: the default personalization string, prediction resistance as a reseed
//! with the request's additional input, a caller's entropy as one reseed then another from the
//! parent.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rustyssl_crypto::md::Algorithm;
    use rustyssl_crypto::rand::{self, CtrDrbg, Drbg, Error, HashDrbg, HmacDrbg};

    /// `DRBG_DEFAULT_PERS_STRING`, with the NUL the reference counts.
    const DEFAULT_PERS: &[u8] = b"OpenSSL NIST SP 800-90A DRBG\0";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn digest(name: &str) -> Algorithm {
        match name {
            "SHA1" => Algorithm::Sha1,
            "SHA256" => Algorithm::Sha256,
            "SHA384" => Algorithm::Sha384,
            "SHA512" => Algorithm::Sha512,
            "SHA512-256" => Algorithm::Sha512_256,
            "SHA3-256" => Algorithm::Sha3_256,
            "SHA3-512" => Algorithm::Sha3_512,
            "SM3" => Algorithm::Sm3,
            other => panic!("unknown digest {other}"),
        }
    }

    fn generate(d: &mut dyn Drbg, len: usize, adin: &[u8]) -> String {
        let mut out = vec![0u8; len];
        d.generate(&mut out, adin).unwrap();
        hex(&out)
    }

    #[test]
    fn vectors_from_the_reference() {
        let mut checked = 0;
        for line in include_str!("data/drbg_vectors.txt")
            .lines()
            .filter(|l| !l.starts_with('#'))
        {
            let (lhs, want) = line.split_once(" -> ").unwrap();
            let mut words = lhs.split(' ');
            let name = words.next().unwrap();
            let p: HashMap<&str, &str> = words.map(|w| w.split_once('=').unwrap()).collect();
            let bytes = |k: &str| p.get(k).and_then(|v| v.strip_prefix('x')).map(unhex);
            let want: Vec<&str> = want.split(':').collect();
            if name == "HMAC-DRBG-KDF" {
                let mut d = HmacDrbg::new(digest(p["digest"])).unwrap();
                d.instantiate(&bytes("entropy").unwrap(), &bytes("nonce").unwrap(), &[]);
                assert_eq!(generate(&mut d, 50, &[]), want[0], "{name}");
                assert_eq!(generate(&mut d, 70000, &[]), want[1], "{name}");
                checked += 1;
                continue;
            }
            let mut d: Box<dyn Drbg> = match name {
                "CTR-DRBG" => {
                    let key = match p["cipher"] {
                        "AES-128-CTR" => 16,
                        "AES-192-CTR" => 24,
                        _ => 32,
                    };
                    Box::new(CtrDrbg::new(key, p["df"] == "1").unwrap())
                }
                "HASH-DRBG" => Box::new(HashDrbg::new(digest(p["digest"])).unwrap()),
                _ => Box::new(HmacDrbg::new(digest(p["digest"])).unwrap()),
            };
            let entropy = bytes("entropy").unwrap();
            let nonce = bytes("nonce").unwrap_or_default();
            let pers = bytes("pers").unwrap_or_else(|| DEFAULT_PERS.to_vec());
            let adin = |k| bytes(k).unwrap_or_default();
            d.instantiate(&entropy, &nonce, &pers);
            let mut got = vec![generate(&mut *d, 37, &adin("adin1"))];
            // The EVP layer doesn't call the mechanism for an empty request.
            let len2: usize = p["len2"].parse().unwrap();
            got.push(if len2 == 0 {
                String::new()
            } else {
                generate(&mut *d, len2, &[])
            });
            d.reseed(&entropy, &adin("radin")).unwrap();
            got.push(generate(&mut *d, 100, &adin("adin3")));
            // Prediction resistance: a reseed with the request's input, then no input.
            d.reseed(&entropy, &adin("adin4")).unwrap();
            got.push(generate(&mut *d, 17, &[]));
            // The caller's entropy: a reseed with it, then one from the parent.
            d.reseed(&bytes("entropy2").unwrap(), &adin("radin2"))
                .unwrap();
            d.reseed(&entropy, &[]).unwrap();
            got.push(generate(&mut *d, 1000, &[]));
            assert_eq!(got, want, "{lhs}");
            checked += 1;
        }
        assert_eq!(checked, 34);
    }

    #[test]
    fn life_cycle_and_limits() {
        let mut d = HmacDrbg::new(Algorithm::Sha256).unwrap();
        let mut out = [0u8; 16];
        assert_eq!(d.generate(&mut out, &[]), Err(Error::NotInstantiated));
        assert_eq!(d.reseed(&[1; 32], &[]), Err(Error::NotInstantiated));
        d.instantiate(&[1; 32], &[2; 16], &[]);
        d.generate(&mut out, &[]).unwrap();
        d.uninstantiate();
        assert_eq!(d.generate(&mut out, &[]), Err(Error::NotInstantiated));

        let l = HashDrbg::new(Algorithm::Sha512).unwrap().limits();
        assert_eq!(
            (l.strength, l.seed_length, l.min_entropy, l.min_nonce),
            (256, 111, 32, 16)
        );
        let l = HashDrbg::new(Algorithm::Sha1).unwrap().limits();
        assert_eq!(
            (l.strength, l.seed_length, l.min_entropy, l.min_nonce),
            (128, 55, 16, 8)
        );
        let l = CtrDrbg::new(24, false).unwrap().limits();
        assert_eq!(
            (
                l.min_entropy,
                l.max_entropy,
                l.max_nonce,
                l.max_additional_input
            ),
            (40, 40, 0, 40)
        );
        assert_eq!(CtrDrbg::new(32, true).unwrap().limits().min_nonce, 16);
        assert!(CtrDrbg::new(20, true).is_err());
        assert!(HashDrbg::new(Algorithm::Shake128).is_err());
        assert!(HmacDrbg::new(Algorithm::Null).is_err());
    }

    #[test]
    fn os_entropy() {
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        rand::os_entropy(&mut a).unwrap();
        rand::os_entropy(&mut b).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0; 64]);
    }
}
