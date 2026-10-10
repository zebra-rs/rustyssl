//! MACs against vectors from the reference OpenSSL (`tests/data/mac_vectors.txt`): HMAC with
//! every digest and key lengths around the block size, CMAC over 64- and 128-bit ciphers, GMAC
//! with IVs of 12 and other lengths, KMAC128/256 with and without customization and as XOFs,
//! SipHash with both sizes and other rounds, and the BLAKE2 MACs with salts and customization;
//! each fed whole and in pieces, copied midway, and reset. Refusals match the reference's.

#[cfg(test)]
mod tests {
    use rustyssl_crypto::mac::{self, Blake2Algorithm, Error, KmacAlgorithm, Mac};
    use rustyssl_crypto::md::Algorithm;
    use rustyssl_crypto::sym::{self, BlockAlgorithm};

    fn algorithm(name: &str) -> Algorithm {
        match name {
            "SHA1" => Algorithm::Sha1,
            "SHA224" => Algorithm::Sha224,
            "SHA256" => Algorithm::Sha256,
            "SHA384" => Algorithm::Sha384,
            "SHA512" => Algorithm::Sha512,
            "SHA512-224" => Algorithm::Sha512_224,
            "SHA512-256" => Algorithm::Sha512_256,
            "SHA3-224" => Algorithm::Sha3_224,
            "SHA3-256" => Algorithm::Sha3_256,
            "SHA3-384" => Algorithm::Sha3_384,
            "SHA3-512" => Algorithm::Sha3_512,
            "SHAKE128" => Algorithm::Shake128,
            "SHAKE256" => Algorithm::Shake256,
            "KECCAK-KMAC-128" => Algorithm::KeccakKmac128,
            "KECCAK-KMAC-256" => Algorithm::KeccakKmac256,
            "MD5" => Algorithm::Md5,
            "MD5-SHA1" => Algorithm::Md5Sha1,
            "SM3" => Algorithm::Sm3,
            "BLAKE2S-256" => Algorithm::Blake2s256,
            "BLAKE2B-512" => Algorithm::Blake2b512,
            "RIPEMD160" => Algorithm::Ripemd160,
            "MD4" => Algorithm::Md4,
            "WHIRLPOOL" => Algorithm::Whirlpool,
            "NULL" => Algorithm::Null,
            other => panic!("unknown algorithm {other}"),
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn pattern(n: usize, mul: usize, add: usize) -> Vec<u8> {
        (0..n)
            .map(|i| u8::try_from((i * mul + add) % 256).unwrap())
            .collect()
    }

    /// A keyed block cipher for a cipher name such as `AES-128-CBC`.
    fn cipher(name: &str, key: &[u8]) -> Box<dyn sym::BlockCipher> {
        let alg = match name.split('-').next().unwrap() {
            "AES" => BlockAlgorithm::Aes,
            "ARIA" => BlockAlgorithm::Aria,
            "CAMELLIA" => BlockAlgorithm::Camellia,
            "SM4" => BlockAlgorithm::Sm4,
            "DES" => BlockAlgorithm::TripleDes,
            "BF" => BlockAlgorithm::Blowfish,
            other => panic!("unknown cipher {other}"),
        };
        sym::block_cipher(alg, key, None).unwrap()
    }

    /// Feeds `msg` in pieces of `piece` octets (all at once for 0) and finalizes.
    fn run(m: &mut dyn Mac, msg: &[u8], piece: usize) -> Vec<u8> {
        if piece == 0 {
            m.update(msg).unwrap();
        } else {
            msg.chunks(piece).for_each(|c| m.update(c).unwrap());
        }
        let mut out = vec![0; m.size()];
        m.finalize(&mut out).unwrap();
        out
    }

    #[test]
    fn vectors_from_the_reference() {
        let key = pattern(300, 13, 5);
        let data = pattern(300, 7, 3);
        let (mut checked, mut refused) = (0, 0);
        for line in include_str!("data/mac_vectors.txt")
            .lines()
            .filter(|l| !l.starts_with('#'))
        {
            let f: Vec<&str> = line.split(' ').collect();
            let n = |i: usize| f[i].parse::<usize>().unwrap();
            let (name, sub, want) = (f[0], f[1], f[9]);
            let (klen, mlen, size, clen, ivlen, r1, r2) =
                (n(2), n(3), n(4), n(5), n(6), n(7), n(8));
            let (k, msg) = (&key[..klen], &data[..mlen]);
            let custom = data.get(100..100 + clen).unwrap_or(&[]);
            let iv = &data[50..50 + ivlen];
            let made: Result<Box<dyn Mac>, Error> = match name {
                "HMAC" => mac::hmac(algorithm(sub), k),
                // The reference refuses CMAC over a cipher that isn't in CBC mode, which is
                // the EVP layer's check (3.5); the backend takes the block cipher itself.
                "CMAC" if sub.ends_with("-ECB") => continue,
                "CMAC" => mac::cmac(cipher(sub, k)),
                "GMAC" => mac::gmac(cipher(sub, k), iv),
                "KMAC128" | "KMAC256" => {
                    let alg = if name == "KMAC128" {
                        KmacAlgorithm::Kmac128
                    } else {
                        KmacAlgorithm::Kmac256
                    };
                    let size = if size == 0 { alg.default_size() } else { size };
                    let custom = if clen > 300 {
                        vec![0; clen]
                    } else {
                        custom.to_vec()
                    };
                    mac::kmac(alg, k, &custom, size, r1 == 1)
                }
                "SIPHASH" => {
                    let (c, d) = if r1 == 0 {
                        (2, 4)
                    } else {
                        (u32::try_from(r1).unwrap(), u32::try_from(r2).unwrap())
                    };
                    mac::siphash(k, if size == 0 { 16 } else { size }, c, d)
                }
                "BLAKE2BMAC" | "BLAKE2SMAC" => {
                    let alg = if name == "BLAKE2BMAC" {
                        Blake2Algorithm::Blake2b
                    } else {
                        Blake2Algorithm::Blake2s
                    };
                    let size = if size == 0 { alg.max_size() } else { size };
                    mac::blake2(alg, k, size, custom, iv)
                }
                other => panic!("unknown MAC {other}"),
            };
            if want.starts_with("refused:") {
                assert!(made.is_err(), "{line}: the reference refuses it");
                refused += 1;
                continue;
            }
            let mut m = made.unwrap_or_else(|e| panic!("{line}: {e:?}"));
            assert_eq!(hex(&run(&mut *m, msg, 0)), want, "{line}");
            // Again after a reset, in pieces of each size.
            for piece in [1, 7, 16, 65] {
                m.reset();
                assert_eq!(
                    hex(&run(&mut *m, msg, piece)),
                    want,
                    "{line} in pieces of {piece}"
                );
            }
            // A copy made midway finishes the same.
            m.reset();
            m.update(&msg[..mlen / 2]).unwrap();
            let mut copy = m.clone_box();
            assert_eq!(
                hex(&run(&mut *copy, &msg[mlen / 2..], 3)),
                want,
                "{line} copied"
            );
            assert_eq!(
                hex(&run(&mut *m, &msg[mlen / 2..], 0)),
                want,
                "{line} original"
            );
            checked += 1;
        }
        assert_eq!((checked, refused), (327, 19));
    }

    #[test]
    fn life_cycle() {
        let mut m = mac::hmac(Algorithm::Sha256, b"key").unwrap();
        let mut out = [0u8; 32];
        assert_eq!(m.finalize(&mut [0u8; 31]), Err(Error::OutputSize));
        m.finalize(&mut out).unwrap();
        assert_eq!(m.update(b"x"), Err(Error::Finalized));
        assert_eq!(m.finalize(&mut out), Err(Error::Finalized));
        m.reset();
        m.update(b"The quick brown fox jumps over the lazy dog")
            .unwrap();
        m.finalize(&mut out).unwrap();
        // The HMAC-SHA256 example in Wikipedia's HMAC article.
        assert_eq!(
            hex(&out),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn poly1305_rfc_8439() {
        let key = (0..32)
            .map(|i| {
                u8::from_str_radix(
                    &"85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
                        [2 * i..2 * i + 2],
                    16,
                )
                .unwrap()
            })
            .collect::<Vec<u8>>();
        let mut m = mac::poly1305(&key).unwrap();
        for piece in [0, 1, 5, 16] {
            m.reset();
            let tag = run(&mut *m, b"Cryptographic Forum Research Group", piece);
            assert_eq!(
                hex(&tag),
                "a8061dc1305136c6c22b8baf0c0127a9",
                "pieces of {piece}"
            );
        }
    }

    #[test]
    fn refusals() {
        let aes = || cipher("AES-128-CBC", &[0; 16]);
        let des = || cipher("DES-EDE3-CBC", &[1; 24]);
        assert!(mac::gmac(des(), &[0; 12]).is_err());
        assert!(mac::gmac(aes(), &[]).is_err());
        assert!(mac::cmac(des()).is_ok());
        assert!(mac::poly1305(&[0; 31]).is_err());
        assert!(mac::siphash(&[0; 16], 12, 2, 4).is_err());
        assert!(mac::kmac(KmacAlgorithm::Kmac128, &[0; 513], b"", 32, false).is_err());
        assert!(mac::kmac(KmacAlgorithm::Kmac128, &[0; 4], b"", 0x20_0000, false).is_err());
        assert!(mac::blake2(Blake2Algorithm::Blake2s, &[1], 0, b"", b"").is_err());
    }
}
