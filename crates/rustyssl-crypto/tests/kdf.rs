//! KDFs against vectors from the reference OpenSSL's EVP_KDF API (`tests/data/kdf_vectors.txt`):
//! every KDF of the default and legacy providers and `EVP_BytesToKey`, at their limits, with
//! the reference's refusals. The test maps EVP_KDF's parameters (names, defaults) onto the
//! backend's arguments the way the EVP layer (3.6) will; RFC vectors check a few more.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rustyssl_crypto::kdf::{self, Argon2, Argon2Variant, Error, KbkdfMode, X942Info};
    use rustyssl_crypto::mac::{self, KmacAlgorithm};
    use rustyssl_crypto::md::Algorithm;
    use rustyssl_crypto::sym::{self, BlockAlgorithm};

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
            "SHA3-224" => Algorithm::Sha3_224,
            "SHA3-256" => Algorithm::Sha3_256,
            "SHA3-512" => Algorithm::Sha3_512,
            "SHAKE128" => Algorithm::Shake128,
            "SHAKE256" => Algorithm::Shake256,
            "NULL" => Algorithm::Null,
            "MD5" => Algorithm::Md5,
            "MD5-SHA1" => Algorithm::Md5Sha1,
            "SM3" => Algorithm::Sm3,
            other => panic!("unknown digest {other}"),
        }
    }

    /// A keyed block cipher for a CBC cipher name, as CMAC and KRB5KDF take it.
    fn cipher(name: &str, key: &[u8]) -> Box<dyn sym::BlockCipher> {
        let alg = match name {
            "AES-128-CBC" | "AES-256-CBC" => BlockAlgorithm::Aes,
            "CAMELLIA-128-CBC" => BlockAlgorithm::Camellia,
            "DES-EDE3-CBC" => BlockAlgorithm::TripleDes,
            other => panic!("unknown cipher {other}"),
        };
        sym::block_cipher(alg, key, None).unwrap()
    }

    /// The DER OBJECT IDENTIFIER of an X942KDF key-wrapping algorithm.
    fn cek_oid(name: &str) -> Vec<u8> {
        let sn = match name {
            "AES-128-WRAP" => "id-aes128-wrap",
            "AES-192-WRAP" => "id-aes192-wrap",
            "AES-256-WRAP" => "id-aes256-wrap",
            "DES3-WRAP" => "id-smime-alg-CMS3DESwrap",
            other => panic!("unknown key-wrapping algorithm {other}"),
        };
        let nid = rustyssl_asn1::objects::by_short_name(sn.as_bytes()).unwrap();
        let der = rustyssl_asn1::objects::object(nid).unwrap().der;
        let mut out = vec![0x06, u8::try_from(der.len()).unwrap()];
        out.extend_from_slice(der);
        out
    }

    fn kek_length(name: &str) -> usize {
        match name {
            "AES-128-WRAP" => 16,
            "AES-192-WRAP" | "DES3-WRAP" => 24,
            _ => 32,
        }
    }

    struct Params<'a>(HashMap<&'a str, &'a str>);

    impl Params<'_> {
        fn bytes(&self, k: &str) -> Option<Vec<u8>> {
            self.0.get(k).map(|v| unhex(v.strip_prefix('x').unwrap()))
        }
        fn or_empty(&self, k: &str) -> Vec<u8> {
            self.bytes(k).unwrap_or_default()
        }
        fn str(&self, k: &str) -> Option<&str> {
            self.0.get(k).copied()
        }
        fn num(&self, k: &str, default: u64) -> u64 {
            self.0.get(k).map_or(default, |v| v.parse().unwrap())
        }
        fn md(&self) -> Algorithm {
            digest(self.str("digest").unwrap())
        }
    }

    /// Derives one vector's output (`out` starts as the reference's 0xaa fill).
    fn derive(name: &str, p: &Params<'_>, out: &mut [u8]) -> Result<(), Error> {
        let n = |k, d| p.num(k, d);
        match name {
            "HKDF" => match p.str("mode") {
                Some("EXTRACT_ONLY") => {
                    kdf::hkdf_extract(p.md(), &p.or_empty("salt"), &p.or_empty("key"), out)
                }
                Some("EXPAND_ONLY") => {
                    kdf::hkdf_expand(p.md(), &p.or_empty("key"), &p.or_empty("info"), out)
                }
                _ => kdf::hkdf(
                    p.md(),
                    &p.or_empty("salt"),
                    &p.or_empty("key"),
                    &p.or_empty("info"),
                    out,
                ),
            },
            "TLS13-KDF" if p.str("mode") == Some("EXPAND_ONLY") => kdf::tls13_expand(
                p.md(),
                &p.or_empty("key"),
                &p.or_empty("prefix"),
                &p.or_empty("label"),
                &p.or_empty("data"),
                out,
            ),
            "TLS13-KDF" => kdf::tls13_extract(
                p.md(),
                p.bytes("salt").as_deref(),
                p.bytes("key").as_deref(),
                &p.or_empty("prefix"),
                &p.or_empty("label"),
                out,
            ),
            "PBKDF1" => kdf::pbkdf1(
                p.md(),
                &p.or_empty("pass"),
                &p.or_empty("salt"),
                n("iter", 1),
                out,
            ),
            "PBKDF2" => kdf::pbkdf2(
                p.md(),
                &p.or_empty("pass"),
                &p.or_empty("salt"),
                n("iter", 1),
                out,
            ),
            "PKCS12KDF" => kdf::pkcs12(
                p.md(),
                &p.or_empty("pass"),
                &p.or_empty("salt"),
                u8::try_from(n("id", 0)).unwrap(),
                n("iter", 1),
                out,
            ),
            "PVKKDF" => kdf::pvk(p.md(), &p.or_empty("salt"), &p.or_empty("pass"), out),
            "SSKDF" => {
                let (z, info) = (p.or_empty("key"), p.or_empty("info"));
                match p.str("mac") {
                    None => kdf::sskdf_hash(p.md(), &z, &info, out),
                    Some("HMAC") => {
                        let salt = p
                            .bytes("salt")
                            .unwrap_or_else(|| vec![0; p.md().output_size()]);
                        let m = mac::hmac(p.md(), &salt)?;
                        kdf::sskdf_mac(&*m, &z, &info, out)
                    }
                    Some(kmac) => {
                        let (alg, default_salt) = if kmac == "KMAC128" {
                            (KmacAlgorithm::Kmac128, 168 - 4)
                        } else {
                            (KmacAlgorithm::Kmac256, 136 - 4)
                        };
                        let salt = p.bytes("salt").unwrap_or_else(|| vec![0; default_salt]);
                        let size = usize::try_from(n("maclen", 0)).unwrap();
                        let size = if size == 0 { out.len() } else { size };
                        let m = mac::kmac(alg, &salt, b"KDF", size, false)?;
                        kdf::sskdf_mac(&*m, &z, &info, out)
                    }
                }
            }
            "X963KDF" => kdf::x963(p.md(), &p.or_empty("key"), &p.or_empty("info"), out),
            "X942KDF-ASN1" => {
                let cek = p.str("cekalg").unwrap();
                let oid = cek_oid(cek);
                let (u, v) = (p.bytes("partyu-info"), p.bytes("partyv-info"));
                let (pub_, priv_, acvp) = (
                    p.bytes("supp-pubinfo"),
                    p.bytes("supp-privinfo"),
                    p.bytes("acvp-info"),
                );
                // Setting suppPubInfo turns the key length off.
                let keybits = n("use-keybits", 1) != 0 && pub_.is_none();
                let info = X942Info {
                    cek_oid: &oid,
                    kek_length: if keybits { kek_length(cek) } else { 0 },
                    acvp: acvp.as_deref(),
                    party_u: u.as_deref(),
                    party_v: v.as_deref(),
                    supp_pub: pub_.as_deref(),
                    supp_priv: priv_.as_deref(),
                };
                kdf::x942(p.md(), &p.or_empty("key"), &info, out)
            }
            "KBKDF" => {
                let key = p.or_empty("key");
                let m = if p.str("mac") == Some("HMAC") {
                    mac::hmac(p.md(), &key)?
                } else {
                    mac::cmac(cipher(p.str("cipher").unwrap(), &key))?
                };
                let seed = p.or_empty("seed");
                let mode = if p.str("mode") == Some("feedback") {
                    KbkdfMode::Feedback(&seed)
                } else {
                    KbkdfMode::Counter
                };
                kdf::kbkdf(
                    &*m,
                    mode,
                    u32::try_from(n("r", 32)).unwrap(),
                    &p.or_empty("salt"),
                    &p.or_empty("info"),
                    n("use-separator", 1) != 0,
                    n("use-l", 1) != 0,
                    out,
                )
            }
            "TLS1-PRF" => kdf::tls1_prf(p.md(), &p.or_empty("secret"), &p.or_empty("seed"), out),
            "SSHKDF" => kdf::sshkdf(
                p.md(),
                &p.or_empty("key"),
                &p.or_empty("xcghash"),
                p.str("type").unwrap().as_bytes()[0],
                &p.or_empty("session_id"),
                out,
            ),
            "KRB5KDF" => {
                let name = p.str("cipher").unwrap();
                let c = cipher(name, &p.or_empty("key"));
                let des3 = name == "DES-EDE3-CBC" && out.len() == 24;
                kdf::krb5kdf(&*c, &p.or_empty("constant"), des3, out)
            }
            "SCRYPT" => kdf::scrypt(
                &p.or_empty("pass"),
                &p.or_empty("salt"),
                n("n", 1 << 20),
                n("r", 8),
                n("p", 1),
                n("maxmem_bytes", 1025 * 1024 * 1024),
                out,
            ),
            "ARGON2D" | "ARGON2I" | "ARGON2ID" => {
                let variant = match name {
                    "ARGON2D" => Argon2Variant::D,
                    "ARGON2I" => Argon2Variant::I,
                    _ => Argon2Variant::Id,
                };
                let u = |k, d| u32::try_from(n(k, d)).unwrap();
                let (pass, salt, secret, ad) = (
                    p.or_empty("pass"),
                    p.or_empty("salt"),
                    p.or_empty("secret"),
                    p.or_empty("ad"),
                );
                kdf::argon2(
                    &Argon2 {
                        variant,
                        version: u("version", 0x13),
                        passes: u("iter", 3),
                        memory: u("memcost", 8),
                        lanes: u("lanes", 1),
                        password: &pass,
                        salt: &salt,
                        secret: &secret,
                        ad: &ad,
                    },
                    out,
                )
            }
            "BYTESTOKEY" => {
                let (key, iv) = out.split_at_mut(32);
                kdf::bytes_to_key(
                    p.md(),
                    p.bytes("salt").as_deref(),
                    &p.or_empty("data"),
                    u32::try_from(n("count", 1)).unwrap(),
                    key,
                    iv,
                )
            }
            other => panic!("unknown KDF {other}"),
        }
    }

    #[test]
    fn vectors_from_the_reference() {
        let (mut derived, mut refused) = (0, 0);
        for line in include_str!("data/kdf_vectors.txt")
            .lines()
            .filter(|l| !l.starts_with('#'))
        {
            let (lhs, want) = line.split_once(" -> ").unwrap();
            let mut words = lhs.split(' ');
            let name = words.next().unwrap();
            let params = Params(words.map(|w| w.split_once('=').unwrap()).collect());
            let len = usize::try_from(params.num("out", 0)).unwrap();
            let mut out = vec![0xaa; len];
            let got = derive(name, &params, &mut out);
            if want.starts_with("refused:") {
                assert!(got.is_err(), "{line}: the reference refuses it");
                refused += 1;
            } else {
                assert_eq!(got, Ok(()), "{line}");
                assert_eq!(hex(&out), want, "{line}");
                derived += 1;
            }
        }
        assert_eq!((derived, refused), (171, 44));
    }

    #[test]
    fn rfc_vectors() {
        // RFC 5869 test case 1.
        let mut okm = [0u8; 42];
        kdf::hkdf(
            Algorithm::Sha256,
            &unhex("000102030405060708090a0b0c"),
            &[0x0b; 22],
            &unhex("f0f1f2f3f4f5f6f7f8f9"),
            &mut okm,
        )
        .unwrap();
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
        // RFC 7914 section 12, the second vector.
        let mut out = [0u8; 64];
        kdf::scrypt(b"password", b"NaCl", 1024, 8, 16, 1 << 30, &mut out).unwrap();
        assert_eq!(
            hex(&out),
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"
        );
        // RFC 9106 section 5.3 (Argon2id).
        let mut tag = [0u8; 32];
        kdf::argon2(
            &Argon2 {
                variant: Argon2Variant::Id,
                version: 0x13,
                passes: 3,
                memory: 32,
                lanes: 4,
                password: &[1; 32],
                salt: &[2; 16],
                secret: &[3; 8],
                ad: &[4; 12],
            },
            &mut tag,
        )
        .unwrap();
        assert_eq!(
            hex(&tag),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
        // RFC 6070 (PBKDF2-HMAC-SHA1), 4096 iterations.
        let mut dk = [0u8; 20];
        kdf::pbkdf2(Algorithm::Sha1, b"password", b"salt", 4096, &mut dk).unwrap();
        assert_eq!(hex(&dk), "4b007901b765489abead49d926f721d065a429c1");
    }

    #[test]
    fn refusals() {
        let mut out = [0u8; 16];
        assert_eq!(
            kdf::sshkdf(Algorithm::Null, b"k", b"h", b'A', b"s", &mut out),
            Err(Error::Digest)
        );
        assert_eq!(
            kdf::pbkdf2(Algorithm::Shake256, b"p", b"s", 1, &mut out),
            Err(Error::Digest)
        );
        assert_eq!(
            kdf::sskdf_hash(Algorithm::Sha256, b"z", b"", &mut []),
            Err(Error::OutputLength)
        );
        assert_eq!(
            kdf::scrypt(b"", b"", 3, 1, 1, 1 << 30, &mut out),
            Err(Error::Parameter)
        );
        assert_eq!(
            kdf::scrypt(b"", b"", 4, 1 << 20, 1 << 10, u64::MAX, &mut out),
            Err(Error::MemoryLimit)
        );
        let m = mac::hmac(Algorithm::Sha256, b"k").unwrap();
        assert_eq!(
            kdf::kbkdf(&*m, KbkdfMode::Counter, 12, b"", b"", true, true, &mut out),
            Err(Error::Parameter)
        );
        let c = sym::block_cipher(BlockAlgorithm::Aes, &[0; 16], None).unwrap();
        assert_eq!(
            kdf::krb5kdf(&*c, b"", false, &mut out),
            Err(Error::Parameter)
        );
        let argon = Argon2 {
            variant: Argon2Variant::I,
            version: 0x12,
            passes: 1,
            memory: 8,
            lanes: 1,
            password: b"",
            salt: &[0; 8],
            secret: b"",
            ad: b"",
        };
        assert_eq!(kdf::argon2(&argon, &mut out), Err(Error::Parameter));
    }
}
