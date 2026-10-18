//! The test provider's keys: the groups' key shares (X25519, X448, the NIST curves, FFDHE,
//! ML-KEM and the hybrids), signing and verifying (RSA PKCS #1 and PSS, ECDSA, Ed25519, Ed448),
//! RSA's premaster secret, and minimal certificates carrying a public key.

use rustyssl_abi::{
    NID_X9_62_prime256v1, NID_md5_sha1, NID_secp384r1, NID_secp521r1, NID_sha1, NID_sha224,
    NID_sha256, NID_sha384, NID_sha512,
};
use rustyssl_crypto::bn::{self, BigNum, Endian};
use rustyssl_crypto::ec::curves;
use rustyssl_crypto::ec::group::Group;
use rustyssl_crypto::ec::{ecdsa, mult, oct, point};
use rustyssl_crypto::{ecx, ecx448, ffc, mlkem, rsa};

use super::{TestProvider, digest, fail};
use crate::crypto::{GroupInfo, HashAlg, Secret};
use crate::error::Result;

// The IANA code points of the groups (RFC 8446, RFC 7919, and the ML-KEM drafts).
pub const SECP256R1: u16 = 23;
pub const SECP384R1: u16 = 24;
pub const SECP521R1: u16 = 25;
pub const X25519: u16 = 29;
pub const X448: u16 = 30;
pub const FFDHE2048: u16 = 256;
pub const FFDHE3072: u16 = 257;
pub const FFDHE4096: u16 = 258;
pub const FFDHE6144: u16 = 259;
pub const FFDHE8192: u16 = 260;
pub const MLKEM512: u16 = 0x0200;
pub const MLKEM768: u16 = 0x0201;
pub const MLKEM1024: u16 = 0x0202;
pub const SECP256R1MLKEM768: u16 = 0x11eb;
pub const X25519MLKEM768: u16 = 0x11ec;
pub const SECP384R1MLKEM1024: u16 = 0x11ed;

// The signature schemes (RFC 8446 section 4.2.3, and the legacy ones OpenSSL numbers).
pub const RSA_PKCS1_SHA1: u16 = 0x0201;
pub const ECDSA_SHA1: u16 = 0x0203;
pub const RSA_PKCS1_SHA224: u16 = 0x0301;
pub const ECDSA_SHA224: u16 = 0x0303;
pub const RSA_PKCS1_SHA256: u16 = 0x0401;
pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
pub const RSA_PKCS1_SHA384: u16 = 0x0501;
pub const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
pub const RSA_PKCS1_SHA512: u16 = 0x0601;
pub const ECDSA_SECP521R1_SHA512: u16 = 0x0603;
pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
pub const RSA_PSS_RSAE_SHA512: u16 = 0x0806;
pub const ED25519: u16 = 0x0807;
pub const ED448: u16 = 0x0808;
pub const RSA_PSS_PSS_SHA256: u16 = 0x0809;
pub const RSA_PSS_PSS_SHA384: u16 = 0x080a;
pub const RSA_PSS_PSS_SHA512: u16 = 0x080b;
/// TLS 1.0 and 1.1's RSA signature over MD5 and SHA-1 (no IANA code point; OpenSSL's
/// `TLSEXT_SIGALG_rsa_pkcs1_md5_sha1`).
pub const RSA_PKCS1_MD5_SHA1: u16 = 0xff01;

/// The groups the test provider offers.
pub fn groups() -> Vec<GroupInfo> {
    let g = |name: &str, id, bits, min_tls, is_kem| GroupInfo {
        name: name.to_owned(),
        internal_name: name.to_owned(),
        aliases: Vec::new(),
        id,
        security_bits: bits,
        min_tls,
        max_tls: 0,
        min_dtls: 0,
        max_dtls: 0,
        is_kem,
        algorithm: match id {
            X25519 => "X25519",
            X448 => "X448",
            SECP256R1 | SECP384R1 | SECP521R1 => "EC",
            FFDHE2048 | FFDHE3072 | FFDHE4096 | FFDHE6144 | FFDHE8192 => "DH",
            _ => name,
        }
        .to_owned(),
    };
    let t13 = 0x0304;
    vec![
        g("X25519MLKEM768", X25519MLKEM768, 192, t13, true),
        g("x25519", X25519, 128, 0, false),
        g("secp256r1", SECP256R1, 128, 0, false),
        g("x448", X448, 224, 0, false),
        g("secp384r1", SECP384R1, 192, 0, false),
        g("secp521r1", SECP521R1, 256, 0, false),
        g("ffdhe2048", FFDHE2048, 112, 0, false),
        g("ffdhe3072", FFDHE3072, 128, 0, false),
        g("ffdhe4096", FFDHE4096, 128, 0, false),
        g("ffdhe6144", FFDHE6144, 128, 0, false),
        g("ffdhe8192", FFDHE8192, 192, 0, false),
        g("MLKEM512", MLKEM512, 128, t13, true),
        g("MLKEM768", MLKEM768, 192, t13, true),
        g("MLKEM1024", MLKEM1024, 256, t13, true),
        g("SecP256r1MLKEM768", SECP256R1MLKEM768, 192, t13, true),
        g("SecP384r1MLKEM1024", SECP384R1MLKEM1024, 256, t13, true),
    ]
}

/// The private half of a key share.
pub enum SharePrivate {
    X25519([u8; 32]),
    X448([u8; 56]),
    Ec(i32, BigNum),
    Dh(BigNum, BigNum),
    MlKem(Box<mlkem::PrivateKey>),
    /// An ECDH share and an ML-KEM key; `kem_first` gives the order of the shares and
    /// secrets (X25519MLKEM768 puts ML-KEM first, the NIST-curve hybrids last).
    Hybrid(Box<SharePrivate>, Box<mlkem::PrivateKey>, bool),
}

/// The random source the crypto crate takes, drawing from the provider.
fn rng(p: &TestProvider) -> impl FnMut(&mut [u8]) -> bool + '_ {
    move |b: &mut [u8]| {
        p.draw(b);
        true
    }
}

/// The NID of a NIST curve group.
fn curve_nid(id: u16) -> Option<i32> {
    match id {
        SECP256R1 => Some(NID_X9_62_prime256v1),
        SECP384R1 => Some(NID_secp384r1),
        SECP521R1 => Some(NID_secp521r1),
        _ => None,
    }
}

/// The curve group of `nid`.
pub fn curve(nid: i32) -> Result<Group> {
    Group::from_curve(curves::by_nid(nid).ok_or_else(fail)?).map_err(|_| fail())
}

/// A scalar in `[1, order)`.
fn scalar(g: &Group, p: &TestProvider) -> Result<BigNum> {
    let mut r = rng(p);
    loop {
        let k = bn::rand::rand_range(&g.order, &mut r).ok_or_else(fail)?;
        if !k.is_zero() {
            return Ok(k);
        }
    }
}

/// `k` times the generator, or times `pt`.
fn ec_mul(
    g: &Group,
    k: &BigNum,
    pt: Option<&point::Point>,
    p: &TestProvider,
) -> Result<point::Point> {
    let mut r = point::Point::infinity();
    let pairs;
    let req = match pt {
        None => mult::Request {
            scalar: Some(k),
            pairs: &[],
            scalar_is_order: false,
        },
        Some(q) => {
            pairs = [(q, k)];
            mult::Request {
                scalar: None,
                pairs: &pairs,
                scalar_is_order: false,
            }
        }
    };
    mult::mul(g, &mut r, &req, &mut rng(p)).map_err(|_| fail())?;
    Ok(r)
}

/// A point's uncompressed encoding.
fn ec_encode(g: &Group, pt: &point::Point, p: &TestProvider) -> Result<Vec<u8>> {
    oct::encode(g, pt, 4, &mut rng(p)).map_err(|_| fail())
}

/// A peer's point, checked on the curve.
fn ec_decode(g: &Group, buf: &[u8], p: &TestProvider) -> Result<point::Point> {
    let mut pt = point::Point::infinity();
    oct::decode(g, &mut pt, buf, &mut rng(p)).map_err(|_| fail())?;
    if pt.is_at_infinity() || !point::is_on_curve(g, &pt).map_err(|_| fail())? {
        return Err(fail());
    }
    Ok(pt)
}

/// The ECDH secret: the x coordinate, padded to the field's length.
fn ecdh(nid: i32, d: &BigNum, peer: &[u8], p: &TestProvider) -> Result<Secret> {
    let g = curve(nid)?;
    let q = ec_decode(&g, peer, p)?;
    let s = ec_mul(&g, d, Some(&q), p)?;
    let (x, _) = point::get_affine(&g, &s, &mut rng(p)).map_err(|_| fail())?;
    let len = oct::field_len(&g);
    Ok(Secret::new(
        x.to_bin(Some(len), Endian::Big, false)
            .ok_or_else(fail)?
            .to_vec(),
    ))
}

/// The FFDHE group of a code point.
fn ffdhe(id: u16) -> Option<&'static ffc::NamedGroup> {
    ffc::by_name(match id {
        FFDHE2048 => "ffdhe2048",
        FFDHE3072 => "ffdhe3072",
        FFDHE4096 => "ffdhe4096",
        FFDHE6144 => "ffdhe6144",
        FFDHE8192 => "ffdhe8192",
        _ => return None,
    })
}

/// A Diffie-Hellman share over `p` and `g`: the private value and the public value padded to
/// the prime's length.
pub fn dh_generate(p: &BigNum, g: &BigNum, prov: &TestProvider) -> Result<(Vec<u8>, SharePrivate)> {
    let mut r = rng(prov);
    let pm1 = bn::sub(p, &BigNum::one()).map_err(|_| fail())?;
    let x = loop {
        let x = bn::rand::rand_range(&pm1, &mut r).ok_or_else(fail)?;
        if bn::cmp(&x, &BigNum::one()).is_gt() {
            break x;
        }
    };
    let y = bn::modular::exp_mod(g, &x, p).map_err(|_| fail())?;
    let len = p.num_bytes();
    let public = y
        .to_bin(Some(len), Endian::Big, false)
        .ok_or_else(fail)?
        .to_vec();
    Ok((public, SharePrivate::Dh(p.clone(), x)))
}

/// The Diffie-Hellman secret, padded to the prime's length (TLS 1.3's form; TLS 1.2 strips
/// the leading zeros).
fn dh_derive(p: &BigNum, x: &BigNum, peer: &[u8]) -> Result<Secret> {
    let y = BigNum::from_bin(peer, Endian::Big, false).map_err(|_| fail())?;
    let pm1 = bn::sub(p, &BigNum::one()).map_err(|_| fail())?;
    if bn::cmp(&y, &BigNum::one()).is_le() || bn::cmp(&y, &pm1).is_ge() {
        return Err(fail());
    }
    let z = bn::modular::exp_mod(&y, x, p).map_err(|_| fail())?;
    Ok(Secret::new(
        z.to_bin(Some(p.num_bytes()), Endian::Big, false)
            .ok_or_else(fail)?
            .to_vec(),
    ))
}

/// The ML-KEM variant of a KEM group.
fn kem_variant(id: u16) -> Option<mlkem::Variant> {
    match id {
        MLKEM512 => Some(mlkem::Variant::MlKem512),
        MLKEM768 | X25519MLKEM768 | SECP256R1MLKEM768 => Some(mlkem::Variant::MlKem768),
        MLKEM1024 | SECP384R1MLKEM1024 => Some(mlkem::Variant::MlKem1024),
        _ => None,
    }
}

/// A new ML-KEM key.
fn kem_generate(v: mlkem::Variant, p: &TestProvider) -> Result<mlkem::PrivateKey> {
    let mut seed = [0u8; mlkem::SEED_BYTES];
    p.draw(&mut seed);
    mlkem::PrivateKey::generate(v, &seed).ok_or_else(fail)
}

/// The classical half of a hybrid group, and whether ML-KEM comes first.
fn hybrid_parts(id: u16) -> Option<(u16, bool)> {
    match id {
        X25519MLKEM768 => Some((X25519, true)),
        SECP256R1MLKEM768 => Some((SECP256R1, false)),
        SECP384R1MLKEM1024 => Some((SECP384R1, false)),
        _ => None,
    }
}

/// A new key share for group `id`: its public value and private half.
pub fn generate(id: u16, p: &TestProvider) -> Result<(Vec<u8>, SharePrivate)> {
    if let Some((classical, kem_first)) = hybrid_parts(id) {
        let (c_pub, c_priv) = generate(classical, p)?;
        let kem = kem_generate(kem_variant(id).ok_or_else(fail)?, p)?;
        let k_pub = kem.public().encode();
        let public = if kem_first {
            [k_pub, c_pub].concat()
        } else {
            [c_pub, k_pub].concat()
        };
        return Ok((
            public,
            SharePrivate::Hybrid(Box::new(c_priv), Box::new(kem), kem_first),
        ));
    }
    match id {
        X25519 => {
            let mut k = [0u8; 32];
            p.draw(&mut k);
            Ok((
                ecx::x25519_public_from_private(&k).to_vec(),
                SharePrivate::X25519(k),
            ))
        }
        X448 => {
            let mut k = [0u8; 56];
            p.draw(&mut k);
            let public = ecx448::x448_public_from_private(&k).ok_or_else(fail)?;
            Ok((public.to_vec(), SharePrivate::X448(k)))
        }
        MLKEM512 | MLKEM768 | MLKEM1024 => {
            let kem = kem_generate(kem_variant(id).ok_or_else(fail)?, p)?;
            Ok((kem.public().encode(), SharePrivate::MlKem(Box::new(kem))))
        }
        _ => {
            if let Some(nid) = curve_nid(id) {
                let g = curve(nid)?;
                let d = scalar(&g, p)?;
                let q = ec_mul(&g, &d, None, p)?;
                return Ok((ec_encode(&g, &q, p)?, SharePrivate::Ec(nid, d)));
            }
            let fg = ffdhe(id).ok_or_else(fail)?;
            dh_generate(&fg.p, &fg.g, p)
        }
    }
}

/// The secret from our private half and the peer's share (for a KEM, the ciphertext).
pub fn derive(id: u16, private: &SharePrivate, peer: &[u8]) -> Result<Secret> {
    let p = TestProvider::new(b"derive");
    derive_with(id, private, peer, &p)
}

fn derive_with(id: u16, private: &SharePrivate, peer: &[u8], p: &TestProvider) -> Result<Secret> {
    match private {
        SharePrivate::X25519(k) => {
            let peer: &[u8; 32] = peer.try_into().map_err(|_| fail())?;
            let s = ecx::x25519(k, peer).ok_or_else(fail)?;
            Ok(Secret::new(s.to_vec()))
        }
        SharePrivate::X448(k) => {
            let peer: &[u8; 56] = peer.try_into().map_err(|_| fail())?;
            let s = ecx448::x448(k, peer).ok_or_else(fail)?;
            Ok(Secret::new(s.to_vec()))
        }
        SharePrivate::Ec(nid, d) => ecdh(*nid, d, peer, p),
        SharePrivate::Dh(prime, x) => dh_derive(prime, x, peer),
        SharePrivate::MlKem(kem) => Ok(Secret::new(
            kem.decapsulate(peer).ok_or_else(fail)?.to_vec(),
        )),
        SharePrivate::Hybrid(classical, kem, kem_first) => {
            let (cid, _) = hybrid_parts(id).ok_or_else(fail)?;
            let ct_len = kem_ct_len(kem_variant(id).ok_or_else(fail)?);
            let (k_part, c_part) = if *kem_first {
                peer.split_at_checked(ct_len).ok_or_else(fail)?
            } else {
                let (c, k) = peer
                    .split_at_checked(peer.len().checked_sub(ct_len).ok_or_else(fail)?)
                    .ok_or_else(fail)?;
                (k, c)
            };
            let ks = kem.decapsulate(k_part).ok_or_else(fail)?;
            let cs = derive_with(cid, classical, c_part, p)?;
            Ok(Secret::new(if *kem_first {
                [ks.as_slice(), cs.bytes()].concat()
            } else {
                [cs.bytes(), ks.as_slice()].concat()
            }))
        }
    }
}

/// The length of an ML-KEM ciphertext.
fn kem_ct_len(v: mlkem::Variant) -> usize {
    match v {
        mlkem::Variant::MlKem512 => 768,
        mlkem::Variant::MlKem768 => 1088,
        mlkem::Variant::MlKem1024 => 1568,
    }
}

/// The server's response to the client's share: its own share (or ciphertext) and the secret.
pub fn respond(id: u16, peer: &[u8], p: &TestProvider) -> Result<(Vec<u8>, Secret)> {
    if let Some(v) = kem_variant(id) {
        let ek_len = match v {
            mlkem::Variant::MlKem512 => 800,
            mlkem::Variant::MlKem768 => 1184,
            mlkem::Variant::MlKem1024 => 1568,
        };
        let (k_part, c_part, kem_first) = match hybrid_parts(id) {
            None => (peer, &[][..], true),
            Some((_, true)) => {
                let (k, c) = peer.split_at_checked(ek_len).ok_or_else(fail)?;
                (k, c, true)
            }
            Some((_, false)) => {
                let (c, k) = peer
                    .split_at_checked(peer.len().checked_sub(ek_len).ok_or_else(fail)?)
                    .ok_or_else(fail)?;
                (k, c, false)
            }
        };
        let ek = mlkem::PublicKey::parse(v, k_part).map_err(|_| fail())?;
        let mut m = [0u8; mlkem::RANDOM_BYTES];
        p.draw(&mut m);
        let (ct, ks) = ek.encapsulate(&m).ok_or_else(fail)?;
        let Some((cid, _)) = hybrid_parts(id) else {
            return Ok((ct, Secret::new(ks.to_vec())));
        };
        let (c_pub, c_priv) = generate(cid, p)?;
        let cs = derive_with(cid, &c_priv, c_part, p)?;
        return Ok(if kem_first {
            (
                [ct, c_pub].concat(),
                Secret::new([ks.as_slice(), cs.bytes()].concat()),
            )
        } else {
            (
                [c_pub, ct].concat(),
                Secret::new([cs.bytes(), ks.as_slice()].concat()),
            )
        });
    }
    let (public, private) = generate(id, p)?;
    let secret = derive_with(id, &private, peer, p)?;
    Ok((public, secret))
}

/// A private key for signing.
pub enum PrivateKey {
    Rsa(Box<rsa::Key>),
    Ec(i32, BigNum),
    Ed25519([u8; 32]),
    Ed448([u8; 57]),
}

/// A public key from a certificate.
pub enum PublicKey {
    Rsa(Box<rsa::Key>, bool),
    Ec(i32, Vec<u8>),
    Ed25519([u8; 32]),
    Ed448([u8; 57]),
}

/// A DER element: its tag, its contents, and what follows.
fn tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first().ok_or_else(fail)?;
    let (&first, rest) = rest.split_first().ok_or_else(fail)?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        let (l, rest) = rest.split_at_checked(n).ok_or_else(fail)?;
        (
            l.iter().fold(0usize, |a, &b| (a << 8) | usize::from(b)),
            rest,
        )
    };
    let (content, after) = rest.split_at_checked(len).ok_or_else(fail)?;
    Ok((tag, content, after))
}

/// A DER element of the length `len`'s contents.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(u8::try_from(n).unwrap());
    } else {
        let be = n.to_be_bytes();
        let skip = be.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | u8::try_from(be.len() - skip).unwrap());
        out.extend_from_slice(&be[skip..]);
    }
    out.extend_from_slice(content);
    out
}

// The OIDs' DER contents.
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_RSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const OID_EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const OID_ED448: &[u8] = &[0x2b, 0x65, 0x71];

/// An INTEGER's content, unsigned.
fn int_content(n: &BigNum) -> Vec<u8> {
    let mut b = n.to_bin(None, Endian::Big, false).unwrap().to_vec();
    if b.first().is_none_or(|&f| f & 0x80 != 0) {
        b.insert(0, 0);
    }
    b
}

impl PublicKey {
    /// The SubjectPublicKeyInfo's DER.
    pub fn spki(&self) -> Vec<u8> {
        let (alg, key) = match self {
            Self::Rsa(k, pss) => {
                let body = [
                    der(0x02, &int_content(k.n.as_ref().unwrap())),
                    der(0x02, &int_content(k.e.as_ref().unwrap())),
                ]
                .concat();
                let oid = if *pss { OID_RSA_PSS } else { OID_RSA };
                let alg = if *pss {
                    der(0x30, &der(0x06, oid))
                } else {
                    der(0x30, &[der(0x06, oid), vec![0x05, 0]].concat())
                };
                (alg, der(0x30, &body))
            }
            Self::Ec(nid, pt) => {
                let curve = match *nid {
                    n if n == NID_X9_62_prime256v1 => OID_P256,
                    n if n == NID_secp384r1 => OID_P384,
                    _ => OID_P521,
                };
                (
                    der(0x30, &[der(0x06, OID_EC), der(0x06, curve)].concat()),
                    pt.clone(),
                )
            }
            Self::Ed25519(k) => (der(0x30, &der(0x06, OID_ED25519)), k.to_vec()),
            Self::Ed448(k) => (der(0x30, &der(0x06, OID_ED448)), k.to_vec()),
        };
        der(
            0x30,
            &[alg, der(0x03, &[&[0u8][..], &key].concat())].concat(),
        )
    }

    /// A minimal certificate carrying the key, issued by `name` to itself (its signature is a
    /// placeholder: verification is the caller's business, not the provider's).
    pub fn cert(&self, name: &str) -> Vec<u8> {
        let cn = der(
            0x30,
            &der(
                0x31,
                &der(
                    0x30,
                    &[der(0x06, &[0x55, 0x04, 0x03]), der(0x0c, name.as_bytes())].concat(),
                ),
            ),
        );
        let validity = der(
            0x30,
            &[der(0x17, b"250101000000Z"), der(0x17, b"350101000000Z")].concat(),
        );
        let alg = der(0x30, &der(0x06, OID_ED25519));
        let tbs = der(
            0x30,
            &[
                der(0xa0, &der(0x02, &[2])),
                der(0x02, &[1]),
                alg.clone(),
                cn.clone(),
                validity,
                cn,
                self.spki(),
            ]
            .concat(),
        );
        der(0x30, &[tbs, alg, der(0x03, &[0, 0])].concat())
    }

    /// The key in a certificate's DER.
    pub fn from_cert(cert: &[u8]) -> Result<Self> {
        let (_, c, _) = tlv(cert)?;
        let (_, mut tbs, _) = tlv(c)?;
        if tbs.first() == Some(&0xa0) {
            tbs = tlv(tbs)?.2;
        }
        // serial, signature, issuer, validity, subject
        for _ in 0..5 {
            tbs = tlv(tbs)?.2;
        }
        let (_, spki, _) = tlv(tbs)?;
        Self::from_spki(spki)
    }

    /// The key in a SubjectPublicKeyInfo's DER.
    pub fn from_spki_der(spki: &[u8]) -> Result<Self> {
        let (_, c, _) = tlv(spki)?;
        Self::from_spki(c)
    }

    /// What the signature checks need to know about the key.
    pub fn info(&self) -> crate::crypto::PeerKey {
        use crate::crypto::KeyKind;
        let (kind, curve_nid, size, bits) = match self {
            Self::Rsa(k, pss) => {
                let n = k.n.as_ref().map_or(0, |n| n.num_bytes());
                let kind = if *pss { KeyKind::RsaPss } else { KeyKind::Rsa };
                let bits = if n >= 384 {
                    128
                } else if n >= 256 {
                    112
                } else {
                    80
                };
                (kind, rustyssl_abi::NID_undef, n, bits)
            }
            Self::Ec(nid, _) => {
                let (size, bits) = if *nid == NID_secp384r1 {
                    (104, 192)
                } else if *nid == NID_secp521r1 {
                    (139, 256)
                } else {
                    (72, 128)
                };
                (KeyKind::Ec, *nid, size, bits)
            }
            Self::Ed25519(_) => (KeyKind::Ed25519, rustyssl_abi::NID_undef, 64, 128),
            Self::Ed448(_) => (KeyKind::Ed448, rustyssl_abi::NID_undef, 114, 224),
        };
        crate::crypto::PeerKey {
            kind,
            curve_nid,
            size,
            security_bits: bits,
        }
    }

    /// The key in a SubjectPublicKeyInfo's contents.
    fn from_spki(spki: &[u8]) -> Result<Self> {
        let (_, alg, rest) = tlv(spki)?;
        let (_, bits, _) = tlv(rest)?;
        let key = bits.get(1..).ok_or_else(fail)?;
        let (_, oid, params) = tlv(alg)?;
        match oid {
            o if o == OID_RSA || o == OID_RSA_PSS => {
                let (_, seq, _) = tlv(key)?;
                let (_, n, rest) = tlv(seq)?;
                let (_, e, _) = tlv(rest)?;
                let mut k = rsa::Key::new();
                k.n = Some(BigNum::from_bin(n, Endian::Big, false).map_err(|_| fail())?);
                k.e = Some(BigNum::from_bin(e, Endian::Big, false).map_err(|_| fail())?);
                Ok(Self::Rsa(Box::new(k), o == OID_RSA_PSS))
            }
            o if o == OID_EC => {
                let (_, c, _) = tlv(params)?;
                let nid = match c {
                    c if c == OID_P256 => NID_X9_62_prime256v1,
                    c if c == OID_P384 => NID_secp384r1,
                    c if c == OID_P521 => NID_secp521r1,
                    _ => return Err(fail()),
                };
                Ok(Self::Ec(nid, key.to_vec()))
            }
            o if o == OID_ED25519 => Ok(Self::Ed25519(key.try_into().map_err(|_| fail())?)),
            o if o == OID_ED448 => Ok(Self::Ed448(key.try_into().map_err(|_| fail())?)),
            _ => Err(fail()),
        }
    }
}

impl PrivateKey {
    /// The matching public key.
    pub fn public(&self, p: &TestProvider) -> Result<PublicKey> {
        Ok(match self {
            Self::Rsa(k) => {
                let mut pk = rsa::Key::new();
                pk.n = k.n.clone();
                pk.e = k.e.clone();
                PublicKey::Rsa(Box::new(pk), false)
            }
            Self::Ec(nid, d) => {
                let g = curve(*nid)?;
                let q = ec_mul(&g, d, None, p)?;
                PublicKey::Ec(*nid, ec_encode(&g, &q, p)?)
            }
            Self::Ed25519(k) => {
                PublicKey::Ed25519(ecx::ed25519_public_from_private(k).ok_or_else(fail)?)
            }
            Self::Ed448(k) => {
                PublicKey::Ed448(ecx448::ed448_public_from_private(k).ok_or_else(fail)?)
            }
        })
    }

    /// A new Ed25519 key.
    pub fn ed25519(p: &TestProvider) -> Self {
        let mut k = [0u8; 32];
        p.draw(&mut k);
        Self::Ed25519(k)
    }

    /// A new Ed448 key.
    pub fn ed448(p: &TestProvider) -> Self {
        let mut k = [0u8; 57];
        p.draw(&mut k);
        Self::Ed448(k)
    }

    /// A new ECDSA key on the curve of `nid`.
    pub fn ec(nid: i32, p: &TestProvider) -> Result<Self> {
        let g = curve(nid)?;
        Ok(Self::Ec(nid, scalar(&g, p)?))
    }

    /// An RSA key from its numbers (big-endian).
    #[allow(clippy::too_many_arguments, reason = "the key's numbers")]
    pub fn rsa(
        n: &[u8],
        e: &[u8],
        d: &[u8],
        p: &[u8],
        q: &[u8],
        dmp1: &[u8],
        dmq1: &[u8],
        iqmp: &[u8],
    ) -> Self {
        let b = |x: &[u8]| Some(BigNum::from_bin(x, Endian::Big, false).unwrap());
        let mut k = rsa::Key::new();
        k.n = b(n);
        k.e = b(e);
        k.d = b(d);
        k.p = b(p);
        k.q = b(q);
        k.dmp1 = b(dmp1);
        k.dmq1 = b(dmq1);
        k.iqmp = b(iqmp);
        Self::Rsa(Box::new(k))
    }
}

/// The hash of a signature scheme, and its NID.
fn scheme_hash(scheme: u16) -> Result<(HashAlg, i32)> {
    Ok(match scheme {
        RSA_PKCS1_MD5_SHA1 => (HashAlg::Md5Sha1, NID_md5_sha1),
        RSA_PKCS1_SHA1 | ECDSA_SHA1 => (HashAlg::Sha1, NID_sha1),
        RSA_PKCS1_SHA224 | ECDSA_SHA224 => (HashAlg::Sha224, NID_sha224),
        RSA_PKCS1_SHA256 | ECDSA_SECP256R1_SHA256 | RSA_PSS_RSAE_SHA256 | RSA_PSS_PSS_SHA256 => {
            (HashAlg::Sha256, NID_sha256)
        }
        RSA_PKCS1_SHA384 | ECDSA_SECP384R1_SHA384 | RSA_PSS_RSAE_SHA384 | RSA_PSS_PSS_SHA384 => {
            (HashAlg::Sha384, NID_sha384)
        }
        RSA_PKCS1_SHA512 | ECDSA_SECP521R1_SHA512 | RSA_PSS_RSAE_SHA512 | RSA_PSS_PSS_SHA512 => {
            (HashAlg::Sha512, NID_sha512)
        }
        _ => return Err(fail()),
    })
}

/// Whether a scheme is RSA-PSS.
fn is_pss(scheme: u16) -> bool {
    matches!(scheme, RSA_PSS_RSAE_SHA256..=RSA_PSS_RSAE_SHA512 | RSA_PSS_PSS_SHA256..=RSA_PSS_PSS_SHA512)
}

/// A hash as the RSA paddings take it.
struct RsaHash(HashAlg);

impl rsa::Hash for RsaHash {
    fn size(&self) -> usize {
        self.0.len()
    }

    fn block_size(&self) -> usize {
        match self.0 {
            HashAlg::Sha384 | HashAlg::Sha512 => 128,
            _ => 64,
        }
    }

    fn digest(&self, parts: &[&[u8]]) -> Option<Vec<u8>> {
        Some(digest(self.0, &parts.concat()))
    }
}

/// Signs `msg` under `scheme`.
pub fn sign(key: &PrivateKey, scheme: u16, msg: &[u8], p: &TestProvider) -> Result<Vec<u8>> {
    match key {
        PrivateKey::Ed25519(k) => {
            if scheme != ED25519 {
                return Err(fail());
            }
            let public = ecx::ed25519_public_from_private(k).ok_or_else(fail)?;
            let dom = ecx::Dom {
                dom2: false,
                ph: false,
                cs: false,
                context: &[],
            };
            Ok(ecx::ed25519_sign(msg, &public, k, &dom)
                .ok_or_else(fail)?
                .to_vec())
        }
        PrivateKey::Ed448(k) => {
            if scheme != ED448 {
                return Err(fail());
            }
            let public = ecx448::ed448_public_from_private(k).ok_or_else(fail)?;
            Ok(ecx448::ed448_sign(msg, &public, k, false, &[])
                .ok_or_else(fail)?
                .to_vec())
        }
        PrivateKey::Ec(nid, d) => {
            let (h, _) = scheme_hash(scheme)?;
            let g = curve(*nid)?;
            let m = ecdsa::digest_to_int(&digest(h, msg), g.order.num_bits());
            loop {
                let k = scalar(&g, p)?;
                let r_pt = ec_mul(&g, &k, None, p)?;
                let (x, _) = point::get_affine(&g, &r_pt, &mut rng(p)).map_err(|_| fail())?;
                let r = bn::nnmod(&x, &g.order).map_err(|_| fail())?;
                if r.is_zero() {
                    continue;
                }
                let kinv = ecdsa::inverse_mod_order(&g.order, &k).ok_or_else(fail)?;
                let Ok(s) = ecdsa::sign_s(&g.order, d, &m, &kinv, &r) else {
                    continue;
                };
                return ecdsa::encode_sig(&r, &s).ok_or_else(fail);
            }
        }
        PrivateKey::Rsa(k) => {
            let (h, nid) = scheme_hash(scheme)?;
            let mut sig = vec![0u8; k.size()];
            let mut r = rng(p);
            if is_pss(scheme) {
                let mut em = vec![0u8; k.size()];
                let hh = RsaHash(h);
                pad_ok(rsa::add_pss(
                    &mut em,
                    k.bits(),
                    &digest(h, msg),
                    &hh,
                    &hh,
                    -1,
                    &mut r,
                ))?;
                pad_ok(k.private_encrypt(&em, &mut sig, rsa::Padding::None, &mut r))?;
            } else {
                pad_ok(rsa::sign(k, nid, &digest(h, msg), &mut sig, &mut r))?;
            }
            Ok(sig)
        }
    }
}

/// An RSA outcome's value.
fn pad_ok<T>(o: rsa::Outcome<T>) -> Result<T> {
    o.0.map_err(|()| fail())
}

/// Whether `sig` verifies.
pub fn verify(key: &PublicKey, scheme: u16, msg: &[u8], sig: &[u8]) -> Result<bool> {
    let p = TestProvider::new(b"verify");
    Ok(match key {
        PublicKey::Ed25519(k) => {
            let dom = ecx::Dom {
                dom2: false,
                ph: false,
                cs: false,
                context: &[],
            };
            scheme == ED25519
                && sig
                    .try_into()
                    .is_ok_and(|s| ecx::ed25519_verify(msg, s, k, &dom))
        }
        PublicKey::Ed448(k) => {
            scheme == ED448
                && sig
                    .try_into()
                    .is_ok_and(|s| ecx448::ed448_verify(msg, s, k, false, &[]))
        }
        PublicKey::Ec(nid, q) => {
            let (h, _) = scheme_hash(scheme)?;
            let g = curve(*nid)?;
            let ecdsa::Decoded::Sig { r, s, consumed } = ecdsa::decode_sig(sig) else {
                return Ok(false);
            };
            if consumed != sig.len()
                || r.is_zero()
                || s.is_zero()
                || bn::cmp(&r, &g.order).is_ge()
                || bn::cmp(&s, &g.order).is_ge()
            {
                return Ok(false);
            }
            let m = ecdsa::digest_to_int(&digest(h, msg), g.order.num_bits());
            let w = ecdsa::inverse_mod_order(&g.order, &s).ok_or_else(fail)?;
            let u1 = bn::modular::mod_mul(&m, &w, &g.order).map_err(|_| fail())?;
            let u2 = bn::modular::mod_mul(&r, &w, &g.order).map_err(|_| fail())?;
            let qp = ec_decode(&g, q, &p)?;
            let mut x = point::Point::infinity();
            let pairs = [(&qp, &u2)];
            let req = mult::Request {
                scalar: Some(&u1),
                pairs: &pairs,
                scalar_is_order: false,
            };
            mult::mul(&g, &mut x, &req, &mut rng(&p)).map_err(|_| fail())?;
            if x.is_at_infinity() {
                return Ok(false);
            }
            let (xx, _) = point::get_affine(&g, &x, &mut rng(&p)).map_err(|_| fail())?;
            bn::cmp(&bn::nnmod(&xx, &g.order).map_err(|_| fail())?, &r).is_eq()
        }
        PublicKey::Rsa(k, pss_key) => {
            let (h, nid) = scheme_hash(scheme)?;
            if *pss_key && !matches!(scheme, RSA_PSS_PSS_SHA256..=RSA_PSS_PSS_SHA512) {
                return Ok(false);
            }
            if is_pss(scheme) {
                let mut em = vec![0u8; k.size()];
                let Ok(n) = k.public_decrypt(sig, &mut em, rsa::Padding::None).0 else {
                    return Ok(false);
                };
                let hh = RsaHash(h);
                rsa::verify_pss(
                    &digest(h, msg),
                    &hh,
                    &hh,
                    em.get(..n).unwrap_or_default(),
                    k.bits(),
                    -2,
                )
                .0
                .is_ok()
            } else {
                rsa::verify(k, nid, Some(&digest(h, msg)), sig).0.is_ok()
            }
        }
    })
}

/// The premaster secret encrypted to the certificate's RSA key.
pub fn rsa_encrypt(key: &PublicKey, pms: &[u8], p: &TestProvider) -> Result<Vec<u8>> {
    let PublicKey::Rsa(k, _) = key else {
        return Err(fail());
    };
    let mut out = vec![0u8; k.size()];
    let n = pad_ok(k.public_encrypt(pms, &mut out, rsa::Padding::Pkcs1, None, &mut rng(p)))?;
    out.truncate(n);
    Ok(out)
}

/// The premaster secret from its encryption, with implicit rejection: always 48 octets.
pub fn rsa_decrypt_pms(
    key: &PrivateKey,
    ct: &[u8],
    client_version: u16,
    p: &TestProvider,
) -> Result<Secret> {
    let PrivateKey::Rsa(k) = key else {
        return Err(fail());
    };
    let num = k.size();
    let mut block = vec![0u8; num];
    let mut r = rng(p);
    let (n, _) = k.private_decrypt(ct, &mut block, rsa::Padding::None, None, None, &mut r);
    if n < 0 {
        return Err(fail());
    }
    let mut pms = [0u8; 48];
    pad_ok(rsa::check_pkcs1_type2_tls(
        &mut pms,
        &block,
        i32::from(client_version),
        0,
        &mut r,
    ))?;
    Ok(Secret::new(pms.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Provider;

    #[test]
    fn every_group_agrees() {
        let p = TestProvider::new(b"groups");
        for g in groups() {
            let client = p.key_share(g.id).unwrap();
            let (reply, server_secret) = p.respond(g.id, client.public()).unwrap();
            let client_secret = client.derive(&reply).unwrap();
            assert_eq!(client_secret, server_secret, "{}", g.name);
            assert!(!client_secret.is_empty());
        }
    }

    #[test]
    fn signatures_verify_and_tampering_fails() {
        let p = TestProvider::new(b"sigs");
        let keys = [
            (PrivateKey::ed25519(&p), ED25519),
            (PrivateKey::ed448(&p), ED448),
            (
                PrivateKey::ec(NID_X9_62_prime256v1, &p).unwrap(),
                ECDSA_SECP256R1_SHA256,
            ),
            (
                PrivateKey::ec(NID_secp384r1, &p).unwrap(),
                ECDSA_SECP384R1_SHA384,
            ),
            (
                super::super::keys_rsa::rfc8448_server(),
                RSA_PSS_RSAE_SHA256,
            ),
            (super::super::keys_rsa::rfc8448_server(), RSA_PKCS1_SHA256),
        ];
        for (key, scheme) in keys {
            let cert = key.public(&p).unwrap().cert("test");
            let id = p.add_key(key);
            let sig = p.sign(id, scheme, b"message").unwrap();
            assert!(
                p.verify(&cert, scheme, b"message", &sig).unwrap(),
                "{scheme:#06x}"
            );
            assert!(
                !p.verify(&cert, scheme, b"messagf", &sig).unwrap(),
                "{scheme:#06x}"
            );
        }
    }

    #[test]
    fn rsa_premaster_round_trips_and_rejects_implicitly() {
        let p = TestProvider::new(b"pms");
        let key = super::super::keys_rsa::rfc8448_server();
        let cert = key.public(&p).unwrap().cert("rsa");
        let id = p.add_key(key);
        let mut pms = vec![0x03, 0x03];
        pms.extend_from_slice(&[7u8; 46]);
        let ct = p.rsa_encrypt(&cert, &pms).unwrap();
        assert_eq!(
            p.rsa_decrypt_pms(id, &ct, 0x0303).unwrap().bytes(),
            &pms[..]
        );
        // The wrong version: a random secret of the same length, no error.
        let wrong = p.rsa_decrypt_pms(id, &ct, 0x0302).unwrap();
        assert_eq!(wrong.len(), 48);
        assert_ne!(wrong.bytes(), &pms[..]);
    }
}
