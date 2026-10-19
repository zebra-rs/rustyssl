//! X25519 and Ed25519 (RFC 7748, RFC 8032; OpenSSL's `curve25519.c`), over `curve25519-dalek`'s
//! arithmetic.
//!
//! What OpenSSL decides is ours: X25519 clamps the scalar and fails on an all-zero result (a
//! low-order peer); Ed25519 hashes with `dom2` for Ed25519ctx and Ed25519ph, signs with the
//! public key it's given (not one recomputed), and verifies with the strict equation
//! `ENC(h(-A) + sB) == R`, refusing `s >= L` and public keys that don't decode. Point decoding
//! takes y as OpenSSL's does: the top bit is x's sign, y needn't be reduced, and x = 0 with
//! the sign bit set is x = 0.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroizing;

use crate::md::{self, Algorithm};

/// The keys' and X25519's output length.
pub const KEYLEN: usize = 32;
/// Ed25519's signature length.
pub const ED25519_SIGSIZE: usize = 64;

/// `L` in little-endian, the order of the base point: `2^252 + 27742317777372353535851937790883648493`.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// Clamps an X25519 private key as generation does.
pub fn x25519_clamp(k: &mut [u8; KEYLEN]) {
    let [first, .., last] = k;
    *first &= 248;
    *last &= 127;
    *last |= 64;
}

/// `ossl_x25519`: the shared secret of `scalar` (clamped here) and the peer's u-coordinate, or
/// `None` if it's all zeros (the peer's point has a small order).
pub fn x25519(scalar: &[u8; KEYLEN], peer: &[u8; KEYLEN]) -> Option<Zeroizing<[u8; KEYLEN]>> {
    crate::dit::with(|| {
        let out = Zeroizing::new(MontgomeryPoint(*peer).mul_clamped(*scalar).to_bytes());
        let zero = out.iter().fold(0u8, |acc, &b| acc | b) == 0;
        (!zero).then_some(out)
    })
}

/// `ossl_x25519_public_from_private`: the base point times the clamped scalar.
pub fn x25519_public_from_private(private: &[u8; KEYLEN]) -> [u8; KEYLEN] {
    crate::dit::with(|| MontgomeryPoint::mul_base_clamped(*private).to_bytes())
}

/// SHA-512 of the parts.
fn sha512(parts: &[&[u8]]) -> Option<Zeroizing<[u8; 64]>> {
    let mut ctx = md::context(Algorithm::Sha512);
    for p in parts {
        ctx.update(p).ok()?;
    }
    let mut out = Zeroizing::new([0u8; 64]);
    ctx.finalize(out.as_mut_slice()).ok()?;
    Some(out)
}

/// The secret scalar and the nonce prefix of a private key: SHA-512, its first half clamped.
fn expand(private: &[u8; KEYLEN]) -> Option<(Scalar, Zeroizing<[u8; 32]>)> {
    let az = sha512(&[private])?;
    let mut a = Zeroizing::new([0u8; 32]);
    a.copy_from_slice(az.get(..32)?);
    if let [first, .., last] = a.as_mut_slice() {
        *first &= 248;
        *last &= 63;
        *last |= 64;
    }
    let mut prefix = Zeroizing::new([0u8; 32]);
    prefix.copy_from_slice(az.get(32..)?);
    Some((Scalar::from_bytes_mod_order(*a), prefix))
}

/// `ossl_ed25519_public_from_private`: the encoded `aB`.
pub fn ed25519_public_from_private(private: &[u8; KEYLEN]) -> Option<[u8; KEYLEN]> {
    crate::dit::with(|| {
        let (a, _) = expand(private)?;
        Some(EdwardsPoint::mul_base(&a).compress().to_bytes())
    })
}

/// How a signature's hashes start (`hash_init_with_dom`): nothing for Ed25519, `dom2(phflag,
/// context)` for Ed25519ctx and Ed25519ph.
#[derive(Clone, Copy, Debug, Default)]
pub struct Dom<'a> {
    /// `dom2flag`: the hashes start with `dom2`.
    pub dom2: bool,
    /// `phflag`: the message is a SHA-512 prehash.
    pub ph: bool,
    /// `csflag`: a non-empty context is required.
    pub cs: bool,
    /// The context string.
    pub context: &'a [u8],
}

impl Dom<'_> {
    /// The checks OpenSSL makes before hashing: a context where required, none without dom2,
    /// at most 255 octets.
    fn valid(&self) -> bool {
        !(self.cs && self.context.is_empty())
            && (self.dom2 || self.context.is_empty())
            && self.context.len() <= usize::from(u8::MAX)
    }

    /// `dom2`'s octets, or none.
    fn prefix(&self) -> Vec<u8> {
        if !self.dom2 {
            return Vec::new();
        }
        let mut v = b"SigEd25519 no Ed25519 collisions".to_vec();
        v.push(u8::from(self.ph));
        v.push(u8::try_from(self.context.len()).unwrap_or(u8::MAX));
        v.extend_from_slice(self.context);
        v
    }
}

/// `ossl_ed25519_sign`: the signature of `msg` with the private key and the public key given
/// (OpenSSL doesn't check they match), or `None` for a context the variant refuses.
pub fn ed25519_sign(
    msg: &[u8],
    public: &[u8; KEYLEN],
    private: &[u8; KEYLEN],
    dom: &Dom<'_>,
) -> Option<[u8; ED25519_SIGSIZE]> {
    if !dom.valid() {
        return None;
    }
    crate::dit::with(|| {
        let (a, prefix) = expand(private)?;
        let d = dom.prefix();
        let nonce = sha512(&[&d, prefix.as_slice(), msg])?;
        let r = Scalar::from_bytes_mod_order_wide(&nonce);
        let big_r = EdwardsPoint::mul_base(&r).compress().to_bytes();
        let hram = sha512(&[&d, &big_r, public, msg])?;
        let h = Scalar::from_bytes_mod_order_wide(&hram);
        // Scalars are reduced mod L; their operators can't overflow.
        #[expect(clippy::arithmetic_side_effects, reason = "arithmetic mod L")]
        let s = h * a + r;
        let mut sig = [0u8; ED25519_SIGSIZE];
        sig.get_mut(..32)?.copy_from_slice(&big_r);
        sig.get_mut(32..)?.copy_from_slice(s.as_bytes());
        Some(sig)
    })
}

/// Whether `s < L`, compared as OpenSSL compares it (public, so in variable time).
fn below_l(s: &[u8; 32]) -> bool {
    for (&a, &b) in s.iter().rev().zip(L.iter().rev()) {
        if a != b {
            return a < b;
        }
    }
    false
}

/// `ossl_ed25519_verify`: whether `sig` signs `msg` for the public key, by the strict
/// equation.
pub fn ed25519_verify(
    msg: &[u8],
    sig: &[u8; ED25519_SIGSIZE],
    public: &[u8; KEYLEN],
    dom: &Dom<'_>,
) -> bool {
    if !dom.valid() {
        return false;
    }
    let (mut r, mut s) = ([0u8; 32], [0u8; 32]);
    r.copy_from_slice(&sig[..32]);
    s.copy_from_slice(&sig[32..]);
    if !below_l(&s) {
        return false;
    }
    let Some(big_a) = CompressedEdwardsY(*public).decompress() else {
        return false;
    };
    let Some(hram) = sha512(&[&dom.prefix(), &r, public, msg]) else {
        return false;
    };
    let h = Scalar::from_bytes_mod_order_wide(&hram);
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s)) else {
        return false;
    };
    #[expect(clippy::arithmetic_side_effects, reason = "a point's negation")]
    let neg_a = -big_a;
    let check = EdwardsPoint::vartime_double_scalar_mul_basepoint(&h, &neg_a, &s);
    // OpenSSL compares the encodings with CRYPTO_memcmp.
    subtle_eq(&check.compress().to_bytes(), &r)
}

/// Constant-time equality of two encodings.
fn subtle_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i.saturating_add(2)], 16).unwrap_or(0))
            .collect()
    }

    fn arr<const N: usize>(v: &[u8]) -> [u8; N] {
        let mut a = [0u8; N];
        a.copy_from_slice(v);
        a
    }

    /// RFC 7748, 6.1.
    #[test]
    fn x25519_matches_rfc_7748() {
        let a = arr::<32>(&hex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let b = arr::<32>(&hex(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ));
        let a_pub = x25519_public_from_private(&a);
        assert_eq!(
            a_pub.to_vec(),
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        let b_pub = x25519_public_from_private(&b);
        let k = x25519(&a, &b_pub).unwrap_or_else(|| panic!("a secret"));
        assert_eq!(
            k.to_vec(),
            hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        );
        // A low-order peer gives zeros.
        assert!(x25519(&a, &[0u8; 32]).is_none());
    }

    /// RFC 8032, 7.1 TEST 2, and 7.3's Ed25519ph and 7.2's Ed25519ctx.
    #[test]
    fn ed25519_matches_rfc_8032() {
        let sk = arr::<32>(&hex(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        ));
        let pk = ed25519_public_from_private(&sk).unwrap_or_default();
        assert_eq!(
            pk.to_vec(),
            hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        );
        let sig = ed25519_sign(&[0x72], &pk, &sk, &Dom::default()).unwrap_or([0; 64]);
        assert_eq!(
            sig.to_vec(),
            hex(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            )
        );
        assert!(ed25519_verify(&[0x72], &sig, &pk, &Dom::default()));
        assert!(!ed25519_verify(&[0x73], &sig, &pk, &Dom::default()));
        // s = L is refused.
        let mut bad = sig;
        bad[32..].copy_from_slice(&L);
        assert!(!ed25519_verify(&[0x72], &bad, &pk, &Dom::default()));

        let sk = arr::<32>(&hex(
            "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6",
        ));
        let pk = ed25519_public_from_private(&sk).unwrap_or_default();
        let ctx = Dom {
            dom2: true,
            ph: false,
            cs: true,
            context: &hex("666f6f"),
        };
        let sig = ed25519_sign(&hex("f726936d19c800494e3fdaff20b276a8"), &pk, &sk, &ctx)
            .unwrap_or([0; 64]);
        assert_eq!(
            sig.to_vec(),
            hex(
                "55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d"
            )
        );
        let no_ctx = Dom {
            context: &[],
            ..ctx
        };
        assert!(ed25519_sign(&[1], &pk, &sk, &no_ctx).is_none());

        let sk = arr::<32>(&hex(
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        ));
        let pk = ed25519_public_from_private(&sk).unwrap_or_default();
        let ph = Dom {
            dom2: true,
            ph: true,
            cs: false,
            context: &[],
        };
        let digest = sha512(&[&hex("616263")]).unwrap_or_else(|| panic!("hashes"));
        let sig = ed25519_sign(digest.as_slice(), &pk, &sk, &ph).unwrap_or([0; 64]);
        assert_eq!(
            sig.to_vec(),
            hex(
                "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406"
            )
        );
    }
}
