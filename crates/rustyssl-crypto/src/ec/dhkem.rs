//! A DHKEM private key derived from input key material (RFC 9180, 7.1.3, `DeriveKeyPair` for
//! the NIST curves; OpenSSL's `ossl_ec_dhkem_derive_private`): HPKE's labeled HKDF over the
//! KEM's suite, then candidates until one is a valid scalar.

use zeroize::Zeroizing;

use crate::bn::{self, BigNum, Endian};
use crate::kdf;
use crate::md::Algorithm;

/// One of the KEMs over a NIST curve (OpenSSL's `hpke_kem_tab`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kem {
    /// The curve's NIST name, as the table names it.
    pub curve: &'static str,
    /// The KEM's identifier.
    pub id: u16,
    /// The KDF's digest.
    pub digest: Algorithm,
    /// `Nsecret`: the extracted secret's length.
    pub secret_len: usize,
    /// `Nsk`: a private key's length.
    pub private_len: usize,
    /// The mask for a candidate's first octet.
    pub bitmask: u8,
}

/// The KEMs over the NIST curves.
pub const KEMS: [Kem; 3] = [
    Kem {
        curve: "P-256",
        id: 0x10,
        digest: Algorithm::Sha256,
        secret_len: 32,
        private_len: 32,
        bitmask: 0xff,
    },
    Kem {
        curve: "P-384",
        id: 0x11,
        digest: Algorithm::Sha384,
        secret_len: 48,
        private_len: 48,
        bitmask: 0xff,
    },
    Kem {
        curve: "P-521",
        id: 0x12,
        digest: Algorithm::Sha512,
        secret_len: 64,
        private_len: 66,
        bitmask: 0x01,
    },
];

/// The KEM over the curve of a NIST name (in any case).
pub fn kem_by_curve(name: &[u8]) -> Option<&'static Kem> {
    KEMS.iter()
        .find(|k| k.curve.as_bytes().eq_ignore_ascii_case(name))
}

/// Why no key was derived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The input is shorter than a private key (`PROV_R_INVALID_INPUT_LENGTH`).
    ShortInput {
        /// The input's length.
        len: usize,
        /// The private key's length it must reach.
        min: usize,
    },
    /// No candidate was a valid scalar (`PROV_R_FAILED_TO_GENERATE_KEY`).
    Exhausted,
    /// The KDF failed.
    Kdf(kdf::Error),
}

impl From<kdf::Error> for Error {
    fn from(e: kdf::Error) -> Self {
        Self::Kdf(e)
    }
}

/// HPKE's version label.
const HPKE_V1: &[u8] = b"HPKE-v1";
/// The KEM's protocol label.
const KEM_LABEL: &[u8] = b"KEM";

/// `LabeledExtract(salt, label, ikm)` for the KEM.
pub fn labeled_extract(
    kem: &Kem,
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
    out: &mut [u8],
) -> Result<(), kdf::Error> {
    let suite = kem.id.to_be_bytes();
    let labeled = Zeroizing::new([HPKE_V1, KEM_LABEL, &suite, label, ikm].concat());
    kdf::hkdf_extract(kem.digest, salt, &labeled, out)
}

/// `LabeledExpand(prk, label, info, L)` for the KEM, `L` being `out`'s length.
pub fn labeled_expand(
    kem: &Kem,
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), kdf::Error> {
    let len = u16::try_from(out.len())
        .map_err(|_| kdf::Error::OutputLength)?
        .to_be_bytes();
    let suite = kem.id.to_be_bytes();
    let labeled = [&len, HPKE_V1, KEM_LABEL, &suite, label, info].concat();
    kdf::hkdf_expand(kem.digest, prk, &labeled, out)
}

/// `DeriveKeyPair`'s private key: the first candidate (counter 0 to 254) in `[1, order)`.
pub fn derive_private(kem: &Kem, order: &BigNum, ikm: &[u8]) -> Result<BigNum, Error> {
    if ikm.len() < kem.private_len {
        return Err(Error::ShortInput {
            len: ikm.len(),
            min: kem.private_len,
        });
    }
    let mut prk = Zeroizing::new(vec![0u8; kem.secret_len]);
    labeled_extract(kem, &[], b"dkp_prk", ikm, &mut prk)?;
    let mut candidate = Zeroizing::new(vec![0u8; kem.private_len]);
    for counter in 0..=u8::MAX {
        labeled_expand(kem, &prk, b"candidate", &[counter], &mut candidate)?;
        if let Some(first) = candidate.first_mut() {
            *first &= kem.bitmask;
        }
        if counter == u8::MAX {
            break;
        }
        let sk = BigNum::from_bin(&candidate, Endian::Big, false).unwrap_or_default();
        if !sk.is_zero() && bn::cmp(&sk, order).is_lt() {
            return Ok(sk);
        }
    }
    Err(Error::Exhausted)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9180, A.3.1: DHKEM(P-256, HKDF-SHA256), the sender's ephemeral key.
    #[test]
    fn rfc9180_p256() {
        let Some(kem) = kem_by_curve(b"p-256") else {
            panic!("P-256's KEM");
        };
        let order = BigNum::from_hex_digits(
            b"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        )
        .unwrap_or_default();
        let ikm = BigNum::from_hex_digits(
            b"4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e",
        )
        .ok()
        .and_then(|n| n.to_bin(Some(32), Endian::Big, false))
        .map(|z| z.to_vec())
        .unwrap_or_default();
        let sk = derive_private(kem, &order, &ikm).unwrap_or_default();
        let want = BigNum::from_hex_digits(
            b"4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb",
        )
        .unwrap_or_default();
        assert!(bn::cmp(&sk, &want).is_eq());
        assert_eq!(
            derive_private(kem, &order, ikm.get(..31).unwrap_or_default()),
            Err(Error::ShortInput { len: 31, min: 32 })
        );
        assert!(kem_by_curve(b"P-224").is_none());
    }
}
