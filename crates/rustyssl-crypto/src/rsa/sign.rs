//! PKCS #1 v1.5 signatures over a digest (`rsa_sign.c`, `rsa_saos.c`): the DigestInfo signed
//! (`RSA_sign`), checked or recovered (`ossl_rsa_verify`), and MDC2's bare OCTET STRING
//! (`RSA_sign_ASN1_OCTET_STRING`).

use rustyssl_abi::{NID_md5_sha1, NID_mdc2, NID_undef};

use super::{
    Entry, Key, Outcome, PKCS1_PADDING_SIZE, Padding, Raised, Random, Reason, digest_info,
    digest_size, fail, silent,
};

/// MD5-SHA1's "digest": the two digests, signed without a DigestInfo.
const MD5_SHA1_LEN: usize = 36;

/// `encode_pkcs1`: the digest `m` in its DigestInfo.
fn encode_pkcs1(nid: i32, m: &[u8]) -> Result<Vec<u8>, Entry> {
    const F: &str = "encode_pkcs1";
    if nid == NID_undef {
        return Err(Entry::raised(F, Reason::UnknownAlgorithmType));
    }
    let Some(mut out) = digest_info(nid) else {
        return Err(Entry::raised(F, Reason::AsnObjectNotKnownForMd));
    };
    out.extend_from_slice(m);
    Ok(out)
}

/// `RSA_sign`'s block before padding: the digest `m` of `nid` in its DigestInfo (MD5-SHA1's
/// bare), checked against the key's size `num`.
pub fn sign_encoding(nid: i32, m: &[u8], num: usize) -> Result<Vec<u8>, Raised> {
    const F: &str = "RSA_sign";
    let encoded = if nid == NID_md5_sha1 {
        if m.len() != MD5_SHA1_LEN {
            return Err(vec![Entry::raised(F, Reason::InvalidMessageLength)]);
        }
        m.to_vec()
    } else {
        encode_pkcs1(nid, m).map_err(|e| vec![e])?
    };
    if encoded.len().saturating_add(PKCS1_PADDING_SIZE) > num {
        return Err(vec![Entry::raised(F, Reason::DigestTooBigForRsaKey)]);
    }
    Ok(encoded)
}

/// `RSA_sign`: the digest `m` of `nid` signed into `sig` (the key's size).
pub fn sign(key: &Key, nid: i32, m: &[u8], sig: &mut [u8], rng: &mut Random<'_>) -> Outcome<usize> {
    match sign_encoding(nid, m, key.size()) {
        Ok(encoded) => key.private_encrypt(&encoded, sig, Padding::Pkcs1, rng),
        Err(raised) => (Err(()), raised),
    }
}

/// The DER encoding of an OCTET STRING holding `m` (`i2d_ASN1_OCTET_STRING`).
pub fn octet_string_der(m: &[u8]) -> Vec<u8> {
    let len = m.len();
    let mut out = vec![0x04];
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        out.push(0x80 | u8::try_from(bytes.len()).unwrap_or(0));
        out.extend(bytes);
    }
    out.extend_from_slice(m);
    out
}

/// `RSA_sign_ASN1_OCTET_STRING`'s block before padding: `m` as a DER OCTET STRING, checked
/// against the key's size `num`.
pub fn octet_string_encoding(m: &[u8], num: usize) -> Result<Vec<u8>, Raised> {
    let der = octet_string_der(m);
    if der.len() > num.saturating_sub(PKCS1_PADDING_SIZE) {
        return Err(vec![Entry::raised(
            "RSA_sign_ASN1_OCTET_STRING",
            Reason::DigestTooBigForRsaKey,
        )]);
    }
    Ok(der)
}

/// `RSA_sign_ASN1_OCTET_STRING`: the digest as a DER OCTET STRING, signed with PKCS #1 v1.5
/// padding (MDC2's form).
pub fn sign_octet_string(
    key: &Key,
    m: &[u8],
    sig: &mut [u8],
    rng: &mut Random<'_>,
) -> Outcome<usize> {
    match octet_string_encoding(m, key.size()) {
        Ok(der) => key.private_encrypt(&der, sig, Padding::Pkcs1, rng),
        Err(raised) => (Err(()), raised),
    }
}

/// `ossl_rsa_verify`: whether `sig` signs the digest `m` of `nid`, or, with no `m`, the digest
/// recovered from it. Returns the digest.
pub fn verify(key: &Key, nid: i32, m: Option<&[u8]>, sig: &[u8]) -> Outcome<Vec<u8>> {
    const F: &str = "ossl_rsa_verify";
    let num = key.size();
    if sig.len() != num {
        return fail(F, Reason::WrongSignatureLength);
    }
    let mut buf = vec![0u8; num];
    let (r, raised) = key.public_decrypt(sig, &mut buf, Padding::Pkcs1);
    let len = match r {
        Ok(n) if n > 0 => n,
        _ => return (Err(()), raised),
    };
    check_decrypted(nid, m, buf.get(..len).unwrap_or_default())
}

/// `ossl_rsa_verify` after the public decryption: whether `decrypted` (the block's data)
/// holds the digest `m` of `nid`, or, with no `m`, the digest it holds. Returns the digest.
pub fn check_decrypted(nid: i32, m: Option<&[u8]>, decrypted: &[u8]) -> Outcome<Vec<u8>> {
    const F: &str = "ossl_rsa_verify";
    let len = decrypted.len();
    if nid == NID_md5_sha1 {
        if len != MD5_SHA1_LEN {
            return fail(F, Reason::BadSignature);
        }
        return match m {
            None => (Ok(decrypted.to_vec()), Vec::new()),
            Some(m) if m.len() != MD5_SHA1_LEN => fail(F, Reason::InvalidMessageLength),
            Some(m) if m != decrypted => fail(F, Reason::BadSignature),
            Some(m) => (Ok(m.to_vec()), Vec::new()),
        };
    }
    if nid == NID_mdc2 && len == 18 && decrypted.starts_with(&[0x04, 0x10]) {
        let d = decrypted.get(2..).unwrap_or_default();
        return match m {
            None => (Ok(d.to_vec()), Vec::new()),
            Some(m) if m.len() != 16 => fail(F, Reason::InvalidMessageLength),
            Some(m) if m != d => fail(F, Reason::BadSignature),
            Some(m) => (Ok(m.to_vec()), Vec::new()),
        };
    }
    let digest = match m {
        Some(m) => m.to_vec(),
        None => {
            let m_len = digest_size(nid);
            if m_len == 0 {
                return silent();
            }
            let Some(start) = len.checked_sub(m_len) else {
                return fail(F, Reason::InvalidDigestLength);
            };
            decrypted.get(start..).unwrap_or_default().to_vec()
        }
    };
    let encoded = match encode_pkcs1(nid, &digest) {
        Ok(e) => e,
        Err(e) => return (Err(()), vec![e]),
    };
    if encoded != decrypted {
        return fail(F, Reason::BadSignature);
    }
    (Ok(digest), Vec::new())
}
