//! PKCS #1 v1.5 signatures' DigestInfo (`ossl_rsa_digestinfo_encoding`, `digest_sz_from_nid`
//! in `rsa_sign.c`): the DER prefix `30 L 30 L 06 L <OID> 05 00 04 <size>` the digest follows,
//! built from the object table.
//!
//! Two of OpenSSL's prefixes carry another OID than the digest's, which signatures made with
//! them depend on, so they're kept: MD4's encodes 1.2.840.113549.2.3 (MD4 is 2.4), and SM3's
//! encodes sm3WithRSAEncryption (1.2.156.10197.1.504), not SM3.

use rustyssl_abi::{
    NID_md4, NID_md5, NID_mdc2, NID_ripemd160, NID_sha1, NID_sha3_224, NID_sha3_256, NID_sha3_384,
    NID_sha3_512, NID_sha224, NID_sha256, NID_sha384, NID_sha512, NID_sha512_224, NID_sha512_256,
    NID_sm3, NID_sm3WithRSAEncryption,
};
use rustyssl_asn1::objects;

/// The digests with a prefix, and their sizes.
const DIGESTS: &[(i32, u8)] = &[
    (NID_md4, 16),
    (NID_md5, 16),
    (NID_mdc2, 16),
    (NID_ripemd160, 20),
    (NID_sm3, 32),
    (NID_sha1, 20),
    (NID_sha224, 28),
    (NID_sha256, 32),
    (NID_sha384, 48),
    (NID_sha512, 64),
    (NID_sha512_224, 28),
    (NID_sha512_256, 32),
    (NID_sha3_224, 28),
    (NID_sha3_256, 32),
    (NID_sha3_384, 48),
    (NID_sha3_512, 64),
];

/// The DigestInfo prefix for the digest `nid`, or `None` for one without.
pub fn digest_info(nid: i32) -> Option<Vec<u8>> {
    let &(_, size) = DIGESTS.iter().find(|(n, _)| *n == nid)?;
    let named = if nid == NID_sm3 {
        NID_sm3WithRSAEncryption
    } else {
        nid
    };
    let mut oid = objects::object(named)?.der.to_vec();
    if nid == NID_md4 {
        // OpenSSL's MD4 prefix ends the OID with arc 3.
        if let Some(last) = oid.last_mut() {
            *last = 3;
        }
    }
    let olen = u8::try_from(oid.len()).ok()?;
    // AlgorithmIdentifier: OID and NULL.
    let alg_len = olen.checked_add(4)?;
    let total = alg_len.checked_add(2)?.checked_add(2)?.checked_add(size)?;
    let mut out = vec![0x30, total, 0x30, alg_len, 0x06, olen];
    out.extend_from_slice(&oid);
    out.extend_from_slice(&[0x05, 0x00, 0x04, size]);
    Some(out)
}

/// `digest_sz_from_nid`: the digest sizes recovery knows (SM3's isn't among them, as in
/// OpenSSL), or 0.
pub fn digest_size(nid: i32) -> usize {
    if nid == NID_sm3 {
        return 0;
    }
    DIGESTS
        .iter()
        .find(|(n, _)| *n == nid)
        .map_or(0, |&(_, s)| usize::from(s))
}
