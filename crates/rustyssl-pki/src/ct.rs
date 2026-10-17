//! Certificate Transparency's signed certificate timestamps (RFC 6962 section 3): the TLS
//! encodings of an SCT and of a list of them (`ct_oct.c`), and the data a log signs for one
//! (`ct_vfy.c`), parsed and built as OpenSSL does.
//!
//! As OpenSSL's:
//! - An SCT of another version than 1 is kept whole and opaque.
//! - A version 1 SCT's encoding may run past its signature; the rest is skipped.
//! - Lengths written in 16 (or 24) bits keep only their low bits.

/// Version 1 (`SCT_VERSION_V1`).
pub const V1: u8 = 0;
/// A version 1 log identifier's length (`CT_V1_HASHLEN`).
pub const HASH_LEN: usize = 32;
/// The longest SCT, and SCT list (`MAX_SCT_SIZE`, `MAX_SCT_LIST_SIZE`).
pub const MAX_SIZE: usize = 65535;
/// A version 1 SCT's fixed part: the version, log identifier, timestamp, and extensions'
/// length.
const V1_FIXED: usize = 1 + HASH_LEN + 8 + 2;

/// Why an encoding didn't parse (each a `CT_R_*` reason).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// `CT_R_SCT_INVALID`.
    Invalid,
    /// `CT_R_SCT_INVALID_SIGNATURE`.
    InvalidSignature,
    /// `CT_R_SCT_LIST_INVALID`.
    ListInvalid,
}

/// An SCT's parts, as decoded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Sct {
    pub version: u8,
    /// The whole encoding, for a version other than 1.
    pub raw: Vec<u8>,
    pub log_id: Vec<u8>,
    pub timestamp: u64,
    pub extensions: Vec<u8>,
    pub hash_alg: u8,
    pub sig_alg: u8,
    pub signature: Vec<u8>,
}

/// A big-endian 16-bit length at `at`.
fn be16(s: &[u8], at: usize) -> Option<usize> {
    let b = s.get(at..at.checked_add(2)?)?;
    Some(usize::from(u16::from_be_bytes([*b.first()?, *b.get(1)?])))
}

/// `o2i_SCT_signature`: a digitally-signed struct's algorithms and signature, from `input`
/// (more than 4 octets); `known` says whether the algorithms are a signature OpenSSL knows.
/// The octets used.
///
/// # Errors
/// [`Error::InvalidSignature`] if too short, unknown, or the signature runs past `input`.
pub fn parse_signature(
    sct: &mut Sct,
    input: &[u8],
    known: impl Fn(u8, u8) -> bool,
) -> Result<usize, Error> {
    if input.len() <= 4 {
        return Err(Error::InvalidSignature);
    }
    let (&hash_alg, &sig_alg) = (
        input.first().ok_or(Error::InvalidSignature)?,
        input.get(1).ok_or(Error::InvalidSignature)?,
    );
    sct.hash_alg = hash_alg;
    sct.sig_alg = sig_alg;
    if !known(hash_alg, sig_alg) {
        return Err(Error::InvalidSignature);
    }
    let siglen = be16(input, 2).ok_or(Error::InvalidSignature)?;
    let sig = input
        .get(4..)
        .and_then(|rest| rest.get(..siglen))
        .ok_or(Error::InvalidSignature)?;
    sct.signature = sig.to_vec();
    Ok(4usize.saturating_add(siglen))
}

/// `o2i_SCT`: an SCT from all of `input`.
///
/// # Errors
/// [`Error::Invalid`] for an empty or too long encoding, a version 1 one too short for its
/// parts, or (after the signature's own error) a bad signature.
pub fn parse_sct(input: &[u8], known: impl Fn(u8, u8) -> bool) -> Result<Sct, Vec<Error>> {
    if input.is_empty() || input.len() > MAX_SIZE {
        return Err(vec![Error::Invalid]);
    }
    let mut sct = Sct {
        version: *input.first().ok_or_else(|| vec![Error::Invalid])?,
        ..Sct::default()
    };
    if sct.version != V1 {
        sct.raw = input.to_vec();
        return Ok(sct);
    }
    if input.len() < V1_FIXED {
        return Err(vec![Error::Invalid]);
    }
    let field = |from: usize, len: usize| input.get(from..from.checked_add(len)?);
    let invalid = || vec![Error::Invalid];
    sct.log_id = field(1, HASH_LEN).ok_or_else(invalid)?.to_vec();
    let ts = field(1 + HASH_LEN, 8).ok_or_else(invalid)?;
    let mut t = [0u8; 8];
    t.copy_from_slice(ts);
    sct.timestamp = u64::from_be_bytes(t);
    let ext_len = be16(input, 1 + HASH_LEN + 8).ok_or_else(invalid)?;
    let rest = input.get(V1_FIXED..).ok_or_else(invalid)?;
    let ext = rest.get(..ext_len).ok_or_else(invalid)?;
    sct.extensions = ext.to_vec();
    let sig = rest.get(ext_len..).ok_or_else(invalid)?;
    if let Err(e) = parse_signature(&mut sct, sig, known) {
        return Err(vec![e, Error::Invalid]);
    }
    Ok(sct)
}

/// `i2o_SCT_signature`'s encoding.
#[must_use]
pub fn encode_signature(sct: &Sct) -> Vec<u8> {
    let mut out = Vec::with_capacity(sct.signature.len().saturating_add(4));
    out.push(sct.hash_alg);
    out.push(sct.sig_alg);
    out.extend_from_slice(&low16(sct.signature.len()));
    out.extend_from_slice(&sct.signature);
    out
}

/// A length's low 16 bits, big-endian (`s2n`).
fn low16(n: usize) -> [u8; 2] {
    let [.., a, b] = n.to_be_bytes();
    [a, b]
}

/// A length's low 24 bits, big-endian (`l2n3`).
fn low24(n: usize) -> [u8; 3] {
    let [.., a, b, c] = n.to_be_bytes();
    [a, b, c]
}

/// `i2o_SCT`'s encoding of a complete SCT: a version 1 SCT's parts (the log identifier's
/// first 32 octets), or another version's whole encoding.
#[must_use]
pub fn encode_sct(sct: &Sct) -> Vec<u8> {
    if sct.version != V1 {
        return sct.raw.clone();
    }
    let mut out = Vec::new();
    out.push(sct.version);
    let mut id = [0u8; HASH_LEN];
    for (d, s) in id.iter_mut().zip(&sct.log_id) {
        *d = *s;
    }
    out.extend_from_slice(&id);
    out.extend_from_slice(&sct.timestamp.to_be_bytes());
    out.extend_from_slice(&low16(sct.extensions.len()));
    out.extend_from_slice(&sct.extensions);
    out.extend_from_slice(&encode_signature(sct));
    out
}

/// A list that didn't parse: its errors, the octets OpenSSL's parser had moved past (the
/// lengths read), and the SCTs before the bad one.
#[derive(Debug, PartialEq, Eq)]
pub struct ListError {
    pub errors: Vec<Error>,
    pub consumed: usize,
    pub parsed: Vec<Sct>,
}

/// `o2i_SCT_LIST`: the SCTs of a list's encoding (all of `input`).
///
/// # Errors
/// [`Error::ListInvalid`] for a bad length (of the list or an entry), or an entry's errors.
pub fn parse_sct_list(input: &[u8], known: impl Fn(u8, u8) -> bool) -> Result<Vec<Sct>, ListError> {
    let fail = |errors, consumed, parsed| ListError {
        errors,
        consumed,
        parsed,
    };
    if input.len() < 2 || input.len() > MAX_SIZE {
        return Err(fail(vec![Error::ListInvalid], 0, Vec::new()));
    }
    let list_len = be16(input, 0).unwrap_or(0);
    let mut consumed = 2usize;
    if Some(list_len) != input.len().checked_sub(2) {
        return Err(fail(vec![Error::ListInvalid], consumed, Vec::new()));
    }
    let mut out = Vec::new();
    while let Some(rest) = input.get(consumed..).filter(|r| !r.is_empty()) {
        if rest.len() < 2 {
            return Err(fail(vec![Error::ListInvalid], consumed, out));
        }
        let sct_len = be16(rest, 0).unwrap_or(0);
        consumed = consumed.saturating_add(2);
        let body = rest.get(2..).unwrap_or_default();
        if sct_len == 0 || sct_len > body.len() {
            return Err(fail(vec![Error::ListInvalid], consumed, out));
        }
        let one = body.get(..sct_len).unwrap_or_default();
        match parse_sct(one, &known) {
            Ok(s) => out.push(s),
            Err(errors) => return Err(fail(errors, consumed, out)),
        }
        consumed = consumed.saturating_add(sct_len);
    }
    Ok(out)
}

/// `i2o_SCT_LIST`'s encoding of the SCTs' encodings, or `None` past 65,535 octets.
#[must_use]
pub fn encode_sct_list(scts: &[Vec<u8>]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    for s in scts {
        body.extend_from_slice(&low16(s.len()));
        body.extend_from_slice(s);
    }
    if body.len().checked_add(2)? > MAX_SIZE {
        return None;
    }
    let mut out = low16(body.len()).to_vec();
    out.extend_from_slice(&body);
    Some(out)
}

/// The entry types (`CT_LOG_ENTRY_TYPE_*`) a log signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryType {
    X509,
    Precert,
}

/// `sct_ctx_update`'s input: what a log signs for a version 1 SCT over `der` (the
/// certificate, or the precertificate's TBS with `issuer_key_hash`).
#[must_use]
pub fn signed_data(sct: &Sct, entry: EntryType, issuer_key_hash: &[u8], der: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(sct.version);
    // signature_type: certificate_timestamp.
    out.push(0);
    out.extend_from_slice(&sct.timestamp.to_be_bytes());
    let (code, precert) = match entry {
        EntryType::X509 => (0u16, false),
        EntryType::Precert => (1u16, true),
    };
    out.extend_from_slice(&code.to_be_bytes());
    if precert {
        out.extend_from_slice(issuer_key_hash);
    }
    out.extend_from_slice(&low24(der.len()));
    out.extend_from_slice(der);
    out.extend_from_slice(&low16(sct.extensions.len()));
    out.extend_from_slice(&sct.extensions);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known(h: u8, s: u8) -> bool {
        h == 4 && (s == 1 || s == 3)
    }

    fn sample() -> Vec<u8> {
        let mut v = vec![V1];
        v.extend_from_slice(&[0xab; HASH_LEN]);
        v.extend_from_slice(&1_500_000_000_000u64.to_be_bytes());
        v.extend_from_slice(&[0, 2, 0xee, 0xff]);
        v.extend_from_slice(&[4, 3, 0, 3, 1, 2, 3]);
        v
    }

    #[test]
    fn round_trips() {
        let s = parse_sct(&sample(), known).expect("parses");
        assert_eq!(s.timestamp, 1_500_000_000_000);
        assert_eq!(s.extensions, [0xee, 0xff]);
        assert_eq!(s.signature, [1, 2, 3]);
        assert_eq!(encode_sct(&s), sample());
        let list = encode_sct_list(&[sample(), sample()]).expect("fits");
        assert_eq!(parse_sct_list(&list, known).expect("parses").len(), 2);
    }

    #[test]
    fn rejects_what_openssl_rejects() {
        let mut short = sample();
        short.truncate(V1_FIXED - 1);
        assert_eq!(parse_sct(&short, known), Err(vec![Error::Invalid]));
        let mut bad_sig = sample();
        if let Some(b) = bad_sig.get_mut(V1_FIXED + 2) {
            *b = 2;
        }
        assert_eq!(
            parse_sct(&bad_sig, known),
            Err(vec![Error::InvalidSignature, Error::Invalid])
        );
        assert_eq!(parse_sct(&[], known), Err(vec![Error::Invalid]));
        let e = parse_sct_list(&[0, 1, 0], known).expect_err("one octet left");
        assert_eq!((e.errors, e.consumed), (vec![Error::ListInvalid], 2));
        let e = parse_sct_list(&[0, 2, 0, 0], known).expect_err("an empty SCT");
        assert_eq!((e.errors, e.consumed), (vec![Error::ListInvalid], 4));
    }

    #[test]
    fn keeps_other_versions_whole() {
        let s = parse_sct(&[7, 1, 2], known).expect("parses");
        assert_eq!(s.raw, [7, 1, 2]);
        assert_eq!(encode_sct(&s), [7, 1, 2]);
    }

    /// Arbitrary input never panics, and what parses encodes back to a prefix of it.
    #[test]
    fn arbitrary_input() {
        let mut x: u32 = 1;
        for _ in 0..2000 {
            let mut v = Vec::new();
            for _ in 0..(x % 90) {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                v.push(u8::try_from(x & 0xff).unwrap_or(0));
            }
            if let Ok(s) = parse_sct(&v, known) {
                let e = encode_sct(&s);
                assert!(v.starts_with(&e));
            }
            let _ = parse_sct_list(&v, known);
        }
    }
}
