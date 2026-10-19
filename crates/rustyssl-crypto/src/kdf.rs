//! Key derivation: the computations behind the built-in providers' KDFs (HKDF, TLS13-KDF,
//! PBKDF1, PBKDF2, PKCS12KDF, PVKKDF, SSKDF, X963KDF, X942KDF, KBKDF, TLS1-PRF, SSHKDF,
//! KRB5KDF, scrypt, and Argon2) and `EVP_BytesToKey`.
//!
//! All are ours, composed from the digest backend (`md`), the MACs (`mac`), and the block
//! ciphers (`sym`); scrypt's Salsa20/8 and Argon2's compression function are ours too, Argon2
//! over the `blake2` crate's core (through `mac`). Each is one function that derives into an
//! output buffer. The EVP layer (3.6) owns the parameters: their names, defaults, which are
//! required, and the errors it raises; these functions check what the computations themselves
//! need, with the reference's limits where it has them:
//! - digests: a KDF over a hash refuses XOFs and digests of no size (NULL), as the reference
//!   fails on them (except SSHKDF over NULL, which loops forever there: docs/DEVIATIONS.md);
//! - HKDF-Expand: at most 255 blocks; TLS 1.3's labels: lengths that fit their length octets;
//! - SSKDF, X963KDF, and X942KDF: inputs and output of at most 2^30 octets;
//! - PBKDF2: fewer than 2^32 - 1 blocks; KBKDF: the counter's range; KRB5KDF: a constant of
//!   1 to a block;
//! - scrypt: N a power of two from 2, r and p from 1 with p * r < 2^30, N < 2^(16r), and the
//!   memory (128 * r * p + 128 * r * (N + 2) octets) within `maxmem`;
//! - Argon2: versions 0x10 and 0x13, at least one pass, 1 to 2^24 - 1 lanes, at least
//!   8 * lanes blocks of memory, salts of at least 8 octets, and 4 octets of output or more.
//!
//! Every intermediate secret is wiped when dropped. Argon2d's memory accesses depend on the
//! password, as the algorithm defines them; Argon2i's don't, and Argon2id's don't in its first
//! half pass. scrypt's accesses depend on the password, as the algorithm defines them.

use zeroize::{Zeroize, Zeroizing};

use crate::{mac, md, sym};

/// Why a derivation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A digest the KDF can't use: an XOF, or one of no size (NULL).
    Digest,
    /// An output length the KDF can't produce.
    OutputLength,
    /// An input over the KDF's limits.
    InputLength,
    /// A parameter out of range: scrypt's N, r, or p; Argon2's costs, lanes, or version;
    /// KBKDF's counter length or IV; KRB5KDF's constant.
    Parameter,
    /// scrypt's memory over the limit.
    MemoryLimit,
    /// The memory couldn't be allocated.
    Allocation,
    /// KRB5KDF derived triple-DES keys that degrade to single DES.
    WeakKey,
    /// The MAC refused its key or parameters.
    Mac(mac::Error),
}

impl From<mac::Error> for Error {
    fn from(e: mac::Error) -> Self {
        Self::Mac(e)
    }
}

/// SSKDF's, X963KDF's, and X942KDF's limit on each input and the output.
const MAX_INLEN: usize = 1 << 30;

/// The size of a digest a KDF can hash with.
fn digest_size(digest: md::Algorithm) -> Result<usize, Error> {
    match digest.output_size() {
        0 => Err(Error::Digest),
        _ if digest.is_xof() => Err(Error::Digest),
        n => Ok(n),
    }
}

/// `digest` of the concatenated `parts`, into `out` (exactly the digest's size).
fn hash(digest: md::Algorithm, parts: &[&[u8]], out: &mut [u8]) -> Result<(), Error> {
    let mut ctx = md::context(digest);
    for part in parts {
        ctx.update(part).map_err(|_| Error::Digest)?;
    }
    ctx.finalize(out).map_err(|_| Error::Digest)
}

/// A MAC of the concatenated `parts`, from a copy of the keyed `mac`, into `out` (exactly the
/// MAC's size).
fn mac_of(mac: &dyn mac::Mac, parts: &[&[u8]], out: &mut [u8]) -> Result<(), Error> {
    let mut m = mac.clone_box();
    for part in parts {
        m.update(part)?;
    }
    Ok(m.finalize(out)?)
}

/// Fills `out` block by block: `block(counter, buf)` computes block `counter` (from 1) into
/// `buf` of `size` octets, the last block truncated.
fn by_blocks(
    out: &mut [u8],
    size: usize,
    mut block: impl FnMut(u32, &mut [u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut buf = Zeroizing::new(vec![0u8; size]);
    let mut counter = 0u32;
    for chunk in out.chunks_mut(size.max(1)) {
        counter = counter.checked_add(1).ok_or(Error::OutputLength)?;
        block(counter, &mut buf)?;
        chunk.copy_from_slice(buf.get(..chunk.len()).ok_or(Error::OutputLength)?);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// HKDF (RFC 5869) and TLS 1.3's (RFC 8446)

/// HKDF-Extract: PRK = HMAC(salt, ikm), into `out` of exactly the digest's size.
pub fn hkdf_extract(
    digest: md::Algorithm,
    salt: &[u8],
    ikm: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    crate::dit::with(|| {
        if out.len() != digest_size(digest)? {
            return Err(Error::OutputLength);
        }
        let m = mac::hmac(digest, salt)?;
        mac_of(&*m, &[ikm], out)
    })
}

/// HKDF-Expand: T(i) = HMAC(PRK, T(i - 1) || info || i), at most 255 blocks.
pub fn hkdf_expand(
    digest: md::Algorithm,
    prk: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    crate::dit::with(|| {
        let size = digest_size(digest)?;
        if out.len().div_ceil(size) > 255 {
            return Err(Error::OutputLength);
        }
        let m = mac::hmac(digest, prk)?;
        let mut prev = Zeroizing::new(Vec::with_capacity(size));
        by_blocks(out, size, |i, buf| {
            let counter = u8::try_from(i).map_err(|_| Error::OutputLength)?;
            mac_of(&*m, &[&prev, info, &[counter]], buf)?;
            prev.clear();
            prev.extend_from_slice(buf);
            Ok(())
        })
    })
}

/// HKDF: extract, then expand.
pub fn hkdf(
    digest: md::Algorithm,
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    crate::dit::with(|| {
        let mut prk = Zeroizing::new(vec![0u8; digest_size(digest)?]);
        hkdf_extract(digest, salt, ikm, &mut prk)?;
        hkdf_expand(digest, &prk, info, out)
    })
}

/// TLS 1.3's HKDF-Expand-Label: HKDF-Expand with the `HkdfLabel` structure (the output
/// length, `prefix || label`, and `data`, each with its length), the prefix normally
/// `"tls13 "`. The lengths must fit their fields.
pub fn tls13_expand(
    digest: md::Algorithm,
    secret: &[u8],
    prefix: &[u8],
    label: &[u8],
    data: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    crate::dit::with(|| {
        let out_len = u16::try_from(out.len()).map_err(|_| Error::OutputLength)?;
        let label_len = prefix
            .len()
            .checked_add(label.len())
            .and_then(|n| u8::try_from(n).ok())
            .ok_or(Error::InputLength)?;
        let data_len = u8::try_from(data.len()).map_err(|_| Error::InputLength)?;
        let mut info = Vec::with_capacity(514);
        info.extend_from_slice(&out_len.to_be_bytes());
        info.push(label_len);
        info.extend_from_slice(prefix);
        info.extend_from_slice(label);
        info.push(data_len);
        info.extend_from_slice(data);
        hkdf_expand(digest, secret, &info, out)
    })
}

/// TLS 1.3's secret derivation (OpenSSL's TLS13-KDF in extract mode): HKDF-Extract of
/// `secret` (zeros if `None`) with the salt `Derive-Secret(previous, label, "")` (zeros if
/// there's no previous secret), into `out` of exactly the digest's size.
pub fn tls13_extract(
    digest: md::Algorithm,
    previous: Option<&[u8]>,
    secret: Option<&[u8]>,
    prefix: &[u8],
    label: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    crate::dit::with(|| {
        let size = digest_size(digest)?;
        let zeros = vec![0u8; size];
        let salt = match previous {
            None => Zeroizing::new(zeros.clone()),
            Some(previous) => {
                let mut empty_hash = vec![0u8; size];
                hash(digest, &[], &mut empty_hash)?;
                let mut salt = Zeroizing::new(vec![0u8; size]);
                tls13_expand(digest, previous, prefix, label, &empty_hash, &mut salt)?;
                salt
            }
        };
        hkdf_extract(digest, &salt, secret.unwrap_or(&zeros), out)
    })
}

// ---------------------------------------------------------------------------------------------
// Password-based: PBKDF1, PBKDF2 (RFC 8018), PKCS#12's (RFC 7292), PVK's, EVP_BytesToKey

/// PBKDF1: T = Hash^iterations(password || salt), the first `out.len()` octets (at most the
/// digest's size). Zero iterations count as one.
pub fn pbkdf1(
    digest: md::Algorithm,
    password: &[u8],
    salt: &[u8],
    iterations: u64,
    out: &mut [u8],
) -> Result<(), Error> {
    crate::dit::with(|| {
        let size = digest_size(digest)?;
        if out.len() > size {
            return Err(Error::OutputLength);
        }
        let mut t = Zeroizing::new(vec![0u8; size]);
        hash(digest, &[password, salt], &mut t)?;
        for _ in 1..iterations {
            let prev = t.clone();
            hash(digest, &[&prev], &mut t)?;
        }
        out.copy_from_slice(t.get(..out.len()).ok_or(Error::OutputLength)?);
        Ok(())
    })
}

/// PBKDF2 with HMAC over `digest`. Zero iterations count as one.
pub fn pbkdf2(
    digest: md::Algorithm,
    password: &[u8],
    salt: &[u8],
    iterations: u64,
    out: &mut [u8],
) -> Result<(), Error> {
    crate::dit::with(|| {
        let size = digest_size(digest)?;
        if out.len().checked_div(size).ok_or(Error::Digest)? >= 0xffff_ffff {
            return Err(Error::OutputLength);
        }
        let m = mac::hmac(digest, password)?;
        let mut u = Zeroizing::new(vec![0u8; size]);
        by_blocks(out, size, |i, t| {
            mac_of(&*m, &[salt, &i.to_be_bytes()], &mut u)?;
            t.copy_from_slice(&u);
            for _ in 1..iterations {
                let prev = u.clone();
                mac_of(&*m, &[&prev], &mut u)?;
                t.iter_mut().zip(u.iter()).for_each(|(t, &u)| *t ^= u);
            }
            Ok(())
        })
    })
}

/// `s` repeated to fill `n` octets.
fn repeat(s: &[u8], n: usize) -> impl Iterator<Item = u8> + '_ {
    s.iter()
        .copied()
        .cycle()
        .take(if s.is_empty() { 0 } else { n })
}

/// PKCS#12's KDF (RFC 7292 appendix B) with the purpose `id` (1 key, 2 IV, 3 MAC key);
/// `password` is already encoded (BMPString with its terminating zeros). Zero iterations count
/// as one.
pub fn pkcs12(
    digest: md::Algorithm,
    password: &[u8],
    salt: &[u8],
    id: u8,
    iterations: u64,
    out: &mut [u8],
) -> Result<(), Error> {
    crate::dit::with(|| {
        let u = digest_size(digest)?;
        let v = digest.block_size();
        if v == 0 {
            return Err(Error::Digest);
        }
        let fill = |n: usize| n.div_ceil(v).checked_mul(v).ok_or(Error::InputLength);
        let d = vec![id; v];
        let mut i: Zeroizing<Vec<u8>> = Zeroizing::new(
            repeat(salt, fill(salt.len())?)
                .chain(repeat(password, fill(password.len())?))
                .collect(),
        );
        let mut a = Zeroizing::new(vec![0u8; u]);
        let mut b = Zeroizing::new(vec![0u8; v]);
        let mut chunks = out.chunks_mut(u).peekable();
        while let Some(chunk) = chunks.next() {
            hash(digest, &[&d, &i], &mut a)?;
            for _ in 1..iterations {
                let prev = a.clone();
                hash(digest, &[&prev], &mut a)?;
            }
            chunk.copy_from_slice(a.get(..chunk.len()).ok_or(Error::OutputLength)?);
            if chunks.peek().is_none() {
                break;
            }
            // I_j = (I_j + B + 1) mod 2^(8v), for each v-octet block of I.
            b.iter_mut().zip(repeat(&a, v)).for_each(|(b, a)| *b = a);
            for block in i.chunks_mut(v) {
                let mut carry = 1u16;
                for (x, &y) in block.iter_mut().rev().zip(b.iter().rev()) {
                    let sum = carry.wrapping_add(u16::from(*x)).wrapping_add(u16::from(y));
                    *x = sum.to_le_bytes()[0];
                    carry = sum >> 8;
                }
            }
        }
        Ok(())
    })
}

/// PVK's KDF (Microsoft's private-key blobs): Hash(salt || password) into the first digest's
/// size of `out`, which must be at least that long; the rest is left as it is.
pub fn pvk(
    digest: md::Algorithm,
    salt: &[u8],
    password: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    crate::dit::with(|| {
        let size = digest_size(digest)?;
        let head = out.get_mut(..size).ok_or(Error::OutputLength)?;
        hash(digest, &[salt, password], head)
    })
}

/// `EVP_BytesToKey`: D_i = Hash^count(D_(i-1) || data || salt), filling `key` then `iv`.
/// A count of zero counts as one.
pub fn bytes_to_key(
    digest: md::Algorithm,
    salt: Option<&[u8]>,
    data: &[u8],
    count: u32,
    key: &mut [u8],
    iv: &mut [u8],
) -> Result<(), Error> {
    crate::dit::with(|| {
        let size = digest_size(digest)?;
        let mut d = Zeroizing::new(Vec::new());
        let mut outputs = key.iter_mut().chain(iv.iter_mut()).peekable();
        while outputs.peek().is_some() {
            let mut next = Zeroizing::new(vec![0u8; size]);
            hash(digest, &[&d, data, salt.unwrap_or(&[])], &mut next)?;
            for _ in 1..count {
                let prev = next.clone();
                hash(digest, &[&prev], &mut next)?;
            }
            // The digest's octets drive the zip, so no output is taken past them.
            for (&b, o) in next.iter().zip(outputs.by_ref()) {
                *o = b;
            }
            d = next;
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------------------------
// One-step and ANSI KDFs: SSKDF (SP 800-56C), X9.63, X9.42

/// Checks SSKDF's, X963KDF's, and X942KDF's limits.
fn check_one_step(inputs: &[&[u8]], out: &[u8]) -> Result<(), Error> {
    if out.is_empty() || out.len() > MAX_INLEN {
        return Err(Error::OutputLength);
    }
    if inputs.iter().any(|i| i.len() > MAX_INLEN) {
        return Err(Error::InputLength);
    }
    Ok(())
}

/// SSKDF with a hash: Hash(counter || z || info) for counters from 1.
pub fn sskdf_hash(
    digest: md::Algorithm,
    z: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    crate::dit::with(|| {
        check_one_step(&[z, info], out)?;
        by_blocks(out, digest_size(digest)?, |i, buf| {
            hash(digest, &[&i.to_be_bytes(), z, info], buf)
        })
    })
}

/// X9.63's KDF: Hash(z || counter || info) for counters from 1.
pub fn x963(digest: md::Algorithm, z: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), Error> {
    crate::dit::with(|| {
        check_one_step(&[z, info], out)?;
        by_blocks(out, digest_size(digest)?, |i, buf| {
            hash(digest, &[z, &i.to_be_bytes(), info], buf)
        })
    })
}

/// SSKDF with a MAC (HMAC or KMAC), already keyed with the salt and sized:
/// MAC(counter || z || info) for counters from 1.
pub fn sskdf_mac(mac: &dyn mac::Mac, z: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), Error> {
    crate::dit::with(|| {
        check_one_step(&[z, info], out)?;
        if mac.size() == 0 {
            return Err(Error::Mac(mac::Error::OutputSize));
        }
        by_blocks(out, mac.size(), |i, buf| {
            mac_of(mac, &[&i.to_be_bytes(), z, info], buf)
        })
    })
}

/// X9.42's `OtherInfo` fields (each `None` if absent).
#[derive(Debug, Clone, Copy, Default)]
pub struct X942Info<'a> {
    /// The key-wrapping algorithm's OBJECT IDENTIFIER, DER-encoded (tag and length too).
    pub cek_oid: &'a [u8],
    /// The wrapping key's length in octets, encoded in bits as `suppPubInfo` (0 to omit).
    pub kek_length: usize,
    /// A precomputed blob of DER fields, placed after the key information (ACVP's tests).
    pub acvp: Option<&'a [u8]>,
    /// `partyUInfo` (the CMS ukm).
    pub party_u: Option<&'a [u8]>,
    /// `partyVInfo`.
    pub party_v: Option<&'a [u8]>,
    /// `suppPubInfo`.
    pub supp_pub: Option<&'a [u8]>,
    /// `suppPrivInfo`.
    pub supp_priv: Option<&'a [u8]>,
}

/// A DER element: `tag`, the definite length, `content`.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        let digits = bytes.get(skip..).unwrap_or(&[]);
        out.push(0x80 | u8::try_from(digits.len()).unwrap_or(0));
        out.extend_from_slice(digits);
    }
    out.extend_from_slice(content);
    out
}

/// An explicitly tagged OCTET STRING, `[n] OCTET STRING`.
fn tagged_octets(n: u8, content: &[u8]) -> Vec<u8> {
    der(0xa0 | n, &der(0x04, content))
}

/// The DER `OtherInfo` with a counter of 1, and the counter's offset in it.
pub fn x942_other_info(info: &X942Info<'_>) -> Result<(Vec<u8>, usize), Error> {
    let kek_bits = u32::try_from(info.kek_length)
        .ok()
        .filter(|&n| n <= 0xff_ffff)
        .map(|n| n.wrapping_mul(8))
        .ok_or(Error::OutputLength)?;
    let mut key_info = info.cek_oid.to_vec();
    key_info.extend_from_slice(&der(0x04, &1u32.to_be_bytes()));
    let key_info = der(0x30, &key_info);
    // The counter is the last four octets of the key information.
    let mut content = key_info;
    let counter = content.len().checked_sub(4).ok_or(Error::Parameter)?;
    if let Some(acvp) = info.acvp {
        content.extend_from_slice(acvp);
    }
    if let Some(u) = info.party_u {
        content.extend(tagged_octets(0, u));
    }
    if let Some(v) = info.party_v {
        content.extend(tagged_octets(1, v));
    }
    if kek_bits != 0 {
        content.extend(tagged_octets(2, &kek_bits.to_be_bytes()));
    }
    if let Some(p) = info.supp_pub {
        content.extend(tagged_octets(2, p));
    }
    if let Some(p) = info.supp_priv {
        content.extend(tagged_octets(3, p));
    }
    let header = der(0x30, &content)
        .len()
        .checked_sub(content.len())
        .ok_or(Error::Parameter)?;
    let other = der(0x30, &content);
    Ok((other, header.checked_add(counter).ok_or(Error::Parameter)?))
}

/// X9.42's KDF (OpenSSL's X942KDF-ASN1): Hash(z || OtherInfo) with the counter in
/// `OtherInfo`'s key information counting from 1.
pub fn x942(
    digest: md::Algorithm,
    z: &[u8],
    info: &X942Info<'_>,
    out: &mut [u8],
) -> Result<(), Error> {
    crate::dit::with(|| {
        let size = digest_size(digest)?;
        let (mut other, at) = x942_other_info(info)?;
        check_one_step(&[z, &other], out)?;
        by_blocks(out, size, |i, buf| {
            other
                .get_mut(at..)
                .and_then(|c| c.get_mut(..4))
                .ok_or(Error::Parameter)?
                .copy_from_slice(&i.to_be_bytes());
            hash(digest, &[z, &other], buf)
        })
    })
}

// ---------------------------------------------------------------------------------------------
// KBKDF (SP 800-108)

/// KBKDF's modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KbkdfMode<'a> {
    /// Counter mode.
    Counter,
    /// Feedback mode, from an IV (empty, or the MAC's size).
    Feedback(&'a [u8]),
}

/// KBKDF over `mac` (HMAC or CMAC, keyed): MAC([K(i-1)] || counter || label || [0x00] ||
/// context || [L]), the counter `counter_bits` (8, 16, 24, or 32) wide, the separator and L
/// (the output length in bits, as 32 bits) included if asked for.
#[allow(clippy::too_many_arguments)]
pub fn kbkdf(
    mac: &dyn mac::Mac,
    mode: KbkdfMode<'_>,
    counter_bits: u32,
    label: &[u8],
    context: &[u8],
    separator: bool,
    use_l: bool,
    out: &mut [u8],
) -> Result<(), Error> {
    crate::dit::with(|| {
        if !matches!(counter_bits, 8 | 16 | 24 | 32) {
            return Err(Error::Parameter);
        }
        if out.is_empty() {
            return Err(Error::OutputLength);
        }
        let h = mac.size();
        if h == 0 {
            return Err(Error::Mac(mac::Error::OutputSize));
        }
        let counter_len = usize::try_from(counter_bits / 8).map_err(|_| Error::Parameter)?;
        let mut previous = Zeroizing::new(Vec::new());
        match mode {
            KbkdfMode::Feedback(iv) => {
                if !iv.is_empty() && iv.len() != h {
                    return Err(Error::Parameter);
                }
                previous.extend_from_slice(iv);
            }
            KbkdfMode::Counter => {
                let blocks = u64::try_from(out.len().checked_div(h).unwrap_or(0))
                    .map_err(|_| Error::OutputLength)?;
                if blocks >= 1u64 << counter_bits {
                    return Err(Error::OutputLength);
                }
            }
        }
        let feedback = matches!(mode, KbkdfMode::Feedback(_));
        // L is the output length in bits, taken modulo 2^32 as the reference's 32-bit field.
        let l = u64::try_from(out.len())
            .map(|n| n.wrapping_mul(8).to_be_bytes())
            .map_err(|_| Error::OutputLength)?;
        let l = l.get(4..).unwrap_or(&[]);
        let mut counter = 0u32;
        for chunk in out.chunks_mut(h) {
            counter = counter.wrapping_add(1);
            let be = counter.to_be_bytes();
            let ctr = be.get(4usize.saturating_sub(counter_len)..).unwrap_or(&[]);
            let mut block = Zeroizing::new(vec![0u8; h]);
            let fb: &[u8] = if feedback { &previous } else { &[] };
            let sep: &[u8] = if separator { &[0] } else { &[] };
            let len: &[u8] = if use_l { l } else { &[] };
            mac_of(mac, &[fb, ctr, label, sep, context, len], &mut block)?;
            chunk.copy_from_slice(block.get(..chunk.len()).ok_or(Error::OutputLength)?);
            previous = block;
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------------------------
// Protocol KDFs: TLS 1.0 to 1.2's PRF, SSH's, Kerberos's

/// TLS's P_hash: HMAC(secret, A(i) || seed) with A(0) = seed, A(i) = HMAC(secret, A(i-1)).
fn p_hash(digest: md::Algorithm, secret: &[u8], seed: &[u8], out: &mut [u8]) -> Result<(), Error> {
    let m = mac::hmac(digest, secret)?;
    let size = m.size();
    if size == 0 {
        return Err(Error::Digest);
    }
    let mut a = Zeroizing::new(vec![0u8; size]);
    mac_of(&*m, &[seed], &mut a)?;
    by_blocks(out, size, |_, buf| {
        mac_of(&*m, &[&a, seed], buf)?;
        let prev = a.clone();
        mac_of(&*m, &[&prev], &mut a)
    })
}

/// TLS's PRF: P_hash over `digest` (TLS 1.2), or for MD5-SHA1 (TLS 1.0 and 1.1) P_MD5 over
/// the secret's first half XOR P_SHA1 over its second (the halves share the middle octet of
/// an odd-length secret).
pub fn tls1_prf(
    digest: md::Algorithm,
    secret: &[u8],
    seed: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    crate::dit::with(|| {
        if digest != md::Algorithm::Md5Sha1 {
            return p_hash(digest, secret, seed, out);
        }
        let half = secret.len().div_ceil(2);
        let first = secret.get(..half).ok_or(Error::InputLength)?;
        let second = secret
            .get(secret.len().saturating_sub(half)..)
            .ok_or(Error::InputLength)?;
        p_hash(md::Algorithm::Md5, first, seed, out)?;
        let mut sha1 = Zeroizing::new(vec![0u8; out.len()]);
        p_hash(md::Algorithm::Sha1, second, seed, &mut sha1)?;
        out.iter_mut().zip(sha1.iter()).for_each(|(o, &s)| *o ^= s);
        Ok(())
    })
}

/// SSH's KDF (RFC 4253 section 7.2): K1 = Hash(K || H || type || session_id), then
/// K(n) = Hash(K || H || K1 || ... || K(n-1)).
pub fn sshkdf(
    digest: md::Algorithm,
    key: &[u8],
    exchange_hash: &[u8],
    kind: u8,
    session_id: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    crate::dit::with(|| {
        let size = digest_size(digest)?;
        let mut block = Zeroizing::new(vec![0u8; size]);
        let mut done = 0usize;
        while done < out.len() {
            let so_far = out.get(..done).ok_or(Error::OutputLength)?;
            if done == 0 {
                hash(
                    digest,
                    &[key, exchange_hash, &[kind], session_id],
                    &mut block,
                )?;
            } else {
                hash(digest, &[key, exchange_hash, so_far], &mut block)?;
            }
            let n = size.min(out.len().saturating_sub(done));
            let end = done.saturating_add(n);
            out.get_mut(done..end)
                .ok_or(Error::OutputLength)?
                .copy_from_slice(block.get(..n).ok_or(Error::OutputLength)?);
            done = end;
        }
        Ok(())
    })
}

/// RFC 3961's n-fold of `constant` to `size` octets, computed as the reference does.
pub fn n_fold(constant: &[u8], size: usize) -> Result<Vec<u8>, Error> {
    if constant.len() == size {
        return Ok(constant.to_vec());
    }
    let k = u32::try_from(constant.len()).map_err(|_| Error::Parameter)?;
    let n = u32::try_from(size).map_err(|_| Error::Parameter)?;
    let (mut gcd, mut rem) = (n, k);
    while rem != 0 {
        let t = gcd.checked_rem(rem).ok_or(Error::Parameter)?;
        gcd = rem;
        rem = t;
    }
    let lcm = n
        .checked_mul(k)
        .and_then(|p| p.checked_div(gcd))
        .ok_or(Error::Parameter)?;
    let byte = |i: u32| -> Result<u32, Error> {
        let i = usize::try_from(i.checked_rem(k).ok_or(Error::Parameter)?)
            .map_err(|_| Error::Parameter)?;
        constant
            .get(i)
            .copied()
            .map(u32::from)
            .ok_or(Error::Parameter)
    };
    let mut block = vec![0u8; size];
    let mut carry = 0u32;
    for l in (0..lcm).rev() {
        let b = usize::try_from(l.checked_rem(n).ok_or(Error::Parameter)?)
            .map_err(|_| Error::Parameter)?;
        let rotbits = l.checked_div(k).ok_or(Error::Parameter)?.wrapping_mul(13);
        let rbyte = l.wrapping_sub(rotbits / 8);
        let rshift = rotbits & 7;
        let tmp = ((byte(rbyte.wrapping_sub(1))? << 8u32.wrapping_sub(rshift))
            | (byte(rbyte)? >> rshift))
            & 0xff;
        let slot = block.get_mut(b).ok_or(Error::Parameter)?;
        let sum = tmp.wrapping_add(carry).wrapping_add(u32::from(*slot));
        *slot = sum.to_le_bytes()[0];
        carry = sum >> 8;
    }
    for slot in block.iter_mut().rev() {
        if carry == 0 {
            break;
        }
        carry = carry.wrapping_add(u32::from(*slot));
        *slot = carry.to_le_bytes()[0];
        carry >>= 8;
    }
    Ok(block)
}

/// Equality of two secrets without branching on their contents.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Triple DES's key from 21 random octets in the first 21 of `key` (RFC 3961's
/// random-to-key): each 7 octets spread to 8 with odd parity. Refuses keys that degrade to
/// single DES.
pub fn des3_random_to_key(key: &mut [u8]) -> Result<(), Error> {
    for i in (0..3usize).rev() {
        let src = i.wrapping_mul(7);
        let dst = i.wrapping_mul(8);
        let mut block = [0u8; 8];
        block
            .get_mut(..7)
            .ok_or(Error::OutputLength)?
            .copy_from_slice(
                key.get(src..src.wrapping_add(7))
                    .ok_or(Error::OutputLength)?,
            );
        let low_bits = block
            .iter()
            .take(7)
            .enumerate()
            .fold(0u8, |acc, (j, &b)| acc | ((b & 1) << (j.wrapping_add(1))));
        block[7] = low_bits;
        for b in &mut block {
            // Odd parity in the low bit.
            *b = (*b & 0xfe) | u8::from((*b >> 1).count_ones() % 2 == 0);
        }
        key.get_mut(dst..dst.wrapping_add(8))
            .ok_or(Error::OutputLength)?
            .copy_from_slice(&block);
    }
    let k = |i: usize| key.get(i..i.wrapping_add(8)).unwrap_or(&[]);
    if ct_eq(k(0), k(8)) || ct_eq(k(8), k(16)) {
        return Err(Error::WeakKey);
    }
    Ok(())
}

/// Kerberos's DK (RFC 3961): the n-folded `constant` (1 to a block) encrypted, then each block
/// encrypted again, with a keyed block cipher. For triple DES (`des3`), the 24 octets are then
/// turned into a key with parity from their first 21.
pub fn krb5kdf(
    cipher: &dyn sym::BlockCipher,
    constant: &[u8],
    des3: bool,
    out: &mut [u8],
) -> Result<(), Error> {
    crate::dit::with(|| {
        let size = cipher.block_size();
        if constant.is_empty() || constant.len() > size {
            return Err(Error::Parameter);
        }
        if des3 && out.len() != 24 {
            return Err(Error::OutputLength);
        }
        let mut block = Zeroizing::new(n_fold(constant, size)?);
        for chunk in out.chunks_mut(size) {
            cipher
                .encrypt_blocks(&mut block)
                .map_err(|_| Error::Parameter)?;
            chunk.copy_from_slice(block.get(..chunk.len()).ok_or(Error::OutputLength)?);
        }
        if des3 {
            des3_random_to_key(out)?;
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------------------------
// scrypt (RFC 7914)

/// Salsa20/8's core, added back into its input.
fn salsa20_8(b: &mut [u32; 16]) {
    let mut x = *b;
    macro_rules! qr {
        ($a:literal, $b:literal, $c:literal, $d:literal) => {
            x[$b] ^= x[$a].wrapping_add(x[$d]).rotate_left(7);
            x[$c] ^= x[$b].wrapping_add(x[$a]).rotate_left(9);
            x[$d] ^= x[$c].wrapping_add(x[$b]).rotate_left(13);
            x[$a] ^= x[$d].wrapping_add(x[$c]).rotate_left(18);
        };
    }
    for _ in 0..4 {
        qr!(0, 4, 8, 12);
        qr!(5, 9, 13, 1);
        qr!(10, 14, 2, 6);
        qr!(15, 3, 7, 11);
        qr!(0, 1, 2, 3);
        qr!(5, 6, 7, 4);
        qr!(10, 11, 8, 9);
        qr!(15, 12, 13, 14);
    }
    b.iter_mut()
        .zip(x)
        .for_each(|(b, x)| *b = b.wrapping_add(x));
    x.zeroize();
}

/// scrypt's BlockMix over `input` (2r 64-octet blocks as words) into `output`: even blocks
/// first, then odd.
fn block_mix(input: &[u32], output: &mut [u32], r: usize) {
    let mut x = [0u32; 16];
    let last = input.len().saturating_sub(16);
    x.iter_mut()
        .zip(input.get(last..).unwrap_or(&[]))
        .for_each(|(x, &b)| *x = b);
    for (i, block) in input.as_chunks::<16>().0.iter().enumerate() {
        x.iter_mut().zip(block).for_each(|(x, &b)| *x ^= b);
        salsa20_8(&mut x);
        let at = (i / 2)
            .wrapping_add((i % 2).wrapping_mul(r))
            .wrapping_mul(16);
        if let Some(dst) = output.get_mut(at..at.wrapping_add(16)) {
            dst.copy_from_slice(&x);
        }
    }
    x.zeroize();
}

/// A vector of `n` copies of `value`, or `Allocation`.
fn try_filled<T: Clone>(n: usize, value: T) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Allocation)?;
    v.resize(n, value);
    Ok(v)
}

/// scrypt's ROMix on one 128r-octet block of `b`, with `v` holding N blocks.
fn ro_mix(b: &mut [u8], r: usize, n: u64, v: &mut [u32]) -> Result<(), Error> {
    let words = r.checked_mul(32).ok_or(Error::MemoryLimit)?;
    let mut x: Zeroizing<Vec<u32>> = Zeroizing::new(
        b.as_chunks::<4>()
            .0
            .iter()
            .map(|w| u32::from_le_bytes(*w))
            .collect(),
    );
    let mut t = Zeroizing::new(vec![0u32; words]);
    for block in v.chunks_exact_mut(words) {
        block.copy_from_slice(&x);
        block_mix(block, &mut t, r);
        std::mem::swap(&mut *x, &mut *t);
    }
    // The first word of the last 64-octet block.
    let last = words.checked_sub(16).ok_or(Error::Parameter)?;
    for _ in 0..n {
        // Integerify takes the low 32 bits of the last block's first word, as the reference
        // does.
        let j = u64::from(x.get(last).copied().unwrap_or(0))
            .checked_rem(n)
            .unwrap_or(0);
        let at = usize::try_from(j)
            .ok()
            .and_then(|j| j.checked_mul(words))
            .ok_or(Error::Parameter)?;
        let vj = v
            .get(at..at.saturating_add(words))
            .ok_or(Error::Parameter)?;
        t.iter_mut()
            .zip(x.iter().zip(vj))
            .for_each(|(t, (&x, &v))| *t = x ^ v);
        block_mix(&t, &mut x, r);
    }
    for (out, w) in b.as_chunks_mut::<4>().0.iter_mut().zip(x.iter()) {
        out.copy_from_slice(&w.to_le_bytes());
    }
    Ok(())
}

/// scrypt with cost `n`, block size `r`, and parallelism `p`, using at most `max_memory`
/// octets (the reference's checks), with PBKDF2-HMAC-SHA256 at each end.
pub fn scrypt(
    password: &[u8],
    salt: &[u8],
    n: u64,
    r: u64,
    p: u64,
    max_memory: u64,
    out: &mut [u8],
) -> Result<(), Error> {
    crate::dit::with(|| {
        const PR_MAX: u64 = (1 << 30) - 1;
        if r == 0 || p == 0 || n < 2 || !n.is_power_of_two() {
            return Err(Error::Parameter);
        }
        if p > PR_MAX.checked_div(r).unwrap_or(0) {
            return Err(Error::MemoryLimit);
        }
        if let Some(bits) = r.checked_mul(16).filter(|&b| b <= 63)
            && n >= 1u64 << bits
        {
            return Err(Error::MemoryLimit);
        }
        let b_len = p.wrapping_mul(128).wrapping_mul(r);
        if b_len > u64::from(i32::MAX.unsigned_abs()) {
            return Err(Error::MemoryLimit);
        }
        if n.saturating_add(2) > (u64::MAX / 128).checked_div(r).unwrap_or(0) {
            return Err(Error::MemoryLimit);
        }
        let v_len = r.wrapping_mul(128).wrapping_mul(n.wrapping_add(2));
        let total = b_len.checked_add(v_len).ok_or(Error::MemoryLimit)?;
        let max_memory = max_memory.min(u64::try_from(usize::MAX).unwrap_or(u64::MAX));
        if total > max_memory {
            return Err(Error::MemoryLimit);
        }
        let r = usize::try_from(r).map_err(|_| Error::MemoryLimit)?;
        let block = r.checked_mul(128).ok_or(Error::MemoryLimit)?;
        let v_words = usize::try_from(n)
            .ok()
            .and_then(|n| n.checked_mul(r.checked_mul(32)?))
            .ok_or(Error::MemoryLimit)?;
        let mut b = Zeroizing::new(try_filled(
            usize::try_from(b_len).map_err(|_| Error::MemoryLimit)?,
            0u8,
        )?);
        let mut v = Zeroizing::new(try_filled(v_words, 0u32)?);
        pbkdf2(md::Algorithm::Sha256, password, salt, 1, &mut b)?;
        for chunk in b.chunks_exact_mut(block) {
            ro_mix(chunk, r, n, &mut v)?;
        }
        pbkdf2(md::Algorithm::Sha256, password, &b, 1, out)
    })
}

// ---------------------------------------------------------------------------------------------
// Argon2 (RFC 9106)

/// The Argon2 variants, numbered as the algorithm hashes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Argon2Variant {
    /// Argon2d: data-dependent addressing.
    D,
    /// Argon2i: data-independent addressing.
    I,
    /// Argon2id: independent in the first half pass, dependent after.
    Id,
}

impl Argon2Variant {
    const fn number(self) -> u32 {
        match self {
            Self::D => 0,
            Self::I => 1,
            Self::Id => 2,
        }
    }
}

/// Argon2's inputs.
#[derive(Debug, Clone, Copy)]
pub struct Argon2<'a> {
    /// The variant.
    pub variant: Argon2Variant,
    /// 0x10 or 0x13 (the current one).
    pub version: u32,
    /// The number of passes, from 1.
    pub passes: u32,
    /// The memory in 1-KiB blocks, at least 8 per lane.
    pub memory: u32,
    /// The lanes (parallelism), 1 to 2^24 - 1.
    pub lanes: u32,
    /// The password.
    pub password: &'a [u8],
    /// The salt, at least 8 octets.
    pub salt: &'a [u8],
    /// The secret (key), possibly empty.
    pub secret: &'a [u8],
    /// The associated data, possibly empty.
    pub ad: &'a [u8],
}

/// A 1-KiB block of 128 words.
type Block = [u64; 128];

/// The 32-bit length prefix Argon2 hashes before each variable field.
fn le32(n: usize) -> Result<[u8; 4], Error> {
    u32::try_from(n)
        .map(u32::to_le_bytes)
        .map_err(|_| Error::InputLength)
}

/// Unkeyed BLAKE2b of `size` octets (1 to 64) over the concatenated `parts`.
fn blake2b(size: usize, parts: &[&[u8]], out: &mut [u8]) -> Result<(), Error> {
    let mut m = mac::blake2_unkeyed(mac::Blake2Algorithm::Blake2b, size)?;
    for part in parts {
        m.update(part)?;
    }
    Ok(m.finalize(out)?)
}

/// Argon2's variable-length hash H'.
fn blake2b_long(parts: &[&[u8]], out: &mut [u8]) -> Result<(), Error> {
    let length = le32(out.len())?;
    let mut all: Vec<&[u8]> = vec![&length];
    all.extend_from_slice(parts);
    if out.len() <= 64 {
        return blake2b(out.len(), &all, out);
    }
    // V1 = H(LE32(T) || input); 32 octets of each V(i) out while more than 64 remain; the
    // rest is a hash of that size of the last V.
    let mut v = Zeroizing::new([0u8; 64]);
    blake2b(64, &all, &mut *v)?;
    out.get_mut(..32)
        .ok_or(Error::OutputLength)?
        .copy_from_slice(v.get(..32).ok_or(Error::OutputLength)?);
    let mut done = 32usize;
    let mut rest = out.len().wrapping_sub(32);
    while rest > 64 {
        let prev = v.clone();
        blake2b(64, &[&*prev], &mut *v)?;
        out.get_mut(done..done.wrapping_add(32))
            .ok_or(Error::OutputLength)?
            .copy_from_slice(v.get(..32).ok_or(Error::OutputLength)?);
        done = done.wrapping_add(32);
        rest = rest.wrapping_sub(32);
    }
    let prev = v.clone();
    blake2b(
        rest,
        &[&*prev],
        out.get_mut(done..).ok_or(Error::OutputLength)?,
    )
}

/// BlaMka's G on four words of `v`.
macro_rules! g {
    ($v:ident, $a:literal, $b:literal, $c:literal, $d:literal) => {
        $v[$a] = blamka($v[$a], $v[$b]);
        $v[$d] = ($v[$d] ^ $v[$a]).rotate_right(32);
        $v[$c] = blamka($v[$c], $v[$d]);
        $v[$b] = ($v[$b] ^ $v[$c]).rotate_right(24);
        $v[$a] = blamka($v[$a], $v[$b]);
        $v[$d] = ($v[$d] ^ $v[$a]).rotate_right(16);
        $v[$c] = blamka($v[$c], $v[$d]);
        $v[$b] = ($v[$b] ^ $v[$c]).rotate_right(63);
    };
}

/// a + b + 2 * lo(a) * lo(b), modulo 2^64.
fn blamka(a: u64, b: u64) -> u64 {
    let product = (a & 0xffff_ffff).wrapping_mul(b & 0xffff_ffff);
    a.wrapping_add(b).wrapping_add(product.wrapping_mul(2))
}

/// The permutation P on 16 words.
fn permute(v: &mut [u64; 16]) {
    g!(v, 0, 4, 8, 12);
    g!(v, 1, 5, 9, 13);
    g!(v, 2, 6, 10, 14);
    g!(v, 3, 7, 11, 15);
    g!(v, 0, 5, 10, 15);
    g!(v, 1, 6, 11, 12);
    g!(v, 2, 7, 8, 13);
    g!(v, 3, 4, 9, 14);
}

/// P on the 16 words of `block` at `indices`.
fn permute_at(block: &mut Block, indices: impl Iterator<Item = usize> + Clone) {
    let mut v = [0u64; 16];
    v.iter_mut()
        .zip(indices.clone())
        .for_each(|(v, i)| *v = block.get(i).copied().unwrap_or(0));
    permute(&mut v);
    for (i, w) in indices.zip(v) {
        if let Some(slot) = block.get_mut(i) {
            *slot = w;
        }
    }
}

/// The compression G: next = P(prev ^ reference) ^ (prev ^ reference) [^ next].
fn fill_block(prev: &Block, reference: &Block, next: &mut Block, with_xor: bool) {
    let mut r = [0u64; 128];
    r.iter_mut()
        .zip(prev.iter().zip(reference))
        .for_each(|(r, (&p, &q))| *r = p ^ q);
    let mut tmp = r;
    if with_xor {
        tmp.iter_mut().zip(next.iter()).for_each(|(t, &n)| *t ^= n);
    }
    // Rows of 16 consecutive words, then columns of word pairs 16 apart.
    for i in 0..8usize {
        let base = i.wrapping_mul(16);
        permute_at(&mut r, (0..16usize).map(move |k| base.wrapping_add(k)));
    }
    for i in 0..8usize {
        let base = i.wrapping_mul(2);
        permute_at(
            &mut r,
            (0..16usize).map(move |k| {
                base.wrapping_add((k / 2).wrapping_mul(16))
                    .wrapping_add(k % 2)
            }),
        );
    }
    next.iter_mut()
        .zip(tmp.iter().zip(&r))
        .for_each(|(n, (&t, &r))| *n = t ^ r);
    r.zeroize();
    tmp.zeroize();
}

/// The next block of pseudo-random addresses (data-independent addressing).
fn next_addresses(address: &mut Block, input: &mut Block) {
    input[6] = input[6].wrapping_add(1);
    let zero = [0u64; 128];
    fill_block(&zero, input, address, false);
    let copy = *address;
    fill_block(&zero, &copy, address, false);
}

/// The memory's geometry.
struct Geometry {
    lanes: u32,
    passes: u32,
    segment: u32,
    lane_length: u32,
    blocks: u32,
    variant: Argon2Variant,
    version: u32,
}

impl Geometry {
    /// The reference block's position in its lane (RFC 9106 section 3.4.1.2).
    fn index_alpha(&self, pass: u32, slice: u32, index: u32, rand: u32, same_lane: bool) -> u32 {
        let finished = slice.wrapping_mul(self.segment);
        let mut start = 0u32;
        let area = if pass == 0 {
            if slice == 0 {
                index.wrapping_sub(1)
            } else if same_lane {
                finished.wrapping_add(index).wrapping_sub(1)
            } else {
                finished.wrapping_add(if index == 0 { u32::MAX } else { 0 })
            }
        } else {
            if slice != 3 {
                start = slice.wrapping_add(1).wrapping_mul(self.segment);
            }
            let others = self.lane_length.wrapping_sub(self.segment);
            if same_lane {
                others.wrapping_add(index).wrapping_sub(1)
            } else {
                others.wrapping_add(if index == 0 { u32::MAX } else { 0 })
            }
        };
        let x = u64::from(rand);
        let x = x.wrapping_mul(x) >> 32;
        let area = u64::from(area);
        let relative = area
            .wrapping_sub(1)
            .wrapping_sub(area.wrapping_mul(x) >> 32);
        let absolute = u64::from(start)
            .wrapping_add(relative)
            .checked_rem(u64::from(self.lane_length))
            .unwrap_or(0);
        u32::try_from(absolute).unwrap_or(0)
    }

    fn independent(&self, pass: u32, slice: u32) -> bool {
        match self.variant {
            Argon2Variant::I => true,
            Argon2Variant::Id => pass == 0 && slice < 2,
            Argon2Variant::D => false,
        }
    }

    fn fill_segment(&self, memory: &mut [Block], pass: u32, lane: u32, slice: u32) {
        let independent = self.independent(pass, slice);
        let mut input = [0u64; 128];
        let mut address = [0u64; 128];
        if independent {
            input[0] = u64::from(pass);
            input[1] = u64::from(lane);
            input[2] = u64::from(slice);
            input[3] = u64::from(self.blocks);
            input[4] = u64::from(self.passes);
            input[5] = u64::from(self.variant.number());
        }
        let mut start = 0u32;
        if pass == 0 && slice == 0 {
            start = 2;
            if independent {
                next_addresses(&mut address, &mut input);
            }
        }
        let mut current = lane
            .wrapping_mul(self.lane_length)
            .wrapping_add(slice.wrapping_mul(self.segment))
            .wrapping_add(start);
        let mut previous = if current.checked_rem(self.lane_length) == Some(0) {
            current.wrapping_add(self.lane_length).wrapping_sub(1)
        } else {
            current.wrapping_sub(1)
        };
        let at = |i: u32| usize::try_from(i).unwrap_or(usize::MAX);
        for j in start..self.segment {
            if current.checked_rem(self.lane_length) == Some(1) {
                previous = current.wrapping_sub(1);
            }
            let rand = if independent {
                if j % 128 == 0 {
                    next_addresses(&mut address, &mut input);
                }
                address.get(at(j % 128)).copied().unwrap_or(0)
            } else {
                memory
                    .get(at(previous))
                    .map_or(0, |b| b.first().copied().unwrap_or(0))
            };
            let mut ref_lane =
                u32::try_from((rand >> 32).checked_rem(u64::from(self.lanes)).unwrap_or(0))
                    .unwrap_or(0);
            if pass == 0 && slice == 0 {
                ref_lane = lane;
            }
            let ref_index = self.index_alpha(
                pass,
                slice,
                j,
                u32::try_from(rand & 0xffff_ffff).unwrap_or(0),
                ref_lane == lane,
            );
            let reference = ref_lane
                .wrapping_mul(self.lane_length)
                .wrapping_add(ref_index);
            let prev_block = memory.get(at(previous)).copied().unwrap_or([0; 128]);
            let ref_block = memory.get(at(reference)).copied().unwrap_or([0; 128]);
            let with_xor = self.version != 0x10 && pass != 0;
            if let Some(next) = memory.get_mut(at(current)) {
                fill_block(&prev_block, &ref_block, next, with_xor);
            }
            current = current.wrapping_add(1);
            previous = previous.wrapping_add(1);
        }
        input.zeroize();
        address.zeroize();
    }
}

/// Argon2 into `out` (4 octets or more).
pub fn argon2(params: &Argon2<'_>, out: &mut [u8]) -> Result<(), Error> {
    crate::dit::with(|| {
        if !matches!(params.version, 0x10 | 0x13)
            || params.passes == 0
            || !(1..=0xff_ffff).contains(&params.lanes)
            || params.memory < params.lanes.wrapping_mul(8)
        {
            return Err(Error::Parameter);
        }
        let out_len = u32::try_from(out.len()).map_err(|_| Error::OutputLength)?;
        if out_len < 4 {
            return Err(Error::OutputLength);
        }
        if params.salt.len() < 8 {
            return Err(Error::InputLength);
        }
        let lanes = params.lanes;
        let segment = params
            .memory
            .checked_div(lanes.wrapping_mul(4))
            .unwrap_or(0);
        let geometry = Geometry {
            lanes,
            passes: params.passes,
            segment,
            lane_length: segment.wrapping_mul(4),
            blocks: segment.wrapping_mul(lanes).wrapping_mul(4),
            variant: params.variant,
            version: params.version,
        };
        let mut memory: Zeroizing<Vec<Block>> = Zeroizing::new(try_filled(
            usize::try_from(geometry.blocks).map_err(|_| Error::Allocation)?,
            [0u64; 128],
        )?);

        // H0, then the first two blocks of each lane.
        let mut seed = Zeroizing::new([0u8; 72]);
        let fields = [
            lanes,
            out_len,
            params.memory,
            params.passes,
            params.version,
            params.variant.number(),
        ]
        .map(u32::to_le_bytes);
        let mut parts: Vec<&[u8]> = fields.iter().map(|f| &f[..]).collect();
        let lengths = [
            le32(params.password.len())?,
            le32(params.salt.len())?,
            le32(params.secret.len())?,
            le32(params.ad.len())?,
        ];
        let [pl, sl, kl, al] = &lengths;
        parts.extend_from_slice(&[
            pl,
            params.password,
            sl,
            params.salt,
            kl,
            params.secret,
            al,
            params.ad,
        ]);
        {
            let (h0, _) = seed.split_at_mut(64);
            let mut m = md::context(md::Algorithm::Blake2b512);
            for part in &parts {
                m.update(part).map_err(|_| Error::Digest)?;
            }
            m.finalize(h0).map_err(|_| Error::Digest)?;
        }
        let mut bytes = Zeroizing::new([0u8; 1024]);
        for lane in 0..lanes {
            for first in 0..2u32 {
                let (_, tail) = seed.split_at_mut(64);
                let (a, b) = tail.split_at_mut(4);
                a.copy_from_slice(&first.to_le_bytes());
                b.copy_from_slice(&lane.to_le_bytes());
                blake2b_long(&[&*seed], &mut *bytes)?;
                let index = lane.wrapping_mul(geometry.lane_length).wrapping_add(first);
                let block = memory
                    .get_mut(usize::try_from(index).map_err(|_| Error::Allocation)?)
                    .ok_or(Error::Allocation)?;
                for (w, chunk) in block.iter_mut().zip(bytes.as_chunks::<8>().0) {
                    *w = u64::from_le_bytes(*chunk);
                }
            }
        }

        for pass in 0..params.passes {
            for slice in 0..4 {
                for lane in 0..lanes {
                    geometry.fill_segment(&mut memory, pass, lane, slice);
                }
            }
        }

        // The XOR of each lane's last block, hashed to the output.
        let mut last = [0u64; 128];
        for lane in 0..lanes {
            let index = lane
                .wrapping_mul(geometry.lane_length)
                .wrapping_add(geometry.lane_length.wrapping_sub(1));
            if let Some(block) = memory.get(usize::try_from(index).unwrap_or(usize::MAX)) {
                last.iter_mut().zip(block).for_each(|(l, &b)| *l ^= b);
            }
        }
        for (chunk, w) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(last) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
        last.zeroize();
        blake2b_long(&[&*bytes], out)
    })
}
