//! The paddings (`rsa_pk1.c`, `rsa_oaep.c`, `rsa_pss.c`, `rsa_x931.c`, `rsa_none.c`), each as
//! OpenSSL lays it out and checks it, its errors in the same order. `to` is the caller's
//! output buffer: an `add` fills all of it, a check writes what it found (and, in constant
//! time, nothing where decryption's checks failed).
//!
//! Lengths are checked before every offset taken from them; the arithmetic that follows a
//! check says so (`saturating`, or `wrapping` where the C's unsigned arithmetic is meant).

use rustyssl_abi::{NID_sha1, NID_sha256, NID_sha384, NID_sha512};

use super::ct::{bit_u8, eq_u8, eq_usize, ge_usize, lt_usize, select_u8, select_usize};
use super::{Entry, Hash, Outcome, PKCS1_PADDING_SIZE, Raised, Random, Reason, fail, silent};

/// The ok result of an `add`.
fn added() -> Outcome<()> {
    (Ok(()), Vec::new())
}

/// A length or -1, as the C's `int` results (a length always fits).
fn signed(len: usize) -> isize {
    isize::try_from(len).unwrap_or(-1)
}

/// `good ? len : -1`, chosen in constant time.
fn len_or_minus_one(good: usize, len: usize) -> isize {
    // All ones is -1 as a two's complement isize.
    let r = select_usize(good, len, usize::MAX);
    isize::from_ne_bytes(r.to_ne_bytes())
}

/// HMAC over `h` (RFC 2104): the key hashed when longer than a block.
pub(crate) fn hmac(h: &dyn Hash, key: &[u8], parts: &[&[u8]]) -> Option<Vec<u8>> {
    let block = h.block_size();
    let mut k = if key.len() > block {
        h.digest(&[key])?
    } else {
        key.to_vec()
    };
    k.resize(block, 0);
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner_parts: Vec<&[u8]> = vec![&ipad];
    inner_parts.extend_from_slice(parts);
    let inner = h.digest(&inner_parts)?;
    h.digest(&[&opad, &inner])
}

/// `ossl_rsa_prf`: `tlen` octets of `HMAC-SHA256(kdk, BE16(i) || label || BE16(bitlen))` for
/// i = 0, 1, ...; `None` unless `tlen * 8 == bitlen` (a 16-bit number) and HMAC works.
pub fn prf(
    sha256: &dyn Hash,
    kdk: &[u8],
    label: &[u8],
    tlen: usize,
    bitlen: usize,
) -> Option<Vec<u8>> {
    let bits = u16::try_from(bitlen).ok()?;
    if tlen.checked_mul(8)? != bitlen {
        return None;
    }
    let mut out = Vec::with_capacity(tlen);
    let mut i: u16 = 0;
    while out.len() < tlen {
        let t = hmac(sha256, kdk, &[&i.to_be_bytes(), label, &bits.to_be_bytes()])?;
        out.extend_from_slice(&t);
        i = i.wrapping_add(1);
    }
    out.truncate(tlen);
    Some(out)
}

/// `PKCS1_MGF1`: `len` octets of `Hash(seed || BE32(i))` for i = 0, 1, ...
pub fn mgf1(len: usize, seed: &[u8], h: &dyn Hash) -> Option<Vec<u8>> {
    if h.size() == 0 {
        return None;
    }
    let mut out = Vec::with_capacity(len);
    let mut i: u32 = 0;
    while out.len() < len {
        out.extend_from_slice(&h.digest(&[seed, &i.to_be_bytes()])?);
        i = i.wrapping_add(1);
    }
    out.truncate(len);
    Some(out)
}

/// The padding area of a PKCS #1 v1.5 block: `to` split into its header (`00 0x PS 00`) and
/// the data's place, or `None` if `from` doesn't leave the 11 octets of padding.
fn pkcs1_split<'a>(to: &'a mut [u8], from: &[u8]) -> Option<(&'a mut [u8], &'a mut [u8])> {
    let room = to.len().checked_sub(PKCS1_PADDING_SIZE)?;
    if from.len() > room {
        return None;
    }
    let at = to.len().checked_sub(from.len())?;
    Some(to.split_at_mut(at))
}

/// `RSA_padding_add_PKCS1_type_1`: `00 01 FF.. 00 || from`.
pub fn add_pkcs1_type1(to: &mut [u8], from: &[u8]) -> Outcome<()> {
    const F: &str = "RSA_padding_add_PKCS1_type_1";
    let Some((head, data)) = pkcs1_split(to, from) else {
        return fail(F, Reason::DataTooLargeForKeySize);
    };
    head.fill(0xff);
    if let [first, second, ..] = head {
        *first = 0;
        *second = 1;
    }
    if let Some(sep) = head.last_mut() {
        *sep = 0;
    }
    data.copy_from_slice(from);
    added()
}

/// `RSA_padding_check_PKCS1_type_1` (public data, not constant time): the payload of
/// `from` (the leading zero optional) into `to`.
pub fn check_pkcs1_type1(to: &mut [u8], from: &[u8], num: usize) -> Outcome<usize> {
    const F: &str = "RSA_padding_check_PKCS1_type_1";
    if num < PKCS1_PADDING_SIZE {
        return silent();
    }
    let mut p = from;
    if num == from.len() {
        match p.split_first() {
            Some((0, rest)) => p = rest,
            _ => return fail(F, Reason::InvalidPadding),
        }
    }
    // The block type follows; `num` must be the octets after the leading zero, plus one.
    let body = match p.split_first() {
        Some((1, rest)) if num.checked_sub(1) == Some(p.len()) => rest,
        _ => return fail(F, Reason::BlockTypeIsNot01),
    };
    // The 0xFF octets, then a zero.
    let Some(ffs) = body.iter().position(|&b| b != 0xff) else {
        return fail(F, Reason::NullBeforeBlockMissing);
    };
    if body.get(ffs) != Some(&0) {
        return fail(F, Reason::BadFixedHeaderDecrypt);
    }
    if ffs < 8 {
        return fail(F, Reason::BadPadByteCount);
    }
    let data = body.get(ffs.saturating_add(1)..).unwrap_or_default();
    if data.len() > to.len() {
        return fail(F, Reason::DataTooLarge);
    }
    if let Some(t) = to.get_mut(..data.len()) {
        t.copy_from_slice(data);
    }
    (Ok(data.len()), Vec::new())
}

/// `ossl_rsa_padding_add_PKCS1_type_2_ex`: `00 02 PS 00 || from`, PS random and nonzero.
pub fn add_pkcs1_type2(to: &mut [u8], from: &[u8], rng: &mut Random<'_>) -> Outcome<()> {
    const F: &str = "ossl_rsa_padding_add_PKCS1_type_2_ex";
    let Some((head, data)) = pkcs1_split(to, from) else {
        return fail(F, Reason::DataTooLargeForKeySize);
    };
    let [first, second, ps @ .., sep] = head else {
        return silent();
    };
    *first = 0;
    *second = 2;
    *sep = 0;
    if !rng(ps) {
        return silent();
    }
    for b in ps.iter_mut() {
        while *b == 0 {
            let mut one = [0u8];
            if !rng(&mut one) {
                return silent();
            }
            let [x] = one;
            *b = x;
        }
    }
    data.copy_from_slice(from);
    added()
}

/// `from` right-aligned in `num` octets (it holds at most `num`).
fn left_padded(from: &[u8], num: usize) -> Vec<u8> {
    let mut em = vec![0u8; num];
    if let Some(t) = em.get_mut(num.saturating_sub(from.len())..) {
        t.copy_from_slice(from.get(..t.len()).unwrap_or(from));
    }
    em
}

/// Shifts `buf[start..]` left by `shift` in constant time, a power of two at a time up to
/// `span`, as OpenSSL's decoders do (`shift` comes from secret data; the loops don't).
fn barrel_shift(buf: &mut [u8], start: usize, span: usize, shift: usize) {
    let n = buf.len();
    let mut step: usize = 1;
    while step < span {
        let m = bit_u8(1 ^ eq_usize(step & shift, 0));
        for i in start..n.saturating_sub(step) {
            let src = buf.get(i.saturating_add(step)).copied().unwrap_or(0);
            if let Some(b) = buf.get_mut(i) {
                *b = select_u8(m, src, *b);
            }
        }
        step = step.saturating_mul(2);
    }
}

/// The index of the first zero octet of `em` from index 2, or 0 if none, in constant time.
fn first_zero_from_2(em: &[u8]) -> usize {
    let mut found = 0usize;
    let mut zero_index = 0usize;
    for (i, &b) in em.iter().enumerate().skip(2) {
        let is0 = usize::from(eq_u8(b, 0));
        zero_index = select_usize(!found & is0 & 1, i, zero_index);
        found |= is0;
    }
    zero_index
}

/// `RSA_padding_check_PKCS1_type_2` in constant time: the message length or -1, and the
/// decoding error raised then cleared unless the padding was bad.
pub fn check_pkcs1_type2(to: &mut [u8], from: &[u8], num: usize) -> (isize, Raised) {
    crate::dit::with(|| check_pkcs1_type2_dit(to, from, num))
}

/// [`check_pkcs1_type2`]'s work.
fn check_pkcs1_type2_dit(to: &mut [u8], from: &[u8], num: usize) -> (isize, Raised) {
    const F: &str = "RSA_padding_check_PKCS1_type_2";
    let tlen = to.len();
    if tlen == 0 || from.is_empty() {
        return (-1, Vec::new());
    }
    let Some(span) = num.checked_sub(PKCS1_PADDING_SIZE) else {
        return (-1, vec![Entry::raised(F, Reason::PkcsDecodingError)]);
    };
    if from.len() > num {
        return (-1, vec![Entry::raised(F, Reason::PkcsDecodingError)]);
    }
    let mut em = left_padded(from, num);
    let byte = |e: &[u8], i: usize| e.get(i).copied().unwrap_or(0);
    let mut good = usize::from(eq_u8(byte(&em, 0), 0) & eq_u8(byte(&em, 1), 2));
    let zero_index = first_zero_from_2(&em);
    good &= ge_usize(zero_index, 2 + 8);
    // As the C's ints: garbage when the padding is bad, and then never used.
    let mlen = num.wrapping_sub(zero_index).wrapping_sub(1);
    good &= ge_usize(tlen, mlen);
    let tl = select_usize(lt_usize(span, tlen), span, tlen);
    barrel_shift(&mut em, PKCS1_PADDING_SIZE, span, span.wrapping_sub(mlen));
    let gm = bit_u8(good);
    for (i, t) in to.iter_mut().enumerate().take(tl) {
        let m = gm & bit_u8(lt_usize(i, mlen));
        *t = select_u8(m, byte(&em, i.saturating_add(PKCS1_PADDING_SIZE)), *t);
    }
    (
        len_or_minus_one(good, mlen),
        vec![Entry {
            func: F,
            reason: Reason::PkcsDecodingError,
            clear: gm,
        }],
    )
}

/// `ossl_rsa_padding_check_PKCS1_type_2` with implicit rejection: the message, or one
/// derived from `kdk` and the ciphertext when the padding is bad, so it never fails on bad
/// padding. `from` is the whole decryption (`num` octets).
pub fn check_pkcs1_type2_implicit(
    to: &mut [u8],
    from: &[u8],
    num: usize,
    kdk: &[u8],
    sha256: &dyn Hash,
) -> (isize, Raised) {
    crate::dit::with(|| check_pkcs1_type2_implicit_dit(to, from, num, kdk, sha256))
}

/// [`check_pkcs1_type2_implicit`]'s work.
fn check_pkcs1_type2_implicit_dit(
    to: &mut [u8],
    from: &[u8],
    num: usize,
    kdk: &[u8],
    sha256: &dyn Hash,
) -> (isize, Raised) {
    const F: &str = "ossl_rsa_padding_check_PKCS1_type_2";
    const TRIES: usize = 128;
    let internal = || {
        (
            -1,
            vec![
                Entry::raised("ossl_rsa_prf", Reason::Internal),
                Entry::raised(F, Reason::Internal),
            ],
        )
    };
    let (tlen, flen) = (to.len(), from.len());
    if num != flen || tlen == 0 || flen == 0 {
        return (-1, vec![Entry::raised(F, Reason::Internal)]);
    }
    let Some(synthetic) = prf(sha256, kdk, b"message", flen, flen.saturating_mul(8)) else {
        return internal();
    };
    let Some(candidates) = prf(sha256, kdk, b"length", TRIES * 2, TRIES * 16) else {
        return internal();
    };
    // `flen - 10` as the C's uint16_t.
    let max_sep_offset = flen.wrapping_sub(10) & 0xffff;
    let mut len_mask = max_sep_offset;
    len_mask |= len_mask >> 1;
    len_mask |= len_mask >> 2;
    len_mask |= len_mask >> 4;
    len_mask |= len_mask >> 8;
    let mut synthetic_length = 0usize;
    for &[hi, lo] in candidates.as_chunks::<2>().0 {
        let c = (usize::from(hi) << 8 | usize::from(lo)) & len_mask;
        synthetic_length = select_usize(lt_usize(c, max_sep_offset), c, synthetic_length);
    }
    let synth_msg_index = flen.wrapping_sub(synthetic_length);
    let byte = |i: usize| from.get(i).copied().unwrap_or(0);
    let mut good = usize::from(eq_u8(byte(0), 0) & eq_u8(byte(1), 2));
    let zero_index = first_zero_from_2(from);
    good &= ge_usize(zero_index, 10);
    let msg_index = zero_index.wrapping_add(1);
    good &= ge_usize(tlen, num.wrapping_sub(msg_index));
    let msg_index = select_usize(good, msg_index, synth_msg_index);
    // The real or synthetic message, selected octet by octet, shifted to the start; then as
    // many octets as the C's loop copies (`flen - msg_index`, at most `tlen`).
    let gm = bit_u8(good);
    let mut src: Vec<u8> = from
        .iter()
        .zip(&synthetic)
        .map(|(&f, &s)| select_u8(gm, f, s))
        .collect();
    barrel_shift(&mut src, 0, flen, msg_index);
    let count = flen.wrapping_sub(msg_index);
    let count = select_usize(lt_usize(tlen, count), tlen, count);
    for (k, t) in to.iter_mut().enumerate() {
        let m = bit_u8(lt_usize(k, count));
        *t = select_u8(m, src.get(k).copied().unwrap_or(0), *t);
    }
    (signed(count), Vec::new())
}

/// `ossl_rsa_padding_check_PKCS1_type_2_TLS`: the 48-octet premaster secret, or random
/// octets in its place when the padding or the version is wrong; always 48.
pub fn check_pkcs1_type2_tls(
    to: &mut [u8],
    from: &[u8],
    client_version: i32,
    alt_version: i32,
    rng: &mut Random<'_>,
) -> Outcome<usize> {
    crate::dit::with(|| check_pkcs1_type2_tls_dit(to, from, client_version, alt_version, rng))
}

/// [`check_pkcs1_type2_tls`]'s work.
fn check_pkcs1_type2_tls_dit(
    to: &mut [u8],
    from: &[u8],
    client_version: i32,
    alt_version: i32,
    rng: &mut Random<'_>,
) -> Outcome<usize> {
    const F: &str = "ossl_rsa_padding_check_PKCS1_type_2_TLS";
    const PMS: usize = 48;
    let flen = from.len();
    if flen < PKCS1_PADDING_SIZE + PMS || to.len() < PMS {
        return fail(F, Reason::PkcsDecodingError);
    }
    let mut rand_pms = [0u8; PMS];
    if !rng(&mut rand_pms) {
        return fail(F, Reason::Internal);
    }
    // flen >= 59: the separator and the secret's place.
    let sep = flen.saturating_sub(PMS + 1);
    let pms_at = flen.saturating_sub(PMS);
    let byte = |i: usize| from.get(i).copied().unwrap_or(0);
    let mut good = eq_u8(byte(0), 0) & eq_u8(byte(1), 2);
    for i in 2..sep {
        good &= 1 ^ eq_u8(byte(i), 0);
    }
    good &= eq_u8(byte(sep), 0);
    let ver = |v: i32| {
        let [_, _, hi, lo] = v.to_be_bytes();
        eq_u8(byte(pms_at), hi) & eq_u8(byte(pms_at.saturating_add(1)), lo)
    };
    let mut version_good = ver(client_version);
    if alt_version > 0 {
        version_good |= ver(alt_version);
    }
    good &= version_good;
    for ((t, &r), i) in to.iter_mut().zip(&rand_pms).zip(pms_at..) {
        *t = select_u8(good, byte(i), r);
    }
    (Ok(PMS), Vec::new())
}

/// `ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex`: `00 || maskedSeed || maskedDB`.
pub fn add_oaep(
    to: &mut [u8],
    from: &[u8],
    label: &[u8],
    md: &dyn Hash,
    mgf1md: &dyn Hash,
    rng: &mut Random<'_>,
) -> Outcome<()> {
    const F: &str = "ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex";
    let mdlen = md.size();
    if mdlen == 0 {
        return fail(F, Reason::InvalidLength);
    }
    // `emlen = tlen - 1`; the room is `emlen - 2 mdlen - 1`, negative for a small key.
    let room = to
        .len()
        .checked_sub(1)
        .and_then(|e| e.checked_sub(mdlen.saturating_mul(2).saturating_add(1)));
    // A key too small for the digest fails this first test too (the C's bound is negative),
    // so its KEY_SIZE_TOO_SMALL never shows.
    if room.is_none_or(|r| from.len() > r) {
        return fail(F, Reason::DataTooLargeForKeySize);
    }
    let Some(lhash) = md.digest(&[label]) else {
        return silent();
    };
    let Some((_, rest)) = to.split_first_mut() else {
        return silent();
    };
    let (masked_seed, masked_db) = rest.split_at_mut(mdlen);
    let dblen = masked_db.len();
    let mut db = vec![0u8; dblen];
    if let Some(h) = db.get_mut(..mdlen) {
        h.copy_from_slice(lhash.get(..mdlen).unwrap_or(&lhash));
    }
    // The room check leaves at least one octet for the 01 separator.
    let one_at = dblen.saturating_sub(from.len()).saturating_sub(1);
    if let Some(b) = db.get_mut(one_at) {
        *b = 1;
    }
    if let Some(t) = db.get_mut(one_at.saturating_add(1)..) {
        t.copy_from_slice(from);
    }
    let mut seed = vec![0u8; mdlen];
    if !rng(&mut seed) {
        return silent();
    }
    let Some(db_mask) = mgf1(dblen, &seed, mgf1md) else {
        return silent();
    };
    for ((m, d), k) in masked_db.iter_mut().zip(&db).zip(&db_mask) {
        *m = d ^ k;
    }
    let Some(seed_mask) = mgf1(mdlen, masked_db, mgf1md) else {
        return silent();
    };
    for ((m, s), k) in masked_seed.iter_mut().zip(&seed).zip(&seed_mask) {
        *m = s ^ k;
    }
    if let Some(b) = to.first_mut() {
        *b = 0;
    }
    added()
}

/// `RSA_padding_check_PKCS1_OAEP_mgf1` in constant time: the message length or -1, and the
/// decoding error raised then cleared unless the encoding was bad.
pub fn check_oaep(
    to: &mut [u8],
    from: &[u8],
    num: usize,
    label: &[u8],
    md: &dyn Hash,
    mgf1md: &dyn Hash,
) -> (isize, Raised) {
    crate::dit::with(|| check_oaep_dit(to, from, num, label, md, mgf1md))
}

/// [`check_oaep`]'s work.
fn check_oaep_dit(
    to: &mut [u8],
    from: &[u8],
    num: usize,
    label: &[u8],
    md: &dyn Hash,
    mgf1md: &dyn Hash,
) -> (isize, Raised) {
    const F: &str = "RSA_padding_check_PKCS1_OAEP_mgf1";
    let (tlen, flen, mdlen) = (to.len(), from.len(), md.size());
    if tlen == 0 || flen == 0 || mdlen == 0 {
        return (-1, Vec::new());
    }
    if num < flen || num < mdlen.saturating_mul(2).saturating_add(2) {
        return (-1, vec![Entry::raised(F, Reason::OaepDecodingError)]);
    }
    // num >= 2 mdlen + 2: the DB and the message's room are positive.
    let dblen = num.saturating_sub(mdlen).saturating_sub(1);
    let em = left_padded(from, num);
    let mut good = usize::from(eq_u8(em.first().copied().unwrap_or(1), 0));
    let (masked_seed, masked_db) = em.get(1..).unwrap_or_default().split_at(mdlen);
    let Some(seed_mask) = mgf1(mdlen, masked_db, mgf1md) else {
        return (-1, Vec::new());
    };
    let seed: Vec<u8> = seed_mask
        .iter()
        .zip(masked_seed)
        .map(|(a, b)| a ^ b)
        .collect();
    let Some(db_mask) = mgf1(dblen, &seed, mgf1md) else {
        return (-1, Vec::new());
    };
    let mut db: Vec<u8> = db_mask.iter().zip(masked_db).map(|(a, b)| a ^ b).collect();
    let Some(phash) = md.digest(&[label]) else {
        return (-1, Vec::new());
    };
    let mut diff = 0u8;
    for (a, b) in db.iter().zip(&phash).take(mdlen) {
        diff |= a ^ b;
    }
    good &= usize::from(eq_u8(diff, 0));
    let mut found = 0usize;
    let mut one_index = 0usize;
    for (i, &b) in db.iter().enumerate().skip(mdlen) {
        let is1 = usize::from(eq_u8(b, 1));
        let is0 = usize::from(eq_u8(b, 0));
        one_index = select_usize(!found & is1 & 1, i, one_index);
        found |= is1;
        good &= found | is0;
    }
    good &= found;
    let mlen = dblen.wrapping_sub(one_index.wrapping_add(1));
    good &= ge_usize(tlen, mlen);
    let start = mdlen.saturating_add(1);
    let span = dblen.saturating_sub(start);
    let tl = select_usize(lt_usize(span, tlen), span, tlen);
    barrel_shift(&mut db, start, span, span.wrapping_sub(mlen));
    let gm = bit_u8(good);
    for (i, t) in to.iter_mut().enumerate().take(tl) {
        let m = gm & bit_u8(lt_usize(i, mlen));
        *t = select_u8(m, db.get(i.saturating_add(start)).copied().unwrap_or(0), *t);
    }
    (
        len_or_minus_one(good, mlen),
        vec![Entry {
            func: F,
            reason: Reason::OaepDecodingError,
            clear: gm,
        }],
    )
}

/// `RSA_padding_add_none`: `from` exactly the size of `to`.
pub fn add_none(to: &mut [u8], from: &[u8]) -> Outcome<()> {
    const F: &str = "RSA_padding_add_none";
    if from.len() > to.len() {
        return fail(F, Reason::DataTooLargeForKeySize);
    }
    if from.len() < to.len() {
        return fail(F, Reason::DataTooSmallForKeySize);
    }
    to.copy_from_slice(from);
    added()
}

/// `RSA_padding_check_none`: `from` right-aligned in `to`.
pub fn check_none(to: &mut [u8], from: &[u8]) -> Outcome<usize> {
    const F: &str = "RSA_padding_check_none";
    let tlen = to.len();
    let Some(at) = tlen.checked_sub(from.len()) else {
        return fail(F, Reason::DataTooLarge);
    };
    let (zeros, data) = to.split_at_mut(at);
    zeros.fill(0);
    data.copy_from_slice(from);
    (Ok(tlen), Vec::new())
}

/// `RSA_padding_add_X931`: `6A || from || CC`, or `6B BB.. BA || from || CC`.
pub fn add_x931(to: &mut [u8], from: &[u8]) -> Outcome<()> {
    const F: &str = "RSA_padding_add_X931";
    let Some(j) = to
        .len()
        .checked_sub(from.len())
        .and_then(|x| x.checked_sub(2))
    else {
        return fail(F, Reason::DataTooLargeForKeySize);
    };
    // Header and padding (j + 1 octets), the data, the trailer.
    let (head, rest) = to.split_at_mut(j.saturating_add(1));
    match head {
        [only] => *only = 0x6a,
        [first, mid @ .., last] => {
            *first = 0x6b;
            mid.fill(0xbb);
            *last = 0xba;
        }
        [] => return silent(),
    }
    let Some((trailer, data)) = rest.split_last_mut() else {
        return silent();
    };
    data.copy_from_slice(from);
    *trailer = 0xcc;
    added()
}

/// `RSA_padding_check_X931`: the hash and its identifier octet.
pub fn check_x931(to: &mut [u8], from: &[u8], num: usize) -> Outcome<usize> {
    const F: &str = "RSA_padding_check_X931";
    let flen = from.len();
    let first = from.first().copied();
    if num != flen || !matches!(first, Some(0x6a | 0x6b)) {
        return fail(F, Reason::InvalidHeader);
    }
    let p = from.get(1..).unwrap_or_default();
    let (start, j) = if first == Some(0x6b) {
        let limit = flen.saturating_sub(3);
        let mut i: usize = 0;
        let mut found = false;
        while i < limit {
            match p.get(i) {
                Some(0xba) => {
                    found = true;
                    break;
                }
                Some(0xbb) => i = i.saturating_add(1),
                _ => return fail(F, Reason::InvalidPadding),
            }
        }
        if i == 0 {
            return fail(F, Reason::InvalidPadding);
        }
        // Past the BA when one was found; as OpenSSL, past the BBs (and no data) otherwise.
        (
            i.saturating_add(usize::from(found)),
            limit.saturating_sub(i),
        )
    } else {
        (0, flen.saturating_sub(2))
    };
    if p.get(start.saturating_add(j)) != Some(&0xcc) {
        return fail(F, Reason::InvalidTrailer);
    }
    let data = p.get(start..start.saturating_add(j)).unwrap_or_default();
    if let Some(t) = to.get_mut(..data.len()) {
        t.copy_from_slice(data);
    }
    (Ok(j), Vec::new())
}

/// `RSA_X931_hash_id`.
pub fn x931_hash_id(nid: i32) -> i32 {
    [
        (NID_sha1, 0x33),
        (NID_sha256, 0x34),
        (NID_sha384, 0x36),
        (NID_sha512, 0x35),
    ]
    .iter()
    .find(|(n, _)| *n == nid)
    .map_or(-1, |&(_, id)| id)
}

/// PSS salt lengths' special values (`RSA_PSS_SALTLEN_*`).
pub struct PssSaltLen;

impl PssSaltLen {
    pub const DIGEST: i32 = -1;
    pub const AUTO: i32 = -2;
    pub const MAX: i32 = -3;
    pub const AUTO_DIGEST_MAX: i32 = -4;
}

/// The PSS encoding's octets after the forced leading zero (`emLen`), and the most salt it
/// takes for a digest of `hlen` octets, or `None` when `emLen < hLen + 2`.
fn pss_room(em_len: usize, hlen: usize) -> Option<usize> {
    em_len.checked_sub(hlen)?.checked_sub(2)
}

/// `ossl_rsa_padding_add_PKCS1_PSS_mgf1`: `mhash` encoded into `em` (the key's size) for a
/// key of `bits` bits. Returns the salt length used.
pub fn add_pss(
    em: &mut [u8],
    bits: usize,
    mhash: &[u8],
    md: &dyn Hash,
    mgf1md: &dyn Hash,
    slen: i32,
    rng: &mut Random<'_>,
) -> Outcome<i32> {
    const F: &str = "ossl_rsa_padding_add_PKCS1_PSS_mgf1";
    let hlen = md.size();
    if hlen == 0 {
        return silent();
    }
    if slen < PssSaltLen::AUTO_DIGEST_MAX {
        return fail(F, Reason::SlenCheckFailed(None));
    }
    let msbits = bits.wrapping_sub(1) & 7;
    let mut out: &mut [u8] = em;
    if msbits == 0 {
        let Some((first, rest)) = out.split_first_mut() else {
            return silent();
        };
        *first = 0;
        out = rest;
    }
    let Some(max_salt) = pss_room(out.len(), hlen) else {
        return fail(F, Reason::DataTooLargeForKeySize);
    };
    let salt_len = match slen {
        PssSaltLen::DIGEST => hlen,
        PssSaltLen::AUTO | PssSaltLen::MAX => max_salt,
        PssSaltLen::AUTO_DIGEST_MAX => max_salt.min(hlen),
        n => usize::try_from(n).unwrap_or(0),
    };
    if salt_len > max_salt {
        return fail(F, Reason::DataTooLargeForKeySize);
    }
    let mut salt = vec![0u8; salt_len];
    if salt_len > 0 && !rng(&mut salt) {
        return silent();
    }
    // emLen - hLen - 1 octets of masked DB, then H, then BC.
    let masked_len = max_salt.saturating_add(1);
    let m = mhash.get(..hlen.min(mhash.len())).unwrap_or_default();
    let Some(h) = md.digest(&[&[0u8; 8], m, &salt]) else {
        return silent();
    };
    let Some(mask) = mgf1(masked_len, &h, mgf1md) else {
        return silent();
    };
    let (db, tail) = out.split_at_mut(masked_len);
    db.copy_from_slice(&mask);
    // DB = 00.. 01 || salt: the 01 sits `salt_len + 1` octets from DB's end.
    let one_at = masked_len.saturating_sub(salt_len).saturating_sub(1);
    if let Some(b) = db.get_mut(one_at) {
        *b ^= 1;
    }
    for (b, s) in db.iter_mut().skip(one_at.saturating_add(1)).zip(&salt) {
        *b ^= s;
    }
    if msbits != 0
        && let Some(b) = db.first_mut()
    {
        *b &= 0xff >> (8_usize.saturating_sub(msbits));
    }
    let Some((bc, hh)) = tail.split_last_mut() else {
        return silent();
    };
    hh.copy_from_slice(h.get(..hlen).unwrap_or(&h));
    *bc = 0xbc;
    (Ok(i32::try_from(salt_len).unwrap_or(0)), Vec::new())
}

/// `ossl_rsa_verify_PKCS1_PSS_mgf1`: whether `em` (the key's size, `bits` bits) encodes
/// `mhash`. Returns the recovered salt length.
pub fn verify_pss(
    mhash: &[u8],
    md: &dyn Hash,
    mgf1md: &dyn Hash,
    em: &[u8],
    bits: usize,
    slen: i32,
) -> Outcome<i32> {
    const F: &str = "ossl_rsa_verify_PKCS1_PSS_mgf1";
    let hlen = md.size();
    if hlen == 0 {
        return silent();
    }
    if slen < PssSaltLen::AUTO_DIGEST_MAX {
        return fail(F, Reason::SlenCheckFailed(None));
    }
    let msbits = bits.wrapping_sub(1) & 7;
    let first = em.first().copied().unwrap_or(0);
    if (0xff_u8
        .checked_shl(u32::try_from(msbits).unwrap_or(8))
        .unwrap_or(0))
        & first
        != 0
    {
        return fail(F, Reason::FirstOctetInvalid);
    }
    let e = if msbits == 0 {
        em.get(1..).unwrap_or_default()
    } else {
        em
    };
    let Some(max_salt) = pss_room(e.len(), hlen) else {
        return fail(F, Reason::DataTooLarge);
    };
    let expected = match slen {
        PssSaltLen::DIGEST => Some(hlen),
        PssSaltLen::MAX => Some(max_salt),
        PssSaltLen::AUTO | PssSaltLen::AUTO_DIGEST_MAX => None,
        n => Some(usize::try_from(n).unwrap_or(0)),
    };
    if expected.is_some_and(|s| s > max_salt) {
        return fail(F, Reason::DataTooLarge);
    }
    if e.last() != Some(&0xbc) {
        return fail(F, Reason::LastOctetInvalid);
    }
    let masked_len = max_salt.saturating_add(1);
    let (masked, tail) = e.split_at(masked_len);
    let h = tail.get(..hlen).unwrap_or_default();
    let Some(mask) = mgf1(masked_len, h, mgf1md) else {
        return silent();
    };
    let mut db: Vec<u8> = mask.iter().zip(masked).map(|(a, b)| a ^ b).collect();
    if msbits != 0
        && let Some(b) = db.first_mut()
    {
        *b &= 0xff >> (8_usize.saturating_sub(msbits));
    }
    let i = db
        .iter()
        .take(masked_len.saturating_sub(1))
        .position(|&b| b != 0)
        .unwrap_or(masked_len.saturating_sub(1));
    if db.get(i) != Some(&1) {
        return fail(F, Reason::SlenRecoveryFailed);
    }
    let salt = db.get(i.saturating_add(1)..).unwrap_or_default();
    let recovered = i32::try_from(salt.len()).unwrap_or(0);
    if let Some(s) = expected
        && s != salt.len()
    {
        let s = i32::try_from(s).unwrap_or(0);
        return fail(F, Reason::SlenCheckFailed(Some((s, recovered))));
    }
    let m = mhash.get(..hlen.min(mhash.len())).unwrap_or_default();
    let Some(hh) = md.digest(&[&[0u8; 8], m, salt]) else {
        return silent();
    };
    if hh.get(..hlen) != Some(h) {
        return fail(F, Reason::BadSignature);
    }
    (Ok(recovered), Vec::new())
}
