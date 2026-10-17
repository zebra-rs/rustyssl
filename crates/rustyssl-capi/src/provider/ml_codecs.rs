//! What ML-KEM's and ML-DSA's key codecs share (`ml_common_codecs.c`, the tables of
//! `ml_kem_codecs.c` and `ml_dsa_codecs.c`): the SubjectPublicKeyInfo's fixed 22-octet prefix,
//! and the six PrivateKeyInfo private-key formats — a SEQUENCE of the seed and the expanded
//! key (`seed-priv`), the expanded key alone (`priv-only`), the expanded key followed by the
//! public key in one OCTET STRING (`oqskeypair`), the seed as `[0]` (`seed-only`), and the bare
//! expanded key or seed (`bare-priv`, `bare-seed`) — in the order a provider configuration's
//! `ml-kem.input_formats` or `ml-dsa.input_formats` prefers.
//!
//! OpenSSL writes the tables out per parameter set; here they follow from the sizes, which
//! gives the same octets (each key is longer than 255 octets, so every length is two octets).

use core::ffi::{CStr, c_int};

use rustyssl_abi::{ERR_LIB_PROV, PROV_R_ML_DSA_NO_FORMAT};

use crate::err;

/// `ML_COMMON_SPKI_OVERHEAD`.
pub(crate) const SPKI_OVERHEAD: usize = 22;

/// `ML_COMMON_PKCS8_FMT`: a private-key format's total length, how its first four octets
/// identify it (`shift` octets of them aren't the format's: all four for a bare format), and
/// where its seed, expanded private key, and public key lie, each 0 when it has none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Fmt {
    pub(crate) name: &'static str,
    pub(crate) bytes: usize,
    pub(crate) shift: usize,
    pub(crate) magic: u32,
    pub(crate) seed_magic: u16,
    pub(crate) seed_offset: usize,
    pub(crate) seed_length: usize,
    pub(crate) priv_magic: u32,
    pub(crate) priv_offset: usize,
    pub(crate) priv_length: usize,
    pub(crate) pub_offset: usize,
    pub(crate) pub_length: usize,
}

/// A DER length that fits two octets, as a `u32` beside its header octets.
fn len16(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(0) & 0xffff
}

/// The six formats for a seed, expanded private key, and public key of these lengths, in
/// OpenSSL's table order.
pub(crate) fn formats(seed: usize, sk: usize, pk: usize) -> [Fmt; 6] {
    let none = Fmt {
        name: "",
        bytes: 0,
        shift: 0,
        magic: 0,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0,
        priv_magic: 0,
        priv_offset: 0,
        priv_length: 0,
        pub_offset: 0,
        pub_length: 0,
    };
    let seed_priv = 4 + 2 + seed + 4 + sk;
    let seed16 = u16::try_from(seed).unwrap_or(0) & 0xff;
    [
        Fmt {
            name: "seed-priv",
            bytes: seed_priv,
            magic: 0x3082_0000 | len16(seed_priv - 4),
            seed_magic: 0x0400 | seed16,
            seed_offset: 6,
            seed_length: seed,
            priv_magic: 0x0482_0000 | len16(sk),
            priv_offset: 6 + seed + 4,
            priv_length: sk,
            ..none
        },
        Fmt {
            name: "priv-only",
            bytes: 4 + sk,
            magic: 0x0482_0000 | len16(sk),
            priv_offset: 4,
            priv_length: sk,
            ..none
        },
        Fmt {
            name: "oqskeypair",
            bytes: 4 + sk + pk,
            magic: 0x0482_0000 | len16(sk + pk),
            priv_offset: 4,
            priv_length: sk,
            pub_offset: 4 + sk,
            pub_length: pk,
            ..none
        },
        Fmt {
            name: "seed-only",
            bytes: 2 + seed,
            shift: 2,
            magic: 0x8000 | u32::from(seed16),
            seed_offset: 2,
            seed_length: seed,
            ..none
        },
        Fmt {
            name: "bare-priv",
            bytes: sk,
            shift: 4,
            priv_length: sk,
            ..none
        },
        Fmt {
            name: "bare-seed",
            bytes: seed,
            shift: 4,
            seed_length: seed,
            ..none
        },
    ]
}

/// `ossl_ml_common_pkcs8_fmt_order`: the formats a configuration's list names (separated by
/// tabs, spaces, or commas; each name's prefix in any case), in its order; all of them in
/// table order for no list. `None` (with `PROV_R_ML_DSA_NO_FORMAT`) when the list names none.
pub(crate) fn order(
    algorithm_name: &str,
    table: &[Fmt; 6],
    direction: &str,
    list: Option<&CStr>,
) -> Option<Vec<Fmt>> {
    let Some(list) = list else {
        return Some(table.to_vec());
    };
    let mut prefs = [0usize; 6];
    let mut count = 0;
    let is_sep = |c: &u8| matches!(c, b'\t' | b' ' | b',');
    for word in list.to_bytes().split(is_sep).filter(|w| !w.is_empty()) {
        if count == table.len() {
            break;
        }
        // `OPENSSL_strncasecmp(name, word, len(word))`: the word is a prefix of the name (or,
        // past the name's end, longer than it, which never matches).
        let found = table.iter().zip(prefs.iter_mut()).find(|(f, p)| {
            **p == 0
                && f.name
                    .as_bytes()
                    .get(..word.len())
                    .is_some_and(|n| n.eq_ignore_ascii_case(word))
        });
        if let Some((_, p)) = found {
            count += 1;
            *p = count;
        }
    }
    if count == 0 {
        err::raise_with_text(
            ERR_LIB_PROV,
            PROV_R_ML_DSA_NO_FORMAT,
            "ossl_ml_common_pkcs8_fmt_order",
            &format!("no {algorithm_name} private key {direction} formats are enabled"),
        );
        return None;
    }
    let mut chosen: Vec<(usize, Fmt)> = table
        .iter()
        .zip(prefs)
        .filter(|&(_, p)| p > 0)
        .map(|(f, p)| (p, *f))
        .collect();
    chosen.sort_by_key(|&(p, _)| p);
    Some(chosen.into_iter().map(|(_, f)| f).collect())
}

/// What a private-key encoding holds, by its format.
pub(crate) struct Parts<'a> {
    pub(crate) seed: Option<&'a [u8]>,
    pub(crate) private: Option<&'a [u8]>,
}

/// Why a private-key encoding wasn't taken.
pub(crate) enum Refused {
    /// No enabled format fits (OpenSSL's "no matching enabled ... formats").
    NoFormat,
    /// A format fits by length and magic but not in its inner tags or layout (no error).
    Malformed,
}

/// `ossl_ml_*_d2i_PKCS8`'s parse of the PrivateKeyInfo's key octets: the first enabled format of
/// their length whose magic they carry (a bare format always does), its parts checked to be the
/// expected lengths and where the format puts them.
pub(crate) fn parse<'a>(
    buf: &'a [u8],
    slots: &[Fmt],
    seed_bytes: usize,
    sk_bytes: usize,
    pk_bytes: usize,
) -> Result<Parts<'a>, Refused> {
    let Some(head) = buf.first_chunk::<4>() else {
        return Err(Refused::Malformed);
    };
    let magic = u32::from_be_bytes(*head);
    let f = slots
        .iter()
        .find(|f| buf.len() == f.bytes && (f.shift == 4 || (magic >> (f.shift * 8)) == f.magic))
        .ok_or(Refused::NoFormat)?;
    if (f.seed_length > 0 && f.seed_length != seed_bytes)
        || (f.priv_length > 0 && f.priv_length != sk_bytes)
        || (f.pub_length > 0 && f.pub_length != pk_bytes)
    {
        return Err(Refused::NoFormat);
    }
    // The position after the format's own magic octets.
    let mut pos = 4 - f.shift;
    let u16_at = |at: usize| {
        buf.get(at..)
            .and_then(<[u8]>::first_chunk::<2>)
            .map(|b| u16::from_be_bytes(*b))
    };
    let u32_at = |at: usize| {
        buf.get(at..)
            .and_then(<[u8]>::first_chunk::<4>)
            .map(|b| u32::from_be_bytes(*b))
    };
    if f.seed_length > 0 {
        if pos + 2 == f.seed_offset {
            if u16_at(pos) != Some(f.seed_magic) {
                return Err(Refused::Malformed);
            }
            pos += 2;
        } else if pos != f.seed_offset {
            return Err(Refused::Malformed);
        }
        pos += seed_bytes;
    }
    if f.priv_length > 0 {
        if pos + 4 == f.priv_offset {
            if u32_at(pos) != Some(f.priv_magic) {
                return Err(Refused::Malformed);
            }
            pos += 4;
        } else if pos != f.priv_offset {
            return Err(Refused::Malformed);
        }
        pos += sk_bytes;
    }
    if f.pub_length > 0 {
        if pos != f.pub_offset {
            return Err(Refused::Malformed);
        }
        pos += pk_bytes;
    }
    if pos != buf.len() {
        return Err(Refused::Malformed);
    }
    let seed = (f.seed_length > 0)
        .then(|| buf.get(f.seed_offset..f.seed_offset + seed_bytes))
        .flatten();
    let private = (f.priv_length > 0)
        .then(|| buf.get(f.priv_offset..f.priv_offset + sk_bytes))
        .flatten();
    Ok(Parts { seed, private })
}

/// `ossl_ml_*_i2d_prvkey`'s choice: the first enabled format the key can fill (one with a seed
/// only when the key kept its seed), if its lengths are the key's.
pub(crate) fn output_format(
    slots: &[Fmt],
    have_seed: bool,
    seed_bytes: usize,
    sk_bytes: usize,
    pk_bytes: usize,
) -> Option<Fmt> {
    let f = slots.iter().find(|f| have_seed || f.seed_length == 0)?;
    let fits = (f.seed_length == 0 || f.seed_length == seed_bytes)
        && (f.priv_length == 0 || f.priv_length == sk_bytes)
        && (f.pub_length == 0 || f.pub_length == pk_bytes);
    fits.then_some(*f)
}

/// `ossl_ml_*_i2d_prvkey`'s layout: the format's magic, then the seed, expanded key, and
/// public key it holds, each with its own magic where the format has one.
pub(crate) fn write(f: &Fmt, seed: Option<&[u8]>, sk: &[u8], pk: &[u8]) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(f.bytes);
    match f.shift {
        0 => buf.extend_from_slice(&f.magic.to_be_bytes()),
        2 => buf.extend_from_slice(&u16::try_from(f.magic & 0xffff).ok()?.to_be_bytes()),
        4 => {}
        _ => return None,
    }
    if f.seed_length != 0 {
        if buf.len() + 2 == f.seed_offset {
            buf.extend_from_slice(&f.seed_magic.to_be_bytes());
        }
        if buf.len() != f.seed_offset {
            return None;
        }
        buf.extend_from_slice(seed?);
    }
    if f.priv_length != 0 {
        if buf.len() + 4 == f.priv_offset {
            buf.extend_from_slice(&f.priv_magic.to_be_bytes());
        }
        if buf.len() != f.priv_offset {
            return None;
        }
        buf.extend_from_slice(sk);
    }
    if f.pub_length != 0 {
        if buf.len() != f.pub_offset {
            return None;
        }
        buf.extend_from_slice(pk);
    }
    (buf.len() == f.bytes).then_some(buf)
}

/// The SubjectPublicKeyInfo prefix of a key type's public key of `pk` octets: the SEQUENCE,
/// the AlgorithmIdentifier of the type's 9-octet OID without parameters, and the BIT STRING
/// header with no unused bits.
pub(crate) fn spki_prefix(oid: &[u8], pk: usize) -> Option<[u8; SPKI_OVERHEAD]> {
    let oid: &[u8; 9] = oid.try_into().ok()?;
    let total = u16::try_from(SPKI_OVERHEAD - 4 + pk).ok()?.to_be_bytes();
    let bits = u16::try_from(pk + 1).ok()?.to_be_bytes();
    let mut p = [0u8; SPKI_OVERHEAD];
    p[..4].copy_from_slice(&[0x30, 0x82, total[0], total[1]]);
    p[4..7].copy_from_slice(&[0x30, 0x0b, 0x06]);
    p[7] = 0x09;
    p[8..17].copy_from_slice(oid);
    p[17..].copy_from_slice(&[0x03, 0x82, bits[0], bits[1], 0x00]);
    Some(p)
}

/// The DER contents of a NID's OID, or `None`.
pub(crate) fn oid_octets(nid: c_int) -> Option<Vec<u8>> {
    // SAFETY: no preconditions.
    let obj = unsafe { crate::objects::OBJ_nid2obj(nid) };
    if obj.is_null() {
        return None;
    }
    // SAFETY: the object.
    let n = unsafe { crate::objects::OBJ_length(obj) };
    // SAFETY: as above.
    let data = unsafe { crate::objects::OBJ_get0_data(obj) };
    // SAFETY: the object's `n` octets.
    unsafe { crate::ffi::bytes(data, n) }.map(<[u8]>::to_vec)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tables OpenSSL writes out for ML-KEM-512 and ML-DSA-44.
    #[test]
    fn the_formats_are_openssls() {
        let kem = formats(64, 0x0660, 0x0320);
        assert_eq!(
            (
                kem[0].bytes,
                kem[0].magic,
                kem[0].seed_magic,
                kem[0].priv_magic,
                kem[0].priv_offset
            ),
            (0x06aa, 0x3082_06a6, 0x0440, 0x0482_0660, 0x4a)
        );
        assert_eq!(
            (kem[2].bytes, kem[2].magic, kem[2].pub_offset),
            (0x0984, 0x0482_0980, 0x0664)
        );
        assert_eq!(
            (kem[3].bytes, kem[3].magic, kem[3].shift),
            (0x0042, 0x8040, 2)
        );
        let dsa = formats(32, 0x0a00, 0x0520);
        assert_eq!(
            (dsa[0].bytes, dsa[0].magic, dsa[0].priv_offset),
            (0x0a2a, 0x3082_0a26, 0x2a)
        );
        assert_eq!((dsa[5].bytes, dsa[5].shift), (0x0020, 4));
        let p = spki_prefix(
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01],
            0x320,
        );
        assert_eq!(
            p.map(|p| p[..4].to_vec()),
            Some(vec![0x30, 0x82, 0x03, 0x32])
        );
        assert_eq!(
            p.map(|p| p[17..].to_vec()),
            Some(vec![0x03, 0x82, 0x03, 0x21, 0x00])
        );
        let o = order("ML-KEM-512", &kem, "input", Some(c"Bare-Seed, priv"));
        assert_eq!(
            o.map(|v| v.iter().map(|f| f.name).collect::<Vec<_>>()),
            Some(vec!["bare-seed", "priv-only"])
        );
    }
}
