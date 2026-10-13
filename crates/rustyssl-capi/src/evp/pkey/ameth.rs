//! The key types of OpenSSL's built-in ASN.1 methods (`crypto/asn1/standard_methods.h`), as
//! far as typing keys needs them: each method's key type, the type an alias stands for, its
//! flags, PEM name, and description, in the table's order. `EVP_PKEY_type`, the lookup by PEM
//! name (`EVP_PKEY_asn1_find_str`), and `evp_pkey_name2type` work from it.
//!
//! The methods' functions (encoding, printing, ...) come with the key types (4.3 onwards); the
//! `EVP_PKEY_asn1_*` API and application-added methods with 4.2d.

use core::ffi::{CStr, c_int, c_ulong};

use rustyssl_abi::{
    ASN1_PKEY_ALIAS, ASN1_PKEY_SIGPARAM_NULL, EVP_PKEY_DH, EVP_PKEY_DHX, EVP_PKEY_DSA,
    EVP_PKEY_DSA1, EVP_PKEY_DSA2, EVP_PKEY_DSA3, EVP_PKEY_DSA4, EVP_PKEY_EC, EVP_PKEY_ED448,
    EVP_PKEY_ED25519, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, EVP_PKEY_RSA2, EVP_PKEY_SM2, EVP_PKEY_X448,
    EVP_PKEY_X25519, NID_undef,
};

use crate::objects::{OBJ_ln2nid, OBJ_sn2nid};

/// One of the built-in ASN.1 methods, as typing sees it.
pub(crate) struct Ameth {
    pub(crate) pkey_id: c_int,
    pub(crate) base_id: c_int,
    pub(crate) flags: c_ulong,
    /// The PEM name (NULL for an alias).
    pub(crate) pem_str: Option<&'static CStr>,
    /// The description (NULL for an alias).
    pub(crate) info: Option<&'static CStr>,
    /// Which of the method's functions it has (`F_*`).
    funcs: u32,
}

/// `pub_cmp`.
pub(crate) const F_PUB_CMP: u32 = 1;
/// `pkey_size`, `pkey_bits`, and `pkey_security_bits`.
pub(crate) const F_SIZES: u32 = 1 << 1;
/// `param_missing`.
pub(crate) const F_PARAM_MISSING: u32 = 1 << 2;
/// `param_copy`.
pub(crate) const F_PARAM_COPY: u32 = 1 << 3;
/// `param_cmp`.
pub(crate) const F_PARAM_CMP: u32 = 1 << 4;
/// `pkey_ctrl`.
pub(crate) const F_CTRL: u32 = 1 << 5;
/// `get_priv_key` and `get_pub_key`.
pub(crate) const F_GET_RAW: u32 = 1 << 6;
/// `copy`.
pub(crate) const F_COPY: u32 = 1 << 7;

/// RSA's and RSA-PSS's functions.
const RSA_FUNCS: u32 = F_PUB_CMP | F_SIZES | F_CTRL | F_COPY;
/// DH's, DHX's, DSA's, and EC's.
const PARAMS_FUNCS: u32 =
    F_PUB_CMP | F_SIZES | F_PARAM_MISSING | F_PARAM_COPY | F_PARAM_CMP | F_CTRL | F_COPY;
/// The ECX types'.
const ECX_FUNCS: u32 = F_PUB_CMP | F_SIZES | F_PARAM_CMP | F_CTRL | F_GET_RAW | F_COPY;

impl Ameth {
    /// Whether it has the function `f` (an `F_*`). The functions work on legacy key data,
    /// which comes with the key types (4.3 onwards): a key typed without data reaches them only
    /// where OpenSSL would use data it doesn't have.
    pub(crate) fn has(&self, f: u32) -> bool {
        self.funcs & f != 0
    }

    /// Whether it's an alias for another type.
    pub(crate) fn is_alias(&self) -> bool {
        self.flags & ASN1_PKEY_ALIAS.cast_unsigned() as c_ulong != 0
    }
}

const fn method(
    pkey_id: c_int,
    flags: c_int,
    pem_str: &'static CStr,
    info: &'static CStr,
    funcs: u32,
) -> Ameth {
    Ameth {
        pkey_id,
        base_id: pkey_id,
        flags: flags.cast_unsigned() as c_ulong,
        pem_str: Some(pem_str),
        info: Some(info),
        funcs,
    }
}

const fn alias(pkey_id: c_int, base_id: c_int) -> Ameth {
    Ameth {
        pkey_id,
        base_id,
        flags: ASN1_PKEY_ALIAS.cast_unsigned() as c_ulong,
        pem_str: None,
        info: None,
        funcs: 0,
    }
}

/// `standard_methods`, in OpenSSL's order (sorted by key type).
pub(crate) static STANDARD: [Ameth; 15] = [
    method(
        EVP_PKEY_RSA,
        ASN1_PKEY_SIGPARAM_NULL,
        c"RSA",
        c"OpenSSL RSA method",
        RSA_FUNCS,
    ),
    alias(EVP_PKEY_RSA2, EVP_PKEY_RSA),
    method(
        EVP_PKEY_DH,
        0,
        c"DH",
        c"OpenSSL PKCS#3 DH method",
        PARAMS_FUNCS,
    ),
    alias(EVP_PKEY_DSA1, EVP_PKEY_DSA),
    alias(EVP_PKEY_DSA4, EVP_PKEY_DSA2),
    alias(EVP_PKEY_DSA3, EVP_PKEY_DSA2),
    method(EVP_PKEY_DSA, 0, c"DSA", c"OpenSSL DSA method", PARAMS_FUNCS),
    method(EVP_PKEY_EC, 0, c"EC", c"OpenSSL EC algorithm", PARAMS_FUNCS),
    method(
        EVP_PKEY_RSA_PSS,
        ASN1_PKEY_SIGPARAM_NULL,
        c"RSA-PSS",
        c"OpenSSL RSA-PSS method",
        RSA_FUNCS,
    ),
    method(
        EVP_PKEY_DHX,
        0,
        c"X9.42 DH",
        c"OpenSSL X9.42 DH method",
        PARAMS_FUNCS,
    ),
    method(
        EVP_PKEY_X25519,
        0,
        c"X25519",
        c"OpenSSL X25519 algorithm",
        ECX_FUNCS,
    ),
    method(
        EVP_PKEY_X448,
        0,
        c"X448",
        c"OpenSSL X448 algorithm",
        ECX_FUNCS,
    ),
    method(
        EVP_PKEY_ED25519,
        0,
        c"ED25519",
        c"OpenSSL ED25519 algorithm",
        ECX_FUNCS,
    ),
    method(
        EVP_PKEY_ED448,
        0,
        c"ED448",
        c"OpenSSL ED448 algorithm",
        ECX_FUNCS,
    ),
    alias(EVP_PKEY_SM2, EVP_PKEY_EC),
];

/// The table's entries.
fn standard() -> &'static [Ameth] {
    &STANDARD
}

/// `pkey_asn1_find`: the method of exactly key type `type_`.
pub(crate) fn find_exact(type_: c_int) -> Option<&'static Ameth> {
    standard().iter().find(|m| m.pkey_id == type_)
}

/// `EVP_PKEY_asn1_find`: the method of `type_`, following aliases to the type they stand for.
pub(crate) fn find(mut type_: c_int) -> Option<&'static Ameth> {
    loop {
        let m = find_exact(type_)?;
        if !m.is_alias() {
            return Some(m);
        }
        type_ = m.base_id;
    }
}

/// `EVP_PKEY_asn1_find_str`: the (non-alias) method whose PEM name is `name`, ignoring case,
/// searching from the table's end.
pub(crate) fn find_str(name: &[u8]) -> Option<&'static Ameth> {
    standard().iter().rev().find(|m| {
        !m.is_alias()
            && m.pem_str
                .is_some_and(|p| p.to_bytes().eq_ignore_ascii_case(name))
    })
}

/// `EVP_PKEY_type`: the key type `type_` stands for, `NID_undef` if none.
pub(crate) fn pkey_type(type_: c_int) -> c_int {
    find(type_).map_or(NID_undef, |m| m.pkey_id)
}

/// `standard_name2type`.
const NAME2TYPE: [(c_int, &[u8]); 12] = [
    (EVP_PKEY_RSA, b"RSA"),
    (EVP_PKEY_RSA_PSS, b"RSA-PSS"),
    (EVP_PKEY_EC, b"EC"),
    (EVP_PKEY_ED25519, b"ED25519"),
    (EVP_PKEY_ED448, b"ED448"),
    (EVP_PKEY_X25519, b"X25519"),
    (EVP_PKEY_X448, b"X448"),
    (EVP_PKEY_SM2, b"SM2"),
    (EVP_PKEY_DH, b"DH"),
    (EVP_PKEY_DHX, b"X9.42 DH"),
    (EVP_PKEY_DHX, b"DHX"),
    (EVP_PKEY_DSA, b"DSA"),
];

/// `evp_pkey_name2type`: the key type a name stands for (the standard names ignoring case,
/// then an object's short and long name), `NID_undef` if none.
pub(crate) fn name2type(name: &[u8]) -> c_int {
    if let Some((t, _)) = NAME2TYPE.iter().find(|(_, n)| n.eq_ignore_ascii_case(name)) {
        return *t;
    }
    let Ok(c) = std::ffi::CString::new(name) else {
        return NID_undef;
    };
    // SAFETY: a string.
    let t = pkey_type(unsafe { OBJ_sn2nid(c.as_ptr()) });
    if t != NID_undef {
        return t;
    }
    // SAFETY: as above.
    pkey_type(unsafe { OBJ_ln2nid(c.as_ptr()) })
}

/// `evp_pkey_type2name`: the first standard name of a key type, else its object's short name
/// (empty if it has none).
pub(crate) fn type2name(type_: c_int) -> Vec<u8> {
    if let Some((_, n)) = NAME2TYPE.iter().find(|(t, _)| *t == type_) {
        return n.to_vec();
    }
    // SAFETY: a number.
    let sn = unsafe { crate::objects::OBJ_nid2sn(type_) };
    if sn.is_null() {
        return Vec::new();
    }
    // SAFETY: a static string.
    unsafe { core::ffi::CStr::from_ptr(sn) }.to_bytes().to_vec()
}

/// The pre-filled names of the key types (`get_legacy_pkey_meth_names`), in table order: for
/// each method, the base type (aliases other than SM2) and the type, as numbers, with the PEM
/// name, and DHX's extra name.
pub(crate) fn prefill_entries() -> Vec<(c_int, c_int, Option<&'static [u8]>)> {
    let mut out = Vec::new();
    for m in standard() {
        let pem = m.pem_str.map(CStr::to_bytes);
        if !m.is_alias() {
            if m.pkey_id == EVP_PKEY_DHX {
                out.push((NID_undef, m.pkey_id, Some(&b"DHX"[..])));
            }
            out.push((NID_undef, m.pkey_id, pem));
        } else if m.pkey_id == EVP_PKEY_SM2 {
            out.push((NID_undef, m.pkey_id, pem));
        } else {
            out.push((m.base_id, m.pkey_id, pem));
        }
    }
    out
}
