//! The tag names of `ASN1_generate_nconf`'s mini-language (`asn1_str2tag`), from the
//! reference's `crypto/asn1/asn1_gen.c` (OpenSSL 3.5.9), by a script.

use rustyssl_abi as abi;

/// `ASN1_GEN_FLAG`.
pub const GEN_FLAG: i32 = 0x10000;
/// `ASN1_GEN_FLAG_IMP`.
pub const GEN_FLAG_IMP: i32 = GEN_FLAG | 1;
/// `ASN1_GEN_FLAG_EXP`.
pub const GEN_FLAG_EXP: i32 = GEN_FLAG | 2;
/// `ASN1_GEN_FLAG_TAG`.
pub const GEN_FLAG_TAG: i32 = GEN_FLAG | 3;
/// `ASN1_GEN_FLAG_BITWRAP`.
pub const GEN_FLAG_BITWRAP: i32 = GEN_FLAG | 4;
/// `ASN1_GEN_FLAG_OCTWRAP`.
pub const GEN_FLAG_OCTWRAP: i32 = GEN_FLAG | 5;
/// `ASN1_GEN_FLAG_SEQWRAP`.
pub const GEN_FLAG_SEQWRAP: i32 = GEN_FLAG | 6;
/// `ASN1_GEN_FLAG_SETWRAP`.
pub const GEN_FLAG_SETWRAP: i32 = GEN_FLAG | 7;
/// `ASN1_GEN_FLAG_FORMAT`.
pub const GEN_FLAG_FORMAT: i32 = GEN_FLAG | 8;

/// The names, in OpenSSL's order, and their tags (or `GEN_FLAG_*` modifiers).
pub const TAG_NAMES: &[(&str, i32)] = &[
    ("BOOL", abi::V_ASN1_BOOLEAN),
    ("BOOLEAN", abi::V_ASN1_BOOLEAN),
    ("NULL", abi::V_ASN1_NULL),
    ("INT", abi::V_ASN1_INTEGER),
    ("INTEGER", abi::V_ASN1_INTEGER),
    ("ENUM", abi::V_ASN1_ENUMERATED),
    ("ENUMERATED", abi::V_ASN1_ENUMERATED),
    ("OID", abi::V_ASN1_OBJECT),
    ("OBJECT", abi::V_ASN1_OBJECT),
    ("UTCTIME", abi::V_ASN1_UTCTIME),
    ("UTC", abi::V_ASN1_UTCTIME),
    ("GENERALIZEDTIME", abi::V_ASN1_GENERALIZEDTIME),
    ("GENTIME", abi::V_ASN1_GENERALIZEDTIME),
    ("OCT", abi::V_ASN1_OCTET_STRING),
    ("OCTETSTRING", abi::V_ASN1_OCTET_STRING),
    ("BITSTR", abi::V_ASN1_BIT_STRING),
    ("BITSTRING", abi::V_ASN1_BIT_STRING),
    ("UNIVERSALSTRING", abi::V_ASN1_UNIVERSALSTRING),
    ("UNIV", abi::V_ASN1_UNIVERSALSTRING),
    ("IA5", abi::V_ASN1_IA5STRING),
    ("IA5STRING", abi::V_ASN1_IA5STRING),
    ("UTF8", abi::V_ASN1_UTF8STRING),
    ("UTF8String", abi::V_ASN1_UTF8STRING),
    ("BMP", abi::V_ASN1_BMPSTRING),
    ("BMPSTRING", abi::V_ASN1_BMPSTRING),
    ("VISIBLESTRING", abi::V_ASN1_VISIBLESTRING),
    ("VISIBLE", abi::V_ASN1_VISIBLESTRING),
    ("PRINTABLESTRING", abi::V_ASN1_PRINTABLESTRING),
    ("PRINTABLE", abi::V_ASN1_PRINTABLESTRING),
    ("T61", abi::V_ASN1_T61STRING),
    ("T61STRING", abi::V_ASN1_T61STRING),
    ("TELETEXSTRING", abi::V_ASN1_T61STRING),
    ("GeneralString", abi::V_ASN1_GENERALSTRING),
    ("GENSTR", abi::V_ASN1_GENERALSTRING),
    ("NUMERIC", abi::V_ASN1_NUMERICSTRING),
    ("NUMERICSTRING", abi::V_ASN1_NUMERICSTRING),
    ("SEQUENCE", abi::V_ASN1_SEQUENCE),
    ("SEQ", abi::V_ASN1_SEQUENCE),
    ("SET", abi::V_ASN1_SET),
    ("EXP", GEN_FLAG_EXP),
    ("EXPLICIT", GEN_FLAG_EXP),
    ("IMP", GEN_FLAG_IMP),
    ("IMPLICIT", GEN_FLAG_IMP),
    ("OCTWRAP", GEN_FLAG_OCTWRAP),
    ("SEQWRAP", GEN_FLAG_SEQWRAP),
    ("SETWRAP", GEN_FLAG_SETWRAP),
    ("BITWRAP", GEN_FLAG_BITWRAP),
    ("FORM", GEN_FLAG_FORMAT),
    ("FORMAT", GEN_FLAG_FORMAT),
];

/// `asn1_str2tag`: the tag (or modifier) named `name`, in any case; -1 if none.
pub fn str2tag(name: &[u8]) -> i32 {
    TAG_NAMES
        .iter()
        .find(|(n, _)| n.as_bytes().eq_ignore_ascii_case(name))
        .map_or(-1, |&(_, t)| t)
}
