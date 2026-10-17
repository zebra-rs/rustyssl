//! Printing an attribute's value (`ossl_print_attribute_value` and `print_oid`, in
//! `x_attrib.c`), for the attribute certificate extensions and, with step 5.6, attribute
//! certificates.
//!
//! As OpenSSL's, an INTEGER is read as an ENUMERATED, which fails (leaving
//! `ASN1_R_WRONG_INTEGER_TYPE` on the error queue), so it prints in hex.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;

use rustyssl_abi::{
    ASN1_OBJECT, ASN1_STRING, ASN1_TYPE, BIO, NID_associatedName, NID_dITRedirect,
    NID_documentAuthor, NID_manager, NID_member, NID_owner, NID_roleOccupant, NID_secretary,
    NID_seeAlso, V_ASN1_BIT_STRING, V_ASN1_BOOLEAN, V_ASN1_ENUMERATED, V_ASN1_GENERALIZEDTIME,
    V_ASN1_GENERALSTRING, V_ASN1_GRAPHICSTRING, V_ASN1_IA5STRING, V_ASN1_INTEGER, V_ASN1_NULL,
    V_ASN1_NUMERICSTRING, V_ASN1_OBJECT, V_ASN1_OBJECT_DESCRIPTOR, V_ASN1_OCTET_STRING,
    V_ASN1_PRINTABLESTRING, V_ASN1_REAL, V_ASN1_SEQUENCE, V_ASN1_SET, V_ASN1_T61STRING,
    V_ASN1_UTCTIME, V_ASN1_UTF8STRING, V_ASN1_VIDEOTEXSTRING, V_ASN1_VISIBLESTRING,
    XN_FLAG_SEP_CPLUS_SPC,
};

use super::name::{X509_NAME_free, X509_NAME_print_ex, d2i_X509_NAME};
use crate::asn1::integer::ASN1_ENUMERATED_get_int64;
use crate::asn1::parse::ASN1_parse_dump;
use crate::objects::{OBJ_nid2ln, OBJ_obj2nid, OBJ_obj2txt};
use crate::x509v3::text::Out;

/// A string's octets.
///
/// # Safety
/// `s` is NULL or a live string.
unsafe fn octets<'a>(s: *const ASN1_STRING) -> &'a [u8] {
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { s.as_ref() }) else {
        return &[];
    };
    match usize::try_from(s.length) {
        // SAFETY: a string's data holds its length.
        Ok(n) if n > 0 && !s.data.is_null() => unsafe { core::slice::from_raw_parts(s.data, n) },
        _ => &[],
    }
}

/// `ossl_bio_print_hex`: the octets in upper-case hex, colon separated (`OPENSSL_buf2hexstr`):
/// 1 (for none too), or 0.
pub(crate) fn bio_print_hex(out: Out, buf: &[u8]) -> c_int {
    if buf.is_empty() {
        return 1;
    }
    let hex: Vec<String> = buf.iter().map(|c| format!("{c:02X}")).collect();
    c_int::from(out.print(&hex.join(":")) > 0)
}

/// An OID in dotted form as `OBJ_obj2txt` writes it into 80 octets (so at most 79
/// characters), or `None`.
///
/// # Safety
/// `oid` is NULL or a live object.
pub(crate) unsafe fn oid_text80(oid: *const ASN1_OBJECT) -> Option<String> {
    let mut buf: [c_char; 80] = [0; 80];
    // SAFETY: the buffer and its size; the caller's guarantee.
    if unsafe { OBJ_obj2txt(buf.as_mut_ptr(), 80, oid, 1) } <= 0 {
        return None;
    }
    // SAFETY: written above, and NUL-terminated within the buffer.
    let text = unsafe { CStr::from_ptr(buf.as_ptr()) };
    Some(text.to_string_lossy().into_owned())
}

/// `print_oid`: the OID in dotted form and its long name in parentheses: 1, or 0.
///
/// # Safety
/// `oid` is NULL or a live object.
unsafe fn print_oid(out: Out, oid: *const ASN1_OBJECT) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(text) = (unsafe { oid_text80(oid) }) else {
        return 0;
    };
    // SAFETY: as above.
    let nid = unsafe { OBJ_obj2nid(oid) };
    // SAFETY: a NID.
    let ln = unsafe { OBJ_nid2ln(nid) };
    let line = if ln.is_null() {
        text
    } else {
        // SAFETY: a static name.
        let ln = unsafe { CStr::from_ptr(ln) }.to_string_lossy();
        format!("{text} ({ln})")
    };
    c_int::from(out.print(&line) >= 0)
}

/// The attributes whose SEQUENCE values are distinguished names.
const NAME_VALUED: [c_int; 9] = [
    NID_member,
    NID_roleOccupant,
    NID_seeAlso,
    NID_manager,
    NID_documentAuthor,
    NID_secretary,
    NID_associatedName,
    NID_dITRedirect,
    NID_owner,
];

/// `ossl_print_attribute_value`: a value of the attribute `obj_nid`, `indent` in, by its
/// type: booleans, NULL, and REAL by name; numbers in decimal if they read as an ENUMERATED,
/// otherwise in hex, as BIT and OCTET STRINGs; OIDs with their names; strings and times as
/// they are; SETs and SEQUENCEs dumped (a name's SEQUENCE as the name), and other types by
/// their tag. Positive if printed.
///
/// # Safety
/// `out` is a live BIO; `av` is NULL or a live `ASN1_TYPE`.
pub(crate) unsafe fn print_attribute_value(
    out: *mut BIO,
    obj_nid: c_int,
    av: *const ASN1_TYPE,
    indent: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let o = unsafe { Out::new(out) };
    // SAFETY: as above.
    let Some(av) = (unsafe { av.as_ref() }) else {
        return 0;
    };
    // Each pointer member of the union is the value's string (or object).
    // SAFETY: the union's member, as its type says.
    let s = unsafe { av.value.asn1_string }.cast_const();
    match av.type_ {
        t if t == V_ASN1_BOOLEAN => {
            // SAFETY: as above.
            if unsafe { av.value.boolean } != 0 {
                c_int::from(o.line(indent, "TRUE") >= 4)
            } else {
                c_int::from(o.line(indent, "FALSE") >= 5)
            }
        }
        t if t == V_ASN1_INTEGER || t == V_ASN1_ENUMERATED => {
            if o.line(indent, "") < 0 {
                return 0;
            }
            let mut v: i64 = 0;
            // SAFETY: a local; the value's number.
            if unsafe { ASN1_ENUMERATED_get_int64(&raw mut v, s) } > 0 {
                return c_int::from(o.print(&v.to_string()) > 0);
            }
            // SAFETY: as above.
            bio_print_hex(o, unsafe { octets(s) })
        }
        t if t == V_ASN1_BIT_STRING || t == V_ASN1_OCTET_STRING || t == V_ASN1_VIDEOTEXSTRING => {
            if o.line(indent, "") < 0 {
                return 0;
            }
            // SAFETY: the value's string.
            bio_print_hex(o, unsafe { octets(s) })
        }
        t if t == V_ASN1_NULL => c_int::from(o.line(indent, "NULL") >= 4),
        t if t == V_ASN1_OBJECT => {
            if o.line(indent, "") < 0 {
                return 0;
            }
            // SAFETY: the union's object.
            let obj = unsafe { av.value.object };
            // SAFETY: the value's object.
            unsafe { print_oid(o, obj) }
        }
        t if [
            V_ASN1_GENERALSTRING,
            V_ASN1_GRAPHICSTRING,
            V_ASN1_OBJECT_DESCRIPTOR,
            V_ASN1_UTF8STRING,
            V_ASN1_VISIBLESTRING,
            V_ASN1_UTCTIME,
            V_ASN1_GENERALIZEDTIME,
            V_ASN1_NUMERICSTRING,
            V_ASN1_PRINTABLESTRING,
            V_ASN1_T61STRING,
            V_ASN1_IA5STRING,
        ]
        .contains(&t) =>
        {
            // SAFETY: the value's string.
            c_int::from(unsafe { o.line_string(indent, s) } >= 0)
        }
        t if t == V_ASN1_REAL => c_int::from(o.line(indent, "REAL") >= 4),
        t if t == V_ASN1_SEQUENCE && NAME_VALUED.contains(&obj_nid) => {
            // SAFETY: the value's string.
            let der = unsafe { octets(s) };
            let mut p = der.as_ptr();
            let Ok(len) = der.len().try_into() else {
                return 0;
            };
            // SAFETY: a local over the octets.
            let xn = unsafe { d2i_X509_NAME(ptr::null_mut(), &raw mut p, len) };
            if xn.is_null() {
                o.print("(COULD NOT DECODE DISTINGUISHED NAME)\n");
                return 0;
            }
            // SAFETY: the caller's BIO; the name decoded above.
            let ret = unsafe {
                X509_NAME_print_ex(
                    out,
                    xn,
                    indent,
                    core::ffi::c_ulong::from(XN_FLAG_SEP_CPLUS_SPC.cast_unsigned()),
                )
            };
            // SAFETY: as above.
            unsafe { X509_NAME_free(xn) };
            c_int::from(ret > 0)
        }
        t if t == V_ASN1_SEQUENCE || t == V_ASN1_SET => {
            // SAFETY: the value's string.
            let der = unsafe { octets(s) };
            let Ok(len) = der.len().try_into() else {
                return 0;
            };
            // SAFETY: the caller's BIO; the octets.
            c_int::from(unsafe { ASN1_parse_dump(out, der.as_ptr(), len, indent, 1) } > 0)
        }
        t => c_int::from(o.line(indent, &format!("<Unsupported tag {t}>")) >= 0),
    }
}
