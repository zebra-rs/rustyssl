//! Checking name constraints (`v3_ncons.c`'s `NAME_CONSTRAINTS_check`, `_check_CN`, and
//! `nc_match`): whether a certificate's subject, its email addresses, and its alternative
//! names lie within a CA's permitted subtrees and outside its excluded ones.
//!
//! The comparisons are `rustyssl_pki::ncons`'s. As OpenSSL's:
//! - A subtree's minimum must be 0 and it mustn't have a maximum
//!   (`X509_V_ERR_SUBTREE_MINMAX`).
//! - A name type with permitted subtrees must match one of them; other names are permitted.
//! - Checks are bounded: names times constraints at most 2^20 (`X509_V_ERR_UNSPECIFIED`).
//! - Directory names compare by their canonical encodings' prefix.
//! - A URI without a scheme is unsupported, with an error naming it.

use core::ffi::c_int;
use core::ptr;

use rustyssl_abi::{
    ASN1_STRING, ERR_LIB_X509V3, GEN_DIRNAME, GEN_DNS, GEN_EMAIL, GEN_IPADD, GEN_OTHERNAME,
    GEN_URI, GENERAL_NAME, GENERAL_SUBTREE, NAME_CONSTRAINTS, NID_commonName,
    NID_id_on_SmtpUTF8Mailbox, NID_pkcs9_emailAddress, V_ASN1_IA5STRING, V_ASN1_UTF8STRING, X509,
    X509_NAME, X509_V_ERR_EXCLUDED_VIOLATION, X509_V_ERR_OUT_OF_MEM,
    X509_V_ERR_PERMITTED_VIOLATION, X509_V_ERR_SUBTREE_MINMAX, X509_V_ERR_UNSPECIFIED,
    X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE, X509_V_ERR_UNSUPPORTED_NAME_SYNTAX, X509_V_OK,
};
use rustyssl_pki::ncons::{self, Match};

use crate::asn1::integer::ASN1_INTEGER_get_int64;
use crate::asn1::text::ASN1_STRING_to_UTF8;
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::{OBJ_cmp, OBJ_obj2nid};
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::x509::cert::X509_get_subject_name;
use crate::x509::name::{
    X509_NAME_ENTRY_get_data, X509_NAME_entry_count, X509_NAME_get_entry,
    X509_NAME_get_index_by_NID, i2d_X509_NAME, name_of,
};
use crate::x509::purpose::cache_view;

/// `NAME_CHECK_MAX`.
const NAME_CHECK_MAX: c_int = 1 << 20;

/// A comparison's result as a verification error.
fn code(m: Match) -> c_int {
    match m {
        Match::Within => X509_V_OK,
        Match::Outside => X509_V_ERR_PERMITTED_VIOLATION,
        Match::BadSyntax => X509_V_ERR_UNSUPPORTED_NAME_SYNTAX,
        Match::Unspecified => X509_V_ERR_UNSPECIFIED,
    }
}

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

/// `nc_dn`: whether the name starts with the base's RDNs (canonical encodings).
///
/// # Safety
/// `nm` and `base` are live names.
unsafe fn nc_dn(nm: *const X509_NAME, base: *const X509_NAME) -> c_int {
    for n in [nm, base] {
        // SAFETY: the caller's names.
        let modified = unsafe { name_of(n) }.is_some_and(|n| n.modified != 0);
        // SAFETY: as above; encoding brings its canonical form up to date.
        if modified && unsafe { i2d_X509_NAME(n, ptr::null_mut()) } < 0 {
            return X509_V_ERR_OUT_OF_MEM;
        }
    }
    // SAFETY: as above.
    let (Some(a), Some(b)) = (unsafe { name_of(nm) }, unsafe { name_of(base) }) else {
        return X509_V_ERR_PERMITTED_VIOLATION;
    };
    if b.canon_enclen > a.canon_enclen {
        return X509_V_ERR_PERMITTED_VIOLATION;
    }
    if b.canon_enclen == 0 {
        return X509_V_OK;
    }
    let n = usize::try_from(b.canon_enclen).unwrap_or(0);
    let canon = |p: *const u8| {
        if p.is_null() {
            &[][..]
        } else {
            // SAFETY: a name's canonical encoding holds its length, at least `n` here.
            unsafe { core::slice::from_raw_parts(p, n) }
        }
    };
    if canon(b.canon_enc) == canon(a.canon_enc) {
        X509_V_OK
    } else {
        X509_V_ERR_PERMITTED_VIOLATION
    }
}

/// `nc_uri`: the URI's host against the base.
///
/// # Safety
/// `uri` and `base` are live strings.
unsafe fn nc_uri(uri: *const ASN1_STRING, base: *const ASN1_STRING) -> c_int {
    // SAFETY: the caller's guarantee.
    let text = unsafe { octets(uri) };
    // `OPENSSL_strndup` stops at a NUL.
    let text = text
        .get(..text.iter().position(|&c| c == 0).unwrap_or(text.len()))
        .unwrap_or_default();
    let Ok(u) = crate::http_lib::parse(text, false) else {
        return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
    };
    if u.scheme.0 == u.scheme.1 {
        let shown = String::from_utf8_lossy(text);
        let data = format!("x509: missing scheme in URI: {shown}\n");
        err::raise_with_text(
            ERR_LIB_X509V3,
            X509_V_ERR_UNSUPPORTED_NAME_SYNTAX,
            "nc_uri",
            &data,
        );
        return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
    }
    let host = text.get(u.host.0..u.host.1).unwrap_or_default();
    // SAFETY: as above.
    code(ncons::uri_host(host, unsafe { octets(base) }))
}

/// `nc_match_single`: a name against a subtree's base of the same type.
///
/// # Safety
/// `name` and `base` are live names.
unsafe fn match_single(effective_type: c_int, name: &GENERAL_NAME, base: &GENERAL_NAME) -> c_int {
    // Each pointer member of the unions is the name's value.
    // SAFETY: the union's member, as its type says.
    let gv = unsafe { name.d.ptr }.cast::<ASN1_STRING>().cast_const();
    // SAFETY: as above.
    let bv = unsafe { base.d.ptr }.cast::<ASN1_STRING>().cast_const();
    match name.type_ {
        t if t == GEN_OTHERNAME => {
            if effective_type != GEN_EMAIL {
                return X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE;
            }
            // SAFETY: an other name's member.
            let on = unsafe { name.d.otherName };
            // SAFETY: as above.
            let Some(on) = (unsafe { on.as_ref() }) else {
                return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
            };
            // SAFETY: its value.
            let Some(v) = (unsafe { on.value.as_ref() }) else {
                return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
            };
            // SAFETY: the base's string.
            let b = unsafe { octets(bv) };
            if b.contains(&0) {
                return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
            }
            if v.type_ != V_ASN1_UTF8STRING {
                return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
            }
            // SAFETY: a UTF8String value's member.
            let utf8 = unsafe { v.value.utf8string };
            // SAFETY: as above.
            code(ncons::email_eai(unsafe { octets(utf8) }, b))
        }
        t if t == GEN_DIRNAME => {
            // SAFETY: directory names' members.
            unsafe { nc_dn(gv.cast(), bv.cast()) }
        }
        // SAFETY: the names' strings.
        t if t == GEN_DNS => code(ncons::dns(unsafe { octets(gv) }, unsafe { octets(bv) })),
        // SAFETY: as above.
        t if t == GEN_EMAIL => code(ncons::email(unsafe { octets(gv) }, unsafe { octets(bv) })),
        // SAFETY: as above.
        t if t == GEN_URI => unsafe { nc_uri(gv, bv) },
        // SAFETY: as above.
        t if t == GEN_IPADD => code(ncons::ip(unsafe { octets(gv) }, unsafe { octets(bv) })),
        _ => X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE,
    }
}

/// `nc_minmax_valid`: no maximum, and a minimum of 0 if any.
fn minmax_valid(sub: &GENERAL_SUBTREE) -> bool {
    if !sub.maximum.is_null() {
        return false;
    }
    if sub.minimum.is_null() {
        return true;
    }
    let mut v: i64 = -1;
    // SAFETY: a local; the subtree's minimum.
    let ok = unsafe { ASN1_INTEGER_get_int64(&raw mut v, sub.minimum) } == 1;
    if !ok {
        // SAFETY: no preconditions; OpenSSL reads it as a BIGNUM, without an error.
        unsafe { crate::err::ERR_clear_error() };
    }
    ok && v == 0
}

/// Whether a subtree's base is of the name's (effective) type, and for other names, the same
/// one.
///
/// # Safety
/// `name` and `base` are live names.
unsafe fn same_type(effective_type: c_int, name: &GENERAL_NAME, base: &GENERAL_NAME) -> bool {
    if effective_type != base.type_ {
        return false;
    }
    if effective_type != GEN_OTHERNAME {
        return true;
    }
    // SAFETY: other names' members.
    let (a, b) = (unsafe { name.d.otherName }, unsafe { base.d.otherName });
    // SAFETY: as above.
    let (Some(a), Some(b)) = (unsafe { a.as_ref() }, unsafe { b.as_ref() }) else {
        return false;
    };
    // SAFETY: their types.
    unsafe { OBJ_cmp(a.type_id, b.type_id) == 0 }
}

/// The subtrees of a list.
///
/// # Safety
/// `sk` is NULL or a live list of subtrees, which outlives the iterator.
unsafe fn subtrees<'a>(
    sk: *const rustyssl_abi::stack_st_GENERAL_SUBTREE,
) -> impl Iterator<Item = &'a GENERAL_SUBTREE> {
    // SAFETY: the caller's guarantee.
    let n = unsafe { OPENSSL_sk_num(sk.cast()) };
    (0..n).filter_map(move |i| {
        // SAFETY: an index within the list.
        let p = unsafe { OPENSSL_sk_value(sk.cast(), i) }.cast::<GENERAL_SUBTREE>();
        // SAFETY: a subtree of the list.
        unsafe { p.as_ref() }
    })
}

/// `nc_match`: a name against the constraints.
///
/// # Safety
/// `name` is a live name; `nc` is live constraints.
unsafe fn nc_match(name: &GENERAL_NAME, nc: &NAME_CONSTRAINTS) -> c_int {
    let mut effective_type = name.type_;
    if effective_type == GEN_OTHERNAME {
        // SAFETY: an other name's member.
        let on = unsafe { name.d.otherName };
        // SAFETY: as above.
        let smtp = unsafe { on.as_ref() }.is_some_and(|o| {
            // SAFETY: its type.
            (unsafe { OBJ_obj2nid(o.type_id) }) == NID_id_on_SmtpUTF8Mailbox
        });
        if smtp {
            effective_type = GEN_EMAIL;
        }
    }
    let mut matched = 0;
    // SAFETY: the constraints' lists.
    for sub in unsafe { subtrees(nc.permittedSubtrees) } {
        // SAFETY: the subtree's base, live in a decoded subtree.
        let Some(base) = (unsafe { sub.base.as_ref() }) else {
            continue;
        };
        // SAFETY: the names.
        if !unsafe { same_type(effective_type, name, base) } {
            continue;
        }
        if !minmax_valid(sub) {
            return X509_V_ERR_SUBTREE_MINMAX;
        }
        if matched == 2 {
            continue;
        }
        if matched == 0 {
            matched = 1;
        }
        // SAFETY: as above.
        let r = unsafe { match_single(effective_type, name, base) };
        if r == X509_V_OK {
            matched = 2;
        } else if r != X509_V_ERR_PERMITTED_VIOLATION {
            return r;
        }
    }
    if matched == 1 {
        return X509_V_ERR_PERMITTED_VIOLATION;
    }
    // SAFETY: as above.
    for sub in unsafe { subtrees(nc.excludedSubtrees) } {
        // SAFETY: as above.
        let Some(base) = (unsafe { sub.base.as_ref() }) else {
            continue;
        };
        // SAFETY: as above.
        if !unsafe { same_type(effective_type, name, base) } {
            continue;
        }
        if !minmax_valid(sub) {
            return X509_V_ERR_SUBTREE_MINMAX;
        }
        // SAFETY: as above.
        let r = unsafe { match_single(effective_type, name, base) };
        if r == X509_V_OK {
            return X509_V_ERR_EXCLUDED_VIOLATION;
        } else if r != X509_V_ERR_PERMITTED_VIOLATION {
            return r;
        }
    }
    X509_V_OK
}

/// A name of `type_` holding `value` (only to be read).
fn temp_name(type_: c_int, value: *mut core::ffi::c_void) -> GENERAL_NAME {
    // SAFETY: an all-zero GENERAL_NAME is a valid (empty) value.
    let mut g: GENERAL_NAME = unsafe { core::mem::zeroed() };
    g.type_ = type_;
    g.d.ptr = value.cast();
    g
}

ffi_export! {
    /// Checks the certificate's subject (as a directory name, and its email addresses) and
    /// alternative names against the constraints: `X509_V_OK`, or the verification error.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `nc` is NULL or live constraints.
    pub unsafe extern "C" fn NAME_CONSTRAINTS_check(x: *mut X509, nc: *mut NAME_CONSTRAINTS) -> c_int
    where failure = X509_V_ERR_UNSPECIFIED, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(nc) = (unsafe { nc.as_ref() }) else { return X509_V_ERR_UNSPECIFIED };
        // SAFETY: as above.
        let nm = unsafe { X509_get_subject_name(x) };
        // SAFETY: as above.
        let altname = unsafe { cache_view(x) }.altname;
        // SAFETY: the subject, or NULL.
        let entries = unsafe { X509_NAME_entry_count(nm) }.max(0);
        // SAFETY: the alternative names, or NULL.
        let alts = unsafe { OPENSSL_sk_num(altname.cast()) }.max(0);
        // SAFETY: the constraints' lists.
        let permitted = unsafe { OPENSSL_sk_num(nc.permittedSubtrees.cast()) }.max(0);
        // SAFETY: as above.
        let excluded = unsafe { OPENSSL_sk_num(nc.excludedSubtrees.cast()) }.max(0);
        let (Some(name_count), Some(constraint_count)) = (entries.checked_add(alts), permitted.checked_add(excluded)) else {
            return X509_V_ERR_UNSPECIFIED;
        };
        if name_count > 0 && constraint_count > NAME_CHECK_MAX / name_count {
            return X509_V_ERR_UNSPECIFIED;
        }
        if entries > 0 {
            let dir = temp_name(GEN_DIRNAME, nm.cast());
            // SAFETY: a name over the subject; the constraints.
            let r = unsafe { nc_match(&dir, nc) };
            if r != X509_V_OK {
                return r;
            }
            let mut i = -1;
            loop {
                // SAFETY: the subject.
                i = unsafe { X509_NAME_get_index_by_NID(nm, NID_pkcs9_emailAddress, i) };
                if i == -1 {
                    break;
                }
                // SAFETY: an index within the subject.
                let ne = unsafe { X509_NAME_get_entry(nm, i) };
                // SAFETY: an entry of the subject.
                let data = unsafe { X509_NAME_ENTRY_get_data(ne) };
                // SAFETY: its string.
                if unsafe { data.as_ref() }.is_none_or(|d| d.type_ != V_ASN1_IA5STRING) {
                    return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
                }
                let email = temp_name(GEN_EMAIL, data.cast());
                // SAFETY: a name over the entry's string; the constraints.
                let r = unsafe { nc_match(&email, nc) };
                if r != X509_V_OK {
                    return r;
                }
            }
        }
        for i in 0..alts {
            // SAFETY: an index within the names.
            let g = unsafe { OPENSSL_sk_value(altname.cast(), i) }.cast::<GENERAL_NAME>();
            // SAFETY: a name of the list.
            let Some(g) = (unsafe { g.as_ref() }) else { continue };
            // SAFETY: as above.
            let r = unsafe { nc_match(g, nc) };
            if r != X509_V_OK {
                return r;
            }
        }
        X509_V_OK
    }
}

ffi_export! {
    /// Checks the subject's common names that look like DNS names (`cn2dnsid`) against the
    /// constraints' DNS subtrees: `X509_V_OK`, or the verification error.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `nc` is NULL or live constraints.
    pub unsafe extern "C" fn NAME_CONSTRAINTS_check_CN(x: *mut X509, nc: *mut NAME_CONSTRAINTS) -> c_int
    where failure = X509_V_ERR_UNSPECIFIED, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(nc) = (unsafe { nc.as_ref() }) else { return X509_V_ERR_UNSPECIFIED };
        // SAFETY: as above.
        let nm = unsafe { X509_get_subject_name(x) };
        let mut i = -1;
        loop {
            // SAFETY: the subject, or NULL.
            i = unsafe { X509_NAME_get_index_by_NID(nm, NID_commonName, i) };
            if i == -1 {
                return X509_V_OK;
            }
            // SAFETY: an index within the subject.
            let ne = unsafe { X509_NAME_get_entry(nm, i) };
            // SAFETY: an entry of the subject.
            let cn = unsafe { X509_NAME_ENTRY_get_data(ne) };
            let mut utf8: *mut u8 = ptr::null_mut();
            // SAFETY: a local slot; the entry's string.
            let len = unsafe { ASN1_STRING_to_UTF8(&raw mut utf8, cn) };
            let Ok(n) = usize::try_from(len) else { return X509_V_ERR_OUT_OF_MEM };
            let text: &[u8] = if utf8.is_null() {
                &[]
            } else {
                // SAFETY: the conversion's `n` octets.
                unsafe { core::slice::from_raw_parts(utf8, n) }
            };
            let id = ncons::cn_as_dns(text).map(|d| d.map(<[u8]>::to_vec));
            // SAFETY: the conversion's C memory.
            unsafe { mem::release(utf8.cast()) };
            let id = match id {
                Ok(Some(id)) => id,
                Ok(None) => continue,
                Err(m) => return code(m),
            };
            let mut stmp: ASN1_STRING = ASN1_STRING {
                length: c_int::try_from(id.len()).unwrap_or(0),
                type_: V_ASN1_IA5STRING,
                data: id.as_ptr().cast_mut(),
                flags: 0,
            };
            let dns = temp_name(GEN_DNS, (&raw mut stmp).cast());
            // SAFETY: a name over the local string; the constraints.
            let r = unsafe { nc_match(&dns, nc) };
            if r != X509_V_OK {
                return r;
            }
        }
    }
}
