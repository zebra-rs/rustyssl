//! Checking a certificate's identity (`v3_utl.c`): `X509_check_host`, `X509_check_email`,
//! `X509_check_ip` (and from text), against the subject alternative names, or the subject's
//! common names or email addresses when there are none of the type (or always, or never, as
//! the flags say); and the email addresses and OCSP responders a certificate or request names.
//!
//! The names are matched by `rustyssl_pki::identity`. As OpenSSL's:
//! - An expected name may end with a NUL but not hold one (that's -2, as is no name).
//! - Once an SmtpUTF8Mailbox other name has been seen, the email names after it compare as
//!   UTF-8 text, as it does (OpenSSL keeps the type it last compared).
//! - An IP address given with a length of 0 is a C string.

use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    _X509_CHECK_FLAG_DOT_SUBDOMAINS, ASN1_IA5STRING, ASN1_STRING, ERR_LIB_X509V3, GEN_DNS,
    GEN_EMAIL, GEN_IPADD, GEN_OTHERNAME, GEN_URI, GENERAL_NAME, GENERAL_NAMES, NID_ad_OCSP,
    NID_commonName, NID_id_on_SmtpUTF8Mailbox, NID_info_access, NID_pkcs9_emailAddress,
    NID_subject_alt_name, NID_undef, V_ASN1_IA5STRING, V_ASN1_OCTET_STRING, V_ASN1_UTF8STRING,
    X509, X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT, X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS,
    X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS,
    X509_CHECK_FLAG_NO_WILDCARDS, X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS, X509_NAME, X509_REQ,
    stack_st_OPENSSL_STRING,
};
use rustyssl_pki::identity::{HostFlags, equal_case, equal_email, equal_nocase, equal_wildcard};

use super::genn::GENERAL_NAMES_free;
use super::info::AUTHORITY_INFO_ACCESS_free;
use crate::asn1::text::ASN1_STRING_to_UTF8;
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::OBJ_obj2nid;
use crate::stack::{
    OPENSSL_sk_find, OPENSSL_sk_new, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_value,
};
use crate::x509::name::{
    X509_NAME_ENTRY_get_data, X509_NAME_get_entry, X509_NAME_get_index_by_NID,
};
use crate::x509::purpose::X509_get_ext_d2i;

/// A flag of `x509v3.h` (all positive) as the checks' `unsigned int`.
fn flag(v: c_int) -> c_uint {
    v.cast_unsigned()
}

/// A string's octets.
///
/// # Safety
/// `s` is a live string.
unsafe fn octets<'a>(s: &ASN1_STRING) -> &'a [u8] {
    match usize::try_from(s.length) {
        // SAFETY: a string's data holds its length.
        Ok(n) if n > 0 && !s.data.is_null() => unsafe { core::slice::from_raw_parts(s.data, n) },
        _ => &[],
    }
}

/// How names compare (OpenSSL's `equal_fn`s).
#[derive(Clone, Copy)]
enum Equal {
    Email,
    NoCase,
    Wildcard,
    Case,
}

impl Equal {
    fn matches(self, pattern: &[u8], subject: &[u8], flags: c_uint) -> bool {
        let f = HostFlags {
            no_partial_wildcards: flags & flag(X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS) != 0,
            multi_label_wildcards: flags & flag(X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS) != 0,
            single_label_subdomains: flags & flag(X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS) != 0,
            dot_subdomains: flags & flag(_X509_CHECK_FLAG_DOT_SUBDOMAINS) != 0,
        };
        match self {
            Self::Email => equal_email(pattern, subject),
            Self::NoCase => equal_nocase(pattern, subject, f),
            Self::Wildcard => equal_wildcard(pattern, subject, f),
            Self::Case => equal_case(pattern, subject, f),
        }
    }
}

/// A copy of `octets` and a NUL, in C memory, or NULL.
fn c_copy(octets: &[u8]) -> *mut c_char {
    let Some(n) = octets.len().checked_add(1) else {
        return ptr::null_mut();
    };
    let p = mem::alloc(n).cast::<u8>();
    if !p.is_null() {
        // SAFETY: the new block holds `n` octets.
        let block = unsafe { core::slice::from_raw_parts_mut(p, n) };
        if let Some((last, body)) = block.split_last_mut() {
            body.copy_from_slice(octets);
            *last = 0;
        }
    }
    p.cast()
}

/// `do_check_string`: whether the name `a` matches `b`: by octets for its type (`cmp_type`,
/// IA5 strings by `equal`), or (for `cmp_type` 0 or less) as UTF-8 text; 1, 0, or -1 on
/// failure. A match's name goes to `*peername` (C memory) if asked.
///
/// # Safety
/// `a` is a live string; `peername` is NULL or writable.
unsafe fn check_string(
    a: &ASN1_STRING,
    cmp_type: c_int,
    equal: Equal,
    flags: c_uint,
    b: &[u8],
    peername: *mut *mut c_char,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let data = unsafe { octets(a) };
    if data.is_empty() {
        return 0;
    }
    if cmp_type > 0 {
        if cmp_type != a.type_ {
            return 0;
        }
        let rv = if cmp_type == V_ASN1_IA5STRING {
            equal.matches(data, b, flags)
        } else {
            data == b
        };
        if rv && !peername.is_null() {
            let copy = c_copy(data);
            if copy.is_null() {
                return -1;
            }
            // SAFETY: the caller's slot.
            unsafe { *peername = copy };
        }
        return c_int::from(rv);
    }
    let mut astr: *mut u8 = ptr::null_mut();
    // SAFETY: a local slot; the caller's string.
    let astrlen = unsafe { ASN1_STRING_to_UTF8(&raw mut astr, a) };
    let Ok(n) = usize::try_from(astrlen) else {
        return -1;
    };
    let text: &[u8] = if astr.is_null() {
        &[]
    } else {
        // SAFETY: the conversion's `n` octets.
        unsafe { core::slice::from_raw_parts(astr, n) }
    };
    let rv = equal.matches(text, b, flags);
    let mut ret = c_int::from(rv);
    if rv && !peername.is_null() {
        let copy = c_copy(text);
        if copy.is_null() {
            ret = -1;
        } else {
            // SAFETY: the caller's slot.
            unsafe { *peername = copy };
        }
    }
    // SAFETY: the conversion's C memory, or NULL.
    unsafe { mem::release(astr.cast()) };
    ret
}

/// `do_x509_check`: checks `chk` against the certificate's names of `check_type` (`GEN_DNS`,
/// `GEN_EMAIL`, `GEN_IPADD`), then, for hosts and emails without such a name (or with
/// `X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT`), its subject's: 1, 0, or -1 on failure.
///
/// # Safety
/// `x` is NULL or a live certificate; `peername` is NULL or writable.
unsafe fn do_check(
    x: *mut X509,
    chk: &[u8],
    flags: c_uint,
    check_type: c_int,
    peername: *mut *mut c_char,
) -> c_int {
    let mut flags = flags & !flag(_X509_CHECK_FLAG_DOT_SUBDOMAINS);
    let (cnid, mut alt_type, equal) = match check_type {
        t if t == GEN_EMAIL => (NID_pkcs9_emailAddress, V_ASN1_IA5STRING, Equal::Email),
        t if t == GEN_DNS => {
            if chk.len() > 1 && chk.first() == Some(&b'.') {
                flags |= flag(_X509_CHECK_FLAG_DOT_SUBDOMAINS);
            }
            let equal = if flags & flag(X509_CHECK_FLAG_NO_WILDCARDS) != 0 {
                Equal::NoCase
            } else {
                Equal::Wildcard
            };
            (NID_commonName, V_ASN1_IA5STRING, equal)
        }
        _ => (NID_undef, V_ASN1_OCTET_STRING, Equal::Case),
    };
    // SAFETY: the caller's certificate, or NULL; no outputs.
    let gens =
        unsafe { X509_get_ext_d2i(x, NID_subject_alt_name, ptr::null_mut(), ptr::null_mut()) }
            .cast::<GENERAL_NAMES>();
    if !gens.is_null() {
        let mut rv = 0;
        let mut san_present = false;
        // SAFETY: the decoded names.
        let n = unsafe { OPENSSL_sk_num(gens.cast()) };
        for i in 0..n {
            // SAFETY: an index within the names.
            let gn = unsafe { OPENSSL_sk_value(gens.cast(), i) }.cast::<GENERAL_NAME>();
            // SAFETY: a name of the list.
            let Some(g) = (unsafe { gn.as_ref() }) else {
                continue;
            };
            // SAFETY: the name's member, as its type says (`d.ptr` is each pointer).
            let member = unsafe { g.d.ptr }.cast::<ASN1_STRING>();
            let cstr: *const ASN1_STRING = match g.type_ {
                t if t == GEN_OTHERNAME => {
                    // SAFETY: the union's member, as its type says.
                    let onp = unsafe { g.d.otherName };
                    // SAFETY: an other name's member.
                    let Some(on) = (unsafe { onp.as_ref() }) else {
                        continue;
                    };
                    // SAFETY: its type.
                    if unsafe { OBJ_obj2nid(on.type_id) } != NID_id_on_SmtpUTF8Mailbox {
                        continue;
                    }
                    // SAFETY: its value.
                    let Some(v) = (unsafe { on.value.as_ref() }) else {
                        continue;
                    };
                    if check_type != GEN_EMAIL || v.type_ != V_ASN1_UTF8STRING {
                        continue;
                    }
                    alt_type = 0;
                    // SAFETY: the value's member, a UTF8String.
                    unsafe { v.value.utf8string }.cast_const()
                }
                t if (t == GEN_EMAIL || t == GEN_DNS || t == GEN_IPADD) && t == check_type => {
                    member.cast_const()
                }
                _ => continue,
            };
            san_present = true;
            // SAFETY: the name's string, or NULL.
            let Some(s) = (unsafe { cstr.as_ref() }) else {
                continue;
            };
            // SAFETY: as above; the caller's slot.
            rv = unsafe { check_string(s, alt_type, equal, flags, chk, peername) };
            if rv != 0 {
                break;
            }
        }
        // SAFETY: decoded above.
        unsafe { GENERAL_NAMES_free(gens) };
        if rv != 0 {
            return rv;
        }
        if san_present && flags & flag(X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT) == 0 {
            return 0;
        }
    }
    if cnid == NID_undef || flags & flag(X509_CHECK_FLAG_NEVER_CHECK_SUBJECT) != 0 {
        return 0;
    }
    // SAFETY: the caller's certificate, or NULL.
    let name = unsafe { crate::x509::cert::X509_get_subject_name(x) };
    let mut i = -1;
    loop {
        // SAFETY: the certificate's name, or NULL.
        i = unsafe { X509_NAME_get_index_by_NID(name, cnid, i) };
        if i < 0 {
            return 0;
        }
        // SAFETY: an index within the name.
        let ne = unsafe { X509_NAME_get_entry(name, i) };
        // SAFETY: an entry of the name.
        let s = unsafe { X509_NAME_ENTRY_get_data(ne) };
        // SAFETY: the entry's string, or NULL.
        let Some(s) = (unsafe { s.as_ref() }) else {
            continue;
        };
        // SAFETY: as above; the caller's slot.
        let rv = unsafe { check_string(s, -1, equal, flags, chk, peername) };
        if rv != 0 {
            return rv;
        }
    }
}

/// The expected name: `chklen` octets (a C string for 0), one trailing NUL dropped; `None`
/// (-2) for NULL or a NUL inside.
///
/// # Safety
/// `chk` is NULL, a C string for a `chklen` of 0, or holds `chklen` octets.
unsafe fn expected<'a>(chk: *const c_char, chklen: usize) -> Option<&'a [u8]> {
    if chk.is_null() {
        return None;
    }
    let text: &[u8] = if chklen == 0 {
        // SAFETY: the caller's guarantee.
        unsafe { CStr::from_ptr(chk) }.to_bytes()
    } else {
        // SAFETY: as above.
        let t = unsafe { core::slice::from_raw_parts(chk.cast::<u8>(), chklen) };
        let body = if chklen > 1 { chklen - 1 } else { chklen };
        if t.get(..body).unwrap_or(t).contains(&0) {
            return None;
        }
        t
    };
    Some(match text.split_last() {
        Some((0, rest)) if text.len() > 1 => rest,
        _ => text,
    })
}

ffi_export! {
    /// Checks the certificate against the host name `chk` (see `X509_check_host(3)`): 1 for a
    /// match (its name in `*peername`, C memory, if asked), 0 for none, -1 on failure, -2 for
    /// a malformed name.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `chk` is NULL, a C string for a `chklen` of 0, or
    /// holds `chklen` octets; `peername` is NULL or writable.
    pub unsafe extern "C" fn X509_check_host(x: *mut X509, chk: *const c_char, chklen: usize, flags: c_uint, peername: *mut *mut c_char) -> c_int
    where failure = -1, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(name) = (unsafe { expected(chk, chklen) }) else { return -2 };
        // SAFETY: as above.
        unsafe { do_check(x, name, flags, GEN_DNS, peername) }
    }
}

ffi_export! {
    /// Checks the certificate against the email address `chk`: 1, 0, -1, or -2, as
    /// `X509_check_host`.
    ///
    /// # Safety
    /// As for [`X509_check_host`], without a peer name.
    pub unsafe extern "C" fn X509_check_email(x: *mut X509, chk: *const c_char, chklen: usize, flags: c_uint) -> c_int
    where failure = -1, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(name) = (unsafe { expected(chk, chklen) }) else { return -2 };
        // SAFETY: as above.
        unsafe { do_check(x, name, flags, GEN_EMAIL, ptr::null_mut()) }
    }
}

ffi_export! {
    /// Checks the certificate against the IP address `chk` (`chklen` octets; a C string's for
    /// 0): 1, 0, -1, or -2 for NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `chk` is NULL, a C string for a `chklen` of 0, or
    /// holds `chklen` octets.
    pub unsafe extern "C" fn X509_check_ip(x: *mut X509, chk: *const u8, chklen: usize, flags: c_uint) -> c_int
    where failure = -1, library = ERR_LIB_X509V3
    {
        if chk.is_null() {
            return -2;
        }
        let ip: &[u8] = if chklen == 0 {
            // SAFETY: the caller's guarantee.
            unsafe { CStr::from_ptr(chk.cast()) }.to_bytes()
        } else {
            // SAFETY: as above.
            unsafe { core::slice::from_raw_parts(chk, chklen) }
        };
        // SAFETY: as above.
        unsafe { do_check(x, ip, flags, GEN_IPADD, ptr::null_mut()) }
    }
}

ffi_export! {
    /// Checks the certificate against the IP address written `ipasc` (`ossl_a2i_ipadd`): 1,
    /// 0, -1, or -2 for none.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `ipasc` is NULL or a C string.
    pub unsafe extern "C" fn X509_check_ip_asc(x: *mut X509, ipasc: *const c_char, flags: c_uint) -> c_int
    where failure = -1, library = ERR_LIB_X509V3
    {
        if ipasc.is_null() {
            return -2;
        }
        // SAFETY: the caller's C string.
        let Some(ip) = rustyssl_pki::ip::parse(unsafe { CStr::from_ptr(ipasc) }.to_bytes()) else { return -2 };
        // SAFETY: the caller's guarantee.
        unsafe { do_check(x, &ip, flags, GEN_IPADD, ptr::null_mut()) }
    }
}

// Email addresses and OCSP responders.

/// `X509_EXTENSION_free` as a list's free function.
unsafe extern "C" fn ext_free(e: *mut c_void) {
    // SAFETY: an extension of the list, which the list owned.
    unsafe { crate::x509::ext::X509_EXTENSION_free(e.cast()) };
}

/// `sk_strcmp`, the comparison of a list of strings.
unsafe extern "C" fn str_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: pointers to the list's C strings.
    let sa = unsafe { *a.cast::<*const c_char>() };
    // SAFETY: as above.
    let sb = unsafe { *b.cast::<*const c_char>() };
    // SAFETY: the list's C strings.
    unsafe { libc::strcmp(sa, sb) }
}

/// `str_free`, as a list's free function.
unsafe extern "C" fn str_free(s: *mut c_void) {
    // SAFETY: a C string of the list, which the list owned.
    unsafe { mem::release(s) };
}

/// `append_ia5`: adds an IA5 string (not empty, without a NUL) to `*sk` unless it's there:
/// true, or false (freeing the list) on failure.
///
/// # Safety
/// `sk` holds NULL or a live list of C strings; `email` is a live string.
unsafe fn append_ia5(sk: &mut *mut stack_st_OPENSSL_STRING, email: &ASN1_IA5STRING) -> bool {
    if email.type_ != V_ASN1_IA5STRING {
        return true;
    }
    // SAFETY: the caller's guarantee.
    let data = unsafe { octets(email) };
    if data.is_empty() || data.contains(&0) {
        return true;
    }
    if sk.is_null() {
        // SAFETY: our comparison, for C strings.
        *sk = unsafe { OPENSSL_sk_new(Some(str_cmp)) }.cast();
    }
    if sk.is_null() {
        return false;
    }
    let emtmp = c_copy(data);
    if emtmp.is_null() {
        // SAFETY: the list and its strings.
        unsafe { X509_email_free(*sk) };
        *sk = ptr::null_mut();
        return false;
    }
    // SAFETY: the list; the copy, as its elements are compared.
    if unsafe { OPENSSL_sk_find((*sk).cast(), emtmp.cast()) } != -1 {
        // SAFETY: made above.
        unsafe { mem::release(emtmp.cast()) };
        return true;
    }
    // SAFETY: the list; the copy, which it takes.
    if unsafe { OPENSSL_sk_push((*sk).cast(), emtmp.cast()) } == 0 {
        // SAFETY: as above.
        unsafe { mem::release(emtmp.cast()) };
        // SAFETY: the list and its strings.
        unsafe { X509_email_free(*sk) };
        *sk = ptr::null_mut();
        return false;
    }
    true
}

/// `get_email`: the email addresses of the name (`emailAddress`) and the names
/// (`rfc822Name`), each once, or NULL for none or on failure.
///
/// # Safety
/// `name` is NULL or a live name; `gens` is NULL or a live list of names.
unsafe fn get_email(
    name: *const X509_NAME,
    gens: *const GENERAL_NAMES,
) -> *mut stack_st_OPENSSL_STRING {
    let mut ret: *mut stack_st_OPENSSL_STRING = ptr::null_mut();
    let mut i = -1;
    loop {
        // SAFETY: the caller's name, or NULL.
        i = unsafe { X509_NAME_get_index_by_NID(name, NID_pkcs9_emailAddress, i) };
        if i < 0 {
            break;
        }
        // SAFETY: an index within the name.
        let ne = unsafe { X509_NAME_get_entry(name, i) };
        // SAFETY: an entry of the name.
        let data = unsafe { X509_NAME_ENTRY_get_data(ne) };
        // SAFETY: an entry of the name; its string.
        let Some(email) = (unsafe { data.as_ref() }) else {
            continue;
        };
        // SAFETY: the list; the string.
        if !unsafe { append_ia5(&mut ret, email) } {
            return ptr::null_mut();
        }
    }
    // SAFETY: the caller's names, or NULL.
    let n = unsafe { OPENSSL_sk_num(gens.cast()) };
    for j in 0..n {
        // SAFETY: an index within the names.
        let gn = unsafe { OPENSSL_sk_value(gens.cast(), j) }.cast::<GENERAL_NAME>();
        // SAFETY: a name of the list.
        let Some(g) = (unsafe { gn.as_ref() }) else {
            continue;
        };
        if g.type_ != GEN_EMAIL {
            continue;
        }
        // SAFETY: the union's member, as its type says.
        let ia5p = unsafe { g.d.ia5 };
        // SAFETY: an email name's member.
        let Some(ia5) = (unsafe { ia5p.as_ref() }) else {
            continue;
        };
        // SAFETY: as above.
        if !unsafe { append_ia5(&mut ret, ia5) } {
            return ptr::null_mut();
        }
    }
    ret
}

ffi_export! {
    /// The certificate's email addresses (its subject's, then its alternative names'), each
    /// once, for `X509_email_free`; NULL for none.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_get1_email(x: *mut X509) -> *mut stack_st_OPENSSL_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's certificate, or NULL; no outputs.
        let gens = unsafe { X509_get_ext_d2i(x, NID_subject_alt_name, ptr::null_mut(), ptr::null_mut()) }.cast::<GENERAL_NAMES>();
        // SAFETY: as above.
        let name = unsafe { crate::x509::cert::X509_get_subject_name(x) };
        // SAFETY: the certificate's name and names.
        let ret = unsafe { get_email(name, gens) };
        // SAFETY: decoded above, or NULL.
        unsafe { GENERAL_NAMES_free(gens) };
        ret
    }
}

ffi_export! {
    /// The request's email addresses (its subject's, then its alternative names'), each once,
    /// for `X509_email_free`; NULL for none.
    ///
    /// # Safety
    /// `x` is NULL or a live request.
    pub unsafe extern "C" fn X509_REQ_get1_email(x: *mut X509_REQ) -> *mut stack_st_OPENSSL_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's request, or NULL.
        let exts = unsafe { crate::x509::req::X509_REQ_get_extensions(x) };
        // SAFETY: its extensions, or NULL; no outputs.
        let gens = unsafe { super::registry::X509V3_get_d2i(exts, NID_subject_alt_name, ptr::null_mut(), ptr::null_mut()) }.cast::<GENERAL_NAMES>();
        // SAFETY: as above.
        let name = unsafe { crate::x509::req::X509_REQ_get_subject_name(x) };
        // SAFETY: the request's name and names.
        let ret = unsafe { get_email(name, gens) };
        // SAFETY: decoded above, or NULL.
        unsafe { GENERAL_NAMES_free(gens) };
        // SAFETY: the request's extensions, a copy, and its entries.
        unsafe { OPENSSL_sk_pop_free(exts.cast(), Some(ext_free)) };
        ret
    }
}

ffi_export! {
    /// The URIs of the certificate's OCSP responders (its authority information access), each
    /// once; NULL for none.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_get1_ocsp(x: *mut X509) -> *mut stack_st_OPENSSL_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's certificate, or NULL; no outputs.
        let info = unsafe { X509_get_ext_d2i(x, NID_info_access, ptr::null_mut(), ptr::null_mut()) };
        if info.is_null() {
            return ptr::null_mut();
        }
        let mut ret: *mut stack_st_OPENSSL_STRING = ptr::null_mut();
        // SAFETY: the decoded access descriptions.
        let n = unsafe { OPENSSL_sk_num(info.cast()) };
        for i in 0..n {
            // SAFETY: an index within the list.
            let ad = unsafe { OPENSSL_sk_value(info.cast(), i) }.cast::<rustyssl_abi::ACCESS_DESCRIPTION>();
            // SAFETY: a description of the list.
            let Some(ad) = (unsafe { ad.as_ref() }) else { continue };
            // SAFETY: its method.
            if unsafe { OBJ_obj2nid(ad.method) } != NID_ad_OCSP {
                continue;
            }
            // SAFETY: its location.
            let Some(loc) = (unsafe { ad.location.as_ref() }) else { continue };
            if loc.type_ != GEN_URI {
                continue;
            }
            // SAFETY: the union's member, as its type says.
            let urip = unsafe { loc.d.uniformResourceIdentifier };
            // SAFETY: a URI name's member.
            let Some(uri) = (unsafe { urip.as_ref() }) else { continue };
            // SAFETY: the list; the URI.
            if !unsafe { append_ia5(&mut ret, uri) } {
                break;
            }
        }
        // SAFETY: decoded above.
        unsafe { AUTHORITY_INFO_ACCESS_free(info.cast()) };
        ret
    }
}

ffi_export! {
    /// Frees a list of email addresses or URIs (nothing for NULL).
    ///
    /// # Safety
    /// `sk` is NULL or a list from `X509_get1_email` and the others, not otherwise used after.
    pub unsafe extern "C" fn X509_email_free(sk: *mut stack_st_OPENSSL_STRING)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { OPENSSL_sk_pop_free(sk.cast(), Some(str_free)) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_certificates_match_nothing() {
        let x: *mut X509 = ptr::null_mut();
        // SAFETY: NULL where OpenSSL dereferences it; a C string.
        let r = unsafe { X509_check_host(x, c"a.example".as_ptr(), 0, 0, ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { X509_check_email(x, c"a@example".as_ptr(), 0, 0) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        assert!(unsafe { X509_get1_email(x) }.is_null());
    }
}
