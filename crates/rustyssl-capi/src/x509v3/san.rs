//! Alternative names (`v3_san.c`, and the IP address functions of `v3_utl.c`): the subject's
//! and issuer's alternative names and a CRL entry's certificate issuer, as GeneralNames; each
//! name as `CONF_VALUE`s and printed; names made from `type:value` text, with `email:copy` and
//! `email:move` (from the subject) and `issuer:copy` (from the issuer's alternative names);
//! and IP addresses and networks as text.
//!
//! A directory name is read from a section of the context's configuration. An other name's
//! value is `ASN1_generate_v3` text, which comes with step 6.1: making one aborts until then
//! (AGENTS.md rule 10).

use core::ffi::{CStr, c_char, c_int};
use core::ptr;

use rustyssl_abi::{
    ASN1_OCTET_STRING, ASN1_STRING, BIO, CONF_VALUE, ERR_LIB_X509V3, ERR_R_ASN1_LIB,
    ERR_R_CRYPTO_LIB, GEN_DIRNAME, GEN_DNS, GEN_EDIPARTY, GEN_EMAIL, GEN_IPADD, GEN_OTHERNAME,
    GEN_RID, GEN_URI, GEN_X400, GENERAL_NAME, GENERAL_NAMES, MBSTRING_ASC, NID_NAIRealm,
    NID_SRVName, NID_XmppAddr, NID_certificate_issuer, NID_id_on_SmtpUTF8Mailbox,
    NID_issuer_alt_name, NID_ms_upn, NID_pkcs9_emailAddress, NID_subject_alt_name,
    V_ASN1_IA5STRING, V_ASN1_UTF8STRING, X509V3_CTX, X509V3_CTX_TEST, X509V3_EXT_METHOD,
    X509V3_R_BAD_IP_ADDRESS, X509V3_R_BAD_OBJECT, X509V3_R_DIRNAME_ERROR,
    X509V3_R_ISSUER_DECODE_ERROR, X509V3_R_MISSING_VALUE, X509V3_R_NO_ISSUER_DETAILS,
    X509V3_R_NO_SUBJECT_DETAILS, X509V3_R_OTHERNAME_ERROR, X509V3_R_SECTION_NOT_FOUND,
    X509V3_R_UNSUPPORTED_OPTION, X509V3_R_UNSUPPORTED_TYPE, XN_FLAG_ONELINE, stack_st_CONF_VALUE,
};

use super::ctx::{X509V3_NAME_from_section, X509V3_get_section, X509V3_section_free};
use super::genn::{GENERAL_NAME_free, GENERAL_NAME_new, GENERAL_NAMES_it};
use super::registry::{Method, X509V3_EXT_d2i, method};
use super::{X509V3_add_value, add_value};
use crate::asn1::string::{
    ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set, ASN1_STRING_dup,
    ASN1_STRING_free, ASN1_STRING_set, ASN1_STRING_type_new,
};
use crate::asn1::text::ASN1_STRING_print;
use crate::bio::print::BIO_printf;
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::objects::{OBJ_obj2nid, OBJ_obj2txt, OBJ_txt2obj, i2a_ASN1_OBJECT, i2t_ASN1_OBJECT};
use crate::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_reserve, OPENSSL_sk_value,
};
use crate::x509::cert::{X509_get_ext, X509_get_ext_by_NID, X509_get_subject_name};
use crate::x509::name::{
    X509_NAME_ENTRY_free, X509_NAME_ENTRY_get_data, X509_NAME_delete_entry, X509_NAME_free,
    X509_NAME_get_entry, X509_NAME_get_index_by_NID, X509_NAME_new, X509_NAME_oneline,
    X509_NAME_print_ex,
};
use crate::x509::req::X509_REQ_get_subject_name;

/// A C string's bytes, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a C string.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) }.to_bytes())
}

/// A string's octets (empty for none).
///
/// # Safety
/// `s` is NULL or a live string whose data holds its length.
unsafe fn octets<'a>(s: *const ASN1_STRING) -> &'a [u8] {
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { s.as_ref() }) else {
        return &[];
    };
    match usize::try_from(s.length) {
        // SAFETY: as above.
        Ok(n) if n > 0 && !s.data.is_null() => unsafe { core::slice::from_raw_parts(s.data, n) },
        _ => &[],
    }
}

/// `x509v3_add_len_value_uchar`: adds `name` with `value`'s octets, refusing a value with a
/// NUL in it.
///
/// # Safety
/// `ret` holds NULL or a live stack.
unsafe fn add_len_value(name: &[u8], value: &[u8], ret: *mut *mut stack_st_CONF_VALUE) -> bool {
    if value.contains(&0) {
        return false;
    }
    // SAFETY: the caller's guarantee.
    unsafe { add_value(Some(name), Some(value), ret) }
}

/// `ossl_v3_name_cmp`: whether `name` is `cmp`, or `cmp` followed by `.` and anything.
fn name_is(name: Option<&[u8]>, cmp: &[u8]) -> bool {
    name.and_then(|n| n.strip_prefix(cmp))
        .is_some_and(|rest| rest.first().is_none_or(|&c| c == b'.'))
}

/// `ossl_ipaddr_to_asc` in C memory.
fn ip_text(octets: &[u8]) -> *mut c_char {
    let t = rustyssl_pki::ip::to_text(octets);
    crate::conf::c_dup(t.as_bytes())
}

/// `X509V3_conf_free` as a stack's free function.
unsafe extern "C" fn free_conf(c: *mut core::ffi::c_void) {
    // SAFETY: a `CONF_VALUE` of the stack, which the stack owned.
    unsafe { super::X509V3_conf_free(c.cast()) };
}

/// `GENERAL_NAME_free` as a stack's free function.
pub(crate) unsafe extern "C" fn free_gen(g: *mut core::ffi::c_void) {
    // SAFETY: a name of the stack, which the stack owned.
    unsafe { GENERAL_NAME_free(g.cast()) };
}

ffi_export! {
    /// Each name of `gens` as `CONF_VALUE`s ([`i2v_GENERAL_NAME`]) added to `ret` (made if
    /// NULL, and an empty one for no names), or NULL (freeing a list made here).
    ///
    /// # Safety
    /// `gens` is a live stack of names; `ret` is NULL or a live stack.
    pub unsafe extern "C" fn i2v_GENERAL_NAMES(method: *mut X509V3_EXT_METHOD, gens: *mut GENERAL_NAMES, ret: *mut stack_st_CONF_VALUE) -> *mut stack_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        let origret = ret;
        let mut ret = ret;
        // SAFETY: the caller's stack.
        let n = unsafe { OPENSSL_sk_num(gens.cast()) };
        for i in 0..n {
            // SAFETY: an index within the stack.
            let gname = unsafe { OPENSSL_sk_value(gens.cast(), i) }.cast::<GENERAL_NAME>();
            // SAFETY: a name of the stack; the list.
            let tmp = unsafe { i2v_GENERAL_NAME(method, gname, ret) };
            if tmp.is_null() {
                if origret.is_null() {
                    // SAFETY: the list made here, with its entries.
                    unsafe { OPENSSL_sk_pop_free(ret.cast(), Some(free_conf)) };
                }
                return ptr::null_mut();
            }
            ret = tmp;
        }
        if ret.is_null() {
            // SAFETY: no preconditions.
            return unsafe { crate::stack::OPENSSL_sk_new_null() }.cast();
        }
        ret
    }
}

ffi_export! {
    /// The name as a `CONF_VALUE` (`email:…`, `DNS:…`, `IP Address:…`, `DirName:…`, the known
    /// other names, `<unsupported>` for the rest) added to `ret` (made if NULL), or NULL.
    ///
    /// # Safety
    /// `gname` is a live name; `ret` is NULL or a live stack.
    pub unsafe extern "C" fn i2v_GENERAL_NAME(_method: *mut X509V3_EXT_METHOD, gname: *mut GENERAL_NAME, ret: *mut stack_st_CONF_VALUE) -> *mut stack_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { gname.as_ref() }) else { return ptr::null_mut() };
        let mut ret = ret;
        let list = &raw mut ret;
        // SAFETY: every alternative is a pointer at the same place.
        let p = unsafe { g.d.ptr };
        let string = |label: &[u8]| {
            // SAFETY: the name's string.
            let o = unsafe { octets(p.cast()) };
            // SAFETY: the list.
            unsafe { add_len_value(label, o, list) }
        };
        let ok = match g.type_ {
            // SAFETY: an other name; the list.
            GEN_OTHERNAME => unsafe { other_i2v(g, list) },
            // SAFETY: the list.
            GEN_X400 => unsafe { add_value(Some(b"X400Name"), Some(b"<unsupported>"), list) },
            // SAFETY: as above.
            GEN_EDIPARTY => unsafe { add_value(Some(b"EdiPartyName"), Some(b"<unsupported>"), list) },
            GEN_EMAIL => string(b"email"),
            GEN_DNS => string(b"DNS"),
            GEN_URI => string(b"URI"),
            GEN_DIRNAME => {
                let mut oline = [0 as c_char; 256];
                // SAFETY: the directory name; room for 256 octets.
                let made = !unsafe { X509_NAME_oneline(p.cast(), oline.as_mut_ptr(), 256) }.is_null();
                // SAFETY: a static name; the text; the list.
                made && unsafe { X509V3_add_value(c"DirName".as_ptr(), oline.as_ptr(), list) } != 0
            }
            GEN_IPADD => {
                // SAFETY: the IP address.
                let t = ip_text(unsafe { octets(p.cast()) });
                // SAFETY: as above.
                let ok = !t.is_null() && unsafe { X509V3_add_value(c"IP Address".as_ptr(), t, list) } != 0;
                // SAFETY: made above.
                unsafe { mem::release(t.cast()) };
                ok
            }
            GEN_RID => {
                let mut oline = [0 as c_char; 256];
                // SAFETY: room for 256 octets; the object.
                unsafe { i2t_ASN1_OBJECT(oline.as_mut_ptr(), 256, p.cast()) };
                // SAFETY: as above.
                (unsafe { X509V3_add_value(c"Registered ID".as_ptr(), oline.as_ptr(), list) } != 0)
            }
            _ => true,
        };
        if ok { ret } else { ptr::null_mut() }
    }
}

/// The known other names' labels, and whether their values are IA5Strings (else UTF8Strings).
const OTHERNAMES: [(c_int, &[u8], bool); 5] = [
    (NID_id_on_SmtpUTF8Mailbox, b"SmtpUTF8Mailbox", false),
    (NID_XmppAddr, b"XmppAddr", false),
    (NID_SRVName, b"SRVName", true),
    (NID_ms_upn, b"UPN", false),
    (NID_NAIRealm, b"NAIRealm", false),
];

/// `i2v_GENERAL_NAME` of an other name.
///
/// # Safety
/// `g` is a live other name; `list` holds NULL or a live stack.
unsafe fn other_i2v(g: &GENERAL_NAME, list: *mut *mut stack_st_CONF_VALUE) -> bool {
    // SAFETY: the caller's guarantee.
    let op = unsafe { g.d.otherName };
    // SAFETY: the other name.
    let Some(o) = (unsafe { op.as_ref() }) else {
        return false;
    };
    // SAFETY: its object.
    let nid = unsafe { OBJ_obj2nid(o.type_id) };
    // SAFETY: its value.
    let Some(v) = (unsafe { o.value.as_ref() }) else {
        return false;
    };
    // SAFETY: a string value's string.
    let s = unsafe { v.value.asn1_string };
    if let Some(&(_, label, ia5)) = OTHERNAMES.iter().find(|k| k.0 == nid) {
        let want = if ia5 {
            V_ASN1_IA5STRING
        } else {
            V_ASN1_UTF8STRING
        };
        if v.type_ != want {
            return false;
        }
        let mut name = b"othername: ".to_vec();
        name.extend_from_slice(label);
        // SAFETY: the value's string.
        let o = unsafe { octets(s) };
        // SAFETY: the caller's list.
        return unsafe { add_len_value(&name, o, list) };
    }
    let mut oline = [0 as c_char; 256];
    // SAFETY: room for 256 octets; the object.
    let n = unsafe { OBJ_obj2txt(oline.as_mut_ptr(), 256, o.type_id, 0) };
    let mut name = b"othername".to_vec();
    if n > 0 {
        name.extend_from_slice(b": ");
        // SAFETY: NUL-terminated by `OBJ_obj2txt`.
        name.extend_from_slice(unsafe { CStr::from_ptr(oline.as_ptr()) }.to_bytes());
        // As OpenSSL's 300-octet buffer cuts it.
        name.truncate(299);
    }
    if v.type_ == V_ASN1_IA5STRING || v.type_ == V_ASN1_UTF8STRING {
        // SAFETY: a string value's string.
        let so = unsafe { octets(s) };
        // SAFETY: the caller's list.
        if unsafe { add_len_value(&name, so, list) } {
            return true;
        }
    }
    // SAFETY: the caller's list.
    unsafe { add_value(Some(&name), Some(b"<unsupported>"), list) }
}

ffi_export! {
    /// Prints the name on one line (`DNS:…`, `IP Address:…`, `DirName:` and the one-line name,
    /// the known other names, `<unsupported>` for the rest): 1, or 0.
    ///
    /// # Safety
    /// `out` is a live BIO; `gname` is a live name.
    pub unsafe extern "C" fn GENERAL_NAME_print(out: *mut BIO, gname: *mut GENERAL_NAME) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { gname.as_ref() }) else { return 0 };
        let puts = |s: &CStr| {
            // SAFETY: the caller's BIO; a static format.
            unsafe { BIO_printf(out, s.as_ptr()) };
        };
        // SAFETY: every alternative is a pointer at the same place.
        let p = unsafe { g.d.ptr };
        let string = |label: &CStr| {
            puts(label);
            // SAFETY: the name's string.
            unsafe { ASN1_STRING_print(out, p.cast()) };
        };
        match g.type_ {
            GEN_OTHERNAME => {
                // SAFETY: the other name.
                let Some(o) = (unsafe { p.cast::<rustyssl_abi::OTHERNAME>().as_ref() }) else { return 1 };
                // SAFETY: its object.
                let nid = unsafe { OBJ_obj2nid(o.type_id) };
                // SAFETY: its value.
                let Some(v) = (unsafe { o.value.as_ref() }) else { return 1 };
                let want = if nid == NID_SRVName { V_ASN1_IA5STRING } else { V_ASN1_UTF8STRING };
                match OTHERNAMES.iter().find(|k| k.0 == nid) {
                    Some(&(_, label, _)) if v.type_ == want => {
                        // SAFETY: a string value's string.
                        let s = unsafe { v.value.asn1_string };
                        // SAFETY: as above.
                        let (len, data) = unsafe { s.as_ref() }.map_or((0, ptr::null_mut()), |s| (s.length, s.data));
                        let label = core::str::from_utf8(label).unwrap_or_default();
                        let fmt = std::ffi::CString::new(format!("othername:{label}:%.*s")).unwrap_or_default();
                        // SAFETY: the caller's BIO; a format and its arguments.
                        unsafe { BIO_printf(out, fmt.as_ptr(), len, data) };
                    }
                    _ => puts(c"othername:<unsupported>"),
                }
            }
            GEN_X400 => puts(c"X400Name:<unsupported>"),
            GEN_EDIPARTY => puts(c"EdiPartyName:<unsupported>"),
            GEN_EMAIL => string(c"email:"),
            GEN_DNS => string(c"DNS:"),
            GEN_URI => string(c"URI:"),
            GEN_DIRNAME => {
                puts(c"DirName:");
                let flags = core::ffi::c_ulong::from(XN_FLAG_ONELINE.cast_unsigned());
                // SAFETY: the caller's BIO; the directory name.
                unsafe { X509_NAME_print_ex(out, p.cast(), 0, flags) };
            }
            GEN_IPADD => {
                // SAFETY: the IP address.
                let t = ip_text(unsafe { octets(p.cast()) });
                if t.is_null() {
                    return 0;
                }
                // SAFETY: the caller's BIO; a static format and the text.
                unsafe { BIO_printf(out, c"IP Address:%s".as_ptr(), t) };
                // SAFETY: made above.
                unsafe { mem::release(t.cast()) };
            }
            GEN_RID => {
                puts(c"Registered ID:");
                // SAFETY: the caller's BIO; the object.
                unsafe { i2a_ASN1_OBJECT(out, p.cast()) };
            }
            _ => {}
        }
        1
    }
}

/// A new stack of names with room for `num`, or NULL with `ERR_R_CRYPTO_LIB`.
fn new_names(num: c_int, f: &str) -> *mut GENERAL_NAMES {
    // SAFETY: no preconditions.
    let gens = unsafe { OPENSSL_sk_new_reserve(None, num) };
    if gens.is_null() {
        err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, f);
    }
    gens.cast()
}

/// The `CONF_VALUE`s of a stack.
///
/// # Safety
/// `nval` is NULL or a live stack of `CONF_VALUE`s.
unsafe fn values<'a>(nval: *mut stack_st_CONF_VALUE) -> impl Iterator<Item = &'a CONF_VALUE> {
    // SAFETY: the caller's guarantee.
    let n = unsafe { OPENSSL_sk_num(nval.cast()) };
    // SAFETY: as above; an index within it.
    (0..n.max(0))
        .filter_map(move |i| unsafe { super::item_at::<CONF_VALUE>(nval.cast(), i) }.map(|v| &*v))
}

/// The names `cnf` makes pushed onto `gens`, through `v2i_GENERAL_NAME`.
///
/// # Safety
/// `gens` is a live stack with room; `cnf` a live `CONF_VALUE`; `ctx` NULL or live.
unsafe fn push_name(
    gens: *mut GENERAL_NAMES,
    method: *const X509V3_EXT_METHOD,
    ctx: *mut X509V3_CTX,
    cnf: &CONF_VALUE,
) -> bool {
    // SAFETY: the caller's guarantee.
    let gname = unsafe { v2i_GENERAL_NAME(method, ctx, ptr::from_ref(cnf).cast_mut()) };
    if gname.is_null() {
        return false;
    }
    // SAFETY: the stack, with room reserved; the name, which it takes.
    unsafe { OPENSSL_sk_push(gens.cast(), gname.cast()) };
    true
}

ffi_callback! {
    /// `v2i_issuer_alt`: each name, or the issuer's subject alternative names for `issuer:copy`.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `nval` is NULL or a live stack of `CONF_VALUE`s.
    pub(crate) unsafe extern "C" fn v2i_issuer_alt(method: *const X509V3_EXT_METHOD, ctx: *mut X509V3_CTX, nval: *mut stack_st_CONF_VALUE) -> *mut core::ffi::c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's stack, or NULL.
        let num = unsafe { OPENSSL_sk_num(nval.cast()) };
        let gens = new_names(num, "v2i_issuer_alt");
        if gens.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        for cnf in unsafe { values(nval) } {
            // SAFETY: the value's strings.
            let (name, value) = (unsafe { text(cnf.name) }, unsafe { text(cnf.value) });
            let ok = if name_is(name, b"issuer") && value == Some(b"copy") {
                // SAFETY: the caller's context; the stack.
                unsafe { copy_issuer(ctx, gens) }
            } else {
                // SAFETY: as above.
                unsafe { push_name(gens, method, ctx, cnf) }
            };
            if !ok {
                // SAFETY: the stack made above, with its names.
                unsafe { OPENSSL_sk_pop_free(gens.cast(), Some(free_gen)) };
                return ptr::null_mut();
            }
        }
        gens.cast()
    }
}

/// `copy_issuer`: the issuer certificate's subject alternative names appended to `gens`
/// (nothing in a test context, or without them).
///
/// # Safety
/// `ctx` is NULL or a live context; `gens` is a live stack of names.
unsafe fn copy_issuer(ctx: *mut X509V3_CTX, gens: *mut GENERAL_NAMES) -> bool {
    const F: &str = "copy_issuer";
    // SAFETY: the caller's guarantee.
    let c = unsafe { ctx.as_ref() };
    if c.is_some_and(|c| c.flags & X509V3_CTX_TEST != 0) {
        return true;
    }
    let Some(issuer) = c.map(|c| c.issuer_cert).filter(|i| !i.is_null()) else {
        err::raise(ERR_LIB_X509V3, X509V3_R_NO_ISSUER_DETAILS, F);
        return false;
    };
    // SAFETY: the context's certificate.
    let i = unsafe { X509_get_ext_by_NID(issuer, NID_subject_alt_name, -1) };
    if i < 0 {
        return true;
    }
    // SAFETY: as above; its extension's index.
    let ext = unsafe { X509_get_ext(issuer, i) };
    // SAFETY: the extension, or NULL.
    let ialt: *mut GENERAL_NAMES = if ext.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: the issuer's extension.
        unsafe { X509V3_EXT_d2i(ext) }.cast()
    };
    if ialt.is_null() {
        err::raise(ERR_LIB_X509V3, X509V3_R_ISSUER_DECODE_ERROR, F);
        return false;
    }
    // SAFETY: the decoded names.
    let num = unsafe { OPENSSL_sk_num(ialt.cast()) };
    // SAFETY: the caller's stack.
    let reserved = unsafe { OPENSSL_sk_reserve(gens.cast(), num) } != 0;
    if reserved {
        for j in 0..num {
            // SAFETY: an index within the decoded names.
            let g = unsafe { OPENSSL_sk_value(ialt.cast(), j) };
            // SAFETY: the stack, with room reserved; it takes the name.
            unsafe { OPENSSL_sk_push(gens.cast(), g) };
        }
    } else {
        err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, F);
    }
    // As OpenSSL's, the names moved over; only the stack goes (and, failing, the names leak).
    // SAFETY: the decoded stack.
    unsafe { OPENSSL_sk_free(ialt.cast()) };
    reserved
}

ffi_callback! {
    /// `v2i_subject_alt`: each name, or the subject's e-mail addresses for `email:copy` (and,
    /// for `email:move`, taken out of the subject).
    ///
    /// # Safety
    /// As for [`v2i_issuer_alt`].
    pub(crate) unsafe extern "C" fn v2i_subject_alt(method: *const X509V3_EXT_METHOD, ctx: *mut X509V3_CTX, nval: *mut stack_st_CONF_VALUE) -> *mut core::ffi::c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's stack, or NULL.
        let num = unsafe { OPENSSL_sk_num(nval.cast()) };
        let gens = new_names(num, "v2i_subject_alt");
        if gens.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        for cnf in unsafe { values(nval) } {
            // SAFETY: the value's strings.
            let (name, value) = (unsafe { text(cnf.name) }, unsafe { text(cnf.value) });
            let email = name_is(name, b"email");
            let ok = if email && value == Some(b"copy") {
                // SAFETY: the caller's context; the stack.
                unsafe { copy_email(ctx, gens, false) }
            } else if email && value == Some(b"move") {
                // SAFETY: as above.
                unsafe { copy_email(ctx, gens, true) }
            } else {
                // SAFETY: as above.
                unsafe { push_name(gens, method, ctx, cnf) }
            };
            if !ok {
                // SAFETY: the stack made above, with its names.
                unsafe { OPENSSL_sk_pop_free(gens.cast(), Some(free_gen)) };
                return ptr::null_mut();
            }
        }
        gens.cast()
    }
}

/// `copy_email`: each e-mail address of the subject (the context's certificate's or
/// request's) appended to `gens` as an e-mail name; `move_p` deletes them from the subject.
///
/// # Safety
/// `ctx` is NULL or a live context; `gens` is a live stack of names.
unsafe fn copy_email(ctx: *mut X509V3_CTX, gens: *mut GENERAL_NAMES, move_p: bool) -> bool {
    const F: &str = "copy_email";
    // SAFETY: the caller's guarantee.
    let c = unsafe { ctx.as_ref() };
    if c.is_some_and(|c| c.flags & X509V3_CTX_TEST != 0) {
        return true;
    }
    let nm = match c {
        // SAFETY: the context's certificate.
        Some(c) if !c.subject_cert.is_null() => unsafe { X509_get_subject_name(c.subject_cert) },
        // SAFETY: the context's request.
        Some(c) if !c.subject_req.is_null() => unsafe { X509_REQ_get_subject_name(c.subject_req) },
        _ => {
            err::raise(ERR_LIB_X509V3, X509V3_R_NO_SUBJECT_DETAILS, F);
            return false;
        }
    };
    let mut i = -1;
    loop {
        // SAFETY: the subject.
        i = unsafe { X509_NAME_get_index_by_NID(nm, NID_pkcs9_emailAddress, i) };
        if i < 0 {
            return true;
        }
        // SAFETY: an index within the subject.
        let ne = unsafe { X509_NAME_get_entry(nm, i) };
        // SAFETY: the entry.
        let data = unsafe { X509_NAME_ENTRY_get_data(ne) };
        // SAFETY: its value.
        let email = unsafe { ASN1_STRING_dup(data) };
        if move_p {
            // SAFETY: as above; the entry taken out, ours to free.
            unsafe { X509_NAME_delete_entry(nm, i) };
            // SAFETY: as above.
            unsafe { X509_NAME_ENTRY_free(ne) };
            i -= 1;
        }
        // SAFETY: no preconditions.
        let gname = if email.is_null() {
            ptr::null_mut()
        } else {
            // SAFETY: no preconditions.
            unsafe { GENERAL_NAME_new() }
        };
        // SAFETY: new, or NULL.
        let Some(g) = (unsafe { gname.as_mut() }) else {
            err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
            // SAFETY: copied above, or NULL.
            unsafe { ASN1_STRING_free(email) };
            return false;
        };
        g.d.ia5 = email;
        g.type_ = GEN_EMAIL;
        // SAFETY: the caller's stack; the name, which it takes.
        if unsafe { OPENSSL_sk_push(gens.cast(), gname.cast()) } == 0 {
            err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, F);
            // SAFETY: made above.
            unsafe { GENERAL_NAME_free(gname) };
            return false;
        }
    }
}

ffi_export! {
    /// A name for each value (`v2i_GENERAL_NAME`), or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `nval` is NULL or a live stack of `CONF_VALUE`s.
    pub unsafe extern "C" fn v2i_GENERAL_NAMES(method: *const X509V3_EXT_METHOD, ctx: *mut X509V3_CTX, nval: *mut stack_st_CONF_VALUE) -> *mut GENERAL_NAMES
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's stack, or NULL.
        let num = unsafe { OPENSSL_sk_num(nval.cast()) };
        let gens = new_names(num, "v2i_GENERAL_NAMES");
        if gens.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        for cnf in unsafe { values(nval) } {
            // SAFETY: the stack; the value; the caller's context.
            if !unsafe { push_name(gens, method, ctx, cnf) } {
                // SAFETY: the stack made above, with its names.
                unsafe { OPENSSL_sk_pop_free(gens.cast(), Some(free_gen)) };
                return ptr::null_mut();
            }
        }
        gens
    }
}

ffi_export! {
    /// The name `cnf` says (`email`, `URI`, `DNS`, `RID`, `IP`, `dirName`, or `otherName`, any
    /// with a `.` suffix), or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `cnf` is a live `CONF_VALUE`.
    pub unsafe extern "C" fn v2i_GENERAL_NAME(method: *const X509V3_EXT_METHOD, ctx: *mut X509V3_CTX, cnf: *mut CONF_VALUE) -> *mut GENERAL_NAME
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { v2i_GENERAL_NAME_ex(ptr::null_mut(), method, ctx, cnf, 0) }
    }
}

ffi_export! {
    /// [`v2i_GENERAL_NAME`] into `out` (a new name for NULL); with `is_nc`, an IP address is a
    /// network (`address/mask`, for name constraints).
    ///
    /// # Safety
    /// As for [`v2i_GENERAL_NAME`]; `out` is NULL or a live, empty name.
    pub unsafe extern "C" fn v2i_GENERAL_NAME_ex(out: *mut GENERAL_NAME, method: *const X509V3_EXT_METHOD, ctx: *mut X509V3_CTX, cnf: *mut CONF_VALUE, is_nc: c_int) -> *mut GENERAL_NAME
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        const F: &str = "v2i_GENERAL_NAME_ex";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cnf.as_ref() }) else { return ptr::null_mut() };
        if c.value.is_null() {
            err::raise(ERR_LIB_X509V3, X509V3_R_MISSING_VALUE, F);
            return ptr::null_mut();
        }
        // SAFETY: its name.
        let name = unsafe { text(c.name) };
        let type_ = [
            (&b"email"[..], GEN_EMAIL),
            (b"URI", GEN_URI),
            (b"DNS", GEN_DNS),
            (b"RID", GEN_RID),
            (b"IP", GEN_IPADD),
            (b"dirName", GEN_DIRNAME),
            (b"otherName", GEN_OTHERNAME),
        ]
        .into_iter()
        .find(|(n, _)| name_is(name, n))
        .map(|(_, t)| t);
        let Some(type_) = type_ else {
            let mut data = b"name=".to_vec();
            data.extend_from_slice(name.unwrap_or_default());
            err::raise_with_bytes(ERR_LIB_X509V3, X509V3_R_UNSUPPORTED_OPTION, F, &data);
            return ptr::null_mut();
        };
        // SAFETY: as above.
        unsafe { a2i_GENERAL_NAME(out, method, ctx, type_, c.value, is_nc) }
    }
}

ffi_export! {
    /// A name of `gen_type` from `value` into `out` (a new name for NULL), or NULL (with the
    /// reason, and the value as data for an object or an IP address).
    ///
    /// # Safety
    /// `out` is NULL or a live, empty name; `ctx` is NULL or a live context; `value` is NULL or
    /// a C string.
    pub unsafe extern "C" fn a2i_GENERAL_NAME(out: *mut GENERAL_NAME, _method: *const X509V3_EXT_METHOD, ctx: *mut X509V3_CTX, gen_type: c_int, value: *const c_char, is_nc: c_int) -> *mut GENERAL_NAME
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        const F: &str = "a2i_GENERAL_NAME";
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { text(value) }) else {
            err::raise(ERR_LIB_X509V3, X509V3_R_MISSING_VALUE, F);
            return ptr::null_mut();
        };
        let gname = if out.is_null() {
            // SAFETY: no preconditions.
            let g = unsafe { GENERAL_NAME_new() };
            if g.is_null() {
                err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
                return ptr::null_mut();
            }
            g
        } else {
            out
        };
        let fail = move || {
            if out.is_null() {
                // SAFETY: made above.
                unsafe { GENERAL_NAME_free(gname) };
            }
            ptr::null_mut()
        };
        // SAFETY: the name, new or the caller's.
        let g = unsafe { &mut *gname };
        let with_value = |reason| {
            let mut data = b"value=".to_vec();
            data.extend_from_slice(v);
            err::raise_with_bytes(ERR_LIB_X509V3, reason, F, &data);
        };
        match gen_type {
            GEN_URI | GEN_EMAIL | GEN_DNS => {
                // SAFETY: no preconditions.
                let s = unsafe { ASN1_STRING_type_new(V_ASN1_IA5STRING) };
                let n = c_int::try_from(v.len()).unwrap_or(c_int::MAX);
                // SAFETY: the new string, or NULL; the value's octets.
                if s.is_null() || unsafe { ASN1_STRING_set(s, v.as_ptr().cast(), n) } == 0 {
                    // SAFETY: made above, or NULL.
                    unsafe { ASN1_STRING_free(s) };
                    err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
                    return fail();
                }
                g.d.ia5 = s;
            }
            GEN_RID => {
                // SAFETY: the caller's string.
                let obj = unsafe { OBJ_txt2obj(value, 0) };
                if obj.is_null() {
                    with_value(X509V3_R_BAD_OBJECT);
                    return fail();
                }
                g.d.rid = obj;
            }
            GEN_IPADD => {
                let ip = if is_nc != 0 {
                    // SAFETY: the caller's string.
                    unsafe { a2i_IPADDRESS_NC(value) }
                } else {
                    // SAFETY: as above.
                    unsafe { a2i_IPADDRESS(value) }
                };
                if ip.is_null() {
                    with_value(X509V3_R_BAD_IP_ADDRESS);
                    return fail();
                }
                g.d.ip = ip;
            }
            GEN_DIRNAME => {
                // SAFETY: the name; the caller's string and context.
                if !unsafe { do_dirname(g, value, ctx) } {
                    err::raise(ERR_LIB_X509V3, X509V3_R_DIRNAME_ERROR, F);
                    return fail();
                }
            }
            GEN_OTHERNAME => {
                if !v.contains(&b';') {
                    err::raise(ERR_LIB_X509V3, X509V3_R_OTHERNAME_ERROR, F);
                    return fail();
                }
                crate::stub::unimplemented("an otherName from text (ASN1_generate_v3, step 6.1)");
            }
            _ => {
                err::raise(ERR_LIB_X509V3, X509V3_R_UNSUPPORTED_TYPE, F);
                return fail();
            }
        }
        g.type_ = gen_type;
        gname
    }
}

/// `do_dirname`: a directory name from the context's section `value`.
///
/// # Safety
/// `g` is a live name; `value` is a C string; `ctx` is NULL or a live context.
unsafe fn do_dirname(g: &mut GENERAL_NAME, value: *const c_char, ctx: *mut X509V3_CTX) -> bool {
    // SAFETY: no preconditions.
    let nm = unsafe { X509_NAME_new() };
    if nm.is_null() {
        return false;
    }
    // SAFETY: the caller's guarantee.
    let sk = unsafe { X509V3_get_section(ctx, value) };
    let ok = if sk.is_null() {
        // SAFETY: as above.
        let mut data = b"section=".to_vec();
        // SAFETY: the caller's string.
        data.extend_from_slice(unsafe { text(value) }.unwrap_or_default());
        err::raise_with_bytes(
            ERR_LIB_X509V3,
            X509V3_R_SECTION_NOT_FOUND,
            "do_dirname",
            &data,
        );
        false
    } else {
        // SAFETY: the new name; the section.
        (unsafe { X509V3_NAME_from_section(nm, sk, MBSTRING_ASC.cast_unsigned().into()) } != 0)
    };
    if ok {
        g.d.dirn = nm;
    } else {
        // SAFETY: made above.
        unsafe { X509_NAME_free(nm) };
    }
    // SAFETY: the context's section, or NULL.
    unsafe { X509V3_section_free(ctx, sk) };
    ok
}

/// An OCTET STRING of `octets`, or NULL.
fn octet_string(octets: &[u8]) -> *mut ASN1_OCTET_STRING {
    // SAFETY: no preconditions.
    let ret = unsafe { ASN1_OCTET_STRING_new() };
    let n = c_int::try_from(octets.len()).unwrap_or(0);
    // SAFETY: the new string, or NULL; the octets.
    if ret.is_null() || unsafe { ASN1_OCTET_STRING_set(ret, octets.as_ptr(), n) } == 0 {
        // SAFETY: made above, or NULL.
        unsafe { ASN1_OCTET_STRING_free(ret) };
        return ptr::null_mut();
    }
    ret
}

ffi_export! {
    /// The octets of an IPv4 or IPv6 address written as text, or NULL.
    ///
    /// # Safety
    /// `ipasc` is a C string.
    pub unsafe extern "C" fn a2i_IPADDRESS(ipasc: *const c_char) -> *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { text(ipasc) }) else { return ptr::null_mut() };
        rustyssl_pki::ip::parse(t).map_or(ptr::null_mut(), |o| octet_string(&o))
    }
}

ffi_export! {
    /// The octets of a network written as `address/mask` (both of a family), or NULL.
    ///
    /// # Safety
    /// `ipasc` is a C string.
    pub unsafe extern "C" fn a2i_IPADDRESS_NC(ipasc: *const c_char) -> *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { text(ipasc) }) else { return ptr::null_mut() };
        rustyssl_pki::ip::parse_network(t).map_or(ptr::null_mut(), |o| octet_string(&o))
    }
}

ffi_callback! {
    /// `i2v_GENERAL_NAMES` as a method's `i2v`.
    ///
    /// # Safety
    /// As for [`i2v_GENERAL_NAMES`].
    pub(crate) unsafe extern "C" fn names_i2v(method: *const X509V3_EXT_METHOD, ext: *mut core::ffi::c_void, extlist: *mut stack_st_CONF_VALUE) -> *mut stack_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { i2v_GENERAL_NAMES(method.cast_mut(), ext.cast(), extlist) }
    }
}

const fn alt(nid: c_int, v2i: Option<rustyssl_abi::X509V3_EXT_V2I>) -> Method {
    let mut m = method(nid, 0);
    m.it = Some(GENERAL_NAMES_it);
    m.i2v = Some(names_i2v);
    if let Some(v) = v2i {
        m.v2i = v;
    }
    Method(m)
}

pub(crate) static SUBJECT_ALT: Method = alt(NID_subject_alt_name, Some(Some(v2i_subject_alt)));
pub(crate) static ISSUER_ALT: Method = alt(NID_issuer_alt_name, Some(Some(v2i_issuer_alt)));
pub(crate) static CERT_ISSUER: Method = alt(NID_certificate_issuer, None);
