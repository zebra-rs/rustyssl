//! Policies and constraints (`v3_cpols.c`, `v3_pmaps.c`, `v3_pcons.c`, `v3_pcia.c`, `v3_pci.c`,
//! and the extension parts of `v3_ncons.c`): certificate policies with their CPS and user
//! notice qualifiers, policy mappings, policy constraints, a proxy certificate's information,
//! and name constraints (and the attribute certificates' holder and delegated ones), as their
//! types, printed and made from text.
//!
//! Checking a certificate's names against name constraints (`NAME_CONSTRAINTS_check`) is in
//! `ncons.rs`, and printing a policy tree's node (`X509_POLICY_NODE_print`) with the policy
//! tree (`x509/pcy.rs`).

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ASN1_INTEGER, ASN1_ITEM, ASN1_ITYPE_PRIMITIVE, ASN1_OBJECT, ASN1_OCTET_STRING,
    ASN1_TFLG_IMPLICIT, ASN1_TFLG_OPTIONAL, ASN1_TFLG_SEQUENCE_OF, BIO, BIO_FLAGS_SHOULD_RETRY,
    CERTIFICATEPOLICIES, CONF_VALUE, ERR_LIB_ASN1, ERR_LIB_X509V3, ERR_R_ASN1_LIB, ERR_R_BIO_LIB,
    ERR_R_CRYPTO_LIB, ERR_R_INTERNAL_ERROR, ERR_R_X509V3_LIB, GEN_IPADD, GENERAL_SUBTREE,
    NAME_CONSTRAINTS, NID_Independent, NID_certificate_policies, NID_delegated_name_constraints,
    NID_holder_name_constraints, NID_id_ppl_inheritAll, NID_id_qt_cps, NID_id_qt_unotice,
    NID_name_constraints, NID_policy_constraints, NID_policy_mappings, NID_proxyCertInfo,
    NOTICEREF, POLICY_CONSTRAINTS, POLICY_MAPPING, POLICYINFO, POLICYQUALINFO,
    PROXY_CERT_INFO_EXTENSION, PROXY_POLICY, USERNOTICE, V_ASN1_BMPSTRING, V_ASN1_IA5STRING,
    V_ASN1_UTF8STRING, V_ASN1_VISIBLESTRING, X509V3_CTX, X509V3_EXT_METHOD,
    X509V3_R_EXPECTED_A_SECTION_NAME, X509V3_R_ILLEGAL_EMPTY_EXTENSION,
    X509V3_R_INCORRECT_POLICY_SYNTAX_TAG, X509V3_R_INVALID_NAME, X509V3_R_INVALID_NUMBER,
    X509V3_R_INVALID_NUMBERS, X509V3_R_INVALID_OBJECT_IDENTIFIER, X509V3_R_INVALID_OPTION,
    X509V3_R_INVALID_POLICY_IDENTIFIER, X509V3_R_INVALID_PROXY_POLICY_SETTING,
    X509V3_R_INVALID_SECTION, X509V3_R_INVALID_SYNTAX, X509V3_R_NEED_ORGANIZATION_AND_NUMBERS,
    X509V3_R_NO_POLICY_IDENTIFIER, X509V3_R_NO_PROXY_CERT_POLICY_LANGUAGE_DEFINED,
    X509V3_R_POLICY_LANGUAGE_ALREADY_DEFINED, X509V3_R_POLICY_PATH_LENGTH,
    X509V3_R_POLICY_PATH_LENGTH_ALREADY_DEFINED,
    X509V3_R_POLICY_WHEN_PROXY_LANGUAGE_REQUIRES_NO_POLICY, stack_st_CONF_VALUE,
};

use super::ctx::{X509V3_get_section, X509V3_section_free};
use super::genn::GENERAL_NAME_it;
use super::registry::{Method, indent_to, method};
use super::san::{GENERAL_NAME_print, v2i_GENERAL_NAME_ex};
use super::simple::{X509V3_get_value_int, add_error_name_value};
use super::{
    X509V3_add_value, X509V3_conf_free, X509V3_parse_list, i2s_ASN1_INTEGER, item_at,
    s2i_ASN1_INTEGER,
};
use crate::asn1::integer::i2a_ASN1_INTEGER;
use crate::asn1::string::{
    ASN1_INTEGER_free, ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_STRING_free,
    ASN1_STRING_set, ASN1_STRING_type_new,
};
use crate::asn1::tpl::items::{
    ASN1_ANY_it, ASN1_IA5STRING_it, ASN1_INTEGER_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_it,
    DISPLAYTEXT_it, d2i, i2d, new_free,
};
use crate::asn1::tpl::statics::{
    Adb, AdbEntries, Templates, adb_entry, adb_object, adb_oid, sequence,
};
use crate::asn1::tpl::{Template, item, item_fns, template, template_at};
use crate::bio::print::BIO_printf;
use crate::bio::{BIO_free_all, BIO_puts, BIO_read, BIO_test_flags};
use crate::err;
use crate::ffi::ffi_callback;
use crate::mem;
use crate::objects::{
    ASN1_OBJECT_free, OBJ_nid2obj, OBJ_obj2nid, OBJ_txt2obj, i2a_ASN1_OBJECT, i2t_ASN1_OBJECT,
};
use crate::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_pop_free,
    OPENSSL_sk_push,
};

/// A C string's bytes, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a C string.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) }.to_bytes())
}

/// `X509V3_conf_err`: the value's section, name, and value as the error's data.
///
/// # Safety
/// `v` is a live `CONF_VALUE`.
unsafe fn conf_err(v: &CONF_VALUE) {
    // SAFETY: the value's section.
    let s = unsafe { text(v.section) };
    // SAFETY: its name.
    let n = unsafe { text(v.name) };
    // SAFETY: its value.
    let x = unsafe { text(v.value) };
    err::add_error_data([
        Some(&b"section:"[..]),
        s,
        Some(b",name:"),
        n,
        Some(b",value:"),
        x,
    ]);
}

/// `X509V3_conf_free` as a stack's free function.
unsafe extern "C" fn free_conf(c: *mut c_void) {
    // SAFETY: a `CONF_VALUE` of the stack, which the stack owned.
    unsafe { X509V3_conf_free(c.cast()) };
}

// Certificate policies (`v3_cpols.c`).

static NOTICEREF_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(NOTICEREF, organization),
        c"organization",
        DISPLAYTEXT_it,
    ),
    template_at(
        ASN1_TFLG_SEQUENCE_OF,
        0,
        offset_of!(NOTICEREF, noticenos),
        c"noticenos",
        ASN1_INTEGER_it,
    ),
]);

item_fns! {
    /// NoticeReference: SEQUENCE { organization DisplayText, noticeNumbers SEQUENCE OF INTEGER }.
    pub unsafe extern "C" fn NOTICEREF_it = sequence::<NOTICEREF, 2>(&NOTICEREF_TT, None, c"NOTICEREF");
}

new_free! {
    pub unsafe extern "C" fn NOTICEREF_new, pub unsafe extern "C" fn NOTICEREF_free(NOTICEREF) = NOTICEREF_it;
}

i2d! {
    /// Encodes a NoticeReference.
    pub unsafe extern "C" fn i2d_NOTICEREF(NOTICEREF) = NOTICEREF_it;
}

d2i! {
    /// Decodes a NoticeReference (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_NOTICEREF(NOTICEREF) = NOTICEREF_it;
}

static USERNOTICE_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(USERNOTICE, noticeref),
        c"noticeref",
        NOTICEREF_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(USERNOTICE, exptext),
        c"exptext",
        DISPLAYTEXT_it,
    ),
]);

item_fns! {
    /// UserNotice: SEQUENCE { noticeRef NoticeReference OPTIONAL, explicitText DisplayText
    /// OPTIONAL }.
    pub unsafe extern "C" fn USERNOTICE_it = sequence::<USERNOTICE, 2>(&USERNOTICE_TT, None, c"USERNOTICE");
}

new_free! {
    pub unsafe extern "C" fn USERNOTICE_new, pub unsafe extern "C" fn USERNOTICE_free(USERNOTICE) = USERNOTICE_it;
}

i2d! {
    /// Encodes a UserNotice.
    pub unsafe extern "C" fn i2d_USERNOTICE(USERNOTICE) = USERNOTICE_it;
}

d2i! {
    /// Decodes a UserNotice (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_USERNOTICE(USERNOTICE) = USERNOTICE_it;
}

/// The qualifier's value, every alternative at the same place.
const QUAL_D: usize = offset_of!(POLICYQUALINFO, d);

static POLICYDEFAULT: Template = Template(template_at(0, 0, QUAL_D, c"d.other", ASN1_ANY_it));

static QUAL_ENTRIES: AdbEntries<2> = AdbEntries([
    adb_entry(
        NID_id_qt_cps,
        template_at(0, 0, QUAL_D, c"d.cpsuri", ASN1_IA5STRING_it),
    ),
    adb_entry(
        NID_id_qt_unotice,
        template_at(0, 0, QUAL_D, c"d.usernotice", USERNOTICE_it),
    ),
]);

static QUAL_ADB: Adb = adb_oid(
    offset_of!(POLICYQUALINFO, pqualid),
    &QUAL_ENTRIES,
    &POLICYDEFAULT,
);

/// The qualifier's table, in place of an item.
unsafe extern "C" fn qual_adb() -> *const ASN1_ITEM {
    (&raw const QUAL_ADB.0).cast()
}

static QUAL_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(POLICYQUALINFO, pqualid),
        c"pqualid",
        ASN1_OBJECT_it,
    ),
    adb_object(c"POLICYQUALINFO", qual_adb),
]);

item_fns! {
    /// PolicyQualifierInfo: SEQUENCE { policyQualifierId, qualifier ANY DEFINED BY it }: a CPS
    /// URI, a user notice, or anything.
    pub unsafe extern "C" fn POLICYQUALINFO_it = sequence::<POLICYQUALINFO, 2>(&QUAL_TT, None, c"POLICYQUALINFO");
}

new_free! {
    pub unsafe extern "C" fn POLICYQUALINFO_new, pub unsafe extern "C" fn POLICYQUALINFO_free(POLICYQUALINFO) = POLICYQUALINFO_it;
}

i2d! {
    /// Encodes a PolicyQualifierInfo.
    pub unsafe extern "C" fn i2d_POLICYQUALINFO(POLICYQUALINFO) = POLICYQUALINFO_it;
}

d2i! {
    /// Decodes a PolicyQualifierInfo (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_POLICYQUALINFO(POLICYQUALINFO) = POLICYQUALINFO_it;
}

static POLICYINFO_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(POLICYINFO, policyid),
        c"policyid",
        ASN1_OBJECT_it,
    ),
    template_at(
        ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(POLICYINFO, qualifiers),
        c"qualifiers",
        POLICYQUALINFO_it,
    ),
]);

item_fns! {
    /// PolicyInformation: SEQUENCE { policyIdentifier, policyQualifiers SEQUENCE OF
    /// PolicyQualifierInfo OPTIONAL }.
    pub unsafe extern "C" fn POLICYINFO_it = sequence::<POLICYINFO, 2>(&POLICYINFO_TT, None, c"POLICYINFO");
}

new_free! {
    pub unsafe extern "C" fn POLICYINFO_new, pub unsafe extern "C" fn POLICYINFO_free(POLICYINFO) = POLICYINFO_it;
}

i2d! {
    /// Encodes a PolicyInformation.
    pub unsafe extern "C" fn i2d_POLICYINFO(POLICYINFO) = POLICYINFO_it;
}

d2i! {
    /// Decodes a PolicyInformation (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_POLICYINFO(POLICYINFO) = POLICYINFO_it;
}

static CPOLS_T: Template = template(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    c"CERTIFICATEPOLICIES",
    POLICYINFO_it,
);

item_fns! {
    /// CertificatePolicies: SEQUENCE OF PolicyInformation.
    pub unsafe extern "C" fn CERTIFICATEPOLICIES_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const CPOLS_T.0, 0, ptr::null(), 0, c"CERTIFICATEPOLICIES");
}

new_free! {
    pub unsafe extern "C" fn CERTIFICATEPOLICIES_new, pub unsafe extern "C" fn CERTIFICATEPOLICIES_free(CERTIFICATEPOLICIES) = CERTIFICATEPOLICIES_it;
}

i2d! {
    /// Encodes CertificatePolicies.
    pub unsafe extern "C" fn i2d_CERTIFICATEPOLICIES(CERTIFICATEPOLICIES) = CERTIFICATEPOLICIES_it;
}

d2i! {
    /// Decodes CertificatePolicies (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_CERTIFICATEPOLICIES(CERTIFICATEPOLICIES) = CERTIFICATEPOLICIES_it;
}

/// `POLICYINFO_free` as a stack's free function.
pub(crate) unsafe extern "C" fn free_pol(p: *mut c_void) {
    // SAFETY: a policy of the stack, which the stack owned.
    unsafe { POLICYINFO_free(p.cast()) };
}

ffi_callback! {
    /// `r2i_certpol`: a policy for each object in the list, or each `@section`; `ia5org` makes
    /// the later sections' organizations IA5Strings.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `value` is NULL or a C string.
    pub(crate) unsafe extern "C" fn certpol_r2i(_method: *const X509V3_EXT_METHOD, ctx: *mut X509V3_CTX, value: *const c_char) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        const F: &str = "r2i_certpol";
        // SAFETY: the caller's guarantee.
        let vals = unsafe { X509V3_parse_list(value) };
        if vals.is_null() {
            err::raise(ERR_LIB_X509V3, ERR_R_X509V3_LIB, F);
            return ptr::null_mut();
        }
        // SAFETY: the list.
        let num = unsafe { OPENSSL_sk_num(vals.cast()) };
        // SAFETY: no preconditions.
        let pols = unsafe { OPENSSL_sk_new_reserve(None, num) };
        let done = |ret: *mut c_void| {
            // SAFETY: the list made above.
            unsafe { OPENSSL_sk_pop_free(vals.cast(), Some(free_conf)) };
            ret
        };
        let fail = || {
            // SAFETY: the stack made above, with its policies, or NULL.
            unsafe { OPENSSL_sk_pop_free(pols, Some(free_pol)) };
            done(ptr::null_mut())
        };
        if pols.is_null() {
            err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, F);
            return fail();
        }
        let mut ia5org = false;
        for i in 0..num {
            // SAFETY: an index within the list.
            let Some(cnf) = (unsafe { item_at::<CONF_VALUE>(vals.cast(), i) }) else { continue };
            if !cnf.value.is_null() || cnf.name.is_null() {
                err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_POLICY_IDENTIFIER, F);
                // SAFETY: the value.
                unsafe { add_error_name_value(cnf) };
                return fail();
            }
            // SAFETY: its name.
            let pstr = unsafe { text(cnf.name) }.unwrap_or_default();
            let pol = if pstr == b"ia5org" {
                ia5org = true;
                continue;
            } else if pstr.first() == Some(&b'@') {
                // SAFETY: the caller's context; the section's name after `@`.
                let polsect = unsafe { X509V3_get_section(ctx, cnf.name.wrapping_add(1)) };
                if polsect.is_null() {
                    err::raise_with_bytes(ERR_LIB_X509V3, X509V3_R_INVALID_SECTION, F, pstr);
                    return fail();
                }
                // SAFETY: as above; the section.
                let pol = unsafe { policy_section(ctx, polsect, ia5org) };
                // SAFETY: the context's section.
                unsafe { X509V3_section_free(ctx, polsect) };
                if pol.is_null() {
                    return fail();
                }
                pol
            } else {
                // SAFETY: the name.
                let pobj = unsafe { OBJ_txt2obj(cnf.name, 0) };
                if pobj.is_null() {
                    err::raise_with_bytes(ERR_LIB_X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER, F, pstr);
                    return fail();
                }
                // SAFETY: no preconditions.
                let pol = unsafe { POLICYINFO_new() };
                // SAFETY: new, or NULL.
                let Some(p) = (unsafe { pol.as_mut() }) else {
                    // SAFETY: made above.
                    unsafe { ASN1_OBJECT_free(pobj) };
                    err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
                    return fail();
                };
                p.policyid = pobj;
                pol
            };
            // SAFETY: the stack; the policy, which it takes.
            if unsafe { OPENSSL_sk_push(pols, pol.cast()) } == 0 {
                // SAFETY: made above.
                unsafe { POLICYINFO_free(pol) };
                err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, F);
                return fail();
            }
        }
        done(pols.cast())
    }
}

/// A qualifier pushed onto `pol`'s qualifiers (made if missing): true, or false (freeing it).
///
/// # Safety
/// `qual` is a live qualifier it takes.
unsafe fn push_qual(pol: &mut POLICYINFO, qual: *mut POLICYQUALINFO, f: &str) -> bool {
    if pol.qualifiers.is_null() {
        // SAFETY: no preconditions.
        pol.qualifiers = unsafe { OPENSSL_sk_new_null() }.cast();
    }
    let pushed = !pol.qualifiers.is_null() && {
        // SAFETY: the stack; the qualifier, which it takes.
        (unsafe { OPENSSL_sk_push(pol.qualifiers.cast(), qual.cast()) } != 0)
    };
    if !pushed {
        // SAFETY: the caller's qualifier.
        unsafe { POLICYQUALINFO_free(qual) };
        err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, f);
        return false;
    }
    true
}

/// `policy_section`: a policy from a section (`policyIdentifier`, `CPS…`, `userNotice…`).
///
/// # Safety
/// `ctx` is NULL or a live context; `polstrs` is a live stack of `CONF_VALUE`s.
unsafe fn policy_section(
    ctx: *mut X509V3_CTX,
    polstrs: *mut stack_st_CONF_VALUE,
    ia5org: bool,
) -> *mut POLICYINFO {
    const F: &str = "policy_section";
    // SAFETY: no preconditions.
    let pol = unsafe { POLICYINFO_new() };
    // SAFETY: new, or NULL.
    let Some(p) = (unsafe { pol.as_mut() }) else {
        err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
        return ptr::null_mut();
    };
    let fail = || {
        // SAFETY: made above.
        unsafe { POLICYINFO_free(pol) };
        ptr::null_mut()
    };
    // SAFETY: the caller's stack.
    let n = unsafe { OPENSSL_sk_num(polstrs.cast()) };
    for i in 0..n {
        // SAFETY: an index within the stack.
        let Some(cnf) = (unsafe { item_at::<CONF_VALUE>(polstrs.cast(), i) }) else {
            continue;
        };
        // SAFETY: its name.
        let name = unsafe { text(cnf.name) };
        if name == Some(b"policyIdentifier") {
            let pobj = if cnf.value.is_null() {
                ptr::null_mut()
            } else {
                // SAFETY: its value.
                unsafe { OBJ_txt2obj(cnf.value, 0) }
            };
            if pobj.is_null() {
                err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER, F);
                // SAFETY: the value.
                unsafe { conf_err(cnf) };
                return fail();
            }
            p.policyid = pobj;
        } else if super::san::name_is(name, b"CPS") {
            // SAFETY: no preconditions.
            let qual = unsafe { POLICYQUALINFO_new() };
            if qual.is_null() {
                err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
                return fail();
            }
            // SAFETY: the policy; the new qualifier.
            if !unsafe { push_qual(p, qual, F) } {
                return fail();
            }
            // SAFETY: the qualifier, now the policy's.
            let q = unsafe { &mut *qual };
            // SAFETY: a NID.
            q.pqualid = unsafe { OBJ_nid2obj(NID_id_qt_cps) };
            if q.pqualid.is_null() {
                err::raise(ERR_LIB_X509V3, ERR_R_INTERNAL_ERROR, F);
                return fail();
            }
            // SAFETY: no preconditions.
            let s = unsafe { ASN1_STRING_type_new(V_ASN1_IA5STRING) };
            q.d.cpsuri = s;
            // SAFETY: its value.
            let v = unsafe { text(cnf.value) }.unwrap_or_default();
            let len = c_int::try_from(v.len()).unwrap_or(c_int::MAX);
            // SAFETY: the new string, or NULL; the value's octets.
            if s.is_null() || unsafe { ASN1_STRING_set(s, v.as_ptr().cast(), len) } == 0 {
                err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
                return fail();
            }
        } else if super::san::name_is(name, b"userNotice") {
            // SAFETY: its value.
            let v = unsafe { text(cnf.value) };
            if v.and_then(|v| v.first()) != Some(&b'@') {
                err::raise(ERR_LIB_X509V3, X509V3_R_EXPECTED_A_SECTION_NAME, F);
                // SAFETY: the value.
                unsafe { conf_err(cnf) };
                return fail();
            }
            // SAFETY: the caller's context; the section's name after `@`.
            let unot = unsafe { X509V3_get_section(ctx, cnf.value.wrapping_add(1)) };
            if unot.is_null() {
                err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_SECTION, F);
                // SAFETY: the value.
                unsafe { conf_err(cnf) };
                return fail();
            }
            // SAFETY: as above; the section.
            let qual = unsafe { notice_section(ctx, unot, ia5org) };
            // SAFETY: the context's section.
            unsafe { X509V3_section_free(ctx, unot) };
            // SAFETY: the policy; the qualifier, if made.
            if qual.is_null() || !unsafe { push_qual(p, qual, F) } {
                return fail();
            }
        } else {
            err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_OPTION, F);
            // SAFETY: the value.
            unsafe { conf_err(cnf) };
            return fail();
        }
    }
    if p.policyid.is_null() {
        err::raise(ERR_LIB_X509V3, X509V3_R_NO_POLICY_IDENTIFIER, F);
        return fail();
    }
    pol
}

/// `displaytext_str2tag`: the string type a `TYPE:` prefix names (`UTF8`, `UTF8String`, `BMP`,
/// `BMPSTRING`, `VISIBLE`, `VISIBLESTRING`; a VisibleString otherwise) and the prefix's length
/// to skip (0 without a known one).
fn display_tag(value: &[u8]) -> (c_int, usize) {
    let Some(colon) = value.iter().position(|&c| c == b':') else {
        return (V_ASN1_VISIBLESTRING, 0);
    };
    let tag = value.get(..colon).unwrap_or_default();
    match tag {
        b"UTF8" | b"UTF8String" => (V_ASN1_UTF8STRING, colon),
        b"BMP" | b"BMPSTRING" => (V_ASN1_BMPSTRING, colon),
        b"VISIBLE" | b"VISIBLESTRING" => (V_ASN1_VISIBLESTRING, colon),
        _ => (V_ASN1_VISIBLESTRING, 0),
    }
}

/// The notice reference of `not`, made if missing, or NULL.
///
/// # Safety
/// `not` is a live user notice.
unsafe fn noticeref(not: &mut USERNOTICE, f: &str) -> *mut NOTICEREF {
    if not.noticeref.is_null() {
        // SAFETY: no preconditions.
        not.noticeref = unsafe { NOTICEREF_new() };
        if not.noticeref.is_null() {
            err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, f);
        }
    }
    not.noticeref
}

/// `notice_section`: a user notice qualifier from a section (`explicitText`, `organization`,
/// `noticeNumbers`).
///
/// # Safety
/// `ctx` is NULL or a live context; `unot` is a live stack of `CONF_VALUE`s.
unsafe fn notice_section(
    _ctx: *mut X509V3_CTX,
    unot: *mut stack_st_CONF_VALUE,
    ia5org: bool,
) -> *mut POLICYQUALINFO {
    const F: &str = "notice_section";
    // SAFETY: no preconditions.
    let qual = unsafe { POLICYQUALINFO_new() };
    // SAFETY: new, or NULL.
    let Some(q) = (unsafe { qual.as_mut() }) else {
        err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
        return ptr::null_mut();
    };
    let fail = || {
        // SAFETY: made above.
        unsafe { POLICYQUALINFO_free(qual) };
        ptr::null_mut()
    };
    // SAFETY: a NID.
    q.pqualid = unsafe { OBJ_nid2obj(NID_id_qt_unotice) };
    if q.pqualid.is_null() {
        err::raise(ERR_LIB_X509V3, ERR_R_INTERNAL_ERROR, F);
        return fail();
    }
    // SAFETY: no preconditions.
    let not = unsafe { USERNOTICE_new() };
    if not.is_null() {
        err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
        return fail();
    }
    q.d.usernotice = not;
    // SAFETY: the new notice, now the qualifier's.
    let nt = unsafe { &mut *not };
    // SAFETY: the caller's stack.
    let n = unsafe { OPENSSL_sk_num(unot.cast()) };
    for i in 0..n {
        // SAFETY: an index within the stack.
        let Some(cnf) = (unsafe { item_at::<CONF_VALUE>(unot.cast(), i) }) else {
            continue;
        };
        // SAFETY: its strings.
        let (name, value) = (unsafe { text(cnf.name) }, unsafe { text(cnf.value) });
        match name {
            Some(b"explicitText") => {
                let v = value.unwrap_or_default();
                let (tag, skip) = display_tag(v);
                // SAFETY: no preconditions.
                let s = unsafe { ASN1_STRING_type_new(tag) };
                if s.is_null() {
                    err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
                    return fail();
                }
                // SAFETY: its old text, or NULL.
                unsafe { ASN1_STRING_free(nt.exptext) };
                nt.exptext = s;
                let rest = if skip == 0 {
                    v
                } else {
                    v.get(skip.saturating_add(1)..).unwrap_or_default()
                };
                let len = c_int::try_from(rest.len()).unwrap_or(c_int::MAX);
                // SAFETY: the new string; the text.
                if unsafe { ASN1_STRING_set(s, rest.as_ptr().cast(), len) } == 0 {
                    err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
                    return fail();
                }
            }
            Some(b"organization") => {
                // SAFETY: the notice.
                let nref = unsafe { noticeref(nt, F) };
                // SAFETY: its reference, or NULL.
                let Some(r) = (unsafe { nref.as_mut() }) else {
                    return fail();
                };
                // SAFETY: its organization, made with it.
                let Some(org) = (unsafe { r.organization.as_mut() }) else {
                    return fail();
                };
                org.type_ = if ia5org {
                    V_ASN1_IA5STRING
                } else {
                    V_ASN1_VISIBLESTRING
                };
                let v = value.unwrap_or_default();
                let len = c_int::try_from(v.len()).unwrap_or(c_int::MAX);
                // SAFETY: the organization; the value's octets.
                if unsafe { ASN1_STRING_set(org, v.as_ptr().cast(), len) } == 0 {
                    err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
                    return fail();
                }
            }
            Some(b"noticeNumbers") => {
                // SAFETY: the notice.
                let nref = unsafe { noticeref(nt, F) };
                // SAFETY: its reference, or NULL.
                let Some(r) = (unsafe { nref.as_mut() }) else {
                    return fail();
                };
                // SAFETY: the value, NULL or a string.
                let nos = unsafe { X509V3_parse_list(cnf.value) };
                // SAFETY: the list, or NULL.
                if nos.is_null() || unsafe { OPENSSL_sk_num(nos.cast()) } == 0 {
                    err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_NUMBERS, F);
                    // SAFETY: the value.
                    unsafe { add_error_name_value(cnf) };
                    // SAFETY: the list, or NULL.
                    unsafe { OPENSSL_sk_pop_free(nos.cast(), Some(free_conf)) };
                    return fail();
                }
                // SAFETY: the reference's numbers; the list.
                let ok = unsafe { nref_nos(r, nos) };
                // SAFETY: the list made above.
                unsafe { OPENSSL_sk_pop_free(nos.cast(), Some(free_conf)) };
                if !ok {
                    return fail();
                }
            }
            _ => {
                err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_OPTION, F);
                // SAFETY: the value.
                unsafe { add_error_name_value(cnf) };
                return fail();
            }
        }
    }
    // SAFETY: the reference, or NULL.
    if let Some(r) = unsafe { nt.noticeref.as_ref() }
        && (r.noticenos.is_null() || r.organization.is_null())
    {
        err::raise(ERR_LIB_X509V3, X509V3_R_NEED_ORGANIZATION_AND_NUMBERS, F);
        return fail();
    }
    qual
}

/// `nref_nos`: each name of `nos` as an INTEGER appended to the reference's numbers.
///
/// # Safety
/// `nos` is a live stack of `CONF_VALUE`s.
unsafe fn nref_nos(r: &mut NOTICEREF, nos: *mut stack_st_CONF_VALUE) -> bool {
    const F: &str = "nref_nos";
    // SAFETY: the caller's stack.
    let n = unsafe { OPENSSL_sk_num(nos.cast()) };
    for i in 0..n {
        // SAFETY: an index within the stack.
        let Some(cnf) = (unsafe { item_at::<CONF_VALUE>(nos.cast(), i) }) else {
            continue;
        };
        // SAFETY: its name.
        let aint = unsafe { s2i_ASN1_INTEGER(ptr::null_mut(), cnf.name) };
        if aint.is_null() {
            err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_NUMBER, F);
            return false;
        }
        // SAFETY: the reference's numbers; the INTEGER, which they take.
        if unsafe { OPENSSL_sk_push(r.noticenos.cast(), aint.cast()) } == 0 {
            // SAFETY: made above.
            unsafe { ASN1_INTEGER_free(aint) };
            err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, F);
            return false;
        }
    }
    true
}

/// `%.*s` of a string, with its length and data.
///
/// # Safety
/// `out` is a live BIO; `fmt` takes an indent, an empty string, a length, and data;
/// `s` is NULL or a live string.
unsafe fn print_string(
    out: *mut BIO,
    fmt: &CStr,
    indent: c_int,
    s: *const rustyssl_abi::ASN1_STRING,
) {
    // SAFETY: the caller's guarantee.
    let (len, data) = unsafe { s.as_ref() }.map_or((0, ptr::null_mut()), |s| (s.length, s.data));
    // SAFETY: as above.
    unsafe { BIO_printf(out, fmt.as_ptr(), indent, c"".as_ptr(), len, data) };
}

/// `print_notice`.
///
/// # Safety
/// `out` is a live BIO; `notice` is a live user notice.
unsafe fn print_notice(out: *mut BIO, notice: &USERNOTICE, indent: c_int) {
    // SAFETY: the caller's guarantee.
    if let Some(r) = unsafe { notice.noticeref.as_ref() } {
        // SAFETY: the caller's BIO; its organization.
        unsafe { print_string(out, c"%*sOrganization: %.*s\n", indent, r.organization) };
        // SAFETY: its numbers.
        let n = unsafe { OPENSSL_sk_num(r.noticenos.cast()) };
        let plural = if n > 1 { c"s" } else { c"" };
        // SAFETY: as above; a static format and its arguments.
        unsafe {
            BIO_printf(
                out,
                c"%*sNumber%s: ".as_ptr(),
                indent,
                c"".as_ptr(),
                plural.as_ptr(),
            )
        };
        for i in 0..n {
            if i > 0 {
                // SAFETY: as above.
                unsafe { BIO_puts(out, c", ".as_ptr()) };
            }
            // SAFETY: an index within the numbers.
            match unsafe { item_at::<ASN1_INTEGER>(r.noticenos.cast(), i) } {
                None => {
                    // SAFETY: as above.
                    unsafe { BIO_puts(out, c"(null)".as_ptr()) };
                }
                Some(num) => {
                    // SAFETY: the number.
                    let tmp = unsafe { i2s_ASN1_INTEGER(ptr::null_mut(), num) };
                    if tmp.is_null() {
                        return;
                    }
                    // SAFETY: as above; the text.
                    unsafe { BIO_puts(out, tmp) };
                    // SAFETY: made above.
                    unsafe { mem::release(tmp.cast()) };
                }
            }
        }
        if !notice.exptext.is_null() {
            // SAFETY: as above.
            unsafe { BIO_puts(out, c"\n".as_ptr()) };
        }
    }
    if !notice.exptext.is_null() {
        // SAFETY: as above; its text.
        unsafe { print_string(out, c"%*sExplicit Text: %.*s", indent, notice.exptext) };
    }
}

/// `print_qualifiers`.
///
/// # Safety
/// `out` is a live BIO; `quals` is a live stack of qualifiers.
pub(crate) unsafe fn print_qualifiers(out: *mut BIO, quals: *mut c_void, indent: c_int) {
    // SAFETY: the caller's guarantee.
    let n = unsafe { OPENSSL_sk_num(quals.cast()) };
    for i in 0..n {
        if i > 0 {
            // SAFETY: the caller's BIO.
            unsafe { BIO_puts(out, c"\n".as_ptr()) };
        }
        // SAFETY: an index within the stack.
        let Some(q) = (unsafe { item_at::<POLICYQUALINFO>(quals, i) }) else {
            continue;
        };
        // SAFETY: its object.
        match unsafe { OBJ_obj2nid(q.pqualid) } {
            n if n == NID_id_qt_cps => {
                // SAFETY: a CPS qualifier's field.
                let s = unsafe { q.d.cpsuri };
                // SAFETY: the caller's BIO; the URI.
                unsafe { print_string(out, c"%*sCPS: %.*s", indent, s) };
            }
            n if n == NID_id_qt_unotice => {
                // SAFETY: as above; a static format and its arguments.
                unsafe { BIO_printf(out, c"%*sUser Notice:\n".as_ptr(), indent, c"".as_ptr()) };
                // SAFETY: a user notice qualifier's field.
                let un = unsafe { q.d.usernotice };
                // SAFETY: its notice, or NULL.
                if let Some(un) = unsafe { un.as_ref() } {
                    // SAFETY: as above.
                    unsafe { print_notice(out, un, indent.saturating_add(2)) };
                }
            }
            _ => {
                // SAFETY: as above.
                unsafe {
                    BIO_printf(
                        out,
                        c"%*sUnknown Qualifier: ".as_ptr(),
                        indent.saturating_add(2),
                        c"".as_ptr(),
                    )
                };
                // SAFETY: as above; its object.
                unsafe { i2a_ASN1_OBJECT(out, q.pqualid) };
            }
        }
    }
}

ffi_callback! {
    /// `i2r_certpol`: each policy and its qualifiers.
    ///
    /// # Safety
    /// `ext` is a live stack of policies; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn certpol_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's stack.
        let n = unsafe { OPENSSL_sk_num(ext.cast()) };
        for i in 0..n {
            if i > 0 {
                // SAFETY: the caller's BIO.
                unsafe { BIO_puts(out, c"\n".as_ptr()) };
            }
            // SAFETY: an index within the stack.
            let Some(p) = (unsafe { item_at::<POLICYINFO>(ext, i) }) else { continue };
            // SAFETY: as above; a static format and its arguments.
            unsafe { BIO_printf(out, c"%*sPolicy: ".as_ptr(), indent, c"".as_ptr()) };
            // SAFETY: as above; its object.
            unsafe { i2a_ASN1_OBJECT(out, p.policyid) };
            if !p.qualifiers.is_null() {
                // SAFETY: as above.
                unsafe { BIO_puts(out, c"\n".as_ptr()) };
                // SAFETY: as above; its qualifiers.
                unsafe { print_qualifiers(out, p.qualifiers.cast(), indent.saturating_add(2)) };
            }
        }
        1
    }
}

pub(crate) static CPOLS: Method = Method({
    let mut m = method(NID_certificate_policies, 0);
    m.it = Some(CERTIFICATEPOLICIES_it);
    m.i2r = Some(certpol_i2r);
    m.r2i = Some(certpol_r2i);
    m
});

// Policy mappings (`v3_pmaps.c`).

static PMAP_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(POLICY_MAPPING, issuerDomainPolicy),
        c"issuerDomainPolicy",
        ASN1_OBJECT_it,
    ),
    template_at(
        0,
        0,
        offset_of!(POLICY_MAPPING, subjectDomainPolicy),
        c"subjectDomainPolicy",
        ASN1_OBJECT_it,
    ),
]);

item_fns! {
    /// PolicyMapping: SEQUENCE { issuerDomainPolicy, subjectDomainPolicy }.
    pub unsafe extern "C" fn POLICY_MAPPING_it = sequence::<POLICY_MAPPING, 2>(&PMAP_TT, None, c"POLICY_MAPPING");
}

new_free! {
    pub unsafe extern "C" fn POLICY_MAPPING_new, pub unsafe extern "C" fn POLICY_MAPPING_free(POLICY_MAPPING) = POLICY_MAPPING_it;
}

static PMAPS_T: Template = template(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    c"POLICY_MAPPINGS",
    POLICY_MAPPING_it,
);

item_fns! {
    /// PolicyMappings: SEQUENCE OF PolicyMapping.
    pub unsafe extern "C" fn POLICY_MAPPINGS_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const PMAPS_T.0, 0, ptr::null(), 0, c"POLICY_MAPPINGS");
}

ffi_callback! {
    /// `i2v_POLICY_MAPPINGS`: each mapping as `issuer:subject`.
    ///
    /// # Safety
    /// `a` is a live stack of mappings; `ext_list` is NULL or a live stack.
    pub(crate) unsafe extern "C" fn pmaps_i2v(_method: *const X509V3_EXT_METHOD, a: *mut c_void, ext_list: *mut stack_st_CONF_VALUE) -> *mut stack_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        let mut list = ext_list;
        // SAFETY: the caller's stack.
        let n = unsafe { OPENSSL_sk_num(a.cast()) };
        for i in 0..n {
            // SAFETY: an index within the stack.
            let Some(m) = (unsafe { item_at::<POLICY_MAPPING>(a, i) }) else { continue };
            let (mut t1, mut t2) = ([0 as c_char; 80], [0 as c_char; 80]);
            // SAFETY: room for 80 octets; its objects.
            unsafe { i2t_ASN1_OBJECT(t1.as_mut_ptr(), 80, m.issuerDomainPolicy) };
            // SAFETY: as above.
            unsafe { i2t_ASN1_OBJECT(t2.as_mut_ptr(), 80, m.subjectDomainPolicy) };
            // SAFETY: the names; the list.
            unsafe { X509V3_add_value(t1.as_ptr(), t2.as_ptr(), &raw mut list) };
        }
        list
    }
}

/// `POLICY_MAPPING_free` as a stack's free function.
pub(crate) unsafe extern "C" fn free_pmap(p: *mut c_void) {
    // SAFETY: a mapping of the stack, which the stack owned.
    unsafe { POLICY_MAPPING_free(p.cast()) };
}

ffi_callback! {
    /// `v2i_POLICY_MAPPINGS`: each `issuer:subject` pair of objects.
    ///
    /// # Safety
    /// `nval` is NULL or a live stack of `CONF_VALUE`s.
    pub(crate) unsafe extern "C" fn pmaps_v2i(_method: *const X509V3_EXT_METHOD, _ctx: *mut X509V3_CTX, nval: *mut stack_st_CONF_VALUE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        const F: &str = "v2i_POLICY_MAPPINGS";
        // SAFETY: the caller's stack, or NULL.
        let num = unsafe { OPENSSL_sk_num(nval.cast()) };
        // SAFETY: no preconditions.
        let pmaps = unsafe { OPENSSL_sk_new_reserve(None, num) };
        if pmaps.is_null() {
            err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, F);
            return ptr::null_mut();
        }
        let fail = |obj1: *mut ASN1_OBJECT, obj2: *mut ASN1_OBJECT| {
            // SAFETY: made here, or NULL.
            unsafe { ASN1_OBJECT_free(obj1) };
            // SAFETY: as above.
            unsafe { ASN1_OBJECT_free(obj2) };
            // SAFETY: the stack made above, with its mappings.
            unsafe { OPENSSL_sk_pop_free(pmaps, Some(free_pmap)) };
            ptr::null_mut()
        };
        for i in 0..num {
            // SAFETY: an index within the stack.
            let Some(v) = (unsafe { item_at::<CONF_VALUE>(nval.cast(), i) }) else { continue };
            // SAFETY: its name.
            let name = unsafe { text(v.name) }.unwrap_or_default();
            if v.value.is_null() || v.name.is_null() {
                err::raise_with_bytes(ERR_LIB_X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER, F, name);
                return fail(ptr::null_mut(), ptr::null_mut());
            }
            // SAFETY: its strings.
            let obj1 = unsafe { OBJ_txt2obj(v.name, 0) };
            // SAFETY: as above.
            let obj2 = unsafe { OBJ_txt2obj(v.value, 0) };
            if obj1.is_null() || obj2.is_null() {
                err::raise_with_bytes(ERR_LIB_X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER, F, name);
                return fail(obj1, obj2);
            }
            // SAFETY: no preconditions.
            let pmap = unsafe { POLICY_MAPPING_new() };
            // SAFETY: new, or NULL.
            let Some(m) = (unsafe { pmap.as_mut() }) else {
                err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
                return fail(obj1, obj2);
            };
            m.issuerDomainPolicy = obj1;
            m.subjectDomainPolicy = obj2;
            // SAFETY: the stack, with room reserved; the mapping, which it takes.
            unsafe { OPENSSL_sk_push(pmaps, pmap.cast()) };
        }
        pmaps.cast()
    }
}

pub(crate) static POLICY_MAPPINGS: Method = Method({
    let mut m = method(NID_policy_mappings, 0);
    m.it = Some(POLICY_MAPPINGS_it);
    m.i2v = Some(pmaps_i2v);
    m.v2i = Some(pmaps_v2i);
    m
});

// Policy constraints (`v3_pcons.c`).

static PCONS_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(POLICY_CONSTRAINTS, requireExplicitPolicy),
        c"requireExplicitPolicy",
        ASN1_INTEGER_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(POLICY_CONSTRAINTS, inhibitPolicyMapping),
        c"inhibitPolicyMapping",
        ASN1_INTEGER_it,
    ),
]);

item_fns! {
    /// PolicyConstraints: SEQUENCE { requireExplicitPolicy [0] OPTIONAL, inhibitPolicyMapping
    /// [1] OPTIONAL }.
    pub unsafe extern "C" fn POLICY_CONSTRAINTS_it = sequence::<POLICY_CONSTRAINTS, 2>(&PCONS_TT, None, c"POLICY_CONSTRAINTS");
}

new_free! {
    pub unsafe extern "C" fn POLICY_CONSTRAINTS_new, pub unsafe extern "C" fn POLICY_CONSTRAINTS_free(POLICY_CONSTRAINTS) = POLICY_CONSTRAINTS_it;
}

ffi_callback! {
    /// `i2v_POLICY_CONSTRAINTS`: the two numbers, where present.
    ///
    /// # Safety
    /// `a` is a live PolicyConstraints; `extlist` is NULL or a live stack.
    pub(crate) unsafe extern "C" fn pcons_i2v(_method: *const X509V3_EXT_METHOD, a: *mut c_void, extlist: *mut stack_st_CONF_VALUE) -> *mut stack_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { a.cast::<POLICY_CONSTRAINTS>().as_ref() }) else { return extlist };
        let mut list = extlist;
        // SAFETY: a static name; its number, or NULL; the list.
        unsafe { super::simple::X509V3_add_value_int(c"Require Explicit Policy".as_ptr(), p.requireExplicitPolicy, &raw mut list) };
        // SAFETY: as above.
        unsafe { super::simple::X509V3_add_value_int(c"Inhibit Policy Mapping".as_ptr(), p.inhibitPolicyMapping, &raw mut list) };
        list
    }
}

ffi_callback! {
    /// `v2i_POLICY_CONSTRAINTS`: `requireExplicitPolicy` and `inhibitPolicyMapping`, at least one.
    ///
    /// # Safety
    /// `values` is NULL or a live stack of `CONF_VALUE`s.
    pub(crate) unsafe extern "C" fn pcons_v2i(_method: *const X509V3_EXT_METHOD, _ctx: *mut X509V3_CTX, values: *mut stack_st_CONF_VALUE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        const F: &str = "v2i_POLICY_CONSTRAINTS";
        // SAFETY: no preconditions.
        let pcons = unsafe { POLICY_CONSTRAINTS_new() };
        // SAFETY: new, or NULL.
        let Some(p) = (unsafe { pcons.as_mut() }) else {
            err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
            return ptr::null_mut();
        };
        let fail = || {
            // SAFETY: made above.
            unsafe { POLICY_CONSTRAINTS_free(pcons) };
            ptr::null_mut()
        };
        // SAFETY: the caller's stack, or NULL.
        let n = unsafe { OPENSSL_sk_num(values.cast()) };
        for i in 0..n {
            // SAFETY: an index within the stack.
            let Some(v) = (unsafe { item_at::<CONF_VALUE>(values.cast(), i) }) else { continue };
            // SAFETY: its name.
            let name = unsafe { text(v.name) };
            let slot = match name {
                Some(b"requireExplicitPolicy") => &raw mut p.requireExplicitPolicy,
                Some(b"inhibitPolicyMapping") => &raw mut p.inhibitPolicyMapping,
                _ => {
                    err::raise_with_bytes(ERR_LIB_X509V3, X509V3_R_INVALID_NAME, F, name.unwrap_or_default());
                    return fail();
                }
            };
            // SAFETY: the value; the field.
            if unsafe { X509V3_get_value_int(v, slot) } == 0 {
                return fail();
            }
        }
        if p.inhibitPolicyMapping.is_null() && p.requireExplicitPolicy.is_null() {
            err::raise(ERR_LIB_X509V3, X509V3_R_ILLEGAL_EMPTY_EXTENSION, F);
            return fail();
        }
        pcons.cast()
    }
}

pub(crate) static POLICY_CONSTRAINTS_METHOD: Method = Method({
    let mut m = method(NID_policy_constraints, 0);
    m.it = Some(POLICY_CONSTRAINTS_it);
    m.i2v = Some(pcons_i2v);
    m.v2i = Some(pcons_v2i);
    m
});

// Proxy certificates (`v3_pcia.c`, `v3_pci.c`).

static PROXY_POLICY_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(PROXY_POLICY, policyLanguage),
        c"policyLanguage",
        ASN1_OBJECT_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(PROXY_POLICY, policy),
        c"policy",
        ASN1_OCTET_STRING_it,
    ),
]);

item_fns! {
    /// ProxyPolicy: SEQUENCE { policyLanguage, policy OCTET STRING OPTIONAL }.
    pub unsafe extern "C" fn PROXY_POLICY_it = sequence::<PROXY_POLICY, 2>(&PROXY_POLICY_TT, None, c"PROXY_POLICY");
}

new_free! {
    pub unsafe extern "C" fn PROXY_POLICY_new, pub unsafe extern "C" fn PROXY_POLICY_free(PROXY_POLICY) = PROXY_POLICY_it;
}

i2d! {
    /// Encodes a ProxyPolicy.
    pub unsafe extern "C" fn i2d_PROXY_POLICY(PROXY_POLICY) = PROXY_POLICY_it;
}

d2i! {
    /// Decodes a ProxyPolicy (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_PROXY_POLICY(PROXY_POLICY) = PROXY_POLICY_it;
}

static PCI_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(PROXY_CERT_INFO_EXTENSION, pcPathLengthConstraint),
        c"pcPathLengthConstraint",
        ASN1_INTEGER_it,
    ),
    template_at(
        0,
        0,
        offset_of!(PROXY_CERT_INFO_EXTENSION, proxyPolicy),
        c"proxyPolicy",
        PROXY_POLICY_it,
    ),
]);

item_fns! {
    /// ProxyCertInfo: SEQUENCE { pCPathLenConstraint INTEGER OPTIONAL, proxyPolicy }.
    pub unsafe extern "C" fn PROXY_CERT_INFO_EXTENSION_it = sequence::<PROXY_CERT_INFO_EXTENSION, 2>(&PCI_TT, None, c"PROXY_CERT_INFO_EXTENSION");
}

new_free! {
    pub unsafe extern "C" fn PROXY_CERT_INFO_EXTENSION_new, pub unsafe extern "C" fn PROXY_CERT_INFO_EXTENSION_free(PROXY_CERT_INFO_EXTENSION) = PROXY_CERT_INFO_EXTENSION_it;
}

i2d! {
    /// Encodes a ProxyCertInfo.
    pub unsafe extern "C" fn i2d_PROXY_CERT_INFO_EXTENSION(PROXY_CERT_INFO_EXTENSION) = PROXY_CERT_INFO_EXTENSION_it;
}

d2i! {
    /// Decodes a ProxyCertInfo (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_PROXY_CERT_INFO_EXTENSION(PROXY_CERT_INFO_EXTENSION) = PROXY_CERT_INFO_EXTENSION_it;
}

ffi_callback! {
    /// `i2r_pci`: the path length (or `infinite`), the policy language, and the policy text.
    ///
    /// # Safety
    /// `ext` is a live ProxyCertInfo; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn pci_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(pci) = (unsafe { ext.cast::<PROXY_CERT_INFO_EXTENSION>().as_ref() }) else { return 0 };
        // SAFETY: the caller's BIO; a static format and its arguments.
        unsafe { BIO_printf(out, c"%*sPath Length Constraint: ".as_ptr(), indent, c"".as_ptr()) };
        if pci.pcPathLengthConstraint.is_null() {
            // SAFETY: as above.
            unsafe { BIO_puts(out, c"infinite".as_ptr()) };
        } else {
            // SAFETY: as above; its INTEGER.
            unsafe { i2a_ASN1_INTEGER(out, pci.pcPathLengthConstraint) };
        }
        // SAFETY: as above.
        unsafe { BIO_puts(out, c"\n".as_ptr()) };
        // SAFETY: as above.
        unsafe { BIO_printf(out, c"%*sPolicy Language: ".as_ptr(), indent, c"".as_ptr()) };
        // SAFETY: its policy, made with it.
        let Some(pp) = (unsafe { pci.proxyPolicy.as_ref() }) else { return 1 };
        // SAFETY: as above; its object.
        unsafe { i2a_ASN1_OBJECT(out, pp.policyLanguage) };
        // SAFETY: its policy, or NULL.
        if let Some(pol) = unsafe { pp.policy.as_ref() }
            && !pol.data.is_null()
        {
            // SAFETY: as above.
            unsafe { print_string(out, c"\n%*sPolicy Text: %.*s", indent, pol) };
        }
        1
    }
}

/// Appends `bytes` (and a NUL) to the policy's octets.
///
/// # Safety
/// `policy` is a live OCTET STRING.
unsafe fn append(policy: &mut ASN1_OCTET_STRING, bytes: &[u8]) -> bool {
    let old = usize::try_from(policy.length).unwrap_or(0);
    let Some(new_len) = old.checked_add(bytes.len()) else {
        return false;
    };
    let Ok(new_int) = c_int::try_from(new_len) else {
        return false;
    };
    // SAFETY: the string's own data, or NULL.
    let grown: *mut u8 =
        unsafe { mem::resize(policy.data.cast(), new_len.saturating_add(1)) }.cast();
    if grown.is_null() {
        // SAFETY: as above.
        unsafe { mem::release(policy.data.cast()) };
        policy.data = ptr::null_mut();
        policy.length = 0;
        return false;
    }
    // SAFETY: room for the old octets, the new ones, and a NUL.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), grown.wrapping_add(old), bytes.len()) };
    // SAFETY: as above.
    unsafe { grown.wrapping_add(new_len).write(0) };
    policy.data = grown;
    policy.length = new_int;
    true
}

/// The octets of a `hex:`, `file:`, or `text:` policy, or `None` (with the reason raised).
///
/// # Safety
/// No preconditions beyond `valp` being the value's text.
unsafe fn policy_octets(valp: &[u8]) -> Result<Vec<u8>, Option<c_int>> {
    if let Some(h) = valp.strip_prefix(b"hex:") {
        let s = std::ffi::CString::new(h).map_err(|_| None)?;
        let mut n: c_long = 0;
        // SAFETY: a C string; a writable length.
        let buf = unsafe { crate::string::OPENSSL_hexstr2buf(s.as_ptr(), &raw mut n) };
        if buf.is_null() {
            return Err(None);
        }
        let len = usize::try_from(n).unwrap_or(0);
        // SAFETY: the buffer's `n` octets.
        let v = unsafe { core::slice::from_raw_parts(buf.cast_const(), len) }.to_vec();
        // SAFETY: made above.
        unsafe { mem::release(buf.cast()) };
        return Ok(v);
    }
    if let Some(path) = valp.strip_prefix(b"file:") {
        let p = std::ffi::CString::new(path).map_err(|_| None)?;
        // SAFETY: C strings.
        let b = unsafe { crate::bio::file::BIO_new_file(p.as_ptr(), c"r".as_ptr()) };
        if b.is_null() {
            return Err(Some(ERR_R_BIO_LIB));
        }
        let mut out = Vec::new();
        let mut buf = [0u8; 2048];
        let n = loop {
            // SAFETY: the file's BIO; room for the buffer.
            let n = unsafe { BIO_read(b, buf.as_mut_ptr().cast(), 2048) };
            // SAFETY: as above.
            if n > 0 || (n == 0 && unsafe { BIO_test_flags(b, BIO_FLAGS_SHOULD_RETRY) } != 0) {
                out.extend_from_slice(
                    buf.get(..usize::try_from(n).unwrap_or(0))
                        .unwrap_or_default(),
                );
                continue;
            }
            break n;
        };
        // SAFETY: made above.
        unsafe { BIO_free_all(b) };
        if n < 0 {
            return Err(Some(ERR_R_BIO_LIB));
        }
        return Ok(out);
    }
    if let Some(t) = valp.strip_prefix(b"text:") {
        return Ok(t.to_vec());
    }
    Err(Some(X509V3_R_INCORRECT_POLICY_SYNTAX_TAG))
}

/// `process_pci_value`: one setting (`language`, `pathlen`, or `policy`, which accumulates).
///
/// # Safety
/// `val` is a live `CONF_VALUE`.
unsafe fn process_pci_value(
    val: &CONF_VALUE,
    language: &mut *mut ASN1_OBJECT,
    pathlen: &mut *mut ASN1_INTEGER,
    policy: &mut *mut ASN1_OCTET_STRING,
) -> bool {
    const F: &str = "process_pci_value";
    // SAFETY: its name.
    match unsafe { text(val.name) } {
        Some(b"language") => {
            if !language.is_null() {
                err::raise(ERR_LIB_X509V3, X509V3_R_POLICY_LANGUAGE_ALREADY_DEFINED, F);
                // SAFETY: the value.
                unsafe { conf_err(val) };
                return false;
            }
            *language = if val.value.is_null() {
                ptr::null_mut()
            } else {
                // SAFETY: its value.
                unsafe { OBJ_txt2obj(val.value, 0) }
            };
            if language.is_null() {
                err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER, F);
                // SAFETY: the value.
                unsafe { conf_err(val) };
                return false;
            }
        }
        Some(b"pathlen") => {
            if !pathlen.is_null() {
                err::raise(
                    ERR_LIB_X509V3,
                    X509V3_R_POLICY_PATH_LENGTH_ALREADY_DEFINED,
                    F,
                );
                // SAFETY: the value.
                unsafe { conf_err(val) };
                return false;
            }
            // SAFETY: the value; the slot.
            if unsafe { X509V3_get_value_int(val, pathlen) } == 0 {
                err::raise(ERR_LIB_X509V3, X509V3_R_POLICY_PATH_LENGTH, F);
                // SAFETY: the value.
                unsafe { conf_err(val) };
                return false;
            }
        }
        Some(b"policy") => {
            let free_policy = policy.is_null();
            if free_policy {
                // SAFETY: no preconditions.
                *policy = unsafe { ASN1_OCTET_STRING_new() };
                if policy.is_null() {
                    err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
                    // SAFETY: the value.
                    unsafe { conf_err(val) };
                    return false;
                }
            }
            // SAFETY: its value.
            let valp = unsafe { text(val.value) }.unwrap_or_default();
            // SAFETY: the value's text.
            let ok = match unsafe { policy_octets(valp) } {
                Ok(bytes) => {
                    // SAFETY: the policy, made or the caller's.
                    let p = unsafe { &mut **policy };
                    // SAFETY: as above.
                    unsafe { append(p, &bytes) }
                }
                Err(reason) => {
                    if let Some(r) = reason {
                        err::raise(ERR_LIB_X509V3, r, F);
                    }
                    false
                }
            };
            if !ok {
                // SAFETY: the value.
                unsafe { conf_err(val) };
                if free_policy {
                    // SAFETY: made above.
                    unsafe { ASN1_OCTET_STRING_free(*policy) };
                    *policy = ptr::null_mut();
                }
                return false;
            }
        }
        _ => {}
    }
    true
}

ffi_callback! {
    /// `r2i_pci`: `language`, `pathlen`, and `policy` settings, directly or in `@section`s; the
    /// language is required, and the inheriting and independent ones take no policy.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `value` is NULL or a C string.
    pub(crate) unsafe extern "C" fn pci_r2i(_method: *const X509V3_EXT_METHOD, ctx: *mut X509V3_CTX, value: *const c_char) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        const F: &str = "r2i_pci";
        // SAFETY: the caller's guarantee.
        let vals = unsafe { X509V3_parse_list(value) };
        let (mut language, mut pathlen, mut policy) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        let mut pci: *mut PROXY_CERT_INFO_EXTENSION = ptr::null_mut();
        let ok = 'parse: {
            // SAFETY: the list, or NULL.
            let n = unsafe { OPENSSL_sk_num(vals.cast()) };
            for i in 0..n {
                // SAFETY: an index within the list.
                let Some(cnf) = (unsafe { item_at::<CONF_VALUE>(vals.cast(), i) }) else { continue };
                // SAFETY: its name.
                let name = unsafe { text(cnf.name) };
                let at = name.and_then(|n| n.first()) == Some(&b'@');
                if name.is_none() || (!at && cnf.value.is_null()) {
                    err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_PROXY_POLICY_SETTING, F);
                    // SAFETY: the value.
                    unsafe { conf_err(cnf) };
                    break 'parse false;
                }
                if at {
                    // SAFETY: the caller's context; the section's name after `@`.
                    let sect = unsafe { X509V3_get_section(ctx, cnf.name.wrapping_add(1)) };
                    if sect.is_null() {
                        err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_SECTION, F);
                        // SAFETY: the value.
                        unsafe { conf_err(cnf) };
                        break 'parse false;
                    }
                    let mut success = true;
                    // SAFETY: the section.
                    let m = unsafe { OPENSSL_sk_num(sect.cast()) };
                    for j in 0..m {
                        if !success {
                            break;
                        }
                        // SAFETY: an index within the section.
                        if let Some(v) = unsafe { item_at::<CONF_VALUE>(sect.cast(), j) } {
                            // SAFETY: a value of the section; the settings.
                            success = unsafe { process_pci_value(v, &mut language, &mut pathlen, &mut policy) };
                        }
                    }
                    // SAFETY: the context's section.
                    unsafe { X509V3_section_free(ctx, sect) };
                    if !success {
                        break 'parse false;
                    }
                } else {
                    // SAFETY: the value; the settings.
                    if !unsafe { process_pci_value(cnf, &mut language, &mut pathlen, &mut policy) } {
                        // SAFETY: the value.
                        unsafe { conf_err(cnf) };
                        break 'parse false;
                    }
                }
            }
            if language.is_null() {
                err::raise(ERR_LIB_X509V3, X509V3_R_NO_PROXY_CERT_POLICY_LANGUAGE_DEFINED, F);
                break 'parse false;
            }
            // SAFETY: the language.
            let nid = unsafe { OBJ_obj2nid(language) };
            if (nid == NID_Independent || nid == NID_id_ppl_inheritAll) && !policy.is_null() {
                err::raise(ERR_LIB_X509V3, X509V3_R_POLICY_WHEN_PROXY_LANGUAGE_REQUIRES_NO_POLICY, F);
                break 'parse false;
            }
            // SAFETY: no preconditions.
            pci = unsafe { PROXY_CERT_INFO_EXTENSION_new() };
            // SAFETY: new, or NULL.
            let Some(p) = (unsafe { pci.as_mut() }) else {
                err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
                break 'parse false;
            };
            // SAFETY: its policy, made with it.
            let Some(pp) = (unsafe { p.proxyPolicy.as_mut() }) else { break 'parse false };
            pp.policyLanguage = core::mem::replace(&mut language, ptr::null_mut());
            pp.policy = core::mem::replace(&mut policy, ptr::null_mut());
            p.pcPathLengthConstraint = core::mem::replace(&mut pathlen, ptr::null_mut());
            true
        };
        if !ok {
            // SAFETY: made here, or NULL.
            unsafe { ASN1_OBJECT_free(language) };
            // SAFETY: as above.
            unsafe { ASN1_INTEGER_free(pathlen) };
            // SAFETY: as above.
            unsafe { ASN1_OCTET_STRING_free(policy) };
            // SAFETY: as above.
            unsafe { PROXY_CERT_INFO_EXTENSION_free(pci) };
            pci = ptr::null_mut();
        }
        // SAFETY: the list made above, or NULL.
        unsafe { OPENSSL_sk_pop_free(vals.cast(), Some(free_conf)) };
        pci.cast()
    }
}

pub(crate) static PCI: Method = Method({
    let mut m = method(NID_proxyCertInfo, 0);
    m.it = Some(PROXY_CERT_INFO_EXTENSION_it);
    m.i2r = Some(pci_i2r);
    m.r2i = Some(pci_r2i);
    m
});

// Name constraints (`v3_ncons.c`).

static SUBTREE_TT: Templates<3> = Templates([
    template_at(
        0,
        0,
        offset_of!(GENERAL_SUBTREE, base),
        c"base",
        GENERAL_NAME_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(GENERAL_SUBTREE, minimum),
        c"minimum",
        ASN1_INTEGER_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(GENERAL_SUBTREE, maximum),
        c"maximum",
        ASN1_INTEGER_it,
    ),
]);

item_fns! {
    /// GeneralSubtree: SEQUENCE { base GeneralName, minimum [0] OPTIONAL, maximum [1] OPTIONAL }.
    pub unsafe extern "C" fn GENERAL_SUBTREE_it = sequence::<GENERAL_SUBTREE, 3>(&SUBTREE_TT, None, c"GENERAL_SUBTREE");
}

new_free! {
    pub unsafe extern "C" fn GENERAL_SUBTREE_new, pub unsafe extern "C" fn GENERAL_SUBTREE_free(GENERAL_SUBTREE) = GENERAL_SUBTREE_it;
}

static NC_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(NAME_CONSTRAINTS, permittedSubtrees),
        c"permittedSubtrees",
        GENERAL_SUBTREE_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(NAME_CONSTRAINTS, excludedSubtrees),
        c"excludedSubtrees",
        GENERAL_SUBTREE_it,
    ),
]);

item_fns! {
    /// NameConstraints: SEQUENCE { permittedSubtrees [0] OPTIONAL, excludedSubtrees [1]
    /// OPTIONAL }.
    pub unsafe extern "C" fn NAME_CONSTRAINTS_it = sequence::<NAME_CONSTRAINTS, 2>(&NC_TT, None, c"NAME_CONSTRAINTS");
}

new_free! {
    pub unsafe extern "C" fn NAME_CONSTRAINTS_new, pub unsafe extern "C" fn NAME_CONSTRAINTS_free(NAME_CONSTRAINTS) = NAME_CONSTRAINTS_it;
}

ffi_callback! {
    /// `v2i_NAME_CONSTRAINTS`: `permitted;type:value` and `excluded;type:value` (any separator
    /// after the word), each a subtree of a name (an IP address as a network).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `nval` is NULL or a live stack of `CONF_VALUE`s.
    pub(crate) unsafe extern "C" fn ncons_v2i(method: *const X509V3_EXT_METHOD, ctx: *mut X509V3_CTX, nval: *mut stack_st_CONF_VALUE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        const F: &str = "v2i_NAME_CONSTRAINTS";
        // SAFETY: no preconditions.
        let ncons = unsafe { NAME_CONSTRAINTS_new() };
        // SAFETY: new, or NULL.
        let Some(nc) = (unsafe { ncons.as_mut() }) else {
            err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
            return ptr::null_mut();
        };
        let fail = |sub: *mut GENERAL_SUBTREE| {
            // SAFETY: made above.
            unsafe { NAME_CONSTRAINTS_free(ncons) };
            // SAFETY: made here, or NULL.
            unsafe { GENERAL_SUBTREE_free(sub) };
            ptr::null_mut()
        };
        // SAFETY: the caller's stack, or NULL.
        let n = unsafe { OPENSSL_sk_num(nval.cast()) };
        for i in 0..n {
            // SAFETY: an index within the stack.
            let Some(val) = (unsafe { item_at::<CONF_VALUE>(nval.cast(), i) }) else { continue };
            // SAFETY: its name.
            let name = unsafe { text(val.name) }.unwrap_or_default();
            let (ptree, skip) = if name.len() > 9 && name.starts_with(b"permitted") {
                (&raw mut nc.permittedSubtrees, 10)
            } else if name.len() > 8 && name.starts_with(b"excluded") {
                (&raw mut nc.excludedSubtrees, 9)
            } else {
                err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_SYNTAX, F);
                return fail(ptr::null_mut());
            };
            let mut tval = CONF_VALUE { section: ptr::null_mut(), name: val.name.wrapping_add(skip), value: val.value };
            // SAFETY: no preconditions.
            let sub = unsafe { GENERAL_SUBTREE_new() };
            // SAFETY: new, or NULL.
            let Some(s) = (unsafe { sub.as_mut() }) else {
                err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
                return fail(ptr::null_mut());
            };
            // SAFETY: its base; the caller's context; the value, as a network for an address.
            if unsafe { v2i_GENERAL_NAME_ex(s.base, method, ctx, &raw mut tval, 1) }.is_null() {
                err::raise(ERR_LIB_X509V3, ERR_R_X509V3_LIB, F);
                return fail(sub);
            }
            // SAFETY: the constraints' field.
            let tree = unsafe { &mut *ptree };
            if tree.is_null() {
                // SAFETY: no preconditions.
                *tree = unsafe { OPENSSL_sk_new_null() }.cast();
            }
            // SAFETY: the stack, or NULL; the subtree, which it takes.
            if tree.is_null() || unsafe { OPENSSL_sk_push(tree.cast(), sub.cast()) } == 0 {
                err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, F);
                return fail(sub);
            }
        }
        ncons.cast()
    }
}

/// `print_nc_ipadd`: an address and its mask, as `IP:address/mask`.
///
/// # Safety
/// `bp` is a live BIO; `ip` is a live OCTET STRING.
unsafe fn print_nc_ipadd(bp: *mut BIO, ip: *const ASN1_OCTET_STRING) {
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { ip.as_ref() }) else {
        return;
    };
    let total = usize::try_from(s.length).unwrap_or(0);
    let octets = if s.data.is_null() {
        &[][..]
    } else {
        // SAFETY: the string's octets.
        unsafe { core::slice::from_raw_parts(s.data, total) }
    };
    let len1 = if total >= 16 {
        16
    } else if total >= 4 {
        4
    } else {
        total
    };
    let (a, m) = octets.split_at(len1.min(octets.len()));
    let text = format!(
        "IP:{}/{}",
        rustyssl_pki::ip::to_text(a),
        rustyssl_pki::ip::to_text(m)
    );
    let c = crate::conf::c_dup(text.as_bytes());
    if !c.is_null() {
        // SAFETY: the caller's BIO; the text.
        unsafe { BIO_puts(bp, c) };
        // SAFETY: made above.
        unsafe { mem::release(c.cast()) };
    }
}

/// `do_i2r_name_constraints`.
///
/// # Safety
/// `trees` is NULL or a live stack of subtrees; `bp` is a live BIO.
unsafe fn print_trees(trees: *mut c_void, bp: *mut BIO, ind: c_int, name: &CStr) {
    // SAFETY: the caller's guarantee.
    let n = unsafe { OPENSSL_sk_num(trees.cast()) };
    if n > 0 {
        // SAFETY: the caller's BIO; a static format and its arguments.
        unsafe { BIO_printf(bp, c"%*s%s:\n".as_ptr(), ind, c"".as_ptr(), name.as_ptr()) };
    }
    for i in 0..n {
        if i > 0 {
            // SAFETY: as above.
            unsafe { BIO_puts(bp, c"\n".as_ptr()) };
        }
        // SAFETY: an index within the stack.
        let Some(t) = (unsafe { item_at::<GENERAL_SUBTREE>(trees, i) }) else {
            continue;
        };
        // SAFETY: as above.
        unsafe { indent_to(bp, ind.saturating_add(2)) };
        // SAFETY: its base.
        let Some(base) = (unsafe { t.base.as_mut() }) else {
            continue;
        };
        if base.type_ == GEN_IPADD {
            // SAFETY: an address's field.
            let ip = unsafe { base.d.ip };
            // SAFETY: as above.
            unsafe { print_nc_ipadd(bp, ip) };
        } else {
            // SAFETY: as above.
            unsafe { GENERAL_NAME_print(bp, base) };
        }
    }
}

ffi_callback! {
    /// `i2r_NAME_CONSTRAINTS`: the permitted subtrees, a blank line, and the excluded ones.
    ///
    /// # Safety
    /// `a` is a live NameConstraints; `bp` is a live BIO.
    pub(crate) unsafe extern "C" fn ncons_i2r(_method: *const X509V3_EXT_METHOD, a: *mut c_void, bp: *mut BIO, ind: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(nc) = (unsafe { a.cast::<NAME_CONSTRAINTS>().as_ref() }) else { return 0 };
        // SAFETY: its trees; the caller's BIO.
        unsafe { print_trees(nc.permittedSubtrees.cast(), bp, ind, c"Permitted") };
        if !nc.permittedSubtrees.is_null() && !nc.excludedSubtrees.is_null() {
            // SAFETY: as above.
            unsafe { BIO_puts(bp, c"\n".as_ptr()) };
        }
        // SAFETY: as above.
        unsafe { print_trees(nc.excludedSubtrees.cast(), bp, ind, c"Excluded") };
        1
    }
}

const fn ncons(nid: c_int) -> Method {
    let mut m = method(nid, 0);
    m.it = Some(NAME_CONSTRAINTS_it);
    m.v2i = Some(ncons_v2i);
    m.i2r = Some(ncons_i2r);
    Method(m)
}

pub(crate) static NAME_CONSTRAINTS_METHOD: Method = ncons(NID_name_constraints);
pub(crate) static HOLDER_NAME_CONSTRAINTS: Method = ncons(NID_holder_name_constraints);
pub(crate) static DELEGATED_NAME_CONSTRAINTS: Method = ncons(NID_delegated_name_constraints);
