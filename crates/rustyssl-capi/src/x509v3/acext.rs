//! The attribute certificate extensions (RFC 5755 and ITU-T X.509's, `v3_ac_tgt.c`,
//! `v3_authattid.c`, `v3_battcons.c`, `v3_iobo.c`, `v3_rolespec.c`, `v3_sda.c`,
//! `v3_usernotice.c`, and the NULL ones): targeting information, the authority attribute
//! identifier, basic attribute constraints, issued on behalf of, role specification
//! certificate identifiers, subject directory attributes and associated information, user
//! notices, and the markers whose value is NULL (indirect issuer, no assertion, SOA
//! identifier, group AC, no revocation available, single use).
//!
//! As OpenSSL's, they print (`i2r`) but aren't made from configuration, but for basic
//! attribute constraints (`authority`, `pathlen`) and the markers (any value). Issued on
//! behalf of prints nothing, and fails, at no indent.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ASN1_ITEM, ASN1_ITYPE_PRIMITIVE, ASN1_TFLG_EXPLICIT, ASN1_TFLG_IMPLICIT, ASN1_TFLG_OPTIONAL,
    ASN1_TFLG_SEQUENCE_OF, BIO, CONF_VALUE, ERR_LIB_ASN1, ERR_LIB_X509V3, ERR_R_ASN1_LIB,
    GENERAL_NAME, NID_associated_information, NID_authority_attribute_identifier,
    NID_basic_att_constraints, NID_group_ac, NID_indirect_issuer, NID_issued_on_behalf_of,
    NID_no_assertion, NID_no_rev_avail, NID_role_spec_cert_identifier, NID_single_use,
    NID_soa_identifier, NID_subject_directory_attributes, NID_target_information, NID_undef,
    NID_user_notice, NOTICEREF, OSSL_ATTRIBUTES_SYNTAX, OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX,
    OSSL_BASIC_ATTR_CONSTRAINTS, OSSL_ROLE_SPEC_CERT_ID, OSSL_ROLE_SPEC_CERT_ID_SYNTAX,
    OSSL_TARGET, OSSL_TARGET_CERT, OSSL_TARGETING_INFORMATION, OSSL_TARGETS, OSSL_TGT_TARGET_CERT,
    OSSL_TGT_TARGET_GROUP, OSSL_TGT_TARGET_NAME, OSSL_USER_NOTICE_SYNTAX, USERNOTICE, X509V3_CTX,
    X509V3_EXT_METHOD, X509V3_EXT_MULTILINE, X509V3_R_INVALID_NAME, stack_st_CONF_VALUE,
};

use super::crld::OSSL_GENERAL_NAMES_print;
use super::genn::GENERAL_NAME_it;
use super::policy::USERNOTICE_it;
use super::registry::{Method, method};
use super::san::GENERAL_NAME_print;
use super::simple::{
    X509V3_add_value_bool, X509V3_add_value_int, X509V3_get_value_int, add_error_name_value,
};
use super::text::{Out, precision_text};
use super::{X509V3_get_value_bool, i2s_ASN1_INTEGER, item_at};
use crate::asn1::tpl::items::{
    ASN1_FBOOLEAN_it, ASN1_INTEGER_it, ASN1_NULL_it, ASN1_NULL_new, d2i, i2d, new_free,
};
use crate::asn1::tpl::statics::{Templates, choice, sequence};
use crate::asn1::tpl::{Template, item, item_fns, template, template_at};
use crate::err;
use crate::ffi::ffi_callback;
use crate::mem;
use crate::objects::{OBJ_nid2ln, OBJ_obj2nid, i2a_ASN1_OBJECT};
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::x509::acert::{
    issuer_serial_it, issuer_serial_print, object_digest_info_it, object_digest_info_print,
};
use crate::x509::attrib::{
    X509_ATTRIBUTE_count, X509_ATTRIBUTE_get0_object, X509_ATTRIBUTE_get0_type, X509_ATTRIBUTE_it,
};
use crate::x509::attrval::print_attribute_value;
use crate::x509::print::serial_number_print;

// The items.

static TARGET_CERT_TT: Templates<3> = Templates([
    template_at(
        0,
        0,
        offset_of!(OSSL_TARGET_CERT, targetCertificate),
        c"targetCertificate",
        issuer_serial_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(OSSL_TARGET_CERT, targetName),
        c"targetName",
        GENERAL_NAME_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(OSSL_TARGET_CERT, certDigestInfo),
        c"certDigestInfo",
        object_digest_info_it,
    ),
]);

/// TargetCert: the certificate's issuer and serial number, and optionally its name and digest.
unsafe extern "C" fn target_cert_it() -> *const ASN1_ITEM {
    static ITEM: crate::asn1::tpl::Item =
        sequence::<OSSL_TARGET_CERT, 3>(&TARGET_CERT_TT, None, c"OSSL_TARGET_CERT");
    &raw const ITEM.0
}

static TARGET_TT: Templates<3> = Templates([
    template_at(
        ASN1_TFLG_EXPLICIT,
        0,
        offset_of!(OSSL_TARGET, choice),
        c"choice.targetName",
        GENERAL_NAME_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT,
        1,
        offset_of!(OSSL_TARGET, choice),
        c"choice.targetGroup",
        GENERAL_NAME_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT,
        2,
        offset_of!(OSSL_TARGET, choice),
        c"choice.targetCert",
        target_cert_it,
    ),
]);

item_fns! {
    /// A target: [0] a name, [1] a group, or [2] a certificate.
    pub unsafe extern "C" fn OSSL_TARGET_it = choice::<OSSL_TARGET, 3>(&TARGET_TT, offset_of!(OSSL_TARGET, type_), None, c"OSSL_TARGET");
}

new_free! {
    pub unsafe extern "C" fn OSSL_TARGET_new, pub unsafe extern "C" fn OSSL_TARGET_free(OSSL_TARGET) = OSSL_TARGET_it;
}

i2d! {
    /// Encodes an `OSSL_TARGET`.
    pub unsafe extern "C" fn i2d_OSSL_TARGET(OSSL_TARGET) = OSSL_TARGET_it;
}

d2i! {
    /// Decodes an `OSSL_TARGET` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_TARGET(OSSL_TARGET) = OSSL_TARGET_it;
}

static TARGETS_T: Template = template(ASN1_TFLG_SEQUENCE_OF, 0, c"Targets", OSSL_TARGET_it);

item_fns! {
    /// Targets: SEQUENCE OF Target.
    pub unsafe extern "C" fn OSSL_TARGETS_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const TARGETS_T.0, 0, ptr::null(), 0, c"OSSL_TARGETS");
}

new_free! {
    pub unsafe extern "C" fn OSSL_TARGETS_new, pub unsafe extern "C" fn OSSL_TARGETS_free(OSSL_TARGETS) = OSSL_TARGETS_it;
}

i2d! {
    /// Encodes an `OSSL_TARGETS`.
    pub unsafe extern "C" fn i2d_OSSL_TARGETS(OSSL_TARGETS) = OSSL_TARGETS_it;
}

d2i! {
    /// Decodes an `OSSL_TARGETS` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_TARGETS(OSSL_TARGETS) = OSSL_TARGETS_it;
}

static TINFO_T: Template = template(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    c"TargetingInformation",
    OSSL_TARGETS_it,
);

item_fns! {
    /// Targeting information: SEQUENCE OF Targets.
    pub unsafe extern "C" fn OSSL_TARGETING_INFORMATION_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const TINFO_T.0, 0, ptr::null(), 0, c"OSSL_TARGETING_INFORMATION");
}

new_free! {
    pub unsafe extern "C" fn OSSL_TARGETING_INFORMATION_new, pub unsafe extern "C" fn OSSL_TARGETING_INFORMATION_free(OSSL_TARGETING_INFORMATION) = OSSL_TARGETING_INFORMATION_it;
}

i2d! {
    /// Encodes an `OSSL_TARGETING_INFORMATION`.
    pub unsafe extern "C" fn i2d_OSSL_TARGETING_INFORMATION(OSSL_TARGETING_INFORMATION) = OSSL_TARGETING_INFORMATION_it;
}

d2i! {
    /// Decodes an `OSSL_TARGETING_INFORMATION` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_TARGETING_INFORMATION(OSSL_TARGETING_INFORMATION) = OSSL_TARGETING_INFORMATION_it;
}

static AAID_T: Template = template(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    c"OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX",
    issuer_serial_it,
);

item_fns! {
    /// An authority attribute identifier: SEQUENCE OF IssuerSerial.
    pub unsafe extern "C" fn OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const AAID_T.0, 0, ptr::null(), 0, c"OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX");
}

new_free! {
    pub unsafe extern "C" fn OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new, pub unsafe extern "C" fn OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX) = OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it;
}

i2d! {
    /// Encodes an `OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX`.
    pub unsafe extern "C" fn i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX) = OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it;
}

d2i! {
    /// Decodes an `OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX) = OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it;
}

static BATTCONS_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(OSSL_BASIC_ATTR_CONSTRAINTS, authority),
        c"authority",
        ASN1_FBOOLEAN_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(OSSL_BASIC_ATTR_CONSTRAINTS, pathlen),
        c"pathlen",
        ASN1_INTEGER_it,
    ),
]);

item_fns! {
    /// Basic attribute constraints: authority (BOOLEAN DEFAULT FALSE) and an optional path length.
    pub unsafe extern "C" fn OSSL_BASIC_ATTR_CONSTRAINTS_it = sequence::<OSSL_BASIC_ATTR_CONSTRAINTS, 2>(&BATTCONS_TT, None, c"OSSL_BASIC_ATTR_CONSTRAINTS");
}

new_free! {
    pub unsafe extern "C" fn OSSL_BASIC_ATTR_CONSTRAINTS_new, pub unsafe extern "C" fn OSSL_BASIC_ATTR_CONSTRAINTS_free(OSSL_BASIC_ATTR_CONSTRAINTS) = OSSL_BASIC_ATTR_CONSTRAINTS_it;
}

i2d! {
    /// Encodes an `OSSL_BASIC_ATTR_CONSTRAINTS`.
    pub unsafe extern "C" fn i2d_OSSL_BASIC_ATTR_CONSTRAINTS(OSSL_BASIC_ATTR_CONSTRAINTS) = OSSL_BASIC_ATTR_CONSTRAINTS_it;
}

d2i! {
    /// Decodes an `OSSL_BASIC_ATTR_CONSTRAINTS` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_BASIC_ATTR_CONSTRAINTS(OSSL_BASIC_ATTR_CONSTRAINTS) = OSSL_BASIC_ATTR_CONSTRAINTS_it;
}

static ATTRS_T: Template = template(ASN1_TFLG_SEQUENCE_OF, 0, c"Attributes", X509_ATTRIBUTE_it);

item_fns! {
    /// Attributes: SEQUENCE OF Attribute.
    pub unsafe extern "C" fn OSSL_ATTRIBUTES_SYNTAX_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const ATTRS_T.0, 0, ptr::null(), 0, c"OSSL_ATTRIBUTES_SYNTAX");
}

new_free! {
    pub unsafe extern "C" fn OSSL_ATTRIBUTES_SYNTAX_new, pub unsafe extern "C" fn OSSL_ATTRIBUTES_SYNTAX_free(OSSL_ATTRIBUTES_SYNTAX) = OSSL_ATTRIBUTES_SYNTAX_it;
}

i2d! {
    /// Encodes an `OSSL_ATTRIBUTES_SYNTAX`.
    pub unsafe extern "C" fn i2d_OSSL_ATTRIBUTES_SYNTAX(OSSL_ATTRIBUTES_SYNTAX) = OSSL_ATTRIBUTES_SYNTAX_it;
}

d2i! {
    /// Decodes an `OSSL_ATTRIBUTES_SYNTAX` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_ATTRIBUTES_SYNTAX(OSSL_ATTRIBUTES_SYNTAX) = OSSL_ATTRIBUTES_SYNTAX_it;
}

static RSCID_TT: Templates<4> = Templates([
    template_at(
        ASN1_TFLG_EXPLICIT,
        0,
        offset_of!(OSSL_ROLE_SPEC_CERT_ID, roleName),
        c"roleName",
        GENERAL_NAME_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT,
        1,
        offset_of!(OSSL_ROLE_SPEC_CERT_ID, roleCertIssuer),
        c"roleCertIssuer",
        GENERAL_NAME_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        2,
        offset_of!(OSSL_ROLE_SPEC_CERT_ID, roleCertSerialNumber),
        c"roleCertSerialNumber",
        ASN1_INTEGER_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        3,
        offset_of!(OSSL_ROLE_SPEC_CERT_ID, roleCertLocator),
        c"roleCertLocator",
        GENERAL_NAME_it,
    ),
]);

item_fns! {
    /// A role specification certificate identifier: [0] the role's name, [1] the issuer, and the optional [2] serial number and [3] locator.
    pub unsafe extern "C" fn OSSL_ROLE_SPEC_CERT_ID_it = sequence::<OSSL_ROLE_SPEC_CERT_ID, 4>(&RSCID_TT, None, c"OSSL_ROLE_SPEC_CERT_ID");
}

new_free! {
    pub unsafe extern "C" fn OSSL_ROLE_SPEC_CERT_ID_new, pub unsafe extern "C" fn OSSL_ROLE_SPEC_CERT_ID_free(OSSL_ROLE_SPEC_CERT_ID) = OSSL_ROLE_SPEC_CERT_ID_it;
}

i2d! {
    /// Encodes an `OSSL_ROLE_SPEC_CERT_ID`.
    pub unsafe extern "C" fn i2d_OSSL_ROLE_SPEC_CERT_ID(OSSL_ROLE_SPEC_CERT_ID) = OSSL_ROLE_SPEC_CERT_ID_it;
}

d2i! {
    /// Decodes an `OSSL_ROLE_SPEC_CERT_ID` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_ROLE_SPEC_CERT_ID(OSSL_ROLE_SPEC_CERT_ID) = OSSL_ROLE_SPEC_CERT_ID_it;
}

static RSCIDS_T: Template = template(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    c"OSSL_ROLE_SPEC_CERT_ID_SYNTAX",
    OSSL_ROLE_SPEC_CERT_ID_it,
);

item_fns! {
    /// Role specification certificate identifiers: SEQUENCE OF them.
    pub unsafe extern "C" fn OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const RSCIDS_T.0, 0, ptr::null(), 0, c"OSSL_ROLE_SPEC_CERT_ID_SYNTAX");
}

new_free! {
    pub unsafe extern "C" fn OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new, pub unsafe extern "C" fn OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free(OSSL_ROLE_SPEC_CERT_ID_SYNTAX) = OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it;
}

i2d! {
    /// Encodes an `OSSL_ROLE_SPEC_CERT_ID_SYNTAX`.
    pub unsafe extern "C" fn i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX(OSSL_ROLE_SPEC_CERT_ID_SYNTAX) = OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it;
}

d2i! {
    /// Decodes an `OSSL_ROLE_SPEC_CERT_ID_SYNTAX` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX(OSSL_ROLE_SPEC_CERT_ID_SYNTAX) = OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it;
}

static UNS_T: Template = template(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    c"OSSL_USER_NOTICE_SYNTAX",
    USERNOTICE_it,
);

item_fns! {
    /// User notices: SEQUENCE OF UserNotice.
    pub unsafe extern "C" fn OSSL_USER_NOTICE_SYNTAX_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const UNS_T.0, 0, ptr::null(), 0, c"OSSL_USER_NOTICE_SYNTAX");
}

new_free! {
    pub unsafe extern "C" fn OSSL_USER_NOTICE_SYNTAX_new, pub unsafe extern "C" fn OSSL_USER_NOTICE_SYNTAX_free(OSSL_USER_NOTICE_SYNTAX) = OSSL_USER_NOTICE_SYNTAX_it;
}

i2d! {
    /// Encodes an `OSSL_USER_NOTICE_SYNTAX`.
    pub unsafe extern "C" fn i2d_OSSL_USER_NOTICE_SYNTAX(OSSL_USER_NOTICE_SYNTAX) = OSSL_USER_NOTICE_SYNTAX_it;
}

d2i! {
    /// Decodes an `OSSL_USER_NOTICE_SYNTAX` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OSSL_USER_NOTICE_SYNTAX(OSSL_USER_NOTICE_SYNTAX) = OSSL_USER_NOTICE_SYNTAX_it;
}

// The markers: a NULL value (`v3_ind_iss.c` and the others).

extern "C" fn null_i2s(_method: *const X509V3_EXT_METHOD, _ext: *mut c_void) -> *mut c_char {
    // SAFETY: a static C string.
    unsafe { crate::string::CRYPTO_strdup(c"NULL".as_ptr(), ptr::null(), 0) }
}

extern "C" fn null_s2i(
    _method: *const X509V3_EXT_METHOD,
    _ctx: *mut X509V3_CTX,
    _value: *const c_char,
) -> *mut c_void {
    // SAFETY: no preconditions.
    unsafe { ASN1_NULL_new() }.cast()
}

extern "C" fn null_i2r(
    _method: *const X509V3_EXT_METHOD,
    _ext: *mut c_void,
    _out: *mut BIO,
    _indent: c_int,
) -> c_int {
    1
}

/// A marker's method: `NULL` as text, and a NULL from any.
const fn marker(nid: c_int) -> Method {
    let mut m = method(nid, 0);
    m.it = Some(ASN1_NULL_it);
    m.i2s = Some(null_i2s);
    m.s2i = Some(null_s2i);
    m.i2r = Some(null_i2r);
    m.r2i = Some(null_s2i);
    Method(m)
}

pub(crate) static INDIRECT_ISSUER: Method = marker(NID_indirect_issuer);
pub(crate) static NO_ASSERTION: Method = marker(NID_no_assertion);
pub(crate) static SOA_IDENTIFIER: Method = marker(NID_soa_identifier);
pub(crate) static GROUP_AC: Method = marker(NID_group_ac);
pub(crate) static NO_REV_AVAIL: Method = marker(NID_no_rev_avail);
pub(crate) static SINGLE_USE: Method = marker(NID_single_use);

/// A method that only prints, and decodes `it`.
const fn printed(
    nid: c_int,
    flags: c_int,
    it: rustyssl_abi::ASN1_ITEM_EXP,
    i2r: rustyssl_abi::X509V3_EXT_I2R,
) -> Method {
    let mut m = method(nid, flags);
    m.it = it;
    m.i2r = i2r;
    Method(m)
}

// Targeting information (`v3_ac_tgt.c`).

/// A name of `GENERAL_NAME_print`'s.
///
/// # Safety
/// `out` is a live BIO; `gn` is NULL or a live name.
unsafe fn name_line(o: Out, indent: c_int, label: &str, gn: *mut GENERAL_NAME) {
    o.line(indent, label);
    // SAFETY: the caller's guarantee.
    unsafe { GENERAL_NAME_print(o.bio(), gn) };
    o.print("\n");
}

/// `i2r_TARGET_CERT`.
///
/// # Safety
/// `tc` is a live target certificate.
unsafe fn target_cert_print(o: Out, tc: &OSSL_TARGET_CERT, indent: c_int) {
    o.line(indent, "");
    if !tc.targetCertificate.is_null() {
        o.print("Target Certificate:\n");
        // SAFETY: the caller's guarantee.
        unsafe { issuer_serial_print(o.bio(), tc.targetCertificate, indent.saturating_add(2)) };
    }
    if !tc.targetName.is_null() {
        // SAFETY: as above.
        unsafe { name_line(o, indent, "Target Name: ", tc.targetName) };
    }
    if !tc.certDigestInfo.is_null() {
        o.line(indent, "Certificate Digest Info:\n");
        let ind = indent.saturating_add(2);
        // SAFETY: as above.
        unsafe { object_digest_info_print(o.bio(), tc.certDigestInfo, ind) };
    }
    o.print("\n");
}

/// `i2r_TARGET`.
///
/// # Safety
/// `t` is a live target.
unsafe fn target_print(o: Out, t: &OSSL_TARGET, indent: c_int) {
    match t.type_ {
        k if k == OSSL_TGT_TARGET_NAME => {
            // SAFETY: the choice's member.
            let gn = unsafe { t.choice.targetName };
            // SAFETY: the caller's guarantee.
            unsafe { name_line(o, indent, "Target Name: ", gn) };
        }
        k if k == OSSL_TGT_TARGET_GROUP => {
            // SAFETY: the choice's member.
            let gn = unsafe { t.choice.targetGroup };
            // SAFETY: the caller's guarantee.
            unsafe { name_line(o, indent, "Target Group: ", gn) };
        }
        k if k == OSSL_TGT_TARGET_CERT => {
            o.line(indent, "Target Cert:\n");
            // SAFETY: the choice's member.
            let tc = unsafe { t.choice.targetCert };
            // SAFETY: the caller's guarantee.
            if let Some(tc) = unsafe { tc.as_ref() } {
                // SAFETY: as above.
                unsafe { target_cert_print(o, tc, indent.saturating_add(2)) };
            }
        }
        _ => {}
    }
}

/// The values of a stack.
///
/// # Safety
/// `sk` is NULL or a live stack of `T`, which outlives the iterator.
unsafe fn values<'a, T: 'a>(sk: *const c_void) -> impl Iterator<Item = &'a mut T> {
    // SAFETY: the caller's guarantee.
    let n = unsafe { OPENSSL_sk_num(sk.cast()) };
    // SAFETY: an index within the stack.
    (0..n).filter_map(move |i| unsafe { item_at::<T>(sk, i) })
}

ffi_callback! {
    /// `i2r_TARGETING_INFORMATION`: each set of targets, and each target.
    ///
    /// # Safety
    /// `ext` is a live `OSSL_TARGETING_INFORMATION`; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn tinfo_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let o = unsafe { Out::new(out) };
        // SAFETY: as above; a stack of stacks.
        let n = unsafe { OPENSSL_sk_num(ext.cast()) };
        for i in 0..n {
            o.line(indent, "Targets:\n");
            // SAFETY: an index within the stack.
            let targets = unsafe { OPENSSL_sk_value(ext.cast(), i) };
            // SAFETY: a stack of targets.
            for t in unsafe { values::<OSSL_TARGET>(targets) } {
                o.line(indent.saturating_add(2), "Target:\n");
                // SAFETY: a target of the stack.
                unsafe { target_print(o, t, indent.saturating_add(4)) };
            }
        }
        1
    }
}

pub(crate) static TARGETING_INFORMATION: Method = printed(
    NID_target_information,
    0,
    Some(OSSL_TARGETING_INFORMATION_it),
    Some(tinfo_i2r),
);

// The authority attribute identifier (`v3_authattid.c`).

ffi_callback! {
    /// `i2r_auth_attr_id`: each issuer and serial number.
    ///
    /// # Safety
    /// `ext` is a live `OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX`; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn aaid_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let o = unsafe { Out::new(out) };
        // SAFETY: as above.
        let n = unsafe { OPENSSL_sk_num(ext.cast()) };
        for i in 0..n {
            if o.line(indent, "Issuer-Serials:\n") <= 0 {
                return 0;
            }
            // SAFETY: an index within the stack.
            let aid = unsafe { OPENSSL_sk_value(ext.cast(), i) };
            // SAFETY: the caller's BIO; an `OSSL_ISSUER_SERIAL` of the stack.
            if unsafe { issuer_serial_print(out, aid.cast(), indent.saturating_add(4)) } <= 0 {
                return 0;
            }
            if o.print("\n") <= 0 {
                return 0;
            }
        }
        1
    }
}

pub(crate) static AUTHORITY_ATTRIBUTE_ID: Method = printed(
    NID_authority_attribute_identifier,
    X509V3_EXT_MULTILINE,
    Some(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it),
    Some(aaid_i2r),
);

// Basic attribute constraints (`v3_battcons.c`).

ffi_callback! {
    /// `i2v_OSSL_BASIC_ATTR_CONSTRAINTS`: `authority:TRUE`/`FALSE`, and the path length if
    /// there's one.
    ///
    /// # Safety
    /// `ext` is a live `OSSL_BASIC_ATTR_CONSTRAINTS`; `extlist` is NULL or a live stack.
    pub(crate) unsafe extern "C" fn battcons_i2v(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, extlist: *mut stack_st_CONF_VALUE) -> *mut stack_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { ext.cast::<OSSL_BASIC_ATTR_CONSTRAINTS>().as_ref() }) else { return extlist };
        let mut list = extlist;
        // SAFETY: static names; the list.
        unsafe { X509V3_add_value_bool(c"authority".as_ptr(), b.authority, &raw mut list) };
        // SAFETY: as above; its path length, or NULL.
        unsafe { X509V3_add_value_int(c"pathlen".as_ptr(), b.pathlen, &raw mut list) };
        list
    }
}

ffi_callback! {
    /// `v2i_OSSL_BASIC_ATTR_CONSTRAINTS`: `authority` (a boolean) and `pathlen` (an integer);
    /// any other name fails with `X509V3_R_INVALID_NAME`.
    ///
    /// # Safety
    /// `values` is NULL or a live stack of `CONF_VALUE`s.
    pub(crate) unsafe extern "C" fn battcons_v2i(_method: *const X509V3_EXT_METHOD, _ctx: *mut X509V3_CTX, values: *mut stack_st_CONF_VALUE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        const F: &str = "v2i_OSSL_BASIC_ATTR_CONSTRAINTS";
        // SAFETY: no preconditions.
        let battcons = unsafe { OSSL_BASIC_ATTR_CONSTRAINTS_new() };
        // SAFETY: new, or NULL.
        let Some(b) = (unsafe { battcons.as_mut() }) else {
            err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
            return ptr::null_mut();
        };
        let fail = || {
            // SAFETY: made above.
            unsafe { OSSL_BASIC_ATTR_CONSTRAINTS_free(battcons) };
            ptr::null_mut()
        };
        // SAFETY: the caller's stack, or NULL.
        let n = unsafe { OPENSSL_sk_num(values.cast()) };
        for i in 0..n {
            // SAFETY: an index within the stack; a `CONF_VALUE`.
            let vp = unsafe { OPENSSL_sk_value(values.cast(), i) }.cast::<CONF_VALUE>();
            // SAFETY: as above.
            let Some(v) = (unsafe { vp.as_ref() }) else { continue };
            // SAFETY: its name, a C string.
            let name = (!v.name.is_null()).then(|| unsafe { CStr::from_ptr(v.name) }.to_bytes());
            match name {
                Some(b"authority") => {
                    // SAFETY: the value; the structure's field.
                    if unsafe { X509V3_get_value_bool(vp, &raw mut b.authority) } == 0 {
                        return fail();
                    }
                }
                Some(b"pathlen") => {
                    // SAFETY: as above.
                    if unsafe { X509V3_get_value_int(vp, &raw mut b.pathlen) } == 0 {
                        return fail();
                    }
                }
                _ => {
                    err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_NAME, F);
                    // SAFETY: as above.
                    unsafe { add_error_name_value(v) };
                    return fail();
                }
            }
        }
        battcons.cast()
    }
}

pub(crate) static BASIC_ATTR_CONSTRAINTS: Method = Method({
    let mut m = method(NID_basic_att_constraints, 0);
    m.it = Some(OSSL_BASIC_ATTR_CONSTRAINTS_it);
    m.i2v = Some(battcons_i2v);
    m.v2i = Some(battcons_v2i);
    m
});

// Issued on behalf of (`v3_iobo.c`).

ffi_callback! {
    /// `i2r_ISSUED_ON_BEHALF_OF`: the name; nothing, and 0, at no indent (OpenSSL's check of
    /// its indent's write).
    ///
    /// # Safety
    /// `ext` is a live name; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn iobo_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let o = unsafe { Out::new(out) };
        if o.line(indent, "") <= 0 {
            return 0;
        }
        // SAFETY: as above.
        if unsafe { GENERAL_NAME_print(out, ext.cast()) } <= 0 {
            return 0;
        }
        c_int::from(o.print("\n") > 0)
    }
}

pub(crate) static ISSUED_ON_BEHALF_OF: Method = printed(
    NID_issued_on_behalf_of,
    0,
    Some(GENERAL_NAME_it),
    Some(iobo_i2r),
);

// Role specification certificate identifiers (`v3_rolespec.c`).

/// `i2r_OSSL_ROLE_SPEC_CERT_ID`: 1, or 0.
///
/// # Safety
/// `r`'s parts are NULL or live.
unsafe fn rscid_print(o: Out, r: &OSSL_ROLE_SPEC_CERT_ID, indent: c_int) -> c_int {
    let out = o.bio();
    if o.line(indent, "Role Name: ") <= 0 {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    if unsafe { GENERAL_NAME_print(out, r.roleName) } <= 0 || o.print("\n") <= 0 {
        return 0;
    }
    if o.line(indent, "Role Certificate Issuer: ") <= 0 {
        return 0;
    }
    // SAFETY: as above.
    if unsafe { GENERAL_NAME_print(out, r.roleCertIssuer) } <= 0 {
        return 0;
    }
    // SAFETY: as above.
    if let Some(serial) = unsafe { r.roleCertSerialNumber.as_ref() } {
        if o.print("\n") <= 0 || o.line(indent, "Role Certificate Serial Number:") <= 0 {
            return 0;
        }
        // SAFETY: as above.
        if unsafe { serial_number_print(out, serial, indent) } != 0 {
            return 0;
        }
    }
    if !r.roleCertLocator.is_null() {
        if o.print("\n") <= 0 || o.line(indent, "Role Certificate Locator:\n") <= 0 {
            return 0;
        }
        // SAFETY: as above.
        if unsafe { OSSL_GENERAL_NAMES_print(out, r.roleCertLocator, indent) } <= 0 {
            return 0;
        }
    }
    o.print("\n")
}

ffi_callback! {
    /// `i2r_OSSL_ROLE_SPEC_CERT_ID_SYNTAX`: each identifier, numbered.
    ///
    /// # Safety
    /// `ext` is a live `OSSL_ROLE_SPEC_CERT_ID_SYNTAX`; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn rscids_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let o = unsafe { Out::new(out) };
        // SAFETY: as above.
        for (i, r) in unsafe { values::<OSSL_ROLE_SPEC_CERT_ID>(ext) }.enumerate() {
            if i > 0 && o.print("\n") <= 0 {
                return 0;
            }
            let n = i.saturating_add(1);
            if o.line(indent, &format!("Role Specification Certificate Identifier #{n}:\n")) <= 0 {
                return 0;
            }
            // SAFETY: an identifier of the stack.
            if unsafe { rscid_print(o, r, indent.saturating_add(4)) } != 1 {
                return 0;
            }
        }
        1
    }
}

pub(crate) static ROLE_SPEC_CERT_ID: Method = printed(
    NID_role_spec_cert_identifier,
    X509V3_EXT_MULTILINE,
    Some(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it),
    Some(rscids_i2r),
);

// Subject directory attributes and associated information (`v3_sda.c`).

ffi_callback! {
    /// `i2r_ATTRIBUTES_SYNTAX`: each attribute's type (by long name, or OID) and its values
    /// (`ossl_print_attribute_value`).
    ///
    /// # Safety
    /// `ext` is NULL or a live `OSSL_ATTRIBUTES_SYNTAX`; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn attrs_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let o = unsafe { Out::new(out) };
        if ext.is_null() {
            return c_int::from(o.print("<No Attributes>\n") > 0);
        }
        // SAFETY: as above.
        let n = unsafe { OPENSSL_sk_num(ext.cast()) };
        if n == 0 {
            return c_int::from(o.print("<Empty Attributes>\n") > 0);
        }
        for i in 0..n {
            // SAFETY: an index within the stack.
            let attr = unsafe { OPENSSL_sk_value(ext.cast(), i) }.cast();
            // SAFETY: an attribute of the stack.
            let obj = unsafe { X509_ATTRIBUTE_get0_object(attr) };
            // SAFETY: its type.
            let nid = unsafe { OBJ_obj2nid(obj) };
            if indent != 0 && o.line(indent, "") <= 0 {
                return 0;
            }
            if nid == NID_undef {
                // SAFETY: the caller's BIO; its type.
                if unsafe { i2a_ASN1_OBJECT(out, obj) } <= 0 || o.print(":\n") <= 0 {
                    return 0;
                }
            } else {
                // SAFETY: a known NID.
                let ln = unsafe { OBJ_nid2ln(nid) };
                // SAFETY: NULL or a static name.
                let ln = (!ln.is_null()).then(|| unsafe { CStr::from_ptr(ln) });
                let ln = ln.map_or(std::borrow::Cow::Borrowed("<NULL>"), CStr::to_string_lossy);
                if o.print(&format!("{ln}:\n")) <= 0 {
                    return 0;
                }
            }
            // SAFETY: as above.
            let count = unsafe { X509_ATTRIBUTE_count(attr) };
            if count == 0 {
                if o.line(indent.saturating_add(4), "<No Values>\n") <= 0 {
                    return 0;
                }
                continue;
            }
            for j in 0..count {
                // SAFETY: as above; an index within its values.
                let av = unsafe { X509_ATTRIBUTE_get0_type(attr, j) };
                // SAFETY: as above; its value.
                if unsafe { print_attribute_value(out, nid, av, indent.saturating_add(4)) } <= 0 {
                    return 0;
                }
                if o.print("\n") <= 0 {
                    return 0;
                }
            }
        }
        1
    }
}

pub(crate) static SUBJECT_DIRECTORY_ATTRIBUTES: Method = printed(
    NID_subject_directory_attributes,
    X509V3_EXT_MULTILINE,
    Some(OSSL_ATTRIBUTES_SYNTAX_it),
    Some(attrs_i2r),
);

pub(crate) static ASSOCIATED_INFORMATION: Method = printed(
    NID_associated_information,
    X509V3_EXT_MULTILINE,
    Some(OSSL_ATTRIBUTES_SYNTAX_it),
    Some(attrs_i2r),
);

// User notices (`v3_usernotice.c`).

/// `print_notice`: the organization and its notice numbers, and the explicit text.
///
/// # Safety
/// `notice`'s parts are NULL or live.
unsafe fn print_notice(o: Out, notice: &USERNOTICE, indent: c_int) -> bool {
    // SAFETY: the caller's guarantee.
    if let Some(r) = unsafe { notice.noticeref.cast_const().as_ref() } {
        let r: &NOTICEREF = r;
        // SAFETY: as above.
        let org = unsafe { precision_text(r.organization) };
        let mut text = b"Organization: ".to_vec();
        text.extend_from_slice(org);
        text.push(b'\n');
        if o.line(indent, "") < 0 || o.write(&text) <= 0 {
            return false;
        }
        // SAFETY: as above.
        let n = unsafe { OPENSSL_sk_num(r.noticenos.cast()) };
        let s = if n > 1 { "s" } else { "" };
        if o.line(indent, &format!("Number{s}: ")) <= 0 {
            return false;
        }
        for i in 0..n {
            if i > 0 && o.print(", ") <= 0 {
                return false;
            }
            // SAFETY: an index within the stack.
            let num = unsafe { OPENSSL_sk_value(r.noticenos.cast(), i) };
            if num.is_null() {
                // OpenSSL prints this, then fails converting the NULL.
                o.print("(null)");
                return false;
            }
            // SAFETY: an INTEGER of the stack.
            let tmp = unsafe { i2s_ASN1_INTEGER(ptr::null_mut(), num.cast()) };
            if tmp.is_null() {
                return false;
            }
            // SAFETY: the C string made above.
            let ok = o.write(unsafe { CStr::from_ptr(tmp) }.to_bytes()) > 0;
            // SAFETY: made above.
            unsafe { mem::release(tmp.cast()) };
            if !ok {
                return false;
            }
        }
        if !notice.exptext.is_null() && o.print("\n") <= 0 {
            return false;
        }
    }
    if notice.exptext.is_null() {
        return true;
    }
    let mut text = b"Explicit Text: ".to_vec();
    // SAFETY: as above.
    text.extend_from_slice(unsafe { precision_text(notice.exptext) });
    o.line(indent, "") >= 0 && o.write(&text) >= 0
}

ffi_callback! {
    /// `i2r_USER_NOTICE_SYNTAX`: `User Notices:`, then each notice.
    ///
    /// # Safety
    /// `ext` is a live `OSSL_USER_NOTICE_SYNTAX`; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn uns_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let o = unsafe { Out::new(out) };
        if o.line(indent, "User Notices:\n") <= 0 {
            return 0;
        }
        // SAFETY: as above.
        for notice in unsafe { values::<USERNOTICE>(ext) } {
            // SAFETY: a notice of the stack.
            if !unsafe { print_notice(o, notice, indent.saturating_add(4)) } {
                return 0;
            }
            if o.print("\n\n") <= 0 {
                return 0;
            }
        }
        1
    }
}

pub(crate) static USER_NOTICE: Method = printed(
    NID_user_notice,
    0,
    Some(OSSL_USER_NOTICE_SYNTAX_it),
    Some(uns_i2r),
);
