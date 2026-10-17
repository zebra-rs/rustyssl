//! Attribute certificates (RFC 5755; `x509_acert.c`, `x509aset.c`, and the attribute
//! certificate parts of `x_all.c`): `X509_ACERT` with its holder (`OSSL_ISSUER_SERIAL`,
//! entity names, `OSSL_OBJECT_DIGEST_INFO`), issuer, validity, attributes, and extensions;
//! their getters and setters, signing, verification, and the DER, BIO, `FILE`, and PEM forms.
//!
//! As OpenSSL's:
//! - The holder's and issuer's names are read only when they're a single directory name.
//! - The validity times must be GeneralizedTimes.
//! - Printing comes with step 5.6 (it needs `X509_signature_print`), but for the issuer and
//!   serial number and the object digest info, which the extensions print; `ASN1:` attribute values
//!   from configuration need `ASN1_generate_nconf` (step 6.1), and abort until then.
//!
//! The types are opaque in OpenSSL's headers, so their layouts are ours (OpenSSL's, in fact).

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::mem::offset_of;
use core::ptr;

use libc::FILE;
use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_ENUMERATED, ASN1_GENERALIZEDTIME, ASN1_INTEGER, ASN1_ITEM, ASN1_OBJECT,
    ASN1_STRING, ASN1_TFLG_EMBED, ASN1_TFLG_IMPLICIT, ASN1_TFLG_OPTIONAL, ASN1_TFLG_SEQUENCE_OF,
    BIO, CONF, CONF_VALUE, ERR_LIB_ASN1, ERR_LIB_X509, ERR_R_ASN1_LIB, ERR_R_CRYPTO_LIB, EVP_MD,
    EVP_MD_CTX, EVP_PKEY, GEN_DIRNAME, GENERAL_NAME, GENERAL_NAMES, OSSL_ISSUER_SERIAL,
    OSSL_OBJECT_DIGEST_INFO, V_ASN1_GENERALIZEDTIME, V_ASN1_OCTET_STRING, X509_ACERT,
    X509_ACERT_INFO, X509_ACERT_ISSUER_V2FORM, X509_ALGOR, X509_ATTRIBUTE, X509_NAME,
    X509_R_INVALID_ATTRIBUTES, X509_VAL, stack_st_X509_ATTRIBUTE, stack_st_X509_EXTENSION,
};

use super::algor::{X509_ALGOR_cmp, X509_ALGOR_copy};
use super::attrib::{
    X509_ATTRIBUTE_it, X509at_add1_attr, X509at_add1_attr_by_NID, X509at_add1_attr_by_OBJ,
    X509at_add1_attr_by_txt, X509at_delete_attr, X509at_get_attr, X509at_get_attr_by_NID,
    X509at_get_attr_by_OBJ, X509at_get_attr_count,
};
use super::cert::X509_VAL_it;
use super::ext::X509_EXTENSION_it;
use super::name::{X509_NAME_dup, X509_NAME_free};
use super::print::{X509_signature_dump, sig_print};
use crate::asn1::hex::i2a_ASN1_STRING;
use crate::asn1::integer::{
    ASN1_ENUMERATED_get, ASN1_ENUMERATED_set, ASN1_INTEGER_get, ASN1_INTEGER_set,
};
use crate::asn1::integer::{ASN1_ENUMERATED_get_int64, i2a_ASN1_INTEGER};
use crate::asn1::sign::{ASN1_item_sign_ctx, ASN1_item_sign_ex, ASN1_item_verify_ex};
use crate::asn1::string::{
    ASN1_BIT_STRING_free, ASN1_STRING_copy, ASN1_STRING_dup, ASN1_STRING_free,
};
use crate::asn1::tpl::io::{
    ASN1_item_d2i_bio, ASN1_item_d2i_fp, ASN1_item_i2d_bio, ASN1_item_i2d_fp,
};
use crate::asn1::tpl::items::{
    ASN1_BIT_STRING_it, ASN1_ENUMERATED_it, ASN1_INTEGER_it, ASN1_OBJECT_it, X509_ALGOR_it, d2i,
    i2d, new_free,
};
use crate::asn1::tpl::statics::{Templates, choice, sequence};
use crate::asn1::tpl::util::ASN1_item_dup;
use crate::asn1::tpl::{item_fns, template_at};
use crate::conf::NCONF_get_section;
use crate::err;
use crate::ffi::ffi_export;
use crate::objects::OBJ_obj2nid;
use crate::objects::i2a_ASN1_OBJECT;
use crate::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value,
};
use crate::x509v3::crld::OSSL_GENERAL_NAMES_print;
use crate::x509v3::genn::{
    GENERAL_NAME_free, GENERAL_NAME_it, GENERAL_NAME_new, GENERAL_NAME_set0_value,
    GENERAL_NAMES_free,
};
use crate::x509v3::registry::{X509V3_add1_i2d, X509V3_get_d2i};
use crate::x509v3::text::Out;
use rustyssl_abi::{ERR_R_PASSED_NULL_PARAMETER, V_ASN1_BIT_STRING};

/// `X509_ACERT_ISSUER_V2` (`x509_acert.h`, not public): the issuer's v2Form.
const ISSUER_V2: c_int = 1;

/// The digested object types (`OSSL_ODI_TYPE_*`, `x509_acert.h`, not public).
const OSSL_ODI_TYPE_PUBLIC_KEY: c_int = 0;
const OSSL_ODI_TYPE_PUBLIC_KEY_CERT: c_int = 1;
const OSSL_ODI_TYPE_OTHER: c_int = 2;

/// `OSSL_OBJECT_DIGEST_INFO`.
#[repr(C)]
pub(crate) struct ObjectDigestInfo {
    digested_object_type: ASN1_ENUMERATED,
    other_object_type_id: *mut ASN1_OBJECT,
    digest_algorithm: X509_ALGOR,
    object_digest: ASN1_BIT_STRING,
}

/// `OSSL_ISSUER_SERIAL`.
#[repr(C)]
pub(crate) struct IssuerSerial {
    issuer: *mut GENERAL_NAMES,
    serial: ASN1_INTEGER,
    issuer_uid: *mut ASN1_BIT_STRING,
}

/// `X509_ACERT_ISSUER_V2FORM`.
#[repr(C)]
pub(crate) struct IssuerV2Form {
    issuer_name: *mut GENERAL_NAMES,
    base_certificate_id: *mut OSSL_ISSUER_SERIAL,
    object_digest_info: *mut OSSL_OBJECT_DIGEST_INFO,
}

/// `X509_ACERT_ISSUER`: a CHOICE of the v1Form (names) and the v2Form.
#[repr(C)]
pub(crate) struct Issuer {
    type_: c_int,
    /// `v1Form` or `v2Form`, as `type_` says.
    u: *mut c_void,
}

/// `X509_HOLDER`.
#[repr(C)]
pub(crate) struct Holder {
    base_certificate_id: *mut OSSL_ISSUER_SERIAL,
    entity_name: *mut GENERAL_NAMES,
    object_digest_info: *mut OSSL_OBJECT_DIGEST_INFO,
}

/// `X509_ACERT_INFO`.
#[repr(C)]
pub(crate) struct AcertInfo {
    version: ASN1_INTEGER,
    holder: Holder,
    issuer: Issuer,
    signature: X509_ALGOR,
    serial_number: ASN1_INTEGER,
    validity_period: X509_VAL,
    attributes: *mut stack_st_X509_ATTRIBUTE,
    issuer_uid: *mut ASN1_BIT_STRING,
    pub(crate) extensions: *mut stack_st_X509_EXTENSION,
}

/// `X509_ACERT`.
#[repr(C)]
pub(crate) struct Acert {
    pub(crate) acinfo: *mut X509_ACERT_INFO,
    sig_alg: X509_ALGOR,
    signature: ASN1_BIT_STRING,
}

static ODI_TT: Templates<4> = Templates([
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(ObjectDigestInfo, digested_object_type),
        c"digestedObjectType",
        ASN1_ENUMERATED_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(ObjectDigestInfo, other_object_type_id),
        c"otherObjectTypeID",
        ASN1_OBJECT_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(ObjectDigestInfo, digest_algorithm),
        c"digestAlgorithm",
        X509_ALGOR_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(ObjectDigestInfo, object_digest),
        c"objectDigest",
        ASN1_BIT_STRING_it,
    ),
]);

/// ObjectDigestInfo.
pub(crate) unsafe extern "C" fn object_digest_info_it() -> *const ASN1_ITEM {
    static ITEM: crate::asn1::tpl::Item =
        sequence::<ObjectDigestInfo, 4>(&ODI_TT, None, c"OSSL_OBJECT_DIGEST_INFO");
    &raw const ITEM.0
}

static ISS_TT: Templates<3> = Templates([
    template_at(
        ASN1_TFLG_SEQUENCE_OF,
        0,
        offset_of!(IssuerSerial, issuer),
        c"issuer",
        GENERAL_NAME_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(IssuerSerial, serial),
        c"serial",
        ASN1_INTEGER_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(IssuerSerial, issuer_uid),
        c"issuerUID",
        ASN1_BIT_STRING_it,
    ),
]);

/// IssuerSerial.
pub(crate) unsafe extern "C" fn issuer_serial_it() -> *const ASN1_ITEM {
    static ITEM: crate::asn1::tpl::Item =
        sequence::<IssuerSerial, 3>(&ISS_TT, None, c"OSSL_ISSUER_SERIAL");
    &raw const ITEM.0
}

static V2_TT: Templates<3> = Templates([
    template_at(
        ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(IssuerV2Form, issuer_name),
        c"issuerName",
        GENERAL_NAME_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(IssuerV2Form, base_certificate_id),
        c"baseCertificateId",
        issuer_serial_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(IssuerV2Form, object_digest_info),
        c"objectDigestInfo",
        object_digest_info_it,
    ),
]);

/// V2Form.
unsafe extern "C" fn issuer_v2form_it() -> *const ASN1_ITEM {
    static ITEM: crate::asn1::tpl::Item =
        sequence::<IssuerV2Form, 3>(&V2_TT, None, c"X509_ACERT_ISSUER_V2FORM");
    &raw const ITEM.0
}

static ISSUER_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_SEQUENCE_OF,
        0,
        offset_of!(Issuer, u),
        c"u.v1Form",
        GENERAL_NAME_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT,
        0,
        offset_of!(Issuer, u),
        c"u.v2Form",
        issuer_v2form_it,
    ),
]);

/// AttCertIssuer: CHOICE { v1Form GeneralNames, v2Form [0] V2Form }.
unsafe extern "C" fn issuer_it() -> *const ASN1_ITEM {
    static ITEM: crate::asn1::tpl::Item = choice::<Issuer, 2>(
        &ISSUER_TT,
        offset_of!(Issuer, type_),
        None,
        c"X509_ACERT_ISSUER",
    );
    &raw const ITEM.0
}

static HOLDER_TT: Templates<3> = Templates([
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(Holder, base_certificate_id),
        c"baseCertificateID",
        issuer_serial_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(Holder, entity_name),
        c"entityName",
        GENERAL_NAME_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        2,
        offset_of!(Holder, object_digest_info),
        c"objectDigestInfo",
        object_digest_info_it,
    ),
]);

/// Holder.
unsafe extern "C" fn holder_it() -> *const ASN1_ITEM {
    static ITEM: crate::asn1::tpl::Item = sequence::<Holder, 3>(&HOLDER_TT, None, c"X509_HOLDER");
    &raw const ITEM.0
}

static INFO_TT: Templates<9> = Templates([
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(AcertInfo, version),
        c"version",
        ASN1_INTEGER_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(AcertInfo, holder),
        c"holder",
        holder_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(AcertInfo, issuer),
        c"issuer",
        issuer_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(AcertInfo, signature),
        c"signature",
        X509_ALGOR_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(AcertInfo, serial_number),
        c"serialNumber",
        ASN1_INTEGER_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(AcertInfo, validity_period),
        c"validityPeriod",
        X509_VAL_it,
    ),
    template_at(
        ASN1_TFLG_SEQUENCE_OF,
        0,
        offset_of!(AcertInfo, attributes),
        c"attributes",
        X509_ATTRIBUTE_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(AcertInfo, issuer_uid),
        c"issuerUID",
        ASN1_BIT_STRING_it,
    ),
    template_at(
        ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(AcertInfo, extensions),
        c"extensions",
        X509_EXTENSION_it,
    ),
]);

item_fns! {
    /// AttributeCertificateInfo.
    pub unsafe extern "C" fn X509_ACERT_INFO_it = sequence::<AcertInfo, 9>(&INFO_TT, None, c"X509_ACERT_INFO");
}

static ACERT_TT: Templates<3> = Templates([
    template_at(
        0,
        0,
        offset_of!(Acert, acinfo),
        c"acinfo",
        X509_ACERT_INFO_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Acert, sig_alg),
        c"sig_alg",
        X509_ALGOR_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Acert, signature),
        c"signature",
        ASN1_BIT_STRING_it,
    ),
]);

item_fns! {
    /// AttributeCertificate: SEQUENCE { acinfo, signatureAlgorithm, signatureValue }.
    pub unsafe extern "C" fn X509_ACERT_it = sequence::<Acert, 3>(&ACERT_TT, None, c"X509_ACERT");
}

new_free! {
    pub unsafe extern "C" fn X509_ACERT_new, pub unsafe extern "C" fn X509_ACERT_free(X509_ACERT) = X509_ACERT_it;
}

i2d! {
    /// Encodes an attribute certificate.
    pub unsafe extern "C" fn i2d_X509_ACERT(X509_ACERT) = X509_ACERT_it;
}

d2i! {
    /// Decodes an attribute certificate (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_X509_ACERT(X509_ACERT) = X509_ACERT_it;
}

new_free! {
    pub unsafe extern "C" fn X509_ACERT_INFO_new, pub unsafe extern "C" fn X509_ACERT_INFO_free(X509_ACERT_INFO) = X509_ACERT_INFO_it;
}

new_free! {
    pub unsafe extern "C" fn OSSL_ISSUER_SERIAL_new, pub unsafe extern "C" fn OSSL_ISSUER_SERIAL_free(OSSL_ISSUER_SERIAL) = issuer_serial_it;
}

new_free! {
    pub unsafe extern "C" fn OSSL_OBJECT_DIGEST_INFO_new, pub unsafe extern "C" fn OSSL_OBJECT_DIGEST_INFO_free(OSSL_OBJECT_DIGEST_INFO) = object_digest_info_it;
}

new_free! {
    pub unsafe extern "C" fn X509_ACERT_ISSUER_V2FORM_new, pub unsafe extern "C" fn X509_ACERT_ISSUER_V2FORM_free(X509_ACERT_ISSUER_V2FORM) = issuer_v2form_it;
}

ffi_export! {
    /// A copy of the attribute certificate (through its encoding), or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live attribute certificate.
    pub unsafe extern "C" fn X509_ACERT_dup(a: *const X509_ACERT) -> *mut X509_ACERT
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_ACERT_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_dup(it, a.cast_mut().cast()) }.cast()
    }
}

/// The attribute certificate's parts, or `None`.
///
/// # Safety
/// `x` is NULL or a live attribute certificate.
unsafe fn parts<'a>(x: *const X509_ACERT) -> Option<(&'a mut Acert, &'a mut AcertInfo)> {
    // SAFETY: the caller's guarantee; an `X509_ACERT` is an `Acert`.
    let a = unsafe { x.cast::<Acert>().cast_mut().as_mut() }?;
    // SAFETY: its information, an `AcertInfo`, or NULL.
    let i = unsafe { a.acinfo.cast::<AcertInfo>().as_mut() }?;
    Some((a, i))
}

/// The information of an attribute certificate, or `None`.
///
/// # Safety
/// As for [`parts`].
unsafe fn info<'a>(x: *const X509_ACERT) -> Option<&'a mut AcertInfo> {
    // SAFETY: the caller's guarantee.
    unsafe { parts(x) }.map(|(_, i)| i)
}

/// `get_dirName`: the names' directory name if they're exactly one, or NULL.
fn dir_name(names: *const GENERAL_NAMES) -> *const X509_NAME {
    // SAFETY: a stack of names, or NULL.
    if unsafe { OPENSSL_sk_num(names.cast()) } != 1 {
        return ptr::null();
    }
    // SAFETY: as above, with one.
    let g = unsafe { OPENSSL_sk_value(names.cast(), 0) }.cast::<GENERAL_NAME>();
    // SAFETY: a name of them.
    match unsafe { g.as_ref() } {
        // SAFETY: a directory name's member.
        Some(g) if g.type_ == GEN_DIRNAME => unsafe { g.d.directoryName },
        _ => ptr::null(),
    }
}

ffi_export! {
    /// The digest information's type, AlgorithmIdentifier, and digest (each output if not
    /// NULL; it keeps them).
    ///
    /// # Safety
    /// `o` is NULL or live digest information; the outputs are NULL or writable.
    pub unsafe extern "C" fn OSSL_OBJECT_DIGEST_INFO_get0_digest(o: *const OSSL_OBJECT_DIGEST_INFO, digested_object_type: *mut c_int, digest_algorithm: *mut *const X509_ALGOR, digest: *mut *const ASN1_BIT_STRING)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee; an `OSSL_OBJECT_DIGEST_INFO` is an `ObjectDigestInfo`.
        let Some(d) = (unsafe { o.cast::<ObjectDigestInfo>().as_ref() }) else { return };
        if !digested_object_type.is_null() {
            // SAFETY: its type.
            let t = unsafe { ASN1_ENUMERATED_get(&raw const d.digested_object_type) };
            // SAFETY: the caller's guarantee.
            unsafe { digested_object_type.write(c_int::try_from(t).unwrap_or(-1)) };
        }
        if !digest_algorithm.is_null() {
            // SAFETY: as above.
            unsafe { digest_algorithm.write(&raw const d.digest_algorithm) };
        }
        if !digest.is_null() {
            // SAFETY: as above.
            unsafe { digest.write(&raw const d.object_digest) };
        }
    }
}

ffi_export! {
    /// Sets the digest information's type, and copies of the AlgorithmIdentifier and digest:
    /// 1, or 0.
    ///
    /// # Safety
    /// `o` is NULL or live digest information; `digest_algorithm` and `digest` are live.
    pub unsafe extern "C" fn OSSL_OBJECT_DIGEST_INFO_set1_digest(o: *mut OSSL_OBJECT_DIGEST_INFO, digested_object_type: c_int, digest_algorithm: *mut X509_ALGOR, digest: *mut ASN1_BIT_STRING) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { o.cast::<ObjectDigestInfo>().as_mut() }) else { return 0 };
        // SAFETY: its type.
        if unsafe { ASN1_ENUMERATED_set(&raw mut d.digested_object_type, c_long::from(digested_object_type)) } <= 0 {
            return 0;
        }
        // SAFETY: its AlgorithmIdentifier; the caller's.
        if unsafe { X509_ALGOR_copy(&raw mut d.digest_algorithm, digest_algorithm) } <= 0 {
            return 0;
        }
        // SAFETY: its digest; the caller's.
        c_int::from(unsafe { ASN1_STRING_copy((&raw mut d.object_digest).cast(), digest.cast()) } > 0)
    }
}

/// The issuer serial behind a pointer, or `None`.
///
/// # Safety
/// `x` is NULL or a live issuer serial.
unsafe fn iss<'a>(x: *const OSSL_ISSUER_SERIAL) -> Option<&'a mut IssuerSerial> {
    // SAFETY: the caller's guarantee; an `OSSL_ISSUER_SERIAL` is an `IssuerSerial`.
    unsafe { x.cast::<IssuerSerial>().cast_mut().as_mut() }
}

ffi_export! {
    /// The issuer's directory name (if it's exactly one), or NULL.
    ///
    /// # Safety
    /// `isss` is NULL or a live issuer serial.
    pub unsafe extern "C" fn OSSL_ISSUER_SERIAL_get0_issuer(isss: *const OSSL_ISSUER_SERIAL) -> *const X509_NAME
    where failure = ptr::null(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { iss(isss) }.map_or(ptr::null(), |s| dir_name(s.issuer))
    }
}

ffi_export! {
    /// The serial number (it keeps it).
    ///
    /// # Safety
    /// `isss` is NULL or a live issuer serial.
    pub unsafe extern "C" fn OSSL_ISSUER_SERIAL_get0_serial(isss: *const OSSL_ISSUER_SERIAL) -> *const ASN1_INTEGER
    where failure = ptr::null(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { iss(isss) }.map_or(ptr::null(), |s| &raw const s.serial)
    }
}

ffi_export! {
    /// The issuer's unique ID, or NULL.
    ///
    /// # Safety
    /// `isss` is NULL or a live issuer serial.
    pub unsafe extern "C" fn OSSL_ISSUER_SERIAL_get0_issuerUID(isss: *const OSSL_ISSUER_SERIAL) -> *const ASN1_BIT_STRING
    where failure = ptr::null(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { iss(isss) }.map_or(ptr::null(), |s| s.issuer_uid.cast_const())
    }
}

/// `replace_dirName`: the names replaced by one directory name, a copy of `dir`.
///
/// # Safety
/// `names` holds NULL or live names; `dir` is a live name.
unsafe fn replace_dir_name(names: &mut *mut GENERAL_NAMES, dir: *const X509_NAME) -> c_int {
    const F: &str = "replace_dirName";
    // SAFETY: the caller's guarantee.
    let copy = unsafe { X509_NAME_dup(dir) };
    if copy.is_null() {
        err::raise(ERR_LIB_X509, ERR_R_ASN1_LIB, F);
        return 0;
    }
    // SAFETY: no preconditions.
    let new_names = unsafe { OPENSSL_sk_new_null() };
    let g = if new_names.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: no preconditions.
        unsafe { GENERAL_NAME_new() }
    };
    let fail = |reason| {
        err::raise(ERR_LIB_X509, reason, F);
        // SAFETY: made above, or NULL.
        unsafe { GENERAL_NAME_free(g) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_free(new_names) };
        // SAFETY: as above.
        unsafe { X509_NAME_free(copy) };
        0
    };
    if new_names.is_null() || g.is_null() {
        return fail(ERR_R_ASN1_LIB);
    }
    // SAFETY: the new list; the name, which it takes.
    if unsafe { OPENSSL_sk_push(new_names, g.cast()) } <= 0 {
        return fail(ERR_R_CRYPTO_LIB);
    }
    // SAFETY: the name; the copy, which it takes.
    unsafe { GENERAL_NAME_set0_value(g, GEN_DIRNAME, copy.cast()) };
    // SAFETY: the caller's names, or NULL.
    unsafe { GENERAL_NAMES_free(*names) };
    *names = new_names.cast();
    1
}

ffi_export! {
    /// Sets the issuer to a copy of `issuer` (as its only name): 1, or 0.
    ///
    /// # Safety
    /// `isss` is NULL or a live issuer serial; `issuer` is a live name.
    pub unsafe extern "C" fn OSSL_ISSUER_SERIAL_set1_issuer(isss: *mut OSSL_ISSUER_SERIAL, issuer: *const X509_NAME) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { iss(isss) }) else { return 0 };
        if issuer.is_null() {
            return 0;
        }
        // SAFETY: its names; the caller's name.
        unsafe { replace_dir_name(&mut s.issuer, issuer) }
    }
}

ffi_export! {
    /// Sets the serial number to a copy of `serial`: 1, or 0.
    ///
    /// # Safety
    /// `isss` is NULL or a live issuer serial; `serial` is a live INTEGER.
    pub unsafe extern "C" fn OSSL_ISSUER_SERIAL_set1_serial(isss: *mut OSSL_ISSUER_SERIAL, serial: *const ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { iss(isss) }) else { return 0 };
        // SAFETY: its serial number; the caller's.
        unsafe { ASN1_STRING_copy((&raw mut s.serial).cast(), serial.cast()) }
    }
}

ffi_export! {
    /// Sets the issuer's unique ID to a copy of `uid`: 1, or 0.
    ///
    /// # Safety
    /// `isss` is NULL or a live issuer serial; `uid` is NULL or a live BIT STRING.
    pub unsafe extern "C" fn OSSL_ISSUER_SERIAL_set1_issuerUID(isss: *mut OSSL_ISSUER_SERIAL, uid: *const ASN1_BIT_STRING) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { iss(isss) }) else { return 0 };
        // SAFETY: its own, or NULL.
        unsafe { ASN1_BIT_STRING_free(s.issuer_uid) };
        // SAFETY: the caller's, or NULL.
        s.issuer_uid = unsafe { ASN1_STRING_dup(uid.cast()) }.cast();
        if s.issuer_uid.is_null() {
            err::raise(ERR_LIB_X509, ERR_R_ASN1_LIB, "OSSL_ISSUER_SERIAL_set1_issuerUID");
            return 0;
        }
        1
    }
}

ffi_export! {
    /// The version (`X509_ACERT_VERSION_2` for RFC 5755's).
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate.
    pub unsafe extern "C" fn X509_ACERT_get_version(x: *const X509_ACERT) -> c_long
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { info(x) }) else { return 0 };
        // SAFETY: its version.
        unsafe { ASN1_INTEGER_get(&raw const i.version) }
    }
}

ffi_export! {
    /// Sets the version: 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate.
    pub unsafe extern "C" fn X509_ACERT_set_version(x: *mut X509_ACERT, version: c_long) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { info(x) }) else { return 0 };
        // SAFETY: its version.
        unsafe { ASN1_INTEGER_set(&raw mut i.version, version) }
    }
}

ffi_export! {
    /// The signature and its AlgorithmIdentifier (it keeps them), into `*psig` and `*palg`
    /// where given.
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate; the outputs are NULL or writable.
    pub unsafe extern "C" fn X509_ACERT_get0_signature(x: *const X509_ACERT, psig: *mut *const ASN1_BIT_STRING, palg: *mut *const X509_ALGOR)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { x.cast::<Acert>().as_ref() }) else { return };
        if !psig.is_null() {
            // SAFETY: as above.
            unsafe { psig.write(&raw const a.signature) };
        }
        if !palg.is_null() {
            // SAFETY: as above.
            unsafe { palg.write(&raw const a.sig_alg) };
        }
    }
}

ffi_export! {
    /// The NID of the signature algorithm.
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate.
    pub unsafe extern "C" fn X509_ACERT_get_signature_nid(x: *const X509_ACERT) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { x.cast::<Acert>().as_ref() }) else { return 0 };
        // SAFETY: its object.
        unsafe { OBJ_obj2nid(a.sig_alg.algorithm) }
    }
}

macro_rules! acert_getters {
    ($(
        $(#[$attr:meta])*
        pub unsafe extern "C" fn $name:ident(x: *const X509_ACERT) -> $ret:ty = |$i:ident| $body:expr;
    )*) => {$(
        ffi_export! {
            $(#[$attr])*
            ///
            /// # Safety
            /// `x` is NULL or a live attribute certificate.
            pub unsafe extern "C" fn $name(x: *const X509_ACERT) -> $ret
            where failure = ptr::null(), library = ERR_LIB_X509
            {
                // SAFETY: the caller's guarantee.
                let Some($i) = (unsafe { info(x) }) else { return ptr::null() };
                $body
            }
        }
    )*};
}

acert_getters! {
    /// The holder's entity names, or NULL.
    pub unsafe extern "C" fn X509_ACERT_get0_holder_entityName(x: *const X509_ACERT) -> *const GENERAL_NAMES = |i| i.holder.entity_name;
    /// The holder's base certificate ID, or NULL.
    pub unsafe extern "C" fn X509_ACERT_get0_holder_baseCertId(x: *const X509_ACERT) -> *const OSSL_ISSUER_SERIAL = |i| i.holder.base_certificate_id;
    /// The holder's object digest information, or NULL.
    pub unsafe extern "C" fn X509_ACERT_get0_holder_digest(x: *const X509_ACERT) -> *const OSSL_OBJECT_DIGEST_INFO = |i| i.holder.object_digest_info;
    /// The issuer's directory name (a v2Form with exactly one), or NULL.
    pub unsafe extern "C" fn X509_ACERT_get0_issuerName(x: *const X509_ACERT) -> *const X509_NAME = |i| {
        if i.issuer.type_ != ISSUER_V2 {
            return ptr::null();
        }
        // SAFETY: its v2Form, or NULL.
        match unsafe { i.issuer.u.cast::<IssuerV2Form>().as_ref() } {
            Some(v2) => dir_name(v2.issuer_name),
            None => ptr::null(),
        }
    };
    /// The issuer's unique ID, or NULL.
    pub unsafe extern "C" fn X509_ACERT_get0_issuerUID(x: *const X509_ACERT) -> *const ASN1_BIT_STRING = |i| i.issuer_uid;
    /// The TBS signature's AlgorithmIdentifier.
    pub unsafe extern "C" fn X509_ACERT_get0_info_sigalg(x: *const X509_ACERT) -> *const X509_ALGOR = |i| &raw const i.signature;
    /// The serial number.
    pub unsafe extern "C" fn X509_ACERT_get0_serialNumber(x: *const X509_ACERT) -> *const ASN1_INTEGER = |i| &raw const i.serial_number;
    /// The start of the validity.
    pub unsafe extern "C" fn X509_ACERT_get0_notBefore(x: *const X509_ACERT) -> *const ASN1_GENERALIZEDTIME = |i| i.validity_period.notBefore;
    /// The end of the validity.
    pub unsafe extern "C" fn X509_ACERT_get0_notAfter(x: *const X509_ACERT) -> *const ASN1_GENERALIZEDTIME = |i| i.validity_period.notAfter;
    /// The extensions, or NULL.
    pub unsafe extern "C" fn X509_ACERT_get0_extensions(x: *const X509_ACERT) -> *const stack_st_X509_EXTENSION = |i| i.extensions;
}

ffi_export! {
    /// Replaces the holder's entity names with `names`, which it takes.
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate; `names` is NULL or live names.
    pub unsafe extern "C" fn X509_ACERT_set0_holder_entityName(x: *mut X509_ACERT, names: *mut GENERAL_NAMES)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { info(x) }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { GENERAL_NAMES_free(i.holder.entity_name) };
        i.holder.entity_name = names;
    }
}

ffi_export! {
    /// Replaces the holder's base certificate ID with `isss`, which it takes.
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate; `isss` is NULL or a live issuer serial.
    pub unsafe extern "C" fn X509_ACERT_set0_holder_baseCertId(x: *mut X509_ACERT, isss: *mut OSSL_ISSUER_SERIAL)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { info(x) }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { OSSL_ISSUER_SERIAL_free(i.holder.base_certificate_id) };
        i.holder.base_certificate_id = isss;
    }
}

ffi_export! {
    /// Replaces the holder's object digest information with `dinfo`, which it takes.
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate; `dinfo` is NULL or live digest information.
    pub unsafe extern "C" fn X509_ACERT_set0_holder_digest(x: *mut X509_ACERT, dinfo: *mut OSSL_OBJECT_DIGEST_INFO)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { info(x) }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { OSSL_OBJECT_DIGEST_INFO_free(i.holder.object_digest_info) };
        i.holder.object_digest_info = dinfo;
    }
}

ffi_export! {
    /// Sets the issuer to a v2Form with a copy of `name` as its only name: 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate; `name` is a live name.
    pub unsafe extern "C" fn X509_ACERT_set1_issuerName(x: *mut X509_ACERT, name: *const X509_NAME) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { info(x) }) else { return 0 };
        if name.is_null() {
            return 0;
        }
        if i.issuer.type_ != ISSUER_V2 && !i.issuer.u.is_null() {
            // A v1Form (OpenSSL would take its names as a v2Form): replaced.
            // SAFETY: the v1Form's names.
            unsafe { GENERAL_NAMES_free(i.issuer.u.cast()) };
            i.issuer.u = ptr::null_mut();
        }
        if i.issuer.u.is_null() {
            // SAFETY: no preconditions.
            let v2 = unsafe { X509_ACERT_ISSUER_V2FORM_new() };
            if v2.is_null() {
                err::raise(ERR_LIB_X509, ERR_R_ASN1_LIB, "X509_ACERT_set1_issuerName");
                return 0;
            }
            i.issuer.u = v2.cast();
            i.issuer.type_ = ISSUER_V2;
        }
        // SAFETY: the v2Form.
        let v2 = unsafe { &mut *i.issuer.u.cast::<IssuerV2Form>() };
        // SAFETY: its names; the caller's name.
        unsafe { replace_dir_name(&mut v2.issuer_name, name) }
    }
}

ffi_export! {
    /// Sets the serial number to a copy of `serial`: 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate; `serial` is a live INTEGER.
    pub unsafe extern "C" fn X509_ACERT_set1_serialNumber(x: *mut X509_ACERT, serial: *const ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { info(x) }) else { return 0 };
        // SAFETY: its serial number; the caller's.
        unsafe { ASN1_STRING_copy((&raw mut i.serial_number).cast(), serial.cast()) }
    }
}

/// `replace_gentime`: a copy of the GeneralizedTime `src` in `*dest`: 1, or 0.
///
/// # Safety
/// `dest` holds NULL or a live string; `src` is NULL or a live time.
unsafe fn replace_gentime(dest: &mut *mut ASN1_STRING, src: *const ASN1_GENERALIZEDTIME) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { src.as_ref() }) else {
        return 0;
    };
    if s.type_ != V_ASN1_GENERALIZEDTIME {
        return 0;
    }
    if (*dest).cast_const() == src.cast() {
        return 1;
    }
    // SAFETY: as above.
    let copy = unsafe { ASN1_STRING_dup(src.cast()) };
    if copy.is_null() {
        err::raise(ERR_LIB_X509, ERR_R_ASN1_LIB, "replace_gentime");
        return 0;
    }
    // SAFETY: the caller's string, or NULL.
    unsafe { ASN1_STRING_free(*dest) };
    *dest = copy;
    1
}

ffi_export! {
    /// Sets the start of the validity to a copy of `time` (a GeneralizedTime): 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate; `time` is NULL or a live time.
    pub unsafe extern "C" fn X509_ACERT_set1_notBefore(x: *mut X509_ACERT, time: *const ASN1_GENERALIZEDTIME) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { info(x) }) else { return 0 };
        // SAFETY: its slot; the caller's time.
        unsafe { replace_gentime(&mut i.validity_period.notBefore, time) }
    }
}

ffi_export! {
    /// Sets the end of the validity to a copy of `time` (a GeneralizedTime): 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate; `time` is NULL or a live time.
    pub unsafe extern "C" fn X509_ACERT_set1_notAfter(x: *mut X509_ACERT, time: *const ASN1_GENERALIZEDTIME) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { info(x) }) else { return 0 };
        // SAFETY: its slot; the caller's time.
        unsafe { replace_gentime(&mut i.validity_period.notAfter, time) }
    }
}

// Attributes.

ffi_export! {
    /// The number of attributes.
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate.
    pub unsafe extern "C" fn X509_ACERT_get_attr_count(x: *const X509_ACERT) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let a = unsafe { info(x) }.map_or(ptr::null_mut(), |i| i.attributes);
        // SAFETY: the attributes, or NULL.
        unsafe { X509at_get_attr_count(a) }
    }
}

ffi_export! {
    /// The index of the next attribute of `nid` after `lastpos`, or -1 (-2 for an unknown NID).
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate.
    pub unsafe extern "C" fn X509_ACERT_get_attr_by_NID(x: *const X509_ACERT, nid: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let a = unsafe { info(x) }.map_or(ptr::null_mut(), |i| i.attributes);
        // SAFETY: the attributes, or NULL.
        unsafe { X509at_get_attr_by_NID(a, nid, lastpos) }
    }
}

ffi_export! {
    /// The index of the next attribute of `obj` after `lastpos`, or -1.
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate; `obj` is NULL or a live object.
    pub unsafe extern "C" fn X509_ACERT_get_attr_by_OBJ(x: *const X509_ACERT, obj: *const ASN1_OBJECT, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let a = unsafe { info(x) }.map_or(ptr::null_mut(), |i| i.attributes);
        // SAFETY: the attributes, or NULL; the caller's object.
        unsafe { X509at_get_attr_by_OBJ(a, obj, lastpos) }
    }
}

ffi_export! {
    /// The attribute at `loc` (it keeps it), or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate.
    pub unsafe extern "C" fn X509_ACERT_get_attr(x: *const X509_ACERT, loc: c_int) -> *mut X509_ATTRIBUTE
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let a = unsafe { info(x) }.map_or(ptr::null_mut(), |i| i.attributes);
        // SAFETY: the attributes, or NULL.
        unsafe { X509at_get_attr(a, loc) }
    }
}

ffi_export! {
    /// Takes the attribute at `loc` out (the caller frees it), or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate.
    pub unsafe extern "C" fn X509_ACERT_delete_attr(x: *mut X509_ACERT, loc: c_int) -> *mut X509_ATTRIBUTE
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let a = unsafe { info(x) }.map_or(ptr::null_mut(), |i| i.attributes);
        // SAFETY: the attributes, or NULL.
        unsafe { X509at_delete_attr(a, loc) }
    }
}

ffi_export! {
    /// Adds a copy of the attribute: 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate; `attr` is NULL or a live attribute.
    pub unsafe extern "C" fn X509_ACERT_add1_attr(x: *mut X509_ACERT, attr: *mut X509_ATTRIBUTE) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { info(x) }) else { return 0 };
        // SAFETY: its list; the caller's attribute.
        c_int::from(!unsafe { X509at_add1_attr(&raw mut i.attributes, attr) }.is_null())
    }
}

ffi_export! {
    /// Adds an attribute of `obj` with one value of `type_` from the octets: 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate; `obj` is a live object; `bytes` as for
    /// `X509_ATTRIBUTE_set1_data`.
    pub unsafe extern "C" fn X509_ACERT_add1_attr_by_OBJ(x: *mut X509_ACERT, obj: *const ASN1_OBJECT, type_: c_int, bytes: *const c_void, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { info(x) }) else { return 0 };
        // SAFETY: its list; the caller's arguments.
        c_int::from(!unsafe { X509at_add1_attr_by_OBJ(&raw mut i.attributes, obj, type_, bytes.cast(), len) }.is_null())
    }
}

ffi_export! {
    /// Adds an attribute of `nid` with one value of `type_` from the octets: 1, or 0.
    ///
    /// # Safety
    /// As for [`X509_ACERT_add1_attr_by_OBJ`].
    pub unsafe extern "C" fn X509_ACERT_add1_attr_by_NID(x: *mut X509_ACERT, nid: c_int, type_: c_int, bytes: *const c_void, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { info(x) }) else { return 0 };
        // SAFETY: its list; the caller's arguments.
        c_int::from(!unsafe { X509at_add1_attr_by_NID(&raw mut i.attributes, nid, type_, bytes.cast(), len) }.is_null())
    }
}

ffi_export! {
    /// Adds an attribute named `attrname` with one value of `type_` from the octets: 1, or 0.
    ///
    /// # Safety
    /// As for [`X509_ACERT_add1_attr_by_OBJ`], with `attrname` a C string.
    pub unsafe extern "C" fn X509_ACERT_add1_attr_by_txt(x: *mut X509_ACERT, attrname: *const c_char, type_: c_int, bytes: *const c_uchar, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { info(x) }) else { return 0 };
        // SAFETY: its list; the caller's arguments.
        c_int::from(!unsafe { X509at_add1_attr_by_txt(&raw mut i.attributes, attrname, type_, bytes, len) }.is_null())
    }
}

/// A C string's bytes, or `<NULL>`.
///
/// # Safety
/// `s` is NULL or a C string.
unsafe fn text_or_null<'a>(s: *const c_char) -> &'a [u8] {
    if s.is_null() {
        return b"<NULL>";
    }
    // SAFETY: the caller's guarantee.
    unsafe { CStr::from_ptr(s) }.to_bytes()
}

/// `check_asn1_attribute`: the value after `ASN1:` and spaces, or `None`.
fn asn1_value(v: &[u8]) -> Option<&[u8]> {
    let rest = v.strip_prefix(b"ASN1:")?;
    let n = rest
        .iter()
        .take_while(|c| matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
        .count();
    rest.get(n..)
}

ffi_export! {
    /// Adds an attribute for each value of the configuration's `section`, named by its name:
    /// the value as an OCTET STRING (`ASN1:` values need step 6.1). 1, or 0.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `section` is NULL or a C string; `acert` is NULL
    /// or a live attribute certificate.
    pub unsafe extern "C" fn X509_ACERT_add_attr_nconf(conf: *mut CONF, section: *const c_char, acert: *mut X509_ACERT) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let sk = unsafe { NCONF_get_section(conf, section) };
        if sk.is_null() {
            return 0;
        }
        // SAFETY: the section.
        for k in 0..unsafe { OPENSSL_sk_num(sk.cast()) } {
            // SAFETY: an index within it.
            let v = unsafe { OPENSSL_sk_value(sk.cast(), k) }.cast::<CONF_VALUE>();
            // SAFETY: a value of it.
            let Some(v) = (unsafe { v.as_ref() }) else { return 0 };
            if v.value.is_null() {
                // SAFETY: C strings, or NULL.
                let name = unsafe { text_or_null(v.name) };
                // SAFETY: as above.
                let sec = unsafe { text_or_null(section) };
                let mut d = b"name=".to_vec();
                d.extend_from_slice(name);
                d.extend_from_slice(b",section=");
                d.extend_from_slice(sec);
                err::raise_with_bytes(ERR_LIB_X509, X509_R_INVALID_ATTRIBUTES, "X509_ACERT_add_attr_nconf", &d);
                return 0;
            }
            // SAFETY: a C string.
            let value = unsafe { CStr::from_ptr(v.value) }.to_bytes();
            if asn1_value(value).is_some() {
                crate::stub::unimplemented("an ASN1: attribute value (ASN1_generate_nconf, step 6.1)");
            }
            let len = c_int::try_from(value.len()).unwrap_or(c_int::MAX);
            // SAFETY: the caller's certificate; the value's name and octets.
            if unsafe { X509_ACERT_add1_attr_by_txt(acert, v.name, V_ASN1_OCTET_STRING, value.as_ptr(), len) } == 0 {
                return 0;
            }
        }
        1
    }
}

// Extensions.

ffi_export! {
    /// The extension of `nid`, decoded (see `X509V3_get_d2i`), or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate; `crit` and `idx` are NULL or writable.
    pub unsafe extern "C" fn X509_ACERT_get_ext_d2i(x: *const X509_ACERT, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let e = unsafe { info(x) }.map_or(ptr::null_mut(), |i| i.extensions);
        // SAFETY: the extensions, or NULL; the caller's slots.
        unsafe { X509V3_get_d2i(e, nid, crit, idx) }
    }
}

ffi_export! {
    /// Adds `value` encoded as an extension of `nid` (see `X509V3_add1_i2d`).
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate; `value` is a value of the NID's method.
    pub unsafe extern "C" fn X509_ACERT_add1_ext_i2d(x: *mut X509_ACERT, nid: c_int, value: *mut c_void, crit: c_int, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { info(x) }) else { return 0 };
        // SAFETY: its list; the caller's value.
        unsafe { X509V3_add1_i2d(&raw mut i.extensions, nid, value, crit, flags) }
    }
}

// Signing and I/O (`x_all.c`).

ffi_export! {
    /// Checks the signature with `r` (if both AlgorithmIdentifiers agree): 1, 0, or -1.
    ///
    /// # Safety
    /// `a` is NULL or a live attribute certificate; `r` is NULL or a live key.
    pub unsafe extern "C" fn X509_ACERT_verify(a: *mut X509_ACERT, r: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some((c, i)) = (unsafe { parts(a) }) else { return 0 };
        // SAFETY: its AlgorithmIdentifiers.
        if unsafe { X509_ALGOR_cmp(&raw const c.sig_alg, &raw const i.signature) } != 0 {
            return 0;
        }
        // SAFETY: no preconditions.
        let it = unsafe { X509_ACERT_INFO_it() };
        // SAFETY: the certificate's information, algorithm, and signature; the caller's key.
        unsafe { ASN1_item_verify_ex(it, &raw const c.sig_alg, &raw const c.signature, c.acinfo.cast(), ptr::null(), r, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Signs with `pkey` and `md`: the signature's length, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate; `pkey` is a live key; `md` is NULL or a
    /// digest.
    pub unsafe extern "C" fn X509_ACERT_sign(x: *mut X509_ACERT, pkey: *mut EVP_PKEY, md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some((c, i)) = (unsafe { parts(x) }) else { return 0 };
        // SAFETY: no preconditions.
        let it = unsafe { X509_ACERT_INFO_it() };
        // SAFETY: the certificate's fields; the caller's key and digest.
        unsafe {
            ASN1_item_sign_ex(it, &raw mut c.sig_alg, &raw mut i.signature, &raw mut c.signature, c.acinfo.cast(), ptr::null(), pkey, md, ptr::null_mut(), ptr::null())
        }
    }
}

ffi_export! {
    /// Signs through `ctx`, initialised for signing: the signature's length, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live attribute certificate; `ctx` is a live digest context.
    pub unsafe extern "C" fn X509_ACERT_sign_ctx(x: *mut X509_ACERT, ctx: *mut EVP_MD_CTX) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some((c, i)) = (unsafe { parts(x) }) else { return 0 };
        // SAFETY: no preconditions.
        let it = unsafe { X509_ACERT_INFO_it() };
        // SAFETY: the certificate's fields; the caller's context.
        unsafe { ASN1_item_sign_ctx(it, &raw mut c.sig_alg, &raw mut i.signature, &raw mut c.signature, c.acinfo.cast(), ctx) }
    }
}

ffi_export! {
    /// Decodes an attribute certificate from a `FILE`.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `acert` is NULL or holds NULL or a live one.
    pub unsafe extern "C" fn d2i_X509_ACERT_fp(fp: *mut FILE, acert: *mut *mut X509_ACERT) -> *mut X509_ACERT
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_ACERT_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_d2i_fp(it, fp, acert.cast()) }.cast()
    }
}

ffi_export! {
    /// Encodes an attribute certificate to a `FILE`: 1, or 0.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `acert` is a live one.
    pub unsafe extern "C" fn i2d_X509_ACERT_fp(fp: *mut FILE, acert: *const X509_ACERT) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_ACERT_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_fp(it, fp, acert.cast()) }
    }
}

ffi_export! {
    /// Decodes an attribute certificate from a BIO.
    ///
    /// # Safety
    /// `bp` is a live BIO; `acert` is NULL or holds NULL or a live one.
    pub unsafe extern "C" fn d2i_X509_ACERT_bio(bp: *mut BIO, acert: *mut *mut X509_ACERT) -> *mut X509_ACERT
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_ACERT_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_d2i_bio(it, bp, acert.cast()) }.cast()
    }
}

ffi_export! {
    /// Encodes an attribute certificate to a BIO: 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `acert` is a live one.
    pub unsafe extern "C" fn i2d_X509_ACERT_bio(bp: *mut BIO, acert: *const X509_ACERT) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_ACERT_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_bio(it, bp, acert.cast()) }
    }
}

// Printing (`v3_ac_tgt.c`'s, shared with the attribute certificate extensions).

/// `i2r_ISSUER_SERIAL`: the issuer's names, serial number, and unique ID, each `indent` in: 1,
/// or 0.
///
/// # Safety
/// `out` is a live BIO; `iss` is NULL or a live `OSSL_ISSUER_SERIAL`.
pub(crate) unsafe fn issuer_serial_print(
    out: *mut BIO,
    iss: *const OSSL_ISSUER_SERIAL,
    indent: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(iss) = (unsafe { iss.cast::<IssuerSerial>().as_ref() }) else {
        return 0;
    };
    // SAFETY: as above.
    let o = unsafe { Out::new(out) };
    if iss.issuer.is_null() {
        o.line(indent, "Issuer Names: <none>\n");
    } else {
        o.line(indent, "Issuer Names:\n");
        // SAFETY: the caller's BIO; its names.
        unsafe { OSSL_GENERAL_NAMES_print(out, iss.issuer, indent) };
        o.print("\n");
    }
    o.line(indent, "Issuer Serial: ");
    // SAFETY: as above; its serial number.
    if unsafe { i2a_ASN1_INTEGER(out, &raw const iss.serial) } <= 0 {
        return 0;
    }
    o.print("\n");
    if iss.issuer_uid.is_null() {
        o.line(indent, "Issuer UID: <none>\n");
    } else {
        o.line(indent, "Issuer UID: ");
        // SAFETY: as above; its unique ID.
        if unsafe { i2a_ASN1_STRING(out, iss.issuer_uid, V_ASN1_BIT_STRING) } <= 0 {
            return 0;
        }
        o.print("\n");
    }
    1
}

/// `i2r_OBJECT_DIGEST_INFO`: the digested object's type, the algorithm, and the digest (by the
/// algorithm's key type's printer, or in hex): 1, or 0.
///
/// # Safety
/// `out` is a live BIO; `odi` is NULL or a live `OSSL_OBJECT_DIGEST_INFO`.
pub(crate) unsafe fn object_digest_info_print(
    out: *mut BIO,
    odi: *const OSSL_OBJECT_DIGEST_INFO,
    indent: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(odi) = (unsafe { odi.cast::<ObjectDigestInfo>().as_ref() }) else {
        err::raise(
            ERR_LIB_ASN1,
            ERR_R_PASSED_NULL_PARAMETER,
            "i2r_OBJECT_DIGEST_INFO",
        );
        return 0;
    };
    // SAFETY: as above.
    let o = unsafe { Out::new(out) };
    let mut dot: i64 = 0;
    // SAFETY: a local; its type.
    if unsafe { ASN1_ENUMERATED_get_int64(&raw mut dot, &raw const odi.digested_object_type) } == 0
    {
        return 0;
    }
    let kind = match dot {
        d if d == i64::from(OSSL_ODI_TYPE_PUBLIC_KEY) => Some("Public Key"),
        d if d == i64::from(OSSL_ODI_TYPE_PUBLIC_KEY_CERT) => Some("Public Key Certificate"),
        d if d == i64::from(OSSL_ODI_TYPE_OTHER) => Some("Other"),
        _ => None,
    };
    if let Some(k) = kind {
        o.line(indent, &format!("Digest Type: {k}\n"));
    }
    if !odi.other_object_type_id.is_null() {
        o.line(indent, "Digest Type Identifier: ");
        // SAFETY: the caller's BIO; its type's identifier.
        unsafe { i2a_ASN1_OBJECT(out, odi.other_object_type_id) };
        o.print("\n");
    }
    if o.line(indent, "Signature Algorithm: ") <= 0 {
        return 0;
    }
    // SAFETY: as above; its algorithm.
    if unsafe { i2a_ASN1_OBJECT(out, odi.digest_algorithm.algorithm) } <= 0 {
        return 0;
    }
    o.print("\n");
    let pad = usize::try_from(indent.unsigned_abs()).unwrap_or(0);
    if o.print(&format!("\n{:pad$}Signature Value: ", "")) <= 0 {
        return 0;
    }
    let sig = &raw const odi.object_digest;
    let ind = indent.saturating_add(4);
    // SAFETY: as above; its algorithm and digest.
    if let Some(r) = unsafe { sig_print(out, &odi.digest_algorithm, sig, ind) } {
        return r;
    }
    if o.write(b"\n") != 1 {
        return 0;
    }
    // SAFETY: as above.
    unsafe { X509_signature_dump(out, sig, ind) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: setting the issuer's name of an attribute certificate whose issuer
    /// is a v1Form replaces it with a v2Form (OpenSSL takes the v1Form's names as a v2Form).
    #[test]
    fn a_v1_issuer_is_replaced() {
        // SAFETY: no preconditions.
        let a = unsafe { X509_ACERT_new() };
        // The information's own pointer, which the calls below don't invalidate.
        // SAFETY: the new certificate.
        let i = unsafe { (*a.cast::<Acert>()).acinfo }.cast::<AcertInfo>();
        assert!(!i.is_null());
        // SAFETY: no preconditions.
        let v1 = unsafe { crate::x509v3::genn::GENERAL_NAMES_new() };
        // SAFETY: its information, given a v1Form.
        unsafe { (*i).issuer.type_ = 0 };
        // SAFETY: as above.
        unsafe { (*i).issuer.u = v1.cast() };
        // SAFETY: no preconditions.
        let name = unsafe { crate::x509::name::X509_NAME_new() };
        // SAFETY: the certificate; the name.
        assert_eq!(unsafe { X509_ACERT_set1_issuerName(a, name) }, 1);
        // SAFETY: as above.
        assert_eq!(unsafe { (*i).issuer.type_ }, ISSUER_V2);
        // SAFETY: as above.
        assert!(!unsafe { X509_ACERT_get0_issuerName(a) }.is_null());
        // SAFETY: made above.
        unsafe { X509_NAME_free(name) };
        // SAFETY: as above.
        unsafe { X509_ACERT_free(a) };
    }
}
