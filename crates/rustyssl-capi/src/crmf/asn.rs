//! CRMF's structures (RFC 4211, `crmf_asn.c`): certificate request messages, their templates,
//! controls and registration info, proof-of-possession, encrypted values and keys, and the
//! password-based MAC's parameters.
//!
//! The types are opaque in OpenSSL's headers; the layouts here are OpenSSL's (`crmf_local.h`),
//! which CMP reaches into.

use core::ffi::{c_int, c_void};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_INTEGER, ASN1_ITEM, ASN1_ITYPE_PRIMITIVE, ASN1_OBJECT, ASN1_OCTET_STRING,
    ASN1_TFLG_EXPLICIT, ASN1_TFLG_IMPLICIT, ASN1_TFLG_OPTIONAL, ASN1_TFLG_SEQUENCE_OF, ASN1_TIME,
    ERR_LIB_ASN1, ERR_LIB_CRMF, GENERAL_NAME, NID_id_regCtrl_algId, NID_id_regCtrl_authenticator,
    NID_id_regCtrl_oldCertID, NID_id_regCtrl_pkiPublicationInfo, NID_id_regCtrl_protocolEncrKey,
    NID_id_regCtrl_regToken, NID_id_regCtrl_rsaKeyLen, NID_id_regInfo_certReq,
    NID_id_regInfo_utf8Pairs, X509_ALGOR, X509_NAME, X509_PUBKEY,
};

use crate::asn1::tpl::items::{
    ASN1_ANY_it, ASN1_BIT_STRING_it, ASN1_INTEGER_it, ASN1_NULL_it, ASN1_OBJECT_it,
    ASN1_OCTET_STRING_it, ASN1_TIME_it, ASN1_UTF8STRING_it, X509_ALGOR_it, d2i, i2d, new_free,
};
use crate::asn1::tpl::statics::{
    AdbEntries, Templates, adb_entry, adb_object, adb_oid, choice, sequence,
};
use crate::asn1::tpl::util::ASN1_item_dup;
use crate::asn1::tpl::{Item, Template, item, item_fns, template, template_at};
use crate::cms::CMS_EnvelopedData_it;
use crate::ffi::ffi_export;
use crate::x509::ext::X509_EXTENSION_it;
use crate::x509::name::X509_NAME_it;
use crate::x509::pubkey::X509_PUBKEY_it;
use crate::x509v3::genn::GENERAL_NAME_it;

pub(crate) type Stack = rustyssl_abi::OPENSSL_STACK;

/// `ossl_crmf_encryptedvalue_st`.
#[repr(C)]
pub(crate) struct EncryptedValue {
    pub(crate) intended_alg: *mut X509_ALGOR,
    pub(crate) symm_alg: *mut X509_ALGOR,
    pub(crate) enc_symm_key: *mut ASN1_BIT_STRING,
    pub(crate) key_alg: *mut X509_ALGOR,
    pub(crate) value_hint: *mut ASN1_OCTET_STRING,
    pub(crate) enc_value: *mut ASN1_BIT_STRING,
}

/// A CHOICE: its selector and its one value.
#[repr(C)]
pub(crate) struct Choice {
    pub(crate) type_: c_int,
    pub(crate) value: *mut c_void,
}

/// `ossl_crmf_certid_st`.
#[repr(C)]
pub(crate) struct CertId {
    pub(crate) issuer: *mut GENERAL_NAME,
    pub(crate) serial_number: *mut ASN1_INTEGER,
}

/// `ossl_crmf_singlepubinfo_st`.
#[repr(C)]
pub(crate) struct SinglePubInfo {
    pub(crate) pub_method: *mut ASN1_INTEGER,
    pub(crate) pub_location: *mut GENERAL_NAME,
}

/// `ossl_crmf_pkipublicationinfo_st`.
#[repr(C)]
pub(crate) struct PkiPublicationInfo {
    pub(crate) action: *mut ASN1_INTEGER,
    pub(crate) pub_infos: *mut Stack,
}

/// `ossl_crmf_pkmacvalue_st`.
#[repr(C)]
pub(crate) struct PkMacValue {
    pub(crate) alg_id: *mut X509_ALGOR,
    pub(crate) value: *mut ASN1_BIT_STRING,
}

/// `ossl_crmf_pbmparameter_st`.
#[repr(C)]
pub(crate) struct PbmParameter {
    pub(crate) salt: *mut ASN1_OCTET_STRING,
    pub(crate) owf: *mut X509_ALGOR,
    pub(crate) iteration_count: *mut ASN1_INTEGER,
    pub(crate) mac: *mut X509_ALGOR,
}

/// `ossl_crmf_poposigningkeyinput_st`.
#[repr(C)]
pub(crate) struct PopoSigningKeyInput {
    pub(crate) auth_info: *mut Choice,
    pub(crate) public_key: *mut X509_PUBKEY,
}

/// `ossl_crmf_poposigningkey_st`.
#[repr(C)]
pub(crate) struct PopoSigningKey {
    pub(crate) poposk_input: *mut PopoSigningKeyInput,
    pub(crate) algorithm_identifier: *mut X509_ALGOR,
    pub(crate) signature: *mut ASN1_BIT_STRING,
}

/// `ossl_crmf_optionalvalidity_st`.
#[repr(C)]
pub(crate) struct OptionalValidity {
    pub(crate) not_before: *mut ASN1_TIME,
    pub(crate) not_after: *mut ASN1_TIME,
}

/// `ossl_crmf_certtemplate_st`.
#[repr(C)]
pub(crate) struct CertTemplate {
    pub(crate) version: *mut ASN1_INTEGER,
    pub(crate) serial_number: *mut ASN1_INTEGER,
    pub(crate) signing_alg: *mut X509_ALGOR,
    pub(crate) issuer: *mut X509_NAME,
    pub(crate) validity: *mut OptionalValidity,
    pub(crate) subject: *mut X509_NAME,
    pub(crate) public_key: *mut X509_PUBKEY,
    pub(crate) issuer_uid: *mut ASN1_BIT_STRING,
    pub(crate) subject_uid: *mut ASN1_BIT_STRING,
    pub(crate) extensions: *mut Stack,
}

/// `ossl_crmf_certrequest_st`.
#[repr(C)]
pub(crate) struct CertRequest {
    pub(crate) cert_req_id: *mut ASN1_INTEGER,
    pub(crate) cert_template: *mut CertTemplate,
    pub(crate) controls: *mut Stack,
}

/// `ossl_crmf_msg_st`.
#[repr(C)]
pub(crate) struct Msg {
    pub(crate) cert_req: *mut CertRequest,
    pub(crate) popo: *mut Choice,
    pub(crate) reg_info: *mut Stack,
}

/// `ossl_crmf_attributetypeandvalue_st`: the type and its value (by the type).
#[repr(C)]
pub(crate) struct Atav {
    pub(crate) type_: *mut ASN1_OBJECT,
    pub(crate) value: *mut c_void,
}

/// The object behind a pointer as its `T`.
///
/// # Safety
/// `p` is NULL or a live object `T` mirrors, not otherwise borrowed.
pub(crate) unsafe fn of<'a, T, U>(p: *const U) -> Option<&'a mut T> {
    // SAFETY: the caller's guarantee.
    unsafe { p.cast::<T>().cast_mut().as_mut() }
}

const SIMPLE: c_int = 0;
const OPT: c_int = ASN1_TFLG_OPTIONAL;
const IMP: c_int = ASN1_TFLG_IMPLICIT;
const EXP: c_int = ASN1_TFLG_EXPLICIT;
const IMP_OPT: c_int = ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL;
const EXP_OPT: c_int = ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL;
const SEQ_OF_OPT: c_int = ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL;
const IMP_SEQ_OF_OPT: c_int = ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL;

macro_rules! tt {
    ($t:ty; $($flags:expr, $tag:expr, $field:ident, $name:literal, $it:expr;)*) => {
        Templates([$(template_at($flags, $tag, offset_of!($t, $field), $name, $it),)*])
    };
}

const VALUE: usize = offset_of!(Choice, value);
const SELECTOR: usize = offset_of!(Choice, type_);

/// CHOICE templates: all at the value's offset.
macro_rules! ct {
    ($($flags:expr, $tag:expr, $name:literal, $it:expr;)*) => {
        Templates([$(template_at($flags, $tag, VALUE, $name, $it),)*])
    };
}

static CERTID_TT: Templates<2> = tt![CertId;
    SIMPLE, 0, issuer, c"issuer", GENERAL_NAME_it;
    SIMPLE, 0, serial_number, c"serialNumber", ASN1_INTEGER_it;
];

static ENCRYPTEDVALUE_TT: Templates<6> = tt![EncryptedValue;
    IMP_OPT, 0, intended_alg, c"intendedAlg", X509_ALGOR_it;
    IMP_OPT, 1, symm_alg, c"symmAlg", X509_ALGOR_it;
    IMP_OPT, 2, enc_symm_key, c"encSymmKey", ASN1_BIT_STRING_it;
    IMP_OPT, 3, key_alg, c"keyAlg", X509_ALGOR_it;
    IMP_OPT, 4, value_hint, c"valueHint", ASN1_OCTET_STRING_it;
    SIMPLE, 0, enc_value, c"encValue", ASN1_BIT_STRING_it;
];

static ENCRYPTEDKEY_TT: Templates<2> = ct![
    SIMPLE, 0, c"value.encryptedValue", OSSL_CRMF_ENCRYPTEDVALUE_it;
    IMP, 0, c"value.envelopedData", CMS_EnvelopedData_it;
];

static SINGLEPUBINFO_TT: Templates<2> = tt![SinglePubInfo;
    SIMPLE, 0, pub_method, c"pubMethod", ASN1_INTEGER_it;
    SIMPLE, 0, pub_location, c"pubLocation", GENERAL_NAME_it;
];

static PKIPUBLICATIONINFO_TT: Templates<2> = tt![PkiPublicationInfo;
    SIMPLE, 0, action, c"action", ASN1_INTEGER_it;
    SEQ_OF_OPT, 0, pub_infos, c"pubInfos", OSSL_CRMF_SINGLEPUBINFO_it;
];

static PKMACVALUE_TT: Templates<2> = tt![PkMacValue;
    SIMPLE, 0, alg_id, c"algId", X509_ALGOR_it;
    SIMPLE, 0, value, c"value", ASN1_BIT_STRING_it;
];

static POPOPRIVKEY_TT: Templates<5> = ct![
    IMP, 0, c"value.thisMessage", ASN1_BIT_STRING_it;
    IMP, 1, c"value.subsequentMessage", ASN1_INTEGER_it;
    IMP, 2, c"value.dhMAC", ASN1_BIT_STRING_it;
    IMP, 3, c"value.agreeMAC", pk_mac_value_it;
    IMP, 4, c"value.encryptedKey", ASN1_NULL_it;
];

static PBMPARAMETER_TT: Templates<4> = tt![PbmParameter;
    SIMPLE, 0, salt, c"salt", ASN1_OCTET_STRING_it;
    SIMPLE, 0, owf, c"owf", X509_ALGOR_it;
    SIMPLE, 0, iteration_count, c"iterationCount", ASN1_INTEGER_it;
    SIMPLE, 0, mac, c"mac", X509_ALGOR_it;
];

static AUTHINFO_TT: Templates<2> = ct![
    EXP, 0, c"value.sender", GENERAL_NAME_it;
    SIMPLE, 0, c"value.publicKeyMAC", pk_mac_value_it;
];

static POPOSIGNINGKEYINPUT_TT: Templates<2> = tt![PopoSigningKeyInput;
    SIMPLE, 0, auth_info, c"authInfo", authinfo_it;
    SIMPLE, 0, public_key, c"publicKey", X509_PUBKEY_it;
];

static POPOSIGNINGKEY_TT: Templates<3> = tt![PopoSigningKey;
    IMP_OPT, 0, poposk_input, c"poposkInput", popo_signing_key_input_it;
    SIMPLE, 0, algorithm_identifier, c"algorithmIdentifier", X509_ALGOR_it;
    SIMPLE, 0, signature, c"signature", ASN1_BIT_STRING_it;
];

static POPO_TT: Templates<4> = ct![
    IMP, 0, c"value.raVerified", ASN1_NULL_it;
    IMP, 1, c"value.signature", popo_signing_key_it;
    EXP, 2, c"value.keyEncipherment", popo_priv_key_it;
    EXP, 3, c"value.keyAgreement", popo_priv_key_it;
];

const ATAV_VALUE: usize = offset_of!(Atav, value);

static ATAV_DEFAULT: Template =
    Template(template_at(OPT, 0, ATAV_VALUE, c"value.other", ASN1_ANY_it));

static ATAV_ADB_TBL: AdbEntries<9> = AdbEntries([
    adb_entry(
        NID_id_regCtrl_regToken,
        template_at(SIMPLE, 0, ATAV_VALUE, c"value.regToken", ASN1_UTF8STRING_it),
    ),
    adb_entry(
        NID_id_regCtrl_authenticator,
        template_at(
            SIMPLE,
            0,
            ATAV_VALUE,
            c"value.authenticator",
            ASN1_UTF8STRING_it,
        ),
    ),
    adb_entry(
        NID_id_regCtrl_pkiPublicationInfo,
        template_at(
            SIMPLE,
            0,
            ATAV_VALUE,
            c"value.pkiPublicationInfo",
            OSSL_CRMF_PKIPUBLICATIONINFO_it,
        ),
    ),
    adb_entry(
        NID_id_regCtrl_oldCertID,
        template_at(
            SIMPLE,
            0,
            ATAV_VALUE,
            c"value.oldCertID",
            OSSL_CRMF_CERTID_it,
        ),
    ),
    adb_entry(
        NID_id_regCtrl_protocolEncrKey,
        template_at(
            SIMPLE,
            0,
            ATAV_VALUE,
            c"value.protocolEncrKey",
            X509_PUBKEY_it,
        ),
    ),
    adb_entry(
        NID_id_regCtrl_algId,
        template_at(SIMPLE, 0, ATAV_VALUE, c"value.algId", X509_ALGOR_it),
    ),
    adb_entry(
        NID_id_regCtrl_rsaKeyLen,
        template_at(SIMPLE, 0, ATAV_VALUE, c"value.rsaKeyLen", ASN1_INTEGER_it),
    ),
    adb_entry(
        NID_id_regInfo_utf8Pairs,
        template_at(
            SIMPLE,
            0,
            ATAV_VALUE,
            c"value.utf8Pairs",
            ASN1_UTF8STRING_it,
        ),
    ),
    adb_entry(
        NID_id_regInfo_certReq,
        template_at(SIMPLE, 0, ATAV_VALUE, c"value.certReq", cert_request_it),
    ),
]);

static ATAV_ADB: crate::asn1::tpl::statics::Adb =
    adb_oid(offset_of!(Atav, type_), &ATAV_ADB_TBL, &ATAV_DEFAULT);

/// The ANY DEFINED BY table, as an ADB template's item function returns it.
unsafe extern "C" fn atav_adb() -> *const ASN1_ITEM {
    (&raw const ATAV_ADB.0).cast()
}

static ATAV_TT: Templates<2> = Templates([
    template_at(SIMPLE, 0, offset_of!(Atav, type_), c"type", ASN1_OBJECT_it),
    adb_object(c"OSSL_CRMF_ATTRIBUTETYPEANDVALUE", atav_adb),
]);

static OPTIONALVALIDITY_TT: Templates<2> = tt![OptionalValidity;
    EXP_OPT, 0, not_before, c"notBefore", ASN1_TIME_it;
    EXP_OPT, 1, not_after, c"notAfter", ASN1_TIME_it;
];

static CERTTEMPLATE_TT: Templates<10> = tt![CertTemplate;
    IMP_OPT, 0, version, c"version", ASN1_INTEGER_it;
    IMP_OPT, 1, serial_number, c"serialNumber", ASN1_INTEGER_it;
    IMP_OPT, 2, signing_alg, c"signingAlg", X509_ALGOR_it;
    EXP_OPT, 3, issuer, c"issuer", X509_NAME_it;
    IMP_OPT, 4, validity, c"validity", optional_validity_it;
    EXP_OPT, 5, subject, c"subject", X509_NAME_it;
    IMP_OPT, 6, public_key, c"publicKey", X509_PUBKEY_it;
    IMP_OPT, 7, issuer_uid, c"issuerUID", ASN1_BIT_STRING_it;
    IMP_OPT, 8, subject_uid, c"subjectUID", ASN1_BIT_STRING_it;
    IMP_SEQ_OF_OPT, 9, extensions, c"extensions", X509_EXTENSION_it;
];

static CERTREQUEST_TT: Templates<3> = tt![CertRequest;
    SIMPLE, 0, cert_req_id, c"certReqId", ASN1_INTEGER_it;
    SIMPLE, 0, cert_template, c"certTemplate", OSSL_CRMF_CERTTEMPLATE_it;
    SEQ_OF_OPT, 0, controls, c"controls", attribute_type_and_value_it;
];

static MSG_TT: Templates<3> = tt![Msg;
    SIMPLE, 0, cert_req, c"certReq", cert_request_it;
    OPT, 0, popo, c"popo", popo_it;
    SEQ_OF_OPT, 0, reg_info, c"regInfo", attribute_type_and_value_it;
];

static MSGS_T: Template = template(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    c"OSSL_CRMF_MSGS",
    OSSL_CRMF_MSG_it,
);

macro_rules! private_item {
    ($($(#[$attr:meta])* fn $name:ident = $item:expr;)*) => {$(
        $(#[$attr])*
        pub(crate) unsafe extern "C" fn $name() -> *const ASN1_ITEM {
            static ITEM: Item = $item;
            &raw const ITEM.0
        }
    )*};
}

private_item! {
    /// `OSSL_CRMF_PKMACVALUE_it`.
    fn pk_mac_value_it = sequence::<PkMacValue, 2>(&PKMACVALUE_TT, None, c"OSSL_CRMF_PKMACVALUE");
    /// `OSSL_CRMF_POPOPRIVKEY_it`.
    fn popo_priv_key_it = choice::<Choice, 5>(&POPOPRIVKEY_TT, SELECTOR, None, c"OSSL_CRMF_POPOPRIVKEY");
    /// `OSSL_CRMF_POPOSIGNINGKEYINPUT_AUTHINFO_it`.
    fn authinfo_it = choice::<Choice, 2>(&AUTHINFO_TT, SELECTOR, None, c"OSSL_CRMF_POPOSIGNINGKEYINPUT_AUTHINFO");
    /// `OSSL_CRMF_POPOSIGNINGKEYINPUT_it`.
    fn popo_signing_key_input_it = sequence::<PopoSigningKeyInput, 2>(&POPOSIGNINGKEYINPUT_TT, None, c"OSSL_CRMF_POPOSIGNINGKEYINPUT");
    /// `OSSL_CRMF_POPOSIGNINGKEY_it`.
    fn popo_signing_key_it = sequence::<PopoSigningKey, 3>(&POPOSIGNINGKEY_TT, None, c"OSSL_CRMF_POPOSIGNINGKEY");
    /// `OSSL_CRMF_POPO_it`.
    fn popo_it = choice::<Choice, 4>(&POPO_TT, SELECTOR, None, c"OSSL_CRMF_POPO");
    /// `OSSL_CRMF_ATTRIBUTETYPEANDVALUE_it`.
    fn attribute_type_and_value_it = sequence::<Atav, 2>(&ATAV_TT, None, c"OSSL_CRMF_ATTRIBUTETYPEANDVALUE");
    /// `OSSL_CRMF_OPTIONALVALIDITY_it`.
    fn optional_validity_it = sequence::<OptionalValidity, 2>(&OPTIONALVALIDITY_TT, None, c"OSSL_CRMF_OPTIONALVALIDITY");
    /// `OSSL_CRMF_CERTREQUEST_it`.
    fn cert_request_it = sequence::<CertRequest, 3>(&CERTREQUEST_TT, None, c"OSSL_CRMF_CERTREQUEST");
}

item_fns! {
    /// CertId.
    pub unsafe extern "C" fn OSSL_CRMF_CERTID_it = sequence::<CertId, 2>(&CERTID_TT, None, c"OSSL_CRMF_CERTID");
    /// EncryptedValue.
    pub unsafe extern "C" fn OSSL_CRMF_ENCRYPTEDVALUE_it = sequence::<EncryptedValue, 6>(&ENCRYPTEDVALUE_TT, None, c"OSSL_CRMF_ENCRYPTEDVALUE");
    /// EncryptedKey.
    pub unsafe extern "C" fn OSSL_CRMF_ENCRYPTEDKEY_it = choice::<Choice, 2>(&ENCRYPTEDKEY_TT, SELECTOR, None, c"OSSL_CRMF_ENCRYPTEDKEY");
    /// SinglePubInfo.
    pub unsafe extern "C" fn OSSL_CRMF_SINGLEPUBINFO_it = sequence::<SinglePubInfo, 2>(&SINGLEPUBINFO_TT, None, c"OSSL_CRMF_SINGLEPUBINFO");
    /// PKIPublicationInfo.
    pub unsafe extern "C" fn OSSL_CRMF_PKIPUBLICATIONINFO_it = sequence::<PkiPublicationInfo, 2>(&PKIPUBLICATIONINFO_TT, None, c"OSSL_CRMF_PKIPUBLICATIONINFO");
    /// PBMParameter.
    pub unsafe extern "C" fn OSSL_CRMF_PBMPARAMETER_it = sequence::<PbmParameter, 4>(&PBMPARAMETER_TT, None, c"OSSL_CRMF_PBMPARAMETER");
    /// CertTemplate.
    pub unsafe extern "C" fn OSSL_CRMF_CERTTEMPLATE_it = sequence::<CertTemplate, 10>(&CERTTEMPLATE_TT, None, c"OSSL_CRMF_CERTTEMPLATE");
    /// CertReqMsg.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_it = sequence::<Msg, 3>(&MSG_TT, None, c"OSSL_CRMF_MSG");
    /// CertReqMessages: SEQUENCE OF CertReqMsg.
    pub unsafe extern "C" fn OSSL_CRMF_MSGS_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const MSGS_T.0, 0, ptr::null(), 0, c"OSSL_CRMF_MSGS");
}

new_free! {
    pub unsafe extern "C" fn OSSL_CRMF_CERTID_new, pub unsafe extern "C" fn OSSL_CRMF_CERTID_free(rustyssl_abi::OSSL_CRMF_CERTID) = OSSL_CRMF_CERTID_it;
    pub unsafe extern "C" fn OSSL_CRMF_ENCRYPTEDVALUE_new, pub unsafe extern "C" fn OSSL_CRMF_ENCRYPTEDVALUE_free(rustyssl_abi::OSSL_CRMF_ENCRYPTEDVALUE) = OSSL_CRMF_ENCRYPTEDVALUE_it;
    pub unsafe extern "C" fn OSSL_CRMF_ENCRYPTEDKEY_new, pub unsafe extern "C" fn OSSL_CRMF_ENCRYPTEDKEY_free(rustyssl_abi::OSSL_CRMF_ENCRYPTEDKEY) = OSSL_CRMF_ENCRYPTEDKEY_it;
    pub unsafe extern "C" fn OSSL_CRMF_SINGLEPUBINFO_new, pub unsafe extern "C" fn OSSL_CRMF_SINGLEPUBINFO_free(rustyssl_abi::OSSL_CRMF_SINGLEPUBINFO) = OSSL_CRMF_SINGLEPUBINFO_it;
    pub unsafe extern "C" fn OSSL_CRMF_PKIPUBLICATIONINFO_new, pub unsafe extern "C" fn OSSL_CRMF_PKIPUBLICATIONINFO_free(rustyssl_abi::OSSL_CRMF_PKIPUBLICATIONINFO) = OSSL_CRMF_PKIPUBLICATIONINFO_it;
    pub unsafe extern "C" fn OSSL_CRMF_PBMPARAMETER_new, pub unsafe extern "C" fn OSSL_CRMF_PBMPARAMETER_free(rustyssl_abi::OSSL_CRMF_PBMPARAMETER) = OSSL_CRMF_PBMPARAMETER_it;
    pub unsafe extern "C" fn OSSL_CRMF_CERTTEMPLATE_new, pub unsafe extern "C" fn OSSL_CRMF_CERTTEMPLATE_free(rustyssl_abi::OSSL_CRMF_CERTTEMPLATE) = OSSL_CRMF_CERTTEMPLATE_it;
    pub unsafe extern "C" fn OSSL_CRMF_MSG_new, pub unsafe extern "C" fn OSSL_CRMF_MSG_free(rustyssl_abi::OSSL_CRMF_MSG) = OSSL_CRMF_MSG_it;
    pub unsafe extern "C" fn OSSL_CRMF_MSGS_new, pub unsafe extern "C" fn OSSL_CRMF_MSGS_free(rustyssl_abi::OSSL_CRMF_MSGS) = OSSL_CRMF_MSGS_it;
}

i2d! {
    /// Encodes a OSSL_CRMF_CERTID.
    pub unsafe extern "C" fn i2d_OSSL_CRMF_CERTID(rustyssl_abi::OSSL_CRMF_CERTID) = OSSL_CRMF_CERTID_it;
    /// Encodes a OSSL_CRMF_ENCRYPTEDVALUE.
    pub unsafe extern "C" fn i2d_OSSL_CRMF_ENCRYPTEDVALUE(rustyssl_abi::OSSL_CRMF_ENCRYPTEDVALUE) = OSSL_CRMF_ENCRYPTEDVALUE_it;
    /// Encodes a OSSL_CRMF_ENCRYPTEDKEY.
    pub unsafe extern "C" fn i2d_OSSL_CRMF_ENCRYPTEDKEY(rustyssl_abi::OSSL_CRMF_ENCRYPTEDKEY) = OSSL_CRMF_ENCRYPTEDKEY_it;
    /// Encodes a OSSL_CRMF_SINGLEPUBINFO.
    pub unsafe extern "C" fn i2d_OSSL_CRMF_SINGLEPUBINFO(rustyssl_abi::OSSL_CRMF_SINGLEPUBINFO) = OSSL_CRMF_SINGLEPUBINFO_it;
    /// Encodes a OSSL_CRMF_PKIPUBLICATIONINFO.
    pub unsafe extern "C" fn i2d_OSSL_CRMF_PKIPUBLICATIONINFO(rustyssl_abi::OSSL_CRMF_PKIPUBLICATIONINFO) = OSSL_CRMF_PKIPUBLICATIONINFO_it;
    /// Encodes a OSSL_CRMF_PBMPARAMETER.
    pub unsafe extern "C" fn i2d_OSSL_CRMF_PBMPARAMETER(rustyssl_abi::OSSL_CRMF_PBMPARAMETER) = OSSL_CRMF_PBMPARAMETER_it;
    /// Encodes a OSSL_CRMF_CERTTEMPLATE.
    pub unsafe extern "C" fn i2d_OSSL_CRMF_CERTTEMPLATE(rustyssl_abi::OSSL_CRMF_CERTTEMPLATE) = OSSL_CRMF_CERTTEMPLATE_it;
    /// Encodes a OSSL_CRMF_MSG.
    pub unsafe extern "C" fn i2d_OSSL_CRMF_MSG(rustyssl_abi::OSSL_CRMF_MSG) = OSSL_CRMF_MSG_it;
    /// Encodes a OSSL_CRMF_MSGS.
    pub unsafe extern "C" fn i2d_OSSL_CRMF_MSGS(rustyssl_abi::OSSL_CRMF_MSGS) = OSSL_CRMF_MSGS_it;
}

d2i! {
    /// Decodes a OSSL_CRMF_CERTID.
    pub unsafe extern "C" fn d2i_OSSL_CRMF_CERTID(rustyssl_abi::OSSL_CRMF_CERTID) = OSSL_CRMF_CERTID_it;
    /// Decodes a OSSL_CRMF_ENCRYPTEDVALUE.
    pub unsafe extern "C" fn d2i_OSSL_CRMF_ENCRYPTEDVALUE(rustyssl_abi::OSSL_CRMF_ENCRYPTEDVALUE) = OSSL_CRMF_ENCRYPTEDVALUE_it;
    /// Decodes a OSSL_CRMF_ENCRYPTEDKEY.
    pub unsafe extern "C" fn d2i_OSSL_CRMF_ENCRYPTEDKEY(rustyssl_abi::OSSL_CRMF_ENCRYPTEDKEY) = OSSL_CRMF_ENCRYPTEDKEY_it;
    /// Decodes a OSSL_CRMF_SINGLEPUBINFO.
    pub unsafe extern "C" fn d2i_OSSL_CRMF_SINGLEPUBINFO(rustyssl_abi::OSSL_CRMF_SINGLEPUBINFO) = OSSL_CRMF_SINGLEPUBINFO_it;
    /// Decodes a OSSL_CRMF_PKIPUBLICATIONINFO.
    pub unsafe extern "C" fn d2i_OSSL_CRMF_PKIPUBLICATIONINFO(rustyssl_abi::OSSL_CRMF_PKIPUBLICATIONINFO) = OSSL_CRMF_PKIPUBLICATIONINFO_it;
    /// Decodes a OSSL_CRMF_PBMPARAMETER.
    pub unsafe extern "C" fn d2i_OSSL_CRMF_PBMPARAMETER(rustyssl_abi::OSSL_CRMF_PBMPARAMETER) = OSSL_CRMF_PBMPARAMETER_it;
    /// Decodes a OSSL_CRMF_CERTTEMPLATE.
    pub unsafe extern "C" fn d2i_OSSL_CRMF_CERTTEMPLATE(rustyssl_abi::OSSL_CRMF_CERTTEMPLATE) = OSSL_CRMF_CERTTEMPLATE_it;
    /// Decodes a OSSL_CRMF_MSG.
    pub unsafe extern "C" fn d2i_OSSL_CRMF_MSG(rustyssl_abi::OSSL_CRMF_MSG) = OSSL_CRMF_MSG_it;
    /// Decodes a OSSL_CRMF_MSGS.
    pub unsafe extern "C" fn d2i_OSSL_CRMF_MSGS(rustyssl_abi::OSSL_CRMF_MSGS) = OSSL_CRMF_MSGS_it;
}

ffi_export! {
    /// A copy of the OSSL_CRMF_CERTID, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live value.
    pub unsafe extern "C" fn OSSL_CRMF_CERTID_dup(a: *const rustyssl_abi::OSSL_CRMF_CERTID) -> *mut rustyssl_abi::OSSL_CRMF_CERTID
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        // SAFETY: no preconditions.
        let i = unsafe { OSSL_CRMF_CERTID_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_dup(i, a.cast()) }.cast()
    }
}

ffi_export! {
    /// A copy of the OSSL_CRMF_CERTTEMPLATE, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live value.
    pub unsafe extern "C" fn OSSL_CRMF_CERTTEMPLATE_dup(a: *const rustyssl_abi::OSSL_CRMF_CERTTEMPLATE) -> *mut rustyssl_abi::OSSL_CRMF_CERTTEMPLATE
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        // SAFETY: no preconditions.
        let i = unsafe { OSSL_CRMF_CERTTEMPLATE_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_dup(i, a.cast()) }.cast()
    }
}

ffi_export! {
    /// A copy of the OSSL_CRMF_MSG, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live value.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_dup(a: *const rustyssl_abi::OSSL_CRMF_MSG) -> *mut rustyssl_abi::OSSL_CRMF_MSG
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        // SAFETY: no preconditions.
        let i = unsafe { OSSL_CRMF_MSG_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_dup(i, a.cast()) }.cast()
    }
}

ffi_export! {
    /// Frees a OSSL_CRMF_ATTRIBUTETYPEANDVALUE (nothing for NULL).
    ///
    /// # Safety
    /// `a` is NULL or a live value, not used after.
    pub unsafe extern "C" fn OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free(a: *mut rustyssl_abi::OSSL_CRMF_ATTRIBUTETYPEANDVALUE)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let i = unsafe { attribute_type_and_value_it() };
        // SAFETY: the caller's guarantee.
        unsafe { crate::asn1::tpl::free::ASN1_item_free(a.cast(), i) };
    }
}

ffi_export! {
    /// A copy of the OSSL_CRMF_ATTRIBUTETYPEANDVALUE, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live value.
    pub unsafe extern "C" fn OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup(a: *const rustyssl_abi::OSSL_CRMF_ATTRIBUTETYPEANDVALUE) -> *mut rustyssl_abi::OSSL_CRMF_ATTRIBUTETYPEANDVALUE
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        // SAFETY: no preconditions.
        let i = unsafe { attribute_type_and_value_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_dup(i, a.cast()) }.cast()
    }
}

/// A copy of a value of the private item, or NULL.
///
/// # Safety
/// `v` is NULL or a live value of the item.
pub(crate) unsafe fn dup_of(
    v: *const c_void,
    it: unsafe extern "C" fn() -> *const ASN1_ITEM,
) -> *mut c_void {
    // SAFETY: no preconditions.
    let i = unsafe { it() };
    // SAFETY: the caller's guarantee.
    unsafe { ASN1_item_dup(i, v) }
}

/// A new value of the private item, or NULL.
pub(crate) fn new_of(it: unsafe extern "C" fn() -> *const ASN1_ITEM) -> *mut c_void {
    // SAFETY: no preconditions.
    let i = unsafe { it() };
    // SAFETY: the item.
    unsafe { crate::asn1::tpl::new::ASN1_item_new(i) }.cast()
}

/// Frees a value of the private item.
///
/// # Safety
/// `v` is NULL or a value of the item, not used after.
pub(crate) unsafe fn free_of(v: *mut c_void, it: unsafe extern "C" fn() -> *const ASN1_ITEM) {
    // SAFETY: no preconditions.
    let i = unsafe { it() };
    // SAFETY: the caller's guarantee.
    unsafe { crate::asn1::tpl::free::ASN1_item_free(v.cast(), i) };
}
