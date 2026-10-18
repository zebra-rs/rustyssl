//! CMP's structures (RFC 9810, `cmp_asn.c`): the message, its header and body, and every body's
//! content; InfoTypeAndValue and its typed values; CRL status; and the functions on them.
//!
//! The layouts are OpenSSL's (`cmp_local.h`), with its field names. A CHOICE is a [`Choice`]: its
//! selector and its one value; a union of pointers is one `*mut c_void`. Every stack is an
//! [`Stack`].

use core::ffi::{c_char, c_int, c_long, c_void};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_INTEGER, ASN1_ITEM, ASN1_ITYPE_PRIMITIVE, ASN1_OBJECT, ASN1_OCTET_STRING,
    ASN1_OP_DUP_POST, ASN1_OP_FREE_POST, ASN1_OP_GET0_LIBCTX, ASN1_OP_GET0_PROPQ,
    ASN1_R_INVALID_NUMBER, ASN1_R_TOO_LARGE, ASN1_R_TOO_SMALL, ASN1_TFLG_EXPLICIT,
    ASN1_TFLG_OPTIONAL, ASN1_TFLG_SEQUENCE_OF, ASN1_TFLG_UNIVERSAL, ASN1_TIME, ASN1_TYPE,
    ASN1_VALUE, AUTHORITY_KEYID, CMP_R_INVALID_KEYSPEC, CMP_R_NULL_ARGUMENT, DIST_POINT,
    DIST_POINT_NAME, ERR_LIB_ASN1, ERR_LIB_CMP, ERR_R_PASSED_INVALID_ARGUMENT,
    ERR_R_PASSED_NULL_PARAMETER, GEN_DIRNAME, GENERAL_NAME, GENERAL_NAMES, ISSUING_DIST_POINT,
    NID_authority_key_identifier, NID_crl_distribution_points, NID_id_it_caCerts,
    NID_id_it_caKeyUpdateInfo, NID_id_it_caProtEncCert, NID_id_it_certProfile,
    NID_id_it_certReqTemplate, NID_id_it_confirmWaitTime, NID_id_it_crlStatusList, NID_id_it_crls,
    NID_id_it_currentCRL, NID_id_it_encKeyPairTypes, NID_id_it_implicitConfirm,
    NID_id_it_keyPairParamRep, NID_id_it_keyPairParamReq, NID_id_it_origPKIMessage,
    NID_id_it_preferredSymmAlg, NID_id_it_revPassphrase, NID_id_it_rootCaCert,
    NID_id_it_rootCaKeyUpdate, NID_id_it_signKeyPairTypes, NID_id_it_suppLangTags,
    NID_id_it_unsupportedOIDs, NID_id_regCtrl_algId, NID_id_regCtrl_rsaKeyLen,
    NID_issuing_distribution_point, OSSL_CMP_ATAV, OSSL_CMP_CRLSTATUS, OSSL_CMP_ITAV, OSSL_CMP_MSG,
    OSSL_CRMF_CERTID, OSSL_CRMF_CERTTEMPLATE, OSSL_CRMF_ENCRYPTEDKEY, OSSL_CRMF_PKIPUBLICATIONINFO,
    OSSL_LIB_CTX, X509, X509_ALGOR, X509_CRL, X509_NAME,
};

use crate::asn1::integer::{ASN1_INTEGER_get_int64, ASN1_INTEGER_set};
use crate::asn1::string::{ASN1_INTEGER_free, ASN1_INTEGER_new};
use crate::asn1::tpl::items::{
    ASN1_ANY_it, ASN1_BIT_STRING_it, ASN1_GENERALIZEDTIME_it, ASN1_INTEGER_it, ASN1_NULL_it,
    ASN1_OBJECT_it, ASN1_OCTET_STRING_it, ASN1_TIME_it, ASN1_UTF8STRING_it, X509_ALGOR_free,
    X509_ALGOR_it, d2i, i2d, new_free,
};
use crate::asn1::tpl::statics::{
    AdbEntries, Aux, Templates, adb_entry, adb_object, adb_oid, aux, choice, sequence,
};
use crate::asn1::tpl::util::ASN1_TIME_dup;
use crate::asn1::tpl::{Item, Template, item, item_fns, template, template_at};
use crate::crmf::asn::{
    Atav, OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup, OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free,
    OSSL_CRMF_CERTID_it, OSSL_CRMF_CERTTEMPLATE_dup, OSSL_CRMF_CERTTEMPLATE_free,
    OSSL_CRMF_CERTTEMPLATE_it, OSSL_CRMF_ENCRYPTEDKEY_it, OSSL_CRMF_ENCRYPTEDVALUE_it,
    OSSL_CRMF_MSGS_it, OSSL_CRMF_PKIPUBLICATIONINFO_it, attribute_type_and_value_it, dup_of,
    free_of, new_of,
};
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::objects::{OBJ_nid2ln, OBJ_nid2obj, OBJ_nid2sn, OBJ_obj2nid};
use crate::stack::{
    OPENSSL_sk_deep_copy, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_new_reserve,
    OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
};
use crate::x509::algor::X509_ALGOR_dup;
use crate::x509::cert::{X509_dup, X509_free, X509_get_issuer_name, X509_it};
use crate::x509::crl::{
    X509_CRL_dup, X509_CRL_free, X509_CRL_get_ext_d2i, X509_CRL_get_issuer,
    X509_CRL_get0_lastUpdate, X509_CRL_it,
};
use crate::x509::ext::X509_EXTENSIONS_it;
use crate::x509::purpose::X509_get_ext_d2i;
use crate::x509::req::X509_REQ_it;
use crate::x509v3::akid::AUTHORITY_KEYID_free;
use crate::x509v3::crld::{
    DIST_POINT_NAME_dup, DIST_POINT_NAME_it, DIST_POINT_free, ISSUING_DIST_POINT_free,
};
use crate::x509v3::genn::{
    GENERAL_NAME_dup, GENERAL_NAME_free, GENERAL_NAME_it, GENERAL_NAME_set1_X509_NAME,
    GENERAL_NAMES_it,
};

pub(crate) use crate::crmf::asn::Choice;
pub(crate) use crate::crmf::asn::of;

/// Every stack.
pub(crate) type Stack = rustyssl_abi::OPENSSL_STACK;

/// `OSSL_CMP_REVANNCONTENT`.
#[repr(C)]
pub(crate) struct RevAnnContent {
    pub(crate) status: *mut ASN1_INTEGER,
    pub(crate) certId: *mut OSSL_CRMF_CERTID,
    pub(crate) willBeRevokedAt: *mut ASN1_TIME,
    pub(crate) badSinceDate: *mut ASN1_TIME,
    pub(crate) crlDetails: *mut Stack,
}

/// `OSSL_CMP_CHALLENGE`.
#[repr(C)]
pub(crate) struct Challenge {
    pub(crate) owf: *mut X509_ALGOR,
    pub(crate) witness: *mut ASN1_OCTET_STRING,
    pub(crate) challenge: *mut ASN1_OCTET_STRING,
}

/// `OSSL_CMP_CAKEYUPDANNCONTENT`.
#[repr(C)]
pub(crate) struct CaKeyUpdAnnContent {
    pub(crate) oldWithNew: *mut X509,
    pub(crate) newWithOld: *mut X509,
    pub(crate) newWithNew: *mut X509,
}

/// `OSSL_CMP_ROOTCAKEYUPDATE`.
#[repr(C)]
pub(crate) struct RootCaKeyUpdate {
    pub(crate) newWithNew: *mut X509,
    pub(crate) newWithOld: *mut X509,
    pub(crate) oldWithNew: *mut X509,
}

/// `OSSL_CMP_CERTREQTEMPLATE`.
#[repr(C)]
pub(crate) struct CertReqTemplate {
    pub(crate) certTemplate: *mut OSSL_CRMF_CERTTEMPLATE,
    pub(crate) keySpec: *mut Stack,
}

/// `OSSL_CMP_CRLSTATUS`.
#[repr(C)]
pub(crate) struct CrlStatus {
    /// An `OSSL_CMP_CRLSOURCE`: a [`Choice`] of [`CRLSOURCE_DPN`] or [`CRLSOURCE_ISSUER`].
    pub(crate) source: *mut Choice,
    pub(crate) thisUpdate: *mut ASN1_TIME,
}

/// `OSSL_CMP_CRLSOURCE_DPN`.
pub(crate) const CRLSOURCE_DPN: c_int = 0;
/// `OSSL_CMP_CRLSOURCE_ISSUER`.
pub(crate) const CRLSOURCE_ISSUER: c_int = 1;

/// `OSSL_CMP_ITAV`: `infoValue` is the union (`other` and every typed value).
#[repr(C)]
pub(crate) struct Itav {
    pub(crate) infoType: *mut ASN1_OBJECT,
    pub(crate) infoValue: *mut c_void,
}

/// `OSSL_CMP_CERTIFIEDKEYPAIR`.
#[repr(C)]
pub(crate) struct CertifiedKeyPair {
    /// An `OSSL_CMP_CERTORENCCERT`: a [`Choice`] of [`CERTORENCCERT_CERTIFICATE`] or
    /// [`CERTORENCCERT_ENCRYPTEDCERT`].
    pub(crate) certOrEncCert: *mut Choice,
    pub(crate) privateKey: *mut OSSL_CRMF_ENCRYPTEDKEY,
    pub(crate) publicationInfo: *mut OSSL_CRMF_PKIPUBLICATIONINFO,
}

/// `OSSL_CMP_CERTORENCCERT_CERTIFICATE`.
pub(crate) const CERTORENCCERT_CERTIFICATE: c_int = 0;
/// `OSSL_CMP_CERTORENCCERT_ENCRYPTEDCERT`.
pub(crate) const CERTORENCCERT_ENCRYPTEDCERT: c_int = 1;

/// `OSSL_CMP_PKISI`.
#[repr(C)]
pub(crate) struct PkiSi {
    pub(crate) status: *mut ASN1_INTEGER,
    pub(crate) statusString: *mut Stack,
    pub(crate) failInfo: *mut ASN1_BIT_STRING,
}

/// `OSSL_CMP_REVDETAILS`.
#[repr(C)]
pub(crate) struct RevDetails {
    pub(crate) certDetails: *mut OSSL_CRMF_CERTTEMPLATE,
    pub(crate) crlEntryDetails: *mut Stack,
}

/// `OSSL_CMP_REVREPCONTENT`.
#[repr(C)]
pub(crate) struct RevRepContent {
    pub(crate) status: *mut Stack,
    pub(crate) revCerts: *mut Stack,
    pub(crate) crls: *mut Stack,
}

/// `OSSL_CMP_KEYRECREPCONTENT`.
#[repr(C)]
pub(crate) struct KeyRecRepContent {
    pub(crate) status: *mut PkiSi,
    pub(crate) newSigCert: *mut X509,
    pub(crate) caCerts: *mut Stack,
    pub(crate) keyPairHist: *mut Stack,
}

/// `OSSL_CMP_ERRORMSGCONTENT`.
#[repr(C)]
pub(crate) struct ErrorMsgContent {
    pub(crate) pKIStatusInfo: *mut PkiSi,
    pub(crate) errorCode: *mut ASN1_INTEGER,
    pub(crate) errorDetails: *mut Stack,
}

/// `OSSL_CMP_CERTSTATUS`.
#[repr(C)]
pub(crate) struct CertStatus {
    pub(crate) certHash: *mut ASN1_OCTET_STRING,
    pub(crate) certReqId: *mut ASN1_INTEGER,
    pub(crate) statusInfo: *mut PkiSi,
    pub(crate) hashAlg: *mut X509_ALGOR,
}

/// `OSSL_CMP_CERTRESPONSE`.
#[repr(C)]
pub(crate) struct CertResponse {
    pub(crate) certReqId: *mut ASN1_INTEGER,
    pub(crate) status: *mut PkiSi,
    pub(crate) certifiedKeyPair: *mut CertifiedKeyPair,
    pub(crate) rspInfo: *mut ASN1_OCTET_STRING,
}

/// `OSSL_CMP_CERTREPMESSAGE`.
#[repr(C)]
pub(crate) struct CertRepMessage {
    pub(crate) caPubs: *mut Stack,
    pub(crate) response: *mut Stack,
}

/// `OSSL_CMP_POLLREQ`.
#[repr(C)]
pub(crate) struct PollReq {
    pub(crate) certReqId: *mut ASN1_INTEGER,
}

/// `OSSL_CMP_POLLREP`.
#[repr(C)]
pub(crate) struct PollRep {
    pub(crate) certReqId: *mut ASN1_INTEGER,
    pub(crate) checkAfter: *mut ASN1_INTEGER,
    pub(crate) reason: *mut Stack,
}

/// `OSSL_CMP_PKIHEADER`.
#[repr(C)]
pub(crate) struct PkiHeader {
    pub(crate) pvno: *mut ASN1_INTEGER,
    pub(crate) sender: *mut GENERAL_NAME,
    pub(crate) recipient: *mut GENERAL_NAME,
    pub(crate) messageTime: *mut ASN1_TIME,
    pub(crate) protectionAlg: *mut X509_ALGOR,
    pub(crate) senderKID: *mut ASN1_OCTET_STRING,
    pub(crate) recipKID: *mut ASN1_OCTET_STRING,
    pub(crate) transactionID: *mut ASN1_OCTET_STRING,
    pub(crate) senderNonce: *mut ASN1_OCTET_STRING,
    pub(crate) recipNonce: *mut ASN1_OCTET_STRING,
    pub(crate) freeText: *mut Stack,
    pub(crate) generalInfo: *mut Stack,
}

/// `OSSL_CMP_PKIBODY`: a [`Choice`] whose selector is one of the `PKIBODY_*` numbers.
pub(crate) type PkiBody = Choice;

/// `OSSL_CMP_MSG`.
#[repr(C)]
pub(crate) struct Msg {
    pub(crate) header: *mut PkiHeader,
    pub(crate) body: *mut PkiBody,
    pub(crate) protection: *mut ASN1_BIT_STRING,
    pub(crate) extraCerts: *mut Stack,
    pub(crate) libctx: *mut OSSL_LIB_CTX,
    pub(crate) propq: *mut c_char,
}

/// `OSSL_CMP_PROTECTEDPART`.
#[repr(C)]
pub(crate) struct ProtectedPart {
    pub(crate) header: *mut PkiHeader,
    pub(crate) body: *mut PkiBody,
}

// The body types (`cmp_local.h`).
pub(crate) const PKIBODY_IR: c_int = 0;
pub(crate) const PKIBODY_IP: c_int = 1;
pub(crate) const PKIBODY_CR: c_int = 2;
pub(crate) const PKIBODY_CP: c_int = 3;
pub(crate) const PKIBODY_P10CR: c_int = 4;
pub(crate) const PKIBODY_KUR: c_int = 7;
pub(crate) const PKIBODY_KUP: c_int = 8;
pub(crate) const PKIBODY_RR: c_int = 11;
pub(crate) const PKIBODY_RP: c_int = 12;
pub(crate) const PKIBODY_CCP: c_int = 14;
pub(crate) const PKIBODY_PKICONF: c_int = 19;
pub(crate) const PKIBODY_GENM: c_int = 21;
pub(crate) const PKIBODY_GENP: c_int = 22;
pub(crate) const PKIBODY_ERROR: c_int = 23;
pub(crate) const PKIBODY_CERTCONF: c_int = 24;
pub(crate) const PKIBODY_POLLREQ: c_int = 25;
pub(crate) const PKIBODY_POLLREP: c_int = 26;
pub(crate) const PKIBODY_TYPE_MAX: c_int = PKIBODY_POLLREP;

/// `OSSL_CMP_CERTREQID`: the first (and so far only) certificate request's.
pub(crate) const CERTREQID: c_int = 0;
/// `OSSL_CMP_CERTREQID_NONE`.
pub(crate) const CERTREQID_NONE: c_int = -1;
/// `OSSL_CMP_CERTREQID_INVALID`.
pub(crate) const CERTREQID_INVALID: c_int = -2;
/// `OSSL_CMP_REVREQSID`: the first (and so far only) revocation request's.
pub(crate) const REVREQSID: c_int = 0;
/// `OSSL_CMP_TRANSACTIONID_LENGTH`.
pub(crate) const TRANSACTIONID_LENGTH: c_int = 16;
/// `OSSL_CMP_SENDERNONCE_LENGTH`.
pub(crate) const SENDERNONCE_LENGTH: c_int = 16;
/// `OSSL_CMP_EXPECTED_RESP_TIME`: the expected maximum seconds of a round trip, for polling's
/// last try.
pub(crate) const EXPECTED_RESP_TIME: i64 = 2;

const SIMPLE: c_int = 0;
const OPT: c_int = ASN1_TFLG_OPTIONAL;
const EXP: c_int = ASN1_TFLG_EXPLICIT;
const EXP_OPT: c_int = ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL;
const SEQ_OF: c_int = ASN1_TFLG_SEQUENCE_OF;
const SEQ_OF_OPT: c_int = ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL;
const EXP_SEQ_OF_OPT: c_int = ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL;

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

static REVANNCONTENT_TT: Templates<5> = tt![RevAnnContent;
    SIMPLE, 0, status, c"status", ASN1_INTEGER_it;
    SIMPLE, 0, certId, c"certId", OSSL_CRMF_CERTID_it;
    SIMPLE, 0, willBeRevokedAt, c"willBeRevokedAt", ASN1_GENERALIZEDTIME_it;
    SIMPLE, 0, badSinceDate, c"badSinceDate", ASN1_GENERALIZEDTIME_it;
    OPT, 0, crlDetails, c"crlDetails", X509_EXTENSIONS_it;
];

static CHALLENGE_TT: Templates<3> = tt![Challenge;
    OPT, 0, owf, c"owf", X509_ALGOR_it;
    SIMPLE, 0, witness, c"witness", ASN1_OCTET_STRING_it;
    SIMPLE, 0, challenge, c"challenge", ASN1_OCTET_STRING_it;
];

static POPODECKEYCHALLCONTENT_T: Template =
    template(SEQ_OF, 0, c"OSSL_CMP_POPODECKEYCHALLCONTENT", challenge_it);
static POPODECKEYRESPCONTENT_T: Template = template(
    SEQ_OF,
    0,
    c"OSSL_CMP_POPODECKEYRESPCONTENT",
    ASN1_INTEGER_it,
);

static CAKEYUPDANNCONTENT_TT: Templates<3> = tt![CaKeyUpdAnnContent;
    SIMPLE, 0, oldWithNew, c"oldWithNew", X509_it;
    SIMPLE, 0, newWithOld, c"newWithOld", X509_it;
    SIMPLE, 0, newWithNew, c"newWithNew", X509_it;
];

static ERRORMSGCONTENT_TT: Templates<3> = tt![ErrorMsgContent;
    SIMPLE, 0, pKIStatusInfo, c"pKIStatusInfo", OSSL_CMP_PKISI_it;
    OPT, 0, errorCode, c"errorCode", ASN1_INTEGER_it;
    SEQ_OF_OPT, 0, errorDetails, c"errorDetails", ASN1_UTF8STRING_it;
];

const ITAV_VALUE: usize = offset_of!(Itav, infoValue);

/// An `ADB_ENTRY` of the InfoTypeAndValue table.
const fn itav_entry(
    nid: c_int,
    flags: c_int,
    name: &'static core::ffi::CStr,
    it: unsafe extern "C" fn() -> *const ASN1_ITEM,
) -> rustyssl_abi::ASN1_ADB_TABLE {
    adb_entry(nid, template_at(flags, 0, ITAV_VALUE, name, it))
}

static ITAV_DEFAULT: Template = Template(template_at(
    OPT,
    0,
    ITAV_VALUE,
    c"infoValue.other",
    ASN1_ANY_it,
));

static ITAV_ADB_TBL: AdbEntries<21> = AdbEntries([
    itav_entry(
        NID_id_it_caProtEncCert,
        OPT,
        c"infoValue.caProtEncCert",
        X509_it,
    ),
    itav_entry(
        NID_id_it_signKeyPairTypes,
        SEQ_OF_OPT,
        c"infoValue.signKeyPairTypes",
        X509_ALGOR_it,
    ),
    itav_entry(
        NID_id_it_encKeyPairTypes,
        SEQ_OF_OPT,
        c"infoValue.encKeyPairTypes",
        X509_ALGOR_it,
    ),
    itav_entry(
        NID_id_it_preferredSymmAlg,
        OPT,
        c"infoValue.preferredSymmAlg",
        X509_ALGOR_it,
    ),
    itav_entry(
        NID_id_it_caKeyUpdateInfo,
        OPT,
        c"infoValue.caKeyUpdateInfo",
        cakeyupdanncontent_it,
    ),
    itav_entry(
        NID_id_it_currentCRL,
        OPT,
        c"infoValue.currentCRL",
        X509_CRL_it,
    ),
    itav_entry(
        NID_id_it_unsupportedOIDs,
        SEQ_OF_OPT,
        c"infoValue.unsupportedOIDs",
        ASN1_OBJECT_it,
    ),
    itav_entry(
        NID_id_it_keyPairParamReq,
        OPT,
        c"infoValue.keyPairParamReq",
        ASN1_OBJECT_it,
    ),
    itav_entry(
        NID_id_it_keyPairParamRep,
        OPT,
        c"infoValue.keyPairParamRep",
        X509_ALGOR_it,
    ),
    itav_entry(
        NID_id_it_revPassphrase,
        OPT,
        c"infoValue.revPassphrase",
        OSSL_CRMF_ENCRYPTEDVALUE_it,
    ),
    itav_entry(
        NID_id_it_implicitConfirm,
        OPT,
        c"infoValue.implicitConfirm",
        ASN1_NULL_it,
    ),
    itav_entry(
        NID_id_it_confirmWaitTime,
        OPT,
        c"infoValue.confirmWaitTime",
        ASN1_GENERALIZEDTIME_it,
    ),
    itav_entry(
        NID_id_it_origPKIMessage,
        OPT,
        c"infoValue.origPKIMessage",
        msgs_it,
    ),
    itav_entry(
        NID_id_it_suppLangTags,
        SEQ_OF_OPT,
        c"infoValue.suppLangTagsValue",
        ASN1_UTF8STRING_it,
    ),
    itav_entry(NID_id_it_caCerts, SEQ_OF_OPT, c"infoValue.caCerts", X509_it),
    itav_entry(NID_id_it_rootCaCert, OPT, c"infoValue.rootCaCert", X509_it),
    itav_entry(
        NID_id_it_rootCaKeyUpdate,
        OPT,
        c"infoValue.rootCaKeyUpdate",
        rootcakeyupdate_it,
    ),
    itav_entry(
        NID_id_it_certReqTemplate,
        OPT,
        c"infoValue.certReqTemplate",
        certreqtemplate_it,
    ),
    itav_entry(
        NID_id_it_certProfile,
        SEQ_OF_OPT,
        c"infoValue.certProfile",
        ASN1_UTF8STRING_it,
    ),
    itav_entry(
        NID_id_it_crlStatusList,
        SEQ_OF_OPT,
        c"infoValue.crlStatusList",
        crlstatus_it,
    ),
    itav_entry(NID_id_it_crls, SEQ_OF_OPT, c"infoValue.crls", X509_CRL_it),
]);

static ITAV_ADB: crate::asn1::tpl::statics::Adb =
    adb_oid(offset_of!(Itav, infoType), &ITAV_ADB_TBL, &ITAV_DEFAULT);

/// The ANY DEFINED BY table, as an ADB template's item function returns it.
unsafe extern "C" fn itav_adb() -> *const ASN1_ITEM {
    (&raw const ITAV_ADB.0).cast()
}

static ITAV_TT: Templates<2> = Templates([
    template_at(
        SIMPLE,
        0,
        offset_of!(Itav, infoType),
        c"infoType",
        ASN1_OBJECT_it,
    ),
    adb_object(c"OSSL_CMP_ITAV", itav_adb),
]);

static ROOTCAKEYUPDATE_TT: Templates<3> = tt![RootCaKeyUpdate;
    SIMPLE, 0, newWithNew, c"newWithNew", X509_it;
    EXP_OPT, 0, newWithOld, c"newWithOld", X509_it;
    EXP_OPT, 1, oldWithNew, c"oldWithNew", X509_it;
];

static ATAVS_T: Template = template(SEQ_OF, 0, c"OSSL_CMP_ATAVS", attribute_type_and_value_it);

static CERTREQTEMPLATE_TT: Templates<2> = tt![CertReqTemplate;
    SIMPLE, 0, certTemplate, c"certTemplate", OSSL_CRMF_CERTTEMPLATE_it;
    SEQ_OF_OPT, 0, keySpec, c"keySpec", attribute_type_and_value_it;
];

static CRLSOURCE_TT: Templates<2> = ct![
    EXP, 0, c"value.dpn", DIST_POINT_NAME_it;
    EXP, 1, c"value.issuer", GENERAL_NAMES_it;
];

static CRLSTATUS_TT: Templates<2> = tt![CrlStatus;
    SIMPLE, 0, source, c"source", crlsource_it;
    OPT, 0, thisUpdate, c"thisUpdate", ASN1_TIME_it;
];

static CERTORENCCERT_TT: Templates<2> = ct![
    EXP, 0, c"value.certificate", X509_it;
    EXP, 1, c"value.encryptedCert", OSSL_CRMF_ENCRYPTEDKEY_it;
];

static CERTIFIEDKEYPAIR_TT: Templates<3> = tt![CertifiedKeyPair;
    SIMPLE, 0, certOrEncCert, c"certOrEncCert", certorenccert_it;
    EXP_OPT, 0, privateKey, c"privateKey", OSSL_CRMF_ENCRYPTEDKEY_it;
    EXP_OPT, 1, publicationInfo, c"publicationInfo", OSSL_CRMF_PKIPUBLICATIONINFO_it;
];

static REVDETAILS_TT: Templates<2> = tt![RevDetails;
    SIMPLE, 0, certDetails, c"certDetails", OSSL_CRMF_CERTTEMPLATE_it;
    OPT, 0, crlEntryDetails, c"crlEntryDetails", X509_EXTENSIONS_it;
];

static REVREQCONTENT_T: Template = template(SEQ_OF, 0, c"OSSL_CMP_REVREQCONTENT", revdetails_it);

static REVREPCONTENT_TT: Templates<3> = tt![RevRepContent;
    SEQ_OF, 0, status, c"status", OSSL_CMP_PKISI_it;
    EXP_SEQ_OF_OPT, 0, revCerts, c"revCerts", OSSL_CRMF_CERTID_it;
    EXP_SEQ_OF_OPT, 1, crls, c"crls", X509_CRL_it;
];

static KEYRECREPCONTENT_TT: Templates<4> = tt![KeyRecRepContent;
    SIMPLE, 0, status, c"status", OSSL_CMP_PKISI_it;
    EXP_OPT, 0, newSigCert, c"newSigCert", X509_it;
    EXP_SEQ_OF_OPT, 1, caCerts, c"caCerts", X509_it;
    EXP_SEQ_OF_OPT, 2, keyPairHist, c"keyPairHist", certifiedkeypair_it;
];

static PKISTATUS_T: Template = template(ASN1_TFLG_UNIVERSAL, 0, c"status", ASN1_INTEGER_it);

static PKISI_TT: Templates<3> = tt![PkiSi;
    SIMPLE, 0, status, c"status", OSSL_CMP_PKISTATUS_it;
    SEQ_OF_OPT, 0, statusString, c"statusString", ASN1_UTF8STRING_it;
    OPT, 0, failInfo, c"failInfo", ASN1_BIT_STRING_it;
];

static CERTSTATUS_TT: Templates<4> = tt![CertStatus;
    SIMPLE, 0, certHash, c"certHash", ASN1_OCTET_STRING_it;
    SIMPLE, 0, certReqId, c"certReqId", ASN1_INTEGER_it;
    OPT, 0, statusInfo, c"statusInfo", OSSL_CMP_PKISI_it;
    EXP_OPT, 0, hashAlg, c"hashAlg", X509_ALGOR_it;
];

static CERTCONFIRMCONTENT_T: Template =
    template(SEQ_OF, 0, c"OSSL_CMP_CERTCONFIRMCONTENT", certstatus_it);

static CERTRESPONSE_TT: Templates<4> = tt![CertResponse;
    SIMPLE, 0, certReqId, c"certReqId", ASN1_INTEGER_it;
    SIMPLE, 0, status, c"status", OSSL_CMP_PKISI_it;
    OPT, 0, certifiedKeyPair, c"certifiedKeyPair", certifiedkeypair_it;
    OPT, 0, rspInfo, c"rspInfo", ASN1_OCTET_STRING_it;
];

static POLLREQ_TT: Templates<1> = tt![PollReq;
    SIMPLE, 0, certReqId, c"certReqId", ASN1_INTEGER_it;
];

static POLLREQCONTENT_T: Template = template(SEQ_OF, 0, c"OSSL_CMP_POLLREQCONTENT", pollreq_it);

static POLLREP_TT: Templates<3> = tt![PollRep;
    SIMPLE, 0, certReqId, c"certReqId", ASN1_INTEGER_it;
    SIMPLE, 0, checkAfter, c"checkAfter", ASN1_INTEGER_it;
    SEQ_OF_OPT, 0, reason, c"reason", ASN1_UTF8STRING_it;
];

static POLLREPCONTENT_T: Template = template(SEQ_OF, 0, c"OSSL_CMP_POLLREPCONTENT", pollrep_it);

static CERTREPMESSAGE_TT: Templates<2> = tt![CertRepMessage;
    EXP_SEQ_OF_OPT, 1, caPubs, c"caPubs", X509_it;
    SEQ_OF, 0, response, c"response", certresponse_it;
];

static GENMSGCONTENT_T: Template = template(SEQ_OF, 0, c"OSSL_CMP_GENMSGCONTENT", itav_it);
static GENREPCONTENT_T: Template = template(SEQ_OF, 0, c"OSSL_CMP_GENREPCONTENT", itav_it);
static CRLANNCONTENT_T: Template = template(SEQ_OF, 0, c"OSSL_CMP_CRLANNCONTENT", X509_CRL_it);

static PKIBODY_TT: Templates<27> = ct![
    EXP, 0, c"value.ir", OSSL_CRMF_MSGS_it;
    EXP, 1, c"value.ip", certrepmessage_it;
    EXP, 2, c"value.cr", OSSL_CRMF_MSGS_it;
    EXP, 3, c"value.cp", certrepmessage_it;
    EXP, 4, c"value.p10cr", X509_REQ_it;
    EXP, 5, c"value.popdecc", popodeckeychallcontent_it;
    EXP, 6, c"value.popdecr", popodeckeyrespcontent_it;
    EXP, 7, c"value.kur", OSSL_CRMF_MSGS_it;
    EXP, 8, c"value.kup", certrepmessage_it;
    EXP, 9, c"value.krr", OSSL_CRMF_MSGS_it;
    EXP, 10, c"value.krp", keyrecrepcontent_it;
    EXP, 11, c"value.rr", revreqcontent_it;
    EXP, 12, c"value.rp", revrepcontent_it;
    EXP, 13, c"value.ccr", OSSL_CRMF_MSGS_it;
    EXP, 14, c"value.ccp", certrepmessage_it;
    EXP, 15, c"value.ckuann", cakeyupdanncontent_it;
    EXP, 16, c"value.cann", X509_it;
    EXP, 17, c"value.rann", revanncontent_it;
    EXP, 18, c"value.crlann", crlanncontent_it;
    EXP, 19, c"value.pkiconf", ASN1_ANY_it;
    EXP, 20, c"value.nested", msgs_it;
    EXP, 21, c"value.genm", genmsgcontent_it;
    EXP, 22, c"value.genp", genrepcontent_it;
    EXP, 23, c"value.error", errormsgcontent_it;
    EXP, 24, c"value.certConf", certconfirmcontent_it;
    EXP, 25, c"value.pollReq", pollreqcontent_it;
    EXP, 26, c"value.pollRep", pollrepcontent_it;
];

static PKIHEADER_TT: Templates<12> = tt![PkiHeader;
    SIMPLE, 0, pvno, c"pvno", ASN1_INTEGER_it;
    SIMPLE, 0, sender, c"sender", GENERAL_NAME_it;
    SIMPLE, 0, recipient, c"recipient", GENERAL_NAME_it;
    EXP_OPT, 0, messageTime, c"messageTime", ASN1_GENERALIZEDTIME_it;
    EXP_OPT, 1, protectionAlg, c"protectionAlg", X509_ALGOR_it;
    EXP_OPT, 2, senderKID, c"senderKID", ASN1_OCTET_STRING_it;
    EXP_OPT, 3, recipKID, c"recipKID", ASN1_OCTET_STRING_it;
    EXP_OPT, 4, transactionID, c"transactionID", ASN1_OCTET_STRING_it;
    EXP_OPT, 5, senderNonce, c"senderNonce", ASN1_OCTET_STRING_it;
    EXP_OPT, 6, recipNonce, c"recipNonce", ASN1_OCTET_STRING_it;
    EXP_SEQ_OF_OPT, 7, freeText, c"freeText", ASN1_UTF8STRING_it;
    EXP_SEQ_OF_OPT, 8, generalInfo, c"generalInfo", itav_it;
];

static PROTECTEDPART_TT: Templates<2> = tt![ProtectedPart;
    SIMPLE, 0, header, c"header", OSSL_CMP_PKIHEADER_it;
    SIMPLE, 0, body, c"body", pkibody_it;
];

static MSG_TT: Templates<4> = tt![Msg;
    SIMPLE, 0, header, c"header", OSSL_CMP_PKIHEADER_it;
    SIMPLE, 0, body, c"body", pkibody_it;
    EXP_OPT, 0, protection, c"protection", ASN1_BIT_STRING_it;
    EXP_SEQ_OF_OPT, 1, extraCerts, c"extraCerts", X509_it;
];

static MSG_AUX: Aux = aux(msg_cb);

ffi_callback! {
    /// `ossl_cmp_msg_cb`: freeing a message frees its properties; a copy takes the original's
    /// library context and its own copy of the properties; the library context and the
    /// properties are given to the decoder and encoder.
    ///
    /// # Safety
    /// `pval` holds NULL or a live message; `exarg` is the operation's.
    pub(crate) unsafe extern "C" fn msg_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let v = unsafe { pval.read() };
        // SAFETY: as above.
        let Some(m) = (unsafe { v.cast::<Msg>().as_mut() }) else { return 1 };
        match operation {
            ASN1_OP_FREE_POST => {
                // SAFETY: its own copy, or NULL.
                unsafe { mem::release(m.propq.cast()) };
                m.propq = ptr::null_mut();
                1
            }
            ASN1_OP_DUP_POST => {
                // SAFETY: the original, which the copy was made from.
                let Some(old) = (unsafe { exarg.cast::<Msg>().as_ref() }) else { return 1 };
                // The copy is decoded afresh, with no properties of its own yet.
                // SAFETY: the copy; the original's library context and properties.
                c_int::from(unsafe { super::msg::msg_set0_libctx(ptr::from_mut(m).cast(), old.libctx, old.propq) } != 0)
            }
            ASN1_OP_GET0_LIBCTX => {
                // SAFETY: the operation's output.
                unsafe { exarg.cast::<*mut OSSL_LIB_CTX>().write(m.libctx) };
                1
            }
            ASN1_OP_GET0_PROPQ => {
                // SAFETY: as above.
                unsafe { exarg.cast::<*const c_char>().write(m.propq) };
                1
            }
            _ => 1,
        }
    }
}

static MSGS_T: Template = template(SEQ_OF, 0, c"OSSL_CMP_MSGS", OSSL_CMP_MSG_it);

macro_rules! private_item {
    ($($(#[$attr:meta])* fn $name:ident = $item:expr;)*) => {$(
        $(#[$attr])*
        pub(crate) unsafe extern "C" fn $name() -> *const ASN1_ITEM {
            static ITEM: Item = $item;
            &raw const ITEM.0
        }
    )*};
}

/// An item of one template (`ASN1_ITEM_TEMPLATE`), such as a SEQUENCE OF.
const fn template_item(t: &'static Template, name: &'static core::ffi::CStr) -> Item {
    item(
        ASN1_ITYPE_PRIMITIVE,
        -1,
        &raw const t.0,
        0,
        ptr::null(),
        0,
        name,
    )
}

private_item! {
    /// `OSSL_CMP_REVANNCONTENT_it`.
    fn revanncontent_it = sequence::<RevAnnContent, 5>(&REVANNCONTENT_TT, None, c"OSSL_CMP_REVANNCONTENT");
    /// `OSSL_CMP_CHALLENGE_it`.
    fn challenge_it = sequence::<Challenge, 3>(&CHALLENGE_TT, None, c"OSSL_CMP_CHALLENGE");
    /// `OSSL_CMP_POPODECKEYCHALLCONTENT_it`.
    fn popodeckeychallcontent_it = template_item(&POPODECKEYCHALLCONTENT_T, c"OSSL_CMP_POPODECKEYCHALLCONTENT");
    /// `OSSL_CMP_POPODECKEYRESPCONTENT_it`.
    fn popodeckeyrespcontent_it = template_item(&POPODECKEYRESPCONTENT_T, c"OSSL_CMP_POPODECKEYRESPCONTENT");
    /// `OSSL_CMP_CAKEYUPDANNCONTENT_it`.
    fn cakeyupdanncontent_it = sequence::<CaKeyUpdAnnContent, 3>(&CAKEYUPDANNCONTENT_TT, None, c"OSSL_CMP_CAKEYUPDANNCONTENT");
    /// `OSSL_CMP_ERRORMSGCONTENT_it`.
    fn errormsgcontent_it = sequence::<ErrorMsgContent, 3>(&ERRORMSGCONTENT_TT, None, c"OSSL_CMP_ERRORMSGCONTENT");
    /// `OSSL_CMP_ITAV_it`.
    fn itav_it = sequence::<Itav, 2>(&ITAV_TT, None, c"OSSL_CMP_ITAV");
    /// `OSSL_CMP_ROOTCAKEYUPDATE_it`.
    fn rootcakeyupdate_it = sequence::<RootCaKeyUpdate, 3>(&ROOTCAKEYUPDATE_TT, None, c"OSSL_CMP_ROOTCAKEYUPDATE");
    /// `OSSL_CMP_CERTREQTEMPLATE_it`.
    fn certreqtemplate_it = sequence::<CertReqTemplate, 2>(&CERTREQTEMPLATE_TT, None, c"OSSL_CMP_CERTREQTEMPLATE");
    /// `OSSL_CMP_CRLSOURCE_it`.
    fn crlsource_it = choice::<Choice, 2>(&CRLSOURCE_TT, SELECTOR, None, c"OSSL_CMP_CRLSOURCE");
    /// `OSSL_CMP_CRLSTATUS_it`.
    fn crlstatus_it = sequence::<CrlStatus, 2>(&CRLSTATUS_TT, None, c"OSSL_CMP_CRLSTATUS");
    /// `OSSL_CMP_CERTORENCCERT_it`.
    fn certorenccert_it = choice::<Choice, 2>(&CERTORENCCERT_TT, SELECTOR, None, c"OSSL_CMP_CERTORENCCERT");
    /// `OSSL_CMP_CERTIFIEDKEYPAIR_it`.
    fn certifiedkeypair_it = sequence::<CertifiedKeyPair, 3>(&CERTIFIEDKEYPAIR_TT, None, c"OSSL_CMP_CERTIFIEDKEYPAIR");
    /// `OSSL_CMP_REVDETAILS_it`.
    fn revdetails_it = sequence::<RevDetails, 2>(&REVDETAILS_TT, None, c"OSSL_CMP_REVDETAILS");
    /// `OSSL_CMP_REVREQCONTENT_it`.
    fn revreqcontent_it = template_item(&REVREQCONTENT_T, c"OSSL_CMP_REVREQCONTENT");
    /// `OSSL_CMP_REVREPCONTENT_it`.
    fn revrepcontent_it = sequence::<RevRepContent, 3>(&REVREPCONTENT_TT, None, c"OSSL_CMP_REVREPCONTENT");
    /// `OSSL_CMP_KEYRECREPCONTENT_it`.
    fn keyrecrepcontent_it = sequence::<KeyRecRepContent, 4>(&KEYRECREPCONTENT_TT, None, c"OSSL_CMP_KEYRECREPCONTENT");
    /// `OSSL_CMP_CERTSTATUS_it`.
    fn certstatus_it = sequence::<CertStatus, 4>(&CERTSTATUS_TT, None, c"OSSL_CMP_CERTSTATUS");
    /// `OSSL_CMP_CERTCONFIRMCONTENT_it`.
    fn certconfirmcontent_it = template_item(&CERTCONFIRMCONTENT_T, c"OSSL_CMP_CERTCONFIRMCONTENT");
    /// `OSSL_CMP_CERTRESPONSE_it`.
    fn certresponse_it = sequence::<CertResponse, 4>(&CERTRESPONSE_TT, None, c"OSSL_CMP_CERTRESPONSE");
    /// `OSSL_CMP_POLLREQ_it`.
    fn pollreq_it = sequence::<PollReq, 1>(&POLLREQ_TT, None, c"OSSL_CMP_POLLREQ");
    /// `OSSL_CMP_POLLREQCONTENT_it`.
    fn pollreqcontent_it = template_item(&POLLREQCONTENT_T, c"OSSL_CMP_POLLREQCONTENT");
    /// `OSSL_CMP_POLLREP_it`.
    fn pollrep_it = sequence::<PollRep, 3>(&POLLREP_TT, None, c"OSSL_CMP_POLLREP");
    /// `OSSL_CMP_POLLREPCONTENT_it`.
    fn pollrepcontent_it = template_item(&POLLREPCONTENT_T, c"OSSL_CMP_POLLREPCONTENT");
    /// `OSSL_CMP_CERTREPMESSAGE_it`.
    fn certrepmessage_it = sequence::<CertRepMessage, 2>(&CERTREPMESSAGE_TT, None, c"OSSL_CMP_CERTREPMESSAGE");
    /// `OSSL_CMP_GENMSGCONTENT_it`.
    fn genmsgcontent_it = template_item(&GENMSGCONTENT_T, c"OSSL_CMP_GENMSGCONTENT");
    /// `OSSL_CMP_GENREPCONTENT_it`.
    fn genrepcontent_it = template_item(&GENREPCONTENT_T, c"OSSL_CMP_GENREPCONTENT");
    /// `OSSL_CMP_CRLANNCONTENT_it`.
    fn crlanncontent_it = template_item(&CRLANNCONTENT_T, c"OSSL_CMP_CRLANNCONTENT");
    /// `OSSL_CMP_PKIBODY_it`.
    fn pkibody_it = choice::<Choice, 27>(&PKIBODY_TT, SELECTOR, None, c"OSSL_CMP_PKIBODY");
    /// `OSSL_CMP_PROTECTEDPART_it`.
    fn protectedpart_it = sequence::<ProtectedPart, 2>(&PROTECTEDPART_TT, None, c"OSSL_CMP_PROTECTEDPART");
    /// `OSSL_CMP_MSGS_it`.
    fn msgs_it = template_item(&MSGS_T, c"OSSL_CMP_MSGS");
}

item_fns! {
    /// Controls: SEQUENCE OF AttributeTypeAndValue.
    pub unsafe extern "C" fn OSSL_CMP_ATAVS_it = template_item(&ATAVS_T, c"OSSL_CMP_ATAVS");
    /// PKIStatus: an INTEGER.
    pub unsafe extern "C" fn OSSL_CMP_PKISTATUS_it = template_item(&PKISTATUS_T, c"OSSL_CMP_PKISTATUS");
    /// PKIStatusInfo.
    pub unsafe extern "C" fn OSSL_CMP_PKISI_it = sequence::<PkiSi, 3>(&PKISI_TT, None, c"OSSL_CMP_PKISI");
    /// PKIHeader.
    pub unsafe extern "C" fn OSSL_CMP_PKIHEADER_it = sequence::<PkiHeader, 12>(&PKIHEADER_TT, None, c"OSSL_CMP_PKIHEADER");
    /// PKIMessage, which keeps its library context and properties.
    pub unsafe extern "C" fn OSSL_CMP_MSG_it = sequence::<Msg, 4>(&MSG_TT, Some(&MSG_AUX), c"OSSL_CMP_MSG");
}

new_free! {
    pub unsafe extern "C" fn OSSL_CMP_ATAVS_new, pub unsafe extern "C" fn OSSL_CMP_ATAVS_free(rustyssl_abi::OSSL_CMP_ATAVS) = OSSL_CMP_ATAVS_it;
    pub unsafe extern "C" fn OSSL_CMP_PKISI_new, pub unsafe extern "C" fn OSSL_CMP_PKISI_free(rustyssl_abi::OSSL_CMP_PKISI) = OSSL_CMP_PKISI_it;
    pub unsafe extern "C" fn OSSL_CMP_PKIHEADER_new, pub unsafe extern "C" fn OSSL_CMP_PKIHEADER_free(rustyssl_abi::OSSL_CMP_PKIHEADER) = OSSL_CMP_PKIHEADER_it;
}

i2d! {
    /// Encodes a OSSL_CMP_ATAVS.
    pub unsafe extern "C" fn i2d_OSSL_CMP_ATAVS(rustyssl_abi::OSSL_CMP_ATAVS) = OSSL_CMP_ATAVS_it;
    /// Encodes a OSSL_CMP_PKISI.
    pub unsafe extern "C" fn i2d_OSSL_CMP_PKISI(rustyssl_abi::OSSL_CMP_PKISI) = OSSL_CMP_PKISI_it;
    /// Encodes a OSSL_CMP_PKIHEADER.
    pub unsafe extern "C" fn i2d_OSSL_CMP_PKIHEADER(rustyssl_abi::OSSL_CMP_PKIHEADER) = OSSL_CMP_PKIHEADER_it;
}

d2i! {
    /// Decodes a OSSL_CMP_ATAVS.
    pub unsafe extern "C" fn d2i_OSSL_CMP_ATAVS(rustyssl_abi::OSSL_CMP_ATAVS) = OSSL_CMP_ATAVS_it;
    /// Decodes a OSSL_CMP_PKISI.
    pub unsafe extern "C" fn d2i_OSSL_CMP_PKISI(rustyssl_abi::OSSL_CMP_PKISI) = OSSL_CMP_PKISI_it;
    /// Decodes a OSSL_CMP_PKIHEADER.
    pub unsafe extern "C" fn d2i_OSSL_CMP_PKIHEADER(rustyssl_abi::OSSL_CMP_PKIHEADER) = OSSL_CMP_PKIHEADER_it;
}

ffi_export! {
    /// A copy of the PKIStatusInfo, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live value.
    pub unsafe extern "C" fn OSSL_CMP_PKISI_dup(a: *const rustyssl_abi::OSSL_CMP_PKISI) -> *mut rustyssl_abi::OSSL_CMP_PKISI
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup_of(a.cast(), OSSL_CMP_PKISI_it) }.cast()
    }
}

ffi_export! {
    /// A copy of the message (with its library context and properties), or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live message.
    pub unsafe extern "C" fn OSSL_CMP_MSG_dup(a: *const OSSL_CMP_MSG) -> *mut OSSL_CMP_MSG
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup_of(a.cast(), OSSL_CMP_MSG_it) }.cast()
    }
}

/// `OSSL_CMP_ITAV_new`, which OpenSSL doesn't export: an empty InfoTypeAndValue, or NULL.
pub(crate) fn itav_new() -> *mut OSSL_CMP_ITAV {
    new_of(itav_it).cast()
}

ffi_export! {
    /// Frees the InfoTypeAndValue (nothing for NULL).
    ///
    /// # Safety
    /// `a` is NULL or a live value, not used after.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_free(a: *mut OSSL_CMP_ITAV)
    where failure = (), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        unsafe { free_of(a.cast(), itav_it) };
    }
}

ffi_export! {
    /// A copy of the InfoTypeAndValue, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live value.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_dup(a: *const OSSL_CMP_ITAV) -> *mut OSSL_CMP_ITAV
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup_of(a.cast(), itav_it) }.cast()
    }
}

ffi_export! {
    /// Frees the CRL status (nothing for NULL).
    ///
    /// # Safety
    /// `a` is NULL or a live value, not used after.
    pub unsafe extern "C" fn OSSL_CMP_CRLSTATUS_free(a: *mut OSSL_CMP_CRLSTATUS)
    where failure = (), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        unsafe { free_of(a.cast(), crlstatus_it) };
    }
}

/// The InfoTypeAndValue behind a handle.
///
/// # Safety
/// `p` is NULL or a live InfoTypeAndValue.
unsafe fn itav_of<'a>(p: *const OSSL_CMP_ITAV) -> Option<&'a mut Itav> {
    // SAFETY: the caller's guarantee.
    unsafe { of::<Itav, _>(p) }
}

/// The object of a NID (a static one, or NULL).
fn nid_obj(nid: c_int) -> *mut ASN1_OBJECT {
    // SAFETY: no preconditions.
    unsafe { OBJ_nid2obj(nid) }
}

/// The NID of an object, or `NID_undef`.
///
/// # Safety
/// `o` is NULL or a live object.
unsafe fn obj_nid(o: *const ASN1_OBJECT) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { OBJ_obj2nid(o) }
}

ffi_export! {
    /// A new InfoTypeAndValue of `type_` and `value`, which it takes; NULL if `type_` is NULL.
    ///
    /// # Safety
    /// `type_` is NULL or a live object; `value` NULL or a live value; both owned by the caller.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_create(type_: *mut ASN1_OBJECT, value: *mut ASN1_TYPE) -> *mut OSSL_CMP_ITAV
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        if type_.is_null() {
            return ptr::null_mut();
        }
        let itav = itav_new();
        if itav.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: made here; the caller's objects.
        unsafe { OSSL_CMP_ITAV_set0(itav, type_, value) };
        itav
    }
}

ffi_export! {
    /// Sets the InfoTypeAndValue's type and value, which it takes (without freeing what it held).
    ///
    /// # Safety
    /// `itav` is a live value (as in OpenSSL, NULL crashes); `type_` and `value` NULL or live.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_set0(itav: *mut OSSL_CMP_ITAV, type_: *mut ASN1_OBJECT, value: *mut ASN1_TYPE)
    where failure = (), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { itav_of(itav) }) else { return };
        i.infoType = type_;
        i.infoValue = value.cast();
    }
}

ffi_export! {
    /// The InfoTypeAndValue's type, or NULL.
    ///
    /// # Safety
    /// `itav` is NULL or a live value.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_get0_type(itav: *const OSSL_CMP_ITAV) -> *mut ASN1_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        unsafe { itav_of(itav) }.map_or(ptr::null_mut(), |i| i.infoType)
    }
}

ffi_export! {
    /// The InfoTypeAndValue's value (as an ASN1_TYPE), or NULL.
    ///
    /// # Safety
    /// `itav` is NULL or a live value.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_get0_value(itav: *const OSSL_CMP_ITAV) -> *mut ASN1_TYPE
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        unsafe { itav_of(itav) }.map_or(ptr::null_mut(), |i| i.infoValue.cast())
    }
}

/// Pushes `item` onto the list in `*slot`, made if need be (and freed again on failure); 1 or 0.
///
/// # Safety
/// `slot` is a live slot holding NULL or a live list; `item` a live value.
unsafe fn push0_made(slot: *mut *mut Stack, item: *const c_void) -> c_int {
    // SAFETY: the caller's guarantee.
    let created = unsafe { slot.read() }.is_null();
    if created {
        // SAFETY: no preconditions.
        let sk = unsafe { OPENSSL_sk_new_null() };
        if sk.is_null() {
            return 0;
        }
        // SAFETY: the caller's slot.
        unsafe { slot.write(sk) };
    }
    // SAFETY: the caller's slot, holding the list now.
    let sk = unsafe { slot.read() };
    // SAFETY: the list; the item.
    if unsafe { OPENSSL_sk_push(sk, item) } != 0 {
        return 1;
    }
    if created {
        // SAFETY: the list made here.
        unsafe { OPENSSL_sk_free(sk) };
        // SAFETY: the caller's slot.
        unsafe { slot.write(ptr::null_mut()) };
    }
    0
}

ffi_export! {
    /// Pushes `itav` (taken) onto the list in `*itav_sk_p`, made if need be: 1, or 0.
    ///
    /// # Safety
    /// `itav_sk_p` is NULL or a live slot holding NULL or a live list; `itav` NULL or live.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_push0_stack_item(itav_sk_p: *mut *mut rustyssl_abi::stack_st_OSSL_CMP_ITAV, itav: *mut OSSL_CMP_ITAV) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        if itav_sk_p.is_null() || itav.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, "OSSL_CMP_ITAV_push0_stack_item");
            return 0;
        }
        // SAFETY: the caller's slot and value.
        unsafe { push0_made(itav_sk_p.cast(), itav.cast()) }
    }
}

/// A new InfoTypeAndValue of `nid` holding `value` (taken), or NULL.
fn itav_new_of(nid: c_int, value: *mut c_void) -> *mut OSSL_CMP_ITAV {
    let itav = itav_new();
    // SAFETY: made here, or NULL.
    if let Some(i) = unsafe { itav_of(itav) } {
        i.infoType = nid_obj(nid);
        i.infoValue = value;
    }
    itav
}

/// The InfoTypeAndValue if it is of `nid`, raising OpenSSL's errors otherwise: NULL arguments
/// (`ERR_R_PASSED_NULL_PARAMETER`), another type (`ERR_R_PASSED_INVALID_ARGUMENT`).
///
/// # Safety
/// `itav` is NULL or a live value.
unsafe fn itav_typed<'a>(
    itav: *const OSSL_CMP_ITAV,
    out_null: bool,
    nid: c_int,
    f: &str,
) -> Option<&'a Itav> {
    // SAFETY: the caller's guarantee.
    let Some(i) = (unsafe { itav_of(itav) }) else {
        err::raise(ERR_LIB_CMP, ERR_R_PASSED_NULL_PARAMETER, f);
        return None;
    };
    if out_null {
        err::raise(ERR_LIB_CMP, ERR_R_PASSED_NULL_PARAMETER, f);
        return None;
    }
    // SAFETY: its type.
    if unsafe { obj_nid(i.infoType) } != nid {
        err::raise(ERR_LIB_CMP, ERR_R_PASSED_INVALID_ARGUMENT, f);
        return None;
    }
    Some(i)
}

ffi_export! {
    /// A new `id-it-certProfile` InfoTypeAndValue of the profile names (taken), or NULL.
    ///
    /// # Safety
    /// `certProfile` is NULL or a live list of UTF8Strings.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_new0_certProfile(certProfile: *mut rustyssl_abi::stack_st_ASN1_UTF8STRING) -> *mut OSSL_CMP_ITAV
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        itav_new_of(NID_id_it_certProfile, certProfile.cast())
    }
}

ffi_export! {
    /// The profile names of an `id-it-certProfile` InfoTypeAndValue in `*out`: 1, or 0.
    ///
    /// # Safety
    /// `itav` is NULL or a live value; `out` NULL or a slot.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_get0_certProfile(itav: *const OSSL_CMP_ITAV, out: *mut *mut rustyssl_abi::stack_st_ASN1_UTF8STRING) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { itav_typed(itav, out.is_null(), NID_id_it_certProfile, "OSSL_CMP_ITAV_get0_certProfile") }) else { return 0 };
        // SAFETY: the caller's slot.
        unsafe { out.write(i.infoValue.cast()) };
        1
    }
}

/// `X509_dup` as a stack's copy function.
unsafe extern "C" fn x509_copy(p: *const c_void) -> *mut c_void {
    // SAFETY: a certificate of the stack.
    unsafe { X509_dup(p.cast()) }.cast()
}

/// `X509_free` as a stack's free function.
unsafe extern "C" fn x509_free(p: *mut c_void) {
    // SAFETY: a certificate of the stack, which the stack owned.
    unsafe { X509_free(p.cast()) };
}

ffi_export! {
    /// A new `id-it-caCerts` InfoTypeAndValue with copies of the certificates (none if the list
    /// is NULL or empty), or NULL.
    ///
    /// # Safety
    /// `caCerts` is NULL or a live list of certificates.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_new_caCerts(caCerts: *const rustyssl_abi::stack_st_X509) -> *mut OSSL_CMP_ITAV
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        let itav = itav_new();
        // SAFETY: made here, or NULL.
        let Some(i) = (unsafe { itav_of(itav) }) else { return ptr::null_mut() };
        // SAFETY: the caller's list, or NULL (-1).
        if unsafe { OPENSSL_sk_num(caCerts.cast()) } > 0 {
            // SAFETY: as above, with the certificates' copy and free functions.
            let copy = unsafe { OPENSSL_sk_deep_copy(caCerts.cast(), Some(x509_copy), Some(x509_free)) };
            if copy.is_null() {
                // SAFETY: made here.
                unsafe { OSSL_CMP_ITAV_free(itav) };
                return ptr::null_mut();
            }
            i.infoValue = copy.cast();
        }
        i.infoType = nid_obj(NID_id_it_caCerts);
        itav
    }
}

ffi_export! {
    /// The certificates of an `id-it-caCerts` InfoTypeAndValue in `*out` (NULL if none): 1, or 0.
    ///
    /// # Safety
    /// `itav` is NULL or a live value; `out` NULL or a slot.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_get0_caCerts(itav: *const OSSL_CMP_ITAV, out: *mut *mut rustyssl_abi::stack_st_X509) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { itav_typed(itav, out.is_null(), NID_id_it_caCerts, "OSSL_CMP_ITAV_get0_caCerts") }) else { return 0 };
        let certs: *mut Stack = i.infoValue.cast();
        // SAFETY: its list, or NULL (-1).
        let v = if unsafe { OPENSSL_sk_num(certs) } > 0 { certs } else { ptr::null_mut() };
        // SAFETY: the caller's slot.
        unsafe { out.write(v.cast()) };
        1
    }
}

/// A copy of a certificate in `*slot` if `x` isn't NULL: false if copying failed.
///
/// # Safety
/// `x` is NULL or a live certificate.
unsafe fn dup_cert(slot: &mut *mut X509, x: *const X509) -> bool {
    if x.is_null() {
        return true;
    }
    // SAFETY: the caller's certificate.
    *slot = unsafe { X509_dup(x) };
    !slot.is_null()
}

ffi_export! {
    /// A new `id-it-rootCaCert` InfoTypeAndValue with a copy of the certificate (none if NULL), or
    /// NULL.
    ///
    /// # Safety
    /// `rootCaCert` is NULL or a live certificate.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_new_rootCaCert(rootCaCert: *const X509) -> *mut OSSL_CMP_ITAV
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        let itav = itav_new();
        // SAFETY: made here, or NULL.
        let Some(i) = (unsafe { itav_of(itav) }) else { return ptr::null_mut() };
        let mut x: *mut X509 = ptr::null_mut();
        // SAFETY: the caller's certificate.
        if !unsafe { dup_cert(&mut x, rootCaCert) } {
            // SAFETY: made here.
            unsafe { OSSL_CMP_ITAV_free(itav) };
            return ptr::null_mut();
        }
        i.infoValue = x.cast();
        i.infoType = nid_obj(NID_id_it_rootCaCert);
        itav
    }
}

ffi_export! {
    /// The certificate of an `id-it-rootCaCert` InfoTypeAndValue in `*out`: 1, or 0.
    ///
    /// # Safety
    /// `itav` is NULL or a live value; `out` NULL or a slot.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_get0_rootCaCert(itav: *const OSSL_CMP_ITAV, out: *mut *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { itav_typed(itav, out.is_null(), NID_id_it_rootCaCert, "OSSL_CMP_ITAV_get0_rootCaCert") }) else { return 0 };
        // SAFETY: the caller's slot.
        unsafe { out.write(i.infoValue.cast()) };
        1
    }
}

ffi_export! {
    /// A new `id-it-rootCaKeyUpdate` InfoTypeAndValue with copies of the certificates (no
    /// content if `newWithNew` is NULL), or NULL.
    ///
    /// # Safety
    /// Each certificate is NULL or live.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_new_rootCaKeyUpdate(newWithNew: *const X509, newWithOld: *const X509, oldWithNew: *const X509) -> *mut OSSL_CMP_ITAV
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        let mut upd: *mut RootCaKeyUpdate = ptr::null_mut();
        if !newWithNew.is_null() {
            upd = new_of(rootcakeyupdate_it).cast();
            // SAFETY: made here, or NULL.
            let Some(u) = (unsafe { upd.as_mut() }) else { return ptr::null_mut() };
            // SAFETY: the caller's certificates.
            let ok = unsafe { dup_cert(&mut u.newWithNew, newWithNew) }
                // SAFETY: as above.
                && unsafe { dup_cert(&mut u.newWithOld, newWithOld) }
                // SAFETY: as above.
                && unsafe { dup_cert(&mut u.oldWithNew, oldWithNew) };
            if !ok {
                // SAFETY: made here.
                unsafe { free_of(upd.cast(), rootcakeyupdate_it) };
                return ptr::null_mut();
            }
        }
        let itav = itav_new();
        // SAFETY: made here, or NULL.
        let Some(i) = (unsafe { itav_of(itav) }) else {
            // SAFETY: made here, or NULL.
            unsafe { free_of(upd.cast(), rootcakeyupdate_it) };
            return ptr::null_mut();
        };
        i.infoType = nid_obj(NID_id_it_rootCaKeyUpdate);
        i.infoValue = upd.cast();
        itav
    }
}

ffi_export! {
    /// The certificates of an `id-it-rootCaKeyUpdate` InfoTypeAndValue (each NULL if there is no
    /// content), the last two only where their slots aren't NULL: 1, or 0.
    ///
    /// # Safety
    /// `itav` is NULL or a live value; each slot NULL or writable.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_get0_rootCaKeyUpdate(itav: *const OSSL_CMP_ITAV, newWithNew: *mut *mut X509, newWithOld: *mut *mut X509, oldWithNew: *mut *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { itav_typed(itav, newWithNew.is_null(), NID_id_it_rootCaKeyUpdate, "OSSL_CMP_ITAV_get0_rootCaKeyUpdate") }) else { return 0 };
        // SAFETY: its content, or NULL.
        let upd = unsafe { i.infoValue.cast::<RootCaKeyUpdate>().as_ref() };
        // SAFETY: the caller's slot.
        unsafe { newWithNew.write(upd.map_or(ptr::null_mut(), |u| u.newWithNew)) };
        if !newWithOld.is_null() {
            // SAFETY: as above.
            unsafe { newWithOld.write(upd.map_or(ptr::null_mut(), |u| u.newWithOld)) };
        }
        if !oldWithNew.is_null() {
            // SAFETY: as above.
            unsafe { oldWithNew.write(upd.map_or(ptr::null_mut(), |u| u.oldWithNew)) };
        }
        1
    }
}

ffi_export! {
    /// A new `id-it-certReqTemplate` InfoTypeAndValue of the template and key specification
    /// (both taken; no content without a template), or NULL; a key specification without a
    /// template is an invalid argument.
    ///
    /// # Safety
    /// `certTemplate` is NULL or a live template; `keySpec` NULL or a live list.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_new0_certReqTemplate(certTemplate: *mut OSSL_CRMF_CERTTEMPLATE, keySpec: *mut rustyssl_abi::OSSL_CMP_ATAVS) -> *mut OSSL_CMP_ITAV
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        if certTemplate.is_null() && !keySpec.is_null() {
            err::raise(ERR_LIB_CMP, ERR_R_PASSED_INVALID_ARGUMENT, "OSSL_CMP_ITAV_new0_certReqTemplate");
            return ptr::null_mut();
        }
        let itav = itav_new_of(NID_id_it_certReqTemplate, ptr::null_mut());
        if itav.is_null() || certTemplate.is_null() {
            return itav;
        }
        let tmpl: *mut CertReqTemplate = new_of(certreqtemplate_it).cast();
        // SAFETY: made here, or NULL.
        let Some(t) = (unsafe { tmpl.as_mut() }) else {
            // SAFETY: made here.
            unsafe { OSSL_CMP_ITAV_free(itav) };
            return ptr::null_mut();
        };
        // The new template comes with an empty CertTemplate, which is replaced (OpenSSL leaks
        // it; here it's freed).
        // SAFETY: the empty template made with it.
        unsafe { OSSL_CRMF_CERTTEMPLATE_free(t.certTemplate) };
        t.certTemplate = certTemplate;
        t.keySpec = keySpec.cast();
        // SAFETY: made here.
        if let Some(i) = unsafe { itav_of(itav) } {
            i.infoValue = tmpl.cast();
        }
        itav
    }
}

/// `OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free` as a stack's free function.
unsafe extern "C" fn atav_free(p: *mut c_void) {
    // SAFETY: an attribute of the stack, which the stack owned.
    unsafe { OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free(p.cast()) };
}

ffi_export! {
    /// Copies of an `id-it-certReqTemplate` InfoTypeAndValue's template in `*certTemplate` and
    /// (where `keySpec` isn't NULL) its key specification, whose entries must be `algId` or
    /// `rsaKeyLen`: 1 (both NULL if there is no content), or 0.
    ///
    /// # Safety
    /// `itav` is NULL or a live value; `certTemplate` NULL or a slot; `keySpec` NULL or a slot.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_get1_certReqTemplate(itav: *const OSSL_CMP_ITAV, certTemplate: *mut *mut OSSL_CRMF_CERTTEMPLATE, keySpec: *mut *mut rustyssl_abi::OSSL_CMP_ATAVS) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        const F: &str = "OSSL_CMP_ITAV_get1_certReqTemplate";
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { itav_of(itav) }) else {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, F);
            return 0;
        };
        if certTemplate.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, F);
            return 0;
        }
        // SAFETY: the caller's slots.
        unsafe { certTemplate.write(ptr::null_mut()) };
        if !keySpec.is_null() {
            // SAFETY: as above.
            unsafe { keySpec.write(ptr::null_mut()) };
        }
        // SAFETY: its type.
        if unsafe { obj_nid(i.infoType) } != NID_id_it_certReqTemplate {
            err::raise(ERR_LIB_CMP, ERR_R_PASSED_INVALID_ARGUMENT, F);
            return 0;
        }
        // SAFETY: its content, or NULL.
        let Some(tpl) = (unsafe { i.infoValue.cast::<CertReqTemplate>().as_ref() }) else { return 1 };
        // SAFETY: its template.
        let t = unsafe { OSSL_CRMF_CERTTEMPLATE_dup(tpl.certTemplate) };
        // SAFETY: the caller's slot.
        unsafe { certTemplate.write(t) };
        if t.is_null() {
            return 0;
        }
        if keySpec.is_null() || tpl.keySpec.is_null() {
            return 1;
        }
        // SAFETY: its list.
        let n = unsafe { OPENSSL_sk_num(tpl.keySpec) };
        // SAFETY: no preconditions.
        let list = unsafe { OPENSSL_sk_new_reserve(None, n) };
        // SAFETY: the caller's slot.
        unsafe { keySpec.write(list.cast()) };
        let ok = !list.is_null() && (0..n).all(|k| {
            // SAFETY: an index in range.
            let atav: *mut OSSL_CMP_ATAV = unsafe { OPENSSL_sk_value(tpl.keySpec, k) }.cast();
            // SAFETY: the attribute, or NULL.
            let type_ = unsafe { OSSL_CMP_ATAV_get0_type(atav) };
            if type_.is_null() {
                err::raise_with_text(ERR_LIB_CMP, CMP_R_INVALID_KEYSPEC, F, &format!("keySpec with index {k} in certReqTemplate does not exist"));
                return false;
            }
            // SAFETY: its type.
            let nid = unsafe { obj_nid(type_) };
            if nid != NID_id_regCtrl_algId && nid != NID_id_regCtrl_rsaKeyLen {
                // SAFETY: no preconditions.
                let ln = unsafe { OBJ_nid2ln(nid) };
                // SAFETY: no preconditions.
                let name = if ln.is_null() { unsafe { OBJ_nid2sn(nid) } } else { ln };
                let name = if name.is_null() {
                    "<undef>".into()
                } else {
                    // SAFETY: a static NUL-terminated name.
                    unsafe { core::ffi::CStr::from_ptr(name) }.to_string_lossy()
                };
                err::raise_with_text(ERR_LIB_CMP, CMP_R_INVALID_KEYSPEC, F, &format!("keySpec with index {k} in certReqTemplate has invalid type {name}"));
                return false;
            }
            // As in OpenSSL, a failed copy is skipped silently.
            // SAFETY: the slot holding the list; the attribute.
            unsafe { OSSL_CMP_ATAV_push1(keySpec, atav) };
            true
        });
        if ok {
            return 1;
        }
        // SAFETY: the copy made above.
        unsafe { OSSL_CRMF_CERTTEMPLATE_free(t) };
        // SAFETY: the caller's slot.
        unsafe { certTemplate.write(ptr::null_mut()) };
        // SAFETY: the list made above, or NULL.
        unsafe { OPENSSL_sk_pop_free(list, Some(atav_free)) };
        // SAFETY: the caller's slot.
        unsafe { keySpec.write(ptr::null_mut()) };
        0
    }
}

ffi_export! {
    /// A new AttributeTypeAndValue of `type_` and `value` (both taken), or NULL.
    ///
    /// # Safety
    /// `type_` and `value` are NULL or live.
    pub unsafe extern "C" fn OSSL_CMP_ATAV_create(type_: *mut ASN1_OBJECT, value: *mut ASN1_TYPE) -> *mut OSSL_CMP_ATAV
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        let atav: *mut OSSL_CMP_ATAV = new_of(attribute_type_and_value_it).cast();
        if atav.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: made here; the caller's objects.
        unsafe { OSSL_CMP_ATAV_set0(atav, type_, value) };
        atav
    }
}

ffi_export! {
    /// Sets the AttributeTypeAndValue's type and value, which it takes (without freeing what it
    /// held).
    ///
    /// # Safety
    /// `atav` is a live value (as in OpenSSL, NULL crashes); `type_` and `value` NULL or live.
    pub unsafe extern "C" fn OSSL_CMP_ATAV_set0(atav: *mut OSSL_CMP_ATAV, type_: *mut ASN1_OBJECT, value: *mut ASN1_TYPE)
    where failure = (), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { of::<Atav, _>(atav) }) else { return };
        a.type_ = type_;
        a.value = value.cast();
    }
}

ffi_export! {
    /// The AttributeTypeAndValue's type, or NULL.
    ///
    /// # Safety
    /// `atav` is NULL or a live value.
    pub unsafe extern "C" fn OSSL_CMP_ATAV_get0_type(atav: *const OSSL_CMP_ATAV) -> *mut ASN1_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<Atav, _>(atav) }.map_or(ptr::null_mut(), |a| a.type_)
    }
}

ffi_export! {
    /// The AttributeTypeAndValue's value (as an ASN1_TYPE), or NULL.
    ///
    /// # Safety
    /// `atav` is NULL or a live value.
    pub unsafe extern "C" fn OSSL_CMP_ATAV_get0_value(atav: *const OSSL_CMP_ATAV) -> *mut ASN1_TYPE
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<Atav, _>(atav) }.map_or(ptr::null_mut(), |a| a.value.cast())
    }
}

ffi_export! {
    /// A new `id-regCtrl-algId` AttributeTypeAndValue with a copy of the algorithm, or NULL.
    ///
    /// # Safety
    /// `alg` is NULL or a live algorithm.
    pub unsafe extern "C" fn OSSL_CMP_ATAV_new_algId(alg: *const X509_ALGOR) -> *mut OSSL_CMP_ATAV
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        if alg.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, "OSSL_CMP_ATAV_new_algId");
            return ptr::null_mut();
        }
        // SAFETY: the caller's algorithm.
        let dup = unsafe { X509_ALGOR_dup(alg) };
        if dup.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: a static object; the copy, taken.
        let res = unsafe { OSSL_CMP_ATAV_create(nid_obj(NID_id_regCtrl_algId), dup.cast()) };
        if res.is_null() {
            // SAFETY: the copy, not taken.
            unsafe { X509_ALGOR_free(dup) };
        }
        res
    }
}

ffi_export! {
    /// The algorithm of an `id-regCtrl-algId` AttributeTypeAndValue, or NULL.
    ///
    /// # Safety
    /// `atav` is NULL or a live value.
    pub unsafe extern "C" fn OSSL_CMP_ATAV_get0_algId(atav: *const OSSL_CMP_ATAV) -> *mut X509_ALGOR
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { of::<Atav, _>(atav) }) else { return ptr::null_mut() };
        // SAFETY: its type.
        if unsafe { obj_nid(a.type_) } != NID_id_regCtrl_algId {
            return ptr::null_mut();
        }
        a.value.cast()
    }
}

ffi_export! {
    /// A new `id-regCtrl-rsaKeyLen` AttributeTypeAndValue of `len` (which must be positive), or
    /// NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_CMP_ATAV_new_rsaKeyLen(len: c_int) -> *mut OSSL_CMP_ATAV
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        if len <= 0 {
            err::raise(ERR_LIB_CMP, ERR_R_PASSED_INVALID_ARGUMENT, "OSSL_CMP_ATAV_new_rsaKeyLen");
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let aint = unsafe { ASN1_INTEGER_new() };
        if aint.is_null() {
            return ptr::null_mut();
        }
        let mut res = ptr::null_mut();
        // SAFETY: the integer made here.
        if unsafe { ASN1_INTEGER_set(aint, c_long::from(len)) } != 0 {
            // SAFETY: a static object; the integer, taken.
            res = unsafe { OSSL_CMP_ATAV_create(nid_obj(NID_id_regCtrl_rsaKeyLen), aint.cast()) };
        }
        if res.is_null() {
            // SAFETY: the integer, not taken.
            unsafe { ASN1_INTEGER_free(aint) };
        }
        res
    }
}

ffi_export! {
    /// The length of an `id-regCtrl-rsaKeyLen` AttributeTypeAndValue: -1 if it isn't one or the
    /// integer doesn't decode, -2 if it's not positive or doesn't fit an int.
    ///
    /// # Safety
    /// `atav` is NULL or a live value.
    pub unsafe extern "C" fn OSSL_CMP_ATAV_get_rsaKeyLen(atav: *const OSSL_CMP_ATAV) -> c_int
    where failure = -1, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { of::<Atav, _>(atav) }) else { return -1 };
        // SAFETY: its type.
        if unsafe { obj_nid(a.type_) } != NID_id_regCtrl_rsaKeyLen {
            return -1;
        }
        let mut val: i64 = 0;
        // SAFETY: the room; its integer.
        if unsafe { ASN1_INTEGER_get_int64(&raw mut val, a.value.cast()) } == 0 {
            return -1;
        }
        match c_int::try_from(val) {
            Ok(v) if v > 0 => v,
            _ => -2,
        }
    }
}

ffi_export! {
    /// Pushes a copy of `atav` onto the list in `*sk_p`, made if need be: 1, or 0.
    ///
    /// # Safety
    /// `sk_p` is NULL or a slot holding NULL or a live list; `atav` NULL or a live value.
    pub unsafe extern "C" fn OSSL_CMP_ATAV_push1(sk_p: *mut *mut rustyssl_abi::OSSL_CMP_ATAVS, atav: *const OSSL_CMP_ATAV) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        if sk_p.is_null() || atav.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, "OSSL_CMP_ATAV_push1");
            return 0;
        }
        let slot: *mut *mut Stack = sk_p.cast();
        // SAFETY: the caller's slot.
        let created = unsafe { slot.read() }.is_null();
        if created {
            // SAFETY: no preconditions.
            let sk = unsafe { OPENSSL_sk_new_null() };
            if sk.is_null() {
                return 0;
            }
            // SAFETY: the caller's slot.
            unsafe { slot.write(sk) };
        }
        // SAFETY: the caller's slot, holding the list now.
        let sk = unsafe { slot.read() };
        // SAFETY: the caller's attribute.
        let dup = unsafe { OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup(atav) };
        if !dup.is_null() {
            // SAFETY: the list; the copy, taken.
            if unsafe { OPENSSL_sk_push(sk, dup.cast()) } != 0 {
                return 1;
            }
            // SAFETY: the copy, not taken.
            unsafe { OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free(dup) };
        }
        if created {
            // SAFETY: the list made here.
            unsafe { OPENSSL_sk_free(sk) };
            // SAFETY: the caller's slot.
            unsafe { slot.write(ptr::null_mut()) };
        }
        0
    }
}

ffi_export! {
    /// A new `id-it-crlStatusList` InfoTypeAndValue of the list (taken), or NULL.
    ///
    /// # Safety
    /// `crlStatusList` is NULL or a live list of CRL statuses.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_new0_crlStatusList(crlStatusList: *mut rustyssl_abi::stack_st_OSSL_CMP_CRLSTATUS) -> *mut OSSL_CMP_ITAV
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        itav_new_of(NID_id_it_crlStatusList, crlStatusList.cast())
    }
}

ffi_export! {
    /// The list of an `id-it-crlStatusList` InfoTypeAndValue in `*out`: 1, or 0.
    ///
    /// # Safety
    /// `itav` is NULL or a live value; `out` NULL or a slot.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_get0_crlStatusList(itav: *const OSSL_CMP_ITAV, out: *mut *mut rustyssl_abi::stack_st_OSSL_CMP_CRLSTATUS) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { itav_typed(itav, out.is_null(), NID_id_it_crlStatusList, "OSSL_CMP_ITAV_get0_crlStatusList") }) else { return 0 };
        // SAFETY: the caller's slot.
        unsafe { out.write(i.infoValue.cast()) };
        1
    }
}

/// `GENERAL_NAME_dup` as a stack's copy function.
unsafe extern "C" fn gen_copy(p: *const c_void) -> *mut c_void {
    // SAFETY: a name of the stack.
    unsafe { GENERAL_NAME_dup(p.cast()) }.cast()
}

/// `GENERAL_NAME_free` as a stack's free function.
unsafe extern "C" fn gen_free(p: *mut c_void) {
    // SAFETY: a name of the stack, which the stack owned.
    unsafe { GENERAL_NAME_free(p.cast()) };
}

ffi_export! {
    /// A new CRL status of a copy of the distribution point name or of the issuer names (exactly
    /// one of them) and of the time, or NULL.
    ///
    /// # Safety
    /// Each argument is NULL or live.
    pub unsafe extern "C" fn OSSL_CMP_CRLSTATUS_new1(dpn: *const DIST_POINT_NAME, issuer: *const GENERAL_NAMES, thisUpdate: *const ASN1_TIME) -> *mut OSSL_CMP_CRLSTATUS
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        const F: &str = "OSSL_CMP_CRLSTATUS_new1";
        if dpn.is_null() && issuer.is_null() {
            err::raise(ERR_LIB_CMP, ERR_R_PASSED_NULL_PARAMETER, F);
            return ptr::null_mut();
        }
        if !dpn.is_null() && !issuer.is_null() {
            err::raise(ERR_LIB_CMP, ERR_R_PASSED_INVALID_ARGUMENT, F);
            return ptr::null_mut();
        }
        let status: *mut CrlStatus = new_of(crlstatus_it).cast();
        // SAFETY: made here, or NULL.
        let Some(st) = (unsafe { status.as_mut() }) else { return ptr::null_mut() };
        // SAFETY: the new status's source, which the template made.
        let Some(src) = (unsafe { st.source.as_mut() }) else {
            // SAFETY: made here.
            unsafe { OSSL_CMP_CRLSTATUS_free(status.cast()) };
            return ptr::null_mut();
        };
        let ok = if dpn.is_null() {
            src.type_ = CRLSOURCE_ISSUER;
            // SAFETY: the caller's names, with the names' copy and free functions.
            src.value = unsafe { OPENSSL_sk_deep_copy(issuer.cast(), Some(gen_copy), Some(gen_free)) }.cast();
            !src.value.is_null()
        } else {
            src.type_ = CRLSOURCE_DPN;
            // SAFETY: the caller's name.
            src.value = unsafe { DIST_POINT_NAME_dup(dpn) }.cast();
            !src.value.is_null()
        };
        let ok = ok && (thisUpdate.is_null() || {
            // SAFETY: the caller's time.
            st.thisUpdate = unsafe { ASN1_TIME_dup(thisUpdate) };
            !st.thisUpdate.is_null()
        });
        if !ok {
            // SAFETY: made here.
            unsafe { OSSL_CMP_CRLSTATUS_free(status.cast()) };
            return ptr::null_mut();
        }
        status.cast()
    }
}

/// `gennames_new`: a list of one directory name, a copy of `nm`, or NULL.
///
/// # Safety
/// `nm` is NULL or a live name.
unsafe fn gennames_new(nm: *const X509_NAME) -> *mut Stack {
    // SAFETY: no preconditions.
    let names = unsafe { OPENSSL_sk_new_reserve(None, 1) };
    if names.is_null() {
        return ptr::null_mut();
    }
    let mut name: *mut GENERAL_NAME = ptr::null_mut();
    // SAFETY: the slot; the caller's name.
    if unsafe { GENERAL_NAME_set1_X509_NAME(&raw mut name, nm) } == 0 {
        // SAFETY: the list made here.
        unsafe { OPENSSL_sk_free(names) };
        return ptr::null_mut();
    }
    // Room was reserved, so this can't fail.
    // SAFETY: the list; the name, taken.
    unsafe { OPENSSL_sk_push(names, name.cast()) };
    names
}

/// `gennames_allowed`: whether the names may be used (with `only_DN`, only one directory name).
///
/// # Safety
/// `names` is NULL or a live list of names.
unsafe fn gennames_allowed(names: *const Stack, only_DN: bool) -> bool {
    if names.is_null() {
        return false;
    }
    if !only_DN {
        return true;
    }
    // SAFETY: the caller's list.
    if unsafe { OPENSSL_sk_num(names) } != 1 {
        return false;
    }
    // SAFETY: an index in range.
    let n: *const GENERAL_NAME = unsafe { OPENSSL_sk_value(names, 0) }.cast();
    // SAFETY: a name of the list.
    unsafe { n.as_ref() }.is_some_and(|n| n.type_ == GEN_DIRNAME)
}

/// `DIST_POINT_free` as a stack's free function.
unsafe extern "C" fn dp_free(p: *mut c_void) {
    // SAFETY: a distribution point of the stack, which the stack owned.
    unsafe { DIST_POINT_free(p.cast()) };
}

ffi_export! {
    /// The CRL status for the certificate's distribution point (or CRL issuer), or else the
    /// CRL's issuing distribution point; failing those, the issuer by its authority key
    /// identifier or its name (with `only_DN`, only a single directory name); with the CRL's
    /// last update. NULL on failure.
    ///
    /// # Safety
    /// `crl` and `cert` are NULL or live.
    pub unsafe extern "C" fn OSSL_CMP_CRLSTATUS_create(crl: *const X509_CRL, cert: *const X509, only_DN: c_int) -> *mut OSSL_CMP_CRLSTATUS
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        let only_dn = only_DN != 0;
        let last = if crl.is_null() {
            ptr::null()
        } else {
            // SAFETY: the caller's CRL.
            unsafe { X509_CRL_get0_lastUpdate(crl) }
        };
        let mut crldps: *mut Stack = ptr::null_mut();
        let mut idp: *mut ISSUING_DIST_POINT = ptr::null_mut();
        let mut dpn: *const DIST_POINT_NAME = ptr::null();
        let mut akid: *mut AUTHORITY_KEYID = ptr::null_mut();
        let mut issuers: *mut Stack = ptr::null_mut();
        let mut crl_issuer: *const Stack = ptr::null();
        if cert.is_null() {
            if crl.is_null() {
                err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, "OSSL_CMP_CRLSTATUS_create");
                return ptr::null_mut();
            }
            // SAFETY: the caller's CRL.
            idp = unsafe { X509_CRL_get_ext_d2i(crl, NID_issuing_distribution_point, ptr::null_mut(), ptr::null_mut()) }.cast();
            // SAFETY: decoded here, or NULL.
            if let Some(i) = unsafe { idp.as_ref() } {
                dpn = i.distpoint;
            }
        } else {
            // SAFETY: the caller's certificate.
            crldps = unsafe { X509_get_ext_d2i(cert, NID_crl_distribution_points, ptr::null_mut(), ptr::null_mut()) }.cast();
            // SAFETY: decoded here, or NULL (-1).
            let n = unsafe { OPENSSL_sk_num(crldps) };
            for k in 0..n {
                // SAFETY: an index in range.
                let dp: *const DIST_POINT = unsafe { OPENSSL_sk_value(crldps, k) }.cast();
                // SAFETY: a distribution point of the list, or NULL.
                let Some(dp) = (unsafe { dp.as_ref() }) else { continue };
                if !dp.distpoint.is_null() {
                    dpn = dp.distpoint;
                    crl_issuer = ptr::null();
                    break;
                }
                // Any distribution point name in the list is preferred, so no break here.
                // SAFETY: its CRL issuer, or NULL.
                if unsafe { gennames_allowed(dp.CRLissuer.cast(), only_dn) } && crl_issuer.is_null() {
                    crl_issuer = dp.CRLissuer.cast();
                }
            }
        }
        let mut status: *mut OSSL_CMP_CRLSTATUS = ptr::null_mut();
        let mut found = true;
        if dpn.is_null() && crl_issuer.is_null() {
            if !cert.is_null() {
                // SAFETY: the caller's certificate.
                akid = unsafe { X509_get_ext_d2i(cert, NID_authority_key_identifier, ptr::null_mut(), ptr::null_mut()) }.cast();
                // SAFETY: decoded here, or NULL; its issuer.
                if let Some(a) = unsafe { akid.as_ref() }.filter(|a| unsafe { gennames_allowed(a.issuer.cast(), only_dn) }) {
                    crl_issuer = a.issuer.cast();
                } else {
                    // SAFETY: the caller's certificate.
                    let name = unsafe { X509_get_issuer_name(cert) };
                    // SAFETY: its issuer's name.
                    issuers = unsafe { gennames_new(name) };
                    crl_issuer = issuers;
                }
            }
            if crl_issuer.is_null() && !crl.is_null() {
                // A second decoding replaces the first (OpenSSL leaks it; here it's freed).
                // SAFETY: decoded above, or NULL.
                unsafe { AUTHORITY_KEYID_free(akid) };
                // SAFETY: the caller's CRL.
                akid = unsafe { X509_CRL_get_ext_d2i(crl, NID_authority_key_identifier, ptr::null_mut(), ptr::null_mut()) }.cast();
                // SAFETY: decoded here, or NULL; its issuer.
                if let Some(a) = unsafe { akid.as_ref() }.filter(|a| unsafe { gennames_allowed(a.issuer.cast(), only_dn) }) {
                    crl_issuer = a.issuer.cast();
                } else {
                    // SAFETY: the caller's CRL.
                    let name = unsafe { X509_CRL_get_issuer(crl) };
                    // SAFETY: its issuer's name.
                    issuers = unsafe { gennames_new(name) };
                    crl_issuer = issuers;
                }
            }
            found = !crl_issuer.is_null();
        }
        if found {
            // SAFETY: what was found above, each NULL or live; the CRL's time, or NULL.
            status = unsafe { OSSL_CMP_CRLSTATUS_new1(dpn, crl_issuer.cast(), last) };
        }
        // SAFETY: decoded here, or NULL.
        unsafe { OPENSSL_sk_pop_free(crldps, Some(dp_free)) };
        // SAFETY: as above.
        unsafe { ISSUING_DIST_POINT_free(idp) };
        // SAFETY: as above.
        unsafe { AUTHORITY_KEYID_free(akid) };
        // SAFETY: made here, or NULL.
        unsafe { OPENSSL_sk_pop_free(issuers, Some(gen_free)) };
        status
    }
}

ffi_export! {
    /// The CRL status's source (the distribution point name or the issuer names, the other set
    /// to NULL) and, where `thisUpdate` isn't NULL, its time: 1, or 0.
    ///
    /// # Safety
    /// `crlstatus` is NULL or live; the slots NULL or writable.
    pub unsafe extern "C" fn OSSL_CMP_CRLSTATUS_get0(crlstatus: *const OSSL_CMP_CRLSTATUS, dpn: *mut *mut DIST_POINT_NAME, issuer: *mut *mut GENERAL_NAMES, thisUpdate: *mut *mut ASN1_TIME) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        const F: &str = "OSSL_CMP_CRLSTATUS_get0";
        // SAFETY: the caller's guarantee.
        let st = unsafe { of::<CrlStatus, _>(crlstatus) };
        let (Some(st), false, false) = (st, dpn.is_null(), issuer.is_null()) else {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, F);
            return 0;
        };
        // SAFETY: its source, or NULL.
        let Some(src) = (unsafe { st.source.as_ref() }) else {
            err::raise(ERR_LIB_CMP, ERR_R_PASSED_INVALID_ARGUMENT, F);
            return 0;
        };
        let (d, i) = match src.type_ {
            CRLSOURCE_DPN => (src.value.cast(), ptr::null_mut()),
            CRLSOURCE_ISSUER => (ptr::null_mut(), src.value.cast()),
            _ => {
                err::raise(ERR_LIB_CMP, ERR_R_PASSED_INVALID_ARGUMENT, F);
                return 0;
            }
        };
        // SAFETY: the caller's slots.
        unsafe { dpn.write(d) };
        // SAFETY: as above.
        unsafe { issuer.write(i) };
        if !thisUpdate.is_null() {
            // SAFETY: as above.
            unsafe { thisUpdate.write(st.thisUpdate) };
        }
        1
    }
}

ffi_export! {
    /// A new `id-it-crls` InfoTypeAndValue with a copy of the CRL (no content if NULL), or NULL.
    ///
    /// # Safety
    /// `crl` is NULL or a live CRL.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_new_crls(crl: *const X509_CRL) -> *mut OSSL_CMP_ITAV
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        let itav = itav_new();
        // SAFETY: made here, or NULL.
        let Some(i) = (unsafe { itav_of(itav) }) else { return ptr::null_mut() };
        let mut crls: *mut Stack = ptr::null_mut();
        if !crl.is_null() {
            // SAFETY: no preconditions.
            crls = unsafe { OPENSSL_sk_new_reserve(None, 1) };
            let copy = if crls.is_null() {
                ptr::null_mut()
            } else {
                // SAFETY: the caller's CRL.
                unsafe { X509_CRL_dup(crl) }
            };
            // SAFETY: the list; the copy, taken.
            if copy.is_null() || unsafe { OPENSSL_sk_push(crls, copy.cast()) } == 0 {
                // SAFETY: the copy, not taken, or NULL.
                unsafe { X509_CRL_free(copy) };
                // SAFETY: made here, or NULL.
                unsafe { OPENSSL_sk_free(crls) };
                // SAFETY: made here.
                unsafe { OSSL_CMP_ITAV_free(itav) };
                return ptr::null_mut();
            }
        }
        i.infoType = nid_obj(NID_id_it_crls);
        i.infoValue = crls.cast();
        itav
    }
}

ffi_export! {
    /// The CRLs of an `id-it-crls` InfoTypeAndValue in `*out`: 1, or 0.
    ///
    /// # Safety
    /// `itav` is NULL or a live value; `out` NULL or a slot.
    pub unsafe extern "C" fn OSSL_CMP_ITAV_get0_crls(itav: *const OSSL_CMP_ITAV, out: *mut *mut rustyssl_abi::stack_st_X509_CRL) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { itav_typed(itav, out.is_null(), NID_id_it_crls, "OSSL_CMP_ITAV_get0_crls") }) else { return 0 };
        // SAFETY: the caller's slot.
        unsafe { out.write(i.infoValue.cast()) };
        1
    }
}

/// `ossl_cmp_asn1_get_int`: the integer's value, or -2 (with an error) if it doesn't decode or
/// fit an int; -1 is a valid value (a certReqId's).
///
/// # Safety
/// `a` is NULL or a live integer.
pub(crate) unsafe fn asn1_get_int(a: *const ASN1_INTEGER) -> c_int {
    const F: &str = "ossl_cmp_asn1_get_int";
    let mut res: i64 = 0;
    // SAFETY: the room; the caller's integer.
    if unsafe { ASN1_INTEGER_get_int64(&raw mut res, a) } == 0 {
        err::raise(ERR_LIB_CMP, ASN1_R_INVALID_NUMBER, F);
        return -2;
    }
    if res < i64::from(c_int::MIN) {
        err::raise(ERR_LIB_CMP, ASN1_R_TOO_SMALL, F);
        return -2;
    }
    match c_int::try_from(res) {
        Ok(v) => v,
        Err(_) => {
            err::raise(ERR_LIB_CMP, ASN1_R_TOO_LARGE, F);
            -2
        }
    }
}
