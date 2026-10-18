//! OCSP's structures and their ASN.1 (`ocsp_asn.c`, RFC 6960).
//!
//! The structures are opaque in `ocsp.h`; their layouts here are OpenSSL's internal ones
//! (`ocsp_local.h`), which the templates describe, embedded fields included.

use core::ffi::{c_int, c_void};
use core::mem::offset_of;

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_ENUMERATED, ASN1_GENERALIZEDTIME, ASN1_IA5STRING, ASN1_INTEGER,
    ASN1_ITEM, ASN1_OBJECT, ASN1_OCTET_STRING, ASN1_STRING, ASN1_TFLG_EMBED, ASN1_TFLG_EXPLICIT,
    ASN1_TFLG_IMPLICIT, ASN1_TFLG_OPTIONAL, ASN1_TFLG_SEQUENCE_OF, ERR_LIB_ASN1, ERR_LIB_OCSP,
    GENERAL_NAME, OCSP_CERTID, X509_ALGOR, X509_NAME,
};

use crate::asn1::tpl::items::{
    ASN1_BIT_STRING_it, ASN1_ENUMERATED_it, ASN1_GENERALIZEDTIME_it, ASN1_IA5STRING_it,
    ASN1_INTEGER_it, ASN1_NULL_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_it, X509_ALGOR_it, d2i, i2d,
    new_free,
};
use crate::asn1::tpl::statics::{Templates, choice, sequence};
use crate::asn1::tpl::util::ASN1_item_dup;
use crate::asn1::tpl::{item_fns, template_at};
use crate::ffi::ffi_export;
use crate::x509::cert::X509_it;
use crate::x509::ext::X509_EXTENSION_it;
use crate::x509::name::X509_NAME_it;
use crate::x509v3::genn::GENERAL_NAME_it;
use crate::x509v3::info::ACCESS_DESCRIPTION_it;

/// A stack, as `STACK_OF(...)` is to C.
pub(crate) type Stack = rustyssl_abi::OPENSSL_STACK;

#[repr(C)]
pub(crate) struct CertId {
    pub(crate) hash_algorithm: X509_ALGOR,
    pub(crate) issuer_name_hash: ASN1_STRING,
    pub(crate) issuer_key_hash: ASN1_STRING,
    pub(crate) serial_number: ASN1_STRING,
}

#[repr(C)]
pub(crate) struct OneReq {
    pub(crate) req_cert: *mut CertId,
    pub(crate) single_request_extensions: *mut Stack,
}

#[repr(C)]
pub(crate) struct ReqInfo {
    pub(crate) version: *mut ASN1_INTEGER,
    pub(crate) requestor_name: *mut GENERAL_NAME,
    pub(crate) request_list: *mut Stack,
    pub(crate) request_extensions: *mut Stack,
}

#[repr(C)]
pub(crate) struct Signature {
    pub(crate) signature_algorithm: X509_ALGOR,
    pub(crate) signature: *mut ASN1_BIT_STRING,
    pub(crate) certs: *mut Stack,
}

#[repr(C)]
pub(crate) struct Request {
    pub(crate) tbs_request: ReqInfo,
    pub(crate) optional_signature: *mut Signature,
}

#[repr(C)]
pub(crate) struct RespBytes {
    pub(crate) response_type: *mut ASN1_OBJECT,
    pub(crate) response: *mut ASN1_OCTET_STRING,
}

#[repr(C)]
pub(crate) struct Response {
    pub(crate) response_status: *mut ASN1_ENUMERATED,
    pub(crate) response_bytes: *mut RespBytes,
}

/// ResponderID: by name (`X509_NAME`) or by key (an OCTET STRING).
#[repr(C)]
pub(crate) struct RespId {
    pub(crate) type_: c_int,
    pub(crate) value: *mut c_void,
}

#[repr(C)]
pub(crate) struct RevokedInfo {
    pub(crate) revocation_time: *mut ASN1_GENERALIZEDTIME,
    pub(crate) revocation_reason: *mut ASN1_ENUMERATED,
}

/// CertStatus: good and unknown (NULLs), or revoked.
#[repr(C)]
pub(crate) struct CertStatus {
    pub(crate) type_: c_int,
    pub(crate) value: *mut c_void,
}

#[repr(C)]
pub(crate) struct SingleResp {
    pub(crate) cert_id: *mut CertId,
    pub(crate) cert_status: *mut CertStatus,
    pub(crate) this_update: *mut ASN1_GENERALIZEDTIME,
    pub(crate) next_update: *mut ASN1_GENERALIZEDTIME,
    pub(crate) single_extensions: *mut Stack,
}

#[repr(C)]
pub(crate) struct RespData {
    pub(crate) version: *mut ASN1_INTEGER,
    pub(crate) responder_id: RespId,
    pub(crate) produced_at: *mut ASN1_GENERALIZEDTIME,
    pub(crate) responses: *mut Stack,
    pub(crate) response_extensions: *mut Stack,
}

#[repr(C)]
pub(crate) struct BasicResp {
    pub(crate) tbs_response_data: RespData,
    pub(crate) signature_algorithm: X509_ALGOR,
    pub(crate) signature: *mut ASN1_BIT_STRING,
    pub(crate) certs: *mut Stack,
}

#[repr(C)]
pub(crate) struct CrlId {
    pub(crate) crl_url: *mut ASN1_IA5STRING,
    pub(crate) crl_num: *mut ASN1_INTEGER,
    pub(crate) crl_time: *mut ASN1_GENERALIZEDTIME,
}

#[repr(C)]
pub(crate) struct ServiceLoc {
    pub(crate) issuer: *mut X509_NAME,
    pub(crate) locator: *mut Stack,
}

const SIMPLE: c_int = 0;
const EMBED: c_int = ASN1_TFLG_EMBED;
const EXP: c_int = ASN1_TFLG_EXPLICIT;
const EXP_OPT: c_int = ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL;
const EXP_SEQ_OF_OPT: c_int = ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL;
const SEQ_OF: c_int = ASN1_TFLG_SEQUENCE_OF;
const SEQ_OF_OPT: c_int = ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL;
const IMP: c_int = ASN1_TFLG_IMPLICIT;

macro_rules! tt {
    ($t:ty; $($flags:expr, $tag:expr, $field:ident, $name:literal, $it:expr;)*) => {
        Templates([$(template_at($flags, $tag, offset_of!($t, $field), $name, $it),)*])
    };
}

static SIG_TT: Templates<3> = tt![Signature;
    EMBED, 0, signature_algorithm, c"signatureAlgorithm", X509_ALGOR_it;
    SIMPLE, 0, signature, c"signature", ASN1_BIT_STRING_it;
    EXP_SEQ_OF_OPT, 0, certs, c"certs", X509_it;
];

static CID_TT: Templates<4> = tt![CertId;
    EMBED, 0, hash_algorithm, c"hashAlgorithm", X509_ALGOR_it;
    EMBED, 0, issuer_name_hash, c"issuerNameHash", ASN1_OCTET_STRING_it;
    EMBED, 0, issuer_key_hash, c"issuerKeyHash", ASN1_OCTET_STRING_it;
    EMBED, 0, serial_number, c"serialNumber", ASN1_INTEGER_it;
];

static ONEREQ_TT: Templates<2> = tt![OneReq;
    SIMPLE, 0, req_cert, c"reqCert", OCSP_CERTID_it;
    EXP_SEQ_OF_OPT, 0, single_request_extensions, c"singleRequestExtensions", X509_EXTENSION_it;
];

static REQINFO_TT: Templates<4> = tt![ReqInfo;
    EXP_OPT, 0, version, c"version", ASN1_INTEGER_it;
    EXP_OPT, 1, requestor_name, c"requestorName", GENERAL_NAME_it;
    SEQ_OF, 0, request_list, c"requestList", OCSP_ONEREQ_it;
    EXP_SEQ_OF_OPT, 2, request_extensions, c"requestExtensions", X509_EXTENSION_it;
];

static REQUEST_TT: Templates<2> = tt![Request;
    EMBED, 0, tbs_request, c"tbsRequest", OCSP_REQINFO_it;
    EXP_OPT, 0, optional_signature, c"optionalSignature", OCSP_SIGNATURE_it;
];

static RESPBYTES_TT: Templates<2> = tt![RespBytes;
    SIMPLE, 0, response_type, c"responseType", ASN1_OBJECT_it;
    SIMPLE, 0, response, c"response", ASN1_OCTET_STRING_it;
];

static RESPONSE_TT: Templates<2> = tt![Response;
    SIMPLE, 0, response_status, c"responseStatus", ASN1_ENUMERATED_it;
    EXP_OPT, 0, response_bytes, c"responseBytes", OCSP_RESPBYTES_it;
];

static RESPID_TT: Templates<2> = tt![RespId;
    EXP, 1, value, c"value.byName", X509_NAME_it;
    EXP, 2, value, c"value.byKey", ASN1_OCTET_STRING_it;
];

static REVOKED_TT: Templates<2> = tt![RevokedInfo;
    SIMPLE, 0, revocation_time, c"revocationTime", ASN1_GENERALIZEDTIME_it;
    EXP_OPT, 0, revocation_reason, c"revocationReason", ASN1_ENUMERATED_it;
];

static CERTSTATUS_TT: Templates<3> = tt![CertStatus;
    IMP, 0, value, c"value.good", ASN1_NULL_it;
    IMP, 1, value, c"value.revoked", OCSP_REVOKEDINFO_it;
    IMP, 2, value, c"value.unknown", ASN1_NULL_it;
];

static SINGLERESP_TT: Templates<5> = tt![SingleResp;
    SIMPLE, 0, cert_id, c"certId", OCSP_CERTID_it;
    SIMPLE, 0, cert_status, c"certStatus", OCSP_CERTSTATUS_it;
    SIMPLE, 0, this_update, c"thisUpdate", ASN1_GENERALIZEDTIME_it;
    EXP_OPT, 0, next_update, c"nextUpdate", ASN1_GENERALIZEDTIME_it;
    EXP_SEQ_OF_OPT, 1, single_extensions, c"singleExtensions", X509_EXTENSION_it;
];

static RESPDATA_TT: Templates<5> = tt![RespData;
    EXP_OPT, 0, version, c"version", ASN1_INTEGER_it;
    EMBED, 0, responder_id, c"responderId", OCSP_RESPID_it;
    SIMPLE, 0, produced_at, c"producedAt", ASN1_GENERALIZEDTIME_it;
    SEQ_OF, 0, responses, c"responses", OCSP_SINGLERESP_it;
    EXP_SEQ_OF_OPT, 1, response_extensions, c"responseExtensions", X509_EXTENSION_it;
];

static BASICRESP_TT: Templates<4> = tt![BasicResp;
    EMBED, 0, tbs_response_data, c"tbsResponseData", OCSP_RESPDATA_it;
    EMBED, 0, signature_algorithm, c"signatureAlgorithm", X509_ALGOR_it;
    SIMPLE, 0, signature, c"signature", ASN1_BIT_STRING_it;
    EXP_SEQ_OF_OPT, 0, certs, c"certs", X509_it;
];

static CRLID_TT: Templates<3> = tt![CrlId;
    EXP_OPT, 0, crl_url, c"crlUrl", ASN1_IA5STRING_it;
    EXP_OPT, 1, crl_num, c"crlNum", ASN1_INTEGER_it;
    EXP_OPT, 2, crl_time, c"crlTime", ASN1_GENERALIZEDTIME_it;
];

static SERVICELOC_TT: Templates<2> = tt![ServiceLoc;
    SIMPLE, 0, issuer, c"issuer", X509_NAME_it;
    SEQ_OF_OPT, 0, locator, c"locator", ACCESS_DESCRIPTION_it;
];

item_fns! {
    /// Signature: SEQUENCE { signatureAlgorithm, signature, certs [0] EXPLICIT OPTIONAL }.
    pub unsafe extern "C" fn OCSP_SIGNATURE_it = sequence::<Signature, 3>(&SIG_TT, None, c"OCSP_SIGNATURE");
    /// CertID: SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }.
    pub unsafe extern "C" fn OCSP_CERTID_it = sequence::<CertId, 4>(&CID_TT, None, c"OCSP_CERTID");
    /// Request: SEQUENCE { reqCert, singleRequestExtensions [0] EXPLICIT OPTIONAL }.
    pub unsafe extern "C" fn OCSP_ONEREQ_it = sequence::<OneReq, 2>(&ONEREQ_TT, None, c"OCSP_ONEREQ");
    /// TBSRequest.
    pub unsafe extern "C" fn OCSP_REQINFO_it = sequence::<ReqInfo, 4>(&REQINFO_TT, None, c"OCSP_REQINFO");
    /// OCSPRequest: SEQUENCE { tbsRequest, optionalSignature [0] EXPLICIT OPTIONAL }.
    pub unsafe extern "C" fn OCSP_REQUEST_it = sequence::<Request, 2>(&REQUEST_TT, None, c"OCSP_REQUEST");
    /// ResponseBytes.
    pub unsafe extern "C" fn OCSP_RESPBYTES_it = sequence::<RespBytes, 2>(&RESPBYTES_TT, None, c"OCSP_RESPBYTES");
    /// OCSPResponse: SEQUENCE { responseStatus, responseBytes [0] EXPLICIT OPTIONAL }.
    pub unsafe extern "C" fn OCSP_RESPONSE_it = sequence::<Response, 2>(&RESPONSE_TT, None, c"OCSP_RESPONSE");
    /// ResponderID: CHOICE { byName [1], byKey [2] }.
    pub unsafe extern "C" fn OCSP_RESPID_it = choice::<RespId, 2>(&RESPID_TT, offset_of!(RespId, type_), None, c"OCSP_RESPID");
    /// RevokedInfo.
    pub unsafe extern "C" fn OCSP_REVOKEDINFO_it = sequence::<RevokedInfo, 2>(&REVOKED_TT, None, c"OCSP_REVOKEDINFO");
    /// CertStatus: CHOICE { good [0], revoked [1], unknown [2] }.
    pub unsafe extern "C" fn OCSP_CERTSTATUS_it = choice::<CertStatus, 3>(&CERTSTATUS_TT, offset_of!(CertStatus, type_), None, c"OCSP_CERTSTATUS");
    /// SingleResponse.
    pub unsafe extern "C" fn OCSP_SINGLERESP_it = sequence::<SingleResp, 5>(&SINGLERESP_TT, None, c"OCSP_SINGLERESP");
    /// ResponseData.
    pub unsafe extern "C" fn OCSP_RESPDATA_it = sequence::<RespData, 5>(&RESPDATA_TT, None, c"OCSP_RESPDATA");
    /// BasicOCSPResponse.
    pub unsafe extern "C" fn OCSP_BASICRESP_it = sequence::<BasicResp, 4>(&BASICRESP_TT, None, c"OCSP_BASICRESP");
    /// CrlID.
    pub unsafe extern "C" fn OCSP_CRLID_it = sequence::<CrlId, 3>(&CRLID_TT, None, c"OCSP_CRLID");
    /// ServiceLocator.
    pub unsafe extern "C" fn OCSP_SERVICELOC_it = sequence::<ServiceLoc, 2>(&SERVICELOC_TT, None, c"OCSP_SERVICELOC");
}

new_free! {
    pub unsafe extern "C" fn OCSP_SIGNATURE_new, pub unsafe extern "C" fn OCSP_SIGNATURE_free(rustyssl_abi::OCSP_SIGNATURE) = OCSP_SIGNATURE_it;
    pub unsafe extern "C" fn OCSP_CERTID_new, pub unsafe extern "C" fn OCSP_CERTID_free(rustyssl_abi::OCSP_CERTID) = OCSP_CERTID_it;
    pub unsafe extern "C" fn OCSP_ONEREQ_new, pub unsafe extern "C" fn OCSP_ONEREQ_free(rustyssl_abi::OCSP_ONEREQ) = OCSP_ONEREQ_it;
    pub unsafe extern "C" fn OCSP_REQINFO_new, pub unsafe extern "C" fn OCSP_REQINFO_free(rustyssl_abi::OCSP_REQINFO) = OCSP_REQINFO_it;
    pub unsafe extern "C" fn OCSP_REQUEST_new, pub unsafe extern "C" fn OCSP_REQUEST_free(rustyssl_abi::OCSP_REQUEST) = OCSP_REQUEST_it;
    pub unsafe extern "C" fn OCSP_RESPBYTES_new, pub unsafe extern "C" fn OCSP_RESPBYTES_free(rustyssl_abi::OCSP_RESPBYTES) = OCSP_RESPBYTES_it;
    pub unsafe extern "C" fn OCSP_RESPONSE_new, pub unsafe extern "C" fn OCSP_RESPONSE_free(rustyssl_abi::OCSP_RESPONSE) = OCSP_RESPONSE_it;
    pub unsafe extern "C" fn OCSP_RESPID_new, pub unsafe extern "C" fn OCSP_RESPID_free(rustyssl_abi::OCSP_RESPID) = OCSP_RESPID_it;
    pub unsafe extern "C" fn OCSP_REVOKEDINFO_new, pub unsafe extern "C" fn OCSP_REVOKEDINFO_free(rustyssl_abi::OCSP_REVOKEDINFO) = OCSP_REVOKEDINFO_it;
    pub unsafe extern "C" fn OCSP_CERTSTATUS_new, pub unsafe extern "C" fn OCSP_CERTSTATUS_free(rustyssl_abi::OCSP_CERTSTATUS) = OCSP_CERTSTATUS_it;
    pub unsafe extern "C" fn OCSP_SINGLERESP_new, pub unsafe extern "C" fn OCSP_SINGLERESP_free(rustyssl_abi::OCSP_SINGLERESP) = OCSP_SINGLERESP_it;
    pub unsafe extern "C" fn OCSP_RESPDATA_new, pub unsafe extern "C" fn OCSP_RESPDATA_free(rustyssl_abi::OCSP_RESPDATA) = OCSP_RESPDATA_it;
    pub unsafe extern "C" fn OCSP_BASICRESP_new, pub unsafe extern "C" fn OCSP_BASICRESP_free(rustyssl_abi::OCSP_BASICRESP) = OCSP_BASICRESP_it;
    pub unsafe extern "C" fn OCSP_CRLID_new, pub unsafe extern "C" fn OCSP_CRLID_free(rustyssl_abi::OCSP_CRLID) = OCSP_CRLID_it;
    pub unsafe extern "C" fn OCSP_SERVICELOC_new, pub unsafe extern "C" fn OCSP_SERVICELOC_free(rustyssl_abi::OCSP_SERVICELOC) = OCSP_SERVICELOC_it;
}

i2d! {
    /// Encodes a Signature.
    pub unsafe extern "C" fn i2d_OCSP_SIGNATURE(rustyssl_abi::OCSP_SIGNATURE) = OCSP_SIGNATURE_it;
    /// Encodes a CertID.
    pub unsafe extern "C" fn i2d_OCSP_CERTID(rustyssl_abi::OCSP_CERTID) = OCSP_CERTID_it;
    /// Encodes a Request.
    pub unsafe extern "C" fn i2d_OCSP_ONEREQ(rustyssl_abi::OCSP_ONEREQ) = OCSP_ONEREQ_it;
    /// Encodes a TBSRequest.
    pub unsafe extern "C" fn i2d_OCSP_REQINFO(rustyssl_abi::OCSP_REQINFO) = OCSP_REQINFO_it;
    /// Encodes an OCSPRequest.
    pub unsafe extern "C" fn i2d_OCSP_REQUEST(rustyssl_abi::OCSP_REQUEST) = OCSP_REQUEST_it;
    /// Encodes ResponseBytes.
    pub unsafe extern "C" fn i2d_OCSP_RESPBYTES(rustyssl_abi::OCSP_RESPBYTES) = OCSP_RESPBYTES_it;
    /// Encodes an OCSPResponse.
    pub unsafe extern "C" fn i2d_OCSP_RESPONSE(rustyssl_abi::OCSP_RESPONSE) = OCSP_RESPONSE_it;
    /// Encodes a ResponderID.
    pub unsafe extern "C" fn i2d_OCSP_RESPID(rustyssl_abi::OCSP_RESPID) = OCSP_RESPID_it;
    /// Encodes a RevokedInfo.
    pub unsafe extern "C" fn i2d_OCSP_REVOKEDINFO(rustyssl_abi::OCSP_REVOKEDINFO) = OCSP_REVOKEDINFO_it;
    /// Encodes a CertStatus.
    pub unsafe extern "C" fn i2d_OCSP_CERTSTATUS(rustyssl_abi::OCSP_CERTSTATUS) = OCSP_CERTSTATUS_it;
    /// Encodes a SingleResponse.
    pub unsafe extern "C" fn i2d_OCSP_SINGLERESP(rustyssl_abi::OCSP_SINGLERESP) = OCSP_SINGLERESP_it;
    /// Encodes ResponseData.
    pub unsafe extern "C" fn i2d_OCSP_RESPDATA(rustyssl_abi::OCSP_RESPDATA) = OCSP_RESPDATA_it;
    /// Encodes a BasicOCSPResponse.
    pub unsafe extern "C" fn i2d_OCSP_BASICRESP(rustyssl_abi::OCSP_BASICRESP) = OCSP_BASICRESP_it;
    /// Encodes a CrlID.
    pub unsafe extern "C" fn i2d_OCSP_CRLID(rustyssl_abi::OCSP_CRLID) = OCSP_CRLID_it;
    /// Encodes a ServiceLocator.
    pub unsafe extern "C" fn i2d_OCSP_SERVICELOC(rustyssl_abi::OCSP_SERVICELOC) = OCSP_SERVICELOC_it;
}

d2i! {
    /// Decodes a Signature.
    pub unsafe extern "C" fn d2i_OCSP_SIGNATURE(rustyssl_abi::OCSP_SIGNATURE) = OCSP_SIGNATURE_it;
    /// Decodes a CertID.
    pub unsafe extern "C" fn d2i_OCSP_CERTID(rustyssl_abi::OCSP_CERTID) = OCSP_CERTID_it;
    /// Decodes a Request.
    pub unsafe extern "C" fn d2i_OCSP_ONEREQ(rustyssl_abi::OCSP_ONEREQ) = OCSP_ONEREQ_it;
    /// Decodes a TBSRequest.
    pub unsafe extern "C" fn d2i_OCSP_REQINFO(rustyssl_abi::OCSP_REQINFO) = OCSP_REQINFO_it;
    /// Decodes an OCSPRequest.
    pub unsafe extern "C" fn d2i_OCSP_REQUEST(rustyssl_abi::OCSP_REQUEST) = OCSP_REQUEST_it;
    /// Decodes ResponseBytes.
    pub unsafe extern "C" fn d2i_OCSP_RESPBYTES(rustyssl_abi::OCSP_RESPBYTES) = OCSP_RESPBYTES_it;
    /// Decodes an OCSPResponse.
    pub unsafe extern "C" fn d2i_OCSP_RESPONSE(rustyssl_abi::OCSP_RESPONSE) = OCSP_RESPONSE_it;
    /// Decodes a ResponderID.
    pub unsafe extern "C" fn d2i_OCSP_RESPID(rustyssl_abi::OCSP_RESPID) = OCSP_RESPID_it;
    /// Decodes a RevokedInfo.
    pub unsafe extern "C" fn d2i_OCSP_REVOKEDINFO(rustyssl_abi::OCSP_REVOKEDINFO) = OCSP_REVOKEDINFO_it;
    /// Decodes a CertStatus.
    pub unsafe extern "C" fn d2i_OCSP_CERTSTATUS(rustyssl_abi::OCSP_CERTSTATUS) = OCSP_CERTSTATUS_it;
    /// Decodes a SingleResponse.
    pub unsafe extern "C" fn d2i_OCSP_SINGLERESP(rustyssl_abi::OCSP_SINGLERESP) = OCSP_SINGLERESP_it;
    /// Decodes ResponseData.
    pub unsafe extern "C" fn d2i_OCSP_RESPDATA(rustyssl_abi::OCSP_RESPDATA) = OCSP_RESPDATA_it;
    /// Decodes a BasicOCSPResponse.
    pub unsafe extern "C" fn d2i_OCSP_BASICRESP(rustyssl_abi::OCSP_BASICRESP) = OCSP_BASICRESP_it;
    /// Decodes a CrlID.
    pub unsafe extern "C" fn d2i_OCSP_CRLID(rustyssl_abi::OCSP_CRLID) = OCSP_CRLID_it;
    /// Decodes a ServiceLocator.
    pub unsafe extern "C" fn d2i_OCSP_SERVICELOC(rustyssl_abi::OCSP_SERVICELOC) = OCSP_SERVICELOC_it;
}

ffi_export! {
    /// A copy of the CertID, or NULL.
    ///
    /// # Safety
    /// `cid` is NULL or a live CertID.
    pub unsafe extern "C" fn OCSP_CERTID_dup(cid: *const OCSP_CERTID) -> *mut OCSP_CERTID
    where failure = core::ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: no preconditions.
        let it = unsafe { OCSP_CERTID_it() };
        // SAFETY: the type's item; the caller's value.
        unsafe { ASN1_item_dup(it, cid.cast()) }.cast()
    }
}

/// A pointer to an object as its `T`.
///
/// # Safety
/// `p` is NULL or a live object of the type `T` mirrors.
pub(crate) unsafe fn of<'a, T, U>(p: *const U) -> Option<&'a mut T> {
    // SAFETY: the caller's guarantee.
    unsafe { p.cast::<T>().cast_mut().as_mut() }
}
