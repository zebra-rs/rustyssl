//! The built-in methods (`standard_exts.h`): one for each extension OpenSSL knows. Those of
//! the OCSP extensions (step 6.6) have only their NIDs, and functions that abort when called
//! (AGENTS.md rule 10).

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};

use rustyssl_abi::{
    BIO, NID_id_pkix_OCSP_CrlID, NID_id_pkix_OCSP_Nonce, NID_id_pkix_OCSP_archiveCutoff,
    NID_id_pkix_OCSP_noCheck, NID_id_pkix_OCSP_serviceLocator, X509V3_CTX, X509V3_EXT_METHOD,
    stack_st_CONF_VALUE,
};

use super::registry::{Method, method};
use super::{
    acext, admission, akid, attrdesc, crld, info, misc, policy, rfc3779, san, simple, timespec,
};

fn later() -> ! {
    crate::stub::unimplemented("an X509v3 extension method of step 6.6")
}

extern "C" fn later_new() -> *mut c_void {
    later()
}
extern "C" fn later_free(_: *mut c_void) {
    later()
}
extern "C" fn later_d2i(_: *mut c_void, _: *mut *const c_uchar, _: c_long) -> *mut c_void {
    later()
}
extern "C" fn later_i2d(_: *const c_void, _: *mut *mut c_uchar) -> c_int {
    later()
}
extern "C" fn later_i2s(_: *const X509V3_EXT_METHOD, _: *mut c_void) -> *mut c_char {
    later()
}
extern "C" fn later_s2i(
    _: *const X509V3_EXT_METHOD,
    _: *mut X509V3_CTX,
    _: *const c_char,
) -> *mut c_void {
    later()
}
extern "C" fn later_i2v(
    _: *const X509V3_EXT_METHOD,
    _: *mut c_void,
    _: *mut stack_st_CONF_VALUE,
) -> *mut stack_st_CONF_VALUE {
    later()
}
extern "C" fn later_v2i(
    _: *const X509V3_EXT_METHOD,
    _: *mut X509V3_CTX,
    _: *mut stack_st_CONF_VALUE,
) -> *mut c_void {
    later()
}
extern "C" fn later_i2r(
    _: *const X509V3_EXT_METHOD,
    _: *mut c_void,
    _: *mut BIO,
    _: c_int,
) -> c_int {
    later()
}

/// A method of a later part of step 5.2, with its flags: every function aborts.
const fn placeholder(nid: c_int, flags: c_int) -> Method {
    let mut m = method(nid, flags);
    m.ext_new = Some(later_new);
    m.ext_free = Some(later_free);
    m.d2i = Some(later_d2i);
    m.i2d = Some(later_i2d);
    m.i2s = Some(later_i2s);
    m.s2i = Some(later_s2i);
    m.i2v = Some(later_i2v);
    m.v2i = Some(later_v2i);
    m.i2r = Some(later_i2r);
    m.r2i = Some(later_s2i);
    Method(m)
}

static LATER: [Method; 5] = [
    placeholder(NID_id_pkix_OCSP_Nonce, 0),
    placeholder(NID_id_pkix_OCSP_CrlID, 0),
    placeholder(NID_id_pkix_OCSP_noCheck, 0),
    placeholder(NID_id_pkix_OCSP_archiveCutoff, 0),
    placeholder(NID_id_pkix_OCSP_serviceLocator, 0),
];

/// Every built-in method, in no order.
pub(crate) fn methods() -> impl Iterator<Item = &'static Method> {
    [
        &simple::NSCERT,
        &simple::KEY_USAGE_METHOD,
        &simple::SKEY_ID,
        &simple::PKEY_USAGE_PERIOD_METHOD,
        &simple::BCONS,
        &simple::CRL_NUM,
        &simple::EXT_KU,
        &simple::DELTA_CRL,
        &simple::CRL_REASON,
        &simple::OCSP_ACCRESP,
        &simple::INHIBIT_ANYP,
        &simple::SIGN_TOOL,
        &simple::ACC_CERT_POLICIES,
        &simple::ACC_PRIV_POLICIES,
        &san::SUBJECT_ALT,
        &san::ISSUER_ALT,
        &san::CERT_ISSUER,
        &akid::AKEY_ID,
        &info::INFO,
        &info::SINFO,
        &crld::CRLD,
        &crld::FRESHEST_CRL,
        &crld::IDP,
        &crld::CRL_INVDATE,
        &crld::CRL_HOLD,
        &policy::CPOLS,
        &policy::POLICY_MAPPINGS,
        &policy::POLICY_CONSTRAINTS_METHOD,
        &policy::PCI,
        &policy::NAME_CONSTRAINTS_METHOD,
        &policy::HOLDER_NAME_CONSTRAINTS,
        &policy::DELEGATED_NAME_CONSTRAINTS,
        &misc::SXNET_METHOD,
        &misc::TLS_FEATURE_METHOD,
        &misc::ISSUER_SIGN_TOOL_METHOD,
        &misc::AUDIT_IDENTITY,
        &rfc3779::ADDR,
        &crate::ct::PRECERT_SCTS,
        &crate::ct::POISON,
        &crate::ct::CERT_SCTS,
        &rfc3779::ASID,
        &admission::ADMISSION,
        &crld::AA_ISSUING_DIST_POINT,
        &acext::INDIRECT_ISSUER,
        &acext::NO_ASSERTION,
        &acext::SOA_IDENTIFIER,
        &acext::GROUP_AC,
        &acext::NO_REV_AVAIL,
        &acext::SINGLE_USE,
        &acext::TARGETING_INFORMATION,
        &acext::AUTHORITY_ATTRIBUTE_ID,
        &acext::BASIC_ATTR_CONSTRAINTS,
        &acext::ISSUED_ON_BEHALF_OF,
        &acext::ROLE_SPEC_CERT_ID,
        &acext::SUBJECT_DIRECTORY_ATTRIBUTES,
        &acext::ASSOCIATED_INFORMATION,
        &acext::USER_NOTICE,
        &attrdesc::ATTRIBUTE_DESCRIPTOR,
        &attrdesc::ATTRIBUTE_MAPPINGS,
        &attrdesc::ALLOWED_ATTRIBUTE_ASSIGNMENTS,
        &timespec::TIME_SPEC,
    ]
    .into_iter()
    .chain(simple::NS_IA5.iter())
    .chain(LATER.iter())
}
