//! The built-in methods (`standard_exts.h`): one for each extension OpenSSL knows. Those of
//! the extensions whose types come later in step 5.2 have only their NIDs, and functions that
//! abort when called (AGENTS.md rule 10).

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};

use rustyssl_abi::{
    BIO, NID_ac_auditIdentity, NID_allowed_attribute_assignments, NID_associated_information,
    NID_attribute_descriptor, NID_attribute_mappings, NID_authority_attribute_identifier,
    NID_basic_att_constraints, NID_certificate_policies, NID_ct_cert_scts, NID_ct_precert_poison,
    NID_ct_precert_scts, NID_delegated_name_constraints, NID_group_ac, NID_holder_name_constraints,
    NID_id_aa_issuing_distribution_point, NID_id_pkix_OCSP_CrlID, NID_id_pkix_OCSP_Nonce,
    NID_id_pkix_OCSP_archiveCutoff, NID_id_pkix_OCSP_noCheck, NID_id_pkix_OCSP_serviceLocator,
    NID_indirect_issuer, NID_issued_on_behalf_of, NID_issuerSignTool, NID_name_constraints,
    NID_no_assertion, NID_no_rev_avail, NID_policy_constraints, NID_policy_mappings,
    NID_proxyCertInfo, NID_role_spec_cert_identifier, NID_sbgp_autonomousSysNum,
    NID_sbgp_ipAddrBlock, NID_single_use, NID_soa_identifier, NID_subject_directory_attributes,
    NID_sxnet, NID_target_information, NID_time_specification, NID_tlsfeature, NID_user_notice,
    NID_x509ExtAdmission, X509V3_CTX, X509V3_EXT_METHOD, X509V3_EXT_MULTILINE, stack_st_CONF_VALUE,
};

use super::registry::{Method, method};
use super::{akid, crld, info, san, simple};

fn later() -> ! {
    crate::stub::unimplemented("an X509v3 extension method of a later part of step 5.2")
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

static LATER: [Method; 41] = [
    placeholder(NID_certificate_policies, 0),
    placeholder(NID_sxnet, X509V3_EXT_MULTILINE),
    placeholder(NID_ac_auditIdentity, 0),
    placeholder(NID_sbgp_ipAddrBlock, 0),
    placeholder(NID_sbgp_autonomousSysNum, 0),
    placeholder(NID_id_pkix_OCSP_Nonce, 0),
    placeholder(NID_id_pkix_OCSP_CrlID, 0),
    placeholder(NID_id_pkix_OCSP_noCheck, 0),
    placeholder(NID_id_pkix_OCSP_archiveCutoff, 0),
    placeholder(NID_id_pkix_OCSP_serviceLocator, 0),
    placeholder(NID_policy_constraints, 0),
    placeholder(NID_target_information, 0),
    placeholder(NID_no_rev_avail, 0),
    placeholder(NID_proxyCertInfo, 0),
    placeholder(NID_name_constraints, 0),
    placeholder(NID_policy_mappings, 0),
    placeholder(NID_subject_directory_attributes, X509V3_EXT_MULTILINE),
    placeholder(NID_ct_precert_scts, 0),
    placeholder(NID_ct_precert_poison, 0),
    placeholder(NID_ct_cert_scts, 0),
    placeholder(NID_issuerSignTool, X509V3_EXT_MULTILINE),
    placeholder(NID_tlsfeature, 0),
    placeholder(NID_x509ExtAdmission, 0),
    placeholder(NID_authority_attribute_identifier, X509V3_EXT_MULTILINE),
    placeholder(NID_role_spec_cert_identifier, X509V3_EXT_MULTILINE),
    placeholder(NID_basic_att_constraints, 0),
    placeholder(NID_delegated_name_constraints, 0),
    placeholder(NID_time_specification, X509V3_EXT_MULTILINE),
    placeholder(NID_attribute_descriptor, X509V3_EXT_MULTILINE),
    placeholder(NID_user_notice, 0),
    placeholder(NID_soa_identifier, 0),
    placeholder(NID_indirect_issuer, 0),
    placeholder(NID_no_assertion, 0),
    placeholder(NID_id_aa_issuing_distribution_point, 0),
    placeholder(NID_issued_on_behalf_of, 0),
    placeholder(NID_single_use, 0),
    placeholder(NID_group_ac, 0),
    placeholder(NID_allowed_attribute_assignments, 0),
    placeholder(NID_attribute_mappings, X509V3_EXT_MULTILINE),
    placeholder(NID_holder_name_constraints, 0),
    placeholder(NID_associated_information, X509V3_EXT_MULTILINE),
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
    ]
    .into_iter()
    .chain(simple::NS_IA5.iter())
    .chain(LATER.iter())
}
