//! Fuzzes the extension methods on untrusted values: the first octet picks an extension whose
//! method is in, and the rest is its value. The value is printed under each unknown-extension
//! flag, decoded with X509V3_EXT_d2i, and encoded again with X509V3_EXT_i2d. Nothing may
//! crash or read out of bounds (ASan).

#![no_main]

use core::ffi::{c_int, c_ulong, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{self as abi, ASN1_ITEM, ASN1_OCTET_STRING, BIO, BIO_METHOD, X509_EXTENSION, X509V3_EXT_METHOD};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn ASN1_OCTET_STRING_new() -> *mut ASN1_OCTET_STRING;
    fn ASN1_OCTET_STRING_set(s: *mut ASN1_OCTET_STRING, d: *const u8, len: c_int) -> c_int;
    fn ASN1_OCTET_STRING_free(s: *mut ASN1_OCTET_STRING);
    fn X509_EXTENSION_create_by_NID(ex: *mut *mut X509_EXTENSION, nid: c_int, crit: c_int, data: *mut ASN1_OCTET_STRING) -> *mut X509_EXTENSION;
    fn X509_EXTENSION_free(e: *mut X509_EXTENSION);
    fn X509V3_EXT_print(out: *mut BIO, ext: *mut X509_EXTENSION, flag: c_ulong, indent: c_int) -> c_int;
    fn X509V3_EXT_d2i(ext: *mut X509_EXTENSION) -> *mut c_void;
    fn X509V3_EXT_i2d(nid: c_int, crit: c_int, value: *mut c_void) -> *mut X509_EXTENSION;
    fn X509V3_EXT_get_nid(nid: c_int) -> *const X509V3_EXT_METHOD;
    fn ASN1_item_free(v: *mut c_void, it: *const ASN1_ITEM);
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn ERR_clear_error();
}

/// The extensions whose methods are in: key usage, Netscape's certificate type and strings,
/// the signing tool, the CRL numbers and reason, inhibitAnyPolicy, the subject key identifier,
/// basic constraints, the extended key usages, the private key usage period, the alternative
/// names, the key identifier, the information access and distribution point extensions, the
/// CRL entries' extensions, the policy and constraint extensions, the smaller ones (SXNET, the
/// TLS feature, the signing tools, the audit identity), RFC 3779's, the admission, and one
/// without a method (commonName).
const NIDS: [c_int; 46] = [
    abi::NID_key_usage,
    abi::NID_netscape_cert_type,
    abi::NID_netscape_base_url,
    abi::NID_netscape_revocation_url,
    abi::NID_netscape_ca_revocation_url,
    abi::NID_netscape_renewal_url,
    abi::NID_netscape_ca_policy_url,
    abi::NID_netscape_ssl_server_name,
    abi::NID_netscape_comment,
    abi::NID_subjectSignTool,
    abi::NID_crl_number,
    abi::NID_delta_crl,
    abi::NID_crl_reason,
    abi::NID_inhibit_any_policy,
    abi::NID_subject_key_identifier,
    abi::NID_basic_constraints,
    abi::NID_ext_key_usage,
    abi::NID_id_pkix_OCSP_acceptableResponses,
    abi::NID_private_key_usage_period,
    abi::NID_acceptable_cert_policies,
    abi::NID_subject_alt_name,
    abi::NID_issuer_alt_name,
    abi::NID_certificate_issuer,
    abi::NID_authority_key_identifier,
    abi::NID_info_access,
    abi::NID_sinfo_access,
    abi::NID_crl_distribution_points,
    abi::NID_freshest_crl,
    abi::NID_issuing_distribution_point,
    abi::NID_invalidity_date,
    abi::NID_hold_instruction_code,
    abi::NID_certificate_policies,
    abi::NID_policy_mappings,
    abi::NID_policy_constraints,
    abi::NID_proxyCertInfo,
    abi::NID_name_constraints,
    abi::NID_holder_name_constraints,
    abi::NID_delegated_name_constraints,
    abi::NID_sxnet,
    abi::NID_tlsfeature,
    abi::NID_issuerSignTool,
    abi::NID_ac_auditIdentity,
    abi::NID_sbgp_ipAddrBlock,
    abi::NID_sbgp_autonomousSysNum,
    abi::NID_x509ExtAdmission,
    abi::NID_commonName,
];

/// The unknown-extension flags.
const FLAGS: [c_ulong; 4] = [
    abi::X509V3_EXT_DEFAULT as c_ulong,
    abi::X509V3_EXT_ERROR_UNKNOWN as c_ulong,
    abi::X509V3_EXT_PARSE_UNKNOWN as c_ulong,
    abi::X509V3_EXT_DUMP_UNKNOWN as c_ulong,
];

fuzz_target!(|data: &[u8]| {
    let Some((&pick, value)) = data.split_first() else { return };
    let nid = NIDS[usize::from(pick) % NIDS.len()];
    let Ok(len) = c_int::try_from(value.len()) else { return };
    // SAFETY: the value, read within its length; the strings, extensions, and BIO made here,
    // freed.
    unsafe {
        let os = ASN1_OCTET_STRING_new();
        ASN1_OCTET_STRING_set(os, value.as_ptr(), len);
        let ext = X509_EXTENSION_create_by_NID(ptr::null_mut(), nid, 0, os);
        ASN1_OCTET_STRING_free(os);
        if ext.is_null() {
            ERR_clear_error();
            return;
        }
        let bio = BIO_new(BIO_s_mem());
        for f in FLAGS {
            X509V3_EXT_print(bio, ext, f, 2);
        }
        BIO_free(bio);
        let v = X509V3_EXT_d2i(ext);
        if !v.is_null() {
            X509_EXTENSION_free(X509V3_EXT_i2d(nid, 1, v));
            let m = X509V3_EXT_get_nid(nid);
            if let Some(it) = (*m).it {
                ASN1_item_free(v, it());
            }
        }
        X509_EXTENSION_free(ext);
        ERR_clear_error();
    }
});
