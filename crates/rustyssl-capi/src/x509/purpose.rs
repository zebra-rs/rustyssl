//! The certificate's extension cache and purposes (`v3_purp.c`; `X509_cmp`, `X509_add_cert`,
//! and `X509_self_signed` of `x509_cmp.c` and `x509_vfy.c`; the signature information of
//! `x509_set.c`).
//!
//! As OpenSSL's:
//! - The cache is filled once, under the certificate's lock, on first use: the SHA-1
//!   fingerprint, the flags (`EXFLAG_*`), the key usages, path lengths, key identifiers,
//!   alternative names, name constraints, distribution points, RFC 3779 resources, and the
//!   signature information. A certificate whose extensions don't decode (or say something
//!   impossible: a negative path length, an empty key usage) is `EXFLAG_INVALID`, and the
//!   functions that need the cache fail for it.
//! - Changing a certificate afterwards doesn't refresh the cache; decoding into it does.
//! - The purposes are OpenSSL's table, which applications can add to or change
//!   (`X509_PURPOSE_add`); like OpenSSL's, that table isn't for changing while other threads
//!   use it.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;
use std::sync::Mutex;

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_INTEGER, ASN1_OCTET_STRING, ASN1_STRING, AUTHORITY_KEYID,
    BASIC_CONSTRAINTS, CRLDP_ALL_REASONS, DIST_POINT, ERR_LIB_X509, ERR_LIB_X509V3,
    ERR_R_CRYPTO_LIB, ERR_R_PASSED_INVALID_ARGUMENT, ERR_R_PASSED_NULL_PARAMETER, EVP_PKEY,
    EXFLAG_AKID_CRITICAL, EXFLAG_BCONS, EXFLAG_BCONS_CRITICAL, EXFLAG_CA, EXFLAG_CRITICAL,
    EXFLAG_FRESHEST, EXFLAG_INVALID, EXFLAG_KUSAGE, EXFLAG_NO_FINGERPRINT, EXFLAG_NSCERT,
    EXFLAG_PROXY, EXFLAG_SAN_CRITICAL, EXFLAG_SET, EXFLAG_SI, EXFLAG_SKID_CRITICAL, EXFLAG_SS,
    EXFLAG_V1, EXFLAG_XKUSAGE, GEN_DIRNAME, GENERAL_NAME, GENERAL_NAMES, KU_CRL_SIGN,
    KU_DIGITAL_SIGNATURE, KU_KEY_AGREEMENT, KU_KEY_CERT_SIGN, KU_KEY_ENCIPHERMENT,
    KU_NON_REPUDIATION, NID_OCSP_sign, NID_anyExtendedKeyUsage, NID_authority_key_identifier,
    NID_basic_constraints, NID_certificate_policies, NID_client_auth, NID_code_sign,
    NID_crl_distribution_points, NID_dvcs, NID_email_protect, NID_ext_key_usage, NID_freshest_crl,
    NID_id_GostR3411_94, NID_id_pkix_OCSP_noCheck, NID_inhibit_any_policy, NID_issuer_alt_name,
    NID_key_usage, NID_md5, NID_ms_sgc, NID_name_constraints, NID_netscape_cert_type, NID_ns_sgc,
    NID_policy_constraints, NID_policy_mappings, NID_proxyCertInfo, NID_rsassaPss,
    NID_sbgp_autonomousSysNum, NID_sbgp_ipAddrBlock, NID_server_auth, NID_sha1, NID_sha256,
    NID_sha384, NID_sha512, NID_subject_alt_name, NID_subject_key_identifier, NID_time_stamp,
    NID_undef, NS_ANY_CA, NS_SMIME, NS_SMIME_CA, NS_SSL_CA, NS_SSL_CLIENT, NS_SSL_SERVER,
    PROXY_CERT_INFO_EXTENSION, V_ASN1_NEG_INTEGER, X509, X509_ADD_FLAG_NO_DUP, X509_ADD_FLAG_NO_SS,
    X509_ADD_FLAG_PREPEND, X509_ADD_FLAG_UP_REF, X509_ALGOR, X509_EXTENSION, X509_PURPOSE,
    X509_PURPOSE_ANY, X509_PURPOSE_CODE_SIGN, X509_PURPOSE_CRL_SIGN, X509_PURPOSE_DEFAULT_ANY,
    X509_PURPOSE_DYNAMIC, X509_PURPOSE_DYNAMIC_NAME, X509_PURPOSE_MAX, X509_PURPOSE_MIN,
    X509_PURPOSE_NS_SSL_SERVER, X509_PURPOSE_OCSP_HELPER, X509_PURPOSE_SMIME_ENCRYPT,
    X509_PURPOSE_SMIME_SIGN, X509_PURPOSE_SSL_CLIENT, X509_PURPOSE_SSL_SERVER,
    X509_PURPOSE_TIMESTAMP_SIGN, X509_R_ERROR_GETTING_MD_BY_NID, X509_R_ERROR_USING_SIGINF_SET,
    X509_R_INVALID_DISTPOINT, X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY, X509_R_UNKNOWN_SIGID_ALGS,
    X509_SIG_INFO, X509_SIG_INFO_TLS, X509_SIG_INFO_VALID, X509_TRUST_COMPAT, X509_TRUST_DEFAULT,
    X509_TRUST_EMAIL, X509_TRUST_OBJECT_SIGN, X509_TRUST_SSL_CLIENT, X509_TRUST_SSL_SERVER,
    X509_TRUST_TSA, X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH, X509_V_ERR_AKID_SKID_MISMATCH,
    X509_V_ERR_KEYUSAGE_NO_CERTSIGN, X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE,
    X509_V_ERR_NO_ISSUER_PUBLIC_KEY, X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH,
    X509_V_ERR_SUBJECT_ISSUER_MISMATCH, X509_V_ERR_UNSPECIFIED,
    X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM, X509_V_OK, X509_VERSION_1,
    X509V3_R_EMPTY_KEY_USAGE, X509V3_R_INVALID_CERTIFICATE, X509V3_R_INVALID_PURPOSE,
    X509V3_R_NEGATIVE_PATHLEN, X509V3_R_PURPOSE_NOT_UNIQUE, XKU_ANYEKU, XKU_CODE_SIGN, XKU_DVCS,
    XKU_OCSP_SIGN, XKU_SGC, XKU_SMIME, XKU_SSL_CLIENT, XKU_SSL_SERVER, XKU_TIMESTAMP,
    stack_st_X509,
};

use crate::asn1::integer::{ASN1_INTEGER_cmp, ASN1_INTEGER_get};
use crate::asn1::string::{ASN1_BIT_STRING_free, ASN1_OCTET_STRING_cmp, ASN1_OCTET_STRING_free};
use crate::err;
use crate::evp::digest::EVP_MD_get_size;
use crate::evp::pkey::ameth::EVP_PKEY_asn1_find;
use crate::evp::pkey::{EVP_PKEY_get_security_bits, EVP_PKEY_is_a};
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::objects::sigid::OBJ_find_sigid_algs;
use crate::objects::{ASN1_OBJECT_free, OBJ_nid2sn, OBJ_obj2nid};
use crate::stack::{
    OPENSSL_sk_find, OPENSSL_sk_insert, OPENSSL_sk_new, OPENSSL_sk_num, OPENSSL_sk_pop_free,
    OPENSSL_sk_push, OPENSSL_sk_set, OPENSSL_sk_value,
};
use crate::threads::{CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock};
use crate::x509::cert::{
    Cert, X509_digest, X509_free, X509_get_ext, X509_get_ext_by_NID, X509_get_ext_count,
    X509_get_issuer_name, X509_get_subject_name, X509_get_version, X509_get0_pubkey,
    X509_get0_serialNumber, X509_up_ref, X509_verify, cert_of,
};
use crate::x509::ext::{X509_EXTENSION_get_critical, X509_EXTENSION_get_object};
use crate::x509::name::X509_NAME_cmp;
use crate::x509v3::akid::AUTHORITY_KEYID_free;
use crate::x509v3::crld::CRL_DIST_POINTS_free;
use crate::x509v3::genn::GENERAL_NAMES_free;
use crate::x509v3::policy::{NAME_CONSTRAINTS_free, PROXY_CERT_INFO_EXTENSION_free};
use crate::x509v3::registry::X509V3_get_d2i;
use crate::x509v3::rfc3779::{ASIdentifiers_free, free_family};
use crate::x509v3::simple::BASIC_CONSTRAINTS_free;

/// A flag as `ex_flags` holds it.
const fn f(x: c_int) -> u32 {
    x.cast_unsigned()
}

/// `X509_SIG_INFO`, which is opaque in OpenSSL's headers.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SigInfo {
    mdnid: c_int,
    pknid: c_int,
    secbits: c_int,
    flags: u32,
}

/// What `ossl_x509v3_cache_extensions` fills in, in the certificate.
#[repr(C)]
pub(crate) struct Cache {
    pub(crate) flags: u32,
    kusage: u32,
    xkusage: u32,
    nscert: u32,
    pathlen: c_long,
    pcpathlen: c_long,
    sha1: [u8; 20],
    pub(crate) skid: *mut ASN1_OCTET_STRING,
    pub(crate) akid: *mut AUTHORITY_KEYID,
    pub(crate) altname: *mut GENERAL_NAMES,
    pub(crate) nc: *mut rustyssl_abi::NAME_CONSTRAINTS,
    pub(crate) crldp: *mut rustyssl_abi::CRL_DIST_POINTS,
    pub(crate) addr: *mut rustyssl_abi::IPAddrBlocks,
    pub(crate) asid: *mut rustyssl_abi::ASIdentifiers,
    siginf: SigInfo,
}

impl Cache {
    /// `x509_cb`'s reset: nothing cached, the path lengths -1.
    pub(crate) fn reset(&mut self) {
        self.flags = 0;
        self.kusage = 0;
        self.xkusage = 0;
        self.nscert = 0;
        self.pathlen = -1;
        self.pcpathlen = -1;
        self.skid = ptr::null_mut();
        self.akid = ptr::null_mut();
        self.altname = ptr::null_mut();
        self.nc = ptr::null_mut();
        self.crldp = ptr::null_mut();
        self.addr = ptr::null_mut();
        self.asid = ptr::null_mut();
    }

    /// The cached SHA-1 fingerprint, once the cache is filled with one.
    pub(crate) fn sha1_fingerprint(&self) -> Option<[u8; 20]> {
        (self.flags & f(EXFLAG_SET) != 0 && self.flags & f(EXFLAG_NO_FINGERPRINT) == 0)
            .then_some(self.sha1)
    }

    /// Frees what it holds (then [`Cache::reset`] it).
    pub(crate) fn free(&mut self) {
        // SAFETY: its own, or NULL.
        unsafe { ASN1_OCTET_STRING_free(self.skid) };
        // SAFETY: as above.
        unsafe { AUTHORITY_KEYID_free(self.akid) };
        // SAFETY: as above.
        unsafe { CRL_DIST_POINTS_free(self.crldp) };
        // SAFETY: as above.
        unsafe { GENERAL_NAMES_free(self.altname) };
        // SAFETY: as above.
        unsafe { NAME_CONSTRAINTS_free(self.nc) };
        // SAFETY: as above, with its families.
        unsafe { OPENSSL_sk_pop_free(self.addr.cast(), Some(free_family)) };
        // SAFETY: as above.
        unsafe { ASIdentifiers_free(self.asid) };
        self.reset();
    }
}

ffi_export! {
    /// The decoded extension of `nid` (see `X509V3_get_d2i`), or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `crit` and `idx` are NULL or writable.
    pub unsafe extern "C" fn X509_get_ext_d2i(x: *const X509, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let exts = unsafe { cert_of(x) }.map_or(ptr::null_mut(), |c| c.cert_info.extensions);
        // SAFETY: the extensions, or NULL; the caller's slots.
        unsafe { X509V3_get_d2i(exts, nid, crit, idx) }
    }
}

/// `X509_supported_extension`'s NIDs, sorted (`tests::supported_is_sorted`).
const SUPPORTED: [c_int; 15] = [
    NID_netscape_cert_type,
    NID_key_usage,
    NID_subject_alt_name,
    NID_basic_constraints,
    NID_certificate_policies,
    NID_crl_distribution_points,
    NID_ext_key_usage,
    NID_sbgp_ipAddrBlock,
    NID_sbgp_autonomousSysNum,
    NID_id_pkix_OCSP_noCheck,
    NID_policy_constraints,
    NID_proxyCertInfo,
    NID_name_constraints,
    NID_policy_mappings,
    NID_inhibit_any_policy,
];

ffi_export! {
    /// Whether the extension is one path validation understands (and so may be critical): 1,
    /// or 0.
    ///
    /// # Safety
    /// `ex` is NULL or a live extension.
    pub unsafe extern "C" fn X509_supported_extension(ex: *mut X509_EXTENSION) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let obj = unsafe { X509_EXTENSION_get_object(ex) };
        // SAFETY: its object, or NULL.
        let nid = unsafe { OBJ_obj2nid(obj) };
        c_int::from(nid != NID_undef && SUPPORTED.binary_search(&nid).is_ok())
    }
}

/// `setup_dp`: a distribution point's reasons as flags (all for none).
fn setup_dp(dp: &mut DIST_POINT) -> bool {
    // SAFETY: its names, or NULL.
    if dp.distpoint.is_null() && unsafe { OPENSSL_sk_num(dp.CRLissuer.cast()) } <= 0 {
        err::raise(ERR_LIB_X509, X509_R_INVALID_DISTPOINT, "setup_dp");
        return false;
    }
    // SAFETY: its reasons, or NULL.
    dp.dp_reasons = match unsafe { dp.reasons.as_ref() } {
        Some(r) => c_int::try_from(bits16(r, true)).unwrap_or(0) & CRLDP_ALL_REASONS,
        None => CRLDP_ALL_REASONS,
    };
    true
}

/// `check_sig_alg_match`: whether the issuer's key is of the subject's signature algorithm's
/// type.
///
/// # Safety
/// `issuer_key` is NULL or a live key.
unsafe fn check_sig_alg_match(issuer_key: *const EVP_PKEY, subject: &Cert) -> c_int {
    if issuer_key.is_null() {
        return X509_V_ERR_NO_ISSUER_PUBLIC_KEY;
    }
    let mut pknid = NID_undef;
    // SAFETY: the subject's signature algorithm; a writable NID.
    let alg = unsafe { OBJ_obj2nid(subject.cert_info.signature.algorithm) };
    // SAFETY: as above.
    if unsafe { OBJ_find_sigid_algs(alg, ptr::null_mut(), &raw mut pknid) } == 0 {
        return X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM;
    }
    // SAFETY: the key; a static name, or NULL.
    let is = |name: *const c_char| unsafe { EVP_PKEY_is_a(issuer_key, name) } != 0;
    // SAFETY: no preconditions.
    if is(unsafe { OBJ_nid2sn(pknid) }) || (is(c"RSA".as_ptr()) && pknid == NID_rsassaPss) {
        return X509_V_OK;
    }
    X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH
}

/// `x509_sig_info_init`.
///
/// # Safety
/// `alg`, `sig`, and `pubkey` are live or (`pubkey`) NULL.
unsafe fn sig_info_init(
    siginf: &mut SigInfo,
    alg: *const X509_ALGOR,
    sig: *const ASN1_STRING,
    pubkey: *const EVP_PKEY,
) -> bool {
    const F: &str = "x509_sig_info_init";
    *siginf = SigInfo {
        mdnid: NID_undef,
        pknid: NID_undef,
        secbits: -1,
        flags: 0,
    };
    let (mut mdnid, mut pknid) = (NID_undef, NID_undef);
    // SAFETY: the caller's algorithm.
    let obj = unsafe { (*alg).algorithm };
    // SAFETY: its object.
    let nid = unsafe { OBJ_obj2nid(obj) };
    // SAFETY: writable NIDs.
    if unsafe { OBJ_find_sigid_algs(nid, &raw mut mdnid, &raw mut pknid) } == 0
        || pknid == NID_undef
    {
        err::raise(ERR_LIB_X509, X509_R_UNKNOWN_SIGID_ALGS, F);
        return false;
    }
    siginf.mdnid = mdnid;
    siginf.pknid = pknid;
    match mdnid {
        n if n == NID_undef => {
            // SAFETY: no preconditions.
            let ameth = unsafe { EVP_PKEY_asn1_find(ptr::null_mut(), pknid) };
            // SAFETY: a method, or NULL.
            let set = unsafe { crate::evp::pkey::ameth::siginf_set_of(ameth) };
            let set_ok = set.is_some_and(|set| {
                // SAFETY: the method's function, given the information and the signature.
                (unsafe { set(ptr::from_mut(siginf).cast(), alg, sig) } != 0)
            });
            if !set_ok {
                let bits = if pubkey.is_null() {
                    0
                } else {
                    // SAFETY: the key.
                    unsafe { EVP_PKEY_get_security_bits(pubkey) }
                };
                if bits == 0 {
                    err::raise(ERR_LIB_X509, X509_R_ERROR_USING_SIGINF_SET, F);
                    return false;
                }
                siginf.secbits = bits;
            }
        }
        n if n == NID_sha1 => siginf.secbits = 63,
        n if n == NID_md5 => siginf.secbits = 39,
        n if n == NID_id_GostR3411_94 => siginf.secbits = 105,
        _ => {
            // SAFETY: no preconditions.
            let sn = unsafe { OBJ_nid2sn(mdnid) };
            // SAFETY: a static name, or NULL.
            let md = unsafe { crate::evp::legacy_md::EVP_get_digestbyname(sn) };
            if md.is_null() {
                err::raise(ERR_LIB_X509, X509_R_ERROR_GETTING_MD_BY_NID, F);
                return false;
            }
            // SAFETY: the digest.
            let size = unsafe { EVP_MD_get_size(md) };
            if size <= 0 {
                return false;
            }
            siginf.secbits = size.saturating_mul(4);
        }
    }
    if [NID_sha1, NID_sha256, NID_sha384, NID_sha512].contains(&mdnid) {
        siginf.flags |= f(X509_SIG_INFO_TLS);
    }
    siginf.flags |= f(X509_SIG_INFO_VALID);
    true
}

/// A bit string's first one or two octets as flags, or 0.
fn bits16(bs: &ASN1_BIT_STRING, two: bool) -> u32 {
    let n = usize::try_from(bs.length).unwrap_or(0);
    if n == 0 || bs.data.is_null() {
        return 0;
    }
    // SAFETY: a string's data holds its length.
    let d = unsafe { core::slice::from_raw_parts(bs.data, n) };
    let mut v = u32::from(d.first().copied().unwrap_or(0));
    if two && let Some(&b) = d.get(1) {
        v |= u32::from(b) << 8;
    }
    v
}

/// The cache's fill, under the lock: its flags (with `EXFLAG_SET`).
///
/// # Safety
/// `xp` and `x` are the same live certificate.
unsafe fn fill(xp: *mut X509, x: &mut Cert) {
    let c = &mut x.cache;
    let mut i: c_int = 0;
    // SAFETY: no preconditions.
    let sha1 = unsafe { crate::evp::legacy_md::EVP_sha1() };
    // SAFETY: the certificate; its fingerprint's buffer.
    if unsafe { X509_digest(xp, sha1, c.sha1.as_mut_ptr(), ptr::null_mut()) } == 0 {
        c.flags |= f(EXFLAG_NO_FINGERPRINT);
    }
    // SAFETY: the certificate.
    if unsafe { X509_get_version(xp) } == c_long::from(X509_VERSION_1) {
        c.flags |= f(EXFLAG_V1);
    }
    c.pathlen = -1;
    let exts = x.cert_info.extensions;
    // SAFETY: the certificate's extensions; a slot.
    let d2i = |nid: c_int, i: &mut c_int| unsafe { X509V3_get_d2i(exts, nid, i, ptr::null_mut()) };
    let c = &mut x.cache;
    let bs = d2i(NID_basic_constraints, &mut i).cast::<BASIC_CONSTRAINTS>();
    // SAFETY: decoded, or NULL.
    if let Some(b) = unsafe { bs.as_ref() } {
        if b.ca != 0 {
            c.flags |= f(EXFLAG_CA);
        }
        // SAFETY: its path length, or NULL.
        if let Some(p) = unsafe { b.pathlen.as_ref() } {
            if p.type_ == V_ASN1_NEG_INTEGER {
                err::raise(
                    ERR_LIB_X509V3,
                    X509V3_R_NEGATIVE_PATHLEN,
                    "ossl_x509v3_cache_extensions",
                );
                c.flags |= f(EXFLAG_INVALID);
            } else {
                // SAFETY: as above.
                c.pathlen = unsafe { ASN1_INTEGER_get(b.pathlen) };
            }
        }
        // SAFETY: decoded above.
        unsafe { BASIC_CONSTRAINTS_free(bs) };
        c.flags |= f(EXFLAG_BCONS);
    } else if i != -1 {
        c.flags |= f(EXFLAG_INVALID);
    }
    let pci = d2i(NID_proxyCertInfo, &mut i).cast::<PROXY_CERT_INFO_EXTENSION>();
    // SAFETY: decoded, or NULL.
    if let Some(p) = unsafe { pci.as_ref() } {
        // SAFETY: the certificate.
        let names = unsafe { X509_get_ext_by_NID(xp, NID_subject_alt_name, -1) } >= 0
            // SAFETY: as above.
            || unsafe { X509_get_ext_by_NID(xp, NID_issuer_alt_name, -1) } >= 0;
        if c.flags & f(EXFLAG_CA) != 0 || names {
            c.flags |= f(EXFLAG_INVALID);
        }
        c.pcpathlen = if p.pcPathLengthConstraint.is_null() {
            -1
        } else {
            // SAFETY: its path length.
            unsafe { ASN1_INTEGER_get(p.pcPathLengthConstraint) }
        };
        // SAFETY: decoded above.
        unsafe { PROXY_CERT_INFO_EXTENSION_free(pci) };
        c.flags |= f(EXFLAG_PROXY);
    } else if i != -1 {
        c.flags |= f(EXFLAG_INVALID);
    }
    let usage = d2i(NID_key_usage, &mut i).cast::<ASN1_BIT_STRING>();
    // SAFETY: decoded, or NULL.
    if let Some(u) = unsafe { usage.as_ref() } {
        c.kusage = bits16(u, true);
        c.flags |= f(EXFLAG_KUSAGE);
        // SAFETY: decoded above.
        unsafe { ASN1_BIT_STRING_free(usage) };
        if c.kusage == 0 {
            err::raise(
                ERR_LIB_X509V3,
                X509V3_R_EMPTY_KEY_USAGE,
                "ossl_x509v3_cache_extensions",
            );
            c.flags |= f(EXFLAG_INVALID);
        }
    } else if i != -1 {
        c.flags |= f(EXFLAG_INVALID);
    }
    c.xkusage = 0;
    let eku = d2i(NID_ext_key_usage, &mut i);
    if !eku.is_null() {
        c.flags |= f(EXFLAG_XKUSAGE);
        // SAFETY: the decoded list of objects.
        for k in 0..unsafe { OPENSSL_sk_num(eku.cast()) } {
            // SAFETY: an index within it.
            let obj = unsafe { OPENSSL_sk_value(eku.cast(), k) };
            // SAFETY: an object of it.
            let nid = unsafe { OBJ_obj2nid(obj.cast()) };
            let bit = match nid {
                n if n == NID_server_auth => XKU_SSL_SERVER,
                n if n == NID_client_auth => XKU_SSL_CLIENT,
                n if n == NID_email_protect => XKU_SMIME,
                n if n == NID_code_sign => XKU_CODE_SIGN,
                n if n == NID_ms_sgc || n == NID_ns_sgc => XKU_SGC,
                n if n == NID_OCSP_sign => XKU_OCSP_SIGN,
                n if n == NID_time_stamp => XKU_TIMESTAMP,
                n if n == NID_dvcs => XKU_DVCS,
                n if n == NID_anyExtendedKeyUsage => XKU_ANYEKU,
                _ => 0,
            };
            c.xkusage |= f(bit);
        }
        // SAFETY: decoded above, with its objects.
        unsafe { OPENSSL_sk_pop_free(eku.cast(), Some(free_object)) };
    } else if i != -1 {
        c.flags |= f(EXFLAG_INVALID);
    }
    let ns = d2i(NID_netscape_cert_type, &mut i).cast::<ASN1_BIT_STRING>();
    // SAFETY: decoded, or NULL.
    if let Some(n) = unsafe { ns.as_ref() } {
        c.nscert = bits16(n, false);
        c.flags |= f(EXFLAG_NSCERT);
        // SAFETY: decoded above.
        unsafe { ASN1_BIT_STRING_free(ns) };
    } else if i != -1 {
        c.flags |= f(EXFLAG_INVALID);
    }
    c.skid = d2i(NID_subject_key_identifier, &mut i).cast();
    if c.skid.is_null() && i != -1 {
        c.flags |= f(EXFLAG_INVALID);
    }
    c.akid = d2i(NID_authority_key_identifier, &mut i).cast();
    if c.akid.is_null() && i != -1 {
        c.flags |= f(EXFLAG_INVALID);
    }
    // SAFETY: the certificate.
    let (subject, issuer) = (unsafe { X509_get_subject_name(xp) }, unsafe {
        X509_get_issuer_name(xp)
    });
    // SAFETY: its names.
    if unsafe { X509_NAME_cmp(subject, issuer) } == 0 {
        c.flags |= f(EXFLAG_SI);
        let akid = c.akid;
        // SAFETY: the certificate.
        let key = unsafe { X509_get0_pubkey(xp) }.cast_const();
        // SAFETY: the certificate; its key identifier, or NULL.
        if unsafe { X509_check_akid(xp, akid) } == X509_V_OK
            // SAFETY: its key, or NULL.
            && unsafe { check_sig_alg_match(key, x) } == X509_V_OK
        {
            x.cache.flags |= f(EXFLAG_SS);
        }
    }
    let c = &mut x.cache;
    c.altname = d2i(NID_subject_alt_name, &mut i).cast();
    if c.altname.is_null() && i != -1 {
        c.flags |= f(EXFLAG_INVALID);
    }
    c.nc = d2i(NID_name_constraints, &mut i).cast();
    if c.nc.is_null() && i != -1 {
        c.flags |= f(EXFLAG_INVALID);
    }
    // `setup_crldp`.
    c.crldp = d2i(NID_crl_distribution_points, &mut i).cast();
    let mut crldp_ok = !(c.crldp.is_null() && i != -1);
    if crldp_ok {
        // SAFETY: the decoded points, or NULL.
        for k in 0..unsafe { OPENSSL_sk_num(c.crldp.cast()) } {
            // SAFETY: an index within them.
            let dp = unsafe { OPENSSL_sk_value(c.crldp.cast(), k) }.cast::<DIST_POINT>();
            // SAFETY: a point of them.
            if !unsafe { dp.as_mut() }.is_some_and(setup_dp) {
                crldp_ok = false;
                break;
            }
        }
    }
    if !crldp_ok {
        c.flags |= f(EXFLAG_INVALID);
    }
    c.addr = d2i(NID_sbgp_ipAddrBlock, &mut i).cast();
    if c.addr.is_null() && i != -1 {
        c.flags |= f(EXFLAG_INVALID);
    }
    c.asid = d2i(NID_sbgp_autonomousSysNum, &mut i).cast();
    if c.asid.is_null() && i != -1 {
        c.flags |= f(EXFLAG_INVALID);
    }
    // SAFETY: the certificate.
    for k in 0..unsafe { X509_get_ext_count(xp) } {
        // SAFETY: an index within its extensions.
        let ex = unsafe { X509_get_ext(xp, k) };
        // SAFETY: an extension of it.
        let obj = unsafe { X509_EXTENSION_get_object(ex) };
        // SAFETY: its object.
        let nid = unsafe { OBJ_obj2nid(obj) };
        if nid == NID_freshest_crl {
            c.flags |= f(EXFLAG_FRESHEST);
        }
        // SAFETY: as above.
        if unsafe { X509_EXTENSION_get_critical(ex) } == 0 {
            continue;
        }
        // SAFETY: as above.
        if unsafe { X509_supported_extension(ex) } == 0 {
            c.flags |= f(EXFLAG_CRITICAL);
            break;
        }
        let flag = match nid {
            n if n == NID_basic_constraints => EXFLAG_BCONS_CRITICAL,
            n if n == NID_authority_key_identifier => EXFLAG_AKID_CRITICAL,
            n if n == NID_subject_key_identifier => EXFLAG_SKID_CRITICAL,
            n if n == NID_subject_alt_name => EXFLAG_SAN_CRITICAL,
            _ => 0,
        };
        c.flags |= f(flag);
    }
    let mut siginf = c.siginf;
    // SAFETY: the certificate's key, or NULL.
    let pkey = unsafe { crate::x509::pubkey::X509_PUBKEY_get0(x.cert_info.key) };
    // SAFETY: the certificate's algorithm and signature; the key, or NULL.
    unsafe {
        sig_info_init(
            &mut siginf,
            &raw const x.sig_alg,
            (&raw const x.signature).cast(),
            pkey,
        )
    };
    x.cache.siginf = siginf;
    x.cache.flags |= f(EXFLAG_SET);
}

/// `ASN1_OBJECT_free` as a stack's free function.
unsafe extern "C" fn free_object(p: *mut c_void) {
    // SAFETY: an element of the stack, which the stack owned.
    unsafe { ASN1_OBJECT_free(p.cast()) };
}

/// `ossl_x509v3_cache_extensions`: fills the cache if it isn't: whether the certificate is
/// valid (0 with `X509V3_R_INVALID_CERTIFICATE` if not, or for NULL).
///
/// # Safety
/// `xp` is NULL or a live certificate.
pub(crate) unsafe fn cache_extensions(xp: *const X509) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { cert_of(xp) }) else {
        return false;
    };
    // SAFETY: its lock.
    if unsafe { CRYPTO_THREAD_write_lock(x.lock) } == 0 {
        return false;
    }
    if x.cache.flags & f(EXFLAG_SET) == 0 {
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_set_mark() };
        // SAFETY: the certificate, which `x` is.
        unsafe { fill(xp.cast_mut(), x) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_pop_to_mark() };
        let invalid = x.cache.flags & f(EXFLAG_INVALID) != 0;
        // SAFETY: as above.
        unsafe { CRYPTO_THREAD_unlock(x.lock) };
        if invalid {
            err::raise(
                ERR_LIB_X509V3,
                X509V3_R_INVALID_CERTIFICATE,
                "ossl_x509v3_cache_extensions",
            );
        }
        return !invalid;
    }
    let ok = x.cache.flags & f(EXFLAG_INVALID) == 0;
    // SAFETY: as above.
    unsafe { CRYPTO_THREAD_unlock(x.lock) };
    ok
}

/// The cache of a certificate whose cache is filled.
///
/// # Safety
/// `x` is a live certificate.
unsafe fn cache_of<'a>(x: *const X509) -> &'a Cache {
    // SAFETY: the caller's guarantee.
    unsafe { &(*x.cast::<Cert>()).cache }
}

/// `ku_reject`.
fn ku_reject(c: &Cache, usage: c_int) -> bool {
    c.flags & f(EXFLAG_KUSAGE) != 0 && c.kusage & f(usage) == 0
}

/// `xku_reject`.
fn xku_reject(c: &Cache, usage: c_int) -> bool {
    c.flags & f(EXFLAG_XKUSAGE) != 0 && c.xkusage & f(usage) == 0
}

/// `ns_reject`.
fn ns_reject(c: &Cache, usage: c_int) -> bool {
    c.flags & f(EXFLAG_NSCERT) != 0 && c.nscert & f(usage) == 0
}

/// `check_ca`.
fn check_ca(c: &Cache) -> c_int {
    if ku_reject(c, KU_KEY_CERT_SIGN) {
        return 0;
    }
    if c.flags & f(EXFLAG_BCONS) != 0 {
        return c_int::from(c.flags & f(EXFLAG_CA) != 0);
    }
    let v1_root = f(EXFLAG_V1) | f(EXFLAG_SS);
    if c.flags & v1_root == v1_root {
        3
    } else if c.flags & f(EXFLAG_KUSAGE) != 0 {
        4
    } else if c.flags & f(EXFLAG_NSCERT) != 0 && c.nscert & f(NS_ANY_CA) != 0 {
        5
    } else {
        0
    }
}

ffi_export! {
    /// Whether the certificate is a CA: 1 (basic constraints), 3 (a self-signed version 1
    /// certificate), 4 (a key usage), 5 (a Netscape CA type), or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_check_ca(x: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { cache_extensions(x) } {
            return 0;
        }
        // SAFETY: as above, with its cache filled.
        check_ca(unsafe { cache_of(x) })
    }
}

ffi_export! {
    /// Marks the certificate a proxy certificate.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_set_proxy_flag(x: *mut X509)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(x) }) else { return };
        // SAFETY: its lock.
        if unsafe { CRYPTO_THREAD_write_lock(c.lock) } != 0 {
            c.cache.flags |= f(EXFLAG_PROXY);
            // SAFETY: as above.
            unsafe { CRYPTO_THREAD_unlock(c.lock) };
        }
    }
}

ffi_export! {
    /// Sets the certificate's proxy path length.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_set_proxy_pathlen(x: *mut X509, l: c_long)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { cert_of(x) } {
            c.cache.pcpathlen = l;
        }
    }
}

/// `check_ssl_ca`.
fn check_ssl_ca(c: &Cache) -> c_int {
    let r = check_ca(c);
    if r == 0 {
        return 0;
    }
    c_int::from(r != 5 || c.nscert & f(NS_SSL_CA) != 0)
}

fn ssl_client(c: &Cache, _x: *const X509, non_leaf: bool) -> c_int {
    if xku_reject(c, XKU_SSL_CLIENT) {
        return 0;
    }
    if non_leaf {
        return check_ssl_ca(c);
    }
    c_int::from(
        !ku_reject(c, KU_DIGITAL_SIGNATURE | KU_KEY_AGREEMENT) && !ns_reject(c, NS_SSL_CLIENT),
    )
}

fn ssl_server(c: &Cache, _x: *const X509, non_leaf: bool) -> c_int {
    if xku_reject(c, XKU_SSL_SERVER | XKU_SGC) {
        return 0;
    }
    if non_leaf {
        return check_ssl_ca(c);
    }
    c_int::from(
        !ns_reject(c, NS_SSL_SERVER)
            && !ku_reject(
                c,
                KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT | KU_KEY_AGREEMENT,
            ),
    )
}

fn ns_ssl_server(c: &Cache, x: *const X509, non_leaf: bool) -> c_int {
    let r = ssl_server(c, x, non_leaf);
    if r == 0 || non_leaf {
        return r;
    }
    if ku_reject(c, KU_KEY_ENCIPHERMENT) {
        0
    } else {
        r
    }
}

/// `purpose_smime`.
fn smime(c: &Cache, non_leaf: bool) -> c_int {
    if xku_reject(c, XKU_SMIME) {
        return 0;
    }
    if non_leaf {
        let r = check_ca(c);
        if r == 0 {
            return 0;
        }
        return if r != 5 || c.nscert & f(NS_SMIME_CA) != 0 {
            r
        } else {
            0
        };
    }
    if c.flags & f(EXFLAG_NSCERT) != 0 {
        if c.nscert & f(NS_SMIME) != 0 {
            return 1;
        }
        return if c.nscert & f(NS_SSL_CLIENT) != 0 {
            2
        } else {
            0
        };
    }
    1
}

fn smime_sign(c: &Cache, _x: *const X509, non_leaf: bool) -> c_int {
    let r = smime(c, non_leaf);
    if r == 0 || non_leaf {
        return r;
    }
    if ku_reject(c, KU_DIGITAL_SIGNATURE | KU_NON_REPUDIATION) {
        0
    } else {
        r
    }
}

fn smime_encrypt(c: &Cache, _x: *const X509, non_leaf: bool) -> c_int {
    let r = smime(c, non_leaf);
    if r == 0 || non_leaf {
        return r;
    }
    if ku_reject(c, KU_KEY_ENCIPHERMENT) {
        0
    } else {
        r
    }
}

fn crl_sign(c: &Cache, _x: *const X509, non_leaf: bool) -> c_int {
    if non_leaf {
        let r = check_ca(c);
        return if r == 2 { 0 } else { r };
    }
    c_int::from(!ku_reject(c, KU_CRL_SIGN))
}

fn ocsp_helper(c: &Cache, _x: *const X509, non_leaf: bool) -> c_int {
    if non_leaf { check_ca(c) } else { 1 }
}

/// Whether the certificate's extension of `nid` is there and critical.
fn critical(x: *const X509, nid: c_int) -> Option<bool> {
    // SAFETY: a live certificate.
    let i = unsafe { X509_get_ext_by_NID(x, nid, -1) };
    if i < 0 {
        return None;
    }
    // SAFETY: as above; an index within its extensions.
    let ex = unsafe { X509_get_ext(x, i) };
    // SAFETY: an extension of it.
    Some(unsafe { X509_EXTENSION_get_critical(ex) } != 0)
}

fn timestamp_sign(c: &Cache, x: *const X509, non_leaf: bool) -> c_int {
    if non_leaf {
        return check_ca(c);
    }
    let ds = f(KU_NON_REPUDIATION | KU_DIGITAL_SIGNATURE);
    if c.flags & f(EXFLAG_KUSAGE) != 0 && (c.kusage & !ds != 0 || c.kusage & ds == 0) {
        return 0;
    }
    if c.flags & f(EXFLAG_XKUSAGE) == 0 || c.xkusage != f(XKU_TIMESTAMP) {
        return 0;
    }
    c_int::from(critical(x, NID_ext_key_usage) != Some(false))
}

fn code_sign(c: &Cache, x: *const X509, non_leaf: bool) -> c_int {
    if non_leaf {
        return check_ca(c);
    }
    if c.flags & f(EXFLAG_KUSAGE) == 0
        || c.kusage & f(KU_DIGITAL_SIGNATURE) == 0
        || c.kusage & f(KU_KEY_CERT_SIGN | KU_CRL_SIGN) != 0
    {
        return 0;
    }
    if critical(x, NID_key_usage) != Some(true) {
        return 0;
    }
    if c.flags & f(EXFLAG_XKUSAGE) == 0
        || c.xkusage & f(XKU_CODE_SIGN) == 0
        || c.xkusage & f(XKU_ANYEKU | XKU_SSL_SERVER) != 0
    {
        return 0;
    }
    1
}

fn no_check(_c: &Cache, _x: *const X509, _non_leaf: bool) -> c_int {
    1
}

/// The built-in checks as C functions, which applications may call through the table: they
/// read the cache as it is, as OpenSSL's do.
macro_rules! c_checks {
    ($($c:ident => $rust:ident;)*) => {$(
        ffi_callback! {
            /// A built-in purpose's check.
            ///
            /// # Safety
            /// `x` is a live certificate.
            pub(crate) unsafe extern "C" fn $c(_xp: *const X509_PURPOSE, x: *const X509, non_leaf: c_int) -> c_int
            where failure = 0, library = ERR_LIB_X509V3
            {
                if x.is_null() {
                    return 0;
                }
                // SAFETY: the caller's guarantee.
                $rust(unsafe { cache_of(x) }, x, non_leaf != 0)
            }
        }
    )*};
}

c_checks! {
    check_purpose_ssl_client => ssl_client;
    check_purpose_ssl_server => ssl_server;
    check_purpose_ns_ssl_server => ns_ssl_server;
    check_purpose_smime_sign => smime_sign;
    check_purpose_smime_encrypt => smime_encrypt;
    check_purpose_crl_sign => crl_sign;
    no_check_purpose => no_check;
    check_purpose_ocsp_helper => ocsp_helper;
    check_purpose_timestamp_sign => timestamp_sign;
    check_purpose_code_sign => code_sign;
}

type CheckFn = unsafe extern "C" fn(*const X509_PURPOSE, *const X509, c_int) -> c_int;

const fn purpose(
    id: c_int,
    trust: c_int,
    check: CheckFn,
    name: &'static CStr,
    sname: &'static CStr,
) -> X509_PURPOSE {
    X509_PURPOSE {
        purpose: id,
        trust,
        flags: 0,
        check_purpose: Some(check),
        name: name.as_ptr().cast_mut(),
        sname: sname.as_ptr().cast_mut(),
        usr_data: ptr::null_mut(),
    }
}

/// How many built-in purposes there are (`X509_PURPOSE_COUNT`).
const COUNT: usize = 10;

/// `xstandard`, which `X509_PURPOSE_add` may change.
struct Standard(core::cell::UnsafeCell<[X509_PURPOSE; COUNT]>);

// SAFETY: as OpenSSL's table, changed only by `X509_PURPOSE_add` and `X509_PURPOSE_set`'s
// callers, which OpenSSL doesn't make thread-safe either; reads are of plain values.
unsafe impl Sync for Standard {}

static STANDARD: Standard = Standard(core::cell::UnsafeCell::new([
    purpose(
        X509_PURPOSE_SSL_CLIENT,
        X509_TRUST_SSL_CLIENT,
        check_purpose_ssl_client,
        c"SSL client",
        c"sslclient",
    ),
    purpose(
        X509_PURPOSE_SSL_SERVER,
        X509_TRUST_SSL_SERVER,
        check_purpose_ssl_server,
        c"SSL server",
        c"sslserver",
    ),
    purpose(
        X509_PURPOSE_NS_SSL_SERVER,
        X509_TRUST_SSL_SERVER,
        check_purpose_ns_ssl_server,
        c"Netscape SSL server",
        c"nssslserver",
    ),
    purpose(
        X509_PURPOSE_SMIME_SIGN,
        X509_TRUST_EMAIL,
        check_purpose_smime_sign,
        c"S/MIME signing",
        c"smimesign",
    ),
    purpose(
        X509_PURPOSE_SMIME_ENCRYPT,
        X509_TRUST_EMAIL,
        check_purpose_smime_encrypt,
        c"S/MIME encryption",
        c"smimeencrypt",
    ),
    purpose(
        X509_PURPOSE_CRL_SIGN,
        X509_TRUST_COMPAT,
        check_purpose_crl_sign,
        c"CRL signing",
        c"crlsign",
    ),
    purpose(
        X509_PURPOSE_ANY,
        X509_TRUST_DEFAULT,
        no_check_purpose,
        c"Any Purpose",
        c"any",
    ),
    purpose(
        X509_PURPOSE_OCSP_HELPER,
        X509_TRUST_COMPAT,
        check_purpose_ocsp_helper,
        c"OCSP helper",
        c"ocsphelper",
    ),
    purpose(
        X509_PURPOSE_TIMESTAMP_SIGN,
        X509_TRUST_TSA,
        check_purpose_timestamp_sign,
        c"Time Stamp signing",
        c"timestampsign",
    ),
    purpose(
        X509_PURPOSE_CODE_SIGN,
        X509_TRUST_OBJECT_SIGN,
        check_purpose_code_sign,
        c"Code signing",
        c"codesign",
    ),
]));

/// `xptable`: the purposes applications added, sorted by id, or NULL.
static XPTABLE: core::sync::atomic::AtomicPtr<rustyssl_abi::OPENSSL_STACK> =
    core::sync::atomic::AtomicPtr::new(ptr::null_mut());

/// `xp_cmp`: by id.
unsafe extern "C" fn xp_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: pointers to the stack's elements, purposes.
    let a = unsafe { *a.cast::<*const X509_PURPOSE>() };
    // SAFETY: as above.
    let b = unsafe { *b.cast::<*const X509_PURPOSE>() };
    // SAFETY: the purposes.
    let (pa, pb) = (unsafe { (*a).purpose }, unsafe { (*b).purpose });
    pa.wrapping_sub(pb)
}

fn table() -> *mut rustyssl_abi::OPENSSL_STACK {
    XPTABLE.load(core::sync::atomic::Ordering::Acquire)
}

/// The built-in purposes' count as an `int`.
const COUNT_INT: c_int = 10;

ffi_export! {
    /// How many purposes there are, built in and added.
    pub unsafe extern "C" fn X509_PURPOSE_get_count() -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        let t = table();
        if t.is_null() {
            return COUNT_INT;
        }
        // SAFETY: the table.
        unsafe { OPENSSL_sk_num(t) }.saturating_add(COUNT_INT)
    }
}

ffi_export! {
    /// The purpose at `idx`, or NULL.
    pub unsafe extern "C" fn X509_PURPOSE_get0(idx: c_int) -> *mut X509_PURPOSE
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        let Ok(i) = usize::try_from(idx) else { return ptr::null_mut() };
        if i < COUNT {
            // SAFETY: an index within the built-in purposes.
            return unsafe { STANDARD.0.get().cast::<X509_PURPOSE>().add(i) };
        }
        // SAFETY: the table, or NULL; an index past the built-in ones.
        unsafe { OPENSSL_sk_value(table(), idx.wrapping_sub(COUNT_INT)) }.cast()
    }
}

ffi_export! {
    /// The index of the purpose with the short name, or -1.
    ///
    /// # Safety
    /// `sname` is NULL (-1, where OpenSSL crashes) or a C string.
    pub unsafe extern "C" fn X509_PURPOSE_get_by_sname(sname: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_X509V3
    {
        if sname.is_null() {
            return -1;
        }
        // SAFETY: the caller's guarantee.
        let want = unsafe { CStr::from_ptr(sname) };
        // SAFETY: no preconditions.
        for i in 0..unsafe { X509_PURPOSE_get_count() } {
            // SAFETY: an index within the purposes.
            let p = unsafe { X509_PURPOSE_get0(i) };
            // SAFETY: a purpose, with its short name, or NULL.
            if let Some(p) = unsafe { p.as_ref() } && !p.sname.is_null() && unsafe { CStr::from_ptr(p.sname) } == want {
                return i;
            }
        }
        -1
    }
}

ffi_export! {
    /// The index of the purpose with the id, or -1.
    pub unsafe extern "C" fn X509_PURPOSE_get_by_id(purpose: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509V3
    {
        if (X509_PURPOSE_MIN..=X509_PURPOSE_MAX).contains(&purpose) {
            return purpose.wrapping_sub(X509_PURPOSE_MIN);
        }
        let t = table();
        if t.is_null() {
            return -1;
        }
        // SAFETY: all-zero is a valid purpose to search with.
        let mut tmp: X509_PURPOSE = unsafe { core::mem::zeroed() };
        tmp.purpose = purpose;
        // SAFETY: the table, sorted by id; the key.
        let idx = unsafe { OPENSSL_sk_find(t, (&raw mut tmp).cast()) };
        if idx < 0 { -1 } else { idx.saturating_add(COUNT_INT) }
    }
}

ffi_export! {
    /// Checks the certificate for the purpose `id` (or only fills its cache, for -1): the
    /// check's answer, 1 for -1, or -1 for an invalid certificate or an unknown purpose.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_check_purpose(x: *mut X509, id: c_int, non_leaf: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { cache_extensions(x) } {
            return -1;
        }
        if id == -1 {
            return 1;
        }
        // SAFETY: no preconditions.
        let idx = unsafe { X509_PURPOSE_get_by_id(id) };
        if idx == -1 {
            return -1;
        }
        // SAFETY: as above.
        let pt = unsafe { X509_PURPOSE_get0(idx) };
        // SAFETY: a purpose of the table, or NULL.
        let Some(check) = unsafe { pt.as_ref() }.and_then(|p| p.check_purpose) else { return -1 };
        // SAFETY: the purpose's check (not under any lock).
        unsafe { check(pt, x, non_leaf) }
    }
}

ffi_export! {
    /// Stores `purpose` in `*p` if it's a purpose (or `X509_PURPOSE_DEFAULT_ANY`): 1, or 0
    /// (`X509V3_R_INVALID_PURPOSE`).
    ///
    /// # Safety
    /// `p` is writable.
    pub unsafe extern "C" fn X509_PURPOSE_set(p: *mut c_int, purpose: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: no preconditions.
        if purpose != X509_PURPOSE_DEFAULT_ANY && unsafe { X509_PURPOSE_get_by_id(purpose) } == -1 {
            err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_PURPOSE, "X509_PURPOSE_set");
            return 0;
        }
        if p.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { p.write(purpose) };
        1
    }
}

ffi_export! {
    /// The least id above `X509_PURPOSE_MAX` without a purpose.
    pub unsafe extern "C" fn X509_PURPOSE_get_unused_id(_libctx: *mut rustyssl_abi::OSSL_LIB_CTX) -> c_int
    where failure = -1, library = ERR_LIB_X509V3
    {
        let mut id = X509_PURPOSE_MAX.wrapping_add(1);
        // SAFETY: no preconditions.
        while unsafe { X509_PURPOSE_get_by_id(id) } != -1 {
            id = id.wrapping_add(1);
        }
        id
    }
}

/// A C copy of a string, or NULL.
///
/// # Safety
/// `s` is a C string.
unsafe fn strdup(s: *const c_char) -> *mut c_char {
    // SAFETY: the caller's guarantee.
    crate::conf::c_dup(unsafe { CStr::from_ptr(s) }.to_bytes())
}

/// Serializes `X509_PURPOSE_add` and `X509_PURPOSE_cleanup` with each other.
static ADD: Mutex<()> = Mutex::new(());

ffi_export! {
    /// Adds the purpose `id` (or changes the one with the short name `sname`): 1, or 0.
    ///
    /// # Safety
    /// `name` and `sname` are NULL or C strings; `ck` is NULL or a function of the purpose's
    /// kind.
    pub unsafe extern "C" fn X509_PURPOSE_add(id: c_int, trust: c_int, flags: c_int, ck: Option<CheckFn>, name: *const c_char, sname: *const c_char, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        const F: &str = "X509_PURPOSE_add";
        if id < X509_PURPOSE_MIN {
            err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_PURPOSE, F);
            return 0;
        }
        if trust < X509_TRUST_DEFAULT || name.is_null() || sname.is_null() || ck.is_none() {
            err::raise(ERR_LIB_X509V3, ERR_R_PASSED_INVALID_ARGUMENT, F);
            return 0;
        }
        let _guard = ADD.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let flags = (flags & !X509_PURPOSE_DYNAMIC) | X509_PURPOSE_DYNAMIC_NAME;
        // SAFETY: a C string.
        let idx = unsafe { X509_PURPOSE_get_by_sname(sname) };
        let mut old_id = 0;
        let ptmp: *mut X509_PURPOSE = if idx == -1 {
            // SAFETY: no preconditions.
            if unsafe { X509_PURPOSE_get_by_id(id) } != -1 {
                err::raise(ERR_LIB_X509V3, X509V3_R_PURPOSE_NOT_UNIQUE, F);
                return 0;
            }
            let p = mem::alloc(core::mem::size_of::<X509_PURPOSE>()).cast::<X509_PURPOSE>();
            if p.is_null() {
                return 0;
            }
            // SAFETY: all-zero is a valid purpose.
            let mut fresh: X509_PURPOSE = unsafe { core::mem::zeroed() };
            fresh.flags = X509_PURPOSE_DYNAMIC;
            // SAFETY: new memory for a purpose.
            unsafe { p.write(fresh) };
            p
        } else {
            // SAFETY: an index of a purpose.
            let p = unsafe { X509_PURPOSE_get0(idx) };
            // SAFETY: a purpose of the table.
            old_id = unsafe { (*p).purpose };
            // SAFETY: no preconditions.
            if id != old_id && unsafe { X509_PURPOSE_get_by_id(id) } != -1 {
                err::raise(ERR_LIB_X509V3, X509V3_R_PURPOSE_NOT_UNIQUE, F);
                return 0;
            }
            p
        };
        // SAFETY: the purpose, new or of the table.
        let pt = unsafe { &mut *ptmp };
        if pt.flags & X509_PURPOSE_DYNAMIC_NAME != 0 {
            // SAFETY: its own copies.
            unsafe { mem::release(pt.name.cast()) };
            // SAFETY: as above.
            unsafe { mem::release(pt.sname.cast()) };
        }
        // SAFETY: C strings.
        pt.name = unsafe { strdup(name) };
        // SAFETY: as above.
        pt.sname = unsafe { strdup(sname) };
        let fail = |pt: &mut X509_PURPOSE| {
            if idx == -1 {
                // SAFETY: the new purpose's copies, and it.
                unsafe { mem::release(pt.name.cast()) };
                // SAFETY: as above.
                unsafe { mem::release(pt.sname.cast()) };
                // SAFETY: as above.
                unsafe { mem::release(ptmp.cast()) };
            }
            0
        };
        if pt.name.is_null() || pt.sname.is_null() {
            return fail(pt);
        }
        pt.flags &= X509_PURPOSE_DYNAMIC;
        pt.flags |= flags;
        pt.purpose = id;
        pt.trust = trust;
        pt.check_purpose = ck;
        pt.usr_data = arg;
        if idx == -1 {
            let mut t = table();
            if t.is_null() {
                // SAFETY: a comparison of purposes.
                t = unsafe { OPENSSL_sk_new(Some(xp_cmp)) };
                if t.is_null() {
                    err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, F);
                    return fail(pt);
                }
                XPTABLE.store(t, core::sync::atomic::Ordering::Release);
            }
            // SAFETY: the table; the purpose, which it takes.
            if unsafe { OPENSSL_sk_push(t, ptmp.cast()) } == 0 {
                err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, F);
                return fail(pt);
            }
        } else if id != old_id {
            // SAFETY: the table; its index (as OpenSSL's, which counts the built-in ones).
            unsafe { OPENSSL_sk_set(table(), idx, ptmp.cast()) };
        }
        1
    }
}

/// `xptable_free`.
unsafe extern "C" fn xptable_free(p: *mut c_void) {
    // SAFETY: a purpose of the table, or NULL.
    let Some(pt) = (unsafe { p.cast::<X509_PURPOSE>().as_mut() }) else {
        return;
    };
    if pt.flags & X509_PURPOSE_DYNAMIC != 0 {
        if pt.flags & X509_PURPOSE_DYNAMIC_NAME != 0 {
            // SAFETY: its own copies.
            unsafe { mem::release(pt.name.cast()) };
            // SAFETY: as above.
            unsafe { mem::release(pt.sname.cast()) };
        }
        // SAFETY: as above.
        unsafe { mem::release(p) };
    }
}

ffi_export! {
    /// Removes the added purposes.
    pub unsafe extern "C" fn X509_PURPOSE_cleanup()
    where failure = (), library = ERR_LIB_X509V3
    {
        let _guard = ADD.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let t = XPTABLE.swap(ptr::null_mut(), core::sync::atomic::Ordering::AcqRel);
        // SAFETY: the table, or NULL, with its purposes.
        unsafe { OPENSSL_sk_pop_free(t, Some(xptable_free)) };
    }
}

ffi_export! {
    /// The purpose's id.
    ///
    /// # Safety
    /// `xp` is NULL (0) or a live purpose.
    pub unsafe extern "C" fn X509_PURPOSE_get_id(xp: *const X509_PURPOSE) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { xp.as_ref() }.map_or(0, |p| p.purpose)
    }
}

ffi_export! {
    /// The purpose's name.
    ///
    /// # Safety
    /// `xp` is NULL (NULL) or a live purpose.
    pub unsafe extern "C" fn X509_PURPOSE_get0_name(xp: *const X509_PURPOSE) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { xp.as_ref() }.map_or(ptr::null_mut(), |p| p.name)
    }
}

ffi_export! {
    /// The purpose's short name.
    ///
    /// # Safety
    /// `xp` is NULL (NULL) or a live purpose.
    pub unsafe extern "C" fn X509_PURPOSE_get0_sname(xp: *const X509_PURPOSE) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { xp.as_ref() }.map_or(ptr::null_mut(), |p| p.sname)
    }
}

ffi_export! {
    /// The purpose's trust setting.
    ///
    /// # Safety
    /// `xp` is NULL (0) or a live purpose.
    pub unsafe extern "C" fn X509_PURPOSE_get_trust(xp: *const X509_PURPOSE) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { xp.as_ref() }.map_or(0, |p| p.trust)
    }
}

/// `ossl_x509_likely_issued`.
///
/// # Safety
/// `issuer` and `subject` are NULL or live certificates.
pub(crate) unsafe fn likely_issued(issuer: *mut X509, subject: *mut X509) -> c_int {
    // SAFETY: the caller's guarantee.
    let (a, b) = (unsafe { X509_get_subject_name(issuer) }, unsafe {
        X509_get_issuer_name(subject)
    });
    // SAFETY: their names, or NULL.
    if unsafe { X509_NAME_cmp(a, b) } != 0 {
        return X509_V_ERR_SUBJECT_ISSUER_MISMATCH;
    }
    // SAFETY: as above.
    if !unsafe { cache_extensions(issuer) } || !unsafe { cache_extensions(subject) } {
        return X509_V_ERR_UNSPECIFIED;
    }
    // SAFETY: as above, cached.
    let akid = unsafe { cache_of(subject) }.akid;
    // SAFETY: as above; its identifier, or NULL.
    let ret = unsafe { X509_check_akid(issuer, akid) };
    if ret != X509_V_OK {
        return ret;
    }
    // SAFETY: as above.
    let key = unsafe { X509_get0_pubkey(issuer) };
    // SAFETY: as above.
    let s = unsafe { &*subject.cast::<Cert>() };
    // SAFETY: the key, or NULL.
    unsafe { check_sig_alg_match(key.cast_const(), s) }
}

/// `ossl_x509_signing_allowed`.
///
/// # Safety
/// Both are live certificates with their caches filled.
pub(crate) unsafe fn signing_allowed(issuer: *const X509, subject: *const X509) -> c_int {
    // SAFETY: the caller's guarantee.
    let (i, s) = (unsafe { cache_of(issuer) }, unsafe { cache_of(subject) });
    if s.flags & f(EXFLAG_PROXY) != 0 {
        if ku_reject(i, KU_DIGITAL_SIGNATURE) {
            return X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE;
        }
    } else if ku_reject(i, KU_KEY_CERT_SIGN) {
        return X509_V_ERR_KEYUSAGE_NO_CERTSIGN;
    }
    X509_V_OK
}

ffi_export! {
    /// Whether `issuer` may have issued `subject`: `X509_V_OK`, or the `X509_V_ERR_*` saying
    /// why not (names, key identifiers, the signature algorithm, the key usage).
    ///
    /// # Safety
    /// `issuer` and `subject` are NULL or live certificates.
    pub unsafe extern "C" fn X509_check_issued(issuer: *mut X509, subject: *mut X509) -> c_int
    where failure = X509_V_ERR_UNSPECIFIED, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let ret = unsafe { likely_issued(issuer, subject) };
        if ret != X509_V_OK {
            return ret;
        }
        // SAFETY: as above, cached by `likely_issued`.
        unsafe { signing_allowed(issuer, subject) }
    }
}

ffi_export! {
    /// Whether the authority key identifier matches `issuer`: `X509_V_OK` (also for NULL), or
    /// `X509_V_ERR_AKID_SKID_MISMATCH` or `X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH`.
    ///
    /// # Safety
    /// `issuer` is a live certificate; `akid` is NULL or a live key identifier.
    pub unsafe extern "C" fn X509_check_akid(issuer: *const X509, akid: *const AUTHORITY_KEYID) -> c_int
    where failure = X509_V_ERR_UNSPECIFIED, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { akid.as_ref() }) else { return X509_V_OK };
        // SAFETY: as above.
        let Some(x) = (unsafe { cert_of(issuer) }) else { return X509_V_OK };
        // SAFETY: the identifiers.
        if !a.keyid.is_null() && !x.cache.skid.is_null() && unsafe { ASN1_OCTET_STRING_cmp(a.keyid, x.cache.skid) } != 0 {
            return X509_V_ERR_AKID_SKID_MISMATCH;
        }
        // SAFETY: the certificate.
        let serial = unsafe { X509_get0_serialNumber(issuer) };
        // SAFETY: its serial number; the identifier's.
        if !a.serial.is_null() && unsafe { ASN1_INTEGER_cmp(serial, a.serial) } != 0 {
            return X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH;
        }
        if !a.issuer.is_null() {
            let mut nm = ptr::null_mut();
            // SAFETY: the identifier's names.
            for i in 0..unsafe { OPENSSL_sk_num(a.issuer.cast()) } {
                // SAFETY: an index within them.
                let g = unsafe { OPENSSL_sk_value(a.issuer.cast(), i) }.cast::<GENERAL_NAME>();
                // SAFETY: a name of them.
                if let Some(g) = unsafe { g.as_ref() } && g.type_ == GEN_DIRNAME {
                    // SAFETY: a directory name's member.
                    nm = unsafe { g.d.dirn };
                    break;
                }
            }
            // SAFETY: the certificate.
            let iname = unsafe { X509_get_issuer_name(issuer) };
            // SAFETY: the name; the certificate's issuer.
            if !nm.is_null() && unsafe { X509_NAME_cmp(nm, iname) } != 0 {
                return X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH;
            }
        }
        X509_V_OK
    }
}

/// `X509_check_purpose(x, -1, 0) == 1`, then the cache.
///
/// # Safety
/// `x` is NULL or a live certificate.
unsafe fn cached<'a>(x: *mut X509) -> Option<&'a Cache> {
    // SAFETY: the caller's guarantee.
    (unsafe { X509_check_purpose(x, -1, 0) } == 1).then(|| unsafe { cache_of(x) })
}

ffi_export! {
    /// The certificate's `EXFLAG_*` flags (filling its cache).
    ///
    /// # Safety
    /// `x` is NULL (0, where OpenSSL crashes) or a live certificate.
    pub unsafe extern "C" fn X509_get_extension_flags(x: *mut X509) -> u32
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_check_purpose(x, -1, 0) };
        // SAFETY: as above.
        unsafe { cert_of(x) }.map_or(0, |c| c.cache.flags)
    }
}

ffi_export! {
    /// The key usage bits, `UINT32_MAX` without the extension, or 0 for an invalid certificate.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_get_key_usage(x: *mut X509) -> u32
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { cached(x) }.map_or(0, |c| if c.flags & f(EXFLAG_KUSAGE) != 0 { c.kusage } else { u32::MAX })
    }
}

ffi_export! {
    /// The extended key usage bits (`XKU_*`), `UINT32_MAX` without the extension, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_get_extended_key_usage(x: *mut X509) -> u32
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { cached(x) }.map_or(0, |c| if c.flags & f(EXFLAG_XKUSAGE) != 0 { c.xkusage } else { u32::MAX })
    }
}

ffi_export! {
    /// The subject key identifier, which the certificate keeps, or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_get0_subject_key_id(x: *mut X509) -> *const ASN1_OCTET_STRING
    where failure = ptr::null(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { cached(x) }.map_or(ptr::null(), |c| c.skid.cast_const())
    }
}

/// The cached authority key identifier, or `None`.
///
/// # Safety
/// `x` is NULL or a live certificate.
unsafe fn akid_of<'a>(x: *mut X509) -> Option<&'a AUTHORITY_KEYID> {
    // SAFETY: the caller's guarantee; the identifier, or NULL.
    unsafe { cached(x) }.and_then(|c| unsafe { c.akid.as_ref() })
}

ffi_export! {
    /// The authority key identifier's key identifier, or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_get0_authority_key_id(x: *mut X509) -> *const ASN1_OCTET_STRING
    where failure = ptr::null(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { akid_of(x) }.map_or(ptr::null(), |a| a.keyid.cast_const())
    }
}

ffi_export! {
    /// The authority key identifier's issuer names, or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_get0_authority_issuer(x: *mut X509) -> *const GENERAL_NAMES
    where failure = ptr::null(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { akid_of(x) }.map_or(ptr::null(), |a| a.issuer.cast_const())
    }
}

ffi_export! {
    /// The authority key identifier's serial number, or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_get0_authority_serial(x: *mut X509) -> *const ASN1_INTEGER
    where failure = ptr::null(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { akid_of(x) }.map_or(ptr::null(), |a| a.serial.cast_const())
    }
}

ffi_export! {
    /// The basic constraints' path length, or -1.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_get_pathlen(x: *mut X509) -> c_long
    where failure = -1, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { cached(x) }.filter(|c| c.flags & f(EXFLAG_BCONS) != 0).map_or(-1, |c| c.pathlen)
    }
}

ffi_export! {
    /// The proxy certificate's path length, or -1.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_get_proxy_pathlen(x: *mut X509) -> c_long
    where failure = -1, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { cached(x) }.filter(|c| c.flags & f(EXFLAG_PROXY) != 0).map_or(-1, |c| c.pcpathlen)
    }
}

ffi_export! {
    /// Reads the signature information (each output if not NULL): whether it's valid.
    ///
    /// # Safety
    /// `siginf` is a live `X509_SIG_INFO`; the outputs are NULL or writable.
    pub unsafe extern "C" fn X509_SIG_INFO_get(siginf: *const X509_SIG_INFO, mdnid: *mut c_int, pknid: *mut c_int, secbits: *mut c_int, flags: *mut u32) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee; an `X509_SIG_INFO` is a `SigInfo`.
        let Some(s) = (unsafe { siginf.cast::<SigInfo>().as_ref() }) else { return 0 };
        for (out, v) in [(mdnid, s.mdnid), (pknid, s.pknid), (secbits, s.secbits)] {
            if !out.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { out.write(v) };
            }
        }
        if !flags.is_null() {
            // SAFETY: as above.
            unsafe { flags.write(s.flags) };
        }
        c_int::from(s.flags & f(X509_SIG_INFO_VALID) != 0)
    }
}

ffi_export! {
    /// Sets the signature information.
    ///
    /// # Safety
    /// `siginf` is NULL or a live `X509_SIG_INFO`.
    pub unsafe extern "C" fn X509_SIG_INFO_set(siginf: *mut X509_SIG_INFO, mdnid: c_int, pknid: c_int, secbits: c_int, flags: u32)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(s) = unsafe { siginf.cast::<SigInfo>().as_mut() } {
            *s = SigInfo { mdnid, pknid, secbits, flags };
        }
    }
}

ffi_export! {
    /// The certificate's signature information (see `X509_SIG_INFO_get`).
    ///
    /// # Safety
    /// `x` is NULL (0) or a live certificate; the outputs are NULL or writable.
    pub unsafe extern "C" fn X509_get_signature_info(x: *mut X509, mdnid: *mut c_int, pknid: *mut c_int, secbits: *mut c_int, flags: *mut u32) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_check_purpose(x, -1, -1) };
        // SAFETY: as above.
        let Some(c) = (unsafe { cert_of(x) }) else { return 0 };
        // SAFETY: its information; the caller's outputs.
        unsafe { X509_SIG_INFO_get((&raw const c.cache.siginf).cast(), mdnid, pknid, secbits, flags) }
    }
}

ffi_export! {
    /// Compares two certificates: by SHA-1 fingerprint, then by their encodings as decoded:
    /// -1, 0, or 1 (NULL first).
    ///
    /// # Safety
    /// `a` and `b` are NULL or live certificates.
    pub unsafe extern "C" fn X509_cmp(a: *const X509, b: *const X509) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if a == b {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(y)) = (unsafe { cert_of(a) }, unsafe { cert_of(b) }) else {
            return if a.is_null() { -1 } else { 1 };
        };
        // SAFETY: as above.
        unsafe { X509_check_purpose(a.cast_mut(), -1, 0) };
        // SAFETY: as above.
        unsafe { X509_check_purpose(b.cast_mut(), -1, 0) };
        let nofp = f(EXFLAG_NO_FINGERPRINT);
        if x.cache.flags & nofp == 0 && y.cache.flags & nofp == 0 {
            match x.cache.sha1.cmp(&y.cache.sha1) {
                core::cmp::Ordering::Less => return -1,
                core::cmp::Ordering::Greater => return 1,
                core::cmp::Ordering::Equal => {}
            }
        }
        let (ea, eb) = (&x.cert_info.enc, &y.cert_info.enc);
        if ea.modified == 0 && eb.modified == 0 {
            if ea.len < eb.len {
                return -1;
            }
            if ea.len > eb.len {
                return 1;
            }
            let n = usize::try_from(ea.len).unwrap_or(0);
            if n == 0 || ea.enc.is_null() || eb.enc.is_null() {
                return 0;
            }
            // SAFETY: an encoding holds its length.
            let da = unsafe { core::slice::from_raw_parts(ea.enc, n) };
            // SAFETY: as above (the same length).
            let db = unsafe { core::slice::from_raw_parts(eb.enc, n) };
            return match da.cmp(db) {
                core::cmp::Ordering::Less => -1,
                core::cmp::Ordering::Equal => 0,
                core::cmp::Ordering::Greater => 1,
            };
        }
        0
    }
}

ffi_export! {
    /// Whether the certificate is self-signed (its names match, its key identifiers allow it,
    /// and, with `verify_signature`, its signature verifies with its own key): 1, 0, or -1.
    ///
    /// # Safety
    /// `cert` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_self_signed(cert: *mut X509, verify_signature: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let pkey = unsafe { X509_get0_pubkey(cert) };
        if pkey.is_null() {
            err::raise(ERR_LIB_X509, X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY, "X509_self_signed");
            return -1;
        }
        // SAFETY: as above.
        if !unsafe { cache_extensions(cert) } {
            return -1;
        }
        // SAFETY: as above, cached.
        if unsafe { cache_of(cert) }.flags & f(EXFLAG_SS) == 0 {
            return 0;
        }
        if verify_signature == 0 {
            return 1;
        }
        // SAFETY: as above; its key.
        unsafe { X509_verify(cert, pkey) }
    }
}

ffi_export! {
    /// Adds the certificate to the list (`X509_ADD_FLAG_*`: up-referenced, prepended, not if
    /// already there, not if self-signed): 1, or 0.
    ///
    /// # Safety
    /// `sk` is NULL or a live list of certificates; `cert` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_add_cert(sk: *mut stack_st_X509, cert: *mut X509, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        const F: &str = "X509_add_cert";
        if sk.is_null() {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        }
        if cert.is_null() {
            return 0;
        }
        if flags & X509_ADD_FLAG_NO_DUP != 0 {
            // SAFETY: the caller's list.
            for i in 0..unsafe { OPENSSL_sk_num(sk.cast()) } {
                // SAFETY: an index within it.
                let c = unsafe { OPENSSL_sk_value(sk.cast(), i) };
                // SAFETY: a certificate of it; the caller's.
                if unsafe { X509_cmp(c.cast(), cert) } == 0 {
                    return 1;
                }
            }
        }
        if flags & X509_ADD_FLAG_NO_SS != 0 {
            // SAFETY: the certificate.
            let r = unsafe { X509_self_signed(cert, 0) };
            if r != 0 {
                return c_int::from(r > 0);
            }
        }
        let up = flags & X509_ADD_FLAG_UP_REF != 0;
        // SAFETY: as above.
        if up && unsafe { X509_up_ref(cert) } == 0 {
            return 0;
        }
        let at = if flags & X509_ADD_FLAG_PREPEND != 0 { 0 } else { -1 };
        // SAFETY: the list; the certificate, which it holds.
        if unsafe { OPENSSL_sk_insert(sk.cast(), cert.cast(), at) } == 0 {
            if up {
                // SAFETY: the reference taken above.
                unsafe { X509_free(cert) };
            }
            err::raise(ERR_LIB_X509, ERR_R_CRYPTO_LIB, F);
            return 0;
        }
        1
    }
}

/// `ossl_x509_add_certs_new` into an existing list.
///
/// # Safety
/// `sk` is a live list; `certs` is NULL or a live list of certificates.
unsafe fn add_certs(sk: *mut stack_st_X509, certs: *mut stack_st_X509, flags: c_int) -> c_int {
    // SAFETY: the caller's list, or NULL.
    let n = unsafe { OPENSSL_sk_num(certs.cast()) };
    for i in 0..n {
        let j = if flags & X509_ADD_FLAG_PREPEND == 0 {
            i
        } else {
            n.wrapping_sub(1).wrapping_sub(i)
        };
        // SAFETY: as above; an index within it.
        let c = unsafe { OPENSSL_sk_value(certs.cast(), j) }.cast::<X509>();
        // SAFETY: the list; a certificate of it.
        if unsafe { X509_add_cert(sk, c, flags) } == 0 {
            return 0;
        }
    }
    1
}

ffi_export! {
    /// Adds each certificate of `certs` (see `X509_add_cert`): 1, or 0.
    ///
    /// # Safety
    /// `sk` is NULL or a live list; `certs` is NULL or a live list of certificates.
    pub unsafe extern "C" fn X509_add_certs(sk: *mut stack_st_X509, certs: *mut stack_st_X509, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if sk.is_null() {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "X509_add_certs");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { add_certs(sk, certs, flags) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_is_sorted() {
        assert!(SUPPORTED.is_sorted());
    }

    /// docs/DEVIATIONS.md: a NULL certificate, which OpenSSL reads through, answers as an
    /// invalid one.
    #[test]
    fn null_certificates_are_safe() {
        let p = ptr::null_mut();
        // SAFETY: NULL where OpenSSL dereferences it.
        assert_eq!(unsafe { X509_check_purpose(p, -1, 0) }, -1);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_get_extension_flags(p) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_get_key_usage(p) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_check_ca(p) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_cmp(p, ptr::null()) }, 0);
        let (n, z) = (ptr::null_mut(), ptr::null_mut());
        // SAFETY: as above.
        let v = unsafe { X509_get_ext_d2i(p, NID_key_usage, n, z) };
        assert!(v.is_null());
        // SAFETY: as above.
        let r = unsafe { X509_get_signature_info(p, n, n, n, ptr::null_mut()) };
        assert_eq!(r, 0);
        crate::err::take_all();
    }
}
