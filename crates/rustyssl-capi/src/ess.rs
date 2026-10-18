//! ESS (`crypto/ess`, RFC 2634 and RFC 5035): the signing-certificate attributes, made from a
//! signer's certificates and checked against a verified chain.
//!
//! The structures are opaque in `ess.h`; their layouts here are OpenSSL's internal ones
//! (`include/crypto/ess.h`), which the templates describe.

use core::ffi::{c_char, c_int, c_uint};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ASN1_INTEGER, ASN1_ITEM, ASN1_OCTET_STRING, ASN1_TFLG_OPTIONAL, ASN1_TFLG_SEQUENCE_OF,
    ERR_LIB_ASN1, ERR_LIB_ESS, ERR_R_ASN1_LIB, ERR_R_CRYPTO_LIB, ERR_R_ESS_LIB,
    ERR_R_PASSED_INVALID_ARGUMENT, ERR_R_X509_LIB, ESS_CERT_ID, ESS_CERT_ID_V2, ESS_ISSUER_SERIAL,
    ESS_R_EMPTY_ESS_CERT_ID_LIST, ESS_R_ESS_CERT_DIGEST_ERROR, ESS_R_ESS_CERT_ID_NOT_FOUND,
    ESS_R_ESS_CERT_ID_WRONG_ORDER, ESS_R_ESS_DIGEST_ALG_UNKNOWN,
    ESS_R_MISSING_SIGNING_CERTIFICATE_ATTRIBUTE, ESS_SIGNING_CERT, ESS_SIGNING_CERT_V2,
    EVP_MAX_MD_SIZE, EVP_MD, GEN_DIRNAME, GENERAL_NAME, SHA_DIGEST_LENGTH, SN_sha256, X509,
    X509_ALGOR, stack_st_X509,
};

use crate::asn1::integer::{ASN1_INTEGER_cmp, ASN1_INTEGER_dup};
use crate::asn1::string::{ASN1_INTEGER_free, ASN1_OCTET_STRING_set};
use crate::asn1::tpl::items::{
    ASN1_INTEGER_it, ASN1_OCTET_STRING_it, X509_ALGOR_free, X509_ALGOR_it, X509_ALGOR_new, d2i,
    i2d, new_free,
};
use crate::asn1::tpl::statics::{Templates, sequence};
use crate::asn1::tpl::util::ASN1_item_dup;
use crate::asn1::tpl::{item_fns, template_at};
use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_is_a};
use crate::evp::legacy_md::{EVP_get_digestbyname, EVP_sha1};
use crate::ffi::ffi_export;
use crate::objects::OBJ_obj2txt;
use crate::stack::{OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value};
use crate::x509::algor::X509_ALGOR_set_md;
use crate::x509::cert::{X509_digest, X509_get_issuer_name, X509_get0_serialNumber};
use crate::x509::name::{X509_NAME_cmp, X509_NAME_dup};
use crate::x509v3::genn::{GENERAL_NAME_free, GENERAL_NAME_it, GENERAL_NAME_new};
use crate::x509v3::policy::POLICYINFO_it;

/// A stack of anything, as the structures hold them.
type Stack = core::ffi::c_void;

/// `ESS_ISSUER_SERIAL`.
#[repr(C)]
struct IssuerSerial {
    issuer: *mut Stack,
    serial: *mut ASN1_INTEGER,
}

/// `ESS_CERT_ID`.
#[repr(C)]
struct CertId {
    hash: *mut ASN1_OCTET_STRING,
    issuer_serial: *mut IssuerSerial,
}

/// `ESS_SIGNING_CERT` and `ESS_SIGNING_CERT_V2`.
#[repr(C)]
struct SigningCert {
    cert_ids: *mut Stack,
    policy_info: *mut Stack,
}

/// `ESS_CERT_ID_V2`.
#[repr(C)]
struct CertIdV2 {
    hash_alg: *mut X509_ALGOR,
    hash: *mut ASN1_OCTET_STRING,
    issuer_serial: *mut IssuerSerial,
}

const SEQ_OF: c_int = ASN1_TFLG_SEQUENCE_OF;
const SEQ_OF_OPT: c_int = ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL;
const OPT: c_int = ASN1_TFLG_OPTIONAL;

static IS_TT: Templates<2> = Templates([
    template_at(
        SEQ_OF,
        0,
        offset_of!(IssuerSerial, issuer),
        c"issuer",
        GENERAL_NAME_it,
    ),
    template_at(
        0,
        0,
        offset_of!(IssuerSerial, serial),
        c"serial",
        ASN1_INTEGER_it,
    ),
]);

static CID_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(CertId, hash),
        c"hash",
        ASN1_OCTET_STRING_it,
    ),
    template_at(
        OPT,
        0,
        offset_of!(CertId, issuer_serial),
        c"issuer_serial",
        issuer_serial_it,
    ),
]);

static SC_TT: Templates<2> = Templates([
    template_at(
        SEQ_OF,
        0,
        offset_of!(SigningCert, cert_ids),
        c"cert_ids",
        cert_id_it,
    ),
    template_at(
        SEQ_OF_OPT,
        0,
        offset_of!(SigningCert, policy_info),
        c"policy_info",
        POLICYINFO_it,
    ),
]);

static CID2_TT: Templates<3> = Templates([
    template_at(
        OPT,
        0,
        offset_of!(CertIdV2, hash_alg),
        c"hash_alg",
        X509_ALGOR_it,
    ),
    template_at(
        0,
        0,
        offset_of!(CertIdV2, hash),
        c"hash",
        ASN1_OCTET_STRING_it,
    ),
    template_at(
        OPT,
        0,
        offset_of!(CertIdV2, issuer_serial),
        c"issuer_serial",
        issuer_serial_it,
    ),
]);

static SC2_TT: Templates<2> = Templates([
    template_at(
        SEQ_OF,
        0,
        offset_of!(SigningCert, cert_ids),
        c"cert_ids",
        cert_id_v2_it,
    ),
    template_at(
        SEQ_OF_OPT,
        0,
        offset_of!(SigningCert, policy_info),
        c"policy_info",
        POLICYINFO_it,
    ),
]);

/// `ESS_ISSUER_SERIAL_it`, which OpenSSL doesn't export.
unsafe extern "C" fn issuer_serial_it() -> *const ASN1_ITEM {
    static ITEM: crate::asn1::tpl::Item =
        sequence::<IssuerSerial, 2>(&IS_TT, None, c"ESS_ISSUER_SERIAL");
    &raw const ITEM.0
}

/// `ESS_CERT_ID_it`, which OpenSSL doesn't export.
unsafe extern "C" fn cert_id_it() -> *const ASN1_ITEM {
    static ITEM: crate::asn1::tpl::Item = sequence::<CertId, 2>(&CID_TT, None, c"ESS_CERT_ID");
    &raw const ITEM.0
}

/// `ESS_CERT_ID_V2_it`, which OpenSSL doesn't export.
unsafe extern "C" fn cert_id_v2_it() -> *const ASN1_ITEM {
    static ITEM: crate::asn1::tpl::Item =
        sequence::<CertIdV2, 3>(&CID2_TT, None, c"ESS_CERT_ID_V2");
    &raw const ITEM.0
}

item_fns! {
    /// SigningCertificate (RFC 2634): the signer's certificate and others, by SHA-1 hash.
    pub unsafe extern "C" fn ESS_SIGNING_CERT_it = sequence::<SigningCert, 2>(&SC_TT, None, c"ESS_SIGNING_CERT");
    /// SigningCertificateV2 (RFC 5035): the same, by any hash (SHA-256 by default).
    pub unsafe extern "C" fn ESS_SIGNING_CERT_V2_it = sequence::<SigningCert, 2>(&SC2_TT, None, c"ESS_SIGNING_CERT_V2");
}

new_free! {
    pub unsafe extern "C" fn ESS_ISSUER_SERIAL_new, pub unsafe extern "C" fn ESS_ISSUER_SERIAL_free(ESS_ISSUER_SERIAL) = issuer_serial_it;
    pub unsafe extern "C" fn ESS_CERT_ID_new, pub unsafe extern "C" fn ESS_CERT_ID_free(ESS_CERT_ID) = cert_id_it;
    pub unsafe extern "C" fn ESS_SIGNING_CERT_new, pub unsafe extern "C" fn ESS_SIGNING_CERT_free(ESS_SIGNING_CERT) = ESS_SIGNING_CERT_it;
    pub unsafe extern "C" fn ESS_CERT_ID_V2_new, pub unsafe extern "C" fn ESS_CERT_ID_V2_free(ESS_CERT_ID_V2) = cert_id_v2_it;
    pub unsafe extern "C" fn ESS_SIGNING_CERT_V2_new, pub unsafe extern "C" fn ESS_SIGNING_CERT_V2_free(ESS_SIGNING_CERT_V2) = ESS_SIGNING_CERT_V2_it;
}

i2d! {
    /// Encodes an issuer and serial number.
    pub unsafe extern "C" fn i2d_ESS_ISSUER_SERIAL(ESS_ISSUER_SERIAL) = issuer_serial_it;
    /// Encodes a certificate identifier.
    pub unsafe extern "C" fn i2d_ESS_CERT_ID(ESS_CERT_ID) = cert_id_it;
    /// Encodes a SigningCertificate.
    pub unsafe extern "C" fn i2d_ESS_SIGNING_CERT(ESS_SIGNING_CERT) = ESS_SIGNING_CERT_it;
    /// Encodes a certificate identifier, version 2.
    pub unsafe extern "C" fn i2d_ESS_CERT_ID_V2(ESS_CERT_ID_V2) = cert_id_v2_it;
    /// Encodes a SigningCertificateV2.
    pub unsafe extern "C" fn i2d_ESS_SIGNING_CERT_V2(ESS_SIGNING_CERT_V2) = ESS_SIGNING_CERT_V2_it;
}

d2i! {
    /// Decodes an issuer and serial number.
    pub unsafe extern "C" fn d2i_ESS_ISSUER_SERIAL(ESS_ISSUER_SERIAL) = issuer_serial_it;
    /// Decodes a certificate identifier.
    pub unsafe extern "C" fn d2i_ESS_CERT_ID(ESS_CERT_ID) = cert_id_it;
    /// Decodes a SigningCertificate.
    pub unsafe extern "C" fn d2i_ESS_SIGNING_CERT(ESS_SIGNING_CERT) = ESS_SIGNING_CERT_it;
    /// Decodes a certificate identifier, version 2.
    pub unsafe extern "C" fn d2i_ESS_CERT_ID_V2(ESS_CERT_ID_V2) = cert_id_v2_it;
    /// Decodes a SigningCertificateV2.
    pub unsafe extern "C" fn d2i_ESS_SIGNING_CERT_V2(ESS_SIGNING_CERT_V2) = ESS_SIGNING_CERT_V2_it;
}

ffi_export! {
    /// A copy (`ASN1_item_dup`), or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live value.
    pub unsafe extern "C" fn ESS_ISSUER_SERIAL_dup(a: *const ESS_ISSUER_SERIAL) -> *mut ESS_ISSUER_SERIAL
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { issuer_serial_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_dup(it, a.cast()) }.cast()
    }
}

ffi_export! {
    /// A copy (`ASN1_item_dup`), or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live value.
    pub unsafe extern "C" fn ESS_CERT_ID_dup(a: *const ESS_CERT_ID) -> *mut ESS_CERT_ID
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { cert_id_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_dup(it, a.cast()) }.cast()
    }
}

ffi_export! {
    /// A copy (`ASN1_item_dup`), or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live value.
    pub unsafe extern "C" fn ESS_SIGNING_CERT_dup(a: *const ESS_SIGNING_CERT) -> *mut ESS_SIGNING_CERT
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { ESS_SIGNING_CERT_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_dup(it, a.cast()) }.cast()
    }
}

ffi_export! {
    /// A copy (`ASN1_item_dup`), or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live value.
    pub unsafe extern "C" fn ESS_CERT_ID_V2_dup(a: *const ESS_CERT_ID_V2) -> *mut ESS_CERT_ID_V2
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { cert_id_v2_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_dup(it, a.cast()) }.cast()
    }
}

ffi_export! {
    /// A copy (`ASN1_item_dup`), or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live value.
    pub unsafe extern "C" fn ESS_SIGNING_CERT_V2_dup(a: *const ESS_SIGNING_CERT_V2) -> *mut ESS_SIGNING_CERT_V2
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { ESS_SIGNING_CERT_V2_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_dup(it, a.cast()) }.cast()
    }
}

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_ESS, reason, f);
}

/// The certificate's issuer and serial number, as `ESS_ISSUER_SERIAL` holds them, set into a
/// new value at `*slot`.
///
/// # Safety
/// `slot` is a live slot holding NULL; `cert` a live certificate.
unsafe fn set_issuer_serial(slot: *mut *mut IssuerSerial, cert: *const X509, f: &str) -> bool {
    // SAFETY: no preconditions.
    let is = unsafe { ESS_ISSUER_SERIAL_new() }.cast::<IssuerSerial>();
    // SAFETY: the caller's slot.
    unsafe { slot.write(is) };
    // SAFETY: the new value, or NULL.
    let Some(i) = (unsafe { is.as_mut() }) else {
        raise(ERR_R_ESS_LIB, f);
        return false;
    };
    // SAFETY: no preconditions.
    let name = unsafe { GENERAL_NAME_new() };
    // SAFETY: the new name, or NULL.
    let Some(n) = (unsafe { name.as_mut() }) else {
        raise(ERR_R_ASN1_LIB, f);
        return false;
    };
    n.type_ = GEN_DIRNAME;
    // SAFETY: the caller's certificate.
    let issuer = unsafe { X509_get_issuer_name(cert) };
    // SAFETY: its issuer.
    let dirn = unsafe { X509_NAME_dup(issuer) };
    if dirn.is_null() {
        raise(ERR_R_X509_LIB, f);
        // SAFETY: the name made here.
        unsafe { GENERAL_NAME_free(name) };
        return false;
    }
    n.d.dirn = dirn;
    // SAFETY: the value's list; the name.
    if unsafe { OPENSSL_sk_push(i.issuer.cast(), name.cast()) } == 0 {
        raise(ERR_R_CRYPTO_LIB, f);
        // SAFETY: as above.
        unsafe { GENERAL_NAME_free(name) };
        return false;
    }
    // SAFETY: the value's own serial.
    unsafe { ASN1_INTEGER_free(i.serial) };
    // SAFETY: the caller's certificate.
    let serial = unsafe { X509_get0_serialNumber(cert) };
    // SAFETY: its serial.
    i.serial = unsafe { ASN1_INTEGER_dup(serial) };
    if i.serial.is_null() {
        raise(ERR_R_ASN1_LIB, f);
        return false;
    }
    true
}

/// `ESS_CERT_ID_new_init`: the certificate's SHA-1 hash, and its issuer and serial number if
/// asked.
///
/// # Safety
/// `cert` is a live certificate.
unsafe fn cert_id_new_init(cert: *const X509, set_issuer_serial_too: bool) -> *mut CertId {
    const F: &str = "ESS_CERT_ID_new_init";
    // SAFETY: no preconditions.
    let cid = unsafe { ESS_CERT_ID_new() }.cast::<CertId>();
    let ok = 'err: {
        // SAFETY: the new value, or NULL.
        let Some(c) = (unsafe { cid.as_mut() }) else {
            raise(ERR_R_ESS_LIB, F);
            break 'err false;
        };
        let mut sha1 = [0u8; SHA_DIGEST_LENGTH as usize];
        // SAFETY: no preconditions.
        let md = unsafe { EVP_sha1() };
        // SAFETY: the caller's certificate; room for a SHA-1 digest.
        if unsafe { X509_digest(cert, md, sha1.as_mut_ptr(), ptr::null_mut()) } == 0 {
            raise(ERR_R_X509_LIB, F);
            break 'err false;
        }
        let n = c_int::try_from(sha1.len()).unwrap_or(0);
        // SAFETY: the value's string; the digest.
        if unsafe { ASN1_OCTET_STRING_set(c.hash, sha1.as_ptr(), n) } == 0 {
            raise(ERR_R_ASN1_LIB, F);
            break 'err false;
        }
        if !set_issuer_serial_too {
            break 'err true;
        }
        // SAFETY: the value's empty slot; the caller's certificate.
        c.issuer_serial.is_null() && unsafe { set_issuer_serial(&mut c.issuer_serial, cert, F) }
    };
    if ok {
        return cid;
    }
    // SAFETY: the value made here, or NULL.
    unsafe { ESS_CERT_ID_free(cid.cast()) };
    ptr::null_mut()
}

/// `ESS_CERT_ID_V2_new_init`: the certificate's hash with `hash_alg` (named unless it is
/// SHA-256), and its issuer and serial number if asked.
///
/// # Safety
/// `hash_alg` is a live digest; `cert` a live certificate.
unsafe fn cert_id_v2_new_init(
    hash_alg: *const EVP_MD,
    cert: *const X509,
    set_issuer_serial_too: bool,
) -> *mut CertIdV2 {
    const F: &str = "ESS_CERT_ID_V2_new_init";
    // SAFETY: no preconditions.
    let cid = unsafe { ESS_CERT_ID_V2_new() }.cast::<CertIdV2>();
    let mut alg: *mut X509_ALGOR = ptr::null_mut();
    let ok = 'err: {
        // SAFETY: the new value, or NULL.
        let Some(c) = (unsafe { cid.as_mut() }) else {
            raise(ERR_R_ESS_LIB, F);
            break 'err false;
        };
        // SAFETY: the caller's digest; a static name.
        if unsafe { EVP_MD_is_a(hash_alg, SN_sha256.as_ptr()) } == 0 {
            // SAFETY: no preconditions.
            alg = unsafe { X509_ALGOR_new() };
            if alg.is_null() {
                raise(ERR_R_ASN1_LIB, F);
                break 'err false;
            }
            // SAFETY: the new identifier; the caller's digest.
            unsafe { X509_ALGOR_set_md(alg, hash_alg) };
            // SAFETY: as above.
            if unsafe { (*alg).algorithm }.is_null() {
                raise(ERR_R_ASN1_LIB, F);
                break 'err false;
            }
            c.hash_alg = alg;
            alg = ptr::null_mut();
        } else {
            c.hash_alg = ptr::null_mut();
        }
        let mut hash = [0u8; EVP_MAX_MD_SIZE as usize];
        let mut hash_len: c_uint = c_uint::try_from(hash.len()).unwrap_or(0);
        // SAFETY: the caller's certificate and digest; room for any digest.
        if unsafe { X509_digest(cert, hash_alg, hash.as_mut_ptr(), &mut hash_len) } == 0 {
            raise(ERR_R_X509_LIB, F);
            break 'err false;
        }
        let n = c_int::try_from(hash_len).unwrap_or(0);
        // SAFETY: the value's string; the digest.
        if unsafe { ASN1_OCTET_STRING_set(c.hash, hash.as_ptr(), n) } == 0 {
            raise(ERR_R_ASN1_LIB, F);
            break 'err false;
        }
        if !set_issuer_serial_too {
            break 'err true;
        }
        // SAFETY: the value's empty slot; the caller's certificate.
        unsafe { set_issuer_serial(&mut c.issuer_serial, cert, F) }
    };
    // SAFETY: the identifier made here and not handed on, or NULL.
    unsafe { X509_ALGOR_free(alg) };
    if ok {
        return cid;
    }
    // SAFETY: the value made here, or NULL.
    unsafe { ESS_CERT_ID_V2_free(cid.cast()) };
    ptr::null_mut()
}

ffi_export! {
    /// A SigningCertificate for `signcert` (with its issuer and serial if asked) and each of
    /// `certs` (with theirs), or NULL.
    ///
    /// # Safety
    /// `signcert` is a live certificate; `certs` NULL or a live list.
    pub unsafe extern "C" fn OSSL_ESS_signing_cert_new_init(signcert: *const X509, certs: *const stack_st_X509, set_issuer_serial: c_int) -> *mut ESS_SIGNING_CERT
    where failure = ptr::null_mut(), library = ERR_LIB_ESS
    {
        const F: &str = "OSSL_ESS_signing_cert_new_init";
        // SAFETY: no preconditions.
        let sc = unsafe { ESS_SIGNING_CERT_new() };
        let mut cid: *mut CertId = ptr::null_mut();
        let ok = 'err: {
            // SAFETY: the new value, or NULL.
            let Some(s) = (unsafe { sc.cast::<SigningCert>().as_mut() }) else {
                raise(ERR_R_ESS_LIB, F);
                break 'err false;
            };
            if s.cert_ids.is_null() {
                // SAFETY: no preconditions.
                s.cert_ids = unsafe { OPENSSL_sk_new_null() }.cast();
                if s.cert_ids.is_null() {
                    raise(ERR_R_CRYPTO_LIB, F);
                    break 'err false;
                }
            }
            // SAFETY: the caller's certificate.
            cid = unsafe { cert_id_new_init(signcert, set_issuer_serial != 0) };
            // SAFETY: the list; the identifier.
            if cid.is_null() || unsafe { OPENSSL_sk_push(s.cert_ids.cast(), cid.cast()) } == 0 {
                raise(ERR_R_ESS_LIB, F);
                break 'err false;
            }
            cid = ptr::null_mut();
            // SAFETY: the caller's certificates, or NULL.
            for i in 0..unsafe { OPENSSL_sk_num(certs.cast()) } {
                // SAFETY: an index within them.
                let cert = unsafe { OPENSSL_sk_value(certs.cast(), i) }.cast::<X509>();
                // SAFETY: a certificate.
                cid = unsafe { cert_id_new_init(cert, true) };
                if cid.is_null() {
                    raise(ERR_R_ESS_LIB, F);
                    break 'err false;
                }
                // SAFETY: the list; the identifier.
                if unsafe { OPENSSL_sk_push(s.cert_ids.cast(), cid.cast()) } == 0 {
                    raise(ERR_R_CRYPTO_LIB, F);
                    break 'err false;
                }
                cid = ptr::null_mut();
            }
            true
        };
        if ok {
            return sc;
        }
        // SAFETY: the values made here, or NULL.
        unsafe { ESS_SIGNING_CERT_free(sc) };
        // SAFETY: as above.
        unsafe { ESS_CERT_ID_free(cid.cast()) };
        ptr::null_mut()
    }
}

ffi_export! {
    /// A SigningCertificateV2 for `signcert` and each of `certs`, hashed with `hash_alg`, or
    /// NULL.
    ///
    /// # Safety
    /// `hash_alg` is a live digest; `signcert` a live certificate; `certs` NULL or a live list.
    pub unsafe extern "C" fn OSSL_ESS_signing_cert_v2_new_init(hash_alg: *const EVP_MD, signcert: *const X509, certs: *const stack_st_X509, set_issuer_serial: c_int) -> *mut ESS_SIGNING_CERT_V2
    where failure = ptr::null_mut(), library = ERR_LIB_ESS
    {
        const F: &str = "OSSL_ESS_signing_cert_v2_new_init";
        // SAFETY: no preconditions.
        let sc = unsafe { ESS_SIGNING_CERT_V2_new() };
        let mut cid: *mut CertIdV2 = ptr::null_mut();
        let ok = 'err: {
            // SAFETY: the new value, or NULL.
            let Some(s) = (unsafe { sc.cast::<SigningCert>().as_mut() }) else {
                raise(ERR_R_ESS_LIB, F);
                break 'err false;
            };
            // SAFETY: the caller's digest and certificate.
            cid = unsafe { cert_id_v2_new_init(hash_alg, signcert, set_issuer_serial != 0) };
            if cid.is_null() {
                raise(ERR_R_ESS_LIB, F);
                break 'err false;
            }
            // SAFETY: the value's list; the identifier.
            if unsafe { OPENSSL_sk_push(s.cert_ids.cast(), cid.cast()) } == 0 {
                raise(ERR_R_CRYPTO_LIB, F);
                break 'err false;
            }
            cid = ptr::null_mut();
            // SAFETY: the caller's certificates, or NULL.
            for i in 0..unsafe { OPENSSL_sk_num(certs.cast()) } {
                // SAFETY: an index within them.
                let cert = unsafe { OPENSSL_sk_value(certs.cast(), i) }.cast::<X509>();
                // SAFETY: the caller's digest; a certificate.
                cid = unsafe { cert_id_v2_new_init(hash_alg, cert, true) };
                if cid.is_null() {
                    raise(ERR_R_ESS_LIB, F);
                    break 'err false;
                }
                // SAFETY: as above.
                if unsafe { OPENSSL_sk_push(s.cert_ids.cast(), cid.cast()) } == 0 {
                    raise(ERR_R_CRYPTO_LIB, F);
                    break 'err false;
                }
                cid = ptr::null_mut();
            }
            true
        };
        if ok {
            return sc;
        }
        // SAFETY: the values made here, or NULL.
        unsafe { ESS_SIGNING_CERT_V2_free(sc) };
        // SAFETY: as above.
        unsafe { ESS_CERT_ID_V2_free(cid.cast()) };
        ptr::null_mut()
    }
}

/// `ess_issuer_serial_cmp`: 0 if the issuer (one directory name) and serial are the
/// certificate's.
///
/// # Safety
/// `is` and `cert` are NULL or live.
unsafe fn issuer_serial_cmp(is: *const IssuerSerial, cert: *const X509) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(i) = (unsafe { is.as_ref() }) else {
        return -1;
    };
    // SAFETY: the value's names.
    if cert.is_null() || unsafe { OPENSSL_sk_num(i.issuer.cast()) } != 1 {
        return -1;
    }
    // SAFETY: the only name.
    let issuer = unsafe { OPENSSL_sk_value(i.issuer.cast(), 0) }.cast::<GENERAL_NAME>();
    // SAFETY: a live name, or NULL.
    let Some(g) = (unsafe { issuer.as_ref() }) else {
        return -1;
    };
    if g.type_ != GEN_DIRNAME {
        return -1;
    }
    // SAFETY: the certificate.
    let ci = unsafe { X509_get_issuer_name(cert) };
    // SAFETY: a directory name's member.
    let dirn = unsafe { g.d.dirn };
    // SAFETY: live names.
    if unsafe { X509_NAME_cmp(dirn, ci) } != 0 {
        return -1;
    }
    // SAFETY: the certificate.
    let serial = unsafe { X509_get0_serialNumber(cert) };
    // SAFETY: live integers.
    unsafe { ASN1_INTEGER_cmp(i.serial, serial) }
}

/// `find`: the 1-based position in `certs` of the certificate the identifier names (which
/// must be the first exactly when `index` is 0), 0 if none, or -1.
///
/// # Safety
/// `hash` and `is` belong to a live identifier; `alg` is NULL or live; `certs` NULL or live.
unsafe fn find(
    v1: bool,
    hash: *const ASN1_OCTET_STRING,
    alg: *const X509_ALGOR,
    is: *const IssuerSerial,
    index: c_int,
    certs: *const stack_st_X509,
) -> c_int {
    const F: &str = "find";
    let mut name = [0 as c_char; 50];
    let set = |name: &mut [c_char; 50], s: &[u8]| {
        for (d, &b) in name.iter_mut().zip(s) {
            *d = c_char::from_ne_bytes([b]);
        }
    };
    if v1 {
        set(&mut name, b"SHA1\0");
    // SAFETY: the identifier's algorithm, or NULL.
    } else if let Some(a) = unsafe { alg.as_ref() } {
        // SAFETY: room for the name; its object.
        unsafe { OBJ_obj2txt(name.as_mut_ptr(), 50, a.algorithm, 0) };
    } else {
        set(&mut name, b"SHA256\0");
    }
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: a NUL-terminated name.
    let fetched = unsafe { EVP_MD_fetch(ptr::null_mut(), name.as_ptr(), ptr::null()) };
    let md = if fetched.is_null() {
        // SAFETY: as above.
        unsafe { EVP_get_digestbyname(name.as_ptr()) }
    } else {
        fetched.cast_const()
    };
    let ret = 'end: {
        if md.is_null() {
            // SAFETY: no preconditions.
            unsafe { ERR_clear_last_mark() };
            raise(ESS_R_ESS_DIGEST_ALG_UNKNOWN, F);
            break 'end -1;
        }
        // SAFETY: no preconditions.
        unsafe { ERR_pop_to_mark() };
        // SAFETY: the identifier's hash.
        let want = unsafe { crate::cms::base::octets(hash) };
        // SAFETY: the certificates, or NULL.
        for i in 0..unsafe { OPENSSL_sk_num(certs.cast()) } {
            // SAFETY: an index within them.
            let cert = unsafe { OPENSSL_sk_value(certs.cast(), i) }.cast::<X509>();
            let mut digest = [0u8; EVP_MAX_MD_SIZE as usize];
            let mut len: c_uint = 0;
            // SAFETY: a certificate; the digest; room for any digest.
            let ok = unsafe { X509_digest(cert, md, digest.as_mut_ptr(), &mut len) } != 0;
            let got = digest
                .get(..usize::try_from(len).unwrap_or(0))
                .unwrap_or_default();
            if !ok || got.len() != want.len() {
                raise(ESS_R_ESS_CERT_DIGEST_ERROR, F);
                break 'end -1;
            }
            if got == want {
                // SAFETY: the identifier's issuer and serial, or NULL; the certificate.
                if is.is_null() || unsafe { issuer_serial_cmp(is, cert) } == 0 {
                    if (i == 0) == (index == 0) {
                        break 'end i.saturating_add(1);
                    }
                    raise(ESS_R_ESS_CERT_ID_WRONG_ORDER, F);
                    break 'end -1;
                }
            }
        }
        raise(ESS_R_ESS_CERT_ID_NOT_FOUND, F);
        0
    };
    // SAFETY: the fetched digest, or NULL.
    unsafe { EVP_MD_free(fetched) };
    ret
}

ffi_export! {
    /// Checks that every certificate the attributes name is in `chain` (the signer's first):
    /// 1, 0 if one is missing, or -1 (also when an attribute is required and there is none).
    ///
    /// # Safety
    /// `ss` and `ssv2` are NULL or live; `chain` NULL or a live list.
    pub unsafe extern "C" fn OSSL_ESS_check_signing_certs(ss: *const ESS_SIGNING_CERT, ssv2: *const ESS_SIGNING_CERT_V2, chain: *const stack_st_X509, require_signing_cert: c_int) -> c_int
    where failure = -1, library = ERR_LIB_ESS
    {
        const F: &str = "OSSL_ESS_check_signing_certs";
        // SAFETY: the caller's guarantee.
        let v1 = unsafe { ss.cast::<SigningCert>().as_ref() };
        // SAFETY: as above.
        let v2 = unsafe { ssv2.cast::<SigningCert>().as_ref() };
        // SAFETY: their lists.
        let n_v1 = v1.map_or(-1, |s| unsafe { OPENSSL_sk_num(s.cert_ids.cast()) });
        // SAFETY: as above.
        let n_v2 = v2.map_or(-1, |s| unsafe { OPENSSL_sk_num(s.cert_ids.cast()) });
        if require_signing_cert != 0 && v1.is_none() && v2.is_none() {
            raise(ESS_R_MISSING_SIGNING_CERTIFICATE_ATTRIBUTE, F);
            return -1;
        }
        if n_v1 == 0 || n_v2 == 0 {
            raise(ESS_R_EMPTY_ESS_CERT_ID_LIST, F);
            return -1;
        }
        if let Some(s) = v1 {
            for i in 0..n_v1 {
                // SAFETY: an index within the list.
                let p = unsafe { OPENSSL_sk_value(s.cert_ids.cast(), i) }.cast::<CertId>();
                // SAFETY: an identifier, or NULL.
                let Some(cid) = (unsafe { p.as_ref() }) else {
                    raise(ERR_R_PASSED_INVALID_ARGUMENT, "find");
                    return -1;
                };
                // SAFETY: the identifier's parts; the caller's chain.
                let r = unsafe { find(true, cid.hash, ptr::null(), cid.issuer_serial, i, chain) };
                if r <= 0 {
                    return r;
                }
            }
        }
        if let Some(s) = v2 {
            for i in 0..n_v2 {
                // SAFETY: an index within the list.
                let p = unsafe { OPENSSL_sk_value(s.cert_ids.cast(), i) }.cast::<CertIdV2>();
                // SAFETY: an identifier, or NULL.
                let Some(cid) = (unsafe { p.as_ref() }) else {
                    raise(ERR_R_PASSED_INVALID_ARGUMENT, "find");
                    return -1;
                };
                // SAFETY: as above.
                let r = unsafe { find(false, cid.hash, cid.hash_alg, cid.issuer_serial, i, chain) };
                if r <= 0 {
                    return r;
                }
            }
        }
        1
    }
}
