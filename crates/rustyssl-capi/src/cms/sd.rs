//! SignedData (`cms_sd.c`, and the signature half of `cms_rsa.c`): signers and their
//! identifiers, signing (over signed attributes or the content's digest), verifying, the data
//! path's digests, and S/MIME capabilities.
//!
//! The content's message digest is compared in constant time.

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_INTEGER, ASN1_OCTET_STRING, ASN1_PKEY_CTRL_CMS_SIGN, BIO, CMS_CADES, CMS_ContentInfo,
    CMS_KEY_PARAM, CMS_NO_SIGNING_TIME, CMS_NOATTR, CMS_NOCERTS, CMS_NOINTERN, CMS_NOSMIMECAP,
    CMS_PARTIAL, CMS_R_CONTENT_TYPE_NOT_SIGNED_DATA, CMS_R_CTRL_FAILURE,
    CMS_R_ERROR_READING_MESSAGEDIGEST_ATTRIBUTE, CMS_R_MESSAGEDIGEST_ATTRIBUTE_WRONG_LENGTH,
    CMS_R_NO_DEFAULT_DIGEST, CMS_R_NO_MATCHING_DIGEST, CMS_R_NO_PRIVATE_KEY, CMS_R_NO_PUBLIC_KEY,
    CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE, CMS_R_OPERATION_UNSUPPORTED,
    CMS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE, CMS_R_SIGNFINAL_ERROR,
    CMS_R_UNABLE_TO_FINALIZE_CONTEXT, CMS_R_UNKNOWN_DIGEST_ALGORITHM, CMS_R_UNKNOWN_ID,
    CMS_R_UNSUPPORTED_SIGNATURE_ALGORITHM, CMS_R_VERIFICATION_FAILURE, CMS_REUSE_DIGEST,
    CMS_SIGNERINFO_ISSUER_SERIAL, CMS_SIGNERINFO_KEYIDENTIFIER, CMS_SignedData, CMS_SignerInfo,
    CMS_USE_KEYID, ERR_LIB_CMS, ERR_LIB_RSA, ERR_R_ASN1_LIB, ERR_R_CMS_LIB, ERR_R_CRYPTO_LIB,
    ERR_R_EVP_LIB, ERR_R_PASSED_NULL_PARAMETER, ERR_R_X509_LIB, EVP_MAX_MD_SIZE, EVP_MD,
    EVP_MD_CTX, EVP_PKEY, EVP_PKEY_CTX, EVP_PKEY_RSA_PSS, NID_SMIMECapabilities, NID_aes_128_cbc,
    NID_aes_192_cbc, NID_aes_256_cbc, NID_des_cbc, NID_des_ede3_cbc, NID_id_Gost28147_89,
    NID_id_GostR3411_94, NID_id_GostR3411_2012_256, NID_id_GostR3411_2012_512,
    NID_id_smime_aa_signingCertificate, NID_id_smime_aa_signingCertificateV2, NID_pkcs7_data,
    NID_pkcs7_signed, NID_pkcs9_contentType, NID_pkcs9_messageDigest, NID_pkcs9_signingTime,
    NID_rc2_cbc, NID_rsaEncryption, NID_undef, OSSL_LIB_CTX, RSA_PKCS1_PADDING,
    RSA_PKCS1_PSS_PADDING, RSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE, SN_sha1, V_ASN1_INTEGER,
    V_ASN1_NULL, V_ASN1_OBJECT, V_ASN1_OCTET_STRING, V_ASN1_SEQUENCE, V_ASN1_UNDEF, X509,
    X509_ADD_FLAG_DEFAULT, X509_ALGOR, X509_CRL, X509_NAME, X509_STORE, stack_st_X509,
    stack_st_X509_ALGOR, stack_st_X509_CRL,
};

use super::att::{
    CMS_signed_add1_attr_by_NID, CMS_signed_get_attr_by_NID, CMS_signed_get_attr_count,
    CMS_signed_get0_data_by_OBJ, si_check_attributes, si_of,
};
use super::base::{
    CMS_ContentInfo_free, CMS_ContentInfo_new_ex, CMS_add1_cert, CMS_add1_crl, cms_of, content,
    ctx_of, ctx_parts, digest_algorithm_find_ctx, digest_algorithm_init_bio, ias_cert_cmp,
    keyid_cert_cmp, nid_obj, octets, raise, set1_ias, set1_keyid, type_nid,
};
use super::{
    CERTCHOICE_CERT, CertificateChoices, IssuerAndSerialNumber, RevocationInfoChoice, SignedData,
    SignerIdentifier, SignerInfo, Stack, sk_get,
};
use crate::asn1::integer::ASN1_INTEGER_set;
use crate::asn1::sign::{ASN1_item_sign_ctx, ASN1_item_verify_ex, algorithm_id};
use crate::asn1::string::{ASN1_INTEGER_free, ASN1_INTEGER_new, ASN1_STRING_set0};
use crate::asn1::tpl::encode::ASN1_item_i2d;
use crate::asn1::tpl::free::ASN1_item_free;
use crate::asn1::tpl::items::{ASN1_TIME_free, X509_ALGOR_free, X509_ALGOR_new};
use crate::asn1::tpl::new::ASN1_item_new;
use crate::bio::{BIO_free_all, BIO_push};
use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_get0_name, EVP_MD_is_a};
use crate::evp::legacy_cipher::EVP_get_cipherbyname;
use crate::evp::legacy_md::EVP_get_digestbyname;
use crate::evp::md_ctx::{
    EVP_DigestFinal_ex, EVP_MD_CTX_free, EVP_MD_CTX_get0_md, EVP_MD_CTX_new, EVP_MD_CTX_reset,
    EVP_MD_CTX_set_flags,
};
use crate::evp::pkey::rsa::{ctx_to_pss_string, pss_to_ctx};
use crate::evp::pkey::{
    EVP_PKEY_free, EVP_PKEY_get_default_digest_name, EVP_PKEY_get_default_digest_nid,
    EVP_PKEY_get_id, EVP_PKEY_get_size, EVP_PKEY_get0_type_name, EVP_PKEY_is_a, EVP_PKEY_up_ref,
    asn1_ctrl_of,
};
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_get0_pkey, EVP_PKEY_CTX_new_from_pkey};
use crate::evp::setters::EVP_PKEY_CTX_get_rsa_padding;
use crate::evp::signature::{
    EVP_PKEY_CTX_set_signature_md, EVP_PKEY_sign, EVP_PKEY_sign_init, EVP_PKEY_verify,
    EVP_PKEY_verify_init,
};
use crate::evp::sigver::{
    EVP_DigestSignFinal, EVP_DigestSignInit_ex, EVP_DigestSignUpdate, EVP_DigestVerifyFinal,
    EVP_DigestVerifyInit_ex, EVP_DigestVerifyUpdate, EVP_SignFinal_ex,
};
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::sigid::{OBJ_find_sigid_algs, OBJ_find_sigid_by_algs};
use crate::objects::{OBJ_cmp, OBJ_nid2sn, OBJ_obj2nid, OBJ_obj2txt, OBJ_txt2nid};
use crate::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
};
use crate::x509::algor::{X509_ALGOR_set_md, X509_ALGOR_set0, i2d_X509_ALGORS};
use crate::x509::cert::{
    X509_check_private_key, X509_free, X509_get_pubkey, X509_gmtime_adj, X509_up_ref,
};
use crate::x509::purpose::{X509_add_cert, X509_check_purpose};

/// `EVP_MD_CTX_FLAG_KEEP_PKEY_CTX`: the signer keeps its key context across resets.
#[expect(clippy::cast_possible_truncation, reason = "a flag of the low bits")]
const KEEP_PKEY_CTX: c_int = crate::evp::md_ctx::FLAG_KEEP_PKEY_CTX as c_int;

/// `OSSL_MAX_NAME_SIZE`, the room for an algorithm's name.
const NAME_LEN: usize = 50;

// `cms_local.h`'s other choices, which raise the version.
const CERTCHOICE_V1ACERT: c_int = 2;
const CERTCHOICE_V2ACERT: c_int = 3;
const CERTCHOICE_OTHER: c_int = 4;
const REVCHOICE_OTHER: c_int = 1;

/// The name of an algorithm's object, NUL-terminated.
fn name_of(obj: *const rustyssl_abi::ASN1_OBJECT) -> [c_char; NAME_LEN] {
    let mut name = [0 as c_char; NAME_LEN];
    let len = c_int::try_from(NAME_LEN).unwrap_or(0);
    // SAFETY: room for the name; the object, or NULL.
    unsafe { OBJ_obj2txt(name.as_mut_ptr(), len, obj, 0) };
    name
}

/// An algorithm identifier's object, NULL for none.
fn alg_obj(a: *const X509_ALGOR) -> *mut rustyssl_abi::ASN1_OBJECT {
    // SAFETY: NULL or a live algorithm identifier.
    unsafe { a.as_ref() }.map_or(ptr::null_mut(), |a| a.algorithm)
}

/// `EVP_get_digestbynid`.
fn digest_by_nid(nid: c_int) -> *const EVP_MD {
    // SAFETY: any NID.
    let sn = unsafe { OBJ_nid2sn(nid) };
    // SAFETY: NULL or a static name.
    unsafe { EVP_get_digestbyname(sn) }
}

/// `cms_get0_signed`: SignedData's content, or `None` (`CMS_R_CONTENT_TYPE_NOT_SIGNED_DATA`).
pub(crate) fn get0_signed<'a>(cms: *const CMS_ContentInfo) -> Option<&'a mut SignedData> {
    if type_nid(cms) != NID_pkcs7_signed {
        raise(CMS_R_CONTENT_TYPE_NOT_SIGNED_DATA, "cms_get0_signed");
        return None;
    }
    // SAFETY: the content of its type, NULL or live.
    unsafe { content::<SignedData>(cms) }
}

/// `cms_signed_data_init`: the object made SignedData (with partial Data content) if it has
/// no content yet.
///
/// # Safety
/// `cms` is NULL or a live object.
unsafe fn signed_data_init<'a>(cms: *mut CMS_ContentInfo) -> Option<&'a mut SignedData> {
    // SAFETY: the caller's guarantee.
    let c = unsafe { cms_of(cms) }?;
    if !c.d.is_null() {
        return get0_signed(cms);
    }
    // SAFETY: no preconditions.
    let it = unsafe { super::signed_data_it() };
    // SAFETY: the item.
    let sd = unsafe { ASN1_item_new(it) }.cast::<SignedData>();
    // SAFETY: the new content, or NULL.
    let Some(s) = (unsafe { sd.as_mut() }) else {
        raise(ERR_R_ASN1_LIB, "cms_signed_data_init");
        return None;
    };
    c.d = sd.cast();
    s.version = 1;
    // SAFETY: its encapsulated content, made with it.
    if let Some(e) = unsafe { s.encap.as_mut() } {
        e.e_content_type = nid_obj(NID_pkcs7_data);
        e.partial = 1;
    }
    // SAFETY: the object's own type, or NULL.
    unsafe { crate::objects::ASN1_OBJECT_free(c.content_type) };
    c.content_type = nid_obj(NID_pkcs7_signed);
    Some(s)
}

ffi_export! {
    /// Makes an empty object SignedData: 1, or 0.
    ///
    /// # Safety
    /// `cms` is NULL or a live object.
    pub unsafe extern "C" fn CMS_SignedData_init(cms: *mut CMS_ContentInfo) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { signed_data_init(cms) }.is_some())
    }
}

crate::asn1::tpl::items::new_free! {
    pub unsafe extern "C" fn CMS_SignedData_new, pub unsafe extern "C" fn CMS_SignedData_free(CMS_SignedData) = signed_data_item;
}

/// `CMS_SignedData_it` as `new_free!` takes it.
unsafe extern "C" fn signed_data_item() -> *const rustyssl_abi::ASN1_ITEM {
    // SAFETY: no preconditions.
    unsafe { super::signed_data_it() }
}

/// `cms_sd_set_version`.
fn sd_set_version(sd: &mut SignedData) {
    // SAFETY: the content's certificates, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(sd.certificates.cast()) } {
        // SAFETY: an index within them.
        let Some(cch) = (unsafe { sk_get::<CertificateChoices>(sd.certificates, i) }) else {
            continue;
        };
        let min = match cch.type_ {
            CERTCHOICE_OTHER => 5,
            CERTCHOICE_V2ACERT => 4,
            CERTCHOICE_V1ACERT => 3,
            _ => 0,
        };
        sd.version = sd.version.max(min);
    }
    // SAFETY: the content's CRLs, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(sd.crls.cast()) } {
        // SAFETY: an index within them.
        if let Some(rch) = unsafe { sk_get::<RevocationInfoChoice>(sd.crls, i) }
            && rch.type_ == REVCHOICE_OTHER
        {
            sd.version = sd.version.max(5);
        }
    }
    // SAFETY: the content's encapsulated content, live with it.
    let etype = unsafe { sd.encap.as_ref() }.map_or(ptr::null_mut(), |e| e.e_content_type);
    // SAFETY: its type, or NULL.
    if unsafe { OBJ_obj2nid(etype) } != NID_pkcs7_data && sd.version < 3 {
        sd.version = 3;
    }
    // SAFETY: the content's signer infos, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(sd.signer_infos.cast()) } {
        // SAFETY: an index within them.
        let Some(si) = (unsafe { sk_get::<SignerInfo>(sd.signer_infos, i) }) else {
            continue;
        };
        // SAFETY: its identifier, live with it.
        let keyid =
            unsafe { si.sid.as_ref() }.is_some_and(|s| s.type_ == CMS_SIGNERINFO_KEYIDENTIFIER);
        if keyid {
            si.version = si.version.max(3);
            sd.version = sd.version.max(3);
        } else if si.version < 1 {
            si.version = 1;
        }
    }
    sd.version = sd.version.max(1);
}

/// `cms_set_si_contentType_attr`: the content type as a signed attribute.
fn set_si_content_type_attr(cms: *mut CMS_ContentInfo, si: *mut CMS_SignerInfo) -> bool {
    let ctype = get0_signed(cms)
        // SAFETY: the content's encapsulated content, live with it.
        .and_then(|s| unsafe { s.encap.as_ref() })
        .map_or(ptr::null_mut(), |e| e.e_content_type);
    // SAFETY: the signer info; the object, as an ASN1_OBJECT value.
    (unsafe {
        CMS_signed_add1_attr_by_NID(si, NID_pkcs9_contentType, V_ASN1_OBJECT, ctype.cast(), -1)
    }) > 0
}

/// `cms_copy_messageDigest`: the message digest of another signer with the same digest
/// algorithm and signed attributes.
fn copy_message_digest(cms: *mut CMS_ContentInfo, si: *mut CMS_SignerInfo) -> bool {
    const F: &str = "cms_copy_messageDigest";
    let sinfos = super::base::signer_infos(cms);
    // SAFETY: the signer info.
    let Some(s) = (unsafe { si_of(si) }) else {
        return false;
    };
    let alg = alg_obj(s.digest_algorithm);
    // SAFETY: the object's signer infos, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(sinfos.cast()) } {
        // SAFETY: an index within them.
        let Some(other) = (unsafe { sk_get::<SignerInfo>(sinfos, i) }) else {
            continue;
        };
        let optr: *mut SignerInfo = other;
        if optr.cast::<CMS_SignerInfo>() == si {
            continue;
        }
        // SAFETY: a signer info.
        if unsafe { CMS_signed_get_attr_count(optr.cast()) } < 0 {
            continue;
        }
        // SAFETY: live objects, or NULL.
        if unsafe { OBJ_cmp(alg, alg_obj(other.digest_algorithm)) } != 0 {
            continue;
        }
        let md_obj = nid_obj(NID_pkcs9_messageDigest);
        // SAFETY: a signer info; a static object.
        let digest =
            unsafe { CMS_signed_get0_data_by_OBJ(optr.cast(), md_obj, -3, V_ASN1_OCTET_STRING) };
        if digest.is_null() {
            raise(CMS_R_ERROR_READING_MESSAGEDIGEST_ATTRIBUTE, F);
            return false;
        }
        // SAFETY: the signer info; the digest string, as a value.
        return unsafe {
            CMS_signed_add1_attr_by_NID(
                si,
                NID_pkcs9_messageDigest,
                V_ASN1_OCTET_STRING,
                digest,
                -1,
            )
        } != 0;
    }
    raise(CMS_R_NO_MATCHING_DIGEST, F);
    false
}

/// `ossl_cms_set1_SignerIdentifier`: issuer and serial, or the subject key identifier.
///
/// # Safety
/// `sid` is a live identifier; `cert` a live certificate.
pub(crate) unsafe fn set1_signer_identifier(
    sid: &mut SignerIdentifier,
    cert: *mut X509,
    type_: c_int,
) -> bool {
    match type_ {
        CMS_SIGNERINFO_ISSUER_SERIAL => {
            // SAFETY: the identifier's slot; the caller's certificate.
            if !unsafe { set1_ias((&raw mut sid.d).cast(), cert) } {
                return false;
            }
        }
        CMS_SIGNERINFO_KEYIDENTIFIER => {
            // SAFETY: the identifier's slot; the caller's certificate.
            if !unsafe { set1_keyid((&raw mut sid.d).cast(), cert) } {
                return false;
            }
        }
        _ => {
            raise(CMS_R_UNKNOWN_ID, "ossl_cms_set1_SignerIdentifier");
            return false;
        }
    }
    sid.type_ = type_;
    true
}

/// `ossl_cms_SignerIdentifier_get0_signer_id`.
///
/// # Safety
/// `sid` is a live identifier; the others NULL or room for a pointer.
pub(crate) unsafe fn signer_identifier_get0(
    sid: &SignerIdentifier,
    keyid: *mut *mut ASN1_OCTET_STRING,
    issuer: *mut *mut X509_NAME,
    sno: *mut *mut ASN1_INTEGER,
) -> c_int {
    match sid.type_ {
        CMS_SIGNERINFO_ISSUER_SERIAL => {
            // SAFETY: the choice's member, live.
            let Some(ias) = (unsafe { sid.d.cast::<IssuerAndSerialNumber>().as_ref() }) else {
                return 0;
            };
            // SAFETY: the caller's room, or NULL.
            if let Some(p) = unsafe { issuer.as_mut() } {
                *p = ias.issuer;
            }
            // SAFETY: as above.
            if let Some(p) = unsafe { sno.as_mut() } {
                *p = ias.serial_number;
            }
            1
        }
        CMS_SIGNERINFO_KEYIDENTIFIER => {
            // SAFETY: as above.
            if let Some(p) = unsafe { keyid.as_mut() } {
                *p = sid.d.cast();
            }
            1
        }
        _ => 0,
    }
}

/// `ossl_cms_SignerIdentifier_cert_cmp`: 0 if the identifier is the certificate's.
///
/// # Safety
/// `sid` is a live identifier; `cert` a live certificate.
pub(crate) unsafe fn signer_identifier_cert_cmp(sid: &SignerIdentifier, cert: *mut X509) -> c_int {
    match sid.type_ {
        CMS_SIGNERINFO_ISSUER_SERIAL => {
            // SAFETY: the choice's member, live.
            let Some(ias) = (unsafe { sid.d.cast::<IssuerAndSerialNumber>().as_ref() }) else {
                return -1;
            };
            // SAFETY: the caller's certificate.
            unsafe { ias_cert_cmp(ias, cert) }
        }
        // SAFETY: as above.
        CMS_SIGNERINFO_KEYIDENTIFIER => unsafe { keyid_cert_cmp(sid.d.cast(), cert) },
        _ => -1,
    }
}

/// `cms_signature_nomd`: whether the key signs without a separate digest (Ed25519 and the
/// like).
fn signature_nomd(pkey: *mut EVP_PKEY) -> bool {
    let mut def_md = [0 as c_char; 80];
    // SAFETY: the signer's key; room for the name.
    let r = unsafe { EVP_PKEY_get_default_digest_name(pkey, def_md.as_mut_ptr(), def_md.len()) };
    // SAFETY: a NUL-terminated name.
    r == 2 && unsafe { core::ffi::CStr::from_ptr(def_md.as_ptr()) }.to_bytes() == b"UNDEF"
}

/// `cms_generic_sign`: the signature algorithm from the digest and key types.
fn generic_sign(si: &mut SignerInfo, verify: bool) -> c_int {
    if verify {
        return 1;
    }
    let pkey = si.pkey;
    // SAFETY: the signer's key.
    let mut pknid = unsafe { EVP_PKEY_get_id(pkey) };
    let alg1 = si.digest_algorithm;
    let obj = alg_obj(alg1);
    if obj.is_null() {
        return -1;
    }
    // SAFETY: a live object.
    let hnid = unsafe { OBJ_obj2nid(obj) };
    if hnid == NID_undef {
        return -1;
    }
    if pknid <= 0 {
        // SAFETY: as above.
        let typename = unsafe { EVP_PKEY_get0_type_name(pkey) };
        if !typename.is_null() {
            // SAFETY: the key's type name.
            pknid = unsafe { OBJ_txt2nid(typename) };
        }
    }
    let mut snid = NID_undef;
    if pknid > 0 && signature_nomd(pkey) {
        snid = pknid;
    // SAFETY: room for the NID.
    } else if unsafe { OBJ_find_sigid_by_algs(&mut snid, hnid, pknid) } == 0 {
        return -1;
    }
    // SAFETY: the signer's signature algorithm; a static object.
    unsafe {
        X509_ALGOR_set0(
            si.signature_algorithm,
            nid_obj(snid),
            V_ASN1_UNDEF,
            ptr::null_mut(),
        )
    }
}

/// `rsa_cms_sign`: rsaEncryption, or the context's PSS parameters.
fn rsa_sign(si: &mut SignerInfo) -> c_int {
    let alg = si.signature_algorithm;
    let pkctx = si.pctx;
    let mut pad_mode = RSA_PKCS1_PADDING;
    // SAFETY: the signer's key context.
    if !pkctx.is_null() && unsafe { EVP_PKEY_CTX_get_rsa_padding(pkctx, &mut pad_mode) } <= 0 {
        return 0;
    }
    if pad_mode == RSA_PKCS1_PADDING {
        // SAFETY: the signer's algorithm; a static object.
        return unsafe {
            X509_ALGOR_set0(
                alg,
                nid_obj(NID_rsaEncryption),
                V_ASN1_NULL,
                ptr::null_mut(),
            )
        };
    }
    if pad_mode != RSA_PKCS1_PSS_PADDING {
        return 0;
    }
    // SAFETY: the key context.
    let legacy =
        unsafe { crate::evp::pkey_ctx::context(pkctx) }.is_some_and(|c| c.lock().keymgmt.is_none());
    if legacy {
        // SAFETY: as above.
        let os = unsafe { ctx_to_pss_string(pkctx) };
        if os.is_null() {
            return 0;
        }
        // SAFETY: the signer's algorithm, which takes the parameters.
        if unsafe { X509_ALGOR_set0(alg, nid_obj(EVP_PKEY_RSA_PSS), V_ASN1_SEQUENCE, os.cast()) }
            != 0
        {
            return 1;
        }
        // SAFETY: the parameters made above.
        unsafe { crate::asn1::string::ASN1_STRING_free(os) };
        return 0;
    }
    // SAFETY: the key context; the signer's algorithm.
    c_int::from(unsafe { algorithm_id(pkctx, ptr::null_mut(), alg) }.is_ok())
}

/// `rsa_cms_verify`: the signature algorithm's padding given to the key context.
fn rsa_verify(si: &mut SignerInfo) -> c_int {
    let pkctx = si.pctx;
    // SAFETY: the signer's key context.
    let pkey = unsafe { EVP_PKEY_CTX_get0_pkey(pkctx) };
    let alg = si.signature_algorithm;
    // SAFETY: the algorithm's object, or NULL.
    let nid = unsafe { OBJ_obj2nid(alg_obj(alg)) };
    if nid == EVP_PKEY_RSA_PSS {
        // SAFETY: the key context; the signer's algorithm.
        return c_int::from(
            unsafe { pss_to_ctx(ptr::null_mut(), pkctx, alg, ptr::null_mut()) } > 0,
        );
    }
    // SAFETY: the context's key; a static name.
    if unsafe { EVP_PKEY_is_a(pkey, c"RSA-PSS".as_ptr()) } != 0 {
        err::raise(
            ERR_LIB_RSA,
            RSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE,
            "rsa_cms_verify",
        );
        return 0;
    }
    if nid == NID_rsaEncryption {
        return 1;
    }
    let mut nid2 = NID_undef;
    // SAFETY: room for the NID.
    c_int::from(
        unsafe { OBJ_find_sigid_algs(nid, ptr::null_mut(), &mut nid2) } != 0
            && nid2 == NID_rsaEncryption,
    )
}

/// `cms_sd_asn1_ctrl`: the signature algorithm set (or checked) for the key's type.
fn sd_asn1_ctrl(si: &mut SignerInfo, verify: bool) -> bool {
    let pkey = si.pkey;
    let is = |name: &core::ffi::CStr| {
        // SAFETY: the signer's key; a static name.
        (unsafe { EVP_PKEY_is_a(pkey, name.as_ptr()) }) != 0
    };
    if is(c"DSA") || is(c"EC") {
        return generic_sign(si, verify) > 0;
    }
    if is(c"RSA") || is(c"RSA-PSS") {
        return if verify {
            rsa_verify(si) > 0
        } else {
            rsa_sign(si) > 0
        };
    }
    let siptr: *mut SignerInfo = si;
    // SAFETY: the signer's key; the signer info, as the method's control takes it.
    match unsafe {
        asn1_ctrl_of(
            pkey,
            ASN1_PKEY_CTRL_CMS_SIGN,
            c_long::from(c_int::from(verify)),
            siptr.cast(),
        )
    } {
        None => generic_sign(si, verify) > 0,
        Some(-2) => {
            raise(CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE, "cms_sd_asn1_ctrl");
            false
        }
        Some(i) if i <= 0 => {
            raise(CMS_R_CTRL_FAILURE, "cms_sd_asn1_ctrl");
            false
        }
        Some(_) => true,
    }
}

/// Adds an encoded ESS signing-certificate attribute.
///
/// # Safety
/// `si` is a live signer info; `der` the attribute's DER.
unsafe fn add1_signing_cert_der(si: *mut CMS_SignerInfo, nid: c_int, der: &[u8]) -> bool {
    // SAFETY: no preconditions.
    let seq = unsafe { crate::asn1::string::ASN1_STRING_new() };
    let n = c_int::try_from(der.len()).ok();
    if seq.is_null()
        || n.is_none_or(|n| {
            // SAFETY: the new string; the encoding's octets.
            (unsafe { crate::asn1::string::ASN1_STRING_set(seq, der.as_ptr().cast(), n) }) == 0
        })
    {
        // SAFETY: the new string, or NULL.
        unsafe { crate::asn1::string::ASN1_STRING_free(seq) };
        return false;
    }
    // SAFETY: the caller's signer info; the string, as a SEQUENCE value.
    let r = unsafe { CMS_signed_add1_attr_by_NID(si, nid, V_ASN1_SEQUENCE, seq.cast(), -1) };
    // SAFETY: the string made here; the attribute holds a copy.
    unsafe { crate::asn1::string::ASN1_STRING_free(seq) };
    r != 0
}

/// `ossl_cms_add1_signing_cert(_v2)`: the signer's ESS signing-certificate attribute (v1 for
/// SHA-1 or no digest, v2 otherwise).
///
/// # Safety
/// `si` is a live signer info; `signer` a live certificate; `md` NULL or live.
unsafe fn add1_signing_cert(si: *mut CMS_SignerInfo, signer: *mut X509, md: *const EVP_MD) -> bool {
    use crate::ess::{
        ESS_SIGNING_CERT_V2_free, ESS_SIGNING_CERT_free, OSSL_ESS_signing_cert_new_init,
        OSSL_ESS_signing_cert_v2_new_init, i2d_ESS_SIGNING_CERT, i2d_ESS_SIGNING_CERT_V2,
    };
    let mut der: *mut c_uchar = ptr::null_mut();
    // SAFETY: NULL or a live digest; a static name.
    let v1 = md.is_null() || unsafe { EVP_MD_is_a(md, SN_sha1.as_ptr()) } != 0;
    let (n, nid) = if v1 {
        // SAFETY: the caller's certificate.
        let sc = unsafe { OSSL_ESS_signing_cert_new_init(signer, ptr::null(), 1) };
        if sc.is_null() {
            return false;
        }
        // SAFETY: the value made; room for the encoding's pointer.
        let n = unsafe { i2d_ESS_SIGNING_CERT(sc, &mut der) };
        // SAFETY: the value made here.
        unsafe { ESS_SIGNING_CERT_free(sc) };
        (n, NID_id_smime_aa_signingCertificate)
    } else {
        // SAFETY: the caller's digest and certificate.
        let sc = unsafe { OSSL_ESS_signing_cert_v2_new_init(md, signer, ptr::null(), 1) };
        if sc.is_null() {
            return false;
        }
        // SAFETY: as above.
        let n = unsafe { i2d_ESS_SIGNING_CERT_V2(sc, &mut der) };
        // SAFETY: as above.
        unsafe { ESS_SIGNING_CERT_V2_free(sc) };
        (n, NID_id_smime_aa_signingCertificateV2)
    };
    let ok = match usize::try_from(n) {
        Ok(l) if l > 0 && !der.is_null() => {
            // SAFETY: the encoding's `l` octets.
            let enc = unsafe { core::slice::from_raw_parts(der, l) };
            // SAFETY: the caller's signer info.
            unsafe { add1_signing_cert_der(si, nid, enc) }
        }
        _ => false,
    };
    // SAFETY: the encoding, from CRYPTO_malloc, or NULL.
    unsafe { mem::release(der.cast()) };
    ok
}

/// The `n`th signer info's slot in a SignedData being built, pushing `si`: whether it worked.
fn push_signer(sd: &mut SignedData, si: *mut SignerInfo) -> bool {
    if sd.signer_infos.is_null() {
        // SAFETY: no preconditions.
        sd.signer_infos = unsafe { OPENSSL_sk_new_null() }.cast();
    }
    // SAFETY: the content's list, or NULL; the signer info.
    !sd.signer_infos.is_null() && unsafe { OPENSSL_sk_push(sd.signer_infos.cast(), si.cast()) } != 0
}

ffi_export! {
    /// Adds a signer for `signer` and `pk` with digest `md` (the key's default for NULL):
    /// signed attributes (S/MIME capabilities, signing time, CAdES's signing certificate)
    /// unless `CMS_NOATTR`, and the certificate unless `CMS_NOCERTS`. The signer info, or NULL.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; `signer` and `pk` live; `md` NULL or live.
    pub unsafe extern "C" fn CMS_add1_signer(cms: *mut CMS_ContentInfo, signer: *mut X509, pk: *mut EVP_PKEY, md: *const EVP_MD, flags: c_uint) -> *mut CMS_SignerInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        const F: &str = "CMS_add1_signer";
        let ctx = ctx_of(cms);
        let (libctx, propq) = ctx_parts(ctx);
        let has = |f: c_int| flags & f.cast_unsigned() != 0;
        // SAFETY: the caller's certificate and key.
        if unsafe { X509_check_private_key(signer, pk) } == 0 {
            raise(CMS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE, F);
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let it = unsafe { super::signer_info_it() };
        let mut si: *mut SignerInfo = ptr::null_mut();
        let ok = 'err: {
            // SAFETY: the caller's guarantee.
            let Some(sd) = (unsafe { signed_data_init(cms) }) else { break 'err false };
            // SAFETY: the item.
            si = unsafe { ASN1_item_new(it) }.cast();
            // SAFETY: the new signer info, or NULL.
            let Some(s) = (unsafe { si.as_mut() }) else {
                raise(ERR_R_ASN1_LIB, F);
                break 'err false;
            };
            // SAFETY: the caller's certificate.
            unsafe { X509_check_purpose(signer, -1, -1) };
            // SAFETY: as above.
            if unsafe { X509_up_ref(signer) } == 0 {
                break 'err false;
            }
            // SAFETY: the caller's key.
            if unsafe { EVP_PKEY_up_ref(pk) } == 0 {
                // SAFETY: the reference taken above.
                unsafe { X509_free(signer) };
                break 'err false;
            }
            s.cms_ctx = ctx;
            s.pkey = pk;
            s.signer = signer;
            // SAFETY: no preconditions.
            s.mctx = unsafe { EVP_MD_CTX_new() };
            s.pctx = ptr::null_mut();
            s.omit_signing_time = 0;
            if s.mctx.is_null() {
                raise(ERR_R_EVP_LIB, F);
                break 'err false;
            }
            let id_type = if has(CMS_USE_KEYID) {
                s.version = 3;
                sd.version = sd.version.max(3);
                CMS_SIGNERINFO_KEYIDENTIFIER
            } else {
                s.version = 1;
                CMS_SIGNERINFO_ISSUER_SERIAL
            };
            // SAFETY: the signer info's identifier, made with it.
            let Some(sid) = (unsafe { s.sid.as_mut() }) else { break 'err false };
            // SAFETY: as above; the caller's certificate.
            if !unsafe { set1_signer_identifier(sid, signer, id_type) } {
                break 'err false;
            }
            let mut md = md;
            if md.is_null() {
                let mut def_nid = NID_undef;
                // SAFETY: the caller's key; room for the NID.
                if unsafe { EVP_PKEY_get_default_digest_nid(pk, &mut def_nid) } <= 0 {
                    // SAFETY: as above.
                    let id = unsafe { EVP_PKEY_get_id(pk) };
                    err::raise_with_text(ERR_LIB_CMS, CMS_R_NO_DEFAULT_DIGEST, F, &format!("pkey nid={id}"));
                    break 'err false;
                }
                md = digest_by_nid(def_nid);
                if md.is_null() {
                    err::raise_with_text(ERR_LIB_CMS, CMS_R_NO_DEFAULT_DIGEST, F, &format!("default md nid={def_nid}"));
                    break 'err false;
                }
            }
            // SAFETY: the signer's algorithm; a live digest.
            unsafe { X509_ALGOR_set_md(s.digest_algorithm, md) };
            // SAFETY: the content's digest algorithms.
            let n = unsafe { OPENSSL_sk_num(sd.digest_algorithms.cast()) };
            let found = (0..n).any(|i| {
                // SAFETY: an index within them.
                let a = unsafe { crate::stack::OPENSSL_sk_value(sd.digest_algorithms.cast(), i) }.cast::<X509_ALGOR>();
                let name = name_of(alg_obj(a));
                // SAFETY: a live digest; a NUL-terminated name.
                (unsafe { EVP_MD_is_a(md, name.as_ptr()) }) != 0
            });
            if !found {
                // SAFETY: no preconditions.
                let alg = unsafe { X509_ALGOR_new() };
                if alg.is_null() {
                    raise(ERR_R_ASN1_LIB, F);
                    break 'err false;
                }
                // SAFETY: the new identifier; a live digest.
                unsafe { X509_ALGOR_set_md(alg, md) };
                // SAFETY: the content's list; the identifier.
                if unsafe { OPENSSL_sk_push(sd.digest_algorithms.cast(), alg.cast()) } == 0 {
                    // SAFETY: the identifier made here.
                    unsafe { X509_ALGOR_free(alg) };
                    raise(ERR_R_CRYPTO_LIB, F);
                    break 'err false;
                }
            }
            if !has(CMS_KEY_PARAM) && !sd_asn1_ctrl(s, false) {
                // SAFETY: the caller's key.
                let id = unsafe { EVP_PKEY_get_id(pk) };
                err::raise_with_text(ERR_LIB_CMS, CMS_R_UNSUPPORTED_SIGNATURE_ALGORITHM, F, &format!("pkey nid={id}"));
                break 'err false;
            }
            let si_c = si.cast::<CMS_SignerInfo>();
            if !has(CMS_NOATTR) {
                if s.signed_attrs.is_null() {
                    // SAFETY: no preconditions.
                    s.signed_attrs = unsafe { OPENSSL_sk_new_null() }.cast();
                    if s.signed_attrs.is_null() {
                        raise(ERR_R_CRYPTO_LIB, F);
                        break 'err false;
                    }
                }
                if !has(CMS_NOSMIMECAP) {
                    let mut smcap: *mut stack_st_X509_ALGOR = ptr::null_mut();
                    // SAFETY: the list's slot.
                    let mut i = unsafe { CMS_add_standard_smimecap(&mut smcap) };
                    if i != 0 {
                        // SAFETY: the signer info; the list.
                        i = unsafe { CMS_add_smimecap(si_c, smcap) };
                    }
                    // SAFETY: the list made here.
                    unsafe { OPENSSL_sk_pop_free(smcap.cast(), Some(algor_free)) };
                    if i == 0 {
                        raise(ERR_R_CMS_LIB, F);
                        break 'err false;
                    }
                }
                if has(CMS_NO_SIGNING_TIME) {
                    s.omit_signing_time = 1;
                }
                // SAFETY: the signer info; the caller's certificate; the digest.
                if has(CMS_CADES) && !unsafe { add1_signing_cert(si_c, signer, md) } {
                    break 'err false;
                }
                if has(CMS_REUSE_DIGEST) {
                    if !copy_message_digest(cms, si_c) || !set_si_content_type_attr(cms, si_c) {
                        break 'err false;
                    }
                    // SAFETY: the signer info.
                    if flags & (CMS_PARTIAL | CMS_KEY_PARAM).cast_unsigned() == 0 && unsafe { CMS_SignerInfo_sign(si_c) } == 0 {
                        break 'err false;
                    }
                }
            }
            // SAFETY: the object; the caller's certificate.
            if !has(CMS_NOCERTS) && unsafe { CMS_add1_cert(cms, signer) } == 0 {
                raise(ERR_R_CMS_LIB, F);
                break 'err false;
            }
            if has(CMS_KEY_PARAM) {
                if has(CMS_NOATTR) {
                    // SAFETY: the object's context; the signer's key.
                    s.pctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, s.pkey, propq) };
                    if s.pctx.is_null() {
                        break 'err false;
                    }
                    // SAFETY: the new key context.
                    if unsafe { EVP_PKEY_sign_init(s.pctx) } <= 0 {
                        break 'err false;
                    }
                    // SAFETY: as above; a live digest.
                    if unsafe { EVP_PKEY_CTX_set_signature_md(s.pctx, md) } <= 0 {
                        break 'err false;
                    }
                } else {
                    // SAFETY: a live digest.
                    let mdname = unsafe { EVP_MD_get0_name(md) };
                    // SAFETY: the signer's context; its key-context slot; the caller's key.
                    if unsafe { EVP_DigestSignInit_ex(s.mctx, &mut s.pctx, mdname, libctx, propq, pk, ptr::null()) } <= 0 {
                        s.pctx = ptr::null_mut();
                        break 'err false;
                    }
                    // SAFETY: as above.
                    unsafe { EVP_MD_CTX_set_flags(s.mctx, KEEP_PKEY_CTX) };
                }
            }
            if !push_signer(sd, si) {
                raise(ERR_R_CRYPTO_LIB, F);
                break 'err false;
            }
            true
        };
        if ok {
            return si.cast();
        }
        // SAFETY: the signer info made here, or NULL.
        unsafe { ASN1_item_free(si.cast(), it) };
        ptr::null_mut()
    }
}

unsafe extern "C" fn algor_free(p: *mut c_void) {
    // SAFETY: an algorithm identifier of the list.
    unsafe { X509_ALGOR_free(p.cast()) };
}

/// `cms_add1_signingTime`: the signing time (now for NULL) as a signed attribute.
///
/// # Safety
/// `si` is a live signer info; `t` NULL or a live time.
unsafe fn add1_signing_time(si: *mut CMS_SignerInfo, t: *mut rustyssl_abi::ASN1_TIME) -> bool {
    const F: &str = "cms_add1_signingTime";
    let tt = if t.is_null() {
        // SAFETY: no preconditions.
        unsafe { X509_gmtime_adj(ptr::null_mut(), 0) }
    } else {
        t
    };
    // SAFETY: NULL or a live time.
    let Some(time) = (unsafe { tt.as_ref() }) else {
        raise(ERR_R_X509_LIB, F);
        return false;
    };
    // SAFETY: the caller's signer info; the time, as a value of its type.
    let ok = unsafe {
        CMS_signed_add1_attr_by_NID(si, NID_pkcs9_signingTime, time.type_, tt.cast(), -1)
    } > 0;
    if !ok {
        raise(ERR_R_CMS_LIB, F);
    }
    if t.is_null() {
        // SAFETY: the time made here.
        unsafe { ASN1_TIME_free(tt) };
    }
    ok
}

ffi_export! {
    /// The signer's key context, or NULL.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info.
    pub unsafe extern "C" fn CMS_SignerInfo_get0_pkey_ctx(si: *mut CMS_SignerInfo) -> *mut EVP_PKEY_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        unsafe { si_of(si) }.map_or(ptr::null_mut(), |s| s.pctx)
    }
}

ffi_export! {
    /// The signer's digest context, or NULL.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info.
    pub unsafe extern "C" fn CMS_SignerInfo_get0_md_ctx(si: *mut CMS_SignerInfo) -> *mut EVP_MD_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        unsafe { si_of(si) }.map_or(ptr::null_mut(), |s| s.mctx)
    }
}

ffi_export! {
    /// The signer's signature, or NULL.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info.
    pub unsafe extern "C" fn CMS_SignerInfo_get0_signature(si: *mut CMS_SignerInfo) -> *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        unsafe { si_of(si) }.map_or(ptr::null_mut(), |s| s.signature)
    }
}

ffi_export! {
    /// The signers' certificates known so far, in a new list of borrowed certificates (NULL
    /// for none).
    ///
    /// # Safety
    /// `cms` is NULL or a live object.
    pub unsafe extern "C" fn CMS_get0_signers(cms: *mut CMS_ContentInfo) -> *mut stack_st_X509
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let sinfos = unsafe { super::base::CMS_get0_SignerInfos(cms) }.cast::<Stack>();
        let mut signers: *mut stack_st_X509 = ptr::null_mut();
        // SAFETY: the object's signer infos, or NULL.
        for i in 0..unsafe { OPENSSL_sk_num(sinfos.cast()) } {
            // SAFETY: an index within them.
            let Some(si) = (unsafe { sk_get::<SignerInfo>(sinfos, i) }) else { continue };
            if si.signer.is_null() {
                continue;
            }
            if signers.is_null() {
                // SAFETY: no preconditions.
                signers = unsafe { OPENSSL_sk_new_null() }.cast();
                if signers.is_null() {
                    return ptr::null_mut();
                }
            }
            // SAFETY: the list; the signer's certificate, borrowed.
            if unsafe { X509_add_cert(signers, si.signer, X509_ADD_FLAG_DEFAULT) } == 0 {
                // SAFETY: the list made here.
                unsafe { OPENSSL_sk_free(signers.cast()) };
                return ptr::null_mut();
            }
        }
        signers
    }
}

ffi_export! {
    /// Sets the signer's certificate (and its key from it), NULL to drop it.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; `signer` NULL or live.
    pub unsafe extern "C" fn CMS_SignerInfo_set1_signer_cert(si: *mut CMS_SignerInfo, signer: *mut X509)
    where failure = (), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { si_of(si) }) else { return };
        if !signer.is_null() {
            // SAFETY: the caller's certificate.
            if unsafe { X509_up_ref(signer) } == 0 {
                return;
            }
            // SAFETY: the signer's own key, or NULL.
            unsafe { EVP_PKEY_free(s.pkey) };
            // SAFETY: the caller's certificate.
            s.pkey = unsafe { X509_get_pubkey(signer) };
        }
        // SAFETY: the signer's own certificate, or NULL.
        unsafe { X509_free(s.signer) };
        s.signer = signer;
    }
}

ffi_export! {
    /// The signer's identifier: its key identifier, or issuer and serial number. 1, or 0.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; the others NULL or room for a pointer.
    pub unsafe extern "C" fn CMS_SignerInfo_get0_signer_id(si: *mut CMS_SignerInfo, keyid: *mut *mut ASN1_OCTET_STRING, issuer: *mut *mut X509_NAME, sno: *mut *mut ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee; its identifier, live with it.
        let Some(sid) = (unsafe { si_of(si) }).and_then(|s| unsafe { s.sid.as_ref() }) else { return 0 };
        // SAFETY: as above.
        unsafe { signer_identifier_get0(sid, keyid, issuer, sno) }
    }
}

ffi_export! {
    /// 0 if the certificate is the signer's.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; `cert` a live certificate.
    pub unsafe extern "C" fn CMS_SignerInfo_cert_cmp(si: *mut CMS_SignerInfo, cert: *mut X509) -> c_int
    where failure = -1, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee; its identifier, live with it.
        let Some(sid) = (unsafe { si_of(si) }).and_then(|s| unsafe { s.sid.as_ref() }) else { return -1 };
        // SAFETY: as above.
        unsafe { signer_identifier_cert_cmp(sid, cert) }
    }
}

ffi_export! {
    /// Finds each signer's certificate in `scerts` and (unless `CMS_NOINTERN`) the object's
    /// own: the number found, or -1 for an object that isn't SignedData.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; `scerts` NULL or a live list.
    pub unsafe extern "C" fn CMS_set1_signers_certs(cms: *mut CMS_ContentInfo, scerts: *mut stack_st_X509, flags: c_uint) -> c_int
    where failure = -1, library = ERR_LIB_CMS
    {
        let Some(sd) = get0_signed(cms) else { return -1 };
        let certs = sd.certificates;
        let mut ret = 0;
        // SAFETY: the content's signer infos, or NULL.
        for i in 0..unsafe { OPENSSL_sk_num(sd.signer_infos.cast()) } {
            // SAFETY: an index within them.
            let Some(si) = (unsafe { sk_get::<SignerInfo>(sd.signer_infos, i) }) else { continue };
            if !si.signer.is_null() {
                continue;
            }
            let si_c: *mut CMS_SignerInfo = core::ptr::from_mut(si).cast();
            // SAFETY: the caller's certificates, or NULL.
            for j in 0..unsafe { OPENSSL_sk_num(scerts.cast()) } {
                // SAFETY: an index within them.
                let x = unsafe { crate::stack::OPENSSL_sk_value(scerts.cast(), j) }.cast::<X509>();
                // SAFETY: the signer info; a certificate.
                if unsafe { CMS_SignerInfo_cert_cmp(si_c, x) } == 0 {
                    // SAFETY: as above.
                    unsafe { CMS_SignerInfo_set1_signer_cert(si_c, x) };
                    ret += 1;
                    break;
                }
            }
            // SAFETY: the signer info.
            let found = unsafe { si_of(si_c) }.is_some_and(|s| !s.signer.is_null());
            if found || flags & CMS_NOINTERN.cast_unsigned() != 0 {
                continue;
            }
            // SAFETY: the content's certificates, or NULL.
            for j in 0..unsafe { OPENSSL_sk_num(certs.cast()) } {
                // SAFETY: an index within them.
                let Some(cch) = (unsafe { sk_get::<CertificateChoices>(certs, j) }) else { continue };
                if cch.type_ != CERTCHOICE_CERT {
                    continue;
                }
                let x = cch.d.cast::<X509>();
                // SAFETY: as above.
                if unsafe { CMS_SignerInfo_cert_cmp(si_c, x) } == 0 {
                    // SAFETY: as above.
                    unsafe { CMS_SignerInfo_set1_signer_cert(si_c, x) };
                    ret += 1;
                    break;
                }
            }
        }
        ret
    }
}

ffi_export! {
    /// The signer's key, certificate, digest algorithm, and signature algorithm.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; the others NULL or room for a pointer.
    pub unsafe extern "C" fn CMS_SignerInfo_get0_algs(si: *mut CMS_SignerInfo, pk: *mut *mut EVP_PKEY, signer: *mut *mut X509, pdig: *mut *mut X509_ALGOR, psig: *mut *mut X509_ALGOR)
    where failure = (), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { si_of(si) }) else { return };
        // SAFETY: the caller's room, or NULL.
        if let Some(p) = unsafe { pk.as_mut() } {
            *p = s.pkey;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { signer.as_mut() } {
            *p = s.signer;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { pdig.as_mut() } {
            *p = s.digest_algorithm;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { psig.as_mut() } {
            *p = s.signature_algorithm;
        }
    }
}

/// `cms_SignerInfo_content_sign`: the signer's signature, over its signed attributes (with
/// the content's digest added) or the digest itself.
///
/// # Safety
/// `cms` is a live SignedData object; `si` one of its signer infos; `chain` its chain.
unsafe fn content_sign(
    cms: *mut CMS_ContentInfo,
    si: &mut SignerInfo,
    chain: *mut BIO,
    precomp: &[u8],
) -> bool {
    const F: &str = "cms_SignerInfo_content_sign";
    let (libctx, propq) = ctx_parts(ctx_of(cms));
    // SAFETY: no preconditions.
    let mctx = unsafe { EVP_MD_CTX_new() };
    if mctx.is_null() {
        raise(ERR_R_CMS_LIB, F);
        return false;
    }
    let mut pctx: *mut EVP_PKEY_CTX = ptr::null_mut();
    let si_c: *mut CMS_SignerInfo = core::ptr::from_mut(si).cast();
    let ok = 'err: {
        if si.pkey.is_null() {
            raise(CMS_R_NO_PRIVATE_KEY, F);
            break 'err false;
        }
        // SAFETY: the context; the chain; the signer's algorithm.
        if unsafe { digest_algorithm_find_ctx(mctx, chain, si.digest_algorithm) } == 0 {
            break 'err false;
        }
        if !si.pctx.is_null() && !sd_asn1_ctrl(si, false) {
            break 'err false;
        }
        let mut computed = [0u8; EVP_MAX_MD_SIZE as usize];
        let mut computed_len: c_uint = 0;
        let mut finish = |mctx| -> Option<Vec<u8>> {
            if !precomp.is_empty() {
                return Some(precomp.to_vec());
            }
            // SAFETY: the context; room for any digest.
            if unsafe { EVP_DigestFinal_ex(mctx, computed.as_mut_ptr(), &mut computed_len) } == 0 {
                return None;
            }
            computed
                .get(..usize::try_from(computed_len).unwrap_or(0))
                .map(<[u8]>::to_vec)
        };
        // SAFETY: the signer info.
        if unsafe { CMS_signed_get_attr_count(si_c) } >= 0 {
            let Some(md) = finish(mctx) else {
                break 'err false;
            };
            let n = c_int::try_from(md.len()).unwrap_or(0);
            // SAFETY: as above; the digest's octets.
            if unsafe {
                CMS_signed_add1_attr_by_NID(
                    si_c,
                    NID_pkcs9_messageDigest,
                    V_ASN1_OCTET_STRING,
                    md.as_ptr().cast(),
                    n,
                )
            } == 0
            {
                break 'err false;
            }
            if !set_si_content_type_attr(cms, si_c) {
                break 'err false;
            }
            // SAFETY: as above.
            if unsafe { CMS_SignerInfo_sign(si_c) } == 0 {
                break 'err false;
            }
        } else if !si.pctx.is_null() {
            pctx = si.pctx;
            si.pctx = ptr::null_mut();
            let Some(md) = finish(mctx) else {
                break 'err false;
            };
            // SAFETY: the signer's key.
            let Some(size) = usize::try_from(unsafe { EVP_PKEY_get_size(si.pkey) })
                .ok()
                .filter(|&n| n > 0)
            else {
                break 'err false;
            };
            let sig = mem::alloc(size).cast::<u8>();
            if sig.is_null() {
                break 'err false;
            }
            let mut siglen = size;
            // SAFETY: the key context; room for the signature; the digest.
            if unsafe { EVP_PKEY_sign(pctx, sig, &mut siglen, md.as_ptr(), md.len()) } <= 0 {
                // SAFETY: the buffer allocated here.
                unsafe { mem::release(sig.cast()) };
                break 'err false;
            }
            // SAFETY: the signer's string takes the buffer, from CRYPTO_malloc.
            unsafe {
                ASN1_STRING_set0(
                    si.signature.cast(),
                    sig.cast(),
                    c_int::try_from(siglen).unwrap_or(0),
                )
            };
        } else {
            if !precomp.is_empty() {
                raise(CMS_R_OPERATION_UNSUPPORTED, F);
                break 'err false;
            }
            // SAFETY: the signer's key.
            let Some(size) = usize::try_from(unsafe { EVP_PKEY_get_size(si.pkey) })
                .ok()
                .filter(|&n| n > 0)
            else {
                break 'err false;
            };
            let sig = mem::alloc(size).cast::<u8>();
            if sig.is_null() {
                break 'err false;
            }
            let mut siglen = c_uint::try_from(size).unwrap_or(0);
            // SAFETY: the digest; room for the signature; the signer's key.
            if unsafe { EVP_SignFinal_ex(mctx, sig, &mut siglen, si.pkey, libctx, propq) } == 0 {
                raise(CMS_R_SIGNFINAL_ERROR, F);
                // SAFETY: the buffer allocated here.
                unsafe { mem::release(sig.cast()) };
                break 'err false;
            }
            // SAFETY: the signer's string takes the buffer.
            unsafe {
                ASN1_STRING_set0(
                    si.signature.cast(),
                    sig.cast(),
                    c_int::try_from(siglen).unwrap_or(0),
                )
            };
        }
        true
    };
    // SAFETY: the contexts made or taken here, or NULL.
    unsafe { EVP_MD_CTX_free(mctx) };
    // SAFETY: as above.
    unsafe { EVP_PKEY_CTX_free(pctx) };
    ok
}

/// `ossl_cms_SignedData_final`: every signer's signature, and the content complete.
///
/// # Safety
/// `cms` is a live SignedData object; `chain` its chain.
pub(crate) unsafe fn signed_data_final(
    cms: *mut CMS_ContentInfo,
    chain: *mut BIO,
    precomp: &[u8],
) -> c_int {
    let sinfos = super::base::signer_infos(cms);
    // SAFETY: the object's signer infos, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(sinfos.cast()) } {
        // SAFETY: an index within them.
        let Some(si) = (unsafe { sk_get::<SignerInfo>(sinfos, i) }) else {
            continue;
        };
        // SAFETY: the object, its signer, and its chain.
        if !unsafe { content_sign(cms, si, chain, precomp) } {
            return 0;
        }
    }
    // SAFETY: the content's encapsulated content, live with it.
    if let Some(e) = get0_signed(cms).and_then(|s| unsafe { s.encap.as_mut() }) {
        e.partial = 0;
    }
    1
}

ffi_export! {
    /// Signs the signer's signed attributes (adding the signing time unless omitted, checking
    /// them against RFC 5652): 1, or 0.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info with a key.
    pub unsafe extern "C" fn CMS_SignerInfo_sign(si: *mut CMS_SignerInfo) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { si_of(si) }) else { return 0 };
        let mctx = s.mctx;
        let (libctx, propq) = ctx_parts(s.cms_ctx);
        let name = name_of(alg_obj(s.digest_algorithm));
        if name[0] == 0 {
            return 0;
        }
        let md_name = if signature_nomd(s.pkey) { ptr::null() } else { name.as_ptr() };
        let mut abuf: *mut c_uchar = ptr::null_mut();
        let ok = 'err: {
            // SAFETY: the signer info.
            if s.omit_signing_time == 0 && unsafe { CMS_signed_get_attr_by_NID(si, NID_pkcs9_signingTime, -1) } < 0 {
                // SAFETY: as above.
                if !unsafe { add1_signing_time(si, ptr::null_mut()) } {
                    break 'err false;
                }
            }
            if !si_check_attributes(si) {
                break 'err false;
            }
            if s.pctx.is_null() {
                // SAFETY: the signer's context.
                unsafe { EVP_MD_CTX_reset(mctx) };
                let mut pctx: *mut EVP_PKEY_CTX = ptr::null_mut();
                // SAFETY: as above; the digest's name, or NULL; the signer's key.
                if unsafe { EVP_DigestSignInit_ex(mctx, &mut pctx, md_name, libctx, propq, s.pkey, ptr::null()) } <= 0 {
                    break 'err false;
                }
                // SAFETY: as above.
                unsafe { EVP_MD_CTX_set_flags(mctx, KEEP_PKEY_CTX) };
                s.pctx = pctx;
            }
            // SAFETY: no preconditions.
            let it = unsafe { super::attributes_sign_it() };
            if md_name.is_null() {
                // SAFETY: the item; the signer's signature and attributes; its context.
                break 'err unsafe { ASN1_item_sign_ctx(it, ptr::null_mut(), ptr::null_mut(), s.signature.cast(), s.signed_attrs.cast(), mctx) } > 0;
            }
            // SAFETY: the signer's attributes; room for the encoding's pointer.
            let alen = unsafe { ASN1_item_i2d(s.signed_attrs.cast(), &mut abuf, it) };
            let Some(alen) = usize::try_from(alen).ok().filter(|_| !abuf.is_null()) else { break 'err false };
            // SAFETY: the context; the encoding's octets.
            if unsafe { EVP_DigestSignUpdate(mctx, abuf.cast(), alen) } <= 0 {
                break 'err false;
            }
            let mut siglen = 0usize;
            // SAFETY: the context; room for the length.
            if unsafe { EVP_DigestSignFinal(mctx, ptr::null_mut(), &mut siglen) } <= 0 {
                break 'err false;
            }
            // SAFETY: the encoding, from CRYPTO_malloc.
            unsafe { mem::release(abuf.cast()) };
            abuf = mem::alloc(siglen).cast();
            if abuf.is_null() {
                break 'err false;
            }
            // SAFETY: as above; `siglen` octets of room.
            if unsafe { EVP_DigestSignFinal(mctx, abuf, &mut siglen) } <= 0 {
                break 'err false;
            }
            // SAFETY: the context.
            unsafe { EVP_MD_CTX_reset(mctx) };
            // SAFETY: the signer's string takes the buffer, from CRYPTO_malloc.
            unsafe { ASN1_STRING_set0(s.signature.cast(), abuf.cast(), c_int::try_from(siglen).unwrap_or(0)) };
            return 1;
        };
        if ok {
            return 1;
        }
        // SAFETY: NULL or a buffer from CRYPTO_malloc not handed on.
        unsafe { mem::release(abuf.cast()) };
        // SAFETY: the signer's context.
        unsafe { EVP_MD_CTX_reset(mctx) };
        0
    }
}

ffi_export! {
    /// Checks the signature over the signer's signed attributes: 1, 0, or -1.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info.
    pub unsafe extern "C" fn CMS_SignerInfo_verify(si: *mut CMS_SignerInfo) -> c_int
    where failure = -1, library = ERR_LIB_CMS
    {
        const F: &str = "CMS_SignerInfo_verify";
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { si_of(si) }) else { return -1 };
        let (libctx, propq) = ctx_parts(s.cms_ctx);
        if s.pkey.is_null() {
            raise(CMS_R_NO_PUBLIC_KEY, F);
            return -1;
        }
        if !si_check_attributes(si) {
            return -1;
        }
        // SAFETY: no preconditions.
        let sign_it = unsafe { super::attributes_sign_it() };
        if signature_nomd(s.pkey) {
            // SAFETY: the item; the signer's algorithm, signature, attributes, and key.
            let r = unsafe { ASN1_item_verify_ex(sign_it, s.signature_algorithm, s.signature.cast(), s.signed_attrs.cast(), ptr::null(), s.pkey, libctx, propq) };
            if r <= 0 {
                raise(CMS_R_VERIFICATION_FAILURE, F);
            }
            return r;
        }
        let obj = alg_obj(s.digest_algorithm);
        let name = name_of(obj);
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        // SAFETY: a NUL-terminated name; the signer's context and properties.
        let fetched = unsafe { EVP_MD_fetch(libctx, name.as_ptr(), propq) };
        let md = if fetched.is_null() {
            // SAFETY: the object, or NULL.
            digest_by_nid(unsafe { OBJ_obj2nid(obj) })
        } else {
            fetched.cast_const()
        };
        if md.is_null() {
            // SAFETY: no preconditions.
            unsafe { ERR_clear_last_mark() };
            raise(CMS_R_UNKNOWN_DIGEST_ALGORITHM, F);
            return -1;
        }
        // SAFETY: no preconditions.
        unsafe { ERR_pop_to_mark() };
        let mut r = -1;
        'err: {
            if s.mctx.is_null() {
                // SAFETY: no preconditions.
                s.mctx = unsafe { EVP_MD_CTX_new() };
                if s.mctx.is_null() {
                    raise(ERR_R_EVP_LIB, F);
                    break 'err;
                }
            }
            let mctx = s.mctx;
            // SAFETY: the signer's own key context, or NULL.
            unsafe { EVP_PKEY_CTX_free(s.pctx) };
            s.pctx = ptr::null_mut();
            // SAFETY: a live digest.
            let mdname = unsafe { EVP_MD_get0_name(md) };
            // SAFETY: the signer's context and key-context slot; the digest's name; its key.
            if unsafe { EVP_DigestVerifyInit_ex(mctx, &mut s.pctx, mdname, libctx, propq, s.pkey, ptr::null()) } <= 0 {
                s.pctx = ptr::null_mut();
                break 'err;
            }
            // SAFETY: as above.
            unsafe { EVP_MD_CTX_set_flags(mctx, KEEP_PKEY_CTX) };
            if !sd_asn1_ctrl(s, true) {
                break 'err;
            }
            // SAFETY: no preconditions.
            let it = unsafe { super::attributes_verify_it() };
            let mut abuf: *mut c_uchar = ptr::null_mut();
            // SAFETY: the signer's attributes; room for the encoding's pointer.
            let alen = unsafe { ASN1_item_i2d(s.signed_attrs.cast(), &mut abuf, it) };
            let Some(alen) = usize::try_from(alen).ok().filter(|_| !abuf.is_null()) else { break 'err };
            // SAFETY: the context; the encoding's octets.
            let u = unsafe { EVP_DigestVerifyUpdate(mctx, abuf.cast(), alen) };
            // SAFETY: the encoding, from CRYPTO_malloc.
            unsafe { mem::release(abuf.cast()) };
            if u <= 0 {
                break 'err;
            }
            // SAFETY: the signer's signature, live.
            let sig = unsafe { octets(s.signature) };
            // SAFETY: the context; the signature's octets.
            r = unsafe { EVP_DigestVerifyFinal(mctx, sig.as_ptr(), sig.len()) };
            if r <= 0 {
                raise(CMS_R_VERIFICATION_FAILURE, F);
            }
        }
        // SAFETY: the fetched digest, or NULL.
        unsafe { EVP_MD_free(fetched) };
        // SAFETY: the signer's context, or NULL.
        unsafe { EVP_MD_CTX_reset(s.mctx) };
        r
    }
}

/// `ossl_cms_SignedData_init_bio`: a digest BIO per digest algorithm (the versions settled
/// first for a content being made).
///
/// # Safety
/// `cms` is a live object.
pub(crate) unsafe fn signed_data_init_bio(cms: *mut CMS_ContentInfo) -> *mut BIO {
    let Some(sd) = get0_signed(cms) else {
        return ptr::null_mut();
    };
    // SAFETY: the content's encapsulated content, live with it.
    if unsafe { sd.encap.as_ref() }.is_some_and(|e| e.partial != 0) {
        sd_set_version(sd);
    }
    let mut chain: *mut BIO = ptr::null_mut();
    // SAFETY: the content's digest algorithms.
    for i in 0..unsafe { OPENSSL_sk_num(sd.digest_algorithms.cast()) } {
        // SAFETY: an index within them.
        let alg = unsafe { crate::stack::OPENSSL_sk_value(sd.digest_algorithms.cast(), i) }
            .cast::<X509_ALGOR>();
        // SAFETY: a live algorithm; the object's context.
        let mdbio = unsafe { digest_algorithm_init_bio(alg, ctx_of(cms)) };
        if mdbio.is_null() {
            // SAFETY: the chain built here, or NULL.
            unsafe { BIO_free_all(chain) };
            return ptr::null_mut();
        }
        if chain.is_null() {
            chain = mdbio;
        } else {
            // SAFETY: live BIOs; the chain takes the new one.
            unsafe { BIO_push(chain, mdbio) };
        }
    }
    chain
}

ffi_export! {
    /// Checks the content's digest in the chain against the signer's message-digest
    /// attribute (in constant time), or its signature over the digest when it has no signed
    /// attributes: 1, 0, or -1.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; `chain` the object's chain.
    pub unsafe extern "C" fn CMS_SignerInfo_verify_content(si: *mut CMS_SignerInfo, chain: *mut BIO) -> c_int
    where failure = -1, library = ERR_LIB_CMS
    {
        const F: &str = "CMS_SignerInfo_verify_content";
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { si_of(si) }) else { return -1 };
        // SAFETY: no preconditions.
        let mctx = unsafe { EVP_MD_CTX_new() };
        let mut pkctx: *mut EVP_PKEY_CTX = ptr::null_mut();
        let mut r = -1;
        'err: {
            if mctx.is_null() {
                raise(ERR_R_EVP_LIB, F);
                break 'err;
            }
            let mut os: *const ASN1_OCTET_STRING = ptr::null();
            // SAFETY: the signer info.
            if unsafe { CMS_signed_get_attr_count(si) } >= 0 {
                let md_obj = nid_obj(NID_pkcs9_messageDigest);
                // SAFETY: as above; a static object.
                os = unsafe { CMS_signed_get0_data_by_OBJ(si, md_obj, -3, V_ASN1_OCTET_STRING) }.cast();
                if os.is_null() {
                    raise(CMS_R_ERROR_READING_MESSAGEDIGEST_ATTRIBUTE, F);
                    break 'err;
                }
            }
            // SAFETY: the context; the chain; the signer's algorithm.
            if unsafe { digest_algorithm_find_ctx(mctx, chain, s.digest_algorithm) } == 0 {
                break 'err;
            }
            let mut mval = [0u8; EVP_MAX_MD_SIZE as usize];
            let mut mlen: c_uint = 0;
            // SAFETY: as above; room for any digest.
            if unsafe { EVP_DigestFinal_ex(mctx, mval.as_mut_ptr(), &mut mlen) } <= 0 {
                raise(CMS_R_UNABLE_TO_FINALIZE_CONTEXT, F);
                break 'err;
            }
            let computed = mval.get(..usize::try_from(mlen).unwrap_or(0)).unwrap_or_default();
            if os.is_null() {
                // SAFETY: the context.
                let md = unsafe { EVP_MD_CTX_get0_md(mctx) };
                let (libctx, propq) = ctx_parts(s.cms_ctx);
                // SAFETY: the signer's key; its context and properties.
                pkctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, s.pkey, propq) };
                if pkctx.is_null() {
                    break 'err;
                }
                // SAFETY: the new key context.
                if unsafe { EVP_PKEY_verify_init(pkctx) } <= 0 {
                    break 'err;
                }
                // SAFETY: as above; the digest.
                if unsafe { EVP_PKEY_CTX_set_signature_md(pkctx, md) } <= 0 {
                    break 'err;
                }
                s.pctx = pkctx;
                if !sd_asn1_ctrl(s, true) {
                    s.pctx = ptr::null_mut();
                    break 'err;
                }
                s.pctx = ptr::null_mut();
                // SAFETY: the signer's signature, live.
                let sig = unsafe { octets(s.signature) };
                // SAFETY: the key context; the signature; the digest.
                r = unsafe { EVP_PKEY_verify(pkctx, sig.as_ptr(), sig.len(), computed.as_ptr(), computed.len()) };
                if r <= 0 {
                    raise(CMS_R_VERIFICATION_FAILURE, F);
                    r = 0;
                }
            } else {
                // SAFETY: the attribute's string, live.
                let want = unsafe { octets(os) };
                if want.len() != computed.len() {
                    raise(CMS_R_MESSAGEDIGEST_ATTRIBUTE_WRONG_LENGTH, F);
                    break 'err;
                }
                // SAFETY: two buffers of `computed.len()` octets.
                if unsafe { mem::CRYPTO_memcmp(want.as_ptr().cast(), computed.as_ptr().cast(), computed.len()) } != 0 {
                    raise(CMS_R_VERIFICATION_FAILURE, F);
                    r = 0;
                } else {
                    r = 1;
                }
            }
        }
        // SAFETY: the contexts made here, or NULL.
        unsafe { EVP_PKEY_CTX_free(pkctx) };
        // SAFETY: as above.
        unsafe { EVP_MD_CTX_free(mctx) };
        r
    }
}

ffi_export! {
    /// Verifies SignedData on its own (with `extra` certificates and `crls`), as
    /// [`super::smime::CMS_verify`] does: the content in a new memory BIO, or NULL.
    ///
    /// # Safety
    /// `sd` is NULL or a live SignedData; the others NULL or live.
    pub unsafe extern "C" fn CMS_SignedData_verify(sd: *mut CMS_SignedData, detached_data: *mut BIO, scerts: *mut stack_st_X509, store: *mut X509_STORE, extra: *mut stack_st_X509, crls: *mut stack_st_X509_CRL, flags: c_uint, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        if sd.is_null() {
            raise(ERR_R_PASSED_NULL_PARAMETER, "CMS_SignedData_verify");
            return ptr::null_mut();
        }
        // SAFETY: the caller's context.
        let ci = unsafe { CMS_ContentInfo_new_ex(libctx, propq) };
        // SAFETY: the new object, or NULL.
        let Some(c) = (unsafe { cms_of(ci) }) else { return ptr::null_mut() };
        // SAFETY: no preconditions.
        let method = unsafe { crate::bio::mem::BIO_s_mem() };
        // SAFETY: the built-in method.
        let mut bio = unsafe { crate::bio::BIO_new(method) };
        let res = 'end: {
            if bio.is_null() {
                break 'end false;
            }
            c.content_type = nid_obj(NID_pkcs7_signed);
            c.d = sd.cast();
            // SAFETY: the caller's certificates, or NULL.
            for i in 0..unsafe { OPENSSL_sk_num(extra.cast()) } {
                // SAFETY: an index within them.
                let x = unsafe { crate::stack::OPENSSL_sk_value(extra.cast(), i) }.cast::<X509>();
                // SAFETY: the object; a certificate.
                if unsafe { CMS_add1_cert(ci, x) } == 0 {
                    break 'end false;
                }
            }
            // SAFETY: the caller's CRLs, or NULL.
            for i in 0..unsafe { OPENSSL_sk_num(crls.cast()) } {
                // SAFETY: an index within them.
                let c = unsafe { crate::stack::OPENSSL_sk_value(crls.cast(), i) }.cast::<X509_CRL>();
                // SAFETY: the object; a CRL.
                if unsafe { CMS_add1_crl(ci, c) } == 0 {
                    break 'end false;
                }
            }
            // SAFETY: the object; the caller's arguments.
            (unsafe { super::smime::CMS_verify(ci, scerts, store, detached_data, bio, flags) }) != 0
        };
        // The caller's SignedData isn't freed with the object.
        c.d = ptr::null_mut();
        // SAFETY: the object made here.
        unsafe { CMS_ContentInfo_free(ci) };
        if !res {
            // SAFETY: the BIO made here, or NULL.
            unsafe { crate::bio::BIO_free(bio) };
            bio = ptr::null_mut();
        }
        bio
    }
}

ffi_export! {
    /// Adds the capabilities as the signer's S/MIME capabilities attribute: 1, or 0.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; `algs` NULL or a live list.
    pub unsafe extern "C" fn CMS_add_smimecap(si: *mut CMS_SignerInfo, algs: *mut stack_st_X509_ALGOR) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        let mut der: *mut c_uchar = ptr::null_mut();
        // SAFETY: the caller's list; room for the encoding's pointer.
        let n = unsafe { i2d_X509_ALGORS(algs.cast(), &mut der) };
        if n <= 0 {
            return 0;
        }
        // SAFETY: the caller's signer info; the encoding's octets.
        let r = unsafe { CMS_signed_add1_attr_by_NID(si, NID_SMIMECapabilities, V_ASN1_SEQUENCE, der.cast(), n) };
        // SAFETY: the encoding, from CRYPTO_malloc.
        unsafe { mem::release(der.cast()) };
        r
    }
}

ffi_export! {
    /// Adds a capability for `algnid` (with its key size as an INTEGER when positive) to
    /// `*algs`, made if NULL: 1, or 0.
    ///
    /// # Safety
    /// `algs` is room for a list, holding NULL or a live one.
    pub unsafe extern "C" fn CMS_add_simple_smimecap(algs: *mut *mut stack_st_X509_ALGOR, algnid: c_int, keysize: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        let mut key: *mut ASN1_INTEGER = ptr::null_mut();
        if keysize > 0 {
            // SAFETY: no preconditions.
            key = unsafe { ASN1_INTEGER_new() };
            // SAFETY: the new integer, or NULL.
            if key.is_null() || unsafe { ASN1_INTEGER_set(key, c_long::from(keysize)) } == 0 {
                // SAFETY: as above.
                unsafe { ASN1_INTEGER_free(key) };
                return 0;
            }
        }
        // SAFETY: no preconditions.
        let alg = unsafe { X509_ALGOR_new() };
        let ptype = if key.is_null() { V_ASN1_UNDEF } else { V_ASN1_INTEGER };
        // SAFETY: the new identifier, or NULL; it takes the integer.
        if alg.is_null() || unsafe { X509_ALGOR_set0(alg, nid_obj(algnid), ptype, key.cast()) } == 0 {
            // SAFETY: the values made here, or NULL.
            unsafe { X509_ALGOR_free(alg) };
            // SAFETY: as above.
            unsafe { ASN1_INTEGER_free(key) };
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(slot) = (unsafe { algs.as_mut() }) else {
            // SAFETY: as above.
            unsafe { X509_ALGOR_free(alg) };
            return 0;
        };
        if slot.is_null() {
            // SAFETY: no preconditions.
            *slot = unsafe { OPENSSL_sk_new_null() }.cast();
        }
        // SAFETY: the list, or NULL; the identifier.
        if slot.is_null() || unsafe { OPENSSL_sk_push((*slot).cast(), alg.cast()) } == 0 {
            // SAFETY: as above.
            unsafe { X509_ALGOR_free(alg) };
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Adds the standard capabilities (the ciphers and digests the build has) to `*smcap`:
    /// 1, or 0.
    ///
    /// # Safety
    /// As for [`CMS_add_simple_smimecap`].
    pub unsafe extern "C" fn CMS_add_standard_smimecap(smcap: *mut *mut stack_st_X509_ALGOR) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        let caps = [
            (NID_aes_256_cbc, -1, true),
            (NID_id_GostR3411_2012_256, -1, false),
            (NID_id_GostR3411_2012_512, -1, false),
            (NID_id_GostR3411_94, -1, false),
            (NID_id_Gost28147_89, -1, true),
            (NID_aes_192_cbc, -1, true),
            (NID_aes_128_cbc, -1, true),
            (NID_des_ede3_cbc, -1, true),
            (NID_rc2_cbc, 128, true),
            (NID_rc2_cbc, 64, true),
            (NID_des_cbc, -1, true),
            (NID_rc2_cbc, 40, true),
        ];
        for (nid, arg, cipher) in caps {
            // SAFETY: any NID.
            let sn = unsafe { OBJ_nid2sn(nid) };
            let known = if cipher {
                // SAFETY: NULL or a static name.
                !unsafe { EVP_get_cipherbyname(sn) }.is_null()
            } else {
                !digest_by_nid(nid).is_null()
            };
            // SAFETY: the caller's guarantee.
            if known && unsafe { CMS_add_simple_smimecap(smcap, nid, arg) } == 0 {
                return 0;
            }
        }
        1
    }
}
