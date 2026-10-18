//! CMS (`crypto/cms`, RFC 5652): the content types and their ASN.1 (`cms_asn1.c`), and the
//! library, attribute, digest, compression, receipt-request, encrypted-data, and I/O functions
//! over them ([`base`], [`att`], [`ess`], [`enc`], [`io`], [`smime`]).
//!
//! The structures are opaque in `cms.h`; their layouts here are OpenSSL's internal ones
//! (`cms_local.h`), which the templates describe. Signing and verifying come with step 6.4b, the
//! enveloped types' recipients with 6.4c: until then their paths abort (AGENTS.md rule 10).

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_GENERALIZEDTIME, ASN1_INTEGER, ASN1_ITEM, ASN1_ITYPE_NDEF_SEQUENCE,
    ASN1_ITYPE_PRIMITIVE, ASN1_OBJECT, ASN1_OCTET_STRING, ASN1_OP_DETACHED_POST,
    ASN1_OP_DETACHED_PRE, ASN1_OP_FREE_POST, ASN1_OP_FREE_PRE, ASN1_OP_NEW_POST,
    ASN1_OP_STREAM_POST, ASN1_OP_STREAM_PRE, ASN1_STREAM_ARG, ASN1_TFLG_EMBED, ASN1_TFLG_EXPLICIT,
    ASN1_TFLG_IMPLICIT, ASN1_TFLG_IMPTAG, ASN1_TFLG_NDEF, ASN1_TFLG_OPTIONAL,
    ASN1_TFLG_SEQUENCE_OF, ASN1_TFLG_SET_OF, ASN1_TFLG_SET_ORDER, ASN1_TFLG_UNIVERSAL, ASN1_TYPE,
    ASN1_VALUE, CMS_RECIPINFO_KEK, CMS_RECIPINFO_PASS, CMS_RECIPINFO_TRANS, ERR_LIB_ASN1,
    ERR_LIB_CMS, EVP_CIPHER, EVP_CIPHER_CTX, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW, EVP_MD_CTX, EVP_PKEY,
    EVP_PKEY_CTX, NID_id_smime_ct_authData, NID_id_smime_ct_authEnvelopedData,
    NID_id_smime_ct_compressedData, NID_pkcs7_data, NID_pkcs7_digest, NID_pkcs7_encrypted,
    NID_pkcs7_enveloped, NID_pkcs7_signed, OSSL_LIB_CTX, V_ASN1_SEQUENCE, V_ASN1_SET, X509,
    X509_ALGOR, X509_NAME,
};

use crate::asn1::tpl::ints::INT32_it;
use crate::asn1::tpl::items::{
    ASN1_ANY_it, ASN1_BIT_STRING_it, ASN1_GENERALIZEDTIME_it, ASN1_INTEGER_it, ASN1_OBJECT_it,
    ASN1_OCTET_STRING_NDEF_it, ASN1_OCTET_STRING_it, ASN1_SEQUENCE_it, X509_ALGOR_it,
};
use crate::asn1::tpl::statics::{
    Adb, AdbEntries, Aux, Templates, adb_entry, adb_object, adb_oid, aux, choice, sequence,
};
use crate::asn1::tpl::{Item, Template, item, item_fns, size_of_long, template, template_at};
use crate::evp::cipher_ctx::{EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_set_flags};
use crate::evp::md_ctx::EVP_MD_CTX_free;
use crate::evp::pkey::EVP_PKEY_free;
use crate::evp::pkey_ctx::EVP_PKEY_CTX_free;
use crate::ffi::ffi_callback;
use crate::mem;
use crate::x509::attrib::X509_ATTRIBUTE_it;
use crate::x509::cert::{X509_free, X509_it};
use crate::x509::crl::X509_CRL_it;
use crate::x509::name::X509_NAME_it;
use crate::x509v3::genn::GENERAL_NAMES_it;

pub(crate) mod att;
pub(crate) mod base;
pub(crate) mod enc;
pub(crate) mod env;
pub(crate) mod ess;
pub(crate) mod io;
pub(crate) mod kari;
pub(crate) mod pkey;
pub(crate) mod pwri;
pub(crate) mod sd;
pub(crate) mod smime;

/// A stack of anything, as the structures hold them.
pub(crate) type Stack = c_void;

/// The `i`th element of a stack, as a `T`.
///
/// # Safety
/// `sk` is NULL or a live stack of `T`s.
pub(crate) unsafe fn sk_get<'a, T>(sk: *mut Stack, i: c_int) -> Option<&'a mut T> {
    // SAFETY: the caller's guarantee; an index out of range gives NULL.
    let v = unsafe { crate::stack::OPENSSL_sk_value(sk.cast(), i) };
    // SAFETY: as above, NULL or a live `T`.
    unsafe { v.cast::<T>().as_mut() }
}

/// The value in a template callback's slot.
///
/// # Safety
/// `pval` is the engine's slot, holding NULL or a live `T`.
unsafe fn slot_value<'a, T>(pval: *mut *mut ASN1_VALUE) -> Option<&'a mut T> {
    if pval.is_null() {
        return None;
    }
    // SAFETY: the caller's guarantee.
    let v = unsafe { pval.cast::<*mut T>().read() };
    // SAFETY: as above.
    unsafe { v.as_mut() }
}

// `cms_local.h`'s choice selectors.
pub(crate) const CERTCHOICE_CERT: c_int = 0;
pub(crate) const REVCHOICE_CRL: c_int = 0;

/// `CMS_CTX`.
#[repr(C)]
pub(crate) struct CmsCtx {
    pub(crate) libctx: *mut OSSL_LIB_CTX,
    pub(crate) propq: *mut c_char,
}

/// `CMS_ContentInfo`; `d` is the union of the content types' pointers.
#[repr(C)]
pub(crate) struct ContentInfo {
    pub(crate) content_type: *mut ASN1_OBJECT,
    pub(crate) d: *mut c_void,
    pub(crate) ctx: CmsCtx,
}

#[repr(C)]
pub(crate) struct SignedData {
    pub(crate) version: i32,
    pub(crate) digest_algorithms: *mut Stack,
    pub(crate) encap: *mut EncapContentInfo,
    pub(crate) certificates: *mut Stack,
    pub(crate) crls: *mut Stack,
    pub(crate) signer_infos: *mut Stack,
}

#[repr(C)]
pub(crate) struct EncapContentInfo {
    pub(crate) e_content_type: *mut ASN1_OBJECT,
    pub(crate) e_content: *mut ASN1_OCTET_STRING,
    pub(crate) partial: c_int,
}

#[repr(C)]
pub(crate) struct SignerInfo {
    pub(crate) version: i32,
    pub(crate) sid: *mut SignerIdentifier,
    pub(crate) digest_algorithm: *mut X509_ALGOR,
    pub(crate) signed_attrs: *mut Stack,
    pub(crate) signature_algorithm: *mut X509_ALGOR,
    pub(crate) signature: *mut ASN1_OCTET_STRING,
    pub(crate) unsigned_attrs: *mut Stack,
    pub(crate) signer: *mut X509,
    pub(crate) pkey: *mut EVP_PKEY,
    pub(crate) mctx: *mut EVP_MD_CTX,
    pub(crate) pctx: *mut EVP_PKEY_CTX,
    pub(crate) cms_ctx: *const CmsCtx,
    pub(crate) omit_signing_time: c_int,
}

/// `CMS_SignerIdentifier`, also the recipient identifier: issuer and serial, or a key
/// identifier.
#[repr(C)]
pub(crate) struct SignerIdentifier {
    pub(crate) type_: c_int,
    pub(crate) d: *mut c_void,
}

#[repr(C)]
pub(crate) struct EnvelopedData {
    pub(crate) version: i32,
    pub(crate) originator_info: *mut OriginatorInfo,
    pub(crate) recipient_infos: *mut Stack,
    pub(crate) encrypted_content_info: *mut EncryptedContentInfo,
    pub(crate) unprotected_attrs: *mut Stack,
}

#[repr(C)]
pub(crate) struct OriginatorInfo {
    pub(crate) certificates: *mut Stack,
    pub(crate) crls: *mut Stack,
}

#[repr(C)]
pub(crate) struct EncryptedContentInfo {
    pub(crate) content_type: *mut ASN1_OBJECT,
    pub(crate) content_encryption_algorithm: *mut X509_ALGOR,
    pub(crate) encrypted_content: *mut ASN1_OCTET_STRING,
    pub(crate) cipher: *const EVP_CIPHER,
    pub(crate) key: *mut c_uchar,
    pub(crate) keylen: usize,
    pub(crate) tag: *mut c_uchar,
    pub(crate) taglen: usize,
    pub(crate) debug: c_int,
    pub(crate) havenocert: c_int,
}

#[repr(C)]
pub(crate) struct RecipientInfo {
    pub(crate) type_: c_int,
    pub(crate) d: *mut c_void,
}

#[repr(C)]
pub(crate) struct KeyTransRecipientInfo {
    pub(crate) version: i32,
    pub(crate) rid: *mut SignerIdentifier,
    pub(crate) key_encryption_algorithm: *mut X509_ALGOR,
    pub(crate) encrypted_key: *mut ASN1_OCTET_STRING,
    pub(crate) recip: *mut X509,
    pub(crate) pkey: *mut EVP_PKEY,
    pub(crate) pctx: *mut EVP_PKEY_CTX,
    pub(crate) cms_ctx: *const CmsCtx,
}

#[repr(C)]
pub(crate) struct KeyAgreeRecipientInfo {
    pub(crate) version: i32,
    pub(crate) originator: *mut OriginatorIdentifierOrKey,
    pub(crate) ukm: *mut ASN1_OCTET_STRING,
    pub(crate) key_encryption_algorithm: *mut X509_ALGOR,
    pub(crate) recipient_encrypted_keys: *mut Stack,
    pub(crate) pctx: *mut EVP_PKEY_CTX,
    pub(crate) ctx: *mut EVP_CIPHER_CTX,
    pub(crate) cms_ctx: *const CmsCtx,
}

#[repr(C)]
pub(crate) struct OriginatorIdentifierOrKey {
    pub(crate) type_: c_int,
    pub(crate) d: *mut c_void,
}

#[repr(C)]
pub(crate) struct OriginatorPublicKey {
    pub(crate) algorithm: *mut X509_ALGOR,
    pub(crate) public_key: *mut ASN1_BIT_STRING,
}

#[repr(C)]
pub(crate) struct RecipientEncryptedKey {
    pub(crate) rid: *mut KeyAgreeRecipientIdentifier,
    pub(crate) encrypted_key: *mut ASN1_OCTET_STRING,
    pub(crate) pkey: *mut EVP_PKEY,
}

#[repr(C)]
pub(crate) struct KeyAgreeRecipientIdentifier {
    pub(crate) type_: c_int,
    pub(crate) d: *mut c_void,
}

#[repr(C)]
pub(crate) struct RecipientKeyIdentifier {
    pub(crate) subject_key_identifier: *mut ASN1_OCTET_STRING,
    pub(crate) date: *mut ASN1_GENERALIZEDTIME,
    pub(crate) other: *mut OtherKeyAttribute,
}

#[repr(C)]
pub(crate) struct KekRecipientInfo {
    pub(crate) version: i32,
    pub(crate) kekid: *mut KekIdentifier,
    pub(crate) key_encryption_algorithm: *mut X509_ALGOR,
    pub(crate) encrypted_key: *mut ASN1_OCTET_STRING,
    pub(crate) key: *mut c_uchar,
    pub(crate) keylen: usize,
    pub(crate) cms_ctx: *const CmsCtx,
}

#[repr(C)]
pub(crate) struct KekIdentifier {
    pub(crate) key_identifier: *mut ASN1_OCTET_STRING,
    pub(crate) date: *mut ASN1_GENERALIZEDTIME,
    pub(crate) other: *mut OtherKeyAttribute,
}

#[repr(C)]
pub(crate) struct PasswordRecipientInfo {
    pub(crate) version: i32,
    pub(crate) key_derivation_algorithm: *mut X509_ALGOR,
    pub(crate) key_encryption_algorithm: *mut X509_ALGOR,
    pub(crate) encrypted_key: *mut ASN1_OCTET_STRING,
    pub(crate) pass: *mut c_uchar,
    pub(crate) passlen: usize,
    pub(crate) cms_ctx: *const CmsCtx,
}

#[repr(C)]
pub(crate) struct OtherRecipientInfo {
    pub(crate) ori_type: *mut ASN1_OBJECT,
    pub(crate) ori_value: *mut ASN1_TYPE,
}

#[repr(C)]
pub(crate) struct DigestedData {
    pub(crate) version: i32,
    pub(crate) digest_algorithm: *mut X509_ALGOR,
    pub(crate) encap: *mut EncapContentInfo,
    pub(crate) digest: *mut ASN1_OCTET_STRING,
}

#[repr(C)]
pub(crate) struct EncryptedData {
    pub(crate) version: i32,
    pub(crate) encrypted_content_info: *mut EncryptedContentInfo,
    pub(crate) unprotected_attrs: *mut Stack,
}

#[repr(C)]
pub(crate) struct AuthenticatedData {
    pub(crate) version: i32,
    pub(crate) originator_info: *mut OriginatorInfo,
    pub(crate) recipient_infos: *mut Stack,
    pub(crate) mac_algorithm: *mut X509_ALGOR,
    pub(crate) digest_algorithm: *mut X509_ALGOR,
    pub(crate) encap: *mut EncapContentInfo,
    pub(crate) auth_attrs: *mut Stack,
    pub(crate) mac: *mut ASN1_OCTET_STRING,
    pub(crate) unauth_attrs: *mut Stack,
}

#[repr(C)]
pub(crate) struct AuthEnvelopedData {
    pub(crate) version: i32,
    pub(crate) originator_info: *mut OriginatorInfo,
    pub(crate) recipient_infos: *mut Stack,
    pub(crate) auth_encrypted_content_info: *mut EncryptedContentInfo,
    pub(crate) auth_attrs: *mut Stack,
    pub(crate) mac: *mut ASN1_OCTET_STRING,
    pub(crate) unauth_attrs: *mut Stack,
}

#[repr(C)]
pub(crate) struct CompressedData {
    pub(crate) version: i32,
    pub(crate) compression_algorithm: *mut X509_ALGOR,
    pub(crate) recipient_infos: *mut Stack,
    pub(crate) encap: *mut EncapContentInfo,
}

#[repr(C)]
pub(crate) struct RevocationInfoChoice {
    pub(crate) type_: c_int,
    pub(crate) d: *mut c_void,
}

#[repr(C)]
pub(crate) struct OtherRevocationInfoFormat {
    pub(crate) other_rev_info_format: *mut ASN1_OBJECT,
    pub(crate) other_rev_info: *mut ASN1_TYPE,
}

#[repr(C)]
pub(crate) struct CertificateChoices {
    pub(crate) type_: c_int,
    pub(crate) d: *mut c_void,
}

#[repr(C)]
pub(crate) struct OtherCertificateFormat {
    pub(crate) other_cert_format: *mut ASN1_OBJECT,
    pub(crate) other_cert: *mut ASN1_TYPE,
}

#[repr(C)]
pub(crate) struct IssuerAndSerialNumber {
    pub(crate) issuer: *mut X509_NAME,
    pub(crate) serial_number: *mut ASN1_INTEGER,
}

#[repr(C)]
pub(crate) struct OtherKeyAttribute {
    pub(crate) key_attr_id: *mut ASN1_OBJECT,
    pub(crate) key_attr: *mut ASN1_TYPE,
}

#[repr(C)]
pub(crate) struct ReceiptRequest {
    pub(crate) signed_content_identifier: *mut ASN1_OCTET_STRING,
    pub(crate) receipts_from: *mut ReceiptsFrom,
    pub(crate) receipts_to: *mut Stack,
}

/// `CMS_ReceiptsFrom`'s union.
#[repr(C)]
pub(crate) union ReceiptsFromD {
    pub(crate) all_or_first_tier: i32,
    pub(crate) receipt_list: *mut Stack,
}

#[repr(C)]
pub(crate) struct ReceiptsFrom {
    pub(crate) type_: c_int,
    pub(crate) d: ReceiptsFromD,
}

#[repr(C)]
pub(crate) struct Receipt {
    pub(crate) version: i32,
    pub(crate) content_type: *mut ASN1_OBJECT,
    pub(crate) signed_content_identifier: *mut ASN1_OCTET_STRING,
    pub(crate) originator_signature_value: *mut ASN1_OCTET_STRING,
}

#[repr(C)]
pub(crate) struct SharedInfo {
    pub(crate) key_info: *mut X509_ALGOR,
    pub(crate) entity_u_info: *mut ASN1_OCTET_STRING,
    pub(crate) supp_pub_info: *mut ASN1_OCTET_STRING,
}

// The ASN.1 (`cms_asn1.c`).

const SIMPLE: c_int = 0;
const OPT: c_int = ASN1_TFLG_OPTIONAL;
const EMBED: c_int = ASN1_TFLG_EMBED;
const IMP: c_int = ASN1_TFLG_IMPLICIT;
const IMP_OPT: c_int = ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL;
const IMP_EMBED: c_int = ASN1_TFLG_IMPLICIT | ASN1_TFLG_EMBED;
const EXP: c_int = ASN1_TFLG_EXPLICIT;
const EXP_OPT: c_int = ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL;
const NDEF_EXP: c_int = ASN1_TFLG_EXPLICIT | ASN1_TFLG_NDEF;
const NDEF_EXP_OPT: c_int = ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL | ASN1_TFLG_NDEF;
const SET_OF: c_int = ASN1_TFLG_SET_OF;
const SEQ_OF: c_int = ASN1_TFLG_SEQUENCE_OF;
const IMP_SET_OF_OPT: c_int = ASN1_TFLG_SET_OF | ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL;
const IMP_SEQ_OF: c_int = ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_IMPLICIT;

/// `ASN1_NDEF_SEQUENCE`: an indefinite-length-capable SEQUENCE item over `T`.
const fn ndef_sequence<T, const N: usize>(
    templates: &'static Templates<N>,
    aux: Option<&'static Aux>,
    sname: &'static core::ffi::CStr,
) -> Item {
    #[expect(clippy::cast_possible_wrap, reason = "a handful of templates")]
    let n = N as c_long;
    let funcs: *const c_void = match aux {
        Some(a) => (&raw const a.0).cast(),
        None => ptr::null(),
    };
    item(
        ASN1_ITYPE_NDEF_SEQUENCE,
        V_ASN1_SEQUENCE,
        (&raw const templates.0).cast(),
        n,
        funcs,
        size_of_long::<T>(),
        sname,
    )
}

/// An item OpenSSL keeps static, and its `_it` function.
macro_rules! private_item {
    ($($(#[$attr:meta])* fn $name:ident = $item:expr;)*) => {$(
        $(#[$attr])*
        pub(crate) unsafe extern "C" fn $name() -> *const ASN1_ITEM {
            static ITEM: Item = $item;
            &raw const ITEM.0
        }
    )*};
}

macro_rules! tt {
    ($t:ty; $($flags:expr, $tag:expr, $field:ident, $name:literal, $it:expr;)*) => {
        Templates([$(template_at($flags, $tag, offset_of!($t, $field), $name, $it),)*])
    };
}

static IAS_TT: Templates<2> = tt![IssuerAndSerialNumber;
    SIMPLE, 0, issuer, c"issuer", X509_NAME_it;
    SIMPLE, 0, serial_number, c"serialNumber", ASN1_INTEGER_it;
];

static OCF_TT: Templates<2> = tt![OtherCertificateFormat;
    SIMPLE, 0, other_cert_format, c"otherCertFormat", ASN1_OBJECT_it;
    OPT, 0, other_cert, c"otherCert", ASN1_ANY_it;
];

static CC_TT: Templates<5> = tt![CertificateChoices;
    SIMPLE, 0, d, c"d.certificate", X509_it;
    IMP, 0, d, c"d.extendedCertificate", ASN1_SEQUENCE_it;
    IMP, 1, d, c"d.v1AttrCert", ASN1_SEQUENCE_it;
    IMP, 2, d, c"d.v2AttrCert", ASN1_SEQUENCE_it;
    IMP, 3, d, c"d.other", other_certificate_format_it;
];

static SID_TT: Templates<2> = tt![SignerIdentifier;
    SIMPLE, 0, d, c"d.issuerAndSerialNumber", ias_it;
    IMP, 0, d, c"d.subjectKeyIdentifier", ASN1_OCTET_STRING_it;
];

static ECI_TT: Templates<2> = tt![EncapContentInfo;
    SIMPLE, 0, e_content_type, c"eContentType", ASN1_OBJECT_it;
    NDEF_EXP_OPT, 0, e_content, c"eContent", ASN1_OCTET_STRING_NDEF_it;
];

ffi_callback! {
    /// `cms_si_cb`: frees the signer's key, certificate, and contexts.
    ///
    /// # Safety
    /// As the template engine calls it.
    pub(crate) unsafe extern "C" fn cms_si_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, _exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        if operation == ASN1_OP_FREE_POST {
            // SAFETY: the value being freed, a signer info.
            if let Some(si) = unsafe { slot_value::<SignerInfo>(pval) } {
                // SAFETY: the signer info's own references, or NULL.
                unsafe { EVP_PKEY_free(si.pkey) };
                // SAFETY: as above.
                unsafe { X509_free(si.signer) };
                // SAFETY: as above.
                unsafe { EVP_MD_CTX_free(si.mctx) };
                // SAFETY: as above.
                unsafe { EVP_PKEY_CTX_free(si.pctx) };
            }
        }
        1
    }
}

static SI_AUX: Aux = aux(cms_si_cb);

static SI_TT: Templates<7> = tt![SignerInfo;
    EMBED, 0, version, c"version", INT32_it;
    SIMPLE, 0, sid, c"sid", signer_identifier_it;
    SIMPLE, 0, digest_algorithm, c"digestAlgorithm", X509_ALGOR_it;
    IMP_SET_OF_OPT, 0, signed_attrs, c"signedAttrs", X509_ATTRIBUTE_it;
    SIMPLE, 0, signature_algorithm, c"signatureAlgorithm", X509_ALGOR_it;
    SIMPLE, 0, signature, c"signature", ASN1_OCTET_STRING_it;
    IMP_SET_OF_OPT, 1, unsigned_attrs, c"unsignedAttrs", X509_ATTRIBUTE_it;
];

static ORIF_TT: Templates<2> = tt![OtherRevocationInfoFormat;
    SIMPLE, 0, other_rev_info_format, c"otherRevInfoFormat", ASN1_OBJECT_it;
    OPT, 0, other_rev_info, c"otherRevInfo", ASN1_ANY_it;
];

static RIC_TT: Templates<2> = tt![RevocationInfoChoice;
    SIMPLE, 0, d, c"d.crl", X509_CRL_it;
    IMP, 1, d, c"d.other", other_revocation_info_format_it;
];

static SD_TT: Templates<6> = tt![SignedData;
    EMBED, 0, version, c"version", INT32_it;
    SET_OF, 0, digest_algorithms, c"digestAlgorithms", X509_ALGOR_it;
    SIMPLE, 0, encap, c"encapContentInfo", encapsulated_content_info_it;
    IMP_SET_OF_OPT, 0, certificates, c"certificates", certificate_choices_it;
    IMP_SET_OF_OPT, 1, crls, c"crls", revocation_info_choice_it;
    SET_OF, 0, signer_infos, c"signerInfos", signer_info_it;
];

static OI_TT: Templates<2> = tt![OriginatorInfo;
    IMP_SET_OF_OPT, 0, certificates, c"certificates", certificate_choices_it;
    IMP_SET_OF_OPT, 1, crls, c"crls", revocation_info_choice_it;
];

ffi_callback! {
    /// `cms_ec_cb`: clears and frees the content key.
    ///
    /// # Safety
    /// As the template engine calls it.
    pub(crate) unsafe extern "C" fn cms_ec_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, _exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        if operation == ASN1_OP_FREE_POST {
            // SAFETY: the value being freed.
            if let Some(ec) = unsafe { slot_value::<EncryptedContentInfo>(pval) } {
                // SAFETY: the key, from CRYPTO_malloc, of its length, or NULL.
                unsafe { mem::release_clean(ec.key.cast(), ec.keylen) };
            }
        }
        1
    }
}

static EC_AUX: Aux = aux(cms_ec_cb);

static ECINFO_TT: Templates<3> = tt![EncryptedContentInfo;
    SIMPLE, 0, content_type, c"contentType", ASN1_OBJECT_it;
    SIMPLE, 0, content_encryption_algorithm, c"contentEncryptionAlgorithm", X509_ALGOR_it;
    IMP_OPT, 0, encrypted_content, c"encryptedContent", ASN1_OCTET_STRING_NDEF_it;
];

static KTRI_TT: Templates<4> = tt![KeyTransRecipientInfo;
    EMBED, 0, version, c"version", INT32_it;
    SIMPLE, 0, rid, c"rid", signer_identifier_it;
    SIMPLE, 0, key_encryption_algorithm, c"keyEncryptionAlgorithm", X509_ALGOR_it;
    SIMPLE, 0, encrypted_key, c"encryptedKey", ASN1_OCTET_STRING_it;
];

static OKA_TT: Templates<2> = tt![OtherKeyAttribute;
    SIMPLE, 0, key_attr_id, c"keyAttrId", ASN1_OBJECT_it;
    OPT, 0, key_attr, c"keyAttr", ASN1_ANY_it;
];

static RKID_TT: Templates<3> = tt![RecipientKeyIdentifier;
    SIMPLE, 0, subject_key_identifier, c"subjectKeyIdentifier", ASN1_OCTET_STRING_it;
    OPT, 0, date, c"date", ASN1_GENERALIZEDTIME_it;
    OPT, 0, other, c"other", other_key_attribute_it;
];

static KARID_TT: Templates<2> = tt![KeyAgreeRecipientIdentifier;
    SIMPLE, 0, d, c"d.issuerAndSerialNumber", ias_it;
    IMP, 0, d, c"d.rKeyId", recipient_key_identifier_it;
];

ffi_callback! {
    /// `cms_rek_cb`: frees the recipient's key.
    ///
    /// # Safety
    /// As the template engine calls it.
    pub(crate) unsafe extern "C" fn cms_rek_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, _exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        if operation == ASN1_OP_FREE_POST {
            // SAFETY: the value being freed.
            if let Some(rek) = unsafe { slot_value::<RecipientEncryptedKey>(pval) } {
                // SAFETY: its own key, or NULL.
                unsafe { EVP_PKEY_free(rek.pkey) };
            }
        }
        1
    }
}

static REK_AUX: Aux = aux(cms_rek_cb);

static REK_TT: Templates<2> = tt![RecipientEncryptedKey;
    SIMPLE, 0, rid, c"rid", key_agree_recipient_identifier_it;
    SIMPLE, 0, encrypted_key, c"encryptedKey", ASN1_OCTET_STRING_it;
];

static OPK_TT: Templates<2> = tt![OriginatorPublicKey;
    SIMPLE, 0, algorithm, c"algorithm", X509_ALGOR_it;
    SIMPLE, 0, public_key, c"publicKey", ASN1_BIT_STRING_it;
];

static OIK_TT: Templates<3> = tt![OriginatorIdentifierOrKey;
    SIMPLE, 0, d, c"d.issuerAndSerialNumber", ias_it;
    IMP, 0, d, c"d.subjectKeyIdentifier", ASN1_OCTET_STRING_it;
    IMP, 1, d, c"d.originatorKey", originator_public_key_it;
];

ffi_callback! {
    /// `cms_kari_cb`: the key-wrap cipher context, made and freed with the recipient info.
    ///
    /// # Safety
    /// As the template engine calls it.
    pub(crate) unsafe extern "C" fn cms_kari_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, _exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the value made or being freed.
        let Some(kari) = (unsafe { slot_value::<KeyAgreeRecipientInfo>(pval) }) else {
            return 1;
        };
        if operation == ASN1_OP_NEW_POST {
            // SAFETY: no preconditions.
            kari.ctx = unsafe { EVP_CIPHER_CTX_new() };
            if kari.ctx.is_null() {
                return 0;
            }
            // SAFETY: the new context.
            unsafe { EVP_CIPHER_CTX_set_flags(kari.ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW) };
            kari.pctx = ptr::null_mut();
        } else if operation == ASN1_OP_FREE_POST {
            // SAFETY: its own contexts, or NULL.
            unsafe { EVP_PKEY_CTX_free(kari.pctx) };
            // SAFETY: as above.
            unsafe { EVP_CIPHER_CTX_free(kari.ctx) };
        }
        1
    }
}

static KARI_AUX: Aux = aux(cms_kari_cb);

static KARI_TT: Templates<5> = tt![KeyAgreeRecipientInfo;
    EMBED, 0, version, c"version", INT32_it;
    EXP, 0, originator, c"originator", originator_identifier_or_key_it;
    EXP_OPT, 1, ukm, c"ukm", ASN1_OCTET_STRING_it;
    SIMPLE, 0, key_encryption_algorithm, c"keyEncryptionAlgorithm", X509_ALGOR_it;
    SEQ_OF, 0, recipient_encrypted_keys, c"recipientEncryptedKeys", recipient_encrypted_key_it;
];

static KEKID_TT: Templates<3> = tt![KekIdentifier;
    SIMPLE, 0, key_identifier, c"keyIdentifier", ASN1_OCTET_STRING_it;
    OPT, 0, date, c"date", ASN1_GENERALIZEDTIME_it;
    OPT, 0, other, c"other", other_key_attribute_it;
];

static KEKRI_TT: Templates<4> = tt![KekRecipientInfo;
    EMBED, 0, version, c"version", INT32_it;
    SIMPLE, 0, kekid, c"kekid", kek_identifier_it;
    SIMPLE, 0, key_encryption_algorithm, c"keyEncryptionAlgorithm", X509_ALGOR_it;
    SIMPLE, 0, encrypted_key, c"encryptedKey", ASN1_OCTET_STRING_it;
];

static PWRI_TT: Templates<4> = tt![PasswordRecipientInfo;
    EMBED, 0, version, c"version", INT32_it;
    IMP_OPT, 0, key_derivation_algorithm, c"keyDerivationAlgorithm", X509_ALGOR_it;
    SIMPLE, 0, key_encryption_algorithm, c"keyEncryptionAlgorithm", X509_ALGOR_it;
    SIMPLE, 0, encrypted_key, c"encryptedKey", ASN1_OCTET_STRING_it;
];

static ORI_TT: Templates<2> = tt![OtherRecipientInfo;
    SIMPLE, 0, ori_type, c"oriType", ASN1_OBJECT_it;
    OPT, 0, ori_value, c"oriValue", ASN1_ANY_it;
];

ffi_callback! {
    /// `cms_ri_cb`: frees what a recipient info holds beyond its encoding.
    ///
    /// # Safety
    /// As the template engine calls it.
    pub(crate) unsafe extern "C" fn cms_ri_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, _exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        if operation != ASN1_OP_FREE_PRE {
            return 1;
        }
        // SAFETY: the value being freed.
        let Some(ri) = (unsafe { slot_value::<RecipientInfo>(pval) }) else {
            return 1;
        };
        match ri.type_ {
            CMS_RECIPINFO_TRANS => {
                // SAFETY: the choice's member, NULL or live.
                if let Some(k) = unsafe { ri.d.cast::<KeyTransRecipientInfo>().as_ref() } {
                    // SAFETY: its own references, or NULL.
                    unsafe { EVP_PKEY_free(k.pkey) };
                    // SAFETY: as above.
                    unsafe { X509_free(k.recip) };
                    // SAFETY: as above.
                    unsafe { EVP_PKEY_CTX_free(k.pctx) };
                }
            }
            CMS_RECIPINFO_KEK => {
                // SAFETY: as above.
                if let Some(k) = unsafe { ri.d.cast::<KekRecipientInfo>().as_ref() } {
                    // SAFETY: its key, from CRYPTO_malloc, or NULL.
                    unsafe { mem::release_clean(k.key.cast(), k.keylen) };
                }
            }
            CMS_RECIPINFO_PASS => {
                // SAFETY: as above.
                if let Some(p) = unsafe { ri.d.cast::<PasswordRecipientInfo>().as_ref() } {
                    // SAFETY: its password, from CRYPTO_malloc, or NULL.
                    unsafe { mem::release_clean(p.pass.cast(), p.passlen) };
                }
            }
            _ => {}
        }
        1
    }
}

static RI_AUX: Aux = aux(cms_ri_cb);

static RI_TT: Templates<5> = tt![RecipientInfo;
    SIMPLE, 0, d, c"d.ktri", key_trans_recipient_info_it;
    IMP, 1, d, c"d.kari", key_agree_recipient_info_it;
    IMP, 2, d, c"d.kekri", kek_recipient_info_it;
    IMP, 3, d, c"d.pwri", password_recipient_info_it;
    IMP, 4, d, c"d.ori", other_recipient_info_it;
];

static ED_TT: Templates<5> = tt![EnvelopedData;
    EMBED, 0, version, c"version", INT32_it;
    IMP_OPT, 0, originator_info, c"originatorInfo", originator_info_it;
    SET_OF, 0, recipient_infos, c"recipientInfos", recipient_info_it;
    SIMPLE, 0, encrypted_content_info, c"encryptedContentInfo", encrypted_content_info_it;
    IMP_SET_OF_OPT, 1, unprotected_attrs, c"unprotectedAttrs", X509_ATTRIBUTE_it;
];

static DD_TT: Templates<4> = tt![DigestedData;
    EMBED, 0, version, c"version", INT32_it;
    SIMPLE, 0, digest_algorithm, c"digestAlgorithm", X509_ALGOR_it;
    SIMPLE, 0, encap, c"encapContentInfo", encapsulated_content_info_it;
    SIMPLE, 0, digest, c"digest", ASN1_OCTET_STRING_it;
];

static ENCD_TT: Templates<3> = tt![EncryptedData;
    EMBED, 0, version, c"version", INT32_it;
    SIMPLE, 0, encrypted_content_info, c"encryptedContentInfo", encrypted_content_info_it;
    IMP_SET_OF_OPT, 1, unprotected_attrs, c"unprotectedAttrs", X509_ATTRIBUTE_it;
];

static AED_TT: Templates<7> = tt![AuthEnvelopedData;
    EMBED, 0, version, c"version", INT32_it;
    IMP_OPT, 0, originator_info, c"originatorInfo", originator_info_it;
    SET_OF, 0, recipient_infos, c"recipientInfos", recipient_info_it;
    SIMPLE, 0, auth_encrypted_content_info, c"authEncryptedContentInfo", encrypted_content_info_it;
    IMP_SET_OF_OPT, 1, auth_attrs, c"authAttrs", X509_ATTRIBUTE_it;
    SIMPLE, 0, mac, c"mac", ASN1_OCTET_STRING_it;
    IMP_SET_OF_OPT, 2, unauth_attrs, c"unauthAttrs", X509_ATTRIBUTE_it;
];

static AD_TT: Templates<9> = tt![AuthenticatedData;
    EMBED, 0, version, c"version", INT32_it;
    IMP_OPT, 0, originator_info, c"originatorInfo", originator_info_it;
    SET_OF, 0, recipient_infos, c"recipientInfos", recipient_info_it;
    SIMPLE, 0, mac_algorithm, c"macAlgorithm", X509_ALGOR_it;
    IMP, 1, digest_algorithm, c"digestAlgorithm", X509_ALGOR_it;
    SIMPLE, 0, encap, c"encapContentInfo", encapsulated_content_info_it;
    IMP_SET_OF_OPT, 2, auth_attrs, c"authAttrs", X509_ATTRIBUTE_it;
    SIMPLE, 0, mac, c"mac", ASN1_OCTET_STRING_it;
    IMP_SET_OF_OPT, 3, unauth_attrs, c"unauthAttrs", X509_ATTRIBUTE_it;
];

static CD_TT: Templates<3> = tt![CompressedData;
    EMBED, 0, version, c"version", INT32_it;
    SIMPLE, 0, compression_algorithm, c"compressionAlgorithm", X509_ALGOR_it;
    SIMPLE, 0, encap, c"encapContentInfo", encapsulated_content_info_it;
];

const D: usize = offset_of!(ContentInfo, d);

static CI_DEFAULT: Template = Template(template_at(EXP, 0, D, c"d.other", ASN1_ANY_it));

static CI_ADB_TBL: AdbEntries<8> = AdbEntries([
    adb_entry(
        NID_pkcs7_data,
        template_at(NDEF_EXP, 0, D, c"d.data", ASN1_OCTET_STRING_NDEF_it),
    ),
    adb_entry(
        NID_pkcs7_signed,
        template_at(NDEF_EXP, 0, D, c"d.signedData", signed_data_it),
    ),
    adb_entry(
        NID_pkcs7_enveloped,
        template_at(NDEF_EXP, 0, D, c"d.envelopedData", CMS_EnvelopedData_it),
    ),
    adb_entry(
        NID_pkcs7_digest,
        template_at(NDEF_EXP, 0, D, c"d.digestedData", digested_data_it),
    ),
    adb_entry(
        NID_pkcs7_encrypted,
        template_at(NDEF_EXP, 0, D, c"d.encryptedData", encrypted_data_it),
    ),
    adb_entry(
        NID_id_smime_ct_authEnvelopedData,
        template_at(
            NDEF_EXP,
            0,
            D,
            c"d.authEnvelopedData",
            auth_enveloped_data_it,
        ),
    ),
    adb_entry(
        NID_id_smime_ct_authData,
        template_at(
            NDEF_EXP,
            0,
            D,
            c"d.authenticatedData",
            authenticated_data_it,
        ),
    ),
    adb_entry(
        NID_id_smime_ct_compressedData,
        template_at(NDEF_EXP, 0, D, c"d.compressedData", compressed_data_it),
    ),
]);

static CI_ADB: Adb = adb_oid(
    offset_of!(ContentInfo, content_type),
    &CI_ADB_TBL,
    &CI_DEFAULT,
);

/// The ANY DEFINED BY table, as an ADB template's item function returns it.
unsafe extern "C" fn ci_adb() -> *const ASN1_ITEM {
    (&raw const CI_ADB.0).cast()
}

ffi_callback! {
    /// `cms_cb`: streaming and detached encoding through the content's data path, and the
    /// properties freed with the object.
    ///
    /// # Safety
    /// As the template engine and the streaming functions call it.
    pub(crate) unsafe extern "C" fn cms_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the value's slot, or NULL.
        let Some(&cms) = (unsafe { pval.cast::<*mut ContentInfo>().as_ref() }) else {
            return 1;
        };
        match operation {
            ASN1_OP_STREAM_PRE | ASN1_OP_DETACHED_PRE => {
                // SAFETY: the stream's arguments.
                let Some(sarg) = (unsafe { exarg.cast::<ASN1_STREAM_ARG>().as_mut() }) else {
                    return 0;
                };
                // SAFETY: the object; room for the boundary.
                if operation == ASN1_OP_STREAM_PRE && unsafe { io::CMS_stream(&mut sarg.boundary, cms.cast()) } <= 0 {
                    return 0;
                }
                // SAFETY: the object; the stream's output.
                sarg.ndef_bio = unsafe { base::CMS_dataInit(cms.cast(), sarg.out) };
                c_int::from(!sarg.ndef_bio.is_null())
            }
            ASN1_OP_STREAM_POST | ASN1_OP_DETACHED_POST => {
                // SAFETY: as above.
                let Some(sarg) = (unsafe { exarg.cast::<ASN1_STREAM_ARG>().as_ref() }) else {
                    return 0;
                };
                // SAFETY: the object and its chain.
                c_int::from(unsafe { base::CMS_dataFinal(cms.cast(), sarg.ndef_bio) } > 0)
            }
            ASN1_OP_FREE_POST => {
                // SAFETY: the object being freed.
                if let Some(c) = unsafe { cms.as_mut() } {
                    // SAFETY: its properties, from CRYPTO_malloc, or NULL.
                    unsafe { mem::release(c.ctx.propq.cast()) };
                    c.ctx.propq = ptr::null_mut();
                }
                1
            }
            _ => 1,
        }
    }
}

static CI_AUX: Aux = aux(cms_cb);

static CI_TT: Templates<2> = Templates([
    template_at(
        SIMPLE,
        0,
        offset_of!(ContentInfo, content_type),
        c"contentType",
        ASN1_OBJECT_it,
    ),
    adb_object(c"CMS_ContentInfo", ci_adb),
]);

static ATTR_SIGN: Template = template(ASN1_TFLG_SET_ORDER, 0, c"CMS_ATTRIBUTES", X509_ATTRIBUTE_it);
static ATTR_VERIFY: Template = template(
    ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_IMPTAG | ASN1_TFLG_UNIVERSAL,
    V_ASN1_SET as c_long,
    c"CMS_ATTRIBUTES",
    X509_ATTRIBUTE_it,
);

static RF_TT: Templates<2> = tt![ReceiptsFrom;
    IMP_EMBED, 0, d, c"d.allOrFirstTier", INT32_it;
    IMP_SEQ_OF, 1, d, c"d.receiptList", GENERAL_NAMES_it;
];

static RR_TT: Templates<3> = tt![ReceiptRequest;
    SIMPLE, 0, signed_content_identifier, c"signedContentIdentifier", ASN1_OCTET_STRING_it;
    SIMPLE, 0, receipts_from, c"receiptsFrom", receipts_from_it;
    SEQ_OF, 0, receipts_to, c"receiptsTo", GENERAL_NAMES_it;
];

static RCT_TT: Templates<4> = tt![Receipt;
    EMBED, 0, version, c"version", INT32_it;
    SIMPLE, 0, content_type, c"contentType", ASN1_OBJECT_it;
    SIMPLE, 0, signed_content_identifier, c"signedContentIdentifier", ASN1_OCTET_STRING_it;
    SIMPLE, 0, originator_signature_value, c"originatorSignatureValue", ASN1_OCTET_STRING_it;
];

static SHI_TT: Templates<3> = tt![SharedInfo;
    SIMPLE, 0, key_info, c"keyInfo", X509_ALGOR_it;
    EXP_OPT, 0, entity_u_info, c"entityUInfo", ASN1_OCTET_STRING_it;
    EXP_OPT, 2, supp_pub_info, c"suppPubInfo", ASN1_OCTET_STRING_it;
];

private_item! {
    fn other_certificate_format_it = sequence::<OtherCertificateFormat, 2>(&OCF_TT, None, c"CMS_OtherCertificateFormat");
    fn certificate_choices_it = choice::<CertificateChoices, 5>(&CC_TT, offset_of!(CertificateChoices, type_), None, c"CMS_CertificateChoices");
    fn signer_identifier_it = choice::<SignerIdentifier, 2>(&SID_TT, offset_of!(SignerIdentifier, type_), None, c"CMS_SignerIdentifier");
    fn encapsulated_content_info_it = ndef_sequence::<EncapContentInfo, 2>(&ECI_TT, None, c"CMS_EncapsulatedContentInfo");
    fn other_revocation_info_format_it = sequence::<OtherRevocationInfoFormat, 2>(&ORIF_TT, None, c"CMS_OtherRevocationInfoFormat");
    fn revocation_info_choice_it = choice::<RevocationInfoChoice, 2>(&RIC_TT, offset_of!(RevocationInfoChoice, type_), None, c"CMS_RevocationInfoChoice");
    fn originator_info_it = sequence::<OriginatorInfo, 2>(&OI_TT, None, c"CMS_OriginatorInfo");
    fn key_trans_recipient_info_it = sequence::<KeyTransRecipientInfo, 4>(&KTRI_TT, None, c"CMS_KeyTransRecipientInfo");
    fn other_key_attribute_it = sequence::<OtherKeyAttribute, 2>(&OKA_TT, None, c"CMS_OtherKeyAttribute");
    fn recipient_key_identifier_it = sequence::<RecipientKeyIdentifier, 3>(&RKID_TT, None, c"CMS_RecipientKeyIdentifier");
    fn key_agree_recipient_identifier_it = choice::<KeyAgreeRecipientIdentifier, 2>(&KARID_TT, offset_of!(KeyAgreeRecipientIdentifier, type_), None, c"CMS_KeyAgreeRecipientIdentifier");
    fn recipient_encrypted_key_it = sequence::<RecipientEncryptedKey, 2>(&REK_TT, Some(&REK_AUX), c"CMS_RecipientEncryptedKey");
    fn originator_public_key_it = sequence::<OriginatorPublicKey, 2>(&OPK_TT, None, c"CMS_OriginatorPublicKey");
    fn originator_identifier_or_key_it = choice::<OriginatorIdentifierOrKey, 3>(&OIK_TT, offset_of!(OriginatorIdentifierOrKey, type_), None, c"CMS_OriginatorIdentifierOrKey");
    fn key_agree_recipient_info_it = sequence::<KeyAgreeRecipientInfo, 5>(&KARI_TT, Some(&KARI_AUX), c"CMS_KeyAgreeRecipientInfo");
    fn kek_identifier_it = sequence::<KekIdentifier, 3>(&KEKID_TT, None, c"CMS_KEKIdentifier");
    fn kek_recipient_info_it = sequence::<KekRecipientInfo, 4>(&KEKRI_TT, None, c"CMS_KEKRecipientInfo");
    fn other_recipient_info_it = sequence::<OtherRecipientInfo, 2>(&ORI_TT, None, c"CMS_OtherRecipientInfo");
    fn digested_data_it = ndef_sequence::<DigestedData, 4>(&DD_TT, None, c"CMS_DigestedData");
    fn encrypted_data_it = ndef_sequence::<EncryptedData, 3>(&ENCD_TT, None, c"CMS_EncryptedData");
    fn auth_enveloped_data_it = ndef_sequence::<AuthEnvelopedData, 7>(&AED_TT, None, c"CMS_AuthEnvelopedData");
    fn authenticated_data_it = ndef_sequence::<AuthenticatedData, 9>(&AD_TT, None, c"CMS_AuthenticatedData");
    fn compressed_data_it = ndef_sequence::<CompressedData, 3>(&CD_TT, None, c"CMS_CompressedData");
    fn receipts_from_it = choice::<ReceiptsFrom, 2>(&RF_TT, offset_of!(ReceiptsFrom, type_), None, c"CMS_ReceiptsFrom");
    fn receipt_it = sequence::<Receipt, 4>(&RCT_TT, None, c"CMS_Receipt");
    fn shared_info_it = sequence::<SharedInfo, 3>(&SHI_TT, None, c"CMS_SharedInfo");
    /// `CMS_IssuerAndSerialNumber_it`, which OpenSSL doesn't export.
    fn ias_it = sequence::<IssuerAndSerialNumber, 2>(&IAS_TT, None, c"CMS_IssuerAndSerialNumber");
    /// `CMS_SignerInfo_it`, which OpenSSL doesn't export.
    fn signer_info_it = sequence::<SignerInfo, 7>(&SI_TT, Some(&SI_AUX), c"CMS_SignerInfo");
    /// `CMS_SignedData_it`, which OpenSSL doesn't export.
    fn signed_data_it = ndef_sequence::<SignedData, 6>(&SD_TT, None, c"CMS_SignedData");
    /// `CMS_EncryptedContentInfo_it`, which OpenSSL doesn't export.
    fn encrypted_content_info_it = ndef_sequence::<EncryptedContentInfo, 3>(&ECINFO_TT, Some(&EC_AUX), c"CMS_EncryptedContentInfo");
    /// `CMS_RecipientInfo_it`, which OpenSSL doesn't export.
    fn recipient_info_it = choice::<RecipientInfo, 5>(&RI_TT, offset_of!(RecipientInfo, type_), Some(&RI_AUX), c"CMS_RecipientInfo");
    /// `CMS_PasswordRecipientInfo_it`, which OpenSSL doesn't export.
    fn password_recipient_info_it = sequence::<PasswordRecipientInfo, 4>(&PWRI_TT, None, c"CMS_PasswordRecipientInfo");
    /// `CMS_Attributes_Sign_it`: signed attributes as a SET OF, sorted.
    fn attributes_sign_it = item(ASN1_ITYPE_PRIMITIVE, -1, (&raw const ATTR_SIGN.0).cast(), 0, ptr::null(), 0, c"CMS_Attributes_Sign");
    /// `CMS_Attributes_Verify_it`: signed attributes as received, tagged as a SET.
    fn attributes_verify_it = item(ASN1_ITYPE_PRIMITIVE, -1, (&raw const ATTR_VERIFY.0).cast(), 0, ptr::null(), 0, c"CMS_Attributes_Verify");
}

item_fns! {
    /// ContentInfo: SEQUENCE { contentType, content [0] EXPLICIT ANY DEFINED BY contentType }.
    pub unsafe extern "C" fn CMS_ContentInfo_it = ndef_sequence::<ContentInfo, 2>(&CI_TT, Some(&CI_AUX), c"CMS_ContentInfo");
    /// EnvelopedData.
    pub unsafe extern "C" fn CMS_EnvelopedData_it = ndef_sequence::<EnvelopedData, 5>(&ED_TT, None, c"CMS_EnvelopedData");
    /// ReceiptRequest (RFC 2634).
    pub unsafe extern "C" fn CMS_ReceiptRequest_it = sequence::<ReceiptRequest, 3>(&RR_TT, None, c"CMS_ReceiptRequest");
}
