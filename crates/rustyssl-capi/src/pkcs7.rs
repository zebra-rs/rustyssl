//! PKCS#7 (`crypto/pkcs7`, RFC 2315): the content types and their ASN.1 (`pk7_asn1.c`), building
//! and reading them (`pk7_lib.c`), signer attributes (`pk7_attr.c` and `pk7_doit.c`'s), and their
//! DER, PEM, BIO, and `FILE` forms.
//!
//! The structures are public in `pkcs7.h`; their layouts are OpenSSL's. Signing, verifying,
//! encrypting, and decrypting are in [`doit`] and [`smime`], streaming and S/MIME in [`mime`]. A
//! NULL object, which OpenSSL reads through, fails (docs/DEVIATIONS.md).

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::mem::offset_of;
use core::ptr;

use libc::FILE;
use rustyssl_abi::{
    ASN1_INTEGER, ASN1_ITEM, ASN1_ITYPE_NDEF_SEQUENCE, ASN1_ITYPE_PRIMITIVE, ASN1_OBJECT,
    ASN1_OCTET_STRING, ASN1_OP_DETACHED_POST, ASN1_OP_DETACHED_PRE, ASN1_OP_FREE_POST,
    ASN1_OP_STREAM_POST, ASN1_OP_STREAM_PRE, ASN1_PCTX, ASN1_PKEY_CTRL_PKCS7_ENCRYPT,
    ASN1_PKEY_CTRL_PKCS7_SIGN, ASN1_STRING, ASN1_TFLG_EXPLICIT, ASN1_TFLG_IMPLICIT,
    ASN1_TFLG_IMPTAG, ASN1_TFLG_NDEF, ASN1_TFLG_OPTIONAL, ASN1_TFLG_SEQUENCE_OF, ASN1_TFLG_SET_OF,
    ASN1_TFLG_SET_ORDER, ASN1_TFLG_UNIVERSAL, ASN1_TIME, ASN1_TYPE, ASN1_VALUE, BIO, ERR_LIB_ASN1,
    ERR_LIB_PKCS7, ERR_R_ASN1_LIB, ERR_R_CRYPTO_LIB, ERR_R_X509_LIB, EVP_CIPHER, EVP_MD, EVP_PKEY,
    NID_SMIMECapabilities, NID_pkcs7_data, NID_pkcs7_digest, NID_pkcs7_encrypted,
    NID_pkcs7_enveloped, NID_pkcs7_signed, NID_pkcs7_signedAndEnveloped, NID_pkcs9_contentType,
    NID_pkcs9_messageDigest, NID_pkcs9_signingTime, NID_rsaEncryption, NID_undef, OSSL_LIB_CTX,
    PKCS7, PKCS7_CTX, PKCS7_DIGEST, PKCS7_ENC_CONTENT, PKCS7_ENCRYPT, PKCS7_ENVELOPE,
    PKCS7_ISSUER_AND_SERIAL, PKCS7_OP_GET_DETACHED_SIGNATURE, PKCS7_OP_SET_DETACHED_SIGNATURE,
    PKCS7_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER, PKCS7_R_ENCRYPTION_CTRL_FAILURE,
    PKCS7_R_ENCRYPTION_NOT_SUPPORTED_FOR_THIS_KEY_TYPE, PKCS7_R_NO_CONTENT,
    PKCS7_R_NO_DEFAULT_DIGEST, PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE,
    PKCS7_R_SIGNING_CTRL_FAILURE, PKCS7_R_SIGNING_NOT_SUPPORTED_FOR_THIS_KEY_TYPE,
    PKCS7_R_UNKNOWN_OPERATION, PKCS7_R_UNSUPPORTED_CONTENT_TYPE, PKCS7_R_WRONG_CONTENT_TYPE,
    PKCS7_RECIP_INFO, PKCS7_SIGN_ENVELOPE, PKCS7_SIGNED, PKCS7_SIGNER_INFO, V_ASN1_NULL,
    V_ASN1_OBJECT, V_ASN1_OCTET_STRING, V_ASN1_SEQUENCE, V_ASN1_SET, V_ASN1_UNDEF, V_ASN1_UTCTIME,
    X509, X509_ADD_FLAG_UP_REF, X509_ALGOR, X509_ATTRIBUTE, X509_CRL, stack_st_PKCS7_SIGNER_INFO,
    stack_st_X509, stack_st_X509_ALGOR, stack_st_X509_ATTRIBUTE,
};

use crate::asn1::integer::{ASN1_INTEGER_dup, ASN1_INTEGER_set};
use crate::asn1::string::{
    ASN1_INTEGER_free, ASN1_INTEGER_new, ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new,
    ASN1_STRING_free, ASN1_STRING_new, ASN1_STRING_set,
};
use crate::asn1::tpl::io::{
    ASN1_item_d2i_bio_ex, ASN1_item_d2i_fp_ex, ASN1_item_i2d_bio, ASN1_item_i2d_fp,
};
use crate::asn1::tpl::items::{
    ASN1_ANY_it, ASN1_INTEGER_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_NDEF_it, ASN1_OCTET_STRING_it,
    ASN1_TYPE_new, d2i, i2d, new_free,
};
use crate::asn1::tpl::items::{ASN1_TIME_free, X509_ALGOR_free, X509_ALGOR_it, X509_ALGOR_new};
use crate::asn1::tpl::statics::{AdbEntries, Aux, Templates, adb_entry, adb_object, adb_oid, aux};
use crate::asn1::tpl::{Item, Template, item, item_fns, size_of_long, template, template_at};
use crate::asn1::tpl::{
    decode::ASN1_item_d2i_ex, encode::ASN1_item_i2d, encode::ASN1_item_ndef_i2d,
    free::ASN1_item_free, new::ASN1_item_new_ex, print::ASN1_item_print, util::ASN1_item_dup,
};
use crate::err;
use crate::evp::pkey::{
    EVP_PKEY_free, EVP_PKEY_get_default_digest_nid, EVP_PKEY_is_a, EVP_PKEY_up_ref,
};
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::objects::{OBJ_cmp, OBJ_dup, OBJ_nid2obj, OBJ_obj2nid};
use crate::stack::{
    OPENSSL_sk_deep_copy, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop, OPENSSL_sk_pop_free,
    OPENSSL_sk_push, OPENSSL_sk_set, OPENSSL_sk_value,
};
use crate::string::CRYPTO_strdup;
use crate::x509::algor::{X509_ALGOR_set0, X509_ALGORS_it};
use crate::x509::attrib::{
    X509_ATTRIBUTE_create, X509_ATTRIBUTE_dup, X509_ATTRIBUTE_free, X509_ATTRIBUTE_get0_object,
    X509_ATTRIBUTE_get0_type, X509_ATTRIBUTE_it, X509at_get_attr, X509at_get_attr_by_NID,
};
use crate::x509::cert::{
    X509_find_by_issuer_and_serial, X509_free, X509_get_issuer_name, X509_get0_pubkey,
    X509_get0_serialNumber, X509_gmtime_adj, X509_it, X509_up_ref, cert_of, set0_libctx,
};
use crate::x509::crl::{X509_CRL_free, X509_CRL_it, X509_CRL_up_ref};
use crate::x509::name::{X509_NAME_it, X509_NAME_set};
use crate::x509::purpose::X509_add_cert;

pub(crate) mod doit;
pub(crate) mod mime;
pub(crate) mod smime;

/// `OBJ_nid2obj`: the NID's static object, or NULL.
fn nid_obj(nid: c_int) -> *mut ASN1_OBJECT {
    // SAFETY: any NID; an unknown one gives NULL.
    unsafe { OBJ_nid2obj(nid) }
}

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_PKCS7, reason, f);
}

// The ASN.1 (`pk7_asn1.c`).

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

const SIMPLE: c_int = 0;
const EXP_OPT: c_int = ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL;
const NDEF_EXP_OPT: c_int = EXP_OPT | ASN1_TFLG_NDEF;
const IMP_SEQ_OF_OPT: c_int = ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL;
const IMP_SET_OF_OPT: c_int = ASN1_TFLG_SET_OF | ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL;
const IMP_OPT: c_int = ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL;

const D: usize = offset_of!(PKCS7, d);

static P7_DEFAULT: Template = Template(template_at(EXP_OPT, 0, D, c"d.other", ASN1_ANY_it));

static P7_ADB_TBL: AdbEntries<6> = AdbEntries([
    adb_entry(
        NID_pkcs7_data,
        template_at(NDEF_EXP_OPT, 0, D, c"d.data", ASN1_OCTET_STRING_NDEF_it),
    ),
    adb_entry(
        NID_pkcs7_signed,
        template_at(NDEF_EXP_OPT, 0, D, c"d.sign", PKCS7_SIGNED_it),
    ),
    adb_entry(
        NID_pkcs7_enveloped,
        template_at(NDEF_EXP_OPT, 0, D, c"d.enveloped", PKCS7_ENVELOPE_it),
    ),
    adb_entry(
        NID_pkcs7_signedAndEnveloped,
        template_at(
            NDEF_EXP_OPT,
            0,
            D,
            c"d.signed_and_enveloped",
            PKCS7_SIGN_ENVELOPE_it,
        ),
    ),
    adb_entry(
        NID_pkcs7_digest,
        template_at(NDEF_EXP_OPT, 0, D, c"d.digest", PKCS7_DIGEST_it),
    ),
    adb_entry(
        NID_pkcs7_encrypted,
        template_at(NDEF_EXP_OPT, 0, D, c"d.encrypted", PKCS7_ENCRYPT_it),
    ),
]);

static P7_ADB: crate::asn1::tpl::statics::Adb =
    adb_oid(offset_of!(PKCS7, type_), &P7_ADB_TBL, &P7_DEFAULT);

/// The ANY DEFINED BY table, as an ADB template's item function returns it.
unsafe extern "C" fn p7_adb() -> *const ASN1_ITEM {
    (&raw const P7_ADB.0).cast()
}

ffi_callback! {
    /// `pk7_cb`: streaming and detached encoding, through the object's data path.
    ///
    /// # Safety
    /// As the template engine and the streaming functions call it.
    pub(crate) unsafe extern "C" fn pk7_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        let streaming = [ASN1_OP_STREAM_PRE, ASN1_OP_DETACHED_PRE, ASN1_OP_STREAM_POST, ASN1_OP_DETACHED_POST];
        if !streaming.contains(&operation) {
            return 1;
        }
        // SAFETY: the stream's arguments, as the streaming functions pass them.
        let Some(sarg) = (unsafe { exarg.cast::<rustyssl_abi::ASN1_STREAM_ARG>().as_mut() }) else {
            return 0;
        };
        // SAFETY: the slot of the value being streamed.
        let Some(&p7) = (unsafe { pval.cast::<*mut PKCS7>().as_ref() }) else {
            return 0;
        };
        if operation == ASN1_OP_STREAM_POST || operation == ASN1_OP_DETACHED_POST {
            // SAFETY: the object and the chain its data path made.
            return c_int::from(unsafe { doit::PKCS7_dataFinal(p7, sarg.ndef_bio) } > 0);
        }
        // SAFETY: the object; room for the boundary.
        if operation == ASN1_OP_STREAM_PRE && unsafe { mime::PKCS7_stream(&mut sarg.boundary, p7) } <= 0 {
            return 0;
        }
        // SAFETY: the object; the stream's output.
        sarg.ndef_bio = unsafe { doit::PKCS7_dataInit(p7, sarg.out) };
        c_int::from(!sarg.ndef_bio.is_null())
    }
}

static P7_AUX: Aux = aux(pk7_cb);

static P7_TT: Templates<2> = Templates([
    template_at(SIMPLE, 0, offset_of!(PKCS7, type_), c"type", ASN1_OBJECT_it),
    adb_object(c"PKCS7", p7_adb),
]);

item_fns! {
    /// ContentInfo: SEQUENCE { contentType, content [0] EXPLICIT ANY DEFINED BY contentType
    /// OPTIONAL }.
    pub unsafe extern "C" fn PKCS7_it = ndef_sequence::<PKCS7, 2>(&P7_TT, Some(&P7_AUX), c"PKCS7");
}

static SIGNED_TT: Templates<6> = Templates([
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_SIGNED, version),
        c"version",
        ASN1_INTEGER_it,
    ),
    template_at(
        ASN1_TFLG_SET_OF,
        0,
        offset_of!(PKCS7_SIGNED, md_algs),
        c"md_algs",
        X509_ALGOR_it,
    ),
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_SIGNED, contents),
        c"contents",
        PKCS7_it,
    ),
    template_at(
        IMP_SEQ_OF_OPT,
        0,
        offset_of!(PKCS7_SIGNED, cert),
        c"cert",
        X509_it,
    ),
    template_at(
        IMP_SET_OF_OPT,
        1,
        offset_of!(PKCS7_SIGNED, crl),
        c"crl",
        X509_CRL_it,
    ),
    template_at(
        ASN1_TFLG_SET_OF,
        0,
        offset_of!(PKCS7_SIGNED, signer_info),
        c"signer_info",
        PKCS7_SIGNER_INFO_it,
    ),
]);

item_fns! {
    /// SignedData.
    pub unsafe extern "C" fn PKCS7_SIGNED_it = ndef_sequence::<PKCS7_SIGNED, 6>(&SIGNED_TT, None, c"PKCS7_SIGNED");
}

ffi_callback! {
    /// `si_cb`: freeing a signer info frees its key.
    ///
    /// # Safety
    /// As the template engine calls it.
    pub(crate) unsafe extern "C" fn si_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, _exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        if operation == ASN1_OP_FREE_POST {
            // SAFETY: the engine's signer info.
            let v = unsafe { pval.read() }.cast::<PKCS7_SIGNER_INFO>();
            // SAFETY: as above.
            if let Some(si) = unsafe { v.as_mut() } {
                // SAFETY: its own key reference, or NULL.
                unsafe { EVP_PKEY_free(si.pkey) };
                si.pkey = ptr::null_mut();
            }
        }
        1
    }
}

static SI_AUX: Aux = aux(si_cb);

static SI_TT: Templates<7> = Templates([
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_SIGNER_INFO, version),
        c"version",
        ASN1_INTEGER_it,
    ),
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_SIGNER_INFO, issuer_and_serial),
        c"issuer_and_serial",
        PKCS7_ISSUER_AND_SERIAL_it,
    ),
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_SIGNER_INFO, digest_alg),
        c"digest_alg",
        X509_ALGOR_it,
    ),
    template_at(
        IMP_SEQ_OF_OPT,
        0,
        offset_of!(PKCS7_SIGNER_INFO, auth_attr),
        c"auth_attr",
        X509_ATTRIBUTE_it,
    ),
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_SIGNER_INFO, digest_enc_alg),
        c"digest_enc_alg",
        X509_ALGOR_it,
    ),
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_SIGNER_INFO, enc_digest),
        c"enc_digest",
        ASN1_OCTET_STRING_it,
    ),
    template_at(
        IMP_SET_OF_OPT,
        1,
        offset_of!(PKCS7_SIGNER_INFO, unauth_attr),
        c"unauth_attr",
        X509_ATTRIBUTE_it,
    ),
]);

item_fns! {
    /// SignerInfo.
    pub unsafe extern "C" fn PKCS7_SIGNER_INFO_it = crate::asn1::tpl::statics::sequence::<PKCS7_SIGNER_INFO, 7>(&SI_TT, Some(&SI_AUX), c"PKCS7_SIGNER_INFO");
}

static IAS_TT: Templates<2> = Templates([
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_ISSUER_AND_SERIAL, issuer),
        c"issuer",
        X509_NAME_it,
    ),
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_ISSUER_AND_SERIAL, serial),
        c"serial",
        ASN1_INTEGER_it,
    ),
]);

item_fns! {
    /// IssuerAndSerialNumber.
    pub unsafe extern "C" fn PKCS7_ISSUER_AND_SERIAL_it = crate::asn1::tpl::statics::sequence::<PKCS7_ISSUER_AND_SERIAL, 2>(&IAS_TT, None, c"PKCS7_ISSUER_AND_SERIAL");
}

static ENVELOPE_TT: Templates<3> = Templates([
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_ENVELOPE, version),
        c"version",
        ASN1_INTEGER_it,
    ),
    template_at(
        ASN1_TFLG_SET_OF,
        0,
        offset_of!(PKCS7_ENVELOPE, recipientinfo),
        c"recipientinfo",
        PKCS7_RECIP_INFO_it,
    ),
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_ENVELOPE, enc_data),
        c"enc_data",
        PKCS7_ENC_CONTENT_it,
    ),
]);

item_fns! {
    /// EnvelopedData.
    pub unsafe extern "C" fn PKCS7_ENVELOPE_it = ndef_sequence::<PKCS7_ENVELOPE, 3>(&ENVELOPE_TT, None, c"PKCS7_ENVELOPE");
}

ffi_callback! {
    /// `ri_cb`: freeing a recipient info frees its certificate.
    ///
    /// # Safety
    /// As the template engine calls it.
    pub(crate) unsafe extern "C" fn ri_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, _exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        if operation == ASN1_OP_FREE_POST {
            // SAFETY: the engine's recipient info.
            let v = unsafe { pval.read() }.cast::<PKCS7_RECIP_INFO>();
            // SAFETY: as above.
            if let Some(ri) = unsafe { v.as_mut() } {
                // SAFETY: its own certificate reference, or NULL.
                unsafe { X509_free(ri.cert) };
                ri.cert = ptr::null_mut();
            }
        }
        1
    }
}

static RI_AUX: Aux = aux(ri_cb);

static RI_TT: Templates<4> = Templates([
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_RECIP_INFO, version),
        c"version",
        ASN1_INTEGER_it,
    ),
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_RECIP_INFO, issuer_and_serial),
        c"issuer_and_serial",
        PKCS7_ISSUER_AND_SERIAL_it,
    ),
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_RECIP_INFO, key_enc_algor),
        c"key_enc_algor",
        X509_ALGOR_it,
    ),
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_RECIP_INFO, enc_key),
        c"enc_key",
        ASN1_OCTET_STRING_it,
    ),
]);

item_fns! {
    /// RecipientInfo.
    pub unsafe extern "C" fn PKCS7_RECIP_INFO_it = crate::asn1::tpl::statics::sequence::<PKCS7_RECIP_INFO, 4>(&RI_TT, Some(&RI_AUX), c"PKCS7_RECIP_INFO");
}

static ENC_CONTENT_TT: Templates<3> = Templates([
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_ENC_CONTENT, content_type),
        c"content_type",
        ASN1_OBJECT_it,
    ),
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_ENC_CONTENT, algorithm),
        c"algorithm",
        X509_ALGOR_it,
    ),
    template_at(
        IMP_OPT,
        0,
        offset_of!(PKCS7_ENC_CONTENT, enc_data),
        c"enc_data",
        ASN1_OCTET_STRING_NDEF_it,
    ),
]);

item_fns! {
    /// EncryptedContentInfo.
    pub unsafe extern "C" fn PKCS7_ENC_CONTENT_it = ndef_sequence::<PKCS7_ENC_CONTENT, 3>(&ENC_CONTENT_TT, None, c"PKCS7_ENC_CONTENT");
}

static SIGN_ENVELOPE_TT: Templates<7> = Templates([
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_SIGN_ENVELOPE, version),
        c"version",
        ASN1_INTEGER_it,
    ),
    template_at(
        ASN1_TFLG_SET_OF,
        0,
        offset_of!(PKCS7_SIGN_ENVELOPE, recipientinfo),
        c"recipientinfo",
        PKCS7_RECIP_INFO_it,
    ),
    template_at(
        ASN1_TFLG_SET_OF,
        0,
        offset_of!(PKCS7_SIGN_ENVELOPE, md_algs),
        c"md_algs",
        X509_ALGOR_it,
    ),
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_SIGN_ENVELOPE, enc_data),
        c"enc_data",
        PKCS7_ENC_CONTENT_it,
    ),
    template_at(
        IMP_SET_OF_OPT,
        0,
        offset_of!(PKCS7_SIGN_ENVELOPE, cert),
        c"cert",
        X509_it,
    ),
    template_at(
        IMP_SET_OF_OPT,
        1,
        offset_of!(PKCS7_SIGN_ENVELOPE, crl),
        c"crl",
        X509_CRL_it,
    ),
    template_at(
        ASN1_TFLG_SET_OF,
        0,
        offset_of!(PKCS7_SIGN_ENVELOPE, signer_info),
        c"signer_info",
        PKCS7_SIGNER_INFO_it,
    ),
]);

item_fns! {
    /// SignedAndEnvelopedData.
    pub unsafe extern "C" fn PKCS7_SIGN_ENVELOPE_it = ndef_sequence::<PKCS7_SIGN_ENVELOPE, 7>(&SIGN_ENVELOPE_TT, None, c"PKCS7_SIGN_ENVELOPE");
}

static ENCRYPT_TT: Templates<2> = Templates([
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_ENCRYPT, version),
        c"version",
        ASN1_INTEGER_it,
    ),
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_ENCRYPT, enc_data),
        c"enc_data",
        PKCS7_ENC_CONTENT_it,
    ),
]);

item_fns! {
    /// EncryptedData.
    pub unsafe extern "C" fn PKCS7_ENCRYPT_it = ndef_sequence::<PKCS7_ENCRYPT, 2>(&ENCRYPT_TT, None, c"PKCS7_ENCRYPT");
}

static DIGEST_TT: Templates<4> = Templates([
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_DIGEST, version),
        c"version",
        ASN1_INTEGER_it,
    ),
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_DIGEST, md),
        c"md",
        X509_ALGOR_it,
    ),
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_DIGEST, contents),
        c"contents",
        PKCS7_it,
    ),
    template_at(
        SIMPLE,
        0,
        offset_of!(PKCS7_DIGEST, digest),
        c"digest",
        ASN1_OCTET_STRING_it,
    ),
]);

item_fns! {
    /// DigestedData.
    pub unsafe extern "C" fn PKCS7_DIGEST_it = ndef_sequence::<PKCS7_DIGEST, 4>(&DIGEST_TT, None, c"PKCS7_DIGEST");
}

static ATTR_SIGN: Template = template(
    ASN1_TFLG_SET_ORDER,
    0,
    c"PKCS7_ATTRIBUTES",
    X509_ATTRIBUTE_it,
);
static ATTR_VERIFY: Template = template(
    ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_IMPTAG | ASN1_TFLG_UNIVERSAL,
    V_ASN1_SET as c_long,
    c"PKCS7_ATTRIBUTES",
    X509_ATTRIBUTE_it,
);

item_fns! {
    /// Signed attributes as they're signed: a SET OF in DER order.
    pub unsafe extern "C" fn PKCS7_ATTR_SIGN_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const ATTR_SIGN.0, 0, ptr::null(), 0, c"PKCS7_ATTR_SIGN");
}

item_fns! {
    /// Signed attributes as they're verified: their order kept, tagged as a SET.
    pub unsafe extern "C" fn PKCS7_ATTR_VERIFY_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const ATTR_VERIFY.0, 0, ptr::null(), 0, c"PKCS7_ATTR_VERIFY");
}

new_free! {
    pub unsafe extern "C" fn PKCS7_SIGNED_new, pub unsafe extern "C" fn PKCS7_SIGNED_free(PKCS7_SIGNED) = PKCS7_SIGNED_it;
}
new_free! {
    pub unsafe extern "C" fn PKCS7_SIGNER_INFO_new, pub unsafe extern "C" fn PKCS7_SIGNER_INFO_free(PKCS7_SIGNER_INFO) = PKCS7_SIGNER_INFO_it;
}
new_free! {
    pub unsafe extern "C" fn PKCS7_ISSUER_AND_SERIAL_new, pub unsafe extern "C" fn PKCS7_ISSUER_AND_SERIAL_free(PKCS7_ISSUER_AND_SERIAL) = PKCS7_ISSUER_AND_SERIAL_it;
}
new_free! {
    pub unsafe extern "C" fn PKCS7_ENVELOPE_new, pub unsafe extern "C" fn PKCS7_ENVELOPE_free(PKCS7_ENVELOPE) = PKCS7_ENVELOPE_it;
}
new_free! {
    pub unsafe extern "C" fn PKCS7_RECIP_INFO_new, pub unsafe extern "C" fn PKCS7_RECIP_INFO_free(PKCS7_RECIP_INFO) = PKCS7_RECIP_INFO_it;
}
new_free! {
    pub unsafe extern "C" fn PKCS7_ENC_CONTENT_new, pub unsafe extern "C" fn PKCS7_ENC_CONTENT_free(PKCS7_ENC_CONTENT) = PKCS7_ENC_CONTENT_it;
}
new_free! {
    pub unsafe extern "C" fn PKCS7_SIGN_ENVELOPE_new, pub unsafe extern "C" fn PKCS7_SIGN_ENVELOPE_free(PKCS7_SIGN_ENVELOPE) = PKCS7_SIGN_ENVELOPE_it;
}
new_free! {
    pub unsafe extern "C" fn PKCS7_ENCRYPT_new, pub unsafe extern "C" fn PKCS7_ENCRYPT_free(PKCS7_ENCRYPT) = PKCS7_ENCRYPT_it;
}
new_free! {
    pub unsafe extern "C" fn PKCS7_DIGEST_new, pub unsafe extern "C" fn PKCS7_DIGEST_free(PKCS7_DIGEST) = PKCS7_DIGEST_it;
}

i2d! {
    /// Encodes SignedData.
    pub unsafe extern "C" fn i2d_PKCS7_SIGNED(PKCS7_SIGNED) = PKCS7_SIGNED_it;
}
d2i! {
    /// Decodes SignedData.
    pub unsafe extern "C" fn d2i_PKCS7_SIGNED(PKCS7_SIGNED) = PKCS7_SIGNED_it;
}
i2d! {
    /// Encodes a SignerInfo.
    pub unsafe extern "C" fn i2d_PKCS7_SIGNER_INFO(PKCS7_SIGNER_INFO) = PKCS7_SIGNER_INFO_it;
}
d2i! {
    /// Decodes a SignerInfo.
    pub unsafe extern "C" fn d2i_PKCS7_SIGNER_INFO(PKCS7_SIGNER_INFO) = PKCS7_SIGNER_INFO_it;
}
i2d! {
    /// Encodes an IssuerAndSerialNumber.
    pub unsafe extern "C" fn i2d_PKCS7_ISSUER_AND_SERIAL(PKCS7_ISSUER_AND_SERIAL) = PKCS7_ISSUER_AND_SERIAL_it;
}
d2i! {
    /// Decodes an IssuerAndSerialNumber.
    pub unsafe extern "C" fn d2i_PKCS7_ISSUER_AND_SERIAL(PKCS7_ISSUER_AND_SERIAL) = PKCS7_ISSUER_AND_SERIAL_it;
}
i2d! {
    /// Encodes EnvelopedData.
    pub unsafe extern "C" fn i2d_PKCS7_ENVELOPE(PKCS7_ENVELOPE) = PKCS7_ENVELOPE_it;
}
d2i! {
    /// Decodes EnvelopedData.
    pub unsafe extern "C" fn d2i_PKCS7_ENVELOPE(PKCS7_ENVELOPE) = PKCS7_ENVELOPE_it;
}
i2d! {
    /// Encodes a RecipientInfo.
    pub unsafe extern "C" fn i2d_PKCS7_RECIP_INFO(PKCS7_RECIP_INFO) = PKCS7_RECIP_INFO_it;
}
d2i! {
    /// Decodes a RecipientInfo.
    pub unsafe extern "C" fn d2i_PKCS7_RECIP_INFO(PKCS7_RECIP_INFO) = PKCS7_RECIP_INFO_it;
}
i2d! {
    /// Encodes an EncryptedContentInfo.
    pub unsafe extern "C" fn i2d_PKCS7_ENC_CONTENT(PKCS7_ENC_CONTENT) = PKCS7_ENC_CONTENT_it;
}
d2i! {
    /// Decodes an EncryptedContentInfo.
    pub unsafe extern "C" fn d2i_PKCS7_ENC_CONTENT(PKCS7_ENC_CONTENT) = PKCS7_ENC_CONTENT_it;
}
i2d! {
    /// Encodes SignedAndEnvelopedData.
    pub unsafe extern "C" fn i2d_PKCS7_SIGN_ENVELOPE(PKCS7_SIGN_ENVELOPE) = PKCS7_SIGN_ENVELOPE_it;
}
d2i! {
    /// Decodes SignedAndEnvelopedData.
    pub unsafe extern "C" fn d2i_PKCS7_SIGN_ENVELOPE(PKCS7_SIGN_ENVELOPE) = PKCS7_SIGN_ENVELOPE_it;
}
i2d! {
    /// Encodes EncryptedData.
    pub unsafe extern "C" fn i2d_PKCS7_ENCRYPT(PKCS7_ENCRYPT) = PKCS7_ENCRYPT_it;
}
d2i! {
    /// Decodes EncryptedData.
    pub unsafe extern "C" fn d2i_PKCS7_ENCRYPT(PKCS7_ENCRYPT) = PKCS7_ENCRYPT_it;
}
i2d! {
    /// Encodes DigestedData.
    pub unsafe extern "C" fn i2d_PKCS7_DIGEST(PKCS7_DIGEST) = PKCS7_DIGEST_it;
}
d2i! {
    /// Decodes DigestedData.
    pub unsafe extern "C" fn d2i_PKCS7_DIGEST(PKCS7_DIGEST) = PKCS7_DIGEST_it;
}

/// The library context and properties of a PKCS#7 object (`ossl_pkcs7_get0_ctx`), or NULL.
fn ctx_of(p7: *const PKCS7) -> *const PKCS7_CTX {
    if p7.is_null() {
        return ptr::null();
    }
    // SAFETY: a live PKCS#7 object's field.
    unsafe { &raw const (*p7).ctx }
}

/// `ossl_pkcs7_resolve_libctx`: the object's library context and properties into its
/// certificates, its recipients' certificates, and its signer infos.
///
/// # Safety
/// `p7` is a live PKCS#7 object.
pub(crate) unsafe fn resolve_libctx(p7: *mut PKCS7) {
    // SAFETY: the caller's guarantee.
    let Some(p) = (unsafe { p7.as_ref() }) else {
        return;
    };
    // SAFETY: a union's pointer.
    if content_ptr(p).is_null() {
        return;
    }
    let (libctx, propq) = (p.ctx.libctx, p.ctx.propq.cast_const());
    let ctx = ctx_of(p7);
    // SAFETY: as above.
    let certs = unsafe { certificates(p7) };
    // SAFETY: its certificates, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(certs.cast()) } {
        // SAFETY: an index within them.
        let x = unsafe { OPENSSL_sk_value(certs.cast(), i) }.cast::<X509>();
        // SAFETY: a certificate of the object.
        if let Some(c) = unsafe { cert_of(x) } {
            // SAFETY: the object's properties, or NULL.
            unsafe { set0_libctx(&mut c.libctx, &mut c.propq, libctx, propq) };
        }
    }
    // SAFETY: as above.
    let rinfos = unsafe { recipient_info(p7) };
    // SAFETY: its recipients, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(rinfos.cast()) } {
        // SAFETY: an index within them.
        let ri = unsafe { OPENSSL_sk_value(rinfos.cast(), i) }.cast::<PKCS7_RECIP_INFO>();
        // SAFETY: a recipient of the object, and its certificate, or NULL.
        if let Some(c) = unsafe { ri.as_ref() }.and_then(|r| unsafe { cert_of(r.cert) }) {
            // SAFETY: as above.
            unsafe { set0_libctx(&mut c.libctx, &mut c.propq, libctx, propq) };
        }
    }
    // SAFETY: as above.
    let sinfos = unsafe { PKCS7_get_signer_info(p7) };
    // SAFETY: its signer infos, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(sinfos.cast()) } {
        // SAFETY: an index within them.
        let si = unsafe { OPENSSL_sk_value(sinfos.cast(), i) }.cast::<PKCS7_SIGNER_INFO>();
        // SAFETY: a signer info of the object, or NULL.
        if let Some(s) = unsafe { si.as_mut() } {
            s.ctx = ctx;
        }
    }
}

ffi_export! {
    /// Decodes a PKCS#7 object, in `*a`'s library context if it holds one.
    ///
    /// # Safety
    /// As for `d2i_*`.
    pub unsafe extern "C" fn d2i_PKCS7(a: *mut *mut PKCS7, in_: *mut *const c_uchar, len: c_long) -> *mut PKCS7
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's slot, holding NULL or a live object.
        let (libctx, propq) = unsafe { held_ctx(a) };
        // SAFETY: no preconditions.
        let it = unsafe { PKCS7_it() };
        // SAFETY: the caller's guarantee; the type's item.
        let ret = unsafe { ASN1_item_d2i_ex(a.cast(), in_, len, it, libctx, propq) }.cast::<PKCS7>();
        if !ret.is_null() {
            // SAFETY: the object decoded.
            unsafe { resolve_libctx(ret) };
        }
        ret
    }
}

ffi_export! {
    /// Encodes a PKCS#7 object.
    ///
    /// # Safety
    /// As for `i2d_*`.
    pub unsafe extern "C" fn i2d_PKCS7(a: *const PKCS7, out: *mut *mut c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_PKCS7
    {
        // SAFETY: no preconditions.
        let it = unsafe { PKCS7_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_i2d(a.cast(), out, it) }
    }
}

ffi_export! {
    /// Encodes a PKCS#7 object with indefinite lengths where its type allows them.
    ///
    /// # Safety
    /// As for `i2d_*`.
    pub unsafe extern "C" fn i2d_PKCS7_NDEF(a: *const PKCS7, out: *mut *mut c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_PKCS7
    {
        // SAFETY: no preconditions.
        let it = unsafe { PKCS7_it() };
        // SAFETY: as above.
        unsafe { ASN1_item_ndef_i2d(a.cast(), out, it) }
    }
}

ffi_export! {
    /// A new, empty PKCS#7 object, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn PKCS7_new() -> *mut PKCS7
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        // SAFETY: no property query.
        unsafe { PKCS7_new_ex(ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// A new, empty PKCS#7 object in `libctx` with (a copy of) `propq`, or NULL.
    ///
    /// # Safety
    /// `propq` is NULL or a C string.
    pub unsafe extern "C" fn PKCS7_new_ex(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut PKCS7
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        // SAFETY: no preconditions.
        let it = unsafe { PKCS7_it() };
        // SAFETY: the type's item; the caller's properties.
        let p7 = unsafe { ASN1_item_new_ex(it, libctx, propq) }.cast::<PKCS7>();
        // SAFETY: new, or NULL.
        let Some(p) = (unsafe { p7.as_mut() }) else { return ptr::null_mut() };
        p.ctx.libctx = libctx;
        p.ctx.propq = ptr::null_mut();
        if !propq.is_null() {
            // SAFETY: as above.
            p.ctx.propq = unsafe { CRYPTO_strdup(propq, ptr::null(), 0) };
            if p.ctx.propq.is_null() {
                // SAFETY: made above.
                unsafe { PKCS7_free(p7) };
                return ptr::null_mut();
            }
        }
        p7
    }
}

ffi_export! {
    /// Frees a PKCS#7 object and its properties (nothing for NULL).
    ///
    /// # Safety
    /// `p7` is NULL or a PKCS#7 object not used after.
    pub unsafe extern "C" fn PKCS7_free(p7: *mut PKCS7)
    where failure = (), library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p7.as_mut() }) else { return };
        // SAFETY: its own copy, or NULL.
        unsafe { mem::release(p.ctx.propq.cast()) };
        p.ctx.propq = ptr::null_mut();
        // SAFETY: no preconditions.
        let it = unsafe { PKCS7_it() };
        // SAFETY: the object, of the type's item.
        unsafe { ASN1_item_free(p7.cast(), it) };
    }
}

ffi_export! {
    /// A copy of the PKCS#7 object (through its encoding), or NULL.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object.
    pub unsafe extern "C" fn PKCS7_dup(p7: *const PKCS7) -> *mut PKCS7
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        // SAFETY: no preconditions.
        let it = unsafe { PKCS7_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_dup(it, p7.cast()) }.cast()
    }
}

ffi_export! {
    /// Prints the object's structure, field by field (`ASN1_item_print`).
    ///
    /// # Safety
    /// `out` is a live BIO; `x` is NULL or a live PKCS#7 object; `pctx` is NULL or a live
    /// print context.
    pub unsafe extern "C" fn PKCS7_print_ctx(out: *mut BIO, x: *const PKCS7, indent: c_int, pctx: *const ASN1_PCTX) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        // SAFETY: no preconditions.
        let it = unsafe { PKCS7_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_print(out, x.cast(), indent, it, pctx) }
    }
}

ffi_export! {
    /// The digest of the IssuerAndSerialNumber's DER into `md` (its length in `*len`): 1, or 0.
    ///
    /// # Safety
    /// `data` is a live IssuerAndSerialNumber; `type_` a live digest; `md` has room for it.
    pub unsafe extern "C" fn PKCS7_ISSUER_AND_SERIAL_digest(data: *mut PKCS7_ISSUER_AND_SERIAL, type_: *const EVP_MD, md: *mut c_uchar, len: *mut c_uint) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        // SAFETY: no preconditions.
        let it = unsafe { PKCS7_ISSUER_AND_SERIAL_it() };
        // SAFETY: the caller's guarantee.
        unsafe { crate::asn1::tpl::util::ASN1_item_digest(it, type_, data.cast(), md, len) }
    }
}

// I/O (`x_all.c`, `pem_all.c`).

/// The library context and properties `*p7` holds, if any.
///
/// # Safety
/// `p7` is NULL or holds NULL or a live object.
unsafe fn held_ctx(p7: *mut *mut PKCS7) -> (*mut OSSL_LIB_CTX, *const c_char) {
    // SAFETY: the caller's guarantee.
    let held = unsafe { p7.as_ref() }.copied().unwrap_or(ptr::null_mut());
    // SAFETY: as above.
    unsafe { held.as_ref() }.map_or((ptr::null_mut(), ptr::null()), |p| {
        (p.ctx.libctx, p.ctx.propq.cast_const())
    })
}

ffi_export! {
    /// Decodes a PKCS#7 object from a BIO, in `*p7`'s library context if it holds one.
    ///
    /// # Safety
    /// `bp` is a live BIO; `p7` is NULL or holds NULL or a live object.
    pub unsafe extern "C" fn d2i_PKCS7_bio(bp: *mut BIO, p7: *mut *mut PKCS7) -> *mut PKCS7
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee.
        let (libctx, propq) = unsafe { held_ctx(p7) };
        // SAFETY: no preconditions.
        let it = unsafe { PKCS7_it() };
        // SAFETY: as above.
        let ret = unsafe { ASN1_item_d2i_bio_ex(it, bp, p7.cast(), libctx, propq) }.cast::<PKCS7>();
        if !ret.is_null() {
            // SAFETY: the object decoded.
            unsafe { resolve_libctx(ret) };
        }
        ret
    }
}

ffi_export! {
    /// Decodes a PKCS#7 object from a `FILE`, as `d2i_PKCS7_bio`.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `p7` is NULL or holds NULL or a live object.
    pub unsafe extern "C" fn d2i_PKCS7_fp(fp: *mut FILE, p7: *mut *mut PKCS7) -> *mut PKCS7
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee.
        let (libctx, propq) = unsafe { held_ctx(p7) };
        // SAFETY: no preconditions.
        let it = unsafe { PKCS7_it() };
        // SAFETY: as above.
        let ret = unsafe { ASN1_item_d2i_fp_ex(it, fp, p7.cast(), libctx, propq) }.cast::<PKCS7>();
        if !ret.is_null() {
            // SAFETY: the object decoded.
            unsafe { resolve_libctx(ret) };
        }
        ret
    }
}

ffi_export! {
    /// Encodes a PKCS#7 object to a BIO: 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `p7` is a live object.
    pub unsafe extern "C" fn i2d_PKCS7_bio(bp: *mut BIO, p7: *const PKCS7) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        // SAFETY: no preconditions.
        let it = unsafe { PKCS7_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_bio(it, bp, p7.cast()) }
    }
}

ffi_export! {
    /// Encodes a PKCS#7 object to a `FILE`: 1, or 0.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `p7` is a live object.
    pub unsafe extern "C" fn i2d_PKCS7_fp(fp: *mut FILE, p7: *const PKCS7) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        // SAFETY: no preconditions.
        let it = unsafe { PKCS7_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_fp(it, fp, p7.cast()) }
    }
}

// Building and reading (`pk7_lib.c`).

/// The content union's members (`None` for NULL), for an object of the member's type.
macro_rules! content_of {
    ($($name:ident: $field:ident => $ty:ty;)*) => {$(
        fn $name<'a>(p: &PKCS7) -> Option<&'a mut $ty> {
            // SAFETY: every member is a pointer; the caller reads the one of the object's type.
            let m = unsafe { p.d.$field };
            // SAFETY: the object's content, NULL or live.
            unsafe { m.as_mut() }
        }
    )*};
}

content_of! {
    sign_of: sign => PKCS7_SIGNED;
    sign_env_of: signed_and_enveloped => PKCS7_SIGN_ENVELOPE;
    enveloped_of: enveloped => PKCS7_ENVELOPE;
    digest_of: digest => PKCS7_DIGEST;
    other_of: other => ASN1_TYPE;
}

/// The content union's pointer.
fn content_ptr(p: &PKCS7) -> *mut c_char {
    // SAFETY: every member is a pointer.
    unsafe { p.d.ptr }
}

/// The NID of the object's content type (`NID_undef` for NULL).
fn type_nid(p7: *const PKCS7) -> c_int {
    // SAFETY: a live object, or NULL.
    unsafe { p7.as_ref() }.map_or(NID_undef, |p| {
        // SAFETY: its type, or NULL.
        unsafe { OBJ_obj2nid(p.type_) }
    })
}

/// The NID of a borrowed object's content type, read through the borrow (reading it through
/// the object's pointer instead would invalidate the borrow).
fn nid_of(p: &PKCS7) -> c_int {
    // SAFETY: its type, or NULL.
    unsafe { OBJ_obj2nid(p.type_) }
}

/// The object behind a pointer.
///
/// # Safety
/// `p7` is NULL or a live PKCS#7 object.
unsafe fn p7_of<'a>(p7: *mut PKCS7) -> Option<&'a mut PKCS7> {
    // SAFETY: the caller's guarantee.
    unsafe { p7.as_mut() }
}

/// `pkcs7_get0_certificates`.
///
/// # Safety
/// `p7` is NULL or a live PKCS#7 object.
unsafe fn certificates(p7: *const PKCS7) -> *mut stack_st_X509 {
    // SAFETY: the caller's guarantee.
    let Some(p) = (unsafe { p7.as_ref() }) else {
        return ptr::null_mut();
    };
    // SAFETY: the union's pointer.
    if content_ptr(p).is_null() {
        return ptr::null_mut();
    }
    match type_nid(p7) {
        // SAFETY: the content of its type.
        n if n == NID_pkcs7_signed => sign_of(p).map_or(ptr::null_mut(), |s| s.cert),
        // SAFETY: as above.
        n if n == NID_pkcs7_signedAndEnveloped => {
            sign_env_of(p).map_or(ptr::null_mut(), |s| s.cert)
        }
        _ => ptr::null_mut(),
    }
}

/// `pkcs7_get_recipient_info`.
///
/// # Safety
/// As for [`certificates`].
unsafe fn recipient_info(p7: *const PKCS7) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let Some(p) = (unsafe { p7.as_ref() }) else {
        return ptr::null_mut();
    };
    // SAFETY: the union's pointer.
    if content_ptr(p).is_null() {
        return ptr::null_mut();
    }
    match type_nid(p7) {
        // SAFETY: the content of its type.
        n if n == NID_pkcs7_signedAndEnveloped => {
            sign_env_of(p).map_or(ptr::null_mut(), |s| s.recipientinfo.cast())
        }
        // SAFETY: as above.
        n if n == NID_pkcs7_enveloped => {
            enveloped_of(p).map_or(ptr::null_mut(), |s| s.recipientinfo.cast())
        }
        _ => ptr::null_mut(),
    }
}

ffi_export! {
    /// Sets (`PKCS7_OP_SET_DETACHED_SIGNATURE`, freeing the content's data) or reads
    /// (`PKCS7_OP_GET_DETACHED_SIGNATURE`) whether a SignedData object's content is detached.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object.
    pub unsafe extern "C" fn PKCS7_ctrl(p7: *mut PKCS7, cmd: c_int, larg: c_long, parg: *mut c_char) -> c_long
    where failure = 0, library = ERR_LIB_PKCS7
    {
        const F: &str = "PKCS7_ctrl";
        let _ = parg;
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p7_of(p7) }) else { return 0 };
        let nid = nid_of(p);
        match cmd {
            n if n == PKCS7_OP_SET_DETACHED_SIGNATURE => {
                if nid != NID_pkcs7_signed {
                    raise(PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE, F);
                    return 0;
                }
                // SAFETY: the content of its type, or NULL.
                let Some(sign) = sign_of(p) else {
                    raise(PKCS7_R_NO_CONTENT, F);
                    return 0;
                };
                // OpenSSL's `(int)larg`.
                let detached = u32::try_from(larg & c_long::from(u32::MAX)).unwrap_or(0).cast_signed();
                p.detached = detached;
                if detached != 0 && type_nid(sign.contents) == NID_pkcs7_data {
                    // SAFETY: the content's data, its own.
                    let c = unsafe { &mut *sign.contents };
                    // SAFETY: a Data object's member.
                    let data = unsafe { c.d.data };
                    // SAFETY: its own string, or NULL.
                    unsafe { ASN1_OCTET_STRING_free(data) };
                    c.d.data = ptr::null_mut();
                }
                c_long::from(detached)
            }
            n if n == PKCS7_OP_GET_DETACHED_SIGNATURE => {
                if nid != NID_pkcs7_signed {
                    raise(PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE, F);
                    return 0;
                }
                // SAFETY: the content of its type, or NULL; its content's data, or NULL.
                let present = sign_of(p)
                    .and_then(|s| unsafe { s.contents.as_ref() })
                    .is_some_and(|c| !content_ptr(c).is_null());
                let ret = c_int::from(!present);
                p.detached = ret;
                c_long::from(ret)
            }
            _ => {
                raise(PKCS7_R_UNKNOWN_OPERATION, F);
                0
            }
        }
    }
}

ffi_export! {
    /// Sets the object's content type to `type_` with a new, empty content: 1, or 0.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object.
    pub unsafe extern "C" fn PKCS7_set_type(p7: *mut PKCS7, type_: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p7_of(p7) }) else { return 0 };
        // SAFETY: a NID.
        let obj = unsafe { OBJ_nid2obj(type_) };
        // SAFETY: a NID.
        let data_obj = unsafe { OBJ_nid2obj(NID_pkcs7_data) };
        let set_version = |v: *mut ASN1_INTEGER, n: c_long| {
            // SAFETY: a new content's version.
            (unsafe { ASN1_INTEGER_set(v, n) }) != 0
        };
        match type_ {
            n if n == NID_pkcs7_signed => {
                p.type_ = obj;
                // SAFETY: no preconditions.
                let s = unsafe { PKCS7_SIGNED_new() };
                p.d.sign = s;
                // SAFETY: new, or NULL.
                let Some(sr) = (unsafe { s.as_mut() }) else { return 0 };
                if !set_version(sr.version, 1) {
                    // SAFETY: made above.
                    unsafe { PKCS7_SIGNED_free(s) };
                    p.d.sign = ptr::null_mut();
                    return 0;
                }
            }
            n if n == NID_pkcs7_data => {
                p.type_ = obj;
                // SAFETY: no preconditions.
                p.d.data = unsafe { ASN1_OCTET_STRING_new() };
                // SAFETY: the union's pointer.
                if unsafe { p.d.data }.is_null() {
                    return 0;
                }
            }
            n if n == NID_pkcs7_signedAndEnveloped => {
                p.type_ = obj;
                // SAFETY: no preconditions.
                let s = unsafe { PKCS7_SIGN_ENVELOPE_new() };
                p.d.signed_and_enveloped = s;
                // SAFETY: new, or NULL.
                let Some(sr) = (unsafe { s.as_mut() }) else { return 0 };
                if !set_version(sr.version, 1) {
                    return 0;
                }
                // SAFETY: its new encrypted content.
                unsafe { (*sr.enc_data).content_type = data_obj };
            }
            n if n == NID_pkcs7_enveloped => {
                p.type_ = obj;
                // SAFETY: no preconditions.
                let s = unsafe { PKCS7_ENVELOPE_new() };
                p.d.enveloped = s;
                // SAFETY: new, or NULL.
                let Some(sr) = (unsafe { s.as_mut() }) else { return 0 };
                if !set_version(sr.version, 0) {
                    return 0;
                }
                // SAFETY: as above.
                unsafe { (*sr.enc_data).content_type = data_obj };
            }
            n if n == NID_pkcs7_encrypted => {
                p.type_ = obj;
                // SAFETY: no preconditions.
                let s = unsafe { PKCS7_ENCRYPT_new() };
                p.d.encrypted = s;
                // SAFETY: new, or NULL.
                let Some(sr) = (unsafe { s.as_mut() }) else { return 0 };
                if !set_version(sr.version, 0) {
                    return 0;
                }
                // SAFETY: as above.
                unsafe { (*sr.enc_data).content_type = data_obj };
            }
            n if n == NID_pkcs7_digest => {
                p.type_ = obj;
                // SAFETY: no preconditions.
                let s = unsafe { PKCS7_DIGEST_new() };
                p.d.digest = s;
                // SAFETY: new, or NULL.
                let Some(sr) = (unsafe { s.as_mut() }) else { return 0 };
                if !set_version(sr.version, 0) {
                    return 0;
                }
            }
            _ => {
                raise(PKCS7_R_UNSUPPORTED_CONTENT_TYPE, "PKCS7_set_type");
                return 0;
            }
        }
        1
    }
}

ffi_export! {
    /// Sets the object's type to `type_` and its content to `other` (taken): 1.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object; `other` is NULL or a value the object takes.
    pub unsafe extern "C" fn PKCS7_set0_type_other(p7: *mut PKCS7, type_: c_int, other: *mut ASN1_TYPE) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p7_of(p7) }) else { return 0 };
        // SAFETY: a NID.
        p.type_ = unsafe { OBJ_nid2obj(type_) };
        p.d.other = other;
        1
    }
}

ffi_export! {
    /// Sets the content of a SignedData or DigestedData object to `p7_data` (taken), freeing the
    /// old one: 1, or 0.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object; `p7_data` is NULL or an object it takes.
    pub unsafe extern "C" fn PKCS7_set_content(p7: *mut PKCS7, p7_data: *mut PKCS7) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p7_of(p7) }) else { return 0 };
        let slot = match nid_of(p) {
            // SAFETY: the content of its type.
            n if n == NID_pkcs7_signed => sign_of(p).map(|s| &mut s.contents),
            // SAFETY: as above.
            n if n == NID_pkcs7_digest => digest_of(p).map(|s| &mut s.contents),
            _ => None,
        };
        let Some(slot) = slot else {
            raise(PKCS7_R_UNSUPPORTED_CONTENT_TYPE, "PKCS7_set_content");
            return 0;
        };
        // SAFETY: its own old content, or NULL.
        unsafe { PKCS7_free(*slot) };
        *slot = p7_data;
        1
    }
}

ffi_export! {
    /// Sets a new content of type `type_` in a SignedData or DigestedData object: 1, or 0.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object.
    pub unsafe extern "C" fn PKCS7_content_new(p7: *mut PKCS7, type_: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        // SAFETY: no preconditions.
        let ret = unsafe { PKCS7_new() };
        // SAFETY: new, or NULL; the caller's object.
        if ret.is_null() || unsafe { PKCS7_set_type(ret, type_) } == 0 || unsafe { PKCS7_set_content(p7, ret) } == 0 {
            // SAFETY: made above, not taken.
            unsafe { PKCS7_free(ret) };
            return 0;
        }
        1
    }
}

/// The signer infos and digest algorithms of a SignedData or SignedAndEnvelopedData object.
///
/// # Safety
/// `p7` is NULL or a live PKCS#7 object.
unsafe fn signers_and_digests(
    p7: *mut PKCS7,
) -> Option<(*mut stack_st_PKCS7_SIGNER_INFO, *mut stack_st_X509_ALGOR)> {
    // SAFETY: the caller's guarantee.
    let p = unsafe { p7.as_ref() }?;
    match type_nid(p7) {
        // SAFETY: the content of its type.
        n if n == NID_pkcs7_signed => sign_of(p).map(|s| (s.signer_info, s.md_algs)),
        // SAFETY: as above.
        n if n == NID_pkcs7_signedAndEnveloped => {
            sign_env_of(p).map(|s| (s.signer_info, s.md_algs))
        }
        _ => None,
    }
}

ffi_export! {
    /// Adds the signer info (taken on success) to a SignedData or SignedAndEnvelopedData
    /// object, and its digest algorithm to the object's if new: 1, or 0.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object; `psi` is a live signer info.
    pub unsafe extern "C" fn PKCS7_add_signer(p7: *mut PKCS7, psi: *mut PKCS7_SIGNER_INFO) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee.
        let Some((signer_sk, md_sk)) = (unsafe { signers_and_digests(p7) }) else {
            raise(PKCS7_R_WRONG_CONTENT_TYPE, "PKCS7_add_signer");
            return 0;
        };
        // SAFETY: as above.
        let Some(si) = (unsafe { psi.as_mut() }) else { return 0 };
        // SAFETY: its digest algorithm.
        let obj = unsafe { si.digest_alg.as_ref() }.map_or(ptr::null_mut(), |a| a.algorithm);
        // SAFETY: the object's algorithms.
        let found = (0..unsafe { OPENSSL_sk_num(md_sk.cast()) }).any(|i| {
            // SAFETY: an index within them.
            let alg = unsafe { OPENSSL_sk_value(md_sk.cast(), i) }.cast::<X509_ALGOR>();
            // SAFETY: a live algorithm; the objects.
            unsafe { alg.as_ref() }.is_some_and(|a| unsafe { OBJ_cmp(obj, a.algorithm) } == 0)
        });
        if !found {
            // SAFETY: no preconditions.
            let alg = unsafe { X509_ALGOR_new() };
            // SAFETY: new, or NULL.
            let param = if alg.is_null() { ptr::null_mut() } else { unsafe { ASN1_TYPE_new() } };
            if alg.is_null() || param.is_null() {
                // SAFETY: made above, or NULL.
                unsafe { X509_ALGOR_free(alg) };
                raise(ERR_R_ASN1_LIB, "PKCS7_add_signer");
                return 0;
            }
            // SAFETY: as above.
            let a = unsafe { &mut *alg };
            a.parameter = param;
            // SAFETY: the object.
            let nid = unsafe { OBJ_obj2nid(obj) };
            a.algorithm = if nid == NID_undef {
                // SAFETY: as above.
                unsafe { OBJ_dup(obj) }
            } else {
                // SAFETY: a NID.
                unsafe { OBJ_nid2obj(nid) }
            };
            // SAFETY: the new parameter.
            unsafe { (*param).type_ = V_ASN1_NULL };
            // SAFETY: the object's algorithms; the new one.
            if a.algorithm.is_null() || unsafe { OPENSSL_sk_push(md_sk.cast(), alg.cast()) } == 0 {
                // SAFETY: made above, not taken.
                unsafe { X509_ALGOR_free(alg) };
                return 0;
            }
        }
        si.ctx = ctx_of(p7);
        // SAFETY: the object's signer infos; the caller's.
        c_int::from(unsafe { OPENSSL_sk_push(signer_sk.cast(), psi.cast()) } != 0)
    }
}

ffi_export! {
    /// Adds the certificate (with a reference) to a SignedData or SignedAndEnvelopedData
    /// object: 1, or 0.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object; `x509` is a live certificate.
    pub unsafe extern "C" fn PKCS7_add_certificate(p7: *mut PKCS7, x509: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p7_of(p7) }) else { return 0 };
        let sk = match nid_of(p) {
            // SAFETY: the content of its type.
            n if n == NID_pkcs7_signed => sign_of(p).map(|s| &mut s.cert),
            // SAFETY: as above.
            n if n == NID_pkcs7_signedAndEnveloped => sign_env_of(p).map(|s| &mut s.cert),
            _ => None,
        };
        let Some(sk) = sk else {
            raise(PKCS7_R_WRONG_CONTENT_TYPE, "PKCS7_add_certificate");
            return 0;
        };
        if sk.is_null() {
            // SAFETY: no preconditions.
            *sk = unsafe { OPENSSL_sk_new_null() }.cast();
            if sk.is_null() {
                err::raise(rustyssl_abi::ERR_LIB_X509, ERR_R_CRYPTO_LIB, "ossl_x509_add_cert_new");
                return 0;
            }
        }
        // SAFETY: the object's certificates; the caller's.
        unsafe { X509_add_cert(*sk, x509, X509_ADD_FLAG_UP_REF) }
    }
}

ffi_export! {
    /// Adds the CRL (with a reference) to a SignedData or SignedAndEnvelopedData object: 1, or
    /// 0.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object; `crl` is a live CRL.
    pub unsafe extern "C" fn PKCS7_add_crl(p7: *mut PKCS7, crl: *mut X509_CRL) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        const F: &str = "PKCS7_add_crl";
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p7_of(p7) }) else { return 0 };
        let sk = match nid_of(p) {
            // SAFETY: the content of its type.
            n if n == NID_pkcs7_signed => sign_of(p).map(|s| &mut s.crl),
            // SAFETY: as above.
            n if n == NID_pkcs7_signedAndEnveloped => sign_env_of(p).map(|s| &mut s.crl),
            _ => None,
        };
        let Some(sk) = sk else {
            raise(PKCS7_R_WRONG_CONTENT_TYPE, F);
            return 0;
        };
        if sk.is_null() {
            // SAFETY: no preconditions.
            *sk = unsafe { OPENSSL_sk_new_null() }.cast();
        }
        if sk.is_null() {
            raise(ERR_R_CRYPTO_LIB, F);
            return 0;
        }
        // SAFETY: the caller's CRL.
        if unsafe { X509_CRL_up_ref(crl) } == 0 {
            return 0;
        }
        // SAFETY: the object's CRLs; the reference taken.
        if unsafe { OPENSSL_sk_push((*sk).cast(), crl.cast()) } == 0 {
            // SAFETY: the reference taken above.
            unsafe { X509_CRL_free(crl) };
            return 0;
        }
        1
    }
}

ffi_export! {
    /// The signer info's key, digest algorithm, and signature algorithm, into the non-NULL
    /// outputs.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; the outputs are NULL or writable.
    pub unsafe extern "C" fn PKCS7_SIGNER_INFO_get0_algs(si: *mut PKCS7_SIGNER_INFO, pk: *mut *mut EVP_PKEY, pdig: *mut *mut X509_ALGOR, psig: *mut *mut X509_ALGOR)
    where failure = (), library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { si.as_ref() }) else { return };
        // SAFETY: as above, for each.
        unsafe {
            if !pk.is_null() {
                pk.write(s.pkey);
            }
        }
        if !pdig.is_null() {
            // SAFETY: as above.
            unsafe { pdig.write(s.digest_alg) };
        }
        if !psig.is_null() {
            // SAFETY: as above.
            unsafe { psig.write(s.digest_enc_alg) };
        }
    }
}

ffi_export! {
    /// The recipient info's key encryption algorithm, into `*penc` if not NULL.
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info; `penc` is NULL or writable.
    pub unsafe extern "C" fn PKCS7_RECIP_INFO_get0_alg(ri: *mut PKCS7_RECIP_INFO, penc: *mut *mut X509_ALGOR)
    where failure = (), library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee.
        if let Some(r) = unsafe { ri.as_ref() }
            && !penc.is_null()
        {
            // SAFETY: as above.
            unsafe { penc.write(r.key_enc_algor) };
        }
    }
}

/// `pkcs7_ecdsa_or_dsa_sign_verify_setup` for signing: the signature algorithm from the digest
/// and the key's type.
///
/// # Safety
/// `si` is a live signer info with a key.
unsafe fn ecdsa_or_dsa_setup(si: &mut PKCS7_SIGNER_INFO) -> c_int {
    // SAFETY: its algorithm, or NULL.
    let Some(alg1) = (unsafe { si.digest_alg.as_ref() }) else {
        return -1;
    };
    if alg1.algorithm.is_null() {
        return -1;
    }
    // SAFETY: the object.
    let hnid = unsafe { OBJ_obj2nid(alg1.algorithm) };
    if hnid == NID_undef {
        return -1;
    }
    let mut snid = 0;
    // SAFETY: the key.
    let pkey_id = unsafe { crate::evp::pkey::EVP_PKEY_get_id(si.pkey) };
    // SAFETY: a local.
    if unsafe { crate::objects::sigid::OBJ_find_sigid_by_algs(&raw mut snid, hnid, pkey_id) } == 0 {
        return -1;
    }
    // SAFETY: its signature algorithm; a NID's object.
    unsafe {
        X509_ALGOR_set0(
            si.digest_enc_alg,
            nid_obj(snid),
            V_ASN1_UNDEF,
            ptr::null_mut(),
        )
    }
}

/// `pkcs7_rsa_sign_verify_setup` (and `_encrypt_decrypt_setup`) for signing (encrypting):
/// `rsaEncryption` with a NULL parameter as the algorithm.
fn rsa_setup(alg: *mut X509_ALGOR) -> c_int {
    if alg.is_null() {
        return 1;
    }
    // SAFETY: a live algorithm; a NID's object.
    unsafe {
        X509_ALGOR_set0(
            alg,
            nid_obj(NID_rsaEncryption),
            V_ASN1_NULL,
            ptr::null_mut(),
        )
    }
}

/// An issuer and serial number from the certificate's (`X509_NAME_set`, `ASN1_INTEGER_dup`).
///
/// # Safety
/// `ias` is a live IssuerAndSerialNumber; `x509` a live certificate.
unsafe fn set_issuer_and_serial(ias: *mut PKCS7_ISSUER_AND_SERIAL, x509: *mut X509) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(i) = (unsafe { ias.as_mut() }) else {
        return false;
    };
    // SAFETY: the caller's certificate.
    let name = unsafe { X509_get_issuer_name(x509) };
    // SAFETY: the issuer's slot; the name.
    if unsafe { X509_NAME_set(&raw mut i.issuer, name) } == 0 {
        return false;
    }
    // SAFETY: its own, or NULL.
    unsafe { ASN1_INTEGER_free(i.serial) };
    // SAFETY: the certificate's serial number.
    let serial = unsafe { X509_get0_serialNumber(x509) };
    // SAFETY: its serial number.
    i.serial = unsafe { ASN1_INTEGER_dup(serial) };
    !i.serial.is_null()
}

ffi_export! {
    /// Fills the signer info for `x509`'s key `pkey` and digest `dgst`: version 1, the issuer
    /// and serial number, the key (with a reference), and the algorithms: 1, or 0 (or -1 if no
    /// signature algorithm fits).
    ///
    /// # Safety
    /// `p7i` is NULL or a live signer info; `x509`, `pkey`, and `dgst` are live.
    pub unsafe extern "C" fn PKCS7_SIGNER_INFO_set(p7i: *mut PKCS7_SIGNER_INFO, x509: *mut X509, pkey: *mut EVP_PKEY, dgst: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        const F: &str = "PKCS7_SIGNER_INFO_set";
        // SAFETY: the caller's guarantee.
        let Some(si) = (unsafe { p7i.as_mut() }) else { return 0 };
        // SAFETY: its version.
        if unsafe { ASN1_INTEGER_set(si.version, 1) } == 0 {
            return 0;
        }
        // SAFETY: its issuer and serial number; the caller's certificate.
        if !unsafe { set_issuer_and_serial(si.issuer_and_serial, x509) } {
            return 0;
        }
        // SAFETY: the caller's key.
        if unsafe { EVP_PKEY_up_ref(pkey) } == 0 {
            return 0;
        }
        si.pkey = pkey;
        // SAFETY: the caller's digest.
        let md_nid = unsafe { crate::evp::digest::EVP_MD_get_type(dgst) };
        // SAFETY: its algorithm; a NID's object.
        if unsafe { X509_ALGOR_set0(si.digest_alg, nid_obj(md_nid), V_ASN1_NULL, ptr::null_mut()) } == 0 {
            return 0;
        }
        let is_a = |name: &core::ffi::CStr| {
            // SAFETY: the key; a name.
            (unsafe { EVP_PKEY_is_a(pkey, name.as_ptr()) }) != 0
        };
        if is_a(c"EC") || is_a(c"DSA") {
            // SAFETY: the signer info, with its key.
            return unsafe { ecdsa_or_dsa_setup(si) };
        }
        if is_a(c"RSA") {
            return rsa_setup(si.digest_enc_alg);
        }
        // SAFETY: the key; the control's signer info.
        let ret = unsafe { crate::evp::pkey::asn1_ctrl_of(pkey, ASN1_PKEY_CTRL_PKCS7_SIGN, 0, p7i.cast()) };
        match ret {
            Some(r) if r > 0 => 1,
            Some(-2) | None => {
                raise(PKCS7_R_SIGNING_NOT_SUPPORTED_FOR_THIS_KEY_TYPE, F);
                0
            }
            Some(_) => {
                raise(PKCS7_R_SIGNING_CTRL_FAILURE, F);
                0
            }
        }
    }
}

ffi_export! {
    /// Adds a new signer info for `x509`'s key `pkey` with `dgst` (the key's default digest if
    /// NULL) to the object: the signer info, or NULL.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object; `x509` and `pkey` are live; `dgst` is NULL or live.
    pub unsafe extern "C" fn PKCS7_add_signature(p7: *mut PKCS7, x509: *mut X509, pkey: *mut EVP_PKEY, dgst: *const EVP_MD) -> *mut PKCS7_SIGNER_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        let mut dgst = dgst;
        if dgst.is_null() {
            let mut def_nid = 0;
            // SAFETY: the caller's key; a local.
            if unsafe { EVP_PKEY_get_default_digest_nid(pkey, &raw mut def_nid) } <= 0 {
                return ptr::null_mut();
            }
            // SAFETY: a NID.
            let sn = unsafe { crate::objects::OBJ_nid2sn(def_nid) };
            // SAFETY: a name, or NULL.
            dgst = unsafe { crate::evp::legacy_md::EVP_get_digestbyname(sn) };
            if dgst.is_null() {
                raise(PKCS7_R_NO_DEFAULT_DIGEST, "PKCS7_add_signature");
                return ptr::null_mut();
            }
        }
        // SAFETY: no preconditions.
        let si = unsafe { PKCS7_SIGNER_INFO_new() };
        if si.is_null()
            // SAFETY: the new signer info; the caller's certificate, key, and digest.
            || unsafe { PKCS7_SIGNER_INFO_set(si, x509, pkey, dgst) } <= 0
            // SAFETY: the caller's object; the signer info.
            || unsafe { PKCS7_add_signer(p7, si) } == 0
        {
            // SAFETY: made above, not taken.
            unsafe { PKCS7_SIGNER_INFO_free(si) };
            return ptr::null_mut();
        }
        si
    }
}

ffi_export! {
    /// The signer infos of a SignedData or SignedAndEnvelopedData object, or NULL.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object.
    pub unsafe extern "C" fn PKCS7_get_signer_info(p7: *mut PKCS7) -> *mut stack_st_PKCS7_SIGNER_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p7.as_ref() }) else { return ptr::null_mut() };
        // SAFETY: the union's pointer.
        if content_ptr(p).is_null() {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        unsafe { signers_and_digests(p7) }.map_or(ptr::null_mut(), |(s, _)| s)
    }
}

ffi_export! {
    /// Adds the recipient info (taken on success) to an EnvelopedData or SignedAndEnvelopedData
    /// object: 1, or 0.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object; `ri` is a live recipient info.
    pub unsafe extern "C" fn PKCS7_add_recipient_info(p7: *mut PKCS7, ri: *mut PKCS7_RECIP_INFO) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p7.as_ref() }) else { return 0 };
        let sk = match type_nid(p7) {
            // SAFETY: the content of its type.
            n if n == NID_pkcs7_signedAndEnveloped => sign_env_of(p).map(|s| s.recipientinfo.cast::<c_void>()),
            // SAFETY: as above.
            n if n == NID_pkcs7_enveloped => enveloped_of(p).map(|s| s.recipientinfo.cast::<c_void>()),
            _ => None,
        };
        let Some(sk) = sk else {
            raise(PKCS7_R_WRONG_CONTENT_TYPE, "PKCS7_add_recipient_info");
            return 0;
        };
        // SAFETY: the object's recipients; the caller's.
        c_int::from(unsafe { OPENSSL_sk_push(sk.cast(), ri.cast()) } != 0)
    }
}

ffi_export! {
    /// Fills the recipient info for `x509`: version 0, the issuer and serial number, the key
    /// encryption algorithm, and the certificate (with a reference): 1, 0, or -2 for an RSA-PSS
    /// key.
    ///
    /// # Safety
    /// `p7i` is NULL or a live recipient info; `x509` is a live certificate.
    pub unsafe extern "C" fn PKCS7_RECIP_INFO_set(p7i: *mut PKCS7_RECIP_INFO, x509: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        const F: &str = "PKCS7_RECIP_INFO_set";
        // SAFETY: the caller's guarantee.
        let Some(ri) = (unsafe { p7i.as_mut() }) else { return 0 };
        // SAFETY: its version.
        if unsafe { ASN1_INTEGER_set(ri.version, 0) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        if !unsafe { set_issuer_and_serial(ri.issuer_and_serial, x509) } {
            return 0;
        }
        // SAFETY: the caller's certificate.
        let pkey = unsafe { X509_get0_pubkey(x509) };
        if pkey.is_null() {
            return 0;
        }
        let is_a = |name: &core::ffi::CStr| {
            // SAFETY: the key; a name.
            (unsafe { EVP_PKEY_is_a(pkey, name.as_ptr()) }) != 0
        };
        if is_a(c"RSA-PSS") {
            return -2;
        }
        if is_a(c"RSA") {
            if rsa_setup(ri.key_enc_algor) <= 0 {
                return 0;
            }
        } else {
            // SAFETY: the key; the control's recipient info.
            match unsafe { crate::evp::pkey::asn1_ctrl_of(pkey, ASN1_PKEY_CTRL_PKCS7_ENCRYPT, 0, p7i.cast()) } {
                None | Some(-2) => {
                    raise(PKCS7_R_ENCRYPTION_NOT_SUPPORTED_FOR_THIS_KEY_TYPE, F);
                    return 0;
                }
                Some(r) if r <= 0 => {
                    raise(PKCS7_R_ENCRYPTION_CTRL_FAILURE, F);
                    return 0;
                }
                Some(_) => {}
            }
        }
        // SAFETY: the caller's certificate.
        if unsafe { X509_up_ref(x509) } == 0 {
            return 0;
        }
        ri.cert = x509;
        1
    }
}

ffi_export! {
    /// Adds a new recipient info for `x509` to the object: the recipient info, or NULL.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object; `x509` is a live certificate.
    pub unsafe extern "C" fn PKCS7_add_recipient(p7: *mut PKCS7, x509: *mut X509) -> *mut PKCS7_RECIP_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        // SAFETY: no preconditions.
        let ri = unsafe { PKCS7_RECIP_INFO_new() };
        if ri.is_null()
            // SAFETY: the new recipient info; the caller's certificate.
            || unsafe { PKCS7_RECIP_INFO_set(ri, x509) } <= 0
            // SAFETY: the caller's object; the recipient info.
            || unsafe { PKCS7_add_recipient_info(p7, ri) } == 0
        {
            // SAFETY: made above, not taken.
            unsafe { PKCS7_RECIP_INFO_free(ri) };
            return ptr::null_mut();
        }
        // SAFETY: the new recipient info.
        unsafe { (*ri).ctx = ctx_of(p7) };
        ri
    }
}

ffi_export! {
    /// The certificate of a SignedData object that the signer info names, or NULL.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object; `si` is a live signer info.
    pub unsafe extern "C" fn PKCS7_cert_from_signer_info(p7: *mut PKCS7, si: *mut PKCS7_SIGNER_INFO) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        if type_nid(p7) != NID_pkcs7_signed {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee; the content of its type.
        let (Some(p), Some(s)) = (unsafe { p7.as_ref() }, unsafe { si.as_ref() }) else { return ptr::null_mut() };
        // SAFETY: as above.
        let Some(ias) = (unsafe { s.issuer_and_serial.as_ref() }) else { return ptr::null_mut() };
        // SAFETY: as above.
        let certs = sign_of(p).map_or(ptr::null_mut(), |s| s.cert);
        // SAFETY: the certificates, or NULL; the name and serial number.
        unsafe { X509_find_by_issuer_and_serial(certs, ias.issuer, ias.serial) }
    }
}

ffi_export! {
    /// Sets the content encryption cipher of an EnvelopedData or SignedAndEnvelopedData object:
    /// 1, or 0.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object; `cipher` is a live cipher.
    pub unsafe extern "C" fn PKCS7_set_cipher(p7: *mut PKCS7, cipher: *const EVP_CIPHER) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        const F: &str = "PKCS7_set_cipher";
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p7.as_ref() }) else { return 0 };
        let ec = match type_nid(p7) {
            // SAFETY: the content of its type.
            n if n == NID_pkcs7_signedAndEnveloped => sign_env_of(p).map(|s| s.enc_data),
            // SAFETY: as above.
            n if n == NID_pkcs7_enveloped => enveloped_of(p).map(|s| s.enc_data),
            _ => None,
        };
        // SAFETY: the encrypted content, or NULL.
        let Some(ec) = ec.and_then(|e| unsafe { e.as_mut() }) else {
            raise(PKCS7_R_WRONG_CONTENT_TYPE, F);
            return 0;
        };
        // SAFETY: the caller's cipher.
        if unsafe { crate::evp::cipher::EVP_CIPHER_get_type(cipher) } == NID_undef {
            raise(PKCS7_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER, F);
            return 0;
        }
        ec.cipher = cipher;
        ec.ctx = ctx_of(p7);
        1
    }
}

ffi_export! {
    /// Sets the digest algorithm of a DigestedData object (with a NULL parameter): 1, or 0.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object; `md` is a live digest.
    pub unsafe extern "C" fn PKCS7_set_digest(p7: *mut PKCS7, md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        if type_nid(p7) != NID_pkcs7_digest {
            raise(PKCS7_R_WRONG_CONTENT_TYPE, "PKCS7_set_digest");
            return 0;
        }
        // SAFETY: the caller's guarantee; the content of its type and its algorithm.
        let Some(d) = (unsafe { p7.as_ref() }).and_then(digest_of) else { return 0 };
        // SAFETY: its algorithm.
        let Some(alg) = (unsafe { d.md.as_mut() }) else { return 0 };
        // SAFETY: no preconditions.
        alg.parameter = unsafe { ASN1_TYPE_new() };
        if alg.parameter.is_null() {
            raise(ERR_R_ASN1_LIB, "PKCS7_set_digest");
            return 0;
        }
        // SAFETY: the new parameter.
        unsafe { (*alg.parameter).type_ = V_ASN1_NULL };
        // SAFETY: the caller's digest; its NID's object.
        let nid = unsafe { crate::evp::digest::EVP_MD_get_type(md) };
        alg.algorithm = nid_obj(nid);
        1
    }
}

// Attributes (`pk7_doit.c`, `pk7_attr.c`).

/// `get_attribute`: the first value of the attribute `nid`, or NULL.
///
/// # Safety
/// `sk` is NULL or a live list of attributes.
unsafe fn get_attribute(sk: *const stack_st_X509_ATTRIBUTE, nid: c_int) -> *mut ASN1_TYPE {
    // SAFETY: the caller's guarantee.
    let idx = unsafe { X509at_get_attr_by_NID(sk.cast(), nid, -1) };
    if idx < 0 {
        return ptr::null_mut();
    }
    // SAFETY: as above; an index within it.
    let a = unsafe { X509at_get_attr(sk.cast(), idx) };
    // SAFETY: its attribute.
    unsafe { X509_ATTRIBUTE_get0_type(a, 0) }
}

/// `add_attribute`: sets the attribute `nid` to the value (taken on success), replacing one
/// already there.
///
/// # Safety
/// `sk` holds NULL or a live list of attributes; `value` is what `X509_ATTRIBUTE_create` takes.
unsafe fn add_attribute(
    sk: &mut *mut stack_st_X509_ATTRIBUTE,
    nid: c_int,
    atrtype: c_int,
    value: *mut c_void,
) -> c_int {
    if sk.is_null() {
        // SAFETY: no preconditions.
        *sk = unsafe { OPENSSL_sk_new_null() }.cast();
        if sk.is_null() {
            return 0;
        }
    }
    let list = (*sk).cast();
    // SAFETY: the list.
    let n = unsafe { OPENSSL_sk_num(list) };
    let i = (0..n)
        .find(|&i| {
            // SAFETY: an index within it.
            let a = unsafe { OPENSSL_sk_value(list, i) }.cast::<X509_ATTRIBUTE>();
            // SAFETY: a live attribute; its object.
            let o = unsafe { X509_ATTRIBUTE_get0_object(a) };
            // SAFETY: its object.
            (unsafe { OBJ_obj2nid(o) }) == nid
        })
        .unwrap_or(n);
    // SAFETY: as above.
    if i == n && unsafe { OPENSSL_sk_push(list, ptr::null()) } == 0 {
        return 0;
    }
    // SAFETY: the caller's value.
    let attr = unsafe { X509_ATTRIBUTE_create(nid, atrtype, value) };
    if attr.is_null() {
        if i == n {
            // SAFETY: the placeholder pushed above.
            unsafe { OPENSSL_sk_pop(list) };
        }
        return 0;
    }
    // SAFETY: the old attribute at `i`, or NULL.
    let old = unsafe { OPENSSL_sk_value(list, i) };
    // SAFETY: the list's attribute, or NULL.
    unsafe { X509_ATTRIBUTE_free(old.cast()) };
    // SAFETY: an index within it; the new attribute.
    unsafe { OPENSSL_sk_set(list, i, attr.cast()) };
    1
}

/// `X509_ATTRIBUTE_dup` as a stack's copy function.
unsafe extern "C" fn attr_copy(p: *const c_void) -> *mut c_void {
    // SAFETY: an attribute of the stack.
    unsafe { X509_ATTRIBUTE_dup(p.cast()) }.cast()
}

/// `X509_ATTRIBUTE_free` as a stack's free function.
unsafe extern "C" fn attr_free(p: *mut c_void) {
    // SAFETY: an attribute the stack owned.
    unsafe { X509_ATTRIBUTE_free(p.cast()) };
}

/// Replaces a list of attributes with a deep copy of `sk`: whether there is one.
///
/// # Safety
/// `slot` holds NULL or a live list; `sk` is NULL or a live list of attributes.
unsafe fn set_attributes(
    slot: &mut *mut stack_st_X509_ATTRIBUTE,
    sk: *mut stack_st_X509_ATTRIBUTE,
) -> c_int {
    // SAFETY: the old list, or NULL.
    unsafe { OPENSSL_sk_pop_free((*slot).cast(), Some(attr_free)) };
    // SAFETY: the caller's list; the functions.
    *slot = unsafe { OPENSSL_sk_deep_copy(sk.cast(), Some(attr_copy), Some(attr_free)) }.cast();
    c_int::from(!slot.is_null())
}

/// The signer info behind a pointer.
///
/// # Safety
/// `si` is NULL or a live signer info.
unsafe fn si_of<'a>(si: *const PKCS7_SIGNER_INFO) -> Option<&'a mut PKCS7_SIGNER_INFO> {
    // SAFETY: the caller's guarantee.
    unsafe { si.cast_mut().as_mut() }
}

ffi_export! {
    /// The first value of the signed attribute `nid`, or NULL.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info.
    pub unsafe extern "C" fn PKCS7_get_signed_attribute(si: *const PKCS7_SIGNER_INFO, nid: c_int) -> *mut ASN1_TYPE
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee; its attributes.
        unsafe { si_of(si) }.map_or(ptr::null_mut(), |s| unsafe { get_attribute(s.auth_attr, nid) })
    }
}

ffi_export! {
    /// The first value of the unsigned attribute `nid`, or NULL.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info.
    pub unsafe extern "C" fn PKCS7_get_attribute(si: *const PKCS7_SIGNER_INFO, nid: c_int) -> *mut ASN1_TYPE
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee; its attributes.
        unsafe { si_of(si) }.map_or(ptr::null_mut(), |s| unsafe { get_attribute(s.unauth_attr, nid) })
    }
}

ffi_export! {
    /// The messageDigest attribute's value among the attributes, or NULL.
    ///
    /// # Safety
    /// `sk` is NULL or a live list of attributes.
    pub unsafe extern "C" fn PKCS7_digest_from_attributes(sk: *mut stack_st_X509_ATTRIBUTE) -> *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee.
        let t = unsafe { get_attribute(sk, NID_pkcs9_messageDigest) };
        // SAFETY: the attribute's value, or NULL.
        match unsafe { t.as_ref() } {
            // SAFETY: an OCTET STRING's member.
            Some(v) if v.type_ == V_ASN1_OCTET_STRING => unsafe { v.value.octet_string },
            _ => ptr::null_mut(),
        }
    }
}

ffi_export! {
    /// Replaces the signed attributes with a copy of `sk`: 1, or 0.
    ///
    /// # Safety
    /// `p7si` is NULL or a live signer info; `sk` is NULL or a live list of attributes.
    pub unsafe extern "C" fn PKCS7_set_signed_attributes(p7si: *mut PKCS7_SIGNER_INFO, sk: *mut stack_st_X509_ATTRIBUTE) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee; its attributes.
        unsafe { si_of(p7si) }.map_or(0, |s| unsafe { set_attributes(&mut s.auth_attr, sk) })
    }
}

ffi_export! {
    /// Replaces the unsigned attributes with a copy of `sk`: 1, or 0.
    ///
    /// # Safety
    /// As for `PKCS7_set_signed_attributes`.
    pub unsafe extern "C" fn PKCS7_set_attributes(p7si: *mut PKCS7_SIGNER_INFO, sk: *mut stack_st_X509_ATTRIBUTE) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee; its attributes.
        unsafe { si_of(p7si) }.map_or(0, |s| unsafe { set_attributes(&mut s.unauth_attr, sk) })
    }
}

ffi_export! {
    /// Sets the signed attribute `nid` to `value` (taken on success; `atrtype` its type): 1, or
    /// 0.
    ///
    /// # Safety
    /// `p7si` is NULL or a live signer info; `value` is a value of `atrtype`.
    pub unsafe extern "C" fn PKCS7_add_signed_attribute(p7si: *mut PKCS7_SIGNER_INFO, nid: c_int, atrtype: c_int, value: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee; its attributes.
        unsafe { si_of(p7si) }.map_or(0, |s| unsafe { add_attribute(&mut s.auth_attr, nid, atrtype, value) })
    }
}

ffi_export! {
    /// Sets the unsigned attribute `nid` to `value`, as `PKCS7_add_signed_attribute`.
    ///
    /// # Safety
    /// As for `PKCS7_add_signed_attribute`.
    pub unsafe extern "C" fn PKCS7_add_attribute(p7si: *mut PKCS7_SIGNER_INFO, nid: c_int, atrtype: c_int, value: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee; its attributes.
        unsafe { si_of(p7si) }.map_or(0, |s| unsafe { add_attribute(&mut s.unauth_attr, nid, atrtype, value) })
    }
}

ffi_export! {
    /// The issuer and serial number of a SignedAndEnvelopedData object's recipient `idx`, or
    /// NULL.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object.
    pub unsafe extern "C" fn PKCS7_get_issuer_and_serial(p7: *mut PKCS7, idx: c_int) -> *mut PKCS7_ISSUER_AND_SERIAL
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        if type_nid(p7) != NID_pkcs7_signedAndEnveloped {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee; the content of its type.
        let Some(se) = (unsafe { p7.as_ref() }).and_then(sign_env_of) else { return ptr::null_mut() };
        let rsk = se.recipientinfo;
        // SAFETY: its recipients, or NULL.
        if rsk.is_null() || idx < 0 || unsafe { OPENSSL_sk_num(rsk.cast()) } <= idx {
            return ptr::null_mut();
        }
        // SAFETY: an index within them.
        let ri = unsafe { OPENSSL_sk_value(rsk.cast(), idx) }.cast::<PKCS7_RECIP_INFO>();
        // SAFETY: a live recipient info.
        unsafe { ri.as_ref() }.map_or(ptr::null_mut(), |r| r.issuer_and_serial)
    }
}

ffi_export! {
    /// Whether the object's content type isn't one of PKCS#7's six: 1, or 0.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object.
    pub unsafe extern "C" fn PKCS7_type_is_other(p7: *mut PKCS7) -> c_int
    where failure = 1, library = ERR_LIB_PKCS7
    {
        let known = [NID_pkcs7_data, NID_pkcs7_signed, NID_pkcs7_enveloped, NID_pkcs7_signedAndEnveloped, NID_pkcs7_digest, NID_pkcs7_encrypted];
        c_int::from(!known.contains(&type_nid(p7)))
    }
}

ffi_export! {
    /// A Data object's OCTET STRING, or an other type's if its content is one; NULL otherwise.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object.
    pub unsafe extern "C" fn PKCS7_get_octet_string(p7: *mut PKCS7) -> *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p7.as_ref() }) else { return ptr::null_mut() };
        if type_nid(p7) == NID_pkcs7_data {
            // SAFETY: the content of its type.
            return unsafe { p.d.data };
        }
        // SAFETY: as above.
        if unsafe { PKCS7_type_is_other(p7) } != 0 {
            // SAFETY: the content, or NULL.
            if let Some(o) = other_of(p)
                && o.type_ == V_ASN1_OCTET_STRING
            {
                // SAFETY: an OCTET STRING's member.
                return unsafe { o.value.octet_string };
            }
        }
        ptr::null_mut()
    }
}

ffi_export! {
    /// Adds the S/MIME capabilities (their DER) as a signed attribute: 1 (also for none), or 0.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; `cap` is NULL or a live list of algorithms.
    pub unsafe extern "C" fn PKCS7_add_attrib_smimecap(si: *mut PKCS7_SIGNER_INFO, cap: *mut stack_st_X509_ALGOR) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        // SAFETY: no preconditions.
        let seq: *mut ASN1_STRING = unsafe { ASN1_STRING_new() };
        // SAFETY: new, or NULL.
        let Some(s) = (unsafe { seq.as_mut() }) else {
            raise(ERR_R_ASN1_LIB, "PKCS7_add_attrib_smimecap");
            return 0;
        };
        // SAFETY: no preconditions.
        let it = unsafe { X509_ALGORS_it() };
        // SAFETY: the caller's list; the string's data.
        s.length = unsafe { ASN1_item_i2d(cap.cast(), &raw mut s.data, it) };
        if s.length <= 0 || s.data.is_null() {
            // SAFETY: made above.
            unsafe { ASN1_STRING_free(seq) };
            return 1;
        }
        // SAFETY: the caller's signer info; the string.
        if unsafe { PKCS7_add_signed_attribute(si, NID_SMIMECapabilities, V_ASN1_SEQUENCE, seq.cast()) } == 0 {
            // SAFETY: not taken.
            unsafe { ASN1_STRING_free(seq) };
            return 0;
        }
        1
    }
}

ffi_export! {
    /// The S/MIME capabilities of the signed attributes, decoded, or NULL.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info.
    pub unsafe extern "C" fn PKCS7_get_smimecap(si: *mut PKCS7_SIGNER_INFO) -> *mut stack_st_X509_ALGOR
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee.
        let cap = unsafe { PKCS7_get_signed_attribute(si, NID_SMIMECapabilities) };
        // SAFETY: the value, or NULL.
        let Some(c) = (unsafe { cap.as_ref() }) else { return ptr::null_mut() };
        if c.type_ != V_ASN1_SEQUENCE {
            return ptr::null_mut();
        }
        // SAFETY: a SEQUENCE's member.
        let seq = unsafe { c.value.sequence };
        // SAFETY: the string, or NULL.
        let Some(s) = (unsafe { seq.as_ref() }) else { return ptr::null_mut() };
        let mut p = s.data.cast_const();
        // SAFETY: no preconditions.
        let it = unsafe { X509_ALGORS_it() };
        // SAFETY: its DER.
        unsafe { crate::asn1::tpl::decode::ASN1_item_d2i(ptr::null_mut(), &raw mut p, c_long::from(s.length), it) }.cast()
    }
}

ffi_export! {
    /// Adds the capability `nid` (with `arg` as an INTEGER parameter if positive) to the list:
    /// 1, or 0.
    ///
    /// # Safety
    /// `sk` is a live list of algorithms.
    pub unsafe extern "C" fn PKCS7_simple_smimecap(sk: *mut stack_st_X509_ALGOR, nid: c_int, arg: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        const F: &str = "PKCS7_simple_smimecap";
        // SAFETY: no preconditions.
        let alg = unsafe { X509_ALGOR_new() };
        // SAFETY: new, or NULL.
        let Some(a) = (unsafe { alg.as_mut() }) else {
            raise(ERR_R_ASN1_LIB, F);
            return 0;
        };
        // SAFETY: its own object.
        unsafe { crate::objects::ASN1_OBJECT_free(a.algorithm) };
        // SAFETY: a NID.
        a.algorithm = unsafe { OBJ_nid2obj(nid) };
        let fail = |reason| {
            if reason != 0 {
                raise(reason, F);
            }
            // SAFETY: made above.
            unsafe { X509_ALGOR_free(alg) };
            0
        };
        if arg > 0 {
            // SAFETY: no preconditions.
            a.parameter = unsafe { ASN1_TYPE_new() };
            if a.parameter.is_null() {
                return fail(ERR_R_ASN1_LIB);
            }
            // SAFETY: as above.
            let nbit = unsafe { ASN1_INTEGER_new() };
            // SAFETY: the new integer, or NULL.
            if nbit.is_null() || unsafe { ASN1_INTEGER_set(nbit, c_long::from(arg)) } == 0 {
                // SAFETY: as above.
                unsafe { ASN1_INTEGER_free(nbit) };
                return fail(ERR_R_ASN1_LIB);
            }
            // SAFETY: the new parameter.
            let p = unsafe { &mut *a.parameter };
            p.value.integer = nbit;
            p.type_ = rustyssl_abi::V_ASN1_INTEGER;
        }
        // SAFETY: the caller's list; the new algorithm.
        if unsafe { OPENSSL_sk_push(sk.cast(), alg.cast()) } == 0 {
            return fail(ERR_R_CRYPTO_LIB);
        }
        1
    }
}

ffi_export! {
    /// Adds the contentType signed attribute (`coid`, or Data for NULL) unless there is one: 1,
    /// or 0.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; `coid` is NULL or an object it takes.
    pub unsafe extern "C" fn PKCS7_add_attrib_content_type(si: *mut PKCS7_SIGNER_INFO, coid: *mut ASN1_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { PKCS7_get_signed_attribute(si, NID_pkcs9_contentType) }.is_null() {
            return 0;
        }
        let coid = if coid.is_null() {
            // SAFETY: a NID.
            unsafe { OBJ_nid2obj(NID_pkcs7_data) }
        } else {
            coid
        };
        // SAFETY: as above; the object.
        unsafe { PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT, coid.cast()) }
    }
}

ffi_export! {
    /// Adds the signingTime signed attribute (`t`, taken, or now for NULL): 1, or 0.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; `t` is NULL or a time it takes.
    pub unsafe extern "C" fn PKCS7_add0_attrib_signing_time(si: *mut PKCS7_SIGNER_INFO, t: *mut ASN1_TIME) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        let mut tmp: *mut ASN1_TIME = ptr::null_mut();
        let mut t = t;
        if t.is_null() {
            // SAFETY: a new time.
            tmp = unsafe { X509_gmtime_adj(ptr::null_mut(), 0) };
            if tmp.is_null() {
                raise(ERR_R_X509_LIB, "PKCS7_add0_attrib_signing_time");
                return 0;
            }
            t = tmp;
        }
        // SAFETY: the caller's signer info; the time.
        if unsafe { PKCS7_add_signed_attribute(si, NID_pkcs9_signingTime, V_ASN1_UTCTIME, t.cast()) } == 0 {
            // SAFETY: made above, or NULL.
            unsafe { ASN1_TIME_free(tmp) };
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Adds the messageDigest signed attribute (a copy of the `mdlen` octets at `md`): 1, or 0.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; `md` holds `mdlen` octets.
    pub unsafe extern "C" fn PKCS7_add1_attrib_digest(si: *mut PKCS7_SIGNER_INFO, md: *const c_uchar, mdlen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        // SAFETY: no preconditions.
        let os = unsafe { ASN1_OCTET_STRING_new() };
        if os.is_null() {
            return 0;
        }
        // SAFETY: the new string; the caller's octets.
        if unsafe { ASN1_STRING_set(os, md.cast(), mdlen) } == 0
            // SAFETY: the caller's signer info; the string.
            || unsafe { PKCS7_add_signed_attribute(si, NID_pkcs9_messageDigest, V_ASN1_OCTET_STRING, os.cast()) } == 0
        {
            // SAFETY: not taken.
            unsafe { ASN1_OCTET_STRING_free(os) };
            return 0;
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: the PKCS#7 functions on NULL objects, which OpenSSL reads through.
    #[test]
    fn null_objects_are_refused() {
        let n = ptr::null_mut();
        // SAFETY: NULL objects, which they refuse, for each call below.
        let r = unsafe { PKCS7_set_type(n, NID_pkcs7_data) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { PKCS7_ctrl(n, PKCS7_OP_GET_DETACHED_SIGNATURE, 0, ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { PKCS7_add_signer(n, ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { PKCS7_get_signed_attribute(ptr::null(), NID_pkcs9_contentType) };
        assert!(r.is_null());
        let none = ptr::null_mut();
        // SAFETY: as above.
        let r = unsafe { PKCS7_SIGNER_INFO_set(none, none.cast(), none.cast(), ptr::null()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { PKCS7_type_is_other(n) };
        assert_eq!(r, 1);
    }
}
