//! Certificates (`X509_new(3)`, `X509_get_subject_name(3)`, `X509_sign(3)`, `d2i_X509(3)`;
//! `x_x509.c`, `x_val.c`, `x_x509a.c`, `x509_set.c`, `x509_cmp.c`, `x509_ext.c`, `x_all.c`,
//! `x509_def.c`, and the time functions of `x509_vfy.c`): `X509` as OpenSSL's reference-counted
//! SEQUENCE over its own structure, with the TBSCertificate (`X509_CINF`) keeping the DER it
//! was decoded from until it changes, the auxiliary trust data (`X509_CERT_AUX`) of
//! `d2i_X509_AUX`, ex_data, and the library context it was made in.
//!
//! As in OpenSSL:
//! - A decoded certificate encodes as it was decoded, byte for byte, until a setter changes the
//!   TBSCertificate; `X509_sign` and `i2d_re_X509_tbs` encode it afresh.
//! - `X509_sign` makes a certificate with extensions version 3, and sets both
//!   AlgorithmIdentifiers; `X509_verify` refuses one whose two AlgorithmIdentifiers differ.
//! - The getters return the certificate's own fields, which live as long as it does.
//!
//! What needs the extension cache (`X509_cmp`, the purposes, the key identifiers, the flags,
//! the signature information) comes with the extensions themselves (step 5.2). Where OpenSSL
//! reads through a NULL certificate, these answer NULL or 0 (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void};
use core::mem::offset_of;
use core::ptr;
use std::ffi::CString;
use std::sync::OnceLock;

use libc::{FILE, time_t};
use rustyssl_abi::{
    ASN1_AFLG_ENCODING, ASN1_AFLG_REFCOUNT, ASN1_BIT_STRING, ASN1_ENCODING, ASN1_INTEGER,
    ASN1_ITEM, ASN1_OBJECT, ASN1_OCTET_STRING, ASN1_OP_D2I_PRE, ASN1_OP_DUP_POST,
    ASN1_OP_FREE_POST, ASN1_OP_GET0_LIBCTX, ASN1_OP_GET0_PROPQ, ASN1_OP_NEW_POST,
    ASN1_STRING_FLAG_MSTRING, ASN1_TFLG_EMBED, ASN1_TFLG_EXPLICIT, ASN1_TFLG_IMPLICIT,
    ASN1_TFLG_OPTIONAL, ASN1_TFLG_SEQUENCE_OF, ASN1_TIME, ASN1_VALUE, BIO, CRYPTO_EX_DATA,
    CRYPTO_EX_INDEX_X509, CRYPTO_RWLOCK, ERR_LIB_ASN1, ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER,
    EVP_MD, EVP_MD_CTX, EVP_PK_DH, EVP_PK_DSA, EVP_PK_EC, EVP_PK_RSA, EVP_PKEY, EVP_PKEY_DH,
    EVP_PKEY_DSA, EVP_PKEY_EC, EVP_PKEY_ED448, EVP_PKEY_ED25519, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS,
    EVP_PKS_DSA, EVP_PKS_EC, EVP_PKS_RSA, EVP_PKT_ENC, EVP_PKT_EXCH, EVP_PKT_SIGN, NID_ED448,
    NID_ED25519, NID_X9_62_id_ecPublicKey, NID_X9_62_prime256v1, NID_dsa, NID_dsa_2,
    NID_ecdsa_with_SHA256, NID_ecdsa_with_SHA384, NID_id_GostR3410_2001, NID_id_GostR3410_2012_256,
    NID_id_GostR3410_2012_512, NID_rsa, NID_rsaEncryption, NID_secp384r1, NID_undef, OSSL_LIB_CTX,
    SN_md5, V_ASN1_GENERALIZEDTIME, V_ASN1_UTCTIME, X509, X509_ALGOR, X509_CERT_AUX, X509_CINF,
    X509_EXTENSION, X509_NAME, X509_PUBKEY, X509_R_KEY_TYPE_MISMATCH, X509_R_KEY_VALUES_MISMATCH,
    X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN, X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY,
    X509_R_UNKNOWN_KEY_TYPE, X509_R_UNKNOWN_SIGID_ALGS, X509_R_UNSUPPORTED_ALGORITHM,
    X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256, X509_V_ERR_SUITE_B_INVALID_ALGORITHM,
    X509_V_ERR_SUITE_B_INVALID_CURVE, X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM,
    X509_V_ERR_SUITE_B_INVALID_VERSION, X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED,
    X509_V_FLAG_SUITEB_128_LOS, X509_V_FLAG_SUITEB_128_LOS_ONLY, X509_V_FLAG_SUITEB_192_LOS,
    X509_V_OK, X509_VAL, X509_VERSION_1, X509_VERSION_3, stack_st_X509, stack_st_X509_EXTENSION,
};

use super::algor::X509_ALGOR_cmp;
use super::ext::{
    X509_EXTENSION_it, X509v3_add_ext, X509v3_delete_ext, X509v3_get_ext, X509v3_get_ext_by_NID,
    X509v3_get_ext_by_OBJ, X509v3_get_ext_by_critical, X509v3_get_ext_count,
};
use super::name::{
    X509_NAME_cmp, X509_NAME_hash_ex, X509_NAME_hash_old, X509_NAME_it, X509_NAME_oneline,
    X509_NAME_set,
};
use super::pubkey::{
    X509_PUBKEY_get, X509_PUBKEY_get0, X509_PUBKEY_it, X509_PUBKEY_set, pubkey_of,
};
use crate::asn1::integer::{ASN1_INTEGER_cmp, ASN1_INTEGER_get, ASN1_INTEGER_set};
use crate::asn1::sign::{ASN1_item_sign_ctx, ASN1_item_sign_ex, ASN1_item_verify_ex};
use crate::asn1::string::{
    ASN1_INTEGER_free, ASN1_INTEGER_new, ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new,
    ASN1_OCTET_STRING_set, ASN1_STRING_copy, ASN1_STRING_dup,
};
use crate::asn1::time::{
    ASN1_GENERALIZEDTIME_adj, ASN1_TIME_adj, ASN1_TIME_diff, ASN1_UTCTIME_adj,
};
use crate::asn1::tpl::io::{
    ASN1_item_d2i_bio, ASN1_item_d2i_fp, ASN1_item_i2d_bio, ASN1_item_i2d_fp,
};
use crate::asn1::tpl::items::{
    ASN1_BIT_STRING_it, ASN1_INTEGER_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_it, ASN1_TIME_free,
    ASN1_TIME_it, ASN1_UTF8STRING_it, X509_ALGOR_it, d2i, i2d, new_free,
};
use crate::asn1::tpl::new::ASN1_item_new_ex;
use crate::asn1::tpl::statics::{Aux, Templates, aux_ex, sequence};
use crate::asn1::tpl::util::{ASN1_item_dup, item_digest_ex};
use crate::asn1::tpl::{do_lock, item_fns, template_at};
use crate::err;
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_get0_name};
use crate::evp::legacy_md::EVP_get_digestbyname;
use crate::evp::md_ctx::{
    EVP_Digest, EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free,
    EVP_MD_CTX_new,
};
use crate::evp::pkey::params::EVP_PKEY_get_group_name;
use crate::evp::pkey::{
    EVP_PKEY_copy_parameters, EVP_PKEY_eq, EVP_PKEY_is_a, EVP_PKEY_missing_parameters,
    EVP_PKEY_type,
};
use crate::ex_data::{
    CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data, CRYPTO_set_ex_data,
};
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::objects::sigid::OBJ_find_sigid_algs;
use crate::objects::{OBJ_nid2sn, OBJ_obj2nid, OBJ_txt2nid};
use crate::stack::{
    OPENSSL_sk_dup, OPENSSL_sk_free, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value,
};
use crate::string::CRYPTO_strdup;

/// `X509_CINF` (`x509_cinf_st`): the TBSCertificate.
#[repr(C)]
pub(crate) struct Cinf {
    pub(crate) version: *mut ASN1_INTEGER,
    pub(crate) serial_number: ASN1_INTEGER,
    pub(crate) signature: X509_ALGOR,
    pub(crate) issuer: *mut X509_NAME,
    pub(crate) validity: X509_VAL,
    pub(crate) subject: *mut X509_NAME,
    pub(crate) key: *mut X509_PUBKEY,
    pub(crate) issuer_uid: *mut ASN1_BIT_STRING,
    pub(crate) subject_uid: *mut ASN1_BIT_STRING,
    pub(crate) extensions: *mut stack_st_X509_EXTENSION,
    /// The DER it was decoded from, until it changes (`modified`).
    pub(crate) enc: ASN1_ENCODING,
}

/// `X509` (`x509_st`), as far as this step needs it: the extension cache's fields come with
/// the extensions (step 5.2).
#[repr(C)]
pub(crate) struct Cert {
    pub(crate) cert_info: Cinf,
    pub(crate) sig_alg: X509_ALGOR,
    pub(crate) signature: ASN1_BIT_STRING,
    references: c_int,
    pub(crate) ex_data: CRYPTO_EX_DATA,
    /// The auxiliary trust data, from `d2i_X509_AUX` or the trust setters.
    pub(crate) aux: *mut X509_CERT_AUX,
    pub(crate) lock: *mut CRYPTO_RWLOCK,
    pub(crate) distinguishing_id: *mut ASN1_OCTET_STRING,
    pub(crate) libctx: *mut OSSL_LIB_CTX,
    pub(crate) propq: *mut c_char,
    /// The extension cache (`v3_purp.c`).
    pub(crate) cache: crate::x509::purpose::Cache,
}

/// `X509_CERT_AUX` (`x509_cert_aux_st`).
#[repr(C)]
pub(crate) struct CertAux {
    pub(crate) trust: *mut c_void,
    pub(crate) reject: *mut c_void,
    pub(crate) alias: *mut rustyssl_abi::ASN1_UTF8STRING,
    pub(crate) keyid: *mut ASN1_OCTET_STRING,
    pub(crate) other: *mut c_void,
}

static VAL_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(X509_VAL, notBefore),
        c"notBefore",
        ASN1_TIME_it,
    ),
    template_at(
        0,
        0,
        offset_of!(X509_VAL, notAfter),
        c"notAfter",
        ASN1_TIME_it,
    ),
]);

item_fns! {
    /// Validity: SEQUENCE { notBefore Time, notAfter Time }.
    pub unsafe extern "C" fn X509_VAL_it = sequence::<X509_VAL, 2>(&VAL_TT, None, c"X509_VAL");
}

new_free! {
    pub unsafe extern "C" fn X509_VAL_new, pub unsafe extern "C" fn X509_VAL_free(X509_VAL) = X509_VAL_it;
}

i2d! {
    /// Encodes a Validity.
    pub unsafe extern "C" fn i2d_X509_VAL(X509_VAL) = X509_VAL_it;
}

d2i! {
    /// Decodes a Validity (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_X509_VAL(X509_VAL) = X509_VAL_it;
}

static CINF_TT: Templates<10> = Templates([
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(Cinf, version),
        c"version",
        ASN1_INTEGER_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Cinf, serial_number),
        c"serialNumber",
        ASN1_INTEGER_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Cinf, signature),
        c"signature",
        X509_ALGOR_it,
    ),
    template_at(0, 0, offset_of!(Cinf, issuer), c"issuer", X509_NAME_it),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Cinf, validity),
        c"validity",
        X509_VAL_it,
    ),
    template_at(0, 0, offset_of!(Cinf, subject), c"subject", X509_NAME_it),
    template_at(0, 0, offset_of!(Cinf, key), c"key", X509_PUBKEY_it),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(Cinf, issuer_uid),
        c"issuerUID",
        ASN1_BIT_STRING_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        2,
        offset_of!(Cinf, subject_uid),
        c"subjectUID",
        ASN1_BIT_STRING_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        3,
        offset_of!(Cinf, extensions),
        c"extensions",
        X509_EXTENSION_it,
    ),
]);

/// `ASN1_SEQUENCE_enc`: the TBSCertificate keeps its encoding.
static CINF_AUX: Aux = aux_ex(ASN1_AFLG_ENCODING, 0, 0, None, offset_of!(Cinf, enc));

item_fns! {
    /// TBSCertificate.
    pub unsafe extern "C" fn X509_CINF_it = sequence::<Cinf, 10>(&CINF_TT, Some(&CINF_AUX), c"X509_CINF");
}

new_free! {
    pub unsafe extern "C" fn X509_CINF_new, pub unsafe extern "C" fn X509_CINF_free(X509_CINF) = X509_CINF_it;
}

i2d! {
    /// Encodes a TBSCertificate (as it was decoded, unless it changed).
    pub unsafe extern "C" fn i2d_X509_CINF(X509_CINF) = X509_CINF_it;
}

d2i! {
    /// Decodes a TBSCertificate (`ASN1_item_d2i`), keeping its encoding.
    pub unsafe extern "C" fn d2i_X509_CINF(X509_CINF) = X509_CINF_it;
}

static CERT_AUX_TT: Templates<5> = Templates([
    template_at(
        ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(CertAux, trust),
        c"trust",
        ASN1_OBJECT_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(CertAux, reject),
        c"reject",
        ASN1_OBJECT_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(CertAux, alias),
        c"alias",
        ASN1_UTF8STRING_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(CertAux, keyid),
        c"keyid",
        ASN1_OCTET_STRING_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(CertAux, other),
        c"other",
        X509_ALGOR_it,
    ),
]);

item_fns! {
    /// OpenSSL's auxiliary trust data: trusted and rejected uses, an alias, a key identifier,
    /// and other AlgorithmIdentifiers.
    pub unsafe extern "C" fn X509_CERT_AUX_it = sequence::<CertAux, 5>(&CERT_AUX_TT, None, c"X509_CERT_AUX");
}

new_free! {
    pub unsafe extern "C" fn X509_CERT_AUX_new, pub unsafe extern "C" fn X509_CERT_AUX_free(X509_CERT_AUX) = X509_CERT_AUX_it;
}

i2d! {
    /// Encodes the auxiliary trust data.
    pub unsafe extern "C" fn i2d_X509_CERT_AUX(X509_CERT_AUX) = X509_CERT_AUX_it;
}

d2i! {
    /// Decodes the auxiliary trust data (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_X509_CERT_AUX(X509_CERT_AUX) = X509_CERT_AUX_it;
}

static CERT_TT: Templates<3> = Templates([
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Cert, cert_info),
        c"cert_info",
        X509_CINF_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Cert, sig_alg),
        c"sig_alg",
        X509_ALGOR_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Cert, signature),
        c"signature",
        ASN1_BIT_STRING_it,
    ),
]);

/// `ASN1_SEQUENCE_ref`: counted references, and `x509_cb`.
static CERT_AUX: Aux = aux_ex(
    ASN1_AFLG_REFCOUNT,
    offset_of!(Cert, references),
    offset_of!(Cert, lock),
    Some(x509_cb),
    0,
);

/// `ossl_x509_set0_libctx`: an object's library context and (copied) properties, into its slots.
///
/// # Safety
/// `propq` is NULL or a string.
pub(crate) unsafe fn set0_libctx(
    slot: &mut *mut OSSL_LIB_CTX,
    propq_slot: &mut *mut c_char,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> bool {
    *slot = libctx;
    // SAFETY: the object's own copy, or NULL.
    unsafe { mem::release(propq_slot.cast()) };
    *propq_slot = ptr::null_mut();
    if !propq.is_null() {
        // SAFETY: the caller's string.
        *propq_slot = unsafe { CRYPTO_strdup(propq, ptr::null(), 0) };
        if propq_slot.is_null() {
            return false;
        }
    }
    true
}

/// Frees what the certificate holds beyond its fields: its ex_data, its auxiliary data, and
/// its distinguishing ID (and, when it's going, its properties).
///
/// # Safety
/// `x` is the live certificate at `v`.
unsafe fn free_extras(x: &mut Cert, v: *mut ASN1_VALUE, going: bool) {
    // SAFETY: the certificate's ex_data.
    unsafe { CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509, v.cast(), &raw mut x.ex_data) };
    // SAFETY: its own, or NULL.
    unsafe { X509_CERT_AUX_free(x.aux) };
    // SAFETY: as above.
    unsafe { ASN1_OCTET_STRING_free(x.distinguishing_id) };
    x.aux = ptr::null_mut();
    x.distinguishing_id = ptr::null_mut();
    x.cache.free();
    if going {
        // SAFETY: as above.
        unsafe { mem::release(x.propq.cast()) };
        x.propq = ptr::null_mut();
    }
}

ffi_callback! {
    /// `x509_cb`: a new or re-decoded certificate starts with fresh ex_data and no auxiliary
    /// data; freeing frees them; a copy takes the original's library context; the library
    /// context and properties are given to the decoder and encoder.
    ///
    /// # Safety
    /// `pval` holds NULL or a live certificate; `exarg` is the operation's.
    pub(crate) unsafe extern "C" fn x509_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let v = unsafe { pval.read() };
        // SAFETY: as above.
        let Some(x) = (unsafe { v.cast::<Cert>().as_mut() }) else { return 1 };
        match operation {
            ASN1_OP_D2I_PRE | ASN1_OP_NEW_POST => {
                if operation == ASN1_OP_D2I_PRE {
                    // SAFETY: the certificate at `v`.
                    unsafe { free_extras(x, v, false) };
                }
                x.cache.reset();
                // SAFETY: as above.
                c_int::from(unsafe { CRYPTO_new_ex_data(CRYPTO_EX_INDEX_X509, v.cast(), &raw mut x.ex_data) } != 0)
            }
            ASN1_OP_FREE_POST => {
                // SAFETY: as above.
                unsafe { free_extras(x, v, true) };
                1
            }
            ASN1_OP_DUP_POST => {
                // SAFETY: the original, which the copy was made from.
                let Some(old) = (unsafe { exarg.cast::<Cert>().as_ref() }) else { return 1 };
                // SAFETY: its properties, NULL or a string.
                c_int::from(unsafe { set0_libctx(&mut x.libctx, &mut x.propq, old.libctx, old.propq) })
            }
            ASN1_OP_GET0_LIBCTX => {
                // SAFETY: the operation's output.
                unsafe { exarg.cast::<*mut OSSL_LIB_CTX>().write(x.libctx) };
                1
            }
            ASN1_OP_GET0_PROPQ => {
                // SAFETY: as above.
                unsafe { exarg.cast::<*const c_char>().write(x.propq) };
                1
            }
            _ => 1,
        }
    }
}

item_fns! {
    /// Certificate: SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }.
    pub unsafe extern "C" fn X509_it = sequence::<Cert, 3>(&CERT_TT, Some(&CERT_AUX), c"X509");
}

new_free! {
    pub unsafe extern "C" fn X509_new, pub unsafe extern "C" fn X509_free(X509) = X509_it;
}

i2d! {
    /// Encodes a certificate.
    pub unsafe extern "C" fn i2d_X509(X509) = X509_it;
}

d2i! {
    /// Decodes a certificate (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_X509(X509) = X509_it;
}

/// A certificate decoded from `der` in `libctx` with `propq`, so that its key is decoded with
/// that context's providers (`X509_new_ex`, then `d2i_X509` into it, as libssl does), or NULL.
///
/// # Safety
/// `libctx` is NULL or a live library context; `propq` is NULL or a string.
pub(crate) unsafe fn decode_in(
    der: &[u8],
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> *mut X509 {
    let Ok(len) = c_long::try_from(der.len()) else {
        return ptr::null_mut();
    };
    // SAFETY: the caller's guarantee.
    let mut x = unsafe { X509_new_ex(libctx, propq) };
    if x.is_null() {
        return x;
    }
    let mut p = der.as_ptr();
    // SAFETY: the certificate made above; the octets.
    if unsafe { d2i_X509(&raw mut x, &raw mut p, len) }.is_null() {
        // SAFETY: made above (a failed decoding leaves it as it was).
        unsafe { X509_free(x) };
        return ptr::null_mut();
    }
    x
}

/// The certificate behind a pointer, or `None` for NULL.
///
/// # Safety
/// `x` is NULL or a live certificate.
pub(crate) unsafe fn cert_of<'a>(x: *const X509) -> Option<&'a mut Cert> {
    // SAFETY: the caller's guarantee; a certificate is a `Cert`.
    unsafe { x.cast::<Cert>().cast_mut().as_mut() }
}

ffi_export! {
    /// A copy of the certificate (through its encoding, with its library context), or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_dup(x: *const X509) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_dup(it, x.cast_mut().cast()) }.cast()
    }
}

ffi_export! {
    /// A new certificate in `libctx`, with `propq` (copied) for what it fetches, or NULL.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `propq` is NULL or a string.
    pub unsafe extern "C" fn X509_new_ex(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_it() };
        // SAFETY: the caller's guarantee; the type's item.
        let x: *mut X509 = unsafe { ASN1_item_new_ex(it, libctx, propq) }.cast();
        // SAFETY: just made, or NULL.
        if let Some(c) = unsafe { cert_of(x) }
            // SAFETY: the caller's guarantee.
            && !unsafe { set0_libctx(&mut c.libctx, &mut c.propq, libctx, propq) }
        {
            // SAFETY: made above.
            unsafe { X509_free(x) };
            return ptr::null_mut();
        }
        x
    }
}

ffi_export! {
    /// Adds a reference: 1, or 0 for NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_up_ref(x: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if x.is_null() {
            return 0;
        }
        let mut v = x.cast::<ASN1_VALUE>();
        // SAFETY: no preconditions.
        let it = unsafe { X509_it() };
        // SAFETY: a live certificate of the item.
        c_int::from(unsafe { do_lock(&raw mut v, 1, it) } > 1)
    }
}

ffi_export! {
    /// Sets the certificate's ex_data at `idx`: 1, or 0.
    ///
    /// # Safety
    /// `r` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_set_ex_data(r: *mut X509, idx: c_int, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { cert_of(r) }) else { return 0 };
        // SAFETY: the certificate's ex_data.
        unsafe { CRYPTO_set_ex_data(&raw mut x.ex_data, idx, arg) }
    }
}

ffi_export! {
    /// The certificate's ex_data at `idx`, or NULL.
    ///
    /// # Safety
    /// `r` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_get_ex_data(r: *const X509, idx: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { cert_of(r) }) else { return ptr::null_mut() };
        // SAFETY: the certificate's ex_data.
        unsafe { CRYPTO_get_ex_data(&raw const x.ex_data, idx) }
    }
}

ffi_export! {
    /// Decodes a certificate followed, if there's more, by its auxiliary trust data (OpenSSL's
    /// "trusted certificate"). Advances `*pp` past both.
    ///
    /// # Safety
    /// As for `d2i_X509`.
    pub unsafe extern "C" fn d2i_X509_AUX(a: *mut *mut X509, pp: *mut *const c_uchar, length: c_long) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        if pp.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_PASSED_NULL_PARAMETER, "d2i_X509_AUX");
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let freeret = a.is_null() || unsafe { a.read() }.is_null();
        // SAFETY: as above.
        let start = unsafe { pp.read() };
        let mut q = start;
        // SAFETY: as above.
        let ret = unsafe { d2i_X509(a, &raw mut q, length) };
        // SAFETY: just decoded, or NULL.
        let Some(x) = (unsafe { cert_of(ret) }) else { return ptr::null_mut() };
        // SAFETY: the decoder moved `q` within the input.
        let used = unsafe { q.offset_from(start) };
        let rest = length.saturating_sub(c_long::try_from(used).unwrap_or(c_long::MAX));
        // SAFETY: the rest of the input; the certificate's own slot.
        if rest > 0 && unsafe { d2i_X509_CERT_AUX(&raw mut x.aux, &raw mut q, rest) }.is_null() {
            if freeret {
                // SAFETY: decoded above, ours.
                unsafe { X509_free(ret) };
                if !a.is_null() {
                    // SAFETY: the caller's slot.
                    unsafe { a.write(ptr::null_mut()) };
                }
            }
            return ptr::null_mut();
        }
        // SAFETY: the caller's pointer.
        unsafe { pp.write(q) };
        ret
    }
}

/// `i2d_x509_aux_internal`: the certificate's encoding and its auxiliary data's, to `*pp`
/// (advanced past them) if given.
///
/// # Safety
/// `a` is NULL or a live certificate; `pp` is NULL or holds room for the encoding.
unsafe fn i2d_aux_internal(a: *const X509, pp: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's guarantee.
    let start = if pp.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { pp.read() }
    };
    // SAFETY: as above.
    let length = unsafe { i2d_X509(a, pp) };
    // SAFETY: as above.
    let Some(x) = (unsafe { cert_of(a) }) else {
        return length;
    };
    if length <= 0 {
        return length;
    }
    // SAFETY: the certificate's auxiliary data, or NULL; as above.
    let tmplen = unsafe { i2d_X509_CERT_AUX(x.aux, pp) };
    if tmplen < 0 {
        if !start.is_null() {
            // SAFETY: the caller's pointer.
            unsafe { pp.write(start) };
        }
        return tmplen;
    }
    length.saturating_add(tmplen)
}

ffi_export! {
    /// Encodes a certificate followed by its auxiliary trust data, `i2d` conventions.
    ///
    /// # Safety
    /// `a` is NULL or a live certificate; `pp` is NULL or holds NULL or room for the encoding.
    pub unsafe extern "C" fn i2d_X509_AUX(a: *const X509, pp: *mut *mut c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        if pp.is_null() || !unsafe { pp.read() }.is_null() {
            // SAFETY: as above.
            return unsafe { i2d_aux_internal(a, pp) };
        }
        // SAFETY: as above.
        let length = unsafe { i2d_aux_internal(a, ptr::null_mut()) };
        let Ok(n) = usize::try_from(length) else { return length };
        if n == 0 {
            return length;
        }
        let buf: *mut c_uchar = mem::alloc(n).cast();
        if buf.is_null() {
            return -1;
        }
        let mut tmp = buf;
        // SAFETY: as above; room for the encoding.
        let length = unsafe { i2d_aux_internal(a, &raw mut tmp) };
        if length <= 0 {
            // SAFETY: allocated above.
            unsafe { mem::release(buf.cast()) };
            return length;
        }
        // SAFETY: the caller's pointer.
        unsafe { pp.write(buf) };
        length
    }
}

ffi_export! {
    /// Encodes the TBSCertificate afresh (not as it was decoded), `i2d` conventions.
    ///
    /// # Safety
    /// `x` is a live certificate; `pp` as for `i2d_X509_CINF`.
    pub unsafe extern "C" fn i2d_re_X509_tbs(x: *mut X509, pp: *mut *mut c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(x) }) else { return -1 };
        c.cert_info.enc.modified = 1;
        // SAFETY: as above.
        unsafe { i2d_X509_CINF((&raw const c.cert_info).cast(), pp) }
    }
}

ffi_export! {
    /// The certificate's signature and its AlgorithmIdentifier, into `*psig` and `*palg` where
    /// given.
    ///
    /// # Safety
    /// `psig` and `palg` are NULL or writable; `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_get0_signature(psig: *mut *const ASN1_BIT_STRING, palg: *mut *const X509_ALGOR, x: *const X509)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(x) }) else { return };
        if !psig.is_null() {
            // SAFETY: as above.
            unsafe { psig.write(&raw const c.signature) };
        }
        if !palg.is_null() {
            // SAFETY: as above.
            unsafe { palg.write(&raw const c.sig_alg) };
        }
    }
}

ffi_export! {
    /// The NID of the certificate's signature algorithm.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_get_signature_nid(x: *const X509) -> c_int
    where failure = NID_undef, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(x) }) else { return NID_undef };
        // SAFETY: its object.
        unsafe { OBJ_obj2nid(c.sig_alg.algorithm) }
    }
}

ffi_export! {
    /// Gives the certificate the distinguishing ID (SM2's) it's verified with, freeing the old.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `d_id` is NULL or a string it takes.
    pub unsafe extern "C" fn X509_set0_distinguishing_id(x: *mut X509, d_id: *mut ASN1_OCTET_STRING)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(x) }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { ASN1_OCTET_STRING_free(c.distinguishing_id) };
        c.distinguishing_id = d_id;
    }
}

ffi_export! {
    /// The certificate's distinguishing ID, or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_get0_distinguishing_id(x: *mut X509) -> *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { cert_of(x) }.map_or(ptr::null_mut(), |c| c.distinguishing_id)
    }
}

// The setters (`x509_set.c`): each marks the TBSCertificate changed.

ffi_export! {
    /// Sets the version (`X509_VERSION_1` leaves it out): 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_set_version(x: *mut X509, version: c_long) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(x) }) else { return 0 };
        let ci = &mut c.cert_info;
        // SAFETY: its version, or NULL.
        if version == unsafe { ASN1_INTEGER_get(ci.version) } {
            return 1;
        }
        if version == c_long::from(X509_VERSION_1) {
            // SAFETY: as above.
            unsafe { ASN1_INTEGER_free(ci.version) };
            ci.version = ptr::null_mut();
            ci.enc.modified = 1;
            return 1;
        }
        if ci.version.is_null() {
            // SAFETY: no preconditions.
            ci.version = unsafe { ASN1_INTEGER_new() };
            if ci.version.is_null() {
                return 0;
            }
        }
        // SAFETY: its version.
        if unsafe { ASN1_INTEGER_set(ci.version, version) } == 0 {
            return 0;
        }
        ci.enc.modified = 1;
        1
    }
}

ffi_export! {
    /// Sets the serial number to a copy of `serial`: 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `serial` is NULL or a live INTEGER.
    pub unsafe extern "C" fn X509_set_serialNumber(x: *mut X509, serial: *mut ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(x) }) else { return 0 };
        let ci = &mut c.cert_info;
        let own = &raw mut ci.serial_number;
        if own != serial {
            // As OpenSSL's, a copy leaves the encoding as it was.
            // SAFETY: the certificate's INTEGER; the caller's.
            return unsafe { ASN1_STRING_copy(own, serial) };
        }
        ci.enc.modified = 1;
        1
    }
}

ffi_export! {
    /// Sets the issuer to a copy of `name`: 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `name` is NULL or a live name.
    pub unsafe extern "C" fn X509_set_issuer_name(x: *mut X509, name: *const X509_NAME) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(x) }) else { return 0 };
        // SAFETY: the certificate's slot; the caller's name.
        if unsafe { X509_NAME_set(&raw mut c.cert_info.issuer, name) } == 0 {
            return 0;
        }
        c.cert_info.enc.modified = 1;
        1
    }
}

ffi_export! {
    /// Sets the subject to a copy of `name`: 1, or 0.
    ///
    /// # Safety
    /// As for [`X509_set_issuer_name`].
    pub unsafe extern "C" fn X509_set_subject_name(x: *mut X509, name: *const X509_NAME) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(x) }) else { return 0 };
        // SAFETY: the certificate's slot; the caller's name.
        if unsafe { X509_NAME_set(&raw mut c.cert_info.subject, name) } == 0 {
            return 0;
        }
        c.cert_info.enc.modified = 1;
        1
    }
}

/// `ossl_x509_set1_time`: `*ptm` becomes a copy of `tm` (NULL for none), marking `*modified`.
///
/// # Safety
/// `ptm` holds NULL or a time it owns; `tm` is NULL or a live time.
pub(crate) unsafe fn set1_time(
    modified: Option<&mut c_int>,
    ptm: *mut *mut ASN1_TIME,
    tm: *const ASN1_TIME,
) -> c_int {
    // SAFETY: the caller's guarantee.
    if unsafe { ptm.read() }.cast_const() == tm {
        return 1;
    }
    // SAFETY: as above.
    let new = unsafe { ASN1_STRING_dup(tm) };
    if !tm.is_null() && new.is_null() {
        return 0;
    }
    // SAFETY: as above.
    let old = unsafe { ptm.read() };
    // SAFETY: the time it owned.
    unsafe { ASN1_TIME_free(old) };
    // SAFETY: as above.
    unsafe { ptm.write(new) };
    if let Some(m) = modified {
        *m = 1;
    }
    1
}

ffi_export! {
    /// Sets the start of the validity to a copy of `tm`: 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `tm` is NULL or a live time.
    pub unsafe extern "C" fn X509_set1_notBefore(x: *mut X509, tm: *const ASN1_TIME) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(x) }) else { return 0 };
        if tm.is_null() {
            return 0;
        }
        let ci = &mut c.cert_info;
        // SAFETY: the certificate's time; the caller's.
        unsafe { set1_time(Some(&mut ci.enc.modified), &raw mut ci.validity.notBefore, tm) }
    }
}

ffi_export! {
    /// Sets the end of the validity to a copy of `tm`: 1, or 0.
    ///
    /// # Safety
    /// As for [`X509_set1_notBefore`].
    pub unsafe extern "C" fn X509_set1_notAfter(x: *mut X509, tm: *const ASN1_TIME) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(x) }) else { return 0 };
        if tm.is_null() {
            return 0;
        }
        let ci = &mut c.cert_info;
        // SAFETY: the certificate's time; the caller's.
        unsafe { set1_time(Some(&mut ci.enc.modified), &raw mut ci.validity.notAfter, tm) }
    }
}

ffi_export! {
    /// Sets the public key to `pkey`'s: 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `pkey` is NULL or a live key.
    pub unsafe extern "C" fn X509_set_pubkey(x: *mut X509, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(x) }) else { return 0 };
        // SAFETY: the certificate's slot; the caller's key.
        if unsafe { X509_PUBKEY_set(&raw mut c.cert_info.key, pkey) } == 0 {
            return 0;
        }
        c.cert_info.enc.modified = 1;
        1
    }
}

// The getters (`x509_set.c`, `x509_cmp.c`): the certificate's own fields.

/// Defines getters of a certificate's field: each returns `$fail` for a NULL certificate.
macro_rules! getters {
    ($(
        $(#[$attr:meta])*
        pub unsafe extern "C" fn $name:ident($x:ident: *$m:ident X509) -> $ret:ty = $fail:expr, |$c:ident| $body:expr;
    )*) => {$(
        ffi_export! {
            $(#[$attr])*
            ///
            /// # Safety
            /// `x` is NULL or a live certificate.
            pub unsafe extern "C" fn $name($x: *$m X509) -> $ret
            where failure = $fail, library = ERR_LIB_X509
            {
                // SAFETY: the caller's guarantee.
                let Some($c) = (unsafe { cert_of($x) }) else { return $fail };
                $body
            }
        }
    )*};
}

getters! {
    /// The version (`X509_VERSION_1` when it's left out).
    pub unsafe extern "C" fn X509_get_version(x: *const X509) -> c_long = 0, |c| {
        // SAFETY: its version, or NULL.
        unsafe { ASN1_INTEGER_get(c.cert_info.version) }
    };
    /// The start of the validity.
    pub unsafe extern "C" fn X509_get0_notBefore(x: *const X509) -> *const ASN1_TIME = ptr::null(), |c| c.cert_info.validity.notBefore;
    /// The end of the validity.
    pub unsafe extern "C" fn X509_get0_notAfter(x: *const X509) -> *const ASN1_TIME = ptr::null(), |c| c.cert_info.validity.notAfter;
    /// The start of the validity, to change in place.
    pub unsafe extern "C" fn X509_getm_notBefore(x: *const X509) -> *mut ASN1_TIME = ptr::null_mut(), |c| c.cert_info.validity.notBefore;
    /// The end of the validity, to change in place.
    pub unsafe extern "C" fn X509_getm_notAfter(x: *const X509) -> *mut ASN1_TIME = ptr::null_mut(), |c| c.cert_info.validity.notAfter;
    /// The key type of the signature algorithm (`EVP_PKEY_type` of its NID).
    pub unsafe extern "C" fn X509_get_signature_type(x: *const X509) -> c_int = NID_undef, |c| {
        // SAFETY: its object.
        let nid = unsafe { OBJ_obj2nid(c.sig_alg.algorithm) };
        // SAFETY: no preconditions.
        unsafe { EVP_PKEY_type(nid) }
    };
    /// The SubjectPublicKeyInfo.
    pub unsafe extern "C" fn X509_get_X509_PUBKEY(x: *const X509) -> *mut X509_PUBKEY = ptr::null_mut(), |c| c.cert_info.key;
    /// The extensions, or NULL without.
    pub unsafe extern "C" fn X509_get0_extensions(x: *const X509) -> *const stack_st_X509_EXTENSION = ptr::null(), |c| c.cert_info.extensions;
    /// The TBSCertificate's AlgorithmIdentifier.
    pub unsafe extern "C" fn X509_get0_tbs_sigalg(x: *const X509) -> *const X509_ALGOR = ptr::null(), |c| &raw const c.cert_info.signature;
    /// The issuer.
    pub unsafe extern "C" fn X509_get_issuer_name(x: *const X509) -> *mut X509_NAME = ptr::null_mut(), |c| c.cert_info.issuer;
    /// The subject.
    pub unsafe extern "C" fn X509_get_subject_name(x: *const X509) -> *mut X509_NAME = ptr::null_mut(), |c| c.cert_info.subject;
    /// The serial number, to change in place.
    pub unsafe extern "C" fn X509_get_serialNumber(x: *mut X509) -> *mut ASN1_INTEGER = ptr::null_mut(), |c| &raw mut c.cert_info.serial_number;
    /// The serial number.
    pub unsafe extern "C" fn X509_get0_serialNumber(x: *const X509) -> *const ASN1_INTEGER = ptr::null(), |c| &raw const c.cert_info.serial_number;
    /// The public key (the certificate keeps it), or NULL if it can't be decoded.
    pub unsafe extern "C" fn X509_get0_pubkey(x: *const X509) -> *mut EVP_PKEY = ptr::null_mut(), |c| {
        // SAFETY: its SubjectPublicKeyInfo.
        unsafe { X509_PUBKEY_get0(c.cert_info.key) }
    };
    /// The public key with a reference for the caller, or NULL.
    pub unsafe extern "C" fn X509_get_pubkey(x: *mut X509) -> *mut EVP_PKEY = ptr::null_mut(), |c| {
        // SAFETY: as above.
        unsafe { X509_PUBKEY_get(c.cert_info.key) }
    };
    /// The public key's BIT STRING.
    pub unsafe extern "C" fn X509_get0_pubkey_bitstr(x: *const X509) -> *mut ASN1_BIT_STRING = ptr::null_mut(), |c| {
        // SAFETY: its SubjectPublicKeyInfo, or NULL.
        unsafe { pubkey_of(c.cert_info.key) }.map_or(ptr::null_mut(), |p| p.public_key)
    };
    /// The issuer's hash (`X509_NAME_hash_ex`, without a library context).
    pub unsafe extern "C" fn X509_issuer_name_hash(x: *mut X509) -> c_ulong = 0, |c| {
        // SAFETY: its issuer.
        unsafe { X509_NAME_hash_ex(c.cert_info.issuer, ptr::null_mut(), ptr::null(), ptr::null_mut()) }
    };
    /// The issuer's MD5 hash (`X509_NAME_hash_old`).
    pub unsafe extern "C" fn X509_issuer_name_hash_old(x: *mut X509) -> c_ulong = 0, |c| {
        // SAFETY: as above.
        unsafe { X509_NAME_hash_old(c.cert_info.issuer) }
    };
    /// The subject's hash.
    pub unsafe extern "C" fn X509_subject_name_hash(x: *mut X509) -> c_ulong = 0, |c| {
        // SAFETY: its subject.
        unsafe { X509_NAME_hash_ex(c.cert_info.subject, ptr::null_mut(), ptr::null(), ptr::null_mut()) }
    };
    /// The subject's MD5 hash.
    pub unsafe extern "C" fn X509_subject_name_hash_old(x: *mut X509) -> c_ulong = 0, |c| {
        // SAFETY: as above.
        unsafe { X509_NAME_hash_old(c.cert_info.subject) }
    };
    /// The number of extensions.
    pub unsafe extern "C" fn X509_get_ext_count(x: *const X509) -> c_int = 0, |c| {
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_count(c.cert_info.extensions) }
    };
}

ffi_export! {
    /// The certificate's unique identifiers (NULL where absent), into `*piuid` and `*psuid`
    /// where given.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `piuid` and `psuid` are NULL or writable.
    pub unsafe extern "C" fn X509_get0_uids(x: *const X509, piuid: *mut *const ASN1_BIT_STRING, psuid: *mut *const ASN1_BIT_STRING)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(x) }) else { return };
        if !piuid.is_null() {
            // SAFETY: as above.
            unsafe { piuid.write(c.cert_info.issuer_uid) };
        }
        if !psuid.is_null() {
            // SAFETY: as above.
            unsafe { psuid.write(c.cert_info.subject_uid) };
        }
    }
}

// The extensions (`x509_ext.c`).

ffi_export! {
    /// The index of the next extension after `lastpos` with the NID, -1 for none, or -2 for an
    /// unknown NID.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_get_ext_by_NID(x: *const X509, nid: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let exts = unsafe { cert_of(x) }.map_or(ptr::null_mut(), |c| c.cert_info.extensions);
        // SAFETY: the certificate's extensions, or NULL.
        unsafe { X509v3_get_ext_by_NID(exts, nid, lastpos) }
    }
}

ffi_export! {
    /// The index of the next extension after `lastpos` with the object, or -1.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `obj` is NULL or a live object.
    pub unsafe extern "C" fn X509_get_ext_by_OBJ(x: *const X509, obj: *const ASN1_OBJECT, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let exts = unsafe { cert_of(x) }.map_or(ptr::null_mut(), |c| c.cert_info.extensions);
        // SAFETY: as above.
        unsafe { X509v3_get_ext_by_OBJ(exts, obj, lastpos) }
    }
}

ffi_export! {
    /// The index of the next extension after `lastpos` that is (`crit` nonzero) or isn't
    /// critical, or -1.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_get_ext_by_critical(x: *const X509, crit: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let exts = unsafe { cert_of(x) }.map_or(ptr::null_mut(), |c| c.cert_info.extensions);
        // SAFETY: as above.
        unsafe { X509v3_get_ext_by_critical(exts, crit, lastpos) }
    }
}

ffi_export! {
    /// The extension at `loc` (the certificate keeps it), or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_get_ext(x: *const X509, loc: c_int) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let exts = unsafe { cert_of(x) }.map_or(ptr::null_mut(), |c| c.cert_info.extensions);
        // SAFETY: as above.
        unsafe { X509v3_get_ext(exts, loc) }
    }
}

ffi_export! {
    /// Takes the extension at `loc` out (for the caller to free), freeing the list when it's
    /// left empty; NULL if there's none. As OpenSSL's, the encoding isn't marked changed.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_delete_ext(x: *mut X509, loc: c_int) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(x) }) else { return ptr::null_mut() };
        let sk = &mut c.cert_info.extensions;
        // SAFETY: the certificate's extensions, or NULL.
        let ret = unsafe { X509v3_delete_ext(*sk, loc) };
        // SAFETY: as above.
        if !sk.is_null() && unsafe { OPENSSL_sk_num(sk.cast()) } == 0 {
            // SAFETY: the certificate's empty list.
            unsafe { OPENSSL_sk_free(sk.cast()) };
            *sk = ptr::null_mut();
        }
        ret
    }
}

ffi_export! {
    /// Adds a copy of `ex` at `loc` (-1 for the end): 1, or 0. As OpenSSL's, the encoding
    /// isn't marked changed.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `ex` is NULL or a live extension.
    pub unsafe extern "C" fn X509_add_ext(x: *mut X509, ex: *mut X509_EXTENSION, loc: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(x) }) else { return 0 };
        // SAFETY: the certificate's slot; the caller's extension.
        c_int::from(!unsafe { X509v3_add_ext(&raw mut c.cert_info.extensions, ex, loc) }.is_null())
    }
}

ffi_export! {
    /// Adds an extension of `nid` encoding `value` (`X509V3_add1_i2d`, which `flags`
    /// direct): 1, 0, or -1.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `value` is NULL or a live value of the extension's
    /// type.
    pub unsafe extern "C" fn X509_add1_ext_i2d(x: *mut X509, nid: c_int, value: *mut c_void, crit: c_int, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(x) }) else { return 0 };
        // SAFETY: the certificate's list; the caller's value.
        unsafe { crate::x509v3::registry::X509V3_add1_i2d(&raw mut c.cert_info.extensions, nid, value, crit, flags) }
    }
}

ffi_export! {
    /// The certificate's type (`x509type.c`): what its key (`pkey`, or the certificate's) is
    /// and does (`EVP_PK_*`, `EVP_PKT_*`), and what signed it (`EVP_PKS_*`); 0 for none.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `pkey` is NULL or a live key.
    pub unsafe extern "C" fn X509_certificate_type(x: *const X509, pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if x.is_null() {
            return 0;
        }
        let pk = if pkey.is_null() {
            // SAFETY: the caller's certificate.
            unsafe { X509_get0_pubkey(x) }.cast_const()
        } else {
            pkey
        };
        if pk.is_null() {
            return 0;
        }
        // SAFETY: a live key.
        let mut ret = match unsafe { crate::evp::pkey::EVP_PKEY_get_id(pk) } {
            n if n == EVP_PKEY_RSA => EVP_PK_RSA | EVP_PKT_SIGN | EVP_PKT_ENC,
            n if n == EVP_PKEY_RSA_PSS => EVP_PK_RSA | EVP_PKT_SIGN,
            n if n == EVP_PKEY_DSA => EVP_PK_DSA | EVP_PKT_SIGN,
            n if n == EVP_PKEY_EC => EVP_PK_EC | EVP_PKT_SIGN | EVP_PKT_EXCH,
            n if n == EVP_PKEY_ED448 || n == EVP_PKEY_ED25519 => EVP_PKT_SIGN,
            n if n == EVP_PKEY_DH => EVP_PK_DH | EVP_PKT_EXCH,
            n if n == NID_id_GostR3410_2001
                || n == NID_id_GostR3410_2012_256
                || n == NID_id_GostR3410_2012_512 =>
            {
                EVP_PKT_EXCH | EVP_PKT_SIGN
            }
            _ => 0,
        };
        // SAFETY: the caller's certificate.
        let sig = unsafe { X509_get_signature_nid(x) };
        let mut pkey_nid = 0;
        // SAFETY: a NID; no digest output; a local.
        if sig != 0 && unsafe { OBJ_find_sigid_algs(sig, ptr::null_mut(), &raw mut pkey_nid) } != 0 {
            ret |= match pkey_nid {
                n if n == NID_rsaEncryption || n == NID_rsa => EVP_PKS_RSA,
                n if n == NID_dsa || n == NID_dsa_2 => EVP_PKS_DSA,
                n if n == NID_X9_62_id_ecPublicKey => EVP_PKS_EC,
                _ => 0,
            };
        }
        ret
    }
}

// Comparisons, hashes, and lookups (`x509_cmp.c`).

ffi_export! {
    /// Compares the serial numbers, then the issuers: <0, 0, or >0 (NULL sorts first).
    ///
    /// # Safety
    /// `a` and `b` are NULL or live certificates.
    pub unsafe extern "C" fn X509_issuer_and_serial_cmp(a: *const X509, b: *const X509) -> c_int
    where failure = -2, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(bc) = (unsafe { cert_of(b) }) else { return c_int::from(!a.is_null()) };
        // SAFETY: as above.
        let Some(ac) = (unsafe { cert_of(a) }) else { return -1 };
        // SAFETY: their serial numbers and issuers.
        unsafe { issuer_and_serial(ac, &raw const bc.cert_info.serial_number, bc.cert_info.issuer) }
    }
}

/// `X509_issuer_and_serial_cmp` against a serial number and an issuer.
///
/// # Safety
/// `serial` is a live INTEGER; `issuer` is NULL or a live name.
unsafe fn issuer_and_serial(
    a: &Cert,
    serial: *const ASN1_INTEGER,
    issuer: *const X509_NAME,
) -> c_int {
    // SAFETY: the certificate's; the caller's.
    let i = unsafe { ASN1_INTEGER_cmp(&raw const a.cert_info.serial_number, serial) };
    if i != 0 {
        return if i < 0 { -1 } else { 1 };
    }
    // SAFETY: the certificate's issuer; the caller's.
    unsafe { X509_NAME_cmp(a.cert_info.issuer, issuer) }
}

ffi_export! {
    /// The MD5 hash of the one-line issuer and the serial number's octets, its first four
    /// octets as a little-endian number, or 0.
    ///
    /// # Safety
    /// `a` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_issuer_and_serial_hash(a: *mut X509) -> c_ulong
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(a) }) else { return 0 };
        // SAFETY: no preconditions.
        let ctx = unsafe { EVP_MD_CTX_new() };
        let mut f: *mut c_char = ptr::null_mut();
        let mut digest: *mut EVP_MD = ptr::null_mut();
        let mut ret: c_ulong = 0;
        let mut md = [0u8; 16];
        if !ctx.is_null() {
            // SAFETY: the certificate's issuer.
            f = unsafe { X509_NAME_oneline(c.cert_info.issuer, ptr::null_mut(), 0) };
        }
        if !f.is_null() {
            // SAFETY: the certificate's library context and properties; a static name.
            digest = unsafe { EVP_MD_fetch(c.libctx, SN_md5.as_ptr(), c.propq) };
        }
        let serial = &c.cert_info.serial_number;
        let serial_len = usize::try_from(serial.length).unwrap_or(0);
        // SAFETY: the one-line issuer, a string (when made).
        let f_len = if f.is_null() { 0 } else { unsafe { CStr::from_ptr(f) }.count_bytes() };
        let ok = !digest.is_null()
            // SAFETY: the new context; the digest.
            && unsafe { EVP_DigestInit_ex(ctx, digest, ptr::null_mut()) } != 0
            // SAFETY: the one-line issuer, a string.
            && unsafe { EVP_DigestUpdate(ctx, f.cast(), f_len) } != 0
            // SAFETY: the serial number's octets.
            && unsafe { EVP_DigestUpdate(ctx, serial.data.cast(), serial_len) } != 0
            // SAFETY: room for MD5's 16 octets.
            && unsafe { EVP_DigestFinal_ex(ctx, md.as_mut_ptr(), ptr::null_mut()) } != 0;
        if ok {
            ret = c_ulong::from(u32::from_le_bytes([md[0], md[1], md[2], md[3]]));
        }
        // SAFETY: made above, or NULL.
        unsafe { mem::release(f.cast()) };
        // SAFETY: as above.
        unsafe { EVP_MD_free(digest) };
        // SAFETY: as above.
        unsafe { EVP_MD_CTX_free(ctx) };
        ret
    }
}

ffi_export! {
    /// Compares the issuers (`X509_NAME_cmp`).
    ///
    /// # Safety
    /// `a` and `b` are NULL or live certificates.
    pub unsafe extern "C" fn X509_issuer_name_cmp(a: *const X509, b: *const X509) -> c_int
    where failure = -2, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let na = unsafe { cert_of(a) }.map_or(ptr::null_mut(), |c| c.cert_info.issuer);
        // SAFETY: as above.
        let nb = unsafe { cert_of(b) }.map_or(ptr::null_mut(), |c| c.cert_info.issuer);
        // SAFETY: their issuers, or NULL.
        unsafe { X509_NAME_cmp(na, nb) }
    }
}

ffi_export! {
    /// Compares the subjects (`X509_NAME_cmp`).
    ///
    /// # Safety
    /// `a` and `b` are NULL or live certificates.
    pub unsafe extern "C" fn X509_subject_name_cmp(a: *const X509, b: *const X509) -> c_int
    where failure = -2, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let na = unsafe { cert_of(a) }.map_or(ptr::null_mut(), |c| c.cert_info.subject);
        // SAFETY: as above.
        let nb = unsafe { cert_of(b) }.map_or(ptr::null_mut(), |c| c.cert_info.subject);
        // SAFETY: their subjects, or NULL.
        unsafe { X509_NAME_cmp(na, nb) }
    }
}

/// The certificates of a stack, in order.
///
/// # Safety
/// `sk` is NULL or a live stack of certificates.
unsafe fn certs(sk: *const stack_st_X509) -> impl Iterator<Item = *mut X509> {
    // SAFETY: the caller's guarantee.
    let n = unsafe { OPENSSL_sk_num(sk.cast()) };
    // SAFETY: as above; an index within it.
    (0..n.max(0)).map(move |i| unsafe { OPENSSL_sk_value(sk.cast(), i) }.cast::<X509>())
}

ffi_export! {
    /// The first certificate of `sk` with the issuer and serial number, or NULL.
    ///
    /// # Safety
    /// `sk` is NULL or a live stack of certificates; `name` is NULL or a live name; `serial` is
    /// NULL or a live INTEGER.
    pub unsafe extern "C" fn X509_find_by_issuer_and_serial(sk: *mut stack_st_X509, name: *const X509_NAME, serial: *const ASN1_INTEGER) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        if sk.is_null() || serial.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        for x in unsafe { certs(sk) } {
            // SAFETY: a certificate of the stack.
            if let Some(c) = unsafe { cert_of(x) }
                // SAFETY: the caller's serial number and name.
                && unsafe { issuer_and_serial(c, serial, name) } == 0
            {
                return x;
            }
        }
        ptr::null_mut()
    }
}

ffi_export! {
    /// The first certificate of `sk` with the subject, or NULL.
    ///
    /// # Safety
    /// `sk` is NULL or a live stack of certificates; `name` is NULL or a live name.
    pub unsafe extern "C" fn X509_find_by_subject(sk: *mut stack_st_X509, name: *const X509_NAME) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        for x in unsafe { certs(sk) } {
            // SAFETY: a certificate of the stack.
            let subject = unsafe { cert_of(x) }.map_or(ptr::null_mut(), |c| c.cert_info.subject);
            // SAFETY: its subject; the caller's name.
            if unsafe { X509_NAME_cmp(subject, name) } == 0 {
                return x;
            }
        }
        ptr::null_mut()
    }
}

ffi_export! {
    /// Whether `pkey` is the private key of the certificate's public key: 1, or 0 with the
    /// reason (mismatched values, mismatched types, an unknown type).
    ///
    /// # Safety
    /// `cert` is NULL or a live certificate; `pkey` is NULL or a live key.
    pub unsafe extern "C" fn X509_check_private_key(cert: *const X509, pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let xk = unsafe { X509_get0_pubkey(cert) };
        if xk.is_null() {
            err::raise(ERR_LIB_X509, X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY, "X509_check_private_key");
            return 0;
        }
        // SAFETY: the certificate's key and the caller's.
        unsafe { check_private_key(xk, pkey) }
    }
}

/// `ossl_x509_check_private_key`.
///
/// # Safety
/// `x` and `pkey` are NULL or live keys.
pub(crate) unsafe fn check_private_key(x: *const EVP_PKEY, pkey: *const EVP_PKEY) -> c_int {
    const F: &str = "ossl_x509_check_private_key";
    if x.is_null() {
        err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, F);
        return 0;
    }
    // SAFETY: the caller's guarantee.
    match unsafe { EVP_PKEY_eq(x, pkey) } {
        1 => 1,
        0 => {
            err::raise(ERR_LIB_X509, X509_R_KEY_VALUES_MISMATCH, F);
            0
        }
        -1 => {
            err::raise(ERR_LIB_X509, X509_R_KEY_TYPE_MISMATCH, F);
            0
        }
        -2 => {
            err::raise(ERR_LIB_X509, X509_R_UNKNOWN_KEY_TYPE, F);
            0
        }
        _ => 0,
    }
}

/// `check_suite_b`: whether `pkey` is a Suite B key (P-256 or P-384) signing with
/// `sign_nid`'s algorithm (-1 for any) under `flags`, which a P-384 key narrows to 192-bit.
///
/// # Safety
/// `pkey` is NULL or a live key.
pub(crate) unsafe fn check_suite_b(
    pkey: *mut EVP_PKEY,
    sign_nid: c_int,
    pflags: &mut c_ulong,
) -> c_int {
    // SAFETY: the caller's key; a static name.
    if pkey.is_null() || unsafe { EVP_PKEY_is_a(pkey, c"EC".as_ptr()) } == 0 {
        return X509_V_ERR_SUITE_B_INVALID_ALGORITHM;
    }
    let mut name = [0 as c_char; 80];
    let mut len = 0usize;
    // SAFETY: as above; room for the name.
    if unsafe { EVP_PKEY_get_group_name(pkey, name.as_mut_ptr(), name.len(), &raw mut len) } == 0 {
        return X509_V_ERR_SUITE_B_INVALID_CURVE;
    }
    // SAFETY: the NUL-terminated name.
    let curve_nid = unsafe { OBJ_txt2nid(name.as_ptr()) };
    let flag = |f: c_int| c_ulong::from(f.cast_unsigned());
    if curve_nid == NID_secp384r1 {
        if sign_nid != -1 && sign_nid != NID_ecdsa_with_SHA384 {
            return X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM;
        }
        if *pflags & flag(X509_V_FLAG_SUITEB_192_LOS) == 0 {
            return X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED;
        }
        *pflags &= !flag(X509_V_FLAG_SUITEB_128_LOS_ONLY);
    } else if curve_nid == NID_X9_62_prime256v1 {
        if sign_nid != -1 && sign_nid != NID_ecdsa_with_SHA256 {
            return X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM;
        }
        if *pflags & flag(X509_V_FLAG_SUITEB_128_LOS_ONLY) == 0 {
            return X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED;
        }
    } else {
        return X509_V_ERR_SUITE_B_INVALID_CURVE;
    }
    X509_V_OK
}

ffi_export! {
    /// Checks `x` (or the chain's first certificate) and the chain against Suite B's rules
    /// under `flags`: `X509_V_OK`, or the error, with the failing certificate's depth in
    /// `*perror_depth` if given.
    ///
    /// # Safety
    /// `perror_depth` is NULL or writable; `x` is NULL or a live certificate; `chain` is NULL
    /// or a live stack of certificates (not NULL without `x`).
    pub unsafe extern "C" fn X509_chain_check_suiteb(perror_depth: *mut c_int, x: *mut X509, chain: *mut stack_st_X509, flags: c_ulong) -> c_int
    where failure = X509_V_ERR_SUITE_B_INVALID_ALGORITHM, library = ERR_LIB_X509
    {
        if flags & c_ulong::from(X509_V_FLAG_SUITEB_128_LOS.cast_unsigned()) == 0 {
            return X509_V_OK;
        }
        let mut tflags = flags;
        let (mut x, mut i) = if x.is_null() {
            // SAFETY: the caller's chain.
            (unsafe { OPENSSL_sk_value(chain.cast(), 0) }.cast::<X509>(), 1)
        } else {
            (x, 0)
        };
        // SAFETY: a certificate, or NULL.
        let mut pk = unsafe { X509_get0_pubkey(x) };
        if chain.is_null() {
            // SAFETY: its key, or NULL.
            return unsafe { check_suite_b(pk, -1, &mut tflags) };
        }
        let v3 = c_long::from(X509_VERSION_3);
        let rv = 'check: {
            // SAFETY: as above.
            if unsafe { X509_get_version(x) } != v3 {
                i = 0;
                break 'check X509_V_ERR_SUITE_B_INVALID_VERSION;
            }
            // SAFETY: as above.
            let rv = unsafe { check_suite_b(pk, -1, &mut tflags) };
            if rv != X509_V_OK {
                i = 0;
                break 'check rv;
            }
            // SAFETY: the caller's chain.
            let n = unsafe { OPENSSL_sk_num(chain.cast()) };
            while i < n {
                // SAFETY: a certificate.
                let sign_nid = unsafe { X509_get_signature_nid(x) };
                // SAFETY: an index within the chain.
                x = unsafe { OPENSSL_sk_value(chain.cast(), i) }.cast();
                // SAFETY: a certificate of the chain.
                if unsafe { X509_get_version(x) } != v3 {
                    break 'check X509_V_ERR_SUITE_B_INVALID_VERSION;
                }
                // SAFETY: as above.
                pk = unsafe { X509_get0_pubkey(x) };
                // SAFETY: its key, or NULL.
                let rv = unsafe { check_suite_b(pk, sign_nid, &mut tflags) };
                if rv != X509_V_OK {
                    break 'check rv;
                }
                i += 1;
            }
            // SAFETY: the last certificate.
            let sign_nid = unsafe { X509_get_signature_nid(x) };
            // SAFETY: its key.
            unsafe { check_suite_b(pk, sign_nid, &mut tflags) }
        };
        if rv == X509_V_OK {
            return rv;
        }
        let mut rv = rv;
        if (rv == X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM || rv == X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED) && i != 0 {
            i -= 1;
        }
        if rv == X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED && flags != tflags {
            rv = X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256;
        }
        if !perror_depth.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { perror_depth.write(i) };
        }
        rv
    }
}

ffi_export! {
    /// A copy of the chain holding a reference to each certificate, or NULL.
    ///
    /// # Safety
    /// `chain` is NULL or a live stack of certificates.
    pub unsafe extern "C" fn X509_chain_up_ref(chain: *mut stack_st_X509) -> *mut stack_st_X509
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let ret = unsafe { OPENSSL_sk_dup(chain.cast()) };
        if ret.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the copy.
        let n = unsafe { OPENSSL_sk_num(ret) };
        for i in 0..n {
            // SAFETY: an index within the copy.
            let x = unsafe { OPENSSL_sk_value(ret, i) }.cast::<X509>();
            // SAFETY: a certificate of the chain.
            if unsafe { X509_up_ref(x) } == 0 {
                for j in (0..i).rev() {
                    // SAFETY: an index within the copy.
                    let done = unsafe { OPENSSL_sk_value(ret, j) };
                    // SAFETY: a certificate with the reference taken above.
                    unsafe { X509_free(done.cast()) };
                }
                // SAFETY: the copy.
                unsafe { OPENSSL_sk_free(ret) };
                return ptr::null_mut();
            }
        }
        ret.cast()
    }
}

/// `X509_free` as a stack's free function.
unsafe extern "C" fn free_cert(x: *mut c_void) {
    // SAFETY: a certificate of the stack, which the stack owned.
    unsafe { X509_free(x.cast()) };
}

ffi_export! {
    /// Frees a stack of certificates and its certificates.
    ///
    /// # Safety
    /// `certs` is NULL or a live stack of certificates it owns.
    pub unsafe extern "C" fn OSSL_STACK_OF_X509_free(certs: *mut stack_st_X509)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { OPENSSL_sk_pop_free(certs.cast(), Some(free_cert)) };
    }
}

ffi_export! {
    /// Fills in missing parameters (DSA's) of `pkey` and the chain's keys from the first key of
    /// the chain that has them: 1, or 0.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `chain` is NULL or a live stack of certificates.
    pub unsafe extern "C" fn X509_get_pubkey_parameters(pkey: *mut EVP_PKEY, chain: *mut stack_st_X509) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        const F: &str = "X509_get_pubkey_parameters";
        // SAFETY: the caller's key.
        if !pkey.is_null() && unsafe { EVP_PKEY_missing_parameters(pkey) } == 0 {
            return 1;
        }
        // SAFETY: the caller's chain.
        let n = unsafe { OPENSSL_sk_num(chain.cast()) };
        let mut found = None;
        for i in 0..n {
            // SAFETY: an index within the chain.
            let x = unsafe { OPENSSL_sk_value(chain.cast(), i) }.cast::<X509>();
            // SAFETY: a certificate of the chain.
            let k = unsafe { X509_get0_pubkey(x) };
            if k.is_null() {
                err::raise(ERR_LIB_X509, X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY, F);
                return 0;
            }
            // SAFETY: its key.
            if unsafe { EVP_PKEY_missing_parameters(k) } == 0 {
                found = Some((i, k));
                break;
            }
        }
        let Some((i, ktmp)) = found else {
            err::raise(ERR_LIB_X509, X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN, F);
            return 0;
        };
        for j in (0..i).rev() {
            // SAFETY: an index within the chain.
            let x = unsafe { OPENSSL_sk_value(chain.cast(), j) }.cast::<X509>();
            // SAFETY: a certificate of the chain.
            let k = unsafe { X509_get0_pubkey(x) };
            // SAFETY: its key; the key with the parameters.
            if unsafe { EVP_PKEY_copy_parameters(k, ktmp) } == 0 {
                return 0;
            }
        }
        if pkey.is_null() {
            return 1;
        }
        // SAFETY: the caller's key; as above.
        unsafe { EVP_PKEY_copy_parameters(pkey, ktmp) }
    }
}

// Signing, verifying, and digests (`x_all.c`).

ffi_export! {
    /// Checks the certificate's signature with `r`: 1, 0 if it doesn't verify (or the two
    /// AlgorithmIdentifiers differ), -1 if it can't be checked.
    ///
    /// # Safety
    /// `a` is NULL or a live certificate; `r` is NULL or a live key.
    pub unsafe extern "C" fn X509_verify(a: *mut X509, r: *mut EVP_PKEY) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(a) }) else { return -1 };
        // SAFETY: the certificate's AlgorithmIdentifiers.
        if unsafe { X509_ALGOR_cmp(&raw const c.sig_alg, &raw const c.cert_info.signature) } != 0 {
            return 0;
        }
        // SAFETY: no preconditions.
        let it = unsafe { X509_CINF_it() };
        // SAFETY: the certificate's TBSCertificate, signature, and ID; the caller's key.
        unsafe {
            ASN1_item_verify_ex(it, &raw const c.sig_alg, &raw const c.signature, (&raw const c.cert_info).cast(), c.distinguishing_id, r, c.libctx, c.propq)
        }
    }
}

/// `X509_sign`'s and `X509_sign_ctx`'s start: a certificate with extensions becomes version 3,
/// and its TBSCertificate is marked changed.
fn prepare_signing(x: *mut X509, c: &mut Cert) -> bool {
    // SAFETY: the certificate's extensions, or NULL.
    if unsafe { OPENSSL_sk_num(c.cert_info.extensions.cast()) } > 0
        // SAFETY: the live certificate.
        && unsafe { X509_set_version(x, c_long::from(X509_VERSION_3)) } == 0
    {
        return false;
    }
    c.cert_info.enc.modified = 1;
    true
}

ffi_export! {
    /// Signs the certificate with `pkey` and `md`, setting both AlgorithmIdentifiers: the
    /// signature's length, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `pkey` is a live key; `md` is NULL or a digest.
    pub unsafe extern "C" fn X509_sign(x: *mut X509, pkey: *mut EVP_PKEY, md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(x) }) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "X509_sign");
            return 0;
        };
        if !prepare_signing(x, c) {
            return 0;
        }
        // SAFETY: no preconditions.
        let it = unsafe { X509_CINF_it() };
        // SAFETY: the certificate's fields; the caller's key and digest.
        unsafe {
            ASN1_item_sign_ex(it, &raw mut c.cert_info.signature, &raw mut c.sig_alg, &raw mut c.signature, (&raw const c.cert_info).cast(), ptr::null(), pkey, md, c.libctx, c.propq)
        }
    }
}

ffi_export! {
    /// Signs the certificate through `ctx`, initialised for signing: the signature's length,
    /// or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `ctx` is a live digest context with a key context.
    pub unsafe extern "C" fn X509_sign_ctx(x: *mut X509, ctx: *mut EVP_MD_CTX) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(x) }) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "X509_sign_ctx");
            return 0;
        };
        if !prepare_signing(x, c) {
            return 0;
        }
        // SAFETY: no preconditions.
        let it = unsafe { X509_CINF_it() };
        // SAFETY: the certificate's fields; the caller's context.
        unsafe {
            ASN1_item_sign_ctx(it, &raw mut c.cert_info.signature, &raw mut c.sig_alg, &raw mut c.signature, (&raw const c.cert_info).cast(), ctx)
        }
    }
}

ffi_export! {
    /// Decodes a certificate from a `FILE` (`ASN1_item_d2i_fp`).
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `x509` is NULL or holds NULL or a live certificate.
    pub unsafe extern "C" fn d2i_X509_fp(fp: *mut FILE, x509: *mut *mut X509) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_d2i_fp(it, fp, x509.cast()) }.cast()
    }
}

ffi_export! {
    /// Encodes a certificate to a `FILE`: 1, or 0.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `x509` is a live certificate.
    pub unsafe extern "C" fn i2d_X509_fp(fp: *mut FILE, x509: *const X509) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_fp(it, fp, x509.cast()) }
    }
}

ffi_export! {
    /// Decodes a certificate from a BIO (`ASN1_item_d2i_bio`).
    ///
    /// # Safety
    /// `bp` is a live BIO; `x509` is NULL or holds NULL or a live certificate.
    pub unsafe extern "C" fn d2i_X509_bio(bp: *mut BIO, x509: *mut *mut X509) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_d2i_bio(it, bp, x509.cast()) }.cast()
    }
}

ffi_export! {
    /// Encodes a certificate to a BIO: 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `x509` is a live certificate.
    pub unsafe extern "C" fn i2d_X509_bio(bp: *mut BIO, x509: *const X509) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_bio(it, bp, x509.cast()) }
    }
}

ffi_export! {
    /// The digest of the public key's octets (the BIT STRING's contents): 1, or 0.
    ///
    /// # Safety
    /// `data` is NULL or a live certificate; `type_` is a live digest; `md` has room for its
    /// output; `len` is NULL or writable.
    pub unsafe extern "C" fn X509_pubkey_digest(data: *const X509, type_: *const EVP_MD, md: *mut c_uchar, len: *mut c_uint) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let key = unsafe { X509_get0_pubkey_bitstr(data) };
        // SAFETY: the certificate's key, or NULL.
        let Some(k) = (unsafe { key.as_ref() }) else { return 0 };
        let n = usize::try_from(k.length).unwrap_or(0);
        // SAFETY: its octets; the caller's digest and room.
        unsafe { EVP_Digest(k.data.cast(), n, md, len, type_, ptr::null_mut()) }
    }
}

ffi_export! {
    /// The digest of the certificate's DER (its fingerprint): 1, or 0.
    ///
    /// # Safety
    /// `cert` is NULL or a live certificate; `md` is a live digest; `data` has room for its
    /// output; `len` is NULL or writable.
    pub unsafe extern "C" fn X509_digest(cert: *const X509, md: *const EVP_MD, data: *mut c_uchar, len: *mut c_uint) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(cert) }) else { return 0 };
        // The cached SHA-1 fingerprint, as OpenSSL answers once the cache is filled.
        if let Some(sha1) = c.cache.sha1_fingerprint()
            // SAFETY: the caller's digest.
            && !md.is_null() && unsafe { crate::evp::digest::EVP_MD_is_a(md, c"SHA1".as_ptr()) } != 0
        {
            if !len.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { len.write(20) };
            }
            // SAFETY: the caller's room for a SHA-1 digest.
            unsafe { ptr::copy_nonoverlapping(sha1.as_ptr(), data, sha1.len()) };
            return 1;
        }
        // SAFETY: no preconditions.
        let it = unsafe { X509_it() };
        // SAFETY: the certificate, of the item; the caller's digest and room.
        unsafe { item_digest_ex(it, md, cert.cast_mut().cast(), data, len, c.libctx, c.propq) }
    }
}

ffi_export! {
    /// The certificate's digest with its signature's digest (for RSA-PSS, its parameters'; a
    /// fallback for EdDSA and others without one, saying so in `*md_is_fallback`), and that
    /// digest in `*md_used` (the caller frees it); NULL on failure.
    ///
    /// # Safety
    /// `cert` is NULL or a live certificate; `md_used` and `md_is_fallback` are NULL or writable.
    pub unsafe extern "C" fn X509_digest_sig(cert: *const X509, md_used: *mut *mut EVP_MD, md_is_fallback: *mut c_int) -> *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        const F: &str = "X509_digest_sig";
        if !md_used.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { md_used.write(ptr::null_mut()) };
        }
        if !md_is_fallback.is_null() {
            // SAFETY: as above.
            unsafe { md_is_fallback.write(0) };
        }
        // SAFETY: as above.
        let Some(c) = (unsafe { cert_of(cert) }) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, F);
            return ptr::null_mut();
        };
        let (mut mdnid, mut pknid) = (NID_undef, NID_undef);
        // SAFETY: the certificate.
        let signid = unsafe { X509_get_signature_nid(cert) };
        // SAFETY: writable NIDs.
        if unsafe { OBJ_find_sigid_algs(signid, &raw mut mdnid, &raw mut pknid) } == 0 {
            err::raise(ERR_LIB_X509, X509_R_UNKNOWN_SIGID_ALGS, F);
            return ptr::null_mut();
        }
        let md: *mut EVP_MD = if mdnid == NID_undef {
            if pknid == EVP_PKEY_RSA_PSS {
                // SAFETY: the certificate's AlgorithmIdentifier.
                let mmd = unsafe { pss_digest(&raw const c.sig_alg) };
                if mmd.is_null() {
                    err::raise(ERR_LIB_X509, X509_R_UNSUPPORTED_ALGORITHM, F);
                    return ptr::null_mut();
                }
                // SAFETY: a digest.
                let name = unsafe { EVP_MD_get0_name(mmd) };
                // SAFETY: the certificate's library context and properties; the digest's name.
                let md = unsafe { EVP_MD_fetch(c.libctx, name, c.propq) };
                if md.is_null() {
                    return ptr::null_mut();
                }
                md
            } else if pknid != NID_undef {
                let name = match pknid {
                    NID_ED25519 => c"SHA512",
                    NID_ED448 => c"SHAKE256",
                    _ => c"SHA256",
                };
                // SAFETY: as above; a static name.
                let md = unsafe { EVP_MD_fetch(c.libctx, name.as_ptr(), c.propq) };
                if md.is_null() {
                    return ptr::null_mut();
                }
                if !md_is_fallback.is_null() {
                    // SAFETY: the caller's guarantee.
                    unsafe { md_is_fallback.write(1) };
                }
                md
            } else {
                err::raise(ERR_LIB_X509, X509_R_UNSUPPORTED_ALGORITHM, F);
                return ptr::null_mut();
            }
        } else {
            // SAFETY: a NID.
            let sn = unsafe { OBJ_nid2sn(mdnid) };
            // SAFETY: as above; a name from the table.
            let mut md = if sn.is_null() { ptr::null_mut() } else { unsafe { EVP_MD_fetch(c.libctx, sn, c.propq) } };
            if md.is_null() && !sn.is_null() {
                // SAFETY: as above.
                md = unsafe { EVP_get_digestbyname(sn) }.cast_mut();
            }
            if md.is_null() {
                err::raise(ERR_LIB_X509, X509_R_UNSUPPORTED_ALGORITHM, F);
                return ptr::null_mut();
            }
            md
        };
        let mut hash = [0u8; rustyssl_abi::EVP_MAX_MD_SIZE as usize];
        let mut len: c_uint = 0;
        // SAFETY: the certificate; the digest; room for any digest.
        let new = if unsafe { X509_digest(cert, md, hash.as_mut_ptr(), &raw mut len) } == 0 {
            ptr::null_mut()
        } else {
            // SAFETY: no preconditions.
            unsafe { ASN1_OCTET_STRING_new() }
        };
        let ilen = c_int::try_from(len).unwrap_or(0);
        // SAFETY: the new string; the digest's `len` octets.
        if !new.is_null() && unsafe { ASN1_OCTET_STRING_set(new, hash.as_ptr(), ilen) } != 0 {
            if md_used.is_null() {
                // SAFETY: fetched above (or a static digest, which freeing ignores).
                unsafe { EVP_MD_free(md) };
            } else {
                // SAFETY: the caller's guarantee.
                unsafe { md_used.write(md) };
            }
            return new;
        }
        // SAFETY: made above, or NULL.
        unsafe { ASN1_OCTET_STRING_free(new) };
        // SAFETY: as above.
        unsafe { EVP_MD_free(md) };
        ptr::null_mut()
    }
}

/// The digest an RSA-PSS AlgorithmIdentifier's parameters name (as
/// `ossl_rsa_pss_get_param_unverified` reads them, with the MGF1 digest known too), or NULL.
///
/// # Safety
/// `alg` is a live AlgorithmIdentifier.
unsafe fn pss_digest(alg: *const X509_ALGOR) -> *const EVP_MD {
    // SAFETY: the caller's guarantee.
    let pss = unsafe { crate::evp::pkey::rsa::pss_decode(alg) };
    // SAFETY: just decoded, or NULL.
    let Some(p) = (unsafe { pss.as_ref() }) else {
        return ptr::null();
    };
    // SAFETY: its AlgorithmIdentifiers.
    let md = unsafe { crate::rsa_pmeth::md_of_algor(p.hashAlgorithm) };
    // SAFETY: as above.
    let mgf1md = if md.is_null() {
        ptr::null()
    } else {
        // SAFETY: as above.
        unsafe { crate::rsa_pmeth::md_of_algor(p.maskHash) }
    };
    // SAFETY: decoded above.
    unsafe { crate::rsa_asn1::RSA_PSS_PARAMS_free(pss) };
    if mgf1md.is_null() { ptr::null() } else { md }
}

// Times (`x509_vfy.c`).

ffi_export! {
    /// Compares a strict time (`YYMMDDHHMMSSZ` or `YYYYMMDDHHMMSSZ`) with `*cmp_time` (now
    /// for NULL): -1 if it's not later, 1 if it is, 0 for a time of any other form or an error.
    ///
    /// # Safety
    /// `ctm` is NULL or a live time; `cmp_time` is NULL or readable.
    pub unsafe extern "C" fn X509_cmp_time(ctm: *const ASN1_TIME, cmp_time: *mut time_t) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { ctm.as_ref() }) else { return 0 };
        let want = match t.type_ {
            V_ASN1_UTCTIME => 13,
            V_ASN1_GENERALIZEDTIME => 15,
            _ => return 0,
        };
        if t.length != want || t.data.is_null() {
            return 0;
        }
        // SAFETY: the time's `length` octets.
        let d = unsafe { core::slice::from_raw_parts(t.data, usize::try_from(want).unwrap_or(0)) };
        let Some((&last, digits)) = d.split_last() else { return 0 };
        if !digits.iter().all(u8::is_ascii_digit) || last != b'Z' {
            return 0;
        }
        // SAFETY: the caller's time, or NULL.
        let now = unsafe { X509_time_adj(ptr::null_mut(), 0, cmp_time) };
        if now.is_null() {
            return 0;
        }
        let (mut day, mut sec) = (0, 0);
        // SAFETY: both times; writable outputs.
        let ret = if unsafe { ASN1_TIME_diff(&raw mut day, &raw mut sec, ctm, now) } == 0 {
            0
        } else if day >= 0 && sec >= 0 {
            -1
        } else {
            1
        };
        // SAFETY: made above.
        unsafe { ASN1_TIME_free(now) };
        ret
    }
}

ffi_export! {
    /// [`X509_cmp_time`] with now.
    ///
    /// # Safety
    /// `ctm` is NULL or a live time.
    pub unsafe extern "C" fn X509_cmp_current_time(ctm: *const ASN1_TIME) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_cmp_time(ctm, ptr::null_mut()) }
    }
}

ffi_export! {
    /// Sets `s` (a new time for NULL) to now plus `adj` seconds: it, or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live time.
    pub unsafe extern "C" fn X509_gmtime_adj(s: *mut ASN1_TIME, adj: c_long) -> *mut ASN1_TIME
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_time_adj(s, adj, ptr::null_mut()) }
    }
}

ffi_export! {
    /// Sets `s` (a new time for NULL) to `*in_tm` (now for NULL) plus `offset_sec` seconds:
    /// it, or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live time; `in_tm` is NULL or readable.
    pub unsafe extern "C" fn X509_time_adj(s: *mut ASN1_TIME, offset_sec: c_long, in_tm: *mut time_t) -> *mut ASN1_TIME
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_time_adj_ex(s, 0, offset_sec, in_tm) }
    }
}

ffi_export! {
    /// Sets `s` (a new time for NULL) to `*in_tm` (now for NULL) plus the days and seconds,
    /// keeping a UTCTime or GeneralizedTime its type: it, or NULL.
    ///
    /// # Safety
    /// As for [`X509_time_adj`].
    pub unsafe extern "C" fn X509_time_adj_ex(s: *mut ASN1_TIME, offset_day: c_int, offset_sec: c_long, in_tm: *mut time_t) -> *mut ASN1_TIME
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        let t = if in_tm.is_null() {
            // SAFETY: no preconditions.
            unsafe { libc::time(ptr::null_mut()) }
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { in_tm.read() }
        };
        // SAFETY: as above.
        if let Some(st) = unsafe { s.as_ref() }
            && st.flags & c_long::from(ASN1_STRING_FLAG_MSTRING) == 0
        {
            if st.type_ == V_ASN1_UTCTIME {
                // SAFETY: the caller's UTCTime.
                return unsafe { ASN1_UTCTIME_adj(s, t, offset_day, offset_sec) };
            }
            if st.type_ == V_ASN1_GENERALIZEDTIME {
                // SAFETY: the caller's GeneralizedTime.
                return unsafe { ASN1_GENERALIZEDTIME_adj(s, t, offset_day, offset_sec) };
            }
        }
        // SAFETY: the caller's time, or NULL.
        unsafe { ASN1_TIME_adj(s, t, offset_day, offset_sec) }
    }
}

// The default places (`x509_def.c`), under `OPENSSLDIR`.

/// `OPENSSLDIR` followed by `suffix`, made once.
fn under_openssldir(cell: &'static OnceLock<CString>, suffix: &str) -> *const c_char {
    cell.get_or_init(|| {
        let mut path = crate::version::openssldir().to_bytes().to_vec();
        path.extend_from_slice(suffix.as_bytes());
        CString::new(path).unwrap_or_default()
    })
    .as_ptr()
}

ffi_export! {
    /// The default directory of private keys, `OPENSSLDIR/private`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn X509_get_default_private_dir() -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_X509
    {
        static DIR: OnceLock<CString> = OnceLock::new();
        under_openssldir(&DIR, "/private")
    }
}

ffi_export! {
    /// The default certificate area, `OPENSSLDIR`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn X509_get_default_cert_area() -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_X509
    {
        crate::version::openssldir().as_ptr()
    }
}

ffi_export! {
    /// The default directory of certificates, `OPENSSLDIR/certs`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn X509_get_default_cert_dir() -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_X509
    {
        static DIR: OnceLock<CString> = OnceLock::new();
        under_openssldir(&DIR, "/certs")
    }
}

ffi_export! {
    /// The default file of certificates, `OPENSSLDIR/cert.pem`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn X509_get_default_cert_file() -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_X509
    {
        static FILE_: OnceLock<CString> = OnceLock::new();
        under_openssldir(&FILE_, "/cert.pem")
    }
}

ffi_export! {
    /// The environment variable that overrides the directory of certificates, `SSL_CERT_DIR`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn X509_get_default_cert_dir_env() -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_X509
    {
        c"SSL_CERT_DIR".as_ptr()
    }
}

ffi_export! {
    /// The environment variable that overrides the file of certificates, `SSL_CERT_FILE`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn X509_get_default_cert_file_env() -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_X509
    {
        c"SSL_CERT_FILE".as_ptr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: the getters, setters, and comparisons of a NULL certificate, which
    /// OpenSSL reads through, answer NULL, 0, or nothing; a NULL time compares as an error.
    #[test]
    fn null_certificates_are_safe() {
        let x: *mut X509 = ptr::null_mut();
        // SAFETY: NULL where OpenSSL dereferences it.
        assert_eq!(unsafe { X509_add1_ext_i2d(x, 0, ptr::null_mut(), 0, 0) }, 0);
        // SAFETY: NULL where OpenSSL dereferences it.
        assert!(unsafe { X509_get_subject_name(x) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { X509_get_serialNumber(x) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { X509_get0_notAfter(x) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { X509_get_version(x) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_get_signature_nid(x) }, NID_undef);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_get_ext_count(x) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_up_ref(x) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_verify(x, ptr::null_mut()) }, -1);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_subject_name_cmp(x, x) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_issuer_and_serial_hash(x) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_cmp_time(ptr::null(), ptr::null_mut()) }, 0);
        let mut sig = ptr::null();
        // SAFETY: as above; a local.
        unsafe { X509_get0_signature(&raw mut sig, ptr::null_mut(), x) };
        assert!(sig.is_null());
        // SAFETY: as above.
        let found =
            unsafe { X509_find_by_issuer_and_serial(ptr::null_mut(), ptr::null(), ptr::null()) };
        assert!(found.is_null());
    }

    /// A new certificate counts its references: `X509_up_ref` adds one, and it lives until
    /// each is freed.
    #[test]
    #[cfg_attr(miri, ignore = "makes a lock, which Miri can't")]
    fn references_are_counted() {
        // SAFETY: no preconditions.
        let x = unsafe { X509_new() };
        assert!(!x.is_null());
        // SAFETY: the new certificate.
        assert_eq!(unsafe { X509_up_ref(x) }, 1);
        // SAFETY: as above, with two references.
        unsafe { X509_free(x) };
        // SAFETY: as above, still alive.
        assert_eq!(unsafe { X509_set_version(x, 2) }, 1);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_get_version(x) }, 2);
        // SAFETY: the last reference.
        unsafe { X509_free(x) };
    }
}
