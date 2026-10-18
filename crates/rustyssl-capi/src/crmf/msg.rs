//! Building and checking request messages (`crmf_lib.c`): the controls and registration info,
//! the template, validity, extensions, request IDs, proof-of-possession (made and verified),
//! central key generation, and the encrypted values and keys a CA sends back.

use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_INTEGER, ASN1_OCTET_STRING, ASN1_R_INVALID_NUMBER, ASN1_R_TOO_LARGE, ASN1_R_TOO_SMALL,
    ASN1_TIME, ASN1_UTF8STRING, CMS_EnvelopedData, CRMF_R_ERROR_DECODING_CERTIFICATE,
    CRMF_R_ERROR_DECODING_ENCRYPTEDKEY, CRMF_R_ERROR_DECRYPTING_ENCRYPTEDKEY,
    CRMF_R_ERROR_DECRYPTING_ENCRYPTEDVALUE, CRMF_R_ERROR_DECRYPTING_SYMMETRIC_KEY,
    CRMF_R_ERROR_SETTING_PURPOSE, CRMF_R_ERROR_VERIFYING_ENCRYPTEDKEY, CRMF_R_MALFORMED_IV,
    CRMF_R_NULL_ARGUMENT, CRMF_R_POPO_INCONSISTENT_CENTRAL_KEYGEN,
    CRMF_R_POPO_INCONSISTENT_PUBLIC_KEY, CRMF_R_POPO_MISSING, CRMF_R_POPO_MISSING_PUBLIC_KEY,
    CRMF_R_POPO_MISSING_SUBJECT, CRMF_R_POPO_RAVERIFIED_NOT_ACCEPTED,
    CRMF_R_POPOSKINPUT_NOT_SUPPORTED, CRMF_R_UNSUPPORTED_CIPHER,
    CRMF_R_UNSUPPORTED_METHOD_FOR_CREATING_POPO, CRMF_R_UNSUPPORTED_POPO_METHOD, ERR_LIB_CRMF,
    ERR_R_PASSED_INVALID_ARGUMENT, EVP_MD, EVP_PKEY, GEN_DIRNAME, GENERAL_NAME, LN_cmKGA,
    NID_cmKGA, NID_ext_key_usage, NID_id_regCtrl_authenticator, NID_id_regCtrl_oldCertID,
    NID_id_regCtrl_pkiPublicationInfo, NID_id_regCtrl_protocolEncrKey, NID_id_regCtrl_regToken,
    NID_id_regInfo_certReq, NID_id_regInfo_utf8Pairs, OSSL_CRMF_CERTID, OSSL_CRMF_CERTREQUEST,
    OSSL_CRMF_CERTTEMPLATE, OSSL_CRMF_ENCRYPTEDKEY, OSSL_CRMF_ENCRYPTEDVALUE, OSSL_CRMF_MSG,
    OSSL_CRMF_MSGS, OSSL_CRMF_PKIPUBLICATIONINFO, OSSL_CRMF_POPO_KEYENC, OSSL_CRMF_POPO_NONE,
    OSSL_CRMF_POPO_RAVERIFIED, OSSL_CRMF_POPO_SIGNATURE, OSSL_CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE,
    OSSL_CRMF_PUB_ACTION_DONTPUBLISH, OSSL_CRMF_PUB_ACTION_PLEASEPUBLISH,
    OSSL_CRMF_PUB_METHOD_DONTCARE, OSSL_CRMF_PUB_METHOD_LDAP, OSSL_CRMF_SINGLEPUBINFO,
    OSSL_CRMF_SUBSEQUENTMESSAGE_ENCRCERT, OSSL_LIB_CTX, SN_cmKGA, X509, X509_EXTENSION, X509_NAME,
    X509_PUBKEY, X509_PURPOSE, X509_REQ, X509_STORE, X509_TRUST_COMPAT, stack_st_X509,
    stack_st_X509_EXTENSION,
};

use super::asn::{
    Atav, CertId, CertRequest, CertTemplate, Choice, EncryptedValue, Msg, OSSL_CRMF_CERTID_dup,
    OSSL_CRMF_CERTID_free, OSSL_CRMF_CERTID_new, OSSL_CRMF_ENCRYPTEDKEY_new,
    OSSL_CRMF_PKIPUBLICATIONINFO_it, OptionalValidity, PkiPublicationInfo, PopoSigningKey,
    SinglePubInfo, Stack, attribute_type_and_value_it, cert_request_it, dup_of, free_of, new_of,
    of, optional_validity_it, popo_it, popo_priv_key_it, popo_signing_key_input_it,
    popo_signing_key_it,
};
use crate::asn1::any::ASN1_TYPE_get_octetstring;
use crate::asn1::integer::{ASN1_INTEGER_dup, ASN1_INTEGER_get_int64, ASN1_INTEGER_set};
use crate::asn1::sign::{ASN1_item_sign_ex, ASN1_item_verify_ex};
use crate::asn1::string::{ASN1_INTEGER_free, ASN1_INTEGER_new, ASN1_STRING_dup};
use crate::asn1::tpl::io::ASN1_item_d2i_bio;
use crate::asn1::tpl::items::ASN1_NULL_new;
use crate::bio::BIO_free;
use crate::cms::env::CMS_EnvelopedData_decrypt;
use crate::cms::sd::{CMS_SignedData_free, CMS_SignedData_verify};
use crate::err::{self, ERR_clear_error, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::asymcipher::{EVP_PKEY_decrypt, EVP_PKEY_decrypt_init};
use crate::evp::cipher::{
    EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_block_size, EVP_CIPHER_get_iv_length,
    EVP_CIPHER_get_key_length,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_set_padding, EVP_DecryptFinal,
    EVP_DecryptInit, EVP_DecryptUpdate,
};
use crate::evp::legacy_cipher::EVP_get_cipherbyname;
use crate::evp::pkey::EVP_PKEY_get_default_digest_name;
use crate::evp::pkey::d2i::{d2i_AutoPrivateKey_ex, d2i_PrivateKey_ex_bio};
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey};
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::objects::{ASN1_OBJECT_free, OBJ_nid2obj, OBJ_nid2sn, OBJ_obj2nid, OBJ_obj2txt};
use crate::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_value,
};
use crate::x509::cert::{X509_free, X509_new_ex, check_private_key, d2i_X509, d2i_X509_bio};
use crate::x509::ext::X509_EXTENSION_free;
use crate::x509::name::X509_NAME_set;
use crate::x509::pubkey::{
    X509_PUBKEY_dup, X509_PUBKEY_eq, X509_PUBKEY_get0, X509_PUBKEY_get0_param, X509_PUBKEY_set,
};
use crate::x509::purpose::{
    X509_PURPOSE_add, X509_PURPOSE_get_by_sname, X509_PURPOSE_get_unused_id, X509_get_ext_d2i,
};
use crate::x509::store::{X509_STORE_get0_param, X509_STORE_set_purpose};
use crate::x509::vpm::X509_VERIFY_PARAM_get_purpose;
use crate::x509v3::genn::GENERAL_NAME_free;

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_CRMF, reason, f);
}

/// The value of the message's attribute `nid` among its controls. As in OpenSSL, the
/// `get0_regInfo` functions search the controls too, never the registration info, so what
/// their `set1` twins add isn't found.
///
/// # Safety
/// `msg` is NULL or a live message.
unsafe fn get0_atav(msg: *const OSSL_CRMF_MSG, nid: c_int) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let Some(m) = (unsafe { of::<Msg, _>(msg) }) else {
        return ptr::null_mut();
    };
    // SAFETY: its request, or NULL.
    let Some(cr) = (unsafe { m.cert_req.as_ref() }) else {
        return ptr::null_mut();
    };
    let list = cr.controls;
    // SAFETY: the list, or NULL (0).
    let n = unsafe { OPENSSL_sk_num(list) };
    for i in 0..n {
        // SAFETY: an index in range.
        let a: *mut Atav = unsafe { OPENSSL_sk_value(list, i) }.cast();
        // SAFETY: an attribute of the list.
        if let Some(a) = unsafe { a.as_ref() }
            // SAFETY: its type.
            && unsafe { OBJ_obj2nid(a.type_) } == nid
        {
            return a.value;
        }
    }
    ptr::null_mut()
}

/// Pushes the attribute onto the list in `*slot`, made if need be (and removed again on
/// failure).
///
/// # Safety
/// `*slot` is NULL or a live list; `atav` a live attribute.
unsafe fn push0(slot: &mut *mut Stack, atav: *mut Atav) -> bool {
    let made = slot.is_null();
    if made {
        // SAFETY: no preconditions.
        *slot = unsafe { OPENSSL_sk_new_null() };
        if slot.is_null() {
            return false;
        }
    }
    // SAFETY: the list; the attribute, which it takes.
    if unsafe { OPENSSL_sk_push(*slot, atav.cast()) } > 0 {
        return true;
    }
    if made {
        // SAFETY: the list made here.
        unsafe { OPENSSL_sk_free(*slot) };
        *slot = ptr::null_mut();
    }
    false
}

/// `OSSL_CRMF_MSG_set1_<ctrlinf>_<atyp>`'s work: a new attribute `nid` holding `value` (taken
/// over) pushed onto the message's controls or registration info.
///
/// # Safety
/// `msg` is a live message; `value` NULL or what the attribute type holds.
unsafe fn set1_atav(
    msg: *mut OSSL_CRMF_MSG,
    nid: c_int,
    value: *mut c_void,
    reg_info: bool,
) -> bool {
    let atav: *mut Atav = new_of(attribute_type_and_value_it).cast();
    // SAFETY: the attribute made here, or NULL.
    let Some(a) = (unsafe { atav.as_mut() }) else {
        // SAFETY: the copy, which no attribute took.
        unsafe { free_value(nid, value) };
        return false;
    };
    // SAFETY: a known NID.
    a.type_ = unsafe { OBJ_nid2obj(nid) };
    a.value = value;
    if a.type_.is_null() || value.is_null() {
        // SAFETY: the attribute made here, with its value.
        unsafe { free_of(atav.cast(), attribute_type_and_value_it) };
        return false;
    }
    // SAFETY: the caller's message.
    let m = unsafe { of::<Msg, _>(msg) };
    let ok = if reg_info {
        match m {
            Some(m) => {
                // SAFETY: its registration info, or NULL.
                unsafe { push0(&mut m.reg_info, atav) }
            }
            None => {
                raise(CRMF_R_NULL_ARGUMENT, "OSSL_CRMF_MSG_push0_regInfo");
                false
            }
        }
    } else {
        // SAFETY: its request, or NULL.
        match m.and_then(|m| unsafe { m.cert_req.as_mut() }) {
            // SAFETY: its controls, or NULL.
            Some(cr) => unsafe { push0(&mut cr.controls, atav) },
            None => {
                raise(CRMF_R_NULL_ARGUMENT, "OSSL_CRMF_MSG_push0_regCtrl");
                false
            }
        }
    };
    if !ok {
        // SAFETY: the attribute made here, with its value.
        unsafe { free_of(atav.cast(), attribute_type_and_value_it) };
    }
    ok
}

/// Frees a copied value that no attribute took (by the type it is).
///
/// # Safety
/// `value` is NULL or a value of the attribute type `nid`.
unsafe fn free_value(nid: c_int, value: *mut c_void) {
    if value.is_null() {
        return;
    }
    // A throwaway attribute frees it as the template engine would.
    let atav: *mut Atav = new_of(attribute_type_and_value_it).cast();
    // SAFETY: the attribute made here, or NULL.
    if let Some(a) = unsafe { atav.as_mut() } {
        // SAFETY: a known NID.
        a.type_ = unsafe { OBJ_nid2obj(nid) };
        a.value = value;
        // SAFETY: as above.
        unsafe { free_of(atav.cast(), attribute_type_and_value_it) };
    }
}

/// `OSSL_CRMF_ENCRYPTEDKEY_ENVELOPEDDATA` (`crmf_local.h`), the EncryptedKey CHOICE's selector for
/// an EnvelopedData.
pub(crate) const OSSL_CRMF_ENCRYPTEDKEY_ENVELOPEDDATA: c_int = 1;

ffi_export! {
    /// The message's `id-regCtrl-regToken`, or NULL.
    ///
    /// # Safety
    /// `msg` is NULL or a live message.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_get0_regCtrl_regToken(msg: *const OSSL_CRMF_MSG) -> *mut ASN1_UTF8STRING
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0_atav(msg, NID_id_regCtrl_regToken) }.cast()
    }
}

ffi_export! {
    /// Adds a copy of `tok` as the message's `id-regCtrl-regToken`: 1, or 0.
    ///
    /// # Safety
    /// `msg` is NULL or a live message; `tok` NULL or a live value.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_set1_regCtrl_regToken(msg: *mut OSSL_CRMF_MSG, tok: *const ASN1_UTF8STRING) -> c_int
    where failure = 0, library = ERR_LIB_CRMF
    {
        let in_ = tok;
        if msg.is_null() || in_.is_null() {
            return 0;
        }
        // SAFETY: the caller's value.
        let value: *mut c_void = unsafe { ASN1_STRING_dup(in_.cast()) }.cast();
        // SAFETY: the caller's message; the copy, which the attribute takes.
        c_int::from(unsafe { set1_atav(msg, NID_id_regCtrl_regToken, value, false) })
    }
}

ffi_export! {
    /// The message's `id-regCtrl-authenticator`, or NULL.
    ///
    /// # Safety
    /// `msg` is NULL or a live message.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_get0_regCtrl_authenticator(msg: *const OSSL_CRMF_MSG) -> *mut ASN1_UTF8STRING
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0_atav(msg, NID_id_regCtrl_authenticator) }.cast()
    }
}

ffi_export! {
    /// Adds a copy of `auth` as the message's `id-regCtrl-authenticator`: 1, or 0.
    ///
    /// # Safety
    /// `msg` is NULL or a live message; `auth` NULL or a live value.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_set1_regCtrl_authenticator(msg: *mut OSSL_CRMF_MSG, auth: *const ASN1_UTF8STRING) -> c_int
    where failure = 0, library = ERR_LIB_CRMF
    {
        let in_ = auth;
        if msg.is_null() || in_.is_null() {
            return 0;
        }
        // SAFETY: the caller's value.
        let value: *mut c_void = unsafe { ASN1_STRING_dup(in_.cast()) }.cast();
        // SAFETY: the caller's message; the copy, which the attribute takes.
        c_int::from(unsafe { set1_atav(msg, NID_id_regCtrl_authenticator, value, false) })
    }
}

ffi_export! {
    /// The message's `id-regCtrl-pkiPublicationInfo`, or NULL.
    ///
    /// # Safety
    /// `msg` is NULL or a live message.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo(msg: *const OSSL_CRMF_MSG) -> *mut OSSL_CRMF_PKIPUBLICATIONINFO
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0_atav(msg, NID_id_regCtrl_pkiPublicationInfo) }.cast()
    }
}

ffi_export! {
    /// Adds a copy of `pi` as the message's `id-regCtrl-pkiPublicationInfo`: 1, or 0.
    ///
    /// # Safety
    /// `msg` is NULL or a live message; `pi` NULL or a live value.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo(msg: *mut OSSL_CRMF_MSG, pi: *const OSSL_CRMF_PKIPUBLICATIONINFO) -> c_int
    where failure = 0, library = ERR_LIB_CRMF
    {
        let in_ = pi;
        if msg.is_null() || in_.is_null() {
            return 0;
        }
        // SAFETY: the caller's value.
        let value: *mut c_void = unsafe { dup_of(in_.cast(), OSSL_CRMF_PKIPUBLICATIONINFO_it) }.cast();
        // SAFETY: the caller's message; the copy, which the attribute takes.
        c_int::from(unsafe { set1_atav(msg, NID_id_regCtrl_pkiPublicationInfo, value, false) })
    }
}

ffi_export! {
    /// The message's `id-regCtrl-oldCertID`, or NULL.
    ///
    /// # Safety
    /// `msg` is NULL or a live message.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_get0_regCtrl_oldCertID(msg: *const OSSL_CRMF_MSG) -> *mut OSSL_CRMF_CERTID
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0_atav(msg, NID_id_regCtrl_oldCertID) }.cast()
    }
}

ffi_export! {
    /// Adds a copy of `cid` as the message's `id-regCtrl-oldCertID`: 1, or 0.
    ///
    /// # Safety
    /// `msg` is NULL or a live message; `cid` NULL or a live value.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_set1_regCtrl_oldCertID(msg: *mut OSSL_CRMF_MSG, cid: *const OSSL_CRMF_CERTID) -> c_int
    where failure = 0, library = ERR_LIB_CRMF
    {
        let in_ = cid;
        if msg.is_null() || in_.is_null() {
            return 0;
        }
        // SAFETY: the caller's value.
        let value: *mut c_void = unsafe { OSSL_CRMF_CERTID_dup(in_.cast()) }.cast();
        // SAFETY: the caller's message; the copy, which the attribute takes.
        c_int::from(unsafe { set1_atav(msg, NID_id_regCtrl_oldCertID, value, false) })
    }
}

ffi_export! {
    /// The message's `id-regCtrl-protocolEncrKey`, or NULL.
    ///
    /// # Safety
    /// `msg` is NULL or a live message.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey(msg: *const OSSL_CRMF_MSG) -> *mut X509_PUBKEY
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0_atav(msg, NID_id_regCtrl_protocolEncrKey) }.cast()
    }
}

ffi_export! {
    /// Adds a copy of `pubkey` as the message's `id-regCtrl-protocolEncrKey`: 1, or 0.
    ///
    /// # Safety
    /// `msg` is NULL or a live message; `pubkey` NULL or a live value.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey(msg: *mut OSSL_CRMF_MSG, pubkey: *const X509_PUBKEY) -> c_int
    where failure = 0, library = ERR_LIB_CRMF
    {
        let in_ = pubkey;
        if msg.is_null() || in_.is_null() {
            return 0;
        }
        // SAFETY: the caller's value.
        let value: *mut c_void = unsafe { X509_PUBKEY_dup(in_.cast()) }.cast();
        // SAFETY: the caller's message; the copy, which the attribute takes.
        c_int::from(unsafe { set1_atav(msg, NID_id_regCtrl_protocolEncrKey, value, false) })
    }
}

ffi_export! {
    /// The message's `id-regInfo-utf8Pairs`, or NULL.
    ///
    /// # Safety
    /// `msg` is NULL or a live message.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_get0_regInfo_utf8Pairs(msg: *const OSSL_CRMF_MSG) -> *mut ASN1_UTF8STRING
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0_atav(msg, NID_id_regInfo_utf8Pairs) }.cast()
    }
}

ffi_export! {
    /// Adds a copy of `utf8pairs` as the message's `id-regInfo-utf8Pairs`: 1, or 0.
    ///
    /// # Safety
    /// `msg` is NULL or a live message; `utf8pairs` NULL or a live value.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_set1_regInfo_utf8Pairs(msg: *mut OSSL_CRMF_MSG, utf8pairs: *const ASN1_UTF8STRING) -> c_int
    where failure = 0, library = ERR_LIB_CRMF
    {
        let in_ = utf8pairs;
        if msg.is_null() || in_.is_null() {
            return 0;
        }
        // SAFETY: the caller's value.
        let value: *mut c_void = unsafe { ASN1_STRING_dup(in_.cast()) }.cast();
        // SAFETY: the caller's message; the copy, which the attribute takes.
        c_int::from(unsafe { set1_atav(msg, NID_id_regInfo_utf8Pairs, value, true) })
    }
}

ffi_export! {
    /// The message's `id-regInfo-certReq`, or NULL.
    ///
    /// # Safety
    /// `msg` is NULL or a live message.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_get0_regInfo_certReq(msg: *const OSSL_CRMF_MSG) -> *mut OSSL_CRMF_CERTREQUEST
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0_atav(msg, NID_id_regInfo_certReq) }.cast()
    }
}

ffi_export! {
    /// Adds a copy of `cr` as the message's `id-regInfo-certReq`: 1, or 0.
    ///
    /// # Safety
    /// `msg` is NULL or a live message; `cr` NULL or a live value.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_set1_regInfo_certReq(msg: *mut OSSL_CRMF_MSG, cr: *const OSSL_CRMF_CERTREQUEST) -> c_int
    where failure = 0, library = ERR_LIB_CRMF
    {
        let in_ = cr;
        if msg.is_null() || in_.is_null() {
            return 0;
        }
        // SAFETY: the caller's value.
        let value: *mut c_void = unsafe { dup_of(in_.cast(), cert_request_it) }.cast();
        // SAFETY: the caller's message; the copy, which the attribute takes.
        c_int::from(unsafe { set1_atav(msg, NID_id_regInfo_certReq, value, true) })
    }
}

ffi_export! {
    /// Sets the publication info's method and location (taken over): 1, or 0.
    ///
    /// # Safety
    /// `spi` is NULL or a live publication info; `nm` NULL or a live name.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_set0_SinglePubInfo(spi: *mut OSSL_CRMF_SINGLEPUBINFO, method: c_int, nm: *mut GENERAL_NAME) -> c_int
    where failure = 0, library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { of::<SinglePubInfo, _>(spi) }).filter(|_| (OSSL_CRMF_PUB_METHOD_DONTCARE..=OSSL_CRMF_PUB_METHOD_LDAP).contains(&method)) else {
            raise(ERR_R_PASSED_INVALID_ARGUMENT, "OSSL_CRMF_MSG_set0_SinglePubInfo");
            return 0;
        };
        // SAFETY: its method.
        if unsafe { ASN1_INTEGER_set(s.pub_method, method.into()) } == 0 {
            return 0;
        }
        // SAFETY: its location, or NULL.
        unsafe { GENERAL_NAME_free(s.pub_location) };
        s.pub_location = nm;
        1
    }
}

ffi_export! {
    /// Adds the single publication info (taken over): the list's new count, or 0.
    ///
    /// # Safety
    /// `pi` and `spi` are NULL or live.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo(pi: *mut OSSL_CRMF_PKIPUBLICATIONINFO, spi: *mut OSSL_CRMF_SINGLEPUBINFO) -> c_int
    where failure = 0, library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { of::<PkiPublicationInfo, _>(pi) }).filter(|_| !spi.is_null()) else {
            raise(CRMF_R_NULL_ARGUMENT, "OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo");
            return 0;
        };
        if p.pub_infos.is_null() {
            // SAFETY: no preconditions.
            p.pub_infos = unsafe { OPENSSL_sk_new_null() };
        }
        if p.pub_infos.is_null() {
            return 0;
        }
        // SAFETY: its list; the caller's info, which it takes.
        unsafe { OPENSSL_sk_push(p.pub_infos, spi.cast()) }
    }
}

ffi_export! {
    /// Sets the publication info's action: 1, or 0.
    ///
    /// # Safety
    /// `pi` is NULL or a live publication info.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_set_PKIPublicationInfo_action(pi: *mut OSSL_CRMF_PKIPUBLICATIONINFO, action: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { of::<PkiPublicationInfo, _>(pi) }).filter(|_| (OSSL_CRMF_PUB_ACTION_DONTPUBLISH..=OSSL_CRMF_PUB_ACTION_PLEASEPUBLISH).contains(&action)) else {
            raise(ERR_R_PASSED_INVALID_ARGUMENT, "OSSL_CRMF_MSG_set_PKIPublicationInfo_action");
            return 0;
        };
        // SAFETY: its action.
        unsafe { ASN1_INTEGER_set(p.action, action.into()) }
    }
}

ffi_export! {
    /// A CertId of the issuer (as a directory name) and serial number, or NULL.
    ///
    /// # Safety
    /// `issuer` and `serial` are NULL or live.
    pub unsafe extern "C" fn OSSL_CRMF_CERTID_gen(issuer: *const X509_NAME, serial: *const ASN1_INTEGER) -> *mut OSSL_CRMF_CERTID
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        if issuer.is_null() || serial.is_null() {
            raise(CRMF_R_NULL_ARGUMENT, "OSSL_CRMF_CERTID_gen");
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let cid = unsafe { OSSL_CRMF_CERTID_new() };
        // SAFETY: the CertId made here, or NULL; its name.
        let ok = unsafe { of::<CertId, _>(cid) }.is_some_and(|c| {
            // SAFETY: its issuer, made with it.
            let Some(g) = (unsafe { c.issuer.as_mut() }) else { return false };
            // SAFETY: the name's slot; the caller's name.
            if unsafe { X509_NAME_set(&raw mut g.d.directoryName, issuer) } == 0 {
                return false;
            }
            g.type_ = GEN_DIRNAME;
            // SAFETY: its serial.
            unsafe { ASN1_INTEGER_free(c.serial_number) };
            // SAFETY: the caller's serial.
            c.serial_number = unsafe { ASN1_INTEGER_dup(serial) };
            !c.serial_number.is_null()
        });
        if !ok {
            // SAFETY: made here, or NULL.
            unsafe { OSSL_CRMF_CERTID_free(cid) };
            return ptr::null_mut();
        }
        cid
    }
}

/// The message's request, or `None` with `CRMF_R_NULL_ARGUMENT` from `f`.
///
/// # Safety
/// `crm` is NULL or a live message.
unsafe fn req<'a>(crm: *const OSSL_CRMF_MSG, f: &str) -> Option<&'a mut CertRequest> {
    // SAFETY: the caller's guarantee; its request, or NULL.
    let r = unsafe { of::<Msg, _>(crm) }.and_then(|m| unsafe { m.cert_req.as_mut() });
    if r.is_none() {
        raise(CRMF_R_NULL_ARGUMENT, f);
    }
    r
}

ffi_export! {
    /// The message's certificate template, or NULL.
    ///
    /// # Safety
    /// `crm` is NULL or a live message.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_get0_tmpl(crm: *const OSSL_CRMF_MSG) -> *mut OSSL_CRMF_CERTTEMPLATE
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        unsafe { req(crm, "OSSL_CRMF_MSG_get0_tmpl") }.map_or(ptr::null_mut(), |r| r.cert_template.cast())
    }
}

/// The message's template, or `None` with `CRMF_R_NULL_ARGUMENT` from `f` (after
/// `OSSL_CRMF_MSG_get0_tmpl`'s own).
///
/// # Safety
/// `crm` is NULL or a live message.
unsafe fn tmpl<'a>(crm: *const OSSL_CRMF_MSG, f: &str) -> Option<&'a mut CertTemplate> {
    // SAFETY: the caller's guarantee.
    let t = unsafe { OSSL_CRMF_MSG_get0_tmpl(crm) };
    // SAFETY: the template, or NULL.
    let t = unsafe { of::<CertTemplate, _>(t) };
    if t.is_none() {
        raise(CRMF_R_NULL_ARGUMENT, f);
    }
    t
}

ffi_export! {
    /// Sets the template's validity to the times (taken over; either may be NULL): 1, or 0.
    ///
    /// # Safety
    /// `crm` is NULL or a live message; the times NULL or live.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_set0_validity(crm: *mut OSSL_CRMF_MSG, not_before: *mut ASN1_TIME, not_after: *mut ASN1_TIME) -> c_int
    where failure = 0, library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { tmpl(crm, "OSSL_CRMF_MSG_set0_validity") }) else { return 0 };
        let vld: *mut OptionalValidity = new_of(optional_validity_it).cast();
        // SAFETY: made here, or NULL.
        let Some(v) = (unsafe { vld.as_mut() }) else { return 0 };
        v.not_before = not_before;
        v.not_after = not_after;
        // As OpenSSL's, a validity set before isn't freed: the caller may still hold its times.
        t.validity = vld;
        1
    }
}

ffi_export! {
    /// Sets the request's certReqId: 1, or 0.
    ///
    /// # Safety
    /// `crm` is NULL or a live message.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_set_certReqId(crm: *mut OSSL_CRMF_MSG, rid: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Msg, _>(crm) }).and_then(|m| unsafe { m.cert_req.as_mut() }).filter(|r| !r.cert_req_id.is_null()) else {
            raise(CRMF_R_NULL_ARGUMENT, "OSSL_CRMF_MSG_set_certReqId");
            return 0;
        };
        // SAFETY: its ID.
        unsafe { ASN1_INTEGER_set(r.cert_req_id, rid.into()) }
    }
}

/// `crmf_asn1_get_int`: the integer as an `int`, or -1 with an error.
///
/// # Safety
/// `a` is NULL or a live integer.
pub(crate) unsafe fn asn1_get_int(a: *const ASN1_INTEGER) -> c_int {
    let mut res: i64 = 0;
    // SAFETY: room for the value; the caller's integer.
    if unsafe { ASN1_INTEGER_get_int64(&raw mut res, a) } == 0 {
        raise(ASN1_R_INVALID_NUMBER, "crmf_asn1_get_int");
        return -1;
    }
    match c_int::try_from(res) {
        Ok(v) => v,
        Err(_) => {
            raise(
                if res < 0 {
                    ASN1_R_TOO_SMALL
                } else {
                    ASN1_R_TOO_LARGE
                },
                "crmf_asn1_get_int",
            );
            -1
        }
    }
}

ffi_export! {
    /// The request's certReqId, or -1.
    ///
    /// # Safety
    /// `crm` is NULL or a live message.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_get_certReqId(crm: *const OSSL_CRMF_MSG) -> c_int
    where failure = -1, library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { req(crm, "OSSL_CRMF_MSG_get_certReqId") }) else { return -1 };
        // SAFETY: its ID.
        unsafe { asn1_get_int(r.cert_req_id) }
    }
}

/// `X509_EXTENSION_free` as a stack's free function.
unsafe extern "C" fn ext_free(p: *mut c_void) {
    // SAFETY: an element of a list of extensions.
    unsafe { X509_EXTENSION_free(p.cast()) };
}

ffi_export! {
    /// Sets the template's extensions (taken over; an empty list is none): 1, or 0.
    ///
    /// # Safety
    /// `crm` is NULL or a live message; `exts` NULL or a live list.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_set0_extensions(crm: *mut OSSL_CRMF_MSG, exts: *mut stack_st_X509_EXTENSION) -> c_int
    where failure = 0, library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { tmpl(crm, "OSSL_CRMF_MSG_set0_extensions") }) else { return 0 };
        let mut exts: *mut Stack = exts.cast();
        // SAFETY: the caller's list, or NULL (0).
        if unsafe { OPENSSL_sk_num(exts) } <= 0 {
            // SAFETY: as above.
            unsafe { OPENSSL_sk_free(exts) };
            exts = ptr::null_mut();
        }
        // SAFETY: its own extensions, or NULL.
        unsafe { OPENSSL_sk_pop_free(t.extensions, Some(ext_free)) };
        t.extensions = exts;
        1
    }
}

ffi_export! {
    /// Adds the extension (taken over) to the template's: 1, or 0.
    ///
    /// # Safety
    /// `crm` is NULL or a live message; `ext` NULL or a live extension.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_push0_extension(crm: *mut OSSL_CRMF_MSG, ext: *mut X509_EXTENSION) -> c_int
    where failure = 0, library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        let t = unsafe { tmpl(crm, "OSSL_CRMF_MSG_push0_extension") };
        let Some(t) = t.filter(|_| !ext.is_null()) else {
            if !crm.is_null() {
                raise(CRMF_R_NULL_ARGUMENT, "OSSL_CRMF_MSG_push0_extension");
            }
            return 0;
        };
        let made = t.extensions.is_null();
        if made {
            // SAFETY: no preconditions.
            t.extensions = unsafe { OPENSSL_sk_new_null() };
            if t.extensions.is_null() {
                return 0;
            }
        }
        // SAFETY: its list; the caller's extension, which it takes.
        if unsafe { OPENSSL_sk_push(t.extensions, ext.cast()) } > 0 {
            return 1;
        }
        if made {
            // SAFETY: made here.
            unsafe { OPENSSL_sk_free(t.extensions) };
            t.extensions = ptr::null_mut();
        }
        0
    }
}

/// `create_popo_signature`.
///
/// # Safety
/// `ps` is a new POPOSigningKey; `cr` the message's live request; `pkey` a live key.
unsafe fn create_popo_signature(
    ps: &mut PopoSigningKey,
    cr: &CertRequest,
    pkey: *mut EVP_PKEY,
    mut digest: *const EVP_MD,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> bool {
    // SAFETY: its template, or NULL.
    let pubkey = unsafe { cr.cert_template.as_ref() }.map_or(ptr::null_mut(), |t| t.public_key);
    // SAFETY: the template's key, or NULL.
    let pub_ = unsafe { X509_PUBKEY_get0(pubkey) };
    // SAFETY: the keys, or NULL.
    if unsafe { check_private_key(pub_, pkey) } == 0 {
        return false;
    }
    if !ps.poposk_input.is_null() {
        raise(CRMF_R_POPOSKINPUT_NOT_SUPPORTED, "create_popo_signature");
        return false;
    }
    let mut name = [0 as c_char; 80];
    // SAFETY: the caller's key; the room.
    if unsafe { EVP_PKEY_get_default_digest_name(pkey, name.as_mut_ptr(), 80) } > 0
        // SAFETY: NUL-terminated by the call.
        && unsafe { CStr::from_ptr(name.as_ptr()) }.to_bytes() == b"UNDEF"
    {
        digest = ptr::null();
    }
    // SAFETY: no preconditions.
    let it = unsafe { cert_request_it() };
    // SAFETY: the request's item and value; the POPO's algorithm and signature; the key.
    (unsafe {
        ASN1_item_sign_ex(
            it,
            ps.algorithm_identifier,
            ptr::null_mut(),
            ps.signature,
            ptr::from_ref(cr).cast(),
            ptr::null(),
            pkey,
            digest,
            libctx,
            propq,
        )
    }) > 0
}

ffi_export! {
    /// Sets the message's proof-of-possession: none, RA-verified, a signature over the request
    /// with `pkey`, or key encipherment (the certificate to come encrypted): 1, or 0.
    ///
    /// # Safety
    /// `crm` is NULL or a live message; `pkey` NULL or a live key; `digest` NULL or a digest;
    /// `libctx` NULL or live; `propq` NULL or a C string.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_create_popo(meth: c_int, crm: *mut OSSL_CRMF_MSG, pkey: *mut EVP_PKEY, digest: *const EVP_MD, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CRMF
    {
        const F: &str = "OSSL_CRMF_MSG_create_popo";
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { of::<Msg, _>(crm) }).filter(|_| meth != OSSL_CRMF_POPO_SIGNATURE || !pkey.is_null()) else {
            raise(CRMF_R_NULL_ARGUMENT, F);
            return 0;
        };
        let mut pp: *mut Choice = ptr::null_mut();
        if meth != OSSL_CRMF_POPO_NONE {
            pp = new_of(popo_it).cast();
            // SAFETY: made here, or NULL.
            let Some(p) = (unsafe { pp.as_mut() }) else { return 0 };
            p.type_ = meth;
            // SAFETY: the message's members.
            let ok = unsafe { fill_popo(p, meth, m, pkey, digest, libctx, propq) };
            if !ok {
                // SAFETY: made here.
                unsafe { free_of(pp.cast(), popo_it) };
                return 0;
            }
        }
        // SAFETY: its own POPO, or NULL.
        unsafe { free_of(m.popo.cast(), popo_it) };
        m.popo = pp;
        1
    }
}

/// The POPO's value for the method.
///
/// # Safety
/// `p` is a new POPO; `m`'s members are live; `pkey` NULL or live.
unsafe fn fill_popo(
    p: &mut Choice,
    meth: c_int,
    m: &Msg,
    pkey: *mut EVP_PKEY,
    digest: *const EVP_MD,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> bool {
    match meth {
        OSSL_CRMF_POPO_RAVERIFIED => {
            // SAFETY: no preconditions.
            p.value = unsafe { ASN1_NULL_new() }.cast();
            !p.value.is_null()
        }
        OSSL_CRMF_POPO_SIGNATURE => {
            let ps: *mut PopoSigningKey = new_of(popo_signing_key_it).cast();
            // SAFETY: made here, or NULL; the message's request.
            let ok = match (unsafe { ps.as_mut() }, unsafe { m.cert_req.as_ref() }) {
                // SAFETY: as above.
                (Some(s), Some(cr)) => unsafe {
                    create_popo_signature(s, cr, pkey, digest, libctx, propq)
                },
                (_, None) => {
                    raise(CRMF_R_NULL_ARGUMENT, "create_popo_signature");
                    false
                }
                _ => false,
            };
            if !ok {
                // SAFETY: made here, or NULL.
                unsafe { free_of(ps.cast(), popo_signing_key_it) };
                return false;
            }
            p.value = ps.cast();
            true
        }
        OSSL_CRMF_POPO_KEYENC => {
            let pk: *mut Choice = new_of(popo_priv_key_it).cast();
            // SAFETY: made here, or NULL.
            let Some(k) = (unsafe { pk.as_mut() }) else {
                return false;
            };
            p.value = pk.cast();
            // SAFETY: no preconditions.
            let tag = unsafe { ASN1_INTEGER_new() };
            k.type_ = OSSL_CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE;
            k.value = tag.cast();
            // SAFETY: the integer made here.
            !tag.is_null()
                && unsafe { ASN1_INTEGER_set(tag, OSSL_CRMF_SUBSEQUENTMESSAGE_ENCRCERT.into()) }
                    != 0
        }
        _ => {
            raise(
                CRMF_R_UNSUPPORTED_METHOD_FOR_CREATING_POPO,
                "OSSL_CRMF_MSG_create_popo",
            );
            false
        }
    }
}

ffi_export! {
    /// Checks request `rid`'s proof-of-possession: RA-verified (if accepted) or a signature
    /// by the template's key: 1, or 0.
    ///
    /// # Safety
    /// `reqs` is NULL or a live list; `libctx` NULL or live; `propq` NULL or a C string.
    pub unsafe extern "C" fn OSSL_CRMF_MSGS_verify_popo(reqs: *const OSSL_CRMF_MSGS, rid: c_int, accept_ra_verified: c_int, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CRMF
    {
        const F: &str = "OSSL_CRMF_MSGS_verify_popo";
        let r: *mut Msg = if reqs.is_null() {
            ptr::null_mut()
        } else {
            // SAFETY: the caller's list; an index (out of range gives NULL).
            unsafe { OPENSSL_sk_value(reqs.cast(), rid) }.cast()
        };
        // SAFETY: a message of the list, or NULL.
        let Some(m) = (unsafe { r.as_ref() }) else {
            raise(CRMF_R_NULL_ARGUMENT, F);
            return 0;
        };
        // SAFETY: its POPO, or NULL.
        let Some(popo) = (unsafe { m.popo.as_ref() }) else {
            raise(CRMF_R_POPO_MISSING, F);
            return 0;
        };
        match popo.type_ {
            OSSL_CRMF_POPO_RAVERIFIED => {
                if accept_ra_verified == 0 {
                    raise(CRMF_R_POPO_RAVERIFIED_NOT_ACCEPTED, F);
                    return 0;
                }
                1
            }
            // SAFETY: its members.
            OSSL_CRMF_POPO_SIGNATURE => c_int::from(unsafe { verify_signature(m, popo, libctx, propq) }),
            _ => {
                raise(CRMF_R_UNSUPPORTED_POPO_METHOD, F);
                0
            }
        }
    }
}

/// The signature POPO's check.
///
/// # Safety
/// `m`'s and `popo`'s members are live.
unsafe fn verify_signature(
    m: &Msg,
    popo: &Choice,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> bool {
    const F: &str = "OSSL_CRMF_MSGS_verify_popo";
    // SAFETY: its request and template.
    let Some(t) =
        (unsafe { m.cert_req.as_ref() }).and_then(|r| unsafe { r.cert_template.as_ref() })
    else {
        return false;
    };
    let pubkey = t.public_key;
    if pubkey.is_null() {
        raise(CRMF_R_POPO_MISSING_PUBLIC_KEY, F);
        return false;
    }
    // SAFETY: a signature's value.
    let Some(sig) = (unsafe { popo.value.cast::<PopoSigningKey>().as_ref() }) else {
        return false;
    };
    let (it, asn): (*const rustyssl_abi::ASN1_ITEM, *const c_void) = if sig.poposk_input.is_null() {
        if t.subject.is_null() {
            raise(CRMF_R_POPO_MISSING_SUBJECT, F);
            return false;
        }
        // SAFETY: no preconditions.
        (unsafe { cert_request_it() }, m.cert_req.cast())
    } else {
        // SAFETY: its input.
        let input = unsafe { &*sig.poposk_input };
        if input.public_key.is_null() {
            raise(CRMF_R_POPO_MISSING_PUBLIC_KEY, F);
            return false;
        }
        // SAFETY: the keys.
        if unsafe { X509_PUBKEY_eq(pubkey, input.public_key) } != 1 {
            raise(CRMF_R_POPO_INCONSISTENT_PUBLIC_KEY, F);
            return false;
        }
        // SAFETY: no preconditions.
        (
            unsafe { popo_signing_key_input_it() },
            sig.poposk_input.cast(),
        )
    };
    // SAFETY: the template's key.
    let key = unsafe { X509_PUBKEY_get0(pubkey) };
    // SAFETY: the item and its value; the signature's algorithm and value; the key.
    (unsafe {
        ASN1_item_verify_ex(
            it,
            sig.algorithm_identifier,
            sig.signature,
            asn,
            ptr::null(),
            key,
            libctx,
            propq,
        )
    }) >= 1
}

ffi_export! {
    /// Whether central key generation is asked for (no or an empty public key): 1 or 0, -1 for
    /// no arguments, -2 when the POPO says otherwise.
    ///
    /// # Safety
    /// `crm` and `p10cr` are NULL or live.
    pub unsafe extern "C" fn OSSL_CRMF_MSG_centralkeygen_requested(crm: *const OSSL_CRMF_MSG, p10cr: *const X509_REQ) -> c_int
    where failure = -1, library = ERR_LIB_CRMF
    {
        if crm.is_null() && p10cr.is_null() {
            raise(CRMF_R_NULL_ARGUMENT, "OSSL_CRMF_MSG_centralkeygen_requested");
            return -1;
        }
        let pubkey = if crm.is_null() {
            // SAFETY: the caller's request.
            unsafe { crate::x509::req::X509_REQ_get_X509_PUBKEY(p10cr.cast_mut()) }
        } else {
            // SAFETY: the caller's message.
            let t = unsafe { OSSL_CRMF_MSG_get0_tmpl(crm) };
            // SAFETY: its template, or NULL.
            unsafe { OSSL_CRMF_CERTTEMPLATE_get0_publicKey(t) }
        };
        let (mut pk, mut pklen): (*const u8, c_int) = (ptr::null(), 0);
        let ret = pubkey.is_null()
            // SAFETY: the key; rooms for its parts.
            || (unsafe { X509_PUBKEY_get0_param(ptr::null_mut(), &raw mut pk, &raw mut pklen, ptr::null_mut(), pubkey) } != 0 && pklen == 0);
        if !crm.is_null() {
            // SAFETY: the caller's message.
            let no_popo = unsafe { of::<Msg, _>(crm) }.is_some_and(|m| m.popo.is_null());
            if ret != no_popo {
                raise(CRMF_R_POPO_INCONSISTENT_CENTRAL_KEYGEN, "OSSL_CRMF_MSG_centralkeygen_requested");
                return -2;
            }
        }
        c_int::from(ret)
    }
}

ffi_export! {
    /// The template's public key, or NULL.
    ///
    /// # Safety
    /// `tmpl` is NULL or a live template.
    pub unsafe extern "C" fn OSSL_CRMF_CERTTEMPLATE_get0_publicKey(tmpl: *const OSSL_CRMF_CERTTEMPLATE) -> *mut X509_PUBKEY
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<CertTemplate, _>(tmpl) }.map_or(ptr::null_mut(), |t| t.public_key)
    }
}

ffi_export! {
    /// The template's serial number, or NULL.
    ///
    /// # Safety
    /// `tmpl` is NULL or a live template.
    pub unsafe extern "C" fn OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(tmpl: *const OSSL_CRMF_CERTTEMPLATE) -> *const ASN1_INTEGER
    where failure = ptr::null(), library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<CertTemplate, _>(tmpl) }.map_or(ptr::null(), |t| t.serial_number.cast_const())
    }
}

ffi_export! {
    /// The template's subject, or NULL.
    ///
    /// # Safety
    /// `tmpl` is NULL or a live template.
    pub unsafe extern "C" fn OSSL_CRMF_CERTTEMPLATE_get0_subject(tmpl: *const OSSL_CRMF_CERTTEMPLATE) -> *const X509_NAME
    where failure = ptr::null(), library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<CertTemplate, _>(tmpl) }.map_or(ptr::null(), |t| t.subject.cast_const())
    }
}

ffi_export! {
    /// The template's issuer, or NULL.
    ///
    /// # Safety
    /// `tmpl` is NULL or a live template.
    pub unsafe extern "C" fn OSSL_CRMF_CERTTEMPLATE_get0_issuer(tmpl: *const OSSL_CRMF_CERTTEMPLATE) -> *const X509_NAME
    where failure = ptr::null(), library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<CertTemplate, _>(tmpl) }.map_or(ptr::null(), |t| t.issuer.cast_const())
    }
}

ffi_export! {
    /// The template's extensions, or NULL.
    ///
    /// # Safety
    /// `tmpl` is NULL or a live template.
    pub unsafe extern "C" fn OSSL_CRMF_CERTTEMPLATE_get0_extensions(tmpl: *const OSSL_CRMF_CERTTEMPLATE) -> *mut stack_st_X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<CertTemplate, _>(tmpl) }.map_or(ptr::null_mut(), |t| t.extensions.cast())
    }
}

ffi_export! {
    /// The CertId's issuer when a directory name, or NULL.
    ///
    /// # Safety
    /// `cid` is NULL or a live CertId.
    pub unsafe extern "C" fn OSSL_CRMF_CERTID_get0_issuer(cid: *const OSSL_CRMF_CERTID) -> *const X509_NAME
    where failure = ptr::null(), library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee; its issuer.
        match unsafe { of::<CertId, _>(cid) }.and_then(|c| unsafe { c.issuer.as_ref() }) {
            // SAFETY: a directory name's.
            Some(g) if g.type_ == GEN_DIRNAME => unsafe { g.d.directoryName }.cast_const(),
            _ => ptr::null(),
        }
    }
}

ffi_export! {
    /// The CertId's serial number, or NULL.
    ///
    /// # Safety
    /// `cid` is NULL or a live CertId.
    pub unsafe extern "C" fn OSSL_CRMF_CERTID_get0_serialNumber(cid: *const OSSL_CRMF_CERTID) -> *const ASN1_INTEGER
    where failure = ptr::null(), library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<CertId, _>(cid) }.map_or(ptr::null(), |c| c.serial_number.cast_const())
    }
}

ffi_export! {
    /// Fills the template with copies of what is given: 1, or 0.
    ///
    /// # Safety
    /// `tmpl` is NULL or a live template; the rest NULL or live.
    pub unsafe extern "C" fn OSSL_CRMF_CERTTEMPLATE_fill(tmpl: *mut OSSL_CRMF_CERTTEMPLATE, pubkey: *mut EVP_PKEY, subject: *const X509_NAME, issuer: *const X509_NAME, serial: *const ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { of::<CertTemplate, _>(tmpl) }) else {
            raise(CRMF_R_NULL_ARGUMENT, "OSSL_CRMF_CERTTEMPLATE_fill");
            return 0;
        };
        // SAFETY: its subject's slot; the caller's name.
        if !subject.is_null() && unsafe { X509_NAME_set(&raw mut t.subject, subject) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        if !issuer.is_null() && unsafe { X509_NAME_set(&raw mut t.issuer, issuer) } == 0 {
            return 0;
        }
        if !serial.is_null() {
            // SAFETY: its own serial, or NULL.
            unsafe { ASN1_INTEGER_free(t.serial_number) };
            // SAFETY: the caller's serial.
            t.serial_number = unsafe { ASN1_INTEGER_dup(serial) };
            if t.serial_number.is_null() {
                return 0;
            }
        }
        // SAFETY: its key's slot; the caller's key.
        c_int::from(pubkey.is_null() || unsafe { X509_PUBKEY_set(&raw mut t.public_key, pubkey) } != 0)
    }
}

/// `EVP_get_cipherbyobj`: the legacy cipher named by the object's NID.
///
/// # Safety
/// `obj` is NULL or a live object.
unsafe fn cipher_by_obj(obj: *const rustyssl_abi::ASN1_OBJECT) -> *const rustyssl_abi::EVP_CIPHER {
    // SAFETY: the caller's object.
    let nid = unsafe { OBJ_obj2nid(obj) };
    // SAFETY: no preconditions.
    let sn = unsafe { OBJ_nid2sn(nid) };
    // SAFETY: a NID's static name, or NULL.
    unsafe { EVP_get_cipherbyname(sn) }
}

ffi_export! {
    /// The encrypted value decrypted with `pkey` (its symmetric key unwrapped in constant
    /// time): the plaintext (`CRYPTO_malloc`), its length in `*outlen`, or NULL.
    ///
    /// # Safety
    /// `enc` is NULL or a live value; `pkey` NULL or a live key; `outlen` NULL or room for an
    /// `int`.
    pub unsafe extern "C" fn OSSL_CRMF_ENCRYPTEDVALUE_decrypt(enc: *const OSSL_CRMF_ENCRYPTEDVALUE, libctx: *mut OSSL_LIB_CTX, propq: *const c_char, pkey: *mut EVP_PKEY, outlen: *mut c_int) -> *mut u8
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        const F: &str = "OSSL_CRMF_ENCRYPTEDVALUE_decrypt";
        // SAFETY: the caller's room, or NULL.
        let Some(outlen) = (unsafe { outlen.as_mut() }) else {
            raise(CRMF_R_NULL_ARGUMENT, F);
            return ptr::null_mut();
        };
        *outlen = 0;
        // SAFETY: the caller's guarantee.
        let Some(e) = (unsafe { of::<EncryptedValue, _>(enc) }).filter(|e| !e.symm_alg.is_null() && !e.enc_symm_key.is_null() && !e.enc_value.is_null() && !pkey.is_null()) else {
            raise(CRMF_R_NULL_ARGUMENT, F);
            return ptr::null_mut();
        };
        // SAFETY: its parts.
        unsafe { decrypt_value(e, libctx, propq, pkey, outlen) }
    }
}

/// The decryption of an encrypted value.
///
/// # Safety
/// `e`'s parts are live; `pkey` a live key.
unsafe fn decrypt_value(
    e: &EncryptedValue,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
    pkey: *mut EVP_PKEY,
    outlen: &mut c_int,
) -> *mut u8 {
    // SAFETY: its algorithm.
    let alg = unsafe { &*e.symm_alg };
    let mut name = [0 as c_char; super::NAME_LEN];
    let len = c_int::try_from(super::NAME_LEN).unwrap_or(0);
    // SAFETY: the room; the object.
    unsafe { OBJ_obj2txt(name.as_mut_ptr(), len, alg.algorithm, 0) };
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: the library context; a NUL-terminated name; the properties.
    let fetched = unsafe { EVP_CIPHER_fetch(libctx, name.as_ptr(), propq) };
    let cipher = if fetched.is_null() {
        // SAFETY: the object.
        unsafe { cipher_by_obj(alg.algorithm) }
    } else {
        fetched.cast_const()
    };
    if cipher.is_null() {
        // SAFETY: the mark set above.
        unsafe { ERR_clear_last_mark() };
        raise(
            CRMF_R_UNSUPPORTED_CIPHER,
            "OSSL_CRMF_ENCRYPTEDVALUE_decrypt",
        );
        return ptr::null_mut();
    }
    // SAFETY: as above.
    unsafe { ERR_pop_to_mark() };
    // SAFETY: the cipher; the key; the value's parts.
    let out = unsafe { decrypt_with(e, cipher, libctx, propq, pkey, outlen) };
    // SAFETY: fetched here, or NULL (the legacy cipher is static).
    unsafe { EVP_CIPHER_free(fetched) };
    out
}

/// The symmetric key unwrapped and the value decrypted with the cipher.
///
/// # Safety
/// As for [`decrypt_value`]; `cipher` a live cipher.
unsafe fn decrypt_with(
    e: &EncryptedValue,
    cipher: *const rustyssl_abi::EVP_CIPHER,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
    pkey: *mut EVP_PKEY,
    outlen: &mut c_int,
) -> *mut u8 {
    use subtle::ConstantTimeEq;
    // SAFETY: the cipher.
    let cikeysize = unsafe { EVP_CIPHER_get_key_length(cipher) };
    // SAFETY: the library context; the key; the properties.
    let pkctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq) };
    // SAFETY: its encrypted key.
    let ek_in = unsafe { &*e.enc_symm_key };
    let Ok(ek_len) = usize::try_from(ek_in.length) else {
        return ptr::null_mut();
    };
    let mut ek: Vec<u8> = Vec::new();
    let unwrapped = 'k: {
        // SAFETY: the context made here, or NULL.
        if pkctx.is_null() || unsafe { EVP_PKEY_decrypt_init(pkctx) } <= 0 {
            break 'k false;
        }
        let mut eksize = 0usize;
        // SAFETY: the context; a length only; the encrypted key.
        if unsafe { EVP_PKEY_decrypt(pkctx, ptr::null_mut(), &raw mut eksize, ek_in.data, ek_len) }
            <= 0
        {
            break 'k false;
        }
        ek.resize(eksize, 0);
        // SAFETY: as above; the room.
        let retval = unsafe {
            EVP_PKEY_decrypt(pkctx, ek.as_mut_ptr(), &raw mut eksize, ek_in.data, ek_len)
        };
        // Constant time: a failure (retval <= 0) or a wrong size are one outcome.
        let bad = subtle::Choice::from(u8::from(retval < 1))
            | eksize.ct_ne(&usize::try_from(cikeysize).unwrap_or(usize::MAX));
        if bool::from(bad) {
            // SAFETY: no preconditions.
            unsafe { ERR_clear_error() };
            raise(
                CRMF_R_ERROR_DECRYPTING_SYMMETRIC_KEY,
                "OSSL_CRMF_ENCRYPTEDVALUE_decrypt",
            );
            break 'k false;
        }
        ek.truncate(eksize);
        true
    };
    // SAFETY: made here, or NULL.
    unsafe { EVP_PKEY_CTX_free(pkctx) };
    let out = if unwrapped {
        // SAFETY: the value's parts; the cipher; the key.
        unsafe { decrypt_data(e, cipher, &ek, outlen) }
    } else {
        ptr::null_mut()
    };
    // SAFETY: the key's own octets.
    unsafe { mem::cleanse(ek.as_mut_ptr().cast(), ek.len()) };
    out
}

/// The value decrypted with the unwrapped key and the algorithm's IV.
///
/// # Safety
/// As for [`decrypt_with`].
unsafe fn decrypt_data(
    e: &EncryptedValue,
    cipher: *const rustyssl_abi::EVP_CIPHER,
    ek: &[u8],
    outlen: &mut c_int,
) -> *mut u8 {
    // SAFETY: the cipher.
    let iv_len = unsafe { EVP_CIPHER_get_iv_length(cipher) };
    let mut iv = vec![0u8; usize::try_from(iv_len).unwrap_or(0)];
    // SAFETY: its algorithm.
    let param = unsafe { (*e.symm_alg).parameter };
    if param.is_null()
        // SAFETY: the parameter; the room.
        || unsafe { ASN1_TYPE_get_octetstring(param, iv.as_mut_ptr(), iv_len) } != iv_len
    {
        raise(CRMF_R_MALFORMED_IV, "OSSL_CRMF_ENCRYPTEDVALUE_decrypt");
        return ptr::null_mut();
    }
    // SAFETY: its encrypted value.
    let v = unsafe { &*e.enc_value };
    // SAFETY: the cipher.
    let bs = unsafe { EVP_CIPHER_get_block_size(cipher) };
    let Some(size) = usize::try_from(v.length)
        .ok()
        .zip(usize::try_from(bs).ok())
        .map(|(a, b)| a + b)
    else {
        return ptr::null_mut();
    };
    let out: *mut u8 = mem::alloc(size).cast();
    // SAFETY: no preconditions.
    let ctx = unsafe { EVP_CIPHER_CTX_new() };
    let ok = 'd: {
        if out.is_null() || ctx.is_null() {
            break 'd false;
        }
        // SAFETY: the context made here.
        unsafe { EVP_CIPHER_CTX_set_padding(ctx, 0) };
        let mut n: c_int = 0;
        // SAFETY: the context; the cipher; the key and IV.
        let ok = unsafe { EVP_DecryptInit(ctx, cipher, ek.as_ptr(), iv.as_ptr()) } != 0
            // SAFETY: as above; `size` octets of room; the value.
            && unsafe { EVP_DecryptUpdate(ctx, out, outlen, v.data, v.length) } != 0
            // SAFETY: as above; the room past what was written.
            && unsafe { EVP_DecryptFinal(ctx, out.wrapping_add(usize::try_from(*outlen).unwrap_or(0)), &raw mut n) } != 0;
        if !ok {
            raise(
                CRMF_R_ERROR_DECRYPTING_ENCRYPTEDVALUE,
                "OSSL_CRMF_ENCRYPTEDVALUE_decrypt",
            );
            break 'd false;
        }
        *outlen += n;
        true
    };
    // SAFETY: made here, or NULL.
    unsafe { EVP_CIPHER_CTX_free(ctx) };
    if !ok {
        // SAFETY: as above.
        unsafe { mem::release(out.cast()) };
        return ptr::null_mut();
    }
    out
}

ffi_export! {
    /// The certificate in the encrypted value, decrypted with `pkey`, or NULL.
    ///
    /// # Safety
    /// As for [`OSSL_CRMF_ENCRYPTEDVALUE_decrypt`].
    pub unsafe extern "C" fn OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert(ecert: *const OSSL_CRMF_ENCRYPTEDVALUE, libctx: *mut OSSL_LIB_CTX, propq: *const c_char, pkey: *mut EVP_PKEY) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        let mut len: c_int = 0;
        // SAFETY: the caller's arguments; room for the length.
        let buf = unsafe { OSSL_CRMF_ENCRYPTEDVALUE_decrypt(ecert, libctx, propq, pkey, &raw mut len) };
        if buf.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the library context and properties.
        let mut cert = unsafe { X509_new_ex(libctx, propq) };
        if !cert.is_null() {
            let mut p = buf.cast_const();
            // SAFETY: the certificate; the `len` octets decrypted.
            if unsafe { d2i_X509(&raw mut cert, &raw mut p, len.into()) }.is_null() {
                raise(CRMF_R_ERROR_DECODING_CERTIFICATE, "OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert");
                // SAFETY: as above, or NULL after a failed decode.
                unsafe { X509_free(cert) };
                cert = ptr::null_mut();
            }
        }
        // SAFETY: from `CRYPTO_malloc`.
        unsafe { mem::release(buf.cast()) };
        cert
    }
}

ffi_export! {
    /// The certificate in the encrypted key (an EncryptedValue or an EnvelopedData), decrypted
    /// with `pkey`, or NULL.
    ///
    /// # Safety
    /// `ecert` is a live encrypted key; the rest as for [`OSSL_CRMF_ENCRYPTEDVALUE_decrypt`].
    pub unsafe extern "C" fn OSSL_CRMF_ENCRYPTEDKEY_get1_encCert(ecert: *const OSSL_CRMF_ENCRYPTEDKEY, libctx: *mut OSSL_LIB_CTX, propq: *const c_char, pkey: *mut EVP_PKEY, flags: c_uint) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { of::<Choice, _>(ecert) }) else {
            raise(CRMF_R_NULL_ARGUMENT, "OSSL_CRMF_ENCRYPTEDKEY_get1_encCert");
            return ptr::null_mut();
        };
        if k.type_ != OSSL_CRMF_ENCRYPTEDKEY_ENVELOPEDDATA {
            // SAFETY: an EncryptedValue.
            return unsafe { OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert(k.value.cast(), libctx, propq, pkey) };
        }
        // SAFETY: an EnvelopedData; the key.
        let bio = unsafe { CMS_EnvelopedData_decrypt(k.value.cast(), ptr::null_mut(), pkey, ptr::null_mut(), ptr::null_mut(), flags, libctx, propq) };
        if bio.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the BIO.
        let cert = unsafe { d2i_X509_bio(bio, ptr::null_mut()) };
        if cert.is_null() {
            raise(CRMF_R_ERROR_DECODING_CERTIFICATE, "OSSL_CRMF_ENCRYPTEDKEY_get1_encCert");
        }
        // SAFETY: made here.
        unsafe { BIO_free(bio) };
        cert
    }
}

ffi_callback! {
    /// `check_cmKGA`: a CA, or a certificate with the cmKGA extended key usage.
    ///
    /// # Safety
    /// `x` is a live certificate.
    pub(crate) unsafe extern "C" fn check_cmkga(_purpose: *const X509_PURPOSE, x: *const X509, ca: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CRMF
    {
        if ca != 0 {
            return 1;
        }
        // SAFETY: the certificate.
        let ekus: *mut Stack = unsafe { X509_get_ext_d2i(x, NID_ext_key_usage, ptr::null_mut(), ptr::null_mut()) }.cast();
        // SAFETY: the list, or NULL (0).
        let n = unsafe { OPENSSL_sk_num(ekus) };
        let found = (0..n).any(|i| {
            // SAFETY: an index in range.
            let o = unsafe { OPENSSL_sk_value(ekus, i) };
            // SAFETY: one of the objects.
            (unsafe { OBJ_obj2nid(o.cast()) }) == NID_cmKGA
        });
        /// `ASN1_OBJECT_free` as a stack's free function.
        unsafe extern "C" fn obj_free(p: *mut c_void) {
            // SAFETY: an element of the list.
            unsafe { ASN1_OBJECT_free(p.cast()) };
        }
        // SAFETY: decoded here.
        unsafe { OPENSSL_sk_pop_free(ekus, Some(obj_free)) };
        c_int::from(found)
    }
}

ffi_export! {
    /// The private key in the encrypted key: an EncryptedValue decrypted with `pkey`, or an
    /// EnvelopedData decrypted (with `pkey` and `cert`, or `secret`) whose SignedData verifies
    /// to `ts` as signed by a cmKGA: it, or NULL.
    ///
    /// # Safety
    /// The arguments are NULL or live.
    pub unsafe extern "C" fn OSSL_CRMF_ENCRYPTEDKEY_get1_pkey(encrypted_key: *const OSSL_CRMF_ENCRYPTEDKEY, ts: *mut X509_STORE, extra: *mut stack_st_X509, pkey: *mut EVP_PKEY, cert: *mut X509, secret: *mut ASN1_OCTET_STRING, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        const F: &str = "OSSL_CRMF_ENCRYPTEDKEY_get1_pkey";
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { of::<Choice, _>(encrypted_key) }) else {
            raise(CRMF_R_NULL_ARGUMENT, F);
            return ptr::null_mut();
        };
        if k.type_ != OSSL_CRMF_ENCRYPTEDKEY_ENVELOPEDDATA {
            let mut len: c_int = 0;
            // SAFETY: an EncryptedValue; the key; room for the length.
            let p = unsafe { OSSL_CRMF_ENCRYPTEDVALUE_decrypt(k.value.cast(), libctx, propq, pkey, &raw mut len) };
            if p.is_null() {
                return ptr::null_mut();
            }
            let mut q = p.cast_const();
            // SAFETY: the `len` octets decrypted.
            let ret = unsafe { d2i_AutoPrivateKey_ex(ptr::null_mut(), &raw mut q, len.into(), libctx, propq) };
            // SAFETY: from `CRYPTO_malloc`.
            unsafe { mem::release(p.cast()) };
            return ret;
        }
        if ts.is_null() {
            raise(CRMF_R_NULL_ARGUMENT, F);
            return ptr::null_mut();
        }
        // SAFETY: the EnvelopedData; the caller's arguments.
        unsafe { pkey_from_envdata(k.value.cast(), ts, extra, pkey, cert, secret, libctx, propq) }
    }
}

/// The EnvelopedData's signed private key.
///
/// # Safety
/// As for [`OSSL_CRMF_ENCRYPTEDKEY_get1_pkey`], `ts` live.
#[expect(clippy::too_many_arguments, reason = "OpenSSL's")]
unsafe fn pkey_from_envdata(
    env: *mut CMS_EnvelopedData,
    ts: *mut X509_STORE,
    extra: *mut stack_st_X509,
    pkey: *mut EVP_PKEY,
    cert: *mut X509,
    secret: *mut ASN1_OCTET_STRING,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> *mut EVP_PKEY {
    const F: &str = "OSSL_CRMF_ENCRYPTEDKEY_get1_pkey";
    // SAFETY: the caller's arguments.
    let bio = unsafe {
        CMS_EnvelopedData_decrypt(env, ptr::null_mut(), pkey, cert, secret, 0, libctx, propq)
    };
    if bio.is_null() {
        raise(CRMF_R_ERROR_DECRYPTING_ENCRYPTEDKEY, F);
        return ptr::null_mut();
    }
    let mut ret = ptr::null_mut();
    let mut pkey_bio = ptr::null_mut();
    // SAFETY: no preconditions.
    let it = unsafe { crate::cms::signed_data_it() };
    // SAFETY: the SignedData's item; the BIO.
    let sd = unsafe { ASN1_item_d2i_bio(it, bio, ptr::null_mut()) };
    'e: {
        if sd.is_null() {
            break 'e;
        }
        // SAFETY: a static name.
        let mut purpose_id = unsafe { X509_PURPOSE_get_by_sname(SN_cmKGA.as_ptr()) };
        if purpose_id < 0 {
            // SAFETY: the library context.
            purpose_id = unsafe { X509_PURPOSE_get_unused_id(libctx) };
            // SAFETY: the check; static names.
            if unsafe {
                X509_PURPOSE_add(
                    purpose_id,
                    X509_TRUST_COMPAT,
                    0,
                    Some(check_cmkga),
                    LN_cmKGA.as_ptr(),
                    SN_cmKGA.as_ptr(),
                    ptr::null_mut(),
                )
            } == 0
            {
                break 'e;
            }
        }
        // SAFETY: the store.
        let vpm = unsafe { X509_STORE_get0_param(ts) };
        if vpm.is_null() {
            break 'e;
        }
        // SAFETY: its parameters.
        let bak = unsafe { X509_VERIFY_PARAM_get_purpose(vpm) };
        // SAFETY: the store.
        if unsafe { X509_STORE_set_purpose(ts, purpose_id) } == 0 {
            raise(CRMF_R_ERROR_SETTING_PURPOSE, F);
            break 'e;
        }
        // SAFETY: the SignedData; the store and certificates.
        pkey_bio = unsafe {
            CMS_SignedData_verify(
                sd.cast(),
                ptr::null_mut(),
                ptr::null_mut(),
                ts,
                extra,
                ptr::null_mut(),
                0,
                libctx,
                propq,
            )
        };
        // SAFETY: as above.
        if unsafe { X509_STORE_set_purpose(ts, bak) } == 0 {
            raise(CRMF_R_ERROR_SETTING_PURPOSE, F);
            break 'e;
        }
        if pkey_bio.is_null() {
            raise(CRMF_R_ERROR_VERIFYING_ENCRYPTEDKEY, F);
            break 'e;
        }
        // SAFETY: the verified content.
        ret = unsafe { d2i_PrivateKey_ex_bio(pkey_bio, ptr::null_mut(), libctx, propq) };
        if ret.is_null() {
            raise(CRMF_R_ERROR_DECODING_ENCRYPTEDKEY, F);
        }
    }
    // SAFETY: made here, or NULL.
    unsafe { CMS_SignedData_free(sd.cast()) };
    // SAFETY: as above.
    unsafe { BIO_free(bio) };
    // SAFETY: as above.
    unsafe { BIO_free(pkey_bio) };
    ret
}

ffi_export! {
    /// An encrypted key holding the EnvelopedData (taken over), or NULL.
    ///
    /// # Safety
    /// `envdata` is NULL or a live EnvelopedData the key then owns.
    pub unsafe extern "C" fn OSSL_CRMF_ENCRYPTEDKEY_init_envdata(envdata: *mut CMS_EnvelopedData) -> *mut OSSL_CRMF_ENCRYPTEDKEY
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        // SAFETY: no preconditions.
        let ek = unsafe { OSSL_CRMF_ENCRYPTEDKEY_new() };
        // SAFETY: made here, or NULL.
        if let Some(k) = unsafe { of::<Choice, _>(ek) } {
            k.type_ = OSSL_CRMF_ENCRYPTEDKEY_ENVELOPEDDATA;
            k.value = envdata.cast();
        }
        ek
    }
}
