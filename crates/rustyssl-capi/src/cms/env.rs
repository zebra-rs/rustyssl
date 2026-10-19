//! EnvelopedData and AuthEnvelopedData (`cms_env.c`): the content types, key transport and
//! KEK recipients, encrypting the content key to each recipient, and the data path's
//! cipher.
//!
//! Recipients of key agreement are in `kari.rs`, of passwords in `pwri.rs`; the key types'
//! parameters in `pkey.rs`.

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong};
use core::ptr;

use rustyssl_abi::{
    ASN1_GENERALIZEDTIME, ASN1_INTEGER, ASN1_OBJECT, ASN1_OCTET_STRING,
    ASN1_PKEY_CTRL_CMS_ENVELOPE, ASN1_PKEY_CTRL_CMS_IS_RI_TYPE_SUPPORTED,
    ASN1_PKEY_CTRL_CMS_RI_TYPE, ASN1_STRING, ASN1_TYPE, BIO, BIO_C_GET_CIPHER_CTX, BIO_TYPE_CIPHER,
    CMS_ContentInfo, CMS_EnvelopedData, CMS_KEY_PARAM, CMS_R_CIPHER_GET_TAG,
    CMS_R_CONTENT_NOT_FOUND, CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA, CMS_R_CTRL_FAILURE,
    CMS_R_ERROR_GETTING_PUBLIC_KEY, CMS_R_ERROR_SETTING_RECIPIENTINFO,
    CMS_R_INVALID_ENCRYPTED_KEY_LENGTH, CMS_R_INVALID_KEY_LENGTH, CMS_R_NO_KEY,
    CMS_R_NO_PRIVATE_KEY, CMS_R_NOT_KEK, CMS_R_NOT_KEY_TRANSPORT,
    CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE, CMS_R_UNKNOWN_CIPHER, CMS_R_UNSUPPORTED_KEK_ALGORITHM,
    CMS_R_UNSUPPORTED_RECIPIENT_TYPE, CMS_R_UNSUPPORTED_RECIPIENTINFO_TYPE, CMS_R_UNWRAP_ERROR,
    CMS_R_WRAP_ERROR, CMS_RECIPINFO_AGREE, CMS_RECIPINFO_KEK, CMS_RECIPINFO_NONE,
    CMS_RECIPINFO_OTHER, CMS_RECIPINFO_PASS, CMS_RECIPINFO_TRANS, CMS_RecipientInfo,
    CMS_SIGNERINFO_ISSUER_SERIAL, CMS_SIGNERINFO_KEYIDENTIFIER, CMS_USE_KEYID, ERR_LIB_CMS,
    ERR_R_ASN1_LIB, ERR_R_CMS_LIB, ERR_R_CRYPTO_LIB, ERR_R_EVP_LIB, ERR_R_PASSED_NULL_PARAMETER,
    EVP_CIPH_FLAG_CIPHER_WITH_MAC, EVP_CIPHER, EVP_CIPHER_CTX, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW,
    EVP_CTRL_AEAD_GET_TAG, EVP_CTRL_PROCESS_UNPROTECTED, EVP_PKEY, EVP_PKEY_CTX,
    NID_id_aes128_wrap, NID_id_aes192_wrap, NID_id_aes256_wrap, NID_id_smime_ct_authEnvelopedData,
    NID_pkcs7_data, NID_pkcs7_enveloped, NID_undef, OSSL_LIB_CTX, V_ASN1_OCTET_STRING,
    V_ASN1_UNDEF, X509, X509_ALGOR, X509_NAME,
};

use super::base::{
    CMS_ContentInfo_free, CMS_ContentInfo_new_ex, cms_of, content, ctx_of, ctx_parts, nid_obj,
    octets, raise, type_nid,
};
use super::enc::{drop_key, encrypted_content_init, encrypted_content_init_bio};
use super::sd::{set1_signer_identifier, signer_identifier_cert_cmp, signer_identifier_get0};
use super::{
    AuthEnvelopedData, CertificateChoices, CmsCtx, EncryptedContentInfo, EnvelopedData,
    KekRecipientInfo, KeyAgreeRecipientInfo, KeyTransRecipientInfo, OtherKeyAttribute,
    RecipientInfo, RevocationInfoChoice, Stack, sk_get,
};
use crate::asn1::string::{ASN1_OCTET_STRING_cmp, ASN1_OCTET_STRING_set, ASN1_STRING_set0};
use crate::asn1::tpl::encode::ASN1_item_i2d;
use crate::asn1::tpl::free::ASN1_item_free;
use crate::asn1::tpl::new::ASN1_item_new;
use crate::bio::mem::BIO_s_mem;
use crate::bio::{BIO_ctrl, BIO_find_type, BIO_free, BIO_new};
use crate::err::{ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::asymcipher::{
    EVP_PKEY_decrypt, EVP_PKEY_decrypt_init, EVP_PKEY_encrypt, EVP_PKEY_encrypt_init,
};
use crate::evp::cipher::{
    EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_flags, EVP_CIPHER_get_key_length,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_get_tag_length,
    EVP_CIPHER_CTX_get0_cipher, EVP_CIPHER_CTX_is_encrypting, EVP_CIPHER_CTX_new,
    EVP_CIPHER_CTX_set_flags, EVP_CipherUpdate, EVP_DecryptFinal_ex, EVP_DecryptInit_ex,
    EVP_DecryptUpdate, EVP_EncryptFinal_ex, EVP_EncryptInit_ex, EVP_EncryptUpdate,
};
use crate::evp::legacy_cipher::EVP_get_cipherbyname;
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_is_a, EVP_PKEY_up_ref, asn1_ctrl_of};
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_get0_pkey, EVP_PKEY_CTX_new_from_pkey};
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::{OBJ_nid2sn, OBJ_obj2nid, OBJ_obj2txt};
use crate::stack::{OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push};
use crate::x509::algor::X509_ALGOR_set0;
use crate::x509::cert::{X509_free, X509_get0_pubkey, X509_up_ref};

/// `OSSL_MAX_NAME_SIZE`, the room for an algorithm's name.
const NAME_LEN: usize = 50;

// `cms_local.h`'s other choices, which raise the version.
const CERTCHOICE_V2ACERT: c_int = 3;
const CERTCHOICE_OTHER: c_int = 4;
const REVCHOICE_OTHER: c_int = 1;

/// The recipient info behind a pointer.
///
/// # Safety
/// `ri` is NULL or a live recipient info.
pub(crate) unsafe fn ri_of<'a>(ri: *mut CMS_RecipientInfo) -> Option<&'a mut RecipientInfo> {
    // SAFETY: the caller's guarantee.
    unsafe { ri.cast::<RecipientInfo>().as_mut() }
}

/// The recipient info's choice, as `T`, if it is of type `type_`.
pub(crate) fn member<'a, T>(ri: &RecipientInfo, type_: c_int) -> Option<&'a mut T> {
    if ri.type_ != type_ {
        return None;
    }
    // SAFETY: the choice's member for its type, NULL or live.
    unsafe { ri.d.cast::<T>().as_mut() }
}

/// The key-transport choice, or `None` (`CMS_R_NOT_KEY_TRANSPORT`).
fn ktri_of<'a>(ri: &RecipientInfo, f: &str) -> Option<&'a mut KeyTransRecipientInfo> {
    let k = member(ri, CMS_RECIPINFO_TRANS);
    if k.is_none() {
        raise(CMS_R_NOT_KEY_TRANSPORT, f);
    }
    k
}

/// The KEK choice, or `None` (`CMS_R_NOT_KEK`).
fn kekri_of<'a>(ri: &RecipientInfo, f: &str) -> Option<&'a mut KekRecipientInfo> {
    let k = member(ri, CMS_RECIPINFO_KEK);
    if k.is_none() {
        raise(CMS_R_NOT_KEK, f);
    }
    k
}

/// `ossl_cms_get0_env_enc_content`: (Auth)EnvelopedData's encrypted content, or `None`
/// (`CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA` for other types).
pub(crate) fn env_enc_content<'a>(
    cms: *const CMS_ContentInfo,
) -> Option<&'a mut EncryptedContentInfo> {
    let ec = match type_nid(cms) {
        // SAFETY: the content of its type, NULL or live.
        n if n == NID_pkcs7_enveloped => unsafe { content::<EnvelopedData>(cms) }
            .map_or(ptr::null_mut(), |e| e.encrypted_content_info),
        // SAFETY: as above.
        n if n == NID_id_smime_ct_authEnvelopedData => unsafe { content::<AuthEnvelopedData>(cms) }
            .map_or(ptr::null_mut(), |e| e.auth_encrypted_content_info),
        _ => {
            raise(
                CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA,
                "cms_get_enveloped_type",
            );
            return None;
        }
    };
    // SAFETY: the content's encrypted content, made with it, or NULL.
    unsafe { ec.as_mut() }
}

/// `cms_enveloped_data_init`: the object made EnvelopedData if it has no content yet.
///
/// # Safety
/// `cms` is a live object.
unsafe fn enveloped_data_init<'a>(cms: *mut CMS_ContentInfo) -> Option<&'a mut EnvelopedData> {
    // SAFETY: the caller's guarantee.
    let c = unsafe { cms_of(cms) }?;
    if !c.d.is_null() {
        if type_nid(cms) != NID_pkcs7_enveloped {
            raise(
                CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA,
                "ossl_cms_get0_enveloped",
            );
            return None;
        }
        // SAFETY: the content of its type.
        return unsafe { content::<EnvelopedData>(cms) };
    }
    // SAFETY: no preconditions.
    let it = unsafe { super::CMS_EnvelopedData_it() };
    // SAFETY: the item.
    let env = unsafe { ASN1_item_new(it) }.cast::<EnvelopedData>();
    // SAFETY: the new content, or NULL.
    let Some(e) = (unsafe { env.as_mut() }) else {
        raise(ERR_R_ASN1_LIB, "cms_enveloped_data_init");
        return None;
    };
    c.d = env.cast();
    e.version = 0;
    // SAFETY: its encrypted content, made with it.
    if let Some(ec) = unsafe { e.encrypted_content_info.as_mut() } {
        ec.content_type = nid_obj(NID_pkcs7_data);
    }
    // SAFETY: the object's own type, or NULL.
    unsafe { crate::objects::ASN1_OBJECT_free(c.content_type) };
    c.content_type = nid_obj(NID_pkcs7_enveloped);
    Some(e)
}

/// `cms_auth_enveloped_data_init`: the object made AuthEnvelopedData if it has no content yet.
///
/// # Safety
/// `cms` is a live object.
unsafe fn auth_enveloped_data_init<'a>(
    cms: *mut CMS_ContentInfo,
) -> Option<&'a mut AuthEnvelopedData> {
    // SAFETY: the caller's guarantee.
    let c = unsafe { cms_of(cms) }?;
    if !c.d.is_null() {
        if type_nid(cms) != NID_id_smime_ct_authEnvelopedData {
            raise(
                CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA,
                "ossl_cms_get0_auth_enveloped",
            );
            return None;
        }
        // SAFETY: the content of its type.
        return unsafe { content::<AuthEnvelopedData>(cms) };
    }
    // SAFETY: no preconditions.
    let it = unsafe { super::auth_enveloped_data_it() };
    // SAFETY: the item.
    let aenv = unsafe { ASN1_item_new(it) }.cast::<AuthEnvelopedData>();
    // SAFETY: the new content, or NULL.
    let Some(e) = (unsafe { aenv.as_mut() }) else {
        raise(ERR_R_ASN1_LIB, "cms_auth_enveloped_data_init");
        return None;
    };
    c.d = aenv.cast();
    e.version = 0;
    // SAFETY: its encrypted content, made with it.
    if let Some(ec) = unsafe { e.auth_encrypted_content_info.as_mut() } {
        ec.content_type = nid_obj(NID_pkcs7_data);
    }
    // SAFETY: the object's own type, or NULL.
    unsafe { crate::objects::ASN1_OBJECT_free(c.content_type) };
    c.content_type = nid_obj(NID_id_smime_ct_authEnvelopedData);
    Some(e)
}

/// Which key type's envelope parameters apply.
enum KeyKind {
    Dh,
    Ec,
    Rsa,
    Other,
}

fn key_kind(pkey: *mut EVP_PKEY) -> KeyKind {
    let is = |name: &core::ffi::CStr| {
        // SAFETY: a live key; a static name.
        (unsafe { EVP_PKEY_is_a(pkey, name.as_ptr()) }) != 0
    };
    if is(c"DHX") || is(c"DH") {
        KeyKind::Dh
    } else if is(c"EC") {
        KeyKind::Ec
    } else if is(c"RSA") {
        KeyKind::Rsa
    } else {
        KeyKind::Other
    }
}

/// The key method's own envelope control for a key of another type: 1 without one.
///
/// # Safety
/// `pkey` is a live key; `ri` the recipient info.
unsafe fn other_envelope(pkey: *mut EVP_PKEY, ri: *mut RecipientInfo, cmd: c_int) -> c_int {
    const F: &str = "ossl_cms_env_asn1_ctrl";
    // SAFETY: the caller's guarantee; the recipient info, as the control takes it.
    match unsafe {
        asn1_ctrl_of(
            pkey,
            ASN1_PKEY_CTRL_CMS_ENVELOPE,
            c_long::from(cmd),
            ri.cast(),
        )
    } {
        None => 1,
        Some(-2) => {
            raise(CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE, F);
            0
        }
        Some(i) if i <= 0 => {
            raise(CMS_R_CTRL_FAILURE, F);
            0
        }
        Some(_) => 1,
    }
}

/// `ossl_cms_env_asn1_ctrl` for key transport: the key's parameters for encrypting (`cmd` 0)
/// or decrypting (1). As in OpenSSL, any nonzero result lets the caller go on.
///
/// # Safety
/// `ri` is the live recipient info whose choice is `k`.
pub(crate) unsafe fn ktri_asn1_ctrl(
    ri: *mut RecipientInfo,
    k: &mut KeyTransRecipientInfo,
    cmd: c_int,
) -> c_int {
    let pkey = k.pkey;
    if pkey.is_null() {
        return 0;
    }
    match key_kind(pkey) {
        // Key agreement's parameters for a key-transport recipient: OpenSSL fails on the
        // originator it can't find.
        KeyKind::Dh | KeyKind::Ec => {
            if cmd == 1 || !k.pctx.is_null() {
                raise(
                    rustyssl_abi::CMS_R_NOT_KEY_AGREEMENT,
                    "CMS_RecipientInfo_kari_get0_orig_id",
                );
            }
            0
        }
        KeyKind::Rsa => super::pkey::rsa_envelope(k, cmd),
        // SAFETY: the caller's guarantee.
        KeyKind::Other => unsafe { other_envelope(pkey, ri, cmd) },
    }
}

/// `ossl_cms_env_asn1_ctrl` for key agreement, with its context's key.
///
/// # Safety
/// `ri` is the live recipient info whose choice is `k`.
pub(crate) unsafe fn kari_asn1_ctrl(
    ri: *mut RecipientInfo,
    k: &mut KeyAgreeRecipientInfo,
    cmd: c_int,
) -> c_int {
    if k.pctx.is_null() {
        return 0;
    }
    // SAFETY: a live context.
    let pkey = unsafe { EVP_PKEY_CTX_get0_pkey(k.pctx) };
    if pkey.is_null() {
        return 0;
    }
    match key_kind(pkey) {
        KeyKind::Dh => super::pkey::dh_envelope(k, cmd),
        KeyKind::Ec => super::pkey::ecdh_envelope(k, cmd),
        KeyKind::Rsa => {
            raise(CMS_R_NOT_KEY_TRANSPORT, "CMS_RecipientInfo_ktri_get0_algs");
            if cmd == 1 { -1 } else { 0 }
        }
        // SAFETY: the caller's guarantee.
        KeyKind::Other => unsafe { other_envelope(pkey, ri, cmd) },
    }
}

ffi_export! {
    /// The recipient info's type (`CMS_RECIPINFO_*`).
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info.
    pub unsafe extern "C" fn CMS_RecipientInfo_type(ri: *mut CMS_RecipientInfo) -> c_int
    where failure = CMS_RECIPINFO_NONE, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        unsafe { ri_of(ri) }.map_or(CMS_RECIPINFO_NONE, |r| r.type_)
    }
}

ffi_export! {
    /// The key context of a key-transport or key-agreement recipient, or NULL.
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info.
    pub unsafe extern "C" fn CMS_RecipientInfo_get0_pkey_ctx(ri: *mut CMS_RecipientInfo) -> *mut EVP_PKEY_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return ptr::null_mut() };
        if let Some(k) = member::<KeyTransRecipientInfo>(r, CMS_RECIPINFO_TRANS) {
            return k.pctx;
        }
        if let Some(k) = super::kemri::kemri_of(r, "", false) {
            return k.pctx;
        }
        member::<KeyAgreeRecipientInfo>(r, CMS_RECIPINFO_AGREE).map_or(ptr::null_mut(), |k| k.pctx)
    }
}

/// `CMS_EnvelopedData_create_ex` and `CMS_AuthEnvelopedData_create_ex`.
///
/// # Safety
/// `cipher` is NULL or live; `libctx` and `propq` NULL or live.
unsafe fn create(
    cipher: *const EVP_CIPHER,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
    auth: bool,
    f: &str,
) -> *mut CMS_ContentInfo {
    // SAFETY: the caller's guarantee.
    let cms = unsafe { CMS_ContentInfo_new_ex(libctx, propq) };
    let ok = !cms.is_null() && {
        let ec = if auth {
            // SAFETY: the new object.
            unsafe { auth_enveloped_data_init(cms) }.map(|e| e.auth_encrypted_content_info)
        } else {
            // SAFETY: as above.
            unsafe { enveloped_data_init(cms) }.map(|e| e.encrypted_content_info)
        };
        // SAFETY: the content's encrypted content, made with it.
        ec.and_then(|ec| unsafe { ec.as_mut() })
            .is_some_and(|ec| encrypted_content_init(ec, cipher, &[]))
    };
    if ok {
        return cms;
    }
    // SAFETY: the object made here, or NULL.
    unsafe { CMS_ContentInfo_free(cms) };
    raise(ERR_R_CMS_LIB, f);
    ptr::null_mut()
}

ffi_export! {
    /// A new EnvelopedData object for `cipher`, in a library context. NULL on failure.
    ///
    /// # Safety
    /// `cipher` is NULL or live; `libctx` NULL or live; `propq` NULL or a C string.
    pub unsafe extern "C" fn CMS_EnvelopedData_create_ex(cipher: *const EVP_CIPHER, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut CMS_ContentInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        unsafe { create(cipher, libctx, propq, false, "CMS_EnvelopedData_create_ex") }
    }
}

ffi_export! {
    /// A new EnvelopedData object for `cipher`. NULL on failure.
    ///
    /// # Safety
    /// `cipher` is NULL or live.
    pub unsafe extern "C" fn CMS_EnvelopedData_create(cipher: *const EVP_CIPHER) -> *mut CMS_ContentInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        unsafe { create(cipher, ptr::null_mut(), ptr::null(), false, "CMS_EnvelopedData_create_ex") }
    }
}

ffi_export! {
    /// A new AuthEnvelopedData object for the AEAD `cipher`, in a library context. NULL on
    /// failure.
    ///
    /// # Safety
    /// `cipher` is NULL or live; `libctx` NULL or live; `propq` NULL or a C string.
    pub unsafe extern "C" fn CMS_AuthEnvelopedData_create_ex(cipher: *const EVP_CIPHER, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut CMS_ContentInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        unsafe { create(cipher, libctx, propq, true, "CMS_AuthEnvelopedData_create_ex") }
    }
}

ffi_export! {
    /// A new AuthEnvelopedData object for the AEAD `cipher`. NULL on failure.
    ///
    /// # Safety
    /// `cipher` is NULL or live.
    pub unsafe extern "C" fn CMS_AuthEnvelopedData_create(cipher: *const EVP_CIPHER) -> *mut CMS_ContentInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        unsafe { create(cipher, ptr::null_mut(), ptr::null(), true, "CMS_AuthEnvelopedData_create_ex") }
    }
}

ffi_export! {
    /// Decrypts an EnvelopedData (with a key and certificate, or a password in `secret`) into
    /// a new memory BIO. NULL on failure.
    ///
    /// # Safety
    /// `env` is NULL or a live EnvelopedData; the others NULL or live.
    pub unsafe extern "C" fn CMS_EnvelopedData_decrypt(env: *mut CMS_EnvelopedData, detached_data: *mut BIO, pkey: *mut EVP_PKEY, cert: *mut X509, secret: *mut ASN1_OCTET_STRING, flags: core::ffi::c_uint, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        if env.is_null() {
            raise(ERR_R_PASSED_NULL_PARAMETER, "CMS_EnvelopedData_decrypt");
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let ci = unsafe { CMS_ContentInfo_new_ex(libctx, propq) };
        let mut bio: *mut BIO = ptr::null_mut();
        let mut res = 0;
        // SAFETY: the new object, or NULL.
        if let Some(c) = unsafe { cms_of(ci) } {
            // SAFETY: no preconditions.
            let method = unsafe { BIO_s_mem() };
            // SAFETY: the built-in method.
            bio = unsafe { BIO_new(method) };
            if !bio.is_null() {
                c.content_type = nid_obj(NID_pkcs7_enveloped);
                c.d = env.cast();
                res = 'end: {
                    // SAFETY: NULL or the caller's string.
                    if let Some(s) = unsafe { secret.as_ref() } {
                        let pass = s.data;
                        let len = isize::try_from(s.length).unwrap_or(-1);
                        // SAFETY: the object borrowing `env`; the password's octets.
                        if unsafe { super::smime::CMS_decrypt_set1_password(ci, pass, len) } != 1 {
                            break 'end 0;
                        }
                        // SAFETY: as above.
                        break 'end unsafe { super::smime::CMS_decrypt(ci, ptr::null_mut(), ptr::null_mut(), detached_data, bio, flags) };
                    }
                    // SAFETY: as above; the caller's key and certificate.
                    unsafe { super::smime::CMS_decrypt(ci, pkey, cert, detached_data, bio, flags) }
                };
            }
        }
        // SAFETY: the object made here, or NULL.
        if let Some(c) = unsafe { cms_of(ci) } {
            // The caller keeps `env`.
            c.d = ptr::null_mut();
            c.content_type = ptr::null_mut();
        }
        // SAFETY: as above.
        unsafe { CMS_ContentInfo_free(ci) };
        if res == 0 {
            // SAFETY: the BIO made here, or NULL.
            unsafe { BIO_free(bio) };
            return ptr::null_mut();
        }
        bio
    }
}

/// `cms_RecipientInfo_ktri_init`.
///
/// # Safety
/// `ri` is a new recipient info; `recip` a live certificate; `pk` its key.
unsafe fn ktri_init(
    ri: &mut RecipientInfo,
    recip: *mut X509,
    pk: *mut EVP_PKEY,
    flags: c_int,
    ctx: *const CmsCtx,
) -> bool {
    // SAFETY: no preconditions.
    let it = unsafe { super::key_trans_recipient_info_it() };
    // SAFETY: the item.
    let kp = unsafe { ASN1_item_new(it) }.cast::<KeyTransRecipientInfo>();
    if kp.is_null() {
        return false;
    }
    ri.d = kp.cast();
    ri.encoded_type = CMS_RECIPINFO_TRANS;
    ri.type_ = CMS_RECIPINFO_TRANS;
    let rip: *mut RecipientInfo = ri;
    // SAFETY: the new choice.
    let k = unsafe { &mut *kp };
    k.cms_ctx = ctx;
    let idtype = if flags & CMS_USE_KEYID != 0 {
        k.version = 2;
        CMS_SIGNERINFO_KEYIDENTIFIER
    } else {
        k.version = 0;
        CMS_SIGNERINFO_ISSUER_SERIAL
    };
    // RecipientIdentifier and SignerIdentifier are the same structure.
    // SAFETY: its identifier, made with it.
    let Some(rid) = (unsafe { k.rid.as_mut() }) else {
        return false;
    };
    // SAFETY: the caller's certificate.
    if !unsafe { set1_signer_identifier(rid, recip, idtype) } {
        return false;
    }
    // SAFETY: as above.
    if unsafe { X509_up_ref(recip) } == 0 {
        return false;
    }
    // SAFETY: the caller's key.
    if unsafe { EVP_PKEY_up_ref(pk) } == 0 {
        // SAFETY: the reference taken above.
        unsafe { X509_free(recip) };
        return false;
    }
    k.pkey = pk;
    k.recip = recip;
    if flags & CMS_KEY_PARAM != 0 {
        let (libctx, propq) = ctx_parts(ctx);
        // SAFETY: the recipient's key; the context's parts.
        k.pctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, k.pkey, propq) };
        if k.pctx.is_null() {
            return false;
        }
        // SAFETY: a live context.
        return unsafe { EVP_PKEY_encrypt_init(k.pctx) } > 0;
    }
    // SAFETY: the recipient info and its choice.
    unsafe { ktri_asn1_ctrl(rip, k, 0) != 0 }
}

ffi_export! {
    /// Adds a recipient for the certificate `recip`, by key transport or key agreement as its
    /// key allows (with the originator's key and certificate, or an ephemeral key). The new
    /// recipient info, or NULL.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; `recip` a live certificate; the others NULL or live.
    pub unsafe extern "C" fn CMS_add1_recipient(cms: *mut CMS_ContentInfo, recip: *mut X509, originator_priv_key: *mut EVP_PKEY, originator: *mut X509, flags: core::ffi::c_uint) -> *mut CMS_RecipientInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        const F: &str = "CMS_add1_recipient";
        let ctx = ctx_of(cms);
        // SAFETY: the caller's guarantee.
        let ris = unsafe { super::base::CMS_get0_RecipientInfos(cms) };
        if ris.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let it = unsafe { super::recipient_info_it() };
        // SAFETY: the item.
        let rip = unsafe { ASN1_item_new(it) }.cast::<RecipientInfo>();
        let flags = c_int::try_from(flags).unwrap_or(c_int::MAX);
        let ok = 'err: {
            // SAFETY: the new recipient info, or NULL.
            let Some(ri) = (unsafe { rip.as_mut() }) else {
                raise(ERR_R_ASN1_LIB, F);
                break 'err false;
            };
            // SAFETY: the caller's certificate.
            let pk = unsafe { X509_get0_pubkey(recip) };
            if pk.is_null() {
                raise(CMS_R_ERROR_GETTING_PUBLIC_KEY, F);
                break 'err false;
            }
            let ok = match pkey_get_ri_type(pk) {
                // SAFETY: the new recipient info; the certificate and its key.
                CMS_RECIPINFO_TRANS => unsafe { ktri_init(ri, recip, pk, flags, ctx) },
                // SAFETY: as above; the originator's key and certificate, or NULL.
                CMS_RECIPINFO_AGREE => unsafe {
                    super::kari::kari_init(ri, recip, pk, originator, originator_priv_key, flags, ctx)
                },
                // SAFETY: as above.
                rustyssl_abi::CMS_RECIPINFO_KEM => unsafe { super::kemri::kemri_init(ri, recip, pk, flags, ctx) },
                _ => {
                    raise(CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE, F);
                    false
                }
            };
            if !ok {
                break 'err false;
            }
            // SAFETY: the object's recipient infos; the new one.
            if unsafe { OPENSSL_sk_push(ris.cast(), rip.cast()) } == 0 {
                raise(ERR_R_CRYPTO_LIB, F);
                break 'err false;
            }
            true
        };
        if ok {
            return rip.cast();
        }
        // SAFETY: the recipient info made here, or NULL.
        unsafe { ASN1_item_free(rip.cast(), it) };
        ptr::null_mut()
    }
}

ffi_export! {
    /// Adds a recipient for the certificate `recip` (with an ephemeral key for key
    /// agreement). The new recipient info, or NULL.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; `recip` a live certificate.
    pub unsafe extern "C" fn CMS_add1_recipient_cert(cms: *mut CMS_ContentInfo, recip: *mut X509, flags: core::ffi::c_uint) -> *mut CMS_RecipientInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        unsafe { CMS_add1_recipient(cms, recip, ptr::null_mut(), ptr::null_mut(), flags) }
    }
}

ffi_export! {
    /// A key-transport recipient's key, certificate, and key-encryption algorithm: 1, or 0.
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info; the others NULL or room for a pointer.
    pub unsafe extern "C" fn CMS_RecipientInfo_ktri_get0_algs(ri: *mut CMS_RecipientInfo, pk: *mut *mut EVP_PKEY, recip: *mut *mut X509, palg: *mut *mut X509_ALGOR) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return 0 };
        let Some(k) = ktri_of(r, "CMS_RecipientInfo_ktri_get0_algs") else { return 0 };
        // SAFETY: the caller's room, or NULL.
        if let Some(p) = unsafe { pk.as_mut() } {
            *p = k.pkey;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { recip.as_mut() } {
            *p = k.recip;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { palg.as_mut() } {
            *p = k.key_encryption_algorithm;
        }
        1
    }
}

ffi_export! {
    /// A key-transport recipient's identifier: its key identifier, or issuer and serial
    /// number. 1, or 0.
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info; the others NULL or room for a pointer.
    pub unsafe extern "C" fn CMS_RecipientInfo_ktri_get0_signer_id(ri: *mut CMS_RecipientInfo, keyid: *mut *mut ASN1_OCTET_STRING, issuer: *mut *mut X509_NAME, sno: *mut *mut ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return 0 };
        let Some(k) = ktri_of(r, "CMS_RecipientInfo_ktri_get0_signer_id") else { return 0 };
        // SAFETY: its identifier, made with it.
        let Some(rid) = (unsafe { k.rid.as_ref() }) else { return 0 };
        // SAFETY: the caller's room.
        unsafe { signer_identifier_get0(rid, keyid, issuer, sno) }
    }
}

ffi_export! {
    /// 0 if a key-transport recipient is the certificate's; -2 for other recipients.
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info; `cert` a live certificate.
    pub unsafe extern "C" fn CMS_RecipientInfo_ktri_cert_cmp(ri: *mut CMS_RecipientInfo, cert: *mut X509) -> c_int
    where failure = -2, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return -2 };
        let Some(k) = ktri_of(r, "CMS_RecipientInfo_ktri_cert_cmp") else { return -2 };
        // SAFETY: its identifier, made with it.
        let Some(rid) = (unsafe { k.rid.as_ref() }) else { return -1 };
        // SAFETY: the caller's certificate.
        unsafe { signer_identifier_cert_cmp(rid, cert) }
    }
}

ffi_export! {
    /// Sets a key-transport recipient's (private) key, which it takes: 1, or 0.
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info; `pkey` NULL or live.
    pub unsafe extern "C" fn CMS_RecipientInfo_set0_pkey(ri: *mut CMS_RecipientInfo, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return 0 };
        let Some(k) = ktri_of(r, "CMS_RecipientInfo_set0_pkey") else { return 0 };
        // SAFETY: its own key, or NULL.
        unsafe { EVP_PKEY_free(k.pkey) };
        k.pkey = pkey;
        1
    }
}

/// `cms_RecipientInfo_ktri_encrypt`: the content key, encrypted to the recipient's key.
///
/// # Safety
/// `cms` is a live object; `ri` one of its recipient infos.
unsafe fn ktri_encrypt(cms: *const CMS_ContentInfo, ri: *mut RecipientInfo) -> bool {
    const F: &str = "cms_RecipientInfo_ktri_encrypt";
    // SAFETY: the caller's guarantee.
    let Some(k) = ktri_of(unsafe { &*ri }, F) else {
        return false;
    };
    let Some(ec) = env_enc_content(cms) else {
        return false;
    };
    let (libctx, propq) = ctx_parts(ctx_of(cms));
    let mut pctx = k.pctx;
    let ok = 'err: {
        if pctx.is_null() {
            // SAFETY: the recipient's key; the context's parts.
            pctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, k.pkey, propq) };
            if pctx.is_null() {
                return false;
            }
            // SAFETY: a live context.
            if unsafe { EVP_PKEY_encrypt_init(pctx) } <= 0 {
                break 'err false;
            }
        // SAFETY: the recipient info and its choice.
        } else if unsafe { ktri_asn1_ctrl(ri, k, 0) } == 0 {
            break 'err false;
        }
        let mut eklen = 0usize;
        // SAFETY: a live context; room for the length; the content key.
        if unsafe { EVP_PKEY_encrypt(pctx, ptr::null_mut(), &mut eklen, ec.key, ec.keylen) } <= 0 {
            break 'err false;
        }
        let ek = mem::alloc(eklen).cast::<c_uchar>();
        if ek.is_null() {
            break 'err false;
        }
        // SAFETY: as above; `eklen` octets of room.
        let r = unsafe { EVP_PKEY_encrypt(pctx, ek, &mut eklen, ec.key, ec.keylen) };
        let Ok(n) = c_int::try_from(eklen) else {
            // SAFETY: the buffer made here.
            unsafe { mem::release(ek.cast()) };
            break 'err false;
        };
        if r <= 0 {
            // SAFETY: as above.
            unsafe { mem::release(ek.cast()) };
            break 'err false;
        }
        // SAFETY: the recipient's encrypted key, taking the buffer.
        unsafe { ASN1_STRING_set0(k.encrypted_key.cast(), ek.cast(), n) };
        true
    };
    // SAFETY: the context used, the recipient's or made here.
    unsafe { EVP_PKEY_CTX_free(pctx) };
    k.pctx = ptr::null_mut();
    ok
}

/// The cipher an algorithm names, fetched in the context or else built in, and the fetched
/// one to free.
///
/// # Safety
/// `obj` is NULL or a live object.
pub(crate) unsafe fn cipher_of(
    obj: *const ASN1_OBJECT,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> (*const EVP_CIPHER, *mut EVP_CIPHER) {
    let mut name = [0 as c_char; NAME_LEN];
    let len = c_int::try_from(NAME_LEN).unwrap_or(0);
    // SAFETY: room for the name; the caller's object.
    unsafe { OBJ_obj2txt(name.as_mut_ptr(), len, obj, 0) };
    // SAFETY: the name; the context's parts.
    let fetched = unsafe { EVP_CIPHER_fetch(libctx, name.as_ptr(), propq) };
    if !fetched.is_null() {
        return (fetched, fetched);
    }
    // SAFETY: the caller's object.
    let nid = unsafe { OBJ_obj2nid(obj) };
    // SAFETY: any NID.
    let sn = unsafe { OBJ_nid2sn(nid) };
    // SAFETY: NULL or a static name.
    (unsafe { EVP_get_cipherbyname(sn) }, ptr::null_mut())
}

/// `cms_RecipientInfo_ktri_decrypt`: the content key, decrypted with the recipient's key
/// (of the content cipher's length when no certificate picked the recipient, so as to say
/// nothing to an oracle).
///
/// # Safety
/// `cms` is a live object; `ri` one of its recipient infos, of key transport.
unsafe fn ktri_decrypt(cms: *mut CMS_ContentInfo, ri: *mut RecipientInfo) -> bool {
    const F: &str = "cms_RecipientInfo_ktri_decrypt";
    // SAFETY: the caller's guarantee.
    let Some(k) = member::<KeyTransRecipientInfo>(unsafe { &*ri }, CMS_RECIPINFO_TRANS) else {
        return false;
    };
    let Some(ec) = env_enc_content(cms) else {
        return false;
    };
    let (libctx, propq) = ctx_parts(ctx_of(cms));
    if k.pkey.is_null() {
        raise(CMS_R_NO_PRIVATE_KEY, F);
        return false;
    }
    let mut fixlen = 0usize;
    if ec.havenocert != 0 && ec.debug == 0 {
        // SAFETY: the content's algorithm, or NULL.
        let obj = unsafe { ec.content_encryption_algorithm.as_ref() }
            .map_or(ptr::null(), |a| a.algorithm.cast_const());
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        // SAFETY: the object; the context's parts.
        let (cipher, fetched) = unsafe { cipher_of(obj, libctx, propq) };
        if cipher.is_null() {
            // SAFETY: no preconditions.
            unsafe { ERR_clear_last_mark() };
            raise(CMS_R_UNKNOWN_CIPHER, F);
            return false;
        }
        // SAFETY: no preconditions.
        unsafe { ERR_pop_to_mark() };
        // SAFETY: a live cipher.
        fixlen = usize::try_from(unsafe { EVP_CIPHER_get_key_length(cipher) }).unwrap_or(0);
        // SAFETY: the fetched cipher, or NULL.
        unsafe { EVP_CIPHER_free(fetched) };
    }
    let ok = 'err: {
        // SAFETY: the recipient's key; the context's parts.
        k.pctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, k.pkey, propq) };
        if k.pctx.is_null() {
            break 'err false;
        }
        // SAFETY: a live context.
        if unsafe { EVP_PKEY_decrypt_init(k.pctx) } <= 0 {
            break 'err false;
        }
        // SAFETY: the recipient info and its choice.
        if unsafe { ktri_asn1_ctrl(ri, k, 1) } == 0 {
            break 'err false;
        }
        // SAFETY: the recipient's encrypted key.
        let input = unsafe { octets(k.encrypted_key) };
        let mut eklen = 0usize;
        // SAFETY: a live context; room for the length; the input.
        if unsafe {
            EVP_PKEY_decrypt(
                k.pctx,
                ptr::null_mut(),
                &mut eklen,
                input.as_ptr(),
                input.len(),
            )
        } <= 0
        {
            break 'err false;
        }
        let room = eklen;
        let ek = mem::alloc(room).cast::<c_uchar>();
        if ek.is_null() {
            break 'err false;
        }
        // SAFETY: as above; `eklen` octets of room.
        let r = unsafe { EVP_PKEY_decrypt(k.pctx, ek, &mut eklen, input.as_ptr(), input.len()) };
        if r <= 0 || eklen == 0 || (fixlen != 0 && eklen != fixlen) {
            crate::err::raise(
                rustyssl_abi::ERR_LIB_EVP,
                ERR_R_EVP_LIB,
                "evp_pkey_decrypt_alloc",
            );
            // SAFETY: the buffer made here.
            unsafe { mem::release_clean(ek.cast(), room) };
            break 'err false;
        }
        drop_key(ec);
        ec.key = ek;
        ec.keylen = eklen;
        true
    };
    // SAFETY: the context made here, or NULL.
    unsafe { EVP_PKEY_CTX_free(k.pctx) };
    k.pctx = ptr::null_mut();
    ok
}

ffi_export! {
    /// Compares a KEK recipient's key identifier with `id` (as `ASN1_OCTET_STRING_cmp`); -2
    /// for other recipients.
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info; `id` holds `idlen` octets.
    pub unsafe extern "C" fn CMS_RecipientInfo_kekri_id_cmp(ri: *mut CMS_RecipientInfo, id: *const c_uchar, idlen: usize) -> c_int
    where failure = -2, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return -2 };
        let Some(k) = kekri_of(r, "CMS_RecipientInfo_kekri_id_cmp") else { return -2 };
        // SAFETY: its identifier, made with it.
        let Some(kid) = (unsafe { k.kekid.as_ref() }) else { return -2 };
        let Ok(length) = c_int::try_from(idlen) else { return 1 };
        let tmp = ASN1_STRING {
            length,
            type_: V_ASN1_OCTET_STRING,
            data: id.cast_mut(),
            flags: 0,
        };
        // SAFETY: the caller's octets, as a string; the identifier's key identifier.
        unsafe { ASN1_OCTET_STRING_cmp(&tmp, kid.key_identifier) }
    }
}

/// `aes_wrap_keylen`.
fn aes_wrap_keylen(nid: c_int) -> usize {
    match nid {
        n if n == NID_id_aes128_wrap => 16,
        n if n == NID_id_aes192_wrap => 24,
        n if n == NID_id_aes256_wrap => 32,
        _ => 0,
    }
}

ffi_export! {
    /// Adds a KEK recipient: the key (taken, for the AES key wrap `nid` or the one of its
    /// length), its identifier (taken), and the optional date and other attribute (taken).
    /// The new recipient info, or NULL.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; `key` and `id` NULL or from CRYPTO_malloc, of their
    /// lengths; the others NULL or live.
    pub unsafe extern "C" fn CMS_add0_recipient_key(cms: *mut CMS_ContentInfo, nid: c_int, key: *mut c_uchar, keylen: usize, id: *mut c_uchar, idlen: usize, date: *mut ASN1_GENERALIZEDTIME, other_type_id: *mut ASN1_OBJECT, other_type: *mut ASN1_TYPE) -> *mut CMS_RecipientInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        const F: &str = "CMS_add0_recipient_key";
        // SAFETY: the caller's guarantee.
        let ris = unsafe { super::base::CMS_get0_RecipientInfos(cms) };
        if ris.is_null() {
            return ptr::null_mut();
        }
        let nid = if nid == NID_undef {
            match keylen {
                16 => NID_id_aes128_wrap,
                24 => NID_id_aes192_wrap,
                32 => NID_id_aes256_wrap,
                _ => {
                    raise(CMS_R_INVALID_KEY_LENGTH, F);
                    return ptr::null_mut();
                }
            }
        } else {
            let exp = aes_wrap_keylen(nid);
            if exp == 0 {
                raise(CMS_R_UNSUPPORTED_KEK_ALGORITHM, F);
                return ptr::null_mut();
            }
            if keylen != exp {
                raise(CMS_R_INVALID_KEY_LENGTH, F);
                return ptr::null_mut();
            }
            nid
        };
        let Ok(idlen) = c_int::try_from(idlen) else {
            raise(CMS_R_INVALID_KEY_LENGTH, F);
            return ptr::null_mut();
        };
        // SAFETY: no preconditions.
        let it = unsafe { super::recipient_info_it() };
        // SAFETY: the item.
        let rip = unsafe { ASN1_item_new(it) }.cast::<RecipientInfo>();
        let kekri = 'err: {
            // SAFETY: the new recipient info, or NULL.
            let Some(ri) = (unsafe { rip.as_mut() }) else {
                raise(ERR_R_ASN1_LIB, F);
                break 'err None;
            };
            // SAFETY: no preconditions.
            let kit = unsafe { super::kek_recipient_info_it() };
            // SAFETY: the item.
            let kp = unsafe { ASN1_item_new(kit) }.cast::<KekRecipientInfo>();
            if kp.is_null() {
                raise(ERR_R_ASN1_LIB, F);
                break 'err None;
            }
            ri.d = kp.cast();
            ri.encoded_type = CMS_RECIPINFO_KEK;
            ri.type_ = CMS_RECIPINFO_KEK;
            // SAFETY: the new choice.
            let k = unsafe { &mut *kp };
            // SAFETY: its identifier, made with it.
            let Some(kid) = (unsafe { k.kekid.as_mut() }) else { break 'err None };
            if !other_type_id.is_null() {
                // SAFETY: no preconditions.
                let oit = unsafe { super::other_key_attribute_it() };
                // SAFETY: the item.
                kid.other = unsafe { ASN1_item_new(oit) }.cast::<OtherKeyAttribute>();
                if kid.other.is_null() {
                    raise(ERR_R_ASN1_LIB, F);
                    break 'err None;
                }
            }
            // SAFETY: the object's recipient infos; the new one.
            if unsafe { OPENSSL_sk_push(ris.cast(), rip.cast()) } == 0 {
                raise(ERR_R_CRYPTO_LIB, F);
                break 'err None;
            }
            Some((k, kid))
        };
        let Some((k, kid)) = kekri else {
            // SAFETY: the recipient info made here, or NULL.
            unsafe { ASN1_item_free(rip.cast(), it) };
            return ptr::null_mut();
        };
        // Nothing fails from here on.
        k.version = 4;
        k.key = key;
        k.keylen = keylen;
        // SAFETY: the identifier's key identifier, taking the caller's octets.
        unsafe { ASN1_STRING_set0(kid.key_identifier.cast(), id.cast(), idlen) };
        kid.date = date;
        // SAFETY: the attribute made above, or NULL.
        if let Some(o) = unsafe { kid.other.as_mut() } {
            o.key_attr_id = other_type_id;
            o.key_attr = other_type;
        }
        // SAFETY: the recipient's algorithm, made with it; a static object.
        unsafe { X509_ALGOR_set0(k.key_encryption_algorithm, nid_obj(nid), V_ASN1_UNDEF, ptr::null_mut()) };
        rip.cast()
    }
}

ffi_export! {
    /// A KEK recipient's algorithm, key identifier, date, and other attribute: 1, or 0.
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info; the others NULL or room for a pointer.
    pub unsafe extern "C" fn CMS_RecipientInfo_kekri_get0_id(ri: *mut CMS_RecipientInfo, palg: *mut *mut X509_ALGOR, pid: *mut *mut ASN1_OCTET_STRING, pdate: *mut *mut ASN1_GENERALIZEDTIME, potherid: *mut *mut ASN1_OBJECT, pothertype: *mut *mut ASN1_TYPE) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return 0 };
        let Some(k) = kekri_of(r, "CMS_RecipientInfo_kekri_get0_id") else { return 0 };
        // SAFETY: its identifier, made with it.
        let Some(kid) = (unsafe { k.kekid.as_ref() }) else { return 0 };
        // SAFETY: the identifier's other attribute, or NULL.
        let other = unsafe { kid.other.as_ref() };
        // SAFETY: the caller's room, or NULL.
        if let Some(p) = unsafe { palg.as_mut() } {
            *p = k.key_encryption_algorithm;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { pid.as_mut() } {
            *p = kid.key_identifier;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { pdate.as_mut() } {
            *p = kid.date;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { potherid.as_mut() } {
            *p = other.map_or(ptr::null_mut(), |o| o.key_attr_id);
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { pothertype.as_mut() } {
            *p = other.map_or(ptr::null_mut(), |o| o.key_attr);
        }
        1
    }
}

ffi_export! {
    /// Sets a KEK recipient's key (which it takes): 1, or 0.
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info; `key` NULL or from CRYPTO_malloc, of `keylen`
    /// octets.
    pub unsafe extern "C" fn CMS_RecipientInfo_set0_key(ri: *mut CMS_RecipientInfo, key: *mut c_uchar, keylen: usize) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return 0 };
        let Some(k) = kekri_of(r, "CMS_RecipientInfo_set0_key") else { return 0 };
        k.key = key;
        k.keylen = keylen;
        1
    }
}

/// `cms_get_key_wrap_cipher`: the AES key wrap for a key of `keylen` octets, or NULL.
fn key_wrap_cipher(keylen: usize, ctx: *const CmsCtx) -> *mut EVP_CIPHER {
    let alg = match keylen {
        16 => c"AES-128-WRAP",
        24 => c"AES-192-WRAP",
        32 => c"AES-256-WRAP",
        _ => return ptr::null_mut(),
    };
    let (libctx, propq) = ctx_parts(ctx);
    // SAFETY: a static name; the context's parts.
    unsafe { EVP_CIPHER_fetch(libctx, alg.as_ptr(), propq) }
}

/// `cms_RecipientInfo_kekri_encrypt`: the content key, wrapped with the KEK.
///
/// # Safety
/// `cms` is a live object; `k` one of its KEK recipients.
unsafe fn kekri_encrypt(cms: *const CMS_ContentInfo, k: &mut KekRecipientInfo) -> bool {
    const F: &str = "cms_RecipientInfo_kekri_encrypt";
    let Some(ec) = env_enc_content(cms) else {
        return false;
    };
    if k.key.is_null() {
        raise(CMS_R_NO_KEY, F);
        return false;
    }
    let cipher = key_wrap_cipher(k.keylen, ctx_of(cms));
    let mut wkey: *mut c_uchar = ptr::null_mut();
    let mut ctx: *mut EVP_CIPHER_CTX = ptr::null_mut();
    let ok = 'err: {
        if cipher.is_null() {
            raise(CMS_R_INVALID_KEY_LENGTH, F);
            break 'err false;
        }
        // An 8-octet prefix for the AES key wraps.
        let Some(room) = ec.keylen.checked_add(8) else {
            break 'err false;
        };
        let Ok(inlen) = c_int::try_from(ec.keylen) else {
            break 'err false;
        };
        wkey = mem::alloc(room).cast();
        if wkey.is_null() {
            break 'err false;
        }
        // SAFETY: no preconditions.
        ctx = unsafe { EVP_CIPHER_CTX_new() };
        if ctx.is_null() {
            raise(ERR_R_EVP_LIB, F);
            break 'err false;
        }
        // SAFETY: a live context.
        unsafe { EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW) };
        let mut wkeylen: c_int = 0;
        let mut outlen: c_int = 0;
        // SAFETY: a live context and cipher; the KEK, of the cipher's length.
        let wrapped = unsafe { EVP_EncryptInit_ex(ctx, cipher, ptr::null_mut(), k.key, ptr::null()) } != 0
            // SAFETY: as above; `room` octets of output; the content key.
            && unsafe { EVP_EncryptUpdate(ctx, wkey, &mut wkeylen, ec.key, inlen) } != 0
            // SAFETY: as above; the rest of the output.
            && usize::try_from(wkeylen).ok().filter(|&w| w <= room).is_some_and(|w| {
                // SAFETY: an offset within the buffer.
                let rest = unsafe { wkey.add(w) };
                // SAFETY: as above; the rest of the output.
                (unsafe { EVP_EncryptFinal_ex(ctx, rest, &mut outlen) }) != 0
            });
        if !wrapped {
            raise(CMS_R_WRAP_ERROR, F);
            break 'err false;
        }
        let total = wkeylen.saturating_add(outlen);
        if usize::try_from(total).ok() != Some(room) {
            raise(CMS_R_WRAP_ERROR, F);
            break 'err false;
        }
        // SAFETY: the recipient's encrypted key, taking the buffer.
        unsafe { ASN1_STRING_set0(k.encrypted_key.cast(), wkey.cast(), total) };
        wkey = ptr::null_mut();
        true
    };
    // SAFETY: the cipher fetched here, or NULL.
    unsafe { EVP_CIPHER_free(cipher) };
    // SAFETY: the buffer made here, or NULL.
    unsafe { mem::release(wkey.cast()) };
    // SAFETY: the context made here, or NULL.
    unsafe { EVP_CIPHER_CTX_free(ctx) };
    ok
}

/// `cms_RecipientInfo_kekri_decrypt`: the content key, unwrapped with the KEK.
///
/// # Safety
/// `cms` is a live object; `k` one of its KEK recipients.
unsafe fn kekri_decrypt(cms: *mut CMS_ContentInfo, k: &mut KekRecipientInfo) -> bool {
    const F: &str = "cms_RecipientInfo_kekri_decrypt";
    let Some(ec) = env_enc_content(cms) else {
        return false;
    };
    if k.key.is_null() {
        raise(CMS_R_NO_KEY, F);
        return false;
    }
    // SAFETY: the recipient's algorithm, made with it, and its object.
    let obj = unsafe { k.key_encryption_algorithm.as_ref() }
        .map_or(ptr::null(), |a| a.algorithm.cast_const());
    // SAFETY: the object, or NULL.
    let wrap_nid = unsafe { OBJ_obj2nid(obj) };
    if aes_wrap_keylen(wrap_nid) != k.keylen {
        raise(CMS_R_INVALID_KEY_LENGTH, F);
        return false;
    }
    // SAFETY: the recipient's encrypted key.
    let input = unsafe { octets(k.encrypted_key) };
    let mut cipher: *mut EVP_CIPHER = ptr::null_mut();
    let mut ukey: *mut c_uchar = ptr::null_mut();
    let mut room = 0usize;
    let mut ctx: *mut EVP_CIPHER_CTX = ptr::null_mut();
    let ok = 'err: {
        // If the encrypted key's length is wrong, don't bother.
        if input.len() < 16 {
            raise(CMS_R_INVALID_ENCRYPTED_KEY_LENGTH, F);
            break 'err false;
        }
        cipher = key_wrap_cipher(k.keylen, ctx_of(cms));
        if cipher.is_null() {
            raise(CMS_R_INVALID_KEY_LENGTH, F);
            break 'err false;
        }
        let Ok(inlen) = c_int::try_from(input.len()) else {
            break 'err false;
        };
        room = input.len() - 8;
        ukey = mem::alloc(room).cast();
        if ukey.is_null() {
            break 'err false;
        }
        // SAFETY: no preconditions.
        ctx = unsafe { EVP_CIPHER_CTX_new() };
        if ctx.is_null() {
            raise(ERR_R_EVP_LIB, F);
            break 'err false;
        }
        let mut ukeylen: c_int = 0;
        let mut outlen: c_int = 0;
        // SAFETY: a live context and cipher; the KEK, of the cipher's length.
        let unwrapped = unsafe { EVP_DecryptInit_ex(ctx, cipher, ptr::null_mut(), k.key, ptr::null()) } != 0
            // SAFETY: as above; `room` octets of output; the input.
            && unsafe { EVP_DecryptUpdate(ctx, ukey, &mut ukeylen, input.as_ptr(), inlen) } != 0
            // SAFETY: as above; the rest of the output.
            && usize::try_from(ukeylen).ok().filter(|&u| u <= room).is_some_and(|u| {
                // SAFETY: an offset within the buffer.
                let rest = unsafe { ukey.add(u) };
                // SAFETY: as above; the rest of the output.
                (unsafe { EVP_DecryptFinal_ex(ctx, rest, &mut outlen) }) != 0
            });
        if !unwrapped {
            raise(CMS_R_UNWRAP_ERROR, F);
            break 'err false;
        }
        let Some(total) = usize::try_from(ukeylen.saturating_add(outlen))
            .ok()
            .filter(|&n| n <= room)
        else {
            raise(CMS_R_UNWRAP_ERROR, F);
            break 'err false;
        };
        drop_key(ec);
        ec.key = ukey;
        ec.keylen = total;
        ukey = ptr::null_mut();
        true
    };
    // SAFETY: the cipher fetched here, or NULL.
    unsafe { EVP_CIPHER_free(cipher) };
    // SAFETY: the buffer made here, or NULL.
    unsafe { mem::release_clean(ukey.cast(), room) };
    // SAFETY: the context made here, or NULL.
    unsafe { EVP_CIPHER_CTX_free(ctx) };
    ok
}

ffi_export! {
    /// Decrypts the content key with a key-transport, KEK, or password recipient (its key,
    /// KEK, or password set first): 1, or 0.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; `ri` one of its recipient infos.
    pub unsafe extern "C" fn CMS_RecipientInfo_decrypt(cms: *mut CMS_ContentInfo, ri: *mut CMS_RecipientInfo) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return 0 };
        let rip: *mut RecipientInfo = ri.cast();
        let ok = match r.type_ {
            // SAFETY: the object; its recipient info.
            CMS_RECIPINFO_TRANS => unsafe { ktri_decrypt(cms, rip) },
            CMS_RECIPINFO_KEK => match member::<KekRecipientInfo>(r, CMS_RECIPINFO_KEK) {
                // SAFETY: as above.
                Some(k) => unsafe { kekri_decrypt(cms, k) },
                None => false,
            },
            // SAFETY: as above.
            CMS_RECIPINFO_PASS => unsafe { super::pwri::pwri_crypt(cms, r, false) },
            // SAFETY: as above.
            rustyssl_abi::CMS_RECIPINFO_KEM => unsafe { super::kemri::kemri_decrypt(cms, r) },
            _ => {
                raise(CMS_R_UNSUPPORTED_RECIPIENTINFO_TYPE, "CMS_RecipientInfo_decrypt");
                false
            }
        };
        c_int::from(ok)
    }
}

ffi_export! {
    /// Encrypts the content key to the recipient: 1, or 0.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; `ri` one of its recipient infos.
    pub unsafe extern "C" fn CMS_RecipientInfo_encrypt(cms: *const CMS_ContentInfo, ri: *mut CMS_RecipientInfo) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return 0 };
        let rip: *mut RecipientInfo = ri.cast();
        let ok = match r.type_ {
            // SAFETY: the object; its recipient info.
            CMS_RECIPINFO_TRANS => unsafe { ktri_encrypt(cms, rip) },
            // SAFETY: as above.
            CMS_RECIPINFO_AGREE => unsafe { super::kari::kari_encrypt(cms, rip) },
            CMS_RECIPINFO_KEK => match member::<KekRecipientInfo>(r, CMS_RECIPINFO_KEK) {
                // SAFETY: as above.
                Some(k) => unsafe { kekri_encrypt(cms, k) },
                None => false,
            },
            // SAFETY: as above.
            CMS_RECIPINFO_PASS => unsafe { super::pwri::pwri_crypt(cms, r, true) },
            // SAFETY: as above.
            rustyssl_abi::CMS_RECIPINFO_KEM => unsafe { super::kemri::kemri_encrypt(cms, r) },
            _ => {
                raise(CMS_R_UNSUPPORTED_RECIPIENT_TYPE, "CMS_RecipientInfo_encrypt");
                false
            }
        };
        c_int::from(ok)
    }
}

/// `cms_env_set_originfo_version`.
fn set_originfo_version(env: &mut EnvelopedData) {
    // SAFETY: the content's originator info, or NULL.
    let Some(org) = (unsafe { env.originator_info.as_ref() }) else {
        return;
    };
    // SAFETY: its certificates, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(org.certificates.cast()) } {
        // SAFETY: an index within them.
        let Some(cch) = (unsafe { sk_get::<CertificateChoices>(org.certificates, i) }) else {
            continue;
        };
        if cch.type_ == CERTCHOICE_OTHER {
            env.version = 4;
            return;
        }
        if cch.type_ == CERTCHOICE_V2ACERT && env.version < 3 {
            env.version = 3;
        }
    }
    // SAFETY: its CRLs, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(org.crls.cast()) } {
        // SAFETY: an index within them.
        let Some(rch) = (unsafe { sk_get::<RevocationInfoChoice>(org.crls, i) }) else {
            continue;
        };
        if rch.type_ == REVCHOICE_OTHER {
            env.version = 4;
            return;
        }
    }
}

/// `cms_env_set_version`.
fn env_set_version(env: &mut EnvelopedData) {
    // Nothing above 4.
    if env.version >= 4 {
        return;
    }
    set_originfo_version(env);
    if env.version >= 3 {
        return;
    }
    let ris = env.recipient_infos;
    // SAFETY: the content's recipient infos, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(ris.cast()) } {
        // SAFETY: an index within them.
        let Some(ri) = (unsafe { sk_get::<RecipientInfo>(ris, i) }) else {
            continue;
        };
        if ri.type_ == CMS_RECIPINFO_PASS
            || ri.type_ == CMS_RECIPINFO_OTHER
            || ri.type_ == rustyssl_abi::CMS_RECIPINFO_KEM
        {
            env.version = 3;
            return;
        }
        let v0 = member::<KeyTransRecipientInfo>(ri, CMS_RECIPINFO_TRANS)
            .is_some_and(|k| k.version == 0);
        if !v0 {
            env.version = 2;
        }
    }
    if !env.originator_info.is_null() || !env.unprotected_attrs.is_null() {
        env.version = 2;
    }
    if env.version == 2 {
        return;
    }
    env.version = 0;
}

/// `cms_env_encrypt_content_key`: the content key, encrypted to each recipient.
///
/// # Safety
/// `cms` is a live object; `ris` its recipient infos.
unsafe fn encrypt_content_key(cms: *const CMS_ContentInfo, ris: *mut Stack) -> bool {
    // SAFETY: the recipient infos, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(ris.cast()) } {
        // SAFETY: an index within them.
        let ri = unsafe { crate::stack::OPENSSL_sk_value(ris.cast(), i) };
        // SAFETY: the object; one of its recipient infos.
        if unsafe { CMS_RecipientInfo_encrypt(cms, ri.cast()) } <= 0 {
            return false;
        }
    }
    true
}

/// `cms_env_clear_ec`.
fn clear_ec(ec: &mut EncryptedContentInfo) {
    ec.cipher = ptr::null();
    drop_key(ec);
    ec.keylen = 0;
}

/// The cipher BIO's context, or NULL.
///
/// # Safety
/// `b` is a live BIO.
unsafe fn cipher_ctx(b: *mut BIO) -> *mut EVP_CIPHER_CTX {
    let mut ctx: *mut EVP_CIPHER_CTX = ptr::null_mut();
    // SAFETY: the caller's BIO; room for its context.
    unsafe { BIO_ctrl(b, BIO_C_GET_CIPHER_CTX, 0, (&raw mut ctx).cast()) };
    ctx
}

/// Whether the context's cipher handles unprotected attributes itself.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn with_mac(ctx: *mut EVP_CIPHER_CTX) -> bool {
    // SAFETY: the caller's guarantee.
    let c = unsafe { EVP_CIPHER_CTX_get0_cipher(ctx) };
    // SAFETY: NULL or its cipher.
    !c.is_null()
        && unsafe { EVP_CIPHER_get_flags(c) } & EVP_CIPH_FLAG_CIPHER_WITH_MAC as c_ulong != 0
}

/// `ossl_cms_EnvelopedData_init_bio`: the cipher BIO, encrypting (and the content key to
/// each recipient) if a cipher is set, else decrypting.
///
/// # Safety
/// `cms` is a live EnvelopedData object.
pub(crate) unsafe fn enveloped_init_bio(cms: *mut CMS_ContentInfo) -> *mut BIO {
    // SAFETY: the content of its type.
    let Some(env) = (unsafe { content::<EnvelopedData>(cms) }) else {
        return ptr::null_mut();
    };
    // SAFETY: its encrypted content, made with it.
    let Some(ec) = (unsafe { env.encrypted_content_info.as_mut() }) else {
        return ptr::null_mut();
    };
    if ec.cipher.is_null() {
        // SAFETY: the content's; the object's context.
        let b = unsafe { encrypted_content_init_bio(ec, ctx_of(cms), false) };
        if b.is_null() {
            return b;
        }
        // SAFETY: the cipher BIO.
        let ctx = unsafe { cipher_ctx(b) };
        if ctx.is_null()
            // SAFETY: a live context.
            || (unsafe { with_mac(ctx) }
                // SAFETY: as above; the content's unprotected attributes.
                && unsafe {
                    EVP_CIPHER_CTX_ctrl(
                        ctx,
                        EVP_CTRL_PROCESS_UNPROTECTED,
                        0,
                        env.unprotected_attrs.cast(),
                    )
                } <= 0)
        {
            // SAFETY: the BIO made here.
            unsafe { BIO_free(b) };
            return ptr::null_mut();
        }
        return b;
    }
    // SAFETY: as above.
    let b = unsafe { encrypted_content_init_bio(ec, ctx_of(cms), false) };
    if b.is_null() {
        return b;
    }
    let ris = env.recipient_infos;
    // SAFETY: the object; its recipient infos.
    let ok = unsafe { encrypt_content_key(cms, ris) };
    if ok {
        env_set_version(env);
    } else {
        raise(
            CMS_R_ERROR_SETTING_RECIPIENTINFO,
            "cms_EnvelopedData_Encryption_init_bio",
        );
    }
    clear_ec(ec);
    if ok {
        return b;
    }
    // SAFETY: the BIO made here.
    unsafe { BIO_free(b) };
    ptr::null_mut()
}

/// `cms_AuthEnvelopedData_set_aad`: the authenticated attributes' DER (with the SET OF tag,
/// sorted when encrypting, as received when decrypting) as the AEAD's associated data.
///
/// # Safety
/// `b` is the cipher BIO; `attrs` live attributes.
unsafe fn set_aad(b: *mut BIO, attrs: *mut Stack) -> bool {
    const F: &str = "cms_AuthEnvelopedData_set_aad";
    // SAFETY: the caller's BIO.
    let ctx = unsafe { cipher_ctx(b) };
    if ctx.is_null() {
        return false;
    }
    // SAFETY: a live context.
    let it = if unsafe { EVP_CIPHER_CTX_is_encrypting(ctx) } != 0 {
        // SAFETY: no preconditions.
        unsafe { super::attributes_sign_it() }
    } else {
        // SAFETY: no preconditions.
        unsafe { super::attributes_verify_it() }
    };
    let mut aad: *mut c_uchar = ptr::null_mut();
    // SAFETY: the attributes, as the item's value; room for the encoding.
    let aadlen = unsafe { ASN1_item_i2d(attrs.cast(), &mut aad, it) };
    let ok = 'err: {
        if aadlen <= 0 || aad.is_null() {
            raise(ERR_R_ASN1_LIB, F);
            break 'err false;
        }
        let mut outl: c_int = 0;
        // SAFETY: a live context; the encoding.
        if unsafe { EVP_CipherUpdate(ctx, ptr::null_mut(), &mut outl, aad, aadlen) } <= 0 {
            raise(CMS_R_CTRL_FAILURE, F);
            break 'err false;
        }
        true
    };
    // SAFETY: the encoding, or NULL.
    unsafe { mem::release(aad.cast()) };
    ok
}

/// `ossl_cms_AuthEnvelopedData_init_bio`: the AEAD cipher BIO (with the received tag when
/// decrypting) and its associated data, and when encrypting the content key to each
/// recipient.
///
/// # Safety
/// `cms` is a live AuthEnvelopedData object.
pub(crate) unsafe fn auth_enveloped_init_bio(cms: *mut CMS_ContentInfo) -> *mut BIO {
    // SAFETY: the content of its type.
    let Some(aenv) = (unsafe { content::<AuthEnvelopedData>(cms) }) else {
        return ptr::null_mut();
    };
    // SAFETY: its encrypted content, made with it.
    let Some(ec) = (unsafe { aenv.auth_encrypted_content_info.as_mut() }) else {
        return ptr::null_mut();
    };
    let decrypting = ec.cipher.is_null();
    if decrypting {
        // SAFETY: its MAC, made with it.
        if let Some(mac) = unsafe { aenv.mac.as_ref() } {
            ec.tag = mac.data;
            ec.taglen = usize::try_from(mac.length).unwrap_or(0);
        }
    }
    // SAFETY: the content's; the object's context.
    let b = unsafe { encrypted_content_init_bio(ec, ctx_of(cms), true) };
    if b.is_null() {
        return b;
    }
    let ok = 'err: {
        // SAFETY: the cipher BIO; the content's attributes.
        if !aenv.auth_attrs.is_null() && !unsafe { set_aad(b, aenv.auth_attrs) } {
            break 'err false;
        }
        if decrypting {
            return b;
        }
        let ris = aenv.recipient_infos;
        // SAFETY: the object; its recipient infos.
        if !unsafe { encrypt_content_key(cms, ris) } {
            raise(
                CMS_R_ERROR_SETTING_RECIPIENTINFO,
                "ossl_cms_AuthEnvelopedData_init_bio",
            );
            break 'err false;
        }
        aenv.version = 0;
        true
    };
    clear_ec(ec);
    if ok {
        return b;
    }
    // SAFETY: the BIO made here.
    unsafe { BIO_free(b) };
    ptr::null_mut()
}

/// `ossl_cms_EnvelopedData_final`.
///
/// # Safety
/// `cms` is a live object; `chain` its data path's chain.
pub(crate) unsafe fn enveloped_final(cms: *mut CMS_ContentInfo, chain: *mut BIO) -> c_int {
    const F: &str = "ossl_cms_EnvelopedData_final";
    // SAFETY: the caller's chain.
    let mbio = unsafe { BIO_find_type(chain, BIO_TYPE_CIPHER) };
    if type_nid(cms) != NID_pkcs7_enveloped {
        raise(
            CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA,
            "ossl_cms_get0_enveloped",
        );
        return 0;
    }
    // SAFETY: the content of its type.
    let Some(env) = (unsafe { content::<EnvelopedData>(cms) }) else {
        return 0;
    };
    if mbio.is_null() {
        raise(CMS_R_CONTENT_NOT_FOUND, F);
        return 0;
    }
    // SAFETY: a cipher BIO.
    let ctx = unsafe { cipher_ctx(mbio) };
    // SAFETY: a live context.
    if !ctx.is_null() && unsafe { with_mac(ctx) } {
        if env.unprotected_attrs.is_null() {
            // SAFETY: no preconditions.
            env.unprotected_attrs = unsafe { OPENSSL_sk_new_null() }.cast();
        }
        if env.unprotected_attrs.is_null() {
            raise(ERR_R_CRYPTO_LIB, F);
            return 0;
        }
        // SAFETY: as above; the content's attributes.
        if unsafe {
            EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_PROCESS_UNPROTECTED,
                1,
                env.unprotected_attrs.cast(),
            )
        } <= 0
        {
            raise(CMS_R_CTRL_FAILURE, F);
            return 0;
        }
    }
    env_set_version(env);
    1
}

/// `ossl_cms_AuthEnvelopedData_final`: the tag into the MAC, when encrypting.
///
/// # Safety
/// `cms` is a live AuthEnvelopedData object; `cmsbio` its data path's chain.
pub(crate) unsafe fn auth_enveloped_final(cms: *mut CMS_ContentInfo, cmsbio: *mut BIO) -> c_int {
    const F: &str = "ossl_cms_AuthEnvelopedData_final";
    // SAFETY: the caller's chain.
    let ctx = unsafe { cipher_ctx(cmsbio) };
    if ctx.is_null() {
        return 0;
    }
    // The tag is set only for encryption.
    // SAFETY: a live context.
    if unsafe { EVP_CIPHER_CTX_is_encrypting(ctx) } == 0 {
        return 1;
    }
    // SAFETY: as above.
    let taglen = unsafe { EVP_CIPHER_CTX_get_tag_length(ctx) };
    let mut tag = [0u8; 16];
    let Some(t) = usize::try_from(taglen)
        .ok()
        .filter(|&n| n > 0)
        .and_then(|n| tag.get_mut(..n))
    else {
        raise(CMS_R_CIPHER_GET_TAG, F);
        return 0;
    };
    // SAFETY: as above; room for the tag.
    if unsafe { EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen, t.as_mut_ptr().cast()) }
        <= 0
    {
        raise(CMS_R_CIPHER_GET_TAG, F);
        return 0;
    }
    // SAFETY: the content of its type.
    let Some(aenv) = (unsafe { content::<AuthEnvelopedData>(cms) }) else {
        return 0;
    };
    // SAFETY: its MAC, made with it; the tag.
    c_int::from(unsafe { ASN1_OCTET_STRING_set(aenv.mac, t.as_ptr(), taglen) } != 0)
}

/// `ossl_cms_pkey_get_ri_type` (3.6): the recipient type a provided key reports (`ri-type`),
/// else the known types', else its method's, else what the key can do (encrypt: key
/// transport; derive: key agreement; encapsulate: KEM), key transport by default.
pub(crate) fn pkey_get_ri_type(pk: *mut EVP_PKEY) -> c_int {
    let mut ri_type: c_int = 0;
    // SAFETY: a live key.
    if unsafe { crate::evp::pkey::pkey(pk) }.is_some_and(crate::evp::pkey::Pkey::is_provided)
        // SAFETY: as above; a static name; room for the type.
        && unsafe { crate::evp::pkey::params::EVP_PKEY_get_int_param(pk, c"ri-type".as_ptr(), &raw mut ri_type) } != 0
    {
        return ri_type;
    }
    let is = |name: &core::ffi::CStr| {
        // SAFETY: a live key; a static name.
        (unsafe { EVP_PKEY_is_a(pk, name.as_ptr()) }) != 0
    };
    if is(c"DH") || is(c"DHX") || is(c"EC") {
        return CMS_RECIPINFO_AGREE;
    }
    if is(c"DSA") {
        return CMS_RECIPINFO_NONE;
    }
    if is(c"RSA") {
        return CMS_RECIPINFO_TRANS;
    }
    let mut r: c_int = 0;
    // SAFETY: the key; room for the type.
    if let Some(i) = unsafe { asn1_ctrl_of(pk, ASN1_PKEY_CTRL_CMS_RI_TYPE, 0, (&raw mut r).cast()) }
        && i > 0
    {
        return r;
    }
    // 3.6 tries what the key can do.
    let mut ri_type = CMS_RECIPINFO_TRANS;
    // SAFETY: the key; no engine.
    let ctx = unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_new(pk, ptr::null_mut()) };
    if !ctx.is_null() {
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_set_mark() };
        // SAFETY: the context, for each.
        if unsafe { crate::evp::asymcipher::EVP_PKEY_encrypt_init(ctx) } > 0 {
            ri_type = CMS_RECIPINFO_TRANS;
        // SAFETY: as above.
        } else if unsafe { crate::evp::exchange::EVP_PKEY_derive_init(ctx) } > 0 {
            ri_type = CMS_RECIPINFO_AGREE;
        // SAFETY: as above.
        } else if unsafe { crate::evp::kem::EVP_PKEY_encapsulate_init(ctx, ptr::null()) } > 0 {
            ri_type = rustyssl_abi::CMS_RECIPINFO_KEM;
        }
        // SAFETY: the mark set above.
        unsafe { crate::err::ERR_pop_to_mark() };
    }
    // SAFETY: made here, or NULL.
    unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_free(ctx) };
    ri_type
}

/// `ossl_cms_pkey_is_ri_type_supported`.
pub(crate) fn pkey_is_ri_type_supported(pk: *mut EVP_PKEY, ri_type: c_int) -> bool {
    let mut r: c_int = 0;
    // SAFETY: the key; room for the answer.
    if let Some(i) = unsafe {
        asn1_ctrl_of(
            pk,
            ASN1_PKEY_CTRL_CMS_IS_RI_TYPE_SUPPORTED,
            c_long::from(ri_type),
            (&raw mut r).cast(),
        )
    } && i > 0
    {
        return r != 0;
    }
    let supported = pkey_get_ri_type(pk);
    supported >= 0 && supported == ri_type
}
