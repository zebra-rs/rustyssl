//! KEM recipients (RFC 9629; OpenSSL 3.6's `cms_kemri.c` and `cms_kem.c`): an other
//! recipient info of type `id-ori-kem` whose content key is wrapped with a key derived (by the
//! recipient info's KDF, HKDF-SHA256 unless the key says otherwise) from a KEM's shared
//! secret, the KEM's ciphertext sent along.

use core::ffi::{c_char, c_int, c_long, c_uchar};
use core::ptr;

use rustyssl_abi::{
    ASN1_OBJECT, CMS_ContentInfo, CMS_R_INVALID_KEY_LENGTH, CMS_R_NO_PRIVATE_KEY, CMS_R_NOT_KEM,
    CMS_R_UNSUPPORTED_KDF_ALGORITHM, CMS_RECIPINFO_KEM, CMS_RECIPINFO_OTHER, CMS_RecipientInfo,
    CMS_USE_KEYID, ERR_LIB_CMS, ERR_R_PASSED_INVALID_ARGUMENT, EVP_CIPH_WRAP_MODE, EVP_CIPHER_CTX,
    EVP_MAX_KEY_LENGTH, EVP_PKEY, NID_HKDF_SHA256, NID_id_smime_ori_kem, NID_undef, OSSL_PARAM,
    V_ASN1_NULL, V_ASN1_UNDEF, X509, X509_ALGOR,
};

use super::base::{ctx_parts, raise};
use super::env::{env_enc_content, ri_of};
use super::sd::{set1_signer_identifier, signer_identifier_cert_cmp};
use super::{CmsCtx, KemRecipientInfo, OriForKemOtherInfo, OtherRecipientInfo, RecipientInfo};
use crate::asn1::string::{
    ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set, ASN1_STRING_set0,
};
use crate::asn1::tpl::new::ASN1_item_new;
use crate::ffi::ffi_export;
use crate::mem;

/// `CMS_SIGNERINFO_*` for a recipient identifier.
const ISSUER_SERIAL: c_int = rustyssl_abi::CMS_SIGNERINFO_ISSUER_SERIAL;
const KEYIDENTIFIER: c_int = rustyssl_abi::CMS_SIGNERINFO_KEYIDENTIFIER;

/// The KEM recipient info of `ri`, or `None` (`CMS_R_NOT_KEM` from `f` when `report`).
pub(crate) fn kemri_of<'a>(
    ri: &RecipientInfo,
    f: &str,
    report: bool,
) -> Option<&'a mut KemRecipientInfo> {
    let k = if ri.type_ == CMS_RECIPINFO_KEM {
        // SAFETY: a KEM recipient's choice is an other recipient info holding one.
        unsafe { ri.d.cast::<OtherRecipientInfo>().as_ref() }
            // SAFETY: as above.
            .and_then(|o| unsafe { o.d.cast::<KemRecipientInfo>().as_mut() })
    } else {
        None
    };
    if k.is_none() && report {
        raise(CMS_R_NOT_KEM, f);
    }
    k
}

ffi_export! {
    /// Compares the KEM recipient's identifier with `cert`: 0 if it is the certificate's, -2
    /// for another recipient type (`CMS_R_NOT_KEM`).
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info; `cert` a live certificate.
    pub unsafe extern "C" fn CMS_RecipientInfo_kemri_cert_cmp(ri: *mut CMS_RecipientInfo, cert: *mut X509) -> c_int
    where failure = -2, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return -2 };
        let Some(k) = kemri_of(r, "CMS_RecipientInfo_kemri_cert_cmp", true) else { return -2 };
        // SAFETY: its identifier, made with it.
        let Some(rid) = (unsafe { k.rid.as_ref() }) else { return -2 };
        // SAFETY: the caller's certificate.
        unsafe { signer_identifier_cert_cmp(rid, cert) }
    }
}

ffi_export! {
    /// Sets the private key the KEM recipient decapsulates with (NULL forgets it): 1, or 0.
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info; `pk` is NULL or a live key.
    pub unsafe extern "C" fn CMS_RecipientInfo_kemri_set0_pkey(ri: *mut CMS_RecipientInfo, pk: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return 0 };
        let Some(k) = kemri_of(r, "CMS_RecipientInfo_kemri_set0_pkey", true) else { return 0 };
        // SAFETY: its own context, or NULL.
        unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_free(k.pctx) };
        k.pctx = ptr::null_mut();
        if pk.is_null() {
            return 1;
        }
        let (libctx, propq) = ctx_parts(k.cms_ctx);
        // SAFETY: the context's parts; the caller's key.
        let pctx = unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_new_from_pkey(libctx, pk, propq) };
        // SAFETY: the new context, or NULL.
        if pctx.is_null() || unsafe { crate::evp::kem::EVP_PKEY_decapsulate_init(pctx, ptr::null()) } <= 0 {
            // SAFETY: as above.
            unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_free(pctx) };
            return 0;
        }
        k.pctx = pctx;
        1
    }
}

ffi_export! {
    /// The KEM recipient's key-wrap cipher context, or NULL for another recipient type.
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info.
    pub unsafe extern "C" fn CMS_RecipientInfo_kemri_get0_ctx(ri: *mut CMS_RecipientInfo) -> *mut EVP_CIPHER_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return ptr::null_mut() };
        kemri_of(r, "", false).map_or(ptr::null_mut(), |k| k.ctx)
    }
}

ffi_export! {
    /// The KEM recipient's KDF algorithm, or NULL for another recipient type.
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info.
    pub unsafe extern "C" fn CMS_RecipientInfo_kemri_get0_kdf_alg(ri: *mut CMS_RecipientInfo) -> *mut X509_ALGOR
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return ptr::null_mut() };
        kemri_of(r, "", false).map_or(ptr::null_mut(), |k| k.kdf)
    }
}

ffi_export! {
    /// Sets the KEM recipient's user keying material (`ukm_length` octets; NULL only with 0):
    /// 1, or 0.
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info; `ukm` is NULL or holds `ukm_length` octets.
    pub unsafe extern "C" fn CMS_RecipientInfo_kemri_set_ukm(ri: *mut CMS_RecipientInfo, ukm: *const c_uchar, ukm_length: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        const F: &str = "CMS_RecipientInfo_kemri_set_ukm";
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return 0 };
        let Some(k) = kemri_of(r, F, true) else { return 0 };
        if ukm.is_null() && ukm_length != 0 {
            raise(ERR_R_PASSED_INVALID_ARGUMENT, F);
            return 0;
        }
        // SAFETY: no preconditions.
        let s = unsafe { ASN1_OCTET_STRING_new() };
        if s.is_null() {
            return 0;
        }
        // SAFETY: the new string; the caller's octets.
        if unsafe { ASN1_OCTET_STRING_set(s, ukm, ukm_length) } == 0 {
            // SAFETY: made here.
            unsafe { ASN1_OCTET_STRING_free(s) };
            return 0;
        }
        // SAFETY: its own string, or NULL.
        unsafe { ASN1_OCTET_STRING_free(k.ukm) };
        k.ukm = s;
        1
    }
}

/// `ossl_cms_RecipientInfo_kemri_init`: a KEM recipient for `recip`, its key `pk` ready to
/// encapsulate.
///
/// # Safety
/// `ri` is a new recipient info; `recip` and `pk` live.
pub(crate) unsafe fn kemri_init(
    ri: &mut RecipientInfo,
    recip: *mut X509,
    pk: *mut EVP_PKEY,
    flags: c_int,
    ctx: *const CmsCtx,
) -> bool {
    // SAFETY: no preconditions.
    let oit = unsafe { super::other_recipient_info_it() };
    // SAFETY: the item.
    let ori = unsafe { ASN1_item_new(oit) }.cast::<OtherRecipientInfo>();
    if ori.is_null() {
        return false;
    }
    ri.d = ori.cast();
    ri.encoded_type = CMS_RECIPINFO_OTHER;
    ri.type_ = CMS_RECIPINFO_KEM;
    // SAFETY: the new other recipient info.
    let o = unsafe { &mut *ori };
    // SAFETY: a number.
    o.ori_type = unsafe { crate::objects::OBJ_nid2obj(NID_id_smime_ori_kem) };
    if o.ori_type.is_null() {
        return false;
    }
    // SAFETY: no preconditions.
    let kit = unsafe { super::kem_recipient_info_it() };
    // SAFETY: the item.
    let kp = unsafe { ASN1_item_new(kit) }.cast::<KemRecipientInfo>();
    if kp.is_null() {
        return false;
    }
    o.d = kp.cast();
    // SAFETY: the new KEM recipient info.
    let k = unsafe { &mut *kp };
    k.version = 0;
    k.cms_ctx = ctx;
    let idtype = if flags & CMS_USE_KEYID != 0 {
        KEYIDENTIFIER
    } else {
        ISSUER_SERIAL
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
    let xpk = unsafe { crate::x509::cert::X509_get_X509_PUBKEY(recip) };
    if xpk.is_null() {
        return false;
    }
    let mut alg: *mut X509_ALGOR = ptr::null_mut();
    // SAFETY: the certificate's key; a place for its algorithm.
    if unsafe {
        crate::x509::pubkey::X509_PUBKEY_get0_param(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut alg,
            xpk,
        )
    } == 0
    {
        return false;
    }
    // SAFETY: its algorithm; ours.
    if unsafe { crate::x509::algor::X509_ALGOR_copy(k.kem, alg) } == 0 {
        return false;
    }
    let (libctx, propq) = ctx_parts(ctx);
    // SAFETY: the context's parts; the caller's key.
    k.pctx = unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_new_from_pkey(libctx, pk, propq) };
    // SAFETY: the new context, or NULL.
    !k.pctx.is_null()
        && unsafe { crate::evp::kem::EVP_PKEY_encapsulate_init(k.pctx, ptr::null()) } > 0
}

/// `kem_cms_encrypt` (`ossl_cms_kem_envelope` with 0): the KDF (the key's default, else
/// HKDF-SHA256, unless set), the KEK's length, and the wrap's algorithm identifier.
///
/// # Safety
/// `ri` is a live KEM recipient info.
unsafe fn kem_cms_encrypt(k: &mut KemRecipientInfo) -> bool {
    use crate::evp::cipher_asn1::EVP_CIPHER_param_to_asn1;
    use crate::evp::cipher_ctx::{EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_get_nid};
    if k.kdf.is_null() || k.pctx.is_null() {
        return false;
    }
    // SAFETY: its context.
    let pkey = unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_get0_pkey(k.pctx) };
    // SAFETY: its key, or NULL.
    if pkey.is_null() || unsafe { crate::evp::pkey::EVP_PKEY_get_security_bits(pkey) } == 0 {
        return false;
    }
    let mut kdf_obj: *const ASN1_OBJECT = ptr::null();
    // SAFETY: its KDF; a place for the object.
    unsafe {
        crate::x509::algor::X509_ALGOR_get0(
            &raw mut kdf_obj,
            ptr::null_mut(),
            ptr::null_mut(),
            k.kdf,
        )
    };
    // SAFETY: the object, or NULL.
    if kdf_obj.is_null() || unsafe { crate::objects::OBJ_obj2nid(kdf_obj) } == NID_undef {
        // The key's default KDF (`kemri-kdf-alg`), else HKDF-SHA256.
        let mut buf = [0u8; 256];
        let mut params = [
            // SAFETY: a static key; our buffer.
            unsafe {
                crate::params::OSSL_PARAM_construct_octet_string(
                    c"kemri-kdf-alg".as_ptr(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                )
            },
            crate::params::end(),
        ];
        // SAFETY: the key; the array above.
        if unsafe { crate::evp::pkey::params::EVP_PKEY_get_params(pkey, params.as_mut_ptr()) } == 0
        {
            return false;
        }
        // SAFETY: the parameter above.
        if unsafe { crate::params::OSSL_PARAM_modified(params.as_ptr()) } != 0 {
            let Ok(len) = c_long::try_from(params[0].return_size) else {
                return false;
            };
            let mut p = buf.as_ptr();
            // SAFETY: our octets.
            let a = unsafe {
                crate::asn1::tpl::items::d2i_X509_ALGOR(ptr::null_mut(), &raw mut p, len)
            };
            if a.is_null() {
                return false;
            }
            // SAFETY: the decoded algorithm; ours.
            let ok = unsafe { crate::x509::algor::X509_ALGOR_copy(k.kdf, a) } != 0;
            // SAFETY: decoded here.
            unsafe { crate::asn1::tpl::items::X509_ALGOR_free(a) };
            if !ok {
                return false;
            }
        } else {
            // SAFETY: a number.
            let hkdf = unsafe { crate::objects::OBJ_nid2obj(NID_HKDF_SHA256) };
            // SAFETY: ours; a static object.
            if unsafe {
                crate::x509::algor::X509_ALGOR_set0(k.kdf, hkdf, V_ASN1_UNDEF, ptr::null_mut())
            } == 0
            {
                return false;
            }
        }
    }
    // SAFETY: its wrap context.
    let keylen = unsafe { EVP_CIPHER_CTX_get_key_length(k.ctx) };
    k.kek_length = u32::try_from(keylen).unwrap_or(0);
    // SAFETY: as above.
    let wrap_nid = unsafe { EVP_CIPHER_CTX_get_nid(k.ctx) };
    // SAFETY: its wrap algorithm.
    let Some(wrap) = (unsafe { k.wrap.as_mut() }) else {
        return false;
    };
    // SAFETY: its own fields, replaced.
    unsafe { crate::objects::ASN1_OBJECT_free(wrap.algorithm) };
    // SAFETY: as above.
    unsafe { crate::asn1::tpl::items::ASN1_TYPE_free(wrap.parameter) };
    // SAFETY: a number.
    wrap.algorithm = unsafe { crate::objects::OBJ_nid2obj(wrap_nid) };
    // SAFETY: no preconditions.
    wrap.parameter = unsafe { crate::asn1::tpl::items::ASN1_TYPE_new() };
    if wrap.parameter.is_null() {
        return false;
    }
    // SAFETY: its wrap context; the new type.
    if unsafe { EVP_CIPHER_param_to_asn1(k.ctx, wrap.parameter) } <= 0 {
        // SAFETY: made above.
        unsafe { crate::asn1::tpl::items::ASN1_TYPE_free(wrap.parameter) };
        wrap.parameter = ptr::null_mut();
        return false;
    }
    // SAFETY: as above.
    if unsafe { crate::asn1::any::ASN1_TYPE_get(wrap.parameter) } == NID_undef {
        // SAFETY: as above.
        unsafe { crate::asn1::tpl::items::ASN1_TYPE_free(wrap.parameter) };
        wrap.parameter = ptr::null_mut();
    }
    true
}

/// `kem_cms_decrypt` (`ossl_cms_kem_envelope` with 1): the wrap from its algorithm
/// identifier, which must be a key wrap of the KEK's length.
///
/// # Safety
/// `k` is a live KEM recipient info with a key context.
unsafe fn kem_cms_decrypt(k: &mut KemRecipientInfo) -> bool {
    use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_mode};
    use crate::evp::cipher_ctx::{EVP_CIPHER_CTX_get_key_length, EVP_EncryptInit_ex};
    if k.pctx.is_null() || k.ctx.is_null() {
        return false;
    }
    // SAFETY: its wrap algorithm.
    let Some(wrap) = (unsafe { k.wrap.as_ref() }) else {
        return false;
    };
    let mut name = [0 as c_char; 80];
    // SAFETY: room for the name; its algorithm.
    unsafe { crate::objects::OBJ_obj2txt(name.as_mut_ptr(), 80, wrap.algorithm, 0) };
    // The key context's library context and query.
    // SAFETY: its context.
    let Some(pc) = (unsafe { crate::evp::pkey_ctx::context(k.pctx) }) else {
        return false;
    };
    let (libctx, propq) = {
        let s = pc.lock();
        (s.libctx.0, s.propquery.clone())
    };
    let propq_ptr = propq
        .as_deref()
        .map_or(ptr::null(), core::ffi::CStr::as_ptr);
    // SAFETY: the context's parts; the name.
    let cipher = unsafe { EVP_CIPHER_fetch(libctx, name.as_ptr(), propq_ptr) };
    let ok = 'done: {
        // SAFETY: the cipher, or NULL.
        if cipher.is_null() || unsafe { EVP_CIPHER_get_mode(cipher) } != EVP_CIPH_WRAP_MODE {
            break 'done false;
        }
        // SAFETY: its wrap context; the cipher.
        if unsafe { EVP_EncryptInit_ex(k.ctx, cipher, ptr::null_mut(), ptr::null(), ptr::null()) }
            == 0
        {
            break 'done false;
        }
        // SAFETY: as above; its parameters.
        if unsafe { crate::evp::cipher_asn1::EVP_CIPHER_asn1_to_param(k.ctx, wrap.parameter) } <= 0
        {
            break 'done false;
        }
        // SAFETY: as above.
        let len = unsafe { EVP_CIPHER_CTX_get_key_length(k.ctx) };
        if u32::try_from(len).ok() != Some(k.kek_length) {
            raise(CMS_R_INVALID_KEY_LENGTH, "kem_cms_decrypt");
            break 'done false;
        }
        true
    };
    // SAFETY: fetched here, or NULL.
    unsafe { EVP_CIPHER_free(cipher) };
    ok
}

/// `ossl_cms_kem_envelope`.
///
/// # Safety
/// `k` is a live KEM recipient info.
pub(crate) unsafe fn kem_envelope(k: &mut KemRecipientInfo, decrypt: bool) -> bool {
    if decrypt {
        // SAFETY: the caller's guarantee.
        unsafe { kem_cms_decrypt(k) }
    } else {
        // SAFETY: as above.
        unsafe { kem_cms_encrypt(k) }
    }
}

/// `kdf_derive`: the KEK from the shared secret with the recipient's KDF (no parameters
/// allowed) and `CMSORIforKEMOtherInfo` as its info.
///
/// # Safety
/// `k` is a live KEM recipient info.
unsafe fn kdf_derive(kek: &mut [u8], ss: &[u8], k: &KemRecipientInfo) -> bool {
    use crate::evp::kdf::{
        EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_derive, EVP_KDF_fetch, EVP_KDF_free,
    };
    let mut other = OriForKemOtherInfo {
        wrap: k.wrap,
        kek_length: k.kek_length,
        ukm: k.ukm,
    };
    let mut der: *mut c_uchar = ptr::null_mut();
    // SAFETY: no preconditions.
    let oit = unsafe { super::ori_for_kem_other_info_it() };
    // SAFETY: the structure above; its item; a new encoding.
    let len = unsafe {
        crate::asn1::tpl::encode::ASN1_item_i2d((&raw mut other).cast(), &raw mut der, oit)
    };
    let ok = 'done: {
        let Ok(infolen) = usize::try_from(len) else {
            break 'done false;
        };
        if infolen == 0 {
            break 'done false;
        }
        let mut kdf_obj: *const ASN1_OBJECT = ptr::null();
        let mut ptype: c_int = 0;
        // SAFETY: its KDF; places for its parts.
        unsafe {
            crate::x509::algor::X509_ALGOR_get0(
                &raw mut kdf_obj,
                &raw mut ptype,
                ptr::null_mut(),
                k.kdf,
            )
        };
        if ptype != V_ASN1_UNDEF && ptype != V_ASN1_NULL {
            raise(CMS_R_UNSUPPORTED_KDF_ALGORITHM, "create_kdf_ctx");
            break 'done false;
        }
        let mut name = [0 as c_char; 80];
        // SAFETY: room for the name; the object.
        if unsafe { crate::objects::OBJ_obj2txt(name.as_mut_ptr(), 80, kdf_obj, 1) } < 0 {
            break 'done false;
        }
        let (libctx, propq) = ctx_parts(k.cms_ctx);
        // SAFETY: the context's parts; the name.
        let kdf = unsafe { EVP_KDF_fetch(libctx, name.as_ptr(), propq) };
        if kdf.is_null() {
            break 'done false;
        }
        // SAFETY: the KDF.
        let kctx = unsafe { EVP_KDF_CTX_new(kdf) };
        // SAFETY: fetched here; the context holds its own reference.
        unsafe { EVP_KDF_free(kdf) };
        if kctx.is_null() {
            break 'done false;
        }
        let params: [OSSL_PARAM; 3] = [
            // SAFETY: a static key; the caller's secret, which outlives the call.
            unsafe {
                crate::params::OSSL_PARAM_construct_octet_string(
                    c"key".as_ptr(),
                    ss.as_ptr().cast_mut().cast(),
                    ss.len(),
                )
            },
            // SAFETY: as above; the encoding.
            unsafe {
                crate::params::OSSL_PARAM_construct_octet_string(
                    c"info".as_ptr(),
                    der.cast(),
                    infolen,
                )
            },
            crate::params::end(),
        ];
        // SAFETY: the context; the caller's room; the array above.
        let r = unsafe { EVP_KDF_derive(kctx, kek.as_mut_ptr(), kek.len(), params.as_ptr()) };
        // SAFETY: made here.
        unsafe { EVP_KDF_CTX_free(kctx) };
        r > 0
    };
    // SAFETY: the encoding, or NULL.
    unsafe { mem::release(der.cast()) };
    ok
}

/// `cms_kek_cipher`: `input` wrapped (`enc`) or unwrapped with the KEK derived from the
/// shared secret; the key contexts reset afterwards, as OpenSSL does.
///
/// # Safety
/// `k` is a live KEM recipient info.
unsafe fn kek_cipher(
    k: &mut KemRecipientInfo,
    ss: &[u8],
    input: &[u8],
    enc: bool,
) -> Option<Vec<u8>> {
    use crate::evp::cipher_ctx::{EVP_CIPHER_CTX_reset, EVP_CipherInit_ex, EVP_CipherUpdate};
    let keklen = usize::try_from(k.kek_length).unwrap_or(usize::MAX);
    if keklen > EVP_MAX_KEY_LENGTH as usize {
        raise(CMS_R_INVALID_KEY_LENGTH, "cms_kek_cipher");
        return None;
    }
    let inlen = c_int::try_from(input.len()).ok()?;
    let mut kek = [0u8; EVP_MAX_KEY_LENGTH as usize];
    let out = 'done: {
        let Some(kek) = kek.get_mut(..keklen) else {
            break 'done None;
        };
        // SAFETY: the caller's guarantee.
        if !unsafe { kdf_derive(kek, ss, k) } {
            break 'done None;
        }
        // SAFETY: its wrap context; the KEK.
        if unsafe {
            EVP_CipherInit_ex(
                k.ctx,
                ptr::null(),
                ptr::null_mut(),
                kek.as_ptr(),
                ptr::null(),
                c_int::from(enc),
            )
        } == 0
        {
            break 'done None;
        }
        let mut outlen: c_int = 0;
        // SAFETY: as above; a size query.
        if unsafe {
            EVP_CipherUpdate(
                k.ctx,
                ptr::null_mut(),
                &raw mut outlen,
                input.as_ptr(),
                inlen,
            )
        } == 0
        {
            break 'done None;
        }
        let room = usize::try_from(outlen).unwrap_or(0).max(input.len());
        let mut out = vec![0u8; room];
        // SAFETY: as above; our room.
        if unsafe {
            EVP_CipherUpdate(
                k.ctx,
                out.as_mut_ptr(),
                &raw mut outlen,
                input.as_ptr(),
                inlen,
            )
        } == 0
        {
            crate::provider::macs::wipe(&mut out);
            break 'done None;
        }
        out.truncate(usize::try_from(outlen).unwrap_or(0));
        Some(out)
    };
    crate::provider::macs::wipe(&mut kek);
    // SAFETY: its own contexts.
    unsafe { EVP_CIPHER_CTX_reset(k.ctx) };
    // SAFETY: as above.
    unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_free(k.pctx) };
    k.pctx = ptr::null_mut();
    out
}

/// `ossl_cms_RecipientInfo_kemri_encrypt`: the KEM's ciphertext and the content key wrapped
/// with the KEK.
///
/// # Safety
/// `cms` is a live object; `ri` one of its recipient infos.
pub(crate) unsafe fn kemri_encrypt(cms: *const CMS_ContentInfo, ri: &mut RecipientInfo) -> bool {
    use crate::evp::kem::EVP_PKEY_encapsulate;
    const F: &str = "ossl_cms_RecipientInfo_kemri_encrypt";
    let Some(k) = kemri_of(ri, F, true) else {
        return false;
    };
    let Some(ec) = env_enc_content(cms) else {
        return false;
    };
    // SAFETY: its wrap context; the content cipher.
    if !unsafe { super::kari::wrap_init(k.ctx, k.cms_ctx, ec.cipher) } {
        return false;
    }
    // SAFETY: the recipient.
    if !unsafe { kem_envelope(k, false) } {
        return false;
    }
    let (mut ctlen, mut sslen) = (0usize, 0usize);
    // SAFETY: its context; size queries.
    if unsafe {
        EVP_PKEY_encapsulate(
            k.pctx,
            ptr::null_mut(),
            &raw mut ctlen,
            ptr::null_mut(),
            &raw mut sslen,
        )
    } <= 0
    {
        return false;
    }
    let ct: *mut c_uchar = mem::alloc(ctlen.max(1)).cast();
    let mut ss = vec![0u8; sslen];
    if ct.is_null() {
        return false;
    }
    // SAFETY: as above; rooms of those sizes.
    if unsafe { EVP_PKEY_encapsulate(k.pctx, ct, &raw mut ctlen, ss.as_mut_ptr(), &raw mut sslen) }
        <= 0
    {
        // SAFETY: allocated here.
        unsafe { mem::release(ct.cast()) };
        crate::provider::macs::wipe(&mut ss);
        return false;
    }
    // SAFETY: its ciphertext string; the ciphertext, now its.
    unsafe { ASN1_STRING_set0(k.kemct, ct.cast(), c_int::try_from(ctlen).unwrap_or(0)) };
    ss.truncate(sslen);
    // SAFETY: the content key, `keylen` octets.
    let key = unsafe { crate::ffi::bytes(ec.key, ec.keylen) }
        .unwrap_or_default()
        .to_vec();
    // SAFETY: the recipient.
    let wrapped = unsafe { kek_cipher(k, &ss, &key, true) };
    crate::provider::macs::wipe(&mut ss);
    let mut key = key;
    crate::provider::macs::wipe(&mut key);
    let Some(wrapped) = wrapped else { return false };
    let ek: *mut c_uchar = mem::alloc(wrapped.len().max(1)).cast();
    if ek.is_null() {
        return false;
    }
    // SAFETY: a fresh block of at least `wrapped.len()` octets.
    unsafe { ptr::copy_nonoverlapping(wrapped.as_ptr(), ek, wrapped.len()) };
    // SAFETY: its encrypted key string; the octets, now its.
    unsafe {
        ASN1_STRING_set0(
            k.encrypted_key,
            ek.cast(),
            c_int::try_from(wrapped.len()).unwrap_or(0),
        )
    };
    true
}

/// `ossl_cms_RecipientInfo_kemri_decrypt`: the shared secret decapsulated with the private
/// key set, and the content key unwrapped with the KEK.
///
/// # Safety
/// `cms` is a live object; `ri` one of its recipient infos.
pub(crate) unsafe fn kemri_decrypt(cms: *mut CMS_ContentInfo, ri: &mut RecipientInfo) -> bool {
    use crate::evp::kem::EVP_PKEY_decapsulate;
    const F: &str = "ossl_cms_RecipientInfo_kemri_decrypt";
    let Some(k) = kemri_of(ri, F, true) else {
        return false;
    };
    if env_enc_content(cms).is_none() {
        return false;
    }
    if k.pctx.is_null() {
        raise(CMS_R_NO_PRIVATE_KEY, F);
        return false;
    }
    // SAFETY: the recipient.
    if !unsafe { kem_envelope(k, true) } {
        return false;
    }
    // SAFETY: its ciphertext.
    let ct = unsafe { super::base::octets(k.kemct) }.to_vec();
    let mut sslen = 0usize;
    // SAFETY: its context; a size query.
    if unsafe {
        EVP_PKEY_decapsulate(
            k.pctx,
            ptr::null_mut(),
            &raw mut sslen,
            ct.as_ptr(),
            ct.len(),
        )
    } <= 0
    {
        return false;
    }
    let mut ss = vec![0u8; sslen];
    // SAFETY: as above; room for the secret.
    if unsafe {
        EVP_PKEY_decapsulate(
            k.pctx,
            ss.as_mut_ptr(),
            &raw mut sslen,
            ct.as_ptr(),
            ct.len(),
        )
    } <= 0
    {
        crate::provider::macs::wipe(&mut ss);
        return false;
    }
    ss.truncate(sslen);
    // SAFETY: its encrypted key.
    let ek = unsafe { super::base::octets(k.encrypted_key) }.to_vec();
    // SAFETY: the recipient.
    let cek = unsafe { kek_cipher(k, &ss, &ek, false) };
    crate::provider::macs::wipe(&mut ss);
    let Some(mut cek) = cek else { return false };
    let Some(ec) = env_enc_content(cms) else {
        crate::provider::macs::wipe(&mut cek);
        return false;
    };
    let key: *mut c_uchar = mem::alloc(cek.len().max(1)).cast();
    if key.is_null() {
        crate::provider::macs::wipe(&mut cek);
        return false;
    }
    // SAFETY: a fresh block of at least `cek.len()` octets.
    unsafe { ptr::copy_nonoverlapping(cek.as_ptr(), key, cek.len()) };
    // SAFETY: its content key (C memory), or NULL.
    unsafe { mem::release_clean(ec.key.cast(), ec.keylen) };
    ec.key = key;
    ec.keylen = cek.len();
    crate::provider::macs::wipe(&mut cek);
    true
}
