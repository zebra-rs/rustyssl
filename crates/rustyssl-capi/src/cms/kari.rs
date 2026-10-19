//! Key agreement recipients (`cms_kari.c`): their originator and recipient identifiers, the
//! key-encryption key derived from the agreed secret, and wrapping the content key with it.

use core::ffi::{c_int, c_uchar};
use core::ptr;

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_GENERALIZEDTIME, ASN1_INTEGER, ASN1_OCTET_STRING, CMS_ContentInfo,
    CMS_OtherKeyAttribute, CMS_R_ERROR_UNSUPPORTED_STATIC_KEY_AGREEMENT, CMS_R_NOT_KEY_AGREEMENT,
    CMS_RECIPINFO_AGREE, CMS_RecipientEncryptedKey, CMS_RecipientInfo, CMS_USE_KEYID,
    CMS_USE_ORIGINATOR_KEYID, ERR_LIB_CMS, EVP_CIPH_FLAG_GET_WRAP_CIPHER, EVP_CIPH_WRAP_MODE,
    EVP_CIPHER, EVP_CIPHER_CTX, EVP_CTRL_GET_WRAP_CIPHER, EVP_MAX_KEY_LENGTH, EVP_PKEY,
    EVP_PKEY_CTX, NID_des_ede3_cbc, SN_id_aes128_wrap, SN_id_aes192_wrap, SN_id_aes256_wrap,
    SN_id_smime_alg_CMS3DESwrap, X509, X509_ALGOR, X509_NAME, stack_st_CMS_RecipientEncryptedKey,
};

use super::base::{ctx_parts, ias_cert_cmp, keyid_cert_cmp, octets, raise, set1_ias, set1_keyid};
use super::env::{env_enc_content, kari_asn1_ctrl, member, ri_of};
use super::{
    CmsCtx, IssuerAndSerialNumber, KeyAgreeRecipientInfo, OriginatorPublicKey,
    RecipientEncryptedKey, RecipientInfo, RecipientKeyIdentifier, sk_get,
};
use crate::asn1::string::{ASN1_OCTET_STRING_new, ASN1_STRING_set0};
use crate::asn1::tpl::free::ASN1_item_free;
use crate::asn1::tpl::new::ASN1_item_new;
use crate::evp::cipher::{
    EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_flags, EVP_CIPHER_get_key_length,
    EVP_CIPHER_get_mode, EVP_CIPHER_get_type, EVP_CIPHER_get0_name,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_get0_cipher, EVP_CIPHER_CTX_reset,
    EVP_CipherInit_ex, EVP_CipherUpdate, EVP_EncryptInit_ex,
};
use crate::evp::cipher_meth::EVP_CIPHER_meth_get_ctrl;
use crate::evp::exchange::{EVP_PKEY_derive, EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer};
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_up_ref};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey, EVP_PKEY_keygen, EVP_PKEY_keygen_init,
};
use crate::ffi::ffi_export;
use crate::mem;
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_push};
use crate::x509::cert::X509_get0_pubkey;

// `cms_local.h`'s choices of identifiers.
const REK_ISSUER_SERIAL: c_int = 0;
const REK_KEYIDENTIFIER: c_int = 1;
const OIK_ISSUER_SERIAL: c_int = 0;
const OIK_KEYIDENTIFIER: c_int = 1;
const OIK_PUBKEY: c_int = 2;

/// The key-agreement choice, or `None` (`CMS_R_NOT_KEY_AGREEMENT`).
fn kari_of<'a>(ri: &RecipientInfo, f: &str) -> Option<&'a mut KeyAgreeRecipientInfo> {
    let k = member(ri, CMS_RECIPINFO_AGREE);
    if k.is_none() {
        raise(CMS_R_NOT_KEY_AGREEMENT, f);
    }
    k
}

ffi_export! {
    /// A key-agreement recipient's key-encryption algorithm and user keying material: 1, or 0.
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info; the others NULL or room for a pointer.
    pub unsafe extern "C" fn CMS_RecipientInfo_kari_get0_alg(ri: *mut CMS_RecipientInfo, palg: *mut *mut X509_ALGOR, pukm: *mut *mut ASN1_OCTET_STRING) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return 0 };
        let Some(k) = kari_of(r, "CMS_RecipientInfo_kari_get0_alg") else { return 0 };
        // SAFETY: the caller's room, or NULL.
        if let Some(p) = unsafe { palg.as_mut() } {
            *p = k.key_encryption_algorithm;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { pukm.as_mut() } {
            *p = k.ukm;
        }
        1
    }
}

ffi_export! {
    /// A key-agreement recipient's encrypted keys, or NULL.
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info.
    pub unsafe extern "C" fn CMS_RecipientInfo_kari_get0_reks(ri: *mut CMS_RecipientInfo) -> *mut stack_st_CMS_RecipientEncryptedKey
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return ptr::null_mut() };
        kari_of(r, "CMS_RecipientInfo_kari_get0_reks")
            .map_or(ptr::null_mut(), |k| k.recipient_encrypted_keys.cast())
    }
}

/// The originator's identifier: (public key algorithm, public key, key identifier, issuer,
/// serial number), with the ones of other choices NULL; `None` for an unset choice.
fn orig_id(
    k: &KeyAgreeRecipientInfo,
) -> Option<(
    *mut X509_ALGOR,
    *mut ASN1_BIT_STRING,
    *mut ASN1_OCTET_STRING,
    *mut X509_NAME,
    *mut ASN1_INTEGER,
)> {
    // SAFETY: the recipient's originator, made with it.
    let oik = unsafe { k.originator.as_ref() }?;
    let none = (
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
    );
    match oik.type_ {
        OIK_ISSUER_SERIAL => {
            // SAFETY: the choice's member, NULL or live.
            let ias = unsafe { oik.d.cast::<IssuerAndSerialNumber>().as_ref() };
            Some(ias.map_or(none, |i| {
                (
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    i.issuer,
                    i.serial_number,
                )
            }))
        }
        OIK_KEYIDENTIFIER => Some((
            ptr::null_mut(),
            ptr::null_mut(),
            oik.d.cast(),
            ptr::null_mut(),
            ptr::null_mut(),
        )),
        OIK_PUBKEY => {
            // SAFETY: as above.
            let opk = unsafe { oik.d.cast::<OriginatorPublicKey>().as_ref() };
            Some(opk.map_or(none, |o| {
                (
                    o.algorithm,
                    o.public_key,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            }))
        }
        _ => None,
    }
}

/// The originator's public key algorithm and key, as `CMS_RecipientInfo_kari_get0_orig_id`
/// gives them: `None` for an unset choice, NULLs for an identifier.
pub(crate) fn orig_pubkey(
    k: &KeyAgreeRecipientInfo,
) -> Option<(*mut X509_ALGOR, *mut ASN1_BIT_STRING)> {
    orig_id(k).map(|(alg, key, ..)| (alg, key))
}

ffi_export! {
    /// A key-agreement recipient's originator: its public key and algorithm, key identifier,
    /// or issuer and serial number (the others NULL). 1, or 0.
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info; the others NULL or room for a pointer.
    pub unsafe extern "C" fn CMS_RecipientInfo_kari_get0_orig_id(ri: *mut CMS_RecipientInfo, pubalg: *mut *mut X509_ALGOR, pubkey: *mut *mut ASN1_BIT_STRING, keyid: *mut *mut ASN1_OCTET_STRING, issuer: *mut *mut X509_NAME, sno: *mut *mut ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return 0 };
        let Some(k) = kari_of(r, "CMS_RecipientInfo_kari_get0_orig_id") else { return 0 };
        let found = orig_id(k);
        let (a, p, kid, i, s) = found.unwrap_or((
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        ));
        // SAFETY: the caller's room, or NULL.
        if let Some(o) = unsafe { issuer.as_mut() } {
            *o = i;
        }
        // SAFETY: as above.
        if let Some(o) = unsafe { sno.as_mut() } {
            *o = s;
        }
        // SAFETY: as above.
        if let Some(o) = unsafe { keyid.as_mut() } {
            *o = kid;
        }
        // SAFETY: as above.
        if let Some(o) = unsafe { pubalg.as_mut() } {
            *o = a;
        }
        // SAFETY: as above.
        if let Some(o) = unsafe { pubkey.as_mut() } {
            *o = p;
        }
        c_int::from(found.is_some())
    }
}

ffi_export! {
    /// 0 if a key-agreement recipient's originator is the certificate (by issuer and serial
    /// number or key identifier); -1 otherwise, -2 for other recipients.
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info; `cert` a live certificate.
    pub unsafe extern "C" fn CMS_RecipientInfo_kari_orig_id_cmp(ri: *mut CMS_RecipientInfo, cert: *mut X509) -> c_int
    where failure = -2, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return -2 };
        let Some(k) = kari_of(r, "CMS_RecipientInfo_kari_orig_id_cmp") else { return -2 };
        // SAFETY: the recipient's originator, made with it.
        let Some(oik) = (unsafe { k.originator.as_ref() }) else { return -1 };
        match oik.type_ {
            // SAFETY: the choice's member, NULL or live.
            OIK_ISSUER_SERIAL => match unsafe { oik.d.cast::<IssuerAndSerialNumber>().as_ref() } {
                // SAFETY: the caller's certificate.
                Some(ias) => unsafe { ias_cert_cmp(ias, cert) },
                None => -1,
            },
            // SAFETY: as above.
            OIK_KEYIDENTIFIER => unsafe { keyid_cert_cmp(oik.d.cast(), cert) },
            _ => -1,
        }
    }
}

/// The encrypted key behind a pointer.
///
/// # Safety
/// `rek` is NULL or a live encrypted key.
unsafe fn rek_of<'a>(rek: *mut CMS_RecipientEncryptedKey) -> Option<&'a mut RecipientEncryptedKey> {
    // SAFETY: the caller's guarantee.
    unsafe { rek.cast::<RecipientEncryptedKey>().as_mut() }
}

ffi_export! {
    /// An encrypted key's recipient: its key identifier, date, and other attribute, or issuer
    /// and serial number (the others NULL). 1, or 0.
    ///
    /// # Safety
    /// `rek` is NULL or a live encrypted key; the others NULL or room for a pointer.
    pub unsafe extern "C" fn CMS_RecipientEncryptedKey_get0_id(rek: *mut CMS_RecipientEncryptedKey, keyid: *mut *mut ASN1_OCTET_STRING, tm: *mut *mut ASN1_GENERALIZEDTIME, other: *mut *mut CMS_OtherKeyAttribute, issuer: *mut *mut X509_NAME, sno: *mut *mut ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee; its identifier, made with it.
        let Some(rid) = (unsafe { rek_of(rek) }).and_then(|r| unsafe { r.rid.as_ref() }) else { return 0 };
        let ids = match rid.type_ {
            // SAFETY: the choice's member, NULL or live.
            REK_ISSUER_SERIAL => unsafe { rid.d.cast::<IssuerAndSerialNumber>().as_ref() }.map(|i| {
                (ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), i.issuer, i.serial_number)
            }),
            // SAFETY: as above.
            REK_KEYIDENTIFIER => unsafe { rid.d.cast::<RecipientKeyIdentifier>().as_ref() }.map(|r| {
                (r.subject_key_identifier, r.date, r.other.cast(), ptr::null_mut(), ptr::null_mut())
            }),
            _ => None,
        };
        let Some((k, t, o, i, s)) = ids else { return 0 };
        // SAFETY: the caller's room, or NULL.
        if let Some(p) = unsafe { keyid.as_mut() } {
            *p = k;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { tm.as_mut() } {
            *p = t;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { other.as_mut() } {
            *p = o;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { issuer.as_mut() } {
            *p = i;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { sno.as_mut() } {
            *p = s;
        }
        1
    }
}

ffi_export! {
    /// 0 if an encrypted key's recipient is the certificate; -1 otherwise.
    ///
    /// # Safety
    /// `rek` is NULL or a live encrypted key; `cert` a live certificate.
    pub unsafe extern "C" fn CMS_RecipientEncryptedKey_cert_cmp(rek: *mut CMS_RecipientEncryptedKey, cert: *mut X509) -> c_int
    where failure = -1, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee; its identifier, made with it.
        let Some(rid) = (unsafe { rek_of(rek) }).and_then(|r| unsafe { r.rid.as_ref() }) else { return -1 };
        match rid.type_ {
            // SAFETY: the choice's member, NULL or live.
            REK_ISSUER_SERIAL => match unsafe { rid.d.cast::<IssuerAndSerialNumber>().as_ref() } {
                // SAFETY: the caller's certificate.
                Some(ias) => unsafe { ias_cert_cmp(ias, cert) },
                None => -1,
            },
            // SAFETY: as above.
            REK_KEYIDENTIFIER => match unsafe { rid.d.cast::<RecipientKeyIdentifier>().as_ref() } {
                // SAFETY: the caller's certificate.
                Some(r) => unsafe { keyid_cert_cmp(r.subject_key_identifier, cert) },
                None => -1,
            },
            _ => -1,
        }
    }
}

/// `CMS_RecipientInfo_kari_set0_pkey_and_peer` on the choice.
///
/// # Safety
/// `pk` and `peer` are NULL or live.
unsafe fn set0_pkey_and_peer(
    k: &mut KeyAgreeRecipientInfo,
    pk: *mut EVP_PKEY,
    peer: *mut X509,
) -> bool {
    // SAFETY: the recipient's context, or NULL.
    unsafe { EVP_PKEY_CTX_free(k.pctx) };
    k.pctx = ptr::null_mut();
    if pk.is_null() {
        return true;
    }
    let (libctx, propq) = ctx_parts(k.cms_ctx);
    // SAFETY: the caller's key; the context's parts.
    let pctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, pk, propq) };
    // SAFETY: a live context.
    let ok = !pctx.is_null()
        && unsafe { EVP_PKEY_derive_init(pctx) } > 0
        && (peer.is_null() || {
            // SAFETY: the caller's certificate.
            let pub_pkey = unsafe { X509_get0_pubkey(peer) };
            // SAFETY: the context; its key, or NULL.
            (unsafe { EVP_PKEY_derive_set_peer(pctx, pub_pkey) }) > 0
        });
    if !ok {
        // SAFETY: the context made here, or NULL.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        return false;
    }
    k.pctx = pctx;
    true
}

ffi_export! {
    /// Sets a key-agreement recipient's private key (NULL to drop it) and the originator's
    /// certificate for its public key: 1, or 0.
    ///
    /// # Safety
    /// `ri` is NULL or a live key-agreement recipient info; `pk` and `peer` NULL or live.
    pub unsafe extern "C" fn CMS_RecipientInfo_kari_set0_pkey_and_peer(ri: *mut CMS_RecipientInfo, pk: *mut EVP_PKEY, peer: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return 0 };
        let Some(k) = member::<KeyAgreeRecipientInfo>(r, CMS_RECIPINFO_AGREE) else { return 0 };
        // SAFETY: as above.
        c_int::from(unsafe { set0_pkey_and_peer(k, pk, peer) })
    }
}

ffi_export! {
    /// Sets a key-agreement recipient's private key (NULL to drop it): 1, or 0.
    ///
    /// # Safety
    /// `ri` is NULL or a live key-agreement recipient info; `pk` NULL or live.
    pub unsafe extern "C" fn CMS_RecipientInfo_kari_set0_pkey(ri: *mut CMS_RecipientInfo, pk: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        unsafe { CMS_RecipientInfo_kari_set0_pkey_and_peer(ri, pk, ptr::null_mut()) }
    }
}

ffi_export! {
    /// A key-agreement recipient's key-wrap cipher context, or NULL.
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info.
    pub unsafe extern "C" fn CMS_RecipientInfo_kari_get0_ctx(ri: *mut CMS_RecipientInfo) -> *mut EVP_CIPHER_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return ptr::null_mut() };
        member::<KeyAgreeRecipientInfo>(r, CMS_RECIPINFO_AGREE).map_or(ptr::null_mut(), |k| k.ctx)
    }
}

/// `cms_kek_cipher`: derives the key-encryption key and wraps (`enc`) or unwraps `input` with
/// it, into a buffer from CRYPTO_malloc. The derivation's context is used up either way.
fn kek_cipher(
    k: &mut KeyAgreeRecipientInfo,
    input: &[u8],
    enc: bool,
) -> Option<(*mut c_uchar, usize)> {
    let mut kek = [0u8; EVP_MAX_KEY_LENGTH as usize];
    // SAFETY: the recipient's cipher context.
    let Ok(mut keklen) = usize::try_from(unsafe { EVP_CIPHER_CTX_get_key_length(k.ctx) }) else {
        return None;
    };
    if keklen > kek.len() {
        return None;
    }
    let mut out: *mut c_uchar = ptr::null_mut();
    let mut out_alloc_len = 0usize;
    let rv = 'err: {
        let Ok(inlen) = c_int::try_from(input.len()) else {
            break 'err None;
        };
        // SAFETY: the recipient's derivation context; room for the key.
        if unsafe { EVP_PKEY_derive(k.pctx, kek.as_mut_ptr(), &mut keklen) } <= 0 {
            break 'err None;
        }
        // SAFETY: the cipher context; the derived key.
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
            break 'err None;
        }
        let mut outlen: c_int = 0;
        // SAFETY: as above; the output's length, for the input.
        if unsafe { EVP_CipherUpdate(k.ctx, ptr::null_mut(), &mut outlen, input.as_ptr(), inlen) }
            == 0
        {
            break 'err None;
        }
        // A failed unwrap writes and cleanses up to the input's length.
        let Ok(o) = usize::try_from(outlen) else {
            break 'err None;
        };
        let outsize = o.max(input.len());
        out = mem::alloc(outsize).cast();
        if out.is_null() {
            break 'err None;
        }
        out_alloc_len = outsize;
        // SAFETY: as above; room for the output.
        if unsafe { EVP_CipherUpdate(k.ctx, out, &mut outlen, input.as_ptr(), inlen) } == 0 {
            break 'err None;
        }
        let Some(n) = usize::try_from(outlen).ok().filter(|&n| n <= outsize) else {
            break 'err None;
        };
        Some((out, n))
    };
    kek.fill(0);
    if rv.is_none() {
        // SAFETY: the buffer made here, or NULL.
        unsafe { mem::release_clean(out.cast(), out_alloc_len) };
    }
    // SAFETY: the recipient's cipher context.
    unsafe { EVP_CIPHER_CTX_reset(k.ctx) };
    // SAFETY: its derivation context.
    unsafe { EVP_PKEY_CTX_free(k.pctx) };
    k.pctx = ptr::null_mut();
    rv
}

ffi_export! {
    /// Decrypts the content key from one of a key-agreement recipient's encrypted keys (its
    /// private key set first): 1, or 0.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; `ri` one of its recipient infos; `rek` one of the
    /// recipient's encrypted keys.
    pub unsafe extern "C" fn CMS_RecipientInfo_kari_decrypt(cms: *mut CMS_ContentInfo, ri: *mut CMS_RecipientInfo, rek: *mut CMS_RecipientEncryptedKey) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return 0 };
        let Some(k) = member::<KeyAgreeRecipientInfo>(r, CMS_RECIPINFO_AGREE) else { return 0 };
        // SAFETY: as above.
        let Some(e) = (unsafe { rek_of(rek) }) else { return 0 };
        // SAFETY: the encrypted key's octets.
        let enckey = unsafe { octets(e.encrypted_key) };
        // Set up all the parameters to derive the KEK.
        // SAFETY: the recipient info and its choice.
        if unsafe { kari_asn1_ctrl(ri.cast(), k, 1) } == 0 {
            return 0;
        }
        let Some((cek, ceklen)) = kek_cipher(k, enckey, false) else { return 0 };
        let Some(ec) = env_enc_content(cms) else {
            // SAFETY: the buffer made above.
            unsafe { mem::release_clean(cek.cast(), ceklen) };
            return 0;
        };
        // SAFETY: the content key, from CRYPTO_malloc, or NULL.
        unsafe { mem::release_clean(ec.key.cast(), ec.keylen) };
        ec.key = cek;
        ec.keylen = ceklen;
        1
    }
}

/// `cms_kari_create_ephemeral_key`: a new key of the recipient's parameters, and a derivation
/// context with it.
///
/// # Safety
/// `pk` is a live key.
unsafe fn create_ephemeral_key(k: &mut KeyAgreeRecipientInfo, pk: *mut EVP_PKEY) -> bool {
    let (libctx, propq) = ctx_parts(k.cms_ctx);
    let mut ekey: *mut EVP_PKEY = ptr::null_mut();
    // SAFETY: the caller's key; the context's parts.
    let mut pctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, pk, propq) };
    let ok = 'err: {
        if pctx.is_null() {
            break 'err false;
        }
        // SAFETY: a live context.
        if unsafe { EVP_PKEY_keygen_init(pctx) } <= 0 {
            break 'err false;
        }
        // SAFETY: as above; room for the key.
        if unsafe { EVP_PKEY_keygen(pctx, &mut ekey) } <= 0 {
            break 'err false;
        }
        // SAFETY: as above.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        // SAFETY: the new key; the context's parts.
        pctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, ekey, propq) };
        if pctx.is_null() {
            break 'err false;
        }
        // SAFETY: a live context.
        if unsafe { EVP_PKEY_derive_init(pctx) } <= 0 {
            break 'err false;
        }
        k.pctx = pctx;
        true
    };
    if !ok {
        // SAFETY: the context made here, or NULL.
        unsafe { EVP_PKEY_CTX_free(pctx) };
    }
    // SAFETY: the new key, or NULL; the context holds its own reference.
    unsafe { EVP_PKEY_free(ekey) };
    ok
}

/// `cms_kari_set_originator_private_key`.
///
/// # Safety
/// `key` is a live key.
unsafe fn set_originator_private_key(k: &mut KeyAgreeRecipientInfo, key: *mut EVP_PKEY) -> bool {
    let (libctx, propq) = ctx_parts(k.cms_ctx);
    // SAFETY: the caller's key; the context's parts.
    let pctx: *mut EVP_PKEY_CTX = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, key, propq) };
    // SAFETY: a live context.
    if pctx.is_null() || unsafe { EVP_PKEY_derive_init(pctx) } <= 0 {
        // SAFETY: the context made here, or NULL.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        return false;
    }
    k.pctx = pctx;
    true
}

/// `ossl_cms_RecipientInfo_kari_init`: a key-agreement recipient for `recip` (its key
/// `recip_pubkey`), with an ephemeral key or the originator's.
///
/// # Safety
/// `ri` is a new recipient info; `recip` a live certificate with the live key
/// `recip_pubkey`; `originator` and `originator_priv` NULL or live.
pub(crate) unsafe fn kari_init(
    ri: &mut RecipientInfo,
    recip: *mut X509,
    recip_pubkey: *mut EVP_PKEY,
    originator: *mut X509,
    originator_priv: *mut EVP_PKEY,
    flags: c_int,
    ctx: *const CmsCtx,
) -> bool {
    // SAFETY: no preconditions.
    let it = unsafe { super::key_agree_recipient_info_it() };
    // SAFETY: the item.
    let kp = unsafe { ASN1_item_new(it) }.cast::<KeyAgreeRecipientInfo>();
    if kp.is_null() {
        return false;
    }
    ri.d = kp.cast();
    ri.encoded_type = CMS_RECIPINFO_AGREE;
    ri.type_ = CMS_RECIPINFO_AGREE;
    // SAFETY: the new choice.
    let k = unsafe { &mut *kp };
    k.version = 3;
    k.cms_ctx = ctx;
    // SAFETY: no preconditions.
    let rit = unsafe { super::recipient_encrypted_key_it() };
    // SAFETY: the item.
    let rekp = unsafe { ASN1_item_new(rit) }.cast::<RecipientEncryptedKey>();
    if rekp.is_null() {
        return false;
    }
    // SAFETY: the recipient's encrypted keys, made with it; the new one.
    if unsafe { OPENSSL_sk_push(k.recipient_encrypted_keys.cast(), rekp.cast()) } == 0 {
        // SAFETY: the encrypted key made here.
        unsafe { ASN1_item_free(rekp.cast(), rit) };
        return false;
    }
    // SAFETY: the new encrypted key, now the recipient's.
    let rek = unsafe { &mut *rekp };
    // SAFETY: its identifier, made with it.
    let Some(rid) = (unsafe { rek.rid.as_mut() }) else {
        return false;
    };
    if flags & CMS_USE_KEYID != 0 {
        rid.type_ = REK_KEYIDENTIFIER;
        // SAFETY: no preconditions.
        let kit = unsafe { super::recipient_key_identifier_it() };
        // SAFETY: the item.
        let rkid = unsafe { ASN1_item_new(kit) }.cast::<RecipientKeyIdentifier>();
        rid.d = rkid.cast();
        // SAFETY: the new identifier, or NULL.
        let Some(r) = (unsafe { rkid.as_mut() }) else {
            return false;
        };
        // SAFETY: its key identifier's slot; the caller's certificate.
        if !unsafe { set1_keyid(&raw mut r.subject_key_identifier, recip) } {
            return false;
        }
    } else {
        rid.type_ = REK_ISSUER_SERIAL;
        // SAFETY: the choice's slot; the caller's certificate.
        if !unsafe { set1_ias((&raw mut rid.d).cast(), recip) } {
            return false;
        }
    }
    if originator_priv.is_null() && originator.is_null() {
        // SAFETY: the recipient's key.
        if !unsafe { create_ephemeral_key(k, recip_pubkey) } {
            return false;
        }
    } else {
        if originator_priv.is_null() || originator.is_null() {
            return false;
        }
        // SAFETY: the recipient's originator, made with it.
        let Some(oik) = (unsafe { k.originator.as_mut() }) else {
            return false;
        };
        if flags & CMS_USE_ORIGINATOR_KEYID != 0 {
            oik.type_ = OIK_KEYIDENTIFIER;
            // SAFETY: no preconditions.
            oik.d = unsafe { ASN1_OCTET_STRING_new() }.cast();
            if oik.d.is_null() {
                return false;
            }
            // SAFETY: the choice's slot; the caller's certificate.
            if !unsafe { set1_keyid((&raw mut oik.d).cast(), originator) } {
                return false;
            }
        } else {
            oik.type_ = REK_ISSUER_SERIAL;
            // SAFETY: as above.
            if !unsafe { set1_ias((&raw mut oik.d).cast(), originator) } {
                return false;
            }
        }
        // SAFETY: the caller's key.
        if !unsafe { set_originator_private_key(k, originator_priv) } {
            return false;
        }
    }
    // SAFETY: the recipient's key.
    if unsafe { EVP_PKEY_up_ref(recip_pubkey) } == 0 {
        return false;
    }
    rek.pkey = recip_pubkey;
    true
}

/// `ossl_cms_RecipientInfo_wrap_init` (3.6's `cms_wrap_init`, shared by key agreement and
/// KEM recipients): the key wrap for the content cipher (triple DES's for triple DES, else
/// AES's of the key's size, or the cipher's own) in the recipient's cipher context `ctx`.
///
/// # Safety
/// `ctx` is the recipient's live cipher context; `cipher` is NULL or live.
pub(crate) unsafe fn wrap_init(
    ctx: *mut EVP_CIPHER_CTX,
    cms_ctx: *const CmsCtx,
    cipher: *const EVP_CIPHER,
) -> bool {
    // SAFETY: the recipient's cipher context.
    let set = unsafe { EVP_CIPHER_CTX_get0_cipher(ctx) };
    if !set.is_null() {
        // A suitable wrap is already set.
        // SAFETY: its cipher.
        return unsafe { EVP_CIPHER_get_mode(set) } == wrap_mode();
    }
    if cipher.is_null() {
        return false;
    }
    // SAFETY: a live cipher.
    let keylen = unsafe { EVP_CIPHER_get_key_length(cipher) };
    let mut name: *const core::ffi::c_char = ptr::null();
    // SAFETY: as above.
    if unsafe { EVP_CIPHER_get_flags(cipher) } & EVP_CIPH_FLAG_GET_WRAP_CIPHER as core::ffi::c_ulong
        != 0
    {
        // SAFETY: as above.
        let Some(ctrl) = (unsafe { EVP_CIPHER_meth_get_ctrl(cipher) }) else {
            return false;
        };
        let mut kekcipher: *const EVP_CIPHER = ptr::null();
        // SAFETY: the cipher's control, asked for its wrap with no context.
        if unsafe {
            ctrl(
                ptr::null_mut(),
                EVP_CTRL_GET_WRAP_CIPHER,
                0,
                (&raw mut kekcipher).cast(),
            )
        } <= 0
        {
            return false;
        }
        if !kekcipher.is_null() {
            // SAFETY: the wrap cipher.
            if unsafe { EVP_CIPHER_get_mode(kekcipher) } != wrap_mode() {
                return false;
            }
            // SAFETY: as above.
            name = unsafe { EVP_CIPHER_get0_name(kekcipher) };
        }
    }
    if name.is_null() {
        // SAFETY: a live cipher.
        name = if unsafe { EVP_CIPHER_get_type(cipher) } == NID_des_ede3_cbc {
            SN_id_smime_alg_CMS3DESwrap.as_ptr()
        } else if keylen <= 16 {
            SN_id_aes128_wrap.as_ptr()
        } else if keylen <= 24 {
            SN_id_aes192_wrap.as_ptr()
        } else {
            SN_id_aes256_wrap.as_ptr()
        };
    }
    let (libctx, propq) = ctx_parts(cms_ctx);
    // SAFETY: the name; the context's parts.
    let fetched = unsafe { EVP_CIPHER_fetch(libctx, name, propq) };
    if fetched.is_null() {
        return false;
    }
    // SAFETY: the recipient's cipher context; the wrap.
    let ret =
        unsafe { EVP_EncryptInit_ex(ctx, fetched, ptr::null_mut(), ptr::null(), ptr::null()) };
    // SAFETY: the cipher fetched here; the context holds its own reference.
    unsafe { EVP_CIPHER_free(fetched) };
    ret != 0
}

/// `EVP_CIPH_WRAP_MODE`, as `EVP_CIPHER_get_mode` reports it.
fn wrap_mode() -> c_int {
    EVP_CIPH_WRAP_MODE
}

/// `ossl_cms_RecipientInfo_kari_encrypt`: the ephemeral key into the originator, the KDF's
/// parameters, and the content key wrapped for each encrypted key.
///
/// # Safety
/// `cms` is a live object; `ri` one of its recipient infos.
pub(crate) unsafe fn kari_encrypt(cms: *const CMS_ContentInfo, ri: *mut RecipientInfo) -> bool {
    const F: &str = "ossl_cms_RecipientInfo_kari_encrypt";
    // SAFETY: the caller's guarantee.
    let Some(k) = kari_of(unsafe { &*ri }, F) else {
        return false;
    };
    let Some(ec) = env_enc_content(cms) else {
        return false;
    };
    // SAFETY: the content's cipher, or NULL.
    if !unsafe { wrap_init(k.ctx, k.cms_ctx, ec.cipher) } {
        return false;
    }
    // SAFETY: the recipient's originator, made with it.
    let Some(oik) = (unsafe { k.originator.as_mut() }) else {
        return false;
    };
    // Without an originator's key set up, an ephemeral key's (set by the KDF's parameters).
    if oik.type_ != -1 {
        // The originator's public key isn't kept at initialization.
        raise(CMS_R_ERROR_UNSUPPORTED_STATIC_KEY_AGREEMENT, F);
        return false;
    }
    oik.type_ = OIK_PUBKEY;
    // SAFETY: no preconditions.
    let oit = unsafe { super::originator_public_key_it() };
    // SAFETY: the item.
    oik.d = unsafe { ASN1_item_new(oit) }.cast();
    if oik.d.is_null() {
        return false;
    }
    // SAFETY: the recipient info and its choice.
    if unsafe { kari_asn1_ctrl(ri, k, 0) } == 0 {
        return false;
    }
    let key = if ec.key.is_null() {
        &[][..]
    } else {
        // SAFETY: the content key, of its length.
        unsafe { core::slice::from_raw_parts(ec.key, ec.keylen) }
    };
    let reks = k.recipient_encrypted_keys;
    // SAFETY: the recipient's encrypted keys.
    for i in 0..unsafe { OPENSSL_sk_num(reks.cast()) } {
        // SAFETY: an index within them.
        let Some(rek) = (unsafe { sk_get::<RecipientEncryptedKey>(reks, i) }) else {
            return false;
        };
        // SAFETY: the derivation context; the recipient's key.
        if unsafe { EVP_PKEY_derive_set_peer(k.pctx, rek.pkey) } <= 0 {
            return false;
        }
        let Some((enckey, len)) = kek_cipher(k, key, true) else {
            return false;
        };
        let Ok(n) = c_int::try_from(len) else {
            // SAFETY: the buffer made above.
            unsafe { mem::release(enckey.cast()) };
            return false;
        };
        // SAFETY: the encrypted key's string, taking the buffer.
        unsafe { ASN1_STRING_set0(rek.encrypted_key.cast(), enckey.cast(), n) };
    }
    true
}
