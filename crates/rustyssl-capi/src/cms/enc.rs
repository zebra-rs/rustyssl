//! Encrypted content (`cms_enc.c`): the cipher BIO for an encrypted content, with its key and
//! parameters, and EncryptedData's key.
//!
//! As in OpenSSL, decryption with a key of the wrong length silently uses a random key
//! instead (unless debugging), so a padding oracle learns nothing from which step failed.

use core::ffi::{c_int, c_uchar};
use core::ptr;

use rustyssl_abi::{
    BIO, BIO_C_GET_CIPHER_CTX, CMS_ContentInfo, CMS_R_CIPHER_AEAD_IN_ENVELOPED_DATA,
    CMS_R_CIPHER_AEAD_SET_TAG_ERROR, CMS_R_CIPHER_INITIALISATION_ERROR,
    CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR, CMS_R_INVALID_KEY_LENGTH, CMS_R_NO_KEY,
    CMS_R_NOT_ENCRYPTED_DATA, CMS_R_UNKNOWN_CIPHER, CMS_R_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM,
    ERR_LIB_CMS, ERR_R_ASN1_LIB, ERR_R_BIO_LIB, ERR_R_EVP_LIB, EVP_CIPH_FLAG_AEAD_CIPHER,
    EVP_CIPHER, EVP_CIPHER_CTX, EVP_CTRL_AEAD_SET_TAG, EVP_MAX_IV_LENGTH, NID_pkcs7_data,
    NID_pkcs7_encrypted, NID_undef, V_ASN1_UNDEF,
};

use super::base::{cms_of, content, ctx_of, ctx_parts, nid_obj, raise, type_nid};
use super::{CmsCtx, EncryptedContentInfo, EncryptedData};
use crate::asn1::tpl::free::ASN1_item_free;
use crate::asn1::tpl::items::{ASN1_TYPE_free, ASN1_TYPE_new};
use crate::asn1::tpl::new::ASN1_item_new;
use crate::bio::evp::BIO_f_cipher;
use crate::bio::{BIO_ctrl, BIO_free, BIO_new};
use crate::err::{ERR_clear_error, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::cipher::{
    EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_flags, EVP_CIPHER_get_type,
    EVP_CIPHER_get0_name,
};
use crate::evp::cipher_asn1::{AeadParams, asn1_to_param_ex, param_to_asn1_ex};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_get_iv_length, EVP_CIPHER_CTX_get_key_length,
    EVP_CIPHER_CTX_get_tag_length, EVP_CIPHER_CTX_get0_cipher, EVP_CIPHER_CTX_rand_key,
    EVP_CIPHER_CTX_set_key_length, EVP_CipherInit_ex,
};
use crate::evp::legacy_cipher::EVP_get_cipherbyname;
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::{OBJ_nid2sn, OBJ_obj2nid};
use crate::rand_lib::RAND_bytes_ex;
use rustyssl_crypto::bn::Zeroizing;

fn is_aead(cipher: *const EVP_CIPHER) -> bool {
    // SAFETY: a live cipher.
    (unsafe { EVP_CIPHER_get_flags(cipher) }) & EVP_CIPH_FLAG_AEAD_CIPHER as core::ffi::c_ulong != 0
}

/// A copy of `data` from CRYPTO_malloc (cleared when freed), or NULL.
fn c_copy(data: &[u8]) -> *mut c_uchar {
    let p = mem::alloc(data.len()).cast::<c_uchar>();
    if !p.is_null() && !data.is_empty() {
        // SAFETY: room for `data.len()` octets, fresh.
        unsafe { ptr::copy_nonoverlapping(data.as_ptr(), p, data.len()) };
    }
    p
}

/// Clears and frees the content key.
fn drop_key(ec: &mut EncryptedContentInfo) {
    // SAFETY: the key, from CRYPTO_malloc, of its length, or NULL.
    unsafe { mem::release_clean(ec.key.cast(), ec.keylen) };
    ec.key = ptr::null_mut();
}

/// `ossl_cms_EncryptedContent_init_bio`: a cipher BIO set up to encrypt (with a new key and
/// IV, the parameters written to the algorithm) or to decrypt (from the algorithm's
/// parameters; `auth` for AuthEnvelopedData's AEAD cipher and tag). NULL on failure.
///
/// # Safety
/// `ec` is a live encrypted content info; `cms_ctx` NULL or live.
pub(crate) unsafe fn encrypted_content_init_bio(
    ec: &mut EncryptedContentInfo,
    cms_ctx: *const CmsCtx,
    auth: bool,
) -> *mut BIO {
    const F: &str = "ossl_cms_EncryptedContent_init_bio";
    let (libctx, propq) = ctx_parts(cms_ctx);
    let enc = !ec.cipher.is_null();
    // SAFETY: no preconditions.
    let method = unsafe { BIO_f_cipher() };
    // SAFETY: the built-in method.
    let b = unsafe { BIO_new(method) };
    if b.is_null() {
        raise(ERR_R_BIO_LIB, F);
        return ptr::null_mut();
    }
    let mut ctx: *mut EVP_CIPHER_CTX = ptr::null_mut();
    // SAFETY: a live cipher BIO; room for its context.
    unsafe { BIO_ctrl(b, BIO_C_GET_CIPHER_CTX, 0, (&raw mut ctx).cast()) };
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    let mut cipher: *const EVP_CIPHER = if enc {
        let c = ec.cipher;
        // Without a key to keep, later calls decrypt.
        if !ec.key.is_null() {
            ec.cipher = ptr::null();
        }
        c
    } else {
        // SAFETY: the algorithm, or NULL, and its object.
        let obj = unsafe { ec.content_encryption_algorithm.as_ref() }
            .map_or(ptr::null(), |a| a.algorithm.cast_const());
        // SAFETY: the object, or NULL.
        let nid = unsafe { OBJ_obj2nid(obj) };
        // SAFETY: any NID.
        let sn = unsafe { OBJ_nid2sn(nid) };
        // SAFETY: NULL or a static name.
        unsafe { EVP_get_cipherbyname(sn) }
    };
    let mut fetched: *mut EVP_CIPHER = ptr::null_mut();
    if !cipher.is_null() {
        // SAFETY: a live cipher.
        let name = unsafe { EVP_CIPHER_get0_name(cipher) };
        // SAFETY: its name; the object's context and properties.
        fetched = unsafe { EVP_CIPHER_fetch(libctx, name, propq) };
        if !fetched.is_null() {
            cipher = fetched;
        }
    }
    let mut keep_key = false;
    let mut tkey: Option<Zeroizing<Vec<u8>>> = None;
    let ok = 'err: {
        if cipher.is_null() {
            // SAFETY: no preconditions.
            unsafe { ERR_clear_last_mark() };
            raise(CMS_R_UNKNOWN_CIPHER, F);
            break 'err false;
        }
        // SAFETY: no preconditions.
        unsafe { ERR_pop_to_mark() };
        // SAFETY: the BIO's context; a live cipher.
        if unsafe {
            EVP_CipherInit_ex(
                ctx,
                cipher,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                c_int::from(enc),
            )
        } <= 0
        {
            raise(CMS_R_CIPHER_INITIALISATION_ERROR, F);
            break 'err false;
        }
        let mut aparams = AeadParams::default();
        let mut iv = [0u8; EVP_MAX_IV_LENGTH as usize];
        let mut piv: *const u8 = ptr::null();
        let mut ivlen = 0usize;
        // SAFETY: the algorithm, live with its content.
        let Some(calg) = (unsafe { ec.content_encryption_algorithm.as_mut() }) else {
            break 'err false;
        };
        if enc {
            // SAFETY: the context.
            let c = unsafe { EVP_CIPHER_CTX_get0_cipher(ctx) };
            // SAFETY: its cipher.
            let obj = nid_obj(unsafe { EVP_CIPHER_get_type(c) });
            // SAFETY: NULL or a static object.
            if obj.is_null() || unsafe { OBJ_obj2nid(obj) } == NID_undef {
                raise(CMS_R_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM, F);
                break 'err false;
            }
            calg.algorithm = obj;
            // SAFETY: the context.
            let Ok(n) = usize::try_from(unsafe { EVP_CIPHER_CTX_get_iv_length(ctx) }) else {
                raise(ERR_R_EVP_LIB, F);
                break 'err false;
            };
            ivlen = n;
            if ivlen > 0 {
                let Some(room) = iv.get_mut(..ivlen) else {
                    break 'err false;
                };
                // SAFETY: room for the IV.
                if unsafe { RAND_bytes_ex(libctx, room.as_mut_ptr(), ivlen, 0) } <= 0 {
                    break 'err false;
                }
                piv = iv.as_ptr();
            }
        } else {
            // SAFETY: the context; the algorithm's parameters, or NULL.
            if unsafe { asn1_to_param_ex(ctx, calg.parameter, Some(&mut aparams)) } <= 0 {
                raise(CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR, F);
                break 'err false;
            }
            if is_aead(cipher) {
                if !auth {
                    raise(CMS_R_CIPHER_AEAD_IN_ENVELOPED_DATA, F);
                    break 'err false;
                }
                piv = aparams.iv.as_ptr();
                let tag_ok = (4..=16).contains(&ec.taglen)
                    // SAFETY: the context; the tag of its length.
                    && unsafe { EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, c_int::try_from(ec.taglen).unwrap_or(0), ec.tag.cast()) } > 0;
                if !tag_ok {
                    raise(CMS_R_CIPHER_AEAD_SET_TAG_ERROR, F);
                    break 'err false;
                }
            } else if auth {
                raise(CMS_R_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM, F);
                break 'err false;
            }
        }
        // SAFETY: the context.
        let Some(tkeylen) = usize::try_from(unsafe { EVP_CIPHER_CTX_get_key_length(ctx) })
            .ok()
            .filter(|&n| n > 0)
        else {
            break 'err false;
        };
        if !enc || ec.key.is_null() {
            let mut k = Zeroizing::new(vec![0u8; tkeylen]);
            // SAFETY: room for the context's key.
            if unsafe { EVP_CIPHER_CTX_rand_key(ctx, k.as_mut_ptr()) } <= 0 {
                break 'err false;
            }
            tkey = Some(k);
        }
        if ec.key.is_null() {
            let k = tkey.take().unwrap_or_default();
            ec.key = c_copy(&k);
            ec.keylen = k.len();
            if ec.key.is_null() {
                break 'err false;
            }
            if enc {
                keep_key = true;
            } else {
                // SAFETY: no preconditions.
                unsafe { ERR_clear_error() };
            }
        }
        if ec.keylen != tkeylen {
            let n = c_int::try_from(ec.keylen).unwrap_or(c_int::MAX);
            // SAFETY: the context.
            if unsafe { EVP_CIPHER_CTX_set_key_length(ctx, n) } <= 0 {
                // Reveal only when debugging, so as to say nothing useful to an oracle.
                if enc || ec.debug != 0 {
                    raise(CMS_R_INVALID_KEY_LENGTH, F);
                    break 'err false;
                }
                drop_key(ec);
                let k = tkey.take().unwrap_or_default();
                ec.key = c_copy(&k);
                ec.keylen = k.len();
                // SAFETY: no preconditions.
                unsafe { ERR_clear_error() };
            }
        }
        // SAFETY: the context; the key of its length; the IV, or NULL.
        if unsafe {
            EVP_CipherInit_ex(
                ctx,
                ptr::null(),
                ptr::null_mut(),
                ec.key,
                piv,
                c_int::from(enc),
            )
        } <= 0
        {
            raise(CMS_R_CIPHER_INITIALISATION_ERROR, F);
            break 'err false;
        }
        if enc {
            // SAFETY: no preconditions.
            calg.parameter = unsafe { ASN1_TYPE_new() };
            if calg.parameter.is_null() {
                raise(ERR_R_ASN1_LIB, F);
                break 'err false;
            }
            if is_aead(cipher) {
                let Some(src) = iv.get(..ivlen) else {
                    break 'err false;
                };
                let Some(dst) = aparams.iv.get_mut(..ivlen) else {
                    break 'err false;
                };
                dst.copy_from_slice(src);
                aparams.iv_len = u32::try_from(ivlen).unwrap_or(0);
                // SAFETY: the context.
                let tag_len = unsafe { EVP_CIPHER_CTX_get_tag_length(ctx) };
                let Some(t) = u32::try_from(tag_len).ok().filter(|&t| t > 0) else {
                    break 'err false;
                };
                aparams.tag_len = t;
            }
            // SAFETY: the context; the algorithm's new parameters.
            if unsafe { param_to_asn1_ex(ctx, calg.parameter, Some(&mut aparams)) } <= 0 {
                raise(CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR, F);
                break 'err false;
            }
            // SAFETY: the parameters made above.
            if unsafe { (*calg.parameter).type_ } == V_ASN1_UNDEF {
                // SAFETY: as above.
                unsafe { ASN1_TYPE_free(calg.parameter) };
                calg.parameter = ptr::null_mut();
            }
        }
        true
    };
    // SAFETY: the fetched cipher, or NULL; the context holds its own reference.
    unsafe { EVP_CIPHER_free(fetched) };
    if !keep_key || !ok {
        drop_key(ec);
    }
    if ok {
        return b;
    }
    // SAFETY: the BIO made here.
    unsafe { BIO_free(b) };
    ptr::null_mut()
}

/// `ossl_cms_EncryptedContent_init`: the cipher (and Data as the content type) and a copy of
/// the key.
pub(crate) fn encrypted_content_init(
    ec: &mut EncryptedContentInfo,
    cipher: *const EVP_CIPHER,
    key: &[u8],
) -> bool {
    ec.cipher = cipher;
    if !key.is_empty() {
        ec.key = c_copy(key);
        if ec.key.is_null() {
            return false;
        }
    }
    ec.keylen = key.len();
    if !cipher.is_null() {
        ec.content_type = nid_obj(NID_pkcs7_data);
    }
    true
}

ffi_export! {
    /// Sets EncryptedData's key, making the object EncryptedData with `ciph` if given (an AEAD
    /// cipher can't be): 1, or 0.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; `ciph` NULL or live; `key` holds `keylen` octets.
    pub unsafe extern "C" fn CMS_EncryptedData_set1_key(cms: *mut CMS_ContentInfo, ciph: *const EVP_CIPHER, key: *const c_uchar, keylen: usize) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        const F: &str = "CMS_EncryptedData_set1_key";
        if key.is_null() || keylen == 0 {
            raise(CMS_R_NO_KEY, F);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { crate::ffi::bytes(key, keylen) }) else { return 0 };
        // SAFETY: as above.
        let Some(c) = (unsafe { cms_of(cms) }) else { return 0 };
        if !ciph.is_null() {
            if is_aead(ciph) {
                raise(CMS_R_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM, F);
                return 0;
            }
            // SAFETY: no preconditions.
            let it = unsafe { super::encrypted_data_it() };
            if type_nid(cms) == NID_pkcs7_encrypted && !c.d.is_null() {
                // SAFETY: the object's own content.
                unsafe { ASN1_item_free(c.d.cast(), it) };
                c.d = ptr::null_mut();
            }
            // SAFETY: the item.
            let ed = unsafe { ASN1_item_new(it) }.cast::<EncryptedData>();
            // SAFETY: the new content, or NULL.
            let Some(e) = (unsafe { ed.as_mut() }) else {
                raise(ERR_R_ASN1_LIB, F);
                return 0;
            };
            c.d = ed.cast();
            c.content_type = nid_obj(NID_pkcs7_encrypted);
            e.version = 0;
        } else if type_nid(cms) != NID_pkcs7_encrypted {
            raise(CMS_R_NOT_ENCRYPTED_DATA, F);
            return 0;
        }
        // SAFETY: the content of its type.
        let Some(ed) = (unsafe { content::<EncryptedData>(cms) }) else { return 0 };
        // SAFETY: its encrypted content, made with it.
        let Some(ec) = (unsafe { ed.encrypted_content_info.as_mut() }) else { return 0 };
        c_int::from(encrypted_content_init(ec, ciph, k))
    }
}

/// `ossl_cms_EncryptedData_init_bio`.
///
/// # Safety
/// `cms` is a live EncryptedData object.
pub(crate) unsafe fn encrypted_data_init_bio(cms: *mut CMS_ContentInfo) -> *mut BIO {
    // SAFETY: the content of its type.
    let Some(ed) = (unsafe { content::<EncryptedData>(cms) }) else {
        return ptr::null_mut();
    };
    // SAFETY: its encrypted content.
    let Some(ec) = (unsafe { ed.encrypted_content_info.as_mut() }) else {
        return ptr::null_mut();
    };
    if !ec.cipher.is_null() && !ed.unprotected_attrs.is_null() {
        ed.version = 2;
    }
    // SAFETY: as above; the object's context.
    unsafe { encrypted_content_init_bio(ec, ctx_of(cms), false) }
}
