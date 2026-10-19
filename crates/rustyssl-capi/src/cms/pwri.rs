//! Password recipients (`cms_pwri.c`): the PBKDF2 key-encryption key and RFC 3211's key
//! wrap of the content key.
//!
//! The unwrap checks the wrapped length against the input (CVE-2025-9230), and the wrap
//! refuses a content key too short for its check octets, which the reference reads past
//! (docs/DEVIATIONS.md).

use core::ffi::{c_char, c_int, c_uchar};
use core::ptr;

use rustyssl_abi::{
    CMS_ContentInfo, CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR,
    CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER, CMS_R_NO_CIPHER, CMS_R_NO_PASSWORD, CMS_R_NOT_PWRI,
    CMS_R_UNKNOWN_CIPHER, CMS_R_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM, CMS_R_UNWRAP_FAILURE,
    CMS_RECIPINFO_PASS, CMS_RecipientInfo, ERR_LIB_CMS, ERR_R_ASN1_LIB, ERR_R_CRYPTO_LIB,
    ERR_R_EVP_LIB, EVP_CIPHER, EVP_CIPHER_CTX, EVP_MAX_IV_LENGTH, NID_id_alg_PWRI_KEK,
    NID_id_pbkdf2, OSSL_LIB_CTX, V_ASN1_SEQUENCE,
};

use super::base::{ctx_of, ctx_parts, nid_obj, octets, raise};
use super::enc::drop_key;
use super::env::{env_enc_content, member, ri_of};
use super::{PasswordRecipientInfo, RecipientInfo};
use crate::asn1::any::ASN1_TYPE_set;
use crate::asn1::string::ASN1_STRING_set0;
use crate::asn1::tpl::free::ASN1_item_free;
use crate::asn1::tpl::items::{ASN1_TYPE_new, X509_ALGOR_free, X509_ALGOR_it, X509_ALGOR_new};
use crate::asn1::tpl::new::ASN1_item_new;
use crate::asn1::tpl::util::{ASN1_TYPE_unpack_sequence, ASN1_item_pack};
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_type};
use crate::evp::cipher_asn1::{EVP_CIPHER_asn1_to_param, EVP_CIPHER_param_to_asn1};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_get_block_size, EVP_CIPHER_CTX_get_iv_length,
    EVP_CIPHER_CTX_get0_cipher, EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_set_padding, EVP_CipherInit_ex,
    EVP_DecryptInit_ex, EVP_DecryptUpdate, EVP_EncryptInit_ex, EVP_EncryptUpdate,
};
use crate::evp::pbe::EVP_PBE_CipherInit_ex;
use crate::ffi::ffi_export;
use crate::objects::{OBJ_obj2nid, OBJ_obj2txt};
use crate::rand_lib::RAND_bytes_ex;
use crate::stack::OPENSSL_sk_push;
use crate::x509::pbe::PKCS5_pbkdf2_set_ex;
use rustyssl_crypto::bn::Zeroizing;

/// `OSSL_MAX_NAME_SIZE`, the room for an algorithm's name.
const NAME_LEN: usize = 50;

/// Sets the password choice's password (NUL-terminated if `passlen` is negative).
///
/// # Safety
/// `pass` is NULL or holds `passlen` octets (a C string if negative).
unsafe fn set0_password(p: &mut PasswordRecipientInfo, pass: *mut c_uchar, passlen: isize) {
    p.pass = pass;
    p.passlen = match usize::try_from(passlen) {
        Ok(n) => n,
        Err(_) if !pass.is_null() => {
            // SAFETY: the caller's C string.
            unsafe { core::ffi::CStr::from_ptr(pass.cast::<c_char>()) }.count_bytes()
        }
        // OpenSSL keeps a negative length for no password.
        Err(_) => passlen.cast_unsigned(),
    };
}

ffi_export! {
    /// Sets a password recipient's password (a C string if `passlen` is negative), which it
    /// takes: 1, or 0.
    ///
    /// # Safety
    /// `ri` is NULL or a live recipient info; `pass` NULL or holding `passlen` octets.
    pub unsafe extern "C" fn CMS_RecipientInfo_set0_password(ri: *mut CMS_RecipientInfo, pass: *mut c_uchar, passlen: isize) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { ri_of(ri) }) else { return 0 };
        let Some(p) = member::<PasswordRecipientInfo>(r, CMS_RECIPINFO_PASS) else {
            raise(CMS_R_NOT_PWRI, "CMS_RecipientInfo_set0_password");
            return 0;
        };
        // SAFETY: as above.
        unsafe { set0_password(p, pass, passlen) };
        1
    }
}

ffi_export! {
    /// Adds a password recipient: PBKDF2 of `iter` iterations and RFC 3211's wrap with
    /// `kekciph` (the content's cipher if NULL), for the password (taken; a C string if
    /// `passlen` is negative). The new recipient info, or NULL.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; `pass` NULL or from CRYPTO_malloc, of `passlen` octets;
    /// `kekciph` NULL or live.
    pub unsafe extern "C" fn CMS_add0_recipient_password(cms: *mut CMS_ContentInfo, iter: c_int, wrap_nid: c_int, pbe_nid: c_int, pass: *mut c_uchar, passlen: isize, kekciph: *const EVP_CIPHER) -> *mut CMS_RecipientInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        const F: &str = "CMS_add0_recipient_password";
        let Some(ec) = env_enc_content(cms) else { return ptr::null_mut() };
        // SAFETY: the caller's guarantee.
        let ris = unsafe { super::base::CMS_get0_RecipientInfos(cms) };
        if ris.is_null() {
            return ptr::null_mut();
        }
        let cms_ctx = ctx_of(cms);
        let (libctx, _) = ctx_parts(cms_ctx);
        let wrap_nid = if wrap_nid <= 0 { NID_id_alg_PWRI_KEK } else { wrap_nid };
        // Only PBKDF2 is made.
        let _ = if pbe_nid <= 0 { NID_id_pbkdf2 } else { pbe_nid };
        let kekciph = if kekciph.is_null() { ec.cipher } else { kekciph };
        if kekciph.is_null() {
            raise(CMS_R_NO_CIPHER, F);
            return ptr::null_mut();
        }
        if wrap_nid != NID_id_alg_PWRI_KEK {
            raise(CMS_R_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM, F);
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let rit = unsafe { super::recipient_info_it() };
        let mut encalg: *mut rustyssl_abi::X509_ALGOR;
        let mut ctx: *mut EVP_CIPHER_CTX = ptr::null_mut();
        let mut rip: *mut RecipientInfo = ptr::null_mut();
        let ok = 'err: {
            // The cipher's AlgorithmIdentifier.
            // SAFETY: no preconditions.
            encalg = unsafe { X509_ALGOR_new() };
            // SAFETY: the new AlgorithmIdentifier, or NULL.
            let Some(ea) = (unsafe { encalg.as_mut() }) else {
                raise(ERR_R_ASN1_LIB, F);
                break 'err false;
            };
            // SAFETY: no preconditions.
            ctx = unsafe { EVP_CIPHER_CTX_new() };
            if ctx.is_null() {
                raise(ERR_R_EVP_LIB, F);
                break 'err false;
            }
            // SAFETY: a live context and cipher.
            if unsafe { EVP_EncryptInit_ex(ctx, kekciph, ptr::null_mut(), ptr::null(), ptr::null()) } <= 0 {
                raise(ERR_R_EVP_LIB, F);
                break 'err false;
            }
            // SAFETY: a live context.
            let Ok(ivlen) = usize::try_from(unsafe { EVP_CIPHER_CTX_get_iv_length(ctx) }) else {
                raise(ERR_R_EVP_LIB, F);
                break 'err false;
            };
            if ivlen > 0 {
                let mut iv = [0u8; EVP_MAX_IV_LENGTH as usize];
                let Some(room) = iv.get_mut(..ivlen) else { break 'err false };
                // SAFETY: room for the IV.
                if unsafe { RAND_bytes_ex(libctx, room.as_mut_ptr(), ivlen, 0) } <= 0 {
                    break 'err false;
                }
                // SAFETY: a live context; the IV.
                if unsafe { EVP_EncryptInit_ex(ctx, ptr::null(), ptr::null_mut(), ptr::null(), iv.as_ptr()) } <= 0 {
                    raise(ERR_R_EVP_LIB, F);
                    break 'err false;
                }
                // SAFETY: no preconditions.
                ea.parameter = unsafe { ASN1_TYPE_new() };
                if ea.parameter.is_null() {
                    raise(ERR_R_ASN1_LIB, F);
                    break 'err false;
                }
                // SAFETY: as above; the new parameter.
                if unsafe { EVP_CIPHER_param_to_asn1(ctx, ea.parameter) } <= 0 {
                    raise(CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR, F);
                    break 'err false;
                }
            }
            // SAFETY: a live context.
            let c = unsafe { EVP_CIPHER_CTX_get0_cipher(ctx) };
            // SAFETY: its cipher.
            ea.algorithm = nid_obj(unsafe { EVP_CIPHER_get_type(c) });
            // SAFETY: the context made here.
            unsafe { EVP_CIPHER_CTX_free(ctx) };
            ctx = ptr::null_mut();

            // SAFETY: the item.
            rip = unsafe { ASN1_item_new(rit) }.cast();
            // SAFETY: the new recipient info, or NULL.
            let Some(ri) = (unsafe { rip.as_mut() }) else {
                raise(ERR_R_ASN1_LIB, F);
                break 'err false;
            };
            // SAFETY: no preconditions.
            let pit = unsafe { super::password_recipient_info_it() };
            // SAFETY: the item.
            let pp = unsafe { ASN1_item_new(pit) }.cast::<PasswordRecipientInfo>();
            if pp.is_null() {
                raise(ERR_R_ASN1_LIB, F);
                break 'err false;
            }
            ri.d = pp.cast();
            ri.encoded_type = CMS_RECIPINFO_PASS;
            ri.type_ = CMS_RECIPINFO_PASS;
            // SAFETY: the new choice.
            let p = unsafe { &mut *pp };
            p.cms_ctx = cms_ctx;
            // SAFETY: the empty AlgorithmIdentifier made with it, replaced here.
            unsafe { X509_ALGOR_free(p.key_encryption_algorithm) };
            // SAFETY: no preconditions.
            p.key_encryption_algorithm = unsafe { X509_ALGOR_new() };
            // SAFETY: the new AlgorithmIdentifier, or NULL.
            let Some(ka) = (unsafe { p.key_encryption_algorithm.as_mut() }) else {
                raise(ERR_R_ASN1_LIB, F);
                break 'err false;
            };
            ka.algorithm = nid_obj(wrap_nid);
            // SAFETY: no preconditions.
            ka.parameter = unsafe { ASN1_TYPE_new() };
            if ka.parameter.is_null() {
                raise(ERR_R_ASN1_LIB, F);
                break 'err false;
            }
            // SAFETY: no preconditions.
            let ait = unsafe { X509_ALGOR_it() };
            // SAFETY: the cipher's AlgorithmIdentifier, packed into a new string.
            let seq = unsafe { ASN1_item_pack(encalg.cast(), ait, ptr::null_mut()) };
            if seq.is_null() {
                raise(ERR_R_ASN1_LIB, F);
                break 'err false;
            }
            // SAFETY: the parameter, taking the string.
            unsafe { ASN1_TYPE_set(ka.parameter, V_ASN1_SEQUENCE, seq.cast()) };
            // SAFETY: the AlgorithmIdentifier made above, packed.
            unsafe { X509_ALGOR_free(encalg) };
            encalg = ptr::null_mut();

            // SAFETY: no salt (a random one); the default PRF and key length.
            p.key_derivation_algorithm = unsafe { PKCS5_pbkdf2_set_ex(iter, ptr::null_mut(), 0, -1, -1, libctx) };
            if p.key_derivation_algorithm.is_null() {
                break 'err false;
            }
            // SAFETY: the caller's password.
            unsafe { set0_password(p, pass, passlen) };
            p.version = 0;
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
        // SAFETY: the context made here, or NULL.
        unsafe { EVP_CIPHER_CTX_free(ctx) };
        // SAFETY: the recipient info made here, or NULL.
        unsafe { ASN1_item_free(rip.cast(), rit) };
        // SAFETY: the AlgorithmIdentifier made here, or NULL.
        unsafe { X509_ALGOR_free(encalg) };
        ptr::null_mut()
    }
}

/// RFC 3211's key unwrap: the key from `input`, decrypted with `ctx` (its IV from the last
/// two blocks), checked and of a length within the input.
///
/// # Safety
/// `ctx` is a live context, initialized to decrypt with no padding.
unsafe fn kek_unwrap_key(input: &[u8], ctx: *mut EVP_CIPHER_CTX) -> Option<Zeroizing<Vec<u8>>> {
    // SAFETY: the caller's guarantee.
    let blocklen = usize::try_from(unsafe { EVP_CIPHER_CTX_get_block_size(ctx) }).ok()?;
    if blocklen < 4 {
        return None;
    }
    let inlen = input.len();
    // Too small, or not a whole number of blocks.
    if inlen < 2 * blocklen || !inlen.is_multiple_of(blocklen) {
        return None;
    }
    let n = c_int::try_from(inlen).ok()?;
    let bl = c_int::try_from(blocklen).ok()?;
    let mut tmp = Zeroizing::new(vec![0u8; inlen]);
    let t = tmp.as_mut_ptr();
    let i = input.as_ptr();
    let mut outl: c_int = 0;
    // SAFETY: an offset within the buffer of `inlen` octets.
    let t_last2 = unsafe { t.add(inlen - 2 * blocklen) };
    // SAFETY: as above.
    let t_last = unsafe { t.add(inlen - blocklen) };
    // SAFETY: as above, in the input.
    let i_last2 = unsafe { i.add(inlen - 2 * blocklen) };
    // Decrypt the last two blocks for the IV, then the last decrypted block again (into the
    // start, which the buffer's two blocks keep apart) to set the IV, then the first n - 1
    // blocks; reset the IV and decrypt all again.
    // SAFETY: the context; output and input within the buffers, two blocks each.
    let ok = unsafe { EVP_DecryptUpdate(ctx, t_last2, &mut outl, i_last2, 2 * bl) } != 0
        // SAFETY: as above, a block each, apart.
        && unsafe { EVP_DecryptUpdate(ctx, t, &mut outl, t_last, bl) } != 0
        // SAFETY: as above, `inlen` less a block.
        && unsafe { EVP_DecryptUpdate(ctx, t, &mut outl, i, n - bl) } != 0
        // SAFETY: the context, its IV reset.
        && unsafe { EVP_DecryptInit_ex(ctx, ptr::null(), ptr::null_mut(), ptr::null(), ptr::null()) } != 0
        // SAFETY: the context; in place, `inlen` octets.
        && unsafe { EVP_DecryptUpdate(ctx, t, &mut outl, t, n) } != 0;
    if !ok {
        return None;
    }
    let [len, c1, c2, c3, k1, k2, k3, ..] = tmp[..] else {
        return None;
    };
    // The check octets.
    if (c1 ^ k1) & (c2 ^ k2) & (c3 ^ k3) != 0xff {
        return None;
    }
    let keylen = usize::from(len);
    // The length must fit the input (CVE-2025-9230).
    if inlen < 4 + keylen {
        return None;
    }
    Some(Zeroizing::new(tmp.get(4..4 + keylen)?.to_vec()))
}

/// RFC 3211's key wrap: the key's length, check octets, the key, and random padding to whole
/// blocks (at least two), encrypted twice with `ctx`.
///
/// # Safety
/// `ctx` is a live context, initialized to encrypt with no padding.
unsafe fn kek_wrap_key(
    key: &[u8],
    ctx: *mut EVP_CIPHER_CTX,
    libctx: *mut OSSL_LIB_CTX,
) -> Option<Vec<u8>> {
    // SAFETY: the caller's guarantee.
    let blocklen = usize::try_from(unsafe { EVP_CIPHER_CTX_get_block_size(ctx) }).ok()?;
    if blocklen == 0 {
        return None;
    }
    let inlen = key.len();
    let olen = (inlen + 4).div_ceil(blocklen) * blocklen;
    // Too small, or too large.
    if olen < 2 * blocklen || inlen > 0xFF {
        return None;
    }
    // Too short for its check octets (docs/DEVIATIONS.md).
    let [k1, k2, k3, ..] = *key else {
        return None;
    };
    let mut out = vec![0u8; olen];
    let (head, rest) = out.split_at_mut(4);
    head.copy_from_slice(&[u8::try_from(inlen).ok()?, k1 ^ 0xFF, k2 ^ 0xFF, k3 ^ 0xFF]);
    let (body, pad) = rest.split_at_mut(inlen);
    body.copy_from_slice(key);
    // SAFETY: room for the padding.
    if !pad.is_empty() && unsafe { RAND_bytes_ex(libctx, pad.as_mut_ptr(), pad.len(), 0) } <= 0 {
        return None;
    }
    let n = c_int::try_from(olen).ok()?;
    let o = out.as_mut_ptr();
    let mut dummy: c_int = 0;
    // SAFETY: the context; in place, `olen` octets.
    let ok = unsafe { EVP_EncryptUpdate(ctx, o, &mut dummy, o, n) } != 0
        // SAFETY: as above.
        && unsafe { EVP_EncryptUpdate(ctx, o, &mut dummy, o, n) } != 0;
    ok.then_some(out)
}

/// `ossl_cms_RecipientInfo_pwri_crypt`: the content key wrapped (`en_de`) or unwrapped with
/// the password's key-encryption key.
///
/// # Safety
/// `cms` is a live object; `ri` one of its recipient infos.
pub(crate) unsafe fn pwri_crypt(
    cms: *const CMS_ContentInfo,
    ri: &mut RecipientInfo,
    en_de: bool,
) -> bool {
    const F: &str = "ossl_cms_RecipientInfo_pwri_crypt";
    let Some(ec) = env_enc_content(cms) else {
        return false;
    };
    let Some(p) = member::<PasswordRecipientInfo>(ri, CMS_RECIPINFO_PASS) else {
        return false;
    };
    let (libctx, propq) = ctx_parts(ctx_of(cms));
    if p.pass.is_null() {
        raise(CMS_R_NO_PASSWORD, F);
        return false;
    }
    // SAFETY: the recipient's algorithm, or NULL.
    let Some(alg) = (unsafe { p.key_encryption_algorithm.as_ref() }) else {
        raise(CMS_R_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM, F);
        return false;
    };
    // SAFETY: its object.
    if unsafe { OBJ_obj2nid(alg.algorithm) } != NID_id_alg_PWRI_KEK {
        raise(CMS_R_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM, F);
        return false;
    }
    // SAFETY: no preconditions.
    let ait = unsafe { X509_ALGOR_it() };
    // SAFETY: its parameter, NULL or live.
    let kekalg =
        unsafe { ASN1_TYPE_unpack_sequence(ait, alg.parameter) }.cast::<rustyssl_abi::X509_ALGOR>();
    // SAFETY: the unpacked AlgorithmIdentifier, or NULL.
    let Some(ka) = (unsafe { kekalg.as_ref() }) else {
        raise(CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER, F);
        return false;
    };
    let mut name = [0 as c_char; NAME_LEN];
    let len = c_int::try_from(NAME_LEN).unwrap_or(0);
    // SAFETY: room for the name; its object.
    unsafe { OBJ_obj2txt(name.as_mut_ptr(), len, ka.algorithm, 0) };
    // SAFETY: the name; the context's parts.
    let kekcipher = unsafe { EVP_CIPHER_fetch(libctx, name.as_ptr(), propq) };
    let mut kekctx: *mut EVP_CIPHER_CTX = ptr::null_mut();
    let ok = 'err: {
        if kekcipher.is_null() {
            raise(CMS_R_UNKNOWN_CIPHER, F);
            break 'err false;
        }
        // SAFETY: no preconditions.
        kekctx = unsafe { EVP_CIPHER_CTX_new() };
        if kekctx.is_null() {
            raise(ERR_R_EVP_LIB, F);
            break 'err false;
        }
        // The cipher from the AlgorithmIdentifier, for its IV and the like.
        // SAFETY: a live context and cipher.
        if unsafe {
            EVP_CipherInit_ex(
                kekctx,
                kekcipher,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                c_int::from(en_de),
            )
        } == 0
        {
            break 'err false;
        }
        // SAFETY: a live context.
        unsafe { EVP_CIPHER_CTX_set_padding(kekctx, 0) };
        // SAFETY: as above; the parameters, or NULL.
        if unsafe { EVP_CIPHER_asn1_to_param(kekctx, ka.parameter) } <= 0 {
            raise(CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR, F);
            break 'err false;
        }
        // SAFETY: the recipient's key derivation, or NULL.
        let Some(kd) = (unsafe { p.key_derivation_algorithm.as_ref() }) else {
            crate::err::raise_with_text(
                ERR_LIB_CMS,
                CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER,
                F,
                "Missing KeyDerivationAlgorithm",
            );
            break 'err false;
        };
        // The password-based key derivation sets the context's key.
        let passlen = c_int::try_from(p.passlen).unwrap_or(-1);
        // SAFETY: the derivation's object and parameters; the password; the context.
        if unsafe {
            EVP_PBE_CipherInit_ex(
                kd.algorithm,
                p.pass.cast(),
                passlen,
                kd.parameter,
                kekctx,
                c_int::from(en_de),
                libctx,
                propq,
            )
        } == 0
        {
            raise(ERR_R_EVP_LIB, F);
            break 'err false;
        }
        if en_de {
            let key = if ec.key.is_null() {
                &[][..]
            } else {
                // SAFETY: the content key, of its length.
                unsafe { core::slice::from_raw_parts(ec.key, ec.keylen) }
            };
            // SAFETY: the context, set up to encrypt.
            let Some(wrapped) = (unsafe { kek_wrap_key(key, kekctx, libctx) }) else {
                break 'err false;
            };
            let Ok(n) = c_int::try_from(wrapped.len()) else {
                break 'err false;
            };
            let buf = super::enc::c_copy(&wrapped);
            if buf.is_null() {
                break 'err false;
            }
            // SAFETY: the recipient's encrypted key, taking the buffer.
            unsafe { ASN1_STRING_set0(p.encrypted_key.cast(), buf.cast(), n) };
        } else {
            // SAFETY: the recipient's encrypted key.
            let input = unsafe { octets(p.encrypted_key) };
            // SAFETY: the context, set up to decrypt.
            let Some(key) = (unsafe { kek_unwrap_key(input, kekctx) }) else {
                raise(CMS_R_UNWRAP_FAILURE, F);
                break 'err false;
            };
            let buf = super::enc::c_copy(&key);
            if buf.is_null() {
                break 'err false;
            }
            drop_key(ec);
            ec.key = buf;
            ec.keylen = key.len();
        }
        true
    };
    // SAFETY: the cipher fetched here, or NULL.
    unsafe { EVP_CIPHER_free(kekcipher) };
    // SAFETY: the context made here, or NULL.
    unsafe { EVP_CIPHER_CTX_free(kekctx) };
    // SAFETY: the AlgorithmIdentifier unpacked here.
    unsafe { X509_ALGOR_free(kekalg) };
    ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::legacy_cipher::EVP_aes_128_ctr;

    /// A context to encrypt with AES-128-CTR, whose blocks are one octet.
    fn ctr_ctx() -> *mut EVP_CIPHER_CTX {
        // SAFETY: no preconditions.
        let ctx = unsafe { EVP_CIPHER_CTX_new() };
        assert!(!ctx.is_null());
        let key = [7u8; 16];
        let iv = [9u8; 16];
        // SAFETY: no preconditions.
        let cipher = unsafe { EVP_aes_128_ctr() };
        // SAFETY: a live context; a built-in cipher; its key and IV.
        let r = unsafe {
            EVP_CipherInit_ex(ctx, cipher, ptr::null_mut(), key.as_ptr(), iv.as_ptr(), 1)
        };
        assert_eq!(r, 1);
        ctx
    }

    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn a_key_too_short_for_its_check_octets_is_not_wrapped() {
        let ctx = ctr_ctx();
        // The reference reads the check octets past a two-octet key.
        // SAFETY: a context set up to encrypt.
        assert!(unsafe { kek_wrap_key(&[1, 2], ctx, ptr::null_mut()) }.is_none());
        // SAFETY: as above.
        let w = unsafe { kek_wrap_key(&[1, 2, 3], ctx, ptr::null_mut()) };
        assert_eq!(w.map(|w| w.len()), Some(7));
        // SAFETY: the context made here.
        unsafe { EVP_CIPHER_CTX_free(ctx) };
    }
}
