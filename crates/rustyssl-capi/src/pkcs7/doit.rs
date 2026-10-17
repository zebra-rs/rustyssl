//! PKCS#7's data path (`pk7_doit.c`): the BIO chains that digest, encrypt, or decrypt a content,
//! finishing an object from them, and signing and verifying its signer infos.
//!
//! Decryption keeps OpenSSL's defence against Bleichenbacher-style oracles: a recipient key that
//! fails to decrypt leaves a random content key in its place, so a wrong key and a tampered one
//! fail the same way, at the padding of the content. The signed-attribute digest is compared in
//! constant time. `PKCS7_dataFinal` copies the content out of its memory BIO where OpenSSL takes
//! the BIO's buffer and leaves the BIO read-only (docs/DEVIATIONS.md).

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_OBJECT, ASN1_OCTET_STRING, ASN1_STRING_FLAG_NDEF, BIO, BIO_C_GET_CIPHER_CTX,
    BIO_C_GET_MD_CTX, BIO_C_SET_BUF_MEM_EOF_RETURN, BIO_C_SET_MD, BIO_CTRL_INFO, BIO_TYPE_MD,
    BIO_TYPE_MEM, ERR_LIB_EVP, ERR_LIB_PKCS7, ERR_R_ASN1_LIB, ERR_R_BIO_LIB, ERR_R_EVP_LIB,
    ERR_R_INTERNAL_ERROR, ERR_R_PKCS7_LIB, ERR_R_X509_LIB, EVP_CIPHER, EVP_CIPHER_CTX,
    EVP_MAX_IV_LENGTH, EVP_MAX_KEY_LENGTH, EVP_MAX_MD_SIZE, EVP_MD, EVP_MD_CTX, EVP_PKEY,
    EVP_PKEY_CTX, NID_pkcs7_data, NID_pkcs7_digest, NID_pkcs7_enveloped, NID_pkcs7_signed,
    NID_pkcs7_signedAndEnveloped, NID_pkcs9_signingTime, OSSL_LIB_CTX, PKCS7, PKCS7_CTX,
    PKCS7_OP_GET_DETACHED_SIGNATURE, PKCS7_R_CIPHER_NOT_INITIALIZED, PKCS7_R_DIGEST_FAILURE,
    PKCS7_R_INVALID_NULL_POINTER, PKCS7_R_INVALID_SIGNED_DATA_TYPE, PKCS7_R_NO_CONTENT,
    PKCS7_R_NO_RECIPIENT_MATCHES_CERTIFICATE, PKCS7_R_SIGNATURE_FAILURE,
    PKCS7_R_UNABLE_TO_FIND_CERTIFICATE, PKCS7_R_UNABLE_TO_FIND_MEM_BIO,
    PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST, PKCS7_R_UNKNOWN_DIGEST_TYPE,
    PKCS7_R_UNSUPPORTED_CIPHER_TYPE, PKCS7_R_UNSUPPORTED_CONTENT_TYPE, PKCS7_R_WRONG_PKCS7_TYPE,
    PKCS7_RECIP_INFO, PKCS7_S_HEADER, PKCS7_SIGNER_INFO, V_ASN1_CONSTRUCTED, V_ASN1_SEQUENCE, X509,
    X509_ALGOR, X509_PURPOSE_SMIME_SIGN, X509_STORE, X509_STORE_CTX, stack_st_X509_ALGOR,
};
use rustyssl_crypto::bn::Zeroizing;

use super::{
    PKCS7_ATTR_SIGN_it, PKCS7_ATTR_VERIFY_it, PKCS7_add0_attrib_signing_time,
    PKCS7_add1_attrib_digest, PKCS7_ctrl, PKCS7_digest_from_attributes, PKCS7_get_octet_string,
    PKCS7_get_signed_attribute, PKCS7_type_is_other, content_ptr, ctx_of, digest_of, enveloped_of,
    nid_obj, nid_of, other_of, p7_of, raise, sign_env_of, sign_of, type_nid,
};
use crate::asn1::ASN1_get_object;
use crate::asn1::integer::ASN1_INTEGER_cmp;
use crate::asn1::string::{
    ASN1_OCTET_STRING_dup, ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set,
    ASN1_STRING_set0,
};
use crate::asn1::tpl::encode::ASN1_item_i2d;
use crate::asn1::tpl::items::{ASN1_TYPE_free, ASN1_TYPE_new};
use crate::bio::evp::{BIO_f_cipher, BIO_f_md};
use crate::bio::mem::{BIO_new_mem_buf, BIO_s_mem};
use crate::bio::null::BIO_s_null;
use crate::bio::{
    BIO_ctrl, BIO_find_type, BIO_free, BIO_free_all, BIO_new, BIO_next, BIO_push, BIO_write,
};
use crate::err::{self, ERR_clear_error, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::asymcipher::{
    EVP_PKEY_decrypt, EVP_PKEY_decrypt_init, EVP_PKEY_encrypt, EVP_PKEY_encrypt_init,
};
use crate::evp::cipher::{
    EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_iv_length, EVP_CIPHER_get_key_length,
    EVP_CIPHER_get_type, EVP_CIPHER_get0_name,
};
use crate::evp::cipher_asn1::{EVP_CIPHER_asn1_to_param, EVP_CIPHER_param_to_asn1};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_rand_key, EVP_CIPHER_CTX_set_key_length,
    EVP_CipherInit_ex,
};
use crate::evp::digest::{
    EVP_MD_fetch, EVP_MD_free, EVP_MD_get_pkey_type, EVP_MD_get_type, EVP_MD_get0_name,
};
use crate::evp::legacy_cipher::EVP_get_cipherbyname;
use crate::evp::legacy_md::EVP_get_digestbyname;
use crate::evp::md_ctx::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_copy_ex, EVP_MD_CTX_free,
    EVP_MD_CTX_get0_md, EVP_MD_CTX_new,
};
use crate::evp::pkey::EVP_PKEY_get_size;
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey};
use crate::evp::sigver::{
    EVP_DigestSignFinal, EVP_DigestSignInit_ex, EVP_DigestSignUpdate, EVP_SignFinal_ex,
    EVP_VerifyFinal_ex,
};
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::{ASN1_OBJECT_free, OBJ_nid2sn, OBJ_obj2nid, OBJ_obj2txt};
use crate::rand_lib::RAND_bytes_ex;
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::x509::cert::{
    X509_find_by_issuer_and_serial, X509_get_issuer_name, X509_get0_pubkey, X509_get0_serialNumber,
};
use crate::x509::ctx::{X509_STORE_CTX_init, X509_STORE_CTX_set_purpose, X509_STORE_CTX_set0_crls};
use crate::x509::name::X509_NAME_cmp;
use crate::x509::verify::X509_verify_cert;

/// OpenSSL's `OSSL_MAX_NAME_SIZE`, the room for an algorithm's name.
const NAME_LEN: usize = 50;

/// A PKCS#7 context's library context and properties.
pub(super) fn ctx_parts(ctx: *const PKCS7_CTX) -> (*mut OSSL_LIB_CTX, *const c_char) {
    // SAFETY: NULL or a live object's context.
    unsafe { ctx.as_ref() }.map_or((ptr::null_mut(), ptr::null()), |c| {
        (c.libctx, c.propq.cast_const())
    })
}

/// `PKCS7_is_detached`: SignedData without its content, which `PKCS7_ctrl` records in the
/// object.
pub(super) fn is_detached(p7: *mut PKCS7) -> bool {
    type_nid(p7) == NID_pkcs7_signed
        // SAFETY: a live object.
        && unsafe { PKCS7_ctrl(p7, PKCS7_OP_GET_DETACHED_SIGNATURE, 0, ptr::null_mut()) } != 0
}

/// A new memory BIO that reads as EOF when empty, or NULL.
pub(super) fn mem_bio() -> *mut BIO {
    // SAFETY: no preconditions.
    let method = unsafe { BIO_s_mem() };
    // SAFETY: the built-in method.
    let b = unsafe { BIO_new(method) };
    if !b.is_null() {
        // SAFETY: a live memory BIO.
        unsafe { BIO_ctrl(b, BIO_C_SET_BUF_MEM_EOF_RETURN, 0, ptr::null_mut()) };
    }
    b
}

/// The algorithm's name as `OBJ_obj2txt` gives it, NUL-terminated.
fn name_of(obj: *const ASN1_OBJECT) -> [c_char; NAME_LEN] {
    let mut name = [0 as c_char; NAME_LEN];
    let len = c_int::try_from(NAME_LEN).unwrap_or(0);
    // SAFETY: room for `len` octets; the object, or NULL.
    unsafe { OBJ_obj2txt(name.as_mut_ptr(), len, obj, 0) };
    name
}

/// The digest named by `obj`: the provider's (to free), else the built-in table's.
fn fetch_md(
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
    obj: *const ASN1_OBJECT,
) -> Option<(*const EVP_MD, *mut EVP_MD)> {
    let name = name_of(obj);
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: a NUL-terminated name; the object's context and properties.
    let fetched = unsafe { EVP_MD_fetch(libctx, name.as_ptr(), propq) };
    let md = if fetched.is_null() {
        // SAFETY: as above.
        unsafe { EVP_get_digestbyname(name.as_ptr()) }
    } else {
        fetched.cast_const()
    };
    if md.is_null() {
        // SAFETY: no preconditions.
        unsafe { ERR_clear_last_mark() };
        return None;
    }
    // SAFETY: no preconditions.
    unsafe { ERR_pop_to_mark() };
    Some((md, fetched))
}

/// The cipher named by `obj`, as [`fetch_md`] finds a digest.
fn fetch_cipher(
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
    obj: *const ASN1_OBJECT,
) -> Option<(*const EVP_CIPHER, *mut EVP_CIPHER)> {
    let name = name_of(obj);
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: a NUL-terminated name; the object's context and properties.
    let fetched = unsafe { EVP_CIPHER_fetch(libctx, name.as_ptr(), propq) };
    let cipher = if fetched.is_null() {
        // SAFETY: as above.
        unsafe { EVP_get_cipherbyname(name.as_ptr()) }
    } else {
        fetched.cast_const()
    };
    if cipher.is_null() {
        // SAFETY: no preconditions.
        unsafe { ERR_clear_last_mark() };
        return None;
    }
    // SAFETY: no preconditions.
    unsafe { ERR_pop_to_mark() };
    Some((cipher, fetched))
}

/// The object of an algorithm identifier, NULL for none.
fn algorithm(alg: *const X509_ALGOR) -> *mut ASN1_OBJECT {
    // SAFETY: NULL or a live algorithm identifier.
    unsafe { alg.as_ref() }.map_or(ptr::null_mut(), |a| a.algorithm)
}

/// `pkcs7_bio_add_digest`: a digest BIO for `alg`, pushed on `*pbio`.
fn add_digest(
    pbio: &mut *mut BIO,
    alg: *const X509_ALGOR,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
    f: &str,
) -> bool {
    // SAFETY: no preconditions.
    let method = unsafe { BIO_f_md() };
    // SAFETY: the built-in method.
    let btmp = unsafe { BIO_new(method) };
    if btmp.is_null() {
        raise(ERR_R_BIO_LIB, f);
        return false;
    }
    let ok = 'err: {
        let Some((md, fetched)) = fetch_md(libctx, propq, algorithm(alg)) else {
            raise(PKCS7_R_UNKNOWN_DIGEST_TYPE, f);
            break 'err false;
        };
        // SAFETY: a live digest BIO; a live digest.
        let set = unsafe { BIO_ctrl(btmp, BIO_C_SET_MD, 0, md.cast_mut().cast()) };
        // SAFETY: the fetched digest, or NULL; the BIO holds its own reference.
        unsafe { EVP_MD_free(fetched) };
        if set <= 0 {
            raise(ERR_R_BIO_LIB, f);
            break 'err false;
        }
        if pbio.is_null() {
            *pbio = btmp;
        // SAFETY: live BIOs; the chain takes the new one.
        } else if unsafe { BIO_push(*pbio, btmp) }.is_null() {
            raise(ERR_R_BIO_LIB, f);
            break 'err false;
        }
        true
    };
    if !ok {
        // SAFETY: the BIO made here, in no chain.
        unsafe { BIO_free(btmp) };
    }
    ok
}

/// The BIO's cipher context.
fn cipher_ctx(b: *mut BIO) -> *mut EVP_CIPHER_CTX {
    let mut ctx: *mut EVP_CIPHER_CTX = ptr::null_mut();
    // SAFETY: a live cipher BIO; room for the pointer.
    unsafe { BIO_ctrl(b, BIO_C_GET_CIPHER_CTX, 0, (&raw mut ctx).cast()) };
    ctx
}

/// The BIO's digest context.
fn md_ctx(b: *mut BIO) -> *mut EVP_MD_CTX {
    let mut ctx: *mut EVP_MD_CTX = ptr::null_mut();
    // SAFETY: a live digest BIO; room for the pointer.
    unsafe { BIO_ctrl(b, BIO_C_GET_MD_CTX, 0, (&raw mut ctx).cast()) };
    ctx
}

/// An OCTET STRING's octets, empty for NULL or none.
///
/// # Safety
/// `os` is NULL or a live string, unchanged while the slice lives.
unsafe fn octets<'a>(os: *const ASN1_OCTET_STRING) -> &'a [u8] {
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { os.as_ref() }) else {
        return &[];
    };
    match usize::try_from(s.length) {
        // SAFETY: a live string's `length` octets.
        Ok(n) if n > 0 && !s.data.is_null() => unsafe { core::slice::from_raw_parts(s.data, n) },
        _ => &[],
    }
}

/// `pkcs7_get1_data`: a copy of the content's octets (empty for an indefinite-length string),
/// or of an other type's SEQUENCE's contents; NULL for neither.
///
/// # Safety
/// `p7` is NULL or a live PKCS#7 object.
unsafe fn get1_data(p7: *mut PKCS7) -> *mut ASN1_OCTET_STRING {
    // SAFETY: the caller's guarantee.
    let os = unsafe { PKCS7_get_octet_string(p7) };
    if !os.is_null() {
        // SAFETY: a live string.
        let dup = unsafe { ASN1_OCTET_STRING_dup(os) };
        // SAFETY: as above.
        if !dup.is_null() && unsafe { (*os).flags } & c_long::from(ASN1_STRING_FLAG_NDEF) != 0 {
            // SAFETY: the copy, ours.
            unsafe { ASN1_STRING_set0(dup, ptr::null_mut(), 0) };
        }
        return dup;
    }
    // SAFETY: the caller's guarantee.
    let Some(p) = (unsafe { p7.as_ref() }) else {
        return ptr::null_mut();
    };
    // SAFETY: as above.
    if unsafe { PKCS7_type_is_other(p7) } == 0 {
        return ptr::null_mut();
    }
    let Some(o) = other_of(p).filter(|o| o.type_ == V_ASN1_SEQUENCE) else {
        return ptr::null_mut();
    };
    // SAFETY: a SEQUENCE's member.
    let seq = unsafe { o.value.sequence };
    // SAFETY: NULL or a live string.
    let Some(s) = (unsafe { seq.as_ref() }).filter(|s| s.length > 0) else {
        return ptr::null_mut();
    };
    // SAFETY: no preconditions.
    let out = unsafe { ASN1_OCTET_STRING_new() };
    if out.is_null() {
        return ptr::null_mut();
    }
    let mut data = s.data.cast_const();
    let (mut len, mut tag, mut class) = (0 as c_long, 0, 0);
    // SAFETY: the string's `length` octets; room for the results.
    let inf = unsafe {
        ASN1_get_object(
            &mut data,
            &mut len,
            &mut tag,
            &mut class,
            c_long::from(s.length),
        )
    };
    let ok = inf == V_ASN1_CONSTRUCTED
        && tag == V_ASN1_SEQUENCE
        && c_int::try_from(len).is_ok_and(|n| {
            // SAFETY: the contents `ASN1_get_object` found within the string.
            unsafe { ASN1_OCTET_STRING_set(out, data, n) != 0 }
        });
    if !ok {
        // SAFETY: the string made here.
        unsafe { ASN1_OCTET_STRING_free(out) };
        return ptr::null_mut();
    }
    out
}

/// `pkcs7_encode_rinfo`: the content key, encrypted to the recipient's certificate.
///
/// # Safety
/// `ri` is a live recipient info.
unsafe fn encode_rinfo(ri: &mut PKCS7_RECIP_INFO, key: &[u8]) -> bool {
    // SAFETY: the recipient's certificate, or NULL.
    let pkey = unsafe { X509_get0_pubkey(ri.cert) };
    if pkey.is_null() {
        return false;
    }
    let (libctx, propq) = ctx_parts(ri.ctx);
    // SAFETY: a live key; the context and properties, or NULL.
    let pctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq) };
    if pctx.is_null() {
        return false;
    }
    let mut ek: *mut u8 = ptr::null_mut();
    let ok = 'err: {
        // SAFETY: a live context.
        if unsafe { EVP_PKEY_encrypt_init(pctx) } <= 0 {
            break 'err false;
        }
        let mut eklen = 0usize;
        // SAFETY: as above; the key's octets; room for the length.
        if unsafe { EVP_PKEY_encrypt(pctx, ptr::null_mut(), &mut eklen, key.as_ptr(), key.len()) }
            <= 0
        {
            break 'err false;
        }
        ek = mem::alloc(eklen).cast();
        if ek.is_null() {
            break 'err false;
        }
        // SAFETY: as above; `eklen` octets of room.
        if unsafe { EVP_PKEY_encrypt(pctx, ek, &mut eklen, key.as_ptr(), key.len()) } <= 0 {
            break 'err false;
        }
        let Ok(n) = c_int::try_from(eklen) else {
            break 'err false;
        };
        // SAFETY: the recipient's string takes the buffer, from CRYPTO_malloc.
        unsafe { ASN1_STRING_set0(ri.enc_key, ek.cast(), n) };
        ek = ptr::null_mut();
        true
    };
    // SAFETY: the context made here.
    unsafe { EVP_PKEY_CTX_free(pctx) };
    // SAFETY: NULL, or the buffer allocated here and not handed on.
    unsafe { mem::release(ek.cast()) };
    ok
}

/// `pkcs7_decrypt_rinfo`: the recipient's content key into `ek` (1), a failed decryption (0,
/// `ek` unchanged), or a failure to try (-1).
///
/// # Safety
/// `ri` is a live recipient info; `pkey` is NULL or a live key.
unsafe fn decrypt_rinfo(
    ek: &mut Option<Zeroizing<Vec<u8>>>,
    ri: &PKCS7_RECIP_INFO,
    pkey: *mut EVP_PKEY,
    fixlen: usize,
) -> c_int {
    let (libctx, propq) = ctx_parts(ri.ctx);
    // SAFETY: the caller's key, or NULL; the context and properties, or NULL.
    let pctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq) };
    if pctx.is_null() {
        return -1;
    }
    // SAFETY: the recipient's encrypted key.
    let input = unsafe { octets(ri.enc_key) };
    let ret = 'out: {
        // SAFETY: a live context.
        if unsafe { EVP_PKEY_decrypt_init(pctx) } <= 0 {
            break 'out -1;
        }
        let mut outlen = 0usize;
        // SAFETY: as above; the input's octets; room for the length.
        if unsafe {
            EVP_PKEY_decrypt(
                pctx,
                ptr::null_mut(),
                &mut outlen,
                input.as_ptr(),
                input.len(),
            )
        } <= 0
        {
            break 'out -1;
        }
        let mut out = Zeroizing::new(vec![0u8; outlen]);
        // SAFETY: as above; `outlen` octets of room.
        let r = unsafe {
            EVP_PKEY_decrypt(
                pctx,
                out.as_mut_ptr(),
                &mut outlen,
                input.as_ptr(),
                input.len(),
            )
        };
        if r <= 0 || outlen == 0 || (fixlen != 0 && outlen != fixlen) {
            err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, "evp_pkey_decrypt_alloc");
            break 'out 0;
        }
        out.truncate(outlen);
        *ek = Some(out);
        1
    };
    // SAFETY: the context made here.
    unsafe { EVP_PKEY_CTX_free(pctx) };
    ret
}

ffi_export! {
    /// Starts a content's BIO chain for writing: a digest BIO per digest algorithm, a cipher BIO
    /// with a new content key (encrypted to each recipient) for enveloped types, over `bio` or a
    /// new memory BIO (a null BIO if the content is detached). NULL on failure.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object; `bio` is NULL or a live BIO.
    pub unsafe extern "C" fn PKCS7_dataInit(p7: *mut PKCS7, bio: *mut BIO) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        const F: &str = "PKCS7_dataInit";
        // Read through the pointer before the object is borrowed.
        let (libctx, propq) = ctx_parts(ctx_of(p7));
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p7_of(p7) }) else {
            raise(PKCS7_R_INVALID_NULL_POINTER, F);
            return ptr::null_mut();
        };
        if content_ptr(p).is_null() {
            raise(PKCS7_R_NO_CONTENT, F);
            return ptr::null_mut();
        }
        let nid = nid_of(p);
        p.state = PKCS7_S_HEADER;
        let mut md_sk: *mut stack_st_X509_ALGOR = ptr::null_mut();
        let mut xa: *mut X509_ALGOR = ptr::null_mut();
        let mut os: *mut ASN1_OCTET_STRING = ptr::null_mut();
        let mut rsk: *mut c_void = ptr::null_mut();
        let mut xalg: *mut X509_ALGOR = ptr::null_mut();
        let mut evp_cipher: *const EVP_CIPHER = ptr::null();
        let mut out: *mut BIO = ptr::null_mut();
        let mut btmp: *mut BIO = ptr::null_mut();
        let mut fetched: *mut EVP_CIPHER = ptr::null_mut();
        let ok = 'err: {
            match nid {
                n if n == NID_pkcs7_signed => {
                    if let Some(s) = sign_of(p) {
                        md_sk = s.md_algs;
                        // SAFETY: the content, NULL or live.
                        os = unsafe { get1_data(s.contents) };
                    }
                }
                n if n == NID_pkcs7_signedAndEnveloped || n == NID_pkcs7_enveloped => {
                    let enc = if n == NID_pkcs7_enveloped {
                        enveloped_of(p).map(|e| {
                            rsk = e.recipientinfo.cast();
                            e.enc_data
                        })
                    } else {
                        sign_env_of(p).map(|e| {
                            rsk = e.recipientinfo.cast();
                            md_sk = e.md_algs;
                            e.enc_data
                        })
                    };
                    // SAFETY: the content's encrypted content, NULL or live.
                    let Some(ec) = enc.and_then(|e| unsafe { e.as_mut() }) else {
                        raise(PKCS7_R_CIPHER_NOT_INITIALIZED, F);
                        break 'err false;
                    };
                    xalg = ec.algorithm;
                    evp_cipher = ec.cipher;
                    if evp_cipher.is_null() {
                        raise(PKCS7_R_CIPHER_NOT_INITIALIZED, F);
                        break 'err false;
                    }
                }
                n if n == NID_pkcs7_digest => {
                    if let Some(d) = digest_of(p) {
                        xa = d.md;
                        // SAFETY: the content, NULL or live.
                        os = unsafe { get1_data(d.contents) };
                    }
                }
                n if n == NID_pkcs7_data => {}
                _ => {
                    raise(PKCS7_R_UNSUPPORTED_CONTENT_TYPE, F);
                    break 'err false;
                }
            }
            // SAFETY: the content's digest algorithms, or NULL.
            for i in 0..unsafe { OPENSSL_sk_num(md_sk.cast()) } {
                // SAFETY: an index within them.
                let alg = unsafe { OPENSSL_sk_value(md_sk.cast(), i) }.cast::<X509_ALGOR>();
                if !add_digest(&mut out, alg, libctx, propq, F) {
                    break 'err false;
                }
            }
            if !xa.is_null() && !add_digest(&mut out, xa, libctx, propq, F) {
                break 'err false;
            }
            if !evp_cipher.is_null() {
                // SAFETY: no preconditions.
                let method = unsafe { BIO_f_cipher() };
                // SAFETY: the built-in method.
                btmp = unsafe { BIO_new(method) };
                if btmp.is_null() {
                    raise(ERR_R_BIO_LIB, F);
                    break 'err false;
                }
                let ctx = cipher_ctx(btmp);
                // SAFETY: a live cipher.
                let keylen = unsafe { EVP_CIPHER_get_key_length(evp_cipher) };
                // SAFETY: as above.
                let ivlen = unsafe { EVP_CIPHER_get_iv_length(evp_cipher) };
                // SAFETY: as above.
                let obj = nid_obj(unsafe { EVP_CIPHER_get_type(evp_cipher) });
                // SAFETY: the encrypted content's algorithm, live.
                let a = unsafe { &mut *xalg };
                // SAFETY: the algorithm's object, which it owns; a static one is never freed.
                unsafe { ASN1_OBJECT_free(a.algorithm) };
                a.algorithm = obj;
                let mut iv = [0u8; EVP_MAX_IV_LENGTH as usize];
                let Some(iv_used) = usize::try_from(ivlen).ok().and_then(|n| iv.get_mut(..n)) else {
                    break 'err false;
                };
                // SAFETY: room for the IV.
                if !iv_used.is_empty() && unsafe { RAND_bytes_ex(libctx, iv_used.as_mut_ptr(), iv_used.len(), 0) } <= 0 {
                    break 'err false;
                }
                // SAFETY: no preconditions.
                unsafe { ERR_set_mark() };
                // SAFETY: a live cipher.
                let cname = unsafe { EVP_CIPHER_get0_name(evp_cipher) };
                // SAFETY: the cipher's name; the object's context and properties.
                fetched = unsafe { EVP_CIPHER_fetch(libctx, cname, propq) };
                // SAFETY: no preconditions.
                unsafe { ERR_pop_to_mark() };
                let cipher = if fetched.is_null() { evp_cipher } else { fetched.cast_const() };
                // SAFETY: the BIO's context; a live cipher.
                if unsafe { EVP_CipherInit_ex(ctx, cipher, ptr::null_mut(), ptr::null(), ptr::null(), 1) } <= 0 {
                    break 'err false;
                }
                // SAFETY: the fetched cipher; the context holds its own reference.
                unsafe { EVP_CIPHER_free(fetched) };
                fetched = ptr::null_mut();
                let mut key = Zeroizing::new([0u8; EVP_MAX_KEY_LENGTH as usize]);
                // SAFETY: room for any cipher's key.
                if unsafe { EVP_CIPHER_CTX_rand_key(ctx, key.as_mut_ptr()) } <= 0 {
                    break 'err false;
                }
                // SAFETY: the key and the IV, each as long as the cipher's.
                if unsafe { EVP_CipherInit_ex(ctx, ptr::null(), ptr::null_mut(), key.as_ptr(), iv.as_ptr(), 1) } <= 0 {
                    break 'err false;
                }
                if ivlen > 0 {
                    if a.parameter.is_null() {
                        // SAFETY: no preconditions.
                        a.parameter = unsafe { ASN1_TYPE_new() };
                        if a.parameter.is_null() {
                            break 'err false;
                        }
                    }
                    // SAFETY: the context; the algorithm's parameter.
                    if unsafe { EVP_CIPHER_param_to_asn1(ctx, a.parameter) } <= 0 {
                        // SAFETY: the parameter, the algorithm's.
                        unsafe { ASN1_TYPE_free(a.parameter) };
                        a.parameter = ptr::null_mut();
                        break 'err false;
                    }
                }
                let Some(k) = usize::try_from(keylen).ok().and_then(|n| key.get(..n)) else {
                    break 'err false;
                };
                // SAFETY: the content's recipients, or NULL.
                for i in 0..unsafe { OPENSSL_sk_num(rsk.cast()) } {
                    // SAFETY: an index within them.
                    let ri = unsafe { OPENSSL_sk_value(rsk.cast(), i) }.cast::<PKCS7_RECIP_INFO>();
                    // SAFETY: a recipient of the object.
                    let Some(r) = (unsafe { ri.as_mut() }) else {
                        break 'err false;
                    };
                    // SAFETY: as above.
                    if !unsafe { encode_rinfo(r, k) } {
                        break 'err false;
                    }
                }
                if out.is_null() {
                    out = btmp;
                } else {
                    // SAFETY: live BIOs; the chain takes the cipher BIO.
                    unsafe { BIO_push(out, btmp) };
                }
                btmp = ptr::null_mut();
            }
            let mut bio = bio;
            if bio.is_null() {
                if is_detached(p7) {
                    // SAFETY: no preconditions.
                    let method = unsafe { BIO_s_null() };
                    // SAFETY: the built-in method.
                    bio = unsafe { BIO_new(method) };
                } else {
                    bio = mem_bio();
                    // SAFETY: the copy made here, or NULL.
                    let data = unsafe { octets(os) };
                    if !bio.is_null() && !data.is_empty() {
                        let n = c_int::try_from(data.len()).unwrap_or(c_int::MAX);
                        // SAFETY: a live BIO; the copy's octets.
                        if unsafe { BIO_write(bio, data.as_ptr().cast(), n) } != n {
                            // SAFETY: the BIO made here.
                            unsafe { BIO_free_all(bio) };
                            bio = ptr::null_mut();
                        }
                    }
                }
                if bio.is_null() {
                    break 'err false;
                }
            }
            if out.is_null() {
                out = bio;
            } else {
                // SAFETY: live BIOs; the chain takes the caller's or the new one.
                unsafe { BIO_push(out, bio) };
            }
            true
        };
        // SAFETY: the copy made here, or NULL.
        unsafe { ASN1_OCTET_STRING_free(os) };
        if ok {
            return out;
        }
        // SAFETY: the fetched cipher, or NULL.
        unsafe { EVP_CIPHER_free(fetched) };
        // SAFETY: the chain built here, or NULL.
        unsafe { BIO_free_all(out) };
        // SAFETY: the cipher BIO not yet in it, or NULL.
        unsafe { BIO_free_all(btmp) };
        ptr::null_mut()
    }
}

/// `pkcs7_cmp_ri`: whether the recipient is the certificate's issuer and serial number.
///
/// # Safety
/// `ri` is a live recipient info; `pcert` a live certificate.
unsafe fn recipient_is(ri: &PKCS7_RECIP_INFO, pcert: *mut X509) -> bool {
    // SAFETY: the recipient's issuer and serial, or NULL.
    let Some(ias) = (unsafe { ri.issuer_and_serial.as_ref() }) else {
        return false;
    };
    // SAFETY: the caller's certificate.
    let issuer = unsafe { X509_get_issuer_name(pcert) };
    // SAFETY: live names.
    if unsafe { X509_NAME_cmp(ias.issuer, issuer) } != 0 {
        return false;
    }
    // SAFETY: as above.
    let serial = unsafe { X509_get0_serialNumber(pcert) };
    // SAFETY: live integers.
    unsafe { ASN1_INTEGER_cmp(serial, ias.serial) == 0 }
}

ffi_export! {
    /// Starts a content's BIO chain for reading: a digest BIO per digest algorithm, a cipher
    /// BIO keyed by `pkey`'s recipient info (that of `pcert`, or any), over `in_bio` or the
    /// object's own content. NULL on failure.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object; `pkey`, `in_bio`, and `pcert` are NULL or live.
    pub unsafe extern "C" fn PKCS7_dataDecode(p7: *mut PKCS7, pkey: *mut EVP_PKEY, in_bio: *mut BIO, pcert: *mut X509) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        const F: &str = "PKCS7_dataDecode";
        // Read through the pointer before the object is borrowed.
        let p7_ctx = ctx_of(p7);
        let (libctx, propq) = ctx_parts(p7_ctx);
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p7_of(p7) }) else {
            raise(PKCS7_R_INVALID_NULL_POINTER, F);
            return ptr::null_mut();
        };
        if content_ptr(p).is_null() {
            raise(PKCS7_R_NO_CONTENT, F);
            return ptr::null_mut();
        }
        let nid = nid_of(p);
        p.state = PKCS7_S_HEADER;
        let data_body: *mut ASN1_OCTET_STRING;
        let mut md_sk: *mut stack_st_X509_ALGOR = ptr::null_mut();
        let mut rsk: *mut c_void = ptr::null_mut();
        let mut enc_alg: *mut X509_ALGOR = ptr::null_mut();
        let mut cipher: *const EVP_CIPHER = ptr::null();
        let mut evp_cipher: *mut EVP_CIPHER = ptr::null_mut();
        let mut out: *mut BIO = ptr::null_mut();
        let mut etmp: *mut BIO = ptr::null_mut();
        let mut bio: *mut BIO = ptr::null_mut();
        let ok = 'err: {
            match nid {
                n if n == NID_pkcs7_signed => {
                    let (contents, algs) = sign_of(p).map_or((ptr::null_mut(), ptr::null_mut()), |s| (s.contents, s.md_algs));
                    // SAFETY: the content, NULL or live.
                    data_body = unsafe { PKCS7_get_octet_string(contents) };
                    if !is_detached(p7) && data_body.is_null() {
                        raise(PKCS7_R_INVALID_SIGNED_DATA_TYPE, F);
                        break 'err false;
                    }
                    md_sk = algs;
                }
                n if n == NID_pkcs7_signedAndEnveloped || n == NID_pkcs7_enveloped => {
                    let enc = if n == NID_pkcs7_enveloped {
                        enveloped_of(p).map(|e| {
                            rsk = e.recipientinfo.cast();
                            e.enc_data
                        })
                    } else {
                        sign_env_of(p).map(|e| {
                            rsk = e.recipientinfo.cast();
                            md_sk = e.md_algs;
                            e.enc_data
                        })
                    };
                    // SAFETY: the content's encrypted content, NULL or live.
                    let ec = enc.and_then(|e| unsafe { e.as_ref() });
                    data_body = ec.map_or(ptr::null_mut(), |e| e.enc_data);
                    enc_alg = ec.map_or(ptr::null_mut(), |e| e.algorithm);
                    let Some((c, f)) = fetch_cipher(libctx, propq, algorithm(enc_alg)) else {
                        raise(PKCS7_R_UNSUPPORTED_CIPHER_TYPE, F);
                        break 'err false;
                    };
                    cipher = c;
                    evp_cipher = f;
                }
                _ => {
                    raise(PKCS7_R_UNSUPPORTED_CONTENT_TYPE, F);
                    break 'err false;
                }
            }
            if data_body.is_null() && in_bio.is_null() {
                raise(PKCS7_R_NO_CONTENT, F);
                break 'err false;
            }
            // SAFETY: the content's digest algorithms, or NULL.
            for i in 0..unsafe { OPENSSL_sk_num(md_sk.cast()) } {
                // SAFETY: an index within them.
                let alg = unsafe { OPENSSL_sk_value(md_sk.cast(), i) }.cast::<X509_ALGOR>();
                if !add_digest(&mut out, alg, libctx, propq, F) {
                    break 'err false;
                }
            }
            if !cipher.is_null() {
                // SAFETY: no preconditions.
                let method = unsafe { BIO_f_cipher() };
                // SAFETY: the built-in method.
                etmp = unsafe { BIO_new(method) };
                if etmp.is_null() {
                    raise(ERR_R_BIO_LIB, F);
                    break 'err false;
                }
                let mut ek: Option<Zeroizing<Vec<u8>>> = None;
                // SAFETY: the content's recipients, or NULL.
                let count = unsafe { OPENSSL_sk_num(rsk.cast()) };
                let recipient = |i: c_int| {
                    // SAFETY: an index within them.
                    let ri = unsafe { OPENSSL_sk_value(rsk.cast(), i) }.cast::<PKCS7_RECIP_INFO>();
                    // SAFETY: a recipient of the object, or NULL.
                    unsafe { ri.as_mut() }
                };
                if pcert.is_null() {
                    // SAFETY: a live cipher.
                    let fixlen = usize::try_from(unsafe { EVP_CIPHER_get_key_length(cipher) }).unwrap_or(0);
                    for i in 0..count {
                        let Some(ri) = recipient(i) else { continue };
                        ri.ctx = p7_ctx;
                        // SAFETY: a live recipient; the caller's key.
                        if unsafe { decrypt_rinfo(&mut ek, ri, pkey, fixlen) } < 0 {
                            break 'err false;
                        }
                        // SAFETY: no preconditions.
                        unsafe { ERR_clear_error() };
                    }
                } else {
                    // SAFETY: live recipients; the caller's certificate.
                    let Some(ri) = (0..count).filter_map(recipient).find(|ri| unsafe { recipient_is(ri, pcert) }) else {
                        raise(PKCS7_R_NO_RECIPIENT_MATCHES_CERTIFICATE, F);
                        break 'err false;
                    };
                    ri.ctx = p7_ctx;
                    // SAFETY: as above.
                    if unsafe { decrypt_rinfo(&mut ek, ri, pkey, 0) } < 0 {
                        break 'err false;
                    }
                    // SAFETY: no preconditions.
                    unsafe { ERR_clear_error() };
                }
                let ctx = cipher_ctx(etmp);
                // SAFETY: the BIO's context; a live cipher.
                if unsafe { EVP_CipherInit_ex(ctx, cipher, ptr::null_mut(), ptr::null(), ptr::null(), 0) } <= 0 {
                    break 'err false;
                }
                // SAFETY: the context; the algorithm's parameter, or NULL.
                let param = unsafe { enc_alg.as_ref() }.map_or(ptr::null_mut(), |a| a.parameter);
                // SAFETY: as above.
                if unsafe { EVP_CIPHER_asn1_to_param(ctx, param) } <= 0 {
                    break 'err false;
                }
                // SAFETY: as above.
                let len = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) };
                let Some(len) = usize::try_from(len).ok().filter(|&n| n > 0) else {
                    break 'err false;
                };
                // A random key stands in for one that failed to decrypt.
                let mut tkey = Zeroizing::new(vec![0u8; len]);
                // SAFETY: room for the context's key.
                if unsafe { EVP_CIPHER_CTX_rand_key(ctx, tkey.as_mut_ptr()) } <= 0 {
                    break 'err false;
                }
                let mut key = ek.take().unwrap_or_else(|| tkey.clone());
                if key.len() != len {
                    let n = c_int::try_from(key.len()).unwrap_or(c_int::MAX);
                    // SAFETY: as above.
                    if unsafe { EVP_CIPHER_CTX_set_key_length(ctx, n) } <= 0 {
                        key = tkey.clone();
                    }
                }
                // SAFETY: no preconditions.
                unsafe { ERR_clear_error() };
                // SAFETY: as above; a key as long as the context's.
                if unsafe { EVP_CipherInit_ex(ctx, ptr::null(), ptr::null_mut(), key.as_ptr(), ptr::null(), 0) } <= 0 {
                    break 'err false;
                }
                if out.is_null() {
                    out = etmp;
                } else {
                    // SAFETY: live BIOs; the chain takes the cipher BIO.
                    unsafe { BIO_push(out, etmp) };
                }
                etmp = ptr::null_mut();
            }
            if in_bio.is_null() {
                // SAFETY: the object's content, live.
                let data = unsafe { octets(data_body) };
                if data.is_empty() {
                    bio = mem_bio();
                } else {
                    let n = c_int::try_from(data.len()).unwrap_or(c_int::MAX);
                    // SAFETY: the content's octets, which outlive the BIO's use of them.
                    bio = unsafe { BIO_new_mem_buf(data.as_ptr().cast(), n) };
                }
                if bio.is_null() {
                    break 'err false;
                }
            } else {
                bio = in_bio;
            }
            true
        };
        // SAFETY: the fetched cipher, or NULL; the BIO holds its own reference.
        unsafe { EVP_CIPHER_free(evp_cipher) };
        if ok {
            if out.is_null() {
                // OpenSSL's `BIO_push(NULL, bio)` returns NULL with no error.
                if bio != in_bio {
                    // SAFETY: the BIO made here.
                    unsafe { BIO_free_all(bio) };
                }
                return ptr::null_mut();
            }
            // SAFETY: live BIOs; the chain takes the content's BIO.
            unsafe { BIO_push(out, bio) };
            return out;
        }
        // SAFETY: the chain built here, or NULL.
        unsafe { BIO_free_all(out) };
        // SAFETY: the cipher BIO not yet in it, or NULL.
        unsafe { BIO_free_all(etmp) };
        ptr::null_mut()
    }
}

/// `PKCS7_find_digest`: the first digest BIO from `bio` on with a digest of type `nid`, and its
/// context.
fn find_digest(bio: *mut BIO, nid: c_int, f: &str) -> Option<(*mut BIO, *mut EVP_MD_CTX)> {
    let mut bio = bio;
    loop {
        // SAFETY: a live chain.
        bio = unsafe { BIO_find_type(bio, BIO_TYPE_MD) };
        if bio.is_null() {
            raise(PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST, f);
            return None;
        }
        let ctx = md_ctx(bio);
        if ctx.is_null() {
            raise(ERR_R_INTERNAL_ERROR, f);
            return None;
        }
        if md_ctx_type(ctx) == nid {
            return Some((bio, ctx));
        }
        // SAFETY: a live BIO.
        bio = unsafe { BIO_next(bio) };
    }
}

/// `EVP_MD_CTX_get_type`.
fn md_ctx_type(ctx: *const EVP_MD_CTX) -> c_int {
    // SAFETY: a live context.
    let md = unsafe { EVP_MD_CTX_get0_md(ctx) };
    // SAFETY: its digest, or NULL.
    unsafe { EVP_MD_get_type(md) }
}

/// `do_pkcs7_signed_attrib`: the signing time (unless set), the digest, and the signature.
///
/// # Safety
/// `si` is a live signer info; `mctx` a live digest context.
unsafe fn signed_attrib(si: *mut PKCS7_SIGNER_INFO, mctx: *mut EVP_MD_CTX, f: &str) -> bool {
    // SAFETY: the caller's guarantee.
    if unsafe { PKCS7_get_signed_attribute(si, NID_pkcs9_signingTime) }.is_null()
        // SAFETY: as above.
        && unsafe { PKCS7_add0_attrib_signing_time(si, ptr::null_mut()) } == 0
    {
        raise(ERR_R_PKCS7_LIB, f);
        return false;
    }
    let mut md = [0u8; EVP_MAX_MD_SIZE as usize];
    let mut len: c_uint = 0;
    // SAFETY: as above; room for any digest.
    if unsafe { EVP_DigestFinal_ex(mctx, md.as_mut_ptr(), &mut len) } == 0 {
        raise(ERR_R_EVP_LIB, f);
        return false;
    }
    let n = c_int::try_from(len).unwrap_or(0);
    // SAFETY: as above; the digest's `len` octets.
    if unsafe { PKCS7_add1_attrib_digest(si, md.as_ptr(), n) } == 0 {
        raise(ERR_R_PKCS7_LIB, f);
        return false;
    }
    // SAFETY: as above.
    unsafe { PKCS7_SIGNER_INFO_sign(si) != 0 }
}

/// The memory BIO's contents.
fn mem_contents(b: *mut BIO) -> &'static [u8] {
    let mut cont: *mut c_char = ptr::null_mut();
    // SAFETY: a live memory BIO; room for the pointer.
    let len = unsafe { BIO_ctrl(b, BIO_CTRL_INFO, 0, (&raw mut cont).cast()) };
    match usize::try_from(len) {
        // SAFETY: the BIO's `len` octets, read before it changes.
        Ok(n) if n > 0 && !cont.is_null() => unsafe { core::slice::from_raw_parts(cont.cast(), n) },
        _ => &[],
    }
}

ffi_export! {
    /// Finishes an object from the chain `PKCS7_dataInit` started: signs each signer info that
    /// has a key with its digest BIO's digest (or sets the DigestedData's digest), and stores
    /// the content written unless it is detached. 1, or 0.
    ///
    /// # Safety
    /// `p7` is NULL or a live PKCS#7 object; `bio` is the chain made for it.
    pub unsafe extern "C" fn PKCS7_dataFinal(p7: *mut PKCS7, bio: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        const F: &str = "PKCS7_dataFinal";
        // Read through the pointer before the object is borrowed.
        let (libctx, propq) = ctx_parts(ctx_of(p7));
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p7_of(p7) }) else {
            raise(PKCS7_R_INVALID_NULL_POINTER, F);
            return 0;
        };
        if content_ptr(p).is_null() {
            raise(PKCS7_R_NO_CONTENT, F);
            return 0;
        }
        // SAFETY: no preconditions.
        let ctx_tmp = unsafe { EVP_MD_CTX_new() };
        if ctx_tmp.is_null() {
            raise(ERR_R_EVP_LIB, F);
            return 0;
        }
        let nid = nid_of(p);
        p.state = PKCS7_S_HEADER;
        let ok = 'err: {
            let mut si_sk: *mut c_void = ptr::null_mut();
            let os: *mut ASN1_OCTET_STRING = match nid {
                // SAFETY: the content of its type.
                n if n == NID_pkcs7_data => unsafe { p.d.data },
                n if n == NID_pkcs7_signedAndEnveloped || n == NID_pkcs7_enveloped => {
                    let enc = if n == NID_pkcs7_enveloped {
                        enveloped_of(p).map(|e| e.enc_data)
                    } else {
                        sign_env_of(p).map(|e| {
                            si_sk = e.signer_info.cast();
                            e.enc_data
                        })
                    };
                    // SAFETY: the content's encrypted content, NULL or live.
                    let Some(ec) = enc.and_then(|e| unsafe { e.as_mut() }) else {
                        raise(PKCS7_R_NO_CONTENT, F);
                        break 'err false;
                    };
                    if ec.enc_data.is_null() {
                        // SAFETY: no preconditions.
                        ec.enc_data = unsafe { ASN1_OCTET_STRING_new() };
                        if ec.enc_data.is_null() {
                            raise(ERR_R_ASN1_LIB, F);
                            break 'err false;
                        }
                    }
                    ec.enc_data
                }
                n if n == NID_pkcs7_signed || n == NID_pkcs7_digest => {
                    let contents = if n == NID_pkcs7_signed {
                        sign_of(p).map_or(ptr::null_mut(), |s| {
                            si_sk = s.signer_info.cast();
                            s.contents
                        })
                    } else {
                        digest_of(p).map_or(ptr::null_mut(), |d| d.contents)
                    };
                    if contents.is_null() {
                        raise(PKCS7_R_NO_CONTENT, F);
                        break 'err false;
                    }
                    // SAFETY: the content, live.
                    let mut o = unsafe { PKCS7_get_octet_string(contents) };
                    if type_nid(contents) == NID_pkcs7_data && p.detached != 0 {
                        // SAFETY: the content's data, its own.
                        unsafe { ASN1_OCTET_STRING_free(o) };
                        o = ptr::null_mut();
                        // SAFETY: as above.
                        let c = unsafe { &mut *contents };
                        c.d.data = ptr::null_mut();
                    }
                    o
                }
                _ => {
                    raise(PKCS7_R_UNSUPPORTED_CONTENT_TYPE, F);
                    break 'err false;
                }
            };
            if !si_sk.is_null() {
                // SAFETY: the content's signer infos.
                for i in 0..unsafe { OPENSSL_sk_num(si_sk.cast()) } {
                    // SAFETY: an index within them.
                    let si = unsafe { OPENSSL_sk_value(si_sk.cast(), i) }.cast::<PKCS7_SIGNER_INFO>();
                    // SAFETY: a signer info of the object.
                    let Some(s) = (unsafe { si.as_mut() }) else { continue };
                    if s.pkey.is_null() {
                        continue;
                    }
                    // SAFETY: its digest algorithm's object, or NULL.
                    let j = unsafe { OBJ_obj2nid(algorithm(s.digest_alg)) };
                    let Some((_, mdc)) = find_digest(bio, j, F) else {
                        break 'err false;
                    };
                    // SAFETY: live digest contexts.
                    if unsafe { EVP_MD_CTX_copy_ex(ctx_tmp, mdc) } == 0 {
                        break 'err false;
                    }
                    // SAFETY: the signer's attributes, or NULL.
                    if unsafe { OPENSSL_sk_num(s.auth_attr.cast()) } > 0 {
                        // SAFETY: as above.
                        if !unsafe { signed_attrib(si, ctx_tmp, F) } {
                            break 'err false;
                        }
                    } else {
                        // SAFETY: the signer's key.
                        let size = unsafe { EVP_PKEY_get_size(s.pkey) };
                        let Some(size) = usize::try_from(size).ok().filter(|&n| n > 0) else {
                            break 'err false;
                        };
                        let abuf = mem::alloc(size).cast::<u8>();
                        if abuf.is_null() {
                            break 'err false;
                        }
                        let mut abuflen = c_uint::try_from(size).unwrap_or(0);
                        // SAFETY: the digest; room for the key's signatures; the signer's key.
                        if unsafe { EVP_SignFinal_ex(ctx_tmp, abuf, &mut abuflen, s.pkey, libctx, propq) } == 0 {
                            // SAFETY: the buffer allocated here.
                            unsafe { mem::release(abuf.cast()) };
                            raise(ERR_R_EVP_LIB, F);
                            break 'err false;
                        }
                        let n = c_int::try_from(abuflen).unwrap_or(0);
                        // SAFETY: the signer's string takes the buffer, from CRYPTO_malloc.
                        unsafe { ASN1_STRING_set0(s.enc_digest, abuf.cast(), n) };
                    }
                }
            } else if nid == NID_pkcs7_digest {
                let Some(d) = digest_of(p) else { break 'err false };
                // SAFETY: the digest algorithm's object, or NULL.
                let j = unsafe { OBJ_obj2nid(algorithm(d.md)) };
                let Some((_, mdc)) = find_digest(bio, j, F) else {
                    break 'err false;
                };
                let mut md = [0u8; EVP_MAX_MD_SIZE as usize];
                let mut len: c_uint = 0;
                // SAFETY: a live context; room for any digest.
                if unsafe { EVP_DigestFinal_ex(mdc, md.as_mut_ptr(), &mut len) } == 0 {
                    break 'err false;
                }
                let n = c_int::try_from(len).unwrap_or(0);
                // SAFETY: the object's digest string; the digest's octets.
                if unsafe { ASN1_OCTET_STRING_set(d.digest, md.as_ptr(), n) } == 0 {
                    break 'err false;
                }
            }
            if !is_detached(p7) {
                if os.is_null() {
                    break 'err false;
                }
                // SAFETY: the content's string, live.
                if unsafe { (*os).flags } & c_long::from(ASN1_STRING_FLAG_NDEF) == 0 {
                    // SAFETY: a live chain.
                    let btmp = unsafe { BIO_find_type(bio, BIO_TYPE_MEM) };
                    if btmp.is_null() {
                        raise(PKCS7_R_UNABLE_TO_FIND_MEM_BIO, F);
                        break 'err false;
                    }
                    let cont = mem_contents(btmp);
                    let n = c_int::try_from(cont.len()).unwrap_or(c_int::MAX);
                    // SAFETY: the content's string; the memory BIO's octets, copied.
                    if unsafe { ASN1_OCTET_STRING_set(os, cont.as_ptr(), n) } == 0 {
                        break 'err false;
                    }
                    // SAFETY: a live memory BIO.
                    unsafe { BIO_ctrl(btmp, BIO_C_SET_BUF_MEM_EOF_RETURN, 0, ptr::null_mut()) };
                }
            }
            true
        };
        // SAFETY: the context made here.
        unsafe { EVP_MD_CTX_free(ctx_tmp) };
        c_int::from(ok)
    }
}

ffi_export! {
    /// Signs the signer info's signed attributes (DER, as a SET OF) with its key: 1, or 0.
    ///
    /// # Safety
    /// `si` is a live signer info.
    pub unsafe extern "C" fn PKCS7_SIGNER_INFO_sign(si: *mut PKCS7_SIGNER_INFO) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        const F: &str = "PKCS7_SIGNER_INFO_sign";
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { si.as_mut() }) else {
            raise(PKCS7_R_INVALID_NULL_POINTER, F);
            return 0;
        };
        // SAFETY: its digest algorithm's object, or NULL.
        let nid = unsafe { OBJ_obj2nid(algorithm(s.digest_alg)) };
        // SAFETY: any NID.
        let sn = unsafe { OBJ_nid2sn(nid) };
        // SAFETY: NULL or a static name.
        let md = unsafe { EVP_get_digestbyname(sn) };
        if md.is_null() {
            return 0;
        }
        let (libctx, propq) = ctx_parts(s.ctx);
        // SAFETY: no preconditions.
        let mctx = unsafe { EVP_MD_CTX_new() };
        if mctx.is_null() {
            raise(ERR_R_EVP_LIB, F);
            return 0;
        }
        let mut abuf: *mut u8 = ptr::null_mut();
        let ok = 'err: {
            let mut pctx: *mut EVP_PKEY_CTX = ptr::null_mut();
            // SAFETY: a live digest.
            let mdname = unsafe { EVP_MD_get0_name(md) };
            // SAFETY: a new context; the digest's name; the signer's key.
            if unsafe { EVP_DigestSignInit_ex(mctx, &mut pctx, mdname, libctx, propq, s.pkey, ptr::null()) } <= 0 {
                break 'err false;
            }
            // SAFETY: no preconditions.
            let it = unsafe { PKCS7_ATTR_SIGN_it() };
            // SAFETY: the signer's attributes; room for the encoding's pointer.
            let alen = unsafe { ASN1_item_i2d(s.auth_attr.cast(), &mut abuf, it) };
            let Some(alen) = usize::try_from(alen).ok().filter(|_| !abuf.is_null()) else {
                break 'err false;
            };
            // SAFETY: the context; the encoding's octets.
            if unsafe { EVP_DigestSignUpdate(mctx, abuf.cast(), alen) } <= 0 {
                break 'err false;
            }
            // SAFETY: the encoding, from CRYPTO_malloc.
            unsafe { mem::release(abuf.cast()) };
            abuf = ptr::null_mut();
            let mut siglen = 0usize;
            // SAFETY: the context; room for the length.
            if unsafe { EVP_DigestSignFinal(mctx, ptr::null_mut(), &mut siglen) } <= 0 {
                break 'err false;
            }
            abuf = mem::alloc(siglen).cast();
            if abuf.is_null() {
                break 'err false;
            }
            // SAFETY: as above; `siglen` octets of room.
            if unsafe { EVP_DigestSignFinal(mctx, abuf, &mut siglen) } <= 0 {
                break 'err false;
            }
            let Ok(n) = c_int::try_from(siglen) else {
                break 'err false;
            };
            // SAFETY: the signer's string takes the buffer, from CRYPTO_malloc.
            unsafe { ASN1_STRING_set0(s.enc_digest, abuf.cast(), n) };
            abuf = ptr::null_mut();
            true
        };
        // SAFETY: NULL, or a buffer from CRYPTO_malloc not handed on.
        unsafe { mem::release(abuf.cast()) };
        // SAFETY: the context made here.
        unsafe { EVP_MD_CTX_free(mctx) };
        c_int::from(ok)
    }
}

ffi_export! {
    /// Verifies the signer's certificate (found in the object by issuer and serial number)
    /// against `cert_store` for S/MIME signing, then its signature: 1, or 0 or -1.
    ///
    /// # Safety
    /// `cert_store` and `ctx` are live; `bio` is the object's chain; `p7` and `si` are NULL or
    /// live.
    pub unsafe extern "C" fn PKCS7_dataVerify(cert_store: *mut X509_STORE, ctx: *mut X509_STORE_CTX, bio: *mut BIO, p7: *mut PKCS7, si: *mut PKCS7_SIGNER_INFO) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        const F: &str = "PKCS7_dataVerify";
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p7_of(p7) }) else {
            raise(PKCS7_R_INVALID_NULL_POINTER, F);
            return 0;
        };
        if content_ptr(p).is_null() {
            raise(PKCS7_R_NO_CONTENT, F);
            return 0;
        }
        let nid = nid_of(p);
        let (untrusted, crls) = if nid == NID_pkcs7_signed {
            sign_of(p).map_or((ptr::null_mut(), ptr::null_mut()), |s| (s.cert, s.crl))
        } else if nid == NID_pkcs7_signedAndEnveloped {
            sign_env_of(p).map_or((ptr::null_mut(), ptr::null_mut()), |s| (s.cert, s.crl))
        } else {
            raise(PKCS7_R_WRONG_PKCS7_TYPE, F);
            return 0;
        };
        // SAFETY: the caller's context; the object's CRLs, or NULL.
        unsafe { X509_STORE_CTX_set0_crls(ctx, crls) };
        // SAFETY: the caller's signer info, and its issuer and serial, or NULL.
        let ias = unsafe { si.as_ref() }.and_then(|s| unsafe { s.issuer_and_serial.as_ref() });
        let Some(ias) = ias else {
            raise(PKCS7_R_INVALID_NULL_POINTER, F);
            return 0;
        };
        // SAFETY: the object's certificates; a live name and serial.
        let signer = unsafe { X509_find_by_issuer_and_serial(untrusted, ias.issuer, ias.serial) };
        if signer.is_null() {
            raise(PKCS7_R_UNABLE_TO_FIND_CERTIFICATE, F);
            return 0;
        }
        // SAFETY: the caller's context and store; the signer; the object's certificates.
        if unsafe { X509_STORE_CTX_init(ctx, cert_store, signer, untrusted) } == 0 {
            raise(ERR_R_X509_LIB, F);
            return 0;
        }
        // SAFETY: as above.
        unsafe { X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SMIME_SIGN) };
        // SAFETY: as above.
        if unsafe { X509_verify_cert(ctx) } <= 0 {
            raise(ERR_R_X509_LIB, F);
            return 0;
        }
        // SAFETY: as above.
        unsafe { PKCS7_signatureVerify(bio, p7, si, signer) }
    }
}

ffi_export! {
    /// Checks a signer info's signature over the digest in the chain (through its signed
    /// attributes, whose message digest must match): 1, or 0 or -1.
    ///
    /// # Safety
    /// `bio` is the object's chain; `p7`, `si`, and `signer` are NULL or live.
    pub unsafe extern "C" fn PKCS7_signatureVerify(bio: *mut BIO, p7: *mut PKCS7, si: *mut PKCS7_SIGNER_INFO, signer: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        const F: &str = "PKCS7_signatureVerify";
        let (libctx, propq) = ctx_parts(ctx_of(p7));
        // SAFETY: no preconditions.
        let mdc_tmp = unsafe { EVP_MD_CTX_new() };
        if mdc_tmp.is_null() {
            raise(ERR_R_EVP_LIB, F);
            return 0;
        }
        let mut abuf: *mut u8 = ptr::null_mut();
        let mut fetched: *mut EVP_MD = ptr::null_mut();
        let ret = 'err: {
            let nid = type_nid(p7);
            if nid != NID_pkcs7_signed && nid != NID_pkcs7_signedAndEnveloped {
                raise(PKCS7_R_WRONG_PKCS7_TYPE, F);
                break 'err 0;
            }
            // SAFETY: the caller's guarantee.
            let Some(s) = (unsafe { si.as_ref() }) else {
                raise(PKCS7_R_INVALID_NULL_POINTER, F);
                break 'err 0;
            };
            // SAFETY: its digest algorithm's object, or NULL.
            let md_type = unsafe { OBJ_obj2nid(algorithm(s.digest_alg)) };
            let mut btmp = bio;
            let mdc = loop {
                if btmp.is_null() {
                    raise(PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST, F);
                    break 'err 0;
                }
                // SAFETY: a live chain.
                btmp = unsafe { BIO_find_type(btmp, BIO_TYPE_MD) };
                if btmp.is_null() {
                    raise(PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST, F);
                    break 'err 0;
                }
                let mdc = md_ctx(btmp);
                if mdc.is_null() {
                    raise(ERR_R_INTERNAL_ERROR, F);
                    break 'err 0;
                }
                if md_ctx_type(mdc) == md_type {
                    break mdc;
                }
                // SAFETY: a live context.
                let md = unsafe { EVP_MD_CTX_get0_md(mdc) };
                // SAFETY: its digest, or NULL.
                if unsafe { EVP_MD_get_pkey_type(md) } == md_type {
                    break mdc;
                }
                // SAFETY: a live BIO.
                btmp = unsafe { BIO_next(btmp) };
            };
            // SAFETY: live digest contexts.
            if unsafe { EVP_MD_CTX_copy_ex(mdc_tmp, mdc) } == 0 {
                break 'err 0;
            }
            let sk = s.auth_attr;
            // SAFETY: the signer's attributes, or NULL.
            if unsafe { OPENSSL_sk_num(sk.cast()) } > 0 {
                let mut md_dat = [0u8; EVP_MAX_MD_SIZE as usize];
                let mut md_len: c_uint = 0;
                // SAFETY: as above; room for any digest.
                if unsafe { EVP_DigestFinal_ex(mdc_tmp, md_dat.as_mut_ptr(), &mut md_len) } == 0 {
                    break 'err 0;
                }
                // SAFETY: the signer's attributes.
                let message_digest = unsafe { PKCS7_digest_from_attributes(sk) };
                if message_digest.is_null() {
                    raise(PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST, F);
                    break 'err 0;
                }
                // SAFETY: the attribute's string, live.
                let expected = unsafe { octets(message_digest) };
                let computed = md_dat.get(..usize::try_from(md_len).unwrap_or(0)).unwrap_or_default();
                let same = expected.len() == computed.len()
                    // SAFETY: two buffers of `computed.len()` octets.
                    && unsafe { crate::mem::CRYPTO_memcmp(expected.as_ptr().cast(), computed.as_ptr().cast(), computed.len()) } == 0;
                if !same {
                    raise(PKCS7_R_DIGEST_FAILURE, F);
                    break 'err -1;
                }
                // SAFETY: no preconditions.
                unsafe { ERR_set_mark() };
                // SAFETY: any NID.
                let sn = unsafe { OBJ_nid2sn(md_type) };
                // SAFETY: NULL or a static name; the object's context and properties.
                fetched = unsafe { EVP_MD_fetch(libctx, sn, propq) };
                let md = if fetched.is_null() {
                    // SAFETY: as above.
                    unsafe { EVP_get_digestbyname(sn) }
                } else {
                    fetched.cast_const()
                };
                // SAFETY: the context; a live digest.
                if md.is_null() || unsafe { EVP_DigestInit_ex(mdc_tmp, md, ptr::null_mut()) } == 0 {
                    // SAFETY: no preconditions.
                    unsafe { ERR_clear_last_mark() };
                    break 'err 0;
                }
                // SAFETY: no preconditions.
                unsafe { ERR_pop_to_mark() };
                // SAFETY: no preconditions.
                let it = unsafe { PKCS7_ATTR_VERIFY_it() };
                // SAFETY: the signer's attributes; room for the encoding's pointer.
                let alen = unsafe { ASN1_item_i2d(sk.cast(), &mut abuf, it) };
                let Some(alen) = usize::try_from(alen).ok().filter(|&n| n > 0 && !abuf.is_null()) else {
                    raise(ERR_R_ASN1_LIB, F);
                    break 'err -1;
                };
                // SAFETY: the context; the encoding's octets.
                if unsafe { EVP_DigestUpdate(mdc_tmp, abuf.cast(), alen) } == 0 {
                    break 'err 0;
                }
            }
            // SAFETY: the signer's certificate, or NULL.
            let pkey = unsafe { X509_get0_pubkey(signer) };
            if pkey.is_null() {
                break 'err -1;
            }
            // SAFETY: the signer's signature, live.
            let sig = unsafe { octets(s.enc_digest) };
            let n = c_uint::try_from(sig.len()).unwrap_or(0);
            // SAFETY: the digest; the signature's octets; the signer's key.
            if unsafe { EVP_VerifyFinal_ex(mdc_tmp, sig.as_ptr(), n, pkey, libctx, propq) } <= 0 {
                raise(PKCS7_R_SIGNATURE_FAILURE, F);
                break 'err -1;
            }
            1
        };
        // SAFETY: NULL, or the encoding from CRYPTO_malloc.
        unsafe { mem::release(abuf.cast()) };
        // SAFETY: the context made here.
        unsafe { EVP_MD_CTX_free(mdc_tmp) };
        // SAFETY: the fetched digest, or NULL.
        unsafe { EVP_MD_free(fetched) };
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkcs7::{PKCS7_free, PKCS7_new, PKCS7_set_type};

    /// docs/DEVIATIONS.md: `PKCS7_dataFinal` copies the content, and the memory BIO stays
    /// writable and keeps its own buffer, where OpenSSL hands the buffer to the object.
    #[test]
    fn data_final_copies_the_content() {
        // SAFETY: no preconditions.
        let p7 = unsafe { PKCS7_new() };
        // SAFETY: the new object.
        assert_eq!(unsafe { PKCS7_set_type(p7, NID_pkcs7_data) }, 1);
        // SAFETY: as above.
        let bio = unsafe { PKCS7_dataInit(p7, ptr::null_mut()) };
        assert!(!bio.is_null());
        // SAFETY: the chain; 5 octets.
        assert_eq!(unsafe { BIO_write(bio, c"hello".as_ptr().cast(), 5) }, 5);
        // SAFETY: the object and its chain.
        assert_eq!(unsafe { PKCS7_dataFinal(p7, bio) }, 1);
        // SAFETY: as above; 1 octet.
        assert_eq!(unsafe { BIO_write(bio, c"!".as_ptr().cast(), 1) }, 1);
        // SAFETY: the live object.
        let obj = unsafe { &*p7 };
        // SAFETY: a Data object's content.
        let data = unsafe { obj.d.data };
        // SAFETY: its string.
        assert_eq!(unsafe { octets(data) }, b"hello");
        assert_eq!(mem_contents(bio), b"hello!");
        // SAFETY: the chain and the object, freed once each.
        unsafe { BIO_free_all(bio) };
        // SAFETY: as above.
        unsafe { PKCS7_free(p7) };
    }
}
