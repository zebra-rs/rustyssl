//! CMS's one-call operations (`cms_smime.c`) for Data, DigestedData, EncryptedData, and
//! CompressedData (unsupported, as in the default build without zlib), and the helpers the
//! others share: copying a content out of its chain, and finishing an object.

use core::ffi::{c_char, c_int, c_uchar, c_uint};
use core::ptr;

use rustyssl_abi::{
    BIO, BIO_C_GET_CIPHER_CTX, BIO_C_GET_CIPHER_STATUS, BIO_TYPE_CIPHER, CMS_ContentInfo,
    CMS_DETACHED, CMS_PARTIAL, CMS_R_CMS_DATAFINAL_ERROR, CMS_R_CMS_LIB, CMS_R_NO_CIPHER,
    CMS_R_NO_CONTENT, CMS_R_SMIME_TEXT_ERROR, CMS_R_TYPE_NOT_DATA, CMS_R_TYPE_NOT_DIGESTED_DATA,
    CMS_R_TYPE_NOT_ENCRYPTED_DATA, CMS_R_UNSUPPORTED_COMPRESSION_ALGORITHM, CMS_STREAM, CMS_TEXT,
    ERR_LIB_CMS, ERR_R_BIO_LIB, ERR_R_CMS_LIB, EVP_CIPH_FLAG_AEAD_CIPHER, EVP_CIPHER,
    EVP_CIPHER_CTX, EVP_MD, NID_pkcs7_data, NID_pkcs7_digest, NID_pkcs7_encrypted, OSSL_LIB_CTX,
};

use super::base::{
    CMS_ContentInfo_free, CMS_ContentInfo_new_ex, CMS_dataInit, CMS_get0_content, CMS_set_detached,
    data_create, data_final, digested_create, digested_do_final, mem_bio, raise, type_nid,
};
use super::enc::CMS_EncryptedData_set1_key;
use crate::asn1::mime::{SMIME_crlf_copy, SMIME_text};
use crate::bio::null::BIO_s_null;
use crate::bio::{
    BIO_ctrl, BIO_free, BIO_free_all, BIO_method_type, BIO_new, BIO_pop, BIO_read, BIO_write,
};
use crate::evp::cipher::EVP_CIPHER_get_flags;
use crate::evp::cipher_ctx::EVP_CIPHER_CTX_get0_cipher;
use crate::evp::legacy_md::EVP_sha1;
use crate::ffi::ffi_export;

/// `cms_get_text_bio`: where the content goes: a null BIO for no output, a memory BIO for
/// text, `out` otherwise.
fn text_bio(out: *mut BIO, flags: c_uint) -> *mut BIO {
    if out.is_null() {
        // SAFETY: no preconditions.
        let method = unsafe { BIO_s_null() };
        // SAFETY: the built-in method.
        unsafe { BIO_new(method) }
    } else if flags & CMS_TEXT.cast_unsigned() != 0 {
        mem_bio()
    } else {
        out
    }
}

fn cipher_status_ok(b: *mut BIO) -> bool {
    // SAFETY: a live BIO.
    if unsafe { BIO_method_type(b) } != BIO_TYPE_CIPHER {
        return true;
    }
    // SAFETY: a live cipher BIO.
    unsafe { BIO_ctrl(b, BIO_C_GET_CIPHER_STATUS, 0, ptr::null_mut()) > 0 }
}

/// Copies all of `from` to `to`: whether it read to the end and wrote all.
fn pump(from: *mut BIO, to: *mut BIO, cipher_check: bool) -> bool {
    let mut buf = [0u8; 4096];
    let room = c_int::try_from(buf.len()).unwrap_or(0);
    loop {
        // SAFETY: a live BIO; room for `room` octets.
        let i = unsafe { BIO_read(from, buf.as_mut_ptr().cast(), room) };
        if i <= 0 {
            if cipher_check && !cipher_status_ok(from) {
                return false;
            }
            return i == 0;
        }
        // SAFETY: a live BIO, or NULL; the `i` octets read.
        if !to.is_null() && unsafe { BIO_write(to, buf.as_ptr().cast(), i) } != i {
            return false;
        }
    }
}

/// `cms_copy_content`: the content read through its chain to `out` (its text for
/// `CMS_TEXT`), held back until an AEAD cipher's tag has been checked (RFC 5083).
///
/// # Safety
/// `out` is NULL or a live BIO; `input` a live chain.
pub(crate) unsafe fn copy_content(out: *mut BIO, input: *mut BIO, flags: c_uint) -> bool {
    let mut tmpout = text_bio(out, flags);
    if tmpout.is_null() {
        raise(ERR_R_CMS_LIB, "cms_copy_content");
        return false;
    }
    let mut aeadbuf: *mut BIO = ptr::null_mut();
    let ok = 'err: {
        // SAFETY: a live chain.
        if tmpout == out && unsafe { BIO_method_type(input) } == BIO_TYPE_CIPHER {
            let mut ctx: *mut EVP_CIPHER_CTX = ptr::null_mut();
            // SAFETY: a cipher BIO; room for its context.
            let got =
                unsafe { BIO_ctrl(input, BIO_C_GET_CIPHER_CTX, 0, (&raw mut ctx).cast()) } > 0;
            let cipher: *const EVP_CIPHER = if got {
                // SAFETY: the context, or NULL.
                unsafe { EVP_CIPHER_CTX_get0_cipher(ctx) }
            } else {
                ptr::null()
            };
            if !ctx.is_null()
                && !cipher.is_null()
                // SAFETY: a live cipher.
                && (unsafe { EVP_CIPHER_get_flags(cipher) })
                    & EVP_CIPH_FLAG_AEAD_CIPHER as core::ffi::c_ulong
                    != 0
            {
                aeadbuf = mem_bio();
                if aeadbuf.is_null() {
                    raise(ERR_R_BIO_LIB, "cms_copy_content");
                    break 'err false;
                }
                tmpout = aeadbuf;
            }
        }
        if !pump(input, tmpout, true) {
            break 'err false;
        }
        if flags & CMS_TEXT.cast_unsigned() != 0 {
            // SAFETY: the memory BIO; the caller's.
            if unsafe { SMIME_text(tmpout, out) } == 0 {
                raise(CMS_R_SMIME_TEXT_ERROR, "cms_copy_content");
                break 'err false;
            }
        } else if !aeadbuf.is_null() && !pump(aeadbuf, out, false) {
            break 'err false;
        }
        true
    };
    if tmpout != out {
        // SAFETY: the BIO made here.
        unsafe { BIO_free(tmpout) };
    }
    ok
}

/// `check_content`: whether the object has its content.
///
/// # Safety
/// `cms` is NULL or a live object.
pub(crate) unsafe fn check_content(cms: *mut CMS_ContentInfo) -> bool {
    // SAFETY: the caller's guarantee.
    let pos = unsafe { CMS_get0_content(cms) };
    // SAFETY: NULL or the content's slot.
    if unsafe { pos.as_ref() }.is_none_or(|p| p.is_null()) {
        raise(CMS_R_NO_CONTENT, "check_content");
        return false;
    }
    true
}

/// `do_free_upto`: frees the chain down to `upto` (all of it for NULL).
pub(crate) fn free_upto(f: *mut BIO, upto: *mut BIO) {
    if upto.is_null() {
        // SAFETY: a chain made by the caller.
        unsafe { BIO_free_all(f) };
        return;
    }
    let mut f = f;
    loop {
        // SAFETY: a BIO of the chain.
        let next = unsafe { BIO_pop(f) };
        // SAFETY: as above, out of the chain.
        unsafe { BIO_free(f) };
        f = next;
        if f.is_null() || f == upto {
            break;
        }
    }
}

ffi_export! {
    /// Copies a Data object's content to `out`: 1, or 0.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; `out` NULL or a live BIO.
    pub unsafe extern "C" fn CMS_data(cms: *mut CMS_ContentInfo, out: *mut BIO, flags: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        if type_nid(cms) != NID_pkcs7_data {
            raise(CMS_R_TYPE_NOT_DATA, "CMS_data");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let cont = unsafe { CMS_dataInit(cms, ptr::null_mut()) };
        if cont.is_null() {
            return 0;
        }
        // SAFETY: as above; the chain.
        let r = unsafe { copy_content(out, cont, flags) };
        // SAFETY: the chain made here.
        unsafe { BIO_free_all(cont) };
        c_int::from(r)
    }
}

ffi_export! {
    /// A Data object holding `in_` (unless `CMS_STREAM`), or NULL.
    ///
    /// # Safety
    /// `in_` is NULL or a live BIO; `libctx` NULL or live; `propq` NULL or a C string.
    pub unsafe extern "C" fn CMS_data_create_ex(in_: *mut BIO, flags: c_uint, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut CMS_ContentInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let cms = unsafe { data_create(libctx, propq) };
        if cms.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the new object; the caller's data.
        if flags & CMS_STREAM.cast_unsigned() != 0 || unsafe { CMS_final(cms, in_, ptr::null_mut(), flags) } != 0 {
            return cms;
        }
        // SAFETY: the object made here.
        unsafe { CMS_ContentInfo_free(cms) };
        ptr::null_mut()
    }
}

ffi_export! {
    /// [`CMS_data_create_ex`] in the default library context.
    ///
    /// # Safety
    /// As for [`CMS_data_create_ex`].
    pub unsafe extern "C" fn CMS_data_create(in_: *mut BIO, flags: c_uint) -> *mut CMS_ContentInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        unsafe { CMS_data_create_ex(in_, flags, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Checks DigestedData's digest over its content (or `dcont`), copying the content to
    /// `out`: 1, or 0.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; `dcont` and `out` NULL or live BIOs.
    pub unsafe extern "C" fn CMS_digest_verify(cms: *mut CMS_ContentInfo, dcont: *mut BIO, out: *mut BIO, flags: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        if type_nid(cms) != NID_pkcs7_digest {
            raise(CMS_R_TYPE_NOT_DIGESTED_DATA, "CMS_digest_verify");
            return 0;
        }
        // SAFETY: a live object.
        if dcont.is_null() && !unsafe { check_content(cms) } {
            return 0;
        }
        // SAFETY: as above.
        let cont = unsafe { CMS_dataInit(cms, dcont) };
        if cont.is_null() {
            return 0;
        }
        // SAFETY: the caller's BIO; the chain.
        let mut r = c_int::from(unsafe { copy_content(out, cont, flags) });
        if r != 0 {
            // SAFETY: the object and its chain.
            r = unsafe { digested_do_final(cms, cont, true) };
        }
        free_upto(cont, dcont);
        r
    }
}

ffi_export! {
    /// DigestedData over `in_` with `md` (SHA-1 for NULL), or NULL.
    ///
    /// # Safety
    /// `in_` is NULL or a live BIO; `md` NULL or live; the others as for
    /// `CMS_ContentInfo_new_ex`.
    pub unsafe extern "C" fn CMS_digest_create_ex(in_: *mut BIO, md: *const EVP_MD, flags: c_uint, ctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut CMS_ContentInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        let md = if md.is_null() {
            // SAFETY: no preconditions.
            unsafe { EVP_sha1() }
        } else {
            md
        };
        // SAFETY: a live digest; the caller's context.
        let cms = unsafe { digested_create(md, ctx, propq) };
        if cms.is_null() {
            return ptr::null_mut();
        }
        if flags & CMS_DETACHED.cast_unsigned() == 0 {
            // SAFETY: the new object.
            unsafe { CMS_set_detached(cms, 0) };
        }
        // SAFETY: as above; the caller's data.
        if flags & CMS_STREAM.cast_unsigned() != 0 || unsafe { CMS_final(cms, in_, ptr::null_mut(), flags) } != 0 {
            return cms;
        }
        // SAFETY: the object made here.
        unsafe { CMS_ContentInfo_free(cms) };
        ptr::null_mut()
    }
}

ffi_export! {
    /// [`CMS_digest_create_ex`] in the default library context.
    ///
    /// # Safety
    /// As for [`CMS_digest_create_ex`].
    pub unsafe extern "C" fn CMS_digest_create(in_: *mut BIO, md: *const EVP_MD, flags: c_uint) -> *mut CMS_ContentInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        unsafe { CMS_digest_create_ex(in_, md, flags, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Decrypts EncryptedData with `key` into `out`: 1, or 0.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; `key` holds `keylen` octets; the BIOs NULL or live.
    pub unsafe extern "C" fn CMS_EncryptedData_decrypt(cms: *mut CMS_ContentInfo, key: *const c_uchar, keylen: usize, dcont: *mut BIO, out: *mut BIO, flags: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        if type_nid(cms) != NID_pkcs7_encrypted {
            raise(CMS_R_TYPE_NOT_ENCRYPTED_DATA, "CMS_EncryptedData_decrypt");
            return 0;
        }
        // SAFETY: a live object.
        if dcont.is_null() && !unsafe { check_content(cms) } {
            return 0;
        }
        // SAFETY: as above; the caller's key.
        if unsafe { CMS_EncryptedData_set1_key(cms, ptr::null(), key, keylen) } <= 0 {
            return 0;
        }
        // SAFETY: as above.
        let cont = unsafe { CMS_dataInit(cms, dcont) };
        if cont.is_null() {
            return 0;
        }
        // SAFETY: the caller's BIO; the chain.
        let r = c_int::from(unsafe { copy_content(out, cont, flags) });
        free_upto(cont, dcont);
        r
    }
}

ffi_export! {
    /// EncryptedData of `in_` with `cipher` and `key` (finished unless streaming or partial),
    /// or NULL.
    ///
    /// # Safety
    /// `in_` is NULL or a live BIO; `cipher` NULL or live; `key` holds `keylen` octets; the
    /// others as for `CMS_ContentInfo_new_ex`.
    pub unsafe extern "C" fn CMS_EncryptedData_encrypt_ex(in_: *mut BIO, cipher: *const EVP_CIPHER, key: *const c_uchar, keylen: usize, flags: c_uint, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut CMS_ContentInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        if cipher.is_null() {
            raise(CMS_R_NO_CIPHER, "CMS_EncryptedData_encrypt_ex");
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let cms = unsafe { CMS_ContentInfo_new_ex(libctx, propq) };
        if cms.is_null() {
            return ptr::null_mut();
        }
        let ok = 'err: {
            // SAFETY: the new object; the caller's cipher and key.
            if unsafe { CMS_EncryptedData_set1_key(cms, cipher, key, keylen) } == 0 {
                break 'err false;
            }
            if flags & CMS_DETACHED.cast_unsigned() == 0 {
                // SAFETY: as above.
                unsafe { CMS_set_detached(cms, 0) };
            }
            // SAFETY: as above; the caller's data.
            flags & (CMS_STREAM | CMS_PARTIAL).cast_unsigned() != 0 || unsafe { CMS_final(cms, in_, ptr::null_mut(), flags) } != 0
        };
        if ok {
            return cms;
        }
        // SAFETY: the object made here.
        unsafe { CMS_ContentInfo_free(cms) };
        ptr::null_mut()
    }
}

ffi_export! {
    /// [`CMS_EncryptedData_encrypt_ex`] in the default library context.
    ///
    /// # Safety
    /// As for [`CMS_EncryptedData_encrypt_ex`].
    pub unsafe extern "C" fn CMS_EncryptedData_encrypt(in_: *mut BIO, cipher: *const EVP_CIPHER, key: *const c_uchar, keylen: usize, flags: c_uint) -> *mut CMS_ContentInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        unsafe { CMS_EncryptedData_encrypt_ex(in_, cipher, key, keylen, flags, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Writes `data` through the object's data path (onto `dcont` if given) and finishes the
    /// object: 1, or 0.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; `data` and `dcont` NULL or live BIOs.
    pub unsafe extern "C" fn CMS_final(cms: *mut CMS_ContentInfo, data: *mut BIO, dcont: *mut BIO, flags: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        const F: &str = "CMS_final";
        // SAFETY: the caller's guarantee.
        let cmsbio = unsafe { CMS_dataInit(cms, dcont) };
        if cmsbio.is_null() {
            raise(CMS_R_CMS_LIB, F);
            return 0;
        }
        let ok = 'err: {
            let f = flags.cast_signed();
            // SAFETY: the caller's data; the chain.
            if unsafe { SMIME_crlf_copy(data, cmsbio, f) } == 0 {
                break 'err false;
            }
            // SAFETY: the chain.
            unsafe { BIO_ctrl(cmsbio, rustyssl_abi::BIO_CTRL_FLUSH, 0, ptr::null_mut()) };
            // SAFETY: the object and its chain.
            if unsafe { data_final(cms, cmsbio, &[]) } == 0 {
                raise(CMS_R_CMS_DATAFINAL_ERROR, F);
                break 'err false;
            }
            true
        };
        free_upto(cmsbio, dcont);
        c_int::from(ok)
    }
}

ffi_export! {
    /// Finishes SignedData over a digest computed elsewhere: 1, or 0.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; `md` holds `mdlen` octets; `dcont` NULL or live.
    pub unsafe extern "C" fn CMS_final_digest(cms: *mut CMS_ContentInfo, md: *const c_uchar, mdlen: c_uint, dcont: *mut BIO, flags: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        const F: &str = "CMS_final_digest";
        let _ = flags;
        let n = usize::try_from(mdlen).unwrap_or(0);
        // SAFETY: the caller's guarantee.
        let Some(digest) = (unsafe { crate::ffi::bytes(md, n) }) else { return 0 };
        // SAFETY: as above.
        let cmsbio = unsafe { CMS_dataInit(cms, dcont) };
        if cmsbio.is_null() {
            raise(CMS_R_CMS_LIB, F);
            return 0;
        }
        // SAFETY: the chain.
        unsafe { BIO_ctrl(cmsbio, rustyssl_abi::BIO_CTRL_FLUSH, 0, ptr::null_mut()) };
        // SAFETY: the object and its chain.
        let ok = unsafe { data_final(cms, cmsbio, digest) } != 0;
        if !ok {
            raise(CMS_R_CMS_DATAFINAL_ERROR, F);
        }
        free_upto(cmsbio, dcont);
        c_int::from(ok)
    }
}

ffi_export! {
    /// Fails: the default build has no compression (zlib).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn CMS_uncompress(cms: *mut CMS_ContentInfo, dcont: *mut BIO, out: *mut BIO, flags: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        let _ = (cms, dcont, out, flags);
        raise(CMS_R_UNSUPPORTED_COMPRESSION_ALGORITHM, "CMS_uncompress");
        0
    }
}

ffi_export! {
    /// Fails: the default build has no compression (zlib).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn CMS_compress(in_: *mut BIO, comp_nid: c_int, flags: c_uint) -> *mut CMS_ContentInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        let _ = (in_, comp_nid, flags);
        raise(CMS_R_UNSUPPORTED_COMPRESSION_ALGORITHM, "CMS_compress");
        ptr::null_mut()
    }
}
