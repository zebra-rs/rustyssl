//! CMS's one-call operations (`cms_smime.c`) for Data, DigestedData, EncryptedData, and
//! CompressedData (unsupported, as in the default build without zlib), and the helpers the
//! others share: copying a content out of its chain, and finishing an object.

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint};
use core::ptr;

use rustyssl_abi::{
    ASN1_OCTET_STRING, BIO, BIO_C_GET_CIPHER_CTX, BIO_C_GET_CIPHER_STATUS, BIO_CTRL_INFO,
    BIO_TYPE_CIPHER, BIO_TYPE_MEM, CMS_ASCIICRLF, CMS_BINARY, CMS_CADES, CMS_ContentInfo,
    CMS_DETACHED, CMS_NO_ATTR_VERIFY, CMS_NO_CONTENT_VERIFY, CMS_NO_SIGNER_CERT_VERIFY, CMS_NOCRL,
    CMS_PARTIAL, CMS_R_ADD_SIGNER_ERROR, CMS_R_CERTIFICATE_VERIFY_ERROR, CMS_R_CMS_DATAFINAL_ERROR,
    CMS_R_CMS_LIB, CMS_R_CONTENT_VERIFY_ERROR, CMS_R_NO_CIPHER, CMS_R_NO_CONTENT,
    CMS_R_NO_KEY_OR_CERT, CMS_R_NO_SIGNERS, CMS_R_SIGNER_CERTIFICATE_NOT_FOUND,
    CMS_R_SMIME_TEXT_ERROR, CMS_R_STORE_INIT_ERROR, CMS_R_TYPE_NOT_DATA,
    CMS_R_TYPE_NOT_DIGESTED_DATA, CMS_R_TYPE_NOT_ENCRYPTED_DATA,
    CMS_R_UNSUPPORTED_COMPRESSION_ALGORITHM, CMS_STREAM, CMS_SignerInfo, CMS_TEXT, ERR_LIB_CMS,
    ERR_R_BIO_LIB, ERR_R_CMS_LIB, ERR_R_X509_LIB, EVP_CIPH_FLAG_AEAD_CIPHER, EVP_CIPHER,
    EVP_CIPHER_CTX, EVP_MD, EVP_PKEY, NID_id_ct_asciiTextWithCRLF, NID_id_smime_ct_receipt,
    NID_pkcs7_data, NID_pkcs7_digest, NID_pkcs7_encrypted, OSSL_LIB_CTX, SMIME_BINARY, SMIME_TEXT,
    X509, X509_ADD_FLAG_NO_DUP, X509_ADD_FLAG_UP_REF, X509_STORE, stack_st_X509, stack_st_X509_CRL,
};

use super::att::CMS_signed_get_attr_count;
use super::base::{
    CMS_ContentInfo_free, CMS_ContentInfo_new_ex, CMS_dataInit, CMS_get0_content, CMS_set_detached,
    data_create, data_final, digested_create, digested_do_final, mem_bio, raise, type_nid,
};
use super::enc::CMS_EncryptedData_set1_key;
use crate::asn1::mime::{SMIME_crlf_copy, SMIME_text};
use crate::bio::mem::BIO_new_mem_buf;
use crate::bio::null::BIO_s_null;
use crate::bio::{
    BIO_ctrl, BIO_free, BIO_free_all, BIO_method_type, BIO_new, BIO_pop, BIO_read, BIO_write,
};
use crate::err;
use crate::evp::cipher::EVP_CIPHER_get_flags;
use crate::evp::cipher_ctx::EVP_CIPHER_CTX_get0_cipher;
use crate::evp::legacy_md::EVP_sha1;
use crate::ffi::ffi_export;
use crate::stack::OPENSSL_sk_pop_free;
use crate::x509::cert::{OSSL_STACK_OF_X509_free, X509_free};
use crate::x509::crl::X509_CRL_free;
use crate::x509::ctx::{
    X509_STORE_CTX_free, X509_STORE_CTX_get_error, X509_STORE_CTX_get1_chain, X509_STORE_CTX_init,
    X509_STORE_CTX_new_ex, X509_STORE_CTX_set_default, X509_STORE_CTX_set0_crls,
    X509_verify_cert_error_string,
};
use crate::x509::purpose::X509_add_certs;
use crate::x509::verify::X509_verify_cert;

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

/// `cms_signerinfo_verify_cert`: the signer's certificate verified for S/MIME signing, and
/// its chain into `chain` if asked.
///
/// # Safety
/// `si` is a live signer info; the others NULL or live.
unsafe fn signerinfo_verify_cert(
    si: *mut CMS_SignerInfo,
    store: *mut X509_STORE,
    untrusted: *mut stack_st_X509,
    crls: *mut stack_st_X509_CRL,
    chain: Option<&mut *mut stack_st_X509>,
    cms_ctx: *const super::CmsCtx,
) -> bool {
    const F: &str = "cms_signerinfo_verify_cert";
    let (libctx, propq) = super::base::ctx_parts(cms_ctx);
    // SAFETY: the context and properties.
    let ctx = unsafe { X509_STORE_CTX_new_ex(libctx, propq) };
    let ok = 'err: {
        if ctx.is_null() {
            raise(ERR_R_X509_LIB, F);
            break 'err false;
        }
        let mut signer: *mut X509 = ptr::null_mut();
        // SAFETY: the caller's signer info; room for its certificate.
        unsafe {
            super::sd::CMS_SignerInfo_get0_algs(
                si,
                ptr::null_mut(),
                &mut signer,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        // SAFETY: the new context; the caller's store and certificates; the signer.
        if unsafe { X509_STORE_CTX_init(ctx, store, signer, untrusted) } == 0 {
            raise(CMS_R_STORE_INIT_ERROR, F);
            break 'err false;
        }
        // SAFETY: the context; a static name.
        unsafe { X509_STORE_CTX_set_default(ctx, c"smime_sign".as_ptr()) };
        if !crls.is_null() {
            // SAFETY: the context; the CRLs.
            unsafe { X509_STORE_CTX_set0_crls(ctx, crls) };
        }
        // SAFETY: the context.
        if unsafe { X509_verify_cert(ctx) } <= 0 {
            // SAFETY: as above.
            let j = unsafe { X509_STORE_CTX_get_error(ctx) };
            // SAFETY: any code.
            let text = unsafe { X509_verify_cert_error_string(c_long::from(j)) };
            // SAFETY: a static string.
            let s = unsafe { core::ffi::CStr::from_ptr(text) };
            let mut msg = b"Verify error: ".to_vec();
            msg.extend_from_slice(s.to_bytes());
            err::raise_with_bytes(ERR_LIB_CMS, CMS_R_CERTIFICATE_VERIFY_ERROR, F, &msg);
            break 'err false;
        }
        if let Some(c) = chain {
            // SAFETY: the verified context.
            *c = unsafe { X509_STORE_CTX_get1_chain(ctx) };
        }
        true
    };
    // SAFETY: the context made here, or NULL.
    unsafe { X509_STORE_CTX_free(ctx) };
    ok
}

unsafe extern "C" fn x509_free(p: *mut core::ffi::c_void) {
    // SAFETY: a certificate of the stack.
    unsafe { X509_free(p.cast()) };
}

unsafe extern "C" fn crl_free(p: *mut core::ffi::c_void) {
    // SAFETY: a CRL of the stack.
    unsafe { X509_CRL_free(p.cast()) };
}

ffi_export! {
    /// Verifies SignedData: each signer's certificate (unless `CMS_NO_SIGNER_CERT_VERIFY`),
    /// signed attributes (unless `CMS_NO_ATTR_VERIFY`; CAdES's signing certificate for
    /// `CMS_CADES`), and content digest (unless `CMS_NO_CONTENT_VERIFY`), copying the content
    /// (`dcont` if detached) to `out`. 1, or 0.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; the others NULL or live.
    pub unsafe extern "C" fn CMS_verify(cms: *mut CMS_ContentInfo, certs: *mut stack_st_X509, store: *mut X509_STORE, dcont: *mut BIO, out: *mut BIO, flags: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        const F: &str = "CMS_verify";
        let mut flags = flags;
        let has = |flags: c_uint, f: c_int| flags & f.cast_unsigned() != 0;
        let cades = has(flags, CMS_CADES);
        let ctx = super::base::ctx_of(cms);
        // SAFETY: the caller's guarantee.
        if dcont.is_null() && !unsafe { check_content(cms) } {
            return 0;
        }
        if !dcont.is_null() && !has(flags, CMS_BINARY) {
            // SAFETY: as above.
            let coid = unsafe { super::base::CMS_get0_eContentType(cms) };
            // SAFETY: its type, or NULL.
            if unsafe { crate::objects::OBJ_obj2nid(coid) } == NID_id_ct_asciiTextWithCRLF {
                flags |= CMS_ASCIICRLF.cast_unsigned();
            }
        }
        // SAFETY: as above.
        let sinfos = unsafe { super::base::CMS_get0_SignerInfos(cms) }.cast::<super::Stack>();
        let mut untrusted: *mut stack_st_X509 = ptr::null_mut();
        let mut crls: *mut stack_st_X509_CRL = ptr::null_mut();
        let mut si_chains: Vec<*mut stack_st_X509> = Vec::new();
        let mut cmsbio: *mut BIO = ptr::null_mut();
        let mut tmpin: *mut BIO = ptr::null_mut();
        let mut tmpout: *mut BIO = ptr::null_mut();
        let binary_detached = !has(flags, SMIME_BINARY) && !dcont.is_null();
        // SAFETY: the object's signer infos, or NULL.
        let count = unsafe { crate::stack::OPENSSL_sk_num(sinfos.cast()) };
        let si_at = |i: c_int| {
            // SAFETY: an index within the signer infos.
            unsafe { crate::stack::OPENSSL_sk_value(sinfos.cast(), i) }.cast::<CMS_SignerInfo>()
        };
        let mut tmpin_failed = false;
        let ret = 'err: {
            if count <= 0 {
                raise(CMS_R_NO_SIGNERS, F);
                break 'err 0;
            }
            let mut scount = (0..count)
                .filter(|&i| {
                    let mut signer: *mut X509 = ptr::null_mut();
                    // SAFETY: a signer info; room for its certificate.
                    unsafe { super::sd::CMS_SignerInfo_get0_algs(si_at(i), ptr::null_mut(), &mut signer, ptr::null_mut(), ptr::null_mut()) };
                    !signer.is_null()
                })
                .count();
            let total = usize::try_from(count).unwrap_or(0);
            if scount != total {
                // SAFETY: the object; the caller's certificates.
                let found = unsafe { super::sd::CMS_set1_signers_certs(cms, certs, flags) };
                scount = scount.saturating_add_signed(isize::try_from(found).unwrap_or(0));
            }
            if scount != total {
                raise(CMS_R_SIGNER_CERTIFICATE_NOT_FOUND, F);
                break 'err 0;
            }
            if !has(flags, CMS_NO_SIGNER_CERT_VERIFY) || cades {
                if cades {
                    si_chains = vec![ptr::null_mut(); total];
                }
                // SAFETY: a live object.
                let Some(u) = (unsafe { super::base::get1_certs_ex(cms) }) else { break 'err 0 };
                untrusted = u;
                // SAFETY: the caller's certificates, or NULL.
                if unsafe { crate::stack::OPENSSL_sk_num(certs.cast()) } > 0
                    // SAFETY: the list made; the caller's certificates.
                    && unsafe { X509_add_certs(untrusted, certs, X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP) } == 0
                {
                    break 'err 0;
                }
                if !has(flags, CMS_NOCRL) {
                    // SAFETY: a live object.
                    match unsafe { super::base::get1_crls_ex(cms) } {
                        Some(c) => crls = c,
                        None => break 'err 0,
                    }
                }
                for i in 0..count {
                    let chain = si_chains.get_mut(usize::try_from(i).unwrap_or(usize::MAX));
                    // SAFETY: a signer info; the caller's store; the lists.
                    if !unsafe { signerinfo_verify_cert(si_at(i), store, untrusted, crls, chain, ctx) } {
                        break 'err 0;
                    }
                }
            }
            if !has(flags, CMS_NO_ATTR_VERIFY) || cades {
                for i in 0..count {
                    let si = si_at(i);
                    // SAFETY: a signer info.
                    if unsafe { CMS_signed_get_attr_count(si) } < 0 {
                        continue;
                    }
                    // SAFETY: as above.
                    if unsafe { super::sd::CMS_SignerInfo_verify(si) } <= 0 {
                        break 'err 0;
                    }
                    if cades {
                        let chain = si_chains.get(usize::try_from(i).unwrap_or(usize::MAX)).copied().unwrap_or(ptr::null_mut());
                        // SAFETY: as above; its verified chain, or NULL.
                        if !unsafe { super::ess::check_signing_certs(si, chain) } {
                            break 'err 0;
                        }
                    }
                }
            }
            // SAFETY: the caller's BIO, or NULL.
            if !dcont.is_null() && unsafe { BIO_method_type(dcont) } == BIO_TYPE_MEM {
                let mut p: *mut core::ffi::c_char = ptr::null_mut();
                // SAFETY: a memory BIO; room for the pointer.
                let len = unsafe { BIO_ctrl(dcont, BIO_CTRL_INFO, 0, (&raw mut p).cast()) };
                tmpin = if len == 0 {
                    dcont
                } else {
                    let n = c_int::try_from(len).unwrap_or(c_int::MAX);
                    // SAFETY: the caller's BIO's `len` octets, which outlive this call.
                    unsafe { BIO_new_mem_buf(p.cast(), n) }
                };
                if tmpin.is_null() {
                    raise(ERR_R_BIO_LIB, F);
                    tmpin_failed = true;
                    break 'err 0;
                }
            } else {
                tmpin = dcont;
            }
            if binary_detached {
                tmpout = text_bio(out, flags);
                if tmpout.is_null() {
                    raise(ERR_R_CMS_LIB, F);
                    break 'err 0;
                }
                // SAFETY: the object; the output BIO.
                cmsbio = unsafe { super::base::CMS_dataInit(cms, tmpout) };
                if cmsbio.is_null() {
                    break 'err 0;
                }
                let f = (flags & !SMIME_TEXT.cast_unsigned()).cast_signed();
                // SAFETY: the caller's data; the chain.
                if unsafe { SMIME_crlf_copy(dcont, cmsbio, f) } == 0 {
                    break 'err 0;
                }
                // SAFETY: the memory BIO; the caller's.
                if has(flags, CMS_TEXT) && unsafe { SMIME_text(tmpout, out) } == 0 {
                    raise(CMS_R_SMIME_TEXT_ERROR, F);
                    break 'err 0;
                }
            } else {
                // SAFETY: the object; the content's BIO, or NULL.
                cmsbio = unsafe { super::base::CMS_dataInit(cms, tmpin) };
                if cmsbio.is_null() {
                    break 'err 0;
                }
                // SAFETY: the caller's BIO; the chain.
                if !unsafe { copy_content(out, cmsbio, flags) } {
                    break 'err 0;
                }
            }
            if !has(flags, CMS_NO_CONTENT_VERIFY) {
                for i in 0..count {
                    // SAFETY: a signer info; the chain.
                    if unsafe { super::sd::CMS_SignerInfo_verify_content(si_at(i), cmsbio) } <= 0 {
                        raise(CMS_R_CONTENT_VERIFY_ERROR, F);
                        break 'err 0;
                    }
                }
            }
            1
        };
        if !tmpin_failed {
            if binary_detached {
                if !cmsbio.is_null() {
                    free_upto(cmsbio, tmpout);
                }
                if tmpin != dcont {
                    // SAFETY: the BIO made here, or NULL.
                    unsafe { BIO_free(tmpin) };
                }
            } else if !dcont.is_null() && tmpin == dcont {
                if !cmsbio.is_null() {
                    free_upto(cmsbio, dcont);
                }
            } else if !cmsbio.is_null() {
                // SAFETY: the chain made here.
                unsafe { BIO_free_all(cmsbio) };
            } else if tmpin != dcont {
                // SAFETY: as above, or NULL.
                unsafe { BIO_free(tmpin) };
            }
            if out != tmpout {
                // SAFETY: the BIO made here, or NULL.
                unsafe { BIO_free_all(tmpout) };
            }
        }
        for c in si_chains {
            // SAFETY: a chain with its references, or NULL.
            unsafe { OSSL_STACK_OF_X509_free(c) };
        }
        // SAFETY: the lists made here, with their references, or NULL.
        unsafe { OPENSSL_sk_pop_free(untrusted.cast(), Some(x509_free)) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_pop_free(crls.cast(), Some(crl_free)) };
        ret
    }
}

ffi_export! {
    /// Verifies a signed receipt and checks it against the request in `ocms`: 1, or 0.
    ///
    /// # Safety
    /// `rcms` and `ocms` are NULL or live objects; the others NULL or live.
    pub unsafe extern "C" fn CMS_verify_receipt(rcms: *mut CMS_ContentInfo, ocms: *mut CMS_ContentInfo, certs: *mut stack_st_X509, store: *mut X509_STORE, flags: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        let flags = flags & !(CMS_DETACHED | CMS_TEXT).cast_unsigned();
        // SAFETY: the caller's guarantee.
        let r = unsafe { CMS_verify(rcms, certs, store, ptr::null_mut(), ptr::null_mut(), flags) };
        if r <= 0 {
            return r;
        }
        // SAFETY: as above.
        unsafe { super::ess::receipt_verify(rcms, ocms) }
    }
}

ffi_export! {
    /// SignedData over `data`, signed by `pkey` for `signcert` (if given) with `certs`,
    /// finished unless streaming or partial. NULL on failure.
    ///
    /// # Safety
    /// Each pointer is NULL or live; `propq` NULL or a C string.
    pub unsafe extern "C" fn CMS_sign_ex(signcert: *mut X509, pkey: *mut EVP_PKEY, certs: *mut stack_st_X509, data: *mut BIO, flags: c_uint, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut CMS_ContentInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        const F: &str = "CMS_sign_ex";
        let has = |f: c_int| flags & f.cast_unsigned() != 0;
        // SAFETY: the caller's guarantee.
        let cms = unsafe { CMS_ContentInfo_new_ex(libctx, propq) };
        let ok = 'err: {
            // SAFETY: the new object, or NULL.
            if cms.is_null() || unsafe { super::sd::CMS_SignedData_init(cms) } == 0 {
                raise(ERR_R_CMS_LIB, F);
                break 'err false;
            }
            if has(CMS_ASCIICRLF) {
                let obj = super::base::nid_obj(NID_id_ct_asciiTextWithCRLF);
                // SAFETY: the object; a static object.
                if unsafe { super::base::CMS_set1_eContentType(cms, obj) } == 0 {
                    raise(ERR_R_CMS_LIB, F);
                    break 'err false;
                }
            }
            // SAFETY: as above; the caller's certificate and key.
            if !pkey.is_null() && unsafe { super::sd::CMS_add1_signer(cms, signcert, pkey, ptr::null(), flags) }.is_null() {
                raise(CMS_R_ADD_SIGNER_ERROR, F);
                break 'err false;
            }
            // SAFETY: the caller's certificates, or NULL.
            for i in 0..unsafe { crate::stack::OPENSSL_sk_num(certs.cast()) } {
                // SAFETY: an index within them.
                let x = unsafe { crate::stack::OPENSSL_sk_value(certs.cast(), i) }.cast::<X509>();
                // SAFETY: the object; a certificate.
                if unsafe { super::base::CMS_add1_cert(cms, x) } == 0 {
                    raise(ERR_R_CMS_LIB, F);
                    break 'err false;
                }
            }
            if !has(CMS_DETACHED) {
                // SAFETY: the object.
                unsafe { CMS_set_detached(cms, 0) };
            }
            // SAFETY: the object; the caller's data.
            flags & (CMS_STREAM | CMS_PARTIAL).cast_unsigned() != 0 || unsafe { CMS_final(cms, data, ptr::null_mut(), flags) } != 0
        };
        if ok {
            return cms;
        }
        // SAFETY: the object made here, or NULL.
        unsafe { CMS_ContentInfo_free(cms) };
        ptr::null_mut()
    }
}

ffi_export! {
    /// [`CMS_sign_ex`] in the default library context.
    ///
    /// # Safety
    /// As for [`CMS_sign_ex`].
    pub unsafe extern "C" fn CMS_sign(signcert: *mut X509, pkey: *mut EVP_PKEY, certs: *mut stack_st_X509, data: *mut BIO, flags: c_uint) -> *mut CMS_ContentInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        unsafe { CMS_sign_ex(signcert, pkey, certs, data, flags, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// A signed receipt (RFC 2634) for the request in `si`, signed by `pkey` for `signcert`:
    /// the new object, or NULL.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; the others NULL or live.
    pub unsafe extern "C" fn CMS_sign_receipt(si: *mut CMS_SignerInfo, signcert: *mut X509, pkey: *mut EVP_PKEY, certs: *mut stack_st_X509, flags: c_uint) -> *mut CMS_ContentInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        const F: &str = "CMS_sign_receipt";
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { super::att::si_of(si) }) else { return ptr::null_mut() };
        let (libctx, propq) = super::base::ctx_parts(s.cms_ctx);
        let flags = (flags & !(CMS_STREAM | CMS_TEXT).cast_unsigned()) | (CMS_PARTIAL | CMS_BINARY | CMS_DETACHED).cast_unsigned();
        if pkey.is_null() || signcert.is_null() {
            raise(CMS_R_NO_KEY_OR_CERT, F);
            return ptr::null_mut();
        }
        let cms: *mut CMS_ContentInfo;
        let mut os: *mut ASN1_OCTET_STRING = ptr::null_mut();
        let mut rct_cont: *mut BIO = ptr::null_mut();
        let ok = 'err: {
            // SAFETY: the caller's certificates; the signer's context.
            cms = unsafe { CMS_sign_ex(ptr::null_mut(), ptr::null_mut(), certs, ptr::null_mut(), flags, libctx, propq) };
            if cms.is_null() {
                break 'err false;
            }
            let obj = super::base::nid_obj(NID_id_smime_ct_receipt);
            // SAFETY: the new object; a static object.
            if unsafe { super::base::CMS_set1_eContentType(cms, obj) } == 0 {
                break 'err false;
            }
            // SAFETY: the object; the caller's certificate and key.
            let rct_si = unsafe { super::sd::CMS_add1_signer(cms, signcert, pkey, ptr::null(), flags) };
            if rct_si.is_null() {
                raise(CMS_R_ADD_SIGNER_ERROR, F);
                break 'err false;
            }
            // SAFETY: the caller's signer info.
            os = unsafe { super::ess::encode_receipt(si) };
            // SAFETY: the receipt's string, or NULL.
            let Some(o) = (unsafe { os.as_ref() }) else { break 'err false };
            // SAFETY: the receipt's octets, which outlive the BIO.
            rct_cont = unsafe { BIO_new_mem_buf(o.data.cast(), o.length) };
            if rct_cont.is_null() {
                break 'err false;
            }
            // SAFETY: the receipt's signer; the caller's.
            if !unsafe { super::ess::msg_sig_digest_add1(rct_si, s) } {
                break 'err false;
            }
            // SAFETY: the object; the receipt.
            if unsafe { CMS_final(cms, rct_cont, ptr::null_mut(), flags) } == 0 {
                break 'err false;
            }
            // SAFETY: the object.
            let pos = unsafe { CMS_get0_content(cms) };
            if pos.is_null() {
                break 'err false;
            }
            // SAFETY: the content's slot, empty (detached); the object takes the receipt.
            unsafe { pos.write(os) };
            true
        };
        // SAFETY: the BIO made here, or NULL.
        unsafe { BIO_free(rct_cont) };
        if ok {
            return cms;
        }
        // SAFETY: the values made here, or NULL.
        unsafe { CMS_ContentInfo_free(cms) };
        // SAFETY: as above.
        unsafe { crate::asn1::string::ASN1_OCTET_STRING_free(os) };
        ptr::null_mut()
    }
}
