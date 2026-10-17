//! PKCS#7's one-call operations (`pk7_smime.c`): signing, verifying, encrypting, and
//! decrypting a content, over the data path of [`super::doit`].

use core::ffi::{CStr, c_char, c_int};
use core::ptr;

use rustyssl_abi::{
    BIO, BIO_C_GET_CIPHER_STATUS, BIO_TYPE_CIPHER, ERR_LIB_PKCS7, ERR_R_BIO_LIB, ERR_R_CRYPTO_LIB,
    ERR_R_PKCS7_LIB, ERR_R_X509_LIB, EVP_CIPHER, EVP_MD, EVP_PKEY, NID_aes_128_cbc,
    NID_aes_192_cbc, NID_aes_256_cbc, NID_des_cbc, NID_des_ede3_cbc, NID_id_Gost28147_89,
    NID_id_GostR3411_94, NID_id_GostR3411_2012_256, NID_id_GostR3411_2012_512, NID_pkcs7_data,
    NID_pkcs7_enveloped, NID_pkcs7_signed, NID_pkcs7_signedAndEnveloped, NID_rc2_cbc, OSSL_LIB_CTX,
    PKCS7, PKCS7_DETACHED, PKCS7_NO_DUAL_CONTENT, PKCS7_NOATTR, PKCS7_NOCERTS, PKCS7_NOCHAIN,
    PKCS7_NOCRL, PKCS7_NOINTERN, PKCS7_NOSIGS, PKCS7_NOSMIMECAP, PKCS7_NOVERIFY,
    PKCS7_OP_SET_DETACHED_SIGNATURE, PKCS7_PARTIAL, PKCS7_R_CERTIFICATE_VERIFY_ERROR,
    PKCS7_R_CONTENT_AND_DATA_PRESENT, PKCS7_R_DECRYPT_ERROR, PKCS7_R_ERROR_ADDING_RECIPIENT,
    PKCS7_R_ERROR_SETTING_CIPHER, PKCS7_R_INVALID_NULL_POINTER, PKCS7_R_NO_CONTENT,
    PKCS7_R_NO_MATCHING_DIGEST_TYPE_FOUND, PKCS7_R_NO_SIGNATURES_ON_DATA, PKCS7_R_NO_SIGNERS,
    PKCS7_R_PKCS7_ADD_SIGNATURE_ERROR, PKCS7_R_PKCS7_ADD_SIGNER_ERROR, PKCS7_R_PKCS7_DATASIGN,
    PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE, PKCS7_R_SIGNATURE_FAILURE,
    PKCS7_R_SIGNER_CERTIFICATE_NOT_FOUND, PKCS7_R_SMIME_TEXT_ERROR, PKCS7_R_WRONG_CONTENT_TYPE,
    PKCS7_REUSE_DIGEST, PKCS7_SIGNER_INFO, PKCS7_STREAM, PKCS7_TEXT, X509, X509_ADD_FLAG_NO_DUP,
    X509_STORE, stack_st_X509, stack_st_X509_ALGOR,
};

use super::doit::{
    PKCS7_SIGNER_INFO_sign, PKCS7_dataDecode, PKCS7_dataFinal, PKCS7_dataInit,
    PKCS7_signatureVerify, ctx_parts, is_detached, mem_bio,
};
use super::{
    PKCS7_add_attrib_content_type, PKCS7_add_attrib_smimecap, PKCS7_add_certificate,
    PKCS7_add_recipient, PKCS7_add_signature, PKCS7_add1_attrib_digest, PKCS7_content_new,
    PKCS7_ctrl, PKCS7_digest_from_attributes, PKCS7_free, PKCS7_get_signer_info, PKCS7_new_ex,
    PKCS7_set_cipher, PKCS7_set_type, PKCS7_simple_smimecap, certificates, ctx_of, nid_of, p7_of,
    raise, sign_of, type_nid,
};
use crate::asn1::mime::{SMIME_crlf_copy, SMIME_text};
use crate::asn1::tpl::items::X509_ALGOR_free;
use crate::bio::buffer::BIO_f_buffer;
use crate::bio::{
    BIO_ctrl, BIO_free, BIO_free_all, BIO_method_type, BIO_new, BIO_pop, BIO_push, BIO_read,
    BIO_write,
};
use crate::err;
use crate::evp::legacy_cipher::EVP_get_cipherbyname;
use crate::evp::legacy_md::EVP_get_digestbyname;
use crate::ffi::ffi_export;
use crate::objects::{OBJ_cmp, OBJ_nid2sn};
use crate::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_value,
};
use crate::x509::cert::{X509_check_private_key, X509_find_by_issuer_and_serial};
use crate::x509::ctx::{
    X509_STORE_CTX_free, X509_STORE_CTX_get_error, X509_STORE_CTX_init, X509_STORE_CTX_new_ex,
    X509_STORE_CTX_set_default, X509_STORE_CTX_set0_crls, X509_verify_cert_error_string,
};
use crate::x509::purpose::X509_add_cert;
use crate::x509::verify::X509_verify_cert;

/// `pk7_smime.c`'s copy buffer.
const BUFFERSIZE: usize = 4096;

/// `PKCS7_set_detached`.
fn set_detached(p7: *mut PKCS7) {
    // SAFETY: a live object.
    unsafe { PKCS7_ctrl(p7, PKCS7_OP_SET_DETACHED_SIGNATURE, 1, ptr::null_mut()) };
}

ffi_export! {
    /// Makes SignedData over `data`, signed by `pkey` for `signcert` (if `pkey` is given) with
    /// `certs` included, in `libctx`: finished unless `PKCS7_STREAM` or `PKCS7_PARTIAL` asks
    /// otherwise. NULL on failure.
    ///
    /// # Safety
    /// Each pointer is NULL or live; `propq` NULL or a C string.
    pub unsafe extern "C" fn PKCS7_sign_ex(signcert: *mut X509, pkey: *mut EVP_PKEY, certs: *mut stack_st_X509, data: *mut BIO, flags: c_int, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut PKCS7
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        const F: &str = "PKCS7_sign_ex";
        // SAFETY: the caller's context and properties.
        let p7 = unsafe { PKCS7_new_ex(libctx, propq) };
        if p7.is_null() {
            raise(ERR_R_PKCS7_LIB, F);
            return ptr::null_mut();
        }
        let ok = 'err: {
            // SAFETY: the new object.
            if unsafe { PKCS7_set_type(p7, NID_pkcs7_signed) } == 0 || unsafe { PKCS7_content_new(p7, NID_pkcs7_data) } == 0 {
                break 'err false;
            }
            // SAFETY: the object; the caller's certificate and key.
            if !pkey.is_null() && unsafe { PKCS7_sign_add_signer(p7, signcert, pkey, ptr::null(), flags) }.is_null() {
                raise(PKCS7_R_PKCS7_ADD_SIGNER_ERROR, F);
                break 'err false;
            }
            if flags & PKCS7_NOCERTS == 0 {
                // SAFETY: the caller's certificates, or NULL.
                for i in 0..unsafe { OPENSSL_sk_num(certs.cast()) } {
                    // SAFETY: an index within them.
                    let x = unsafe { OPENSSL_sk_value(certs.cast(), i) }.cast::<X509>();
                    // SAFETY: the object; a certificate.
                    if unsafe { PKCS7_add_certificate(p7, x) } == 0 {
                        break 'err false;
                    }
                }
            }
            if flags & PKCS7_DETACHED != 0 {
                set_detached(p7);
            }
            if flags & (PKCS7_STREAM | PKCS7_PARTIAL) != 0 {
                return p7;
            }
            // SAFETY: the object; the caller's data.
            unsafe { PKCS7_final(p7, data, flags) != 0 }
        };
        if ok {
            return p7;
        }
        // SAFETY: the object made here.
        unsafe { PKCS7_free(p7) };
        ptr::null_mut()
    }
}

ffi_export! {
    /// [`PKCS7_sign_ex`] in the default library context.
    ///
    /// # Safety
    /// As for [`PKCS7_sign_ex`].
    pub unsafe extern "C" fn PKCS7_sign(signcert: *mut X509, pkey: *mut EVP_PKEY, certs: *mut stack_st_X509, data: *mut BIO, flags: c_int) -> *mut PKCS7
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS7_sign_ex(signcert, pkey, certs, data, flags, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Writes `data` through the object's chain (converting line ends unless `PKCS7_BINARY`)
    /// and finishes the object: 1, or 0.
    ///
    /// # Safety
    /// `p7` is NULL or a live object; `data` a live BIO.
    pub unsafe extern "C" fn PKCS7_final(p7: *mut PKCS7, data: *mut BIO, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        const F: &str = "PKCS7_final";
        // SAFETY: the caller's guarantee.
        let p7bio = unsafe { PKCS7_dataInit(p7, ptr::null_mut()) };
        if p7bio.is_null() {
            raise(ERR_R_PKCS7_LIB, F);
            return 0;
        }
        let ok = 'err: {
            // SAFETY: the caller's BIO; the chain.
            if unsafe { SMIME_crlf_copy(data, p7bio, flags) } == 0 {
                break 'err false;
            }
            // SAFETY: the chain.
            unsafe { BIO_ctrl(p7bio, rustyssl_abi::BIO_CTRL_FLUSH, 0, ptr::null_mut()) };
            // SAFETY: as above.
            if unsafe { PKCS7_dataFinal(p7, p7bio) } == 0 {
                raise(PKCS7_R_PKCS7_DATASIGN, F);
                break 'err false;
            }
            true
        };
        // SAFETY: the chain made here.
        unsafe { BIO_free_all(p7bio) };
        c_int::from(ok)
    }
}

/// `add_cipher_smcap`/`add_digest_smcap`: the capability, if the algorithm is known.
fn add_smcap(sk: *mut stack_st_X509_ALGOR, nid: c_int, arg: c_int, cipher: bool) -> bool {
    // SAFETY: any NID.
    let sn = unsafe { OBJ_nid2sn(nid) };
    let known = if cipher {
        // SAFETY: NULL or a static name.
        !unsafe { EVP_get_cipherbyname(sn) }.is_null()
    } else {
        // SAFETY: as above.
        !unsafe { EVP_get_digestbyname(sn) }.is_null()
    };
    // SAFETY: a live list.
    !known || unsafe { PKCS7_simple_smimecap(sk, nid, arg) } != 0
}

/// `pkcs7_copy_existing_digest`: the message digest of an earlier signer with the same digest
/// algorithm and signed attributes.
///
/// # Safety
/// `p7` is a live object; `si` one of its signer infos.
unsafe fn copy_existing_digest(p7: *mut PKCS7, si: *mut PKCS7_SIGNER_INFO, f: &str) -> bool {
    // SAFETY: the caller's guarantee.
    let sinfos = unsafe { PKCS7_get_signer_info(p7) };
    // SAFETY: the caller's signer info.
    let dig = unsafe { (*si).digest_alg };
    // SAFETY: its digest algorithm.
    let alg = unsafe { (*dig).algorithm };
    let mut osdig = ptr::null_mut();
    // SAFETY: the object's signer infos, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(sinfos.cast()) } {
        // SAFETY: an index within them.
        let sitmp = unsafe { OPENSSL_sk_value(sinfos.cast(), i) }.cast::<PKCS7_SIGNER_INFO>();
        if sitmp == si {
            break;
        }
        // SAFETY: a signer info of the object.
        let s = unsafe { &*sitmp };
        // SAFETY: its attributes, or NULL.
        if unsafe { OPENSSL_sk_num(s.auth_attr.cast()) } <= 0 {
            continue;
        }
        // SAFETY: its digest algorithm.
        let other = unsafe { (*s.digest_alg).algorithm };
        // SAFETY: live objects.
        if unsafe { OBJ_cmp(alg, other) } == 0 {
            // SAFETY: its attributes.
            osdig = unsafe { PKCS7_digest_from_attributes(s.auth_attr) };
            break;
        }
    }
    // SAFETY: NULL or the attribute's string.
    if let Some(d) = unsafe { osdig.as_ref() } {
        // SAFETY: the signer info; the digest's octets.
        return unsafe { PKCS7_add1_attrib_digest(si, d.data, d.length) } != 0;
    }
    raise(PKCS7_R_NO_MATCHING_DIGEST_TYPE_FOUND, f);
    false
}

ffi_export! {
    /// Adds a signer for `signcert` and `pkey` with digest `md` (the key's default for NULL):
    /// its certificate and, unless `PKCS7_NOATTR`, the content type and S/MIME capabilities as
    /// signed attributes. The new signer info, or NULL.
    ///
    /// # Safety
    /// `p7` is NULL or a live object; the others live, `md` NULL or live.
    pub unsafe extern "C" fn PKCS7_sign_add_signer(p7: *mut PKCS7, signcert: *mut X509, pkey: *mut EVP_PKEY, md: *const EVP_MD, flags: c_int) -> *mut PKCS7_SIGNER_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        const F: &str = "PKCS7_sign_add_signer";
        // SAFETY: the caller's certificate and key.
        if unsafe { X509_check_private_key(signcert, pkey) } == 0 {
            raise(PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE, F);
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let si = unsafe { PKCS7_add_signature(p7, signcert, pkey, md) };
        if si.is_null() {
            raise(PKCS7_R_PKCS7_ADD_SIGNATURE_ERROR, F);
            return ptr::null_mut();
        }
        // SAFETY: the new signer info, the object's.
        unsafe { (*si).ctx = ctx_of(p7) };
        let mut smcap: *mut stack_st_X509_ALGOR = ptr::null_mut();
        let ok = 'err: {
            // SAFETY: the object; the caller's certificate.
            if flags & PKCS7_NOCERTS == 0 && unsafe { PKCS7_add_certificate(p7, signcert) } == 0 {
                break 'err false;
            }
            if flags & PKCS7_NOATTR != 0 {
                break 'err true;
            }
            // SAFETY: the signer info.
            if unsafe { PKCS7_add_attrib_content_type(si, ptr::null_mut()) } == 0 {
                break 'err false;
            }
            if flags & PKCS7_NOSMIMECAP == 0 {
                // SAFETY: no preconditions.
                smcap = unsafe { OPENSSL_sk_new_null() }.cast();
                if smcap.is_null() {
                    raise(ERR_R_CRYPTO_LIB, F);
                    break 'err false;
                }
                let caps = [
                    (NID_aes_256_cbc, -1, true),
                    (NID_id_GostR3411_2012_256, -1, false),
                    (NID_id_GostR3411_2012_512, -1, false),
                    (NID_id_GostR3411_94, -1, false),
                    (NID_id_Gost28147_89, -1, true),
                    (NID_aes_192_cbc, -1, true),
                    (NID_aes_128_cbc, -1, true),
                    (NID_des_ede3_cbc, -1, true),
                    (NID_rc2_cbc, 128, true),
                    (NID_rc2_cbc, 64, true),
                    (NID_des_cbc, -1, true),
                    (NID_rc2_cbc, 40, true),
                ];
                if !caps.iter().all(|&(nid, arg, cipher)| add_smcap(smcap, nid, arg, cipher)) {
                    break 'err false;
                }
                // SAFETY: the signer info; the list.
                if unsafe { PKCS7_add_attrib_smimecap(si, smcap) } == 0 {
                    break 'err false;
                }
            }
            if flags & PKCS7_REUSE_DIGEST != 0 {
                // SAFETY: the object and its signer info.
                if !unsafe { copy_existing_digest(p7, si, F) } {
                    break 'err false;
                }
                // SAFETY: as above.
                if flags & PKCS7_PARTIAL == 0 && unsafe { PKCS7_SIGNER_INFO_sign(si) } == 0 {
                    break 'err false;
                }
            }
            true
        };
        // SAFETY: the list made here, or NULL.
        unsafe { OPENSSL_sk_pop_free(smcap.cast(), Some(algor_free)) };
        if ok { si } else { ptr::null_mut() }
    }
}

/// `X509_ALGOR_free` as a stack's free function.
unsafe extern "C" fn algor_free(p: *mut core::ffi::c_void) {
    // SAFETY: an algorithm identifier of the list.
    unsafe { X509_ALGOR_free(p.cast()) };
}

/// `ossl_x509_add_certs_new`: `certs` added to `*sk`, made when the first one comes.
///
/// # Safety
/// `*sk` is NULL or a live list; `certs` NULL or a live list.
unsafe fn add_certs_new(
    sk: &mut *mut stack_st_X509,
    certs: *mut stack_st_X509,
    flags: c_int,
) -> bool {
    // SAFETY: the caller's guarantee.
    for i in 0..unsafe { OPENSSL_sk_num(certs.cast()) } {
        // SAFETY: an index within them.
        let cert = unsafe { OPENSSL_sk_value(certs.cast(), i) }.cast::<X509>();
        if sk.is_null() {
            // SAFETY: no preconditions.
            *sk = unsafe { OPENSSL_sk_new_null() }.cast();
            if sk.is_null() {
                err::raise(
                    rustyssl_abi::ERR_LIB_X509,
                    ERR_R_CRYPTO_LIB,
                    "ossl_x509_add_cert_new",
                );
                return false;
            }
        }
        // SAFETY: a live list; a certificate.
        if unsafe { X509_add_cert(*sk, cert, flags) } == 0 {
            return false;
        }
    }
    true
}

ffi_export! {
    /// Verifies SignedData: each signer's certificate against `store` (unless
    /// `PKCS7_NOVERIFY`), then each signature over the content (`indata` if detached), which is
    /// copied to `out` (its text, for `PKCS7_TEXT`). 1, or 0.
    ///
    /// # Safety
    /// `p7` is NULL or a live object; the others NULL or live.
    pub unsafe extern "C" fn PKCS7_verify(p7: *mut PKCS7, certs: *mut stack_st_X509, store: *mut X509_STORE, indata: *mut BIO, out: *mut BIO, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        const F: &str = "PKCS7_verify";
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p7_of(p7) }) else {
            raise(PKCS7_R_INVALID_NULL_POINTER, F);
            return 0;
        };
        if nid_of(p) != NID_pkcs7_signed {
            raise(PKCS7_R_WRONG_CONTENT_TYPE, F);
            return 0;
        }
        let crls = sign_of(p).map_or(ptr::null_mut(), |s| s.crl);
        // `PKCS7_ctrl` borrows the object itself; `p` isn't used after it.
        let detached = is_detached(p7);
        if detached && indata.is_null() {
            raise(PKCS7_R_NO_CONTENT, F);
            return 0;
        }
        if flags & PKCS7_NO_DUAL_CONTENT != 0 && !detached && !indata.is_null() {
            raise(PKCS7_R_CONTENT_AND_DATA_PRESENT, F);
            return 0;
        }
        // SAFETY: a live object.
        let sinfos = unsafe { PKCS7_get_signer_info(p7) };
        // SAFETY: its signer infos, or NULL.
        let count = unsafe { OPENSSL_sk_num(sinfos.cast()) };
        if count <= 0 {
            raise(PKCS7_R_NO_SIGNATURES_ON_DATA, F);
            return 0;
        }
        // SAFETY: as above; the caller's certificates.
        let signers = unsafe { PKCS7_get0_signers(p7, certs, flags) };
        if signers.is_null() {
            return 0;
        }
        let (libctx, propq) = ctx_parts(ctx_of(p7));
        let text = flags & PKCS7_TEXT != 0;
        let mut untrusted: *mut stack_st_X509 = ptr::null_mut();
        // SAFETY: the object's context and properties.
        let cert_ctx = unsafe { X509_STORE_CTX_new_ex(libctx, propq) };
        let mut p7bio: *mut BIO = ptr::null_mut();
        let mut tmpout: *mut BIO = ptr::null_mut();
        let ok = 'err: {
            if cert_ctx.is_null() {
                break 'err false;
            }
            if flags & PKCS7_NOVERIFY == 0 {
                // SAFETY: the list, or NULL; the caller's certificates.
                if !unsafe { add_certs_new(&mut untrusted, certs, X509_ADD_FLAG_NO_DUP) } {
                    break 'err false;
                }
                // SAFETY: a live object.
                let included = unsafe { certificates(p7) };
                // SAFETY: as above; the object's certificates.
                if flags & PKCS7_NOCHAIN == 0 && !unsafe { add_certs_new(&mut untrusted, included, X509_ADD_FLAG_NO_DUP) } {
                    break 'err false;
                }
                // SAFETY: the signers.
                for k in 0..unsafe { OPENSSL_sk_num(signers.cast()) } {
                    // SAFETY: an index within them.
                    let signer = unsafe { OPENSSL_sk_value(signers.cast(), k) }.cast::<X509>();
                    // SAFETY: the context; the caller's store; the signer; the list.
                    if unsafe { X509_STORE_CTX_init(cert_ctx, store, signer, untrusted) } == 0 {
                        raise(ERR_R_X509_LIB, F);
                        break 'err false;
                    }
                    // SAFETY: the context.
                    if flags & PKCS7_NOCHAIN == 0 && unsafe { X509_STORE_CTX_set_default(cert_ctx, c"smime_sign".as_ptr()) } == 0 {
                        break 'err false;
                    }
                    if flags & PKCS7_NOCRL == 0 {
                        // SAFETY: the context; the object's CRLs, or NULL.
                        unsafe { X509_STORE_CTX_set0_crls(cert_ctx, crls) };
                    }
                    // SAFETY: the context.
                    if unsafe { X509_verify_cert(cert_ctx) } <= 0 {
                        // SAFETY: as above.
                        let j = unsafe { X509_STORE_CTX_get_error(cert_ctx) };
                        // SAFETY: any code.
                        let text = unsafe { X509_verify_cert_error_string(c_long_from(j)) };
                        // SAFETY: a static string.
                        let s = unsafe { CStr::from_ptr(text) };
                        let mut msg = b"Verify error: ".to_vec();
                        msg.extend_from_slice(s.to_bytes());
                        err::raise_with_bytes(rustyssl_abi::ERR_LIB_PKCS7, PKCS7_R_CERTIFICATE_VERIFY_ERROR, F, &msg);
                        break 'err false;
                    }
                }
            }
            // SAFETY: the object; the caller's data, or NULL.
            p7bio = unsafe { PKCS7_dataInit(p7, indata) };
            if p7bio.is_null() {
                break 'err false;
            }
            if text {
                tmpout = mem_bio();
                if tmpout.is_null() {
                    raise(ERR_R_BIO_LIB, F);
                    break 'err false;
                }
            } else {
                tmpout = out;
            }
            let mut buf = vec![0u8; BUFFERSIZE];
            let n = c_int::try_from(BUFFERSIZE).unwrap_or(0);
            loop {
                // SAFETY: the chain; room for `n` octets.
                let i = unsafe { BIO_read(p7bio, buf.as_mut_ptr().cast(), n) };
                if i <= 0 {
                    break;
                }
                if !tmpout.is_null() {
                    // SAFETY: a live BIO; the `i` octets read.
                    unsafe { BIO_write(tmpout, buf.as_ptr().cast(), i) };
                }
            }
            // SAFETY: the memory BIO; the caller's.
            if text && unsafe { SMIME_text(tmpout, out) } == 0 {
                raise(PKCS7_R_SMIME_TEXT_ERROR, F);
                break 'err false;
            }
            if flags & PKCS7_NOSIGS == 0 {
                for i in 0..count {
                    // SAFETY: an index within the signer infos.
                    let si = unsafe { OPENSSL_sk_value(sinfos.cast(), i) }.cast::<PKCS7_SIGNER_INFO>();
                    // SAFETY: the matching signer.
                    let signer = unsafe { OPENSSL_sk_value(signers.cast(), i) }.cast::<X509>();
                    // SAFETY: the chain; the object, its signer info, and its signer.
                    if unsafe { PKCS7_signatureVerify(p7bio, p7, si, signer) } <= 0 {
                        raise(PKCS7_R_SIGNATURE_FAILURE, F);
                        break 'err false;
                    }
                }
            }
            true
        };
        if text {
            // SAFETY: the memory BIO made here, or NULL.
            unsafe { BIO_free(tmpout) };
        }
        // SAFETY: the context made here, or NULL.
        unsafe { X509_STORE_CTX_free(cert_ctx) };
        while !p7bio.is_null() && p7bio != indata {
            // SAFETY: the chain made here, down to the caller's BIO.
            let next = unsafe { BIO_pop(p7bio) };
            // SAFETY: as above.
            unsafe { BIO_free(p7bio) };
            p7bio = next;
        }
        // SAFETY: lists of borrowed certificates.
        unsafe { OPENSSL_sk_free(signers.cast()) };
        // SAFETY: as above, or NULL.
        unsafe { OPENSSL_sk_free(untrusted.cast()) };
        c_int::from(ok)
    }
}

fn c_long_from(n: c_int) -> core::ffi::c_long {
    core::ffi::c_long::from(n)
}

ffi_export! {
    /// The signers' certificates, found by issuer and serial number in `certs` and (unless
    /// `PKCS7_NOINTERN`) the object's own, in signer order: a new list of borrowed
    /// certificates, or NULL.
    ///
    /// # Safety
    /// `p7` is NULL or a live object; `certs` NULL or a live list.
    pub unsafe extern "C" fn PKCS7_get0_signers(p7: *mut PKCS7, certs: *mut stack_st_X509, flags: c_int) -> *mut stack_st_X509
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        const F: &str = "PKCS7_get0_signers";
        if p7.is_null() {
            raise(PKCS7_R_INVALID_NULL_POINTER, F);
            return ptr::null_mut();
        }
        if type_nid(p7) != NID_pkcs7_signed {
            raise(PKCS7_R_WRONG_CONTENT_TYPE, F);
            return ptr::null_mut();
        }
        // SAFETY: a live object.
        let included = unsafe { certificates(p7) };
        // SAFETY: as above.
        let sinfos = unsafe { PKCS7_get_signer_info(p7) };
        // SAFETY: its signer infos, or NULL.
        let count = unsafe { OPENSSL_sk_num(sinfos.cast()) };
        if count <= 0 {
            raise(PKCS7_R_NO_SIGNERS, F);
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let signers = unsafe { OPENSSL_sk_new_null() };
        if signers.is_null() {
            raise(ERR_R_CRYPTO_LIB, F);
            return ptr::null_mut();
        }
        for i in 0..count {
            // SAFETY: an index within the signer infos.
            let si = unsafe { OPENSSL_sk_value(sinfos.cast(), i) }.cast::<PKCS7_SIGNER_INFO>();
            // SAFETY: a signer info, and its issuer and serial, or NULL.
            let ias = unsafe { si.as_ref() }.and_then(|s| unsafe { s.issuer_and_serial.as_ref() });
            let mut signer = ptr::null_mut();
            if let Some(ias) = ias {
                // SAFETY: the caller's certificates; a live name and serial.
                signer = unsafe { X509_find_by_issuer_and_serial(certs, ias.issuer, ias.serial) };
                if signer.is_null() && flags & PKCS7_NOINTERN == 0 {
                    // SAFETY: the object's certificates.
                    signer = unsafe { X509_find_by_issuer_and_serial(included, ias.issuer, ias.serial) };
                }
            }
            if signer.is_null() {
                raise(PKCS7_R_SIGNER_CERTIFICATE_NOT_FOUND, F);
                // SAFETY: the list made here.
                unsafe { OPENSSL_sk_free(signers) };
                return ptr::null_mut();
            }
            // SAFETY: as above; a borrowed certificate.
            if unsafe { OPENSSL_sk_push(signers, signer.cast()) } == 0 {
                // SAFETY: as above.
                unsafe { OPENSSL_sk_free(signers) };
                return ptr::null_mut();
            }
        }
        signers.cast()
    }
}

ffi_export! {
    /// Makes EnvelopedData of `in_` for `certs` with `cipher`, in `libctx`: finished unless
    /// `PKCS7_STREAM`. NULL on failure.
    ///
    /// # Safety
    /// Each pointer is NULL or live; `propq` NULL or a C string.
    pub unsafe extern "C" fn PKCS7_encrypt_ex(certs: *mut stack_st_X509, in_: *mut BIO, cipher: *const EVP_CIPHER, flags: c_int, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut PKCS7
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        const F: &str = "PKCS7_encrypt_ex";
        // SAFETY: the caller's context and properties.
        let p7 = unsafe { PKCS7_new_ex(libctx, propq) };
        if p7.is_null() {
            raise(ERR_R_PKCS7_LIB, F);
            return ptr::null_mut();
        }
        let ok = 'err: {
            // SAFETY: the new object.
            if unsafe { PKCS7_set_type(p7, NID_pkcs7_enveloped) } == 0 {
                break 'err false;
            }
            // SAFETY: as above; the caller's cipher.
            if unsafe { PKCS7_set_cipher(p7, cipher) } == 0 {
                raise(PKCS7_R_ERROR_SETTING_CIPHER, F);
                break 'err false;
            }
            // SAFETY: the caller's certificates, or NULL.
            for i in 0..unsafe { OPENSSL_sk_num(certs.cast()) } {
                // SAFETY: an index within them.
                let x = unsafe { OPENSSL_sk_value(certs.cast(), i) }.cast::<X509>();
                // SAFETY: the object; a certificate.
                if unsafe { PKCS7_add_recipient(p7, x) }.is_null() {
                    raise(PKCS7_R_ERROR_ADDING_RECIPIENT, F);
                    break 'err false;
                }
            }
            if flags & PKCS7_STREAM != 0 {
                return p7;
            }
            // SAFETY: the object; the caller's data.
            unsafe { PKCS7_final(p7, in_, flags) != 0 }
        };
        if ok {
            return p7;
        }
        // SAFETY: the object made here.
        unsafe { PKCS7_free(p7) };
        ptr::null_mut()
    }
}

ffi_export! {
    /// [`PKCS7_encrypt_ex`] in the default library context.
    ///
    /// # Safety
    /// As for [`PKCS7_encrypt_ex`].
    pub unsafe extern "C" fn PKCS7_encrypt(certs: *mut stack_st_X509, in_: *mut BIO, cipher: *const EVP_CIPHER, flags: c_int) -> *mut PKCS7
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS7_encrypt_ex(certs, in_, cipher, flags, ptr::null_mut(), ptr::null()) }
    }
}

/// `BIO_get_cipher_status` of a cipher BIO, true for any other.
fn cipher_ok(b: *mut BIO) -> bool {
    // SAFETY: a live BIO.
    if unsafe { BIO_method_type(b) } != BIO_TYPE_CIPHER {
        return true;
    }
    // SAFETY: a live cipher BIO.
    unsafe { BIO_ctrl(b, BIO_C_GET_CIPHER_STATUS, 0, ptr::null_mut()) > 0 }
}

ffi_export! {
    /// Decrypts EnvelopedData or SignedAndEnvelopedData with `pkey` (for `cert`'s recipient if
    /// given) into `data` (its text, for `PKCS7_TEXT`): 1, or 0.
    ///
    /// # Safety
    /// `p7` is NULL or a live object; `pkey` and `data` live; `cert` NULL or live.
    pub unsafe extern "C" fn PKCS7_decrypt(p7: *mut PKCS7, pkey: *mut EVP_PKEY, cert: *mut X509, data: *mut BIO, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        const F: &str = "PKCS7_decrypt";
        if p7.is_null() {
            raise(PKCS7_R_INVALID_NULL_POINTER, F);
            return 0;
        }
        let nid = type_nid(p7);
        if nid != NID_pkcs7_enveloped && nid != NID_pkcs7_signedAndEnveloped {
            raise(PKCS7_R_WRONG_CONTENT_TYPE, F);
            return 0;
        }
        // SAFETY: the caller's certificate and key.
        if !cert.is_null() && unsafe { X509_check_private_key(cert, pkey) } == 0 {
            raise(PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE, F);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let tmpmem = unsafe { PKCS7_dataDecode(p7, pkey, ptr::null_mut(), cert) };
        if tmpmem.is_null() {
            raise(PKCS7_R_DECRYPT_ERROR, F);
            return 0;
        }
        if flags & PKCS7_TEXT != 0 {
            // SAFETY: no preconditions.
            let method = unsafe { BIO_f_buffer() };
            // SAFETY: the built-in method.
            let tmpbuf = unsafe { BIO_new(method) };
            if tmpbuf.is_null() {
                raise(ERR_R_BIO_LIB, F);
                // SAFETY: the chain made here.
                unsafe { BIO_free_all(tmpmem) };
                return 0;
            }
            // SAFETY: live BIOs; the buffer takes the chain.
            let bread = unsafe { BIO_push(tmpbuf, tmpmem) };
            if bread.is_null() {
                raise(ERR_R_BIO_LIB, F);
                // SAFETY: the BIOs made here.
                unsafe { BIO_free_all(tmpbuf) };
                // SAFETY: as above.
                unsafe { BIO_free_all(tmpmem) };
                return 0;
            }
            // SAFETY: the chain; the caller's BIO.
            let mut ret = unsafe { SMIME_text(bread, data) };
            if ret > 0 && !cipher_ok(tmpmem) {
                ret = 0;
            }
            // SAFETY: the chain made here.
            unsafe { BIO_free_all(bread) };
            return ret;
        }
        let mut buf = vec![0u8; BUFFERSIZE];
        let n = c_int::try_from(BUFFERSIZE).unwrap_or(0);
        let mut ret = 0;
        loop {
            // SAFETY: the chain; room for `n` octets.
            let i = unsafe { BIO_read(tmpmem, buf.as_mut_ptr().cast(), n) };
            if i <= 0 {
                ret = c_int::from(cipher_ok(tmpmem));
                break;
            }
            // SAFETY: the caller's BIO; the `i` octets read.
            if unsafe { BIO_write(data, buf.as_ptr().cast(), i) } != i {
                break;
            }
        }
        // SAFETY: the chain made here.
        unsafe { BIO_free_all(tmpmem) };
        ret
    }
}
