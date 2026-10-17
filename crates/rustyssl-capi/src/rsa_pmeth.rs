//! The built-in RSA and RSA-PSS `EVP_PKEY_METHOD`s' functions (`rsa_pmeth.c`). A key whose `RSA`
//! has an application's method (a "foreign" key) stays a legacy key, and its contexts use these
//! instead of a provider; an application that copies or wraps the built-in methods
//! (`EVP_PKEY_meth_find`, `EVP_PKEY_meth_copy`) calls them too.
//!
//! As in OpenSSL, each operation is made of the `RSA_*` functions, so it goes through the key's
//! method: signing is `RSA_sign` (PKCS #1), `RSA_sign_ASN1_OCTET_STRING` (MDC2), or the padding
//! functions and `RSA_private_encrypt` (X9.31, PSS, raw); verifying, encrypting, and decrypting
//! likewise. The context data (`RSA_PKEY_CTX`) is rustyssl's own; the temporary buffer OpenSSL
//! keeps in it is a local one here.
//!
//! An RSA-PSS key generated with restrictions keeps them as OpenSSL's does, as the key's
//! `RSA_PSS_PARAMS` (`RSA_get0_pss_params`): signing with it starts from them and refuses others.

use core::ffi::{CStr, c_char, c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_R_UNKNOWN_DIGEST, BIGNUM, BN_GENCB, ERR_LIB_ASN1, ERR_LIB_EVP, ERR_LIB_RSA,
    ERR_R_PASSED_NULL_PARAMETER, EVP_MD, EVP_MD_FLAG_DIGALGID_ABSENT, EVP_PKEY,
    EVP_PKEY_CTRL_CMS_DECRYPT, EVP_PKEY_CTRL_CMS_ENCRYPT, EVP_PKEY_CTRL_CMS_SIGN,
    EVP_PKEY_CTRL_DIGESTINIT, EVP_PKEY_CTRL_GET_MD, EVP_PKEY_CTRL_GET_RSA_MGF1_MD,
    EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL, EVP_PKEY_CTRL_GET_RSA_OAEP_MD, EVP_PKEY_CTRL_GET_RSA_PADDING,
    EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN, EVP_PKEY_CTRL_MD, EVP_PKEY_CTRL_PEER_KEY,
    EVP_PKEY_CTRL_PKCS7_DECRYPT, EVP_PKEY_CTRL_PKCS7_ENCRYPT, EVP_PKEY_CTRL_PKCS7_SIGN,
    EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION, EVP_PKEY_CTRL_RSA_KEYGEN_BITS,
    EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES, EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, EVP_PKEY_CTRL_RSA_MGF1_MD,
    EVP_PKEY_CTRL_RSA_OAEP_LABEL, EVP_PKEY_CTRL_RSA_OAEP_MD, EVP_PKEY_CTRL_RSA_PADDING,
    EVP_PKEY_CTRL_RSA_PSS_SALTLEN, EVP_PKEY_CTX, EVP_PKEY_OP_KEYGEN, EVP_PKEY_OP_SIGN,
    EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_OP_VERIFY, EVP_PKEY_RSA_PSS, NID_md2,
    NID_md4, NID_md5, NID_md5_sha1, NID_mdc2, NID_mgf1, NID_ripemd160, NID_sha1, NID_sha3_224,
    NID_sha3_256, NID_sha3_384, NID_sha3_512, NID_sha224, NID_sha256, NID_sha384, NID_sha512,
    NID_sha512_224, NID_sha512_256, RSA, RSA_DEFAULT_PRIME_NUM, RSA_F4, RSA_NO_PADDING,
    RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING, RSA_PKCS1_OAEP_PADDING, RSA_PKCS1_PADDING,
    RSA_PKCS1_PSS_PADDING, RSA_PSS_PARAMS, RSA_PSS_SALTLEN_AUTO, RSA_PSS_SALTLEN_DIGEST,
    RSA_PSS_SALTLEN_MAX, RSA_R_ALGORITHM_MISMATCH, RSA_R_BAD_E_VALUE, RSA_R_DIGEST_NOT_ALLOWED,
    RSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE, RSA_R_INVALID_DIGEST, RSA_R_INVALID_DIGEST_LENGTH,
    RSA_R_INVALID_MGF1_MD, RSA_R_INVALID_PADDING_MODE, RSA_R_INVALID_PSS_SALTLEN,
    RSA_R_INVALID_SALT_LENGTH, RSA_R_INVALID_TRAILER, RSA_R_INVALID_X931_DIGEST,
    RSA_R_KEY_PRIME_NUM_INVALID, RSA_R_KEY_SIZE_TOO_SMALL, RSA_R_MGF1_DIGEST_NOT_ALLOWED,
    RSA_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE, RSA_R_PSS_SALTLEN_TOO_SMALL,
    RSA_R_UNKNOWN_PADDING_TYPE, RSA_R_VALUE_MISSING, RSA_X931_PADDING, V_ASN1_NULL,
    V_ASN1_SEQUENCE, V_ASN1_UNDEF, X509_ALGOR,
};
use rustyssl_crypto::rsa::MAX_PRIMES;

use crate::asn1::any::ASN1_TYPE_set;
use crate::asn1::integer::{ASN1_INTEGER_get, ASN1_INTEGER_set};
use crate::asn1::string::{ASN1_INTEGER_new, ASN1_STRING_free};
use crate::asn1::tpl::items::{ASN1_TYPE_new, X509_ALGOR_free, X509_ALGOR_it, X509_ALGOR_new};
use crate::asn1::tpl::util::{ASN1_TYPE_unpack_sequence, ASN1_item_pack};
use crate::bn::prime::{BN_GENCB_free, BN_GENCB_get_arg, BN_GENCB_new, BN_GENCB_set};
use crate::bn::{BN_dup, BN_free, BN_is_odd, BN_is_one, BN_new, BN_set_word};
use crate::err;
use crate::evp::ctrl::EVP_PKEY_CTX_md;
use crate::evp::digest::{EVP_MD_get_flags, EVP_MD_get_size, EVP_MD_get_type, EVP_MD_is_a};
use crate::evp::legacy_md::{EVP_get_digestbyname, EVP_sha1};
use crate::evp::pkey::EVP_PKEY_assign;
use crate::evp::pkey::rsa::EVP_PKEY_get0_RSA;
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_get_data, EVP_PKEY_CTX_get0_pkey, EVP_PKEY_CTX_set_data,
    EVP_PKEY_CTX_set0_keygen_info, legacy_gen_progress, legacy_op,
};
use crate::evp::setters::{
    EVP_PKEY_CTX_set_rsa_keygen_bits, EVP_PKEY_CTX_set_rsa_keygen_primes,
    EVP_PKEY_CTX_set_rsa_padding, EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen,
    EVP_PKEY_CTX_set_rsa_pss_saltlen, EVP_PKEY_CTX_set0_rsa_oaep_label,
    EVP_PKEY_CTX_set1_rsa_keygen_pubexp,
};
use crate::ffi::ffi_callback;
use crate::mem;
use crate::objects::{OBJ_nid2obj, OBJ_nid2sn, OBJ_obj2nid};
use crate::rsa::rsa;
use crate::rsa_asn1::{RSA_PSS_PARAMS_free, RSA_PSS_PARAMS_new};
use crate::rsa_gen::MIN_MODULUS_BITS;
use crate::rsa_lib::{
    RSA_bits, RSA_free, RSA_new, RSA_private_decrypt, RSA_private_encrypt, RSA_public_decrypt,
    RSA_public_encrypt, RSA_size,
};
use crate::rsa_ops::{
    RSA_X931_hash_id, RSA_generate_multi_prime_key, RSA_padding_add_PKCS1_OAEP_mgf1,
    RSA_padding_add_PKCS1_PSS_mgf1, RSA_padding_check_PKCS1_OAEP_mgf1, RSA_sign,
    RSA_sign_ASN1_OCTET_STRING, RSA_verify, RSA_verify_PKCS1_PSS_mgf1, ossl_verify,
};
use crate::string::OPENSSL_hexstr2buf;

/// `RSA_PKEY_CTX`: a context's settings.
struct RsaPkeyCtx {
    nbits: c_int,
    /// Owned.
    pub_exp: *mut BIGNUM,
    primes: c_int,
    /// `keygen_info`'s two values, during generation.
    gentmp: [c_int; 2],
    pad_mode: c_int,
    md: *const EVP_MD,
    mgf1md: *const EVP_MD,
    saltlen: c_int,
    /// The minimum salt length, or -1 without PSS restrictions.
    min_saltlen: c_int,
    /// Owned, from the C allocator (`EVP_PKEY_CTX_set0_rsa_oaep_label`'s).
    oaep_label: *mut c_uchar,
    oaep_labellen: usize,
    implicit_rejection: c_int,
}

impl RsaPkeyCtx {
    fn restricted(&self) -> bool {
        self.min_saltlen != -1
    }
}

impl Drop for RsaPkeyCtx {
    fn drop(&mut self) {
        // SAFETY: the context's own number, or NULL.
        unsafe { BN_free(self.pub_exp) };
        // SAFETY: the context's own label, or NULL, from the C allocator.
        unsafe { mem::release(self.oaep_label.cast()) };
    }
}

/// The context's settings.
///
/// # Safety
/// `ctx` is NULL or a live context whose data is NULL or an `RsaPkeyCtx`; nothing else uses the
/// settings while the reference lives.
unsafe fn settings<'a>(ctx: *const EVP_PKEY_CTX) -> Option<&'a mut RsaPkeyCtx> {
    // SAFETY: the caller's guarantee.
    let data = unsafe { EVP_PKEY_CTX_get_data(ctx) };
    // SAFETY: as above.
    unsafe { data.cast::<RsaPkeyCtx>().as_mut() }
}

/// `pkey_ctx_is_pss`.
///
/// # Safety
/// `ctx` is NULL or a live context.
unsafe fn is_pss(ctx: *const EVP_PKEY_CTX) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { legacy_op(ctx) }.1 == EVP_PKEY_RSA_PSS
}

/// The context's key's `RSA` (`EVP_PKEY_get0_RSA(ctx->pkey)`).
///
/// # Safety
/// `ctx` is NULL or a live context.
unsafe fn key(ctx: *mut EVP_PKEY_CTX) -> *mut RSA {
    // SAFETY: the caller's guarantee.
    let pkey = unsafe { EVP_PKEY_CTX_get0_pkey(ctx) };
    if pkey.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the context's key.
    unsafe { EVP_PKEY_get0_RSA(pkey) }.cast_mut()
}

/// The digest's size, or 0 for none.
///
/// # Safety
/// `md` is NULL or a live digest.
unsafe fn md_size(md: *const EVP_MD) -> c_int {
    if md.is_null() {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    unsafe { EVP_MD_get_size(md) }
}

/// The digest's NID (`EVP_MD_get_type`), or 0 for none.
///
/// # Safety
/// `md` is NULL or a live digest.
unsafe fn md_type(md: *const EVP_MD) -> c_int {
    if md.is_null() {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    unsafe { EVP_MD_get_type(md) }
}

/// A length as an `int`, or `None` past `INT_MAX`.
fn int(n: usize) -> Option<c_int> {
    c_int::try_from(n).ok()
}

/// The key's size in octets.
///
/// # Safety
/// `r` is NULL or a live key.
unsafe fn size_of_key(r: *const RSA) -> usize {
    // SAFETY: the caller's guarantee.
    usize::try_from(unsafe { RSA_size(r) }).unwrap_or(0)
}

ffi_callback! {
    /// `pkey_rsa_init`: the defaults (2048 bits, two primes, PKCS #1 padding or PSS for
    /// RSA-PSS, the salt length found when verifying, implicit rejection), and the context's
    /// `keygen_info` pointing at them.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub(crate) unsafe extern "C" fn pkey_rsa_init(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let pad_mode = if unsafe { is_pss(ctx) } { RSA_PKCS1_PSS_PADDING } else { RSA_PKCS1_PADDING };
        let rctx = Box::new(RsaPkeyCtx {
            nbits: 2048,
            pub_exp: ptr::null_mut(),
            primes: RSA_DEFAULT_PRIME_NUM,
            gentmp: [0; 2],
            pad_mode,
            md: ptr::null(),
            mgf1md: ptr::null(),
            saltlen: RSA_PSS_SALTLEN_AUTO,
            min_saltlen: -1,
            oaep_label: ptr::null_mut(),
            oaep_labellen: 0,
            implicit_rejection: 1,
        });
        let raw = Box::into_raw(rctx);
        // SAFETY: the context; the settings it owns until `pkey_rsa_cleanup`.
        unsafe { EVP_PKEY_CTX_set_data(ctx, raw.cast()) };
        // SAFETY: the settings just made, at a fixed address.
        let gentmp = unsafe { (&raw mut (*raw).gentmp).cast::<c_int>() };
        // SAFETY: the context; two ints that live as long as its data.
        unsafe { EVP_PKEY_CTX_set0_keygen_info(ctx, gentmp, 2) };
        1
    }
}

ffi_callback! {
    /// `pkey_rsa_copy`: `dst`'s settings from `src`'s (not the PSS restrictions' minimum, as in
    /// OpenSSL).
    ///
    /// # Safety
    /// `dst` and `src` are live contexts; `src`'s data is its settings.
    pub(crate) unsafe extern "C" fn pkey_rsa_copy(dst: *mut EVP_PKEY_CTX, src: *const EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        if unsafe { pkey_rsa_init(dst) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let (Some(s), Some(d)) = (unsafe { settings(src) }, unsafe { settings(dst) }) else {
            return 0;
        };
        d.nbits = s.nbits;
        if !s.pub_exp.is_null() {
            // SAFETY: the source's number.
            d.pub_exp = unsafe { BN_dup(s.pub_exp) };
            if d.pub_exp.is_null() {
                return 0;
            }
        }
        d.pad_mode = s.pad_mode;
        d.md = s.md;
        d.mgf1md = s.mgf1md;
        d.saltlen = s.saltlen;
        d.implicit_rejection = s.implicit_rejection;
        if !s.oaep_label.is_null() {
            let copy: *mut c_uchar = mem::alloc(s.oaep_labellen.max(1)).cast();
            if copy.is_null() {
                return 0;
            }
            // SAFETY: the source's label of `oaep_labellen` octets; a block that size.
            unsafe { ptr::copy_nonoverlapping(s.oaep_label, copy, s.oaep_labellen) };
            d.oaep_label = copy;
            d.oaep_labellen = s.oaep_labellen;
        }
        1
    }
}

ffi_callback! {
    /// `pkey_rsa_cleanup`: frees the settings.
    ///
    /// # Safety
    /// `ctx` is a live context whose data is NULL or its settings.
    pub(crate) unsafe extern "C" fn pkey_rsa_cleanup(ctx: *mut EVP_PKEY_CTX)
    where failure = (), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let data = unsafe { EVP_PKEY_CTX_get_data(ctx) };
        if !data.is_null() {
            // SAFETY: the context; its data is gone.
            unsafe { EVP_PKEY_CTX_set_data(ctx, ptr::null_mut()) };
            // SAFETY: the settings `pkey_rsa_init` made, freed once.
            drop(unsafe { Box::from_raw(data.cast::<RsaPkeyCtx>()) });
        }
    }
}

ffi_callback! {
    /// `pkey_rsa_sign`: with a digest, the input is its value, signed by the padding's way;
    /// without one, it's encrypted with the private key as it is. 1, or <= 0.
    ///
    /// # Safety
    /// `ctx` is a live context; `sig` has room for the key's size; `tbs` holds `tbslen` octets.
    pub(crate) unsafe extern "C" fn pkey_rsa_sign(ctx: *mut EVP_PKEY_CTX, sig: *mut c_uchar, siglen: *mut usize, tbs: *const c_uchar, tbslen: usize) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(rctx) = (unsafe { settings(ctx) }) else { return -1 };
        let (md, mgf1md, pad, saltlen) = (rctx.md, rctx.mgf1md, rctx.pad_mode, rctx.saltlen);
        // SAFETY: as above.
        let rsa = unsafe { key(ctx) };
        let Some(tlen) = int(tbslen) else { return -1 };
        let ret = if md.is_null() {
            // SAFETY: the caller's input and output; the key.
            unsafe { RSA_private_encrypt(tlen, tbs, sig, rsa, pad) }
        } else {
            // SAFETY: a live digest.
            let size = unsafe { md_size(md) };
            if size <= 0 || usize::try_from(size).ok() != Some(tbslen) {
                err::raise(ERR_LIB_RSA, RSA_R_INVALID_DIGEST_LENGTH, "pkey_rsa_sign");
                return -1;
            }
            // SAFETY: as above.
            let nid = unsafe { md_type(md) };
            if nid == NID_mdc2 {
                if pad != RSA_PKCS1_PADDING {
                    return -1;
                }
                let mut sltmp: core::ffi::c_uint = 0;
                // SAFETY: the caller's input and output; the key.
                let r = unsafe { RSA_sign_ASN1_OCTET_STRING(0, tbs, tbslen.try_into().unwrap_or(0), sig, &raw mut sltmp, rsa) };
                if r <= 0 {
                    return r;
                }
                c_int::try_from(sltmp).unwrap_or(-1)
            } else if pad == RSA_X931_PADDING {
                // SAFETY: the key.
                let ksize = unsafe { size_of_key(rsa) };
                if ksize < tbslen.saturating_add(1) {
                    err::raise(ERR_LIB_RSA, RSA_R_KEY_SIZE_TOO_SMALL, "pkey_rsa_sign");
                    return -1;
                }
                let mut buf = vec![0u8; ksize];
                // SAFETY: the caller's input of `tbslen` octets.
                let input = unsafe { core::slice::from_raw_parts(tbs, tbslen) };
                let (head, tail) = buf.split_at_mut(tbslen);
                head.copy_from_slice(input);
                // SAFETY: no preconditions.
                let id = unsafe { RSA_X931_hash_id(nid) };
                if let Some(b) = tail.first_mut() {
                    *b = u8::try_from(id & 0xff).unwrap_or(0);
                }
                // SAFETY: the buffer's first `tlen + 1` octets; the caller's output; the key.
                unsafe { RSA_private_encrypt(tlen.saturating_add(1), buf.as_ptr(), sig, rsa, RSA_X931_PADDING) }
            } else if pad == RSA_PKCS1_PADDING {
                let mut sltmp: core::ffi::c_uint = 0;
                // SAFETY: as above.
                let r = unsafe { RSA_sign(nid, tbs, tbslen.try_into().unwrap_or(0), sig, &raw mut sltmp, rsa) };
                if r <= 0 {
                    return r;
                }
                c_int::try_from(sltmp).unwrap_or(-1)
            } else if pad == RSA_PKCS1_PSS_PADDING {
                // SAFETY: the key.
                let ksize = unsafe { size_of_key(rsa) };
                let mut buf = vec![0u8; ksize];
                // SAFETY: a buffer of the key's size; the digest of `tbslen` octets.
                if unsafe { RSA_padding_add_PKCS1_PSS_mgf1(rsa, buf.as_mut_ptr(), tbs, md, mgf1md, saltlen) } == 0 {
                    return -1;
                }
                let Some(k) = int(ksize) else { return -1 };
                // SAFETY: the encoded message; the caller's output; the key.
                unsafe { RSA_private_encrypt(k, buf.as_ptr(), sig, rsa, RSA_NO_PADDING) }
            } else {
                return -1;
            }
        };
        let Ok(len) = usize::try_from(ret) else { return ret };
        // SAFETY: the caller's size.
        unsafe { siglen.write(len) };
        1
    }
}

/// `pkey_rsa_verifyrecover`'s work: the recovered data's length (into `rout` when it isn't
/// NULL), or <= 0.
///
/// # Safety
/// As for [`pkey_rsa_verifyrecover`]; `rout` is NULL or has room for the key's size.
unsafe fn verify_recover(
    ctx: *mut EVP_PKEY_CTX,
    rout: *mut c_uchar,
    sig: *const c_uchar,
    siglen: usize,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(rctx) = (unsafe { settings(ctx) }) else {
        return -1;
    };
    let (md, pad) = (rctx.md, rctx.pad_mode);
    // SAFETY: as above.
    let rsa = unsafe { key(ctx) };
    let Some(slen) = int(siglen) else { return -1 };
    if md.is_null() {
        // SAFETY: the caller's input and output; the key.
        return unsafe { RSA_public_decrypt(slen, sig, rout, rsa, pad) };
    }
    // SAFETY: a live digest.
    let nid = unsafe { md_type(md) };
    if pad == RSA_X931_PADDING {
        // SAFETY: the key.
        let mut buf = vec![0u8; unsafe { size_of_key(rsa) }];
        // SAFETY: the caller's input; a buffer of the key's size; the key.
        let r = unsafe { RSA_public_decrypt(slen, sig, buf.as_mut_ptr(), rsa, RSA_X931_PADDING) };
        if r <= 0 {
            return 0;
        }
        let n = r.saturating_sub(1);
        let last = usize::try_from(n).ok().and_then(|i| buf.get(i)).copied();
        // SAFETY: no preconditions.
        let id = unsafe { RSA_X931_hash_id(nid) };
        if last.map(c_int::from) != Some(id) {
            err::raise(
                ERR_LIB_RSA,
                RSA_R_ALGORITHM_MISMATCH,
                "pkey_rsa_verifyrecover",
            );
            return 0;
        }
        // SAFETY: as above.
        if n != unsafe { md_size(md) } {
            err::raise(
                ERR_LIB_RSA,
                RSA_R_INVALID_DIGEST_LENGTH,
                "pkey_rsa_verifyrecover",
            );
            return 0;
        }
        if !rout.is_null() {
            let len = usize::try_from(n).unwrap_or(0);
            // SAFETY: `len` octets of the buffer into the caller's room.
            unsafe { ptr::copy_nonoverlapping(buf.as_ptr(), rout, len) };
        }
        n
    } else if pad == RSA_PKCS1_PADDING {
        // SAFETY: the caller's signature.
        let s = unsafe { core::slice::from_raw_parts(sig, siglen) };
        // SAFETY: the key.
        let Some(digest) = (unsafe { ossl_verify(rsa, nid, None, s) }) else {
            return 0;
        };
        if !rout.is_null() {
            // SAFETY: the digest into the caller's room.
            unsafe { ptr::copy_nonoverlapping(digest.as_ptr(), rout, digest.len()) };
        }
        int(digest.len()).unwrap_or(0)
    } else {
        -1
    }
}

ffi_callback! {
    /// `pkey_rsa_verifyrecover`: the data the signature carries (with a digest, the digest's
    /// value, checked against it). 1, or <= 0.
    ///
    /// # Safety
    /// `ctx` is a live context; `rout` is NULL or has room for the key's size; `sig` holds
    /// `siglen` octets.
    pub(crate) unsafe extern "C" fn pkey_rsa_verifyrecover(ctx: *mut EVP_PKEY_CTX, rout: *mut c_uchar, routlen: *mut usize, sig: *const c_uchar, siglen: usize) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let ret = unsafe { verify_recover(ctx, rout, sig, siglen) };
        let Ok(len) = usize::try_from(ret) else { return ret };
        if len == 0 {
            return ret;
        }
        // SAFETY: the caller's size.
        unsafe { routlen.write(len) };
        1
    }
}

ffi_callback! {
    /// `pkey_rsa_verify`: 1 when the signature signs `tbs`, else 0 (or -1 for a setting that
    /// can't verify).
    ///
    /// # Safety
    /// `ctx` is a live context; `sig` and `tbs` hold `siglen` and `tbslen` octets.
    pub(crate) unsafe extern "C" fn pkey_rsa_verify(ctx: *mut EVP_PKEY_CTX, sig: *const c_uchar, siglen: usize, tbs: *const c_uchar, tbslen: usize) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(rctx) = (unsafe { settings(ctx) }) else { return -1 };
        let (md, mgf1md, pad, saltlen) = (rctx.md, rctx.mgf1md, rctx.pad_mode, rctx.saltlen);
        // SAFETY: as above.
        let rsa = unsafe { key(ctx) };
        let (Some(slen), Some(_)) = (int(siglen), int(tbslen)) else { return -1 };
        // SAFETY: the key.
        let mut buf = vec![0u8; unsafe { size_of_key(rsa) }];
        let rslen: usize = if md.is_null() {
            // SAFETY: the caller's signature; a buffer of the key's size; the key.
            let r = unsafe { RSA_public_decrypt(slen, sig, buf.as_mut_ptr(), rsa, pad) };
            match usize::try_from(r) {
                Ok(n) if n > 0 => n,
                _ => return 0,
            }
        } else {
            // SAFETY: a live digest.
            let nid = unsafe { md_type(md) };
            if pad == RSA_PKCS1_PADDING {
                // SAFETY: the caller's digest and signature; the key.
                return unsafe { RSA_verify(nid, tbs, tbslen.try_into().unwrap_or(0), sig, siglen.try_into().unwrap_or(0), rsa) };
            }
            // SAFETY: as above.
            let size = unsafe { md_size(md) };
            if size <= 0 || usize::try_from(size).ok() != Some(tbslen) {
                err::raise(ERR_LIB_RSA, RSA_R_INVALID_DIGEST_LENGTH, "pkey_rsa_verify");
                return -1;
            }
            if pad == RSA_X931_PADDING {
                // SAFETY: the caller's guarantee; the recovered digest goes to the buffer.
                let n = unsafe { verify_recover(ctx, buf.as_mut_ptr(), sig, siglen) };
                match usize::try_from(n) {
                    Ok(n) if n > 0 => n,
                    _ => return 0,
                }
            } else if pad == RSA_PKCS1_PSS_PADDING {
                // SAFETY: as above.
                let r = unsafe { RSA_public_decrypt(slen, sig, buf.as_mut_ptr(), rsa, RSA_NO_PADDING) };
                if r <= 0 {
                    return 0;
                }
                // SAFETY: the digest; the encoded message of the key's size; the key.
                let ok = unsafe { RSA_verify_PKCS1_PSS_mgf1(rsa, tbs, md, mgf1md, buf.as_ptr(), saltlen) };
                return c_int::from(ok > 0);
            } else {
                return -1;
            }
        };
        // SAFETY: the caller's input of `tbslen` octets.
        let t = unsafe { core::slice::from_raw_parts(tbs, tbslen) };
        c_int::from(rslen == tbslen && buf.get(..rslen) == Some(t))
    }
}

ffi_callback! {
    /// `pkey_rsa_encrypt`: OAEP through its padding function and a raw encryption (so the
    /// label and digests are the context's), others through `RSA_public_encrypt`. 1, or <= 0.
    ///
    /// # Safety
    /// `ctx` is a live context; `out` has room for the key's size; `in_` holds `inlen` octets.
    pub(crate) unsafe extern "C" fn pkey_rsa_encrypt(ctx: *mut EVP_PKEY_CTX, out: *mut c_uchar, outlen: *mut usize, in_: *const c_uchar, inlen: usize) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(rctx) = (unsafe { settings(ctx) }) else { return -1 };
        let (md, mgf1md, pad) = (rctx.md, rctx.mgf1md, rctx.pad_mode);
        let (label, labellen) = (rctx.oaep_label, rctx.oaep_labellen);
        // SAFETY: as above.
        let rsa = unsafe { key(ctx) };
        let Some(ilen) = int(inlen) else { return -1 };
        let ret = if pad == RSA_PKCS1_OAEP_PADDING {
            // SAFETY: the key.
            let ksize = unsafe { size_of_key(rsa) };
            let (Some(k), Some(l)) = (int(ksize), int(labellen)) else { return -1 };
            let mut buf = vec![0u8; ksize];
            // SAFETY: a buffer of the key's size; the caller's input; the context's label.
            if unsafe { RSA_padding_add_PKCS1_OAEP_mgf1(buf.as_mut_ptr(), k, in_, ilen, label, l, md, mgf1md) } == 0 {
                return -1;
            }
            // SAFETY: the encoded message; the caller's output; the key.
            unsafe { RSA_public_encrypt(k, buf.as_ptr(), out, rsa, RSA_NO_PADDING) }
        } else {
            // SAFETY: the caller's input and output; the key.
            unsafe { RSA_public_encrypt(ilen, in_, out, rsa, pad) }
        };
        let Ok(len) = usize::try_from(ret) else { return ret };
        // SAFETY: the caller's size.
        unsafe { outlen.write(len) };
        1
    }
}

/// `constant_time_msb` of an `int`, as a mask of every bit.
fn msb_mask(x: c_int) -> c_int {
    x >> (c_int::BITS - 1)
}

ffi_callback! {
    /// `pkey_rsa_decrypt`: OAEP through a raw decryption and its padding check, others through
    /// `RSA_private_decrypt` (PKCS #1 without implicit rejection when the context turned it
    /// off). The result and length are chosen without a branch on success, as OpenSSL's are:
    /// 1 with the length on success, else the failure with the length untouched.
    ///
    /// # Safety
    /// `ctx` is a live context; `out` has room for the key's size; `in_` holds `inlen` octets.
    pub(crate) unsafe extern "C" fn pkey_rsa_decrypt(ctx: *mut EVP_PKEY_CTX, out: *mut c_uchar, outlen: *mut usize, in_: *const c_uchar, inlen: usize) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(rctx) = (unsafe { settings(ctx) }) else { return -1 };
        let (md, mgf1md, pad) = (rctx.md, rctx.mgf1md, rctx.pad_mode);
        let (label, labellen, ir) = (rctx.oaep_label, rctx.oaep_labellen, rctx.implicit_rejection);
        // SAFETY: as above.
        let rsa = unsafe { key(ctx) };
        let Some(ilen) = int(inlen) else { return -1 };
        let ret = if pad == RSA_PKCS1_OAEP_PADDING {
            // SAFETY: the key.
            let mut buf = vec![0u8; unsafe { size_of_key(rsa) }];
            // SAFETY: the caller's input; a buffer of the key's size; the key.
            let r = unsafe { RSA_private_decrypt(ilen, in_, buf.as_mut_ptr(), rsa, RSA_NO_PADDING) };
            if r <= 0 {
                return r;
            }
            let Some(l) = int(labellen) else { return -1 };
            // SAFETY: the caller's output (the key's size, at least `r`); the decrypted block
            // of `r` octets; the context's label.
            let r = unsafe { RSA_padding_check_PKCS1_OAEP_mgf1(out, r, buf.as_ptr(), r, r, label, l, md, mgf1md) };
            // SAFETY: the buffer's own octets.
            unsafe { mem::cleanse(buf.as_mut_ptr().cast(), buf.len()) };
            r
        } else {
            let mode = if pad == RSA_PKCS1_PADDING && ir == 0 {
                RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING
            } else {
                pad
            };
            // SAFETY: the caller's input and output; the key.
            unsafe { RSA_private_decrypt(ilen, in_, out, rsa, mode) }
        };
        let neg = msb_mask(ret);
        // SAFETY: the caller's size.
        let old = unsafe { outlen.read() };
        let neg_s = usize::from(neg != 0).wrapping_neg();
        let new = usize::try_from(ret & !neg).unwrap_or(0);
        // SAFETY: as above.
        unsafe { outlen.write((old & neg_s) | (new & !neg_s)) };
        (ret & neg) | (1 & !neg)
    }
}

/// `check_padding_md`: whether `md` (none is fine) goes with `padding`, raising why not.
///
/// # Safety
/// `md` is NULL or a live digest.
unsafe fn check_padding_md(md: *const EVP_MD, padding: c_int) -> bool {
    if md.is_null() {
        return true;
    }
    // SAFETY: the caller's guarantee.
    let nid = unsafe { md_type(md) };
    if padding == RSA_NO_PADDING {
        err::raise(ERR_LIB_RSA, RSA_R_INVALID_PADDING_MODE, "check_padding_md");
        return false;
    }
    if padding == RSA_X931_PADDING {
        // SAFETY: no preconditions.
        if unsafe { RSA_X931_hash_id(nid) } == -1 {
            err::raise(ERR_LIB_RSA, RSA_R_INVALID_X931_DIGEST, "check_padding_md");
            return false;
        }
        return true;
    }
    const SUPPORTED: [c_int; 17] = [
        NID_sha1,
        NID_sha224,
        NID_sha256,
        NID_sha384,
        NID_sha512,
        NID_sha512_224,
        NID_sha512_256,
        NID_md5,
        NID_md5_sha1,
        NID_md2,
        NID_md4,
        NID_mdc2,
        NID_ripemd160,
        NID_sha3_224,
        NID_sha3_256,
        NID_sha3_384,
        NID_sha3_512,
    ];
    if SUPPORTED.contains(&nid) {
        return true;
    }
    err::raise(ERR_LIB_RSA, RSA_R_INVALID_DIGEST, "check_padding_md");
    false
}

/// Writes `v` where `p` points.
///
/// # Safety
/// `p` is room for a `T`.
unsafe fn put<T>(p: *mut c_void, v: T) {
    // SAFETY: the caller's guarantee.
    unsafe { p.cast::<T>().write(v) };
}

/// A ctrl's failure: `reason` raised, `ret` returned.
fn fail(reason: c_int, ret: c_int) -> c_int {
    err::raise(ERR_LIB_RSA, reason, "pkey_rsa_ctrl");
    ret
}

ffi_callback! {
    /// `pkey_rsa_ctrl`: the padding, digests, salt length, OAEP label, implicit rejection, and
    /// generation settings. 1 (or a label's length), or 0 or -2 with the reason raised.
    ///
    /// # Safety
    /// `ctx` is a live context; `p2` is what the command takes.
    pub(crate) unsafe extern "C" fn pkey_rsa_ctrl(ctx: *mut EVP_PKEY_CTX, type_: c_int, p1: c_int, p2: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let (operation, pkey_id) = unsafe { legacy_op(ctx) };
        let pss_ctx = pkey_id == EVP_PKEY_RSA_PSS;
        // SAFETY: as above.
        let Some(rctx) = (unsafe { settings(ctx) }) else { return 0 };
        let md_arg: *const EVP_MD = p2.cast_const().cast();
        match type_ {
            EVP_PKEY_CTRL_RSA_PADDING => {
                let bad = || fail(RSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE, -2);
                if !(RSA_PKCS1_PADDING..=RSA_PKCS1_PSS_PADDING).contains(&p1) {
                    return bad();
                }
                // SAFETY: the context's digest.
                if !unsafe { check_padding_md(rctx.md, p1) } {
                    return 0;
                }
                if p1 == RSA_PKCS1_PSS_PADDING {
                    if operation & (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY) == 0 {
                        return bad();
                    }
                    if rctx.md.is_null() {
                        // SAFETY: no preconditions.
                        rctx.md = unsafe { EVP_sha1() };
                    }
                } else if pss_ctx {
                    return bad();
                }
                if p1 == RSA_PKCS1_OAEP_PADDING {
                    if operation & EVP_PKEY_OP_TYPE_CRYPT == 0 {
                        return bad();
                    }
                    if rctx.md.is_null() {
                        // SAFETY: no preconditions.
                        rctx.md = unsafe { EVP_sha1() };
                    }
                }
                rctx.pad_mode = p1;
                1
            }
            EVP_PKEY_CTRL_GET_RSA_PADDING => {
                // SAFETY: the command's `int *`.
                unsafe { put(p2, rctx.pad_mode) };
                1
            }
            EVP_PKEY_CTRL_RSA_PSS_SALTLEN | EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN => {
                if rctx.pad_mode != RSA_PKCS1_PSS_PADDING {
                    return fail(RSA_R_INVALID_PSS_SALTLEN, -2);
                }
                if type_ == EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN {
                    // SAFETY: as above.
                    unsafe { put(p2, rctx.saltlen) };
                    return 1;
                }
                if p1 < RSA_PSS_SALTLEN_MAX {
                    return -2;
                }
                if rctx.restricted() {
                    if p1 == RSA_PSS_SALTLEN_AUTO && operation == EVP_PKEY_OP_VERIFY {
                        return fail(RSA_R_INVALID_PSS_SALTLEN, -2);
                    }
                    // SAFETY: the context's digest.
                    let size = unsafe { md_size(rctx.md) };
                    if size <= 0 {
                        return fail(RSA_R_INVALID_DIGEST_LENGTH, -2);
                    }
                    if (p1 == RSA_PSS_SALTLEN_DIGEST && rctx.min_saltlen > size)
                        || (p1 >= 0 && p1 < rctx.min_saltlen)
                    {
                        return fail(RSA_R_PSS_SALTLEN_TOO_SMALL, 0);
                    }
                }
                rctx.saltlen = p1;
                1
            }
            EVP_PKEY_CTRL_RSA_KEYGEN_BITS => {
                if usize::try_from(p1).map_or(true, |b| b < MIN_MODULUS_BITS) {
                    return fail(RSA_R_KEY_SIZE_TOO_SMALL, -2);
                }
                rctx.nbits = p1;
                1
            }
            EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP => {
                let e: *mut BIGNUM = p2.cast();
                // SAFETY: NULL or the caller's number.
                if e.is_null() || unsafe { BN_is_odd(e) } == 0 || unsafe { BN_is_one(e) } != 0 {
                    return fail(RSA_R_BAD_E_VALUE, -2);
                }
                // SAFETY: the context's own number, replaced by the caller's.
                unsafe { BN_free(rctx.pub_exp) };
                rctx.pub_exp = e;
                1
            }
            EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES => {
                if usize::try_from(p1).map_or(true, |n| {
                    n < usize::try_from(RSA_DEFAULT_PRIME_NUM).unwrap_or(2) || n > MAX_PRIMES
                }) {
                    return fail(RSA_R_KEY_PRIME_NUM_INVALID, -2);
                }
                rctx.primes = p1;
                1
            }
            EVP_PKEY_CTRL_RSA_OAEP_MD | EVP_PKEY_CTRL_GET_RSA_OAEP_MD => {
                if rctx.pad_mode != RSA_PKCS1_OAEP_PADDING {
                    return fail(RSA_R_INVALID_PADDING_MODE, -2);
                }
                if type_ == EVP_PKEY_CTRL_GET_RSA_OAEP_MD {
                    // SAFETY: the command's `const EVP_MD **`.
                    unsafe { put(p2, rctx.md) };
                } else {
                    rctx.md = md_arg;
                }
                1
            }
            EVP_PKEY_CTRL_MD => {
                // SAFETY: the caller's digest, or NULL.
                if !unsafe { check_padding_md(md_arg, rctx.pad_mode) } {
                    return 0;
                }
                if rctx.restricted() {
                    // SAFETY: live digests.
                    if unsafe { md_type(rctx.md) } == unsafe { md_type(md_arg) } {
                        return 1;
                    }
                    return fail(RSA_R_DIGEST_NOT_ALLOWED, 0);
                }
                rctx.md = md_arg;
                1
            }
            EVP_PKEY_CTRL_GET_MD => {
                // SAFETY: as above.
                unsafe { put(p2, rctx.md) };
                1
            }
            EVP_PKEY_CTRL_RSA_MGF1_MD | EVP_PKEY_CTRL_GET_RSA_MGF1_MD => {
                if rctx.pad_mode != RSA_PKCS1_PSS_PADDING && rctx.pad_mode != RSA_PKCS1_OAEP_PADDING {
                    return fail(RSA_R_INVALID_MGF1_MD, -2);
                }
                if type_ == EVP_PKEY_CTRL_GET_RSA_MGF1_MD {
                    let md = if rctx.mgf1md.is_null() { rctx.md } else { rctx.mgf1md };
                    // SAFETY: as above.
                    unsafe { put(p2, md) };
                } else {
                    if rctx.restricted() {
                        // SAFETY: live digests.
                        if unsafe { md_type(rctx.mgf1md) } == unsafe { md_type(md_arg) } {
                            return 1;
                        }
                        return fail(RSA_R_MGF1_DIGEST_NOT_ALLOWED, 0);
                    }
                    rctx.mgf1md = md_arg;
                }
                1
            }
            EVP_PKEY_CTRL_RSA_OAEP_LABEL => {
                if rctx.pad_mode != RSA_PKCS1_OAEP_PADDING {
                    return fail(RSA_R_INVALID_PADDING_MODE, -2);
                }
                // SAFETY: the context's own label, from the C allocator.
                unsafe { mem::release(rctx.oaep_label.cast()) };
                if !p2.is_null() && p1 > 0 {
                    rctx.oaep_label = p2.cast();
                    rctx.oaep_labellen = usize::try_from(p1).unwrap_or(0);
                } else {
                    rctx.oaep_label = ptr::null_mut();
                    rctx.oaep_labellen = 0;
                }
                1
            }
            EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL => {
                if rctx.pad_mode != RSA_PKCS1_OAEP_PADDING {
                    return fail(RSA_R_INVALID_PADDING_MODE, -2);
                }
                if p2.is_null() {
                    err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, "pkey_rsa_ctrl");
                    return 0;
                }
                // SAFETY: the command's `unsigned char **`.
                unsafe { put(p2, rctx.oaep_label) };
                int(rctx.oaep_labellen).unwrap_or(0)
            }
            EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION => {
                if rctx.pad_mode != RSA_PKCS1_PADDING {
                    return fail(RSA_R_INVALID_PADDING_MODE, -2);
                }
                rctx.implicit_rejection = p1;
                1
            }
            EVP_PKEY_CTRL_DIGESTINIT | EVP_PKEY_CTRL_PKCS7_SIGN | EVP_PKEY_CTRL_CMS_SIGN => 1,
            EVP_PKEY_CTRL_PKCS7_ENCRYPT
            | EVP_PKEY_CTRL_PKCS7_DECRYPT
            | EVP_PKEY_CTRL_CMS_DECRYPT
            | EVP_PKEY_CTRL_CMS_ENCRYPT
                if !pss_ctx =>
            {
                1
            }
            EVP_PKEY_CTRL_PKCS7_ENCRYPT
            | EVP_PKEY_CTRL_PKCS7_DECRYPT
            | EVP_PKEY_CTRL_CMS_DECRYPT
            | EVP_PKEY_CTRL_CMS_ENCRYPT
            | EVP_PKEY_CTRL_PEER_KEY => fail(RSA_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE, -2),
            _ => -2,
        }
    }
}

/// C's `atoi`: leading white space, a sign, then digits, as an `int` (0 for none).
///
/// # Safety
/// `s` is a string.
unsafe fn atoi(s: *const c_char) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { libc::atoi(s) }
}

/// `EVP_PKEY_CTX_md(ctx, optype, cmd, value)`.
///
/// # Safety
/// `ctx` is a live context; `value` a string.
unsafe fn md_by_name(
    ctx: *mut EVP_PKEY_CTX,
    optype: c_int,
    cmd: c_int,
    value: *const c_char,
) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_PKEY_CTX_md(ctx, optype, cmd, value) }
}

ffi_callback! {
    /// `pkey_rsa_ctrl_str`: the `rsa_*` settings by name, through the functions that send their
    /// ctrls. -2 for a name it doesn't know.
    ///
    /// # Safety
    /// `ctx` is a live context; `type_` is a string; `value` is NULL or a string.
    pub(crate) unsafe extern "C" fn pkey_rsa_ctrl_str(ctx: *mut EVP_PKEY_CTX, type_: *const c_char, value: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        if value.is_null() {
            err::raise(ERR_LIB_RSA, RSA_R_VALUE_MISSING, "pkey_rsa_ctrl_str");
            return 0;
        }
        if type_.is_null() {
            return -2;
        }
        // SAFETY: the caller's strings.
        let name = unsafe { CStr::from_ptr(type_) }.to_bytes();
        // SAFETY: as above.
        let v = unsafe { CStr::from_ptr(value) }.to_bytes();
        // SAFETY: as above.
        let pss = unsafe { is_pss(ctx) };
        match name {
            b"rsa_padding_mode" => {
                let pm = match v {
                    b"pkcs1" => RSA_PKCS1_PADDING,
                    b"none" => RSA_NO_PADDING,
                    b"oeap" | b"oaep" => RSA_PKCS1_OAEP_PADDING,
                    b"x931" => RSA_X931_PADDING,
                    b"pss" => RSA_PKCS1_PSS_PADDING,
                    _ => {
                        err::raise(ERR_LIB_RSA, RSA_R_UNKNOWN_PADDING_TYPE, "pkey_rsa_ctrl_str");
                        return -2;
                    }
                };
                // SAFETY: the context.
                unsafe { EVP_PKEY_CTX_set_rsa_padding(ctx, pm) }
            }
            b"rsa_pss_saltlen" => {
                let saltlen = match v {
                    b"digest" => RSA_PSS_SALTLEN_DIGEST,
                    b"max" => RSA_PSS_SALTLEN_MAX,
                    b"auto" => RSA_PSS_SALTLEN_AUTO,
                    // SAFETY: the caller's string.
                    _ => unsafe { atoi(value) },
                };
                // SAFETY: the context.
                unsafe { EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, saltlen) }
            }
            b"rsa_keygen_bits" => {
                // SAFETY: as above.
                let bits = unsafe { atoi(value) };
                // SAFETY: the context.
                unsafe { EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) }
            }
            b"rsa_keygen_pubexp" => {
                let mut e: *mut BIGNUM = ptr::null_mut();
                // SAFETY: a slot for a new number; the caller's string.
                if unsafe { crate::bn::conv::BN_asc2bn(&raw mut e, value) } == 0 {
                    return 0;
                }
                // SAFETY: the context; the number, which it copies.
                let ret = unsafe { EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, e) };
                // SAFETY: the number made above.
                unsafe { BN_free(e) };
                ret
            }
            b"rsa_keygen_primes" => {
                // SAFETY: as above.
                let n = unsafe { atoi(value) };
                // SAFETY: the context.
                unsafe { EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, n) }
            }
            b"rsa_mgf1_md" => {
                // SAFETY: the context and the caller's string.
                unsafe { md_by_name(ctx, EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_RSA_MGF1_MD, value) }
            }
            b"rsa_pss_keygen_mgf1_md" if pss => {
                // SAFETY: as above.
                unsafe { md_by_name(ctx, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_RSA_MGF1_MD, value) }
            }
            b"rsa_pss_keygen_md" if pss => {
                // SAFETY: as above.
                unsafe { md_by_name(ctx, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_MD, value) }
            }
            b"rsa_pss_keygen_saltlen" if pss => {
                // SAFETY: as above.
                let saltlen = unsafe { atoi(value) };
                // SAFETY: the context.
                unsafe { EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, saltlen) }
            }
            b"rsa_oaep_md" => {
                // SAFETY: as above.
                unsafe { md_by_name(ctx, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_RSA_OAEP_MD, value) }
            }
            b"rsa_oaep_label" => {
                let mut len: core::ffi::c_long = 0;
                // SAFETY: the caller's string; a slot for the length.
                let lab = unsafe { OPENSSL_hexstr2buf(value, &raw mut len) };
                if lab.is_null() {
                    return 0;
                }
                // SAFETY: the context; the label, which it takes on success.
                let ret = unsafe { EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, lab.cast(), c_int::try_from(len).unwrap_or(0)) };
                if ret <= 0 {
                    // SAFETY: the label, still ours.
                    unsafe { mem::release(lab.cast()) };
                }
                ret
            }
            _ => -2,
        }
    }
}

/// `trans_cb`: the generator's progress to the context's callback.
///
/// # Safety
/// `cb` is a live `BN_GENCB` whose argument is a live context.
unsafe extern "C" fn trans_cb(a: c_int, b: c_int, cb: *mut BN_GENCB) -> c_int {
    // SAFETY: the caller's guarantee.
    let ctx: *mut EVP_PKEY_CTX = unsafe { BN_GENCB_get_arg(cb) }.cast();
    // SAFETY: as above.
    unsafe { legacy_gen_progress(ctx, a, b) }
}

/// An AlgorithmIdentifier of `nid` with a parameter of type `ptype` (`V_ASN1_UNDEF`: none)
/// whose value `pval` it takes (`ossl_X509_ALGOR_from_nid`), or NULL.
///
/// # Safety
/// `pval` is what `ASN1_TYPE_set` takes for `ptype`, or NULL.
unsafe fn algor_from_nid(nid: c_int, ptype: c_int, pval: *mut c_void) -> *mut X509_ALGOR {
    // SAFETY: no preconditions.
    let alg = unsafe { X509_ALGOR_new() };
    // SAFETY: a new AlgorithmIdentifier, or NULL.
    let Some(a) = (unsafe { alg.as_mut() }) else {
        return ptr::null_mut();
    };
    // SAFETY: no preconditions; a built-in object, which needs no freeing.
    a.algorithm = unsafe { OBJ_nid2obj(nid) };
    if ptype != V_ASN1_UNDEF {
        // SAFETY: no preconditions.
        let t = unsafe { ASN1_TYPE_new() };
        if t.is_null() {
            // SAFETY: the AlgorithmIdentifier made above.
            unsafe { X509_ALGOR_free(alg) };
            return ptr::null_mut();
        }
        // SAFETY: a new `ASN1_TYPE`, taking the value.
        unsafe { ASN1_TYPE_set(t, ptype, pval) };
        a.parameter = t;
    }
    alg
}

/// `ossl_x509_algor_new_from_md`: the digest's AlgorithmIdentifier (its parameters absent or
/// NULL, as the digest says), or none for SHA-1, the default. `false` when memory runs out.
///
/// # Safety
/// `md` is a live digest.
unsafe fn algor_from_md(slot: &mut *mut X509_ALGOR, md: *const EVP_MD) -> bool {
    // SAFETY: the caller's guarantee.
    if md.is_null() || unsafe { EVP_MD_is_a(md, c"SHA1".as_ptr()) } != 0 {
        return true;
    }
    // SAFETY: as above.
    let absent = unsafe { EVP_MD_get_flags(md) }
        & core::ffi::c_ulong::try_from(EVP_MD_FLAG_DIGALGID_ABSENT).unwrap_or(0)
        != 0;
    let ptype = if absent { V_ASN1_UNDEF } else { V_ASN1_NULL };
    // SAFETY: as above.
    let nid = unsafe { md_type(md) };
    // SAFETY: no value.
    *slot = unsafe { algor_from_nid(nid, ptype, ptr::null_mut()) };
    !slot.is_null()
}

/// `ossl_x509_algor_md_to_mgf1`: MGF1 with the digest's AlgorithmIdentifier, or none for
/// SHA-1.
///
/// # Safety
/// `md` is a live digest.
unsafe fn mgf1_from_md(slot: &mut *mut X509_ALGOR, md: *const EVP_MD) -> bool {
    *slot = ptr::null_mut();
    // SAFETY: the caller's guarantee.
    if md.is_null() || unsafe { EVP_MD_is_a(md, c"SHA1".as_ptr()) } != 0 {
        return true;
    }
    let mut inner: *mut X509_ALGOR = ptr::null_mut();
    // SAFETY: as above.
    if !unsafe { algor_from_md(&mut inner, md) } {
        return false;
    }
    let mut packed: *mut rustyssl_abi::ASN1_STRING = ptr::null_mut();
    // SAFETY: no preconditions; the AlgorithmIdentifier, packed into a new string.
    let it = unsafe { X509_ALGOR_it() };
    // SAFETY: as above.
    let ok = !unsafe { ASN1_item_pack(inner.cast(), it, &raw mut packed) }.is_null();
    // SAFETY: the inner AlgorithmIdentifier, packed.
    unsafe { X509_ALGOR_free(inner) };
    if !ok {
        return false;
    }
    // SAFETY: the packed SEQUENCE, which the new AlgorithmIdentifier takes.
    *slot = unsafe { algor_from_nid(NID_mgf1, V_ASN1_SEQUENCE, packed.cast()) };
    if slot.is_null() {
        // SAFETY: the string, not taken.
        unsafe { ASN1_STRING_free(packed) };
        return false;
    }
    true
}

/// `ossl_rsa_pss_params_create`: restrictions to a digest, an MGF1 digest (the digest's when
/// NULL), and a minimum salt length, as an RSASSA-PSS-params with its decoded mask hash.
///
/// # Safety
/// `md` and `mgf1md` are NULL or live digests.
pub(crate) unsafe fn pss_params_create(
    md: *const EVP_MD,
    mgf1md: *const EVP_MD,
    saltlen: c_int,
) -> *mut RSA_PSS_PARAMS {
    // SAFETY: no preconditions.
    let pss = unsafe { RSA_PSS_PARAMS_new() };
    // SAFETY: new parameters, or NULL.
    let Some(p) = (unsafe { pss.as_mut() }) else {
        return ptr::null_mut();
    };
    let mgf1md = if mgf1md.is_null() { md } else { mgf1md };
    let ok = (saltlen == 20 || {
        // SAFETY: no preconditions.
        p.saltLength = unsafe { ASN1_INTEGER_new() };
        // SAFETY: the new INTEGER.
        !p.saltLength.is_null() && unsafe { ASN1_INTEGER_set(p.saltLength, saltlen.into()) } != 0
    })
        // SAFETY: the caller's digests.
        && unsafe { algor_from_md(&mut p.hashAlgorithm, md) }
        // SAFETY: as above.
        && unsafe { mgf1_from_md(&mut p.maskGenAlgorithm, mgf1md) }
        // SAFETY: as above.
        && unsafe { algor_from_md(&mut p.maskHash, mgf1md) };
    if !ok {
        // SAFETY: the parameters made above.
        unsafe { RSA_PSS_PARAMS_free(pss) };
        return ptr::null_mut();
    }
    pss
}

/// `ossl_x509_algor_get_md`: the digest an AlgorithmIdentifier names (SHA-1 for none), or
/// NULL with `ASN1_R_UNKNOWN_DIGEST`.
///
/// # Safety
/// `alg` is NULL or a live AlgorithmIdentifier.
pub(crate) unsafe fn md_of_algor(alg: *const X509_ALGOR) -> *const EVP_MD {
    if alg.is_null() {
        // SAFETY: no preconditions.
        return unsafe { EVP_sha1() };
    }
    // SAFETY: the caller's guarantee.
    let obj = unsafe { (*alg).algorithm };
    // SAFETY: its object.
    let nid = unsafe { OBJ_obj2nid(obj) };
    // SAFETY: a NID.
    let sn = unsafe { OBJ_nid2sn(nid) };
    let md = if sn.is_null() {
        ptr::null()
    } else {
        // SAFETY: a name from the table.
        unsafe { EVP_get_digestbyname(sn) }
    };
    if md.is_null() {
        err::raise(
            ERR_LIB_ASN1,
            ASN1_R_UNKNOWN_DIGEST,
            "ossl_x509_algor_get_md",
        );
    }
    md
}

/// `ossl_rsa_pss_get_param`: the digest, MGF1 digest, and minimum salt length of
/// restrictions, checked (a non-negative salt length, trailer field 1).
///
/// # Safety
/// `pss` is live parameters.
pub(crate) unsafe fn pss_get_param(
    pss: *const RSA_PSS_PARAMS,
) -> Option<(*const EVP_MD, *const EVP_MD, c_int)> {
    // SAFETY: the caller's guarantee.
    let p = unsafe { &*pss };
    // SAFETY: the parameters' AlgorithmIdentifiers.
    let md = unsafe { md_of_algor(p.hashAlgorithm) };
    if md.is_null() {
        return None;
    }
    // SAFETY: as above.
    let mgf1md = unsafe { md_of_algor(p.maskHash) };
    if mgf1md.is_null() {
        return None;
    }
    let saltlen = if p.saltLength.is_null() {
        20
    } else {
        // SAFETY: its INTEGER.
        c_int::try_from(unsafe { ASN1_INTEGER_get(p.saltLength) }).unwrap_or(-1)
    };
    let trailer = if p.trailerField.is_null() {
        1
    } else {
        // SAFETY: as above.
        unsafe { ASN1_INTEGER_get(p.trailerField) }
    };
    if saltlen < 0 {
        err::raise(
            ERR_LIB_RSA,
            RSA_R_INVALID_SALT_LENGTH,
            "rsa_pss_verify_param",
        );
        return None;
    }
    if trailer != 1 {
        err::raise(ERR_LIB_RSA, RSA_R_INVALID_TRAILER, "rsa_pss_verify_param");
        return None;
    }
    Some((md, mgf1md, saltlen))
}

/// `ossl_x509_algor_mgf1_decode`: the AlgorithmIdentifier of MGF1's digest, or NULL.
///
/// # Safety
/// `alg` is a live AlgorithmIdentifier.
pub(crate) unsafe fn mgf1_decode(alg: *const X509_ALGOR) -> *mut X509_ALGOR {
    // SAFETY: the caller's guarantee.
    let a = unsafe { &*alg };
    // SAFETY: its object.
    if unsafe { OBJ_obj2nid(a.algorithm) } != NID_mgf1 {
        return ptr::null_mut();
    }
    // SAFETY: no preconditions.
    let it = unsafe { X509_ALGOR_it() };
    // SAFETY: its parameter, NULL or a live `ASN1_TYPE`.
    unsafe { ASN1_TYPE_unpack_sequence(it, a.parameter) }.cast()
}

ffi_callback! {
    /// `pkey_pss_init`: an RSA-PSS key's restrictions (its `RSA_PSS_PARAMS`, if any) become the
    /// context's digests and salt length, and its minimum. 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context whose data is its settings.
    pub(crate) unsafe extern "C" fn pkey_pss_init(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { is_pss(ctx) } {
            return 0;
        }
        // SAFETY: as above.
        let r = unsafe { key(ctx) };
        // SAFETY: the context's key.
        let Some(k) = (unsafe { rsa(r) }) else { return 0 };
        let pss = k.legacy().pss.0;
        if pss.is_null() {
            return 1;
        }
        // SAFETY: the key's parameters.
        let Some((md, mgf1md, min_saltlen)) = (unsafe { pss_get_param(pss) }) else {
            return 0;
        };
        // SAFETY: a live digest.
        let size = unsafe { md_size(md) };
        if size <= 0 {
            err::raise(ERR_LIB_RSA, RSA_R_INVALID_DIGEST_LENGTH, "pkey_pss_init");
            return 0;
        }
        // SAFETY: the key.
        let mut max_saltlen = unsafe { RSA_size(r) }.saturating_sub(size);
        // SAFETY: as above.
        if unsafe { RSA_bits(r) } & 7 == 1 {
            max_saltlen = max_saltlen.saturating_sub(1);
        }
        if min_saltlen > max_saltlen {
            err::raise(ERR_LIB_RSA, RSA_R_INVALID_SALT_LENGTH, "pkey_pss_init");
            return 0;
        }
        // SAFETY: the context's settings.
        let Some(rctx) = (unsafe { settings(ctx) }) else { return 0 };
        rctx.min_saltlen = min_saltlen;
        rctx.md = md;
        rctx.mgf1md = mgf1md;
        rctx.saltlen = min_saltlen;
        1
    }
}

ffi_callback! {
    /// `pkey_rsa_keygen`: `RSA_generate_multi_prime_key` with the context's settings (65537
    /// unless it has an exponent) and its callback, then, for RSA-PSS with settings that
    /// aren't the defaults, the key's restrictions; `pkey` takes the key as the method's type.
    ///
    /// # Safety
    /// `ctx` is a live context whose data is its settings; `pkey` a live key.
    pub(crate) unsafe extern "C" fn pkey_rsa_keygen(ctx: *mut EVP_PKEY_CTX, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(rctx) = (unsafe { settings(ctx) }) else { return 0 };
        if rctx.pub_exp.is_null() {
            // SAFETY: no preconditions.
            let e = unsafe { BN_new() };
            // SAFETY: the new number.
            if e.is_null() || unsafe { BN_set_word(e, RSA_F4.unsigned_abs()) } == 0 {
                // SAFETY: NULL or the number made above.
                unsafe { BN_free(e) };
                return 0;
            }
            rctx.pub_exp = e;
        }
        let (nbits, primes, e) = (rctx.nbits, rctx.primes, rctx.pub_exp);
        let (md, mgf1md, saltlen) = (rctx.md, rctx.mgf1md, rctx.saltlen);
        // SAFETY: no preconditions.
        let r = unsafe { RSA_new() };
        if r.is_null() {
            return 0;
        }
        // SAFETY: the context.
        let has_cb = unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_get_cb(ctx) }.is_some();
        let pcb = if has_cb {
            // SAFETY: no preconditions.
            let pcb = unsafe { BN_GENCB_new() };
            if pcb.is_null() {
                // SAFETY: the key made above.
                unsafe { RSA_free(r) };
                return 0;
            }
            // SAFETY: the new callback, reporting to the context.
            unsafe { BN_GENCB_set(pcb, Some(trans_cb), ctx.cast()) };
            pcb
        } else {
            ptr::null_mut()
        };
        // SAFETY: the new key; the context's exponent; the callback or NULL.
        let ret = unsafe { RSA_generate_multi_prime_key(r, nbits, primes, e, pcb) };
        // SAFETY: NULL or the callback made above.
        unsafe { BN_GENCB_free(pcb) };
        // SAFETY: the context.
        let pss_ctx = unsafe { is_pss(ctx) };
        if ret > 0 && pss_ctx && !(md.is_null() && mgf1md.is_null() && saltlen == -2) {
            let s = if saltlen == -2 { 0 } else { saltlen };
            // SAFETY: the context's digests.
            let pss = unsafe { pss_params_create(md, mgf1md, s) };
            // SAFETY: the new key.
            let Some(k) = (unsafe { rsa(r) }) else { return 0 };
            if pss.is_null() {
                // SAFETY: the key made above.
                unsafe { RSA_free(r) };
                return 0;
            }
            k.set_pss_params(pss);
        }
        if ret > 0 {
            // SAFETY: the context.
            let id = unsafe { legacy_op(ctx) }.1;
            // SAFETY: the caller's key, which takes the new one.
            unsafe { EVP_PKEY_assign(pkey, id, r.cast()) };
        } else {
            // SAFETY: the key made above.
            unsafe { RSA_free(r) };
        }
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, bare_context};

    #[test]
    fn the_sign_mask_selects_without_branching() {
        assert_eq!(msb_mask(-1), -1);
        assert_eq!(msb_mask(c_int::MIN), -1);
        assert_eq!(msb_mask(0), 0);
        assert_eq!(msb_mask(c_int::MAX), 0);
    }

    /// The settings live in the context's data from `init` to `cleanup`; a copy has its own
    /// label; the label a ctrl hands over is the context's to free.
    #[test]
    fn settings_are_copied_and_freed() {
        let (src, dst) = (bare_context(), bare_context());
        assert!(!src.is_null() && !dst.is_null());
        // SAFETY: a live context.
        assert_eq!(unsafe { pkey_rsa_init(src) }, 1);
        // SAFETY: its settings.
        let s = unsafe { settings(src) }.expect("settings");
        assert_eq!(
            (s.nbits, s.pad_mode, s.saltlen),
            (2048, RSA_PKCS1_PADDING, RSA_PSS_SALTLEN_AUTO)
        );
        s.pad_mode = RSA_PKCS1_OAEP_PADDING;
        let label: *mut u8 = mem::alloc(3).cast();
        // SAFETY: a block of three octets.
        unsafe { ptr::copy_nonoverlapping(b"abc".as_ptr(), label, 3) };
        // SAFETY: the context; the label, which it takes.
        let set = unsafe { pkey_rsa_ctrl(src, EVP_PKEY_CTRL_RSA_OAEP_LABEL, 3, label.cast()) };
        assert_eq!(set, 1);
        // SAFETY: two live contexts.
        assert_eq!(unsafe { pkey_rsa_copy(dst, src) }, 1);
        // SAFETY: the copy's settings.
        let d = unsafe { settings(dst) }.expect("settings");
        assert_eq!(d.oaep_labellen, 3);
        assert_ne!(d.oaep_label, label);
        // SAFETY: the copy's label of three octets.
        let copied = unsafe { core::slice::from_raw_parts(d.oaep_label, 3) };
        assert_eq!(copied, b"abc");
        for c in [src, dst] {
            // SAFETY: a context with settings, then without.
            unsafe { pkey_rsa_cleanup(c) };
            // SAFETY: as above.
            assert!(unsafe { EVP_PKEY_CTX_get_data(c) }.is_null());
            // SAFETY: as above; a second cleanup does nothing.
            unsafe { pkey_rsa_cleanup(c) };
            // SAFETY: the contexts made above.
            unsafe { EVP_PKEY_CTX_free(c) };
        }
    }
}
