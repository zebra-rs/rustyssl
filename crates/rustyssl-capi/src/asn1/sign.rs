//! Signing and verifying ASN.1 items (`ASN1_item_sign(3)`, `ASN1_item_verify(3)`; `a_sign.c`,
//! `a_verify.c`): an item's DER signed through a digest context, with the AlgorithmIdentifiers
//! that say how, and a signature checked against the AlgorithmIdentifier it came with.
//!
//! As in OpenSSL:
//! - A provided key's provider gives the AlgorithmIdentifier (`OSSL_SIGNATURE_PARAM_ALGORITHM_ID`);
//!   a legacy key's ASN.1 method sets it (`item_sign`, RSA-PSS and EdDSA) or names it from the
//!   digest and key type, with a NULL parameter where the method's flags say so.
//! - Verifying finds the digest and key type the AlgorithmIdentifier names: RSA-PSS's from its
//!   parameters, a legacy key's own method (`item_verify`) for the others without a digest.
//! - A signature with bits left over, an unknown algorithm, or the wrong kind of key is -1;
//!   one that doesn't match is 0; each raises its reason.

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_ITEM, ASN1_OCTET_STRING, ASN1_PKEY_SIGPARAM_NULL,
    ASN1_R_CONTEXT_NOT_INITIALISED, ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED,
    ASN1_R_INVALID_BIT_STRING_BITS_LEFT,
    ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD,
    ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM, ASN1_R_UNKNOWN_OBJECT_TYPE,
    ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM, ASN1_R_WRONG_PUBLIC_KEY_TYPE, ASN1_STRING_FLAG_BITS_LEFT,
    ERR_LIB_ASN1, ERR_R_ASN1_LIB, ERR_R_EVP_LIB, ERR_R_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER,
    EVP_MD, EVP_MD_CTX, EVP_PKEY, EVP_PKEY_ASN1_METHOD, EVP_PKEY_CTX, EVP_PKEY_RSA_PSS,
    NID_dsaWithSHA1, NID_sm2, NID_undef, OSSL_LIB_CTX, OSSL_PARAM,
    OSSL_SIGNATURE_PARAM_ALGORITHM_ID, V_ASN1_BIT_STRING, V_ASN1_NULL, V_ASN1_UNDEF, X509_ALGOR,
    i2d_of_void,
};

use crate::asn1::string::ASN1_STRING_set0;
use crate::asn1::tpl::encode::ASN1_item_i2d;
use crate::asn1::tpl::items::{ASN1_TYPE_free, ASN1_TYPE_new, d2i_X509_ALGOR};
use crate::err;
use crate::evp::digest::{EVP_MD_get_pkey_type, EVP_MD_get_type};
use crate::evp::legacy_md::EVP_get_digestbyname;
use crate::evp::md_ctx::{
    EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_get0_md, EVP_MD_CTX_new,
};
use crate::evp::pkey::ameth::EVP_PKEY_get0_asn1;
use crate::evp::pkey::{EVP_PKEY_get_id, EVP_PKEY_get_size, EVP_PKEY_is_a, pkey};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_get_params, EVP_PKEY_CTX_get0_pkey, EVP_PKEY_CTX_new_from_pkey,
};
use crate::evp::setters::EVP_PKEY_CTX_set1_id;
use crate::evp::sigver::{
    EVP_DigestSign, EVP_DigestSignInit, EVP_DigestVerify, EVP_DigestVerifyInit,
    EVP_MD_CTX_get_pkey_ctx, EVP_MD_CTX_set_pkey_ctx, EVP_SignFinal, EVP_VerifyFinal,
};
use crate::ffi::ffi_export;
use crate::handle::Handle;
use crate::mem;
use crate::objects::sigid::{OBJ_find_sigid_algs, OBJ_find_sigid_by_algs};
use crate::objects::{ASN1_OBJECT_free, OBJ_length, OBJ_nid2obj, OBJ_nid2sn, OBJ_obj2nid};
use crate::params::{OSSL_PARAM_construct_octet_string, end};
use crate::x509::algor::X509_ALGOR_set0;

/// `ossl_asn1_string_set_bits_left(s, 0)`.
///
/// # Safety
/// `s` is a live string.
unsafe fn no_bits_left(s: *mut ASN1_BIT_STRING) {
    // SAFETY: the caller's guarantee.
    let st = unsafe { &mut *s };
    st.flags &= !0x07;
    st.flags |= core::ffi::c_long::from(ASN1_STRING_FLAG_BITS_LEFT);
}

/// `evp_md_ctx_new_ex`: a digest context with a key context for `pkey` (from `libctx` with
/// `propq`) given the distinguishing ID `id`, which the caller frees with the context; NULL
/// with `ERR_R_EVP_LIB` if one can't be made.
///
/// # Safety
/// `pkey` is NULL or a live key; `id` is NULL or a live string; `propq` is NULL or a string.
unsafe fn md_ctx_new_ex(
    pkey: *mut EVP_PKEY,
    id: *const ASN1_OCTET_STRING,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> *mut EVP_MD_CTX {
    // SAFETY: no preconditions.
    let ctx = unsafe { EVP_MD_CTX_new() };
    let pctx = if ctx.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq) }
    };
    let fail = |pctx: *mut EVP_PKEY_CTX| {
        // SAFETY: made here, or NULL.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        // SAFETY: as above.
        unsafe { EVP_MD_CTX_free(ctx) };
        ptr::null_mut()
    };
    if pctx.is_null() {
        err::raise(ERR_LIB_ASN1, ERR_R_EVP_LIB, "evp_md_ctx_new_ex");
        return fail(pctx);
    }
    // SAFETY: the caller's string.
    if let Some(i) = unsafe { id.as_ref() }
        // SAFETY: the new context; the ID's octets.
        && unsafe { EVP_PKEY_CTX_set1_id(pctx, i.data.cast(), i.length) } <= 0
    {
        return fail(pctx);
    }
    // SAFETY: both made here; the digest context keeps the key context until the caller
    // frees it.
    unsafe { EVP_MD_CTX_set_pkey_ctx(ctx, pctx) };
    ctx
}

/// Frees a context of [`md_ctx_new_ex`] and its key context.
///
/// # Safety
/// `ctx` is such a context.
unsafe fn md_ctx_free_ex(ctx: *mut EVP_MD_CTX) {
    // SAFETY: the caller's guarantee.
    let pctx = unsafe { EVP_MD_CTX_get_pkey_ctx(ctx) };
    // SAFETY: the context's, which it doesn't free.
    unsafe { EVP_PKEY_CTX_free(pctx) };
    // SAFETY: the caller's guarantee.
    unsafe { EVP_MD_CTX_free(ctx) };
}

/// Why the provider's AlgorithmIdentifier wasn't had.
pub(crate) enum AidError {
    /// The provider refused the parameter.
    Params,
    /// It has none.
    Empty,
    /// It didn't decode.
    Decode,
}

/// The signature's AlgorithmIdentifier from the key context's provider
/// (`OSSL_SIGNATURE_PARAM_ALGORITHM_ID`), decoded into `alg1` and `alg2` where they're given.
///
/// # Safety
/// `pctx` is a live key context; `alg1` and `alg2` are NULL or live AlgorithmIdentifiers.
pub(crate) unsafe fn algorithm_id(
    pctx: *mut EVP_PKEY_CTX,
    alg1: *mut X509_ALGOR,
    alg2: *mut X509_ALGOR,
) -> Result<(), AidError> {
    let mut aid = [0u8; 128];
    let mut params: [OSSL_PARAM; 2] = [
        // SAFETY: a static key; the buffer's room.
        unsafe {
            OSSL_PARAM_construct_octet_string(
                OSSL_SIGNATURE_PARAM_ALGORITHM_ID.as_ptr(),
                aid.as_mut_ptr().cast(),
                aid.len(),
            )
        },
        end(),
    ];
    // SAFETY: the caller's context; an ended array.
    if unsafe { EVP_PKEY_CTX_get_params(pctx, params.as_mut_ptr()) } <= 0 {
        return Err(AidError::Params);
    }
    let len = params[0].return_size.min(aid.len());
    if len == 0 {
        return Err(AidError::Empty);
    }
    let len = core::ffi::c_long::try_from(len).map_err(|_| AidError::Decode)?;
    for mut a in [alg1, alg2] {
        if a.is_null() {
            continue;
        }
        let mut pp = aid.as_ptr();
        // SAFETY: the caller's AlgorithmIdentifier, decoded into; the encoding's octets.
        if unsafe { d2i_X509_ALGOR(&mut a, &mut pp, len) }.is_null() {
            return Err(AidError::Decode);
        }
    }
    Ok(())
}

/// The DER of `data` (an `it`), from `ASN1_item_i2d`, with its length; `None` raising
/// `ERR_R_INTERNAL_ERROR` from `f`.
///
/// # Safety
/// `it` is a live item and `data` NULL or a value of it.
unsafe fn encode(it: *const ASN1_ITEM, data: *const c_void, f: &str) -> Option<(*mut u8, usize)> {
    let mut buf: *mut u8 = ptr::null_mut();
    // SAFETY: the caller's guarantee.
    let len = unsafe { ASN1_item_i2d(data.cast(), &mut buf, it) };
    match usize::try_from(len) {
        Ok(l) if l > 0 => Some((buf, l)),
        _ => {
            err::raise(ERR_LIB_ASN1, ERR_R_INTERNAL_ERROR, f);
            // SAFETY: from the encoder's allocator, or NULL.
            unsafe { mem::release(buf.cast()) };
            None
        }
    }
}

ffi_export! {
    /// Signs `data` (an `it`) with `pkey` and `type_`, setting `algor1` and `algor2` (each NULL
    /// or an AlgorithmIdentifier) to the signature's algorithm and `signature` to it: the
    /// signature's length, or 0.
    ///
    /// # Safety
    /// `it` is a live item and `data` a value of it; `algor1` and `algor2` are NULL or live;
    /// `signature` is a live BIT STRING; `pkey` is a live key; `type_` is NULL or a digest.
    pub unsafe extern "C" fn ASN1_item_sign(it: *const ASN1_ITEM, algor1: *mut X509_ALGOR, algor2: *mut X509_ALGOR, signature: *mut ASN1_BIT_STRING, data: *const c_void, pkey: *mut EVP_PKEY, type_: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_sign_ex(it, algor1, algor2, signature, data, ptr::null(), pkey, type_, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// [`ASN1_item_sign`] with the distinguishing ID `id` (NULL for none), and the signature
    /// algorithm fetched from `libctx` with `propq`.
    ///
    /// # Safety
    /// As for [`ASN1_item_sign`]; `id` is NULL or a live string; `propq` is NULL or a string.
    pub unsafe extern "C" fn ASN1_item_sign_ex(it: *const ASN1_ITEM, algor1: *mut X509_ALGOR, algor2: *mut X509_ALGOR, signature: *mut ASN1_BIT_STRING, data: *const c_void, id: *const ASN1_OCTET_STRING, pkey: *mut EVP_PKEY, md: *const EVP_MD, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let ctx = unsafe { md_ctx_new_ex(pkey, id, libctx, propq) };
        if ctx.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_EVP_LIB, "ASN1_item_sign_ex");
            return 0;
        }
        // SAFETY: the new context; the caller's digest and key.
        let rv = if unsafe { EVP_DigestSignInit(ctx, ptr::null_mut(), md, ptr::null_mut(), pkey) } == 0 {
            0
        } else {
            // SAFETY: the caller's guarantee; the context ready to sign.
            unsafe { ASN1_item_sign_ctx(it, algor1, algor2, signature, data, ctx) }
        };
        // SAFETY: made above.
        unsafe { md_ctx_free_ex(ctx) };
        rv
    }
}

ffi_export! {
    /// [`ASN1_item_sign`] with the digest context `ctx`, initialised for signing: the
    /// signature's length, or 0.
    ///
    /// # Safety
    /// As for [`ASN1_item_sign`]; `ctx` is a live digest context with a key context.
    pub unsafe extern "C" fn ASN1_item_sign_ctx(it: *const ASN1_ITEM, algor1: *mut X509_ALGOR, algor2: *mut X509_ALGOR, signature: *mut ASN1_BIT_STRING, data: *const c_void, ctx: *mut EVP_MD_CTX) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        const F: &str = "ASN1_item_sign_ctx";
        // SAFETY: the caller's context.
        let md = unsafe { EVP_MD_CTX_get0_md(ctx) };
        // SAFETY: as above.
        let pctx = unsafe { EVP_MD_CTX_get_pkey_ctx(ctx) };
        // SAFETY: its key context.
        let pk = unsafe { EVP_PKEY_CTX_get0_pkey(pctx) };
        if pk.is_null() || signature.is_null() {
            err::raise(ERR_LIB_ASN1, ASN1_R_CONTEXT_NOT_INITIALISED, F);
            return 0;
        }
        // SAFETY: the context's key.
        let m = unsafe { EVP_PKEY_get0_asn1(pk) };
        // SAFETY: the key's method, kept while the key lives.
        match unsafe { EVP_PKEY_ASN1_METHOD::get(m) } {
            None => {
                // A provided key: its provider's AlgorithmIdentifier.
                // SAFETY: the context's key context.
                let sig_op = unsafe { crate::evp::pkey_ctx::context(pctx) }.is_some_and(|c| c.lock().is_sig_op());
                if !sig_op {
                    err::raise(ERR_LIB_ASN1, ASN1_R_CONTEXT_NOT_INITIALISED, F);
                    return 0;
                }
                // SAFETY: as above; the caller's AlgorithmIdentifiers.
                match unsafe { algorithm_id(pctx, algor1, algor2) } {
                    Ok(()) => {}
                    Err(AidError::Params) => return 0,
                    Err(AidError::Empty) => {
                        err::raise(ERR_LIB_ASN1, ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED, F);
                        return 0;
                    }
                    Err(AidError::Decode) => {
                        err::raise(ERR_LIB_ASN1, ERR_R_INTERNAL_ERROR, F);
                        return 0;
                    }
                }
            }
            Some(a) => {
                let rv = match a.funcs().item_sign {
                    // SAFETY: the method's function, given the caller's arguments.
                    Some(f) => unsafe { f(ctx, it, data, algor1, algor2, signature) },
                    None => 2,
                };
                if rv <= 0 {
                    err::raise(ERR_LIB_ASN1, ERR_R_EVP_LIB, F);
                }
                if rv == 1 {
                    // The method signed it.
                    // SAFETY: the caller's BIT STRING.
                    return unsafe { (*signature).length };
                }
                if rv <= 1 {
                    return 0;
                }
                if rv == 2 {
                    // The AlgorithmIdentifier the digest and key type name.
                    if md.is_null() {
                        err::raise(ERR_LIB_ASN1, ASN1_R_CONTEXT_NOT_INITIALISED, F);
                        return 0;
                    }
                    // SAFETY: the context's key.
                    let pkey_id = if unsafe { EVP_PKEY_get_id(pk) } == NID_sm2 {
                        NID_sm2
                    } else {
                        a.pkey_id
                    };
                    let mut signid = NID_undef;
                    // SAFETY: the context's digest.
                    let mdnid = unsafe { EVP_MD_get_type(md) };
                    // SAFETY: a writable NID.
                    if unsafe { OBJ_find_sigid_by_algs(&mut signid, mdnid, pkey_id) } == 0 {
                        err::raise(ERR_LIB_ASN1, ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED, F);
                        return 0;
                    }
                    let paramtype = if a.flags & ASN1_PKEY_SIGPARAM_NULL.cast_unsigned() as core::ffi::c_ulong != 0 {
                        V_ASN1_NULL
                    } else {
                        V_ASN1_UNDEF
                    };
                    for alg in [algor1, algor2] {
                        // SAFETY: a NID from the table.
                        let obj = unsafe { OBJ_nid2obj(signid) };
                        // SAFETY: the caller's AlgorithmIdentifier.
                        if !alg.is_null() && unsafe { X509_ALGOR_set0(alg, obj, paramtype, ptr::null_mut()) } == 0 {
                            return 0;
                        }
                    }
                }
            }
        }
        // SAFETY: the caller's item and value.
        let Some((buf_in, inl)) = (unsafe { encode(it, data, F) }) else { return 0 };
        let clear_in = || {
            // SAFETY: the encoding, `inl` octets from the allocator.
            unsafe { mem::release_clean(buf_in.cast(), inl) };
        };
        let mut outll = 0usize;
        // SAFETY: the context ready to sign; the encoding.
        if unsafe { EVP_DigestSign(ctx, ptr::null_mut(), &mut outll, buf_in, inl) } == 0 {
            err::raise(ERR_LIB_ASN1, ERR_R_EVP_LIB, F);
            clear_in();
            return 0;
        }
        let buf_out: *mut u8 = mem::alloc(outll).cast();
        if buf_out.is_null() {
            clear_in();
            return 0;
        }
        let mut outl = outll;
        // SAFETY: as above; room for `outll` octets.
        let ok = unsafe { EVP_DigestSign(ctx, buf_out, &mut outl, buf_in, inl) } != 0;
        clear_in();
        let len = c_int::try_from(outl).ok().filter(|_| ok);
        let Some(len) = len else {
            if !ok {
                err::raise(ERR_LIB_ASN1, ERR_R_EVP_LIB, F);
            }
            // SAFETY: allocated above, `outll` octets.
            unsafe { mem::release_clean(buf_out.cast(), outll) };
            return 0;
        };
        // SAFETY: the caller's BIT STRING; the signature, which it takes.
        unsafe { ASN1_STRING_set0(signature, buf_out.cast(), len) };
        // SAFETY: as above.
        unsafe { no_bits_left(signature) };
        len
    }
}

ffi_export! {
    /// Checks `signature`, made with the algorithm `alg`, is `pkey`'s of `data` (an `it`):
    /// 1 if it is, 0 if it isn't, -1 if it can't be checked.
    ///
    /// # Safety
    /// `it` is a live item and `data` a value of it; `alg` and `signature` are live; `pkey` is
    /// NULL or a live key.
    pub unsafe extern "C" fn ASN1_item_verify(it: *const ASN1_ITEM, alg: *const X509_ALGOR, signature: *const ASN1_BIT_STRING, data: *const c_void, pkey: *mut EVP_PKEY) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_verify_ex(it, alg, signature, data, ptr::null(), pkey, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// [`ASN1_item_verify`] with the distinguishing ID `id` (NULL for none), and the signature
    /// algorithm fetched from `libctx` with `propq`.
    ///
    /// # Safety
    /// As for [`ASN1_item_verify`]; `id` is NULL or a live string; `propq` is NULL or a string.
    pub unsafe extern "C" fn ASN1_item_verify_ex(it: *const ASN1_ITEM, alg: *const X509_ALGOR, signature: *const ASN1_BIT_STRING, data: *const c_void, id: *const ASN1_OCTET_STRING, pkey: *mut EVP_PKEY, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let ctx = unsafe { md_ctx_new_ex(pkey, id, libctx, propq) };
        if ctx.is_null() {
            return -1;
        }
        // SAFETY: the caller's guarantee; the new context.
        let rv = unsafe { ASN1_item_verify_ctx(it, alg, signature, data, ctx) };
        // SAFETY: made above.
        unsafe { md_ctx_free_ex(ctx) };
        rv
    }
}

ffi_export! {
    /// [`ASN1_item_verify`] with the digest context `ctx`, whose key context has the key.
    ///
    /// # Safety
    /// As for [`ASN1_item_verify`]; `ctx` is a live digest context with a key context.
    pub unsafe extern "C" fn ASN1_item_verify_ctx(it: *const ASN1_ITEM, alg: *const X509_ALGOR, signature: *const ASN1_BIT_STRING, data: *const c_void, ctx: *mut EVP_MD_CTX) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        const F: &str = "ASN1_item_verify_ctx";
        // SAFETY: the caller's context.
        let pctx = unsafe { EVP_MD_CTX_get_pkey_ctx(ctx) };
        // SAFETY: its key context.
        let pk = unsafe { EVP_PKEY_CTX_get0_pkey(pctx) };
        // SAFETY: the caller's AlgorithmIdentifier and BIT STRING.
        let (Some(k), Some(s), Some(a)) = (unsafe { pkey(pk) }, unsafe { signature.as_ref() }, unsafe { alg.as_ref() }) else {
            err::raise(ERR_LIB_ASN1, ERR_R_PASSED_NULL_PARAMETER, F);
            return -1;
        };
        if s.type_ == V_ASN1_BIT_STRING && s.flags & 0x7 != 0 {
            err::raise(ERR_LIB_ASN1, ASN1_R_INVALID_BIT_STRING_BITS_LEFT, F);
            return -1;
        }
        let (mut mdnid, mut pknid) = (NID_undef, NID_undef);
        // SAFETY: the AlgorithmIdentifier's object.
        let signid = unsafe { OBJ_obj2nid(a.algorithm) };
        // SAFETY: writable NIDs.
        if unsafe { OBJ_find_sigid_algs(signid, &mut mdnid, &mut pknid) } == 0 {
            err::raise(ERR_LIB_ASN1, ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM, F);
            return -1;
        }
        if mdnid == NID_undef && k.lock().is_legacy() {
            // The key's method knows the algorithm.
            let Some(f) = k.ameth_funcs().and_then(|f| f.item_verify) else {
                err::raise(ERR_LIB_ASN1, ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM, F);
                return -1;
            };
            // SAFETY: the method's function, given the caller's arguments.
            let ret = unsafe { f(ctx, it, data, alg, signature, pk) };
            if ret <= 0 {
                err::raise(ERR_LIB_ASN1, ERR_R_EVP_LIB, F);
            }
            if ret <= 1 {
                return ret;
            }
        } else if mdnid == NID_undef && pknid == EVP_PKEY_RSA_PSS {
            // SAFETY: the context's key; static names.
            if unsafe { EVP_PKEY_is_a(pk, c"RSA".as_ptr()) } == 0 && unsafe { EVP_PKEY_is_a(pk, c"RSA-PSS".as_ptr()) } == 0 {
                err::raise(ERR_LIB_ASN1, ASN1_R_WRONG_PUBLIC_KEY_TYPE, F);
                return -1;
            }
            // SAFETY: the caller's context and AlgorithmIdentifier; the context's key.
            if unsafe { crate::evp::pkey::rsa::pss_to_ctx(ctx, ptr::null_mut(), alg, pk) } <= 0 {
                err::raise(ERR_LIB_ASN1, ERR_R_INTERNAL_ERROR, F);
                return -1;
            }
        } else {
            // SAFETY: a NID.
            let sn = unsafe { OBJ_nid2sn(pknid) };
            // SAFETY: the context's key; a name from the table, or NULL.
            if sn.is_null() || unsafe { EVP_PKEY_is_a(pk, sn) } == 0 {
                err::raise(ERR_LIB_ASN1, ASN1_R_WRONG_PUBLIC_KEY_TYPE, F);
                return -1;
            }
            let mut type_ = ptr::null();
            if mdnid != NID_undef {
                // SAFETY: a NID.
                let mdsn = unsafe { OBJ_nid2sn(mdnid) };
                if !mdsn.is_null() {
                    // SAFETY: a name from the table.
                    type_ = unsafe { EVP_get_digestbyname(mdsn) };
                }
                if type_.is_null() {
                    err::raise_with_text(ERR_LIB_ASN1, ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM, F, &format!("nid=0x{mdnid:x}"));
                    return -1;
                }
            }
            // SAFETY: the caller's context; the digest, or NULL; the context's key.
            if unsafe { EVP_DigestVerifyInit(ctx, ptr::null_mut(), type_, ptr::null_mut(), pk) } == 0 {
                err::raise(ERR_LIB_ASN1, ERR_R_EVP_LIB, F);
                return 0;
            }
        }
        // SAFETY: the caller's item and value.
        let Some((buf_in, inl)) = (unsafe { encode(it, data, F) }) else { return -1 };
        if buf_in.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
            return -1;
        }
        let siglen = usize::try_from(s.length).unwrap_or(0);
        // SAFETY: the context ready to verify; the signature's octets; the encoding.
        let ret = unsafe { EVP_DigestVerify(ctx, s.data, siglen, buf_in, inl) };
        // SAFETY: the encoding, `inl` octets from the allocator.
        unsafe { mem::release_clean(buf_in.cast(), inl) };
        if ret <= 0 {
            err::raise(ERR_LIB_ASN1, ERR_R_EVP_LIB, F);
            return ret;
        }
        1
    }
}

/// The encoding of `data` by `i2d`, with its length, into memory the caller releases; `None`
/// raising `ERR_R_INTERNAL_ERROR` from `f` (or nothing, without memory).
///
/// # Safety
/// `i2d` is a trusted function for `data`'s type.
unsafe fn encode_old(
    i2d: unsafe extern "C" fn(*const c_void, *mut *mut u8) -> c_int,
    data: *const c_void,
    f: &str,
) -> Option<(*mut u8, usize)> {
    // SAFETY: the caller's guarantee.
    let inl = unsafe { i2d(data, ptr::null_mut()) };
    let Ok(n) = usize::try_from(inl) else {
        err::raise(ERR_LIB_ASN1, ERR_R_INTERNAL_ERROR, f);
        return None;
    };
    if n == 0 {
        err::raise(ERR_LIB_ASN1, ERR_R_INTERNAL_ERROR, f);
        return None;
    }
    let buf: *mut u8 = mem::alloc(n).cast();
    if buf.is_null() {
        return None;
    }
    let mut p = buf;
    // SAFETY: as above; room for the encoding.
    unsafe { i2d(data, &mut p) };
    Some((buf, n))
}

ffi_export! {
    /// The deprecated `ASN1_sign`: signs `data`'s encoding by `i2d` with `pkey` and `type_`,
    /// setting `algor1` and `algor2` (each NULL or an AlgorithmIdentifier) to the digest's
    /// signature algorithm (with a NULL parameter, but none for DSA with SHA-1): the
    /// signature's length, or 0.
    ///
    /// # Safety
    /// `i2d` is a trusted function for `data`'s type; `algor1` and `algor2` are NULL or live;
    /// `signature` is a live BIT STRING; `pkey` is a live key; `type_` is a live digest.
    pub unsafe extern "C" fn ASN1_sign(i2d: i2d_of_void, algor1: *mut X509_ALGOR, algor2: *mut X509_ALGOR, signature: *mut ASN1_BIT_STRING, data: *mut c_char, pkey: *mut EVP_PKEY, type_: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        const F: &str = "ASN1_sign";
        let Some(i2d) = i2d else { return 0 };
        if type_.is_null() || signature.is_null() {
            return 0;
        }
        // SAFETY: no preconditions.
        let ctx = unsafe { EVP_MD_CTX_new() };
        if ctx.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_EVP_LIB, F);
            return 0;
        }
        // SAFETY: made above.
        let free_ctx = || unsafe { EVP_MD_CTX_free(ctx) };
        // SAFETY: the caller's digest.
        let pkey_type = unsafe { EVP_MD_get_pkey_type(type_) };
        for a in [algor1, algor2] {
            // SAFETY: the caller's AlgorithmIdentifier.
            let Some(a) = (unsafe { a.as_mut() }) else { continue };
            if pkey_type == NID_dsaWithSHA1 {
                // SAFETY: its parameter, which it owns.
                unsafe { ASN1_TYPE_free(a.parameter) };
                a.parameter = ptr::null_mut();
            // SAFETY: its parameter, if any.
            } else if a.parameter.is_null() || unsafe { (*a.parameter).type_ } != V_ASN1_NULL {
                // SAFETY: as above.
                unsafe { ASN1_TYPE_free(a.parameter) };
                // SAFETY: no preconditions.
                a.parameter = unsafe { ASN1_TYPE_new() };
                // SAFETY: new, or NULL.
                let Some(t) = (unsafe { a.parameter.as_mut() }) else {
                    free_ctx();
                    return 0;
                };
                t.type_ = V_ASN1_NULL;
            }
            // SAFETY: its object, which it owns.
            unsafe { ASN1_OBJECT_free(a.algorithm) };
            // SAFETY: a NID.
            a.algorithm = unsafe { OBJ_nid2obj(pkey_type) };
            if a.algorithm.is_null() {
                err::raise(ERR_LIB_ASN1, ASN1_R_UNKNOWN_OBJECT_TYPE, F);
                free_ctx();
                return 0;
            }
            // SAFETY: the object.
            if unsafe { OBJ_length(a.algorithm) } == 0 {
                err::raise(ERR_LIB_ASN1, ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD, F);
                free_ctx();
                return 0;
            }
        }
        // SAFETY: the caller's guarantee.
        let Some((buf_in, inl)) = (unsafe { encode_old(i2d, data.cast_const().cast(), F) }) else {
            free_ctx();
            return 0;
        };
        // SAFETY: the caller's key.
        let size = unsafe { EVP_PKEY_get_size(pkey) };
        let outll = usize::try_from(size).unwrap_or(0);
        let buf_out: *mut u8 = if outll == 0 { ptr::null_mut() } else { mem::alloc(outll).cast() };
        let done = |out_len: c_int| {
            free_ctx();
            // SAFETY: the encoding, `inl` octets from the allocator.
            unsafe { mem::release_clean(buf_in.cast(), inl) };
            out_len
        };
        if buf_out.is_null() {
            return done(0);
        }
        let mut outl = c_uint::try_from(size).unwrap_or(0);
        // SAFETY: the new context; the caller's digest; the encoding; room for the
        // signature; the caller's key.
        let ok = unsafe { EVP_DigestInit_ex(ctx, type_, ptr::null_mut()) } != 0
            // SAFETY: as above.
            && unsafe { EVP_DigestUpdate(ctx, buf_in.cast(), inl) } != 0
            // SAFETY: as above.
            && unsafe { EVP_SignFinal(ctx, buf_out, &mut outl, pkey) } != 0;
        let len = c_int::try_from(outl).ok().filter(|_| ok);
        let Some(len) = len else {
            err::raise(ERR_LIB_ASN1, ERR_R_EVP_LIB, F);
            // SAFETY: allocated above, `outll` octets.
            unsafe { mem::release_clean(buf_out.cast(), outll) };
            return done(0);
        };
        // SAFETY: the caller's BIT STRING; the signature, which it takes.
        unsafe { ASN1_STRING_set0(signature, buf_out.cast(), len) };
        // SAFETY: as above.
        unsafe { no_bits_left(signature) };
        done(len)
    }
}

ffi_export! {
    /// The deprecated `ASN1_verify`: checks `signature` is `pkey`'s of `data`'s encoding by
    /// `i2d`, with the digest `a` names: 1 if it is, 0 if it isn't, -1 if it can't be checked.
    ///
    /// # Safety
    /// `i2d` is a trusted function for `data`'s type; `a` and `signature` are live; `pkey` is
    /// a live key.
    pub unsafe extern "C" fn ASN1_verify(i2d: i2d_of_void, a: *mut X509_ALGOR, signature: *mut ASN1_BIT_STRING, data: *mut c_char, pkey: *mut EVP_PKEY) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        const F: &str = "ASN1_verify";
        // SAFETY: the caller's AlgorithmIdentifier and BIT STRING.
        let (Some(i2d), Some(alg), Some(s)) = (i2d, unsafe { a.as_ref() }, unsafe { signature.as_ref() }) else {
            return -1;
        };
        // SAFETY: no preconditions.
        let ctx = unsafe { EVP_MD_CTX_new() };
        if ctx.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_EVP_LIB, F);
            return -1;
        }
        let done = |ret: c_int| {
            // SAFETY: made above.
            unsafe { EVP_MD_CTX_free(ctx) };
            ret
        };
        // SAFETY: the AlgorithmIdentifier's object.
        let nid = unsafe { OBJ_obj2nid(alg.algorithm) };
        // SAFETY: a NID.
        let sn = unsafe { OBJ_nid2sn(nid) };
        // SAFETY: a name from the table.
        let type_ = if sn.is_null() { ptr::null() } else { unsafe { EVP_get_digestbyname(sn) } };
        if type_.is_null() {
            err::raise(ERR_LIB_ASN1, ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM, F);
            return done(-1);
        }
        if s.type_ == V_ASN1_BIT_STRING && s.flags & 0x7 != 0 {
            err::raise(ERR_LIB_ASN1, ASN1_R_INVALID_BIT_STRING_BITS_LEFT, F);
            return done(-1);
        }
        // SAFETY: the caller's guarantee.
        let Some((buf_in, inl)) = (unsafe { encode_old(i2d, data.cast_const().cast(), F) }) else {
            return done(-1);
        };
        // SAFETY: the new context; the digest; the encoding.
        let ok = unsafe { EVP_DigestInit_ex(ctx, type_, ptr::null_mut()) } != 0
            // SAFETY: as above.
            && unsafe { EVP_DigestUpdate(ctx, buf_in.cast(), inl) } != 0;
        // SAFETY: the encoding, `inl` octets from the allocator.
        unsafe { mem::release_clean(buf_in.cast(), inl) };
        if !ok {
            err::raise(ERR_LIB_ASN1, ERR_R_EVP_LIB, F);
            return done(-1);
        }
        let siglen = c_uint::try_from(s.length).unwrap_or(0);
        // SAFETY: the context; the signature's octets; the caller's key.
        if unsafe { EVP_VerifyFinal(ctx, s.data, siglen, pkey) } <= 0 {
            err::raise(ERR_LIB_ASN1, ERR_R_EVP_LIB, F);
            return done(0);
        }
        done(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::string::{ASN1_BIT_STRING_free, ASN1_BIT_STRING_new};
    use crate::asn1::tpl::items::{X509_ALGOR_free, X509_ALGOR_new};
    use crate::evp::pkey::EVP_PKEY_free;
    use crate::evp::pkey::raw::EVP_PKEY_new_raw_private_key;
    use crate::x509::name::{X509_NAME_free, X509_NAME_it, X509_NAME_new};

    /// docs/DEVIATIONS.md: a NULL AlgorithmIdentifier, signature, `i2d`, or digest, which
    /// OpenSSL reads through, fails.
    #[test]
    #[cfg_attr(miri, ignore = "makes a key, which loads the configuration")]
    fn null_arguments_fail() {
        let seed = [9u8; 32];
        // SAFETY: a 32-octet Ed25519 key.
        let k = unsafe {
            EVP_PKEY_new_raw_private_key(
                rustyssl_abi::EVP_PKEY_ED25519,
                ptr::null_mut(),
                seed.as_ptr(),
                32,
            )
        };
        assert!(!k.is_null());
        // SAFETY: no preconditions.
        let n = unsafe { X509_NAME_new() };
        // SAFETY: as above.
        let alg = unsafe { X509_ALGOR_new() };
        // SAFETY: as above.
        let sig = unsafe { ASN1_BIT_STRING_new() };
        // SAFETY: as above.
        let it = unsafe { X509_NAME_it() };
        let data: *mut c_char = n.cast();
        let none = ptr::null_mut();
        // SAFETY: a live item, name, and key; NULL where refused.
        let r = unsafe { ASN1_item_verify(it, ptr::null(), sig, data.cast(), k) };
        assert_eq!(r, -1);
        // SAFETY: as above.
        let r = unsafe { ASN1_item_verify(it, alg, ptr::null(), data.cast(), k) };
        assert_eq!(r, -1);
        // SAFETY: as above.
        let r =
            unsafe { ASN1_item_sign(it, alg, none, ptr::null_mut(), data.cast(), k, ptr::null()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { ASN1_sign(None, alg, none, sig, data, k, ptr::null()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { ASN1_verify(None, alg, sig, data, k) };
        assert_eq!(r, -1);
        // SAFETY: as above.
        let r = unsafe { ASN1_verify(None, none, none.cast(), data, k) };
        assert_eq!(r, -1);
        // The NULL cases' errors.
        crate::err::take_all();
        // SAFETY: made above.
        unsafe { ASN1_BIT_STRING_free(sig) };
        // SAFETY: as above.
        unsafe { X509_ALGOR_free(alg) };
        // SAFETY: as above.
        unsafe { X509_NAME_free(n) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(k) };
    }
}
