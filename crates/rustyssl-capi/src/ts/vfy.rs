//! Verifying (`ts_verify_ctx.c`, `ts_rsp_verify.c`): the verification context, a token's
//! signature and signer chain (with the signer named in its signing-certificate attribute),
//! and a TSTInfo's version, policy, imprint, nonce, and TSA name against the context.

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_INTEGER, ASN1_OBJECT, BIO, ERR_LIB_TS, ERR_R_EVP_LIB, ERR_R_X509_LIB, GEN_DIRNAME,
    GENERAL_NAME, NID_id_smime_aa_signingCertificate, NID_id_smime_aa_signingCertificateV2,
    NID_pkcs7_signed, NID_subject_alt_name, PKCS7, PKCS7_OP_GET_DETACHED_SIGNATURE,
    PKCS7_SIGNER_INFO, TS_INFO_ADD_INFO_NOT_AVAILABLE, TS_INFO_BAD_ALG, TS_INFO_BAD_DATA_FORMAT,
    TS_INFO_BAD_REQUEST, TS_INFO_SYSTEM_FAILURE, TS_INFO_TIME_NOT_AVAILABLE,
    TS_INFO_UNACCEPTED_EXTENSION, TS_INFO_UNACCEPTED_POLICY, TS_MAX_STATUS_LENGTH,
    TS_R_CERTIFICATE_VERIFY_ERROR, TS_R_INVALID_NULL_POINTER, TS_R_MESSAGE_IMPRINT_MISMATCH,
    TS_R_NO_CONTENT, TS_R_NO_TIME_STAMP_TOKEN, TS_R_NONCE_MISMATCH, TS_R_NONCE_NOT_RETURNED,
    TS_R_POLICY_MISMATCH, TS_R_SIGNATURE_FAILURE, TS_R_THERE_MUST_BE_ONE_SIGNER,
    TS_R_TSA_NAME_MISMATCH, TS_R_TSA_UNTRUSTED, TS_R_UNSUPPORTED_VERSION, TS_R_WRONG_CONTENT_TYPE,
    TS_REQ, TS_RESP, TS_TST_INFO, TS_VERIFY_CTX, TS_VFY_ALL_IMPRINT, TS_VFY_DATA, TS_VFY_IMPRINT,
    TS_VFY_NONCE, TS_VFY_POLICY, TS_VFY_SIGNATURE, TS_VFY_SIGNER, TS_VFY_TSA_NAME, TS_VFY_VERSION,
    V_ASN1_NULL, V_ASN1_SEQUENCE, X509, X509_ALGOR, X509_PURPOSE_TIMESTAMP_SIGN, X509_STORE,
    stack_st_ASN1_UTF8STRING, stack_st_GENERAL_NAME, stack_st_X509,
};

use super::asn::{
    MsgImprint, PKCS7_to_TS_TST_INFO, Req, Resp, StatusInfo, TS_TST_INFO_free, TstInfo,
};
use super::utils::{TS_TST_INFO_get_version, of};
use crate::asn1::any::ASN1_TYPE_get;
use crate::asn1::bit_string::ASN1_BIT_STRING_get_bit;
use crate::asn1::integer::{ASN1_INTEGER_cmp, ASN1_INTEGER_dup, ASN1_INTEGER_get};
use crate::asn1::string::{ASN1_INTEGER_free, ASN1_STRING_get0_data, ASN1_STRING_length};
use crate::asn1::tpl::items::X509_ALGOR_free;
use crate::bio::{BIO_free_all, BIO_read};
use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::ess::{
    ESS_SIGNING_CERT_V2_free, ESS_SIGNING_CERT_free, OSSL_ESS_check_signing_certs,
    d2i_ESS_SIGNING_CERT, d2i_ESS_SIGNING_CERT_V2,
};
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_get_size};
use crate::evp::legacy_md::EVP_get_digestbyname;
use crate::evp::md_ctx::{
    EVP_DigestFinal, EVP_DigestInit, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
};
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::{ASN1_OBJECT_free, OBJ_cmp, OBJ_dup, OBJ_obj2nid, OBJ_obj2txt};
use crate::pkcs7::doit::{PKCS7_dataInit, PKCS7_signatureVerify};
use crate::pkcs7::smime::PKCS7_get0_signers;
use crate::pkcs7::{PKCS7_ctrl, PKCS7_get_signed_attribute, PKCS7_get_signer_info};
use crate::stack::{OPENSSL_sk_free, OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_value};
use crate::x509::algor::X509_ALGOR_dup;
use crate::x509::cert::{OSSL_STACK_OF_X509_free, X509_free, X509_get_subject_name, X509_up_ref};
use crate::x509::ctx::{
    X509_STORE_CTX_free, X509_STORE_CTX_get_error, X509_STORE_CTX_get1_chain, X509_STORE_CTX_init,
    X509_STORE_CTX_new, X509_STORE_CTX_set_purpose, X509_verify_cert_error_string,
};
use crate::x509::name::X509_NAME_cmp;
use crate::x509::purpose::{X509_add_certs, X509_get_ext_d2i};
use crate::x509::store::X509_STORE_free;
use crate::x509::verify::X509_verify_cert;
use crate::x509v3::genn::{GENERAL_NAME_cmp, GENERAL_NAME_free, GENERAL_NAMES_free};

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_TS, reason, f);
}

/// `TS_VERIFY_CTX`: what to check, and what to check it against.
#[repr(C)]
pub(crate) struct VerifyCtx {
    pub(crate) flags: c_uint,
    pub(crate) store: *mut X509_STORE,
    pub(crate) certs: *mut stack_st_X509,
    pub(crate) policy: *mut ASN1_OBJECT,
    pub(crate) md_alg: *mut X509_ALGOR,
    pub(crate) imprint: *mut c_uchar,
    pub(crate) imprint_len: c_uint,
    pub(crate) data: *mut BIO,
    pub(crate) nonce: *mut ASN1_INTEGER,
    pub(crate) tsa_name: *mut GENERAL_NAME,
}

/// The context behind a pointer.
///
/// # Safety
/// `p` is NULL or a live context.
unsafe fn ctx_of<'a>(p: *mut TS_VERIFY_CTX) -> Option<&'a mut VerifyCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { p.cast::<VerifyCtx>().as_mut() }
}

/// Frees what the context holds and empties it.
///
/// # Safety
/// `c`'s members are NULL or its own.
unsafe fn cleanup(c: &mut VerifyCtx) {
    // SAFETY: each its own, or NULL.
    unsafe { X509_STORE_free(c.store) };
    // SAFETY: as above.
    unsafe { OSSL_STACK_OF_X509_free(c.certs) };
    // SAFETY: as above.
    unsafe { ASN1_OBJECT_free(c.policy) };
    // SAFETY: as above.
    unsafe { X509_ALGOR_free(c.md_alg) };
    // SAFETY: as above, from `CRYPTO_malloc`.
    unsafe { mem::release(c.imprint.cast()) };
    // SAFETY: as above.
    unsafe { BIO_free_all(c.data) };
    // SAFETY: as above.
    unsafe { ASN1_INTEGER_free(c.nonce) };
    // SAFETY: as above.
    unsafe { GENERAL_NAME_free(c.tsa_name) };
    *c = empty();
}

fn empty() -> VerifyCtx {
    VerifyCtx {
        flags: 0,
        store: ptr::null_mut(),
        certs: ptr::null_mut(),
        policy: ptr::null_mut(),
        md_alg: ptr::null_mut(),
        imprint: ptr::null_mut(),
        imprint_len: 0,
        data: ptr::null_mut(),
        nonce: ptr::null_mut(),
        tsa_name: ptr::null_mut(),
    }
}

ffi_export! {
    /// A new, empty verification context, or NULL.
    ///
    /// # Safety
    /// None.
    pub unsafe extern "C" fn TS_VERIFY_CTX_new() -> *mut TS_VERIFY_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        mem::alloc_zeroed(size_of::<VerifyCtx>()).cast()
    }
}

ffi_export! {
    /// Empties the context without freeing what it holds; aborts for NULL, as OpenSSL does.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub unsafe extern "C" fn TS_VERIFY_CTX_init(ctx: *mut TS_VERIFY_CTX)
    where failure = (), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { crate::ffi::die("ctx != NULL") };
        *c = empty();
    }
}

ffi_export! {
    /// Frees what the context holds and empties it.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn TS_VERIFY_CTX_cleanup(ctx: *mut TS_VERIFY_CTX)
    where failure = (), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            // SAFETY: its own members.
            unsafe { cleanup(c) };
        }
    }
}

ffi_export! {
    /// Frees the context and what it holds.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context, not used again.
    pub unsafe extern "C" fn TS_VERIFY_CTX_free(ctx: *mut TS_VERIFY_CTX)
    where failure = (), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return };
        // SAFETY: its own members.
        unsafe { cleanup(c) };
        // SAFETY: made by `TS_VERIFY_CTX_new`.
        unsafe { mem::release(ctx.cast()) };
    }
}

ffi_export! {
    /// Adds to the checks: the new flags.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub unsafe extern "C" fn TS_VERIFY_CTX_add_flags(ctx: *mut TS_VERIFY_CTX, f: c_int) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        c.flags |= f.cast_unsigned();
        c.flags.cast_signed()
    }
}

ffi_export! {
    /// Sets the checks: the new flags.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub unsafe extern "C" fn TS_VERIFY_CTX_set_flags(ctx: *mut TS_VERIFY_CTX, f: c_int) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        c.flags = f.cast_unsigned();
        c.flags.cast_signed()
    }
}

ffi_export! {
    /// Gives the context the data, without freeing the old (deprecated): `b`.
    ///
    /// # Safety
    /// `ctx` is a live context; `b` NULL or a live BIO.
    pub unsafe extern "C" fn TS_VERIFY_CTX_set_data(ctx: *mut TS_VERIFY_CTX, b: *mut BIO) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return ptr::null_mut() };
        c.data = b;
        b
    }
}

ffi_export! {
    /// Gives the context the data, freeing the old: 1.
    ///
    /// # Safety
    /// `ctx` is a live context; `b` NULL or a live BIO the caller gives up.
    pub unsafe extern "C" fn TS_VERIFY_CTX_set0_data(ctx: *mut TS_VERIFY_CTX, b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        // SAFETY: its own, or NULL.
        unsafe { BIO_free_all(c.data) };
        c.data = b;
        1
    }
}

ffi_export! {
    /// Gives the context the store, without freeing the old (deprecated): `s`.
    ///
    /// # Safety
    /// `ctx` is a live context; `s` NULL or a live store.
    pub unsafe extern "C" fn TS_VERIFY_CTX_set_store(ctx: *mut TS_VERIFY_CTX, s: *mut X509_STORE) -> *mut X509_STORE
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return ptr::null_mut() };
        c.store = s;
        s
    }
}

ffi_export! {
    /// Gives the context the store, freeing the old: 1.
    ///
    /// # Safety
    /// `ctx` is a live context; `s` NULL or a live store the caller gives up.
    pub unsafe extern "C" fn TS_VERIFY_CTX_set0_store(ctx: *mut TS_VERIFY_CTX, s: *mut X509_STORE) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        // SAFETY: its own, or NULL.
        unsafe { X509_STORE_free(c.store) };
        c.store = s;
        1
    }
}

ffi_export! {
    /// Gives the context the certificates, without freeing the old (deprecated): `certs`.
    ///
    /// # Safety
    /// `ctx` is a live context; `certs` NULL or a live list.
    pub unsafe extern "C" fn TS_VERIFY_CTX_set_certs(ctx: *mut TS_VERIFY_CTX, certs: *mut stack_st_X509) -> *mut stack_st_X509
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return ptr::null_mut() };
        c.certs = certs;
        certs
    }
}

ffi_export! {
    /// Gives the context the certificates, freeing the old: 1.
    ///
    /// # Safety
    /// `ctx` is a live context; `certs` NULL or a live list the caller gives up.
    pub unsafe extern "C" fn TS_VERIFY_CTX_set0_certs(ctx: *mut TS_VERIFY_CTX, certs: *mut stack_st_X509) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        // SAFETY: its own, or NULL.
        unsafe { OSSL_STACK_OF_X509_free(c.certs) };
        c.certs = certs;
        1
    }
}

/// Gives the context the imprint (the `len` bytes at `imprint`, from `CRYPTO_malloc`).
///
/// # Safety
/// `imprint` is NULL or `CRYPTO_malloc` memory the caller gives up.
unsafe fn set_imprint(c: &mut VerifyCtx, imprint: *mut c_uchar, len: c_long) {
    // SAFETY: its own, or NULL.
    unsafe { mem::release(c.imprint.cast()) };
    c.imprint = imprint;
    // `unsigned` in OpenSSL's context: the length as C converts it.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "C's conversion of long to unsigned"
    )]
    let len = len as c_uint;
    c.imprint_len = len;
}

ffi_export! {
    /// Gives the context the imprint (deprecated): `hexstr`.
    ///
    /// # Safety
    /// `ctx` is a live context; `hexstr` NULL or `CRYPTO_malloc` memory of `len` bytes the
    /// caller gives up.
    pub unsafe extern "C" fn TS_VERIFY_CTX_set_imprint(ctx: *mut TS_VERIFY_CTX, hexstr: *mut c_uchar, len: c_long) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return ptr::null_mut() };
        // SAFETY: the caller's memory.
        unsafe { set_imprint(c, hexstr, len) };
        hexstr
    }
}

ffi_export! {
    /// Gives the context the imprint: 1.
    ///
    /// # Safety
    /// `ctx` is a live context; `hexstr` NULL or `CRYPTO_malloc` memory of `len` bytes the
    /// caller gives up.
    pub unsafe extern "C" fn TS_VERIFY_CTX_set0_imprint(ctx: *mut TS_VERIFY_CTX, hexstr: *mut c_uchar, len: c_long) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        // SAFETY: the caller's memory.
        unsafe { set_imprint(c, hexstr, len) };
        1
    }
}

/// Fills `c` from the request: its policy, imprint, and nonce.
///
/// # Safety
/// `c` is empty; `r`'s members are NULL or live.
unsafe fn from_request(c: &mut VerifyCtx, r: &Req) -> bool {
    c.flags = TS_VFY_ALL_IMPRINT & !(TS_VFY_TSA_NAME | TS_VFY_SIGNATURE);
    if r.policy_id.is_null() {
        c.flags &= !TS_VFY_POLICY;
    } else {
        // SAFETY: its policy.
        c.policy = unsafe { OBJ_dup(r.policy_id) };
        if c.policy.is_null() {
            return false;
        }
    }
    // SAFETY: its imprint, or NULL.
    let Some(mi) = (unsafe { r.msg_imprint.as_ref() }) else {
        return false;
    };
    // SAFETY: its algorithm.
    c.md_alg = unsafe { X509_ALGOR_dup(mi.hash_algo) };
    if c.md_alg.is_null() {
        return false;
    }
    // SAFETY: its hash.
    let len = unsafe { ASN1_STRING_length(mi.hashed_msg) };
    let Ok(n) = usize::try_from(len) else {
        return false;
    };
    if n == 0 {
        return false;
    }
    c.imprint_len = len.cast_unsigned();
    c.imprint = mem::alloc(n).cast();
    if c.imprint.is_null() {
        return false;
    }
    // SAFETY: its hash.
    let d = unsafe { ASN1_STRING_get0_data(mi.hashed_msg) };
    // SAFETY: its `n` bytes into the `n` just allocated.
    unsafe { ptr::copy_nonoverlapping(d, c.imprint, n) };
    if r.nonce.is_null() {
        c.flags &= !TS_VFY_NONCE;
    } else {
        // SAFETY: its nonce.
        c.nonce = unsafe { ASN1_INTEGER_dup(r.nonce) };
        if c.nonce.is_null() {
            return false;
        }
    }
    true
}

ffi_export! {
    /// A context (`ctx`, emptied, or a new one) to check a response to the request against,
    /// or NULL; aborts for a NULL request, as OpenSSL does.
    ///
    /// # Safety
    /// `req` is a live request; `ctx` NULL or a live context.
    pub unsafe extern "C" fn TS_REQ_to_TS_VERIFY_CTX(req: *mut TS_REQ, ctx: *mut TS_VERIFY_CTX) -> *mut TS_VERIFY_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Req, _>(req) }) else { crate::ffi::die("req != NULL") };
        let ret = if ctx.is_null() {
            // SAFETY: no requirements.
            let n = unsafe { TS_VERIFY_CTX_new() };
            if n.is_null() {
                return ptr::null_mut();
            }
            n
        } else {
            // SAFETY: the caller's context.
            unsafe { TS_VERIFY_CTX_cleanup(ctx) };
            ctx
        };
        // SAFETY: the live context.
        let Some(c) = (unsafe { ctx_of(ret) }) else { return ptr::null_mut() };
        // SAFETY: an empty context; the request's members.
        if unsafe { from_request(c, r) } {
            return ret;
        }
        if ctx.is_null() {
            // SAFETY: the context made here.
            unsafe { TS_VERIFY_CTX_free(ret) };
        } else {
            // SAFETY: the caller's context.
            unsafe { TS_VERIFY_CTX_cleanup(ret) };
        }
        ptr::null_mut()
    }
}

/// The elements of a stack.
///
/// # Safety
/// `sk` is NULL or a live stack.
unsafe fn elements<T>(sk: *const c_void) -> impl Iterator<Item = *mut T> {
    // SAFETY: the caller's stack, or NULL (0).
    let n = unsafe { OPENSSL_sk_num(sk.cast()) };
    // SAFETY: as above, each index in range.
    (0..n.max(0)).map(move |i| unsafe { OPENSSL_sk_value(sk.cast(), i) }.cast())
}

/// `ts_verify_cert`: the signer's chain to the store as a time-stamp signer, or NULL.
///
/// # Safety
/// The arguments are live, or NULL where `X509_STORE_CTX_init` allows it.
unsafe fn verify_cert(
    store: *mut X509_STORE,
    untrusted: *mut stack_st_X509,
    signer: *mut X509,
) -> Option<*mut stack_st_X509> {
    const F: &str = "ts_verify_cert";
    // SAFETY: no requirements.
    let ctx = unsafe { X509_STORE_CTX_new() };
    if ctx.is_null() {
        raise(ERR_R_X509_LIB, F);
        return None;
    }
    let chain = 'end: {
        // SAFETY: a new context; the caller's objects.
        if unsafe { X509_STORE_CTX_init(ctx, store, signer, untrusted) } == 0 {
            break 'end None;
        }
        // SAFETY: a live context.
        unsafe { X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_TIMESTAMP_SIGN) };
        // SAFETY: as above.
        if unsafe { X509_verify_cert(ctx) } <= 0 {
            // SAFETY: as above.
            let e = unsafe { X509_STORE_CTX_get_error(ctx) };
            // SAFETY: any error.
            let text = unsafe { X509_verify_cert_error_string(c_long::from(e)) };
            // SAFETY: a static string.
            let s = unsafe { CStr::from_ptr(text) };
            err::raise_with_text(
                ERR_LIB_TS,
                TS_R_CERTIFICATE_VERIFY_ERROR,
                F,
                &format!("Verify error:{}", s.to_string_lossy()),
            );
            break 'end None;
        }
        // SAFETY: as above.
        Some(unsafe { X509_STORE_CTX_get1_chain(ctx) })
    };
    // SAFETY: the context made here.
    unsafe { X509_STORE_CTX_free(ctx) };
    chain
}

/// The signer info's signed attribute `nid` decoded by `d2i`, if it is a SEQUENCE.
///
/// # Safety
/// `si` is a live signer info; `d2i` a decoder.
unsafe fn signed_seq<T>(
    si: *mut PKCS7_SIGNER_INFO,
    nid: c_int,
    d2i: unsafe extern "C" fn(*mut *mut T, *mut *const c_uchar, c_long) -> *mut T,
) -> *mut T {
    // SAFETY: the caller's signer info.
    let attr = unsafe { PKCS7_get_signed_attribute(si, nid) };
    // SAFETY: its attribute, or NULL.
    let Some(a) = (unsafe { attr.as_ref() }) else {
        return ptr::null_mut();
    };
    if a.type_ != V_ASN1_SEQUENCE {
        return ptr::null_mut();
    }
    // SAFETY: a SEQUENCE's string.
    let seq = unsafe { a.value.sequence };
    // SAFETY: as above, or NULL.
    let Some(s) = (unsafe { seq.as_ref() }) else {
        return ptr::null_mut();
    };
    let mut p = s.data.cast_const();
    // SAFETY: its `length` bytes.
    unsafe { d2i(ptr::null_mut(), &raw mut p, c_long::from(s.length)) }
}

/// `ts_check_signing_certs`: the chain's signer is the one the signing-certificate
/// attribute names.
///
/// # Safety
/// `si` is a live signer info; `chain` a live list.
unsafe fn check_signing_certs(si: *mut PKCS7_SIGNER_INFO, chain: *mut stack_st_X509) -> bool {
    // SAFETY: the caller's signer info; the decoders.
    let ss = unsafe { signed_seq(si, NID_id_smime_aa_signingCertificate, d2i_ESS_SIGNING_CERT) };
    // SAFETY: as above.
    let ssv2 = unsafe {
        signed_seq(
            si,
            NID_id_smime_aa_signingCertificateV2,
            d2i_ESS_SIGNING_CERT_V2,
        )
    };
    // SAFETY: the attributes, or NULL; the caller's chain.
    let ok = unsafe { OSSL_ESS_check_signing_certs(ss, ssv2, chain, 1) } > 0;
    // SAFETY: decoded here, or NULL.
    unsafe { ESS_SIGNING_CERT_free(ss) };
    // SAFETY: as above.
    unsafe { ESS_SIGNING_CERT_V2_free(ssv2) };
    ok
}

/// The checks of [`TS_RESP_verify_signature`] after the arguments': the signer, or `None`.
///
/// # Safety
/// `token` is a live SignedData; `certs` NULL or a live list; `store` NULL or a live store.
unsafe fn verify_signature(
    token: *mut PKCS7,
    certs: *mut stack_st_X509,
    store: *mut X509_STORE,
    signers: &mut *mut stack_st_X509,
    untrusted: &mut *mut stack_st_X509,
    chain: &mut *mut stack_st_X509,
    p7bio: &mut *mut BIO,
) -> Option<*mut X509> {
    const F: &str = "TS_RESP_verify_signature";
    // SAFETY: the caller's token.
    let sinfos = unsafe { PKCS7_get_signer_info(token) };
    // SAFETY: its signer infos, or NULL.
    if sinfos.is_null() || unsafe { OPENSSL_sk_num(sinfos.cast()) } != 1 {
        raise(TS_R_THERE_MUST_BE_ONE_SIGNER, F);
        return None;
    }
    // SAFETY: its one signer info.
    let si: *mut PKCS7_SIGNER_INFO = unsafe { OPENSSL_sk_value(sinfos.cast(), 0) }.cast();
    // SAFETY: the caller's token.
    if unsafe { PKCS7_ctrl(token, PKCS7_OP_GET_DETACHED_SIGNATURE, 0, ptr::null_mut()) } != 0 {
        raise(TS_R_NO_CONTENT, F);
        return None;
    }
    // SAFETY: the caller's token and certificates.
    *signers = unsafe { PKCS7_get0_signers(token, certs, 0) };
    // SAFETY: the signers, or NULL.
    if signers.is_null() || unsafe { OPENSSL_sk_num((*signers).cast()) } != 1 {
        return None;
    }
    // SAFETY: the one signer.
    let signer: *mut X509 = unsafe { OPENSSL_sk_value((*signers).cast(), 0) }.cast();
    // SAFETY: the caller's token.
    let t = (unsafe { token.as_ref() })?;
    // SAFETY: a SignedData's content.
    let sign = unsafe { t.d.sign };
    // SAFETY: as above, or NULL.
    let p7certs = unsafe { sign.as_ref() }.map_or(ptr::null_mut(), |s| s.cert);
    // SAFETY: the lists, or NULL (0).
    let n = unsafe { OPENSSL_sk_num(certs.cast()) }.max(0)
        + unsafe { OPENSSL_sk_num(p7certs.cast()) }.max(0);
    // SAFETY: no requirements.
    *untrusted = unsafe { OPENSSL_sk_new_reserve(None, n) }.cast();
    if untrusted.is_null()
        // SAFETY: the new list; the caller's certificates.
        || unsafe { X509_add_certs(*untrusted, certs, 0) } == 0
        // SAFETY: as above; the token's.
        || unsafe { X509_add_certs(*untrusted, p7certs, 0) } == 0
    {
        return None;
    }
    // SAFETY: the caller's store; the list; the signer.
    *chain = unsafe { verify_cert(store, *untrusted, signer) }?;
    // SAFETY: the signer info; the chain.
    if !unsafe { check_signing_certs(si, *chain) } {
        return None;
    }
    // SAFETY: the caller's token.
    *p7bio = unsafe { PKCS7_dataInit(token, ptr::null_mut()) };
    let mut buf = [0u8; 4096];
    // SAFETY: the BIO, or NULL (-1); `buf`'s room.
    while unsafe { BIO_read(*p7bio, buf.as_mut_ptr().cast(), 4096) } > 0 {}
    // SAFETY: the BIO; the token, its signer info, and its signer.
    if unsafe { PKCS7_signatureVerify(*p7bio, token, si, signer) } <= 0 {
        raise(TS_R_SIGNATURE_FAILURE, F);
        return None;
    }
    Some(signer)
}

ffi_export! {
    /// Checks the token's one signature and its signer's chain to the store (with `certs` as
    /// untrusted ones): 1, with the signer up-referenced into `*signer_out`, or 0.
    ///
    /// # Safety
    /// `token` is NULL or a live PKCS #7 object; `certs` NULL or a live list; `store` NULL or a
    /// live store; `signer_out` NULL or room for a pointer.
    pub unsafe extern "C" fn TS_RESP_verify_signature(token: *mut PKCS7, certs: *mut stack_st_X509, store: *mut X509_STORE, signer_out: *mut *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        const F: &str = "TS_RESP_verify_signature";
        if token.is_null() {
            raise(TS_R_INVALID_NULL_POINTER, F);
            return 0;
        }
        // SAFETY: the caller's token.
        let ty = unsafe { (*token).type_ };
        // SAFETY: its type.
        if unsafe { OBJ_obj2nid(ty) } != NID_pkcs7_signed {
            raise(TS_R_WRONG_CONTENT_TYPE, F);
            return 0;
        }
        let (mut signers, mut untrusted, mut chain, mut p7bio) =
            (ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        // SAFETY: the caller's objects; the slots for what it makes.
        let signer = unsafe { verify_signature(token, certs, store, &mut signers, &mut untrusted, &mut chain, &mut p7bio) };
        let ret = match signer {
            Some(s) => {
                // SAFETY: the caller's room, or NULL.
                match unsafe { signer_out.as_mut() } {
                    // SAFETY: the signer.
                    Some(out) if unsafe { X509_up_ref(s) } != 0 => {
                        *out = s;
                        1
                    }
                    Some(_) => 0,
                    None => 1,
                }
            }
            None => 0,
        };
        // SAFETY: each made here, or NULL.
        unsafe { BIO_free_all(p7bio) };
        // SAFETY: as above; the list holds no references.
        unsafe { OPENSSL_sk_free(untrusted.cast()) };
        // SAFETY: as above.
        unsafe { OSSL_STACK_OF_X509_free(chain) };
        // SAFETY: as above; the list holds no references.
        unsafe { OPENSSL_sk_free(signers.cast()) };
        ret
    }
}

const STATUS_TEXT: [&str; 6] = [
    "granted",
    "grantedWithMods",
    "rejection",
    "waiting",
    "revocationWarning",
    "revocationNotification",
];

const FAILURE_INFO: [(c_int, &str); 8] = [
    (TS_INFO_BAD_ALG, "badAlg"),
    (TS_INFO_BAD_REQUEST, "badRequest"),
    (TS_INFO_BAD_DATA_FORMAT, "badDataFormat"),
    (TS_INFO_TIME_NOT_AVAILABLE, "timeNotAvailable"),
    (TS_INFO_UNACCEPTED_POLICY, "unacceptedPolicy"),
    (TS_INFO_UNACCEPTED_EXTENSION, "unacceptedExtension"),
    (TS_INFO_ADD_INFO_NOT_AVAILABLE, "addInfoNotAvailable"),
    (TS_INFO_SYSTEM_FAILURE, "systemFailure"),
];

/// `ossl_sk_ASN1_UTF8STRING2text`: the strings joined by `sep` as a C string reads them (to
/// the first NUL), or `None` past `max_len` bytes (0 for no limit).
///
/// # Safety
/// `text` is NULL or a live list of strings.
pub(crate) unsafe fn utf8_text(
    text: *const stack_st_ASN1_UTF8STRING,
    sep: &str,
    max_len: usize,
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut length = 0usize;
    // SAFETY: the caller's list.
    for (i, s) in unsafe { elements::<rustyssl_abi::ASN1_STRING>(text.cast()) }.enumerate() {
        if i > 0 {
            length = length.checked_add(sep.len())?;
            out.extend_from_slice(sep.as_bytes());
        }
        // SAFETY: an element.
        let n = usize::try_from(unsafe { ASN1_STRING_length(s) }).unwrap_or(0);
        length = length.checked_add(n)?;
        if max_len != 0 && length > max_len {
            return None;
        }
        // SAFETY: its `n` bytes.
        let d = unsafe { ASN1_STRING_get0_data(s) };
        if n > 0 && !d.is_null() {
            // SAFETY: as above.
            out.extend_from_slice(unsafe { core::slice::from_raw_parts(d, n) });
        }
    }
    if let Some(z) = out.iter().position(|&b| b == 0) {
        out.truncate(z);
    }
    Some(out)
}

/// `ts_check_status_info`: whether the response's status grants a token; if not, why, in
/// the error queue.
///
/// # Safety
/// `info` is a live status info.
unsafe fn check_status_info(info: &StatusInfo) -> bool {
    // SAFETY: its status.
    let status = unsafe { ASN1_INTEGER_get(info.status) };
    if status == 0 || status == 1 {
        return true;
    }
    let status_text = usize::try_from(status)
        .ok()
        .and_then(|i| STATUS_TEXT.get(i))
        .copied()
        .unwrap_or("unknown code");
    // SAFETY: its text, or NULL.
    let embedded = if unsafe { OPENSSL_sk_num(info.text.cast()) } > 0 {
        // SAFETY: as above.
        let Some(t) = (unsafe { utf8_text(info.text.cast(), "/", TS_MAX_STATUS_LENGTH as usize) })
        else {
            return false;
        };
        Some(t)
    } else {
        None
    };
    let mut failure = String::new();
    if !info.failure_info.is_null() {
        for (code, text) in FAILURE_INFO {
            // SAFETY: its failure info.
            if unsafe { ASN1_BIT_STRING_get_bit(info.failure_info, code) } != 0 {
                if !failure.is_empty() {
                    failure.push(',');
                }
                failure.push_str(text);
            }
        }
    }
    if failure.is_empty() {
        failure.push_str("unspecified");
    }
    let mut msg = format!("status code: {status_text}, status text: ").into_bytes();
    msg.extend_from_slice(embedded.as_deref().unwrap_or(b"unspecified"));
    msg.extend_from_slice(format!(", failure codes: {failure}").as_bytes());
    err::raise_with_bytes(
        ERR_LIB_TS,
        TS_R_NO_TIME_STAMP_TOKEN,
        "ts_check_status_info",
        &msg,
    );
    false
}

/// `ts_compute_imprint`: the data's digest with the TSTInfo's algorithm, and a copy of the
/// algorithm.
///
/// # Safety
/// `data` is NULL or a live BIO; `t`'s members are live.
unsafe fn compute_imprint(data: *mut BIO, t: &TstInfo) -> Option<(*mut X509_ALGOR, Vec<u8>)> {
    // SAFETY: its imprint, or NULL.
    let mi = unsafe { t.msg_imprint.as_ref() }?;
    // SAFETY: its algorithm.
    let alg = unsafe { X509_ALGOR_dup(mi.hash_algo) };
    if alg.is_null() {
        return None;
    }
    // SAFETY: the algorithm and the digest made below.
    let ok = unsafe { digest_into(data, mi) };
    match ok {
        Some(d) => Some((alg, d)),
        None => {
            // SAFETY: the copy made here.
            unsafe { X509_ALGOR_free(alg) };
            None
        }
    }
}

/// The data's digest with the imprint's algorithm.
///
/// # Safety
/// `data` is NULL or a live BIO; `mi`'s members are live.
unsafe fn digest_into(data: *mut BIO, mi: &MsgImprint) -> Option<Vec<u8>> {
    let mut name = [0 as c_char; super::NAME_LEN];
    // SAFETY: its algorithm, or NULL.
    let alg = unsafe { mi.hash_algo.as_ref() }?;
    let len = c_int::try_from(super::NAME_LEN).unwrap_or(0);
    // SAFETY: its object; `name`'s room.
    unsafe { OBJ_obj2txt(name.as_mut_ptr(), len, alg.algorithm, 0) };
    // SAFETY: no requirements.
    unsafe { ERR_set_mark() };
    // SAFETY: a NUL-terminated name.
    let mut md = unsafe { EVP_MD_fetch(ptr::null_mut(), name.as_ptr(), ptr::null()) };
    let fetched = !md.is_null();
    if md.is_null() {
        // SAFETY: as above.
        md = unsafe { EVP_get_digestbyname(name.as_ptr()) }.cast_mut();
    }
    if md.is_null() {
        // SAFETY: the mark set above.
        unsafe { ERR_clear_last_mark() };
        return None;
    }
    // SAFETY: as above.
    unsafe { ERR_pop_to_mark() };
    let out = 'end: {
        // SAFETY: a live digest.
        let Ok(len) = usize::try_from(unsafe { EVP_MD_get_size(md) }) else {
            break 'end None;
        };
        if len == 0 {
            break 'end None;
        }
        // SAFETY: no requirements.
        let ctx = unsafe { EVP_MD_CTX_new() };
        if ctx.is_null() {
            raise(ERR_R_EVP_LIB, "ts_compute_imprint");
            break 'end None;
        }
        let mut out = vec![0u8; len];
        let ok = 'd: {
            // SAFETY: a new context; the digest.
            if unsafe { EVP_DigestInit(ctx, md) } == 0 {
                break 'd false;
            }
            let mut buf = [0u8; 4096];
            loop {
                // SAFETY: the caller's BIO, or NULL (-1); `buf`'s room.
                let n = unsafe { BIO_read(data, buf.as_mut_ptr().cast(), 4096) };
                let Ok(n) = usize::try_from(n) else { break };
                if n == 0 {
                    break;
                }
                // SAFETY: the `n` bytes read.
                if unsafe { EVP_DigestUpdate(ctx, buf.as_ptr().cast(), n) } == 0 {
                    break 'd false;
                }
            }
            // SAFETY: `out` holds the digest's size.
            (unsafe { EVP_DigestFinal(ctx, out.as_mut_ptr(), ptr::null_mut()) }) != 0
        };
        // SAFETY: the context made here.
        unsafe { EVP_MD_CTX_free(ctx) };
        ok.then_some(out)
    };
    if fetched {
        // SAFETY: the fetched digest.
        unsafe { EVP_MD_free(md) };
    }
    out
}

/// `ts_check_imprints`: the TSTInfo's imprint is `imprint` (with algorithm `alg`, when
/// given, and no parameters).
///
/// # Safety
/// `alg` is NULL or a live algorithm; `t`'s members are live.
unsafe fn check_imprints(alg: *const X509_ALGOR, imprint: &[u8], t: &TstInfo) -> bool {
    let ok = 'c: {
        // SAFETY: its imprint, or NULL.
        let Some(b) = (unsafe { t.msg_imprint.as_ref() }) else {
            break 'c false;
        };
        // SAFETY: the caller's algorithm, or NULL.
        if let Some(a) = unsafe { alg.as_ref() } {
            // SAFETY: its algorithm.
            let Some(ab) = (unsafe { b.hash_algo.as_ref() }) else {
                break 'c false;
            };
            // SAFETY: the objects.
            if unsafe { OBJ_cmp(a.algorithm, ab.algorithm) } != 0 {
                break 'c false;
            }
            let not_null = |p: *mut rustyssl_abi::ASN1_TYPE| {
                // SAFETY: the parameters, if any.
                !p.is_null() && unsafe { ASN1_TYPE_get(p) } != V_ASN1_NULL
            };
            if not_null(a.parameter) || not_null(ab.parameter) {
                break 'c false;
            }
        }
        // SAFETY: its hash.
        let len = unsafe { ASN1_STRING_length(b.hashed_msg) };
        if usize::try_from(len).ok() != Some(imprint.len()) {
            break 'c false;
        }
        // SAFETY: its `len` bytes.
        let d = unsafe { ASN1_STRING_get0_data(b.hashed_msg) };
        imprint.is_empty()
            // SAFETY: as above.
            || unsafe { core::slice::from_raw_parts(d, imprint.len()) } == imprint
    };
    if !ok {
        raise(TS_R_MESSAGE_IMPRINT_MISMATCH, "ts_check_imprints");
    }
    ok
}

/// `ts_check_signer_name`: the signer's subject, or one of its alternative names, is `name`.
///
/// # Safety
/// `name` is a live name; `signer` NULL or a live certificate.
unsafe fn check_signer_name(name: *mut GENERAL_NAME, signer: *mut X509) -> bool {
    // SAFETY: the caller's name, or NULL.
    let Some(n) = (unsafe { name.as_ref() }) else {
        return false;
    };
    if n.type_ == GEN_DIRNAME && !signer.is_null() {
        // SAFETY: a directory name's.
        let dirn = unsafe { n.d.dirn };
        // SAFETY: the signer.
        let subject = unsafe { X509_get_subject_name(signer) };
        // SAFETY: the names.
        if unsafe { X509_NAME_cmp(dirn, subject) } == 0 {
            return true;
        }
    }
    if signer.is_null() {
        return false;
    }
    let mut idx: c_int = -1;
    loop {
        // SAFETY: the signer; `idx`.
        let names: *mut stack_st_GENERAL_NAME = unsafe {
            X509_get_ext_d2i(signer, NID_subject_alt_name, ptr::null_mut(), &raw mut idx)
        }
        .cast();
        if names.is_null() {
            return false;
        }
        // SAFETY: the decoded names; each compared with the caller's.
        let found = unsafe { elements::<GENERAL_NAME>(names.cast()) }
            .any(|g| unsafe { GENERAL_NAME_cmp(g, name) } == 0);
        // SAFETY: decoded here.
        unsafe { GENERAL_NAMES_free(names) };
        if found {
            return true;
        }
    }
}

/// `int_ts_RESP_verify_token`: the checks the context asks for.
///
/// # Safety
/// `c`'s members are NULL or live; `token` NULL or a live PKCS #7 object; `t`'s members live.
unsafe fn verify_token(c: &VerifyCtx, token: *mut PKCS7, t: *mut TS_TST_INFO) -> bool {
    // SAFETY: the caller's TSTInfo.
    let Some(ti) = (unsafe { of::<TstInfo, _>(t) }) else {
        return false;
    };
    let tsa_name = ti.tsa;
    let mut flags = c.flags;
    if (flags & TS_VFY_SIGNER != 0 && !tsa_name.is_null()) || flags & TS_VFY_TSA_NAME != 0 {
        flags |= TS_VFY_SIGNATURE;
    }
    let mut signer: *mut X509 = ptr::null_mut();
    let ok = 'c: {
        if flags & TS_VFY_SIGNATURE != 0
            // SAFETY: the token; the context's certificates and store; `signer`.
            && unsafe { TS_RESP_verify_signature(token, c.certs, c.store, &raw mut signer) } == 0
        {
            break 'c false;
        }
        // SAFETY: the TSTInfo.
        if flags & TS_VFY_VERSION != 0 && unsafe { TS_TST_INFO_get_version(t) } != 1 {
            raise(TS_R_UNSUPPORTED_VERSION, "int_ts_RESP_verify_token");
            break 'c false;
        }
        // SAFETY: the context's policy, or NULL; the TSTInfo's.
        if flags & TS_VFY_POLICY != 0 && unsafe { OBJ_cmp(c.policy, ti.policy_id) } != 0 {
            raise(TS_R_POLICY_MISMATCH, "ts_check_policy");
            break 'c false;
        }
        if flags & TS_VFY_IMPRINT != 0 {
            let imprint = if c.imprint.is_null() {
                &[][..]
            } else {
                // SAFETY: the context's imprint of its length.
                unsafe { core::slice::from_raw_parts(c.imprint, c.imprint_len as usize) }
            };
            // SAFETY: the context's algorithm, or NULL; the TSTInfo.
            if !unsafe { check_imprints(c.md_alg, imprint, ti) } {
                break 'c false;
            }
        }
        if flags & TS_VFY_DATA != 0 {
            // SAFETY: the context's data; the TSTInfo.
            let Some((alg, imprint)) = (unsafe { compute_imprint(c.data, ti) }) else {
                break 'c false;
            };
            // SAFETY: the copy made; the TSTInfo.
            let ok = unsafe { check_imprints(alg, &imprint, ti) };
            // SAFETY: as above.
            unsafe { X509_ALGOR_free(alg) };
            if !ok {
                break 'c false;
            }
        }
        if flags & TS_VFY_NONCE != 0 {
            if ti.nonce.is_null() {
                raise(TS_R_NONCE_NOT_RETURNED, "ts_check_nonces");
                break 'c false;
            }
            // SAFETY: the context's nonce, or NULL; the TSTInfo's.
            if unsafe { ASN1_INTEGER_cmp(c.nonce, ti.nonce) } != 0 {
                raise(TS_R_NONCE_MISMATCH, "ts_check_nonces");
                break 'c false;
            }
        }
        if flags & TS_VFY_SIGNER != 0
            && !tsa_name.is_null()
            // SAFETY: the TSTInfo's name; the signer, or NULL.
            && !unsafe { check_signer_name(tsa_name, signer) }
        {
            raise(TS_R_TSA_NAME_MISMATCH, "int_ts_RESP_verify_token");
            break 'c false;
        }
        // SAFETY: the context's name, or NULL; as above.
        if flags & TS_VFY_TSA_NAME != 0 && !unsafe { check_signer_name(c.tsa_name, signer) } {
            raise(TS_R_TSA_UNTRUSTED, "int_ts_RESP_verify_token");
            break 'c false;
        }
        true
    };
    // SAFETY: up-referenced for this, or NULL.
    unsafe { X509_free(signer) };
    ok
}

ffi_export! {
    /// Checks the response's status and its token as the context asks: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context; `response` a live response.
    pub unsafe extern "C" fn TS_RESP_verify_response(ctx: *mut TS_VERIFY_CTX, response: *mut TS_RESP) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let (Some(c), Some(r)) = (unsafe { ctx_of(ctx) }, unsafe { of::<Resp, _>(response) }) else { return 0 };
        // SAFETY: its status info, or NULL.
        let Some(info) = (unsafe { r.status_info.as_ref() }) else { return 0 };
        // SAFETY: a live status info.
        if !unsafe { check_status_info(info) } {
            return 0;
        }
        // SAFETY: the context; the response's token and TSTInfo.
        c_int::from(unsafe { verify_token(c, r.token, r.tst_info.cast()) })
    }
}

ffi_export! {
    /// Checks the token as the context asks: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context; `token` a live PKCS #7 object.
    pub unsafe extern "C" fn TS_RESP_verify_token(ctx: *mut TS_VERIFY_CTX, token: *mut PKCS7) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        // SAFETY: the caller's token.
        let t = unsafe { PKCS7_to_TS_TST_INFO(token) };
        if t.is_null() {
            return 0;
        }
        // SAFETY: the context; the token and its TSTInfo.
        let ok = unsafe { verify_token(c, token, t) };
        // SAFETY: decoded here.
        unsafe { TS_TST_INFO_free(t) };
        c_int::from(ok)
    }
}
