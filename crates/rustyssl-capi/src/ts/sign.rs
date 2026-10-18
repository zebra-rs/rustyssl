//! Making responses (`ts_rsp_sign.c`): the response context's settings and callbacks, and
//! `TS_RESP_create_response`, which checks a request, builds its TSTInfo, and signs it.
//!
//! The context is handed to the application's callbacks, which may call any function on it,
//! so no reference to it is held across a callback: each step takes a fresh one.

use core::ffi::{CStr, c_char, c_int, c_long, c_uint, c_void};
use core::ptr;

use libc::{time_t, tm};
use rustyssl_abi::{
    ASN1_GENERALIZEDTIME, ASN1_INTEGER, ASN1_OBJECT, BIO, ERR_LIB_TS, ERR_R_ASN1_LIB,
    ERR_R_CRYPTO_LIB, ERR_R_OBJ_LIB, ERR_R_PKCS7_LIB, ERR_R_TS_LIB, EVP_MD, EVP_PKEY, GEN_DIRNAME,
    GENERAL_NAME, NID_id_smime_aa_signingCertificate, NID_id_smime_aa_signingCertificateV2,
    NID_id_smime_ct_TSTInfo, NID_pkcs7_signed, NID_pkcs9_contentType, OPENSSL_STACK, OSSL_LIB_CTX,
    PKCS7, PKCS7_SIGNER_INFO, SN_sha1, TS_ACCURACY, TS_ESS_CERT_ID_CHAIN, TS_INFO_BAD_ALG,
    TS_INFO_BAD_DATA_FORMAT, TS_INFO_BAD_REQUEST, TS_INFO_TIME_NOT_AVAILABLE,
    TS_INFO_UNACCEPTED_EXTENSION, TS_INFO_UNACCEPTED_POLICY, TS_MAX_CLOCK_PRECISION_DIGITS,
    TS_ORDERING, TS_R_COULD_NOT_SET_TIME, TS_R_ESS_ADD_SIGNING_CERT_ERROR,
    TS_R_ESS_ADD_SIGNING_CERT_V2_ERROR, TS_R_INVALID_NULL_POINTER,
    TS_R_INVALID_SIGNER_CERTIFICATE_PURPOSE, TS_R_PKCS7_ADD_SIGNATURE_ERROR,
    TS_R_PKCS7_ADD_SIGNED_ATTR_ERROR, TS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE,
    TS_R_RESPONSE_SETUP_ERROR, TS_R_TIME_SYSCALL_ERROR, TS_R_TS_DATASIGN,
    TS_R_TST_INFO_SETUP_ERROR, TS_R_UNACCEPTABLE_POLICY, TS_REQ, TS_RESP, TS_RESP_CTX,
    TS_STATUS_GRANTED, TS_STATUS_INFO, TS_STATUS_REJECTION, TS_TSA_NAME, TS_TST_INFO,
    TS_extension_cb, TS_serial_cb, TS_time_cb, V_ASN1_NULL, V_ASN1_OBJECT, V_ASN1_OCTET_STRING,
    V_ASN1_SEQUENCE, X509, X509_EXTENSION, X509_PURPOSE_TIMESTAMP_SIGN, stack_st_X509,
};

use super::asn::{
    MsgImprint, Req, Resp, StatusInfo, TS_ACCURACY_free, TS_ACCURACY_new, TS_REQ_free,
    TS_RESP_free, TS_RESP_new, TS_STATUS_INFO_free, TS_STATUS_INFO_new, TS_TST_INFO_free,
    TS_TST_INFO_new, d2i_TS_REQ_bio, i2d_TS_TST_INFO_bio,
};
use super::utils::{
    TS_ACCURACY_set_micros, TS_ACCURACY_set_millis, TS_ACCURACY_set_seconds,
    TS_RESP_set_status_info, TS_RESP_set_tst_info, TS_TST_INFO_set_accuracy,
    TS_TST_INFO_set_msg_imprint, TS_TST_INFO_set_nonce, TS_TST_INFO_set_ordering,
    TS_TST_INFO_set_policy_id, TS_TST_INFO_set_serial, TS_TST_INFO_set_time, TS_TST_INFO_set_tsa,
    TS_TST_INFO_set_version,
};
use crate::asn1::any::{ASN1_TYPE_get, ASN1_TYPE_set};
use crate::asn1::bit_string::ASN1_BIT_STRING_set_bit;
use crate::asn1::integer::{ASN1_INTEGER_get, ASN1_INTEGER_set};
use crate::asn1::string::{
    ASN1_BIT_STRING_new, ASN1_GENERALIZEDTIME_free, ASN1_GENERALIZEDTIME_new, ASN1_INTEGER_free,
    ASN1_INTEGER_new, ASN1_OCTET_STRING_new, ASN1_STRING_free, ASN1_STRING_new, ASN1_STRING_set,
    ASN1_UTF8STRING_free, ASN1_UTF8STRING_new,
};
use crate::asn1::time::{ASN1_GENERALIZEDTIME_set_string, OPENSSL_gmtime};
use crate::asn1::tpl::items::ASN1_TYPE_new;
use crate::bio::BIO_free_all;
use crate::err;
use crate::ess::{
    ESS_SIGNING_CERT_V2_free, ESS_SIGNING_CERT_free, OSSL_ESS_signing_cert_new_init,
    OSSL_ESS_signing_cert_v2_new_init, i2d_ESS_SIGNING_CERT, i2d_ESS_SIGNING_CERT_V2,
};
use crate::evp::digest::{
    EVP_MD_fetch, EVP_MD_free, EVP_MD_get_size, EVP_MD_get0_name, EVP_MD_get0_provider, EVP_MD_is_a,
};
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_up_ref};
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::objects::{ASN1_OBJECT_free, OBJ_cmp, OBJ_dup, OBJ_nid2obj, OBJ_obj2txt};
use crate::pkcs7::doit::{PKCS7_dataFinal, PKCS7_dataInit};
use crate::pkcs7::{
    PKCS7_add_certificate, PKCS7_add_signature, PKCS7_add_signed_attribute, PKCS7_free, PKCS7_new,
    PKCS7_new_ex, PKCS7_set_content, PKCS7_set_type,
};
use crate::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_value,
};
use crate::string::CRYPTO_strdup;
use crate::x509::cert::{
    OSSL_STACK_OF_X509_free, X509_chain_up_ref, X509_check_private_key, X509_free,
    X509_get_subject_name, X509_up_ref,
};
use crate::x509::name::X509_NAME_dup;
use crate::x509::purpose::X509_check_purpose;
use crate::x509v3::genn::{GENERAL_NAME_free, GENERAL_NAME_new};

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_TS, reason, f);
}

/// `TS_RESP_CTX`: the TSA's signer, policies, digests, accuracy, and callbacks, and while a
/// response is made, the request, the response, and its TSTInfo.
#[repr(C)]
pub(crate) struct RespCtx {
    signer_cert: *mut X509,
    signer_key: *mut EVP_PKEY,
    signer_md: *const EVP_MD,
    ess_cert_id_digest: *const EVP_MD,
    certs: *mut stack_st_X509,
    policies: *mut OPENSSL_STACK,
    default_policy: *mut ASN1_OBJECT,
    mds: *mut OPENSSL_STACK,
    seconds: *mut ASN1_INTEGER,
    millis: *mut ASN1_INTEGER,
    micros: *mut ASN1_INTEGER,
    clock_precision_digits: c_uint,
    flags: c_uint,
    serial_cb: TS_serial_cb,
    serial_cb_data: *mut c_void,
    time_cb: TS_time_cb,
    time_cb_data: *mut c_void,
    extension_cb: TS_extension_cb,
    extension_cb_data: *mut c_void,
    request: *mut TS_REQ,
    response: *mut TS_RESP,
    tst_info: *mut TS_TST_INFO,
    libctx: *mut OSSL_LIB_CTX,
    propq: *mut c_char,
}

/// The context behind a pointer, for as long as no callback runs.
///
/// # Safety
/// `p` is NULL or a live context, not otherwise borrowed.
unsafe fn ctx_of<'a>(p: *mut TS_RESP_CTX) -> Option<&'a mut RespCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { p.cast::<RespCtx>().as_mut() }
}

/// The status, and the failure.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn reject(ctx: *mut TS_RESP_CTX, text: &CStr, failure: c_int) {
    // SAFETY: the caller's context.
    unsafe { TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION, text.as_ptr()) };
    // SAFETY: as above.
    unsafe { TS_RESP_CTX_add_failure_info(ctx, failure) };
}

/// Sets the status, if it is still granted.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn reject_cond(ctx: *mut TS_RESP_CTX, text: &CStr) -> c_int {
    // SAFETY: the caller's context.
    unsafe { TS_RESP_CTX_set_status_info_cond(ctx, TS_STATUS_REJECTION, text.as_ptr()) }
}

ffi_callback! {
    /// `def_serial_cb`: serial number 1.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub(crate) unsafe extern "C" fn def_serial_cb(ctx: *mut TS_RESP_CTX, _data: *mut c_void) -> *mut ASN1_INTEGER
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: no requirements.
        let serial = unsafe { ASN1_INTEGER_new() };
        // SAFETY: the integer made here.
        if !serial.is_null() && unsafe { ASN1_INTEGER_set(serial, 1) } != 0 {
            return serial;
        }
        raise(ERR_R_ASN1_LIB, "def_serial_cb");
        // SAFETY: the caller's context.
        unsafe {
            TS_RESP_CTX_set_status_info(
                ctx,
                TS_STATUS_REJECTION,
                c"Error during serial number generation.".as_ptr(),
            )
        };
        // SAFETY: as above, or NULL.
        unsafe { ASN1_INTEGER_free(serial) };
        ptr::null_mut()
    }
}

ffi_callback! {
    /// `def_time_cb`: the time now, in seconds and microseconds since the epoch.
    ///
    /// # Safety
    /// `ctx` is a live context; `sec` and `usec` point to `long`s.
    pub(crate) unsafe extern "C" fn def_time_cb(ctx: *mut TS_RESP_CTX, _data: *mut c_void, sec: *mut c_long, usec: *mut c_long) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
        let parts = now.ok().and_then(|d| {
            Some((c_long::try_from(d.as_secs()).ok()?, c_long::from(d.subsec_micros())))
        });
        let Some((s, us)) = parts.filter(|p| *p != (0, 0)) else {
            raise(TS_R_TIME_SYSCALL_ERROR, "def_time_cb");
            // SAFETY: the caller's context.
            unsafe { reject(ctx, c"Time is not available.", TS_INFO_TIME_NOT_AVAILABLE) };
            return 0;
        };
        // SAFETY: the caller's room.
        unsafe { *sec = s };
        // SAFETY: as above.
        unsafe { *usec = us };
        1
    }
}

ffi_callback! {
    /// `def_extension_cb`: refuses any extension.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub(crate) unsafe extern "C" fn def_extension_cb(ctx: *mut TS_RESP_CTX, _ext: *mut X509_EXTENSION, _data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's context.
        unsafe { reject(ctx, c"Unsupported extension.", TS_INFO_UNACCEPTED_EXTENSION) };
        0
    }
}

ffi_export! {
    /// A new response context in the library context, fetching with `propq`, or NULL.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `propq` NULL or a C string.
    pub unsafe extern "C" fn TS_RESP_CTX_new_ex(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut TS_RESP_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        let p = mem::alloc_zeroed(size_of::<RespCtx>()).cast::<TS_RESP_CTX>();
        // SAFETY: zeroed memory for a context, all of whose fields may be zero, or NULL.
        let Some(c) = (unsafe { ctx_of(p) }) else { return ptr::null_mut() };
        if !propq.is_null() {
            // SAFETY: the caller's string.
            c.propq = unsafe { CRYPTO_strdup(propq, c"ts_rsp_sign.c".as_ptr(), 0) };
            if c.propq.is_null() {
                // SAFETY: allocated above.
                unsafe { mem::release(p.cast()) };
                return ptr::null_mut();
            }
        }
        c.libctx = libctx;
        c.serial_cb = Some(def_serial_cb);
        c.time_cb = Some(def_time_cb);
        c.extension_cb = Some(def_extension_cb);
        p
    }
}

ffi_export! {
    /// A new response context, or NULL.
    ///
    /// # Safety
    /// None.
    pub unsafe extern "C" fn TS_RESP_CTX_new() -> *mut TS_RESP_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the default library context and no property query.
        unsafe { TS_RESP_CTX_new_ex(ptr::null_mut(), ptr::null()) }
    }
}

/// `ASN1_OBJECT_free` as a stack's free function.
unsafe extern "C" fn obj_free(p: *mut c_void) {
    // SAFETY: an element of a list of objects.
    unsafe { ASN1_OBJECT_free(p.cast()) };
}

/// Frees and empties the integer.
///
/// # Safety
/// `*a` is NULL or an integer the caller owns.
unsafe fn int_clear(a: &mut *mut ASN1_INTEGER) {
    // SAFETY: the caller's guarantee.
    unsafe { ASN1_INTEGER_free(*a) };
    *a = ptr::null_mut();
}

/// Frees and empties the accuracy.
///
/// # Safety
/// `c`'s accuracy is NULL or its own.
unsafe fn accuracy_free(c: &mut RespCtx) {
    // SAFETY: its own, or NULL.
    unsafe { int_clear(&mut c.seconds) };
    // SAFETY: as above.
    unsafe { int_clear(&mut c.millis) };
    // SAFETY: as above.
    unsafe { int_clear(&mut c.micros) };
}

ffi_export! {
    /// Frees the context and what it holds.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context, not used again.
    pub unsafe extern "C" fn TS_RESP_CTX_free(ctx: *mut TS_RESP_CTX)
    where failure = (), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return };
        // SAFETY: each its own, or NULL.
        unsafe { mem::release(c.propq.cast()) };
        // SAFETY: as above.
        unsafe { X509_free(c.signer_cert) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(c.signer_key) };
        // SAFETY: as above.
        unsafe { OSSL_STACK_OF_X509_free(c.certs) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_pop_free(c.policies, Some(obj_free)) };
        // SAFETY: as above.
        unsafe { ASN1_OBJECT_free(c.default_policy) };
        // SAFETY: as above; the digests are not its own.
        unsafe { OPENSSL_sk_free(c.mds) };
        // SAFETY: as above.
        unsafe { accuracy_free(c) };
        // SAFETY: made by `TS_RESP_CTX_new_ex`.
        unsafe { mem::release(ctx.cast()) };
    }
}

ffi_export! {
    /// Sets the signer's certificate, which must be fit for time stamping: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context; `signer` a live certificate.
    pub unsafe extern "C" fn TS_RESP_CTX_set_signer_cert(ctx: *mut TS_RESP_CTX, signer: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        // SAFETY: the caller's certificate.
        if unsafe { X509_check_purpose(signer, X509_PURPOSE_TIMESTAMP_SIGN, 0) } != 1 {
            raise(TS_R_INVALID_SIGNER_CERTIFICATE_PURPOSE, "TS_RESP_CTX_set_signer_cert");
            return 0;
        }
        // SAFETY: as above.
        if unsafe { X509_up_ref(signer) } == 0 {
            return 0;
        }
        // SAFETY: its certificate, or NULL.
        unsafe { X509_free(c.signer_cert) };
        c.signer_cert = signer;
        1
    }
}

ffi_export! {
    /// Sets the signer's key: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context; `key` a live key.
    pub unsafe extern "C" fn TS_RESP_CTX_set_signer_key(ctx: *mut TS_RESP_CTX, key: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        // SAFETY: the caller's key.
        if unsafe { EVP_PKEY_up_ref(key) } == 0 {
            return 0;
        }
        // SAFETY: its key, or NULL.
        unsafe { EVP_PKEY_free(c.signer_key) };
        c.signer_key = key;
        1
    }
}

ffi_export! {
    /// Sets the signature's digest (SHA-256 when NULL): 1.
    ///
    /// # Safety
    /// `ctx` is a live context; `md` NULL or a digest that outlives the context's use.
    pub unsafe extern "C" fn TS_RESP_CTX_set_signer_digest(ctx: *mut TS_RESP_CTX, md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        c.signer_md = md;
        1
    }
}

ffi_export! {
    /// Sets the digest of the signing-certificate attribute (SHA-1, version 1, when NULL): 1.
    ///
    /// # Safety
    /// `ctx` is a live context; `md` NULL or a digest that outlives the context's use.
    pub unsafe extern "C" fn TS_RESP_CTX_set_ess_cert_id_digest(ctx: *mut TS_RESP_CTX, md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        c.ess_cert_id_digest = md;
        1
    }
}

ffi_export! {
    /// Sets the default policy to a copy of `def_policy`: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context; `def_policy` a live object.
    pub unsafe extern "C" fn TS_RESP_CTX_set_def_policy(ctx: *mut TS_RESP_CTX, def_policy: *const ASN1_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        // SAFETY: its policy, or NULL.
        unsafe { ASN1_OBJECT_free(c.default_policy) };
        // SAFETY: the caller's object.
        c.default_policy = unsafe { OBJ_dup(def_policy) };
        if c.default_policy.is_null() {
            raise(ERR_R_OBJ_LIB, "TS_RESP_CTX_set_def_policy");
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Sets the certificates to add to the response (up-referenced; none for NULL): 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context; `certs` NULL or a live list.
    pub unsafe extern "C" fn TS_RESP_CTX_set_certs(ctx: *mut TS_RESP_CTX, certs: *mut stack_st_X509) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        // SAFETY: its list, or NULL.
        unsafe { OSSL_STACK_OF_X509_free(c.certs) };
        c.certs = ptr::null_mut();
        if certs.is_null() {
            return 1;
        }
        // SAFETY: the caller's list.
        c.certs = unsafe { X509_chain_up_ref(certs) };
        c_int::from(!c.certs.is_null())
    }
}

ffi_export! {
    /// Adds a copy of `policy` to the acceptable ones: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context; `policy` a live object.
    pub unsafe extern "C" fn TS_RESP_CTX_add_policy(ctx: *mut TS_RESP_CTX, policy: *const ASN1_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        const F: &str = "TS_RESP_CTX_add_policy";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        if c.policies.is_null() {
            // SAFETY: no requirements.
            c.policies = unsafe { OPENSSL_sk_new_null() };
            if c.policies.is_null() {
                raise(ERR_R_CRYPTO_LIB, F);
                return 0;
            }
        }
        // SAFETY: the caller's object.
        let copy = unsafe { OBJ_dup(policy) };
        if copy.is_null() {
            raise(ERR_R_OBJ_LIB, F);
            return 0;
        }
        // SAFETY: its list; the copy.
        if unsafe { OPENSSL_sk_push(c.policies, copy.cast()) } <= 0 {
            raise(ERR_R_CRYPTO_LIB, F);
            // SAFETY: the copy made here.
            unsafe { ASN1_OBJECT_free(copy) };
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Adds a digest to the acceptable ones for requests' imprints: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context; `md` a digest that outlives the context's use.
    pub unsafe extern "C" fn TS_RESP_CTX_add_md(ctx: *mut TS_RESP_CTX, md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        if c.mds.is_null() {
            // SAFETY: no requirements.
            c.mds = unsafe { OPENSSL_sk_new_null() };
        }
        // SAFETY: its list; the caller's digest.
        if c.mds.is_null() || unsafe { OPENSSL_sk_push(c.mds, md.cast_mut().cast()) } <= 0 {
            raise(ERR_R_CRYPTO_LIB, "TS_RESP_CTX_add_md");
            return 0;
        }
        1
    }
}

/// A new integer `v`, or NULL.
fn int_of(v: c_int) -> *mut ASN1_INTEGER {
    // SAFETY: no requirements.
    let a = unsafe { ASN1_INTEGER_new() };
    // SAFETY: the integer made here.
    if !a.is_null() && unsafe { ASN1_INTEGER_set(a, c_long::from(v)) } == 0 {
        // SAFETY: as above.
        unsafe { ASN1_INTEGER_free(a) };
        return ptr::null_mut();
    }
    a
}

ffi_export! {
    /// Sets the accuracy (a 0 part is left out): 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub unsafe extern "C" fn TS_RESP_CTX_set_accuracy(ctx: *mut TS_RESP_CTX, secs: c_int, millis: c_int, micros: c_int) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        // SAFETY: its own.
        unsafe { accuracy_free(c) };
        let mut ok = true;
        for (v, slot) in [(secs, &mut c.seconds), (millis, &mut c.millis), (micros, &mut c.micros)] {
            if v != 0 {
                *slot = int_of(v);
                ok &= !slot.is_null();
            }
        }
        if !ok {
            // SAFETY: its own.
            unsafe { accuracy_free(c) };
            raise(ERR_R_ASN1_LIB, "TS_RESP_CTX_set_accuracy");
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Adds to the flags (`TS_TSA_NAME`, `TS_ORDERING`, `TS_ESS_CERT_ID_CHAIN`).
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub unsafe extern "C" fn TS_RESP_CTX_add_flags(ctx: *mut TS_RESP_CTX, flags: c_int)
    where failure = (), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            c.flags |= flags.cast_unsigned();
        }
    }
}

ffi_export! {
    /// Sets the callback that makes serial numbers.
    ///
    /// # Safety
    /// `ctx` is a live context; `cb` NULL or a callback for `data`.
    pub unsafe extern "C" fn TS_RESP_CTX_set_serial_cb(ctx: *mut TS_RESP_CTX, cb: TS_serial_cb, data: *mut c_void)
    where failure = (), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            c.serial_cb = cb;
            c.serial_cb_data = data;
        }
    }
}

ffi_export! {
    /// Sets the callback that tells the time.
    ///
    /// # Safety
    /// `ctx` is a live context; `cb` NULL or a callback for `data`.
    pub unsafe extern "C" fn TS_RESP_CTX_set_time_cb(ctx: *mut TS_RESP_CTX, cb: TS_time_cb, data: *mut c_void)
    where failure = (), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            c.time_cb = cb;
            c.time_cb_data = data;
        }
    }
}

ffi_export! {
    /// Sets the callback that accepts or refuses each of a request's extensions.
    ///
    /// # Safety
    /// `ctx` is a live context; `cb` NULL or a callback for `data`.
    pub unsafe extern "C" fn TS_RESP_CTX_set_extension_cb(ctx: *mut TS_RESP_CTX, cb: TS_extension_cb, data: *mut c_void)
    where failure = (), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            c.extension_cb = cb;
            c.extension_cb_data = data;
        }
    }
}

/// Adds the text to the status info's.
///
/// # Safety
/// `si`'s members are NULL or live; `text` is a C string.
unsafe fn add_text(si: &mut StatusInfo, text: *const c_char) -> bool {
    const F: &str = "TS_RESP_CTX_set_status_info";
    // SAFETY: the caller's string.
    let len = c_int::try_from(unsafe { CStr::from_ptr(text) }.to_bytes().len());
    // SAFETY: no requirements.
    let s = unsafe { ASN1_UTF8STRING_new() };
    if s.is_null()
        || len.is_err()
        // SAFETY: the string made here; the caller's text.
        || unsafe { ASN1_STRING_set(s, text.cast(), len.unwrap_or(0)) } == 0
    {
        raise(ERR_R_ASN1_LIB, F);
        // SAFETY: as above, or NULL.
        unsafe { ASN1_UTF8STRING_free(s) };
        return false;
    }
    if si.text.is_null() {
        // SAFETY: no requirements.
        si.text = unsafe { OPENSSL_sk_new_null() };
    }
    // SAFETY: its list; the string.
    if si.text.is_null() || unsafe { OPENSSL_sk_push(si.text, s.cast()) } <= 0 {
        raise(ERR_R_CRYPTO_LIB, F);
        // SAFETY: the string made here.
        unsafe { ASN1_UTF8STRING_free(s) };
        return false;
    }
    true
}

/// A new status info with `status` and the text, if any.
///
/// # Safety
/// `text` is NULL or a C string.
unsafe fn new_status(status: c_int, text: *const c_char) -> *mut TS_STATUS_INFO {
    const F: &str = "TS_RESP_CTX_set_status_info";
    // SAFETY: no requirements.
    let p = unsafe { TS_STATUS_INFO_new() };
    // SAFETY: the status info made here, or NULL.
    let Some(si) = (unsafe { p.cast::<StatusInfo>().as_mut() }) else {
        raise(ERR_R_TS_LIB, F);
        return p;
    };
    // SAFETY: its status.
    let ok = if unsafe { ASN1_INTEGER_set(si.status, c_long::from(status)) } == 0 {
        raise(ERR_R_ASN1_LIB, F);
        false
    } else {
        // SAFETY: its members; the caller's text.
        text.is_null() || unsafe { add_text(si, text) }
    };
    if !ok {
        // SAFETY: the status info made here.
        unsafe { TS_STATUS_INFO_free(p) };
        return ptr::null_mut();
    }
    p
}

ffi_export! {
    /// Sets the response's status, with the text if any: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context (making a response); `text` NULL or a C string.
    pub unsafe extern "C" fn TS_RESP_CTX_set_status_info(ctx: *mut TS_RESP_CTX, status: c_int, text: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's text.
        let si = unsafe { new_status(status, text) };
        if si.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let response = unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.response);
        // SAFETY: its response, or NULL; the status info.
        let ok = !response.is_null() && unsafe { TS_RESP_set_status_info(response, si) } != 0;
        if !ok {
            raise(ERR_R_TS_LIB, "TS_RESP_CTX_set_status_info");
        }
        // SAFETY: made here; the response holds a copy.
        unsafe { TS_STATUS_INFO_free(si) };
        c_int::from(ok)
    }
}

/// The response's status info, if it is making one.
///
/// # Safety
/// `ctx` is NULL or a live context.
unsafe fn status_info<'a>(ctx: *mut TS_RESP_CTX) -> Option<&'a mut StatusInfo> {
    // SAFETY: the caller's guarantee.
    let c = unsafe { ctx_of(ctx) }?;
    // SAFETY: its response, or NULL.
    let r = unsafe { c.response.cast::<Resp>().as_mut() }?;
    // SAFETY: its status info, or NULL.
    unsafe { r.status_info.as_mut() }
}

ffi_export! {
    /// Sets the response's status as [`TS_RESP_CTX_set_status_info`] does, if it is still
    /// granted: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context (making a response); `text` NULL or a C string.
    pub unsafe extern "C" fn TS_RESP_CTX_set_status_info_cond(ctx: *mut TS_RESP_CTX, status: c_int, text: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(si) = (unsafe { status_info(ctx) }) else { return 0 };
        // SAFETY: its status.
        if unsafe { ASN1_INTEGER_get(si.status) } == c_long::from(TS_STATUS_GRANTED) {
            // SAFETY: the caller's context and text.
            return unsafe { TS_RESP_CTX_set_status_info(ctx, status, text) };
        }
        1
    }
}

ffi_export! {
    /// Sets the failure bit in the response's status: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context (making a response).
    pub unsafe extern "C" fn TS_RESP_CTX_add_failure_info(ctx: *mut TS_RESP_CTX, failure: c_int) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(si) = (unsafe { status_info(ctx) }) else { return 0 };
        if si.failure_info.is_null() {
            // SAFETY: no requirements.
            si.failure_info = unsafe { ASN1_BIT_STRING_new() };
        }
        // SAFETY: its failure info.
        if si.failure_info.is_null() || unsafe { ASN1_BIT_STRING_set_bit(si.failure_info, failure, 1) } == 0 {
            raise(ERR_R_ASN1_LIB, "TS_RESP_CTX_add_failure_info");
            return 0;
        }
        1
    }
}

ffi_export! {
    /// The request being answered, or NULL.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub unsafe extern "C" fn TS_RESP_CTX_get_request(ctx: *mut TS_RESP_CTX) -> *mut TS_REQ
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.request)
    }
}

ffi_export! {
    /// The TSTInfo being made, or NULL.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub unsafe extern "C" fn TS_RESP_CTX_get_tst_info(ctx: *mut TS_RESP_CTX) -> *mut TS_TST_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.tst_info)
    }
}

ffi_export! {
    /// Sets the number of the time's fractional digits (up to 6): 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub unsafe extern "C" fn TS_RESP_CTX_set_clock_precision_digits(ctx: *mut TS_RESP_CTX, precision: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        if precision > TS_MAX_CLOCK_PRECISION_DIGITS.cast_unsigned() {
            return 0;
        }
        c.clock_precision_digits = precision;
        1
    }
}

/// The request being answered.
///
/// # Safety
/// `ctx` is a live context with a request, not otherwise borrowed.
unsafe fn request<'a>(ctx: *mut TS_RESP_CTX) -> Option<&'a mut Req> {
    // SAFETY: the caller's guarantee.
    let c = unsafe { ctx_of(ctx) }?;
    // SAFETY: its request, or NULL.
    unsafe { c.request.cast::<Req>().as_mut() }
}

/// What [`check_request`] finds wrong: the status text and the failure.
type Refusal = (&'static CStr, c_int);

/// The checks of `ts_RESP_check_request`: the refusal, or `Ok(false)` for an error with no
/// status.
///
/// # Safety
/// `req`'s members are live; `mds` NULL or a live list of digests.
unsafe fn check(req: &Req, mds: *mut OPENSSL_STACK) -> Result<bool, Refusal> {
    // SAFETY: its version.
    if unsafe { ASN1_INTEGER_get(req.version) } != 1 {
        return Err((c"Bad request version.", TS_INFO_BAD_REQUEST));
    }
    // SAFETY: its imprint, set when decoded.
    let Some(mi) = (unsafe { req.msg_imprint.cast::<MsgImprint>().as_ref() }) else {
        return Ok(false);
    };
    // SAFETY: its algorithm.
    let Some(alg) = (unsafe { mi.hash_algo.as_ref() }) else {
        return Ok(false);
    };
    let mut name = [0 as c_char; super::NAME_LEN];
    let len = c_int::try_from(super::NAME_LEN).unwrap_or(0);
    // SAFETY: its algorithm's object; `name`'s room.
    unsafe { OBJ_obj2txt(name.as_mut_ptr(), len, alg.algorithm, 0) };
    // SAFETY: the digests, or NULL (0).
    let n = unsafe { OPENSSL_sk_num(mds) };
    let md = (0..n)
        .map(|i| {
            // SAFETY: an index in range.
            let m = unsafe { OPENSSL_sk_value(mds, i) };
            m.cast::<EVP_MD>().cast_const()
        })
        .find(|&m| {
            // SAFETY: a digest; a NUL-terminated name.
            unsafe { EVP_MD_is_a(m, name.as_ptr()) != 0 }
        });
    let Some(md) = md else {
        return Err((
            c"Message digest algorithm is not supported.",
            TS_INFO_BAD_ALG,
        ));
    };
    // SAFETY: a digest.
    let md_size = unsafe { EVP_MD_get_size(md) };
    if md_size <= 0 {
        return Ok(false);
    }
    // SAFETY: its parameter.
    if !alg.parameter.is_null() && unsafe { ASN1_TYPE_get(alg.parameter) } != V_ASN1_NULL {
        return Err((c"Superfluous message digest parameter.", TS_INFO_BAD_ALG));
    }
    // SAFETY: its hash.
    if unsafe { mi.hashed_msg.as_ref() }.is_none_or(|h| h.length != md_size) {
        return Err((c"Bad message digest.", TS_INFO_BAD_DATA_FORMAT));
    }
    Ok(true)
}

/// `ts_RESP_check_request`: the request's version, and its imprint's algorithm (one of the
/// context's, with no parameters) and length.
///
/// # Safety
/// `ctx` is a live context with a request.
unsafe fn check_request(ctx: *mut TS_RESP_CTX) -> bool {
    // SAFETY: the caller's guarantee.
    let mds = unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.mds);
    // SAFETY: as above.
    let Some(req) = (unsafe { request(ctx) }) else {
        return false;
    };
    // SAFETY: the request's members; the digests.
    match unsafe { check(req, mds) } {
        Ok(ok) => ok,
        Err((text, failure)) => {
            // SAFETY: the caller's context.
            unsafe { reject(ctx, text, failure) };
            false
        }
    }
}

/// `ts_RESP_get_policy`: the policy to answer with.
///
/// # Safety
/// `ctx` is a live context with a request.
unsafe fn get_policy(ctx: *mut TS_RESP_CTX) -> *mut ASN1_OBJECT {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return ptr::null_mut();
    };
    let (default, policies) = (c.default_policy, c.policies);
    // SAFETY: as above.
    let requested = unsafe { request(ctx) }.map_or(ptr::null_mut(), |r| r.policy_id);
    if default.is_null() {
        raise(TS_R_INVALID_NULL_POINTER, "ts_RESP_get_policy");
        return ptr::null_mut();
    }
    // SAFETY: the objects.
    if requested.is_null() || unsafe { OBJ_cmp(requested, default) } == 0 {
        return default;
    }
    // SAFETY: the context's policies, or NULL (0).
    let n = unsafe { OPENSSL_sk_num(policies) };
    for i in 0..n {
        // SAFETY: an index in range.
        let p: *mut ASN1_OBJECT = unsafe { OPENSSL_sk_value(policies, i) }.cast();
        // SAFETY: the objects.
        if unsafe { OBJ_cmp(requested, p) } == 0 {
            return p;
        }
    }
    raise(TS_R_UNACCEPTABLE_POLICY, "ts_RESP_get_policy");
    // SAFETY: the caller's context.
    unsafe {
        reject(
            ctx,
            c"Requested policy is not supported.",
            TS_INFO_UNACCEPTED_POLICY,
        )
    };
    ptr::null_mut()
}

/// The time's GeneralizedTime text with up to `precision` fractional digits (trailing zeros
/// dropped).
fn gen_time_text(sec: c_long, usec: c_long, precision: c_uint) -> Option<std::ffi::CString> {
    if precision > TS_MAX_CLOCK_PRECISION_DIGITS.cast_unsigned() {
        return None;
    }
    let t: time_t = sec;
    // SAFETY: an all-zero `tm` is valid.
    let mut tmv: tm = unsafe { core::mem::zeroed() };
    // SAFETY: the time; the room.
    let r = unsafe { OPENSSL_gmtime(&raw const t, &raw mut tmv) };
    // SAFETY: the room filled, or NULL.
    let r = unsafe { r.as_ref() }?;
    let mut s = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        r.tm_year + 1900,
        r.tm_mon + 1,
        r.tm_mday,
        r.tm_hour,
        r.tm_min,
        r.tm_sec
    );
    if precision > 0 {
        // `BIO_snprintf(p, 2 + precision, ".%06ld", usec)`: at most 1 + precision characters.
        let frac: String = format!(".{usec:06}")
            .chars()
            .take(1 + precision as usize)
            .collect();
        let trimmed = frac.trim_end_matches('0');
        if trimmed != "." {
            s.push_str(trimmed);
        }
    }
    s.push('Z');
    std::ffi::CString::new(s).ok()
}

/// `TS_RESP_set_genTime_with_precision`: the time as a GeneralizedTime, or NULL.
fn gen_time(sec: c_long, usec: c_long, precision: c_uint) -> *mut ASN1_GENERALIZEDTIME {
    const F: &str = "TS_RESP_set_genTime_with_precision";
    let Some(s) = gen_time_text(sec, usec, precision) else {
        raise(TS_R_COULD_NOT_SET_TIME, F);
        return ptr::null_mut();
    };
    // SAFETY: no requirements.
    let t = unsafe { ASN1_GENERALIZEDTIME_new() };
    if t.is_null() {
        raise(TS_R_COULD_NOT_SET_TIME, F);
        return t;
    }
    // SAFETY: the time made here; a C string.
    if unsafe { ASN1_GENERALIZEDTIME_set_string(t, s.as_ptr()) } == 0 {
        // SAFETY: as above.
        unsafe { ASN1_GENERALIZEDTIME_free(t) };
        raise(TS_R_COULD_NOT_SET_TIME, F);
        return ptr::null_mut();
    }
    t
}

/// What `ts_RESP_create_tst_info` makes and frees.
struct Made {
    serial: *mut ASN1_INTEGER,
    time: *mut ASN1_GENERALIZEDTIME,
    accuracy: *mut TS_ACCURACY,
    tsa_name: *mut GENERAL_NAME,
}

impl Drop for Made {
    fn drop(&mut self) {
        // SAFETY: each made for the TSTInfo, which holds copies, or NULL.
        unsafe { GENERAL_NAME_free(self.tsa_name) };
        // SAFETY: as above.
        unsafe { TS_ACCURACY_free(self.accuracy) };
        // SAFETY: as above.
        unsafe { ASN1_GENERALIZEDTIME_free(self.time) };
        // SAFETY: as above.
        unsafe { ASN1_INTEGER_free(self.serial) };
    }
}

/// The TSTInfo's serial and time, from the callbacks.
///
/// # Safety
/// `ctx` is a live context with a request; `t` a live TSTInfo.
unsafe fn serial_and_time(ctx: *mut TS_RESP_CTX, t: *mut TS_TST_INFO, made: &mut Made) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return false;
    };
    let (serial_cb, serial_data) = (c.serial_cb, c.serial_cb_data);
    let Some(serial_cb) = serial_cb else {
        return false;
    };
    // SAFETY: the application's callback, on its context and data; no reference is held.
    made.serial = unsafe { serial_cb(ctx, serial_data) };
    // SAFETY: the TSTInfo; the serial.
    if made.serial.is_null() || unsafe { TS_TST_INFO_set_serial(t, made.serial) } == 0 {
        return false;
    }
    // SAFETY: as above.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return false;
    };
    let (time_cb, time_data) = (c.time_cb, c.time_cb_data);
    let Some(time_cb) = time_cb else { return false };
    let (mut sec, mut usec): (c_long, c_long) = (0, 0);
    // SAFETY: as above; the rooms.
    if unsafe { time_cb(ctx, time_data, &raw mut sec, &raw mut usec) } == 0 {
        return false;
    }
    // SAFETY: as above.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return false;
    };
    made.time = gen_time(sec, usec, c.clock_precision_digits);
    // SAFETY: the TSTInfo; the time.
    !made.time.is_null() && unsafe { TS_TST_INFO_set_time(t, made.time) } != 0
}

/// The TSTInfo's accuracy, from the context's.
///
/// # Safety
/// `c`'s accuracy is NULL or live; `t` a live TSTInfo.
unsafe fn accuracy(c: &RespCtx, t: *mut TS_TST_INFO, made: &mut Made) -> bool {
    let (seconds, millis, micros) = (c.seconds, c.millis, c.micros);
    if seconds.is_null() && millis.is_null() && micros.is_null() {
        return true;
    }
    // SAFETY: no requirements.
    made.accuracy = unsafe { TS_ACCURACY_new() };
    let a = made.accuracy;
    // SAFETY: the accuracy; the context's parts.
    !a.is_null()
        && (seconds.is_null() || unsafe { TS_ACCURACY_set_seconds(a, seconds) } != 0)
        // SAFETY: as above.
        && (millis.is_null() || unsafe { TS_ACCURACY_set_millis(a, millis) } != 0)
        // SAFETY: as above.
        && (micros.is_null() || unsafe { TS_ACCURACY_set_micros(a, micros) } != 0)
        // SAFETY: the TSTInfo; the accuracy.
        && unsafe { TS_TST_INFO_set_accuracy(t, a) } != 0
}

/// The TSTInfo's TSA name: the signer's subject.
///
/// # Safety
/// `signer` is NULL or a live certificate; `t` a live TSTInfo.
unsafe fn tsa_name(signer: *mut X509, t: *mut TS_TST_INFO, made: &mut Made) -> bool {
    // SAFETY: no requirements.
    made.tsa_name = unsafe { GENERAL_NAME_new() };
    // SAFETY: the name made here, or NULL.
    let Some(g) = (unsafe { made.tsa_name.as_mut() }) else {
        return false;
    };
    g.type_ = GEN_DIRNAME;
    // SAFETY: the caller's signer, or NULL.
    let subject = unsafe { X509_get_subject_name(signer) };
    // SAFETY: its subject, or NULL.
    g.d.dirn = unsafe { X509_NAME_dup(subject) };
    // SAFETY: a directory name's.
    if unsafe { g.d.dirn }.is_null() {
        return false;
    }
    // SAFETY: the TSTInfo; the name.
    (unsafe { TS_TST_INFO_set_tsa(t, made.tsa_name) }) != 0
}

/// The TSTInfo's fields from the context.
///
/// # Safety
/// `ctx` is a live context with a request; `t` a new TSTInfo.
unsafe fn fill_tst_info(
    ctx: *mut TS_RESP_CTX,
    t: *mut TS_TST_INFO,
    policy: *mut ASN1_OBJECT,
    made: &mut Made,
) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(req) = (unsafe { request(ctx) }) else {
        return false;
    };
    let imprint = req.msg_imprint.cast();
    // SAFETY: the TSTInfo; the policy; the request's imprint.
    if unsafe { TS_TST_INFO_set_version(t, 1) } == 0
        // SAFETY: as above.
        || unsafe { TS_TST_INFO_set_policy_id(t, policy) } == 0
        // SAFETY: as above.
        || unsafe { TS_TST_INFO_set_msg_imprint(t, imprint) } == 0
        // SAFETY: the caller's context; the TSTInfo.
        || !unsafe { serial_and_time(ctx, t, made) }
    {
        return false;
    }
    // SAFETY: the caller's context, after the callbacks.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return false;
    };
    // SAFETY: its accuracy; the TSTInfo.
    if !unsafe { accuracy(c, t, made) } {
        return false;
    }
    let (flags, signer) = (c.flags, c.signer_cert);
    // SAFETY: the TSTInfo.
    if flags & TS_ORDERING.cast_unsigned() != 0 && unsafe { TS_TST_INFO_set_ordering(t, 1) } == 0 {
        return false;
    }
    // SAFETY: as above.
    let nonce = unsafe { request(ctx) }.map_or(ptr::null_mut(), |r| r.nonce);
    // SAFETY: the TSTInfo; the nonce.
    if !nonce.is_null() && unsafe { TS_TST_INFO_set_nonce(t, nonce) } == 0 {
        return false;
    }
    // SAFETY: the signer, or NULL; the TSTInfo.
    flags & TS_TSA_NAME.cast_unsigned() == 0 || unsafe { tsa_name(signer, t, made) }
}

/// `ts_RESP_create_tst_info`: the TSTInfo for the request, or NULL.
///
/// # Safety
/// `ctx` is a live context with a request.
unsafe fn create_tst_info(ctx: *mut TS_RESP_CTX, policy: *mut ASN1_OBJECT) -> *mut TS_TST_INFO {
    let mut made = Made {
        serial: ptr::null_mut(),
        time: ptr::null_mut(),
        accuracy: ptr::null_mut(),
        tsa_name: ptr::null_mut(),
    };
    // SAFETY: no requirements.
    let t = unsafe { TS_TST_INFO_new() };
    // SAFETY: the caller's context; the new TSTInfo.
    if !t.is_null() && unsafe { fill_tst_info(ctx, t, policy, &mut made) } {
        return t;
    }
    // SAFETY: the TSTInfo made here, or NULL.
    unsafe { TS_TST_INFO_free(t) };
    raise(TS_R_TST_INFO_SETUP_ERROR, "ts_RESP_create_tst_info");
    // SAFETY: the caller's context.
    unsafe { reject_cond(ctx, c"Error during TSTInfo generation.") };
    ptr::null_mut()
}

/// `ts_RESP_process_extensions`: the extension callback accepts each of the request's.
///
/// # Safety
/// `ctx` is a live context with a request.
unsafe fn process_extensions(ctx: *mut TS_RESP_CTX) -> bool {
    let mut i = 0;
    loop {
        // SAFETY: the caller's guarantee; re-read each time, as the callback may change it.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            return false;
        };
        let cb = c.extension_cb;
        // SAFETY: as above.
        let exts = unsafe { request(ctx) }.map_or(ptr::null_mut(), |r| r.extensions);
        // SAFETY: its extensions, or NULL (0).
        if i >= unsafe { OPENSSL_sk_num(exts) } {
            return true;
        }
        // SAFETY: an index in range.
        let ext = unsafe { OPENSSL_sk_value(exts, i) }.cast();
        let Some(cb) = cb else { return false };
        // SAFETY: the application's callback, on its context; no reference is held.
        if unsafe { cb(ctx, ext, ptr::null_mut()) } == 0 {
            return false;
        }
        i += 1;
    }
}

/// Adds the DER of a signing-certificate attribute.
///
/// # Safety
/// `si` is a live signer info.
unsafe fn add_signing_cert(si: *mut PKCS7_SIGNER_INFO, nid: c_int, der: &[u8]) -> bool {
    let Ok(len) = c_int::try_from(der.len()) else {
        return false;
    };
    // SAFETY: no requirements.
    let seq = unsafe { ASN1_STRING_new() };
    // SAFETY: the string made here; the bytes.
    if seq.is_null() || unsafe { ASN1_STRING_set(seq, der.as_ptr().cast(), len) } == 0 {
        // SAFETY: as above, or NULL.
        unsafe { ASN1_STRING_free(seq) };
        return false;
    }
    // SAFETY: the signer info; the string, which it takes on success.
    if unsafe { PKCS7_add_signed_attribute(si, nid, V_ASN1_SEQUENCE, seq.cast()) } == 0 {
        // SAFETY: as above.
        unsafe { ASN1_STRING_free(seq) };
        return false;
    }
    true
}

/// The DER of a value by its `i2d`.
///
/// # Safety
/// `v` is a live value of `i2d`'s type.
unsafe fn der_of<T>(
    v: *const T,
    i2d: unsafe extern "C" fn(*const T, *mut *mut u8) -> c_int,
) -> Option<Vec<u8>> {
    // SAFETY: the caller's value; a length only.
    let n = usize::try_from(unsafe { i2d(v, ptr::null_mut()) }).ok()?;
    let mut buf = vec![0u8; n];
    let mut p = buf.as_mut_ptr();
    // SAFETY: as above; `n` bytes of room.
    (unsafe { i2d(v, &raw mut p) } > 0).then_some(buf)
}

/// `ts_TST_INFO_content_new`: the SignedData's content, an empty TSTInfo OCTET STRING.
///
/// # Safety
/// `p7` is a live SignedData.
unsafe fn tst_info_content_new(p7: *mut PKCS7) -> bool {
    // SAFETY: no requirements.
    let ret = unsafe { PKCS7_new() };
    // SAFETY: the object made here, or NULL.
    let Some(r) = (unsafe { ret.as_mut() }) else {
        return false;
    };
    let ok = 'b: {
        // SAFETY: no requirements.
        let other = unsafe { ASN1_TYPE_new() };
        if other.is_null() {
            break 'b false;
        }
        r.d.other = other;
        // SAFETY: a known NID.
        r.type_ = unsafe { OBJ_nid2obj(NID_id_smime_ct_TSTInfo) };
        // SAFETY: no requirements.
        let os = unsafe { ASN1_OCTET_STRING_new() };
        if os.is_null() {
            break 'b false;
        }
        // SAFETY: the type; the string, which it takes.
        unsafe { ASN1_TYPE_set(other, V_ASN1_OCTET_STRING, os.cast()) };
        // SAFETY: the caller's SignedData; the content, which it takes on success.
        (unsafe { PKCS7_set_content(p7, ret) }) != 0
    };
    if !ok {
        // SAFETY: made here.
        unsafe { PKCS7_free(ret) };
    }
    ok
}

/// The signature's digest: the context's (fetched if it has no provider), or SHA-256.
fn signer_md(c: &RespCtx) -> *mut EVP_MD {
    if c.signer_md.is_null() {
        // SAFETY: the context's library context and query.
        return unsafe { EVP_MD_fetch(c.libctx, c"SHA256".as_ptr(), c.propq) };
    }
    // SAFETY: a digest.
    if unsafe { EVP_MD_get0_provider(c.signer_md) }.is_null() {
        // SAFETY: as above; its name.
        let name = unsafe { EVP_MD_get0_name(c.signer_md) };
        // SAFETY: as above.
        return unsafe { EVP_MD_fetch(c.libctx, name, c.propq) };
    }
    c.signer_md.cast_mut()
}

/// Adds the signing-certificate attribute (version 1 with SHA-1, else version 2).
///
/// # Safety
/// `c`'s signer and certificates are live; `si` a live signer info.
unsafe fn add_ess(c: &RespCtx, si: *mut PKCS7_SIGNER_INFO) -> bool {
    const F: &str = "ts_RESP_sign";
    let certs = if c.flags & TS_ESS_CERT_ID_CHAIN.cast_unsigned() != 0 {
        c.certs
    } else {
        ptr::null_mut()
    };
    let md = c.ess_cert_id_digest;
    // SAFETY: a digest; a NUL-terminated name.
    if md.is_null() || unsafe { EVP_MD_is_a(md, SN_sha1.as_ptr()) } != 0 {
        // SAFETY: the signer; the certificates, or NULL.
        let sc = unsafe { OSSL_ESS_signing_cert_new_init(c.signer_cert, certs, 0) };
        if sc.is_null() {
            return false;
        }
        // SAFETY: the attribute made here.
        let der = unsafe { der_of(sc.cast_const(), i2d_ESS_SIGNING_CERT) };
        // SAFETY: as above.
        unsafe { ESS_SIGNING_CERT_free(sc) };
        // SAFETY: the signer info.
        let ok = der.is_some_and(|d| unsafe {
            add_signing_cert(si, NID_id_smime_aa_signingCertificate, &d)
        });
        if !ok {
            raise(TS_R_ESS_ADD_SIGNING_CERT_ERROR, F);
        }
        return ok;
    }
    // SAFETY: the digest; the signer; the certificates, or NULL.
    let sc2 = unsafe { OSSL_ESS_signing_cert_v2_new_init(md, c.signer_cert, certs, 0) };
    if sc2.is_null() {
        return false;
    }
    // SAFETY: the attribute made here.
    let der = unsafe { der_of(sc2.cast_const(), i2d_ESS_SIGNING_CERT_V2) };
    // SAFETY: as above.
    unsafe { ESS_SIGNING_CERT_V2_free(sc2) };
    // SAFETY: the signer info.
    let ok = der
        .is_some_and(|d| unsafe { add_signing_cert(si, NID_id_smime_aa_signingCertificateV2, &d) });
    if !ok {
        raise(TS_R_ESS_ADD_SIGNING_CERT_V2_ERROR, F);
    }
    ok
}

/// The SignedData's signer info and attributes, its content, and the TSTInfo signed into it.
///
/// # Safety
/// `c` holds a request, a signer, its key, and a TSTInfo; `p7` is a live PKCS #7 object.
unsafe fn sign_into(c: &RespCtx, p7: *mut PKCS7, md: *mut EVP_MD, p7bio: &mut *mut BIO) -> bool {
    const F: &str = "ts_RESP_sign";
    // SAFETY: the object.
    if unsafe { PKCS7_set_type(p7, NID_pkcs7_signed) } == 0 {
        return false;
    }
    // SAFETY: the caller's object.
    let Some(o) = (unsafe { p7.as_ref() }) else {
        return false;
    };
    // SAFETY: a SignedData's content.
    let sign = unsafe { o.d.sign };
    // SAFETY: as above, or NULL.
    let Some(sign) = (unsafe { sign.as_ref() }) else {
        return false;
    };
    // SAFETY: its version.
    if unsafe { ASN1_INTEGER_set(sign.version, 3) } == 0 {
        return false;
    }
    // SAFETY: the context's request.
    if unsafe { c.request.cast::<Req>().as_ref() }.is_some_and(|r| r.cert_req != 0) {
        // SAFETY: the object; the context's signer.
        unsafe { PKCS7_add_certificate(p7, c.signer_cert) };
        // SAFETY: the context's certificates, or NULL (0).
        let n = unsafe { OPENSSL_sk_num(c.certs.cast()) };
        for i in 0..n {
            // SAFETY: an index in range.
            let x = unsafe { OPENSSL_sk_value(c.certs.cast(), i) }.cast();
            // SAFETY: the object; the certificate.
            unsafe { PKCS7_add_certificate(p7, x) };
        }
    }
    // SAFETY: the object; the context's signer and key; the digest.
    let si = unsafe { PKCS7_add_signature(p7, c.signer_cert, c.signer_key, md) };
    if si.is_null() {
        raise(TS_R_PKCS7_ADD_SIGNATURE_ERROR, F);
        return false;
    }
    // SAFETY: a known NID.
    let oid = unsafe { OBJ_nid2obj(NID_id_smime_ct_TSTInfo) };
    // SAFETY: the signer info; the static object.
    if unsafe { PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT, oid.cast()) }
        == 0
    {
        raise(TS_R_PKCS7_ADD_SIGNED_ATTR_ERROR, F);
        return false;
    }
    // SAFETY: the context; the signer info; the object.
    if !unsafe { add_ess(c, si) } || !unsafe { tst_info_content_new(p7) } {
        return false;
    }
    // SAFETY: as above.
    *p7bio = unsafe { PKCS7_dataInit(p7, ptr::null_mut()) };
    if p7bio.is_null() {
        raise(ERR_R_PKCS7_LIB, F);
        return false;
    }
    // SAFETY: the BIO; the context's TSTInfo.
    if unsafe { i2d_TS_TST_INFO_bio(*p7bio, c.tst_info) } == 0
        // SAFETY: the object; the BIO.
        || unsafe { PKCS7_dataFinal(p7, *p7bio) } == 0
    {
        raise(TS_R_TS_DATASIGN, F);
        return false;
    }
    true
}

/// `ts_RESP_sign` up to the response: the signed token, or NULL.
///
/// # Safety
/// `c` holds a request, a signer, its key, and a TSTInfo.
unsafe fn token(c: &RespCtx) -> *mut PKCS7 {
    // SAFETY: the context's signer and key.
    if unsafe { X509_check_private_key(c.signer_cert, c.signer_key) } == 0 {
        raise(TS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE, "ts_RESP_sign");
        return ptr::null_mut();
    }
    // SAFETY: the context's library context and query.
    let mut p7 = unsafe { PKCS7_new_ex(c.libctx, c.propq) };
    if p7.is_null() {
        raise(ERR_R_ASN1_LIB, "ts_RESP_sign");
        return p7;
    }
    let md = signer_md(c);
    let mut p7bio = ptr::null_mut();
    // SAFETY: the context; the object; the digest.
    if !unsafe { sign_into(c, p7, md, &mut p7bio) } {
        // SAFETY: made here.
        unsafe { PKCS7_free(p7) };
        p7 = ptr::null_mut();
    }
    if md.cast_const() != c.signer_md {
        // SAFETY: fetched here, or NULL.
        unsafe { EVP_MD_free(md) };
    }
    // SAFETY: made here, or NULL.
    unsafe { BIO_free_all(p7bio) };
    p7
}

/// `ts_RESP_sign`: signs the TSTInfo into the response's token.
///
/// # Safety
/// `ctx` is a live context with a request, a response, and a TSTInfo.
unsafe fn sign(ctx: *mut TS_RESP_CTX) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return false;
    };
    // SAFETY: a context with a request, a signer, its key, and a TSTInfo.
    let p7 = unsafe { token(c) };
    if p7.is_null() {
        // SAFETY: the caller's context.
        unsafe { reject_cond(ctx, c"Error during signature generation.") };
        return false;
    }
    // SAFETY: as above.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return false;
    };
    // SAFETY: its response; the token and the TSTInfo, which it takes.
    unsafe { TS_RESP_set_tst_info(c.response, p7, c.tst_info) };
    c.tst_info = ptr::null_mut();
    true
}

/// The steps of [`TS_RESP_create_response`] after making the response.
///
/// # Safety
/// `ctx` is a live context with a response; `req_bio` NULL or a live BIO.
unsafe fn create(ctx: *mut TS_RESP_CTX, req_bio: *mut BIO) -> bool {
    // SAFETY: the caller's BIO.
    let req = unsafe { d2i_TS_REQ_bio(req_bio, ptr::null_mut()) };
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return false;
    };
    c.request = req;
    if req.is_null() {
        // SAFETY: the caller's context.
        unsafe {
            reject(
                ctx,
                c"Bad request format or system error.",
                TS_INFO_BAD_DATA_FORMAT,
            )
        };
        return false;
    }
    // SAFETY: the caller's context.
    if unsafe { TS_RESP_CTX_set_status_info(ctx, TS_STATUS_GRANTED, ptr::null()) } == 0
        // SAFETY: a context with a request.
        || !unsafe { check_request(ctx) }
    {
        return false;
    }
    // SAFETY: as above.
    let policy = unsafe { get_policy(ctx) };
    if policy.is_null() {
        return false;
    }
    // SAFETY: as above.
    let t = unsafe { create_tst_info(ctx, policy) };
    // SAFETY: as above.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return false;
    };
    c.tst_info = t;
    // SAFETY: as above, with a TSTInfo.
    !t.is_null() && unsafe { process_extensions(ctx) } && unsafe { sign(ctx) }
}

/// `ts_RESP_CTX_cleanup`: frees what was made for one response.
///
/// # Safety
/// `c`'s request, response, and TSTInfo are NULL or its own.
unsafe fn cleanup(c: &mut RespCtx) {
    // SAFETY: its own, or NULL.
    unsafe { TS_REQ_free(c.request) };
    c.request = ptr::null_mut();
    // SAFETY: as above.
    unsafe { TS_RESP_free(c.response) };
    c.response = ptr::null_mut();
    // SAFETY: as above.
    unsafe { TS_TST_INFO_free(c.tst_info) };
    c.tst_info = ptr::null_mut();
}

ffi_export! {
    /// The response to the DER request read from `req_bio`: a signed token, a rejection
    /// saying why, or NULL.
    ///
    /// # Safety
    /// `ctx` is a live context; `req_bio` a live BIO.
    pub unsafe extern "C" fn TS_RESP_create_response(ctx: *mut TS_RESP_CTX, req_bio: *mut BIO) -> *mut TS_RESP
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return ptr::null_mut() };
        // `ts_RESP_CTX_init` forgets what a past call left.
        c.request = ptr::null_mut();
        c.tst_info = ptr::null_mut();
        // SAFETY: no requirements.
        c.response = unsafe { TS_RESP_new() };
        let ok = if c.response.is_null() {
            raise(ERR_R_TS_LIB, "TS_RESP_create_response");
            false
        } else {
            // SAFETY: a live context with a response; the caller's BIO.
            unsafe { create(ctx, req_bio) }
        };
        if !ok {
            raise(TS_R_RESPONSE_SETUP_ERROR, "TS_RESP_create_response");
            // SAFETY: as above.
            let has = unsafe { ctx_of(ctx) }.is_some_and(|c| !c.response.is_null());
            // SAFETY: as above.
            if has && unsafe { reject_cond(ctx, c"Error during response generation.") } == 0 {
                // SAFETY: as above.
                if let Some(c) = unsafe { ctx_of(ctx) } {
                    // SAFETY: its response.
                    unsafe { TS_RESP_free(c.response) };
                    c.response = ptr::null_mut();
                }
            }
        }
        // SAFETY: as above.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return ptr::null_mut() };
        let response = core::mem::replace(&mut c.response, ptr::null_mut());
        // SAFETY: its own.
        unsafe { cleanup(c) };
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(sec: c_long, usec: c_long, precision: c_uint) -> Option<String> {
        gen_time_text(sec, usec, precision).map(|s| s.into_string().unwrap_or_default())
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls gmtime_r, which Miri does not support")]
    fn the_time_keeps_its_digits_without_trailing_zeros() {
        assert_eq!(
            text(1_700_000_000, 123_000, 3).as_deref(),
            Some("20231114221320.123Z")
        );
        assert_eq!(
            text(1_700_000_000, 120_000, 6).as_deref(),
            Some("20231114221320.12Z")
        );
        assert_eq!(
            text(1_700_000_000, 987_654, 2).as_deref(),
            Some("20231114221320.98Z")
        );
        assert_eq!(
            text(1_700_000_000, 0, 6).as_deref(),
            Some("20231114221320Z")
        );
        assert_eq!(
            text(1_700_000_000, 5, 6).as_deref(),
            Some("20231114221320.000005Z")
        );
        assert_eq!(
            text(1_700_000_000, 123_456, 0).as_deref(),
            Some("20231114221320Z")
        );
        assert_eq!(text(1_700_000_000, 1, 7), None);
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls gmtime_r, which Miri does not support")]
    fn a_negative_fraction_prints_as_c_does() {
        // `.%06ld` of -1 is `.-00001`, cut to the digits asked for; it is no valid time.
        assert_eq!(text(0, -1, 3).as_deref(), Some("19700101000000.-Z"));
        assert!(gen_time(0, -1, 3).is_null());
    }
}
