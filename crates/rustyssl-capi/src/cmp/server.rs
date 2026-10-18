//! The generic CMP server (`cmp_server.c`, `OSSL_CMP_SRV_CTX_new(3)`): a context the application
//! gives its callbacks (certificate requests, revocation, general messages, errors, certificate
//! confirmation, polling, delayed delivery, transaction clean-up), and the processing of one
//! request into one response, with the transaction's state (its ID, nonces, polling) kept in a
//! CMP context. `OSSL_CMP_CTX_server_perform` lets a client use such a server in-process as its
//! transfer callback.
//!
//! The application's callbacks receive the server context and may call any API on it, so no
//! borrow of it is held across a callback: fields are read into locals before each call.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_OCTET_STRING, CMP_R_BAD_REQUEST_ID, CMP_R_CERTREQMSG_NOT_FOUND,
    CMP_R_ERROR_CREATING_CERTREP, CMP_R_ERROR_CREATING_PKICONF, CMP_R_ERROR_CREATING_POLLREP,
    CMP_R_ERROR_CREATING_RR, CMP_R_ERROR_PROCESSING_MESSAGE, CMP_R_ERROR_UNEXPECTED_CERTCONF,
    CMP_R_EXPECTED_POLLREQ, CMP_R_MULTIPLE_REQUESTS_NOT_SUPPORTED, CMP_R_NULL_ARGUMENT,
    CMP_R_SENDER_GENERALNAME_TYPE_NOT_SUPPORTED, CMP_R_TRANSFER_ERROR, CMP_R_UNEXPECTED_PKIBODY,
    CMP_R_UNSUPPORTED_PKIBODY, ERR_LIB_CMP, ERR_TXT_STRING, EVP_PKEY, GEN_DIRNAME,
    NID_id_PasswordBasedMAC, OSSL_CMP_CTX, OSSL_CMP_LOG_DEBUG, OSSL_CMP_LOG_ERR, OSSL_CMP_LOG_INFO,
    OSSL_CMP_LOG_WARNING, OSSL_CMP_MSG, OSSL_CMP_OPT_IMPLICIT_CONFIRM,
    OSSL_CMP_OPT_UNPROTECTED_ERRORS, OSSL_CMP_PKIFAILUREINFO_badPOP,
    OSSL_CMP_PKIFAILUREINFO_badRequest, OSSL_CMP_PKIFAILUREINFO_systemFailure, OSSL_CMP_PKISI,
    OSSL_CMP_PKISTATUS_accepted, OSSL_CMP_PKISTATUS_rejection, OSSL_CMP_PKISTATUS_trans,
    OSSL_CMP_PKISTATUS_unspecified, OSSL_CMP_PKISTATUS_waiting, OSSL_CMP_SRV_CTX,
    OSSL_CMP_SRV_cert_request_cb_t, OSSL_CMP_SRV_certConf_cb_t,
    OSSL_CMP_SRV_clean_transaction_cb_t, OSSL_CMP_SRV_delayed_delivery_cb_t,
    OSSL_CMP_SRV_error_cb_t, OSSL_CMP_SRV_genm_cb_t, OSSL_CMP_SRV_pollReq_cb_t,
    OSSL_CMP_SRV_rr_cb_t, OSSL_CRMF_CERTID, OSSL_CRMF_MSG, OSSL_LIB_CTX, X509, X509_REQ,
    stack_st_OSSL_CMP_ITAV, stack_st_X509,
};

use super::asn::{
    CERTREQID, CERTREQID_INVALID, CERTREQID_NONE, CertStatus, ErrorMsgContent, Msg,
    OSSL_CMP_ITAV_free, OSSL_CMP_PKISI_free, PKIBODY_CERTCONF, PKIBODY_CP, PKIBODY_CR,
    PKIBODY_ERROR, PKIBODY_GENM, PKIBODY_GENP, PKIBODY_IP, PKIBODY_IR, PKIBODY_KUP, PKIBODY_KUR,
    PKIBODY_P10CR, PKIBODY_PKICONF, PKIBODY_POLLREQ, PKIBODY_RP, PKIBODY_RR, PkiHeader, PollReq,
    RevDetails, asn1_get_int, of,
};
use super::ctx::OSSL_CMP_CTX_print_errors;
use super::ctx::{
    OSSL_CMP_CTX_free, OSSL_CMP_CTX_get_option, OSSL_CMP_CTX_get_transfer_cb_arg, OSSL_CMP_CTX_new,
    OSSL_CMP_CTX_set_option, OSSL_CMP_CTX_set0_newPkey, OSSL_CMP_CTX_set1_recipient,
    OSSL_CMP_CTX_set1_senderNonce, OSSL_CMP_CTX_set1_transactionID, ctx_of, ctx_set1_recipNonce,
    print_log,
};
use super::hdr::{
    OSSL_CMP_HDR_get0_transactionID, hdr_get_protection_nid, hdr_has_implicitConfirm,
};
use super::msg::{
    OSSL_CMP_MSG_free, OSSL_CMP_MSG_get_bodytype, OSSL_CMP_MSG_get0_header, bodytype_to_string,
    certrep_new, error_new, genp_new, is_error_with_waiting, pkiconf_new, pollRep_new, rp_new,
};
use super::status::{OSSL_CMP_STATUSINFO_new, PKIStatus_to_string, pkisi_get_status};
use super::vfy::{msg_check_update, verify_popo};
use crate::asn1::string::ASN1_OCTET_STRING_cmp;
use crate::crmf::asn::OSSL_CRMF_CERTID_free;
use crate::crmf::msg::{
    OSSL_CRMF_CERTID_gen, OSSL_CRMF_CERTTEMPLATE_get0_issuer,
    OSSL_CRMF_CERTTEMPLATE_get0_serialNumber, OSSL_CRMF_MSG_centralkeygen_requested,
    OSSL_CRMF_MSG_get_certReqId,
};
use crate::err::strings::ERR_reason_error_string;
use crate::err::{self, ERR_peek_error, ERR_peek_error_data};
use crate::ffi::ffi_export;
use crate::mem;
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value};
use crate::x509::cert::{OSSL_STACK_OF_X509_free, X509_free};
use crate::x509v3::i2s_ASN1_OCTET_STRING;

/// `struct ossl_cmp_srv_ctx_st`, with OpenSSL's field names.
struct SrvCtx {
    /// The CMP context reused for the transaction ID and the rest.
    ctx: *mut OSSL_CMP_CTX,
    /// The application's own context.
    custom_ctx: *mut c_void,
    /// Of the ir/cr/kur, `OSSL_CMP_CERTREQID_NONE` for a p10cr.
    certReqId: c_int,
    /// Whether the current transaction is polling.
    polling: c_int,

    process_cert_request: OSSL_CMP_SRV_cert_request_cb_t,
    process_rr: OSSL_CMP_SRV_rr_cb_t,
    process_genm: OSSL_CMP_SRV_genm_cb_t,
    process_error: OSSL_CMP_SRV_error_cb_t,
    process_certConf: OSSL_CMP_SRV_certConf_cb_t,
    process_pollReq: OSSL_CMP_SRV_pollReq_cb_t,
    delayed_delivery: OSSL_CMP_SRV_delayed_delivery_cb_t,
    clean_transaction: OSSL_CMP_SRV_clean_transaction_cb_t,

    sendUnprotectedErrors: c_int,
    acceptUnprotected: c_int,
    acceptRAVerified: c_int,
    grantImplicitConfirm: c_int,
}

/// The server context behind a handle, borrowed only for the statement that uses it.
///
/// # Safety
/// `s` is NULL or a live server context, not borrowed elsewhere while the result is used.
unsafe fn srv<'a>(s: *const OSSL_CMP_SRV_CTX) -> Option<&'a mut SrvCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { s.cast::<SrvCtx>().cast_mut().as_mut() }
}

fn raise(reason: c_int, function: &str) {
    err::raise(ERR_LIB_CMP, reason, function);
}

/// A body type's name, for logging.
fn body_name(t: c_int) -> String {
    bodytype_to_string(t).to_string_lossy().into_owned()
}

/// The body's value of a message, or NULL.
///
/// # Safety
/// `req` is NULL or a live message.
unsafe fn body_value(req: *const OSSL_CMP_MSG) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let Some(m) = (unsafe { of::<Msg, _>(req) }) else {
        return ptr::null_mut();
    };
    // SAFETY: its body, or NULL.
    unsafe { m.body.as_ref() }.map_or(ptr::null_mut(), |b| b.value)
}

ffi_export! {
    /// Frees a server context and its CMP context (nothing for NULL).
    ///
    /// # Safety
    /// `srv_ctx` is NULL or a live server context, not used after.
    pub unsafe extern "C" fn OSSL_CMP_SRV_CTX_free(srv_ctx: *mut OSSL_CMP_SRV_CTX)
    where failure = (), library = ERR_LIB_CMP
    {
        if srv_ctx.is_null() {
            return;
        }
        // SAFETY: the caller's live context, made by OSSL_CMP_SRV_CTX_new as a Box.
        let s = unsafe { Box::from_raw(srv_ctx.cast::<SrvCtx>()) };
        // SAFETY: its own CMP context, or NULL.
        unsafe { OSSL_CMP_CTX_free(s.ctx) };
    }
}

ffi_export! {
    /// A new server context with a new CMP context in the library context, or NULL.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `propq` NULL or a C string.
    pub unsafe extern "C" fn OSSL_CMP_SRV_CTX_new(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut OSSL_CMP_SRV_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let ctx = unsafe { OSSL_CMP_CTX_new(libctx, propq) };
        if ctx.is_null() {
            return ptr::null_mut();
        }
        let s = SrvCtx {
            ctx,
            custom_ctx: ptr::null_mut(),
            certReqId: CERTREQID_INVALID,
            polling: 0,
            process_cert_request: None,
            process_rr: None,
            process_genm: None,
            process_error: None,
            process_certConf: None,
            process_pollReq: None,
            delayed_delivery: None,
            clean_transaction: None,
            sendUnprotectedErrors: 0,
            acceptUnprotected: 0,
            acceptRAVerified: 0,
            grantImplicitConfirm: 0,
        };
        Box::into_raw(Box::new(s)).cast()
    }
}

ffi_export! {
    /// Sets the application's context and request callbacks: 1, or 0 for NULL.
    ///
    /// # Safety
    /// `srv_ctx` is NULL or a live server context; the callbacks are NULL or valid functions.
    pub unsafe extern "C" fn OSSL_CMP_SRV_CTX_init(
        srv_ctx: *mut OSSL_CMP_SRV_CTX,
        custom_ctx: *mut c_void,
        process_cert_request: OSSL_CMP_SRV_cert_request_cb_t,
        process_rr: OSSL_CMP_SRV_rr_cb_t,
        process_genm: OSSL_CMP_SRV_genm_cb_t,
        process_error: OSSL_CMP_SRV_error_cb_t,
        process_certConf: OSSL_CMP_SRV_certConf_cb_t,
        process_pollReq: OSSL_CMP_SRV_pollReq_cb_t,
    ) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { srv(srv_ctx) }) else {
            raise(CMP_R_NULL_ARGUMENT, "OSSL_CMP_SRV_CTX_init");
            return 0;
        };
        s.custom_ctx = custom_ctx;
        s.process_cert_request = process_cert_request;
        s.process_rr = process_rr;
        s.process_genm = process_genm;
        s.process_error = process_error;
        s.process_certConf = process_certConf;
        s.process_pollReq = process_pollReq;
        1
    }
}

ffi_export! {
    /// Sets the delayed-delivery and transaction clean-up callbacks: 1, or 0 for NULL.
    ///
    /// # Safety
    /// `srv_ctx` is NULL or a live server context; the callbacks are NULL or valid functions.
    pub unsafe extern "C" fn OSSL_CMP_SRV_CTX_init_trans(
        srv_ctx: *mut OSSL_CMP_SRV_CTX,
        delay: OSSL_CMP_SRV_delayed_delivery_cb_t,
        clean: OSSL_CMP_SRV_clean_transaction_cb_t,
    ) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { srv(srv_ctx) }) else {
            raise(CMP_R_NULL_ARGUMENT, "OSSL_CMP_SRV_CTX_init_trans");
            return 0;
        };
        s.delayed_delivery = delay;
        s.clean_transaction = clean;
        1
    }
}

ffi_export! {
    /// The server's CMP context, or NULL (with an error) for NULL.
    ///
    /// # Safety
    /// `srv_ctx` is NULL or a live server context.
    pub unsafe extern "C" fn OSSL_CMP_SRV_CTX_get0_cmp_ctx(srv_ctx: *const OSSL_CMP_SRV_CTX) -> *mut OSSL_CMP_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { srv(srv_ctx) }) else {
            raise(CMP_R_NULL_ARGUMENT, "OSSL_CMP_SRV_CTX_get0_cmp_ctx");
            return ptr::null_mut();
        };
        s.ctx
    }
}

ffi_export! {
    /// The application's context, or NULL (with an error) for NULL.
    ///
    /// # Safety
    /// `srv_ctx` is NULL or a live server context.
    pub unsafe extern "C" fn OSSL_CMP_SRV_CTX_get0_custom_ctx(srv_ctx: *const OSSL_CMP_SRV_CTX) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { srv(srv_ctx) }) else {
            raise(CMP_R_NULL_ARGUMENT, "OSSL_CMP_SRV_CTX_get0_custom_ctx");
            return ptr::null_mut();
        };
        s.custom_ctx
    }
}

/// The four flag setters: the flag set to `val != 0`, 1; or 0 (with an error) for NULL.
///
/// # Safety
/// `srv_ctx` is NULL or a live server context.
unsafe fn set_flag(
    srv_ctx: *mut OSSL_CMP_SRV_CTX,
    val: c_int,
    field: fn(&mut SrvCtx) -> &mut c_int,
    name: &str,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { srv(srv_ctx) }) else {
        raise(CMP_R_NULL_ARGUMENT, name);
        return 0;
    };
    *field(s) = c_int::from(val != 0);
    1
}

ffi_export! {
    /// Whether error and rejection messages go unprotected: 1, or 0 for NULL.
    ///
    /// # Safety
    /// `srv_ctx` is NULL or a live server context.
    pub unsafe extern "C" fn OSSL_CMP_SRV_CTX_set_send_unprotected_errors(srv_ctx: *mut OSSL_CMP_SRV_CTX, val: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_flag(srv_ctx, val, |s| &mut s.sendUnprotectedErrors, "OSSL_CMP_SRV_CTX_set_send_unprotected_errors") }
    }
}

ffi_export! {
    /// Whether requests with missing or invalid protection are accepted: 1, or 0 for NULL.
    ///
    /// # Safety
    /// `srv_ctx` is NULL or a live server context.
    pub unsafe extern "C" fn OSSL_CMP_SRV_CTX_set_accept_unprotected(srv_ctx: *mut OSSL_CMP_SRV_CTX, val: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_flag(srv_ctx, val, |s| &mut s.acceptUnprotected, "OSSL_CMP_SRV_CTX_set_accept_unprotected") }
    }
}

ffi_export! {
    /// Whether an RA-verified proof-of-possession is accepted: 1, or 0 for NULL.
    ///
    /// # Safety
    /// `srv_ctx` is NULL or a live server context.
    pub unsafe extern "C" fn OSSL_CMP_SRV_CTX_set_accept_raverified(srv_ctx: *mut OSSL_CMP_SRV_CTX, val: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_flag(srv_ctx, val, |s| &mut s.acceptRAVerified, "OSSL_CMP_SRV_CTX_set_accept_raverified") }
    }
}

ffi_export! {
    /// Whether implicit confirmation is granted when requested: 1, or 0 for NULL.
    ///
    /// # Safety
    /// `srv_ctx` is NULL or a live server context.
    pub unsafe extern "C" fn OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(srv_ctx: *mut OSSL_CMP_SRV_CTX, val: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_flag(srv_ctx, val, |s| &mut s.grantImplicitConfirm, "OSSL_CMP_SRV_CTX_set_grant_implicit_confirm") }
    }
}

/// The server's CMP context (NULL if none).
///
/// # Safety
/// `s` is a live server context.
unsafe fn cmp_ctx(s: *mut OSSL_CMP_SRV_CTX) -> *mut OSSL_CMP_CTX {
    // SAFETY: the caller's guarantee.
    unsafe { srv(s) }.map_or(ptr::null_mut(), |s| s.ctx)
}

/// `delayed_delivery`: an error message with a waiting status if the application starts
/// polling, else NULL (also when it says not to delay).
///
/// # Safety
/// `srv_ctx` is a live server context with a CMP context; `req` a live message.
unsafe fn delayed_delivery(
    srv_ctx: *mut OSSL_CMP_SRV_CTX,
    req: *const OSSL_CMP_MSG,
) -> *mut OSSL_CMP_MSG {
    // SAFETY: the caller's guarantee.
    let (ctx, cb) = match unsafe { srv(srv_ctx) } {
        Some(s) => (s.ctx, s.delayed_delivery),
        None => return ptr::null_mut(),
    };
    let Some(cb) = cb.filter(|_| !ctx.is_null() && !req.is_null()) else {
        return ptr::null_mut();
    };
    // SAFETY: the application's callback with its server context and the request; no
    // borrow held.
    let ret = unsafe { cb(srv_ctx, req) };
    if ret == 0 {
        return ptr::null_mut();
    }
    let mut status = OSSL_CMP_PKISTATUS_waiting;
    let mut fail_info = 0;
    let mut error_code = 0;
    let mut txt: *const c_char = ptr::null();
    let mut details: *const c_char = ptr::null();
    if ret == 1 {
        // SAFETY: as above.
        if let Some(s) = unsafe { srv(srv_ctx) } {
            s.polling = 1;
        }
    } else {
        status = OSSL_CMP_PKISTATUS_rejection;
        fail_info = 1 << OSSL_CMP_PKIFAILUREINFO_systemFailure;
        txt = c"server application error".as_ptr();
        // SAFETY: no preconditions.
        let e = unsafe { ERR_peek_error() };
        error_code = err::reason_of(e);
        // SAFETY: no preconditions.
        details = unsafe { ERR_reason_error_string(e) };
    }
    // SAFETY: a static string or NULL.
    let si = unsafe { OSSL_CMP_STATUSINFO_new(status, fail_info, txt) };
    if si.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: as above.
    let unprotected = unsafe { srv(srv_ctx) }.map_or(0, |s| s.sendUnprotectedErrors);
    // SAFETY: the CMP context; the status made here; a static string or NULL.
    let msg = unsafe { error_new(ctx, si, i64::from(error_code), details, unprotected) };
    // SAFETY: made here.
    unsafe { OSSL_CMP_PKISI_free(si) };
    msg
}

/// `process_cert_request`: the ip/cp/kup answering the first certification request of an
/// ir/cr/p10cr/kur, or NULL.
///
/// # Safety
/// `srv_ctx` is a live server context with a cert-request callback; `req` a live message.
unsafe fn process_cert_request(
    srv_ctx: *mut OSSL_CMP_SRV_CTX,
    req: *const OSSL_CMP_MSG,
) -> *mut OSSL_CMP_MSG {
    const F: &str = "process_cert_request";
    // SAFETY: the caller's guarantee.
    let ctx = unsafe { cmp_ctx(srv_ctx) };
    if ctx.is_null() || req.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the request.
    let req_type = unsafe { OSSL_CMP_MSG_get_bodytype(req) };
    let bodytype = match req_type {
        PKIBODY_P10CR | PKIBODY_CR => PKIBODY_CP,
        PKIBODY_IR => PKIBODY_IP,
        PKIBODY_KUR => PKIBODY_KUP,
        _ => {
            raise(CMP_R_UNEXPECTED_PKIBODY, F);
            return ptr::null_mut();
        }
    };
    let mut crm: *const OSSL_CRMF_MSG = ptr::null();
    let mut p10cr: *const X509_REQ = ptr::null();
    let cert_req_id;
    // SAFETY: the request.
    let value = unsafe { body_value(req) };
    if req_type == PKIBODY_P10CR {
        cert_req_id = CERTREQID_NONE;
        p10cr = value.cast();
    } else {
        // The same for cr and kur.
        let reqs = value.cast::<rustyssl_abi::OPENSSL_STACK>();
        // SAFETY: the body's list, or NULL.
        if unsafe { OPENSSL_sk_num(reqs) } != 1 {
            raise(CMP_R_MULTIPLE_REQUESTS_NOT_SUPPORTED, F);
            return ptr::null_mut();
        }
        // SAFETY: index 0 of a one-element list.
        crm = unsafe { OPENSSL_sk_value(reqs, 0) }.cast();
        if crm.is_null() {
            raise(CMP_R_CERTREQMSG_NOT_FOUND, F);
            return ptr::null_mut();
        }
        // SAFETY: a live CRMF message.
        cert_req_id = unsafe { OSSL_CRMF_MSG_get_certReqId(crm) };
        if cert_req_id != CERTREQID {
            raise(CMP_R_BAD_REQUEST_ID, F);
            return ptr::null_mut();
        }
    }
    // SAFETY: the caller's guarantee.
    let (accept_ra, grant, unprotected, cb) = match unsafe { srv(srv_ctx) } {
        Some(s) => {
            s.certReqId = cert_req_id;
            (
                s.acceptRAVerified,
                s.grantImplicitConfirm,
                s.sendUnprotectedErrors,
                s.process_cert_request,
            )
        }
        None => return ptr::null_mut(),
    };

    // SAFETY: the request's message or CSR, one of them NULL.
    let central_keygen = unsafe { OSSL_CRMF_MSG_centralkeygen_requested(crm, p10cr) };
    if central_keygen < 0 {
        return ptr::null_mut();
    }
    let mut cert_out: *mut X509 = ptr::null_mut();
    let mut key_out: *const EVP_PKEY = ptr::null();
    let mut chain_out: *mut stack_st_X509 = ptr::null_mut();
    let mut ca_pubs: *mut stack_st_X509 = ptr::null_mut();
    let mut msg: *mut OSSL_CMP_MSG = ptr::null_mut();
    let si: *mut OSSL_CMP_PKISI;
    'end: {
        // SAFETY: the CMP context; the request.
        if central_keygen == 0 && unsafe { verify_popo(ctx, req, accept_ra) } == 0 {
            // Proof of possession could not be verified.
            // SAFETY: no preconditions.
            let e = unsafe { ERR_peek_error() };
            // SAFETY: no preconditions.
            let text = unsafe { ERR_reason_error_string(e) };
            // SAFETY: a static string or NULL.
            si = unsafe {
                OSSL_CMP_STATUSINFO_new(
                    OSSL_CMP_PKISTATUS_rejection,
                    1 << OSSL_CMP_PKIFAILUREINFO_badPOP,
                    text,
                )
            };
            if si.is_null() {
                return ptr::null_mut();
            }
        } else {
            // SAFETY: the request.
            let hdr = unsafe { OSSL_CMP_MSG_get0_header(req) };
            let Some(cb) = cb else {
                si = ptr::null_mut();
                break 'end;
            };
            // SAFETY: the application's callback; rooms for its outputs; no borrow held.
            si = unsafe {
                cb(
                    srv_ctx,
                    req,
                    cert_req_id,
                    crm,
                    p10cr,
                    &raw mut cert_out,
                    &raw mut chain_out,
                    &raw mut ca_pubs,
                )
            };
            if si.is_null() {
                break 'end;
            }
            // SAFETY: the status the callback gave.
            if unsafe { pkisi_get_status(si) } == OSSL_CMP_PKISTATUS_waiting {
                // SAFETY: as above.
                if let Some(s) = unsafe { srv(srv_ctx) } {
                    s.polling = 1;
                }
            }
            // Implicit confirmation if and only if the transaction ends (not if polling starts).
            // SAFETY: the request's header.
            let implicit =
                unsafe { hdr_has_implicitConfirm(hdr) } != 0 && grant != 0 && !cert_out.is_null();
            // SAFETY: the CMP context.
            if unsafe {
                OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_IMPLICIT_CONFIRM, c_int::from(implicit))
            } == 0
            {
                break 'end;
            }
            if central_keygen == 1 {
                // SAFETY: the CMP context, borrowed for this statement.
                if let Some(c) = unsafe { ctx_of(ctx) }
                    && c.newPkey_priv != 0
                    && !c.newPkey.is_null()
                {
                    key_out = c.newPkey;
                }
            }
        }
        // SAFETY: the CMP context; the status; what the callback gave (owned here).
        msg = unsafe {
            certrep_new(
                ctx,
                bodytype,
                cert_req_id,
                si,
                cert_out,
                key_out,
                ptr::null(),
                chain_out.cast(),
                ca_pubs.cast(),
                unprotected,
            )
        };
        // When OSSL_CRMF_POPO_KEYENC is supported, the encryption recipient will be needed.
        if msg.is_null() {
            raise(CMP_R_ERROR_CREATING_CERTREP, F);
        }
    }
    // SAFETY: made here or by the callback, each freed once.
    unsafe { OSSL_CMP_PKISI_free(si) };
    // SAFETY: as above.
    unsafe { X509_free(cert_out) };
    // SAFETY: the CMP context; clears (and frees) its new key.
    unsafe { OSSL_CMP_CTX_set0_newPkey(ctx, 0, ptr::null_mut()) };
    // SAFETY: as above.
    unsafe { OSSL_STACK_OF_X509_free(chain_out) };
    // SAFETY: as above.
    unsafe { OSSL_STACK_OF_X509_free(ca_pubs) };
    msg
}

/// `process_rr`: the rp answering the only revocation request of an rr, or NULL.
///
/// # Safety
/// `srv_ctx` is a live server context with an rr callback; `req` a live rr.
unsafe fn process_rr(
    srv_ctx: *mut OSSL_CMP_SRV_CTX,
    req: *const OSSL_CMP_MSG,
) -> *mut OSSL_CMP_MSG {
    const F: &str = "process_rr";
    // SAFETY: the caller's guarantee.
    let (ctx, cb, unprotected) = match unsafe { srv(srv_ctx) } {
        Some(s) => (s.ctx, s.process_rr, s.sendUnprotectedErrors),
        None => return ptr::null_mut(),
    };
    if ctx.is_null() || req.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the request.
    let rr = unsafe { body_value(req) }.cast::<rustyssl_abi::OPENSSL_STACK>();
    // SAFETY: the body's list, or NULL.
    if unsafe { OPENSSL_sk_num(rr) } != 1 {
        raise(CMP_R_MULTIPLE_REQUESTS_NOT_SUPPORTED, F);
        return ptr::null_mut();
    }
    // SAFETY: index 0 of a one-element list.
    let details = unsafe { OPENSSL_sk_value(rr, 0) }.cast::<RevDetails>();
    // SAFETY: the element, or NULL.
    let Some(details) = (unsafe { details.as_ref() }) else {
        raise(CMP_R_ERROR_PROCESSING_MESSAGE, F);
        return ptr::null_mut();
    };
    let tmpl = details.certDetails;
    // SAFETY: the template, or NULL.
    let issuer = unsafe { OSSL_CRMF_CERTTEMPLATE_get0_issuer(tmpl) };
    // SAFETY: as above.
    let serial = unsafe { OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(tmpl) };
    let mut cert_id: *mut OSSL_CRMF_CERTID = ptr::null_mut();
    if !issuer.is_null() && !serial.is_null() {
        // SAFETY: the template's name and number.
        cert_id = unsafe { OSSL_CRMF_CERTID_gen(issuer, serial) };
        if cert_id.is_null() {
            return ptr::null_mut();
        }
    }
    let mut msg = ptr::null_mut();
    let si = match cb {
        // SAFETY: the application's callback; no borrow held.
        Some(cb) => unsafe { cb(srv_ctx, req, issuer, serial) },
        None => ptr::null_mut(),
    };
    if !si.is_null() {
        // SAFETY: the CMP context; the status; the CertId or NULL.
        msg = unsafe { rp_new(ctx, si, cert_id, unprotected) };
        if msg.is_null() {
            raise(CMP_R_ERROR_CREATING_RR, F);
        }
    }
    // SAFETY: made here, freed once.
    unsafe { OSSL_CRMF_CERTID_free(cert_id) };
    // SAFETY: the callback's status, or NULL.
    unsafe { OSSL_CMP_PKISI_free(si) };
    msg
}

/// `OSSL_CMP_ITAV_free` as a stack's free function.
unsafe extern "C" fn itav_free(p: *mut c_void) {
    // SAFETY: an ITAV of the list.
    unsafe { OSSL_CMP_ITAV_free(p.cast()) };
}

/// `process_genm`: the genp of what the application answers to a genm, or NULL.
///
/// # Safety
/// `srv_ctx` is a live server context with a genm callback; `req` a live genm.
unsafe fn process_genm(
    srv_ctx: *mut OSSL_CMP_SRV_CTX,
    req: *const OSSL_CMP_MSG,
) -> *mut OSSL_CMP_MSG {
    // SAFETY: the caller's guarantee.
    let (ctx, cb) = match unsafe { srv(srv_ctx) } {
        Some(s) => (s.ctx, s.process_genm),
        None => return ptr::null_mut(),
    };
    let Some(cb) = cb.filter(|_| !ctx.is_null() && !req.is_null()) else {
        return ptr::null_mut();
    };
    // SAFETY: the request.
    let genm = unsafe { body_value(req) }.cast::<stack_st_OSSL_CMP_ITAV>();
    let mut itavs: *mut stack_st_OSSL_CMP_ITAV = ptr::null_mut();
    // SAFETY: the application's callback; the room for its answer; no borrow held.
    if unsafe { cb(srv_ctx, req, genm, &raw mut itavs) } == 0 {
        return ptr::null_mut();
    }
    // SAFETY: the CMP context; the answer, or NULL.
    let msg = unsafe { genp_new(ctx, itavs.cast()) };
    // SAFETY: the answer, freed once.
    unsafe { OPENSSL_sk_pop_free(itavs.cast(), Some(itav_free)) };
    msg
}

/// `process_error`: the pkiconf acknowledging an error message, after the application has seen
/// it; or NULL.
///
/// # Safety
/// `srv_ctx` is a live server context with an error callback; `req` a live error message.
unsafe fn process_error(
    srv_ctx: *mut OSSL_CMP_SRV_CTX,
    req: *const OSSL_CMP_MSG,
) -> *mut OSSL_CMP_MSG {
    // SAFETY: the caller's guarantee.
    let (ctx, cb) = match unsafe { srv(srv_ctx) } {
        Some(s) => (s.ctx, s.process_error),
        None => return ptr::null_mut(),
    };
    let Some(cb) = cb.filter(|_| !ctx.is_null() && !req.is_null()) else {
        return ptr::null_mut();
    };
    // SAFETY: the request.
    let content = unsafe { body_value(req) }.cast::<ErrorMsgContent>();
    // SAFETY: the error body (OpenSSL dereferences it unchecked; a decoded error has one).
    let Some(e) = (unsafe { content.as_ref() }) else {
        return ptr::null_mut();
    };
    let (si, code, details) = (e.pKIStatusInfo, e.errorCode, e.errorDetails);
    // SAFETY: the application's callback with the error's parts; no borrow held.
    unsafe { cb(srv_ctx, req, si.cast(), code.cast_const(), details.cast()) };
    // SAFETY: the CMP context.
    let msg = unsafe { pkiconf_new(ctx) };
    if msg.is_null() {
        raise(CMP_R_ERROR_CREATING_PKICONF, "process_error");
    }
    msg
}

/// `process_certConf`: the pkiconf acknowledging a certConf, or NULL.
///
/// # Safety
/// `srv_ctx` is a live server context with a certConf callback; `req` a live certConf.
unsafe fn process_certConf(
    srv_ctx: *mut OSSL_CMP_SRV_CTX,
    req: *const OSSL_CMP_MSG,
) -> *mut OSSL_CMP_MSG {
    const F: &str = "process_certConf";
    // SAFETY: the caller's guarantee.
    let (ctx, cb, srv_id) = match unsafe { srv(srv_ctx) } {
        Some(s) => (s.ctx, s.process_certConf, s.certReqId),
        None => return ptr::null_mut(),
    };
    if ctx.is_null() || req.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the request.
    let ccc = unsafe { body_value(req) }.cast::<rustyssl_abi::OPENSSL_STACK>();
    // SAFETY: the body's list, or NULL.
    let num = unsafe { OPENSSL_sk_num(ccc) };
    // SAFETY: the CMP context.
    let implicit = unsafe { OSSL_CMP_CTX_get_option(ctx, OSSL_CMP_OPT_IMPLICIT_CONFIRM) };
    // SAFETY: as above, borrowed for this statement.
    let status = unsafe { ctx_of(ctx) }.map_or(OSSL_CMP_PKISTATUS_unspecified, |c| c.status);
    if implicit == 1 || status != OSSL_CMP_PKISTATUS_trans {
        raise(CMP_R_ERROR_UNEXPECTED_CERTCONF, F);
        return ptr::null_mut();
    }
    let mut cs: *mut CertStatus = ptr::null_mut();
    if num == 0 {
        // SAFETY: the CMP context.
        unsafe {
            print_log(
                OSSL_CMP_LOG_ERR,
                ctx,
                c"process_certConf",
                "certificate rejected by client",
            )
        };
    } else {
        if num > 1 {
            // SAFETY: as above.
            unsafe {
                print_log(
                    OSSL_CMP_LOG_WARNING,
                    ctx,
                    c"process_certConf",
                    "All CertStatus but the first will be ignored",
                )
            };
        }
        // SAFETY: index 0 of a non-empty list.
        cs = unsafe { OPENSSL_sk_value(ccc, 0) }.cast();
    }
    // SAFETY: the list's first status, or NULL.
    if let Some(cs) = unsafe { cs.as_ref() } {
        let (id, hash, si) = (cs.certReqId, cs.certHash, cs.statusInfo);
        // SAFETY: its number.
        let cert_req_id = unsafe { asn1_get_int(id) };
        if cert_req_id != srv_id {
            raise(CMP_R_BAD_REQUEST_ID, F);
            return ptr::null_mut();
        }
        let Some(cb) = cb else {
            return ptr::null_mut();
        };
        // SAFETY: the application's callback with the status's parts; no borrow held.
        if unsafe { cb(srv_ctx, req, cert_req_id, hash, si.cast()) } == 0 {
            // The reason may be CMP_R_CERTHASH_UNMATCHED.
            return ptr::null_mut();
        }
        if !si.is_null() {
            // SAFETY: the status.
            let pki_status = unsafe { pkisi_get_status(si.cast()) };
            if pki_status != OSSL_CMP_PKISTATUS_accepted {
                let s = PKIStatus_to_string(pki_status);
                let text = if s.is_null() {
                    "certificate rejected by client without PKIStatus".to_owned()
                } else {
                    // SAFETY: a static NUL-terminated name.
                    let name = unsafe { CStr::from_ptr(s) }.to_string_lossy();
                    format!("certificate rejected by client with {name}")
                };
                // SAFETY: the CMP context.
                unsafe { print_log(OSSL_CMP_LOG_INFO, ctx, c"process_certConf", &text) };
            }
        }
    }
    // SAFETY: the CMP context.
    let msg = unsafe { pkiconf_new(ctx) };
    if msg.is_null() {
        raise(CMP_R_ERROR_CREATING_PKICONF, F);
    }
    msg
}

/// `process_non_polling_request`: the response to anything but a pollReq (handled apart, so
/// as not to recurse), or NULL.
///
/// # Safety
/// `srv_ctx` is a live server context; `req` a live message.
unsafe fn process_non_polling_request(
    srv_ctx: *mut OSSL_CMP_SRV_CTX,
    req: *const OSSL_CMP_MSG,
) -> *mut OSSL_CMP_MSG {
    const F: &str = "process_non_polling_request";
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { srv(srv_ctx) }) else {
        return ptr::null_mut();
    };
    let (ctx, has_cr, has_rr, has_genm, has_error, has_cc) = (
        s.ctx,
        s.process_cert_request.is_some(),
        s.process_rr.is_some(),
        s.process_genm.is_some(),
        s.process_error.is_some(),
        s.process_certConf.is_some(),
    );
    // SAFETY: the request, or NULL.
    let has_body = unsafe { of::<Msg, _>(req) }.is_some_and(|m| !m.body.is_null());
    if ctx.is_null() || !has_body {
        return ptr::null_mut();
    }
    // SAFETY: the request.
    let (handler, present): (
        unsafe fn(*mut OSSL_CMP_SRV_CTX, *const OSSL_CMP_MSG) -> *mut OSSL_CMP_MSG,
        bool,
    ) = match unsafe { OSSL_CMP_MSG_get_bodytype(req) } {
        PKIBODY_IR | PKIBODY_CR | PKIBODY_P10CR | PKIBODY_KUR => (process_cert_request, has_cr),
        PKIBODY_RR => (process_rr, has_rr),
        PKIBODY_GENM => (process_genm, has_genm),
        PKIBODY_ERROR => (process_error, has_error),
        PKIBODY_CERTCONF => (process_certConf, has_cc),
        PKIBODY_POLLREQ => {
            raise(CMP_R_UNEXPECTED_PKIBODY, F);
            return ptr::null_mut();
        }
        _ => {
            raise(CMP_R_UNSUPPORTED_PKIBODY, F);
            return ptr::null_mut();
        }
    };
    if !present {
        raise(CMP_R_UNSUPPORTED_PKIBODY, F);
        return ptr::null_mut();
    }
    // SAFETY: the caller's guarantee; the handler's callback is set.
    unsafe { handler(srv_ctx, req) }
}

/// `process_pollReq`: the original request's response once the application has it, else a
/// pollRep; or NULL.
///
/// # Safety
/// `srv_ctx` is a live server context with a pollReq callback; `req` a live pollReq.
unsafe fn process_pollReq(
    srv_ctx: *mut OSSL_CMP_SRV_CTX,
    req: *const OSSL_CMP_MSG,
) -> *mut OSSL_CMP_MSG {
    const F: &str = "process_pollReq";
    // SAFETY: the caller's guarantee.
    let (ctx, cb, polling) = match unsafe { srv(srv_ctx) } {
        Some(s) => (s.ctx, s.process_pollReq, s.polling),
        None => return ptr::null_mut(),
    };
    if ctx.is_null() || req.is_null() {
        return ptr::null_mut();
    }
    if polling == 0 {
        raise(CMP_R_UNEXPECTED_PKIBODY, F);
        return ptr::null_mut();
    }
    // SAFETY: the request.
    let prc = unsafe { body_value(req) }.cast::<rustyssl_abi::OPENSSL_STACK>();
    // SAFETY: the body's list, or NULL.
    if unsafe { OPENSSL_sk_num(prc) } != 1 {
        raise(CMP_R_MULTIPLE_REQUESTS_NOT_SUPPORTED, F);
        return ptr::null_mut();
    }
    // SAFETY: index 0 of a one-element list.
    let pr = unsafe { OPENSSL_sk_value(prc, 0) }.cast::<PollReq>();
    // SAFETY: the element (OpenSSL dereferences it unchecked; a decoded list has no NULL).
    let Some(pr) = (unsafe { pr.as_ref() }) else {
        return ptr::null_mut();
    };
    // SAFETY: its number.
    let cert_req_id = unsafe { asn1_get_int(pr.certReqId) };
    let Some(cb) = cb else {
        return ptr::null_mut();
    };
    let mut orig_req: *mut OSSL_CMP_MSG = ptr::null_mut();
    let mut check_after: i64 = 0;
    // SAFETY: the application's callback; rooms for its outputs; no borrow held.
    if unsafe {
        cb(
            srv_ctx,
            req,
            cert_req_id,
            &raw mut orig_req,
            &raw mut check_after,
        )
    } == 0
    {
        return ptr::null_mut();
    }
    if orig_req.is_null() {
        // SAFETY: the CMP context.
        let msg = unsafe { pollRep_new(ctx, cert_req_id, check_after) };
        if msg.is_null() {
            raise(CMP_R_ERROR_CREATING_POLLREP, F);
        }
        msg
    } else {
        // SAFETY: as above.
        if let Some(s) = unsafe { srv(srv_ctx) } {
            s.polling = 0;
        }
        // SAFETY: the server context; the callback's original request.
        let msg = unsafe { process_non_polling_request(srv_ctx, orig_req) };
        // SAFETY: the callback's request, ours to free.
        unsafe { OSSL_CMP_MSG_free(orig_req) };
        msg
    }
}

/// `unprotected_exception`: whether a request's missing or invalid protection is accepted: 1,
/// 0 for rejection, -1 on an internal error.
///
/// # Safety
/// `ctx` is NULL or a live context; `req` NULL or a live message.
unsafe fn unprotected_exception(
    ctx: *const OSSL_CMP_CTX,
    req: *const OSSL_CMP_MSG,
    invalid_protection: c_int,
    accept_unprotected_requests: c_int,
) -> c_int {
    if ctx.is_null() || req.is_null() {
        return -1;
    }
    if accept_unprotected_requests != 0 {
        let what = if invalid_protection != 0 {
            "invalid"
        } else {
            "missing"
        };
        // SAFETY: the caller's context.
        unsafe {
            print_log(
                OSSL_CMP_LOG_WARNING,
                ctx,
                c"unprotected_exception",
                &format!("ignoring {what} protection of request message"),
            )
        };
        return 1;
    }
    // SAFETY: the caller's message.
    if unsafe { OSSL_CMP_MSG_get_bodytype(req) } == PKIBODY_ERROR
        // SAFETY: the caller's context.
        && unsafe { OSSL_CMP_CTX_get_option(ctx, OSSL_CMP_OPT_UNPROTECTED_ERRORS) } == 1
    {
        // SAFETY: as above.
        unsafe {
            print_log(
                OSSL_CMP_LOG_WARNING,
                ctx,
                c"unprotected_exception",
                "ignoring missing protection of error message",
            )
        };
        return 1;
    }
    0
}

/// An octet string in hex with colons (`i2s_ASN1_OCTET_STRING`), or "(null)".
///
/// # Safety
/// `s` is NULL or a live octet string.
unsafe fn hex_of(s: *const ASN1_OCTET_STRING) -> String {
    // SAFETY: the caller's guarantee.
    let p = unsafe { i2s_ASN1_OCTET_STRING(ptr::null_mut(), s) };
    if p.is_null() {
        return "(null)".to_owned();
    }
    // SAFETY: a NUL-terminated string from CRYPTO_malloc.
    let t = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
    // SAFETY: as above, freed once.
    unsafe { mem::release(p.cast()) };
    t
}

/// `assuming_new_transaction`: whether the request starts a new transaction (none open, another
/// transaction ID, or a body that starts one).
///
/// # Safety
/// `ctx` is a live context; `req` a live message.
unsafe fn assuming_new_transaction(ctx: *mut OSSL_CMP_CTX, req: *const OSSL_CMP_MSG) -> bool {
    // SAFETY: the caller's message.
    let body_type = unsafe { OSSL_CMP_MSG_get_bodytype(req) };
    // SAFETY: the caller's context, borrowed for this statement.
    let current = unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.transactionID);
    if current.is_null() {
        return true;
    }
    // SAFETY: the message's header.
    let hdr = unsafe { OSSL_CMP_MSG_get0_header(req) };
    // SAFETY: the header, or NULL.
    let tid = unsafe { OSSL_CMP_HDR_get0_transactionID(hdr) };
    // SAFETY: two live octet strings.
    if !tid.is_null() && unsafe { ASN1_OCTET_STRING_cmp(tid, current) } != 0 {
        // SAFETY: as above.
        let ctx_str = unsafe { hex_of(current) };
        // SAFETY: as above.
        let tid_str = unsafe { hex_of(tid) };
        let text = format!(
            "Assuming that last transaction with ID={ctx_str} got aborted, new ID={tid_str}"
        );
        // SAFETY: the context.
        unsafe {
            print_log(
                OSSL_CMP_LOG_WARNING,
                ctx,
                c"assuming_new_transaction",
                &text,
            )
        };
        return true;
    }
    match body_type {
        PKIBODY_IR | PKIBODY_CR | PKIBODY_P10CR | PKIBODY_KUR | PKIBODY_RR | PKIBODY_GENM => {
            let text = format!(
                "Assuming new transaction due to received body type {}",
                body_name(body_type)
            );
            // SAFETY: the context.
            unsafe {
                print_log(
                    OSSL_CMP_LOG_WARNING,
                    ctx,
                    c"assuming_new_transaction",
                    &text,
                )
            };
            true
        }
        _ => false,
    }
}

/// `transaction_reinit`: prepares for the next transaction: 1, or 0 if a step failed.
///
/// # Safety
/// `srv_ctx` is a live server context with a CMP context.
unsafe fn transaction_reinit(srv_ctx: *mut OSSL_CMP_SRV_CTX) -> c_int {
    // SAFETY: the caller's guarantee.
    let (ctx, clean) = match unsafe { srv(srv_ctx) } {
        Some(s) => {
            s.certReqId = CERTREQID_INVALID;
            s.polling = 0;
            (s.ctx, s.clean_transaction)
        }
        None => return 0,
    };
    // SAFETY: the CMP context, borrowed for this statement.
    let tid = match unsafe { ctx_of(ctx) } {
        Some(c) => {
            // The transaction is closed.
            c.status = OSSL_CMP_PKISTATUS_unspecified;
            c.transactionID
        }
        None => return 0,
    };
    let mut ret = 1;
    if let Some(clean) = clean {
        // SAFETY: the application's callback; no borrow held.
        ret = unsafe { clean(srv_ctx, tid) };
    }
    // SAFETY: the CMP context.
    if unsafe { OSSL_CMP_CTX_set1_transactionID(ctx, ptr::null()) } == 0 {
        ret = 0;
    }
    // SAFETY: as above.
    if unsafe { OSSL_CMP_CTX_set1_senderNonce(ctx, ptr::null()) } == 0 {
        ret = 0;
    }
    ret
}

ffi_export! {
    /// The response to a request (an error message when it can't be processed), with the
    /// transaction's state updated; NULL on an internal error.
    ///
    /// # Safety
    /// `srv_ctx` is NULL or a live server context; `req` NULL or a live message.
    pub unsafe extern "C" fn OSSL_CMP_SRV_process_request(srv_ctx: *mut OSSL_CMP_SRV_CTX, req: *const OSSL_CMP_MSG) -> *mut OSSL_CMP_MSG
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        unsafe { process_request(srv_ctx, req) }
    }
}

/// [`OSSL_CMP_SRV_process_request`]'s work.
///
/// # Safety
/// As for it.
unsafe fn process_request(
    srv_ctx: *mut OSSL_CMP_SRV_CTX,
    req: *const OSSL_CMP_MSG,
) -> *mut OSSL_CMP_MSG {
    const F: &str = "OSSL_CMP_SRV_process_request";
    // SAFETY: the caller's guarantee.
    let ctx = unsafe { srv(srv_ctx) }.map_or(ptr::null_mut(), |s| s.ctx);
    // SAFETY: as above.
    let has_body = unsafe { of::<Msg, _>(req) }.is_some_and(|m| !m.body.is_null());
    let hdr: *mut PkiHeader = if ctx.is_null() || !has_body {
        ptr::null_mut()
    } else {
        // SAFETY: the request.
        unsafe { OSSL_CMP_MSG_get0_header(req) }.cast()
    };
    if hdr.is_null() {
        raise(CMP_R_NULL_ARGUMENT, F);
        return ptr::null_mut();
    }
    // SAFETY: the CMP context, borrowed for this statement.
    let backup_secret = unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.secretValue);
    // SAFETY: the request.
    let req_type = unsafe { OSSL_CMP_MSG_get_bodytype(req) };
    // SAFETY: the CMP context.
    unsafe {
        print_log(
            OSSL_CMP_LOG_DEBUG,
            ctx,
            c"OSSL_CMP_SRV_process_request",
            &format!("received {}", body_name(req_type)),
        )
    };

    let mut req_verified = 0;
    let mut rsp: *mut OSSL_CMP_MSG = ptr::null_mut();
    // SAFETY: the request's header, not NULL.
    let h = unsafe { &*hdr };
    let (sender, h_tid, h_nonce) = (h.sender, h.transactionID, h.senderNonce);
    'err: {
        // Done before validating, to be able to send an error message as far as possible.
        // SAFETY: the header's sender (a decoded or made header has one).
        let Some(sender) = (unsafe { sender.as_ref() }).filter(|g| g.type_ == GEN_DIRNAME) else {
            raise(CMP_R_SENDER_GENERALNAME_TYPE_NOT_SUPPORTED, F);
            break 'err;
        };
        // SAFETY: a directory name's union member.
        let dn = unsafe { sender.d.directoryName };
        // SAFETY: the CMP context; the name.
        if unsafe { OSSL_CMP_CTX_set1_recipient(ctx, dn) } == 0 {
            break 'err;
        }
        // SAFETY: the CMP context; the request.
        if unsafe { assuming_new_transaction(ctx, req) } {
            // A new transaction: the clean-up callback gets a NULL transaction ID, as documented.
            // SAFETY: the CMP context.
            unsafe { OSSL_CMP_CTX_set1_transactionID(ctx, ptr::null()) };
            // SAFETY: the server context.
            if unsafe { transaction_reinit(srv_ctx) } == 0 {
                raise(CMP_R_ERROR_PROCESSING_MESSAGE, F);
                break 'err;
            }
        } else {
            // The transaction ID should already be set.
            // SAFETY: the CMP context, borrowed for this statement.
            if unsafe { ctx_of(ctx) }.is_some_and(|c| c.transactionID.is_null()) {
                raise(CMP_R_UNEXPECTED_PKIBODY, F);
                break 'err;
            }
            // SAFETY: the server context.
            let polling = unsafe { srv(srv_ctx) }.is_some_and(|s| s.polling != 0);
            if polling && req_type != PKIBODY_POLLREQ && req_type != PKIBODY_ERROR {
                raise(CMP_R_EXPECTED_POLLREQ, F);
                break 'err;
            }
        }
        // SAFETY: the server context.
        let accept = unsafe { srv(srv_ctx) }.map_or(0, |s| s.acceptUnprotected);
        // SAFETY: the CMP context; the request.
        req_verified = unsafe { msg_check_update(ctx, req, Some(unprotected_exception), accept) };
        // SAFETY: the header.
        let nid = unsafe { hdr_get_protection_nid(hdr.cast()) };
        // SAFETY: the CMP context, borrowed for this statement.
        if let Some(c) = unsafe { ctx_of(ctx) }
            && !c.secretValue.is_null()
            && !c.pkey.is_null()
            && nid != NID_id_PasswordBasedMAC
        {
            // Protect the response with a signature.
            c.secretValue = ptr::null_mut();
        }
        if req_verified == 0 {
            break 'err;
        }
        if req_type == PKIBODY_POLLREQ {
            // SAFETY: the server context.
            if unsafe { srv(srv_ctx) }.is_some_and(|s| s.process_pollReq.is_none()) {
                raise(CMP_R_UNSUPPORTED_PKIBODY, F);
            } else {
                // SAFETY: the server context; the request.
                rsp = unsafe { process_pollReq(srv_ctx, req) };
            }
        } else {
            // SAFETY: the server context.
            if unsafe { srv(srv_ctx) }.is_some_and(|s| s.delayed_delivery.is_some()) {
                // SAFETY: the server context; the request.
                rsp = unsafe { delayed_delivery(srv_ctx, req) };
                if !rsp.is_null() {
                    break 'err;
                }
            }
            // SAFETY: the server context; the request.
            rsp = unsafe { process_non_polling_request(srv_ctx, req) };
        }
    }

    if rsp.is_null() {
        // On an error, try to answer with a CMP error message.
        let mut data: *const c_char = ptr::null();
        let mut flags = 0;
        // SAFETY: rooms for the data and flags.
        let e = unsafe { ERR_peek_error_data(&raw mut data, &raw mut flags) };
        // The failure information isn't very specific.
        let fail_info = 1 << OSSL_CMP_PKIFAILUREINFO_badRequest;
        if req_verified == 0 {
            // ossl_cmp_msg_check_update didn't succeed, which would have set the transaction ID
            // and the recipient nonce: try to, ignoring any further error.
            // SAFETY: the CMP context, borrowed for this statement.
            if unsafe { ctx_of(ctx) }.is_some_and(|c| c.transactionID.is_null()) {
                // SAFETY: the CMP context; the header's ID, or NULL.
                unsafe { OSSL_CMP_CTX_set1_transactionID(ctx, h_tid) };
            }
            // SAFETY: the CMP context; the header's nonce, or NULL.
            unsafe { ctx_set1_recipNonce(ctx, h_nonce) };
        }
        // SAFETY: the error's data, a C string if non-NULL.
        if flags & ERR_TXT_STRING == 0 || data.is_null() || unsafe { *data } == 0 {
            data = ptr::null();
        }
        // SAFETY: no preconditions.
        let reason = unsafe { ERR_reason_error_string(e) };
        // SAFETY: a static string or NULL.
        let si =
            unsafe { OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_rejection, fail_info, reason) };
        if !si.is_null() {
            // SAFETY: the server context.
            let unprotected = unsafe { srv(srv_ctx) }.map_or(0, |s| s.sendUnprotectedErrors);
            // The whole error code (an unsigned long) becomes the errorCode, as in OpenSSL.
            let code = i64::try_from(e).unwrap_or(i64::MAX);
            // SAFETY: the CMP context; the status; the error's data or NULL.
            rsp = unsafe { error_new(ctx, si, code, data, unprotected) };
            // SAFETY: made here.
            unsafe { OSSL_CMP_PKISI_free(si) };
        }
    }
    // SAFETY: the CMP context.
    unsafe { OSSL_CMP_CTX_print_errors(ctx) };
    // SAFETY: the CMP context, borrowed for this statement.
    if let Some(c) = unsafe { ctx_of(ctx) } {
        c.secretValue = backup_secret;
    }

    let rsp_type = if rsp.is_null() {
        PKIBODY_ERROR
    } else {
        // SAFETY: the response made here.
        unsafe { OSSL_CMP_MSG_get_bodytype(rsp) }
    };
    if rsp.is_null() {
        // SAFETY: the CMP context.
        unsafe {
            print_log(
                OSSL_CMP_LOG_ERR,
                ctx,
                c"OSSL_CMP_SRV_process_request",
                "cannot send proper CMP response",
            )
        };
    } else {
        // SAFETY: as above.
        unsafe {
            print_log(
                OSSL_CMP_LOG_DEBUG,
                ctx,
                c"OSSL_CMP_SRV_process_request",
                &format!("sending {}", body_name(rsp_type)),
            )
        };
    }

    // Whether the transaction stays open.
    // SAFETY: the CMP context, borrowed for this statement.
    if let Some(c) = unsafe { ctx_of(ctx) } {
        c.status = OSSL_CMP_PKISTATUS_trans;
    }
    // An ip/cp/kup closes it only with implicit confirmation; an error unless it's "waiting".
    let close = match rsp_type {
        PKIBODY_IP | PKIBODY_CP | PKIBODY_KUP => {
            // SAFETY: the CMP context.
            (unsafe { OSSL_CMP_CTX_get_option(ctx, OSSL_CMP_OPT_IMPLICIT_CONFIRM) }) != 0
                // SAFETY: the response made here.
                && !(!rsp.is_null() && unsafe { is_error_with_waiting(rsp) } != 0)
        }
        PKIBODY_ERROR => {
            // SAFETY: the response made here.
            !(!rsp.is_null() && unsafe { is_error_with_waiting(rsp) } != 0)
        }
        PKIBODY_RP | PKIBODY_PKICONF | PKIBODY_GENP => true,
        _ => false,
    };
    if close {
        // Ready for the next transaction, ignoring any error here.
        // SAFETY: the server context.
        unsafe { transaction_reinit(srv_ctx) };
    }
    rsp
}

ffi_export! {
    /// A server as a client's transfer callback: the server context is the client context's
    /// transfer callback argument. The response, or NULL with an error.
    ///
    /// # Safety
    /// `client_ctx` is NULL or a live context whose transfer argument is NULL or a live server
    /// context; `req` NULL or a live message.
    pub unsafe extern "C" fn OSSL_CMP_CTX_server_perform(client_ctx: *mut OSSL_CMP_CTX, req: *const OSSL_CMP_MSG) -> *mut OSSL_CMP_MSG
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        if client_ctx.is_null() || req.is_null() {
            raise(CMP_R_NULL_ARGUMENT, "OSSL_CMP_CTX_server_perform");
            return ptr::null_mut();
        }
        // SAFETY: the caller's context.
        let srv_ctx = unsafe { OSSL_CMP_CTX_get_transfer_cb_arg(client_ctx) }.cast::<OSSL_CMP_SRV_CTX>();
        if srv_ctx.is_null() {
            raise(CMP_R_TRANSFER_ERROR, "OSSL_CMP_CTX_server_perform");
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        unsafe { process_request(srv_ctx, req) }
    }
}
