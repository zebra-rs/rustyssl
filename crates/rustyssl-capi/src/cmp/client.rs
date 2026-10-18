//! The CMP client (`cmp_client.c`): a request sent and its response checked, polling after a
//! `waiting` status, certificate confirmation and error exchanges, and the transactions:
//! certificate requests (ir, cr, kur, p10cr), revocation, and general messages.
//!
//! OpenSSL's `ossl_assert` is a plain check in a release build: a failed one returns the
//! failure value without raising an error, as here.

use core::ffi::{CStr, c_char, c_int, c_ulong, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_STRING, CMP_R_BAD_CHECKAFTER_IN_POLLREP, CMP_R_BAD_REQUEST_ID,
    CMP_R_CERTIFICATE_NOT_ACCEPTED, CMP_R_CERTIFICATE_NOT_FOUND, CMP_R_CHECKAFTER_OUT_OF_RANGE,
    CMP_R_ENCOUNTERED_KEYUPDATEWARNING, CMP_R_ENCOUNTERED_WAITING, CMP_R_INVALID_ARGS,
    CMP_R_MISSING_CERTID, CMP_R_MISSING_REFERENCE_CERT, CMP_R_MULTIPLE_RESPONSES_NOT_SUPPORTED,
    CMP_R_NULL_ARGUMENT, CMP_R_POLLING_FAILED, CMP_R_RECEIVED_ERROR,
    CMP_R_REQUEST_REJECTED_BY_SERVER, CMP_R_TOTAL_TIMEOUT, CMP_R_TRANSFER_ERROR,
    CMP_R_UNEXPECTED_PKIBODY, CMP_R_UNEXPECTED_PKISTATUS, CMP_R_UNKNOWN_PKISTATUS,
    CMP_R_WRONG_CERTID_IN_RP, CMP_R_WRONG_RP_COMPONENT_COUNT, CMP_R_WRONG_SERIAL_IN_RP,
    ERR_LIB_CMP, OSSL_CMP_CTX, OSSL_CMP_CTX_FAILINFO_badRequest, OSSL_CMP_LOG_DEBUG,
    OSSL_CMP_LOG_ERR, OSSL_CMP_LOG_INFO, OSSL_CMP_LOG_WARNING, OSSL_CMP_MSG,
    OSSL_CMP_PKIFAILUREINFO_incorrectData, OSSL_CMP_PKISI_BUFLEN, OSSL_CMP_PKISTATUS_accepted,
    OSSL_CMP_PKISTATUS_checking_response, OSSL_CMP_PKISTATUS_grantedWithMods,
    OSSL_CMP_PKISTATUS_keyUpdateWarning, OSSL_CMP_PKISTATUS_rejected_by_client,
    OSSL_CMP_PKISTATUS_rejection, OSSL_CMP_PKISTATUS_request,
    OSSL_CMP_PKISTATUS_revocationNotification, OSSL_CMP_PKISTATUS_revocationWarning,
    OSSL_CMP_PKISTATUS_trans, OSSL_CMP_PKISTATUS_waiting, OSSL_CMP_severity, OSSL_CRMF_MSG, X509,
    X509_ADD_FLAG_NO_DUP, X509_ADD_FLAG_NO_SS, X509_ADD_FLAG_UP_REF, X509_STORE,
    X509_V_FLAG_NO_CHECK_TIME, X509_V_FLAG_PARTIAL_CHAIN, X509_V_FLAG_POLICY_CHECK,
    X509_V_FLAG_USE_CHECK_TIME, stack_st_X509,
};

use super::asn::{
    CERTREQID, CERTREQID_NONE, CertRepMessage, CertResponse, EXPECTED_RESP_TIME, ErrorMsgContent,
    Msg, OSSL_CMP_PKISI_free, PKIBODY_CP, PKIBODY_ERROR, PKIBODY_GENP, PKIBODY_IP, PKIBODY_KUP,
    PKIBODY_KUR, PKIBODY_P10CR, PKIBODY_PKICONF, PKIBODY_POLLREP, PKIBODY_RP, PkiSi, PollRep,
    REVREQSID, RevDetails, RevRepContent, Stack, asn1_get_int,
};
use super::ctx::{
    Ctx, OSSL_CMP_CTX_get1_extraCertsIn, OSSL_CMP_CTX_print_errors, ctx_get0_newPubkey,
    ctx_set0_newCert, ctx_set0_statusString, ctx_set1_caPubs, ctx_set1_extraCertsIn,
    ctx_set1_first_senderNonce, ctx_set1_newChain, print_log,
};
use super::hdr::hdr_has_implicitConfirm;
use super::http::OSSL_CMP_MSG_http_perform;
use super::msg::{
    OSSL_CMP_MSG_free, OSSL_CMP_MSG_get_bodytype, bodytype_to_string, certConf_new,
    certrepmessage_get0_certresponse, certreq_new, certresponse_get1_cert, error_new, genm_new,
    is_error_with_waiting, pollReq_new, pollrepcontent_get0_pollrep, revrepcontent_get_CertId,
    revrepcontent_get_pkisi, rr_new,
};
use super::status::{
    OSSL_CMP_CTX_snprint_PKIStatus, OSSL_CMP_STATUSINFO_new, pkisi_get_pkifailureinfo,
    pkisi_get_status,
};
use super::vfy::msg_check_update;
use crate::asn1::integer::{ASN1_INTEGER_cmp, ASN1_INTEGER_get, ASN1_INTEGER_get_int64};
use crate::asn1::string::{ASN1_STRING_dup, ASN1_UTF8STRING_free};
use crate::crmf::msg::{
    OSSL_CRMF_CERTID_get0_issuer, OSSL_CRMF_CERTID_get0_serialNumber,
    OSSL_CRMF_CERTTEMPLATE_get0_issuer, OSSL_CRMF_CERTTEMPLATE_get0_serialNumber,
};
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;
use crate::ocsp::cl::add_cert_new;
use crate::sleep::OSSL_sleep;
use crate::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_shift,
    OPENSSL_sk_value,
};
use crate::x509::cert::{
    OSSL_STACK_OF_X509_free, X509_check_private_key, X509_free, X509_get_subject_name,
};
use crate::x509::ctx::{
    X509_STORE_CTX_free, X509_STORE_CTX_get0_chain, X509_STORE_CTX_get0_param, X509_STORE_CTX_init,
    X509_STORE_CTX_new_ex,
};
use crate::x509::name::{X509_NAME_cmp, X509_NAME_oneline};
use crate::x509::verify::{X509_build_chain, X509_verify_cert};
use crate::x509::vpm::X509_VERIFY_PARAM_clear_flags;

/// `OSSL_CMP_PKISI_BUFLEN`, the room OpenSSL formats a status into.
fn buflen() -> usize {
    usize::try_from(OSSL_CMP_PKISI_BUFLEN).unwrap_or(0)
}

/// `IS_CREP`: a certificate response (ip, cp, or kup).
fn is_crep(t: c_int) -> bool {
    t == PKIBODY_IP || t == PKIBODY_CP || t == PKIBODY_KUP
}

/// The seconds since the epoch (`time(NULL)`).
pub(crate) fn now() -> i64 {
    // SAFETY: NULL asks for the time only.
    unsafe { libc::time(ptr::null_mut()) }
}

/// A C string as OpenSSL's `BIO_snprintf` prints it with `%s`: `<NULL>` for NULL, otherwise its
/// text (invalid UTF-8 replaced).
///
/// # Safety
/// `p` is NULL or a NUL-terminated string.
pub(crate) unsafe fn text_of(p: *const c_char) -> String {
    if p.is_null() {
        return "<NULL>".to_owned();
    }
    // SAFETY: the caller's guarantee.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

/// `ossl_sk_ASN1_UTF8STRING2text`: the strings of the list joined by `sep`, or None if that is
/// longer than `max_len` (0: no limit). As OpenSSL copies with `strncpy` into a C string, the
/// text ends at the first NUL.
///
/// # Safety
/// `text` is NULL or a live list of strings.
pub(crate) unsafe fn utf8_text(text: *const Stack, sep: &[u8], max_len: usize) -> Option<Vec<u8>> {
    // SAFETY: the caller's guarantee (0 for NULL).
    let n = unsafe { OPENSSL_sk_num(text) };
    let mut length = 0usize;
    let mut out = Vec::new();
    for i in 0..n {
        // SAFETY: an index in range.
        let s: *const ASN1_STRING = unsafe { OPENSSL_sk_value(text, i) }.cast();
        if i > 0 {
            length = length.saturating_add(sep.len());
            out.extend_from_slice(sep);
        }
        // SAFETY: a string of the list, or NULL.
        let (len, data) = match unsafe { s.as_ref() } {
            Some(s) => (usize::try_from(s.length).unwrap_or(0), s.data),
            None => (0, ptr::null_mut()),
        };
        length = length.saturating_add(len);
        if max_len != 0 && length > max_len {
            return None;
        }
        if len > 0 && !data.is_null() {
            // SAFETY: the string's `len` octets.
            out.extend_from_slice(unsafe { core::slice::from_raw_parts(data, len) });
        }
    }
    if let Some(end) = out.iter().position(|&b| b == 0) {
        out.truncate(end);
    }
    Some(out)
}

/// Logs `msg` for the context at `level` on behalf of OpenSSL's function `func`.
///
/// # Safety
/// `ctx` is NULL or a live context.
#[track_caller]
unsafe fn log(level: OSSL_CMP_severity, ctx: *const OSSL_CMP_CTX, func: &CStr, msg: &str) {
    // SAFETY: the caller's guarantee.
    unsafe { print_log(level, ctx, func, msg) };
}

/// The value of a message's body, or NULL.
///
/// # Safety
/// `msg` is NULL or a live message.
unsafe fn body_value(msg: *const OSSL_CMP_MSG) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let Some(m) = (unsafe { msg.cast::<Msg>().as_ref() }) else {
        return ptr::null_mut();
    };
    // SAFETY: its body, or NULL.
    unsafe { m.body.as_ref() }.map_or(ptr::null_mut(), |b| b.value)
}

/// Appends the context's status, as `OSSL_CMP_CTX_snprint_PKIStatus` prints it, to the newest
/// error's data.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn add_status_data(ctx: *const OSSL_CMP_CTX) {
    let mut buf = vec![0 as c_char; buflen()];
    // SAFETY: the context; the room.
    let p = unsafe { OSSL_CMP_CTX_snprint_PKIStatus(ctx, buf.as_mut_ptr(), buf.len()) };
    if !p.is_null() {
        // SAFETY: the status written, NUL-terminated.
        let text = unsafe { CStr::from_ptr(p) };
        err::add_error_data([Some(text.to_bytes())]);
    }
}

/// Whether there's an exception configured (violating the standard) for a negative response
/// without protection or with invalid protection: 1 to accept it, 0 to reject it, -1 on an
/// internal error.
///
/// # Safety
/// `ctx` and `rep` are NULL or live.
unsafe fn unprotected_exception(
    ctx: *const OSSL_CMP_CTX,
    rep: *const OSSL_CMP_MSG,
    invalid_protection: c_int,
    _expected_type: c_int,
) -> c_int {
    // SAFETY: the caller's message, or NULL.
    let rcvd_type = unsafe { OSSL_CMP_MSG_get_bodytype(rep) };
    if ctx.is_null() || rep.is_null() {
        return -1;
    }
    let c: *const Ctx = ctx.cast();
    // SAFETY: the caller's context.
    if unsafe { (*c).unprotectedErrors } == 0 {
        return 0;
    }
    let mut msg_type: Option<&str> = None;
    if rcvd_type == PKIBODY_ERROR {
        msg_type = Some("error response");
    } else if rcvd_type == PKIBODY_RP {
        // SAFETY: the message's revocation response.
        let rrep: *mut RevRepContent = unsafe { body_value(rep) }.cast();
        // SAFETY: as above.
        let si = unsafe { revrepcontent_get_pkisi(rrep.cast(), REVREQSID) };
        if si.is_null() {
            return -1;
        }
        // SAFETY: a status of the response.
        if unsafe { pkisi_get_status(si.cast()) } == OSSL_CMP_PKISTATUS_rejection {
            msg_type = Some("revocation response message with rejection status");
        }
    } else if rcvd_type == PKIBODY_PKICONF {
        msg_type = Some("PKI Confirmation message");
    } else if is_crep(rcvd_type) {
        // SAFETY: the message's certificate response (the same for ip, cp, and kup).
        let crepmsg: *mut CertRepMessage = unsafe { body_value(rep) }.cast();
        // SAFETY: as above, or NULL.
        let crep: *mut CertResponse =
            unsafe { certrepmessage_get0_certresponse(crepmsg.cast(), CERTREQID_NONE) }.cast();
        // SAFETY: as above.
        let responses = unsafe { crepmsg.as_ref() }.map_or(ptr::null_mut(), |m| m.response);
        // SAFETY: the list of responses, or NULL.
        if unsafe { OPENSSL_sk_num(responses) } > 1 {
            return -1;
        }
        // SAFETY: the response, or NULL.
        let Some(crep) = (unsafe { crep.as_ref() }) else {
            return -1;
        };
        // SAFETY: its status.
        if unsafe { pkisi_get_status(crep.status.cast()) } == OSSL_CMP_PKISTATUS_rejection {
            msg_type = Some("CertRepMessage with rejection status");
        }
    }
    let Some(msg_type) = msg_type else {
        return 0;
    };
    let how = if invalid_protection != 0 {
        "invalid"
    } else {
        "missing"
    };
    // SAFETY: the caller's context.
    unsafe {
        log(
            OSSL_CMP_LOG_WARNING,
            ctx,
            c"unprotected_exception",
            &format!("ignoring {how} protection of {msg_type}"),
        )
    };
    1
}

/// Saves a PKIStatusInfo's status, failure info, and status strings in the context: 1, or 0.
///
/// # Safety
/// `ctx` and `si` are NULL or live.
unsafe fn save_statusInfo(ctx: *mut OSSL_CMP_CTX, si: *const PkiSi) -> c_int {
    if ctx.is_null() || si.is_null() {
        return 0;
    }
    let c: *mut Ctx = ctx.cast();
    // SAFETY: the caller's status info.
    let status = unsafe { pkisi_get_status(si.cast()) };
    // SAFETY: the caller's context.
    unsafe { (*c).status = status };
    if status < OSSL_CMP_PKISTATUS_accepted {
        return 0;
    }
    // SAFETY: as above.
    let fail_info = unsafe { pkisi_get_pkifailureinfo(si.cast()) };
    // SAFETY: as above.
    unsafe { (*c).failInfoCode = fail_info };
    // SAFETY: no preconditions.
    let list = unsafe { OPENSSL_sk_new_null() };
    // SAFETY: the context; the new list, which it takes.
    if unsafe { ctx_set0_statusString(ctx, list.cast()) } == 0 {
        return 0;
    }
    // SAFETY: the context.
    let strings = unsafe { (*c).statusString };
    if strings.is_null() {
        return 0;
    }
    // SAFETY: the caller's status info.
    let ss = unsafe { (*si).statusString };
    // SAFETY: its strings, or NULL (0).
    for i in 0..unsafe { OPENSSL_sk_num(ss) } {
        // SAFETY: an index in range.
        let s: *const ASN1_STRING = unsafe { OPENSSL_sk_value(ss, i) }.cast();
        // SAFETY: a string of the list.
        let dup = unsafe { ASN1_STRING_dup(s) };
        // SAFETY: the context's list; the copy, which it takes.
        if dup.is_null() || unsafe { OPENSSL_sk_push(strings, dup.cast()) } == 0 {
            // SAFETY: the copy, or NULL.
            unsafe { ASN1_UTF8STRING_free(dup.cast()) };
            return 0;
        }
    }
    1
}

/// Whether the response is a certificate response whose response `rid` says `waiting`.
///
/// # Safety
/// `resp` is NULL or a live message.
unsafe fn is_crep_with_waiting(resp: *const OSSL_CMP_MSG, rid: c_int) -> bool {
    // SAFETY: the caller's guarantee.
    let bt = unsafe { OSSL_CMP_MSG_get_bodytype(resp) };
    if !is_crep(bt) {
        return false;
    }
    // SAFETY: as above; the same for ip, cp, and kup.
    let crepmsg = unsafe { body_value(resp) };
    // SAFETY: the certificate response, or NULL.
    let crep: *const CertResponse =
        unsafe { certrepmessage_get0_certresponse(crepmsg.cast(), rid) }.cast();
    // SAFETY: the response, or NULL.
    unsafe { crep.as_ref() }
        // SAFETY: its status.
        .is_some_and(|r| unsafe { pkisi_get_status(r.status.cast()) } == OSSL_CMP_PKISTATUS_waiting)
}

/// The generic part of sending a request and receiving its response: 1 with the response in
/// `*rep`, else 0. Either way the caller frees `*rep` (unless NULL).
///
/// # Safety
/// `ctx` is a live context; `req` a live message; `rep` room for a pointer.
unsafe fn send_receive_check(
    ctx: *mut OSSL_CMP_CTX,
    req: *const OSSL_CMP_MSG,
    rep: &mut *mut OSSL_CMP_MSG,
    expected_type: c_int,
) -> c_int {
    const F: &str = "send_receive_check";
    const FN: &CStr = c"send_receive_check";
    let c: *mut Ctx = ctx.cast();
    let begin_transaction = expected_type != PKIBODY_POLLREP && expected_type != PKIBODY_PKICONF;
    // SAFETY: the caller's message.
    let req_type_str =
        bodytype_to_string(unsafe { OSSL_CMP_MSG_get_bodytype(req) }).to_string_lossy();
    let expected_type_str = bodytype_to_string(expected_type).to_string_lossy();
    // SAFETY: the caller's context, for each access below.
    let bak_msg_timeout = unsafe { (*c).msg_timeout };
    let now = now();
    // SAFETY: as above.
    let mut transfer_cb = unsafe { (*c).transfer_cb };
    // SAFETY: as above.
    unsafe { (*c).status = OSSL_CMP_PKISTATUS_trans };
    if transfer_cb.is_none() {
        transfer_cb = Some(OSSL_CMP_MSG_http_perform);
    }
    *rep = ptr::null_mut();

    // SAFETY: as above.
    let total_timeout = unsafe { (*c).total_timeout };
    if total_timeout != 0 {
        if begin_transaction {
            // SAFETY: as above.
            unsafe { (*c).end_time = now.saturating_add(i64::from(total_timeout)) };
        }
        // SAFETY: as above.
        let end_time = unsafe { (*c).end_time };
        if now >= end_time {
            err::raise(ERR_LIB_CMP, CMP_R_TOTAL_TIMEOUT, F);
            return 0;
        }
        // `end_time - now < INT_MAX`, which the assignment above ensures.
        let Some(time_left) = c_int::try_from(end_time.saturating_sub(now))
            .ok()
            .filter(|&t| t < c_int::MAX)
        else {
            err::raise(ERR_LIB_CMP, CMP_R_INVALID_ARGS, F);
            return 0;
        };
        // SAFETY: as above.
        let msg_timeout = unsafe { (*c).msg_timeout };
        if msg_timeout == 0 || time_left < msg_timeout {
            // SAFETY: as above.
            unsafe { (*c).msg_timeout = time_left };
        }
    }

    // The error queue is printed now, since the transfer callback may clear it.
    // SAFETY: as above.
    unsafe { OSSL_CMP_CTX_print_errors(ctx) };

    // SAFETY: as above.
    if !unsafe { (*c).server }.is_null() || unsafe { (*c).transfer_cb }.is_some() {
        // SAFETY: as above.
        unsafe {
            log(
                OSSL_CMP_LOG_INFO,
                ctx,
                FN,
                &format!("sending {req_type_str}"),
            )
        };
    }

    if let Some(cb) = transfer_cb {
        // SAFETY: the application's (or the HTTP) transfer callback with the context and the
        // request; no lock is held.
        *rep = unsafe { cb(ctx, req) };
    }
    // SAFETY: as above.
    unsafe { (*c).msg_timeout = bak_msg_timeout };

    if rep.is_null() {
        // SAFETY: as above.
        let timed_out = total_timeout != 0 && now_reached(unsafe { (*c).end_time });
        let reason = if timed_out {
            CMP_R_TOTAL_TIMEOUT
        } else {
            CMP_R_TRANSFER_ERROR
        };
        err::raise_with_text(
            ERR_LIB_CMP,
            reason,
            F,
            &format!("request sent: {req_type_str}, expected response: {expected_type_str}"),
        );
        return 0;
    }

    // SAFETY: as above.
    unsafe { (*c).status = OSSL_CMP_PKISTATUS_checking_response };
    // SAFETY: the response.
    let bt = unsafe { OSSL_CMP_MSG_get_bodytype(*rep) };
    // The body type isn't verified yet; it's used already for a progress report, since the
    // checks below may log too and fail.
    // SAFETY: as above.
    let waiting = if unsafe { is_error_with_waiting(*rep) } != 0 {
        " (waiting)"
    } else {
        ""
    };
    let bt_str = bodytype_to_string(bt);
    // SAFETY: as above.
    unsafe {
        log(
            OSSL_CMP_LOG_INFO,
            ctx,
            FN,
            &format!("received {}{waiting}", bt_str.to_string_lossy()),
        )
    };

    // The received extraCerts are copied to the context, so they can be retrieved.
    if bt != PKIBODY_POLLREP && bt != PKIBODY_PKICONF {
        // SAFETY: the response.
        let extra = unsafe { (*(*rep).cast::<Msg>()).extraCerts };
        // SAFETY: the context; the response's certificates, or NULL.
        if unsafe { ctx_set1_extraCertsIn(ctx, extra.cast()) } == 0 {
            return 0;
        }
    }

    // SAFETY: the context; the response; the exception callback.
    if unsafe { msg_check_update(ctx, *rep, Some(unprotected_exception), expected_type) } == 0 {
        return 0;
    }

    // The expected type, which is pollRep while polling. While polling, any other non-error
    // response (the final one) is fine too; before polling, an error with a `waiting` status
    // starts delayed delivery.
    let ok = bt == expected_type
        || if expected_type == PKIBODY_POLLREP {
            bt != PKIBODY_ERROR
        } else {
            // SAFETY: the response.
            (unsafe { is_error_with_waiting(*rep) }) != 0
        };
    if ok {
        return 1;
    }

    // Not one of the expected types (an error, for example).
    let reason = if bt == PKIBODY_ERROR {
        CMP_R_RECEIVED_ERROR
    } else {
        CMP_R_UNEXPECTED_PKIBODY
    };
    err::raise(ERR_LIB_CMP, reason, F);
    if bt != PKIBODY_ERROR {
        err::add_error_data([
            Some(&b"message type is '"[..]),
            Some(bt_str.to_bytes()),
            Some(&b"'"[..]),
        ]);
    } else {
        // SAFETY: the error message's content.
        let emc: *const ErrorMsgContent = unsafe { body_value(*rep) }.cast();
        // SAFETY: as above.
        let Some(emc) = (unsafe { emc.as_ref() }) else {
            return 0;
        };
        // SAFETY: the context; the error's status info.
        if unsafe { save_statusInfo(ctx, emc.pKIStatusInfo) } != 0 {
            // SAFETY: the context.
            unsafe { add_status_data(ctx) };
        }
        if !emc.errorCode.is_null() {
            // SAFETY: the error's code.
            let code = unsafe { ASN1_INTEGER_get(emc.errorCode) };
            let text = format!("; errorCode: {:08X}", code.cast_unsigned());
            err::add_error_data([Some(text.as_bytes())]);
        }
        if !emc.errorDetails.is_null() {
            // SAFETY: the error's details.
            if let Some(text) =
                // SAFETY: the error's details.
                unsafe { utf8_text(emc.errorDetails, b", ", buflen().saturating_sub(1)) }
                && !text.is_empty()
            {
                err::add_error_data([Some(&b"; errorDetails: "[..]), Some(text.as_slice())]);
            }
        }
        // SAFETY: the context.
        let status = unsafe { (*c).status };
        if status != OSSL_CMP_PKISTATUS_rejection {
            err::raise(ERR_LIB_CMP, CMP_R_UNEXPECTED_PKISTATUS, F);
            if status == OSSL_CMP_PKISTATUS_waiting {
                // SAFETY: as above.
                unsafe { (*c).status = OSSL_CMP_PKISTATUS_rejection };
            }
        }
    }
    0
}

/// Whether the time has come: `time(NULL) >= end`.
fn now_reached(end: i64) -> bool {
    now() >= end
}

/// After a `waiting` status: polls, which yields a pollRep or the final response. On a
/// pollRep, sleeps for its checkAfter and retries if `sleep`, else returns -1 with
/// `*check_after` set. With a total timeout, polls a last time when it is reached even if
/// that's before checkAfter. 1 with the final response in `*rep` (which the caller frees), 0
/// on an error (including the timeout and a response that says `waiting` again).
///
/// # Safety
/// `ctx` is a live context; `check_after` NULL or room for an int.
unsafe fn poll_for_response(
    ctx: *mut OSSL_CMP_CTX,
    sleep: bool,
    rid: c_int,
    rep: &mut *mut OSSL_CMP_MSG,
    check_after_out: *mut c_int,
) -> c_int {
    const F: &str = "poll_for_response";
    const FN: &CStr = c"poll_for_response";
    let c: *mut Ctx = ctx.cast();
    let mut preq: *mut OSSL_CMP_MSG;
    let mut prep: *mut OSSL_CMP_MSG = ptr::null_mut();

    // SAFETY: the caller's context.
    unsafe {
        log(
            OSSL_CMP_LOG_INFO,
            ctx,
            FN,
            "received 'waiting' PKIStatus, starting to poll for response",
        )
    };
    *rep = ptr::null_mut();
    let ok = 'poll: loop {
        // SAFETY: the caller's context, for each access below.
        let bak = unsafe { (*c).status };
        // SAFETY: as above.
        unsafe { (*c).status = OSSL_CMP_PKISTATUS_request };
        // SAFETY: as above.
        preq = unsafe { pollReq_new(ctx, rid) };
        if preq.is_null() {
            break 'poll false;
        }
        // SAFETY: the context; the request made here; the room for the response.
        if unsafe { send_receive_check(ctx, preq, &mut prep, PKIBODY_POLLREP) } == 0 {
            break 'poll false;
        }
        // SAFETY: as above.
        unsafe { (*c).status = bak };

        // SAFETY: the response.
        if unsafe { OSSL_CMP_MSG_get_bodytype(prep) } == PKIBODY_POLLREP {
            // SAFETY: as above.
            let prc: *const Stack = unsafe { body_value(prep) }.cast();
            // SAFETY: its pollReps, or NULL.
            if unsafe { OPENSSL_sk_num(prc) } > 1 {
                err::raise(ERR_LIB_CMP, CMP_R_MULTIPLE_RESPONSES_NOT_SUPPORTED, F);
                break 'poll false;
            }
            // SAFETY: as above.
            let poll_rep: *const PollRep =
                unsafe { pollrepcontent_get0_pollrep(prc.cast(), rid) }.cast();
            // SAFETY: the pollRep, or NULL.
            let Some(poll_rep) = (unsafe { poll_rep.as_ref() }) else {
                break 'poll false;
            };
            let mut check_after = 0i64;
            // SAFETY: the room; its checkAfter.
            if unsafe { ASN1_INTEGER_get_int64(&raw mut check_after, poll_rep.checkAfter) } == 0 {
                err::raise(ERR_LIB_CMP, CMP_R_BAD_CHECKAFTER_IN_POLLREP, F);
                break 'poll false;
            }
            let limit = if sleep {
                c_ulong::MAX / 1000
            } else {
                u64::try_from(c_int::MAX).unwrap_or(0)
            };
            if u64::try_from(check_after).map_or(true, |v| v > limit) {
                err::raise(ERR_LIB_CMP, CMP_R_CHECKAFTER_OUT_OF_RANGE, F);
                let text = format!("value = {check_after}");
                err::add_error_data([Some(text.as_bytes())]);
                break 'poll false;
            }

            const PREFIX: &str = " with reason = '";
            let reason = if poll_rep.reason.is_null() {
                String::new()
            } else {
                // SAFETY: its reason strings.
                match unsafe {
                    utf8_text(
                        poll_rep.reason,
                        b", ",
                        buflen().saturating_sub(PREFIX.len() + 2),
                    )
                } {
                    Some(text) => format!("{PREFIX}{}'", String::from_utf8_lossy(&text)),
                    None => String::new(),
                }
            };
            // SAFETY: the context.
            unsafe {
                log(
                    OSSL_CMP_LOG_INFO,
                    ctx,
                    FN,
                    &format!(
                        "received polling response{reason}; checkAfter = {check_after} seconds"
                    ),
                )
            };

            // SAFETY: the context.
            if unsafe { (*c).total_timeout } != 0 {
                // SAFETY: as above.
                let end_time = unsafe { (*c).end_time };
                let time_left = end_time
                    .saturating_sub(EXPECTED_RESP_TIME)
                    .saturating_sub(now());
                if time_left <= 0 {
                    // SAFETY: as above.
                    unsafe { (*c).status = OSSL_CMP_PKISTATUS_trans };
                    err::raise(ERR_LIB_CMP, CMP_R_TOTAL_TIMEOUT, F);
                    break 'poll false;
                }
                // Polls one last time just when the timeout is reached.
                if time_left < check_after {
                    check_after = time_left;
                }
            }

            // SAFETY: made here, freed once.
            unsafe { OSSL_CMP_MSG_free(preq) };
            // SAFETY: as above.
            unsafe { OSSL_CMP_MSG_free(prep) };
            prep = ptr::null_mut();
            if sleep {
                let millis = u64::try_from(check_after).unwrap_or(0).saturating_mul(1000);
                // SAFETY: no preconditions.
                unsafe { OSSL_sleep(millis) };
            } else {
                // SAFETY: the caller's room, or NULL.
                if let Some(out) = unsafe { check_after_out.as_mut() } {
                    *out = c_int::try_from(check_after).unwrap_or(c_int::MAX);
                }
                return -1;
            }
        // SAFETY: the response.
        } else if unsafe { waiting_again(prep, rid) } {
            // The status mustn't be `waiting` again. As in OpenSSL, the failure info passed
            // is the failure code OSSL_CMP_CTX_FAILINFO_badRequest, not its bit.
            // SAFETY: the context; a static text.
            unsafe {
                exchange_error(
                    ctx,
                    OSSL_CMP_PKISTATUS_rejection,
                    OSSL_CMP_CTX_FAILINFO_badRequest,
                    c"polling already started".as_ptr(),
                    0,
                    ptr::null(),
                )
            };
            err::raise(ERR_LIB_CMP, CMP_R_UNEXPECTED_PKISTATUS, F);
            break 'poll false;
        } else {
            // SAFETY: the context.
            unsafe {
                log(
                    OSSL_CMP_LOG_INFO,
                    ctx,
                    FN,
                    "received final response after polling",
                )
            };
            // SAFETY: as above.
            if unsafe { ctx_set1_first_senderNonce(ctx, ptr::null()) } == 0 {
                break 'poll false;
            }
            break 'poll true;
        }
    };
    if ok && !prep.is_null() {
        // SAFETY: made here.
        unsafe { OSSL_CMP_MSG_free(preq) };
        *rep = prep;
        return 1;
    }
    // SAFETY: the context.
    unsafe { ctx_set1_first_senderNonce(ctx, ptr::null()) };
    // SAFETY: made here, or NULL.
    unsafe { OSSL_CMP_MSG_free(preq) };
    // SAFETY: as above.
    unsafe { OSSL_CMP_MSG_free(prep) };
    0
}

/// Saves the request's senderNonce if the response says `waiting` (RFC 9483 section 4.4:
/// it's needed to check the recipNonce of the final response after polling): 1, or 0.
///
/// # Safety
/// `ctx` is a live context; `rep` NULL or a live message.
unsafe fn save_senderNonce_if_waiting(
    ctx: *mut OSSL_CMP_CTX,
    rep: *const OSSL_CMP_MSG,
    rid: c_int,
) -> c_int {
    // SAFETY: the caller's message.
    let waiting = unsafe { is_crep_with_waiting(rep, rid) }
        // SAFETY: as above.
        || unsafe { is_error_with_waiting(rep) } != 0;
    if waiting {
        // SAFETY: the caller's context.
        let nonce = unsafe { (*ctx.cast::<Ctx>()).senderNonce };
        // SAFETY: as above; its nonce.
        if unsafe { ctx_set1_first_senderNonce(ctx, nonce) } == 0 {
            return 0;
        }
    }
    1
}

/// Sends the request and gets the response, polling if an error message with a `waiting`
/// status starts delayed delivery (a certificate response's `waiting` is handled by
/// [`cert_response`]): 1, or 0.
///
/// # Safety
/// As for [`send_receive_check`].
unsafe fn send_receive_also_delayed(
    ctx: *mut OSSL_CMP_CTX,
    req: *const OSSL_CMP_MSG,
    rep: &mut *mut OSSL_CMP_MSG,
    expected_type: c_int,
) -> c_int {
    const F: &str = "send_receive_also_delayed";
    // SAFETY: the caller's guarantee.
    if unsafe { send_receive_check(ctx, req, rep, expected_type) } == 0 {
        return 0;
    }
    // SAFETY: the response.
    if unsafe { is_error_with_waiting(*rep) } != 0 {
        // SAFETY: the context; the response.
        if unsafe { save_senderNonce_if_waiting(ctx, *rep, CERTREQID_NONE) } == 0 {
            return 0;
        }
        // The status isn't changed during certConf and error exchanges.
        if expected_type != PKIBODY_PKICONF {
            // SAFETY: the error message's content.
            let emc: *const ErrorMsgContent = unsafe { body_value(*rep) }.cast();
            // SAFETY: as above.
            let si = unsafe { emc.as_ref() }.map_or(ptr::null_mut(), |e| e.pKIStatusInfo);
            // SAFETY: the context; its status info, or NULL.
            if unsafe { save_statusInfo(ctx, si) } == 0 {
                return 0;
            }
        }
        // SAFETY: the response, freed once.
        unsafe { OSSL_CMP_MSG_free(*rep) };
        *rep = ptr::null_mut();
        // SAFETY: the context; the room for the response.
        if unsafe { poll_for_response(ctx, true, CERTREQID_NONE, rep, ptr::null_mut()) } <= 0 {
            err::raise(ERR_LIB_CMP, CMP_R_POLLING_FAILED, F);
            return 0;
        }
    }
    // SAFETY: the response.
    if unsafe { OSSL_CMP_MSG_get_bodytype(*rep) } != expected_type {
        err::raise(ERR_LIB_CMP, CMP_R_UNEXPECTED_PKIBODY, F);
        return 0;
    }
    1
}

/// `ossl_cmp_exchange_certConf`: sends certConf for an ir, cr, kur, or p10cr sequence and
/// checks the response, the context's status unchanged on success: 1, or 0.
///
/// # Safety
/// `ctx` is a live context; `txt` NULL or a NUL-terminated string.
pub(crate) unsafe fn exchange_certConf(
    ctx: *mut OSSL_CMP_CTX,
    certReqId: c_int,
    fail_info: c_int,
    txt: *const c_char,
) -> c_int {
    let c: *mut Ctx = ctx.cast();
    let mut pki_conf: *mut OSSL_CMP_MSG = ptr::null_mut();
    let mut res = 0;
    // SAFETY: the caller's context, for each access below.
    let bak = unsafe { (*c).status };
    // SAFETY: as above.
    unsafe { (*c).status = OSSL_CMP_PKISTATUS_request };
    // certConf_new() also checks that every option needed is set.
    // SAFETY: as above; the caller's text.
    let cert_conf = unsafe { certConf_new(ctx, certReqId, fail_info, txt) };
    if !cert_conf.is_null() {
        // SAFETY: the context; the message made here; the room for the response.
        res = unsafe { send_receive_also_delayed(ctx, cert_conf, &mut pki_conf, PKIBODY_PKICONF) };
        if res != 0 {
            // SAFETY: as above.
            unsafe { (*c).status = bak };
        }
    }
    // SAFETY: made here, or NULL.
    unsafe { OSSL_CMP_MSG_free(cert_conf) };
    // SAFETY: as above.
    unsafe { OSSL_CMP_MSG_free(pki_conf) };
    res
}

/// `ossl_cmp_exchange_error`: sends an error message with the given status and checks the
/// response; the context's status is then `rejected_by_client`. 1, or 0.
///
/// # Safety
/// `ctx` is a live context; `txt` and `details` NULL or NUL-terminated strings.
pub(crate) unsafe fn exchange_error(
    ctx: *mut OSSL_CMP_CTX,
    status: c_int,
    fail_info: c_int,
    txt: *const c_char,
    errorCode: c_int,
    details: *const c_char,
) -> c_int {
    let c: *mut Ctx = ctx.cast();
    let mut error: *mut OSSL_CMP_MSG = ptr::null_mut();
    let mut pki_conf: *mut OSSL_CMP_MSG = ptr::null_mut();
    let mut res = 0;
    // SAFETY: the caller's context.
    unsafe { (*c).status = OSSL_CMP_PKISTATUS_request };
    // SAFETY: the caller's text.
    let si = unsafe { OSSL_CMP_STATUSINFO_new(status, fail_info, txt) };
    if !si.is_null() {
        // error_new() also checks that every option needed is set.
        // SAFETY: the context; the status info; the caller's details.
        error = unsafe { error_new(ctx, si.cast(), i64::from(errorCode), details, 0) };
        if !error.is_null() {
            // SAFETY: the context; the message made here; the room for the response.
            res = unsafe { send_receive_also_delayed(ctx, error, &mut pki_conf, PKIBODY_PKICONF) };
            // SAFETY: as above.
            unsafe { (*c).status = OSSL_CMP_PKISTATUS_rejected_by_client };
        }
    }
    // SAFETY: made here, or NULL.
    unsafe { OSSL_CMP_MSG_free(error) };
    // SAFETY: as above.
    unsafe { OSSL_CMP_PKISI_free(si.cast()) };
    // SAFETY: as above.
    unsafe { OSSL_CMP_MSG_free(pki_conf) };
    res
}

/// A copy of the certificate in the CertResponse, given its PKIStatusInfo (saved in the
/// context, and reported on an error), or NULL.
///
/// # Safety
/// `ctx` is NULL or a live context; `crep` NULL or a live response.
unsafe fn get1_cert_status(
    ctx: *mut OSSL_CMP_CTX,
    bodytype: c_int,
    crep: *const CertResponse,
) -> *mut X509 {
    const F: &str = "get1_cert_status";
    const FN: &CStr = c"get1_cert_status";
    if ctx.is_null() || crep.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller's response.
    let si = unsafe { (*crep).status };
    // SAFETY: its status.
    let status = unsafe { pkisi_get_status(si.cast()) };
    let ok = if status == OSSL_CMP_PKISTATUS_waiting {
        // SAFETY: the caller's context.
        unsafe {
            log(
                OSSL_CMP_LOG_ERR,
                ctx,
                FN,
                "received \"waiting\" status for cert when actually aiming to extract cert",
            )
        };
        err::raise(ERR_LIB_CMP, CMP_R_ENCOUNTERED_WAITING, F);
        false
    } else if status == OSSL_CMP_PKISTATUS_grantedWithMods {
        // SAFETY: as above.
        unsafe {
            log(
                OSSL_CMP_LOG_WARNING,
                ctx,
                FN,
                "received \"grantedWithMods\" for certificate",
            )
        };
        true
    } else if status == OSSL_CMP_PKISTATUS_accepted {
        true
    } else if status == OSSL_CMP_PKISTATUS_rejection {
        // SAFETY: as above.
        unsafe {
            log(
                OSSL_CMP_LOG_ERR,
                ctx,
                FN,
                "received \"rejection\" status rather than cert",
            )
        };
        err::raise(ERR_LIB_CMP, CMP_R_REQUEST_REJECTED_BY_SERVER, F);
        false
    } else if status == OSSL_CMP_PKISTATUS_revocationWarning {
        // SAFETY: as above.
        unsafe {
            log(
                OSSL_CMP_LOG_WARNING,
                ctx,
                FN,
                "received \"revocationWarning\" - a revocation of the cert is imminent",
            )
        };
        true
    } else if status == OSSL_CMP_PKISTATUS_revocationNotification {
        // SAFETY: as above.
        unsafe {
            log(
                OSSL_CMP_LOG_WARNING,
                ctx,
                FN,
                "received \"revocationNotification\" - a revocation of the cert has occurred",
            )
        };
        true
    } else if status == OSSL_CMP_PKISTATUS_keyUpdateWarning {
        if bodytype != PKIBODY_KUR {
            err::raise(ERR_LIB_CMP, CMP_R_ENCOUNTERED_KEYUPDATEWARNING, F);
            false
        } else {
            true
        }
    } else {
        // As in OpenSSL, the number logged is the context's status, not the response's.
        // SAFETY: as above.
        let ctx_status = unsafe { (*ctx.cast::<Ctx>()).status };
        // SAFETY: as above.
        unsafe {
            log(
                OSSL_CMP_LOG_ERR,
                ctx,
                FN,
                &format!("received unsupported PKIStatus {ctx_status} for certificate"),
            )
        };
        err::raise(ERR_LIB_CMP, CMP_R_UNKNOWN_PKISTATUS, F);
        false
    };
    if !ok {
        // SAFETY: as above.
        unsafe { add_status_data(ctx) };
        return ptr::null_mut();
    }
    // SAFETY: the context; the response.
    let crt = unsafe { certresponse_get1_cert(ctx, crep.cast()) };
    if crt.is_null() {
        // The status says there should be a certificate.
        err::raise(ERR_LIB_CMP, CMP_R_CERTIFICATE_NOT_FOUND, F);
    }
    crt
}

ffi_export! {
    /// The default certificate confirmation callback: with `fail_info` 0, validates the new
    /// certificate against the trust store in the callback argument (else just builds an
    /// approximate chain) using the context's untrusted certificates, and saves the chain
    /// (without the certificate itself) as the context's new chain. 0 to accept, else the
    /// failure bits (`fail_info` itself when not 0).
    ///
    /// # Safety
    /// `ctx` is a live context; `cert` a live certificate.
    pub unsafe extern "C" fn OSSL_CMP_certConf_cb(ctx: *mut OSSL_CMP_CTX, cert: *mut X509, fail_info: c_int, text: *mut *const c_char) -> c_int
    where failure = 1 << OSSL_CMP_PKIFAILUREINFO_incorrectData, library = ERR_LIB_CMP
    {
        const FN: &CStr = c"OSSL_CMP_certConf_cb";
        let _ = text;
        if fail_info != 0 {
            // Any error flagged by the CMP library is accepted.
            return fail_info;
        }
        let mut fail_info = fail_info;
        let c: *mut Ctx = ctx.cast();
        // SAFETY: the caller's context, for each access below.
        let out_trusted: *mut X509_STORE = unsafe { (*c).certConf_cb_arg }.cast();
        // SAFETY: as above.
        let untrusted: *mut stack_st_X509 = unsafe { (*c).untrusted }.cast();
        // SAFETY: as above.
        let libctx = unsafe { (*c).libctx };
        // SAFETY: as above.
        let propq = unsafe { (*c).propq };
        let mut chain: *mut stack_st_X509 = ptr::null_mut();
        if out_trusted.is_null() {
            // SAFETY: as above.
            unsafe { log(OSSL_CMP_LOG_DEBUG, ctx, FN, "trying to build chain for newly enrolled cert") };
            // SAFETY: the caller's certificate; the context's certificates and settings.
            chain = unsafe { X509_build_chain(cert, untrusted, out_trusted, 0, libctx, propq) };
        } else {
            // SAFETY: the context's settings.
            let csc = unsafe { X509_STORE_CTX_new_ex(libctx, propq) };
            // SAFETY: as above.
            unsafe { log(OSSL_CMP_LOG_DEBUG, ctx, FN, "validating newly enrolled cert") };
            'v: {
                if csc.is_null() {
                    break 'v;
                }
                // SAFETY: the new context; the store; the certificate; the untrusted ones.
                if unsafe { X509_STORE_CTX_init(csc, out_trusted, cert, untrusted) } == 0 {
                    break 'v;
                }
                // Any status and revocation checking is disabled.
                let keep = (X509_V_FLAG_USE_CHECK_TIME | X509_V_FLAG_NO_CHECK_TIME | X509_V_FLAG_PARTIAL_CHAIN | X509_V_FLAG_POLICY_CHECK).cast_unsigned();
                // SAFETY: the context's parameters.
                let param = unsafe { X509_STORE_CTX_get0_param(csc) };
                // SAFETY: as above.
                unsafe { X509_VERIFY_PARAM_clear_flags(param, !c_ulong::from(keep)) };
                // SAFETY: the initialized context.
                if unsafe { X509_verify_cert(csc) } <= 0 {
                    break 'v;
                }
                // SAFETY: as above.
                let verified = unsafe { X509_STORE_CTX_get0_chain(csc) };
                let flags = X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP | X509_ADD_FLAG_NO_SS;
                let mut slot: *mut Stack = ptr::null_mut();
                let mut added = true;
                // SAFETY: the verified chain.
                for i in 0..unsafe { OPENSSL_sk_num(verified.cast()) } {
                    // SAFETY: an index in range.
                    let x: *mut X509 = unsafe { OPENSSL_sk_value(verified.cast(), i) }.cast();
                    // SAFETY: the list being made; a certificate of the chain.
                    if !unsafe { add_cert_new(&mut slot, x, flags) } {
                        added = false;
                        break;
                    }
                }
                if added {
                    chain = slot.cast();
                } else {
                    // As in OpenSSL, the list is freed without its certificates.
                    // SAFETY: the list made here.
                    unsafe { OPENSSL_sk_free(slot) };
                }
            }
            // SAFETY: made here, or NULL.
            unsafe { X509_STORE_CTX_free(csc) };
        }

        // SAFETY: the chain, or NULL.
        if unsafe { OPENSSL_sk_num(chain.cast()) } > 0 {
            // The leaf (EE) certificate is removed.
            // SAFETY: as above.
            let leaf = unsafe { OPENSSL_sk_shift(chain.cast()) };
            // SAFETY: the chain's reference.
            unsafe { X509_free(leaf.cast()) };
        }
        if !out_trusted.is_null() {
            if chain.is_null() {
                // SAFETY: as above.
                unsafe { log(OSSL_CMP_LOG_ERR, ctx, FN, "failed to validate newly enrolled cert") };
                fail_info = 1 << OSSL_CMP_PKIFAILUREINFO_incorrectData;
            } else {
                // SAFETY: as above.
                unsafe { log(OSSL_CMP_LOG_DEBUG, ctx, FN, "success validating newly enrolled cert") };
            }
        } else if chain.is_null() {
            // SAFETY: as above.
            unsafe { log(OSSL_CMP_LOG_WARNING, ctx, FN, "could not build approximate chain for newly enrolled cert, resorting to received extraCerts") };
            // SAFETY: as above.
            chain = unsafe { OSSL_CMP_CTX_get1_extraCertsIn(ctx) };
        } else {
            // SAFETY: as above.
            unsafe { log(OSSL_CMP_LOG_DEBUG, ctx, FN, "success building approximate chain for newly enrolled cert") };
        }
        // SAFETY: the context; the chain, or NULL.
        unsafe { ctx_set1_newChain(ctx, chain) };
        // SAFETY: the chain, freed once.
        unsafe { OSSL_STACK_OF_X509_free(chain) };
        fail_info
    }
}

/// The generic handling of the certificate response to an ir, cr, kur, or p10cr; `rid` is
/// `CERTREQID_NONE` when unknown (for p10cr). -1 on a pollRep without `sleep` (with
/// `*check_after` set); 1 on success with the response in `*resp`; 0 on an error (including
/// the timeout). The caller frees `*resp` (unless NULL) either way.
///
/// # Safety
/// `ctx` is NULL or a live context; `*resp` a live message; `check_after` NULL or room.
unsafe fn cert_response(
    ctx: *mut OSSL_CMP_CTX,
    sleep: bool,
    rid: c_int,
    resp: &mut *mut OSSL_CMP_MSG,
    check_after: *mut c_int,
    _req_type: c_int,
    expected_type: c_int,
) -> c_int {
    const F: &str = "cert_response";
    const FN: &CStr = c"cert_response";
    if ctx.is_null() {
        return 0;
    }
    let c: *mut Ctx = ctx.cast();
    let mut rid = rid;
    let mut crepmsg: *mut CertRepMessage = ptr::null_mut();
    let mut crep: *mut CertResponse = ptr::null_mut();
    let rcvd_type = loop {
        // SAFETY: the response.
        let rcvd_type = unsafe { OSSL_CMP_MSG_get_bodytype(*resp) };
        let si: *mut PkiSi;
        if is_crep(rcvd_type) {
            // SAFETY: as above; the same for ip, cp, and kup.
            crepmsg = unsafe { body_value(*resp) }.cast();
            // SAFETY: the certificate response, or NULL.
            let responses = unsafe { crepmsg.as_ref() }.map_or(ptr::null_mut(), |m| m.response);
            // SAFETY: its responses, or NULL.
            if unsafe { OPENSSL_sk_num(responses) } > 1 {
                err::raise(ERR_LIB_CMP, CMP_R_MULTIPLE_RESPONSES_NOT_SUPPORTED, F);
                return 0;
            }
            // SAFETY: as above.
            crep = unsafe { certrepmessage_get0_certresponse(crepmsg.cast(), rid) }.cast();
            // SAFETY: the response, or NULL.
            let Some(r) = (unsafe { crep.as_ref() }) else {
                return 0;
            };
            si = r.status;
            if rid == CERTREQID_NONE {
                // For p10cr, the request id comes from the response.
                // SAFETY: its id.
                rid = unsafe { asn1_get_int(r.certReqId) };
                if rid < CERTREQID_NONE {
                    err::raise(ERR_LIB_CMP, CMP_R_BAD_REQUEST_ID, F);
                    return 0;
                }
            }
        } else if rcvd_type == PKIBODY_ERROR {
            // SAFETY: the error message's content.
            let emc: *const ErrorMsgContent = unsafe { body_value(*resp) }.cast();
            // SAFETY: as above.
            si = unsafe { emc.as_ref() }.map_or(ptr::null_mut(), |e| e.pKIStatusInfo);
        } else {
            err::raise(ERR_LIB_CMP, CMP_R_UNEXPECTED_PKIBODY, F);
            return 0;
        }

        // SAFETY: the context; the status info.
        if unsafe { save_statusInfo(ctx, si) } == 0 {
            return 0;
        }

        // SAFETY: as above.
        if unsafe { pkisi_get_status(si.cast()) } == OSSL_CMP_PKISTATUS_waiting {
            // Both an error message and a certificate response with `waiting` are allowed,
            // and the response's flavor (ip, cp, or kup) needn't match the request.
            // SAFETY: the response, freed once.
            unsafe { OSSL_CMP_MSG_free(*resp) };
            *resp = ptr::null_mut();
            // SAFETY: the context; the room.
            let ret = unsafe { poll_for_response(ctx, sleep, rid, resp, check_after) };
            if ret == -1 {
                // Implies !sleep: waiting.
                return ret;
            }
            if ret == 0 {
                err::raise(ERR_LIB_CMP, CMP_R_POLLING_FAILED, F);
                return 0;
            }
            // Some response other than pollRep.
            continue;
        }
        break rcvd_type;
    };

    // An ip, cp, kup, or error without `waiting` now.
    if rcvd_type == PKIBODY_ERROR {
        err::raise(ERR_LIB_CMP, CMP_R_RECEIVED_ERROR, F);
        return 0;
    }
    // The flavor must match the request here.
    if rcvd_type != expected_type {
        err::raise(ERR_LIB_CMP, CMP_R_UNEXPECTED_PKIBODY, F);
        return 0;
    }

    let m = (*resp).cast::<Msg>();
    // SAFETY: the response's body.
    let body = unsafe { (*m).body };
    // SAFETY: as above.
    let body_type = unsafe { (*body).type_ };
    // SAFETY: the context; the certificate response.
    let cert = unsafe { get1_cert_status(ctx, body_type, crep) };
    if cert.is_null() {
        err::add_error_data([Some(&b"; cannot extract certificate from response"[..])]);
        return 0;
    }
    // SAFETY: the context; the copy, which it takes.
    if unsafe { ctx_set0_newCert(ctx, cert) } == 0 {
        // SAFETY: the copy.
        unsafe { X509_free(cert) };
        return 0;
    }

    // CA certificates in caPubs are copied to the context, so they can be retrieved.
    // SAFETY: the certificate response, or NULL.
    if let Some(m) = unsafe { crepmsg.as_ref() }
        && !m.caPubs.is_null()
        // SAFETY: the context; the certificates.
        && unsafe { ctx_set1_caPubs(ctx, m.caPubs.cast()) } == 0
    {
        return 0;
    }

    // SAFETY: the new certificate.
    let name = unsafe { X509_get_subject_name(cert) };
    // SAFETY: its name; a new string.
    let subj = unsafe { X509_NAME_oneline(name, ptr::null_mut(), 0) };
    // SAFETY: the subject, or NULL.
    let subj_text = unsafe { text_of(subj) };
    // SAFETY: the context.
    let rkey = unsafe { ctx_get0_newPubkey(ctx) };
    let mut fail_info: c_int = 0;
    let mut txt: *const c_char = ptr::null();
    // SAFETY: as above.
    let new_cert = unsafe { (*c).newCert };
    // X509_check_private_key() works with a public key too.
    // SAFETY: the certificate; the key.
    if !rkey.is_null() && unsafe { X509_check_private_key(new_cert, rkey) } == 0 {
        fail_info = 1 << OSSL_CMP_PKIFAILUREINFO_incorrectData;
        txt = c"public key in new certificate does not match our enrollment key".as_ptr();
        // Not an error yet: the certConf callback decides.
    }

    // The checking callback decides whether to accept the new certificate; it may overrule
    // `fail_info` and `txt`.
    // SAFETY: as above.
    let cb = unsafe { (*c).certConf_cb }.unwrap_or(OSSL_CMP_certConf_cb);
    // SAFETY: the application's callback (or the default) with the context, its new
    // certificate, and the room for a text; no lock is held.
    fail_info = unsafe { cb(ctx, new_cert, fail_info, &raw mut txt) };
    if fail_info != 0 && txt.is_null() {
        txt = c"CMP client did not accept it".as_ptr();
    }
    if fail_info != 0 {
        // Logged at once, before any certConf exchange.
        // SAFETY: as above.
        unsafe {
            log(
                OSSL_CMP_LOG_ERR,
                ctx,
                FN,
                &format!("rejecting newly enrolled cert with subject: {subj_text}"),
            )
        };
    }
    let mut ret = 1;
    // SAFETY: as above.
    let disable_confirm = unsafe { (*c).disableConfirm };
    // SAFETY: the response's header.
    let header = unsafe { (*(*resp).cast::<Msg>()).header };
    // SAFETY: as above.
    if disable_confirm == 0 && unsafe { hdr_has_implicitConfirm(header.cast()) } == 0 {
        // SAFETY: the context; the text, NULL or NUL-terminated.
        if unsafe { exchange_certConf(ctx, rid, fail_info, txt) } == 0 {
            ret = 0;
        }
    }

    // Raised only now, since the transfer callback may clear the error queue.
    if fail_info != 0 {
        // SAFETY: the text, NUL-terminated.
        let why = unsafe { text_of(txt) };
        err::raise_with_text(
            ERR_LIB_CMP,
            CMP_R_CERTIFICATE_NOT_ACCEPTED,
            F,
            &format!("rejecting newly enrolled cert with subject: {subj_text}; {why}"),
        );
        // SAFETY: as above.
        unsafe { (*c).status = OSSL_CMP_PKISTATUS_rejected_by_client };
        ret = 0;
    }
    // SAFETY: the subject string, or NULL.
    unsafe { mem::release(subj.cast()) };
    ret
}

/// Sends the first request of a certificate transaction and checks its response: 1, or 0.
///
/// # Safety
/// `ctx` is a live context; `crm` NULL or a live CRMF message.
unsafe fn initial_certreq(
    ctx: *mut OSSL_CMP_CTX,
    req_type: c_int,
    crm: *const OSSL_CRMF_MSG,
    p_rep: &mut *mut OSSL_CMP_MSG,
    rep_type: c_int,
) -> c_int {
    // SAFETY: the caller's context.
    unsafe { (*ctx.cast::<Ctx>()).status = OSSL_CMP_PKISTATUS_request };
    // SAFETY: as above.
    if unsafe { ctx_set0_newCert(ctx, ptr::null_mut()) } == 0 {
        return 0;
    }
    // certreq_new() also checks that every option needed is set.
    // SAFETY: as above; the caller's message.
    let req = unsafe { certreq_new(ctx, req_type, crm) };
    if req.is_null() {
        return 0;
    }
    // SAFETY: the context; the request made here; the room.
    let res = unsafe { send_receive_check(ctx, req, p_rep, rep_type) };
    // SAFETY: made here.
    unsafe { OSSL_CMP_MSG_free(req) };
    res
}

/// The body type of the response to a certificate request and its request id.
fn rep_of(req_type: c_int) -> (c_int, c_int) {
    if req_type == PKIBODY_P10CR {
        (CERTREQID_NONE, PKIBODY_CP)
    } else {
        (CERTREQID, req_type.saturating_add(1))
    }
}

ffi_export! {
    /// One step of a certificate transaction without sleeping: the request (unless polling
    /// already), else a poll (aborted with an error message if `req_type` < 0). 1 with the
    /// new certificate in the context, -1 while waiting (with `*checkAfter` set), 0 on an
    /// error.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `crm` NULL or a live CRMF message; `checkAfter` NULL
    /// or room for an int.
    pub unsafe extern "C" fn OSSL_CMP_try_certreq(ctx: *mut OSSL_CMP_CTX, req_type: c_int, crm: *const OSSL_CRMF_MSG, checkAfter: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        if ctx.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, "OSSL_CMP_try_certreq");
            return 0;
        }
        let (rid, rep_type) = rep_of(req_type);
        let mut rep: *mut OSSL_CMP_MSG = ptr::null_mut();
        // SAFETY: the caller's context.
        let res = if unsafe { (*ctx.cast::<Ctx>()).status } != OSSL_CMP_PKISTATUS_waiting {
            // Not polling yet.
            // SAFETY: as above; the caller's message; the room.
            if unsafe { initial_certreq(ctx, req_type, crm, &mut rep, rep_type) } == 0
                // SAFETY: as above; the response.
                || unsafe { save_senderNonce_if_waiting(ctx, rep, rid) } == 0
            {
                0
            } else {
                // SAFETY: as above.
                unsafe { cert_response(ctx, false, rid, &mut rep, checkAfter, req_type, rep_type) }
            }
        } else {
            if req_type < 0 {
                // SAFETY: as above; static texts.
                return unsafe { exchange_error(ctx, OSSL_CMP_PKISTATUS_rejection, 0, c"polling aborted".as_ptr(), 0, c"by application".as_ptr()) };
            }
            // SAFETY: as above.
            let res = unsafe { poll_for_response(ctx, false, rid, &mut rep, checkAfter) };
            if res <= 0 {
                // Waiting, or an error.
                return res;
            }
            // SAFETY: as above.
            unsafe { cert_response(ctx, false, rid, &mut rep, checkAfter, req_type, rep_type) }
        };
        // SAFETY: the response, or NULL.
        unsafe { OSSL_CMP_MSG_free(rep) };
        res
    }
}

ffi_export! {
    /// The whole certificate transaction (ir, cr, kur, or p10cr; the response; certConf and
    /// PKIConf; polling, sleeping as the server says): the new certificate (the context's), or
    /// NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `crm` NULL or a live CRMF message.
    pub unsafe extern "C" fn OSSL_CMP_exec_certreq(ctx: *mut OSSL_CMP_CTX, req_type: c_int, crm: *const OSSL_CRMF_MSG) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        if ctx.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, "OSSL_CMP_exec_certreq");
            return ptr::null_mut();
        }
        let (rid, rep_type) = rep_of(req_type);
        let mut rep: *mut OSSL_CMP_MSG = ptr::null_mut();
        let mut result = ptr::null_mut();
        // SAFETY: the caller's context; the caller's message; the room.
        if unsafe { initial_certreq(ctx, req_type, crm, &mut rep, rep_type) } != 0
            // SAFETY: as above; the response.
            && unsafe { save_senderNonce_if_waiting(ctx, rep, rid) } != 0
            // SAFETY: as above.
            && unsafe { cert_response(ctx, true, rid, &mut rep, ptr::null_mut(), req_type, rep_type) } > 0
        {
            // SAFETY: as above.
            result = unsafe { (*ctx.cast::<Ctx>()).newCert };
        }
        // SAFETY: the response, or NULL.
        unsafe { OSSL_CMP_MSG_free(rep) };
        result
    }
}

ffi_export! {
    /// A revocation transaction (rr, rp) for the context's old certificate, CSR, or issuer
    /// and serial number: 1 if the revocation was accepted, else 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_exec_RR_ses(ctx: *mut OSSL_CMP_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        const F: &str = "OSSL_CMP_exec_RR_ses";
        const FN: &CStr = c"OSSL_CMP_exec_RR_ses";
        const NUM_REVDETAILS: c_int = 1;
        if ctx.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_INVALID_ARGS, F);
            return 0;
        }
        let c: *mut Ctx = ctx.cast();
        // SAFETY: the caller's context, for each access below.
        unsafe { (*c).status = OSSL_CMP_PKISTATUS_request };
        // SAFETY: as above.
        let cx = unsafe { &*c };
        let (old_cert, p10, serial, issuer) = (cx.oldCert, cx.p10CSR, cx.serialNumber, cx.issuer);
        if old_cert.is_null() && p10.is_null() && (serial.is_null() || issuer.is_null()) {
            err::raise(ERR_LIB_CMP, CMP_R_MISSING_REFERENCE_CERT, F);
            return 0;
        }

        let mut rp: *mut OSSL_CMP_MSG = ptr::null_mut();
        // rr_new() also checks that every option needed is set.
        // SAFETY: as above.
        let rr = unsafe { rr_new(ctx) };
        let mut ret = 0;
        // Whether OpenSSL's `err` label is reached (which adds the status to the error data
        // on failure), or only its `end`.
        let reached_err: bool = 'end: {
            if rr.is_null() {
                break 'end false;
            }
            // SAFETY: the context; the request made here; the room.
            if unsafe { send_receive_also_delayed(ctx, rr, &mut rp, PKIBODY_RP) } == 0 {
                break 'end false;
            }
            // SAFETY: the response's content.
            let rrep: *const RevRepContent = unsafe { body_value(rp) }.cast();
            // SAFETY: as above.
            let Some(r) = (unsafe { rrep.as_ref() }) else {
                break 'end false;
            };
            // SAFETY: its statuses.
            if unsafe { OPENSSL_sk_num(r.status) } != NUM_REVDETAILS {
                err::raise(ERR_LIB_CMP, CMP_R_WRONG_RP_COMPONENT_COUNT, F);
                break 'end false;
            }

            // The PKIStatus.
            // SAFETY: as above.
            let si = unsafe { revrepcontent_get_pkisi(rrep.cast_mut().cast(), REVREQSID) };
            // SAFETY: the context; the status, or NULL.
            if unsafe { save_statusInfo(ctx, si.cast()) } == 0 {
                break 'end true;
            }
            // SAFETY: the status.
            let status = unsafe { pkisi_get_status(si.cast()) };
            if status == OSSL_CMP_PKISTATUS_accepted {
                // SAFETY: as above.
                unsafe { log(OSSL_CMP_LOG_INFO, ctx, FN, "revocation accepted (PKIStatus=accepted)") };
                ret = 1;
            } else if status == OSSL_CMP_PKISTATUS_grantedWithMods {
                // SAFETY: as above.
                unsafe { log(OSSL_CMP_LOG_INFO, ctx, FN, "revocation accepted (PKIStatus=grantedWithMods)") };
                ret = 1;
            } else if status == OSSL_CMP_PKISTATUS_rejection {
                err::raise(ERR_LIB_CMP, CMP_R_REQUEST_REJECTED_BY_SERVER, F);
                break 'end true;
            } else if status == OSSL_CMP_PKISTATUS_revocationWarning {
                // SAFETY: as above.
                unsafe { log(OSSL_CMP_LOG_INFO, ctx, FN, "revocation accepted (PKIStatus=revocationWarning)") };
                ret = 1;
            } else if status == OSSL_CMP_PKISTATUS_revocationNotification {
                // Whether a warning or an error depends on the CA.
                // SAFETY: as above.
                unsafe { log(OSSL_CMP_LOG_WARNING, ctx, FN, "revocation accepted (PKIStatus=revocationNotification)") };
                ret = 1;
            } else if status == OSSL_CMP_PKISTATUS_waiting || status == OSSL_CMP_PKISTATUS_keyUpdateWarning {
                err::raise(ERR_LIB_CMP, CMP_R_UNEXPECTED_PKISTATUS, F);
                break 'end true;
            } else {
                err::raise(ERR_LIB_CMP, CMP_R_UNKNOWN_PKISTATUS, F);
                break 'end true;
            }

            // Any CertId in the optional revCerts.
            // SAFETY: the response's CertIds, or NULL.
            let n_certs = unsafe { OPENSSL_sk_num(r.revCerts) };
            if n_certs >= 1 {
                // SAFETY: the request's content.
                let details: *const Stack = unsafe { body_value(rr) }.cast();
                // SAFETY: its first RevDetails.
                let rd: *const RevDetails = unsafe { OPENSSL_sk_value(details, REVREQSID) }.cast();
                // SAFETY: as above, or NULL.
                let tmpl = unsafe { rd.as_ref() }.map_or(ptr::null_mut(), |d| d.certDetails);
                // SAFETY: the template, or NULL.
                let t_issuer = unsafe { OSSL_CRMF_CERTTEMPLATE_get0_issuer(tmpl) };
                // SAFETY: as above.
                let t_serial = unsafe { OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(tmpl) };
                if n_certs != NUM_REVDETAILS {
                    err::raise(ERR_LIB_CMP, CMP_R_WRONG_RP_COMPONENT_COUNT, F);
                    ret = 0;
                    break 'end true;
                }
                // SAFETY: the response.
                let cid = unsafe { revrepcontent_get_CertId(rrep.cast_mut().cast(), REVREQSID) };
                if cid.is_null() {
                    err::raise(ERR_LIB_CMP, CMP_R_MISSING_CERTID, F);
                    ret = 0;
                    break 'end true;
                }
                // No issuer and serial number when the certificate to revoke was given as a
                // PKCS #10 CSR: nothing to check the CertId against.
                if !t_issuer.is_null() {
                    // SAFETY: the CertId.
                    let c_issuer = unsafe { OSSL_CRMF_CERTID_get0_issuer(cid.cast()) };
                    // SAFETY: both names, or NULL.
                    if unsafe { X509_NAME_cmp(t_issuer, c_issuer) } != 0 {
                        err::raise(ERR_LIB_CMP, CMP_R_WRONG_CERTID_IN_RP, F);
                        ret = 0;
                        break 'end true;
                    }
                }
                if !t_serial.is_null() {
                    // SAFETY: the CertId.
                    let c_serial = unsafe { OSSL_CRMF_CERTID_get0_serialNumber(cid.cast()) };
                    // SAFETY: both serial numbers, or NULL.
                    if unsafe { ASN1_INTEGER_cmp(t_serial, c_serial) } != 0 {
                        err::raise(ERR_LIB_CMP, CMP_R_WRONG_SERIAL_IN_RP, F);
                        ret = 0;
                        break 'end true;
                    }
                }
            }

            // The number of any CRLs.
            // SAFETY: the response's CRLs.
            if !r.crls.is_null() && unsafe { OPENSSL_sk_num(r.crls) } != NUM_REVDETAILS {
                err::raise(ERR_LIB_CMP, CMP_R_WRONG_RP_COMPONENT_COUNT, F);
                ret = 0;
                break 'end true;
            }
            true
        };
        if reached_err && ret == 0 {
            // SAFETY: as above.
            unsafe { add_status_data(ctx) };
        }
        // SAFETY: made here, or NULL.
        unsafe { OSSL_CMP_MSG_free(rr) };
        // SAFETY: as above.
        unsafe { OSSL_CMP_MSG_free(rp) };
        ret
    }
}

ffi_export! {
    /// A general message transaction (genm with the context's ITAVs, genp): the response's
    /// ITAVs (an empty list if none), which the caller frees, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_exec_GENM_ses(ctx: *mut OSSL_CMP_CTX) -> *mut rustyssl_abi::stack_st_OSSL_CMP_ITAV
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        if ctx.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_INVALID_ARGS, "OSSL_CMP_exec_GENM_ses");
            return ptr::null_mut();
        }
        let c: *mut Ctx = ctx.cast();
        // SAFETY: the caller's context.
        unsafe { (*c).status = OSSL_CMP_PKISTATUS_request };
        let mut genp: *mut OSSL_CMP_MSG = ptr::null_mut();
        let mut itavs: *mut Stack = ptr::null_mut();
        // SAFETY: as above.
        let genm = unsafe { genm_new(ctx) };
        // SAFETY: the context; the request made here; the room.
        if !genm.is_null() && unsafe { send_receive_also_delayed(ctx, genm, &mut genp, PKIBODY_GENP) } != 0 {
            // SAFETY: as above.
            unsafe { (*c).status = OSSL_CMP_PKISTATUS_accepted };
            // SAFETY: the response's body (a genp, checked above).
            let body = unsafe { (*genp.cast::<Msg>()).body };
            // SAFETY: as above.
            itavs = unsafe { (*body).value }.cast();
            if itavs.is_null() {
                // SAFETY: no preconditions.
                itavs = unsafe { OPENSSL_sk_new_null() };
            }
            // The ITAVs aren't freed with the response.
            // SAFETY: as above.
            unsafe { (*body).value = ptr::null_mut() };
        }
        // SAFETY: made here, or NULL.
        unsafe { OSSL_CMP_MSG_free(genm) };
        // SAFETY: as above.
        unsafe { OSSL_CMP_MSG_free(genp) };
        itavs.cast()
    }
}

/// Whether a response to polling says `waiting` again: a certificate response or an error.
///
/// # Safety
/// `prep` is a live message.
unsafe fn waiting_again(prep: *const OSSL_CMP_MSG, rid: c_int) -> bool {
    // SAFETY: the caller's guarantee.
    (unsafe { is_crep_with_waiting(prep, rid) })
        // SAFETY: as above.
        || unsafe { is_error_with_waiting(prep) } != 0
}
