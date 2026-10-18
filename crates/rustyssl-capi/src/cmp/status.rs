//! CMP's PKIStatusInfo (`cmp_status.c`): its status, failure info, and status strings; their
//! human-readable text; and making one.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;

use rustyssl_abi::{
    ASN1_UTF8STRING, CMP_R_ERROR_PARSING_PKISTATUS, CMP_R_NULL_ARGUMENT, ERR_LIB_CMP, OSSL_CMP_CTX,
    OSSL_CMP_PKIFAILUREINFO_MAX, OSSL_CMP_PKIFAILUREINFO_addInfoNotAvailable,
    OSSL_CMP_PKIFAILUREINFO_badAlg, OSSL_CMP_PKIFAILUREINFO_badCertId,
    OSSL_CMP_PKIFAILUREINFO_badCertTemplate, OSSL_CMP_PKIFAILUREINFO_badDataFormat,
    OSSL_CMP_PKIFAILUREINFO_badMessageCheck, OSSL_CMP_PKIFAILUREINFO_badPOP,
    OSSL_CMP_PKIFAILUREINFO_badRecipientNonce, OSSL_CMP_PKIFAILUREINFO_badRequest,
    OSSL_CMP_PKIFAILUREINFO_badSenderNonce, OSSL_CMP_PKIFAILUREINFO_badTime,
    OSSL_CMP_PKIFAILUREINFO_certConfirmed, OSSL_CMP_PKIFAILUREINFO_certRevoked,
    OSSL_CMP_PKIFAILUREINFO_duplicateCertReq, OSSL_CMP_PKIFAILUREINFO_incorrectData,
    OSSL_CMP_PKIFAILUREINFO_missingTimeStamp, OSSL_CMP_PKIFAILUREINFO_notAuthorized,
    OSSL_CMP_PKIFAILUREINFO_signerNotTrusted, OSSL_CMP_PKIFAILUREINFO_systemFailure,
    OSSL_CMP_PKIFAILUREINFO_systemUnavail, OSSL_CMP_PKIFAILUREINFO_timeNotAvailable,
    OSSL_CMP_PKIFAILUREINFO_transactionIdInUse, OSSL_CMP_PKIFAILUREINFO_unacceptedExtension,
    OSSL_CMP_PKIFAILUREINFO_unacceptedPolicy, OSSL_CMP_PKIFAILUREINFO_unsupportedVersion,
    OSSL_CMP_PKIFAILUREINFO_wrongAuthority, OSSL_CMP_PKIFAILUREINFO_wrongIntegrity, OSSL_CMP_PKISI,
    OSSL_CMP_PKISTATUS_accepted, OSSL_CMP_PKISTATUS_grantedWithMods,
    OSSL_CMP_PKISTATUS_keyUpdateWarning, OSSL_CMP_PKISTATUS_rejection,
    OSSL_CMP_PKISTATUS_revocationNotification, OSSL_CMP_PKISTATUS_revocationWarning,
    OSSL_CMP_PKISTATUS_waiting,
};

use super::asn::{OSSL_CMP_PKISI_free, OSSL_CMP_PKISI_new, PkiSi, Stack, asn1_get_int, of};
use super::ctx::{
    OSSL_CMP_CTX_get_failInfoCode, OSSL_CMP_CTX_get_status, OSSL_CMP_CTX_get0_statusString,
};
use crate::asn1::bit_string::{ASN1_BIT_STRING_get_bit, ASN1_BIT_STRING_set_bit};
use crate::asn1::integer::{ASN1_INTEGER_get, ASN1_INTEGER_set};
use crate::asn1::string::{
    ASN1_BIT_STRING_new, ASN1_STRING_get0_data, ASN1_STRING_length, ASN1_STRING_set,
    ASN1_UTF8STRING_free, ASN1_UTF8STRING_new,
};
use crate::err;
use crate::ffi::ffi_export;
use crate::stack::{OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value};

/// The PKIStatusInfo behind a handle.
///
/// # Safety
/// `si` is NULL or a live PKIStatusInfo, not otherwise borrowed mutably.
unsafe fn si_of<'a>(si: *const OSSL_CMP_PKISI) -> Option<&'a mut PkiSi> {
    // SAFETY: the caller's guarantee.
    unsafe { of::<PkiSi, _>(si) }
}

/// `ossl_cmp_pkisi_get_status`: the status, or -1.
///
/// # Safety
/// `si` is NULL or a live PKIStatusInfo.
pub(crate) unsafe fn pkisi_get_status(si: *const OSSL_CMP_PKISI) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { si_of(si) }) else {
        return -1;
    };
    if s.status.is_null() {
        return -1;
    }
    // SAFETY: its status.
    let res = unsafe { asn1_get_int(s.status) };
    if res == -2 { -1 } else { res }
}

/// `ossl_cmp_PKIStatus_to_string`: the status's static NUL-terminated text, or NULL (raising)
/// for an unknown one.
pub(crate) fn PKIStatus_to_string(status: c_int) -> *const c_char {
    status_text(status).map_or(ptr::null(), CStr::as_ptr)
}

/// [`PKIStatus_to_string`] as a `CStr`.
fn status_text(status: c_int) -> Option<&'static CStr> {
    Some(match status {
        OSSL_CMP_PKISTATUS_accepted => c"PKIStatus: accepted",
        OSSL_CMP_PKISTATUS_grantedWithMods => c"PKIStatus: granted with modifications",
        OSSL_CMP_PKISTATUS_rejection => c"PKIStatus: rejection",
        OSSL_CMP_PKISTATUS_waiting => c"PKIStatus: waiting",
        OSSL_CMP_PKISTATUS_revocationWarning => {
            c"PKIStatus: revocation warning - a revocation of the cert is imminent"
        }
        OSSL_CMP_PKISTATUS_revocationNotification => {
            c"PKIStatus: revocation notification - a revocation of the cert has occurred"
        }
        OSSL_CMP_PKISTATUS_keyUpdateWarning => {
            c"PKIStatus: key update warning - update already done for the cert"
        }
        _ => {
            err::raise_with_text(
                ERR_LIB_CMP,
                CMP_R_ERROR_PARSING_PKISTATUS,
                "ossl_cmp_PKIStatus_to_string",
                &format!("PKIStatus: invalid={status}"),
            );
            return None;
        }
    })
}

/// `ossl_cmp_pkisi_get_pkifailureinfo`: the failure info's bits as a number, or -1.
///
/// # Safety
/// `si` is NULL or a live PKIStatusInfo.
pub(crate) unsafe fn pkisi_get_pkifailureinfo(si: *const OSSL_CMP_PKISI) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { si_of(si) }) else {
        return -1;
    };
    let mut res = 0;
    if !s.failInfo.is_null() {
        for i in 0..=OSSL_CMP_PKIFAILUREINFO_MAX {
            // SAFETY: its failure info.
            if unsafe { ASN1_BIT_STRING_get_bit(s.failInfo, i) } != 0 {
                res |= 1 << i;
            }
        }
    }
    res
}

/// `CMP_PKIFAILUREINFO_to_string`: a failure bit's name.
fn failure_name(number: c_int) -> Option<&'static str> {
    Some(match number {
        OSSL_CMP_PKIFAILUREINFO_badAlg => "badAlg",
        OSSL_CMP_PKIFAILUREINFO_badMessageCheck => "badMessageCheck",
        OSSL_CMP_PKIFAILUREINFO_badRequest => "badRequest",
        OSSL_CMP_PKIFAILUREINFO_badTime => "badTime",
        OSSL_CMP_PKIFAILUREINFO_badCertId => "badCertId",
        OSSL_CMP_PKIFAILUREINFO_badDataFormat => "badDataFormat",
        OSSL_CMP_PKIFAILUREINFO_wrongAuthority => "wrongAuthority",
        OSSL_CMP_PKIFAILUREINFO_incorrectData => "incorrectData",
        OSSL_CMP_PKIFAILUREINFO_missingTimeStamp => "missingTimeStamp",
        OSSL_CMP_PKIFAILUREINFO_badPOP => "badPOP",
        OSSL_CMP_PKIFAILUREINFO_certRevoked => "certRevoked",
        OSSL_CMP_PKIFAILUREINFO_certConfirmed => "certConfirmed",
        OSSL_CMP_PKIFAILUREINFO_wrongIntegrity => "wrongIntegrity",
        OSSL_CMP_PKIFAILUREINFO_badRecipientNonce => "badRecipientNonce",
        OSSL_CMP_PKIFAILUREINFO_timeNotAvailable => "timeNotAvailable",
        OSSL_CMP_PKIFAILUREINFO_unacceptedPolicy => "unacceptedPolicy",
        OSSL_CMP_PKIFAILUREINFO_unacceptedExtension => "unacceptedExtension",
        OSSL_CMP_PKIFAILUREINFO_addInfoNotAvailable => "addInfoNotAvailable",
        OSSL_CMP_PKIFAILUREINFO_badSenderNonce => "badSenderNonce",
        OSSL_CMP_PKIFAILUREINFO_badCertTemplate => "badCertTemplate",
        OSSL_CMP_PKIFAILUREINFO_signerNotTrusted => "signerNotTrusted",
        OSSL_CMP_PKIFAILUREINFO_transactionIdInUse => "transactionIdInUse",
        OSSL_CMP_PKIFAILUREINFO_unsupportedVersion => "unsupportedVersion",
        OSSL_CMP_PKIFAILUREINFO_notAuthorized => "notAuthorized",
        OSSL_CMP_PKIFAILUREINFO_systemUnavail => "systemUnavail",
        OSSL_CMP_PKIFAILUREINFO_systemFailure => "systemFailure",
        OSSL_CMP_PKIFAILUREINFO_duplicateCertReq => "duplicateCertReq",
        _ => return None,
    })
}

/// The caller's buffer as `BIO_snprintf` fills it: each piece written after the last, cut to
/// fit with a NUL; a piece that doesn't fit whole fails the text, as in OpenSSL.
struct Buffer {
    at: *mut c_char,
    left: usize,
}

impl Buffer {
    /// Writes `piece` (and a NUL); `None` if it didn't fit whole.
    ///
    /// # Safety
    /// `at` has room for `left` octets.
    unsafe fn put(&mut self, piece: &[u8]) -> Option<()> {
        if self.left == 0 {
            return None;
        }
        let n = piece.len().min(self.left - 1);
        // SAFETY: room for `n` octets and a NUL, as the caller guarantees.
        unsafe { ptr::copy_nonoverlapping(piece.as_ptr(), self.at.cast::<u8>(), n) };
        // SAFETY: as above.
        let end = unsafe { self.at.add(n) };
        // SAFETY: as above.
        unsafe { end.write(0) };
        if piece.len() >= self.left {
            return None;
        }
        // SAFETY: within the buffer.
        self.at = unsafe { self.at.add(n) };
        self.left -= n;
        Some(())
    }
}

/// `snprint_PKIStatusInfo_parts`: the text into `buf`, or NULL.
///
/// # Safety
/// `buf` is NULL or has room for `bufsize` octets; `status_strings` NULL or a live list of
/// strings.
unsafe fn snprint_parts(
    status: c_int,
    fail_info: c_int,
    status_strings: *const Stack,
    buf: *mut c_char,
    bufsize: usize,
) -> *mut c_char {
    if buf.is_null() || status < 0 {
        return ptr::null_mut();
    }
    let Some(status_string) = status_text(status) else {
        return ptr::null_mut();
    };
    let mut out = Buffer {
        at: buf,
        left: bufsize,
    };
    // Writes a piece, failing the text if it doesn't fit.
    macro_rules! put {
        ($piece:expr) => {
            // SAFETY: the caller's buffer, which `out` tracks.
            if unsafe { out.put($piece) }.is_none() {
                return ptr::null_mut();
            }
        };
    }
    put!(status_string.to_bytes());
    // failInfo before statusString, being more concise.
    let mut failinfo_found = false;
    if fail_info != -1 && fail_info != 0 {
        put!(b"; PKIFailureInfo: ");
        for failure in 0..=OSSL_CMP_PKIFAILUREINFO_MAX {
            if fail_info & (1 << failure) != 0
                && let Some(name) = failure_name(failure)
            {
                let piece = format!("{}{name}", if failinfo_found { ", " } else { "" });
                put!(piece.as_bytes());
                failinfo_found = true;
            }
        }
    }
    if !failinfo_found
        && status != OSSL_CMP_PKISTATUS_accepted
        && status != OSSL_CMP_PKISTATUS_grantedWithMods
    {
        put!(b"; <no failure info>");
    }
    // SAFETY: the caller's list, or NULL (0).
    let n = unsafe { OPENSSL_sk_num(status_strings) };
    if n > 0 {
        let piece = format!("; StatusString{}: ", if n > 1 { "s" } else { "" });
        put!(piece.as_bytes());
        for i in 0..n {
            // SAFETY: an index in range.
            let text = unsafe { OPENSSL_sk_value(status_strings, i) }.cast::<ASN1_UTF8STRING>();
            let mut piece = vec![b'"'];
            // SAFETY: a string of the list.
            piece.extend(unsafe { precision_text(text) });
            piece.push(b'"');
            if i < n - 1 {
                piece.extend(b", ");
            }
            put!(&piece);
        }
    }
    buf
}

/// `"%.*s"` of a string's length and data: up to its length, stopping at a NUL (the whole
/// NUL-terminated data for a negative length); "(null)" for no data, as BIO_snprintf prints.
///
/// # Safety
/// `text` is NULL or a live string.
unsafe fn precision_text(text: *const ASN1_UTF8STRING) -> Vec<u8> {
    // SAFETY: the caller's guarantee.
    let len = unsafe { ASN1_STRING_length(text) };
    // SAFETY: as above.
    let data = unsafe { ASN1_STRING_get0_data(text) };
    if data.is_null() {
        return b"(null)".to_vec();
    }
    let limit = usize::try_from(len).ok();
    let mut out = Vec::new();
    let mut i = 0usize;
    while limit.is_none_or(|l| i < l) {
        // SAFETY: within the string's data or its terminating NUL, which stops the loop.
        let p = unsafe { data.add(i) };
        // SAFETY: as above.
        let b = unsafe { p.read() };
        if b == 0 {
            break;
        }
        out.push(b);
        i += 1;
    }
    out
}

ffi_export! {
    /// The PKIStatusInfo's text (status, failure info, status strings) in `buf`: `buf`, or NULL.
    ///
    /// # Safety
    /// `statusInfo` is NULL or a live PKIStatusInfo; `buf` NULL or room for `bufsize` octets.
    pub unsafe extern "C" fn OSSL_CMP_snprint_PKIStatusInfo(statusInfo: *const OSSL_CMP_PKISI, buf: *mut c_char, bufsize: usize) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { si_of(statusInfo) }) else {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, "OSSL_CMP_snprint_PKIStatusInfo");
            return ptr::null_mut();
        };
        // SAFETY: the caller's PKIStatusInfo.
        let failure_info = unsafe { pkisi_get_pkifailureinfo(statusInfo) };
        // SAFETY: its status.
        let status = unsafe { ASN1_INTEGER_get(s.status) };
        // OpenSSL converts the long to int; a status beyond an int is invalid either way.
        let status = c_int::try_from(status).unwrap_or(-1);
        // SAFETY: its strings; the caller's buffer.
        unsafe { snprint_parts(status, failure_info, s.statusString, buf, bufsize) }
    }
}

ffi_export! {
    /// The context's last status, failure info, and status strings as text in `buf`: `buf`, or
    /// NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `buf` NULL or room for `bufsize` octets.
    pub unsafe extern "C" fn OSSL_CMP_CTX_snprint_PKIStatus(ctx: *const OSSL_CMP_CTX, buf: *mut c_char, bufsize: usize) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        if ctx.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, "OSSL_CMP_CTX_snprint_PKIStatus");
            return ptr::null_mut();
        }
        // SAFETY: the caller's context, for each getter.
        let status = unsafe { OSSL_CMP_CTX_get_status(ctx) };
        // SAFETY: as above.
        let fail_info = unsafe { OSSL_CMP_CTX_get_failInfoCode(ctx) };
        // SAFETY: as above.
        let strings = unsafe { OSSL_CMP_CTX_get0_statusString(ctx) };
        // SAFETY: the context's strings; the caller's buffer.
        unsafe { snprint_parts(status, fail_info, strings.cast(), buf, bufsize) }
    }
}

ffi_export! {
    /// A new PKIStatusInfo of `status`, the failure bits of `fail_info`, and `text` (if not
    /// NULL) as its status string; or NULL.
    ///
    /// # Safety
    /// `text` is NULL or a NUL-terminated string.
    pub unsafe extern "C" fn OSSL_CMP_STATUSINFO_new(status: c_int, fail_info: c_int, text: *const c_char) -> *mut OSSL_CMP_PKISI
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: no preconditions.
        let si = unsafe { OSSL_CMP_PKISI_new() };
        let mut utf8_text: *mut ASN1_UTF8STRING = ptr::null_mut();
        let ok = 'm: {
            // SAFETY: the new PKIStatusInfo, or NULL.
            let Some(s) = (unsafe { si_of(si) }) else {
                break 'm false;
            };
            // SAFETY: its status.
            if unsafe { ASN1_INTEGER_set(s.status, status.into()) } == 0 {
                break 'm false;
            }
            if !text.is_null() {
                // SAFETY: no preconditions.
                utf8_text = unsafe { ASN1_UTF8STRING_new() };
                // SAFETY: the new string; the caller's NUL-terminated text.
                if utf8_text.is_null() || unsafe { ASN1_STRING_set(utf8_text, text.cast(), -1) } == 0 {
                    break 'm false;
                }
                // SAFETY: no preconditions.
                s.statusString = unsafe { OPENSSL_sk_new_null() };
                if s.statusString.is_null() {
                    break 'm false;
                }
                // SAFETY: the new list; the string, which it takes.
                if unsafe { OPENSSL_sk_push(s.statusString, utf8_text.cast()) } == 0 {
                    break 'm false;
                }
                utf8_text = ptr::null_mut();
            }
            for failure in 0..=OSSL_CMP_PKIFAILUREINFO_MAX {
                if fail_info & (1 << failure) != 0 {
                    if s.failInfo.is_null() {
                        // SAFETY: no preconditions.
                        s.failInfo = unsafe { ASN1_BIT_STRING_new() };
                        if s.failInfo.is_null() {
                            break 'm false;
                        }
                    }
                    // SAFETY: its failure info.
                    if unsafe { ASN1_BIT_STRING_set_bit(s.failInfo, failure, 1) } == 0 {
                        break 'm false;
                    }
                }
            }
            true
        };
        if ok {
            return si;
        }
        // SAFETY: made here, or NULL.
        unsafe { OSSL_CMP_PKISI_free(si) };
        // SAFETY: made here and not taken, or NULL.
        unsafe { ASN1_UTF8STRING_free(utf8_text) };
        ptr::null_mut()
    }
}
