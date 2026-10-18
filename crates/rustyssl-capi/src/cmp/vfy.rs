//! Checking received CMP messages (`cmp_vfy.c`): their protection, by password-based MAC or
//! by signature with a pinned server certificate or one found among the extra, untrusted, and
//! trusted certificates (whose path is validated, with the 3GPP exception of trusting a
//! self-issued extra certificate in an IP); the sender, transaction ID, and nonces; and the
//! proof-of-possession of requests.

use core::ffi::{CStr, c_char, c_int, c_ulong};
use core::ptr;

use rustyssl_abi::{
    ASN1_OCTET_STRING, CMP_R_ERROR_VALIDATING_PROTECTION, CMP_R_ERROR_VALIDATING_SIGNATURE,
    CMP_R_FAILED_EXTRACTING_PUBKEY, CMP_R_MISSING_KEY_USAGE_DIGITALSIGNATURE,
    CMP_R_MISSING_PROTECTION, CMP_R_MISSING_SECRET, CMP_R_MISSING_TRUST_ANCHOR,
    CMP_R_MISSING_TRUST_STORE, CMP_R_NO_SUITABLE_SENDER_CERT, CMP_R_NULL_ARGUMENT,
    CMP_R_PKIBODY_ERROR, CMP_R_POTENTIALLY_INVALID_CERTIFICATE, CMP_R_RECIPNONCE_UNMATCHED,
    CMP_R_REQUEST_NOT_ACCEPTED, CMP_R_SENDER_GENERALNAME_TYPE_NOT_SUPPORTED,
    CMP_R_SRVCERT_DOES_NOT_VALIDATE_MSG, CMP_R_TRANSACTIONID_UNMATCHED, CMP_R_UNEXPECTED_PVNO,
    CMP_R_UNEXPECTED_SENDER, CMP_R_UNSUPPORTED_PROTECTION_ALG_DHBASEDMAC, CMP_R_WRONG_PBM_VALUE,
    ERR_LIB_CMP, GEN_DIRNAME, NID_id_DHBasedMac, NID_id_PasswordBasedMAC, OSSL_CMP_CTX,
    OSSL_CMP_LOG_DEBUG, OSSL_CMP_LOG_INFO, OSSL_CMP_LOG_WARNING, OSSL_CMP_MSG, OSSL_CMP_PVNO_2,
    OSSL_CMP_PVNO_3, OSSL_CMP_severity, X509, X509_ADD_FLAG_NO_DUP, X509_ADD_FLAG_PREPEND,
    X509_ADD_FLAG_UP_REF, X509_FLAG_NO_EXTENSIONS, X509_NAME, X509_REQ, X509_STORE,
    X509_V_ERR_CERT_HAS_EXPIRED, X509_V_ERR_CERT_NOT_YET_VALID, X509_V_OK,
    X509v3_KU_DIGITAL_SIGNATURE,
};

use super::asn::{
    CERTREQID, CertRepMessage, Msg, PKIBODY_CCP, PKIBODY_CP, PKIBODY_CR, PKIBODY_IP, PKIBODY_IR,
    PKIBODY_KUP, PKIBODY_KUR, PKIBODY_P10CR, PKIBODY_POLLREP, PkiHeader, ProtectedPart, Stack, of,
    protectedpart_it,
};
use super::ctx::{
    OSSL_CMP_CTX_print_errors, OSSL_CMP_CTX_set1_transactionID, ctx_of, ctx_set1_recipNonce,
    ctx_set1_validatedSrvCert, print_log,
};
use super::hdr::{hdr_get_protection_nid, hdr_get_pvno};
use super::msg::{
    OSSL_CMP_MSG_get_bodytype, OSSL_CMP_MSG_get0_header, certrepmessage_get0_certresponse,
    certresponse_get1_cert,
};
use super::protect::{add_certs_new, calc_protection};
use super::util::X509_STORE_add1_certs;
use crate::asn1::sign::ASN1_item_verify_ex;
use crate::asn1::string::{ASN1_BIT_STRING_free, ASN1_OCTET_STRING_cmp};
use crate::bio::mem::BIO_s_mem;
use crate::bio::{BIO_free, BIO_new};
use crate::crmf::msg::OSSL_CRMF_MSGS_verify_popo;
use crate::err::strings::ERR_add_error_mem_bio;
use crate::err::{
    self, ERR_add_error_txt, ERR_clear_last_mark, ERR_peek_last_error, ERR_pop_to_mark,
    ERR_set_mark,
};
use crate::evp::pkey::EVP_PKEY_free;
use crate::ffi::ffi_export;
use crate::mem::{self, CRYPTO_memcmp};
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_shift, OPENSSL_sk_value};
use crate::x509::cert::{
    OSSL_STACK_OF_X509_free, X509_free, X509_get_issuer_name, X509_get_pubkey,
    X509_get_subject_name, X509_get0_notAfter, X509_get0_notBefore,
};
use crate::x509::ctx::{
    X509_STORE_CTX_free, X509_STORE_CTX_init, X509_STORE_CTX_new, X509_STORE_CTX_new_ex,
    X509_STORE_CTX_set_current_cert, X509_STORE_CTX_set_error, X509_cmp_timeframe,
};
use crate::x509::name::{X509_NAME_cmp, X509_NAME_oneline};
use crate::x509::purpose::{
    X509_check_issued, X509_cmp, X509_get_key_usage, X509_get0_subject_key_id, cache_extensions,
};
use crate::x509::req::{X509_REQ_get0_pubkey, X509_REQ_verify_ex};
use crate::x509::store::{
    X509_STORE_free, X509_STORE_get_verify_cb, X509_STORE_get0_param, X509_STORE_get1_all_certs,
    X509_STORE_new,
};
use crate::x509::tprint::print_ex_brief;
use crate::x509::verify::X509_verify_cert;
use crate::x509v3::i2s_ASN1_OCTET_STRING;

/// `ossl_cmp_allow_unprotected_cb_t`: whether a message whose protection is missing (`0`) or
/// invalid (`1`) may pass anyway, given the caller's argument; positive for yes.
pub(crate) type AllowUnprotectedCb =
    Option<unsafe fn(*const OSSL_CMP_CTX, *const OSSL_CMP_MSG, c_int, c_int) -> c_int>;

/// Logs `msg` from `func` at `level` (see [`print_log`]).
///
/// # Safety
/// `ctx` is NULL or a live context.
#[track_caller]
unsafe fn log(level: OSSL_CMP_severity, ctx: *const OSSL_CMP_CTX, func: &CStr, msg: &str) {
    // SAFETY: the caller's guarantee.
    unsafe { print_log(level, ctx, func, msg) };
}

/// Takes a CRYPTO_malloc'd C string: its text, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a NUL-terminated string from CRYPTO_malloc, not used after.
unsafe fn take_string(s: *mut c_char) -> Option<String> {
    if s.is_null() {
        return None;
    }
    // SAFETY: the caller's guarantee.
    let text = unsafe { CStr::from_ptr(s) }.to_string_lossy().into_owned();
    // SAFETY: as above, freed once.
    unsafe { mem::release(s.cast()) };
    Some(text)
}

/// `X509_NAME_oneline(name, NULL, 0)`, or `None`.
///
/// # Safety
/// `name` is NULL or a live name.
unsafe fn oneline(name: *const X509_NAME) -> Option<String> {
    // SAFETY: the caller's name; a new buffer.
    let s = unsafe { X509_NAME_oneline(name, ptr::null_mut(), 0) };
    // SAFETY: the new string, or NULL.
    unsafe { take_string(s) }
}

/// `i2s_ASN1_OCTET_STRING(NULL, oct)`: the octets in colon-separated hex, or `None`.
///
/// # Safety
/// `oct` is a live string.
unsafe fn hex_string(oct: *const ASN1_OCTET_STRING) -> Option<String> {
    // SAFETY: the caller's string.
    let s = unsafe { i2s_ASN1_OCTET_STRING(ptr::null_mut(), oct) };
    // SAFETY: the new string, or NULL.
    unsafe { take_string(s) }
}

/// The directory name of a header's sender (whose type the callers checked or trust).
///
/// # Safety
/// `h` is a live header with a sender.
unsafe fn sender_dn(h: &PkiHeader) -> *mut X509_NAME {
    // SAFETY: the caller's guarantee.
    let g = unsafe { &*h.sender };
    // SAFETY: the union's directory name (a pointer whatever the type).
    unsafe { g.d.directoryName }
}

/// `verify_signature`: the message's signature (over its protected part) verified with the
/// certificate's key, which must allow digitalSignature unless the context ignores key usage.
/// On failure an `CMP_R_ERROR_VALIDATING_SIGNATURE` error carries the certificate in brief.
///
/// # Safety
/// `ctx`, `msg`, and `cert` are NULL or live.
unsafe fn verify_signature(
    ctx: *const OSSL_CMP_CTX,
    msg: *const OSSL_CMP_MSG,
    cert: *mut X509,
) -> bool {
    const F: &str = "verify_signature";
    // SAFETY: the caller's guarantee.
    let (Some(c), Some(m)) = (unsafe { ctx_of(ctx) }, unsafe { of::<Msg, _>(msg) }) else {
        return false;
    };
    if cert.is_null() {
        return false;
    }
    // SAFETY: no preconditions.
    let meth = unsafe { BIO_s_mem() };
    // SAFETY: the built-in method.
    let bio = unsafe { BIO_new(meth) };
    if bio.is_null() {
        return false;
    }
    let mut pubkey = ptr::null_mut();
    let mut res = false;
    'sig_err: {
        let ku = u32::try_from(X509v3_KU_DIGITAL_SIGNATURE).unwrap_or(0);
        // SAFETY: the caller's certificate.
        if c.ignore_keyusage == 0 && unsafe { X509_get_key_usage(cert) } & ku == 0 {
            err::raise(ERR_LIB_CMP, CMP_R_MISSING_KEY_USAGE_DIGITALSIGNATURE, F);
            break 'sig_err;
        }
        // SAFETY: as above.
        pubkey = unsafe { X509_get_pubkey(cert) };
        if pubkey.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_FAILED_EXTRACTING_PUBKEY, F);
            break 'sig_err;
        }
        let prot_part = ProtectedPart {
            header: m.header,
            body: m.body,
        };
        // SAFETY: no preconditions.
        let it = unsafe { protectedpart_it() };
        // SAFETY: the message's header.
        let alg = unsafe { (*m.header).protectionAlg };
        // SAFETY: the protected part's item and value; the header's algorithm and the
        // message's protection; the key; the context's library context and properties.
        if unsafe {
            ASN1_item_verify_ex(
                it,
                alg,
                m.protection,
                ptr::from_ref(&prot_part).cast(),
                ptr::null(),
                pubkey,
                c.libctx,
                c.propq,
            )
        } > 0
        {
            res = true;
        }
    }
    if !res {
        let flags = c_ulong::try_from(X509_FLAG_NO_EXTENSIONS).unwrap_or(0);
        // SAFETY: the memory BIO; the caller's certificate.
        let printed = unsafe { print_ex_brief(bio, cert, flags) };
        err::raise(ERR_LIB_CMP, CMP_R_ERROR_VALIDATING_SIGNATURE, F);
        if printed {
            // SAFETY: no separator; a static string.
            unsafe { ERR_add_error_txt(ptr::null(), c"\n".as_ptr()) };
            // SAFETY: as above; the BIO with the certificate printed.
            unsafe { ERR_add_error_mem_bio(ptr::null(), bio) };
        }
    }
    // SAFETY: from X509_get_pubkey, or NULL.
    unsafe { EVP_PKEY_free(pubkey) };
    // SAFETY: made above.
    unsafe { BIO_free(bio) };
    res
}

/// `verify_PBMAC`: the message's protection compared, in constant time, with the MAC computed
/// afresh; `CMP_R_WRONG_PBM_VALUE` if they differ.
///
/// # Safety
/// `ctx` and `msg` are NULL or live.
unsafe fn verify_PBMAC(ctx: *mut OSSL_CMP_CTX, msg: *const OSSL_CMP_MSG) -> bool {
    // SAFETY: the caller's guarantee.
    let protection = unsafe { calc_protection(ctx, msg) };
    // SAFETY: the new string, or NULL.
    let Some(expected) = (unsafe { protection.as_ref() }) else {
        return false;
    };
    // SAFETY: the caller's message.
    let got = unsafe { of::<Msg, _>(msg) }.and_then(|m| {
        // SAFETY: its protection, or NULL.
        unsafe { m.protection.as_ref() }
    });
    let valid = got.is_some_and(|g| {
        g.length >= 0
            && g.type_ == expected.type_
            && g.length == expected.length
            && usize::try_from(expected.length).is_ok_and(|n| {
                // SAFETY: both strings' `n` octets.
                (unsafe { CRYPTO_memcmp(g.data.cast(), expected.data.cast(), n) }) == 0
            })
    });
    // SAFETY: made above.
    unsafe { ASN1_BIT_STRING_free(protection) };
    if !valid {
        err::raise(ERR_LIB_CMP, CMP_R_WRONG_PBM_VALUE, "verify_PBMAC");
    }
    valid
}

ffi_export! {
    /// Validates the certificate's path to `trusted_store` (with the context's untrusted
    /// certificates as intermediates): 1, or 0 with at least
    /// `CMP_R_POTENTIALLY_INVALID_CERTIFICATE` queued. Fresh errors are printed through the
    /// context's log callback either way.
    ///
    /// # Safety
    /// `ctx`, `trusted_store`, and `cert` are NULL or live.
    pub unsafe extern "C" fn OSSL_CMP_validate_cert_path(ctx: *const OSSL_CMP_CTX, trusted_store: *mut X509_STORE, cert: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        const F: &str = "OSSL_CMP_validate_cert_path";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, F);
            return 0;
        };
        if cert.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, F);
            return 0;
        }
        if trusted_store.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_MISSING_TRUST_STORE, F);
            return 0;
        }
        let mut valid = false;
        // SAFETY: the context's library context and properties.
        let csc = unsafe { X509_STORE_CTX_new_ex(c.libctx, c.propq) };
        // SAFETY: the new context; the caller's store and certificate; the untrusted
        // certificates, or NULL.
        if !csc.is_null() && unsafe { X509_STORE_CTX_init(csc, trusted_store, cert, c.untrusted.cast()) } != 0 {
            // SAFETY: the initialized context.
            valid = unsafe { X509_verify_cert(csc) } > 0;
            // A suitable error queued even if the verify callback didn't.
            // SAFETY: no preconditions.
            let e = unsafe { ERR_peek_last_error() };
            if !valid && err::reason_of(e) != CMP_R_POTENTIALLY_INVALID_CERTIFICATE {
                err::raise(ERR_LIB_CMP, CMP_R_POTENTIALLY_INVALID_CERTIFICATE, F);
            }
        }
        // Printed now, as check_msg_find_cert needs.
        // SAFETY: the caller's context.
        unsafe { OSSL_CMP_CTX_print_errors(ctx) };
        // SAFETY: made above, or NULL.
        unsafe { X509_STORE_CTX_free(csc) };
        c_int::from(valid)
    }
}

/// `verify_cb_cert`: the store's verify callback asked about `err` for the certificate (0 if
/// it has none).
///
/// # Safety
/// `ts` is NULL or a live store; `cert` a live certificate.
unsafe fn verify_cb_cert(ts: *mut X509_STORE, cert: *mut X509, err: c_int) -> c_int {
    if ts.is_null() {
        return 0;
    }
    // SAFETY: the caller's store.
    let Some(verify_cb) = (unsafe { X509_STORE_get_verify_cb(ts) }) else {
        return 0;
    };
    let mut ok = 0;
    // SAFETY: no preconditions.
    let csc = unsafe { X509_STORE_CTX_new() };
    // SAFETY: the new context; the store and certificate.
    if !csc.is_null() && unsafe { X509_STORE_CTX_init(csc, ts, cert, ptr::null_mut()) } != 0 {
        // SAFETY: the initialized context.
        unsafe { X509_STORE_CTX_set_error(csc, err) };
        // SAFETY: as above.
        unsafe { X509_STORE_CTX_set_current_cert(csc, cert) };
        // SAFETY: the application's callback with the context; no lock is held.
        ok = unsafe { verify_cb(0, csc) };
    }
    // SAFETY: made above, or NULL.
    unsafe { X509_STORE_CTX_free(csc) };
    ok
}

/// `check_name`: whether `actual_name` matches `expect_name` (trivially when there is no
/// expectation), logging the outcome.
///
/// # Safety
/// `ctx` is NULL or live; the names NULL or live.
unsafe fn check_name(
    ctx: *const OSSL_CMP_CTX,
    log_success: bool,
    actual_desc: &str,
    actual_name: *const X509_NAME,
    expect_desc: &str,
    expect_name: *const X509_NAME,
) -> bool {
    const FUNC: &CStr = c"check_name";
    if expect_name.is_null() {
        return true;
    }
    if actual_name.is_null() {
        // SAFETY: the caller's context.
        unsafe {
            log(
                OSSL_CMP_LOG_WARNING,
                ctx,
                FUNC,
                &format!("missing {actual_desc}"),
            )
        };
        return false;
    }
    // SAFETY: the caller's name.
    let s = unsafe { oneline(actual_name) };
    // SAFETY: both names.
    if unsafe { X509_NAME_cmp(actual_name, expect_name) } == 0 {
        if let (true, Some(s)) = (log_success, &s) {
            // SAFETY: the caller's context.
            unsafe {
                log(
                    OSSL_CMP_LOG_INFO,
                    ctx,
                    FUNC,
                    &format!(" {actual_desc} matches {expect_desc}: {s}"),
                )
            };
        }
        return true;
    }
    if let Some(s) = s {
        // SAFETY: the caller's context.
        unsafe {
            log(
                OSSL_CMP_LOG_INFO,
                ctx,
                FUNC,
                &format!(" actual name in {actual_desc} = {s}"),
            )
        };
    }
    // SAFETY: the expected name.
    if let Some(s) = unsafe { oneline(expect_name) } {
        // SAFETY: the caller's context.
        unsafe {
            log(
                OSSL_CMP_LOG_INFO,
                ctx,
                FUNC,
                &format!(" does not match {expect_desc} = {s}"),
            )
        };
    }
    false
}

/// `check_kid`: whether the certificate's subject key ID `ckid` is `skid` (trivially when no
/// senderKID is expected), logging the outcome.
///
/// # Safety
/// `ctx` is NULL or live; the IDs NULL or live.
unsafe fn check_kid(
    ctx: *const OSSL_CMP_CTX,
    ckid: *const ASN1_OCTET_STRING,
    skid: *const ASN1_OCTET_STRING,
) -> bool {
    const FUNC: &CStr = c"check_kid";
    if skid.is_null() {
        return true;
    }
    if ckid.is_null() {
        // SAFETY: the caller's context.
        unsafe {
            log(
                OSSL_CMP_LOG_WARNING,
                ctx,
                FUNC,
                "missing Subject Key Identifier in certificate",
            )
        };
        return false;
    }
    // SAFETY: the certificate's ID.
    let s = unsafe { hex_string(ckid) };
    // SAFETY: both IDs.
    if unsafe { ASN1_OCTET_STRING_cmp(ckid, skid) } == 0 {
        if let Some(s) = s {
            // SAFETY: the caller's context.
            unsafe {
                log(
                    OSSL_CMP_LOG_INFO,
                    ctx,
                    FUNC,
                    &format!(" subjectKID matches senderKID: {s}"),
                )
            };
        }
        return true;
    }
    if let Some(s) = s {
        // SAFETY: the caller's context.
        unsafe {
            log(
                OSSL_CMP_LOG_INFO,
                ctx,
                FUNC,
                &format!(" cert Subject Key Identifier = {s}"),
            )
        };
    }
    // SAFETY: the expected ID.
    if let Some(s) = unsafe { hex_string(skid) } {
        // SAFETY: the caller's context.
        unsafe {
            log(
                OSSL_CMP_LOG_INFO,
                ctx,
                FUNC,
                &format!(" does not match senderKID    = {s}"),
            )
        };
    }
    false
}

/// `already_checked`: whether the certificate is in the list (searched from the end).
///
/// # Safety
/// `list` is NULL or a live list of certificates; `cert` live.
unsafe fn already_checked(cert: *const X509, list: *const Stack) -> bool {
    // SAFETY: the caller's list, or NULL (0).
    let n = unsafe { OPENSSL_sk_num(list) };
    (1..=n).rev().any(|i| {
        // SAFETY: an index in range.
        let x: *const X509 = unsafe { OPENSSL_sk_value(list, i - 1) }.cast();
        // SAFETY: two certificates.
        (unsafe { X509_cmp(x, cert) }) == 0
    })
}

/// `cert_acceptable`: whether the certificate may be the message's sender's: not among those
/// already checked, current (or excused by the trust store's verify callback while logging is
/// on), with the sender's subject and (if the message has one) senderKID, valid in its
/// extensions, and verifying the message's signature. Logs every step.
///
/// # Safety
/// `ctx` is a live context; `cert` live; the lists NULL or live; `msg` a live message with a
/// directory-name sender.
unsafe fn cert_acceptable(
    ctx: *const OSSL_CMP_CTX,
    desc1: &str,
    desc2: &str,
    cert: *mut X509,
    already_checked1: *const Stack,
    already_checked2: *const Stack,
    msg: *const OSSL_CMP_MSG,
) -> bool {
    const FUNC: &CStr = c"cert_acceptable";
    // SAFETY: the caller's guarantee.
    let (Some(c), Some(m)) = (unsafe { ctx_of(ctx) }, unsafe { of::<Msg, _>(msg) }) else {
        return false;
    };
    let ts = c.trusted;
    let has_log_cb = c.log_cb.is_some();
    // SAFETY: the caller's certificate, twice.
    let self_issued = unsafe { X509_check_issued(cert, cert) } == X509_V_OK;
    let vpm = if ts.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: the context's store.
        unsafe { X509_STORE_get0_param(ts) }
    };
    let si = if self_issued { "self-issued " } else { "" };
    // SAFETY: the live context.
    unsafe {
        log(
            OSSL_CMP_LOG_INFO,
            ctx,
            FUNC,
            &format!(" considering {si}{desc1} {desc2} with.."),
        )
    };
    // SAFETY: the certificate.
    let subject = unsafe { X509_get_subject_name(cert) };
    // SAFETY: its subject.
    if let Some(s) = unsafe { oneline(subject) } {
        // SAFETY: the live context.
        unsafe { log(OSSL_CMP_LOG_INFO, ctx, FUNC, &format!("  subject = {s}")) };
    }
    if !self_issued {
        // SAFETY: the certificate.
        let issuer = unsafe { X509_get_issuer_name(cert) };
        // SAFETY: its issuer.
        if let Some(s) = unsafe { oneline(issuer) } {
            // SAFETY: the live context.
            unsafe { log(OSSL_CMP_LOG_INFO, ctx, FUNC, &format!("  issuer  = {s}")) };
        }
    }

    // SAFETY: the certificate; the caller's lists.
    if unsafe { already_checked(cert, already_checked1) }
        // SAFETY: as above.
        || unsafe { already_checked(cert, already_checked2) }
    {
        // SAFETY: the live context.
        unsafe {
            log(
                OSSL_CMP_LOG_INFO,
                ctx,
                FUNC,
                " cert has already been checked",
            )
        };
        return false;
    }

    // SAFETY: the certificate.
    let not_before = unsafe { X509_get0_notBefore(cert) };
    // SAFETY: as above.
    let not_after = unsafe { X509_get0_notAfter(cert) };
    // SAFETY: the store's parameters, or NULL; the certificate's times.
    let time_cmp = unsafe { X509_cmp_timeframe(vpm, not_before, not_after) };
    if time_cmp != 0 {
        let (e, text) = if time_cmp > 0 {
            (X509_V_ERR_CERT_HAS_EXPIRED, "cert has expired")
        } else {
            (X509_V_ERR_CERT_NOT_YET_VALID, "cert is not yet valid")
        };
        // SAFETY: the live context.
        unsafe { log(OSSL_CMP_LOG_WARNING, ctx, FUNC, text) };
        // Only while logging isn't temporarily off.
        // SAFETY: the store, or NULL; the certificate.
        if has_log_cb && unsafe { verify_cb_cert(ts, cert, e) } <= 0 {
            return false;
        }
    }

    // SAFETY: the message's header, whose sender the caller checked.
    let h = unsafe { &*m.header };
    // SAFETY: as above.
    let sender = unsafe { sender_dn(h) };
    // SAFETY: the live context; the names.
    if !unsafe { check_name(ctx, true, "cert subject", subject, "sender field", sender) } {
        return false;
    }
    // SAFETY: the certificate.
    let ckid = unsafe { X509_get0_subject_key_id(cert) };
    // SAFETY: the live context; the IDs.
    if !unsafe { check_kid(ctx, ckid, h.senderKID) } {
        return false;
    }
    // Lest a failing extension cache give a misleading error later.
    // SAFETY: the certificate.
    if !unsafe { cache_extensions(cert) } {
        // SAFETY: the live context.
        unsafe {
            log(
                OSSL_CMP_LOG_WARNING,
                ctx,
                FUNC,
                "cert appears to be invalid",
            )
        };
        return false;
    }
    // SAFETY: the live context, message, and certificate.
    if !unsafe { verify_signature(ctx, msg, cert) } {
        // SAFETY: the live context.
        unsafe {
            log(
                OSSL_CMP_LOG_WARNING,
                ctx,
                FUNC,
                "msg signature verification failed",
            )
        };
        return false;
    }
    // Acceptable also if the header has no senderKID.
    // SAFETY: the live context.
    unsafe { log(OSSL_CMP_LOG_INFO, ctx, FUNC, " cert seems acceptable") };
    true
}

/// `check_cert_path`: the certificate's path validated against `store`.
///
/// # Safety
/// `ctx` is a live context; `store` NULL or live; `scrt` live.
unsafe fn check_cert_path(
    ctx: *const OSSL_CMP_CTX,
    store: *mut X509_STORE,
    scrt: *mut X509,
) -> bool {
    // SAFETY: the caller's guarantee.
    if unsafe { OSSL_CMP_validate_cert_path(ctx, store, scrt) } != 0 {
        return true;
    }
    // SAFETY: the live context.
    unsafe {
        log(
            OSSL_CMP_LOG_WARNING,
            ctx,
            c"check_cert_path",
            "msg signature validates but cert path validation failed",
        )
    };
    false
}

/// `check_cert_path_3gpp`: 3GPP TS 33.310's exception, only when the context permits it: the
/// certificate's path validated with the message's self-issued extra certificates as trust
/// anchors, which for an IP must also validate the newly enrolled certificate.
///
/// # Safety
/// `ctx` is a live context; `msg` a live message; `scrt` live.
unsafe fn check_cert_path_3gpp(
    ctx: *const OSSL_CMP_CTX,
    msg: *const OSSL_CMP_MSG,
    scrt: *mut X509,
) -> bool {
    // SAFETY: the caller's guarantee.
    let (Some(c), Some(m)) = (unsafe { ctx_of(ctx) }, unsafe { of::<Msg, _>(msg) }) else {
        return false;
    };
    if c.permitTAInExtraCertsForIR == 0 {
        return false;
    }
    let mut valid = false;
    // SAFETY: no preconditions.
    let store = unsafe { X509_STORE_new() };
    // SAFETY: the new store; the message's extra certificates, or NULL.
    if !store.is_null() && unsafe { X509_STORE_add1_certs(store, m.extraCerts.cast(), 1) } != 0 {
        // The store has no CRLs.
        // SAFETY: the live context; the store; the certificate.
        valid = unsafe { OSSL_CMP_validate_cert_path(ctx, store, scrt) } != 0;
        if !valid {
            // SAFETY: the live context.
            unsafe {
                log(
                    OSSL_CMP_LOG_WARNING,
                    ctx,
                    c"check_cert_path_3gpp",
                    "also exceptional 3GPP mode cert path validation failed",
                )
            };
        // SAFETY: the live message.
        } else if unsafe { OSSL_CMP_MSG_get_bodytype(msg) } == PKIBODY_IP {
            // The newly enrolled certificate (assumed rid CERTREQID) must validate with the
            // same store.
            // SAFETY: the message's body, an IP.
            let ip: *const CertRepMessage = unsafe { (*m.body).value }.cast();
            // SAFETY: its CertRepMessage.
            let crep = unsafe { certrepmessage_get0_certresponse(ip.cast(), CERTREQID) };
            let mut newcrt: *mut X509 = ptr::null_mut();
            valid = !crep.is_null() && {
                // SAFETY: the live context; the response.
                newcrt = unsafe { certresponse_get1_cert(ctx, crep.cast()) };
                // SAFETY: as above; the store; the new certificate.
                !newcrt.is_null() && unsafe { OSSL_CMP_validate_cert_path(ctx, store, newcrt) } != 0
            };
            // SAFETY: the certificate got above, or NULL.
            unsafe { X509_free(newcrt) };
        }
    }
    // SAFETY: made above, or NULL.
    unsafe { X509_STORE_free(store) };
    valid
}

/// `check_msg_given_cert`: the message's protection checked with an earlier validated sender
/// certificate (not its revocation or chain).
///
/// # Safety
/// As for [`cert_acceptable`].
unsafe fn check_msg_given_cert(
    ctx: *const OSSL_CMP_CTX,
    cert: *mut X509,
    msg: *const OSSL_CMP_MSG,
) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe {
        cert_acceptable(
            ctx,
            "previously validated",
            "sender cert",
            cert,
            ptr::null(),
            ptr::null(),
            msg,
        )
    }
}

/// `check_msg_with_certs`: each of `certs` tried as the sender's, normally or in 3GPP mode;
/// the first acceptable one with a valid path is cached as the validated server certificate.
/// With no `already_checked1`, `certs` are the message's extra certificates.
///
/// # Safety
/// `ctx` is a live context; the lists NULL or live; `msg` live, with a directory-name sender.
unsafe fn check_msg_with_certs(
    ctx: *mut OSSL_CMP_CTX,
    certs: *const Stack,
    desc: &str,
    already_checked1: *const Stack,
    already_checked2: *const Stack,
    msg: *const OSSL_CMP_MSG,
    mode_3gpp: bool,
) -> bool {
    const FUNC: &CStr = c"check_msg_with_certs";
    let in_extra_certs = already_checked1.is_null();
    let mut n_acceptable_certs = 0;
    // SAFETY: the caller's list, or NULL (0).
    let n = unsafe { OPENSSL_sk_num(certs) };
    if n <= 0 {
        // SAFETY: the live context.
        unsafe { log(OSSL_CMP_LOG_INFO, ctx, FUNC, &format!("no {desc}")) };
        return false;
    }
    for i in 0..n {
        // SAFETY: an index in range.
        let cert: *mut X509 = unsafe { OPENSSL_sk_value(certs, i) }.cast();
        if cert.is_null() {
            return false;
        }
        // SAFETY: the live context, certificate, lists, and message.
        if !unsafe {
            cert_acceptable(
                ctx,
                "cert from",
                desc,
                cert,
                already_checked1,
                already_checked2,
                msg,
            )
        } {
            continue;
        }
        n_acceptable_certs += 1;
        let ok = if mode_3gpp {
            // SAFETY: as above.
            unsafe { check_cert_path_3gpp(ctx, msg, cert) }
        } else {
            // SAFETY: the live context.
            let trusted = unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.trusted);
            // SAFETY: as above; the context's store, or NULL.
            unsafe { check_cert_path(ctx, trusted, cert) }
        };
        if ok {
            // Kept for the transaction's further messages.
            // SAFETY: the live context; the certificate.
            return unsafe { ctx_set1_validatedSrvCert(ctx, cert) } != 0;
        }
    }
    if in_extra_certs && n_acceptable_certs == 0 {
        // SAFETY: the live context.
        unsafe {
            log(
                OSSL_CMP_LOG_WARNING,
                ctx,
                FUNC,
                &format!("no acceptable {desc}"),
            )
        };
    }
    false
}

/// `check_msg_all_certs`: the sender's certificate sought among the message's extra
/// certificates, then the untrusted ones, then those of the trust store (or, in 3GPP mode,
/// only when the context permits it for an IP).
///
/// # Safety
/// `ctx` is a live context; `msg` live, with a directory-name sender.
unsafe fn check_msg_all_certs(
    ctx: *mut OSSL_CMP_CTX,
    msg: *const OSSL_CMP_MSG,
    mode_3gpp: bool,
) -> bool {
    const FUNC: &CStr = c"check_msg_all_certs";
    // SAFETY: the caller's guarantee.
    let (Some(c), Some(m)) = (unsafe { ctx_of(ctx) }, unsafe { of::<Msg, _>(msg) }) else {
        return false;
    };
    let permit = c.permitTAInExtraCertsForIR != 0;
    // SAFETY: the live message.
    if permit && unsafe { OSSL_CMP_MSG_get_bodytype(msg) } == PKIBODY_IP {
        let text = if mode_3gpp {
            "normal mode failed; trying now 3GPP mode trusting extraCerts"
        } else {
            "trying first normal mode using trust store"
        };
        // SAFETY: the live context.
        unsafe { log(OSSL_CMP_LOG_INFO, ctx, FUNC, text) };
    } else if mode_3gpp {
        return false;
    }
    let extra = m.extraCerts.cast_const();
    // SAFETY: the live context, lists, and message.
    if unsafe {
        check_msg_with_certs(
            ctx,
            extra,
            "extraCerts",
            ptr::null(),
            ptr::null(),
            msg,
            mode_3gpp,
        )
    } {
        return true;
    }
    // SAFETY: the live context.
    let untrusted = unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.untrusted);
    // SAFETY: as above.
    if unsafe {
        check_msg_with_certs(
            ctx,
            untrusted,
            "untrusted certs",
            extra,
            ptr::null(),
            msg,
            mode_3gpp,
        )
    } {
        return true;
    }
    // SAFETY: the live context.
    let (trusted_store, untrusted) = unsafe { ctx_of(ctx) }
        .map_or((ptr::null_mut(), ptr::null_mut()), |c| {
            (c.trusted, c.untrusted)
        });
    if trusted_store.is_null() {
        let text = if mode_3gpp {
            "no self-issued extraCerts"
        } else {
            "no trusted store"
        };
        // SAFETY: the live context.
        unsafe { log(OSSL_CMP_LOG_WARNING, ctx, FUNC, text) };
        return false;
    }
    // SAFETY: the context's store.
    let trusted = unsafe { X509_STORE_get1_all_certs(trusted_store) };
    let desc = if mode_3gpp {
        "self-issued extraCerts"
    } else {
        "certs in trusted store"
    };
    // SAFETY: as above; the store's certificates, or NULL.
    let ret = unsafe {
        check_msg_with_certs(ctx, trusted.cast(), desc, extra, untrusted, msg, mode_3gpp)
    };
    // SAFETY: the copy got above, or NULL.
    unsafe { OSSL_STACK_OF_X509_free(trusted) };
    ret
}

/// Sets the context's log callback, returning the old one (logging is turned off while
/// candidate certificates are tried).
///
/// # Safety
/// `ctx` is NULL or a live context.
unsafe fn swap_log_cb(
    ctx: *mut OSSL_CMP_CTX,
    cb: rustyssl_abi::OSSL_CMP_log_cb_t,
) -> rustyssl_abi::OSSL_CMP_log_cb_t {
    // SAFETY: the caller's guarantee.
    unsafe { ctx_of(ctx) }.and_then(|c| core::mem::replace(&mut c.log_cb, cb))
}

/// `check_msg_find_cert`: the message's signature verified with an acceptable and valid sender
/// certificate: first the one validated earlier in the transaction, then any found (normally,
/// then in 3GPP mode), quietly; on failure the search is repeated with logging for diagnosis,
/// and `CMP_R_NO_SUITABLE_SENDER_CERT` names the sender and senderKID.
///
/// # Safety
/// `ctx` is a live context; `msg` a live message with a header.
unsafe fn check_msg_find_cert(ctx: *mut OSSL_CMP_CTX, msg: *const OSSL_CMP_MSG) -> bool {
    const FUNC: &CStr = c"check_msg_find_cert";
    const F: &str = "check_msg_find_cert";
    // SAFETY: the caller's guarantee.
    let (Some(c), Some(m)) = (unsafe { ctx_of(ctx) }, unsafe { of::<Msg, _>(msg) }) else {
        return false;
    };
    let scrt = c.validatedSrvCert;
    // SAFETY: the message's header.
    let h = unsafe { &*m.header };
    // SAFETY: the header's sender, or NULL.
    let Some(sender) = (unsafe { h.sender.as_ref() }) else {
        return false;
    };
    if m.body.is_null() {
        return false;
    }
    if sender.type_ != GEN_DIRNAME {
        // So far only directory names.
        err::raise(ERR_LIB_CMP, CMP_R_SENDER_GENERALNAME_TYPE_NOT_SUPPORTED, F);
        return false;
    }
    let skid = h.senderKID.cast_const();

    // Earlier errors dumped, lest they confuse what's printed next.
    // SAFETY: the live context.
    unsafe { OSSL_CMP_CTX_print_errors(ctx) };
    // So errors of the attempts can be cleared.
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: the live context; logging off for now.
    let backup_log_cb = unsafe { swap_log_cb(ctx, None) };

    if !scrt.is_null() {
        // The sender certificate that worked earlier in this transaction is a good guess.
        // SAFETY: the live context, certificate, and message.
        if unsafe { check_msg_given_cert(ctx, scrt, msg) } {
            // SAFETY: the live context.
            unsafe { swap_log_cb(ctx, backup_log_cb) };
            // SAFETY: no preconditions.
            unsafe { ERR_pop_to_mark() };
            return true;
        }
        // No longer usable: the check redone (just) for the diagnostics.
        // SAFETY: the live context.
        unsafe {
            log(
                OSSL_CMP_LOG_INFO,
                ctx,
                FUNC,
                "trying to verify msg signature with previously validated cert",
            )
        };
        // SAFETY: as above.
        unsafe { swap_log_cb(ctx, backup_log_cb) };
        // SAFETY: as above.
        unsafe { check_msg_given_cert(ctx, scrt, msg) };
        // SAFETY: as above.
        unsafe { swap_log_cb(ctx, None) };
        // This invalidates `scrt`.
        // SAFETY: as above.
        unsafe { ctx_set1_validatedSrvCert(ctx, ptr::null_mut()) };
    }

    // SAFETY: as above.
    let res = unsafe { check_msg_all_certs(ctx, msg, false) }
        // SAFETY: as above.
        || unsafe { check_msg_all_certs(ctx, msg, true) };
    // SAFETY: as above; logging back on.
    unsafe { swap_log_cb(ctx, backup_log_cb) };
    // The diagnostics of the attempts are dropped.
    // SAFETY: no preconditions.
    unsafe { ERR_pop_to_mark() };
    if res {
        return true;
    }

    // SAFETY: the sender's directory name, which its type says the union holds.
    let dn = unsafe { sender.d.directoryName };
    // SAFETY: as above.
    let sname = unsafe { oneline(dn) };
    let skid_str = if skid.is_null() {
        None
    } else {
        // SAFETY: the header's senderKID.
        unsafe { hex_string(skid) }
    };
    if backup_log_cb.is_some() {
        // SAFETY: the live context.
        unsafe {
            log(
                OSSL_CMP_LOG_INFO,
                ctx,
                FUNC,
                "trying to verify msg signature with a valid cert that..",
            )
        };
        if let Some(s) = &sname {
            // SAFETY: as above.
            unsafe {
                log(
                    OSSL_CMP_LOG_INFO,
                    ctx,
                    FUNC,
                    &format!("matches msg sender    = {s}"),
                )
            };
        }
        if let Some(s) = &skid_str {
            // SAFETY: as above.
            unsafe {
                log(
                    OSSL_CMP_LOG_INFO,
                    ctx,
                    FUNC,
                    &format!("matches msg senderKID = {s}"),
                )
            };
        } else {
            // SAFETY: as above.
            unsafe {
                log(
                    OSSL_CMP_LOG_INFO,
                    ctx,
                    FUNC,
                    "while msg header does not contain senderKID",
                )
            };
        }
        // The checks redone (just) for the diagnostics.
        // SAFETY: as above.
        unsafe { check_msg_all_certs(ctx, msg, false) };
        // SAFETY: as above.
        unsafe { check_msg_all_certs(ctx, msg, true) };
    }

    err::raise(ERR_LIB_CMP, CMP_R_NO_SUITABLE_SENDER_CERT, F);
    if let Some(s) = sname {
        add_error_txt(None, "for msg sender name = ");
        add_error_txt(None, &s);
    }
    if let Some(s) = skid_str {
        add_error_txt(Some(" and "), "for msg senderKID = ");
        add_error_txt(None, &s);
    }
    false
}

/// `ERR_add_error_txt(separator, text)` with Rust strings (an interior NUL ends them).
fn add_error_txt(separator: Option<&str>, text: &str) {
    let c_text = |s: &str| -> Vec<u8> {
        let mut v: Vec<u8> = s.bytes().take_while(|&b| b != 0).collect();
        v.push(0);
        v
    };
    let sep = separator.map(c_text);
    let txt = c_text(text);
    let sep_ptr = sep.as_ref().map_or(ptr::null(), |v| v.as_ptr().cast());
    // SAFETY: NUL-terminated strings (or NULL) that outlive the call.
    unsafe { ERR_add_error_txt(sep_ptr, txt.as_ptr().cast()) };
}

ffi_export! {
    /// Validates the message's protection: a password-based MAC with the context's secret (then
    /// trusting the caPubs of an IP, CP, KUP, or CCP), or a signature by the pinned server
    /// certificate or by a sender certificate found and path-validated (cached for the
    /// transaction). 1, or 0.
    ///
    /// # Safety
    /// `ctx` and `msg` are NULL or live.
    pub unsafe extern "C" fn OSSL_CMP_validate_msg(ctx: *mut OSSL_CMP_CTX, msg: *const OSSL_CMP_MSG) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        const FUNC: &CStr = c"OSSL_CMP_validate_msg";
        const F: &str = "OSSL_CMP_validate_msg";
        // SAFETY: the caller's context, or NULL (no log).
        unsafe { log(OSSL_CMP_LOG_DEBUG, ctx, FUNC, "validating CMP message") };
        // SAFETY: the caller's guarantee.
        let (Some(c), Some(m)) = (unsafe { ctx_of(ctx) }, unsafe { of::<Msg, _>(msg) }) else {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, F);
            return 0;
        };
        if m.header.is_null() || m.body.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, F);
            return 0;
        }
        // SAFETY: the message's header.
        let h = unsafe { &*m.header };
        // SAFETY: the message's protection, or NULL.
        let unprotected = h.protectionAlg.is_null() || unsafe { m.protection.as_ref() }.is_none_or(|p| p.data.is_null());
        if unprotected {
            err::raise(ERR_LIB_CMP, CMP_R_MISSING_PROTECTION, F);
            return 0;
        }

        // SAFETY: the header.
        let nid = unsafe { hdr_get_protection_nid(m.header.cast()) };
        if nid == NID_id_PasswordBasedMAC {
            // RFC 9810 5.1.3.1, shared secret information.
            if c.secretValue.is_null() {
                // SAFETY: the live context.
                unsafe { log(OSSL_CMP_LOG_INFO, ctx, FUNC, "no secret available for verifying PBM-based CMP message protection") };
                err::raise(ERR_LIB_CMP, CMP_R_MISSING_SECRET, F);
                return 0;
            }
            // SAFETY: the live context and message.
            if unsafe { verify_PBMAC(ctx, msg) } {
                // RFC 9810 5.3.2: with shared-secret protection, the certificates in caPubs
                // may be trusted directly as root CAs.
                // SAFETY: the live message.
                match unsafe { OSSL_CMP_MSG_get_bodytype(msg) } {
                    -1 => return 0,
                    // SAFETY: the live context and message.
                    PKIBODY_IP | PKIBODY_CP | PKIBODY_KUP | PKIBODY_CCP if unsafe { trust_caPubs(ctx, msg) } == 0 => {
                        return 0;
                    }
                    _ => {}
                }
                // SAFETY: the live context.
                unsafe { log(OSSL_CMP_LOG_DEBUG, ctx, FUNC, "successfully validated PBM-based CMP message protection") };
                return 1;
            }
            // SAFETY: the live context.
            unsafe { log(OSSL_CMP_LOG_WARNING, ctx, FUNC, "verifying PBM-based CMP message protection failed") };
        } else if nid == NID_id_DHBasedMac {
            // 5.1.3.2, DH key pairs: not supported.
            err::raise(ERR_LIB_CMP, CMP_R_UNSUPPORTED_PROTECTION_ALG_DHBASEDMAC, F);
        } else {
            // 5.1.3.3, signature.
            let scrt = c.srvCert;
            if scrt.is_null() {
                if c.trusted.is_null() && !c.secretValue.is_null() {
                    // SAFETY: the live context.
                    unsafe { log(OSSL_CMP_LOG_INFO, ctx, FUNC, "no trust store nor pinned sender cert available for verifying signature-based CMP message protection") };
                    err::raise(ERR_LIB_CMP, CMP_R_MISSING_TRUST_ANCHOR, F);
                    return 0;
                }
                // SAFETY: the live context and message.
                if unsafe { check_msg_find_cert(ctx, msg) } {
                    // SAFETY: the live context.
                    let permit = unsafe { ctx_of(ctx) }.is_some_and(|c| c.permitTAInExtraCertsForIR != 0);
                    let or3gpp = if permit { " or 3GPP mode" } else { "" };
                    // SAFETY: as above.
                    unsafe { log(OSSL_CMP_LOG_DEBUG, ctx, FUNC, &format!("successfully validated signature-based CMP message protection using trust store{or3gpp}")) };
                    return 1;
                }
            } else {
                // The pinned sender certificate is used even if it isn't acceptable.
                // SAFETY: the live context, message, and certificate.
                if unsafe { verify_signature(ctx, msg, scrt) } {
                    // SAFETY: the live context.
                    unsafe { log(OSSL_CMP_LOG_DEBUG, ctx, FUNC, "successfully validated signature-based CMP message protection using pinned sender cert") };
                    // SAFETY: as above; the certificate.
                    return unsafe { ctx_set1_validatedSrvCert(ctx, scrt) };
                }
                // SAFETY: the live context.
                unsafe { log(OSSL_CMP_LOG_WARNING, ctx, FUNC, "CMP message signature verification failed") };
                err::raise(ERR_LIB_CMP, CMP_R_SRVCERT_DOES_NOT_VALIDATE_MSG, F);
            }
        }
        0
    }
}

/// The caPubs of a certificate response (IP, CP, KUP, or CCP: the same body layout) added to
/// the context's trust store, if it has one (self-issued or not). 1, or 0.
///
/// # Safety
/// `ctx` is a live context; `msg` a live message with a body of one of those types.
unsafe fn trust_caPubs(ctx: *mut OSSL_CMP_CTX, msg: *const OSSL_CMP_MSG) -> c_int {
    // SAFETY: the caller's guarantee.
    let trusted = unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.trusted);
    if trusted.is_null() {
        return 1;
    }
    // SAFETY: the caller's message.
    let Some(m) = (unsafe { of::<Msg, _>(msg) }) else {
        return 0;
    };
    // SAFETY: the message's body.
    let rep: *const CertRepMessage = unsafe { (*m.body).value }.cast();
    // SAFETY: the CertRepMessage, or NULL.
    let certs = unsafe { rep.as_ref() }.map_or(ptr::null_mut(), |r| r.caPubs);
    // SAFETY: the store; the certificates, or NULL.
    unsafe { X509_STORE_add1_certs(trusted, certs.cast(), 0) }
}

/// `check_transactionID_or_nonce`: whether `actual` is `expected` (trivially without an
/// expectation); if not, `reason` is raised with both in hex ("?" when unprintable, "(none)"
/// when missing).
///
/// # Safety
/// `expected` and `actual` are NULL or live.
unsafe fn check_transactionID_or_nonce(
    expected: *const ASN1_OCTET_STRING,
    actual: *const ASN1_OCTET_STRING,
    reason: c_int,
) -> bool {
    if expected.is_null() {
        return true;
    }
    // SAFETY: both strings, `actual` checked.
    if !actual.is_null() && unsafe { ASN1_OCTET_STRING_cmp(expected, actual) } == 0 {
        return true;
    }
    // SAFETY: the expected string.
    let expected_str = unsafe { hex_string(expected) };
    let actual_str = if actual.is_null() {
        None
    } else {
        // SAFETY: the actual string.
        unsafe { hex_string(actual) }
    };
    let e = expected_str.as_deref().unwrap_or("?");
    let a = if actual.is_null() {
        "(none)"
    } else {
        actual_str.as_deref().unwrap_or("?")
    };
    err::raise_with_text(
        ERR_LIB_CMP,
        reason,
        "check_transactionID_or_nonce",
        &format!("expected = {e}, actual = {a}"),
    );
    false
}

/// `ossl_cmp_msg_check_update`: a received message (a response by the server or a request by
/// a client) checked: its sender a directory name matching any expected sender (or the pinned
/// server certificate's subject); its protection valid, or missing or invalid with the
/// callback's consent; its version 2 or 3; its body type; its transaction ID and recipNonce
/// what was sent (when polling, also the nonce at the poll's start). Its extra certificates are
/// prepended to the context's untrusted ones (removed again if not caching or on failure). Then
/// the transaction ID (if new) and the senderNonce are learned, and with PBM protection the
/// caPubs trusted. 1, or 0.
///
/// # Safety
/// `ctx` and `msg` are NULL or live.
pub(crate) unsafe fn msg_check_update(
    ctx: *mut OSSL_CMP_CTX,
    msg: *const OSSL_CMP_MSG,
    cb: AllowUnprotectedCb,
    cb_arg: c_int,
) -> c_int {
    const FUNC: &CStr = c"ossl_cmp_msg_check_update";
    const F: &str = "ossl_cmp_msg_check_update";
    // SAFETY: the caller's guarantee.
    let (Some(c), Some(m)) = (unsafe { ctx_of(ctx) }, unsafe { of::<Msg, _>(msg) }) else {
        return 0;
    };
    if m.header.is_null() {
        return 0;
    }
    // SAFETY: the live message.
    let hdr: *const PkiHeader = unsafe { OSSL_CMP_MSG_get0_header(msg) }.cast();
    // SAFETY: its header.
    let h = unsafe { &*hdr };

    let mut expected_sender = c.expected_sender.cast_const();
    if expected_sender.is_null() && !c.srvCert.is_null() {
        // SAFETY: the pinned certificate.
        expected_sender = unsafe { X509_get_subject_name(c.srvCert) };
    }
    if !expected_sender.is_null() {
        // SAFETY: the header's sender (always present in a decoded or made header).
        if unsafe { (*h.sender).type_ } != GEN_DIRNAME {
            err::raise(ERR_LIB_CMP, CMP_R_SENDER_GENERALNAME_TYPE_NOT_SUPPORTED, F);
            return 0;
        }
        // SAFETY: as above.
        let actual_sender = unsafe { sender_dn(h) };
        // Mitigates accepting a misused PBM secret or a misused certificate of an
        // unauthorized entity of a trusted hierarchy.
        // SAFETY: the live context; the names.
        if !unsafe {
            check_name(
                ctx,
                false,
                "sender DN field",
                actual_sender,
                "expected sender",
                expected_sender,
            )
        } {
            // SAFETY: the sender's name.
            let s = unsafe { oneline(actual_sender) };
            err::raise_with_text(
                ERR_LIB_CMP,
                CMP_R_UNEXPECTED_SENDER,
                F,
                s.as_deref().unwrap_or("<unknown>"),
            );
            return 0;
        }
    }
    // A NULL-DN recipient could be learned here if needed.

    // SAFETY: the message's extra certificates, or NULL (0).
    let extra_count = unsafe { OPENSSL_sk_num(m.extraCerts) };
    if extra_count > 10 {
        // SAFETY: the live context.
        unsafe {
            log(
                OSSL_CMP_LOG_WARNING,
                ctx,
                FUNC,
                &format!("received CMP message contains {extra_count} extraCerts"),
            )
        };
    }
    // Kept for OSSL_CMP_validate_msg and the rest of the transaction (also for certConf_cb),
    // prepended so they can be removed simply and are tried first.
    // SAFETY: the live context.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return 0;
    };
    // SAFETY: the context's untrusted list, or NULL (0).
    let num_untrusted = unsafe { OPENSSL_sk_num(c.untrusted) };
    // SAFETY: the context's list; the message's certificates (self-signed ones allowed).
    let added = unsafe {
        add_certs_new(
            &mut c.untrusted,
            m.extraCerts,
            X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP | X509_ADD_FLAG_PREPEND,
        )
    };
    // SAFETY: as above.
    let num_added = unsafe { OPENSSL_sk_num(c.untrusted) }.saturating_sub(num_untrusted);
    if !added {
        // SAFETY: the live context.
        unsafe { remove_first(ctx, num_added) };
        return 0;
    }

    let protected = !h.protectionAlg.is_null();
    let res = if protected {
        // SAFETY: the live context and message.
        (unsafe { OSSL_CMP_validate_msg(ctx, msg) }) != 0
            // Explicitly permitted exceptions for invalid protection.
            // SAFETY: the caller's callback with the live context and message.
            || cb.is_some_and(|f| unsafe { f(ctx, msg, 1, cb_arg) } > 0)
    } else {
        // Explicitly permitted exceptions for missing protection.
        // SAFETY: as above.
        cb.is_some_and(|f| unsafe { f(ctx, msg, 0, cb_arg) } > 0)
    };

    // The extra certificates removed again if not caching or on failure, lest a peer grow the
    // list without bound with invalid messages.
    // SAFETY: the live context.
    let no_cache = unsafe { ctx_of(ctx) }.is_some_and(|c| c.noCacheExtraCerts != 0);
    if no_cache || !res {
        // SAFETY: as above.
        unsafe { remove_first(ctx, num_added) };
    }
    if !res {
        let reason = if protected {
            CMP_R_ERROR_VALIDATING_PROTECTION
        } else {
            CMP_R_MISSING_PROTECTION
        };
        err::raise(ERR_LIB_CMP, reason, F);
        return 0;
    }

    // SAFETY: the header.
    let pvno = unsafe { hdr_get_pvno(hdr.cast()) };
    if pvno != OSSL_CMP_PVNO_2 && pvno != OSSL_CMP_PVNO_3 {
        err::raise(ERR_LIB_CMP, CMP_R_UNEXPECTED_PVNO, F);
        return 0;
    }
    // SAFETY: the live message.
    let bodytype = unsafe { OSSL_CMP_MSG_get_bodytype(msg) };
    if bodytype < 0 {
        err::raise(ERR_LIB_CMP, CMP_R_PKIBODY_ERROR, F);
        return 0;
    }

    // SAFETY: the live context.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return 0;
    };
    // The transaction ID must be that of the earlier messages.
    // SAFETY: the context's and the header's IDs, or NULL.
    if !unsafe {
        check_transactionID_or_nonce(
            c.transactionID,
            h.transactionID,
            CMP_R_TRANSACTIONID_UNMATCHED,
        )
    } {
        return 0;
    }

    // So errors can be cleared when a delayed delivery's nonce is checked again.
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // The recipNonce must be the nonce sent.
    // SAFETY: the context's and the header's nonces, or NULL.
    if !unsafe {
        check_transactionID_or_nonce(c.senderNonce, h.recipNonce, CMP_R_RECIPNONCE_UNMATCHED)
    } {
        // Polling and the final response: the nonce sent when polling began.
        if c.first_senderNonce.is_null()
            || bodytype == PKIBODY_POLLREP
            // SAFETY: as above.
            || !unsafe { check_transactionID_or_nonce(c.first_senderNonce, h.recipNonce, CMP_R_RECIPNONCE_UNMATCHED) }
        {
            // SAFETY: no preconditions.
            unsafe { ERR_clear_last_mark() };
            return 0;
        }
    }
    // SAFETY: no preconditions.
    unsafe { ERR_pop_to_mark() };

    // The transaction ID learned if not yet known.
    // SAFETY: the live context; the header's ID, or NULL.
    if c.transactionID.is_null()
        // SAFETY: the live context; the header's ID, or NULL.
        && unsafe { OSSL_CMP_CTX_set1_transactionID(ctx, h.transactionID) } == 0
    {
        return 0;
    }
    // RFC 9810 5.1.1: the next message's recipNonce is this one's senderNonce.
    // SAFETY: as above; the header's nonce, or NULL.
    if unsafe { ctx_set1_recipNonce(ctx, h.senderNonce) } == 0 {
        return 0;
    }

    // SAFETY: the header.
    if unsafe { hdr_get_protection_nid(hdr.cast()) } == NID_id_PasswordBasedMAC {
        // RFC 9810 5.3.2: with shared-secret protection, caPubs may be trusted directly.
        if matches!(bodytype, PKIBODY_IP | PKIBODY_CP | PKIBODY_KUP | PKIBODY_CCP)
            // SAFETY: the live context and message.
            && unsafe { trust_caPubs(ctx, msg) } == 0
        {
            return 0;
        }
    }
    1
}

/// The first `n` of the context's untrusted certificates removed and freed.
///
/// # Safety
/// `ctx` is a live context with at least `n` untrusted certificates.
unsafe fn remove_first(ctx: *mut OSSL_CMP_CTX, n: c_int) {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return;
    };
    for _ in 0..n {
        // SAFETY: the context's list.
        let x: *mut X509 = unsafe { OPENSSL_sk_shift(c.untrusted) }.cast();
        // SAFETY: a certificate it held, or NULL.
        unsafe { X509_free(x) };
    }
}

/// `ossl_cmp_verify_popo`: the proof-of-possession of a P10CR (its self-signature) or of an
/// IR, CR, or KUR's first request (RA-verified accepted as told); any other body is
/// `CMP_R_PKIBODY_ERROR`. 1, or 0.
///
/// # Safety
/// `ctx` is NULL or live (needed for P10CR, IR, CR, and KUR); `msg` NULL or live.
pub(crate) unsafe fn verify_popo(
    ctx: *const OSSL_CMP_CTX,
    msg: *const OSSL_CMP_MSG,
    accept_ra_verified: c_int,
) -> c_int {
    const F: &str = "ossl_cmp_verify_popo";
    // SAFETY: the caller's guarantee.
    let Some(m) = (unsafe { of::<Msg, _>(msg) }) else {
        return 0;
    };
    // SAFETY: the message's body, or NULL.
    let Some(body) = (unsafe { m.body.as_ref() }) else {
        return 0;
    };
    // OpenSSL dereferences the context here; NULL uses the default library context instead
    // of crashing.
    // SAFETY: the caller's guarantee.
    let (libctx, propq) = unsafe { ctx_of(ctx) }.map_or((ptr::null_mut(), ptr::null()), |c| {
        (c.libctx, c.propq.cast_const())
    });
    match body.type_ {
        PKIBODY_P10CR => {
            let req: *mut X509_REQ = body.value.cast();
            // SAFETY: the request.
            let key = unsafe { X509_REQ_get0_pubkey(req) };
            // SAFETY: the request; its key; the context's library context and properties.
            if unsafe { X509_REQ_verify_ex(req, key, libctx, propq) } <= 0 {
                err::raise(ERR_LIB_CMP, CMP_R_REQUEST_NOT_ACCEPTED, F);
                return 0;
            }
        }
        PKIBODY_IR | PKIBODY_CR | PKIBODY_KUR => {
            // SAFETY: the requests; as above.
            if unsafe {
                OSSL_CRMF_MSGS_verify_popo(
                    body.value.cast(),
                    CERTREQID,
                    accept_ra_verified,
                    libctx,
                    propq,
                )
            } == 0
            {
                return 0;
            }
        }
        _ => {
            err::raise(ERR_LIB_CMP, CMP_R_PKIBODY_ERROR, F);
            return 0;
        }
    }
    1
}
