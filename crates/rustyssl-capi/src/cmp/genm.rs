//! General messages for the client (`cmp_genm.c`): asking the server for its CA certificates,
//! a root CA key update, a CRL update, or a certificate request template, each by a genm with
//! one ITAV and checked on its way back.

use core::ffi::{CStr, c_char, c_int, c_ulong, c_void};
use core::ptr;

use rustyssl_abi::{
    CMP_R_GENERATE_CERTREQTEMPLATE, CMP_R_GENERATE_CRLSTATUS, CMP_R_GETTING_GENP,
    CMP_R_INVALID_GENP, CMP_R_INVALID_ROOTCAKEYUPDATE, CMP_R_NULL_ARGUMENT, CMP_R_UNCLEAN_CTX,
    ERR_LIB_CMP, ERR_R_PASSED_NULL_PARAMETER, EXFLAG_CA, EXFLAG_V1, NID_id_it_caCerts,
    NID_id_it_certReqTemplate, NID_id_it_crls, NID_id_it_rootCaKeyUpdate, OSSL_CMP_ATAVS,
    OSSL_CMP_CRLSTATUS, OSSL_CMP_CTX, OSSL_CMP_ITAV, OSSL_CMP_LOG_ERR, OSSL_CMP_LOG_WARNING,
    OSSL_CMP_PKISTATUS_request, OSSL_CMP_PKISTATUS_unspecified, OSSL_CMP_severity,
    OSSL_CRMF_CERTTEMPLATE, OSSL_LIB_CTX, X509, X509_ADD_FLAG_NO_DUP, X509_ADD_FLAG_UP_REF,
    X509_CRL, X509_STORE, X509_STORE_CTX, X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
    X509_V_FLAG_CHECK_SS_SIGNATURE, X509_VERIFY_PARAM, stack_st_OSSL_CMP_CRLSTATUS, stack_st_X509,
    stack_st_X509_CRL,
};

use super::asn::{
    OSSL_CMP_CRLSTATUS_create, OSSL_CMP_CRLSTATUS_free, OSSL_CMP_ITAV_free,
    OSSL_CMP_ITAV_get0_caCerts, OSSL_CMP_ITAV_get0_crls, OSSL_CMP_ITAV_get0_rootCaKeyUpdate,
    OSSL_CMP_ITAV_get0_type, OSSL_CMP_ITAV_get1_certReqTemplate, OSSL_CMP_ITAV_new_caCerts,
    OSSL_CMP_ITAV_new_rootCaCert, OSSL_CMP_ITAV_new0_certReqTemplate,
    OSSL_CMP_ITAV_new0_crlStatusList, Stack,
};
use super::client::{OSSL_CMP_exec_GENM_ses, text_of};
use super::ctx::{Ctx, OSSL_CMP_CTX_push0_genm_ITAV, print_log};
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::objects::{OBJ_obj2nid, OBJ_obj2txt};
use crate::ocsp::cl::add_cert_new;
use crate::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_shift, OPENSSL_sk_value,
};
use crate::x509::cert::{
    X509_dup, X509_free, X509_get_subject_name, X509_get0_notAfter, X509_get0_notBefore,
    X509_up_ref,
};
use crate::x509::crl::X509_CRL_up_ref;
use crate::x509::ctx::{
    X509_STORE_CTX_free, X509_STORE_CTX_get_check_issued, X509_STORE_CTX_get_error,
    X509_STORE_CTX_get_error_depth, X509_STORE_CTX_get0_chain, X509_STORE_CTX_get0_store,
    X509_STORE_CTX_get0_untrusted, X509_STORE_CTX_init, X509_STORE_CTX_new_ex,
    X509_STORE_CTX_set_flags, X509_STORE_CTX_set_verify_cb, X509_cmp_timeframe,
};
use crate::x509::name::X509_NAME_oneline;
use crate::x509::purpose::{X509_add_cert, X509_add_certs, X509_get_extension_flags};
use crate::x509::store::{
    X509_STORE_add_cert, X509_STORE_free, X509_STORE_get_verify_cb, X509_STORE_get0_param,
    X509_STORE_get1_all_certs, X509_STORE_new, X509_STORE_set1_param,
};
use crate::x509::verify::X509_verify_cert;

/// `X509_free` as a stack's free function.
unsafe extern "C" fn x509_free(p: *mut c_void) {
    // SAFETY: a certificate of the list.
    unsafe { X509_free(p.cast()) };
}

/// The verification parameters of the context's trust store, or NULL.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn get0_trustedStore_vpm(ctx: *const OSSL_CMP_CTX) -> *const X509_VERIFY_PARAM {
    // SAFETY: the caller's context.
    let ts = unsafe { (*ctx.cast::<Ctx>()).trusted };
    if ts.is_null() {
        return ptr::null();
    }
    // SAFETY: its store.
    unsafe { X509_STORE_get0_param(ts) }
}

/// Logs a problem with a certificate from `source`, naming its subject, on behalf of
/// OpenSSL's function `func`.
///
/// # Safety
/// `ctx` is a live context; `cert` a live certificate.
#[track_caller]
unsafe fn cert_msg(
    func: &CStr,
    level: OSSL_CMP_severity,
    ctx: *const OSSL_CMP_CTX,
    source: &str,
    cert: *mut X509,
    msg: &str,
) {
    // SAFETY: the caller's certificate.
    let name = unsafe { X509_get_subject_name(cert) };
    // SAFETY: its name; a new string.
    let subj = unsafe { X509_NAME_oneline(name, ptr::null_mut(), 0) };
    // SAFETY: the string, or NULL.
    let subj_text = unsafe { text_of(subj) };
    // SAFETY: the caller's context.
    unsafe {
        print_log(
            level,
            ctx,
            func,
            &format!("certificate from '{source}' with subject '{subj_text}' {msg}"),
        )
    };
    // SAFETY: the string made here, or NULL.
    unsafe { mem::release(subj.cast()) };
}

/// Checks a certificate's validity period and (`type_CA` 0: must be an EE, 1: must be a CA,
/// -1: either) its kind, logging each problem: whether it passed.
///
/// # Safety
/// `ctx` is a live context; `cert` a live certificate; `vpm` NULL or live parameters.
unsafe fn ossl_X509_check(
    ctx: *const OSSL_CMP_CTX,
    source: &str,
    cert: *mut X509,
    type_CA: c_int,
    vpm: *const X509_VERIFY_PARAM,
) -> bool {
    const FN: &CStr = c"ossl_X509_check";
    // SAFETY: the caller's certificate.
    let ex_flags = unsafe { X509_get_extension_flags(cert) };
    // SAFETY: as above.
    let not_before = unsafe { X509_get0_notBefore(cert) };
    // SAFETY: as above.
    let not_after = unsafe { X509_get0_notAfter(cert) };
    // SAFETY: the parameters, or NULL; its times.
    let res = unsafe { X509_cmp_timeframe(vpm, not_before, not_after) };
    let mut ret = res == 0;
    let level = if vpm.is_null() {
        OSSL_CMP_LOG_WARNING
    } else {
        OSSL_CMP_LOG_ERR
    };
    if !ret {
        // SAFETY: the caller's context and certificate.
        unsafe {
            cert_msg(
                FN,
                level,
                ctx,
                source,
                cert,
                if res > 0 {
                    "has expired"
                } else {
                    "not yet valid"
                },
            )
        };
    }
    if type_CA >= 0 && ex_flags & EXFLAG_V1.cast_unsigned() == 0 {
        let is_CA = ex_flags & EXFLAG_CA.cast_unsigned() != 0;
        if (type_CA != 0) != is_CA {
            // SAFETY: as above.
            unsafe {
                cert_msg(
                    FN,
                    level,
                    ctx,
                    source,
                    cert,
                    if is_CA {
                        "is not an EE cert"
                    } else {
                        "is not a CA cert"
                    },
                )
            };
            ret = false;
        }
    }
    ret
}

/// [`ossl_X509_check`] on every certificate of the list (all of them, logging each problem):
/// whether all passed.
///
/// # Safety
/// As for [`ossl_X509_check`]; `certs` NULL or a live list.
unsafe fn ossl_X509_check_all(
    ctx: *const OSSL_CMP_CTX,
    source: &str,
    certs: *const Stack,
    type_CA: c_int,
    vpm: *const X509_VERIFY_PARAM,
) -> bool {
    let mut ret = true;
    // SAFETY: the caller's list, or NULL (0).
    for i in 0..unsafe { OPENSSL_sk_num(certs) } {
        // SAFETY: an index in range.
        let cert: *mut X509 = unsafe { OPENSSL_sk_value(certs, i) }.cast();
        // SAFETY: the context; a certificate of the list.
        ret = unsafe { ossl_X509_check(ctx, source, cert, type_CA, vpm) } && ret;
    }
    ret
}

/// Sends a genm with the ITAV `req` (which it takes) and returns the first ITAV of the
/// response with the infoType `expected` (named `desc` in messages), or NULL.
///
/// # Safety
/// `ctx` is NULL or a live context; `req` a live ITAV.
unsafe fn get_genm_itav(
    ctx: *mut OSSL_CMP_CTX,
    req: *mut OSSL_CMP_ITAV,
    expected: c_int,
    desc: &str,
) -> *mut OSSL_CMP_ITAV {
    const F: &str = "get_genm_itav";
    const FN: &CStr = c"get_genm_itav";
    'err: {
        if ctx.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, F);
            break 'err;
        }
        let c: *mut Ctx = ctx.cast();
        // SAFETY: the caller's context.
        if unsafe { (*c).status } != OSSL_CMP_PKISTATUS_unspecified {
            err::raise_with_text(
                ERR_LIB_CMP,
                CMP_R_UNCLEAN_CTX,
                F,
                "client context in unsuitable state; should call CMPclient_reinit() before",
            );
            break 'err;
        }
        // SAFETY: as above; the ITAV, which it takes.
        if unsafe { OSSL_CMP_CTX_push0_genm_ITAV(ctx, req) } == 0 {
            break 'err;
        }
        // SAFETY: as above.
        let itavs: *mut Stack = unsafe { OSSL_CMP_exec_GENM_ses(ctx) }.cast();
        if itavs.is_null() {
            // SAFETY: as above.
            if unsafe { (*c).status } != OSSL_CMP_PKISTATUS_request {
                err::raise_with_text(
                    ERR_LIB_CMP,
                    CMP_R_GETTING_GENP,
                    F,
                    &format!("with infoType {desc}"),
                );
            }
            return ptr::null_mut();
        }

        // SAFETY: the response's ITAVs.
        let n = unsafe { OPENSSL_sk_num(itavs) };
        if n <= 0 {
            err::raise_with_text(
                ERR_LIB_CMP,
                CMP_R_INVALID_GENP,
                F,
                &format!(
                    "response on genm requesting infoType {desc} does not include suitable value"
                ),
            );
            // SAFETY: the list (without ITAVs).
            unsafe { OPENSSL_sk_free(itavs) };
            return ptr::null_mut();
        }
        if n > 1 {
            // SAFETY: as above.
            unsafe {
                print_log(
                    OSSL_CMP_LOG_WARNING,
                    ctx,
                    FN,
                    &format!(
                        "response on genm contains {n} ITAVs; will use the first ITAV with infoType id-it-{desc}"
                    ),
                )
            };
        }
        for _ in 0..n {
            // SAFETY: the list, which owns its ITAVs.
            let itav: *mut OSSL_CMP_ITAV = unsafe { OPENSSL_sk_shift(itavs) }.cast();
            // SAFETY: the ITAV, or NULL.
            let obj = unsafe { OSSL_CMP_ITAV_get0_type(itav) };
            // SAFETY: its type, or NULL.
            if unsafe { OBJ_obj2nid(obj) } == expected {
                // The rest are freed.
                // SAFETY: as above.
                while unsafe { OPENSSL_sk_num(itavs) } > 0 {
                    // SAFETY: as above.
                    let rest: *mut OSSL_CMP_ITAV = unsafe { OPENSSL_sk_shift(itavs) }.cast();
                    // SAFETY: an ITAV taken from the list.
                    unsafe { OSSL_CMP_ITAV_free(rest) };
                }
                // SAFETY: the empty list.
                unsafe { OPENSSL_sk_free(itavs) };
                return itav;
            }
            let mut name = [0 as c_char; 128];
            // SAFETY: the room; the type.
            let len = unsafe { OBJ_obj2txt(name.as_mut_ptr(), 128, obj, 0) };
            let shown = if len < 0 {
                String::new()
            } else {
                // SAFETY: the name written, NUL-terminated.
                unsafe { CStr::from_ptr(name.as_ptr()) }
                    .to_string_lossy()
                    .into_owned()
            };
            let shown = if shown.is_empty() {
                "<unknown>".to_owned()
            } else {
                shown
            };
            // SAFETY: as above.
            unsafe {
                print_log(
                    OSSL_CMP_LOG_WARNING,
                    ctx,
                    FN,
                    &format!("genp contains InfoType '{shown}' while expecting 'id-it-{desc}'"),
                )
            };
            // SAFETY: the ITAV taken.
            unsafe { OSSL_CMP_ITAV_free(itav) };
        }
        err::raise_with_text(
            ERR_LIB_CMP,
            CMP_R_INVALID_GENP,
            F,
            &format!("could not find any ITAV for {desc}"),
        );
        // SAFETY: the empty list.
        unsafe { OPENSSL_sk_free(itavs) };
        return ptr::null_mut();
    }
    // SAFETY: the ITAV if not taken, or NULL.
    unsafe { OSSL_CMP_ITAV_free(req) };
    ptr::null_mut()
}

ffi_export! {
    /// Asks the server for its CA certificates (a genm with id-it-caCerts): 1 with them in
    /// `*out` (NULL if none), which the caller frees, after checking each is a currently
    /// valid CA certificate; else 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `out` NULL or room for a pointer.
    pub unsafe extern "C" fn OSSL_CMP_get1_caCerts(ctx: *mut OSSL_CMP_CTX, out: *mut *mut stack_st_X509) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's room, or NULL.
        let Some(out) = (unsafe { out.as_mut() }) else {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, "OSSL_CMP_get1_caCerts");
            return 0;
        };
        *out = ptr::null_mut();
        // SAFETY: no preconditions.
        let req = unsafe { OSSL_CMP_ITAV_new_caCerts(ptr::null()) };
        if req.is_null() {
            return 0;
        }
        // SAFETY: the caller's context; the ITAV, which it takes.
        let itav = unsafe { get_genm_itav(ctx, req, NID_id_it_caCerts, "caCerts") };
        if itav.is_null() {
            return 0;
        }
        let mut ret = 0;
        let mut certs: *mut stack_st_X509 = ptr::null_mut();
        // SAFETY: the ITAV; the room.
        if unsafe { OSSL_CMP_ITAV_get0_caCerts(itav, &raw mut certs) } != 0 {
            ret = 1;
            if !certs.is_null() {
                // SAFETY: the context.
                let vpm = unsafe { get0_trustedStore_vpm(ctx) };
                // SAFETY: the context; the certificates; the parameters.
                if !unsafe { ossl_X509_check_all(ctx, "genp", certs.cast(), 1, vpm) } {
                    ret = 0;
                } else {
                    // SAFETY: the certificates.
                    let n = unsafe { OPENSSL_sk_num(certs.cast()) };
                    // SAFETY: no preconditions.
                    *out = unsafe { OPENSSL_sk_new_reserve(None, n) }.cast();
                    // SAFETY: the new list, or NULL; the certificates.
                    if unsafe { X509_add_certs(*out, certs, X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP) } == 0 {
                        // SAFETY: the list made here.
                        unsafe { OPENSSL_sk_pop_free((*out).cast(), Some(x509_free)) };
                        *out = ptr::null_mut();
                        ret = 0;
                    }
                }
            }
        }
        // SAFETY: the ITAV received.
        unsafe { OSSL_CMP_ITAV_free(itav) };
        ret
    }
}

ffi_callback! {
    /// The verification callback for a self-signed target: on `DEPTH_ZERO_SELF_SIGNED_CERT`
    /// at depth 0, builds the chain itself from the untrusted certificates and an issuer in
    /// the trust store; otherwise defers to the store's callback.
    ///
    /// As in OpenSSL, the issuer searched for is that of the last untrusted certificate (the
    /// target itself if there are none).
    ///
    /// # Safety
    /// `store_ctx` is a live verification context.
    pub(crate) unsafe extern "C" fn selfsigned_verify_cb(ok: c_int, store_ctx: *mut X509_STORE_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's context, for each call below.
        let custom = ok == 0
            && unsafe { X509_STORE_CTX_get_error_depth(store_ctx) } == 0
            // SAFETY: as above.
            && unsafe { X509_STORE_CTX_get_error(store_ctx) } == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT;
        if custom {
            let mut ok = ok;
            // SAFETY: as above.
            let chain = unsafe { X509_STORE_CTX_get0_chain(store_ctx) };
            // SAFETY: as above.
            let untrusted = unsafe { X509_STORE_CTX_get0_untrusted(store_ctx) };
            // SAFETY: as above.
            let check_issued = unsafe { X509_STORE_CTX_get_check_issued(store_ctx) };
            // The target.
            // SAFETY: the chain.
            let mut cert: *mut X509 = unsafe { OPENSSL_sk_value(chain.cast(), 0) }.cast();
            // SAFETY: the untrusted certificates, or NULL (0).
            for i in 0..unsafe { OPENSSL_sk_num(untrusted.cast()) } {
                // SAFETY: an index in range.
                cert = unsafe { OPENSSL_sk_value(untrusted.cast(), i) }.cast();
                // SAFETY: the chain; a certificate.
                if unsafe { X509_add_cert(chain, cert, X509_ADD_FLAG_UP_REF) } == 0 {
                    return 0;
                }
            }
            // SAFETY: as above.
            let store = unsafe { X509_STORE_CTX_get0_store(store_ctx) };
            // SAFETY: the store.
            let trust = unsafe { X509_STORE_get1_all_certs(store) };
            // SAFETY: the copies, or NULL (0).
            for i in 0..unsafe { OPENSSL_sk_num(trust.cast()) } {
                // SAFETY: an index in range.
                let issuer: *mut X509 = unsafe { OPENSSL_sk_value(trust.cast(), i) }.cast();
                let Some(check) = check_issued else {
                    break;
                };
                // SAFETY: the verification's own issuer check, with live certificates; no
                // lock is held.
                if unsafe { check(store_ctx, cert, issuer) } != 0 {
                    // SAFETY: the chain; the issuer.
                    if unsafe { X509_add_cert(chain, issuer, X509_ADD_FLAG_UP_REF) } != 0 {
                        ok = 1;
                    }
                    break;
                }
            }
            // SAFETY: the copies.
            unsafe { OPENSSL_sk_pop_free(trust.cast(), Some(x509_free)) };
            ok
        } else {
            // SAFETY: the caller's context.
            let ts = unsafe { X509_STORE_CTX_get0_store(store_ctx) };
            if ts.is_null() {
                return ok;
            }
            // SAFETY: its store.
            let Some(verify_cb) = (unsafe { X509_STORE_get_verify_cb(ts) }) else {
                return ok;
            };
            // SAFETY: the store's callback with its own arguments; no lock is held.
            unsafe { verify_cb(ok, store_ctx) }
        }
    }
}

/// Verifies a self-signed target, which plain `X509_verify_cert` doesn't support as such:
/// whether it verified.
///
/// # Safety
/// `ts` is NULL or a live store; `untrusted` NULL or a live list; `target` NULL or live.
unsafe fn verify_ss_cert(
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
    ts: *mut X509_STORE,
    untrusted: *mut stack_st_X509,
    target: *mut X509,
) -> bool {
    if ts.is_null() || target.is_null() {
        err::raise(ERR_LIB_CMP, ERR_R_PASSED_NULL_PARAMETER, "verify_ss_cert");
        return false;
    }
    // SAFETY: the caller's settings.
    let csc = unsafe { X509_STORE_CTX_new_ex(libctx, propq) };
    let mut ok = false;
    // SAFETY: the new context; the store, target, and certificates.
    if !csc.is_null() && unsafe { X509_STORE_CTX_init(csc, ts, target, untrusted) } != 0 {
        // SAFETY: the context.
        unsafe {
            X509_STORE_CTX_set_flags(
                csc,
                c_ulong::from(X509_V_FLAG_CHECK_SS_SIGNATURE.cast_unsigned()),
            )
        };
        // SAFETY: as above; a callback for its kind.
        unsafe { X509_STORE_CTX_set_verify_cb(csc, Some(selfsigned_verify_cb)) };
        // SAFETY: as above.
        ok = unsafe { X509_verify_cert(csc) } > 0;
    }
    // SAFETY: made here, or NULL.
    unsafe { X509_STORE_CTX_free(csc) };
    ok
}

/// Verifies the self-signed `target` with the context's trust store, or with `trusted` as the
/// only trust anchor (under the store's parameters), and `trans` as the only untrusted
/// certificate; raises an error naming `desc` if it fails. Whether it verified.
///
/// # Safety
/// `ctx` is a live context; the certificates NULL or live.
unsafe fn verify_ss_cert_trans(
    ctx: *mut OSSL_CMP_CTX,
    trusted: *mut X509,
    trans: *mut X509,
    target: *mut X509,
    desc: &str,
) -> bool {
    let c: *mut Ctx = ctx.cast();
    // SAFETY: the caller's context.
    let mut ts = unsafe { (*c).trusted };
    let mut untrusted: *mut Stack = ptr::null_mut();
    let mut res = false;
    'err: {
        if !trusted.is_null() {
            let vpm = if ts.is_null() {
                ptr::null_mut()
            } else {
                // SAFETY: the context's store.
                unsafe { X509_STORE_get0_param(ts) }
            };
            // SAFETY: no preconditions.
            ts = unsafe { X509_STORE_new() };
            if ts.is_null() {
                return false;
            }
            // SAFETY: the new store; the parameters, or NULL.
            if unsafe { X509_STORE_set1_param(ts, vpm) } == 0
                // SAFETY: as above; the trust anchor.
                || unsafe { X509_STORE_add_cert(ts, trusted) } == 0
            {
                break 'err;
            }
        }
        // SAFETY: the list being made; the certificate.
        if !trans.is_null() && !unsafe { add_cert_new(&mut untrusted, trans, X509_ADD_FLAG_UP_REF) }
        {
            break 'err;
        }
        // SAFETY: the context, for each access below.
        let cx = unsafe { &*c };
        let (libctx, propq) = (cx.libctx, cx.propq);
        // SAFETY: the settings; the store; the list; the target.
        res = unsafe { verify_ss_cert(libctx, propq, ts, untrusted.cast(), target) };
        if !res {
            let how = if trusted.is_null() {
                "using trust store"
            } else {
                "with given certificate as trust anchor"
            };
            err::raise_with_text(
                ERR_LIB_CMP,
                CMP_R_INVALID_ROOTCAKEYUPDATE,
                "verify_ss_cert_trans",
                &format!("failed to validate {desc} certificate received in genp {how}"),
            );
        }
    }
    // SAFETY: the list made here, or NULL.
    unsafe { OPENSSL_sk_pop_free(untrusted, Some(x509_free)) };
    if !trusted.is_null() {
        // SAFETY: the store made here.
        unsafe { X509_STORE_free(ts) };
    }
    res
}

ffi_export! {
    /// Asks the server for a root CA key update (a genm with id-it-rootCaCert holding
    /// `oldWithOld`): 1 with `*newWithNew` (NULL if there's no update) and, when asked,
    /// `*newWithOld` and `*oldWithNew`, each a new reference, after verifying them; else 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `oldWithOld` NULL or live; the outputs NULL or room.
    pub unsafe extern "C" fn OSSL_CMP_get1_rootCaKeyUpdate(ctx: *mut OSSL_CMP_CTX, oldWithOld: *const X509, newWithNew: *mut *mut X509, newWithOld: *mut *mut X509, oldWithNew: *mut *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        const F: &str = "OSSL_CMP_get1_rootCaKeyUpdate";
        if newWithNew.is_null() {
            err::raise(ERR_LIB_CMP, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        }
        // SAFETY: the caller's room.
        unsafe { *newWithNew = ptr::null_mut() };
        // SAFETY: the caller's certificate, or NULL.
        let req = unsafe { OSSL_CMP_ITAV_new_rootCaCert(oldWithOld) };
        if req.is_null() {
            return 0;
        }
        // SAFETY: the caller's context; the ITAV, which it takes.
        let itav = unsafe { get_genm_itav(ctx, req, NID_id_it_rootCaKeyUpdate, "rootCaKeyUpdate") };
        if itav.is_null() {
            return 0;
        }
        let mut res = 0;
        let mut old_copy: *mut X509 = ptr::null_mut();
        let mut my_new_with_old: *mut X509 = ptr::null_mut();
        let mut my_old_with_new: *mut X509 = ptr::null_mut();
        'end: {
            // SAFETY: the ITAV; the rooms.
            if unsafe { OSSL_CMP_ITAV_get0_rootCaKeyUpdate(itav, newWithNew, &raw mut my_new_with_old, &raw mut my_old_with_new) } == 0 {
                break 'end;
            }
            // SAFETY: the caller's room, set above.
            let nwn = unsafe { *newWithNew };
            if nwn.is_null() {
                // No root CA certificate update available.
                res = 1;
                break 'end;
            }
            // SAFETY: the caller's certificate, or NULL.
            old_copy = unsafe { X509_dup(oldWithOld) };
            if old_copy.is_null() && !oldWithOld.is_null() {
                break 'end;
            }
            // SAFETY: the context; the certificates, borrowed from the ITAV or copied.
            if !unsafe { verify_ss_cert_trans(ctx, old_copy, my_new_with_old, nwn, "newWithNew") } {
                err::raise(ERR_LIB_CMP, CMP_R_INVALID_ROOTCAKEYUPDATE, F);
                break 'end;
            }
            if !oldWithOld.is_null() && !my_old_with_new.is_null()
                // SAFETY: as above.
                && !unsafe { verify_ss_cert_trans(ctx, nwn, my_old_with_new, old_copy, "oldWithOld") }
            {
                err::raise(ERR_LIB_CMP, CMP_R_INVALID_ROOTCAKEYUPDATE, F);
                break 'end;
            }

            // SAFETY: the certificate of the ITAV.
            if unsafe { X509_up_ref(nwn) } == 0 {
                break 'end;
            }
            'free: {
                if !newWithOld.is_null() {
                    // SAFETY: the caller's room.
                    unsafe { *newWithOld = my_new_with_old };
                    // SAFETY: the certificate of the ITAV.
                    if !my_new_with_old.is_null() && unsafe { X509_up_ref(my_new_with_old) } == 0 {
                        break 'free;
                    }
                }
                if oldWithNew.is_null() {
                    res = 1;
                    break 'end;
                }
                // SAFETY: the caller's room.
                unsafe { *oldWithNew = my_old_with_new };
                // SAFETY: the certificate of the ITAV.
                if my_old_with_new.is_null() || unsafe { X509_up_ref(my_old_with_new) } != 0 {
                    res = 1;
                    break 'end;
                }
                if !newWithOld.is_null() {
                    // SAFETY: the caller's slot.
                    let old = unsafe { *newWithOld };
                    // SAFETY: the reference taken above.
                    unsafe { X509_free(old) };
                }
            }
            // SAFETY: the reference taken above.
            unsafe { X509_free(nwn) };
        }
        // SAFETY: the ITAV received.
        unsafe { OSSL_CMP_ITAV_free(itav) };
        // SAFETY: the copy, or NULL.
        unsafe { X509_free(old_copy) };
        res
    }
}

ffi_export! {
    /// Asks the server for a CRL update (a genm with id-it-crlStatusList for `crlcert`'s CRL
    /// distribution point, or `last_crl`'s): 1 with the new CRL in `*crl` (NULL if there's
    /// none), a new reference; else 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `crlcert` and `last_crl` NULL or live; `crl` NULL or
    /// room for a pointer.
    pub unsafe extern "C" fn OSSL_CMP_get1_crlUpdate(ctx: *mut OSSL_CMP_CTX, crlcert: *const X509, last_crl: *const X509_CRL, crl: *mut *mut X509_CRL) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        const F: &str = "OSSL_CMP_get1_crlUpdate";
        // SAFETY: the caller's room, or NULL.
        let Some(crl) = (unsafe { crl.as_mut() }) else {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, F);
            return 0;
        };
        *crl = ptr::null_mut();
        let mut status: *mut OSSL_CMP_CRLSTATUS;
        let mut list: *mut Stack = ptr::null_mut();
        let mut itav: *mut OSSL_CMP_ITAV = ptr::null_mut();
        let mut res = 0;
        'end: {
            // SAFETY: the caller's CRL and certificate, or NULL.
            status = unsafe { OSSL_CMP_CRLSTATUS_create(last_crl, crlcert, 1) };
            if status.is_null() {
                err::raise(ERR_LIB_CMP, CMP_R_GENERATE_CRLSTATUS, F);
                break 'end;
            }
            // SAFETY: no preconditions.
            list = unsafe { OPENSSL_sk_new_reserve(None, 1) };
            if list.is_null() {
                err::raise(ERR_LIB_CMP, CMP_R_GENERATE_CRLSTATUS, F);
                break 'end;
            }
            // Can't fail, with the room reserved.
            // SAFETY: the list; the status, which it takes.
            unsafe { OPENSSL_sk_push(list, status.cast()) };
            // SAFETY: the list, which it takes.
            let req = unsafe { OSSL_CMP_ITAV_new0_crlStatusList(list.cast::<stack_st_OSSL_CMP_CRLSTATUS>()) };
            if req.is_null() {
                break 'end;
            }
            status = ptr::null_mut();
            list = ptr::null_mut();

            // SAFETY: the caller's context; the ITAV, which it takes.
            itav = unsafe { get_genm_itav(ctx, req, NID_id_it_crls, "crl") };
            if itav.is_null() {
                break 'end;
            }
            let mut crls: *mut stack_st_X509_CRL = ptr::null_mut();
            // SAFETY: the ITAV; the room.
            if unsafe { OSSL_CMP_ITAV_get0_crls(itav, &raw mut crls) } == 0 {
                break 'end;
            }
            if crls.is_null() {
                // No CRL update available.
                res = 1;
                break 'end;
            }
            // SAFETY: the ITAV's CRLs.
            let n = unsafe { OPENSSL_sk_num(crls.cast()) };
            if n != 1 {
                err::raise_with_text(ERR_LIB_CMP, CMP_R_INVALID_GENP, F, &format!("Unexpected number of CRLs in genp: {n}"));
                break 'end;
            }
            // SAFETY: as above.
            let first: *mut X509_CRL = unsafe { OPENSSL_sk_value(crls.cast(), 0) }.cast();
            // SAFETY: the CRL.
            if first.is_null() || unsafe { X509_CRL_up_ref(first) } == 0 {
                break 'end;
            }
            *crl = first;
            res = 1;
        }
        // SAFETY: the status if not taken, or NULL.
        unsafe { OSSL_CMP_CRLSTATUS_free(status) };
        // SAFETY: the list if not taken, or NULL.
        unsafe { OPENSSL_sk_free(list) };
        // SAFETY: the ITAV received, or NULL.
        unsafe { OSSL_CMP_ITAV_free(itav) };
        res
    }
}

ffi_export! {
    /// Asks the server for a certificate request template (a genm with
    /// id-it-certReqTemplate): 1 with copies of the template in `*certTemplate` (NULL if
    /// there's none) and, when asked, its key specification in `*keySpec`; else 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `certTemplate` and `keySpec` NULL or room.
    pub unsafe extern "C" fn OSSL_CMP_get1_certReqTemplate(ctx: *mut OSSL_CMP_CTX, certTemplate: *mut *mut OSSL_CRMF_CERTTEMPLATE, keySpec: *mut *mut OSSL_CMP_ATAVS) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        const F: &str = "OSSL_CMP_get1_certReqTemplate";
        // SAFETY: the caller's room, or NULL.
        if let Some(k) = unsafe { keySpec.as_mut() } {
            *k = ptr::null_mut();
        }
        if certTemplate.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, F);
            return 0;
        }
        // SAFETY: the caller's room.
        unsafe { *certTemplate = ptr::null_mut() };
        // SAFETY: no preconditions.
        let req = unsafe { OSSL_CMP_ITAV_new0_certReqTemplate(ptr::null_mut(), ptr::null_mut()) };
        if req.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_GENERATE_CERTREQTEMPLATE, F);
            return 0;
        }
        // SAFETY: the caller's context; the ITAV, which it takes.
        let itav = unsafe { get_genm_itav(ctx, req, NID_id_it_certReqTemplate, "certReqTemplate") };
        if itav.is_null() {
            return 0;
        }
        // SAFETY: the ITAV; the caller's rooms.
        let res = c_int::from(unsafe { OSSL_CMP_ITAV_get1_certReqTemplate(itav, certTemplate, keySpec) } != 0);
        // SAFETY: the ITAV received.
        unsafe { OSSL_CMP_ITAV_free(itav) };
        res
    }
}
