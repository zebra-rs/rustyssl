//! The CMP client's context (`cmp_ctx.c`): what a session sends, how it authenticates both
//! sides, the template of the certificate it asks for, what the server answered; and logging.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::panic::Location;
use core::ptr;

use rustyssl_abi::{
    ASN1_INTEGER, ASN1_OCTET_STRING, ASN1_UTF8STRING, CMP_R_FAILED_BUILDING_OWN_CHAIN,
    CMP_R_INVALID_OPTION, CMP_R_MULTIPLE_SAN_SOURCES, CMP_R_NULL_ARGUMENT,
    CMP_R_POTENTIALLY_INVALID_CERTIFICATE, CMP_R_UNSUPPORTED_ALGORITHM, CMP_R_VALUE_TOO_LARGE,
    CMP_R_VALUE_TOO_SMALL, CRL_REASON_NONE, ERR_LIB_CMP, ERR_LIB_X509, ERR_R_CRYPTO_LIB, EVP_MD,
    EVP_PKEY, GENERAL_NAME, NID_hmac_sha1, NID_sha256, NID_subject_alt_name,
    OCSP_REVOKED_STATUS_AACOMPROMISE, OCSP_REVOKED_STATUS_NOSTATUS, OSSL_CMP_CTX, OSSL_CMP_ITAV,
    OSSL_CMP_LOG_DEBUG, OSSL_CMP_LOG_ERR, OSSL_CMP_LOG_INFO, OSSL_CMP_LOG_MAX,
    OSSL_CMP_OPT_DIGEST_ALGNID, OSSL_CMP_OPT_DISABLE_CONFIRM, OSSL_CMP_OPT_IGNORE_KEYUSAGE,
    OSSL_CMP_OPT_IMPLICIT_CONFIRM, OSSL_CMP_OPT_KEEP_ALIVE, OSSL_CMP_OPT_LOG_VERBOSITY,
    OSSL_CMP_OPT_MAC_ALGNID, OSSL_CMP_OPT_MSG_TIMEOUT, OSSL_CMP_OPT_NO_CACHE_EXTRACERTS,
    OSSL_CMP_OPT_OWF_ALGNID, OSSL_CMP_OPT_PERMIT_TA_IN_EXTRACERTS_FOR_IR,
    OSSL_CMP_OPT_POLICIES_CRITICAL, OSSL_CMP_OPT_POPO_METHOD, OSSL_CMP_OPT_REVOCATION_REASON,
    OSSL_CMP_OPT_SUBJECTALTNAME_CRITICAL, OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT,
    OSSL_CMP_OPT_TOTAL_TIMEOUT, OSSL_CMP_OPT_UNPROTECTED_ERRORS, OSSL_CMP_OPT_UNPROTECTED_SEND,
    OSSL_CMP_OPT_USE_TLS, OSSL_CMP_OPT_VALIDITY_DAYS, OSSL_CMP_PKIFREETEXT,
    OSSL_CMP_PKISTATUS_unspecified, OSSL_CMP_certConf_cb_t, OSSL_CMP_log_cb_t, OSSL_CMP_severity,
    OSSL_CMP_transfer_cb_t, OSSL_CRMF_POPO_KEYAGREE, OSSL_CRMF_POPO_NONE, OSSL_CRMF_POPO_SIGNATURE,
    OSSL_HTTP_REQ_CTX, OSSL_HTTP_bio_cb_t, OSSL_LIB_CTX, POLICYINFO, X509, X509_ADD_FLAG_NO_DUP,
    X509_ADD_FLAG_PREPEND, X509_ADD_FLAG_UP_REF, X509_EXTENSIONS, X509_NAME, X509_REQ, X509_STORE,
    stack_st_OSSL_CMP_ITAV, stack_st_X509,
};

use super::asn::{OSSL_CMP_ITAV_free, OSSL_CMP_ITAV_push0_stack_item, Stack};
use super::util::{OSSL_CMP_print_errors_cb, asn1_octet_string_set1, asn1_octet_string_set1_bytes};
use crate::asn1::integer::ASN1_INTEGER_dup;
use crate::asn1::string::{ASN1_INTEGER_free, ASN1_OCTET_STRING_free, ASN1_UTF8STRING_free};
use crate::err;
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_get_type};
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_up_ref};
use crate::ffi::ffi_export;
use crate::http_client::OSSL_HTTP_close;
use crate::mem;
use crate::objects::OBJ_nid2sn;
use crate::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
};
use crate::string::CRYPTO_strdup;
use crate::x509::cert::{
    OSSL_STACK_OF_X509_free, X509_chain_up_ref, X509_free, X509_get0_pubkey, X509_up_ref,
};
use crate::x509::ext::{X509_EXTENSION_free, X509v3_get_ext_by_NID};
use crate::x509::name::{X509_NAME_dup, X509_NAME_free};
use crate::x509::purpose::{X509_add_cert, cache_extensions};
use crate::x509::req::{X509_REQ_dup, X509_REQ_free, X509_REQ_get0_pubkey};
use crate::x509::store::X509_STORE_free;
use crate::x509::verify::X509_build_chain;
use crate::x509v3::genn::{GENERAL_NAME_dup, GENERAL_NAME_free};
use crate::x509v3::policy::{CERTIFICATEPOLICIES_new, POLICYINFO_free};

/// `struct ossl_cmp_ctx_st` (opaque to applications), with OpenSSL's field names. Made by
/// `OSSL_CMP_CTX_new` as a `Box` and freed by `OSSL_CMP_CTX_free`.
pub(crate) struct Ctx {
    pub(crate) libctx: *mut OSSL_LIB_CTX,
    pub(crate) propq: *mut c_char,
    pub(crate) log_cb: OSSL_CMP_log_cb_t,
    pub(crate) log_verbosity: OSSL_CMP_severity,

    // Message transfer.
    pub(crate) transfer_cb: OSSL_CMP_transfer_cb_t,
    pub(crate) transfer_cb_arg: *mut c_void,
    pub(crate) http_ctx: *mut OSSL_HTTP_REQ_CTX,
    pub(crate) serverPath: *mut c_char,
    pub(crate) server: *mut c_char,
    pub(crate) serverPort: c_int,
    pub(crate) proxy: *mut c_char,
    pub(crate) no_proxy: *mut c_char,
    pub(crate) keep_alive: c_int,
    pub(crate) msg_timeout: c_int,
    pub(crate) total_timeout: c_int,
    pub(crate) tls_used: c_int,
    /// The session's start plus `total_timeout`, in seconds since the epoch (0: none).
    pub(crate) end_time: i64,
    pub(crate) http_cb: OSSL_HTTP_bio_cb_t,
    pub(crate) http_cb_arg: *mut c_void,

    // Server authentication.
    pub(crate) unprotectedErrors: c_int,
    pub(crate) noCacheExtraCerts: c_int,
    pub(crate) srvCert: *mut X509,
    pub(crate) validatedSrvCert: *mut X509,
    pub(crate) expected_sender: *mut X509_NAME,
    pub(crate) trusted: *mut X509_STORE,
    pub(crate) untrusted: *mut Stack,
    pub(crate) ignore_keyusage: c_int,
    pub(crate) permitTAInExtraCertsForIR: c_int,

    // Client authentication.
    pub(crate) unprotectedSend: c_int,
    pub(crate) cert: *mut X509,
    pub(crate) chain: *mut Stack,
    pub(crate) pkey: *mut EVP_PKEY,
    pub(crate) referenceValue: *mut ASN1_OCTET_STRING,
    pub(crate) secretValue: *mut ASN1_OCTET_STRING,
    pub(crate) pbm_slen: usize,
    pub(crate) pbm_owf: *mut EVP_MD,
    pub(crate) pbm_itercnt: c_int,
    pub(crate) pbm_mac: c_int,

    // The header and extra certificates.
    pub(crate) recipient: *mut X509_NAME,
    pub(crate) digest: *mut EVP_MD,
    pub(crate) transactionID: *mut ASN1_OCTET_STRING,
    pub(crate) senderNonce: *mut ASN1_OCTET_STRING,
    pub(crate) recipNonce: *mut ASN1_OCTET_STRING,
    pub(crate) first_senderNonce: *mut ASN1_OCTET_STRING,
    pub(crate) freeText: *mut ASN1_UTF8STRING,
    pub(crate) geninfo_ITAVs: *mut Stack,
    pub(crate) implicitConfirm: c_int,
    pub(crate) disableConfirm: c_int,
    pub(crate) extraCertsOut: *mut Stack,

    // The certificate template.
    pub(crate) newPkey: *mut EVP_PKEY,
    pub(crate) newPkey_priv: c_int,
    pub(crate) issuer: *mut X509_NAME,
    pub(crate) serialNumber: *mut ASN1_INTEGER,
    pub(crate) days: c_int,
    pub(crate) subjectName: *mut X509_NAME,
    pub(crate) subjectAltNames: *mut Stack,
    pub(crate) SubjectAltName_nodefault: c_int,
    pub(crate) setSubjectAltNameCritical: c_int,
    pub(crate) reqExtensions: *mut Stack,
    pub(crate) policies: *mut Stack,
    pub(crate) setPoliciesCritical: c_int,
    pub(crate) popoMethod: c_int,
    pub(crate) oldCert: *mut X509,
    pub(crate) p10CSR: *mut X509_REQ,

    // Other body contents.
    pub(crate) revocationReason: c_int,
    pub(crate) genm_ITAVs: *mut Stack,

    // What the last response said.
    pub(crate) status: c_int,
    pub(crate) statusString: *mut Stack,
    pub(crate) failInfoCode: c_int,
    pub(crate) newCert: *mut X509,
    pub(crate) newChain: *mut Stack,
    pub(crate) caPubs: *mut Stack,
    pub(crate) extraCertsIn: *mut Stack,

    // Certificate confirmation.
    pub(crate) certConf_cb: OSSL_CMP_certConf_cb_t,
    pub(crate) certConf_cb_arg: *mut c_void,
}

/// The context behind a handle.
///
/// # Safety
/// `ctx` is NULL or a live context, not otherwise borrowed mutably.
pub(crate) unsafe fn ctx_of<'a>(ctx: *const OSSL_CMP_CTX) -> Option<&'a mut Ctx> {
    // SAFETY: the caller's guarantee.
    unsafe { ctx.cast::<Ctx>().cast_mut().as_mut() }
}

/// `ossl_cmp_print_log` (and the `ossl_cmp_log*` macros): `msg`, already formatted, to the
/// context's log callback at `level` if its verbosity allows, with the calling function's name
/// `func` (OpenSSL's) and the caller's file and line. 1 when the message is dropped (no context,
/// no callback, or too verbose), 0 when it is empty or doesn't fit OpenSSL's 2 KiB buffer,
/// otherwise the callback's result.
///
/// # Safety
/// `ctx` is NULL or a live context.
#[track_caller]
pub(crate) unsafe fn print_log(
    level: OSSL_CMP_severity,
    ctx: *const OSSL_CMP_CTX,
    func: &CStr,
    msg: &str,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return 1;
    };
    let Some(cb) = c.log_cb else {
        return 1;
    };
    if level > c.log_verbosity {
        return 1;
    }
    // BIO_vsnprintf into 2048 octets fails rather than truncate, and OpenSSL calls the callback
    // only when it printed something.
    const HUGEBUF: usize = 1024 * 2;
    if msg.is_empty() || msg.len() >= HUGEBUF {
        return 0;
    }
    let mut text: Vec<u8> = Vec::with_capacity(msg.len() + 1);
    // An interior NUL ends the C string there, as it would have in OpenSSL's buffer.
    text.extend(msg.bytes().take_while(|&b| b != 0));
    text.push(0);
    let caller = Location::caller();
    let mut file: Vec<u8> = caller.file().bytes().filter(|&b| b != 0).collect();
    file.push(0);
    let line = c_int::try_from(caller.line()).unwrap_or(c_int::MAX);
    // SAFETY: the application's callback with NUL-terminated strings that outlive the call; no
    // lock is held.
    unsafe {
        cb(
            func.as_ptr(),
            file.as_ptr().cast(),
            line,
            level,
            text.as_ptr().cast(),
        )
    }
}

/// Raises `CMP_R_NULL_ARGUMENT` for the function `func`.
#[track_caller]
fn null_argument(func: &str) {
    err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, func);
}

/// `OPENSSL_strdup`.
///
/// # Safety
/// `s` is a NUL-terminated string.
unsafe fn strdup(s: *const c_char) -> *mut c_char {
    // SAFETY: the caller's guarantee.
    unsafe { CRYPTO_strdup(s, ptr::null(), 0) }
}

/// `OPENSSL_free` of a string.
///
/// # Safety
/// `s` is NULL or a string from `CRYPTO_malloc`, not used after.
unsafe fn free_str(s: *mut c_char) {
    // SAFETY: the caller's guarantee.
    unsafe { mem::free(s.cast(), ptr::null(), 0) };
}

/// `OSSL_CMP_ITAV_free` as a stack's free function.
unsafe extern "C" fn free_itav(p: *mut c_void) {
    // SAFETY: an element of the stack, which the stack owned.
    unsafe { OSSL_CMP_ITAV_free(p.cast()) };
}

/// `X509_EXTENSION_free` as a stack's free function.
unsafe extern "C" fn free_extension(p: *mut c_void) {
    // SAFETY: as above.
    unsafe { X509_EXTENSION_free(p.cast()) };
}

/// `ASN1_UTF8STRING_free` as a stack's free function.
unsafe extern "C" fn free_utf8string(p: *mut c_void) {
    // SAFETY: as above.
    unsafe { ASN1_UTF8STRING_free(p.cast()) };
}

/// `GENERAL_NAME_free` as a stack's free function.
unsafe extern "C" fn free_general_name(p: *mut c_void) {
    // SAFETY: as above.
    unsafe { GENERAL_NAME_free(p.cast()) };
}

/// `POLICYINFO_free` as a stack's free function.
unsafe extern "C" fn free_policyinfo(p: *mut c_void) {
    // SAFETY: as above.
    unsafe { POLICYINFO_free(p.cast()) };
}

/// `sk_<type>_pop_free(list, free)`.
///
/// # Safety
/// `list` is NULL or a live list whose elements `free` frees, not used after.
unsafe fn pop_free(list: *mut Stack, free: unsafe extern "C" fn(*mut c_void)) {
    // SAFETY: the caller's guarantee.
    unsafe { OPENSSL_sk_pop_free(list, Some(free)) };
}

/// `ossl_x509_add_certs_new`: adds `certs` to `*sk` with `X509_add_cert`'s `flags`, making the
/// list when the first certificate comes (`ERR_R_CRYPTO_LIB` if that fails).
///
/// # Safety
/// `*sk` is NULL or a live list; `certs` NULL or a live list.
unsafe fn add_certs_new(sk: &mut *mut Stack, certs: *mut stack_st_X509, flags: c_int) -> bool {
    // SAFETY: the caller's list, or NULL (0).
    let n = unsafe { OPENSSL_sk_num(certs.cast()) };
    for i in 0..n {
        let j = if flags & X509_ADD_FLAG_PREPEND == 0 {
            i
        } else {
            n - 1 - i
        };
        // SAFETY: an index in range.
        let cert: *mut X509 = unsafe { OPENSSL_sk_value(certs.cast(), j) }.cast();
        if sk.is_null() {
            // SAFETY: no preconditions.
            *sk = unsafe { OPENSSL_sk_new_null() };
            if sk.is_null() {
                err::raise(ERR_LIB_X509, ERR_R_CRYPTO_LIB, "ossl_x509_add_cert_new");
                return false;
            }
        }
        // SAFETY: the list; a certificate of the caller's list.
        if unsafe { X509_add_cert((*sk).cast(), cert, flags) } == 0 {
            return false;
        }
    }
    true
}

/// `cmp_ctx_set_md`'s fetch: the digest `nid` names, fetched in advance to fail early if it's
/// unsupported (`CMP_R_UNSUPPORTED_ALGORITHM`), or NULL.
///
/// # Safety
/// `c`'s library context and property query are live or NULL.
unsafe fn fetch_md(c: &Ctx, nid: c_int) -> *mut EVP_MD {
    // SAFETY: no preconditions.
    let name = unsafe { OBJ_nid2sn(nid) };
    // SAFETY: the context's library context and properties; the name, or NULL.
    let md = unsafe { EVP_MD_fetch(c.libctx, name, c.propq) };
    if md.is_null() {
        err::raise(ERR_LIB_CMP, CMP_R_UNSUPPORTED_ALGORITHM, "cmp_ctx_set_md");
    }
    md
}

/// `cmp_ctx_set_md`: replaces `*pmd` with the digest `nid` names: true, or false.
///
/// # Safety
/// As for [`fetch_md`]; `*pmd` is NULL or a live digest.
unsafe fn set_md(c: &Ctx, pmd: *mut *mut EVP_MD, nid: c_int) -> bool {
    // SAFETY: the caller's guarantee.
    let md = unsafe { fetch_md(c, nid) };
    if md.is_null() {
        return false;
    }
    // SAFETY: the caller's slot.
    let old = unsafe { *pmd };
    // SAFETY: the slot's digest, replaced.
    unsafe { EVP_MD_free(old) };
    // SAFETY: the caller's slot.
    unsafe { *pmd = md };
    true
}

impl Ctx {
    /// A context with every field zero or NULL, as `OPENSSL_zalloc` leaves it.
    fn zeroed() -> Self {
        Self {
            libctx: ptr::null_mut(),
            propq: ptr::null_mut(),
            log_cb: None,
            log_verbosity: 0,
            transfer_cb: None,
            transfer_cb_arg: ptr::null_mut(),
            http_ctx: ptr::null_mut(),
            serverPath: ptr::null_mut(),
            server: ptr::null_mut(),
            serverPort: 0,
            proxy: ptr::null_mut(),
            no_proxy: ptr::null_mut(),
            keep_alive: 0,
            msg_timeout: 0,
            total_timeout: 0,
            tls_used: 0,
            end_time: 0,
            http_cb: None,
            http_cb_arg: ptr::null_mut(),
            unprotectedErrors: 0,
            noCacheExtraCerts: 0,
            srvCert: ptr::null_mut(),
            validatedSrvCert: ptr::null_mut(),
            expected_sender: ptr::null_mut(),
            trusted: ptr::null_mut(),
            untrusted: ptr::null_mut(),
            ignore_keyusage: 0,
            permitTAInExtraCertsForIR: 0,
            unprotectedSend: 0,
            cert: ptr::null_mut(),
            chain: ptr::null_mut(),
            pkey: ptr::null_mut(),
            referenceValue: ptr::null_mut(),
            secretValue: ptr::null_mut(),
            pbm_slen: 0,
            pbm_owf: ptr::null_mut(),
            pbm_itercnt: 0,
            pbm_mac: 0,
            recipient: ptr::null_mut(),
            digest: ptr::null_mut(),
            transactionID: ptr::null_mut(),
            senderNonce: ptr::null_mut(),
            recipNonce: ptr::null_mut(),
            first_senderNonce: ptr::null_mut(),
            freeText: ptr::null_mut(),
            geninfo_ITAVs: ptr::null_mut(),
            implicitConfirm: 0,
            disableConfirm: 0,
            extraCertsOut: ptr::null_mut(),
            newPkey: ptr::null_mut(),
            newPkey_priv: 0,
            issuer: ptr::null_mut(),
            serialNumber: ptr::null_mut(),
            days: 0,
            subjectName: ptr::null_mut(),
            subjectAltNames: ptr::null_mut(),
            SubjectAltName_nodefault: 0,
            setSubjectAltNameCritical: 0,
            reqExtensions: ptr::null_mut(),
            policies: ptr::null_mut(),
            setPoliciesCritical: 0,
            popoMethod: 0,
            oldCert: ptr::null_mut(),
            p10CSR: ptr::null_mut(),
            revocationReason: 0,
            genm_ITAVs: ptr::null_mut(),
            status: 0,
            statusString: ptr::null_mut(),
            failInfoCode: 0,
            newCert: ptr::null_mut(),
            newChain: ptr::null_mut(),
            caPubs: ptr::null_mut(),
            extraCertsIn: ptr::null_mut(),
            certConf_cb: None,
            certConf_cb_arg: ptr::null_mut(),
        }
    }
}

ffi_export! {
    /// A new context with OpenSSL's defaults (verbosity INFO, SHA-256 for signatures and as the
    /// PBM's one-way function with 500 iterations and a 16-byte salt, HMAC-SHA1 as its MAC,
    /// signature POPO, keep-alive), or NULL.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `propq` NULL or a NUL-terminated string.
    pub unsafe extern "C" fn OSSL_CMP_CTX_new(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut OSSL_CMP_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        let mut c = Box::new(Ctx::zeroed());
        let ok = 'init: {
            c.libctx = libctx;
            if !propq.is_null() {
                // SAFETY: the caller's string.
                c.propq = unsafe { strdup(propq) };
                if c.propq.is_null() {
                    break 'init false;
                }
            }
            c.log_verbosity = OSSL_CMP_LOG_INFO;
            c.status = OSSL_CMP_PKISTATUS_unspecified;
            c.failInfoCode = -1;
            c.keep_alive = 1;
            c.msg_timeout = -1;
            // The default, for backward compatibility.
            c.tls_used = -1;
            // SAFETY: no preconditions.
            c.untrusted = unsafe { OPENSSL_sk_new_null() };
            if c.untrusted.is_null() {
                err::raise(ERR_LIB_X509, ERR_R_CRYPTO_LIB, "OSSL_CMP_CTX_new");
                break 'init false;
            }
            c.pbm_slen = 16;
            let mut owf = ptr::null_mut();
            // SAFETY: the context's library context and properties; a local slot.
            if !unsafe { set_md(&c, &raw mut owf, NID_sha256) } {
                break 'init false;
            }
            c.pbm_owf = owf;
            c.pbm_itercnt = 500;
            c.pbm_mac = NID_hmac_sha1;
            let mut digest = ptr::null_mut();
            // SAFETY: as above.
            if !unsafe { set_md(&c, &raw mut digest, NID_sha256) } {
                break 'init false;
            }
            c.digest = digest;
            c.popoMethod = OSSL_CRMF_POPO_SIGNATURE;
            c.revocationReason = CRL_REASON_NONE;
            true
        };
        let ctx: *mut OSSL_CMP_CTX = Box::into_raw(c).cast();
        if !ok {
            // SAFETY: the context made here, freed once.
            unsafe { OSSL_CMP_CTX_free(ctx) };
            return ptr::null_mut();
        }
        ctx
    }
}

ffi_export! {
    /// Prepares the context for another transaction: closes any HTTP connection, resets the
    /// status and failInfo, and drops the general message's ITAVs, the last response's results,
    /// the validated server certificate, the transactionID, and the nonces: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_reinit(ctx: *mut OSSL_CMP_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_reinit");
            return 0;
        };
        let http_ctx = c.http_ctx;
        c.http_ctx = ptr::null_mut();
        if !http_ctx.is_null() {
            // SAFETY: the context's connection, freed here.
            unsafe { OSSL_HTTP_close(http_ctx, 1) };
            // SAFETY: the caller's context.
            unsafe { print_log(OSSL_CMP_LOG_DEBUG, ctx, c"OSSL_CMP_CTX_reinit", "disconnected from CMP server") };
        }
        // Borrowed afresh: the log callback may have used the context.
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            return 0;
        };
        c.status = OSSL_CMP_PKISTATUS_unspecified;
        c.failInfoCode = -1;
        // SAFETY: the context's list, or NULL.
        unsafe { pop_free(c.genm_ITAVs, free_itav) };
        c.genm_ITAVs = ptr::null_mut();
        // SAFETY: the caller's context, for each call.
        let ok = unsafe { ctx_set0_statusString(ctx, ptr::null_mut()) } != 0
            // SAFETY: as above.
            && unsafe { ctx_set0_newCert(ctx, ptr::null_mut()) } != 0
            // SAFETY: as above.
            && unsafe { ctx_set1_newChain(ctx, ptr::null_mut()) } != 0
            // SAFETY: as above.
            && unsafe { ctx_set1_caPubs(ctx, ptr::null_mut()) } != 0
            // SAFETY: as above.
            && unsafe { ctx_set1_extraCertsIn(ctx, ptr::null_mut()) } != 0
            // SAFETY: as above.
            && unsafe { ctx_set1_validatedSrvCert(ctx, ptr::null_mut()) } != 0
            // SAFETY: as above.
            && unsafe { ctx_set1_first_senderNonce(ctx, ptr::null()) } != 0
            // SAFETY: as above.
            && unsafe { OSSL_CMP_CTX_set1_transactionID(ctx, ptr::null()) } != 0
            // SAFETY: as above.
            && unsafe { OSSL_CMP_CTX_set1_senderNonce(ctx, ptr::null()) } != 0
            // SAFETY: as above.
            && unsafe { ctx_set1_recipNonce(ctx, ptr::null()) } != 0;
        c_int::from(ok)
    }
}

ffi_export! {
    /// Frees the context and everything it holds (nothing for NULL), closing any HTTP
    /// connection; the shared secret is wiped first.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context, not used after.
    pub unsafe extern "C" fn OSSL_CMP_CTX_free(ctx: *mut OSSL_CMP_CTX)
    where failure = (), library = ERR_LIB_CMP
    {
        if ctx.is_null() {
            return;
        }
        // SAFETY: the caller's live context.
        let http_ctx = unsafe { (*ctx.cast::<Ctx>()).http_ctx };
        if !http_ctx.is_null() {
            // SAFETY: the context's connection, freed here.
            unsafe { OSSL_HTTP_close(http_ctx, 1) };
            // SAFETY: the caller's context, still whole.
            unsafe { print_log(OSSL_CMP_LOG_DEBUG, ctx, c"OSSL_CMP_CTX_free", "disconnected from CMP server") };
        }
        // SAFETY: made by `OSSL_CMP_CTX_new` with `Box::into_raw`; the caller's guarantee that
        // it is used no more.
        let c = unsafe { Box::from_raw(ctx.cast::<Ctx>()) };
        // SAFETY: each the context's own, or NULL, freed once with its type's function.
        unsafe { free_str(c.propq) };
        // SAFETY: as above.
        unsafe { free_str(c.serverPath) };
        // SAFETY: as above.
        unsafe { free_str(c.server) };
        // SAFETY: as above.
        unsafe { free_str(c.proxy) };
        // SAFETY: as above.
        unsafe { free_str(c.no_proxy) };

        // SAFETY: as above.
        unsafe { X509_free(c.srvCert) };
        // SAFETY: as above.
        unsafe { X509_free(c.validatedSrvCert) };
        // SAFETY: as above.
        unsafe { X509_NAME_free(c.expected_sender) };
        // SAFETY: as above.
        unsafe { X509_STORE_free(c.trusted) };
        // SAFETY: as above.
        unsafe { OSSL_STACK_OF_X509_free(c.untrusted.cast()) };

        // SAFETY: as above.
        unsafe { X509_free(c.cert) };
        // SAFETY: as above.
        unsafe { OSSL_STACK_OF_X509_free(c.chain.cast()) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(c.pkey) };
        // SAFETY: as above.
        unsafe { ASN1_OCTET_STRING_free(c.referenceValue) };
        // SAFETY: the secret, or NULL.
        unsafe { wipe_octet_string(c.secretValue) };
        // SAFETY: as above.
        unsafe { ASN1_OCTET_STRING_free(c.secretValue) };
        // SAFETY: as above.
        unsafe { EVP_MD_free(c.pbm_owf) };

        // SAFETY: as above.
        unsafe { X509_NAME_free(c.recipient) };
        // SAFETY: as above.
        unsafe { EVP_MD_free(c.digest) };
        // SAFETY: as above.
        unsafe { ASN1_OCTET_STRING_free(c.transactionID) };
        // SAFETY: as above.
        unsafe { ASN1_OCTET_STRING_free(c.senderNonce) };
        // SAFETY: as above.
        unsafe { ASN1_OCTET_STRING_free(c.recipNonce) };
        // SAFETY: as above.
        unsafe { ASN1_OCTET_STRING_free(c.first_senderNonce) };
        // SAFETY: as above.
        unsafe { pop_free(c.geninfo_ITAVs, free_itav) };
        // SAFETY: as above.
        unsafe { OSSL_STACK_OF_X509_free(c.extraCertsOut.cast()) };

        // SAFETY: as above.
        unsafe { EVP_PKEY_free(c.newPkey) };
        // SAFETY: as above.
        unsafe { X509_NAME_free(c.issuer) };
        // SAFETY: as above.
        unsafe { ASN1_INTEGER_free(c.serialNumber) };
        // SAFETY: as above.
        unsafe { X509_NAME_free(c.subjectName) };
        // SAFETY: as above.
        unsafe { pop_free(c.subjectAltNames, free_general_name) };
        // SAFETY: as above.
        unsafe { pop_free(c.reqExtensions, free_extension) };
        // SAFETY: as above.
        unsafe { pop_free(c.policies, free_policyinfo) };
        // SAFETY: as above.
        unsafe { X509_free(c.oldCert) };
        // SAFETY: as above.
        unsafe { X509_REQ_free(c.p10CSR) };

        // SAFETY: as above.
        unsafe { pop_free(c.genm_ITAVs, free_itav) };

        // SAFETY: as above.
        unsafe { pop_free(c.statusString, free_utf8string) };
        // SAFETY: as above.
        unsafe { X509_free(c.newCert) };
        // SAFETY: as above.
        unsafe { OSSL_STACK_OF_X509_free(c.newChain.cast()) };
        // SAFETY: as above.
        unsafe { OSSL_STACK_OF_X509_free(c.caPubs.cast()) };
        // SAFETY: as above.
        unsafe { OSSL_STACK_OF_X509_free(c.extraCertsIn.cast()) };
    }
}

/// `OPENSSL_cleanse` of an octet string's bytes (nothing for NULL).
///
/// # Safety
/// `s` is NULL or a live string.
unsafe fn wipe_octet_string(s: *mut ASN1_OCTET_STRING) {
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { s.as_ref() }) else {
        return;
    };
    if s.data.is_null() {
        return;
    }
    let len = usize::try_from(s.length).unwrap_or(0);
    // SAFETY: the string's `length` bytes.
    unsafe { mem::cleanse(s.data.cast(), len) };
}

ffi_export! {
    /// Replaces the trust store for authenticating the server (and any CRLs and verify
    /// callback with it), which the context takes; NULL resets it: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `val` NULL or a live store, owned by the context after.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set0_trustedStore(ctx: *mut OSSL_CMP_CTX, val: *mut X509_STORE) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set0_trustedStore");
            return 0;
        };
        // SAFETY: the context's own store, or NULL.
        unsafe { X509_STORE_free(c.trusted) };
        c.trusted = val;
        1
    }
}

/// `ossl_cmp_ctx_set0_statusString`: the last response's statusString, which the context takes:
/// 1, or 0.
///
/// # Safety
/// `ctx` is NULL or a live context; `text` NULL or a live list, owned by the context after.
pub(crate) unsafe fn ctx_set0_statusString(
    ctx: *mut OSSL_CMP_CTX,
    text: *mut OSSL_CMP_PKIFREETEXT,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        null_argument("ossl_cmp_ctx_set0_statusString");
        return 0;
    };
    // SAFETY: the context's own list, or NULL.
    unsafe { pop_free(c.statusString, free_utf8string) };
    c.statusString = text.cast();
    1
}

/// `ossl_cmp_ctx_set0_newCert`: the newly enrolled certificate, which the context takes: 1, or
/// 0.
///
/// # Safety
/// `ctx` is NULL or a live context; `cert` NULL or a live certificate, owned by the context
/// after.
pub(crate) unsafe fn ctx_set0_newCert(ctx: *mut OSSL_CMP_CTX, cert: *mut X509) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        null_argument("ossl_cmp_ctx_set0_newCert");
        return 0;
    };
    // SAFETY: the context's own certificate, or NULL.
    unsafe { X509_free(c.newCert) };
    c.newCert = cert;
    1
}

ffi_export! {
    /// Replaces the untrusted certificates for building chains with `certs`' (new references,
    /// without duplicates; none for NULL or empty): 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `certs` NULL or a live list.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set1_untrusted(ctx: *mut OSSL_CMP_CTX, certs: *mut stack_st_X509) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set1_untrusted");
            return 0;
        };
        let mut untrusted: *mut Stack = ptr::null_mut();
        // SAFETY: a local list; the caller's.
        if !unsafe { add_certs_new(&mut untrusted, certs, X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP) } {
            // SAFETY: the list made here, or NULL.
            unsafe { OSSL_STACK_OF_X509_free(untrusted.cast()) };
            return 0;
        }
        // SAFETY: the context's own list, or NULL.
        unsafe { OSSL_STACK_OF_X509_free(c.untrusted.cast()) };
        c.untrusted = untrusted;
        1
    }
}

ffi_export! {
    /// Sets the callback for log messages and error output (none for NULL): 1, or 0. With
    /// tracing disabled there is no trace channel to redirect.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `cb` a callback taking the strings it is given.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set_log_cb(ctx: *mut OSSL_CMP_CTX, cb: OSSL_CMP_log_cb_t) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set_log_cb");
            return 0;
        };
        c.log_cb = cb;
        1
    }
}

ffi_export! {
    /// Reports the error queue through the context's log callback (to standard error without
    /// one, or for a NULL context), unless its verbosity is below `OSSL_CMP_LOG_ERR`.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_print_errors(ctx: *const OSSL_CMP_CTX)
    where failure = (), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let c = unsafe { ctx_of(ctx) };
        if let Some(c) = &c
            && OSSL_CMP_LOG_ERR > c.log_verbosity
        {
            return;
        }
        let cb = c.and_then(|c| c.log_cb);
        // SAFETY: the context's callback, or none.
        unsafe { OSSL_CMP_print_errors_cb(cb) };
    }
}

ffi_export! {
    /// Sets (or with NULL clears) the reference value, the user name for PBM protection, to `len`
    /// bytes of `ref_`: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `ref_` NULL or `len` readable bytes.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set1_referenceValue(ctx: *mut OSSL_CMP_CTX, ref_: *const u8, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set1_referenceValue");
            return 0;
        };
        // SAFETY: the context's field; the caller's bytes.
        unsafe { asn1_octet_string_set1_bytes(&raw mut c.referenceValue, ref_, len) }
    }
}

ffi_export! {
    /// Sets (or with NULL clears) the shared secret for PBM protection to `len` bytes of `sec`,
    /// wiping the previous one: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `sec` NULL or `len` readable bytes.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set1_secretValue(ctx: *mut OSSL_CMP_CTX, sec: *const u8, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set1_secretValue");
            return 0;
        };
        let mut secret_value = ptr::null_mut();
        // SAFETY: a local slot; the caller's bytes.
        if unsafe { asn1_octet_string_set1_bytes(&raw mut secret_value, sec, len) } != 1 {
            return 0;
        }
        if !c.secretValue.is_null() {
            // SAFETY: the context's secret.
            unsafe { wipe_octet_string(c.secretValue) };
            // SAFETY: as above, freed once.
            unsafe { ASN1_OCTET_STRING_free(c.secretValue) };
        }
        c.secretValue = secret_value;
        1
    }
}

ffi_export! {
    /// Adds `pinfo`, which the context takes, to the certificate policies to request: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `pinfo` NULL or a live policy, owned by the context
    /// after success.
    pub unsafe extern "C" fn OSSL_CMP_CTX_push0_policy(ctx: *mut OSSL_CMP_CTX, pinfo: *mut POLICYINFO) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let c = unsafe { ctx_of(ctx) };
        let (Some(c), false) = (c, pinfo.is_null()) else {
            null_argument("OSSL_CMP_CTX_push0_policy");
            return 0;
        };
        if c.policies.is_null() {
            // SAFETY: no preconditions.
            c.policies = unsafe { CERTIFICATEPOLICIES_new() }.cast();
            if c.policies.is_null() {
                return 0;
            }
        }
        // SAFETY: the context's list; the caller's policy, which it takes.
        unsafe { OPENSSL_sk_push(c.policies, pinfo.cast_const().cast()) }
    }
}

ffi_export! {
    /// Adds `itav`, which the context takes, to the generalInfo of outgoing headers: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `itav` NULL or a live ITAV, owned by the context after
    /// success.
    pub unsafe extern "C" fn OSSL_CMP_CTX_push0_geninfo_ITAV(ctx: *mut OSSL_CMP_CTX, itav: *mut OSSL_CMP_ITAV) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_push0_geninfo_ITAV");
            return 0;
        };
        // SAFETY: the context's list slot; the caller's ITAV.
        unsafe { OSSL_CMP_ITAV_push0_stack_item((&raw mut c.geninfo_ITAVs).cast(), itav) }
    }
}

ffi_export! {
    /// Drops the ITAVs for the generalInfo of outgoing headers: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_reset_geninfo_ITAVs(ctx: *mut OSSL_CMP_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_reset_geninfo_ITAVs");
            return 0;
        };
        // SAFETY: the context's list, or NULL.
        unsafe { pop_free(c.geninfo_ITAVs, free_itav) };
        c.geninfo_ITAVs = ptr::null_mut();
        1
    }
}

ffi_export! {
    /// Adds `itav`, which the context takes, to the body of outgoing general messages: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `itav` NULL or a live ITAV, owned by the context after
    /// success.
    pub unsafe extern "C" fn OSSL_CMP_CTX_push0_genm_ITAV(ctx: *mut OSSL_CMP_CTX, itav: *mut OSSL_CMP_ITAV) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_push0_genm_ITAV");
            return 0;
        };
        // SAFETY: the context's list slot; the caller's ITAV.
        unsafe { OSSL_CMP_ITAV_push0_stack_item((&raw mut c.genm_ITAVs).cast(), itav) }
    }
}

ffi_export! {
    /// Replaces the extensions to request, which the context takes: 1, or 0 (with
    /// `CMP_R_MULTIPLE_SAN_SOURCES` if they have a subject alternative name and the context
    /// has SANs already).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `exts` NULL or a live list, owned by the context after
    /// success.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set0_reqExtensions(ctx: *mut OSSL_CMP_CTX, exts: *mut X509_EXTENSIONS) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set0_reqExtensions");
            return 0;
        };
        // SAFETY: the context's list, or NULL (0).
        if unsafe { OPENSSL_sk_num(c.subjectAltNames) } > 0
            && !exts.is_null()
            // SAFETY: the caller's list.
            && unsafe { X509v3_get_ext_by_NID(exts.cast_const().cast(), NID_subject_alt_name, -1) } >= 0
        {
            err::raise(ERR_LIB_CMP, CMP_R_MULTIPLE_SAN_SOURCES, "OSSL_CMP_CTX_set0_reqExtensions");
            return 0;
        }
        // SAFETY: the context's list, or NULL.
        unsafe { pop_free(c.reqExtensions, free_extension) };
        c.reqExtensions = exts.cast();
        1
    }
}

ffi_export! {
    /// Whether the extensions to request have a subject alternative name: 1 or 0, or -1 for a
    /// NULL context.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_reqExtensions_have_SAN(ctx: *mut OSSL_CMP_CTX) -> c_int
    where failure = -1, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_reqExtensions_have_SAN");
            return -1;
        };
        let have = !c.reqExtensions.is_null()
            // SAFETY: the context's list.
            && unsafe { X509v3_get_ext_by_NID(c.reqExtensions.cast_const().cast(), NID_subject_alt_name, -1) } >= 0;
        c_int::from(have)
    }
}

ffi_export! {
    /// Adds a copy of `name` to the subject alternative names to request: 1, or 0 (with
    /// `CMP_R_MULTIPLE_SAN_SOURCES` if the extensions to request have one).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `name` NULL or a live name.
    pub unsafe extern "C" fn OSSL_CMP_CTX_push1_subjectAltName(ctx: *mut OSSL_CMP_CTX, name: *const GENERAL_NAME) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        if ctx.is_null() || name.is_null() {
            null_argument("OSSL_CMP_CTX_push1_subjectAltName");
            return 0;
        }
        // SAFETY: the caller's context.
        if unsafe { OSSL_CMP_CTX_reqExtensions_have_SAN(ctx) } == 1 {
            err::raise(ERR_LIB_CMP, CMP_R_MULTIPLE_SAN_SOURCES, "OSSL_CMP_CTX_push1_subjectAltName");
            return 0;
        }
        // SAFETY: as above, checked non-NULL.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            return 0;
        };
        if c.subjectAltNames.is_null() {
            // SAFETY: no preconditions.
            c.subjectAltNames = unsafe { OPENSSL_sk_new_null() };
            if c.subjectAltNames.is_null() {
                return 0;
            }
        }
        // SAFETY: the caller's name.
        let name_dup = unsafe { GENERAL_NAME_dup(name) };
        if name_dup.is_null() {
            return 0;
        }
        // SAFETY: the context's list; the copy, which it takes.
        if unsafe { OPENSSL_sk_push(c.subjectAltNames, name_dup.cast_const().cast()) } == 0 {
            // SAFETY: the copy, not taken.
            unsafe { GENERAL_NAME_free(name_dup) };
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Adds `candidates` to the untrusted certificates and builds the chain of the client's own
    /// certificate with them and `own_trusted`: 1, or 0 (`CMP_R_FAILED_BUILDING_OWN_CHAIN`).
    /// OpenSSL drops an earlier chain without freeing it; this frees it.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `own_trusted` NULL or a live store; `candidates` NULL or
    /// a live list.
    pub unsafe extern "C" fn OSSL_CMP_CTX_build_cert_chain(ctx: *mut OSSL_CMP_CTX, own_trusted: *mut X509_STORE, candidates: *mut stack_st_X509) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_build_cert_chain");
            return 0;
        };
        // SAFETY: the context's list; the caller's.
        if !unsafe { add_certs_new(&mut c.untrusted, candidates, X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP) } {
            return 0;
        }
        let (cert, untrusted, libctx, propq) = (c.cert, c.untrusted, c.libctx, c.propq);
        // SAFETY: the caller's context.
        unsafe { print_log(OSSL_CMP_LOG_DEBUG, ctx, c"OSSL_CMP_CTX_build_cert_chain", "trying to build chain for own CMP signer cert") };
        // SAFETY: the context's certificate, list, library context, and properties; the
        // caller's store.
        let chain = unsafe { X509_build_chain(cert, untrusted.cast(), own_trusted, 0, libctx, propq) };
        if chain.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_FAILED_BUILDING_OWN_CHAIN, "OSSL_CMP_CTX_build_cert_chain");
            return 0;
        }
        // SAFETY: the caller's context.
        unsafe { print_log(OSSL_CMP_LOG_DEBUG, ctx, c"OSSL_CMP_CTX_build_cert_chain", "success building chain for own CMP signer cert") };
        // Borrowed afresh: the log callback may have used the context.
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            return 0;
        };
        // SAFETY: the context's earlier chain, or NULL.
        unsafe { OSSL_STACK_OF_X509_free(c.chain.cast()) };
        c.chain = chain.cast();
        1
    }
}

ffi_export! {
    /// Sets the new key pair to enroll (`priv`: whether it has the private key), which the
    /// context takes: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `pkey` NULL or a live key, owned by the context after.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set0_newPkey(ctx: *mut OSSL_CMP_CTX, priv_: c_int, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set0_newPkey");
            return 0;
        };
        // SAFETY: the context's own key, or NULL.
        unsafe { EVP_PKEY_free(c.newPkey) };
        c.newPkey = pkey;
        c.newPkey_priv = priv_;
        1
    }
}

ffi_export! {
    /// The key to enroll: the new key (NULL if `priv_` and it has no private key), else the
    /// PKCS #10 request's public key (NULL if `priv_`), else the client's key; or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_get0_newPkey(ctx: *const OSSL_CMP_CTX, priv_: c_int) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_get0_newPkey");
            return ptr::null_mut();
        };
        if !c.newPkey.is_null() {
            return if priv_ != 0 && c.newPkey_priv == 0 { ptr::null_mut() } else { c.newPkey };
        }
        if !c.p10CSR.is_null() {
            if priv_ != 0 {
                return ptr::null_mut();
            }
            // SAFETY: the context's request.
            return unsafe { X509_REQ_get0_pubkey(c.p10CSR) };
        }
        c.pkey
    }
}

/// `ossl_cmp_ctx_get0_newPubkey`: the public key to enroll: the new key, else the PKCS #10
/// request's, the old certificate's, the client certificate's, else the client's key; NULL
/// (with no error, OpenSSL's `ossl_assert` in a release build) for a NULL context.
///
/// # Safety
/// `ctx` is NULL or a live context.
pub(crate) unsafe fn ctx_get0_newPubkey(ctx: *const OSSL_CMP_CTX) -> *mut EVP_PKEY {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return ptr::null_mut();
    };
    if !c.newPkey.is_null() {
        return c.newPkey;
    }
    if !c.p10CSR.is_null() {
        // SAFETY: the context's request.
        return unsafe { X509_REQ_get0_pubkey(c.p10CSR) };
    }
    if !c.oldCert.is_null() {
        // SAFETY: the context's certificate.
        return unsafe { X509_get0_pubkey(c.oldCert) };
    }
    if !c.cert.is_null() {
        // SAFETY: as above.
        return unsafe { X509_get0_pubkey(c.cert) };
    }
    c.pkey
}

ffi_export! {
    /// Sets a Boolean or integer option: 1, or 0 (`CMP_R_VALUE_TOO_SMALL` below its minimum, 0
    /// for most, -1 for the revocation reason, `OSSL_CRMF_POPO_NONE` for the POPO method;
    /// `CMP_R_VALUE_TOO_LARGE` above its maximum; `CMP_R_UNSUPPORTED_ALGORITHM` for a digest
    /// that can't be fetched; `CMP_R_INVALID_OPTION` for an unknown one).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set_option(ctx: *mut OSSL_CMP_CTX, opt: c_int, val: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        const F: &str = "OSSL_CMP_CTX_set_option";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument(F);
            return 0;
        };
        let min_val = match opt {
            OSSL_CMP_OPT_REVOCATION_REASON => OCSP_REVOKED_STATUS_NOSTATUS,
            OSSL_CMP_OPT_POPO_METHOD => OSSL_CRMF_POPO_NONE,
            _ => 0,
        };
        if val < min_val {
            err::raise(ERR_LIB_CMP, CMP_R_VALUE_TOO_SMALL, F);
            return 0;
        }
        match opt {
            OSSL_CMP_OPT_LOG_VERBOSITY => {
                if val > OSSL_CMP_LOG_MAX {
                    err::raise(ERR_LIB_CMP, CMP_R_VALUE_TOO_LARGE, F);
                    return 0;
                }
                c.log_verbosity = val;
            }
            OSSL_CMP_OPT_IMPLICIT_CONFIRM => c.implicitConfirm = val,
            OSSL_CMP_OPT_DISABLE_CONFIRM => c.disableConfirm = val,
            OSSL_CMP_OPT_UNPROTECTED_SEND => c.unprotectedSend = val,
            OSSL_CMP_OPT_UNPROTECTED_ERRORS => c.unprotectedErrors = val,
            OSSL_CMP_OPT_NO_CACHE_EXTRACERTS => c.noCacheExtraCerts = val,
            OSSL_CMP_OPT_VALIDITY_DAYS => c.days = val,
            OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT => c.SubjectAltName_nodefault = val,
            OSSL_CMP_OPT_SUBJECTALTNAME_CRITICAL => c.setSubjectAltNameCritical = val,
            OSSL_CMP_OPT_POLICIES_CRITICAL => c.setPoliciesCritical = val,
            OSSL_CMP_OPT_IGNORE_KEYUSAGE => c.ignore_keyusage = val,
            OSSL_CMP_OPT_POPO_METHOD => {
                if val > OSSL_CRMF_POPO_KEYAGREE {
                    err::raise(ERR_LIB_CMP, CMP_R_VALUE_TOO_LARGE, F);
                    return 0;
                }
                c.popoMethod = val;
            }
            OSSL_CMP_OPT_DIGEST_ALGNID => {
                let mut md = c.digest;
                // SAFETY: the context's library context and properties; a local slot holding
                // its digest.
                let ok = unsafe { set_md(c, &raw mut md, val) };
                c.digest = md;
                if !ok {
                    return 0;
                }
            }
            OSSL_CMP_OPT_OWF_ALGNID => {
                let mut md = c.pbm_owf;
                // SAFETY: as above.
                let ok = unsafe { set_md(c, &raw mut md, val) };
                c.pbm_owf = md;
                if !ok {
                    return 0;
                }
            }
            OSSL_CMP_OPT_MAC_ALGNID => c.pbm_mac = val,
            OSSL_CMP_OPT_KEEP_ALIVE => c.keep_alive = val,
            OSSL_CMP_OPT_MSG_TIMEOUT => c.msg_timeout = val,
            OSSL_CMP_OPT_TOTAL_TIMEOUT => c.total_timeout = val,
            OSSL_CMP_OPT_USE_TLS => c.tls_used = val,
            OSSL_CMP_OPT_PERMIT_TA_IN_EXTRACERTS_FOR_IR => c.permitTAInExtraCertsForIR = val,
            OSSL_CMP_OPT_REVOCATION_REASON => {
                if val > OCSP_REVOKED_STATUS_AACOMPROMISE {
                    err::raise(ERR_LIB_CMP, CMP_R_VALUE_TOO_LARGE, F);
                    return 0;
                }
                c.revocationReason = val;
            }
            _ => {
                err::raise(ERR_LIB_CMP, CMP_R_INVALID_OPTION, F);
                return 0;
            }
        }
        1
    }
}

ffi_export! {
    /// A Boolean or integer option's value, or -1 (`CMP_R_INVALID_OPTION` for an unknown one).
    /// -1 is also the default revocation reason.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_get_option(ctx: *const OSSL_CMP_CTX, opt: c_int) -> c_int
    where failure = -1, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_get_option");
            return -1;
        };
        match opt {
            OSSL_CMP_OPT_LOG_VERBOSITY => c.log_verbosity,
            OSSL_CMP_OPT_IMPLICIT_CONFIRM => c.implicitConfirm,
            OSSL_CMP_OPT_DISABLE_CONFIRM => c.disableConfirm,
            OSSL_CMP_OPT_UNPROTECTED_SEND => c.unprotectedSend,
            OSSL_CMP_OPT_UNPROTECTED_ERRORS => c.unprotectedErrors,
            OSSL_CMP_OPT_NO_CACHE_EXTRACERTS => c.noCacheExtraCerts,
            OSSL_CMP_OPT_VALIDITY_DAYS => c.days,
            OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT => c.SubjectAltName_nodefault,
            OSSL_CMP_OPT_SUBJECTALTNAME_CRITICAL => c.setSubjectAltNameCritical,
            OSSL_CMP_OPT_POLICIES_CRITICAL => c.setPoliciesCritical,
            OSSL_CMP_OPT_IGNORE_KEYUSAGE => c.ignore_keyusage,
            OSSL_CMP_OPT_POPO_METHOD => c.popoMethod,
            // SAFETY: the context's digest.
            OSSL_CMP_OPT_DIGEST_ALGNID => unsafe { EVP_MD_get_type(c.digest) },
            // SAFETY: as above.
            OSSL_CMP_OPT_OWF_ALGNID => unsafe { EVP_MD_get_type(c.pbm_owf) },
            OSSL_CMP_OPT_MAC_ALGNID => c.pbm_mac,
            OSSL_CMP_OPT_KEEP_ALIVE => c.keep_alive,
            OSSL_CMP_OPT_MSG_TIMEOUT => c.msg_timeout,
            OSSL_CMP_OPT_TOTAL_TIMEOUT => c.total_timeout,
            OSSL_CMP_OPT_USE_TLS => c.tls_used,
            OSSL_CMP_OPT_PERMIT_TA_IN_EXTRACERTS_FOR_IR => c.permitTAInExtraCertsForIR,
            OSSL_CMP_OPT_REVOCATION_REASON => c.revocationReason,
            _ => {
                err::raise(ERR_LIB_CMP, CMP_R_INVALID_OPTION, "OSSL_CMP_CTX_get_option");
                -1
            }
        }
    }
}

ffi_export! {
    /// The trust store for authenticating the server, or NULL. Raises `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_get0_trustedStore(ctx: *const OSSL_CMP_CTX) -> *mut X509_STORE
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_get0_trustedStore");
            return ptr::null_mut();
        };
        c.trusted
    }
}

ffi_export! {
    /// The library context, or NULL. Raises `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_get0_libctx(ctx: *const OSSL_CMP_CTX) -> *mut OSSL_LIB_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_get0_libctx");
            return ptr::null_mut();
        };
        c.libctx
    }
}

ffi_export! {
    /// The property query, or NULL. Raises `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_get0_propq(ctx: *const OSSL_CMP_CTX) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_get0_propq");
            return ptr::null();
        };
        c.propq.cast_const()
    }
}

ffi_export! {
    /// The untrusted certificates for building chains, or NULL. Raises `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_get0_untrusted(ctx: *const OSSL_CMP_CTX) -> *mut stack_st_X509
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_get0_untrusted");
            return ptr::null_mut();
        };
        c.untrusted.cast()
    }
}

ffi_export! {
    /// The statusString of the last response, or NULL. Raises `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_get0_statusString(ctx: *const OSSL_CMP_CTX) -> *mut OSSL_CMP_PKIFREETEXT
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_get0_statusString");
            return ptr::null_mut();
        };
        c.statusString.cast()
    }
}

ffi_export! {
    /// The ITAVs for the generalInfo of outgoing headers, or NULL. Raises `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_get0_geninfo_ITAVs(ctx: *const OSSL_CMP_CTX) -> *mut stack_st_OSSL_CMP_ITAV
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_get0_geninfo_ITAVs");
            return ptr::null_mut();
        };
        c.geninfo_ITAVs.cast()
    }
}

ffi_export! {
    /// The server certificate validated in this transaction, or NULL. Raises `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_get0_validatedSrvCert(ctx: *const OSSL_CMP_CTX) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_get0_validatedSrvCert");
            return ptr::null_mut();
        };
        c.validatedSrvCert
    }
}

ffi_export! {
    /// The newly enrolled certificate, or NULL. Raises `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_get0_newCert(ctx: *const OSSL_CMP_CTX) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_get0_newCert");
            return ptr::null_mut();
        };
        c.newCert
    }
}

ffi_export! {
    /// Sets the callback that checks a newly enrolled certificate: 1, or 0. Raises `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set_certConf_cb(ctx: *mut OSSL_CMP_CTX, val: OSSL_CMP_certConf_cb_t) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set_certConf_cb");
            return 0;
        };
        c.certConf_cb = val;
        1
    }
}

ffi_export! {
    /// Sets the certConf callback's argument: 1, or 0. Raises `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set_certConf_cb_arg(ctx: *mut OSSL_CMP_CTX, val: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set_certConf_cb_arg");
            return 0;
        };
        c.certConf_cb_arg = val;
        1
    }
}

ffi_export! {
    /// Sets the HTTP connect/disconnect callback: 1, or 0. Raises `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set_http_cb(ctx: *mut OSSL_CMP_CTX, val: OSSL_HTTP_bio_cb_t) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set_http_cb");
            return 0;
        };
        c.http_cb = val;
        1
    }
}

ffi_export! {
    /// Sets the HTTP callback's argument: 1, or 0. Raises `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set_http_cb_arg(ctx: *mut OSSL_CMP_CTX, val: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set_http_cb_arg");
            return 0;
        };
        c.http_cb_arg = val;
        1
    }
}

ffi_export! {
    /// Sets the callback that sends a request and returns the response: 1, or 0. Raises `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set_transfer_cb(ctx: *mut OSSL_CMP_CTX, val: OSSL_CMP_transfer_cb_t) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set_transfer_cb");
            return 0;
        };
        c.transfer_cb = val;
        1
    }
}

ffi_export! {
    /// Sets the transfer callback's argument: 1, or 0. Raises `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set_transfer_cb_arg(ctx: *mut OSSL_CMP_CTX, val: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set_transfer_cb_arg");
            return 0;
        };
        c.transfer_cb_arg = val;
        1
    }
}

ffi_export! {
    /// Sets the server's HTTP port: 1, or 0. Raises `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set_serverPort(ctx: *mut OSSL_CMP_CTX, val: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set_serverPort");
            return 0;
        };
        c.serverPort = val;
        1
    }
}

ffi_export! {
    /// The PKIStatus of the last response, or -1. Raises `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_get_status(ctx: *const OSSL_CMP_CTX) -> c_int
    where failure = -1, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_get_status");
            return -1;
        };
        c.status
    }
}

ffi_export! {
    /// The failInfo bits of the last response, or -1. Raises `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_get_failInfoCode(ctx: *const OSSL_CMP_CTX) -> c_int
    where failure = -1, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_get_failInfoCode");
            return -1;
        };
        c.failInfoCode
    }
}

ffi_export! {
    /// The certConf callback's argument, or NULL. Raises `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_get_certConf_cb_arg(ctx: *const OSSL_CMP_CTX) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_get_certConf_cb_arg");
            return ptr::null_mut();
        };
        c.certConf_cb_arg
    }
}

ffi_export! {
    /// The HTTP callback's argument, or NULL. Raises `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_get_http_cb_arg(ctx: *const OSSL_CMP_CTX) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_get_http_cb_arg");
            return ptr::null_mut();
        };
        c.http_cb_arg
    }
}

ffi_export! {
    /// The transfer callback's argument, or NULL. Raises `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_get_transfer_cb_arg(ctx: *const OSSL_CMP_CTX) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_get_transfer_cb_arg");
            return ptr::null_mut();
        };
        c.transfer_cb_arg
    }
}

ffi_export! {
    /// Sets the recipient for the header to a copy of `name` (none for NULL): 1, or 0. Raises
    /// `CMP_R_NULL_ARGUMENT` for a NULL context.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `name` NULL or a live value.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set1_recipient(ctx: *mut OSSL_CMP_CTX, name: *const X509_NAME) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set1_recipient");
            return 0;
        };
        let mut val_dup = ptr::null_mut();
        if !name.is_null() {
            // SAFETY: the caller's value.
            val_dup = unsafe { X509_NAME_dup(name) };
            if val_dup.is_null() {
                return 0;
            }
        }
        // SAFETY: the context's own, or NULL.
        unsafe { X509_NAME_free(c.recipient) };
        c.recipient = val_dup;
        1
    }
}

ffi_export! {
    /// Sets the sender expected in responses to a copy of `name` (none for NULL): 1, or 0. Raises
    /// `CMP_R_NULL_ARGUMENT` for a NULL context.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `name` NULL or a live value.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set1_expected_sender(ctx: *mut OSSL_CMP_CTX, name: *const X509_NAME) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set1_expected_sender");
            return 0;
        };
        let mut val_dup = ptr::null_mut();
        if !name.is_null() {
            // SAFETY: the caller's value.
            val_dup = unsafe { X509_NAME_dup(name) };
            if val_dup.is_null() {
                return 0;
            }
        }
        // SAFETY: the context's own, or NULL.
        unsafe { X509_NAME_free(c.expected_sender) };
        c.expected_sender = val_dup;
        1
    }
}

ffi_export! {
    /// Sets the issuer for the certificate template to a copy of `name` (none for NULL): 1, or 0. Raises
    /// `CMP_R_NULL_ARGUMENT` for a NULL context.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `name` NULL or a live value.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set1_issuer(ctx: *mut OSSL_CMP_CTX, name: *const X509_NAME) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set1_issuer");
            return 0;
        };
        let mut val_dup = ptr::null_mut();
        if !name.is_null() {
            // SAFETY: the caller's value.
            val_dup = unsafe { X509_NAME_dup(name) };
            if val_dup.is_null() {
                return 0;
            }
        }
        // SAFETY: the context's own, or NULL.
        unsafe { X509_NAME_free(c.issuer) };
        c.issuer = val_dup;
        1
    }
}

ffi_export! {
    /// Sets the serial number for revocation requests to a copy of `sn` (none for NULL): 1, or 0. Raises
    /// `CMP_R_NULL_ARGUMENT` for a NULL context.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `sn` NULL or a live value.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set1_serialNumber(ctx: *mut OSSL_CMP_CTX, sn: *const ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set1_serialNumber");
            return 0;
        };
        let mut val_dup = ptr::null_mut();
        if !sn.is_null() {
            // SAFETY: the caller's value.
            val_dup = unsafe { ASN1_INTEGER_dup(sn) };
            if val_dup.is_null() {
                return 0;
            }
        }
        // SAFETY: the context's own, or NULL.
        unsafe { ASN1_INTEGER_free(c.serialNumber) };
        c.serialNumber = val_dup;
        1
    }
}

ffi_export! {
    /// Sets the subject for the certificate template to a copy of `name` (none for NULL): 1, or 0. Raises
    /// `CMP_R_NULL_ARGUMENT` for a NULL context.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `name` NULL or a live value.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set1_subjectName(ctx: *mut OSSL_CMP_CTX, name: *const X509_NAME) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set1_subjectName");
            return 0;
        };
        let mut val_dup = ptr::null_mut();
        if !name.is_null() {
            // SAFETY: the caller's value.
            val_dup = unsafe { X509_NAME_dup(name) };
            if val_dup.is_null() {
                return 0;
            }
        }
        // SAFETY: the context's own, or NULL.
        unsafe { X509_NAME_free(c.subjectName) };
        c.subjectName = val_dup;
        1
    }
}

ffi_export! {
    /// Sets the PKCS #10 request for P10CR to a copy of `csr` (none for NULL): 1, or 0. Raises
    /// `CMP_R_NULL_ARGUMENT` for a NULL context.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `csr` NULL or a live value.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set1_p10CSR(ctx: *mut OSSL_CMP_CTX, csr: *const X509_REQ) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set1_p10CSR");
            return 0;
        };
        let mut val_dup = ptr::null_mut();
        if !csr.is_null() {
            // SAFETY: the caller's value.
            val_dup = unsafe { X509_REQ_dup(csr) };
            if val_dup.is_null() {
                return 0;
            }
        }
        // SAFETY: the context's own, or NULL.
        unsafe { X509_REQ_free(c.p10CSR) };
        c.p10CSR = val_dup;
        1
    }
}

ffi_export! {
    /// Sets the HTTP(S) proxy to a copy of `name` (none for NULL): 1, or 0. Raises
    /// `CMP_R_NULL_ARGUMENT` for a NULL context.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `name` NULL or a live value.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set1_proxy(ctx: *mut OSSL_CMP_CTX, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set1_proxy");
            return 0;
        };
        let mut val_dup = ptr::null_mut();
        if !name.is_null() {
            // SAFETY: the caller's value.
            val_dup = unsafe { strdup(name) };
            if val_dup.is_null() {
                return 0;
            }
        }
        // SAFETY: the context's own, or NULL.
        unsafe { free_str(c.proxy) };
        c.proxy = val_dup;
        1
    }
}

ffi_export! {
    /// Sets the server's host name or address to a copy of `address` (none for NULL): 1, or 0. Raises
    /// `CMP_R_NULL_ARGUMENT` for a NULL context.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `address` NULL or a live value.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set1_server(ctx: *mut OSSL_CMP_CTX, address: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set1_server");
            return 0;
        };
        let mut val_dup = ptr::null_mut();
        if !address.is_null() {
            // SAFETY: the caller's value.
            val_dup = unsafe { strdup(address) };
            if val_dup.is_null() {
                return 0;
            }
        }
        // SAFETY: the context's own, or NULL.
        unsafe { free_str(c.server) };
        c.server = val_dup;
        1
    }
}

ffi_export! {
    /// Sets the hosts not to reach through the proxy to a copy of `names` (none for NULL): 1, or 0. Raises
    /// `CMP_R_NULL_ARGUMENT` for a NULL context.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `names` NULL or a live value.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set1_no_proxy(ctx: *mut OSSL_CMP_CTX, names: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set1_no_proxy");
            return 0;
        };
        let mut val_dup = ptr::null_mut();
        if !names.is_null() {
            // SAFETY: the caller's value.
            val_dup = unsafe { strdup(names) };
            if val_dup.is_null() {
                return 0;
            }
        }
        // SAFETY: the context's own, or NULL.
        unsafe { free_str(c.no_proxy) };
        c.no_proxy = val_dup;
        1
    }
}

ffi_export! {
    /// Sets the HTTP path on the server to a copy of `path` (none for NULL): 1, or 0. Raises
    /// `CMP_R_NULL_ARGUMENT` for a NULL context.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `path` NULL or a live value.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set1_serverPath(ctx: *mut OSSL_CMP_CTX, path: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set1_serverPath");
            return 0;
        };
        let mut val_dup = ptr::null_mut();
        if !path.is_null() {
            // SAFETY: the caller's value.
            val_dup = unsafe { strdup(path) };
            if val_dup.is_null() {
                return 0;
            }
        }
        // SAFETY: the context's own, or NULL.
        unsafe { free_str(c.serverPath) };
        c.serverPath = val_dup;
        1
    }
}

/// `ossl_cmp_ctx_set1_validatedSrvCert`: caches the server certificate validated in this transaction (a new reference; none for NULL): 1, or 0.
///
/// # Safety
/// `ctx` is NULL or a live context; `cert` NULL or live.
pub(crate) unsafe fn ctx_set1_validatedSrvCert(ctx: *mut OSSL_CMP_CTX, cert: *mut X509) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        null_argument("ossl_cmp_ctx_set1_validatedSrvCert");
        return 0;
    };
    // A malformed certificate (or a provider's failure) would mislead later.
    // SAFETY: the caller's certificate.
    if !cert.is_null() && !unsafe { cache_extensions(cert) } {
        err::raise(
            ERR_LIB_CMP,
            CMP_R_POTENTIALLY_INVALID_CERTIFICATE,
            "ossl_cmp_ctx_set1_validatedSrvCert",
        );
        return 0;
    }
    // SAFETY: the caller's value.
    if !cert.is_null() && unsafe { X509_up_ref(cert) } == 0 {
        return 0;
    }
    // SAFETY: the context's own reference, or NULL.
    unsafe { X509_free(c.validatedSrvCert) };
    c.validatedSrvCert = cert;
    1
}

ffi_export! {
    /// Pins the server's certificate, trusted directly (even expired) (a new reference; none for NULL): 1, or 0. Raises
    /// `CMP_R_NULL_ARGUMENT` for a NULL context, `CMP_R_POTENTIALLY_INVALID_CERTIFICATE` for a
    /// certificate whose extensions don't parse.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `cert` NULL or live.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set1_srvCert(ctx: *mut OSSL_CMP_CTX, cert: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set1_srvCert");
            return 0;
        };
        // A malformed certificate (or a provider's failure) would mislead later.
        // SAFETY: the caller's certificate.
        if !cert.is_null() && !unsafe { cache_extensions(cert) } {
            err::raise(ERR_LIB_CMP, CMP_R_POTENTIALLY_INVALID_CERTIFICATE, "OSSL_CMP_CTX_set1_srvCert");
            return 0;
        }
        // SAFETY: the caller's value.
        if !cert.is_null() && unsafe { X509_up_ref(cert) } == 0 {
            return 0;
        }
        // SAFETY: the context's own reference, or NULL.
        unsafe { X509_free(c.srvCert) };
        c.srvCert = cert;
        1
    }
}

ffi_export! {
    /// Sets the client's own protection certificate (a new reference; none for NULL): 1, or 0. Raises
    /// `CMP_R_NULL_ARGUMENT` for a NULL context, `CMP_R_POTENTIALLY_INVALID_CERTIFICATE` for a
    /// certificate whose extensions don't parse.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `cert` NULL or live.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set1_cert(ctx: *mut OSSL_CMP_CTX, cert: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set1_cert");
            return 0;
        };
        // A malformed certificate (or a provider's failure) would mislead later.
        // SAFETY: the caller's certificate.
        if !cert.is_null() && !unsafe { cache_extensions(cert) } {
            err::raise(ERR_LIB_CMP, CMP_R_POTENTIALLY_INVALID_CERTIFICATE, "OSSL_CMP_CTX_set1_cert");
            return 0;
        }
        // SAFETY: the caller's value.
        if !cert.is_null() && unsafe { X509_up_ref(cert) } == 0 {
            return 0;
        }
        // SAFETY: the context's own reference, or NULL.
        unsafe { X509_free(c.cert) };
        c.cert = cert;
        1
    }
}

ffi_export! {
    /// Sets the certificate to update (KUR) or revoke (RR), also the reference for the template's subject and SANs (a new reference; none for NULL): 1, or 0. Raises
    /// `CMP_R_NULL_ARGUMENT` for a NULL context, `CMP_R_POTENTIALLY_INVALID_CERTIFICATE` for a
    /// certificate whose extensions don't parse.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `cert` NULL or live.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set1_oldCert(ctx: *mut OSSL_CMP_CTX, cert: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set1_oldCert");
            return 0;
        };
        // A malformed certificate (or a provider's failure) would mislead later.
        // SAFETY: the caller's certificate.
        if !cert.is_null() && !unsafe { cache_extensions(cert) } {
            err::raise(ERR_LIB_CMP, CMP_R_POTENTIALLY_INVALID_CERTIFICATE, "OSSL_CMP_CTX_set1_oldCert");
            return 0;
        }
        // SAFETY: the caller's value.
        if !cert.is_null() && unsafe { X509_up_ref(cert) } == 0 {
            return 0;
        }
        // SAFETY: the context's own reference, or NULL.
        unsafe { X509_free(c.oldCert) };
        c.oldCert = cert;
        1
    }
}

ffi_export! {
    /// Sets the client's private key (a new reference; none for NULL): 1, or 0. Raises
    /// `CMP_R_NULL_ARGUMENT` for a NULL context.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `pkey` NULL or live.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set1_pkey(ctx: *mut OSSL_CMP_CTX, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set1_pkey");
            return 0;
        };
        // SAFETY: the caller's value.
        if !pkey.is_null() && unsafe { EVP_PKEY_up_ref(pkey) } == 0 {
            return 0;
        }
        // SAFETY: the context's own reference, or NULL.
        unsafe { EVP_PKEY_free(c.pkey) };
        c.pkey = pkey;
        1
    }
}

/// `ossl_cmp_ctx_set1_newChain`: replaces the context's `newChain` with a copy of `certs` sharing the certificates (none for
/// NULL): 1, or 0.
///
/// # Safety
/// `ctx` is NULL or a live context; `certs` NULL or a live list.
pub(crate) unsafe fn ctx_set1_newChain(ctx: *mut OSSL_CMP_CTX, certs: *mut stack_st_X509) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        null_argument("ossl_cmp_ctx_set1_newChain");
        return 0;
    };
    // SAFETY: the context's own list, or NULL.
    unsafe { OSSL_STACK_OF_X509_free(c.newChain.cast()) };
    c.newChain = ptr::null_mut();
    if certs.is_null() {
        return 1;
    }
    // SAFETY: the caller's list.
    c.newChain = unsafe { X509_chain_up_ref(certs) }.cast();
    c_int::from(!c.newChain.is_null())
}

/// `ossl_cmp_ctx_set1_extraCertsIn`: replaces the context's `extraCertsIn` with a copy of `certs` sharing the certificates (none for
/// NULL): 1, or 0.
///
/// # Safety
/// `ctx` is NULL or a live context; `certs` NULL or a live list.
pub(crate) unsafe fn ctx_set1_extraCertsIn(
    ctx: *mut OSSL_CMP_CTX,
    certs: *mut stack_st_X509,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        null_argument("ossl_cmp_ctx_set1_extraCertsIn");
        return 0;
    };
    // SAFETY: the context's own list, or NULL.
    unsafe { OSSL_STACK_OF_X509_free(c.extraCertsIn.cast()) };
    c.extraCertsIn = ptr::null_mut();
    if certs.is_null() {
        return 1;
    }
    // SAFETY: the caller's list.
    c.extraCertsIn = unsafe { X509_chain_up_ref(certs) }.cast();
    c_int::from(!c.extraCertsIn.is_null())
}

ffi_export! {
    /// Replaces the context's `extraCertsOut` with a copy of `extraCertsOut` sharing the certificates (none for
    /// NULL): 1, or 0. Raises `CMP_R_NULL_ARGUMENT` for a NULL context.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `extraCertsOut` NULL or a live list.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set1_extraCertsOut(ctx: *mut OSSL_CMP_CTX, extraCertsOut: *mut stack_st_X509) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set1_extraCertsOut");
            return 0;
        };
        // SAFETY: the context's own list, or NULL.
        unsafe { OSSL_STACK_OF_X509_free(c.extraCertsOut.cast()) };
        c.extraCertsOut = ptr::null_mut();
        if extraCertsOut.is_null() {
            return 1;
        }
        // SAFETY: the caller's list.
        c.extraCertsOut = unsafe { X509_chain_up_ref(extraCertsOut) }.cast();
        c_int::from(!c.extraCertsOut.is_null())
    }
}

/// `ossl_cmp_ctx_set1_caPubs`: replaces the context's `caPubs` with a copy of `certs` sharing the certificates (none for
/// NULL): 1, or 0.
///
/// # Safety
/// `ctx` is NULL or a live context; `certs` NULL or a live list.
pub(crate) unsafe fn ctx_set1_caPubs(ctx: *mut OSSL_CMP_CTX, certs: *mut stack_st_X509) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        null_argument("ossl_cmp_ctx_set1_caPubs");
        return 0;
    };
    // SAFETY: the context's own list, or NULL.
    unsafe { OSSL_STACK_OF_X509_free(c.caPubs.cast()) };
    c.caPubs = ptr::null_mut();
    if certs.is_null() {
        return 1;
    }
    // SAFETY: the caller's list.
    c.caPubs = unsafe { X509_chain_up_ref(certs) }.cast();
    c_int::from(!c.caPubs.is_null())
}

ffi_export! {
    /// A copy of the chain of the newly enrolled certificate, sharing the certificates, or NULL. Raises
    /// `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_get1_newChain(ctx: *const OSSL_CMP_CTX) -> *mut stack_st_X509
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_get1_newChain");
            return ptr::null_mut();
        };
        // SAFETY: the context's own list, or NULL.
        unsafe { X509_chain_up_ref(c.newChain.cast()) }
    }
}

ffi_export! {
    /// A copy of the extraCerts of the last response, sharing the certificates, or NULL. Raises
    /// `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_get1_extraCertsIn(ctx: *const OSSL_CMP_CTX) -> *mut stack_st_X509
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_get1_extraCertsIn");
            return ptr::null_mut();
        };
        // SAFETY: the context's own list, or NULL.
        unsafe { X509_chain_up_ref(c.extraCertsIn.cast()) }
    }
}

ffi_export! {
    /// A copy of the caPubs of the last response, sharing the certificates, or NULL. Raises
    /// `CMP_R_NULL_ARGUMENT` for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_get1_caPubs(ctx: *const OSSL_CMP_CTX) -> *mut stack_st_X509
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_get1_caPubs");
            return ptr::null_mut();
        };
        // SAFETY: the context's own list, or NULL.
        unsafe { X509_chain_up_ref(c.caPubs.cast()) }
    }
}

ffi_export! {
    /// Sets the transactionID to a copy of `id` (none for NULL): 1, or 0. Raises
    /// `CMP_R_NULL_ARGUMENT` for a NULL context.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `id` NULL or a live string.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set1_transactionID(ctx: *mut OSSL_CMP_CTX, id: *const ASN1_OCTET_STRING) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set1_transactionID");
            return 0;
        };
        // SAFETY: the context's field; the caller's value.
        unsafe { asn1_octet_string_set1(&raw mut c.transactionID, id) }
    }
}

/// `ossl_cmp_ctx_set1_recipNonce`: sets the recipNonce of the next message to a copy of `nonce` (none for NULL): 1, or 0.
///
/// # Safety
/// `ctx` is NULL or a live context; `nonce` NULL or a live string.
pub(crate) unsafe fn ctx_set1_recipNonce(
    ctx: *mut OSSL_CMP_CTX,
    nonce: *const ASN1_OCTET_STRING,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        null_argument("ossl_cmp_ctx_set1_recipNonce");
        return 0;
    };
    // SAFETY: the context's field; the caller's value.
    unsafe { asn1_octet_string_set1(&raw mut c.recipNonce, nonce) }
}

ffi_export! {
    /// Sets the last senderNonce sent to a copy of `nonce` (none for NULL): 1, or 0. Raises
    /// `CMP_R_NULL_ARGUMENT` for a NULL context.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `nonce` NULL or a live string.
    pub unsafe extern "C" fn OSSL_CMP_CTX_set1_senderNonce(ctx: *mut OSSL_CMP_CTX, nonce: *const ASN1_OCTET_STRING) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            null_argument("OSSL_CMP_CTX_set1_senderNonce");
            return 0;
        };
        // SAFETY: the context's field; the caller's value.
        unsafe { asn1_octet_string_set1(&raw mut c.senderNonce, nonce) }
    }
}

/// `ossl_cmp_ctx_set1_first_senderNonce`: sets the first request's senderNonce, for checking delayed delivery to a copy of `nonce` (none for NULL): 1, or 0.
///
/// # Safety
/// `ctx` is NULL or a live context; `nonce` NULL or a live string.
pub(crate) unsafe fn ctx_set1_first_senderNonce(
    ctx: *mut OSSL_CMP_CTX,
    nonce: *const ASN1_OCTET_STRING,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        null_argument("ossl_cmp_ctx_set1_first_senderNonce");
        return 0;
    };
    // SAFETY: the context's field; the caller's value.
    unsafe { asn1_octet_string_set1(&raw mut c.first_senderNonce, nonce) }
}
