//! Certificate Transparency on a connection (`ssl_lib.c`'s CT part): the validation callback
//! (`SSL_enable_ct`'s permissive and strict ones, or the application's), the context's log
//! store, the SCTs the server sent (the extension's, the stapled OCSP response's, and the
//! leaf certificate's), and `ssl_validate_ct`, which answers the core's
//! [`Request::CtValidate`](rustyssl_tls::conn::Request::CtValidate).

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    CT_POLICY_EVAL_CTX, CTLOG_STORE, ERR_LIB_SSL, ERR_R_CT_LIB, NID_ct_cert_scts,
    NID_ct_precert_scts, OCSP_RESPONSE, SCT, SCT_SOURCE_OCSP_STAPLED_RESPONSE,
    SCT_SOURCE_TLS_EXTENSION, SCT_SOURCE_X509V3_EXTENSION, SCT_VALIDATION_STATUS_VALID, SSL,
    SSL_AD_HANDSHAKE_FAILURE, SSL_CT_VALIDATION_PERMISSIVE, SSL_CT_VALIDATION_STRICT, SSL_CTX,
    SSL_R_CALLBACK_FAILED, SSL_R_INVALID_CT_VALIDATION_TYPE, SSL_R_NO_VALID_SCTS,
    SSL_R_SCT_VERIFICATION_FAILED, TLSEXT_STATUSTYPE_ocsp, X509, X509_V_OK, sct_source_t,
    ssl_ct_validation_cb, stack_st_SCT,
};
use rustyssl_tls::conn::Answer;

use super::conn::{Ssl, ctx_of, ssl};
use super::ctx::{self as ctxs, Ctx};
use crate::ct::{
    CT_POLICY_EVAL_CTX_free, CT_POLICY_EVAL_CTX_new_ex, CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE,
    CT_POLICY_EVAL_CTX_set_time, CT_POLICY_EVAL_CTX_set1_cert, CT_POLICY_EVAL_CTX_set1_issuer,
    CTLOG_STORE_free, CTLOG_STORE_load_default_file, CTLOG_STORE_load_file, CTLOG_STORE_new_ex,
    SCT_LIST_free, SCT_LIST_validate, SCT_free, SCT_get_validation_status, SCT_set_source,
    o2i_SCT_LIST,
};
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::ocsp::asn::{OCSP_BASICRESP_free, OCSP_RESPONSE_free, d2i_OCSP_RESPONSE};
use crate::ocsp::cl::{OCSP_resp_count, OCSP_resp_get0, OCSP_response_get1_basic};
use crate::ocsp::ext::OCSP_SINGLERESP_get1_ext_d2i;
use crate::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop, OPENSSL_sk_push, OPENSSL_sk_value,
};
use crate::x509::purpose::X509_get_ext_d2i;

/// A context's CT settings.
#[derive(Debug)]
pub(crate) struct CtxCt {
    pub(crate) callback: ssl_ct_validation_cb,
    pub(crate) arg: *mut c_void,
    /// The log store (owned, or NULL after `SSL_CTX_set0_ctlog_store(ctx, NULL)`); `None`
    /// until first needed.
    store: Option<*mut CTLOG_STORE>,
}

impl Default for CtxCt {
    fn default() -> Self {
        Self {
            callback: None,
            arg: ptr::null_mut(),
            store: None,
        }
    }
}

impl Drop for CtxCt {
    fn drop(&mut self) {
        if let Some(store) = self.store {
            // SAFETY: our own store, or NULL.
            unsafe { CTLOG_STORE_free(store) };
        }
    }
}

/// A connection's CT state.
#[derive(Debug)]
pub(crate) struct ConnCt {
    pub(crate) callback: ssl_ct_validation_cb,
    pub(crate) arg: *mut c_void,
    /// The SCTs received (owned), once collected (`scts`, `scts_parsed`).
    scts: *mut stack_st_SCT,
    parsed: bool,
}

impl ConnCt {
    pub(crate) fn new(callback: ssl_ct_validation_cb, arg: *mut c_void) -> Self {
        Self {
            callback,
            arg,
            scts: ptr::null_mut(),
            parsed: false,
        }
    }
}

impl Drop for ConnCt {
    fn drop(&mut self) {
        // SAFETY: our own list, or NULL.
        unsafe { SCT_LIST_free(self.scts) };
    }
}

/// The context's log store, made on first use (OpenSSL makes it with the context).
fn store(c: &Ctx) -> *mut CTLOG_STORE {
    let mut st = c.state();
    if let Some(store) = st.ct.store {
        return store;
    }
    // SAFETY: the context's library context and property query.
    let store = unsafe { CTLOG_STORE_new_ex(c.libctx, c.propq_ptr()) };
    st.ct.store = Some(store);
    store
}

ffi_callback! {
    /// `ct_permissive`: accepts any SCTs.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ct_permissive(_ctx: *const CT_POLICY_EVAL_CTX, _scts: *const stack_st_SCT, _arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        1
    }
}

ffi_callback! {
    /// `ct_strict`: at least one valid SCT.
    ///
    /// # Safety
    /// `scts` is NULL or a live list.
    pub(crate) unsafe extern "C" fn ct_strict(_ctx: *const CT_POLICY_EVAL_CTX, scts: *const stack_st_SCT, _arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let n = unsafe { OPENSSL_sk_num(scts.cast()) };
        for i in 0..n.max(0) {
            // SAFETY: an index of the list.
            let sct = unsafe { OPENSSL_sk_value(scts.cast(), i) };
            // SAFETY: an SCT of the list.
            if unsafe { SCT_get_validation_status(sct.cast()) } == SCT_VALIDATION_STATUS_VALID {
                return 1;
            }
        }
        err::raise(ERR_LIB_SSL, SSL_R_NO_VALID_SCTS, "ct_strict");
        0
    }
}

/// The callback `SSL_enable_ct`'s mode selects, or `None` for an unknown mode.
fn mode_callback(mode: c_int) -> Option<ssl_ct_validation_cb> {
    let mode = u32::try_from(mode).ok()?;
    if mode == SSL_CT_VALIDATION_PERMISSIVE {
        Some(Some(ct_permissive))
    } else if mode == SSL_CT_VALIDATION_STRICT {
        Some(Some(ct_strict))
    } else {
        None
    }
}

ffi_export! {
    /// Sets the context's CT validation callback (NULL: no CT): 1.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_ct_validation_callback(ctx: *mut SSL_CTX, callback: ssl_ct_validation_cb, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctxs::ctx(ctx) }) else { return 0 };
        let mut st = c.state();
        // The application's own SCT extension and CT validation don't mix.
        if callback.is_some() && super::custom::has_client_sct(&st.cert.custext) {
            drop(st);
            err::raise(ERR_LIB_SSL, rustyssl_abi::SSL_R_CUSTOM_EXT_HANDLER_ALREADY_INSTALLED, "SSL_CTX_set_ct_validation_callback");
            return 0;
        }
        st.ct.callback = callback;
        st.ct.arg = arg;
        1
    }
}

ffi_export! {
    /// Sets the connection's CT validation callback; one also asks for OCSP stapling: 1.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_ct_validation_callback(s: *mut SSL, callback: ssl_ct_validation_cb, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let mut st = x.state();
        // SAFETY: the connection holds a reference to its context.
        let sct = unsafe { ctx_of(&st) }.is_some_and(|c| super::custom::has_client_sct(&c.state().cert.custext));
        if callback.is_some() && sct {
            drop(st);
            err::raise(ERR_LIB_SSL, rustyssl_abi::SSL_R_CUSTOM_EXT_HANDLER_ALREADY_INSTALLED, "SSL_set_ct_validation_callback");
            return 0;
        }
        if callback.is_some() {
            st.status_type = TLSEXT_STATUSTYPE_ocsp;
        }
        st.ct.callback = callback;
        st.ct.arg = arg;
        1
    }
}

ffi_export! {
    /// Enables CT on the context, permissive or strict: 1, or 0 for another mode.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_enable_ct(ctx: *mut SSL_CTX, validation_mode: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let Some(cb) = mode_callback(validation_mode) else {
            err::raise(ERR_LIB_SSL, SSL_R_INVALID_CT_VALIDATION_TYPE, "SSL_CTX_enable_ct");
            return 0;
        };
        // SAFETY: the caller's guarantee.
        unsafe { rustyssl_private_SSL_CTX_set_ct_validation_callback(ctx, cb, ptr::null_mut()) }
    }
}

ffi_export! {
    /// Enables CT on the connection, permissive or strict: 1, or 0 for another mode.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_enable_ct(s: *mut SSL, validation_mode: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let Some(cb) = mode_callback(validation_mode) else {
            err::raise(ERR_LIB_SSL, SSL_R_INVALID_CT_VALIDATION_TYPE, "SSL_enable_ct");
            return 0;
        };
        // SAFETY: the caller's guarantee.
        unsafe { rustyssl_private_SSL_set_ct_validation_callback(s, cb, ptr::null_mut()) }
    }
}

ffi_export! {
    /// Whether the context has a CT validation callback.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_ct_is_enabled(ctx: *const SSL_CTX) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctxs::ctx(ctx) }) else { return 0 };
        c_int::from(c.state().ct.callback.is_some())
    }
}

ffi_export! {
    /// Whether the connection has a CT validation callback.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_ct_is_enabled(s: *const SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        c_int::from(x.state().ct.callback.is_some())
    }
}

ffi_export! {
    /// Loads the default CT log list into the context's store: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_default_ctlog_list_file(ctx: *mut SSL_CTX) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctxs::ctx(ctx) }) else { return 0 };
        let store = store(c);
        // SAFETY: the context's store (NULL is refused there).
        unsafe { CTLOG_STORE_load_default_file(store) }
    }
}

ffi_export! {
    /// Loads the CT log list `path` into the context's store: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live context; `path` a string.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_ctlog_list_file(ctx: *mut SSL_CTX, path: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctxs::ctx(ctx) }) else { return 0 };
        let store = store(c);
        // SAFETY: the context's store; the caller's path.
        unsafe { CTLOG_STORE_load_file(store, path) }
    }
}

ffi_export! {
    /// Replaces the context's log store with `logs`, which it takes.
    ///
    /// # Safety
    /// `ctx` is a live context; `logs` NULL or a store the caller gives up.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set0_ctlog_store(ctx: *mut SSL_CTX, logs: *mut CTLOG_STORE)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctxs::ctx(ctx) }) else { return };
        let old = c.state().ct.store.replace(logs);
        if let Some(old) = old {
            // SAFETY: the store the context owned, or NULL; no lock is held.
            unsafe { CTLOG_STORE_free(old) };
        }
    }
}

ffi_export! {
    /// The context's log store.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_get0_ctlog_store(ctx: *const SSL_CTX) -> *const CTLOG_STORE
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctxs::ctx(ctx) }) else { return ptr::null() };
        store(c)
    }
}

/// `ct_move_scts`: moves `src`'s SCTs onto `dst` (made if NULL) with `origin`: how many, or
/// -1. `src` is left empty but not freed.
///
/// # Safety
/// `dst` holds NULL or a live list; `src` is NULL or a live list.
unsafe fn move_scts(
    dst: &mut *mut stack_st_SCT,
    src: *mut stack_st_SCT,
    origin: sct_source_t,
) -> c_int {
    if dst.is_null() {
        // SAFETY: no preconditions.
        *dst = unsafe { OPENSSL_sk_new_null() }.cast();
        if dst.is_null() {
            err::raise(ERR_LIB_SSL, rustyssl_abi::ERR_R_CRYPTO_LIB, "ct_move_scts");
            return -1;
        }
    }
    let mut moved: c_int = 0;
    loop {
        // SAFETY: the caller's list (popping NULL gives NULL).
        let sct: *mut SCT = unsafe { OPENSSL_sk_pop(src.cast()) }.cast();
        if sct.is_null() {
            return moved;
        }
        // SAFETY: an SCT the list owned, now ours.
        if unsafe { SCT_set_source(sct, origin) } != 1
            // SAFETY: our list; it takes the SCT.
            || unsafe { OPENSSL_sk_push(dst.cast(), sct.cast()) } == 0
        {
            // SAFETY: the SCT nothing owns now.
            unsafe { SCT_free(sct) };
            return -1;
        }
        moved = moved.saturating_add(1);
    }
}

/// The SCTs of the stapled OCSP response's single responses.
///
/// # Safety
/// `dst` holds NULL or a live list.
unsafe fn ocsp_scts(dst: &mut *mut stack_st_SCT, resp: &[u8]) -> c_int {
    let Ok(len) = c_long::try_from(resp.len()) else {
        return 0;
    };
    let mut p: *const c_uchar = resp.as_ptr();
    // SAFETY: our octets.
    let rsp: *mut OCSP_RESPONSE = unsafe { d2i_OCSP_RESPONSE(ptr::null_mut(), &raw mut p, len) };
    if rsp.is_null() {
        return 0;
    }
    // SAFETY: the response just decoded.
    let br = unsafe { OCSP_response_get1_basic(rsp) };
    let mut extracted = 0;
    if !br.is_null() {
        // SAFETY: the basic response.
        let n = unsafe { OCSP_resp_count(br) };
        for i in 0..n.max(0) {
            // SAFETY: an index of the response.
            let single = unsafe { OCSP_resp_get0(br, i) };
            if single.is_null() {
                continue;
            }
            // SAFETY: a single response of it.
            let scts: *mut stack_st_SCT = unsafe {
                OCSP_SINGLERESP_get1_ext_d2i(
                    single,
                    NID_ct_cert_scts,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            }
            .cast();
            // SAFETY: as above; the list just decoded.
            extracted = unsafe { move_scts(dst, scts, SCT_SOURCE_OCSP_STAPLED_RESPONSE) };
            // SAFETY: the decoded list, ours.
            unsafe { SCT_LIST_free(scts) };
            if extracted < 0 {
                break;
            }
        }
    }
    // SAFETY: ours, or NULL.
    unsafe { OCSP_BASICRESP_free(br) };
    // SAFETY: ours.
    unsafe { OCSP_RESPONSE_free(rsp) };
    extracted
}

/// The peer's leaf certificate, as received (`s->session->peer`), or NULL.
fn peer_leaf(st: &super::conn::SslState) -> *mut X509 {
    // SAFETY: the connection's own chain, or NULL.
    unsafe { OPENSSL_sk_value(st.drv.peer.chain.cast(), 0) }.cast()
}

/// `SSL_get0_peer_scts`'s collection: the SCTs of the extension, the OCSP response, and the
/// leaf, once. NULL on failure.
fn peer_scts(x: &Ssl) -> *mut stack_st_SCT {
    let mut st = x.state();
    if st.ct.parsed {
        return st.ct.scts;
    }
    let (ext, ocsp) = st.drv.tls.as_ref().map_or((None, None), |c| {
        let n = c.negotiated();
        (n.scts.clone(), n.ocsp_response.clone())
    });
    let leaf = peer_leaf(&st);
    let mut list = core::mem::replace(&mut st.ct.scts, ptr::null_mut());
    drop(st);
    let mut ok = true;
    if let Some(ext) = ext {
        let len = ext.len();
        let mut p: *const c_uchar = ext.as_ptr();
        // SAFETY: our octets.
        let scts = unsafe { o2i_SCT_LIST(ptr::null_mut(), &raw mut p, len) };
        // SAFETY: the list just decoded, or NULL.
        ok &= unsafe { move_scts(&mut list, scts, SCT_SOURCE_TLS_EXTENSION) } >= 0;
        // SAFETY: as above.
        unsafe { SCT_LIST_free(scts) };
    }
    if ok && let Some(resp) = ocsp.filter(|r| !r.is_empty()) {
        // SAFETY: our list.
        ok &= unsafe { ocsp_scts(&mut list, &resp) } >= 0;
    }
    if ok && !leaf.is_null() {
        // SAFETY: the connection's live leaf certificate.
        let scts: *mut stack_st_SCT = unsafe {
            X509_get_ext_d2i(leaf, NID_ct_precert_scts, ptr::null_mut(), ptr::null_mut())
        }
        .cast();
        // SAFETY: the list just decoded, or NULL.
        ok &= unsafe { move_scts(&mut list, scts, SCT_SOURCE_X509V3_EXTENSION) } >= 0;
        // SAFETY: as above.
        unsafe { SCT_LIST_free(scts) };
    }
    let mut st = x.state();
    st.ct.scts = list;
    if !ok {
        return ptr::null_mut();
    }
    st.ct.parsed = true;
    list
}

ffi_export! {
    /// The SCTs the server sent (in its extension, its stapled OCSP response, and its
    /// certificate), or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get0_peer_scts(s: *mut SSL) -> *const stack_st_SCT
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return ptr::null() };
        peer_scts(x)
    }
}

/// `ssl_validate_ct`: the core's [`rustyssl_tls::conn::Request::CtValidate`] answered.
///
/// # Safety
/// `s` is the live connection behind `x`; no lock is held.
pub(crate) unsafe fn validate(_s: *mut SSL, x: &Ssl) -> Answer {
    let fail = |reason| Answer::Fail {
        alert: u8::try_from(SSL_AD_HANDSHAKE_FAILURE).ok(),
        reason,
    };
    let (cb, arg, leaf, verified, ok, time, c) = {
        let st = x.state();
        let time = st
            .drv
            .tls
            .as_ref()
            .map_or(0, |c| c.negotiated().session.time);
        (
            st.ct.callback,
            st.ct.arg,
            peer_leaf(&st),
            st.drv.peer.verified,
            st.verify_result == c_long::from(X509_V_OK),
            time,
            // SAFETY: the connection's own context.
            unsafe { ctx_of(&st) },
        )
    };
    // SAFETY: the connection's verified chain, or NULL.
    let depth = unsafe { OPENSSL_sk_num(verified.cast()) };
    let (Some(cb), Some(c)) = (cb, c) else {
        return Answer::Continue;
    };
    if leaf.is_null() || !ok || depth <= 1 {
        return Answer::Continue;
    }
    // SAFETY: the context's library context and property query.
    let ctx = unsafe { CT_POLICY_EVAL_CTX_new_ex(c.libctx, c.propq_ptr()) };
    if ctx.is_null() {
        return Answer::Fail {
            alert: u8::try_from(rustyssl_abi::SSL_AD_INTERNAL_ERROR).ok(),
            reason: ERR_R_CT_LIB,
        };
    }
    // SAFETY: the verified chain's second certificate.
    let issuer: *mut X509 = unsafe { OPENSSL_sk_value(verified.cast(), 1) }.cast();
    // SAFETY: the new context and the connection's certificate.
    unsafe { CT_POLICY_EVAL_CTX_set1_cert(ctx, leaf) };
    // SAFETY: as above.
    unsafe { CT_POLICY_EVAL_CTX_set1_issuer(ctx, issuer) };
    let store = store(c);
    // SAFETY: the new context and the connection's context's store.
    unsafe { CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE(ctx, store) };
    let ms = u64::try_from(time).unwrap_or(0).saturating_mul(1000);
    // SAFETY: the new context.
    unsafe { CT_POLICY_EVAL_CTX_set_time(ctx, ms) };
    let scts = peer_scts(x);
    // SAFETY: the connection's list (or NULL) and the new context.
    let answer = if unsafe { SCT_LIST_validate(scts, ctx) } < 0 {
        fail(SSL_R_SCT_VERIFICATION_FAILED)
    } else {
        // SAFETY: the application's callback, with no lock held.
        let r = unsafe { cb(ctx, scts, arg) };
        if r > 0 {
            Answer::Continue
        } else {
            fail(SSL_R_CALLBACK_FAILED)
        }
    };
    // SAFETY: ours.
    unsafe { CT_POLICY_EVAL_CTX_free(ctx) };
    answer
}
