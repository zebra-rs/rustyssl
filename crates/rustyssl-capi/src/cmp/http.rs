//! CMP over HTTP (`cmp_http.c`): a request message posted to the context's server as
//! `application/pkixcmp`, its response decoded.

use core::ffi::{CStr, c_int, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    BIO, CMP_R_NULL_ARGUMENT, ERR_LIB_CMP, OSSL_CMP_CTX, OSSL_CMP_LOG_DEBUG, OSSL_CMP_MSG,
    OSSL_HTTP_DEFAULT_MAX_RESP_LEN, stack_st_CONF_VALUE,
};

use super::asn::{
    Msg, OSSL_CMP_MSG_it, PKIBODY_CR, PKIBODY_IR, PKIBODY_KUR, PKIBODY_P10CR, PKIBODY_POLLREQ,
};
use super::client::text_of;
use super::ctx::{Ctx, print_log};
use crate::asn1::tpl::io::{ASN1_item_d2i_bio, ASN1_item_i2d_mem_bio};
use crate::bio::BIO_free;
use crate::err;
use crate::ffi::ffi_export;
use crate::http_client::OSSL_HTTP_transfer;
use crate::stack::OPENSSL_sk_pop_free;
use crate::x509v3::{X509V3_add_value, X509V3_conf_free};

/// The content type of CMP messages over HTTP, both ways.
const CONTENT_TYPE_PKIX: &CStr = c"application/pkixcmp";

/// Whether to ask for a persistent connection: only if more round trips may follow (polling
/// included), and only on a connection of our own (`bios` NULL).
fn keep_alive(keep_alive: c_int, body_type: c_int, bios: *mut *mut BIO) -> c_int {
    if keep_alive != 0
        && bios.is_null()
        && body_type != PKIBODY_IR
        && body_type != PKIBODY_CR
        && body_type != PKIBODY_P10CR
        && body_type != PKIBODY_KUR
        && body_type != PKIBODY_POLLREQ
    {
        return 0;
    }
    keep_alive
}

/// `X509V3_conf_free` as a stack's free function.
unsafe extern "C" fn conf_free(p: *mut c_void) {
    // SAFETY: a value of the header list.
    unsafe { X509V3_conf_free(p.cast()) };
}

ffi_export! {
    /// Sends the request to the context's server (or over the BIO pair in the transfer
    /// callback's argument) and returns the decoded response, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `req` NULL or a live message. A non-NULL transfer
    /// callback argument points to two BIOs (`bio`, `rbio`).
    pub unsafe extern "C" fn OSSL_CMP_MSG_http_perform(ctx: *mut OSSL_CMP_CTX, req: *const OSSL_CMP_MSG) -> *mut OSSL_CMP_MSG
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        const F: &str = "OSSL_CMP_MSG_http_perform";
        if ctx.is_null() || req.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, F);
            return ptr::null_mut();
        }
        let c: *mut Ctx = ctx.cast();
        let mut headers: *mut stack_st_CONF_VALUE = ptr::null_mut();
        // SAFETY: static strings; the list's room.
        if unsafe { X509V3_add_value(c"Pragma".as_ptr(), c"no-cache".as_ptr(), &raw mut headers) } == 0 {
            return ptr::null_mut();
        }
        let mut res: *mut OSSL_CMP_MSG = ptr::null_mut();
        // SAFETY: no preconditions.
        let it = unsafe { OSSL_CMP_MSG_it() };
        // SAFETY: the item; the caller's message.
        let req_mem = unsafe { ASN1_item_i2d_mem_bio(it, req.cast()) };
        if !req_mem.is_null() {
            // SAFETY: the caller's context.
            let bios: *mut *mut BIO = unsafe { (*c).transfer_cb_arg }.cast();
            // SAFETY: as above.
            let server_port = unsafe { (*c).serverPort };
            let port = if server_port != 0 {
                CString::new(server_port.to_string()).unwrap_or_default()
            } else {
                CString::default()
            };
            // SAFETY: as above.
            let tls_flag = unsafe { (*c).tls_used };
            // SAFETY: as above.
            let http_cb_arg = unsafe { (*c).http_cb_arg };
            // Backward compatibility: a negative flag means TLS if there's an HTTP callback
            // argument.
            let tls_used = if tls_flag >= 0 { tls_flag != 0 } else { !http_cb_arg.is_null() };
            // SAFETY: as above.
            let server = unsafe { (*c).server };
            // SAFETY: as above.
            if unsafe { (*c).http_ctx }.is_null() {
                // SAFETY: as above.
                let path_ptr = unsafe { (*c).serverPath };
                let path = if path_ptr.is_null() {
                    String::new()
                } else {
                    // SAFETY: the context's path, NUL-terminated.
                    unsafe { text_of(path_ptr) }
                };
                let path = path.strip_prefix('/').unwrap_or(&path).to_owned();
                // SAFETY: the context's server name, NULL or NUL-terminated.
                let server_name = unsafe { text_of(server) };
                let port_text = port.to_string_lossy();
                let msg = if bios.is_null() {
                    format!("connecting to CMP server via http{}://{}:{}/{}", if tls_used { "s" } else { "" }, server_name, port_text, path)
                } else {
                    format!("using existing connection with CMP server {server_name}:{port_text} and HTTP path /{path}")
                };
                // SAFETY: the caller's context.
                unsafe { print_log(OSSL_CMP_LOG_DEBUG, ctx, c"OSSL_CMP_MSG_http_perform", &msg) };
            }
            let (bio, rbio) = if bios.is_null() {
                (ptr::null_mut(), ptr::null_mut())
            } else {
                // SAFETY: the first of the caller's two BIOs.
                let b = unsafe { *bios };
                // SAFETY: the second slot of the caller's pair.
                let rb_slot = unsafe { bios.add(1) };
                // SAFETY: as above.
                let rb = unsafe { *rb_slot };
                (b, rb)
            };
            // SAFETY: the request's body.
            let body = unsafe { (*req.cast::<Msg>()).body };
            // SAFETY: as above.
            let body_type = unsafe { (*body).type_ };
            // SAFETY: as above.
            let ka = keep_alive(unsafe { (*c).keep_alive }, body_type, bios);
            // SAFETY: as above.
            let proxy = unsafe { (*c).proxy };
            // SAFETY: as above.
            let no_proxy = unsafe { (*c).no_proxy };
            // SAFETY: as above.
            let path = unsafe { (*c).serverPath };
            // SAFETY: as above.
            let http_cb = unsafe { (*c).http_cb };
            // SAFETY: as above.
            let msg_timeout = unsafe { (*c).msg_timeout };
            let max = usize::try_from(OSSL_HTTP_DEFAULT_MAX_RESP_LEN).unwrap_or(0);
            // SAFETY: as above.
            let http_ctx = unsafe { &raw mut (*c).http_ctx };
            // SAFETY: the context's connection slot and settings, NUL-terminated strings or
            // NULL; the request's BIO; static content types. No lock is held while the HTTP
            // callback runs.
            let rsp = unsafe { OSSL_HTTP_transfer(http_ctx, server, port.as_ptr(), path, c_int::from(tls_used), proxy, no_proxy, bio, rbio, http_cb, http_cb_arg, 0, headers, CONTENT_TYPE_PKIX.as_ptr(), req_mem, CONTENT_TYPE_PKIX.as_ptr(), 1, max, msg_timeout, ka) };
            // SAFETY: the request's BIO, made here.
            unsafe { BIO_free(req_mem) };
            // SAFETY: the item; the response's BIO, or NULL.
            res = unsafe { ASN1_item_d2i_bio(it, rsp, ptr::null_mut()) }.cast();
            // SAFETY: as above.
            unsafe { BIO_free(rsp) };
            // SAFETY: the caller's context.
            if unsafe { (*c).http_ctx }.is_null() {
                // SAFETY: as above.
                unsafe { print_log(OSSL_CMP_LOG_DEBUG, ctx, c"OSSL_CMP_MSG_http_perform", "disconnected from CMP server") };
            }
            // On success the connection stays open if kept alive; the application closes it
            // with OSSL_CMP_CTX_free() or OSSL_CMP_CTX_reinit(). A caller's BIOs aren't freed.
            if !res.is_null() {
                // SAFETY: as above.
                unsafe { print_log(OSSL_CMP_LOG_DEBUG, ctx, c"OSSL_CMP_MSG_http_perform", "finished reading response from CMP server") };
            }
        }
        // SAFETY: the header list made here.
        unsafe { OPENSSL_sk_pop_free(headers.cast(), Some(conf_free)) };
        res
    }
}
