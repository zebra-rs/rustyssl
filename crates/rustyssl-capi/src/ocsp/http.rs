//! Sending a request over HTTP (`ocsp_http.c`): a POST of the request's DER that expects an
//! ASN.1 response.

use core::ffi::{c_char, c_int};
use core::ptr;

use rustyssl_abi::{BIO, ERR_LIB_OCSP, OCSP_REQUEST, OCSP_RESPONSE, OSSL_HTTP_REQ_CTX};

use super::asn::{OCSP_REQUEST_it, OCSP_RESPONSE_it};
use crate::asn1::tpl::io::ASN1_item_d2i_bio;
use crate::ffi::ffi_export;
use crate::http_client::{
    OSSL_HTTP_REQ_CTX_exchange, OSSL_HTTP_REQ_CTX_free, OSSL_HTTP_REQ_CTX_new,
    OSSL_HTTP_REQ_CTX_set_expected, OSSL_HTTP_REQ_CTX_set_request_line, OSSL_HTTP_REQ_CTX_set1_req,
};

ffi_export! {
    /// A context to POST the request (when given, else set later) to `path` over `io`, with
    /// lines of up to `buf_size` octets, expecting ASN.1: the context, or NULL.
    ///
    /// # Safety
    /// `io` is a live BIO that outlives the context; `path` NULL or a C string; `req` NULL or a
    /// live request.
    pub unsafe extern "C" fn OCSP_sendreq_new(io: *mut BIO, path: *const c_char, req: *const OCSP_REQUEST, buf_size: c_int) -> *mut OSSL_HTTP_REQ_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's BIO, both ways.
        let rctx = unsafe { OSSL_HTTP_REQ_CTX_new(io, io, buf_size) };
        if rctx.is_null() {
            return rctx;
        }
        // SAFETY: no preconditions.
        let it = unsafe { OCSP_REQUEST_it() };
        // SAFETY: the context made here; the caller's path.
        let ok = unsafe { OSSL_HTTP_REQ_CTX_set_request_line(rctx, 1, ptr::null(), ptr::null(), path) } != 0
            // SAFETY: as above.
            && unsafe { OSSL_HTTP_REQ_CTX_set_expected(rctx, ptr::null(), 1, 0, 0) } != 0
            && (req.is_null()
                // SAFETY: as above; the request's item and the caller's request.
                || unsafe { OSSL_HTTP_REQ_CTX_set1_req(rctx, c"application/ocsp-request".as_ptr(), it, req.cast()) } != 0);
        if !ok {
            // SAFETY: made here.
            unsafe { OSSL_HTTP_REQ_CTX_free(rctx) };
            return ptr::null_mut();
        }
        rctx
    }
}

ffi_export! {
    /// POSTs the request to `path` over `b` and reads the response: it, or NULL.
    ///
    /// # Safety
    /// `b` is a live BIO; `path` NULL or a C string; `req` NULL or a live request.
    pub unsafe extern "C" fn OCSP_sendreq_bio(b: *mut BIO, path: *const c_char, req: *mut OCSP_REQUEST) -> *mut OCSP_RESPONSE
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's arguments.
        let ctx = unsafe { OCSP_sendreq_new(b, path, req, 0) };
        if ctx.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the context made here.
        let mem = unsafe { OSSL_HTTP_REQ_CTX_exchange(ctx) };
        // SAFETY: no preconditions.
        let it = unsafe { OCSP_RESPONSE_it() };
        // SAFETY: the response's item; its BIO, or NULL.
        let resp = unsafe { ASN1_item_d2i_bio(it, mem, ptr::null_mut()) };
        // SAFETY: as above.
        unsafe { OSSL_HTTP_REQ_CTX_free(ctx) };
        resp.cast()
    }
}
