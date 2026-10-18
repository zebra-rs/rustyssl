//! Fuzzes the HTTP client's response parser on untrusted input: the input read as the answer
//! to a GET (text or ASN.1, with or without an expected content type, keep-alive asked for or
//! required, small and default line buffers and header limits), and to `OCSP_sendreq_bio`.
//! Nothing may crash or read out of bounds (ASan).

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIO, BIO_METHOD, OSSL_HTTP_REQ_CTX};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn OSSL_HTTP_REQ_CTX_new(wbio: *mut BIO, rbio: *mut BIO, buf_size: c_int) -> *mut OSSL_HTTP_REQ_CTX;
    fn OSSL_HTTP_REQ_CTX_free(rctx: *mut OSSL_HTTP_REQ_CTX);
    fn OSSL_HTTP_REQ_CTX_set_request_line(rctx: *mut OSSL_HTTP_REQ_CTX, post: c_int, server: *const c_char, port: *const c_char, path: *const c_char) -> c_int;
    fn OSSL_HTTP_REQ_CTX_set_expected(rctx: *mut OSSL_HTTP_REQ_CTX, ct: *const c_char, asn1: c_int, timeout: c_int, keep_alive: c_int) -> c_int;
    fn OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines(rctx: *mut OSSL_HTTP_REQ_CTX, count: usize);
    fn OSSL_HTTP_REQ_CTX_exchange(rctx: *mut OSSL_HTTP_REQ_CTX) -> *mut BIO;
    fn OSSL_HTTP_REQ_CTX_get_resp_len(rctx: *const OSSL_HTTP_REQ_CTX) -> usize;
    fn OCSP_sendreq_bio(b: *mut BIO, path: *const c_char, req: *mut c_void) -> *mut c_void;
    fn OCSP_RESPONSE_free(a: *mut c_void);
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_write(b: *mut BIO, data: *const c_void, len: c_int) -> c_int;
    fn BIO_read(b: *mut BIO, data: *mut c_void, len: c_int) -> c_int;
    fn BIO_ctrl(b: *mut BIO, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn ERR_clear_error();
}

/// A memory BIO holding the input, at its end returning 0 (end of file) rather than retry.
fn input(data: &[u8], len: c_int) -> *mut BIO {
    // SAFETY: the built-in method.
    let r = unsafe { BIO_new(BIO_s_mem()) };
    // SAFETY: the BIO made here; the input's octets.
    unsafe { BIO_write(r, data.as_ptr().cast(), len) };
    // SAFETY: as above.
    unsafe { BIO_ctrl(r, rustyssl_abi::BIO_C_SET_BUF_MEM_EOF_RETURN, 0, ptr::null_mut()) };
    r
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let Ok(len) = c_int::try_from(rest.len()) else {
        return;
    };
    let expected: [*const c_char; 3] = [ptr::null(), c"text/plain".as_ptr(), c"application/ocsp-response".as_ptr()];
    // SAFETY: the built-in method.
    let w = unsafe { BIO_new(BIO_s_mem()) };
    let r = input(rest, len);
    let buf_size = if mode & 1 != 0 { 40 } else { 0 };
    // SAFETY: the BIOs made here.
    let rctx = unsafe { OSSL_HTTP_REQ_CTX_new(w, r, buf_size) };
    // SAFETY: the context made here; static strings.
    unsafe { OSSL_HTTP_REQ_CTX_set_request_line(rctx, c_int::from(mode & 2 != 0), ptr::null(), ptr::null(), c"/x".as_ptr()) };
    let ct = expected[usize::from(mode >> 2 & 3) % 3];
    // SAFETY: as above.
    unsafe { OSSL_HTTP_REQ_CTX_set_expected(rctx, ct, c_int::from(mode & 16 != 0), 0, c_int::from(mode >> 5 & 3)) };
    if mode & 128 != 0 {
        // SAFETY: as above.
        unsafe { OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines(rctx, 4) };
    }
    // SAFETY: as above.
    let got = unsafe { OSSL_HTTP_REQ_CTX_exchange(rctx) };
    if !got.is_null() {
        let mut buf = [0u8; 256];
        // SAFETY: the response's BIO; the buffer's room.
        while unsafe { BIO_read(got, buf.as_mut_ptr().cast(), 256) } > 0 {}
        // SAFETY: as above.
        unsafe { OSSL_HTTP_REQ_CTX_get_resp_len(rctx) };
    }
    // SAFETY: each made here.
    unsafe { OSSL_HTTP_REQ_CTX_free(rctx) };
    // SAFETY: as above.
    unsafe { BIO_free(w) };
    // SAFETY: as above.
    unsafe { BIO_free(r) };

    // As the answer to an OCSP request, over one BIO both ways.
    let io = input(rest, len);
    // SAFETY: the BIO made here; no request.
    let resp = unsafe { OCSP_sendreq_bio(io, c"/".as_ptr(), ptr::null_mut()) };
    // SAFETY: the response, or NULL.
    unsafe { OCSP_RESPONSE_free(resp) };
    // SAFETY: made here.
    unsafe { BIO_free(io) };
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
