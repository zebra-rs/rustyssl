//! The HTTP/1.0 client (`http_client.c`): `OSSL_HTTP_REQ_CTX`, a non-blocking exchange of one
//! request and its response over a pair of BIOs, and on it `OSSL_HTTP_open`, `_set1_request`,
//! `_exchange`, `_get` (following redirections), `_transfer`, `_close`, and
//! `OSSL_HTTP_proxy_connect`.
//!
//! As OpenSSL's:
//! - A response is read line by line (each at most the buffer's size, by default 4096 octets),
//!   with at most 256 header lines (`OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines`) and a
//!   content of at most 100 KiB (`OSSL_HTTP_REQ_CTX_set_max_response_length`) unless set
//!   otherwise; ASN.1 content is read to the length its DER header gives, and must agree with
//!   any `Content-Length`.
//! - CR and LF are refused in what goes into the request's header (CVE-2025-9232's lesson for
//!   the request line and headers).
//! - Redirections are followed for GET only, at most 50 of them, and never from HTTPS to HTTP.
//!
//! OpenSSL's default build has no tracing, so neither has this: the error content of a failed
//! response is not read.

use core::ffi::{CStr, c_char, c_int, c_long, c_ulong, c_void};
use core::ptr;

use libc::time_t;
use rustyssl_abi::{
    ASN1_ITEM, ASN1_VALUE, BIO, BIO_C_SET_CONNECT, BIO_CTRL_EOF, BIO_CTRL_FLUSH, BIO_CTRL_INFO,
    BIO_CTRL_RESET, BIO_FLAGS_SHOULD_RETRY, BIO_PARSE_PRIO_HOST, BIO_R_CONNECT_ERROR,
    BIO_R_CONNECT_TIMEOUT, BIO_TYPE_FILE, CMP_R_POTENTIALLY_INVALID_CERTIFICATE, ERR_LIB_BIO,
    ERR_LIB_CMP, ERR_LIB_HTTP, ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT,
    ERR_R_PASSED_NULL_PARAMETER, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, HTTP_R_CONNECT_FAILURE,
    HTTP_R_CONTENT_TYPE_MISMATCH, HTTP_R_ERROR_PARSING_ASN1_LENGTH,
    HTTP_R_ERROR_PARSING_CONTENT_LENGTH, HTTP_R_ERROR_RECEIVING, HTTP_R_ERROR_SENDING,
    HTTP_R_FAILED_READING_DATA, HTTP_R_HEADER_PARSE_ERROR, HTTP_R_INCONSISTENT_CONTENT_LENGTH,
    HTTP_R_MAX_RESP_LEN_EXCEEDED, HTTP_R_MISSING_ASN1_ENCODING, HTTP_R_MISSING_CONTENT_TYPE,
    HTTP_R_MISSING_REDIRECT_LOCATION, HTTP_R_RECEIVED_WRONG_HTTP_VERSION,
    HTTP_R_REDIRECTION_FROM_HTTPS_TO_HTTP, HTTP_R_REDIRECTION_NOT_ENABLED,
    HTTP_R_RESPONSE_LINE_TOO_LONG, HTTP_R_RESPONSE_TOO_MANY_HDRLINES, HTTP_R_RETRY_TIMEOUT,
    HTTP_R_SERVER_CANCELED_CONNECTION, HTTP_R_STATUS_CODE_UNSUPPORTED, HTTP_R_TLS_NOT_ENABLED,
    HTTP_R_TOO_MANY_REDIRECTIONS, HTTP_R_UNEXPECTED_CONTENT_TYPE, OSSL_HTTP_DEFAULT_MAX_CRL_LEN,
    OSSL_HTTP_DEFAULT_MAX_LINE_LEN, OSSL_HTTP_DEFAULT_MAX_RESP_HDR_LINES,
    OSSL_HTTP_DEFAULT_MAX_RESP_LEN, OSSL_HTTP_PORT, OSSL_HTTP_PREFIX, OSSL_HTTP_REQ_CTX,
    OSSL_HTTP_bio_cb_t, OSSL_HTTPS_NAME, OSSL_HTTPS_PORT, V_ASN1_CONSTRUCTED, V_ASN1_SEQUENCE,
    X509, X509_CRL, stack_st_CONF_VALUE,
};

use crate::asn1::generate::strtoul10;
use crate::asn1::tpl::decode::ASN1_item_d2i;
use crate::asn1::tpl::io::{ASN1_item_d2i_bio, ASN1_item_i2d_mem_bio};
use crate::bio::addr::BIO_parse_hostserv;
use crate::bio::buffer::BIO_f_buffer;
use crate::bio::connect::BIO_new_connect;
use crate::bio::mem::BIO_s_mem;
use crate::bio::sock::{BIO_do_connect_retry, BIO_wait};
use crate::bio::{
    BIO_ctrl, BIO_free, BIO_free_all, BIO_get_line, BIO_gets, BIO_method_type, BIO_new, BIO_pop,
    BIO_push, BIO_read, BIO_test_flags, BIO_up_ref, BIO_write, BIO_write_ex,
};
use crate::err::{self, ERR_clear_last_mark, ERR_peek_error, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::encode::EVP_EncodeBlock;
use crate::ffi::ffi_export;
use crate::http_lib::{OSSL_HTTP_adapt_proxy, OSSL_HTTP_parse_url};
use crate::mem;
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::string::CRYPTO_strdup;

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_HTTP, reason, f);
}

fn raise_text(reason: c_int, f: &str, text: &[u8]) {
    err::raise_with_bytes(ERR_LIB_HTTP, reason, f, text);
}

const HTTP_PREFIX_VERSION: &[u8] = b"HTTP/1.";
/// `sizeof(HTTP_PREFIX_VERSION "x 200\n") - 1`.
const HTTP_LINE1_MINLEN: c_int = 13;
const MAX_REDIRECTIONS: c_int = 50;
const STATUS_OK: c_int = 200;
const STATUS_MOVED_PERMANENTLY: c_int = 301;
const STATUS_FOUND: c_int = 302;
const STATUS_NONFATAL_ERROR: c_int = 400;
const STATUS_NOT_FOUND: c_int = 404;

// The states: those with `NOREAD` write the request, the others read the response.
const NOREAD: c_int = 0x1000;
const ERROR: c_int = NOREAD;
const ADD_HEADERS: c_int = 1 | NOREAD;
const WRITE_INIT: c_int = 2 | NOREAD;
const WRITE_HDR1: c_int = 3 | NOREAD;
const WRITE_HDR: c_int = 4 | NOREAD;
const WRITE_REQ: c_int = 5 | NOREAD;
const FLUSH: c_int = 6 | NOREAD;
const FIRSTLINE: c_int = 1;
const HEADERS: c_int = 2;
const HEADERS_ERROR: c_int = 3;
const REDIRECT: c_int = 4;
const ASN1_HEADER: c_int = 5;
const ASN1_CONTENT: c_int = 6;
const ASN1_DONE: c_int = 7;
const STREAM: c_int = 8;
const ERROR_CONTENT: c_int = 9;

/// `OSSL_HTTP_REQ_CTX`.
#[repr(C)]
pub(crate) struct ReqCtx {
    state: c_int,
    /// `buf_size` octets from `CRYPTO_malloc`.
    buf: *mut u8,
    buf_size: c_int,
    free_wbio: bool,
    wbio: *mut BIO,
    rbio: *mut BIO,
    upd_fn: OSSL_HTTP_bio_cb_t,
    upd_arg: *mut c_void,
    use_ssl: bool,
    proxy: *mut c_char,
    server: *mut c_char,
    port: *mut c_char,
    /// The request's header being written, then the response read.
    mem: *mut BIO,
    /// The request's content.
    req: *mut BIO,
    method_post: bool,
    text: bool,
    expected_ct: *mut c_char,
    expect_asn1: c_int,
    pos: *const u8,
    len_to_send: c_long,
    resp_len: usize,
    max_resp_len: usize,
    keep_alive: c_int,
    max_time: time_t,
    max_total_time: time_t,
    /// Into `buf`: the `Location` of a redirection.
    redirection_url: *const c_char,
    max_hdr_lines: usize,
}

/// The context behind a pointer.
///
/// # Safety
/// `p` is NULL or a live context, not otherwise borrowed.
unsafe fn ctx_of<'a>(p: *const OSSL_HTTP_REQ_CTX) -> Option<&'a mut ReqCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { p.cast::<ReqCtx>().cast_mut().as_mut() }
}

/// The C string's octets (none for NULL).
///
/// # Safety
/// `p` is NULL or a C string that outlives the octets.
unsafe fn bytes<'a>(p: *const c_char) -> &'a [u8] {
    if p.is_null() {
        return &[];
    }
    // SAFETY: the caller's guarantee.
    unsafe { CStr::from_ptr(p) }.to_bytes()
}

fn now() -> time_t {
    // SAFETY: NULL asks for the time only.
    unsafe { libc::time(ptr::null_mut()) }
}

/// `ossl_isspace`.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// A copy of the C string from `CRYPTO_malloc`, or NULL.
///
/// # Safety
/// `s` is a C string.
unsafe fn strdup(s: *const c_char) -> *mut c_char {
    // SAFETY: the caller's string.
    unsafe { CRYPTO_strdup(s, c"http_client.c".as_ptr(), 0) }
}

/// `no_crlf`: whether `value` (NULL or a C string) has no CR or LF.
///
/// # Safety
/// `value` is NULL or a C string.
unsafe fn no_crlf(component: &str, value: *const c_char) -> bool {
    // SAFETY: the caller's string.
    if unsafe { bytes(value) }
        .iter()
        .any(|&c| c == b'\r' || c == b'\n')
    {
        err::raise_with_text(
            ERR_LIB_HTTP,
            ERR_R_PASSED_INVALID_ARGUMENT,
            "no_crlf",
            &format!("CR or LF character in {component}"),
        );
        return false;
    }
    true
}

/// Writes the octets: whether all were.
///
/// # Safety
/// `b` is a live BIO.
unsafe fn put(b: *mut BIO, s: &[u8]) -> bool {
    let Ok(n) = c_int::try_from(s.len()) else {
        return false;
    };
    // SAFETY: the caller's BIO; the octets.
    n == 0 || unsafe { BIO_write(b, s.as_ptr().cast(), n) } == n
}

/// `BIO_get_mem_data`: the memory BIO's unread octets.
///
/// # Safety
/// `b` is a live memory BIO.
unsafe fn mem_data(b: *mut BIO) -> (*const u8, c_long) {
    let mut p: *mut c_char = ptr::null_mut();
    // SAFETY: the caller's BIO; room for the pointer.
    let n = unsafe { BIO_ctrl(b, rustyssl_abi::BIO_CTRL_INFO, 0, (&raw mut p).cast()) };
    (p.cast_const().cast(), n)
}

/// `BIO_should_retry`.
///
/// # Safety
/// `b` is a live BIO.
unsafe fn should_retry(b: *mut BIO) -> bool {
    // SAFETY: the caller's BIO.
    (unsafe { BIO_test_flags(b, BIO_FLAGS_SHOULD_RETRY) }) != 0
}

/// `BIO_reset`, its result unused.
///
/// # Safety
/// `b` is NULL or a live BIO.
unsafe fn reset(b: *mut BIO) {
    // SAFETY: the caller's BIO.
    unsafe { BIO_ctrl(b, BIO_CTRL_RESET, 0, ptr::null_mut()) };
}

ffi_export! {
    /// A context for an exchange over `wbio` and `rbio` with lines of up to `buf_size` octets
    /// (4096 for 0 or less), or NULL.
    ///
    /// # Safety
    /// `wbio` and `rbio` are live BIOs that outlive the context.
    pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_new(wbio: *mut BIO, rbio: *mut BIO, buf_size: c_int) -> *mut OSSL_HTTP_REQ_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_HTTP
    {
        if wbio.is_null() || rbio.is_null() {
            raise(ERR_R_PASSED_NULL_PARAMETER, "OSSL_HTTP_REQ_CTX_new");
            return ptr::null_mut();
        }
        let p = mem::alloc_zeroed(size_of::<ReqCtx>()).cast::<OSSL_HTTP_REQ_CTX>();
        // SAFETY: zeroed memory for a context, all of whose fields may be zero, or NULL.
        let Some(c) = (unsafe { ctx_of(p) }) else { return ptr::null_mut() };
        c.state = ERROR;
        c.buf_size = if buf_size > 0 { buf_size } else { OSSL_HTTP_DEFAULT_MAX_LINE_LEN };
        c.buf = mem::alloc(usize::try_from(c.buf_size).unwrap_or(0)).cast();
        c.wbio = wbio;
        c.rbio = rbio;
        c.max_hdr_lines = usize::try_from(OSSL_HTTP_DEFAULT_MAX_RESP_HDR_LINES).unwrap_or(0);
        if c.buf.is_null() {
            // SAFETY: allocated above.
            unsafe { mem::release(p.cast()) };
            return ptr::null_mut();
        }
        c.max_resp_len = usize::try_from(OSSL_HTTP_DEFAULT_MAX_RESP_LEN).unwrap_or(0);
        p
    }
}

ffi_export! {
    /// Frees the context, and its write BIO if it opened it.
    ///
    /// # Safety
    /// `rctx` is NULL or a live context, not used again.
    pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_free(rctx: *mut OSSL_HTTP_REQ_CTX)
    where failure = (), library = ERR_LIB_HTTP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(rctx) }) else { return };
        if c.free_wbio {
            // SAFETY: the BIO it opened.
            unsafe { BIO_free_all(c.wbio) };
        }
        // SAFETY: its own, or NULL.
        unsafe { BIO_free(c.mem) };
        // SAFETY: as above.
        unsafe { BIO_free(c.req) };
        for p in [c.buf.cast::<c_void>(), c.proxy.cast(), c.server.cast(), c.port.cast(), c.expected_ct.cast()] {
            // SAFETY: as above, from `CRYPTO_malloc`.
            unsafe { mem::release(p) };
        }
        // SAFETY: made by `OSSL_HTTP_REQ_CTX_new`.
        unsafe { mem::release(rctx.cast()) };
    }
}

ffi_export! {
    /// The memory BIO the request's header goes to and the response comes into, or NULL.
    ///
    /// # Safety
    /// `rctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_get0_mem_bio(rctx: *const OSSL_HTTP_REQ_CTX) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_HTTP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(rctx) }) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, "OSSL_HTTP_REQ_CTX_get0_mem_bio");
            return ptr::null_mut();
        };
        c.mem
    }
}

ffi_export! {
    /// The response's content length, when known, or 0.
    ///
    /// # Safety
    /// `rctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_get_resp_len(rctx: *const OSSL_HTTP_REQ_CTX) -> usize
    where failure = 0, library = ERR_LIB_HTTP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(rctx) }) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, "OSSL_HTTP_REQ_CTX_get_resp_len");
            return 0;
        };
        c.resp_len
    }
}

ffi_export! {
    /// Sets the longest content accepted (100 KiB for 0).
    ///
    /// # Safety
    /// `rctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_set_max_response_length(rctx: *mut OSSL_HTTP_REQ_CTX, len: c_ulong)
    where failure = (), library = ERR_LIB_HTTP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(rctx) }) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, "OSSL_HTTP_REQ_CTX_set_max_response_length");
            return;
        };
        c.max_resp_len = if len != 0 {
            usize::try_from(len).unwrap_or(usize::MAX)
        } else {
            usize::try_from(OSSL_HTTP_DEFAULT_MAX_RESP_LEN).unwrap_or(0)
        };
    }
}

ffi_export! {
    /// Sets the most header lines accepted (0 for no limit).
    ///
    /// # Safety
    /// `rctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines(rctx: *mut OSSL_HTTP_REQ_CTX, count: usize)
    where failure = (), library = ERR_LIB_HTTP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(rctx) }) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, "OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines");
            return;
        };
        c.max_hdr_lines = count;
    }
}

/// The request line's text: `GET` or `POST`, the server's prefix when given (for a proxy),
/// the path, and the version.
///
/// # Safety
/// `server`, `port`, and `path` are NULL or C strings.
unsafe fn request_line(
    post: bool,
    server: *const c_char,
    port: *const c_char,
    path: *const c_char,
) -> Option<Vec<u8>> {
    let mut l = if post {
        b"POST ".to_vec()
    } else {
        b"GET ".to_vec()
    };
    if !server.is_null() {
        l.extend_from_slice(OSSL_HTTP_PREFIX.to_bytes());
        // SAFETY: the caller's strings.
        l.extend_from_slice(unsafe { bytes(server) });
        if !port.is_null() {
            l.push(b':');
            // SAFETY: as above.
            l.extend_from_slice(unsafe { bytes(port) });
        }
    }
    let path = if path.is_null() {
        &b"/"[..]
    } else {
        // SAFETY: as above.
        unsafe { bytes(path) }
    };
    if path.starts_with(b"http://") {
        if !server.is_null() {
            raise(
                ERR_R_PASSED_INVALID_ARGUMENT,
                "OSSL_HTTP_REQ_CTX_set_request_line",
            );
            return None;
        }
    } else if path.first() != Some(&b'/') {
        l.push(b'/');
    }
    l.extend_from_slice(path);
    l.extend_from_slice(b" HTTP/1.0\r\n");
    Some(l)
}

ffi_export! {
    /// Starts the request's header with its line: `POST` (non-zero `method_post`) or `GET`,
    /// `server` and `port` before the path for a proxy: 1, or 0.
    ///
    /// # Safety
    /// `rctx` is NULL or a live context; `server`, `port`, and `path` NULL or C strings.
    pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_set_request_line(rctx: *mut OSSL_HTTP_REQ_CTX, method_post: c_int, server: *const c_char, port: *const c_char, path: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_HTTP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(rctx) }) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, "OSSL_HTTP_REQ_CTX_set_request_line");
            return 0;
        };
        // SAFETY: the caller's strings.
        if !unsafe { no_crlf("server", server) } || !unsafe { no_crlf("port", port) } || !unsafe { no_crlf("path", path) } {
            return 0;
        }
        // SAFETY: its own, or NULL.
        unsafe { BIO_free(c.mem) };
        // SAFETY: the built-in method.
        let method = unsafe { BIO_s_mem() };
        // SAFETY: the built-in method.
        c.mem = unsafe { BIO_new(method) };
        if c.mem.is_null() {
            return 0;
        }
        c.method_post = method_post != 0;
        // SAFETY: the caller's strings.
        let Some(line) = (unsafe { request_line(c.method_post, server, port, path) }) else { return 0 };
        // SAFETY: its memory BIO.
        if !unsafe { put(c.mem, &line) } {
            return 0;
        }
        c.resp_len = 0;
        c.state = ADD_HEADERS;
        1
    }
}

ffi_export! {
    /// Adds the header line `name: value` (`name` alone for a NULL value): 1, or 0.
    ///
    /// # Safety
    /// `rctx` is NULL or a live context; `name` NULL or a C string; `value` NULL or one.
    pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_add1_header(rctx: *mut OSSL_HTTP_REQ_CTX, name: *const c_char, value: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_HTTP
    {
        const F: &str = "OSSL_HTTP_REQ_CTX_add1_header";
        // SAFETY: the caller's guarantee.
        let c = unsafe { ctx_of(rctx) };
        let (Some(c), false) = (c, name.is_null()) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        };
        if c.mem.is_null() {
            raise(ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, F);
            return 0;
        }
        // SAFETY: the caller's strings.
        if !unsafe { no_crlf("header name", name) } || !unsafe { no_crlf("header value", value) } {
            return 0;
        }
        // SAFETY: as above.
        let n = unsafe { bytes(name) };
        // `BIO_puts` of an empty name writes nothing, which OpenSSL takes as a failure.
        // SAFETY: its memory BIO.
        if n.is_empty() || !unsafe { put(c.mem, n) } {
            return 0;
        }
        if !value.is_null() {
            // SAFETY: as above.
            let v = unsafe { bytes(value) };
            // SAFETY: its memory BIO.
            if !unsafe { put(c.mem, b": ") } || v.is_empty() || !unsafe { put(c.mem, v) } {
                return 0;
            }
        }
        // SAFETY: as above.
        c_int::from(unsafe { put(c.mem, b"\r\n") })
    }
}

ffi_export! {
    /// Sets what the response must be: its content type (when given), whether ASN.1 (DER),
    /// the timeout in seconds (0 for none, -1 for the overall one), and whether to keep the
    /// connection alive (1 asks, 2 requires): 1, or 0.
    ///
    /// # Safety
    /// `rctx` is NULL or a live context; `content_type` NULL or a C string.
    pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_set_expected(rctx: *mut OSSL_HTTP_REQ_CTX, content_type: *const c_char, asn1: c_int, timeout: c_int, keep_alive: c_int) -> c_int
    where failure = 0, library = ERR_LIB_HTTP
    {
        const F: &str = "OSSL_HTTP_REQ_CTX_set_expected";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(rctx) }) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        };
        if keep_alive != 0 && c.state != ERROR && c.state != ADD_HEADERS {
            raise(ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, F);
            return 0;
        }
        // SAFETY: its own, or NULL.
        unsafe { mem::release(c.expected_ct.cast()) };
        c.expected_ct = ptr::null_mut();
        if !content_type.is_null() {
            // SAFETY: the caller's string.
            c.expected_ct = unsafe { strdup(content_type) };
            if c.expected_ct.is_null() {
                return 0;
            }
        }
        c.expect_asn1 = asn1;
        c.max_time = if timeout >= 0 {
            if timeout > 0 { now() + time_t::from(timeout) } else { 0 }
        } else {
            c.max_total_time
        };
        c.keep_alive = keep_alive;
        1
    }
}

/// `set1_content`: the request's content (none for NULL), its type, and its length.
///
/// # Safety
/// `rctx` is NULL or a live context; `content_type` NULL or a C string; `req` NULL or a live
/// BIO.
unsafe fn set1_content(
    rctx: *mut OSSL_HTTP_REQ_CTX,
    content_type: *const c_char,
    req: *mut BIO,
) -> bool {
    const F: &str = "set1_content";
    // SAFETY: the caller's guarantee.
    let keep = unsafe { ctx_of(rctx) }.map(|c| c.keep_alive);
    let Some(keep) = keep.filter(|_| !req.is_null() || content_type.is_null()) else {
        raise(ERR_R_PASSED_NULL_PARAMETER, F);
        return false;
    };
    if keep != 0
        // SAFETY: the caller's context; static strings.
        && unsafe {
            OSSL_HTTP_REQ_CTX_add1_header(rctx, c"Connection".as_ptr(), c"keep-alive".as_ptr())
        } == 0
    {
        return false;
    }
    // SAFETY: as above.
    let Some(c) = (unsafe { ctx_of(rctx) }) else {
        return false;
    };
    // SAFETY: its own, or NULL.
    unsafe { BIO_free(c.req) };
    c.req = ptr::null_mut();
    if req.is_null() {
        return true;
    }
    if !c.method_post {
        raise(ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, F);
        return false;
    }
    if content_type.is_null() {
        c.text = true;
    } else {
        // SAFETY: the caller's string.
        if unsafe { bytes(content_type) }
            .get(..5)
            .is_some_and(|p| p.eq_ignore_ascii_case(b"text/"))
        {
            c.text = true;
        }
        // SAFETY: the caller's context and string.
        if unsafe { OSSL_HTTP_REQ_CTX_add1_header(rctx, c"Content-Type".as_ptr(), content_type) }
            == 0
        {
            return false;
        }
    }
    // SAFETY: as above.
    let Some(c) = (unsafe { ctx_of(rctx) }) else {
        return false;
    };
    // SAFETY: the caller's BIO.
    let (has_fp, len) = if unsafe { BIO_method_type(req) } == BIO_TYPE_FILE {
        // SAFETY: as above.
        unsafe { file_length(req) }
    } else {
        // SAFETY: as above.
        (false, unsafe {
            BIO_ctrl(req, BIO_CTRL_INFO, 0, ptr::null_mut())
        })
    };
    if (has_fp || len > 0)
        // SAFETY: its memory BIO.
        && !unsafe { put(c.mem, format!("Content-Length: {len}\r\n").as_bytes()) }
    {
        return false;
    }
    // SAFETY: the caller's BIO.
    if unsafe { BIO_up_ref(req) } == 0 {
        return false;
    }
    c.req = req;
    true
}

/// A file BIO's length: whether its file seeks, and how long it is (rewound).
///
/// # Safety
/// `req` is a live file BIO.
unsafe fn file_length(req: *mut BIO) -> (bool, c_long) {
    let mut fp: *mut libc::FILE = ptr::null_mut();
    // SAFETY: the caller's BIO; room for its file.
    if unsafe {
        BIO_ctrl(
            req,
            rustyssl_abi::BIO_C_GET_FILE_PTR,
            0,
            (&raw mut fp).cast(),
        )
    } != 1
        || fp.is_null()
    {
        return (false, 0);
    }
    // SAFETY: its file.
    if unsafe { libc::fseek(fp, 0, libc::SEEK_END) } != 0 {
        return (false, 0);
    }
    // SAFETY: as above.
    let len = unsafe { libc::ftell(fp) };
    // SAFETY: as above.
    unsafe { libc::fseek(fp, 0, libc::SEEK_SET) };
    (true, len)
}

ffi_export! {
    /// Sets the request's content to the DER of `req` (none for NULL), of `content_type`: 1, or
    /// 0.
    ///
    /// # Safety
    /// `rctx` is NULL or a live context; `content_type` NULL or a C string; `it` and `req` an
    /// item and NULL or a value of it.
    pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_set1_req(rctx: *mut OSSL_HTTP_REQ_CTX, content_type: *const c_char, it: *const ASN1_ITEM, req: *const ASN1_VALUE) -> c_int
    where failure = 0, library = ERR_LIB_HTTP
    {
        let mut membio = ptr::null_mut();
        let mut ok = true;
        if !req.is_null() {
            // SAFETY: the caller's item and value.
            membio = unsafe { ASN1_item_i2d_mem_bio(it, req) };
            ok = !membio.is_null();
        }
        // SAFETY: the caller's context and type; the BIO, or NULL.
        ok = ok && unsafe { set1_content(rctx, content_type, membio) };
        // SAFETY: made here, or NULL.
        unsafe { BIO_free(membio) };
        c_int::from(ok)
    }
}

/// `add1_headers`: the headers, and `Host` unless they have one.
///
/// # Safety
/// `rctx` is a live context; `headers` NULL or a live list; `host` NULL or a C string.
unsafe fn add1_headers(
    rctx: *mut OSSL_HTTP_REQ_CTX,
    headers: *const stack_st_CONF_VALUE,
    host: *const c_char,
) -> bool {
    // SAFETY: the caller's string.
    let mut add_host = !unsafe { bytes(host) }.is_empty();
    // SAFETY: the caller's list, or NULL (0).
    let n = unsafe { OPENSSL_sk_num(headers.cast()) };
    for i in 0..n {
        // SAFETY: an index in range.
        let hdr = unsafe { OPENSSL_sk_value(headers.cast(), i) }.cast::<rustyssl_abi::CONF_VALUE>();
        // SAFETY: a value of the list.
        let Some(h) = (unsafe { hdr.as_ref() }) else {
            return false;
        };
        // SAFETY: its name.
        if add_host && unsafe { bytes(h.name) }.eq_ignore_ascii_case(b"host") {
            add_host = false;
        }
        // SAFETY: the caller's context; its name and value.
        if unsafe { OSSL_HTTP_REQ_CTX_add1_header(rctx, h.name, h.value) } == 0 {
            return false;
        }
    }
    // SAFETY: the caller's context and host.
    !add_host || unsafe { OSSL_HTTP_REQ_CTX_add1_header(rctx, c"Host".as_ptr(), host) } != 0
}

/// `parse_http_line1`: the status line's code (200, 301, and 302 quietly; 404 and codes
/// below 400 with an error), or 0 for no status line.
fn parse_line1(line: &mut [u8], found_keep_alive: &mut bool) -> c_int {
    const F: &str = "parse_http_line1";
    let len = line.iter().position(|&c| c == 0).unwrap_or(line.len());
    let mut start = 0;
    let parsed = 'p: {
        if !part(line, 0..len).starts_with(HTTP_PREFIX_VERSION) {
            break 'p None;
        }
        start = HTTP_PREFIX_VERSION.len();
        let at = |line: &[u8], i: usize| line.get(i).copied().filter(|_| i < len).unwrap_or(0);
        *found_keep_alive = at(line, start) > b'0';
        let mut code = start;
        while at(line, code) != 0 && !is_space(at(line, code)) {
            code += 1;
        }
        while at(line, code) != 0 && is_space(at(line, code)) {
            code += 1;
        }
        if at(line, code) == 0 {
            break 'p None;
        }
        let mut reason = code;
        while at(line, reason) != 0 && !is_space(at(line, reason)) {
            reason += 1;
        }
        if at(line, reason) == 0 {
            break 'p None;
        }
        let code_end = reason;
        reason += 1;
        let (value, used) = strtoul10(part(line, code..code_end));
        // `*reason++ = '\0'` comes before the code is read.
        terminate(line, code_end);
        if used != code_end - code {
            break 'p None;
        }
        while at(line, reason) != 0 && is_space(at(line, reason)) {
            reason += 1;
        }
        let mut end = len;
        while end > reason && is_space(byte(line, end - 1)) {
            end -= 1;
        }
        Some((value, code, code_end, reason, end))
    };
    let Some((value, code, code_end, reason, end)) = parsed else {
        // The text from where the parse got to, printable, up to 60 characters.
        let text: Vec<u8> = part(line, start..line.len())
            .iter()
            .take_while(|&&c| c != 0)
            .take(60)
            .map(|&c| if (0x20..0x7f).contains(&c) { c } else { b' ' })
            .collect();
        let mut d = b"content=".to_vec();
        d.extend_from_slice(&text);
        raise_text(HTTP_R_HEADER_PARSE_ERROR, F, &d);
        return 0;
    };
    // `int retcode = strtoul(...)`: C's conversion.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "C's conversion of unsigned long to int"
    )]
    let retcode = value as c_int;
    if matches!(retcode, STATUS_OK | STATUS_MOVED_PERMANENTLY | STATUS_FOUND) {
        return retcode;
    }
    if retcode == STATUS_NOT_FOUND || retcode < STATUS_NONFATAL_ERROR {
        let mut d = b"code=".to_vec();
        d.extend_from_slice(part(line, code..code_end));
        if end > reason {
            d.extend_from_slice(b", reason=");
            d.extend_from_slice(part(line, reason..end));
        }
        raise_text(HTTP_R_STATUS_CODE_UNSUPPORTED, F, &d);
    }
    retcode
}

/// `check_max_len`.
fn check_max_len(desc: &str, max_len: usize, len: usize) -> bool {
    if max_len != 0 && len > max_len {
        err::raise_with_text(
            ERR_LIB_HTTP,
            HTTP_R_MAX_RESP_LEN_EXCEEDED,
            "check_max_len",
            &format!("{desc} length={len}, max={max_len}"),
        );
        return false;
    }
    true
}

/// `check_set_resp_len`.
fn check_set_resp_len(desc: &str, c: &mut ReqCtx, len: usize) -> bool {
    if !check_max_len(desc, c.max_resp_len, len) {
        return false;
    }
    if c.resp_len != 0 && c.resp_len != len {
        err::raise_with_text(
            ERR_LIB_HTTP,
            HTTP_R_INCONSISTENT_CONTENT_LENGTH,
            "check_set_resp_len",
            &format!("{desc} length={len}, Content-Length={}", c.resp_len),
        );
        return false;
    }
    c.resp_len = len;
    true
}

/// `may_still_retry`: whether time is left, with the seconds left into `*timeout`.
fn may_still_retry(max_time: time_t, timeout: &mut c_int) -> bool {
    let t = now();
    if max_time != 0 {
        if max_time < t {
            raise(HTTP_R_RETRY_TIMEOUT, "may_still_retry");
            return false;
        }
        *timeout = c_int::try_from(max_time - t).unwrap_or(c_int::MAX);
    }
    true
}

/// The octets of `b` in `r`, or none past its end.
fn part(b: &[u8], r: core::ops::Range<usize>) -> &[u8] {
    b.get(r).unwrap_or_default()
}

/// The octet of `b` at `i`, or 0 past its end.
fn byte(b: &[u8], i: usize) -> u8 {
    b.get(i).copied().unwrap_or(0)
}

/// Ends the C string in `b` at `i`, as `*p = '\0'` does.
fn terminate(b: &mut [u8], i: usize) {
    if let Some(x) = b.get_mut(i) {
        *x = 0;
    }
}

/// The length of the C string at the start of `b`.
fn c_len(b: &[u8]) -> usize {
    b.iter().position(|&c| c == 0).unwrap_or(b.len())
}

/// The index of `c` in the C string from `from`.
fn c_find(b: &[u8], from: usize, c: u8) -> Option<usize> {
    let s = b.get(from..)?;
    s.get(..c_len(s))?
        .iter()
        .position(|&x| x == c)
        .map(|i| i + from)
}

/// What one call of `OSSL_HTTP_REQ_CTX_nbio` keeps between lines.
#[derive(Default)]
struct Pass {
    found_expected_ct: bool,
    found_keep_alive: bool,
    status_code: c_int,
    resp_hdr_lines: usize,
    /// The error content's length so far.
    resp_len: usize,
}

/// One header line, in `buf` (which it changes, as OpenSSL's parse does): `Some` to return
/// with that value, `None` to go on.
///
/// # Safety
/// `c`'s members are live.
unsafe fn header_line(c: &mut ReqCtx, buf: &mut [u8], pass: &mut Pass) -> Option<c_int> {
    const F: &str = "OSSL_HTTP_REQ_CTX_nbio";
    let mut value_at = None;
    if let Some(colon) = c_find(buf, 0, b':') {
        terminate(buf, colon);
        let mut v = colon + 1;
        while buf.get(v).is_some_and(|&x| is_space(x)) {
            v += 1;
        }
        let end = c_find(buf, v, b'\r').or_else(|| c_find(buf, v, b'\n'));
        if let Some(e) = end {
            terminate(buf, e);
            value_at = Some(v);
        }
    }
    if let Some(v) = value_at {
        let key_len = c_len(buf);
        let key = part(buf, 0..key_len).to_vec();
        let rest = part(buf, v..buf.len());
        let value = part(rest, 0..c_len(rest)).to_vec();
        if c.state == REDIRECT && key.eq_ignore_ascii_case(b"Location") {
            c.redirection_url = buf.as_ptr().wrapping_add(v).cast();
            // SAFETY: its read BIO.
            unsafe { reset(c.rbio) };
            return Some(0);
        }
        if key.eq_ignore_ascii_case(b"Content-Type") {
            let got_text = value
                .get(..5)
                .is_some_and(|p| p.eq_ignore_ascii_case(b"text/"));
            if got_text
                && c.state == HEADERS
                && c.expect_asn1 != 0
                && (pass.status_code >= STATUS_NONFATAL_ERROR || pass.status_code == STATUS_OK)
            {
                let mut d = format!(
                    "expected ASN.1 content but got http code {} with Content-Type: ",
                    pass.status_code
                )
                .into_bytes();
                d.extend_from_slice(&value);
                raise_text(HTTP_R_CONTENT_TYPE_MISMATCH, F, &d);
                c.state = HEADERS_ERROR;
                return None;
            }
            if c.state == HEADERS && !c.expected_ct.is_null() {
                // SAFETY: its own string.
                let expected = unsafe { bytes(c.expected_ct) };
                let matches = expected.eq_ignore_ascii_case(&value)
                    || (!expected.contains(&b';')
                        && value.iter().position(|&x| x == b';').is_some_and(|s| {
                            s == expected.len() && part(&value, 0..s).eq_ignore_ascii_case(expected)
                        }));
                if !matches {
                    let mut d = b"expected=".to_vec();
                    d.extend_from_slice(expected);
                    d.extend_from_slice(b", actual=");
                    d.extend_from_slice(&value);
                    raise_text(HTTP_R_UNEXPECTED_CONTENT_TYPE, F, &d);
                    return Some(0);
                }
                pass.found_expected_ct = true;
            }
        }
        if key.eq_ignore_ascii_case(b"Connection") {
            if value.eq_ignore_ascii_case(b"keep-alive") {
                pass.found_keep_alive = true;
            } else if value.eq_ignore_ascii_case(b"close") {
                pass.found_keep_alive = false;
            }
        } else if key.eq_ignore_ascii_case(b"Content-Length") {
            let (n, used) = strtoul10(&value);
            if used == 0 || used != value.len() {
                let mut d = b"input=".to_vec();
                d.extend_from_slice(&value);
                raise_text(HTTP_R_ERROR_PARSING_CONTENT_LENGTH, F, &d);
                return Some(0);
            }
            #[expect(
                clippy::cast_possible_truncation,
                reason = "C's conversion of unsigned long to size_t"
            )]
            let n = n as usize;
            if !check_set_resp_len("response content-length", c, n) {
                return Some(0);
            }
        }
    }
    // A line of only CR and LF (or one the parse emptied) ends the header.
    if buf
        .iter()
        .take_while(|&&x| x != 0)
        .any(|&x| x != b'\r' && x != b'\n')
    {
        return None;
    }
    if c.keep_alive != 0 && !pass.found_keep_alive {
        if c.keep_alive == 2 {
            c.keep_alive = 0;
            raise(HTTP_R_SERVER_CANCELED_CONNECTION, F);
            return Some(0);
        }
        c.keep_alive = 0;
    }
    if c.state == HEADERS_ERROR {
        c.state = ERROR_CONTENT;
        // SAFETY: its read BIO.
        unsafe { reset(c.rbio) };
        return Some(0);
    }
    if !c.expected_ct.is_null() && !pass.found_expected_ct {
        let mut d = b"expected=".to_vec();
        // SAFETY: its own string.
        d.extend_from_slice(unsafe { bytes(c.expected_ct) });
        raise_text(HTTP_R_MISSING_CONTENT_TYPE, F, &d);
        return Some(0);
    }
    if c.state == REDIRECT {
        raise(HTTP_R_MISSING_REDIRECT_LOCATION, F);
        return Some(0);
    }
    if c.expect_asn1 == 0 {
        c.state = STREAM;
        return Some(1);
    }
    c.state = ASN1_HEADER;
    Some(-2)
}

/// What a step of the exchange asks for next.
enum Next {
    /// Read more, then go on.
    Io,
    /// Go on with the state as it is.
    Go,
    /// Return this.
    Return(c_int),
}

/// The ASN.1 content's DER header: the content's length, once enough has come.
///
/// # Safety
/// `c`'s memory BIO is live.
unsafe fn asn1_header(c: &mut ReqCtx) -> Next {
    const F: &str = "OSSL_HTTP_REQ_CTX_nbio";
    // SAFETY: its memory BIO.
    let (p, n) = unsafe { mem_data(c.mem) };
    if n < 2 {
        return Next::Io;
    }
    let Ok(avail) = usize::try_from(n) else {
        return Next::Io;
    };
    // SAFETY: its `n` unread octets.
    let d = unsafe { core::slice::from_raw_parts(p, avail) };
    let seq = u8::try_from(V_ASN1_SEQUENCE | V_ASN1_CONSTRUCTED).unwrap_or(0);
    if byte(d, 0) != seq {
        raise(HTTP_R_MISSING_ASN1_ENCODING, F);
        return Next::Return(0);
    }
    let resp_len = if byte(d, 1) & 0x80 != 0 {
        if n < 6 {
            return Next::Io;
        }
        let k = usize::from(byte(d, 1) & 0x7f);
        if k == 0 || k > 4 {
            raise(HTTP_R_ERROR_PARSING_ASN1_LENGTH, F);
            return Next::Return(0);
        }
        let len = part(d, 2..2 + k)
            .iter()
            .fold(0usize, |a, &b| (a << 8) | usize::from(b));
        len + k + 2
    } else {
        usize::from(byte(d, 1)) + 2
    };
    if !check_set_resp_len("ASN.1 DER content", c, resp_len) {
        return Next::Return(0);
    }
    c.state = ASN1_CONTENT;
    Next::Go
}

/// Writes what is left to send, or the request's next content: `Go` when all is sent.
///
/// # Safety
/// `c`'s BIOs are live.
unsafe fn write_step(c: &mut ReqCtx) -> Next {
    if c.len_to_send > 0 {
        let mut sz = 0usize;
        let len = usize::try_from(c.len_to_send).unwrap_or(0);
        // SAFETY: its write BIO; `len` octets at `pos` (of its memory BIO or its buffer).
        if unsafe { BIO_write_ex(c.wbio, c.pos.cast(), len, &raw mut sz) } == 0 {
            // SAFETY: as above.
            if unsafe { should_retry(c.wbio) } {
                return Next::Return(-1);
            }
            c.state = ERROR;
            return Next::Return(0);
        }
        if c.state == WRITE_HDR1 {
            c.state = WRITE_HDR;
        }
        c.pos = c.pos.wrapping_add(sz);
        c.len_to_send -= c_long::try_from(sz).unwrap_or(c.len_to_send);
        return Next::Io;
    }
    if c.state == WRITE_HDR {
        // SAFETY: its memory BIO.
        unsafe { reset(c.mem) };
        c.state = WRITE_REQ;
    }
    // SAFETY: its request BIO, or NULL.
    if !c.req.is_null() && unsafe { BIO_ctrl(c.req, BIO_CTRL_EOF, 0, ptr::null_mut()) } == 0 {
        // SAFETY: as above; its buffer's `buf_size` octets.
        let n = unsafe { BIO_read(c.req, c.buf.cast(), c.buf_size) };
        if n <= 0 {
            // SAFETY: as above.
            if unsafe { should_retry(c.req) } {
                return Next::Return(-1);
            }
            raise(HTTP_R_FAILED_READING_DATA, "OSSL_HTTP_REQ_CTX_nbio");
            return Next::Return(0);
        }
        c.pos = c.buf;
        c.len_to_send = c_long::from(n);
        return Next::Io;
    }
    c.state = FLUSH;
    Next::Go
}

/// Reads the next line of the response's header from the memory BIO and takes it in.
///
/// # Safety
/// `c`'s members are live.
unsafe fn next_line(c: &mut ReqCtx, pass: &mut Pass) -> Next {
    const F: &str = "OSSL_HTTP_REQ_CTX_nbio";
    // SAFETY: its memory BIO.
    let (p, n) = unsafe { mem_data(c.mem) };
    let avail = usize::try_from(n).unwrap_or(0);
    // SAFETY: its `n` unread octets.
    if n <= 0 || !unsafe { core::slice::from_raw_parts(p, avail) }.contains(&b'\n') {
        if n >= c_long::from(c.buf_size) {
            c.state = ERROR;
            return Next::Return(0);
        }
        return Next::Io;
    }
    // SAFETY: its memory BIO; its buffer's `buf_size` octets.
    let n = unsafe { BIO_gets(c.mem, c.buf.cast(), c.buf_size) };
    if n <= 0 {
        // SAFETY: as above.
        if unsafe { should_retry(c.mem) } {
            return Next::Io;
        }
        c.state = ERROR;
        return Next::Return(0);
    }
    if c.state == ERROR_CONTENT {
        pass.resp_len = pass
            .resp_len
            .saturating_add(usize::try_from(n).unwrap_or(0));
        if !check_max_len("error response content", c.max_resp_len, pass.resp_len) {
            return Next::Return(0);
        }
        return Next::Go;
    }
    pass.resp_hdr_lines += 1;
    if c.max_hdr_lines != 0 && c.max_hdr_lines < pass.resp_hdr_lines {
        raise(HTTP_R_RESPONSE_TOO_MANY_HDRLINES, F);
        c.state = ERROR;
        return Next::Return(0);
    }
    if n == c.buf_size {
        raise(HTTP_R_RESPONSE_LINE_TOO_LONG, F);
        c.state = ERROR;
        return Next::Return(0);
    }
    let size = usize::try_from(c.buf_size).unwrap_or(0);
    // SAFETY: its buffer, NUL-terminated by `BIO_gets`.
    let buf = unsafe { core::slice::from_raw_parts_mut(c.buf, size) };
    if c.state == FIRSTLINE {
        pass.status_code = parse_line1(buf, &mut pass.found_keep_alive);
        c.state = match pass.status_code {
            STATUS_OK => HEADERS,
            STATUS_MOVED_PERMANENTLY | STATUS_FOUND if !c.method_post => REDIRECT,
            code => {
                if code == STATUS_MOVED_PERMANENTLY || code == STATUS_FOUND {
                    raise(HTTP_R_REDIRECTION_NOT_ENABLED, F);
                }
                if code < STATUS_NONFATAL_ERROR {
                    HEADERS_ERROR
                } else {
                    HEADERS
                }
            }
        };
        return Next::Go;
    }
    // SAFETY: its members.
    match unsafe { header_line(c, buf, pass) } {
        None => Next::Go,
        Some(-2) => Next::Go,
        Some(r) => Next::Return(r),
    }
}

/// The exchange's steps from the state as it is.
///
/// # Safety
/// `c`'s members are live.
unsafe fn nbio(c: &mut ReqCtx) -> c_int {
    let mut pass = Pass::default();
    c.redirection_url = ptr::null();
    'io: loop {
        if c.state & NOREAD == 0 {
            // SAFETY: its members.
            if let Some(r) = unsafe { read_step(c, pass.resp_len) } {
                return r;
            }
        }
        loop {
            // SAFETY: as above.
            let next = match c.state {
                ADD_HEADERS => {
                    // SAFETY: its memory BIO.
                    if !unsafe { put(c.mem, b"\r\n") } {
                        c.state = ERROR;
                        return 0;
                    }
                    c.state = WRITE_INIT;
                    Next::Go
                }
                WRITE_INIT => {
                    // SAFETY: as above.
                    let (p, n) = unsafe { mem_data(c.mem) };
                    c.pos = p;
                    c.len_to_send = n;
                    c.state = WRITE_HDR1;
                    Next::Go
                }
                // SAFETY: its BIOs.
                WRITE_HDR1 | WRITE_HDR | WRITE_REQ => unsafe { write_step(c) },
                FLUSH => {
                    // SAFETY: its write BIO.
                    if unsafe { BIO_ctrl(c.wbio, BIO_CTRL_FLUSH, 0, ptr::null_mut()) } > 0 {
                        c.state = FIRSTLINE;
                        Next::Io
                    // SAFETY: as above.
                    } else if unsafe { should_retry(c.wbio) } {
                        Next::Return(-1)
                    } else {
                        c.state = ERROR;
                        Next::Return(0)
                    }
                }
                // SAFETY: its members.
                FIRSTLINE | HEADERS | HEADERS_ERROR | REDIRECT | ERROR_CONTENT => unsafe {
                    next_line(c, &mut pass)
                },
                // SAFETY: its memory BIO.
                ASN1_HEADER => unsafe { asn1_header(c) },
                ASN1_CONTENT => {
                    // SAFETY: as above.
                    let (_, n) = unsafe { mem_data(c.mem) };
                    if usize::try_from(n).is_ok_and(|n| n >= c.resp_len) {
                        c.state = ASN1_DONE;
                        Next::Return(1)
                    } else {
                        Next::Io
                    }
                }
                _ => Next::Return(0),
            };
            match next {
                Next::Io => continue 'io,
                Next::Go => {}
                Next::Return(r) => return r,
            }
        }
    }
}

/// Reads what came (raw for ASN.1 content, else a line) into the memory BIO: `Some` to return
/// with that value.
///
/// # Safety
/// `c`'s members are live.
unsafe fn read_step(c: &mut ReqCtx, resp_len: usize) -> Option<c_int> {
    let n = if c.expect_asn1 != 0 && (c.state == ASN1_HEADER || c.state == ASN1_CONTENT) {
        // SAFETY: its read BIO; its buffer's `buf_size` octets.
        unsafe { BIO_read(c.rbio, c.buf.cast(), c.buf_size) }
    } else {
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        // SAFETY: as above.
        let n = unsafe { BIO_gets(c.rbio, c.buf.cast(), c.buf_size) };
        if n == -2 {
            // SAFETY: the mark set above.
            unsafe { ERR_pop_to_mark() };
            // SAFETY: as above.
            unsafe { BIO_get_line(c.rbio, c.buf.cast(), c.buf_size) }
        } else {
            // SAFETY: as above.
            unsafe { ERR_clear_last_mark() };
            n
        }
    };
    if n <= 0 {
        if c.state == ERROR_CONTENT {
            check_set_resp_len("error response content", c, resp_len);
            return Some(0);
        }
        // SAFETY: its read BIO.
        if unsafe { should_retry(c.rbio) } {
            return Some(-1);
        }
        raise(HTTP_R_FAILED_READING_DATA, "OSSL_HTTP_REQ_CTX_nbio");
        return Some(0);
    }
    // SAFETY: its memory BIO; the `n` octets read into its buffer.
    if unsafe { BIO_write(c.mem, c.buf.cast(), n) } != n {
        return Some(0);
    }
    None
}

ffi_export! {
    /// Takes the exchange as far as it can go without blocking: 1 when the response's header
    /// (and ASN.1 content) are in, -1 to retry, 0 on failure or a redirection.
    ///
    /// # Safety
    /// `rctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_nbio(rctx: *mut OSSL_HTTP_REQ_CTX) -> c_int
    where failure = 0, library = ERR_LIB_HTTP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(rctx) }) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, "OSSL_HTTP_REQ_CTX_nbio");
            return 0;
        };
        if c.mem.is_null() || c.wbio.is_null() || c.rbio.is_null() {
            raise(ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, "OSSL_HTTP_REQ_CTX_nbio");
            return 0;
        }
        // SAFETY: a live context.
        unsafe { nbio(c) }
    }
}

ffi_export! {
    /// As [`OSSL_HTTP_REQ_CTX_nbio`], then the ASN.1 content decoded as `it` into `*pval`.
    ///
    /// # Safety
    /// `rctx` is NULL or a live context; `pval` room for a pointer; `it` an item.
    pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_nbio_d2i(rctx: *mut OSSL_HTTP_REQ_CTX, pval: *mut *mut ASN1_VALUE, it: *const ASN1_ITEM) -> c_int
    where failure = 0, library = ERR_LIB_HTTP
    {
        if pval.is_null() {
            raise(ERR_R_PASSED_NULL_PARAMETER, "OSSL_HTTP_REQ_CTX_nbio_d2i");
            return 0;
        }
        // SAFETY: the caller's room.
        unsafe { *pval = ptr::null_mut() };
        // SAFETY: the caller's context.
        let rv = unsafe { OSSL_HTTP_REQ_CTX_nbio(rctx) };
        if rv != 1 {
            return rv;
        }
        // SAFETY: as above.
        let Some(c) = (unsafe { ctx_of(rctx) }) else { return 0 };
        // SAFETY: its memory BIO.
        let (p, n) = unsafe { mem_data(c.mem) };
        let mut q = p;
        // SAFETY: its `n` unread octets; the caller's item.
        let v = unsafe { ASN1_item_d2i(ptr::null_mut(), &raw mut q, n, it) };
        // SAFETY: the caller's room.
        unsafe { *pval = v };
        c_int::from(!v.is_null())
    }
}

ffi_export! {
    /// Runs the exchange to its end, waiting as needed up to the timeout: the BIO with the
    /// response (the memory BIO, or for a stream the read BIO), or NULL.
    ///
    /// # Safety
    /// `rctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_exchange(rctx: *mut OSSL_HTTP_REQ_CTX) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_HTTP
    {
        const F: &str = "OSSL_HTTP_REQ_CTX_exchange";
        if rctx.is_null() {
            raise(ERR_R_PASSED_NULL_PARAMETER, F);
            return ptr::null_mut();
        }
        let rv = loop {
            // SAFETY: the caller's context.
            let rv = unsafe { OSSL_HTTP_REQ_CTX_nbio(rctx) };
            if rv != -1 {
                break rv;
            }
            // SAFETY: as above.
            let Some(c) = (unsafe { ctx_of(rctx) }) else { return ptr::null_mut() };
            // SAFETY: its read BIO.
            if unsafe { BIO_wait(c.rbio, c.max_time, 100) } <= 0 {
                return ptr::null_mut();
            }
        };
        // SAFETY: as above.
        let Some(c) = (unsafe { ctx_of(rctx) }) else { return ptr::null_mut() };
        if rv == 0 {
            if c.redirection_url.is_null() {
                raise(if c.len_to_send > 0 { HTTP_R_ERROR_SENDING } else { HTTP_R_ERROR_RECEIVING }, F);
            }
            return ptr::null_mut();
        }
        if c.state == STREAM { c.rbio } else { c.mem }
    }
}

ffi_export! {
    /// Whether the connection is to be kept alive.
    ///
    /// # Safety
    /// `rctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_HTTP_is_alive(rctx: *const OSSL_HTTP_REQ_CTX) -> c_int
    where failure = 0, library = ERR_LIB_HTTP
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(rctx) }.map_or(0, |c| c_int::from(c.keep_alive != 0))
    }
}

/// `explict_or_default_port`: `port`, or the default when `hostserv` names no service.
///
/// # Safety
/// `hostserv` is a C string; `port` NULL or one.
unsafe fn explicit_or_default_port(
    hostserv: *const c_char,
    port: *const c_char,
    use_ssl: bool,
) -> Option<*const c_char> {
    if !port.is_null() {
        return Some(port);
    }
    let mut service: *mut c_char = ptr::null_mut();
    // SAFETY: the caller's string; room for the service.
    if unsafe {
        BIO_parse_hostserv(
            hostserv,
            ptr::null_mut(),
            &raw mut service,
            BIO_PARSE_PRIO_HOST,
        )
    } == 0
    {
        return None;
    }
    let p = if service.is_null() {
        if use_ssl {
            OSSL_HTTPS_PORT.as_ptr()
        } else {
            OSSL_HTTP_PORT.as_ptr()
        }
    } else {
        ptr::null()
    };
    // SAFETY: from `CRYPTO_malloc`, or NULL.
    unsafe { mem::release(service.cast()) };
    Some(p)
}

/// `http_new_bio`: a connect BIO to the server, or to the proxy.
///
/// # Safety
/// The arguments are NULL or C strings, `server` not NULL.
unsafe fn http_new_bio(
    server: *const c_char,
    server_port: *const c_char,
    use_ssl: bool,
    proxy: *const c_char,
    proxy_port: *const c_char,
) -> *mut BIO {
    let (host, port) = if proxy.is_null() {
        (server, server_port)
    } else {
        (proxy, proxy_port)
    };
    // SAFETY: the caller's strings.
    let port = unsafe { explicit_or_default_port(host, port, use_ssl) };
    // SAFETY: the caller's host.
    let cbio = unsafe { BIO_new_connect(host) };
    if let (false, Some(p)) = (cbio.is_null(), port)
        && !p.is_null()
    {
        // SAFETY: the BIO made here; a C string, which it copies.
        unsafe { BIO_ctrl(cbio, BIO_C_SET_CONNECT, 1, p.cast_mut().cast()) };
    }
    cbio
}

/// `http_req_ctx_new`.
///
/// # Safety
/// The BIOs are live; the strings NULL or C strings.
#[expect(clippy::too_many_arguments, reason = "OpenSSL's")]
unsafe fn http_req_ctx_new(
    free_wbio: bool,
    wbio: *mut BIO,
    rbio: *mut BIO,
    upd_fn: OSSL_HTTP_bio_cb_t,
    arg: *mut c_void,
    use_ssl: bool,
    proxy: *const c_char,
    server: *const c_char,
    port: *const c_char,
    buf_size: c_int,
    overall_timeout: c_int,
) -> *mut OSSL_HTTP_REQ_CTX {
    // SAFETY: the caller's BIOs.
    let rctx = unsafe { OSSL_HTTP_REQ_CTX_new(wbio, rbio, buf_size) };
    // SAFETY: the context made here, or NULL.
    let Some(c) = (unsafe { ctx_of(rctx) }) else {
        return rctx;
    };
    c.free_wbio = free_wbio;
    c.upd_fn = upd_fn;
    c.upd_arg = arg;
    c.use_ssl = use_ssl;
    for (src, dst) in [
        (proxy, &mut c.proxy),
        (server, &mut c.server),
        (port, &mut c.port),
    ] {
        if !src.is_null() {
            // SAFETY: the caller's string.
            *dst = unsafe { strdup(src) };
            if dst.is_null() {
                // SAFETY: made here.
                unsafe { OSSL_HTTP_REQ_CTX_free(rctx) };
                return ptr::null_mut();
            }
        }
    }
    c.max_total_time = if overall_timeout > 0 {
        now() + time_t::from(overall_timeout)
    } else {
        0
    };
    rctx
}

/// The connection's BIO for [`OSSL_HTTP_open`]: `bio`, or one to the server (or proxy).
///
/// # Safety
/// As for [`OSSL_HTTP_open`].
unsafe fn open_bio(
    server: *const c_char,
    port: &mut *const c_char,
    proxy: &mut *const c_char,
    no_proxy: *const c_char,
    use_ssl: bool,
    bio: *mut BIO,
) -> Option<*mut BIO> {
    const F: &str = "OSSL_HTTP_open";
    if !bio.is_null() {
        if !proxy.is_null() || !no_proxy.is_null() {
            raise(ERR_R_PASSED_INVALID_ARGUMENT, F);
            return None;
        }
        return Some(bio);
    }
    if server.is_null() {
        raise(ERR_R_PASSED_NULL_PARAMETER, F);
        return None;
    }
    // SAFETY: the caller's port.
    if unsafe { bytes(*port) }.is_empty() {
        *port = ptr::null();
    }
    // SAFETY: the caller's strings.
    *proxy = unsafe { OSSL_HTTP_adapt_proxy(*proxy, no_proxy, server, c_int::from(use_ssl)) };
    let (mut proxy_host, mut proxy_port): (*mut c_char, *mut c_char) =
        (ptr::null_mut(), ptr::null_mut());
    if !proxy.is_null()
        // SAFETY: a C string; rooms for the parts.
        && unsafe {
            OSSL_HTTP_parse_url(*proxy, ptr::null_mut(), ptr::null_mut(), &raw mut proxy_host, &raw mut proxy_port, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut())
        } == 0
    {
        return None;
    }
    // SAFETY: C strings, or NULL.
    let cbio = unsafe { http_new_bio(server, *port, use_ssl, proxy_host, proxy_port) };
    // SAFETY: from `CRYPTO_malloc`, or NULL.
    unsafe { mem::release(proxy_host.cast()) };
    // SAFETY: as above.
    unsafe { mem::release(proxy_port.cast()) };
    (!cbio.is_null()).then_some(cbio)
}

ffi_export! {
    /// Opens a connection to `server` (directly or through the proxy, unless `no_proxy` lists
    /// it), or takes `bio` (and `rbio`) as one, connected (and set up for TLS by
    /// `bio_update_fn`) within `overall_timeout` seconds: its context, or NULL.
    ///
    /// # Safety
    /// The strings are NULL or C strings; `bio` and `rbio` NULL or live BIOs; `bio_update_fn`
    /// NULL or a callback for `arg`.
    pub unsafe extern "C" fn OSSL_HTTP_open(server: *const c_char, port: *const c_char, proxy: *const c_char, no_proxy: *const c_char, use_ssl: c_int, bio: *mut BIO, rbio: *mut BIO, bio_update_fn: OSSL_HTTP_bio_cb_t, arg: *mut c_void, buf_size: c_int, overall_timeout: c_int) -> *mut OSSL_HTTP_REQ_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_HTTP
    {
        const F: &str = "OSSL_HTTP_open";
        if use_ssl != 0 && bio_update_fn.is_none() {
            raise(HTTP_R_TLS_NOT_ENABLED, F);
            return ptr::null_mut();
        }
        if !rbio.is_null() && (bio.is_null() || bio_update_fn.is_some()) {
            raise(ERR_R_PASSED_INVALID_ARGUMENT, F);
            return ptr::null_mut();
        }
        let (mut port, mut proxy) = (port, proxy);
        // SAFETY: the caller's arguments.
        let Some(mut cbio) = (unsafe { open_bio(server, &mut port, &mut proxy, no_proxy, use_ssl != 0, bio) }) else {
            return ptr::null_mut();
        };
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        let rctx = 'b: {
            // SAFETY: the connection's BIO.
            if rbio.is_null() && unsafe { BIO_do_connect_retry(cbio, overall_timeout, -1) } <= 0 {
                if bio.is_null() {
                    // SAFETY: the BIO opened here.
                    unsafe { BIO_free_all(cbio) };
                }
                break 'b ptr::null_mut();
            }
            if let Some(update) = bio_update_fn {
                let orig = cbio;
                // SAFETY: the application's callback, on the connection.
                cbio = unsafe { update(cbio, arg, 1, c_int::from(use_ssl != 0)) };
                if cbio.is_null() {
                    if bio.is_null() {
                        // SAFETY: as above.
                        unsafe { BIO_free_all(orig) };
                    }
                    break 'b ptr::null_mut();
                }
            }
            let r = if rbio.is_null() { cbio } else { rbio };
            // SAFETY: the BIOs; the strings.
            unsafe { http_req_ctx_new(bio.is_null(), cbio, r, bio_update_fn, arg, use_ssl != 0, proxy, server, port, buf_size, overall_timeout) }
        };
        if rctx.is_null() {
            // SAFETY: the mark set above.
            unsafe { ERR_clear_last_mark() };
        } else {
            // SAFETY: as above.
            unsafe { ERR_pop_to_mark() };
        }
        rctx
    }
}

ffi_export! {
    /// Sets up the request: GET, or POST of `req`; the path (by default `/`), the headers
    /// (and `Host`), and what the response must be: 1, or 0.
    ///
    /// # Safety
    /// `rctx` is NULL or a live context; the strings NULL or C strings; `headers` NULL or a
    /// live list; `req` NULL or a live BIO.
    pub unsafe extern "C" fn OSSL_HTTP_set1_request(rctx: *mut OSSL_HTTP_REQ_CTX, path: *const c_char, headers: *const stack_st_CONF_VALUE, content_type: *const c_char, req: *mut BIO, expected_content_type: *const c_char, expect_asn1: c_int, max_resp_len: usize, timeout: c_int, keep_alive: c_int) -> c_int
    where failure = 0, library = ERR_LIB_HTTP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(rctx) }) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, "OSSL_HTTP_set1_request");
            return 0;
        };
        let use_http_proxy = !c.proxy.is_null() && !c.use_ssl;
        if use_http_proxy && c.server.is_null() {
            raise(ERR_R_PASSED_INVALID_ARGUMENT, "OSSL_HTTP_set1_request");
            return 0;
        }
        c.max_resp_len = max_resp_len;
        let (server, port) = (c.server, c.port);
        let line_server = if use_http_proxy { server } else { ptr::null_mut() };
        // SAFETY: the context; the strings.
        let ok = unsafe { OSSL_HTTP_REQ_CTX_set_request_line(rctx, c_int::from(!req.is_null()), line_server, port, path) } != 0
            // SAFETY: as above.
            && unsafe { add1_headers(rctx, headers, server) }
            // SAFETY: as above.
            && unsafe { OSSL_HTTP_REQ_CTX_set_expected(rctx, expected_content_type, expect_asn1, timeout, keep_alive) } != 0
            // SAFETY: as above.
            && unsafe { set1_content(rctx, content_type, req) };
        c_int::from(ok)
    }
}

/// The error data [`OSSL_HTTP_exchange`] adds to a failure the connection likely caused.
///
/// # Safety
/// `c`'s strings are NULL or its own.
unsafe fn add_connection_data(c: &ReqCtx) {
    // SAFETY: no preconditions.
    let e = unsafe { ERR_peek_error() };
    let lib = err::library_of(e);
    let reason = err::reason_of(e);
    if !(lib == ERR_LIB_SSL
        || lib == ERR_LIB_HTTP
        || (lib == ERR_LIB_BIO
            && (reason == BIO_R_CONNECT_TIMEOUT || reason == BIO_R_CONNECT_ERROR))
        || (lib == ERR_LIB_CMP && reason == CMP_R_POTENTIALLY_INVALID_CERTIFICATE))
    {
        return;
    }
    // SAFETY: its strings.
    let server = unsafe { bytes(c.server) };
    if !server.is_empty() {
        let mut d = format!("server=http{}://", if c.use_ssl { "s" } else { "" }).into_bytes();
        d.extend_from_slice(server);
        if !c.port.is_null() {
            d.push(b':');
            // SAFETY: as above.
            d.extend_from_slice(unsafe { bytes(c.port) });
        }
        // `BIO_snprintf` into 200 octets.
        d.truncate(199);
        err::add_error_data([Some(&d[..])]);
    }
    if !c.proxy.is_null() {
        let mut d = b" proxy=".to_vec();
        // SAFETY: as above.
        d.extend_from_slice(unsafe { bytes(c.proxy) });
        err::add_error_data([Some(&d[..])]);
    }
    if e == 0 {
        let d = if c.use_ssl {
            " peer has disconnected violating the protocol"
        } else {
            " peer has disconnected, likely because it requires the use of TLS"
        };
        err::add_error_data([Some(d.as_bytes())]);
    }
}

ffi_export! {
    /// Runs the exchange: the response's BIO (up-referenced), or NULL with a redirection's URL
    /// in `*redirection_url` (from `CRYPTO_malloc`) when one was followed.
    ///
    /// # Safety
    /// `rctx` is NULL or a live context; `redirection_url` NULL or room for a pointer.
    pub unsafe extern "C" fn OSSL_HTTP_exchange(rctx: *mut OSSL_HTTP_REQ_CTX, redirection_url: *mut *mut c_char) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_HTTP
    {
        if rctx.is_null() {
            raise(ERR_R_PASSED_NULL_PARAMETER, "OSSL_HTTP_exchange");
            return ptr::null_mut();
        }
        // SAFETY: the caller's room, or NULL.
        if let Some(r) = unsafe { redirection_url.as_mut() } {
            *r = ptr::null_mut();
        }
        // SAFETY: the caller's context.
        let mut resp = unsafe { OSSL_HTTP_REQ_CTX_exchange(rctx) };
        // SAFETY: as above.
        let Some(c) = (unsafe { ctx_of(rctx) }) else { return ptr::null_mut() };
        if resp.is_null() {
            if c.redirection_url.is_null() {
                // SAFETY: its strings.
                unsafe { add_connection_data(c) };
            } else {
                // SAFETY: the caller's room, or NULL.
                match unsafe { redirection_url.as_mut() } {
                    None => raise(HTTP_R_REDIRECTION_NOT_ENABLED, "OSSL_HTTP_exchange"),
                    // SAFETY: the URL in its buffer.
                    Some(r) => *r = unsafe { strdup(c.redirection_url) },
                }
            }
        }
        // SAFETY: the response's BIO.
        if !resp.is_null() && unsafe { BIO_up_ref(resp) } == 0 {
            resp = ptr::null_mut();
        }
        resp
    }
}

/// `redirection_ok`.
///
/// # Safety
/// `new_url` is a C string.
unsafe fn redirection_ok(n_redir: c_int, use_ssl: bool, new_url: *const c_char) -> bool {
    if n_redir >= MAX_REDIRECTIONS {
        raise(HTTP_R_TOO_MANY_REDIRECTIONS, "redirection_ok");
        return false;
    }
    // SAFETY: the caller's string.
    let url = unsafe { bytes(new_url) };
    if url.first() == Some(&b'/') {
        return true;
    }
    let mut https = OSSL_HTTPS_NAME.to_bytes().to_vec();
    https.push(b':');
    if use_ssl && !url.starts_with(&https) {
        raise(HTTP_R_REDIRECTION_FROM_HTTPS_TO_HTTP, "redirection_ok");
        return false;
    }
    true
}

ffi_export! {
    /// GETs the URL, following redirections within `timeout` seconds: the response's BIO, or
    /// NULL.
    ///
    /// # Safety
    /// As for [`OSSL_HTTP_open`] and [`OSSL_HTTP_set1_request`]; `url` NULL or a C string.
    pub unsafe extern "C" fn OSSL_HTTP_get(url: *const c_char, proxy: *const c_char, no_proxy: *const c_char, bio: *mut BIO, rbio: *mut BIO, bio_update_fn: OSSL_HTTP_bio_cb_t, arg: *mut c_void, buf_size: c_int, headers: *const stack_st_CONF_VALUE, expected_ct: *const c_char, expect_asn1: c_int, max_resp_len: usize, timeout: c_int) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_HTTP
    {
        if url.is_null() {
            raise(ERR_R_PASSED_NULL_PARAMETER, "OSSL_HTTP_get");
            return ptr::null_mut();
        }
        let max_time = if timeout > 0 { now() + time_t::from(timeout) } else { 0 };
        let mut timeout = timeout;
        // SAFETY: the caller's string.
        let mut current_url = unsafe { strdup(url) };
        if current_url.is_null() {
            return ptr::null_mut();
        }
        let mut n_redirs = 0;
        let mut resp: *mut BIO = ptr::null_mut();
        'url: loop {
            let mut use_ssl: c_int = 0;
            let (mut host, mut port, mut path): (*mut c_char, *mut c_char, *mut c_char) =
                (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
            // SAFETY: a C string; rooms for the parts.
            if unsafe { OSSL_HTTP_parse_url(current_url, &raw mut use_ssl, ptr::null_mut(), &raw mut host, &raw mut port, ptr::null_mut(), &raw mut path, ptr::null_mut(), ptr::null_mut()) } == 0 {
                break;
            }
            // SAFETY: the parts; the caller's arguments.
            let mut rctx = unsafe { OSSL_HTTP_open(host, port, proxy, no_proxy, use_ssl, bio, rbio, bio_update_fn, arg, buf_size, timeout) };
            loop {
                let mut redirection_url: *mut c_char = ptr::null_mut();
                if !rctx.is_null() {
                    // SAFETY: the context; the path; the caller's arguments.
                    if unsafe { OSSL_HTTP_set1_request(rctx, path, headers, ptr::null(), ptr::null_mut(), expected_ct, expect_asn1, max_resp_len, -1, 0) } == 0 {
                        // SAFETY: the context opened here.
                        unsafe { OSSL_HTTP_REQ_CTX_free(rctx) };
                        rctx = ptr::null_mut();
                    } else {
                        // SAFETY: as above; room for the URL.
                        resp = unsafe { OSSL_HTTP_exchange(rctx, &raw mut redirection_url) };
                    }
                }
                // SAFETY: from `CRYPTO_malloc`, or NULL.
                unsafe { mem::release(path.cast()) };
                if resp.is_null() && !redirection_url.is_null() {
                    n_redirs += 1;
                    // SAFETY: a C string.
                    if unsafe { redirection_ok(n_redirs, use_ssl != 0, redirection_url) } && may_still_retry(max_time, &mut timeout) {
                        // SAFETY: the caller's BIO, or NULL.
                        unsafe { reset(bio) };
                        // SAFETY: from `CRYPTO_malloc`.
                        unsafe { mem::release(current_url.cast()) };
                        current_url = redirection_url;
                        // SAFETY: a C string.
                        if unsafe { bytes(redirection_url) }.first() == Some(&b'/') {
                            // SAFETY: as above.
                            path = unsafe { strdup(redirection_url) };
                            if path.is_null() {
                                // SAFETY: each made here.
                                unsafe { release_all(host, port, rctx, current_url) };
                                return ptr::null_mut();
                            }
                            continue;
                        }
                        // SAFETY: from `CRYPTO_malloc`.
                        unsafe { mem::release(host.cast()) };
                        // SAFETY: as above.
                        unsafe { mem::release(port.cast()) };
                        // SAFETY: the context, or NULL.
                        unsafe { OSSL_HTTP_close(rctx, 1) };
                        continue 'url;
                    }
                    // SAFETY: from `CRYPTO_malloc`.
                    unsafe { mem::release(redirection_url.cast()) };
                }
                // SAFETY: as above.
                unsafe { mem::release(host.cast()) };
                // SAFETY: as above.
                unsafe { mem::release(port.cast()) };
                // SAFETY: the context, or NULL.
                if unsafe { OSSL_HTTP_close(rctx, c_int::from(!resp.is_null())) } == 0 {
                    // SAFETY: the response's BIO.
                    unsafe { BIO_free(resp) };
                    resp = ptr::null_mut();
                }
                break 'url;
            }
        }
        // SAFETY: from `CRYPTO_malloc`.
        unsafe { mem::release(current_url.cast()) };
        resp
    }
}

/// Frees what [`OSSL_HTTP_get`] holds when it cannot go on.
///
/// # Safety
/// Each is NULL or its own.
unsafe fn release_all(
    host: *mut c_char,
    port: *mut c_char,
    rctx: *mut OSSL_HTTP_REQ_CTX,
    url: *mut c_char,
) {
    // SAFETY: the caller's guarantee.
    unsafe { mem::release(host.cast()) };
    // SAFETY: as above.
    unsafe { mem::release(port.cast()) };
    // SAFETY: as above.
    unsafe { OSSL_HTTP_close(rctx, 1) };
    // SAFETY: as above.
    unsafe { mem::release(url.cast()) };
}

ffi_export! {
    /// Sends the request (opening the connection unless `*prctx` holds one) and gets the
    /// response: its BIO, or NULL; the context stays in `*prctx` while it's kept alive.
    ///
    /// # Safety
    /// As for [`OSSL_HTTP_open`] and [`OSSL_HTTP_set1_request`]; `prctx` NULL or room for a
    /// pointer, holding NULL or a live context.
    pub unsafe extern "C" fn OSSL_HTTP_transfer(prctx: *mut *mut OSSL_HTTP_REQ_CTX, server: *const c_char, port: *const c_char, path: *const c_char, use_ssl: c_int, proxy: *const c_char, no_proxy: *const c_char, bio: *mut BIO, rbio: *mut BIO, bio_update_fn: OSSL_HTTP_bio_cb_t, arg: *mut c_void, buf_size: c_int, headers: *const stack_st_CONF_VALUE, content_type: *const c_char, req: *mut BIO, expected_ct: *const c_char, expect_asn1: c_int, max_resp_len: usize, timeout: c_int, keep_alive: c_int) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_HTTP
    {
        // SAFETY: the caller's room, or NULL.
        let mut rctx = unsafe { prctx.as_ref() }.map_or(ptr::null_mut(), |p| *p);
        let mut timeout = timeout;
        let mut resp = ptr::null_mut();
        if rctx.is_null() {
            // SAFETY: the caller's arguments.
            rctx = unsafe { OSSL_HTTP_open(server, port, proxy, no_proxy, use_ssl, bio, rbio, bio_update_fn, arg, buf_size, timeout) };
            timeout = -1;
        }
        if !rctx.is_null() {
            // SAFETY: the context; the caller's arguments.
            if unsafe { OSSL_HTTP_set1_request(rctx, path, headers, content_type, req, expected_ct, expect_asn1, max_resp_len, timeout, keep_alive) } != 0 {
                // SAFETY: as above.
                resp = unsafe { OSSL_HTTP_exchange(rctx, ptr::null_mut()) };
            }
            // SAFETY: as above.
            if resp.is_null() || unsafe { OSSL_HTTP_is_alive(rctx) } == 0 {
                // SAFETY: as above.
                if unsafe { OSSL_HTTP_close(rctx, c_int::from(!resp.is_null())) } == 0 {
                    // SAFETY: the response's BIO.
                    unsafe { BIO_free(resp) };
                    resp = ptr::null_mut();
                }
                rctx = ptr::null_mut();
            }
        }
        // SAFETY: the caller's room, or NULL.
        if let Some(p) = unsafe { prctx.as_mut() } {
            *p = rctx;
        }
        resp
    }
}

ffi_export! {
    /// Ends the exchange: the TLS callback's disconnect (whether it succeeded), then frees the
    /// context: 1, or 0 if the callback failed.
    ///
    /// # Safety
    /// `rctx` is NULL or a live context, not used again.
    pub unsafe extern "C" fn OSSL_HTTP_close(rctx: *mut OSSL_HTTP_REQ_CTX, ok: c_int) -> c_int
    where failure = 0, library = ERR_LIB_HTTP
    {
        let mut ret = 1;
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(rctx) }
            && let Some(update) = c.upd_fn
        {
            let (wbio, arg) = (c.wbio, c.upd_arg);
            // SAFETY: the application's callback, on the connection.
            let w = unsafe { update(wbio, arg, 0, ok) };
            ret = c_int::from(!w.is_null());
            // SAFETY: as above, after the callback.
            if let (false, Some(c)) = (w.is_null(), unsafe { ctx_of(rctx) }) {
                c.wbio = w;
            }
        }
        // SAFETY: as above.
        unsafe { OSSL_HTTP_REQ_CTX_free(rctx) };
        ret
    }
}

/// Writes to `bio_err` (when given) what `BIO_printf` would.
///
/// # Safety
/// `bio_err` is NULL or a live BIO.
unsafe fn report(bio_err: *mut BIO, text: &[u8]) {
    if !bio_err.is_null() {
        // SAFETY: the caller's BIO.
        unsafe { put(bio_err, text) };
    }
}

/// `base64encode`: the octets in Base64, from `CRYPTO_malloc`, or NULL.
fn base64encode(buf: &[u8]) -> *mut u8 {
    let outl = buf.len().div_ceil(3) * 4;
    let out = mem::alloc(outl + 1).cast::<u8>();
    if out.is_null() {
        return out;
    }
    let Ok(len) = c_int::try_from(buf.len()) else {
        // SAFETY: allocated above.
        unsafe { mem::release(out.cast()) };
        return ptr::null_mut();
    };
    // SAFETY: room for `outl + 1` octets; the input's `len`.
    let i = unsafe { EVP_EncodeBlock(out, buf.as_ptr(), len) };
    if usize::try_from(i).map_or(true, |i| i > outl) {
        // SAFETY: as above.
        unsafe { mem::release(out.cast()) };
        return ptr::null_mut();
    }
    out
}

/// The `CONNECT` request's text.
///
/// # Safety
/// The arguments are NULL or C strings, `server` and `port` not NULL.
unsafe fn connect_request(
    server: *const c_char,
    port: *const c_char,
    proxyuser: *const c_char,
    proxypass: *const c_char,
) -> Option<Vec<u8>> {
    // SAFETY: the caller's strings.
    let s = unsafe { bytes(server) };
    // SAFETY: as above.
    let p = unsafe { bytes(port) };
    let mut r = b"CONNECT ".to_vec();
    let bracket = s.first() != Some(&b'[') && s.contains(&b':');
    if bracket {
        r.push(b'[');
    }
    r.extend_from_slice(s);
    if bracket {
        r.push(b']');
    }
    r.push(b':');
    r.extend_from_slice(p);
    r.extend_from_slice(b" HTTP/1.0\r\nProxy-Connection: Keep-Alive\r\n");
    if !proxyuser.is_null() {
        // SAFETY: as above.
        let mut auth = unsafe { bytes(proxyuser) }.to_vec();
        auth.push(b':');
        // SAFETY: as above.
        auth.extend_from_slice(unsafe { bytes(proxypass) });
        let enc = base64encode(&auth);
        // SAFETY: the credentials' own octets.
        unsafe { mem::cleanse(auth.as_mut_ptr().cast(), auth.len()) };
        if enc.is_null() {
            return None;
        }
        // SAFETY: a NUL-terminated encoding.
        let e = unsafe { CStr::from_ptr(enc.cast()) }.to_bytes();
        r.extend_from_slice(b"Proxy-Authorization: Basic ");
        r.extend_from_slice(e);
        r.extend_from_slice(b"\r\n");
        let n = e.len();
        // SAFETY: from `CRYPTO_malloc`, its `n` octets cleansed.
        unsafe { mem::release_clean(enc.cast(), n) };
    }
    r.extend_from_slice(b"\r\n");
    Some(r)
}

/// The proxy's answer to `CONNECT`, read from `fbio`: whether it is a 2xx.
///
/// # Safety
/// `fbio` is a live BIO; `bio_err` NULL or a live BIO; `prog` a C string when `bio_err` is
/// given.
unsafe fn connect_answer(
    fbio: *mut BIO,
    mbuf: &mut [u8],
    max_time: time_t,
    bio_err: *mut BIO,
    prog: &[u8],
) -> bool {
    let size = c_int::try_from(mbuf.len()).unwrap_or(0);
    loop {
        // SAFETY: the caller's BIO.
        let rv = unsafe { BIO_wait(fbio, max_time, 100) };
        if rv <= 0 {
            let what: &[u8] = if rv == 0 {
                b"timed out"
            } else {
                b"failed waiting for data"
            };
            // SAFETY: the caller's BIO.
            unsafe { report(bio_err, &[prog, b": HTTP CONNECT ", what, b"\n"].concat()) };
            return false;
        }
        // SAFETY: as above; the buffer's octets.
        let read_len = unsafe { BIO_gets(fbio, mbuf.as_mut_ptr().cast(), size) };
        if read_len < HTTP_LINE1_MINLEN {
            continue;
        }
        let len = c_len(mbuf);
        let line = part(mbuf, 0..len);
        let Some(rest) = line.strip_prefix(b"HTTP/") else {
            raise(
                rustyssl_abi::HTTP_R_HEADER_PARSE_ERROR,
                "OSSL_HTTP_proxy_connect",
            );
            // SAFETY: as above.
            unsafe {
                report(
                    bio_err,
                    &[prog, b": HTTP CONNECT failed, non-HTTP response\n"].concat(),
                )
            };
            return false;
        };
        if !rest.starts_with(b"1.") {
            raise(
                HTTP_R_RECEIVED_WRONG_HTTP_VERSION,
                "OSSL_HTTP_proxy_connect",
            );
            // `%.*s` of `sizeof("1.")`, 3 characters.
            let v: Vec<u8> = rest.iter().copied().take(3).collect();
            // SAFETY: as above.
            unsafe {
                report(
                    bio_err,
                    &[prog, b": HTTP CONNECT failed, bad HTTP version ", &v, b"\n"].concat(),
                )
            };
            return false;
        }
        let mut at = 5 + 3;
        if !part(mbuf, at..len).starts_with(b" 2") {
            if mbuf.get(at).is_some_and(|&c| at < len && is_space(c)) {
                at += 1;
            }
            let mut end = usize::try_from(read_len).unwrap_or(0);
            while end > 0 && is_space(byte(mbuf, end - 1)) {
                end -= 1;
            }
            let reason = mbuf.get(at..end).unwrap_or_default();
            let mut d = b"reason=".to_vec();
            d.extend_from_slice(reason);
            raise_text(HTTP_R_CONNECT_FAILURE, "OSSL_HTTP_proxy_connect", &d);
            // SAFETY: as above.
            unsafe {
                report(
                    bio_err,
                    &[prog, b": HTTP CONNECT failed, reason=", reason, b"\n"].concat(),
                )
            };
            return false;
        }
        return true;
    }
}

ffi_export! {
    /// Asks the HTTP proxy at the other end of `bio` to `CONNECT` to `server` (on port 443 by
    /// default), with Basic authentication for `proxyuser`, waiting up to `timeout` seconds: 1
    /// once it has, or 0 (with what went wrong on `bio_err`, after `prog`).
    ///
    /// # Safety
    /// `bio` is NULL or a live BIO; the strings NULL or C strings; `bio_err` NULL or a live BIO.
    pub unsafe extern "C" fn OSSL_HTTP_proxy_connect(bio: *mut BIO, server: *const c_char, port: *const c_char, proxyuser: *const c_char, proxypass: *const c_char, timeout: c_int, bio_err: *mut BIO, prog: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_HTTP
    {
        const BUF_SIZE: usize = 8 * 1024;
        let max_time = if timeout > 0 { now() + time_t::from(timeout) } else { 0 };
        if bio.is_null() || server.is_null() || (!bio_err.is_null() && prog.is_null()) {
            raise(ERR_R_PASSED_NULL_PARAMETER, "OSSL_HTTP_proxy_connect");
            return 0;
        }
        // SAFETY: the caller's string.
        let port = if unsafe { bytes(port) }.is_empty() { OSSL_HTTPS_PORT.as_ptr() } else { port };
        // SAFETY: as above.
        if !unsafe { no_crlf("server", server) } || !unsafe { no_crlf("port", port) } {
            return 0;
        }
        // SAFETY: as above.
        let prog_b = unsafe { bytes(prog) };
        let mut mbuf = vec![0u8; BUF_SIZE];
        // SAFETY: the built-in method.
        let method = unsafe { BIO_f_buffer() };
        // SAFETY: the built-in method.
        let fbio = unsafe { BIO_new(method) };
        if fbio.is_null() {
            // SAFETY: the caller's BIO, or NULL.
            unsafe { report(bio_err, &[prog_b, b": out of memory"].concat()) };
            return 0;
        }
        // SAFETY: the buffer; the caller's BIO.
        unsafe { BIO_push(fbio, bio) };
        // SAFETY: the caller's strings.
        let ok = match unsafe { connect_request(server, port, proxyuser, proxypass) } {
            None => false,
            Some(r) => {
                // SAFETY: the buffer BIO.
                unsafe { put(fbio, &r) };
                loop {
                    // SAFETY: as above.
                    if unsafe { BIO_ctrl(fbio, BIO_CTRL_FLUSH, 0, ptr::null_mut()) } != 0 || !unsafe { should_retry(fbio) } {
                        break;
                    }
                }
                // SAFETY: as above; the caller's BIO and name.
                let ok = unsafe { connect_answer(fbio, &mut mbuf, max_time, bio_err, prog_b) };
                if ok {
                    let size = c_int::try_from(BUF_SIZE).unwrap_or(0);
                    // The rest of the proxy's header, up to its blank line.
                    // SAFETY: as above; the buffer's octets.
                    while unsafe { BIO_gets(fbio, mbuf.as_mut_ptr().cast(), size) } > 2 {}
                }
                ok
            }
        };
        // SAFETY: as above.
        unsafe { BIO_ctrl(fbio, BIO_CTRL_FLUSH, 0, ptr::null_mut()) };
        // SAFETY: as above.
        unsafe { BIO_pop(fbio) };
        // SAFETY: as above, made here.
        unsafe { BIO_free(fbio) };
        c_int::from(ok)
    }
}

/// `simple_get_asn1`: the URL's ASN.1 content, GETted with no proxy and lines of up to 1024
/// octets, decoded as `it`.
///
/// # Safety
/// `url` is NULL or a C string; `bio` and `rbio` NULL or live BIOs; `it` an item.
unsafe fn simple_get_asn1(
    url: *const c_char,
    bio: *mut BIO,
    rbio: *mut BIO,
    timeout: c_int,
    it: *const ASN1_ITEM,
    max_resp_len: c_int,
) -> *mut c_void {
    let max = usize::try_from(max_resp_len).unwrap_or(0);
    // SAFETY: the caller's arguments.
    let mem = unsafe {
        OSSL_HTTP_get(
            url,
            ptr::null(),
            ptr::null(),
            bio,
            rbio,
            None,
            ptr::null_mut(),
            1024,
            ptr::null(),
            ptr::null(),
            1,
            max,
            timeout,
        )
    };
    // SAFETY: the caller's item; the response's BIO, or NULL.
    let res = unsafe { ASN1_item_d2i_bio(it, mem, ptr::null_mut()) };
    // SAFETY: as above.
    unsafe { BIO_free(mem) };
    res
}

ffi_export! {
    /// The certificate at the URL (GET, DER, at most 100 KiB), or NULL.
    ///
    /// # Safety
    /// `url` is NULL or a C string; `bio` and `rbio` NULL or live BIOs.
    pub unsafe extern "C" fn X509_load_http(url: *const c_char, bio: *mut BIO, rbio: *mut BIO, timeout: c_int) -> *mut X509
    where failure = ptr::null_mut(), library = rustyssl_abi::ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { crate::x509::cert::X509_it() };
        // SAFETY: the caller's arguments; the item.
        unsafe { simple_get_asn1(url, bio, rbio, timeout, it, OSSL_HTTP_DEFAULT_MAX_RESP_LEN) }.cast()
    }
}

ffi_export! {
    /// The CRL at the URL (GET, DER, at most 32 MiB), or NULL.
    ///
    /// # Safety
    /// `url` is NULL or a C string; `bio` and `rbio` NULL or live BIOs.
    pub unsafe extern "C" fn X509_CRL_load_http(url: *const c_char, bio: *mut BIO, rbio: *mut BIO, timeout: c_int) -> *mut X509_CRL
    where failure = ptr::null_mut(), library = rustyssl_abi::ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { crate::x509::crl::X509_CRL_it() };
        // SAFETY: the caller's arguments; the item.
        unsafe { simple_get_asn1(url, bio, rbio, timeout, it, OSSL_HTTP_DEFAULT_MAX_CRL_LEN) }.cast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line1(s: &[u8]) -> (c_int, bool) {
        let mut b = s.to_vec();
        b.push(0);
        let mut keep = false;
        (parse_line1(&mut b, &mut keep), keep)
    }

    #[test]
    fn status_lines_parse_as_openssls() {
        assert_eq!(line1(b"HTTP/1.0 200 OK\r\n"), (200, false));
        assert_eq!(line1(b"HTTP/1.1 302 Found\r\n"), (302, true));
        assert_eq!(line1(b"HTTP/1.1 500 Oops\r\n"), (500, true));
        assert_eq!(line1(b"HTTP/1.0 404 Not Found\r\n"), (404, false));
        // `int retcode = strtoul(...)`: 2^32 + 200 is 200.
        assert_eq!(line1(b"HTTP/1.0 4294967496 OK\r\n"), (200, false));
        assert_eq!(line1(b"HTTP/2 200 OK\r\n").0, 0);
        assert_eq!(line1(b"HTTP/1.0 2x0 OK\r\n").0, 0);
        assert_eq!(line1(b"HTTP/1.0 200").0, 0);
        assert_eq!(line1(b"HTTP/1.0\r\n").0, 0);
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }

    #[test]
    fn c_strings_end_at_their_nul() {
        assert_eq!(c_len(b"ab\0cd"), 2);
        assert_eq!(c_find(b"a:b\0:", 0, b':'), Some(1));
        assert_eq!(c_find(b"ab\0:", 0, b':'), None);
        assert_eq!(c_find(b"ab", 5, b':'), None);
        assert_eq!(part(b"abc", 2..9), b"");
        assert_eq!(byte(b"a", 3), 0);
    }
}
