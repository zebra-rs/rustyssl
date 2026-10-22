//! Fuzzes OCSP on untrusted input: the input decoded as a response and as a request, each
//! encoded again (decoding to the same encoding) and printed; the response's basic response
//! read (its single responses, statuses, validity, responder, and nonce) and verified without
//! a chain; the request's requests and nonce read. Nothing may crash or read out of bounds
//! (ASan).

#![no_main]

use core::ffi::{c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIO, BIO_METHOD, OCSP_BASICRESP, OCSP_REQUEST, OCSP_RESPONSE};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_OCSP_RESPONSE(a: *mut *mut OCSP_RESPONSE, pp: *mut *const c_uchar, len: c_long) -> *mut OCSP_RESPONSE;
    fn i2d_OCSP_RESPONSE(a: *const OCSP_RESPONSE, out: *mut *mut c_uchar) -> c_int;
    fn OCSP_RESPONSE_free(a: *mut OCSP_RESPONSE);
    fn OCSP_RESPONSE_print(bp: *mut BIO, o: *mut OCSP_RESPONSE, flags: c_ulong) -> c_int;
    fn OCSP_response_get1_basic(resp: *mut OCSP_RESPONSE) -> *mut OCSP_BASICRESP;
    fn OCSP_BASICRESP_free(a: *mut OCSP_BASICRESP);
    fn OCSP_resp_count(bs: *mut OCSP_BASICRESP) -> c_int;
    fn OCSP_resp_get0(bs: *mut OCSP_BASICRESP, idx: c_int) -> *mut c_void;
    fn OCSP_single_get0_status(s: *mut c_void, reason: *mut c_int, revtime: *mut *mut c_void, thisupd: *mut *mut c_void, nextupd: *mut *mut c_void) -> c_int;
    fn OCSP_check_validity(thisupd: *mut c_void, nextupd: *mut c_void, nsec: c_long, maxsec: c_long) -> c_int;
    fn OCSP_SINGLERESP_get0_id(s: *const c_void) -> *const c_void;
    fn OCSP_resp_find(bs: *mut OCSP_BASICRESP, id: *const c_void, last: c_int) -> c_int;
    fn OCSP_resp_get0_id(bs: *const OCSP_BASICRESP, pid: *mut *const c_void, pname: *mut *const c_void) -> c_int;
    fn OCSP_basic_verify(bs: *mut OCSP_BASICRESP, certs: *mut c_void, st: *mut c_void, flags: c_ulong) -> c_int;
    fn OCSP_check_nonce(req: *mut OCSP_REQUEST, bs: *mut OCSP_BASICRESP) -> c_int;
    fn d2i_OCSP_REQUEST(a: *mut *mut OCSP_REQUEST, pp: *mut *const c_uchar, len: c_long) -> *mut OCSP_REQUEST;
    fn i2d_OCSP_REQUEST(a: *const OCSP_REQUEST, out: *mut *mut c_uchar) -> c_int;
    fn OCSP_REQUEST_free(a: *mut OCSP_REQUEST);
    fn OCSP_REQUEST_print(bp: *mut BIO, o: *mut OCSP_REQUEST, flags: c_ulong) -> c_int;
    fn OCSP_REQUEST_new() -> *mut OCSP_REQUEST;
    fn OCSP_request_onereq_count(req: *mut OCSP_REQUEST) -> c_int;
    fn OCSP_request_onereq_get0(req: *mut OCSP_REQUEST, i: c_int) -> *mut c_void;
    fn OCSP_onereq_get0_id(one: *mut c_void) -> *mut c_void;
    fn X509_STORE_new() -> *mut c_void;
    fn X509_STORE_free(st: *mut c_void);
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn CRYPTO_free(p: *mut c_void, file: *const core::ffi::c_char, line: c_int);
    fn ERR_clear_error();
}

/// Encodes, decodes, and encodes again: the encodings must agree.
fn round_trip<T>(x: *mut T, i2d: unsafe extern "C" fn(*const T, *mut *mut c_uchar) -> c_int, d2i: unsafe extern "C" fn(*mut *mut T, *mut *const c_uchar, c_long) -> *mut T, free: unsafe extern "C" fn(*mut T)) {
    let mut der: *mut c_uchar = ptr::null_mut();
    // SAFETY: a live object.
    let n = unsafe { i2d(x, &mut der) };
    if n > 0 {
        let mut q = der.cast_const();
        // SAFETY: the encoding's `n` octets.
        let again = unsafe { d2i(ptr::null_mut(), &mut q, c_long::from(n)) };
        // OpenSSL writes an ANY of universal tag 0 (`20 00`, a constructed end-of-contents) as
        // `00 00`, which no decoder takes back; the reference does the same. Any other
        // encoding must decode.
        // SAFETY: the encoding's `n` octets.
        let eoc = unsafe { core::slice::from_raw_parts(der, n as usize) }.windows(2).any(|w| w == [0, 0]);
        assert!(!again.is_null() || eoc, "an encoding that doesn't decode");
        if !again.is_null() {
            let mut der2: *mut c_uchar = ptr::null_mut();
            // SAFETY: as above.
            let n2 = unsafe { i2d(again, &mut der2) };
            assert_eq!(n, n2, "the encoding changed");
            // SAFETY: both encodings' `n` octets.
            let (a, b) = unsafe { (core::slice::from_raw_parts(der, n as usize), core::slice::from_raw_parts(der2, n as usize)) };
            assert_eq!(a, b, "the encoding changed");
            // SAFETY: as above, freed once.
            unsafe { CRYPTO_free(der2.cast(), ptr::null(), 0) };
            // SAFETY: as above.
            unsafe { free(again) };
        }
    }
    // SAFETY: the encoding, or NULL.
    unsafe { CRYPTO_free(der.cast(), ptr::null(), 0) };
}

fuzz_target!(|data: &[u8]| {
    let Ok(len) = c_long::try_from(data.len()) else {
        return;
    };
    // SAFETY: the built-in method.
    let out = unsafe { BIO_new(BIO_s_mem()) };
    let mut p = data.as_ptr();
    // SAFETY: the input's octets.
    let resp = unsafe { d2i_OCSP_RESPONSE(ptr::null_mut(), &mut p, len) };
    if !resp.is_null() {
        round_trip(resp, i2d_OCSP_RESPONSE, d2i_OCSP_RESPONSE, OCSP_RESPONSE_free);
        // SAFETY: live objects.
        unsafe { OCSP_RESPONSE_print(out, resp, 0) };
        // SAFETY: a live response.
        let bs = unsafe { OCSP_response_get1_basic(resp) };
        if !bs.is_null() {
            // SAFETY: a live basic response.
            for i in 0..unsafe { OCSP_resp_count(bs) } {
                // SAFETY: as above.
                let s = unsafe { OCSP_resp_get0(bs, i) };
                let (mut reason, mut rev, mut thisupd, mut nextupd) = (0, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
                // SAFETY: a single response; room for each.
                unsafe { OCSP_single_get0_status(s, &mut reason, &mut rev, &mut thisupd, &mut nextupd) };
                if !thisupd.is_null() {
                    // SAFETY: its times.
                    unsafe { OCSP_check_validity(thisupd, nextupd, 300, -1) };
                }
                // SAFETY: as above.
                let id = unsafe { OCSP_SINGLERESP_get0_id(s) };
                if !id.is_null() {
                    // SAFETY: the response; its CertID.
                    unsafe { OCSP_resp_find(bs, id, -1) };
                }
            }
            let (mut pid, mut pname) = (ptr::null(), ptr::null());
            // SAFETY: as above; room for each.
            unsafe { OCSP_resp_get0_id(bs, &mut pid, &mut pname) };
            // SAFETY: no preconditions.
            let st = unsafe { X509_STORE_new() };
            // SAFETY: as above; an empty store.
            unsafe { OCSP_basic_verify(bs, ptr::null_mut(), st, 0) };
            // SAFETY: the store made here.
            unsafe { X509_STORE_free(st) };
            // SAFETY: no preconditions.
            let req = unsafe { OCSP_REQUEST_new() };
            // SAFETY: live objects.
            unsafe { OCSP_check_nonce(req, bs) };
            // SAFETY: as above, freed once.
            unsafe { OCSP_REQUEST_free(req) };
            // SAFETY: as above.
            unsafe { OCSP_BASICRESP_free(bs) };
        }
        // SAFETY: the object decoded, freed once.
        unsafe { OCSP_RESPONSE_free(resp) };
    }
    let mut p = data.as_ptr();
    // SAFETY: the input's octets.
    let req = unsafe { d2i_OCSP_REQUEST(ptr::null_mut(), &mut p, len) };
    if !req.is_null() {
        round_trip(req, i2d_OCSP_REQUEST, d2i_OCSP_REQUEST, OCSP_REQUEST_free);
        // SAFETY: live objects.
        unsafe { OCSP_REQUEST_print(out, req, 0) };
        // SAFETY: a live request.
        for i in 0..unsafe { OCSP_request_onereq_count(req) } {
            // SAFETY: as above.
            let one = unsafe { OCSP_request_onereq_get0(req, i) };
            // SAFETY: a request of it.
            unsafe { OCSP_onereq_get0_id(one) };
        }
        // SAFETY: the object decoded, freed once.
        unsafe { OCSP_REQUEST_free(req) };
    }
    // SAFETY: the BIO made here.
    unsafe { BIO_free(out) };
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
