//! Fuzzes time stamping on untrusted input: the input decoded as a response, a request, a
//! TSTInfo, and a PKCS #7 token, each encoded again (decoding to the same encoding) and
//! printed; the request turned into a verification context and answered by a TSA with no
//! signer; the response and the token verified against it with an empty store. Nothing may
//! crash or read out of bounds (ASan).

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{
    BIO, BIO_METHOD, EVP_MD, PKCS7, TS_REQ, TS_RESP, TS_RESP_CTX, TS_TST_INFO, TS_VERIFY_CTX,
    TS_VFY_ALL_IMPRINT,
};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_TS_RESP(a: *mut *mut TS_RESP, pp: *mut *const c_uchar, len: c_long) -> *mut TS_RESP;
    fn i2d_TS_RESP(a: *const TS_RESP, out: *mut *mut c_uchar) -> c_int;
    fn TS_RESP_free(a: *mut TS_RESP);
    fn TS_RESP_print_bio(bio: *mut BIO, a: *mut TS_RESP) -> c_int;
    fn d2i_TS_REQ(a: *mut *mut TS_REQ, pp: *mut *const c_uchar, len: c_long) -> *mut TS_REQ;
    fn i2d_TS_REQ(a: *const TS_REQ, out: *mut *mut c_uchar) -> c_int;
    fn TS_REQ_free(a: *mut TS_REQ);
    fn TS_REQ_print_bio(bio: *mut BIO, a: *mut TS_REQ) -> c_int;
    fn d2i_TS_TST_INFO(a: *mut *mut TS_TST_INFO, pp: *mut *const c_uchar, len: c_long) -> *mut TS_TST_INFO;
    fn i2d_TS_TST_INFO(a: *const TS_TST_INFO, out: *mut *mut c_uchar) -> c_int;
    fn TS_TST_INFO_free(a: *mut TS_TST_INFO);
    fn TS_TST_INFO_print_bio(bio: *mut BIO, a: *mut TS_TST_INFO) -> c_int;
    fn d2i_PKCS7(a: *mut *mut PKCS7, pp: *mut *const c_uchar, len: c_long) -> *mut PKCS7;
    fn PKCS7_free(a: *mut PKCS7);
    fn PKCS7_to_TS_TST_INFO(token: *mut PKCS7) -> *mut TS_TST_INFO;
    fn TS_REQ_to_TS_VERIFY_CTX(req: *mut TS_REQ, ctx: *mut TS_VERIFY_CTX) -> *mut TS_VERIFY_CTX;
    fn TS_VERIFY_CTX_new() -> *mut TS_VERIFY_CTX;
    fn TS_VERIFY_CTX_set_flags(ctx: *mut TS_VERIFY_CTX, f: c_int) -> c_int;
    fn TS_VERIFY_CTX_add_flags(ctx: *mut TS_VERIFY_CTX, f: c_int) -> c_int;
    fn TS_VERIFY_CTX_set0_store(ctx: *mut TS_VERIFY_CTX, s: *mut c_void) -> c_int;
    fn TS_VERIFY_CTX_set0_data(ctx: *mut TS_VERIFY_CTX, b: *mut BIO) -> c_int;
    fn TS_VERIFY_CTX_free(ctx: *mut TS_VERIFY_CTX);
    fn TS_RESP_verify_response(ctx: *mut TS_VERIFY_CTX, response: *mut TS_RESP) -> c_int;
    fn TS_RESP_verify_token(ctx: *mut TS_VERIFY_CTX, token: *mut PKCS7) -> c_int;
    fn TS_RESP_CTX_new() -> *mut TS_RESP_CTX;
    fn TS_RESP_CTX_free(ctx: *mut TS_RESP_CTX);
    fn TS_RESP_CTX_add_md(ctx: *mut TS_RESP_CTX, md: *const EVP_MD) -> c_int;
    fn TS_RESP_CTX_set_def_policy(ctx: *mut TS_RESP_CTX, policy: *const c_void) -> c_int;
    fn TS_RESP_create_response(ctx: *mut TS_RESP_CTX, req_bio: *mut BIO) -> *mut TS_RESP;
    fn OBJ_txt2obj(s: *const c_char, no_name: c_int) -> *mut c_void;
    fn ASN1_OBJECT_free(a: *mut c_void);
    fn EVP_sha256() -> *const EVP_MD;
    fn X509_STORE_new() -> *mut c_void;
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
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
        assert!(!again.is_null(), "an encoding that doesn't decode");
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
    // SAFETY: the encoding, or NULL.
    unsafe { CRYPTO_free(der.cast(), ptr::null(), 0) };
}

/// A verification context for the request (or with every check but the TSA's name), with an
/// empty store and the input as the data.
fn verify_ctx(req: *mut TS_REQ, data: &[u8]) -> *mut TS_VERIFY_CTX {
    let ctx = if req.is_null() {
        // SAFETY: no preconditions.
        let c = unsafe { TS_VERIFY_CTX_new() };
        // SAFETY: a live context.
        unsafe { TS_VERIFY_CTX_set_flags(c, (TS_VFY_ALL_IMPRINT & !rustyssl_abi::TS_VFY_TSA_NAME) as c_int) };
        c
    } else {
        // SAFETY: a live request; a new context.
        unsafe { TS_REQ_to_TS_VERIFY_CTX(req, ptr::null_mut()) }
    };
    if ctx.is_null() {
        return ctx;
    }
    // SAFETY: a live context.
    unsafe { TS_VERIFY_CTX_add_flags(ctx, (rustyssl_abi::TS_VFY_SIGNATURE | rustyssl_abi::TS_VFY_DATA) as c_int) };
    // SAFETY: as above; a new store it takes.
    unsafe { TS_VERIFY_CTX_set0_store(ctx, X509_STORE_new()) };
    let len = c_int::try_from(data.len()).unwrap_or(0);
    // SAFETY: as above; a BIO over the input, which outlives the context.
    unsafe { TS_VERIFY_CTX_set0_data(ctx, BIO_new_mem_buf(data.as_ptr().cast(), len)) };
    ctx
}

fuzz_target!(|data: &[u8]| {
    let Ok(len) = c_long::try_from(data.len()) else {
        return;
    };
    // SAFETY: the built-in method.
    let out = unsafe { BIO_new(BIO_s_mem()) };

    let mut p = data.as_ptr();
    // SAFETY: the input's octets.
    let req = unsafe { d2i_TS_REQ(ptr::null_mut(), &mut p, len) };
    if !req.is_null() {
        round_trip(req, i2d_TS_REQ, d2i_TS_REQ, TS_REQ_free);
        // SAFETY: live objects.
        unsafe { TS_REQ_print_bio(out, req) };
    }

    // A TSA with no signer: the request's checks run, the signing fails.
    // SAFETY: no preconditions.
    let tsa = unsafe { TS_RESP_CTX_new() };
    // SAFETY: a NUL-terminated OID.
    let policy = unsafe { OBJ_txt2obj(c"1.2.3.4.1".as_ptr(), 1) };
    // SAFETY: a live context; the object.
    unsafe { TS_RESP_CTX_set_def_policy(tsa, policy) };
    // SAFETY: as above; a built-in digest.
    unsafe { TS_RESP_CTX_add_md(tsa, EVP_sha256()) };
    let n = c_int::try_from(data.len()).unwrap_or(0);
    // SAFETY: the input's octets.
    let bio = unsafe { BIO_new_mem_buf(data.as_ptr().cast(), n) };
    // SAFETY: the context; the BIO.
    let answer = unsafe { TS_RESP_create_response(tsa, bio) };
    if !answer.is_null() {
        // SAFETY: live objects.
        unsafe { TS_RESP_print_bio(out, answer) };
        // SAFETY: the response made here.
        unsafe { TS_RESP_free(answer) };
    }
    // SAFETY: each made here.
    unsafe { BIO_free(bio) };
    // SAFETY: as above.
    unsafe { ASN1_OBJECT_free(policy) };
    // SAFETY: as above.
    unsafe { TS_RESP_CTX_free(tsa) };

    let mut p = data.as_ptr();
    // SAFETY: the input's octets.
    let resp = unsafe { d2i_TS_RESP(ptr::null_mut(), &mut p, len) };
    if !resp.is_null() {
        round_trip(resp, i2d_TS_RESP, d2i_TS_RESP, TS_RESP_free);
        // SAFETY: live objects.
        unsafe { TS_RESP_print_bio(out, resp) };
        let ctx = verify_ctx(req, data);
        if !ctx.is_null() {
            // SAFETY: live objects.
            unsafe { TS_RESP_verify_response(ctx, resp) };
            // SAFETY: the context made here.
            unsafe { TS_VERIFY_CTX_free(ctx) };
        }
        // SAFETY: the object decoded, freed once.
        unsafe { TS_RESP_free(resp) };
    }

    let mut p = data.as_ptr();
    // SAFETY: the input's octets.
    let tst = unsafe { d2i_TS_TST_INFO(ptr::null_mut(), &mut p, len) };
    if !tst.is_null() {
        round_trip(tst, i2d_TS_TST_INFO, d2i_TS_TST_INFO, TS_TST_INFO_free);
        // SAFETY: live objects.
        unsafe { TS_TST_INFO_print_bio(out, tst) };
        // SAFETY: the object decoded, freed once.
        unsafe { TS_TST_INFO_free(tst) };
    }

    let mut p = data.as_ptr();
    // SAFETY: the input's octets.
    let token = unsafe { d2i_PKCS7(ptr::null_mut(), &mut p, len) };
    if !token.is_null() {
        // SAFETY: a live object.
        let t = unsafe { PKCS7_to_TS_TST_INFO(token) };
        if !t.is_null() {
            // SAFETY: live objects.
            unsafe { TS_TST_INFO_print_bio(out, t) };
            // SAFETY: the object made here.
            unsafe { TS_TST_INFO_free(t) };
        }
        let ctx = verify_ctx(ptr::null_mut(), data);
        if !ctx.is_null() {
            // SAFETY: live objects.
            unsafe { TS_RESP_verify_token(ctx, token) };
            // SAFETY: the context made here.
            unsafe { TS_VERIFY_CTX_free(ctx) };
        }
        // SAFETY: the object decoded, freed once.
        unsafe { PKCS7_free(token) };
    }

    if !req.is_null() {
        // SAFETY: the object decoded, freed once.
        unsafe { TS_REQ_free(req) };
    }
    // SAFETY: the BIO made here.
    unsafe { BIO_free(out) };
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
