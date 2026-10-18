//! Fuzzes CMP on untrusted input: the input decoded as a message, a header, a PKIStatusInfo,
//! and controls, each encoded again (decoding to the same encoding); the message's status text
//! printed; the message validated by a client with a shared secret (the MAC path); and the
//! message given to a server with no handlers, which answers it with an error or a refusal.
//! Nothing may crash or read out of bounds (ASan).

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{
    OSSL_CMP_ATAVS, OSSL_CMP_CTX, OSSL_CMP_MSG, OSSL_CMP_PKIHEADER, OSSL_CMP_PKISI,
    OSSL_CMP_SRV_CTX, OSSL_LIB_CTX,
};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_OSSL_CMP_MSG(a: *mut *mut OSSL_CMP_MSG, pp: *mut *const c_uchar, len: c_long) -> *mut OSSL_CMP_MSG;
    fn i2d_OSSL_CMP_MSG(a: *const OSSL_CMP_MSG, out: *mut *mut c_uchar) -> c_int;
    fn OSSL_CMP_MSG_free(a: *mut OSSL_CMP_MSG);
    fn OSSL_CMP_MSG_get_bodytype(msg: *const OSSL_CMP_MSG) -> c_int;
    fn OSSL_CMP_MSG_dup(msg: *const OSSL_CMP_MSG) -> *mut OSSL_CMP_MSG;
    fn d2i_OSSL_CMP_PKIHEADER(a: *mut *mut OSSL_CMP_PKIHEADER, pp: *mut *const c_uchar, len: c_long) -> *mut OSSL_CMP_PKIHEADER;
    fn i2d_OSSL_CMP_PKIHEADER(a: *const OSSL_CMP_PKIHEADER, out: *mut *mut c_uchar) -> c_int;
    fn OSSL_CMP_PKIHEADER_free(a: *mut OSSL_CMP_PKIHEADER);
    fn d2i_OSSL_CMP_PKISI(a: *mut *mut OSSL_CMP_PKISI, pp: *mut *const c_uchar, len: c_long) -> *mut OSSL_CMP_PKISI;
    fn i2d_OSSL_CMP_PKISI(a: *const OSSL_CMP_PKISI, out: *mut *mut c_uchar) -> c_int;
    fn OSSL_CMP_PKISI_free(a: *mut OSSL_CMP_PKISI);
    fn OSSL_CMP_snprint_PKIStatusInfo(si: *const OSSL_CMP_PKISI, buf: *mut c_char, bufsize: usize) -> *mut c_char;
    fn d2i_OSSL_CMP_ATAVS(a: *mut *mut OSSL_CMP_ATAVS, pp: *mut *const c_uchar, len: c_long) -> *mut OSSL_CMP_ATAVS;
    fn i2d_OSSL_CMP_ATAVS(a: *const OSSL_CMP_ATAVS, out: *mut *mut c_uchar) -> c_int;
    fn OSSL_CMP_ATAVS_free(a: *mut OSSL_CMP_ATAVS);
    fn OSSL_CMP_CTX_new(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut OSSL_CMP_CTX;
    fn OSSL_CMP_CTX_free(ctx: *mut OSSL_CMP_CTX);
    fn OSSL_CMP_CTX_set1_secretValue(ctx: *mut OSSL_CMP_CTX, sec: *const c_uchar, len: c_int) -> c_int;
    fn OSSL_CMP_validate_msg(ctx: *mut OSSL_CMP_CTX, msg: *const OSSL_CMP_MSG) -> c_int;
    fn OSSL_CMP_SRV_CTX_new(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut OSSL_CMP_SRV_CTX;
    fn OSSL_CMP_SRV_CTX_free(srv_ctx: *mut OSSL_CMP_SRV_CTX);
    fn OSSL_CMP_SRV_CTX_get0_cmp_ctx(srv_ctx: *const OSSL_CMP_SRV_CTX) -> *mut OSSL_CMP_CTX;
    fn OSSL_CMP_SRV_CTX_set_accept_unprotected(srv_ctx: *mut OSSL_CMP_SRV_CTX, val: c_int) -> c_int;
    fn OSSL_CMP_SRV_process_request(srv_ctx: *mut OSSL_CMP_SRV_CTX, req: *const OSSL_CMP_MSG) -> *mut OSSL_CMP_MSG;
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
        if again.is_null() {
            // An ANY of universal tag 0 (an end-of-contents octet pair, `20 00`) re-encodes as
            // `00 00`, which no decoder takes: the reference does the same.
            // SAFETY: the encoding.
            unsafe { CRYPTO_free(der.cast(), ptr::null(), 0) };
            return;
        }
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

/// Decodes the input as a `T` and, if it is one, round-trips it; returns it (or NULL).
fn decode<T>(data: &[u8], i2d: unsafe extern "C" fn(*const T, *mut *mut c_uchar) -> c_int, d2i: unsafe extern "C" fn(*mut *mut T, *mut *const c_uchar, c_long) -> *mut T, free: unsafe extern "C" fn(*mut T)) -> *mut T {
    let Ok(len) = c_long::try_from(data.len()) else {
        return ptr::null_mut();
    };
    let mut p = data.as_ptr();
    // SAFETY: the input's octets.
    let x = unsafe { d2i(ptr::null_mut(), &mut p, len) };
    if !x.is_null() {
        round_trip(x, i2d, d2i, free);
    }
    x
}

fuzz_target!(|data: &[u8]| {
    let msg = decode(data, i2d_OSSL_CMP_MSG, d2i_OSSL_CMP_MSG, OSSL_CMP_MSG_free);
    if !msg.is_null() {
        // SAFETY: a live message, for each call.
        unsafe { OSSL_CMP_MSG_get_bodytype(msg) };
        // SAFETY: as above.
        let copy = unsafe { OSSL_CMP_MSG_dup(msg) };
        // SAFETY: the copy, or NULL.
        unsafe { OSSL_CMP_MSG_free(copy) };

        // A client knowing a shared secret: a MAC-protected message is checked, others fail.
        // SAFETY: the default library context.
        let ctx = unsafe { OSSL_CMP_CTX_new(ptr::null_mut(), ptr::null()) };
        if !ctx.is_null() {
            let secret = b"fuzz secret";
            // SAFETY: a live context; the secret's octets.
            unsafe { OSSL_CMP_CTX_set1_secretValue(ctx, secret.as_ptr(), 11) };
            // SAFETY: live objects.
            unsafe { OSSL_CMP_validate_msg(ctx, msg) };
            // SAFETY: made here.
            unsafe { OSSL_CMP_CTX_free(ctx) };
        }

        // A server with no handlers: every request is refused with an error message.
        // SAFETY: as above.
        let srv = unsafe { OSSL_CMP_SRV_CTX_new(ptr::null_mut(), ptr::null()) };
        if !srv.is_null() {
            // SAFETY: a live server context.
            unsafe { OSSL_CMP_SRV_CTX_set_accept_unprotected(srv, 1) };
            // SAFETY: as above.
            let sctx = unsafe { OSSL_CMP_SRV_CTX_get0_cmp_ctx(srv) };
            // SAFETY: its client context.
            unsafe { OSSL_CMP_CTX_set1_secretValue(sctx, b"s".as_ptr(), 1) };
            // SAFETY: live objects.
            let rsp = unsafe { OSSL_CMP_SRV_process_request(srv, msg) };
            // SAFETY: the response, or NULL.
            unsafe { OSSL_CMP_MSG_free(rsp) };
            // SAFETY: made here.
            unsafe { OSSL_CMP_SRV_CTX_free(srv) };
        }
        // SAFETY: the message decoded, freed once.
        unsafe { OSSL_CMP_MSG_free(msg) };
    }
    let hdr = decode(data, i2d_OSSL_CMP_PKIHEADER, d2i_OSSL_CMP_PKIHEADER, OSSL_CMP_PKIHEADER_free);
    // SAFETY: decoded here, or NULL.
    unsafe { OSSL_CMP_PKIHEADER_free(hdr) };
    let si = decode(data, i2d_OSSL_CMP_PKISI, d2i_OSSL_CMP_PKISI, OSSL_CMP_PKISI_free);
    if !si.is_null() {
        let mut buf = [0 as c_char; 512];
        // SAFETY: a live PKIStatusInfo; the buffer's room.
        unsafe { OSSL_CMP_snprint_PKIStatusInfo(si, buf.as_mut_ptr(), buf.len()) };
        // SAFETY: decoded here.
        unsafe { OSSL_CMP_PKISI_free(si) };
    }
    let atavs = decode(data, i2d_OSSL_CMP_ATAVS, d2i_OSSL_CMP_ATAVS, OSSL_CMP_ATAVS_free);
    // SAFETY: decoded here, or NULL.
    unsafe { OSSL_CMP_ATAVS_free(atavs) };
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
