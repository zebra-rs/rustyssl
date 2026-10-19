//! OpenSSL 3.6's OCSP responses on a connection (`s->ext.ocsp.resp_ex`): a stack of parsed
//! `OCSP_RESPONSE`s, one per certificate of the chain from the leaf, beside the single DER
//! response (`s->ext.ocsp.resp`) that `SSL_set_tlsext_status_ocsp_resp` takes and
//! `SSL_get_tlsext_status_ocsp_resp` returns (re-encoded from the first parsed one).
//!
//! A server staples, for each certificate, the response at its index when it's for that
//! certificate (its serial number and issuer name hash; a self-signed certificate gets none,
//! and a response that isn't successful or has no basic response is sent as it is). A client
//! keeps what it receives, parsed, and TLS 1.3 verification checks the chain against them
//! (`X509_V_FLAG_OCSP_RESP_CHECK`).

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_INTEGER, ASN1_OBJECT, ASN1_OCTET_STRING, EVP_MAX_MD_SIZE, OCSP_RESPONSE,
    OCSP_RESPONSE_STATUS_SUCCESSFUL, SSL, SSL_CTRL_GET_CHAIN_CERTS, X509, stack_st_OCSP_RESPONSE,
};

use super::conn::SslState;
use super::ctx::Ctx;
use crate::ocsp::asn::{
    OCSP_BASICRESP_free, OCSP_RESPONSE_free, d2i_OCSP_RESPONSE, i2d_OCSP_RESPONSE,
};
use crate::ocsp::cl::{
    OCSP_SINGLERESP_get0_id, OCSP_resp_count, OCSP_resp_get0, OCSP_response_get1_basic,
    OCSP_response_status,
};
use crate::ocsp::srv::OCSP_id_get0_info;
use crate::stack::{
    OPENSSL_sk_insert, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value,
};

/// `OCSP_RESPONSE_free` as a stack's free function.
unsafe extern "C" fn free_response(p: *mut c_void) {
    // SAFETY: an element of a stack of responses.
    unsafe { OCSP_RESPONSE_free(p.cast()) };
}

/// Frees the connection's parsed responses.
///
/// # Safety
/// `st.ocsp_resp_ex` is NULL or the connection's own stack.
pub(crate) unsafe fn free_ex(st: &mut SslState) {
    let sk = core::mem::replace(&mut st.ocsp_resp_ex, ptr::null_mut());
    // SAFETY: the caller's guarantee.
    unsafe { OPENSSL_sk_pop_free(sk.cast(), Some(free_response)) };
}

/// Frees the single DER response.
fn free_resp(st: &mut SslState) {
    let old = core::mem::replace(&mut st.ocsp_resp, ptr::null_mut());
    st.ocsp_resp_len = 0;
    // SAFETY: the response the connection owned (C memory), or NULL.
    unsafe { crate::mem::release(old.cast()) };
}

/// The response `der` decodes to, or NULL.
fn parse(der: &[u8]) -> *mut OCSP_RESPONSE {
    let Ok(len) = c_long::try_from(der.len()) else {
        return ptr::null_mut();
    };
    let mut p = der.as_ptr();
    // SAFETY: our octets.
    unsafe { d2i_OCSP_RESPONSE(ptr::null_mut(), &raw mut p, len) }
}

/// Whether `der` decodes as an OCSP response, raising nothing.
pub(crate) fn decodes(der: &[u8]) -> bool {
    // SAFETY: no preconditions.
    unsafe { crate::err::ERR_set_mark() };
    let r = parse(der);
    // SAFETY: the mark set above.
    unsafe { crate::err::ERR_pop_to_mark() };
    // SAFETY: decoded here, or NULL.
    unsafe { OCSP_RESPONSE_free(r) };
    !r.is_null()
}

/// `SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP`: takes `parg` (`larg` octets, C memory), and
/// keeps it parsed as the only response if it decodes (else none). 1.
///
/// # Safety
/// `parg` is NULL or `larg` octets of C memory the connection now owns.
pub(crate) unsafe fn set_resp(st: &mut SslState, parg: *mut c_void, larg: c_long) -> c_long {
    free_resp(st);
    // SAFETY: the connection's own stack.
    unsafe { free_ex(st) };
    if parg.is_null() {
        return 1;
    }
    // SAFETY: no preconditions.
    let sk = unsafe { OPENSSL_sk_new_null() };
    if sk.is_null() {
        return 0;
    }
    let len = usize::try_from(larg).unwrap_or(0);
    // SAFETY: the caller's `larg` octets.
    let der = unsafe { crate::ffi::bytes(parg.cast::<u8>().cast_const(), len) }.unwrap_or_default();
    let r = parse(der);
    if !r.is_null() {
        // SAFETY: the stack made above; the response decoded.
        unsafe { OPENSSL_sk_insert(sk, r.cast(), 0) };
    }
    st.ocsp_resp_ex = sk.cast();
    st.ocsp_resp = parg.cast();
    st.ocsp_resp_len = len;
    1
}

/// `SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP`: the first response re-encoded (kept as the
/// single one), its length; else NULL and -1.
///
/// # Safety
/// `parg` is a writable `unsigned char **`.
pub(crate) unsafe fn get_resp(st: &mut SslState, parg: *mut c_void) -> c_long {
    let out = parg.cast::<*mut u8>();
    // SAFETY: the caller's slot.
    unsafe { out.write(ptr::null_mut()) };
    // SAFETY: the connection's own stack, or NULL.
    let r = unsafe { OPENSSL_sk_value(st.ocsp_resp_ex.cast(), 0) }.cast::<OCSP_RESPONSE>();
    if r.is_null() {
        return -1;
    }
    let mut p: *mut c_uchar = ptr::null_mut();
    // SAFETY: a parsed response; a new encoding.
    let n = unsafe { i2d_OCSP_RESPONSE(r, &raw mut p) };
    if n <= 0 {
        return -1;
    }
    free_resp(st);
    st.ocsp_resp = p;
    st.ocsp_resp_len = usize::try_from(n).unwrap_or(0);
    // SAFETY: as above.
    unsafe { out.write(p) };
    c_long::from(n)
}

/// `SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP_EX`: the parsed responses (the connection's), and
/// their count (-1 for none).
///
/// # Safety
/// `parg` is a writable `STACK_OF(OCSP_RESPONSE) **`.
pub(crate) unsafe fn get_ex(st: &SslState, parg: *mut c_void) -> c_long {
    // SAFETY: the caller's slot.
    unsafe {
        parg.cast::<*mut stack_st_OCSP_RESPONSE>()
            .write(st.ocsp_resp_ex)
    };
    // SAFETY: the connection's own stack, or NULL.
    c_long::from(unsafe { OPENSSL_sk_num(st.ocsp_resp_ex.cast()) })
}

/// `SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP_EX`: takes `parg` as the responses, dropping the
/// single one. 1.
///
/// # Safety
/// `parg` is NULL or a stack of responses the connection now owns.
pub(crate) unsafe fn set_ex(st: &mut SslState, parg: *mut c_void) -> c_long {
    free_resp(st);
    // SAFETY: the connection's own stack.
    unsafe { free_ex(st) };
    st.ocsp_resp_ex = parg.cast();
    1
}

/// A client's received responses, parsed (`tls_process_cert_status_body`), replacing what
/// the connection held; the single response is dropped.
///
/// # Safety
/// The connection's stack and response are its own.
pub(crate) unsafe fn set_received(st: &mut SslState, received: &[Vec<u8>]) {
    free_resp(st);
    // SAFETY: the caller's guarantee.
    unsafe { free_ex(st) };
    if received.is_empty() {
        return;
    }
    // SAFETY: no preconditions.
    let sk = unsafe { OPENSSL_sk_new_null() };
    if sk.is_null() {
        return;
    }
    for der in received {
        let r = parse(der);
        if !r.is_null() {
            // SAFETY: the stack made above; a response decoded here, appended.
            unsafe { OPENSSL_sk_insert(sk, r.cast(), c_int::MAX) };
        }
    }
    st.ocsp_resp_ex = sk.cast();
}

/// The server's answer to the status callback: whether any response was set (a status is
/// promised), and for each certificate (the leaf, then the chain certificates) the response
/// to staple (`ossl_get_ocsp_response`).
///
/// # Safety
/// `s` is the live connection; `st` is its state, not locked.
pub(crate) unsafe fn server_responses(s: *mut SSL) -> (bool, Vec<Option<Vec<u8>>>) {
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { super::conn::ssl(s) }) else {
        return (false, Vec::new());
    };
    let (list, ctx) = {
        let st = x.state();
        // SAFETY: the connection's own context.
        (st.ocsp_resp_ex, unsafe { super::conn::ctx_of(&st) })
    };
    let Some(ctx) = ctx else {
        return (false, Vec::new());
    };
    // SAFETY: the connection's stack, or NULL.
    let num = unsafe { OPENSSL_sk_num(list.cast()) };
    if num <= 0 {
        return (false, Vec::new());
    }
    let mut chain: *mut c_void = ptr::null_mut();
    // SAFETY: the connection; a place for its chain.
    unsafe {
        super::conn::rustyssl_private_SSL_ctrl(
            s,
            SSL_CTRL_GET_CHAIN_CERTS,
            0,
            (&raw mut chain).cast(),
        )
    };
    // SAFETY: the connection.
    let leaf = unsafe { super::keys::rustyssl_private_SSL_get_certificate(s) };
    // SAFETY: the chain, or NULL.
    let chain_len = unsafe { OPENSSL_sk_num(chain.cast()) }.max(0);
    let mut out = Vec::new();
    for idx in 0..=chain_len {
        let x = if idx == 0 {
            leaf
        } else {
            // SAFETY: an index within the chain.
            unsafe { OPENSSL_sk_value(chain.cast(), idx - 1) }.cast::<X509>()
        };
        // SAFETY: as above.
        let resp = unsafe { OPENSSL_sk_value(list.cast(), idx) }.cast::<OCSP_RESPONSE>();
        // SAFETY: a live certificate and response, or NULL.
        out.push(unsafe { response_for(ctx, x, resp) });
    }
    (true, out)
}

/// `ossl_get_ocsp_response`'s choice for certificate `x`: `resp` encoded, if it applies.
///
/// # Safety
/// `x` and `resp` are NULL or live.
unsafe fn response_for(ctx: &Ctx, x: *mut X509, resp: *mut OCSP_RESPONSE) -> Option<Vec<u8>> {
    if x.is_null() || resp.is_null() {
        return None;
    }
    // SAFETY: a live certificate.
    if unsafe { crate::x509::purpose::X509_self_signed(x, 0) } == 1 {
        return None;
    }
    // SAFETY: a live response.
    if unsafe { OCSP_response_status(resp) } == OCSP_RESPONSE_STATUS_SUCCESSFUL {
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_set_mark() };
        // SAFETY: as above.
        let matches = unsafe { matches(ctx, x, resp) };
        // SAFETY: the mark set above.
        unsafe { crate::err::ERR_pop_to_mark() };
        if !matches {
            return None;
        }
    }
    let mut p: *mut c_uchar = ptr::null_mut();
    // SAFETY: a live response; a new encoding.
    let n = unsafe { i2d_OCSP_RESPONSE(resp, &raw mut p) };
    let der = usize::try_from(n)
        .ok()
        // SAFETY: the encoding's octets.
        .and_then(|n| unsafe { crate::ffi::bytes(p, n) })
        .map(<[u8]>::to_vec);
    // SAFETY: the encoding made above, or NULL.
    unsafe { crate::mem::release(p.cast()) };
    der
}

/// Whether a successful response is for `x` (or has no basic response or single response to
/// compare): a single response with the certificate's serial number and the hash of its
/// issuer's name (by the first one's hash algorithm).
///
/// # Safety
/// `x` and `resp` are live.
unsafe fn matches(ctx: &Ctx, x: *mut X509, resp: *mut OCSP_RESPONSE) -> bool {
    // SAFETY: a live response.
    let bs = unsafe { OCSP_response_get1_basic(resp) };
    if bs.is_null() {
        return true;
    }
    let found = 'done: {
        // SAFETY: the basic response.
        let first = unsafe { OCSP_resp_get0(bs, 0) };
        if first.is_null() {
            break 'done true;
        }
        let mut md_oid: *mut ASN1_OBJECT = ptr::null_mut();
        // SAFETY: the first single response's identifier.
        let cid = unsafe { OCSP_SINGLERESP_get0_id(first) };
        // SAFETY: as above; a place for the algorithm.
        unsafe {
            OCSP_id_get0_info(
                ptr::null_mut(),
                &raw mut md_oid,
                ptr::null_mut(),
                ptr::null_mut(),
                cid.cast_mut(),
            )
        };
        let mut name = [0 as c_char; 80];
        let md_name = if md_oid.is_null() {
            c"SHA1".as_ptr()
        } else {
            // SAFETY: the algorithm; room for its name.
            unsafe { crate::objects::OBJ_obj2txt(name.as_mut_ptr(), 80, md_oid, 0) };
            name.as_ptr()
        };
        // SAFETY: the context's library context and query; a name.
        let md = unsafe { crate::evp::digest::EVP_MD_fetch(ctx.libctx, md_name, ctx.propq_ptr()) };
        if md.is_null() {
            break 'done false;
        }
        let mut hash = [0u8; EVP_MAX_MD_SIZE as usize];
        let mut len: c_uint = 0;
        // SAFETY: the certificate.
        let issuer = unsafe { crate::x509::cert::X509_get_issuer_name(x) };
        // SAFETY: its issuer's name; the digest; room for it.
        let ok = unsafe {
            crate::x509::name::X509_NAME_digest(issuer, md, hash.as_mut_ptr(), &raw mut len)
        };
        // SAFETY: fetched above.
        unsafe { crate::evp::digest::EVP_MD_free(md) };
        if ok == 0 {
            break 'done false;
        }
        let hash = hash
            .get(..usize::try_from(len).unwrap_or(0))
            .unwrap_or_default();
        // SAFETY: the certificate.
        let serial = unsafe { crate::x509::cert::X509_get0_serialNumber(x) };
        // SAFETY: the basic response.
        let num = unsafe { OCSP_resp_count(bs) };
        (0..num).any(|i| {
            // SAFETY: an index within the single responses.
            let sr = unsafe { OCSP_resp_get0(bs, i) };
            let mut name_hash: *mut ASN1_OCTET_STRING = ptr::null_mut();
            let mut rserial: *mut ASN1_INTEGER = ptr::null_mut();
            // SAFETY: a single response of the basic response.
            let id = unsafe { OCSP_SINGLERESP_get0_id(sr) };
            // SAFETY: its identifier; places for its parts.
            unsafe {
                OCSP_id_get0_info(
                    &raw mut name_hash,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &raw mut rserial,
                    id.cast_mut(),
                )
            };
            // SAFETY: two integers.
            let same_serial =
                unsafe { crate::asn1::integer::ASN1_INTEGER_cmp(serial, rserial) } == 0;
            // SAFETY: the response's hash, or NULL.
            let resp_hash = unsafe { name_hash.as_ref() }.and_then(|h| {
                let n = usize::try_from(h.length).ok()?;
                // SAFETY: a string's data holds its length.
                unsafe { crate::ffi::bytes(h.data, n) }
            });
            same_serial && resp_hash == Some(hash)
        })
    };
    // SAFETY: got above.
    unsafe { OCSP_BASICRESP_free(bs) };
    found
}
