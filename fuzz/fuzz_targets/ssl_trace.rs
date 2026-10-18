//! Fuzzes SSL_trace on untrusted input: the first octet picks the connection (a fresh TLS
//! client, TLS server, DTLS client, or DTLS server) and the direction, the second the content
//! type (a record header, an inner content type, a handshake message, ChangeCipherSpec, an
//! alert, or another), and the rest is the message, printed into a memory BIO. Handshake
//! messages reach every printer, including the certificate, name and public key decoders.
//! Nothing may crash or read out of bounds (ASan).

#![no_main]

use core::ffi::{c_int, c_void};

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{
    BIO, BIO_METHOD, SSL, SSL_CTX, SSL_METHOD, SSL3_RT_ALERT, SSL3_RT_APPLICATION_DATA,
    SSL3_RT_CHANGE_CIPHER_SPEC, SSL3_RT_HANDSHAKE, SSL3_RT_HEADER, SSL3_RT_INNER_CONTENT_TYPE,
    TLS1_2_VERSION,
};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn rustyssl_private_TLS_client_method() -> *const SSL_METHOD;
    fn rustyssl_private_TLS_server_method() -> *const SSL_METHOD;
    fn rustyssl_private_DTLS_client_method() -> *const SSL_METHOD;
    fn rustyssl_private_DTLS_server_method() -> *const SSL_METHOD;
    fn rustyssl_private_SSL_CTX_new(m: *const SSL_METHOD) -> *mut SSL_CTX;
    fn rustyssl_private_SSL_CTX_free(ctx: *mut SSL_CTX);
    fn rustyssl_private_SSL_new(ctx: *mut SSL_CTX) -> *mut SSL;
    fn rustyssl_private_SSL_free(s: *mut SSL);
    fn rustyssl_private_SSL_trace(write_p: c_int, version: c_int, content_type: c_int, buf: *const c_void, len: usize, ssl: *mut SSL, arg: *mut c_void);
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn ERR_clear_error();
}

const TYPES: [c_int; 7] = [
    SSL3_RT_HANDSHAKE,
    SSL3_RT_HEADER,
    SSL3_RT_INNER_CONTENT_TYPE,
    SSL3_RT_CHANGE_CIPHER_SPEC,
    SSL3_RT_ALERT,
    SSL3_RT_APPLICATION_DATA,
    0,
];

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else { return };
    let Some((&ty, msg)) = rest.split_first() else { return };
    let content_type = TYPES.get(usize::from(ty) % TYPES.len()).copied().unwrap_or(0);
    // SAFETY: the methods, contexts, connections and BIO made here, freed; the input, read
    // within its length.
    unsafe {
        let method = match sel & 3 {
            0 => rustyssl_private_TLS_client_method(),
            1 => rustyssl_private_TLS_server_method(),
            2 => rustyssl_private_DTLS_client_method(),
            _ => rustyssl_private_DTLS_server_method(),
        };
        let ctx = rustyssl_private_SSL_CTX_new(method);
        let s = rustyssl_private_SSL_new(ctx);
        let bio = BIO_new(BIO_s_mem());
        rustyssl_private_SSL_trace(
            c_int::from(sel & 4 != 0),
            TLS1_2_VERSION,
            content_type,
            msg.as_ptr().cast(),
            msg.len(),
            s,
            bio.cast(),
        );
        BIO_free(bio);
        rustyssl_private_SSL_free(s);
        rustyssl_private_SSL_CTX_free(ctx);
        ERR_clear_error();
    }
});
