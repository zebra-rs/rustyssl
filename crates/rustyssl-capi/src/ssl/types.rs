//! The callback types libssl stores whose prototypes the headers spell out inline (so
//! `rustyssl_abi` has no name for them), and a few internal constants of `ssl_local.h`.

use core::ffi::{c_int, c_uchar, c_uint, c_void};

use rustyssl_abi::{
    EVP_CIPHER_CTX, EVP_MAC_CTX, EVP_PKEY, SSL, SSL_CTX, SSL_SESSION, X509, X509_STORE_CTX,
};

/// The info callback (`SSL_CTX_set_info_callback`).
pub(crate) type InfoCb = Option<unsafe extern "C" fn(ssl: *const SSL, type_: c_int, val: c_int)>;
/// The message callback (`SSL_CTX_set_msg_callback`).
pub(crate) type MsgCb = Option<
    unsafe extern "C" fn(
        write_p: c_int,
        version: c_int,
        content_type: c_int,
        buf: *const c_void,
        len: usize,
        ssl: *mut SSL,
        arg: *mut c_void,
    ),
>;
/// The security callback (`SSL_CTX_set_security_callback`).
pub(crate) type SecCb = Option<
    unsafe extern "C" fn(
        s: *const SSL,
        ctx: *const SSL_CTX,
        op: c_int,
        bits: c_int,
        nid: c_int,
        other: *mut c_void,
        ex: *mut c_void,
    ) -> c_int,
>;
/// The certificate callback (`SSL_CTX_set_cert_cb`).
pub(crate) type CertCb = Option<unsafe extern "C" fn(ssl: *mut SSL, arg: *mut c_void) -> c_int>;
/// The client certificate callback (`SSL_CTX_set_client_cert_cb`).
pub(crate) type ClientCertCb = Option<
    unsafe extern "C" fn(ssl: *mut SSL, x509: *mut *mut X509, pkey: *mut *mut EVP_PKEY) -> c_int,
>;
/// The application's verification (`SSL_CTX_set_cert_verify_callback`).
pub(crate) type AppVerifyCb =
    Option<unsafe extern "C" fn(arg1: *mut X509_STORE_CTX, arg2: *mut c_void) -> c_int>;
/// `SSL_CTX_set_not_resumable_session_callback`'s.
pub(crate) type NotResumableCb =
    Option<unsafe extern "C" fn(ssl: *mut SSL, is_forward_secure: c_int) -> c_int>;
/// The record padding callback.
pub(crate) type RecordPaddingCb = Option<
    unsafe extern "C" fn(ssl: *mut SSL, type_: c_int, len: usize, arg: *mut c_void) -> usize,
>;
/// The deprecated temporary DH callback.
pub(crate) type TmpDhCb = Option<
    unsafe extern "C" fn(
        ssl: *mut SSL,
        is_export: c_int,
        keylength: c_int,
    ) -> *mut rustyssl_abi::DH,
>;
/// DTLS's cookie generator.
pub(crate) type CookieGenCb = Option<
    unsafe extern "C" fn(ssl: *mut SSL, cookie: *mut c_uchar, cookie_len: *mut c_uint) -> c_int,
>;
/// DTLS's cookie verifier.
pub(crate) type CookieVerifyCb = Option<
    unsafe extern "C" fn(ssl: *mut SSL, cookie: *const c_uchar, cookie_len: c_uint) -> c_int,
>;
/// TLS 1.3's stateless cookie generator.
pub(crate) type StatelessCookieGenCb = Option<
    unsafe extern "C" fn(ssl: *mut SSL, cookie: *mut c_uchar, cookie_len: *mut usize) -> c_int,
>;
/// TLS 1.3's stateless cookie verifier.
pub(crate) type StatelessCookieVerifyCb =
    Option<unsafe extern "C" fn(ssl: *mut SSL, cookie: *const c_uchar, cookie_len: usize) -> c_int>;
/// The ticket key callback (`SSL_CTX_set_tlsext_ticket_key_evp_cb`).
pub(crate) type TicketKeyEvpCb = Option<
    unsafe extern "C" fn(
        arg1: *mut SSL,
        arg2: *mut c_uchar,
        arg3: *mut c_uchar,
        arg4: *mut EVP_CIPHER_CTX,
        arg5: *mut EVP_MAC_CTX,
        arg6: c_int,
    ) -> c_int,
>;
/// SRP's username callback.
pub(crate) type SrpUsernameCb =
    Option<unsafe extern "C" fn(arg1: *mut SSL, arg2: *mut c_int, arg3: *mut c_void) -> c_int>;
/// SRP's parameter check.
pub(crate) type SrpVerifyParamCb =
    Option<unsafe extern "C" fn(arg1: *mut SSL, arg2: *mut c_void) -> c_int>;
/// SRP's client password callback.
pub(crate) type SrpClientPwdCb =
    Option<unsafe extern "C" fn(arg1: *mut SSL, arg2: *mut c_void) -> *mut core::ffi::c_char>;
/// The session cache's new-session callback.
pub(crate) type SessNewCb =
    Option<unsafe extern "C" fn(ssl: *mut SSL, sess: *mut SSL_SESSION) -> c_int>;
/// The session cache's removal callback.
pub(crate) type SessRemoveCb =
    Option<unsafe extern "C" fn(ctx: *mut SSL_CTX, sess: *mut SSL_SESSION)>;
/// The session cache's lookup callback.
pub(crate) type SessGetCb = Option<
    unsafe extern "C" fn(
        ssl: *mut SSL,
        data: *const c_uchar,
        len: c_int,
        copy: *mut c_int,
    ) -> *mut SSL_SESSION,
>;
/// A callback stored through a `*_callback_ctrl` command, kept as the generic pointer it came
/// as; it is cast to its own type where it is called.
pub(crate) type AnyCb = Option<unsafe extern "C" fn()>;

/// `SSL_PKEY_NUM` (`ssl_local.h`): the certificate slots of the built-in key types.
pub(crate) const SSL_PKEY_NUM: usize = 9;
/// `SSL_PKEY_RSA`.
pub(crate) const SSL_PKEY_RSA: usize = 0;
/// `SSL_PKEY_ECC`.
pub(crate) const SSL_PKEY_ECC: usize = 3;
/// `TLSEXT_STATUSTYPE_nothing` (`ssl_local.h`): no status request.
pub(crate) const TLSEXT_STATUSTYPE_NOTHING: c_int = -1;
/// `TLS_CIPHER_LEN` (`ssl_local.h`): a cipher suite's octets on the wire.
pub(crate) const TLS_CIPHER_LEN: core::ffi::c_long = 2;
/// The ticket key name's length (`ext.tick_key_name`).
pub(crate) const TICK_KEY_NAME_LEN: usize = 16;
/// The ticket HMAC and AES keys' lengths (`TLSEXT_TICK_KEY_LENGTH`).
pub(crate) const TICK_KEY_LEN: usize = 32;
/// The cookie HMAC key's length (`SHA256_DIGEST_LENGTH`).
pub(crate) const COOKIE_HMAC_KEY_LEN: usize = 32;
