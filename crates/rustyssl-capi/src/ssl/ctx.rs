//! The context (`SSL_CTX`, `ssl_lib.c`'s `SSL_CTX_new_ex` and its accessors, `s3_lib.c`'s
//! `ssl3_ctx_ctrl`): the settings every connection made from it starts with.
//!
//! The settings live in [`CtxState`] behind one lock, taken only to read or write them: never
//! while an application's callback runs (security rule 7). The verification parameters and the
//! application data have fixed addresses for the `get0` functions.

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    CRYPTO_EX_DATA, CRYPTO_EX_INDEX_SSL_CTX, CRYPTO_EX_INDEX_X509_STORE_CTX, DTLS_ANY_VERSION,
    DTLS1_2_VERSION, DTLS1_BAD_VER, DTLS1_VERSION, DTLS1_VERSION_MAJOR, ERR_LIB_SSL,
    ERR_R_CRYPTO_LIB, ERR_R_RAND_LIB, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, ERR_R_X509_LIB,
    OPENSSL_INIT_LOAD_SSL_STRINGS, OSSL_LIB_CTX, SSL_CTRL_CERT_FLAGS, SSL_CTRL_CHAIN,
    SSL_CTRL_CHAIN_CERT, SSL_CTRL_CLEAR_CERT_FLAGS, SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS,
    SSL_CTRL_CLEAR_MODE, SSL_CTRL_EXTRA_CHAIN_CERT, SSL_CTRL_GET_CHAIN_CERT_STORE,
    SSL_CTRL_GET_CHAIN_CERTS, SSL_CTRL_GET_EXTRA_CHAIN_CERTS, SSL_CTRL_GET_MAX_CERT_LIST,
    SSL_CTRL_GET_MAX_PROTO_VERSION, SSL_CTRL_GET_MIN_PROTO_VERSION, SSL_CTRL_GET_READ_AHEAD,
    SSL_CTRL_GET_SESS_CACHE_MODE, SSL_CTRL_GET_SESS_CACHE_SIZE, SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB,
    SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG, SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE,
    SSL_CTRL_GET_TLSEXT_TICKET_KEYS, SSL_CTRL_GET_VERIFY_CERT_STORE, SSL_CTRL_MODE,
    SSL_CTRL_SELECT_CURRENT_CERT, SSL_CTRL_SESS_ACCEPT, SSL_CTRL_SESS_ACCEPT_GOOD,
    SSL_CTRL_SESS_ACCEPT_RENEGOTIATE, SSL_CTRL_SESS_CACHE_FULL, SSL_CTRL_SESS_CB_HIT,
    SSL_CTRL_SESS_CONNECT, SSL_CTRL_SESS_CONNECT_GOOD, SSL_CTRL_SESS_CONNECT_RENEGOTIATE,
    SSL_CTRL_SESS_HIT, SSL_CTRL_SESS_MISSES, SSL_CTRL_SESS_NUMBER, SSL_CTRL_SESS_TIMEOUTS,
    SSL_CTRL_SET_CHAIN_CERT_STORE, SSL_CTRL_SET_CURRENT_CERT, SSL_CTRL_SET_DH_AUTO,
    SSL_CTRL_SET_MAX_CERT_LIST, SSL_CTRL_SET_MAX_PIPELINES, SSL_CTRL_SET_MAX_PROTO_VERSION,
    SSL_CTRL_SET_MAX_SEND_FRAGMENT, SSL_CTRL_SET_MIN_PROTO_VERSION, SSL_CTRL_SET_MSG_CALLBACK,
    SSL_CTRL_SET_MSG_CALLBACK_ARG, SSL_CTRL_SET_NOT_RESUMABLE_SESS_CB, SSL_CTRL_SET_READ_AHEAD,
    SSL_CTRL_SET_SESS_CACHE_MODE, SSL_CTRL_SET_SESS_CACHE_SIZE, SSL_CTRL_SET_SPLIT_SEND_FRAGMENT,
    SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB, SSL_CTRL_SET_SRP_VERIFY_PARAM_CB,
    SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD, SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH,
    SSL_CTRL_SET_TLS_EXT_SRP_USERNAME, SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB,
    SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB,
    SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB, SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG,
    SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE, SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB,
    SSL_CTRL_SET_TLSEXT_TICKET_KEYS, SSL_CTRL_SET_TMP_DH_CB, SSL_CTRL_SET_VERIFY_CERT_STORE,
    SSL_CTX, SSL_MAX_CERT_LIST_DEFAULT, SSL_MAX_PIPELINES, SSL_METHOD, SSL_MODE_AUTO_RETRY,
    SSL_OP_ENABLE_MIDDLEBOX_COMPAT, SSL_OP_NO_COMPRESSION, SSL_OP_NO_TICKET,
    SSL_R_INVALID_SRP_USERNAME, SSL_R_INVALID_TICKET_KEYS_LENGTH, SSL_R_NULL_SSL_METHOD_PASSED,
    SSL_R_X509_VERIFICATION_SETUP_PROBLEMS, SSL_SESS_CACHE_SERVER,
    SSL_SESSION_CACHE_MAX_SIZE_DEFAULT, SSL_VERIFY_NONE, SSL_verify_cb, SSL3_RT_MAX_PLAIN_LENGTH,
    SSL3_VERSION, TLS_ANY_VERSION, X509_STORE, X509_VERIFY_PARAM, pem_password_cb, stack_st_X509,
    stack_st_X509_NAME,
};

use super::cert::{self, Cert, Owner};
use super::method::{DEFAULT_TIMEOUT, Method, method_of};
use super::types::{
    AnyCb, AppVerifyCb, COOKIE_HMAC_KEY_LEN, ClientCertCb, CookieGenCb, CookieVerifyCb, InfoCb,
    MsgCb, NotResumableCb, RecordPaddingCb, SessGetCb, SessNewCb, SessRemoveCb, SrpClientPwdCb,
    SrpUsernameCb, SrpVerifyParamCb, StatelessCookieGenCb, StatelessCookieVerifyCb, TICK_KEY_LEN,
    TICK_KEY_NAME_LEN, TLSEXT_STATUSTYPE_NOTHING, TicketKeyEvpCb,
};
use crate::err;
use crate::ex_data::{CRYPTO_free_ex_data, CRYPTO_get_ex_new_index, CRYPTO_new_ex_data};
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::rand_lib::{RAND_bytes_ex, RAND_priv_bytes_ex};
use crate::stack::{OPENSSL_sk_new_null, OPENSSL_sk_pop_free, OPENSSL_sk_push};
use crate::x509::cert::OSSL_STACK_OF_X509_free;
use crate::x509::name::X509_NAME_free;
use crate::x509::store::{X509_STORE_free, X509_STORE_new};
use crate::x509::vpm::{X509_VERIFY_PARAM_free, X509_VERIFY_PARAM_new};

/// The SRP settings (`SRP_CTX`'s client side, as far as the context stores them).
#[derive(Debug, Default)]
pub(crate) struct Srp {
    /// The username (`login`).
    pub(crate) login: Option<CString>,
    /// The password (`info`).
    pub(crate) info: Option<CString>,
    /// The minimum strength in bits.
    pub(crate) strength: c_int,
    /// The callbacks' argument.
    pub(crate) cb_arg: *mut c_void,
    /// Whether SRP was configured (`srp_Mask & SSL_kSRP`).
    pub(crate) enabled: bool,
    /// The server's username callback.
    pub(crate) username_cb: SrpUsernameCb,
    /// The client's parameter check.
    pub(crate) verify_param_cb: SrpVerifyParamCb,
    /// The client's password callback.
    pub(crate) give_client_pwd_cb: SrpClientPwdCb,
    /// Whether the password callback is the built-in one returning `info`.
    pub(crate) pwd_from_info: bool,
}

/// A context's settings, with OpenSSL's field names (`struct ssl_ctx_st`).
#[derive(Debug)]
pub(crate) struct CtxState {
    pub(crate) method: &'static Method,
    pub(crate) options: u64,
    pub(crate) mode: u32,
    pub(crate) min_proto_version: c_int,
    pub(crate) max_proto_version: c_int,
    pub(crate) verify_mode: c_int,
    pub(crate) default_verify_callback: SSL_verify_cb,
    /// The certificate store (a reference held).
    pub(crate) cert_store: *mut X509_STORE,
    pub(crate) sid_ctx: Vec<u8>,
    pub(crate) default_passwd_callback: pem_password_cb,
    pub(crate) default_passwd_callback_userdata: *mut c_void,
    pub(crate) quiet_shutdown: c_int,
    pub(crate) read_ahead: c_int,
    pub(crate) max_cert_list: usize,
    pub(crate) session_cache_mode: u32,
    pub(crate) session_cache_size: usize,
    /// The session timeout in seconds.
    pub(crate) session_timeout: c_long,
    pub(crate) max_send_fragment: usize,
    pub(crate) split_send_fragment: usize,
    pub(crate) max_pipelines: usize,
    pub(crate) default_read_buf_len: usize,
    pub(crate) num_tickets: usize,
    pub(crate) max_early_data: u32,
    pub(crate) recv_max_early_data: u32,
    pub(crate) pha_enabled: c_int,
    pub(crate) info_callback: InfoCb,
    pub(crate) msg_callback: MsgCb,
    pub(crate) msg_callback_arg: *mut c_void,
    pub(crate) keylog_callback: rustyssl_abi::SSL_CTX_keylog_cb_func,
    pub(crate) client_cert_cb: ClientCertCb,
    pub(crate) app_verify_callback: AppVerifyCb,
    pub(crate) app_verify_arg: *mut c_void,
    pub(crate) client_hello_cb: rustyssl_abi::SSL_client_hello_cb_fn,
    pub(crate) client_hello_cb_arg: *mut c_void,
    pub(crate) alpn_select_cb: rustyssl_abi::SSL_CTX_alpn_select_cb_func,
    pub(crate) alpn_select_cb_arg: *mut c_void,
    pub(crate) npn_select_cb: rustyssl_abi::SSL_CTX_npn_select_cb_func,
    pub(crate) npn_select_cb_arg: *mut c_void,
    pub(crate) npn_advertised_cb: rustyssl_abi::SSL_CTX_npn_advertised_cb_func,
    pub(crate) npn_advertised_cb_arg: *mut c_void,
    /// The ALPN protocols offered, in wire format (empty: none).
    pub(crate) alpn: Vec<u8>,
    pub(crate) max_fragment_len_mode: u8,
    pub(crate) generate_ticket_cb: rustyssl_abi::SSL_CTX_generate_session_ticket_fn,
    pub(crate) decrypt_ticket_cb: rustyssl_abi::SSL_CTX_decrypt_session_ticket_fn,
    pub(crate) ticket_cb_data: *mut c_void,
    pub(crate) ticket_key_evp_cb: TicketKeyEvpCb,
    /// The deprecated `SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB` callback.
    pub(crate) ticket_key_cb: AnyCb,
    pub(crate) new_session_cb: SessNewCb,
    pub(crate) remove_session_cb: SessRemoveCb,
    pub(crate) get_session_cb: SessGetCb,
    pub(crate) app_gen_cookie_cb: CookieGenCb,
    pub(crate) app_verify_cookie_cb: CookieVerifyCb,
    pub(crate) gen_stateless_cookie_cb: StatelessCookieGenCb,
    pub(crate) verify_stateless_cookie_cb: StatelessCookieVerifyCb,
    pub(crate) generate_session_id: rustyssl_abi::GEN_SESSION_CB,
    pub(crate) not_resumable_session_cb: NotResumableCb,
    pub(crate) allow_early_data_cb: rustyssl_abi::SSL_allow_early_data_cb_fn,
    pub(crate) allow_early_data_cb_data: *mut c_void,
    pub(crate) record_padding_cb: RecordPaddingCb,
    pub(crate) record_padding_arg: *mut c_void,
    pub(crate) block_padding: usize,
    pub(crate) hs_padding: usize,
    pub(crate) psk_client_callback: rustyssl_abi::SSL_psk_client_cb_func,
    pub(crate) psk_server_callback: rustyssl_abi::SSL_psk_server_cb_func,
    pub(crate) psk_find_session_cb: rustyssl_abi::SSL_psk_find_session_cb_func,
    pub(crate) psk_use_session_cb: rustyssl_abi::SSL_psk_use_session_cb_func,
    pub(crate) async_cb: rustyssl_abi::SSL_async_callback_fn,
    pub(crate) async_cb_arg: *mut c_void,
    pub(crate) servername_cb: AnyCb,
    pub(crate) servername_arg: *mut c_void,
    pub(crate) status_cb: AnyCb,
    pub(crate) status_arg: *mut c_void,
    pub(crate) status_type: c_int,
    /// CT validation and the log store (`ct_validation_callback`, `ctlog_store`).
    pub(crate) ct: super::ct::CtxCt,
    /// `SSL_CTX_set_tlsext_use_srtp`'s profiles (`srtp_profiles`).
    pub(crate) srtp: super::srtp::Profiles,
    pub(crate) tick_key_name: [u8; TICK_KEY_NAME_LEN],
    pub(crate) tick_hmac_key: [u8; TICK_KEY_LEN],
    pub(crate) tick_aes_key: [u8; TICK_KEY_LEN],
    pub(crate) cookie_hmac_key: [u8; COOKIE_HMAC_KEY_LEN],
    pub(crate) srp: Srp,
    /// The names sent as acceptable CAs (`ca_names`, owned).
    pub(crate) ca_names: *mut stack_st_X509_NAME,
    /// The names sent in a CertificateRequest (`client_ca_names`, owned).
    pub(crate) client_ca_names: *mut stack_st_X509_NAME,
    /// `SSL_CTX_add_extra_chain_cert`'s certificates (owned), or NULL.
    pub(crate) extra_certs: *mut stack_st_X509,
    pub(crate) cert: Cert,
    /// The cipher lists (`cipher_list`, `cipher_list_by_id`, `tls13_ciphersuites`).
    pub(crate) ciphers: super::ciphers::CipherLists,
    /// The algorithms the context's providers lack (`disabled_*_mask`, `ssl_load_ciphers`).
    pub(crate) available: rustyssl_tls::cipherstring::Available,
    /// The group and certificate type lists (`ctx->ext.supportedgroups`, ...; `super::lists`).
    pub(crate) lists: super::lists::Lists,
}

impl Drop for CtxState {
    fn drop(&mut self) {
        // SAFETY: our own references and lists, each NULL or live.
        unsafe { X509_STORE_free(self.cert_store) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_pop_free(self.ca_names.cast(), Some(name_free)) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_pop_free(self.client_ca_names.cast(), Some(name_free)) };
        // SAFETY: as above.
        unsafe { OSSL_STACK_OF_X509_free(self.extra_certs) };
        wipe(&mut self.tick_hmac_key);
        wipe(&mut self.tick_aes_key);
        wipe(&mut self.cookie_hmac_key);
    }
}

/// Zeroes a secret key.
pub(crate) fn wipe(key: &mut [u8]) {
    // SAFETY: the slice's own octets.
    unsafe { crate::mem::cleanse(key.as_mut_ptr().cast(), key.len()) };
}

/// `X509_NAME_free` as a stack's free function.
pub(crate) unsafe extern "C" fn name_free(p: *mut c_void) {
    // SAFETY: a name of the stack, which the stack owned.
    unsafe { X509_NAME_free(p.cast()) };
}

/// A context (`SSL_CTX`, shared by reference).
pub(crate) struct Ctx {
    references: AtomicI32,
    /// The library context algorithms come from (not owned).
    pub(crate) libctx: *mut OSSL_LIB_CTX,
    /// The property query, or `None`.
    pub(crate) propq: Option<CString>,
    /// The verification parameters (owned), at a fixed address for `SSL_CTX_get0_param`.
    pub(crate) param: *mut X509_VERIFY_PARAM,
    /// The application's data, at a fixed address for the `CRYPTO_*_ex_data` functions.
    ex_data: UnsafeCell<CRYPTO_EX_DATA>,
    state: Mutex<CtxState>,
    /// The session cache (`sessions`, the expiry list, `stats`).
    pub(crate) cache: super::sess_cache::Cache,
}

// SAFETY: the settings are behind the mutex; the parameters and the application data are
// OpenSSL's own objects, which applications set up before sharing the context, as OpenSSL
// requires (its setters take no lock either).
unsafe impl Send for Ctx {}
// SAFETY: as above.
unsafe impl Sync for Ctx {}
// SAFETY: the state's raw pointers are owned references to OpenSSL objects, used only under
// the context's lock.
unsafe impl Send for CtxState {}

handle_type!(SSL_CTX => Ctx);

impl Drop for Ctx {
    fn drop(&mut self) {
        // SAFETY: our own parameters.
        unsafe { X509_VERIFY_PARAM_free(self.param) };
    }
}

impl Ctx {
    /// The settings, locked.
    pub(crate) fn state(&self) -> MutexGuard<'_, CtxState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The property query as a C string, or NULL.
    pub(crate) fn propq_ptr(&self) -> *const c_char {
        self.propq
            .as_deref()
            .map_or(ptr::null(), core::ffi::CStr::as_ptr)
    }

    /// The application's data.
    pub(crate) fn ex_data(&self) -> *mut CRYPTO_EX_DATA {
        self.ex_data.get()
    }
}

/// The context behind `c`, or `None` for NULL.
///
/// # Safety
/// `c` is NULL or a live context.
pub(crate) unsafe fn ctx<'a>(c: *const SSL_CTX) -> Option<&'a Ctx> {
    // SAFETY: the caller's guarantee.
    unsafe { SSL_CTX::get(c) }
}

/// Whether DTLS version `a` is older than `b` (DTLS versions count down; `DTLS1_BAD_VER`
/// is the oldest).
pub(crate) fn dtls_lt(a: c_int, b: c_int) -> bool {
    let rank = |v: c_int| if v == DTLS1_BAD_VER { 0xff00 } else { v };
    rank(a) > rank(b)
}

/// `ssl_check_allowed_versions`, for the default build (no SSLv3): 0 when the bounds mix
/// TLS and DTLS or only leave a disabled version, 1 otherwise.
pub(crate) fn check_allowed_versions(min_version: c_int, max_version: c_int) -> c_int {
    let is_dtls = |v: c_int| v == DTLS1_BAD_VER || v >> 8 == DTLS1_VERSION_MAJOR;
    let (minisdtls, maxisdtls) = (is_dtls(min_version), is_dtls(max_version));
    if (minisdtls && !maxisdtls && max_version != 0)
        || (maxisdtls && !minisdtls && min_version != 0)
    {
        return 0;
    }
    if minisdtls || maxisdtls {
        // Both DTLS versions are built: nothing is disabled.
        return 1;
    }
    let mut min = if min_version == 0 {
        SSL3_VERSION
    } else {
        min_version
    };
    let max = if max_version == 0 {
        rustyssl_abi::TLS1_3_VERSION
    } else {
        max_version
    };
    // SSLv3 isn't built, so a lower bound of SSLv3 means TLS 1.0.
    if min == SSL3_VERSION {
        min = rustyssl_abi::TLS1_VERSION;
    }
    c_int::from(!(min <= SSL3_VERSION && SSL3_VERSION <= max))
}

/// `ssl_set_version_bound`: sets `bound` to `version` if the method's family takes it
/// (a fixed-version method ignores bounds); 0 for a version that is neither TLS nor DTLS.
pub(crate) fn set_version_bound(method_version: c_int, version: c_int, bound: &mut c_int) -> c_int {
    if version == 0 {
        *bound = 0;
        return 1;
    }
    let valid_tls = (SSL3_VERSION..=rustyssl_abi::TLS1_3_VERSION).contains(&version);
    let valid_dtls = version == DTLS1_BAD_VER
        || (!dtls_lt(version, DTLS1_VERSION)
            && !dtls_lt(DTLS1_2_VERSION, version)
            && version >> 8 == DTLS1_VERSION_MAJOR);
    if !valid_tls && !valid_dtls {
        return 0;
    }
    match method_version {
        TLS_ANY_VERSION if valid_tls => *bound = version,
        DTLS_ANY_VERSION if valid_dtls => *bound = version,
        _ => {}
    }
    1
}

/// The `SSL_CTX_get_ex_new_index` index OpenSSL keeps for the connection in a verification
/// (`SSL_get_ex_data_X509_STORE_CTX_idx`), made once.
pub(crate) fn store_ctx_index() -> c_int {
    static INDEX: std::sync::OnceLock<c_int> = std::sync::OnceLock::new();
    *INDEX.get_or_init(|| {
        // SAFETY: a static description; no callbacks.
        unsafe {
            CRYPTO_get_ex_new_index(
                CRYPTO_EX_INDEX_X509_STORE_CTX,
                0,
                c"SSL for verify callback".as_ptr().cast_mut().cast(),
                None,
                None,
                None,
            )
        }
    })
}

/// A new context's settings for `method`.
fn new_state(method: &'static Method, cert_store: *mut X509_STORE) -> CtxState {
    CtxState {
        method,
        options: SSL_OP_NO_COMPRESSION | SSL_OP_ENABLE_MIDDLEBOX_COMPAT,
        mode: SSL_MODE_AUTO_RETRY,
        min_proto_version: 0,
        max_proto_version: 0,
        verify_mode: SSL_VERIFY_NONE,
        default_verify_callback: None,
        cert_store,
        sid_ctx: Vec::new(),
        default_passwd_callback: None,
        default_passwd_callback_userdata: ptr::null_mut(),
        quiet_shutdown: 0,
        read_ahead: 0,
        max_cert_list: usize::try_from(SSL_MAX_CERT_LIST_DEFAULT).unwrap_or(0),
        session_cache_mode: SSL_SESS_CACHE_SERVER.cast_unsigned(),
        session_cache_size: usize::try_from(SSL_SESSION_CACHE_MAX_SIZE_DEFAULT).unwrap_or(0),
        session_timeout: DEFAULT_TIMEOUT,
        max_send_fragment: usize::try_from(SSL3_RT_MAX_PLAIN_LENGTH).unwrap_or(0),
        split_send_fragment: usize::try_from(SSL3_RT_MAX_PLAIN_LENGTH).unwrap_or(0),
        max_pipelines: 0,
        default_read_buf_len: 0,
        num_tickets: 2,
        max_early_data: 0,
        recv_max_early_data: u32::try_from(SSL3_RT_MAX_PLAIN_LENGTH).unwrap_or(0),
        pha_enabled: 0,
        info_callback: None,
        msg_callback: None,
        msg_callback_arg: ptr::null_mut(),
        keylog_callback: None,
        client_cert_cb: None,
        app_verify_callback: None,
        app_verify_arg: ptr::null_mut(),
        client_hello_cb: None,
        client_hello_cb_arg: ptr::null_mut(),
        alpn_select_cb: None,
        alpn_select_cb_arg: ptr::null_mut(),
        npn_select_cb: None,
        npn_select_cb_arg: ptr::null_mut(),
        npn_advertised_cb: None,
        npn_advertised_cb_arg: ptr::null_mut(),
        alpn: Vec::new(),
        max_fragment_len_mode: 0,
        generate_ticket_cb: None,
        decrypt_ticket_cb: None,
        ticket_cb_data: ptr::null_mut(),
        ticket_key_evp_cb: None,
        ticket_key_cb: None,
        new_session_cb: None,
        remove_session_cb: None,
        get_session_cb: None,
        app_gen_cookie_cb: None,
        app_verify_cookie_cb: None,
        gen_stateless_cookie_cb: None,
        verify_stateless_cookie_cb: None,
        generate_session_id: None,
        not_resumable_session_cb: None,
        allow_early_data_cb: None,
        allow_early_data_cb_data: ptr::null_mut(),
        record_padding_cb: None,
        record_padding_arg: ptr::null_mut(),
        block_padding: 0,
        hs_padding: 0,
        psk_client_callback: None,
        psk_server_callback: None,
        psk_find_session_cb: None,
        psk_use_session_cb: None,
        async_cb: None,
        async_cb_arg: ptr::null_mut(),
        servername_cb: None,
        servername_arg: ptr::null_mut(),
        status_cb: None,
        status_arg: ptr::null_mut(),
        status_type: TLSEXT_STATUSTYPE_NOTHING,
        ct: super::ct::CtxCt::default(),
        srtp: super::srtp::Profiles::default(),
        tick_key_name: [0; TICK_KEY_NAME_LEN],
        tick_hmac_key: [0; TICK_KEY_LEN],
        tick_aes_key: [0; TICK_KEY_LEN],
        cookie_hmac_key: [0; COOKIE_HMAC_KEY_LEN],
        srp: Srp::default(),
        ca_names: ptr::null_mut(),
        client_ca_names: ptr::null_mut(),
        extra_certs: ptr::null_mut(),
        cert: Cert::new(),
        ciphers: super::ciphers::CipherLists::none(),
        available: rustyssl_tls::cipherstring::Available::default(),
        lists: super::lists::Lists::default(),
    }
}

ffi_export! {
    /// A new context for `meth` with `libctx` and `propq` (NULL for the defaults), or NULL.
    /// It starts with OpenSSL's defaults: compression off and middlebox compatibility on,
    /// auto-retry, a server session cache, two tickets, random ticket keys, an empty store.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `propq` NULL or a string; `meth` NULL or a
    /// method.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_new_ex(libctx: *mut OSSL_LIB_CTX, propq: *const c_char, meth: *const SSL_METHOD) -> *mut SSL_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        const F: &str = "SSL_CTX_new_ex";
        let Some(method) = method_of(meth) else {
            err::raise(ERR_LIB_SSL, SSL_R_NULL_SSL_METHOD_PASSED, F);
            return ptr::null_mut();
        };
        // SAFETY: no preconditions.
        if unsafe { super::rustyssl_private_OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS.cast_unsigned(), ptr::null()) } == 0 {
            return ptr::null_mut();
        }
        if store_ctx_index() < 0 {
            err::raise(ERR_LIB_SSL, SSL_R_X509_VERIFICATION_SETUP_PROBLEMS, F);
            return ptr::null_mut();
        }
        let propq = if propq.is_null() {
            None
        } else {
            // SAFETY: the caller's string.
            Some(unsafe { core::ffi::CStr::from_ptr(propq) }.to_owned())
        };
        // SAFETY: no preconditions.
        let store = unsafe { X509_STORE_new() };
        if store.is_null() {
            err::raise(ERR_LIB_SSL, ERR_R_X509_LIB, F);
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let param = unsafe { X509_VERIFY_PARAM_new() };
        let mut state = new_state(method, store);
        if param.is_null() {
            err::raise(ERR_LIB_SSL, ERR_R_X509_LIB, F);
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        state.ca_names = unsafe { OPENSSL_sk_new_null() }.cast();
        // SAFETY: as above.
        state.client_ca_names = unsafe { OPENSSL_sk_new_null() }.cast();
        if state.ca_names.is_null() || state.client_ca_names.is_null() {
            err::raise(ERR_LIB_SSL, ERR_R_CRYPTO_LIB, F);
            // SAFETY: made above.
            unsafe { X509_VERIFY_PARAM_free(param) };
            return ptr::null_mut();
        }
        // SAFETY: the library context; the rooms.
        let ticket_keys = unsafe { RAND_bytes_ex(libctx, state.tick_key_name.as_mut_ptr(), TICK_KEY_NAME_LEN, 0) } > 0
            // SAFETY: as above.
            && unsafe { RAND_priv_bytes_ex(libctx, state.tick_hmac_key.as_mut_ptr(), TICK_KEY_LEN, 0) } > 0
            // SAFETY: as above.
            && unsafe { RAND_priv_bytes_ex(libctx, state.tick_aes_key.as_mut_ptr(), TICK_KEY_LEN, 0) } > 0;
        if !ticket_keys {
            state.options |= SSL_OP_NO_TICKET;
        }
        // SAFETY: as above.
        if unsafe { RAND_priv_bytes_ex(libctx, state.cookie_hmac_key.as_mut_ptr(), COOKIE_HMAC_KEY_LEN, 0) } <= 0 {
            err::raise(ERR_LIB_SSL, ERR_R_RAND_LIB, F);
            // SAFETY: made above.
            unsafe { X509_VERIFY_PARAM_free(param) };
            return ptr::null_mut();
        }
        // `ssl_load_ciphers`, then the default TLS 1.3 suites and cipher list.
        let propq_ptr = propq.as_ref().map_or(ptr::null(), |p| p.as_ptr());
        // SAFETY: the caller's library context; the property query, or NULL.
        state.available = unsafe { super::ciphers::available(libctx, propq_ptr) };
        let available = state.available;
        let Some(lists) = super::ciphers::new_ctx_lists(&available, method, &mut state.cert) else {
            // SAFETY: made above.
            unsafe { X509_VERIFY_PARAM_free(param) };
            return ptr::null_mut();
        };
        state.ciphers = lists;
        let c = SSL_CTX::new_handle(Ctx {
            references: AtomicI32::new(1),
            libctx,
            propq,
            param,
            // SAFETY: an all-zero `CRYPTO_EX_DATA` is the empty one `CRYPTO_new_ex_data` fills.
            ex_data: UnsafeCell::new(unsafe { core::mem::zeroed() }),
            state: Mutex::new(state),
            cache: super::sess_cache::Cache::new(),
        });
        // SAFETY: the new context.
        let Some(x) = (unsafe { ctx(c) }) else { return ptr::null_mut() };
        // SAFETY: the new context and its own application data.
        if unsafe { CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL_CTX, c.cast(), x.ex_data()) } == 0 {
            err::raise(ERR_LIB_SSL, ERR_R_CRYPTO_LIB, F);
            // SAFETY: the new context's only reference.
            unsafe { SSL_CTX::free(c) };
            return ptr::null_mut();
        }
        // SAFETY: the new context.
        if !unsafe { super::conf::system_config(c) } {
            err::raise(ERR_LIB_SSL, rustyssl_abi::SSL_R_ERROR_IN_SYSTEM_DEFAULT_CONFIG, F);
            // SAFETY: the new context's only reference.
            unsafe { SSL_CTX::free(c) };
            return ptr::null_mut();
        }
        c
    }
}

ffi_export! {
    /// `SSL_CTX_new_ex` with the default library context and no properties.
    ///
    /// # Safety
    /// `meth` is NULL or a method.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_new(meth: *const SSL_METHOD) -> *mut SSL_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { rustyssl_private_SSL_CTX_new_ex(ptr::null_mut(), ptr::null(), meth) }
    }
}

ffi_export! {
    /// Adds a reference: 1, or 0 for NULL.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_up_ref(c: *mut SSL_CTX) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx(c) }) else { return 0 };
        x.references.fetch_add(1, Ordering::AcqRel);
        // SAFETY: as above.
        c_int::from(unsafe { SSL_CTX::up_ref(c) })
    }
}

ffi_export! {
    /// Drops a reference; with the last, frees the application data, then everything the
    /// context holds. Nothing for NULL.
    ///
    /// # Safety
    /// `c` is NULL or a live context whose reference the caller gives up.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_free(c: *mut SSL_CTX)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(held) = (unsafe { SSL_CTX::hold(c) }) else { return };
        if held.references.fetch_sub(1, Ordering::AcqRel) == 1 {
            // The cache goes first, while the removal callback can still use the context.
            // SAFETY: the context's last reference.
            unsafe { super::sess_cache::flush(c, &held, 0) };
            // SAFETY: the context's own application data; its last reference.
            unsafe { CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_CTX, c.cast(), held.ex_data()) };
        }
        // SAFETY: the caller's reference; the hold keeps the context until this returns.
        unsafe { SSL_CTX::free(c) };
    }
}

ffi_export! {
    /// The index of the connection in a verification's application data, made once (-1 on
    /// failure).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_ex_data_X509_STORE_CTX_idx() -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        store_ctx_index()
    }
}

/// What a context's ctrl command does with a numeric setting: the new value as a `usize`
/// (0 rejected by the caller where it matters), or `None` for a negative one.
fn non_negative(larg: c_long) -> Option<usize> {
    usize::try_from(larg).ok()
}

/// A `usize` setting as a ctrl's `long` result.
pub(crate) fn as_long(v: usize) -> c_long {
    c_long::try_from(v).unwrap_or(c_long::MAX)
}

/// A context's ctrl commands that change its certificate configuration (`SSL_CTRL_CHAIN` and
/// the rest), shared with connections' (`Owner`).
///
/// # Safety
/// The owner is live; `parg` is what `cmd` documents.
pub(crate) unsafe fn cert_ctrl(
    owner: Owner,
    cmd: c_int,
    larg: c_long,
    parg: *mut c_void,
) -> Option<c_long> {
    let r = match cmd {
        SSL_CTRL_CHAIN => {
            if larg != 0 {
                // SAFETY: the caller's guarantee: a list of certificates, or NULL.
                unsafe { cert::set1_chain(owner, parg.cast()) }
            } else {
                // SAFETY: as above.
                unsafe { cert::set0_chain(owner, parg.cast()) }
            }
        }
        SSL_CTRL_CHAIN_CERT => {
            if larg != 0 {
                // SAFETY: the caller's guarantee: a certificate.
                unsafe { cert::add1_chain(owner, parg.cast()) }
            } else {
                // SAFETY: as above.
                unsafe { cert::add0_chain(owner, parg.cast()) }
            }
        }
        SSL_CTRL_GET_CHAIN_CERTS => {
            // SAFETY: the owner.
            let chain = unsafe {
                cert::with_cert(owner, |c| c.current().map_or(ptr::null_mut(), |p| p.chain))
            }
            .unwrap_or(ptr::null_mut());
            // SAFETY: the caller's slot.
            unsafe { parg.cast::<*mut stack_st_X509>().write(chain) };
            1
        }
        SSL_CTRL_SELECT_CURRENT_CERT => {
            let f = |c: &mut Cert| {
                // SAFETY: the caller's certificate, or NULL.
                unsafe { c.select_current(parg.cast()) }
            };
            // SAFETY: the owner.
            unsafe { cert::with_cert(owner, f) }.unwrap_or(0)
        }
        SSL_CTRL_SET_VERIFY_CERT_STORE | SSL_CTRL_SET_CHAIN_CERT_STORE => {
            let chain = cmd == SSL_CTRL_SET_CHAIN_CERT_STORE;
            let mut rel = cert::Released::default();
            let f = |c: &mut Cert| {
                // SAFETY: the caller's store, or NULL.
                unsafe { c.set_store(parg.cast(), chain, larg != 0, &mut rel) }
            };
            // SAFETY: the owner.
            unsafe { cert::with_cert(owner, f) }.unwrap_or(0)
        }
        SSL_CTRL_GET_VERIFY_CERT_STORE | SSL_CTRL_GET_CHAIN_CERT_STORE => {
            let chain = cmd == SSL_CTRL_GET_CHAIN_CERT_STORE;
            // SAFETY: the owner.
            let st = unsafe {
                cert::with_cert(
                    owner,
                    |c| if chain { c.chain_store } else { c.verify_store },
                )
            }
            .unwrap_or(ptr::null_mut());
            // SAFETY: the caller's slot.
            unsafe { parg.cast::<*mut X509_STORE>().write(st) };
            1
        }
        SSL_CTRL_SET_DH_AUTO => {
            // SAFETY: the owner.
            unsafe {
                cert::with_cert(owner, |c| {
                    c.dh_tmp_auto = c_int::try_from(larg).unwrap_or(1)
                })
            };
            1
        }
        SSL_CTRL_CERT_FLAGS => {
            // SAFETY: the owner.
            let f = unsafe {
                cert::with_cert(owner, |c| {
                    c.cert_flags |= u32::try_from(larg).unwrap_or(0);
                    c.cert_flags
                })
            };
            return Some(c_long::from(f.unwrap_or(0)));
        }
        SSL_CTRL_CLEAR_CERT_FLAGS => {
            // SAFETY: the owner.
            let f = unsafe {
                cert::with_cert(owner, |c| {
                    c.cert_flags &= !u32::try_from(larg).unwrap_or(0);
                    c.cert_flags
                })
            };
            return Some(c_long::from(f.unwrap_or(0)));
        }
        _ => return None,
    };
    Some(c_long::from(r))
}

/// The ctrl commands OpenSSL handles that rustyssl doesn't yet: they abort (security rule
/// 10) rather than report a failure OpenSSL wouldn't.
pub(crate) fn unimplemented_ctrl(cmd: c_int) -> bool {
    use rustyssl_abi::{
        SSL_CTRL_BUILD_CERT_CHAIN, SSL_CTRL_SET_CLIENT_CERT_TYPES, SSL_CTRL_SET_TMP_DH,
    };
    matches!(
        cmd,
        SSL_CTRL_SET_TMP_DH | SSL_CTRL_SET_CLIENT_CERT_TYPES | SSL_CTRL_BUILD_CERT_CHAIN
    )
}

ffi_export! {
    /// The context's control commands (`SSL_CTX_ctrl`, `ssl3_ctx_ctrl`): the numbers and
    /// settings behind the `SSL_CTX_*` macros, with OpenSSL's return values; 0 for an unknown
    /// command or a NULL context.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `parg` is what `cmd` documents.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_ctrl(c: *mut SSL_CTX, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_SSL
    {
        const F: &str = "SSL_CTX_ctrl";
        // SAFETY: the caller's guarantee (the group and signature algorithm lists, with the
        // syntax checks made with no context).
        if let Some(r) = unsafe { super::lists::ctx_ctrl(c, cmd, larg, parg) } {
            return r;
        }
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx(c) }) else { return 0 };
        if unimplemented_ctrl(cmd) {
            crate::stub::unimplemented(&format!("SSL_CTX_ctrl command {cmd}"));
        }
        // SAFETY: the live context; the caller's argument.
        if let Some(r) = unsafe { cert_ctrl(Owner::Ctx(c), cmd, larg, parg) } {
            return r;
        }
        let mut st = x.state();
        match cmd {
            SSL_CTRL_GET_READ_AHEAD => c_long::from(st.read_ahead),
            SSL_CTRL_SET_READ_AHEAD => {
                let old = st.read_ahead;
                st.read_ahead = c_int::try_from(larg).unwrap_or(1);
                c_long::from(old)
            }
            SSL_CTRL_SET_MSG_CALLBACK_ARG => {
                st.msg_callback_arg = parg;
                1
            }
            SSL_CTRL_GET_MAX_CERT_LIST => as_long(st.max_cert_list),
            SSL_CTRL_SET_MAX_CERT_LIST => match non_negative(larg) {
                Some(v) => as_long(core::mem::replace(&mut st.max_cert_list, v)),
                None => 0,
            },
            SSL_CTRL_SET_SESS_CACHE_SIZE => match non_negative(larg) {
                Some(v) => as_long(core::mem::replace(&mut st.session_cache_size, v)),
                None => 0,
            },
            SSL_CTRL_GET_SESS_CACHE_SIZE => as_long(st.session_cache_size),
            SSL_CTRL_SET_SESS_CACHE_MODE => {
                let old = st.session_cache_mode;
                st.session_cache_mode = u32::try_from(larg & 0xffff_ffff).unwrap_or(0);
                c_long::from(old)
            }
            SSL_CTRL_GET_SESS_CACHE_MODE => c_long::from(st.session_cache_mode),
            // The session cache's statistics (`sess_cache`).
            SSL_CTRL_SESS_NUMBER | SSL_CTRL_SESS_CONNECT | SSL_CTRL_SESS_CONNECT_GOOD
            | SSL_CTRL_SESS_CONNECT_RENEGOTIATE | SSL_CTRL_SESS_ACCEPT | SSL_CTRL_SESS_ACCEPT_GOOD
            | SSL_CTRL_SESS_ACCEPT_RENEGOTIATE | SSL_CTRL_SESS_HIT | SSL_CTRL_SESS_CB_HIT
            | SSL_CTRL_SESS_MISSES | SSL_CTRL_SESS_TIMEOUTS | SSL_CTRL_SESS_CACHE_FULL => {
                super::sess_cache::stat_ctrl(x, cmd).unwrap_or(0)
            }
            SSL_CTRL_MODE => {
                st.mode |= u32::try_from(larg & 0xffff_ffff).unwrap_or(0);
                c_long::from(st.mode)
            }
            SSL_CTRL_CLEAR_MODE => {
                st.mode &= !u32::try_from(larg & 0xffff_ffff).unwrap_or(0);
                c_long::from(st.mode)
            }
            SSL_CTRL_SET_MAX_SEND_FRAGMENT => {
                if larg < 512 || larg > c_long::from(SSL3_RT_MAX_PLAIN_LENGTH) {
                    return 0;
                }
                st.max_send_fragment = non_negative(larg).unwrap_or(0);
                if st.max_send_fragment < st.split_send_fragment {
                    st.split_send_fragment = st.max_send_fragment;
                }
                1
            }
            SSL_CTRL_SET_SPLIT_SEND_FRAGMENT => match non_negative(larg) {
                Some(v) if v != 0 && v <= st.max_send_fragment => {
                    st.split_send_fragment = v;
                    1
                }
                _ => 0,
            },
            SSL_CTRL_SET_MAX_PIPELINES => {
                if larg < 1 || larg > c_long::from(SSL_MAX_PIPELINES) {
                    return 0;
                }
                st.max_pipelines = non_negative(larg).unwrap_or(1);
                1
            }
            SSL_CTRL_SET_MIN_PROTO_VERSION | SSL_CTRL_SET_MAX_PROTO_VERSION => {
                let Ok(v) = c_int::try_from(larg) else { return 0 };
                let method_version = st.method.version;
                if cmd == SSL_CTRL_SET_MIN_PROTO_VERSION {
                    c_long::from(check_allowed_versions(v, st.max_proto_version) != 0 && set_version_bound(method_version, v, &mut st.min_proto_version) != 0)
                } else {
                    c_long::from(check_allowed_versions(st.min_proto_version, v) != 0 && set_version_bound(method_version, v, &mut st.max_proto_version) != 0)
                }
            }
            SSL_CTRL_GET_MIN_PROTO_VERSION => c_long::from(st.min_proto_version),
            SSL_CTRL_GET_MAX_PROTO_VERSION => c_long::from(st.max_proto_version),
            SSL_CTRL_SET_TMP_DH_CB => {
                err::raise(ERR_LIB_SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, F);
                0
            }
            SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG => {
                st.servername_arg = parg;
                1
            }
            SSL_CTRL_SET_TLSEXT_TICKET_KEYS | SSL_CTRL_GET_TLSEXT_TICKET_KEYS => {
                const LEN: usize = TICK_KEY_NAME_LEN + 2 * TICK_KEY_LEN;
                if parg.is_null() {
                    return as_long(LEN);
                }
                if non_negative(larg) != Some(LEN) {
                    drop(st);
                    err::raise(ERR_LIB_SSL, SSL_R_INVALID_TICKET_KEYS_LENGTH, F);
                    return 0;
                }
                // SAFETY: the caller's buffer of `LEN` octets.
                let keys = unsafe { core::slice::from_raw_parts_mut(parg.cast::<u8>(), LEN) };
                let (name, rest) = keys.split_at_mut(TICK_KEY_NAME_LEN);
                let (hmac, aes) = rest.split_at_mut(TICK_KEY_LEN);
                if cmd == SSL_CTRL_SET_TLSEXT_TICKET_KEYS {
                    st.tick_key_name.copy_from_slice(name);
                    st.tick_hmac_key.copy_from_slice(hmac);
                    st.tick_aes_key.copy_from_slice(aes);
                } else {
                    name.copy_from_slice(&st.tick_key_name);
                    hmac.copy_from_slice(&st.tick_hmac_key);
                    aes.copy_from_slice(&st.tick_aes_key);
                }
                1
            }
            SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE => c_long::from(st.status_type),
            SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE => {
                st.status_type = c_int::try_from(larg).unwrap_or(TLSEXT_STATUSTYPE_NOTHING);
                1
            }
            SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG => {
                st.status_arg = parg;
                1
            }
            SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG => {
                // SAFETY: the caller's slot.
                unsafe { parg.cast::<*mut c_void>().write(st.status_arg) };
                1
            }
            SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB => {
                // SAFETY: the caller's slot for the callback.
                unsafe { parg.cast::<AnyCb>().write(st.status_cb) };
                1
            }
            SSL_CTRL_SET_TLS_EXT_SRP_USERNAME => {
                st.srp.enabled = true;
                st.srp.login = None;
                if parg.is_null() {
                    return 1;
                }
                // SAFETY: the caller's string.
                let name = unsafe { core::ffi::CStr::from_ptr(parg.cast::<c_char>()) };
                if name.is_empty() || name.count_bytes() > 255 {
                    drop(st);
                    err::raise(ERR_LIB_SSL, SSL_R_INVALID_SRP_USERNAME, F);
                    return 0;
                }
                st.srp.login = Some(name.to_owned());
                1
            }
            SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD => {
                st.srp.pwd_from_info = true;
                if parg.is_null() {
                    // OpenSSL strdups the NULL and fails (with ERR_R_INTERNAL_ERROR).
                    st.srp.info = None;
                    drop(st);
                    err::raise(ERR_LIB_SSL, rustyssl_abi::ERR_R_INTERNAL_ERROR, F);
                    return 0;
                }
                // SAFETY: the caller's string.
                st.srp.info = Some(unsafe { core::ffi::CStr::from_ptr(parg.cast::<c_char>()) }.to_owned());
                1
            }
            SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH => {
                st.srp.strength = c_int::try_from(larg).unwrap_or(0);
                1
            }
            SSL_CTRL_EXTRA_CHAIN_CERT => {
                if st.extra_certs.is_null() {
                    // SAFETY: no preconditions.
                    st.extra_certs = unsafe { OPENSSL_sk_new_null() }.cast();
                }
                // SAFETY: the list, or NULL (which fails); the caller's certificate, taken.
                if st.extra_certs.is_null() || unsafe { OPENSSL_sk_push(st.extra_certs.cast(), parg) } == 0 {
                    drop(st);
                    err::raise(ERR_LIB_SSL, ERR_R_CRYPTO_LIB, F);
                    return 0;
                }
                1
            }
            SSL_CTRL_GET_EXTRA_CHAIN_CERTS => {
                let v = if st.extra_certs.is_null() && larg == 0 {
                    st.cert.current().map_or(ptr::null_mut(), |p| p.chain)
                } else {
                    st.extra_certs
                };
                // SAFETY: the caller's slot.
                unsafe { parg.cast::<*mut stack_st_X509>().write(v) };
                1
            }
            SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS => {
                let old = core::mem::replace(&mut st.extra_certs, ptr::null_mut());
                drop(st);
                // SAFETY: our own list, or NULL, freed after the lock.
                unsafe { OSSL_STACK_OF_X509_free(old) };
                1
            }
            SSL_CTRL_SET_CURRENT_CERT => c_long::from(st.cert.set_current(larg)),
            _ => 0,
        }
    }
}

ffi_export! {
    /// The context's callback commands (`SSL_CTX_callback_ctrl`, `ssl3_ctx_callback_ctrl`):
    /// stores the callback; 1, or 0 for an unknown command or a NULL context.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `fp` NULL or a callback of the type `cmd` documents.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_callback_ctrl(c: *mut SSL_CTX, cmd: c_int, fp: Option<unsafe extern "C" fn()>) -> c_long
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx(c) }) else { return 0 };
        let mut st = x.state();
        match cmd {
            // SAFETY: the caller passes the message callback's type, as the C cast does.
            SSL_CTRL_SET_MSG_CALLBACK => st.msg_callback = unsafe { core::mem::transmute::<AnyCb, MsgCb>(fp) },
            // SAFETY: as above, the temporary DH callback.
            SSL_CTRL_SET_TMP_DH_CB => st.cert.dh_tmp_cb = unsafe { core::mem::transmute::<AnyCb, super::types::TmpDhCb>(fp) },
            SSL_CTRL_SET_TLSEXT_SERVERNAME_CB => st.servername_cb = fp,
            SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB => st.status_cb = fp,
            SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB => st.ticket_key_cb = fp,
            SSL_CTRL_SET_SRP_VERIFY_PARAM_CB => {
                st.srp.enabled = true;
                // SAFETY: as above, the parameter check.
                st.srp.verify_param_cb = unsafe { core::mem::transmute::<AnyCb, SrpVerifyParamCb>(fp) };
            }
            SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB => {
                st.srp.enabled = true;
                // SAFETY: as above, the username callback.
                st.srp.username_cb = unsafe { core::mem::transmute::<AnyCb, SrpUsernameCb>(fp) };
            }
            SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB => {
                st.srp.enabled = true;
                st.srp.pwd_from_info = false;
                // SAFETY: as above, the password callback.
                st.srp.give_client_pwd_cb = unsafe { core::mem::transmute::<AnyCb, SrpClientPwdCb>(fp) };
            }
            // SAFETY: as above, the not-resumable callback.
            SSL_CTRL_SET_NOT_RESUMABLE_SESS_CB => st.not_resumable_session_cb = unsafe { core::mem::transmute::<AnyCb, NotResumableCb>(fp) },
            _ => return 0,
        }
        1
    }
}

/// The context's certificate store, its library context and properties (for loading into it).
///
/// # Safety
/// `c` is NULL or a live context.
unsafe fn store_of(
    c: *const SSL_CTX,
) -> Option<(*mut X509_STORE, *mut OSSL_LIB_CTX, *const c_char)> {
    // SAFETY: the caller's guarantee.
    let x = unsafe { ctx(c) }?;
    let store = x.state().cert_store;
    Some((store, x.libctx, x.propq_ptr()))
}

ffi_export! {
    /// The default trusted locations into the store (`X509_STORE_set_default_paths_ex`).
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_default_verify_paths(c: *mut SSL_CTX) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some((store, libctx, propq)) = (unsafe { store_of(c) }) else { return 0 };
        // SAFETY: the context's store, library context, and properties.
        unsafe { crate::x509::store::X509_STORE_set_default_paths_ex(store, libctx, propq) }
    }
}

/// Adds a lookup to the context's store and loads its default location, ignoring errors (it
/// may not exist): 1, or 0 if the lookup couldn't be added.
///
/// # Safety
/// `c` is NULL or a live context; `method` a lookup method.
unsafe fn default_location(
    c: *const SSL_CTX,
    method: *mut rustyssl_abi::X509_LOOKUP_METHOD,
    cmd: c_int,
) -> c_int {
    use crate::x509::lookup::X509_LOOKUP_ctrl_ex;
    use crate::x509::store::X509_STORE_add_lookup;
    // SAFETY: the caller's guarantee.
    let Some((store, libctx, propq)) = (unsafe { store_of(c) }) else {
        return 0;
    };
    // SAFETY: the store; the method.
    let lookup = unsafe { X509_STORE_add_lookup(store, method) };
    if lookup.is_null() {
        return 0;
    }
    // SAFETY: no preconditions.
    unsafe { crate::err::ERR_set_mark() };
    let argl = c_long::from(rustyssl_abi::X509_FILETYPE_DEFAULT);
    // SAFETY: the store's lookup; NULL for the default location; the context's library context.
    unsafe {
        X509_LOOKUP_ctrl_ex(
            lookup,
            cmd,
            ptr::null(),
            argl,
            ptr::null_mut(),
            libctx,
            propq,
        )
    };
    // SAFETY: no preconditions.
    unsafe { crate::err::ERR_pop_to_mark() };
    1
}

ffi_export! {
    /// The default certificate directory (as a hashed directory) into the store; errors are
    /// ignored. 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_default_verify_dir(c: *mut SSL_CTX) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: no preconditions.
        let m = unsafe { crate::x509::lookup::X509_LOOKUP_hash_dir() };
        // SAFETY: the caller's guarantee; the method.
        unsafe { default_location(c, m, rustyssl_abi::X509_L_ADD_DIR) }
    }
}

ffi_export! {
    /// The default certificate file into the store; errors are ignored. 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_default_verify_file(c: *mut SSL_CTX) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: no preconditions.
        let m = unsafe { crate::x509::lookup::X509_LOOKUP_file() };
        // SAFETY: the caller's guarantee; the method.
        unsafe { default_location(c, m, rustyssl_abi::X509_L_FILE_LOAD) }
    }
}

ffi_export! {
    /// The default certificate store URI into the store; errors are ignored. 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_default_verify_store(c: *mut SSL_CTX) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: no preconditions.
        let m = unsafe { crate::x509::lookup::X509_LOOKUP_store() };
        // SAFETY: the caller's guarantee; the method.
        unsafe { default_location(c, m, rustyssl_abi::X509_L_ADD_STORE) }
    }
}

ffi_export! {
    /// Loads trusted certificates and CRLs from `cafile` into the store: 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `cafile` NULL or a path.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_load_verify_file(c: *mut SSL_CTX, cafile: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some((store, libctx, propq)) = (unsafe { store_of(c) }) else { return 0 };
        // SAFETY: the context's store; the caller's path.
        unsafe { crate::x509::store::X509_STORE_load_file_ex(store, cafile, libctx, propq) }
    }
}

ffi_export! {
    /// Adds `capath` as a hashed directory to the store: 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `capath` NULL or a path.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_load_verify_dir(c: *mut SSL_CTX, capath: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some((store, _, _)) = (unsafe { store_of(c) }) else { return 0 };
        // SAFETY: the context's store; the caller's path.
        unsafe { crate::x509::store::X509_STORE_load_path(store, capath) }
    }
}

ffi_export! {
    /// Adds the URI `castore` to the store: 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `castore` NULL or a URI.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_load_verify_store(c: *mut SSL_CTX, castore: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some((store, libctx, propq)) = (unsafe { store_of(c) }) else { return 0 };
        // SAFETY: the context's store; the caller's URI.
        unsafe { crate::x509::store::X509_STORE_load_store_ex(store, castore, libctx, propq) }
    }
}

ffi_export! {
    /// `cafile` and then `capath` into the store (0 if both are NULL): 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; the paths NULL or strings.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_load_verify_locations(c: *mut SSL_CTX, cafile: *const c_char, capath: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        if cafile.is_null() && capath.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        if !cafile.is_null() && unsafe { rustyssl_private_SSL_CTX_load_verify_file(c, cafile) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        if !capath.is_null() && unsafe { rustyssl_private_SSL_CTX_load_verify_dir(c, capath) } == 0 {
            return 0;
        }
        1
    }
}

ffi_export! {
    /// The context's certificate store (no reference taken), or NULL.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_get_cert_store(c: *const SSL_CTX) -> *mut X509_STORE
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx(c) }.map_or(ptr::null_mut(), |x| x.state().cert_store)
    }
}

ffi_export! {
    /// Replaces the store with `store` (taking the caller's reference) and frees the old one.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `store` NULL or a live store whose reference it takes.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_cert_store(c: *mut SSL_CTX, store: *mut X509_STORE)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx(c) }) else { return };
        let old = core::mem::replace(&mut x.state().cert_store, store);
        // SAFETY: our old reference, freed outside the lock.
        unsafe { X509_STORE_free(old) };
    }
}

ffi_export! {
    /// As `SSL_CTX_set_cert_store`, taking a new reference to `store`.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `store` NULL or a live store.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set1_cert_store(c: *mut SSL_CTX, store: *mut X509_STORE)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's store.
        if !store.is_null() && unsafe { crate::x509::store::X509_STORE_up_ref(store) } == 0 {
            return;
        }
        // SAFETY: the caller's guarantee; the new reference.
        unsafe { rustyssl_private_SSL_CTX_set_cert_store(c, store) };
    }
}

ffi_export! {
    /// The context's verification parameters (`get0`), or NULL.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_get0_param(c: *mut SSL_CTX) -> *mut X509_VERIFY_PARAM
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx(c) }.map_or(ptr::null_mut(), |x| x.param)
    }
}

ffi_export! {
    /// Copies `vpm` into the context's parameters: 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `vpm` NULL or live parameters.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set1_param(c: *mut SSL_CTX, vpm: *mut X509_VERIFY_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx(c) }) else { return 0 };
        // SAFETY: the context's parameters; the caller's.
        unsafe { crate::x509::vpm::X509_VERIFY_PARAM_set1(x.param, vpm) }
    }
}

ffi_export! {
    /// The context's verification depth (its parameters'), or 0 for NULL.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_get_verify_depth(c: *const SSL_CTX) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx(c) }) else { return 0 };
        // SAFETY: the context's parameters.
        unsafe { crate::x509::vpm::X509_VERIFY_PARAM_get_depth(x.param) }
    }
}

ffi_export! {
    /// Sets the context's verification depth.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_verify_depth(c: *mut SSL_CTX, depth: c_int)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx(c) }) else { return };
        // SAFETY: the context's parameters.
        unsafe { crate::x509::vpm::X509_VERIFY_PARAM_set_depth(x.param, depth) };
    }
}

ffi_export! {
    /// Sets the purpose checked in verification: 1, or 0 for an unknown one.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_purpose(c: *mut SSL_CTX, purpose: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx(c) }) else { return 0 };
        // SAFETY: the context's parameters.
        unsafe { crate::x509::vpm::X509_VERIFY_PARAM_set_purpose(x.param, purpose) }
    }
}

ffi_export! {
    /// Sets the trust checked in verification: 1, or 0 for an unknown one.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_trust(c: *mut SSL_CTX, trust: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx(c) }) else { return 0 };
        // SAFETY: the context's parameters.
        unsafe { crate::x509::vpm::X509_VERIFY_PARAM_set_trust(x.param, trust) }
    }
}

ffi_export! {
    /// Stores `arg` in the context's application data at `idx`: 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_ex_data(c: *mut SSL_CTX, idx: c_int, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx(c) }) else { return 0 };
        // SAFETY: the context's application data.
        unsafe { crate::ex_data::CRYPTO_set_ex_data(x.ex_data(), idx, arg) }
    }
}

ffi_export! {
    /// The context's application data at `idx`, or NULL.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_get_ex_data(c: *const SSL_CTX, idx: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx(c) }) else { return ptr::null_mut() };
        // SAFETY: the context's application data.
        unsafe { crate::ex_data::CRYPTO_get_ex_data(x.ex_data(), idx) }
    }
}

ffi_export! {
    /// Sets the session ID context (up to 32 octets): 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `sid_ctx` points to `sid_ctx_len` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_session_id_context(c: *mut SSL_CTX, sid_ctx: *const u8, sid_ctx_len: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { sid_ctx_of(sid_ctx, sid_ctx_len, "SSL_CTX_set_session_id_context") }) else { return 0 };
        // SAFETY: as above.
        let Some(x) = (unsafe { ctx(c) }) else { return 0 };
        x.state().sid_ctx = v;
        1
    }
}

/// A session ID context from the caller, at most `SSL_MAX_SID_CTX_LENGTH` octets (raising
/// `SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG` otherwise).
///
/// # Safety
/// `p` points to `len` octets (or `len` is 0).
pub(crate) unsafe fn sid_ctx_of(p: *const u8, len: c_uint, f: &str) -> Option<Vec<u8>> {
    let n = usize::try_from(len).ok()?;
    if n > usize::try_from(rustyssl_abi::SSL_MAX_SID_CTX_LENGTH).unwrap_or(32) {
        err::raise(
            ERR_LIB_SSL,
            rustyssl_abi::SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG,
            f,
        );
        return None;
    }
    if n == 0 || p.is_null() {
        return Some(Vec::new());
    }
    // SAFETY: the caller's `n` octets.
    Some(unsafe { core::slice::from_raw_parts(p, n) }.to_vec())
}

ffi_export! {
    /// The session timeout in seconds; sets `t` and returns the previous one.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_timeout(c: *mut SSL_CTX, t: c_long) -> c_long
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx(c) }) else { return 0 };
        core::mem::replace(&mut x.state().session_timeout, t)
    }
}

ffi_export! {
    /// The session timeout in seconds, or 0 for NULL.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_get_timeout(c: *const SSL_CTX) -> c_long
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx(c) }.map_or(0, |x| x.state().session_timeout)
    }
}

ffi_export! {
    /// Sets the ALPN protocols offered (wire format: non-empty, length-prefixed names; NULL or
    /// empty clears them): **0 on success**, 1 for an invalid list, as OpenSSL.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `protos` points to `protos_len` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_alpn_protos(c: *mut SSL_CTX, protos: *const u8, protos_len: c_uint) -> c_int
    where failure = 1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { alpn_of(protos, protos_len) }) else { return 1 };
        // SAFETY: as above.
        let Some(x) = (unsafe { ctx(c) }) else { return 1 };
        x.state().alpn = v;
        0
    }
}

/// `alpn_value_ok`: the caller's list if it is valid (`Some(empty)` clears), `None` if not.
///
/// # Safety
/// `p` points to `len` octets (or is NULL).
pub(crate) unsafe fn alpn_of(p: *const u8, len: c_uint) -> Option<Vec<u8>> {
    let n = usize::try_from(len).ok()?;
    if n == 0 || p.is_null() {
        return Some(Vec::new());
    }
    // SAFETY: the caller's `n` octets.
    let v = unsafe { core::slice::from_raw_parts(p, n) };
    if n < 2 {
        return None;
    }
    let mut rest = v;
    while let Some((&l, tail)) = rest.split_first() {
        if l == 0 {
            return None;
        }
        rest = tail.get(usize::from(l)..)?;
    }
    Some(v.to_vec())
}

ffi_export! {
    /// The maximum fragment length extension's mode (`TLSEXT_max_fragment_length_*`): 1, or 0
    /// for a bad mode.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_tlsext_max_fragment_length(c: *mut SSL_CTX, mode: u8) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        if !mfl_ok(mode, "SSL_CTX_set_tlsext_max_fragment_length") {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx(c) }) else { return 0 };
        x.state().max_fragment_len_mode = mode;
        1
    }
}

/// Whether `mode` is a maximum fragment length mode (or disabled), raising
/// `SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH` if not.
pub(crate) fn mfl_ok(mode: u8, f: &str) -> bool {
    let ok = c_int::from(mode) == rustyssl_abi::TLSEXT_max_fragment_length_DISABLED
        || (rustyssl_abi::TLSEXT_max_fragment_length_512
            ..=rustyssl_abi::TLSEXT_max_fragment_length_4096)
            .contains(&c_int::from(mode));
    if !ok {
        err::raise(
            ERR_LIB_SSL,
            rustyssl_abi::SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH,
            f,
        );
    }
    ok
}

ffi_export! {
    /// Sets record padding to multiples of `app_block_size` for application data and
    /// `hs_block_size` for the handshake (0 or 1: none): 1, or 0 for a size above 16384.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_block_padding_ex(c: *mut SSL_CTX, app_block_size: usize, hs_block_size: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let (Some(a), Some(h)) = (padding(app_block_size), padding(hs_block_size)) else { return 0 };
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx(c) }) else { return 0 };
        let mut st = x.state();
        st.block_padding = a;
        st.hs_padding = h;
        1
    }
}

ffi_export! {
    /// `SSL_CTX_set_block_padding_ex` with one size for both.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_block_padding(c: *mut SSL_CTX, block_size: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { rustyssl_private_SSL_CTX_set_block_padding_ex(c, block_size, block_size) }
    }
}

/// A padding block size as stored (1 means none), or `None` above a record's plaintext.
pub(crate) fn padding(size: usize) -> Option<usize> {
    match size {
        1 => Some(0),
        n if n <= usize::try_from(SSL3_RT_MAX_PLAIN_LENGTH).unwrap_or(0) => Some(n),
        _ => None,
    }
}

ffi_export! {
    /// The PSK identity hint (at most 256 octets; NULL clears it): 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `identity_hint` NULL or a string.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_use_psk_identity_hint(c: *mut SSL_CTX, identity_hint: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(h) = (unsafe { hint_of(identity_hint, "SSL_CTX_use_psk_identity_hint") }) else { return 0 };
        // SAFETY: as above.
        let Some(x) = (unsafe { ctx(c) }) else { return 0 };
        x.state().cert.psk_identity_hint = h;
        1
    }
}

/// A PSK identity hint from the caller (`Some(None)` clears it), `None` if too long.
///
/// # Safety
/// `p` is NULL or a string.
pub(crate) unsafe fn hint_of(p: *const c_char, f: &str) -> Option<Option<CString>> {
    if p.is_null() {
        return Some(None);
    }
    // SAFETY: the caller's string.
    let s = unsafe { core::ffi::CStr::from_ptr(p) };
    if s.count_bytes() > usize::try_from(rustyssl_abi::PSK_MAX_IDENTITY_LEN).unwrap_or(256) {
        err::raise(ERR_LIB_SSL, rustyssl_abi::SSL_R_DATA_LENGTH_TOO_LONG, f);
        return None;
    }
    Some(Some(s.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_bounds_follow_the_reference() {
        assert_eq!(check_allowed_versions(0x200, 0), 0);
        assert_eq!(check_allowed_versions(SSL3_VERSION, 0), 1);
        assert_eq!(
            check_allowed_versions(rustyssl_abi::TLS1_2_VERSION, DTLS1_2_VERSION),
            0
        );
        assert_eq!(check_allowed_versions(DTLS1_BAD_VER, 0), 1);
        let mut b = 0;
        assert_eq!(set_version_bound(TLS_ANY_VERSION, 0x305, &mut b), 0);
        assert_eq!(set_version_bound(TLS_ANY_VERSION, DTLS1_VERSION, &mut b), 1);
        assert_eq!(b, 0);
        assert_eq!(
            set_version_bound(DTLS_ANY_VERSION, DTLS1_VERSION, &mut b),
            1
        );
        assert_eq!(b, DTLS1_VERSION);
        assert_eq!(set_version_bound(DTLS_ANY_VERSION, 0xfefc, &mut b), 0);
        assert_eq!(
            set_version_bound(
                rustyssl_abi::TLS1_2_VERSION,
                rustyssl_abi::TLS1_VERSION,
                &mut b
            ),
            1
        );
        assert_eq!(b, DTLS1_VERSION);
    }

    #[test]
    fn alpn_lists_are_checked() {
        let ok = [2, b'h', b'2', 1, b'x'];
        // SAFETY: the arrays' octets.
        assert_eq!(unsafe { alpn_of(ok.as_ptr(), 5) }, Some(ok.to_vec()));
        // SAFETY: as above.
        assert_eq!(unsafe { alpn_of(ok.as_ptr(), 4) }, None);
        // SAFETY: as above.
        assert_eq!(unsafe { alpn_of([2, b'h', b'2', 0].as_ptr(), 4) }, None);
        // SAFETY: as above.
        assert_eq!(unsafe { alpn_of(ok.as_ptr(), 1) }, None);
        // SAFETY: NULL clears.
        assert_eq!(unsafe { alpn_of(ptr::null(), 0) }, Some(Vec::new()));
    }

    #[test]
    fn dtls_versions_count_down() {
        assert!(dtls_lt(DTLS1_VERSION, DTLS1_2_VERSION));
        assert!(!dtls_lt(DTLS1_2_VERSION, DTLS1_VERSION));
        assert!(dtls_lt(DTLS1_BAD_VER, DTLS1_VERSION));
    }
}

/// A `SSL_CTX_ctrl` command on `c` with a string argument, as `int`.
///
/// # Safety
/// `c` is NULL or a live context; `p` NULL or a NUL-terminated string.
unsafe fn srp_ctrl(c: *mut SSL_CTX, cmd: c_int, larg: c_long, p: *mut c_char) -> c_int {
    // SAFETY: the caller's guarantee.
    let r = unsafe { rustyssl_private_SSL_CTX_ctrl(c, cmd, larg, p.cast()) };
    c_int::try_from(r).unwrap_or(0)
}

/// Stores one SRP callback (or the callbacks' argument) on `c`: 1, or 0 for a NULL context.
///
/// # Safety
/// `c` is NULL or a live context.
unsafe fn set_srp(c: *mut SSL_CTX, f: impl FnOnce(&mut Srp)) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { ctx(c) }) else {
        return 0;
    };
    let mut st = x.state();
    st.srp.enabled = true;
    f(&mut st.srp);
    1
}

ffi_export! {
    /// `SSL_CTX_set_srp_username`: the client's SRP login (`SSL_CTRL_SET_TLS_EXT_SRP_USERNAME`).
    ///
    /// # Safety
    /// `c` is NULL or a live context; `name` NULL or a NUL-terminated string.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_srp_username(c: *mut SSL_CTX, name: *mut c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { srp_ctrl(c, SSL_CTRL_SET_TLS_EXT_SRP_USERNAME, 0, name) }
    }
}

ffi_export! {
    /// `SSL_CTX_set_srp_password`: the client's SRP password (`SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD`).
    ///
    /// # Safety
    /// `c` is NULL or a live context; `password` NULL or a NUL-terminated string.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_srp_password(c: *mut SSL_CTX, password: *mut c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { srp_ctrl(c, SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD, 0, password) }
    }
}

ffi_export! {
    /// `SSL_CTX_set_srp_strength`: the minimum SRP group size (`SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH`).
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_srp_strength(c: *mut SSL_CTX, strength: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { srp_ctrl(c, SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH, c_long::from(strength), ptr::null_mut()) }
    }
}

ffi_export! {
    /// `SSL_CTX_set_srp_cb_arg`: the argument the SRP callbacks get. Its command number,
    /// `SSL_CTRL_SET_SRP_ARG`, is `SSL_CTRL_CLEAR_MODE`'s, so (as in OpenSSL) it isn't
    /// reachable through `SSL_CTX_ctrl`.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_srp_cb_arg(c: *mut SSL_CTX, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_srp(c, |s| s.cb_arg = arg) }
    }
}

ffi_export! {
    /// `SSL_CTX_set_srp_username_callback`: the server's SRP username callback.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `cb` NULL or a function of this type.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_srp_username_callback(c: *mut SSL_CTX, cb: SrpUsernameCb) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_srp(c, |s| s.username_cb = cb) }
    }
}

ffi_export! {
    /// `SSL_CTX_set_srp_verify_param_callback`: the client's SRP parameter check.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `cb` NULL or a function of this type.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_srp_verify_param_callback(c: *mut SSL_CTX, cb: SrpVerifyParamCb) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_srp(c, |s| s.verify_param_cb = cb) }
    }
}

ffi_export! {
    /// `SSL_CTX_set_srp_client_pwd_callback`: the client's SRP password callback, which
    /// replaces a password set with `SSL_CTX_set_srp_password`.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `cb` NULL or a function of this type.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_srp_client_pwd_callback(c: *mut SSL_CTX, cb: SrpClientPwdCb) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe {
            set_srp(c, |s| {
                s.pwd_from_info = false;
                s.give_client_pwd_cb = cb;
            })
        }
    }
}
