//! The connection (`SSL`, `SSL_CONNECTION` in `ssl_lib.c`): the settings it copies from its
//! context at `SSL_new`, its role, its BIOs, and the state the handshake reports.
//!
//! **Where the handshake goes.** The sans-IO core (`rustyssl_tls`'s connection, ADR 0002)
//! becomes a field of [`SslState`] (`tls`), made by `SSL_set_connect_state`/`_accept_state`
//! or the first `SSL_do_handshake`, and reset by `SSL_clear`. The fields under "handshake
//! results" (`hand_state`, `in_init`, `version`, the randoms, the Finished messages, the
//! renegotiation counts, `hit`, `rwstate`, `shutdown`, `verify_result`) are what the
//! handshake updates as it reports events; until then they hold their idle values, which is
//! what OpenSSL reports before a handshake. Every getter that needs a session, a cipher, or
//! the peer's certificates stays an aborting stub until the handshake fills them.

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    BIO, BIO_C_GET_FD, BIO_C_SET_FD, BIO_NOCLOSE, BIO_TYPE_DESCRIPTOR, BIO_TYPE_SOCKET,
    CRYPTO_EX_DATA, CRYPTO_EX_INDEX_SSL, ERR_LIB_SSL, ERR_R_ASN1_LIB, ERR_R_BUF_LIB,
    ERR_R_PASSED_INVALID_ARGUMENT, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, ERR_R_SSL_LIB,
    OSSL_HANDSHAKE_STATE, SSL, SSL_CTRL_CLEAR_MODE, SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS,
    SSL_CTRL_GET_CLIENT_CERT_REQUEST, SSL_CTRL_GET_FLAGS, SSL_CTRL_GET_MAX_CERT_LIST,
    SSL_CTRL_GET_MAX_PROTO_VERSION, SSL_CTRL_GET_MIN_PROTO_VERSION,
    SSL_CTRL_GET_NUM_RENEGOTIATIONS, SSL_CTRL_GET_RAW_CIPHERLIST, SSL_CTRL_GET_READ_AHEAD,
    SSL_CTRL_GET_RI_SUPPORT, SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS,
    SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS, SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP,
    SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE, SSL_CTRL_GET_TOTAL_RENEGOTIATIONS, SSL_CTRL_MODE,
    SSL_CTRL_SET_CURRENT_CERT, SSL_CTRL_SET_MAX_CERT_LIST, SSL_CTRL_SET_MAX_PIPELINES,
    SSL_CTRL_SET_MAX_PROTO_VERSION, SSL_CTRL_SET_MAX_SEND_FRAGMENT, SSL_CTRL_SET_MIN_PROTO_VERSION,
    SSL_CTRL_SET_MSG_CALLBACK, SSL_CTRL_SET_MSG_CALLBACK_ARG, SSL_CTRL_SET_NOT_RESUMABLE_SESS_CB,
    SSL_CTRL_SET_READ_AHEAD, SSL_CTRL_SET_RETRY_VERIFY, SSL_CTRL_SET_SPLIT_SEND_FRAGMENT,
    SSL_CTRL_SET_TLSEXT_DEBUG_ARG, SSL_CTRL_SET_TLSEXT_DEBUG_CB, SSL_CTRL_SET_TLSEXT_HOSTNAME,
    SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS, SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS,
    SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP, SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE,
    SSL_CTRL_SET_TMP_DH_CB, SSL_CTX, SSL_MAX_PIPELINES, SSL_METHOD, SSL_NOTHING,
    SSL_R_NO_METHOD_SPECIFIED, SSL_R_NULL_SSL_CTX, SSL_R_SSL3_EXT_INVALID_SERVERNAME,
    SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE, SSL_RETRY_VERIFY, SSL_verify_cb,
    SSL3_RT_MAX_PLAIN_LENGTH, TLS_ST_BEFORE, TLSEXT_MAXLEN_host_name, TLSEXT_NAMETYPE_host_name,
    X509_V_OK, X509_VERIFY_PARAM, pem_password_cb, stack_st_X509_NAME,
};

use super::cert::{Cert, Owner};
use super::ctx::{self, Ctx, as_long, cert_ctrl, check_allowed_versions, set_version_bound};
use super::method::{DEFAULT_TIMEOUT, Method, method_of};
use super::types::{AnyCb, InfoCb, MsgCb, NotResumableCb, RecordPaddingCb, TLS_CIPHER_LEN};
use crate::bio::{BIO_ctrl, BIO_find_type, BIO_free_all, BIO_method_type, BIO_new, BIO_up_ref};
use crate::err;
use crate::ex_data::{CRYPTO_free_ex_data, CRYPTO_new_ex_data};
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::stack::OPENSSL_sk_pop_free;
use crate::x509::vpm::{X509_VERIFY_PARAM_free, X509_VERIFY_PARAM_inherit, X509_VERIFY_PARAM_new};

/// Which handshake the connection was set up for (`handshake_func`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    /// `SSL_set_connect_state` (or `SSL_connect`).
    Connect,
    /// `SSL_set_accept_state` (or `SSL_accept`).
    Accept,
}

/// A connection's settings and state, with OpenSSL's field names.
#[derive(Debug)]
pub(crate) struct SslState {
    /// The context (a reference held); `SSL_set_SSL_CTX` changes it.
    pub(crate) ctx: *mut SSL_CTX,
    /// The context it was made from (a reference held): sessions are cached there.
    pub(crate) session_ctx: *mut SSL_CTX,
    pub(crate) method: &'static Method,
    pub(crate) defltmeth: &'static Method,
    pub(crate) server: bool,
    pub(crate) handshake_func: Option<Role>,
    pub(crate) options: u64,
    pub(crate) mode: u32,
    pub(crate) min_proto_version: c_int,
    pub(crate) max_proto_version: c_int,
    pub(crate) max_cert_list: usize,
    pub(crate) max_early_data: u32,
    pub(crate) recv_max_early_data: u32,
    pub(crate) num_tickets: usize,
    pub(crate) pha_enabled: c_int,
    pub(crate) verify_mode: c_int,
    pub(crate) verify_callback: SSL_verify_cb,
    pub(crate) sid_ctx: Vec<u8>,
    pub(crate) quiet_shutdown: c_int,
    pub(crate) read_ahead: c_int,
    pub(crate) max_send_fragment: usize,
    pub(crate) split_send_fragment: usize,
    pub(crate) max_pipelines: usize,
    pub(crate) default_read_buf_len: usize,
    pub(crate) msg_callback: MsgCb,
    pub(crate) msg_callback_arg: *mut c_void,
    pub(crate) info_callback: InfoCb,
    pub(crate) record_padding_cb: RecordPaddingCb,
    pub(crate) record_padding_arg: *mut c_void,
    pub(crate) block_padding: usize,
    pub(crate) hs_padding: usize,
    pub(crate) max_fragment_len_mode: u8,
    pub(crate) status_type: c_int,
    /// The OCSP response to staple (owned C memory), and its length.
    pub(crate) ocsp_resp: *mut u8,
    pub(crate) ocsp_resp_len: usize,
    /// The OCSP request's extensions and responder IDs (the application's, not owned until
    /// the handshake uses them, as in OpenSSL).
    pub(crate) ocsp_exts: *mut c_void,
    pub(crate) ocsp_ids: *mut c_void,
    pub(crate) debug_cb: AnyCb,
    pub(crate) debug_arg: *mut c_void,
    pub(crate) not_resumable_session_cb: NotResumableCb,
    pub(crate) generate_session_id: rustyssl_abi::GEN_SESSION_CB,
    pub(crate) psk_client_callback: rustyssl_abi::SSL_psk_client_cb_func,
    pub(crate) psk_server_callback: rustyssl_abi::SSL_psk_server_cb_func,
    pub(crate) psk_find_session_cb: rustyssl_abi::SSL_psk_find_session_cb_func,
    pub(crate) psk_use_session_cb: rustyssl_abi::SSL_psk_use_session_cb_func,
    pub(crate) allow_early_data_cb: rustyssl_abi::SSL_allow_early_data_cb_fn,
    pub(crate) allow_early_data_cb_data: *mut c_void,
    pub(crate) async_cb: rustyssl_abi::SSL_async_callback_fn,
    pub(crate) async_cb_arg: *mut c_void,
    pub(crate) default_passwd_callback: pem_password_cb,
    pub(crate) default_passwd_callback_userdata: *mut c_void,
    pub(crate) alpn: Vec<u8>,
    /// The server name to send (`ext.hostname`).
    pub(crate) hostname: Option<CString>,
    pub(crate) ca_names: *mut stack_st_X509_NAME,
    pub(crate) client_ca_names: *mut stack_st_X509_NAME,
    pub(crate) cert: Cert,
    pub(crate) rbio: *mut BIO,
    pub(crate) wbio: *mut BIO,
    // Handshake results.
    pub(crate) version: c_int,
    pub(crate) client_version: c_int,
    pub(crate) hand_state: OSSL_HANDSHAKE_STATE,
    /// Whether the state machine is uninitialized (`MSG_FLOW_UNINITED`).
    pub(crate) flow_uninited: bool,
    pub(crate) in_init: bool,
    pub(crate) rwstate: c_int,
    pub(crate) shutdown: c_int,
    pub(crate) verify_result: c_long,
    /// CT validation (`ct_validation_callback`, the SCTs received).
    pub(crate) ct: super::ct::ConnCt,
    /// `SSL_set_tlsext_use_srtp`'s profiles (`srtp_profiles`).
    pub(crate) srtp: super::srtp::Profiles,
    pub(crate) hit: c_int,
    pub(crate) num_renegotiations: c_int,
    pub(crate) total_renegotiations: c_int,
    pub(crate) s3_flags: c_int,
    /// The EAP-FAST hooks (`super::eap`).
    pub(crate) eap: super::eap::Eap,
    pub(crate) send_connection_binding: c_int,
    pub(crate) client_random: [u8; 32],
    pub(crate) server_random: [u8; 32],
    pub(crate) finish_md: Vec<u8>,
    pub(crate) peer_finish_md: Vec<u8>,
    /// The CA names the peer sent (owned), or NULL.
    pub(crate) peer_ca_names: *mut stack_st_X509_NAME,
    /// The cipher lists, and the client's suites on a server (`cipher_list`, `peer_ciphers`, ...).
    pub(crate) ciphers: super::ciphers::CipherLists,
    /// The group and certificate type lists, copied from the context (`super::lists`).
    pub(crate) lists: super::lists::Lists,
    /// The protocol engine and what it hands the application (`super::io`).
    pub(crate) drv: super::io::Driver,
    /// The session (`session`) and the one a server's lookup found (`super::sess_cache`).
    pub(crate) sess: super::sess_cache::Slot,
}

// SAFETY: the raw pointers are owned references to OpenSSL objects (or the application's
// values it stores), used only under the connection's lock.
unsafe impl Send for SslState {}

impl Drop for SslState {
    fn drop(&mut self) {
        // A bad session leaves the cache while the contexts are still held.
        super::sess_cache::on_free(self);
        // SAFETY: our own lists and memory, each NULL or live.
        unsafe { OPENSSL_sk_pop_free(self.ca_names.cast(), Some(ctx::name_free)) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_pop_free(self.client_ca_names.cast(), Some(ctx::name_free)) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_pop_free(self.peer_ca_names.cast(), Some(ctx::name_free)) };
        // SAFETY: as above.
        unsafe { crate::mem::release(self.ocsp_resp.cast()) };
        // SAFETY: as above.
        unsafe { super::ocsp_req::free(self) };
        // The write BIO first, then the read BIO (BIO_free_all frees a chain only when its
        // first BIO's last reference goes).
        // SAFETY: our references, each NULL or live.
        unsafe { BIO_free_all(self.wbio) };
        // SAFETY: as above.
        unsafe { BIO_free_all(self.rbio) };
        // SAFETY: our references to the contexts.
        unsafe { ctx::rustyssl_private_SSL_CTX_free(self.session_ctx) };
        // SAFETY: as above.
        unsafe { ctx::rustyssl_private_SSL_CTX_free(self.ctx) };
    }
}

/// A connection (`SSL`, shared by reference).
pub(crate) struct Ssl {
    references: AtomicI32,
    /// The verification parameters (owned), at a fixed address for `SSL_get0_param`.
    pub(crate) param: *mut X509_VERIFY_PARAM,
    /// The application's data, at a fixed address for the `CRYPTO_*_ex_data` functions.
    ex_data: UnsafeCell<CRYPTO_EX_DATA>,
    state: Mutex<SslState>,
}

// SAFETY: as for `Ctx`: the settings are behind the mutex; the parameters and the application
// data are set up by the application before it shares the connection, as OpenSSL requires.
unsafe impl Send for Ssl {}
// SAFETY: as above.
unsafe impl Sync for Ssl {}

handle_type!(SSL => Ssl);

impl Drop for Ssl {
    fn drop(&mut self) {
        // SAFETY: our own parameters.
        unsafe { X509_VERIFY_PARAM_free(self.param) };
    }
}

impl Ssl {
    /// The state, locked.
    pub(crate) fn state(&self) -> MutexGuard<'_, SslState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The application's data.
    pub(crate) fn ex_data(&self) -> *mut CRYPTO_EX_DATA {
        self.ex_data.get()
    }
}

/// The connection behind `s`, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a live connection.
pub(crate) unsafe fn ssl<'a>(s: *const SSL) -> Option<&'a Ssl> {
    // SAFETY: the caller's guarantee.
    unsafe { SSL::get(s) }
}

/// The context of a connection's state (live while the connection holds its reference).
///
/// # Safety
/// `st` is a live connection's state.
pub(crate) unsafe fn ctx_of<'a>(st: &SslState) -> Option<&'a Ctx> {
    // SAFETY: the connection's reference keeps the context alive.
    unsafe { ctx::ctx(st.ctx) }
}

impl SslState {
    /// `ossl_statem_clear`: the state machine back to its start.
    pub(crate) fn statem_clear(&mut self) {
        self.hand_state = TLS_ST_BEFORE;
        self.flow_uninited = true;
        self.in_init = true;
    }

    /// `ossl_ssl_connection_reset` and the method's `ssl_clear`, for a connection with no
    /// handshake under way: the per-handshake state back to its start.
    pub(crate) fn reset(&mut self) {
        self.hit = 0;
        self.shutdown = 0;
        self.statem_clear();
        if !core::ptr::eq(self.method, self.defltmeth) {
            self.method = self.defltmeth;
        }
        self.client_version = self.method.version;
        self.version = self.method.idle_version();
        self.rwstate = SSL_NOTHING;
        self.num_renegotiations = 0;
        self.total_renegotiations = 0;
        self.s3_flags = 0;
        self.send_connection_binding = 0;
        self.client_random = [0; 32];
        self.server_random = [0; 32];
        self.finish_md.clear();
        self.peer_finish_md.clear();
    }
}

ffi_export! {
    /// A new connection with `ctx`'s settings, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_new(ctx: *mut SSL_CTX) -> *mut SSL
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        const F: &str = "SSL_new";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx::ctx(ctx) }) else {
            err::raise(ERR_LIB_SSL, SSL_R_NULL_SSL_CTX, F);
            return ptr::null_mut();
        };
        // SAFETY: no preconditions.
        let param = unsafe { X509_VERIFY_PARAM_new() };
        if param.is_null() {
            err::raise(ERR_LIB_SSL, ERR_R_ASN1_LIB, "ossl_ssl_connection_new_int");
            return ptr::null_mut();
        }
        // SAFETY: the new parameters; the context's.
        unsafe { X509_VERIFY_PARAM_inherit(param, c.param) };
        let state = {
            let cs = c.state();
            let Some(cert) = cs.cert.dup() else {
                drop(cs);
                err::raise(ERR_LIB_SSL, ERR_R_SSL_LIB, "ossl_ssl_connection_new_int");
                // SAFETY: made above.
                unsafe { X509_VERIFY_PARAM_free(param) };
                return ptr::null_mut();
            };
            let method = cs.method;
            let Some(ciphers) = super::ciphers::CipherLists::for_ssl(&cs.ciphers) else {
                drop(cs);
                err::raise(ERR_LIB_SSL, ERR_R_SSL_LIB, "ossl_ssl_connection_new_int");
                // SAFETY: made above.
                unsafe { X509_VERIFY_PARAM_free(param) };
                return ptr::null_mut();
            };
            let mut st = SslState {
                ctx,
                session_ctx: ctx,
                method,
                defltmeth: method,
                server: method.server,
                handshake_func: None,
                options: cs.options,
                mode: cs.mode,
                min_proto_version: cs.min_proto_version,
                max_proto_version: cs.max_proto_version,
                max_cert_list: cs.max_cert_list,
                max_early_data: cs.max_early_data,
                recv_max_early_data: cs.recv_max_early_data,
                num_tickets: cs.num_tickets,
                pha_enabled: cs.pha_enabled,
                verify_mode: cs.verify_mode,
                verify_callback: cs.default_verify_callback,
                sid_ctx: cs.sid_ctx.clone(),
                quiet_shutdown: cs.quiet_shutdown,
                read_ahead: cs.read_ahead,
                max_send_fragment: cs.max_send_fragment,
                split_send_fragment: cs.split_send_fragment,
                max_pipelines: cs.max_pipelines,
                default_read_buf_len: cs.default_read_buf_len,
                msg_callback: cs.msg_callback,
                msg_callback_arg: cs.msg_callback_arg,
                info_callback: None,
                record_padding_cb: cs.record_padding_cb,
                record_padding_arg: cs.record_padding_arg,
                block_padding: cs.block_padding,
                hs_padding: cs.hs_padding,
                max_fragment_len_mode: cs.max_fragment_len_mode,
                // `SSL_set_ct_validation_callback` from `SSL_new`: CT asks for OCSP too.
                status_type: if cs.ct.callback.is_some() {
                    rustyssl_abi::TLSEXT_STATUSTYPE_ocsp
                } else {
                    cs.status_type
                },
                ocsp_resp: ptr::null_mut(),
                ocsp_resp_len: 0,
                ocsp_exts: ptr::null_mut(),
                ocsp_ids: ptr::null_mut(),
                debug_cb: None,
                debug_arg: ptr::null_mut(),
                not_resumable_session_cb: cs.not_resumable_session_cb,
                generate_session_id: cs.generate_session_id,
                psk_client_callback: cs.psk_client_callback,
                psk_server_callback: cs.psk_server_callback,
                psk_find_session_cb: cs.psk_find_session_cb,
                psk_use_session_cb: cs.psk_use_session_cb,
                allow_early_data_cb: cs.allow_early_data_cb,
                allow_early_data_cb_data: cs.allow_early_data_cb_data,
                async_cb: cs.async_cb,
                async_cb_arg: cs.async_cb_arg,
                default_passwd_callback: cs.default_passwd_callback,
                default_passwd_callback_userdata: cs.default_passwd_callback_userdata,
                alpn: cs.alpn.clone(),
                hostname: None,
                ca_names: ptr::null_mut(),
                client_ca_names: ptr::null_mut(),
                cert,
                rbio: ptr::null_mut(),
                wbio: ptr::null_mut(),
                version: method.version,
                client_version: method.version,
                hand_state: TLS_ST_BEFORE,
                flow_uninited: true,
                in_init: true,
                rwstate: SSL_NOTHING,
                shutdown: 0,
                verify_result: c_long::from(X509_V_OK),
                ct: super::ct::ConnCt::new(cs.ct.callback, cs.ct.arg),
                srtp: super::srtp::Profiles::default(),
                hit: 0,
                num_renegotiations: 0,
                total_renegotiations: 0,
                s3_flags: 0,
                eap: super::eap::Eap::default(),
                send_connection_binding: 0,
                client_random: [0; 32],
                server_random: [0; 32],
                finish_md: Vec::new(),
                peer_finish_md: Vec::new(),
                peer_ca_names: ptr::null_mut(),
                ciphers,
                lists: cs.lists.for_ssl(),
                drv: super::io::Driver::default(),
                sess: super::sess_cache::Slot::default(),
            };
            st.reset();
            st
        };
        // The two references the connection holds: `ctx` and `session_ctx`.
        // SAFETY: the live context.
        unsafe { ctx::rustyssl_private_SSL_CTX_up_ref(ctx) };
        // SAFETY: as above.
        unsafe { ctx::rustyssl_private_SSL_CTX_up_ref(ctx) };
        let s = SSL::new_handle(Ssl {
            references: AtomicI32::new(1),
            param,
            // SAFETY: an all-zero `CRYPTO_EX_DATA` is the empty one `CRYPTO_new_ex_data` fills.
            ex_data: UnsafeCell::new(unsafe { core::mem::zeroed() }),
            state: Mutex::new(state),
        });
        // SAFETY: the new connection.
        let Some(x) = (unsafe { ssl(s) }) else { return ptr::null_mut() };
        // SAFETY: the new connection and its own application data.
        if unsafe { CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL, s.cast(), x.ex_data()) } == 0 {
            // SAFETY: the new connection's only reference.
            unsafe { SSL::free(s) };
            return ptr::null_mut();
        }
        s
    }
}

ffi_export! {
    /// Adds a reference: 1, or 0 for NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_up_ref(s: *mut SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        x.references.fetch_add(1, Ordering::AcqRel);
        // SAFETY: as above.
        c_int::from(unsafe { SSL::up_ref(s) })
    }
}

ffi_export! {
    /// Drops a reference; with the last, frees the application data and everything the
    /// connection holds (its BIOs included). Nothing for NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection whose reference the caller gives up.
    pub unsafe extern "C" fn rustyssl_private_SSL_free(s: *mut SSL)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(held) = (unsafe { SSL::hold(s) }) else { return };
        if held.references.fetch_sub(1, Ordering::AcqRel) == 1 {
            // SAFETY: the connection's own application data; its last reference.
            unsafe { CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL, s.cast(), held.ex_data()) };
        }
        // SAFETY: the caller's reference; the hold keeps the connection until this returns.
        unsafe { SSL::free(s) };
    }
}

ffi_export! {
    /// The connection's context (no reference taken), or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_SSL_CTX(s: *const SSL) -> *mut SSL_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl(s) }.map_or(ptr::null_mut(), |x| x.state().ctx)
    }
}

ffi_export! {
    /// Moves the connection to `ctx` (NULL: back to the one it was made from): it takes a
    /// copy of the new context's certificates, and its session ID context too if it still had
    /// the old context's. Returns the context now used, or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `ctx` NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_SSL_CTX(s: *mut SSL, ctx: *mut SSL_CTX) -> *mut SSL_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return ptr::null_mut() };
        let (old, target) = {
            let st = x.state();
            if st.ctx == ctx {
                return st.ctx;
            }
            (st.ctx, if ctx.is_null() { st.session_ctx } else { ctx })
        };
        // SAFETY: the caller's context, or the connection's own.
        let Some(newc) = (unsafe { ctx::ctx(target) }) else { return ptr::null_mut() };
        let (new_cert, new_sid) = {
            let cs = newc.state();
            (cs.cert.dup(), cs.sid_ctx.clone())
        };
        let Some(new_cert) = new_cert else { return ptr::null_mut() };
        // SAFETY: the old context, kept alive by the connection's reference.
        let old_sid = unsafe { ctx::ctx(old) }.map(|o| o.state().sid_ctx.clone());
        // SAFETY: the new context.
        if unsafe { ctx::rustyssl_private_SSL_CTX_up_ref(target) } == 0 {
            return ptr::null_mut();
        }
        let old_cert = {
            let mut st = x.state();
            if old_sid.as_ref() == Some(&st.sid_ctx) {
                st.sid_ctx = new_sid;
            }
            st.ctx = target;
            core::mem::replace(&mut st.cert, new_cert)
        };
        drop(old_cert);
        // SAFETY: the reference the connection held to the old context.
        unsafe { ctx::rustyssl_private_SSL_CTX_free(old) };
        target
    }
}

ffi_export! {
    /// Sets the connection up as a client: the role, a cleared shutdown and state machine.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_connect_state(s: *mut SSL)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return };
        let old = {
            let mut st = x.state();
            st.server = false;
            st.shutdown = 0;
            st.statem_clear();
            st.handshake_func = Some(Role::Connect);
            restart(&mut st)
        };
        // Freed with no lock held (ex_data callbacks).
        drop(old);
    }
}

/// `RECORD_LAYER_reset` after a handshake: the engine goes, with the records it buffered, so the
/// next handshake starts afresh (the session stays, to be resumed). What it held, to be freed
/// with no lock held.
fn restart(st: &mut SslState) -> Option<super::io::Driver> {
    st.drv.tls.as_ref()?;
    let kept = st.drv.clear();
    Some(core::mem::replace(&mut st.drv, kept))
}

ffi_export! {
    /// Sets the connection up as a server: the role, a cleared shutdown and state machine.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_accept_state(s: *mut SSL)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return };
        let old = {
            let mut st = x.state();
            st.server = true;
            st.shutdown = 0;
            st.statem_clear();
            st.handshake_func = Some(Role::Accept);
            restart(&mut st)
        };
        // Freed with no lock held (ex_data callbacks).
        drop(old);
    }
}

ffi_export! {
    /// Whether the connection is a server (before a role is set, whether its method can be
    /// one), or 0 for NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_is_server(s: *const SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl(s) }.map_or(0, |x| c_int::from(x.state().server))
    }
}

ffi_export! {
    /// Resets the connection for a new handshake (keeping its settings): 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_clear(s: *mut SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else {
            err::raise(ERR_LIB_SSL, SSL_R_NO_METHOD_SPECIFIED, "SSL_clear");
            return 0;
        };
        // A bad session goes (a good one stays, to be resumed).
        // SAFETY: the live connection; no lock is held.
        unsafe { super::sess_cache::on_clear(x) };
        // The engine goes with the handshake (the session's peer certificates and cipher stay);
        // it's freed with no lock held, since freeing what it holds may run ex_data callbacks.
        let (old, mcert) = {
            let mut st = x.state();
            st.reset();
            let kept = st.drv.clear();
            // The DANE verification's result goes (the records stay).
            let mcert = st.lists.dane.reset();
            (core::mem::replace(&mut st.drv, kept), mcert)
        };
        drop(old);
        // SAFETY: the DANE match's reference, or NULL.
        unsafe { crate::x509::cert::X509_free(mcert) };
        // SAFETY: the connection's parameters.
        unsafe { crate::x509::vpm::X509_VERIFY_PARAM_move_peername(x.param, ptr::null_mut()) };
        1
    }
}

ffi_export! {
    /// The connection's method, or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_ssl_method(s: *const SSL) -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl(s) }.map_or(ptr::null(), |x| x.state().method.handle())
    }
}

ffi_export! {
    /// The context's method, or NULL.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_get_ssl_method(c: *const SSL_CTX) -> *const SSL_METHOD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx::ctx(c) }.map_or(ptr::null(), |x| x.state().method.handle())
    }
}

ffi_export! {
    /// Switches the connection's method (its role stays): 1, or 0. A method of another
    /// version resets the per-handshake state, as OpenSSL's `ssl_init` does.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `meth` NULL or a method.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_ssl_method(s: *mut SSL, meth: *const SSL_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let Some(m) = method_of(meth) else { return 0 };
        let mut st = x.state();
        if !core::ptr::eq(st.method, m) {
            let same_version = st.method.version == m.version;
            st.method = m;
            if !same_version {
                st.version = m.idle_version();
            }
        }
        1
    }
}

ffi_export! {
    /// The negotiated (before a handshake: the method's) protocol version, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_version(s: *const SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl(s) }.map_or(0, |x| x.state().version)
    }
}

ffi_export! {
    /// The version the client offered (before a handshake: the method's), or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_client_version(s: *const SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let st = x.state();
        // The ClientHello's version once there is one, the method's before.
        match st.drv.tls.as_ref().map(|c| c.client_version()) {
            Some(v) if v != 0 => c_int::from(v),
            _ => st.client_version,
        }
    }
}

/// `ssl_protocol_to_string`.
pub(crate) fn protocol_name(version: c_int) -> &'static core::ffi::CStr {
    use rustyssl_abi::{
        DTLS1_2_VERSION, DTLS1_BAD_VER, DTLS1_VERSION, SSL3_VERSION, TLS1_1_VERSION,
        TLS1_2_VERSION, TLS1_3_VERSION, TLS1_VERSION,
    };
    match version {
        TLS1_3_VERSION => c"TLSv1.3",
        TLS1_2_VERSION => c"TLSv1.2",
        TLS1_1_VERSION => c"TLSv1.1",
        TLS1_VERSION => c"TLSv1",
        SSL3_VERSION => c"SSLv3",
        DTLS1_BAD_VER => c"DTLSv0.9",
        DTLS1_VERSION => c"DTLSv1",
        DTLS1_2_VERSION => c"DTLSv1.2",
        _ => c"unknown",
    }
}

ffi_export! {
    /// The protocol version's name (`TLSv1.3`, ...), or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_version(s: *const SSL) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl(s) }.map_or(ptr::null(), |x| protocol_name(x.state().version).as_ptr())
    }
}

ffi_export! {
    /// Whether the connection is DTLS.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_is_dtls(s: *const SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl(s) }.map_or(0, |x| c_int::from(x.state().method.dtls))
    }
}

ffi_export! {
    /// Whether the connection is TLS (not DTLS).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_is_tls(s: *const SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl(s) }.map_or(0, |x| c_int::from(!x.state().method.dtls))
    }
}

ffi_export! {
    /// Whether the connection is QUIC: never (QUIC isn't built yet, and no method makes one).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_is_quic(s: *const SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let _ = s;
        0
    }
}

ffi_export! {
    /// The default session timeout of the connection's method, in seconds.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_default_timeout(s: *const SSL) -> c_long
    where failure = 0, library = ERR_LIB_SSL
    {
        let _ = s;
        DEFAULT_TIMEOUT
    }
}

ffi_export! {
    /// The handshake state (`TLS_ST_*`).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_state(s: *const SSL) -> OSSL_HANDSHAKE_STATE
    where failure = TLS_ST_BEFORE, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl(s) }.map_or(TLS_ST_BEFORE, |x| x.state().hand_state)
    }
}

ffi_export! {
    /// Whether a handshake is under way (or hasn't started).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_in_init(s: *const SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl(s) }.map_or(0, |x| c_int::from(x.state().in_init))
    }
}

ffi_export! {
    /// Whether no handshake has started.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_in_before(s: *const SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl(s) }.map_or(0, |x| {
            let st = x.state();
            c_int::from(st.hand_state == TLS_ST_BEFORE && st.flow_uninited)
        })
    }
}

ffi_export! {
    /// Whether the handshake has finished.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_is_init_finished(s: *const SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl(s) }.map_or(0, |x| {
            let st = x.state();
            c_int::from(!st.in_init && st.hand_state == rustyssl_abi::TLS_ST_OK)
        })
    }
}

ffi_export! {
    /// What the connection is waiting for (`SSL_NOTHING`, `SSL_READING`, ...).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_want(s: *const SSL) -> c_int
    where failure = SSL_NOTHING, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl(s) }.map_or(SSL_NOTHING, |x| x.state().rwstate)
    }
}

ffi_export! {
    /// The connection's verification parameters (`get0`), or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get0_param(s: *mut SSL) -> *mut X509_VERIFY_PARAM
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl(s) }.map_or(ptr::null_mut(), |x| x.param)
    }
}

/// The connection's parameters, for the functions that act on them.
///
/// # Safety
/// `s` is NULL or a live connection.
unsafe fn param_of(s: *const SSL) -> Option<*mut X509_VERIFY_PARAM> {
    // SAFETY: the caller's guarantee.
    unsafe { ssl(s) }.map(|x| x.param)
}

ffi_export! {
    /// Copies `vpm` into the connection's parameters: 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `vpm` NULL or live parameters.
    pub unsafe extern "C" fn rustyssl_private_SSL_set1_param(s: *mut SSL, vpm: *mut X509_VERIFY_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { param_of(s) }) else { return 0 };
        // SAFETY: the connection's parameters; the caller's.
        unsafe { crate::x509::vpm::X509_VERIFY_PARAM_set1(p, vpm) }
    }
}

ffi_export! {
    /// Sets the purpose checked in verification: 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_purpose(s: *mut SSL, purpose: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { param_of(s) }) else { return 0 };
        // SAFETY: the connection's parameters.
        unsafe { crate::x509::vpm::X509_VERIFY_PARAM_set_purpose(p, purpose) }
    }
}

ffi_export! {
    /// Sets the trust checked in verification: 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_trust(s: *mut SSL, trust: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { param_of(s) }) else { return 0 };
        // SAFETY: the connection's parameters.
        unsafe { crate::x509::vpm::X509_VERIFY_PARAM_set_trust(p, trust) }
    }
}

ffi_export! {
    /// The connection's verification depth, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_verify_depth(s: *const SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { param_of(s) }) else { return 0 };
        // SAFETY: the connection's parameters.
        unsafe { crate::x509::vpm::X509_VERIFY_PARAM_get_depth(p) }
    }
}

ffi_export! {
    /// Sets the connection's verification depth.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_verify_depth(s: *mut SSL, depth: c_int)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { param_of(s) }) else { return };
        // SAFETY: the connection's parameters.
        unsafe { crate::x509::vpm::X509_VERIFY_PARAM_set_depth(p, depth) };
    }
}

ffi_export! {
    /// Sets the verification mode, and the callback unless `callback` is NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_verify(s: *mut SSL, mode: c_int, callback: SSL_verify_cb)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return };
        let mut st = x.state();
        st.verify_mode = mode;
        if callback.is_some() {
            st.verify_callback = callback;
        }
    }
}

ffi_export! {
    /// Sets the host name (or IP address) checked against the peer's certificate, replacing
    /// any; NULL clears them. 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `host` NULL or a string.
    pub unsafe extern "C" fn rustyssl_private_SSL_set1_host(s: *mut SSL, host: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        use crate::x509::vpm::{X509_VERIFY_PARAM_set1_host, X509_VERIFY_PARAM_set1_ip, X509_VERIFY_PARAM_set1_ip_asc};
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { param_of(s) }) else { return 0 };
        // SAFETY: the connection's parameters.
        unsafe { X509_VERIFY_PARAM_set1_host(p, ptr::null(), 0) };
        // SAFETY: as above.
        unsafe { X509_VERIFY_PARAM_set1_ip(p, ptr::null(), 0) };
        if host.is_null() {
            return 1;
        }
        // SAFETY: as above; the caller's string.
        if unsafe { X509_VERIFY_PARAM_set1_ip_asc(p, host) } != 0 {
            return 1;
        }
        // SAFETY: as above.
        unsafe { X509_VERIFY_PARAM_set1_host(p, host, 0) }
    }
}

ffi_export! {
    /// Adds a host name to check (an IP address replaces none: only one may be set). 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `host` NULL or a string.
    pub unsafe extern "C" fn rustyssl_private_SSL_add1_host(s: *mut SSL, host: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        use crate::x509::vpm::{X509_VERIFY_PARAM_add1_host, X509_VERIFY_PARAM_get1_ip_asc, X509_VERIFY_PARAM_set1_ip_asc};
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { param_of(s) }) else { return 0 };
        if !host.is_null() {
            // SAFETY: the caller's string.
            let ip = unsafe { crate::x509v3::san::a2i_IPADDRESS(host) };
            if !ip.is_null() {
                // SAFETY: made here; only checked.
                unsafe { crate::asn1::string::ASN1_OCTET_STRING_free(ip) };
                // SAFETY: the connection's parameters.
                let old = unsafe { X509_VERIFY_PARAM_get1_ip_asc(p) };
                if !old.is_null() {
                    // SAFETY: the copy made for us.
                    unsafe { crate::mem::release(old.cast()) };
                    err::raise_with_text(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT, "SSL_add1_host", "IP address was already set");
                    return 0;
                }
                // SAFETY: as above.
                return unsafe { X509_VERIFY_PARAM_set1_ip_asc(p, host) };
            }
        }
        // SAFETY: as above.
        unsafe { X509_VERIFY_PARAM_add1_host(p, host, 0) }
    }
}

ffi_export! {
    /// Sets the host check's flags (`X509_CHECK_FLAG_*`).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_hostflags(s: *mut SSL, flags: c_uint)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { param_of(s) }) else { return };
        // SAFETY: the connection's parameters.
        unsafe { crate::x509::vpm::X509_VERIFY_PARAM_set_hostflags(p, flags) };
    }
}

ffi_export! {
    /// The host name a verification matched, or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get0_peername(s: *mut SSL) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { param_of(s) }) else { return ptr::null() };
        // SAFETY: the connection's parameters.
        unsafe { crate::x509::vpm::X509_VERIFY_PARAM_get0_peername(p) }
    }
}

ffi_export! {
    /// Stores `arg` in the connection's application data at `idx`: 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_ex_data(s: *mut SSL, idx: c_int, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        // SAFETY: the connection's application data.
        unsafe { crate::ex_data::CRYPTO_set_ex_data(x.ex_data(), idx, arg) }
    }
}

ffi_export! {
    /// The connection's application data at `idx`, or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_ex_data(s: *const SSL, idx: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return ptr::null_mut() };
        // SAFETY: the connection's application data.
        unsafe { crate::ex_data::CRYPTO_get_ex_data(x.ex_data(), idx) }
    }
}

ffi_export! {
    /// Sets the session ID context (up to 32 octets): 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `sid_ctx` points to `sid_ctx_len` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_session_id_context(s: *mut SSL, sid_ctx: *const u8, sid_ctx_len: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        // SAFETY: as above.
        let Some(v) = (unsafe { ctx::sid_ctx_of(sid_ctx, sid_ctx_len, "SSL_set_session_id_context") }) else { return 0 };
        x.state().sid_ctx = v;
        1
    }
}

ffi_export! {
    /// The connection's ALPN protocols (wire format; NULL or empty clears): 0 on success, 1
    /// for an invalid list, as OpenSSL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `protos` points to `protos_len` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_alpn_protos(s: *mut SSL, protos: *const u8, protos_len: c_uint) -> c_int
    where failure = 1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 1 };
        // SAFETY: as above.
        let Some(v) = (unsafe { ctx::alpn_of(protos, protos_len) }) else { return 1 };
        x.state().alpn = v;
        0
    }
}

ffi_export! {
    /// The maximum fragment length extension's mode: 1, or 0 for a bad mode.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_tlsext_max_fragment_length(s: *mut SSL, mode: u8) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        if !ctx::mfl_ok(mode, "SSL_set_tlsext_max_fragment_length") {
            return 0;
        }
        x.state().max_fragment_len_mode = mode;
        1
    }
}

ffi_export! {
    /// Sets the connection's record padding sizes: 1, or 0 for a size above 16384.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_block_padding_ex(s: *mut SSL, app_block_size: usize, hs_block_size: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let (Some(a), Some(h)) = (ctx::padding(app_block_size), ctx::padding(hs_block_size)) else { return 0 };
        let mut st = x.state();
        st.block_padding = a;
        st.hs_padding = h;
        1
    }
}

ffi_export! {
    /// `SSL_set_block_padding_ex` with one size for both.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_block_padding(s: *mut SSL, block_size: usize) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { rustyssl_private_SSL_set_block_padding_ex(s, block_size, block_size) }
    }
}

ffi_export! {
    /// The connection's record padding callback (refused with kernel TLS sending, which isn't
    /// built): 1, or 0 for NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_record_padding_callback(s: *mut SSL, cb: RecordPaddingCb) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        x.state().record_padding_cb = cb;
        1
    }
}

ffi_export! {
    /// The connection's PSK identity hint (at most 256 octets; NULL clears it): 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `identity_hint` NULL or a string.
    pub unsafe extern "C" fn rustyssl_private_SSL_use_psk_identity_hint(s: *mut SSL, identity_hint: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        // SAFETY: as above.
        let Some(h) = (unsafe { ctx::hint_of(identity_hint, "SSL_use_psk_identity_hint") }) else { return 0 };
        x.state().cert.psk_identity_hint = h;
        1
    }
}

ffi_export! {
    /// The client random (copied into `out`, at most `outlen` octets; with `outlen` 0, its
    /// length): the octets copied.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `out` has room for `outlen` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_client_random(s: *const SSL, out: *mut u8, outlen: usize) -> usize
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let r = x.state().client_random;
        // SAFETY: as above.
        unsafe { copy_out(&r, out, outlen, true) }
    }
}

ffi_export! {
    /// The server random, as `SSL_get_client_random`.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `out` has room for `outlen` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_server_random(s: *const SSL, out: *mut u8, outlen: usize) -> usize
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let r = x.state().server_random;
        // SAFETY: as above.
        unsafe { copy_out(&r, out, outlen, true) }
    }
}

ffi_export! {
    /// The last Finished message sent (copied, at most `count` octets): its length.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `buf` has room for `count` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_finished(s: *const SSL, buf: *mut c_void, count: usize) -> usize
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let f = x.state().finish_md.clone();
        // SAFETY: as above.
        unsafe { copy_out(&f, buf.cast(), count, false) }
    }
}

ffi_export! {
    /// The last Finished message received, as `SSL_get_finished`.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `buf` has room for `count` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_peer_finished(s: *const SSL, buf: *mut c_void, count: usize) -> usize
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let f = x.state().peer_finish_md.clone();
        // SAFETY: as above.
        unsafe { copy_out(&f, buf.cast(), count, false) }
    }
}

/// Copies up to `room` octets of `v` to `out`. The randoms return their length for a zero
/// `room` and the octets copied otherwise (`length_if_empty`); the Finished messages always
/// return their whole length.
///
/// # Safety
/// `out` has room for `room` octets.
unsafe fn copy_out(v: &[u8], out: *mut u8, room: usize, length_if_empty: bool) -> usize {
    if length_if_empty && room == 0 {
        return v.len();
    }
    let n = room.min(v.len());
    if n > 0 {
        // SAFETY: the caller's room for `n` octets.
        unsafe { ptr::copy_nonoverlapping(v.as_ptr(), out, n) };
    }
    if length_if_empty { n } else { v.len() }
}

ffi_export! {
    /// The server name (`SSL_get_servername`): for a client, the one it will send (or sent);
    /// for a server, the one the client asked for (none before a handshake). NULL for another
    /// name type.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_servername(s: *const SSL, type_: c_int) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return ptr::null() };
        if type_ != TLSEXT_NAMETYPE_host_name {
            return ptr::null();
        }
        let st = x.state();
        // An end whose role isn't known yet counts as a client.
        let server = st.handshake_func.is_some() && st.server;
        // `SSL_CONNECTION_IS_TLS13`: the negotiated version's method, else the method's own.
        let method_version = st
            .drv
            .tls
            .as_ref()
            .map(|c| c.negotiated())
            .filter(|n| n.cipher.is_some())
            .map_or(st.method.version, |n| c_int::from(n.version));
        let tls13 = method_version >= rustyssl_abi::TLS1_3_VERSION && method_version != rustyssl_abi::TLS_ANY_VERSION;
        let session = st.sess.session;
        // SAFETY: the connection's session, alive while it holds it, or NULL.
        let session_name = || unsafe { super::session::rustyssl_private_SSL_SESSION_get0_hostname(session) };
        if server {
            // A TLS 1.2 resumption reports the name the original handshake accepted.
            if st.hit != 0 && !tls13 {
                return session_name();
            }
            // Else the name the client's hello carried.
            return st.drv.servername.as_deref().map_or(ptr::null(), core::ffi::CStr::as_ptr);
        }
        // `SSL_in_before`.
        let before = st.hand_state == TLS_ST_BEFORE && st.flow_uninited;
        if before {
            // A TLS 1.2 session about to be resumed names the server it was made with.
            // SAFETY: as above.
            let version = unsafe { super::session::rustyssl_private_SSL_SESSION_get_protocol_version(session) };
            if st.hostname.is_none() && !session.is_null() && version != rustyssl_abi::TLS1_3_VERSION {
                return session_name();
            }
        } else if !tls13 && st.hit != 0 && !session_name().is_null() {
            return session_name();
        }
        st.hostname.as_deref().map_or(ptr::null(), core::ffi::CStr::as_ptr)
    }
}

ffi_export! {
    /// `TLSEXT_NAMETYPE_host_name` if there is a server name, else -1.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_servername_type(s: *const SSL) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { rustyssl_private_SSL_get_servername(s, TLSEXT_NAMETYPE_host_name) }.is_null() { -1 } else { TLSEXT_NAMETYPE_host_name }
    }
}

ffi_export! {
    /// Sets the verification result.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_verify_result(s: *mut SSL, v: c_long)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if let Some(x) = unsafe { ssl(s) } {
            x.state().verify_result = v;
        }
    }
}

ffi_export! {
    /// The verification result (`X509_V_OK` before a handshake), or 0 for NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_verify_result(s: *const SSL) -> c_long
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl(s) }.map_or(0, |x| x.state().verify_result)
    }
}

ffi_export! {
    /// Sets read-ahead.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_read_ahead(s: *mut SSL, yes: c_int)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if let Some(x) = unsafe { ssl(s) } {
            x.state().read_ahead = yes;
        }
    }
}

ffi_export! {
    /// Whether read-ahead is set.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_read_ahead(s: *const SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl(s) }.map_or(0, |x| x.state().read_ahead)
    }
}

// --- BIOs and file descriptors ---

ffi_export! {
    /// The read BIO (no reference taken), or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_rbio(s: *const SSL) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl(s) }.map_or(ptr::null_mut(), |x| x.state().rbio)
    }
}

ffi_export! {
    /// The write BIO (no reference taken), or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_wbio(s: *const SSL) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl(s) }.map_or(ptr::null_mut(), |x| x.state().wbio)
    }
}

ffi_export! {
    /// Replaces the read BIO with `rbio` (taking the caller's reference), freeing the old.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `rbio` NULL or a live BIO whose reference it takes.
    pub unsafe extern "C" fn rustyssl_private_SSL_set0_rbio(s: *mut SSL, rbio: *mut BIO)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return };
        let old = core::mem::replace(&mut x.state().rbio, rbio);
        // SAFETY: our old reference, freed outside the lock.
        unsafe { BIO_free_all(old) };
    }
}

ffi_export! {
    /// Replaces the write BIO with `wbio` (taking the caller's reference), freeing the old.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `wbio` NULL or a live BIO whose reference it takes.
    pub unsafe extern "C" fn rustyssl_private_SSL_set0_wbio(s: *mut SSL, wbio: *mut BIO)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return };
        let old = core::mem::replace(&mut x.state().wbio, wbio);
        // SAFETY: our old reference, freed outside the lock.
        unsafe { BIO_free_all(old) };
    }
}

ffi_export! {
    /// Sets both BIOs with OpenSSL's historical ownership rules: nothing if neither changes;
    /// one reference for the same BIO twice is made two; a change of the write side alone
    /// takes one reference; a change of the read side alone takes one when the two were
    /// different; otherwise both are taken.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; the BIOs NULL or live, their references given.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_bio(s: *mut SSL, rbio: *mut BIO, wbio: *mut BIO)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return };
        let (cur_r, cur_w) = {
            let st = x.state();
            (st.rbio, st.wbio)
        };
        if rbio == cur_r && wbio == cur_w {
            return;
        }
        // SAFETY: the caller's BIO.
        if !rbio.is_null() && rbio == wbio && unsafe { BIO_up_ref(rbio) } == 0 {
            return;
        }
        if rbio == cur_r {
            // SAFETY: as above.
            unsafe { rustyssl_private_SSL_set0_wbio(s, wbio) };
            return;
        }
        if wbio == cur_w && cur_r != cur_w {
            // SAFETY: as above.
            unsafe { rustyssl_private_SSL_set0_rbio(s, rbio) };
            return;
        }
        // SAFETY: as above.
        unsafe { rustyssl_private_SSL_set0_rbio(s, rbio) };
        // SAFETY: as above.
        unsafe { rustyssl_private_SSL_set0_wbio(s, wbio) };
    }
}

/// The descriptor of the first descriptor BIO in `b`'s chain, or -1.
///
/// # Safety
/// `b` is NULL or a live BIO.
unsafe fn fd_of(b: *mut BIO) -> c_int {
    // SAFETY: the caller's BIO, or NULL.
    let r = unsafe { BIO_find_type(b, BIO_TYPE_DESCRIPTOR) };
    if r.is_null() {
        return -1;
    }
    let mut fd: c_int = -1;
    // SAFETY: a descriptor BIO; the room for its descriptor.
    unsafe { BIO_ctrl(r, BIO_C_GET_FD, 0, (&raw mut fd).cast()) };
    fd
}

ffi_export! {
    /// The read BIO's descriptor, or -1.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_rfd(s: *const SSL) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let b = unsafe { rustyssl_private_SSL_get_rbio(s) };
        // SAFETY: the connection's BIO, or NULL.
        unsafe { fd_of(b) }
    }
}

ffi_export! {
    /// The write BIO's descriptor, or -1.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_wfd(s: *const SSL) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let b = unsafe { rustyssl_private_SSL_get_wbio(s) };
        // SAFETY: the connection's BIO, or NULL.
        unsafe { fd_of(b) }
    }
}

ffi_export! {
    /// The read descriptor (`SSL_get_rfd`).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_fd(s: *const SSL) -> c_int
    where failure = -1, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { rustyssl_private_SSL_get_rfd(s) }
    }
}

/// A new socket BIO over `fd`, not closing it; NULL (with `ERR_R_BUF_LIB`) on failure.
fn socket_bio(fd: c_int, f: &str) -> *mut BIO {
    // SAFETY: no preconditions.
    let m = unsafe { crate::bio::sock::BIO_s_socket() };
    // SAFETY: the built-in method.
    let b = unsafe { BIO_new(m) };
    if b.is_null() {
        err::raise(ERR_LIB_SSL, ERR_R_BUF_LIB, f);
        return b;
    }
    let mut v = fd;
    // SAFETY: a socket BIO; the descriptor.
    unsafe {
        BIO_ctrl(
            b,
            BIO_C_SET_FD,
            c_long::from(BIO_NOCLOSE),
            (&raw mut v).cast(),
        )
    };
    b
}

ffi_export! {
    /// Both sides over socket `fd` (one BIO): 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_fd(s: *mut SSL, fd: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { ssl(s) }.is_none() {
            return 0;
        }
        let b = socket_bio(fd, "SSL_set_fd");
        if b.is_null() {
            return 0;
        }
        // SAFETY: as above; the new BIO for both sides.
        unsafe { rustyssl_private_SSL_set_bio(s, b, b) };
        1
    }
}

/// Whether `b` is a socket BIO over `fd`.
///
/// # Safety
/// `b` is NULL or a live BIO.
unsafe fn is_socket_of(b: *mut BIO, fd: c_int) -> bool {
    // SAFETY: the caller's BIO.
    !b.is_null() && unsafe { BIO_method_type(b) } == BIO_TYPE_SOCKET && {
        // SAFETY: as above; NULL asks for the descriptor only.
        let got = unsafe { BIO_ctrl(b, BIO_C_GET_FD, 0, ptr::null_mut()) };
        got == c_long::from(fd)
    }
}

ffi_export! {
    /// The write side over socket `fd` (sharing the read BIO if it is over the same socket):
    /// 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_wfd(s: *mut SSL, fd: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { ssl(s) }.is_none() {
            return 0;
        }
        // SAFETY: as above.
        let rbio = unsafe { rustyssl_private_SSL_get_rbio(s) };
        // SAFETY: the connection's BIO, or NULL.
        if unsafe { is_socket_of(rbio, fd) } {
            // SAFETY: as above.
            if unsafe { BIO_up_ref(rbio) } == 0 {
                return 0;
            }
            // SAFETY: as above; the new reference.
            unsafe { rustyssl_private_SSL_set0_wbio(s, rbio) };
        } else {
            let b = socket_bio(fd, "SSL_set_wfd");
            if b.is_null() {
                return 0;
            }
            // SAFETY: as above; the new BIO.
            unsafe { rustyssl_private_SSL_set0_wbio(s, b) };
        }
        1
    }
}

ffi_export! {
    /// The read side over socket `fd` (sharing the write BIO if it is over the same socket):
    /// 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_rfd(s: *mut SSL, fd: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        if unsafe { ssl(s) }.is_none() {
            return 0;
        }
        // SAFETY: as above.
        let wbio = unsafe { rustyssl_private_SSL_get_wbio(s) };
        // SAFETY: the connection's BIO, or NULL.
        if unsafe { is_socket_of(wbio, fd) } {
            // SAFETY: as above.
            if unsafe { BIO_up_ref(wbio) } == 0 {
                return 0;
            }
            // SAFETY: as above; the new reference.
            unsafe { rustyssl_private_SSL_set0_rbio(s, wbio) };
        } else {
            let b = socket_bio(fd, "SSL_set_rfd");
            if b.is_null() {
                return 0;
            }
            // SAFETY: as above; the new BIO.
            unsafe { rustyssl_private_SSL_set0_rbio(s, b) };
        }
        1
    }
}

// --- ctrl ---

ffi_export! {
    /// The connection's control commands (`SSL_ctrl`, `ssl3_ctrl`) that need no handshake,
    /// with OpenSSL's return values; 0 for an unknown command or NULL. Commands reporting what
    /// a handshake negotiated abort until the handshake is built (security rule 10).
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `parg` is what `cmd` documents.
    pub unsafe extern "C" fn rustyssl_private_SSL_ctrl(s: *mut SSL, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_SSL
    {
        // The commands' errors come from OpenSSL's `ssl3_ctrl`.
        const F: &str = "ssl3_ctrl";
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        // SAFETY: the live connection; `parg` as `cmd` documents.
        if let Some(r) = unsafe { super::io::api::handshake_ctrl(x, cmd, parg) } {
            return r;
        }
        // SAFETY: as above (the group and signature algorithm lists).
        if let Some(r) = unsafe { super::lists::ssl_ctrl(x, cmd, larg, parg) } {
            return r;
        }
        // SAFETY: as above (certificate types, temporary keys, DH parameters, chains).
        if let Some(r) = unsafe { super::cert_ctrl::ssl_ctrl(s, x, cmd, larg, parg) } {
            return r;
        }
        if handshake_ctrl(cmd) || (cmd == SSL_CTRL_GET_RAW_CIPHERLIST && !parg.is_null()) {
            crate::stub::unimplemented(&format!("SSL_ctrl command {cmd}"));
        }
        if cmd == SSL_CTRL_SET_CURRENT_CERT && larg == c_long::from(rustyssl_abi::SSL_CERT_SET_SERVER) {
            // Only a server with a negotiated cipher has one to set.
            let st = x.state();
            if !st.server || st.in_init {
                return 0;
            }
            drop(st);
            crate::stub::unimplemented("SSL_ctrl(SSL_CTRL_SET_CURRENT_CERT, SSL_CERT_SET_SERVER) after a handshake");
        }
        // SAFETY: the live connection; the caller's argument.
        if let Some(r) = unsafe { cert_ctrl(Owner::Ssl(s), cmd, larg, parg) } {
            return r;
        }
        if cmd == SSL_CTRL_SET_CURRENT_CERT {
            return c_long::from(x.state().cert.set_current(larg));
        }
        let mut st = x.state();
        match cmd {
            SSL_CTRL_GET_READ_AHEAD => c_long::from(st.read_ahead),
            SSL_CTRL_SET_READ_AHEAD => {
                let old = st.read_ahead;
                st.read_ahead = c_int::try_from(larg).unwrap_or(1);
                c_long::from(old)
            }
            SSL_CTRL_MODE => {
                st.mode |= u32::try_from(larg & 0xffff_ffff).unwrap_or(0);
                c_long::from(st.mode)
            }
            SSL_CTRL_CLEAR_MODE => {
                st.mode &= !u32::try_from(larg & 0xffff_ffff).unwrap_or(0);
                c_long::from(st.mode)
            }
            SSL_CTRL_GET_MAX_CERT_LIST => as_long(st.max_cert_list),
            SSL_CTRL_SET_MAX_CERT_LIST => match usize::try_from(larg) {
                Ok(v) => as_long(core::mem::replace(&mut st.max_cert_list, v)),
                Err(_) => 0,
            },
            SSL_CTRL_SET_MAX_SEND_FRAGMENT => {
                if larg < 512 || larg > c_long::from(SSL3_RT_MAX_PLAIN_LENGTH) {
                    return 0;
                }
                st.max_send_fragment = usize::try_from(larg).unwrap_or(512);
                if st.max_send_fragment < st.split_send_fragment {
                    st.split_send_fragment = st.max_send_fragment;
                }
                1
            }
            SSL_CTRL_SET_SPLIT_SEND_FRAGMENT => match usize::try_from(larg) {
                Ok(v) if v != 0 && v <= st.max_send_fragment => {
                    st.split_send_fragment = v;
                    1
                }
                _ => 0,
            },
            SSL_CTRL_SET_MAX_PIPELINES => {
                if larg < 1 || larg > c_long::from(SSL_MAX_PIPELINES) {
                    return 0;
                }
                st.max_pipelines = usize::try_from(larg).unwrap_or(1);
                1
            }
            SSL_CTRL_GET_RI_SUPPORT => c_long::from(st.send_connection_binding),
            SSL_CTRL_SET_RETRY_VERIFY => {
                st.rwstate = SSL_RETRY_VERIFY;
                1
            }
            // With no argument, the length of a cipher suite on the wire.
            SSL_CTRL_GET_RAW_CIPHERLIST => TLS_CIPHER_LEN,
            SSL_CTRL_SET_MIN_PROTO_VERSION | SSL_CTRL_SET_MAX_PROTO_VERSION => {
                let Ok(v) = c_int::try_from(larg) else { return 0 };
                let method_version = st.defltmeth.version;
                if cmd == SSL_CTRL_SET_MIN_PROTO_VERSION {
                    c_long::from(check_allowed_versions(v, st.max_proto_version) != 0 && set_version_bound(method_version, v, &mut st.min_proto_version) != 0)
                } else {
                    c_long::from(check_allowed_versions(st.min_proto_version, v) != 0 && set_version_bound(method_version, v, &mut st.max_proto_version) != 0)
                }
            }
            SSL_CTRL_GET_MIN_PROTO_VERSION => c_long::from(st.min_proto_version),
            SSL_CTRL_GET_MAX_PROTO_VERSION => c_long::from(st.max_proto_version),
            SSL_CTRL_GET_CLIENT_CERT_REQUEST => 0,
            SSL_CTRL_GET_NUM_RENEGOTIATIONS => c_long::from(st.num_renegotiations),
            SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS => c_long::from(core::mem::replace(&mut st.num_renegotiations, 0)),
            SSL_CTRL_GET_TOTAL_RENEGOTIATIONS => c_long::from(st.total_renegotiations),
            SSL_CTRL_GET_FLAGS => c_long::from(st.s3_flags),
            SSL_CTRL_SET_TMP_DH_CB => {
                drop(st);
                err::raise(ERR_LIB_SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, F);
                0
            }
            SSL_CTRL_SET_TLSEXT_HOSTNAME => {
                if larg != c_long::from(TLSEXT_NAMETYPE_host_name) {
                    drop(st);
                    err::raise(ERR_LIB_SSL, SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE, F);
                    return 0;
                }
                st.hostname = None;
                if parg.is_null() {
                    return 1;
                }
                // SAFETY: the caller's string.
                let name = unsafe { core::ffi::CStr::from_ptr(parg.cast::<c_char>()) };
                if name.is_empty() || name.count_bytes() > usize::try_from(TLSEXT_MAXLEN_host_name).unwrap_or(255) {
                    drop(st);
                    err::raise(ERR_LIB_SSL, SSL_R_SSL3_EXT_INVALID_SERVERNAME, F);
                    return 0;
                }
                st.hostname = Some(name.to_owned());
                1
            }
            SSL_CTRL_SET_TLSEXT_DEBUG_ARG => {
                st.debug_arg = parg;
                1
            }
            SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE => c_long::from(st.status_type),
            SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE => {
                st.status_type = c_int::try_from(larg).unwrap_or(-1);
                1
            }
            SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS => {
                // SAFETY: the caller's slot.
                unsafe { parg.cast::<*mut c_void>().write(st.ocsp_exts) };
                1
            }
            SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS => {
                st.ocsp_exts = parg;
                1
            }
            SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS => {
                // SAFETY: the caller's slot.
                unsafe { parg.cast::<*mut c_void>().write(st.ocsp_ids) };
                1
            }
            SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS => {
                st.ocsp_ids = parg;
                1
            }
            SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP => {
                // SAFETY: the caller's slot.
                unsafe { parg.cast::<*mut u8>().write(st.ocsp_resp) };
                match c_long::try_from(st.ocsp_resp_len) {
                    Ok(n) if n > 0 => n,
                    _ => -1,
                }
            }
            SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP => {
                let old = core::mem::replace(&mut st.ocsp_resp, parg.cast());
                st.ocsp_resp_len = usize::try_from(larg).unwrap_or(0);
                drop(st);
                // SAFETY: the response we owned (C memory), or NULL.
                unsafe { crate::mem::release(old.cast()) };
                1
            }
            SSL_CTRL_SET_MSG_CALLBACK_ARG => {
                st.msg_callback_arg = parg;
                1
            }
            _ => 0,
        }
    }
}

/// The connection ctrl commands that report what a handshake negotiated: they abort until
/// the handshake is built (security rule 10).
fn handshake_ctrl(cmd: c_int) -> bool {
    use rustyssl_abi::{
        SSL_CTRL_GET_EC_POINT_FORMATS, SSL_CTRL_GET_EXTMS_SUPPORT, SSL_CTRL_GET_NEGOTIATED_GROUP,
        SSL_CTRL_GET_PEER_SIGNATURE_NAME, SSL_CTRL_GET_PEER_SIGNATURE_NID,
        SSL_CTRL_GET_PEER_TMP_KEY, SSL_CTRL_GET_SIGNATURE_NAME, SSL_CTRL_GET_SIGNATURE_NID,
    };
    matches!(
        cmd,
        SSL_CTRL_GET_EC_POINT_FORMATS
            | SSL_CTRL_GET_EXTMS_SUPPORT
            | SSL_CTRL_GET_NEGOTIATED_GROUP
            | SSL_CTRL_GET_PEER_SIGNATURE_NAME
            | SSL_CTRL_GET_PEER_SIGNATURE_NID
            | SSL_CTRL_GET_PEER_TMP_KEY
            | SSL_CTRL_GET_SIGNATURE_NAME
            | SSL_CTRL_GET_SIGNATURE_NID
    )
}

ffi_export! {
    /// The connection's callback commands: stores the callback; 1, or 0 for an unknown
    /// command or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `fp` NULL or a callback of the type `cmd` documents.
    pub unsafe extern "C" fn rustyssl_private_SSL_callback_ctrl(s: *mut SSL, cmd: c_int, fp: Option<unsafe extern "C" fn()>) -> c_long
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ssl(s) }) else { return 0 };
        let mut st = x.state();
        match cmd {
            // SAFETY: the caller passes the temporary DH callback's type, as the C cast does.
            SSL_CTRL_SET_TMP_DH_CB => st.cert.dh_tmp_cb = unsafe { core::mem::transmute::<AnyCb, super::types::TmpDhCb>(fp) },
            SSL_CTRL_SET_TLSEXT_DEBUG_CB => st.debug_cb = fp,
            // SAFETY: as above, the not-resumable callback.
            SSL_CTRL_SET_NOT_RESUMABLE_SESS_CB => st.not_resumable_session_cb = unsafe { core::mem::transmute::<AnyCb, NotResumableCb>(fp) },
            // SAFETY: as above, the message callback.
            SSL_CTRL_SET_MSG_CALLBACK => st.msg_callback = unsafe { core::mem::transmute::<AnyCb, MsgCb>(fp) },
            _ => return 0,
        }
        1
    }
}

ffi_export! {
    /// Frees the connection's certificates and keys (its own copy; the context keeps its).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_certs_clear(s: *mut SSL)
    where failure = (), library = ERR_LIB_SSL
    {
        let mut rel = super::cert::Released::default();
        // SAFETY: the caller's guarantee.
        if let Some(x) = unsafe { ssl(s) } {
            x.state().cert.clear_certs(&mut rel);
        }
    }
}

ffi_export! {
    /// Does nothing (the deprecated debug switch never did anything).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_debug(s: *mut SSL, debug: c_int)
    where failure = (), library = ERR_LIB_SSL
    {
        let _ = (s, debug);
    }
}
