//! libssl: contexts, connections, sessions, ciphers, `SSL_CONF`, and the `*_ctrl` macros the
//! TLS commands use (`s_client`, `s_server`, `s_time`, `ciphers`).
//!
//! Owned objects ([`SslCtx`], [`Ssl`], [`Session`], [`ConfCtx`]) are freed on drop; the
//! borrowed ones ([`CtxRef`], [`SslRef`], [`SessionRef`], [`CipherRef`]) are what the library
//! hands out (`SSL_get_SSL_CTX`, a callback's `SSL *`, ...) and stay valid while their owner
//! does. Objects that other wrappers already know (`Bio`, `Cert`, `Pkey`) are lent as
//! [`BioRef`], [`CertRef`], [`PkeyRef`], which dereference to them without owning them.

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ops::Deref;

use crate::abi::*;
use crate::bio::Bio;
use crate::ffi;
use crate::pkey::Pkey;
use crate::provider::LibCtx;
use crate::util::{cstring, string_at};
use crate::x509::{Cert, CertStack, CrlStack, NameRef, Store};

/// A `BIO` lent by the library or another owner, usable as a [`Bio`] without owning it.
pub struct BioRef<'a>(ManuallyDrop<Bio>, PhantomData<&'a ()>);

impl BioRef<'_> {
    /// `None` for NULL. The caller lends a `BIO` that stays live for `'a`.
    pub(crate) fn new(p: *mut BIO) -> Option<Self> {
        Bio::from_ptr(p).map(|b| Self(ManuallyDrop::new(b), PhantomData))
    }
}

impl Deref for BioRef<'_> {
    type Target = Bio;
    fn deref(&self) -> &Bio {
        &self.0
    }
}

impl Bio {
    /// Lends this `BIO` (for an API that takes a [`BioRef`]).
    pub fn lend(&self) -> BioRef<'_> {
        match BioRef::new(self.as_ptr()) {
            Some(b) => b,
            // A Bio's pointer is never NULL.
            None => std::process::abort(),
        }
    }
}

/// An `X509` lent by its owner.
pub struct CertRef<'a>(ManuallyDrop<Cert>, PhantomData<&'a ()>);

impl CertRef<'_> {
    pub(crate) fn new(p: *mut X509) -> Option<Self> {
        Cert::from_raw(p).map(|c| Self(ManuallyDrop::new(c), PhantomData))
    }
}

impl Deref for CertRef<'_> {
    type Target = Cert;
    fn deref(&self) -> &Cert {
        &self.0
    }
}

/// An `EVP_PKEY` lent by its owner.
pub struct PkeyRef<'a>(ManuallyDrop<Pkey>, PhantomData<&'a ()>);

impl PkeyRef<'_> {
    pub(crate) fn new(p: *mut EVP_PKEY) -> Option<Self> {
        Pkey::from_raw(p).map(|k| Self(ManuallyDrop::new(k), PhantomData))
    }
}

impl Deref for PkeyRef<'_> {
    type Target = Pkey;
    fn deref(&self) -> &Pkey {
        &self.0
    }
}

/// An `SSL_METHOD` (static in the library).
#[derive(Clone, Copy)]
pub struct Method(*const SSL_METHOD);

impl Method {
    /// `TLS_client_method()`.
    pub fn tls_client() -> Self {
        // SAFETY: no arguments; a static table.
        Self(unsafe { ffi::TLS_client_method() })
    }
    /// `TLS_server_method()`.
    pub fn tls_server() -> Self {
        // SAFETY: as above.
        Self(unsafe { ffi::TLS_server_method() })
    }
    /// `DTLS_client_method()`.
    pub fn dtls_client() -> Self {
        // SAFETY: as above.
        Self(unsafe { ffi::DTLS_client_method() })
    }
    /// `DTLS_server_method()`.
    pub fn dtls_server() -> Self {
        // SAFETY: as above.
        Self(unsafe { ffi::DTLS_server_method() })
    }
    /// `OSSL_QUIC_client_method()`.
    pub fn quic_client() -> Self {
        // SAFETY: as above.
        Self(unsafe { ffi::OSSL_QUIC_client_method() })
    }
}

crate::handle!(
    /// An owned `SSL_CTX`.
    SslCtx, SSL_CTX, SSL_CTX_free
);
crate::handle!(
    /// An owned `SSL`.
    Ssl, SSL, SSL_free
);
crate::handle!(
    /// An owned `SSL_SESSION`.
    Session, SSL_SESSION, SSL_SESSION_free
);
crate::handle!(
    /// An owned `SSL_CONF_CTX`.
    ConfCtx, SSL_CONF_CTX, SSL_CONF_CTX_free
);

/// A borrowed `SSL_CTX`.
#[derive(Clone, Copy)]
pub struct CtxRef<'a>(*mut SSL_CTX, PhantomData<&'a ()>);

/// A borrowed `SSL`.
#[derive(Clone, Copy)]
pub struct SslRef<'a>(*mut SSL, PhantomData<&'a ()>);

/// A borrowed `SSL_SESSION`.
#[derive(Clone, Copy)]
pub struct SessionRef<'a>(*mut SSL_SESSION, PhantomData<&'a ()>);

/// A cipher (owned by the library).
#[derive(Clone, Copy)]
pub struct CipherRef<'a>(*const SSL_CIPHER, PhantomData<&'a ()>);

/// An `EVP_MD` lent by the library (compared by identity).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MdRef(*const EVP_MD);

impl MdRef {
    pub(crate) fn new(p: *const EVP_MD) -> Option<Self> {
        (!p.is_null()).then_some(Self(p))
    }
}

impl<'a> CtxRef<'a> {
    #[allow(dead_code)]
    pub(crate) fn new(p: *mut SSL_CTX) -> Option<Self> {
        (!p.is_null()).then_some(Self(p, PhantomData))
    }
    /// The object, for the C API.
    pub fn as_ptr(self) -> *mut SSL_CTX {
        self.0
    }
}

impl<'a> SslRef<'a> {
    pub(crate) fn new(p: *mut SSL) -> Option<Self> {
        (!p.is_null()).then_some(Self(p, PhantomData))
    }
    /// The object, for the C API.
    pub fn as_ptr(self) -> *mut SSL {
        self.0
    }
}

impl<'a> SessionRef<'a> {
    pub(crate) fn new(p: *mut SSL_SESSION) -> Option<Self> {
        (!p.is_null()).then_some(Self(p, PhantomData))
    }
    /// The object, for the C API.
    pub fn as_ptr(self) -> *mut SSL_SESSION {
        self.0
    }
}

impl<'a> CipherRef<'a> {
    pub(crate) fn new(p: *const SSL_CIPHER) -> Option<Self> {
        (!p.is_null()).then_some(Self(p, PhantomData))
    }
}

impl SslCtx {
    /// `SSL_CTX_new_ex(libctx, propq, method)`.
    pub fn new_ex(libctx: Option<&LibCtx>, propq: Option<&str>, method: Method) -> Option<Self> {
        let pq = match propq {
            Some(p) => Some(cstring(p)?),
            None => None,
        };
        let lc = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: the method is a static table; libctx and propq are valid or NULL.
        Self::from_ptr(unsafe {
            ffi::SSL_CTX_new_ex(
                lc,
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
                method.0,
            )
        })
    }

    /// `SSL_CTX_new(method)`.
    pub fn new(method: Method) -> Option<Self> {
        // SAFETY: a static method table.
        Self::from_ptr(unsafe { ffi::SSL_CTX_new(method.0) })
    }

    /// The context, borrowed.
    pub fn r(&self) -> CtxRef<'_> {
        CtxRef(self.as_ptr(), PhantomData)
    }
}

impl Ssl {
    /// `SSL_new(ctx)`.
    pub fn new(ctx: CtxRef<'_>) -> Option<Self> {
        // SAFETY: the context is live.
        Self::from_ptr(unsafe { ffi::SSL_new(ctx.0) })
    }

    /// The connection, borrowed.
    pub fn r(&self) -> SslRef<'_> {
        SslRef(self.as_ptr(), PhantomData)
    }
}

impl Session {
    /// The session, borrowed.
    pub fn r(&self) -> SessionRef<'_> {
        SessionRef(self.as_ptr(), PhantomData)
    }

    /// `SSL_SESSION_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::SSL_SESSION_new() })
    }

    /// `PEM_read_bio_SSL_SESSION(bio, NULL, NULL, NULL)`.
    pub fn read_pem(bio: &Bio) -> Option<Self> {
        // SAFETY: the BIO is live; no callback.
        Self::from_ptr(unsafe {
            ffi::PEM_read_bio_SSL_SESSION(
                bio.as_ptr(),
                core::ptr::null_mut(),
                None,
                core::ptr::null_mut(),
            )
        })
    }

    /// `d2i_SSL_SESSION_ex`.
    pub fn from_der(der: &[u8], libctx: Option<&LibCtx>, propq: Option<&str>) -> Option<Self> {
        let len = c_long::try_from(der.len()).ok()?;
        let pq = match propq {
            Some(p) => Some(cstring(p)?),
            None => None,
        };
        let mut p = der.as_ptr();
        let lc = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: p is valid for len bytes; the strings are valid or NULL.
        Self::from_ptr(unsafe {
            ffi::d2i_SSL_SESSION_ex(
                core::ptr::null_mut(),
                &mut p,
                len,
                lc,
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
            )
        })
    }
}

impl SessionRef<'_> {
    /// `SSL_SESSION_up_ref`: a new owned reference.
    pub fn up_ref(self) -> Option<Session> {
        // SAFETY: the session is live.
        if unsafe { ffi::SSL_SESSION_up_ref(self.0) } != 1 {
            return None;
        }
        Session::from_ptr(self.0)
    }

    /// `SSL_SESSION_print(bio, sess)`.
    pub fn print(self, bio: &Bio) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::SSL_SESSION_print(bio.as_ptr(), self.0) == 1 }
    }

    /// `PEM_write_bio_SSL_SESSION(bio, sess)`.
    pub fn write_pem(self, bio: &Bio) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::PEM_write_bio_SSL_SESSION(bio.as_ptr(), self.0) == 1 }
    }

    /// `SSL_SESSION_get_max_early_data`.
    pub fn max_early_data(self) -> u32 {
        // SAFETY: the session is live.
        unsafe { ffi::SSL_SESSION_get_max_early_data(self.0) }
    }

    /// `SSL_SESSION_set1_master_key`.
    pub fn set1_master_key(self, key: &[u8]) -> bool {
        // SAFETY: the session is live; key is valid for its length.
        unsafe { ffi::SSL_SESSION_set1_master_key(self.0, key.as_ptr(), key.len()) == 1 }
    }

    /// `SSL_SESSION_set_cipher`.
    pub fn set_cipher(self, c: CipherRef<'_>) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::SSL_SESSION_set_cipher(self.0, c.0) == 1 }
    }

    /// `SSL_SESSION_set_protocol_version`.
    pub fn set_protocol_version(self, v: c_int) -> bool {
        // SAFETY: the session is live.
        unsafe { ffi::SSL_SESSION_set_protocol_version(self.0, v) == 1 }
    }

    /// `SSL_SESSION_get0_cipher`.
    pub fn cipher(self) -> Option<CipherRef<'static>> {
        // SAFETY: the session is live; ciphers are static.
        CipherRef::new(unsafe { ffi::SSL_SESSION_get0_cipher(self.0) })
    }

    /// `SSL_SESSION_get_id`.
    pub fn id(self) -> Vec<u8> {
        let mut len: c_uint = 0;
        // SAFETY: the session is live; len is a valid out-pointer.
        let p = unsafe { ffi::SSL_SESSION_get_id(self.0, &mut len) };
        if p.is_null() {
            return Vec::new();
        }
        let n = usize::try_from(len).unwrap_or(0);
        // SAFETY: p points to len bytes owned by the session.
        unsafe { core::slice::from_raw_parts(p, n) }.to_vec()
    }

    /// `i2d_SSL_SESSION`.
    pub fn to_der(self) -> Option<Vec<u8>> {
        // SAFETY: the session is live; NULL asks for the length.
        let n = unsafe { ffi::i2d_SSL_SESSION(self.0, core::ptr::null_mut()) };
        let len = usize::try_from(n).ok()?;
        let mut buf = vec![0u8; len];
        let mut p = buf.as_mut_ptr();
        // SAFETY: buf has room for the encoding the first call measured.
        let m = unsafe { ffi::i2d_SSL_SESSION(self.0, &mut p) };
        (m == n).then_some(buf)
    }
}

impl<'a> CipherRef<'a> {
    /// `SSL_CIPHER_get_name` ("(NONE)" for none).
    pub fn name(self) -> Option<String> {
        // SAFETY: the cipher is static.
        string_at(unsafe { ffi::SSL_CIPHER_get_name(self.0) })
    }
    /// `SSL_CIPHER_standard_name`.
    pub fn standard_name(self) -> Option<String> {
        // SAFETY: as above.
        string_at(unsafe { ffi::SSL_CIPHER_standard_name(self.0) })
    }
    /// `SSL_CIPHER_get_version`.
    pub fn version(self) -> Option<String> {
        // SAFETY: as above.
        string_at(unsafe { ffi::SSL_CIPHER_get_version(self.0) })
    }
    /// `SSL_CIPHER_get_id`.
    pub fn id(self) -> u32 {
        // SAFETY: as above.
        unsafe { ffi::SSL_CIPHER_get_id(self.0) }
    }
    /// `SSL_CIPHER_description(c, buf, 512)`.
    pub fn description(self) -> Option<String> {
        let mut buf = [0 as c_char; 512];
        // SAFETY: buf is writable for its length.
        string_at(unsafe { ffi::SSL_CIPHER_description(self.0, buf.as_mut_ptr(), 512) })
    }
    /// `SSL_CIPHER_get_handshake_digest`.
    pub fn handshake_digest(self) -> Option<MdRef> {
        // SAFETY: as above.
        MdRef::new(unsafe { ffi::SSL_CIPHER_get_handshake_digest(self.0) })
    }
}

/// `OPENSSL_cipher_name(stdname)`.
pub fn openssl_cipher_name(stdname: &str) -> String {
    let Some(c) = cstring(stdname) else {
        return "(NONE)".to_owned();
    };
    // SAFETY: a valid C string; the result is static.
    string_at(unsafe { ffi::OPENSSL_cipher_name(c.as_ptr()) }).unwrap_or_default()
}

/// The members of a `STACK_OF(SSL_CIPHER)`.
fn ciphers_of<'a>(sk: *const stack_st_SSL_CIPHER) -> Vec<CipherRef<'a>> {
    let st = sk.cast::<OPENSSL_STACK>();
    // SAFETY: st is NULL (-1) or a live stack.
    let n = unsafe { ffi::OPENSSL_sk_num(st) };
    (0..n.max(0))
        // SAFETY: i is in range; the members are ciphers.
        .filter_map(|i| CipherRef::new(unsafe { ffi::OPENSSL_sk_value(st, i) }.cast()))
        .collect()
}

/// The members of a `STACK_OF(X509)` (borrowed).
fn certs_of<'a>(sk: *const stack_st_X509) -> Vec<CertRef<'a>> {
    let st = sk.cast::<OPENSSL_STACK>();
    // SAFETY: st is NULL (-1) or a live stack.
    let n = unsafe { ffi::OPENSSL_sk_num(st) };
    (0..n.max(0))
        // SAFETY: i is in range; the members are certificates.
        .filter_map(|i| CertRef::new(unsafe { ffi::OPENSSL_sk_value(st, i) }.cast()))
        .collect()
}

/// `NULL` or a C string kept alive for a call.
fn opt_cstr(s: Option<&str>) -> Option<Option<std::ffi::CString>> {
    match s {
        Some(s) => cstring(s).map(Some),
        None => Some(None),
    }
}

fn ptr_of(c: &Option<std::ffi::CString>) -> *const c_char {
    c.as_ref().map_or(core::ptr::null(), |c| c.as_ptr())
}

impl<'a> CtxRef<'a> {
    fn ctrl(self, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long {
        // SAFETY: the context is live; each caller passes the argument its command takes.
        unsafe { ffi::SSL_CTX_ctrl(self.0, cmd, larg, parg) }
    }

    /// `SSL_CTX_set_min_proto_version`.
    pub fn set_min_proto_version(self, v: c_int) -> bool {
        self.ctrl(
            SSL_CTRL_SET_MIN_PROTO_VERSION,
            c_long::from(v),
            core::ptr::null_mut(),
        ) != 0
    }
    /// `SSL_CTX_set_max_proto_version`.
    pub fn set_max_proto_version(self, v: c_int) -> bool {
        self.ctrl(
            SSL_CTRL_SET_MAX_PROTO_VERSION,
            c_long::from(v),
            core::ptr::null_mut(),
        ) != 0
    }
    /// `SSL_CTX_set_mode`.
    pub fn set_mode(self, mode: c_long) -> c_long {
        self.ctrl(SSL_CTRL_MODE, mode, core::ptr::null_mut())
    }
    /// `SSL_CTX_clear_mode`.
    pub fn clear_mode(self, mode: c_long) -> c_long {
        self.ctrl(SSL_CTRL_CLEAR_MODE, mode, core::ptr::null_mut())
    }
    /// `SSL_CTX_set_options`.
    pub fn set_options(self, op: u64) -> u64 {
        // SAFETY: the context is live.
        unsafe { ffi::SSL_CTX_set_options(self.0, op) }
    }
    /// `SSL_CTX_set_quiet_shutdown`.
    pub fn set_quiet_shutdown(self, mode: c_int) {
        // SAFETY: the context is live.
        unsafe { ffi::SSL_CTX_set_quiet_shutdown(self.0, mode) }
    }
    /// `SSL_CTX_set_cipher_list`.
    pub fn set_cipher_list(self, s: &str) -> bool {
        let Some(c) = cstring(s) else { return false };
        // SAFETY: the context is live; c is a valid C string.
        unsafe { ffi::SSL_CTX_set_cipher_list(self.0, c.as_ptr()) == 1 }
    }
    /// `SSL_CTX_set_ciphersuites`.
    pub fn set_ciphersuites(self, s: &str) -> bool {
        let Some(c) = cstring(s) else { return false };
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_set_ciphersuites(self.0, c.as_ptr()) == 1 }
    }
    /// `SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM)`.
    pub fn use_certificate_file_pem(self, file: &str) -> c_int {
        let Some(c) = cstring(file) else { return 0 };
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_use_certificate_file(self.0, c.as_ptr(), SSL_FILETYPE_PEM) }
    }
    /// `SSL_CTX_use_PrivateKey_file(ctx, file, SSL_FILETYPE_PEM)`.
    pub fn use_private_key_file_pem(self, file: &str) -> c_int {
        let Some(c) = cstring(file) else { return 0 };
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_use_PrivateKey_file(self.0, c.as_ptr(), SSL_FILETYPE_PEM) }
    }
    /// `SSL_CTX_check_private_key`.
    pub fn check_private_key(self) -> bool {
        // SAFETY: the context is live.
        unsafe { ffi::SSL_CTX_check_private_key(self.0) == 1 }
    }
    /// `SSL_CTX_use_certificate`.
    pub fn use_certificate(self, x: &Cert) -> c_int {
        // SAFETY: both are live; the context takes its own reference.
        unsafe { ffi::SSL_CTX_use_certificate(self.0, x.as_ptr()) }
    }
    /// `SSL_CTX_use_PrivateKey`.
    pub fn use_private_key(self, k: &Pkey) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_use_PrivateKey(self.0, k.as_ptr()) }
    }
    /// `SSL_CTX_set1_chain`.
    pub fn set1_chain(self, chain: &CertStack) -> bool {
        self.ctrl(SSL_CTRL_CHAIN, 1, chain.as_ptr().cast()) != 0
    }
    /// `SSL_CTX_build_cert_chain`.
    pub fn build_cert_chain(self, flags: c_long) -> bool {
        self.ctrl(SSL_CTRL_BUILD_CERT_CHAIN, flags, core::ptr::null_mut()) > 0
    }
    /// `SSL_CTX_get0_chain_certs`: the current certificate's chain (borrowed).
    pub fn chain_certs(self) -> Option<Vec<CertRef<'a>>> {
        let mut sk: *mut stack_st_X509 = core::ptr::null_mut();
        if self.ctrl(SSL_CTRL_GET_CHAIN_CERTS, 0, (&raw mut sk).cast()) == 0 {
            return None;
        }
        Some(certs_of(sk))
    }
    /// `SSL_CTX_set1_param`.
    pub fn set1_param(self, vpm: &crate::verify::VerifyParam) -> bool {
        // SAFETY: both are live; the parameters are copied.
        unsafe { ffi::SSL_CTX_set1_param(self.0, vpm.as_ptr()) == 1 }
    }
    /// `SSL_CTX_set_max_send_fragment`.
    pub fn set_max_send_fragment(self, n: c_uint) -> bool {
        self.ctrl(
            SSL_CTRL_SET_MAX_SEND_FRAGMENT,
            c_long::from(n),
            core::ptr::null_mut(),
        ) != 0
    }
    /// `SSL_CTX_set_split_send_fragment`.
    pub fn set_split_send_fragment(self, n: c_uint) -> bool {
        self.ctrl(
            SSL_CTRL_SET_SPLIT_SEND_FRAGMENT,
            c_long::from(n),
            core::ptr::null_mut(),
        ) != 0
    }
    /// `SSL_CTX_set_max_pipelines`.
    pub fn set_max_pipelines(self, n: c_uint) -> bool {
        self.ctrl(
            SSL_CTRL_SET_MAX_PIPELINES,
            c_long::from(n),
            core::ptr::null_mut(),
        ) != 0
    }
    /// `SSL_CTX_set_default_read_buffer_len`.
    pub fn set_default_read_buffer_len(self, n: usize) {
        // SAFETY: the context is live.
        unsafe { ffi::SSL_CTX_set_default_read_buffer_len(self.0, n) }
    }
    /// `SSL_CTX_set_tlsext_max_fragment_length`.
    pub fn set_tlsext_max_fragment_length(self, mode: u8) -> bool {
        // SAFETY: the context is live.
        unsafe { ffi::SSL_CTX_set_tlsext_max_fragment_length(self.0, mode) == 1 }
    }
    /// `SSL_CTX_set1_verify_cert_store`.
    pub fn set1_verify_cert_store(self, st: &Store) -> bool {
        self.ctrl(SSL_CTRL_SET_VERIFY_CERT_STORE, 1, st.as_ptr().cast()) != 0
    }
    /// `SSL_CTX_set1_chain_cert_store`.
    pub fn set1_chain_cert_store(self, st: &Store) -> bool {
        self.ctrl(SSL_CTRL_SET_CHAIN_CERT_STORE, 1, st.as_ptr().cast()) != 0
    }
    /// `SSL_CTX_get_cert_store`: the trust store (borrowed; adding CRLs to it).
    pub fn add_crls_to_cert_store(self, crls: &CrlStack) -> bool {
        // SAFETY: the context is live; its store is owned by it.
        let st = unsafe { ffi::SSL_CTX_get_cert_store(self.0) };
        add_crls(st, crls)
    }
    /// `store_setup_crl_download(SSL_CTX_get_cert_store(ctx))`.
    pub fn cert_store_setup_crl_download(self) {
        // SAFETY: as above.
        let st = unsafe { ffi::SSL_CTX_get_cert_store(self.0) };
        crate::ssl::store_setup_crl_download_raw(st);
    }
    /// `SSL_CTX_load_verify_file`.
    pub fn load_verify_file(self, f: &str) -> bool {
        let Some(c) = cstring(f) else { return false };
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_load_verify_file(self.0, c.as_ptr()) == 1 }
    }
    /// `SSL_CTX_load_verify_dir`.
    pub fn load_verify_dir(self, d: &str) -> bool {
        let Some(c) = cstring(d) else { return false };
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_load_verify_dir(self.0, c.as_ptr()) == 1 }
    }
    /// `SSL_CTX_load_verify_store`.
    pub fn load_verify_store(self, s: &str) -> bool {
        let Some(c) = cstring(s) else { return false };
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_load_verify_store(self.0, c.as_ptr()) == 1 }
    }
    /// `SSL_CTX_set_default_verify_file`.
    pub fn set_default_verify_file(self) -> bool {
        // SAFETY: the context is live.
        unsafe { ffi::SSL_CTX_set_default_verify_file(self.0) == 1 }
    }
    /// `SSL_CTX_set_default_verify_dir`.
    pub fn set_default_verify_dir(self) -> bool {
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_set_default_verify_dir(self.0) == 1 }
    }
    /// `SSL_CTX_set_default_verify_store`.
    pub fn set_default_verify_store(self) -> bool {
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_set_default_verify_store(self.0) == 1 }
    }
    /// `SSL_CTX_config(ctx, name)`.
    pub fn config(self, name: &str) -> bool {
        let Some(c) = cstring(name) else { return false };
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_config(self.0, c.as_ptr()) == 1 }
    }
    /// `SSL_CTX_set_session_cache_mode`.
    pub fn set_session_cache_mode(self, m: c_long) -> c_long {
        self.ctrl(SSL_CTRL_SET_SESS_CACHE_MODE, m, core::ptr::null_mut())
    }
    /// `SSL_CTX_sess_set_cache_size`.
    pub fn sess_set_cache_size(self, n: c_long) -> c_long {
        self.ctrl(SSL_CTRL_SET_SESS_CACHE_SIZE, n, core::ptr::null_mut())
    }
    /// `SSL_CTX_sess_get_cache_size`.
    pub fn sess_get_cache_size(self) -> c_long {
        self.ctrl(SSL_CTRL_GET_SESS_CACHE_SIZE, 0, core::ptr::null_mut())
    }
    /// The session-statistics counters of `print_stats` (`SSL_CTX_sess_number`, ...), by
    /// their `SSL_CTRL_SESS_*` command.
    pub fn sess_stat(self, cmd: c_int) -> c_long {
        self.ctrl(cmd, 0, core::ptr::null_mut())
    }
    /// `SSL_CTX_set_session_id_context`.
    pub fn set_session_id_context(self, ctx: &[u8]) -> bool {
        let Ok(n) = c_uint::try_from(ctx.len()) else {
            return false;
        };
        // SAFETY: ctx is valid for n bytes.
        unsafe { ffi::SSL_CTX_set_session_id_context(self.0, ctx.as_ptr(), n) == 1 }
    }
    /// `SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(file))`.
    pub fn set_client_ca_list_from_file(self, file: &str) {
        let Some(c) = cstring(file) else { return };
        // SAFETY: a valid C string; the list (or NULL) is ours.
        let l = unsafe { ffi::SSL_load_client_CA_file(c.as_ptr()) };
        // SAFETY: the context takes the list.
        unsafe { ffi::SSL_CTX_set_client_CA_list(self.0, l) };
    }
    /// `SSL_add_file_cert_subjects_to_stack` into a new list, set with `SSL_CTX_set0_CA_list`.
    pub fn set0_ca_list_from_file(self, file: &str) -> bool {
        let Some(c) = cstring(file) else { return false };
        // SAFETY: a new empty stack.
        let nm = unsafe { ffi::OPENSSL_sk_new_null() }.cast::<stack_st_X509_NAME>();
        // SAFETY: nm is NULL or a live stack; c is a valid C string.
        if nm.is_null() || unsafe { ffi::SSL_add_file_cert_subjects_to_stack(nm, c.as_ptr()) } == 0
        {
            free_name_stack(nm);
            return false;
        }
        // SAFETY: the context takes the stack.
        unsafe { ffi::SSL_CTX_set0_CA_list(self.0, nm) };
        true
    }
    /// `SSL_CTX_set_client_cert_engine`.
    pub fn set_client_cert_engine(self, e: &crate::engine::Engine) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::SSL_CTX_set_client_cert_engine(self.0, e.as_ptr()) == 1 }
    }
    /// `SSL_CTX_set_tlsext_use_srtp` (0 on success).
    pub fn set_tlsext_use_srtp(self, profiles: &str) -> c_int {
        let Some(c) = cstring(profiles) else { return 1 };
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_set_tlsext_use_srtp(self.0, c.as_ptr()) }
    }
    /// `SSL_CTX_set_alpn_protos` (0 on success).
    pub fn set_alpn_protos(self, protos: &[u8]) -> c_int {
        let Ok(n) = c_uint::try_from(protos.len()) else {
            return 1;
        };
        // SAFETY: protos is valid for n bytes.
        unsafe { ffi::SSL_CTX_set_alpn_protos(self.0, protos.as_ptr(), n) }
    }
    /// `SSL_CTX_enable_ct`.
    pub fn enable_ct(self, mode: c_int) -> bool {
        // SAFETY: the context is live.
        unsafe { ffi::SSL_CTX_enable_ct(self.0, mode) == 1 }
    }
    /// `SSL_CTX_set_ctlog_list_file` (or the default with `None`).
    pub fn set_ctlog_list_file(self, path: Option<&str>) -> bool {
        match path {
            None => {
                // SAFETY: the context is live.
                unsafe { ffi::SSL_CTX_set_default_ctlog_list_file(self.0) == 1 }
            }
            Some(p) => {
                let Some(c) = cstring(p) else { return false };
                // SAFETY: as above.
                unsafe { ffi::SSL_CTX_set_ctlog_list_file(self.0, c.as_ptr()) == 1 }
            }
        }
    }
    /// `SSL_CTX_dane_enable`.
    pub fn dane_enable(self) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::SSL_CTX_dane_enable(self.0) }
    }
    /// `SSL_CTX_use_serverinfo_file`.
    pub fn use_serverinfo_file(self, f: &str) -> bool {
        let Some(c) = cstring(f) else { return false };
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_use_serverinfo_file(self.0, c.as_ptr()) == 1 }
    }
    /// `SSL_CTX_set_max_early_data`.
    pub fn set_max_early_data(self, n: u32) -> bool {
        // SAFETY: the context is live.
        unsafe { ffi::SSL_CTX_set_max_early_data(self.0, n) == 1 }
    }
    /// `SSL_CTX_set_recv_max_early_data`.
    pub fn set_recv_max_early_data(self, n: u32) -> bool {
        // SAFETY: the context is live.
        unsafe { ffi::SSL_CTX_set_recv_max_early_data(self.0, n) == 1 }
    }
    /// `SSL_CTX_compress_certs(ctx, alg)`.
    pub fn compress_certs(self, alg: c_int) -> bool {
        // SAFETY: the context is live.
        unsafe { ffi::SSL_CTX_compress_certs(self.0, alg) == 1 }
    }
    /// `SSL_CTX_set1_server_cert_type`.
    pub fn set1_server_cert_type(self, t: &[u8]) -> bool {
        // SAFETY: t is valid for its length.
        unsafe { ffi::SSL_CTX_set1_server_cert_type(self.0, t.as_ptr(), t.len()) == 1 }
    }
    /// `SSL_CTX_set1_client_cert_type`.
    pub fn set1_client_cert_type(self, t: &[u8]) -> bool {
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_set1_client_cert_type(self.0, t.as_ptr(), t.len()) == 1 }
    }
    /// `SSL_CTX_set_dh_auto(ctx, onoff)`.
    pub fn set_dh_auto(self, onoff: c_long) -> c_long {
        self.ctrl(SSL_CTRL_SET_DH_AUTO, onoff, core::ptr::null_mut())
    }
    /// `SSL_CTX_set0_tmp_dh_pkey` (the context takes the key on success).
    pub fn set0_tmp_dh_pkey(self, k: Pkey) -> Result<(), Pkey> {
        // SAFETY: both are live; on success the context owns the key.
        if unsafe { ffi::SSL_CTX_set0_tmp_dh_pkey(self.0, k.as_ptr()) } == 1 {
            let _ = k.into_ptr();
            Ok(())
        } else {
            Err(k)
        }
    }
    /// `SSL_CTX_use_psk_identity_hint`.
    pub fn use_psk_identity_hint(self, hint: &str) -> bool {
        let Some(c) = cstring(hint) else { return false };
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_use_psk_identity_hint(self.0, c.as_ptr()) == 1 }
    }
    /// `SSL_CTX_set_srp_username`.
    pub fn set_srp_username(self, user: &str) -> bool {
        let Some(c) = cstring(user) else { return false };
        // SAFETY: the library copies the name.
        unsafe { ffi::SSL_CTX_set_srp_username(self.0, c.as_ptr().cast_mut()) == 1 }
    }
    /// `SSL_CTX_set_srp_strength`.
    pub fn set_srp_strength(self, n: c_int) -> bool {
        // SAFETY: the context is live.
        unsafe { ffi::SSL_CTX_set_srp_strength(self.0, n) == 1 }
    }
    /// `SSL_CTX_set_max_proto_version` and the like through `SSL_CTX_get_options`.
    pub fn options(self) -> u64 {
        // SAFETY: the context is live.
        unsafe { ffi::SSL_CTX_get_options(self.0) }
    }
    /// `SSL_CTX_get0_ctlog_store` (for `SCT_print`).
    pub(crate) fn ctlog_store(self) -> *const CTLOG_STORE {
        // SAFETY: the context is live.
        unsafe { ffi::SSL_CTX_get0_ctlog_store(self.0) }
    }
}

fn add_crls(st: *mut X509_STORE, crls: &CrlStack) -> bool {
    let sk = crls.as_ptr().cast::<OPENSSL_STACK>();
    // SAFETY: a live stack.
    let n = unsafe { ffi::OPENSSL_sk_num(sk) };
    let mut ret = true;
    for i in 0..n.max(0) {
        // SAFETY: i is in range; the members are CRLs.
        let crl = unsafe { ffi::OPENSSL_sk_value(sk, i) };
        // SAFETY: the store takes its own reference.
        if unsafe { ffi::X509_STORE_add_crl(st, crl.cast()) } != 1 {
            ret = false;
        }
    }
    ret
}

/// `store_setup_crl_download` of `apps.c`: CRL download from the certificates' distribution
/// points, through `X509_STORE_set_lookup_crls`.
pub(crate) fn store_setup_crl_download_raw(st: *mut X509_STORE) {
    if !st.is_null() {
        // SAFETY: st is a live store; the callback is a valid lookup function.
        unsafe { ffi::X509_STORE_set_lookup_crls(st, Some(crls_http_cb)) };
    }
}

impl Store {
    /// `X509_STORE_load_file`.
    pub fn load_file(&self, f: &str) -> bool {
        let Some(c) = cstring(f) else { return false };
        // SAFETY: the store is live; c is a valid C string.
        unsafe { ffi::X509_STORE_load_file(self.as_ptr(), c.as_ptr()) == 1 }
    }
    /// `X509_STORE_load_path`.
    pub fn load_path(&self, d: &str) -> bool {
        let Some(c) = cstring(d) else { return false };
        // SAFETY: as above.
        unsafe { ffi::X509_STORE_load_path(self.as_ptr(), c.as_ptr()) == 1 }
    }
    /// `X509_STORE_load_store`.
    pub fn load_store(&self, s: &str) -> bool {
        let Some(c) = cstring(s) else { return false };
        // SAFETY: as above.
        unsafe { ffi::X509_STORE_load_store(self.as_ptr(), c.as_ptr()) == 1 }
    }
    /// `X509_STORE_add_crl` for each CRL.
    pub fn add_crls(&self, crls: &CrlStack) -> bool {
        add_crls(self.as_ptr(), crls)
    }
    /// `store_setup_crl_download`.
    pub fn setup_crl_download(&self) {
        store_setup_crl_download_raw(self.as_ptr());
    }
}

/// `crls_http_cb` of `apps.c`: the CRLs of the certificate's first distribution point that
/// loads, fetched over HTTP.
unsafe extern "C" fn crls_http_cb(
    ctx: *const X509_STORE_CTX,
    _nm: *const X509_NAME,
) -> *mut stack_st_X509_CRL {
    // SAFETY: a new empty stack.
    let crls = unsafe { ffi::OPENSSL_sk_new_null() };
    if crls.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the context is live during the callback.
    let x = unsafe { ffi::X509_STORE_CTX_get_current_cert(ctx) };
    let crl = load_crl_crldp(x);
    if crl.is_null() {
        // SAFETY: crls is ours and empty.
        unsafe { ffi::OPENSSL_sk_free(crls) };
        return core::ptr::null_mut();
    }
    // SAFETY: crls takes the CRL.
    unsafe { ffi::OPENSSL_sk_push(crls, crl.cast()) };
    // Try to download the delta CRL (FreshestCRL) too.
    // SAFETY: x is live; the extension (or NULL) is ours.
    let fcrl = unsafe {
        ffi::X509_get_ext_d2i(
            x,
            NID_freshest_crl,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    let crl = load_crl_from_dps(fcrl.cast());
    free_dps(fcrl.cast());
    if !crl.is_null() {
        // SAFETY: crls takes the CRL.
        unsafe { ffi::OPENSSL_sk_push(crls, crl.cast()) };
    }
    crls.cast()
}

fn load_crl_crldp(x: *mut X509) -> *mut X509_CRL {
    // SAFETY: x is a live certificate; the extension (or NULL) is ours.
    let crldp = unsafe {
        ffi::X509_get_ext_d2i(
            x,
            NID_crl_distribution_points,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    let crl = load_crl_from_dps(crldp.cast());
    free_dps(crldp.cast());
    crl
}

/// `sk_DIST_POINT_pop_free(sk, DIST_POINT_free)`.
fn free_dps(sk: *mut OPENSSL_STACK) {
    if sk.is_null() {
        return;
    }
    // SAFETY: a live stack of DIST_POINTs we own.
    let n = unsafe { ffi::OPENSSL_sk_num(sk) };
    for i in 0..n.max(0) {
        // SAFETY: i in range.
        let dp = unsafe { ffi::OPENSSL_sk_value(sk, i) };
        // SAFETY: each member is ours.
        unsafe { ffi::DIST_POINT_free(dp.cast()) };
    }
    // SAFETY: the stack is ours.
    unsafe { ffi::OPENSSL_sk_free(sk) };
}

/// The first CRL that loads from a `STACK_OF(DIST_POINT)`'s full-name URIs.
fn load_crl_from_dps(crldp: *mut OPENSSL_STACK) -> *mut X509_CRL {
    if crldp.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: a live stack.
    let n = unsafe { ffi::OPENSSL_sk_num(crldp) };
    for i in 0..n.max(0) {
        // SAFETY: i is in range; the members are DIST_POINTs (a public struct).
        let dp = unsafe { ffi::OPENSSL_sk_value(crldp, i) }.cast::<DIST_POINT>();
        if let Some(url) = dp_url(dp)
            && let Some(c) = cstring(&url)
        {
            {
                // SAFETY: a valid C string; no BIOs; no timeout.
                let crl = unsafe {
                    ffi::X509_CRL_load_http(
                        c.as_ptr(),
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        0,
                    )
                };
                if !crl.is_null() {
                    return crl;
                }
            }
        }
    }
    core::ptr::null_mut()
}

/// `get_dp_url` of `apps.c`: the first URI of a distribution point's full name.
fn dp_url(dp: *const DIST_POINT) -> Option<String> {
    if dp.is_null() {
        return None;
    }
    // SAFETY: dp is a live DIST_POINT; its layout is public.
    let dpn = unsafe { (*dp).distpoint };
    if dpn.is_null() {
        return None;
    }
    // SAFETY: dpn is a live DIST_POINT_NAME.
    let dpn = unsafe { &*dpn };
    if dpn.type_ != 0 {
        return None;
    }
    // SAFETY: type 0 means the full name, a STACK_OF(GENERAL_NAME) (a union member).
    let gens = unsafe { dpn.name.fullname };
    let gens = gens.cast::<OPENSSL_STACK>();
    // SAFETY: a live stack.
    let n = unsafe { ffi::OPENSSL_sk_num(gens) };
    for i in 0..n.max(0) {
        let mut gtype: c_int = 0;
        // SAFETY: i is in range; the members are GENERAL_NAMEs.
        let gname = unsafe { ffi::OPENSSL_sk_value(gens, i) }.cast::<GENERAL_NAME>();
        // SAFETY: gen is live; the value is borrowed.
        let uri = unsafe { ffi::GENERAL_NAME_get0_value(gname, &mut gtype) }.cast::<ASN1_STRING>();
        if gtype == GEN_URI {
            // SAFETY: an IA5STRING.
            let len = unsafe { ffi::ASN1_STRING_length(uri) };
            if len > 6 {
                // SAFETY: data is valid for len bytes.
                let d = unsafe { ffi::ASN1_STRING_get0_data(uri) };
                // SAFETY: as above.
                let s = unsafe { core::slice::from_raw_parts(d, usize::try_from(len).ok()?) };
                return Some(String::from_utf8_lossy(s).into_owned());
            }
        }
    }
    None
}

impl<'a> SslRef<'a> {
    fn ctrl(self, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long {
        // SAFETY: the connection is live; each caller passes the argument its command takes.
        unsafe { ffi::SSL_ctrl(self.0, cmd, larg, parg) }
    }

    /// `SSL_get_SSL_CTX`.
    pub fn ctx(self) -> CtxRef<'a> {
        // SAFETY: the connection is live; the context outlives it.
        CtxRef(unsafe { ffi::SSL_get_SSL_CTX(self.0) }, PhantomData)
    }
    /// `SSL_set_SSL_CTX`.
    pub fn set_ssl_ctx(self, ctx: CtxRef<'_>) {
        // SAFETY: both are live; the connection takes a reference.
        unsafe { ffi::SSL_set_SSL_CTX(self.0, ctx.0) };
    }
    /// `SSL_get_ciphers`.
    pub fn ciphers(self) -> Vec<CipherRef<'a>> {
        // SAFETY: the connection is live; the stack is owned by it.
        ciphers_of(unsafe { ffi::SSL_get_ciphers(self.0) })
    }
    /// `SSL_get1_supported_ciphers` (the stack freed, its ciphers static).
    pub fn supported_ciphers(self) -> Vec<CipherRef<'static>> {
        // SAFETY: the connection is live; the stack is ours.
        let sk = unsafe { ffi::SSL_get1_supported_ciphers(self.0) };
        let v = ciphers_of(sk);
        // SAFETY: only the stack is freed.
        unsafe { ffi::OPENSSL_sk_free(sk.cast()) };
        v
    }
    /// `SSL_is_server`.
    pub fn is_server(self) -> bool {
        // SAFETY: the connection is live.
        unsafe { ffi::SSL_is_server(self.0) != 0 }
    }
    /// `SSL_is_dtls`.
    pub fn is_dtls(self) -> bool {
        // SAFETY: as above.
        unsafe { ffi::SSL_is_dtls(self.0) != 0 }
    }
    /// `SSL_is_quic`.
    pub fn is_quic(self) -> bool {
        // SAFETY: as above.
        unsafe { ffi::SSL_is_quic(self.0) != 0 }
    }
    /// `SSL_version`.
    pub fn version(self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::SSL_version(self.0) }
    }
    /// `SSL_get_version`.
    pub fn version_str(self) -> String {
        // SAFETY: as above; a static string.
        string_at(unsafe { ffi::SSL_get_version(self.0) }).unwrap_or_default()
    }
    /// `SSL_session_reused`.
    pub fn session_reused(self) -> bool {
        // SAFETY: as above.
        unsafe { ffi::SSL_session_reused(self.0) != 0 }
    }
    /// `SSL_get_verify_result`.
    pub fn verify_result(self) -> c_long {
        // SAFETY: as above.
        unsafe { ffi::SSL_get_verify_result(self.0) }
    }
    /// `SSL_get0_peername`.
    pub fn peername(self) -> Option<String> {
        // SAFETY: as above.
        string_at(unsafe { ffi::SSL_get0_peername(self.0) })
    }
    /// `SSL_get0_peer_certificate`.
    pub fn peer_certificate(self) -> Option<CertRef<'a>> {
        // SAFETY: as above; the certificate is owned by the session.
        CertRef::new(unsafe { ffi::SSL_get0_peer_certificate(self.0) })
    }
    /// `SSL_get0_peer_rpk`.
    pub fn peer_rpk(self) -> Option<PkeyRef<'a>> {
        // SAFETY: as above.
        PkeyRef::new(unsafe { ffi::SSL_get0_peer_rpk(self.0) })
    }
    /// `SSL_get_peer_cert_chain` (`None` if there is no stack).
    pub fn peer_cert_chain(self) -> Option<Vec<CertRef<'a>>> {
        // SAFETY: as above.
        let sk = unsafe { ffi::SSL_get_peer_cert_chain(self.0) };
        (!sk.is_null()).then(|| certs_of(sk))
    }
    /// `SSL_get_current_cipher`.
    pub fn current_cipher(self) -> Option<CipherRef<'static>> {
        // SAFETY: as above.
        CipherRef::new(unsafe { ffi::SSL_get_current_cipher(self.0) })
    }
    /// `SSL_get_session` (or `SSL_get0_session`).
    pub fn session(self) -> Option<SessionRef<'a>> {
        // SAFETY: as above.
        SessionRef::new(unsafe { ffi::SSL_get_session(self.0) })
    }
    /// `SSL_set_session`.
    pub fn set_session(self, s: &Session) -> bool {
        // SAFETY: both are live; the connection takes a reference.
        unsafe { ffi::SSL_set_session(self.0, s.as_ptr()) == 1 }
    }
    /// `SSL_get_error`.
    pub fn get_error(self, ret: c_int) -> c_int {
        // SAFETY: the connection is live.
        unsafe { ffi::SSL_get_error(self.0, ret) }
    }
    /// `SSL_read` into `buf`.
    pub fn read(self, buf: &mut [u8]) -> c_int {
        let n = c_int::try_from(buf.len()).unwrap_or(c_int::MAX);
        // SAFETY: buf is writable for n bytes.
        unsafe { ffi::SSL_read(self.0, buf.as_mut_ptr().cast(), n) }
    }
    /// `SSL_write` of `buf`.
    pub fn write(self, buf: &[u8]) -> c_int {
        let n = c_int::try_from(buf.len()).unwrap_or(c_int::MAX);
        // SAFETY: buf is valid for n bytes.
        unsafe { ffi::SSL_write(self.0, buf.as_ptr().cast(), n) }
    }
    /// `SSL_write_early_data`: whether it succeeded, and the bytes written.
    pub fn write_early_data(self, buf: &[u8]) -> (bool, usize) {
        let mut w = 0usize;
        // SAFETY: buf is valid for its length; w is a valid out-pointer.
        let r =
            unsafe { ffi::SSL_write_early_data(self.0, buf.as_ptr().cast(), buf.len(), &mut w) };
        (r == 1, w)
    }
    /// `SSL_read_early_data`: its result and the bytes read.
    pub fn read_early_data(self, buf: &mut [u8]) -> (c_int, usize) {
        let mut n = 0usize;
        // SAFETY: buf is writable for its length; n is a valid out-pointer.
        let r =
            unsafe { ffi::SSL_read_early_data(self.0, buf.as_mut_ptr().cast(), buf.len(), &mut n) };
        (r, n)
    }
    /// `SSL_get_early_data_status`.
    pub fn early_data_status(self) -> c_int {
        // SAFETY: the connection is live.
        unsafe { ffi::SSL_get_early_data_status(self.0) }
    }
    /// `SSL_has_pending`.
    pub fn has_pending(self) -> bool {
        // SAFETY: as above.
        unsafe { ffi::SSL_has_pending(self.0) != 0 }
    }
    /// `SSL_get_fd`.
    pub fn fd(self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::SSL_get_fd(self.0) }
    }
    /// `SSL_set_bio(s, b, b)`: the connection takes the BIO.
    pub fn set_bio(self, b: Bio) {
        let p = b.into_ptr();
        // SAFETY: the connection takes the one reference for both directions.
        unsafe { ffi::SSL_set_bio(self.0, p, p) };
    }
    /// `SSL_get_rbio`.
    pub fn rbio(self) -> Option<BioRef<'a>> {
        // SAFETY: the connection is live; the BIO is owned by it.
        BioRef::new(unsafe { ffi::SSL_get_rbio(self.0) })
    }
    /// `SSL_get_wbio`.
    pub fn wbio(self) -> Option<BioRef<'a>> {
        // SAFETY: as above.
        BioRef::new(unsafe { ffi::SSL_get_wbio(self.0) })
    }
    /// `SSL_set_connect_state`.
    pub fn set_connect_state(self) {
        // SAFETY: the connection is live.
        unsafe { ffi::SSL_set_connect_state(self.0) }
    }
    /// `SSL_set_accept_state`.
    pub fn set_accept_state(self) {
        // SAFETY: as above.
        unsafe { ffi::SSL_set_accept_state(self.0) }
    }
    /// `SSL_shutdown`.
    pub fn shutdown(self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::SSL_shutdown(self.0) }
    }
    /// `SSL_set_shutdown`.
    pub fn set_shutdown(self, mode: c_int) {
        // SAFETY: as above.
        unsafe { ffi::SSL_set_shutdown(self.0, mode) }
    }
    /// `SSL_clear`.
    pub fn clear(self) -> bool {
        // SAFETY: as above.
        unsafe { ffi::SSL_clear(self.0) == 1 }
    }
    /// `SSL_connect`.
    pub fn connect(self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::SSL_connect(self.0) }
    }
    /// `SSL_accept`.
    pub fn accept(self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::SSL_accept(self.0) }
    }
    /// `SSL_do_handshake`.
    pub fn do_handshake(self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::SSL_do_handshake(self.0) }
    }
    /// `SSL_renegotiate`.
    pub fn renegotiate(self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::SSL_renegotiate(self.0) }
    }
    /// `SSL_key_update`.
    pub fn key_update(self, t: c_int) -> bool {
        // SAFETY: as above.
        unsafe { ffi::SSL_key_update(self.0, t) == 1 }
    }
    /// `SSL_get_key_update_type`.
    pub fn key_update_type(self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::SSL_get_key_update_type(self.0) }
    }
    /// `SSL_is_init_finished`.
    pub fn is_init_finished(self) -> bool {
        // SAFETY: as above.
        unsafe { ffi::SSL_is_init_finished(self.0) != 0 }
    }
    /// `SSL_total_renegotiations`.
    pub fn total_renegotiations(self) -> c_long {
        self.ctrl(SSL_CTRL_GET_TOTAL_RENEGOTIATIONS, 0, core::ptr::null_mut())
    }
    /// `SSL_waiting_for_async`.
    pub fn waiting_for_async(self) -> bool {
        // SAFETY: as above.
        unsafe { ffi::SSL_waiting_for_async(self.0) != 0 }
    }
    /// `SSL_verify_client_post_handshake`.
    pub fn verify_client_post_handshake(self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::SSL_verify_client_post_handshake(self.0) }
    }
    /// `SSL_set_verify(s, mode, NULL)`.
    pub fn set_verify_mode(self, mode: c_int) {
        // SAFETY: as above; no callback.
        unsafe { ffi::SSL_set_verify(self.0, mode, None) }
    }
    /// `SSL_get_options`.
    pub fn options(self) -> u64 {
        // SAFETY: as above.
        unsafe { ffi::SSL_get_options(self.0) }
    }
    /// `SSL_set_options`.
    pub fn set_options(self, op: u64) -> u64 {
        // SAFETY: as above.
        unsafe { ffi::SSL_set_options(self.0, op) }
    }
    /// `SSL_set_mode`.
    pub fn set_mode(self, mode: c_long) -> c_long {
        self.ctrl(SSL_CTRL_MODE, mode, core::ptr::null_mut())
    }
    /// `SSL_handle_events`.
    pub fn handle_events(self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::SSL_handle_events(self.0) }
    }
    /// `SSL_get_event_timeout`: the timeout, if not infinite.
    pub fn event_timeout(self) -> Option<Option<std::time::Duration>> {
        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let mut inf: c_int = 0;
        // SAFETY: both out-pointers are valid.
        if unsafe { ffi::SSL_get_event_timeout(self.0, &mut tv, &mut inf) } == 0 {
            return None;
        }
        Some((inf == 0).then(|| tv_duration(&tv)))
    }
    /// `DTLSv1_get_timeout`.
    pub fn dtls_timeout(self) -> Option<std::time::Duration> {
        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        (self.ctrl(DTLS_CTRL_GET_TIMEOUT, 0, (&raw mut tv).cast()) != 0).then(|| tv_duration(&tv))
    }
    /// `DTLSv1_handle_timeout`.
    pub fn dtls_handle_timeout(self) -> c_long {
        self.ctrl(DTLS_CTRL_HANDLE_TIMEOUT, 0, core::ptr::null_mut())
    }
    /// `DTLS_get_link_min_mtu`.
    pub fn dtls_link_min_mtu(self) -> c_long {
        self.ctrl(DTLS_CTRL_GET_LINK_MIN_MTU, 0, core::ptr::null_mut())
    }
    /// `DTLS_set_link_mtu`.
    pub fn dtls_set_link_mtu(self, mtu: c_long) -> bool {
        self.ctrl(DTLS_CTRL_SET_LINK_MTU, mtu, core::ptr::null_mut()) != 0
    }
    /// `SSL_get_certificate`.
    pub fn certificate(self) -> Option<CertRef<'a>> {
        // SAFETY: as above.
        CertRef::new(unsafe { ffi::SSL_get_certificate(self.0) })
    }
    /// `SSL_get0_chain_certs`.
    pub fn chain_certs(self) -> Option<Vec<CertRef<'a>>> {
        let mut sk: *mut stack_st_X509 = core::ptr::null_mut();
        self.ctrl(SSL_CTRL_GET_CHAIN_CERTS, 0, (&raw mut sk).cast());
        (!sk.is_null()).then(|| certs_of(sk))
    }
    /// `SSL_set_post_handshake_auth`.
    pub fn set_post_handshake_auth(self, v: c_int) {
        // SAFETY: as above.
        unsafe { ffi::SSL_set_post_handshake_auth(self.0, v) }
    }
    /// `SSL_set1_client_cert_type`.
    pub fn set1_client_cert_type(self, t: &[u8]) -> bool {
        // SAFETY: t is valid for its length.
        unsafe { ffi::SSL_set1_client_cert_type(self.0, t.as_ptr(), t.len()) == 1 }
    }
    /// `SSL_set1_server_cert_type`.
    pub fn set1_server_cert_type(self, t: &[u8]) -> bool {
        // SAFETY: as above.
        unsafe { ffi::SSL_set1_server_cert_type(self.0, t.as_ptr(), t.len()) == 1 }
    }
    /// `SSL_get_negotiated_client_cert_type`.
    pub fn negotiated_client_cert_type(self) -> c_int {
        // SAFETY: the connection is live.
        unsafe { ffi::SSL_get_negotiated_client_cert_type(self.0) }
    }
    /// `SSL_get_negotiated_server_cert_type`.
    pub fn negotiated_server_cert_type(self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::SSL_get_negotiated_server_cert_type(self.0) }
    }
    /// `SSL_set_tlsext_host_name`.
    pub fn set_tlsext_host_name(self, name: &str) -> bool {
        let Some(c) = cstring(name) else { return false };
        self.ctrl(
            SSL_CTRL_SET_TLSEXT_HOSTNAME,
            c_long::from(TLSEXT_NAMETYPE_host_name),
            c.as_ptr().cast_mut().cast(),
        ) != 0
    }
    /// `SSL_get_servername(s, TLSEXT_NAMETYPE_host_name)`.
    pub fn servername(self) -> Option<Vec<u8>> {
        // SAFETY: as above; the name is owned by the connection.
        let p = unsafe { ffi::SSL_get_servername(self.0, TLSEXT_NAMETYPE_host_name) };
        if p.is_null() {
            return None;
        }
        // SAFETY: p is a NUL-terminated string.
        Some(unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes().to_vec())
    }
    /// `SSL_get_servername_type`.
    pub fn servername_type(self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::SSL_get_servername_type(self.0) }
    }
    /// `SSL_dane_enable`.
    pub fn dane_enable(self, domain: &str) -> c_int {
        let Some(c) = cstring(domain) else { return 0 };
        // SAFETY: as above.
        unsafe { ffi::SSL_dane_enable(self.0, c.as_ptr()) }
    }
    /// `SSL_dane_tlsa_add`.
    pub fn dane_tlsa_add(self, usage: u8, selector: u8, mtype: u8, data: &[u8]) -> c_int {
        // SAFETY: data is valid for its length.
        unsafe { ffi::SSL_dane_tlsa_add(self.0, usage, selector, mtype, data.as_ptr(), data.len()) }
    }
    /// `SSL_dane_set_flags`.
    pub fn dane_set_flags(self, flags: c_ulong) {
        // SAFETY: as above.
        unsafe { ffi::SSL_dane_set_flags(self.0, flags) };
    }
    /// `SSL_get0_dane_authority`: the depth, and whether a public key (`mspki`) matched.
    pub fn dane_authority(self) -> (c_int, bool) {
        let mut pk: *mut EVP_PKEY = core::ptr::null_mut();
        // SAFETY: the out-pointer is valid; the key is borrowed.
        let d = unsafe { ffi::SSL_get0_dane_authority(self.0, core::ptr::null_mut(), &mut pk) };
        (d, !pk.is_null())
    }
    /// `SSL_get0_dane_tlsa`: depth, usage, selector, mtype, data.
    pub fn dane_tlsa(self) -> (c_int, u8, u8, u8, Vec<u8>) {
        let (mut u, mut s, mut m) = (0u8, 0u8, 0u8);
        let mut data: *const u8 = core::ptr::null();
        let mut dlen = 0usize;
        // SAFETY: all out-pointers are valid; the data is owned by the connection.
        let d = unsafe {
            ffi::SSL_get0_dane_tlsa(self.0, &mut u, &mut s, &mut m, &mut data, &mut dlen)
        };
        let v = if data.is_null() {
            Vec::new()
        } else {
            // SAFETY: data is valid for dlen bytes.
            unsafe { core::slice::from_raw_parts(data, dlen) }.to_vec()
        };
        (d, u, s, m, v)
    }
    /// `SSL_get_sigalgs(s, idx, ...)`: the count for `idx = -1`, else (count, sign_nid,
    /// hash_nid, rsign, rhash).
    pub fn sigalgs(self, idx: c_int, shared: bool) -> (c_int, c_int, c_int, u8, u8) {
        let (mut sn, mut hn) = (0, 0);
        let (mut rs, mut rh) = (0u8, 0u8);
        let (psn, phn, prs, prh): (*mut c_int, *mut c_int, *mut u8, *mut u8) = if idx < 0 {
            (
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        } else {
            (&mut sn, &mut hn, &mut rs, &mut rh)
        };
        let n = if shared {
            // SAFETY: the out-pointers are valid or NULL.
            unsafe {
                ffi::SSL_get_shared_sigalgs(
                    self.0,
                    idx.max(0),
                    psn,
                    phn,
                    core::ptr::null_mut(),
                    prs,
                    prh,
                )
            }
        } else {
            // SAFETY: as above.
            unsafe { ffi::SSL_get_sigalgs(self.0, idx, psn, phn, core::ptr::null_mut(), prs, prh) }
        };
        (n, sn, hn, rs, rh)
    }
    /// `SSL_get_peer_signature_nid`.
    pub fn peer_signature_nid(self) -> Option<c_int> {
        let mut n: c_int = 0;
        (self.ctrl(SSL_CTRL_GET_PEER_SIGNATURE_NID, 0, (&raw mut n).cast()) != 0).then_some(n)
    }
    /// `SSL_get0_peer_signature_name`.
    pub fn peer_signature_name(self) -> Option<String> {
        let mut p: *const c_char = core::ptr::null();
        if self.ctrl(SSL_CTRL_GET_PEER_SIGNATURE_NAME, 0, (&raw mut p).cast()) == 0 {
            return None;
        }
        string_at(p)
    }
    /// `SSL_get_peer_signature_type_nid`.
    pub fn peer_signature_type_nid(self) -> Option<c_int> {
        let mut n: c_int = 0;
        // SAFETY: n is a valid out-pointer.
        (unsafe { ffi::SSL_get_peer_signature_type_nid(self.0, &mut n) } != 0).then_some(n)
    }
    /// `SSL_get0_certificate_types`.
    pub fn certificate_types(self) -> Vec<u8> {
        let mut p: *const u8 = core::ptr::null();
        let n = self.ctrl(SSL_CTRL_GET_CLIENT_CERT_TYPES, 0, (&raw mut p).cast());
        bytes_at(p, n)
    }
    /// `SSL_get0_ec_point_formats`.
    pub fn ec_point_formats(self) -> Vec<u8> {
        let mut p: *const u8 = core::ptr::null();
        let n = self.ctrl(SSL_CTRL_GET_EC_POINT_FORMATS, 0, (&raw mut p).cast());
        bytes_at(p, n)
    }
    /// `SSL_get1_groups`.
    pub fn groups(self) -> Vec<c_int> {
        let n = self.ctrl(SSL_CTRL_GET_GROUPS, 0, core::ptr::null_mut());
        let Ok(len) = usize::try_from(n) else {
            return Vec::new();
        };
        let mut v = vec![0 as c_int; len];
        self.ctrl(SSL_CTRL_GET_GROUPS, 0, v.as_mut_ptr().cast());
        v
    }
    /// `SSL_get_shared_group(s, n)`.
    pub fn shared_group(self, n: c_long) -> c_long {
        self.ctrl(SSL_CTRL_GET_SHARED_GROUP, n, core::ptr::null_mut())
    }
    /// `SSL_get_negotiated_group`.
    pub fn negotiated_group(self) -> c_int {
        c_int::try_from(self.ctrl(SSL_CTRL_GET_NEGOTIATED_GROUP, 0, core::ptr::null_mut()))
            .unwrap_or(0)
    }
    /// `SSL_group_to_name`.
    pub fn group_to_name(self, nid: c_int) -> Option<String> {
        // SAFETY: the connection is live; a static string or NULL.
        string_at(unsafe { ffi::SSL_group_to_name(self.0, nid) })
    }
    /// `SSL_get_peer_tmp_key` (an owned reference).
    pub fn peer_tmp_key(self) -> Option<Pkey> {
        let mut k: *mut EVP_PKEY = core::ptr::null_mut();
        if self.ctrl(SSL_CTRL_GET_PEER_TMP_KEY, 0, (&raw mut k).cast()) == 0 {
            return None;
        }
        Pkey::from_raw(k)
    }
    /// `SSL_get0_raw_cipherlist`: the list, and the size of one entry.
    pub fn raw_cipherlist(self) -> (usize, Vec<u8>) {
        let num = self.ctrl(SSL_CTRL_GET_RAW_CIPHERLIST, 0, core::ptr::null_mut());
        let mut p: *const u8 = core::ptr::null();
        let n = self.ctrl(SSL_CTRL_GET_RAW_CIPHERLIST, 0, (&raw mut p).cast());
        (usize::try_from(num).unwrap_or(0), bytes_at(p, n))
    }
    /// `SSL_CIPHER_find(s, id)`.
    pub fn cipher_find(self, id: &[u8; 2]) -> Option<CipherRef<'static>> {
        // SAFETY: id is two bytes; the cipher is static.
        CipherRef::new(unsafe { ffi::SSL_CIPHER_find(self.0, id.as_ptr()) })
    }
    /// `SSL_set_cert_flags(s, 0)`: the current flags.
    pub fn cert_flags(self) -> c_long {
        self.ctrl(SSL_CTRL_CERT_FLAGS, 0, core::ptr::null_mut())
    }
    /// `SSL_check_chain`.
    pub fn check_chain(self, x: &Cert, k: &Pkey, chain: Option<&CertStack>) -> c_int {
        let sk = chain.map_or(core::ptr::null_mut(), CertStack::as_ptr);
        // SAFETY: all are live (or NULL).
        unsafe { ffi::SSL_check_chain(self.0, x.as_ptr(), k.as_ptr(), sk) }
    }
    /// `SSL_certs_clear`.
    pub fn certs_clear(self) {
        // SAFETY: the connection is live.
        unsafe { ffi::SSL_certs_clear(self.0) }
    }
    /// `SSL_use_certificate`.
    pub fn use_certificate(self, x: &Cert) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::SSL_use_certificate(self.0, x.as_ptr()) == 1 }
    }
    /// `SSL_use_PrivateKey`.
    pub fn use_private_key(self, k: &Pkey) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::SSL_use_PrivateKey(self.0, k.as_ptr()) == 1 }
    }
    /// `SSL_build_cert_chain`.
    pub fn build_cert_chain(self, flags: c_long) -> bool {
        self.ctrl(SSL_CTRL_BUILD_CERT_CHAIN, flags, core::ptr::null_mut()) > 0
    }
    /// `SSL_set1_chain`.
    pub fn set1_chain(self, chain: &CertStack) -> bool {
        self.ctrl(SSL_CTRL_CHAIN, 1, chain.as_ptr().cast()) != 0
    }
    /// `SSL_get0_peer_CA_list`.
    pub fn peer_ca_list(self) -> Vec<NameRef<'a>> {
        // SAFETY: the connection is live; the stack is owned by it.
        let sk = unsafe { ffi::SSL_get0_peer_CA_list(self.0) }.cast::<OPENSSL_STACK>();
        // SAFETY: NULL (-1) or a live stack.
        let n = unsafe { ffi::OPENSSL_sk_num(sk) };
        (0..n.max(0))
            // SAFETY: i is in range; the members are names.
            .map(|i| NameRef::new(unsafe { ffi::OPENSSL_sk_value(sk, i) }.cast()))
            .collect()
    }
    /// `SSL_get_secure_renegotiation_support`.
    pub fn secure_renegotiation_support(self) -> bool {
        self.ctrl(SSL_CTRL_GET_RI_SUPPORT, 0, core::ptr::null_mut()) != 0
    }
    /// `SSL_get_current_compression`/`SSL_get_current_expansion` names.
    pub fn compression(self) -> (Option<String>, Option<String>) {
        // SAFETY: the connection is live; the methods are static.
        let c = unsafe { ffi::SSL_get_current_compression(self.0) };
        // SAFETY: as above.
        let e = unsafe { ffi::SSL_get_current_expansion(self.0) };
        let name = |m: *const COMP_METHOD| {
            (!m.is_null())
                // SAFETY: m is a static method.
                .then(|| string_at(unsafe { ffi::SSL_COMP_get_name(m) }))
                .flatten()
        };
        (name(c), name(e))
    }
    /// `SSL_get0_next_proto_negotiated`.
    pub fn next_proto_negotiated(self) -> Option<Vec<u8>> {
        let mut p: *const u8 = core::ptr::null();
        let mut n: c_uint = 0;
        // SAFETY: both out-pointers are valid.
        unsafe { ffi::SSL_get0_next_proto_negotiated(self.0, &mut p, &mut n) };
        (!p.is_null()).then(|| bytes_at(p, c_long::from(n)))
    }
    /// `SSL_get0_alpn_selected`.
    pub fn alpn_selected(self) -> Vec<u8> {
        let mut p: *const u8 = core::ptr::null();
        let mut n: c_uint = 0;
        // SAFETY: as above.
        unsafe { ffi::SSL_get0_alpn_selected(self.0, &mut p, &mut n) };
        bytes_at(p, c_long::from(n))
    }
    /// `SSL_get_selected_srtp_profile`'s name.
    pub fn selected_srtp_profile(self) -> Option<String> {
        // SAFETY: the connection is live; the profile is static.
        let p = unsafe { ffi::SSL_get_selected_srtp_profile(self.0) };
        if p.is_null() {
            return None;
        }
        // SAFETY: a live profile (public layout).
        string_at(unsafe { (*p).name })
    }
    /// `SSL_export_keying_material(s, out, len, label, strlen(label), NULL, 0, 0)`.
    pub fn export_keying_material(self, len: usize, label: &str) -> Option<Vec<u8>> {
        let mut out = vec![0u8; len];
        // SAFETY: out is writable for len bytes; label is valid for its length.
        let r = unsafe {
            ffi::SSL_export_keying_material(
                self.0,
                out.as_mut_ptr(),
                len,
                label.as_ptr().cast(),
                label.len(),
                core::ptr::null(),
                0,
                0,
            )
        };
        (r > 0).then_some(out)
    }
    /// `SSL_get_shared_ciphers(s, buf, size)`.
    pub fn shared_ciphers(self, size: usize) -> Option<String> {
        let mut buf = vec![0 as c_char; size.max(1)];
        let n = c_int::try_from(buf.len()).unwrap_or(c_int::MAX);
        // SAFETY: buf is writable for n bytes.
        string_at(unsafe { ffi::SSL_get_shared_ciphers(self.0, buf.as_mut_ptr(), n) })
    }
    /// `SSL_ct_is_enabled`.
    pub fn ct_is_enabled(self) -> bool {
        // SAFETY: the connection is live.
        unsafe { ffi::SSL_ct_is_enabled(self.0) != 0 }
    }
    /// The peer's SCTs: their count, and each one's validation status and `SCT_print` text.
    pub fn print_peer_scts(self, bio: &Bio) -> c_int {
        // SAFETY: the connection is live; the stack is owned by it.
        let sk = unsafe { ffi::SSL_get0_peer_scts(self.0) }.cast::<OPENSSL_STACK>();
        // SAFETY: NULL (-1) or a live stack.
        let n = if sk.is_null() {
            0
        } else {
            // SAFETY: a live stack.
            unsafe { ffi::OPENSSL_sk_num(sk) }
        };
        let _ = bio.write_all(format!("---\nSCTs present ({n})\n").as_bytes());
        if n > 0 {
            let store = self.ctx().ctlog_store();
            let _ = bio.write_all(b"---\n");
            for i in 0..n {
                // SAFETY: i is in range; the members are SCTs.
                let sct = unsafe { ffi::OPENSSL_sk_value(sk, i) }.cast::<SCT>();
                // SAFETY: sct is live; the string is static.
                let st = string_at(unsafe { ffi::SCT_validation_status_string(sct) })
                    .unwrap_or_default();
                let _ = bio.write_all(format!("SCT validation status: {st}\n").as_bytes());
                // SAFETY: all are live.
                unsafe { ffi::SCT_print(sct, bio.as_ptr(), 0, store) };
                if i < n - 1 {
                    let _ = bio.write_all(b"\n---\n");
                }
            }
            let _ = bio.write_all(b"\n");
        }
        n
    }
    /// `SSL_set_tlsext_status_type(s, TLSEXT_STATUSTYPE_ocsp)`.
    pub fn set_tlsext_status_type_ocsp(self) {
        self.ctrl(
            SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE,
            c_long::from(TLSEXT_STATUSTYPE_ocsp),
            core::ptr::null_mut(),
        );
    }
    /// `SSL_set_session_id_context`.
    pub fn set_session_id_context(self, ctx: &[u8]) -> bool {
        let Ok(n) = c_uint::try_from(ctx.len()) else {
            return false;
        };
        // SAFETY: ctx is valid for n bytes.
        unsafe { ffi::SSL_set_session_id_context(self.0, ctx.as_ptr(), n) == 1 }
    }
    /// `SSL_state_string_long`.
    pub fn state_string_long(self) -> String {
        // SAFETY: the connection is live; a static string.
        string_at(unsafe { ffi::SSL_state_string_long(self.0) }).unwrap_or_default()
    }
    /// `SSL_get_state`.
    pub fn state(self) -> OSSL_HANDSHAKE_STATE {
        // SAFETY: as above.
        unsafe { ffi::SSL_get_state(self.0) }
    }
    /// `SSL_has_matching_session_id`.
    pub fn has_matching_session_id(self, id: &[u8]) -> bool {
        let Ok(n) = c_uint::try_from(id.len()) else {
            return false;
        };
        // SAFETY: id is valid for n bytes.
        unsafe { ffi::SSL_has_matching_session_id(self.0, id.as_ptr(), n) != 0 }
    }
    /// `SSL_get_srp_username`.
    pub fn srp_username(self) -> Option<String> {
        // SAFETY: the connection is live.
        string_at(unsafe { ffi::SSL_get_srp_username(self.0) })
    }
    /// `SSL_get_srp_N` and `SSL_get_srp_g`, printed with `BN_print` by the caller.
    pub fn srp_n_g(self) -> Option<(crate::ssl::BnRef<'a>, crate::ssl::BnRef<'a>)> {
        // SAFETY: the connection is live; the numbers are owned by it.
        let n = unsafe { ffi::SSL_get_srp_N(self.0) };
        // SAFETY: as above.
        let g = unsafe { ffi::SSL_get_srp_g(self.0) };
        if n.is_null() || g.is_null() {
            return None;
        }
        Some((BnRef(n, PhantomData), BnRef(g, PhantomData)))
    }
    /// `DTLSv1_listen`: its result, and the client's address.
    pub fn dtls_listen(self) -> (c_int, Option<crate::sock::Addr>) {
        let Some(a) = crate::sock::Addr::new() else {
            return (-1, None);
        };
        // SAFETY: both are live.
        let r = unsafe { ffi::DTLSv1_listen(self.0, a.as_ptr()) };
        (r, Some(a))
    }
    /// `SSL_stateless`.
    pub fn stateless(self) -> c_int {
        // SAFETY: the connection is live.
        unsafe { ffi::SSL_stateless(self.0) }
    }
    /// `SSL_get_all_async_fds`.
    pub fn all_async_fds(self) -> Option<Vec<c_int>> {
        let mut n = 0usize;
        // SAFETY: a NULL buffer asks for the count.
        if unsafe { ffi::SSL_get_all_async_fds(self.0, core::ptr::null_mut(), &mut n) } == 0 {
            return None;
        }
        let mut v = vec![0 as c_int; n];
        // SAFETY: v has room for n fds.
        if n > 0 && unsafe { ffi::SSL_get_all_async_fds(self.0, v.as_mut_ptr(), &mut n) } == 0 {
            return None;
        }
        Some(v)
    }
    /// `SSL_set1_initial_peer_addr`.
    pub fn set1_initial_peer_addr(self, a: &crate::sock::Addr) -> bool {
        // SAFETY: both are live; the address is copied.
        unsafe { ffi::SSL_set1_initial_peer_addr(self.0, a.as_ptr()) == 1 }
    }
    /// `SSL_set_blocking_mode`.
    pub fn set_blocking_mode(self, b: c_int) -> bool {
        // SAFETY: the connection is live.
        unsafe { ffi::SSL_set_blocking_mode(self.0, b) == 1 }
    }
    /// `SSL_net_read_desired`.
    pub fn net_read_desired(self) -> bool {
        // SAFETY: as above.
        unsafe { ffi::SSL_net_read_desired(self.0) != 0 }
    }
    /// `SSL_net_write_desired`.
    pub fn net_write_desired(self) -> bool {
        // SAFETY: as above.
        unsafe { ffi::SSL_net_write_desired(self.0) != 0 }
    }
    /// `SSL_stream_conclude(s, 0)`.
    pub fn stream_conclude(self) -> bool {
        // SAFETY: as above.
        unsafe { ffi::SSL_stream_conclude(self.0, 0) == 1 }
    }
    /// `SSL_set_srp_server_param` from a user of a verifier file.
    pub fn set_srp_server_param(self, user: &SrpUser) -> c_int {
        // SAFETY: the user is live (public layout).
        let u = unsafe { &*user.0 };
        // SAFETY: the library copies the values.
        unsafe { ffi::SSL_set_srp_server_param(self.0, u.N, u.g, u.s, u.v, u.info) }
    }
    /// `SSL_get_tlsext_status_ocsp_resp`: the stapled response's DER.
    pub fn tlsext_status_ocsp_resp(self) -> Option<Vec<u8>> {
        let mut p: *const u8 = core::ptr::null();
        let n = self.ctrl(
            SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP,
            0,
            (&raw mut p).cast(),
        );
        (!p.is_null()).then(|| bytes_at(p, n))
    }
}

/// A `BIGNUM` lent by its owner.
#[derive(Clone, Copy)]
pub struct BnRef<'a>(*const BIGNUM, PhantomData<&'a ()>);

impl BnRef<'_> {
    /// `BN_print(bio, bn)`.
    pub fn print(self, bio: &Bio) {
        // SAFETY: both are live.
        unsafe { ffi::BN_print(bio.as_ptr(), self.0) };
    }
    /// `SRP_check_known_gN_param(g, N)` with `self` as g.
    pub fn srp_known_gn(self, n: BnRef<'_>) -> bool {
        // SAFETY: both are live.
        !unsafe { ffi::SRP_check_known_gN_param(self.0, n.0) }.is_null()
    }
    /// `BN_num_bits`.
    pub fn num_bits(self) -> c_int {
        // SAFETY: the number is live.
        unsafe { ffi::BN_num_bits(self.0) }
    }
    /// `srp_Verify_N_and_g` of `tlssrp_depr.c`: N a safe prime with g a generator.
    pub fn srp_verify_n_and_g(n: BnRef<'_>, g: BnRef<'_>) -> bool {
        // SAFETY: no arguments; new objects (checked below), freed at the end.
        let ctx = unsafe { ffi::BN_CTX_new() };
        // SAFETY: as above.
        let p = unsafe { ffi::BN_new() };
        // SAFETY: as above.
        let r = unsafe { ffi::BN_new() };
        let null = core::ptr::null_mut();
        // Every pointer is checked before use; the calls follow the C expression's order.
        let check = || {
            if ctx.is_null() {
                return false;
            }
            // SAFETY: n is live.
            if unsafe { ffi::BN_is_odd(n.0) } == 0 {
                return false;
            }
            // SAFETY: n and ctx are live.
            if unsafe { ffi::BN_check_prime(n.0, ctx, null) } != 1 || p.is_null() {
                return false;
            }
            // SAFETY: p and n are live.
            if unsafe { ffi::BN_rshift1(p, n.0) } == 0 {
                return false;
            }
            // SAFETY: p and ctx are live.
            if unsafe { ffi::BN_check_prime(p, ctx, null) } != 1 || r.is_null() {
                return false;
            }
            // SAFETY: all are live.
            if unsafe { ffi::BN_mod_exp(r, g.0, p, n.0, ctx) } == 0 {
                return false;
            }
            // SAFETY: r is live.
            if unsafe { ffi::BN_add_word(r, 1) } == 0 {
                return false;
            }
            // SAFETY: r and n are live.
            unsafe { ffi::BN_cmp(r, n.0) == 0 }
        };
        let ret = check();
        // SAFETY: NULL or ours.
        unsafe { ffi::BN_free(r) };
        // SAFETY: as above.
        unsafe { ffi::BN_free(p) };
        // SAFETY: as above.
        unsafe { ffi::BN_CTX_free(ctx) };
        ret
    }
}

/// A user of an SRP verifier file (`SRP_user_pwd`), owned.
pub struct SrpUser(*mut SRP_user_pwd);

impl Drop for SrpUser {
    fn drop(&mut self) {
        // SAFETY: owned, freed once.
        unsafe { ffi::SRP_user_pwd_free(self.0) };
    }
}

impl SrpUser {
    /// Its `info` field.
    pub fn info(&self) -> Option<String> {
        // SAFETY: the user is live (public layout).
        string_at(unsafe { (*self.0).info })
    }
}

/// An `SRP_VBASE`, owned.
pub struct SrpVbase(core::ptr::NonNull<SRP_VBASE>);

impl Drop for SrpVbase {
    fn drop(&mut self) {
        // SAFETY: owned, freed once.
        unsafe { ffi::SRP_VBASE_free(self.0.as_ptr()) };
    }
}

impl SrpVbase {
    /// `SRP_VBASE_new(seed)`.
    pub fn new(seed: Option<&str>) -> Option<Self> {
        let s = opt_cstr(seed)?;
        // SAFETY: the seed is copied.
        core::ptr::NonNull::new(unsafe { ffi::SRP_VBASE_new(ptr_of(&s).cast_mut()) }).map(Self)
    }
    /// `SRP_VBASE_init(vb, file)`.
    pub fn init(&self, file: &str) -> c_int {
        let Some(c) = cstring(file) else {
            return SRP_ERR_OPEN_FILE;
        };
        // SAFETY: both are live.
        unsafe { ffi::SRP_VBASE_init(self.0.as_ptr(), c.as_ptr().cast_mut()) }
    }
    /// `SRP_VBASE_get1_by_user`.
    pub fn get1_by_user(&self, user: &str) -> Option<SrpUser> {
        let c = cstring(user)?;
        // SAFETY: both are live; the result is ours.
        let u = unsafe { ffi::SRP_VBASE_get1_by_user(self.0.as_ptr(), c.as_ptr().cast_mut()) };
        (!u.is_null()).then_some(SrpUser(u))
    }
}

fn bytes_at(p: *const u8, n: c_long) -> Vec<u8> {
    match usize::try_from(n) {
        Ok(n) if !p.is_null() && n > 0 => {
            // SAFETY: the library returned p with n valid bytes, owned by the object queried.
            unsafe { core::slice::from_raw_parts(p, n) }.to_vec()
        }
        _ => Vec::new(),
    }
}

fn tv_duration(tv: &libc::timeval) -> std::time::Duration {
    let s = u64::try_from(tv.tv_sec).unwrap_or(0);
    let us = u32::try_from(tv.tv_usec).unwrap_or(0);
    std::time::Duration::new(s, us.saturating_mul(1000).min(999_999_999))
}

fn free_name_stack(nm: *mut stack_st_X509_NAME) {
    if nm.is_null() {
        return;
    }
    let sk = nm.cast::<OPENSSL_STACK>();
    // SAFETY: a live stack of names we own.
    let n = unsafe { ffi::OPENSSL_sk_num(sk) };
    for i in 0..n.max(0) {
        // SAFETY: i in range.
        let nm = unsafe { ffi::OPENSSL_sk_value(sk, i) };
        // SAFETY: each name is ours.
        unsafe { ffi::X509_NAME_free(nm.cast()) };
    }
    // SAFETY: the stack is ours.
    unsafe { ffi::OPENSSL_sk_free(sk) };
}

impl ConfCtx {
    /// `SSL_CONF_CTX_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::SSL_CONF_CTX_new() })
    }
    /// `SSL_CONF_CTX_set_flags`.
    pub fn set_flags(&self, flags: c_uint) -> c_uint {
        // SAFETY: the context is live.
        unsafe { ffi::SSL_CONF_CTX_set_flags(self.as_ptr(), flags) }
    }
    /// `SSL_CONF_CTX_set_ssl_ctx`.
    pub fn set_ssl_ctx(&self, ctx: CtxRef<'_>) {
        // SAFETY: both are live; the SSL_CTX outlives its use here (config_ctx).
        unsafe { ffi::SSL_CONF_CTX_set_ssl_ctx(self.as_ptr(), ctx.0) }
    }
    /// `SSL_CONF_cmd`.
    pub fn cmd(&self, flag: &str, arg: Option<&str>) -> c_int {
        let (Some(f), Some(a)) = (cstring(flag), opt_cstr(arg)) else {
            return 0;
        };
        // SAFETY: the strings are valid or NULL.
        unsafe { ffi::SSL_CONF_cmd(self.as_ptr(), f.as_ptr(), ptr_of(&a)) }
    }
    /// `SSL_CONF_CTX_finish`.
    pub fn finish(&self) -> bool {
        // SAFETY: the context is live.
        unsafe { ffi::SSL_CONF_CTX_finish(self.as_ptr()) == 1 }
    }
}

/// `SSL_alert_type_string_long`.
pub fn alert_type_string_long(v: c_int) -> String {
    // SAFETY: a static string.
    string_at(unsafe { ffi::SSL_alert_type_string_long(v) }).unwrap_or_default()
}

/// `SSL_alert_desc_string_long`.
pub fn alert_desc_string_long(v: c_int) -> String {
    // SAFETY: a static string.
    string_at(unsafe { ffi::SSL_alert_desc_string_long(v) }).unwrap_or_default()
}

/// `BIO_dump(bio, data, len)`.
pub fn bio_dump(bio: &Bio, data: &[u8]) {
    let n = c_int::try_from(data.len()).unwrap_or(c_int::MAX);
    // SAFETY: data is valid for n bytes.
    unsafe { ffi::BIO_dump(bio.as_ptr(), data.as_ptr().cast(), n) };
}

/// `BIO_dump_indent(bio, data, len, indent)`.
pub fn bio_dump_indent(bio: &Bio, data: &[u8], indent: c_int) {
    let n = c_int::try_from(data.len()).unwrap_or(c_int::MAX);
    // SAFETY: as above.
    unsafe { ffi::BIO_dump_indent(bio.as_ptr(), data.as_ptr().cast(), n, indent) };
}

/// `OBJ_nid2sn`.
pub fn nid2sn(nid: c_int) -> Option<String> {
    // SAFETY: a static string or NULL.
    string_at(unsafe { ffi::OBJ_nid2sn(nid) })
}

/// `OBJ_nid2ln`.
pub fn nid2ln(nid: c_int) -> Option<String> {
    // SAFETY: as above.
    string_at(unsafe { ffi::OBJ_nid2ln(nid) })
}

/// `EC_curve_nid2nist`.
pub fn ec_curve_nid2nist(nid: c_int) -> Option<String> {
    // SAFETY: as above.
    string_at(unsafe { ffi::EC_curve_nid2nist(nid) })
}

/// `X509_verify_cert_error_string`.
pub fn verify_cert_error_string(e: c_long) -> String {
    // SAFETY: a static string.
    string_at(unsafe { ffi::X509_verify_cert_error_string(e) }).unwrap_or_default()
}

/// `EVP_Q_mac(NULL, "HMAC", NULL, "SHA1", NULL, key, data, out, outsize)`.
pub fn hmac_sha1(key: &[u8], data: &[u8], outsize: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; outsize];
    let mut n = 0usize;
    // SAFETY: every buffer is valid for its length; the strings are static.
    let r = unsafe {
        ffi::EVP_Q_mac(
            core::ptr::null_mut(),
            c"HMAC".as_ptr(),
            core::ptr::null(),
            c"SHA1".as_ptr(),
            core::ptr::null(),
            key.as_ptr().cast(),
            key.len(),
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
            outsize,
            &mut n,
        )
    };
    if r.is_null() {
        return None;
    }
    out.truncate(n);
    Some(out)
}

/// `RAND_bytes` into `buf`.
pub fn rand_bytes(buf: &mut [u8]) -> bool {
    let Ok(n) = c_int::try_from(buf.len()) else {
        return false;
    };
    // SAFETY: buf is writable for n bytes.
    unsafe { ffi::RAND_bytes(buf.as_mut_ptr(), n) > 0 }
}

/// `OSSL_sleep(ms)`.
pub fn sleep_ms(ms: u64) {
    // SAFETY: no pointers.
    unsafe { ffi::OSSL_sleep(ms) };
}

/// `X509_get0_pubkey` of a certificate.
pub fn cert_pubkey(x: &Cert) -> Option<PkeyRef<'_>> {
    // SAFETY: the certificate is live; the key is owned by it.
    PkeyRef::new(unsafe { ffi::X509_get0_pubkey(x.as_ptr()) })
}

/// `X509_get_signature_nid`.
pub fn cert_signature_nid(x: &Cert) -> c_int {
    // SAFETY: the certificate is live.
    unsafe { ffi::X509_get_signature_nid(x.as_ptr()) }
}

/// `ASN1_TIME_print(bio, X509_get0_notBefore(x))` / notAfter.
pub fn print_cert_time(bio: &Bio, x: &Cert, not_after: bool) {
    let t = if not_after {
        // SAFETY: the certificate is live; the time is owned by it.
        unsafe { ffi::X509_get0_notAfter(x.as_ptr()) }
    } else {
        // SAFETY: as above.
        unsafe { ffi::X509_get0_notBefore(x.as_ptr()) }
    };
    // SAFETY: both are live.
    unsafe { ffi::ASN1_TIME_print(bio.as_ptr(), t) };
}

/// `PEM_write_bio_X509`.
pub fn write_cert_pem(bio: &Bio, x: &Cert) -> bool {
    // SAFETY: both are live.
    unsafe { ffi::PEM_write_bio_X509(bio.as_ptr(), x.as_ptr()) == 1 }
}

/// `X509_print`.
pub fn print_cert(bio: &Bio, x: &Cert) {
    // SAFETY: both are live.
    unsafe { ffi::X509_print(bio.as_ptr(), x.as_ptr()) };
}

/// `PEM_write_bio(bio, name, "", data, len)`.
pub fn pem_write(bio: &Bio, name: &str, data: &[u8]) {
    let Some(n) = cstring(name) else { return };
    let Ok(len) = c_long::try_from(data.len()) else {
        return;
    };
    // SAFETY: the strings are valid; data is valid for len bytes.
    unsafe { ffi::PEM_write_bio(bio.as_ptr(), n.as_ptr(), c"".as_ptr(), data.as_ptr(), len) };
}

impl Pkey {
    /// `EVP_PKEY_get_id`.
    pub fn id(&self) -> c_int {
        // SAFETY: the key is live.
        unsafe { ffi::EVP_PKEY_get_id(self.as_ptr()) }
    }
    /// `EVP_PKEY_get_base_id`.
    pub fn base_id(&self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::EVP_PKEY_get_base_id(self.as_ptr()) }
    }
    /// `EVP_PKEY_get_bits`.
    pub fn bits(&self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::EVP_PKEY_get_bits(self.as_ptr()) }
    }
    /// `EVP_PKEY_get0_type_name`.
    pub fn type_name(&self) -> Option<String> {
        // SAFETY: as above.
        string_at(unsafe { ffi::EVP_PKEY_get0_type_name(self.as_ptr()) })
    }
    /// `EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, name, 80, &len)`.
    pub fn group_name_param(&self) -> Option<String> {
        let mut buf = [0 as c_char; 80];
        let mut len = 0usize;
        // SAFETY: buf is writable for 80 bytes; the parameter name is static.
        let ok = unsafe {
            ffi::EVP_PKEY_get_utf8_string_param(
                self.as_ptr(),
                c"group".as_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut len,
            )
        };
        if ok == 0 {
            return None;
        }
        string_at(buf.as_ptr())
    }
    /// `EVP_PKEY_get_group_name` (the `ec_curve_name` of `s_client.c`).
    pub fn group_name(&self) -> Option<String> {
        let mut n = 0usize;
        // SAFETY: a NULL buffer asks for the length.
        if unsafe { ffi::EVP_PKEY_get_group_name(self.as_ptr(), core::ptr::null_mut(), 0, &mut n) }
            == 0
        {
            return None;
        }
        let mut buf = vec![0 as c_char; n + 1];
        // SAFETY: buf has room for the name and its NUL.
        if unsafe {
            ffi::EVP_PKEY_get_group_name(
                self.as_ptr(),
                buf.as_mut_ptr(),
                n + 1,
                core::ptr::null_mut(),
            )
        } == 0
        {
            return None;
        }
        string_at(buf.as_ptr())
    }
    /// `EVP_PKEY_print_public(bio, key, indent, NULL)`.
    pub fn print_public(&self, bio: &Bio, indent: c_int) {
        // SAFETY: both are live.
        unsafe {
            ffi::EVP_PKEY_print_public(bio.as_ptr(), self.as_ptr(), indent, core::ptr::null_mut())
        };
    }
    /// `EVP_PKEY_up_ref`: a second owned reference.
    pub fn up_ref(&self) -> Option<Pkey> {
        // SAFETY: the key is live.
        if unsafe { ffi::EVP_PKEY_up_ref(self.as_ptr()) } != 1 {
            return None;
        }
        Pkey::from_raw(self.as_ptr())
    }
}

/// `OPENSSL_strdup` of a Rust string, for C callbacks whose result the library frees.
pub(crate) fn c_strdup(s: &str) -> *mut c_char {
    let Some(c) = cstring(s) else {
        return core::ptr::null_mut();
    };
    // SAFETY: a valid C string; the copy is the library's to free.
    unsafe { ffi::CRYPTO_strdup(c.as_ptr(), c"rustyssl-ossl".as_ptr(), 0) }
}

/// `ASN1_get_object(&p, &len, &tag, &xclass, max)` on `buf`: its result, the content length,
/// tag and class, and how many octets the header took.
pub fn asn1_get_object(buf: &[u8], max: c_long) -> (c_int, c_long, c_int, c_int, usize) {
    let mut p = buf.as_ptr();
    let (mut len, mut tag, mut class): (c_long, c_int, c_int) = (0, 0, 0);
    let max = max.min(c_long::try_from(buf.len()).unwrap_or(c_long::MAX));
    // SAFETY: p is valid for max (<= buf.len()) bytes; the out-pointers are valid.
    let r = unsafe { ffi::ASN1_get_object(&mut p, &mut len, &mut tag, &mut class, max) };
    let used = (p as usize).saturating_sub(buf.as_ptr() as usize);
    (r, len, tag, class, used)
}

/// `ASN1_generate_nconf(genstr, cnf)` of a configuration text: `Err(line)` if the text
/// doesn't load (`NCONF_load_bio`'s error line), `Ok(None)` if the string doesn't generate a
/// SEQUENCE, else the SEQUENCE's content octets.
pub fn asn1_generate_sequence(
    conf_text: &str,
    section: &str,
    name: &str,
) -> Result<Option<Vec<u8>>, c_long> {
    let conf = crate::conf::Conf::new(None).ok_or(0)?;
    let bio = Bio::from_bytes(conf_text.as_bytes()).ok_or(0)?;
    let (r, errline) = conf.load_bio(&bio);
    if r <= 0 {
        return Err(errline);
    }
    let Some(genstr) = conf.get_string(Some(section), name) else {
        return Ok(None);
    };
    let g = cstring(&genstr).ok_or(0)?;
    // SAFETY: valid strings and a live conf; the result is ours.
    let t = unsafe { ffi::ASN1_generate_nconf(g.as_ptr(), conf.as_ptr()) };
    if t.is_null() {
        return Ok(None);
    }
    // SAFETY: t is a live ASN1_TYPE (public layout).
    let ty = unsafe { &*t };
    let out = if ty.type_ == V_ASN1_SEQUENCE {
        // SAFETY: a SEQUENCE's value is an ASN1_STRING of its encoding.
        let s = unsafe { ty.value.sequence };
        // SAFETY: s is a live ASN1_STRING.
        let len = usize::try_from(unsafe { ffi::ASN1_STRING_length(s) }).unwrap_or(0);
        // SAFETY: as above.
        let d = unsafe { ffi::ASN1_STRING_get0_data(s) };
        Some(bytes_at(d, c_long::try_from(len).unwrap_or(0)))
    } else {
        None
    };
    // SAFETY: t is ours.
    unsafe { ffi::ASN1_TYPE_free(t) };
    Ok(out)
}

/// `OSSL_HTTP_proxy_connect(bio, server, port, proxyuser, proxypass, timeout, bio_err,
/// prog)`.
#[allow(clippy::too_many_arguments)]
pub fn http_proxy_connect(
    bio: &Bio,
    server: &str,
    port: &str,
    user: Option<&str>,
    pass: Option<&str>,
    timeout: c_int,
    bio_err: Option<&Bio>,
    prog: &str,
) -> bool {
    let (Some(s), Some(p), Some(u), Some(pw), Some(pr)) = (
        cstring(server),
        cstring(port),
        opt_cstr(user),
        opt_cstr(pass),
        cstring(prog),
    ) else {
        return false;
    };
    let be = bio_err.map_or(core::ptr::null_mut(), Bio::as_ptr);
    // SAFETY: the strings are valid or NULL; the BIOs are live.
    unsafe {
        ffi::OSSL_HTTP_proxy_connect(
            bio.as_ptr(),
            s.as_ptr(),
            p.as_ptr(),
            ptr_of(&u),
            ptr_of(&pw),
            timeout,
            be,
            pr.as_ptr(),
        ) == 1
    }
}

/// `d2i_OCSP_RESPONSE` then `OCSP_RESPONSE_print(bio, rsp, flags)`: false if it doesn't
/// parse.
pub fn ocsp_response_print(bio: &Bio, der: &[u8], flags: c_ulong) -> bool {
    let Ok(len) = c_long::try_from(der.len()) else {
        return false;
    };
    let mut p = der.as_ptr();
    // SAFETY: p is valid for len bytes; the result is ours.
    let r = unsafe { ffi::d2i_OCSP_RESPONSE(core::ptr::null_mut(), &mut p, len) };
    if r.is_null() {
        return false;
    }
    // SAFETY: both are live.
    unsafe { ffi::OCSP_RESPONSE_print(bio.as_ptr(), r, flags) };
    // SAFETY: r is ours.
    unsafe { ffi::OCSP_RESPONSE_free(r) };
    true
}

impl SslRef<'_> {
    /// `SSL_get0_tlsext_status_ocsp_resp_ex`: each stapled response's DER (`None` for a NULL
    /// entry); `None` without a stack.
    pub fn tlsext_status_ocsp_resp_ex(self) -> Option<Vec<Option<Vec<u8>>>> {
        let mut sk: *mut OPENSSL_STACK = core::ptr::null_mut();
        self.ctrl(
            SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP_EX,
            0,
            (&raw mut sk).cast(),
        );
        if sk.is_null() {
            return None;
        }
        // SAFETY: a live stack owned by the connection.
        let n = unsafe { ffi::OPENSSL_sk_num(sk) };
        let mut out = Vec::new();
        for i in 0..n.max(0) {
            // SAFETY: i in range; the members are OCSP responses or NULL.
            let r = unsafe { ffi::OPENSSL_sk_value(sk, i) }.cast::<OCSP_RESPONSE>();
            out.push(ocsp_der(r));
        }
        Some(out)
    }
}

fn ocsp_der(r: *const OCSP_RESPONSE) -> Option<Vec<u8>> {
    if r.is_null() {
        return None;
    }
    // SAFETY: r is live; NULL asks for the length.
    let n = unsafe { ffi::i2d_OCSP_RESPONSE(r, core::ptr::null_mut()) };
    let len = usize::try_from(n).ok()?;
    let mut v = vec![0u8; len];
    let mut p = v.as_mut_ptr();
    // SAFETY: v has room for the encoding.
    (unsafe { ffi::i2d_OCSP_RESPONSE(r, &mut p) } == n).then_some(v)
}

/// `OPENSSL_hexchar2int`.
pub fn hexchar2int(c: u8) -> c_int {
    // SAFETY: a plain value.
    unsafe { ffi::OPENSSL_hexchar2int(c) }
}
