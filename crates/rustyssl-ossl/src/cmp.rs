//! CMP (`openssl/cmp.h`, `openssl/crmf.h`): the client context, messages, and a server
//! context whose callbacks call a Rust [`Server`], for `openssl cmp` and its mock server.
//!
//! The library calls back into the CLI four ways: logging, the message transfer, the server's
//! request handlers, and TLS setup (`app_http_tls_cb` of [`crate::http`]). The trampolines are
//! here; what they do is the caller's (a closure or a [`Server`]), so the CLI's logic stays in
//! the CLI.

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_long, c_void};
use core::marker::PhantomData;
use core::ptr;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::abi::{
    ASN1_INTEGER, ASN1_OCTET_STRING, ASN1_TIME, BIO, EVP_PKEY, GENERAL_NAME, OSSL_CMP_ATAV,
    OSSL_CMP_ATAVS, OSSL_CMP_CRLSTATUS, OSSL_CMP_CTX, OSSL_CMP_ITAV, OSSL_CMP_MSG,
    OSSL_CMP_PKIFREETEXT, OSSL_CMP_PKISI, OSSL_CMP_SRV_CTX, OSSL_CRMF_CERTTEMPLATE, OSSL_CRMF_MSG,
    X509, X509_ALGOR, X509_EXTENSION, X509_NAME, X509_REQ, X509_STORE, X509_STORE_CTX,
    stack_st_ASN1_UTF8STRING, stack_st_OSSL_CMP_CRLSTATUS, stack_st_OSSL_CMP_ITAV, stack_st_X509,
    stack_st_X509_EXTENSION,
};
use crate::bio::Bio;
use crate::conf::Conf;
use crate::ffi;
use crate::http::{SslCtx, TlsInfo};
use crate::object::Object;
use crate::pkey::Pkey;
use crate::provider::LibCtx;
use crate::util::{cstring, string_at};
use crate::x509::{Cert, CertStack, Crl, Name, NameRef, Req, Store, V3Ctx};

/// Borrowed views of library objects: `&View` is a pointer to the object, valid while the
/// reference is (the object's owner outlives it).
macro_rules! view {
    ($(#[$m:meta])* $name:ident, $ty:ty) => {
        $(#[$m])*
        pub struct $name(UnsafeCell<[u8; 0]>, PhantomData<*mut ()>);

        impl $name {
            /// The object at `p` (NULL: `None`), borrowed for `'a`: the caller passes an
            /// object that stays live at least that long.
            #[allow(dead_code)]
            pub(crate) fn from_raw<'a>(p: *const $ty) -> Option<&'a Self> {
                // SAFETY: a zero-sized type at a non-NULL address; the object is live for 'a
                // (the caller's contract above), and the view only hands the pointer back.
                unsafe { p.cast::<Self>().as_ref() }
            }

            /// The object, for the C API.
            pub fn as_ptr(&self) -> *mut $ty {
                (self as *const Self).cast_mut().cast()
            }
        }
    };
}

/// An owned object whose view is `$view`.
macro_rules! owned {
    ($(#[$m:meta])* $name:ident, $ty:ty, $view:ident, $free:ident) => {
        $(#[$m])*
        pub struct $name(ptr::NonNull<$ty>);

        impl $name {
            /// Takes ownership of `p` (NULL: `None`).
            pub(crate) fn from_ptr(p: *mut $ty) -> Option<Self> {
                ptr::NonNull::new(p).map(Self)
            }

            /// Gives up ownership.
            pub fn into_ptr(self) -> *mut $ty {
                let p = self.0.as_ptr();
                core::mem::forget(self);
                p
            }
        }

        impl core::ops::Deref for $name {
            type Target = $view;
            fn deref(&self) -> &$view {
                // SAFETY: the object is owned by self, so it lives as long as the borrow.
                unsafe { &*self.0.as_ptr().cast::<$view>() }
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                // SAFETY: the pointer is owned by self, and freed exactly once, here.
                unsafe { ffi::$free(self.0.as_ptr()) };
            }
        }
    };
}

view!(
    /// An `OSSL_CMP_CTX`.
    Ctx, OSSL_CMP_CTX
);
view!(
    /// An `OSSL_CMP_MSG`.
    MsgRef, OSSL_CMP_MSG
);
view!(
    /// An `OSSL_CRMF_MSG`.
    CrmfMsgRef, OSSL_CRMF_MSG
);
view!(
    /// An `X509_REQ` (a PKCS#10 request in a `p10cr`).
    ReqRef, X509_REQ
);
view!(
    /// An `OSSL_CMP_ITAV`.
    ItavRef, OSSL_CMP_ITAV
);
view!(
    /// An `OSSL_CMP_PKISI`.
    PkisiRef, OSSL_CMP_PKISI
);
view!(
    /// An `ASN1_INTEGER`.
    IntegerRef, ASN1_INTEGER
);
view!(
    /// An `OSSL_CMP_CRLSTATUS`.
    CrlStatusRef, OSSL_CMP_CRLSTATUS
);
view!(
    /// An `OSSL_CMP_ATAV`.
    AtavRef, OSSL_CMP_ATAV
);
view!(
    /// An `X509_ALGOR`.
    AlgorRef, X509_ALGOR
);
view!(
    /// An `OSSL_CMP_PKIFREETEXT` (a stack of `ASN1_UTF8STRING`).
    FreeTextRef, OSSL_CMP_PKIFREETEXT
);
view!(
    /// An `OSSL_CMP_SRV_CTX`.
    SrvRef, OSSL_CMP_SRV_CTX
);
view!(
    /// An `OSSL_CRMF_CERTTEMPLATE`.
    CertTemplateRef, OSSL_CRMF_CERTTEMPLATE
);

owned!(
    /// An owned `OSSL_CMP_MSG`.
    Msg, OSSL_CMP_MSG, MsgRef, OSSL_CMP_MSG_free
);
owned!(
    /// An owned `OSSL_CMP_PKISI`.
    Pkisi, OSSL_CMP_PKISI, PkisiRef, OSSL_CMP_PKISI_free
);
owned!(
    /// An owned `OSSL_CMP_ITAV`.
    Itav, OSSL_CMP_ITAV, ItavRef, OSSL_CMP_ITAV_free
);
owned!(
    /// An owned `OSSL_CMP_ATAV`.
    Atav, OSSL_CMP_ATAV, AtavRef, OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free
);
owned!(
    /// An owned `OSSL_CRMF_CERTTEMPLATE`.
    CertTemplate, OSSL_CRMF_CERTTEMPLATE, CertTemplateRef, OSSL_CRMF_CERTTEMPLATE_free
);

crate::handle!(
    /// An owned `GENERAL_NAME`.
    GeneralName, GENERAL_NAME, GENERAL_NAME_free
);

fn cert_ptr(c: Option<&Cert>) -> *mut X509 {
    c.map_or(ptr::null_mut(), Cert::as_ptr)
}

fn libctx_ptr(l: Option<&LibCtx>) -> *mut crate::abi::OSSL_LIB_CTX {
    l.map_or(ptr::null_mut(), LibCtx::as_ptr)
}

/// The members of a stack the caller borrows (NULL: none).
fn members<T>(sk: *const c_void) -> Vec<*mut T> {
    if sk.is_null() {
        return Vec::new();
    }
    // SAFETY: sk is a live stack.
    let n = unsafe { ffi::OPENSSL_sk_num(sk.cast()) };
    (0..n.max(0))
        // SAFETY: i is in range.
        .map(|i| unsafe { ffi::OPENSSL_sk_value(sk.cast(), i) }.cast::<T>())
        .collect()
}

/// The bytes of an `ASN1_STRING` the caller borrows (NULL: `None`).
fn string_bytes(s: *const crate::abi::ASN1_STRING) -> Option<Vec<u8>> {
    if s.is_null() {
        return None;
    }
    // SAFETY: s is a live string.
    let data = unsafe { ffi::ASN1_STRING_get0_data(s) };
    // SAFETY: as above.
    let len = usize::try_from(unsafe { ffi::ASN1_STRING_length(s) }).ok()?;
    if data.is_null() {
        return Some(Vec::new());
    }
    // SAFETY: data holds len bytes owned by the string.
    Some(unsafe { core::slice::from_raw_parts(data, len) }.to_vec())
}

/// A new `ASN1_OCTET_STRING` holding `data` (NULL for `None`), or `Err` when out of memory.
fn octet_string(data: Option<&[u8]>) -> Result<*mut ASN1_OCTET_STRING, ()> {
    let Some(d) = data else {
        return Ok(ptr::null_mut());
    };
    let len = c_int::try_from(d.len()).map_err(|_| ())?;
    // SAFETY: no arguments.
    let s = unsafe { ffi::ASN1_OCTET_STRING_new() };
    if s.is_null() {
        return Err(());
    }
    // SAFETY: s is live; d holds len bytes.
    if unsafe { ffi::ASN1_OCTET_STRING_set(s, d.as_ptr(), len) } == 1 {
        Ok(s)
    } else {
        // SAFETY: s is owned here.
        unsafe { ffi::ASN1_OCTET_STRING_free(s) };
        Err(())
    }
}

/// `OBJ_ln2nid(s)`.
pub fn ln2nid(s: &str) -> c_int {
    let Some(c) = cstring(s) else {
        return crate::abi::NID_undef as c_int;
    };
    // SAFETY: c is a valid C string.
    unsafe { ffi::OBJ_ln2nid(c.as_ptr()) }
}

/// `ERR_raise_data(ERR_LIB_CMP, reason, data)` from `func` at `file:line` (`ERR_raise`
/// without data).
pub fn raise(
    reason: c_int,
    file: &'static core::ffi::CStr,
    line: c_int,
    func: &'static core::ffi::CStr,
    data: Option<&str>,
) {
    // SAFETY: no pointer arguments.
    unsafe { ffi::ERR_new() };
    // SAFETY: the strings are static C strings.
    unsafe { ffi::ERR_set_debug(file.as_ptr(), line, func.as_ptr()) };
    let lib = crate::abi::ERR_LIB_CMP as c_int;
    match data.and_then(cstring) {
        Some(d) => {
            let f = ffi::ERR_set_error();
            // SAFETY: a "%s" format with one C string argument.
            unsafe { f(lib, reason, c"%s".as_ptr(), d.as_ptr()) };
        }
        None => {
            let f = ffi::ERR_set_error();
            // SAFETY: no format.
            unsafe { f(lib, reason, ptr::null()) };
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Logging

static LOG_OUT: AtomicPtr<BIO> = AtomicPtr::new(ptr::null_mut());
static LOG_ERR: AtomicPtr<BIO> = AtomicPtr::new(ptr::null_mut());

/// The `BIO`s the log callbacks print to (`bio_out` and `bio_err`), which live to the end of
/// the program.
pub fn set_log_bios(out: &'static Bio, err: &'static Bio) {
    LOG_OUT.store(out.as_ptr(), Ordering::Relaxed);
    LOG_ERR.store(err.as_ptr(), Ordering::Relaxed);
}

/// Where a context's log callback prints.
#[derive(Clone, Copy)]
pub enum LogTarget {
    /// `print_to_bio_out`.
    Out,
    /// `print_to_bio_err`.
    Err,
}

unsafe extern "C" fn print_to_bio_out(
    func: *const c_char,
    file: *const c_char,
    line: c_int,
    level: c_int,
    msg: *const c_char,
) -> c_int {
    // SAFETY: the library passes valid strings; the BIO is NULL or lives to the end.
    unsafe {
        ffi::OSSL_CMP_print_to_bio(
            LOG_OUT.load(Ordering::Relaxed),
            func,
            file,
            line,
            level,
            msg,
        )
    }
}

unsafe extern "C" fn print_to_bio_err(
    func: *const c_char,
    file: *const c_char,
    line: c_int,
    level: c_int,
    msg: *const c_char,
) -> c_int {
    // SAFETY: as print_to_bio_out.
    unsafe {
        ffi::OSSL_CMP_print_to_bio(
            LOG_ERR.load(Ordering::Relaxed),
            func,
            file,
            line,
            level,
            msg,
        )
    }
}

/// `OSSL_CMP_CTX_print_errors(ctx)` (NULL for `None`).
pub fn print_errors(ctx: Option<&Ctx>) {
    // SAFETY: ctx is NULL or live.
    unsafe { ffi::OSSL_CMP_CTX_print_errors(ctx.map_or(ptr::null(), |c| c.as_ptr().cast_const())) };
}

/// `OSSL_CMP_log_close()`.
pub fn log_close() {
    // SAFETY: no arguments.
    unsafe { ffi::OSSL_CMP_log_close() };
}

/// The verify callback `X509_STORE_CTX_print_verify_cb`.
unsafe extern "C" fn print_verify_cb(ok: c_int, ctx: *mut X509_STORE_CTX) -> c_int {
    // SAFETY: the library passes a live store context.
    unsafe { ffi::X509_STORE_CTX_print_verify_cb(ok, ctx) }
}

impl Store {
    /// `X509_STORE_set_verify_cb(store, X509_STORE_CTX_print_verify_cb)`.
    pub fn set_print_verify_cb(&self) {
        // SAFETY: the store is live; the callback is a static function.
        unsafe { ffi::X509_STORE_set_verify_cb(self.as_ptr(), Some(print_verify_cb)) };
    }

    /// `X509_VERIFY_PARAM_clear_flags(X509_STORE_get0_param(store), flags)`.
    pub fn clear_param_flags(&self, flags: core::ffi::c_ulong) {
        // SAFETY: the store is live; the param stays owned by it.
        let vpm = unsafe { ffi::X509_STORE_get0_param(self.as_ptr()) };
        // SAFETY: vpm is live.
        unsafe { ffi::X509_VERIFY_PARAM_clear_flags(vpm, flags) };
    }

    /// `X509_STORE_add_cert(store, cert)`.
    pub fn add_cert(&self, cert: &Cert) -> bool {
        // SAFETY: both are live; the store takes its own reference.
        unsafe { ffi::X509_STORE_add_cert(self.as_ptr(), cert.as_ptr()) == 1 }
    }
}

// ---------------------------------------------------------------------------------------------
// The client context

/// An owned `OSSL_CMP_CTX`, with what its callbacks' arguments point to: the mock server
/// (the transfer callback's argument), the TLS info and its `SSL_CTX` (the HTTP callback's),
/// and the trust store for `OSSL_CMP_certConf_cb` (the certConf callback's).
pub struct CmpCtx {
    ctx: ptr::NonNull<OSSL_CMP_CTX>,
    srv: Option<SrvCtx>,
    tls: Option<(Box<TlsInfo>, Option<SslCtx>)>,
    out_trusted: Option<Store>,
}

thread_local! {
    /// The transfer callbacks, by context.
    static TRANSFER: RefCell<HashMap<usize, TransferFn>> = RefCell::new(HashMap::new());
}

/// A transfer callback: the response to a request (`None`: error).
pub type TransferFn = Box<dyn FnMut(&Ctx, &MsgRef) -> Option<Msg>>;

unsafe extern "C" fn transfer_cb(
    ctx: *mut OSSL_CMP_CTX,
    req: *const OSSL_CMP_MSG,
) -> *mut OSSL_CMP_MSG {
    let (Some(c), Some(r)) = (Ctx::from_raw(ctx), MsgRef::from_raw(req)) else {
        return ptr::null_mut();
    };
    let key = ctx as usize;
    // Taken out while it runs, so the callback may use the context freely.
    let Some(mut f) = TRANSFER.with(|t| t.borrow_mut().remove(&key)) else {
        return ptr::null_mut();
    };
    let res = f(c, r);
    TRANSFER.with(|t| t.borrow_mut().insert(key, f));
    res.map_or(ptr::null_mut(), Msg::into_ptr)
}

impl CmpCtx {
    /// `OSSL_CMP_CTX_new(libctx, propq)`.
    pub fn new(libctx: Option<&LibCtx>, propq: Option<&str>) -> Option<Self> {
        let pq = propq.and_then(cstring);
        // SAFETY: libctx is NULL or live; pq is NULL or a valid C string.
        let p = unsafe {
            ffi::OSSL_CMP_CTX_new(
                libctx_ptr(libctx),
                pq.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            )
        };
        Some(Self {
            ctx: ptr::NonNull::new(p)?,
            srv: None,
            tls: None,
            out_trusted: None,
        })
    }

    /// `OSSL_CMP_CTX_set_transfer_cb(ctx, cb)` with `f` as the callback.
    pub fn set_transfer_cb(&self, f: TransferFn) -> bool {
        TRANSFER.with(|t| t.borrow_mut().insert(self.as_ptr() as usize, f));
        // SAFETY: the context is live; the callback is a static function.
        unsafe { ffi::OSSL_CMP_CTX_set_transfer_cb(self.as_ptr(), Some(transfer_cb)) == 1 }
    }

    /// `OSSL_CMP_CTX_set_transfer_cb_arg(ctx, srv_ctx)`: `OSSL_CMP_CTX_server_perform` sends
    /// the requests to it. The context keeps it.
    pub fn set_mock_server(&mut self, srv: SrvCtx) {
        // SAFETY: both are live; srv is kept in self until after the context is freed.
        unsafe { ffi::OSSL_CMP_CTX_set_transfer_cb_arg(self.as_ptr(), srv.as_ptr().cast()) };
        self.srv = Some(srv);
    }

    /// The mock server set with [`Self::set_mock_server`].
    pub fn mock_server(&self) -> Option<&SrvCtx> {
        self.srv.as_ref()
    }

    /// `OSSL_CMP_CTX_set_certConf_cb_arg(ctx, store)`: the trust store
    /// `OSSL_CMP_certConf_cb` checks newly enrolled certificates with. The context keeps it.
    pub fn set_certconf_trusted(&mut self, store: Store) -> bool {
        // SAFETY: both are live; the store is kept in self until after the context is freed.
        let ok =
            unsafe { ffi::OSSL_CMP_CTX_set_certConf_cb_arg(self.as_ptr(), store.as_ptr().cast()) }
                == 1;
        if ok {
            self.out_trusted = Some(store);
        }
        ok
    }

    /// `OSSL_CMP_CTX_set_http_cb_arg(ctx, info)` and `OSSL_CMP_CTX_set_http_cb(ctx,
    /// app_http_tls_cb)`; the context keeps the info and its `SSL_CTX`. `ssl_ctx` `None` sets
    /// only the argument (the callback is set once the `SSL_CTX` is made, see
    /// [`Self::set_tls_ssl_ctx`]).
    pub fn set_tls_info(&mut self, info: Box<TlsInfo>) {
        // SAFETY: both are live; the info is kept in self until after the context is freed.
        unsafe { ffi::OSSL_CMP_CTX_set_http_cb_arg(self.as_ptr(), info.as_arg()) };
        self.tls = Some((info, None));
    }

    /// Keeps the `SSL_CTX` the TLS info points to, and sets the HTTP callback.
    pub fn set_tls_ssl_ctx(&mut self, ssl_ctx: SslCtx) -> bool {
        if let Some((_, s)) = &mut self.tls {
            *s = Some(ssl_ctx);
        }
        // SAFETY: the context is live; the callback is a static function.
        unsafe {
            ffi::OSSL_CMP_CTX_set_http_cb(self.as_ptr(), Some(crate::http::app_http_tls_cb)) == 1
        }
    }
}

impl core::ops::Deref for CmpCtx {
    type Target = Ctx;
    fn deref(&self) -> &Ctx {
        // SAFETY: the context is owned by self, so it lives as long as the borrow.
        unsafe { &*self.ctx.as_ptr().cast::<Ctx>() }
    }
}

impl Drop for CmpCtx {
    fn drop(&mut self) {
        TRANSFER.with(|t| t.borrow_mut().remove(&(self.as_ptr() as usize)));
        // SAFETY: the context is owned by self and freed once, here, before what its
        // callbacks' arguments point to (the fields, dropped after this).
        unsafe { ffi::OSSL_CMP_CTX_free(self.ctx.as_ptr()) };
    }
}

/// `OSSL_CMP_CTX_set1_*` taking a name.
#[derive(Clone, Copy)]
pub enum NameField {
    Issuer,
    Subject,
    Recipient,
    ExpectedSender,
}

impl Ctx {
    /// `OSSL_CMP_CTX_set_log_verbosity(ctx, level)`.
    pub fn set_log_verbosity(&self, level: c_int) -> bool {
        // SAFETY: the context is live.
        unsafe {
            ffi::OSSL_CMP_CTX_set_option(
                self.as_ptr(),
                crate::abi::OSSL_CMP_OPT_LOG_VERBOSITY as c_int,
                level,
            ) == 1
        }
    }

    /// `OSSL_CMP_CTX_set_log_cb(ctx, print_to_bio_out or print_to_bio_err)`.
    pub fn set_log_cb(&self, target: LogTarget) -> bool {
        let cb = match target {
            LogTarget::Out => print_to_bio_out as unsafe extern "C" fn(_, _, _, _, _) -> _,
            LogTarget::Err => print_to_bio_err,
        };
        // SAFETY: the context is live; the callback is a static function.
        unsafe { ffi::OSSL_CMP_CTX_set_log_cb(self.as_ptr(), Some(cb)) == 1 }
    }

    /// `OSSL_CMP_CTX_print_errors(ctx)`.
    pub fn print_errors(&self) {
        print_errors(Some(self));
    }

    /// `OSSL_CMP_CTX_set_option(ctx, opt, val)`.
    pub fn set_option(&self, opt: c_int, val: c_int) -> bool {
        // SAFETY: the context is live.
        unsafe { ffi::OSSL_CMP_CTX_set_option(self.as_ptr(), opt, val) == 1 }
    }

    /// `OSSL_CMP_CTX_get_option(ctx, opt)`.
    pub fn get_option(&self, opt: c_int) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::OSSL_CMP_CTX_get_option(self.as_ptr(), opt) }
    }

    /// `OSSL_CMP_CTX_set1_referenceValue(ctx, ref, len)`.
    pub fn set1_reference_value(&self, value: &[u8]) -> bool {
        let Ok(len) = c_int::try_from(value.len()) else {
            return false;
        };
        // SAFETY: the context is live; value holds len bytes.
        unsafe { ffi::OSSL_CMP_CTX_set1_referenceValue(self.as_ptr(), value.as_ptr(), len) == 1 }
    }

    /// `OSSL_CMP_CTX_set1_secretValue(ctx, sec, len)`.
    pub fn set1_secret_value(&self, value: &[u8]) -> bool {
        let Ok(len) = c_int::try_from(value.len()) else {
            return false;
        };
        // SAFETY: the context is live; value holds len bytes.
        unsafe { ffi::OSSL_CMP_CTX_set1_secretValue(self.as_ptr(), value.as_ptr(), len) == 1 }
    }

    /// `OSSL_CMP_CTX_set1_cert(ctx, cert)`.
    pub fn set1_cert(&self, cert: &Cert) -> bool {
        // SAFETY: both are live; the context takes its own reference.
        unsafe { ffi::OSSL_CMP_CTX_set1_cert(self.as_ptr(), cert.as_ptr()) == 1 }
    }

    /// `OSSL_CMP_CTX_set1_srvCert(ctx, cert)`.
    pub fn set1_srv_cert(&self, cert: &Cert) -> bool {
        // SAFETY: both are live; the context takes its own reference.
        unsafe { ffi::OSSL_CMP_CTX_set1_srvCert(self.as_ptr(), cert.as_ptr()) == 1 }
    }

    /// `OSSL_CMP_CTX_set1_oldCert(ctx, cert)`.
    pub fn set1_old_cert(&self, cert: &Cert) -> bool {
        // SAFETY: both are live; the context takes its own reference.
        unsafe { ffi::OSSL_CMP_CTX_set1_oldCert(self.as_ptr(), cert.as_ptr()) == 1 }
    }

    /// `OSSL_CMP_CTX_set1_pkey(ctx, pkey)`.
    pub fn set1_pkey(&self, pkey: &Pkey) -> bool {
        // SAFETY: both are live; the context takes its own reference.
        unsafe { ffi::OSSL_CMP_CTX_set1_pkey(self.as_ptr(), pkey.as_ptr()) == 1 }
    }

    /// `OSSL_CMP_CTX_build_cert_chain(ctx, own_trusted, candidates)`.
    pub fn build_cert_chain(
        &self,
        own_trusted: Option<&Store>,
        candidates: Option<&CertStack>,
    ) -> bool {
        // SAFETY: the context is live; the others are NULL or live.
        unsafe {
            ffi::OSSL_CMP_CTX_build_cert_chain(
                self.as_ptr(),
                own_trusted.map_or(ptr::null_mut(), Store::as_ptr),
                candidates.map_or(ptr::null_mut(), CertStack::as_ptr),
            ) == 1
        }
    }

    /// `OSSL_CMP_CTX_set1_extraCertsOut(ctx, certs)`.
    pub fn set1_extra_certs_out(&self, certs: &CertStack) -> bool {
        // SAFETY: both are live; the context copies the stack.
        unsafe { ffi::OSSL_CMP_CTX_set1_extraCertsOut(self.as_ptr(), certs.as_ptr()) == 1 }
    }

    /// `OSSL_CMP_CTX_set1_untrusted(ctx, certs)`.
    pub fn set1_untrusted(&self, certs: &CertStack) -> bool {
        // SAFETY: both are live; the context copies the stack.
        unsafe { ffi::OSSL_CMP_CTX_set1_untrusted(self.as_ptr(), certs.as_ptr()) == 1 }
    }

    /// `OSSL_CMP_CTX_get0_untrusted(ctx)`, each certificate as a new reference.
    pub fn untrusted(&self) -> Vec<Cert> {
        // SAFETY: the context is live; the stack stays owned by it.
        crate::x509::certs_of(unsafe { ffi::OSSL_CMP_CTX_get0_untrusted(self.as_ptr()) })
    }

    /// `OSSL_CMP_CTX_set0_trusted(ctx, store)`, which takes the store on success.
    pub fn set0_trusted(&self, store: Store) -> bool {
        // SAFETY: both are live; on success the context owns the store.
        if unsafe { ffi::OSSL_CMP_CTX_set0_trustedStore(self.as_ptr(), store.as_ptr()) } == 1 {
            let _ = store.into_ptr();
            true
        } else {
            false
        }
    }

    /// `OSSL_CMP_CTX_set1_<field>(ctx, name)`.
    pub fn set1_name(&self, field: NameField, name: &Name) -> bool {
        let (c, n) = (self.as_ptr(), name.as_ptr());
        let r = match field {
            // SAFETY: both are live; the context copies the name.
            NameField::Issuer => unsafe { ffi::OSSL_CMP_CTX_set1_issuer(c, n) },
            // SAFETY: as above.
            NameField::Subject => unsafe { ffi::OSSL_CMP_CTX_set1_subjectName(c, n) },
            // SAFETY: as above.
            NameField::Recipient => unsafe { ffi::OSSL_CMP_CTX_set1_recipient(c, n) },
            // SAFETY: as above.
            NameField::ExpectedSender => unsafe { ffi::OSSL_CMP_CTX_set1_expected_sender(c, n) },
        };
        r == 1
    }

    /// `s2i_ASN1_INTEGER(NULL, serial)` then `OSSL_CMP_CTX_set1_serialNumber`: `None` if the
    /// number doesn't parse.
    pub fn set1_serial_number(&self, serial: &str) -> Option<bool> {
        let s = cstring(serial)?;
        // SAFETY: s is a valid C string; the result is owned here.
        let sno = unsafe { ffi::s2i_ASN1_INTEGER(ptr::null_mut(), s.as_ptr()) };
        if sno.is_null() {
            return None;
        }
        // SAFETY: both are live; the context copies the number.
        let ok = unsafe { ffi::OSSL_CMP_CTX_set1_serialNumber(self.as_ptr(), sno) } == 1;
        // SAFETY: sno is owned here.
        unsafe { ffi::ASN1_INTEGER_free(sno) };
        Some(ok)
    }

    /// `OSSL_CMP_CTX_set0_newPkey(ctx, priv, pkey)`, which takes the key on success.
    pub fn set0_new_pkey(&self, private: bool, pkey: Pkey) -> bool {
        // SAFETY: both are live; on success the context owns the key.
        if unsafe {
            ffi::OSSL_CMP_CTX_set0_newPkey(self.as_ptr(), c_int::from(private), pkey.as_ptr())
        } == 1
        {
            let _ = pkey.into_ptr();
            true
        } else {
            false
        }
    }

    /// `OSSL_CMP_CTX_get0_newPkey(ctx, priv)`, as a new reference.
    pub fn new_pkey(&self, private: bool) -> Option<Pkey> {
        // SAFETY: the context is live; the key stays owned by it.
        let p = unsafe { ffi::OSSL_CMP_CTX_get0_newPkey(self.as_ptr(), c_int::from(private)) };
        pkey_ref(p)
    }

    /// `OSSL_CMP_CTX_set1_p10CSR(ctx, csr)`.
    pub fn set1_p10_csr(&self, csr: &Req) -> bool {
        // SAFETY: both are live; the context copies the request.
        unsafe { ffi::OSSL_CMP_CTX_set1_p10CSR(self.as_ptr(), csr.as_ptr()) == 1 }
    }

    /// `OSSL_CMP_CTX_set0_reqExtensions(ctx, exts)`.
    pub fn set0_req_extensions(&self, exts: ExtStack) -> bool {
        // SAFETY: both are live; on success the context owns the stack.
        if unsafe { ffi::OSSL_CMP_CTX_set0_reqExtensions(self.as_ptr(), exts.0.as_ptr()) } == 1 {
            core::mem::forget(exts);
            true
        } else {
            false
        }
    }

    /// `OSSL_CMP_CTX_reqExtensions_have_SAN(ctx)`.
    pub fn req_extensions_have_san(&self) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::OSSL_CMP_CTX_reqExtensions_have_SAN(self.as_ptr()) }
    }

    /// `OSSL_CMP_CTX_push1_subjectAltName(ctx, name)`.
    pub fn push1_subject_alt_name(&self, name: &GeneralName) -> bool {
        // SAFETY: both are live; the context copies the name.
        unsafe { ffi::OSSL_CMP_CTX_push1_subjectAltName(self.as_ptr(), name.as_ptr()) != 0 }
    }

    /// A `POLICYINFO` for `policy` pushed with `OSSL_CMP_CTX_push0_policy`.
    pub fn push0_policy(&self, policy: Object) -> bool {
        // SAFETY: no arguments.
        let pinfo = unsafe { ffi::POLICYINFO_new() };
        if pinfo.is_null() {
            return false;
        }
        // SAFETY: pinfo is a live POLICYINFO (a public struct); it takes the object.
        unsafe { (*pinfo).policyid = policy.into_ptr() };
        // SAFETY: both are live; on success the context owns pinfo.
        if unsafe { ffi::OSSL_CMP_CTX_push0_policy(self.as_ptr(), pinfo) } != 0 {
            true
        } else {
            // SAFETY: pinfo is still owned here.
            unsafe { ffi::POLICYINFO_free(pinfo) };
            false
        }
    }

    /// `OSSL_CMP_CTX_push0_geninfo_ITAV(ctx, itav)`.
    pub fn push0_geninfo_itav(&self, itav: Itav) -> bool {
        // SAFETY: both are live; on success the context owns the ITAV.
        if unsafe { ffi::OSSL_CMP_CTX_push0_geninfo_ITAV(self.as_ptr(), itav.as_ptr()) } != 0 {
            let _ = itav.into_ptr();
            true
        } else {
            false
        }
    }

    /// `OSSL_CMP_CTX_push0_genm_ITAV(ctx, itav)`.
    pub fn push0_genm_itav(&self, itav: Itav) -> bool {
        // SAFETY: both are live; on success the context owns the ITAV.
        if unsafe { ffi::OSSL_CMP_CTX_push0_genm_ITAV(self.as_ptr(), itav.as_ptr()) } != 0 {
            let _ = itav.into_ptr();
            true
        } else {
            false
        }
    }

    /// `OSSL_CMP_CTX_set1_server(ctx, host)`.
    pub fn set1_server(&self, host: &str) -> bool {
        let Some(h) = cstring(host) else {
            return false;
        };
        // SAFETY: the context is live; h is a valid C string.
        unsafe { ffi::OSSL_CMP_CTX_set1_server(self.as_ptr(), h.as_ptr()) == 1 }
    }

    /// `OSSL_CMP_CTX_set_serverPort(ctx, port)`.
    pub fn set_server_port(&self, port: c_int) -> bool {
        // SAFETY: the context is live.
        unsafe { ffi::OSSL_CMP_CTX_set_serverPort(self.as_ptr(), port) == 1 }
    }

    /// `OSSL_CMP_CTX_set1_proxy(ctx, name)`.
    pub fn set1_proxy(&self, name: &str) -> bool {
        let Some(n) = cstring(name) else {
            return false;
        };
        // SAFETY: the context is live; n is a valid C string.
        unsafe { ffi::OSSL_CMP_CTX_set1_proxy(self.as_ptr(), n.as_ptr()) == 1 }
    }

    /// `OSSL_CMP_CTX_set1_no_proxy(ctx, names)`.
    pub fn set1_no_proxy(&self, names: &str) -> bool {
        let Some(n) = cstring(names) else {
            return false;
        };
        // SAFETY: the context is live; n is a valid C string.
        unsafe { ffi::OSSL_CMP_CTX_set1_no_proxy(self.as_ptr(), n.as_ptr()) == 1 }
    }

    /// `OSSL_CMP_CTX_set1_serverPath(ctx, path)` (NULL for `None`).
    pub fn set1_server_path(&self, path: Option<&str>) -> bool {
        let p = path.and_then(cstring);
        // SAFETY: the context is live; p is NULL or a valid C string.
        unsafe {
            ffi::OSSL_CMP_CTX_set1_serverPath(
                self.as_ptr(),
                p.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            ) == 1
        }
    }

    /// `OSSL_CMP_CTX_set1_transactionID(ctx, id)` (NULL for `None`).
    pub fn set1_transaction_id(&self, id: Option<&[u8]>) -> bool {
        let Ok(s) = octet_string(id) else {
            return false;
        };
        // SAFETY: the context is live; s is NULL or live (the context copies it).
        let ok = unsafe { ffi::OSSL_CMP_CTX_set1_transactionID(self.as_ptr(), s) } == 1;
        // SAFETY: s is NULL or owned here.
        unsafe { ffi::ASN1_OCTET_STRING_free(s) };
        ok
    }

    /// `OSSL_CMP_CTX_set1_senderNonce(ctx, nonce)` (NULL for `None`).
    pub fn set1_sender_nonce(&self, nonce: Option<&[u8]>) -> bool {
        let Ok(s) = octet_string(nonce) else {
            return false;
        };
        // SAFETY: the context is live; s is NULL or live (the context copies it).
        let ok = unsafe { ffi::OSSL_CMP_CTX_set1_senderNonce(self.as_ptr(), s) } == 1;
        // SAFETY: s is NULL or owned here.
        unsafe { ffi::ASN1_OCTET_STRING_free(s) };
        ok
    }

    /// `OSSL_CMP_CTX_get_status(ctx)`.
    pub fn status(&self) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::OSSL_CMP_CTX_get_status(self.as_ptr()) }
    }

    /// `OSSL_CMP_CTX_snprint_PKIStatus(ctx, buf, OSSL_CMP_PKISI_BUFLEN)`.
    pub fn snprint_pki_status(&self) -> Option<String> {
        let mut buf = vec![0 as c_char; crate::abi::OSSL_CMP_PKISI_BUFLEN as usize];
        // SAFETY: the context is live; buf holds its length.
        let p = unsafe {
            ffi::OSSL_CMP_CTX_snprint_PKIStatus(self.as_ptr(), buf.as_mut_ptr(), buf.len())
        };
        string_at(p)
    }

    /// `OSSL_CMP_CTX_get0_validatedSrvCert(ctx)`, as a new reference.
    pub fn validated_srv_cert(&self) -> Option<Cert> {
        // SAFETY: the context is live; the certificate stays owned by it.
        Cert::from_borrowed(unsafe { ffi::OSSL_CMP_CTX_get0_validatedSrvCert(self.as_ptr()) })
    }

    /// `OSSL_CMP_CTX_get1_extraCertsIn(ctx)`.
    pub fn extra_certs_in(&self) -> Option<CertStack> {
        // SAFETY: the context is live; the stack is the caller's.
        CertStack::from_raw(unsafe { ffi::OSSL_CMP_CTX_get1_extraCertsIn(self.as_ptr()) })
    }

    /// `OSSL_CMP_CTX_get1_newChain(ctx)`.
    pub fn new_chain(&self) -> Option<CertStack> {
        // SAFETY: the context is live; the stack is the caller's.
        CertStack::from_raw(unsafe { ffi::OSSL_CMP_CTX_get1_newChain(self.as_ptr()) })
    }

    /// `OSSL_CMP_CTX_get1_caPubs(ctx)`.
    pub fn ca_pubs(&self) -> Option<CertStack> {
        // SAFETY: the context is live; the stack is the caller's.
        CertStack::from_raw(unsafe { ffi::OSSL_CMP_CTX_get1_caPubs(self.as_ptr()) })
    }

    /// `OSSL_CMP_CTX_reinit(ctx)`.
    pub fn reinit(&self) -> bool {
        // SAFETY: the context is live.
        unsafe { ffi::OSSL_CMP_CTX_reinit(self.as_ptr()) == 1 }
    }

    /// `OSSL_CMP_CTX_server_perform(ctx, req)`: the response of the mock server set as the
    /// transfer callback's argument.
    pub fn server_perform(&self, req: &MsgRef) -> Option<Msg> {
        // SAFETY: both are live; the response is the caller's.
        Msg::from_ptr(unsafe { ffi::OSSL_CMP_CTX_server_perform(self.as_ptr(), req.as_ptr()) })
    }

    /// `OSSL_CMP_MSG_http_perform(ctx, req)`.
    pub fn http_perform(&self, req: &MsgRef) -> Option<Msg> {
        // SAFETY: both are live; the response is the caller's.
        Msg::from_ptr(unsafe { ffi::OSSL_CMP_MSG_http_perform(self.as_ptr(), req.as_ptr()) })
    }

    /// `OSSL_CMP_exec_IR_ses`, `_CR_`, `_KUR_`, or `_P10CR_` (`OSSL_CMP_exec_certreq` with
    /// the body type): the new certificate.
    pub fn exec_certreq(&self, body_type: c_int) -> Option<Cert> {
        let t = body_type;
        // SAFETY: the context is live; the certificate stays owned by it (a new reference
        // is taken for the caller).
        Cert::from_borrowed(unsafe { ffi::OSSL_CMP_exec_certreq(self.as_ptr(), t, ptr::null()) })
    }

    /// `OSSL_CMP_exec_RR_ses(ctx)`.
    pub fn exec_rr(&self) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::OSSL_CMP_exec_RR_ses(self.as_ptr()) }
    }

    /// `OSSL_CMP_exec_GENM_ses(ctx)`.
    pub fn exec_genm(&self) -> Option<ItavStack> {
        // SAFETY: the context is live; the stack is the caller's.
        ItavStack::from_ptr(unsafe { ffi::OSSL_CMP_exec_GENM_ses(self.as_ptr()) })
    }

    /// `OSSL_CMP_get1_caCerts(ctx, &certs)`: `None` on failure.
    pub fn get1_ca_certs(&self) -> Option<Option<CertStack>> {
        let mut out = ptr::null_mut();
        // SAFETY: the context is live; out receives a stack for the caller.
        let ok = unsafe { ffi::OSSL_CMP_get1_caCerts(self.as_ptr(), &mut out) } == 1;
        let certs = CertStack::from_raw(out);
        ok.then_some(certs)
    }

    /// `OSSL_CMP_get1_rootCaKeyUpdate(ctx, oldWithOld, ...)`: newWithNew, newWithOld, and
    /// oldWithNew; `None` on failure.
    pub fn get1_root_ca_key_update(&self, old_with_old: Option<&Cert>) -> Option<RootCaKeyUpdate> {
        let (mut a, mut b, mut c) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        // SAFETY: the context is live; old_with_old is NULL or live; the outputs receive new
        // references for the caller.
        let ok = unsafe {
            ffi::OSSL_CMP_get1_rootCaKeyUpdate(
                self.as_ptr(),
                cert_ptr(old_with_old),
                &mut a,
                &mut b,
                &mut c,
            )
        } == 1;
        let r = RootCaKeyUpdate {
            new_with_new: Cert::from_raw(a),
            new_with_old: Cert::from_raw(b),
            old_with_new: Cert::from_raw(c),
        };
        ok.then_some(r)
    }

    /// `OSSL_CMP_get1_crlUpdate(ctx, crlcert, oldcrl, &crl)`: `None` on failure.
    pub fn get1_crl_update(
        &self,
        crlcert: Option<&Cert>,
        oldcrl: Option<&Crl>,
    ) -> Option<Option<Crl>> {
        let mut out = ptr::null_mut();
        // SAFETY: the context is live; the others are NULL or live; out receives a CRL for
        // the caller.
        let ok = unsafe {
            ffi::OSSL_CMP_get1_crlUpdate(
                self.as_ptr(),
                cert_ptr(crlcert),
                oldcrl.map_or(ptr::null(), |c| c.as_ptr().cast_const()),
                &mut out,
            )
        } == 1;
        let crl = Crl::from_raw(out);
        ok.then_some(crl)
    }

    /// `OSSL_CMP_get1_certReqTemplate(ctx, &template, &keySpec)`: `None` on failure.
    pub fn get1_cert_req_template(&self) -> Option<(Option<CertTemplate>, Option<Atavs>)> {
        let (mut t, mut k) = (ptr::null_mut(), ptr::null_mut());
        // SAFETY: the context is live; the outputs receive objects for the caller.
        let ok = unsafe { ffi::OSSL_CMP_get1_certReqTemplate(self.as_ptr(), &mut t, &mut k) } == 1;
        let r = (CertTemplate::from_ptr(t), Atavs::from_ptr(k));
        ok.then_some(r)
    }
}

/// The certificates of a root CA key update.
pub struct RootCaKeyUpdate {
    pub new_with_new: Option<Cert>,
    pub new_with_old: Option<Cert>,
    pub old_with_new: Option<Cert>,
}

fn pkey_ref(p: *mut EVP_PKEY) -> Option<Pkey> {
    if p.is_null() {
        return None;
    }
    // SAFETY: p is a live key; the new reference is owned by the result.
    if unsafe { ffi::EVP_PKEY_up_ref(p) } != 1 {
        return None;
    }
    Pkey::from_raw(p)
}

impl Crl {
    /// A new reference to the same CRL (`X509_CRL_up_ref`).
    pub fn clone_ref(&self) -> Option<Crl> {
        Crl::from_borrowed(self.as_ptr())
    }
}

impl Pkey {
    /// A new reference to the same key (`EVP_PKEY_up_ref`).
    pub fn clone_ref(&self) -> Option<Pkey> {
        pkey_ref(self.as_ptr())
    }

    /// `EVP_PKEY_dup(pkey)`.
    pub fn dup(&self) -> Option<Pkey> {
        // SAFETY: the key is live; the copy is the caller's.
        Pkey::from_raw(unsafe { ffi::EVP_PKEY_dup(self.as_ptr()) })
    }
}

// ---------------------------------------------------------------------------------------------
// Messages

impl Msg {
    /// `OSSL_CMP_MSG_read(file, libctx, propq)`.
    pub fn read(file: &str, libctx: Option<&LibCtx>, propq: Option<&str>) -> Option<Self> {
        let f = cstring(file)?;
        let pq = propq.and_then(cstring);
        // SAFETY: f is a valid C string; libctx and pq are NULL or valid.
        Self::from_ptr(unsafe {
            ffi::OSSL_CMP_MSG_read(
                f.as_ptr(),
                libctx_ptr(libctx),
                pq.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            )
        })
    }

    /// `OSSL_CMP_MSG_update_transactionID(ctx, msg)`.
    pub fn update_transaction_id(&self, ctx: &Ctx) -> bool {
        // SAFETY: both are live; the message is owned by self.
        unsafe { ffi::OSSL_CMP_MSG_update_transactionID(ctx.as_ptr(), self.as_ptr()) == 1 }
    }

    /// `OSSL_CMP_MSG_update_recipNonce(ctx, msg)`.
    pub fn update_recip_nonce(&self, ctx: &Ctx) -> bool {
        // SAFETY: both are live; the message is owned by self.
        unsafe { ffi::OSSL_CMP_MSG_update_recipNonce(ctx.as_ptr(), self.as_ptr()) == 1 }
    }
}

impl Msg {
    /// `ASN1_item_d2i_bio(ASN1_ITEM_rptr(OSSL_CMP_MSG), bio, NULL)`.
    pub fn read_der(bio: &Bio) -> Option<Self> {
        Self::from_ptr(crate::ocsp::Item::CmpMsg.d2i_bio(bio.as_ptr()).cast())
    }
}

impl MsgRef {
    /// `ASN1_item_i2d(msg, NULL, ASN1_ITEM_rptr(OSSL_CMP_MSG))`: the encoding's length.
    pub fn der_len(&self) -> c_int {
        crate::ocsp::Item::CmpMsg.i2d_len(self.as_ptr().cast_const().cast())
    }

    /// `ASN1_item_i2d_bio(ASN1_ITEM_rptr(OSSL_CMP_MSG), out, msg)`.
    pub fn write_der(&self, out: &Bio) -> c_int {
        crate::ocsp::Item::CmpMsg.i2d_bio(out, self.as_ptr().cast_const().cast())
    }

    /// `OSSL_CMP_MSG_write(file, msg)`.
    pub fn write(&self, file: &str) -> c_int {
        let Some(f) = cstring(file) else {
            return -1;
        };
        // SAFETY: f is a valid C string; the message is live.
        unsafe { ffi::OSSL_CMP_MSG_write(f.as_ptr(), self.as_ptr()) }
    }

    /// `OSSL_CMP_MSG_get_bodytype(msg)`.
    pub fn body_type(&self) -> c_int {
        // SAFETY: the message is live.
        unsafe { ffi::OSSL_CMP_MSG_get_bodytype(self.as_ptr()) }
    }

    /// `OSSL_CMP_MSG_dup(msg)`.
    pub fn dup(&self) -> Option<Msg> {
        // SAFETY: the message is live; the copy is the caller's.
        Msg::from_ptr(unsafe { ffi::OSSL_CMP_MSG_dup(self.as_ptr()) })
    }

    /// `EVP_PKEY_dup(X509_PUBKEY_get0(OSSL_CMP_MSG_get0_certreq_publickey(msg)))`: `None`
    /// if the message has no public key, `Some(None)` if the copy failed.
    pub fn certreq_public_key(&self) -> Option<Option<Pkey>> {
        // SAFETY: the message is live; the key stays owned by it.
        let pk = unsafe { ffi::OSSL_CMP_MSG_get0_certreq_publickey(self.as_ptr()) };
        if pk.is_null() {
            return None;
        }
        // SAFETY: pk is live.
        let p = unsafe { ffi::X509_PUBKEY_get0(pk) };
        if p.is_null() {
            return None;
        }
        // SAFETY: p is live; the copy is the caller's.
        Some(Pkey::from_raw(unsafe { ffi::EVP_PKEY_dup(p) }))
    }

    fn header(&self) -> *mut crate::abi::OSSL_CMP_PKIHEADER {
        // SAFETY: the message is live; the header is owned by it.
        unsafe { ffi::OSSL_CMP_MSG_get0_header(self.as_ptr()) }
    }

    /// The header's recipNonce.
    pub fn recip_nonce(&self) -> Option<Vec<u8>> {
        // SAFETY: the header is live (owned by the message).
        string_bytes(unsafe { ffi::OSSL_CMP_HDR_get0_recipNonce(self.header()) }.cast())
    }

    /// The header's transactionID.
    pub fn transaction_id(&self) -> Option<Vec<u8>> {
        // SAFETY: the header is live (owned by the message).
        string_bytes(unsafe { ffi::OSSL_CMP_HDR_get0_transactionID(self.header()) }.cast())
    }

    /// The header's generalInfo ITAVs.
    pub fn geninfo_itavs(&self) -> Vec<&ItavRef> {
        // SAFETY: the header is live (owned by the message).
        let sk = unsafe { ffi::OSSL_CMP_HDR_get0_geninfo_ITAVs(self.header()) };
        members::<OSSL_CMP_ITAV>(sk.cast())
            .into_iter()
            .filter_map(|p| ItavRef::from_raw(p))
            .collect()
    }
}

/// A stack of `OSSL_CMP_ITAV`, owned.
pub struct ItavStack(ptr::NonNull<stack_st_OSSL_CMP_ITAV>);

unsafe extern "C" fn free_itav(p: *mut c_void) {
    // SAFETY: the stack's members are ITAVs.
    unsafe { ffi::OSSL_CMP_ITAV_free(p.cast()) };
}

impl ItavStack {
    pub(crate) fn from_ptr(p: *mut stack_st_OSSL_CMP_ITAV) -> Option<Self> {
        ptr::NonNull::new(p).map(Self)
    }

    /// An empty stack.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::OPENSSL_sk_new_null() }.cast())
    }

    /// `sk_OSSL_CMP_ITAV_push`, which takes the ITAV.
    pub fn push(&self, itav: Itav) -> bool {
        // SAFETY: both are live; on success the stack owns the ITAV.
        if unsafe { ffi::OPENSSL_sk_push(self.0.as_ptr().cast(), itav.as_ptr().cast()) } > 0 {
            let _ = itav.into_ptr();
            true
        } else {
            false
        }
    }

    /// The ITAVs (NULL members as `None`).
    pub fn items(&self) -> Vec<Option<&ItavRef>> {
        members::<OSSL_CMP_ITAV>(self.0.as_ptr().cast())
            .into_iter()
            .map(|p| ItavRef::from_raw(p))
            .collect()
    }

    fn into_ptr(self) -> *mut stack_st_OSSL_CMP_ITAV {
        let p = self.0.as_ptr();
        core::mem::forget(self);
        p
    }
}

impl Drop for ItavStack {
    fn drop(&mut self) {
        // SAFETY: the stack and its members are owned by self.
        unsafe { ffi::OPENSSL_sk_pop_free(self.0.as_ptr().cast(), Some(free_itav)) };
    }
}

/// A stack of `X509_EXTENSION`, owned.
pub struct ExtStack(ptr::NonNull<stack_st_X509_EXTENSION>);

unsafe extern "C" fn free_ext(p: *mut c_void) {
    // SAFETY: the stack's members are extensions.
    unsafe { ffi::X509_EXTENSION_free(p.cast::<X509_EXTENSION>()) };
}

impl ExtStack {
    /// An empty stack.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        ptr::NonNull::new(unsafe { ffi::OPENSSL_sk_new_null() }.cast()).map(Self)
    }

    /// `X509V3_EXT_add_nconf_sk(conf, ctx, section, &sk)`.
    pub fn add_nconf(&mut self, conf: Option<&Conf>, ctx: &mut V3Ctx<'_>, section: &str) -> bool {
        let Some(s) = cstring(section) else {
            return false;
        };
        let mut sk = self.0.as_ptr();
        // SAFETY: conf is NULL or live, the others live; the function adds to the stack in place (it is non-NULL, so
        // the pointer stays the same).
        let ok = unsafe {
            ffi::X509V3_EXT_add_nconf_sk(
                conf.map_or(ptr::null_mut(), Conf::as_ptr),
                ctx.as_ptr(),
                s.as_ptr(),
                &mut sk,
            )
        } == 1;
        if let Some(p) = ptr::NonNull::new(sk) {
            self.0 = p;
        }
        ok
    }
}

impl Drop for ExtStack {
    fn drop(&mut self) {
        // SAFETY: the stack and its members are owned by self.
        unsafe { ffi::OPENSSL_sk_pop_free(self.0.as_ptr().cast(), Some(free_ext)) };
    }
}

impl GeneralName {
    /// `a2i_GENERAL_NAME(NULL, NULL, NULL, gen_type, value, 0)`.
    pub fn from_text(gen_type: c_int, value: &str) -> Option<Self> {
        let v = cstring(value)?;
        let t = gen_type;
        // SAFETY: v is a valid C string; the NULL method and context are allowed; the name
        // is the caller's.
        Self::from_ptr(unsafe {
            ffi::a2i_GENERAL_NAME(
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                t,
                v.as_ptr(),
                0,
            )
        })
    }
}

// ---------------------------------------------------------------------------------------------
// ITAVs, ATAVs, status, templates

/// A CRL status's issuer: its first general name.
pub enum CrlIssuer<'a> {
    /// No issuer.
    Absent,
    /// A directory name.
    DirName(NameRef<'a>),
    /// No first name, or one of another type.
    Other,
}

impl ItavRef {
    /// `OBJ_obj2nid(OSSL_CMP_ITAV_get0_type(itav))`.
    pub fn type_nid(&self) -> c_int {
        // SAFETY: the ITAV is live; the object stays owned by it.
        let t = unsafe { ffi::OSSL_CMP_ITAV_get0_type(self.as_ptr()) };
        // SAFETY: t is NULL or live.
        unsafe { ffi::OBJ_obj2nid(t) }
    }

    /// `i2t_ASN1_OBJECT(buf, size, OSSL_CMP_ITAV_get0_type(itav))`: `None` if it fails.
    pub fn type_text(&self, size: usize) -> Option<String> {
        // SAFETY: the ITAV is live; the object stays owned by it.
        let t = unsafe { ffi::OSSL_CMP_ITAV_get0_type(self.as_ptr()) };
        let mut buf = vec![0 as c_char; size];
        let len = c_int::try_from(size).ok()?;
        // SAFETY: buf holds len bytes; t is NULL or live.
        if unsafe { ffi::i2t_ASN1_OBJECT(buf.as_mut_ptr(), len, t) } <= 0 {
            return None;
        }
        string_at(buf.as_ptr())
    }

    /// `OSSL_CMP_ITAV_get0_certProfile(itav, &strs)`: the profiles' bytes (NULL members as
    /// `None`); `None` on failure.
    pub fn cert_profile(&self) -> Option<Vec<Option<Vec<u8>>>> {
        let mut sk: *mut stack_st_ASN1_UTF8STRING = ptr::null_mut();
        // SAFETY: the ITAV is live; sk receives a stack it owns.
        if unsafe { ffi::OSSL_CMP_ITAV_get0_certProfile(self.as_ptr(), &mut sk) } != 1 {
            return None;
        }
        Some(
            members::<crate::abi::ASN1_STRING>(sk.cast())
                .into_iter()
                .map(|s| string_bytes(s))
                .collect(),
        )
    }

    /// `OSSL_CMP_ITAV_get0_rootCaCert(itav, &cert)` (as a new reference); `None` on failure.
    pub fn root_ca_cert(&self) -> Option<Option<Cert>> {
        let mut c = ptr::null_mut();
        // SAFETY: the ITAV is live; c receives a certificate it owns.
        if unsafe { ffi::OSSL_CMP_ITAV_get0_rootCaCert(self.as_ptr(), &mut c) } != 1 {
            return None;
        }
        Some(Cert::from_borrowed(c))
    }

    /// `OSSL_CMP_ITAV_get0_crlStatusList(itav, &list)`; `None` on failure.
    pub fn crl_status_list(&self) -> Option<Vec<Option<&CrlStatusRef>>> {
        let mut sk: *mut stack_st_OSSL_CMP_CRLSTATUS = ptr::null_mut();
        // SAFETY: the ITAV is live; sk receives a stack it owns.
        if unsafe { ffi::OSSL_CMP_ITAV_get0_crlStatusList(self.as_ptr(), &mut sk) } != 1 {
            return None;
        }
        Some(
            members::<OSSL_CMP_CRLSTATUS>(sk.cast())
                .into_iter()
                .map(|p| CrlStatusRef::from_raw(p))
                .collect(),
        )
    }
}

impl CrlStatusRef {
    /// `OSSL_CMP_CRLSTATUS_get0`: the issuer and `ASN1_TIME_compare(thisUpdate, crl's
    /// lastUpdate)` (`None`: no thisUpdate); `None` on failure.
    pub fn issuer_and_update(&self, crl: &Crl) -> Option<(CrlIssuer<'_>, Option<c_int>)> {
        let mut dpn = ptr::null_mut();
        let mut issuer: *mut crate::abi::GENERAL_NAMES = ptr::null_mut();
        let mut thisupd: *mut ASN1_TIME = ptr::null_mut();
        // SAFETY: the status is live; the outputs receive objects it owns.
        if unsafe {
            ffi::OSSL_CMP_CRLSTATUS_get0(self.as_ptr(), &mut dpn, &mut issuer, &mut thisupd)
        } != 1
        {
            return None;
        }
        let iss = if issuer.is_null() {
            CrlIssuer::Absent
        } else {
            match members::<GENERAL_NAME>(issuer.cast()).first() {
                Some(gn) if !gn.is_null() => {
                    // SAFETY: gn is a live GENERAL_NAME (a public struct).
                    let g = unsafe { &**gn };
                    if g.type_ == crate::abi::GEN_DIRNAME as c_int {
                        // SAFETY: a GEN_DIRNAME's union member is the name.
                        CrlIssuer::DirName(NameRef::from_raw(unsafe { g.d.dirn }))
                    } else {
                        CrlIssuer::Other
                    }
                }
                _ => CrlIssuer::Other,
            }
        };
        let cmp = if thisupd.is_null() {
            None
        } else {
            // SAFETY: the CRL is live; the time stays owned by it.
            let last = unsafe { ffi::X509_CRL_get0_lastUpdate(crl.as_ptr()) };
            // SAFETY: both times are live.
            Some(unsafe { ffi::ASN1_TIME_compare(thisupd, last) })
        };
        Some((iss, cmp))
    }
}

impl Itav {
    /// `OSSL_CMP_ITAV_new_caCerts(certs)`.
    pub fn new_ca_certs(certs: Option<&CertStack>) -> Option<Self> {
        // SAFETY: certs is NULL or live (the ITAV copies it).
        Self::from_ptr(unsafe {
            ffi::OSSL_CMP_ITAV_new_caCerts(certs.map_or(ptr::null(), |c| c.as_ptr().cast_const()))
        })
    }

    /// `OSSL_CMP_ITAV_new_rootCaKeyUpdate(newWithNew, newWithOld, oldWithNew)`.
    pub fn new_root_ca_key_update(
        a: Option<&Cert>,
        b: Option<&Cert>,
        c: Option<&Cert>,
    ) -> Option<Self> {
        // SAFETY: each is NULL or live (the ITAV copies them).
        Self::from_ptr(unsafe {
            ffi::OSSL_CMP_ITAV_new_rootCaKeyUpdate(cert_ptr(a), cert_ptr(b), cert_ptr(c))
        })
    }

    /// `OSSL_CMP_ITAV_new_crls(crl)`.
    pub fn new_crls(crl: Option<&Crl>) -> Option<Self> {
        // SAFETY: crl is NULL or live (the ITAV copies it).
        Self::from_ptr(unsafe {
            ffi::OSSL_CMP_ITAV_new_crls(crl.map_or(ptr::null(), |c| c.as_ptr().cast_const()))
        })
    }

    /// `OSSL_CMP_ITAV_new0_certReqTemplate(template, keyspec)`, which takes both.
    pub fn new0_cert_req_template(template: CertTemplate, keyspec: Option<Atavs>) -> Option<Self> {
        let t = template.into_ptr();
        let k = keyspec.map_or(ptr::null_mut(), Atavs::into_ptr);
        // SAFETY: t is live, k NULL or live; the ITAV owns them on success.
        let p = unsafe { ffi::OSSL_CMP_ITAV_new0_certReqTemplate(t, k) };
        if p.is_null() {
            drop(CertTemplate::from_ptr(t));
            drop(Atavs::from_ptr(k));
        }
        Self::from_ptr(p)
    }

    /// `OSSL_CMP_ITAV_dup(itav)`.
    pub fn dup(itav: &ItavRef) -> Option<Self> {
        // SAFETY: the ITAV is live; the copy is the caller's.
        Self::from_ptr(unsafe { ffi::OSSL_CMP_ITAV_dup(itav.as_ptr()) })
    }

    /// `OSSL_CMP_ITAV_create(OBJ_nid2obj(nid), NULL)`.
    pub fn from_nid(nid: c_int) -> Option<Self> {
        // SAFETY: no pointer arguments; the object is static or the caller's to free.
        let obj = unsafe { ffi::OBJ_nid2obj(nid) };
        // SAFETY: obj is NULL or live; the ITAV takes it on success.
        Self::from_ptr(unsafe { ffi::OSSL_CMP_ITAV_create(obj, ptr::null_mut()) })
    }

    /// `OSSL_CMP_ITAV_create(obj, type)` with an `ASN1_TYPE` holding an INTEGER (`Ok`) or
    /// a UTF8String (`Err`): `None` on failure.
    pub fn create(obj: Object, value: Result<c_long, &str>) -> Option<Self> {
        // SAFETY: no arguments.
        let ty = unsafe { ffi::ASN1_TYPE_new() };
        if ty.is_null() {
            return None;
        }
        let set = match value {
            Ok(n) => {
                // SAFETY: no arguments.
                let a = unsafe { ffi::ASN1_INTEGER_new() };
                // SAFETY: a is NULL or live.
                if a.is_null() || unsafe { ffi::ASN1_INTEGER_set(a, n) } != 1 {
                    // SAFETY: a is NULL or owned here.
                    unsafe { ffi::ASN1_INTEGER_free(a) };
                    false
                } else {
                    // SAFETY: ty is live; it takes a.
                    unsafe {
                        ffi::ASN1_TYPE_set(ty, crate::abi::V_ASN1_INTEGER as c_int, a.cast())
                    };
                    true
                }
            }
            Err(s) => {
                let text = cstring(s);
                // SAFETY: no arguments.
                let u = unsafe { ffi::ASN1_UTF8STRING_new() };
                let ok = match (&text, u.is_null()) {
                    (Some(t), false) => {
                        // SAFETY: u is live; t is a valid C string (-1: its length).
                        (unsafe { ffi::ASN1_STRING_set(u.cast(), t.as_ptr().cast(), -1) }) == 1
                    }
                    _ => false,
                };
                if ok {
                    // SAFETY: ty is live; it takes u.
                    unsafe {
                        ffi::ASN1_TYPE_set(ty, crate::abi::V_ASN1_UTF8STRING as c_int, u.cast())
                    };
                } else {
                    // SAFETY: u is NULL or owned here.
                    unsafe { ffi::ASN1_UTF8STRING_free(u) };
                }
                ok
            }
        };
        if !set {
            // SAFETY: ty is owned here.
            unsafe { ffi::ASN1_TYPE_free(ty) };
            return None;
        }
        let o = obj.into_ptr();
        // SAFETY: both are live; the ITAV takes them on success.
        let p = unsafe { ffi::OSSL_CMP_ITAV_create(o, ty) };
        if p.is_null() {
            // SAFETY: both are still owned here.
            unsafe { ffi::ASN1_TYPE_free(ty) };
            // SAFETY: as above.
            unsafe { ffi::ASN1_OBJECT_free(o) };
        }
        Self::from_ptr(p)
    }

    /// `OSSL_CMP_ITAV_new0_certProfile` of a one-element stack holding `name`.
    pub fn new_cert_profile(name: &str) -> Option<Self> {
        let n = cstring(name)?;
        let len = c_int::try_from(name.len()).ok()?;
        // SAFETY: no arguments.
        let sk = unsafe { ffi::OPENSSL_sk_new_null() };
        if sk.is_null() {
            return None;
        }
        // SAFETY: no arguments.
        let u = unsafe { ffi::ASN1_UTF8STRING_new() };
        // SAFETY: u is NULL or live; n holds len bytes.
        let ok =
            !u.is_null() && unsafe { ffi::ASN1_STRING_set(u.cast(), n.as_ptr().cast(), len) } == 1;
        // SAFETY: sk is live; on success it owns u.
        if !ok || unsafe { ffi::OPENSSL_sk_push(sk, u.cast()) } <= 0 {
            // SAFETY: u is NULL or owned here, sk empty and owned here.
            unsafe { ffi::ASN1_UTF8STRING_free(u) };
            // SAFETY: as above.
            unsafe { ffi::OPENSSL_sk_free(sk) };
            return None;
        }
        // SAFETY: sk is live; the ITAV owns it on success.
        let p = unsafe { ffi::OSSL_CMP_ITAV_new0_certProfile(sk.cast()) };
        if p.is_null() {
            // SAFETY: sk and its member are still owned here.
            unsafe { ffi::ASN1_UTF8STRING_free(u) };
            // SAFETY: as above.
            unsafe { ffi::OPENSSL_sk_free(sk) };
        }
        Self::from_ptr(p)
    }
}

impl Pkisi {
    /// `OSSL_CMP_PKISI_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::OSSL_CMP_PKISI_new() })
    }

    /// `OSSL_CMP_STATUSINFO_new(status, fail_info, text)`.
    pub fn status_info(status: c_int, fail_info: c_int, text: Option<&str>) -> Option<Self> {
        let t = text.and_then(cstring);
        // SAFETY: t is NULL or a valid C string.
        Self::from_ptr(unsafe {
            ffi::OSSL_CMP_STATUSINFO_new(
                status,
                fail_info,
                t.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            )
        })
    }
}

impl PkisiRef {
    /// `OSSL_CMP_PKISI_dup(si)`.
    pub fn dup(&self) -> Option<Pkisi> {
        // SAFETY: the status is live; the copy is the caller's.
        Pkisi::from_ptr(unsafe { ffi::OSSL_CMP_PKISI_dup(self.as_ptr()) })
    }

    /// `OSSL_CMP_snprint_PKIStatusInfo(si, buf, OSSL_CMP_PKISI_BUFLEN)`.
    pub fn snprint(&self) -> Option<String> {
        let mut buf = vec![0 as c_char; crate::abi::OSSL_CMP_PKISI_BUFLEN as usize];
        // SAFETY: the status is live; buf holds its length.
        let p = unsafe {
            ffi::OSSL_CMP_snprint_PKIStatusInfo(self.as_ptr(), buf.as_mut_ptr(), buf.len())
        };
        string_at(p)
    }
}

impl IntegerRef {
    /// `ASN1_INTEGER_get(a)`.
    pub fn get(&self) -> c_long {
        // SAFETY: the integer is live.
        unsafe { ffi::ASN1_INTEGER_get(self.as_ptr()) }
    }

    /// `ASN1_INTEGER_cmp(a, b)`.
    pub fn compare(&self, b: &IntegerRef) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::ASN1_INTEGER_cmp(self.as_ptr(), b.as_ptr()) }
    }
}

impl FreeTextRef {
    /// The number of strings.
    pub fn len(&self) -> usize {
        members::<crate::abi::ASN1_STRING>(self.as_ptr().cast()).len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `ASN1_STRING_print_ex(out, string i, flags)`.
    pub fn print_ex(&self, i: usize, out: &Bio, flags: core::ffi::c_ulong) -> c_int {
        let m = members::<crate::abi::ASN1_STRING>(self.as_ptr().cast());
        let s = m.get(i).copied().unwrap_or(ptr::null_mut());
        // SAFETY: the BIO is live; s is NULL or a live string.
        unsafe { ffi::ASN1_STRING_print_ex(out.as_ptr(), s, flags) }
    }
}

impl CertTemplate {
    /// `OSSL_CRMF_CERTTEMPLATE_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::OSSL_CRMF_CERTTEMPLATE_new() })
    }

    /// `OSSL_CRMF_CERTTEMPLATE_fill(tmpl, NULL, NULL, issuer, NULL)`.
    pub fn fill_issuer(&self, issuer: NameRef<'_>) -> bool {
        // SAFETY: the template is live; issuer is NULL or live (copied).
        unsafe {
            ffi::OSSL_CRMF_CERTTEMPLATE_fill(
                self.as_ptr(),
                ptr::null_mut(),
                ptr::null(),
                issuer.as_raw(),
                ptr::null(),
            ) == 1
        }
    }
}

impl CertTemplateRef {
    /// `i2d_OSSL_CRMF_CERTTEMPLATE`.
    pub fn to_der(&self) -> Option<Vec<u8>> {
        // SAFETY: the template is live; NULL output asks for the length.
        let len = unsafe { ffi::i2d_OSSL_CRMF_CERTTEMPLATE(self.as_ptr(), ptr::null_mut()) };
        let mut buf = vec![0u8; usize::try_from(len).ok()?];
        let mut p = buf.as_mut_ptr();
        // SAFETY: buf holds len bytes.
        let n = unsafe { ffi::i2d_OSSL_CRMF_CERTTEMPLATE(self.as_ptr(), &mut p) };
        (n == len).then_some(buf)
    }
}

/// An owned `OSSL_CMP_ATAVS` (a stack of `OSSL_CMP_ATAV`).
pub struct Atavs(ptr::NonNull<OSSL_CMP_ATAVS>);

unsafe extern "C" fn free_atav(p: *mut c_void) {
    // SAFETY: the stack's members are ATAVs.
    unsafe { ffi::OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free(p.cast()) };
}

impl Atavs {
    fn from_ptr(p: *mut OSSL_CMP_ATAVS) -> Option<Self> {
        ptr::NonNull::new(p).map(Self)
    }

    fn into_ptr(self) -> *mut OSSL_CMP_ATAVS {
        let p = self.0.as_ptr();
        core::mem::forget(self);
        p
    }

    /// `OSSL_CMP_ATAV_push1(&atavs, atav)` (`None` makes the stack).
    pub fn push1(atavs: &mut Option<Atavs>, atav: Option<&AtavRef>) -> bool {
        let mut p = atavs.take().map_or(ptr::null_mut(), Atavs::into_ptr);
        // SAFETY: p is NULL or a live stack; atav is NULL or live (copied).
        let ok = unsafe {
            ffi::OSSL_CMP_ATAV_push1(
                &mut p,
                atav.map_or(ptr::null(), |a| a.as_ptr().cast_const()),
            )
        } == 1;
        *atavs = Atavs::from_ptr(p);
        ok
    }

    /// The members (NULL as `None`).
    pub fn items(&self) -> Vec<Option<&AtavRef>> {
        members::<OSSL_CMP_ATAV>(self.0.as_ptr().cast())
            .into_iter()
            .map(|p| AtavRef::from_raw(p))
            .collect()
    }

    /// `i2d_OSSL_CMP_ATAVS`.
    pub fn to_der(&self) -> Option<Vec<u8>> {
        // SAFETY: the stack is live; NULL output asks for the length.
        let len = unsafe { ffi::i2d_OSSL_CMP_ATAVS(self.0.as_ptr(), ptr::null_mut()) };
        let mut buf = vec![0u8; usize::try_from(len).ok()?];
        let mut p = buf.as_mut_ptr();
        // SAFETY: buf holds len bytes.
        let n = unsafe { ffi::i2d_OSSL_CMP_ATAVS(self.0.as_ptr(), &mut p) };
        (n == len).then_some(buf)
    }
}

impl Drop for Atavs {
    fn drop(&mut self) {
        // SAFETY: the stack and its members are owned by self.
        unsafe { ffi::OPENSSL_sk_pop_free(self.0.as_ptr().cast(), Some(free_atav)) };
    }
}

impl Atav {
    /// `OSSL_CMP_ATAV_new_algId` of an `X509_ALGOR` with `OBJ_nid2obj(nid)` and no
    /// parameters.
    pub fn new_alg_id(nid: c_int) -> Option<Self> {
        // SAFETY: no arguments.
        let alg = unsafe { ffi::X509_ALGOR_new() };
        if alg.is_null() {
            return None;
        }
        // SAFETY: no pointer arguments.
        let obj = unsafe { ffi::OBJ_nid2obj(nid) };
        // SAFETY: alg is live; it takes obj (V_ASN1_UNDEF: no parameter).
        unsafe { ffi::X509_ALGOR_set0(alg, obj, crate::abi::V_ASN1_UNDEF, ptr::null_mut()) };
        // SAFETY: alg is live (copied).
        let p = unsafe { ffi::OSSL_CMP_ATAV_new_algId(alg) };
        // SAFETY: alg is owned here.
        unsafe { ffi::X509_ALGOR_free(alg) };
        Self::from_ptr(p)
    }

    /// `OSSL_CMP_ATAV_new_rsaKeyLen(len)`.
    pub fn new_rsa_key_len(len: c_int) -> Option<Self> {
        // SAFETY: no pointer arguments.
        Self::from_ptr(unsafe { ffi::OSSL_CMP_ATAV_new_rsaKeyLen(len) })
    }
}

impl AtavRef {
    /// `OBJ_obj2nid(OSSL_CMP_ATAV_get0_type(atav))`.
    pub fn type_nid(&self) -> c_int {
        // SAFETY: the ATAV is live; the object stays owned by it.
        let t = unsafe { ffi::OSSL_CMP_ATAV_get0_type(self.as_ptr()) };
        // SAFETY: t is NULL or live.
        unsafe { ffi::OBJ_obj2nid(t) }
    }

    /// `OSSL_CMP_ATAV_get0_algId(atav)`.
    pub fn alg_id(&self) -> Option<&AlgorRef> {
        // SAFETY: the ATAV is live; the algorithm stays owned by it.
        AlgorRef::from_raw(unsafe { ffi::OSSL_CMP_ATAV_get0_algId(self.as_ptr()) })
    }

    /// `OSSL_CMP_ATAV_get_rsaKeyLen(atav)`.
    pub fn rsa_key_len(&self) -> c_int {
        // SAFETY: the ATAV is live.
        unsafe { ffi::OSSL_CMP_ATAV_get_rsaKeyLen(self.as_ptr()) }
    }
}

/// `OBJ_obj2nid(NULL)` for an absent ATAV (`OSSL_CMP_ATAV_get0_type(NULL)` is NULL).
pub fn absent_atav_nid() -> c_int {
    // SAFETY: NULL is allowed.
    let t = unsafe { ffi::OSSL_CMP_ATAV_get0_type(ptr::null()) };
    // SAFETY: t is NULL or live.
    unsafe { ffi::OBJ_obj2nid(t) }
}

impl AlgorRef {
    /// `i2a_ASN1_OBJECT(out, oid)` of `X509_ALGOR_get0`'s OID.
    pub fn print_oid(&self, out: &Bio) -> c_int {
        let mut oid = ptr::null();
        // SAFETY: the algorithm is live; NULL outputs are allowed.
        unsafe { ffi::X509_ALGOR_get0(&mut oid, ptr::null_mut(), ptr::null_mut(), self.as_ptr()) };
        // SAFETY: the BIO is live; oid is NULL or live.
        unsafe { ffi::i2a_ASN1_OBJECT(out.as_ptr(), oid) }
    }

    /// Whether it has parameters: `X509_ALGOR_get0`'s type isn't `V_ASN1_UNDEF` and the
    /// parameter is set.
    pub fn has_parameter(&self) -> bool {
        let mut ptype: c_int = 0;
        let mut pval = ptr::null();
        // SAFETY: the algorithm is live; NULL outputs are allowed.
        unsafe { ffi::X509_ALGOR_get0(ptr::null_mut(), &mut ptype, &mut pval, self.as_ptr()) };
        // SAFETY: the algorithm is live (a public struct).
        let param = unsafe { (*self.as_ptr()).parameter };
        ptype != crate::abi::V_ASN1_UNDEF && !param.is_null()
    }

    /// `ASN1_item_print(out, alg, 0, ASN1_ITEM_rptr(X509_ALGOR), NULL)`.
    pub fn item_print(&self, out: &Bio) -> c_int {
        // SAFETY: no arguments.
        let it = unsafe { ffi::X509_ALGOR_it() };
        // SAFETY: the BIO and algorithm are live; NULL print context is allowed.
        unsafe { ffi::ASN1_item_print(out.as_ptr(), self.as_ptr().cast(), 0, it, ptr::null()) }
    }
}

// ---------------------------------------------------------------------------------------------
// Certificates and names, as the mock server compares them

impl Cert {
    /// `X509_dup(cert)`.
    pub fn dup(&self) -> Option<Cert> {
        // SAFETY: the certificate is live; the copy is the caller's.
        Cert::from_raw(unsafe { ffi::X509_dup(self.as_ptr()) })
    }

    /// `X509_get0_serialNumber(cert)`.
    pub fn serial(&self) -> Option<&IntegerRef> {
        // SAFETY: the certificate is live; the number stays owned by it.
        IntegerRef::from_raw(unsafe { ffi::X509_get0_serialNumber(self.as_ptr()) })
    }

    /// `X509_digest_sig(cert, NULL, NULL)`.
    pub fn digest_sig(&self) -> Option<Vec<u8>> {
        // SAFETY: the certificate is live; NULL outputs are allowed; the string is the
        // caller's.
        let s = unsafe { ffi::X509_digest_sig(self.as_ptr(), ptr::null_mut(), ptr::null_mut()) };
        let b = string_bytes(s.cast());
        // SAFETY: s is NULL or owned here.
        unsafe { ffi::ASN1_OCTET_STRING_free(s) };
        b
    }

    /// `X509_add_cert(certs, cert, X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_PREPEND)`.
    pub fn prepend_to(&self, certs: &CertStack) -> bool {
        let flags = (crate::abi::X509_ADD_FLAG_UP_REF | crate::abi::X509_ADD_FLAG_PREPEND) as c_int;
        // SAFETY: both are live; the stack takes a new reference.
        unsafe { ffi::X509_add_cert(certs.as_ptr(), self.as_ptr(), flags) == 1 }
    }
}

impl CertStack {
    /// `X509_chain_up_ref(certs)`.
    pub fn up_ref_copy(&self) -> Option<CertStack> {
        // SAFETY: the stack is live; the copy is the caller's.
        CertStack::from_raw(unsafe { ffi::X509_chain_up_ref(self.as_ptr()) })
    }
}

impl Crl {
    /// `X509_CRL_get_issuer(crl)`.
    pub fn issuer_name(&self) -> NameRef<'_> {
        // SAFETY: the CRL is live; the name stays owned by it.
        NameRef::from_raw(unsafe { ffi::X509_CRL_get_issuer(self.as_ptr()) })
    }

    /// `i2d_X509_CRL_bio(out, crl)`.
    pub fn write_der(&self, out: &Bio) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::i2d_X509_CRL_bio(out.as_ptr(), self.as_ptr()) == 1 }
    }
}

/// `X509_NAME_cmp(a, b)`.
pub fn name_cmp(a: NameRef<'_>, b: NameRef<'_>) -> c_int {
    // SAFETY: both are NULL or live.
    unsafe { ffi::X509_NAME_cmp(a.as_raw(), b.as_raw()) }
}

/// `OSSL_CRMF_MSG_get0_regCtrl_oldCertID(crm)`: its issuer and serial number; `None` if
/// absent.
pub fn old_cert_id(crm: &CrmfMsgRef) -> Option<(NameRef<'_>, Option<&IntegerRef>)> {
    // SAFETY: the message is live; the ID stays owned by it.
    let cid = unsafe { ffi::OSSL_CRMF_MSG_get0_regCtrl_oldCertID(crm.as_ptr()) };
    if cid.is_null() {
        return None;
    }
    // SAFETY: cid is live.
    let issuer = unsafe { ffi::OSSL_CRMF_CERTID_get0_issuer(cid) };
    // SAFETY: cid is live.
    let serial = unsafe { ffi::OSSL_CRMF_CERTID_get0_serialNumber(cid) };
    Some((NameRef::from_raw(issuer), IntegerRef::from_raw(serial)))
}

/// `OSSL_CRMF_MSG_centralkeygen_requested(crm, p10cr)`.
pub fn centralkeygen_requested(crm: Option<&CrmfMsgRef>, p10cr: Option<&ReqRef>) -> c_int {
    // SAFETY: each is NULL or live.
    unsafe {
        ffi::OSSL_CRMF_MSG_centralkeygen_requested(
            crm.map_or(ptr::null(), |c| c.as_ptr().cast_const()),
            p10cr.map_or(ptr::null(), |r| r.as_ptr().cast_const()),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// The server context

/// The response to a certificate request: the status, and the certificate, its chain, and
/// the CA certificates to return.
pub struct CertResponse {
    pub si: Pkisi,
    pub cert: Option<Cert>,
    pub chain: Option<CertStack>,
    pub ca_pubs: Option<CertStack>,
}

/// A pollReq's answer.
pub enum Poll {
    /// Polling ends: the original request to answer.
    Done(Msg),
    /// Poll again after this many seconds.
    After(i64),
}

/// The request handlers of `OSSL_CMP_SRV_CTX_init` and `OSSL_CMP_SRV_CTX_init_trans`. A
/// `None`/`false`/negative result is an error the handler raised.
pub trait Server {
    fn cert_request(
        &self,
        srv: &SrvRef,
        req: Option<&MsgRef>,
        cert_req_id: c_int,
        crm: Option<&CrmfMsgRef>,
        p10cr: Option<&ReqRef>,
    ) -> Option<CertResponse>;
    fn rr(
        &self,
        srv: &SrvRef,
        req: Option<&MsgRef>,
        issuer: Option<NameRef<'_>>,
        serial: Option<&IntegerRef>,
    ) -> Option<Pkisi>;
    fn genm(
        &self,
        srv: &SrvRef,
        req: Option<&MsgRef>,
        items: Option<Vec<&ItavRef>>,
    ) -> Option<ItavStack>;
    fn error(
        &self,
        srv: &SrvRef,
        req: Option<&MsgRef>,
        si: Option<&PkisiRef>,
        error_code: Option<&IntegerRef>,
        details: Option<&FreeTextRef>,
    );
    fn cert_conf(
        &self,
        srv: &SrvRef,
        req: Option<&MsgRef>,
        cert_req_id: c_int,
        cert_hash: Option<Vec<u8>>,
        si: Option<&PkisiRef>,
    ) -> bool;
    fn poll_req(&self, srv: &SrvRef, req: Option<&MsgRef>, cert_req_id: c_int) -> Option<Poll>;
    fn delayed_delivery(&self, srv: &SrvRef, req: Option<&MsgRef>) -> c_int;
    fn clean_transaction(&self, srv: &SrvRef) -> bool;
}

/// An owned `OSSL_CMP_SRV_CTX` whose custom context is a [`Server`].
pub struct SrvCtx {
    srv: ptr::NonNull<OSSL_CMP_SRV_CTX>,
    handler: *mut Box<dyn Server>,
}

fn handler<'a>(srv: *mut OSSL_CMP_SRV_CTX) -> Option<(&'a SrvRef, &'a dyn Server)> {
    let s = SrvRef::from_raw(srv)?;
    // SAFETY: srv is a live server context made by SrvCtx::new, whose custom context is the
    // boxed handler, which lives as long as the server context.
    let h = unsafe { ffi::OSSL_CMP_SRV_CTX_get0_custom_ctx(srv) }.cast::<Box<dyn Server>>();
    // SAFETY: as above; the handler is only borrowed shared.
    let h = unsafe { h.as_ref() }?;
    Some((s, &**h))
}

unsafe extern "C" fn srv_cert_request(
    srv: *mut OSSL_CMP_SRV_CTX,
    req: *const OSSL_CMP_MSG,
    cert_req_id: c_int,
    crm: *const OSSL_CRMF_MSG,
    p10cr: *const X509_REQ,
    cert_out: *mut *mut X509,
    chain_out: *mut *mut stack_st_X509,
    ca_pubs: *mut *mut stack_st_X509,
) -> *mut OSSL_CMP_PKISI {
    let Some((s, h)) = handler(srv) else {
        return ptr::null_mut();
    };
    if cert_out.is_null() || chain_out.is_null() || ca_pubs.is_null() {
        raise(
            crate::abi::CMP_R_NULL_ARGUMENT as c_int,
            c"apps/lib/cmp_mock_srv.c",
            314,
            c"process_cert_request",
            None,
        );
        return ptr::null_mut();
    }
    let r = h.cert_request(
        s,
        MsgRef::from_raw(req),
        cert_req_id,
        CrmfMsgRef::from_raw(crm),
        ReqRef::from_raw(p10cr),
    );
    let Some(r) = r else {
        return ptr::null_mut();
    };
    // SAFETY: the outputs are non-NULL (checked above); the library takes what they get.
    unsafe {
        *cert_out = r.cert.map_or(ptr::null_mut(), Cert::into_ptr);
    }
    // SAFETY: as above.
    unsafe {
        *chain_out = r.chain.map_or(ptr::null_mut(), CertStack::into_ptr);
    }
    // SAFETY: as above.
    unsafe {
        *ca_pubs = r.ca_pubs.map_or(ptr::null_mut(), CertStack::into_ptr);
    }
    r.si.into_ptr()
}

unsafe extern "C" fn srv_rr(
    srv: *mut OSSL_CMP_SRV_CTX,
    req: *const OSSL_CMP_MSG,
    issuer: *const X509_NAME,
    serial: *const ASN1_INTEGER,
) -> *mut OSSL_CMP_PKISI {
    let Some((s, h)) = handler(srv) else {
        return ptr::null_mut();
    };
    h.rr(
        s,
        MsgRef::from_raw(req),
        (!issuer.is_null()).then(|| NameRef::from_raw(issuer)),
        IntegerRef::from_raw(serial),
    )
    .map_or(ptr::null_mut(), Pkisi::into_ptr)
}

unsafe extern "C" fn srv_genm(
    srv: *mut OSSL_CMP_SRV_CTX,
    req: *const OSSL_CMP_MSG,
    in_: *const stack_st_OSSL_CMP_ITAV,
    out: *mut *mut stack_st_OSSL_CMP_ITAV,
) -> c_int {
    let Some((s, h)) = handler(srv) else {
        return 0;
    };
    if out.is_null() {
        raise(
            crate::abi::CMP_R_NULL_ARGUMENT as c_int,
            c"apps/lib/cmp_mock_srv.c",
            593,
            c"process_genm",
            None,
        );
        return 0;
    }
    let items = (!in_.is_null()).then(|| {
        members::<OSSL_CMP_ITAV>(in_.cast())
            .into_iter()
            .filter_map(|p| ItavRef::from_raw(p))
            .collect()
    });
    match h.genm(s, MsgRef::from_raw(req), items) {
        Some(st) => {
            // SAFETY: out is non-NULL (checked above); the library takes the stack.
            unsafe { *out = st.into_ptr() };
            1
        }
        None => 0,
    }
}

unsafe extern "C" fn srv_error(
    srv: *mut OSSL_CMP_SRV_CTX,
    req: *const OSSL_CMP_MSG,
    si: *const OSSL_CMP_PKISI,
    error_code: *const ASN1_INTEGER,
    details: *const OSSL_CMP_PKIFREETEXT,
) {
    if let Some((s, h)) = handler(srv) {
        h.error(
            s,
            MsgRef::from_raw(req),
            PkisiRef::from_raw(si),
            IntegerRef::from_raw(error_code),
            FreeTextRef::from_raw(details),
        );
    }
}

unsafe extern "C" fn srv_cert_conf(
    srv: *mut OSSL_CMP_SRV_CTX,
    req: *const OSSL_CMP_MSG,
    cert_req_id: c_int,
    cert_hash: *const ASN1_OCTET_STRING,
    si: *const OSSL_CMP_PKISI,
) -> c_int {
    let Some((s, h)) = handler(srv) else {
        return 0;
    };
    c_int::from(h.cert_conf(
        s,
        MsgRef::from_raw(req),
        cert_req_id,
        string_bytes(cert_hash.cast()),
        PkisiRef::from_raw(si),
    ))
}

unsafe extern "C" fn srv_poll_req(
    srv: *mut OSSL_CMP_SRV_CTX,
    req: *const OSSL_CMP_MSG,
    cert_req_id: c_int,
    cert_req: *mut *mut OSSL_CMP_MSG,
    check_after: *mut i64,
) -> c_int {
    if !cert_req.is_null() {
        // SAFETY: cert_req is non-NULL; it is an output.
        unsafe { *cert_req = ptr::null_mut() };
    }
    let Some((s, h)) = handler(srv) else {
        return 0;
    };
    if cert_req.is_null() || check_after.is_null() {
        raise(
            crate::abi::CMP_R_NULL_ARGUMENT as c_int,
            c"apps/lib/cmp_mock_srv.c",
            709,
            c"process_pollReq",
            None,
        );
        return 0;
    }
    match h.poll_req(s, MsgRef::from_raw(req), cert_req_id) {
        Some(Poll::Done(m)) => {
            // SAFETY: the outputs are non-NULL (checked above); the library takes the message.
            unsafe { *cert_req = m.into_ptr() };
            // SAFETY: as above.
            unsafe { *check_after = 0 };
            1
        }
        Some(Poll::After(t)) => {
            // SAFETY: as above.
            unsafe { *check_after = t };
            1
        }
        None => 0,
    }
}

unsafe extern "C" fn srv_delayed_delivery(
    srv: *mut OSSL_CMP_SRV_CTX,
    req: *const OSSL_CMP_MSG,
) -> c_int {
    match handler(srv) {
        Some((s, h)) => h.delayed_delivery(s, MsgRef::from_raw(req)),
        None => -1,
    }
}

unsafe extern "C" fn srv_clean_transaction(
    srv: *mut OSSL_CMP_SRV_CTX,
    _id: *const ASN1_OCTET_STRING,
) -> c_int {
    match handler(srv) {
        Some((s, h)) => c_int::from(h.clean_transaction(s)),
        None => 0,
    }
}

impl SrvCtx {
    /// `OSSL_CMP_SRV_CTX_new(libctx, propq)`, initialized with `handler`'s callbacks
    /// (`OSSL_CMP_SRV_CTX_init` and `OSSL_CMP_SRV_CTX_init_trans`).
    pub fn new(
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
        handler: Box<dyn Server>,
    ) -> Option<Self> {
        let pq = propq.and_then(cstring);
        // SAFETY: libctx is NULL or live; pq is NULL or a valid C string.
        let p = unsafe {
            ffi::OSSL_CMP_SRV_CTX_new(
                libctx_ptr(libctx),
                pq.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            )
        };
        let srv = ptr::NonNull::new(p)?;
        let h = Box::into_raw(Box::new(handler));
        let me = Self { srv, handler: h };
        // SAFETY: the context is live; the custom context is the boxed handler, freed only
        // after the server context (Drop); the callbacks are static functions.
        let ok = unsafe {
            ffi::OSSL_CMP_SRV_CTX_init(
                me.as_ptr(),
                h.cast(),
                Some(srv_cert_request),
                Some(srv_rr),
                Some(srv_genm),
                Some(srv_error),
                Some(srv_cert_conf),
                Some(srv_poll_req),
            )
        } == 1;
        // SAFETY: as above.
        let ok = ok
            && unsafe {
                ffi::OSSL_CMP_SRV_CTX_init_trans(
                    me.as_ptr(),
                    Some(srv_delayed_delivery),
                    Some(srv_clean_transaction),
                )
            } == 1;
        ok.then_some(me)
    }

    /// The context, for the C API.
    pub fn as_ptr(&self) -> *mut OSSL_CMP_SRV_CTX {
        self.srv.as_ptr()
    }
}

impl core::ops::Deref for SrvCtx {
    type Target = SrvRef;
    fn deref(&self) -> &SrvRef {
        // SAFETY: the context is owned by self, so it lives as long as the borrow.
        unsafe { &*self.srv.as_ptr().cast::<SrvRef>() }
    }
}

impl Drop for SrvCtx {
    fn drop(&mut self) {
        // SAFETY: the context is owned by self and freed once, here.
        unsafe { ffi::OSSL_CMP_SRV_CTX_free(self.srv.as_ptr()) };
        // SAFETY: the handler was made by Box::into_raw in new, and nothing uses it now.
        drop(unsafe { Box::from_raw(self.handler) });
    }
}

impl SrvRef {
    /// `OSSL_CMP_SRV_CTX_get0_cmp_ctx(srv_ctx)`.
    pub fn cmp_ctx(&self) -> Option<&Ctx> {
        // SAFETY: the server context is live; the context is owned by it.
        Ctx::from_raw(unsafe { ffi::OSSL_CMP_SRV_CTX_get0_cmp_ctx(self.as_ptr()) })
    }

    /// `OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(srv_ctx, val)`.
    pub fn set_grant_implicit_confirm(&self, val: bool) -> bool {
        // SAFETY: the server context is live.
        unsafe {
            ffi::OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(self.as_ptr(), c_int::from(val)) == 1
        }
    }

    /// `OSSL_CMP_SRV_CTX_set_send_unprotected_errors(srv_ctx, val)`.
    pub fn set_send_unprotected_errors(&self, val: bool) -> bool {
        // SAFETY: the server context is live.
        unsafe {
            ffi::OSSL_CMP_SRV_CTX_set_send_unprotected_errors(self.as_ptr(), c_int::from(val)) == 1
        }
    }

    /// `OSSL_CMP_SRV_CTX_set_accept_unprotected(srv_ctx, val)`.
    pub fn set_accept_unprotected(&self, val: bool) -> bool {
        // SAFETY: the server context is live.
        unsafe {
            ffi::OSSL_CMP_SRV_CTX_set_accept_unprotected(self.as_ptr(), c_int::from(val)) == 1
        }
    }

    /// `OSSL_CMP_SRV_CTX_set_accept_raverified(srv_ctx, val)`.
    pub fn set_accept_raverified(&self, val: bool) -> bool {
        // SAFETY: the server context is live.
        unsafe { ffi::OSSL_CMP_SRV_CTX_set_accept_raverified(self.as_ptr(), c_int::from(val)) == 1 }
    }
}

// ---------------------------------------------------------------------------------------------
// TLS (setup_ssl_ctx)

impl SslCtx {
    /// `SSL_CTX_set_cert_store(ctx, store)` (which takes it) and, if `verify_peer`,
    /// `SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL)`.
    pub fn set_cert_store(&self, store: Store, verify_peer: bool) {
        // SAFETY: both are live; the SSL_CTX takes the store.
        unsafe { ffi::SSL_CTX_set_cert_store(self.as_ptr(), store.into_ptr()) };
        if verify_peer {
            // SAFETY: the SSL_CTX is live; no callback.
            unsafe {
                ffi::SSL_CTX_set_verify(self.as_ptr(), crate::abi::SSL_VERIFY_PEER as c_int, None)
            };
        }
    }

    /// `SSL_CTX_get_cert_store(ctx)`'s verification flags: `X509_VERIFY_PARAM_get_flags`.
    pub fn store_flags(&self) -> Option<core::ffi::c_ulong> {
        let vpm = self.store_param()?;
        // SAFETY: vpm is live (owned by the store).
        Some(unsafe { ffi::X509_VERIFY_PARAM_get_flags(vpm) })
    }

    fn store_param(&self) -> Option<*mut crate::abi::X509_VERIFY_PARAM> {
        // SAFETY: the SSL_CTX is live; the store stays owned by it.
        let st = unsafe { ffi::SSL_CTX_get_cert_store(self.as_ptr()) };
        if st.is_null() {
            return None;
        }
        // SAFETY: st is live; the param stays owned by it.
        Some(unsafe { ffi::X509_STORE_get0_param(st) })
    }

    /// `X509_VERIFY_PARAM_clear_flags` on the store's parameters.
    pub fn store_clear_flags(&self, flags: core::ffi::c_ulong) {
        if let Some(vpm) = self.store_param() {
            // SAFETY: vpm is live (owned by the store).
            unsafe { ffi::X509_VERIFY_PARAM_clear_flags(vpm, flags) };
        }
    }

    /// `X509_VERIFY_PARAM_set_flags` on the store's parameters.
    pub fn store_set_flags(&self, flags: core::ffi::c_ulong) {
        if let Some(vpm) = self.store_param() {
            // SAFETY: vpm is live (owned by the store).
            unsafe { ffi::X509_VERIFY_PARAM_set_flags(vpm, flags) };
        }
    }

    /// [`truststore_set_host_etc`] on the `SSL_CTX`'s trust store (`false` if it has none).
    pub fn store_set_host_etc(&self, host: Option<&str>) -> bool {
        // SAFETY: the SSL_CTX is live; the store stays owned by it.
        let st = unsafe { ffi::SSL_CTX_get_cert_store(self.as_ptr()) };
        !st.is_null() && set_host_etc(st, host)
    }

    /// `SSL_CTX_use_certificate(ctx, cert) > 0`.
    pub fn use_certificate(&self, cert: &Cert) -> bool {
        // SAFETY: both are live; the SSL_CTX takes its own reference.
        unsafe { ffi::SSL_CTX_use_certificate(self.as_ptr(), cert.as_ptr()) > 0 }
    }

    /// `SSL_CTX_set0_chain(ctx, certs)` (`SSL_CTX_ctrl(SSL_CTRL_CHAIN, 0, certs)`), which
    /// takes the stack on success.
    pub fn set0_chain(&self, certs: Option<CertStack>) -> Result<(), Option<CertStack>> {
        let p = certs.as_ref().map_or(ptr::null_mut(), CertStack::as_ptr);
        // SAFETY: the SSL_CTX is live; p is NULL or a live stack it takes on success.
        let r = unsafe {
            ffi::SSL_CTX_ctrl(
                self.as_ptr(),
                crate::abi::SSL_CTRL_CHAIN as c_int,
                0,
                p.cast(),
            )
        };
        if r != 0 {
            if let Some(c) = certs {
                let _ = c.into_ptr();
            }
            Ok(())
        } else {
            Err(certs)
        }
    }

    /// `SSL_CTX_add1_chain_cert(ctx, cert)`.
    pub fn add1_chain_cert(&self, cert: &Cert) -> bool {
        // SAFETY: both are live; the SSL_CTX takes its own reference.
        unsafe {
            ffi::SSL_CTX_ctrl(
                self.as_ptr(),
                crate::abi::SSL_CTRL_CHAIN_CERT as c_int,
                1,
                cert.as_ptr().cast(),
            ) != 0
        }
    }

    /// `SSL_CTX_build_cert_chain(ctx, flags)`.
    pub fn build_cert_chain(&self, flags: c_long) -> bool {
        // SAFETY: the SSL_CTX is live.
        unsafe {
            ffi::SSL_CTX_ctrl(
                self.as_ptr(),
                crate::abi::SSL_CTRL_BUILD_CERT_CHAIN as c_int,
                flags,
                ptr::null_mut(),
            ) != 0
        }
    }

    /// `SSL_CTX_add_extra_chain_cert(ctx, cert)`, which takes it on success.
    pub fn add_extra_chain_cert(&self, cert: Cert) -> bool {
        // SAFETY: both are live; on success the SSL_CTX owns the certificate.
        if unsafe {
            ffi::SSL_CTX_ctrl(
                self.as_ptr(),
                crate::abi::SSL_CTRL_EXTRA_CHAIN_CERT as c_int,
                0,
                cert.as_ptr().cast(),
            )
        } != 0
        {
            let _ = cert.into_ptr();
            true
        } else {
            false
        }
    }

    /// `SSL_CTX_get0_certificate(ctx)`, as a new reference.
    pub fn certificate(&self) -> Option<Cert> {
        // SAFETY: the SSL_CTX is live; the certificate stays owned by it.
        Cert::from_borrowed(unsafe { ffi::SSL_CTX_get0_certificate(self.as_ptr()) })
    }

    /// `SSL_CTX_use_PrivateKey(ctx, pkey) > 0`.
    pub fn use_private_key(&self, pkey: &Pkey) -> bool {
        // SAFETY: both are live; the SSL_CTX takes its own reference.
        unsafe { ffi::SSL_CTX_use_PrivateKey(self.as_ptr(), pkey.as_ptr()) > 0 }
    }
}

/// `X509_check_private_key(cert, pkey)` with a possibly absent certificate.
pub fn check_private_key(cert: Option<&Cert>, pkey: &Pkey) -> bool {
    // SAFETY: cert is NULL or live; pkey is live.
    unsafe { ffi::X509_check_private_key(cert_ptr(cert), pkey.as_ptr()) == 1 }
}

/// `X509_VERIFY_PARAM_set1_host(vpm, NULL, 0)`, `..._ip(NULL, 0)`, `..._email(NULL, 0)`, the
/// host flags, then `X509_VERIFY_PARAM_set1_ip_asc(vpm, host) ||
/// X509_VERIFY_PARAM_set1_host(vpm, host, 0)`: `truststore_set_host_etc` of `cmp.c`.
pub fn truststore_set_host_etc(store: &Store, host: Option<&str>) -> bool {
    set_host_etc(store.as_ptr(), host)
}

fn set_host_etc(store: *mut X509_STORE, host: Option<&str>) -> bool {
    // SAFETY: the store is live (the callers' objects); the param stays owned by it.
    let vpm = unsafe { ffi::X509_STORE_get0_param(store) };
    // SAFETY: vpm is live; NULL clears.
    if unsafe { ffi::X509_VERIFY_PARAM_set1_host(vpm, ptr::null(), 0) } != 1 {
        return false;
    }
    // SAFETY: as above.
    if unsafe { ffi::X509_VERIFY_PARAM_set1_ip(vpm, ptr::null(), 0) } != 1 {
        return false;
    }
    // SAFETY: as above.
    if unsafe { ffi::X509_VERIFY_PARAM_set1_email(vpm, ptr::null(), 0) } != 1 {
        return false;
    }
    let flags = (crate::abi::X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT
        | crate::abi::X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS) as core::ffi::c_uint;
    // SAFETY: vpm is live.
    unsafe { ffi::X509_VERIFY_PARAM_set_hostflags(vpm, flags) };
    let h = host.and_then(cstring);
    let hp = h.as_ref().map_or(ptr::null(), |s| s.as_ptr());
    // SAFETY: vpm is live; hp is a valid C string.
    if !hp.is_null() && unsafe { ffi::X509_VERIFY_PARAM_set1_ip_asc(vpm, hp) } == 1 {
        return true;
    }
    // SAFETY: vpm is live; hp is NULL or a valid C string (0: its length).
    unsafe { ffi::X509_VERIFY_PARAM_set1_host(vpm, hp, 0) == 1 }
}

impl Bio {
    /// Writes `data` (for `ASN1_i2d_bio_of`'s output).
    pub fn write_der(&self, data: &[u8]) -> bool {
        self.write_all(data).is_ok()
    }
}
