//! libssl's callbacks for the TLS commands (`apps/lib/s_cb.c` and the commands' own).
//!
//! Each kind of callback has one trampoline here: an `extern "C"` function the library calls,
//! which turns its arguments into safe borrowed wrappers and calls the Rust function the
//! command registered for that kind (one per kind and process, as the commands use them).
//! The callbacks' `void *arg`s aren't used: the commands keep their state themselves, except
//! for the `BIO`s a few callbacks write to, which are passed through as [`BioRef`]s.

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use std::sync::Mutex;

use crate::abi::*;
use crate::bio::Bio;
use crate::ffi;
use crate::ssl::{BioRef, CertRef, CipherRef, CtxRef, MdRef, Session, SessionRef, SslRef};
use crate::util::string_at;

fn get<T: Copy>(m: &Mutex<Option<T>>) -> Option<T> {
    *m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn set<T>(m: &Mutex<Option<T>>, v: Option<T>) {
    *m.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = v;
}

/// A slice from a pointer and length the library passed (empty for NULL).
///
/// # Safety
/// `p` is NULL or valid for `n` bytes for the callback's duration.
unsafe fn slice<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if p.is_null() || n == 0 {
        &[]
    } else {
        // SAFETY: the caller's contract.
        unsafe { core::slice::from_raw_parts(p, n) }
    }
}

/// A writable slice from a pointer and length the library passed (empty for NULL).
///
/// # Safety
/// `p` is NULL or writable for `n` bytes for the callback's duration.
unsafe fn slice_mut<'a>(p: *mut u8, n: usize) -> &'a mut [u8] {
    if p.is_null() || n == 0 {
        &mut []
    } else {
        // SAFETY: the caller's contract.
        unsafe { core::slice::from_raw_parts_mut(p, n) }
    }
}

/// `n` as a `usize` (0 if negative).
fn us<T: TryInto<usize>>(n: T) -> usize {
    n.try_into().unwrap_or(0)
}

fn transmute_cb<F>(f: F) -> Option<unsafe extern "C" fn()> {
    // SAFETY: f is an `unsafe extern "C" fn` pointer; `*_callback_ctrl` takes any function
    // pointer as `void (*)(void)` and calls it with the type its command documents.
    Some(unsafe { core::mem::transmute_copy::<F, unsafe extern "C" fn()>(&f) })
}

// ---- verification ----

/// An `X509_STORE_CTX` during a verify callback.
#[derive(Clone, Copy)]
pub struct StoreCtxRef<'a>(*mut X509_STORE_CTX, core::marker::PhantomData<&'a ()>);

impl<'a> StoreCtxRef<'a> {
    /// `X509_STORE_CTX_get_current_cert`.
    pub fn current_cert(self) -> Option<CertRef<'a>> {
        // SAFETY: the context is live during the callback.
        CertRef::new(unsafe { ffi::X509_STORE_CTX_get_current_cert(self.0) })
    }
    /// `X509_STORE_CTX_get_error`.
    pub fn error(self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::X509_STORE_CTX_get_error(self.0) }
    }
    /// `X509_STORE_CTX_get_error_depth`.
    pub fn error_depth(self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::X509_STORE_CTX_get_error_depth(self.0) }
    }
    /// `X509_STORE_CTX_get_explicit_policy`.
    pub fn explicit_policy(self) -> bool {
        // SAFETY: as above.
        unsafe { ffi::X509_STORE_CTX_get_explicit_policy(self.0) != 0 }
    }
    /// `nodes_print` of `apps.c` for the authority (`user` false) or user policies of the
    /// policy tree, through `X509_POLICY_NODE_print`; `None` if the stack is NULL.
    pub fn print_policy_nodes(self, bio: &Bio, user: bool, indent: c_int) -> bool {
        // SAFETY: as above; the tree is owned by the context.
        let tree = unsafe { ffi::X509_STORE_CTX_get0_policy_tree(self.0) };
        let nodes = if user {
            // SAFETY: tree is NULL or live; the stack is owned by it.
            unsafe { ffi::X509_policy_tree_get0_user_policies(tree) }
        } else {
            // SAFETY: as above.
            unsafe { ffi::X509_policy_tree_get0_policies(tree) }
        };
        if nodes.is_null() {
            return false;
        }
        let sk = nodes.cast::<OPENSSL_STACK>();
        // SAFETY: a live stack.
        let n = unsafe { ffi::OPENSSL_sk_num(sk) };
        for i in 0..n.max(0) {
            // SAFETY: i in range.
            let node = unsafe { ffi::OPENSSL_sk_value(sk, i) };
            // SAFETY: the members are policy nodes.
            unsafe { ffi::X509_POLICY_NODE_print(bio.as_ptr(), node.cast(), indent) };
        }
        true
    }
}

/// A verify callback (`SSL_CTX_set_verify`).
pub type VerifyFn = fn(c_int, StoreCtxRef<'_>) -> c_int;
static VERIFY: Mutex<Option<VerifyFn>> = Mutex::new(None);

unsafe extern "C" fn verify_tramp(ok: c_int, ctx: *mut X509_STORE_CTX) -> c_int {
    match get(&VERIFY) {
        Some(f) => f(ok, StoreCtxRef(ctx, core::marker::PhantomData)),
        None => ok,
    }
}

impl CtxRef<'_> {
    /// `SSL_CTX_set_verify(ctx, mode, cb)`.
    pub fn set_verify(self, mode: c_int, cb: Option<VerifyFn>) {
        if cb.is_some() {
            set(&VERIFY, cb);
        }
        let c: SSL_verify_cb = if cb.is_some() {
            Some(verify_tramp)
        } else {
            None
        };
        // SAFETY: the context is live; the trampoline matches SSL_verify_cb.
        unsafe { ffi::SSL_CTX_set_verify(self.as_ptr(), mode, c) };
    }
}

// ---- info, message, extension debug ----

/// An info callback (`SSL_CTX_set_info_callback`).
pub type InfoFn = fn(SslRef<'_>, c_int, c_int);
static INFO: Mutex<Option<InfoFn>> = Mutex::new(None);

unsafe extern "C" fn info_tramp(s: *const SSL, where_: c_int, ret: c_int) {
    if let (Some(f), Some(s)) = (get(&INFO), SslRef::new(s.cast_mut())) {
        f(s, where_, ret);
    }
}

impl CtxRef<'_> {
    /// `SSL_CTX_set_info_callback`.
    pub fn set_info_callback(self, cb: InfoFn) {
        set(&INFO, Some(cb));
        // SAFETY: the context is live; the trampoline has the callback's type.
        unsafe { ffi::SSL_CTX_set_info_callback(self.as_ptr(), Some(info_tramp)) };
    }
}

/// A message callback: `write_p`, version, content type, the message, the connection, and the
/// `BIO` set as its argument.
pub type MsgFn = fn(c_int, c_int, c_int, &[u8], SslRef<'_>, Option<BioRef<'_>>);
static MSG: Mutex<Option<MsgFn>> = Mutex::new(None);

unsafe extern "C" fn msg_tramp(
    write_p: c_int,
    version: c_int,
    content_type: c_int,
    buf: *const c_void,
    len: usize,
    ssl: *mut SSL,
    arg: *mut c_void,
) {
    if let (Some(f), Some(s)) = (get(&MSG), SslRef::new(ssl)) {
        // SAFETY: buf is valid for len bytes during the callback; arg is the BIO the
        // command set (`set_msg_callback_arg`).
        f(
            write_p,
            version,
            content_type,
            unsafe { slice(buf.cast(), len) },
            s,
            BioRef::new(arg.cast()),
        );
    }
}

unsafe extern "C" fn trace_tramp(
    write_p: c_int,
    version: c_int,
    content_type: c_int,
    buf: *const c_void,
    len: usize,
    ssl: *mut SSL,
    arg: *mut c_void,
) {
    // SAFETY: the library's own arguments, passed on unchanged to its SSL_trace.
    unsafe { ffi::SSL_trace(write_p, version, content_type, buf, len, ssl, arg) };
}

/// Which message callback (`msg_cb` or the library's `SSL_trace`).
#[derive(Clone, Copy)]
pub enum MsgCallback {
    Rust(MsgFn),
    Trace,
}

impl SslRef<'_> {
    /// `SSL_set_msg_callback` and `SSL_set_msg_callback_arg(s, bio)`.
    pub fn set_msg_callback(self, cb: MsgCallback, arg: &Bio) {
        let t: unsafe extern "C" fn(
            c_int,
            c_int,
            c_int,
            *const c_void,
            usize,
            *mut SSL,
            *mut c_void,
        ) = match cb {
            MsgCallback::Rust(f) => {
                set(&MSG, Some(f));
                msg_tramp
            }
            MsgCallback::Trace => trace_tramp,
        };
        // SAFETY: the connection is live; the trampoline has the callback's type.
        unsafe { ffi::SSL_set_msg_callback(self.as_ptr(), Some(t)) };
        // SAFETY: the BIO is kept alive by the command while the connection is.
        unsafe {
            ffi::SSL_ctrl(
                self.as_ptr(),
                SSL_CTRL_SET_MSG_CALLBACK_ARG,
                0,
                arg.as_ptr().cast(),
            );
        }
    }
}

/// A TLS extension debug callback: client_server, type, data, and the argument `BIO`.
pub type TlsextFn = fn(SslRef<'_>, c_int, c_int, &[u8], Option<BioRef<'_>>);
static TLSEXT: Mutex<Option<TlsextFn>> = Mutex::new(None);

unsafe extern "C" fn tlsext_tramp(
    s: *mut SSL,
    client_server: c_int,
    type_: c_int,
    data: *const c_uchar,
    len: c_int,
    arg: *mut c_void,
) {
    if let (Some(f), Some(r)) = (get(&TLSEXT), SslRef::new(s)) {
        // SAFETY: data is valid for len bytes; arg is the command's BIO.
        f(
            r,
            client_server,
            type_,
            unsafe { slice(data, us(len)) },
            BioRef::new(arg.cast()),
        );
    }
}

impl SslRef<'_> {
    /// `SSL_set_tlsext_debug_callback` and `SSL_set_tlsext_debug_arg(s, bio)`.
    pub fn set_tlsext_debug_callback(self, cb: TlsextFn, arg: &Bio) {
        set(&TLSEXT, Some(cb));
        type T = unsafe extern "C" fn(*mut SSL, c_int, c_int, *const c_uchar, c_int, *mut c_void);
        // SAFETY: the connection is live; the command's type is the trampoline's.
        unsafe {
            ffi::SSL_callback_ctrl(
                self.as_ptr(),
                SSL_CTRL_SET_TLSEXT_DEBUG_CB,
                transmute_cb::<T>(tlsext_tramp),
            )
        };
        // SAFETY: the BIO is kept alive by the command while the connection is.
        unsafe {
            ffi::SSL_ctrl(
                self.as_ptr(),
                SSL_CTRL_SET_TLSEXT_DEBUG_ARG,
                0,
                arg.as_ptr().cast(),
            );
        }
    }
}

// ---- BIO callbacks ----

/// One call of a `BIO_set_callback_ex` callback.
pub struct BioCbArgs<'a> {
    pub bio: BioRef<'a>,
    pub cmd: c_int,
    argp: *const c_char,
    pub len: usize,
    pub argi: c_int,
    pub argl: c_long,
    pub ret: c_int,
    processed: *mut usize,
}

impl BioCbArgs<'_> {
    /// `argp`'s address (for `%p`).
    pub fn argp_addr(&self) -> usize {
        self.argp as usize
    }
    /// The `BIO`'s address.
    pub fn bio_addr(&self) -> usize {
        self.bio.as_ptr() as usize
    }
    /// `*processed`, if given.
    pub fn processed(&self) -> Option<usize> {
        // SAFETY: processed is NULL or valid during the callback.
        (!self.processed.is_null()).then(|| unsafe { *self.processed })
    }
    /// The bytes read or written: `argp` for `*processed` bytes (after a successful read or
    /// write).
    pub fn data(&self) -> &[u8] {
        match self.processed() {
            // SAFETY: after a read or write that returned > 0, argp holds *processed bytes.
            Some(n) if self.ret > 0 => unsafe { slice(self.argp.cast(), n) },
            _ => &[],
        }
    }
    /// For `BIO_CB_RECVMMSG`/`BIO_CB_SENDMMSG`: each processed message's data address and
    /// bytes, `num_msg`, and the first message's (address, length).
    #[allow(clippy::type_complexity)]
    pub fn mmsgs(&self) -> (Vec<(usize, &[u8])>, usize, Option<(usize, usize)>) {
        let a = self.argp.cast::<BIO_MMSG_CB_ARGS>();
        if a.is_null() {
            return (Vec::new(), 0, None);
        }
        // SAFETY: for these commands argp is a BIO_MMSG_CB_ARGS (public layout).
        let args = unsafe { &*a };
        let mut out = Vec::new();
        if self.ret > 0 && !args.msgs_processed.is_null() {
            // SAFETY: msgs_processed is valid during the callback.
            let n = unsafe { *args.msgs_processed };
            for i in 0..n {
                let Some(off) = i.checked_mul(args.stride) else {
                    break;
                };
                // SAFETY: the library's array of messages, `stride` bytes apart.
                let mp = unsafe { args.msg.cast::<u8>().add(off) }.cast::<BIO_MSG>();
                // SAFETY: mp is the i-th message.
                let msg = unsafe { &*mp };
                // SAFETY: each message's data is valid for data_len bytes.
                let d = unsafe { slice(msg.data.cast(), msg.data_len) };
                out.push((msg.data as usize, d));
            }
        }
        let first = (args.num_msg > 0 && !args.msg.is_null()).then(|| {
            // SAFETY: at least one message.
            let m = unsafe { &*args.msg };
            (m.data as usize, m.data_len)
        });
        (out, args.num_msg, first)
    }
}

/// A `BIO_set_callback_ex` callback.
pub type BioCbFn = fn(&BioCbArgs<'_>) -> c_long;
static BIOCB: Mutex<Option<BioCbFn>> = Mutex::new(None);

unsafe extern "C" fn bio_tramp(
    b: *mut BIO,
    cmd: c_int,
    argp: *const c_char,
    len: usize,
    argi: c_int,
    argl: c_long,
    ret: c_int,
    processed: *mut usize,
) -> c_long {
    let (Some(f), Some(bio)) = (get(&BIOCB), BioRef::new(b)) else {
        return c_long::from(ret);
    };
    f(&BioCbArgs {
        bio,
        cmd,
        argp,
        len,
        argi,
        argl,
        ret,
        processed,
    })
}

impl Bio {
    /// `BIO_set_callback_ex(b, cb)`.
    pub fn set_callback_ex(&self, cb: BioCbFn) {
        set(&BIOCB, Some(cb));
        // SAFETY: the BIO is live; the trampoline has BIO_callback_fn_ex's type.
        unsafe { ffi::BIO_set_callback_ex(self.as_ptr(), Some(bio_tramp)) };
    }
}

// ---- cookies ----

/// Makes a cookie for a connection.
pub type CookieGenFn = fn(SslRef<'_>) -> Option<Vec<u8>>;
/// Checks a cookie.
pub type CookieVerifyFn = fn(SslRef<'_>, &[u8]) -> bool;
static COOKIE_GEN: Mutex<Option<CookieGenFn>> = Mutex::new(None);
static COOKIE_VERIFY: Mutex<Option<CookieVerifyFn>> = Mutex::new(None);

fn cookie_into(s: *mut SSL, out: *mut c_uchar, cap: usize) -> Option<usize> {
    let f = get(&COOKIE_GEN)?;
    let c = f(SslRef::new(s)?)?;
    let n = c.len().min(cap);
    // SAFETY: out is writable for cap bytes (DTLS1_COOKIE_LENGTH, the callback's contract).
    unsafe { slice_mut(out, cap) }
        .get_mut(..n)?
        .copy_from_slice(c.get(..n)?);
    Some(n)
}

unsafe extern "C" fn cookie_gen_tramp(s: *mut SSL, out: *mut c_uchar, len: *mut c_uint) -> c_int {
    match cookie_into(s, out, us(DTLS1_COOKIE_LENGTH)) {
        Some(n) => {
            // SAFETY: len is a valid out-pointer.
            unsafe { *len = c_uint::try_from(n).unwrap_or(0) };
            1
        }
        None => 0,
    }
}

unsafe extern "C" fn cookie_verify_tramp(s: *mut SSL, c: *const c_uchar, len: c_uint) -> c_int {
    let (Some(f), Some(r)) = (get(&COOKIE_VERIFY), SslRef::new(s)) else {
        return 0;
    };
    // SAFETY: c is valid for len bytes.
    c_int::from(f(r, unsafe { slice(c, us(len)) }))
}

unsafe extern "C" fn scookie_gen_tramp(s: *mut SSL, out: *mut c_uchar, len: *mut usize) -> c_int {
    match cookie_into(s, out, us(DTLS1_COOKIE_LENGTH)) {
        Some(n) => {
            // SAFETY: len is a valid out-pointer.
            unsafe { *len = n };
            1
        }
        None => 0,
    }
}

unsafe extern "C" fn scookie_verify_tramp(s: *mut SSL, c: *const c_uchar, len: usize) -> c_int {
    let (Some(f), Some(r)) = (get(&COOKIE_VERIFY), SslRef::new(s)) else {
        return 0;
    };
    // SAFETY: c is valid for len bytes.
    c_int::from(f(r, unsafe { slice(c, len) }))
}

impl CtxRef<'_> {
    /// `SSL_CTX_set_cookie_generate_cb`/`_verify_cb` and their stateless (TLS 1.3) twins.
    pub fn set_cookie_callbacks(self, gen_cb: CookieGenFn, verify: CookieVerifyFn) {
        set(&COOKIE_GEN, Some(gen_cb));
        set(&COOKIE_VERIFY, Some(verify));
        let c = self.as_ptr();
        // SAFETY: the context is live; each trampoline has its callback's type.
        unsafe { ffi::SSL_CTX_set_cookie_generate_cb(c, Some(cookie_gen_tramp)) };
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_set_cookie_verify_cb(c, Some(cookie_verify_tramp)) };
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_set_stateless_cookie_generate_cb(c, Some(scookie_gen_tramp)) };
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_set_stateless_cookie_verify_cb(c, Some(scookie_verify_tramp)) };
    }
}

// ---- certificates ----

/// A certificate callback (`SSL_CTX_set_cert_cb`).
pub type CertCbFn = fn(SslRef<'_>) -> c_int;
static CERTCB: Mutex<Option<CertCbFn>> = Mutex::new(None);

unsafe extern "C" fn cert_tramp(s: *mut SSL, _arg: *mut c_void) -> c_int {
    match (get(&CERTCB), SslRef::new(s)) {
        (Some(f), Some(r)) => f(r),
        _ => 1,
    }
}

impl CtxRef<'_> {
    /// `SSL_CTX_set_cert_cb(ctx, cb, NULL)`.
    pub fn set_cert_cb(self, cb: CertCbFn) {
        set(&CERTCB, Some(cb));
        // SAFETY: the context is live; the trampoline has the callback's type.
        unsafe { ffi::SSL_CTX_set_cert_cb(self.as_ptr(), Some(cert_tramp), core::ptr::null_mut()) };
    }
}

// ---- security ----

/// What a security callback's `other` is, by `op & SSL_SECOP_OTHER_TYPE`.
pub enum SecOther<'a> {
    None,
    Cipher(Option<CipherRef<'a>>),
    Curve,
    Cert(Option<CertRef<'a>>),
    Sigalg([u8; 2]),
}

/// One security check: the connection or context, `op`, `bits`, `nid`, `other`, and what the
/// previous (default) callback returned.
pub struct SecArgs<'a> {
    pub op: c_int,
    pub bits: c_int,
    pub nid: c_int,
    pub other: SecOther<'a>,
    pub rv: c_int,
}

/// A security callback wrapping the context's previous one.
pub type SecFn = fn(&SecArgs<'_>) -> c_int;
type RawSecCb = unsafe extern "C" fn(
    *const SSL,
    *const SSL_CTX,
    c_int,
    c_int,
    c_int,
    *mut c_void,
    *mut c_void,
) -> c_int;
static SEC: Mutex<Option<SecFn>> = Mutex::new(None);
static SEC_OLD: Mutex<Option<RawSecCb>> = Mutex::new(None);

unsafe extern "C" fn sec_tramp(
    s: *const SSL,
    ctx: *const SSL_CTX,
    op: c_int,
    bits: c_int,
    nid: c_int,
    other: *mut c_void,
    ex: *mut c_void,
) -> c_int {
    let rv = match get(&SEC_OLD) {
        // SAFETY: the previous callback, with the library's own arguments.
        Some(old) => unsafe { old(s, ctx, op, bits, nid, other, ex) },
        None => 1,
    };
    let Some(f) = get(&SEC) else { return rv };
    let o = match op & c_int::from_ne_bytes(SSL_SECOP_OTHER_TYPE.to_ne_bytes()) {
        SSL_SECOP_OTHER_CIPHER => SecOther::Cipher(CipherRef::new(other.cast())),
        SSL_SECOP_OTHER_CURVE => SecOther::Curve,
        SSL_SECOP_OTHER_CERT => SecOther::Cert(CertRef::new(other.cast())),
        SSL_SECOP_OTHER_SIGALG if !other.is_null() => {
            // SAFETY: for signature algorithms other is the 2-octet code.
            let p = unsafe { slice(other.cast(), 2) };
            SecOther::Sigalg([
                p.first().copied().unwrap_or(0),
                p.get(1).copied().unwrap_or(0),
            ])
        }
        _ => SecOther::None,
    };
    f(&SecArgs {
        op,
        bits,
        nid,
        other: o,
        rv,
    })
}

impl CtxRef<'_> {
    /// `ssl_ctx_security_debug`'s wiring: `SSL_CTX_get_security_callback` kept as the previous
    /// callback, `SSL_CTX_set_security_callback(ctx, cb)`.
    pub fn wrap_security_callback(self, cb: SecFn) {
        // SAFETY: the context is live.
        let old = unsafe { ffi::SSL_CTX_get_security_callback(self.as_ptr()) };
        set(&SEC_OLD, old);
        set(&SEC, Some(cb));
        // SAFETY: the trampoline has the callback's type.
        unsafe { ffi::SSL_CTX_set_security_callback(self.as_ptr(), Some(sec_tramp)) };
    }
}

// ---- key log ----

/// A key log callback.
pub type KeylogFn = fn(&str);
static KEYLOG: Mutex<Option<KeylogFn>> = Mutex::new(None);

unsafe extern "C" fn keylog_tramp(_s: *const SSL, line: *const c_char) {
    if let (Some(f), Some(l)) = (get(&KEYLOG), string_at(line)) {
        f(&l);
    }
}

impl CtxRef<'_> {
    /// `SSL_CTX_set_keylog_callback`.
    pub fn set_keylog_callback(self, cb: KeylogFn) {
        set(&KEYLOG, Some(cb));
        // SAFETY: the context is live; the trampoline has the callback's type.
        unsafe { ffi::SSL_CTX_set_keylog_callback(self.as_ptr(), Some(keylog_tramp)) };
    }
}

// ---- PSK ----

/// The client's PSK callback: hint, identity buffer, PSK buffer; the PSK's length (0 fails).
pub type PskClientFn = fn(SslRef<'_>, Option<&str>, &mut [u8], &mut [u8]) -> c_uint;
/// The server's PSK callback: identity, PSK buffer; the PSK's length.
pub type PskServerFn = fn(SslRef<'_>, Option<&str>, &mut [u8]) -> c_uint;
/// The server's TLS 1.3 PSK lookup: `Err` fails, `Ok(None)` finds nothing.
pub type PskFindFn = fn(SslRef<'_>, &[u8]) -> Result<Option<Session>, ()>;
/// The client's TLS 1.3 PSK: `Err` fails, `Ok(None)` offers nothing, else the session and
/// identity.
pub type PskUseFn = fn(SslRef<'_>, Option<MdRef>) -> Result<Option<(Session, Vec<u8>)>, ()>;
static PSK_CLIENT: Mutex<Option<PskClientFn>> = Mutex::new(None);
static PSK_SERVER: Mutex<Option<PskServerFn>> = Mutex::new(None);
static PSK_FIND: Mutex<Option<PskFindFn>> = Mutex::new(None);
static PSK_USE: Mutex<Option<PskUseFn>> = Mutex::new(None);
/// The identity the client offered last; it must outlive the callback.
static PSK_ID: Mutex<Option<Box<[u8]>>> = Mutex::new(None);

unsafe extern "C" fn psk_client_tramp(
    s: *mut SSL,
    hint: *const c_char,
    identity: *mut c_char,
    max_identity_len: c_uint,
    psk: *mut c_uchar,
    max_psk_len: c_uint,
) -> c_uint {
    let (Some(f), Some(r)) = (get(&PSK_CLIENT), SslRef::new(s)) else {
        return 0;
    };
    let h = string_at(hint);
    // SAFETY: identity is writable for max_identity_len bytes.
    let id = unsafe { slice_mut(identity.cast(), us(max_identity_len)) };
    // SAFETY: psk is writable for max_psk_len bytes.
    let k = unsafe { slice_mut(psk, us(max_psk_len)) };
    f(r, h.as_deref(), id, k)
}

unsafe extern "C" fn psk_server_tramp(
    s: *mut SSL,
    identity: *const c_char,
    psk: *mut c_uchar,
    max_psk_len: c_uint,
) -> c_uint {
    let (Some(f), Some(r)) = (get(&PSK_SERVER), SslRef::new(s)) else {
        return 0;
    };
    let id = string_at(identity);
    // SAFETY: psk is writable for max_psk_len bytes.
    f(r, id.as_deref(), unsafe { slice_mut(psk, us(max_psk_len)) })
}

unsafe extern "C" fn psk_find_tramp(
    s: *mut SSL,
    identity: *const c_uchar,
    identity_len: usize,
    sess: *mut *mut SSL_SESSION,
) -> c_int {
    let (Some(f), Some(r)) = (get(&PSK_FIND), SslRef::new(s)) else {
        return 0;
    };
    // SAFETY: identity is valid for identity_len bytes.
    match f(r, unsafe { slice(identity, identity_len) }) {
        Err(()) => 0,
        Ok(found) => {
            // SAFETY: sess is a valid out-pointer; the library takes the reference.
            unsafe { *sess = found.map_or(core::ptr::null_mut(), Session::into_ptr) };
            1
        }
    }
}

unsafe extern "C" fn psk_use_tramp(
    s: *mut SSL,
    md: *const EVP_MD,
    id: *mut *const c_uchar,
    idlen: *mut usize,
    sess: *mut *mut SSL_SESSION,
) -> c_int {
    let (Some(f), Some(r)) = (get(&PSK_USE), SslRef::new(s)) else {
        return 0;
    };
    match f(r, MdRef::new(md)) {
        Err(()) => 0,
        Ok(None) => {
            // SAFETY: valid out-pointers.
            unsafe { *id = core::ptr::null() };
            // SAFETY: as above.
            unsafe { *idlen = 0 };
            // SAFETY: as above.
            unsafe { *sess = core::ptr::null_mut() };
            1
        }
        Ok(Some((session, ident))) => {
            let b: Box<[u8]> = ident.into_boxed_slice();
            let (p, n) = (b.as_ptr(), b.len());
            set(&PSK_ID, Some(b));
            // SAFETY: valid out-pointers; the identity stays alive in PSK_ID until the next
            // call; the library takes the session reference.
            unsafe { *id = p };
            // SAFETY: as above.
            unsafe { *idlen = n };
            // SAFETY: as above.
            unsafe { *sess = session.into_ptr() };
            1
        }
    }
}

impl CtxRef<'_> {
    /// `SSL_CTX_set_psk_client_callback`.
    pub fn set_psk_client_callback(self, cb: PskClientFn) {
        set(&PSK_CLIENT, Some(cb));
        // SAFETY: the context is live; the trampoline has the callback's type.
        unsafe { ffi::SSL_CTX_set_psk_client_callback(self.as_ptr(), Some(psk_client_tramp)) };
    }
    /// `SSL_CTX_set_psk_server_callback`.
    pub fn set_psk_server_callback(self, cb: PskServerFn) {
        set(&PSK_SERVER, Some(cb));
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_set_psk_server_callback(self.as_ptr(), Some(psk_server_tramp)) };
    }
    /// `SSL_CTX_set_psk_find_session_callback`.
    pub fn set_psk_find_session_callback(self, cb: PskFindFn) {
        set(&PSK_FIND, Some(cb));
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_set_psk_find_session_callback(self.as_ptr(), Some(psk_find_tramp)) };
    }
    /// `SSL_CTX_set_psk_use_session_callback`.
    pub fn set_psk_use_session_callback(self, cb: PskUseFn) {
        set(&PSK_USE, Some(cb));
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_set_psk_use_session_callback(self.as_ptr(), Some(psk_use_tramp)) };
    }
}

// ---- server name, NPN, ALPN ----

/// A server name callback: sets `*ad`, returns `SSL_TLSEXT_ERR_*`.
pub type ServernameFn = fn(SslRef<'_>, &mut c_int) -> c_int;
static SERVERNAME: Mutex<Option<ServernameFn>> = Mutex::new(None);

unsafe extern "C" fn servername_tramp(s: *mut SSL, ad: *mut c_int, _arg: *mut c_void) -> c_int {
    let (Some(f), Some(r)) = (get(&SERVERNAME), SslRef::new(s)) else {
        return SSL_TLSEXT_ERR_OK;
    };
    let mut a = if ad.is_null() {
        0
    } else {
        // SAFETY: ad is valid during the callback.
        unsafe { *ad }
    };
    let ret = f(r, &mut a);
    if !ad.is_null() {
        // SAFETY: as above.
        unsafe { *ad = a };
    }
    ret
}

impl CtxRef<'_> {
    /// `SSL_CTX_set_tlsext_servername_callback` (the argument unused).
    pub fn set_servername_callback(self, cb: ServernameFn) {
        set(&SERVERNAME, Some(cb));
        type T = unsafe extern "C" fn(*mut SSL, *mut c_int, *mut c_void) -> c_int;
        // SAFETY: the context is live; the command's type is the trampoline's.
        unsafe {
            ffi::SSL_CTX_callback_ctrl(
                self.as_ptr(),
                SSL_CTRL_SET_TLSEXT_SERVERNAME_CB,
                transmute_cb::<T>(servername_tramp),
            )
        };
    }
}

/// The client's NPN list (wire format), the selection's status, and the printer of the
/// server's list.
static NPN_CLIENT: Mutex<Option<Box<[u8]>>> = Mutex::new(None);
static NPN_STATUS: Mutex<Option<c_int>> = Mutex::new(None);
/// Called with the server's protocols before the selection.
pub type NpnSelectFn = fn(SslRef<'_>, &[u8]);
static NPN_SELECT: Mutex<Option<NpnSelectFn>> = Mutex::new(None);

unsafe extern "C" fn npn_select_tramp(
    s: *mut SSL,
    out: *mut *mut c_uchar,
    outlen: *mut c_uchar,
    in_: *const c_uchar,
    inlen: c_uint,
    _arg: *mut c_void,
) -> c_int {
    if let (Some(f), Some(r)) = (get(&NPN_SELECT), SslRef::new(s)) {
        // SAFETY: in_ is valid for inlen bytes.
        f(r, unsafe { slice(in_, us(inlen)) });
    }
    let guard = NPN_CLIENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (p, n) = guard
        .as_ref()
        .map_or((core::ptr::null(), 0), |b| (b.as_ptr(), b.len()));
    // SAFETY: the lists are valid for their lengths; the client's list stays alive in
    // NPN_CLIENT (never replaced while connected), so *out may point into it.
    let st = unsafe {
        ffi::SSL_select_next_proto(out, outlen, in_, inlen, p, c_uint::try_from(n).unwrap_or(0))
    };
    drop(guard);
    set(&NPN_STATUS, Some(st));
    SSL_TLSEXT_ERR_OK
}

impl CtxRef<'_> {
    /// `SSL_CTX_set_next_proto_select_cb` with the client's list.
    pub fn set_next_proto_select_cb(self, protos: Vec<u8>, cb: NpnSelectFn) {
        set(&NPN_CLIENT, Some(protos.into_boxed_slice()));
        set(&NPN_SELECT, Some(cb));
        // SAFETY: the context is live; the trampoline has the callback's type.
        unsafe {
            ffi::SSL_CTX_set_next_proto_select_cb(
                self.as_ptr(),
                Some(npn_select_tramp),
                core::ptr::null_mut(),
            )
        };
    }
}

/// The NPN selection's status (`next_proto.status`), once the callback ran.
pub fn next_proto_status() -> Option<c_int> {
    get(&NPN_STATUS)
}

static NPN_SERVER: Mutex<Option<Box<[u8]>>> = Mutex::new(None);

unsafe extern "C" fn npn_adv_tramp(
    _s: *mut SSL,
    data: *mut *const c_uchar,
    len: *mut c_uint,
    _arg: *mut c_void,
) -> c_int {
    let guard = NPN_SERVER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (p, n) = guard
        .as_ref()
        .map_or((core::ptr::null(), 0), |b| (b.as_ptr(), b.len()));
    // SAFETY: valid out-pointers; the list stays alive in NPN_SERVER.
    unsafe { *data = p };
    // SAFETY: as above.
    unsafe { *len = c_uint::try_from(n).unwrap_or(0) };
    SSL_TLSEXT_ERR_OK
}

impl CtxRef<'_> {
    /// `SSL_CTX_set_next_protos_advertised_cb` with the server's list.
    pub fn set_next_protos_advertised(self, protos: Vec<u8>) {
        set(&NPN_SERVER, Some(protos.into_boxed_slice()));
        // SAFETY: the context is live; the trampoline has the callback's type.
        unsafe {
            ffi::SSL_CTX_set_next_protos_advertised_cb(
                self.as_ptr(),
                Some(npn_adv_tramp),
                core::ptr::null_mut(),
            )
        };
    }
}

/// The ALPN select callback's printer: called with the client's list, then (if the selection
/// succeeded) with the selected protocol.
pub type AlpnFn = fn(SslRef<'_>, &[u8], Option<&[u8]>);
static ALPN: Mutex<Option<AlpnFn>> = Mutex::new(None);
static ALPN_SERVER: Mutex<Option<Box<[u8]>>> = Mutex::new(None);

unsafe extern "C" fn alpn_tramp(
    s: *mut SSL,
    out: *mut *const c_uchar,
    outlen: *mut c_uchar,
    in_: *const c_uchar,
    inlen: c_uint,
    _arg: *mut c_void,
) -> c_int {
    let f = get(&ALPN);
    let r = SslRef::new(s);
    // SAFETY: in_ is valid for inlen bytes.
    let input = unsafe { slice(in_, us(inlen)) };
    if let (Some(f), Some(r)) = (f, r) {
        f(r, input, None);
    }
    let guard = ALPN_SERVER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (p, n) = guard
        .as_ref()
        .map_or((core::ptr::null(), 0), |b| (b.as_ptr(), b.len()));
    // SAFETY: the lists are valid; the server's list stays alive in ALPN_SERVER.
    let st = unsafe {
        ffi::SSL_select_next_proto(
            out.cast(),
            outlen,
            p,
            c_uint::try_from(n).unwrap_or(0),
            in_,
            inlen,
        )
    };
    drop(guard);
    if st != OPENSSL_NPN_NEGOTIATED {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    if let (Some(f), Some(r)) = (f, r) {
        // SAFETY: valid out-pointers, set by the selection.
        let o = unsafe { *out };
        // SAFETY: as above.
        let ol = unsafe { *outlen };
        // SAFETY: o points to ol bytes of one of the lists.
        let sel = unsafe { slice(o, us(ol)) };
        f(r, input, Some(sel));
    }
    SSL_TLSEXT_ERR_OK
}

impl CtxRef<'_> {
    /// `SSL_CTX_set_alpn_select_cb` with the server's list.
    pub fn set_alpn_select_cb(self, protos: Vec<u8>, cb: AlpnFn) {
        set(&ALPN_SERVER, Some(protos.into_boxed_slice()));
        set(&ALPN, Some(cb));
        // SAFETY: the context is live; the trampoline has the callback's type.
        unsafe {
            ffi::SSL_CTX_set_alpn_select_cb(self.as_ptr(), Some(alpn_tramp), core::ptr::null_mut())
        };
    }
}

// ---- status (OCSP) ----

/// A certificate status callback (`SSL_CTX_set_tlsext_status_cb`).
pub type StatusFn = fn(SslRef<'_>) -> c_int;
static STATUS: Mutex<Option<StatusFn>> = Mutex::new(None);

unsafe extern "C" fn status_tramp(s: *mut SSL, _arg: *mut c_void) -> c_int {
    match (get(&STATUS), SslRef::new(s)) {
        (Some(f), Some(r)) => f(r),
        _ => 1,
    }
}

impl CtxRef<'_> {
    /// `SSL_CTX_set_tlsext_status_cb` (the argument unused).
    pub fn set_tlsext_status_cb(self, cb: StatusFn) {
        set(&STATUS, Some(cb));
        type T = unsafe extern "C" fn(*mut SSL, *mut c_void) -> c_int;
        // SAFETY: the context is live; the command's type is the trampoline's.
        unsafe {
            ffi::SSL_CTX_callback_ctrl(
                self.as_ptr(),
                SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB,
                transmute_cb::<T>(status_tramp),
            )
        };
    }
}

// ---- sessions ----

/// A new-session callback (`SSL_CTX_sess_set_new_cb`): 1 keeps the reference.
pub type NewSessFn = fn(SslRef<'_>, SessionRef<'_>) -> c_int;
/// A session lookup (`SSL_CTX_sess_set_get_cb`).
pub type GetSessFn = fn(SslRef<'_>, &[u8]) -> Option<Session>;
/// A session removal (`SSL_CTX_sess_set_remove_cb`).
pub type RemoveSessFn = fn(SessionRef<'_>);
static NEW_SESS: Mutex<Option<NewSessFn>> = Mutex::new(None);
static GET_SESS: Mutex<Option<GetSessFn>> = Mutex::new(None);
static REMOVE_SESS: Mutex<Option<RemoveSessFn>> = Mutex::new(None);

unsafe extern "C" fn new_sess_tramp(s: *mut SSL, sess: *mut SSL_SESSION) -> c_int {
    match (get(&NEW_SESS), SslRef::new(s), SessionRef::new(sess)) {
        (Some(f), Some(r), Some(x)) => f(r, x),
        _ => 0,
    }
}

unsafe extern "C" fn get_sess_tramp(
    s: *mut SSL,
    id: *const c_uchar,
    len: c_int,
    copy: *mut c_int,
) -> *mut SSL_SESSION {
    if !copy.is_null() {
        // SAFETY: copy is a valid out-pointer.
        unsafe { *copy = 0 };
    }
    match (get(&GET_SESS), SslRef::new(s)) {
        (Some(f), Some(r)) => {
            // SAFETY: id is valid for len bytes; the library takes the reference.
            f(r, unsafe { slice(id, us(len)) }).map_or(core::ptr::null_mut(), Session::into_ptr)
        }
        _ => core::ptr::null_mut(),
    }
}

unsafe extern "C" fn remove_sess_tramp(_ctx: *mut SSL_CTX, sess: *mut SSL_SESSION) {
    if let (Some(f), Some(x)) = (get(&REMOVE_SESS), SessionRef::new(sess)) {
        f(x);
    }
}

impl CtxRef<'_> {
    /// `SSL_CTX_sess_set_new_cb`.
    pub fn sess_set_new_cb(self, cb: NewSessFn) {
        set(&NEW_SESS, Some(cb));
        // SAFETY: the context is live; the trampoline has the callback's type.
        unsafe { ffi::SSL_CTX_sess_set_new_cb(self.as_ptr(), Some(new_sess_tramp)) };
    }
    /// `SSL_CTX_sess_set_get_cb`.
    pub fn sess_set_get_cb(self, cb: GetSessFn) {
        set(&GET_SESS, Some(cb));
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_sess_set_get_cb(self.as_ptr(), Some(get_sess_tramp)) };
    }
    /// `SSL_CTX_sess_set_remove_cb`.
    pub fn sess_set_remove_cb(self, cb: RemoveSessFn) {
        set(&REMOVE_SESS, Some(cb));
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_sess_set_remove_cb(self.as_ptr(), Some(remove_sess_tramp)) };
    }
}

/// A session ID generator (`SSL_CTX_set_generate_session_id`).
pub type GenIdFn = fn(SslRef<'_>, &mut [u8]) -> c_int;
static GEN_ID: Mutex<Option<GenIdFn>> = Mutex::new(None);

unsafe extern "C" fn gen_id_tramp(s: *mut SSL, id: *mut c_uchar, len: *mut c_uint) -> c_int {
    let (Some(f), Some(r)) = (get(&GEN_ID), SslRef::new(s)) else {
        return 0;
    };
    if len.is_null() {
        return 0;
    }
    // SAFETY: len is valid.
    let n = unsafe { *len };
    // SAFETY: id is writable for n bytes.
    f(r, unsafe { slice_mut(id, us(n)) })
}

impl CtxRef<'_> {
    /// `SSL_CTX_set_generate_session_id`.
    pub fn set_generate_session_id(self, cb: GenIdFn) -> bool {
        set(&GEN_ID, Some(cb));
        // SAFETY: the context is live; the trampoline has GEN_SESSION_CB's type.
        unsafe { ffi::SSL_CTX_set_generate_session_id(self.as_ptr(), Some(gen_id_tramp)) == 1 }
    }
}

/// A not-resumable callback.
pub type NotResumableFn = fn(SslRef<'_>, c_int) -> c_int;
static NOT_RESUMABLE: Mutex<Option<NotResumableFn>> = Mutex::new(None);

unsafe extern "C" fn not_resumable_tramp(s: *mut SSL, fs: c_int) -> c_int {
    match (get(&NOT_RESUMABLE), SslRef::new(s)) {
        (Some(f), Some(r)) => f(r, fs),
        _ => 0,
    }
}

impl CtxRef<'_> {
    /// `SSL_CTX_set_not_resumable_session_callback`.
    pub fn set_not_resumable_session_callback(self, cb: NotResumableFn) {
        set(&NOT_RESUMABLE, Some(cb));
        // SAFETY: the context is live; the trampoline has the callback's type.
        unsafe {
            ffi::SSL_CTX_set_not_resumable_session_callback(
                self.as_ptr(),
                Some(not_resumable_tramp),
            )
        };
    }
}

// ---- custom extensions ----

/// A client custom extension's parse callback: type and data.
pub type ExtParseFn = fn(SslRef<'_>, c_uint, &[u8]) -> c_int;
static EXT_PARSE: Mutex<Option<ExtParseFn>> = Mutex::new(None);

unsafe extern "C" fn ext_parse_tramp(
    s: *mut SSL,
    ext_type: c_uint,
    in_: *const c_uchar,
    inlen: usize,
    _al: *mut c_int,
    _arg: *mut c_void,
) -> c_int {
    match (get(&EXT_PARSE), SslRef::new(s)) {
        // SAFETY: in_ is valid for inlen bytes.
        (Some(f), Some(r)) => f(r, ext_type, unsafe { slice(in_, inlen) }),
        _ => 1,
    }
}

impl CtxRef<'_> {
    /// `SSL_CTX_add_client_custom_ext(ctx, type, NULL, NULL, NULL, cb, NULL)`.
    pub fn add_client_custom_ext(self, ext_type: c_uint, cb: ExtParseFn) -> bool {
        set(&EXT_PARSE, Some(cb));
        // SAFETY: the context is live; the trampoline has custom_ext_parse_cb's type.
        unsafe {
            ffi::SSL_CTX_add_client_custom_ext(
                self.as_ptr(),
                ext_type,
                None,
                None,
                core::ptr::null_mut(),
                Some(ext_parse_tramp),
                core::ptr::null_mut(),
            ) == 1
        }
    }
}

// ---- SRP ----

/// The SRP client's password callback.
pub type SrpPwdFn = fn(SslRef<'_>) -> Option<String>;
/// The SRP client's parameter check.
pub type SrpVerifyFn = fn(SslRef<'_>) -> c_int;
/// The SRP server's user lookup: sets `*ad`.
pub type SrpUserFn = fn(SslRef<'_>, &mut c_int) -> c_int;
static SRP_PWD: Mutex<Option<SrpPwdFn>> = Mutex::new(None);
static SRP_VERIFY: Mutex<Option<SrpVerifyFn>> = Mutex::new(None);
static SRP_USER: Mutex<Option<SrpUserFn>> = Mutex::new(None);

unsafe extern "C" fn srp_pwd_tramp(s: *mut SSL, _arg: *mut c_void) -> *mut c_char {
    match (get(&SRP_PWD), SslRef::new(s)) {
        // The library frees the password with OPENSSL_free.
        (Some(f), Some(r)) => f(r).map_or(core::ptr::null_mut(), |p| crate::ssl::c_strdup(&p)),
        _ => core::ptr::null_mut(),
    }
}

unsafe extern "C" fn srp_verify_tramp(s: *mut SSL, _arg: *mut c_void) -> c_int {
    match (get(&SRP_VERIFY), SslRef::new(s)) {
        (Some(f), Some(r)) => f(r),
        _ => 0,
    }
}

unsafe extern "C" fn srp_user_tramp(s: *mut SSL, ad: *mut c_int, _arg: *mut c_void) -> c_int {
    let (Some(f), Some(r)) = (get(&SRP_USER), SslRef::new(s)) else {
        return SSL3_AL_FATAL;
    };
    let mut a = if ad.is_null() {
        0
    } else {
        // SAFETY: ad is valid during the callback.
        unsafe { *ad }
    };
    let ret = f(r, &mut a);
    if !ad.is_null() {
        // SAFETY: as above.
        unsafe { *ad = a };
    }
    ret
}

impl CtxRef<'_> {
    /// `SSL_CTX_set_srp_client_pwd_callback`.
    pub fn set_srp_client_pwd_callback(self, cb: SrpPwdFn) {
        set(&SRP_PWD, Some(cb));
        // SAFETY: the context is live; the trampoline has the callback's type.
        unsafe { ffi::SSL_CTX_set_srp_client_pwd_callback(self.as_ptr(), Some(srp_pwd_tramp)) };
    }
    /// `SSL_CTX_set_srp_verify_param_callback`.
    pub fn set_srp_verify_param_callback(self, cb: SrpVerifyFn) {
        set(&SRP_VERIFY, Some(cb));
        // SAFETY: as above.
        unsafe {
            ffi::SSL_CTX_set_srp_verify_param_callback(self.as_ptr(), Some(srp_verify_tramp))
        };
    }
    /// `SSL_CTX_set_srp_username_callback`.
    pub fn set_srp_username_callback(self, cb: SrpUserFn) {
        set(&SRP_USER, Some(cb));
        // SAFETY: as above.
        unsafe { ffi::SSL_CTX_set_srp_username_callback(self.as_ptr(), Some(srp_user_tramp)) };
    }
}
