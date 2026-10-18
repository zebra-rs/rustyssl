//! Cipher lists and `SSL_CIPHER` objects (`ssl_ciph.c`, the cipher parts of `ssl_lib.c`).
//!
//! An `SSL_CIPHER *` is the address of an entry of the TLS core's static suite table
//! (`rustyssl_tls::suites`), so pointers are stable and compare equal as OpenSSL's do. A pointer
//! coming back from C is mapped to its entry by searching the table for it, never by reading
//! through it. Lists are `STACK_OF(SSL_CIPHER)`s the `SSL_CTX` or `SSL` owns, as OpenSSL's are:
//! `SSL_get_ciphers` returns the object's own stack.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    DTLS_ANY_VERSION, DTLS1_2_VERSION, DTLS1_BAD_VER, DTLS1_VERSION, ERR_LIB_SSL, ERR_R_CRYPTO_LIB,
    EVP_MD, NID_undef, OPENSSL_STACK, OSSL_CIPHER_PARAM_DECRYPT_ONLY, OSSL_LIB_CTX, SSL,
    SSL_CIPHER, SSL_CTX, SSL_METHOD, SSL_R_AT_LEAST_TLS_1_2_NEEDED_IN_SUITEB_MODE,
    SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST, SSL_R_LIBRARY_HAS_NO_CIPHERS, SSL_R_NO_CIPHER_MATCH,
    SSL_R_NO_CIPHERS_SPECIFIED, SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS, SSL3_VERSION, TLS_ANY_VERSION,
    TLS1_1_VERSION, TLS1_2_VERSION, TLS1_3_VERSION, TLS1_VERSION, stack_st_SSL_CIPHER,
};
use rustyssl_tls::cipherstring::{self, Available, CertSettings, Offers};
use rustyssl_tls::suites::{self, Cipher};

use super::cert::Cert;
use super::ctx;
use super::method::{Method, method_of};
use crate::err::{self, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_params};
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free};
use crate::evp::exchange::{EVP_KEYEXCH_fetch, EVP_KEYEXCH_free};
use crate::evp::legacy_md::EVP_get_digestbyname;
use crate::evp::pkey::ameth::{EVP_PKEY_asn1_find_str, EVP_PKEY_asn1_get0_info};
use crate::evp::signature::{EVP_SIGNATURE_fetch, EVP_SIGNATURE_free};
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::OBJ_nid2sn;
use crate::params::{OSSL_PARAM_construct_end, OSSL_PARAM_construct_int};
use crate::stack::{
    OPENSSL_sk_dup, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push,
    OPENSSL_sk_set_cmp_func, OPENSSL_sk_sort, OPENSSL_sk_value,
};

/// The `SSL_CIPHER *` of a suite.
pub(crate) fn cipher_ptr(c: &'static Cipher) -> *const SSL_CIPHER {
    ptr::from_ref(c).cast()
}

/// The suite an `SSL_CIPHER *` points to, if it is one of ours.
pub(crate) fn cipher_of(p: *const SSL_CIPHER) -> Option<&'static Cipher> {
    if p.is_null() {
        return None;
    }
    suites::all().find(|c| ptr::eq(cipher_ptr(c), p))
}

/// An owned `STACK_OF(SSL_CIPHER)` (its entries are static), or NULL.
#[derive(Debug)]
pub(crate) struct CipherStack(pub(crate) *mut OPENSSL_STACK);

impl CipherStack {
    /// No stack.
    pub(crate) const NONE: Self = Self(ptr::null_mut());

    /// A stack of `list`, or `None` if it couldn't be made.
    pub(crate) fn of(list: &[&'static Cipher]) -> Option<Self> {
        // SAFETY: no preconditions.
        let st = Self(unsafe { OPENSSL_sk_new_null() });
        if st.0.is_null() {
            return None;
        }
        for &c in list {
            // SAFETY: the stack made above; a static entry.
            if unsafe { OPENSSL_sk_push(st.0, cipher_ptr(c).cast()) } == 0 {
                return None;
            }
        }
        Some(st)
    }

    /// A copy of the stack (`sk_SSL_CIPHER_dup`), or `None`.
    pub(crate) fn dup(&self) -> Option<Self> {
        if self.0.is_null() {
            return Some(Self::NONE);
        }
        // SAFETY: our own stack.
        let d = unsafe { OPENSSL_sk_dup(self.0) };
        if d.is_null() { None } else { Some(Self(d)) }
    }

    /// The suites in the stack.
    pub(crate) fn ciphers(&self) -> Vec<&'static Cipher> {
        ciphers_of(self.0)
    }

    /// Whether there is a stack.
    pub(crate) fn is_null(&self) -> bool {
        self.0.is_null()
    }

    /// The stack as C sees it.
    pub(crate) fn as_ptr(&self) -> *mut stack_st_SSL_CIPHER {
        self.0.cast()
    }

    /// The stack, given away (the caller frees it).
    pub(crate) fn into_raw(self) -> *mut stack_st_SSL_CIPHER {
        let p = self.0.cast();
        core::mem::forget(self);
        p
    }
}

impl Drop for CipherStack {
    fn drop(&mut self) {
        // SAFETY: our own stack, or NULL; its entries are static.
        unsafe { OPENSSL_sk_free(self.0) };
    }
}

// SAFETY: the stack is owned and used under its owner's lock; its entries are static.
unsafe impl Send for CipherStack {}

/// The suites of a `STACK_OF(SSL_CIPHER)` (entries not ours are skipped).
///
/// The stack is NULL or a live stack.
fn ciphers_of(st: *const OPENSSL_STACK) -> Vec<&'static Cipher> {
    // SAFETY: NULL or a live stack (-1 for NULL).
    let n = unsafe { OPENSSL_sk_num(st) };
    (0..n)
        .filter_map(|i| {
            // SAFETY: an index in range.
            let p = unsafe { OPENSSL_sk_value(st, i) };
            cipher_of(p.cast())
        })
        .collect()
}

/// A context's or connection's lists (`cipher_list`, `cipher_list_by_id`,
/// `tls13_ciphersuites`), and the peer's list a server received (`peer_ciphers`, which the
/// handshake fills).
#[derive(Debug)]
pub(crate) struct CipherLists {
    /// The preference-ordered list, or NULL (a connection's until it sets its own).
    pub(crate) list: CipherStack,
    /// The same, sorted by id.
    pub(crate) by_id: CipherStack,
    /// The TLS 1.3 suites (`set_ciphersuites`).
    pub(crate) tls13: CipherStack,
    /// The client's suites, on a server after the ClientHello.
    pub(crate) peer: CipherStack,
}

impl CipherLists {
    /// No lists.
    pub(crate) const fn none() -> Self {
        Self {
            list: CipherStack::NONE,
            by_id: CipherStack::NONE,
            tls13: CipherStack::NONE,
            peer: CipherStack::NONE,
        }
    }

    /// A connection's lists from its context's (`SSL_new`): its own copy of the TLS 1.3 suites,
    /// no list of its own (the context's is used).
    pub(crate) fn for_ssl(ctx: &Self) -> Option<Self> {
        Some(Self {
            list: CipherStack::NONE,
            by_id: CipherStack::NONE,
            tls13: ctx.tls13.dup()?,
            peer: CipherStack::NONE,
        })
    }
}

/// `ssl_cipher_ptr_id_cmp`: the by-id list's order.
///
/// # Safety
/// `a` and `b` point to stack entries.
unsafe extern "C" fn id_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the stack's comparison hands pointers to its entries.
    let pa = unsafe { a.cast::<*const SSL_CIPHER>().read() };
    // SAFETY: as above.
    let pb = unsafe { b.cast::<*const SSL_CIPHER>().read() };
    let ia = cipher_of(pa).map_or(0, |c| c.id);
    let ib = cipher_of(pb).map_or(0, |c| c.id);
    match ia.cmp(&ib) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// `update_cipher_list_by_id`: the list sorted by id, with the comparison set.
fn by_id_of(list: &CipherStack) -> Option<CipherStack> {
    let d = list.dup()?;
    // SAFETY: the copy made above; a comparison over its entries.
    unsafe { OPENSSL_sk_set_cmp_func(d.0, Some(id_cmp)) };
    // SAFETY: as above.
    unsafe { OPENSSL_sk_sort(d.0) };
    Some(d)
}

/// What a library context's providers offer, as `ssl_load_ciphers` fetches it.
struct ProviderOffers {
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
}

impl ProviderOffers {
    /// A NID's short name.
    fn sn(nid: c_int) -> *const c_char {
        // SAFETY: any NID.
        unsafe { OBJ_nid2sn(nid) }
    }
}

impl Offers for ProviderOffers {
    /// `ssl_evp_cipher_fetch`: fetchable, and not decrypt-only.
    fn cipher(&self, nid: c_int) -> bool {
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        // SAFETY: the library context; the name (NULL fetches nothing); the property query.
        let c = unsafe { EVP_CIPHER_fetch(self.libctx, Self::sn(nid), self.propq) };
        let mut ok = !c.is_null();
        if ok {
            let mut decrypt_only: c_int = 0;
            // SAFETY: a static key; the flag, which outlives the call below.
            let mut params = [
                unsafe {
                    OSSL_PARAM_construct_int(
                        OSSL_CIPHER_PARAM_DECRYPT_ONLY.as_ptr(),
                        &raw mut decrypt_only,
                    )
                },
                // SAFETY: no preconditions.
                unsafe { OSSL_PARAM_construct_end() },
            ];
            // SAFETY: the cipher; the terminated parameters.
            if unsafe { EVP_CIPHER_get_params(c, params.as_mut_ptr()) } != 0 && decrypt_only != 0 {
                ok = false;
            }
        }
        // SAFETY: fetched above, or NULL.
        unsafe { EVP_CIPHER_free(c) };
        // SAFETY: no preconditions.
        unsafe { ERR_pop_to_mark() };
        ok
    }

    /// `ssl_evp_md_fetch`.
    fn digest(&self, nid: c_int) -> bool {
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        // SAFETY: as above.
        let md = unsafe { EVP_MD_fetch(self.libctx, Self::sn(nid), self.propq) };
        let ok = !md.is_null();
        // SAFETY: fetched above, or NULL.
        unsafe { EVP_MD_free(md) };
        // SAFETY: no preconditions.
        unsafe { ERR_pop_to_mark() };
        ok
    }

    fn signature(&self, name: &str) -> bool {
        let Ok(n) = std::ffi::CString::new(name) else {
            return false;
        };
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        // SAFETY: the library context; the name; the property query.
        let s = unsafe { EVP_SIGNATURE_fetch(self.libctx, n.as_ptr(), self.propq) };
        let ok = !s.is_null();
        // SAFETY: fetched above, or NULL.
        unsafe { EVP_SIGNATURE_free(s) };
        // SAFETY: no preconditions.
        unsafe { ERR_pop_to_mark() };
        ok
    }

    fn key_exchange(&self, name: &str) -> bool {
        let Ok(n) = std::ffi::CString::new(name) else {
            return false;
        };
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        // SAFETY: the library context; the name; the property query.
        let k = unsafe { EVP_KEYEXCH_fetch(self.libctx, n.as_ptr(), self.propq) };
        let ok = !k.is_null();
        // SAFETY: fetched above, or NULL.
        unsafe { EVP_KEYEXCH_free(k) };
        // SAFETY: no preconditions.
        unsafe { ERR_pop_to_mark() };
        ok
    }

    /// `get_optional_pkey_id`: a legacy public key method by name.
    fn pkey(&self, nid: c_int) -> bool {
        let mut eng = ptr::null_mut();
        // SAFETY: the slot for an engine (none exist); the name, NUL-terminated, or NULL.
        let ameth = unsafe { EVP_PKEY_asn1_find_str(&raw mut eng, Self::sn(nid), -1) };
        if ameth.is_null() {
            return false;
        }
        let mut id: c_int = 0;
        // SAFETY: the method found; one slot asked for.
        let ok = unsafe {
            EVP_PKEY_asn1_get0_info(
                &raw mut id,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ameth,
            )
        } > 0;
        ok && id != 0
    }
}

/// `ssl_load_ciphers`'s masks for a library context and property query.
///
/// # Safety
/// `libctx` is NULL or live; `propq` NULL or a NUL-terminated string.
pub(crate) unsafe fn available(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> Available {
    Available::from_offers(&ProviderOffers { libctx, propq })
}

/// The cipher-list builder's view of a method.
fn method_kind(m: &Method) -> cipherstring::Method {
    cipherstring::Method {
        dtls: m.dtls,
        tls12_ciphers: matches!(
            m.version,
            TLS_ANY_VERSION | TLS1_2_VERSION | DTLS_ANY_VERSION | DTLS1_2_VERSION
        ),
    }
}

/// The function OpenSSL names when it raises `reason` while building a list.
fn build_function(reason: c_int) -> &'static str {
    if reason == SSL_R_AT_LEAST_TLS_1_2_NEEDED_IN_SUITEB_MODE {
        "check_suiteb_cipher_list"
    } else {
        "ssl_cipher_process_rulestr"
    }
}

/// `ssl_create_cipher_list`: builds `rule` into `lists` (the TLS 1.3 suites first; unusable
/// ones are also deleted from `lists.tls13`), changing `cert`'s level and Suite B flags as
/// the string says even if it then fails. Returns the new list's TLS 1.2-and-earlier count, or
/// `None` on failure (errors raised, lists unchanged).
fn create(
    available: &Available,
    method: &Method,
    lists: &mut CipherLists,
    rule: &CStr,
    cert: &mut Cert,
) -> Option<usize> {
    let mut tls13 = lists.tls13.ciphers();
    let mut settings = CertSettings {
        sec_level: cert.sec_level,
        cert_flags: cert.cert_flags,
    };
    let rule = rule.to_str().ok();
    let r = match rule {
        Some(r) => {
            cipherstring::build(available, method_kind(method), &mut tls13, r, &mut settings)
        }
        // OpenSSL works on bytes; a non-UTF-8 rule has characters no rule may contain.
        None => Err(cipherstring::ParseError {
            raised: vec![rustyssl_abi::SSL_R_INVALID_COMMAND],
        }),
    };
    cert.sec_level = settings.sec_level;
    cert.cert_flags = settings.cert_flags;
    let list = match r {
        Ok(l) => l,
        Err(e) => {
            for reason in e.raised {
                err::raise(ERR_LIB_SSL, reason, build_function(reason));
            }
            return None;
        }
    };
    // The unusable TLS 1.3 suites go from the TLS 1.3 list too.
    let tls13_kept = CipherStack::of(&tls13)?;
    let stack = CipherStack::of(&list)?;
    let by_id = by_id_of(&stack)?;
    lists.tls13 = tls13_kept;
    lists.by_id = by_id;
    lists.list = stack;
    Some(cipherstring::count_tls12(&list))
}

/// `set_ciphersuites`: the TLS 1.3 suites named in `s`.
fn set_ciphersuites(lists: &mut CipherLists, s: &CStr) -> bool {
    let parsed = match s.to_str() {
        Ok(v) => cipherstring::parse_ciphersuites(v),
        Err(_) => Err(rustyssl_tls::error::Error::quiet(SSL_R_NO_CIPHER_MATCH)),
    };
    match parsed {
        Ok(v) => match CipherStack::of(&v) {
            Some(st) => {
                lists.tls13 = st;
                true
            }
            None => false,
        },
        Err(_) => {
            err::raise(ERR_LIB_SSL, SSL_R_NO_CIPHER_MATCH, "set_ciphersuites");
            false
        }
    }
}

/// `update_cipher_list`: the list with its leading TLS 1.3 suites replaced by the usable ones
/// of `lists.tls13`.
fn update(available: &Available, lists: &mut CipherLists) -> bool {
    let list =
        cipherstring::replace_tls13(available, &lists.list.ciphers(), &lists.tls13.ciphers());
    let Some(stack) = CipherStack::of(&list) else {
        return false;
    };
    let Some(by_id) = by_id_of(&stack) else {
        return false;
    };
    lists.by_id = by_id;
    lists.list = stack;
    true
}

/// A new context's lists (`SSL_CTX_new_ex`): the default TLS 1.3 suites, then the default list.
/// `None` (with `SSL_R_LIBRARY_HAS_NO_CIPHERS` raised) if nothing usable remains.
pub(crate) fn new_ctx_lists(
    available: &Available,
    method: &Method,
    cert: &mut Cert,
) -> Option<CipherLists> {
    let mut lists = CipherLists::none();
    if !set_ciphersuites(&mut lists, cipherstring::DEFAULT_CIPHERSUITES) {
        err::raise(ERR_LIB_SSL, rustyssl_abi::ERR_R_SSL_LIB, "SSL_CTX_new_ex");
        return None;
    }
    if create(
        available,
        method,
        &mut lists,
        cipherstring::DEFAULT_CIPHER_LIST,
        cert,
    )
    .is_none()
        || lists.list.ciphers().is_empty()
    {
        err::raise(ERR_LIB_SSL, SSL_R_LIBRARY_HAS_NO_CIPHERS, "SSL_CTX_new_ex");
        return None;
    }
    Some(lists)
}

/// A C string argument, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or NUL-terminated.
unsafe fn cstr<'a>(s: *const c_char) -> Option<&'a CStr> {
    if s.is_null() {
        None
    } else {
        // SAFETY: the caller's guarantee.
        Some(unsafe { CStr::from_ptr(s) })
    }
}

ffi_export! {
    /// Sets the context's cipher list from a cipher string: 1, or 0. As in OpenSSL, a string
    /// matching no TLS 1.2-and-earlier suite still installs the (TLS 1.3-only or empty) list,
    /// then fails with `SSL_R_NO_CIPHER_MATCH`.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `str_` NULL or NUL-terminated.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_cipher_list(c: *mut SSL_CTX, str_: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(rule)) = (unsafe { ctx::ctx(c) }, unsafe { cstr(str_) }) else { return 0 };
        let mut st = x.state();
        let (available, method) = (st.available, st.method);
        let s = &mut *st;
        let Some(n) = create(&available, method, &mut s.ciphers, rule, &mut s.cert) else { return 0 };
        drop(st);
        if n == 0 {
            err::raise(ERR_LIB_SSL, SSL_R_NO_CIPHER_MATCH, "SSL_CTX_set_cipher_list");
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Sets the connection's own cipher list from a cipher string (with its context's method
    /// and algorithms): 1, or 0, as for the context.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `str_` NULL or NUL-terminated.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_cipher_list(s: *mut SSL, str_: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(rule)) = (unsafe { super::conn::ssl(s) }, unsafe { cstr(str_) }) else { return 0 };
        let c = x.state().ctx;
        // SAFETY: the connection's context, which it holds a reference to.
        let Some(cx) = (unsafe { ctx::ctx(c) }) else { return 0 };
        let (available, method) = {
            let cs = cx.state();
            (cs.available, cs.method)
        };
        let mut st = x.state();
        let sst = &mut *st;
        let Some(n) = create(&available, method, &mut sst.ciphers, rule, &mut sst.cert) else { return 0 };
        drop(st);
        if n == 0 {
            err::raise(ERR_LIB_SSL, SSL_R_NO_CIPHER_MATCH, "SSL_set_cipher_list");
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Sets the context's TLS 1.3 suites (colon-separated standard names) and puts them at the
    /// front of its list: 1, or 0 (`SSL_R_NO_CIPHER_MATCH` when a non-empty string names none).
    ///
    /// # Safety
    /// `c` is NULL or a live context; `str_` NULL or NUL-terminated.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_ciphersuites(c: *mut SSL_CTX, str_: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(s)) = (unsafe { ctx::ctx(c) }, unsafe { cstr(str_) }) else { return 0 };
        let mut st = x.state();
        let available = st.available;
        if !set_ciphersuites(&mut st.ciphers, s) {
            return 0;
        }
        if st.ciphers.list.is_null() {
            return 1;
        }
        c_int::from(update(&available, &mut st.ciphers))
    }
}

ffi_export! {
    /// Sets the connection's TLS 1.3 suites, making its own list from its context's first if it
    /// has none (as OpenSSL does even when the string is refused): 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `str_` NULL or NUL-terminated.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_ciphersuites(s: *mut SSL, str_: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(text)) = (unsafe { super::conn::ssl(s) }, unsafe { cstr(str_) }) else { return 0 };
        let c = x.state().ctx;
        // SAFETY: the connection's context, which it holds a reference to.
        let Some(cx) = (unsafe { ctx::ctx(c) }) else { return 0 };
        let (available, ctx_list) = {
            let cs = cx.state();
            (cs.available, cs.ciphers.list.dup())
        };
        let mut st = x.state();
        let ok = set_ciphersuites(&mut st.ciphers, text);
        if st.ciphers.list.is_null() {
            match ctx_list {
                Some(l) => st.ciphers.list = l,
                None => return 0,
            }
        }
        if ok && !st.ciphers.list.is_null() {
            return c_int::from(update(&available, &mut st.ciphers));
        }
        c_int::from(ok)
    }
}

ffi_export! {
    /// The connection's cipher list (its own, or else its context's), or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_ciphers(s: *const SSL) -> *mut stack_st_SSL_CIPHER
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ssl_ciphers(s) }
    }
}

/// `SSL_get_ciphers`.
///
/// # Safety
/// `s` is NULL or a live connection.
pub(crate) unsafe fn ssl_ciphers(s: *const SSL) -> *mut stack_st_SSL_CIPHER {
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { super::conn::ssl(s) }) else {
        return ptr::null_mut();
    };
    let st = x.state();
    if !st.ciphers.list.is_null() {
        return st.ciphers.list.as_ptr();
    }
    let c = st.ctx;
    drop(st);
    // SAFETY: the connection's context.
    unsafe { ctx::ctx(c) }.map_or(ptr::null_mut(), |cx| cx.state().ciphers.list.as_ptr())
}

ffi_export! {
    /// The context's cipher list, or NULL.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_get_ciphers(c: *const SSL_CTX) -> *mut stack_st_SSL_CIPHER
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx::ctx(c) }.map_or(ptr::null_mut(), |x| x.state().ciphers.list.as_ptr())
    }
}

ffi_export! {
    /// The name of the `n`th suite of the connection's list, or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_cipher_list(s: *const SSL, n: c_int) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let sk = unsafe { ssl_ciphers(s) };
        let list = ciphers_of(sk.cast());
        usize::try_from(n).ok().and_then(|i| list.get(i)).map_or(ptr::null(), |c| c.name.as_ptr())
    }
}

ffi_export! {
    /// The client's suites (a server's, after a ClientHello), or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_client_ciphers(s: *const SSL) -> *mut stack_st_SSL_CIPHER
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { super::conn::ssl(s) }) else { return ptr::null_mut() };
        let st = x.state();
        if !st.server {
            return ptr::null_mut();
        }
        st.ciphers.peer.as_ptr()
    }
}

ffi_export! {
    /// The suites both ends support (a server's, after a ClientHello), colon-separated in the
    /// client's order, written to `buf` (`size` octets, at least 2), stopping at the first name
    /// that doesn't fit. `buf`, or NULL (for a small or NULL buffer, a NULL or client
    /// connection).
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `buf` NULL or `size` writable octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_shared_ciphers(s: *const SSL, buf: *mut c_char, size: c_int) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        if size < 2 || buf.is_null() {
            return ptr::null_mut();
        }
        let Ok(cap) = usize::try_from(size) else { return ptr::null_mut() };
        // SAFETY: the caller's `size` octets.
        let out = unsafe { core::slice::from_raw_parts_mut(buf.cast::<u8>(), cap) };
        if let Some(b) = out.first_mut() {
            *b = 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { super::conn::ssl(s) }) else { return ptr::null_mut() };
        let (server, peer) = {
            let st = x.state();
            (st.server, st.ciphers.peer.ciphers())
        };
        if !server {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        let ours = ciphers_of(unsafe { ssl_ciphers(s) }.cast());
        if peer.is_empty() || ours.is_empty() {
            return buf;
        }
        let mut at = 0usize;
        let mut left = cap;
        for c in peer {
            if !ours.iter().any(|o| ptr::eq(*o, c)) {
                continue;
            }
            let name = c.name.to_bytes();
            // `OPENSSL_strnlen(name, size)`: a name as long as the room left stops it.
            if name.len() >= left {
                break;
            }
            let end = at.saturating_add(name.len());
            let Some(d) = out.get_mut(at..end) else { break };
            d.copy_from_slice(name);
            if let Some(b) = out.get_mut(end) {
                *b = b':';
            }
            at = end.saturating_add(1);
            left = left.saturating_sub(name.len().saturating_add(1));
        }
        if at > 0
            && let Some(b) = out.get_mut(at.saturating_sub(1))
        {
            *b = 0;
        }
        buf
    }
}

ffi_export! {
    /// Parses a ClientHello's cipher suites (`isv2format`: SSLv2's 3-octet entries, those with
    /// a non-zero first octet skipped) into the suites and the signalling values, each stack
    /// given to the caller where its slot isn't NULL: 1, or 0 (`SSL_R_NO_CIPHERS_SPECIFIED`,
    /// `SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST`).
    ///
    /// # Safety
    /// `s` is NULL or live; `bytes` holds `len` octets; `sk` and `scsvs` NULL or slots.
    pub unsafe extern "C" fn rustyssl_private_SSL_bytes_to_cipher_list(s: *mut SSL, bytes: *const u8, len: usize, isv2format: c_int, sk: *mut *mut stack_st_SSL_CIPHER, scsvs: *mut *mut stack_st_SSL_CIPHER) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        const F: &str = "ossl_bytes_to_cipher_list";
        // SAFETY: the caller's guarantee.
        if unsafe { super::conn::ssl(s) }.is_none() {
            return 0;
        }
        let data: &[u8] = if bytes.is_null() || len == 0 {
            if bytes.is_null() && len != 0 {
                return 0;
            }
            &[]
        } else {
            // SAFETY: the caller's `len` octets.
            unsafe { core::slice::from_raw_parts(bytes, len) }
        };
        let n = if isv2format != 0 { 3 } else { 2 };
        if data.is_empty() {
            err::raise(ERR_LIB_SSL, SSL_R_NO_CIPHERS_SPECIFIED, F);
            return 0;
        }
        if !data.len().is_multiple_of(n) {
            err::raise(ERR_LIB_SSL, SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST, F);
            return 0;
        }
        let (mut found, mut signalling) = (Vec::new(), Vec::new());
        for e in data.chunks_exact(n) {
            let id = if n == 3 {
                // True SSLv2 suites (a non-zero first octet) aren't supported.
                if e.first() != Some(&0) {
                    continue;
                }
                e.get(1..3)
            } else {
                Some(e)
            };
            let Some(&[hi, lo]) = id else { continue };
            let Some(c) = suites::by_protocol_id(u16::from_be_bytes([hi, lo])) else { continue };
            if c.valid { found.push(c) } else { signalling.push(c) }
        }
        let (Some(a), Some(b)) = (CipherStack::of(&found), CipherStack::of(&signalling)) else {
            err::raise(ERR_LIB_SSL, ERR_R_CRYPTO_LIB, F);
            return 0;
        };
        for (slot, st) in [(sk, a), (scsvs, b)] {
            if !slot.is_null() {
                // SAFETY: the caller's slot; the stack is given to the caller.
                unsafe { slot.write(st.into_raw()) };
            }
        }
        1
    }
}

ffi_export! {
    /// Sets a new method on the context and rebuilds its lists from the defaults: 1, or 0
    /// (`SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS`).
    ///
    /// # Safety
    /// `c` is NULL or a live context; `meth` NULL or a method.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_ssl_version(c: *mut SSL_CTX, meth: *const SSL_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        const F: &str = "SSL_CTX_set_ssl_version";
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx::ctx(c) }) else { return 0 };
        let Some(m) = method_of(meth) else { return 0 };
        let mut st = x.state();
        st.method = m;
        let available = st.available;
        if !set_ciphersuites(&mut st.ciphers, cipherstring::DEFAULT_CIPHERSUITES) {
            err::raise(ERR_LIB_SSL, SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS, F);
            return 0;
        }
        if !st.ciphers.list.is_null() && !update(&available, &mut st.ciphers) {
            err::raise(ERR_LIB_SSL, SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS, F);
            return 0;
        }
        let s = &mut *st;
        let built = create(&available, m, &mut s.ciphers, cipherstring::DEFAULT_CIPHER_LIST, &mut s.cert).is_some();
        if !built || st.ciphers.list.ciphers().is_empty() {
            drop(st);
            err::raise(ERR_LIB_SSL, SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS, F);
            return 0;
        }
        1
    }
}

/// `ssl_protocol_to_string`.
fn protocol_name(v: c_int) -> &'static CStr {
    match v {
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
    /// The suite's description line: written to `buf` (at least 128 octets, else NULL), or to a
    /// new 128-octet buffer for NULL `buf`; truncated as `BIO_snprintf` truncates.
    ///
    /// # Safety
    /// `c` is a suite from this library; `buf` NULL or `len` writable octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_CIPHER_description(c: *const SSL_CIPHER, buf: *mut c_char, len: c_int) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        let (out, cap) = if buf.is_null() {
            let p: *mut c_char = mem::alloc(128).cast();
            if p.is_null() {
                return ptr::null_mut();
            }
            (p, 128usize)
        } else {
            if len < 128 {
                return ptr::null_mut();
            }
            (buf, usize::try_from(len).unwrap_or(128))
        };
        let text = cipher_of(c).map(Cipher::description).unwrap_or_default();
        let bytes = text.as_bytes();
        let n = bytes.len().min(cap.saturating_sub(1));
        // SAFETY: room for `cap` octets.
        let dst = unsafe { core::slice::from_raw_parts_mut(out.cast::<u8>(), cap) };
        if let Some(d) = dst.get_mut(..n)
            && let Some(sv) = bytes.get(..n)
        {
            d.copy_from_slice(sv);
        }
        if let Some(b) = dst.get_mut(n) {
            *b = 0;
        }
        out
    }
}

ffi_export! {
    /// The lowest version the suite works with (`TLSv1.0` for TLS 1.0, as OpenSSL says it for
    /// suites), or "(NONE)".
    ///
    /// # Safety
    /// `c` is NULL or a suite from this library.
    pub unsafe extern "C" fn rustyssl_private_SSL_CIPHER_get_version(c: *const SSL_CIPHER) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        if c.is_null() {
            return c"(NONE)".as_ptr();
        }
        match cipher_of(c) {
            Some(x) if x.min_tls == TLS1_VERSION => c"TLSv1.0".as_ptr(),
            Some(x) => protocol_name(x.min_tls).as_ptr(),
            None => c"unknown".as_ptr(),
        }
    }
}

ffi_export! {
    /// The suite's OpenSSL name, or "(NONE)".
    ///
    /// # Safety
    /// `c` is NULL or a suite from this library.
    pub unsafe extern "C" fn rustyssl_private_SSL_CIPHER_get_name(c: *const SSL_CIPHER) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        if c.is_null() {
            return c"(NONE)".as_ptr();
        }
        cipher_of(c).map_or(ptr::null(), |x| x.name.as_ptr())
    }
}

ffi_export! {
    /// The suite's RFC name (NULL for the GOST suites, which have none), or "(NONE)".
    ///
    /// # Safety
    /// `c` is NULL or a suite from this library.
    pub unsafe extern "C" fn rustyssl_private_SSL_CIPHER_standard_name(c: *const SSL_CIPHER) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        if c.is_null() {
            return c"(NONE)".as_ptr();
        }
        cipher_of(c).and_then(|x| x.stdname).map_or(ptr::null(), CStr::as_ptr)
    }
}

ffi_export! {
    /// The OpenSSL name of the suite with this RFC name, or "(NONE)".
    ///
    /// # Safety
    /// `stdname` is NULL or NUL-terminated.
    pub unsafe extern "C" fn rustyssl_private_OPENSSL_cipher_name(stdname: *const c_char) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { cstr(stdname) }) else { return c"(NONE)".as_ptr() };
        s.to_str().ok().and_then(suites::by_std_name).map_or(c"(NONE)".as_ptr(), |c| c.name.as_ptr())
    }
}

ffi_export! {
    /// The suite's secret bits (and, where `alg_bits` isn't NULL, the cipher's key bits), or 0
    /// for NULL.
    ///
    /// # Safety
    /// `c` is NULL or a suite from this library; `alg_bits` NULL or writable.
    pub unsafe extern "C" fn rustyssl_private_SSL_CIPHER_get_bits(c: *const SSL_CIPHER, alg_bits: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let Some(x) = cipher_of(c) else { return 0 };
        if !alg_bits.is_null() {
            // SAFETY: the caller's slot.
            unsafe { alg_bits.write(x.alg_bits) };
        }
        x.strength_bits
    }
}

ffi_export! {
    /// The suite's OpenSSL id (`0x0300` and the two wire octets). OpenSSL reads through NULL;
    /// here NULL gives 0.
    ///
    /// # Safety
    /// `c` is NULL or a suite from this library.
    pub unsafe extern "C" fn rustyssl_private_SSL_CIPHER_get_id(c: *const SSL_CIPHER) -> u32
    where failure = 0, library = ERR_LIB_SSL
    {
        cipher_of(c).map_or(0, |x| x.id)
    }
}

ffi_export! {
    /// The suite's two wire octets as a number (0 for NULL, where OpenSSL reads through it).
    ///
    /// # Safety
    /// `c` is NULL or a suite from this library.
    pub unsafe extern "C" fn rustyssl_private_SSL_CIPHER_get_protocol_id(c: *const SSL_CIPHER) -> u16
    where failure = 0, library = ERR_LIB_SSL
    {
        cipher_of(c).map_or(0, Cipher::protocol_id)
    }
}

ffi_export! {
    /// The suite's cipher NID (`NID_undef` for none, or NULL).
    ///
    /// # Safety
    /// `c` is NULL or a suite from this library.
    pub unsafe extern "C" fn rustyssl_private_SSL_CIPHER_get_cipher_nid(c: *const SSL_CIPHER) -> c_int
    where failure = NID_undef, library = ERR_LIB_SSL
    {
        cipher_of(c).map_or(NID_undef, Cipher::cipher_nid)
    }
}

ffi_export! {
    /// The suite's MAC digest NID (`NID_undef` for AEADs; NULL gives `NID_undef`, where OpenSSL
    /// reads through it).
    ///
    /// # Safety
    /// `c` is NULL or a suite from this library.
    pub unsafe extern "C" fn rustyssl_private_SSL_CIPHER_get_digest_nid(c: *const SSL_CIPHER) -> c_int
    where failure = NID_undef, library = ERR_LIB_SSL
    {
        cipher_of(c).map_or(NID_undef, Cipher::digest_nid)
    }
}

ffi_export! {
    /// The suite's key exchange NID (`NID_kx_*`; NULL gives `NID_undef`).
    ///
    /// # Safety
    /// `c` is NULL or a suite from this library.
    pub unsafe extern "C" fn rustyssl_private_SSL_CIPHER_get_kx_nid(c: *const SSL_CIPHER) -> c_int
    where failure = NID_undef, library = ERR_LIB_SSL
    {
        cipher_of(c).map_or(NID_undef, Cipher::kx_nid)
    }
}

ffi_export! {
    /// The suite's authentication NID (`NID_auth_*`; NULL gives `NID_undef`).
    ///
    /// # Safety
    /// `c` is NULL or a suite from this library.
    pub unsafe extern "C" fn rustyssl_private_SSL_CIPHER_get_auth_nid(c: *const SSL_CIPHER) -> c_int
    where failure = NID_undef, library = ERR_LIB_SSL
    {
        cipher_of(c).map_or(NID_undef, Cipher::auth_nid)
    }
}

ffi_export! {
    /// The digest of the suite's handshake transcript and PRF (`EVP_get_digestbynid`), or NULL.
    ///
    /// # Safety
    /// `c` is NULL or a suite from this library.
    pub unsafe extern "C" fn rustyssl_private_SSL_CIPHER_get_handshake_digest(c: *const SSL_CIPHER) -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        let Some(x) = cipher_of(c) else { return ptr::null() };
        let nid = x.handshake_digest_nid();
        if nid == NID_undef {
            return ptr::null();
        }
        // SAFETY: any NID.
        let sn = unsafe { OBJ_nid2sn(nid) };
        // SAFETY: NULL or a static name.
        unsafe { EVP_get_digestbyname(sn) }
    }
}

ffi_export! {
    /// Whether the suite is an AEAD one: 1 or 0 (0 for NULL, where OpenSSL reads through it).
    ///
    /// # Safety
    /// `c` is NULL or a suite from this library.
    pub unsafe extern "C" fn rustyssl_private_SSL_CIPHER_is_aead(c: *const SSL_CIPHER) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        c_int::from(cipher_of(c).is_some_and(Cipher::is_aead))
    }
}

ffi_export! {
    /// The suite with these two wire octets (any method's table), or NULL.
    ///
    /// # Safety
    /// `ssl` is NULL or a live connection; `ptr_` NULL or two readable octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_CIPHER_find(ssl: *mut SSL, ptr_: *const u8) -> *const SSL_CIPHER
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // OpenSSL reads the method through the connection and the octets: both are required.
        if ssl.is_null() || ptr_.is_null() {
            return ptr::null();
        }
        // SAFETY: the caller's two octets.
        let b = unsafe { core::slice::from_raw_parts(ptr_, 2) };
        let Some(&[hi, lo]) = b.get(..2) else { return ptr::null() };
        suites::by_protocol_id(u16::from_be_bytes([hi, lo])).map_or(ptr::null(), cipher_ptr)
    }
}

/// The default security callback's cipher operations (`SSL_SECOP_CIPHER_*`): no suite below
/// the level's bits, no unauthenticated or MD5 suites, no SHA-1 MAC above 160 bits, and only
/// forward-secret ones (or TLS 1.3's) from level 3.
pub(crate) fn cipher_allowed(
    other: *const c_void,
    bits: c_int,
    minbits: c_int,
    level: c_int,
) -> bool {
    use rustyssl_tls::suites::masks::{
        SSL_MD5, SSL_SHA1, SSL_aNULL, SSL_kDHE, SSL_kDHEPSK, SSL_kECDHE, SSL_kECDHEPSK,
    };
    let Some(c) = cipher_of(other.cast()) else {
        return false;
    };
    if bits < minbits || c.auth & SSL_aNULL != 0 || c.mac & SSL_MD5 != 0 {
        return false;
    }
    if minbits > 160 && c.mac & SSL_SHA1 != 0 {
        return false;
    }
    let pfs = SSL_kDHE | SSL_kECDHE | SSL_kDHEPSK | SSL_kECDHEPSK;
    !(level >= 3 && c.min_tls != TLS1_3_VERSION && c.mkey & pfs == 0)
}
