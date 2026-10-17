//! Trust settings (`x509_trust.c`, the trust parts of `x_x509a.c`; `X509_check_trust(3)`): the
//! trust table (`X509_TRUST_*`, which applications can add to or change), the checks, and a
//! certificate's auxiliary trust data (`X509_add1_trust_object`, the alias, and the key ID).
//!
//! As OpenSSL's:
//! - A certificate whose auxiliary data names trusted uses is trusted for those (and for any,
//!   with `anyExtendedKeyUsage` where the check allows it) and rejected for the rest; a
//!   rejected use wins. Without auxiliary data, the compatible check trusts a self-signed
//!   certificate.
//! - `X509_TRUST_get_by_id` sorts the added entries; like OpenSSL's, the table isn't for
//!   changing while other threads use it.

use core::ffi::{CStr, c_char, c_int, c_uchar, c_void};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Mutex;

use rustyssl_abi::{
    ASN1_OBJECT, ERR_LIB_X509, ERR_R_CRYPTO_LIB, EXFLAG_SS, NID_OCSP_sign, NID_ad_OCSP,
    NID_anyExtendedKeyUsage, NID_client_auth, NID_code_sign, NID_email_protect, NID_server_auth,
    NID_time_stamp, OPENSSL_STACK, X509, X509_R_INVALID_TRUST, X509_TRUST, X509_TRUST_COMPAT,
    X509_TRUST_DEFAULT, X509_TRUST_DO_SS_COMPAT, X509_TRUST_DYNAMIC, X509_TRUST_DYNAMIC_NAME,
    X509_TRUST_EMAIL, X509_TRUST_MAX, X509_TRUST_MIN, X509_TRUST_NO_SS_COMPAT,
    X509_TRUST_OBJECT_SIGN, X509_TRUST_OCSP_REQUEST, X509_TRUST_OCSP_SIGN, X509_TRUST_OK_ANY_EKU,
    X509_TRUST_REJECTED, X509_TRUST_SSL_CLIENT, X509_TRUST_SSL_SERVER, X509_TRUST_TRUSTED,
    X509_TRUST_TSA, X509_TRUST_UNTRUSTED, stack_st_ASN1_OBJECT,
};

use super::cert::{CertAux, X509_CERT_AUX_new, cert_of};
use super::purpose::X509_check_purpose;
use crate::asn1::string::{
    ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_STRING_set, ASN1_UTF8STRING_free,
    ASN1_UTF8STRING_new,
};
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::objects::{ASN1_OBJECT_free, OBJ_dup, OBJ_obj2nid};
use crate::stack::{
    OPENSSL_sk_find, OPENSSL_sk_new, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free,
    OPENSSL_sk_push, OPENSSL_sk_sort, OPENSSL_sk_value,
};

/// The `X509_TRUST_*` flags, which the headers define unsigned, as `int`s.
const OK_ANY_EKU: c_int = X509_TRUST_OK_ANY_EKU.cast_signed();
const DO_SS_COMPAT: c_int = X509_TRUST_DO_SS_COMPAT.cast_signed();
const NO_SS_COMPAT: c_int = X509_TRUST_NO_SS_COMPAT.cast_signed();
const DYNAMIC: c_int = X509_TRUST_DYNAMIC.cast_signed();
const DYNAMIC_NAME: c_int = X509_TRUST_DYNAMIC_NAME.cast_signed();

type CheckFn = unsafe extern "C" fn(*mut X509_TRUST, *mut X509, c_int) -> c_int;

/// The certificate's auxiliary data, or `None`.
///
/// # Safety
/// `x` is NULL or a live certificate.
unsafe fn aux_of<'a>(x: *const X509) -> Option<&'a mut CertAux> {
    // SAFETY: the caller's guarantee; its auxiliary data, a `CertAux`, or NULL.
    unsafe { cert_of(x) }.and_then(|c| unsafe { c.aux.cast::<CertAux>().as_mut() })
}

/// `aux_get`: the certificate's auxiliary data, made if absent, or `None`.
///
/// # Safety
/// `x` is NULL or a live certificate.
unsafe fn aux_get<'a>(x: *mut X509) -> Option<&'a mut CertAux> {
    // SAFETY: the caller's guarantee.
    let c = unsafe { cert_of(x) }?;
    if c.aux.is_null() {
        // SAFETY: no preconditions.
        c.aux = unsafe { X509_CERT_AUX_new() };
    }
    // SAFETY: its auxiliary data, a `CertAux`, or NULL.
    unsafe { c.aux.cast::<CertAux>().as_mut() }
}

/// The NIDs of a list of objects.
///
/// # Safety
/// `sk` is NULL or a live stack of objects.
unsafe fn nids(sk: *mut c_void) -> impl Iterator<Item = c_int> {
    // SAFETY: the caller's guarantee.
    let n = unsafe { OPENSSL_sk_num(sk.cast()) };
    (0..n).map(move |i| {
        // SAFETY: an index within the stack.
        let o = unsafe { OPENSSL_sk_value(sk.cast(), i) };
        // SAFETY: an object of it.
        unsafe { OBJ_obj2nid(o.cast()) }
    })
}

/// `obj_trust`: the auxiliary data's verdict on the use `id`.
///
/// # Safety
/// `x` is a live certificate.
unsafe fn obj_trust(id: c_int, x: *mut X509, flags: c_int) -> c_int {
    let any = flags & OK_ANY_EKU != 0;
    let matches = |nid: c_int| nid == id || (nid == NID_anyExtendedKeyUsage && any);
    // SAFETY: the caller's guarantee.
    if let Some(ax) = unsafe { aux_of(x) } {
        // SAFETY: its rejected uses, or NULL.
        if !ax.reject.is_null() && unsafe { nids(ax.reject) }.any(matches) {
            return X509_TRUST_REJECTED;
        }
        if !ax.trust.is_null() {
            // SAFETY: its trusted uses.
            return if unsafe { nids(ax.trust) }.any(matches) {
                X509_TRUST_TRUSTED
            } else {
                X509_TRUST_REJECTED
            };
        }
    }
    if flags & DO_SS_COMPAT == 0 {
        return X509_TRUST_UNTRUSTED;
    }
    // SAFETY: as above.
    unsafe { compat(x, flags) }
}

/// `trust_compat`: trusted if self-signed.
///
/// # Safety
/// `x` is a live certificate.
unsafe fn compat(x: *mut X509, flags: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    if unsafe { X509_check_purpose(x, -1, 0) } != 1 {
        return X509_TRUST_UNTRUSTED;
    }
    // SAFETY: as above.
    let ss = unsafe { cert_of(x) }.is_some_and(|c| c.cache.flags & EXFLAG_SS.cast_unsigned() != 0);
    if flags & NO_SS_COMPAT == 0 && ss {
        X509_TRUST_TRUSTED
    } else {
        X509_TRUST_UNTRUSTED
    }
}

ffi_callback! {
    /// `trust_1oidany`: the entry's use, or any, trusting a self-signed certificate without
    /// auxiliary data.
    ///
    /// # Safety
    /// `trust` is a live entry; `x` is a live certificate.
    pub(crate) unsafe extern "C" fn trust_1oidany(trust: *mut X509_TRUST, x: *mut X509, flags: c_int) -> c_int
    where failure = X509_TRUST_UNTRUSTED, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let id = unsafe { trust.as_ref() }.map_or(0, |t| t.arg1);
        // SAFETY: as above.
        unsafe { obj_trust(id, x, flags | DO_SS_COMPAT | OK_ANY_EKU) }
    }
}

ffi_callback! {
    /// `trust_1oid`: the entry's use only.
    ///
    /// # Safety
    /// `trust` is a live entry; `x` is a live certificate.
    pub(crate) unsafe extern "C" fn trust_1oid(trust: *mut X509_TRUST, x: *mut X509, flags: c_int) -> c_int
    where failure = X509_TRUST_UNTRUSTED, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let id = unsafe { trust.as_ref() }.map_or(0, |t| t.arg1);
        // SAFETY: as above.
        unsafe { obj_trust(id, x, flags & !(DO_SS_COMPAT | OK_ANY_EKU)) }
    }
}

ffi_callback! {
    /// `trust_compat`.
    ///
    /// # Safety
    /// `x` is a live certificate.
    pub(crate) unsafe extern "C" fn trust_compat(_trust: *mut X509_TRUST, x: *mut X509, flags: c_int) -> c_int
    where failure = X509_TRUST_UNTRUSTED, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { compat(x, flags) }
    }
}

ffi_callback! {
    /// `obj_trust` as the default check: the use `id` by the auxiliary data, no compatibility.
    ///
    /// # Safety
    /// `x` is a live certificate.
    pub(crate) unsafe extern "C" fn default_obj_trust(id: c_int, x: *mut X509, flags: c_int) -> c_int
    where failure = X509_TRUST_UNTRUSTED, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { obj_trust(id, x, flags) }
    }
}

const fn entry(id: c_int, check: CheckFn, name: &'static CStr, arg1: c_int) -> X509_TRUST {
    X509_TRUST {
        trust: id,
        flags: 0,
        check_trust: Some(check),
        name: name.as_ptr().cast_mut(),
        arg1,
        arg2: ptr::null_mut(),
    }
}

/// How many built-in entries there are (`X509_TRUST_COUNT`).
const COUNT: usize = 8;
const COUNT_INT: c_int = 8;

/// `trstandard`, which `X509_TRUST_add` may change.
struct Standard(core::cell::UnsafeCell<[X509_TRUST; COUNT]>);

// SAFETY: as OpenSSL's table, changed only by `X509_TRUST_add`, which OpenSSL doesn't make
// thread-safe either.
unsafe impl Sync for Standard {}

static STANDARD: Standard = Standard(core::cell::UnsafeCell::new([
    entry(X509_TRUST_COMPAT, trust_compat, c"compatible", 0),
    entry(
        X509_TRUST_SSL_CLIENT,
        trust_1oidany,
        c"SSL Client",
        NID_client_auth,
    ),
    entry(
        X509_TRUST_SSL_SERVER,
        trust_1oidany,
        c"SSL Server",
        NID_server_auth,
    ),
    entry(
        X509_TRUST_EMAIL,
        trust_1oidany,
        c"S/MIME email",
        NID_email_protect,
    ),
    entry(
        X509_TRUST_OBJECT_SIGN,
        trust_1oidany,
        c"Object Signer",
        NID_code_sign,
    ),
    entry(
        X509_TRUST_OCSP_SIGN,
        trust_1oid,
        c"OCSP responder",
        NID_OCSP_sign,
    ),
    entry(
        X509_TRUST_OCSP_REQUEST,
        trust_1oid,
        c"OCSP request",
        NID_ad_OCSP,
    ),
    entry(X509_TRUST_TSA, trust_1oidany, c"TSA server", NID_time_stamp),
]));

/// `trtable`: the entries applications added, or NULL.
static TRTABLE: AtomicPtr<OPENSSL_STACK> = AtomicPtr::new(ptr::null_mut());

type DefaultFn = unsafe extern "C" fn(c_int, *mut X509, c_int) -> c_int;

/// `default_trust`: the check for ids without an entry: `obj_trust` until an application sets
/// one (or NULL).
static DEFAULT_TRUST: Mutex<Option<Option<DefaultFn>>> = Mutex::new(None);

/// The default check, copied out (it's called without the lock).
fn default_trust() -> Option<DefaultFn> {
    let set = *DEFAULT_TRUST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    set.unwrap_or(Some(default_obj_trust))
}

/// Serializes `X509_TRUST_add` and `X509_TRUST_cleanup` with each other.
static ADD: Mutex<()> = Mutex::new(());

/// `tr_cmp`: by id.
unsafe extern "C" fn tr_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: pointers to the stack's elements, entries.
    let a = unsafe { *a.cast::<*const X509_TRUST>() };
    // SAFETY: as above.
    let b = unsafe { *b.cast::<*const X509_TRUST>() };
    // SAFETY: the entries.
    let (ta, tb) = (unsafe { (*a).trust }, unsafe { (*b).trust });
    ta.wrapping_sub(tb)
}

ffi_export! {
    /// Makes `trust` the check for ids without an entry: the one before.
    ///
    /// # Safety
    /// `trust` is NULL or a function that outlives its use.
    pub unsafe extern "C" fn X509_TRUST_set_default(trust: Option<DefaultFn>) -> Option<DefaultFn>
    where failure = None, library = ERR_LIB_X509
    {
        let mut set = DEFAULT_TRUST.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let old = set.unwrap_or(Some(default_obj_trust));
        *set = Some(trust);
        old
    }
}

ffi_export! {
    /// How many entries there are, built in and added.
    pub unsafe extern "C" fn X509_TRUST_get_count() -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        let t = TRTABLE.load(Ordering::Acquire);
        if t.is_null() {
            return COUNT_INT;
        }
        // SAFETY: the table.
        unsafe { OPENSSL_sk_num(t) }.saturating_add(COUNT_INT)
    }
}

ffi_export! {
    /// The entry at `idx`, or NULL.
    pub unsafe extern "C" fn X509_TRUST_get0(idx: c_int) -> *mut X509_TRUST
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        let Ok(i) = usize::try_from(idx) else { return ptr::null_mut() };
        if i < COUNT {
            // SAFETY: an index within the built-in entries.
            return unsafe { STANDARD.0.get().cast::<X509_TRUST>().add(i) };
        }
        // SAFETY: the table, or NULL; an index past the built-in ones.
        unsafe { OPENSSL_sk_value(TRTABLE.load(Ordering::Acquire), idx.wrapping_sub(COUNT_INT)) }.cast()
    }
}

ffi_export! {
    /// The index of the entry with the id (sorting the added ones), or -1.
    pub unsafe extern "C" fn X509_TRUST_get_by_id(id: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        if (X509_TRUST_MIN..=X509_TRUST_MAX).contains(&id) {
            return id.wrapping_sub(X509_TRUST_MIN);
        }
        let t = TRTABLE.load(Ordering::Acquire);
        if t.is_null() {
            return -1;
        }
        // SAFETY: all-zero is a valid entry to search with.
        let mut tmp: X509_TRUST = unsafe { core::mem::zeroed() };
        tmp.trust = id;
        // SAFETY: the table.
        unsafe { OPENSSL_sk_sort(t) };
        // SAFETY: as above; the key.
        let idx = unsafe { OPENSSL_sk_find(t, (&raw mut tmp).cast()) };
        if idx < 0 { -1 } else { idx.saturating_add(COUNT_INT) }
    }
}

ffi_export! {
    /// Stores `trust` in `*t` if it has an entry: 1, or 0 (`X509_R_INVALID_TRUST`).
    ///
    /// # Safety
    /// `t` is writable.
    pub unsafe extern "C" fn X509_TRUST_set(t: *mut c_int, trust: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        if unsafe { X509_TRUST_get_by_id(trust) } < 0 {
            err::raise(ERR_LIB_X509, X509_R_INVALID_TRUST, "X509_TRUST_set");
            return 0;
        }
        if t.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { t.write(trust) };
        1
    }
}

ffi_export! {
    /// The certificate's trust for `id`: `X509_TRUST_TRUSTED`, `_REJECTED`, or `_UNTRUSTED`,
    /// by the entry's check (the default one for an id without an entry; any extended key usage
    /// with the compatible check for `X509_TRUST_DEFAULT`).
    ///
    /// # Safety
    /// `x` is a live certificate.
    pub unsafe extern "C" fn X509_check_trust(x: *mut X509, id: c_int, flags: c_int) -> c_int
    where failure = X509_TRUST_UNTRUSTED, library = ERR_LIB_X509
    {
        if x.is_null() {
            return X509_TRUST_UNTRUSTED;
        }
        if id == X509_TRUST_DEFAULT {
            // SAFETY: the caller's guarantee.
            return unsafe { obj_trust(NID_anyExtendedKeyUsage, x, flags | DO_SS_COMPAT) };
        }
        // SAFETY: no preconditions.
        let idx = unsafe { X509_TRUST_get_by_id(id) };
        if idx < 0 {
            let Some(f) = default_trust() else { return X509_TRUST_UNTRUSTED };
            // SAFETY: the default check, given the caller's certificate.
            return unsafe { f(id, x, flags) };
        }
        // SAFETY: as above.
        let pt = unsafe { X509_TRUST_get0(idx) };
        // SAFETY: an entry of the table.
        let Some(check) = unsafe { pt.as_ref() }.and_then(|t| t.check_trust) else { return X509_TRUST_UNTRUSTED };
        // SAFETY: the entry's check, given it and the caller's certificate.
        unsafe { check(pt, x, flags) }
    }
}

ffi_export! {
    /// Adds the entry `id` (or changes it): 1, or 0.
    ///
    /// # Safety
    /// `ck` is NULL or a check; `name` is a C string.
    pub unsafe extern "C" fn X509_TRUST_add(id: c_int, flags: c_int, ck: Option<CheckFn>, name: *const c_char, arg1: c_int, arg2: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        const F: &str = "X509_TRUST_add";
        if name.is_null() {
            return 0;
        }
        let _guard = ADD.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let flags = (flags & !DYNAMIC) | DYNAMIC_NAME;
        // SAFETY: no preconditions.
        let idx = unsafe { X509_TRUST_get_by_id(id) };
        let p: *mut X509_TRUST = if idx < 0 {
            let p = mem::alloc(core::mem::size_of::<X509_TRUST>()).cast::<X509_TRUST>();
            if p.is_null() {
                return 0;
            }
            // SAFETY: all-zero is a valid entry.
            let mut fresh: X509_TRUST = unsafe { core::mem::zeroed() };
            fresh.flags = DYNAMIC;
            // SAFETY: new memory for an entry.
            unsafe { p.write(fresh) };
            p
        } else {
            // SAFETY: an index of an entry.
            unsafe { X509_TRUST_get0(idx) }
        };
        // SAFETY: the entry, new or of the table.
        let t = unsafe { &mut *p };
        if t.flags & DYNAMIC_NAME != 0 {
            // SAFETY: its own copy.
            unsafe { mem::release(t.name.cast()) };
        }
        // SAFETY: a C string.
        t.name = crate::conf::c_dup(unsafe { CStr::from_ptr(name) }.to_bytes());
        let fail = |t: &mut X509_TRUST| {
            if idx < 0 {
                // SAFETY: the new entry's copy, and it.
                unsafe { mem::release(t.name.cast()) };
                // SAFETY: as above.
                unsafe { mem::release(p.cast()) };
            }
            0
        };
        if t.name.is_null() {
            return fail(t);
        }
        t.flags &= DYNAMIC;
        t.flags |= flags;
        t.trust = id;
        t.check_trust = ck;
        t.arg1 = arg1;
        t.arg2 = arg2;
        if idx < 0 {
            let mut tab = TRTABLE.load(Ordering::Acquire);
            if tab.is_null() {
                // SAFETY: a comparison of entries.
                tab = unsafe { OPENSSL_sk_new(Some(tr_cmp)) };
                if tab.is_null() {
                    err::raise(ERR_LIB_X509, ERR_R_CRYPTO_LIB, F);
                    return fail(t);
                }
                TRTABLE.store(tab, Ordering::Release);
            }
            // SAFETY: the table; the entry, which it takes.
            if unsafe { OPENSSL_sk_push(tab, p.cast()) } == 0 {
                err::raise(ERR_LIB_X509, ERR_R_CRYPTO_LIB, F);
                return fail(t);
            }
        }
        1
    }
}

/// `trtable_free`.
unsafe extern "C" fn trtable_free(p: *mut c_void) {
    // SAFETY: an entry of the table, or NULL.
    let Some(t) = (unsafe { p.cast::<X509_TRUST>().as_mut() }) else {
        return;
    };
    if t.flags & DYNAMIC != 0 {
        if t.flags & DYNAMIC_NAME != 0 {
            // SAFETY: its own copy.
            unsafe { mem::release(t.name.cast()) };
        }
        // SAFETY: as above.
        unsafe { mem::release(p) };
    }
}

ffi_export! {
    /// Removes the added entries.
    pub unsafe extern "C" fn X509_TRUST_cleanup()
    where failure = (), library = ERR_LIB_X509
    {
        let _guard = ADD.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let t = TRTABLE.swap(ptr::null_mut(), Ordering::AcqRel);
        // SAFETY: the table, or NULL, with its entries.
        unsafe { OPENSSL_sk_pop_free(t, Some(trtable_free)) };
    }
}

ffi_export! {
    /// The entry's flags.
    ///
    /// # Safety
    /// `xp` is NULL (0) or a live entry.
    pub unsafe extern "C" fn X509_TRUST_get_flags(xp: *const X509_TRUST) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { xp.as_ref() }.map_or(0, |t| t.flags)
    }
}

ffi_export! {
    /// The entry's name.
    ///
    /// # Safety
    /// `xp` is NULL (NULL) or a live entry.
    pub unsafe extern "C" fn X509_TRUST_get0_name(xp: *const X509_TRUST) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { xp.as_ref() }.map_or(ptr::null_mut(), |t| t.name)
    }
}

ffi_export! {
    /// The entry's id.
    ///
    /// # Safety
    /// `xp` is NULL (0) or a live entry.
    pub unsafe extern "C" fn X509_TRUST_get_trust(xp: *const X509_TRUST) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { xp.as_ref() }.map_or(0, |t| t.trust)
    }
}

// The auxiliary trust data (`x_x509a.c`).

ffi_export! {
    /// Whether the certificate has auxiliary trust data: 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_trusted(x: *const X509) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { cert_of(x) }.is_some_and(|c| !c.aux.is_null()))
    }
}

/// `X509_alias_set1` and `X509_keyid_set1`: a string of the auxiliary data set to the octets
/// (made if absent), or removed for NULL.
///
/// # Safety
/// `x` is NULL or a live certificate; `data` is NULL or holds `len` octets (a C string for -1).
unsafe fn set1_string(x: *mut X509, data: *const c_uchar, len: c_int, alias: bool) -> c_int {
    if data.is_null() {
        // SAFETY: the caller's guarantee.
        let Some(ax) = (unsafe { aux_of(x) }) else {
            return 1;
        };
        if alias {
            // SAFETY: its own, or NULL.
            unsafe { ASN1_UTF8STRING_free(ax.alias) };
            ax.alias = ptr::null_mut();
        } else {
            // SAFETY: as above.
            unsafe { ASN1_OCTET_STRING_free(ax.keyid) };
            ax.keyid = ptr::null_mut();
        }
        return 1;
    }
    // SAFETY: the caller's guarantee.
    let Some(ax) = (unsafe { aux_get(x) }) else {
        return 0;
    };
    let slot = if alias { &mut ax.alias } else { &mut ax.keyid };
    if slot.is_null() {
        *slot = if alias {
            // SAFETY: no preconditions.
            unsafe { ASN1_UTF8STRING_new() }
        } else {
            // SAFETY: no preconditions.
            unsafe { ASN1_OCTET_STRING_new() }
        };
        if slot.is_null() {
            return 0;
        }
    }
    // SAFETY: the string; the caller's octets.
    unsafe { ASN1_STRING_set((*slot).cast(), data.cast(), len) }
}

ffi_export! {
    /// Sets the certificate's alias (friendly name) to the octets, or removes it for NULL: 1,
    /// or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `name` is NULL or holds `len` octets.
    pub unsafe extern "C" fn X509_alias_set1(x: *mut X509, name: *const c_uchar, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { set1_string(x, name, len, true) }
    }
}

ffi_export! {
    /// Sets the certificate's key ID to the octets, or removes it for NULL: 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `id` is NULL or holds `len` octets.
    pub unsafe extern "C" fn X509_keyid_set1(x: *mut X509, id: *const c_uchar, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { set1_string(x, id, len, false) }
    }
}

/// The octets of a string of the auxiliary data, with its length in `*len`, or NULL.
///
/// # Safety
/// `x` is NULL or a live certificate; `len` is NULL or writable.
unsafe fn get0_string(x: *mut X509, len: *mut c_int, alias: bool) -> *mut c_uchar {
    // SAFETY: the caller's guarantee.
    let Some(ax) = (unsafe { aux_of(x) }) else {
        return ptr::null_mut();
    };
    let s = if alias { ax.alias } else { ax.keyid };
    // SAFETY: the string, or NULL.
    let Some(st) = (unsafe { s.as_ref() }) else {
        return ptr::null_mut();
    };
    if !len.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { len.write(st.length) };
    }
    st.data
}

ffi_export! {
    /// The certificate's alias (the certificate keeps it), its length in `*len`, or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `len` is NULL or writable.
    pub unsafe extern "C" fn X509_alias_get0(x: *mut X509, len: *mut c_int) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0_string(x, len, true) }
    }
}

ffi_export! {
    /// The certificate's key ID (the certificate keeps it), its length in `*len`, or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `len` is NULL or writable.
    pub unsafe extern "C" fn X509_keyid_get0(x: *mut X509, len: *mut c_int) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0_string(x, len, false) }
    }
}

/// Pushes a copy of `obj` onto a list of the auxiliary data, made if absent.
///
/// # Safety
/// `list` holds NULL or a live stack of objects; `obj` is a live object.
unsafe fn push_copy(list: &mut *mut c_void, obj: *const ASN1_OBJECT) -> bool {
    // SAFETY: the caller's guarantee.
    let copy = unsafe { OBJ_dup(obj) };
    if copy.is_null() {
        return false;
    }
    if list.is_null() {
        // SAFETY: no preconditions.
        *list = unsafe { OPENSSL_sk_new_null() }.cast();
    }
    // SAFETY: the list, or NULL; the copy, which it takes.
    if list.is_null() || unsafe { OPENSSL_sk_push(list.cast(), copy.cast()) } <= 0 {
        // SAFETY: made above.
        unsafe { ASN1_OBJECT_free(copy) };
        return false;
    }
    true
}

ffi_export! {
    /// Adds a copy of `obj` to the uses the certificate is trusted for (or, for NULL, only makes
    /// the list): 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `obj` is NULL or a live object.
    pub unsafe extern "C" fn X509_add1_trust_object(x: *mut X509, obj: *const ASN1_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(ax) = (unsafe { aux_get(x) }) else { return 0 };
        if obj.is_null() {
            if ax.trust.is_null() {
                // SAFETY: no preconditions.
                ax.trust = unsafe { OPENSSL_sk_new_null() }.cast();
            }
            return c_int::from(!ax.trust.is_null());
        }
        // SAFETY: its list; the caller's object.
        c_int::from(unsafe { push_copy(&mut ax.trust, obj) })
    }
}

ffi_export! {
    /// Adds a copy of `obj` to the uses the certificate is rejected for: 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `obj` is a live object.
    pub unsafe extern "C" fn X509_add1_reject_object(x: *mut X509, obj: *const ASN1_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if obj.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(ax) = (unsafe { aux_get(x) }) else { return 0 };
        // SAFETY: its list; the caller's object.
        c_int::from(unsafe { push_copy(&mut ax.reject, obj) })
    }
}

/// `ASN1_OBJECT_free` as a stack's free function.
unsafe extern "C" fn free_object(p: *mut c_void) {
    // SAFETY: an element of the stack, which the stack owned.
    unsafe { ASN1_OBJECT_free(p.cast()) };
}

ffi_export! {
    /// Removes the uses the certificate is trusted for.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_trust_clear(x: *mut X509)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(ax) = unsafe { aux_of(x) } {
            // SAFETY: its list, or NULL, with its objects.
            unsafe { OPENSSL_sk_pop_free(ax.trust.cast(), Some(free_object)) };
            ax.trust = ptr::null_mut();
        }
    }
}

ffi_export! {
    /// Removes the uses the certificate is rejected for.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_reject_clear(x: *mut X509)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(ax) = unsafe { aux_of(x) } {
            // SAFETY: its list, or NULL, with its objects.
            unsafe { OPENSSL_sk_pop_free(ax.reject.cast(), Some(free_object)) };
            ax.reject = ptr::null_mut();
        }
    }
}

ffi_export! {
    /// The uses the certificate is trusted for (it keeps them), or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_get0_trust_objects(x: *mut X509) -> *mut stack_st_ASN1_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { aux_of(x) }.map_or(ptr::null_mut(), |a| a.trust.cast())
    }
}

ffi_export! {
    /// The uses the certificate is rejected for (it keeps them), or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_get0_reject_objects(x: *mut X509) -> *mut stack_st_ASN1_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { aux_of(x) }.map_or(ptr::null_mut(), |a| a.reject.cast())
    }
}
