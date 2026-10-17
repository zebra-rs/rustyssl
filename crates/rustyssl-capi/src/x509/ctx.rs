//! The verification context (`x509_vfy.c`, the context parts of `x509_lu.c`, `x509_txt.c`, and
//! `X509_STORE_CTX_print_verify_cb` of `t_x509.c`): `X509_STORE_CTX`, what one verification
//! of a certificate uses and finds (the store, the untrusted certificates and CRLs, the
//! parameters, the callbacks, the chain, and the error with its depth and certificate); its
//! searches of the store; issuer lookup; validity-time checks; and the verification errors'
//! text.
//!
//! The verification itself is in `verify.rs`, revocation in `revoke.rs`, and policies in
//! `pcy.rs`.
//!
//! The type is opaque in OpenSSL's headers, so its layout is ours (OpenSSL's, in fact).

use core::ffi::{CStr, c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr;

use libc::time_t;
use rustyssl_abi::{
    ASN1_TIME, CRYPTO_EX_DATA, CRYPTO_EX_INDEX_X509_STORE_CTX, ERR_LIB_X509, ERR_R_ASN1_LIB,
    ERR_R_CRYPTO_LIB, ERR_R_PASSED_NULL_PARAMETER, EVP_PKEY, OSSL_LIB_CTX, SSL_DANE, X509,
    X509_ADD_FLAG_UP_REF, X509_CRL, X509_LOOKUP, X509_LOOKUP_TYPE, X509_LU_CRL, X509_LU_X509,
    X509_NAME, X509_OBJECT, X509_POLICY_TREE, X509_R_UNKNOWN_PURPOSE_ID, X509_R_UNKNOWN_TRUST_ID,
    X509_STORE, X509_STORE_CTX, X509_STORE_CTX_cert_crl_fn, X509_STORE_CTX_check_crl_fn,
    X509_STORE_CTX_check_issued_fn, X509_STORE_CTX_check_policy_fn,
    X509_STORE_CTX_check_revocation_fn, X509_STORE_CTX_cleanup_fn, X509_STORE_CTX_get_crl_fn,
    X509_STORE_CTX_get_issuer_fn, X509_STORE_CTX_lookup_certs_fn, X509_STORE_CTX_lookup_crls_fn,
    X509_STORE_CTX_verify_cb, X509_STORE_CTX_verify_fn, X509_TRUST_DEFAULT,
    X509_V_ERR_CERT_HAS_EXPIRED, X509_V_ERR_CERT_NOT_YET_VALID,
    X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD, X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD,
    X509_V_ERR_OUT_OF_MEM, X509_V_FLAG_NO_CHECK_TIME, X509_V_FLAG_USE_CHECK_TIME, X509_V_OK,
    X509_VERIFY_PARAM, X509_VP_FLAG_DEFAULT, X509_VP_FLAG_ONCE, stack_st_X509, stack_st_X509_CRL,
};

use super::cert::{
    OSSL_STACK_OF_X509_free, X509_chain_up_ref, X509_cmp_time, X509_get_issuer_name,
    X509_get_subject_name, X509_get0_notAfter, X509_get0_notBefore, X509_up_ref,
};
use super::crl::{X509_CRL_free, X509_CRL_up_ref};
use super::lookup::{X509_LOOKUP_by_subject_ex, skip_of};
use super::name::X509_NAME_cmp;
use super::purpose::X509_add_cert;
use super::purpose::{
    X509_PURPOSE_get_by_id, X509_PURPOSE_get_trust, X509_PURPOSE_get0, likely_issued,
};
use super::store::{
    Object, X509_OBJECT_free, X509_OBJECT_new, X509_OBJECT_retrieve_by_subject,
    X509_OBJECT_up_ref_count, X509_STORE_get0_param, idx_cnt, read_lock, store,
};
use super::trust::X509_TRUST_get_by_id;
use super::vpm::{
    Param, X509_VERIFY_PARAM_free, X509_VERIFY_PARAM_inherit, X509_VERIFY_PARAM_lookup,
    X509_VERIFY_PARAM_new, X509_VERIFY_PARAM_set_depth, X509_VERIFY_PARAM_set_flags,
    X509_VERIFY_PARAM_set_time,
};
use crate::err;
use crate::ex_data::{
    CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data, CRYPTO_set_ex_data,
};
use crate::ffi::ffi_export;
use crate::generated::verify_strings::{UNKNOWN, VERIFY_STRINGS};
use crate::mem;
use crate::stack::{
    OPENSSL_sk_free, OPENSSL_sk_is_sorted, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push,
    OPENSSL_sk_sort, OPENSSL_sk_value,
};
use crate::threads::{CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock};

/// `struct x509_store_ctx_st` (`crypto/x509.h`).
#[repr(C)]
pub(crate) struct Ctx {
    pub(crate) store: *mut X509_STORE,
    pub(crate) cert: *mut X509,
    pub(crate) untrusted: *mut stack_st_X509,
    pub(crate) crls: *mut stack_st_X509_CRL,
    pub(crate) param: *mut X509_VERIFY_PARAM,
    pub(crate) other_ctx: *mut c_void,
    pub(crate) verify: X509_STORE_CTX_verify_fn,
    pub(crate) verify_cb: X509_STORE_CTX_verify_cb,
    pub(crate) get_issuer: X509_STORE_CTX_get_issuer_fn,
    pub(crate) check_issued: X509_STORE_CTX_check_issued_fn,
    pub(crate) check_revocation: X509_STORE_CTX_check_revocation_fn,
    pub(crate) get_crl: X509_STORE_CTX_get_crl_fn,
    pub(crate) check_crl: X509_STORE_CTX_check_crl_fn,
    pub(crate) cert_crl: X509_STORE_CTX_cert_crl_fn,
    pub(crate) check_policy: X509_STORE_CTX_check_policy_fn,
    pub(crate) lookup_certs: X509_STORE_CTX_lookup_certs_fn,
    pub(crate) lookup_crls: X509_STORE_CTX_lookup_crls_fn,
    pub(crate) cleanup: X509_STORE_CTX_cleanup_fn,
    pub(crate) valid: c_int,
    pub(crate) num_untrusted: c_int,
    pub(crate) chain: *mut stack_st_X509,
    pub(crate) tree: *mut X509_POLICY_TREE,
    pub(crate) explicit_policy: c_int,
    pub(crate) error_depth: c_int,
    pub(crate) error: c_int,
    pub(crate) current_cert: *mut X509,
    pub(crate) current_issuer: *mut X509,
    pub(crate) current_crl: *mut X509_CRL,
    pub(crate) current_crl_score: c_int,
    pub(crate) current_reasons: c_uint,
    pub(crate) parent: *mut X509_STORE_CTX,
    pub(crate) ex_data: CRYPTO_EX_DATA,
    pub(crate) dane: *mut SSL_DANE,
    pub(crate) bare_ta_signed: c_int,
    pub(crate) rpk: *mut EVP_PKEY,
    pub(crate) libctx: *mut OSSL_LIB_CTX,
    pub(crate) propq: *mut c_char,
}

/// The context behind `ctx`, or `None` for NULL.
///
/// # Safety
/// `ctx` is NULL or a live context no one else is using.
pub(crate) unsafe fn ctx_of<'a>(ctx: *const X509_STORE_CTX) -> Option<&'a mut Ctx> {
    // SAFETY: the caller's guarantee.
    unsafe { ctx.cast::<Ctx>().cast_mut().as_mut() }
}

/// The context's parameters.
fn param(c: &mut Ctx) -> Option<&mut Param> {
    // SAFETY: a context's parameters are NULL or live, and its own.
    unsafe { c.param.cast::<Param>().as_mut() }
}

// The default functions.

/// `null_callback`: the verification callback that changes nothing.
unsafe extern "C" fn null_callback(ok: c_int, _ctx: *mut X509_STORE_CTX) -> c_int {
    ok
}

/// `check_issued`: whether `issuer` likely issued `x` (`ossl_x509_likely_issued`).
unsafe extern "C" fn check_issued(
    _ctx: *mut X509_STORE_CTX,
    x: *mut X509,
    issuer: *mut X509,
) -> c_int {
    crate::ffi::guard(
        ERR_LIB_X509,
        "check_issued",
        || 0,
        move || {
            // SAFETY: the context's certificates.
            c_int::from(unsafe { likely_issued(issuer, x) } == X509_V_OK)
        },
    )
}

// Callbacks and time checks.

/// `verify_cb_cert`: reports `err` (unless OK) at `depth` (the current one for negative) for
/// `x` (the chain's at the depth for NULL) to the verification callback: its answer.
///
/// # Safety
/// `ctx` is a live context.
pub(crate) unsafe fn verify_cb_cert(
    ctx: *mut X509_STORE_CTX,
    x: *mut X509,
    depth: c_int,
    err: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return 0;
    };
    let depth = if depth < 0 {
        c.error_depth
    } else {
        c.error_depth = depth;
        depth
    };
    c.current_cert = if x.is_null() {
        // SAFETY: the context's chain, or NULL.
        unsafe { OPENSSL_sk_value(c.chain.cast(), depth) }.cast()
    } else {
        x
    };
    if err != X509_V_OK {
        c.error = err;
    }
    let cb = c.verify_cb;
    // SAFETY: the context's callback, with no reference into the context held.
    cb.map_or(0, |f| unsafe { f(0, ctx) })
}

/// `ossl_x509_check_cert_time`: whether `x` is valid at the context's time (now, the
/// parameters', or always with `X509_V_FLAG_NO_CHECK_TIME`). At a negative depth, only the
/// answer (no callback); otherwise each failure goes to the callback, which may accept it.
///
/// # Safety
/// `ctx` is a live context; `x` is a live certificate.
pub(crate) unsafe fn check_cert_time(
    ctx: *mut X509_STORE_CTX,
    x: *mut X509,
    depth: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return 0;
    };
    let Some(p) = param(c) else { return 0 };
    let mut check_time = p.check_time;
    let ptime: *mut time_t = if p.flags & flag(X509_V_FLAG_USE_CHECK_TIME) != 0 {
        &raw mut check_time
    } else if p.flags & flag(X509_V_FLAG_NO_CHECK_TIME) != 0 {
        return 1;
    } else {
        ptr::null_mut()
    };
    let rejects = |err| {
        // SAFETY: the caller's context and certificate.
        (unsafe { verify_cb_cert(ctx, x, depth, err) }) == 0
    };
    // SAFETY: the caller's certificate.
    let nb = unsafe { X509_get0_notBefore(x) };
    // SAFETY: its time; the time, or NULL for now.
    let i = unsafe { X509_cmp_time(nb, ptime) };
    if i >= 0 && depth < 0 {
        return 0;
    }
    if i == 0 && rejects(X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD) {
        return 0;
    }
    if i > 0 && rejects(X509_V_ERR_CERT_NOT_YET_VALID) {
        return 0;
    }
    // SAFETY: as above.
    let na = unsafe { X509_get0_notAfter(x) };
    // SAFETY: as above.
    let i = unsafe { X509_cmp_time(na, ptime) };
    if i <= 0 && depth < 0 {
        return 0;
    }
    if i == 0 && rejects(X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD) {
        return 0;
    }
    if i < 0 && rejects(X509_V_ERR_CERT_HAS_EXPIRED) {
        return 0;
    }
    1
}

/// A flag of `x509_vfy.h` (all positive) as the parameters' `unsigned long`.
fn flag(v: c_int) -> c_ulong {
    c_ulong::from(v.cast_unsigned())
}

ffi_export! {
    /// Compares the times with the parameters' (now, the time set, or none with
    /// `X509_V_FLAG_NO_CHECK_TIME`): 1 if past `end`, -1 if before `start`, else 0 (also for no
    /// times).
    ///
    /// # Safety
    /// `vpm` is NULL or live parameters; `start` and `end` are NULL or live times.
    pub unsafe extern "C" fn X509_cmp_timeframe(vpm: *const X509_VERIFY_PARAM, start: *const ASN1_TIME, end: *const ASN1_TIME) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let p = unsafe { vpm.cast::<Param>().as_ref() };
        let flags = p.map_or(0, |p| p.flags);
        let mut ref_time = p.map_or(0, |p| p.check_time);
        let time: *mut time_t = if flags & flag(X509_V_FLAG_USE_CHECK_TIME) != 0 {
            &raw mut ref_time
        } else if flags & flag(X509_V_FLAG_NO_CHECK_TIME) != 0 {
            return 0;
        } else {
            ptr::null_mut()
        };
        // SAFETY: the caller's time; the reference time, or NULL for now.
        if !end.is_null() && unsafe { X509_cmp_time(end, time) } < 0 {
            return 1;
        }
        // SAFETY: as above.
        if !start.is_null() && unsafe { X509_cmp_time(start, time) } > 0 {
            return -1;
        }
        0
    }
}

// Searching the store (`x509_lu.c`).

/// `ossl_x509_store_ctx_get_by_subject`: the store's object of `type_` named `name` (sorting
/// its objects), or the first lookup's that finds one (and, for CRLs, a lookup's first), into
/// `ret` with a reference: 1, 0 for none, -1 on failure.
///
/// # Safety
/// `ctx` is a live context; `name` is NULL or a live name; `ret` is NULL or a live object.
pub(crate) unsafe fn get_by_subject(
    ctx: *const X509_STORE_CTX,
    type_: X509_LOOKUP_TYPE,
    name: *const X509_NAME,
    ret: *mut X509_OBJECT,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return 0;
    };
    let (xs, libctx, propq) = (c.store, c.libctx, c.propq.cast_const());
    // SAFETY: the context's store, or NULL.
    let Some(s) = (unsafe { store(xs) }) else {
        return 0;
    };
    // SAFETY: the store, which the caller doesn't hold locked.
    if !unsafe { read_lock(s) } {
        return 0;
    }
    // SAFETY: the store's objects, under its lock.
    if unsafe { OPENSSL_sk_is_sorted(s.objs.cast()) } == 0 {
        // SAFETY: as above.
        unsafe { CRYPTO_THREAD_unlock(s.lock) };
        // SAFETY: the store's lock, to sort.
        if unsafe { CRYPTO_THREAD_write_lock(s.lock) } == 0 {
            return 0;
        }
        // SAFETY: the store's objects, under its lock.
        unsafe { OPENSSL_sk_sort(s.objs.cast()) };
    }
    // SAFETY: as above.
    let mut tmp = unsafe { X509_OBJECT_retrieve_by_subject(s.objs, type_, name) }.cast::<Object>();
    // SAFETY: as above.
    unsafe { CRYPTO_THREAD_unlock(s.lock) };
    let mut stmp = Object {
        type_: rustyssl_abi::X509_LU_NONE,
        data: ptr::null_mut(),
    };
    if tmp.is_null() || type_ == X509_LU_CRL {
        // SAFETY: the store's lookups.
        let n = unsafe { OPENSSL_sk_num(s.lookups) };
        for i in 0..n {
            // SAFETY: an index within the stack.
            let lu = unsafe { OPENSSL_sk_value(s.lookups, i) }.cast::<X509_LOOKUP>();
            // SAFETY: a lookup of the store.
            if unsafe { skip_of(lu) } {
                continue;
            }
            // SAFETY: as above.
            if unsafe { super::lookup::method_of(lu) }.is_null() {
                return -1;
            }
            let sp: *mut Object = &raw mut stmp;
            // SAFETY: as above; the caller's name; a local object; the context's library
            // context.
            if unsafe { X509_LOOKUP_by_subject_ex(lu, type_, name, sp.cast(), libctx, propq) } != 0
            {
                tmp = sp;
                break;
            }
        }
        if tmp.is_null() {
            return 0;
        }
    }
    if !ret.is_null() {
        // SAFETY: the object found, the store's or the lookup's (borrowing the store's).
        if unsafe { X509_OBJECT_up_ref_count(tmp.cast()) } == 0 {
            return -1;
        }
        // SAFETY: as above; the caller's object.
        let (Some(t), Some(r)) = (unsafe { tmp.as_ref() }, unsafe {
            ret.cast::<Object>().as_mut()
        }) else {
            return -1;
        };
        r.type_ = t.type_;
        r.data = t.data;
    }
    1
}

ffi_export! {
    /// Finds an object of `type_` named `name` in the store or its lookups, into `ret` with a
    /// reference: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `name` is NULL or a live name; `ret` is NULL or a live
    /// object.
    pub unsafe extern "C" fn X509_STORE_CTX_get_by_subject(ctx: *const X509_STORE_CTX, type_: X509_LOOKUP_TYPE, name: *const X509_NAME, ret: *mut X509_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { get_by_subject(ctx, type_, name, ret) } > 0)
    }
}

ffi_export! {
    /// A new object holding what `X509_STORE_CTX_get_by_subject` finds, or NULL.
    ///
    /// # Safety
    /// As for [`X509_STORE_CTX_get_by_subject`].
    pub unsafe extern "C" fn X509_STORE_CTX_get_obj_by_subject(ctx: *mut X509_STORE_CTX, type_: X509_LOOKUP_TYPE, name: *const X509_NAME) -> *mut X509_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let ret = unsafe { X509_OBJECT_new() };
        if ret.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee; the new object.
        if unsafe { X509_STORE_CTX_get_by_subject(ctx, type_, name, ret) } == 0 {
            // SAFETY: made above.
            unsafe { X509_OBJECT_free(ret) };
            return ptr::null_mut();
        }
        ret
    }
}

ffi_export! {
    /// The store's certificates named `nm` (looked up if it has none), each with a reference;
    /// an empty list for none (or no store); NULL on failure.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `nm` is NULL or a live name.
    pub unsafe extern "C" fn X509_STORE_CTX_get1_certs(ctx: *mut X509_STORE_CTX, nm: *const X509_NAME) -> *mut stack_st_X509
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return ptr::null_mut() };
        let xs = c.store;
        // SAFETY: the context's store, or NULL.
        let Some(s) = (unsafe { store(xs) }) else {
            // SAFETY: no preconditions.
            return unsafe { OPENSSL_sk_new_null() }.cast();
        };
        let mut cnt = 0;
        // SAFETY: the store's lock.
        if unsafe { CRYPTO_THREAD_write_lock(s.lock) } == 0 {
            return ptr::null_mut();
        }
        // SAFETY: the store's objects, under its lock.
        unsafe { OPENSSL_sk_sort(s.objs.cast()) };
        // SAFETY: as above; the caller's name; a local.
        let mut idx = unsafe { idx_cnt(s.objs, X509_LU_X509, nm, &raw mut cnt) };
        if idx < 0 {
            // SAFETY: as above.
            unsafe { CRYPTO_THREAD_unlock(s.lock) };
            // SAFETY: the caller's context and name.
            let i = unsafe { get_by_subject(ctx, X509_LU_X509, nm, ptr::null_mut()) };
            if i <= 0 {
                return if i < 0 {
                    ptr::null_mut()
                } else {
                    // SAFETY: no preconditions.
                    unsafe { OPENSSL_sk_new_null() }.cast()
                };
            }
            // SAFETY: as above.
            if unsafe { CRYPTO_THREAD_write_lock(s.lock) } == 0 {
                return ptr::null_mut();
            }
            // SAFETY: as above.
            unsafe { OPENSSL_sk_sort(s.objs.cast()) };
            // SAFETY: as above.
            idx = unsafe { idx_cnt(s.objs, X509_LU_X509, nm, &raw mut cnt) };
        }
        // SAFETY: no preconditions.
        let sk = unsafe { OPENSSL_sk_new_null() }.cast::<stack_st_X509>();
        if idx >= 0 && !sk.is_null() {
            let flags = c_int::try_from(X509_ADD_FLAG_UP_REF).unwrap_or(0);
            for i in idx..idx.saturating_add(cnt) {
                // SAFETY: an index within the store's objects, a certificate's.
                let obj = unsafe { OPENSSL_sk_value(s.objs.cast(), i) }.cast::<Object>();
                // SAFETY: as above.
                let Some(o) = (unsafe { obj.as_ref() }) else { continue };
                // SAFETY: the new list; the object's certificate.
                if unsafe { X509_add_cert(sk, o.data.cast(), flags) } == 0 {
                    // SAFETY: as above.
                    unsafe { CRYPTO_THREAD_unlock(s.lock) };
                    // SAFETY: the new list and its references.
                    unsafe { OSSL_STACK_OF_X509_free(sk) };
                    return ptr::null_mut();
                }
            }
        }
        // SAFETY: as above.
        unsafe { CRYPTO_THREAD_unlock(s.lock) };
        sk
    }
}

/// `X509_CRL_free` as a stack's free function.
pub(crate) unsafe extern "C" fn crl_free(c: *mut c_void) {
    // SAFETY: a CRL of the stack, which the stack held a reference to.
    unsafe { X509_CRL_free(c.cast()) };
}

ffi_export! {
    /// The store's CRLs issued by `nm` (after looking them up), each with a reference; an empty
    /// list for none; NULL on failure.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `nm` is NULL or a live name.
    pub unsafe extern "C" fn X509_STORE_CTX_get1_crls(ctx: *const X509_STORE_CTX, nm: *const X509_NAME) -> *mut stack_st_X509_CRL
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let i = unsafe { get_by_subject(ctx, X509_LU_CRL, nm, ptr::null_mut()) };
        if i < 0 {
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let sk = unsafe { OPENSSL_sk_new_null() };
        if i == 0 {
            return sk.cast();
        }
        // SAFETY: as above, found through the context's store.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return sk.cast() };
        // SAFETY: as above.
        let Some(s) = (unsafe { store(c.store) }) else { return sk.cast() };
        // SAFETY: the store's lock.
        if unsafe { CRYPTO_THREAD_write_lock(s.lock) } == 0 {
            // SAFETY: the new list.
            unsafe { OPENSSL_sk_free(sk) };
            return ptr::null_mut();
        }
        // SAFETY: the store's objects, under its lock.
        unsafe { OPENSSL_sk_sort(s.objs.cast()) };
        let mut cnt = 0;
        // SAFETY: as above; the caller's name; a local.
        let idx = unsafe { idx_cnt(s.objs, X509_LU_CRL, nm, &raw mut cnt) };
        if idx >= 0 {
            for j in idx..idx.saturating_add(cnt) {
                // SAFETY: an index within the store's objects, a CRL's.
                let obj = unsafe { OPENSSL_sk_value(s.objs.cast(), j) }.cast::<Object>();
                // SAFETY: as above.
                let Some(o) = (unsafe { obj.as_ref() }) else { continue };
                let x = o.data.cast::<X509_CRL>();
                // SAFETY: the object's CRL; the new list.
                let pushed = unsafe { X509_CRL_up_ref(x) } != 0 && unsafe { OPENSSL_sk_push(sk, x.cast()) } != 0;
                if !pushed {
                    // SAFETY: as above.
                    unsafe { CRYPTO_THREAD_unlock(s.lock) };
                    // SAFETY: the new list and its references.
                    unsafe { crate::stack::OPENSSL_sk_pop_free(sk, Some(crl_free)) };
                    return ptr::null_mut();
                }
            }
        }
        // SAFETY: as above.
        unsafe { CRYPTO_THREAD_unlock(s.lock) };
        sk.cast()
    }
}

// Issuers.

/// `sk_X509_contains`: whether the list holds a certificate equal to `cert` (`X509_cmp`).
///
/// # Safety
/// `sk` is NULL or a live list of certificates; `cert` is a live certificate.
unsafe fn contains(sk: *const stack_st_X509, cert: *mut X509) -> bool {
    // SAFETY: the caller's guarantee.
    let n = unsafe { OPENSSL_sk_num(sk.cast()) };
    (0..n).any(|i| {
        // SAFETY: an index within the list.
        let other = unsafe { OPENSSL_sk_value(sk.cast(), i) };
        // SAFETY: a certificate of the list; the caller's certificate.
        unsafe { super::purpose::X509_cmp(other.cast(), cert) == 0 }
    })
}

/// `get0_best_issuer_sk`: the first certificate of `sk` that issued `x` (the context's
/// `check_issued`) and is valid now; failing that, the one of them that expires last. With
/// `no_dup`, those in the chain are skipped (unless `x` is self-issued and alone in it).
///
/// # Safety
/// `ctx` is a live context; `sk` is NULL or a live list of certificates; `x` is a live
/// certificate.
pub(crate) unsafe fn best_issuer_sk(
    ctx: *mut X509_STORE_CTX,
    check_signing_allowed: bool,
    no_dup: bool,
    sk: *const stack_st_X509,
    x: *mut X509,
) -> *mut X509 {
    let mut issuer: *mut X509 = ptr::null_mut();
    // SAFETY: the caller's guarantee.
    let n = unsafe { OPENSSL_sk_num(sk.cast()) };
    for i in 0..n {
        // SAFETY: an index within the list.
        let candidate = unsafe { OPENSSL_sk_value(sk.cast(), i) }.cast::<X509>();
        // SAFETY: the caller's context.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            return ptr::null_mut();
        };
        let (chain, check) = (c.chain, c.check_issued);
        if no_dup {
            // SAFETY: the caller's certificate; the context's chain.
            let si_alone = unsafe { super::purpose::self_issued(x) }
                && unsafe { OPENSSL_sk_num(chain.cast()) } == 1;
            // SAFETY: as above.
            if !si_alone && unsafe { contains(chain, candidate) } {
                continue;
            }
        }
        // SAFETY: the context's function, with its certificates.
        if check.is_some_and(|f| unsafe { f(ctx, x, candidate) } != 0) {
            // SAFETY: the certificates.
            let allowed = || unsafe { super::purpose::signing_allowed(candidate, x) } == X509_V_OK;
            if check_signing_allowed && !allowed() {
                continue;
            }
            // SAFETY: the context; a candidate.
            if unsafe { check_cert_time(ctx, candidate, -1) } != 0 {
                return candidate;
            }
            let later_end = issuer.is_null() || {
                // SAFETY: a candidate.
                let a = unsafe { X509_get0_notAfter(candidate) };
                // SAFETY: the issuer kept.
                let b = unsafe { X509_get0_notAfter(issuer) };
                // SAFETY: their times.
                (unsafe { crate::asn1::time::ASN1_TIME_compare(a, b) }) > 0
            };
            if later_end {
                issuer = candidate;
            }
        }
    }
    issuer
}

ffi_export! {
    /// Finds `x`'s issuer in the store (by its issuer name), into `*issuer` with a reference:
    /// one valid now first, else the one that expires last. 1, 0 for none, -1 on failure.
    ///
    /// # Safety
    /// `issuer` is writable; `ctx` is NULL or a live context; `x` is NULL or a live
    /// certificate.
    pub unsafe extern "C" fn X509_STORE_CTX_get1_issuer(issuer: *mut *mut X509, ctx: *mut X509_STORE_CTX, x: *mut X509) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        if issuer.is_null() {
            return -1;
        }
        // SAFETY: the caller's slot.
        unsafe { *issuer = ptr::null_mut() };
        // SAFETY: the caller's certificate, or NULL.
        let xn = unsafe { X509_get_issuer_name(x) };
        // SAFETY: no preconditions.
        let obj = unsafe { X509_OBJECT_new() };
        if obj.is_null() {
            return -1;
        }
        // SAFETY: the caller's context; the name; the new object.
        let mut ret = unsafe { get_by_subject(ctx, X509_LU_X509, xn, obj) };
        if ret == 1 {
            // SAFETY: the object found.
            let found = unsafe { obj.cast::<Object>().as_mut() }.map_or(ptr::null_mut(), |o| o.data.cast::<X509>());
            // SAFETY: the caller's context.
            let check = unsafe { ctx_of(ctx) }.and_then(|c| c.check_issued);
            // SAFETY: the context's function; the certificates.
            let issued = check.is_some_and(|f| unsafe { f(ctx, x, found) } != 0);
            // SAFETY: the context; the certificate found.
            if issued && unsafe { check_cert_time(ctx, found, -1) } != 0 {
                // SAFETY: the caller's slot, which takes the object's reference.
                unsafe { *issuer = found };
                // SAFETY: as above.
                if let Some(o) = unsafe { obj.cast::<Object>().as_mut() } {
                    o.type_ = rustyssl_abi::X509_LU_NONE;
                }
            } else {
                ret = -1;
                // SAFETY: the caller's context and name.
                let certs = unsafe { X509_STORE_CTX_get1_certs(ctx, xn) };
                if !certs.is_null() {
                    // SAFETY: the context; the list; the certificate.
                    let best = unsafe { best_issuer_sk(ctx, false, false, certs, x) };
                    ret = 0;
                    if !best.is_null() {
                        // SAFETY: a certificate of the list.
                        ret = if unsafe { X509_up_ref(best) } != 0 { 1 } else { -1 };
                        // SAFETY: as above.
                        unsafe { *issuer = best };
                    }
                    // SAFETY: the list and its references.
                    unsafe { OSSL_STACK_OF_X509_free(certs) };
                }
            }
        }
        // SAFETY: made above.
        unsafe { X509_OBJECT_free(obj) };
        ret
    }
}

/// `get1_best_issuer_other_sk`: the issuer from the trusted list (`X509_STORE_CTX_set0_trusted_stack`).
unsafe extern "C" fn best_issuer_other_sk(
    issuer: *mut *mut X509,
    ctx: *mut X509_STORE_CTX,
    x: *mut X509,
) -> c_int {
    crate::ffi::guard(
        ERR_LIB_X509,
        "get1_best_issuer_other_sk",
        || -1,
        move || {
            // SAFETY: the context.
            let Some(c) = (unsafe { ctx_of(ctx) }) else {
                return -1;
            };
            let other = c.other_ctx.cast::<stack_st_X509>();
            // SAFETY: as above; its trusted list; the certificate.
            let found = unsafe { best_issuer_sk(ctx, false, true, other, x) };
            // SAFETY: the caller's slot.
            unsafe { *issuer = found };
            if found.is_null() {
                return 0;
            }
            // SAFETY: a certificate of the list.
            if unsafe { X509_up_ref(found) } != 0 {
                1
            } else {
                -1
            }
        },
    )
}

/// `lookup_certs_sk`: the trusted list's certificates named `nm`, each with a reference.
unsafe extern "C" fn lookup_certs_sk(
    ctx: *mut X509_STORE_CTX,
    nm: *const X509_NAME,
) -> *mut stack_st_X509 {
    crate::ffi::guard(ERR_LIB_X509, "lookup_certs_sk", ptr::null_mut, move || {
        // SAFETY: no preconditions.
        let sk = unsafe { OPENSSL_sk_new_null() }.cast::<stack_st_X509>();
        // SAFETY: the context.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            return sk;
        };
        if sk.is_null() {
            return sk;
        }
        let other = c.other_ctx.cast::<stack_st_X509>();
        // SAFETY: the context's trusted list.
        let n = unsafe { OPENSSL_sk_num(other.cast()) };
        let flags = c_int::try_from(X509_ADD_FLAG_UP_REF).unwrap_or(0);
        for i in 0..n {
            // SAFETY: an index within the list.
            let x = unsafe { OPENSSL_sk_value(other.cast(), i) }.cast::<X509>();
            // SAFETY: a certificate of the list.
            let subject = unsafe { X509_get_subject_name(x) };
            // SAFETY: the caller's name; the certificate's.
            if unsafe { X509_NAME_cmp(nm, subject) } == 0
                // SAFETY: the new list; the certificate.
                && unsafe { X509_add_cert(sk, x, flags) } == 0
            {
                // SAFETY: the new list and its references.
                unsafe { OSSL_STACK_OF_X509_free(sk) };
                // SAFETY: the context.
                if let Some(c) = unsafe { ctx_of(ctx) } {
                    c.error = X509_V_ERR_OUT_OF_MEM;
                }
                return ptr::null_mut();
            }
        }
        sk
    })
}

ffi_export! {
    /// The verification's error (`X509_V_OK` for none).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get_error(ctx: *const X509_STORE_CTX) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.map_or(0, |c| c.error)
    }
}

ffi_export! {
    /// The depth of the error's certificate.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get_error_depth(ctx: *const X509_STORE_CTX) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.map_or(0, |c| c.error_depth)
    }
}

ffi_export! {
    /// The certificate being checked, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get_current_cert(ctx: *const X509_STORE_CTX) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.current_cert)
    }
}

ffi_export! {
    /// The chain built (its own list), or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get0_chain(ctx: *const X509_STORE_CTX) -> *mut stack_st_X509
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.chain)
    }
}

ffi_export! {
    /// The issuer being checked, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get0_current_issuer(ctx: *const X509_STORE_CTX) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.current_issuer)
    }
}

ffi_export! {
    /// The CRL being checked, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get0_current_crl(ctx: *const X509_STORE_CTX) -> *mut X509_CRL
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.current_crl)
    }
}

ffi_export! {
    /// The context of the verification a CRL's path is checked for, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get0_parent_ctx(ctx: *const X509_STORE_CTX) -> *mut X509_STORE_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.parent)
    }
}

ffi_export! {
    /// The certificate to verify, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get0_cert(ctx: *const X509_STORE_CTX) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.cert)
    }
}

ffi_export! {
    /// The raw public key to verify, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get0_rpk(ctx: *const X509_STORE_CTX) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.rpk)
    }
}

ffi_export! {
    /// The untrusted certificates, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get0_untrusted(ctx: *const X509_STORE_CTX) -> *mut stack_st_X509
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.untrusted)
    }
}

ffi_export! {
    /// The store, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get0_store(ctx: *const X509_STORE_CTX) -> *mut X509_STORE
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.store)
    }
}

ffi_export! {
    /// The parameters, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get0_param(ctx: *const X509_STORE_CTX) -> *mut X509_VERIFY_PARAM
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.param)
    }
}

ffi_export! {
    /// The valid policy tree, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get0_policy_tree(ctx: *const X509_STORE_CTX) -> *mut X509_POLICY_TREE
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.tree)
    }
}

ffi_export! {
    /// Whether an explicit policy is required.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get_explicit_policy(ctx: *const X509_STORE_CTX) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.map_or(0, |c| c.explicit_policy)
    }
}

ffi_export! {
    /// The number of untrusted certificates in the chain.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get_num_untrusted(ctx: *const X509_STORE_CTX) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.map_or(0, |c| c.num_untrusted)
    }
}

ffi_export! {
    /// The verification callback.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get_verify_cb(ctx: *const X509_STORE_CTX) -> X509_STORE_CTX_verify_cb
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.and_then(|c| c.verify_cb)
    }
}

ffi_export! {
    /// The verification function.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get_verify(ctx: *const X509_STORE_CTX) -> X509_STORE_CTX_verify_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.and_then(|c| c.verify)
    }
}

ffi_export! {
    /// The issuer lookup.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get_get_issuer(ctx: *const X509_STORE_CTX) -> X509_STORE_CTX_get_issuer_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.and_then(|c| c.get_issuer)
    }
}

ffi_export! {
    /// The issuer check.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get_check_issued(ctx: *const X509_STORE_CTX) -> X509_STORE_CTX_check_issued_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.and_then(|c| c.check_issued)
    }
}

ffi_export! {
    /// The revocation check.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get_check_revocation(ctx: *const X509_STORE_CTX) -> X509_STORE_CTX_check_revocation_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.and_then(|c| c.check_revocation)
    }
}

ffi_export! {
    /// The CRL lookup.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get_get_crl(ctx: *const X509_STORE_CTX) -> X509_STORE_CTX_get_crl_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.and_then(|c| c.get_crl)
    }
}

ffi_export! {
    /// The CRL check.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get_check_crl(ctx: *const X509_STORE_CTX) -> X509_STORE_CTX_check_crl_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.and_then(|c| c.check_crl)
    }
}

ffi_export! {
    /// The check of a certificate against a CRL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get_cert_crl(ctx: *const X509_STORE_CTX) -> X509_STORE_CTX_cert_crl_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.and_then(|c| c.cert_crl)
    }
}

ffi_export! {
    /// The policy check.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get_check_policy(ctx: *const X509_STORE_CTX) -> X509_STORE_CTX_check_policy_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.and_then(|c| c.check_policy)
    }
}

ffi_export! {
    /// The certificates lookup.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get_lookup_certs(ctx: *const X509_STORE_CTX) -> X509_STORE_CTX_lookup_certs_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.and_then(|c| c.lookup_certs)
    }
}

ffi_export! {
    /// The CRLs lookup.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get_lookup_crls(ctx: *const X509_STORE_CTX) -> X509_STORE_CTX_lookup_crls_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.and_then(|c| c.lookup_crls)
    }
}

ffi_export! {
    /// The cleanup function.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get_cleanup(ctx: *const X509_STORE_CTX) -> X509_STORE_CTX_cleanup_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx_of(ctx) }.and_then(|c| c.cleanup)
    }
}

ffi_export! {
    /// Sets the verification's error.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `err` is as the context needs.
    pub unsafe extern "C" fn X509_STORE_CTX_set_error(ctx: *mut X509_STORE_CTX, err: c_int)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            c.error = err;
        }
    }
}

ffi_export! {
    /// Sets the error's depth.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `depth` is as the context needs.
    pub unsafe extern "C" fn X509_STORE_CTX_set_error_depth(ctx: *mut X509_STORE_CTX, depth: c_int)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            c.error_depth = depth;
        }
    }
}

ffi_export! {
    /// Sets the certificate being checked.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `x` is as the context needs.
    pub unsafe extern "C" fn X509_STORE_CTX_set_current_cert(ctx: *mut X509_STORE_CTX, x: *mut X509)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            c.current_cert = x;
        }
    }
}

ffi_export! {
    /// Sets the certificate to verify (not a reference).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `x` is as the context needs.
    pub unsafe extern "C" fn X509_STORE_CTX_set_cert(ctx: *mut X509_STORE_CTX, x: *mut X509)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            c.cert = x;
        }
    }
}

ffi_export! {
    /// Sets the raw public key to verify (not a reference).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `rpk` is as the context needs.
    pub unsafe extern "C" fn X509_STORE_CTX_set0_rpk(ctx: *mut X509_STORE_CTX, rpk: *mut EVP_PKEY)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            c.rpk = rpk;
        }
    }
}

ffi_export! {
    /// Sets the CRLs to use (not a copy).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `sk` is as the context needs.
    pub unsafe extern "C" fn X509_STORE_CTX_set0_crls(ctx: *mut X509_STORE_CTX, sk: *mut stack_st_X509_CRL)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            c.crls = sk;
        }
    }
}

ffi_export! {
    /// Sets the untrusted certificates (not a copy).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `sk` is as the context needs.
    pub unsafe extern "C" fn X509_STORE_CTX_set0_untrusted(ctx: *mut X509_STORE_CTX, sk: *mut stack_st_X509)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            c.untrusted = sk;
        }
    }
}

ffi_export! {
    /// Sets the CRL reasons covered so far.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `current_reasons` is as the context needs.
    pub unsafe extern "C" fn X509_STORE_CTX_set_current_reasons(ctx: *mut X509_STORE_CTX, current_reasons: c_uint)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            c.current_reasons = current_reasons;
        }
    }
}

ffi_export! {
    /// Sets the verification callback.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `verify_cb` is as the context needs.
    pub unsafe extern "C" fn X509_STORE_CTX_set_verify_cb(ctx: *mut X509_STORE_CTX, verify_cb: X509_STORE_CTX_verify_cb)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            c.verify_cb = verify_cb;
        }
    }
}

ffi_export! {
    /// Sets the verification function.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `verify` is as the context needs.
    pub unsafe extern "C" fn X509_STORE_CTX_set_verify(ctx: *mut X509_STORE_CTX, verify: X509_STORE_CTX_verify_fn)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            c.verify = verify;
        }
    }
}

ffi_export! {
    /// Sets the CRL lookup.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `get_crl` is as the context needs.
    pub unsafe extern "C" fn X509_STORE_CTX_set_get_crl(ctx: *mut X509_STORE_CTX, get_crl: X509_STORE_CTX_get_crl_fn)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            c.get_crl = get_crl;
        }
    }
}

ffi_export! {
    /// The chain built, each with a reference (`X509_chain_up_ref`), or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get1_chain(ctx: *const X509_STORE_CTX) -> *mut stack_st_X509
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let chain = unsafe { ctx_of(ctx) }.map_or(ptr::null_mut(), |c| c.chain);
        if chain.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the context's chain.
        unsafe { X509_chain_up_ref(chain) }
    }
}

ffi_export! {
    /// Replaces the chain built (freeing the old one and its references) with `sk`, which the
    /// context takes.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `sk` is NULL or a list of certificates with references
    /// the context takes.
    pub unsafe extern "C" fn X509_STORE_CTX_set0_verified_chain(ctx: *mut X509_STORE_CTX, sk: *mut stack_st_X509)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return };
        // SAFETY: its own chain, or NULL.
        unsafe { OSSL_STACK_OF_X509_free(c.chain) };
        c.chain = sk;
    }
}

ffi_export! {
    /// Uses `sk` as the trusted certificates in place of the store's (its issuers and
    /// certificates lookups).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `sk` is NULL or a live list of certificates that
    /// outlives the context's use of it.
    pub unsafe extern "C" fn X509_STORE_CTX_set0_trusted_stack(ctx: *mut X509_STORE_CTX, sk: *mut stack_st_X509)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return };
        c.other_ctx = sk.cast();
        c.get_issuer = Some(best_issuer_other_sk);
        c.lookup_certs = Some(lookup_certs_sk);
    }
}

ffi_export! {
    /// Sets the verification depth.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_set_depth(ctx: *mut X509_STORE_CTX, depth: c_int)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            // SAFETY: the context's parameters.
            unsafe { X509_VERIFY_PARAM_set_depth(c.param, depth) };
        }
    }
}

ffi_export! {
    /// Adds verification flags.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_set_flags(ctx: *mut X509_STORE_CTX, flags: c_ulong)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            // SAFETY: the context's parameters.
            unsafe { X509_VERIFY_PARAM_set_flags(c.param, flags) };
        }
    }
}

ffi_export! {
    /// Verifies at time `t` (`flags` is unused, as in OpenSSL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_set_time(ctx: *mut X509_STORE_CTX, _flags: c_ulong, t: time_t)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            // SAFETY: the context's parameters.
            unsafe { X509_VERIFY_PARAM_set_time(c.param, t) };
        }
    }
}

ffi_export! {
    /// Replaces the parameters (freeing the old ones) with `param`, which the context takes.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `param` is NULL or parameters the context takes.
    pub unsafe extern "C" fn X509_STORE_CTX_set0_param(ctx: *mut X509_STORE_CTX, param: *mut X509_VERIFY_PARAM)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return };
        // SAFETY: its own parameters, or NULL.
        unsafe { X509_VERIFY_PARAM_free(c.param) };
        c.param = param;
    }
}

ffi_export! {
    /// Sets the DANE state to verify with (libssl's; not a reference).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `dane` is NULL or a live DANE state.
    pub unsafe extern "C" fn X509_STORE_CTX_set0_dane(ctx: *mut X509_STORE_CTX, dane: *mut SSL_DANE)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            c.dane = dane;
        }
    }
}

ffi_export! {
    /// Inherits the named parameters (`X509_VERIFY_PARAM_lookup`): 1, or 0
    /// (`X509_R_UNKNOWN_PURPOSE_ID` for an unknown name).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `name` is NULL or a C string.
    pub unsafe extern "C" fn X509_STORE_CTX_set_default(ctx: *mut X509_STORE_CTX, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let param = unsafe { X509_VERIFY_PARAM_lookup(name) };
        if param.is_null() {
            // SAFETY: as above.
            let shown = (!name.is_null()).then(|| unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned());
            let data = format!("name={}", shown.as_deref().unwrap_or("(null)"));
            err::raise_with_text(ERR_LIB_X509, X509_R_UNKNOWN_PURPOSE_ID, "X509_STORE_CTX_set_default", &data);
            return 0;
        }
        // SAFETY: as above.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        // SAFETY: the context's parameters; the named ones.
        unsafe { X509_VERIFY_PARAM_inherit(c.param, param) }
    }
}

ffi_export! {
    /// Sets the purpose and trust where the parameters have none: `purpose` (or
    /// `def_purpose`), and `trust` (or the purpose's, or the default purpose's for one
    /// without): 1, or 0 (`X509_R_UNKNOWN_PURPOSE_ID`, `X509_R_UNKNOWN_TRUST_ID`).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_purpose_inherit(ctx: *mut X509_STORE_CTX, def_purpose: c_int, purpose: c_int, trust: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        const F: &str = "X509_STORE_CTX_purpose_inherit";
        let (mut def_purpose, mut purpose, mut trust) = (def_purpose, purpose, trust);
        if purpose == 0 {
            purpose = def_purpose;
        } else if def_purpose == 0 {
            def_purpose = purpose;
        }
        if purpose != 0 {
            // SAFETY: no preconditions.
            let mut idx = unsafe { X509_PURPOSE_get_by_id(purpose) };
            if idx == -1 {
                err::raise(ERR_LIB_X509, X509_R_UNKNOWN_PURPOSE_ID, F);
                return 0;
            }
            // SAFETY: an index of the table.
            let mut ptmp = unsafe { X509_PURPOSE_get0(idx) };
            // SAFETY: a purpose of the table.
            if unsafe { X509_PURPOSE_get_trust(ptmp) } == X509_TRUST_DEFAULT {
                // SAFETY: no preconditions.
                idx = unsafe { X509_PURPOSE_get_by_id(def_purpose) };
                if idx == -1 {
                    err::raise(ERR_LIB_X509, X509_R_UNKNOWN_PURPOSE_ID, F);
                    return 0;
                }
                // SAFETY: as above.
                ptmp = unsafe { X509_PURPOSE_get0(idx) };
            }
            if trust == 0 {
                // SAFETY: as above.
                trust = unsafe { X509_PURPOSE_get_trust(ptmp) };
            }
        }
        // SAFETY: no preconditions.
        if trust != 0 && unsafe { X509_TRUST_get_by_id(trust) } == -1 {
            err::raise(ERR_LIB_X509, X509_R_UNKNOWN_TRUST_ID, F);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { ctx_of(ctx) }).and_then(|c| param(c)) else { return 0 };
        if p.purpose == 0 && purpose != 0 {
            p.purpose = purpose;
        }
        if p.trust == 0 && trust != 0 {
            p.trust = trust;
        }
        1
    }
}

ffi_export! {
    /// Sets the purpose (and its trust) where the parameters have none:
    /// `X509_STORE_CTX_purpose_inherit(ctx, 0, purpose, 0)`.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_set_purpose(ctx: *mut X509_STORE_CTX, purpose: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_STORE_CTX_purpose_inherit(ctx, 0, purpose, 0) }
    }
}

ffi_export! {
    /// Sets the trust where the parameters have none:
    /// `X509_STORE_CTX_purpose_inherit(ctx, 0, 0, trust)`.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_set_trust(ctx: *mut X509_STORE_CTX, trust: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_STORE_CTX_purpose_inherit(ctx, 0, 0, trust) }
    }
}

ffi_export! {
    /// A new, uninitialized context in the library context (a copy of `propq`), or NULL.
    ///
    /// # Safety
    /// `propq` is NULL or a C string.
    pub unsafe extern "C" fn X509_STORE_CTX_new_ex(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut X509_STORE_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        let ctx = mem::alloc_zeroed(size_of::<Ctx>()).cast::<X509_STORE_CTX>();
        // SAFETY: new and zeroed (a valid `Ctx`), or NULL.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return ptr::null_mut() };
        c.libctx = libctx;
        if !propq.is_null() {
            // SAFETY: the caller's C string.
            c.propq = unsafe { crate::string::CRYPTO_strdup(propq, ptr::null(), 0) };
            if c.propq.is_null() {
                // SAFETY: made above.
                unsafe { mem::release(ctx.cast()) };
                return ptr::null_mut();
            }
        }
        ctx
    }
}

ffi_export! {
    /// A new, uninitialized context, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn X509_STORE_CTX_new() -> *mut X509_STORE_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no property query.
        unsafe { X509_STORE_CTX_new_ex(ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Cleans the context up (`X509_STORE_CTX_cleanup`) and frees it (nothing for NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a context made by `X509_STORE_CTX_new`, not otherwise used after.
    pub unsafe extern "C" fn X509_STORE_CTX_free(ctx: *mut X509_STORE_CTX)
    where failure = (), library = ERR_LIB_X509
    {
        if ctx.is_null() {
            return;
        }
        // SAFETY: the caller's guarantee.
        unsafe { X509_STORE_CTX_cleanup(ctx) };
        // SAFETY: as above.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            // SAFETY: its own copy, or NULL.
            unsafe { mem::release(c.propq.cast()) };
        }
        // SAFETY: as above.
        unsafe { mem::release(ctx.cast()) };
    }
}

ffi_export! {
    /// Runs the cleanup function, then frees the parameters (unless a CRL path's, which are
    /// its parent's), the policy tree, the chain, and the application data. The context can be
    /// initialized again.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_cleanup(ctx: *mut X509_STORE_CTX)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return };
        if let Some(f) = c.cleanup.take() {
            // SAFETY: the context's function, with no reference into it held.
            unsafe { f(ctx) };
        }
        // SAFETY: as above, after the function.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return };
        if !c.param.is_null() {
            if c.parent.is_null() {
                // SAFETY: its own parameters.
                unsafe { X509_VERIFY_PARAM_free(c.param) };
            }
            c.param = ptr::null_mut();
        }
        // SAFETY: its own tree, or NULL.
        unsafe { crate::x509::pcy::X509_policy_tree_free(c.tree) };
        c.tree = ptr::null_mut();
        // SAFETY: its own chain, or NULL.
        unsafe { OSSL_STACK_OF_X509_free(c.chain) };
        c.chain = ptr::null_mut();
        // SAFETY: the context; its own application data.
        unsafe { CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509_STORE_CTX, ctx.cast(), &raw mut c.ex_data) };
        // SAFETY: an all-zero `CRYPTO_EX_DATA` is the empty one.
        c.ex_data = unsafe { core::mem::zeroed() };
    }
}

ffi_export! {
    /// Sets the context up to verify `x509` (with the untrusted `chain`) against `store`: the
    /// store's callbacks or the defaults, and new parameters inheriting the store's and then
    /// the "default" ones: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `store`, `x509`, and `chain` are NULL or live and
    /// outlive the verification.
    pub unsafe extern "C" fn X509_STORE_CTX_init(ctx: *mut X509_STORE_CTX, store: *mut X509_STORE, x509: *mut X509, chain: *mut stack_st_X509) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        const F: &str = "X509_STORE_CTX_init";
        if ctx.is_null() {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        }
        // SAFETY: the caller's context.
        unsafe { X509_STORE_CTX_cleanup(ctx) };
        // SAFETY: as above.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        c.store = store;
        c.cert = x509;
        c.untrusted = chain;
        c.crls = ptr::null_mut();
        c.num_untrusted = 0;
        c.other_ctx = ptr::null_mut();
        c.valid = 0;
        c.chain = ptr::null_mut();
        c.error = X509_V_OK;
        c.explicit_policy = 0;
        c.error_depth = 0;
        c.current_cert = ptr::null_mut();
        c.current_issuer = ptr::null_mut();
        c.current_crl = ptr::null_mut();
        c.current_crl_score = 0;
        c.current_reasons = 0;
        c.tree = ptr::null_mut();
        c.parent = ptr::null_mut();
        c.dane = ptr::null_mut();
        c.bare_ta_signed = 0;
        c.rpk = ptr::null_mut();
        // SAFETY: an all-zero `CRYPTO_EX_DATA` is the empty one.
        c.ex_data = unsafe { core::mem::zeroed() };
        // SAFETY: the caller's store, or NULL.
        let cb = unsafe { super::store::store(store) }.map(super::store::Store::callbacks).unwrap_or_default();
        c.cleanup = cb.cleanup;
        c.check_issued = cb.check_issued.or(Some(check_issued));
        c.get_issuer = cb.get_issuer.or(Some(X509_STORE_CTX_get1_issuer));
        c.verify_cb = cb.verify_cb.or(Some(null_callback));
        c.verify = cb.verify.or(Some(super::verify::internal_verify));
        c.check_revocation = cb.check_revocation.or(Some(super::revoke::check_revocation));
        c.get_crl = cb.get_crl;
        c.check_crl = cb.check_crl.or(Some(super::revoke::check_crl));
        c.cert_crl = cb.cert_crl.or(Some(super::revoke::cert_crl));
        c.check_policy = cb.check_policy.or(Some(super::pcy::check_policy));
        c.lookup_certs = cb.lookup_certs.or(Some(X509_STORE_CTX_get1_certs));
        c.lookup_crls = cb.lookup_crls.or(Some(X509_STORE_CTX_get1_crls));
        // SAFETY: no preconditions.
        c.param = unsafe { X509_VERIFY_PARAM_new() };
        let fail = || {
            // SAFETY: the caller's context.
            unsafe { X509_STORE_CTX_cleanup(ctx) };
            0
        };
        let Some(p) = param(c) else {
            err::raise(ERR_LIB_X509, ERR_R_ASN1_LIB, F);
            return fail();
        };
        if store.is_null() {
            p.inh_flags |= (X509_VP_FLAG_DEFAULT | X509_VP_FLAG_ONCE).cast_unsigned();
        } else {
            // SAFETY: the caller's store.
            let from = unsafe { X509_STORE_get0_param(store) };
            // SAFETY: the new parameters; the store's.
            if unsafe { X509_VERIFY_PARAM_inherit(c.param, from) } == 0 {
                return fail();
            }
        }
        // SAFETY: the caller's context; a static name.
        if unsafe { X509_STORE_CTX_set_default(ctx, c"default".as_ptr()) } == 0 {
            return fail();
        }
        // SAFETY: as above.
        let Some(p) = (unsafe { ctx_of(ctx) }).and_then(|c| param(c)) else { return fail() };
        if p.trust == X509_TRUST_DEFAULT {
            // SAFETY: no preconditions.
            let idx = unsafe { X509_PURPOSE_get_by_id(p.purpose) };
            // SAFETY: an index of the table, or -1.
            let xp = unsafe { X509_PURPOSE_get0(idx) };
            if !xp.is_null() {
                // SAFETY: a purpose of the table.
                p.trust = unsafe { X509_PURPOSE_get_trust(xp) };
            }
        }
        // SAFETY: as above.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return fail() };
        // SAFETY: the context; its own application data.
        if unsafe { CRYPTO_new_ex_data(CRYPTO_EX_INDEX_X509_STORE_CTX, ctx.cast(), &raw mut c.ex_data) } != 0 {
            return 1;
        }
        err::raise(ERR_LIB_X509, ERR_R_CRYPTO_LIB, F);
        fail()
    }
}

ffi_export! {
    /// Sets the context up to verify the raw public key `rpk` against `store`: 1, or 0.
    ///
    /// # Safety
    /// As for [`X509_STORE_CTX_init`]; `rpk` is NULL or a live key.
    pub unsafe extern "C" fn X509_STORE_CTX_init_rpk(ctx: *mut X509_STORE_CTX, store: *mut X509_STORE, rpk: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if unsafe { X509_STORE_CTX_init(ctx, store, ptr::null_mut(), ptr::null_mut()) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        if let Some(c) = unsafe { ctx_of(ctx) } {
            c.rpk = rpk;
        }
        1
    }
}

ffi_export! {
    /// Sets the application's data at `idx`: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_set_ex_data(ctx: *mut X509_STORE_CTX, idx: c_int, data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        // SAFETY: its application data.
        unsafe { CRYPTO_set_ex_data(&raw mut c.ex_data, idx, data) }
    }
}

ffi_export! {
    /// The application's data at `idx`, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_get_ex_data(ctx: *const X509_STORE_CTX, idx: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return ptr::null_mut() };
        // SAFETY: its application data.
        unsafe { CRYPTO_get_ex_data(&raw const c.ex_data, idx) }
    }
}

ffi_export! {
    /// The text of verification error `n` (`x509_txt.c`'s; OpenSSL reads `n` as an `int`), or
    /// "unknown certificate verification error".
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn X509_verify_cert_error_string(n: c_long) -> *const c_char
    where failure = UNKNOWN.as_ptr(), library = ERR_LIB_X509
    {
        // `(int)n`: the low 32 bits, as two's complement.
        let low = u32::try_from(n & 0xFFFF_FFFF).unwrap_or(0);
        let code = c_int::from_ne_bytes(low.to_ne_bytes());
        VERIFY_STRINGS
            .iter()
            .find(|&&(c, _)| c == code)
            .map_or(UNKNOWN, |&(_, text)| text)
            .as_ptr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_contexts_are_safe() {
        let c: *mut X509_STORE_CTX = ptr::null_mut();
        // SAFETY: NULL where OpenSSL dereferences it.
        assert_eq!(unsafe { X509_STORE_CTX_get_error(c) }, 0);
        // SAFETY: as above.
        unsafe { X509_STORE_CTX_set_error(c, 1) };
        // SAFETY: as above.
        assert!(unsafe { X509_STORE_CTX_get0_param(c) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { X509_STORE_CTX_get_verify_cb(c) }.is_none());
        // SAFETY: as above.
        assert_eq!(unsafe { X509_STORE_CTX_set_purpose(c, 0) }, 0);
        // SAFETY: as above.
        unsafe { X509_STORE_CTX_cleanup(c) };
        let mut issuer: *mut X509 = ptr::null_mut();
        // SAFETY: as above; a local slot.
        let r = unsafe { X509_STORE_CTX_get1_issuer(&raw mut issuer, c, ptr::null_mut()) };
        assert!(r <= 0);
    }
}
