//! The certificate store (`x509_lu.c`, `x509_d2.c`): `X509_STORE`, its objects (`X509_OBJECT`,
//! a certificate or a CRL, sorted by subject or issuer name), its lookups, verification
//! parameters, callbacks, and application data; and loading files, directories, store URIs,
//! and the default paths into it. Verification itself (`X509_STORE_CTX`) comes with step 5.4.
//!
//! As OpenSSL's:
//! - Adding an object the store has (the same certificate, or a matching CRL) succeeds and
//!   keeps one.
//! - Searching sorts the objects, so the order `X509_STORE_get0_objects` shows changes.
//! - `X509_STORE_lock` takes the store's lock for writing; the store's functions take it too,
//!   so they mustn't be called while it's held.
//!
//! The types are opaque in OpenSSL's headers, so the object's layout is ours (OpenSSL's, in
//! fact).

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use rustyssl_abi::{
    CRYPTO_EX_DATA, CRYPTO_EX_INDEX_X509_STORE, CRYPTO_RWLOCK, ERR_LIB_X509, ERR_R_CRYPTO_LIB,
    ERR_R_PASSED_NULL_PARAMETER, ERR_R_X509_LIB, OPENSSL_STACK, OSSL_LIB_CTX, X509,
    X509_ADD_FLAG_UP_REF, X509_CRL, X509_FILETYPE_DEFAULT, X509_FILETYPE_PEM, X509_L_ADD_DIR,
    X509_L_ADD_STORE, X509_L_FILE_LOAD, X509_LOOKUP, X509_LOOKUP_METHOD, X509_LOOKUP_TYPE,
    X509_LU_CRL, X509_LU_NONE, X509_LU_X509, X509_NAME, X509_OBJECT, X509_STORE,
    X509_STORE_CTX_cert_crl_fn, X509_STORE_CTX_check_crl_fn, X509_STORE_CTX_check_issued_fn,
    X509_STORE_CTX_check_policy_fn, X509_STORE_CTX_check_revocation_fn, X509_STORE_CTX_cleanup_fn,
    X509_STORE_CTX_get_crl_fn, X509_STORE_CTX_get_issuer_fn, X509_STORE_CTX_lookup_certs_fn,
    X509_STORE_CTX_lookup_crls_fn, X509_STORE_CTX_verify_cb, X509_STORE_CTX_verify_fn,
    X509_VERIFY_PARAM, stack_st_X509, stack_st_X509_OBJECT,
};

use super::cert::{X509_free, X509_get_subject_name, X509_up_ref};
use super::crl::{X509_CRL_free, X509_CRL_get_issuer, X509_CRL_match, X509_CRL_up_ref};
use super::lookup::{
    X509_LOOKUP_ctrl, X509_LOOKUP_ctrl_ex, X509_LOOKUP_free, X509_LOOKUP_new, X509_LOOKUP_shutdown,
    dir_method, file_method, set_store, store_method,
};
use super::name::X509_NAME_cmp;
use super::purpose::{X509_add_cert, X509_cmp};
use super::vpm::{
    X509_VERIFY_PARAM_free, X509_VERIFY_PARAM_new, X509_VERIFY_PARAM_set_depth,
    X509_VERIFY_PARAM_set_flags, X509_VERIFY_PARAM_set_purpose, X509_VERIFY_PARAM_set_trust,
    X509_VERIFY_PARAM_set1,
};
use crate::err;
use crate::err::ERR_clear_error;
use crate::ex_data::{
    CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data, CRYPTO_set_ex_data,
};
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::mem;
use crate::stack::{
    OPENSSL_sk_deep_copy, OPENSSL_sk_find, OPENSSL_sk_find_all, OPENSSL_sk_free, OPENSSL_sk_new,
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_sort,
    OPENSSL_sk_value,
};
use crate::threads::{
    CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CRYPTO_THREAD_read_lock, CRYPTO_THREAD_unlock,
    CRYPTO_THREAD_write_lock,
};

// Objects.

/// `struct x509_object_st`.
#[repr(C)]
pub(crate) struct Object {
    pub(crate) type_: X509_LOOKUP_TYPE,
    /// The certificate or CRL, as `type_` says.
    pub(crate) data: *mut c_void,
}

/// Marks a search key: an object whose data is the name searched for (OpenSSL's on-stack
/// certificate or CRL holding only the name).
const KEY: X509_LOOKUP_TYPE = 0x100;

/// A search key for the objects of `type_` named `name`.
pub(crate) fn key(type_: X509_LOOKUP_TYPE, name: *const X509_NAME) -> Object {
    Object {
        type_: type_ | KEY,
        data: name.cast_mut().cast(),
    }
}

/// The type an object sorts by, and its name: a certificate's subject, a CRL's issuer.
///
/// # Safety
/// `o` is a live object or key.
unsafe fn sort_key(o: &Object) -> (X509_LOOKUP_TYPE, *const X509_NAME) {
    if o.type_ & KEY != 0 {
        return (o.type_ & !KEY, o.data.cast_const().cast());
    }
    let name = match o.type_ {
        // SAFETY: the object's certificate.
        X509_LU_X509 => unsafe { X509_get_subject_name(o.data.cast()) }.cast_const(),
        // SAFETY: the object's CRL.
        X509_LU_CRL => unsafe { X509_CRL_get_issuer(o.data.cast()) }.cast_const(),
        _ => ptr::null(),
    };
    (o.type_, name)
}

/// `x509_object_cmp`, as a stack's comparison: by type, then name.
///
/// # Safety
/// `a` and `b` point to live objects' pointers.
pub(crate) unsafe extern "C" fn object_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the stack's elements.
    let pa = unsafe { *a.cast::<*const Object>() };
    // SAFETY: as above.
    let pb = unsafe { *b.cast::<*const Object>() };
    // SAFETY: live objects.
    let (Some(oa), Some(ob)) = (unsafe { pa.as_ref() }, unsafe { pb.as_ref() }) else {
        return 0;
    };
    // SAFETY: as above.
    let (ta, na) = unsafe { sort_key(oa) };
    // SAFETY: as above.
    let (tb, nb) = unsafe { sort_key(ob) };
    match ta.cmp(&tb) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Greater => 1,
        // SAFETY: the objects' names.
        _ if ta == X509_LU_X509 || ta == X509_LU_CRL => unsafe { X509_NAME_cmp(na, nb) },
        _ => 0,
    }
}

/// The caller's object, or `None` for NULL.
///
/// # Safety
/// `a` is NULL or a live object.
unsafe fn object<'a>(a: *const X509_OBJECT) -> Option<&'a mut Object> {
    // SAFETY: the caller's guarantee.
    unsafe { a.cast::<Object>().cast_mut().as_mut() }
}

ffi_export! {
    /// A new object of no type (`X509_LU_NONE`), or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn X509_OBJECT_new() -> *mut X509_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        mem::alloc_zeroed(size_of::<Object>()).cast()
    }
}

/// `x509_object_free_internal`: drops the object's reference to its certificate or CRL.
fn release(a: &mut Object) {
    match a.type_ {
        // SAFETY: the object's certificate, whose reference it holds.
        X509_LU_X509 => unsafe { X509_free(a.data.cast()) },
        // SAFETY: the object's CRL, whose reference it holds.
        X509_LU_CRL => unsafe { X509_CRL_free(a.data.cast()) },
        _ => {}
    }
}

ffi_export! {
    /// Frees the object and its reference to its certificate or CRL (nothing for NULL).
    ///
    /// # Safety
    /// `a` is NULL or an object made by `X509_OBJECT_new`, not otherwise used after.
    pub unsafe extern "C" fn X509_OBJECT_free(a: *mut X509_OBJECT)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(o) = unsafe { object(a) } {
            release(o);
        }
        // SAFETY: as above.
        unsafe { mem::release(a.cast()) };
    }
}

/// `X509_OBJECT_free` as a stack's free function.
pub(crate) unsafe extern "C" fn object_free(a: *mut c_void) {
    // SAFETY: an object of the stack, which the stack owned.
    unsafe { X509_OBJECT_free(a.cast()) };
}

ffi_export! {
    /// Adds a reference to the object's certificate or CRL: 1, or 0 (1 for no type).
    ///
    /// # Safety
    /// `a` is NULL or a live object.
    pub unsafe extern "C" fn X509_OBJECT_up_ref_count(a: *mut X509_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(o) = (unsafe { object(a) }) else { return 0 };
        match o.type_ {
            // SAFETY: the object's certificate.
            X509_LU_X509 => unsafe { X509_up_ref(o.data.cast()) },
            // SAFETY: the object's CRL.
            X509_LU_CRL => unsafe { X509_CRL_up_ref(o.data.cast()) },
            _ => 1,
        }
    }
}

ffi_export! {
    /// The object's certificate, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live object.
    pub unsafe extern "C" fn X509_OBJECT_get0_X509(a: *const X509_OBJECT) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        match unsafe { object(a) } {
            Some(o) if o.type_ == X509_LU_X509 => o.data.cast(),
            _ => ptr::null_mut(),
        }
    }
}

ffi_export! {
    /// The object's CRL, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live object.
    pub unsafe extern "C" fn X509_OBJECT_get0_X509_CRL(a: *const X509_OBJECT) -> *mut X509_CRL
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        match unsafe { object(a) } {
            Some(o) if o.type_ == X509_LU_CRL => o.data.cast(),
            _ => ptr::null_mut(),
        }
    }
}

ffi_export! {
    /// The object's type (`X509_LU_NONE` for NULL).
    ///
    /// # Safety
    /// `a` is NULL or a live object.
    pub unsafe extern "C" fn X509_OBJECT_get_type(a: *const X509_OBJECT) -> X509_LOOKUP_TYPE
    where failure = X509_LU_NONE, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { object(a) }.map_or(X509_LU_NONE, |o| o.type_)
    }
}

ffi_export! {
    /// Makes the object hold a reference to the certificate, dropping what it held: 1, or 0.
    ///
    /// # Safety
    /// `a` is NULL or a live object; `obj` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_OBJECT_set1_X509(a: *mut X509_OBJECT, obj: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(o) = (unsafe { object(a) }) else { return 0 };
        // SAFETY: as above.
        if unsafe { X509_up_ref(obj) } == 0 {
            return 0;
        }
        release(o);
        o.type_ = X509_LU_X509;
        o.data = obj.cast();
        1
    }
}

ffi_export! {
    /// Makes the object hold a reference to the CRL, dropping what it held: 1, or 0.
    ///
    /// # Safety
    /// `a` is NULL or a live object; `obj` is NULL or a live CRL.
    pub unsafe extern "C" fn X509_OBJECT_set1_X509_CRL(a: *mut X509_OBJECT, obj: *mut X509_CRL) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(o) = (unsafe { object(a) }) else { return 0 };
        // SAFETY: as above.
        if unsafe { X509_CRL_up_ref(obj) } == 0 {
            return 0;
        }
        release(o);
        o.type_ = X509_LU_CRL;
        o.data = obj.cast();
        1
    }
}

/// `x509_object_idx_cnt`: the index of the first object of `type_` named `name` (sorting the
/// stack), and their count; -1 for none or another type.
///
/// # Safety
/// `h` is NULL or a live stack of objects; `name` is NULL or a live name.
pub(crate) unsafe fn idx_cnt(
    h: *mut stack_st_X509_OBJECT,
    type_: X509_LOOKUP_TYPE,
    name: *const X509_NAME,
    pnmatch: *mut c_int,
) -> c_int {
    if type_ != X509_LU_X509 && type_ != X509_LU_CRL {
        return -1;
    }
    let k = key(type_, name);
    let kp: *const Object = &raw const k;
    // SAFETY: the caller's stack; a pointer to the key, as its elements are pointers.
    unsafe { OPENSSL_sk_find_all(h.cast(), kp.cast(), pnmatch) }
}

ffi_export! {
    /// The index of the first object of `type_` named `name` (sorting the stack), or -1.
    ///
    /// # Safety
    /// `h` is NULL or a live stack of objects; `name` is NULL or a live name.
    pub unsafe extern "C" fn X509_OBJECT_idx_by_subject(h: *mut stack_st_X509_OBJECT, type_: X509_LOOKUP_TYPE, name: *const X509_NAME) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee; no count.
        unsafe { idx_cnt(h, type_, name, ptr::null_mut()) }
    }
}

ffi_export! {
    /// The first object of `type_` named `name` (sorting the stack), or NULL.
    ///
    /// # Safety
    /// As for [`X509_OBJECT_idx_by_subject`].
    pub unsafe extern "C" fn X509_OBJECT_retrieve_by_subject(h: *mut stack_st_X509_OBJECT, type_: X509_LOOKUP_TYPE, name: *const X509_NAME) -> *mut X509_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let idx = unsafe { X509_OBJECT_idx_by_subject(h, type_, name) };
        if idx == -1 {
            return ptr::null_mut();
        }
        // SAFETY: as above; an index within the stack.
        unsafe { OPENSSL_sk_value(h.cast(), idx) }.cast()
    }
}

ffi_export! {
    /// The stack's object that's the same certificate as `x`'s (`X509_cmp`), or a CRL that
    /// matches its (`X509_CRL_match`); for another type, the first of its type; or NULL.
    ///
    /// # Safety
    /// `h` is NULL or a live stack of objects; `x` is NULL or a live object.
    pub unsafe extern "C" fn X509_OBJECT_retrieve_match(h: *mut stack_st_X509_OBJECT, x: *mut X509_OBJECT) -> *mut X509_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(xo) = (unsafe { object(x) }) else { return ptr::null_mut() };
        let (xt, xd) = (xo.type_, xo.data);
        let xp: *const *mut X509_OBJECT = &raw const x;
        // SAFETY: the caller's stack; a pointer to the object's pointer, as its elements are.
        let idx = unsafe { OPENSSL_sk_find(h.cast(), x.cast()) };
        if idx < 0 {
            return ptr::null_mut();
        }
        if xt != X509_LU_X509 && xt != X509_LU_CRL {
            // SAFETY: an index within the stack.
            return unsafe { OPENSSL_sk_value(h.cast(), idx) }.cast();
        }
        // SAFETY: as above.
        let num = unsafe { OPENSSL_sk_num(h.cast()) };
        for i in idx..num {
            // SAFETY: an index within the stack.
            let obj = unsafe { OPENSSL_sk_value(h.cast(), i) }.cast::<X509_OBJECT>();
            let op: *const *mut X509_OBJECT = &raw const obj;
            // SAFETY: pointers to the two objects' pointers.
            if unsafe { object_cmp(op.cast(), xp.cast()) } != 0 {
                return ptr::null_mut();
            }
            // SAFETY: an object of the stack.
            let Some(o) = (unsafe { object(obj) }) else { continue };
            let same = if xt == X509_LU_X509 {
                // SAFETY: the two certificates.
                (unsafe { X509_cmp(o.data.cast(), xd.cast()) }) == 0
            } else {
                // SAFETY: the two CRLs.
                (unsafe { X509_CRL_match(o.data.cast(), xd.cast()) }) == 0
            };
            if same {
                return obj;
            }
        }
        ptr::null_mut()
    }
}

// The store.

/// The store's callbacks (`X509_STORE_set_verify` and the others).
#[derive(Clone, Copy, Default)]
pub(crate) struct Callbacks {
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
}

/// A certificate store (`struct x509_store_st`), shared by reference.
pub(crate) struct Store {
    references: AtomicI32,
    /// The objects, a stack sorted by `object_cmp` when searched.
    pub(crate) objs: *mut stack_st_X509_OBJECT,
    /// The lookups (`get_cert_methods`), in the order added.
    pub(crate) lookups: *mut OPENSSL_STACK,
    pub(crate) param: *mut X509_VERIFY_PARAM,
    pub(crate) lock: *mut CRYPTO_RWLOCK,
    callbacks: UnsafeCell<Callbacks>,
    /// The application's data, at a fixed address for the `CRYPTO_*_ex_data` functions.
    ex_data: UnsafeCell<CRYPTO_EX_DATA>,
}

// SAFETY: the stacks are guarded by the store's lock, as OpenSSL's are; the parameters,
// callbacks, and application data are set before the store is shared, as OpenSSL requires
// (its setters take no lock either).
unsafe impl Send for Store {}
// SAFETY: as above.
unsafe impl Sync for Store {}

handle_type!(X509_STORE => Store);

impl Store {
    /// The callbacks.
    pub(crate) fn callbacks(&self) -> Callbacks {
        // SAFETY: see the type's `Sync`.
        unsafe { *self.callbacks.get() }
    }

    /// Changes the callbacks.
    fn set_callbacks(&self, f: impl FnOnce(&mut Callbacks)) {
        // SAFETY: see the type's `Sync`.
        f(unsafe { &mut *self.callbacks.get() });
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: the store's own lookups, each shut down and freed (no lock is held).
        let n = unsafe { OPENSSL_sk_num(self.lookups) };
        for i in 0..n {
            // SAFETY: an index within the stack.
            let lu = unsafe { OPENSSL_sk_value(self.lookups, i) }.cast::<X509_LOOKUP>();
            // SAFETY: a lookup of the store.
            unsafe { X509_LOOKUP_shutdown(lu) };
            // SAFETY: as above, which the store owned.
            unsafe { X509_LOOKUP_free(lu) };
        }
        // SAFETY: the store's own stacks and parameters.
        unsafe { OPENSSL_sk_free(self.lookups) };
        // SAFETY: as above.
        unsafe { OPENSSL_sk_pop_free(self.objs.cast(), Some(object_free)) };
        // SAFETY: as above.
        unsafe { X509_VERIFY_PARAM_free(self.param) };
        // SAFETY: the store's own lock.
        unsafe { CRYPTO_THREAD_lock_free(self.lock) };
    }
}

/// The store behind `xs`, or `None` for NULL.
///
/// # Safety
/// `xs` is NULL or a live store.
pub(crate) unsafe fn store<'a>(xs: *const X509_STORE) -> Option<&'a Store> {
    // SAFETY: the caller's guarantee.
    unsafe { X509_STORE::get(xs) }
}

ffi_export! {
    /// A new, empty store with default parameters, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn X509_STORE_new() -> *mut X509_STORE
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        const F: &str = "X509_STORE_new";
        // SAFETY: our comparison, for objects.
        let objs = unsafe { OPENSSL_sk_new(Some(object_cmp)) };
        // SAFETY: no preconditions.
        let lookups = unsafe { OPENSSL_sk_new_null() };
        // SAFETY: as above.
        let param = unsafe { X509_VERIFY_PARAM_new() };
        // SAFETY: as above.
        let lock = unsafe { CRYPTO_THREAD_lock_new() };
        if objs.is_null() || lookups.is_null() || param.is_null() || lock.is_null() {
            let reason = if param.is_null() && !objs.is_null() && !lookups.is_null() { ERR_R_X509_LIB } else { ERR_R_CRYPTO_LIB };
            err::raise(ERR_LIB_X509, reason, F);
            // SAFETY: made above, or NULL.
            unsafe { OPENSSL_sk_free(objs) };
            // SAFETY: as above.
            unsafe { OPENSSL_sk_free(lookups) };
            // SAFETY: as above.
            unsafe { X509_VERIFY_PARAM_free(param) };
            // SAFETY: as above.
            unsafe { CRYPTO_THREAD_lock_free(lock) };
            return ptr::null_mut();
        }
        let xs = X509_STORE::new_handle(Store {
            references: AtomicI32::new(1),
            objs: objs.cast(),
            lookups,
            param,
            lock,
            callbacks: UnsafeCell::new(Callbacks::default()),
            // SAFETY: an all-zero `CRYPTO_EX_DATA` is the empty one `CRYPTO_new_ex_data` fills.
            ex_data: UnsafeCell::new(unsafe { core::mem::zeroed() }),
        });
        // SAFETY: the new store.
        let Some(s) = (unsafe { store(xs) }) else { return ptr::null_mut() };
        // SAFETY: the new store and its own application data.
        if unsafe { CRYPTO_new_ex_data(CRYPTO_EX_INDEX_X509_STORE, xs.cast(), s.ex_data.get()) } == 0 {
            err::raise(ERR_LIB_X509, ERR_R_CRYPTO_LIB, F);
            // SAFETY: the new store's only reference.
            unsafe { X509_STORE::free(xs) };
            return ptr::null_mut();
        }
        xs
    }
}

ffi_export! {
    /// Drops a reference; with the last, frees the application data, shuts down and frees the
    /// lookups, then frees the objects, parameters, and the store. Nothing for NULL.
    ///
    /// # Safety
    /// `xs` is NULL or a live store whose reference the caller gives up.
    pub unsafe extern "C" fn X509_STORE_free(xs: *mut X509_STORE)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(held) = (unsafe { X509_STORE::hold(xs) }) else { return };
        if held.references.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        // SAFETY: the store's own application data; its last reference.
        unsafe { CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509_STORE, xs.cast(), held.ex_data.get()) };
        // SAFETY: the last reference; the hold keeps the store until this returns.
        unsafe { X509_STORE::free(xs) };
    }
}

ffi_export! {
    /// Adds a reference: 1, or 0 for NULL.
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_up_ref(xs: *mut X509_STORE) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { store(xs) }) else { return 0 };
        c_int::from(s.references.fetch_add(1, Ordering::AcqRel) >= 1)
    }
}

ffi_export! {
    /// Takes the store's lock (for writing): 1, or 0.
    ///
    /// # Safety
    /// `xs` is NULL or a live store, which the caller doesn't hold locked.
    pub unsafe extern "C" fn X509_STORE_lock(xs: *mut X509_STORE) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { store(xs) }) else { return 0 };
        // SAFETY: the store's lock.
        unsafe { CRYPTO_THREAD_write_lock(s.lock) }
    }
}

ffi_export! {
    /// Releases the store's lock: 1, or 0.
    ///
    /// # Safety
    /// `xs` is NULL or a live store, which the caller holds locked.
    pub unsafe extern "C" fn X509_STORE_unlock(xs: *mut X509_STORE) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { store(xs) }) else { return 0 };
        // SAFETY: the store's lock.
        unsafe { CRYPTO_THREAD_unlock(s.lock) }
    }
}

/// `ossl_x509_store_read_lock`.
///
/// # Safety
/// The caller doesn't hold the store locked.
pub(crate) unsafe fn read_lock(s: &Store) -> bool {
    // SAFETY: the store's lock.
    (unsafe { CRYPTO_THREAD_read_lock(s.lock) }) != 0
}

ffi_export! {
    /// The store's lookup of method `m`, made and added if it hasn't one; or NULL.
    ///
    /// # Safety
    /// `xs` is NULL or a live store; `m` is a live method that outlives the store.
    pub unsafe extern "C" fn X509_STORE_add_lookup(xs: *mut X509_STORE, m: *mut X509_LOOKUP_METHOD) -> *mut X509_LOOKUP
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { store(xs) }) else { return ptr::null_mut() };
        // SAFETY: the store's lookups.
        let n = unsafe { OPENSSL_sk_num(s.lookups) };
        for i in 0..n {
            // SAFETY: an index within the stack.
            let lu = unsafe { OPENSSL_sk_value(s.lookups, i) }.cast::<X509_LOOKUP>();
            // SAFETY: a lookup of the store.
            if unsafe { super::lookup::method_of(lu) } == m {
                return lu;
            }
        }
        // SAFETY: the caller's method.
        let lu = unsafe { X509_LOOKUP_new(m) };
        if lu.is_null() {
            err::raise(ERR_LIB_X509, ERR_R_X509_LIB, "X509_STORE_add_lookup");
            return ptr::null_mut();
        }
        // SAFETY: the new lookup; the store.
        unsafe { set_store(lu, xs) };
        // SAFETY: the store's lookups; the new lookup, which it takes.
        if unsafe { OPENSSL_sk_push(s.lookups, lu.cast()) } != 0 {
            return lu;
        }
        err::raise(ERR_LIB_X509, ERR_R_CRYPTO_LIB, "X509_STORE_add_lookup");
        // SAFETY: made above.
        unsafe { X509_LOOKUP_free(lu) };
        ptr::null_mut()
    }
}

/// `x509_store_add`: adds an object holding a reference to `x` (a CRL for `crl`), unless the
/// store has it: 1, or 0.
///
/// # Safety
/// `xs` is NULL or a live store; `x` is NULL or a live certificate (CRL).
unsafe fn store_add(xs: *mut X509_STORE, x: *mut c_void, crl: bool) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { store(xs) }) else {
        return false;
    };
    if x.is_null() {
        return false;
    }
    // SAFETY: no preconditions.
    let obj = unsafe { X509_OBJECT_new() };
    // SAFETY: new, or NULL.
    let Some(o) = (unsafe { object(obj) }) else {
        return false;
    };
    o.type_ = if crl { X509_LU_CRL } else { X509_LU_X509 };
    o.data = x;
    // SAFETY: the new object.
    if unsafe { X509_OBJECT_up_ref_count(obj) } == 0 {
        o.type_ = X509_LU_NONE;
        // SAFETY: as above.
        unsafe { X509_OBJECT_free(obj) };
        return false;
    }
    // SAFETY: the store's lock.
    if unsafe { CRYPTO_THREAD_write_lock(s.lock) } == 0 {
        // SAFETY: as above.
        unsafe { X509_OBJECT_free(obj) };
        return false;
    }
    let mut added = false;
    // SAFETY: the store's objects, under its lock; the new object.
    let ret = if unsafe { X509_OBJECT_retrieve_match(s.objs, obj) }.is_null() {
        // SAFETY: as above; the object, which the stack takes.
        added = unsafe { OPENSSL_sk_push(s.objs.cast(), obj.cast()) } != 0;
        added
    } else {
        true
    };
    // SAFETY: as above.
    unsafe { CRYPTO_THREAD_unlock(s.lock) };
    if !added {
        // SAFETY: the new object, not added.
        unsafe { X509_OBJECT_free(obj) };
    }
    ret
}

ffi_export! {
    /// Adds the certificate (a reference), unless the store has it: 1, or 0 (`ERR_R_X509_LIB`).
    ///
    /// # Safety
    /// `xs` is NULL or a live store; `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_STORE_add_cert(xs: *mut X509_STORE, x: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { store_add(xs, x.cast(), false) } {
            err::raise(ERR_LIB_X509, ERR_R_X509_LIB, "X509_STORE_add_cert");
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Adds the CRL (a reference), unless the store has a matching one: 1, or 0
    /// (`ERR_R_X509_LIB`).
    ///
    /// # Safety
    /// `xs` is NULL or a live store; `x` is NULL or a live CRL.
    pub unsafe extern "C" fn X509_STORE_add_crl(xs: *mut X509_STORE, x: *mut X509_CRL) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { store_add(xs, x.cast(), true) } {
            err::raise(ERR_LIB_X509, ERR_R_X509_LIB, "X509_STORE_add_crl");
            return 0;
        }
        1
    }
}

ffi_export! {
    /// The store's objects (its own stack, to use under its lock), or NULL.
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_get0_objects(xs: *const X509_STORE) -> *mut stack_st_X509_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { store(xs) }.map_or(ptr::null_mut(), |s| s.objs)
    }
}

/// `x509_object_dup`, as a stack's copy function: a new object with a reference to the
/// same certificate or CRL.
unsafe extern "C" fn object_dup(a: *const c_void) -> *mut c_void {
    // SAFETY: an object of the stack being copied.
    let Some(src) = (unsafe { a.cast::<Object>().as_ref() }) else {
        return ptr::null_mut();
    };
    // SAFETY: no preconditions.
    let ret = unsafe { X509_OBJECT_new() };
    // SAFETY: new, or NULL.
    let Some(o) = (unsafe { object(ret) }) else {
        return ptr::null_mut();
    };
    o.type_ = src.type_;
    o.data = src.data;
    // SAFETY: the new object.
    if unsafe { X509_OBJECT_up_ref_count(ret) } == 0 {
        // SAFETY: as above, holding no reference.
        unsafe { mem::release(ret.cast()) };
        return ptr::null_mut();
    }
    ret.cast()
}

ffi_export! {
    /// A copy of the store's objects (each a new object with a reference), or NULL
    /// (`ERR_R_PASSED_NULL_PARAMETER` for no store).
    ///
    /// # Safety
    /// `xs` is NULL or a live store, which the caller doesn't hold locked.
    pub unsafe extern "C" fn X509_STORE_get1_objects(xs: *mut X509_STORE) -> *mut stack_st_X509_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { store(xs) }) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "X509_STORE_get1_objects");
            return ptr::null_mut();
        };
        // SAFETY: as above.
        if !unsafe { read_lock(s) } {
            return ptr::null_mut();
        }
        // SAFETY: the store's objects, under its lock.
        let objs = unsafe { OPENSSL_sk_deep_copy(s.objs.cast(), Some(object_dup), Some(object_free)) };
        // SAFETY: the store's lock.
        unsafe { CRYPTO_THREAD_unlock(s.lock) };
        objs.cast()
    }
}

ffi_export! {
    /// The store's certificates, each with a reference, sorted by subject, or NULL
    /// (`ERR_R_PASSED_NULL_PARAMETER` for no store).
    ///
    /// # Safety
    /// `xs` is NULL or a live store, which the caller doesn't hold locked.
    pub unsafe extern "C" fn X509_STORE_get1_all_certs(xs: *mut X509_STORE) -> *mut stack_st_X509
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { store(xs) }) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "X509_STORE_get1_all_certs");
            return ptr::null_mut();
        };
        // SAFETY: no preconditions.
        let sk = unsafe { OPENSSL_sk_new_null() }.cast::<stack_st_X509>();
        if sk.is_null() {
            return ptr::null_mut();
        }
        let free_all = || {
            // SAFETY: the new stack and its references.
            unsafe { super::cert::OSSL_STACK_OF_X509_free(sk) };
            ptr::null_mut()
        };
        // SAFETY: the store's lock.
        if unsafe { CRYPTO_THREAD_write_lock(s.lock) } == 0 {
            return free_all();
        }
        // SAFETY: the store's objects, under its lock.
        unsafe { OPENSSL_sk_sort(s.objs.cast()) };
        // SAFETY: as above.
        let n = unsafe { OPENSSL_sk_num(s.objs.cast()) };
        for i in 0..n {
            // SAFETY: an index within the stack.
            let obj = unsafe { OPENSSL_sk_value(s.objs.cast(), i) };
            // SAFETY: an object of the store.
            let cert = unsafe { X509_OBJECT_get0_X509(obj.cast()) };
            let flags = c_int::try_from(X509_ADD_FLAG_UP_REF).unwrap_or(0);
            // SAFETY: the new stack; a certificate of the store.
            if !cert.is_null() && unsafe { X509_add_cert(sk, cert, flags) } == 0 {
                // SAFETY: as above.
                unsafe { CRYPTO_THREAD_unlock(s.lock) };
                return free_all();
            }
        }
        // SAFETY: as above.
        unsafe { CRYPTO_THREAD_unlock(s.lock) };
        sk
    }
}

ffi_export! {
    /// Adds verification flags (`X509_VERIFY_PARAM_set_flags`): 1, or 0.
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_set_flags(xs: *mut X509_STORE, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { store(xs) }) else { return 0 };
        // SAFETY: the store's parameters.
        unsafe { X509_VERIFY_PARAM_set_flags(s.param, flags) }
    }
}

ffi_export! {
    /// Sets the verification depth: 1 (0 for no store).
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_set_depth(xs: *mut X509_STORE, depth: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { store(xs) }) else { return 0 };
        // SAFETY: the store's parameters.
        unsafe { X509_VERIFY_PARAM_set_depth(s.param, depth) };
        1
    }
}

ffi_export! {
    /// Sets the purpose: 1, or 0.
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_set_purpose(xs: *mut X509_STORE, purpose: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { store(xs) }) else { return 0 };
        // SAFETY: the store's parameters.
        unsafe { X509_VERIFY_PARAM_set_purpose(s.param, purpose) }
    }
}

ffi_export! {
    /// Sets the trust: 1, or 0.
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_set_trust(xs: *mut X509_STORE, trust: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { store(xs) }) else { return 0 };
        // SAFETY: the store's parameters.
        unsafe { X509_VERIFY_PARAM_set_trust(s.param, trust) }
    }
}

ffi_export! {
    /// Copies the parameters' settings into the store's (`X509_VERIFY_PARAM_set1`): 1, or 0.
    ///
    /// # Safety
    /// `xs` is NULL or a live store; `param` is NULL or live parameters.
    pub unsafe extern "C" fn X509_STORE_set1_param(xs: *mut X509_STORE, param: *const X509_VERIFY_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { store(xs) }) else { return 0 };
        // SAFETY: the store's parameters; the caller's.
        unsafe { X509_VERIFY_PARAM_set1(s.param, param) }
    }
}

ffi_export! {
    /// The store's parameters, or NULL.
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_get0_param(xs: *const X509_STORE) -> *mut X509_VERIFY_PARAM
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { store(xs) }.map_or(ptr::null_mut(), |s| s.param)
    }
}

ffi_export! {
    /// Sets the application's data at `idx`: 1, or 0.
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_set_ex_data(xs: *mut X509_STORE, idx: c_int, data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { store(xs) }) else { return 0 };
        // SAFETY: the store's application data.
        unsafe { CRYPTO_set_ex_data(s.ex_data.get(), idx, data) }
    }
}

ffi_export! {
    /// The application's data at `idx`, or NULL.
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_get_ex_data(xs: *const X509_STORE, idx: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { store(xs) }) else { return ptr::null_mut() };
        // SAFETY: the store's application data.
        unsafe { CRYPTO_get_ex_data(s.ex_data.get(), idx) }
    }
}
ffi_export! {
    /// Sets the verification function (NULL for the default).
    ///
    /// # Safety
    /// `xs` is NULL or a live store, not yet shared; `f` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_STORE_set_verify(xs: *mut X509_STORE, f: X509_STORE_CTX_verify_fn)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(s) = unsafe { store(xs) } {
            s.set_callbacks(|c| c.verify = f);
        }
    }
}

ffi_export! {
    /// The verification function, or NULL.
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_get_verify(xs: *const X509_STORE) -> X509_STORE_CTX_verify_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { store(xs) }.and_then(|s| s.callbacks().verify)
    }
}

ffi_export! {
    /// Sets the verification callback (NULL for the default).
    ///
    /// # Safety
    /// `xs` is NULL or a live store, not yet shared; `f` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_STORE_set_verify_cb(xs: *mut X509_STORE, f: X509_STORE_CTX_verify_cb)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(s) = unsafe { store(xs) } {
            s.set_callbacks(|c| c.verify_cb = f);
        }
    }
}

ffi_export! {
    /// The verification callback, or NULL.
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_get_verify_cb(xs: *const X509_STORE) -> X509_STORE_CTX_verify_cb
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { store(xs) }.and_then(|s| s.callbacks().verify_cb)
    }
}

ffi_export! {
    /// Sets the issuer lookup (NULL for the default).
    ///
    /// # Safety
    /// `xs` is NULL or a live store, not yet shared; `f` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_STORE_set_get_issuer(xs: *mut X509_STORE, f: X509_STORE_CTX_get_issuer_fn)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(s) = unsafe { store(xs) } {
            s.set_callbacks(|c| c.get_issuer = f);
        }
    }
}

ffi_export! {
    /// The issuer lookup, or NULL.
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_get_get_issuer(xs: *const X509_STORE) -> X509_STORE_CTX_get_issuer_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { store(xs) }.and_then(|s| s.callbacks().get_issuer)
    }
}

ffi_export! {
    /// Sets the issuer check (NULL for the default).
    ///
    /// # Safety
    /// `xs` is NULL or a live store, not yet shared; `f` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_STORE_set_check_issued(xs: *mut X509_STORE, f: X509_STORE_CTX_check_issued_fn)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(s) = unsafe { store(xs) } {
            s.set_callbacks(|c| c.check_issued = f);
        }
    }
}

ffi_export! {
    /// The issuer check, or NULL.
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_get_check_issued(xs: *const X509_STORE) -> X509_STORE_CTX_check_issued_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { store(xs) }.and_then(|s| s.callbacks().check_issued)
    }
}

ffi_export! {
    /// Sets the revocation check (NULL for the default).
    ///
    /// # Safety
    /// `xs` is NULL or a live store, not yet shared; `f` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_STORE_set_check_revocation(xs: *mut X509_STORE, f: X509_STORE_CTX_check_revocation_fn)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(s) = unsafe { store(xs) } {
            s.set_callbacks(|c| c.check_revocation = f);
        }
    }
}

ffi_export! {
    /// The revocation check, or NULL.
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_get_check_revocation(xs: *const X509_STORE) -> X509_STORE_CTX_check_revocation_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { store(xs) }.and_then(|s| s.callbacks().check_revocation)
    }
}

ffi_export! {
    /// Sets the CRL lookup (NULL for the default).
    ///
    /// # Safety
    /// `xs` is NULL or a live store, not yet shared; `f` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_STORE_set_get_crl(xs: *mut X509_STORE, f: X509_STORE_CTX_get_crl_fn)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(s) = unsafe { store(xs) } {
            s.set_callbacks(|c| c.get_crl = f);
        }
    }
}

ffi_export! {
    /// The CRL lookup, or NULL.
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_get_get_crl(xs: *const X509_STORE) -> X509_STORE_CTX_get_crl_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { store(xs) }.and_then(|s| s.callbacks().get_crl)
    }
}

ffi_export! {
    /// Sets the CRL check (NULL for the default).
    ///
    /// # Safety
    /// `xs` is NULL or a live store, not yet shared; `f` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_STORE_set_check_crl(xs: *mut X509_STORE, f: X509_STORE_CTX_check_crl_fn)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(s) = unsafe { store(xs) } {
            s.set_callbacks(|c| c.check_crl = f);
        }
    }
}

ffi_export! {
    /// The CRL check, or NULL.
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_get_check_crl(xs: *const X509_STORE) -> X509_STORE_CTX_check_crl_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { store(xs) }.and_then(|s| s.callbacks().check_crl)
    }
}

ffi_export! {
    /// Sets the check of a certificate against a CRL (NULL for the default).
    ///
    /// # Safety
    /// `xs` is NULL or a live store, not yet shared; `f` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_STORE_set_cert_crl(xs: *mut X509_STORE, f: X509_STORE_CTX_cert_crl_fn)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(s) = unsafe { store(xs) } {
            s.set_callbacks(|c| c.cert_crl = f);
        }
    }
}

ffi_export! {
    /// The check of a certificate against a CRL, or NULL.
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_get_cert_crl(xs: *const X509_STORE) -> X509_STORE_CTX_cert_crl_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { store(xs) }.and_then(|s| s.callbacks().cert_crl)
    }
}

ffi_export! {
    /// Sets the policy check (NULL for the default).
    ///
    /// # Safety
    /// `xs` is NULL or a live store, not yet shared; `f` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_STORE_set_check_policy(xs: *mut X509_STORE, f: X509_STORE_CTX_check_policy_fn)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(s) = unsafe { store(xs) } {
            s.set_callbacks(|c| c.check_policy = f);
        }
    }
}

ffi_export! {
    /// The policy check, or NULL.
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_get_check_policy(xs: *const X509_STORE) -> X509_STORE_CTX_check_policy_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { store(xs) }.and_then(|s| s.callbacks().check_policy)
    }
}

ffi_export! {
    /// Sets the certificates lookup (NULL for the default).
    ///
    /// # Safety
    /// `xs` is NULL or a live store, not yet shared; `f` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_STORE_set_lookup_certs(xs: *mut X509_STORE, f: X509_STORE_CTX_lookup_certs_fn)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(s) = unsafe { store(xs) } {
            s.set_callbacks(|c| c.lookup_certs = f);
        }
    }
}

ffi_export! {
    /// The certificates lookup, or NULL.
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_get_lookup_certs(xs: *const X509_STORE) -> X509_STORE_CTX_lookup_certs_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { store(xs) }.and_then(|s| s.callbacks().lookup_certs)
    }
}

ffi_export! {
    /// Sets the CRLs lookup (NULL for the default).
    ///
    /// # Safety
    /// `xs` is NULL or a live store, not yet shared; `f` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_STORE_set_lookup_crls(xs: *mut X509_STORE, f: X509_STORE_CTX_lookup_crls_fn)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(s) = unsafe { store(xs) } {
            s.set_callbacks(|c| c.lookup_crls = f);
        }
    }
}

ffi_export! {
    /// The CRLs lookup, or NULL.
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_get_lookup_crls(xs: *const X509_STORE) -> X509_STORE_CTX_lookup_crls_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { store(xs) }.and_then(|s| s.callbacks().lookup_crls)
    }
}

ffi_export! {
    /// Sets the cleanup function (NULL for the default).
    ///
    /// # Safety
    /// `xs` is NULL or a live store, not yet shared; `f` is NULL or a function of the type.
    pub unsafe extern "C" fn X509_STORE_set_cleanup(xs: *mut X509_STORE, f: X509_STORE_CTX_cleanup_fn)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(s) = unsafe { store(xs) } {
            s.set_callbacks(|c| c.cleanup = f);
        }
    }
}

ffi_export! {
    /// The cleanup function, or NULL.
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_get_cleanup(xs: *const X509_STORE) -> X509_STORE_CTX_cleanup_fn
    where failure = None, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { store(xs) }.and_then(|s| s.callbacks().cleanup)
    }
}

// Loading (`x509_d2.c`).

/// The store's lookup of `m`, made if need be, or NULL.
///
/// # Safety
/// `xs` is NULL or a live store.
unsafe fn lookup_of(xs: *mut X509_STORE, m: *mut X509_LOOKUP_METHOD) -> *mut X509_LOOKUP {
    if xs.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller's guarantee; a built-in method.
    unsafe { X509_STORE_add_lookup(xs, m) }
}

ffi_export! {
    /// Adds the default file, directory, and store (`X509_STORE_set_default_paths(3)`) in the
    /// library context, clearing the errors of their loading: 1, or 0 if a lookup can't be
    /// made.
    ///
    /// # Safety
    /// `xs` is NULL or a live store; `propq` is NULL or a C string.
    pub unsafe extern "C" fn X509_STORE_set_default_paths_ex(xs: *mut X509_STORE, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee; no preconditions.
        let lookup = unsafe { lookup_of(xs, file_method()) };
        if lookup.is_null() {
            return 0;
        }
        let default = c_long::from(X509_FILETYPE_DEFAULT);
        // SAFETY: the store's lookup; no file; the caller's context.
        unsafe { X509_LOOKUP_ctrl_ex(lookup, X509_L_FILE_LOAD, ptr::null(), default, ptr::null_mut(), libctx, propq) };
        // SAFETY: as above.
        let lookup = unsafe { lookup_of(xs, dir_method()) };
        if lookup.is_null() {
            return 0;
        }
        // SAFETY: as above; no directory.
        unsafe { X509_LOOKUP_ctrl(lookup, X509_L_ADD_DIR, ptr::null(), default, ptr::null_mut()) };
        // SAFETY: as above.
        let lookup = unsafe { lookup_of(xs, store_method()) };
        if lookup.is_null() {
            return 0;
        }
        // SAFETY: as above; no URI.
        unsafe { X509_LOOKUP_ctrl_ex(lookup, X509_L_ADD_STORE, ptr::null(), 0, ptr::null_mut(), libctx, propq) };
        // SAFETY: no preconditions.
        unsafe { ERR_clear_error() };
        1
    }
}

ffi_export! {
    /// Adds the default paths (`X509_STORE_set_default_paths_ex` in the default library
    /// context).
    ///
    /// # Safety
    /// `xs` is NULL or a live store.
    pub unsafe extern "C" fn X509_STORE_set_default_paths(xs: *mut X509_STORE) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_STORE_set_default_paths_ex(xs, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Loads a PEM file's certificates and CRLs into the store (its file lookup): 1, or 0.
    ///
    /// # Safety
    /// `xs` is NULL or a live store; `file` and `propq` are NULL or C strings.
    pub unsafe extern "C" fn X509_STORE_load_file_ex(xs: *mut X509_STORE, file: *const c_char, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if file.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee; no preconditions.
        let lookup = unsafe { lookup_of(xs, file_method()) };
        let pem = c_long::from(X509_FILETYPE_PEM);
        // SAFETY: the store's lookup, or NULL; the caller's file and context.
        c_int::from(!lookup.is_null() && unsafe { X509_LOOKUP_ctrl_ex(lookup, X509_L_FILE_LOAD, file, pem, ptr::null_mut(), libctx, propq) } > 0)
    }
}

ffi_export! {
    /// Loads a PEM file (`X509_STORE_load_file_ex` in the default library context).
    ///
    /// # Safety
    /// As for [`X509_STORE_load_file_ex`].
    pub unsafe extern "C" fn X509_STORE_load_file(xs: *mut X509_STORE, file: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_STORE_load_file_ex(xs, file, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Adds hashed directories (`:`-separated) of PEM files to the store's directory lookup: 1,
    /// or 0.
    ///
    /// # Safety
    /// `xs` is NULL or a live store; `path` is NULL or a C string.
    pub unsafe extern "C" fn X509_STORE_load_path(xs: *mut X509_STORE, path: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if path.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee; no preconditions.
        let lookup = unsafe { lookup_of(xs, dir_method()) };
        let pem = c_long::from(X509_FILETYPE_PEM);
        // SAFETY: the store's lookup, or NULL; the caller's directories.
        c_int::from(!lookup.is_null() && unsafe { X509_LOOKUP_ctrl(lookup, X509_L_ADD_DIR, path, pem, ptr::null_mut()) } > 0)
    }
}

ffi_export! {
    /// Adds an OSSL_STORE URI to the store's store lookup (checking it opens): 1, or 0.
    ///
    /// # Safety
    /// `xs` is NULL or a live store; `uri` and `propq` are NULL or C strings.
    pub unsafe extern "C" fn X509_STORE_load_store_ex(xs: *mut X509_STORE, uri: *const c_char, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if uri.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee; no preconditions.
        let lookup = unsafe { lookup_of(xs, store_method()) };
        // SAFETY: the store's lookup, or NULL; the caller's URI and context.
        c_int::from(!lookup.is_null() && unsafe { X509_LOOKUP_ctrl_ex(lookup, X509_L_ADD_STORE, uri, 0, ptr::null_mut(), libctx, propq) } != 0)
    }
}

ffi_export! {
    /// Adds an OSSL_STORE URI (`X509_STORE_load_store_ex` in the default library context).
    ///
    /// # Safety
    /// As for [`X509_STORE_load_store_ex`].
    pub unsafe extern "C" fn X509_STORE_load_store(xs: *mut X509_STORE, uri: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_STORE_load_store_ex(xs, uri, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Loads a PEM file and adds hashed directories, either NULL but not both: 1, or 0.
    ///
    /// # Safety
    /// `xs` is NULL or a live store; `file`, `path`, and `propq` are NULL or C strings.
    pub unsafe extern "C" fn X509_STORE_load_locations_ex(xs: *mut X509_STORE, file: *const c_char, path: *const c_char, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if file.is_null() && path.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        if !file.is_null() && unsafe { X509_STORE_load_file_ex(xs, file, libctx, propq) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        if !path.is_null() && unsafe { X509_STORE_load_path(xs, path) } == 0 {
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Loads a file and adds directories (`X509_STORE_load_locations_ex` in the default
    /// library context).
    ///
    /// # Safety
    /// As for [`X509_STORE_load_locations_ex`].
    pub unsafe extern "C" fn X509_STORE_load_locations(xs: *mut X509_STORE, file: *const c_char, path: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_STORE_load_locations_ex(xs, file, path, ptr::null_mut(), ptr::null()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_stores_are_safe() {
        let s: *mut X509_STORE = ptr::null_mut();
        // SAFETY: NULL where OpenSSL dereferences it.
        assert!(unsafe { X509_STORE_get0_objects(s) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { X509_STORE_get0_param(s) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { X509_STORE_lock(s) }, 0);
        // SAFETY: as above; a built-in method.
        assert!(unsafe { X509_STORE_add_lookup(s, file_method()) }.is_null());
        // SAFETY: as above.
        unsafe { X509_STORE_set_verify_cb(s, None) };
        // SAFETY: as above.
        assert!(unsafe { X509_STORE_get_verify_cb(s) }.is_none());
        // SAFETY: as above.
        assert_eq!(unsafe { X509_STORE_set_flags(s, 1) }, 0);
        // SAFETY: as above.
        assert!(unsafe { X509_STORE_get_ex_data(s, 0) }.is_null());
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }

    #[test]
    fn null_objects_are_safe() {
        let o: *mut X509_OBJECT = ptr::null_mut();
        // SAFETY: NULL where OpenSSL dereferences it.
        assert_eq!(unsafe { X509_OBJECT_get_type(o) }, X509_LU_NONE);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_OBJECT_up_ref_count(o) }, 0);
        // SAFETY: as above.
        assert!(unsafe { X509_OBJECT_retrieve_match(ptr::null_mut(), o) }.is_null());
        // SAFETY: a new object.
        let obj = unsafe { X509_OBJECT_new() };
        // SAFETY: the object; no certificate, where OpenSSL dereferences it.
        assert_eq!(unsafe { X509_OBJECT_set1_X509(obj, ptr::null_mut()) }, 0);
        // SAFETY: made above.
        unsafe { X509_OBJECT_free(obj) };
    }
}
