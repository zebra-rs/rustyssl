//! Application data on objects (`CRYPTO_get_ex_new_index(3)`): numbered slots in each object's
//! public `CRYPTO_EX_DATA`, with callbacks registered per class of object.
//!
//! As in OpenSSL 3.5:
//! - Each class (`CRYPTO_EX_INDEX_*`) numbers its indexes from 1; 0 is reserved for the SSL
//!   "app data" functions.
//! - The values are an ordinary `STACK_OF(void)` in `CRYPTO_EX_DATA.sk`, which applications may
//!   read with the stack functions.
//! - New and dup callbacks run in index order. Free callbacks run by priority, high first,
//!   sorted with the C library's `qsort`; with equal priorities (all of the public API's), the
//!   order is whatever `qsort` leaves, which this reproduces by calling it.
//! - A freed index keeps its number, with callbacks that do nothing.
//!
//! The registry stands for the default library context's; a context's own (step 3.1) comes
//! later. No lock is held while a callback runs.

use core::ffi::{c_int, c_long, c_void};
use core::ptr;
use std::sync::{Arc, Mutex, PoisonError};

use rustyssl_abi::{
    CRYPTO_EX_DATA, CRYPTO_EX_INDEX__COUNT, CRYPTO_EX_dup, CRYPTO_EX_free, CRYPTO_EX_new,
    ERR_LIB_CRYPTO, ERR_R_CRYPTO_LIB, ERR_R_PASSED_INVALID_ARGUMENT, OPENSSL_STACK,
};

use crate::ffi::ffi_export;
use crate::{err, init, stack};

/// The number of classes.
const CLASSES: usize = CRYPTO_EX_INDEX__COUNT.unsigned_abs() as usize;

/// An index's callbacks: the application's, or none at all once `CRYPTO_free_ex_index` has
/// replaced them with OpenSSL's do-nothing ones (which, unlike missing ones, count as present).
#[derive(Clone, Copy)]
enum Funcs {
    Registered {
        new: CRYPTO_EX_new,
        dup: CRYPTO_EX_dup,
        free: CRYPTO_EX_free,
    },
    Freed,
}

struct Callback {
    argl: c_long,
    argp: *mut c_void,
    funcs: Funcs,
    priority: c_int,
}

// SAFETY: `argp` is the application's, only passed back to its callbacks.
unsafe impl Send for Callback {}
// SAFETY: as above.
unsafe impl Sync for Callback {}

/// A class's indexes: `None` until the first is registered (OpenSSL's null `meth` stack, whose
/// count is -1), then one entry per index, with index 0 empty.
type Indexes = Option<Vec<Option<Arc<Callback>>>>;

static REGISTRY: Mutex<[Indexes; CLASSES]> = Mutex::new([const { None }; CLASSES]);

/// The registry slot for `class_index`, or `None` with `ERR_R_PASSED_INVALID_ARGUMENT` if it's
/// out of range, or without an error after `OPENSSL_cleanup` (OpenSSL's freed lock).
#[track_caller]
fn class(class_index: c_int, function: &str) -> Option<usize> {
    let Some(class) = usize::try_from(class_index).ok().filter(|c| *c < CLASSES) else {
        err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT, function);
        return None;
    };
    init::base().then_some(class)
}

/// A copy of a class's indexes, taken so the callbacks run without the lock.
#[track_caller]
fn snapshot(class_index: c_int, function: &str) -> Option<Indexes> {
    let class = class(class_index, function)?;
    let registry = REGISTRY.lock().unwrap_or_else(PoisonError::into_inner);
    registry.get(class).cloned()
}

/// The number of indexes, -1 for a class with none registered.
fn count(indexes: &Indexes) -> c_int {
    indexes
        .as_ref()
        .map_or(-1, |i| c_int::try_from(i.len()).unwrap_or(c_int::MAX))
}

/// The values stack in `ad`.
///
/// # Safety
/// `ad` is valid for reads.
unsafe fn values(ad: *const CRYPTO_EX_DATA) -> *mut OPENSSL_STACK {
    // SAFETY: the caller's guarantee.
    unsafe { (*ad).sk }.cast()
}

/// `CRYPTO_get_ex_data`: value `idx`, or null.
///
/// # Safety
/// `ad` is valid for reads, with a null or live stack.
unsafe fn get(ad: *const CRYPTO_EX_DATA, idx: c_int) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let sk = unsafe { values(ad) };
    // SAFETY: as above.
    if sk.is_null() || idx >= unsafe { stack::num(sk) } {
        return ptr::null_mut();
    }
    // SAFETY: as above.
    unsafe { stack::value(sk, idx) }
}

/// `CRYPTO_set_ex_data`: stores `val` at `idx`, growing the stack as needed.
///
/// # Safety
/// `ad` is valid for reads and writes, with a null or live stack.
unsafe fn set(ad: *mut CRYPTO_EX_DATA, idx: c_int, val: *mut c_void) -> c_int {
    const FUNCTION: &str = "CRYPTO_set_ex_data";
    // SAFETY: the caller's guarantee, for each access below.
    let mut sk = unsafe { values(ad) };
    if sk.is_null() {
        sk = stack::new_reserve(None, 0);
        if sk.is_null() {
            err::raise(ERR_LIB_CRYPTO, ERR_R_CRYPTO_LIB, FUNCTION);
            return 0;
        }
        // SAFETY: as above.
        unsafe { (*ad).sk = sk.cast() };
    }
    // SAFETY: as above.
    let mut i = i64::from(unsafe { stack::num(sk) });
    while i <= i64::from(idx) {
        // SAFETY: as above.
        if unsafe { stack::insert(sk, ptr::null(), -1, "OPENSSL_sk_insert") } == 0 {
            err::raise(ERR_LIB_CRYPTO, ERR_R_CRYPTO_LIB, FUNCTION);
            return 0;
        }
        i += 1;
    }
    // SAFETY: as above.
    if unsafe { stack::set(sk, idx, val, "OPENSSL_sk_set") } != val {
        err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT, FUNCTION);
        return 0;
    }
    1
}

/// An index as a C `int`; indexes are counted in `int`.
fn number(i: usize) -> c_int {
    c_int::try_from(i).unwrap_or(c_int::MAX)
}

ffi_export! {
    /// Registers an index in `class_index` with callbacks for when objects are created,
    /// copied, and freed, and returns it (from 1), or -1 for a class out of range.
    ///
    /// # Safety
    /// The callbacks are null or functions of the documented types.
    pub unsafe extern "C" fn CRYPTO_get_ex_new_index(class_index: c_int, argl: c_long, argp: *mut c_void, new_func: CRYPTO_EX_new, dup_func: CRYPTO_EX_dup, free_func: CRYPTO_EX_free) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        let Some(class) = class(class_index, "CRYPTO_get_ex_new_index") else {
            return -1;
        };
        let mut registry = REGISTRY.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(indexes) = registry.get_mut(class) else {
            return -1;
        };
        let indexes = indexes.get_or_insert_with(|| vec![None]);
        indexes.push(Some(Arc::new(Callback {
            argl,
            argp,
            funcs: Funcs::Registered {
                new: new_func,
                dup: dup_func,
                free: free_func,
            },
            priority: 0,
        })));
        number(indexes.len() - 1)
    }
}

ffi_export! {
    /// Replaces an index's callbacks with ones that do nothing; the number isn't reused.
    /// Returns 1, or 0 for an index that doesn't exist (or 0, the reserved one).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn CRYPTO_free_ex_index(class_index: c_int, idx: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(class) = class(class_index, "CRYPTO_free_ex_index") else {
            return 0;
        };
        let mut registry = REGISTRY.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = registry
            .get_mut(class)
            .and_then(Option::as_mut)
            .and_then(|indexes| indexes.get_mut(usize::try_from(idx).ok()?));
        let Some(entry @ Some(_)) = entry else {
            return 0;
        };
        let (argl, argp, priority) = entry.as_ref().map_or((0, ptr::null_mut(), 0), |c| (c.argl, c.argp, c.priority));
        *entry = Some(Arc::new(Callback {
            argl,
            argp,
            funcs: Funcs::Freed,
            priority,
        }));
        1
    }
}

ffi_export! {
    /// Starts an object's application data: clears `ad` and runs the class's new callbacks in
    /// index order. Returns 1, or 0 for a class out of range or a null `ad` (OpenSSL's would
    /// crash, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `ad` is null or valid for writes; the callbacks accept `obj`.
    pub unsafe extern "C" fn CRYPTO_new_ex_data(class_index: c_int, obj: *mut c_void, ad: *mut CRYPTO_EX_DATA) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if ad.is_null() {
            return 0;
        }
        let Some(indexes) = snapshot(class_index, "CRYPTO_new_ex_data") else {
            return 0;
        };
        // SAFETY: the caller's guarantee.
        unsafe { ad.write(CRYPTO_EX_DATA { ctx: ptr::null_mut(), sk: ptr::null_mut() }) };
        for (i, callback) in indexes.iter().flatten().enumerate() {
            let Some(callback) = callback else { continue };
            let Funcs::Registered { new: Some(new), .. } = callback.funcs else { continue };
            let idx = number(i);
            // SAFETY: `ad` is valid, with the stack the callbacks have built.
            let ptr = unsafe { get(ad, idx) };
            // SAFETY: the caller's guarantee about the callbacks.
            unsafe { new(obj, ptr, ad, idx, callback.argl, callback.argp) };
        }
        1
    }
}

ffi_export! {
    /// Copies `from`'s values into `to` for the indexes registered in the class, through the
    /// dup callbacks, which may replace each value. Returns 1, or 0 if a dup callback fails, the
    /// class is out of range or has no indexes while `from` has values, or either is null
    /// (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `to` and `from` are null or valid, with null or live stacks.
    pub unsafe extern "C" fn CRYPTO_dup_ex_data(class_index: c_int, to: *mut CRYPTO_EX_DATA, from: *const CRYPTO_EX_DATA) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if to.is_null() || from.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee, for each access to `to` and `from` below.
        let ctx = unsafe { (*from).ctx };
        // SAFETY: as above.
        unsafe { (*to).ctx = ctx };
        // SAFETY: as above.
        let from_values = unsafe { values(from) };
        if from_values.is_null() {
            return 1;
        }
        let Some(indexes) = snapshot(class_index, "CRYPTO_dup_ex_data") else {
            return 0;
        };
        // SAFETY: as above.
        let mx = count(&indexes).min(unsafe { stack::num(from_values) });
        if mx == 0 {
            return 1;
        }
        if mx < 0 {
            return 0;
        }
        // SAFETY: as above.
        let last = unsafe { get(to, mx - 1) };
        // SAFETY: as above.
        if unsafe { set(to, mx - 1, last) } == 0 {
            return 0;
        }
        let callbacks = indexes.unwrap_or_default();
        for i in 0..mx {
            // SAFETY: as above.
            let mut ptr = unsafe { get(from, i) };
            let callback = usize::try_from(i).ok().and_then(|i| callbacks.get(i)).cloned().flatten();
            if let Some(callback) = callback
                && let Funcs::Registered { dup: Some(dup), .. } = callback.funcs
            {
                // SAFETY: the caller's guarantee about the callbacks.
                if unsafe { dup(to, from, &mut ptr, i, callback.argl, callback.argp) } == 0 {
                    return 0;
                }
            }
            // SAFETY: as above.
            unsafe { set(to, i, ptr) };
        }
        1
    }
}

/// One free callback to run, laid out as OpenSSL's `struct ex_callback_entry` (16 bytes), as
/// `qsort` sees it.
#[repr(C)]
struct FreeEntry {
    callback: *const Callback,
    index: c_int,
    priority: c_int,
}

/// OpenSSL's `ex_callback_compare`: higher priority first, missing callbacks last.
unsafe extern "C" fn by_priority(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: qsort passes pointers to two entries of the array being sorted.
    let a = unsafe { &*a.cast::<FreeEntry>() };
    // SAFETY: as above.
    let b = unsafe { &*b.cast::<FreeEntry>() };
    if a.callback == b.callback {
        return 0;
    }
    if a.callback.is_null() {
        return 1;
    }
    if b.callback.is_null() {
        return -1;
    }
    if a.priority == b.priority {
        return 0;
    }
    if a.priority > b.priority { -1 } else { 1 }
}

ffi_export! {
    /// Ends an object's application data: runs the class's free callbacks, highest priority
    /// first, then frees the values stack and clears `ad`. A class out of range still frees
    /// the stack; a null `ad` does nothing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `ad` is null or valid, with a null or live stack; the callbacks accept `obj`.
    pub unsafe extern "C" fn CRYPTO_free_ex_data(class_index: c_int, obj: *mut c_void, ad: *mut CRYPTO_EX_DATA)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if ad.is_null() {
            return;
        }
        if let Some(Some(callbacks)) = snapshot(class_index, "CRYPTO_free_ex_data") {
            let mut entries: Vec<FreeEntry> = callbacks
                .iter()
                .enumerate()
                .map(|(i, c)| FreeEntry {
                    callback: c.as_ref().map_or(ptr::null(), Arc::as_ptr),
                    index: number(i),
                    priority: c.as_ref().map_or(0, |c| c.priority),
                })
                .collect();
            // SAFETY: the comparator takes pointers to entries.
            unsafe { stack::qsort(&mut entries, by_priority) };
            for entry in &entries {
                let callback = usize::try_from(entry.index).ok().and_then(|i| callbacks.get(i)).cloned().flatten();
                let Some(callback) = callback else { continue };
                let Funcs::Registered { free: Some(free), .. } = callback.funcs else { continue };
                // SAFETY: the caller's guarantee about `ad`.
                let ptr = unsafe { get(ad, entry.index) };
                // SAFETY: the caller's guarantee about the callbacks.
                unsafe { free(obj, ptr, ad, entry.index, callback.argl, callback.argp) };
            }
        }
        // SAFETY: as above.
        let sk = unsafe { values(ad) };
        // SAFETY: the stack is `ad`'s own, and `ad` stops referring to it below.
        unsafe { stack::free(sk) };
        // SAFETY: as above.
        unsafe { ad.write(CRYPTO_EX_DATA { ctx: ptr::null_mut(), sk: ptr::null_mut() }) };
    }
}

ffi_export! {
    /// Stores `val` at `idx`, growing the values stack as needed. Returns 1, or 0 with an
    /// error (also for a negative `idx` with a non-null `val`; with a null one it returns 1,
    /// leaving the stack's error, as OpenSSL does). A null `ad` returns 0 (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `ad` is null or valid, with a null or live stack.
    pub unsafe extern "C" fn CRYPTO_set_ex_data(ad: *mut CRYPTO_EX_DATA, idx: c_int, val: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if ad.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { set(ad, idx, val) }
    }
}

ffi_export! {
    /// Returns the value at `idx`, or null (also for a null `ad`, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `ad` is null or valid, with a null or live stack.
    pub unsafe extern "C" fn CRYPTO_get_ex_data(ad: *const CRYPTO_EX_DATA, idx: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        if ad.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        unsafe { get(ad, idx) }
    }
}

ffi_export! {
    /// Makes sure `idx` has a value: if it has none, runs the index's new callback, which
    /// should set one. Returns 1, or 0 if the index has no new callback or doesn't exist (where
    /// OpenSSL's would crash, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `ad` is null or valid, with a null or live stack; the callback accepts `obj`.
    pub unsafe extern "C" fn CRYPTO_alloc_ex_data(class_index: c_int, obj: *mut c_void, ad: *mut CRYPTO_EX_DATA, idx: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if ad.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        if !unsafe { get(ad, idx) }.is_null() {
            return 1;
        }
        let Some(indexes) = snapshot(class_index, "CRYPTO_alloc_ex_data") else {
            return 0;
        };
        let callback = indexes
            .as_ref()
            .and_then(|i| i.get(usize::try_from(idx).ok()?))
            .cloned()
            .flatten();
        let Some(callback) = callback else {
            return 0;
        };
        match callback.funcs {
            Funcs::Freed => 1,
            Funcs::Registered { new: None, .. } => 0,
            Funcs::Registered { new: Some(new), .. } => {
                // SAFETY: the caller's guarantee about the callback.
                unsafe { new(obj, ptr::null_mut(), ad, idx, callback.argl, callback.argp) };
                1
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: null `CRYPTO_EX_DATA` and missing indexes.
    #[test]
    fn null_data_and_missing_indexes_fail() {
        // SAFETY: nulls are the case under test, for each call below.
        let started = unsafe { CRYPTO_new_ex_data(0, ptr::null_mut(), ptr::null_mut()) };
        assert_eq!(started, 0);
        // SAFETY: as above.
        let set = unsafe { CRYPTO_set_ex_data(ptr::null_mut(), 1, ptr::null_mut()) };
        assert_eq!(set, 0);
        // SAFETY: as above.
        assert!(unsafe { CRYPTO_get_ex_data(ptr::null(), 1) }.is_null());
        // SAFETY: as above.
        unsafe { CRYPTO_free_ex_data(0, ptr::null_mut(), ptr::null_mut()) };
        let mut ad = CRYPTO_EX_DATA {
            ctx: ptr::null_mut(),
            sk: ptr::null_mut(),
        };
        let class = rustyssl_abi::CRYPTO_EX_INDEX_DRBG;
        // SAFETY: `ad` is a valid, empty CRYPTO_EX_DATA.
        let allocated = unsafe { CRYPTO_alloc_ex_data(class, ptr::null_mut(), &mut ad, 40) };
        assert_eq!(allocated, 0);
        // SAFETY: as above.
        unsafe { CRYPTO_free_ex_data(class, ptr::null_mut(), &mut ad) };
    }
}
