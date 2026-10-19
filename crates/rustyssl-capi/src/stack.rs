//! The generic stack (`OPENSSL_sk_*`, `OPENSSL_sk_new(3)`): an array of pointers the
//! application owns, with an optional comparator. The typed `sk_TYPE_*` wrappers in
//! `safestack.h` are inline functions over these.
//!
//! As in OpenSSL 3.5:
//! - Finding uses the comparator when there is one: a linear search on an unsorted stack (it
//!   no longer sorts it, as 1.1.1 did), and OpenSSL's binary search on a sorted one, which
//!   lands on the same element after the same comparisons. Without a comparator it compares
//!   pointers.
//! - Sorting is the C library's `qsort`, so elements that compare equal end up in the same
//!   order as with OpenSSL on the same system.
//! - Changing the elements or the comparator clears the sorted flag.
//!
//! A stack is a Rust object behind a handle. No lock is held while the application's
//! comparator, copy, or free function runs: those work on a copy of the elements, so a
//! callback that uses the same stack sees a consistent one and can't invalidate the search.

use core::ffi::{c_int, c_void};
use core::ptr;
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use rustyssl_abi::{
    CRYPTO_R_TOO_MANY_RECORDS, ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT,
    ERR_R_PASSED_NULL_PARAMETER, OPENSSL_STACK, OPENSSL_sk_compfunc, OPENSSL_sk_copyfunc,
    OPENSSL_sk_freefunc, OPENSSL_sk_freefunc_thunk,
};

use crate::err;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};

/// An element: a pointer the application owns, never dereferenced here.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub(crate) struct Element(pub(crate) *const c_void);

// SAFETY: elements are only stored and handed back; their owners decide how they're shared.
unsafe impl Send for Element {}
// SAFETY: as above.
unsafe impl Sync for Element {}

/// The comparator, which is a C function pointer.
#[derive(Clone, Copy)]
struct Comparator(OPENSSL_sk_compfunc);

impl Comparator {
    /// The function's address, for telling comparators apart.
    fn address(self) -> Option<usize> {
        self.0.map(|f| f as usize)
    }
}

/// The free thunk 3.6's typed stacks set (`OPENSSL_sk_set_thunks`): it calls the element type's
/// free function through `OPENSSL_sk_pop_free`'s untyped one.
#[derive(Clone, Copy)]
struct Thunk(OPENSSL_sk_freefunc_thunk);

struct Inner {
    data: Vec<Element>,
    sorted: bool,
    comp: Comparator,
    thunk: Thunk,
}

/// What a stack handle points to.
pub(crate) struct Stack(RwLock<Inner>);

handle_type!(OPENSSL_STACK => Stack);

/// The most elements a stack holds: the largest `int`, as the count is one.
const MAX_NODES: usize = c_int::MAX.unsigned_abs() as usize;

/// The smallest capacity OpenSSL gives a stack once it has elements.
const MIN_NODES: usize = 4;

impl Stack {
    fn new(comp: OPENSSL_sk_compfunc) -> Self {
        Self(RwLock::new(Inner {
            data: Vec::new(),
            sorted: false,
            comp: Comparator(comp),
            thunk: Thunk(None),
        }))
    }

    fn read(&self) -> RwLockReadGuard<'_, Inner> {
        self.0.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, Inner> {
        self.0.write().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The stack behind `handle`, or `None` for null.
///
/// # Safety
/// `handle` is null or a live stack handle that outlives `'a`.
unsafe fn stack<'a>(handle: *const OPENSSL_STACK) -> Option<&'a Stack> {
    // SAFETY: the caller's guarantee.
    unsafe { OPENSSL_STACK::get(handle) }
}

/// A count as the C `int` OpenSSL returns; stacks never hold more than [`MAX_NODES`].
fn count(n: usize) -> c_int {
    c_int::try_from(n).unwrap_or(c_int::MAX)
}

/// Makes room for `n` more elements (OpenSSL's `sk_reserve`). Fails past [`MAX_NODES`], with
/// `CRYPTO_R_TOO_MANY_RECORDS`, or if memory runs out.
#[track_caller]
fn reserve(inner: &mut Inner, n: usize, function: &str) -> bool {
    if n > MAX_NODES - inner.data.len() {
        err::raise(ERR_LIB_CRYPTO, CRYPTO_R_TOO_MANY_RECORDS, function);
        return false;
    }
    let wanted = (inner.data.len() + n).max(MIN_NODES);
    inner.data.try_reserve(wanted - inner.data.len()).is_ok()
}

/// Sorts `data` with the C library's `qsort` and a C comparator, as OpenSSL does. (Miri can't
/// run `qsort`; there a stable sort stands in.)
///
/// # Safety
/// `compare` accepts two pointers to elements of `data`.
pub(crate) unsafe fn qsort<T>(
    data: &mut [T],
    compare: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
) {
    if cfg!(miri) {
        data.sort_by(|a, b| {
            let (a, b) = (ptr::from_ref(a).cast(), ptr::from_ref(b).cast());
            // SAFETY: the caller's guarantee.
            unsafe { compare(a, b) }.cmp(&0)
        });
        return;
    }
    // SAFETY: the slice is `data.len()` elements of `size_of::<T>()` bytes, and the caller
    // guarantees the comparator accepts pointers to them.
    unsafe {
        libc::qsort(
            data.as_mut_ptr().cast(),
            data.len(),
            size_of::<T>(),
            Some(compare),
        );
    }
}

/// OpenSSL's `ossl_bsearch` over `data` for `key`, with the same probes: returns the index of
/// a match (the first of a run with `first`), else the last index probed if `nearest`, else
/// `None`.
///
/// # Safety
/// `compare` accepts pointers to `key` and to elements of `data`.
unsafe fn bsearch(
    key: &Element,
    data: &[Element],
    compare: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
    first: bool,
    nearest: bool,
) -> Option<usize> {
    let call = |i: usize| -> c_int {
        let element = data.get(i).map_or(ptr::null(), |e| ptr::from_ref(e).cast());
        // SAFETY: the caller's guarantee; `i` is inside `data`.
        unsafe { compare(ptr::from_ref(key).cast(), element) }
    };
    if data.is_empty() {
        return None;
    }
    let (mut low, mut high, mut i, mut c) = (0, data.len(), 0, 0);
    while low < high {
        i = low + (high - low) / 2;
        c = call(i);
        if c < 0 {
            high = i;
        } else if c > 0 {
            low = i + 1;
        } else {
            break;
        }
    }
    if c != 0 {
        return nearest.then_some(i);
    }
    if first {
        while i > 0 && call(i - 1) == 0 {
            i -= 1;
        }
    }
    Some(i)
}

/// What `OPENSSL_sk_find` and its variants return when nothing matches.
const NOT_FOUND: c_int = -1;

/// OpenSSL's `internal_find`. `nearest` is `OPENSSL_sk_find_ex`'s mode; `matches` is
/// `OPENSSL_sk_find_all`'s count, which an unsorted search adds to as OpenSSL's does.
///
/// # Safety
/// `stack` is null or a live stack handle; `matches` is null or valid for reads and writes.
unsafe fn find(
    stack_handle: *mut OPENSSL_STACK,
    data: *const c_void,
    nearest: bool,
    matches: *mut c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(stack) = (unsafe { self::stack(stack_handle) }) else {
        return NOT_FOUND;
    };
    let (elements, sorted, comp) = {
        let inner = stack.read();
        if inner.data.is_empty() {
            return NOT_FOUND;
        }
        let Some(comp) = inner.comp.0 else {
            let found = inner.data.iter().position(|e| e.0 == data);
            drop(inner);
            if !matches.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { matches.write(c_int::from(found.is_some())) };
            }
            return found.map_or(NOT_FOUND, count);
        };
        (inner.data.clone(), inner.sorted, comp)
    };
    if data.is_null() {
        return NOT_FOUND;
    }
    let key = Element(data);
    let compare = |e: &Element| {
        // SAFETY: the stack's comparator takes pointers to elements.
        unsafe { comp(ptr::from_ref(&key).cast(), ptr::from_ref(e).cast()) }
    };
    if !sorted {
        let mut first = None;
        let mut found: c_int = 0;
        for (i, element) in elements.iter().enumerate() {
            if compare(element) == 0 {
                first = first.or(Some(i));
                found += 1;
                if matches.is_null() {
                    break;
                }
            }
        }
        if !matches.is_null() {
            let total = if first.is_none() {
                0
            } else {
                // SAFETY: the caller's guarantee.
                unsafe { matches.read() }.wrapping_add(found)
            };
            // SAFETY: as above.
            unsafe { matches.write(total) };
        }
        return first.map_or(NOT_FOUND, count);
    }
    let first = !matches.is_null() || !nearest;
    // SAFETY: as above.
    let found = unsafe { bsearch(&key, &elements, comp, first, nearest) };
    if !matches.is_null() {
        let run = found.map_or(0, |i| {
            elements
                .get(i..)
                .unwrap_or_default()
                .iter()
                .take_while(|e| compare(e) == 0)
                .count()
        });
        // SAFETY: as above.
        unsafe { matches.write(count(run)) };
    }
    found.map_or(NOT_FOUND, count)
}

/// Creates a stack with room for `n` elements, as `OPENSSL_sk_new_reserve` does.
pub(crate) fn new_reserve(comp: OPENSSL_sk_compfunc, n: c_int) -> *mut OPENSSL_STACK {
    let stack = Stack::new(comp);
    if let Ok(n) = usize::try_from(n)
        && n > 0
        && !reserve(&mut stack.write(), n, "OPENSSL_sk_new_reserve")
    {
        return ptr::null_mut();
    }
    OPENSSL_STACK::new_handle(stack)
}

/// `OPENSSL_sk_insert`.
///
/// # Safety
/// `handle` is null or a live stack handle.
#[track_caller]
pub(crate) unsafe fn insert(
    handle: *mut OPENSSL_STACK,
    data: *const c_void,
    loc: c_int,
    function: &str,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(stack) = (unsafe { stack(handle) }) else {
        err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, function);
        return 0;
    };
    let mut inner = stack.write();
    if inner.data.len() >= MAX_NODES {
        err::raise(ERR_LIB_CRYPTO, CRYPTO_R_TOO_MANY_RECORDS, function);
        return 0;
    }
    if inner.data.len() == inner.data.capacity() && !reserve(&mut inner, 1, function) {
        return 0;
    }
    match usize::try_from(loc) {
        Ok(at) if at < inner.data.len() => inner.data.insert(at, Element(data)),
        _ => inner.data.push(Element(data)),
    }
    inner.sorted = false;
    count(inner.data.len())
}

/// `OPENSSL_sk_num`: the number of elements, or -1 for null.
///
/// # Safety
/// `handle` is null or a live stack handle.
pub(crate) unsafe fn num(handle: *const OPENSSL_STACK) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { stack(handle) }.map_or(-1, |s| count(s.read().data.len()))
}

/// `OPENSSL_sk_value`: element `i`, or null if there is none.
///
/// # Safety
/// `handle` is null or a live stack handle.
pub(crate) unsafe fn value(handle: *const OPENSSL_STACK, i: c_int) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let Some(stack) = (unsafe { stack(handle) }) else {
        return ptr::null_mut();
    };
    let at = usize::try_from(i).ok();
    let inner = stack.read();
    at.and_then(|at| inner.data.get(at))
        .map_or(ptr::null_mut(), |e| e.0.cast_mut())
}

/// `OPENSSL_sk_set`: replaces element `i` and returns the new one, or fails with null.
///
/// # Safety
/// `handle` is null or a live stack handle.
#[track_caller]
pub(crate) unsafe fn set(
    handle: *mut OPENSSL_STACK,
    i: c_int,
    data: *const c_void,
    function: &str,
) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let Some(stack) = (unsafe { stack(handle) }) else {
        err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, function);
        return ptr::null_mut();
    };
    let mut inner = stack.write();
    let slot = usize::try_from(i)
        .ok()
        .and_then(|at| inner.data.get_mut(at));
    let Some(slot) = slot else {
        drop(inner);
        let text = format!("i={i}");
        err::raise_with_text(
            ERR_LIB_CRYPTO,
            ERR_R_PASSED_INVALID_ARGUMENT,
            function,
            &text,
        );
        return ptr::null_mut();
    };
    *slot = Element(data);
    inner.sorted = false;
    data.cast_mut()
}

/// Frees a stack, not its elements (`OPENSSL_sk_free`).
///
/// # Safety
/// `handle` is null or a live stack handle, not used afterwards.
pub(crate) unsafe fn free(handle: *mut OPENSSL_STACK) {
    // SAFETY: the caller's guarantee.
    unsafe { OPENSSL_STACK::free(handle) };
}

/// A copy of the stack's elements, sorted flag, and comparator, or an empty stack's for null.
///
/// # Safety
/// `handle` is null or a live stack handle.
unsafe fn snapshot(handle: *const OPENSSL_STACK) -> (Vec<Element>, bool, Comparator) {
    // SAFETY: the caller's guarantee.
    match unsafe { stack(handle) } {
        Some(stack) => {
            let inner = stack.read();
            (inner.data.clone(), inner.sorted, inner.comp)
        }
        None => (Vec::new(), false, Comparator(None)),
    }
}

/// The stack's free thunk (none for null).
///
/// # Safety
/// `handle` is null or a live stack.
unsafe fn thunk_of(handle: *const OPENSSL_STACK) -> Thunk {
    // SAFETY: the caller's guarantee.
    unsafe { stack(handle) }.map_or(Thunk(None), |s| s.read().thunk)
}

/// A new stack holding `data`.
fn with_elements(
    data: Vec<Element>,
    sorted: bool,
    comp: Comparator,
    thunk: Thunk,
) -> *mut OPENSSL_STACK {
    OPENSSL_STACK::new_handle(Stack(RwLock::new(Inner {
        data,
        sorted,
        comp,
        thunk,
    })))
}

ffi_export! {
    /// Returns a new empty stack without a comparator.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        new_reserve(None, 0)
    }
}

ffi_export! {
    /// Returns a new empty stack ordered by `cmp`, which receives pointers to the elements.
    ///
    /// # Safety
    /// `cmp` is null or a comparator for the elements the stack will hold.
    pub unsafe extern "C" fn OPENSSL_sk_new(cmp: OPENSSL_sk_compfunc) -> *mut OPENSSL_STACK
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        new_reserve(cmp, 0)
    }
}

ffi_export! {
    /// `OPENSSL_sk_new` with room for `n` elements; `n` of 0 or less reserves nothing.
    ///
    /// # Safety
    /// As for `OPENSSL_sk_new`.
    pub unsafe extern "C" fn OPENSSL_sk_new_reserve(c: OPENSSL_sk_compfunc, n: c_int) -> *mut OPENSSL_STACK
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        new_reserve(c, n)
    }
}

ffi_export! {
    /// Makes room for `n` more elements. Returns 1 (also for negative `n`), or 0 for a null
    /// stack or past the limit, with an error.
    ///
    /// # Safety
    /// `st` is null or a live stack.
    pub unsafe extern "C" fn OPENSSL_sk_reserve(st: *mut OPENSSL_STACK, n: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(stack) = (unsafe { stack(st) }) else {
            err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, "OPENSSL_sk_reserve");
            return 0;
        };
        let Ok(n) = usize::try_from(n) else {
            return 1;
        };
        c_int::from(reserve(&mut stack.write(), n, "OPENSSL_sk_reserve"))
    }
}

ffi_export! {
    /// Frees the stack, not its elements. Null is ignored.
    ///
    /// # Safety
    /// `st` is null or a live stack, not used afterwards.
    pub unsafe extern "C" fn OPENSSL_sk_free(st: *mut OPENSSL_STACK)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { free(st) };
    }
}

ffi_export! {
    /// Calls `func` on each non-null element, in order, then frees the stack. Null is ignored;
    /// a null `func` frees only the stack (OpenSSL's would crash, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `st` is null or a live stack, not used afterwards; `func` accepts its elements.
    pub unsafe extern "C" fn OPENSSL_sk_pop_free(st: *mut OPENSSL_STACK, func: OPENSSL_sk_freefunc)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let (elements, _, _) = unsafe { snapshot(st) };
        // SAFETY: as above.
        let thunk = unsafe { thunk_of(st) };
        if let Some(func) = func {
            for element in elements.iter().filter(|e| !e.0.is_null()) {
                match thunk.0 {
                    // SAFETY: the thunk the stack's typed constructor set, for its elements.
                    Some(t) => unsafe { t(Some(func), element.0.cast_mut()) },
                    // SAFETY: the caller's guarantee about `func`.
                    None => unsafe { func(element.0.cast_mut()) },
                }
            }
        }
        // SAFETY: as above.
        unsafe { free(st) };
    }
}

ffi_export! {
    /// Sets the free thunk `OPENSSL_sk_pop_free` calls each element's free function through
    /// (3.6; the typed constructors in `safestack.h` call it). Returns the stack; null does
    /// nothing.
    ///
    /// # Safety
    /// `st` is null or a live stack; `f_thunk` is null or takes its elements.
    pub unsafe extern "C" fn OPENSSL_sk_set_thunks(st: *mut OPENSSL_STACK, f_thunk: OPENSSL_sk_freefunc_thunk) -> *mut OPENSSL_STACK
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        if let Some(s) = unsafe { stack(st) } {
            s.write().thunk = Thunk(f_thunk);
        }
        st
    }
}

ffi_export! {
    /// Returns the number of elements, or -1 for a null stack.
    ///
    /// # Safety
    /// `st` is null or a live stack.
    pub unsafe extern "C" fn OPENSSL_sk_num(st: *const OPENSSL_STACK) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { num(st) }
    }
}

ffi_export! {
    /// Returns element `i`, or null if `i` is out of range or the stack is null.
    ///
    /// # Safety
    /// `st` is null or a live stack.
    pub unsafe extern "C" fn OPENSSL_sk_value(st: *const OPENSSL_STACK, i: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { value(st, i) }
    }
}

ffi_export! {
    /// Replaces element `i` and returns `data`. Fails with null and an error for a null stack
    /// or an index out of range (the error's data names the index).
    ///
    /// # Safety
    /// `st` is null or a live stack.
    pub unsafe extern "C" fn OPENSSL_sk_set(st: *mut OPENSSL_STACK, i: c_int, data: *const c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { set(st, i, data, "OPENSSL_sk_set") }
    }
}

ffi_export! {
    /// Inserts `data` before element `loc`, or at the end if `loc` is negative or past it.
    /// Returns the new count, or 0 for a null stack (with an error) or failure.
    ///
    /// # Safety
    /// `sk` is null or a live stack.
    pub unsafe extern "C" fn OPENSSL_sk_insert(sk: *mut OPENSSL_STACK, data: *const c_void, where_: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { insert(sk, data, where_, "OPENSSL_sk_insert") }
    }
}

ffi_export! {
    /// Appends `data`. Returns the new count, or 0 for a null stack or failure.
    ///
    /// # Safety
    /// `st` is null or a live stack.
    pub unsafe extern "C" fn OPENSSL_sk_push(st: *mut OPENSSL_STACK, data: *const c_void) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if st.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { insert(st, data, -1, "OPENSSL_sk_insert") }
    }
}

ffi_export! {
    /// Inserts `data` at the front. Returns the new count, or 0 for a null stack (with an
    /// error) or failure.
    ///
    /// # Safety
    /// `st` is null or a live stack.
    pub unsafe extern "C" fn OPENSSL_sk_unshift(st: *mut OPENSSL_STACK, data: *const c_void) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { insert(st, data, 0, "OPENSSL_sk_insert") }
    }
}

/// Removes and returns element `at`, if there is one.
///
/// # Safety
/// `handle` is null or a live stack handle.
unsafe fn remove(
    handle: *mut OPENSSL_STACK,
    at: impl FnOnce(&[Element]) -> Option<usize>,
) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let Some(stack) = (unsafe { stack(handle) }) else {
        return ptr::null_mut();
    };
    let mut inner = stack.write();
    match at(&inner.data) {
        Some(at) if at < inner.data.len() => inner.data.remove(at).0.cast_mut(),
        _ => ptr::null_mut(),
    }
}

ffi_export! {
    /// Removes and returns the first element; null if there is none.
    ///
    /// # Safety
    /// `st` is null or a live stack.
    pub unsafe extern "C" fn OPENSSL_sk_shift(st: *mut OPENSSL_STACK) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { remove(st, |_| Some(0)) }
    }
}

ffi_export! {
    /// Removes and returns the last element; null if there is none.
    ///
    /// # Safety
    /// `st` is null or a live stack.
    pub unsafe extern "C" fn OPENSSL_sk_pop(st: *mut OPENSSL_STACK) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { remove(st, |data| data.len().checked_sub(1)) }
    }
}

ffi_export! {
    /// Removes and returns element `loc`; null if there is none.
    ///
    /// # Safety
    /// `st` is null or a live stack.
    pub unsafe extern "C" fn OPENSSL_sk_delete(st: *mut OPENSSL_STACK, loc: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { remove(st, |_| usize::try_from(loc).ok()) }
    }
}

ffi_export! {
    /// Removes the first element that is `p` itself and returns it; null if there is none.
    ///
    /// # Safety
    /// `st` is null or a live stack.
    pub unsafe extern "C" fn OPENSSL_sk_delete_ptr(st: *mut OPENSSL_STACK, p: *const c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { remove(st, |data| data.iter().position(|e| e.0 == p)) }
    }
}

ffi_export! {
    /// Removes every element.
    ///
    /// # Safety
    /// `st` is null or a live stack.
    pub unsafe extern "C" fn OPENSSL_sk_zero(st: *mut OPENSSL_STACK)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        if let Some(stack) = unsafe { stack(st) } {
            stack.write().data.clear();
        }
    }
}

ffi_export! {
    /// Returns the index of an element matching `data`: by the comparator (the first match on
    /// an unsorted stack, by a linear search; the first of a run on a sorted one, by a binary
    /// search), or by pointer without one. -1 if none matches.
    ///
    /// # Safety
    /// `st` is null or a live stack.
    pub unsafe extern "C" fn OPENSSL_sk_find(st: *mut OPENSSL_STACK, data: *const c_void) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { find(st, data, false, ptr::null_mut()) }
    }
}

ffi_export! {
    /// `OPENSSL_sk_find`, except that on a sorted stack a missing value gives the index where
    /// the binary search stopped, and a match isn't necessarily the first of its run.
    ///
    /// # Safety
    /// `st` is null or a live stack.
    pub unsafe extern "C" fn OPENSSL_sk_find_ex(st: *mut OPENSSL_STACK, data: *const c_void) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { find(st, data, true, ptr::null_mut()) }
    }
}

ffi_export! {
    /// `OPENSSL_sk_find`, also counting the matches into `pnum`. On an unsorted stack the
    /// count is added to `*pnum`, as OpenSSL does; on a sorted one it replaces it.
    ///
    /// # Safety
    /// `st` is null or a live stack; `pnum` is null or valid for reads and writes.
    pub unsafe extern "C" fn OPENSSL_sk_find_all(st: *mut OPENSSL_STACK, data: *const c_void, pnum: *mut c_int) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { find(st, data, false, pnum) }
    }
}

ffi_export! {
    /// Sorts the stack with its comparator (with the C library's `qsort`), unless it is sorted
    /// already or has no comparator.
    ///
    /// # Safety
    /// `st` is null or a live stack.
    pub unsafe extern "C" fn OPENSSL_sk_sort(st: *mut OPENSSL_STACK)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(stack) = (unsafe { stack(st) }) else {
            return;
        };
        let (mut elements, comp) = {
            let mut inner = stack.write();
            let Some(comp) = inner.comp.0.filter(|_| !inner.sorted) else {
                return;
            };
            (core::mem::take(&mut inner.data), comp)
        };
        if elements.len() > 1 {
            // SAFETY: the stack's comparator takes pointers to elements.
            unsafe { qsort(&mut elements, comp) };
        }
        let mut inner = stack.write();
        // Anything a comparator added meanwhile goes after the sorted elements.
        elements.append(&mut inner.data);
        inner.data = elements;
        inner.sorted = true;
    }
}

ffi_export! {
    /// Returns 1 if the stack is sorted (or null), else 0.
    ///
    /// # Safety
    /// `st` is null or a live stack.
    pub unsafe extern "C" fn OPENSSL_sk_is_sorted(st: *const OPENSSL_STACK) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { stack(st) }.map_or(1, |s| c_int::from(s.read().sorted))
    }
}

ffi_export! {
    /// Sets the comparator and returns the old one; a different one clears the sorted flag.
    /// A null stack returns null (OpenSSL's would crash, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `sk` is null or a live stack; `cmp` is null or a comparator for its elements.
    pub unsafe extern "C" fn OPENSSL_sk_set_cmp_func(sk: *mut OPENSSL_STACK, cmp: OPENSSL_sk_compfunc) -> OPENSSL_sk_compfunc
    where failure = None, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let stack = unsafe { stack(sk) }?;
        let mut inner = stack.write();
        let old = inner.comp;
        if old.address() != Comparator(cmp).address() {
            inner.sorted = false;
        }
        inner.comp = Comparator(cmp);
        old.0
    }
}

ffi_export! {
    /// Returns a new stack with the same elements, comparator, and sorted flag; an empty one
    /// for null.
    ///
    /// # Safety
    /// `sk` is null or a live stack.
    pub unsafe extern "C" fn OPENSSL_sk_dup(sk: *const OPENSSL_STACK) -> *mut OPENSSL_STACK
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let (elements, sorted, comp) = unsafe { snapshot(sk) };
        // SAFETY: as above.
        with_elements(elements, sorted, comp, unsafe { thunk_of(sk) })
    }
}

ffi_export! {
    /// Returns a new stack holding `copy_func`'s copy of each non-null element (null ones stay
    /// null), with the same comparator and sorted flag; an empty stack for null. If a copy
    /// fails, the copies made so far are freed with `free_func`, newest first, and the result
    /// is null. Without `copy_func` a stack with elements can't be copied (OpenSSL's would
    /// crash, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `sk` is null or a live stack; `copy_func` and `free_func` are null or accept its
    /// elements.
    pub unsafe extern "C" fn OPENSSL_sk_deep_copy(sk: *const OPENSSL_STACK, copy_func: OPENSSL_sk_copyfunc, free_func: OPENSSL_sk_freefunc) -> *mut OPENSSL_STACK
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let (elements, sorted, comp) = unsafe { snapshot(sk) };
        let mut copies = Vec::new();
        if copies.try_reserve_exact(elements.len().max(MIN_NODES)).is_err() {
            return ptr::null_mut();
        }
        for element in elements {
            if element.0.is_null() {
                copies.push(element);
                continue;
            }
            // SAFETY: the caller's guarantee about `copy_func`.
            let copy = copy_func.map_or(ptr::null_mut(), |f| unsafe { f(element.0) });
            if copy.is_null() {
                for made in copies.iter().rev().filter(|c| !c.0.is_null()) {
                    if let Some(free_func) = free_func {
                        // SAFETY: the caller's guarantee about `free_func`.
                        unsafe { free_func(made.0.cast_mut()) };
                    }
                }
                return ptr::null_mut();
            }
            copies.push(Element(copy));
        }
        // SAFETY: the caller's guarantee.
        with_elements(copies, sorted, comp, unsafe { thunk_of(sk) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static VALUES: [c_int; 6] = [5, 3, 9, 3, 7, 1];

    unsafe extern "C" fn by_value(a: *const c_void, b: *const c_void) -> c_int {
        // SAFETY: the stacks below hold pointers into VALUES, or the key, an int.
        let a = unsafe { *a.cast::<*const c_int>() };
        // SAFETY: as above.
        let b = unsafe { *b.cast::<*const c_int>() };
        // SAFETY: as above.
        let a = unsafe { *a };
        // SAFETY: as above.
        let b = unsafe { *b };
        c_int::from(a > b) - c_int::from(a < b)
    }

    fn element(i: usize) -> *const c_void {
        ptr::from_ref(&VALUES[i]).cast()
    }

    /// A stack of all of VALUES, with the comparator.
    fn filled() -> *mut OPENSSL_STACK {
        // SAFETY: a valid comparator.
        let st = unsafe { OPENSSL_sk_new(Some(by_value)) };
        for i in 0..VALUES.len() {
            // SAFETY: a live stack.
            unsafe { OPENSSL_sk_push(st, element(i)) };
        }
        st
    }

    #[test]
    fn find_follows_openssl() {
        let st = filled();
        let three = ptr::from_ref(&3).cast();
        let four = ptr::from_ref(&4).cast();
        let mut n = 10;
        // SAFETY: a live stack, for each call below.
        assert_eq!(unsafe { OPENSSL_sk_find(st, three) }, 1);
        // SAFETY: as above.
        assert_eq!(unsafe { OPENSSL_sk_find_all(st, three, &mut n) }, 1);
        assert_eq!(n, 12, "unsorted: added to the caller's count");
        // SAFETY: as above.
        unsafe { OPENSSL_sk_sort(st) };
        // SAFETY: as above.
        assert_eq!(unsafe { OPENSSL_sk_is_sorted(st) }, 1);
        // SAFETY: as above.
        assert_eq!(unsafe { OPENSSL_sk_find(st, three) }, 1);
        // SAFETY: as above.
        assert_eq!(unsafe { OPENSSL_sk_find_all(st, three, &mut n) }, 1);
        assert_eq!(n, 2);
        // SAFETY: as above.
        assert_eq!(unsafe { OPENSSL_sk_find(st, four) }, -1);
        // SAFETY: as above.
        assert!(unsafe { OPENSSL_sk_find_ex(st, four) } >= 0);
        // SAFETY: as above.
        unsafe { OPENSSL_sk_free(st) };
    }

    #[test]
    fn set_out_of_range_names_the_index() {
        crate::err::take_all();
        // SAFETY: no preconditions.
        let st = unsafe { OPENSSL_sk_new_null() };
        // SAFETY: a live stack.
        assert!(unsafe { OPENSSL_sk_set(st, 3, element(0)) }.is_null());
        // SAFETY: as above.
        unsafe { OPENSSL_sk_free(st) };
        let errors = crate::err::take_all();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].function, "OPENSSL_sk_set");
    }

    /// docs/DEVIATIONS.md: null callbacks and stacks where OpenSSL's would crash.
    #[test]
    fn null_callbacks_are_refused() {
        let st = filled();
        // SAFETY: a live stack; the null callbacks are the case under test.
        assert!(unsafe { OPENSSL_sk_deep_copy(st, None, None) }.is_null());
        // SAFETY: as above.
        unsafe { OPENSSL_sk_pop_free(st, None) };
        // SAFETY: a null stack is the case under test.
        assert!(unsafe { OPENSSL_sk_set_cmp_func(ptr::null_mut(), Some(by_value)) }.is_none());
    }
}
