//! The name registry (`OBJ_NAME_add(3)`, `OBJ_NAME_get`, `OBJ_NAME_do_all`, ...): names of
//! some type, each mapped to data or, as an alias, to another name. OpenSSL's EVP layer keeps
//! cipher and digest names here; applications can add types with `OBJ_NAME_new_index`.
//!
//! As in OpenSSL, names and data are the caller's pointers, not copies, and the registry is one
//! of OpenSSL's hash tables (`OPENSSL_LH_*`, by default hashing and comparing names without
//! regard to ASCII case), so `OBJ_NAME_do_all` visits names in OpenSSL's order. No lock is held
//! while an application's hash, comparison, free, or visiting function runs.

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use core::ptr;
use std::sync::{Mutex, PoisonError};

use rustyssl_abi::{ERR_LIB_OBJ, OBJ_NAME, OBJ_NAME_ALIAS, OBJ_NAME_TYPE_NUM, OPENSSL_LHASH};

use crate::ffi::{ffi_callback, ffi_export};
use crate::lhash::{
    OPENSSL_LH_delete, OPENSSL_LH_doall_arg, OPENSSL_LH_error, OPENSSL_LH_get_down_load,
    OPENSSL_LH_insert, OPENSSL_LH_new, OPENSSL_LH_retrieve, OPENSSL_LH_set_down_load,
};
use crate::mem;
use crate::string::OPENSSL_strcasecmp;

type HashFunc = unsafe extern "C" fn(*const c_char) -> c_ulong;
type CompareFunc = unsafe extern "C" fn(*const c_char, *const c_char) -> c_int;
type FreeFunc = unsafe extern "C" fn(*const c_char, c_int, *const c_char);

/// The functions of a type added with `OBJ_NAME_new_index` (OpenSSL's `NAME_FUNCS`).
#[derive(Clone, Copy)]
struct Funcs {
    hash: HashFunc,
    compare: CompareFunc,
    free: Option<FreeFunc>,
}

struct State {
    /// The table, made at first use. A table is never freed, so it can be used without the
    /// lock; `OBJ_NAME_cleanup(-1)` empties it and starts a new one.
    table: *mut OPENSSL_LHASH,
    /// Tables `OBJ_NAME_cleanup(-1)` emptied, which another thread may still be using.
    retired: Vec<*mut OPENSSL_LHASH>,
    /// One entry for each type up to the newest from `OBJ_NAME_new_index`, once there is one.
    funcs: Option<Vec<Funcs>>,
    /// The type `OBJ_NAME_new_index` hands out next.
    next_type: c_int,
}

// SAFETY: the table is safe to use from any thread; the rest is only used under the mutex.
unsafe impl Send for State {}

static STATE: Mutex<State> = Mutex::new(State {
    table: ptr::null_mut(),
    retired: Vec::new(),
    funcs: None,
    next_type: OBJ_NAME_TYPE_NUM,
});

fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The functions of `kind`, if `OBJ_NAME_new_index` has set up that many types.
fn funcs_of(kind: c_int) -> Option<Funcs> {
    let state = state();
    state
        .funcs
        .as_ref()?
        .get(usize::try_from(kind).ok()?)
        .copied()
}

ffi_callback! {
    /// OpenSSL's `ossl_lh_strcasehash`: `OPENSSL_LH_strhash` without regard to ASCII case.
    ///
    /// # Safety
    /// `c` is NULL or a NUL-terminated string.
    pub(crate) unsafe extern "C" fn strcasehash(c: *const c_char) -> c_ulong
    where failure = 0, library = ERR_LIB_OBJ
    {
        if c.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let text = unsafe { core::ffi::CStr::from_ptr(c) };
        let mut hash: u64 = 0;
        let mut n: u64 = 0x100;
        for &byte in text.to_bytes() {
            // `case_adjust & *c` with C's `char`, sign-extended where `char` is signed.
            let character = i64::from(c_char::from_ne_bytes([byte]));
            let v = n | (!0x20i64 & character).cast_unsigned();
            let r = u32::try_from(((v >> 2) ^ v) & 0x0f).unwrap_or(0);
            hash = (hash << r) | (hash >> (32 - r));
            hash &= 0xFFFF_FFFF;
            hash ^= v.wrapping_mul(v);
            n = n.wrapping_add(0x100);
        }
        c_ulong::from((hash >> 16) ^ hash)
    }
}

/// `type` as OpenSSL mixes it into a hash: converted from `int` to `unsigned long`.
fn widened(kind: c_int) -> c_ulong {
    c_ulong::from_ne_bytes(c_long::from(kind).to_ne_bytes())
}

ffi_callback! {
    /// `obj_name_hash`: the type's hash of the name, mixed with the type.
    ///
    /// # Safety
    /// `a` is a live `OBJ_NAME`.
    pub(crate) unsafe extern "C" fn name_hash(a: *const c_void) -> c_ulong
    where failure = 0, library = ERR_LIB_OBJ
    {
        // SAFETY: the caller's guarantee.
        let name = unsafe { &*a.cast::<OBJ_NAME>() };
        let hash = funcs_of(name.type_).map_or(strcasehash as HashFunc, |f| f.hash);
        // SAFETY: the name is a string, as the type's hash function expects.
        (unsafe { hash(name.name) }) ^ widened(name.type_)
    }
}

ffi_callback! {
    /// `obj_name_cmp`: by type, then with the type's comparison.
    ///
    /// # Safety
    /// `a` and `b` are live `OBJ_NAME`s.
    pub(crate) unsafe extern "C" fn name_compare(a: *const c_void, b: *const c_void) -> c_int
    where failure = 0, library = ERR_LIB_OBJ
    {
        // SAFETY: the caller's guarantee.
        let a = unsafe { &*a.cast::<OBJ_NAME>() };
        // SAFETY: as above.
        let b = unsafe { &*b.cast::<OBJ_NAME>() };
        let difference = a.type_.wrapping_sub(b.type_);
        if difference != 0 {
            return difference;
        }
        let compare = funcs_of(a.type_).map_or(OPENSSL_strcasecmp as CompareFunc, |f| f.compare);
        // SAFETY: the names are strings, as the type's comparison expects.
        unsafe { compare(a.name, b.name) }
    }
}

/// The table, made if there is none yet; NULL if it can't be.
fn table() -> *mut OPENSSL_LHASH {
    let mut state = state();
    if state.table.is_null() {
        // SAFETY: the callbacks take `OBJ_NAME`s, which is what the table holds.
        state.table = unsafe { OPENSSL_LH_new(Some(name_hash), Some(name_compare)) };
    }
    state.table
}

/// The table if it has been made, without making it.
fn existing_table() -> *mut OPENSSL_LHASH {
    state().table
}

/// Runs the type's free function on a removed entry, then frees the entry.
///
/// # Safety
/// `entry` is a live entry just taken out of the table.
unsafe fn discard(entry: *mut OBJ_NAME) {
    // SAFETY: the caller's guarantee.
    let removed = unsafe { *entry };
    if let Some(free) = funcs_of(removed.type_).and_then(|f| f.free) {
        // SAFETY: the application's function, with what it was given.
        unsafe { free(removed.name, removed.type_, removed.data) };
    }
    // SAFETY: entries come from this allocator.
    unsafe { mem::release(entry.cast()) };
}

ffi_export! {
    /// Sets up the registry. Returns 1, or 0 if it can't be.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OBJ_NAME_init() -> c_int
    where failure = 0, library = ERR_LIB_OBJ
    {
        c_int::from(!table().is_null())
    }
}

ffi_export! {
    /// Adds a type of name, returning its number (from `OBJ_NAME_TYPE_NUM` on), with the given
    /// hash, comparison, and free functions (each NULL for the default: no regard to ASCII case,
    /// no freeing). 0 on failure.
    ///
    /// # Safety
    /// The functions are NULL or callable with the names (and data) of this type.
    pub unsafe extern "C" fn OBJ_NAME_new_index(hash_func: Option<HashFunc>, cmp_func: Option<CompareFunc>, free_func: Option<FreeFunc>) -> c_int
    where failure = 0, library = ERR_LIB_OBJ
    {
        if table().is_null() {
            return 0;
        }
        let mut state = state();
        let kind = state.next_type;
        state.next_type = kind.wrapping_add(1);
        let count = usize::try_from(state.next_type).unwrap_or(0);
        let funcs = state.funcs.get_or_insert_with(Vec::new);
        while funcs.len() < count {
            funcs.push(Funcs { hash: strcasehash, compare: OPENSSL_strcasecmp, free: None });
        }
        if let Some(entry) = usize::try_from(kind).ok().and_then(|i| funcs.get_mut(i)) {
            if let Some(hash) = hash_func {
                entry.hash = hash;
            }
            if let Some(compare) = cmp_func {
                entry.compare = compare;
            }
            if free_func.is_some() {
                entry.free = free_func;
            }
        }
        kind
    }
}

ffi_export! {
    /// The data of `name` of type `type`, following aliases (at most 10) unless `type` has
    /// `OBJ_NAME_ALIAS`; NULL if there is none.
    ///
    /// # Safety
    /// `name` is NULL or a NUL-terminated string.
    pub unsafe extern "C" fn OBJ_NAME_get(name: *const c_char, type_: c_int) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_OBJ
    {
        if name.is_null() {
            return ptr::null();
        }
        let table = table();
        if table.is_null() {
            return ptr::null();
        }
        let alias = type_ & OBJ_NAME_ALIAS != 0;
        let mut key = OBJ_NAME { type_: type_ & !OBJ_NAME_ALIAS, alias: 0, name, data: ptr::null() };
        let mut hops = 0;
        loop {
            // SAFETY: a table of `OBJ_NAME`s; the key is one.
            let found = unsafe { OPENSSL_LH_retrieve(table, (&raw const key).cast()) };
            if found.is_null() {
                return ptr::null();
            }
            // SAFETY: entries are live while in the table.
            let entry = unsafe { *found.cast::<OBJ_NAME>() };
            if entry.alias == 0 || alias {
                return entry.data;
            }
            hops += 1;
            if hops > 10 {
                return ptr::null();
            }
            key.name = entry.data;
        }
    }
}

ffi_export! {
    /// Maps `name` of type `type` to `data` (with `OBJ_NAME_ALIAS`, to the name `data`),
    /// replacing (and freeing, with the type's free function) any earlier entry. Keeps the
    /// pointers, not copies. Returns 1, or 0 on failure.
    ///
    /// # Safety
    /// `name` and `data` are strings the type's functions accept, and outlive the entry.
    pub unsafe extern "C" fn OBJ_NAME_add(name: *const c_char, type_: c_int, data: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_OBJ
    {
        let table = table();
        if table.is_null() {
            return 0;
        }
        let entry: *mut OBJ_NAME = mem::alloc(size_of::<OBJ_NAME>()).cast();
        if entry.is_null() {
            return 0;
        }
        let alias = type_ & OBJ_NAME_ALIAS;
        // SAFETY: just allocated, big enough.
        unsafe { entry.write(OBJ_NAME { type_: type_ & !OBJ_NAME_ALIAS, alias, name, data }) };
        // SAFETY: a table of `OBJ_NAME`s; the entry is one.
        let replaced = unsafe { OPENSSL_LH_insert(table, entry.cast()) };
        if !replaced.is_null() {
            // SAFETY: the replaced entry, out of the table now.
            unsafe { discard(replaced.cast()) };
        // SAFETY: the table.
        } else if unsafe { OPENSSL_LH_error(table) } != 0 {
            // SAFETY: not in the table.
            unsafe { mem::release(entry.cast()) };
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Removes `name` of type `type`, freeing it with the type's free function. Returns 1, or 0
    /// if there was none.
    ///
    /// # Safety
    /// `name` is a string the type's functions accept.
    pub unsafe extern "C" fn OBJ_NAME_remove(name: *const c_char, type_: c_int) -> c_int
    where failure = 0, library = ERR_LIB_OBJ
    {
        let table = table();
        if table.is_null() {
            return 0;
        }
        let key = OBJ_NAME { type_: type_ & !OBJ_NAME_ALIAS, alias: 0, name, data: ptr::null() };
        // SAFETY: a table of `OBJ_NAME`s; the key is one.
        let removed = unsafe { OPENSSL_LH_delete(table, (&raw const key).cast()) };
        if removed.is_null() {
            return 0;
        }
        // SAFETY: the removed entry.
        unsafe { discard(removed.cast()) };
        1
    }
}

type Visit = unsafe extern "C" fn(*const OBJ_NAME, *mut c_void);

/// What `OBJ_NAME_do_all` passes through the table's walk.
struct DoAll {
    kind: c_int,
    visit: Visit,
    arg: *mut c_void,
}

ffi_callback! {
    /// Calls the application's function for an entry of the type.
    ///
    /// # Safety
    /// `entry` is a live `OBJ_NAME`; `arg` is a `DoAll`.
    pub(crate) unsafe extern "C" fn do_all_entry(entry: *mut c_void, arg: *mut c_void)
    where failure = (), library = ERR_LIB_OBJ
    {
        // SAFETY: the caller's guarantee.
        let (name, d) = unsafe { (entry.cast::<OBJ_NAME>(), &*arg.cast::<DoAll>()) };
        // SAFETY: as above.
        if unsafe { (*name).type_ } == d.kind {
            // SAFETY: the application's function, with an entry and its argument.
            unsafe { (d.visit)(name, d.arg) };
        }
    }
}

/// Walks the table in OpenSSL's order with `visit` on each entry.
///
/// # Safety
/// `arg` is what `visit` expects.
unsafe fn walk(visit: unsafe extern "C" fn(*mut c_void, *mut c_void), arg: *mut c_void) {
    let table = existing_table();
    if !table.is_null() {
        // SAFETY: a table of `OBJ_NAME`s; the caller's guarantee about `arg`.
        unsafe { OPENSSL_LH_doall_arg(table, Some(visit), arg) };
    }
}

ffi_export! {
    /// Calls `fn(name, arg)` for each entry of type `type`, in the table's order.
    ///
    /// # Safety
    /// `fn` is NULL or callable with the entries and `arg`.
    pub unsafe extern "C" fn OBJ_NAME_do_all(type_: c_int, fn_: Option<Visit>, arg: *mut c_void)
    where failure = (), library = ERR_LIB_OBJ
    {
        let Some(visit) = fn_ else {
            return;
        };
        let mut d = DoAll { kind: type_, visit, arg };
        // SAFETY: the walk passes the `DoAll`.
        unsafe { walk(do_all_entry, (&raw mut d).cast()) };
    }
}

ffi_callback! {
    /// Collects an entry of the type into a `Collect`.
    ///
    /// # Safety
    /// `entry` is a live `OBJ_NAME`; `arg` is a `Collect`.
    pub(crate) unsafe extern "C" fn collect_entry(entry: *mut c_void, arg: *mut c_void)
    where failure = (), library = ERR_LIB_OBJ
    {
        // SAFETY: the caller's guarantee.
        let (name, collect) = unsafe { (entry.cast::<OBJ_NAME>().cast_const(), &mut *arg.cast::<Collect>()) };
        // SAFETY: as above.
        if unsafe { (*name).type_ } == collect.kind {
            collect.names.push(name);
        }
    }
}

struct Collect {
    kind: c_int,
    names: Vec<*const OBJ_NAME>,
}

ffi_callback! {
    /// Orders entries by name with `strcmp`.
    ///
    /// # Safety
    /// Both point to pointers to live `OBJ_NAME`s.
    pub(crate) unsafe extern "C" fn by_name(a: *const c_void, b: *const c_void) -> c_int
    where failure = 0, library = ERR_LIB_OBJ
    {
        // SAFETY: the caller's guarantee.
        let a = unsafe { *a.cast::<*const OBJ_NAME>() };
        // SAFETY: as above.
        let b = unsafe { *b.cast::<*const OBJ_NAME>() };
        // SAFETY: as above.
        let a = unsafe { &*a };
        // SAFETY: as above.
        let b = unsafe { &*b };
        // SAFETY: the names are strings.
        unsafe { libc::strcmp(a.name, b.name) }
    }
}

ffi_export! {
    /// `OBJ_NAME_do_all`, in order of name (`strcmp`, with the C library's `qsort`).
    ///
    /// # Safety
    /// As for `OBJ_NAME_do_all`.
    pub unsafe extern "C" fn OBJ_NAME_do_all_sorted(type_: c_int, fn_: Option<Visit>, arg: *mut c_void)
    where failure = (), library = ERR_LIB_OBJ
    {
        let Some(visit) = fn_ else {
            return;
        };
        let mut collect = Collect { kind: type_, names: Vec::new() };
        // SAFETY: the walk passes the `Collect`.
        unsafe { walk(collect_entry, (&raw mut collect).cast()) };
        // SAFETY: the comparator takes pointers to the elements, pointers to entries.
        unsafe { crate::stack::qsort(&mut collect.names, by_name) };
        for name in collect.names {
            // SAFETY: the application's function, with an entry and its argument.
            unsafe { visit(name, arg) };
        }
    }
}

ffi_callback! {
    /// Removes an entry if it is of the type being cleaned up (any, for a negative type).
    ///
    /// # Safety
    /// `entry` is a live `OBJ_NAME`; `arg` points to the type.
    pub(crate) unsafe extern "C" fn cleanup_entry(entry: *mut c_void, arg: *mut c_void)
    where failure = (), library = ERR_LIB_OBJ
    {
        // SAFETY: the caller's guarantee.
        let name = unsafe { *entry.cast::<OBJ_NAME>() };
        // SAFETY: as above.
        let kind = unsafe { *arg.cast::<c_int>() };
        if kind < 0 || kind == name.type_ {
            // SAFETY: the entry's own name and type.
            unsafe { OBJ_NAME_remove(name.name, name.type_) };
        }
    }
}

ffi_export! {
    /// Removes every entry of type `type` (of every type, and the types added with
    /// `OBJ_NAME_new_index`, for a negative one).
    ///
    /// Unlike OpenSSL, the registry can be used again after `OBJ_NAME_cleanup(-1)`
    /// (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OBJ_NAME_cleanup(type_: c_int)
    where failure = (), library = ERR_LIB_OBJ
    {
        let table = existing_table();
        if table.is_null() {
            return;
        }
        // SAFETY: the table.
        let down_load = unsafe { OPENSSL_LH_get_down_load(table) };
        // SAFETY: as above.
        unsafe { OPENSSL_LH_set_down_load(table, 0) };
        let mut kind = type_;
        // SAFETY: the walk passes the type.
        unsafe { walk(cleanup_entry, (&raw mut kind).cast()) };
        if type_ < 0 {
            let mut state = state();
            state.retired.push(table);
            state.table = ptr::null_mut();
            state.funcs = None;
            state.next_type = OBJ_NAME_TYPE_NUM;
        } else {
            // SAFETY: the table.
            unsafe { OPENSSL_LH_set_down_load(table, down_load) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_free_functions_negative_types_and_reuse_after_cleanup_are_safe() {
        // SAFETY: default functions.
        let kind = unsafe { OBJ_NAME_new_index(None, None, None) };
        assert!(kind >= OBJ_NAME_TYPE_NUM);
        for t in [1, kind, -5] {
            // SAFETY: static strings.
            let first = unsafe { OBJ_NAME_add(c"x".as_ptr(), t, c"one".as_ptr()) };
            // SAFETY: as above; replacing with no free function set.
            let second = unsafe { OBJ_NAME_add(c"X".as_ptr(), t, c"two".as_ptr()) };
            assert_eq!((first, second), (1, 1));
            // SAFETY: a string.
            let got = unsafe { OBJ_NAME_get(c"x".as_ptr(), t) };
            // SAFETY: the data added above.
            assert_eq!(unsafe { core::ffi::CStr::from_ptr(got) }, c"two");
            // SAFETY: a string.
            assert_eq!(unsafe { OBJ_NAME_remove(c"x".as_ptr(), t) }, 1);
        }
        // SAFETY: no preconditions.
        unsafe { OBJ_NAME_cleanup(-1) };
        // SAFETY: the registry starts again.
        assert_eq!(unsafe { OBJ_NAME_add(c"y".as_ptr(), 1, c"d".as_ptr()) }, 1);
        // SAFETY: a string.
        assert!(!unsafe { OBJ_NAME_get(c"y".as_ptr(), 1) }.is_null());
        // SAFETY: default functions.
        let kind = unsafe { OBJ_NAME_new_index(None, None, None) };
        assert_eq!(kind, OBJ_NAME_TYPE_NUM);
        // SAFETY: no preconditions.
        unsafe { OBJ_NAME_cleanup(-1) };
    }

    #[test]
    fn strcasehash_ignores_case() {
        // SAFETY: a string.
        let upper = unsafe { strcasehash(c"SHA256".as_ptr()) };
        // SAFETY: a string.
        let lower = unsafe { strcasehash(c"sha256".as_ptr()) };
        assert_eq!(upper, lower);
        // SAFETY: as above.
        assert_eq!(unsafe { strcasehash(c"".as_ptr()) }, 0);
    }
}
