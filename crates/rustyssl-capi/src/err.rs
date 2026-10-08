//! The error queue (`ERR_raise(3)`, `ERR_get_error(3)`, `ERR_set_mark(3)`,
//! `ERR_add_error_data(3)`, `OSSL_ERR_STATE_save(3)`).
//!
//! Each thread's queue is OpenSSL's `ERR_STATE`, the public `struct err_state_st`: a ring of
//! `ERR_NUM_ERRORS` slots from `bottom` (exclusive) to `top` (the newest error), so it holds one
//! error fewer than it has slots, and raising an error into a full ring drops the oldest.
//! Applications may read it through the deprecated `ERR_get_state`, so its layout and contents
//! are OpenSSL's: it lives in memory from `CRYPTO_malloc`, and so do the copies of the file and
//! function names each error carries and the data attached to it.
//!
//! A thread's state is created on its first use, which also loads libcrypto's error strings
//! (unless `OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS` came first). It is freed when the thread exits
//! or calls `OPENSSL_thread_stop`. After `OPENSSL_cleanup` there is none, and the functions do
//! nothing. Getting the state never changes `errno`.
//!
//! The application's allocator may call back into these functions, so no reference to a state
//! is held across an allocation: a slot is copied out, changed, and written back.
//!
//! [`strings`] holds the error strings and the functions that print errors.

pub(crate) mod strings;

pub(crate) use strings::{load_crypto_strings, load_ssl_strings};

use core::ffi::{CStr, VaList, c_char, c_int, c_ulong, c_void};
use core::ptr::{self, NonNull};
use std::cell::Cell;
use std::panic::Location;

use rustyssl_abi::{
    ERR_FLAG_CLEAR, ERR_LIB_CRYPTO, ERR_LIB_MASK, ERR_LIB_NONE, ERR_LIB_OFFSET, ERR_LIB_SYS,
    ERR_MAX_DATA_SIZE, ERR_NUM_ERRORS, ERR_REASON_MASK, ERR_STATE, ERR_SYSTEM_FLAG,
    ERR_TXT_MALLOCED, ERR_TXT_STRING,
};

use crate::ffi::{ffi_export, guard};
use crate::{init, mem};

/// A C string table as (packed error, text), in the order of OpenSSL's table.
pub(crate) type Table = &'static [(c_ulong, &'static CStr)];

/// `ERR_PACK(library, 0, reason)` from `err.h`.
pub(crate) const fn pack(library: c_int, reason: c_int) -> c_ulong {
    let library = (library & ERR_LIB_MASK).cast_unsigned() as c_ulong;
    let reason = (reason & ERR_REASON_MASK).cast_unsigned() as c_ulong;
    (library << ERR_LIB_OFFSET) | reason
}

/// `ERR_GET_LIB(code)` from `err.h`.
pub(crate) fn library_of(code: c_ulong) -> c_int {
    if is_system(code) {
        return ERR_LIB_SYS;
    }
    let library = (code >> ERR_LIB_OFFSET) & c_ulong::from(ERR_LIB_MASK.cast_unsigned());
    c_int::try_from(library).unwrap_or(0)
}

/// `ERR_SYSTEM_ERROR(code)` from `err.h`.
fn is_system(code: c_ulong) -> bool {
    code & c_ulong::from(ERR_SYSTEM_FLAG) != 0
}

/// The number of slots in the ring.
const SLOTS: usize = ERR_NUM_ERRORS.unsigned_abs() as usize;

/// What `OPENSSL_free`d data is flagged with.
const MALLOCED_STRING: c_int = ERR_TXT_MALLOCED | ERR_TXT_STRING;

/// One slot of the ring, copied out of the state.
#[derive(Clone, Copy)]
struct Entry {
    flags: c_int,
    marks: c_int,
    code: c_ulong,
    data: *mut c_char,
    data_size: usize,
    data_flags: c_int,
    file: *mut c_char,
    line: c_int,
    func: *mut c_char,
}

/// `array[i]`, or `default` if `i` is out of range (it never is: slots are below [`SLOTS`]).
fn at<T: Copy>(array: &[T], i: usize, default: T) -> T {
    array.get(i).copied().unwrap_or(default)
}

/// Sets `array[i]`, if `i` is in range.
fn put<T>(array: &mut [T], i: usize, value: T) {
    if let Some(slot) = array.get_mut(i) {
        *slot = value;
    }
}

/// Copies slot `i` out of `state`.
///
/// # Safety
/// `state` is a live `ERR_STATE` that nothing else accesses during the call.
unsafe fn load(state: NonNull<ERR_STATE>, i: usize) -> Entry {
    // SAFETY: the caller's guarantee.
    let s = unsafe { state.as_ref() };
    Entry {
        flags: at(&s.err_flags, i, 0),
        marks: at(&s.err_marks, i, 0),
        code: at(&s.err_buffer, i, 0),
        data: at(&s.err_data, i, ptr::null_mut()),
        data_size: at(&s.err_data_size, i, 0),
        data_flags: at(&s.err_data_flags, i, 0),
        file: at(&s.err_file, i, ptr::null_mut()),
        line: at(&s.err_line, i, 0),
        func: at(&s.err_func, i, ptr::null_mut()),
    }
}

/// Writes `entry` into slot `i` of `state`.
///
/// # Safety
/// As for [`load`].
unsafe fn store(state: NonNull<ERR_STATE>, i: usize, entry: Entry) {
    // SAFETY: the caller's guarantee.
    let s = unsafe { &mut *state.as_ptr() };
    put(&mut s.err_flags, i, entry.flags);
    put(&mut s.err_marks, i, entry.marks);
    put(&mut s.err_buffer, i, entry.code);
    put(&mut s.err_data, i, entry.data);
    put(&mut s.err_data_size, i, entry.data_size);
    put(&mut s.err_data_flags, i, entry.data_flags);
    put(&mut s.err_file, i, entry.file);
    put(&mut s.err_line, i, entry.line);
    put(&mut s.err_func, i, entry.func);
}

/// A ring position from the state. Applications can write the public struct, so a value out of
/// range is wrapped into it rather than trusted.
fn position(value: c_int) -> usize {
    usize::try_from(value).map_or(0, |v| v % SLOTS)
}

/// The ring's `(top, bottom)`.
///
/// # Safety
/// As for [`load`].
unsafe fn ends(state: NonNull<ERR_STATE>) -> (usize, usize) {
    // SAFETY: the caller's guarantee.
    let s = unsafe { state.as_ref() };
    (position(s.top), position(s.bottom))
}

/// Sets the ring's `top` and `bottom`.
///
/// # Safety
/// As for [`load`].
unsafe fn set_ends(state: NonNull<ERR_STATE>, top: usize, bottom: usize) {
    // SAFETY: the caller's guarantee.
    let s = unsafe { &mut *state.as_ptr() };
    s.top = c_int::try_from(top).unwrap_or(0);
    s.bottom = c_int::try_from(bottom).unwrap_or(0);
}

/// The slot before `i` in the ring.
fn previous(i: usize) -> usize {
    i.checked_sub(1).unwrap_or(SLOTS - 1)
}

/// The slot after `i` in the ring.
fn following(i: usize) -> usize {
    (i + 1) % SLOTS
}

/// Moves `top` to a fresh slot, dropping the oldest error if the ring is full (OpenSSL's
/// `err_get_slot`). Returns the new `top`.
///
/// # Safety
/// As for [`load`].
unsafe fn next_slot(state: NonNull<ERR_STATE>) -> usize {
    // SAFETY: the caller's guarantee, for each call below.
    let (top, bottom) = unsafe { ends(state) };
    let top = following(top);
    let bottom = if top == bottom {
        following(bottom)
    } else {
        bottom
    };
    // SAFETY: as above.
    unsafe { set_ends(state, top, bottom) };
    top
}

/// Drops slot `i`'s data (OpenSSL's `err_clear_data`). Allocated data is freed if `deallocate`,
/// and otherwise kept for reuse, emptied.
///
/// # Safety
/// `state` is a live `ERR_STATE`.
unsafe fn clear_data(state: NonNull<ERR_STATE>, i: usize, deallocate: bool) {
    // SAFETY: the caller's guarantee; nothing else runs during the copy.
    let mut entry = unsafe { load(state, i) };
    let mut freed = ptr::null_mut();
    if entry.data_flags & ERR_TXT_MALLOCED != 0 {
        if deallocate {
            freed = entry.data;
            entry.data = ptr::null_mut();
            entry.data_size = 0;
            entry.data_flags = 0;
        } else if !entry.data.is_null() {
            // SAFETY: allocated data is a block of at least one byte (CRYPTO_malloc never
            // returns an empty one).
            unsafe { entry.data.write(0) };
            entry.data_flags = ERR_TXT_MALLOCED;
        }
    } else {
        entry.data = ptr::null_mut();
        entry.data_size = 0;
        entry.data_flags = 0;
    }
    // SAFETY: as above.
    unsafe { store(state, i, entry) };
    // SAFETY: allocated data came from CRYPTO_malloc, and the slot no longer refers to it.
    unsafe { mem::release(freed.cast()) };
}

/// Sets slot `i`'s data, freeing allocated data it had (OpenSSL's `err_set_data`).
///
/// # Safety
/// `state` is a live `ERR_STATE`; `data` is null, a string, or (with `ERR_TXT_MALLOCED`) a
/// block from `CRYPTO_malloc` the state now owns.
unsafe fn set_data(
    state: NonNull<ERR_STATE>,
    i: usize,
    data: *mut c_char,
    size: usize,
    flags: c_int,
) {
    // SAFETY: the caller's guarantee; nothing else runs during the copy.
    let mut entry = unsafe { load(state, i) };
    // Setting the data the slot already has must not free it.
    let freed = if entry.data_flags & ERR_TXT_MALLOCED != 0 && entry.data != data {
        entry.data
    } else {
        ptr::null_mut()
    };
    entry.data = data;
    entry.data_size = size;
    entry.data_flags = flags;
    // SAFETY: as above.
    unsafe { store(state, i, entry) };
    // SAFETY: the old allocated data came from CRYPTO_malloc and nothing refers to it now.
    unsafe { mem::release(freed.cast()) };
}

/// A copy of `text` in memory from `CRYPTO_malloc`, or null for none or an empty one. Like
/// OpenSSL's, the allocation names no file, so a failure raises no error.
fn copy_string(text: Option<&[u8]>) -> *mut c_char {
    let Some(text) = text.filter(|t| !t.is_empty()) else {
        return ptr::null_mut();
    };
    let Some(size) = text.len().checked_add(1) else {
        return ptr::null_mut();
    };
    let block = mem::malloc(size, ptr::null(), 0).cast::<u8>();
    if !block.is_null() {
        // SAFETY: the block holds `size` bytes, a fresh allocation distinct from `text`.
        unsafe { ptr::copy_nonoverlapping(text.as_ptr(), block, text.len()) };
        // SAFETY: as above; the last byte.
        unsafe { block.wrapping_add(text.len()).write(0) };
    }
    block.cast()
}

/// Sets slot `i`'s file, line, and function (OpenSSL's `err_set_debug`), copying the names:
/// they may belong to a provider that gets unloaded.
///
/// # Safety
/// `state` is a live `ERR_STATE`.
unsafe fn set_debug(
    state: NonNull<ERR_STATE>,
    i: usize,
    file: Option<&[u8]>,
    line: c_int,
    func: Option<&[u8]>,
) {
    // SAFETY: the caller's guarantee, for each access below; nothing else runs during them.
    let mut entry = unsafe { load(state, i) };
    let old = entry.file;
    entry.file = ptr::null_mut();
    // SAFETY: as above.
    unsafe { store(state, i, entry) };
    // SAFETY: the old name came from CRYPTO_malloc and the slot no longer refers to it.
    unsafe { mem::release(old.cast()) };
    let file = copy_string(file);
    // SAFETY: as above.
    let mut entry = unsafe { load(state, i) };
    entry.file = file;
    entry.line = line;
    let old = entry.func;
    entry.func = ptr::null_mut();
    // SAFETY: as above.
    unsafe { store(state, i, entry) };
    // SAFETY: as for the file.
    unsafe { mem::release(old.cast()) };
    let func = copy_string(func);
    // SAFETY: as above.
    let mut entry = unsafe { load(state, i) };
    entry.func = func;
    // SAFETY: as above.
    unsafe { store(state, i, entry) };
}

/// Sets slot `i`'s code (OpenSSL's `err_set_error`): system errors carry `ERR_SYSTEM_FLAG` and
/// the whole reason, which is `errno`.
///
/// # Safety
/// As for [`load`].
unsafe fn set_code(state: NonNull<ERR_STATE>, i: usize, library: c_int, reason: c_int) {
    // SAFETY: the caller's guarantee, for both accesses.
    let mut entry = unsafe { load(state, i) };
    entry.code = if library == ERR_LIB_SYS {
        c_ulong::from(ERR_SYSTEM_FLAG | reason.cast_unsigned())
    } else {
        pack(library, reason)
    };
    // SAFETY: as above.
    unsafe { store(state, i, entry) };
}

/// Empties slot `i` (OpenSSL's `err_clear`). Allocated data is freed if `deallocate`, and
/// otherwise kept for reuse.
///
/// # Safety
/// `state` is a live `ERR_STATE`.
unsafe fn clear(state: NonNull<ERR_STATE>, i: usize, deallocate: bool) {
    // SAFETY: the caller's guarantee, for each call below.
    unsafe { clear_data(state, i, deallocate) };
    // SAFETY: as above.
    let mut entry = unsafe { load(state, i) };
    let (file, func) = (entry.file, entry.func);
    entry.marks = 0;
    entry.flags = 0;
    entry.code = 0;
    entry.line = -1;
    entry.file = ptr::null_mut();
    entry.func = ptr::null_mut();
    // SAFETY: as above.
    unsafe { store(state, i, entry) };
    // SAFETY: the names came from CRYPTO_malloc, and the slot no longer refers to them.
    unsafe { mem::release(file.cast()) };
    // SAFETY: as above.
    unsafe { mem::release(func.cast()) };
}

/// Frees a state and everything its slots own (`OSSL_ERR_STATE_free`).
///
/// # Safety
/// `state` is a live `ERR_STATE` from `CRYPTO_malloc`, not used afterwards.
unsafe fn free_state(state: NonNull<ERR_STATE>) {
    for i in 0..SLOTS {
        // SAFETY: the caller's guarantee.
        unsafe { clear(state, i, true) };
    }
    // SAFETY: as above.
    unsafe { mem::release(state.as_ptr().cast()) };
}

/// A thread's state: none yet, being created (the allocator may call back in), or ready.
#[derive(Clone, Copy)]
enum Slot {
    Empty,
    Creating,
    Ready(NonNull<ERR_STATE>),
}

/// Frees the thread's state when the thread exits.
struct ThreadState(Cell<Slot>);

impl Drop for ThreadState {
    fn drop(&mut self) {
        if let Slot::Ready(state) = self.0.replace(Slot::Empty) {
            // SAFETY: only this thread used its state, and it is ending.
            unsafe { free_state(state) };
        }
    }
}

thread_local! {
    static STATE: ThreadState = const { ThreadState(Cell::new(Slot::Empty)) };
}

/// This thread's error state, created on first use (OpenSSL's `ossl_err_get_state_int`). None
/// after `OPENSSL_cleanup`, while the thread exits, while the state is being created, or if it
/// can't be allocated. `errno` is left as it was.
fn state() -> Option<NonNull<ERR_STATE>> {
    let saved = crate::errno::get();
    let state = current_or_new();
    crate::errno::set(saved);
    state
}

fn current_or_new() -> Option<NonNull<ERR_STATE>> {
    if !init::base() {
        return None;
    }
    match STATE.try_with(|s| s.0.get()).ok()? {
        Slot::Ready(state) => Some(state),
        Slot::Creating => None,
        Slot::Empty => {
            STATE.try_with(|s| s.0.set(Slot::Creating)).ok()?;
            let state = new_state();
            let slot = state.map_or(Slot::Empty, Slot::Ready);
            if STATE.try_with(|s| s.0.set(slot)).is_err() {
                if let Some(state) = state {
                    // SAFETY: the state was just allocated, and nothing else has it.
                    unsafe { free_state(state) };
                }
                return None;
            }
            // As OpenSSL does once a thread can record errors; a failure is ignored.
            init::load_crypto_strings_at_first_error();
            state
        }
    }
}

/// A zeroed state (`OSSL_ERR_STATE_new`). The allocation names no file, so a failure raises no
/// error that would need a state.
fn new_state() -> Option<NonNull<ERR_STATE>> {
    NonNull::new(mem::zalloc(size_of::<ERR_STATE>(), ptr::null(), 0).cast())
}

/// Frees this thread's state, as `OPENSSL_thread_stop` does; the next error creates another.
pub(crate) fn stop_thread() {
    let state = STATE.try_with(|s| s.0.replace(Slot::Empty));
    if let Ok(Slot::Ready(state)) = state {
        // SAFETY: the thread no longer refers to its state.
        unsafe { free_state(state) };
    }
}

/// Raises an error, as `ERR_raise(library, reason)` does in OpenSSL, from the caller's Rust
/// file and line on behalf of the exported C function `function`.
#[track_caller]
pub(crate) fn raise(library: c_int, reason: c_int, function: &str) {
    let caller = Location::caller();
    let line = c_int::try_from(caller.line()).unwrap_or(c_int::MAX);
    raise_from(
        library,
        reason,
        Some(caller.file().as_bytes()),
        line,
        Some(function.as_bytes()),
    );
}

/// Raises an error with the given origin: `ERR_new`, `ERR_set_debug`, and `ERR_set_error`
/// without data.
pub(crate) fn raise_from(
    library: c_int,
    reason: c_int,
    file: Option<&[u8]>,
    line: c_int,
    function: Option<&[u8]>,
) {
    new();
    if let Some(state) = state() {
        // SAFETY: this thread's state; it stays live during these calls.
        let (top, _) = unsafe { ends(state) };
        // SAFETY: as above.
        unsafe { set_debug(state, top, file, line, function) };
        // SAFETY: as above.
        unsafe { clear_data(state, top, false) };
        // SAFETY: as above.
        unsafe { set_code(state, top, library, reason) };
    }
}

/// `ERR_new`: starts a new error in a fresh slot.
fn new() {
    if let Some(state) = state() {
        // SAFETY: this thread's state.
        let top = unsafe { next_slot(state) };
        // SAFETY: as above.
        unsafe { clear(state, top, false) };
    }
}

/// The string at `text`, or `None` for null.
///
/// # Safety
/// `text` is null or a NUL-terminated string that outlives `'a`.
unsafe fn c_bytes<'a>(text: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    (!text.is_null()).then(|| unsafe { CStr::from_ptr(text) }.to_bytes())
}

/// Which error `get` reads, and whether it removes it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Get {
    Pop,
    Peek,
    PeekLast,
}

/// An error's details, as the `ERR_get_error_all` family returns them.
struct Details {
    file: *const c_char,
    line: c_int,
    func: *const c_char,
    data: *const c_char,
    flags: c_int,
}

/// Reads the oldest or the newest error, removing the oldest for [`Get::Pop`] (OpenSSL's
/// `get_error_values`). Errors flagged `ERR_FLAG_CLEAR` are dropped first. A popped error keeps
/// its data, file, and function until its slot is reused, so the pointers stay valid that long.
/// `keep_data` says the caller wants the data: missing data then reads as `""` with flags 0;
/// without it, a popped error's data is dropped at once. Returns 0 for an empty queue.
fn get(action: Get, keep_data: bool) -> (c_ulong, Details) {
    let none = Details {
        file: c"".as_ptr(),
        line: 0,
        func: c"".as_ptr(),
        data: c"".as_ptr(),
        flags: 0,
    };
    let Some(state) = state() else {
        return (0, none);
    };
    // SAFETY: this thread's state, for every access below.
    let (mut top, mut bottom) = unsafe { ends(state) };
    while bottom != top {
        // SAFETY: as above.
        if unsafe { load(state, top) }.flags & ERR_FLAG_CLEAR != 0 {
            // SAFETY: as above.
            unsafe { clear(state, top, false) };
            top = previous(top);
            // SAFETY: as above.
            unsafe { set_ends(state, top, bottom) };
            continue;
        }
        let i = following(bottom);
        // SAFETY: as above.
        if unsafe { load(state, i) }.flags & ERR_FLAG_CLEAR != 0 {
            bottom = i;
            // SAFETY: as above.
            unsafe { set_ends(state, top, bottom) };
            // SAFETY: as above.
            unsafe { clear(state, bottom, false) };
            continue;
        }
        break;
    }
    if bottom == top {
        return (0, none);
    }
    let i = if action == Get::PeekLast {
        top
    } else {
        following(bottom)
    };
    // SAFETY: as above.
    let mut entry = unsafe { load(state, i) };
    let code = entry.code;
    if action == Get::Pop {
        entry.code = 0;
        // SAFETY: as above.
        unsafe { store(state, i, entry) };
        // SAFETY: as above.
        unsafe { set_ends(state, top, i) };
    }
    let or_empty = |text: *mut c_char| {
        if text.is_null() {
            c"".as_ptr()
        } else {
            text.cast_const()
        }
    };
    let mut details = Details {
        file: or_empty(entry.file),
        line: entry.line,
        func: or_empty(entry.func),
        data: entry.data,
        flags: entry.data_flags,
    };
    if !keep_data {
        if action == Get::Pop {
            // SAFETY: as above.
            unsafe { clear_data(state, i, false) };
        }
    } else if details.data.is_null() {
        details.data = c"".as_ptr();
        details.flags = 0;
    }
    (code, details)
}

/// Writes `value` through `out` unless it is null.
///
/// # Safety
/// `out` is null or valid for a write.
unsafe fn write_out<T>(out: *mut T, value: T) {
    if !out.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { out.write(value) };
    }
}

/// The `ERR_get_error_all` family: reads an error and its details into the outputs that
/// aren't null.
///
/// # Safety
/// Each output is null or valid for a write.
unsafe fn get_into(
    action: Get,
    file: *mut *const c_char,
    line: *mut c_int,
    func: *mut *const c_char,
    data: *mut *const c_char,
    flags: *mut c_int,
) -> c_ulong {
    let (code, details) = get(action, !data.is_null());
    if code == 0 {
        return 0;
    }
    // SAFETY: the caller's guarantee, for each output.
    unsafe { write_out(file, details.file) };
    // SAFETY: as above.
    unsafe { write_out(line, details.line) };
    // SAFETY: as above.
    unsafe { write_out(func, details.func) };
    // Without data, the flags are the slot's even when no data is asked for.
    // SAFETY: as above.
    unsafe { write_out(flags, details.flags) };
    // SAFETY: as above.
    unsafe { write_out(data, details.data) };
    code
}

/// Replaces the newest error's data (OpenSSL's `err_set_error_data_int`). Returns false if
/// there is no state, leaving `data` to the caller.
///
/// # Safety
/// As for [`set_data`].
unsafe fn set_error_data(data: *mut c_char, size: usize, flags: c_int, deallocate: bool) -> bool {
    let Some(state) = state() else {
        return false;
    };
    // SAFETY: this thread's state, for each access below.
    let (top, _) = unsafe { ends(state) };
    // SAFETY: as above.
    let current = unsafe { load(state, top) }.data;
    if current != data {
        // SAFETY: as above.
        unsafe { clear_data(state, top, deallocate) };
    }
    // SAFETY: as above, and the caller's guarantee for `data`.
    unsafe { set_data(state, top, data, size, flags) };
    true
}

/// Appends `pieces` to the newest error's data, null pieces as `<NULL>` (OpenSSL's
/// `ERR_add_error_vdata`). Allocated string data is extended in place; any other data is
/// replaced.
pub(crate) fn add_error_data<'a>(pieces: impl IntoIterator<Item = Option<&'a [u8]>>) {
    let Some(state) = state() else {
        return;
    };
    // SAFETY: this thread's state, for each access below.
    let (top, _) = unsafe { ends(state) };
    // SAFETY: as above.
    let mut entry = unsafe { load(state, top) };
    let (mut text, mut size) = if entry.data_flags & MALLOCED_STRING == MALLOCED_STRING
        && !entry.data.is_null()
        && entry.data_size > 0
    {
        // Taken out of the slot, so nothing called meanwhile can free or change it.
        let taken = (entry.data.cast::<u8>(), entry.data_size);
        entry.data = ptr::null_mut();
        entry.data_flags = 0;
        // SAFETY: as above.
        unsafe { store(state, top, entry) };
        taken
    } else {
        let block = mem::alloc(81).cast::<u8>();
        if block.is_null() {
            return;
        }
        // SAFETY: a fresh block of 81 bytes.
        unsafe { block.write(0) };
        (block, 81)
    };
    // The text so far ends at its NUL, or (if an application left none) at the block's end.
    let mut len = 0;
    // SAFETY: the data is a block of `size` bytes that this function now owns; the bytes up
    // to the NUL are initialized.
    while len < size - 1 && unsafe { text.wrapping_add(len).read() } != 0 {
        len += 1;
    }
    // SAFETY: as above; `len < size`.
    unsafe { text.wrapping_add(len).write(0) };
    for piece in pieces {
        let piece = piece.unwrap_or(b"<NULL>");
        let grown = len.checked_add(piece.len());
        let Some(new_len) = grown else {
            // SAFETY: the block is ours, from CRYPTO_malloc.
            unsafe { mem::release(text.cast()) };
            return;
        };
        if new_len >= size {
            let new_size = new_len.saturating_add(20);
            // SAFETY: the block is ours, from CRYPTO_malloc.
            let resized = unsafe { mem::resize(text.cast(), new_size) }.cast::<u8>();
            if resized.is_null() {
                // SAFETY: a failed resize leaves the block as it was.
                unsafe { mem::release(text.cast()) };
                return;
            }
            text = resized;
            size = new_size;
        }
        // SAFETY: `len + piece.len() < size`, inside the block, which `piece` isn't part of.
        unsafe { ptr::copy_nonoverlapping(piece.as_ptr(), text.wrapping_add(len), piece.len()) };
        len = new_len;
        // SAFETY: as above.
        unsafe { text.wrapping_add(len).write(0) };
    }
    // SAFETY: the block is from CRYPTO_malloc, and the state takes it over.
    if !unsafe { set_error_data(text.cast(), size, MALLOCED_STRING, false) } {
        // SAFETY: the state didn't take it.
        unsafe { mem::release(text.cast()) };
    }
}

/// What `ERR_add_error_txt` aims to keep an error's data under, so that `ERR_print_errors`
/// prints it whole (`MAX_DATA_LEN` in OpenSSL's `err_prn.c`).
const MAX_DATA_LEN: usize = 4096 - 100;

/// `ERR_add_error_txt`: appends `text` to the newest error's data, after `separator` if there
/// is data already. Text that would make the data longer than [`MAX_DATA_LEN`] goes on to new
/// errors with the same code and origin, split after a separator where there is one.
///
/// OpenSSL loops forever when a piece between separators doesn't fit even in a fresh error;
/// such a piece is split at the limit instead (docs/DEVIATIONS.md).
fn add_error_txt(separator: &[u8], mut text: &[u8]) {
    let (err, _) = get(Get::PeekLast, true);
    if err == 0 {
        raise_from(ERR_LIB_NONE, 0, Some(b""), 0, None);
    }
    loop {
        let (_, details) = get(Get::PeekLast, true);
        // SAFETY: the strings belong to the newest error, which nothing changes until the
        // copies are made.
        let file = unsafe { c_bytes(details.file) }.map(<[u8]>::to_vec);
        // SAFETY: as above.
        let func = unsafe { c_bytes(details.func) }.map(<[u8]>::to_vec);
        let (data_len, leading) = if details.flags & ERR_TXT_STRING == 0 {
            (0, &b""[..])
        } else {
            // SAFETY: as above.
            (
                unsafe { c_bytes(details.data) }.map_or(0, <[u8]>::len),
                separator,
            )
        };
        let available = if data_len >= MAX_DATA_LEN || separator.len() >= MAX_DATA_LEN - data_len {
            0
        } else {
            MAX_DATA_LEN - data_len - separator.len() - 1
        };

        // Where to split, if the text doesn't fit; where the part that fits ends, and whether
        // it ends with a separator to leave out.
        let (split, next, trailing) = if separator.is_empty() {
            if text.len() <= available {
                (None, text.len(), false)
            } else {
                (Some(available), available, false)
            }
        } else {
            let mut current = 0;
            let mut next = 0;
            let mut trailing = false;
            while next < text.len() && next <= available {
                current = next;
                let rest = text.get(current..).unwrap_or_default();
                match rest.windows(separator.len()).position(|w| w == separator) {
                    Some(at) => {
                        next = current + at + separator.len();
                        trailing = next == text.len();
                    }
                    None => next = text.len(),
                }
            }
            if next <= available {
                (None, next, trailing)
            } else if current == 0 && data_len == 0 {
                // Splitting at separators can't make progress: a fresh error is no roomier.
                (Some(available.clamp(1, text.len())), 0, false)
            } else {
                (Some(current), next, false)
            }
        };
        match split {
            Some(at) => {
                if at != 0 {
                    add_error_data([Some(separator), text.get(..at)]);
                }
                // OpenSSL passes the whole code as the reason, which packing masks again.
                let reason =
                    u32::try_from(err & c_ulong::from(u32::MAX)).map_or(0, u32::cast_signed);
                raise_from(
                    library_of(err),
                    reason,
                    file.as_deref(),
                    details.line,
                    func.as_deref(),
                );
                text = text.get(at..).unwrap_or_default();
            }
            None => {
                let end = if trailing {
                    next - separator.len()
                } else {
                    text.len()
                };
                add_error_data([Some(leading), text.get(..end)]);
                text = text.get(next..).unwrap_or_default();
            }
        }
        if text.is_empty() {
            break;
        }
    }
}

ffi_export! {
    /// Starts a new error in a fresh slot of this thread's queue, dropping the oldest error if
    /// the queue is full. `ERR_set_debug` and `ERR_set_error` fill it in.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ERR_new()
    where failure = (), library = ERR_LIB_CRYPTO
    {
        new();
    }
}

ffi_export! {
    /// Sets the newest error's file, line, and function. The names are copied; null or empty
    /// ones read back as `""`.
    ///
    /// # Safety
    /// `file` and `func` are null or NUL-terminated strings.
    pub unsafe extern "C" fn ERR_set_debug(file: *const c_char, line: c_int, func: *const c_char)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if let Some(state) = state() {
            // SAFETY: this thread's state.
            let (top, _) = unsafe { ends(state) };
            // SAFETY: the caller passes null or strings, read before anything else runs.
            let file = unsafe { c_bytes(file) };
            // SAFETY: as above.
            let func = unsafe { c_bytes(func) };
            // SAFETY: this thread's state.
            unsafe { set_debug(state, top, file, line, func) };
        }
    }
}

/// [`set_error_printed`] with text already formatted. Text that doesn't fit leaves the data
/// empty, as `BIO_vsnprintf` reports truncation as a failure.
fn set_error_with_text(library: c_int, reason: c_int, text: &[u8]) {
    set_error_printed(library, reason, |buffer, size| {
        if text.len() >= size {
            return 0;
        }
        // SAFETY: `text.len() < size`, inside the buffer, which `text` isn't part of.
        unsafe { ptr::copy_nonoverlapping(text.as_ptr(), buffer, text.len()) };
        text.len()
    });
}

/// `ERR_vset_error` with a format: sets the newest error's code, and its data to what `print`
/// writes into the buffer it gets (of the given size), returning the length, which is below
/// the size. The slot's old buffer is reused, grown to `ERR_MAX_DATA_SIZE`, written, and shrunk
/// to fit, as OpenSSL does.
fn set_error_printed(library: c_int, reason: c_int, print: impl FnOnce(*mut u8, usize) -> usize) {
    let Some(state) = state() else {
        return;
    };
    // SAFETY: this thread's state, for each access below; the slot's buffer is taken out, so
    // nothing called meanwhile can free or change it.
    let (top, _) = unsafe { ends(state) };
    // SAFETY: as above.
    let mut entry = unsafe { load(state, top) };
    // Only allocated data can be reused; anything else isn't the queue's to resize.
    let (mut buffer, mut size) = if entry.data_flags & ERR_TXT_MALLOCED != 0 {
        (entry.data.cast::<u8>(), entry.data_size)
    } else {
        (ptr::null_mut(), 0)
    };
    entry.data = ptr::null_mut();
    entry.data_flags = 0;
    // SAFETY: as above.
    unsafe { store(state, top, entry) };
    let max = usize::try_from(ERR_MAX_DATA_SIZE).unwrap_or(1024);
    if size < max {
        // SAFETY: the buffer is null or the slot's allocated data, which this function owns.
        let grown = unsafe { mem::resize(buffer.cast(), max) }.cast::<u8>();
        if !grown.is_null() {
            buffer = grown;
            size = max;
        }
    }
    let mut flags = 0;
    if !buffer.is_null() {
        let printed = print(buffer, size).min(size - 1);
        // SAFETY: `printed < size`, inside the buffer.
        unsafe { buffer.wrapping_add(printed).write(0) };
        // SAFETY: the buffer is from CRYPTO_malloc; a failed resize leaves it as it was.
        let shrunk = unsafe { mem::resize(buffer.cast(), printed + 1) }.cast::<u8>();
        if !shrunk.is_null() {
            buffer = shrunk;
            size = printed + 1;
        }
        flags = MALLOCED_STRING;
    }
    // SAFETY: this thread's state, as above.
    unsafe { clear_data(state, top, false) };
    // SAFETY: as above.
    unsafe { set_code(state, top, library, reason) };
    // SAFETY: as above; the queue takes over the buffer.
    unsafe { set_data(state, top, buffer.cast(), size, flags) };
}

/// Raises an error with text as its data, as `ERR_raise_data(library, reason, format, ...)`
/// does in OpenSSL once the format is applied, from the caller's Rust file and line on behalf
/// of the exported C function `function`.
#[track_caller]
pub(crate) fn raise_with_text(library: c_int, reason: c_int, function: &str, text: &str) {
    raise_with_bytes(library, reason, function, text.as_bytes());
}

/// [`raise_with_text`] for text that needn't be UTF-8, such as a file name.
#[track_caller]
pub(crate) fn raise_with_bytes(library: c_int, reason: c_int, function: &str, text: &[u8]) {
    let caller = Location::caller();
    let line = c_int::try_from(caller.line()).unwrap_or(c_int::MAX);
    new();
    if let Some(state) = state() {
        // SAFETY: this thread's state.
        let (top, _) = unsafe { ends(state) };
        let (file, function) = (Some(caller.file().as_bytes()), Some(function.as_bytes()));
        // SAFETY: as above.
        unsafe { set_debug(state, top, file, line, function) };
    }
    set_error_with_text(library, reason, text);
}

/// `ERR_vset_error`, which `ERR_set_error` shares.
///
/// # Safety
/// `format` is null or a NUL-terminated string whose conversions `args` match.
unsafe fn set_error(library: c_int, reason: c_int, format: *const c_char, args: &mut VaList<'_>) {
    if !format.is_null() {
        set_error_printed(library, reason, |buffer, size| {
            // SAFETY: the buffer has `size` bytes; the caller's guarantee about the format.
            let printed =
                unsafe { crate::bio::print::vsnprintf(buffer.cast(), size, format, args) };
            usize::try_from(printed).unwrap_or(0)
        });
        return;
    }
    let Some(state) = state() else {
        return;
    };
    // SAFETY: this thread's state, for each access.
    let (top, _) = unsafe { ends(state) };
    // SAFETY: as above.
    unsafe { clear_data(state, top, false) };
    // SAFETY: as above.
    unsafe { set_code(state, top, library, reason) };
}

/// Sets the newest error's code. `ERR_LIB_SYS` makes a system error, whose reason is an
/// `errno` value. With a format, the error's data becomes the text it formats as
/// `BIO_snprintf` would (empty if it's longer than `ERR_MAX_DATA_SIZE` - 1); without one, the
/// error has no data.
///
/// # Safety
/// `fmt` is null or a NUL-terminated string whose conversions the arguments match, as for C's
/// `printf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ERR_set_error(lib: c_int, reason: c_int, fmt: *const c_char, args: ...) {
    guard(
        ERR_LIB_CRYPTO,
        "ERR_set_error",
        || (),
        move || {
            let mut args = args;
            // SAFETY: the caller's guarantee.
            unsafe { set_error(lib, reason, fmt, &mut args) };
        },
    );
}

ffi_export! {
    /// `ERR_set_error` with its arguments in a `va_list`.
    ///
    /// # Safety
    /// As for `ERR_set_error`.
    pub unsafe extern "C" fn ERR_vset_error(lib: c_int, reason: c_int, fmt: *const c_char, args: VaList<'_>)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let mut args = args;
        // SAFETY: the caller's guarantee.
        unsafe { set_error(lib, reason, fmt, &mut args) };
    }
}

ffi_export! {
    /// Sets the newest error's data. With `ERR_TXT_MALLOCED`, the queue takes over `data`, which
    /// must come from `OPENSSL_malloc`; `ERR_TXT_STRING` marks it as text to print. Null clears
    /// the data (OpenSSL's would crash, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `data` is null or a NUL-terminated string, from `OPENSSL_malloc` if `flags` has
    /// `ERR_TXT_MALLOCED`, that stays valid while the error holds it.
    pub unsafe extern "C" fn ERR_set_error_data(data: *mut c_char, flags: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller passes null or a string.
        let size = unsafe { c_bytes(data) }.map_or(0, |d| d.len() + 1);
        // SAFETY: the caller's guarantee about `data` and its ownership.
        unsafe { set_error_data(data, size, flags, true) };
    }
}

/// `ERR_add_error_vdata`, which `ERR_add_error_data` shares.
///
/// # Safety
/// `args` holds `num` arguments, each null or a NUL-terminated string.
unsafe fn add_error_vdata(num: c_int, mut args: VaList<'_>) {
    let mut pieces = Vec::new();
    for _ in 0..num.max(0) {
        // SAFETY: the caller passes `num` string arguments.
        let arg = unsafe { args.next_arg::<*const c_char>() };
        // SAFETY: each is null or a string that outlives the call.
        pieces.push(unsafe { c_bytes(arg) });
    }
    add_error_data(pieces);
}

/// Appends `num` strings to the newest error's data, null ones as `<NULL>`. The data becomes
/// allocated text the queue owns; data that wasn't is replaced.
///
/// # Safety
/// `num` arguments follow, each null or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ERR_add_error_data(num: c_int, args: ...) {
    let add = move || {
        // SAFETY: the caller's guarantee about the arguments.
        unsafe { add_error_vdata(num, args) }
    };
    guard(ERR_LIB_CRYPTO, "ERR_add_error_data", || (), add);
}

ffi_export! {
    /// `ERR_add_error_data` with its arguments in a `va_list`.
    ///
    /// # Safety
    /// `args` holds `num` arguments, each null or a NUL-terminated string.
    pub unsafe extern "C" fn ERR_add_error_vdata(num: c_int, args: VaList<'_>)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee about the arguments.
        unsafe { add_error_vdata(num, args) };
    }
}

ffi_export! {
    /// Appends `txt` to the newest error's data after `sepr` (null for none), raising an error
    /// of library `ERR_LIB_NONE` first if the queue is empty. Text that would make the data
    /// too long to print whole goes on to new errors with the same code and origin.
    ///
    /// # Safety
    /// `sepr` and `txt` are null or NUL-terminated strings; null `txt` does nothing (OpenSSL's
    /// would crash, docs/DEVIATIONS.md).
    pub unsafe extern "C" fn ERR_add_error_txt(sepr: *const c_char, txt: *const c_char)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller passes null or strings, which outlive the call.
        let separator = unsafe { c_bytes(sepr) };
        // SAFETY: as above.
        let text = unsafe { c_bytes(txt) };
        if let Some(text) = text {
            add_error_txt(separator.unwrap_or_default(), text);
        }
    }
}

/// Defines the `ERR_get_error`/`ERR_peek_error` family, each written with its full signature,
/// as `get_into(action, outputs...)`.
macro_rules! getters {
    ($(
        $(#[$attr:meta])*
        pub unsafe extern "C" fn $name:ident($($arg:ident: $ty:ty),*) -> c_ulong
        = $action:ident($file:expr, $line:expr, $func:expr, $data:expr, $flags:expr);
    )*) => {$(
        ffi_export! {
            $(#[$attr])*
            ///
            /// # Safety
            /// Each output is null or valid for a write.
            pub unsafe extern "C" fn $name($($arg: $ty),*) -> c_ulong
            where failure = 0, library = ERR_LIB_CRYPTO
            {
                // SAFETY: the caller's guarantee about the outputs.
                unsafe { get_into(Get::$action, $file, $line, $func, $data, $flags) }
            }
        }
    )*};
}

getters! {
    /// Removes and returns the oldest error's code; 0 if there is none.
    pub unsafe extern "C" fn ERR_get_error() -> c_ulong
    = Pop(ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    /// `ERR_get_error`, with the error's file, line, function, data, and data flags. The strings
    /// stay valid until the slot is reused; missing ones are `""`.
    pub unsafe extern "C" fn ERR_get_error_all(file: *mut *const c_char, line: *mut c_int, func: *mut *const c_char, data: *mut *const c_char, flags: *mut c_int) -> c_ulong
    = Pop(file, line, func, data, flags);
    /// `ERR_get_error`, with the file and line (deprecated).
    pub unsafe extern "C" fn ERR_get_error_line(file: *mut *const c_char, line: *mut c_int) -> c_ulong
    = Pop(file, line, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    /// `ERR_get_error`, with the file, line, data, and data flags (deprecated).
    pub unsafe extern "C" fn ERR_get_error_line_data(file: *mut *const c_char, line: *mut c_int, data: *mut *const c_char, flags: *mut c_int) -> c_ulong
    = Pop(file, line, ptr::null_mut(), data, flags);
    /// Returns the oldest error's code without removing it; 0 if there is none.
    pub unsafe extern "C" fn ERR_peek_error() -> c_ulong
    = Peek(ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    /// `ERR_peek_error`, with the file and line.
    pub unsafe extern "C" fn ERR_peek_error_line(file: *mut *const c_char, line: *mut c_int) -> c_ulong
    = Peek(file, line, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    /// `ERR_peek_error`, with the function.
    pub unsafe extern "C" fn ERR_peek_error_func(func: *mut *const c_char) -> c_ulong
    = Peek(ptr::null_mut(), ptr::null_mut(), func, ptr::null_mut(), ptr::null_mut());
    /// `ERR_peek_error`, with the data and data flags.
    pub unsafe extern "C" fn ERR_peek_error_data(data: *mut *const c_char, flags: *mut c_int) -> c_ulong
    = Peek(ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), data, flags);
    /// `ERR_peek_error`, with everything `ERR_get_error_all` returns.
    pub unsafe extern "C" fn ERR_peek_error_all(file: *mut *const c_char, line: *mut c_int, func: *mut *const c_char, data: *mut *const c_char, flags: *mut c_int) -> c_ulong
    = Peek(file, line, func, data, flags);
    /// `ERR_peek_error`, with the file, line, data, and data flags (deprecated).
    pub unsafe extern "C" fn ERR_peek_error_line_data(file: *mut *const c_char, line: *mut c_int, data: *mut *const c_char, flags: *mut c_int) -> c_ulong
    = Peek(file, line, ptr::null_mut(), data, flags);
    /// Returns the newest error's code without removing it; 0 if there is none.
    pub unsafe extern "C" fn ERR_peek_last_error() -> c_ulong
    = PeekLast(ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    /// `ERR_peek_last_error`, with the file and line.
    pub unsafe extern "C" fn ERR_peek_last_error_line(file: *mut *const c_char, line: *mut c_int) -> c_ulong
    = PeekLast(file, line, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    /// `ERR_peek_last_error`, with the function.
    pub unsafe extern "C" fn ERR_peek_last_error_func(func: *mut *const c_char) -> c_ulong
    = PeekLast(ptr::null_mut(), ptr::null_mut(), func, ptr::null_mut(), ptr::null_mut());
    /// `ERR_peek_last_error`, with the data and data flags.
    pub unsafe extern "C" fn ERR_peek_last_error_data(data: *mut *const c_char, flags: *mut c_int) -> c_ulong
    = PeekLast(ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), data, flags);
    /// `ERR_peek_last_error`, with everything `ERR_get_error_all` returns.
    pub unsafe extern "C" fn ERR_peek_last_error_all(file: *mut *const c_char, line: *mut c_int, func: *mut *const c_char, data: *mut *const c_char, flags: *mut c_int) -> c_ulong
    = PeekLast(file, line, func, data, flags);
    /// `ERR_peek_last_error`, with the file, line, data, and data flags (deprecated).
    pub unsafe extern "C" fn ERR_peek_last_error_line_data(file: *mut *const c_char, line: *mut c_int, data: *mut *const c_char, flags: *mut c_int) -> c_ulong
    = PeekLast(file, line, ptr::null_mut(), data, flags);
}

ffi_export! {
    /// Empties this thread's queue.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ERR_clear_error()
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if let Some(state) = state() {
            for i in 0..SLOTS {
                // SAFETY: this thread's state.
                unsafe { clear(state, i, false) };
            }
            // SAFETY: as above.
            unsafe { set_ends(state, 0, 0) };
        }
    }
}

ffi_export! {
    /// Marks the newest error, for `ERR_pop_to_mark` to stop at. Returns 1, or 0 if the queue
    /// is empty.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ERR_set_mark() -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(state) = state() else {
            return 0;
        };
        // SAFETY: this thread's state, for each access.
        let (top, bottom) = unsafe { ends(state) };
        if top == bottom {
            return 0;
        }
        // SAFETY: as above.
        let mut entry = unsafe { load(state, top) };
        entry.marks = entry.marks.wrapping_add(1);
        // SAFETY: as above.
        unsafe { store(state, top, entry) };
        1
    }
}

/// Counts the errors after the newest mark (all of them without one), and returns the count
/// and the marked slot, if any.
///
/// # Safety
/// `state` is a live `ERR_STATE`.
unsafe fn find_mark(state: NonNull<ERR_STATE>) -> (c_int, Option<usize>) {
    // SAFETY: the caller's guarantee, for each access.
    let (mut top, bottom) = unsafe { ends(state) };
    let mut count: c_int = 0;
    // SAFETY: as above.
    while top != bottom && unsafe { load(state, top) }.marks == 0 {
        count += 1;
        top = previous(top);
    }
    (count, (top != bottom).then_some(top))
}

ffi_export! {
    /// Removes the newest error. Returns 1, or 0 if the queue is empty.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ERR_pop() -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(state) = state() else {
            return 0;
        };
        // SAFETY: this thread's state, for each access.
        let (top, bottom) = unsafe { ends(state) };
        if top == bottom {
            return 0;
        }
        // SAFETY: as above.
        unsafe { clear(state, top, false) };
        // SAFETY: as above.
        unsafe { set_ends(state, previous(top), bottom) };
        1
    }
}

ffi_export! {
    /// Removes the errors after the newest mark, and the mark. Returns 1, or 0 if there was no
    /// mark, after emptying the queue.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ERR_pop_to_mark() -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(state) = state() else {
            return 0;
        };
        // SAFETY: this thread's state, for each access.
        let (mut top, bottom) = unsafe { ends(state) };
        // SAFETY: as above.
        while top != bottom && unsafe { load(state, top) }.marks == 0 {
            // SAFETY: as above.
            unsafe { clear(state, top, false) };
            top = previous(top);
            // SAFETY: as above.
            unsafe { set_ends(state, top, bottom) };
        }
        if top == bottom {
            return 0;
        }
        // SAFETY: as above.
        let mut entry = unsafe { load(state, top) };
        entry.marks -= 1;
        // SAFETY: as above.
        unsafe { store(state, top, entry) };
        1
    }
}

ffi_export! {
    /// Returns the number of errors after the newest mark, or all of them without one.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ERR_count_to_mark() -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: this thread's state.
        state().map_or(0, |state| unsafe { find_mark(state) }.0)
    }
}

ffi_export! {
    /// Removes the newest mark, keeping the errors. Returns 1, or 0 if there is none.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ERR_clear_last_mark() -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(state) = state() else {
            return 0;
        };
        // SAFETY: this thread's state, for each access.
        let Some(marked) = unsafe { find_mark(state) }.1 else {
            return 0;
        };
        // SAFETY: as above.
        let mut entry = unsafe { load(state, marked) };
        entry.marks -= 1;
        // SAFETY: as above.
        unsafe { store(state, marked, entry) };
        1
    }
}

ffi_export! {
    /// Returns this thread's queue, in OpenSSL's public layout (deprecated); null after
    /// `OPENSSL_cleanup`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ERR_get_state() -> *mut ERR_STATE
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        state().map_or(ptr::null_mut(), NonNull::as_ptr)
    }
}

ffi_export! {
    /// Does nothing (deprecated; the state is freed at thread exit or `OPENSSL_thread_stop`).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ERR_remove_thread_state(dummy: *mut c_void)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let _ = dummy;
    }
}

ffi_export! {
    /// Does nothing (deprecated).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ERR_remove_state(pid: c_ulong)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let _ = pid;
    }
}

ffi_export! {
    /// Returns a new, empty error state for `OSSL_ERR_STATE_save`, or null.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_ERR_STATE_new() -> *mut ERR_STATE
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        new_state().map_or(ptr::null_mut(), NonNull::as_ptr)
    }
}

ffi_export! {
    /// Frees a state from `OSSL_ERR_STATE_new` and the errors it holds. Null is ignored.
    ///
    /// # Safety
    /// `es` is null or a live state from `OSSL_ERR_STATE_new`, not used afterwards.
    pub unsafe extern "C" fn OSSL_ERR_STATE_free(es: *mut ERR_STATE)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if let Some(es) = NonNull::new(es) {
            // SAFETY: the caller's guarantee.
            unsafe { free_state(es) };
        }
    }
}

ffi_export! {
    /// Moves this thread's errors into `es`, replacing what it held, and empties the queue.
    /// Null is ignored.
    ///
    /// # Safety
    /// `es` is null or a live state from `OSSL_ERR_STATE_new`.
    pub unsafe extern "C" fn OSSL_ERR_STATE_save(es: *mut ERR_STATE)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let Some(es) = NonNull::new(es) else {
            return;
        };
        for i in 0..SLOTS {
            // SAFETY: the caller's guarantee.
            unsafe { clear(es, i, true) };
        }
        let Some(thread) = state() else {
            return;
        };
        if thread != es {
            // SAFETY: two distinct live states; `es` takes over the thread's allocations.
            unsafe { ptr::copy_nonoverlapping(thread.as_ptr(), es.as_ptr(), 1) };
        }
        // SAFETY: this thread's state, whose allocations now belong to `es`.
        unsafe { ptr::write_bytes(thread.as_ptr(), 0, 1) };
    }
}

ffi_export! {
    /// Moves the errors after the newest mark (all of them without one) into `es`, replacing
    /// what it held. The mark stays on the queue. Null is ignored.
    ///
    /// # Safety
    /// `es` is null or a live state from `OSSL_ERR_STATE_new`.
    pub unsafe extern "C" fn OSSL_ERR_STATE_save_to_mark(es: *mut ERR_STATE)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let Some(es) = NonNull::new(es) else {
            return;
        };
        let thread = state();
        if thread == Some(es) {
            return; // the thread's own state: there is nothing to move
        }
        let Some(thread) = thread else {
            for i in 0..SLOTS {
                // SAFETY: the caller's guarantee.
                unsafe { clear(es, i, true) };
            }
            // SAFETY: as above.
            unsafe { set_ends(es, 0, 0) };
            return;
        };
        // SAFETY: this thread's state, and the caller's, distinct; for each access below.
        let (count, _) = unsafe { find_mark(thread) };
        let count = usize::try_from(count).unwrap_or(0);
        // SAFETY: as above.
        let (top, bottom) = unsafe { ends(thread) };
        let mut from = top;
        for _ in 0..count {
            from = previous(from);
        }
        let mark = from;
        for i in 0..count {
            from = following(from);
            // SAFETY: as above.
            unsafe { clear(es, i, true) };
            // SAFETY: as above.
            let mut moved = unsafe { load(thread, from) };
            moved.marks = 0;
            // SAFETY: as above.
            unsafe { store(es, i, moved) };
            let emptied = Entry {
                flags: 0,
                code: 0,
                data: ptr::null_mut(),
                data_size: 0,
                data_flags: 0,
                file: ptr::null_mut(),
                line: 0,
                func: ptr::null_mut(),
                // SAFETY: as above.
                ..unsafe { load(thread, from) }
            };
            // SAFETY: as above.
            unsafe { store(thread, from, emptied) };
        }
        if count > 0 {
            // SAFETY: as above.
            unsafe { set_ends(thread, mark, bottom) };
            // SAFETY: as above; es's errors start at slot 0.
            unsafe { set_ends(es, count - 1, SLOTS - 1) };
        } else {
            // SAFETY: as above.
            unsafe { set_ends(es, 0, 0) };
        }
        for i in count..SLOTS {
            // SAFETY: as above.
            unsafe { clear(es, i, true) };
        }
    }
}

ffi_export! {
    /// Adds copies of the errors in `es` to this thread's queue, after its own. `es` keeps
    /// them, so restoring twice adds them twice. Null is ignored.
    ///
    /// # Safety
    /// `es` is null or a live state from `OSSL_ERR_STATE_new`.
    pub unsafe extern "C" fn OSSL_ERR_STATE_restore(es: *const ERR_STATE)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let Some(es) = NonNull::new(es.cast_mut()) else {
            return;
        };
        // SAFETY: the caller's guarantee, for each access to `es` below.
        let (es_top, es_bottom) = unsafe { ends(es) };
        if es_top == es_bottom {
            return;
        }
        let Some(thread) = state().filter(|thread| *thread != es) else {
            return;
        };
        let mut i = es_bottom;
        while i != es_top {
            i = following(i);
            // SAFETY: as above.
            let saved = unsafe { load(es, i) };
            if saved.flags & ERR_FLAG_CLEAR != 0 {
                continue;
            }
            // SAFETY: this thread's state, distinct from `es`, for each access below.
            let top = unsafe { next_slot(thread) };
            // SAFETY: as above.
            unsafe { clear(thread, top, false) };
            // SAFETY: as above.
            let mut entry = unsafe { load(thread, top) };
            entry.flags = saved.flags;
            entry.code = saved.code;
            // SAFETY: as above.
            unsafe { store(thread, top, entry) };
            // SAFETY: the saved names are null or strings the saved state owns.
            let file = unsafe { c_bytes(saved.file) };
            // SAFETY: as above.
            let func = unsafe { c_bytes(saved.func) };
            // SAFETY: as above.
            unsafe { set_debug(thread, top, file, saved.line, func) };
            if !saved.data.is_null() && saved.data_size != 0 {
                let copy = mem::malloc(saved.data_size, ptr::null(), 0).cast::<c_char>();
                if !copy.is_null() {
                    // SAFETY: the saved data holds `data_size` bytes; the copy is a fresh
                    // block of that size.
                    unsafe { ptr::copy_nonoverlapping(saved.data, copy, saved.data_size) };
                    let flags = saved.data_flags | ERR_TXT_MALLOCED;
                    // SAFETY: as above; the queue takes over the copy.
                    unsafe { set_data(thread, top, copy, saved.data_size, flags) };
                }
            } else {
                // SAFETY: as above.
                unsafe { clear_data(thread, top, false) };
            }
        }
    }
}

/// An error taken off this thread's queue, for tests.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct Taken {
    pub(crate) code: c_ulong,
    pub(crate) file: String,
    pub(crate) function: String,
}

/// Removes and returns this thread's errors, oldest first.
#[cfg(test)]
pub(crate) fn take_all() -> Vec<Taken> {
    let mut taken = Vec::new();
    loop {
        let (code, details) = get(Get::Pop, false);
        if code == 0 {
            return taken;
        }
        // SAFETY: the strings stay valid until the slot is reused.
        let file = unsafe { c_bytes(details.file) };
        // SAFETY: as above.
        let func = unsafe { c_bytes(details.func) };
        taken.push(Taken {
            code,
            file: String::from_utf8_lossy(file.unwrap_or_default()).into_owned(),
            function: String::from_utf8_lossy(func.unwrap_or_default()).into_owned(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyssl_abi::{ERR_LIB_BUF, ERR_R_PASSED_INVALID_ARGUMENT};

    #[test]
    fn packs_like_err_pack() {
        // ERR_PACK(ERR_LIB_BUF, 0, ERR_R_PASSED_INVALID_ARGUMENT): the library in bits 23-30,
        // the reason (with its flags) in bits 0-22.
        let code = pack(ERR_LIB_BUF, ERR_R_PASSED_INVALID_ARGUMENT);
        assert_eq!(code, 0x0388_0106);
        assert_eq!(library_of(code), ERR_LIB_BUF);
        assert_eq!(library_of(c_ulong::from(ERR_SYSTEM_FLAG) | 2), ERR_LIB_SYS);
    }

    #[test]
    fn the_queue_keeps_the_newest_errors() {
        take_all();
        for reason in 1..=20 {
            raise(ERR_LIB_BUF, reason, "test");
        }
        let errors = take_all();
        assert_eq!(errors.len(), SLOTS - 1);
        // The oldest were dropped.
        assert_eq!(errors[0].code, pack(ERR_LIB_BUF, 6));
        assert!(errors[0].file.ends_with("err.rs"), "{}", errors[0].file);
        assert_eq!(errors[0].function, "test");
        assert!(take_all().is_empty());
    }

    #[test]
    fn thread_stop_frees_the_queue() {
        raise(ERR_LIB_BUF, 1, "test");
        stop_thread();
        assert!(take_all().is_empty());
        raise(ERR_LIB_BUF, 2, "test");
        assert_eq!(take_all().len(), 1);
    }

    #[test]
    fn data_grows_and_survives_a_pop_that_asks_for_it() {
        take_all();
        raise(ERR_LIB_BUF, 1, "test");
        add_error_data([Some(&b"abc"[..]), None]);
        add_error_data([Some(&[b'x'; 100][..])]);
        let (code, details) = get(Get::Pop, true);
        assert_eq!(code, pack(ERR_LIB_BUF, 1));
        assert_eq!(details.flags, MALLOCED_STRING);
        // SAFETY: popped data stays valid until the slot is reused.
        let data = unsafe { c_bytes(details.data) }.unwrap();
        assert_eq!(data.len(), 109);
        assert!(data.starts_with(b"abc<NULL>xxx"));
    }

    /// A piece between separators that is too long even for a fresh error is split at the
    /// limit, where OpenSSL loops forever (docs/DEVIATIONS.md).
    #[test]
    fn long_text_without_separators_is_split() {
        take_all();
        raise(ERR_LIB_BUF, 1, "test");
        let text = vec![b'z'; 5000];
        add_error_txt(b";", &text);
        let mut lengths = Vec::new();
        loop {
            let (code, details) = get(Get::Pop, true);
            if code == 0 {
                break;
            }
            assert_eq!(code, pack(ERR_LIB_BUF, 1));
            // SAFETY: as above.
            lengths.push(unsafe { c_bytes(details.data) }.map_or(0, <[u8]>::len));
        }
        // The separator leads the first piece, as OpenSSL's splits do.
        assert_eq!(lengths, [MAX_DATA_LEN - 1, 5000 - (MAX_DATA_LEN - 2)]);
    }

    /// docs/DEVIATIONS.md: null data and text, where OpenSSL's `strlen` crashes.
    #[test]
    fn null_data_and_text_do_nothing() {
        take_all();
        raise(ERR_LIB_BUF, 1, "test");
        // SAFETY: null is the case under test.
        unsafe { ERR_set_error_data(ptr::null_mut(), ERR_TXT_STRING) };
        // SAFETY: as above.
        unsafe { ERR_add_error_txt(c";".as_ptr(), ptr::null()) };
        let (code, details) = get(Get::Pop, true);
        assert_eq!(code, pack(ERR_LIB_BUF, 1));
        // SAFETY: a static string.
        assert_eq!(unsafe { c_bytes(details.data) }, Some(&b""[..]));
        assert_eq!(details.flags, 0);
        assert!(take_all().is_empty());
    }

    /// docs/DEVIATIONS.md: restoring the thread's own state into itself, where OpenSSL's loop
    /// chases its own end forever, and saving it to itself.
    #[test]
    fn the_threads_own_state_is_left_alone() {
        take_all();
        raise(ERR_LIB_BUF, 1, "test");
        raise(ERR_LIB_BUF, 2, "test");
        // SAFETY: no preconditions.
        let own = unsafe { ERR_get_state() };
        // SAFETY: `own` is this thread's live state.
        unsafe { OSSL_ERR_STATE_restore(own) };
        // SAFETY: as above.
        unsafe { OSSL_ERR_STATE_save_to_mark(own) };
        assert_eq!(take_all().len(), 2);
    }

    #[test]
    fn wild_ring_positions_are_wrapped() {
        take_all();
        raise(ERR_LIB_BUF, 1, "test");
        let state = state().unwrap();
        // SAFETY: this thread's state; nothing else uses it during the writes.
        let s = unsafe { &mut *state.as_ptr() };
        s.top = 1000;
        s.bottom = -7;
        raise(ERR_LIB_BUF, 2, "test");
        let (code, _) = get(Get::PeekLast, false);
        assert_eq!(code, pack(ERR_LIB_BUF, 2));
        // SAFETY: as above.
        unsafe { ERR_clear_error() };
    }
}
