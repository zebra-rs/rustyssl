//! The error queue: printing it, clearing it, marks, and a snapshot.

use core::ffi::{c_char, c_int, c_ulong};

use crate::abi::{ERR_REASON_MASK, ERR_SYSTEM_FLAG, ERR_SYSTEM_MASK};
use crate::bio::Bio;
use crate::ffi;
use crate::util::string_at;

/// `ERR_print_errors(bio)`.
pub fn print_errors(bio: &Bio) {
    // SAFETY: the BIO is live.
    unsafe { ffi::ERR_print_errors(bio.as_ptr()) };
}

/// `ERR_print_errors` to standard error (descriptor 2).
pub fn print_errors_fd2() {
    if let Some(b) = Bio::new_fd(2, false) {
        print_errors(&b);
    }
}

/// `ERR_clear_error()`.
pub fn clear() {
    // SAFETY: no arguments; it only touches this thread's queue.
    unsafe { ffi::ERR_clear_error() };
}

/// `ERR_set_mark()`.
pub fn set_mark() -> bool {
    // SAFETY: as above.
    unsafe { ffi::ERR_set_mark() == 1 }
}

/// `ERR_pop_to_mark()`.
pub fn pop_to_mark() -> bool {
    // SAFETY: as above.
    unsafe { ffi::ERR_pop_to_mark() == 1 }
}

/// `ERR_clear_last_mark()`.
pub fn clear_last_mark() -> bool {
    // SAFETY: as above.
    unsafe { ffi::ERR_clear_last_mark() == 1 }
}

/// `ERR_peek_error()`.
pub fn peek_error() -> c_ulong {
    // SAFETY: as above.
    unsafe { ffi::ERR_peek_error() }
}

/// `ERR_peek_last_error()`.
pub fn peek_last_error() -> c_ulong {
    // SAFETY: as above.
    unsafe { ffi::ERR_peek_last_error() }
}

/// `ERR_SYSTEM_ERROR(e)`: whether the code is a system error (its reason an `errno`).
pub fn is_system_error(e: c_ulong) -> bool {
    e & c_ulong::from(ERR_SYSTEM_FLAG) != 0
}

/// `ERR_GET_REASON(e)`.
pub fn reason(e: c_ulong) -> c_int {
    let mask = if is_system_error(e) {
        c_ulong::from(ERR_SYSTEM_MASK)
    } else {
        c_ulong::try_from(ERR_REASON_MASK).unwrap_or(0)
    };
    // Both masks fit an int.
    c_int::try_from(e & mask).unwrap_or(0)
}

/// One entry of the queue.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub code: c_ulong,
    pub file: Option<String>,
    pub line: c_int,
    pub func: Option<String>,
    pub data: Option<String>,
}

/// Takes every entry off the queue (`ERR_get_error_all`), oldest first.
pub fn snapshot() -> Vec<Entry> {
    let mut out = Vec::new();
    loop {
        let mut file: *const c_char = core::ptr::null();
        let mut func: *const c_char = core::ptr::null();
        let mut data: *const c_char = core::ptr::null();
        let mut line: c_int = 0;
        let mut flags: c_int = 0;
        // SAFETY: every out-pointer is a valid local; the strings returned stay valid until
        // the entry is gone, and are copied before the next call.
        let code = unsafe {
            ffi::ERR_get_error_all(&mut file, &mut line, &mut func, &mut data, &mut flags)
        };
        if code == 0 {
            return out;
        }
        out.push(Entry {
            code,
            file: string_at(file),
            line,
            func: string_at(func),
            data: string_at(data),
        });
    }
}
