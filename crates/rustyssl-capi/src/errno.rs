//! The calling thread's `errno`, which OpenSSL's functions read and set.

use core::ffi::c_int;

/// Where this thread's `errno` lives.
#[cfg(target_os = "macos")]
pub(crate) fn location() -> *mut c_int {
    // SAFETY: no preconditions.
    unsafe { libc::__error() }
}

/// Where this thread's `errno` lives.
#[cfg(not(target_os = "macos"))]
pub(crate) fn location() -> *mut c_int {
    // SAFETY: no preconditions.
    unsafe { libc::__errno_location() }
}

/// This thread's `errno`.
pub(crate) fn get() -> c_int {
    // SAFETY: `location` returns this thread's errno.
    unsafe { location().read() }
}

/// Sets this thread's `errno`.
pub(crate) fn set(value: c_int) {
    // SAFETY: `location` returns this thread's errno.
    unsafe { location().write(value) };
}
