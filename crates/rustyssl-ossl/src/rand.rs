//! Random seed files.

use crate::ffi;
use crate::util::cstring;

/// `RAND_load_file(name, -1)`: what it returns (bytes read, or < 0).
pub fn load_file(name: &str) -> i32 {
    let Some(n) = cstring(name) else {
        return -1;
    };
    // SAFETY: n is a valid C string.
    unsafe { ffi::RAND_load_file(n.as_ptr(), -1) }
}

/// `RAND_write_file(name)`: what it returns.
pub fn write_file(name: &str) -> i32 {
    let Some(n) = cstring(name) else {
        return -1;
    };
    // SAFETY: n is a valid C string.
    unsafe { ffi::RAND_write_file(n.as_ptr()) }
}

/// `RAND_poll()`.
pub fn poll() -> bool {
    // SAFETY: no arguments.
    unsafe { ffi::RAND_poll() > 0 }
}

/// `RAND_status()`.
pub fn status() -> bool {
    // SAFETY: no arguments.
    unsafe { ffi::RAND_status() == 1 }
}

/// `RAND_bytes_ex(libctx, buf, len, 0)`: what it returns.
pub fn bytes_ex(libctx: Option<&crate::provider::LibCtx>, buf: &mut [u8]) -> i32 {
    let ctx = libctx.map_or(core::ptr::null_mut(), crate::provider::LibCtx::as_ptr);
    // SAFETY: ctx is NULL or live; buf is writable for its length.
    unsafe { ffi::RAND_bytes_ex(ctx, buf.as_mut_ptr(), buf.len(), 0) }
}

/// `RAND_bytes(buf, len)`: what it returns.
pub fn bytes(buf: &mut [u8]) -> i32 {
    let Ok(n) = core::ffi::c_int::try_from(buf.len()) else {
        return 0;
    };
    // SAFETY: buf is writable for n bytes.
    unsafe { ffi::RAND_bytes(buf.as_mut_ptr(), n) }
}
