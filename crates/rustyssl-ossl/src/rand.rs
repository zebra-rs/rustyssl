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
