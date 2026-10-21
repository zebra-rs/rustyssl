//! The few system calls the CLI makes that Rust's standard library doesn't offer.

/// `access(path, W_OK) == 0`: whether the calling process may write to `path`.
pub fn writable(path: &str) -> bool {
    let Some(p) = crate::cstring(path) else {
        return false;
    };
    // SAFETY: p is a valid C string; access only reads it.
    unsafe { libc::access(p.as_ptr(), libc::W_OK) == 0 }
}
