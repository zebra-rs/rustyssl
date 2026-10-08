//! Directory listing (`OPENSSL_DIR_read`, `OPENSSL_DIR_end`), which OpenSSL declares only in
//! its internal `o_dir.h` but exports; `X509_LOOKUP_hash_dir` and the `openssl` tool use it.
//!
//! As OpenSSL's Unix version: entries come in `readdir`'s order, `.` and `..` included, each
//! name copied into the context (truncated to `PATH_MAX`); the end and every failure return
//! null with `errno` saying which (0 at the end).

use core::ffi::{c_char, c_int};
use core::ptr;
use std::sync::{Mutex, PoisonError};

use rustssl_abi::{ERR_LIB_CRYPTO, OPENSSL_DIR_CTX};

use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};

/// The longest name kept, as OpenSSL's `LP_ENTRY_SIZE`.
const ENTRY_SIZE: usize = {
    let path_max = libc::PATH_MAX.unsigned_abs() as usize;
    if path_max < 255 { 255 } else { path_max }
};

struct State {
    dir: *mut libc::DIR,
    /// The last name read, NUL-terminated; what `OPENSSL_DIR_read` returns points here.
    entry: Box<[c_char]>,
}

/// What a directory context points to.
pub(crate) struct DirContext(Mutex<State>);

// SAFETY: the `DIR` is used only under the lock, and C's DIR streams may move between threads.
unsafe impl Send for DirContext {}
// SAFETY: as above.
unsafe impl Sync for DirContext {}

handle_type!(OPENSSL_DIR_CTX => DirContext);

ffi_export! {
    /// Returns the next name in `directory`, opening it into `*ctx` on the first call (with
    /// `*ctx` null). Returns null at the end, with `errno` 0, or on failure with `errno` set
    /// (`EINVAL` for null arguments, `opendir`'s or `readdir`'s error otherwise). The name stays
    /// valid until the next call. Call `OPENSSL_DIR_end` when done.
    ///
    /// # Safety
    /// `ctx` is null or valid for reads and writes, holding null or a live context; `directory`
    /// is null or a NUL-terminated path.
    pub unsafe extern "C" fn OPENSSL_DIR_read(ctx: *mut *mut OPENSSL_DIR_CTX, directory: *const c_char) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_CRYPTO
    {
        if ctx.is_null() || directory.is_null() {
            crate::errno::set(libc::EINVAL);
            return ptr::null();
        }
        crate::errno::set(0);
        // SAFETY: the caller's guarantee.
        let mut handle = unsafe { ctx.read() };
        if handle.is_null() {
            // SAFETY: as above.
            let dir = unsafe { libc::opendir(directory) };
            if dir.is_null() {
                return ptr::null();
            }
            handle = OPENSSL_DIR_CTX::new_handle(DirContext(Mutex::new(State {
                dir,
                entry: vec![0; ENTRY_SIZE + 1].into_boxed_slice(),
            })));
            // SAFETY: as above.
            unsafe { ctx.write(handle) };
        }
        // SAFETY: as above.
        let Some(context) = (unsafe { OPENSSL_DIR_CTX::get(handle) }) else {
            crate::errno::set(libc::EINVAL);
            return ptr::null();
        };
        let mut state = context.0.lock().unwrap_or_else(PoisonError::into_inner);
        // SAFETY: the stream is open until OPENSSL_DIR_end.
        let entry = unsafe { libc::readdir(state.dir) };
        if entry.is_null() {
            return ptr::null();
        }
        // SAFETY: readdir returned a valid entry, which stays valid until the next readdir.
        let name = unsafe { &(*entry).d_name };
        // SAFETY: the name is NUL-terminated.
        let name = unsafe { core::ffi::CStr::from_ptr(name.as_ptr()) }.to_bytes();
        let kept = name.len().min(ENTRY_SIZE);
        for (slot, byte) in state.entry.iter_mut().zip(name.iter().take(kept)) {
            *slot = c_char::from_ne_bytes([*byte]);
        }
        if let Some(end) = state.entry.get_mut(kept) {
            *end = 0;
        }
        state.entry.as_ptr()
    }
}

ffi_export! {
    /// Closes the directory and frees `*ctx`, setting it to null. Returns 1, or 0 if `closedir`
    /// failed or there was nothing to close (with `errno` `EINVAL`).
    ///
    /// # Safety
    /// `ctx` is null or valid for reads and writes, holding null or a live context.
    pub unsafe extern "C" fn OPENSSL_DIR_end(ctx: *mut *mut OPENSSL_DIR_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let handle = if ctx.is_null() { ptr::null_mut() } else { unsafe { ctx.read() } };
        // SAFETY: as above.
        let Some(context) = (unsafe { OPENSSL_DIR_CTX::get(handle) }) else {
            crate::errno::set(libc::EINVAL);
            return 0;
        };
        let closed = {
            let mut state = context.0.lock().unwrap_or_else(PoisonError::into_inner);
            let dir = core::mem::replace(&mut state.dir, ptr::null_mut());
            // SAFETY: the stream was open, and nothing uses it after this.
            unsafe { libc::closedir(dir) }
        };
        // SAFETY: as above; the caller gives up the context.
        unsafe { OPENSSL_DIR_CTX::free(handle) };
        // Unlike OpenSSL, which leaves it dangling (docs/DEVIATIONS.md).
        // SAFETY: as above.
        unsafe { ctx.write(ptr::null_mut()) };
        c_int::from(closed == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: `OPENSSL_DIR_end` clears the context, so ending twice is harmless
    /// where OpenSSL would free it twice.
    #[test]
    #[cfg_attr(miri, ignore = "Miri can't open directories")]
    fn ending_clears_the_context() {
        let mut ctx: *mut OPENSSL_DIR_CTX = ptr::null_mut();
        // SAFETY: `ctx` is a valid, null context; the path is NUL-terminated.
        let first = unsafe { OPENSSL_DIR_read(&mut ctx, c"/".as_ptr()) };
        assert!(!first.is_null());
        // SAFETY: `ctx` holds a live context.
        assert_eq!(unsafe { OPENSSL_DIR_end(&mut ctx) }, 1);
        assert!(ctx.is_null());
        // SAFETY: `ctx` is null now.
        assert_eq!(unsafe { OPENSSL_DIR_end(&mut ctx) }, 0);
    }
}
