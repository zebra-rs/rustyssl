//! docs/DEVIATIONS.md, "An allocator that calls back into CRYPTO_malloc": an application's
//! malloc that calls `CRYPTO_malloc` gets the default allocator instead of recursing forever.
//! Its own process, because the allocator is process-wide and replaceable only before the
//! first allocation.

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicUsize, Ordering};

use rustssl_capi as _;

unsafe extern "C" {
    fn CRYPTO_set_mem_functions(
        malloc: Option<unsafe extern "C" fn(usize, *const c_char, c_int) -> *mut c_void>,
        realloc: Option<
            unsafe extern "C" fn(*mut c_void, usize, *const c_char, c_int) -> *mut c_void,
        >,
        free: Option<unsafe extern "C" fn(*mut c_void, *const c_char, c_int)>,
    ) -> c_int;
    fn CRYPTO_malloc(num: usize, file: *const c_char, line: c_int) -> *mut c_void;
    fn CRYPTO_free(ptr: *mut c_void, file: *const c_char, line: c_int);
}

static CALLS: AtomicUsize = AtomicUsize::new(0);

/// A malloc that wraps `CRYPTO_malloc`, as one reached through a different address would.
unsafe extern "C" fn wrapping_malloc(num: usize, file: *const c_char, line: c_int) -> *mut c_void {
    CALLS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: CRYPTO_malloc takes any size and a null file.
    unsafe { CRYPTO_malloc(num, file, line) }
}

#[test]
fn a_reentrant_allocator_gets_the_default_one() {
    // SAFETY: installing a malloc that behaves like malloc, before anything allocates.
    let installed = unsafe { CRYPTO_set_mem_functions(Some(wrapping_malloc), None, None) };
    assert_eq!(installed, 1);
    // SAFETY: CRYPTO_malloc takes any size and a null file.
    let block = unsafe { CRYPTO_malloc(32, core::ptr::null(), 0) };
    assert!(!block.is_null());
    assert_eq!(CALLS.load(Ordering::Relaxed), 1);
    // SAFETY: `block` came from the default allocator, which CRYPTO_free still uses.
    unsafe { CRYPTO_free(block, core::ptr::null(), 0) };
}
