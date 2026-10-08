//! docs/DEVIATIONS.md, "Secure-heap queries without a secure heap": with no heap set up,
//! `CRYPTO_secure_used` and `CRYPTO_secure_actual_size` return 0 where OpenSSL's dereference a
//! null lock. Its own process, so no other test sets up a heap.

use core::ffi::c_void;

use rustyssl_capi as _;

unsafe extern "C" {
    fn CRYPTO_secure_used() -> usize;
    fn CRYPTO_secure_actual_size(ptr: *mut c_void) -> usize;
    fn CRYPTO_secure_malloc_initialized() -> core::ffi::c_int;
}

#[test]
fn queries_without_a_heap_return_zero() {
    let mut local = 0u8;
    // SAFETY: no preconditions.
    assert_eq!(unsafe { CRYPTO_secure_malloc_initialized() }, 0);
    // SAFETY: no preconditions.
    assert_eq!(unsafe { CRYPTO_secure_used() }, 0);
    // SAFETY: no preconditions; the pointer is only compared.
    let size = unsafe { CRYPTO_secure_actual_size(core::ptr::from_mut(&mut local).cast()) };
    assert_eq!(size, 0);
}
