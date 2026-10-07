//! Memory that crosses the C boundary. Anything C may free with `OPENSSL_free` comes from here,
//! never from Rust's allocator, and anything C hands back to be freed returns here (security
//! rule 6). Step 1.1 exports the `CRYPTO_malloc` family on top of this module and adds
//! `CRYPTO_set_mem_functions`.
//!
//! The functions follow OpenSSL's `CRYPTO_*` semantics: a zero-byte allocation returns null
//! without an error, and a failed one returns null and raises `ERR_R_MALLOC_FAILURE`.

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{Ordering, compiler_fence};

use rustssl_abi::{ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE};

use crate::err;

fn failed(size: usize, result: *mut c_void) -> *mut c_void {
    if result.is_null() && size != 0 {
        err::raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE, "CRYPTO_malloc");
    }
    result
}

/// Allocates `size` bytes, like `CRYPTO_malloc`.
pub(crate) fn alloc(size: usize) -> *mut c_void {
    if size == 0 {
        return ptr::null_mut();
    }
    // SAFETY: malloc accepts any size and returns null or a fresh allocation.
    failed(size, unsafe { libc::malloc(size) })
}

/// Allocates `size` zeroed bytes, like `CRYPTO_zalloc`.
pub(crate) fn zalloc(size: usize) -> *mut c_void {
    if size == 0 {
        return ptr::null_mut();
    }
    // SAFETY: calloc accepts any count and size and returns null or zeroed memory.
    failed(size, unsafe { libc::calloc(1, size) })
}

/// Resizes `block` to `size` bytes, like `CRYPTO_realloc`: a null `block` allocates, and a zero
/// `size` frees and returns null. On failure `block` is left untouched.
///
/// # Safety
/// `block` is null or a live allocation from this module.
pub(crate) unsafe fn realloc(block: *mut c_void, size: usize) -> *mut c_void {
    if block.is_null() {
        return alloc(size);
    }
    if size == 0 {
        // SAFETY: the caller passes a live allocation from this module.
        unsafe { free(block) };
        return ptr::null_mut();
    }
    // SAFETY: the caller passes a live allocation from this module, which comes from malloc.
    failed(size, unsafe { libc::realloc(block, size) })
}

/// Resizes `block` from `old` to `size` bytes, like `CRYPTO_clear_realloc`: the old contents
/// never survive anywhere but in the result. Shrinking zeroes the tail in place; growing moves
/// to a new block and clears and frees the old one.
///
/// # Safety
/// `block` is null or a live allocation from this module of at least `old` bytes.
pub(crate) unsafe fn clear_realloc(block: *mut c_void, old: usize, size: usize) -> *mut c_void {
    if block.is_null() {
        return alloc(size);
    }
    if size == 0 {
        // SAFETY: the caller passes a live allocation of `old` bytes from this module.
        unsafe { clear_free(block, old) };
        return ptr::null_mut();
    }
    if size < old {
        // SAFETY: bytes `size..old` lie inside the caller's allocation of `old` bytes.
        unsafe { cleanse(block.cast::<u8>().wrapping_add(size).cast(), old - size) };
        return block;
    }
    let fresh = alloc(size);
    if !fresh.is_null() {
        // SAFETY: both blocks hold at least `old` bytes and are distinct allocations.
        unsafe { ptr::copy_nonoverlapping(block.cast::<u8>(), fresh.cast::<u8>(), old) };
        // SAFETY: the caller passes a live allocation of `old` bytes from this module.
        unsafe { clear_free(block, old) };
    }
    fresh
}

/// Frees `block`, like `CRYPTO_free`. Null does nothing.
///
/// # Safety
/// `block` is null or a live allocation from this module, which must not be used afterwards.
pub(crate) unsafe fn free(block: *mut c_void) {
    // SAFETY: the caller passes null or a live malloc'd block.
    unsafe { libc::free(block) }
}

/// Zeroes `len` bytes of `block` and frees it, like `CRYPTO_clear_free`. Null does nothing.
///
/// # Safety
/// `block` is null or a live allocation from this module of at least `len` bytes, which must
/// not be used afterwards.
pub(crate) unsafe fn clear_free(block: *mut c_void, len: usize) {
    if block.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `len` writable bytes at `block`.
    unsafe { cleanse(block, len) };
    // SAFETY: as above, the block is a live allocation from this module.
    unsafe { free(block) };
}

/// Zeroes `len` bytes at `block` in a way the compiler can't remove, like `OPENSSL_cleanse`.
///
/// # Safety
/// `block` is valid for `len` bytes of writes.
pub(crate) unsafe fn cleanse(block: *mut c_void, len: usize) {
    let bytes = block.cast::<u8>();
    for offset in 0..len {
        // SAFETY: `offset < len`, and the caller guarantees `len` writable bytes.
        unsafe { ptr::write_volatile(bytes.wrapping_add(offset), 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sets the `len` bytes at `block` to `byte`.
    fn fill(block: *mut c_void, len: usize, byte: u8) {
        // SAFETY: the tests pass blocks of at least `len` bytes.
        unsafe { ptr::write_bytes(block.cast::<u8>(), byte, len) };
    }

    /// The `len` bytes at `block`.
    fn bytes<'a>(block: *mut c_void, len: usize) -> &'a [u8] {
        // SAFETY: the tests pass blocks of at least `len` initialized bytes.
        unsafe { std::slice::from_raw_parts(block.cast::<u8>(), len) }
    }

    #[test]
    fn zero_sized_allocations_are_null_without_an_error() {
        crate::err::take_all();
        assert!(alloc(0).is_null());
        assert!(zalloc(0).is_null());
        assert!(crate::err::take_all().is_empty());
    }

    #[test]
    fn zalloc_zeroes_and_realloc_keeps_the_contents() {
        let block = zalloc(16);
        assert_eq!(bytes(block, 16), [0; 16]);
        fill(block, 16, 0xab);
        // SAFETY: `block` is a live 16-byte allocation from this module.
        let block = unsafe { realloc(block, 64) };
        assert_eq!(bytes(block, 16), [0xab; 16]);
        // SAFETY: `block` is live; resizing to zero frees it.
        let freed = unsafe { realloc(block, 0) };
        assert!(freed.is_null());
    }

    #[test]
    fn clear_realloc_shrinks_in_place_and_grows_into_a_new_block() {
        let block = alloc(32);
        fill(block, 32, 0x5a);
        // SAFETY: `block` is a live 32-byte allocation from this module.
        let same = unsafe { clear_realloc(block, 32, 8) };
        assert_eq!(same, block);
        assert_eq!(bytes(block, 8), [0x5a; 8]);
        assert_eq!(bytes(block, 32)[8..], [0; 24]);
        // SAFETY: the shrunk block is still the same 32-byte allocation.
        let grown = unsafe { clear_realloc(block, 32, 128) };
        assert_eq!(bytes(grown, 8), [0x5a; 8]);
        // SAFETY: `grown` is a live 128-byte allocation, not used afterwards.
        unsafe { clear_free(grown, 128) };
        // SAFETY: null does nothing.
        unsafe { clear_free(ptr::null_mut(), 10) };
        // SAFETY: as above.
        unsafe { free(ptr::null_mut()) };
    }

    #[test]
    fn cleanse_zeroes() {
        let mut buffer = [0xffu8; 40];
        // SAFETY: `buffer` holds 40 writable bytes.
        unsafe { cleanse(buffer.as_mut_ptr().cast(), 33) };
        assert_eq!(buffer[..33], [0; 33]);
        assert_eq!(buffer[33..], [0xff; 7]);
    }
}
