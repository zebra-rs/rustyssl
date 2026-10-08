//! `BUF_MEM`, OpenSSL's growable byte buffer (`buffer.h`, `BUF_MEM_new(3)`).
//!
//! Its layout is public: applications read `length`, `data`, and `max` directly, so the struct
//! and its data live in C memory from [`crate::mem`]. The behavior follows OpenSSL's
//! `crypto/buffer/buffer.c`:
//! - growing past `max` reallocates to `(len + 3) / 3 * 4` bytes;
//! - newly exposed bytes are zero;
//! - lengths above [`LIMIT_BEFORE_EXPANSION`] fail with `ERR_R_PASSED_INVALID_ARGUMENT`;
//! - freeing zeroes the data first.
//!
//! With `BUF_MEM_FLAG_SECURE`, the data lives in the secure heap ([`crate::secure`]) when one
//! is set up, and in ordinary memory otherwise, as in OpenSSL.

use core::ffi::{c_ulong, c_void};
use core::ptr;

use rustyssl_abi::{
    BUF_MEM, BUF_MEM_FLAG_SECURE, ERR_LIB_BUF, ERR_R_PASSED_INVALID_ARGUMENT,
    ERR_R_PASSED_NULL_PARAMETER,
};

use crate::err;
use crate::ffi::ffi_export;
use crate::mem;
use crate::secure;

/// The largest length a buffer may grow to. OpenSSL's `buffer.c` picks it so that
/// `(len + 3) / 3 * 4` stays below 2^31.
const LIMIT_BEFORE_EXPANSION: usize = 0x5fff_fffc;

ffi_export! {
    /// Allocates an empty buffer: no data, length and size zero, no flags.
    ///
    /// # Safety
    /// Always safe to call. The result is null on allocation failure, or a buffer the caller
    /// frees with `BUF_MEM_free`.
    pub unsafe extern "C" fn BUF_MEM_new() -> *mut BUF_MEM
    where failure = ptr::null_mut(), library = ERR_LIB_BUF
    {
        mem::alloc_zeroed(size_of::<BUF_MEM>()).cast()
    }
}

ffi_export! {
    /// Like `BUF_MEM_new`, with `flags` set (`BUF_MEM_FLAG_SECURE` asks for secure-heap data).
    ///
    /// # Safety
    /// As for `BUF_MEM_new`.
    pub unsafe extern "C" fn BUF_MEM_new_ex(flags: c_ulong) -> *mut BUF_MEM
    where failure = ptr::null_mut(), library = ERR_LIB_BUF
    {
        let buffer: *mut BUF_MEM = mem::alloc_zeroed(size_of::<BUF_MEM>()).cast();
        // SAFETY: a non-null result is a zeroed `BUF_MEM` this function just allocated.
        if let Some(fresh) = unsafe { buffer.as_mut() } {
            fresh.flags = flags;
        }
        buffer
    }
}

ffi_export! {
    /// Zeroes the buffer's data, then frees the data and the buffer. Null does nothing.
    ///
    /// # Safety
    /// `buffer` is null or a live `BUF_MEM` from `BUF_MEM_new`/`BUF_MEM_new_ex` whose `data`
    /// (if any) holds `max` bytes from the OpenSSL allocator. It must not be used afterwards.
    pub unsafe extern "C" fn BUF_MEM_free(buffer: *mut BUF_MEM)
    where failure = (), library = ERR_LIB_BUF
    {
        // SAFETY: the caller passes null or a live `BUF_MEM`.
        let Some(contents) = (unsafe { buffer.as_ref() }) else {
            return;
        };
        let data = contents.data.cast();
        if contents.flags & BUF_MEM_FLAG_SECURE.cast_unsigned() as c_ulong != 0 {
            // SAFETY: `data` is null or holds `max` bytes from the secure heap or, without
            // one, the OpenSSL allocator.
            unsafe { secure::release_clean(data, contents.max) };
        } else {
            // SAFETY: `data` is null or holds `max` bytes from the OpenSSL allocator.
            unsafe { mem::release_clean(data, contents.max) };
        }
        // SAFETY: the buffer itself came from the OpenSSL allocator.
        unsafe { mem::release(buffer.cast()) };
    }
}

ffi_export! {
    /// Sets the buffer's length to `len`, preserving existing data and zeroing new bytes.
    /// Returns `len`, or 0 on failure. Shrinking keeps the memory and its old contents.
    ///
    /// # Safety
    /// `buffer` is null or a live `BUF_MEM` (see `BUF_MEM_free`) that nothing else uses during
    /// the call. (OpenSSL crashes on null; this raises `ERR_R_PASSED_NULL_PARAMETER`.)
    pub unsafe extern "C" fn BUF_MEM_grow(buffer: *mut BUF_MEM, len: usize) -> usize
    where failure = 0, library = ERR_LIB_BUF
    {
        // SAFETY: the caller passes null or a live `BUF_MEM` used by nothing else.
        unsafe { grow(buffer, len, false, "BUF_MEM_grow") }
    }
}

ffi_export! {
    /// Like `BUF_MEM_grow`, but no old contents survive outside the buffer: shrinking zeroes
    /// the cut-off bytes, and moving to a bigger block zeroes and frees the old one.
    ///
    /// # Safety
    /// As for `BUF_MEM_grow`.
    pub unsafe extern "C" fn BUF_MEM_grow_clean(buffer: *mut BUF_MEM, len: usize) -> usize
    where failure = 0, library = ERR_LIB_BUF
    {
        // SAFETY: the caller passes null or a live `BUF_MEM` used by nothing else.
        unsafe { grow(buffer, len, true, "BUF_MEM_grow_clean") }
    }
}

/// `BUF_MEM_grow` (`clean == false`) and `BUF_MEM_grow_clean` (`clean == true`).
///
/// # Safety
/// `buffer` is null or a live `BUF_MEM` from this library that nothing else uses during the
/// call.
unsafe fn grow(buffer: *mut BUF_MEM, len: usize, clean: bool, function: &'static str) -> usize {
    // SAFETY: the caller passes null or a live `BUF_MEM` used by nothing else.
    let Some(buffer) = (unsafe { buffer.as_mut() }) else {
        err::raise(ERR_LIB_BUF, ERR_R_PASSED_NULL_PARAMETER, function);
        return 0;
    };
    let data = buffer.data.cast::<u8>();
    if buffer.length >= len {
        if clean && !data.is_null() {
            // SAFETY: bytes `len..length` lie inside the buffer's `max` bytes.
            unsafe { mem::cleanse(data.wrapping_add(len).cast(), buffer.length - len) };
        }
        buffer.length = len;
        return len;
    }
    if buffer.max >= len {
        if !data.is_null() {
            // SAFETY: bytes `length..len` lie inside the buffer's `max` bytes.
            unsafe { ptr::write_bytes(data.wrapping_add(buffer.length), 0, len - buffer.length) };
        }
        buffer.length = len;
        return len;
    }
    if len > LIMIT_BEFORE_EXPANSION {
        err::raise(ERR_LIB_BUF, ERR_R_PASSED_INVALID_ARGUMENT, function);
        return 0;
    }
    let size = (len + 3) / 3 * 4;
    let secure = buffer.flags & BUF_MEM_FLAG_SECURE.cast_unsigned() as c_ulong != 0;
    let fresh: *mut c_void = if secure {
        // OpenSSL moves secure data to a new block, copying only `length` bytes.
        let fresh = secure::alloc(size);
        if !fresh.is_null() && !data.is_null() {
            // SAFETY: the old block holds `length` bytes, the new one `size > length`.
            unsafe { ptr::copy_nonoverlapping(data, fresh.cast::<u8>(), buffer.length) };
            // SAFETY: the old block came from the secure heap or the OpenSSL allocator and
            // holds `length` bytes.
            unsafe { secure::release_clean(data.cast(), buffer.length) };
        }
        fresh
    } else if clean {
        // SAFETY: `data` is null or holds `max` bytes from the OpenSSL allocator.
        unsafe { mem::resize_clean(data.cast(), buffer.max, size) }
    } else {
        // SAFETY: `data` is null or a live block from the OpenSSL allocator.
        unsafe { mem::resize(data.cast(), size) }
    };
    if fresh.is_null() {
        return 0;
    }
    let fresh = fresh.cast::<u8>();
    // SAFETY: the new block holds `size >= len` bytes, so `length..len` lies inside it.
    unsafe { ptr::write_bytes(fresh.wrapping_add(buffer.length), 0, len - buffer.length) };
    buffer.data = fresh.cast();
    buffer.max = size;
    buffer.length = len;
    len
}

ffi_export! {
    /// Writes the `size` bytes at `input` to `out` in reverse order, or reverses `out` in
    /// place if `input` is null. Overlapping `input` and `out` behave as in OpenSSL, which
    /// copies byte by byte from the end of `out`.
    ///
    /// # Safety
    /// `out` is valid for `size` bytes of writes (and reads, when `input` is null), and
    /// `input` is null or valid for `size` bytes of reads. (OpenSSL crashes on a null `out`;
    /// this does nothing.)
    pub unsafe extern "C" fn BUF_reverse(out: *mut u8, input: *const u8, size: usize)
    where failure = (), library = ERR_LIB_BUF
    {
        if out.is_null() || size == 0 {
            return;
        }
        // Raw pointers rather than slices: C may pass overlapping ranges.
        if input.is_null() {
            for i in 0..size / 2 {
                let (low, high) = (out.wrapping_add(i), out.wrapping_add(size - 1 - i));
                // SAFETY: `i` and `size - 1 - i` are distinct offsets below `size`.
                unsafe { ptr::swap(low, high) };
            }
        } else {
            for i in 0..size {
                // SAFETY: `i < size`, and `input` holds `size` readable bytes.
                let byte = unsafe { input.wrapping_add(i).read() };
                // SAFETY: `size - 1 - i < size`, and `out` holds `size` writable bytes.
                unsafe { out.wrapping_add(size - 1 - i).write(byte) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::err;
    use core::slice;

    fn contents<'a>(buffer: *mut BUF_MEM) -> (&'a BUF_MEM, &'a [u8]) {
        // SAFETY: the tests pass live buffers.
        let buffer = unsafe { &*buffer };
        let data = if buffer.data.is_null() {
            &[][..]
        } else {
            // SAFETY: a buffer's data holds `max` bytes.
            unsafe { slice::from_raw_parts(buffer.data.cast::<u8>(), buffer.max) }
        };
        (buffer, data)
    }

    #[test]
    fn a_new_buffer_is_empty() {
        // SAFETY: always safe to call.
        let buffer = unsafe { BUF_MEM_new() };
        let (fields, _) = contents(buffer);
        assert_eq!((fields.length, fields.max, fields.flags), (0, 0, 0));
        assert!(fields.data.is_null());
        // SAFETY: frees the buffer just made.
        unsafe { BUF_MEM_free(buffer) };
        // SAFETY: always safe to call.
        let secure = unsafe { BUF_MEM_new_ex(BUF_MEM_FLAG_SECURE.cast_unsigned().into()) };
        assert_eq!(contents(secure).0.flags, 1);
        // SAFETY: frees the buffer just made; null does nothing.
        unsafe { BUF_MEM_free(secure) };
        // SAFETY: as above.
        unsafe { BUF_MEM_free(ptr::null_mut()) };
    }

    #[test]
    fn growing_allocates_four_thirds_and_zeroes_new_bytes() {
        for secure in [0, BUF_MEM_FLAG_SECURE.cast_unsigned().into()] {
            for clean in [false, true] {
                let grow_fn = if clean {
                    BUF_MEM_grow_clean
                } else {
                    BUF_MEM_grow
                };
                // SAFETY: always safe to call.
                let buffer = unsafe { BUF_MEM_new_ex(secure) };
                // SAFETY: `buffer` is live and used only here.
                assert_eq!(unsafe { grow_fn(buffer, 10) }, 10);
                let (fields, data) = contents(buffer);
                assert_eq!((fields.length, fields.max), (10, 16));
                assert_eq!(data[..10], [0; 10]);
                // SAFETY: `data` holds `max` bytes.
                unsafe { ptr::write_bytes(fields.data, 0x41, 10) };
                // Within `max`: no reallocation, new bytes zeroed.
                // SAFETY: as above.
                assert_eq!(unsafe { grow_fn(buffer, 14) }, 14);
                let (fields, data) = contents(buffer);
                assert_eq!((fields.length, fields.max), (14, 16));
                assert_eq!(data[..14], *b"AAAAAAAAAA\0\0\0\0");
                // Past `max`: the contents move along.
                // SAFETY: as above.
                assert_eq!(unsafe { grow_fn(buffer, 100) }, 100);
                let (fields, data) = contents(buffer);
                assert_eq!((fields.length, fields.max), (100, 136));
                assert_eq!(data[..10], *b"AAAAAAAAAA");
                assert_eq!(data[10..100], [0; 90]);
                // SAFETY: frees the buffer.
                unsafe { BUF_MEM_free(buffer) };
            }
        }
    }

    #[test]
    fn shrinking_keeps_memory_and_only_grow_clean_zeroes_it() {
        for (clean, kept) in [(false, 0x41), (true, 0)] {
            // SAFETY: always safe to call.
            let buffer = unsafe { BUF_MEM_new() };
            // SAFETY: `buffer` is live and used only here.
            unsafe { BUF_MEM_grow(buffer, 8) };
            let fields = contents(buffer).0;
            // SAFETY: `data` holds `max` bytes.
            unsafe { ptr::write_bytes(fields.data, 0x41, 8) };
            let grow_fn = if clean {
                BUF_MEM_grow_clean
            } else {
                BUF_MEM_grow
            };
            // SAFETY: as above.
            assert_eq!(unsafe { grow_fn(buffer, 3) }, 3);
            let (fields, data) = contents(buffer);
            assert_eq!((fields.length, fields.max), (3, 12));
            assert_eq!(data[..3], [0x41; 3]);
            assert_eq!(data[3..8], [kept; 5]);
            // SAFETY: frees the buffer.
            unsafe { BUF_MEM_free(buffer) };
        }
    }

    #[test]
    fn oversized_and_null_buffers_fail_with_an_error() {
        err::take_all();
        // SAFETY: always safe to call.
        let buffer = unsafe { BUF_MEM_new() };
        // SAFETY: `buffer` is live and used only here.
        let grown = unsafe { BUF_MEM_grow(buffer, LIMIT_BEFORE_EXPANSION + 1) };
        assert_eq!(grown, 0);
        assert_eq!(contents(buffer).0.length, 0);
        // SAFETY: null is allowed.
        assert_eq!(unsafe { BUF_MEM_grow_clean(ptr::null_mut(), 4) }, 0);
        let errors = err::take_all();
        let codes: Vec<_> = errors
            .iter()
            .map(|e| (e.code, e.function.as_str()))
            .collect();
        assert_eq!(
            codes,
            [
                (
                    err::pack(ERR_LIB_BUF, ERR_R_PASSED_INVALID_ARGUMENT),
                    "BUF_MEM_grow"
                ),
                (
                    err::pack(ERR_LIB_BUF, ERR_R_PASSED_NULL_PARAMETER),
                    "BUF_MEM_grow_clean"
                ),
            ]
        );
        // SAFETY: frees the buffer.
        unsafe { BUF_MEM_free(buffer) };
    }

    #[test]
    fn reverse_copies_backwards_or_in_place() {
        let input = *b"abcdef";
        let mut out = [0u8; 6];
        // SAFETY: both arrays hold six bytes.
        unsafe { BUF_reverse(out.as_mut_ptr(), input.as_ptr(), 6) };
        assert_eq!(out, *b"fedcba");
        let mut odd = *b"abcde";
        // SAFETY: `odd` holds five bytes.
        unsafe { BUF_reverse(odd.as_mut_ptr(), ptr::null(), 5) };
        assert_eq!(odd, *b"edcba");
        // SAFETY: nothing is touched for a zero size or a null output.
        unsafe { BUF_reverse(ptr::null_mut(), input.as_ptr(), 6) };
        // SAFETY: as above.
        unsafe { BUF_reverse(out.as_mut_ptr(), input.as_ptr(), 0) };
        assert_eq!(out, *b"fedcba");
    }
}
