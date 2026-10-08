//! The `CRYPTO_malloc` family (`crypto.h`, `OPENSSL_malloc(3)`): memory that crosses the C
//! boundary. Anything C may free with `OPENSSL_free` comes from here, never from Rust's
//! allocator, and anything C hands back to be freed returns here (security rule 6).
//!
//! - **The application's allocator.** `CRYPTO_set_mem_functions` replaces the allocator until
//!   the first allocation made with the default one; after that it returns 0. While replaced,
//!   every allocation goes to the application's functions, rustssl's own included, with a file
//!   and line as OpenSSL passes its own (`"rustssl"` and the Rust source line).
//! - **The defaults** are `malloc`, `realloc`, and `free`. `CRYPTO_get_mem_functions` reports
//!   them as `CRYPTO_malloc`, `CRYPTO_realloc`, and `CRYPTO_free`, as OpenSSL does.
//! - **Errors.** A zero-byte allocation returns null without an error. A failed `CRYPTO_malloc`
//!   raises `ERR_R_MALLOC_FAILURE` unless both file and line are null and 0, which OpenSSL's
//!   error queue uses for its own allocations. A failed `CRYPTO_realloc` raises nothing, as in
//!   OpenSSL.

use core::cell::Cell;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::panic::Location;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering, compiler_fence};

use rustssl_abi::{
    CRYPTO_free_fn, CRYPTO_malloc_fn, CRYPTO_realloc_fn, ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE,
};
use subtle::ConstantTimeEq;

use crate::err;
use crate::ffi::ffi_export;

type MallocFn = unsafe extern "C" fn(usize, *const c_char, c_int) -> *mut c_void;
type ReallocFn = unsafe extern "C" fn(*mut c_void, usize, *const c_char, c_int) -> *mut c_void;
type FreeFn = unsafe extern "C" fn(*mut c_void, *const c_char, c_int);

/// The application's functions from `CRYPTO_set_mem_functions`, null for the defaults. Each
/// holds only functions of its own type.
static MALLOC: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());
static REALLOC: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());
static FREE: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());

/// Whether `CRYPTO_set_mem_functions` may still replace the allocator.
static CUSTOMIZABLE: AtomicBool = AtomicBool::new(true);

thread_local! {
    /// Set while this thread runs one of the application's functions. If that function calls
    /// back into `CRYPTO_malloc` and the like (as it would if it *were* `CRYPTO_malloc`, reached
    /// through a different address), the call takes the default path instead of recursing.
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

/// The file rustssl's own allocations name.
pub(crate) const FILE: &CStr = c"rustssl";

/// The application's function in `slot`, unless this thread is already inside one.
fn hook(slot: &AtomicPtr<()>) -> Option<*mut ()> {
    let function = slot.load(Ordering::Acquire);
    if function.is_null() || IN_HOOK.with(Cell::get) {
        return None;
    }
    Some(function)
}

/// Runs `call` with [`IN_HOOK`] set.
fn in_hook<R>(call: impl FnOnce() -> R) -> R {
    IN_HOOK.with(|flag| flag.set(true));
    let result = call();
    IN_HOOK.with(|flag| flag.set(false));
    result
}

/// Ends `CRYPTO_set_mem_functions`, as OpenSSL's first allocation with the default allocator
/// does. Code that allocates where OpenSSL does but not through this module calls it too.
pub(crate) fn close_customization() {
    if MALLOC.load(Ordering::Acquire).is_null() && CUSTOMIZABLE.load(Ordering::Relaxed) {
        CUSTOMIZABLE.store(false, Ordering::Relaxed);
    }
}

/// `CRYPTO_malloc`.
pub(crate) fn malloc(num: usize, file: *const c_char, line: c_int) -> *mut c_void {
    let block = match hook(&MALLOC) {
        Some(function) => {
            // SAFETY: MALLOC only ever holds a `MallocFn` (see `CRYPTO_set_mem_functions`).
            let function = unsafe { core::mem::transmute::<*mut (), MallocFn>(function) };
            // SAFETY: the application's malloc takes any size and these arguments.
            let block = in_hook(|| unsafe { function(num, file, line) });
            if !block.is_null() || num == 0 {
                return block;
            }
            block
        }
        None => {
            if num == 0 {
                return ptr::null_mut();
            }
            close_customization();
            // SAFETY: malloc accepts any size and returns null or a fresh allocation.
            let block = unsafe { libc::malloc(num) };
            if !block.is_null() {
                return block;
            }
            block
        }
    };
    if !file.is_null() || line != 0 {
        // As OpenSSL's: the caller's file and line, and no function.
        // SAFETY: CRYPTO_malloc's callers pass null or a NUL-terminated file name.
        let file = (!file.is_null()).then(|| unsafe { CStr::from_ptr(file) }.to_bytes());
        err::raise_from(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE, file, line, None);
    }
    block
}

/// `CRYPTO_zalloc`.
pub(crate) fn zalloc(num: usize, file: *const c_char, line: c_int) -> *mut c_void {
    let block = malloc(num, file, line);
    if !block.is_null() {
        // SAFETY: the block holds `num` bytes.
        unsafe { ptr::write_bytes(block.cast::<u8>(), 0, num) };
    }
    block
}

/// `CRYPTO_realloc`.
///
/// # Safety
/// `block` is null or a live block from this allocator.
unsafe fn realloc(block: *mut c_void, num: usize, file: *const c_char, line: c_int) -> *mut c_void {
    if let Some(function) = hook(&REALLOC) {
        // SAFETY: REALLOC only ever holds a `ReallocFn`.
        let function = unsafe { core::mem::transmute::<*mut (), ReallocFn>(function) };
        // SAFETY: the caller passes null or a block from the application's allocator.
        return in_hook(|| unsafe { function(block, num, file, line) });
    }
    if block.is_null() {
        return malloc(num, file, line);
    }
    if num == 0 {
        // SAFETY: the caller passes a live block from this allocator.
        unsafe { free(block, file, line) };
        return ptr::null_mut();
    }
    // SAFETY: the caller passes a live block, which the default allocator got from malloc.
    unsafe { libc::realloc(block, num) }
}

/// `CRYPTO_free`.
///
/// # Safety
/// `block` is null or a live block from this allocator, not used afterwards.
pub(crate) unsafe fn free(block: *mut c_void, file: *const c_char, line: c_int) {
    if let Some(function) = hook(&FREE) {
        // SAFETY: FREE only ever holds a `FreeFn`.
        let function = unsafe { core::mem::transmute::<*mut (), FreeFn>(function) };
        // SAFETY: the caller passes null or a block from the application's allocator.
        in_hook(|| unsafe { function(block, file, line) });
        return;
    }
    // SAFETY: the caller passes null or a live block from malloc.
    unsafe { libc::free(block) }
}

/// `CRYPTO_clear_free`.
///
/// # Safety
/// `block` is null or a live block from this allocator of at least `num` bytes, not used
/// afterwards.
unsafe fn clear_free(block: *mut c_void, num: usize, file: *const c_char, line: c_int) {
    if block.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `num` writable bytes at `block`.
    unsafe { cleanse(block, num) };
    // SAFETY: as above.
    unsafe { free(block, file, line) };
}

/// `CRYPTO_clear_realloc`: the old contents never survive anywhere but in the result.
/// Shrinking zeroes the tail in place; growing moves to a new block and clears the old one.
///
/// # Safety
/// `block` is null or a live block from this allocator of at least `old` bytes.
unsafe fn clear_realloc(
    block: *mut c_void,
    old: usize,
    num: usize,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    if block.is_null() {
        return malloc(num, file, line);
    }
    if num == 0 {
        // SAFETY: the caller passes a live block of `old` bytes.
        unsafe { clear_free(block, old, file, line) };
        return ptr::null_mut();
    }
    if num < old {
        // SAFETY: bytes `num..old` lie inside the caller's block of `old` bytes.
        unsafe { cleanse(block.cast::<u8>().wrapping_add(num).cast(), old - num) };
        return block;
    }
    let fresh = malloc(num, file, line);
    if !fresh.is_null() {
        // SAFETY: both blocks hold at least `old` bytes and are distinct allocations.
        unsafe { ptr::copy_nonoverlapping(block.cast::<u8>(), fresh.cast::<u8>(), old) };
        // SAFETY: the caller passes a live block of `old` bytes.
        unsafe { clear_free(block, old, file, line) };
    }
    fresh
}

/// `CRYPTO_aligned_alloc`. Without the application's malloc, Linux uses `posix_memalign` and
/// macOS over-allocates and rounds up, as OpenSSL's build does on each, so a bad alignment
/// behaves as the reference's does on the same platform.
///
/// # Safety
/// `freeptr` is valid for a write.
unsafe fn aligned_alloc(
    num: usize,
    alignment: usize,
    freeptr: *mut *mut c_void,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    // SAFETY: the caller guarantees `freeptr` is writable.
    unsafe { freeptr.write(ptr::null_mut()) };
    if cfg!(target_os = "linux") && MALLOC.load(Ordering::Acquire).is_null() {
        let mut block = ptr::null_mut();
        // SAFETY: posix_memalign writes `block` only on success and checks the alignment.
        if unsafe { libc::posix_memalign(&mut block, alignment, num) } != 0 {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        unsafe { freeptr.write(block) };
        return block;
    }
    // OpenSSL adds without checking, so a huge `num` wraps to a small block; this fails instead
    // (docs/DEVIATIONS.md).
    let Some(total) = num.checked_add(alignment) else {
        return ptr::null_mut();
    };
    let block = malloc(total, file, line);
    if block.is_null() {
        return block;
    }
    // SAFETY: as above.
    unsafe { freeptr.write(block) };
    // Round up to the alignment, which callers must make a power of two. The arithmetic wraps
    // as OpenSSL's does, so alignment 0 gives null.
    let mask = alignment.wrapping_sub(1);
    block.map_addr(|address| address.wrapping_add(mask) & !mask)
}

/// Zeroes `len` bytes at `block` with volatile writes the compiler can't remove, like
/// `OPENSSL_cleanse`: bytes up to an 8-byte boundary, then words, then the tail.
///
/// # Safety
/// `block` is valid for `len` bytes of writes.
pub(crate) unsafe fn cleanse(block: *mut c_void, len: usize) {
    let mut at = block.cast::<u8>();
    let mut left = len;
    while left > 0 && at.addr() % size_of::<u64>() != 0 {
        // SAFETY: `left` bytes from `at` lie inside the caller's `len` writable bytes.
        unsafe { at.write_volatile(0) };
        at = at.wrapping_add(1);
        left -= 1;
    }
    while left >= size_of::<u64>() {
        // SAFETY: as above, and `at` is now 8-byte aligned.
        unsafe { at.cast::<u64>().write_volatile(0) };
        at = at.wrapping_add(size_of::<u64>());
        left -= size_of::<u64>();
    }
    while left > 0 {
        // SAFETY: as above.
        unsafe { at.write_volatile(0) };
        at = at.wrapping_add(1);
        left -= 1;
    }
    compiler_fence(Ordering::SeqCst);
}

/// The calling Rust source line, as a C `int`, for allocations rustssl makes itself.
#[track_caller]
pub(crate) fn caller_line() -> c_int {
    c_int::try_from(Location::caller().line()).unwrap_or(c_int::MAX)
}

/// Allocates `size` bytes for rustssl itself, like `OPENSSL_malloc`.
#[track_caller]
pub(crate) fn alloc(size: usize) -> *mut c_void {
    malloc(size, FILE.as_ptr(), caller_line())
}

/// Like [`alloc`], zeroed, like `OPENSSL_zalloc`.
#[track_caller]
pub(crate) fn alloc_zeroed(size: usize) -> *mut c_void {
    zalloc(size, FILE.as_ptr(), caller_line())
}

/// Resizes `block` to `size` bytes, like `OPENSSL_realloc`.
///
/// # Safety
/// `block` is null or a live block from this allocator.
#[track_caller]
pub(crate) unsafe fn resize(block: *mut c_void, size: usize) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    unsafe { realloc(block, size, FILE.as_ptr(), caller_line()) }
}

/// Resizes `block` from `old` to `size` bytes, like `OPENSSL_clear_realloc`.
///
/// # Safety
/// `block` is null or a live block from this allocator of at least `old` bytes.
#[track_caller]
pub(crate) unsafe fn resize_clean(block: *mut c_void, old: usize, size: usize) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    unsafe { clear_realloc(block, old, size, FILE.as_ptr(), caller_line()) }
}

/// Frees `block`, like `OPENSSL_free`.
///
/// # Safety
/// `block` is null or a live block from this allocator, not used afterwards.
#[track_caller]
pub(crate) unsafe fn release(block: *mut c_void) {
    // SAFETY: the caller's guarantee.
    unsafe { free(block, FILE.as_ptr(), caller_line()) }
}

/// Zeroes `len` bytes of `block` and frees it, like `OPENSSL_clear_free`.
///
/// # Safety
/// `block` is null or a live block from this allocator of at least `len` bytes, not used
/// afterwards.
#[track_caller]
pub(crate) unsafe fn release_clean(block: *mut c_void, len: usize) {
    // SAFETY: the caller's guarantee.
    unsafe { clear_free(block, len, FILE.as_ptr(), caller_line()) }
}

ffi_export! {
    /// Replaces the allocator with the application's functions, each of which may be null to
    /// keep the current one. Returns 0, changing nothing, once the default allocator has
    /// allocated.
    ///
    /// # Safety
    /// Each function behaves like its C library counterpart.
    pub unsafe extern "C" fn CRYPTO_set_mem_functions(
        malloc_fn: CRYPTO_malloc_fn,
        realloc_fn: CRYPTO_realloc_fn,
        free_fn: CRYPTO_free_fn,
    ) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if !CUSTOMIZABLE.load(Ordering::Relaxed) {
            return 0;
        }
        // Passing back the defaults (as CRYPTO_get_mem_functions reports them) restores them.
        if let Some(function) = malloc_fn {
            let ours = core::ptr::fn_addr_eq(function, CRYPTO_malloc as MallocFn);
            MALLOC.store(if ours { ptr::null_mut() } else { function as *mut () }, Ordering::Release);
        }
        if let Some(function) = realloc_fn {
            let ours = core::ptr::fn_addr_eq(function, CRYPTO_realloc as ReallocFn);
            REALLOC.store(if ours { ptr::null_mut() } else { function as *mut () }, Ordering::Release);
        }
        if let Some(function) = free_fn {
            let ours = core::ptr::fn_addr_eq(function, CRYPTO_free as FreeFn);
            FREE.store(if ours { ptr::null_mut() } else { function as *mut () }, Ordering::Release);
        }
        1
    }
}

ffi_export! {
    /// Reports the allocator's functions through each non-null pointer.
    ///
    /// # Safety
    /// Each pointer is null or valid for a write.
    pub unsafe extern "C" fn CRYPTO_get_mem_functions(
        malloc_fn: *mut CRYPTO_malloc_fn,
        realloc_fn: *mut CRYPTO_realloc_fn,
        free_fn: *mut CRYPTO_free_fn,
    )
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let current = |slot: &AtomicPtr<()>| {
            let function = slot.load(Ordering::Acquire);
            (!function.is_null()).then_some(function)
        };
        if !malloc_fn.is_null() {
            let function = match current(&MALLOC) {
                // SAFETY: MALLOC only ever holds a `MallocFn`.
                Some(function) => unsafe { core::mem::transmute::<*mut (), MallocFn>(function) },
                None => CRYPTO_malloc,
            };
            // SAFETY: the caller passes a writable pointer.
            unsafe { malloc_fn.write(Some(function)) };
        }
        if !realloc_fn.is_null() {
            let function = match current(&REALLOC) {
                // SAFETY: REALLOC only ever holds a `ReallocFn`.
                Some(function) => unsafe { core::mem::transmute::<*mut (), ReallocFn>(function) },
                None => CRYPTO_realloc,
            };
            // SAFETY: as above.
            unsafe { realloc_fn.write(Some(function)) };
        }
        if !free_fn.is_null() {
            let function = match current(&FREE) {
                // SAFETY: FREE only ever holds a `FreeFn`.
                Some(function) => unsafe { core::mem::transmute::<*mut (), FreeFn>(function) },
                None => CRYPTO_free,
            };
            // SAFETY: as above.
            unsafe { free_fn.write(Some(function)) };
        }
    }
}

ffi_export! {
    /// Allocates `num` bytes. Zero bytes gives null without an error.
    ///
    /// # Safety
    /// `file` is null or a NUL-terminated string the allocator may keep.
    pub unsafe extern "C" fn CRYPTO_malloc(num: usize, file: *const c_char, line: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        malloc(num, file, line)
    }
}

ffi_export! {
    /// Allocates `num` zeroed bytes.
    ///
    /// # Safety
    /// As for `CRYPTO_malloc`.
    pub unsafe extern "C" fn CRYPTO_zalloc(num: usize, file: *const c_char, line: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        zalloc(num, file, line)
    }
}

ffi_export! {
    /// Allocates `num` bytes aligned to `alignment`, a power of two, and stores the block to
    /// pass to `OPENSSL_free` in `*freeptr`.
    ///
    /// # Safety
    /// `freeptr` is valid for a write.
    pub unsafe extern "C" fn CRYPTO_aligned_alloc(
        num: usize,
        alignment: usize,
        freeptr: *mut *mut c_void,
        file: *const c_char,
        line: c_int,
    ) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { aligned_alloc(num, alignment, freeptr, file, line) }
    }
}

ffi_export! {
    /// Resizes `addr` to `num` bytes; a null `addr` allocates, and zero bytes frees.
    ///
    /// # Safety
    /// `addr` is null or a live block from this allocator.
    pub unsafe extern "C" fn CRYPTO_realloc(
        addr: *mut c_void,
        num: usize,
        file: *const c_char,
        line: c_int,
    ) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { realloc(addr, num, file, line) }
    }
}

ffi_export! {
    /// Resizes `addr` from `old_num` to `num` bytes without leaving the old contents anywhere
    /// else in memory.
    ///
    /// # Safety
    /// `addr` is null or a live block from this allocator of at least `old_num` bytes.
    pub unsafe extern "C" fn CRYPTO_clear_realloc(
        addr: *mut c_void,
        old_num: usize,
        num: usize,
        file: *const c_char,
        line: c_int,
    ) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { clear_realloc(addr, old_num, num, file, line) }
    }
}

ffi_export! {
    /// Frees `ptr`.
    ///
    /// # Safety
    /// `ptr` is null or a live block from this allocator, not used afterwards.
    pub unsafe extern "C" fn CRYPTO_free(ptr: *mut c_void, file: *const c_char, line: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { free(ptr, file, line) }
    }
}

ffi_export! {
    /// Zeroes `num` bytes of `ptr` and frees it. Null does nothing.
    ///
    /// # Safety
    /// `ptr` is null or a live block from this allocator of at least `num` bytes, not used
    /// afterwards.
    pub unsafe extern "C" fn CRYPTO_clear_free(
        ptr: *mut c_void,
        num: usize,
        file: *const c_char,
        line: c_int,
    )
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { clear_free(ptr, num, file, line) }
    }
}

ffi_export! {
    /// Zeroes `len` bytes at `ptr` in a way the compiler can't remove. A null `ptr` does
    /// nothing (OpenSSL's would crash).
    ///
    /// # Safety
    /// `ptr` is null or valid for `len` bytes of writes.
    pub unsafe extern "C" fn OPENSSL_cleanse(ptr: *mut c_void, len: usize)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if !ptr.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { cleanse(ptr, len) };
        }
    }
}

ffi_export! {
    /// Compares `len` bytes in time that depends only on `len`: 0 if they're equal, 1 if not,
    /// as OpenSSL's assembly versions return. A null pointer with a nonzero length compares
    /// unequal (OpenSSL's would crash).
    ///
    /// # Safety
    /// `in_a` and `in_b` are each null or valid for `len` bytes of reads.
    pub unsafe extern "C" fn CRYPTO_memcmp(in_a: *const c_void, in_b: *const c_void, len: usize) -> c_int
    where failure = 1, library = ERR_LIB_CRYPTO
    {
        if len == 0 {
            return 0;
        }
        if in_a.is_null() || in_b.is_null() {
            return 1;
        }
        // SAFETY: `in_a` is non-null and valid for `len` bytes of reads (caller's guarantee).
        let a = unsafe { core::slice::from_raw_parts(in_a.cast::<u8>(), len) };
        // SAFETY: as for `in_a`.
        let b = unsafe { core::slice::from_raw_parts(in_b.cast::<u8>(), len) };
        c_int::from((!a.ct_eq(b)).unwrap_u8())
    }
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
        assert!(alloc_zeroed(0).is_null());
        assert!(crate::err::take_all().is_empty());
    }

    #[test]
    fn failures_raise_unless_the_location_is_empty() {
        crate::err::take_all();
        assert!(malloc(usize::MAX, ptr::null(), 0).is_null());
        assert!(crate::err::take_all().is_empty());
        assert!(alloc(usize::MAX).is_null());
        assert_eq!(crate::err::take_all().len(), 1);
    }

    #[test]
    fn zalloc_zeroes_and_resize_keeps_the_contents() {
        let block = alloc_zeroed(16);
        assert_eq!(bytes(block, 16), [0; 16]);
        fill(block, 16, 0xab);
        // SAFETY: `block` is a live 16-byte allocation from this module.
        let block = unsafe { resize(block, 64) };
        assert_eq!(bytes(block, 16), [0xab; 16]);
        // SAFETY: `block` is live; resizing to zero frees it.
        let freed = unsafe { resize(block, 0) };
        assert!(freed.is_null());
    }

    #[test]
    fn resize_clean_shrinks_in_place_and_grows_into_a_new_block() {
        let block = alloc(32);
        fill(block, 32, 0x5a);
        // SAFETY: `block` is a live 32-byte allocation from this module.
        let same = unsafe { resize_clean(block, 32, 8) };
        assert_eq!(same, block);
        assert_eq!(bytes(block, 8), [0x5a; 8]);
        assert_eq!(bytes(block, 32)[8..], [0; 24]);
        // SAFETY: the shrunk block is still the same 32-byte allocation.
        let grown = unsafe { resize_clean(block, 32, 128) };
        assert_eq!(bytes(grown, 8), [0x5a; 8]);
        // SAFETY: `grown` is a live 128-byte allocation, not used afterwards.
        unsafe { release_clean(grown, 128) };
        // SAFETY: null does nothing.
        unsafe { release_clean(ptr::null_mut(), 10) };
        // SAFETY: as above.
        unsafe { release(ptr::null_mut()) };
    }

    #[test]
    fn cleanse_zeroes_exactly_the_range() {
        for start in 0..9 {
            for len in [0, 1, 7, 8, 9, 15, 16, 17, 31] {
                let mut buffer = [0xffu8; 48];
                // SAFETY: `start + len` stays inside the 48-byte buffer.
                unsafe { cleanse(buffer.as_mut_ptr().wrapping_add(start).cast(), len) };
                assert!(buffer[..start].iter().all(|b| *b == 0xff));
                assert!(buffer[start..start + len].iter().all(|b| *b == 0));
                assert!(buffer[start + len..].iter().all(|b| *b == 0xff));
            }
        }
    }

    #[test]
    fn cleanse_null_does_nothing() {
        // SAFETY: a null pointer is skipped; OpenSSL's would write to it (docs/DEVIATIONS.md).
        unsafe { OPENSSL_cleanse(ptr::null_mut(), 16) };
    }

    #[test]
    fn memcmp_returns_zero_or_one() {
        let compare = |a: &[u8], b: &[u8]| {
            // SAFETY: both slices hold `a.len()` bytes.
            unsafe { CRYPTO_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) }
        };
        assert_eq!(compare(b"abc", b"abc"), 0);
        assert_eq!(compare(b"abc", b"abd"), 1);
        assert_eq!(compare(&[0; 16], &[0xff; 16]), 1);
        assert_eq!(compare(b"", b""), 0);
        // SAFETY: a zero length reads nothing.
        assert_eq!(unsafe { CRYPTO_memcmp(ptr::null(), ptr::null(), 0) }, 0);
        // SAFETY: null pointers are handled without being read.
        let unequal = unsafe { CRYPTO_memcmp(ptr::null(), b"a".as_ptr().cast(), 1) };
        assert_eq!(unequal, 1);
    }

    #[test]
    fn aligned_allocations() {
        for alignment in [8, 16, 64, 4096] {
            let mut freeptr = ptr::null_mut();
            // SAFETY: `freeptr` is writable.
            let block = unsafe { aligned_alloc(100, alignment, &mut freeptr, FILE.as_ptr(), 1) };
            assert!(!block.is_null());
            assert_eq!(block.addr() % alignment, 0);
            assert!(block.addr() >= freeptr.addr());
            // SAFETY: `freeptr` is the block to free.
            unsafe { release(freeptr) };
        }
        // On Linux the size goes to posix_memalign, which Miri can't fail gracefully: it stops
        // with "resource exhaustion" instead of returning ENOMEM.
        if cfg!(miri) && cfg!(target_os = "linux") {
            return;
        }
        let mut freeptr = ptr::null_mut();
        // SAFETY: as above; the size overflows when the alignment is added.
        let block = unsafe { aligned_alloc(usize::MAX - 8, 64, &mut freeptr, FILE.as_ptr(), 1) };
        assert!(block.is_null() && freeptr.is_null());
    }
}
