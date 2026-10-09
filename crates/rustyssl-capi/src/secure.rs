//! The secure heap (`CRYPTO_secure_malloc(3)`): one arena, set up by
//! `CRYPTO_secure_malloc_init`, for secrets that should stay out of swap and core dumps.
//!
//! The arena sits between two inaccessible guard pages and is locked into memory (`mlock`, on
//! Linux `mlock2` with `MLOCK_ONFAULT`) and, on Linux, left out of core dumps
//! (`MADV_DONTDUMP`). Initialization returns 2 instead of 1 when any of that fails, exactly as
//! OpenSSL's does. Blocks are handed out by [`buddy::Buddy`], which places them as OpenSSL does,
//! and are zeroed when freed, so a new block is always zero.
//!
//! Before initialization, and for memory that isn't in the arena, the functions fall back to
//! the ordinary allocator. Freeing a pointer inside the arena that isn't an allocated block
//! aborts, as OpenSSL's assertions do.

mod buddy;

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use rustyssl_abi::{CRYPTO_R_SECURE_MALLOC_FAILURE, ERR_LIB_CRYPTO, ERR_R_CRYPTO_LIB};

use self::buddy::Buddy;
use crate::err;
use crate::ffi::{die, ffi_export};
use crate::mem;

/// The arena: `size` bytes at `start`, inside a mapping of `map_size` bytes at `map`.
struct Arena {
    map: NonNull<c_void>,
    map_size: usize,
    start: NonNull<u8>,
    size: usize,
}

// SAFETY: the arena is process-wide memory that no thread owns; `HEAP`'s mutex serializes its
// bookkeeping, and each block belongs to whoever it was handed to.
unsafe impl Send for Arena {}

impl Arena {
    /// Maps `size` bytes between two guard pages and locks them, as OpenSSL's `sh_init` does.
    /// Returns 1 with the arena, 2 if a guard page, the lock, or (on Linux) the core-dump
    /// exclusion failed, or `None` if the memory can't be mapped.
    fn map(size: usize) -> Option<(Self, c_int)> {
        // SAFETY: sysconf has no preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page = usize::try_from(page)
            .ok()
            .filter(|p| *p >= 1)
            .unwrap_or(4096);
        let map_size = page.checked_add(size)?.checked_add(page)?;
        // SAFETY: an anonymous private mapping with no address hint has no preconditions.
        let map = unsafe {
            libc::mmap(
                ptr::null_mut(),
                map_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if map == libc::MAP_FAILED {
            return None;
        }
        let map = NonNull::new(map)?;
        let start = NonNull::new(map.as_ptr().cast::<u8>().wrapping_add(page))?;
        let arena = Self {
            map,
            map_size,
            start,
            size,
        };

        let mut result = 1;
        // SAFETY: the first page of the mapping is the leading guard page.
        if unsafe { libc::mprotect(map.as_ptr(), page, libc::PROT_NONE) } < 0 {
            result = 2;
        }
        // The trailing guard page starts at the page boundary after the arena. mmap rounds the
        // mapping up to whole pages, so it lies inside it even when the arena is smaller than a
        // page.
        let trailing = (page + size + (page - 1)) & !(page - 1);
        let guard = map.as_ptr().cast::<u8>().wrapping_add(trailing);
        // SAFETY: as above, the page at `guard` is part of the mapping.
        if unsafe { libc::mprotect(guard.cast(), page, libc::PROT_NONE) } < 0 {
            result = 2;
        }
        if !arena.lock() {
            result = 2;
        }
        Some((arena, result))
    }

    /// Locks the arena into memory and, on Linux, out of core dumps.
    #[cfg(target_os = "linux")]
    fn lock(&self) -> bool {
        let start = self.start.as_ptr().cast::<c_void>();
        // SAFETY: the arena is mapped; MLOCK_ONFAULT locks its pages as they are first touched.
        let mut locked =
            unsafe { libc::syscall(libc::SYS_mlock2, start, self.size, libc::MLOCK_ONFAULT) } == 0;
        if !locked && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS) {
            // SAFETY: as above; kernels before 4.4 have no mlock2.
            locked = unsafe { libc::mlock(start, self.size) } == 0;
        }
        // SAFETY: the arena is mapped.
        let undumped = unsafe { libc::madvise(start, self.size, libc::MADV_DONTDUMP) } == 0;
        locked && undumped
    }

    /// Locks the arena into memory.
    #[cfg(not(target_os = "linux"))]
    fn lock(&self) -> bool {
        // SAFETY: the arena is mapped.
        unsafe { libc::mlock(self.start.as_ptr().cast(), self.size) == 0 }
    }

    /// The block at `offset`.
    fn block(&self, offset: usize) -> *mut c_void {
        self.start.as_ptr().wrapping_add(offset).cast()
    }

    /// The offset of `block` in the arena, if it's inside it.
    fn offset(&self, block: *const c_void) -> Option<usize> {
        let offset = block.addr().checked_sub(self.start.addr().get())?;
        (offset < self.size).then_some(offset)
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        // SAFETY: `map` and `map_size` describe this arena's own mapping, which nothing uses
        // any more (the heap is dropped only once every block has been freed).
        unsafe { libc::munmap(self.map.as_ptr(), self.map_size) };
    }
}

struct Heap {
    arena: Arena,
    buddy: Buddy,
    /// The bytes of the blocks handed out (`CRYPTO_secure_used`).
    used: usize,
}

static HEAP: Mutex<Option<Heap>> = Mutex::new(None);

/// Whether the heap is set up, readable without the lock.
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// The arena's address range, for `CRYPTO_secure_allocated`, which takes no lock.
static START: AtomicUsize = AtomicUsize::new(0);
static END: AtomicUsize = AtomicUsize::new(0);

/// Whether `block` lies in the arena.
pub(crate) fn in_arena(block: *const c_void) -> bool {
    INITIALIZED.load(Ordering::Acquire)
        && (START.load(Ordering::Acquire)..END.load(Ordering::Acquire)).contains(&block.addr())
}

/// `CRYPTO_secure_malloc`.
fn secure_malloc(num: usize, file: *const c_char, line: c_int) -> *mut c_void {
    if !INITIALIZED.load(Ordering::Acquire) {
        return mem::malloc(num, file, line);
    }
    let reason = match HEAP.lock() {
        Ok(mut heap) => match heap.as_mut() {
            Some(heap) => match heap.buddy.allocate(num) {
                Some(offset) => {
                    heap.used += heap.buddy.size_of(offset).unwrap_or(0);
                    return heap.arena.block(offset);
                }
                None => CRYPTO_R_SECURE_MALLOC_FAILURE,
            },
            // The heap was torn down after the check above.
            None => return mem::malloc(num, file, line),
        },
        Err(_) => ERR_R_CRYPTO_LIB,
    };
    if !file.is_null() || line != 0 {
        // As OpenSSL's: the caller's file and line, and no function.
        // SAFETY: CRYPTO_secure_malloc's callers pass null or a NUL-terminated file name.
        let file = (!file.is_null()).then(|| unsafe { CStr::from_ptr(file) }.to_bytes());
        err::raise_from(ERR_LIB_CRYPTO, reason, file, line, None);
    }
    ptr::null_mut()
}

/// `CRYPTO_secure_free` (`clear` is `None`) and `CRYPTO_secure_clear_free` (`Some(num)`).
///
/// # Safety
/// `block` is null or a live block from this heap or from the ordinary allocator (of at least
/// `num` bytes for `Some(num)`), not used afterwards.
unsafe fn secure_free(block: *mut c_void, clear: Option<usize>, file: *const c_char, line: c_int) {
    if block.is_null() {
        return;
    }
    if !in_arena(block) {
        if let Some(num) = clear {
            // SAFETY: the caller guarantees `num` writable bytes.
            unsafe { mem::cleanse(block, num) };
        }
        // SAFETY: a block outside the arena came from the ordinary allocator.
        unsafe { mem::free(block, file, line) };
        return;
    }
    let Ok(mut heap) = HEAP.lock() else {
        return;
    };
    let Some(heap) = heap.as_mut() else {
        return;
    };
    let Some(offset) = heap.arena.offset(block) else {
        return;
    };
    let size = match heap.buddy.allocated_size(offset) {
        Ok(size) => size,
        Err(buddy::Misuse::NotABlock) => {
            die("WITHIN_ARENA(ptr) && sh_testbit(ptr, list, sh.bittable)")
        }
        Err(buddy::Misuse::DoubleFree) => die("TESTBIT(table, bit)"),
    };
    // SAFETY: the block holds `size` bytes of the arena, which nothing else uses.
    unsafe { mem::cleanse(block, size) };
    heap.used = heap.used.saturating_sub(size);
    if heap.buddy.free(offset).is_err() {
        die("TESTBIT(table, bit)");
    }
}

/// Allocates `size` bytes in the secure heap for rustyssl itself, like
/// `OPENSSL_secure_malloc`.
#[track_caller]
pub(crate) fn alloc(size: usize) -> *mut c_void {
    secure_malloc(size, mem::FILE.as_ptr(), mem::caller_line())
}

/// Like [`alloc`], zeroed, like `OPENSSL_secure_zalloc`: a secure block is zero already, and
/// without a secure heap the ordinary allocator's memory is zeroed.
#[track_caller]
pub(crate) fn alloc_zeroed(size: usize) -> *mut c_void {
    if INITIALIZED.load(Ordering::Acquire) {
        alloc(size)
    } else {
        mem::alloc_zeroed(size)
    }
}

/// Zeroes and frees a block from [`alloc`] or the ordinary allocator, like
/// `OPENSSL_secure_clear_free`: a secure block is zeroed whole, any other for `len` bytes.
///
/// # Safety
/// `block` is null or a live block of at least `len` bytes from either allocator, not used
/// afterwards.
#[track_caller]
pub(crate) unsafe fn release_clean(block: *mut c_void, len: usize) {
    // SAFETY: the caller's guarantee.
    unsafe { secure_free(block, Some(len), mem::FILE.as_ptr(), mem::caller_line()) }
}

ffi_export! {
    /// Sets up a secure heap of `size` bytes, a power of two, in blocks of at least `minsize`
    /// bytes (a power of two, or 16 or less for the smallest). Returns 1, or 2 if the arena
    /// couldn't be fully protected; 0 if a heap exists, the sizes give fewer than four blocks,
    /// or the memory can't be mapped. A `size` or `minsize` that isn't a power of two aborts.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn CRYPTO_secure_malloc_init(size: usize, minsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Ok(mut heap) = HEAP.lock() else {
            return 0;
        };
        if heap.is_some() {
            return 0;
        }
        if size == 0 {
            die("size > 0");
        }
        if !size.is_power_of_two() {
            die("(size & (size - 1)) == 0");
        }
        // OpenSSL's smallest block holds its free-list links, two pointers.
        let links = 2 * size_of::<usize>();
        let minsize = if minsize <= links {
            links.next_power_of_two()
        } else if minsize.is_power_of_two() {
            minsize
        } else {
            die("(minsize & (minsize - 1)) == 0")
        };
        let Some(buddy) = Buddy::new(size, minsize) else {
            return 0;
        };
        // OpenSSL allocates its free lists and bit tables at this point.
        mem::close_customization();
        let Some((arena, result)) = Arena::map(size) else {
            return 0;
        };
        START.store(arena.start.addr().get(), Ordering::Release);
        END.store(arena.start.addr().get() + size, Ordering::Release);
        *heap = Some(Heap {
            arena,
            buddy,
            used: 0,
        });
        INITIALIZED.store(true, Ordering::Release);
        result
    }
}

ffi_export! {
    /// Tears down the secure heap if no block is in use and returns 1; returns 0 otherwise.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn CRYPTO_secure_malloc_done() -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Ok(mut heap) = HEAP.lock() else {
            return 0;
        };
        if heap.as_ref().is_some_and(|heap| heap.used != 0) {
            return 0;
        }
        INITIALIZED.store(false, Ordering::Release);
        START.store(0, Ordering::Release);
        END.store(0, Ordering::Release);
        *heap = None;
        1
    }
}

ffi_export! {
    /// Whether the secure heap is set up.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn CRYPTO_secure_malloc_initialized() -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        c_int::from(INITIALIZED.load(Ordering::Acquire))
    }
}

ffi_export! {
    /// Allocates `num` zeroed bytes in the secure heap (zero bytes get its smallest block), or
    /// with `CRYPTO_malloc` if there's no secure heap. Null if the heap has no room.
    ///
    /// # Safety
    /// `file` is null or a NUL-terminated string.
    pub unsafe extern "C" fn CRYPTO_secure_malloc(num: usize, file: *const c_char, line: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        secure_malloc(num, file, line)
    }
}

ffi_export! {
    /// Like `CRYPTO_secure_malloc` (whose blocks are already zero), or `CRYPTO_zalloc` if
    /// there's no secure heap.
    ///
    /// # Safety
    /// `file` is null or a NUL-terminated string.
    pub unsafe extern "C" fn CRYPTO_secure_zalloc(num: usize, file: *const c_char, line: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        if INITIALIZED.load(Ordering::Acquire) {
            secure_malloc(num, file, line)
        } else {
            mem::zalloc(num, file, line)
        }
    }
}

ffi_export! {
    /// Zeroes and frees a secure-heap block, or frees memory from the ordinary allocator.
    ///
    /// # Safety
    /// `ptr` is null or a live block from either allocator, not used afterwards.
    pub unsafe extern "C" fn CRYPTO_secure_free(ptr: *mut c_void, file: *const c_char, line: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { secure_free(ptr, None, file, line) }
    }
}

ffi_export! {
    /// Like `CRYPTO_secure_free`, zeroing `num` bytes first if the block isn't in the secure
    /// heap (a secure block is always zeroed whole).
    ///
    /// # Safety
    /// `ptr` is null or a live block of at least `num` bytes from either allocator, not used
    /// afterwards.
    pub unsafe extern "C" fn CRYPTO_secure_clear_free(
        ptr: *mut c_void,
        num: usize,
        file: *const c_char,
        line: c_int,
    )
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { secure_free(ptr, Some(num), file, line) }
    }
}

ffi_export! {
    /// Whether `ptr` points into the secure heap.
    ///
    /// # Safety
    /// No preconditions; `ptr` is only compared.
    pub unsafe extern "C" fn CRYPTO_secure_allocated(ptr: *const c_void) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        c_int::from(in_arena(ptr))
    }
}

ffi_export! {
    /// The bytes of secure-heap blocks in use, counting each block's full size.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn CRYPTO_secure_used() -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        HEAP.lock().ok().and_then(|heap| heap.as_ref().map(|heap| heap.used)).unwrap_or(0)
    }
}

ffi_export! {
    /// The full size of the secure-heap block at `ptr`, or 0 if there's no secure heap. A
    /// pointer that isn't the start of a block in the heap aborts.
    ///
    /// # Safety
    /// No preconditions; `ptr` is only compared.
    pub unsafe extern "C" fn CRYPTO_secure_actual_size(ptr: *mut c_void) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Ok(heap) = HEAP.lock() else {
            return 0;
        };
        let Some(heap) = heap.as_ref() else {
            return 0;
        };
        let Some(offset) = heap.arena.offset(ptr) else {
            die("WITHIN_ARENA(ptr)");
        };
        match heap.buddy.size_of(offset) {
            Ok(size) => size,
            Err(_) => die("sh_testbit(ptr, list, sh.bittable)"),
        }
    }
}
