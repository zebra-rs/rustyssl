//! Secret storage in the secure heap (docs/adr/0005-secure-heap.md).
//!
//! OpenSSL keeps private keys and secure `BIGNUM`s in the secure heap when it's set up
//! (`BN_secure_new`, `OPENSSL_secure_malloc` in the key managers). rustyssl's secrets are Rust
//! values, so the library's global allocator places a thread's allocations in the arena while
//! that thread is inside [`scope`], which wraps the operations OpenSSL makes secure: key
//! generation, import, loading and copying, and stores into a secure `BIGNUM`. Outside a scope
//! every allocation goes to the system allocator.
//!
//! A block in the arena stays there: growing it inside or outside a scope moves it to another
//! arena block, and freeing it zeroes it and returns it to the arena (whatever the thread). A
//! value moved into the arena from the system heap leaves its old block zeroed. When the arena
//! is full (or not set up) an allocation falls back to the system allocator, as the Rust
//! allocation model can't fail one gracefully (docs/DEVIATIONS.md).

use core::alloc::{GlobalAlloc, Layout};
use core::cell::Cell;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::Ordering;
use std::alloc::System;

use super::{HEAP, INITIALIZED, in_arena, secure_free};

thread_local! {
    /// How many [`scope`]s this thread is in.
    static DEPTH: Cell<u32> = const { Cell::new(0) };
    /// Whether this thread is inside the arena's bookkeeping, whose own allocations (if any)
    /// must not come back to it.
    static BUSY: Cell<bool> = const { Cell::new(false) };
}

/// Runs `f` with this thread's Rust allocations placed in the secure heap, when it's set up
/// and has room.
pub(crate) fn scope<T>(f: impl FnOnce() -> T) -> T {
    struct Leave;
    impl Drop for Leave {
        fn drop(&mut self) {
            let _ = DEPTH.try_with(|d| d.set(d.get().saturating_sub(1)));
        }
    }
    let _ = DEPTH.try_with(|d| d.set(d.get().saturating_add(1)));
    let _leave = Leave;
    f()
}

/// Whether this thread is in a [`scope`].
fn wanted() -> bool {
    DEPTH.try_with(|d| d.get() > 0).unwrap_or(false)
}

/// A block of the arena for `layout`, if the arena is set up, the caller wants one (`force`,
/// or a [`scope`]), and there's room; null otherwise.
fn arena_alloc(layout: Layout, force: bool) -> *mut u8 {
    if layout.size() == 0 || !INITIALIZED.load(Ordering::Acquire) || !(force || wanted()) {
        return ptr::null_mut();
    }
    let entered = BUSY.try_with(|b| !b.replace(true)).unwrap_or(false);
    if !entered {
        return ptr::null_mut();
    }
    let block = (|| {
        let mut heap = HEAP.lock().ok()?;
        let heap = heap.as_mut()?;
        // A block's size is a power of two at an offset that is a multiple of it, from the
        // page-aligned start: one at least as large as the alignment is aligned.
        let offset = heap.buddy.allocate(layout.size().max(layout.align()))?;
        let block = heap.arena.block(offset).cast::<u8>();
        let size = heap.buddy.size_of(offset).unwrap_or(0);
        // Rust's copies use more of the arena than OpenSSL's private components do: they may
        // fill only half of it, so the library's own secure allocations (the random
        // generator's entropy, an application's) still find room.
        let reserve = heap.arena.size / 2;
        if block.addr() % layout.align() != 0 || heap.used.saturating_add(size) > reserve {
            let _ = heap.buddy.free(offset);
            return None;
        }
        heap.used += size;
        Some(block)
    })();
    let _ = BUSY.try_with(|b| b.set(false));
    block.unwrap_or(ptr::null_mut())
}

/// The library's allocator: the system's, with [`scope`]s' allocations in the secure heap.
pub(crate) struct Allocator;

// SAFETY: every block comes from `System` or the arena and goes back to the same one
// (`in_arena` tells them apart); arena blocks are at least the layout's size and aligned to it.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let block = arena_alloc(layout, false);
        if !block.is_null() {
            return block;
        }
        // SAFETY: the caller's layout, non-zero in size.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // An arena block is zero: the arena starts zeroed, and freed blocks are zeroed.
        let block = arena_alloc(layout, false);
        if !block.is_null() {
            return block;
        }
        // SAFETY: as in `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        if in_arena(block.cast::<c_void>()) {
            // SAFETY: a live arena block from `arena_alloc`, not used again; it's zeroed whole.
            unsafe { secure_free(block.cast(), None, ptr::null(), 0) };
        } else {
            // SAFETY: the caller's block, from `System` with this layout.
            unsafe { System.dealloc(block, layout) };
        }
    }

    unsafe fn realloc(&self, block: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let secure = in_arena(block.cast::<c_void>());
        if !secure && !wanted() {
            // SAFETY: the caller's block, from `System` with this layout.
            return unsafe { System.realloc(block, layout, new_size) };
        }
        let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) else {
            return ptr::null_mut();
        };
        // A secure block stays in the arena if it can; a block grown in a scope moves there.
        let mut grown = arena_alloc(new_layout, secure);
        if grown.is_null() {
            // SAFETY: a valid layout, non-zero in size (GlobalAlloc's contract).
            grown = unsafe { System.alloc(new_layout) };
        }
        if grown.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: both blocks are live and distinct; the shorter length fits both.
        unsafe { ptr::copy_nonoverlapping(block, grown, layout.size().min(new_size)) };
        if !secure {
            // What moved into the arena leaves no copy behind.
            // SAFETY: the old block is live and `layout.size()` bytes long.
            unsafe { ptr::write_bytes(block, 0, layout.size()) };
        }
        // SAFETY: the old block, not used again.
        unsafe { self.dealloc(block, layout) };
        grown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scope_nests_and_ends() {
        assert!(!wanted());
        scope(|| {
            assert!(wanted());
            scope(|| assert!(wanted()));
            assert!(wanted());
        });
        assert!(!wanted());
    }

    #[test]
    fn a_scope_ends_when_it_unwinds() {
        let r = std::panic::catch_unwind(|| scope(|| panic!("inside")));
        assert!(r.is_err());
        assert!(!wanted());
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri can't map the arena's guard pages (mprotect)")]
    fn scoped_allocations_live_in_the_arena_and_stay_there() {
        // SAFETY: no preconditions. It fails where the arena can't be mapped (under Miri), or
        // if another test set the heap up first; either way the checks below still hold.
        unsafe { super::super::CRYPTO_secure_malloc_init(1 << 16, 16) };
        if !super::super::initialized() {
            return;
        }
        let outside: Vec<u8> = vec![1; 100];
        assert!(!in_arena(outside.as_ptr().cast()));
        let mut inside: Vec<u8> = scope(|| vec![2; 100]);
        assert!(in_arena(inside.as_ptr().cast()));
        // Grown outside the scope, it moves to another arena block.
        inside.extend_from_slice(&[3; 1000]);
        assert!(in_arena(inside.as_ptr().cast()));
        assert!(inside.iter().take(100).all(|&b| b == 2));
        // A block that needs more alignment than its size gets it.
        #[repr(align(64))]
        struct Aligned(u8);
        let a = scope(|| Box::new(Aligned(5)));
        assert_eq!((&raw const *a).addr() % 64, 0);
        assert_eq!(a.0, 5);
    }

    #[test]
    fn without_a_heap_a_scope_allocates_normally() {
        // The heap is process-wide and another test may set it up; nothing here takes it down,
        // so if it isn't set up after the allocation, it wasn't during it.
        let v: Vec<u8> = scope(|| vec![7; 64]);
        if !super::super::initialized() {
            assert!(!in_arena(v.as_ptr().cast()));
        }
        assert_eq!(v, [7; 64]);
    }
}
