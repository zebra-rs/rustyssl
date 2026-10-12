//! Threads (`CRYPTO_THREAD_run_once(3)`, `CRYPTO_atomic_add(3)`, `OSSL_set_max_threads(3)`).
//!
//! `crypto.h` makes the types POSIX's own: `CRYPTO_ONCE` is a `pthread_once_t` that applications
//! initialize with `CRYPTO_ONCE_STATIC_INIT`, `CRYPTO_THREAD_LOCAL` a `pthread_key_t`, and
//! `CRYPTO_THREAD_ID` a `pthread_t`. Their storage belongs to the application, so these
//! functions are thin wrappers around the pthread calls OpenSSL makes, and behave identically.
//! `CRYPTO_RWLOCK` is opaque; as in OpenSSL it's a `pthread_rwlock_t` from `OPENSSL_zalloc`.
//!
//! The atomics are lock-free on every target rustyssl supports, so like OpenSSL's they ignore
//! the lock, which may be null. Only a value that isn't naturally aligned (undefined behavior in
//! C, but cheap to handle) falls back to the lock, as OpenSSL's does when `__atomic_is_lock_free`
//! says no.
//!
//! Where OpenSSL would dereference a null pointer, these return their failure value instead
//! (docs/DEVIATIONS.md).

use core::ffi::{c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicU64, Ordering};

use rustyssl_abi::{
    CRYPTO_ONCE, CRYPTO_RWLOCK, CRYPTO_THREAD_ID, CRYPTO_THREAD_LOCAL, ERR_LIB_CRYPTO,
    OSSL_LIB_CTX, OSSL_THREAD_SUPPORT_FLAG_DEFAULT_SPAWN, OSSL_THREAD_SUPPORT_FLAG_THREAD_POOL,
};

use crate::err;
use crate::ffi::ffi_export;
use crate::mem;

/// The lock behind a `CRYPTO_RWLOCK *`.
fn rwlock(lock: *mut CRYPTO_RWLOCK) -> *mut libc::pthread_rwlock_t {
    lock.cast()
}

ffi_export! {
    /// A new read-write lock, or null if it can't be allocated.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn CRYPTO_THREAD_lock_new() -> *mut CRYPTO_RWLOCK
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        let lock = mem::alloc_zeroed(size_of::<libc::pthread_rwlock_t>());
        if lock.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `lock` is a fresh, suitably aligned block the size of a pthread_rwlock_t.
        if unsafe { libc::pthread_rwlock_init(lock.cast(), ptr::null()) } != 0 {
            // SAFETY: the block came from the allocator and holds no initialized lock.
            unsafe { mem::release(lock) };
            return ptr::null_mut();
        }
        lock
    }
}

ffi_export! {
    /// Takes the lock for reading, shared with other readers. Returns 1, or 0 on failure.
    ///
    /// # Safety
    /// `lock` is null or a live lock from `CRYPTO_THREAD_lock_new`.
    pub unsafe extern "C" fn CRYPTO_THREAD_read_lock(lock: *mut CRYPTO_RWLOCK) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller passes a live lock; null is checked.
        c_int::from(!lock.is_null() && unsafe { libc::pthread_rwlock_rdlock(rwlock(lock)) } == 0)
    }
}

ffi_export! {
    /// Takes the lock for writing, exclusively. Returns 1, or 0 on failure.
    ///
    /// # Safety
    /// As for `CRYPTO_THREAD_read_lock`.
    pub unsafe extern "C" fn CRYPTO_THREAD_write_lock(lock: *mut CRYPTO_RWLOCK) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller passes a live lock; null is checked.
        c_int::from(!lock.is_null() && unsafe { libc::pthread_rwlock_wrlock(rwlock(lock)) } == 0)
    }
}

ffi_export! {
    /// Releases the lock. Returns 1, or 0 on failure.
    ///
    /// # Safety
    /// As for `CRYPTO_THREAD_read_lock`.
    pub unsafe extern "C" fn CRYPTO_THREAD_unlock(lock: *mut CRYPTO_RWLOCK) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller passes a live lock; null is checked.
        c_int::from(!lock.is_null() && unsafe { libc::pthread_rwlock_unlock(rwlock(lock)) } == 0)
    }
}

ffi_export! {
    /// Destroys and frees a lock. Null does nothing.
    ///
    /// # Safety
    /// `lock` is null or a live, unheld lock from `CRYPTO_THREAD_lock_new`, not used afterwards.
    pub unsafe extern "C" fn CRYPTO_THREAD_lock_free(lock: *mut CRYPTO_RWLOCK)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if lock.is_null() {
            return;
        }
        // SAFETY: the caller passes a live lock that nobody holds.
        unsafe { libc::pthread_rwlock_destroy(rwlock(lock)) };
        // SAFETY: the lock's block came from the allocator.
        unsafe { mem::release(lock) };
    }
}

ffi_export! {
    /// Runs `init` exactly once for `once` across all threads (`pthread_once`). Returns 1, or 0
    /// on failure.
    ///
    /// # Safety
    /// `once` is null or a `CRYPTO_ONCE` initialized with `CRYPTO_ONCE_STATIC_INIT`, and `init`
    /// is null or a function that returns normally.
    pub unsafe extern "C" fn CRYPTO_THREAD_run_once(
        once: *mut CRYPTO_ONCE,
        init: Option<unsafe extern "C" fn()>,
    ) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(init) = init else {
            return 0;
        };
        if once.is_null() {
            return 0;
        }
        // The libc crate spells the routine's type differently per platform.
        #[cfg(target_os = "linux")]
        // SAFETY: the two function pointer types differ only in Rust's `unsafe`; both are C
        // functions without arguments.
        let init = unsafe { core::mem::transmute::<unsafe extern "C" fn(), extern "C" fn()>(init) };
        #[cfg(not(target_os = "linux"))]
        let init = Some(init);
        // SAFETY: the caller passes an initialized pthread_once_t.
        c_int::from(unsafe { libc::pthread_once(once, init) } == 0)
    }
}

ffi_export! {
    /// Creates thread-local storage in `key`, with `cleanup` called on each thread's non-null
    /// value when the thread exits (`pthread_key_create`). Returns 1, or 0 on failure.
    ///
    /// # Safety
    /// `key` is null or valid for a write; `cleanup` is null or a function safe to call with
    /// any value stored under the key.
    pub unsafe extern "C" fn CRYPTO_THREAD_init_local(
        key: *mut CRYPTO_THREAD_LOCAL,
        cleanup: Option<unsafe extern "C" fn(*mut c_void)>,
    ) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller passes a writable key; null is checked.
        c_int::from(!key.is_null() && unsafe { libc::pthread_key_create(key, cleanup) } == 0)
    }
}

ffi_export! {
    /// This thread's value under `key`, or null.
    ///
    /// # Safety
    /// `key` is null or a key from `CRYPTO_THREAD_init_local`.
    pub unsafe extern "C" fn CRYPTO_THREAD_get_local(key: *mut CRYPTO_THREAD_LOCAL) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        if key.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller passes a valid key; null is checked.
        let key = unsafe { key.read() };
        // SAFETY: `key` came from pthread_key_create.
        unsafe { libc::pthread_getspecific(key) }
    }
}

ffi_export! {
    /// Sets this thread's value under `key`. Returns 1, or 0 on failure.
    ///
    /// # Safety
    /// As for `CRYPTO_THREAD_get_local`.
    pub unsafe extern "C" fn CRYPTO_THREAD_set_local(key: *mut CRYPTO_THREAD_LOCAL, val: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if key.is_null() {
            return 0;
        }
        // SAFETY: the caller passes a valid key; null is checked.
        let key = unsafe { key.read() };
        // SAFETY: `key` came from pthread_key_create.
        c_int::from(unsafe { libc::pthread_setspecific(key, val) } == 0)
    }
}

ffi_export! {
    /// Deletes `key` (`pthread_key_delete`; the cleanup function isn't called). Returns 1, or 0
    /// on failure.
    ///
    /// # Safety
    /// As for `CRYPTO_THREAD_get_local`.
    pub unsafe extern "C" fn CRYPTO_THREAD_cleanup_local(key: *mut CRYPTO_THREAD_LOCAL) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if key.is_null() {
            return 0;
        }
        // SAFETY: the caller passes a valid key; null is checked.
        let key = unsafe { key.read() };
        // SAFETY: `key` came from pthread_key_create.
        c_int::from(unsafe { libc::pthread_key_delete(key) } == 0)
    }
}

ffi_export! {
    /// The calling thread's ID (`pthread_self`).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn CRYPTO_THREAD_get_current_id() -> CRYPTO_THREAD_ID
    where failure = 0 as CRYPTO_THREAD_ID, library = ERR_LIB_CRYPTO
    {
        // SAFETY: pthread_self has no preconditions.
        unsafe { libc::pthread_self() }
    }
}

ffi_export! {
    /// Whether two thread IDs are the same thread: nonzero if so (`pthread_equal`).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn CRYPTO_THREAD_compare_id(a: CRYPTO_THREAD_ID, b: CRYPTO_THREAD_ID) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: pthread_equal only compares the two values.
        unsafe { libc::pthread_equal(a, b) }
    }
}

/// Applies `update` to the value at `val` under `lock`, for a value too misaligned to be
/// atomic. Returns the new value, or `None` without a lock.
///
/// # Safety
/// `val` is valid for reads and writes, and `lock` is null or a live lock that every other
/// access to `val` also takes.
unsafe fn locked<T: Copy>(
    val: *mut T,
    lock: *mut CRYPTO_RWLOCK,
    update: impl FnOnce(T) -> T,
) -> Option<T> {
    // SAFETY: the caller passes null or a live lock.
    if unsafe { CRYPTO_THREAD_write_lock(lock) } == 0 {
        return None;
    }
    // SAFETY: the caller guarantees `val` is readable and writable; it may be misaligned.
    let new = update(unsafe { val.read_unaligned() });
    // SAFETY: as above.
    unsafe { val.write_unaligned(new) };
    // SAFETY: we hold the lock.
    (unsafe { CRYPTO_THREAD_unlock(lock) } != 0).then_some(new)
}

/// Runs an atomic read-modify-write on a `u64`, or a locked one if `val` is misaligned, and
/// stores the new value in `*ret`. Returns 1, or 0 on failure.
///
/// # Safety
/// `val` and `ret` are null or valid; `val` is only accessed atomically or under `lock`.
unsafe fn update64(
    val: *mut u64,
    ret: *mut u64,
    lock: *mut CRYPTO_RWLOCK,
    atomic: impl FnOnce(&AtomicU64) -> u64,
    plain: impl FnOnce(u64) -> u64,
) -> c_int {
    if val.is_null() || ret.is_null() {
        return 0;
    }
    let new = if val.is_aligned() {
        // SAFETY: `val` is aligned, valid, and only accessed atomically (the caller's
        // guarantee).
        Some(atomic(unsafe { AtomicU64::from_ptr(val) }))
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { locked(val, lock, plain) }
    };
    match new {
        Some(new) => {
            // SAFETY: `ret` is valid for a write (checked non-null; the caller's guarantee).
            unsafe { ret.write_unaligned(new) };
            1
        }
        None => 0,
    }
}

ffi_export! {
    /// Adds `amount` to `*val` atomically (wrapping) and stores the result in `*ret`. Returns
    /// 1, or 0 on failure.
    ///
    /// # Safety
    /// `val` and `ret` are null or valid; `val` is only accessed atomically or under `lock`,
    /// which is null or a live lock.
    pub unsafe extern "C" fn CRYPTO_atomic_add(val: *mut c_int, amount: c_int, ret: *mut c_int, lock: *mut CRYPTO_RWLOCK) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if val.is_null() || ret.is_null() {
            return 0;
        }
        let new = if val.is_aligned() {
            // SAFETY: `val` is aligned, valid, and only accessed atomically.
            let atomic = unsafe { AtomicI32::from_ptr(val) };
            Some(atomic.fetch_add(amount, Ordering::AcqRel).wrapping_add(amount))
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { locked(val, lock, |v| v.wrapping_add(amount)) }
        };
        match new {
            Some(new) => {
                // SAFETY: `ret` is valid for a write.
                unsafe { ret.write_unaligned(new) };
                1
            }
            None => 0,
        }
    }
}

ffi_export! {
    /// Adds `op` to `*val` atomically (wrapping) and stores the result in `*ret`.
    ///
    /// # Safety
    /// As for `CRYPTO_atomic_add`.
    pub unsafe extern "C" fn CRYPTO_atomic_add64(val: *mut u64, op: u64, ret: *mut u64, lock: *mut CRYPTO_RWLOCK) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe {
            update64(
                val,
                ret,
                lock,
                |a| a.fetch_add(op, Ordering::AcqRel).wrapping_add(op),
                |v| v.wrapping_add(op),
            )
        }
    }
}

ffi_export! {
    /// ANDs `op` into `*val` atomically and stores the result in `*ret`.
    ///
    /// # Safety
    /// As for `CRYPTO_atomic_add`.
    pub unsafe extern "C" fn CRYPTO_atomic_and(val: *mut u64, op: u64, ret: *mut u64, lock: *mut CRYPTO_RWLOCK) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { update64(val, ret, lock, |a| a.fetch_and(op, Ordering::AcqRel) & op, |v| v & op) }
    }
}

ffi_export! {
    /// ORs `op` into `*val` atomically and stores the result in `*ret`.
    ///
    /// # Safety
    /// As for `CRYPTO_atomic_add`.
    pub unsafe extern "C" fn CRYPTO_atomic_or(val: *mut u64, op: u64, ret: *mut u64, lock: *mut CRYPTO_RWLOCK) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { update64(val, ret, lock, |a| a.fetch_or(op, Ordering::AcqRel) | op, |v| v | op) }
    }
}

ffi_export! {
    /// Reads `*val` atomically into `*ret`.
    ///
    /// # Safety
    /// As for `CRYPTO_atomic_add`.
    pub unsafe extern "C" fn CRYPTO_atomic_load(val: *mut u64, ret: *mut u64, lock: *mut CRYPTO_RWLOCK) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { update64(val, ret, lock, |a| a.load(Ordering::Acquire), |v| v) }
    }
}

ffi_export! {
    /// Writes `val` to `*dst` atomically.
    ///
    /// # Safety
    /// `dst` is null or valid, and only accessed atomically or under `lock`.
    pub unsafe extern "C" fn CRYPTO_atomic_store(dst: *mut u64, val: u64, lock: *mut CRYPTO_RWLOCK) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let mut ignored = 0u64;
        // SAFETY: the caller's guarantee; `ignored` is a valid place for the result.
        unsafe {
            update64(
                dst,
                &mut ignored,
                lock,
                |a| {
                    a.store(val, Ordering::Release);
                    val
                },
                |_| val,
            )
        }
    }
}

ffi_export! {
    /// Reads `*val` atomically into `*ret`.
    ///
    /// # Safety
    /// As for `CRYPTO_atomic_add`.
    pub unsafe extern "C" fn CRYPTO_atomic_load_int(val: *mut c_int, ret: *mut c_int, lock: *mut CRYPTO_RWLOCK) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if val.is_null() || ret.is_null() {
            return 0;
        }
        let value = if val.is_aligned() {
            // SAFETY: `val` is aligned, valid, and only accessed atomically.
            Some(unsafe { AtomicI32::from_ptr(val) }.load(Ordering::Acquire))
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { locked(val, lock, |v| v) }
        };
        match value {
            Some(value) => {
                // SAFETY: `ret` is valid for a write.
                unsafe { ret.write_unaligned(value) };
                1
            }
            None => 0,
        }
    }
}

ffi_export! {
    /// What the build supports: a thread pool, and spawning its threads by default.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_get_thread_support_flags() -> u32
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // The default build enables both (no OPENSSL_NO_THREAD_POOL, no
        // OPENSSL_NO_DEFAULT_THREAD_POOL).
        OSSL_THREAD_SUPPORT_FLAG_THREAD_POOL | OSSL_THREAD_SUPPORT_FLAG_DEFAULT_SPAWN
    }
}

/// Frees the calling thread's library state, as `OPENSSL_thread_stop` does: its random
/// generators (of every context) and its error queue.
pub(crate) fn stop_thread() {
    crate::rand_lib::stop_thread(None);
    err::stop_thread();
}

ffi_export! {
    /// Frees the calling thread's library state now instead of at thread exit.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OPENSSL_thread_stop()
    where failure = (), library = ERR_LIB_CRYPTO
    {
        stop_thread();
    }
}

ffi_export! {
    /// Frees the calling thread's state for `ctx` (null for the default context): its public
    /// and private random generators.
    ///
    /// # Safety
    /// `ctx` is null or a live library context.
    pub unsafe extern "C" fn OPENSSL_thread_stop_ex(ctx: *mut OSSL_LIB_CTX)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { crate::libctx::resolve(ctx) } {
            crate::rand_lib::stop_thread(Some(crate::rand_lib::id_of(&c)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_LOCK: *mut CRYPTO_RWLOCK = ptr::null_mut();

    #[test]
    fn atomics_wrap_and_combine() {
        let mut value: c_int = c_int::MAX;
        let mut ret: c_int = 0;
        // SAFETY: both pointers are valid and aligned; no lock is needed.
        let ok = unsafe { CRYPTO_atomic_add(&mut value, 1, &mut ret, NO_LOCK) };
        assert_eq!((ok, value, ret), (1, c_int::MIN, c_int::MIN));

        let mut bits = 0b1100u64;
        let mut out = 0u64;
        // SAFETY: as above.
        let ok = unsafe { CRYPTO_atomic_or(&mut bits, 0b0011, &mut out, NO_LOCK) };
        assert_eq!((ok, bits, out), (1, 0b1111, 0b1111));
        // SAFETY: as above.
        let ok = unsafe { CRYPTO_atomic_and(&mut bits, 0b0110, &mut out, NO_LOCK) };
        assert_eq!((ok, bits, out), (1, 0b0110, 0b0110));
        // SAFETY: as above.
        let stored = unsafe { CRYPTO_atomic_store(&mut bits, 42, NO_LOCK) };
        // SAFETY: as above.
        let loaded = unsafe { CRYPTO_atomic_load(&mut bits, &mut out, NO_LOCK) };
        assert_eq!((stored, loaded, out), (1, 1, 42));
    }

    #[test]
    fn misaligned_values_need_the_lock() {
        // Words are 8-byte aligned, so one byte in is always misaligned.
        let mut words = [0u64; 3];
        let misaligned = words
            .as_mut_ptr()
            .cast::<u8>()
            .wrapping_add(1)
            .cast::<u64>();
        let mut out = 0u64;
        // SAFETY: the bytes are valid; without a lock the call fails before touching them.
        let unlocked = unsafe { CRYPTO_atomic_add64(misaligned, 5, &mut out, NO_LOCK) };
        assert_eq!(unlocked, 0);
        // Miri can't run pthread_rwlock_init; tests/c/crypto_threads.c covers the locks.
        if cfg!(miri) {
            return;
        }
        // SAFETY: no preconditions.
        let lock = unsafe { CRYPTO_THREAD_lock_new() };
        // SAFETY: the bytes are valid and only accessed here, under the lock.
        let locked = unsafe { CRYPTO_atomic_add64(misaligned, 5, &mut out, lock) };
        assert_eq!((locked, out), (1, 5));
        // SAFETY: the lock is live and unheld.
        unsafe { CRYPTO_THREAD_lock_free(lock) };
    }

    #[test]
    fn null_pointers_fail() {
        let mut out = 0u64;
        // SAFETY: null pointers are checked first.
        let load = unsafe { CRYPTO_atomic_load(ptr::null_mut(), &mut out, NO_LOCK) };
        // SAFETY: as above.
        let lock = unsafe { CRYPTO_THREAD_write_lock(NO_LOCK) };
        // SAFETY: as above.
        let once = unsafe { CRYPTO_THREAD_run_once(ptr::null_mut(), None) };
        assert_eq!((load, lock, once), (0, 0, 0));
    }
}
