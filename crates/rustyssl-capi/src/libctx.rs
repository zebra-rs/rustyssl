//! Library contexts (`OSSL_LIB_CTX(3)`): `OSSL_LIB_CTX_new`, `OSSL_LIB_CTX_free`, the global
//! default context, each thread's default (`OSSL_LIB_CTX_set0_default`), and the state a
//! context keeps so far: its thread limit (`OSSL_set_max_threads`), its configuration
//! diagnostics flag, its application-data registry ([`crate::ex_data`]), its properties
//! ([`crate::property`]), and its providers ([`crate::provider`]).
//!
//! As in OpenSSL, a NULL context means the calling thread's default: the context it set with
//! `OSSL_LIB_CTX_set0_default`, or else the global default, which is made on first use and
//! never freed. A thread's default is held with a reference of its own, so a context another
//! thread frees stays valid for as long as it's some thread's default (in OpenSSL it would
//! dangle).

use core::ffi::c_int;
use core::ptr;
use std::cell::RefCell;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

use rustyssl_abi::{ERR_LIB_CRYPTO, OSSL_LIB_CTX};

use crate::ffi::ffi_export;
use crate::handle::{Handle, Held, handle_type};
use crate::{ex_data, property, provider};

/// A library context's state.
#[derive(Default)]
pub(crate) struct LibCtx {
    /// `OSSL_set_max_threads`'s limit.
    max_threads: AtomicU64,
    /// `OSSL_LIB_CTX_set_conf_diagnostics`'s flag.
    conf_diagnostics: AtomicI32,
    /// The application-data indexes registered in this context.
    pub(crate) ex_data: ex_data::Registry,
    /// The property names and values numbered in this context, and its default query.
    pub(crate) properties: property::Store,
    /// The providers loaded into this context.
    pub(crate) providers: provider::Store,
    /// The algorithm names and EVP methods fetched in this context.
    pub(crate) evp: crate::evp::fetch::Store,
    /// Its random generators and their settings.
    pub(crate) rand: crate::rand_lib::Global,
    /// `OSSL_INDICATOR_set_callback`'s callback (only a FIPS provider calls it; there's none).
    indicator: std::sync::Mutex<rustyssl_abi::OSSL_INDICATOR_CALLBACK>,
}

handle_type!(OSSL_LIB_CTX => LibCtx);

/// The global default context's address.
struct Global(*mut OSSL_LIB_CTX);

// SAFETY: the context is never freed and its state is thread-safe; the pointer is only handed
// out and compared.
unsafe impl Send for Global {}
// SAFETY: as above.
unsafe impl Sync for Global {}

static GLOBAL: OnceLock<Global> = OnceLock::new();

thread_local! {
    /// The context this thread set as its default, if not the global one.
    static THREAD_DEFAULT: RefCell<Option<(*mut OSSL_LIB_CTX, Held<OSSL_LIB_CTX>)>> =
        const { RefCell::new(None) };
}

/// The global default context, made on first use.
pub(crate) fn global() -> *mut OSSL_LIB_CTX {
    GLOBAL
        .get_or_init(|| Global(OSSL_LIB_CTX::new_handle(LibCtx::default())))
        .0
}

/// Whether `ctx` is the global default context.
pub(crate) fn is_global(ctx: &LibCtx) -> bool {
    // SAFETY: the global context is never freed.
    unsafe { OSSL_LIB_CTX::get(global()) }.is_some_and(|g| ptr::eq(g, ctx))
}

/// The calling thread's default context: the one it set, or the global one.
pub(crate) fn current() -> *mut OSSL_LIB_CTX {
    THREAD_DEFAULT
        .try_with(|d| d.borrow().as_ref().map(|(p, _)| *p))
        .ok()
        .flatten()
        .unwrap_or_else(global)
}

/// The context `ctx` stands for (the thread's default for NULL), held for the caller, or
/// `None` for a pointer that isn't a library context.
///
/// # Safety
/// `ctx` is NULL or a live library context.
pub(crate) unsafe fn resolve(ctx: *const OSSL_LIB_CTX) -> Option<Held<OSSL_LIB_CTX>> {
    let ctx = if ctx.is_null() {
        current().cast_const()
    } else {
        ctx
    };
    // SAFETY: the caller's guarantee, or a default context, which is held and so live.
    unsafe { OSSL_LIB_CTX::hold(ctx) }
}

ffi_export! {
    /// A new library context, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_LIB_CTX_new() -> *mut OSSL_LIB_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        OSSL_LIB_CTX::new_handle(LibCtx::default())
    }
}

ffi_export! {
    /// Frees a library context. NULL and the calling thread's default do nothing.
    ///
    /// Unlike OpenSSL, the global default context is never freed, even by a thread whose
    /// default is another (OpenSSL frees its static object; docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context, not used afterwards unless it's a default.
    pub unsafe extern "C" fn OSSL_LIB_CTX_free(ctx: *mut OSSL_LIB_CTX)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if ctx.is_null() || ctx == current() || ctx == global() {
            return;
        }
        // `ossl_ctx_thread_stop`: the calling thread's generators of the context go first.
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { OSSL_LIB_CTX::get(ctx) } {
            crate::rand_lib::stop_thread(Some(crate::rand_lib::id_of(c)));
        }
        // SAFETY: the caller's guarantee.
        unsafe { OSSL_LIB_CTX::free(ctx) };
    }
}

ffi_export! {
    /// The global default library context.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_LIB_CTX_get0_global_default() -> *mut OSSL_LIB_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        global()
    }
}

ffi_export! {
    /// Makes `libctx` the calling thread's default (the global default undoes it), unless it's
    /// NULL. Returns the previous default.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context.
    pub unsafe extern "C" fn OSSL_LIB_CTX_set0_default(libctx: *mut OSSL_LIB_CTX) -> *mut OSSL_LIB_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        let previous = current();
        if libctx.is_null() {
            return previous;
        }
        let next = if libctx == global() {
            None
        } else {
            // SAFETY: the caller's guarantee.
            let Some(held) = (unsafe { OSSL_LIB_CTX::hold(libctx) }) else {
                return previous;
            };
            Some((libctx, held))
        };
        // The old default's reference is dropped after the borrow ends.
        let old = THREAD_DEFAULT.try_with(|d| d.replace(next));
        drop(old);
        previous
    }
}

ffi_export! {
    /// Whether configuration diagnostics are on in `ctx` (the thread's default for NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context.
    pub unsafe extern "C" fn OSSL_LIB_CTX_get_conf_diagnostics(ctx: *mut OSSL_LIB_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { resolve(ctx) }.map_or(0, |c| c.conf_diagnostics.load(Ordering::Acquire))
    }
}

ffi_export! {
    /// Turns configuration diagnostics on (nonzero) or off in `ctx` (the thread's default for
    /// NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context.
    pub unsafe extern "C" fn OSSL_LIB_CTX_set_conf_diagnostics(ctx: *mut OSSL_LIB_CTX, value: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { resolve(ctx) } {
            c.conf_diagnostics.store(value, Ordering::Release);
        }
    }
}

ffi_export! {
    /// Sets how many threads the library may use for one operation in `ctx` (the thread's
    /// default for NULL). Returns 1, or 0 for a pointer that isn't a library context.
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context.
    pub unsafe extern "C" fn OSSL_set_max_threads(ctx: *mut OSSL_LIB_CTX, max_threads: u64) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { resolve(ctx) }) else { return 0 };
        c.max_threads.store(max_threads, Ordering::Release);
        1
    }
}

ffi_export! {
    /// The thread limit of `ctx` (the thread's default for NULL), 0 by default.
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context.
    pub unsafe extern "C" fn OSSL_get_max_threads(ctx: *mut OSSL_LIB_CTX) -> u64
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { resolve(ctx) }.map_or(0, |c| c.max_threads.load(Ordering::Acquire))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_follow_the_thread() {
        // SAFETY: no preconditions.
        let ctx = unsafe { OSSL_LIB_CTX_new() };
        // SAFETY: a live context.
        let previous = unsafe { OSSL_LIB_CTX_set0_default(ctx) };
        assert_eq!(previous, global());
        // SAFETY: the thread's default: freeing it does nothing.
        unsafe { OSSL_LIB_CTX_free(ctx) };
        // SAFETY: the global default is never freed, though it isn't the thread's default.
        unsafe { OSSL_LIB_CTX_free(global()) };
        // SAFETY: still live.
        assert_eq!(unsafe { OSSL_set_max_threads(global(), 0) }, 1);
        // SAFETY: NULL is the thread's default, `ctx`.
        let r = unsafe { OSSL_set_max_threads(ptr::null_mut(), 3) };
        assert_eq!(r, 1);
        // SAFETY: still live.
        assert_eq!(unsafe { OSSL_get_max_threads(ctx) }, 3);
        let other = std::thread::spawn(|| current() == global()).join();
        assert!(matches!(other, Ok(true)));
        // SAFETY: back to the global default.
        let previous = unsafe { OSSL_LIB_CTX_set0_default(global()) };
        assert_eq!(previous, ctx);
        // SAFETY: the global default is never freed.
        unsafe { OSSL_LIB_CTX_free(global()) };
        // SAFETY: no longer a default, so freed now.
        unsafe { OSSL_LIB_CTX_free(ctx) };
    }
}

ffi_export! {
    /// Sets the FIPS indicator callback of `libctx` (the thread's default for NULL). Only a
    /// FIPS provider calls it, and rustyssl has none.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `cb` is NULL or of the documented type.
    pub unsafe extern "C" fn OSSL_INDICATOR_set_callback(libctx: *mut OSSL_LIB_CTX, cb: rustyssl_abi::OSSL_INDICATOR_CALLBACK)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { resolve(libctx) } {
            *c.indicator.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = cb;
        }
    }
}

ffi_export! {
    /// The FIPS indicator callback of `libctx` (the thread's default for NULL) in `*cb`.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `cb` is NULL or valid for a write.
    pub unsafe extern "C" fn OSSL_INDICATOR_get_callback(libctx: *mut OSSL_LIB_CTX, cb: *mut rustyssl_abi::OSSL_INDICATOR_CALLBACK)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if cb.is_null() {
            return;
        }
        // SAFETY: the caller's guarantee.
        let current = unsafe { resolve(libctx) }
            .and_then(|c| *c.indicator.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
        // SAFETY: the caller's guarantee.
        unsafe { cb.write(current) };
    }
}
