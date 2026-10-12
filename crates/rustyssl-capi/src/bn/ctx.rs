//! `BN_CTX` (`BN_CTX_new(3)`, `BN_CTX_start(3)`; `bn_ctx.c`): a pool of temporary numbers in
//! nested frames, and the library context the numbers' operations use.
//!
//! As in OpenSSL, `BN_CTX_get` hands out the pool's numbers in order, each zeroed (and
//! `BN_FLG_CONSTTIME` cleared), and `BN_CTX_end` gives back the ones taken since the matching
//! `BN_CTX_start`, so the same numbers come out again. The numbers belong to the pool, which
//! wipes and frees them with itself.

use core::ptr;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    BIGNUM, BN_CTX, BN_FLG_CONSTTIME, BN_FLG_SECURE, BN_R_TOO_MANY_TEMPORARY_VARIABLES, ERR_LIB_BN,
    OSSL_LIB_CTX,
};
use rustyssl_crypto::bn::BigNum;

use super::{Owner, bignum, new_handle};
use crate::err;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};

/// A pool's frames and numbers.
#[derive(Default)]
struct Pool {
    /// The numbers, as addresses; the pool holds one reference to each.
    numbers: Vec<usize>,
    /// How many are in use.
    used: usize,
    /// Where each open frame starts.
    frames: Vec<usize>,
    /// Frames opened after a failure, which `BN_CTX_end` closes without giving anything back.
    err_stack: usize,
    /// Set when a `BN_CTX_get` failed: gets fail until the next `BN_CTX_end`.
    too_many: bool,
}

/// The object behind a `BN_CTX *`.
pub(crate) struct Ctx {
    libctx: usize,
    secure: bool,
    pool: Mutex<Pool>,
}

handle_type!(BN_CTX => Ctx);

impl Ctx {
    fn lock(&self) -> MutexGuard<'_, Pool> {
        self.pool.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        let pool = self.pool.get_mut().unwrap_or_else(PoisonError::into_inner);
        for &n in &pool.numbers {
            // SAFETY: the pool's own reference to a number it made.
            unsafe { BIGNUM::free(ptr::with_exposed_provenance_mut(n)) };
        }
    }
}

/// The library context of `ctx` (NULL for none or the default).
///
/// # Safety
/// `ctx` is NULL or a live `BN_CTX`.
pub(crate) unsafe fn libctx_of(ctx: *const BN_CTX) -> *mut OSSL_LIB_CTX {
    // SAFETY: the caller's guarantee.
    unsafe { BN_CTX::get(ctx) }.map_or(ptr::null_mut(), |c| {
        ptr::with_exposed_provenance_mut(c.libctx)
    })
}

/// A new pool for `libctx`.
fn new_ctx(libctx: *mut OSSL_LIB_CTX, secure: bool) -> *mut BN_CTX {
    BN_CTX::new_handle(Ctx {
        libctx: libctx.expose_provenance(),
        secure,
        pool: Mutex::new(Pool::default()),
    })
}

ffi_export! {
    /// A new `BN_CTX` for the library context `ctx` (NULL for the default), or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a library context that outlives the `BN_CTX`.
    pub unsafe extern "C" fn BN_CTX_new_ex(ctx: *mut OSSL_LIB_CTX) -> *mut BN_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        new_ctx(ctx, false)
    }
}

ffi_export! {
    /// A new `BN_CTX` for the default library context, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BN_CTX_new() -> *mut BN_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        new_ctx(ptr::null_mut(), false)
    }
}

ffi_export! {
    /// As `BN_CTX_new_ex`, with numbers flagged `BN_FLG_SECURE`.
    ///
    /// # Safety
    /// `ctx` is NULL or a library context that outlives the `BN_CTX`.
    pub unsafe extern "C" fn BN_CTX_secure_new_ex(ctx: *mut OSSL_LIB_CTX) -> *mut BN_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        new_ctx(ctx, true)
    }
}

ffi_export! {
    /// As `BN_CTX_new`, with numbers flagged `BN_FLG_SECURE`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BN_CTX_secure_new() -> *mut BN_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        new_ctx(ptr::null_mut(), true)
    }
}

ffi_export! {
    /// Frees a `BN_CTX` and wipes and frees its numbers; NULL does nothing.
    ///
    /// # Safety
    /// `ctx` is NULL or a live `BN_CTX`; neither it nor its numbers are used afterwards.
    pub unsafe extern "C" fn BN_CTX_free(ctx: *mut BN_CTX)
    where failure = (), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { BN_CTX::free(ctx) };
    }
}

ffi_export! {
    /// Opens a frame: the numbers got from here on are given back by the matching
    /// `BN_CTX_end`.
    ///
    /// # Safety
    /// `ctx` is NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn BN_CTX_start(ctx: *mut BN_CTX)
    where failure = (), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { BN_CTX::get(ctx) }) else { return };
        let mut p = c.lock();
        if p.err_stack > 0 || p.too_many {
            p.err_stack = p.err_stack.saturating_add(1);
        } else {
            let used = p.used;
            p.frames.push(used);
        }
    }
}

ffi_export! {
    /// Closes the last frame, giving back the numbers got in it; NULL, or no open frame, does
    /// nothing.
    ///
    /// # Safety
    /// `ctx` is NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn BN_CTX_end(ctx: *mut BN_CTX)
    where failure = (), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { BN_CTX::get(ctx) }) else { return };
        let mut p = c.lock();
        if p.err_stack > 0 {
            p.err_stack = p.err_stack.wrapping_sub(1);
        } else if let Some(fp) = p.frames.pop() {
            p.used = fp;
            p.too_many = false;
        }
    }
}

ffi_export! {
    /// The pool's next number, zero, or NULL (after a failure, until `BN_CTX_end`).
    ///
    /// # Safety
    /// `ctx` is NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn BN_CTX_get(ctx: *mut BN_CTX) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { BN_CTX::get(ctx) }) else { return ptr::null_mut() };
        let mut p = c.lock();
        if p.err_stack > 0 || p.too_many {
            return ptr::null_mut();
        }
        let n = match p.numbers.get(p.used) {
            Some(&n) => ptr::with_exposed_provenance_mut::<BIGNUM>(n),
            None => {
                let n = new_handle(Owner::Pool, if c.secure { BN_FLG_SECURE } else { 0 });
                if n.is_null() {
                    p.too_many = true;
                    drop(p);
                    err::raise(ERR_LIB_BN, BN_R_TOO_MANY_TEMPORARY_VARIABLES, "BN_CTX_get");
                    return ptr::null_mut();
                }
                p.numbers.push(n.expose_provenance());
                n
            }
        };
        // SAFETY: one of the pool's live numbers.
        if let Some(b) = unsafe { bignum(n) } {
            let mut s = b.lock();
            s.value = BigNum::zero();
            s.flags &= !BN_FLG_CONSTTIME;
        }
        p.used = p.used.saturating_add(1);
        n
    }
}
