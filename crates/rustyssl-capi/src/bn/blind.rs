//! Blinding (`BN_BLINDING_new(3)`; `bn_blind.c`): a random `A` and its inverse `Ai` modulo
//! `mod`, with `A` raised to `e` (an RSA public exponent), multiplied into a value before a
//! private-key operation and out of the result after. The pair is squared on each use and
//! recreated every 32 uses (unless the flags say otherwise). With a Montgomery context both are
//! kept in Montgomery form.
//!
//! The numbers are the blinding's own `BIGNUM`s, handed to an application's `bn_mod_exp`
//! callback as OpenSSL hands them; no lock of ours is held while it runs. The blinding's
//! `CRYPTO_RWLOCK` is the application's to take (`BN_BLINDING_lock`).

use core::ffi::{c_int, c_ulong};
use core::ptr;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    BIGNUM, BN_BLINDING, BN_BLINDING_NO_RECREATE, BN_BLINDING_NO_UPDATE, BN_CTX, BN_FLG_CONSTTIME,
    BN_MONT_CTX, BN_R_NOT_INITIALIZED, BN_R_TOO_MANY_ITERATIONS, CRYPTO_RWLOCK, CRYPTO_THREAD_ID,
    ERR_LIB_BN, ERR_R_CRYPTO_LIB,
};

use super::modular::{BN_mod_exp, BN_mod_mul};
use super::mont::{BN_mod_mul_montgomery, BN_to_montgomery, montgomery};
use super::{BN_copy, BN_dup, BN_free, BN_new, BN_set_flags, bignum, store, value};
use crate::err;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::threads::{
    CRYPTO_THREAD_compare_id, CRYPTO_THREAD_get_current_id, CRYPTO_THREAD_lock_free,
    CRYPTO_THREAD_lock_new, CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock,
};

/// `BN_BLINDING_COUNTER`: uses between recreations.
const COUNTER: c_int = 32;

/// An application's modular exponentiation.
type ModExp = unsafe extern "C" fn(
    *mut BIGNUM,
    *const BIGNUM,
    *const BIGNUM,
    *const BIGNUM,
    *mut BN_CTX,
    *mut BN_MONT_CTX,
) -> c_int;

/// A pointer kept in the blinding.
struct Kept<T>(*mut T);

impl<T> Clone for Kept<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Kept<T> {}

// SAFETY: the blinding only stores these and passes them to calls, as OpenSSL's does; the
// numbers it owns are its own handles, which are thread-safe.
unsafe impl<T> Send for Kept<T> {}
// SAFETY: as above.
unsafe impl<T> Sync for Kept<T> {}

/// A blinding's fields.
struct State {
    a: Kept<BIGNUM>,
    ai: Kept<BIGNUM>,
    e: Kept<BIGNUM>,
    modulus: Kept<BIGNUM>,
    tid: Tid,
    counter: c_int,
    flags: c_ulong,
    m_ctx: Kept<BN_MONT_CTX>,
    exp: Option<ModExp>,
}

/// The object behind a `BN_BLINDING *`.
pub(crate) struct Blinding {
    state: Mutex<State>,
    lock: Kept<CRYPTO_RWLOCK>,
}

handle_type!(BN_BLINDING => Blinding);

impl Blinding {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for Blinding {
    fn drop(&mut self) {
        let s = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
        for n in [s.a, s.ai, s.e, s.modulus] {
            // SAFETY: the blinding's own numbers.
            unsafe { BN_free(n.0) };
        }
        // SAFETY: the blinding's own lock.
        unsafe { CRYPTO_THREAD_lock_free(self.lock.0) };
    }
}

/// A thread's id.
#[derive(Clone, Copy)]
struct Tid(CRYPTO_THREAD_ID);

// SAFETY: an id is only compared, as OpenSSL compares it.
unsafe impl Send for Tid {}
// SAFETY: as above.
unsafe impl Sync for Tid {}

/// The current thread's id.
fn current_thread() -> Tid {
    // SAFETY: no preconditions.
    Tid(unsafe { CRYPTO_THREAD_get_current_id() })
}

/// The blinding behind `b`.
///
/// # Safety
/// `b` is NULL or a live `BN_BLINDING` that outlives `'a`.
unsafe fn blinding<'a>(b: *const BN_BLINDING) -> Option<&'a Blinding> {
    // SAFETY: the caller's guarantee.
    unsafe { BN_BLINDING::get(b) }
}

/// A copy of `n` (NULL for NULL), as `BN_dup`.
///
/// # Safety
/// `n` is NULL or a live `BIGNUM`.
unsafe fn dup(n: *const BIGNUM) -> *mut BIGNUM {
    // SAFETY: the caller's guarantee.
    unsafe { BN_dup(n) }
}

ffi_export! {
    /// A new blinding with copies of `A` and `Ai` (each if not NULL), and `mod` (keeping its
    /// `BN_FLG_CONSTTIME`), owned by the current thread. NULL on failure (for a NULL `mod`
    /// too).
    ///
    /// # Safety
    /// `a_in`, `ai_in`, and `mod_` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_BLINDING_new(a_in: *const BIGNUM, ai_in: *const BIGNUM, mod_: *mut BIGNUM) -> *mut BN_BLINDING
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        // SAFETY: no preconditions.
        let lock = unsafe { CRYPTO_THREAD_lock_new() };
        if lock.is_null() {
            err::raise(ERR_LIB_BN, ERR_R_CRYPTO_LIB, "BN_BLINDING_new");
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee, here and below.
        let a = if a_in.is_null() { ptr::null_mut() } else { unsafe { dup(a_in) } };
        // SAFETY: as above.
        let ai = if ai_in.is_null() { ptr::null_mut() } else { unsafe { dup(ai_in) } };
        // SAFETY: as above.
        let m = unsafe { dup(mod_) };
        let b = BN_BLINDING::new_handle(Blinding {
            state: Mutex::new(State {
                a: Kept(a),
                ai: Kept(ai),
                e: Kept(ptr::null_mut()),
                modulus: Kept(m),
                tid: current_thread(),
                counter: -1,
                flags: 0,
                m_ctx: Kept(ptr::null_mut()),
                exp: None,
            }),
            lock: Kept(lock),
        });
        if (!a_in.is_null() && a.is_null()) || (!ai_in.is_null() && ai.is_null()) || m.is_null() {
            // SAFETY: ours to free.
            unsafe { BN_BLINDING::free(b) };
            return ptr::null_mut();
        }
        // SAFETY: as above.
        if unsafe { bignum(mod_) }.is_some_and(|x| x.flags() & BN_FLG_CONSTTIME != 0) {
            // SAFETY: the copy just made.
            unsafe { BN_set_flags(m, BN_FLG_CONSTTIME) };
        }
        b
    }
}

ffi_export! {
    /// Frees a blinding and its numbers; NULL does nothing.
    ///
    /// # Safety
    /// `b` is NULL or a live `BN_BLINDING`, not used afterwards.
    pub unsafe extern "C" fn BN_BLINDING_free(b: *mut BN_BLINDING)
    where failure = (), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { BN_BLINDING::free(b) };
    }
}

/// `r = x * y` in the blinding's arithmetic: Montgomery's with `m_ctx`, else modulo `modulus`.
///
/// # Safety
/// The pointers are live objects (or NULL).
unsafe fn multiply(
    r: *mut BIGNUM,
    x: *const BIGNUM,
    y: *const BIGNUM,
    s: &Snapshot,
    ctx: *mut BN_CTX,
) -> c_int {
    if s.m_ctx.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { BN_mod_mul(r, x, y, s.modulus, ctx) }
    } else {
        // SAFETY: as above.
        unsafe { BN_mod_mul_montgomery(r, x, y, s.m_ctx, ctx) }
    }
}

/// The pointers a blinding's operations use.
struct Snapshot {
    a: *mut BIGNUM,
    ai: *mut BIGNUM,
    e: *mut BIGNUM,
    modulus: *mut BIGNUM,
    m_ctx: *mut BN_MONT_CTX,
    exp: Option<ModExp>,
}

impl Blinding {
    fn snapshot(&self) -> Snapshot {
        let s = self.lock();
        Snapshot {
            a: s.a.0,
            ai: s.ai.0,
            e: s.e.0,
            modulus: s.modulus.0,
            m_ctx: s.m_ctx.0,
            exp: s.exp,
        }
    }
}

ffi_export! {
    /// Advances the blinding: recreates it on the 32nd use (if it has an exponent and
    /// `BN_BLINDING_NO_RECREATE` isn't set), else squares `A` and `Ai` (unless
    /// `BN_BLINDING_NO_UPDATE`). Returns 1, or 0 (`BN_R_NOT_INITIALIZED` without `A` and `Ai`).
    ///
    /// # Safety
    /// `b` is NULL or a live `BN_BLINDING`; `ctx` is NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn BN_BLINDING_update(b: *mut BN_BLINDING, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(bl) = (unsafe { blinding(b) }) else { return 0 };
        let s = bl.snapshot();
        if s.a.is_null() || s.ai.is_null() {
            err::raise(ERR_LIB_BN, BN_R_NOT_INITIALIZED, "BN_BLINDING_update");
            return 0;
        }
        let (counter, flags) = {
            let mut st = bl.lock();
            if st.counter == -1 {
                st.counter = 0;
            }
            st.counter += 1;
            (st.counter, st.flags)
        };
        let ret = if counter == COUNTER && !s.e.is_null() && flags & c_ulong::from(BN_BLINDING_NO_RECREATE.unsigned_abs()) == 0 {
            // OpenSSL checks for NULL, which recreating an existing blinding never returns, so
            // a failed recreation still succeeds.
            // SAFETY: as above.
            unsafe { BN_BLINDING_create_param(b, ptr::null(), ptr::null_mut(), ctx, None, ptr::null_mut()) };
            1
        } else if flags & c_ulong::from(BN_BLINDING_NO_UPDATE.unsigned_abs()) == 0 {
            // SAFETY: the blinding's numbers.
            let first = unsafe { multiply(s.ai, s.ai, s.ai, &s, ctx) } != 0;
            // SAFETY: as above.
            c_int::from(first && unsafe { multiply(s.a, s.a, s.a, &s, ctx) } != 0)
        } else {
            1
        };
        let mut st = bl.lock();
        if st.counter == COUNTER {
            st.counter = 0;
        }
        ret
    }
}

ffi_export! {
    /// Blinds `n` (`n *= A`), first advancing the blinding unless it's fresh, and copies `Ai`
    /// into `r` unless it's NULL. Returns 1, or 0.
    ///
    /// # Safety
    /// `n` and `r` are NULL or live `BIGNUM`s; `b` is NULL or a live `BN_BLINDING`; `ctx` is
    /// NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn BN_BLINDING_convert_ex(n: *mut BIGNUM, r: *mut BIGNUM, b: *mut BN_BLINDING, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(bl) = (unsafe { blinding(b) }) else { return 0 };
        let s = bl.snapshot();
        if s.a.is_null() || s.ai.is_null() {
            err::raise(ERR_LIB_BN, BN_R_NOT_INITIALIZED, "BN_BLINDING_convert_ex");
            return 0;
        }
        let fresh = {
            let mut st = bl.lock();
            let fresh = st.counter == -1;
            if fresh {
                st.counter = 0;
            }
            fresh
        };
        // SAFETY: as above.
        if !fresh && unsafe { BN_BLINDING_update(b, ctx) } == 0 {
            return 0;
        }
        let s = bl.snapshot();
        // SAFETY: as above.
        if !r.is_null() && unsafe { BN_copy(r, s.ai) }.is_null() {
            return 0;
        }
        // SAFETY: as above.
        unsafe { multiply(n, n, s.a, &s, ctx) }
    }
}

ffi_export! {
    /// `BN_BLINDING_convert_ex` without copying `Ai`.
    ///
    /// # Safety
    /// As for `BN_BLINDING_convert_ex`.
    pub unsafe extern "C" fn BN_BLINDING_convert(n: *mut BIGNUM, b: *mut BN_BLINDING, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { BN_BLINDING_convert_ex(n, ptr::null_mut(), b, ctx) }
    }
}

ffi_export! {
    /// Unblinds `n` (`n *= r`, or `Ai` if `r` is NULL). Returns 1, or 0
    /// (`BN_R_NOT_INITIALIZED` without either).
    ///
    /// # Safety
    /// `n` and `r` are NULL or live `BIGNUM`s; `b` is NULL or a live `BN_BLINDING`; `ctx` is
    /// NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn BN_BLINDING_invert_ex(n: *mut BIGNUM, r: *const BIGNUM, b: *mut BN_BLINDING, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(bl) = (unsafe { blinding(b) }) else { return 0 };
        let s = bl.snapshot();
        let r = if r.is_null() { s.ai.cast_const() } else { r };
        if r.is_null() {
            err::raise(ERR_LIB_BN, BN_R_NOT_INITIALIZED, "BN_BLINDING_invert_ex");
            return 0;
        }
        if !s.m_ctx.is_null() {
            // OpenSSL pads `n` to the Montgomery length first, so a longer `n` fails.
            // SAFETY: as above.
            let nl = unsafe { montgomery(s.m_ctx) }.map_or(0, |m| m.limbs());
            // SAFETY: as above.
            if unsafe { value(n) }.is_some_and(|v| v.top() > nl) {
                return 0;
            }
        }
        // SAFETY: as above.
        unsafe { multiply(n, n, r, &s, ctx) }
    }
}

ffi_export! {
    /// `BN_BLINDING_invert_ex` with `Ai`.
    ///
    /// # Safety
    /// As for `BN_BLINDING_invert_ex`.
    pub unsafe extern "C" fn BN_BLINDING_invert(n: *mut BIGNUM, b: *mut BN_BLINDING, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { BN_BLINDING_invert_ex(n, ptr::null(), b, ctx) }
    }
}

ffi_export! {
    /// Whether the current thread is the blinding's.
    ///
    /// # Safety
    /// `b` is NULL or a live `BN_BLINDING`.
    pub unsafe extern "C" fn BN_BLINDING_is_current_thread(b: *mut BN_BLINDING) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(bl) = (unsafe { blinding(b) }) else { return 0 };
        let tid = bl.lock().tid.0;
        // SAFETY: no preconditions.
        let current = unsafe { CRYPTO_THREAD_get_current_id() };
        // SAFETY: two ids.
        unsafe { CRYPTO_THREAD_compare_id(current, tid) }
    }
}

ffi_export! {
    /// Makes the current thread the blinding's.
    ///
    /// # Safety
    /// `b` is NULL or a live `BN_BLINDING`.
    pub unsafe extern "C" fn BN_BLINDING_set_current_thread(b: *mut BN_BLINDING)
    where failure = (), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        if let Some(bl) = unsafe { blinding(b) } {
            bl.lock().tid = current_thread();
        }
    }
}

ffi_export! {
    /// Takes the blinding's lock for writing. Returns 1, or 0.
    ///
    /// # Safety
    /// `b` is NULL or a live `BN_BLINDING`.
    pub unsafe extern "C" fn BN_BLINDING_lock(b: *mut BN_BLINDING) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(bl) = (unsafe { blinding(b) }) else { return 0 };
        // SAFETY: the blinding's lock.
        unsafe { CRYPTO_THREAD_write_lock(bl.lock.0) }
    }
}

ffi_export! {
    /// Releases the blinding's lock. Returns 1, or 0.
    ///
    /// # Safety
    /// `b` is NULL or a live `BN_BLINDING`.
    pub unsafe extern "C" fn BN_BLINDING_unlock(b: *mut BN_BLINDING) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(bl) = (unsafe { blinding(b) }) else { return 0 };
        // SAFETY: the blinding's lock.
        unsafe { CRYPTO_THREAD_unlock(bl.lock.0) }
    }
}

ffi_export! {
    /// The blinding's flags.
    ///
    /// # Safety
    /// `b` is NULL or a live `BN_BLINDING`.
    pub unsafe extern "C" fn BN_BLINDING_get_flags(b: *const BN_BLINDING) -> c_ulong
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { blinding(b) }.map_or(0, |bl| bl.lock().flags)
    }
}

ffi_export! {
    /// Sets the blinding's flags (`BN_BLINDING_NO_UPDATE`, `BN_BLINDING_NO_RECREATE`).
    ///
    /// # Safety
    /// `b` is NULL or a live `BN_BLINDING`.
    pub unsafe extern "C" fn BN_BLINDING_set_flags(b: *mut BN_BLINDING, flags: c_ulong)
    where failure = (), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        if let Some(bl) = unsafe { blinding(b) } {
            bl.lock().flags = flags;
        }
    }
}

/// `int_bn_mod_inverse` for blinding: `ai = a^-1 mod m`, `Some(true)` if found,
/// `Some(false)` if there's none (no error), `None` on a failure.
///
/// # Safety
/// The numbers are live.
unsafe fn try_inverse(ai: *mut BIGNUM, a: *const BIGNUM, m: *const BIGNUM) -> Option<bool> {
    // SAFETY: the caller's guarantee.
    let x = unsafe { value(a) }?;
    // SAFETY: as above.
    let mv = unsafe { value(m) }?;
    if mv.abs_is_word(1) || mv.is_zero() {
        return Some(false);
    }
    let modulus = mv.abs();
    let x = rustyssl_crypto::bn::nnmod(&x, &modulus).ok()?;
    match rustyssl_crypto::bn::ct::inverse(&x, &modulus) {
        // SAFETY: as above.
        Some(v) => unsafe { store(ai, v) }.then_some(true),
        None => Some(false),
    }
}

ffi_export! {
    /// Sets up `b` (or a new blinding for `m` if it's NULL) with a new random `A` and its
    /// inverse, `A` raised to `e` (kept, or set here) with `bn_mod_exp` and `m_ctx` if both are
    /// given (also kept), else `BN_mod_exp`; with a Montgomery context, both are converted to
    /// its form. Returns the blinding; on failure NULL for a new one, `b` itself otherwise (as
    /// OpenSSL does).
    ///
    /// # Safety
    /// `b` is NULL or a live `BN_BLINDING`; `e` and `m` are NULL or live `BIGNUM`s; `ctx` is
    /// NULL or a live `BN_CTX`; `bn_mod_exp` is NULL or a function that works on the numbers it's
    /// given; `m_ctx` is NULL or a live `BN_MONT_CTX` that outlives the blinding.
    pub unsafe extern "C" fn BN_BLINDING_create_param(b: *mut BN_BLINDING, e: *const BIGNUM, m: *mut BIGNUM, ctx: *mut BN_CTX, bn_mod_exp: Option<ModExp>, m_ctx: *mut BN_MONT_CTX) -> *mut BN_BLINDING
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        let ret = if b.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { BN_BLINDING_new(ptr::null(), ptr::null(), m) }
        } else {
            b
        };
        // SAFETY: as above.
        let ok = unsafe { create_param(ret, e, ctx, bn_mod_exp, m_ctx) };
        if !ok && b.is_null() {
            // SAFETY: ours to free.
            unsafe { BN_BLINDING_free(ret) };
            return ptr::null_mut();
        }
        ret
    }
}

/// `BN_BLINDING_create_param`'s work on a blinding.
///
/// # Safety
/// As for `BN_BLINDING_create_param`, with `ret` NULL or a live blinding.
unsafe fn create_param(
    ret: *mut BN_BLINDING,
    e: *const BIGNUM,
    ctx: *mut BN_CTX,
    bn_mod_exp: Option<ModExp>,
    m_ctx: *mut BN_MONT_CTX,
) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(bl) = (unsafe { blinding(ret) }) else {
        return false;
    };
    {
        let mut st = bl.lock();
        if st.a.0.is_null() {
            // SAFETY: no preconditions.
            st.a = Kept(unsafe { BN_new() });
        }
        if st.ai.0.is_null() {
            // SAFETY: no preconditions.
            st.ai = Kept(unsafe { BN_new() });
        }
        if !e.is_null() {
            // SAFETY: the blinding's old exponent; the caller's new one.
            unsafe { BN_free(st.e.0) };
            // SAFETY: as above.
            st.e = Kept(unsafe { dup(e) });
        }
        if bn_mod_exp.is_some() {
            st.exp = bn_mod_exp;
        }
        if !m_ctx.is_null() {
            st.m_ctx = Kept(m_ctx);
        }
    }
    let s = bl.snapshot();
    if s.a.is_null() || s.ai.is_null() || s.e.is_null() {
        return false;
    }
    let mut retries = 32;
    loop {
        // SAFETY: the blinding's numbers.
        if unsafe { super::rand::BN_priv_rand_range_ex(s.a, s.modulus, 0, ctx) } == 0 {
            return false;
        }
        // SAFETY: as above.
        match unsafe { try_inverse(s.ai, s.a, s.modulus) } {
            Some(true) => break,
            Some(false) => {}
            None => return false,
        }
        if retries == 0 {
            err::raise(
                ERR_LIB_BN,
                BN_R_TOO_MANY_ITERATIONS,
                "BN_BLINDING_create_param",
            );
            return false;
        }
        retries -= 1;
    }
    let raised = match (s.exp, s.m_ctx.is_null()) {
        // SAFETY: the application's function, on the blinding's numbers; no lock is held.
        (Some(f), false) => unsafe { f(s.a, s.a, s.e, s.modulus, ctx, s.m_ctx) },
        // SAFETY: the blinding's numbers.
        _ => unsafe { BN_mod_exp(s.a, s.a, s.e, s.modulus, ctx) },
    };
    if raised == 0 {
        return false;
    }
    if !s.m_ctx.is_null() {
        // SAFETY: as above.
        if unsafe { BN_to_montgomery(s.ai, s.ai, s.m_ctx, ctx) } == 0 {
            return false;
        }
        // SAFETY: as above.
        if unsafe { BN_to_montgomery(s.a, s.a, s.m_ctx, ctx) } == 0 {
            return false;
        }
    }
    true
}
