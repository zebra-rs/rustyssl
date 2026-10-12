//! Montgomery and reciprocal contexts (`BN_mod_mul_montgomery(3)`, `BN_mod_mul_reciprocal(3)`;
//! `bn_mont.c`, `bn_recp.c`).
//!
//! A `BN_MONT_CTX` holds `rustyssl_crypto::bn::mont::Montgomery`, whose reduction is OpenSSL's
//! word by word, so operands that aren't reduced give OpenSSL's results. A `BN_RECP_CTX` holds
//! its divisor; OpenSSL's cached reciprocal makes no difference to the results, which are
//! `BN_div`'s.

use core::ffi::c_int;
use core::ptr;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    BIGNUM, BN_CTX, BN_MONT_CTX, BN_R_BAD_RECIPROCAL, BN_R_NO_INVERSE, BN_RECP_CTX, CRYPTO_RWLOCK,
    ERR_LIB_BN,
};
use rustyssl_crypto::bn::mont::{MontError, Montgomery};
use rustyssl_crypto::bn::{self as core_bn, BigNum};

use super::{raise, set_result, store, value};
use crate::err;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::threads::{CRYPTO_THREAD_read_lock, CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock};

/// The object behind a `BN_MONT_CTX *`.
#[derive(Default)]
pub(crate) struct MontCtx {
    state: Mutex<Montgomery>,
}

handle_type!(BN_MONT_CTX => MontCtx);

impl MontCtx {
    fn lock(&self) -> MutexGuard<'_, Montgomery> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A copy of the Montgomery context behind `mont`.
///
/// # Safety
/// `mont` is NULL or a live `BN_MONT_CTX`.
pub(crate) unsafe fn montgomery(mont: *const BN_MONT_CTX) -> Option<Montgomery> {
    // SAFETY: the caller's guarantee.
    unsafe { BN_MONT_CTX::get(mont) }.map(|m| m.lock().clone())
}

/// `BN_MONT_CTX_set`'s work: the context for `modulus`, raising `BN_R_NO_INVERSE` for an even
/// one (a zero one fails quietly).
pub(crate) fn new_montgomery(modulus: &BigNum) -> Option<Montgomery> {
    match Montgomery::new(modulus) {
        Ok(m) => Some(m),
        Err(MontError::Zero) => None,
        Err(MontError::NoInverse) => {
            err::raise(ERR_LIB_BN, BN_R_NO_INVERSE, "BN_mod_inverse");
            None
        }
        Err(MontError::Bn(e)) => {
            raise(e);
            None
        }
    }
}

ffi_export! {
    /// A new, unset Montgomery context, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BN_MONT_CTX_new() -> *mut BN_MONT_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        BN_MONT_CTX::new_handle(MontCtx::default())
    }
}

ffi_export! {
    /// Frees a Montgomery context; NULL does nothing.
    ///
    /// # Safety
    /// `mont` is NULL or a live `BN_MONT_CTX`, not used afterwards.
    pub unsafe extern "C" fn BN_MONT_CTX_free(mont: *mut BN_MONT_CTX)
    where failure = (), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { BN_MONT_CTX::free(mont) };
    }
}

ffi_export! {
    /// Sets a context for the modulus `|mod|`. Returns 1, or 0 for a zero modulus (no error)
    /// or an even one (`BN_R_NO_INVERSE`), leaving the context as it was.
    ///
    /// # Safety
    /// `mont` and `mod_` are NULL or live objects.
    pub unsafe extern "C" fn BN_MONT_CTX_set(mont: *mut BN_MONT_CTX, mod_: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let (Some(m), Some(n)) = (unsafe { BN_MONT_CTX::get(mont) }, unsafe { value(mod_) }) else { return 0 };
        // A failure leaves the context as it was (docs/DEVIATIONS.md).
        let Some(new) = new_montgomery(&n) else { return 0 };
        *m.lock() = new;
        1
    }
}

ffi_export! {
    /// Copies `from` into `to`; returns `to` (a context copied to itself too), or NULL.
    ///
    /// # Safety
    /// `to` and `from` are NULL or live `BN_MONT_CTX`s.
    pub unsafe extern "C" fn BN_MONT_CTX_copy(to: *mut BN_MONT_CTX, from: *mut BN_MONT_CTX) -> *mut BN_MONT_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        if ptr::eq(to, from) {
            return to;
        }
        // SAFETY: the caller's guarantee.
        let (Some(t), Some(f)) = (unsafe { BN_MONT_CTX::get(to) }, unsafe { montgomery(from) }) else {
            return ptr::null_mut();
        };
        *t.lock() = f;
        to
    }
}

ffi_export! {
    /// `*pmont` if it's set; otherwise a new context for `mod_`, stored there under `lock`
    /// (unless another thread stored one first, which is returned instead). NULL on failure.
    ///
    /// # Safety
    /// `pmont` points to NULL or a live `BN_MONT_CTX`; `lock` is a live lock; `mod_` is NULL or
    /// a live `BIGNUM`.
    pub unsafe extern "C" fn BN_MONT_CTX_set_locked(pmont: *mut *mut BN_MONT_CTX, lock: *mut CRYPTO_RWLOCK, mod_: *const BIGNUM, ctx: *mut BN_CTX) -> *mut BN_MONT_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        if pmont.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's lock.
        if unsafe { CRYPTO_THREAD_read_lock(lock) } == 0 {
            return ptr::null_mut();
        }
        // SAFETY: the caller's pointer, read under the lock.
        let current = unsafe { *pmont };
        // SAFETY: as above.
        unsafe { CRYPTO_THREAD_unlock(lock) };
        if !current.is_null() {
            return current;
        }
        // SAFETY: no preconditions.
        let ret = unsafe { BN_MONT_CTX_new() };
        // SAFETY: the context just made; the caller's modulus.
        if unsafe { BN_MONT_CTX_set(ret, mod_, ctx) } == 0 {
            // SAFETY: ours to free.
            unsafe { BN_MONT_CTX_free(ret) };
            return ptr::null_mut();
        }
        // SAFETY: the caller's lock.
        if unsafe { CRYPTO_THREAD_write_lock(lock) } == 0 {
            // SAFETY: ours to free.
            unsafe { BN_MONT_CTX_free(ret) };
            return ptr::null_mut();
        }
        // SAFETY: the caller's pointer, under the lock.
        let current = unsafe { *pmont };
        let out = if current.is_null() {
            // SAFETY: as above.
            unsafe { *pmont = ret };
            ret
        } else {
            // SAFETY: ours to free.
            unsafe { BN_MONT_CTX_free(ret) };
            current
        };
        // SAFETY: as above.
        unsafe { CRYPTO_THREAD_unlock(lock) };
        out
    }
}

/// Stores a Montgomery result in `r`: 1, or 0 if there was none (OpenSSL's operands too long,
/// raising nothing) or `r` can't take it.
///
/// # Safety
/// `r` is NULL or a live `BIGNUM`.
unsafe fn store_mont(r: *mut BIGNUM, v: Option<BigNum>) -> c_int {
    // SAFETY: the caller's guarantee.
    v.map_or(0, |v| c_int::from(unsafe { store(r, v) }))
}

ffi_export! {
    /// `r = a * b / R mod N`, with `N` subtracted at most once (operands below `N` give a
    /// result below it). Returns 1, or 0 when the operands have more words between them than
    /// twice the modulus's.
    ///
    /// # Safety
    /// `r`, `a`, and `b` are NULL or live `BIGNUM`s; `mont` is NULL or a live `BN_MONT_CTX`.
    pub unsafe extern "C" fn BN_mod_mul_montgomery(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM, mont: *mut BN_MONT_CTX, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(y), Some(m)) = (unsafe { value(a) }, unsafe { value(b) }, unsafe { montgomery(mont) }) else {
            return 0;
        };
        // SAFETY: as above.
        unsafe { store_mont(r, m.mul(&x, &y)) }
    }
}

ffi_export! {
    /// `r = a * R mod N` (`a` times `RR`, reduced). Returns 1, or 0 when `a` is longer than the
    /// modulus.
    ///
    /// # Safety
    /// `r` and `a` are NULL or live `BIGNUM`s; `mont` is NULL or a live `BN_MONT_CTX`.
    pub unsafe extern "C" fn BN_to_montgomery(r: *mut BIGNUM, a: *const BIGNUM, mont: *mut BN_MONT_CTX, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(m)) = (unsafe { value(a) }, unsafe { montgomery(mont) }) else { return 0 };
        // SAFETY: as above.
        unsafe { store_mont(r, m.to_mont(&x)) }
    }
}

ffi_export! {
    /// `ret = a / R mod N` (`a` cut to twice the modulus's words). Returns 1, or 0.
    ///
    /// # Safety
    /// `ret` and `a` are NULL or live `BIGNUM`s; `mont` is NULL or a live `BN_MONT_CTX`.
    pub unsafe extern "C" fn BN_from_montgomery(ret: *mut BIGNUM, a: *const BIGNUM, mont: *mut BN_MONT_CTX, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(m)) = (unsafe { value(a) }, unsafe { montgomery(mont) }) else { return 0 };
        // SAFETY: as above.
        unsafe { store_mont(ret, Some(m.from_mont(&x))) }
    }
}

/// A reciprocal context's state: the divisor and OpenSSL's `shift`, the length its cached
/// reciprocal was made for (-1 after a failure), which decides when it's made again.
#[derive(Default)]
struct Recp {
    n: BigNum,
    shift: i64,
}

/// The object behind a `BN_RECP_CTX *`.
#[derive(Default)]
pub(crate) struct RecpCtx {
    state: Mutex<Recp>,
}

impl RecpCtx {
    fn lock(&self) -> MutexGuard<'_, Recp> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

handle_type!(BN_RECP_CTX => RecpCtx);

ffi_export! {
    /// A new, unset reciprocal context, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BN_RECP_CTX_new() -> *mut BN_RECP_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        BN_RECP_CTX::new_handle(RecpCtx::default())
    }
}

ffi_export! {
    /// Frees a reciprocal context; NULL does nothing.
    ///
    /// # Safety
    /// `recp` is NULL or a live `BN_RECP_CTX`, not used afterwards.
    pub unsafe extern "C" fn BN_RECP_CTX_free(recp: *mut BN_RECP_CTX)
    where failure = (), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { BN_RECP_CTX::free(recp) };
    }
}

ffi_export! {
    /// Sets the divisor `d`; 1, or 0 for zero.
    ///
    /// # Safety
    /// `recp` is NULL or a live `BN_RECP_CTX`; `d` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_RECP_CTX_set(recp: *mut BN_RECP_CTX, d: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let (Some(rc), Some(v)) = (unsafe { BN_RECP_CTX::get(recp) }, unsafe { value(d) }) else { return 0 };
        if v.is_zero() {
            return 0;
        }
        *rc.lock() = Recp { n: v, shift: 0 };
        1
    }
}

/// `BN_div_recp`'s outcome.
enum Outcome {
    Done(Result<(BigNum, BigNum), core_bn::Error>),
    /// The reciprocal couldn't be made (a zero divisor): `BN_R_DIV_BY_ZERO`, raised.
    Failed,
    /// Zero by a zero divisor whose reciprocal OpenSSL thinks it has: its corrections run out
    /// (`BN_R_BAD_RECIPROCAL`) having counted the quotient to 3, with a zero remainder.
    BadReciprocal,
}

/// `BN_div_recp`'s work: the quotient and remainder of `m` by the context's divisor, keeping
/// OpenSSL's `shift`.
fn div_recp(m: &BigNum, recp: &RecpCtx) -> Outcome {
    let mut st = recp.lock();
    if core_bn::ucmp(m, &st.n) == core::cmp::Ordering::Less {
        return Outcome::Done(Ok((BigNum::zero(), m.clone())));
    }
    let i = i64::try_from(m.num_bits().max(st.n.num_bits().saturating_mul(2))).unwrap_or(i64::MAX);
    if i != st.shift {
        if st.n.is_zero() {
            st.shift = -1;
            drop(st);
            raise(core_bn::Error::DivByZero);
            return Outcome::Failed;
        }
        st.shift = i;
    }
    if st.n.is_zero() {
        return Outcome::BadReciprocal;
    }
    Outcome::Done(core_bn::div_rem(m, &st.n))
}

/// The partial quotient and remainder OpenSSL leaves on `BN_R_BAD_RECIPROCAL`, which is
/// raised.
fn bad_reciprocal() -> (BigNum, BigNum) {
    err::raise(ERR_LIB_BN, BN_R_BAD_RECIPROCAL, "BN_div_recp");
    (BigNum::from_word(3), BigNum::zero())
}

ffi_export! {
    /// Divides `m` by the context's divisor as `BN_div` does: the quotient into `dv` and the
    /// remainder into `rem`, each unless NULL. Returns 1, or 0.
    ///
    /// # Safety
    /// `dv`, `rem`, and `m` are NULL or live `BIGNUM`s; `recp` is NULL or a live `BN_RECP_CTX`.
    pub unsafe extern "C" fn BN_div_recp(dv: *mut BIGNUM, rem: *mut BIGNUM, m: *const BIGNUM, recp: *mut BN_RECP_CTX, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(rc)) = (unsafe { value(m) }, unsafe { BN_RECP_CTX::get(recp) }) else { return 0 };
        let (q, r, ok) = match div_recp(&x, rc) {
            Outcome::Done(Ok((q, r))) => (q, r, true),
            Outcome::Done(Err(e)) => {
                raise(e);
                return 0;
            }
            Outcome::Failed => return 0,
            Outcome::BadReciprocal => {
                let (q, r) = bad_reciprocal();
                (q, r, false)
            }
        };
        // SAFETY: as above.
        if !dv.is_null() && !unsafe { store(dv, q) } {
            return 0;
        }
        // SAFETY: as above.
        if !rem.is_null() && !unsafe { store(rem, r) } {
            return 0;
        }
        c_int::from(ok)
    }
}

ffi_export! {
    /// `r = x * y` (or `x` alone for a NULL `y`) modulo the context's divisor, the remainder
    /// signed as `BN_div` leaves it. Returns 1, or 0.
    ///
    /// # Safety
    /// `r`, `x`, and `y` are NULL or live `BIGNUM`s; `recp` is NULL or a live `BN_RECP_CTX`.
    pub unsafe extern "C" fn BN_mod_mul_reciprocal(r: *mut BIGNUM, x: *const BIGNUM, y: *const BIGNUM, recp: *mut BN_RECP_CTX, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let (Some(a), Some(rc)) = (unsafe { value(x) }, unsafe { BN_RECP_CTX::get(recp) }) else { return 0 };
        let product = if y.is_null() {
            Ok(a)
        } else {
            // SAFETY: as above.
            let Some(b) = (unsafe { value(y) }) else { return 0 };
            core_bn::mul(&a, &b)
        };
        let rem = match product {
            Ok(p) => match div_recp(&p, rc) {
                Outcome::Done(qr) => qr.map(|(_, rem)| rem),
                Outcome::Failed => return 0,
                Outcome::BadReciprocal => {
                    let (_, rem) = bad_reciprocal();
                    // SAFETY: as above.
                    unsafe { store(r, rem) };
                    return 0;
                }
            },
            Err(e) => Err(e),
        };
        // SAFETY: as above.
        unsafe { set_result(r, rem) }
    }
}

ffi_export! {
    /// `r = 2^len / m`, truncated. Returns `len`, or -1 (for a negative `len` too).
    ///
    /// # Safety
    /// `r` and `m` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_reciprocal(r: *mut BIGNUM, m: *const BIGNUM, len: c_int, ctx: *mut BN_CTX) -> c_int
    where failure = -1, library = ERR_LIB_BN
    {
        let _ = ctx;
        let Ok(bits) = usize::try_from(len) else { return -1 };
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { value(m) }) else { return -1 };
        // SAFETY: as above.
        if unsafe { set_result(r, core_bn::modular::reciprocal(&x, bits)) } == 1 { len } else { -1 }
    }
}
