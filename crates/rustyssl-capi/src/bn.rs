//! `BIGNUM` (`BN_new(3)`, `BN_add(3)`, `BN_bn2bin(3)`, `BN_CTX_new(3)`, `BN_rand(3)`, ...;
//! `crypto/bn`): handles over `rustyssl_crypto::bn::BigNum`.
//!
//! A `BIGNUM *` is a handle to a number and its flags behind a lock. An operation reads its
//! inputs (each a copy, taken under its lock), computes, and stores the result, so a result
//! may be one of the inputs, as OpenSSL allows. Who frees the handle is fixed when it's made,
//! not read from the flags an application may set: `BN_new` and `BN_secure_new` give the
//! application one (`BN_FLG_MALLOCED`), a `BN_CTX` keeps its own (`BN_free` on one only clears
//! it, as OpenSSL's does), and `BN_value_one()` is never freed.
//!
//! As in OpenSSL, a number flagged `BN_FLG_STATIC_DATA` (`BN_value_one()`, a `BN_with_flags`
//! destination) isn't written to; OpenSSL refuses only a write that needs more room and writes
//! the others into memory it doesn't own, read-only for `BN_value_one()` (docs/DEVIATIONS.md).
//!
//! OpenSSL's operations dereference a NULL `BIGNUM` or `BN_CTX`; ours fail instead (0, NULL,
//! or nothing), and work without a `BN_CTX` (docs/DEVIATIONS.md).

pub(crate) mod arith;
pub(crate) mod blind;
pub(crate) mod conv;
pub(crate) mod ctx;
pub(crate) mod gf2m;
pub(crate) mod modular;
pub(crate) mod mont;
pub(crate) mod prime;
pub(crate) mod rand;

use core::cmp::Ordering;
use core::ffi::{c_char, c_int, c_ulong};
use core::ptr;
use std::sync::atomic::{AtomicI32, AtomicPtr};
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    BIGNUM, BN_FLG_CONSTTIME, BN_FLG_MALLOCED, BN_FLG_SECURE, BN_FLG_STATIC_DATA,
    BN_R_ARG2_LT_ARG3, BN_R_BIGNUM_TOO_LONG, BN_R_DIV_BY_ZERO, BN_R_ENCODING_ERROR,
    BN_R_EXPAND_ON_STATIC_BIGNUM_DATA, BN_R_INPUT_NOT_REDUCED, BN_R_INVALID_LENGTH,
    BN_R_NO_INVERSE, BN_R_NOT_A_SQUARE, BN_R_P_IS_NOT_PRIME, BN_R_TOO_MANY_ITERATIONS, ERR_LIB_BN,
};
use rustyssl_crypto::bn::{self as core_bn, BigNum, Error};

use crate::err;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};

pub(crate) use conv::{BN_asc2bn, BN_hex2bn, BN_print};
pub(crate) use ctx::libctx_of;

/// `BN_FLG_FIXED_TOP` (`bn_local.h`): OpenSSL's internal mark for an unnormalized number,
/// which `BN_copy` and `BN_swap` carry. Ours are always normalized, so it's never set.
const FLAGS_DATA: c_int = BN_FLG_STATIC_DATA | BN_FLG_CONSTTIME | BN_FLG_SECURE;

/// Who frees a number.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Owner {
    /// The application, with `BN_free` (made by `BN_new`).
    App,
    /// A `BN_CTX`, when it's freed.
    Pool,
    /// No one: `BN_value_one()`.
    Static,
}

/// A number and its flags.
#[derive(Clone, Default)]
pub(crate) struct State {
    pub(crate) value: BigNum,
    pub(crate) flags: c_int,
}

/// The object behind a `BIGNUM *`.
pub(crate) struct Bignum {
    owner: Owner,
    state: Mutex<State>,
}

handle_type!(BIGNUM => Bignum);

impl Bignum {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A copy of the number and its flags.
    pub(crate) fn state(&self) -> State {
        self.lock().clone()
    }

    /// A copy of the number.
    pub(crate) fn value(&self) -> BigNum {
        self.lock().value.clone()
    }

    /// The flags.
    pub(crate) fn flags(&self) -> c_int {
        self.lock().flags
    }

    /// Stores `value`, unless the number is static data: then `BN_R_EXPAND_ON_STATIC_BIGNUM_DATA`
    /// and `false`.
    pub(crate) fn store(&self, value: BigNum) -> bool {
        let mut s = self.lock();
        if s.flags & BN_FLG_STATIC_DATA != 0 {
            drop(s);
            err::raise(
                ERR_LIB_BN,
                BN_R_EXPAND_ON_STATIC_BIGNUM_DATA,
                "bn_expand_internal",
            );
            return false;
        }
        s.value = value;
        true
    }

    /// Changes the number in place with `f`, unless it's static data (as [`Bignum::store`]).
    pub(crate) fn update<T>(&self, f: impl FnOnce(&mut BigNum) -> T) -> Option<T> {
        let mut s = self.lock();
        if s.flags & BN_FLG_STATIC_DATA != 0 {
            drop(s);
            err::raise(
                ERR_LIB_BN,
                BN_R_EXPAND_ON_STATIC_BIGNUM_DATA,
                "bn_expand_internal",
            );
            return None;
        }
        Some(f(&mut s.value))
    }
}

/// The number behind `a`, if it's a live `BIGNUM`.
///
/// # Safety
/// `a` is NULL or a live `BIGNUM` that outlives `'a`.
pub(crate) unsafe fn bignum<'a>(a: *const BIGNUM) -> Option<&'a Bignum> {
    // SAFETY: the caller's guarantee.
    unsafe { BIGNUM::get(a) }
}

/// A copy of the number behind `a`.
///
/// # Safety
/// As for [`bignum`].
pub(crate) unsafe fn value(a: *const BIGNUM) -> Option<BigNum> {
    // SAFETY: the caller's guarantee.
    unsafe { bignum(a) }.map(Bignum::value)
}

/// Stores `value` in `r`; `false` if `r` is NULL or static data.
///
/// # Safety
/// As for [`bignum`].
pub(crate) unsafe fn store(r: *mut BIGNUM, value: BigNum) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { bignum(r) }.is_some_and(|r| r.store(value))
}

/// A new number with `flags`, owned as `owner`.
fn new_handle(owner: Owner, flags: c_int) -> *mut BIGNUM {
    BIGNUM::new_handle(Bignum {
        owner,
        state: Mutex::new(State {
            value: BigNum::zero(),
            flags,
        }),
    })
}

/// A new number for the application (`BN_new`), holding `value`.
pub(crate) fn new_bignum(value: BigNum, secure: bool) -> *mut BIGNUM {
    let flags = BN_FLG_MALLOCED | if secure { BN_FLG_SECURE } else { 0 };
    let b = new_handle(Owner::App, flags);
    // SAFETY: just made.
    unsafe { store(b, value) };
    b
}

/// Raises the error OpenSSL raises for `e`, from the function that raises it.
pub(crate) fn raise(e: Error) {
    let (reason, function) = match e {
        Error::TooLong => (BN_R_BIGNUM_TOO_LONG, "bn_expand_internal"),
        Error::DivByZero => (BN_R_DIV_BY_ZERO, "BN_div"),
        Error::Arg2LtArg3 => (BN_R_ARG2_LT_ARG3, "BN_usub"),
        Error::InvalidLength => (BN_R_INVALID_LENGTH, "BN_mpi2bn"),
        Error::EncodingError => (BN_R_ENCODING_ERROR, "BN_mpi2bn"),
        Error::InputNotReduced => (BN_R_INPUT_NOT_REDUCED, "BN_mod_lshift_quick"),
        Error::PIsNotPrime => (BN_R_P_IS_NOT_PRIME, "BN_mod_sqrt"),
        Error::NotASquare => (BN_R_NOT_A_SQUARE, "BN_mod_sqrt"),
        Error::TooManyIterations => (BN_R_TOO_MANY_ITERATIONS, "BN_mod_sqrt"),
        Error::NoInverse => (BN_R_NO_INVERSE, "BN_mod_inverse"),
        // The generator raised its own.
        Error::Rand => return,
    };
    err::raise(ERR_LIB_BN, reason, function);
}

/// Stores the result of an operation in `r`: 1, or 0 (with the error raised) if it failed or
/// `r` can't take it.
///
/// # Safety
/// As for [`bignum`].
pub(crate) unsafe fn set_result(r: *mut BIGNUM, result: Result<BigNum, Error>) -> c_int {
    match result {
        // SAFETY: the caller's guarantee.
        Ok(v) => c_int::from(unsafe { store(r, v) }),
        Err(e) => {
            raise(e);
            0
        }
    }
}

/// A comparison as `-1`, `0`, or `1`.
fn sign(o: Ordering) -> c_int {
    match o {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

ffi_export! {
    /// A new number, zero, for the application to free (`BN_FLG_MALLOCED`), or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BN_new() -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        new_handle(Owner::App, BN_FLG_MALLOCED)
    }
}

ffi_export! {
    /// As `BN_new`, flagged `BN_FLG_SECURE` (its digits are always wiped when freed).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BN_secure_new() -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        new_handle(Owner::App, BN_FLG_MALLOCED | BN_FLG_SECURE)
    }
}

/// `BN_free` and `BN_clear_free` (the digits are wiped either way): frees an application's
/// number, clears a `BN_CTX`'s, and leaves `BN_value_one()` alone.
///
/// # Safety
/// `a` is NULL or a live `BIGNUM`, not used afterwards if it's the application's.
unsafe fn free(a: *mut BIGNUM) {
    // SAFETY: the caller's guarantee.
    let Some(b) = (unsafe { bignum(a) }) else {
        return;
    };
    match b.owner {
        // SAFETY: as above; the application gives up its reference.
        Owner::App => unsafe { BIGNUM::free(a) },
        Owner::Pool => {
            let mut s = b.lock();
            if s.flags & BN_FLG_STATIC_DATA == 0 {
                s.value = BigNum::zero();
            }
        }
        Owner::Static => {}
    }
}

ffi_export! {
    /// Frees a number (wiping its digits); NULL does nothing.
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`, not used afterwards.
    pub unsafe extern "C" fn BN_free(a: *mut BIGNUM)
    where failure = (), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { free(a) };
    }
}

ffi_export! {
    /// Wipes and frees a number; NULL does nothing.
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`, not used afterwards.
    pub unsafe extern "C" fn BN_clear_free(a: *mut BIGNUM)
    where failure = (), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { free(a) };
    }
}

/// Makes `a` zero, unless it's static data (`BN_clear`, `BN_zero_ex`).
///
/// # Safety
/// `a` is NULL or a live `BIGNUM`.
unsafe fn clear(a: *mut BIGNUM) {
    // SAFETY: the caller's guarantee.
    if let Some(b) = unsafe { bignum(a) } {
        let mut s = b.lock();
        if s.flags & BN_FLG_STATIC_DATA == 0 {
            s.value = BigNum::zero();
        }
    }
}

ffi_export! {
    /// Wipes a number to zero; NULL does nothing.
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_clear(a: *mut BIGNUM)
    where failure = (), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { clear(a) };
    }
}

ffi_export! {
    /// Sets a number to zero (`BN_zero`).
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_zero_ex(a: *mut BIGNUM)
    where failure = (), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { clear(a) };
    }
}

ffi_export! {
    /// Copies `b`'s value into `a`; returns `a`, or NULL. Copying a number to itself does
    /// nothing.
    ///
    /// # Safety
    /// `a` and `b` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_copy(a: *mut BIGNUM, b: *const BIGNUM) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        if ptr::eq(a, b) {
            return a;
        }
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { value(b) }) else { return ptr::null_mut() };
        // SAFETY: as above.
        if unsafe { store(a, v) } { a } else { ptr::null_mut() }
    }
}

ffi_export! {
    /// A new number with `a`'s value (from the secure heap if `a` is), or NULL (for NULL too).
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_dup(a: *const BIGNUM) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { bignum(a) }).map(Bignum::state) else { return ptr::null_mut() };
        new_bignum(s.value, s.flags & BN_FLG_SECURE != 0)
    }
}

ffi_export! {
    /// Exchanges two numbers' values and their data flags (`BN_FLG_CONSTTIME`,
    /// `BN_FLG_SECURE`, `BN_FLG_STATIC_DATA`), as OpenSSL swaps their digits.
    ///
    /// # Safety
    /// `a` and `b` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_swap(a: *mut BIGNUM, b: *mut BIGNUM)
    where failure = (), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(y)) = (unsafe { bignum(a) }, unsafe { bignum(b) }) else { return };
        if ptr::eq(a, b) || x.owner == Owner::Static || y.owner == Owner::Static {
            return;
        }
        let (sa, sb) = (x.state(), y.state());
        {
            let mut s = x.lock();
            s.value = sb.value;
            s.flags = (sa.flags & !FLAGS_DATA) | (sb.flags & FLAGS_DATA);
        }
        let mut s = y.lock();
        s.value = sa.value;
        s.flags = (sb.flags & !FLAGS_DATA) | (sa.flags & FLAGS_DATA);
    }
}

ffi_export! {
    /// Makes `dest` a read-only copy of `b` with `flags` added (OpenSSL shares `b`'s digits):
    /// `dest` keeps its own `BN_FLG_MALLOCED`, takes `b`'s other flags, and is flagged
    /// `BN_FLG_STATIC_DATA`.
    ///
    /// # Safety
    /// `dest` and `b` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_with_flags(dest: *mut BIGNUM, b: *const BIGNUM, flags: c_int)
    where failure = (), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let (Some(d), Some(src)) = (unsafe { bignum(dest) }, unsafe { bignum(b) }) else { return };
        if d.owner == Owner::Static {
            return;
        }
        let from = src.state();
        let mut s = d.lock();
        s.flags = (s.flags & BN_FLG_MALLOCED) | (from.flags & !BN_FLG_MALLOCED) | BN_FLG_STATIC_DATA | flags;
        s.value = from.value;
    }
}

ffi_export! {
    /// Adds `n` to a number's flags.
    ///
    /// # Safety
    /// `b` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_set_flags(b: *mut BIGNUM, n: c_int)
    where failure = (), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        if let Some(x) = unsafe { bignum(b) }.filter(|x| x.owner != Owner::Static) {
            x.lock().flags |= n;
        }
    }
}

ffi_export! {
    /// The flags of a number among `n`.
    ///
    /// # Safety
    /// `b` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_get_flags(b: *const BIGNUM, n: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { bignum(b) }.map_or(0, |x| x.flags() & n)
    }
}

/// `BN_value_one()`'s handle, made on first use and never freed.
static ONE: AtomicPtr<BIGNUM> = AtomicPtr::new(ptr::null_mut());

ffi_export! {
    /// The constant one, read-only.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BN_value_one() -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_BN
    {
        use std::sync::atomic::Ordering::{AcqRel, Acquire};
        let current = ONE.load(Acquire);
        if !current.is_null() {
            return current;
        }
        let one = new_handle(Owner::Static, 0);
        // SAFETY: just made, not yet static data.
        unsafe { store(one, BigNum::one()) };
        // SAFETY: as above.
        if let Some(b) = unsafe { bignum(one) } {
            b.lock().flags = BN_FLG_STATIC_DATA;
        }
        match ONE.compare_exchange(ptr::null_mut(), one, AcqRel, Acquire) {
            Ok(_) => one,
            Err(winner) => {
                // SAFETY: ours lost the race and was never shared.
                unsafe { BIGNUM::free(one) };
                winner
            }
        }
    }
}

ffi_export! {
    /// Sets a number to `w`; 1, or 0.
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_set_word(a: *mut BIGNUM, w: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { store(a, BigNum::from_word(w)) })
    }
}

ffi_export! {
    /// A number's magnitude if it fits a word, else all ones.
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_get_word(a: *const BIGNUM) -> c_ulong
    where failure = c_ulong::MAX, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { value(a) }.map_or(c_ulong::MAX, |v| v.get_word())
    }
}

ffi_export! {
    /// The number of significant bits in a number's magnitude.
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_num_bits(a: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let bits = unsafe { bignum(a) }.map_or(0, |b| b.lock().value.num_bits());
        c_int::try_from(bits).unwrap_or(c_int::MAX)
    }
}

ffi_export! {
    /// The number of significant bits in `l`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BN_num_bits_word(l: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        c_int::try_from(core_bn::num_bits_word(l)).unwrap_or(0)
    }
}

/// Defines the predicates, each 0 for NULL.
macro_rules! predicates {
    ($(
        $(#[$attr:meta])*
        pub unsafe extern "C" fn $name:ident($a:ident $(, $w:ident)?) = $test:expr;
    )*) => {$(
        ffi_export! {
            $(#[$attr])*
            ///
            /// # Safety
            /// `a` is NULL or a live `BIGNUM`.
            pub unsafe extern "C" fn $name(a: *const BIGNUM $(, $w: c_ulong)?) -> c_int
            where failure = 0, library = ERR_LIB_BN
            {
                // SAFETY: the caller's guarantee.
                let Some(b) = (unsafe { bignum(a) }) else { return 0 };
                let $a = &b.lock().value;
                c_int::from($test)
            }
        }
    )*};
}

predicates! {
    /// Whether a number is zero.
    pub unsafe extern "C" fn BN_is_zero(v) = v.is_zero();
    /// Whether a number is one.
    pub unsafe extern "C" fn BN_is_one(v) = v.is_one();
    /// Whether a number is odd.
    pub unsafe extern "C" fn BN_is_odd(v) = v.is_odd();
    /// Whether a number is negative.
    pub unsafe extern "C" fn BN_is_negative(v) = v.is_negative();
    /// Whether a number is `w` (0 matches either sign).
    pub unsafe extern "C" fn BN_is_word(v, w) = v.is_word(w);
    /// Whether a number's magnitude is `w`.
    pub unsafe extern "C" fn BN_abs_is_word(v, w) = v.abs_is_word(w);
}

ffi_export! {
    /// Makes a nonzero number negative (`b` nonzero) or non-negative.
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_set_negative(a: *mut BIGNUM, b: c_int)
    where failure = (), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        if let Some(x) = unsafe { bignum(a) } {
            let _ = x.update(|v| v.set_negative(b != 0));
        }
    }
}

ffi_export! {
    /// Compares two numbers: -1, 0, or 1. NULL is less than any number, and equal to NULL.
    ///
    /// # Safety
    /// `a` and `b` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        match (unsafe { value(a) }, unsafe { value(b) }) {
            (Some(x), Some(y)) => sign(core_bn::cmp(&x, &y)),
            (Some(_), None) => -1,
            (None, Some(_)) => 1,
            (None, None) => 0,
        }
    }
}

ffi_export! {
    /// Compares two numbers' magnitudes: below, at, or above 0. As in OpenSSL, numbers of
    /// different lengths in words (neither flagged `BN_FLG_CONSTTIME`) give the difference in
    /// words, others -1, 0, or 1. NULL is less than any number.
    ///
    /// # Safety
    /// `a` and `b` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_ucmp(a: *const BIGNUM, b: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        match (unsafe { bignum(a) }.map(Bignum::state), unsafe { bignum(b) }.map(Bignum::state)) {
            (Some(x), Some(y)) => {
                let (tx, ty) = (x.value.top(), y.value.top());
                if (x.flags | y.flags) & BN_FLG_CONSTTIME == 0 && tx != ty {
                    // OpenSSL returns the difference in words.
                    let diff = i64::try_from(tx).unwrap_or(i64::MAX) - i64::try_from(ty).unwrap_or(i64::MAX);
                    return c_int::try_from(diff).unwrap_or(if diff < 0 { -1 } else { 1 });
                }
                sign(core_bn::ucmp(&x.value, &y.value))
            }
            (x, y) => c_int::from(y.is_none()) - c_int::from(x.is_none()),
        }
    }
}

/// A bit number from C: `None` if negative.
fn bit(n: c_int) -> Option<usize> {
    usize::try_from(n).ok()
}

ffi_export! {
    /// Sets bit `n` of a number's magnitude; 1, or 0 (for a negative `n` too).
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_set_bit(a: *mut BIGNUM, n: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let (Some(n), Some(x)) = (bit(n), unsafe { bignum(a) }) else { return 0 };
        match x.update(|v| v.set_bit(n)) {
            Some(Ok(())) => 1,
            Some(Err(e)) => {
                raise(e);
                0
            }
            None => 0,
        }
    }
}

ffi_export! {
    /// Clears bit `n`; 0 if `n` is negative or beyond the number.
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_clear_bit(a: *mut BIGNUM, n: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let (Some(n), Some(x)) = (bit(n), unsafe { bignum(a) }) else { return 0 };
        c_int::from(x.update(|v| v.clear_bit(n)).unwrap_or(false))
    }
}

ffi_export! {
    /// Whether bit `n` is set (0 for a negative `n`).
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_is_bit_set(a: *const BIGNUM, n: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let (Some(n), Some(x)) = (bit(n), unsafe { bignum(a) }) else { return 0 };
        c_int::from(x.lock().value.is_bit_set(n))
    }
}

ffi_export! {
    /// Keeps the low `n` bits; 0 if `n` is negative or reaches past the number's top word.
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_mask_bits(a: *mut BIGNUM, n: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let (Some(n), Some(x)) = (bit(n), unsafe { bignum(a) }) else { return 0 };
        c_int::from(x.update(|v| v.mask_bits(n)).unwrap_or(false))
    }
}

ffi_export! {
    /// Exchanges `a` and `b` if `swap` is nonzero, touching every word of both either way:
    /// their values and their `BN_FLG_CONSTTIME` flags.
    ///
    /// # Safety
    /// `a` and `b` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_consttime_swap(swap: c_ulong, a: *mut BIGNUM, b: *mut BIGNUM, nwords: c_int)
    where failure = (), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(y)) = (unsafe { bignum(a) }, unsafe { bignum(b) }) else { return };
        if ptr::eq(a, b) || x.owner == Owner::Static || y.owner == Owner::Static {
            return;
        }
        let (mut sa, mut sb) = (x.state(), y.state());
        let swap = swap != 0;
        core_bn::consttime_swap(swap, &mut sa.value, &mut sb.value, usize::try_from(nwords).unwrap_or(0));
        let t = if swap { (sa.flags ^ sb.flags) & BN_FLG_CONSTTIME } else { 0 };
        sa.flags ^= t;
        sb.flags ^= t;
        *x.lock() = sa;
        *y.lock() = sb;
    }
}

ffi_export! {
    /// The security strength in bits of a finite-field key of `L` bits with a subgroup of `N`
    /// bits (-1 for none), per SP 800-57; 0 below 80.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BN_security_bits(l: c_int, n: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let secbits = match l {
            15360.. => 256,
            7680.. => 192,
            3072.. => 128,
            2048.. => 112,
            1024.. => 80,
            _ => return 0,
        };
        if n == -1 {
            return secbits;
        }
        let bits = n / 2;
        if bits < 80 {
            return 0;
        }
        bits.min(secbits)
    }
}

ffi_export! {
    /// The library's word sizes, as text: `bn(64,64)`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BN_options() -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        static OPTIONS: [u8; 10] = *b"bn(64,64)\0";
        OPTIONS.as_ptr().cast_mut().cast()
    }
}

/// `BN_set_params`'s four settings, which nothing reads.
static PARAMS: [AtomicI32; 4] = [
    AtomicI32::new(0),
    AtomicI32::new(0),
    AtomicI32::new(0),
    AtomicI32::new(0),
];

ffi_export! {
    /// Records four tuning settings, each capped at 31; a negative one is left as it was. They
    /// have no effect.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BN_set_params(mult: c_int, high: c_int, low: c_int, mont: c_int)
    where failure = (), library = ERR_LIB_BN
    {
        for (slot, v) in PARAMS.iter().zip([mult, high, low, mont]) {
            if v >= 0 {
                slot.store(v.min(c_int::BITS.cast_signed() - 1), std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

ffi_export! {
    /// A setting from `BN_set_params`: 0 for `mult`, 1 `high`, 2 `low`, 3 `mont`; 0 otherwise.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BN_get_params(which: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        usize::try_from(which)
            .ok()
            .and_then(|i| PARAMS.get(i))
            .map_or(0, |p| p.load(std::sync::atomic::Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests;

/// A read-only number for a static table (`BN_FLG_STATIC_DATA`), never freed.
pub(crate) fn new_static(value: BigNum) -> *mut BIGNUM {
    let h = new_handle(Owner::Static, 0);
    // SAFETY: just made, not yet static data.
    unsafe { store(h, value) };
    // SAFETY: as above.
    if let Some(b) = unsafe { bignum(h) } {
        b.lock().flags = BN_FLG_STATIC_DATA;
    }
    h
}
