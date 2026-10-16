//! Primes (`BN_generate_prime(3)`, `BN_check_prime`, `BN_GENCB_new`; `bn_prime.c`,
//! `bn_depr.c`, `bn_x931p.c`): Miller-Rabin with random bases from the private generator,
//! trial division by the first primes, candidate generation with OpenSSL's sieve, and the
//! application's progress callbacks.
//!
//! Every random number is drawn as OpenSSL draws it, so a known generator gives OpenSSL's
//! primes. A callback runs with no lock of ours held. The X9.31 functions are compositions of
//! exported ones, as in OpenSSL.

use core::ffi::{c_int, c_ulong, c_void};
use core::ptr;
use std::sync::{Mutex, PoisonError};

use rustyssl_abi::{
    BIGNUM, BN_CTX, BN_GENCB, BN_R_BITS_TOO_SMALL, BN_RAND_BOTTOM_ANY, BN_RAND_BOTTOM_ODD,
    BN_RAND_TOP_ONE, BN_RAND_TOP_TWO, ERR_LIB_BN,
};
use rustyssl_crypto::bn::prime::{PRIMES, min_checks, trial_divisions};
use rustyssl_crypto::bn::{self as core_bn, BigNum};

use super::arith::{BN_add, BN_add_word, BN_mul, BN_sub, BN_sub_word};
use super::modular::{BN_gcd, BN_mod_inverse, BN_mod_sub};
use super::rand::{BN_priv_rand_ex, BN_priv_rand_range_ex, BN_rand_ex};
use super::{BN_copy, BN_free, BN_is_odd, BN_is_one, bignum, new_bignum, store, value};
use crate::err;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};

/// An old-style callback.
pub(crate) type OldCb = unsafe extern "C" fn(c_int, c_int, *mut c_void);
/// A new-style callback.
type NewCb = unsafe extern "C" fn(c_int, c_int, *mut BN_GENCB) -> c_int;

/// What a `BN_GENCB` was set to.
#[derive(Clone, Copy, Default)]
enum Setting {
    /// Never set (OpenSSL's is uninitialized memory).
    #[default]
    Unset,
    Old(Option<OldCb>, usize),
    New(Option<NewCb>, usize),
}

/// The object behind a `BN_GENCB *`.
#[derive(Default)]
pub(crate) struct Gencb {
    setting: Mutex<Setting>,
}

handle_type!(BN_GENCB => Gencb);

/// A callback to report to: an application's `BN_GENCB`, or an old-style one of a deprecated
/// function.
#[derive(Clone, Copy)]
pub(crate) enum Callback {
    None,
    Gencb(*mut BN_GENCB),
    Old(Option<OldCb>, *mut c_void),
}

/// `BN_GENCB_call`: 1 to go on, 0 to stop.
///
/// # Safety
/// The callback's pointers are live.
pub(crate) unsafe fn call(cb: Callback, a: c_int, b: c_int) -> c_int {
    match cb {
        Callback::None => 1,
        Callback::Old(f, arg) => {
            if let Some(f) = f {
                // SAFETY: the application's callback and argument.
                unsafe { f(a, b, arg) };
            }
            1
        }
        Callback::Gencb(g) => {
            // SAFETY: the caller's guarantee.
            let Some(obj) = (unsafe { BN_GENCB::get(g) }) else {
                return 1;
            };
            let setting = *obj.setting.lock().unwrap_or_else(PoisonError::into_inner);
            match setting {
                Setting::Unset => 0,
                Setting::Old(f, arg) => {
                    if let Some(f) = f {
                        // SAFETY: the application's callback and argument; no lock is held.
                        unsafe { f(a, b, ptr::with_exposed_provenance_mut(arg)) };
                    }
                    1
                }
                // SAFETY: as above.
                Setting::New(Some(f), _) => unsafe { f(a, b, g) },
                Setting::New(None, _) => 1,
            }
        }
    }
}

/// A `BN_GENCB *` as a callback.
pub(crate) fn gencb(cb: *mut BN_GENCB) -> Callback {
    if cb.is_null() {
        Callback::None
    } else {
        Callback::Gencb(cb)
    }
}

ffi_export! {
    /// A new callback holder, unset, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BN_GENCB_new() -> *mut BN_GENCB
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        BN_GENCB::new_handle(Gencb::default())
    }
}

ffi_export! {
    /// Frees a callback holder; NULL does nothing.
    ///
    /// # Safety
    /// `cb` is NULL or a live `BN_GENCB`, not used afterwards.
    pub unsafe extern "C" fn BN_GENCB_free(cb: *mut BN_GENCB)
    where failure = (), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { BN_GENCB::free(cb) };
    }
}

ffi_export! {
    /// Sets an old-style callback, called with the progress and `cb_arg`.
    ///
    /// # Safety
    /// `gencb` is NULL or a live `BN_GENCB`; `callback` is NULL or a function.
    pub unsafe extern "C" fn BN_GENCB_set_old(gencb: *mut BN_GENCB, callback: Option<OldCb>, cb_arg: *mut c_void)
    where failure = (), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        if let Some(g) = unsafe { BN_GENCB::get(gencb) } {
            *g.setting.lock().unwrap_or_else(PoisonError::into_inner) = Setting::Old(callback, cb_arg.expose_provenance());
        }
    }
}

ffi_export! {
    /// Sets a new-style callback, called with the progress and the `BN_GENCB` (whose
    /// `BN_GENCB_get_arg` is `cb_arg`); it returns 0 to stop.
    ///
    /// # Safety
    /// `gencb` is NULL or a live `BN_GENCB`; `callback` is NULL or a function.
    pub unsafe extern "C" fn BN_GENCB_set(gencb: *mut BN_GENCB, callback: Option<NewCb>, cb_arg: *mut c_void)
    where failure = (), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        if let Some(g) = unsafe { BN_GENCB::get(gencb) } {
            *g.setting.lock().unwrap_or_else(PoisonError::into_inner) = Setting::New(callback, cb_arg.expose_provenance());
        }
    }
}

ffi_export! {
    /// The argument a callback was set with (NULL if never set).
    ///
    /// # Safety
    /// `cb` is NULL or a live `BN_GENCB`.
    pub unsafe extern "C" fn BN_GENCB_get_arg(cb: *mut BN_GENCB) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { BN_GENCB::get(cb) }) else { return ptr::null_mut() };
        match *g.setting.lock().unwrap_or_else(PoisonError::into_inner) {
            Setting::Old(_, arg) | Setting::New(_, arg) => ptr::with_exposed_provenance_mut(arg),
            Setting::Unset => ptr::null_mut(),
        }
    }
}

ffi_export! {
    /// Reports progress `(a, b)` to the callback: 1 to go on (also with no callback), 0 to stop
    /// (or for a holder never set).
    ///
    /// # Safety
    /// `cb` is NULL or a live `BN_GENCB` whose callback is safe to call.
    pub unsafe extern "C" fn BN_GENCB_call(cb: *mut BN_GENCB, a: c_int, b: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { call(gencb(cb), a, b) }
    }
}

/// A temporary number, freed when dropped.
struct Temp(*mut BIGNUM);

impl Temp {
    fn new() -> Self {
        Temp(new_bignum(BigNum::zero(), false))
    }

    fn value(&self) -> BigNum {
        // SAFETY: ours, live until dropped.
        unsafe { value(self.0) }.unwrap_or_default()
    }

    fn set(&self, v: BigNum) {
        // SAFETY: as above.
        unsafe { store(self.0, v) };
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        // SAFETY: ours to free.
        unsafe { BN_free(self.0) };
    }
}

/// What Miller-Rabin found (`BN_PRIMETEST_*`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Status {
    ProbablyPrime,
    Composite,
    /// The enhanced test found a factor.
    CompositeWithFactor,
    /// The enhanced test's composite that isn't a prime's power.
    CompositeNotPowerOfPrime,
}

/// `ossl_bn_miller_rabin_is_prime`: what `iterations` rounds (the minimum for the size if 0)
/// with random bases from the private generator found, or `None` on a failure (or a callback
/// that stopped it). The enhanced test (FIPS 186-5 B.3.1) also looks for a factor.
///
/// # Safety
/// `ctx` is NULL or a live `BN_CTX`; the callback's pointers are live.
pub(crate) unsafe fn miller_rabin_status(
    w: &BigNum,
    iterations: i32,
    ctx: *mut BN_CTX,
    cb: Callback,
    enhanced: bool,
) -> Option<Status> {
    if !w.is_odd() {
        return None;
    }
    let mut w1 = w.clone();
    w1.sub_word(1).ok()?;
    let mut w3 = w.clone();
    w3.sub_word(3).ok()?;
    if w3.is_zero() || w3.is_negative() {
        return None;
    }
    let mut a = 1usize;
    while !w1.is_bit_set(a) {
        a = a.saturating_add(1);
    }
    let m = core_bn::rshift(&w1, a);
    let mont = core_bn::mont::Montgomery::new(w).ok()?;
    let iterations = if iterations == 0 {
        min_checks(w.num_bits())
    } else {
        iterations
    };
    let range = Temp::new();
    range.set(w3);
    let b = Temp::new();
    // `gcd(v, w)` is one.
    let coprime = |v: &BigNum| v.is_zero() || core_bn::ct::gcd(v, w).0.is_one();
    for i in 0..iterations {
        // SAFETY: ours; the caller's context.
        if unsafe { BN_priv_rand_range_ex(b.0, range.0, 0, ctx) } == 0 {
            return None;
        }
        let mut bv = b.value();
        bv.add_word(2).ok()?;
        if enhanced && !coprime(&bv) {
            return Some(Status::CompositeWithFactor);
        }
        let mut z = mont.exp_consttime(&bv, m.limbs());
        // The witness's x when the round proves w composite.
        let mut composite = None;
        if !(z.is_one() || core_bn::cmp(&z, &w1).is_eq()) {
            let mut passed = false;
            for _ in 1..a {
                let x = z.clone();
                z = core_bn::modular::mod_mul(&x, &x, w).ok()?;
                if core_bn::cmp(&z, &w1).is_eq() {
                    passed = true;
                    break;
                }
                if z.is_one() {
                    composite = Some(x);
                    break;
                }
            }
            if !passed && composite.is_none() {
                let x = z.clone();
                z = core_bn::modular::mod_mul(&x, &x, w).ok()?;
                composite = Some(if z.is_one() { x } else { z });
            }
        }
        if let Some(mut x) = composite {
            if !enhanced {
                return Some(Status::Composite);
            }
            x.sub_word(1).ok()?;
            let x = x.abs();
            return Some(if coprime(&x) && !x.is_zero() {
                Status::CompositeNotPowerOfPrime
            } else {
                Status::CompositeWithFactor
            });
        }
        // SAFETY: the caller's guarantee.
        if unsafe { call(cb, 1, i) } == 0 {
            return None;
        }
    }
    Some(Status::ProbablyPrime)
}

/// `ossl_bn_miller_rabin_is_prime` (not enhanced): `Some(true)` for probably prime,
/// `Some(false)` for composite, `None` on a failure (or a callback that stopped it).
///
/// # Safety
/// As for [`miller_rabin_status`].
unsafe fn miller_rabin(
    w: &BigNum,
    iterations: i32,
    ctx: *mut BN_CTX,
    cb: Callback,
) -> Option<bool> {
    // SAFETY: the caller's guarantee.
    unsafe { miller_rabin_status(w, iterations, ctx, cb, false) }
        .map(|s| s == Status::ProbablyPrime)
}

/// `bn_is_prime_int`: 1 probably prime, 0 composite, -1 failure.
///
/// # Safety
/// As for [`miller_rabin`].
pub(crate) unsafe fn is_prime_int(
    w: &BigNum,
    checks: i32,
    ctx: *mut BN_CTX,
    trial: bool,
    cb: Callback,
) -> c_int {
    if core_bn::cmp(w, &BigNum::one()).is_le() {
        return 0;
    }
    if !w.is_odd() {
        return c_int::from(w.is_word(2));
    }
    if w.is_word(3) {
        return 1;
    }
    if trial {
        for &p in PRIMES.iter().take(trial_divisions(w.num_bits())).skip(1) {
            if w.mod_word(c_ulong::from(p)) == 0 {
                return c_int::from(w.is_word(c_ulong::from(p)));
            }
        }
        // SAFETY: the caller's guarantee.
        if unsafe { call(cb, 1, -1) } == 0 {
            return -1;
        }
    }
    // SAFETY: as above.
    match unsafe { miller_rabin(w, checks, ctx, cb) } {
        Some(p) => c_int::from(p),
        None => -1,
    }
}

/// `ossl_bn_check_prime`: at least the minimum rounds for the size.
///
/// # Safety
/// `w` is NULL or a live `BIGNUM`; as for [`miller_rabin`].
unsafe fn check_prime(
    w: *const BIGNUM,
    checks: c_int,
    ctx: *mut BN_CTX,
    trial: bool,
    cb: Callback,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(v) = (unsafe { value(w) }) else {
        return -1;
    };
    let checks = checks.max(min_checks(v.num_bits()));
    // SAFETY: as above.
    unsafe { is_prime_int(&v, checks, ctx, trial, cb) }
}

ffi_export! {
    /// Whether `p` is probably prime (1), composite (0), or the test failed (-1): trial
    /// division, then Miller-Rabin with enough rounds for its size (random bases from the
    /// private generator), reporting to `cb`.
    ///
    /// # Safety
    /// `p` is NULL or a live `BIGNUM`; `ctx` is NULL or a live `BN_CTX`; `cb` is NULL or a live
    /// `BN_GENCB`.
    pub unsafe extern "C" fn BN_check_prime(p: *const BIGNUM, ctx: *mut BN_CTX, cb: *mut BN_GENCB) -> c_int
    where failure = -1, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { check_prime(p, 0, ctx, true, gencb(cb)) }
    }
}

ffi_export! {
    /// As `BN_check_prime` without trial division, with at least `checks` rounds.
    ///
    /// # Safety
    /// As for `BN_check_prime`.
    pub unsafe extern "C" fn BN_is_prime_ex(a: *const BIGNUM, checks: c_int, ctx: *mut BN_CTX, cb: *mut BN_GENCB) -> c_int
    where failure = -1, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { check_prime(a, checks, ctx, false, gencb(cb)) }
    }
}

ffi_export! {
    /// As `BN_is_prime_ex`, with trial division if `do_trial_division`.
    ///
    /// # Safety
    /// As for `BN_check_prime`.
    pub unsafe extern "C" fn BN_is_prime_fasttest_ex(w: *const BIGNUM, checks: c_int, ctx: *mut BN_CTX, do_trial_division: c_int, cb: *mut BN_GENCB) -> c_int
    where failure = -1, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { check_prime(w, checks, ctx, do_trial_division != 0, gencb(cb)) }
    }
}

ffi_export! {
    /// `BN_is_prime_ex` with an old-style callback (deprecated).
    ///
    /// # Safety
    /// As for `BN_check_prime`; `callback` is NULL or a function taking `cb_arg`.
    pub unsafe extern "C" fn BN_is_prime(a: *const BIGNUM, checks: c_int, callback: Option<OldCb>, ctx_passed: *mut BN_CTX, cb_arg: *mut c_void) -> c_int
    where failure = -1, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { check_prime(a, checks, ctx_passed, false, Callback::Old(callback, cb_arg)) }
    }
}

ffi_export! {
    /// `BN_is_prime_fasttest_ex` with an old-style callback (deprecated).
    ///
    /// # Safety
    /// As for `BN_is_prime`.
    pub unsafe extern "C" fn BN_is_prime_fasttest(a: *const BIGNUM, checks: c_int, callback: Option<OldCb>, ctx_passed: *mut BN_CTX, cb_arg: *mut c_void, do_trial_division: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { check_prime(a, checks, ctx_passed, do_trial_division != 0, Callback::Old(callback, cb_arg)) }
    }
}

/// `probable_prime`: a random odd `bits`-bit candidate (top two bits set) in `rnd`, stepped
/// past small factors (and, for a safe prime, past those of `(p-1)/2`). `false` on a
/// failure.
///
/// # Safety
/// `rnd` is a live `BIGNUM`; `ctx` is NULL or a live `BN_CTX`.
unsafe fn probable_prime(rnd: *mut BIGNUM, bits: c_int, safe: bool, ctx: *mut BN_CTX) -> bool {
    let nbits = usize::try_from(bits).unwrap_or(0);
    let td = trial_divisions(nbits);
    let last = c_ulong::from(PRIMES.get(td.wrapping_sub(1)).copied().unwrap_or(0));
    let maxdelta = c_ulong::MAX - last;
    loop {
        // SAFETY: the caller's guarantee.
        if unsafe { BN_priv_rand_ex(rnd, bits, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ODD, 0, ctx) } == 0 {
            return false;
        }
        // SAFETY: as above.
        let Some(mut v) = (unsafe { value(rnd) }) else {
            return false;
        };
        if safe && v.set_bit(1).is_err() {
            return false;
        }
        let Some(delta) = sieve(&v, nbits, td, safe, 2, maxdelta) else {
            continue;
        };
        if v.add_word(delta).is_err() {
            return false;
        }
        // SAFETY: as above.
        if !unsafe { store(rnd, v.clone()) } {
            return false;
        }
        if v.num_bits() == nbits {
            return true;
        }
    }
}

/// The sieve of `probable_prime` and `probable_prime_dh`: the smallest step (a multiple of
/// `step`, doubled for a safe prime with the plain step) that clears the small primes, or
/// `None` once it passes `maxdelta` (start again).
fn sieve(
    v: &BigNum,
    bits: usize,
    td: usize,
    safe: bool,
    step: c_ulong,
    maxdelta: c_ulong,
) -> Option<c_ulong> {
    let primes: Vec<c_ulong> = PRIMES
        .iter()
        .take(td)
        .skip(1)
        .map(|&p| c_ulong::from(p))
        .collect();
    let mods: Vec<c_ulong> = primes.iter().map(|&p| v.mod_word(p)).collect();
    let word = v.get_word();
    let inc = if safe && step == 2 { 4 } else { step };
    let mut delta: c_ulong = 0;
    'again: loop {
        for (&p, &m) in primes.iter().zip(&mods) {
            if bits <= 31 && delta <= 0x7fff_ffff && p.wrapping_mul(p) > word.wrapping_add(delta) {
                break;
            }
            let r = m.wrapping_add(delta) % p;
            if if safe { r <= 1 } else { r == 0 } {
                delta = delta.wrapping_add(inc);
                if delta > maxdelta {
                    return None;
                }
                continue 'again;
            }
        }
        return Some(delta);
    }
}

/// `probable_prime_dh`: a random `bits`-bit candidate (from the public generator) equal to
/// `rem` (or 1, or 3 for a safe prime) modulo `add`, stepped by `add` past small factors.
///
/// # Safety
/// `rnd`, `add`, and `rem` are live `BIGNUM`s or NULL (`rem`); `ctx` is NULL or a live
/// `BN_CTX`.
unsafe fn probable_prime_dh(
    rnd: *mut BIGNUM,
    bits: c_int,
    safe: bool,
    add: &BigNum,
    rem: Option<&BigNum>,
    ctx: *mut BN_CTX,
) -> bool {
    let nbits = usize::try_from(bits).unwrap_or(0);
    let td = trial_divisions(nbits);
    let last = c_ulong::from(PRIMES.get(td.wrapping_sub(1)).copied().unwrap_or(0));
    let maxdelta = (c_ulong::MAX - last).min(c_ulong::MAX - add.get_word());
    loop {
        // SAFETY: the caller's guarantee.
        if unsafe { BN_rand_ex(rnd, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD, 0, ctx) } == 0 {
            return false;
        }
        // SAFETY: as above.
        let Some(v) = (unsafe { value(rnd) }) else {
            return false;
        };
        let Ok((_, t1)) = core_bn::div_rem(&v, add) else {
            return false;
        };
        let Ok(mut v) = core_bn::sub(&v, &t1) else {
            return false;
        };
        let shifted = match rem {
            None => v.add_word(if safe { 3 } else { 1 }).map(|()| v.clone()),
            Some(r) => core_bn::add(&v, r),
        };
        let Ok(mut v) = shifted else { return false };
        if v.num_bits() < nbits || v.get_word() < if safe { 5 } else { 3 } {
            let Ok(sum) = core_bn::add(&v, add) else {
                return false;
            };
            v = sum;
        }
        let Some(delta) = sieve(&v, nbits, td, safe, add.get_word(), maxdelta) else {
            // SAFETY: as above.
            unsafe { store(rnd, v) };
            continue;
        };
        if v.add_word(delta).is_err() {
            return false;
        }
        // SAFETY: as above.
        return unsafe { store(rnd, v) };
    }
}

/// `BN_generate_prime_ex2`'s work, reporting to `cb`.
///
/// # Safety
/// `ret`, `add`, and `rem` are NULL or live `BIGNUM`s; `ctx` is NULL or a live `BN_CTX`; the
/// callback's pointers are live.
pub(crate) unsafe fn generate(
    ret: *mut BIGNUM,
    bits: c_int,
    safe: bool,
    add: *const BIGNUM,
    rem: *const BIGNUM,
    cb: Callback,
    ctx: *mut BN_CTX,
) -> c_int {
    const F: &str = "BN_generate_prime_ex2";
    if bits < 2 || (add.is_null() && safe && bits < 6 && bits != 3) {
        err::raise(ERR_LIB_BN, BN_R_BITS_TOO_SMALL, F);
        return 0;
    }
    // SAFETY: the caller's guarantee.
    if unsafe { bignum(ret) }.is_none() {
        return 0;
    }
    // SAFETY: as above.
    let add_v = unsafe { value(add) };
    // SAFETY: as above.
    let rem_v = unsafe { value(rem) };
    let checks = min_checks(usize::try_from(bits).unwrap_or(0));
    let mut c1: c_int = 0;
    loop {
        let ok = match &add_v {
            // SAFETY: as above.
            None => unsafe { probable_prime(ret, bits, safe, ctx) },
            // SAFETY: as above.
            Some(a) => unsafe { probable_prime_dh(ret, bits, safe, a, rem_v.as_ref(), ctx) },
        };
        if !ok {
            return 0;
        }
        // SAFETY: as above.
        if unsafe { call(cb, 0, c1) } == 0 {
            return 0;
        }
        c1 = c1.wrapping_add(1);
        // SAFETY: as above.
        let candidate = unsafe { value(ret) }.unwrap_or_default();
        if !safe {
            // SAFETY: as above.
            match unsafe { is_prime_int(&candidate, checks, ctx, false, cb) } {
                -1 => return 0,
                0 => continue,
                _ => return 1,
            }
        }
        let half = core_bn::rshift1(&candidate);
        let mut prime = true;
        for _ in 0..checks {
            // SAFETY: as above.
            match unsafe { is_prime_int(&candidate, 1, ctx, false, cb) } {
                -1 => return 0,
                0 => {
                    prime = false;
                    break;
                }
                _ => {}
            }
            // SAFETY: as above.
            match unsafe { is_prime_int(&half, 1, ctx, false, cb) } {
                -1 => return 0,
                0 => {
                    prime = false;
                    break;
                }
                _ => {}
            }
            // SAFETY: as above.
            if unsafe { call(cb, 2, c1.wrapping_sub(1)) } == 0 {
                return 0;
            }
        }
        if prime {
            return 1;
        }
    }
}

ffi_export! {
    /// A random prime of exactly `bits` bits into `ret` (a safe one, `(p-1)/2` prime too, if
    /// `safe`; `p = rem` modulo `add` if `add` is given), from `ctx`'s library context,
    /// reporting progress to `cb` (which may stop it). Returns 1, or 0.
    ///
    /// # Safety
    /// `ret`, `add`, and `rem` are NULL or live `BIGNUM`s; `cb` is NULL or a live `BN_GENCB`;
    /// `ctx` is NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn BN_generate_prime_ex2(ret: *mut BIGNUM, bits: c_int, safe: c_int, add: *const BIGNUM, rem: *const BIGNUM, cb: *mut BN_GENCB, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { generate(ret, bits, safe != 0, add, rem, gencb(cb), ctx) }
    }
}

ffi_export! {
    /// `BN_generate_prime_ex2` in the default library context.
    ///
    /// # Safety
    /// As for `BN_generate_prime_ex2`.
    pub unsafe extern "C" fn BN_generate_prime_ex(ret: *mut BIGNUM, bits: c_int, safe: c_int, add: *const BIGNUM, rem: *const BIGNUM, cb: *mut BN_GENCB) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { generate(ret, bits, safe != 0, add, rem, gencb(cb), ptr::null_mut()) }
    }
}

ffi_export! {
    /// `BN_generate_prime_ex` into `ret` (or a new number if NULL) with an old-style callback
    /// (deprecated). Returns the number, or NULL; a new number is freed on failure, `ret` is
    /// left to its owner.
    ///
    /// # Safety
    /// As for `BN_generate_prime_ex`; `callback` is NULL or a function taking `cb_arg`.
    pub unsafe extern "C" fn BN_generate_prime(ret: *mut BIGNUM, bits: c_int, safe: c_int, add: *const BIGNUM, rem: *const BIGNUM, callback: Option<OldCb>, cb_arg: *mut c_void) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        let rnd = if ret.is_null() { new_bignum(BigNum::zero(), false) } else { ret };
        // SAFETY: the caller's guarantee.
        if unsafe { generate(rnd, bits, safe != 0, add, rem, Callback::Old(callback, cb_arg), ptr::null_mut()) } == 1 {
            return rnd;
        }
        if ret.is_null() {
            // SAFETY: ours to free.
            unsafe { BN_free(rnd) };
        }
        ptr::null_mut()
    }
}

/// `bn_x931_derive_pi`: the first probable prime from `xpi` (made odd) up.
///
/// # Safety
/// `pi` and `xpi` are live `BIGNUM`s; `ctx` is NULL or a live `BN_CTX`; the callback's
/// pointers are live.
unsafe fn derive_pi(
    pi: *mut BIGNUM,
    xpi: *const BIGNUM,
    ctx: *mut BN_CTX,
    cb: *mut BN_GENCB,
) -> bool {
    // SAFETY: the caller's guarantee.
    if unsafe { BN_copy(pi, xpi) }.is_null() {
        return false;
    }
    // SAFETY: as above.
    if unsafe { BN_is_odd(pi) } == 0 && unsafe { BN_add_word(pi, 1) } == 0 {
        return false;
    }
    let mut i: c_int = 0;
    loop {
        i = i.wrapping_add(1);
        // SAFETY: as above.
        unsafe { call(gencb(cb), 0, i) };
        // SAFETY: as above.
        let r = unsafe { BN_check_prime(pi, ctx, cb) };
        if r < 0 {
            return false;
        }
        if r != 0 {
            break;
        }
        // SAFETY: as above.
        if unsafe { BN_add_word(pi, 2) } == 0 {
            return false;
        }
    }
    // SAFETY: as above.
    unsafe { call(gencb(cb), 2, i) };
    true
}

ffi_export! {
    /// The X9.31 prime `p` from its auxiliary primes (derived from `xp1` and `xp2`, into `p1`
    /// and `p2` unless NULL) and `xp`, with `gcd(p - 1, e) = 1` for an odd `e` (an even one
    /// fails). Returns 1, or 0.
    ///
    /// # Safety
    /// The numbers are NULL or live `BIGNUM`s; `ctx` is NULL or a live `BN_CTX`; `cb` is NULL or
    /// a live `BN_GENCB`.
    pub unsafe extern "C" fn BN_X931_derive_prime_ex(p: *mut BIGNUM, p1: *mut BIGNUM, p2: *mut BIGNUM, xp: *const BIGNUM, xp1: *const BIGNUM, xp2: *const BIGNUM, e: *const BIGNUM, ctx: *mut BN_CTX, cb: *mut BN_GENCB) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        if unsafe { BN_is_odd(e) } == 0 {
            return 0;
        }
        let (tp1, tp2, t, p1p2, pm1) = (Temp::new(), Temp::new(), Temp::new(), Temp::new(), Temp::new());
        let p1 = if p1.is_null() { tp1.0 } else { p1 };
        let p2 = if p2.is_null() { tp2.0 } else { p2 };
        // SAFETY: the caller's numbers and ours, here and below.
        let ok = unsafe { derive_pi(p1, xp1, ctx, cb) }
            // SAFETY: as above.
            && unsafe { derive_pi(p2, xp2, ctx, cb) }
            // SAFETY: as above.
            && unsafe { BN_mul(p1p2.0, p1, p2, ctx) } != 0
            // SAFETY: as above.
            && !unsafe { BN_mod_inverse(p, p2, p1, ctx) }.is_null()
            // SAFETY: as above.
            && unsafe { BN_mul(p, p, p2, ctx) } != 0
            // SAFETY: as above.
            && !unsafe { BN_mod_inverse(t.0, p1, p2, ctx) }.is_null()
            // SAFETY: as above.
            && unsafe { BN_mul(t.0, t.0, p1, ctx) } != 0
            // SAFETY: as above.
            && unsafe { BN_sub(p, p, t.0) } != 0;
        if !ok {
            return 0;
        }
        // SAFETY: as above.
        if unsafe { value(p) }.is_some_and(|v| v.is_negative()) && unsafe { BN_add(p, p, p1p2.0) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        if unsafe { BN_mod_sub(p, p, xp, p1p2.0, ctx) } == 0 || unsafe { BN_add(p, p, xp) } == 0 {
            return 0;
        }
        loop {
            // SAFETY: as above.
            unsafe { call(gencb(cb), 0, 1) };
            // SAFETY: as above.
            if unsafe { BN_copy(pm1.0, p) }.is_null() || unsafe { BN_sub_word(pm1.0, 1) } == 0 {
                return 0;
            }
            // SAFETY: as above.
            if unsafe { BN_gcd(t.0, pm1.0, e, ctx) } == 0 {
                return 0;
            }
            // SAFETY: as above.
            if unsafe { BN_is_one(t.0) } != 0 {
                // SAFETY: as above.
                let r = unsafe { BN_check_prime(p, ctx, cb) };
                if r < 0 {
                    return 0;
                }
                if r != 0 {
                    break;
                }
            }
            // SAFETY: as above.
            if unsafe { BN_add(p, p, p1p2.0) } == 0 {
                return 0;
            }
        }
        // SAFETY: as above.
        unsafe { call(gencb(cb), 3, 0) };
        1
    }
}

ffi_export! {
    /// Random `xp` and `xq` of half of `nbits` bits each (top two bits set) more than
    /// `2^(nbits/2 - 100)` apart, from the private generator; `nbits` is at least 1024 and a
    /// multiple of 256. Returns 1, or 0.
    ///
    /// # Safety
    /// `xp` and `xq` are NULL or live `BIGNUM`s; `ctx` is NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn BN_X931_generate_Xpq(xp: *mut BIGNUM, xq: *mut BIGNUM, nbits: c_int, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        if nbits < 1024 || nbits & 0xff != 0 {
            return 0;
        }
        let half = nbits >> 1;
        // SAFETY: the caller's guarantee.
        if unsafe { BN_priv_rand_ex(xp, half, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY, 0, ctx) } == 0 {
            return 0;
        }
        let t = Temp::new();
        for _ in 0..1000 {
            // SAFETY: as above.
            if unsafe { BN_priv_rand_ex(xq, half, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY, 0, ctx) } == 0 {
                return 0;
            }
            // SAFETY: as above; `t` is ours.
            if unsafe { BN_sub(t.0, xp, xq) } == 0 {
                return 0;
            }
            if i64::try_from(t.value().num_bits()).unwrap_or(0) > i64::from(half) - 100 {
                return 1;
            }
        }
        0
    }
}

ffi_export! {
    /// An X9.31 prime: random 101-bit `xp1` and `xp2` (into the given numbers unless NULL),
    /// then `BN_X931_derive_prime_ex`. Returns 1, or 0.
    ///
    /// # Safety
    /// As for `BN_X931_derive_prime_ex`.
    pub unsafe extern "C" fn BN_X931_generate_prime_ex(p: *mut BIGNUM, p1: *mut BIGNUM, p2: *mut BIGNUM, xp1: *mut BIGNUM, xp2: *mut BIGNUM, xp: *const BIGNUM, e: *const BIGNUM, ctx: *mut BN_CTX, cb: *mut BN_GENCB) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let (t1, t2) = (Temp::new(), Temp::new());
        let x1 = if xp1.is_null() { t1.0 } else { xp1 };
        let x2 = if xp2.is_null() { t2.0 } else { xp2 };
        // SAFETY: the caller's numbers or ours.
        if unsafe { BN_priv_rand_ex(x1, 101, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY, 0, ctx) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        if unsafe { BN_priv_rand_ex(x2, 101, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY, 0, ctx) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        unsafe { BN_X931_derive_prime_ex(p, p1, p2, xp, x1, x2, e, ctx, cb) }
    }
}
