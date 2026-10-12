//! Arithmetic (`BN_add(3)`, `BN_add_word(3)`, `BN_set_bit(3)`'s shifts): signed and unsigned
//! addition and subtraction, multiplication, truncating division, `BN_nnmod`, powers, shifts,
//! and the one-word forms.
//!
//! The `BN_CTX` OpenSSL takes for temporaries isn't needed (and may be NULL).

use core::ffi::{c_int, c_ulong};
use core::ptr;

use rustyssl_abi::{
    BIGNUM, BN_CTX, BN_FLG_CONSTTIME, BN_R_INVALID_SHIFT, ERR_LIB_BN,
    ERR_R_PASSED_INVALID_ARGUMENT, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,
};
use rustyssl_crypto::bn::{self as core_bn, BigNum, Error};

use super::{bignum, raise, set_result, store, value};
use crate::err;
use crate::ffi::ffi_export;

/// Defines the two-operand operations `r = f(a, b)`.
macro_rules! binary {
    ($( $(#[$attr:meta])* pub unsafe extern "C" fn $name:ident($($ctx:ident)?) = $f:path; )*) => {$(
        ffi_export! {
            $(#[$attr])*
            /// Returns 1, or 0. `r` may be `a` or `b`.
            ///
            /// # Safety
            /// `r`, `a`, and `b` are NULL or live `BIGNUM`s.
            pub unsafe extern "C" fn $name(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM $(, $ctx: *mut BN_CTX)?) -> c_int
            where failure = 0, library = ERR_LIB_BN
            {
                $(let _ = $ctx;)?
                // SAFETY: the caller's guarantee.
                let (Some(x), Some(y)) = (unsafe { value(a) }, unsafe { value(b) }) else { return 0 };
                // SAFETY: as above.
                unsafe { set_result(r, $f(&x, &y)) }
            }
        }
    )*};
}

binary! {
    /// `r = a + b`.
    pub unsafe extern "C" fn BN_add() = core_bn::add;
    /// `r = a - b`.
    pub unsafe extern "C" fn BN_sub() = core_bn::sub;
    /// `r = |a| + |b|`.
    pub unsafe extern "C" fn BN_uadd() = core_bn::uadd;
    /// `r = |a| - |b|`, for `|a| >= |b|` (fails if `b` has more words; wraps if it's larger
    /// with as many).
    pub unsafe extern "C" fn BN_usub() = core_bn::usub;
    /// `r = a * b`.
    pub unsafe extern "C" fn BN_mul(ctx) = core_bn::mul;
}

ffi_export! {
    /// `r = a * a`; 1, or 0.
    ///
    /// # Safety
    /// `r` and `a` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_sqr(r: *mut BIGNUM, a: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { value(a) }) else { return 0 };
        // SAFETY: as above.
        unsafe { set_result(r, core_bn::sqr(&x)) }
    }
}

ffi_export! {
    /// Divides `m` by `d`, truncating: the quotient into `dv` and the remainder (with `m`'s
    /// sign) into `rem`, each unless NULL. Returns 1, or 0 (`d` zero raises
    /// `BN_R_DIV_BY_ZERO`).
    ///
    /// # Safety
    /// `dv` and `rem` are NULL or live `BIGNUM`s, not the same one; `m` and `d` are NULL or
    /// live `BIGNUM`s.
    pub unsafe extern "C" fn BN_div(dv: *mut BIGNUM, rem: *mut BIGNUM, m: *const BIGNUM, d: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(y)) = (unsafe { value(m) }, unsafe { value(d) }) else { return 0 };
        let (q, r) = match core_bn::div_rem(&x, &y) {
            Ok(qr) => qr,
            Err(e) => {
                raise(e);
                return 0;
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
        1
    }
}

ffi_export! {
    /// `r = m mod |d|`, in `[0, |d|)`; 1, or 0. `r` may not be `d`
    /// (`ERR_R_PASSED_INVALID_ARGUMENT`).
    ///
    /// # Safety
    /// `r`, `m`, and `d` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_nnmod(r: *mut BIGNUM, m: *const BIGNUM, d: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        if ptr::eq(r, d) {
            err::raise(ERR_LIB_BN, ERR_R_PASSED_INVALID_ARGUMENT, "BN_nnmod");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(y)) = (unsafe { value(m) }, unsafe { value(d) }) else { return 0 };
        // SAFETY: as above.
        unsafe { set_result(r, core_bn::nnmod(&x, &y)) }
    }
}

ffi_export! {
    /// `r = a^|p|`; 1, or 0. Numbers flagged `BN_FLG_CONSTTIME` are refused, as only
    /// `BN_mod_exp_mont` takes them.
    ///
    /// # Safety
    /// `r`, `a`, and `p` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_exp(r: *mut BIGNUM, a: *const BIGNUM, p: *const BIGNUM, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let _ = ctx;
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(y)) = (unsafe { bignum(a) }, unsafe { bignum(p) }) else { return 0 };
        let (x, y) = (x.state(), y.state());
        if (x.flags | y.flags) & BN_FLG_CONSTTIME != 0 {
            err::raise(ERR_LIB_BN, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, "BN_exp");
            return 0;
        }
        // SAFETY: as above.
        unsafe { set_result(r, core_bn::exp(&x.value, &y.value)) }
    }
}

/// A shift count from C, raising `BN_R_INVALID_SHIFT` for a negative one.
fn shift(n: c_int, function: &str) -> Option<usize> {
    let s = usize::try_from(n).ok();
    if s.is_none() {
        err::raise(ERR_LIB_BN, BN_R_INVALID_SHIFT, function);
    }
    s
}

ffi_export! {
    /// `r = a * 2^n`; 1, or 0 (a negative `n` raises `BN_R_INVALID_SHIFT`).
    ///
    /// # Safety
    /// `r` and `a` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_lshift(r: *mut BIGNUM, a: *const BIGNUM, n: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let Some(n) = shift(n, "BN_lshift") else { return 0 };
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { value(a) }) else { return 0 };
        // SAFETY: as above.
        unsafe { set_result(r, core_bn::lshift(&x, n)) }
    }
}

ffi_export! {
    /// `r = a / 2^n`, the magnitude shifted; 1, or 0 (a negative `n` raises
    /// `BN_R_INVALID_SHIFT`).
    ///
    /// # Safety
    /// `r` and `a` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_rshift(r: *mut BIGNUM, a: *const BIGNUM, n: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        let Some(n) = shift(n, "BN_rshift") else { return 0 };
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { value(a) }) else { return 0 };
        // SAFETY: as above.
        unsafe { set_result(r, Ok(core_bn::rshift(&x, n))) }
    }
}

ffi_export! {
    /// `r = a * 2`; 1, or 0.
    ///
    /// # Safety
    /// `r` and `a` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_lshift1(r: *mut BIGNUM, a: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { value(a) }) else { return 0 };
        // SAFETY: as above.
        unsafe { set_result(r, core_bn::lshift1(&x)) }
    }
}

ffi_export! {
    /// `r = a / 2`, the magnitude shifted; 1, or 0.
    ///
    /// # Safety
    /// `r` and `a` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_rshift1(r: *mut BIGNUM, a: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { value(a) }) else { return 0 };
        // SAFETY: as above.
        unsafe { set_result(r, Ok(core_bn::rshift1(&x))) }
    }
}

/// Changes `a` in place with `f`: 1, or 0 (with the error raised).
///
/// # Safety
/// `a` is NULL or a live `BIGNUM`.
unsafe fn in_place(a: *mut BIGNUM, f: impl FnOnce(&mut BigNum) -> Result<(), Error>) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(b) = (unsafe { bignum(a) }) else {
        return 0;
    };
    match b.update(f) {
        Some(Ok(())) => 1,
        Some(Err(e)) => {
            raise(e);
            0
        }
        None => 0,
    }
}

ffi_export! {
    /// `a += w`; 1, or 0.
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_add_word(a: *mut BIGNUM, w: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { in_place(a, |v| v.add_word(w)) }
    }
}

ffi_export! {
    /// `a -= w`; 1, or 0.
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_sub_word(a: *mut BIGNUM, w: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { in_place(a, |v| v.sub_word(w)) }
    }
}

ffi_export! {
    /// `a *= w`; 1, or 0.
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_mul_word(a: *mut BIGNUM, w: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { in_place(a, |v| v.mul_word(w)) }
    }
}

ffi_export! {
    /// `a /= w`, truncating; returns the magnitude's remainder, or all ones (with `a`
    /// unchanged) for a zero `w`.
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_div_word(a: *mut BIGNUM, w: c_ulong) -> c_ulong
    where failure = c_ulong::MAX, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { bignum(a) }) else { return c_ulong::MAX };
        if w == 0 {
            return c_ulong::MAX;
        }
        b.update(|v| v.div_word(w)).unwrap_or(c_ulong::MAX)
    }
}

ffi_export! {
    /// The magnitude of `a` modulo `w`, or all ones for a zero `w`.
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_mod_word(a: *const BIGNUM, w: c_ulong) -> c_ulong
    where failure = c_ulong::MAX, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { value(a) }.map_or(c_ulong::MAX, |v| v.mod_word(w))
    }
}
