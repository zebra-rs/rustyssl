//! Random numbers (`BN_rand(3)`; `bn_rand.c`): octets from the RAND layer, drawn as OpenSSL
//! draws them (so a seeded generator gives the same numbers), shaped by the top and bottom
//! settings; and numbers below a range, by rejection.

use core::cmp::Ordering;
use core::ffi::{c_int, c_uint};
use core::ptr;

use rustyssl_abi::{
    BIGNUM, BN_CTX, BN_R_BITS_TOO_SMALL, BN_R_INVALID_RANGE, BN_R_TOO_MANY_ITERATIONS,
    BN_RAND_BOTTOM_ANY, BN_RAND_TOP_ANY, ERR_LIB_BN, ERR_R_PASSED_NULL_PARAMETER, OSSL_LIB_CTX,
};
use rustyssl_crypto::bn::{self as core_bn, BigNum, Endian, Zeroizing};

use super::{bignum, libctx_of, raise, store, value};
use crate::err;
use crate::ffi::ffi_export;
use crate::rand_lib::{RAND_bytes_ex, RAND_priv_bytes_ex};

/// Which generator, and whether to skew the octets toward patterns that find bugs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Flag {
    Normal,
    Testing,
    Private,
}

/// `num` octets from the public (or private) generator; `false` if it failed.
fn draw(libctx: *mut OSSL_LIB_CTX, buf: &mut [u8], private: bool, strength: c_uint) -> bool {
    let f = if private {
        RAND_priv_bytes_ex
    } else {
        RAND_bytes_ex
    };
    // SAFETY: `buf` has room for its length.
    (unsafe { f(libctx, buf.as_mut_ptr(), buf.len(), strength) }) > 0
}

/// `bnrand`: a random number of `bits` bits into `rnd`; 1, or 0.
///
/// # Safety
/// `rnd` is NULL or a live `BIGNUM`; `ctx` is NULL or a live `BN_CTX`.
unsafe fn bnrand(
    flag: Flag,
    rnd: *mut BIGNUM,
    bits: c_int,
    top: c_int,
    bottom: c_int,
    strength: c_uint,
    ctx: *mut BN_CTX,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let libctx = unsafe { libctx_of(ctx) };
    if bits == 0 {
        if top != BN_RAND_TOP_ANY || bottom != BN_RAND_BOTTOM_ANY {
            err::raise(ERR_LIB_BN, BN_R_BITS_TOO_SMALL, "bnrand");
            return 0;
        }
        // SAFETY: as above.
        return c_int::from(rnd.is_null() || unsafe { store(rnd, BigNum::zero()) });
    }
    let Ok(nbits) = usize::try_from(bits) else {
        err::raise(ERR_LIB_BN, BN_R_BITS_TOO_SMALL, "bnrand");
        return 0;
    };
    if nbits == 1 && top > 0 {
        err::raise(ERR_LIB_BN, BN_R_BITS_TOO_SMALL, "bnrand");
        return 0;
    }
    let bytes = nbits.div_ceil(8);
    let bit = (nbits - 1) % 8;
    let mut buf = Zeroizing::new(vec![0u8; bytes]);
    if !draw(libctx, &mut buf, flag != Flag::Normal, strength) {
        return 0;
    }
    if flag == Flag::Testing {
        // Runs of equal, zero, and all-one octets.
        for i in 0..bytes {
            let mut c = [0u8];
            if !draw(libctx, &mut c, false, strength) {
                return 0;
            }
            let prev = i.checked_sub(1).and_then(|j| buf.get(j).copied());
            let new = match (c[0], prev) {
                (128.., Some(p)) => Some(p),
                (..42, _) => Some(0),
                (..84, _) => Some(255),
                _ => None,
            };
            if let (Some(v), Some(slot)) = (new, buf.get_mut(i)) {
                *slot = v;
            }
        }
    }
    if top >= 0 {
        if top != 0 {
            if bit == 0 {
                if let Some(b) = buf.get_mut(0) {
                    *b = 1;
                }
                if let Some(b) = buf.get_mut(1) {
                    *b |= 0x80;
                }
            } else if let Some(b) = buf.get_mut(0) {
                *b |= 3 << (bit - 1);
            }
        } else if let Some(b) = buf.get_mut(0) {
            *b |= 1 << bit;
        }
    }
    if let Some(b) = buf.get_mut(0) {
        *b &= !0xffu8
            .checked_shl(u32::try_from(bit + 1).unwrap_or(8))
            .unwrap_or(0);
    }
    if bottom != 0
        && let Some(b) = buf.last_mut()
    {
        *b |= 1;
    }
    let v = match BigNum::from_bin(&buf, Endian::Big, false) {
        Ok(v) => v,
        Err(e) => {
            raise(e);
            return 0;
        }
    };
    // OpenSSL makes (and leaks) a new number for a NULL `rnd`, and succeeds.
    // SAFETY: as above.
    c_int::from(rnd.is_null() || unsafe { store(rnd, v) })
}

/// `bnrand_range`: a random number in `[0, range)` into `r`; 1, or 0.
///
/// # Safety
/// `r` and `range` are NULL or live `BIGNUM`s; `ctx` is NULL or a live `BN_CTX`.
unsafe fn bnrand_range(
    flag: Flag,
    r: *mut BIGNUM,
    range: *const BIGNUM,
    strength: c_uint,
    ctx: *mut BN_CTX,
) -> c_int {
    const F: &str = "bnrand_range";
    // SAFETY: the caller's guarantee.
    let (Some(out), Some(range)) = (unsafe { bignum(r) }, unsafe { value(range) }) else {
        err::raise(ERR_LIB_BN, ERR_R_PASSED_NULL_PARAMETER, F);
        return 0;
    };
    if range.is_negative() || range.is_zero() {
        err::raise(ERR_LIB_BN, BN_R_INVALID_RANGE, F);
        return 0;
    }
    let n = range.num_bits();
    if n == 1 {
        return c_int::from(out.store(BigNum::zero()));
    }
    let three = !range.is_bit_set(n.wrapping_sub(2)) && !range.is_bit_set(n.wrapping_sub(3));
    let bits = c_int::try_from(if three { n.saturating_add(1) } else { n }).unwrap_or(c_int::MAX);
    let mut count = 100;
    loop {
        // SAFETY: as above.
        if unsafe {
            bnrand(
                flag,
                r,
                bits,
                BN_RAND_TOP_ANY,
                BN_RAND_BOTTOM_ANY,
                strength,
                ctx,
            )
        } == 0
        {
            return 0;
        }
        let mut v = out.value();
        if three {
            // `range` is 100..., so `3 * range` is 11... and one bit longer: take `v mod range`
            // when `v` is below it.
            for _ in 0..2 {
                if core_bn::cmp(&v, &range) != Ordering::Less {
                    v = match core_bn::sub(&v, &range) {
                        Ok(d) => d,
                        Err(e) => {
                            raise(e);
                            return 0;
                        }
                    };
                }
            }
            if !out.store(v.clone()) {
                return 0;
            }
        }
        count -= 1;
        if count == 0 {
            err::raise(ERR_LIB_BN, BN_R_TOO_MANY_ITERATIONS, F);
            return 0;
        }
        if core_bn::cmp(&v, &range) == Ordering::Less {
            return 1;
        }
    }
}

ffi_export! {
    /// A random number of `bits` bits: its top bit set (`top` 0), its top two (1), or neither
    /// (-1); odd if `bottom`. Draws on `ctx`'s library context's public generator, asking for
    /// `strength` bits of security. Returns 1, or 0.
    ///
    /// # Safety
    /// `rnd` is NULL or a live `BIGNUM`; `ctx` is NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn BN_rand_ex(rnd: *mut BIGNUM, bits: c_int, top: c_int, bottom: c_int, strength: c_uint, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { bnrand(Flag::Normal, rnd, bits, top, bottom, strength, ctx) }
    }
}

ffi_export! {
    /// As `BN_rand_ex`, from the default library context.
    ///
    /// # Safety
    /// `rnd` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_rand(rnd: *mut BIGNUM, bits: c_int, top: c_int, bottom: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { bnrand(Flag::Normal, rnd, bits, top, bottom, 0, ptr::null_mut()) }
    }
}

ffi_export! {
    /// As `BN_rand` (deprecated).
    ///
    /// # Safety
    /// `rnd` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_pseudo_rand(rnd: *mut BIGNUM, bits: c_int, top: c_int, bottom: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { bnrand(Flag::Normal, rnd, bits, top, bottom, 0, ptr::null_mut()) }
    }
}

ffi_export! {
    /// As `BN_rand`, from the private generator, with octets skewed toward runs of equal, zero,
    /// and all-one octets (each decided by one more octet from the public generator).
    ///
    /// # Safety
    /// `rnd` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_bntest_rand(rnd: *mut BIGNUM, bits: c_int, top: c_int, bottom: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { bnrand(Flag::Testing, rnd, bits, top, bottom, 0, ptr::null_mut()) }
    }
}

ffi_export! {
    /// As `BN_rand_ex`, from the private generator.
    ///
    /// # Safety
    /// `rnd` is NULL or a live `BIGNUM`; `ctx` is NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn BN_priv_rand_ex(rnd: *mut BIGNUM, bits: c_int, top: c_int, bottom: c_int, strength: c_uint, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { bnrand(Flag::Private, rnd, bits, top, bottom, strength, ctx) }
    }
}

ffi_export! {
    /// As `BN_rand`, from the private generator.
    ///
    /// # Safety
    /// `rnd` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_priv_rand(rnd: *mut BIGNUM, bits: c_int, top: c_int, bottom: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { bnrand(Flag::Private, rnd, bits, top, bottom, 0, ptr::null_mut()) }
    }
}

ffi_export! {
    /// A random number in `[0, range)` from `ctx`'s library context's public generator (at
    /// most 100 tries). Returns 1, or 0.
    ///
    /// # Safety
    /// `r` and `range` are NULL or live `BIGNUM`s; `ctx` is NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn BN_rand_range_ex(r: *mut BIGNUM, range: *const BIGNUM, strength: c_uint, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { bnrand_range(Flag::Normal, r, range, strength, ctx) }
    }
}

ffi_export! {
    /// As `BN_rand_range_ex`, from the default library context.
    ///
    /// # Safety
    /// `r` and `range` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_rand_range(r: *mut BIGNUM, range: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { bnrand_range(Flag::Normal, r, range, 0, ptr::null_mut()) }
    }
}

ffi_export! {
    /// As `BN_rand_range` (deprecated).
    ///
    /// # Safety
    /// `r` and `range` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_pseudo_rand_range(r: *mut BIGNUM, range: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { bnrand_range(Flag::Normal, r, range, 0, ptr::null_mut()) }
    }
}

ffi_export! {
    /// As `BN_rand_range_ex`, from the private generator.
    ///
    /// # Safety
    /// `r` and `range` are NULL or live `BIGNUM`s; `ctx` is NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn BN_priv_rand_range_ex(r: *mut BIGNUM, range: *const BIGNUM, strength: c_uint, ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { bnrand_range(Flag::Private, r, range, strength, ctx) }
    }
}

ffi_export! {
    /// As `BN_rand_range`, from the private generator.
    ///
    /// # Safety
    /// `r` and `range` are NULL or live `BIGNUM`s.
    pub unsafe extern "C" fn BN_priv_rand_range(r: *mut BIGNUM, range: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { bnrand_range(Flag::Private, r, range, 0, ptr::null_mut()) }
    }
}
