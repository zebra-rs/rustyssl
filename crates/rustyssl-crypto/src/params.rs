//! The value conversions of `OSSL_PARAM(3)` (`crypto/params.c`): reading a parameter's integer
//! or real as another width or signedness, and what writing one into a parameter of a given type
//! and size stores and reports in `return_size`.
//!
//! A parameter's data is in the platform's byte order, as OpenSSL keeps it. Getters take the
//! data as a slice (`None` for a NULL pointer); setters say what to store, and the C layer
//! writes it, so no reference to the caller's buffer is made here.
//!
//! Integers of other sizes than 4 and 8 octets are converted as OpenSSL's `copy_integer` does:
//! sign-extended or zero-padded when widening, and narrowed only if the dropped octets are
//! padding and, for a signed result, the sign is kept.

use rustyssl_abi as abi;

/// `OSSL_PARAM_INTEGER`.
pub const INTEGER: u32 = abi::OSSL_PARAM_INTEGER.cast_unsigned();
/// `OSSL_PARAM_UNSIGNED_INTEGER`.
pub const UNSIGNED_INTEGER: u32 = abi::OSSL_PARAM_UNSIGNED_INTEGER.cast_unsigned();
/// `OSSL_PARAM_REAL`.
pub const REAL: u32 = abi::OSSL_PARAM_REAL.cast_unsigned();
/// `OSSL_PARAM_UTF8_STRING`.
pub const UTF8_STRING: u32 = abi::OSSL_PARAM_UTF8_STRING.cast_unsigned();
/// `OSSL_PARAM_OCTET_STRING`.
pub const OCTET_STRING: u32 = abi::OSSL_PARAM_OCTET_STRING.cast_unsigned();
/// `OSSL_PARAM_UTF8_PTR`.
pub const UTF8_PTR: u32 = abi::OSSL_PARAM_UTF8_PTR.cast_unsigned();
/// `OSSL_PARAM_OCTET_PTR`.
pub const OCTET_PTR: u32 = abi::OSSL_PARAM_OCTET_PTR.cast_unsigned();

/// The mantissa bits of a `double`: integers below `1 << REAL_SHIFT` convert exactly.
const REAL_SHIFT: u32 = f64::MANTISSA_DIGITS;

/// Why a conversion failed: OpenSSL's `CRYPTO_R_*` reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// `ERR_R_PASSED_NULL_PARAMETER`.
    NullArgument,
    /// `CRYPTO_R_PARAM_UNSIGNED_INTEGER_NEGATIVE_VALUE_UNSUPPORTED`.
    UnsignedNegative,
    /// `CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION`.
    OutOfRange,
    /// `CRYPTO_R_PARAM_CANNOT_BE_REPRESENTED_EXACTLY`.
    Inexact,
    /// `CRYPTO_R_PARAM_NOT_INTEGER_TYPE`.
    NotInteger,
    /// `CRYPTO_R_TOO_SMALL_BUFFER`.
    TooSmall,
    /// `CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE`.
    BadType,
    /// `CRYPTO_R_PARAM_UNSUPPORTED_FLOATING_POINT_FORMAT`.
    UnsupportedReal,
}

/// What a setter does to a parameter: the `return_size` it leaves, and on success the octets
/// to store in its data (`None` when the data pointer is NULL, a size query).
#[derive(Debug, Clone, PartialEq)]
pub struct Set {
    /// The parameter's new `return_size`, set on failure too.
    pub return_size: usize,
    /// The data to store, exactly `data_size` octets, or why nothing is stored.
    pub result: Result<Option<Vec<u8>>, Error>,
}

impl Set {
    fn ok(return_size: usize, data: Option<Vec<u8>>) -> Self {
        Self {
            return_size,
            result: Ok(data),
        }
    }

    fn err(return_size: usize, error: Error) -> Self {
        Self {
            return_size,
            result: Err(error),
        }
    }
}

/// The parameter a setter writes to: its type, its `data_size`, and whether its data pointer
/// is NULL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    /// `data_type`.
    pub data_type: u32,
    /// `data_size`.
    pub data_size: usize,
    /// `data == NULL`.
    pub null: bool,
}

/// Float and integer conversions as C's casts make them where OpenSSL range-checks first.
mod real {
    /// `(double)v` for a 64-bit integer: the nearest `double`.
    #[expect(
        clippy::cast_precision_loss,
        reason = "C's conversion, rounding to nearest"
    )]
    pub(super) fn from_i64(v: i64) -> f64 {
        v as f64
    }

    /// `(double)v` for an unsigned 64-bit integer.
    #[expect(
        clippy::cast_precision_loss,
        reason = "C's conversion, rounding to nearest"
    )]
    pub(super) fn from_u64(v: u64) -> f64 {
        v as f64
    }

    /// `(int32_t)d`, saturating where C's is undefined.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "truncation toward zero is the point"
    )]
    pub(super) fn to_i32(d: f64) -> i32 {
        d as i32
    }

    /// `(uint32_t)d`, saturating where C's is undefined.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "truncation toward zero is the point"
    )]
    pub(super) fn to_u32(d: f64) -> u32 {
        d as u32
    }

    /// `(int64_t)d`, saturating where C's is undefined.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "truncation toward zero is the point"
    )]
    pub(super) fn to_i64(d: f64) -> i64 {
        d as i64
    }

    /// `(uint64_t)d`, saturating where C's is undefined.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "truncation toward zero is the point"
    )]
    pub(super) fn to_u64(d: f64) -> u64 {
        d as u64
    }
}

/// 2^31, 2^32, 2^63, and 2^64 as `double`s.
const POW_31: f64 = 2_147_483_648.0;
const POW_32: f64 = 4_294_967_296.0;
const POW_63: f64 = 9_223_372_036_854_775_808.0;
const POW_64: f64 = 18_446_744_073_709_551_616.0;

/// The octets of a native integer, least significant first.
fn little(native: &[u8]) -> Vec<u8> {
    let mut v = native.to_vec();
    if cfg!(target_endian = "big") {
        v.reverse();
    }
    v
}

/// The native order of octets given least significant first.
fn native(mut little: Vec<u8>) -> Vec<u8> {
    if cfg!(target_endian = "big") {
        little.reverse();
    }
    little
}

/// `is_negative`: the sign bit of a native integer. An empty one is zero (OpenSSL reads the
/// octet before it).
fn is_negative(n: &[u8]) -> bool {
    little(n).last().is_some_and(|&b| b & 0x80 != 0)
}

/// `copy_integer`: `src` as a `dest_len`-octet integer, padded with `pad`; narrowing fails
/// (`OutOfRange`) if a dropped octet isn't `pad` or, for a signed result, the sign changes. A
/// zero-octet result holds only zero (OpenSSL reads the octet before the source for the sign).
fn copy_integer(dest_len: usize, src: &[u8], pad: u8, signed: bool) -> Result<Vec<u8>, Error> {
    let src = little(src);
    if src.len() < dest_len {
        let mut out = src;
        out.resize(dest_len, pad);
        return Ok(native(out));
    }
    let (kept, dropped) = src.split_at(dest_len);
    let top = kept.last().copied().unwrap_or(0);
    if dropped.iter().any(|&b| b != pad) || (signed && (pad ^ top) & 0x80 != 0) {
        return Err(Error::OutOfRange);
    }
    Ok(native(kept.to_vec()))
}

fn signed_from_signed(dest_len: usize, src: &[u8]) -> Result<Vec<u8>, Error> {
    let pad = if is_negative(src) { 0xff } else { 0 };
    copy_integer(dest_len, src, pad, true)
}

fn signed_from_unsigned(dest_len: usize, src: &[u8]) -> Result<Vec<u8>, Error> {
    copy_integer(dest_len, src, 0, true)
}

fn unsigned_from_signed(dest_len: usize, src: &[u8]) -> Result<Vec<u8>, Error> {
    if is_negative(src) {
        return Err(Error::UnsignedNegative);
    }
    copy_integer(dest_len, src, 0, false)
}

fn unsigned_from_unsigned(dest_len: usize, src: &[u8]) -> Result<Vec<u8>, Error> {
    copy_integer(dest_len, src, 0, false)
}

/// `general_get_int`: the data as a signed integer of `N` octets.
fn general_get_int<const N: usize>(data_type: u32, data: &[u8]) -> Result<[u8; N], Error> {
    let v = match data_type {
        INTEGER => signed_from_signed(N, data)?,
        UNSIGNED_INTEGER => signed_from_unsigned(N, data)?,
        _ => return Err(Error::NotInteger),
    };
    v.try_into().map_err(|_| Error::OutOfRange)
}

/// `general_get_uint`: the data as an unsigned integer of `N` octets.
fn general_get_uint<const N: usize>(data_type: u32, data: &[u8]) -> Result<[u8; N], Error> {
    let v = match data_type {
        INTEGER => unsigned_from_signed(N, data)?,
        UNSIGNED_INTEGER => unsigned_from_unsigned(N, data)?,
        _ => return Err(Error::NotInteger),
    };
    v.try_into().map_err(|_| Error::OutOfRange)
}

/// `general_set_int`: stores the signed native integer `val` (the data isn't NULL).
fn general_set_int(t: Target, val: &[u8]) -> Set {
    let r = match t.data_type {
        INTEGER => signed_from_signed(t.data_size, val),
        UNSIGNED_INTEGER => unsigned_from_signed(t.data_size, val),
        _ => Err(Error::NotInteger),
    };
    match r {
        Ok(v) => Set::ok(t.data_size, Some(v)),
        Err(e) => Set::err(val.len(), e),
    }
}

/// `general_set_uint`: stores the unsigned native integer `val` (the data isn't NULL).
fn general_set_uint(t: Target, val: &[u8]) -> Set {
    let r = match t.data_type {
        INTEGER => signed_from_unsigned(t.data_size, val),
        UNSIGNED_INTEGER => unsigned_from_unsigned(t.data_size, val),
        _ => Err(Error::NotInteger),
    };
    match r {
        Ok(v) => Set::ok(t.data_size, Some(v)),
        Err(e) => Set::err(val.len(), e),
    }
}

/// The data as `N` native octets, if it's that long.
fn exact<const N: usize>(data: &[u8]) -> Option<[u8; N]> {
    data.try_into().ok()
}

/// The data as a `double`, for a real: only 8-octet reals are supported.
fn read_real(data: &[u8]) -> Result<f64, Error> {
    exact::<8>(data)
        .map(f64::from_ne_bytes)
        .ok_or(Error::UnsupportedReal)
}

/// `OSSL_PARAM_get_int32`.
pub fn get_int32(data_type: u32, data: Option<&[u8]>) -> Result<i32, Error> {
    let data = data.ok_or(Error::NullArgument)?;
    match data_type {
        INTEGER => {
            if let Some(b) = exact::<4>(data) {
                return Ok(i32::from_ne_bytes(b));
            }
            if let Some(b) = exact::<8>(data) {
                return i32::try_from(i64::from_ne_bytes(b)).map_err(|_| Error::OutOfRange);
            }
            general_get_int::<4>(data_type, data).map(i32::from_ne_bytes)
        }
        UNSIGNED_INTEGER => {
            if let Some(b) = exact::<4>(data) {
                return i32::try_from(u32::from_ne_bytes(b)).map_err(|_| Error::OutOfRange);
            }
            if let Some(b) = exact::<8>(data) {
                return i32::try_from(u64::from_ne_bytes(b)).map_err(|_| Error::OutOfRange);
            }
            general_get_int::<4>(data_type, data).map(i32::from_ne_bytes)
        }
        REAL => {
            let d = read_real(data)?;
            if d >= -POW_31 && d <= f64::from(i32::MAX) && d == f64::from(real::to_i32(d)) {
                Ok(real::to_i32(d))
            } else {
                Err(Error::OutOfRange)
            }
        }
        _ => Err(Error::BadType),
    }
}

/// `OSSL_PARAM_get_uint32`.
pub fn get_uint32(data_type: u32, data: Option<&[u8]>) -> Result<u32, Error> {
    let data = data.ok_or(Error::NullArgument)?;
    match data_type {
        UNSIGNED_INTEGER => {
            if let Some(b) = exact::<4>(data) {
                return Ok(u32::from_ne_bytes(b));
            }
            if let Some(b) = exact::<8>(data) {
                return u32::try_from(u64::from_ne_bytes(b)).map_err(|_| Error::OutOfRange);
            }
            general_get_uint::<4>(data_type, data).map(u32::from_ne_bytes)
        }
        INTEGER => {
            if let Some(b) = exact::<4>(data) {
                return u32::try_from(i32::from_ne_bytes(b)).map_err(|_| Error::UnsignedNegative);
            }
            if let Some(b) = exact::<8>(data) {
                let v = i64::from_ne_bytes(b);
                if v < 0 {
                    return Err(Error::UnsignedNegative);
                }
                return u32::try_from(v).map_err(|_| Error::OutOfRange);
            }
            general_get_uint::<4>(data_type, data).map(u32::from_ne_bytes)
        }
        REAL => {
            let d = read_real(data)?;
            if d >= 0.0 && d <= f64::from(u32::MAX) && d == f64::from(real::to_u32(d)) {
                Ok(real::to_u32(d))
            } else {
                Err(Error::Inexact)
            }
        }
        _ => Err(Error::BadType),
    }
}

/// `OSSL_PARAM_get_int64`.
pub fn get_int64(data_type: u32, data: Option<&[u8]>) -> Result<i64, Error> {
    let data = data.ok_or(Error::NullArgument)?;
    match data_type {
        INTEGER => {
            if let Some(b) = exact::<4>(data) {
                return Ok(i64::from(i32::from_ne_bytes(b)));
            }
            if let Some(b) = exact::<8>(data) {
                return Ok(i64::from_ne_bytes(b));
            }
            general_get_int::<8>(data_type, data).map(i64::from_ne_bytes)
        }
        UNSIGNED_INTEGER => {
            if let Some(b) = exact::<4>(data) {
                return Ok(i64::from(u32::from_ne_bytes(b)));
            }
            if let Some(b) = exact::<8>(data) {
                return i64::try_from(u64::from_ne_bytes(b)).map_err(|_| Error::OutOfRange);
            }
            general_get_int::<8>(data_type, data).map(i64::from_ne_bytes)
        }
        REAL => {
            let d = read_real(data)?;
            if (-POW_63..POW_63).contains(&d) && d == real::from_i64(real::to_i64(d)) {
                Ok(real::to_i64(d))
            } else {
                Err(Error::Inexact)
            }
        }
        _ => Err(Error::BadType),
    }
}

/// `OSSL_PARAM_get_uint64`.
pub fn get_uint64(data_type: u32, data: Option<&[u8]>) -> Result<u64, Error> {
    let data = data.ok_or(Error::NullArgument)?;
    match data_type {
        UNSIGNED_INTEGER => {
            if let Some(b) = exact::<4>(data) {
                return Ok(u64::from(u32::from_ne_bytes(b)));
            }
            if let Some(b) = exact::<8>(data) {
                return Ok(u64::from_ne_bytes(b));
            }
            general_get_uint::<8>(data_type, data).map(u64::from_ne_bytes)
        }
        INTEGER => {
            if let Some(b) = exact::<4>(data) {
                return u64::try_from(i32::from_ne_bytes(b)).map_err(|_| Error::UnsignedNegative);
            }
            if let Some(b) = exact::<8>(data) {
                return u64::try_from(i64::from_ne_bytes(b)).map_err(|_| Error::UnsignedNegative);
            }
            general_get_uint::<8>(data_type, data).map(u64::from_ne_bytes)
        }
        REAL => {
            let d = read_real(data)?;
            if (0.0..POW_64).contains(&d) && d == real::from_u64(real::to_u64(d)) {
                Ok(real::to_u64(d))
            } else {
                Err(Error::Inexact)
            }
        }
        _ => Err(Error::BadType),
    }
}

/// `OSSL_PARAM_get_double`.
pub fn get_double(data_type: u32, data: Option<&[u8]>) -> Result<f64, Error> {
    let data = data.ok_or(Error::NullArgument)?;
    match data_type {
        REAL => read_real(data),
        UNSIGNED_INTEGER => {
            if let Some(b) = exact::<4>(data) {
                return Ok(f64::from(u32::from_ne_bytes(b)));
            }
            if let Some(b) = exact::<8>(data) {
                let v = u64::from_ne_bytes(b);
                return if v >> REAL_SHIFT == 0 {
                    Ok(real::from_u64(v))
                } else {
                    Err(Error::Inexact)
                };
            }
            Err(Error::BadType)
        }
        INTEGER => {
            if let Some(b) = exact::<4>(data) {
                return Ok(f64::from(i32::from_ne_bytes(b)));
            }
            if let Some(b) = exact::<8>(data) {
                let v = i64::from_ne_bytes(b);
                return if v.unsigned_abs() >> REAL_SHIFT == 0 {
                    Ok(real::from_i64(v))
                } else {
                    Err(Error::Inexact)
                };
            }
            Err(Error::BadType)
        }
        _ => Err(Error::BadType),
    }
}

/// The data a successful set of `t` stores: `bytes`, or nothing for a NULL data pointer.
fn store(t: Target, bytes: &[u8]) -> Option<Vec<u8>> {
    (!t.null).then(|| bytes.to_vec())
}

/// `OSSL_PARAM_set_int32`.
pub fn set_int32(t: Target, val: i32) -> Set {
    match t.data_type {
        INTEGER => match (t.null, t.data_size) {
            (true, _) => Set::ok(4, None),
            (false, 4) => Set::ok(4, store(t, &val.to_ne_bytes())),
            (false, 8) => Set::ok(8, store(t, &i64::from(val).to_ne_bytes())),
            _ => general_set_int(t, &val.to_ne_bytes()),
        },
        UNSIGNED_INTEGER if val >= 0 => match (t.null, t.data_size) {
            (true, _) => Set::ok(4, None),
            (false, 4) => Set::ok(4, store(t, &val.to_ne_bytes())),
            (false, 8) => Set::ok(8, store(t, &i64::from(val).to_ne_bytes())),
            _ => general_set_int(t, &val.to_ne_bytes()),
        },
        REAL => match (t.null, t.data_size) {
            (true, _) => Set::ok(8, None),
            (false, 8) => Set::ok(8, store(t, &f64::from(val).to_ne_bytes())),
            _ => Set::err(8, Error::UnsupportedReal),
        },
        _ => Set::err(0, Error::BadType),
    }
}

/// `OSSL_PARAM_set_uint32`.
pub fn set_uint32(t: Target, val: u32) -> Set {
    match t.data_type {
        UNSIGNED_INTEGER => match (t.null, t.data_size) {
            (true, _) => Set::ok(4, None),
            (false, 4) => Set::ok(4, store(t, &val.to_ne_bytes())),
            (false, 8) => Set::ok(8, store(t, &u64::from(val).to_ne_bytes())),
            _ => general_set_uint(t, &val.to_ne_bytes()),
        },
        INTEGER => match (t.null, t.data_size) {
            (true, _) => Set::ok(4, None),
            (false, 4) => match i32::try_from(val) {
                Ok(v) => Set::ok(4, store(t, &v.to_ne_bytes())),
                Err(_) => Set::err(4, Error::OutOfRange),
            },
            (false, 8) => Set::ok(8, store(t, &i64::from(val).to_ne_bytes())),
            _ => general_set_uint(t, &val.to_ne_bytes()),
        },
        REAL => match (t.null, t.data_size) {
            (true, _) => Set::ok(8, None),
            (false, 8) => Set::ok(8, store(t, &f64::from(val).to_ne_bytes())),
            _ => Set::err(0, Error::UnsupportedReal),
        },
        _ => Set::err(0, Error::BadType),
    }
}

/// `OSSL_PARAM_set_int64`.
pub fn set_int64(t: Target, val: i64) -> Set {
    match t.data_type {
        INTEGER => match (t.null, t.data_size) {
            (true, _) => Set::ok(8, None),
            (false, 4) => match i32::try_from(val) {
                Ok(v) => Set::ok(4, store(t, &v.to_ne_bytes())),
                Err(_) => Set::err(0, Error::OutOfRange),
            },
            (false, 8) => Set::ok(8, store(t, &val.to_ne_bytes())),
            _ => general_set_int(t, &val.to_ne_bytes()),
        },
        UNSIGNED_INTEGER if val >= 0 => match (t.null, t.data_size) {
            (true, _) => Set::ok(8, None),
            (false, 4) => match u32::try_from(val) {
                Ok(v) => Set::ok(4, store(t, &v.to_ne_bytes())),
                Err(_) => Set::err(0, Error::OutOfRange),
            },
            (false, 8) => Set::ok(8, store(t, &val.to_ne_bytes())),
            _ => general_set_int(t, &val.to_ne_bytes()),
        },
        REAL => match (t.null, t.data_size) {
            (true, _) => Set::ok(8, None),
            (false, 8) if val.unsigned_abs() >> REAL_SHIFT == 0 => {
                Set::ok(8, store(t, &real::from_i64(val).to_ne_bytes()))
            }
            (false, 8) => Set::err(0, Error::Inexact),
            _ => Set::err(0, Error::UnsupportedReal),
        },
        _ => Set::err(0, Error::BadType),
    }
}

/// `OSSL_PARAM_set_uint64`. A NULL real of 8 octets is a size query here (OpenSSL writes
/// through the NULL).
pub fn set_uint64(t: Target, val: u64) -> Set {
    match t.data_type {
        UNSIGNED_INTEGER => match (t.null, t.data_size) {
            (true, _) => Set::ok(8, None),
            (false, 4) => match u32::try_from(val) {
                Ok(v) => Set::ok(4, store(t, &v.to_ne_bytes())),
                Err(_) => Set::err(0, Error::OutOfRange),
            },
            (false, 8) => Set::ok(8, store(t, &val.to_ne_bytes())),
            _ => general_set_uint(t, &val.to_ne_bytes()),
        },
        INTEGER => match (t.null, t.data_size) {
            (true, _) => Set::ok(8, None),
            (false, 4) => match i32::try_from(val) {
                Ok(v) => Set::ok(4, store(t, &v.to_ne_bytes())),
                Err(_) => Set::err(0, Error::OutOfRange),
            },
            (false, 8) => match i64::try_from(val) {
                Ok(v) => Set::ok(8, store(t, &v.to_ne_bytes())),
                Err(_) => Set::err(0, Error::OutOfRange),
            },
            _ => general_set_uint(t, &val.to_ne_bytes()),
        },
        REAL => match t.data_size {
            8 if val >> REAL_SHIFT == 0 => Set::ok(8, store(t, &real::from_u64(val).to_ne_bytes())),
            8 => Set::err(0, Error::Inexact),
            _ => Set::err(0, Error::UnsupportedReal),
        },
        _ => Set::err(0, Error::BadType),
    }
}

/// `OSSL_PARAM_set_double`. An integral value is first checked against C's conversion,
/// saturating here where C's is undefined.
pub fn set_double(t: Target, val: f64) -> Set {
    match t.data_type {
        REAL => match (t.null, t.data_size) {
            (true, _) => Set::ok(8, None),
            (false, 8) => Set::ok(8, store(t, &val.to_ne_bytes())),
            _ => Set::err(0, Error::UnsupportedReal),
        },
        UNSIGNED_INTEGER => {
            if t.null {
                return Set::ok(8, None);
            }
            if val != real::from_u64(real::to_u64(val)) {
                return Set::err(0, Error::Inexact);
            }
            match t.data_size {
                4 if (0.0..POW_32).contains(&val) => {
                    Set::ok(4, store(t, &real::to_u32(val).to_ne_bytes()))
                }
                8 if (0.0..POW_64).contains(&val) => {
                    Set::ok(8, store(t, &real::to_u64(val).to_ne_bytes()))
                }
                4 | 8 => Set::err(0, Error::OutOfRange),
                _ => Set::err(0, Error::BadType),
            }
        }
        INTEGER => {
            if t.null {
                return Set::ok(8, None);
            }
            if val != real::from_i64(real::to_i64(val)) {
                return Set::err(0, Error::Inexact);
            }
            match t.data_size {
                4 if (-POW_31..POW_31).contains(&val) => {
                    Set::ok(4, store(t, &real::to_i32(val).to_ne_bytes()))
                }
                8 if (-POW_63..POW_63).contains(&val) => {
                    Set::ok(8, store(t, &real::to_i64(val).to_ne_bytes()))
                }
                4 | 8 => Set::err(0, Error::OutOfRange),
                _ => Set::err(0, Error::BadType),
            }
        }
        _ => Set::err(0, Error::BadType),
    }
}

/// `OPENSSL_strcasecmp`'s order: ASCII letters compared without case, octet by octet.
pub fn strcasecmp(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    let lower = |s: &[u8]| -> Vec<u8> { s.iter().map(u8::to_ascii_lowercase).collect() };
    lower(a).cmp(&lower(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(data_type: u32, data_size: usize) -> Target {
        Target {
            data_type,
            data_size,
            null: false,
        }
    }

    #[test]
    fn narrows_and_widens() {
        // -253 in two octets doesn't fit one: 0x03 would read as 3.
        let src = (-253i16).to_ne_bytes();
        assert_eq!(signed_from_signed(1, &src), Err(Error::OutOfRange));
        let src = (-3i16).to_ne_bytes();
        assert_eq!(signed_from_signed(1, &src), Ok(vec![0xfd]));
        // 130 in two octets would read as -126 in one.
        let src = 130i16.to_ne_bytes();
        assert_eq!(signed_from_signed(1, &src), Err(Error::OutOfRange));
        assert_eq!(unsigned_from_unsigned(1, &src), Ok(vec![130]));
        assert_eq!(get_int32(INTEGER, Some(&[0xff, 0xff])), Ok(-1));
        assert_eq!(
            get_uint32(INTEGER, Some(&[0xff, 0xff])),
            Err(Error::UnsignedNegative)
        );
        assert_eq!(get_int64(UNSIGNED_INTEGER, Some(&[0; 16])), Ok(0));
        assert_eq!(get_int32(INTEGER, Some(&[])), Ok(0));
    }

    #[test]
    fn sets_with_return_sizes() {
        let s = set_int32(t(INTEGER, 8), -2);
        assert_eq!(s.return_size, 8);
        assert_eq!(s.result, Ok(Some((-2i64).to_ne_bytes().to_vec())));
        let s = set_int32(t(UNSIGNED_INTEGER, 4), -2);
        assert_eq!(s, Set::err(0, Error::BadType));
        let s = set_int32(t(REAL, 4), 1);
        assert_eq!(s, Set::err(8, Error::UnsupportedReal));
        let s = set_uint32(t(INTEGER, 2), 70000);
        assert_eq!(s, Set::err(4, Error::OutOfRange));
        let s = set_int64(t(INTEGER, 3), -70000);
        assert_eq!(s.return_size, 3);
        let s = set_uint64(t(REAL, 8), 1 << 53);
        assert_eq!(s, Set::err(0, Error::Inexact));
        let s = set_double(t(INTEGER, 8), POW_63);
        assert_eq!(s, Set::err(0, Error::OutOfRange));
        let s = set_double(t(UNSIGNED_INTEGER, 4), 1.5);
        assert_eq!(s, Set::err(0, Error::Inexact));
        let s = set_double(t(UNSIGNED_INTEGER, 2), 1.0);
        assert_eq!(s, Set::err(0, Error::BadType));
    }

    #[test]
    fn reals() {
        let d = |v: f64| v.to_ne_bytes();
        assert_eq!(get_int32(REAL, Some(&d(-2_147_483_648.0))), Ok(i32::MIN));
        assert_eq!(get_int32(REAL, Some(&d(0.5))), Err(Error::OutOfRange));
        assert_eq!(get_uint32(REAL, Some(&d(-1.0))), Err(Error::Inexact));
        assert_eq!(get_int64(REAL, Some(&d(POW_63))), Err(Error::Inexact));
        assert_eq!(get_uint64(REAL, Some(&d(f64::NAN))), Err(Error::Inexact));
        assert_eq!(
            get_double(INTEGER, Some(&i64::MIN.to_ne_bytes())),
            Err(Error::Inexact)
        );
        assert_eq!(get_double(INTEGER, Some(&[1, 0])), Err(Error::BadType));
        assert_eq!(get_int32(REAL, Some(&[0; 4])), Err(Error::UnsupportedReal));
    }
}
