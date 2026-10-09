//! Parameters (`OSSL_PARAM(3)`, `OSSL_PARAM_int(3)`): `OSSL_PARAM_locate`, the
//! `OSSL_PARAM_construct_*` functions, the typed getters and setters over
//! `rustyssl_crypto::params`, the string and pointer forms, and the modified flags.
//! `OSSL_PARAM_dup`, `OSSL_PARAM_merge`, and `OSSL_PARAM_free` are in [`dup`], and
//! `OSSL_PARAM_BLD` in [`build`].
//!
//! A parameter's data is the caller's, sized by `data_size`: getters read it as one slice,
//! setters write the octets the core says to store. The `_ptr` types hold a pointer in their
//! data, and `data_size` is then the length of what that pointer points to.

use core::ffi::{CStr, c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr;

use libc::time_t;
use rustyssl_abi::{
    CRYPTO_R_NO_SPACE_FOR_TERMINATING_NULL, CRYPTO_R_PARAM_CANNOT_BE_REPRESENTED_EXACTLY,
    CRYPTO_R_PARAM_NOT_INTEGER_TYPE, CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE,
    CRYPTO_R_PARAM_UNSIGNED_INTEGER_NEGATIVE_VALUE_UNSUPPORTED,
    CRYPTO_R_PARAM_UNSUPPORTED_FLOATING_POINT_FORMAT,
    CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION, CRYPTO_R_TOO_SMALL_BUFFER, ERR_LIB_CRYPTO,
    ERR_R_PASSED_NULL_PARAMETER, OSSL_PARAM, OSSL_PARAM_UNMODIFIED,
};
use rustyssl_crypto::params::{
    self as conv, Error, INTEGER, OCTET_PTR, OCTET_STRING, REAL, Set, Target, UNSIGNED_INTEGER,
    UTF8_PTR, UTF8_STRING,
};

use crate::err;
use crate::ffi::ffi_export;
use crate::mem;

pub(crate) mod build;
pub(crate) mod dup;

// `long`, `size_t`, and `time_t` are 64 bits on every supported target, so their functions
// are those of `int64_t` and `uint64_t`, as OpenSSL picks by size.
const _: () = assert!(size_of::<c_long>() == 8 && size_of::<usize>() == 8);
const _: () = assert!(size_of::<time_t>() == 8 && size_of::<c_int>() == 4);

/// Raises `error` for `function`.
#[track_caller]
fn raise(error: Error, function: &str) {
    let reason = match error {
        Error::NullArgument => ERR_R_PASSED_NULL_PARAMETER,
        Error::UnsignedNegative => CRYPTO_R_PARAM_UNSIGNED_INTEGER_NEGATIVE_VALUE_UNSUPPORTED,
        Error::OutOfRange => CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION,
        Error::Inexact => CRYPTO_R_PARAM_CANNOT_BE_REPRESENTED_EXACTLY,
        Error::NotInteger => CRYPTO_R_PARAM_NOT_INTEGER_TYPE,
        Error::TooSmall => CRYPTO_R_TOO_SMALL_BUFFER,
        Error::BadType => CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE,
        Error::UnsupportedReal => CRYPTO_R_PARAM_UNSUPPORTED_FLOATING_POINT_FORMAT,
    };
    err::raise(ERR_LIB_CRYPTO, reason, function);
}

/// `OSSL_PARAM_UNMODIFIED`, as a `size_t`.
fn unmodified() -> usize {
    usize::try_from(OSSL_PARAM_UNMODIFIED).unwrap_or(usize::MAX)
}

/// `ossl_param_construct`.
fn construct(
    key: *const c_char,
    data_type: u32,
    data: *mut c_void,
    data_size: usize,
) -> OSSL_PARAM {
    OSSL_PARAM {
        key,
        data_type,
        data,
        data_size,
        return_size: unmodified(),
    }
}

/// `OSSL_PARAM_END`.
pub(crate) const fn end() -> OSSL_PARAM {
    OSSL_PARAM {
        key: ptr::null(),
        data_type: 0,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    }
}

/// A parameter's data as a slice: `Ok(None)` for NULL. A `data_size` no object can have is
/// refused (`OutOfRange`) instead of read.
///
/// # Safety
/// The data is NULL or holds `data_size` octets that outlive `'a`.
unsafe fn data<'a>(p: &OSSL_PARAM) -> Result<Option<&'a [u8]>, Error> {
    if p.data.is_null() {
        return Ok(None);
    }
    if isize::try_from(p.data_size).is_err() {
        return Err(Error::OutOfRange);
    }
    // SAFETY: the caller's guarantee; the length fits an `isize`.
    Ok(Some(unsafe {
        core::slice::from_raw_parts(p.data.cast::<u8>(), p.data_size)
    }))
}

/// Applies a setter's outcome to `p`: its `return_size`, the octets stored, or the error.
///
/// # Safety
/// `p`'s data, if the outcome stores octets, holds `data_size` writable octets.
#[track_caller]
unsafe fn apply(p: &mut OSSL_PARAM, set: Set, function: &str) -> c_int {
    p.return_size = set.return_size;
    match set.result {
        Ok(None) => 1,
        Ok(Some(octets)) => {
            let n = octets.len().min(p.data_size);
            // SAFETY: the caller's guarantee; the core stores `data_size` octets at most.
            unsafe { ptr::copy_nonoverlapping(octets.as_ptr(), p.data.cast::<u8>(), n) };
            1
        }
        Err(e) => {
            raise(e, function);
            0
        }
    }
}

/// The target a setter writes to.
fn target(p: &OSSL_PARAM) -> Target {
    Target {
        data_type: p.data_type,
        data_size: p.data_size,
        null: p.data.is_null(),
    }
}

/// A `size_t` from a `uint64_t` (the same width here).
fn to_usize(v: u64) -> Result<usize, Error> {
    usize::try_from(v).map_err(|_| Error::OutOfRange)
}

/// Defines typed getters: each reads `*p` through a conversion of `rustyssl_crypto::params`.
macro_rules! getters {
    ($(
        $(#[$attr:meta])*
        pub unsafe extern "C" fn $name:ident(*mut $ty:ty) = $core:ident $(=> $then:ident)?;
    )*) => {$(
        ffi_export! {
            $(#[$attr])*
            ///
            /// # Safety
            /// `p` is NULL or a parameter whose data is NULL or holds `data_size` octets; `val`
            /// is NULL or valid for a write.
            pub unsafe extern "C" fn $name(p: *const OSSL_PARAM, val: *mut $ty) -> c_int
            where failure = 0, library = ERR_LIB_CRYPTO
            {
                // SAFETY: the caller's guarantee.
                let param = unsafe { p.as_ref() };
                let Some(param) = param.filter(|_| !val.is_null()) else {
                    raise(Error::NullArgument, stringify!($name));
                    return 0;
                };
                // SAFETY: the caller's guarantee.
                let data = unsafe { data(param) };
                let value = data.and_then(|d| conv::$core(param.data_type, d)) $(.and_then($then))?;
                match value {
                    Ok(v) => {
                        // SAFETY: the caller's guarantee; `val` isn't NULL.
                        unsafe { val.write(v) };
                        1
                    }
                    Err(e) => {
                        raise(e, stringify!($name));
                        0
                    }
                }
            }
        }
    )*};
}

getters! {
    /// Reads the parameter as an `int`: 1, or 0 if it's missing, not a number, or out of range.
    pub unsafe extern "C" fn OSSL_PARAM_get_int(*mut c_int) = get_int32;
    /// As `OSSL_PARAM_get_int`, for an `unsigned int`.
    pub unsafe extern "C" fn OSSL_PARAM_get_uint(*mut c_uint) = get_uint32;
    /// As `OSSL_PARAM_get_int`, for a `long`.
    pub unsafe extern "C" fn OSSL_PARAM_get_long(*mut c_long) = get_int64;
    /// As `OSSL_PARAM_get_int`, for an `unsigned long`.
    pub unsafe extern "C" fn OSSL_PARAM_get_ulong(*mut c_ulong) = get_uint64;
    /// As `OSSL_PARAM_get_int`, for an `int32_t`.
    pub unsafe extern "C" fn OSSL_PARAM_get_int32(*mut i32) = get_int32;
    /// As `OSSL_PARAM_get_int`, for a `uint32_t`.
    pub unsafe extern "C" fn OSSL_PARAM_get_uint32(*mut u32) = get_uint32;
    /// As `OSSL_PARAM_get_int`, for an `int64_t`.
    pub unsafe extern "C" fn OSSL_PARAM_get_int64(*mut i64) = get_int64;
    /// As `OSSL_PARAM_get_int`, for a `uint64_t`.
    pub unsafe extern "C" fn OSSL_PARAM_get_uint64(*mut u64) = get_uint64;
    /// As `OSSL_PARAM_get_int`, for a `size_t`.
    pub unsafe extern "C" fn OSSL_PARAM_get_size_t(*mut usize) = get_uint64 => to_usize;
    /// As `OSSL_PARAM_get_int`, for a `time_t`.
    pub unsafe extern "C" fn OSSL_PARAM_get_time_t(*mut time_t) = get_int64;
    /// Reads the parameter as a `double`: a real, or an integer a `double` holds exactly.
    pub unsafe extern "C" fn OSSL_PARAM_get_double(*mut f64) = get_double;
}

/// Defines typed setters: each writes `val` through a conversion of `rustyssl_crypto::params`.
macro_rules! setters {
    ($(
        $(#[$attr:meta])*
        pub unsafe extern "C" fn $name:ident($ty:ty) = $core:ident $(as $wide:ty)?;
    )*) => {$(
        ffi_export! {
            $(#[$attr])*
            ///
            /// # Safety
            /// `p` is NULL or a parameter whose data is NULL or holds `data_size` writable
            /// octets.
            pub unsafe extern "C" fn $name(p: *mut OSSL_PARAM, val: $ty) -> c_int
            where failure = 0, library = ERR_LIB_CRYPTO
            {
                // SAFETY: the caller's guarantee.
                let Some(param) = (unsafe { p.as_mut() }) else {
                    raise(Error::NullArgument, stringify!($name));
                    return 0;
                };
                let set = conv::$core(target(param), val $(as $wide)?);
                // SAFETY: the caller's guarantee.
                unsafe { apply(param, set, stringify!($name)) }
            }
        }
    )*};
}

setters! {
    /// Stores an `int` in the parameter, converted to its type and size; sets `return_size`.
    /// Returns 1, or 0 if it doesn't fit.
    pub unsafe extern "C" fn OSSL_PARAM_set_int(c_int) = set_int32;
    /// As `OSSL_PARAM_set_int`, for an `unsigned int`.
    pub unsafe extern "C" fn OSSL_PARAM_set_uint(c_uint) = set_uint32;
    /// As `OSSL_PARAM_set_int`, for a `long`.
    pub unsafe extern "C" fn OSSL_PARAM_set_long(c_long) = set_int64;
    /// As `OSSL_PARAM_set_int`, for an `unsigned long`.
    pub unsafe extern "C" fn OSSL_PARAM_set_ulong(c_ulong) = set_uint64;
    /// As `OSSL_PARAM_set_int`, for an `int32_t`.
    pub unsafe extern "C" fn OSSL_PARAM_set_int32(i32) = set_int32;
    /// As `OSSL_PARAM_set_int`, for a `uint32_t`.
    pub unsafe extern "C" fn OSSL_PARAM_set_uint32(u32) = set_uint32;
    /// As `OSSL_PARAM_set_int`, for an `int64_t`.
    pub unsafe extern "C" fn OSSL_PARAM_set_int64(i64) = set_int64;
    /// As `OSSL_PARAM_set_int`, for a `uint64_t`. A NULL real of 8 octets is a size query
    /// (OpenSSL writes through the NULL; docs/DEVIATIONS.md).
    pub unsafe extern "C" fn OSSL_PARAM_set_uint64(u64) = set_uint64;
    /// As `OSSL_PARAM_set_uint64`, for a `size_t`.
    pub unsafe extern "C" fn OSSL_PARAM_set_size_t(usize) = set_uint64 as u64;
    /// As `OSSL_PARAM_set_int`, for a `time_t`.
    pub unsafe extern "C" fn OSSL_PARAM_set_time_t(time_t) = set_int64;
    /// Stores a `double`: in a real, or in an integer if it's integral and fits.
    pub unsafe extern "C" fn OSSL_PARAM_set_double(f64) = set_double;
}

/// Defines the `OSSL_PARAM_construct_*` functions of fixed-size types.
macro_rules! constructs {
    ($(
        $(#[$attr:meta])*
        pub unsafe extern "C" fn $name:ident(*mut $ty:ty) = $data_type:ident;
    )*) => {$(
        ffi_export! {
            $(#[$attr])*
            ///
            /// # Safety
            /// No preconditions: the pointers are only stored.
            pub unsafe extern "C" fn $name(key: *const c_char, buf: *mut $ty) -> OSSL_PARAM
            where failure = end(), library = ERR_LIB_CRYPTO
            {
                construct(key, $data_type, buf.cast(), size_of::<$ty>())
            }
        }
    )*};
}

constructs! {
    /// A parameter `key` for an `int` at `buf`, unmodified.
    pub unsafe extern "C" fn OSSL_PARAM_construct_int(*mut c_int) = INTEGER;
    /// A parameter `key` for an `unsigned int` at `buf`, unmodified.
    pub unsafe extern "C" fn OSSL_PARAM_construct_uint(*mut c_uint) = UNSIGNED_INTEGER;
    /// A parameter `key` for a `long` at `buf`, unmodified.
    pub unsafe extern "C" fn OSSL_PARAM_construct_long(*mut c_long) = INTEGER;
    /// A parameter `key` for an `unsigned long` at `buf`, unmodified.
    pub unsafe extern "C" fn OSSL_PARAM_construct_ulong(*mut c_ulong) = UNSIGNED_INTEGER;
    /// A parameter `key` for an `int32_t` at `buf`, unmodified.
    pub unsafe extern "C" fn OSSL_PARAM_construct_int32(*mut i32) = INTEGER;
    /// A parameter `key` for a `uint32_t` at `buf`, unmodified.
    pub unsafe extern "C" fn OSSL_PARAM_construct_uint32(*mut u32) = UNSIGNED_INTEGER;
    /// A parameter `key` for an `int64_t` at `buf`, unmodified.
    pub unsafe extern "C" fn OSSL_PARAM_construct_int64(*mut i64) = INTEGER;
    /// A parameter `key` for a `uint64_t` at `buf`, unmodified.
    pub unsafe extern "C" fn OSSL_PARAM_construct_uint64(*mut u64) = UNSIGNED_INTEGER;
    /// A parameter `key` for a `size_t` at `buf`, unmodified.
    pub unsafe extern "C" fn OSSL_PARAM_construct_size_t(*mut usize) = UNSIGNED_INTEGER;
    /// A parameter `key` for a `time_t` at `buf`, unmodified.
    pub unsafe extern "C" fn OSSL_PARAM_construct_time_t(*mut time_t) = INTEGER;
    /// A parameter `key` for a `double` at `buf`, unmodified.
    pub unsafe extern "C" fn OSSL_PARAM_construct_double(*mut f64) = REAL;
}

ffi_export! {
    /// A parameter `key` for an unsigned big number of `bsize` octets at `buf`, unmodified.
    ///
    /// # Safety
    /// No preconditions: the pointers are only stored.
    pub unsafe extern "C" fn OSSL_PARAM_construct_BN(key: *const c_char, buf: *mut u8, bsize: usize) -> OSSL_PARAM
    where failure = end(), library = ERR_LIB_CRYPTO
    {
        construct(key, UNSIGNED_INTEGER, buf.cast(), bsize)
    }
}

ffi_export! {
    /// A parameter `key` for a UTF-8 string in the `bsize` octets at `buf`; a `bsize` of 0
    /// takes the length of the string `buf` holds.
    ///
    /// # Safety
    /// `buf` is NULL, or a NUL-terminated string if `bsize` is 0.
    pub unsafe extern "C" fn OSSL_PARAM_construct_utf8_string(key: *const c_char, buf: *mut c_char, bsize: usize) -> OSSL_PARAM
    where failure = end(), library = ERR_LIB_CRYPTO
    {
        let mut size = bsize;
        if !buf.is_null() && bsize == 0 {
            // SAFETY: the caller's guarantee.
            size = unsafe { CStr::from_ptr(buf) }.count_bytes();
        }
        construct(key, UTF8_STRING, buf.cast(), size)
    }
}

ffi_export! {
    /// A parameter `key` for an octet string in the `bsize` octets at `buf`.
    ///
    /// # Safety
    /// No preconditions: the pointers are only stored.
    pub unsafe extern "C" fn OSSL_PARAM_construct_octet_string(key: *const c_char, buf: *mut c_void, bsize: usize) -> OSSL_PARAM
    where failure = end(), library = ERR_LIB_CRYPTO
    {
        construct(key, OCTET_STRING, buf, bsize)
    }
}

ffi_export! {
    /// A parameter `key` for a pointer, at `buf`, to a UTF-8 string of `bsize` octets.
    ///
    /// # Safety
    /// No preconditions: the pointers are only stored.
    pub unsafe extern "C" fn OSSL_PARAM_construct_utf8_ptr(key: *const c_char, buf: *mut *mut c_char, bsize: usize) -> OSSL_PARAM
    where failure = end(), library = ERR_LIB_CRYPTO
    {
        construct(key, UTF8_PTR, buf.cast(), bsize)
    }
}

ffi_export! {
    /// A parameter `key` for a pointer, at `buf`, to `bsize` octets.
    ///
    /// # Safety
    /// No preconditions: the pointers are only stored.
    pub unsafe extern "C" fn OSSL_PARAM_construct_octet_ptr(key: *const c_char, buf: *mut *mut c_void, bsize: usize) -> OSSL_PARAM
    where failure = end(), library = ERR_LIB_CRYPTO
    {
        construct(key, OCTET_PTR, buf.cast(), bsize)
    }
}

ffi_export! {
    /// The terminating parameter: all zero.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_PARAM_construct_end() -> OSSL_PARAM
    where failure = end(), library = ERR_LIB_CRYPTO
    {
        end()
    }
}

/// The parameter named `key` (compared exactly) in the array at `p`, or NULL.
///
/// # Safety
/// `p` is NULL or an array ended by a parameter with a NULL key, whose keys are strings; `key`
/// is NULL or a string.
unsafe fn locate(p: *const OSSL_PARAM, key: *const c_char) -> *const OSSL_PARAM {
    if p.is_null() || key.is_null() {
        return ptr::null();
    }
    // SAFETY: the caller's guarantee.
    let key = unsafe { CStr::from_ptr(key) };
    let mut at = p;
    loop {
        // SAFETY: the caller's guarantee: the array goes on to its end.
        let param = unsafe { &*at };
        if param.key.is_null() {
            return ptr::null();
        }
        // SAFETY: the caller's guarantee.
        if unsafe { CStr::from_ptr(param.key) } == key {
            return at;
        }
        at = at.wrapping_add(1);
    }
}

ffi_export! {
    /// The parameter named `key` in the array `p`, or NULL (also for a NULL array or key).
    ///
    /// # Safety
    /// `p` is NULL or an array ended by a parameter with a NULL key; `key` is NULL or a string.
    pub unsafe extern "C" fn OSSL_PARAM_locate(p: *mut OSSL_PARAM, key: *const c_char) -> *mut OSSL_PARAM
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { locate(p, key) }.cast_mut()
    }
}

ffi_export! {
    /// As `OSSL_PARAM_locate`, for a constant array.
    ///
    /// # Safety
    /// As for `OSSL_PARAM_locate`.
    pub unsafe extern "C" fn OSSL_PARAM_locate_const(p: *const OSSL_PARAM, key: *const c_char) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { locate(p, key) }
    }
}

ffi_export! {
    /// Whether a setter has set the parameter's `return_size` since it was made unmodified.
    ///
    /// # Safety
    /// `p` is NULL or a parameter.
    pub unsafe extern "C" fn OSSL_PARAM_modified(p: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let param = unsafe { p.as_ref() };
        c_int::from(param.is_some_and(|q| q.return_size != unmodified()))
    }
}

ffi_export! {
    /// Marks every parameter of the array `p` unmodified.
    ///
    /// # Safety
    /// `p` is NULL or an array ended by a parameter with a NULL key.
    pub unsafe extern "C" fn OSSL_PARAM_set_all_unmodified(p: *mut OSSL_PARAM)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let mut at = p;
        // SAFETY: the caller's guarantee: the array goes on to its end.
        while let Some(param) = unsafe { at.as_mut() } {
            if param.key.is_null() {
                break;
            }
            param.return_size = unmodified();
            at = at.wrapping_add(1);
        }
    }
}

/// `get_string_internal`: copies a string parameter of type `data_type` to `*val`, allocating
/// it (`data_size` octets, one more for a UTF-8 string or an empty one) if `*val` is NULL, and
/// reports the length through `used_len`. Returns the room `*val` has, or why it failed.
///
/// # Safety
/// `p` is NULL or a parameter whose data is NULL or holds `data_size` octets; `val` is NULL or
/// points to NULL or to a buffer of `max_len` octets; `used_len` is NULL or valid for a write.
unsafe fn get_string(
    p: *const OSSL_PARAM,
    val: *mut *mut c_void,
    max_len: usize,
    used_len: *mut usize,
    data_type: u32,
) -> Result<usize, Option<Error>> {
    // SAFETY: the caller's guarantee.
    let param = unsafe { p.as_ref() };
    let Some(param) = param.filter(|_| !(val.is_null() && used_len.is_null())) else {
        return Err(Some(Error::NullArgument));
    };
    if param.data_type != data_type {
        return Err(Some(Error::BadType));
    }
    let size = param.data_size;
    let extra = usize::from(data_type == UTF8_STRING || size == 0);
    if !used_len.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { used_len.write(size) };
    }
    // SAFETY: the caller's guarantee.
    let Some(data) = (unsafe { data(param) }).map_err(Some)? else {
        return Err(Some(Error::NullArgument));
    };
    if val.is_null() {
        return Ok(max_len);
    }
    let mut room = max_len;
    // SAFETY: the caller's guarantee.
    let mut out = unsafe { val.read() };
    if out.is_null() {
        let alloc = size.checked_add(extra).ok_or(Some(Error::OutOfRange))?;
        out = mem::alloc(alloc);
        if out.is_null() {
            // The allocator raised the error.
            return Err(None);
        }
        // SAFETY: the caller's guarantee.
        unsafe { val.write(out) };
        room = alloc;
    }
    if room < size {
        return Err(Some(Error::TooSmall));
    }
    // SAFETY: `out` has room for `size` octets, checked above, and the data holds them.
    unsafe { ptr::copy_nonoverlapping(data.as_ptr(), out.cast::<u8>(), size) };
    Ok(room)
}

/// Raises `error`, if there's one to raise.
#[track_caller]
fn raise_some(error: Option<Error>, function: &str) {
    if let Some(e) = error {
        raise(e, function);
    }
}

ffi_export! {
    /// Copies a UTF-8 string parameter to `*val` and ends it with a NUL: to the caller's
    /// buffer of `max_len` octets, or to one allocated with `OPENSSL_malloc` if `*val` is NULL.
    /// Returns 1, or 0 (the copy may be made) if there's no room for the NUL.
    ///
    /// Unlike OpenSSL, a NULL `p` returns 0 rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `p` is NULL or a parameter whose data is NULL or holds `data_size` octets; `val` is NULL
    /// or points to NULL or to a buffer of `max_len` octets.
    pub unsafe extern "C" fn OSSL_PARAM_get_utf8_string(p: *const OSSL_PARAM, val: *mut *mut c_char, max_len: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let name = "OSSL_PARAM_get_utf8_string";
        // SAFETY: the caller's guarantee.
        let room = match unsafe { get_string(p, val.cast(), max_len, ptr::null_mut(), UTF8_STRING) } {
            Ok(room) => room,
            Err(e) => {
                raise_some(e, name);
                return 0;
            }
        };
        // SAFETY: `get_string` succeeded, so `p` isn't NULL.
        let param = unsafe { &*p };
        // SAFETY: as above, `val` isn't NULL and `*val` holds a copy of the data.
        let out = unsafe { val.read() };
        let mut length = param.data_size;
        if length >= room {
            // SAFETY: the data holds `data_size` octets (`get_string` read them).
            let data = unsafe { core::slice::from_raw_parts(param.data.cast::<u8>(), length) };
            length = data.iter().position(|&c| c == 0).unwrap_or(length);
        }
        if length >= room {
            err::raise(ERR_LIB_CRYPTO, CRYPTO_R_NO_SPACE_FOR_TERMINATING_NULL, name);
            return 0;
        }
        // SAFETY: `length` is within the `room` octets of `*val`.
        unsafe { out.wrapping_add(length).write(0) };
        1
    }
}

ffi_export! {
    /// Copies an octet string parameter to `*val` (the caller's buffer of `max_len` octets,
    /// or one allocated with `OPENSSL_malloc` if `*val` is NULL) and its length to
    /// `*used_len`. With a NULL `val`, only the length is reported.
    ///
    /// # Safety
    /// `p` is NULL or a parameter whose data is NULL or holds `data_size` octets; `val` is NULL
    /// or points to NULL or to a buffer of `max_len` octets; `used_len` is NULL or valid for a
    /// write.
    pub unsafe extern "C" fn OSSL_PARAM_get_octet_string(p: *const OSSL_PARAM, val: *mut *mut c_void, max_len: usize, used_len: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        match unsafe { get_string(p, val, max_len, used_len, OCTET_STRING) } {
            Ok(_) => 1,
            Err(e) => {
                raise_some(e, "OSSL_PARAM_get_octet_string");
                0
            }
        }
    }
}

/// `set_string_internal`: stores `len` octets of `val` in a string parameter of type
/// `data_type`, then a NUL for a UTF-8 string if there's room.
///
/// # Safety
/// The parameter's data is NULL or holds `data_size` writable octets; `val` holds `len`
/// octets.
#[track_caller]
unsafe fn set_string(
    p: &mut OSSL_PARAM,
    val: *const c_void,
    len: usize,
    data_type: u32,
    function: &str,
) -> c_int {
    p.return_size = 0;
    if p.data_type != data_type {
        raise(Error::BadType, function);
        return 0;
    }
    p.return_size = len;
    if p.data.is_null() {
        return 1;
    }
    if p.data_size < len {
        raise(Error::TooSmall, function);
        return 0;
    }
    // SAFETY: the caller's guarantee; the data has room for `len` octets.
    unsafe { ptr::copy(val.cast::<u8>(), p.data.cast::<u8>(), len) };
    if data_type == UTF8_STRING && p.data_size > len {
        // SAFETY: the octet after the string is within the data.
        unsafe { p.data.cast::<u8>().wrapping_add(len).write(0) };
    }
    1
}

ffi_export! {
    /// Stores the string `val` in a UTF-8 string parameter (with a NUL if there's room) and
    /// its length in `return_size`; a NULL data pointer only reports the length.
    ///
    /// # Safety
    /// `p` is NULL or a parameter whose data is NULL or holds `data_size` writable octets;
    /// `val` is NULL or a string.
    pub unsafe extern "C" fn OSSL_PARAM_set_utf8_string(p: *mut OSSL_PARAM, val: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let name = "OSSL_PARAM_set_utf8_string";
        // SAFETY: the caller's guarantee.
        let Some(param) = (unsafe { p.as_mut() }).filter(|_| !val.is_null()) else {
            raise(Error::NullArgument, name);
            return 0;
        };
        // SAFETY: the caller's guarantee.
        let len = unsafe { CStr::from_ptr(val) }.count_bytes();
        // SAFETY: the caller's guarantee; the string holds `len` octets.
        unsafe { set_string(param, val.cast(), len, UTF8_STRING, name) }
    }
}

ffi_export! {
    /// Stores `len` octets of `val` in an octet string parameter and `len` in `return_size`; a
    /// NULL data pointer only reports the length.
    ///
    /// # Safety
    /// `p` is NULL or a parameter whose data is NULL or holds `data_size` writable octets;
    /// `val` is NULL or holds `len` octets.
    pub unsafe extern "C" fn OSSL_PARAM_set_octet_string(p: *mut OSSL_PARAM, val: *const c_void, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let name = "OSSL_PARAM_set_octet_string";
        // SAFETY: the caller's guarantee.
        let Some(param) = (unsafe { p.as_mut() }).filter(|_| !val.is_null()) else {
            raise(Error::NullArgument, name);
            return 0;
        };
        // SAFETY: the caller's guarantee.
        unsafe { set_string(param, val, len, OCTET_STRING, name) }
    }
}

/// `get_ptr_internal`: the pointer a `_ptr` parameter of type `data_type` holds, reporting
/// `data_size` through `used_len`. A NULL data pointer fails (OpenSSL reads through it).
///
/// # Safety
/// `p` is NULL or a parameter whose data is NULL or holds a pointer; `used_len` is NULL or
/// valid for a write.
unsafe fn get_ptr(
    p: *const OSSL_PARAM,
    used_len: *mut usize,
    data_type: u32,
) -> Result<*const c_void, Error> {
    // SAFETY: the caller's guarantee.
    let param = unsafe { p.as_ref() }.ok_or(Error::NullArgument)?;
    if param.data_type != data_type {
        return Err(Error::BadType);
    }
    if !used_len.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { used_len.write(param.data_size) };
    }
    if param.data.is_null() {
        return Err(Error::NullArgument);
    }
    // SAFETY: the caller's guarantee: the data holds a pointer, perhaps unaligned.
    Ok(unsafe { param.data.cast::<*const c_void>().read_unaligned() })
}

/// `get_string_ptr_internal`: the data pointer of a string parameter of type `data_type`,
/// reporting `data_size` through `used_len`.
///
/// # Safety
/// `p` is NULL or a parameter; `used_len` is NULL or valid for a write.
unsafe fn get_string_ptr(
    p: *const OSSL_PARAM,
    used_len: *mut usize,
    data_type: u32,
) -> Result<*const c_void, Error> {
    // SAFETY: the caller's guarantee.
    let param = unsafe { p.as_ref() }.ok_or(Error::NullArgument)?;
    if param.data_type != data_type {
        return Err(Error::BadType);
    }
    if !used_len.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { used_len.write(param.data_size) };
    }
    Ok(param.data.cast_const())
}

/// Stores a pointer result through `val`, or raises the error.
///
/// # Safety
/// `val` is valid for a write.
#[track_caller]
unsafe fn give<T>(
    val: *mut *const T,
    result: Result<*const c_void, Error>,
    function: &str,
) -> c_int {
    match result {
        Ok(v) => {
            // SAFETY: the caller's guarantee.
            unsafe { val.write(v.cast()) };
            1
        }
        Err(e) => {
            raise(e, function);
            0
        }
    }
}

ffi_export! {
    /// The string pointer a UTF-8 pointer parameter holds, through `*val`.
    ///
    /// Unlike OpenSSL, a NULL data pointer fails rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `p` is NULL or a parameter whose data is NULL or holds a pointer; `val` is NULL or
    /// valid for a write.
    pub unsafe extern "C" fn OSSL_PARAM_get_utf8_ptr(p: *const OSSL_PARAM, val: *mut *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let name = "OSSL_PARAM_get_utf8_ptr";
        if val.is_null() {
            raise(Error::NullArgument, name);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let result = unsafe { get_ptr(p, ptr::null_mut(), UTF8_PTR) };
        // SAFETY: `val` isn't NULL; the caller's guarantee.
        unsafe { give(val, result, name) }
    }
}

ffi_export! {
    /// The pointer an octet pointer parameter holds, through `*val`, and its length through
    /// `*used_len`.
    ///
    /// Unlike OpenSSL, a NULL data pointer fails rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `p` is NULL or a parameter whose data is NULL or holds a pointer; `val` is NULL or
    /// valid for a write; `used_len` is NULL or valid for a write.
    pub unsafe extern "C" fn OSSL_PARAM_get_octet_ptr(p: *const OSSL_PARAM, val: *mut *const c_void, used_len: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let name = "OSSL_PARAM_get_octet_ptr";
        if val.is_null() {
            raise(Error::NullArgument, name);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let result = unsafe { get_ptr(p, used_len, OCTET_PTR) };
        // SAFETY: `val` isn't NULL; the caller's guarantee.
        unsafe { give(val, result, name) }
    }
}

ffi_export! {
    /// The string a UTF-8 pointer or UTF-8 string parameter holds, through `*val`.
    ///
    /// # Safety
    /// `p` is NULL or a parameter whose data, for a pointer type, is NULL or holds a pointer;
    /// `val` is NULL or valid for a write.
    pub unsafe extern "C" fn OSSL_PARAM_get_utf8_string_ptr(p: *const OSSL_PARAM, val: *mut *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let name = "OSSL_PARAM_get_utf8_string_ptr";
        if val.is_null() {
            raise(Error::NullArgument, name);
            return 0;
        }
        // The pointer form's errors are dropped, as OpenSSL pops them to a mark.
        // SAFETY: the caller's guarantee.
        let mut result = unsafe { get_ptr(p, ptr::null_mut(), UTF8_PTR) };
        if result.is_err() {
            // SAFETY: the caller's guarantee.
            result = unsafe { get_string_ptr(p, ptr::null_mut(), UTF8_STRING) };
        }
        // SAFETY: `val` isn't NULL; the caller's guarantee.
        unsafe { give(val, result, name) }
    }
}

ffi_export! {
    /// The octets an octet pointer or octet string parameter holds, through `*val`, and their
    /// length through `*used_len`.
    ///
    /// # Safety
    /// `p` is NULL or a parameter whose data, for a pointer type, is NULL or holds a pointer;
    /// `val` is NULL or valid for a write; `used_len` is NULL or valid for a write.
    pub unsafe extern "C" fn OSSL_PARAM_get_octet_string_ptr(p: *const OSSL_PARAM, val: *mut *const c_void, used_len: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let name = "OSSL_PARAM_get_octet_string_ptr";
        if val.is_null() {
            raise(Error::NullArgument, name);
            return 0;
        }
        // The pointer form's errors are dropped, as OpenSSL pops them to a mark.
        // SAFETY: the caller's guarantee.
        let mut result = unsafe { get_ptr(p, used_len, OCTET_PTR) };
        if result.is_err() {
            // SAFETY: the caller's guarantee.
            result = unsafe { get_string_ptr(p, used_len, OCTET_STRING) };
        }
        // SAFETY: `val` isn't NULL; the caller's guarantee.
        unsafe { give(val, result, name) }
    }
}

/// `set_ptr_internal`: stores `val` in a `_ptr` parameter of type `data_type` and `len` in
/// `return_size`.
///
/// # Safety
/// The parameter's data is NULL or has room for a pointer.
#[track_caller]
unsafe fn set_ptr(
    p: &mut OSSL_PARAM,
    val: *const c_void,
    len: usize,
    data_type: u32,
    function: &str,
) -> c_int {
    p.return_size = 0;
    if p.data_type != data_type {
        raise(Error::BadType, function);
        return 0;
    }
    p.return_size = len;
    if !p.data.is_null() {
        // SAFETY: the caller's guarantee, perhaps unaligned.
        unsafe { p.data.cast::<*const c_void>().write_unaligned(val) };
    }
    1
}

ffi_export! {
    /// Stores the string pointer `val` in a UTF-8 pointer parameter and its length (0 for
    /// NULL) in `return_size`.
    ///
    /// # Safety
    /// `p` is NULL or a parameter whose data is NULL or has room for a pointer; `val` is NULL
    /// or a string.
    pub unsafe extern "C" fn OSSL_PARAM_set_utf8_ptr(p: *mut OSSL_PARAM, val: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let name = "OSSL_PARAM_set_utf8_ptr";
        // SAFETY: the caller's guarantee.
        let Some(param) = (unsafe { p.as_mut() }) else {
            raise(Error::NullArgument, name);
            return 0;
        };
        let len = if val.is_null() {
            0
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { CStr::from_ptr(val) }.count_bytes()
        };
        // SAFETY: the caller's guarantee.
        unsafe { set_ptr(param, val.cast(), len, UTF8_PTR, name) }
    }
}

ffi_export! {
    /// Stores the pointer `val` in an octet pointer parameter and `used_len` in
    /// `return_size`.
    ///
    /// # Safety
    /// `p` is NULL or a parameter whose data is NULL or has room for a pointer.
    pub unsafe extern "C" fn OSSL_PARAM_set_octet_ptr(p: *mut OSSL_PARAM, val: *const c_void, used_len: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let name = "OSSL_PARAM_set_octet_ptr";
        // SAFETY: the caller's guarantee.
        let Some(param) = (unsafe { p.as_mut() }) else {
            raise(Error::NullArgument, name);
            return 0;
        };
        // SAFETY: the caller's guarantee.
        unsafe { set_ptr(param, val, used_len, OCTET_PTR, name) }
    }
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::dup::*;
    use super::*;

    #[test]
    fn deviations_are_safe() {
        let mut p = construct(c"r".as_ptr(), REAL, ptr::null_mut(), 8);
        // SAFETY: NULL data is a size query here.
        let r = unsafe { OSSL_PARAM_set_uint64(&raw mut p, 5) };
        assert_eq!((r, p.return_size), (1, 8));
        let mut v = 0i32;
        let empty = construct(c"e".as_ptr(), INTEGER, (&raw mut v).cast(), 0);
        // SAFETY: an empty integer reads as zero.
        let r = unsafe { OSSL_PARAM_get_int32(&raw const empty, &raw mut v) };
        assert_eq!((r, v), (1, 0));
        let ptr_param = construct(c"p".as_ptr(), UTF8_PTR, ptr::null_mut(), 0);
        let mut s: *const c_char = ptr::null();
        // SAFETY: NULL data fails.
        let r = unsafe { OSSL_PARAM_get_utf8_ptr(&raw const ptr_param, &raw mut s) };
        assert_eq!(r, 0);
        // SAFETY: a NULL parameter fails.
        let r = unsafe { OSSL_PARAM_get_utf8_string(ptr::null(), ptr::null_mut(), 0) };
        assert_eq!(r, 0);
        let mut w = 0i64;
        let huge = construct(c"h".as_ptr(), INTEGER, (&raw mut w).cast(), usize::MAX);
        // SAFETY: a size no object has is refused before the data is read.
        let r = unsafe { OSSL_PARAM_get_int64(&raw const huge, &raw mut w) };
        assert_eq!(r, 0);
        // SAFETY: no preconditions.
        let bld = unsafe { build::OSSL_PARAM_BLD_new() };
        // SAFETY: a size with no room for the NUL is refused before the string is read.
        let r = unsafe {
            build::OSSL_PARAM_BLD_push_utf8_string(bld, c"k".as_ptr(), c"x".as_ptr(), usize::MAX)
        };
        assert_eq!(r, 0);
        // SAFETY: the builder.
        unsafe { build::OSSL_PARAM_BLD_free(bld) };
    }

    #[test]
    fn strings_and_pointers() {
        let mut text = *b"hello\0";
        let p = construct(c"s".as_ptr(), UTF8_STRING, text.as_mut_ptr().cast(), 5);
        let mut got: *mut c_char = ptr::null_mut();
        // SAFETY: the data holds 5 octets; `got` receives an allocation.
        let r = unsafe { OSSL_PARAM_get_utf8_string(&raw const p, &raw mut got, 0) };
        assert_eq!(r, 1);
        // SAFETY: allocated and NUL-terminated above.
        assert_eq!(unsafe { CStr::from_ptr(got) }, c"hello");
        // SAFETY: from `OPENSSL_malloc`.
        unsafe { mem::release(got.cast()) };
        let mut out = [0xaau8; 4];
        let mut w = construct(c"w".as_ptr(), UTF8_STRING, out.as_mut_ptr().cast(), 4);
        // SAFETY: the data holds 4 octets.
        let r = unsafe { OSSL_PARAM_set_utf8_string(&raw mut w, c"abc".as_ptr()) };
        assert_eq!((r, out), (1, *b"abc\0"));
        let mut target: *mut c_char = ptr::null_mut();
        let mut q = construct(c"q".as_ptr(), UTF8_PTR, (&raw mut target).cast(), 0);
        // SAFETY: the data holds a pointer.
        let r = unsafe { OSSL_PARAM_set_utf8_ptr(&raw mut q, c"xy".as_ptr()) };
        assert_eq!((r, q.return_size), (1, 2));
        let mut back: *const c_char = ptr::null();
        // SAFETY: as above.
        let r = unsafe { OSSL_PARAM_get_utf8_string_ptr(&raw const q, &raw mut back) };
        assert_eq!((r, back), (1, target.cast_const()));
    }

    #[test]
    fn dup_merge_and_build() {
        let mut n = 7i64;
        let mut octets = *b"abc";
        let params = [
            construct(c"n".as_ptr(), INTEGER, (&raw mut n).cast(), 8),
            construct(c"O".as_ptr(), OCTET_STRING, octets.as_mut_ptr().cast(), 3),
            construct(c"null".as_ptr(), OCTET_STRING, ptr::null_mut(), 2),
            end(),
        ];
        // SAFETY: an array ended by a NULL key.
        let dup = unsafe { OSSL_PARAM_dup(params.as_ptr()) };
        assert!(!dup.is_null());
        // SAFETY: the copy of the second parameter.
        let second = unsafe { &*dup.wrapping_add(1) };
        // SAFETY: its data holds 3 octets.
        let copied = unsafe { core::slice::from_raw_parts(second.data.cast::<u8>(), 3) };
        assert_eq!(copied, b"abc");
        // SAFETY: the copy's terminator.
        assert_eq!(unsafe { (*dup.wrapping_add(3)).data_type }, ALLOCATED_END);
        // SAFETY: both arrays end with a NULL key.
        let merged = unsafe { OSSL_PARAM_merge(params.as_ptr(), dup) };
        // SAFETY: the merge's first entry.
        let first = unsafe { &*merged };
        // SAFETY: its key is a string.
        assert_eq!(unsafe { CStr::from_ptr(first.key) }, c"n");
        // SAFETY: from merge and dup.
        unsafe { OSSL_PARAM_free(merged) };
        // SAFETY: as above.
        unsafe { OSSL_PARAM_free(dup) };

        // SAFETY: no preconditions.
        let bld = unsafe { OSSL_PARAM_BLD_new() };
        // SAFETY: a live builder; the keys and strings are static.
        let a = unsafe { OSSL_PARAM_BLD_push_int(bld, c"i".as_ptr(), -2) };
        // SAFETY: as above.
        let b = unsafe { OSSL_PARAM_BLD_push_utf8_string(bld, c"s".as_ptr(), c"text".as_ptr(), 0) };
        // SAFETY: as above.
        let c = unsafe { OSSL_PARAM_BLD_push_octet_ptr(bld, c"p".as_ptr(), ptr::null_mut(), 0) };
        assert_eq!((a, b, c), (1, 1, 1));
        // SAFETY: a live builder.
        let built = unsafe { OSSL_PARAM_BLD_to_param(bld) };
        // SAFETY: the built array has three parameters and a terminator.
        let s = unsafe { &*built.wrapping_add(1) };
        // SAFETY: a UTF-8 string with its NUL.
        assert_eq!(unsafe { CStr::from_ptr(s.data.cast()) }, c"text");
        let mut v = 0i32;
        // SAFETY: the first built parameter.
        let r = unsafe { OSSL_PARAM_get_int32(built, &raw mut v) };
        assert_eq!((r, v), (1, -2));
        // SAFETY: from the builder.
        unsafe { OSSL_PARAM_free(built) };
        // SAFETY: the builder.
        unsafe { OSSL_PARAM_BLD_free(bld) };
    }
}
