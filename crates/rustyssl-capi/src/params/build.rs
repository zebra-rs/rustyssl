//! `OSSL_PARAM_BLD(3)` (`crypto/param_build.c`): a builder that collects parameters and makes
//! them one array, as `OSSL_PARAM_dup` lays it out, with data from the secure heap copied to a
//! secure block.
//!
//! The builder keeps the caller's pointers, as OpenSSL does: the keys go into the array as they
//! are, and strings are read only by `OSSL_PARAM_BLD_to_param`, so each must stay valid until
//! then. The big-number pushes come with BIGNUM (step 4.1).

use core::ffi::{CStr, c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr;
use std::sync::Mutex;

use libc::time_t;
use rustyssl_abi::{ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, OSSL_PARAM, OSSL_PARAM_BLD};
use rustyssl_crypto::params::{
    INTEGER, OCTET_PTR, OCTET_STRING, REAL, UNSIGNED_INTEGER, UTF8_PTR, UTF8_STRING,
};

use super::dup::{ALIGN, allocated_end, array_blocks, blocks};
use super::unmodified;
use crate::err;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::{mem, secure};

/// A pointer of the caller's, kept until `OSSL_PARAM_BLD_to_param`.
#[derive(Clone, Copy)]
struct Kept(*const c_void);

// SAFETY: the builder only stores the pointer and reads through it in `to_param`, on the
// caller's thread, as OpenSSL does; it may be stored from any thread.
unsafe impl Send for Kept {}
// SAFETY: as above.
unsafe impl Sync for Kept {}

/// `OSSL_PARAM_BLD_DEF`: a pushed parameter.
struct Def {
    key: Kept,
    data_type: u32,
    size: usize,
    blocks: usize,
    secure: bool,
    /// A number's native octets.
    num: [u8; 8],
    /// A string's or pointer's address.
    string: Kept,
}

/// The builder: the parameters pushed since it was made or last turned into an array.
#[derive(Default)]
pub(crate) struct Builder {
    defs: Mutex<Vec<Def>>,
}

handle_type!(OSSL_PARAM_BLD => Builder);

/// Adds the parameter `key` defined by `def`. Returns 1, or 0 if the builder is poisoned.
fn push(bld: &Builder, key: *const c_char, def: Def) -> c_int {
    let Ok(mut defs) = bld.defs.lock() else {
        return 0;
    };
    defs.push(Def {
        key: Kept(key.cast()),
        ..def
    });
    1
}

/// The builder behind `bld`, raising `ERR_R_PASSED_NULL_PARAMETER` for NULL or a NULL key.
///
/// # Safety
/// `bld` is NULL or a live builder that outlives `'a`.
#[track_caller]
unsafe fn builder<'a>(
    bld: *mut OSSL_PARAM_BLD,
    key: *const c_char,
    function: &str,
) -> Option<&'a Builder> {
    // SAFETY: the caller's guarantee.
    let b = unsafe { OSSL_PARAM_BLD::get(bld) }.filter(|_| !key.is_null());
    if b.is_none() {
        err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, function);
    }
    b
}

/// A definition of `size` octets taking `alloc` octets of the array.
fn def(data_type: u32, size: usize, alloc: usize, secure: bool) -> Option<Def> {
    Some(Def {
        key: Kept(ptr::null()),
        data_type,
        size,
        blocks: blocks(alloc)?,
        secure,
        num: [0; 8],
        string: Kept(ptr::null()),
    })
}

ffi_export! {
    /// A new, empty builder, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_PARAM_BLD_new() -> *mut OSSL_PARAM_BLD
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        OSSL_PARAM_BLD::new_handle(Builder::default())
    }
}

ffi_export! {
    /// Frees a builder and what it holds (not the caller's keys or strings); NULL does nothing.
    ///
    /// # Safety
    /// `bld` is NULL or a live builder, not used afterwards.
    pub unsafe extern "C" fn OSSL_PARAM_BLD_free(bld: *mut OSSL_PARAM_BLD)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { OSSL_PARAM_BLD::free(bld) };
    }
}

/// Defines the number pushes: each copies the value's native octets.
macro_rules! push_numbers {
    ($(
        $(#[$attr:meta])*
        pub unsafe extern "C" fn $name:ident($ty:ty) = $data_type:ident;
    )*) => {$(
        ffi_export! {
            $(#[$attr])*
            ///
            /// # Safety
            /// `bld` is NULL or a live builder; `key` is NULL or a string that outlives the
            /// array made from the builder.
            pub unsafe extern "C" fn $name(bld: *mut OSSL_PARAM_BLD, key: *const c_char, num: $ty) -> c_int
            where failure = 0, library = ERR_LIB_CRYPTO
            {
                // SAFETY: the caller's guarantee.
                let Some(b) = (unsafe { builder(bld, key, stringify!($name)) }) else { return 0 };
                let octets = num.to_ne_bytes();
                let Some(mut d) = def($data_type, octets.len(), octets.len(), false) else { return 0 };
                let Some(slot) = d.num.get_mut(..octets.len()) else { return 0 };
                slot.copy_from_slice(&octets);
                push(b, key, d)
            }
        }
    )*};
}

push_numbers! {
    /// Adds an `int` parameter `key`. Returns 1, or 0 on failure.
    pub unsafe extern "C" fn OSSL_PARAM_BLD_push_int(c_int) = INTEGER;
    /// Adds an `unsigned int` parameter `key`.
    pub unsafe extern "C" fn OSSL_PARAM_BLD_push_uint(c_uint) = UNSIGNED_INTEGER;
    /// Adds a `long` parameter `key`.
    pub unsafe extern "C" fn OSSL_PARAM_BLD_push_long(c_long) = INTEGER;
    /// Adds an `unsigned long` parameter `key`.
    pub unsafe extern "C" fn OSSL_PARAM_BLD_push_ulong(c_ulong) = UNSIGNED_INTEGER;
    /// Adds an `int32_t` parameter `key`.
    pub unsafe extern "C" fn OSSL_PARAM_BLD_push_int32(i32) = INTEGER;
    /// Adds a `uint32_t` parameter `key`.
    pub unsafe extern "C" fn OSSL_PARAM_BLD_push_uint32(u32) = UNSIGNED_INTEGER;
    /// Adds an `int64_t` parameter `key`.
    pub unsafe extern "C" fn OSSL_PARAM_BLD_push_int64(i64) = INTEGER;
    /// Adds a `uint64_t` parameter `key`.
    pub unsafe extern "C" fn OSSL_PARAM_BLD_push_uint64(u64) = UNSIGNED_INTEGER;
    /// Adds a `size_t` parameter `key`.
    pub unsafe extern "C" fn OSSL_PARAM_BLD_push_size_t(usize) = UNSIGNED_INTEGER;
    /// Adds a `time_t` parameter `key`.
    pub unsafe extern "C" fn OSSL_PARAM_BLD_push_time_t(time_t) = INTEGER;
    /// Adds a `double` parameter `key`.
    pub unsafe extern "C" fn OSSL_PARAM_BLD_push_double(f64) = REAL;
}

/// Pushes a string or pointer parameter: `size` octets, `alloc` of the array.
///
/// # Safety
/// `bld` is NULL or a live builder.
#[track_caller]
#[expect(
    clippy::too_many_arguments,
    reason = "each is one of OpenSSL's `param_push` inputs"
)]
unsafe fn push_string(
    bld: *mut OSSL_PARAM_BLD,
    key: *const c_char,
    buf: *const c_void,
    data_type: u32,
    size: usize,
    alloc: Option<usize>,
    secure: bool,
    function: &str,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(b) = (unsafe { builder(bld, key, function) }) else {
        return 0;
    };
    let Some(mut d) = alloc.and_then(|a| def(data_type, size, a, secure)) else {
        // A size no string can have.
        err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, function);
        return 0;
    };
    d.string = Kept(buf);
    push(b, key, d)
}

/// The length of a pushed string: `bsize`, or the string's own if 0.
///
/// # Safety
/// `buf` is a string if `bsize` is 0.
unsafe fn string_size(buf: *const c_char, bsize: usize) -> usize {
    if bsize != 0 {
        return bsize;
    }
    // SAFETY: the caller's guarantee.
    unsafe { CStr::from_ptr(buf) }.count_bytes()
}

ffi_export! {
    /// Adds a UTF-8 string parameter `key`: `bsize` octets of `buf` (its own length if 0),
    /// read when the array is made.
    ///
    /// # Safety
    /// `bld` is NULL or a live builder; `key` is NULL or a string; `buf` is NULL, or holds
    /// `bsize` octets (a string if `bsize` is 0) until the array is made.
    pub unsafe extern "C" fn OSSL_PARAM_BLD_push_utf8_string(bld: *mut OSSL_PARAM_BLD, key: *const c_char, buf: *const c_char, bsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let name = "OSSL_PARAM_BLD_push_utf8_string";
        if buf.is_null() {
            err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, name);
            return 0;
        }
        // SAFETY: the caller's guarantee (checked for NULL first, as OpenSSL does).
        if unsafe { builder(bld, key, name) }.is_none() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let size = unsafe { string_size(buf, bsize) };
        let secure = secure::in_arena(buf.cast());
        // SAFETY: the caller's guarantee.
        unsafe { push_string(bld, key, buf.cast(), UTF8_STRING, size, size.checked_add(1), secure, name) }
    }
}

ffi_export! {
    /// Adds a UTF-8 pointer parameter `key` holding `buf`, of `bsize` octets (its own length if
    /// 0).
    ///
    /// # Safety
    /// `bld` is NULL or a live builder; `key` is NULL or a string; `buf` is NULL or, if `bsize`
    /// is 0, a string.
    pub unsafe extern "C" fn OSSL_PARAM_BLD_push_utf8_ptr(bld: *mut OSSL_PARAM_BLD, key: *const c_char, buf: *mut c_char, bsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let name = "OSSL_PARAM_BLD_push_utf8_ptr";
        if buf.is_null() {
            err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, name);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        if unsafe { builder(bld, key, name) }.is_none() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let size = unsafe { string_size(buf, bsize) };
        // SAFETY: the caller's guarantee.
        unsafe { push_string(bld, key, buf.cast(), UTF8_PTR, size, Some(size_of::<*const c_void>()), false, name) }
    }
}

ffi_export! {
    /// Adds an octet string parameter `key`: `bsize` octets of `buf`, read when the array is
    /// made.
    ///
    /// # Safety
    /// `bld` is NULL or a live builder; `key` is NULL or a string; `buf` is NULL (with a
    /// `bsize` of 0) or holds `bsize` octets until the array is made.
    pub unsafe extern "C" fn OSSL_PARAM_BLD_push_octet_string(bld: *mut OSSL_PARAM_BLD, key: *const c_char, buf: *const c_void, bsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let name = "OSSL_PARAM_BLD_push_octet_string";
        if buf.is_null() && bsize != 0 {
            err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, name);
            return 0;
        }
        let secure = secure::in_arena(buf);
        // SAFETY: the caller's guarantee.
        unsafe { push_string(bld, key, buf, OCTET_STRING, bsize, Some(bsize), secure, name) }
    }
}

ffi_export! {
    /// Adds an octet pointer parameter `key` holding `buf`, of `bsize` octets.
    ///
    /// # Safety
    /// `bld` is NULL or a live builder; `key` is NULL or a string.
    pub unsafe extern "C" fn OSSL_PARAM_BLD_push_octet_ptr(bld: *mut OSSL_PARAM_BLD, key: *const c_char, buf: *mut c_void, bsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let name = "OSSL_PARAM_BLD_push_octet_ptr";
        if buf.is_null() && bsize != 0 {
            err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, name);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { push_string(bld, key, buf, OCTET_PTR, bsize, Some(size_of::<*const c_void>()), false, name) }
    }
}

/// Writes a parameter's data at `to`, which has room for its units.
///
/// # Safety
/// `to` has room for `d.blocks` units; a string `d` points to holds `d.size` octets.
unsafe fn fill(d: &Def, to: *mut u8) {
    match d.data_type {
        OCTET_PTR | UTF8_PTR => {
            // SAFETY: the room counted for a pointer, perhaps unaligned.
            unsafe { to.cast::<*const c_void>().write_unaligned(d.string.0) };
        }
        OCTET_STRING | UTF8_STRING => {
            if d.string.0.is_null() {
                // SAFETY: the room counted for `size` octets.
                unsafe { to.write_bytes(0, d.size) };
            } else {
                // SAFETY: the caller's guarantee for the string, and the room for `size`.
                unsafe { ptr::copy_nonoverlapping(d.string.0.cast::<u8>(), to, d.size) };
            }
            if d.data_type == UTF8_STRING {
                // SAFETY: the room counted one octet more for the NUL.
                unsafe { to.add(d.size).write(0) };
            }
        }
        _ => {
            let n = d.size.min(d.num.len());
            // SAFETY: the room counted for `size` octets.
            unsafe { ptr::copy_nonoverlapping(d.num.as_ptr(), to, n) };
        }
    }
}

ffi_export! {
    /// The parameters pushed so far as one array (free it with `OSSL_PARAM_free`), each
    /// unmodified, and the builder emptied for reuse. NULL on failure.
    ///
    /// # Safety
    /// `bld` is NULL or a live builder whose pushed strings are still valid.
    pub unsafe extern "C" fn OSSL_PARAM_BLD_to_param(bld: *mut OSSL_PARAM_BLD) -> *mut OSSL_PARAM
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { OSSL_PARAM_BLD::get(bld) }) else {
            err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, "OSSL_PARAM_BLD_to_param");
            return ptr::null_mut();
        };
        let Ok(mut guard) = b.defs.lock() else { return ptr::null_mut() };
        let defs = core::mem::take(&mut *guard);
        drop(guard);
        let units = |secure: bool| -> Option<usize> {
            defs.iter().filter(|d| d.secure == secure).try_fold(0usize, |n, d| n.checked_add(d.blocks))
        };
        let (Some(head), Some(public), Some(private)) =
            (defs.len().checked_add(1).and_then(array_blocks), units(false), units(true))
        else {
            return ptr::null_mut();
        };
        let (Some(size), Some(secure_size)) =
            (head.checked_add(public).and_then(|n| n.checked_mul(ALIGN)), private.checked_mul(ALIGN))
        else {
            return ptr::null_mut();
        };
        let mut secure_block = ptr::null_mut::<u8>();
        if secure_size > 0 {
            secure_block = secure::alloc(secure_size).cast();
            if secure_block.is_null() {
                return ptr::null_mut();
            }
        }
        let block = mem::alloc_zeroed(size).cast::<u8>();
        if block.is_null() {
            // SAFETY: just allocated, of `secure_size` octets.
            unsafe { secure::release_clean(secure_block.cast(), secure_size) };
            return ptr::null_mut();
        }
        let array = block.cast::<OSSL_PARAM>();
        let mut public_at = block.wrapping_add(head * ALIGN);
        let mut secure_at = secure_block;
        for (i, d) in defs.iter().enumerate() {
            let cursor = if d.secure { &mut secure_at } else { &mut public_at };
            let to = *cursor;
            *cursor = to.wrapping_add(d.blocks * ALIGN);
            // SAFETY: the units counted for `d`; the caller's guarantee for its string.
            unsafe { fill(d, to) };
            let param = OSSL_PARAM {
                key: d.key.0.cast(),
                data_type: d.data_type,
                data: to.cast(),
                data_size: d.size,
                return_size: unmodified(),
            };
            // SAFETY: the array has room for every parameter and the terminator.
            unsafe { array.add(i).write(param) };
        }
        // SAFETY: the terminator's place.
        unsafe { array.add(defs.len()).write(allocated_end(secure_block.cast(), secure_size)) };
        array
    }
}
