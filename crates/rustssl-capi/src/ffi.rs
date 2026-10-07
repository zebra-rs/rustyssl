//! The C boundary (security rules 2 and 3).
//!
//! Every export runs inside [`guard`], usually through [`ffi_export!`]: a panic becomes an
//! `ERR_R_INTERNAL_ERROR` on the error queue and the function's failure value, never an unwind
//! into C. The conversions turn C's integers and pointer-length pairs into checked Rust values,
//! once, at the boundary.
//!
//! # C-variadic exports
//!
//! `ffi_export!` doesn't take `...`. Write such an export by hand and move its argument list
//! into a helper that the `v` variant (the one taking a `va_list`) shares:
//!
//! ```ignore
//! #[unsafe(no_mangle)]
//! pub unsafe extern "C" fn BIO_printf(bio: *mut BIO, format: *const c_char, args: ...) -> c_int {
//!     guard(ERR_LIB_BIO, "BIO_printf", || -1, move || print(bio, format, args))
//! }
//!
//! ffi_export! {
//!     pub unsafe extern "C" fn BIO_vprintf(bio: *mut BIO, format: *const c_char, args: VaList<'_>) -> c_int
//!     where failure = -1, library = ERR_LIB_BIO
//!     { print(bio, format, args) }
//! }
//! ```

use core::ffi::{c_char, c_int};
use std::panic::{AssertUnwindSafe, catch_unwind};

use rustssl_abi::ERR_R_INTERNAL_ERROR;

use crate::err;

/// Runs an export's `body`. If it panics, raises `ERR_R_INTERNAL_ERROR` for `library` and
/// returns `failure()` instead of unwinding into C. Objects the body was changing may be left
/// partly updated, as after any internal error; a panic is always a bug.
pub(crate) fn guard<R>(
    library: c_int,
    function: &'static str,
    failure: impl FnOnce() -> R,
    body: impl FnOnce() -> R,
) -> R {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or_else(|_| {
        err::raise(library, ERR_R_INTERNAL_ERROR, function);
        failure()
    })
}

/// Defines an exported C function whose body runs inside [`guard`].
///
/// ```ignore
/// ffi_export! {
///     /// Docs, including a `# Safety` section on what C must guarantee.
///     pub unsafe extern "C" fn BUF_MEM_grow(buffer: *mut BUF_MEM, len: usize) -> usize
///     where failure = 0, library = ERR_LIB_BUF
///     {
///         // ...
///     }
/// }
/// ```
///
/// `failure` is what the function returns after a panic (`()` for `void` functions), and
/// `library` is the `ERR_LIB_*` code the panic is reported under.
macro_rules! ffi_export {
    (
        $(#[$attr:meta])*
        pub unsafe extern "C" fn $name:ident ( $($arg:ident : $ty:ty),* $(,)? ) $(-> $ret:ty)?
        where failure = $failure:expr, library = $library:path
        $body:block
    ) => {
        $(#[$attr])*
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name($($arg: $ty),*) $(-> $ret)? {
            $crate::ffi::guard($library, stringify!($name), || $failure, move || $body)
        }
    };
}
pub(crate) use ffi_export;

/// A C length that must not be negative, as `usize`.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "first used by the step 1 exports")
)]
pub(crate) fn length(len: c_int) -> Option<usize> {
    usize::try_from(len).ok()
}

/// A Rust length as a C `int`, or `None` if it doesn't fit.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "first used by the step 1 exports")
)]
pub(crate) fn to_c_int(len: usize) -> Option<c_int> {
    c_int::try_from(len).ok()
}

/// The `len` bytes at `data`, or `None` if `data` is null while `len` isn't zero. A null
/// pointer with a zero length is an empty slice, which C callers commonly pass.
///
/// # Safety
/// If `data` isn't null, it is valid for `len` bytes of reads that nothing writes to for `'a`.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "first used by the step 1 exports")
)]
pub(crate) unsafe fn bytes<'a>(data: *const u8, len: usize) -> Option<&'a [u8]> {
    if data.is_null() {
        return (len == 0).then_some(&[]);
    }
    // SAFETY: the caller guarantees `len` readable bytes at `data` for `'a`.
    Some(unsafe { std::slice::from_raw_parts(data, len) })
}

/// OpenSSL's common "length or -1" convention: the `len` bytes at `data`, or up to the NUL if
/// `len` is negative.
///
/// # Safety
/// `data` is null, or valid for `len` bytes of reads, or (when `len` is negative) a
/// NUL-terminated string; nothing writes to it for `'a`.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "first used by the step 1 exports")
)]
pub(crate) unsafe fn bytes_or_c_str<'a>(data: *const c_char, len: c_int) -> Option<&'a [u8]> {
    match length(len) {
        // SAFETY: the caller guarantees `len` readable bytes at `data`.
        Some(len) => unsafe { bytes(data.cast(), len) },
        None if data.is_null() => None,
        // SAFETY: the caller guarantees a NUL-terminated string at `data` for `'a`.
        None => Some(unsafe { core::ffi::CStr::from_ptr(data) }.to_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustssl_abi::ERR_LIB_BUF;

    #[test]
    fn guard_turns_a_panic_into_an_error_and_the_failure_value() {
        err::take_all();
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = guard(ERR_LIB_BUF, "TEST_function", || -1, || panic!("bug"));
        std::panic::set_hook(previous);
        assert_eq!(result, -1);
        let errors = err::take_all();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code, err::pack(ERR_LIB_BUF, ERR_R_INTERNAL_ERROR));
        assert_eq!(errors[0].function, "TEST_function");
    }

    #[test]
    fn guard_passes_results_through() {
        err::take_all();
        assert_eq!(guard(ERR_LIB_BUF, "TEST_function", || 0, || 7), 7);
        assert!(err::take_all().is_empty());
    }

    #[test]
    fn conversions_reject_what_doesnt_fit() {
        assert_eq!(length(5), Some(5));
        assert_eq!(length(-1), None);
        assert_eq!(to_c_int(7), Some(7));
        assert_eq!(to_c_int(usize::MAX), None);
    }

    #[test]
    fn byte_slices_follow_c_conventions() {
        let text = c"hello";
        // SAFETY: null with a zero length is allowed, and nothing else is dereferenced.
        assert_eq!(unsafe { bytes(core::ptr::null(), 0) }, Some(&[][..]));
        // SAFETY: a null pointer is never dereferenced.
        assert_eq!(unsafe { bytes(core::ptr::null(), 3) }, None);
        // SAFETY: `text` holds 5 bytes before its NUL.
        assert_eq!(unsafe { bytes(text.as_ptr().cast(), 3) }, Some(&b"hel"[..]));
        // SAFETY: `text` is NUL-terminated.
        let whole = unsafe { bytes_or_c_str(text.as_ptr(), -1) };
        assert_eq!(whole, Some(&b"hello"[..]));
        // SAFETY: `text` holds 5 bytes before its NUL.
        let prefix = unsafe { bytes_or_c_str(text.as_ptr(), 2) };
        assert_eq!(prefix, Some(&b"he"[..]));
        // SAFETY: a null pointer is never dereferenced.
        assert_eq!(unsafe { bytes_or_c_str(core::ptr::null(), -1) }, None);
    }

    /// The C-variadic pattern from the module docs: the export moves its argument list into
    /// a guarded helper shared with the `va_list` variant.
    #[test]
    fn variadic_exports_hand_their_arguments_to_a_guarded_helper() {
        use core::ffi::VaList;

        fn sum(count: c_int, mut args: VaList<'_>) -> c_int {
            (0..count)
                // SAFETY: the callers below pass `count` ints.
                .map(|_| unsafe { args.next_arg::<c_int>() })
                .sum()
        }
        unsafe extern "C" fn test_sum(count: c_int, args: ...) -> c_int {
            guard(ERR_LIB_BUF, "test_sum", || -1, move || sum(count, args))
        }
        // SAFETY: three ints follow, as `count` says.
        assert_eq!(unsafe { test_sum(3, 1, 2, 39) }, 42);
    }
}
