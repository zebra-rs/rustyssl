//! What the wrappers share: C strings in both directions, `OPENSSL_free`, and owned handles.

use core::ffi::{CStr, c_char, c_void};
use std::ffi::CString;

use crate::ffi;

/// A Rust string as a C string; `None` if it holds a NUL (which no C caller could pass).
pub fn cstring(s: &str) -> Option<CString> {
    CString::new(s).ok()
}

/// The C string at `p` (copied), or `None` for NULL.
///
/// Every caller passes a pointer the library returned as a NUL-terminated string that stays
/// valid at least until this returns.
pub(crate) fn string_at(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: p is non-NULL and, per the caller's contract above, a valid C string.
    Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
}

/// `OPENSSL_free(p)`.
pub(crate) fn openssl_free(p: *mut c_void) {
    // SAFETY: p is NULL or memory the library allocated for the caller to free.
    unsafe { ffi::CRYPTO_free(p, c"rustyssl-ossl".as_ptr(), 0) };
}

/// The C string at `p` (copied), then `OPENSSL_free(p)`.
pub(crate) fn take_string(p: *mut c_char) -> Option<String> {
    let s = string_at(p);
    openssl_free(p.cast());
    s
}

/// An owned library object, freed with its `*_free` when dropped.
#[macro_export]
#[doc(hidden)]
macro_rules! handle {
    ($(#[$m:meta])* $name:ident, $ty:ident, $free:ident) => {
        $(#[$m])*
        pub struct $name(core::ptr::NonNull<$crate::abi::$ty>);

        impl $name {
            /// Takes ownership of `p`; `None` for NULL.
            #[allow(dead_code)]
            pub(crate) fn from_ptr(p: *mut $crate::abi::$ty) -> Option<Self> {
                core::ptr::NonNull::new(p).map(Self)
            }

            /// The object, for the C API (it stays owned by `self`).
            pub fn as_ptr(&self) -> *mut $crate::abi::$ty {
                self.0.as_ptr()
            }

            /// Gives up ownership: the caller now frees it (or hands it to a `set0`/`push0`).
            pub fn into_ptr(self) -> *mut $crate::abi::$ty {
                let p = self.0.as_ptr();
                core::mem::forget(self);
                p
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                // SAFETY: the pointer is owned by self, and freed exactly once, here.
                unsafe { $crate::ffi::$free(self.0.as_ptr()) };
            }
        }
    };
}
