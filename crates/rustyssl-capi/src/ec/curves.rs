//! The built-in curves (`EC_get_builtin_curves`) and their names (`EC_curve_nid2nist`,
//! `EC_curve_nist2nid`, `OSSL_EC_curve_nid2name`), from the generated curve table. The strings
//! are made once, NUL-terminated, at fixed addresses.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use std::ffi::CString;
use std::sync::LazyLock;

use rustyssl_abi::{EC_builtin_curve, ERR_LIB_EC, NID_undef};
use rustyssl_crypto::ec::curves;

use crate::ffi::ffi_export;

/// A string table entry at a fixed address.
struct Named {
    nid: c_int,
    text: CString,
}

/// Each curve's comment, in table order.
static COMMENTS: LazyLock<Vec<Named>> = LazyLock::new(|| {
    curves::builtin()
        .iter()
        .map(|c| Named {
            nid: c.nid,
            text: CString::new(c.comment).unwrap_or_default(),
        })
        .collect()
});

/// A NUL-terminated copy of a static name, made once per name.
fn c_name(name: &'static str) -> *const c_char {
    static NAMES: LazyLock<std::sync::Mutex<Vec<(&'static str, CString)>>> =
        LazyLock::new(|| std::sync::Mutex::new(Vec::new()));
    let mut names = NAMES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((_, c)) = names.iter().find(|(n, _)| *n == name) {
        return c.as_ptr();
    }
    let c = CString::new(name).unwrap_or_default();
    let p = c.as_ptr();
    names.push((name, c));
    p
}

ffi_export! {
    /// The built-in curves: up to `nitems` into `r`; returns how many there are.
    ///
    /// # Safety
    /// `r` is NULL or has room for `nitems` entries.
    pub unsafe extern "C" fn EC_get_builtin_curves(r: *mut EC_builtin_curve, nitems: usize) -> usize
    where failure = 0, library = ERR_LIB_EC
    {
        let all = &*COMMENTS;
        if r.is_null() || nitems == 0 {
            return all.len();
        }
        for (i, c) in all.iter().take(nitems).enumerate() {
            // SAFETY: the caller's room for `nitems` entries.
            let slot = unsafe { r.add(i) };
            let entry = EC_builtin_curve {
                nid: c.nid,
                comment: c.text.as_ptr(),
            };
            // SAFETY: as above.
            unsafe { slot.write(entry) };
        }
        all.len()
    }
}

ffi_export! {
    /// The NIST name of a curve (`P-256`, ...), or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EC_curve_nid2nist(nid: c_int) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        curves::nist_name(nid).map_or(ptr::null(), c_name)
    }
}

ffi_export! {
    /// The curve with this NIST name (exactly), or `NID_undef`.
    ///
    /// # Safety
    /// `name` is a string.
    pub unsafe extern "C" fn EC_curve_nist2nid(name: *const c_char) -> c_int
    where failure = NID_undef, library = ERR_LIB_EC
    {
        if name.is_null() {
            return NID_undef;
        }
        // SAFETY: the caller's string.
        let n = unsafe { CStr::from_ptr(name) }.to_bytes();
        curves::nist_nid(n).unwrap_or(NID_undef)
    }
}

ffi_export! {
    /// A curve's name (`prime256v1`, ...), or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_EC_curve_nid2name(nid: c_int) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        curves::name(nid).map_or(ptr::null(), c_name)
    }
}
