//! Object names and NIDs (`OBJ_*`).

use core::ffi::c_int;

use crate::ffi;
use crate::util::{cstring, string_at};

/// `OBJ_sn2nid`.
pub fn sn2nid(s: &str) -> c_int {
    let Some(c) = cstring(s) else {
        return 0;
    };
    // SAFETY: c is a valid C string.
    unsafe { ffi::OBJ_sn2nid(c.as_ptr()) }
}

/// `OBJ_ln2nid`.
pub fn ln2nid(s: &str) -> c_int {
    let Some(c) = cstring(s) else {
        return 0;
    };
    // SAFETY: c is a valid C string.
    unsafe { ffi::OBJ_ln2nid(c.as_ptr()) }
}

/// `OBJ_txt2nid`.
pub fn txt2nid(s: &str) -> c_int {
    let Some(c) = cstring(s) else {
        return 0;
    };
    // SAFETY: c is a valid C string.
    unsafe { ffi::OBJ_txt2nid(c.as_ptr()) }
}

/// `OBJ_nid2sn`.
pub fn nid2sn(nid: c_int) -> Option<String> {
    // SAFETY: any NID is accepted; the name is static and copied.
    string_at(unsafe { ffi::OBJ_nid2sn(nid) })
}
