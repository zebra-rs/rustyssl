//! ASN.1 identifier and length octets (`ASN1_get_object(3)`, `ASN1_put_object`,
//! `ASN1_put_eoc`, `ASN1_object_size`, `ASN1_check_infinite_end`), over
//! `rustyssl_asn1::der`, which documents what OpenSSL's reader accepts.
//!
//! `ASN1_get_object`'s `omax` is how much input the caller claims, which some pass generously;
//! the header is read one octet at a time, never past what it needs, rather than through a
//! slice of `omax` octets.

pub(crate) mod any;
pub(crate) mod bit_string;
pub(crate) mod generate;
pub(crate) mod hex;
pub(crate) mod integer;
pub(crate) mod mime;
pub(crate) mod parse;
pub(crate) mod sign;
pub(crate) mod string;
pub(crate) mod text;
pub(crate) mod time;
pub(crate) mod tpl;

use core::ffi::{c_int, c_long, c_uchar};
use core::ptr;

use rustyssl_abi::{
    ASN1_R_HEADER_TOO_LONG, ASN1_R_TOO_LONG, ASN1_R_TOO_SMALL, ERR_LIB_ASN1, V_ASN1_CONSTRUCTED,
};
use rustyssl_asn1::der::{self, Header, HeaderError};

use crate::err;
use crate::ffi::ffi_export;

/// `ASN1_get_object`'s result bit for an error (including a length past `omax`).
pub(crate) const GET_ERROR: c_int = 0x80;

/// Reads the header at `p` from `omax` claimed octets, raising OpenSSL's errors. On success,
/// also whether the length runs past `omax` (`ASN1_R_TOO_LONG`, raised too).
///
/// # Safety
/// `p` is valid for reads of `omax` octets, or of as many as the header needs.
pub(crate) unsafe fn read_header(p: *const c_uchar, omax: c_long) -> Result<Header, HeaderError> {
    // SAFETY: `read_header` asks only for octets below `omax`, within the header, which the
    // caller provides.
    let result = der::read_header(omax, |i| unsafe { p.wrapping_add(i).read() });
    raise_header_errors(&result);
    result
}

/// `ASN1_get_object` on a slice: reads the header at the start of `input`, raising OpenSSL's
/// errors (`ASN1_R_TOO_LONG` too when the length runs past `input`).
pub(crate) fn read_header_in(input: &[u8]) -> Result<Header, HeaderError> {
    let result = der::header(input);
    raise_header_errors(&result);
    result
}

/// Raises the errors `ASN1_get_object` raises for a header read.
fn raise_header_errors(result: &Result<Header, HeaderError>) {
    match result {
        Err(HeaderError::TooSmall) => err::raise(ERR_LIB_ASN1, ASN1_R_TOO_SMALL, "ASN1_get_object"),
        Err(HeaderError::Malformed { .. }) => {
            err::raise(ERR_LIB_ASN1, ASN1_R_HEADER_TOO_LONG, "ASN1_get_object");
        }
        Ok(h) if h.overrun => err::raise(ERR_LIB_ASN1, ASN1_R_TOO_LONG, "ASN1_get_object"),
        Ok(_) => {}
    }
}

/// `ASN1_get_object`'s result for a header read: the constructed bit, the error bit for a
/// length past the input, and 1 for the indefinite length.
pub(crate) fn get_result(h: &Header) -> c_int {
    let mut result = if h.constructed { V_ASN1_CONSTRUCTED } else { 0 };
    if h.overrun {
        result |= GET_ERROR;
    }
    result | c_int::from(h.indefinite)
}

/// Stores `value` through `out` unless it's NULL.
///
/// # Safety
/// `out` is NULL or valid for a write.
unsafe fn store<T>(out: *mut T, value: T) {
    if !out.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { out.write(value) };
    }
}

ffi_export! {
    /// Reads the identifier and length octets at `*pp`, from at most `omax` octets: the tag
    /// number into `*ptag`, the class bits into `*pclass`, the content length into `*plength`
    /// (0 for the indefinite length), and moves `*pp` past them. Returns `V_ASN1_CONSTRUCTED`
    /// if constructed, ORed with 1 for the indefinite length; 0x80 on error (with `*pp` left),
    /// or ORed in when the length runs past `omax` (`*pp` moved anyway).
    ///
    /// Unlike OpenSSL, NULL `pp` or `*pp` returns 0x80 and NULL output pointers are skipped,
    /// rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `*pp` is valid for reads of `omax` octets (or of the whole header); the output pointers
    /// are NULL or valid for writes.
    pub unsafe extern "C" fn ASN1_get_object(pp: *mut *const c_uchar, plength: *mut c_long, ptag: *mut c_int, pclass: *mut c_int, omax: c_long) -> c_int
    where failure = GET_ERROR, library = ERR_LIB_ASN1
    {
        if omax <= 0 {
            err::raise(ERR_LIB_ASN1, ASN1_R_TOO_SMALL, "ASN1_get_object");
            return GET_ERROR;
        }
        // SAFETY: the caller's guarantee.
        let start = if pp.is_null() { ptr::null() } else { unsafe { *pp } };
        if start.is_null() {
            return GET_ERROR;
        }
        // SAFETY: the caller's guarantee about the input.
        match unsafe { read_header(start, omax) } {
            Ok(h) => {
                // SAFETY: the caller's guarantee about the outputs.
                unsafe {
                    store(ptag, h.tag);
                }
                // SAFETY: as above.
                unsafe { store(pclass, c_int::from(h.class)) };
                // SAFETY: as above.
                unsafe { store(plength, h.length) };
                // SAFETY: the header's octets were read, so the pointer stays in the input.
                unsafe { *pp = start.wrapping_add(h.header_len) };
                get_result(&h)
            }
            Err(HeaderError::Malformed { tag_class, length }) => {
                if let Some((tag, class)) = tag_class {
                    // SAFETY: as above.
                    unsafe { store(ptag, tag) };
                    // SAFETY: as above.
                    unsafe { store(pclass, c_int::from(class)) };
                }
                if let Some(length) = length {
                    // SAFETY: as above.
                    unsafe { store(plength, length) };
                }
                GET_ERROR
            }
            Err(HeaderError::TooSmall) => GET_ERROR,
        }
    }
}

ffi_export! {
    /// Writes identifier and length octets at `*pp` and moves it past them: `constructed` 0 or
    /// 1, or 2 for the indefinite length; the class bits of `xclass`. The caller sizes the
    /// buffer with `ASN1_object_size`.
    ///
    /// Unlike OpenSSL, NULL `pp` or `*pp` writes nothing rather than crashing
    /// (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `*pp` is valid for writes of the header (`ASN1_object_size` less `length`).
    pub unsafe extern "C" fn ASN1_put_object(pp: *mut *mut c_uchar, constructed: c_int, length: c_int, tag: c_int, xclass: c_int)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        if pp.is_null() || unsafe { *pp }.is_null() {
            return;
        }
        let mut header = Vec::new();
        der::put_header(&mut header, constructed, length, tag, xclass);
        // SAFETY: the caller's guarantee.
        let out = unsafe { *pp };
        // SAFETY: the caller's buffer has room for the header.
        unsafe { ptr::copy_nonoverlapping(header.as_ptr(), out, header.len()) };
        // SAFETY: just past what was written.
        unsafe { *pp = out.wrapping_add(header.len()) };
    }
}

ffi_export! {
    /// Writes the end-of-contents octets (two zeros) at `*pp` and moves it past them. Returns 2.
    ///
    /// Unlike OpenSSL, NULL `pp` or `*pp` writes nothing and returns 0 rather than crashing
    /// (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `*pp` is valid for writes of 2 octets.
    pub unsafe extern "C" fn ASN1_put_eoc(pp: *mut *mut c_uchar) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        if pp.is_null() || unsafe { *pp }.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let out = unsafe { *pp };
        // SAFETY: room for 2 octets.
        unsafe { out.write_bytes(0, 2) };
        // SAFETY: as above.
        unsafe { *pp = out.wrapping_add(2) };
        2
    }
}

ffi_export! {
    /// The size of an element with `length` content octets: header and content; -1 for a
    /// negative length or a size past `INT_MAX`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_object_size(constructed: c_int, length: c_int, tag: c_int) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        der::object_size(constructed, length, tag)
    }
}

/// `ASN1_check_infinite_end` for both pointer types.
///
/// # Safety
/// `p` is NULL or valid; `*p` is valid for reads of `len` octets (2 at most are read).
unsafe fn infinite_end(p: *mut *const c_uchar, len: c_long) -> c_int {
    if len <= 0 {
        return 1;
    }
    // SAFETY: the caller's guarantee.
    if len < 2 || p.is_null() || unsafe { *p }.is_null() {
        return 0;
    }
    // SAFETY: as above.
    let at = unsafe { *p };
    // SAFETY: `len` is at least 2.
    let (first, second) = (unsafe { at.read() }, unsafe { at.wrapping_add(1).read() });
    if first == 0 && second == 0 {
        // SAFETY: as above.
        unsafe { *p = at.wrapping_add(2) };
        return 1;
    }
    0
}

ffi_export! {
    /// Whether the end of indefinite-length content is at `*p` (then moving past its two zero
    /// octets) or nothing is left (`len` 0 or less).
    ///
    /// # Safety
    /// `*p` is valid for reads of `len` octets.
    pub unsafe extern "C" fn ASN1_check_infinite_end(p: *mut *mut c_uchar, len: c_long) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { infinite_end(p.cast(), len) }
    }
}

ffi_export! {
    /// `ASN1_check_infinite_end` for a pointer to const.
    ///
    /// # Safety
    /// As for `ASN1_check_infinite_end`.
    pub unsafe extern "C" fn ASN1_const_check_infinite_end(p: *mut *const c_uchar, len: c_long) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { infinite_end(p, len) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_arguments_are_safe() {
        let input = [0x04u8, 0x01, 0x00];
        let mut p = input.as_ptr();
        // SAFETY: NULL outputs are skipped; the input holds 3 octets.
        let result = unsafe {
            ASN1_get_object(
                &raw mut p,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                3,
            )
        };
        assert_eq!(result, 0);
        // SAFETY: NULL pointers are refused.
        let null = unsafe {
            ASN1_get_object(
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                3,
            )
        };
        assert_eq!(null, GET_ERROR);
        // SAFETY: as above.
        unsafe { ASN1_put_object(ptr::null_mut(), 0, 1, 4, 0) };
        // SAFETY: as above.
        assert_eq!(unsafe { ASN1_put_eoc(ptr::null_mut()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { ASN1_check_infinite_end(ptr::null_mut(), 5) }, 0);
        // SAFETY: as above.
        let object =
            unsafe { crate::objects::d2i_ASN1_OBJECT(ptr::null_mut(), ptr::null_mut(), 5) };
        assert!(object.is_null());
    }
}
