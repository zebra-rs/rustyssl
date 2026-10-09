//! BIT STRING bits and named bits (`ASN1_BIT_STRING_set_bit(3)`, `ASN1_BIT_STRING_get_bit`,
//! `ASN1_BIT_STRING_check`, `ASN1_BIT_STRING_num_asc`, `ASN1_BIT_STRING_name_print`).
//!
//! Bit 0 is the most significant bit of the first octet. Setting a bit past the end grows
//! the string with zero octets, and every change drops trailing zero octets and the stored
//! unused-bits count (`ASN1_STRING_FLAG_BITS_LEFT`), which the encoder then computes, as in
//! OpenSSL. Bit-name tables are the application's, ended by an entry whose long name is NULL.

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar};

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_STRING_FLAG_BITS_LEFT, BIO, BIT_STRING_BITNAME, ERR_LIB_ASN1,
};

use super::string;
use crate::bio::print::{Arg, printf};
use crate::ffi::ffi_export;
use crate::mem;

/// Bit `n`'s octet and mask (most significant bit first).
fn position(n: c_int) -> Option<(usize, u8)> {
    let n = usize::try_from(n).ok()?;
    Some((n / 8, 0x80 >> (n % 8)))
}

/// The string's octets: `length` of them, or none for NULL data or a negative length.
///
/// # Safety
/// `a`'s data holds its length.
unsafe fn octets<'a>(a: &ASN1_BIT_STRING) -> &'a [u8] {
    match usize::try_from(a.length) {
        // SAFETY: the caller's guarantee.
        Ok(length) if !a.data.is_null() => unsafe { core::slice::from_raw_parts(a.data, length) },
        _ => &[],
    }
}

ffi_export! {
    /// `ASN1_STRING_set` for a BIT STRING.
    ///
    /// # Safety
    /// As for `ASN1_STRING_set`.
    pub unsafe extern "C" fn ASN1_BIT_STRING_set(x: *mut ASN1_BIT_STRING, d: *mut c_uchar, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { string::ASN1_STRING_set(x, d.cast_const().cast(), len) }
    }
}

ffi_export! {
    /// Sets bit `n` of `a` to `value` (nonzero for 1), growing the string with zero octets if
    /// needed (not to clear a bit past its end), then drops trailing zero octets. Returns 1, or
    /// 0 for a negative `n`, NULL `a`, or on failure.
    ///
    /// Unlike OpenSSL, a negative length is taken as 0 rather than overwriting
    /// `(size_t)length` octets (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `a` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_BIT_STRING_set_bit(a: *mut ASN1_BIT_STRING, n: c_int, value: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        let Some((w, bit)) = position(n) else {
            return 0;
        };
        if a.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let string = unsafe { &mut *a };
        string.flags &= !c_long::from(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
        let length = usize::try_from(string.length).unwrap_or(0);
        if length < w + 1 || string.data.is_null() {
            if value == 0 {
                return 1;
            }
            // SAFETY: the string's data, from this allocator, holds `length` octets.
            let grown: *mut u8 = unsafe { mem::resize_clean(string.data.cast(), length, w + 1) }.cast();
            if grown.is_null() {
                return 0;
            }
            if w + 1 > length {
                // SAFETY: the new octets are within the `w + 1` allocated.
                unsafe { grown.wrapping_add(length).write_bytes(0, w + 1 - length) };
            }
            string.data = grown;
            string.length = c_int::try_from(w + 1).unwrap_or(c_int::MAX);
        }
        // SAFETY: octet `w` is within the string.
        let octet = unsafe { &mut *string.data.wrapping_add(w) };
        *octet = (*octet & !bit) | if value != 0 { bit } else { 0 };
        // SAFETY: the string's octets.
        let trimmed = unsafe { octets(string) }.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        string.length = c_int::try_from(trimmed).unwrap_or(0);
        1
    }
}

ffi_export! {
    /// Bit `n` of `a`: 1 or 0 (0 past its end, for a negative `n`, or NULL `a`).
    ///
    /// # Safety
    /// `a` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_BIT_STRING_get_bit(a: *const ASN1_BIT_STRING, n: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        let Some((w, bit)) = position(n) else {
            return 0;
        };
        if a.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let string = unsafe { &*a };
        // SAFETY: as above.
        let octets = unsafe { octets(string) };
        octets.get(w).map_or(0, |&octet| c_int::from(octet & bit != 0))
    }
}

ffi_export! {
    /// Whether `a` has no bits set outside `flags` (`flags_len` octets; none past them).
    /// 1 for NULL `a` or data.
    ///
    /// Unlike OpenSSL, NULL `flags` is taken as no octets rather than crashing
    /// (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `a` is NULL or a live string; `flags` is NULL or holds `flags_len` octets.
    pub unsafe extern "C" fn ASN1_BIT_STRING_check(a: *const ASN1_BIT_STRING, flags: *const c_uchar, flags_len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if a.is_null() {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let string = unsafe { &*a };
        if string.data.is_null() {
            return 1;
        }
        let allowed: &[u8] = match usize::try_from(flags_len) {
            // SAFETY: the caller's guarantee.
            Ok(len) if !flags.is_null() => unsafe { core::slice::from_raw_parts(flags, len) },
            _ => &[],
        };
        // SAFETY: as above.
        let octets = unsafe { octets(string) };
        let ok = octets.iter().enumerate().all(|(i, &octet)| {
            let mask = allowed.get(i).map_or(0xff, |&f| !f);
            octet & mask == 0
        });
        c_int::from(ok)
    }
}

/// The entries of a bit-name table, up to the one with a NULL long name.
///
/// # Safety
/// `tbl` is NULL or a table ended by an entry with a NULL long name.
unsafe fn entries(tbl: *const BIT_STRING_BITNAME) -> impl Iterator<Item = BIT_STRING_BITNAME> {
    let mut at = tbl;
    core::iter::from_fn(move || {
        if at.is_null() {
            return None;
        }
        // SAFETY: the caller's guarantee: entries up to the terminator are valid.
        let entry = unsafe { at.read() };
        if entry.lname.is_null() {
            return None;
        }
        at = at.wrapping_add(1);
        Some(entry)
    })
}

/// Whether the C string `text` equals `name` (false for NULL).
///
/// # Safety
/// `text` is NULL or a NUL-terminated string.
unsafe fn equals(text: *const c_char, name: &CStr) -> bool {
    // SAFETY: the caller's guarantee.
    !text.is_null() && unsafe { CStr::from_ptr(text) } == name
}

ffi_export! {
    /// The bit number of the entry of `tbl` whose short or long name is `name`, or -1.
    ///
    /// Unlike OpenSSL, NULL `name` or a NULL short name doesn't crash (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `name` is NULL or a NUL-terminated string; `tbl` is NULL or a table ended by an entry
    /// with a NULL long name.
    pub unsafe extern "C" fn ASN1_BIT_STRING_num_asc(name: *const c_char, tbl: *mut BIT_STRING_BITNAME) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        if name.is_null() {
            return -1;
        }
        // SAFETY: the caller's guarantee.
        let name = unsafe { CStr::from_ptr(name) };
        // SAFETY: as above.
        unsafe { entries(tbl) }
            .find(|e| {
                // SAFETY: the entries' names are strings.
                let short = unsafe { equals(e.sname, name) };
                // SAFETY: as above.
                short || unsafe { equals(e.lname, name) }
            })
            .map_or(-1, |e| e.bitnum)
    }
}

ffi_export! {
    /// Sets the bit `name` names in `tbl` to `value` (in `bs`, if not NULL). Returns 1, or 0 for
    /// an unknown name or on failure.
    ///
    /// # Safety
    /// As for `ASN1_BIT_STRING_num_asc`; `bs` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_BIT_STRING_set_asc(bs: *mut ASN1_BIT_STRING, name: *const c_char, value: c_int, tbl: *mut BIT_STRING_BITNAME) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let bit = unsafe { ASN1_BIT_STRING_num_asc(name, tbl) };
        if bit < 0 {
            return 0;
        }
        // SAFETY: as above.
        if !bs.is_null() && unsafe { ASN1_BIT_STRING_set_bit(bs, bit, value) } == 0 {
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Writes `indent` spaces, the long names of the bits of `tbl` set in `bs` (separated by
    /// `, `), and a newline to `out`. Returns 1.
    ///
    /// # Safety
    /// `out` is NULL or a live BIO; `bs` is NULL or a live string; `tbl` is NULL or a table
    /// ended by an entry with a NULL long name.
    pub unsafe extern "C" fn ASN1_BIT_STRING_name_print(out: *mut BIO, bs: *mut ASN1_BIT_STRING, tbl: *mut BIT_STRING_BITNAME, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee about `out`; the arguments match the format.
        unsafe { printf(out, c"%*s", &[Arg::Int(indent), Arg::Pointer(c"".as_ptr().cast())]) };
        let mut first = true;
        // SAFETY: the caller's guarantee.
        for entry in unsafe { entries(tbl) } {
            // SAFETY: as above.
            if unsafe { ASN1_BIT_STRING_get_bit(bs, entry.bitnum) } != 0 {
                if !first {
                    // SAFETY: the caller's guarantee about `out`.
                    unsafe { crate::bio::BIO_puts(out, c", ".as_ptr()) };
                }
                // SAFETY: as above; the long name is a string.
                unsafe { crate::bio::BIO_puts(out, entry.lname) };
                first = false;
            }
        }
        // SAFETY: as above.
        unsafe { crate::bio::BIO_puts(out, c"\n".as_ptr()) };
        1
    }
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;

    #[test]
    fn null_arguments_and_negative_lengths_are_safe() {
        let s = string::type_new(rustyssl_abi::V_ASN1_BIT_STRING);
        // SAFETY: a live string.
        assert_eq!(unsafe { ASN1_BIT_STRING_set_bit(s, 3, 1) }, 1);
        // SAFETY: NULL flags are taken as none.
        assert_eq!(unsafe { ASN1_BIT_STRING_check(s, ptr::null(), 4) }, 0);
        // SAFETY: NULL name is unknown.
        let unknown = unsafe { ASN1_BIT_STRING_num_asc(ptr::null(), ptr::null_mut()) };
        assert_eq!(unknown, -1);
        let table = [
            BIT_STRING_BITNAME {
                bitnum: 2,
                lname: c"two".as_ptr(),
                sname: ptr::null(),
            },
            BIT_STRING_BITNAME {
                bitnum: 0,
                lname: ptr::null(),
                sname: ptr::null(),
            },
        ];
        // SAFETY: a table with a NULL short name, ended properly.
        let found = unsafe { ASN1_BIT_STRING_num_asc(c"two".as_ptr(), table.as_ptr().cast_mut()) };
        assert_eq!(found, 2);
        // SAFETY: a live string, given a negative length.
        unsafe { (*s).length = -4 };
        // SAFETY: as above; the length is taken as 0.
        assert_eq!(unsafe { ASN1_BIT_STRING_set_bit(s, 9, 1) }, 1);
        // SAFETY: as above.
        assert_eq!(unsafe { ASN1_BIT_STRING_get_bit(s, 9) }, 1);
        // SAFETY: made above.
        unsafe { string::ASN1_STRING_free(s) };
    }
}
