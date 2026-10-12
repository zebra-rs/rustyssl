//! INTEGER and ENUMERATED (`ASN1_INTEGER_get_int64(3)`, `ASN1_INTEGER_set(3)`,
//! `ASN1_INTEGER_cmp`, `i2a_ASN1_INTEGER`, `a2i_ASN1_INTEGER(3)`, `d2i_ASN1_UINTEGER`).
//!
//! Both are `ASN1_STRING`s holding a value's magnitude, big-endian, with `V_ASN1_NEG` in the
//! type for a negative one. The magnitude is used as stored: leading zero octets count toward
//! the 8 a 64-bit value allows, as in OpenSSL. The `BIGNUM` conversions are in `bn::conv`.

use core::ffi::{c_char, c_int, c_long};
use core::ptr;

use rustyssl_abi::{
    ASN1_ENUMERATED, ASN1_INTEGER, ASN1_R_BAD_OBJECT_HEADER, ASN1_R_EXPECTING_AN_INTEGER,
    ASN1_R_ILLEGAL_NEGATIVE_VALUE, ASN1_R_ODD_NUMBER_OF_CHARS, ASN1_R_SHORT_LINE, ASN1_R_TOO_LARGE,
    ASN1_R_TOO_SMALL, ASN1_R_WRONG_INTEGER_TYPE, ASN1_STRING, BIO, ERR_LIB_ASN1,
    ERR_R_PASSED_NULL_PARAMETER, V_ASN1_ENUMERATED, V_ASN1_INTEGER, V_ASN1_NEG,
};

use super::string;
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;

/// The magnitude a string holds: its `length` octets, or none (with NULL data, `None`).
///
/// # Safety
/// `a` is a live string whose data holds its length.
unsafe fn magnitude<'a>(a: &ASN1_STRING) -> Option<&'a [u8]> {
    if a.data.is_null() {
        return None;
    }
    let length = usize::try_from(a.length).unwrap_or(0);
    // SAFETY: the caller's guarantee.
    Some(unsafe { core::slice::from_raw_parts(a.data, length) })
}

/// `asn1_get_uint64`: a magnitude of at most 8 octets as a number.
fn get_u64(magnitude: Option<&[u8]>, length: c_int) -> Result<u64, Option<c_int>> {
    if usize::try_from(length).is_ok_and(|l| l > 8) {
        return Err(Some(ASN1_R_TOO_LARGE));
    }
    let bytes = magnitude.ok_or(None)?;
    Ok(bytes.iter().fold(0u64, |r, &b| (r << 8) | u64::from(b)))
}

/// `asn1_string_get_int64` (signed) and `asn1_string_get_uint64` (unsigned): the value, or
/// the reason raised (none for NULL data).
///
/// # Safety
/// `a` is NULL or a live string whose data holds its length.
unsafe fn get(
    a: *const ASN1_STRING,
    kind: c_int,
    unsigned: bool,
) -> Result<(u64, bool), Option<c_int>> {
    if a.is_null() {
        return Err(Some(ERR_R_PASSED_NULL_PARAMETER));
    }
    // SAFETY: the caller's guarantee.
    let a = unsafe { &*a };
    if a.type_ & !V_ASN1_NEG != kind {
        return Err(Some(ASN1_R_WRONG_INTEGER_TYPE));
    }
    // The unsigned getter refuses a negative value before looking at its size.
    if unsigned && a.type_ & V_ASN1_NEG != 0 {
        return Err(Some(ASN1_R_ILLEGAL_NEGATIVE_VALUE));
    }
    // SAFETY: as above.
    let value = get_u64(unsafe { magnitude(a) }, a.length)?;
    Ok((value, a.type_ & V_ASN1_NEG != 0))
}

/// The signed value of [`get`]'s result, as `asn1_get_int64` limits it.
fn signed((value, negative): (u64, bool)) -> Result<i64, Option<c_int>> {
    if negative {
        if let Ok(v) = i64::try_from(value) {
            Ok(-v)
        } else if value == i64::MIN.unsigned_abs() {
            Ok(i64::MIN)
        } else {
            Err(Some(ASN1_R_TOO_SMALL))
        }
    } else {
        i64::try_from(value).map_err(|_| Some(ASN1_R_TOO_LARGE))
    }
}

/// Raises `reason` (if any) as `function`.
fn fail(reason: Option<c_int>, function: &str) -> c_int {
    if let Some(reason) = reason {
        err::raise(ERR_LIB_ASN1, reason, function);
    }
    0
}

/// `asn1_string_set_int64`/`asn1_string_set_uint64`: the type, then the magnitude's shortest
/// big-endian octets (one zero octet for 0).
///
/// # Safety
/// `a` is a live string.
unsafe fn set(a: *mut ASN1_STRING, magnitude: u64, negative: bool, kind: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let string = unsafe { &mut *a };
    string.type_ = if negative {
        kind | V_ASN1_NEG
    } else {
        kind & !V_ASN1_NEG
    };
    let bytes = magnitude.to_be_bytes();
    let first = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let octets = bytes.get(first..).unwrap_or(&[0]);
    let length = c_int::try_from(octets.len()).unwrap_or(0);
    // SAFETY: a live string; the octets are local.
    unsafe { string::set(a, octets.as_ptr().cast(), length) }
}

/// Writes `value` through `out`, or fails for NULL `out`.
///
/// # Safety
/// `out` is NULL or valid for a write.
unsafe fn store<T>(out: *mut T, value: T, function: &str) -> c_int {
    if out.is_null() {
        err::raise(ERR_LIB_ASN1, ERR_R_PASSED_NULL_PARAMETER, function);
        return 0;
    }
    // SAFETY: the caller's guarantee.
    unsafe { out.write(value) };
    1
}

ffi_export! {
    /// A copy of `x` (`ASN1_STRING_dup`).
    ///
    /// # Safety
    /// `x` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_INTEGER_dup(x: *const ASN1_INTEGER) -> *mut ASN1_INTEGER
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { string::ASN1_STRING_dup(x) }
    }
}

ffi_export! {
    /// Compares two integers: a negative one is less than a non-negative one; otherwise as
    /// `ASN1_STRING_cmp`, reversed for negatives.
    ///
    /// Unlike OpenSSL, a NULL integer sorts first rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `x` and `y` are NULL or live strings.
    pub unsafe extern "C" fn ASN1_INTEGER_cmp(x: *const ASN1_INTEGER, y: *const ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        match (x.is_null(), y.is_null()) {
            (true, true) => return 0,
            (true, false) => return -1,
            (false, true) => return 1,
            (false, false) => {}
        }
        // SAFETY: the caller's guarantee.
        let negative = unsafe { (*x).type_ } & V_ASN1_NEG;
        // SAFETY: as above.
        if negative != unsafe { (*y).type_ } & V_ASN1_NEG {
            return if negative != 0 { -1 } else { 1 };
        }
        // SAFETY: as above.
        let order = unsafe { string::compare(x, y) };
        if negative != 0 { order.wrapping_neg() } else { order }
    }
}

ffi_export! {
    /// The value of INTEGER `a` into `*pr`. Returns 1, or 0 with an error: a NULL `a`, another
    /// type (`ASN1_R_WRONG_INTEGER_TYPE`), more than 8 octets, or a value outside `int64_t`.
    ///
    /// # Safety
    /// `pr` is NULL or valid for a write; `a` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_INTEGER_get_int64(pr: *mut i64, a: *const ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        match unsafe { get(a, V_ASN1_INTEGER, false) }.and_then(signed) {
            // SAFETY: as above.
            Ok(value) => unsafe { store(pr, value, "ASN1_INTEGER_get_int64") },
            Err(reason) => fail(reason, "ASN1_INTEGER_get_int64"),
        }
    }
}

ffi_export! {
    /// The value of a non-negative INTEGER `a` into `*pr` (`ASN1_R_ILLEGAL_NEGATIVE_VALUE`
    /// for a negative one).
    ///
    /// # Safety
    /// As for `ASN1_INTEGER_get_int64`.
    pub unsafe extern "C" fn ASN1_INTEGER_get_uint64(pr: *mut u64, a: *const ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let result = unsafe { get(a, V_ASN1_INTEGER, true) }.map(|(value, _)| value);
        match result {
            // SAFETY: as above.
            Ok(value) => unsafe { store(pr, value, "ASN1_INTEGER_get_uint64") },
            Err(reason) => fail(reason, "ASN1_INTEGER_get_uint64"),
        }
    }
}

/// `ASN1_INTEGER_get` and `ASN1_ENUMERATED_get` once their checks pass: -1 for any failure.
///
/// # Safety
/// `a` is a live string.
unsafe fn get_long(a: *const ASN1_STRING, kind: c_int, function: &str) -> c_long {
    // SAFETY: the caller's guarantee.
    match unsafe { get(a, kind, false) }.and_then(signed) {
        Ok(value) => value,
        Err(reason) => {
            fail(reason, function);
            -1
        }
    }
}

ffi_export! {
    /// The value of INTEGER `a`: 0 for NULL, -1 on failure (as `ASN1_INTEGER_get_int64`).
    ///
    /// # Safety
    /// `a` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_INTEGER_get(a: *const ASN1_INTEGER) -> c_long
    where failure = -1, library = ERR_LIB_ASN1
    {
        if a.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { get_long(a, V_ASN1_INTEGER, "ASN1_INTEGER_get_int64") }
    }
}

ffi_export! {
    /// Makes `a` an INTEGER with value `r`. Returns 1, or 0 on failure.
    ///
    /// Unlike OpenSSL, NULL `a` returns 0 rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `a` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_INTEGER_set_int64(a: *mut ASN1_INTEGER, r: i64) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if a.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { set(a, r.unsigned_abs(), r < 0, V_ASN1_INTEGER) }
    }
}

ffi_export! {
    /// Makes `a` a non-negative INTEGER with value `r`.
    ///
    /// # Safety
    /// As for `ASN1_INTEGER_set_int64`.
    pub unsafe extern "C" fn ASN1_INTEGER_set_uint64(a: *mut ASN1_INTEGER, r: u64) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if a.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { set(a, r, false, V_ASN1_INTEGER) }
    }
}

ffi_export! {
    /// `ASN1_INTEGER_set_int64` with a `long`.
    ///
    /// # Safety
    /// As for `ASN1_INTEGER_set_int64`.
    pub unsafe extern "C" fn ASN1_INTEGER_set(a: *mut ASN1_INTEGER, v: c_long) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_INTEGER_set_int64(a, v) }
    }
}

ffi_export! {
    /// The value of ENUMERATED `a` into `*pr`, as `ASN1_INTEGER_get_int64`.
    ///
    /// # Safety
    /// As for `ASN1_INTEGER_get_int64`.
    pub unsafe extern "C" fn ASN1_ENUMERATED_get_int64(pr: *mut i64, a: *const ASN1_ENUMERATED) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        match unsafe { get(a, V_ASN1_ENUMERATED, false) }.and_then(signed) {
            // SAFETY: as above.
            Ok(value) => unsafe { store(pr, value, "ASN1_ENUMERATED_get_int64") },
            Err(reason) => fail(reason, "ASN1_ENUMERATED_get_int64"),
        }
    }
}

ffi_export! {
    /// Makes `a` an ENUMERATED with value `r`.
    ///
    /// # Safety
    /// As for `ASN1_INTEGER_set_int64`.
    pub unsafe extern "C" fn ASN1_ENUMERATED_set_int64(a: *mut ASN1_ENUMERATED, r: i64) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if a.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { set(a, r.unsigned_abs(), r < 0, V_ASN1_ENUMERATED) }
    }
}

ffi_export! {
    /// `ASN1_ENUMERATED_set_int64` with a `long`.
    ///
    /// # Safety
    /// As for `ASN1_INTEGER_set_int64`.
    pub unsafe extern "C" fn ASN1_ENUMERATED_set(a: *mut ASN1_ENUMERATED, v: c_long) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_ENUMERATED_set_int64(a, v) }
    }
}

ffi_export! {
    /// The value of ENUMERATED `a`: 0 for NULL, -1 for another type or on failure, and
    /// `0xffffffff` (as OpenSSL) for more than 8 octets.
    ///
    /// # Safety
    /// `a` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_ENUMERATED_get(a: *const ASN1_ENUMERATED) -> c_long
    where failure = -1, library = ERR_LIB_ASN1
    {
        if a.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let string = unsafe { &*a };
        if string.type_ & !V_ASN1_NEG != V_ASN1_ENUMERATED {
            return -1;
        }
        if usize::try_from(string.length).is_ok_and(|l| l > size_of::<c_long>()) {
            return 0xffff_ffff;
        }
        // SAFETY: as above.
        unsafe { get_long(a, V_ASN1_ENUMERATED, "ASN1_ENUMERATED_get_int64") }
    }
}

/// Uppercase hex digits, as OpenSSL's `ossl_to_hex`.
const HEX: &[u8; 16] = b"0123456789ABCDEF";

ffi_export! {
    /// Writes INTEGER `a` to `bp` as hex (`-` first for a negative one, `00` for no octets), a
    /// backslash and newline after every 35 octets. Returns the characters written, 0 for NULL
    /// `a`, or -1 if a write fails.
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `a` is NULL or a live string.
    pub unsafe extern "C" fn i2a_ASN1_INTEGER(bp: *mut BIO, a: *const ASN1_INTEGER) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        if a.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let string = unsafe { &*a };
        let write = |text: &[u8]| -> bool {
            let length = c_int::try_from(text.len()).unwrap_or(0);
            // SAFETY: the caller's guarantee about `bp`; `text` holds `length` octets.
            unsafe { crate::bio::BIO_write(bp, text.as_ptr().cast(), length) == length }
        };
        let mut written: c_int = 0;
        if string.type_ & V_ASN1_NEG != 0 {
            if !write(b"-") {
                return -1;
            }
            written = 1;
        }
        // SAFETY: the caller's guarantee.
        let octets = unsafe { magnitude(string) }.unwrap_or(&[]);
        if string.length == 0 {
            if !write(b"00") {
                return -1;
            }
            return written + 2;
        }
        for (i, &octet) in octets.iter().enumerate() {
            if i != 0 && i % 35 == 0 {
                if !write(b"\\\n") {
                    return -1;
                }
                written = written.wrapping_add(2);
            }
            let digit = |n: u8| HEX.get(usize::from(n)).copied().unwrap_or(b'0');
            let pair = [digit(octet >> 4), digit(octet & 0xf)];
            if !write(&pair) {
                return -1;
            }
            written = written.wrapping_add(2);
        }
        written
    }
}

ffi_export! {
    /// `i2a_ASN1_INTEGER` for an ENUMERATED.
    ///
    /// # Safety
    /// As for `i2a_ASN1_INTEGER`.
    pub unsafe extern "C" fn i2a_ASN1_ENUMERATED(bp: *mut BIO, a: *const ASN1_ENUMERATED) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { i2a_ASN1_INTEGER(bp, a) }
    }
}

/// `a2i_ASN1_INTEGER`: reads lines of `size` octets into `buf` (writing NULs into it, as
/// OpenSSL does) and returns the octets, or 0 with an error.
///
/// # Safety
/// `bp` is NULL or a live BIO; `buf` is valid for `size` octets.
unsafe fn read_hex(bp: *mut BIO, buf: *mut c_char, size: c_int) -> Result<Vec<u8>, c_int> {
    let line_at = |i: usize| -> *mut u8 { buf.cast::<u8>().wrapping_add(i) };
    // SAFETY: the caller's guarantee.
    let read_line = || unsafe { crate::bio::BIO_gets(bp, buf, size) };
    let mut octets: Vec<u8> = Vec::new();
    let mut first = true;
    let mut got = read_line();
    loop {
        let Ok(mut i) = usize::try_from(got) else {
            return Err(ASN1_R_SHORT_LINE);
        };
        if i < 1 {
            return Err(ASN1_R_SHORT_LINE);
        }
        // SAFETY: `BIO_gets` wrote `i` characters into `buf`.
        let at = |k: usize| unsafe { line_at(k).read() };
        // SAFETY: as above; writes stay within them.
        let clear = |k: usize| unsafe { line_at(k).write(0) };
        if at(i - 1) == b'\n' {
            i -= 1;
            clear(i);
        }
        if i == 0 {
            return Err(ASN1_R_SHORT_LINE);
        }
        if at(i - 1) == b'\r' {
            i -= 1;
            clear(i);
        }
        if i == 0 {
            return Err(ASN1_R_SHORT_LINE);
        }
        let again = at(i - 1) == b'\\';
        if let Some(end) = (0..i).find(|&j| !at(j).is_ascii_hexdigit()) {
            i = end;
        }
        clear(i);
        if i < 2 {
            return Err(ASN1_R_SHORT_LINE);
        }
        let mut start = 0;
        if first {
            first = false;
            if at(0) == b'0' && at(1) == b'0' {
                start = 2;
                i -= 2;
            }
        }
        // As in OpenSSL, the character before a trailing backslash is dropped too.
        // (`00\` leaves -1 characters, which C finds odd.)
        let Some(count) = i.checked_sub(usize::from(again)) else {
            return Err(ASN1_R_ODD_NUMBER_OF_CHARS);
        };
        if count % 2 != 0 {
            return Err(ASN1_R_ODD_NUMBER_OF_CHARS);
        }
        for pair in 0..count / 2 {
            let digit = |k: usize| {
                let c = at(start + 2 * pair + k);
                (c as char)
                    .to_digit(16)
                    .and_then(|d| u8::try_from(d).ok())
                    .unwrap_or(0)
            };
            octets.push((digit(0) << 4) | digit(1));
        }
        if !again {
            return Ok(octets);
        }
        got = read_line();
    }
}

/// `a2i_ASN1_INTEGER` and `a2i_ASN1_ENUMERATED`.
///
/// # Safety
/// As for `a2i_ASN1_INTEGER`.
unsafe fn a2i(
    bp: *mut BIO,
    bs: *mut ASN1_STRING,
    buf: *mut c_char,
    size: c_int,
    function: &str,
) -> c_int {
    if bs.is_null() || buf.is_null() {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    unsafe { (*bs).type_ = V_ASN1_INTEGER };
    // SAFETY: as above.
    match unsafe { read_hex(bp, buf, size) } {
        Ok(octets) => {
            let data: *mut u8 = if octets.is_empty() {
                ptr::null_mut()
            } else {
                mem::alloc(octets.len()).cast()
            };
            if !octets.is_empty() && data.is_null() {
                return 0;
            }
            if !data.is_null() {
                // SAFETY: room for the octets.
                unsafe { ptr::copy_nonoverlapping(octets.as_ptr(), data, octets.len()) };
            }
            // SAFETY: the caller's string. As in OpenSSL, its earlier data isn't freed.
            let string = unsafe { &mut *bs };
            string.length = c_int::try_from(octets.len()).unwrap_or(0);
            string.data = data;
            1
        }
        Err(reason) => {
            err::raise(ERR_LIB_ASN1, reason, function);
            0
        }
    }
}

ffi_export! {
    /// Reads hex (as `i2a_ASN1_INTEGER` writes it, a leading `00` dropped) from `bp`, a line
    /// of at most `size` characters at a time into `buf`, into INTEGER `bs`. Returns 1, or 0
    /// with an error (`ASN1_R_SHORT_LINE`, `ASN1_R_ODD_NUMBER_OF_CHARS`).
    ///
    /// Unlike OpenSSL, NULL `bs` or `buf` returns 0 rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `bs` is NULL or a live string; `buf` is NULL or valid for
    /// `size` octets.
    pub unsafe extern "C" fn a2i_ASN1_INTEGER(bp: *mut BIO, bs: *mut ASN1_INTEGER, buf: *mut c_char, size: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { a2i(bp, bs, buf, size, "a2i_ASN1_INTEGER") }
    }
}

ffi_export! {
    /// `a2i_ASN1_INTEGER`, keeping the result's type INTEGER as OpenSSL does.
    ///
    /// # Safety
    /// As for `a2i_ASN1_INTEGER`.
    pub unsafe extern "C" fn a2i_ASN1_ENUMERATED(bp: *mut BIO, bs: *mut ASN1_ENUMERATED, buf: *mut c_char, size: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let result = unsafe { a2i(bp, bs, buf, size, "a2i_ASN1_INTEGER") };
        if result == 1 {
            // SAFETY: as above.
            let string = unsafe { &mut *bs };
            string.type_ = V_ASN1_INTEGER | (string.type_ & V_ASN1_NEG);
        }
        result
    }
}

ffi_export! {
    /// Decodes an INTEGER (any class) as unsigned octets, dropping one leading zero octet, into
    /// `*a` or a new INTEGER, moving `*pp` past it.
    ///
    /// Unlike OpenSSL, NULL `pp` or `*pp` returns NULL rather than crashing
    /// (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `*pp` is valid for reads of `length` octets (or of the whole element); `a` is NULL or
    /// points to NULL or a live string.
    pub unsafe extern "C" fn d2i_ASN1_UINTEGER(a: *mut *mut ASN1_INTEGER, pp: *mut *const u8, length: c_long) -> *mut ASN1_INTEGER
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let start = if pp.is_null() { ptr::null() } else { unsafe { *pp } };
        if start.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        let existing = if a.is_null() { ptr::null_mut() } else { unsafe { *a } };
        let target = if existing.is_null() {
            string::type_new(V_ASN1_INTEGER)
        } else {
            existing
        };
        if target.is_null() {
            return ptr::null_mut();
        }
        let failed = |reason: Option<c_int>| {
            if let Some(reason) = reason {
                err::raise(ERR_LIB_ASN1, reason, "d2i_ASN1_UINTEGER");
            }
            if target != existing {
                // SAFETY: the new string.
                unsafe { string::ASN1_STRING_free(target) };
            }
            ptr::null_mut()
        };
        let header = if length <= 0 {
            err::raise(ERR_LIB_ASN1, ASN1_R_TOO_SMALL, "ASN1_get_object");
            None
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { super::read_header(start, length) }.ok().filter(|h| !h.overrun)
        };
        let Some(header) = header else {
            return failed(Some(ASN1_R_BAD_OBJECT_HEADER));
        };
        if header.tag != V_ASN1_INTEGER {
            return failed(Some(ASN1_R_EXPECTING_AN_INTEGER));
        }
        let Ok(mut len) = usize::try_from(header.length) else {
            return failed(Some(ASN1_R_ILLEGAL_NEGATIVE_VALUE));
        };
        if c_int::try_from(len).is_err() {
            return failed(None);
        }
        let mut p = start.wrapping_add(header.header_len);
        let data: *mut u8 = mem::alloc(len + 1).cast();
        if data.is_null() {
            return failed(None);
        }
        // SAFETY: the caller's guarantee; the content holds `len` octets.
        unsafe { (*target).type_ = V_ASN1_INTEGER };
        if len != 0 {
            // SAFETY: as above.
            if unsafe { p.read() } == 0 && len != 1 {
                p = p.wrapping_add(1);
                len -= 1;
            }
            // SAFETY: as above; `data` has room.
            unsafe { ptr::copy_nonoverlapping(p, data, len) };
            p = p.wrapping_add(len);
        }
        // SAFETY: the string and the data just made.
        unsafe { string::ASN1_STRING_set0(target, data.cast(), c_int::try_from(len).unwrap_or(0)) };
        if !a.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { *a = target };
        }
        // SAFETY: as above.
        unsafe { *pp = p };
        target
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_arguments_are_safe() {
        // SAFETY: NULL integers sort first.
        assert_eq!(unsafe { ASN1_INTEGER_cmp(ptr::null(), ptr::null()) }, 0);
        // SAFETY: NULL integers are refused.
        assert_eq!(unsafe { ASN1_INTEGER_set_int64(ptr::null_mut(), 5) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { ASN1_INTEGER_set_uint64(ptr::null_mut(), 5) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { ASN1_ENUMERATED_set_int64(ptr::null_mut(), 5) }, 0);
        let a = string::type_new(V_ASN1_INTEGER);
        // SAFETY: a live integer.
        assert_eq!(unsafe { ASN1_INTEGER_set_int64(a, 5) }, 1);
        // SAFETY: a NULL output fails rather than being written.
        assert_eq!(unsafe { ASN1_INTEGER_get_int64(ptr::null_mut(), a) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { ASN1_INTEGER_get_uint64(ptr::null_mut(), a) }, 0);
        // SAFETY: NULL string and buffer are refused.
        let refused =
            unsafe { a2i_ASN1_INTEGER(ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), 5) };
        assert_eq!(refused, 0);
        // SAFETY: as above.
        let no_buffer = unsafe { a2i_ASN1_INTEGER(ptr::null_mut(), a, ptr::null_mut(), 5) };
        assert_eq!(no_buffer, 0);
        // SAFETY: as above.
        assert!(unsafe { d2i_ASN1_UINTEGER(ptr::null_mut(), ptr::null_mut(), 5) }.is_null());
        // SAFETY: made above.
        unsafe { string::ASN1_STRING_free(a) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }
}
