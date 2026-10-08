//! Hex dumps (`BIO_dump(3)`) and `BIO_hex_string`.
//!
//! A dump line is the indentation (at most 64), the offset in at least 4 hex digits, `" - "`,
//! the bytes in hex (a `-` after the 8th), two spaces, the bytes as text (`.` for anything but
//! printable ASCII), and a newline. A line holds 16 bytes, fewer as the indentation grows past
//! 6, so that it stays within 80 columns. Each line goes to the output in one call, whose
//! results are summed. Lines never come near OpenSSL's 289-byte line buffer, whose checks
//! therefore never cut one short.

use core::ffi::{c_int, c_void};
use std::io::Write as _;

use libc::FILE;
use rustyssl_abi::{BIO, ERR_LIB_BIO};

use super::print::{Arg, printf};
use crate::ffi::{bytes, ffi_export};

/// A dump's output function, as `BIO_dump_cb` takes it.
type Callback =
    Option<unsafe extern "C" fn(data: *const c_void, len: usize, u: *mut c_void) -> c_int>;

/// OpenSSL's `BIO_dump_indent_cb`: dumps `len` bytes at `data`, handing each line to `output`.
/// Returns the sum of what it returned, or the first negative value. Null data with bytes to
/// dump returns -1 (OpenSSL's would crash, docs/DEVIATIONS.md).
///
/// # Safety
/// `data` is null or valid for `len` bytes of reads.
unsafe fn dump(
    data: *const c_void,
    len: c_int,
    indent: c_int,
    mut output: impl FnMut(&[u8]) -> c_int,
) -> c_int {
    let indent = indent.clamp(0, 64);
    let width = 16 - (indent - indent.min(6) + 3) / 4;
    let mut rows = len / width;
    if rows * width < len {
        rows += 1;
    }
    if rows <= 0 {
        return 0;
    }
    let Ok(size) = usize::try_from(len) else {
        return 0;
    };
    // SAFETY: the caller's guarantee.
    let Some(data) = (unsafe { bytes(data.cast(), size) }) else {
        return -1;
    };
    let pad = usize::try_from(indent).unwrap_or(0);
    let row_len = usize::try_from(width).unwrap_or(16);
    let mut total: c_int = 0;
    for (row, chunk) in data.chunks(row_len).enumerate() {
        let mut line = Vec::with_capacity(160);
        // Writing to a Vec doesn't fail.
        let _ = write!(line, "{:pad$}{:04x} - ", "", row * row_len);
        for column in 0..row_len {
            let _ = match chunk.get(column) {
                Some(byte) => write!(line, "{byte:02x}{}", if column == 7 { '-' } else { ' ' }),
                None => write!(line, "   "),
            };
        }
        line.extend_from_slice(b"  ");
        line.extend(
            chunk
                .iter()
                .map(|b| if (b' '..=b'~').contains(b) { *b } else { b'.' }),
        );
        line.push(b'\n');
        let ret = output(&line);
        if ret < 0 {
            return ret;
        }
        total = total.wrapping_add(ret);
    }
    total
}

ffi_export! {
    /// Dumps `len` bytes at `s` in hex and as text, a line at a time through `cb` (which gets
    /// `u` too). Returns the sum of `cb`'s results, or the first negative one.
    ///
    /// # Safety
    /// `cb` is null or a function taking these arguments; `s` is null or valid for `len` bytes
    /// of reads.
    pub unsafe extern "C" fn BIO_dump_cb(cb: Callback, u: *mut c_void, s: *const c_void, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { BIO_dump_indent_cb(cb, u, s, len, 0) }
    }
}

ffi_export! {
    /// `BIO_dump_cb`, with each line indented by `indent` spaces (0 to 64). A null `cb` with
    /// lines to output returns -1 (OpenSSL's would crash).
    ///
    /// # Safety
    /// As for `BIO_dump_cb`.
    pub unsafe extern "C" fn BIO_dump_indent_cb(cb: Callback, u: *mut c_void, s: *const c_void, len: c_int, indent: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let output = |line: &[u8]| match cb {
            // SAFETY: the caller's guarantee about `cb`; the line is valid for its length.
            Some(cb) => unsafe { cb(line.as_ptr().cast(), line.len(), u) },
            None => -1,
        };
        // SAFETY: the caller's guarantee about `s`.
        unsafe { dump(s, len, indent, output) }
    }
}

/// Writes a dump line to `bio`, returning what `BIO_write` does.
///
/// # Safety
/// `bio` is null or a live BIO.
unsafe fn write_bio(bio: *mut BIO, line: &[u8]) -> c_int {
    let len = c_int::try_from(line.len()).unwrap_or(c_int::MAX);
    // SAFETY: the caller's guarantee; the line is valid for its length.
    unsafe { super::BIO_write(bio, line.as_ptr().cast(), len) }
}

/// Writes a dump line to `fp` with `fwrite`, returning the number of lines written (1 or 0).
/// A null `fp` returns -1 (OpenSSL's would crash).
///
/// # Safety
/// `fp` is null or an open `FILE`.
unsafe fn write_fp(fp: *mut FILE, line: &[u8]) -> c_int {
    if fp.is_null() {
        return -1;
    }
    // SAFETY: the caller's guarantee; the line is valid for its length.
    let written = unsafe { libc::fwrite(line.as_ptr().cast(), line.len(), 1, fp) };
    c_int::try_from(written).unwrap_or(-1)
}

ffi_export! {
    /// Dumps `len` bytes at `s` to `b`. Returns the sum of `BIO_write`'s results, or the first
    /// negative one.
    ///
    /// # Safety
    /// `b` is null or a live BIO; `s` is null or valid for `len` bytes of reads.
    pub unsafe extern "C" fn BIO_dump(b: *mut BIO, s: *const c_void, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let output = |line: &[u8]| {
            // SAFETY: the caller's guarantee about `b`.
            unsafe { write_bio(b, line) }
        };
        // SAFETY: the caller's guarantee about `s`.
        unsafe { dump(s, len, 0, output) }
    }
}

ffi_export! {
    /// `BIO_dump`, with each line indented by `indent` spaces (0 to 64).
    ///
    /// # Safety
    /// As for `BIO_dump`.
    pub unsafe extern "C" fn BIO_dump_indent(b: *mut BIO, s: *const c_void, len: c_int, indent: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let output = |line: &[u8]| {
            // SAFETY: the caller's guarantee about `b`.
            unsafe { write_bio(b, line) }
        };
        // SAFETY: the caller's guarantee about `s`.
        unsafe { dump(s, len, indent, output) }
    }
}

ffi_export! {
    /// Dumps `len` bytes at `s` to `fp`. Returns the number of lines written, or -1.
    ///
    /// # Safety
    /// `fp` is null or an open `FILE`; `s` is null or valid for `len` bytes of reads.
    pub unsafe extern "C" fn BIO_dump_fp(fp: *mut FILE, s: *const c_void, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let output = |line: &[u8]| {
            // SAFETY: the caller's guarantee about `fp`.
            unsafe { write_fp(fp, line) }
        };
        // SAFETY: the caller's guarantee about `s`.
        unsafe { dump(s, len, 0, output) }
    }
}

ffi_export! {
    /// `BIO_dump_fp`, with each line indented by `indent` spaces (0 to 64).
    ///
    /// # Safety
    /// As for `BIO_dump_fp`.
    pub unsafe extern "C" fn BIO_dump_indent_fp(fp: *mut FILE, s: *const c_void, len: c_int, indent: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let output = |line: &[u8]| {
            // SAFETY: the caller's guarantee about `fp`.
            unsafe { write_fp(fp, line) }
        };
        // SAFETY: the caller's guarantee about `s`.
        unsafe { dump(s, len, indent, output) }
    }
}

ffi_export! {
    /// Writes `datalen` bytes at `data` to `out` as colon-separated uppercase hex, starting a
    /// new line indented by `indent` after every `width` bytes. Each piece is its own
    /// `BIO_printf`, as in OpenSSL. Returns 1, also when nothing is written; null data with
    /// bytes to write returns 0 (OpenSSL's would crash).
    ///
    /// # Safety
    /// `out` is null or a live BIO; `data` is null or valid for `datalen` bytes of reads.
    pub unsafe extern "C" fn BIO_hex_string(out: *mut BIO, indent: c_int, width: c_int, data: *const c_void, datalen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        let Some(len) = usize::try_from(datalen).ok().filter(|l| *l >= 1) else {
            return 1;
        };
        // SAFETY: the caller's guarantee.
        let Some(data) = (unsafe { bytes(data.cast(), len) }) else {
            return 0;
        };
        let Some((last, rest)) = data.split_last() else {
            return 1;
        };
        let indentation = [Arg::Int(indent), Arg::Pointer(c"".as_ptr().cast())];
        let mut column: c_int = 0;
        for (i, byte) in rest.iter().enumerate() {
            // SAFETY: the caller's guarantee about `out`, for each print below; the
            // arguments match the formats.
            unsafe {
                if i != 0 && column == 0 {
                    printf(out, c"%*s", &indentation);
                }
            }
            // SAFETY: as above.
            unsafe { printf(out, c"%02X:", &[Arg::Int(c_int::from(*byte))]) };
            column = column.wrapping_add(1);
            if column >= width {
                column = 0;
                // SAFETY: as above.
                unsafe { printf(out, c"\n", &[]) };
            }
        }
        if !rest.is_empty() && column == 0 {
            // SAFETY: as above.
            unsafe { printf(out, c"%*s", &indentation) };
        }
        // SAFETY: as above.
        unsafe { printf(out, c"%02X", &[Arg::Int(c_int::from(*last))]) };
        1
    }
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;

    /// docs/DEVIATIONS.md: OpenSSL dereferences these null pointers once there is a line.
    #[test]
    fn null_data_callbacks_and_files_fail() {
        let data = c"abc".as_ptr().cast::<c_void>();
        // SAFETY: null arguments are refused before use; the data is valid, for each call.
        let no_callback = unsafe { BIO_dump_indent_cb(None, ptr::null_mut(), data, 3, 0) };
        assert_eq!(no_callback, -1);
        // SAFETY: as above.
        let no_data = unsafe { BIO_dump(ptr::null_mut(), ptr::null(), 3) };
        assert_eq!(no_data, -1);
        // SAFETY: as above.
        let no_file = unsafe { BIO_dump_fp(ptr::null_mut(), data, 3) };
        assert_eq!(no_file, -1);
        // SAFETY: as above.
        let no_hex = unsafe { BIO_hex_string(ptr::null_mut(), 0, 0, ptr::null(), 3) };
        assert_eq!(no_hex, 0);
        // SAFETY: nothing to dump touches nothing.
        let nothing = unsafe { BIO_dump_cb(None, ptr::null_mut(), ptr::null(), 0) };
        assert_eq!(nothing, 0);
    }
}
