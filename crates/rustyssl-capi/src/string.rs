//! The string and hex helpers in `crypto.h` (`OPENSSL_strdup(3)`, `OPENSSL_hexstr2buf(3)`,
//! `OPENSSL_strcasecmp(3)`), from OpenSSL's `crypto/o_str.c`.
//!
//! As in OpenSSL:
//! - The copies come from `CRYPTO_malloc`, with the caller's file and line.
//! - The case-insensitive comparisons fold only ASCII letters and return the difference of the
//!   C `char`s, which are signed on x86-64 and macOS and unsigned on Linux on Arm.
//! - `OPENSSL_strtoul` is the C library's `strtoul`, refusing only a leading `-`.
//! - Hex output is uppercase, with `:` between bytes by default.
//!
//! OpenSSL dereferences null strings, buffers, and outputs that its documentation doesn't
//! allow; here they fail (or count as empty) instead of crashing (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;

use rustyssl_abi::{
    CRYPTO_R_HEX_STRING_TOO_SHORT, CRYPTO_R_ILLEGAL_HEX_DIGIT, CRYPTO_R_ODD_NUMBER_OF_DIGITS,
    CRYPTO_R_TOO_MANY_BYTES, CRYPTO_R_TOO_SMALL_BUFFER, ERR_LIB_CRYPTO,
};

use crate::err;
use crate::ffi::ffi_export;
use crate::mem;

/// The separator `OPENSSL_hexstr2buf` and `OPENSSL_buf2hexstr` use.
const DEFAULT_SEPARATOR: c_char = c_char::from_ne_bytes(*b":");

/// The string at `text`, or `None` for null.
///
/// # Safety
/// `text` is null or a NUL-terminated string that outlives `'a`.
unsafe fn c_text<'a>(text: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    (!text.is_null()).then(|| unsafe { CStr::from_ptr(text) }.to_bytes())
}

/// A copy of `bytes` from `CRYPTO_malloc` with a NUL after them, naming `file` and `line`.
fn copy_with_nul(bytes: &[u8], file: *const c_char, line: c_int) -> *mut c_char {
    let Some(size) = bytes.len().checked_add(1) else {
        return ptr::null_mut();
    };
    let block = mem::malloc(size, file, line).cast::<u8>();
    if !block.is_null() {
        // SAFETY: the block holds `size` bytes and is distinct from `bytes`.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), block, bytes.len()) };
        // SAFETY: as above; the last byte.
        unsafe { block.wrapping_add(bytes.len()).write(0) };
    }
    block.cast()
}

ffi_export! {
    /// Returns a copy of `str` from `CRYPTO_malloc`, or null for null.
    ///
    /// # Safety
    /// `str` is null or a NUL-terminated string; `file` is null or a string.
    pub unsafe extern "C" fn CRYPTO_strdup(str: *const c_char, file: *const c_char, line: c_int) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { c_text(str) }.map_or(ptr::null_mut(), |s| copy_with_nul(s, file, line))
    }
}

/// `OPENSSL_strnlen`: the length of the string at `text`, up to `max`.
///
/// # Safety
/// `text` is valid for reads up to its NUL or `max` bytes, whichever is first.
unsafe fn strnlen(text: *const c_char, max: usize) -> usize {
    let mut len = 0;
    // SAFETY: the caller's guarantee; each byte read is before the NUL and within `max`.
    while len < max && unsafe { text.wrapping_add(len).read() } != 0 {
        len += 1;
    }
    len
}

ffi_export! {
    /// Returns a copy of at most `s` bytes of `str`, NUL-terminated, from `CRYPTO_malloc`, or
    /// null for null.
    ///
    /// # Safety
    /// `str` is null or valid for reads up to its NUL or `s` bytes; `file` is null or a
    /// string.
    pub unsafe extern "C" fn CRYPTO_strndup(str: *const c_char, s: usize, file: *const c_char, line: c_int) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        if str.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let len = unsafe { strnlen(str, s) };
        // SAFETY: as above; `len` bytes are readable.
        let bytes = unsafe { core::slice::from_raw_parts(str.cast::<u8>(), len) };
        copy_with_nul(bytes, file, line)
    }
}

ffi_export! {
    /// Returns a copy of `siz` bytes at `data` from `CRYPTO_malloc`; null for null data or
    /// `INT_MAX` bytes or more, without an error.
    ///
    /// # Safety
    /// `data` is null or valid for `siz` bytes of reads; `file` is null or a string.
    pub unsafe extern "C" fn CRYPTO_memdup(data: *const c_void, siz: usize, file: *const c_char, line: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        if data.is_null() || siz >= usize::try_from(c_int::MAX).unwrap_or(usize::MAX) {
            return ptr::null_mut();
        }
        let block = mem::malloc(siz, file, line);
        if !block.is_null() {
            // SAFETY: both hold `siz` bytes, in distinct allocations.
            unsafe { ptr::copy_nonoverlapping(data.cast::<u8>(), block.cast::<u8>(), siz) };
        }
        block
    }
}

ffi_export! {
    /// Returns the length of `str`, counting at most `maxlen` bytes.
    ///
    /// # Safety
    /// `str` is valid for reads up to its NUL or `maxlen` bytes; null counts as empty
    /// (docs/DEVIATIONS.md).
    pub unsafe extern "C" fn OPENSSL_strnlen(str: *const c_char, maxlen: usize) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if str.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { strnlen(str, maxlen) }
    }
}

/// `OPENSSL_strlcpy`: copies what fits of `src` into `size` bytes at `dst`, NUL-terminated if
/// `size` isn't 0, and returns `src`'s length.
///
/// # Safety
/// `dst` is valid for `size` bytes of writes; `src` is a string; they don't overlap.
unsafe fn strlcpy(dst: *mut c_char, src: &[u8], size: usize) -> usize {
    let copied = src.len().min(size.saturating_sub(1));
    // SAFETY: the caller's guarantee; `copied < size`.
    unsafe { ptr::copy_nonoverlapping(src.as_ptr(), dst.cast::<u8>(), copied) };
    if size > 0 {
        // SAFETY: as above.
        unsafe { dst.wrapping_add(copied).write(0) };
    }
    src.len()
}

ffi_export! {
    /// Copies `src` into `size` bytes at `dst`, truncating and always NUL-terminating (unless
    /// `size` is 0). Returns the length of `src`, so a result of `size` or more means it was
    /// truncated.
    ///
    /// # Safety
    /// `dst` is valid for `size` bytes of writes; `src` is a NUL-terminated string. Null ones
    /// count as empty (docs/DEVIATIONS.md).
    pub unsafe extern "C" fn OPENSSL_strlcpy(dst: *mut c_char, src: *const c_char, size: usize) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let src = unsafe { c_text(src) }.unwrap_or_default();
        if dst.is_null() {
            return src.len();
        }
        // SAFETY: as above.
        unsafe { strlcpy(dst, src, size) }
    }
}

ffi_export! {
    /// Appends `src` to the string at `dst` within `size` bytes, truncating and always
    /// NUL-terminating. Returns the length it tried to make (`dst`'s length, at most `size`,
    /// plus `src`'s).
    ///
    /// # Safety
    /// `dst` is valid for `size` bytes, a string or (if no NUL is within `size`) not; `src`
    /// is a NUL-terminated string. Null ones count as empty (docs/DEVIATIONS.md).
    pub unsafe extern "C" fn OPENSSL_strlcat(dst: *mut c_char, src: *const c_char, size: usize) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let src = unsafe { c_text(src) }.unwrap_or_default();
        if dst.is_null() {
            return src.len();
        }
        // SAFETY: as above.
        let used = unsafe { strnlen(dst, size) };
        // SAFETY: as above; the rest of the `size` bytes follow the existing text.
        used + unsafe { strlcpy(dst.wrapping_add(used), src, size - used) }
    }
}

/// OpenSSL's `ossl_tolower` on a C `char`: ASCII letters fold, everything else (including
/// negative `char`s) stays.
fn lower(c: c_char) -> c_int {
    let c = c_int::from(c);
    if (c_int::from(b'A')..=c_int::from(b'Z')).contains(&c) {
        c ^ 0x20
    } else {
        c
    }
}

/// Compares at most `n` characters of two strings, ignoring ASCII case, as OpenSSL does.
///
/// # Safety
/// `a` and `b` are NUL-terminated strings, or valid for `n` bytes.
unsafe fn casecmp(a: *const c_char, b: *const c_char, n: usize) -> c_int {
    for i in 0..n {
        // SAFETY: the caller's guarantee; reading stops at the first NUL or difference.
        let x = unsafe { a.wrapping_add(i).read() };
        // SAFETY: as above.
        let y = unsafe { b.wrapping_add(i).read() };
        let t = lower(x) - lower(y);
        if t != 0 {
            return t;
        }
        if x == 0 {
            return 0;
        }
    }
    0
}

ffi_export! {
    /// Compares two strings, ignoring the case of ASCII letters.
    ///
    /// # Safety
    /// `s1` and `s2` are NUL-terminated strings.
    pub unsafe extern "C" fn OPENSSL_strcasecmp(s1: *const c_char, s2: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { casecmp(s1, s2, usize::MAX) }
    }
}

ffi_export! {
    /// Compares at most `n` characters of two strings, ignoring the case of ASCII letters.
    ///
    /// # Safety
    /// `s1` and `s2` are NUL-terminated strings or valid for `n` bytes.
    pub unsafe extern "C" fn OPENSSL_strncasecmp(s1: *const c_char, s2: *const c_char, n: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { casecmp(s1, s2, n) }
    }
}

ffi_export! {
    /// Converts `str` with `strtoul` into `*num`. Returns 1, or 0 if `strtoul` failed (see
    /// `errno`, which is cleared first), nothing was converted, `str` starts with `-`, or
    /// (without `endptr`) text is left over. `*endptr` is set to `str` first.
    ///
    /// # Safety
    /// `str` is null or a NUL-terminated string; `endptr` and `num` are null or valid for a
    /// write.
    pub unsafe extern "C" fn OPENSSL_strtoul(str: *const c_char, endptr: *mut *mut c_char, base: c_int, num: *mut c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let mut local = ptr::null_mut();
        let end = if endptr.is_null() { &raw mut local } else { endptr };
        crate::errno::set(0);
        // SAFETY: `end` is the caller's endptr or the local.
        unsafe { end.write(str.cast_mut()) };
        if num.is_null() || str.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        if unsafe { str.read() } == c_char::from_ne_bytes(*b"-") {
            return 0;
        }
        // SAFETY: as above; strtoul writes the end position through `end`.
        let value = unsafe { libc::strtoul(str, end, base) };
        // SAFETY: as above.
        unsafe { num.write(value) };
        // SAFETY: as above.
        let end_at = unsafe { end.read() };
        let errno = crate::errno::get();
        // SAFETY: strtoul's end position is inside the string.
        let left_over = endptr.is_null() && unsafe { end_at.read() } != 0;
        c_int::from(errno == 0 && !left_over && end_at.cast_const() != str)
    }
}

/// `OPENSSL_hexchar2int`: a hex digit's value, or -1.
fn hex_value(c: u8) -> c_int {
    match c {
        b'0'..=b'9' => c_int::from(c - b'0'),
        b'a'..=b'f' => c_int::from(c - b'a' + 10),
        b'A'..=b'F' => c_int::from(c - b'A' + 10),
        _ => -1,
    }
}

ffi_export! {
    /// Returns the value of the hex digit `c`, or -1.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OPENSSL_hexchar2int(c: c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        hex_value(c)
    }
}

/// Decodes hex `text` into `out` (or just counts with `None`), skipping `separator` between
/// pairs unless it's NUL (OpenSSL's `hexstr2buf_sep`). The separator is a C `char`, so where
/// `char` is signed one above 0x7f never matches, as in OpenSSL. Returns the byte count, or
/// raises the failure.
#[track_caller]
fn decode_hex(
    text: &[u8],
    mut out: Option<&mut [u8]>,
    separator: c_char,
    function: &str,
) -> Option<usize> {
    let mut bytes = text.iter();
    let mut count = 0;
    while let Some(&high) = bytes.next() {
        if separator != 0 && c_int::from(high) == c_int::from(separator) {
            continue;
        }
        let Some(&low) = bytes.next() else {
            err::raise(ERR_LIB_CRYPTO, CRYPTO_R_ODD_NUMBER_OF_DIGITS, function);
            return None;
        };
        let (l, h) = (hex_value(low), hex_value(high));
        if l < 0 || h < 0 {
            err::raise(ERR_LIB_CRYPTO, CRYPTO_R_ILLEGAL_HEX_DIGIT, function);
            return None;
        }
        count += 1;
        if let Some(out) = out.as_deref_mut() {
            let Some(slot) = out.get_mut(count - 1) else {
                err::raise(ERR_LIB_CRYPTO, CRYPTO_R_TOO_SMALL_BUFFER, function);
                return None;
            };
            *slot = u8::try_from((h << 4) | l).unwrap_or(0);
        }
    }
    Some(count)
}

ffi_export! {
    /// Decodes hex `str` into `buf` (at most `buf_n` bytes; a null `buf` only counts),
    /// skipping `sep` between digit pairs unless it's NUL, and stores the byte count in
    /// `*buflen`. Returns 1, or 0 with an error. A null `str` fails (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `buf` is null or valid for `buf_n` bytes of writes; `buflen` is null or valid for a
    /// write; `str` is null or a NUL-terminated string.
    pub unsafe extern "C" fn OPENSSL_hexstr2buf_ex(buf: *mut c_uchar, buf_n: usize, buflen: *mut usize, str: *const c_char, sep: c_char) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(text) = (unsafe { c_text(str) }) else {
            return 0;
        };
        // SAFETY: as above.
        let out = (!buf.is_null()).then(|| unsafe { core::slice::from_raw_parts_mut(buf, buf_n) });
        let Some(count) = decode_hex(text, out, sep, "OPENSSL_hexstr2buf_ex") else {
            return 0;
        };
        if !buflen.is_null() {
            // SAFETY: as above.
            unsafe { buflen.write(count) };
        }
        1
    }
}

ffi_export! {
    /// Decodes hex `str`, with `:` allowed between digit pairs, into a new buffer from
    /// `OPENSSL_malloc`, storing its length in `*buflen`. Returns null with an error for fewer
    /// than two characters, an odd number of digits, or anything but hex digits.
    ///
    /// # Safety
    /// `str` is a NUL-terminated string (null fails, docs/DEVIATIONS.md); `buflen` is null or
    /// valid for a write.
    pub unsafe extern "C" fn OPENSSL_hexstr2buf(str: *const c_char, buflen: *mut c_long) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(text) = (unsafe { c_text(str) }) else {
            return ptr::null_mut();
        };
        if text.len() <= 1 {
            err::raise(ERR_LIB_CRYPTO, CRYPTO_R_HEX_STRING_TOO_SHORT, "OPENSSL_hexstr2buf");
            return ptr::null_mut();
        }
        let size = text.len() / 2;
        let block = mem::alloc(size).cast::<u8>();
        if block.is_null() {
            return ptr::null_mut();
        }
        if !buflen.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { buflen.write(0) };
        }
        // SAFETY: a fresh block of `size` bytes, only written.
        let out = unsafe { core::slice::from_raw_parts_mut(block, size) };
        let Some(count) = decode_hex(text, Some(out), DEFAULT_SEPARATOR, "OPENSSL_hexstr2buf") else {
            // SAFETY: the block is ours, from CRYPTO_malloc.
            unsafe { mem::release(block.cast()) };
            return ptr::null_mut();
        };
        if !buflen.is_null() {
            // SAFETY: as above.
            unsafe { buflen.write(c_long::try_from(count).unwrap_or(c_long::MAX)) };
        }
        block
    }
}

/// The length `OPENSSL_buf2hexstr_ex` needs for `len` bytes, with the NUL: three characters a
/// byte with a separator (the last separator's place takes the NUL, and an empty buffer still
/// needs 1), else two a byte plus one. `None` past `SIZE_MAX`.
fn hex_length(len: usize, separator: c_char) -> Option<usize> {
    if separator != 0 {
        len.checked_mul(3).map(|n| n.max(1))
    } else {
        len.checked_mul(2)?.checked_add(1)
    }
}

/// Writes `bytes` as uppercase hex into `out`, separated by `separator` unless it's NUL, then a
/// NUL. `out` holds at least [`hex_length`] bytes.
fn encode_hex(bytes: &[u8], separator: c_char, out: &mut [u8]) {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let [separator] = separator.to_ne_bytes();
    let mut text = Vec::with_capacity(out.len());
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 && separator != 0 {
            text.push(separator);
        }
        text.push(DIGITS.get(usize::from(byte >> 4)).copied().unwrap_or(b'0'));
        text.push(
            DIGITS
                .get(usize::from(byte & 0x0f))
                .copied()
                .unwrap_or(b'0'),
        );
    }
    text.push(0);
    for (slot, byte) in out.iter_mut().zip(text) {
        *slot = byte;
    }
}

ffi_export! {
    /// Writes `buflen` bytes from `buf` as uppercase hex into `str` (at most `str_n` bytes),
    /// separated by `sep` unless it's NUL, and stores the length needed, with the NUL, in
    /// `*strlength`. A null `str` only computes the length. Returns 1, or 0 with an error.
    ///
    /// # Safety
    /// `str` is null or valid for `str_n` bytes of writes; `strlength` is null or valid for a
    /// write; `buf` is valid for `buflen` bytes (null fails, docs/DEVIATIONS.md).
    pub unsafe extern "C" fn OPENSSL_buf2hexstr_ex(str: *mut c_char, str_n: usize, strlength: *mut usize, buf: *const c_uchar, buflen: usize, sep: c_char) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(len) = hex_length(buflen, sep) else {
            err::raise(ERR_LIB_CRYPTO, CRYPTO_R_TOO_MANY_BYTES, "OPENSSL_buf2hexstr_ex");
            return 0;
        };
        if !strlength.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { strlength.write(len) };
        }
        if str.is_null() {
            return 1;
        }
        if str_n < len {
            err::raise(ERR_LIB_CRYPTO, CRYPTO_R_TOO_SMALL_BUFFER, "OPENSSL_buf2hexstr_ex");
            return 0;
        }
        if buf.is_null() && buflen > 0 {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let bytes = unsafe { crate::ffi::bytes(buf, buflen) }.unwrap_or_default();
        // SAFETY: as above; only written.
        let out = unsafe { core::slice::from_raw_parts_mut(str.cast::<u8>(), len) };
        encode_hex(bytes, sep, out);
        1
    }
}

ffi_export! {
    /// Returns `buflen` bytes from `buf` as uppercase hex separated by `:`, in a new string from
    /// `OPENSSL_malloc`; "" for none, null with an error for a negative length.
    ///
    /// # Safety
    /// `buf` is valid for `buflen` bytes (null fails, docs/DEVIATIONS.md).
    pub unsafe extern "C" fn OPENSSL_buf2hexstr(buf: *const c_uchar, buflen: c_long) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        if buflen == 0 {
            return mem::alloc_zeroed(1).cast();
        }
        let sized = usize::try_from(buflen)
            .ok()
            .and_then(|n| Some((n, hex_length(n, DEFAULT_SEPARATOR)?)));
        let Some((n, len)) = sized else {
            err::raise(ERR_LIB_CRYPTO, CRYPTO_R_TOO_MANY_BYTES, "OPENSSL_buf2hexstr");
            return ptr::null_mut();
        };
        // SAFETY: the caller's guarantee.
        let Some(bytes) = (unsafe { crate::ffi::bytes(buf, n) }) else {
            return ptr::null_mut();
        };
        let block = mem::alloc(len).cast::<u8>();
        if !block.is_null() {
            // SAFETY: a fresh block of `len` bytes, only written.
            let out = unsafe { core::slice::from_raw_parts_mut(block, len) };
            encode_hex(bytes, DEFAULT_SEPARATOR, out);
        }
        block.cast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let mut out = [0u8; 4];
        assert_eq!(
            decode_hex(b"0a:FF:10", Some(&mut out), DEFAULT_SEPARATOR, "t"),
            Some(3)
        );
        assert_eq!(&out[..3], &[0x0a, 0xff, 0x10]);
        let mut text = [0u8; 9];
        encode_hex(&out[..3], DEFAULT_SEPARATOR, &mut text);
        assert_eq!(&text, b"0A:FF:10\0");
        assert_eq!(hex_length(0, DEFAULT_SEPARATOR), Some(1));
        assert_eq!(hex_length(2, 0), Some(5));
        assert_eq!(hex_length(usize::MAX, 0), None);
    }

    fn compare(a: &CStr, b: &CStr, n: usize) -> c_int {
        // SAFETY: NUL-terminated strings.
        unsafe { casecmp(a.as_ptr(), b.as_ptr(), n) }
    }

    #[test]
    fn case_folding_is_ascii_only() {
        assert_eq!(compare(c"HeLLo", c"hello", usize::MAX), 0);
        assert_eq!(compare(c"a", c"z", usize::MAX), -25);
        assert_eq!(compare(c"abc", c"ABD", 2), 0);
    }

    /// docs/DEVIATIONS.md: null strings and buffers fail or count as empty.
    #[test]
    fn nulls_are_refused() {
        // SAFETY: nulls are the case under test, for each call below.
        assert_eq!(unsafe { OPENSSL_strnlen(ptr::null(), 5) }, 0);
        // SAFETY: as above.
        let copied = unsafe { OPENSSL_strlcpy(ptr::null_mut(), c"abc".as_ptr(), 4) };
        assert_eq!(copied, 3);
        let no_text = ptr::null();
        // SAFETY: as above.
        let decoded =
            unsafe { OPENSSL_hexstr2buf_ex(ptr::null_mut(), 0, ptr::null_mut(), no_text, 0) };
        assert_eq!(decoded, 0);
        // SAFETY: as above.
        assert!(unsafe { OPENSSL_hexstr2buf(ptr::null(), ptr::null_mut()) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { OPENSSL_buf2hexstr(ptr::null(), 3) }.is_null());
    }
}
