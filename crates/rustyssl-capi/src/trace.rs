//! Tracing (`OSSL_trace_set_channel(3)`, `OSSL_trace_enabled(3)`, `OSSL_trace_get_category_num(3)`,
//! `OSSL_trace_string`).
//!
//! OpenSSL's default build is configured without tracing (`OPENSSL_NO_TRACE` in
//! `configuration.h`), and rustyssl behaves as that build does: the category names still map to
//! numbers and back, and `OSSL_trace_string` still formats, but no category can be given a
//! channel, callback, prefix, or suffix (each setter returns 0 and takes nothing over), none is
//! enabled, and `OSSL_trace_begin` gives no channel. The header's `OSSL_TRACE*` macros compile
//! to nothing in applications built against that configuration.

use core::ffi::{CStr, c_char, c_int, c_void};

use rustyssl_abi::{
    BIO, ERR_LIB_CRYPTO, OSSL_TRACE_CATEGORY_ALL, OSSL_TRACE_CATEGORY_BN_CTX,
    OSSL_TRACE_CATEGORY_CMP, OSSL_TRACE_CATEGORY_CONF, OSSL_TRACE_CATEGORY_DECODER,
    OSSL_TRACE_CATEGORY_ENCODER, OSSL_TRACE_CATEGORY_ENGINE_REF_COUNT,
    OSSL_TRACE_CATEGORY_ENGINE_TABLE, OSSL_TRACE_CATEGORY_HTTP, OSSL_TRACE_CATEGORY_INIT,
    OSSL_TRACE_CATEGORY_PKCS5V2, OSSL_TRACE_CATEGORY_PKCS12_DECRYPT,
    OSSL_TRACE_CATEGORY_PKCS12_KEYGEN, OSSL_TRACE_CATEGORY_PROVIDER, OSSL_TRACE_CATEGORY_QUERY,
    OSSL_TRACE_CATEGORY_REF_COUNT, OSSL_TRACE_CATEGORY_STORE, OSSL_TRACE_CATEGORY_TLS,
    OSSL_TRACE_CATEGORY_TLS_CIPHER, OSSL_TRACE_CATEGORY_TRACE, OSSL_TRACE_CATEGORY_X509V3_POLICY,
    OSSL_TRACE_STRING_MAX, OSSL_trace_cb,
};

use crate::bio::print::{Arg, printf};
use crate::ffi::ffi_export;

/// The part of a `OSSL_TRACE_CATEGORY_<NAME>\0` identifier after the prefix: the name (empty
/// without the NUL, which the tests rule out).
const fn category_name(identifier: &'static str) -> &'static CStr {
    let (_, name) = identifier.as_bytes().split_at("OSSL_TRACE_CATEGORY_".len());
    match CStr::from_bytes_with_nul(name) {
        Ok(name) => name,
        Err(_) => c"",
    }
}

/// Each category's name (its macro's suffix) and number, in number order.
macro_rules! categories {
    ($($constant:ident),* $(,)?) => {
        [$((const { category_name(concat!(stringify!($constant), "\0")) }, $constant)),*]
    };
}

static CATEGORIES: [(&CStr, c_int); 21] = categories![
    OSSL_TRACE_CATEGORY_ALL,
    OSSL_TRACE_CATEGORY_TRACE,
    OSSL_TRACE_CATEGORY_INIT,
    OSSL_TRACE_CATEGORY_TLS,
    OSSL_TRACE_CATEGORY_TLS_CIPHER,
    OSSL_TRACE_CATEGORY_CONF,
    OSSL_TRACE_CATEGORY_ENGINE_TABLE,
    OSSL_TRACE_CATEGORY_ENGINE_REF_COUNT,
    OSSL_TRACE_CATEGORY_PKCS5V2,
    OSSL_TRACE_CATEGORY_PKCS12_KEYGEN,
    OSSL_TRACE_CATEGORY_PKCS12_DECRYPT,
    OSSL_TRACE_CATEGORY_X509V3_POLICY,
    OSSL_TRACE_CATEGORY_BN_CTX,
    OSSL_TRACE_CATEGORY_CMP,
    OSSL_TRACE_CATEGORY_STORE,
    OSSL_TRACE_CATEGORY_DECODER,
    OSSL_TRACE_CATEGORY_ENCODER,
    OSSL_TRACE_CATEGORY_REF_COUNT,
    OSSL_TRACE_CATEGORY_HTTP,
    OSSL_TRACE_CATEGORY_PROVIDER,
    OSSL_TRACE_CATEGORY_QUERY,
];

/// The category numbered `num`.
fn category(num: c_int) -> Option<&'static (&'static CStr, c_int)> {
    CATEGORIES.get(usize::try_from(num).ok()?)
}

ffi_export! {
    /// The name of category `num` (`"TLS"` for `OSSL_TRACE_CATEGORY_TLS`), or NULL if there's
    /// no such category.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_trace_get_category_name(num: c_int) -> *const c_char
    where failure = core::ptr::null(), library = ERR_LIB_CRYPTO
    {
        category(num).map_or(core::ptr::null(), |(name, _)| name.as_ptr())
    }
}

ffi_export! {
    /// The number of the category called `name`, ignoring the case of ASCII letters, or -1 if
    /// `name` is NULL or names no category.
    ///
    /// # Safety
    /// `name` is NULL or a NUL-terminated string.
    pub unsafe extern "C" fn OSSL_trace_get_category_num(name: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        if name.is_null() {
            return -1;
        }
        // SAFETY: the caller's guarantee.
        let name = unsafe { CStr::from_ptr(name) }.to_bytes();
        CATEGORIES
            .iter()
            .find(|(known, _)| known.to_bytes().eq_ignore_ascii_case(name))
            .map_or(-1, |(_, num)| *num)
    }
}

ffi_export! {
    /// Would attach `channel` to `category`; without tracing, returns 0 and leaves `channel`
    /// to the caller.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_trace_set_channel(category: c_int, channel: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let _ = (category, channel);
        0
    }
}

ffi_export! {
    /// Would make `callback` (with `data`) the channel of `category`; without tracing, returns
    /// 0.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_trace_set_callback(category: c_int, callback: OSSL_trace_cb, data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let _ = (category, callback, data);
        0
    }
}

ffi_export! {
    /// Would set the line written before each trace of `category`; without tracing, returns 0.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_trace_set_prefix(category: c_int, prefix: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let _ = (category, prefix);
        0
    }
}

ffi_export! {
    /// Would set the line written after each trace of `category`; without tracing, returns 0.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_trace_set_suffix(category: c_int, suffix: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let _ = (category, suffix);
        0
    }
}

ffi_export! {
    /// Whether `category` is traced: without tracing, never (0).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_trace_enabled(category: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let _ = category;
        0
    }
}

ffi_export! {
    /// Starts a trace of `category`, returning the channel to write it to; without tracing,
    /// there's none (NULL).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_trace_begin(category: c_int) -> *mut BIO
    where failure = core::ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        let _ = category;
        core::ptr::null_mut()
    }
}

ffi_export! {
    /// Ends a trace that `OSSL_trace_begin` started; without tracing, does nothing.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_trace_end(category: c_int, channel: *mut BIO)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let _ = (category, channel);
    }
}

/// Whether `byte` is an ASCII control character, as `ossl_iscntrl`.
fn is_control(byte: u8) -> bool {
    byte < 0x20 || byte == 0x7f
}

/// `data` with every control character but a newline turned into a space, ending in a newline.
fn masked(data: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = data
        .iter()
        .map(|&b| if b != b'\n' && is_control(b) { b' ' } else { b })
        .collect();
    if out.last() != Some(&b'\n') {
        out.push(b'\n');
    }
    out
}

ffi_export! {
    /// Prints `size` bytes of `data` to `out`: at most `OSSL_TRACE_STRING_MAX` of them, after a
    /// `[len N limited to 80]: ` note, unless `full`; and unless `text`, with control characters
    /// but newlines shown as spaces and a newline added if the data doesn't end in one. Returns
    /// what `BIO_printf` returns for the data.
    ///
    /// Unlike OpenSSL, masks any length `full` asks for (OpenSSL overflows its 81-byte buffer),
    /// fails with -1 for null `data` to mask or a length over `INT_MAX` (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `out` is NULL or a live BIO; `data` is valid for `size` bytes, or (as text) NULL.
    pub unsafe extern "C" fn OSSL_trace_string(out: *mut BIO, text: c_int, full: c_int, data: *const u8, size: usize) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        let max = usize::try_from(OSSL_TRACE_STRING_MAX).unwrap_or(0);
        let len = if full == 0 && size > max {
            // SAFETY: the caller's guarantee about `out`; the arguments match the format.
            unsafe {
                printf(
                    out,
                    c"[len %zu limited to %d]: ",
                    &[Arg::Long(u64::try_from(size).unwrap_or(u64::MAX)), Arg::Int(OSSL_TRACE_STRING_MAX)],
                )
            };
            max
        } else {
            size
        };
        let Ok(precision) = c_int::try_from(len) else {
            return -1;
        };
        if text != 0 {
            // SAFETY: the caller's guarantee about `out`; `%.*s` reads at most `len` bytes of
            // `data`, which the caller guarantees (or prints a placeholder for NULL).
            return unsafe { printf(out, c"%.*s", &[Arg::Int(precision), Arg::Pointer(data.cast())]) };
        }
        let shown = if len == 0 {
            masked(&[])
        } else if data.is_null() {
            return -1;
        } else {
            // SAFETY: `data` is valid for `size` bytes, and `len` is at most `size`.
            masked(unsafe { core::slice::from_raw_parts(data, len) })
        };
        let Ok(precision) = c_int::try_from(shown.len()) else {
            return -1;
        };
        // SAFETY: the caller's guarantee about `out`; `shown` holds `precision` bytes.
        unsafe { printf(out, c"%.*s", &[Arg::Int(precision), Arg::Pointer(shown.as_ptr().cast())]) }
    }
}

#[cfg(test)]
mod tests {
    use rustyssl_abi::OSSL_TRACE_CATEGORY_NUM;

    use super::*;

    #[test]
    fn the_categories_are_named_and_numbered_in_order() {
        assert_eq!(
            c_int::try_from(CATEGORIES.len()),
            Ok(OSSL_TRACE_CATEGORY_NUM)
        );
        for (index, (name, num)) in CATEGORIES.iter().enumerate() {
            assert!(!name.is_empty());
            assert_eq!(usize::try_from(*num).ok(), Some(index), "{name:?}");
        }
        assert_eq!(CATEGORIES.get(4).map(|c| c.0), Some(c"TLS_CIPHER"));
    }

    #[test]
    fn masking_shows_control_characters_as_spaces() {
        assert_eq!(masked(b"a\tb\0c\x7f\xff\n"), b"a b c \xff\n");
        assert_eq!(masked(b"no newline"), b"no newline\n");
        assert_eq!(masked(b""), b"\n");
    }

    #[test]
    fn full_masking_past_the_limit_and_bad_arguments_are_safe() {
        let long = [b'x'; 200];
        // SAFETY: no preconditions.
        let method = unsafe { crate::bio::mem::BIO_s_mem() };
        // SAFETY: the built-in memory method.
        let mem = unsafe { crate::bio::BIO_new(method) };
        // SAFETY: a live memory BIO and a 200-byte buffer.
        let written = unsafe { OSSL_trace_string(mem, 0, 1, long.as_ptr(), long.len()) };
        assert_eq!(written, 201);
        // SAFETY: null data to mask is refused before any read.
        let null = unsafe { OSSL_trace_string(mem, 0, 1, core::ptr::null(), 5) };
        // SAFETY: a length over `INT_MAX` is refused before any read.
        let huge = unsafe { OSSL_trace_string(mem, 0, 1, long.as_ptr(), usize::MAX) };
        assert_eq!((null, huge), (-1, -1));
        // SAFETY: the BIO made above.
        unsafe { crate::bio::BIO_free(mem) };
    }
}
