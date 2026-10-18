//! CMP's utilities (`cmp_util.c`): logging to a BIO, the error queue through a CMP log
//! callback, adding certificates to a store, and setting octet and UTF-8 strings.
//!
//! The reference build has tracing disabled (`OPENSSL_NO_TRACE`), so `OSSL_CMP_log_open` and
//! `OSSL_CMP_log_close` do nothing, and it is built with `NDEBUG`, so `OSSL_CMP_print_to_bio`
//! prints no location.

use core::ffi::{CStr, c_char, c_int, c_ulong, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_OCTET_STRING, BIO, BIO_NOCLOSE, CMP_R_NULL_ARGUMENT, ERR_LIB_CMP, ERR_SYSTEM_FLAG,
    ERR_TXT_STRING, OSSL_CMP_LOG_ALERT, OSSL_CMP_LOG_CRIT, OSSL_CMP_LOG_DEBUG, OSSL_CMP_LOG_EMERG,
    OSSL_CMP_LOG_ERR, OSSL_CMP_LOG_INFO, OSSL_CMP_LOG_NOTICE, OSSL_CMP_LOG_PREFIX,
    OSSL_CMP_LOG_WARNING, OSSL_CMP_log_cb_t, OSSL_CMP_severity, X509, X509_STORE,
    stack_st_ASN1_UTF8STRING, stack_st_X509,
};

use crate::asn1::string::{
    ASN1_OCTET_STRING_dup, ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set,
    ASN1_STRING_set, ASN1_UTF8STRING_free, ASN1_UTF8STRING_new,
};
use crate::bio::BIO_free;
use crate::bio::file::BIO_new_fp;
use crate::bio::print::{Arg, printf};
use crate::err;
use crate::err::ERR_get_error_all;
use crate::err::strings::{
    ERR_lib_error_string, ERR_reason_error_string, reason_of, system_reason,
};
use crate::ffi::ffi_export;
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value};
use crate::x509::purpose::X509_self_signed;
use crate::x509::store::X509_STORE_add_cert;

unsafe extern "C" {
    #[cfg_attr(target_os = "macos", link_name = "__stderrp")]
    static mut stderr: *mut libc::FILE;
}

/// `UNKNOWN_FUNC`, the default for `OPENSSL_FUNC`.
const UNKNOWN_FUNC: &CStr = c"(unknown function)";

/// `ERR_PRINT_BUF_SIZE`, the room for one error's message.
const ERR_PRINT_BUF_SIZE: usize = 4096;

ffi_export! {
    /// Opens the CMP log: 1. With tracing disabled there is no channel to set up.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_CMP_log_open() -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        1
    }
}

ffi_export! {
    /// Closes the CMP log: nothing to do with tracing disabled.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_CMP_log_close()
    where failure = (), library = ERR_LIB_CMP
    {
    }
}

/// `improve_location_name`: `fallback` when `func` is NULL, empty, or the placeholder for an
/// unknown function (and there is a fallback).
///
/// # Safety
/// `func` and `fallback` are NULL or NUL-terminated strings.
unsafe fn improve_location_name(func: *const c_char, fallback: *const c_char) -> *const c_char {
    if fallback.is_null() {
        return if func.is_null() {
            UNKNOWN_FUNC.as_ptr()
        } else {
            func
        };
    }
    if func.is_null() {
        return fallback;
    }
    // SAFETY: the caller's NUL-terminated string.
    let name = unsafe { CStr::from_ptr(func) };
    if name.is_empty() || name == UNKNOWN_FUNC {
        fallback
    } else {
        func
    }
}

/// The level's name as `OSSL_CMP_print_to_bio` prints it.
fn level_string(level: OSSL_CMP_severity) -> &'static CStr {
    match level {
        OSSL_CMP_LOG_EMERG => c"EMERG",
        OSSL_CMP_LOG_ALERT => c"ALERT",
        OSSL_CMP_LOG_CRIT => c"CRIT",
        OSSL_CMP_LOG_ERR => c"error",
        OSSL_CMP_LOG_WARNING => c"warning",
        OSSL_CMP_LOG_NOTICE => c"NOTE",
        OSSL_CMP_LOG_INFO => c"info",
        OSSL_CMP_LOG_DEBUG => c"DEBUG",
        _ => c"(unknown level)",
    }
}

ffi_export! {
    /// Prints a log message to `bio` as `CMP <level>: <msg>` and a newline: 1, or 0 if writing
    /// failed. The reference is built with `NDEBUG`, so the component, file, and line aren't
    /// printed.
    ///
    /// # Safety
    /// `bio` is NULL or a live BIO; `msg` NULL or a NUL-terminated string.
    pub unsafe extern "C" fn OSSL_CMP_print_to_bio(bio: *mut BIO, component: *const c_char, file: *const c_char, line: c_int, level: OSSL_CMP_severity, msg: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        let _ = (component, file, line);
        let args = [
            Arg::Pointer(OSSL_CMP_LOG_PREFIX.as_ptr().cast()),
            Arg::Pointer(level_string(level).as_ptr().cast()),
            Arg::Pointer(msg.cast()),
        ];
        // SAFETY: the caller's BIO; string arguments for the three conversions.
        c_int::from(unsafe { printf(bio, c"%s%s: %s\n", &args) } >= 0)
    }
}

/// The bytes of a C string (none for NULL).
///
/// # Safety
/// `s` is NULL or a NUL-terminated string.
unsafe fn bytes_of<'a>(s: *const c_char) -> &'a [u8] {
    if s.is_null() {
        return &[];
    }
    // SAFETY: the caller's guarantee.
    unsafe { CStr::from_ptr(s) }.to_bytes()
}

/// The reason text of an error code as `OSSL_CMP_print_errors_cb` gets it: `strerror`'s for a
/// system error, the reason string otherwise, else `reason(<n>)`.
fn reason_text(code: c_ulong) -> Vec<u8> {
    let reason = reason_of(code);
    let text = if code & c_ulong::from(ERR_SYSTEM_FLAG) != 0 {
        system_reason(reason)
    } else {
        // SAFETY: no preconditions.
        let rs = unsafe { ERR_reason_error_string(code) };
        // SAFETY: a static string, or NULL.
        (!rs.is_null()).then(|| unsafe { bytes_of(rs) }.to_vec())
    };
    text.unwrap_or_else(|| format!("reason({reason})").into_bytes())
}

/// The standard error stream.
fn stderr_stream() -> *mut libc::FILE {
    // SAFETY: the C library's stream, read, never written here.
    unsafe { ptr::addr_of!(stderr).read() }
}

ffi_export! {
    /// Takes every error off the thread's queue and reports each through `log_fn` at
    /// `OSSL_CMP_LOG_ERR` (to standard error through [`OSSL_CMP_print_to_bio`] without one),
    /// stopping early if the callback returns 0 or less. The message is the reason, then `:` and
    /// the error's data if it is text, cut to 4095 bytes; the component is the error's function,
    /// else its library's name.
    ///
    /// # Safety
    /// `log_fn` is NULL or a callback taking the strings it is given.
    pub unsafe extern "C" fn OSSL_CMP_print_errors_cb(log_fn: OSSL_CMP_log_cb_t)
    where failure = (), library = ERR_LIB_CMP
    {
        loop {
            let mut file: *const c_char = ptr::null();
            let mut func: *const c_char = ptr::null();
            let mut data: *const c_char = ptr::null();
            let mut line: c_int = 0;
            let mut flags: c_int = 0;
            // SAFETY: rooms for what it reports.
            let code = unsafe { ERR_get_error_all(&raw mut file, &raw mut line, &raw mut func, &raw mut data, &raw mut flags) };
            if code == 0 {
                break;
            }
            // SAFETY: no preconditions.
            let lib = unsafe { ERR_lib_error_string(code) };
            // SAFETY: the error's function name and its library's name, each NULL or a string.
            let component = unsafe { improve_location_name(func, lib) };
            let mut msg = reason_text(code);
            if !data.is_null() && (flags & ERR_TXT_STRING) != 0 {
                msg.push(b':');
                // SAFETY: the error's text, a NUL-terminated string.
                msg.extend_from_slice(unsafe { bytes_of(data) });
            }
            msg.truncate(ERR_PRINT_BUF_SIZE - 1);
            // The message ends at an interior NUL, as in OpenSSL's buffer.
            let end = msg.iter().position(|&b| b == 0).unwrap_or(msg.len());
            msg.truncate(end);
            msg.push(0);
            match log_fn {
                None => {
                    // SAFETY: the standard error stream, not closed by the BIO.
                    let bio = unsafe { BIO_new_fp(stderr_stream(), BIO_NOCLOSE) };
                    if !bio.is_null() {
                        // SAFETY: the BIO made here; NUL-terminated strings.
                        unsafe { OSSL_CMP_print_to_bio(bio, component, file, line, OSSL_CMP_LOG_ERR, msg.as_ptr().cast()) };
                        // SAFETY: as above, freed once.
                        unsafe { BIO_free(bio) };
                    }
                }
                Some(cb) => {
                    // SAFETY: the application's callback with NUL-terminated strings that
                    // outlive the call; no lock is held.
                    if unsafe { cb(component, file, line, OSSL_CMP_LOG_ERR, msg.as_ptr().cast()) } <= 0 {
                        break;
                    }
                }
            }
        }
    }
}

/// `ossl_cmp_X509_STORE_add1_certs`: adds `certs` (only the self-signed ones if
/// `only_self_signed`) to `store`, which takes references: 1, or 0.
///
/// # Safety
/// `store` is NULL or a live store; `certs` NULL or a live list.
pub(crate) unsafe fn X509_STORE_add1_certs(
    store: *mut X509_STORE,
    certs: *mut stack_st_X509,
    only_self_signed: c_int,
) -> c_int {
    if store.is_null() {
        err::raise(
            ERR_LIB_CMP,
            CMP_R_NULL_ARGUMENT,
            "ossl_cmp_X509_STORE_add1_certs",
        );
        return 0;
    }
    if certs.is_null() {
        return 1;
    }
    // SAFETY: the caller's list.
    let n = unsafe { OPENSSL_sk_num(certs.cast()) };
    for i in 0..n {
        // SAFETY: an index in range.
        let cert: *mut X509 = unsafe { OPENSSL_sk_value(certs.cast(), i) }.cast();
        // SAFETY: a certificate of the list.
        if (only_self_signed == 0 || unsafe { X509_self_signed(cert, 0) } == 1)
            // SAFETY: the store; the certificate, which it takes a reference to.
            && unsafe { X509_STORE_add_cert(store, cert) } == 0
        {
            return 0;
        }
    }
    1
}

/// `ossl_cmp_sk_ASN1_UTF8STRING_push_str`: pushes a new UTF8String of `len` bytes of `text`
/// (up to its NUL for a negative `len`) onto `sk`: 1, or 0 (silently for NULLs).
///
/// # Safety
/// `sk` is NULL or a live list; `text` NULL or `len` readable bytes (NUL-terminated if `len`
/// is negative).
pub(crate) unsafe fn sk_ASN1_UTF8STRING_push_str(
    sk: *mut stack_st_ASN1_UTF8STRING,
    text: *const c_char,
    len: c_int,
) -> c_int {
    if sk.is_null() || text.is_null() {
        return 0;
    }
    // SAFETY: no preconditions.
    let utf8string = unsafe { ASN1_UTF8STRING_new() };
    if utf8string.is_null() {
        return 0;
    }
    // SAFETY: the string made here; the caller's text.
    if unsafe { ASN1_STRING_set(utf8string.cast(), text.cast::<c_void>(), len) } != 0
        // SAFETY: the caller's list; the string, which it takes.
        && unsafe { OPENSSL_sk_push(sk.cast(), utf8string.cast_const().cast()) } != 0
    {
        return 1;
    }
    // SAFETY: the string made here, not taken.
    unsafe { ASN1_UTF8STRING_free(utf8string) };
    0
}

/// `ossl_cmp_asn1_octet_string_set1`: replaces `*tgt` with a copy of `src` (NULL for NULL;
/// nothing if they are the same): 1, or 0.
///
/// # Safety
/// `tgt` is NULL or points to NULL or a live string; `src` NULL or a live string.
pub(crate) unsafe fn asn1_octet_string_set1(
    tgt: *mut *mut ASN1_OCTET_STRING,
    src: *const ASN1_OCTET_STRING,
) -> c_int {
    if tgt.is_null() {
        err::raise(
            ERR_LIB_CMP,
            CMP_R_NULL_ARGUMENT,
            "ossl_cmp_asn1_octet_string_set1",
        );
        return 0;
    }
    // SAFETY: the caller's slot.
    let old = unsafe { *tgt };
    if old.cast_const() == src {
        return 1;
    }
    let mut new = ptr::null_mut();
    if !src.is_null() {
        // SAFETY: the caller's string.
        new = unsafe { ASN1_OCTET_STRING_dup(src) };
        if new.is_null() {
            return 0;
        }
    }
    // SAFETY: the slot's string, replaced.
    unsafe { ASN1_OCTET_STRING_free(old) };
    // SAFETY: the caller's slot.
    unsafe { *tgt = new };
    1
}

/// `ossl_cmp_asn1_octet_string_set1_bytes`: replaces `*tgt` with a new string of `len` bytes
/// of `bytes` (NULL for NULL): 1, or 0.
///
/// # Safety
/// `tgt` is NULL or points to NULL or a live string; `bytes` NULL or `len` readable bytes.
pub(crate) unsafe fn asn1_octet_string_set1_bytes(
    tgt: *mut *mut ASN1_OCTET_STRING,
    bytes: *const u8,
    len: c_int,
) -> c_int {
    if tgt.is_null() {
        err::raise(
            ERR_LIB_CMP,
            CMP_R_NULL_ARGUMENT,
            "ossl_cmp_asn1_octet_string_set1_bytes",
        );
        return 0;
    }
    let mut new = ptr::null_mut();
    if !bytes.is_null() {
        // SAFETY: no preconditions.
        new = unsafe { ASN1_OCTET_STRING_new() };
        // SAFETY: the string made here; the caller's bytes.
        if new.is_null() || unsafe { ASN1_OCTET_STRING_set(new, bytes, len) } == 0 {
            // SAFETY: the string made here, or NULL.
            unsafe { ASN1_OCTET_STRING_free(new) };
            return 0;
        }
    }
    // SAFETY: the caller's slot.
    let old = unsafe { *tgt };
    // SAFETY: the slot's string, replaced.
    unsafe { ASN1_OCTET_STRING_free(old) };
    // SAFETY: the caller's slot.
    unsafe { *tgt = new };
    1
}
