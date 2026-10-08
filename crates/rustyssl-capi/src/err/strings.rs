//! Error strings and printing (`ERR_error_string(3)`, `ERR_load_strings(3)`,
//! `ERR_print_errors(3)`).
//!
//! The strings live in one table keyed by packed error code, like OpenSSL's hash: library names
//! under `ERR_PACK(library, 0, 0)`, reasons under `ERR_PACK(library, 0, reason)`, and the common
//! `ERR_R_*` reasons under library 0, where a reason missing from its library is looked up.
//! Loading a string replaces the one with the same code.
//!
//! Nothing is loaded at first. Loading any table loads the library names and common reasons
//! first (`ERR_load_ERR_strings`). libcrypto's tables load in OpenSSL's order when a thread
//! first records an error, or on `OPENSSL_INIT_LOAD_CRYPTO_STRINGS`, unless
//! `OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS` came first; SSL's load on
//! `OPENSSL_INIT_LOAD_SSL_STRINGS`. As in OpenSSL, a table whose first entry is already known
//! isn't loaded, and the encoder and decoder tables are never loaded.
//!
//! An application's strings are kept by pointer, not copied: `ERR_load_strings` requires them to
//! stay valid until `ERR_unload_strings`.

use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_ulong, c_void};
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicI32, Ordering};
use libc::FILE;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, RwLock};

use rustyssl_abi::{
    BIO, BIO_CTRL_INFO, ERR_LIB_CRYPTO, ERR_LIB_SSL, ERR_LIB_USER, ERR_REASON_MASK,
    ERR_RFLAGS_MASK, ERR_RFLAGS_OFFSET, ERR_STRING_DATA, ERR_SYSTEM_MASK, ERR_TXT_STRING,
    OPENSSL_INIT_LOAD_SSL_STRINGS,
};

use super::{Get, Table, c_bytes, get, is_system, library_of, pack};
use crate::ffi::ffi_export;
use crate::generated::err_strings::*;
use crate::init;

/// A string in the table: rustyssl's own, or the application's.
#[derive(Clone, Copy)]
struct Text(*const c_char);

// SAFETY: nothing writes through these pointers: rustyssl's strings are static, and applications
// keep theirs valid and unchanged while they are loaded (ERR_load_strings(3)).
unsafe impl Send for Text {}
// SAFETY: as above.
unsafe impl Sync for Text {}

static STRINGS: LazyLock<RwLock<HashMap<c_ulong, Text>>> = LazyLock::new(Default::default);

/// The string for `code`, which may be null if the application loaded a null one.
fn lookup(code: c_ulong) -> Option<*const c_char> {
    STRINGS.read().ok()?.get(&code).map(|text| text.0)
}

/// Adds strings, replacing those with the same codes.
fn insert(entries: impl IntoIterator<Item = (c_ulong, *const c_char)>) {
    if let Ok(mut strings) = STRINGS.write() {
        for (code, text) in entries {
            strings.insert(code, Text(text));
        }
    }
}

/// A table's entries for [`insert`].
fn entries(table: Table) -> impl Iterator<Item = (c_ulong, *const c_char)> {
    table.iter().map(|(code, text)| (*code, text.as_ptr()))
}

/// `ERR_GET_REASON(code)` from `err.h`.
fn reason_of(code: c_ulong) -> c_ulong {
    let mask = if is_system(code) {
        ERR_SYSTEM_MASK
    } else {
        ERR_REASON_MASK.cast_unsigned()
    };
    code & c_ulong::from(mask)
}

/// `ERR_lib_error_string`.
fn library_string(code: c_ulong) -> Option<*const c_char> {
    if !init::base() {
        return None;
    }
    lookup(pack(library_of(code), 0))
}

/// `ERR_reason_error_string`: the library's string for the reason, else the common one. None
/// for system errors, whose strings come from `strerror`.
fn reason_string(code: c_ulong) -> Option<*const c_char> {
    if !init::base() || is_system(code) {
        return None;
    }
    let reason = c_int::try_from(reason_of(code)).unwrap_or(0);
    lookup(pack(library_of(code), reason)).or_else(|| lookup(pack(0, reason)))
}

/// Loads the library names and common reasons (OpenSSL's `ossl_err_load_ERR_strings`). False
/// after `OPENSSL_cleanup`.
fn load_err_strings() -> bool {
    if !init::base() {
        return false;
    }
    insert(entries(LIBRARY_NAMES));
    insert(entries(COMMON_REASONS));
    true
}

/// Loads `table` unless its first entry has a string already (OpenSSL's
/// `ossl_err_load_<library>_strings`).
fn load_table(table: Table) {
    let first = table.first().map_or(0, |(code, _)| *code);
    if reason_string(first).is_none_or(<*const c_char>::is_null) && load_err_strings() {
        insert(entries(table));
    }
}

/// Loads libcrypto's error strings, in OpenSSL's order (`ossl_err_load_crypto_strings`).
pub(crate) fn load_crypto_strings() -> bool {
    if !load_err_strings() {
        return false;
    }
    for table in CRYPTO_TABLES {
        load_table(table);
    }
    true
}

/// Loads libssl's error strings (`ossl_err_load_SSL_strings`).
pub(crate) fn load_ssl_strings() {
    load_table(SSL_REASONS);
}

/// The entries of an application's table, up to the one whose code is 0. `patch` is or-ed into
/// each code, in the table itself, as `ERR_load_strings` does.
///
/// # Safety
/// `table` points to entries ending with one whose code is 0, writable if `patch` isn't 0.
unsafe fn application_entries(
    table: *mut ERR_STRING_DATA,
    patch: c_ulong,
) -> Vec<(c_ulong, *const c_char)> {
    let mut found = Vec::new();
    let mut at = table;
    loop {
        // SAFETY: the caller's guarantee: `at` is an entry up to and including the last.
        let entry = unsafe { at.read() };
        if entry.error == 0 {
            return found;
        }
        let code = entry.error | patch;
        if patch != 0 {
            // SAFETY: as above, and the caller allows writes.
            unsafe { (*at).error = code };
        }
        found.push((code, entry.string));
        // SAFETY: an entry with a nonzero code isn't the last, so the next one is in the table.
        at = unsafe { at.add(1) };
    }
}

ffi_export! {
    /// Adds an application library's strings: `ERR_PACK(lib, 0, 0)` is or-ed into each entry's
    /// code, in the table itself, which runs up to an entry whose code is 0. The strings are
    /// kept by pointer. Returns 1, or 0 after `OPENSSL_cleanup`. A null table adds nothing
    /// (OpenSSL's would crash, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `str` is null or a writable table ending with a 0 code, whose strings stay valid until
    /// `ERR_unload_strings`.
    pub unsafe extern "C" fn ERR_load_strings(lib: c_int, str: *mut ERR_STRING_DATA) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if !load_err_strings() {
            return 0;
        }
        if !str.is_null() {
            // SAFETY: the caller's guarantee.
            insert(unsafe { application_entries(str, pack(lib, 0)) });
        }
        1
    }
}

ffi_export! {
    /// `ERR_load_strings` for a table whose codes are already packed, which it leaves alone.
    ///
    /// # Safety
    /// `str` is null or a table ending with a 0 code, whose strings stay valid until
    /// `ERR_unload_strings`.
    pub unsafe extern "C" fn ERR_load_strings_const(str: *const ERR_STRING_DATA) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if !load_err_strings() {
            return 0;
        }
        if !str.is_null() {
            // SAFETY: the caller's guarantee; with no patch, the table isn't written.
            insert(unsafe { application_entries(str.cast_mut(), 0) });
        }
        1
    }
}

ffi_export! {
    /// Removes the strings for the codes in a table that `ERR_load_strings` packed (or
    /// `ERR_load_strings_const` loaded); `lib` isn't used. Returns 1, or 0 after
    /// `OPENSSL_cleanup`.
    ///
    /// # Safety
    /// `str` is null or a table ending with a 0 code.
    pub unsafe extern "C" fn ERR_unload_strings(lib: c_int, str: *mut ERR_STRING_DATA) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let _ = lib;
        if !init::base() {
            return 0;
        }
        if str.is_null() {
            return 1;
        }
        // SAFETY: the caller's guarantee; with no patch, the table isn't written.
        let codes = unsafe { application_entries(str, 0) };
        if let Ok(mut strings) = STRINGS.write() {
            for (code, _) in codes {
                strings.remove(&code);
            }
        }
        1
    }
}

/// The next library number `ERR_get_next_error_library` hands out.
static NEXT_LIBRARY: AtomicI32 = AtomicI32::new(ERR_LIB_USER);

ffi_export! {
    /// Returns a new library number for an application's errors, counting up from
    /// `ERR_LIB_USER`; 0 after `OPENSSL_cleanup`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ERR_get_next_error_library() -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if !init::base() {
            return 0;
        }
        NEXT_LIBRARY.fetch_add(1, Ordering::Relaxed)
    }
}

ffi_export! {
    /// Returns the name of the error's library, or null if none is loaded.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ERR_lib_error_string(e: c_ulong) -> *const c_char
    where failure = core::ptr::null(), library = ERR_LIB_CRYPTO
    {
        library_string(e).unwrap_or(core::ptr::null())
    }
}

ffi_export! {
    /// Returns the error's reason: its library's string, else the common one, else null. Null
    /// for system errors.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ERR_reason_error_string(e: c_ulong) -> *const c_char
    where failure = core::ptr::null(), library = ERR_LIB_CRYPTO
    {
        reason_string(e).unwrap_or(core::ptr::null())
    }
}

ffi_export! {
    /// Returns null: errors have carried no function codes since OpenSSL 3 (deprecated).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ERR_func_error_string(e: c_ulong) -> *const c_char
    where failure = core::ptr::null(), library = ERR_LIB_CRYPTO
    {
        let _ = e;
        core::ptr::null()
    }
}

/// Writes `pieces` into `out` as `BIO_snprintf` does: as much as fits before a final NUL.
/// Returns the length written, without the NUL; nothing is written to an empty `out`.
fn write_truncated(out: &mut [MaybeUninit<u8>], pieces: &[&[u8]]) -> usize {
    let Some(room) = out.len().checked_sub(1) else {
        return 0;
    };
    let mut bytes = pieces.iter().flat_map(|piece| piece.iter());
    let mut len = 0;
    for (slot, byte) in out.iter_mut().take(room).zip(bytes.by_ref()) {
        slot.write(*byte);
        len += 1;
    }
    if let Some(end) = out.get_mut(len) {
        end.write(0);
    }
    len
}

/// The `strerror` text for a system error, as OpenSSL's `openssl_strerror_r` gets it into a
/// 256-byte buffer. Which C library call that is depends on the platform's feature macros:
/// - glibc defines `_POSIX_C_SOURCE`, so OpenSSL calls the XSI `strerror_r`, and uses no text
///   when it fails, as it does for numbers it doesn't know;
/// - macOS doesn't, so OpenSSL falls back to `strerror`, which describes any number
///   (`Unknown error: 200`). `strerror_r` writes the same text, even when it returns `EINVAL`.
fn system_reason(reason: c_ulong) -> Option<Vec<u8>> {
    let number = c_int::try_from(reason).ok()?;
    let mut buffer = [0 as c_char; 256];
    // SAFETY: the buffer holds 256 bytes, which strerror_r NUL-terminates.
    let failed = unsafe { libc::strerror_r(number, buffer.as_mut_ptr(), buffer.len()) } != 0;
    if failed && !cfg!(target_os = "macos") {
        return None;
    }
    // The last byte stays NUL whatever strerror_r did.
    let bytes: Vec<u8> = buffer
        .iter()
        .take(buffer.len() - 1)
        .take_while(|c| **c != 0)
        .map(|c| c.to_ne_bytes()[0])
        .collect();
    Some(bytes)
}

/// Writes an error's string into `out` (OpenSSL's `ossl_err_string_int`):
/// `error:<code>:<library>:<function>:<reason>`, with numbers for missing strings. If that
/// fills `out`, the short form `err:<code>:<library>:0:<reason>` in hex replaces it. Returns the
/// length written.
fn error_string_into(code: c_ulong, func: &[u8], out: &mut [MaybeUninit<u8>]) -> usize {
    if out.is_empty() {
        return 0;
    }
    let library = library_of(code);
    let reason = reason_of(code);
    let library_text = match library_string(code) {
        // SAFETY: loaded strings stay valid while loaded.
        Some(text) if !text.is_null() => unsafe { CStr::from_ptr(text) }.to_bytes().to_vec(),
        _ => format!("lib({library})").into_bytes(),
    };
    let reason_text = if is_system(code) {
        system_reason(reason)
    } else {
        reason_string(code)
            .filter(|text| !text.is_null())
            // SAFETY: as above.
            .map(|text| unsafe { CStr::from_ptr(text) }.to_bytes().to_vec())
    };
    let flags = c_ulong::from(ERR_RFLAGS_MASK.cast_unsigned()) << ERR_RFLAGS_OFFSET;
    let reason_text =
        reason_text.unwrap_or_else(|| format!("reason({})", reason & !flags).into_bytes());
    let code_text = format!("{code:08X}");
    let written = write_truncated(
        out,
        &[
            b"error:",
            code_text.as_bytes(),
            b":",
            &library_text,
            b":",
            func,
            b":",
            &reason_text,
        ],
    );
    if written == out.len() - 1 {
        let short = format!("err:{code:x}:{library:x}:0:{reason:x}");
        return write_truncated(out, &[short.as_bytes()]);
    }
    written
}

ffi_export! {
    /// Writes the error's string into `buf`, at most `len` bytes with the NUL:
    /// `error:<code>:<library>::<reason>`, or a short numeric form if that doesn't fit. Nothing
    /// is written for length 0, or to a null buffer (OpenSSL's would crash,
    /// docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `buf` is null or valid for `len` bytes of writes.
    pub unsafe extern "C" fn ERR_error_string_n(e: c_ulong, buf: *mut c_char, len: usize)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if buf.is_null() || len == 0 {
            return;
        }
        // SAFETY: the caller's guarantee; the bytes are only written.
        let out = unsafe { core::slice::from_raw_parts_mut(buf.cast::<MaybeUninit<u8>>(), len) };
        error_string_into(e, b"", out);
    }
}

/// `ERR_error_string`'s buffer when the caller passes none: one for the process, as in OpenSSL,
/// so the result is overwritten by the next call from any thread.
struct StaticBuffer(UnsafeCell<[MaybeUninit<u8>; 256]>);

// SAFETY: rustyssl writes the buffer only under STATIC_BUFFER_LOCK; readers are C callers, whom
// ERR_error_string(3) warns that the buffer is shared.
unsafe impl Sync for StaticBuffer {}

static STATIC_BUFFER: StaticBuffer = StaticBuffer(UnsafeCell::new([MaybeUninit::uninit(); 256]));
static STATIC_BUFFER_LOCK: Mutex<()> = Mutex::new(());

ffi_export! {
    /// `ERR_error_string_n` into `buf`, which must hold 256 bytes, or into a static buffer if
    /// `buf` is null. Returns the buffer.
    ///
    /// # Safety
    /// `buf` is null or valid for 256 bytes of writes.
    pub unsafe extern "C" fn ERR_error_string(e: c_ulong, buf: *mut c_char) -> *mut c_char
    where failure = core::ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        if !buf.is_null() {
            // SAFETY: the caller's guarantee.
            let out = unsafe { core::slice::from_raw_parts_mut(buf.cast::<MaybeUninit<u8>>(), 256) };
            error_string_into(e, b"", out);
            return buf;
        }
        let _lock = STATIC_BUFFER_LOCK.lock();
        // SAFETY: the static buffer, written only under the lock.
        let out = unsafe { &mut *STATIC_BUFFER.0.get() };
        error_string_into(e, b"", out);
        STATIC_BUFFER.0.get().cast()
    }
}

/// The size of the buffer each printed error is formatted in (`ERR_PRINT_BUF_SIZE`).
const PRINT_BUFFER: usize = 4096;

/// The calling thread's ID as `ERR_print_errors` prints it: the bytes of its `pthread_t`, in
/// memory order, as uppercase hex.
fn thread_id() -> Vec<u8> {
    // SAFETY: no preconditions.
    let id = unsafe { libc::pthread_self() };
    id.to_ne_bytes()
        .iter()
        .flat_map(|b| format!("{b:02X}").into_bytes())
        .collect()
}

/// Removes the errors one by one, oldest first, and hands each to `emit` as a NUL-terminated
/// line (OpenSSL's `ERR_print_errors_cb`): `<thread>:<error string with the
/// function>:<file>:<line>:<data>\n`, cut to fit 4096 bytes. Stops when `emit` returns false.
fn print_errors(mut emit: impl FnMut(&[u8]) -> bool) {
    let thread = thread_id();
    loop {
        let (code, details) = get(Get::Pop, true);
        if code == 0 {
            return;
        }
        // SAFETY: a popped error's strings stay valid until its slot is reused, which nothing
        // here does.
        let file = unsafe { c_bytes(details.file) };
        // SAFETY: as above.
        let func = unsafe { c_bytes(details.func) };
        // SAFETY: as above.
        let data = unsafe { c_bytes(details.data) };
        let data = if details.flags & ERR_TXT_STRING == 0 {
            &b""[..]
        } else {
            data.unwrap_or_default()
        };
        let mut buffer = [MaybeUninit::<u8>::uninit(); PRINT_BUFFER];
        let mut len = write_truncated(&mut buffer, &[&thread, b":"]);
        len += error_string_into(
            code,
            func.unwrap_or_default(),
            buffer.get_mut(len..).unwrap_or_default(),
        );
        let line = details.line.to_string();
        len += write_truncated(
            buffer.get_mut(len..).unwrap_or_default(),
            &[
                b":",
                file.unwrap_or_default(),
                b":",
                line.as_bytes(),
                b":",
                data,
                b"\n",
            ],
        );
        // SAFETY: the first `len` bytes and the NUL after them were written.
        let text = unsafe { core::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), len + 1) };
        if !emit(text) {
            return;
        }
    }
}

ffi_export! {
    /// Removes the errors one by one, oldest first, passing each to `cb` as a line of text with
    /// its length and `u`, until the queue is empty or `cb` returns 0 or less. A null `cb` does
    /// nothing (OpenSSL's would crash, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `cb` is null or a function that accepts a string, its length, and `u`.
    pub unsafe extern "C" fn ERR_print_errors_cb(
        cb: Option<unsafe extern "C" fn(*const c_char, usize, *mut c_void) -> c_int>,
        u: *mut c_void,
    )
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let Some(cb) = cb else {
            return;
        };
        print_errors(|text| {
            let len = text.len().saturating_sub(1);
            // SAFETY: the caller's guarantee about `cb`; `text` is NUL-terminated after `len`.
            unsafe { cb(text.as_ptr().cast(), len, u) > 0 }
        });
    }
}

ffi_export! {
    /// `ERR_print_errors_cb` writing each line to `fp`, stopping if a write fails. A null `fp`
    /// does nothing (OpenSSL's would crash, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `fp` is null or an open `FILE`.
    pub unsafe extern "C" fn ERR_print_errors_fp(fp: *mut FILE)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if fp.is_null() {
            return;
        }
        print_errors(|text| {
            let len = text.len().saturating_sub(1);
            // SAFETY: the caller's guarantee about `fp`; `text` holds `len` bytes.
            unsafe { libc::fwrite(text.as_ptr().cast(), len, 1, fp) == 1 }
        });
    }
}

ffi_export! {
    /// `ERR_print_errors_cb` writing each line to `bp` with `BIO_write`, stopping when a write
    /// fails (so a null BIO consumes one error, as in OpenSSL).
    ///
    /// # Safety
    /// `bp` is null or a live BIO.
    pub unsafe extern "C" fn ERR_print_errors(bp: *mut BIO)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        print_errors(|text| {
            let len = c_int::try_from(text.len().saturating_sub(1)).unwrap_or(c_int::MAX);
            // SAFETY: the caller's guarantee about `bp`; `text` holds `len` bytes.
            unsafe { crate::bio::BIO_write(bp, text.as_ptr().cast(), len) > 0 }
        });
    }
}

ffi_export! {
    /// Adds the text in memory BIO `bio` to the newest error's data with `ERR_add_error_txt`,
    /// NUL-terminating the BIO's data first. Null and empty BIOs add nothing.
    ///
    /// # Safety
    /// `separator` is null or a NUL-terminated string; `bio` is null or a live memory BIO.
    pub unsafe extern "C" fn ERR_add_error_mem_bio(separator: *const c_char, bio: *mut BIO)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if bio.is_null() {
            return;
        }
        let mut data: *mut c_char = core::ptr::null_mut();
        // SAFETY: the caller's guarantee; BIO_CTRL_INFO stores a `char *`.
        let mut len = unsafe { crate::bio::ctrl(bio, BIO_CTRL_INFO, 0, (&raw mut data).cast()) };
        if len <= 0 || data.is_null() {
            return;
        }
        let last = usize::try_from(len - 1).unwrap_or(0);
        // SAFETY: the memory BIO's data holds `len` bytes.
        if unsafe { data.wrapping_add(last).read() } != 0 {
            // SAFETY: as above.
            if unsafe { crate::bio::BIO_write(bio, c"".as_ptr().cast(), 1) } <= 0 {
                return;
            }
            // SAFETY: as above.
            len = unsafe { crate::bio::ctrl(bio, BIO_CTRL_INFO, 0, (&raw mut data).cast()) };
        }
        if len > 1 && !data.is_null() {
            // SAFETY: the data is NUL-terminated now; `separator` is the caller's.
            unsafe { super::ERR_add_error_txt(separator, data) };
        }
    }
}

/// Defines the deprecated `ERR_load_<library>_strings`, each written with its full signature,
/// as loading its table.
macro_rules! legacy_loaders {
    ($(pub unsafe extern "C" fn $name:ident() -> c_int = $table:ident;)*) => {$(
        ffi_export! {
            /// Loads this library's error strings unless its first one is known, and returns 1
            /// (deprecated: libcrypto loads them itself).
            ///
            /// # Safety
            /// No preconditions.
            pub unsafe extern "C" fn $name() -> c_int
            where failure = 0, library = ERR_LIB_CRYPTO
            {
                load_table($table);
                1
            }
        }
    )*};
}

legacy_loaders! {
    pub unsafe extern "C" fn ERR_load_ASN1_strings() -> c_int = ASN1_REASONS;
    pub unsafe extern "C" fn ERR_load_ASYNC_strings() -> c_int = ASYNC_REASONS;
    pub unsafe extern "C" fn ERR_load_BIO_strings() -> c_int = BIO_REASONS;
    pub unsafe extern "C" fn ERR_load_BN_strings() -> c_int = BN_REASONS;
    pub unsafe extern "C" fn ERR_load_BUF_strings() -> c_int = BUF_REASONS;
    pub unsafe extern "C" fn ERR_load_CMS_strings() -> c_int = CMS_REASONS;
    pub unsafe extern "C" fn ERR_load_COMP_strings() -> c_int = COMP_REASONS;
    pub unsafe extern "C" fn ERR_load_CONF_strings() -> c_int = CONF_REASONS;
    pub unsafe extern "C" fn ERR_load_CRYPTO_strings() -> c_int = CRYPTO_REASONS;
    pub unsafe extern "C" fn ERR_load_CT_strings() -> c_int = CT_REASONS;
    pub unsafe extern "C" fn ERR_load_DH_strings() -> c_int = DH_REASONS;
    pub unsafe extern "C" fn ERR_load_DSA_strings() -> c_int = DSA_REASONS;
    pub unsafe extern "C" fn ERR_load_EC_strings() -> c_int = EC_REASONS;
    pub unsafe extern "C" fn ERR_load_ENGINE_strings() -> c_int = ENGINE_REASONS;
    pub unsafe extern "C" fn ERR_load_EVP_strings() -> c_int = EVP_REASONS;
    pub unsafe extern "C" fn ERR_load_OBJ_strings() -> c_int = OBJ_REASONS;
    pub unsafe extern "C" fn ERR_load_OCSP_strings() -> c_int = OCSP_REASONS;
    pub unsafe extern "C" fn ERR_load_OSSL_STORE_strings() -> c_int = OSSL_STORE_REASONS;
    pub unsafe extern "C" fn ERR_load_PEM_strings() -> c_int = PEM_REASONS;
    pub unsafe extern "C" fn ERR_load_PKCS12_strings() -> c_int = PKCS12_REASONS;
    pub unsafe extern "C" fn ERR_load_PKCS7_strings() -> c_int = PKCS7_REASONS;
    pub unsafe extern "C" fn ERR_load_RAND_strings() -> c_int = RAND_REASONS;
    pub unsafe extern "C" fn ERR_load_RSA_strings() -> c_int = RSA_REASONS;
    pub unsafe extern "C" fn ERR_load_TS_strings() -> c_int = TS_REASONS;
    pub unsafe extern "C" fn ERR_load_UI_strings() -> c_int = UI_REASONS;
    pub unsafe extern "C" fn ERR_load_X509_strings() -> c_int = X509_REASONS;
    pub unsafe extern "C" fn ERR_load_X509V3_strings() -> c_int = X509V3_REASONS;
}

ffi_export! {
    /// Loads the library names and common reasons (deprecated). Returns 1, or 0 after
    /// `OPENSSL_cleanup`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ERR_load_ERR_strings() -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        c_int::from(load_err_strings())
    }
}

ffi_export! {
    /// Does nothing: the strings are freed at `OPENSSL_cleanup` (OpenSSL's is empty too).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn err_free_strings_int()
    where failure = (), library = ERR_LIB_CRYPTO
    {}
}

ffi_export! {
    /// Returns 1: the KDF library has no strings of its own (deprecated).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ERR_load_KDF_strings() -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        1
    }
}

ffi_export! {
    /// libssl's `ERR_load_SSL_strings` (deprecated): `OPENSSL_init_crypto` with
    /// `OPENSSL_INIT_LOAD_SSL_STRINGS`, so it loads them once at most.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn rustyssl_private_ERR_load_SSL_strings() -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        let flags = OPENSSL_INIT_LOAD_SSL_STRINGS.cast_unsigned();
        // SAFETY: no settings.
        unsafe { init::OPENSSL_init_crypto(flags, core::ptr::null()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyssl_abi::{ERR_LIB_BN, ERR_LIB_BUF, ERR_R_PASSED_INVALID_ARGUMENT};

    fn formatted(code: c_ulong, size: usize) -> String {
        let mut out = vec![MaybeUninit::<u8>::uninit(); size];
        let len = error_string_into(code, b"", &mut out);
        // SAFETY: `len` bytes were written.
        let bytes = unsafe { core::slice::from_raw_parts(out.as_ptr().cast::<u8>(), len) };
        String::from_utf8_lossy(bytes).into_owned()
    }

    #[test]
    fn error_strings_fall_back_to_numbers_and_a_short_form() {
        load_crypto_strings();
        let code = pack(ERR_LIB_BUF, ERR_R_PASSED_INVALID_ARGUMENT);
        assert_eq!(
            formatted(code, 256),
            "error:03880106:memory buffer routines::passed invalid argument"
        );
        assert_eq!(
            formatted(pack(100, 5), 256),
            "error:32000005:lib(100)::reason(5)"
        );
        assert_eq!(formatted(code, 20), "err:3880106:7:0:801");
        assert_eq!(formatted(code, 1), "");
        assert_eq!(
            formatted(pack(ERR_LIB_BN, 0x67), 256),
            "error:01800067:bignum routines::div by zero"
        );
    }

    /// docs/DEVIATIONS.md: null tables, buffers, callbacks, and files, where OpenSSL's crash.
    #[test]
    fn null_arguments_do_nothing() {
        // SAFETY: null is the case under test, for each call.
        let loaded = unsafe { ERR_load_strings(ERR_LIB_USER, core::ptr::null_mut()) };
        assert_eq!(loaded, 1);
        // SAFETY: as above.
        assert_eq!(unsafe { ERR_load_strings_const(core::ptr::null()) }, 1);
        // SAFETY: as above.
        assert_eq!(unsafe { ERR_unload_strings(0, core::ptr::null_mut()) }, 1);
        // SAFETY: as above.
        unsafe { ERR_error_string_n(1, core::ptr::null_mut(), 10) };
        super::super::take_all();
        super::super::raise(ERR_LIB_BUF, 1, "test");
        // SAFETY: as above.
        unsafe { ERR_print_errors_cb(None, core::ptr::null_mut()) };
        // SAFETY: as above.
        unsafe { ERR_print_errors_fp(core::ptr::null_mut()) };
        assert_eq!(super::super::take_all().len(), 1, "the error stays queued");
    }

    #[test]
    fn truncation_keeps_room_for_the_nul() {
        let mut out = [MaybeUninit::<u8>::uninit(); 4];
        assert_eq!(write_truncated(&mut out, &[b"ab", b"cd"]), 3);
        assert_eq!(write_truncated(&mut [], &[b"ab"]), 0);
    }
}
