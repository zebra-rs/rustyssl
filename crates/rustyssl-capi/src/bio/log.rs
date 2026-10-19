//! The syslog sink (`BIO_s_log`, `bss_log.c`), as OpenSSL builds it on Unix: a new BIO opens
//! the log as `"application"` with `LOG_PID | LOG_CONS` for `LOG_DAEMON`, each write becomes
//! one `syslog` message at the priority its leading word names (`"ERROR "`, `"WARN "`, ...,
//! `LOG_ERR` without one), `BIO_CTRL_SET` reopens it under the given name and facility, and
//! freeing the BIO closes the log. There is no read. Like OpenSSL's, the method's type is
//! `BIO_TYPE_MEM`.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::atomic::Ordering;

use rustyssl_abi::{BIO, BIO_CTRL_SET, BIO_METHOD, BIO_TYPE_MEM, ERR_LIB_BIO};

use super::method::{Builtin, Funcs, bwrite_conv};
use crate::ffi::{bytes, ffi_callback, ffi_export};

/// The leading words that set a message's priority, in OpenSSL's order (the first match
/// wins), and what each is stripped as.
const PRIORITIES: &[(&[u8], c_int)] = &[
    (b"PANIC ", libc::LOG_EMERG),
    (b"EMERG ", libc::LOG_EMERG),
    (b"EMR ", libc::LOG_EMERG),
    (b"ALERT ", libc::LOG_ALERT),
    (b"ALR ", libc::LOG_ALERT),
    (b"CRIT ", libc::LOG_CRIT),
    (b"CRI ", libc::LOG_CRIT),
    (b"ERROR ", libc::LOG_ERR),
    (b"ERR ", libc::LOG_ERR),
    (b"WARNING ", libc::LOG_WARNING),
    (b"WARN ", libc::LOG_WARNING),
    (b"WAR ", libc::LOG_WARNING),
    (b"NOTICE ", libc::LOG_NOTICE),
    (b"NOTE ", libc::LOG_NOTICE),
    (b"NOT ", libc::LOG_NOTICE),
    (b"INFO ", libc::LOG_INFO),
    (b"INF ", libc::LOG_INFO),
    (b"DEBUG ", libc::LOG_DEBUG),
    (b"DBG ", libc::LOG_DEBUG),
];

/// A message's priority and its text without the leading word. OpenSSL compares the words
/// with `strncmp` on the message cut at its first NUL, so a NUL inside a word stops the match.
fn priority(msg: &[u8]) -> (c_int, &[u8]) {
    let text = msg.split(|&c| c == 0).next().unwrap_or_default();
    PRIORITIES
        .iter()
        .find_map(|(word, level)| text.strip_prefix(*word).map(|rest| (*level, rest)))
        .unwrap_or((libc::LOG_ERR, text))
}

/// Opens the log under `name` (which the C library keeps, so it must stay alive).
///
/// # Safety
/// `name` is NULL or a NUL-terminated string that outlives the log's use.
unsafe fn open(name: *const c_char, facility: c_int) {
    // SAFETY: the caller's guarantee.
    unsafe { libc::openlog(name, libc::LOG_PID | libc::LOG_CONS, facility) };
}

fn close() {
    // SAFETY: no preconditions.
    unsafe { libc::closelog() };
}

ffi_callback! {
    /// `slg_new`: initialized, and the log opened as `"application"`.
    ///
    /// # Safety
    /// `b` is NULL or a live BIO.
    pub(crate) unsafe extern "C" fn slg_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        if let Some(object) = unsafe { super::object(b) } {
            object.init.store(1, Ordering::Relaxed);
            object.num.store(0, Ordering::Relaxed);
            object.ptr.store(ptr::null_mut(), Ordering::Relaxed);
        }
        // SAFETY: a static name.
        unsafe { open(c"application".as_ptr(), libc::LOG_DAEMON) };
        1
    }
}

ffi_callback! {
    /// `slg_free`: closes the log. 0 for NULL, else 1.
    ///
    /// # Safety
    /// `b` is NULL or a live BIO.
    pub(crate) unsafe extern "C" fn slg_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        if b.is_null() {
            return 0;
        }
        close();
        1
    }
}

ffi_callback! {
    /// `slg_write`: `len` octets as one message (up to a NUL), at the priority they name. The
    /// length written, or 0 for a negative one.
    ///
    /// # Safety
    /// `data` holds `len` octets.
    pub(crate) unsafe extern "C" fn slg_write(b: *mut BIO, data: *const c_char, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        let _ = b;
        let Ok(n) = usize::try_from(len) else { return 0 };
        // SAFETY: the caller's `len` octets.
        let Some(msg) = (unsafe { bytes(data.cast(), n) }) else { return 0 };
        let (level, text) = priority(msg);
        // `priority` stopped at the first NUL, so there is none inside.
        let Ok(text) = CString::new(text) else { return 0 };
        // SAFETY: a format of one string, and that string.
        unsafe { libc::syslog(level, c"%s".as_ptr(), text.as_ptr()) };
        len
    }
}

ffi_callback! {
    /// `slg_puts`: the string written as a message.
    ///
    /// # Safety
    /// `text` is NULL or a NUL-terminated string.
    pub(crate) unsafe extern "C" fn slg_puts(b: *mut BIO, text: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        if text.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let len = unsafe { CStr::from_ptr(text) }.count_bytes();
        let Ok(len) = c_int::try_from(len) else { return 0 };
        // SAFETY: the string's octets.
        unsafe { slg_write(b, text, len) }
    }
}

ffi_callback! {
    /// `slg_ctrl`: `BIO_CTRL_SET` reopens the log as `ptr` (a name the caller keeps alive)
    /// for the facility `num`. Every control returns 0.
    ///
    /// # Safety
    /// For `BIO_CTRL_SET`, `ptr` is NULL or a NUL-terminated string that outlives the log's use.
    pub(crate) unsafe extern "C" fn slg_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        let _ = b;
        if cmd == BIO_CTRL_SET {
            close();
            // OpenSSL passes the facility through as an int.
            let facility = c_int::try_from(num).unwrap_or(libc::LOG_USER);
            // SAFETY: the caller's guarantee.
            unsafe { open(ptr.cast_const().cast(), facility) };
        }
        0
    }
}

static LOG: Builtin = Builtin::new(BIO_TYPE_MEM, c"syslog", || Funcs {
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(slg_write),
    bputs: Some(slg_puts),
    ctrl: Some(slg_ctrl),
    create: Some(slg_new),
    destroy: Some(slg_free),
    ..Funcs::default()
});

ffi_export! {
    /// Returns the syslog sink's method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_s_log() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        LOG.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_leading_word_sets_the_priority() {
        assert_eq!(
            priority(b"ERROR disk full"),
            (libc::LOG_ERR, &b"disk full"[..])
        );
        assert_eq!(priority(b"WARNING low"), (libc::LOG_WARNING, &b"low"[..]));
        assert_eq!(priority(b"WAR x"), (libc::LOG_WARNING, &b"x"[..]));
        assert_eq!(priority(b"PANIC "), (libc::LOG_EMERG, &b""[..]));
        assert_eq!(priority(b"DBG y"), (libc::LOG_DEBUG, &b"y"[..]));
        // No word, or one without its space: the default, the text as it is.
        assert_eq!(priority(b"hello"), (libc::LOG_ERR, &b"hello"[..]));
        assert_eq!(priority(b"INFO"), (libc::LOG_ERR, &b"INFO"[..]));
        // Up to a NUL, as OpenSSL's string functions see it.
        assert_eq!(priority(b"INFO a\0b"), (libc::LOG_INFO, &b"a"[..]));
        assert_eq!(priority(b"IN\0FO x"), (libc::LOG_ERR, &b"IN"[..]));
        assert_eq!(priority(b""), (libc::LOG_ERR, &b""[..]));
    }
}
