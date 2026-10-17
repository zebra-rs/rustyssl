//! `UI_OpenSSL`'s console functions (`ui_openssl.c`, its POSIX `termios` build): the session
//! opens `/dev/tty` for reading and writing (standard input and standard error without one),
//! prompts are written there, and input is read a line at a time (at most 1,023 octets, the
//! rest of a longer line discarded) with echo turned off unless the prompt asks for it, every
//! catchable signal but `SIGUSR1` and `SIGUSR2` recorded meanwhile (an interrupt fails the
//! read with -1), and the line cleansed once copied into the result.
//!
//! The state is OpenSSL's: one terminal for the process, kept from the session's opening to
//! its closing (behind a lock taken only briefly, never across another function).

use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Mutex, PoisonError};

use rustyssl_abi::{
    ERR_LIB_UI, UI, UI_INPUT_FLAG_ECHO, UI_R_UNKNOWN_TTYGET_ERRNO_VALUE, UI_STRING, UIT_BOOLEAN,
    UIT_ERROR, UIT_INFO, UIT_PROMPT, UIT_VERIFY,
};

use super::ui_lib::{
    UI_get_input_flags, UI_get_string_type, UI_get0_action_string, UI_get0_output_string,
    UI_get0_result_string, UI_get0_test_string, UI_set_result,
};
use crate::err;

/// The most signals saved (`NX509_SIG`).
const NSIG: usize = 32;
/// The line's room (`BUFSIZ` in OpenSSL's console, 1,024 octets).
const LINE: usize = 1024;

/// The terminal (`tty_in`, `tty_out`, `is_a_tty`, `tty_orig`, `savsig`).
struct Console {
    tty_in: *mut libc::FILE,
    tty_out: *mut libc::FILE,
    is_a_tty: bool,
    orig: Option<libc::termios>,
    saved: [Option<libc::sigaction>; NSIG],
}

// SAFETY: the streams are the C library's, which serialises their use; the rest is plain data.
unsafe impl Send for Console {}

static CONSOLE: Mutex<Console> = Mutex::new(Console {
    tty_in: ptr::null_mut(),
    tty_out: ptr::null_mut(),
    is_a_tty: false,
    orig: None,
    saved: [None; NSIG],
});

/// The signal recorded while reading (`intr_signal`).
static INTR: AtomicI32 = AtomicI32::new(0);

fn console() -> std::sync::MutexGuard<'static, Console> {
    CONSOLE.lock().unwrap_or_else(PoisonError::into_inner)
}

unsafe extern "C" {
    #[cfg_attr(target_os = "macos", link_name = "__stdinp")]
    static mut stdin: *mut libc::FILE;
    #[cfg_attr(target_os = "macos", link_name = "__stderrp")]
    static mut stderr: *mut libc::FILE;
}

/// The C library's standard input and standard error.
fn std_streams() -> (*mut libc::FILE, *mut libc::FILE) {
    // SAFETY: the C library's streams, read, never written here.
    let i = unsafe { ptr::addr_of!(stdin).read() };
    // SAFETY: as above.
    let e = unsafe { ptr::addr_of!(stderr).read() };
    (i, e)
}

/// Writes a C string to the terminal.
fn puts(out: *mut libc::FILE, s: *const c_char) {
    if out.is_null() || s.is_null() {
        return;
    }
    // SAFETY: an open stream; a C string.
    unsafe { libc::fputs(s, out) };
}

fn flush(out: *mut libc::FILE) {
    if !out.is_null() {
        // SAFETY: an open stream.
        unsafe { libc::fflush(out) };
    }
}

/// `recsig`: records the signal.
extern "C" fn recsig(i: c_int) {
    INTR.store(i, Ordering::SeqCst);
}

/// Whether `pushsig` leaves the signal alone.
fn skipped(i: c_int) -> bool {
    i == libc::SIGUSR1 || i == libc::SIGUSR2 || i == libc::SIGKILL
}

/// `pushsig`: records every catchable signal (saving their handlers) and restores the default
/// for `SIGWINCH`.
fn pushsig() {
    // SAFETY: an all-zero `sigaction` is an empty one, with no flags or mask.
    let mut sa: libc::sigaction = unsafe { core::mem::zeroed() };
    sa.sa_sigaction = recsig as extern "C" fn(c_int) as libc::sighandler_t;
    let mut c = console();
    for (i, slot) in c.saved.iter_mut().enumerate().skip(1) {
        let Ok(sig) = c_int::try_from(i) else {
            continue;
        };
        if skipped(sig) {
            continue;
        }
        // SAFETY: an all-zero `sigaction`, to be filled.
        let mut old: libc::sigaction = unsafe { core::mem::zeroed() };
        // SAFETY: a signal number; the handler; the old one's room.
        let r = unsafe { libc::sigaction(sig, &raw const sa, &raw mut old) };
        *slot = (r == 0).then_some(old);
    }
    // SAFETY: a signal number; the default handler.
    unsafe { libc::signal(libc::SIGWINCH, libc::SIG_DFL) };
}

/// `popsig`: restores the handlers `pushsig` saved.
fn popsig() {
    let mut c = console();
    for (i, slot) in c.saved.iter_mut().enumerate().skip(1) {
        let Ok(sig) = c_int::try_from(i) else {
            continue;
        };
        if sig == libc::SIGUSR1 || sig == libc::SIGUSR2 {
            continue;
        }
        if let Some(old) = slot.take() {
            // SAFETY: a signal number; the handler saved for it.
            unsafe { libc::sigaction(sig, &raw const old, ptr::null_mut()) };
        }
    }
}

/// Sets the terminal's echo (`echo_console`, `noecho_console`): whether it could.
fn set_echo(on: bool) -> bool {
    let c = console();
    let Some(mut t) = c.orig else {
        return true;
    };
    if !on {
        t.c_lflag &= !libc::ECHO;
    }
    if !c.is_a_tty {
        return true;
    }
    // SAFETY: the open input stream.
    let fd = unsafe { libc::fileno(c.tty_in) };
    // SAFETY: its descriptor; the settings.
    let r = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw const t) };
    r != -1
}

/// `read_till_nl`: discards input up to the next newline: whether it found one.
fn read_till_nl(input: *mut libc::FILE) -> bool {
    let mut buf = [0 as c_char; 5];
    loop {
        // SAFETY: room for 4 octets and a NUL; an open stream.
        if unsafe { libc::fgets(buf.as_mut_ptr(), 4, input) }.is_null() {
            return false;
        }
        if buf
            .iter()
            .take_while(|&&c| c != 0)
            .any(|&c| c.to_ne_bytes() == *b"\n")
        {
            return true;
        }
    }
}

/// `read_string_inner`: reads a line into the string's result, echoing as asked, the
/// newline stripped if `strip_nl`: 1, 0, or -1 if interrupted.
///
/// # Safety
/// `ui` and `uis` are a live UI and one of its strings.
unsafe fn read_inner(ui: *mut UI, uis: *mut UI_STRING, echo: bool, strip_nl: bool) -> c_int {
    let mut result = [0 as c_char; LINE];
    INTR.store(0, Ordering::SeqCst);
    let mut ok = 0;
    pushsig();
    let mut ps = 1;
    let tty_in = console().tty_in;
    'error: {
        if !echo && !set_echo(false) {
            break 'error;
        }
        ps = 2;
        if tty_in.is_null() {
            break 'error;
        }
        let max = c_int::try_from(LINE - 1).unwrap_or(0);
        // SAFETY: room for `max` octets and a NUL; the open input stream.
        let p = unsafe { libc::fgets(result.as_mut_ptr(), max, tty_in) };
        // SAFETY: as above.
        if p.is_null() || unsafe { libc::feof(tty_in) } != 0 || unsafe { libc::ferror(tty_in) } != 0
        {
            break 'error;
        }
        let n = result.iter().position(|&c| c == 0).unwrap_or(LINE - 1);
        match result
            .get(..n)
            .and_then(|r| r.iter().position(|&c| c.to_ne_bytes() == *b"\n"))
        {
            Some(nl) => {
                if strip_nl && let Some(c) = result.get_mut(nl) {
                    *c = 0;
                }
            }
            None => {
                if !read_till_nl(tty_in) {
                    break 'error;
                }
            }
        }
        // SAFETY: the caller's UI and string; the line, NUL-terminated.
        if unsafe { UI_set_result(ui, uis, result.as_ptr()) } >= 0 {
            ok = 1;
        }
    }
    if INTR.load(Ordering::SeqCst) == libc::SIGINT {
        ok = -1;
    }
    if !echo {
        puts(console().tty_out, c"\n".as_ptr());
    }
    if ps >= 2 && !echo && !set_echo(true) {
        ok = 0;
    }
    if ps >= 1 {
        popsig();
    }
    // SAFETY: the line's room.
    unsafe { crate::mem::cleanse(result.as_mut_ptr().cast(), LINE) };
    ok
}

/// `open_console`.
pub(crate) unsafe extern "C" fn open_console(_ui: *mut UI) -> c_int {
    crate::ffi::guard(
        ERR_LIB_UI,
        "open_console",
        || 0,
        || {
            let (std_in, std_err) = std_streams();
            let mut c = console();
            c.is_a_tty = true;
            // SAFETY: C strings.
            let i = unsafe { libc::fopen(c"/dev/tty".as_ptr(), c"r".as_ptr()) };
            c.tty_in = if i.is_null() { std_in } else { i };
            // SAFETY: as above.
            let o = unsafe { libc::fopen(c"/dev/tty".as_ptr(), c"w".as_ptr()) };
            c.tty_out = if o.is_null() { std_err } else { o };
            // SAFETY: an all-zero `termios`, to be filled.
            let mut t: libc::termios = unsafe { core::mem::zeroed() };
            // SAFETY: the open input stream.
            let fd = unsafe { libc::fileno(c.tty_in) };
            // SAFETY: its descriptor; the settings' room.
            if unsafe { libc::tcgetattr(fd, &raw mut t) } == -1 {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if [
                    libc::ENOTTY,
                    libc::EINVAL,
                    libc::ENXIO,
                    libc::EIO,
                    libc::EPERM,
                    libc::ENODEV,
                ]
                .contains(&e)
                {
                    c.is_a_tty = false;
                } else {
                    drop(c);
                    let text = format!("errno={e}");
                    err::raise_with_text(
                        ERR_LIB_UI,
                        UI_R_UNKNOWN_TTYGET_ERRNO_VALUE,
                        "open_console",
                        &text,
                    );
                    return 0;
                }
            }
            c.orig = Some(t);
            1
        },
    )
}

/// `close_console`.
pub(crate) unsafe extern "C" fn close_console(_ui: *mut UI) -> c_int {
    crate::ffi::guard(
        ERR_LIB_UI,
        "close_console",
        || 0,
        || {
            let (std_in, std_err) = std_streams();
            let mut c = console();
            if !c.tty_in.is_null() && c.tty_in != std_in {
                // SAFETY: the stream the session opened.
                unsafe { libc::fclose(c.tty_in) };
            }
            if !c.tty_out.is_null() && c.tty_out != std_err {
                // SAFETY: as above.
                unsafe { libc::fclose(c.tty_out) };
            }
            c.tty_in = ptr::null_mut();
            c.tty_out = ptr::null_mut();
            1
        },
    )
}

/// `write_string`: errors and information to the terminal.
pub(crate) unsafe extern "C" fn write_string(_ui: *mut UI, uis: *mut UI_STRING) -> c_int {
    crate::ffi::guard(
        ERR_LIB_UI,
        "write_string",
        || 0,
        move || {
            // SAFETY: the method's caller's string.
            let t = unsafe { UI_get_string_type(uis) };
            if t == UIT_ERROR || t == UIT_INFO {
                let out = console().tty_out;
                // SAFETY: as above.
                puts(out, unsafe { UI_get0_output_string(uis) });
                flush(out);
            }
            1
        },
    )
}

/// `read_string`: a prompt's, a verification's, or a boolean's input.
pub(crate) unsafe extern "C" fn read_string(ui: *mut UI, uis: *mut UI_STRING) -> c_int {
    crate::ffi::guard(
        ERR_LIB_UI,
        "read_string",
        || 0,
        move || {
            // SAFETY: the method's caller's string, for each.
            let t = unsafe { UI_get_string_type(uis) };
            // SAFETY: as above.
            let echo = unsafe { UI_get_input_flags(uis) } & UI_INPUT_FLAG_ECHO != 0;
            let out = console().tty_out;
            // SAFETY: as above.
            let prompt = unsafe { UI_get0_output_string(uis) };
            match t {
                UIT_BOOLEAN => {
                    puts(out, prompt);
                    // SAFETY: as above.
                    puts(out, unsafe { UI_get0_action_string(uis) });
                    flush(out);
                    // SAFETY: the caller's UI and string.
                    unsafe { read_inner(ui, uis, echo, false) }
                }
                UIT_PROMPT => {
                    puts(out, prompt);
                    flush(out);
                    // SAFETY: as above.
                    unsafe { read_inner(ui, uis, echo, true) }
                }
                UIT_VERIFY => {
                    puts(out, c"Verifying - ".as_ptr());
                    puts(out, prompt);
                    flush(out);
                    // SAFETY: as above.
                    let ok = unsafe { read_inner(ui, uis, echo, true) };
                    if ok <= 0 {
                        return ok;
                    }
                    // SAFETY: as above.
                    let r = unsafe { UI_get0_result_string(uis) };
                    // SAFETY: as above.
                    let tst = unsafe { UI_get0_test_string(uis) };
                    let same = !r.is_null() && !tst.is_null() && {
                        // SAFETY: C strings.
                        let a = unsafe { CStr::from_ptr(r) };
                        // SAFETY: as above.
                        a == unsafe { CStr::from_ptr(tst) }
                    };
                    if !same {
                        puts(out, c"Verify failure\n".as_ptr());
                        flush(out);
                        return 0;
                    }
                    1
                }
                _ => 1,
            }
        },
    )
}
