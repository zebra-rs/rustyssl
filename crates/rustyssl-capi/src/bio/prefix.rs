//! The prefix filter (`BIO_f_prefix(3)`): writes a prefix and an indentation at the start of
//! each line written through it. A port of OpenSSL's `bf_prefix.c`.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::Ordering;
use std::ffi::CString;

use rustyssl_abi::{
    BIO, BIO_C_FILE_SEEK, BIO_CTRL_GET_INDENT, BIO_CTRL_RESET, BIO_CTRL_SET_INDENT,
    BIO_CTRL_SET_PREFIX, BIO_METHOD, BIO_TYPE_BUFFER, BIO_info_cb, ERR_LIB_BIO,
};

use super::method::{Builtin, Funcs};
use super::object;
use super::print::{Arg, printf};
use super::state::{self, lock};
use crate::ffi::{ffi_callback, ffi_export};

/// The state of a prefix filter (OpenSSL's `PREFIX_CTX`).
pub(crate) struct Prefix {
    prefix: Option<CString>,
    indent: u32,
    /// The next byte written starts a line.
    linestart: bool,
}

/// Writes `len` bytes at `data` to `next`, as `BIO_write_ex`. Returns whether it wrote any,
/// and how many.
///
/// # Safety
/// `next` is null or a live BIO; `data` is valid for `len` bytes of reads.
unsafe fn write_ex(next: *mut BIO, data: *const c_char, len: usize) -> (bool, usize) {
    let mut written = 0;
    // SAFETY: the caller's guarantee; `written` is a local.
    let ok = unsafe { super::BIO_write_ex(next, data.cast(), len, &raw mut written) };
    (ok > 0, written)
}

ffi_callback! {
    /// Sets up a prefix filter, with no prefix and no indentation, at the start of a line.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn prefix_create(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        state::install(object, Prefix { prefix: None, indent: 0, linestart: true });
        object.init.store(1, Ordering::Relaxed);
        1
    }
}

ffi_callback! {
    /// Frees a prefix filter's prefix.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn prefix_destroy(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        if let Some(object) = unsafe { object(b) } {
            drop(state::remove::<Prefix>(object));
        }
        1
    }
}

ffi_callback! {
    /// Reads from the next BIO.
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is valid for `size` bytes of writes; `read` is null or valid
    /// for a write.
    pub(crate) unsafe extern "C" fn prefix_read(b: *mut BIO, data: *mut c_char, size: usize, read: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let next = unsafe { object(b) }.map_or(ptr::null_mut(), super::Bio::next);
        // SAFETY: the caller's guarantee; a null next BIO fails with an error.
        unsafe { super::BIO_read_ex(next, data.cast(), size, read) }
    }
}

ffi_callback! {
    /// Writes to the next BIO, with the prefix and the indentation before each line. Returns
    /// 1, with the count of the caller's bytes written in `*written`, or 0 if a write failed.
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is null or valid for `len` bytes of reads; `written` is valid
    /// for a write.
    pub(crate) unsafe extern "C" fn prefix_write(b: *mut BIO, data: *const c_char, len: usize, written: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        let Some(state) = state::get::<Prefix>(object) else {
            return 0;
        };
        let next = object.next();
        // SAFETY: the caller's guarantee.
        let Some(mut input) = (unsafe { crate::ffi::bytes(data.cast(), len) }) else {
            return 0;
        };
        let plain = {
            let s = lock(&state);
            s.prefix.as_ref().is_none_or(|p| p.is_empty()) && s.indent == 0
        };
        if plain {
            // Nothing to add, but whether the next write starts a line still matters.
            if let Some(last) = input.last() {
                lock(&state).linestart = *last == b'\n';
            }
            // SAFETY: the caller's guarantee.
            return unsafe { super::BIO_write_ex(next, data.cast(), len, written) };
        }
        let mut total = 0;
        // SAFETY: the caller's guarantee.
        unsafe { written.write(0) };
        while !input.is_empty() {
            let start = {
                let s = lock(&state);
                s.linestart.then(|| (s.prefix.clone(), s.indent))
            };
            if let Some((prefix, indent)) = start {
                if let Some(prefix) = prefix {
                    // SAFETY: the prefix is valid for its length; `next` is null or live.
                    let (ok, _) = unsafe { write_ex(next, prefix.as_ptr(), prefix.count_bytes()) };
                    if !ok {
                        return 0;
                    }
                }
                let indent = Arg::Int(c_int::from_ne_bytes(indent.to_ne_bytes()));
                // SAFETY: `next` is null or live; the arguments match the format.
                unsafe { printf(next, c"%*s", &[indent, Arg::Pointer(c"".as_ptr().cast())]) };
                lock(&state).linestart = false;
            }
            // Up to and including the next newline, or the rest.
            let (mut line, newline) = match input.iter().position(|c| *c == b'\n') {
                Some(at) => (at + 1, true),
                None => (input.len(), false),
            };
            while line > 0 {
                // SAFETY: `line` bytes of the input are readable; `next` is null or live.
                let (ok, n) = unsafe { write_ex(next, input.as_ptr().cast(), line) };
                if !ok {
                    return 0;
                }
                let n = n.min(line);
                input = input.get(n..).unwrap_or_default();
                total += n;
                // SAFETY: as above.
                unsafe { written.write(total) };
                line -= n;
            }
            if newline {
                lock(&state).linestart = true;
            }
        }
        1
    }
}

ffi_callback! {
    /// The prefix filter's controls: the prefix and the indentation; seeking and resetting
    /// start a new line; the rest go to the next BIO. Returns -1 without the filter's state.
    ///
    /// # Safety
    /// `b` is a live BIO; `ptr` is what the command expects (a string or null for
    /// `BIO_CTRL_SET_PREFIX`).
    pub(crate) unsafe extern "C" fn prefix_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return -1;
        };
        let Some(state) = state::get::<Prefix>(object) else {
            return -1;
        };
        match cmd {
            BIO_CTRL_SET_PREFIX => {
                let prefix = if ptr.is_null() {
                    None
                } else {
                    // SAFETY: the caller's guarantee: a NUL-terminated string.
                    Some(unsafe { CStr::from_ptr(ptr.cast()) }.to_owned())
                };
                lock(&state).prefix = prefix;
                1
            }
            BIO_CTRL_SET_INDENT => {
                if num < 0 {
                    return 0;
                }
                // OpenSSL keeps the low 32 bits.
                lock(&state).indent = u32::try_from(num & 0xFFFF_FFFF).unwrap_or(0);
                1
            }
            BIO_CTRL_GET_INDENT => c_long::from(lock(&state).indent),
            _ => {
                if cmd == BIO_C_FILE_SEEK || cmd == BIO_CTRL_RESET {
                    lock(&state).linestart = true;
                }
                let next = object.next();
                if next.is_null() {
                    return 0;
                }
                // SAFETY: the caller's guarantee about `ptr`; `next` is live.
                unsafe { super::BIO_ctrl(next, cmd, num, ptr) }
            }
        }
    }
}

ffi_callback! {
    /// Passes `BIO_callback_ctrl` to the next BIO.
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn prefix_callback_ctrl(b: *mut BIO, cmd: c_int, fp: BIO_info_cb) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let next = unsafe { object(b) }.map_or(ptr::null_mut(), super::Bio::next);
        // SAFETY: the next BIO is null or live.
        unsafe { super::BIO_callback_ctrl(next, cmd, fp) }
    }
}

ffi_callback! {
    /// Reads a line from the next BIO.
    ///
    /// # Safety
    /// `b` is a live BIO; `buf` is valid for `size` bytes of writes.
    pub(crate) unsafe extern "C" fn prefix_gets(b: *mut BIO, buf: *mut c_char, size: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let next = unsafe { object(b) }.map_or(ptr::null_mut(), super::Bio::next);
        // SAFETY: the next BIO is null (which fails with an error) or live.
        unsafe { super::BIO_gets(next, buf, size) }
    }
}

ffi_callback! {
    /// Writes a string through the filter itself, as `BIO_write` on it.
    ///
    /// # Safety
    /// `b` is a live BIO; `text` is a NUL-terminated string.
    pub(crate) unsafe extern "C" fn prefix_puts(b: *mut BIO, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if text.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let len = unsafe { CStr::from_ptr(text) }.count_bytes();
        let len = super::wrap_int(c_long::try_from(len).unwrap_or(c_long::MAX));
        // SAFETY: the caller's guarantee.
        unsafe { super::BIO_write(b, text.cast(), len) }
    }
}

static PREFIX: Builtin = Builtin::new(BIO_TYPE_BUFFER, c"prefix", || Funcs {
    bwrite: Some(prefix_write),
    bread: Some(prefix_read),
    bputs: Some(prefix_puts),
    bgets: Some(prefix_gets),
    ctrl: Some(prefix_ctrl),
    create: Some(prefix_create),
    destroy: Some(prefix_destroy),
    callback_ctrl: Some(prefix_callback_ctrl),
    ..Funcs::default()
});

ffi_export! {
    /// Returns the prefix filter's method, which writes a prefix (`BIO_set_prefix`) and an
    /// indentation (`BIO_set_indent`) at the start of each line written through it.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_f_prefix() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        PREFIX.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: OpenSSL reads the last byte of null data.
    #[test]
    fn null_data_is_refused() {
        // SAFETY: a built-in method.
        let f = unsafe { crate::bio::BIO_new(PREFIX.get()) };
        let mut written = 9;
        // SAFETY: a live BIO; null data is refused before use.
        let ret = unsafe { prefix_write(f, ptr::null(), 3, &raw mut written) };
        assert_eq!(ret, 0);
        // SAFETY: a live BIO, freed once.
        unsafe { crate::bio::BIO_free(f) };
    }
}
