//! The null sink (`BIO_s_null(3)`), which swallows writes and reads nothing, and the null
//! filter (`BIO_f_null(3)`), which passes everything to the next BIO.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;

use rustssl_abi::{
    BIO, BIO_C_DO_STATE_MACHINE, BIO_CTRL_DUP, BIO_CTRL_EOF, BIO_CTRL_FLUSH, BIO_CTRL_RESET,
    BIO_CTRL_SET, BIO_CTRL_SET_CLOSE, BIO_METHOD, BIO_TYPE_NULL, BIO_TYPE_NULL_FILTER, BIO_info_cb,
    ERR_LIB_BIO,
};

use super::method::{Builtin, Funcs};
use crate::ffi::{ffi_callback, ffi_export};

ffi_callback! {
    /// The null sink's `write`: everything is written.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn null_write(b: *mut BIO, data: *const c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let _ = (b, data);
        len
    }
}

ffi_callback! {
    /// The null sink's `read`: nothing.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn null_read(b: *mut BIO, out: *mut c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let _ = (b, out, len);
        0
    }
}

ffi_callback! {
    /// The null sink's `puts`: the string's length, as if written.
    ///
    /// # Safety
    /// `text` is null or a NUL-terminated string.
    pub(crate) unsafe extern "C" fn null_puts(b: *mut BIO, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let _ = b;
        if text.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let len = unsafe { CStr::from_ptr(text) }.count_bytes();
        c_int::try_from(len).unwrap_or(c_int::MAX)
    }
}

ffi_callback! {
    /// The null sink's `gets`: nothing.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn null_gets(b: *mut BIO, buf: *mut c_char, size: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let _ = (b, buf, size);
        0
    }
}

ffi_callback! {
    /// The null sink's controls: 1 for the ones that succeed trivially, else 0.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn null_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        let _ = (b, num, ptr);
        let trivial = [BIO_CTRL_RESET, BIO_CTRL_EOF, BIO_CTRL_SET, BIO_CTRL_SET_CLOSE, BIO_CTRL_FLUSH, BIO_CTRL_DUP];
        c_long::from(trivial.contains(&cmd))
    }
}

static NULL: Builtin = Builtin::new(BIO_TYPE_NULL, c"NULL", || Funcs {
    bputs: Some(null_puts),
    bgets: Some(null_gets),
    ctrl: Some(null_ctrl),
    ..Funcs::classic(null_write, null_read)
});

ffi_export! {
    /// Returns the null sink's method: writes succeed, reads return nothing.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_s_null() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        NULL.get()
    }
}

/// The BIO after `b`, if `b` is a live BIO with one.
///
/// # Safety
/// `b` is null or a live BIO.
unsafe fn next(b: *mut BIO) -> *mut BIO {
    // SAFETY: the caller's guarantee.
    unsafe { super::object(b) }.map_or(ptr::null_mut(), super::Bio::next)
}

/// After passing an operation on: the filter's retry flags become the next BIO's.
///
/// # Safety
/// `b` is null or a live BIO.
unsafe fn copy_retry(b: *mut BIO) {
    // SAFETY: the caller's guarantee.
    if let Some(object) = unsafe { super::object(b) } {
        object.clear_retry_flags();
        super::copy_next_retry(object);
    }
}

ffi_callback! {
    /// The null filter's `read`: the next BIO's.
    ///
    /// # Safety
    /// `b` is a live BIO; `out` is null or valid for `len` bytes of writes.
    pub(crate) unsafe extern "C" fn nullf_read(b: *mut BIO, out: *mut c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let next = unsafe { next(b) };
        if out.is_null() || next.is_null() {
            return 0;
        }
        // SAFETY: as above; the next BIO is live.
        let ret = unsafe { super::BIO_read(next, out.cast(), len) };
        // SAFETY: as above.
        unsafe { copy_retry(b) };
        ret
    }
}

ffi_callback! {
    /// The null filter's `write`: the next BIO's.
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is null or valid for `len` bytes of reads.
    pub(crate) unsafe extern "C" fn nullf_write(b: *mut BIO, data: *const c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let next = unsafe { next(b) };
        if data.is_null() || len <= 0 || next.is_null() {
            return 0;
        }
        // SAFETY: as above; the next BIO is live.
        let ret = unsafe { super::BIO_write(next, data.cast(), len) };
        // SAFETY: as above.
        unsafe { copy_retry(b) };
        ret
    }
}

ffi_callback! {
    /// The null filter's controls: the next BIO's, except that it can't be copied.
    ///
    /// # Safety
    /// `b` is a live BIO; `ptr` is what the command expects.
    pub(crate) unsafe extern "C" fn nullf_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let next = unsafe { next(b) };
        if next.is_null() {
            return 0;
        }
        if cmd == BIO_CTRL_DUP {
            return 0;
        }
        if cmd == BIO_C_DO_STATE_MACHINE {
            // SAFETY: as above.
            if let Some(object) = unsafe { super::object(b) } {
                object.clear_retry_flags();
            }
        }
        // SAFETY: as above; the next BIO is live.
        let ret = unsafe { super::ctrl(next, cmd, num, ptr) };
        if cmd == BIO_C_DO_STATE_MACHINE {
            // SAFETY: as above.
            if let Some(object) = unsafe { super::object(b) } {
                super::copy_next_retry(object);
            }
        }
        ret
    }
}

ffi_callback! {
    /// The null filter's `callback_ctrl`: the next BIO's.
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn nullf_callback_ctrl(b: *mut BIO, cmd: c_int, fp: BIO_info_cb) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let next = unsafe { next(b) };
        if next.is_null() {
            return 0;
        }
        // SAFETY: as above; the next BIO is live.
        unsafe { super::BIO_callback_ctrl(next, cmd, fp) }
    }
}

ffi_callback! {
    /// The null filter's `gets`: the next BIO's.
    ///
    /// # Safety
    /// `b` is a live BIO; `buf` is valid for `size` bytes of writes.
    pub(crate) unsafe extern "C" fn nullf_gets(b: *mut BIO, buf: *mut c_char, size: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let next = unsafe { next(b) };
        if next.is_null() {
            return 0;
        }
        // SAFETY: as above; the next BIO is live.
        unsafe { super::gets(next, buf, size) }
    }
}

ffi_callback! {
    /// The null filter's `puts`: the next BIO's.
    ///
    /// # Safety
    /// `b` is a live BIO; `text` is a NUL-terminated string.
    pub(crate) unsafe extern "C" fn nullf_puts(b: *mut BIO, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let next = unsafe { next(b) };
        if next.is_null() {
            return 0;
        }
        // SAFETY: as above; the next BIO is live.
        unsafe { super::puts(next, text) }
    }
}

static NULL_FILTER: Builtin = Builtin::new(BIO_TYPE_NULL_FILTER, c"NULL filter", || Funcs {
    bputs: Some(nullf_puts),
    bgets: Some(nullf_gets),
    ctrl: Some(nullf_ctrl),
    callback_ctrl: Some(nullf_callback_ctrl),
    ..Funcs::classic(nullf_write, nullf_read)
});

ffi_export! {
    /// Returns the null filter's method, which passes everything to the next BIO.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_f_null() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        NULL_FILTER.get()
    }
}
