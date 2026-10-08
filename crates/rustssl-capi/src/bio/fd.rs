//! The file descriptor BIO (`BIO_s_fd(3)`, `BIO_new_fd`): `read`, `write`, and `lseek` on a
//! descriptor, kept in the BIO's `num` as in OpenSSL. A read or write that fails with a
//! transient `errno` (`BIO_fd_non_fatal_error`) sets the retry flags; a read of 0 sets the EOF
//! flag that `BIO_eof` reports.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::Ordering;

use rustssl_abi::{
    BIO, BIO_C_FILE_SEEK, BIO_C_FILE_TELL, BIO_C_GET_FD, BIO_C_SET_FD, BIO_CTRL_DUP, BIO_CTRL_EOF,
    BIO_CTRL_FLUSH, BIO_CTRL_GET_CLOSE, BIO_CTRL_INFO, BIO_CTRL_PENDING, BIO_CTRL_RESET,
    BIO_CTRL_SET_CLOSE, BIO_CTRL_WPENDING, BIO_FLAGS_IN_EOF, BIO_METHOD, BIO_TYPE_FD, ERR_LIB_BIO,
};

use super::method::{Builtin, Funcs};
use crate::errno;
use crate::ffi::{ffi_callback, ffi_export};

ffi_callback! {
    /// The descriptor BIO's `create`: uninitialized, descriptor -1.
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn fd_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        if let Some(object) = unsafe { super::object(b) } {
            object.init.store(0, Ordering::Relaxed);
            object.num.store(-1, Ordering::Relaxed);
            object.ptr.store(ptr::null_mut(), Ordering::Relaxed);
            object.clear_flags(!0);
        }
        1
    }
}

ffi_callback! {
    /// The descriptor BIO's `destroy`: closes the descriptor if the BIO owns it.
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn fd_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { super::object(b) }) else {
            return 0;
        };
        if object.shutdown.load(Ordering::Relaxed) != 0 {
            if object.init.load(Ordering::Relaxed) != 0 {
                // SAFETY: the BIO owns the descriptor.
                unsafe { libc::close(object.num.load(Ordering::Relaxed)) };
            }
            object.init.store(0, Ordering::Relaxed);
            object.clear_flags(!0);
        }
        1
    }
}

/// Whether a read or write that returned `ret` failed transiently (`BIO_fd_should_retry`).
fn should_retry(ret: isize) -> bool {
    (ret == 0 || ret == -1) && non_fatal(errno::get())
}

/// `BIO_fd_non_fatal_error`: the `errno` values that mean "try again".
fn non_fatal(err: c_int) -> bool {
    [
        libc::EWOULDBLOCK,
        libc::ENOTCONN,
        libc::EINTR,
        libc::EAGAIN,
        libc::EPROTO,
        libc::EINPROGRESS,
        libc::EALREADY,
    ]
    .contains(&err)
}

ffi_callback! {
    /// The descriptor BIO's `read`.
    ///
    /// # Safety
    /// `b` is a live BIO; `out` is null or valid for `outl` bytes of writes.
    pub(crate) unsafe extern "C" fn fd_read(b: *mut BIO, out: *mut c_char, outl: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { super::object(b) }) else {
            return 0;
        };
        if out.is_null() {
            return 0;
        }
        errno::set(0);
        let len = usize::try_from(outl).unwrap_or(0);
        // SAFETY: the caller's buffer holds `len` bytes.
        let ret = unsafe { libc::read(object.num.load(Ordering::Relaxed), out.cast(), len) };
        object.clear_retry_flags();
        if ret <= 0 {
            if should_retry(ret) {
                object.set_retry_read();
            } else if ret == 0 {
                object.set_flags(BIO_FLAGS_IN_EOF);
            }
        }
        c_int::try_from(ret).unwrap_or(-1)
    }
}

ffi_callback! {
    /// The descriptor BIO's `write`.
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is valid for `inl` bytes of reads.
    pub(crate) unsafe extern "C" fn fd_write(b: *mut BIO, data: *const c_char, inl: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { super::object(b) }) else {
            return 0;
        };
        errno::set(0);
        let len = usize::try_from(inl).unwrap_or(0);
        // SAFETY: the caller's buffer holds `len` bytes.
        let ret = unsafe { libc::write(object.num.load(Ordering::Relaxed), data.cast(), len) };
        object.clear_retry_flags();
        if ret <= 0 && should_retry(ret) {
            object.set_retry_write();
        }
        c_int::try_from(ret).unwrap_or(-1)
    }
}

ffi_callback! {
    /// The descriptor BIO's controls.
    ///
    /// # Safety
    /// `b` is a live BIO; `ptr` is what the command expects.
    pub(crate) unsafe extern "C" fn fd_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { super::object(b) }) else {
            return 0;
        };
        let fd = object.num.load(Ordering::Relaxed);
        match cmd {
            BIO_CTRL_RESET | BIO_C_FILE_SEEK => {
                let to = if cmd == BIO_CTRL_RESET { 0 } else { num };
                // SAFETY: lseek takes any descriptor and offset.
                c_long::from(unsafe { libc::lseek(fd, to, libc::SEEK_SET) })
            }
            // SAFETY: as above.
            BIO_C_FILE_TELL | BIO_CTRL_INFO => c_long::from(unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) }),
            BIO_C_SET_FD => {
                if ptr.is_null() {
                    return 0;
                }
                // SAFETY: as above.
                unsafe { fd_free(b) };
                // SAFETY: the caller passes a pointer to the descriptor.
                object.num.store(unsafe { ptr.cast::<c_int>().read() }, Ordering::Relaxed);
                object.shutdown.store(super::wrap_int(num), Ordering::Relaxed);
                object.init.store(1, Ordering::Relaxed);
                1
            }
            BIO_C_GET_FD => {
                if object.init.load(Ordering::Relaxed) == 0 {
                    return -1;
                }
                if !ptr.is_null() {
                    // SAFETY: the caller passes a pointer to an `int`.
                    unsafe { ptr.cast::<c_int>().write(fd) };
                }
                c_long::from(fd)
            }
            BIO_CTRL_GET_CLOSE => c_long::from(object.shutdown.load(Ordering::Relaxed)),
            BIO_CTRL_SET_CLOSE => {
                object.shutdown.store(super::wrap_int(num), Ordering::Relaxed);
                1
            }
            BIO_CTRL_PENDING | BIO_CTRL_WPENDING => 0,
            BIO_CTRL_DUP | BIO_CTRL_FLUSH => 1,
            BIO_CTRL_EOF => c_long::from(object.flags() & BIO_FLAGS_IN_EOF != 0),
            _ => 0,
        }
    }
}

ffi_callback! {
    /// The descriptor BIO's `puts`.
    ///
    /// # Safety
    /// `b` is a live BIO; `text` is a NUL-terminated string.
    pub(crate) unsafe extern "C" fn fd_puts(b: *mut BIO, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let len = unsafe { CStr::from_ptr(text) }.count_bytes();
        // SAFETY: as above.
        unsafe { fd_write(b, text, c_int::try_from(len).unwrap_or(c_int::MAX)) }
    }
}

ffi_callback! {
    /// The descriptor BIO's `gets`: a byte at a time, up to a newline or `size - 1` bytes.
    ///
    /// # Safety
    /// `b` is a live BIO; `buf` is valid for `size` bytes of writes.
    pub(crate) unsafe extern "C" fn fd_gets(b: *mut BIO, buf: *mut c_char, size: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let limit = usize::try_from(size).unwrap_or(0).saturating_sub(1);
        let mut used = 0;
        while used < limit {
            let at = buf.wrapping_add(used);
            // SAFETY: the caller's guarantee; `at` is inside the buffer.
            if unsafe { fd_read(b, at, 1) } <= 0 {
                break;
            }
            used += 1;
            // SAFETY: as above; just read.
            if unsafe { at.read() } == c_char::from_ne_bytes(*b"\n") {
                break;
            }
        }
        // SAFETY: as above; `used <= limit < size`, or the buffer's one byte.
        unsafe { buf.wrapping_add(used).write(0) };
        c_int::try_from(used).unwrap_or(c_int::MAX)
    }
}

static FD: Builtin = Builtin::new(BIO_TYPE_FD, c"file descriptor", || Funcs {
    bputs: Some(fd_puts),
    bgets: Some(fd_gets),
    ctrl: Some(fd_ctrl),
    create: Some(fd_new),
    destroy: Some(fd_free),
    ..Funcs::classic(fd_write, fd_read)
});

ffi_export! {
    /// Returns the descriptor BIO's method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_s_fd() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        FD.get()
    }
}

ffi_export! {
    /// Returns a BIO over descriptor `fd`, which it closes when freed if `close_flag` has
    /// `BIO_CLOSE`.
    ///
    /// # Safety
    /// `fd` is a descriptor the BIO may use.
    pub unsafe extern "C" fn BIO_new_fd(fd: c_int, close_flag: c_int) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        // SAFETY: the built-in method.
        let bio = unsafe { super::new(ptr::null_mut(), FD.get()) };
        if !bio.is_null() {
            let mut descriptor = fd;
            // SAFETY: the new BIO; `descriptor` lives through the call.
            unsafe { super::ctrl(bio, BIO_C_SET_FD, c_long::from(close_flag), (&raw mut descriptor).cast()) };
        }
        bio
    }
}

ffi_export! {
    /// Returns 1 if a read or write that returned `i` (0 or -1) failed with a transient
    /// `errno`, so it may be retried.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_fd_should_retry(i: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        c_int::from(should_retry(isize::try_from(i).unwrap_or(0)))
    }
}

ffi_export! {
    /// Returns 1 if `err` is an `errno` value that means "try again" (`EAGAIN`, `EINTR`,
    /// `EINPROGRESS`, ...).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_fd_non_fatal_error(err: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        c_int::from(non_fatal(err))
    }
}
