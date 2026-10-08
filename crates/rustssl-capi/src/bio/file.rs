//! The `FILE` BIO (`BIO_s_file(3)`, `BIO_new_file`, `BIO_new_fp`): stdio underneath, with
//! OpenSSL's Unix behavior.
//!
//! Each operation is the matching stdio call on the BIO's `FILE *` (its data pointer, as in
//! OpenSSL): `fread`, `fwrite`, `fgets`, `fseek` (whose 0 is `BIO_seek`'s and `BIO_reset`'s
//! success), `ftell`, `feof`, `fflush`. Failures raise the system error with the call in its
//! data (`calling fopen(name, mode)`), then a BIO error. A BIO with no `FILE` yet fails its
//! operations instead of passing null to stdio as OpenSSL's would (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::Ordering;

use libc::FILE;
use rustssl_abi::{
    BIO, BIO_C_FILE_SEEK, BIO_C_FILE_TELL, BIO_C_GET_FILE_PTR, BIO_C_SET_FILE_PTR,
    BIO_C_SET_FILENAME, BIO_CLOSE, BIO_CTRL_DUP, BIO_CTRL_EOF, BIO_CTRL_FLUSH, BIO_CTRL_GET_CLOSE,
    BIO_CTRL_INFO, BIO_CTRL_RESET, BIO_CTRL_SET_CLOSE, BIO_FP_APPEND, BIO_FP_READ, BIO_FP_TEXT,
    BIO_FP_WRITE, BIO_METHOD, BIO_R_BAD_FOPEN_MODE, BIO_R_NO_SUCH_FILE, BIO_TYPE_FILE, ERR_LIB_BIO,
    ERR_LIB_SYS, ERR_R_SYS_LIB,
};

use super::method::{Builtin, Funcs};
use crate::ffi::{ffi_callback, ffi_export};
use crate::{err, errno};

/// The BIO and its `FILE`, which is null until one is set.
///
/// # Safety
/// `b` is null or a live BIO.
unsafe fn file<'a>(b: *mut BIO) -> Option<(&'a super::Bio, *mut FILE)> {
    // SAFETY: the caller's guarantee.
    let object = unsafe { super::object(b) }?;
    Some((object, object.ptr.load(Ordering::Relaxed).cast()))
}

/// Raises the system error for a failed stdio call, `calling <call>`, then a BIO error.
#[track_caller]
fn raise_call(call: &[u8], reason: c_int, function: &str) {
    let number = errno::get();
    let mut text = b"calling ".to_vec();
    text.extend_from_slice(call);
    err::raise_with_bytes(ERR_LIB_SYS, number, function, &text);
    err::raise(ERR_LIB_BIO, reason, function);
}

ffi_callback! {
    /// The `FILE` BIO's `create`: uninitialized, with no `FILE` and no flags.
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn file_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        if let Some(object) = unsafe { super::object(b) } {
            object.init.store(0, Ordering::Relaxed);
            object.num.store(0, Ordering::Relaxed);
            object.ptr.store(ptr::null_mut(), Ordering::Relaxed);
            object.clear_flags(!0);
        }
        1
    }
}

ffi_callback! {
    /// The `FILE` BIO's `destroy`: closes the `FILE` if the BIO owns it.
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn file_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, fp)) = (unsafe { file(b) }) else {
            return 0;
        };
        if object.shutdown.load(Ordering::Relaxed) != 0 {
            if object.init.load(Ordering::Relaxed) != 0 && !fp.is_null() {
                // SAFETY: the BIO owns the open FILE.
                unsafe { libc::fclose(fp) };
                object.ptr.store(ptr::null_mut(), Ordering::Relaxed);
                object.clear_flags(!0);
            }
            object.init.store(0, Ordering::Relaxed);
        }
        1
    }
}

ffi_callback! {
    /// The `FILE` BIO's `read`: `fread`, -1 with an error if it failed.
    ///
    /// # Safety
    /// `b` is a live BIO; `out` is null or valid for `outl` bytes of writes.
    pub(crate) unsafe extern "C" fn file_read(b: *mut BIO, out: *mut c_char, outl: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, fp)) = (unsafe { file(b) }) else {
            return 0;
        };
        if object.init.load(Ordering::Relaxed) == 0 || out.is_null() || fp.is_null() {
            return 0;
        }
        let len = usize::try_from(outl).unwrap_or(0);
        // SAFETY: the BIO's open FILE; the caller's buffer holds `len` bytes.
        let got = unsafe { libc::fread(out.cast(), 1, len, fp) };
        // SAFETY: as above.
        if got == 0 && unsafe { libc::ferror(fp) } != 0 {
            raise_call(b"fread()", ERR_R_SYS_LIB, "file_read");
            return -1;
        }
        c_int::try_from(got).unwrap_or(c_int::MAX)
    }
}

ffi_callback! {
    /// The `FILE` BIO's `write`: `fwrite` of the whole buffer, so all or nothing.
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is null or valid for `inl` bytes of reads.
    pub(crate) unsafe extern "C" fn file_write(b: *mut BIO, data: *const c_char, inl: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, fp)) = (unsafe { file(b) }) else {
            return 0;
        };
        if object.init.load(Ordering::Relaxed) == 0 || data.is_null() || fp.is_null() {
            return 0;
        }
        let len = usize::try_from(inl).unwrap_or(0);
        // SAFETY: the BIO's open FILE; the caller's buffer holds `len` bytes.
        if unsafe { libc::fwrite(data.cast(), len, 1, fp) } == 0 {
            return 0;
        }
        inl
    }
}

/// The `fopen` mode for `BIO_C_SET_FILENAME`'s flags, or `None` without a direction. Unix
/// has no text or binary modes, so OpenSSL adds no `t` or `b`.
fn open_mode(flags: c_long) -> Option<&'static CStr> {
    let has = |flag: c_int| flags & c_long::from(flag) != 0;
    if has(BIO_FP_APPEND) {
        Some(if has(BIO_FP_READ) { c"a+" } else { c"a" })
    } else if has(BIO_FP_READ) && has(BIO_FP_WRITE) {
        Some(c"r+")
    } else if has(BIO_FP_WRITE) {
        Some(c"w")
    } else if has(BIO_FP_READ) {
        Some(c"r")
    } else {
        None
    }
}

/// `calling fopen(<name>, <mode>)` as bytes.
fn fopen_call(name: &[u8], mode: &[u8]) -> Vec<u8> {
    let mut call = b"fopen(".to_vec();
    call.extend_from_slice(name);
    call.extend_from_slice(b", ");
    call.extend_from_slice(mode);
    call.push(b')');
    call
}

ffi_callback! {
    /// The `FILE` BIO's controls.
    ///
    /// # Safety
    /// `b` is a live BIO; `ptr` is what the command expects.
    pub(crate) unsafe extern "C" fn file_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, fp)) = (unsafe { file(b) }) else {
            return 0;
        };
        let needs_file = [BIO_C_FILE_SEEK, BIO_CTRL_RESET, BIO_CTRL_EOF, BIO_C_FILE_TELL, BIO_CTRL_INFO];
        if fp.is_null() && needs_file.contains(&cmd) {
            return if cmd == BIO_CTRL_EOF { 0 } else { -1 };
        }
        match cmd {
            // SAFETY: the BIO's open FILE, for each stdio call below.
            BIO_C_FILE_SEEK | BIO_CTRL_RESET => c_long::from(unsafe { libc::fseek(fp, num, libc::SEEK_SET) }),
            // SAFETY: as above.
            BIO_CTRL_EOF => c_long::from(unsafe { libc::feof(fp) }),
            // SAFETY: as above.
            BIO_C_FILE_TELL | BIO_CTRL_INFO => unsafe { libc::ftell(fp) },
            BIO_C_SET_FILE_PTR => {
                // SAFETY: as above.
                unsafe { file_free(b) };
                object.shutdown.store(super::wrap_int(num & c_long::from(BIO_CLOSE)), Ordering::Relaxed);
                object.ptr.store(ptr, Ordering::Relaxed);
                object.init.store(1, Ordering::Relaxed);
                1
            }
            BIO_C_SET_FILENAME => {
                // SAFETY: as above.
                unsafe { file_free(b) };
                object.shutdown.store(super::wrap_int(num & c_long::from(BIO_CLOSE)), Ordering::Relaxed);
                let Some(mode) = open_mode(num) else {
                    err::raise(ERR_LIB_BIO, BIO_R_BAD_FOPEN_MODE, "file_ctrl");
                    return 0;
                };
                if ptr.is_null() {
                    return 0;
                }
                // SAFETY: the caller passes a NUL-terminated file name.
                let opened = unsafe { libc::fopen(ptr.cast(), mode.as_ptr()) };
                if opened.is_null() {
                    // SAFETY: as above.
                    let name = unsafe { CStr::from_ptr(ptr.cast()) }.to_bytes();
                    raise_call(&fopen_call(name, mode.to_bytes()), ERR_R_SYS_LIB, "file_ctrl");
                    return 0;
                }
                object.ptr.store(opened.cast(), Ordering::Relaxed);
                object.init.store(1, Ordering::Relaxed);
                1
            }
            BIO_C_GET_FILE_PTR => {
                if !ptr.is_null() {
                    // SAFETY: the caller passes a `FILE **`.
                    unsafe { ptr.cast::<*mut FILE>().write(fp) };
                }
                1
            }
            BIO_CTRL_GET_CLOSE => c_long::from(object.shutdown.load(Ordering::Relaxed)),
            BIO_CTRL_SET_CLOSE => {
                object.shutdown.store(super::wrap_int(num), Ordering::Relaxed);
                1
            }
            BIO_CTRL_FLUSH => {
                // SAFETY: the BIO's FILE, or null, which flushes every stream as in OpenSSL.
                if unsafe { libc::fflush(fp) } == libc::EOF {
                    raise_call(b"fflush()", ERR_R_SYS_LIB, "file_ctrl");
                    return 0;
                }
                1
            }
            BIO_CTRL_DUP => 1,
            _ => 0,
        }
    }
}

ffi_callback! {
    /// The `FILE` BIO's `gets`: `fgets`.
    ///
    /// # Safety
    /// `b` is a live BIO; `buf` is valid for `size` bytes of writes.
    pub(crate) unsafe extern "C" fn file_gets(b: *mut BIO, buf: *mut c_char, size: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { buf.write(0) };
        // SAFETY: as above.
        let Some((_, fp)) = (unsafe { file(b) }) else {
            return 0;
        };
        // SAFETY: the BIO's open FILE; the caller's buffer holds `size` bytes.
        if fp.is_null() || unsafe { libc::fgets(buf, size, fp) }.is_null() {
            return 0;
        }
        // SAFETY: fgets NUL-terminated the buffer.
        let len = unsafe { CStr::from_ptr(buf) }.count_bytes();
        c_int::try_from(len).unwrap_or(c_int::MAX)
    }
}

ffi_callback! {
    /// The `FILE` BIO's `puts`.
    ///
    /// # Safety
    /// `b` is a live BIO; `text` is a NUL-terminated string.
    pub(crate) unsafe extern "C" fn file_puts(b: *mut BIO, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let len = unsafe { CStr::from_ptr(text) }.count_bytes();
        // SAFETY: as above.
        unsafe { file_write(b, text, c_int::try_from(len).unwrap_or(c_int::MAX)) }
    }
}

static FILE_METHOD: Builtin = Builtin::new(BIO_TYPE_FILE, c"FILE pointer", || Funcs {
    bputs: Some(file_puts),
    bgets: Some(file_gets),
    ctrl: Some(file_ctrl),
    create: Some(file_new),
    destroy: Some(file_free),
    ..Funcs::classic(file_write, file_read)
});

ffi_export! {
    /// Returns the `FILE` BIO's method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_s_file() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        FILE_METHOD.get()
    }
}

ffi_export! {
    /// Opens `filename` with `fopen` and returns a BIO that reads or writes it and closes it when
    /// freed. Null on failure, after the system error (with the call in its data) and
    /// `BIO_R_NO_SUCH_FILE` for a missing file or `ERR_R_SYS_LIB` otherwise.
    ///
    /// # Safety
    /// `filename` and `mode` are NUL-terminated strings (null ones fail, docs/DEVIATIONS.md).
    pub unsafe extern "C" fn BIO_new_file(filename: *const c_char, mode: *const c_char) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        if filename.is_null() || mode.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let fp = unsafe { libc::fopen(filename, mode) };
        // SAFETY: as above.
        let mode_bytes = unsafe { CStr::from_ptr(mode) }.to_bytes();
        if fp.is_null() {
            let number = errno::get();
            // SAFETY: as above.
            let name = unsafe { CStr::from_ptr(filename) }.to_bytes();
            let mut text = b"calling ".to_vec();
            text.extend_from_slice(&fopen_call(name, mode_bytes));
            err::raise_with_bytes(ERR_LIB_SYS, number, "BIO_new_file", &text);
            let reason = if number == libc::ENOENT || number == libc::ENXIO { BIO_R_NO_SUCH_FILE } else { ERR_R_SYS_LIB };
            err::raise(ERR_LIB_BIO, reason, "BIO_new_file");
            return ptr::null_mut();
        }
        // SAFETY: the built-in method.
        let bio = unsafe { super::new(ptr::null_mut(), FILE_METHOD.get()) };
        if bio.is_null() {
            // SAFETY: the FILE just opened.
            unsafe { libc::fclose(fp) };
            return bio;
        }
        let mut flags = c_long::from(BIO_CLOSE);
        if !mode_bytes.contains(&b'b') {
            flags |= c_long::from(BIO_FP_TEXT);
        }
        // SAFETY: the new BIO; it takes over the FILE.
        unsafe { super::ctrl(bio, BIO_C_SET_FILE_PTR, flags, fp.cast()) };
        bio
    }
}

ffi_export! {
    /// Returns a BIO over an open `FILE`, which it closes when freed if `close_flag` has
    /// `BIO_CLOSE`.
    ///
    /// # Safety
    /// `stream` is null or an open `FILE` that outlives the BIO's use of it.
    pub unsafe extern "C" fn BIO_new_fp(stream: *mut FILE, close_flag: c_int) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        // SAFETY: the built-in method.
        let bio = unsafe { super::new(ptr::null_mut(), FILE_METHOD.get()) };
        if !bio.is_null() {
            // SAFETY: the new BIO.
            unsafe { super::ctrl(bio, BIO_C_SET_FILE_PTR, c_long::from(close_flag), stream.cast()) };
        }
        bio
    }
}
