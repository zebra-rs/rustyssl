//! Memory BIOs (`BIO_s_mem(3)`, `BIO_s_secmem`, `BIO_new_mem_buf`): a buffer that is read in
//! the order it was written.
//!
//! The buffer is a public `BUF_MEM`, which applications reach with `BIO_get_mem_ptr` and may
//! change between calls, and which `BIO_set_mem_buf` can replace with their own. So the state is
//! OpenSSL's, in C memory behind the BIO's data pointer: the buffer, and a second `BUF_MEM` that
//! marks how far reading has got. Unread data is moved back to the buffer's start before it
//! grows or is handed out, as OpenSSL does. A read-only BIO (`BIO_new_mem_buf`) reads the
//! caller's memory in place, advancing the buffer itself, and `BIO_reset` rewinds it.
//!
//! An empty writable BIO's read returns the "EOF return", -1 by default with the retry flags
//! set, so a reader treats it as "no data yet"; a read-only one returns 0.

use core::ffi::{CStr, c_char, c_int, c_long, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::Ordering;

use rustyssl_abi::{
    BIO, BIO_C_FILE_SEEK, BIO_C_FILE_TELL, BIO_C_GET_BUF_MEM_PTR, BIO_C_SET_BUF_MEM,
    BIO_C_SET_BUF_MEM_EOF_RETURN, BIO_CTRL_DUP, BIO_CTRL_EOF, BIO_CTRL_FLUSH, BIO_CTRL_GET_CLOSE,
    BIO_CTRL_INFO, BIO_CTRL_PENDING, BIO_CTRL_RESET, BIO_CTRL_SET_CLOSE, BIO_CTRL_WPENDING,
    BIO_FLAGS_MEM_RDONLY, BIO_FLAGS_NONCLEAR_RST, BIO_METHOD, BIO_R_WRITE_TO_READ_ONLY_BIO,
    BIO_TYPE_MEM, BUF_MEM, BUF_MEM_FLAG_SECURE, ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER,
};

use super::method::{Builtin, Funcs};
use crate::buffer::{BUF_MEM_free, BUF_MEM_grow_clean, BUF_MEM_new_ex};
use crate::ffi::{ffi_callback, ffi_export};
use crate::{err, mem};

/// OpenSSL's `BIO_BUF_MEM`: the buffer, and where reading has got to.
#[repr(C)]
struct BufMem {
    buf: *mut BUF_MEM,
    readp: *mut BUF_MEM,
}

/// A memory BIO's state and object, if `b` is a live BIO with one.
///
/// # Safety
/// `b` is null or a live BIO.
unsafe fn state<'a>(b: *mut BIO) -> Option<(&'a super::Bio, *mut BufMem)> {
    // SAFETY: the caller's guarantee.
    let object = unsafe { super::object(b) }?;
    let state = object.ptr.load(Ordering::Relaxed).cast::<BufMem>();
    (!state.is_null()).then_some((object, state))
}

/// Reads the state's two pointers.
///
/// # Safety
/// `state` is a live `BufMem`.
unsafe fn parts(state: *mut BufMem) -> (*mut BUF_MEM, *mut BUF_MEM) {
    // SAFETY: the caller's guarantee.
    let s = unsafe { state.read() };
    (s.buf, s.readp)
}

fn read_only(object: &super::Bio) -> bool {
    object.flags() & BIO_FLAGS_MEM_RDONLY != 0
}

/// Sets up a memory BIO (OpenSSL's `mem_init`).
///
/// # Safety
/// `b` is a live BIO.
unsafe fn init(b: *mut BIO, flags: c_ulong) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(object) = (unsafe { super::object(b) }) else {
        return 0;
    };
    let state = mem::alloc_zeroed(size_of::<BufMem>()).cast::<BufMem>();
    if state.is_null() {
        return 0;
    }
    // SAFETY: no preconditions.
    let buf = unsafe { BUF_MEM_new_ex(flags) };
    if buf.is_null() {
        // SAFETY: the block just allocated.
        unsafe { mem::release(state.cast()) };
        return 0;
    }
    let readp = mem::alloc_zeroed(size_of::<BUF_MEM>()).cast::<BUF_MEM>();
    if readp.is_null() {
        // SAFETY: the buffer just made.
        unsafe { BUF_MEM_free(buf) };
        // SAFETY: as above.
        unsafe { mem::release(state.cast()) };
        return 0;
    }
    // SAFETY: both are fresh, valid blocks of their type.
    unsafe { ptr::copy(buf, readp, 1) };
    // SAFETY: as above.
    unsafe { state.write(BufMem { buf, readp }) };
    object.shutdown.store(1, Ordering::Relaxed);
    object.init.store(1, Ordering::Relaxed);
    object.num.store(-1, Ordering::Relaxed);
    object.ptr.store(state.cast(), Ordering::Relaxed);
    1
}

ffi_callback! {
    /// The memory BIO's `create`.
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn mem_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { init(b, 0) }
    }
}

ffi_callback! {
    /// The secure memory BIO's `create`: its buffer is on the secure heap.
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn secmem_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { init(b, c_ulong::from(BUF_MEM_FLAG_SECURE.unsigned_abs())) }
    }
}

/// Frees the buffer if the BIO owns it (OpenSSL's `mem_buf_free`); a read-only BIO's data is
/// the caller's and stays.
///
/// # Safety
/// `b` is a live memory BIO.
unsafe fn free_buffer(b: *mut BIO) {
    // SAFETY: the caller's guarantee.
    let Some((object, state)) = (unsafe { state(b) }) else {
        return;
    };
    if object.shutdown.load(Ordering::Relaxed) == 0 || object.init.load(Ordering::Relaxed) == 0 {
        return;
    }
    // SAFETY: the state is live.
    let (buf, _) = unsafe { parts(state) };
    if buf.is_null() {
        return;
    }
    if read_only(object) {
        // SAFETY: the buffer is live; its data isn't ours to free.
        unsafe { (*buf).data = ptr::null_mut() };
    }
    // SAFETY: the BIO owns the buffer.
    unsafe { BUF_MEM_free(buf) };
}

ffi_callback! {
    /// The memory BIO's `destroy`.
    ///
    /// # Safety
    /// `b` is a live BIO, not used afterwards.
    pub(crate) unsafe extern "C" fn mem_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { state(b) }) else {
            return 0;
        };
        // SAFETY: as above.
        unsafe { free_buffer(b) };
        // SAFETY: the state is live, and the BIO is going away.
        let (_, readp) = unsafe { parts(state) };
        // SAFETY: as above; both from CRYPTO_malloc.
        unsafe { mem::release(readp.cast()) };
        // SAFETY: as above.
        unsafe { mem::release(state.cast()) };
        object.ptr.store(ptr::null_mut(), Ordering::Relaxed);
        1
    }
}

/// Moves unread data back to the buffer's start (OpenSSL's `mem_buf_sync`).
///
/// # Safety
/// `b` is a live memory BIO whose buffer is writable.
unsafe fn sync(b: *mut BIO) {
    // SAFETY: the caller's guarantee.
    let Some((object, state)) = (unsafe { state(b) }) else {
        return;
    };
    if object.init.load(Ordering::Relaxed) == 0 {
        return;
    }
    // SAFETY: the state is live.
    let (buf, readp) = unsafe { parts(state) };
    // SAFETY: both are live `BUF_MEM`s.
    let mut whole = unsafe { buf.read() };
    // SAFETY: as above.
    let mut unread = unsafe { readp.read() };
    if unread.data != whole.data {
        // SAFETY: the unread bytes lie inside the buffer, which can hold them at its start.
        unsafe { ptr::copy(unread.data, whole.data, unread.length) };
        whole.length = unread.length;
        unread.data = whole.data;
        // SAFETY: as above.
        unsafe { buf.write(whole) };
        // SAFETY: as above.
        unsafe { readp.write(unread) };
    }
}

/// The `BUF_MEM` reads come from: the read position, or the buffer itself when read-only.
///
/// # Safety
/// `state` is a live `BufMem`.
unsafe fn reading(object: &super::Bio, state: *mut BufMem) -> *mut BUF_MEM {
    // SAFETY: the caller's guarantee.
    let (buf, readp) = unsafe { parts(state) };
    if read_only(object) { buf } else { readp }
}

ffi_callback! {
    /// The memory BIO's `read`: up to `outl` unread bytes; when there are none, the EOF return
    /// (with the retry flags unless it is 0).
    ///
    /// # Safety
    /// `b` is a live BIO; `out` is null or valid for `outl` bytes of writes.
    pub(crate) unsafe extern "C" fn mem_read(b: *mut BIO, out: *mut c_char, outl: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { state(b) }) else {
            return -1;
        };
        // SAFETY: the state is live.
        let bm = unsafe { reading(object, state) };
        object.clear_retry_flags();
        // SAFETY: a live `BUF_MEM`.
        let mut m = unsafe { bm.read() };
        let ret = match usize::try_from(outl) {
            Ok(want) if want > m.length => c_int::try_from(m.length).unwrap_or(c_int::MAX),
            _ => outl,
        };
        match usize::try_from(ret) {
            Ok(n) if n > 0 && !out.is_null() => {
                // SAFETY: `n` unread bytes are at `data`; the caller's buffer holds `outl >= n`.
                unsafe { ptr::copy_nonoverlapping(m.data, out, n) };
                m.length -= n;
                m.max = m.max.wrapping_sub(n);
                m.data = m.data.wrapping_add(n);
                // SAFETY: as above.
                unsafe { bm.write(m) };
                ret
            }
            _ if m.length == 0 => {
                let eof = object.num.load(Ordering::Relaxed);
                if eof != 0 {
                    object.set_retry_read();
                }
                eof
            }
            _ => ret,
        }
    }
}

ffi_callback! {
    /// The memory BIO's `write`: appends to the buffer. A read-only BIO refuses.
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is null or valid for `inl` bytes of reads.
    pub(crate) unsafe extern "C" fn mem_write(b: *mut BIO, data: *const c_char, inl: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { state(b) }) else {
            return -1;
        };
        if read_only(object) {
            err::raise(ERR_LIB_BIO, BIO_R_WRITE_TO_READ_ONLY_BIO, "mem_write");
            return -1;
        }
        object.clear_retry_flags();
        if inl == 0 {
            return 0;
        }
        if data.is_null() {
            err::raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER, "mem_write");
            return -1;
        }
        let Ok(len) = usize::try_from(inl) else {
            return -1;
        };
        // SAFETY: the state is live.
        let (buf, readp) = unsafe { parts(state) };
        // SAFETY: a live `BUF_MEM`.
        let unread = unsafe { readp.read() }.length;
        // SAFETY: as above.
        unsafe { sync(b) };
        let Some(total) = unread.checked_add(len) else {
            return -1;
        };
        // SAFETY: the BIO's own buffer.
        if unsafe { BUF_MEM_grow_clean(buf, total) } == 0 {
            return -1;
        }
        // SAFETY: the BIO's own, live buffer.
        let start = unsafe { buf.read() }.data;
        // SAFETY: the buffer now holds `total` bytes; `data` holds `len`, elsewhere.
        unsafe { ptr::copy_nonoverlapping(data, start.wrapping_add(unread), len) };
        // SAFETY: both are live `BUF_MEM`s.
        unsafe { ptr::copy(buf, readp, 1) };
        inl
    }
}

ffi_callback! {
    /// The memory BIO's controls.
    ///
    /// # Safety
    /// `b` is a live BIO; `ptr` is what the command expects.
    pub(crate) unsafe extern "C" fn mem_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { state(b) }) else {
            return 0;
        };
        // SAFETY: the state is live, for each access below.
        let (buf, readp) = unsafe { parts(state) };
        let rdonly = read_only(object);
        let (bm, bo) = if rdonly { (buf, readp) } else { (readp, buf) };
        // SAFETY: as above.
        let mut m = unsafe { bm.read() };
        // SAFETY: as above.
        let other = unsafe { bo.read() };
        let off: c_long = if m.data == other.data {
            0
        } else {
            c_long::try_from(m.data.addr().wrapping_sub(other.data.addr())).unwrap_or(0)
        };
        let remain = c_long::try_from(m.length).unwrap_or(c_long::MAX);
        match cmd {
            BIO_CTRL_RESET => {
                // SAFETY: as above.
                let whole = unsafe { buf.read() };
                if !whole.data.is_null() {
                    if rdonly {
                        // SAFETY: as above; the start was kept in `readp`.
                        unsafe { ptr::copy(readp, buf, 1) };
                    } else {
                        if object.flags() & BIO_FLAGS_NONCLEAR_RST == 0 {
                            // SAFETY: the buffer's `max` bytes are allocated.
                            unsafe { ptr::write_bytes(whole.data, 0, whole.max) };
                            // SAFETY: as above.
                            unsafe { (*buf).length = 0 };
                        }
                        // SAFETY: as above.
                        unsafe { ptr::copy(buf, readp, 1) };
                    }
                }
                1
            }
            BIO_C_FILE_SEEK | BIO_C_FILE_TELL => {
                if cmd == BIO_C_FILE_TELL {
                    return off;
                }
                let Some(to) = usize::try_from(num).ok().filter(|_| num <= off.saturating_add(remain)) else {
                    return -1;
                };
                m.data = other.data.wrapping_add(to);
                m.length = other.length.wrapping_sub(to);
                m.max = other.max.wrapping_sub(to);
                // SAFETY: as above.
                unsafe { bm.write(m) };
                num
            }
            BIO_CTRL_EOF => c_long::from(m.length == 0),
            BIO_C_SET_BUF_MEM_EOF_RETURN => {
                object.num.store(super::wrap_int(num), Ordering::Relaxed);
                1
            }
            BIO_CTRL_INFO => {
                if !ptr.is_null() {
                    // SAFETY: the caller passes a `char **`.
                    unsafe { ptr.cast::<*mut c_char>().write(m.data) };
                }
                c_long::try_from(m.length).unwrap_or(c_long::MAX)
            }
            BIO_C_SET_BUF_MEM => {
                let replacement = ptr.cast::<BUF_MEM>();
                if replacement.is_null() {
                    return 0;
                }
                // SAFETY: as above.
                unsafe { free_buffer(b) };
                object.shutdown.store(super::wrap_int(num), Ordering::Relaxed);
                // SAFETY: as above; the caller's buffer is a live `BUF_MEM`.
                unsafe { (*state).buf = replacement };
                // SAFETY: as above.
                unsafe { ptr::copy(replacement, readp, 1) };
                1
            }
            BIO_C_GET_BUF_MEM_PTR => {
                if !ptr.is_null() {
                    if !rdonly {
                        // SAFETY: as above.
                        unsafe { sync(b) };
                    }
                    // SAFETY: the caller passes a `BUF_MEM **`.
                    unsafe { ptr.cast::<*mut BUF_MEM>().write(buf) };
                }
                1
            }
            BIO_CTRL_GET_CLOSE => c_long::from(object.shutdown.load(Ordering::Relaxed)),
            BIO_CTRL_SET_CLOSE => {
                object.shutdown.store(super::wrap_int(num), Ordering::Relaxed);
                1
            }
            BIO_CTRL_WPENDING => 0,
            BIO_CTRL_PENDING => c_long::try_from(m.length).unwrap_or(c_long::MAX),
            BIO_CTRL_DUP | BIO_CTRL_FLUSH => 1,
            _ => 0,
        }
    }
}

ffi_callback! {
    /// The memory BIO's `gets`: up to and including a newline, at most `size - 1` bytes.
    ///
    /// # Safety
    /// `b` is a live BIO; `buf` is valid for `size` bytes of writes.
    pub(crate) unsafe extern "C" fn mem_gets(b: *mut BIO, buf: *mut c_char, size: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { state(b) }) else {
            return -1;
        };
        // SAFETY: the state is live.
        let bm = unsafe { reading(object, state) };
        object.clear_retry_flags();
        // SAFETY: a live `BUF_MEM`.
        let m = unsafe { bm.read() };
        let available = c_int::try_from(m.length).unwrap_or(c_int::MAX);
        let j = available.min(size.saturating_sub(1));
        let Some(j) = usize::try_from(j).ok().filter(|j| *j > 0) else {
            // SAFETY: the caller's buffer holds at least a byte here.
            unsafe { buf.write(0) };
            return 0;
        };
        // SAFETY: `j` unread bytes are at `data`.
        let unread = unsafe { core::slice::from_raw_parts(m.data.cast::<u8>(), j) };
        let line = unread.iter().position(|c| *c == b'\n').map_or(j, |i| i + 1);
        // SAFETY: as above.
        let got = unsafe { mem_read(b, buf, c_int::try_from(line).unwrap_or(0)) };
        if let Ok(n) = usize::try_from(got)
            && n > 0
        {
            // SAFETY: `n < size`.
            unsafe { buf.wrapping_add(n).write(0) };
        }
        got
    }
}

ffi_callback! {
    /// The memory BIO's `puts`.
    ///
    /// # Safety
    /// `b` is a live BIO; `text` is a NUL-terminated string.
    pub(crate) unsafe extern "C" fn mem_puts(b: *mut BIO, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let len = unsafe { CStr::from_ptr(text) }.count_bytes();
        // SAFETY: as above.
        unsafe { mem_write(b, text, c_int::try_from(len).unwrap_or(c_int::MAX)) }
    }
}

fn mem_funcs(create: super::method::Create) -> Funcs {
    Funcs {
        bputs: Some(mem_puts),
        bgets: Some(mem_gets),
        ctrl: Some(mem_ctrl),
        create: Some(create),
        destroy: Some(mem_free),
        ..Funcs::classic(mem_write, mem_read)
    }
}

pub(crate) static MEM: Builtin =
    Builtin::new(BIO_TYPE_MEM, c"memory buffer", || mem_funcs(mem_new));
static SECMEM: Builtin = Builtin::new(BIO_TYPE_MEM, c"secure memory buffer", || {
    mem_funcs(secmem_new)
});

ffi_export! {
    /// Returns the memory BIO's method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_s_mem() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        MEM.get()
    }
}

ffi_export! {
    /// Returns the secure memory BIO's method, whose buffer is on the secure heap.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_s_secmem() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        SECMEM.get()
    }
}

ffi_export! {
    /// Returns a read-only memory BIO over `len` bytes at `buf` (up to its NUL if `len` is
    /// negative), read in place; its end reads as 0, without retrying.
    ///
    /// # Safety
    /// `buf` is null or valid for `len` bytes (or NUL-terminated), unchanged while the BIO lives.
    pub unsafe extern "C" fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        if buf.is_null() {
            err::raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER, "BIO_new_mem_buf");
            return ptr::null_mut();
        }
        let size = match usize::try_from(len) {
            Ok(n) => n,
            // SAFETY: the caller's guarantee.
            Err(_) => unsafe { CStr::from_ptr(buf.cast()) }.count_bytes(),
        };
        // SAFETY: the built-in method.
        let bio = unsafe { super::new(ptr::null_mut(), MEM.get()) };
        // SAFETY: just created.
        let Some((object, state)) = (unsafe { state(bio) }) else {
            return bio;
        };
        // SAFETY: the new BIO's state.
        let (bm, readp) = unsafe { parts(state) };
        // SAFETY: a live, empty `BUF_MEM`.
        let empty = unsafe { bm.read() };
        let over = BUF_MEM {
            length: size,
            data: buf.cast_mut().cast(),
            max: size,
            ..empty
        };
        // SAFETY: as above; the data is the caller's, never written through.
        unsafe { bm.write(over) };
        // SAFETY: both are live `BUF_MEM`s.
        unsafe { ptr::copy(bm, readp, 1) };
        object.set_flags(BIO_FLAGS_MEM_RDONLY);
        object.num.store(0, Ordering::Relaxed);
        bio
    }
}
