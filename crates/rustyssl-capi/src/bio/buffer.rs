//! The buffering filters: `BIO_f_buffer(3)`, which buffers reads and writes, `BIO_f_linebuffer`,
//! which buffers writes up to each newline, and `BIO_f_readbuffer(3)`, which keeps everything
//! read so that `BIO_seek` and `BIO_tell` work over a source that can't seek.
//!
//! These are ports of OpenSSL's `bf_buff.c`, `bf_lbuf.c`, and `bf_readbuff.c`, whose results
//! (how many bytes each call passes on, when it retries, what the controls return) applications
//! can see. The buffers are Rust-owned. While a call reads into or writes from one through the
//! next BIO, the buffer is out of the state, so a callback that re-enters the filter can't
//! change it under the call.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use rustyssl_abi::{
    BIO, BIO_C_DO_STATE_MACHINE, BIO_C_FILE_SEEK, BIO_C_FILE_TELL, BIO_C_GET_BUFF_NUM_LINES,
    BIO_C_SET_BUFF_READ_DATA, BIO_C_SET_BUFF_SIZE, BIO_CTRL_DUP, BIO_CTRL_EOF, BIO_CTRL_FLUSH,
    BIO_CTRL_INFO, BIO_CTRL_PEEK, BIO_CTRL_PENDING, BIO_CTRL_RESET, BIO_CTRL_WPENDING, BIO_METHOD,
    BIO_TYPE_BUFFER, BIO_TYPE_LINEBUFFER, BIO_info_cb, ERR_LIB_BIO,
};

use super::method::{Builtin, Funcs};
use super::state::{self, lock, zeroed};
use super::{Bio, object};
use crate::ffi::{ffi_callback, ffi_export};

/// The buffer size of `BIO_f_buffer` and `BIO_f_readbuffer`, and their read granularity.
const DEFAULT_BUFFER_SIZE: usize = 4096;

/// The output buffer size of `BIO_f_linebuffer`.
const DEFAULT_LINEBUFFER_SIZE: usize = 10 * 1024;

/// A length as a C `int`, for the lengths here, which never exceed one.
fn int(len: usize) -> c_int {
    c_int::try_from(len).unwrap_or(c_int::MAX)
}

/// A C `int` count that the code above checked isn't negative.
fn size(n: c_int) -> usize {
    usize::try_from(n).unwrap_or(0)
}

/// The filter `b`, its state, and its next BIO, or `None` where OpenSSL returns 0 because the
/// state or the next BIO is missing.
///
/// # Safety
/// `b` is null or a live BIO that outlives `'a`.
unsafe fn filter<'a, T: Send + 'static>(b: *mut BIO) -> Option<(&'a Bio, Arc<Mutex<T>>, *mut BIO)> {
    // SAFETY: the caller's guarantee.
    let object = unsafe { object(b) }?;
    let state = state::get::<T>(object)?;
    let next = object.next();
    if next.is_null() {
        return None;
    }
    Some((object, state, next))
}

/// Reads up to `len` bytes from `next` into `buf`, as `BIO_read` (which fails for null).
///
/// # Safety
/// `next` is null or a live BIO; `buf` is valid for `len` bytes of writes.
unsafe fn read_next(next: *mut BIO, buf: *mut u8, len: usize) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { super::BIO_read(next, buf.cast(), int(len)) }
}

/// Writes `len` bytes at `data` to `next`, as `BIO_write`.
///
/// # Safety
/// `next` is a live BIO; `data` is valid for `len` bytes of reads.
unsafe fn write_next(next: *mut BIO, data: *const u8, len: usize) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { super::BIO_write(next, data.cast(), int(len)) }
}

/// Passes a control to `next`, as `BIO_ctrl` (0 for a null `next`).
///
/// # Safety
/// `next` is null or a live BIO; `ptr` is what the command expects.
unsafe fn ctrl_next(next: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long {
    // SAFETY: the caller's guarantee.
    unsafe { super::BIO_ctrl(next, cmd, num, ptr) }
}

/// What a filter returns when the next BIO's read or write returned `i` (0 or less) after `num`
/// bytes went through: what went through, unless the next BIO failed before any did.
fn short(num: c_int, i: c_int) -> c_int {
    if i < 0 && num <= 0 { i } else { num }
}

/// The state of a `BIO_f_buffer` (OpenSSL's `BIO_F_BUFFER_CTX`). Offsets and lengths are within
/// the sizes, which are at most `INT_MAX`.
pub(crate) struct Buffer {
    /// The read buffer, at least `ibuf_size` long (longer after `BIO_set_buffer_read_data`).
    ibuf: Vec<u8>,
    ibuf_size: usize,
    ibuf_off: usize,
    ibuf_len: usize,
    obuf: Vec<u8>,
    obuf_size: usize,
    obuf_off: usize,
    obuf_len: usize,
}

ffi_callback! {
    /// Sets up a buffering filter with 4 KiB buffers each way.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn buffer_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        let (Some(ibuf), Some(obuf)) = (zeroed(DEFAULT_BUFFER_SIZE), zeroed(DEFAULT_BUFFER_SIZE)) else {
            return 0;
        };
        state::install(object, Buffer {
            ibuf,
            ibuf_size: DEFAULT_BUFFER_SIZE,
            ibuf_off: 0,
            ibuf_len: 0,
            obuf,
            obuf_size: DEFAULT_BUFFER_SIZE,
            obuf_off: 0,
            obuf_len: 0,
        });
        object.init.store(1, Ordering::Relaxed);
        object.flags.store(0, Ordering::Relaxed);
        1
    }
}

ffi_callback! {
    /// Frees a buffering filter's buffers; what wasn't flushed is lost.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn buffer_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        drop(state::remove::<Buffer>(object));
        object.init.store(0, Ordering::Relaxed);
        object.flags.store(0, Ordering::Relaxed);
        1
    }
}

ffi_callback! {
    /// Reads from the buffer, refilling it from the next BIO a buffer at a time; a read larger
    /// than the buffer goes to the next BIO directly.
    ///
    /// # Safety
    /// `b` is a live BIO; `out` is null or valid for `outl` bytes of writes.
    pub(crate) unsafe extern "C" fn buffer_read(b: *mut BIO, out: *mut c_char, outl: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if out.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some((object, state, next)) = (unsafe { filter::<Buffer>(b) }) else {
            return 0;
        };
        object.clear_retry_flags();
        let mut out = out.cast::<u8>();
        let mut outl = size(outl);
        let mut num: c_int = 0;
        loop {
            let ibuf = {
                let mut s = lock(&state);
                if s.ibuf_len != 0 {
                    let i = s.ibuf_len.min(outl);
                    let from = s.ibuf.get(s.ibuf_off..s.ibuf_off + i).unwrap_or_default();
                    // SAFETY: `out` has `outl` writable bytes left, and `i` is at most that.
                    unsafe { ptr::copy_nonoverlapping(from.as_ptr(), out, from.len()) };
                    s.ibuf_off += i;
                    s.ibuf_len -= i;
                    num += int(i);
                    if outl == i {
                        return num;
                    }
                    outl -= i;
                    // SAFETY: as above, so `out + i` is inside the caller's buffer.
                    out = unsafe { out.add(i) };
                }
                if outl > s.ibuf_size {
                    None
                } else {
                    let size = s.ibuf_size;
                    Some((core::mem::take(&mut s.ibuf), size))
                }
            };
            let Some((mut ibuf, ibuf_size)) = ibuf else {
                // Larger than the buffer: straight from the next BIO.
                loop {
                    // SAFETY: `out` has `outl` writable bytes left; `next` is live.
                    let i = unsafe { read_next(next, out, outl) };
                    if i <= 0 {
                        super::copy_next_retry(object);
                        return short(num, i);
                    }
                    num += i;
                    let i = size(i);
                    if outl == i {
                        return num;
                    }
                    // SAFETY: as above; the next BIO read at most `outl` bytes.
                    out = unsafe { out.add(i) };
                    outl -= i;
                }
            };
            // The buffer is empty: refill it.
            let len = ibuf_size.min(ibuf.len());
            // SAFETY: the buffer has `len` writable bytes; `next` is live.
            let i = unsafe { read_next(next, ibuf.as_mut_ptr(), len) };
            let mut s = lock(&state);
            if s.ibuf.is_empty() {
                s.ibuf = ibuf;
            }
            if i <= 0 {
                drop(s);
                super::copy_next_retry(object);
                return short(num, i);
            }
            s.ibuf_off = 0;
            s.ibuf_len = size(i);
        }
    }
}

/// Writes the output buffer's contents to the next BIO until they're all written. Returns
/// `Ok` once empty, or what the next BIO's write returned when it wrote nothing.
///
/// # Safety
/// `next` is a live BIO.
unsafe fn drain_obuf(state: &Mutex<Buffer>, next: *mut BIO) -> Result<(), c_int> {
    loop {
        let (obuf, off, len) = {
            let mut s = lock(state);
            (core::mem::take(&mut s.obuf), s.obuf_off, s.obuf_len)
        };
        let data = obuf.get(off..off + len).unwrap_or_default();
        // SAFETY: `data` is valid for its length; `next` is live.
        let i = unsafe { write_next(next, data.as_ptr(), data.len()) };
        let mut s = lock(state);
        if s.obuf.is_empty() {
            s.obuf = obuf;
        }
        if i <= 0 {
            return Err(i);
        }
        let i = size(i).min(s.obuf_len);
        s.obuf_off += i;
        s.obuf_len -= i;
        if s.obuf_len == 0 {
            return Ok(());
        }
    }
}

ffi_callback! {
    /// Adds to the output buffer, writing it to the next BIO when full; writes of a buffer or
    /// more go to the next BIO directly.
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is null or valid for `len` bytes of reads.
    pub(crate) unsafe extern "C" fn buffer_write(b: *mut BIO, data: *const c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if data.is_null() || len <= 0 {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some((object, state, next)) = (unsafe { filter::<Buffer>(b) }) else {
            return 0;
        };
        object.clear_retry_flags();
        let mut input = data.cast::<u8>();
        let mut inl = size(len);
        let mut num: c_int = 0;
        loop {
            let had_output = {
                let mut s = lock(&state);
                let room = s.obuf_size.saturating_sub(s.obuf_len + s.obuf_off);
                let at = s.obuf_off + s.obuf_len;
                if room >= inl {
                    if let Some(to) = s.obuf.get_mut(at..at + inl) {
                        // SAFETY: the caller's buffer has `inl` readable bytes left.
                        unsafe { ptr::copy_nonoverlapping(input, to.as_mut_ptr(), inl) };
                    }
                    s.obuf_len += inl;
                    return num + int(inl);
                }
                if s.obuf_len != 0 && room > 0 {
                    // Fill the buffer, then flush it.
                    if let Some(to) = s.obuf.get_mut(at..at + room) {
                        // SAFETY: `room < inl` bytes of the caller's buffer are readable.
                        unsafe { ptr::copy_nonoverlapping(input, to.as_mut_ptr(), room) };
                    }
                    // SAFETY: as above.
                    input = unsafe { input.add(room) };
                    inl -= room;
                    num += int(room);
                    s.obuf_len += room;
                }
                s.obuf_len != 0
            };
            if had_output {
                // SAFETY: `next` is live.
                if let Err(i) = unsafe { drain_obuf(&state, next) } {
                    super::copy_next_retry(object);
                    return short(num, i);
                }
            }
            let obuf_size = {
                let mut s = lock(&state);
                s.obuf_off = 0;
                s.obuf_size
            };
            // A buffer or more left: straight to the next BIO.
            while inl >= obuf_size {
                // SAFETY: `inl` bytes of the caller's buffer are readable; `next` is live.
                let i = unsafe { write_next(next, input, inl) };
                if i <= 0 {
                    super::copy_next_retry(object);
                    return short(num, i);
                }
                num += i;
                let i = size(i).min(inl);
                // SAFETY: as above.
                input = unsafe { input.add(i) };
                inl -= i;
                if inl == 0 {
                    return num;
                }
            }
        }
    }
}

ffi_callback! {
    /// Writes a string, as `buffer_write`.
    ///
    /// # Safety
    /// `b` is a live BIO; `text` is null or a NUL-terminated string.
    pub(crate) unsafe extern "C" fn buffer_puts(b: *mut BIO, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if text.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let len = unsafe { core::ffi::CStr::from_ptr(text) }.count_bytes();
        // SAFETY: the string is valid for its length.
        unsafe { buffer_write(b, text, int(len)) }
    }
}

ffi_callback! {
    /// Reads a line of at most `size - 1` bytes, with its newline, into `buf`, refilling the
    /// buffer as needed, and ends it with a NUL. With a `size` of 0, OpenSSL refills an empty
    /// buffer, writes a NUL past the caller's zero bytes, and returns the read's failure or
    /// loops forever; this returns the failure without writing, or 0 (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `b` is a live BIO; `buf` is null or valid for `size` bytes of writes.
    pub(crate) unsafe extern "C" fn buffer_gets(b: *mut BIO, buf: *mut c_char, size_: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if buf.is_null() || size_ < 0 {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        let Some(state) = state::get::<Buffer>(object) else {
            return 0;
        };
        // Unlike a read, a missing next BIO isn't checked: reading from it fails with an error.
        let next = object.next();
        object.clear_retry_flags();
        if size_ == 0 {
            let (mut ibuf, ibuf_size) = {
                let mut s = lock(&state);
                if s.ibuf_len > 0 {
                    return 0;
                }
                let size = s.ibuf_size;
                (core::mem::take(&mut s.ibuf), size)
            };
            let len = ibuf_size.min(ibuf.len());
            // SAFETY: the buffer has `len` writable bytes; `next` is null or live.
            let i = unsafe { read_next(next, ibuf.as_mut_ptr(), len) };
            let mut s = lock(&state);
            if s.ibuf.is_empty() {
                s.ibuf = ibuf;
            }
            if i <= 0 {
                drop(s);
                super::copy_next_retry(object);
                return i;
            }
            s.ibuf_len = size(i);
            s.ibuf_off = 0;
            return 0;
        }
        let mut out = buf.cast::<u8>();
        let mut room = size(size_) - 1;
        let mut num: c_int = 0;
        loop {
            let refill = {
                let mut s = lock(&state);
                if s.ibuf_len > 0 {
                    let available = s.ibuf.get(s.ibuf_off..s.ibuf_off + s.ibuf_len).unwrap_or_default();
                    let mut taken = 0;
                    let mut newline = false;
                    for &c in available.iter().take(room) {
                        // SAFETY: `room` bytes before the NUL's place are left in the buffer.
                        unsafe { out.write(c) };
                        // SAFETY: as above.
                        out = unsafe { out.add(1) };
                        taken += 1;
                        if c == b'\n' {
                            newline = true;
                            break;
                        }
                    }
                    num += int(taken);
                    room -= taken;
                    s.ibuf_len -= taken;
                    s.ibuf_off += taken;
                    if newline || room == 0 {
                        // SAFETY: the byte kept for the NUL.
                        unsafe { out.write(0) };
                        return num;
                    }
                    None
                } else {
                    let size = s.ibuf_size;
                    Some((core::mem::take(&mut s.ibuf), size))
                }
            };
            let Some((mut ibuf, ibuf_size)) = refill else {
                continue;
            };
            let len = ibuf_size.min(ibuf.len());
            // SAFETY: the buffer has `len` writable bytes; `next` is live.
            let i = unsafe { read_next(next, ibuf.as_mut_ptr(), len) };
            let mut s = lock(&state);
            if s.ibuf.is_empty() {
                s.ibuf = ibuf;
            }
            if i <= 0 {
                drop(s);
                super::copy_next_retry(object);
                // SAFETY: the byte kept for the NUL is still free.
                unsafe { out.write(0) };
                return short(num, i);
            }
            s.ibuf_len = size(i);
            s.ibuf_off = 0;
        }
    }
}

/// `BIO_set_buffer_size` and its read and write forms (`BIO_C_SET_BUFF_SIZE`): only sizes
/// above the default replace a buffer, which empties it.
fn set_buffer_size(s: &mut Buffer, num: c_long, which: Option<c_int>) -> c_long {
    let wanted = super::wrap_int(num);
    let (ibs, obs) = match which {
        Some(0) => (wanted, int(s.obuf_size)),
        Some(_) => (int(s.ibuf_size), wanted),
        None => (wanted, wanted),
    };
    let default = int(DEFAULT_BUFFER_SIZE);
    // OpenSSL allocates `num` bytes for a new buffer, whatever `ibs` and `obs` became.
    let allocation = usize::try_from(num).ok();
    let new_ibuf = if ibs > default && size(ibs) != s.ibuf_size {
        let Some(bytes) = allocation.and_then(zeroed) else {
            return 0;
        };
        Some(bytes)
    } else {
        None
    };
    let new_obuf = if obs > default && size(obs) != s.obuf_size {
        let Some(bytes) = allocation.and_then(zeroed) else {
            return 0;
        };
        Some(bytes)
    } else {
        None
    };
    if let Some(ibuf) = new_ibuf {
        s.ibuf = ibuf;
        s.ibuf_off = 0;
        s.ibuf_len = 0;
        s.ibuf_size = size(ibs);
    }
    if let Some(obuf) = new_obuf {
        s.obuf = obuf;
        s.obuf_off = 0;
        s.obuf_len = 0;
        s.obuf_size = size(obs);
    }
    1
}

ffi_callback! {
    /// The buffering filter's controls: its buffers' contents and sizes, preloading read data,
    /// flushing, and peeking, with the rest passed to the next BIO.
    ///
    /// # Safety
    /// `b` is a live BIO; `ptr` is what the command expects.
    pub(crate) unsafe extern "C" fn buffer_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        let Some(state) = state::get::<Buffer>(object) else {
            return 0;
        };
        let next = object.next();
        match cmd {
            BIO_CTRL_RESET => {
                {
                    let mut s = lock(&state);
                    s.ibuf_off = 0;
                    s.ibuf_len = 0;
                    s.obuf_off = 0;
                    s.obuf_len = 0;
                }
                if next.is_null() {
                    return 0;
                }
                // SAFETY: the caller's guarantee about `ptr`; `next` is live.
                unsafe { ctrl_next(next, cmd, num, ptr) }
            }
            BIO_CTRL_EOF => {
                if lock(&state).ibuf_len > 0 {
                    return 0;
                }
                // SAFETY: as above.
                unsafe { ctrl_next(next, cmd, num, ptr) }
            }
            BIO_CTRL_INFO => c_long::from(int(lock(&state).obuf_len)),
            BIO_C_GET_BUFF_NUM_LINES => {
                let s = lock(&state);
                let lines = s.ibuf.get(s.ibuf_off..s.ibuf_off + s.ibuf_len).unwrap_or_default();
                c_long::from(int(lines.iter().filter(|c| **c == b'\n').count()))
            }
            BIO_CTRL_WPENDING | BIO_CTRL_PENDING => {
                let pending = {
                    let s = lock(&state);
                    if cmd == BIO_CTRL_WPENDING { s.obuf_len } else { s.ibuf_len }
                };
                if pending != 0 {
                    return c_long::from(int(pending));
                }
                if next.is_null() {
                    return 0;
                }
                // SAFETY: as above.
                unsafe { ctrl_next(next, cmd, num, ptr) }
            }
            BIO_C_SET_BUFF_READ_DATA => {
                // OpenSSL copies `num` bytes from `ptr` without checking either; a negative
                // count or null data is refused instead (docs/DEVIATIONS.md).
                let Ok(len) = usize::try_from(num) else {
                    return 0;
                };
                if ptr.is_null() && len > 0 {
                    return 0;
                }
                let mut s = lock(&state);
                if len > s.ibuf_size {
                    let Some(bytes) = zeroed(len) else {
                        return 0;
                    };
                    // The size stays: reads refill only that much of the larger buffer.
                    s.ibuf = bytes;
                }
                if len > s.ibuf.len() {
                    return 0;
                }
                if let Some(to) = s.ibuf.get_mut(..len) {
                    // SAFETY: the caller's guarantee: `ptr` holds `num` bytes.
                    unsafe { ptr::copy_nonoverlapping(ptr.cast::<u8>(), to.as_mut_ptr(), len) };
                }
                s.ibuf_off = 0;
                s.ibuf_len = len;
                1
            }
            BIO_C_SET_BUFF_SIZE => {
                let which = if ptr.is_null() {
                    None
                } else {
                    // SAFETY: the caller's guarantee: an `int` choosing the buffer.
                    Some(unsafe { ptr.cast::<c_int>().read() })
                };
                set_buffer_size(&mut lock(&state), num, which)
            }
            BIO_C_DO_STATE_MACHINE => {
                if next.is_null() {
                    return 0;
                }
                object.clear_retry_flags();
                // SAFETY: as above.
                let ret = unsafe { ctrl_next(next, cmd, num, ptr) };
                super::copy_next_retry(object);
                ret
            }
            BIO_CTRL_FLUSH => {
                if next.is_null() {
                    return 0;
                }
                if lock(&state).obuf_len > 0 {
                    object.clear_retry_flags();
                    // SAFETY: `next` is live.
                    let drained = unsafe { drain_obuf(&state, next) };
                    super::copy_next_retry(object);
                    if let Err(r) = drained {
                        return c_long::from(r);
                    }
                    object.clear_retry_flags();
                    let mut s = lock(&state);
                    s.obuf_len = 0;
                    s.obuf_off = 0;
                }
                // SAFETY: as above.
                let ret = unsafe { ctrl_next(next, cmd, num, ptr) };
                super::copy_next_retry(object);
                ret
            }
            BIO_CTRL_DUP => {
                let (ibuf_size, obuf_size) = {
                    let s = lock(&state);
                    (int(s.ibuf_size), int(s.obuf_size))
                };
                let copy = ptr.cast::<BIO>();
                // SAFETY: BIO_dup_chain passes the new BIO.
                let read = unsafe { super::BIO_int_ctrl(copy, BIO_C_SET_BUFF_SIZE, c_long::from(ibuf_size), 0) };
                // SAFETY: as above.
                let write = unsafe { super::BIO_int_ctrl(copy, BIO_C_SET_BUFF_SIZE, c_long::from(obuf_size), 1) };
                c_long::from(read > 0 && write > 0)
            }
            BIO_CTRL_PEEK => {
                // Fill the buffer if it's empty, as a read of nothing does.
                let mut fake = 0u8;
                // SAFETY: the caller's guarantee about `b`; a read of 0 bytes writes nothing.
                unsafe { buffer_read(b, (&raw mut fake).cast(), 0) };
                // OpenSSL copies a negative count or to null and crashes; nothing is copied.
                let s = lock(&state);
                let Ok(wanted) = usize::try_from(num) else {
                    return 0;
                };
                let n = wanted.min(s.ibuf_len);
                if ptr.is_null() {
                    return 0;
                }
                let from = s.ibuf.get(s.ibuf_off..s.ibuf_off + n).unwrap_or_default();
                // SAFETY: the caller's guarantee: `ptr` has room for `num` bytes, at least `n`.
                unsafe { ptr::copy_nonoverlapping(from.as_ptr(), ptr.cast::<u8>(), from.len()) };
                c_long::from(int(n))
            }
            _ => {
                if next.is_null() {
                    return 0;
                }
                // SAFETY: as above.
                unsafe { ctrl_next(next, cmd, num, ptr) }
            }
        }
    }
}

ffi_callback! {
    /// Passes `BIO_callback_ctrl` to the next BIO (0 without one).
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn filter_callback_ctrl(b: *mut BIO, cmd: c_int, fp: BIO_info_cb) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let next = unsafe { object(b) }.map_or(ptr::null_mut(), Bio::next);
        if next.is_null() {
            return 0;
        }
        // SAFETY: the next BIO is live.
        unsafe { super::BIO_callback_ctrl(next, cmd, fp) }
    }
}

static BUFFER: Builtin = Builtin::new(BIO_TYPE_BUFFER, c"buffer", || Funcs {
    bputs: Some(buffer_puts),
    bgets: Some(buffer_gets),
    ctrl: Some(buffer_ctrl),
    create: Some(buffer_new),
    destroy: Some(buffer_free),
    callback_ctrl: Some(filter_callback_ctrl),
    ..Funcs::classic(buffer_write, buffer_read)
});

ffi_export! {
    /// Returns the buffering filter's method: reads and writes go through 4 KiB buffers (see
    /// `BIO_set_buffer_size`), and writes reach the next BIO when a buffer fills or on
    /// `BIO_flush`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_f_buffer() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        BUFFER.get()
    }
}

/// The state of a `BIO_f_linebuffer` (OpenSSL's `BIO_LINEBUFFER_CTX`): the buffered output,
/// at most `size` bytes.
pub(crate) struct LineBuffer {
    data: Vec<u8>,
    size: usize,
}

ffi_callback! {
    /// Sets up a line-buffering filter with a 10 KiB buffer.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn linebuffer_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        let mut data = Vec::new();
        if data.try_reserve_exact(DEFAULT_LINEBUFFER_SIZE).is_err() {
            return 0;
        }
        state::install(object, LineBuffer { data, size: DEFAULT_LINEBUFFER_SIZE });
        object.init.store(1, Ordering::Relaxed);
        object.flags.store(0, Ordering::Relaxed);
        1
    }
}

ffi_callback! {
    /// Frees a line-buffering filter's buffer; what wasn't flushed is lost.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn linebuffer_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        drop(state::remove::<LineBuffer>(object));
        object.init.store(0, Ordering::Relaxed);
        object.flags.store(0, Ordering::Relaxed);
        1
    }
}

ffi_callback! {
    /// Reads from the next BIO, unbuffered.
    ///
    /// # Safety
    /// `b` is a live BIO; `out` is null or valid for `outl` bytes of writes.
    pub(crate) unsafe extern "C" fn linebuffer_read(b: *mut BIO, out: *mut c_char, outl: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        let next = object.next();
        if out.is_null() || next.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee; `next` is live.
        let ret = unsafe { super::BIO_read(next, out.cast(), outl) };
        object.clear_retry_flags();
        super::copy_next_retry(object);
        ret
    }
}

/// Writes the first `len` buffered bytes to the next BIO. Returns what the write returned; on
/// success, those bytes are gone from the buffer.
///
/// # Safety
/// `next` is a live BIO.
unsafe fn write_buffered(state: &Mutex<LineBuffer>, next: *mut BIO) -> c_int {
    let data = core::mem::take(&mut lock(state).data);
    // SAFETY: the data is valid for its length; `next` is live.
    let i = unsafe { write_next(next, data.as_ptr(), data.len()) };
    let mut s = lock(state);
    if s.data.is_empty() {
        s.data = data;
    }
    if i > 0 {
        let written = size(i).min(s.data.len());
        s.data.drain(..written);
    }
    i
}

ffi_callback! {
    /// Writes whole lines through to the next BIO, adding them to what's buffered first, and
    /// buffers the text after the last newline. Text longer than the buffer goes through too.
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is null or valid for `len` bytes of reads.
    pub(crate) unsafe extern "C" fn linebuffer_write(b: *mut BIO, data: *const c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if data.is_null() || len <= 0 {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some((object, state, next)) = (unsafe { filter::<LineBuffer>(b) }) else {
            return 0;
        };
        // SAFETY: the caller's guarantee.
        let mut input = unsafe { core::slice::from_raw_parts(data.cast::<u8>(), size(len)) };
        let mut num: c_int = 0;
        object.clear_retry_flags();
        loop {
            // The input up to and including its first newline, or all of it.
            let (mut segment, newline) = match input.iter().position(|c| *c == b'\n') {
                Some(at) => (at + 1, true),
                None => (input.len(), false),
            };
            loop {
                let (buffered, room) = {
                    let s = lock(&state);
                    (s.data.len(), s.size.saturating_sub(s.data.len()))
                };
                if !((newline || segment > room) && buffered > 0) {
                    break;
                }
                // Add what fits of the segment, then write the buffer.
                if segment > 0 {
                    let n = segment.min(room);
                    lock(&state).data.extend_from_slice(input.get(..n).unwrap_or_default());
                    input = input.get(n..).unwrap_or_default();
                    num += int(n);
                    segment -= n;
                }
                // SAFETY: `next` is live.
                let i = unsafe { write_buffered(&state, next) };
                if i <= 0 {
                    // OpenSSL drops what it added to the buffer, though it counted it.
                    lock(&state).data.truncate(buffered);
                    super::copy_next_retry(object);
                    return short(num, i);
                }
            }
            let buffer_size = lock(&state).size;
            if (newline || segment > buffer_size) && segment > 0 {
                // SAFETY: `segment` bytes of the input are readable; `next` is live.
                let i = unsafe { write_next(next, input.as_ptr(), segment) };
                if i <= 0 {
                    super::copy_next_retry(object);
                    return short(num, i);
                }
                num += i;
                input = input.get(size(i)..).unwrap_or_default();
            }
            if !(newline && !input.is_empty()) {
                break;
            }
        }
        // The rest has no newline: buffer it, writing the buffer out to make room.
        while !input.is_empty() {
            let room = {
                let s = lock(&state);
                s.size.saturating_sub(s.data.len())
            };
            if room == 0 {
                // SAFETY: `next` is live.
                let i = unsafe { write_buffered(&state, next) };
                if i <= 0 {
                    super::copy_next_retry(object);
                    return if num > 0 { num } else { i };
                }
                continue;
            }
            let n = room.min(input.len());
            lock(&state).data.extend_from_slice(input.get(..n).unwrap_or_default());
            input = input.get(n..).unwrap_or_default();
            num += int(n);
        }
        num
    }
}

ffi_callback! {
    /// Writes a string, as `linebuffer_write`.
    ///
    /// # Safety
    /// `b` is a live BIO; `text` is null or a NUL-terminated string.
    pub(crate) unsafe extern "C" fn linebuffer_puts(b: *mut BIO, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if text.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let len = unsafe { core::ffi::CStr::from_ptr(text) }.count_bytes();
        // SAFETY: the string is valid for its length.
        unsafe { linebuffer_write(b, text, int(len)) }
    }
}

ffi_callback! {
    /// Reads a line from the next BIO, unbuffered.
    ///
    /// # Safety
    /// `b` is a live BIO; `buf` is valid for `size` bytes of writes.
    pub(crate) unsafe extern "C" fn linebuffer_gets(b: *mut BIO, buf: *mut c_char, size_: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let next = unsafe { object(b) }.map_or(ptr::null_mut(), Bio::next);
        if next.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee; the next BIO is live.
        unsafe { super::gets(next, buf, size_) }
    }
}

ffi_callback! {
    /// The line-buffering filter's controls: the buffered length and size, and flushing, with
    /// the rest passed to the next BIO.
    ///
    /// # Safety
    /// `b` is a live BIO; `ptr` is what the command expects.
    pub(crate) unsafe extern "C" fn linebuffer_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        let Some(state) = state::get::<LineBuffer>(object) else {
            return 0;
        };
        let next = object.next();
        match cmd {
            BIO_CTRL_RESET => {
                lock(&state).data.clear();
                if next.is_null() {
                    return 0;
                }
                // SAFETY: the caller's guarantee about `ptr`; `next` is live.
                unsafe { ctrl_next(next, cmd, num, ptr) }
            }
            BIO_CTRL_INFO => c_long::from(int(lock(&state).data.len())),
            BIO_CTRL_WPENDING => {
                let pending = lock(&state).data.len();
                if pending != 0 {
                    return c_long::from(int(pending));
                }
                if next.is_null() {
                    return 0;
                }
                // SAFETY: as above.
                unsafe { ctrl_next(next, cmd, num, ptr) }
            }
            BIO_C_SET_BUFF_SIZE => {
                if num > c_long::from(c_int::MAX) {
                    return 0;
                }
                let obs = super::wrap_int(num);
                let mut s = lock(&state);
                if obs > int(DEFAULT_LINEBUFFER_SIZE) && size(obs) != s.size {
                    let obs = size(obs);
                    let mut data = Vec::new();
                    if data.try_reserve_exact(obs).is_err() {
                        return 0;
                    }
                    let kept = s.data.len().min(obs);
                    data.extend_from_slice(s.data.get(..kept).unwrap_or_default());
                    s.data = data;
                    s.size = obs;
                }
                1
            }
            BIO_C_DO_STATE_MACHINE => {
                if next.is_null() {
                    return 0;
                }
                object.clear_retry_flags();
                // SAFETY: as above.
                let ret = unsafe { ctrl_next(next, cmd, num, ptr) };
                super::copy_next_retry(object);
                ret
            }
            BIO_CTRL_FLUSH => {
                if next.is_null() {
                    return 0;
                }
                // With nothing buffered, the retry flags are left as they were.
                let mut buffered = !lock(&state).data.is_empty();
                while buffered {
                    object.clear_retry_flags();
                    buffered = !lock(&state).data.is_empty();
                    if !buffered {
                        break;
                    }
                    // SAFETY: `next` is live.
                    let r = unsafe { write_buffered(&state, next) };
                    super::copy_next_retry(object);
                    if r <= 0 {
                        return c_long::from(r);
                    }
                }
                // SAFETY: as above.
                let ret = unsafe { ctrl_next(next, cmd, num, ptr) };
                super::copy_next_retry(object);
                ret
            }
            BIO_CTRL_DUP => {
                let size = int(lock(&state).size);
                // SAFETY: BIO_dup_chain passes the new BIO.
                let ret = unsafe { super::BIO_int_ctrl(ptr.cast(), BIO_C_SET_BUFF_SIZE, c_long::from(size), 1) };
                c_long::from(ret > 0)
            }
            _ => {
                if next.is_null() {
                    return 0;
                }
                // SAFETY: as above.
                unsafe { ctrl_next(next, cmd, num, ptr) }
            }
        }
    }
}

static LINEBUFFER: Builtin = Builtin::new(BIO_TYPE_LINEBUFFER, c"linebuffer", || Funcs {
    bputs: Some(linebuffer_puts),
    bgets: Some(linebuffer_gets),
    ctrl: Some(linebuffer_ctrl),
    create: Some(linebuffer_new),
    destroy: Some(linebuffer_free),
    callback_ctrl: Some(filter_callback_ctrl),
    ..Funcs::classic(linebuffer_write, linebuffer_read)
});

ffi_export! {
    /// Returns the line-buffering filter's method: writes reach the next BIO a line at a time,
    /// and on `BIO_flush`; reads aren't buffered.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_f_linebuffer() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        LINEBUFFER.get()
    }
}

/// The state of a `BIO_f_readbuffer`: everything read so far, from the start (OpenSSL keeps
/// it in a `BIO_F_BUFFER_CTX` too, without the output side).
pub(crate) struct ReadBuffer {
    /// What was read, in a buffer whose length is a multiple of 4 KiB.
    ibuf: Vec<u8>,
    ibuf_off: usize,
    ibuf_len: usize,
}

impl ReadBuffer {
    /// OpenSSL's `readbuffer_resize`: room for `more` bytes after the read position, rounded
    /// up to whole 4 KiB blocks. Fails where OpenSSL's `int` arithmetic would overflow (and
    /// it would then read into too small a buffer, docs/DEVIATIONS.md).
    fn reserve(&mut self, more: usize) -> bool {
        let Some(wanted) = more
            .checked_add(self.ibuf_off)
            .and_then(|n| n.checked_add(DEFAULT_BUFFER_SIZE - 1))
            .filter(|n| c_int::try_from(*n).is_ok())
        else {
            return false;
        };
        let blocks = DEFAULT_BUFFER_SIZE * (wanted / DEFAULT_BUFFER_SIZE);
        if blocks > self.ibuf.len() {
            if self
                .ibuf
                .try_reserve_exact(blocks - self.ibuf.len())
                .is_err()
            {
                return false;
            }
            self.ibuf.resize(blocks, 0);
        }
        true
    }
}

ffi_callback! {
    /// Sets up a read-buffering filter.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn readbuffer_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        let Some(ibuf) = zeroed(DEFAULT_BUFFER_SIZE) else {
            return 0;
        };
        state::install(object, ReadBuffer { ibuf, ibuf_off: 0, ibuf_len: 0 });
        object.init.store(1, Ordering::Relaxed);
        object.flags.store(0, Ordering::Relaxed);
        1
    }
}

ffi_callback! {
    /// Frees a read-buffering filter's buffer.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn readbuffer_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        drop(state::remove::<ReadBuffer>(object));
        object.init.store(0, Ordering::Relaxed);
        object.flags.store(0, Ordering::Relaxed);
        1
    }
}

/// Reads up to `len` bytes from `next` into the buffer at the read position, as `BIO_read`.
///
/// # Safety
/// `next` is a live BIO; the buffer has room for `len` bytes there ([`ReadBuffer::reserve`]).
unsafe fn read_into(state: &Mutex<ReadBuffer>, next: *mut BIO, len: usize) -> c_int {
    let (mut ibuf, off) = {
        let mut s = lock(state);
        (core::mem::take(&mut s.ibuf), s.ibuf_off)
    };
    let i = match ibuf.get_mut(off..off + len) {
        // SAFETY: the slice is writable for its length; `next` is live.
        Some(to) => unsafe { read_next(next, to.as_mut_ptr(), len) },
        None => 0,
    };
    let mut s = lock(state);
    if s.ibuf.is_empty() {
        s.ibuf = ibuf;
    }
    i
}

ffi_callback! {
    /// Reads what's buffered after the read position, then reads more from the next BIO into
    /// the buffer, which keeps it.
    ///
    /// # Safety
    /// `b` is a live BIO; `out` is null or valid for `outl` bytes of writes.
    pub(crate) unsafe extern "C" fn readbuffer_read(b: *mut BIO, out: *mut c_char, outl: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if out.is_null() || outl == 0 {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some((object, state, next)) = (unsafe { filter::<ReadBuffer>(b) }) else {
            return 0;
        };
        object.clear_retry_flags();
        let mut out = out.cast::<u8>();
        let mut outl = size(outl);
        let mut num: c_int = 0;
        loop {
            {
                let mut s = lock(&state);
                if s.ibuf_len != 0 {
                    let i = s.ibuf_len.min(outl);
                    let from = s.ibuf.get(s.ibuf_off..s.ibuf_off + i).unwrap_or_default();
                    // SAFETY: `out` has `outl` writable bytes left, and `i` is at most that.
                    unsafe { ptr::copy_nonoverlapping(from.as_ptr(), out, from.len()) };
                    s.ibuf_off += i;
                    s.ibuf_len -= i;
                    num += int(i);
                    if outl == i {
                        return num;
                    }
                    outl -= i;
                    // SAFETY: as above.
                    out = unsafe { out.add(i) };
                }
                if !s.reserve(outl) {
                    return 0;
                }
            }
            // SAFETY: `next` is live; the buffer has room for `outl` bytes.
            let i = unsafe { read_into(&state, next, outl) };
            if i <= 0 {
                super::copy_next_retry(object);
                return short(num, i);
            }
            lock(&state).ibuf_len = size(i);
        }
    }
}

ffi_callback! {
    /// The read-buffering filter can't be written to: writes return 0.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn readbuffer_write(b: *mut BIO, data: *const c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let _ = (b, data, len);
        0
    }
}

ffi_callback! {
    /// The read-buffering filter can't be written to: puts returns 0.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn readbuffer_puts(b: *mut BIO, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let _ = (b, text);
        0
    }
}

ffi_callback! {
    /// Reads a line, from what's buffered and then from the next BIO a byte at a time (so as
    /// not to read past the line from a source that can't give bytes back).
    ///
    /// # Safety
    /// `b` is a live BIO; `buf` is null or valid for `size` bytes of writes.
    pub(crate) unsafe extern "C" fn readbuffer_gets(b: *mut BIO, buf: *mut c_char, size_: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if buf.is_null() || size_ <= 0 {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some((object, state, next)) = (unsafe { filter::<ReadBuffer>(b) }) else {
            return 0;
        };
        let mut room = size(size_) - 1;
        let mut out = buf.cast::<u8>();
        let mut num: c_int = 0;
        object.clear_retry_flags();
        {
            let mut s = lock(&state);
            if s.ibuf_len > 0 {
                let available = s.ibuf.get(s.ibuf_off..s.ibuf_off + s.ibuf_len).unwrap_or_default();
                let mut taken = 0;
                let mut newline = false;
                for &c in available.iter().take(room) {
                    // SAFETY: `room` bytes before the NUL's place are left in the buffer.
                    unsafe { out.write(c) };
                    // SAFETY: as above.
                    out = unsafe { out.add(1) };
                    taken += 1;
                    if c == b'\n' {
                        newline = true;
                        break;
                    }
                }
                num += int(taken);
                room -= taken;
                s.ibuf_len -= taken;
                s.ibuf_off += taken;
                if newline || room == 0 {
                    // SAFETY: the byte kept for the NUL.
                    unsafe { out.write(0) };
                    return num;
                }
            }
            if !s.reserve(1 + room) {
                return 0;
            }
        }
        for _ in 0..room {
            // SAFETY: `next` is live; the buffer has room for the line.
            let j = unsafe { read_into(&state, next, 1) };
            if j <= 0 {
                super::copy_next_retry(object);
                // SAFETY: the byte kept for the NUL is still free.
                unsafe { out.write(0) };
                return if num > 0 { num } else { j };
            }
            let c = {
                let mut s = lock(&state);
                let c = s.ibuf.get(s.ibuf_off).copied().unwrap_or(0);
                s.ibuf_off += 1;
                c
            };
            // SAFETY: fewer than `room` bytes written, so this one fits.
            unsafe { out.write(c) };
            // SAFETY: as above.
            out = unsafe { out.add(1) };
            num += 1;
            if c == b'\n' {
                break;
            }
        }
        // SAFETY: the byte kept for the NUL.
        unsafe { out.write(0) };
        num
    }
}

ffi_callback! {
    /// The read-buffering filter's controls: seeking back within what was read, the read
    /// position, and what's pending; other controls aren't passed on and return 0.
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn readbuffer_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        let Some(state) = state::get::<ReadBuffer>(object) else {
            return 0;
        };
        let next = object.next();
        match cmd {
            BIO_CTRL_EOF => {
                if lock(&state).ibuf_len > 0 {
                    return 0;
                }
                if next.is_null() {
                    return 1;
                }
                // SAFETY: the caller's guarantee about `ptr`; `next` is live.
                unsafe { ctrl_next(next, cmd, num, ptr) }
            }
            BIO_C_FILE_SEEK | BIO_CTRL_RESET => {
                let mut s = lock(&state);
                let end = s.ibuf_off + s.ibuf_len;
                // Only backwards, within what was read.
                let Some(to) = usize::try_from(num).ok().filter(|to| *to <= end) else {
                    return 0;
                };
                s.ibuf_off = to;
                s.ibuf_len = end - to;
                1
            }
            BIO_C_FILE_TELL | BIO_CTRL_INFO => c_long::from(int(lock(&state).ibuf_off)),
            BIO_CTRL_PENDING => {
                let pending = lock(&state).ibuf_len;
                if pending != 0 {
                    return c_long::from(int(pending));
                }
                if next.is_null() {
                    return 0;
                }
                // SAFETY: as above.
                unsafe { ctrl_next(next, cmd, num, ptr) }
            }
            BIO_CTRL_DUP | BIO_CTRL_FLUSH => 1,
            _ => 0,
        }
    }
}

static READBUFFER: Builtin = Builtin::new(BIO_TYPE_BUFFER, c"readbuffer", || Funcs {
    bputs: Some(readbuffer_puts),
    bgets: Some(readbuffer_gets),
    ctrl: Some(readbuffer_ctrl),
    create: Some(readbuffer_new),
    destroy: Some(readbuffer_free),
    callback_ctrl: Some(filter_callback_ctrl),
    ..Funcs::classic(readbuffer_write, readbuffer_read)
});

ffi_export! {
    /// Returns the read-buffering filter's method, which keeps everything it reads so that
    /// `BIO_seek` and `BIO_tell` work within it; it can't be written to.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_f_readbuffer() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        READBUFFER.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bio::{BIO_free_all, BIO_gets, BIO_new, BIO_push, BIO_read, BIO_write, mem};

    /// A buffer filter in front of a memory BIO holding `text`.
    fn filter_over(method: *const BIO_METHOD, text: &CStr) -> *mut BIO {
        // SAFETY: a built-in method, then a string that outlives the BIO.
        let f = unsafe { BIO_new(method) };
        // SAFETY: as above.
        let source = unsafe { mem::BIO_new_mem_buf(text.as_ptr().cast(), -1) };
        // SAFETY: live BIOs.
        unsafe { BIO_push(f, source) }
    }

    use core::ffi::CStr;

    /// docs/DEVIATIONS.md: OpenSSL loops forever, or writes past a zero-size buffer.
    #[test]
    fn gets_of_size_zero_doesnt_loop_or_write() {
        let f = filter_over(BUFFER.get(), c"abc");
        let mut buf = [b'#'; 2];
        // SAFETY: a live BIO; a size of 0 writes nothing.
        let first = unsafe { BIO_gets(f, buf.as_mut_ptr().cast(), 0) };
        // SAFETY: as above, now with data buffered.
        let second = unsafe { BIO_gets(f, buf.as_mut_ptr().cast(), 0) };
        assert_eq!((first, second, buf), (0, 0, [b'#'; 2]));
        // SAFETY: a live chain.
        unsafe { BIO_free_all(f) };
    }

    /// docs/DEVIATIONS.md: OpenSSL copies a negative count, or from or to null.
    #[test]
    fn bad_read_data_and_peeks_are_refused() {
        let f = filter_over(BUFFER.get(), c"abc");
        let mut buf = [0u8; 4];
        let at = buf.as_mut_ptr().cast::<c_void>();
        let calls = [
            (BIO_C_SET_BUFF_READ_DATA, -1, at),
            (BIO_C_SET_BUFF_READ_DATA, 3, ptr::null_mut()),
            (BIO_CTRL_PEEK, -1, at),
            (BIO_CTRL_PEEK, 3, ptr::null_mut()),
        ];
        for (cmd, num, arg) in calls {
            // SAFETY: a live BIO; the refused arguments are never used.
            assert_eq!(unsafe { crate::bio::BIO_ctrl(f, cmd, num, arg) }, 0);
        }
        // SAFETY: a live chain.
        unsafe { BIO_free_all(f) };
    }

    /// docs/DEVIATIONS.md: OpenSSL's `int` arithmetic overflows and it reads into too small a
    /// buffer.
    #[test]
    fn reads_past_int_max_are_refused() {
        let f = filter_over(READBUFFER.get(), c"abc");
        let mut buf = [0u8; 4];
        // SAFETY: a live BIO; the refused read writes nothing.
        let ret = unsafe { BIO_read(f, buf.as_mut_ptr().cast(), c_int::MAX) };
        assert_eq!(ret, 0);
        // SAFETY: a live chain.
        unsafe { BIO_free_all(f) };
    }

    ffi_callback! {
        /// A create function that isn't the buffer filter's, with a `ptr` that isn't its state.
        ///
        /// # Safety
        /// `b` is a live BIO.
        pub(crate) unsafe extern "C" fn foreign_create(b: *mut BIO) -> c_int
        where failure = 0, library = ERR_LIB_BIO
        {
            static NOT_STATE: u64 = 0;
            // SAFETY: the caller's guarantee.
            if let Some(object) = unsafe { object(b) } {
                object.ptr.store(ptr::from_ref(&NOT_STATE).cast_mut().cast(), Ordering::Relaxed);
                object.init.store(1, Ordering::Relaxed);
            }
            1
        }
    }

    /// An application's method built from the buffer filter's functions with its own create
    /// function: the filter's functions don't take its `ptr` for their state.
    #[test]
    fn functions_in_a_method_with_another_create_do_nothing() {
        // SAFETY: a name.
        let method = unsafe { crate::bio::method::BIO_meth_new(0x7f, c"mixed".as_ptr()) };
        // SAFETY: a live method, for each call.
        unsafe { crate::bio::method::BIO_meth_set_write(method, Some(buffer_write)) };
        // SAFETY: as above.
        unsafe { crate::bio::method::BIO_meth_set_create(method, Some(foreign_create)) };
        // SAFETY: as above.
        let b = unsafe { BIO_new(method) };
        // SAFETY: a live BIO and 3 readable bytes.
        assert_eq!(unsafe { BIO_write(b, c"abc".as_ptr().cast(), 3) }, 0);
        // SAFETY: a live BIO, then its method, freed once each.
        unsafe { BIO_free_all(b) };
        // SAFETY: as above.
        unsafe { crate::bio::method::BIO_meth_free(method) };
    }
}
