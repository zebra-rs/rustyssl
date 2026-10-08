//! BIO pairs (`BIO_s_bio(3)`, `BIO_new_bio_pair(3)`): two source/sink BIOs joined so that what
//! is written to one is read from the other, through a ring buffer on each side. A port of
//! OpenSSL's `bss_bio.c`, including the non-copying `BIO_nread` and `BIO_nwrite`, which hand
//! out pointers into the ring buffers; those stay in place until the pair is freed.
//!
//! Each end's state is its own (what it writes); a read takes from the peer's. Each end holds
//! a reference to its peer, BIO and state, which `BIO_destroy_bio_pair` or freeing either end
//! drops, so a misused pair never reaches freed memory. Only one end's state is locked at a
//! time. OpenSSL documents a pair as used by one thread; two threads on the two ends are at
//! least memory-safe here.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr::{self, NonNull};
use core::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use rustyssl_abi::{
    BIO, BIO_C_DESTROY_BIO_PAIR, BIO_C_GET_READ_REQUEST, BIO_C_GET_WRITE_BUF_SIZE,
    BIO_C_GET_WRITE_GUARANTEE, BIO_C_MAKE_BIO_PAIR, BIO_C_NREAD, BIO_C_NREAD0, BIO_C_NWRITE,
    BIO_C_NWRITE0, BIO_C_RESET_READ_REQUEST, BIO_C_SET_WRITE_BUF_SIZE, BIO_C_SHUTDOWN_WR,
    BIO_CTRL_DUP, BIO_CTRL_EOF, BIO_CTRL_FLUSH, BIO_CTRL_GET_CLOSE, BIO_CTRL_PENDING,
    BIO_CTRL_RESET, BIO_CTRL_SET_CLOSE, BIO_CTRL_WPENDING, BIO_METHOD, BIO_R_BROKEN_PIPE,
    BIO_R_IN_USE, BIO_R_INVALID_ARGUMENT, BIO_R_UNINITIALIZED, BIO_TYPE_BIO, ERR_LIB_BIO,
};

use super::method::{Builtin, Funcs};
use super::state::{self, lock};
use super::{Bio, object};
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::handle::{Handle, Held};
use crate::mem;

/// The default ring buffer size: one TLS record.
const DEFAULT_SIZE: usize = 17 * 1024;

/// A ring buffer in C memory, so that `BIO_nread` and `BIO_nwrite` can hand out pointers into
/// it, which stay valid until it's freed.
struct Ring(NonNull<u8>);

// SAFETY: the ring is plain bytes, accessed under its end's lock (or by the application
// through pointers OpenSSL's contract lets it use).
unsafe impl Send for Ring {}

impl Ring {
    fn new(size: usize) -> Option<Self> {
        NonNull::new(mem::alloc(size).cast::<u8>()).map(Self)
    }

    fn at(&self, offset: usize) -> *mut u8 {
        self.0.as_ptr().wrapping_add(offset)
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        // SAFETY: allocated by `mem::alloc`, freed once here.
        unsafe { mem::release(self.0.as_ptr().cast()) };
    }
}

/// The other end of a pair.
struct Peer {
    bio: Held<BIO>,
    state: Arc<Mutex<End>>,
}

/// One end of a pair (OpenSSL's `struct bio_bio_st`): what it writes, for its peer to read.
pub(crate) struct End {
    peer: Option<Peer>,
    /// Writes were shut down (`BIO_shutdown_wr`).
    closed: bool,
    /// Bytes waiting, from `offset` on, wrapping at `size`.
    len: usize,
    offset: usize,
    size: usize,
    /// Allocated when the pair is made.
    buf: Option<Ring>,
    /// How much the peer last tried to read from an empty buffer.
    request: usize,
}

/// A `long` as C converts it to `size_t`.
fn size_t(value: c_long) -> usize {
    usize::from_ne_bytes(value.to_ne_bytes())
}

/// A `size_t` as C converts it to `long`.
fn long(value: usize) -> c_long {
    c_long::from_ne_bytes(value.to_ne_bytes())
}

/// An `ossl_ssize_t` result as a `long`.
fn ssize(value: isize) -> c_long {
    c_long::try_from(value).unwrap_or(c_long::MAX)
}

/// The end `b` and its state, if it's a pair BIO.
///
/// # Safety
/// `b` is null or a live BIO that outlives `'a`.
unsafe fn end<'a>(b: *mut BIO) -> Option<(&'a Bio, Arc<Mutex<End>>)> {
    // SAFETY: the caller's guarantee.
    let object = unsafe { object(b) }?;
    let state = state::get::<End>(object)?;
    Some((object, state))
}

/// The peer's state, if `b` is paired.
fn peer_of(state: &Mutex<End>) -> Option<Arc<Mutex<End>>> {
    lock(state).peer.as_ref().map(|p| Arc::clone(&p.state))
}

ffi_callback! {
    /// Sets up an unpaired end with the default buffer size.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn pair_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        state::install(object, End {
            peer: None,
            closed: false,
            len: 0,
            offset: 0,
            size: DEFAULT_SIZE,
            buf: None,
            request: 0,
        });
        1
    }
}

ffi_callback! {
    /// Frees an end, unpairing both ends first.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn pair_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        if let Some(state) = state::get::<End>(object) {
            destroy_pair(object, &state);
        }
        drop(state::remove::<End>(object));
        1
    }
}

/// OpenSSL's `bio_destroy_pair`: unpairs both ends, emptying their buffers and marking both
/// uninitialized.
fn destroy_pair(object: &Bio, state: &Mutex<End>) {
    let Some(peer) = lock(state).peer.take() else {
        return;
    };
    {
        let mut p = lock(&peer.state);
        // Drops the peer's references to this end.
        p.peer = None;
        p.len = 0;
        p.offset = 0;
    }
    peer.bio.init.store(0, Ordering::Relaxed);
    {
        let mut s = lock(state);
        s.len = 0;
        s.offset = 0;
    }
    object.init.store(0, Ordering::Relaxed);
}

/// OpenSSL's `bio_make_pair`: joins two unpaired ends, allocating their buffers. Fails if
/// either isn't a pair BIO (OpenSSL's would misread or crash, docs/DEVIATIONS.md) or is
/// paired.
///
/// # Safety
/// `b1` and `b2` are null or live BIOs.
unsafe fn make_pair(b1: *mut BIO, b2: *mut BIO) -> bool {
    // SAFETY: the caller's guarantee, for each.
    let (Some((o1, s1)), Some((o2, s2))) = (unsafe { end(b1) }, unsafe { end(b2) }) else {
        return false;
    };
    if lock(&s1).peer.is_some() || lock(&s2).peer.is_some() {
        err::raise(ERR_LIB_BIO, BIO_R_IN_USE, "bio_make_pair");
        return false;
    }
    for s in [&s1, &s2] {
        let mut end = lock(s);
        if end.buf.is_none() {
            let Some(ring) = Ring::new(end.size) else {
                return false;
            };
            end.buf = Some(ring);
            end.len = 0;
            end.offset = 0;
        }
    }
    // SAFETY: both are live BIOs (checked above).
    let (Some(h1), Some(h2)) = (unsafe { BIO::hold(b1) }, unsafe { BIO::hold(b2) }) else {
        return false;
    };
    {
        let mut e1 = lock(&s1);
        e1.peer = Some(Peer {
            bio: h2,
            state: Arc::clone(&s2),
        });
        e1.closed = false;
        e1.request = 0;
    }
    {
        let mut e2 = lock(&s2);
        e2.peer = Some(Peer {
            bio: h1,
            state: Arc::clone(&s1),
        });
        e2.closed = false;
        e2.request = 0;
    }
    o1.init.store(1, Ordering::Relaxed);
    o2.init.store(1, Ordering::Relaxed);
    true
}

/// Copies `len` bytes out of a ring buffer from `offset`, wrapping at `size`.
///
/// # Safety
/// `out` is valid for `len` bytes of writes; `len <= size` and `offset < size`.
unsafe fn copy_out(ring: &Ring, size: usize, offset: usize, out: *mut u8, len: usize) {
    let first = len.min(size - offset);
    // SAFETY: the caller's guarantee; the ring has `size` bytes.
    unsafe { ptr::copy_nonoverlapping(ring.at(offset), out, first) };
    // SAFETY: as above; the rest is at the ring's start.
    unsafe { ptr::copy_nonoverlapping(ring.at(0), out.wrapping_add(first), len - first) };
}

ffi_callback! {
    /// Reads what the peer wrote. With nothing there, returns 0 if the peer shut down writes,
    /// else -1 with a read retry, recording the request for `BIO_get_read_request`.
    ///
    /// # Safety
    /// `b` is a live BIO; `buf` is null or valid for `size` bytes of writes.
    pub(crate) unsafe extern "C" fn pair_read(b: *mut BIO, buf: *mut c_char, size: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { end(b) }) else {
            return 0;
        };
        object.clear_retry_flags();
        if object.init.load(Ordering::Relaxed) == 0 {
            return 0;
        }
        let Some(peer) = peer_of(&state) else {
            return 0;
        };
        let size = size_t(c_long::from(size));
        let mut p = lock(&peer);
        p.request = 0;
        if buf.is_null() || size == 0 {
            return 0;
        }
        if p.len == 0 {
            if p.closed {
                return 0;
            }
            object.set_retry_read();
            p.request = size.min(p.size);
            return -1;
        }
        let n = size.min(p.len);
        let Some(ring) = p.buf.as_ref() else {
            return 0;
        };
        // SAFETY: `buf` has `size` bytes, at least `n`; `n <= len <= size`, `offset < size`.
        unsafe { copy_out(ring, p.size, p.offset, buf.cast(), n) };
        p.len -= n;
        p.offset = if p.len == 0 { 0 } else { (p.offset + n) % p.size };
        c_int::try_from(n).unwrap_or(c_int::MAX)
    }
}

/// OpenSSL's `bio_nread0`: how many bytes can be read in one piece, with `*buf` pointing to
/// them; with nothing there, what a 1-byte read returns.
///
/// # Safety
/// `b` is a live BIO; `buf` is null or valid for a write.
unsafe fn nread0(b: *mut BIO, buf: *mut *mut c_char) -> isize {
    // SAFETY: the caller's guarantee.
    let Some((object, state)) = (unsafe { end(b) }) else {
        return 0;
    };
    object.clear_retry_flags();
    if object.init.load(Ordering::Relaxed) == 0 {
        return 0;
    }
    let Some(peer) = peer_of(&state) else {
        return 0;
    };
    {
        let mut p = lock(&peer);
        p.request = 0;
        if p.len != 0 {
            let num = p.len.min(p.size - p.offset);
            if !buf.is_null() {
                let at = p.buf.as_ref().map_or(ptr::null_mut(), |r| r.at(p.offset));
                // SAFETY: the caller's guarantee.
                unsafe { buf.write(at.cast()) };
            }
            return isize::try_from(num).unwrap_or(isize::MAX);
        }
    }
    let mut dummy: c_char = 0;
    // SAFETY: as above; a 1-byte buffer.
    let ret = unsafe { pair_read(b, &raw mut dummy, 1) };
    isize::try_from(ret).unwrap_or(-1)
}

/// OpenSSL's `bio_nread`: [`nread0`], then consumes up to `num` of those bytes.
///
/// # Safety
/// As for [`nread0`].
unsafe fn nread(b: *mut BIO, buf: *mut *mut c_char, num: usize) -> isize {
    let wanted = isize::try_from(num).unwrap_or(isize::MAX);
    // SAFETY: the caller's guarantee.
    let num = wanted.min(unsafe { nread0(b, buf) });
    let Ok(n) = usize::try_from(num) else {
        return num;
    };
    if n == 0 {
        return 0;
    }
    // SAFETY: as above.
    let Some(peer) = (unsafe { end(b) }).and_then(|(_, s)| peer_of(&s)) else {
        return 0;
    };
    let mut p = lock(&peer);
    let n = n.min(p.len);
    p.len -= n;
    p.offset = if p.len == 0 {
        0
    } else {
        (p.offset + n) % p.size
    };
    num
}

ffi_callback! {
    /// Writes into this end's buffer for the peer, as much as fits. Fails with
    /// `BIO_R_BROKEN_PIPE` after `BIO_shutdown_wr`, and with -1 and a write retry when full.
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is null or valid for `len` bytes of reads.
    pub(crate) unsafe extern "C" fn pair_write(b: *mut BIO, data: *const c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { end(b) }) else {
            return 0;
        };
        object.clear_retry_flags();
        if object.init.load(Ordering::Relaxed) == 0 || data.is_null() || len <= 0 {
            return 0;
        }
        let mut s = lock(&state);
        if s.peer.is_none() {
            return 0;
        }
        s.request = 0;
        if s.closed {
            drop(s);
            err::raise(ERR_LIB_BIO, BIO_R_BROKEN_PIPE, "bio_write");
            return -1;
        }
        if s.len == s.size {
            drop(s);
            object.set_retry_write();
            return -1;
        }
        let n = usize::try_from(len).unwrap_or(0).min(s.size - s.len);
        let Some(ring) = s.buf.as_ref() else {
            return 0;
        };
        let start = (s.offset + s.len) % s.size;
        let first = n.min(s.size - start);
        // SAFETY: the caller's buffer has `len` bytes, at least `n`; the ring has `size`, and
        // `n` fits in its free space, wrapping once.
        unsafe { ptr::copy_nonoverlapping(data.cast::<u8>(), ring.at(start), first) };
        // SAFETY: as above.
        unsafe { ptr::copy_nonoverlapping(data.cast::<u8>().wrapping_add(first), ring.at(0), n - first) };
        s.len += n;
        c_int::try_from(n).unwrap_or(c_int::MAX)
    }
}

/// OpenSSL's `bio_nwrite0`: how many bytes can be written in one piece, with `*buf` pointing
/// to where.
///
/// # Safety
/// `b` is a live BIO; `buf` is null or valid for a write.
unsafe fn nwrite0(b: *mut BIO, buf: *mut *mut c_char) -> isize {
    // SAFETY: the caller's guarantee.
    let Some((object, state)) = (unsafe { end(b) }) else {
        return 0;
    };
    object.clear_retry_flags();
    if object.init.load(Ordering::Relaxed) == 0 {
        return 0;
    }
    let mut s = lock(&state);
    if s.peer.is_none() {
        return 0;
    }
    s.request = 0;
    if s.closed {
        drop(s);
        err::raise(ERR_LIB_BIO, BIO_R_BROKEN_PIPE, "bio_nwrite0");
        return -1;
    }
    if s.len == s.size {
        drop(s);
        object.set_retry_write();
        return -1;
    }
    let start = (s.offset + s.len) % s.size;
    let num = (s.size - s.len).min(s.size - start);
    if !buf.is_null() {
        let at = s.buf.as_ref().map_or(ptr::null_mut(), |r| r.at(start));
        // SAFETY: the caller's guarantee.
        unsafe { buf.write(at.cast()) };
    }
    isize::try_from(num).unwrap_or(isize::MAX)
}

/// OpenSSL's `bio_nwrite`: [`nwrite0`], then adds up to `num` bytes the caller wrote there.
///
/// # Safety
/// As for [`nwrite0`].
unsafe fn nwrite(b: *mut BIO, buf: *mut *mut c_char, num: usize) -> isize {
    let wanted = isize::try_from(num).unwrap_or(isize::MAX);
    // SAFETY: the caller's guarantee.
    let num = wanted.min(unsafe { nwrite0(b, buf) });
    let Ok(n) = usize::try_from(num) else {
        return num;
    };
    if n == 0 {
        return 0;
    }
    // SAFETY: as above.
    let Some((_, state)) = (unsafe { end(b) }) else {
        return 0;
    };
    let mut s = lock(&state);
    s.len = (s.len + n).min(s.size);
    num
}

ffi_callback! {
    /// The pair's controls: buffer sizes, pairing and unpairing, the write guarantee and read
    /// request, shutting down writes, the non-copying reads and writes, and the standard
    /// controls.
    ///
    /// # Safety
    /// `b` is a live BIO; `ptr` is what the command expects.
    pub(crate) unsafe extern "C" fn pair_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { end(b) }) else {
            return 0;
        };
        match cmd {
            BIO_C_SET_WRITE_BUF_SIZE => {
                let mut s = lock(&state);
                if s.peer.is_some() {
                    drop(s);
                    err::raise(ERR_LIB_BIO, BIO_R_IN_USE, "bio_ctrl");
                    0
                } else if num == 0 {
                    drop(s);
                    err::raise(ERR_LIB_BIO, BIO_R_INVALID_ARGUMENT, "bio_ctrl");
                    0
                } else {
                    let size = size_t(num);
                    if s.size != size {
                        s.buf = None;
                        s.size = size;
                    }
                    1
                }
            }
            BIO_C_GET_WRITE_BUF_SIZE => long(lock(&state).size),
            // SAFETY: the caller's guarantee: `ptr` is the other BIO.
            BIO_C_MAKE_BIO_PAIR => c_long::from(unsafe { make_pair(b, ptr.cast()) }),
            BIO_C_DESTROY_BIO_PAIR => {
                destroy_pair(object, &state);
                1
            }
            BIO_C_GET_WRITE_GUARANTEE => {
                let s = lock(&state);
                if s.peer.is_none() || s.closed {
                    0
                } else {
                    long(s.size.wrapping_sub(s.len))
                }
            }
            BIO_C_GET_READ_REQUEST => long(lock(&state).request),
            BIO_C_RESET_READ_REQUEST => {
                lock(&state).request = 0;
                1
            }
            BIO_C_SHUTDOWN_WR => {
                lock(&state).closed = true;
                1
            }
            // SAFETY: the caller's guarantee: `ptr` is null or a `char **`, for each below.
            BIO_C_NREAD0 => ssize(unsafe { nread0(b, ptr.cast()) }),
            // SAFETY: as above.
            BIO_C_NREAD => ssize(unsafe { nread(b, ptr.cast(), size_t(num)) }),
            // SAFETY: as above.
            BIO_C_NWRITE0 => ssize(unsafe { nwrite0(b, ptr.cast()) }),
            // SAFETY: as above.
            BIO_C_NWRITE => ssize(unsafe { nwrite(b, ptr.cast(), size_t(num)) }),
            BIO_CTRL_RESET => {
                let mut s = lock(&state);
                if s.buf.is_some() {
                    s.len = 0;
                    s.offset = 0;
                }
                0
            }
            BIO_CTRL_GET_CLOSE => c_long::from(object.shutdown.load(Ordering::Relaxed)),
            BIO_CTRL_SET_CLOSE => {
                object.shutdown.store(super::wrap_int(num), Ordering::Relaxed);
                1
            }
            BIO_CTRL_PENDING => peer_of(&state).map_or(0, |p| long(lock(&p).len)),
            BIO_CTRL_WPENDING => {
                let s = lock(&state);
                if s.buf.is_some() { long(s.len) } else { 0 }
            }
            BIO_CTRL_DUP => {
                let size = lock(&state).size;
                // SAFETY: BIO_dup_chain passes the new BIO, a fresh pair BIO.
                let Some((_, other)) = (unsafe { end(ptr.cast()) }) else {
                    return 0;
                };
                lock(&other).size = size;
                1
            }
            BIO_CTRL_FLUSH => 1,
            BIO_CTRL_EOF => peer_of(&state).map_or(1, |p| {
                let p = lock(&p);
                c_long::from(p.len == 0 && p.closed)
            }),
            _ => 0,
        }
    }
}

ffi_callback! {
    /// Writes a string, as `pair_write`.
    ///
    /// # Safety
    /// `b` is a live BIO; `text` is null or a NUL-terminated string.
    pub(crate) unsafe extern "C" fn pair_puts(b: *mut BIO, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if text.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let len = unsafe { CStr::from_ptr(text) }.count_bytes();
        let len = super::wrap_int(c_long::try_from(len).unwrap_or(c_long::MAX));
        // SAFETY: the string is valid for its length.
        unsafe { pair_write(b, text, len) }
    }
}

static PAIR: Builtin = Builtin::new(BIO_TYPE_BIO, c"BIO pair", || Funcs {
    bputs: Some(pair_puts),
    ctrl: Some(pair_ctrl),
    create: Some(pair_new),
    destroy: Some(pair_free),
    ..Funcs::classic(pair_write, pair_read)
});

ffi_export! {
    /// Returns the method of one end of a BIO pair; join two with `BIO_make_bio_pair`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_s_bio() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        PAIR.get()
    }
}

ffi_export! {
    /// Makes a joined pair, with write buffers of the given sizes (0 for the default, 17 KiB).
    /// Returns 1, with the ends in `*bio1_p` and `*bio2_p`, or 0 with both null. Null
    /// out-pointers return 0 (OpenSSL's would crash).
    ///
    /// # Safety
    /// `bio1_p` and `bio2_p` are null or valid for a write.
    pub unsafe extern "C" fn BIO_new_bio_pair(bio1_p: *mut *mut BIO, writebuf1: usize, bio2_p: *mut *mut BIO, writebuf2: usize) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        if bio1_p.is_null() || bio2_p.is_null() {
            return 0;
        }
        let method = PAIR.get();
        // SAFETY: the built-in method.
        let mut bio1 = unsafe { super::BIO_new(method) };
        // SAFETY: as above.
        let mut bio2 = unsafe { super::BIO_new(method) };
        let set_size = |bio: *mut BIO, size: usize| {
            // SAFETY: `bio` is a fresh pair BIO.
            size == 0 || super::wrap_int(unsafe { super::BIO_ctrl(bio, BIO_C_SET_WRITE_BUF_SIZE, long(size), ptr::null_mut()) }) != 0
        };
        let ok = !bio1.is_null()
            && !bio2.is_null()
            && set_size(bio1, writebuf1)
            && set_size(bio2, writebuf2)
            // SAFETY: both are fresh pair BIOs.
            && super::wrap_int(unsafe { super::BIO_ctrl(bio1, BIO_C_MAKE_BIO_PAIR, 0, bio2.cast()) }) != 0;
        if !ok {
            // SAFETY: each is null or a BIO made above.
            unsafe { super::BIO_free(bio1) };
            // SAFETY: as above.
            unsafe { super::BIO_free(bio2) };
            bio1 = ptr::null_mut();
            bio2 = ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        unsafe { bio1_p.write(bio1) };
        // SAFETY: as above.
        unsafe { bio2_p.write(bio2) };
        c_int::from(ok)
    }
}

ffi_export! {
    /// How many bytes the next write to `bio`, one end of a pair, can take without the peer
    /// reading (0 if unpaired or shut down).
    ///
    /// # Safety
    /// `bio` is null or a live BIO.
    pub unsafe extern "C" fn BIO_ctrl_get_write_guarantee(bio: *mut BIO) -> usize
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        size_t(unsafe { super::BIO_ctrl(bio, BIO_C_GET_WRITE_GUARANTEE, 0, ptr::null_mut()) })
    }
}

ffi_export! {
    /// How many bytes the peer of `bio` last tried to read when there was nothing (0 once
    /// something was written or read since).
    ///
    /// # Safety
    /// `bio` is null or a live BIO.
    pub unsafe extern "C" fn BIO_ctrl_get_read_request(bio: *mut BIO) -> usize
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        size_t(unsafe { super::BIO_ctrl(bio, BIO_C_GET_READ_REQUEST, 0, ptr::null_mut()) })
    }
}

ffi_export! {
    /// Forgets the peer's last read request. Returns 1.
    ///
    /// # Safety
    /// `bio` is null or a live BIO.
    pub unsafe extern "C" fn BIO_ctrl_reset_read_request(bio: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { super::BIO_ctrl(bio, BIO_C_RESET_READ_REQUEST, 0, ptr::null_mut()) } != 0)
    }
}

/// Whether `bio` is initialized; if not, raises `BIO_R_UNINITIALIZED` for `function`. A null
/// BIO counts as uninitialized (OpenSSL's would crash).
///
/// # Safety
/// `bio` is null or a live BIO.
unsafe fn initialized(bio: *mut BIO, function: &str) -> bool {
    // SAFETY: the caller's guarantee.
    let init = unsafe { object(bio) }.is_some_and(|o| o.init.load(Ordering::Relaxed) != 0);
    if !init {
        err::raise(ERR_LIB_BIO, BIO_R_UNINITIALIZED, function);
    }
    init
}

/// A count from `BIO_ctrl` as the `int` the non-copying functions return.
fn clamp(ret: c_long) -> c_int {
    if ret > c_long::from(c_int::MAX) {
        c_int::MAX
    } else {
        super::wrap_int(ret)
    }
}

ffi_export! {
    /// Points `*buf` at the bytes `bio` can read without copying, and returns how many (in one
    /// piece; read them, then call `BIO_nread`). Returns 0 or -1 as a read would when there
    /// are none, and -2 for an uninitialized BIO.
    ///
    /// # Safety
    /// `bio` is null or a live BIO; `buf` is null or valid for a write.
    pub unsafe extern "C" fn BIO_nread0(bio: *mut BIO, buf: *mut *mut c_char) -> c_int
    where failure = -2, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { initialized(bio, "BIO_nread0") } {
            return -2;
        }
        // SAFETY: as above.
        clamp(unsafe { super::BIO_ctrl(bio, BIO_C_NREAD0, 0, buf.cast()) })
    }
}

ffi_export! {
    /// `BIO_nread0`, then marks up to `num` of those bytes read. Returns how many.
    ///
    /// # Safety
    /// As for `BIO_nread0`.
    pub unsafe extern "C" fn BIO_nread(bio: *mut BIO, buf: *mut *mut c_char, num: c_int) -> c_int
    where failure = -2, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { initialized(bio, "BIO_nread") } {
            return -2;
        }
        // SAFETY: as above.
        let ret = super::wrap_int(unsafe { super::BIO_ctrl(bio, BIO_C_NREAD, c_long::from(num), buf.cast()) });
        if ret > 0 {
            // SAFETY: as above; `initialized` saw it live.
            if let Some(object) = unsafe { object(bio) } {
                object.num_read.fetch_add(u64::from(ret.unsigned_abs()), Ordering::Relaxed);
            }
        }
        ret
    }
}

ffi_export! {
    /// Points `*buf` at where `bio` can take bytes without copying, and returns how many (in
    /// one piece; write them, then call `BIO_nwrite`). Returns -1 as a write would when full
    /// or shut down, and -2 for an uninitialized BIO.
    ///
    /// # Safety
    /// `bio` is null or a live BIO; `buf` is null or valid for a write.
    pub unsafe extern "C" fn BIO_nwrite0(bio: *mut BIO, buf: *mut *mut c_char) -> c_int
    where failure = -2, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { initialized(bio, "BIO_nwrite0") } {
            return -2;
        }
        // SAFETY: as above.
        clamp(unsafe { super::BIO_ctrl(bio, BIO_C_NWRITE0, 0, buf.cast()) })
    }
}

ffi_export! {
    /// `BIO_nwrite0`, then marks up to `num` bytes written there. Returns how many.
    ///
    /// # Safety
    /// As for `BIO_nwrite0`.
    pub unsafe extern "C" fn BIO_nwrite(bio: *mut BIO, buf: *mut *mut c_char, num: c_int) -> c_int
    where failure = -2, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { initialized(bio, "BIO_nwrite") } {
            return -2;
        }
        // SAFETY: as above.
        let ret = super::wrap_int(unsafe { super::BIO_ctrl(bio, BIO_C_NWRITE, c_long::from(num), buf.cast()) });
        if ret > 0 {
            // SAFETY: as above.
            if let Some(object) = unsafe { object(bio) } {
                object.num_write.fetch_add(u64::from(ret.unsigned_abs()), Ordering::Relaxed);
            }
        }
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: OpenSSL misreads or crashes on these.
    #[test]
    fn misused_pairs_fail() {
        let (pair_method, mem_method) = (PAIR.get(), super::super::mem::MEM.get());
        // SAFETY: a built-in method.
        let a = unsafe { super::super::BIO_new(pair_method) };
        // SAFETY: as above.
        let mem = unsafe { super::super::BIO_new(mem_method) };
        // SAFETY: live BIOs; a memory BIO isn't a pair end.
        let ret = unsafe { super::super::BIO_ctrl(a, BIO_C_MAKE_BIO_PAIR, 0, mem.cast()) };
        assert_eq!(ret, 0);
        // SAFETY: as above; null isn't one either.
        let ret = unsafe { super::super::BIO_ctrl(a, BIO_C_MAKE_BIO_PAIR, 0, ptr::null_mut()) };
        assert_eq!(ret, 0);
        // SAFETY: null BIOs are refused.
        assert_eq!(unsafe { BIO_nread0(ptr::null_mut(), ptr::null_mut()) }, -2);
        // SAFETY: as above.
        let ret = unsafe { BIO_nwrite(ptr::null_mut(), ptr::null_mut(), 1) };
        assert_eq!(ret, -2);
        // SAFETY: null out-pointers are refused.
        let ret = unsafe { BIO_new_bio_pair(ptr::null_mut(), 0, ptr::null_mut(), 0) };
        assert_eq!(ret, 0);
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
        // SAFETY: live BIOs, freed once.
        unsafe { super::super::BIO_free(a) };
        // SAFETY: as above.
        unsafe { super::super::BIO_free(mem) };
    }

    /// docs/DEVIATIONS.md: `BIO_dup_chain` copies an end's `init` but not its pairing, and
    /// OpenSSL then dereferences the missing peer.
    #[test]
    fn an_unpaired_copy_reads_and_writes_nothing() {
        let (mut a, mut b) = (ptr::null_mut(), ptr::null_mut());
        // SAFETY: valid out-pointers.
        assert_eq!(unsafe { BIO_new_bio_pair(&raw mut a, 0, &raw mut b, 0) }, 1);
        // SAFETY: a live BIO.
        let copy = unsafe { super::super::BIO_dup_chain(a) };
        let mut byte = 0u8;
        // SAFETY: a live BIO and a 1-byte buffer.
        let ret = unsafe { super::super::BIO_read(copy, (&raw mut byte).cast(), 1) };
        assert_eq!(ret, 0);
        // SAFETY: as above.
        let ret = unsafe { super::super::BIO_write(copy, (&raw const byte).cast(), 1) };
        assert_eq!(ret, 0);
        for bio in [copy, a, b] {
            // SAFETY: live BIOs, freed once.
            unsafe { super::super::BIO_free(bio) };
        }
    }
}
