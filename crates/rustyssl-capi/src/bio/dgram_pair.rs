//! Datagram pairs and datagram memory BIOs (`BIO_s_dgram_pair(3)`, `BIO_new_bio_dgram_pair(3)`,
//! `BIO_s_dgram_mem`): datagrams with their source and destination addresses through a ring
//! buffer, between two joined ends or within one BIO. A port of OpenSSL's `bss_dgram_pair.c`.
//!
//! Each datagram is stored as OpenSSL stores it: a header (`size_t` length, source and
//! destination `BIO_ADDR`) and the payload, so the buffer sizes applications see (the default is
//! nine headers and 1,472-byte datagrams) are OpenSSL's. Writes go to the writer's own ring and
//! reads come from the peer's (a memory BIO reads its own). Each end holds a reference to its
//! peer, as BIO pairs do, and only one end's state is locked at a time.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::mem::size_of;
use core::ptr::{self, NonNull};
use core::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use rustyssl_abi::{
    BIO, BIO_ADDR, BIO_C_DESTROY_BIO_PAIR, BIO_C_GET_WRITE_BUF_SIZE, BIO_C_GET_WRITE_GUARANTEE,
    BIO_C_MAKE_BIO_PAIR, BIO_C_SET_WRITE_BUF_SIZE, BIO_CTRL_DGRAM_GET_CAPS,
    BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS, BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP,
    BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE, BIO_CTRL_DGRAM_GET_MTU, BIO_CTRL_DGRAM_GET_NO_TRUNC,
    BIO_CTRL_DGRAM_SET_CAPS, BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE, BIO_CTRL_DGRAM_SET_MTU,
    BIO_CTRL_DGRAM_SET_NO_TRUNC, BIO_CTRL_DGRAM_SET0_LOCAL_ADDR, BIO_CTRL_EOF, BIO_CTRL_FLUSH,
    BIO_CTRL_PENDING, BIO_CTRL_RESET, BIO_DGRAM_CAP_HANDLES_DST_ADDR,
    BIO_DGRAM_CAP_HANDLES_SRC_ADDR, BIO_DGRAM_CAP_PROVIDES_DST_ADDR, BIO_METHOD, BIO_MSG,
    BIO_R_BROKEN_PIPE, BIO_R_IN_USE, BIO_R_INVALID_ARGUMENT, BIO_R_LOCAL_ADDR_NOT_AVAILABLE,
    BIO_R_NON_FATAL, BIO_R_PEER_ADDR_NOT_AVAILABLE, BIO_R_TRANSFER_ERROR, BIO_R_UNINITIALIZED,
    BIO_TYPE_DGRAM_MEM, BIO_TYPE_DGRAM_PAIR, ERR_LIB_BIO, ERR_R_BIO_LIB,
};

use super::addr::{self, Addr};
use super::method::{Builtin, Funcs};
use super::state::{self, lock};
use super::{Bio, object};
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::handle::{Handle, Held};
use crate::mem;

/// OpenSSL's `struct dgram_hdr`, stored before each datagram's payload.
#[repr(C)]
#[derive(Clone, Copy)]
struct Hdr {
    len: usize,
    src_addr: Addr,
    dst_addr: Addr,
}

const HDR: usize = size_of::<Hdr>();

/// The smallest buffer (`MIN_BUF_LEN`).
const MIN_BUF_LEN: usize = 1024;

/// The default MTU, a conservative one.
const DEFAULT_MTU: usize = 1472;

/// OpenSSL's `struct ring_buf`, in C memory (`OPENSSL_malloc`/`OPENSSL_realloc`) so that
/// allocation failures are reported as OpenSSL reports them.
struct Ring {
    start: Option<NonNull<u8>>,
    len: usize,
    count: usize,
    /// 0: the head (writes), 1: the tail (reads).
    idx: [usize; 2],
}

// SAFETY: the ring's memory is owned by it and only reached through its end's lock.
unsafe impl Send for Ring {}

impl Ring {
    const EMPTY: Self = Self {
        start: None,
        len: 0,
        count: 0,
        idx: [0, 0],
    };

    fn init(&mut self, nbytes: usize) -> bool {
        // OpenSSL's re-init of a ring that has memory leaks it; this frees it.
        self.destroy();
        let Some(start) = NonNull::new(mem::alloc(nbytes).cast::<u8>()) else {
            return false;
        };
        *self = Self {
            start: Some(start),
            len: nbytes,
            count: 0,
            idx: [0, 0],
        };
        true
    }

    fn destroy(&mut self) {
        if let Some(start) = self.start.take() {
            // SAFETY: allocated by `mem`, freed once.
            unsafe { mem::release(start.as_ptr().cast()) };
        }
        self.len = 0;
        self.count = 0;
    }

    /// OpenSSL's `ring_buf_head_tail`: where the head (0) can write, or the tail (1) can read,
    /// in one piece.
    fn head_tail(&self, i: usize) -> (*mut u8, usize) {
        let at = self.idx.get(i).copied().unwrap_or(0);
        let mut max = self.len.saturating_sub(at);
        if i == 0 {
            max = max.min(self.len - self.count);
        } else {
            max = max.min(self.count);
        }
        let base = self.start.map_or(ptr::null_mut(), NonNull::as_ptr);
        (base.wrapping_add(at), max)
    }

    /// OpenSSL's `ring_buf_push_pop`.
    fn push_pop(&mut self, i: usize, n: usize) {
        let at = self.idx.get(i).copied().unwrap_or(0);
        if n > self.len - at {
            return;
        }
        if if i != 0 {
            n > self.count
        } else {
            n + self.count > self.len
        } {
            return;
        }
        let mut new = at + n;
        if new == self.len {
            new = 0;
        }
        if let Some(slot) = self.idx.get_mut(i) {
            *slot = new;
        }
        if i != 0 {
            self.count -= n;
        } else {
            self.count += n;
        }
    }

    fn clear(&mut self) {
        self.idx = [0, 0];
        self.count = 0;
    }

    /// OpenSSL's `ring_buf_resize`: grows (or, if empty, shrinks) the buffer, moving the data
    /// after the head to the new end when the data wraps.
    fn resize(&mut self, nbytes: usize) -> bool {
        let Some(start) = self.start else {
            return self.init(nbytes);
        };
        if nbytes == self.len {
            return true;
        }
        if self.count > 0 && nbytes < self.len {
            return false;
        }
        // SAFETY: allocated by `mem`; a failed resize leaves it as it was.
        let Some(new_start) =
            NonNull::new(unsafe { mem::resize(start.as_ptr().cast(), nbytes) }.cast::<u8>())
        else {
            return false;
        };
        if self.count > 0 {
            if self.idx[0] <= self.idx[1] {
                let offset = nbytes - self.len;
                let from = new_start.as_ptr().wrapping_add(self.idx[1]);
                // SAFETY: the tail's bytes up to the old end, moved within the new buffer.
                unsafe { ptr::copy(from, from.wrapping_add(offset), self.len - self.idx[1]) };
                self.idx[1] += offset;
            }
        } else {
            self.idx = [0, 0];
        }
        self.start = Some(new_start);
        self.len = nbytes;
        true
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        self.destroy();
    }
}

/// The other end of a pair.
struct Peer {
    bio: Held<BIO>,
    state: Arc<Mutex<End>>,
}

/// One end of a datagram pair, or a datagram memory BIO (OpenSSL's `struct
/// bio_dgram_pair_st`).
pub(crate) struct End {
    peer: Option<Peer>,
    rbuf: Ring,
    req_buf_len: usize,
    mtu: usize,
    cap: u32,
    /// Owned; from `BIO_dgram_set0_local_addr`.
    local_addr: *mut BIO_ADDR,
    no_trunc: bool,
    local_addr_enable: bool,
    grows_on_write: bool,
}

// SAFETY: the local address is owned by the state.
unsafe impl Send for End {}

impl End {
    fn new() -> Self {
        Self {
            peer: None,
            rbuf: Ring::EMPTY,
            req_buf_len: 9 * (HDR + DEFAULT_MTU),
            mtu: DEFAULT_MTU,
            cap: 0,
            local_addr: ptr::null_mut(),
            no_trunc: false,
            local_addr_enable: false,
            grows_on_write: false,
        }
    }

    fn free_local_addr(&mut self) {
        // SAFETY: null or the address handed over with set0, freed once.
        unsafe { addr::BIO_ADDR_free(self.local_addr) };
        self.local_addr = ptr::null_mut();
    }
}

impl Drop for End {
    fn drop(&mut self) {
        self.free_local_addr();
    }
}

/// The end `b` and its state.
///
/// # Safety
/// `b` is null or a live BIO that outlives `'a`.
unsafe fn end<'a>(b: *mut BIO) -> Option<(&'a Bio, Arc<Mutex<End>>)> {
    // SAFETY: the caller's guarantee.
    let object = unsafe { object(b) }?;
    Some((object, state::get::<End>(object)?))
}

/// The state datagrams are read from: the peer's for a pair, the BIO's own for a memory BIO.
fn read_side(state: &Arc<Mutex<End>>) -> Arc<Mutex<End>> {
    lock(state)
        .peer
        .as_ref()
        .map_or_else(|| Arc::clone(state), |p| Arc::clone(&p.state))
}

ffi_callback! {
    /// Sets up an unpaired end.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn dgram_pair_init(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        state::install(object, End::new());
        1
    }
}

ffi_callback! {
    /// Sets up a datagram memory BIO, whose buffer grows as needed.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn dgram_mem_init(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        let mut end = End::new();
        if !end.rbuf.init(end.req_buf_len) {
            err::raise(ERR_LIB_BIO, ERR_R_BIO_LIB, "dgram_mem_init");
            return 0;
        }
        end.grows_on_write = true;
        state::install(object, end);
        object.init.store(1, Ordering::Relaxed);
        1
    }
}

/// OpenSSL's `dgram_pair_ctrl_destroy_bio_pair`: frees both ends' buffers and this end's local
/// address, and unpairs them.
fn destroy_pair(object: &Bio, state: &Mutex<End>) {
    let peer = {
        let mut s = lock(state);
        s.rbuf.destroy();
        // OpenSSL frees the address without forgetting it, so a later free frees it again.
        s.free_local_addr();
        s.peer.take()
    };
    object.init.store(0, Ordering::Relaxed);
    if let Some(peer) = peer {
        {
            let mut p = lock(&peer.state);
            p.rbuf.destroy();
            p.peer = None;
        }
        peer.bio.init.store(0, Ordering::Relaxed);
    }
}

ffi_callback! {
    /// Frees an end, unpairing both.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn dgram_pair_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { end(b) }) else {
            return 0;
        };
        destroy_pair(object, &state);
        drop(state);
        drop(state::remove::<End>(object));
        1
    }
}

/// Whether `b` is a datagram pair end (not a memory BIO).
fn is_pair_method(object: &Bio) -> bool {
    ptr::eq(object.method.0.cast_const(), DGRAM_PAIR.get())
}

/// OpenSSL's `dgram_pair_ctrl_make_bio_pair`.
///
/// # Safety
/// `b1` and `b2` are null or live BIOs.
unsafe fn make_pair(b1: *mut BIO, b2: *mut BIO) -> bool {
    if b1.is_null() || b2.is_null() {
        err::raise(
            ERR_LIB_BIO,
            BIO_R_INVALID_ARGUMENT,
            "dgram_pair_ctrl_make_bio_pair",
        );
        return false;
    }
    // SAFETY: the caller's guarantee, for each.
    let (Some((o1, s1)), Some((o2, s2))) = (unsafe { end(b1) }, unsafe { end(b2) }) else {
        err::raise_with_text(
            ERR_LIB_BIO,
            BIO_R_INVALID_ARGUMENT,
            "dgram_pair_ctrl_make_bio_pair",
            "both BIOs must be BIO_dgram_pair",
        );
        return false;
    };
    if !is_pair_method(o1) || !is_pair_method(o2) {
        err::raise_with_text(
            ERR_LIB_BIO,
            BIO_R_INVALID_ARGUMENT,
            "dgram_pair_ctrl_make_bio_pair",
            "both BIOs must be BIO_dgram_pair",
        );
        return false;
    }
    if lock(&s1).peer.is_some() || lock(&s2).peer.is_some() {
        err::raise_with_text(
            ERR_LIB_BIO,
            BIO_R_IN_USE,
            "dgram_pair_ctrl_make_bio_pair",
            "cannot associate a BIO_dgram_pair which is already in use",
        );
        return false;
    }
    for (i, s) in [&s1, &s2].into_iter().enumerate() {
        let mut e = lock(s);
        if e.rbuf.len != e.req_buf_len {
            let len = e.req_buf_len;
            if !e.rbuf.init(len) {
                drop(e);
                err::raise(ERR_LIB_BIO, ERR_R_BIO_LIB, "dgram_pair_ctrl_make_bio_pair");
                if i == 1 {
                    lock(&s1).rbuf.destroy();
                }
                return false;
            }
        }
    }
    // SAFETY: both are live (checked above).
    let (Some(h1), Some(h2)) = (unsafe { BIO::hold(b1) }, unsafe { BIO::hold(b2) }) else {
        return false;
    };
    lock(&s1).peer = Some(Peer {
        bio: h2,
        state: Arc::clone(&s2),
    });
    lock(&s2).peer = Some(Peer {
        bio: h1,
        state: Arc::clone(&s1),
    });
    o1.init.store(1, Ordering::Relaxed);
    o2.init.store(1, Ordering::Relaxed);
    true
}

/// OpenSSL's `dgram_pair_read_inner`: pops up to `sz` bytes into `buf` (or discards them for
/// null).
fn read_inner(ring: &mut Ring, mut buf: *mut u8, mut sz: usize) -> usize {
    let mut total = 0;
    while sz > 0 {
        let (src, len) = ring.head_tail(1);
        if len == 0 {
            break;
        }
        let n = len.min(sz);
        if !buf.is_null() {
            // SAFETY: the ring holds `n` bytes at `src`; the caller's buffer has room for `sz`.
            unsafe { ptr::copy_nonoverlapping(src, buf, n) };
            buf = buf.wrapping_add(n);
        }
        ring.push_pop(1, n);
        total += n;
        sz -= n;
    }
    total
}

/// OpenSSL's `compute_rbuf_growth`: grows `current` by 8/5 until it reaches `target`; 0 past
/// half the address space.
fn rbuf_growth(target: usize, mut current: usize) -> usize {
    let max = usize::MAX / 2;
    while current < target {
        if current >= max {
            return 0;
        }
        current = match current.checked_mul(8) {
            Some(n) => n / 5,
            None => return 0,
        };
        current = current.min(max);
    }
    current
}

/// OpenSSL's `dgram_pair_write_inner`: pushes up to `sz` bytes, growing a memory BIO's buffer.
fn write_inner(end: &mut End, mut buf: *const u8, mut sz: usize) -> usize {
    let mut total = 0;
    while sz > 0 {
        let (dst, len) = end.rbuf.head_tail(0);
        if len == 0 {
            if !end.grows_on_write {
                break;
            }
            let new_len = rbuf_growth(end.req_buf_len + sz, end.req_buf_len);
            if new_len == 0 || !end.rbuf.resize(new_len) {
                break;
            }
            end.req_buf_len = new_len;
            continue;
        }
        let n = len.min(sz);
        // SAFETY: the ring has room for `n` bytes at `dst`; the caller's data has `sz`.
        unsafe { ptr::copy_nonoverlapping(buf, dst, n) };
        end.rbuf.push_pop(0, n);
        buf = buf.wrapping_add(n);
        sz -= n;
        total += n;
    }
    total
}

/// Copies an address from the caller (`*peer` in OpenSSL), its family's bytes only.
///
/// # Safety
/// `ap` is null or an address.
unsafe fn copy_in(ap: *const BIO_ADDR) -> Addr {
    let mut out = Addr::unspecified();
    if !ap.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { addr::make(&raw mut out, ap.cast()) };
    }
    out
}

/// OpenSSL's `dgram_pair_read_actual`: reads one datagram. Returns its length, or a negated
/// reason (`-BIO_R_NON_FATAL` when there's none).
///
/// # Safety
/// `buf` is null or valid for `sz` bytes of writes; `local` and `peer` are null or whole
/// `BIO_ADDR`s.
unsafe fn read_actual(
    object: &Bio,
    state: &Arc<Mutex<End>>,
    buf: *mut u8,
    sz: usize,
    local: *mut BIO_ADDR,
    peer: *mut BIO_ADDR,
    multi: bool,
) -> isize {
    if !multi {
        object.clear_retry_flags();
    }
    if object.init.load(Ordering::Relaxed) == 0 {
        return -reason(BIO_R_UNINITIALIZED);
    }
    let (no_trunc, local_enable) = {
        let s = lock(state);
        (s.no_trunc, s.local_addr_enable)
    };
    let readb = read_side(state);
    let mut r = lock(&readb);
    if r.rbuf.start.is_none() {
        return -reason(BIO_R_TRANSFER_ERROR);
    }
    if sz > 0 && buf.is_null() {
        return -reason(BIO_R_INVALID_ARGUMENT);
    }
    if !local.is_null() && !local_enable {
        return -reason(BIO_R_LOCAL_ADDR_NOT_AVAILABLE);
    }
    let (saved_idx, saved_count) = (r.rbuf.idx[1], r.rbuf.count);
    let mut hdr = Hdr {
        len: 0,
        src_addr: Addr::unspecified(),
        dst_addr: Addr::unspecified(),
    };
    let l = read_inner(&mut r.rbuf, (&raw mut hdr).cast(), HDR);
    if l == 0 {
        if !multi {
            object.set_retry_read();
        }
        return -reason(BIO_R_NON_FATAL);
    }
    if l != HDR {
        return -reason(rustyssl_abi::BIO_R_BROKEN_PIPE);
    }
    let mut sz = sz;
    let mut trunc = 0;
    if sz > hdr.len {
        sz = hdr.len;
    } else if sz < hdr.len {
        trunc = hdr.len - sz;
        if no_trunc {
            r.rbuf.idx[1] = saved_idx;
            r.rbuf.count = saved_count;
            return -reason(BIO_R_NON_FATAL);
        }
    }
    let l = read_inner(&mut r.rbuf, buf, sz);
    if l != sz || (trunc > 0 && read_inner(&mut r.rbuf, ptr::null_mut(), trunc) != trunc) {
        return -reason(BIO_R_TRANSFER_ERROR);
    }
    drop(r);
    if !local.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { local.cast::<Addr>().write_unaligned(hdr.dst_addr) };
    }
    if !peer.is_null() {
        // SAFETY: as above.
        unsafe { peer.cast::<Addr>().write_unaligned(hdr.src_addr) };
    }
    isize::try_from(l).unwrap_or(isize::MAX)
}

/// OpenSSL's `dgram_pair_write_actual`: writes one datagram with its addresses. Returns its
/// length, or a negated reason (`-BIO_R_NON_FATAL` when it doesn't fit).
///
/// # Safety
/// `buf` is null or valid for `sz` bytes of reads; `local` and `peer` are null or addresses.
unsafe fn write_actual(
    object: &Bio,
    state: &Arc<Mutex<End>>,
    buf: *const u8,
    sz: usize,
    local: *const BIO_ADDR,
    peer: *const BIO_ADDR,
    multi: bool,
) -> isize {
    if !multi {
        object.clear_retry_flags();
    }
    if object.init.load(Ordering::Relaxed) == 0 {
        return -reason(BIO_R_UNINITIALIZED);
    }
    let readb = read_side(state);
    let read_cap = if Arc::ptr_eq(&readb, state) {
        None
    } else {
        Some(lock(&readb).cap)
    };
    let mut s = lock(state);
    if s.rbuf.start.is_none() {
        return -reason(BIO_R_TRANSFER_ERROR);
    }
    if sz > 0 && buf.is_null() {
        return -reason(BIO_R_INVALID_ARGUMENT);
    }
    if !local.is_null() && !s.local_addr_enable {
        return -reason(BIO_R_LOCAL_ADDR_NOT_AVAILABLE);
    }
    let cap = read_cap.unwrap_or(s.cap);
    if !peer.is_null() && cap & BIO_DGRAM_CAP_HANDLES_DST_ADDR == 0 {
        return -reason(BIO_R_PEER_ADDR_NOT_AVAILABLE);
    }
    let local = if local.is_null() {
        s.local_addr.cast_const()
    } else {
        local
    };
    // SAFETY: the caller's guarantee, or the end's own address.
    let src_addr = unsafe { copy_in(local) };
    // SAFETY: the caller's guarantee.
    let dst_addr = unsafe { copy_in(peer) };
    let hdr = Hdr {
        len: sz,
        src_addr,
        dst_addr,
    };
    let (saved_idx, saved_count) = (s.rbuf.idx[0], s.rbuf.count);
    if write_inner(&mut s, (&raw const hdr).cast(), HDR) != HDR
        || write_inner(&mut s, buf, sz) != sz
    {
        s.rbuf.idx[0] = saved_idx;
        s.rbuf.count = saved_count;
        drop(s);
        if !multi {
            object.set_retry_write();
        }
        return -reason(BIO_R_NON_FATAL);
    }
    isize::try_from(sz).unwrap_or(isize::MAX)
}

/// A reason code as the `ossl_ssize_t` OpenSSL negates.
fn reason(r: c_int) -> isize {
    isize::try_from(r).unwrap_or(0)
}

/// A negated reason as the `int` `ERR_raise` takes.
fn from_reason(l: isize) -> c_int {
    c_int::try_from(-l).unwrap_or(0)
}

ffi_callback! {
    /// Reads a datagram from the peer's buffer, truncating it to `len` unless
    /// `BIO_dgram_set_no_trunc`; with none there, -1 and a read retry.
    ///
    /// # Safety
    /// `b` is a live BIO; `buf` is valid for `len` bytes of writes.
    pub(crate) unsafe extern "C" fn dgram_pair_read(b: *mut BIO, buf: *mut c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { read_common(b, buf, len, true) }
    }
}

ffi_callback! {
    /// Reads a datagram from the memory BIO's own buffer.
    ///
    /// # Safety
    /// As for `dgram_pair_read`.
    pub(crate) unsafe extern "C" fn dgram_mem_read(b: *mut BIO, buf: *mut c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { read_common(b, buf, len, false) }
    }
}

/// The body of the two reads.
///
/// # Safety
/// As for `dgram_pair_read`.
unsafe fn read_common(b: *mut BIO, buf: *mut c_char, len: c_int, pair: bool) -> c_int {
    let Ok(size) = usize::try_from(len) else {
        err::raise(ERR_LIB_BIO, BIO_R_INVALID_ARGUMENT, "dgram_pair_read");
        return -1;
    };
    // SAFETY: the caller's guarantee.
    let Some((object, state)) = (unsafe { end(b) }) else {
        return -1;
    };
    if pair && lock(&state).peer.is_none() {
        err::raise(ERR_LIB_BIO, BIO_R_BROKEN_PIPE, "dgram_pair_read");
        return -1;
    }
    // SAFETY: the caller's guarantee.
    let l = unsafe {
        read_actual(
            object,
            &state,
            buf.cast(),
            size,
            ptr::null_mut(),
            ptr::null_mut(),
            false,
        )
    };
    if l < 0 {
        if l != -reason(BIO_R_NON_FATAL) {
            err::raise(ERR_LIB_BIO, from_reason(l), "dgram_pair_read");
        }
        return -1;
    }
    c_int::try_from(l).unwrap_or(c_int::MAX)
}

ffi_callback! {
    /// Writes a datagram to this end's buffer; when it doesn't fit, -1 and a write retry.
    ///
    /// # Safety
    /// `b` is a live BIO; `buf` is valid for `len` bytes of reads.
    pub(crate) unsafe extern "C" fn dgram_pair_write(b: *mut BIO, buf: *const c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let Ok(size) = usize::try_from(len) else {
            err::raise(ERR_LIB_BIO, BIO_R_INVALID_ARGUMENT, "dgram_pair_write");
            return -1;
        };
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { end(b) }) else {
            return -1;
        };
        // SAFETY: the caller's guarantee.
        let l = unsafe { write_actual(object, &state, buf.cast(), size, ptr::null(), ptr::null(), false) };
        if l < 0 {
            err::raise(ERR_LIB_BIO, from_reason(l), "dgram_pair_write");
            return -1;
        }
        c_int::try_from(l).unwrap_or(c_int::MAX)
    }
}

/// The `n`th message of an array with the given stride.
fn nth(msg: *mut BIO_MSG, stride: usize, n: usize) -> *mut BIO_MSG {
    msg.cast::<u8>().wrapping_add(n.wrapping_mul(stride)).cast()
}

/// The shared body of the message functions: each message in turn until one fails, which is an
/// error only if it's the first.
///
/// # Safety
/// `msg` holds `num_msg` messages at `stride`; `processed` is valid for a write.
unsafe fn mmsg(
    b: *mut BIO,
    msg: *mut BIO_MSG,
    stride: usize,
    num_msg: usize,
    processed: *mut usize,
    send: bool,
) -> c_int {
    let set = |n: usize| {
        if !processed.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { processed.write(n) };
        }
    };
    if num_msg == 0 {
        set(0);
        return 1;
    }
    // SAFETY: the caller's guarantee.
    let Some((object, state)) = (unsafe { end(b) }) else {
        set(0);
        return 0;
    };
    if !send && object.init.load(Ordering::Relaxed) == 0 {
        err::raise(ERR_LIB_BIO, BIO_R_BROKEN_PIPE, "dgram_pair_recvmmsg");
        set(0);
        return 0;
    }
    for i in 0..num_msg {
        let at = nth(msg, stride, i);
        // SAFETY: the caller's guarantee: `num_msg` messages.
        let mut m = unsafe { at.read_unaligned() };
        let l = if send {
            // SAFETY: the message's buffers.
            unsafe {
                write_actual(
                    object,
                    &state,
                    m.data.cast(),
                    m.data_len,
                    m.local,
                    m.peer,
                    true,
                )
            }
        } else {
            // SAFETY: as above.
            unsafe {
                read_actual(
                    object,
                    &state,
                    m.data.cast(),
                    m.data_len,
                    m.local,
                    m.peer,
                    true,
                )
            }
        };
        if l < 0 {
            set(i);
            if i > 0 {
                return 1;
            }
            err::raise(
                ERR_LIB_BIO,
                from_reason(l),
                if send {
                    "dgram_pair_sendmmsg"
                } else {
                    "dgram_pair_recvmmsg"
                },
            );
            return 0;
        }
        if !send {
            m.data_len = usize::try_from(l).unwrap_or(0);
        }
        m.flags = 0;
        // SAFETY: as above.
        unsafe { at.write_unaligned(m) };
    }
    set(num_msg);
    1
}

ffi_callback! {
    /// Sends messages with their addresses.
    ///
    /// # Safety
    /// `b` is a live BIO; `msg` holds `num_msg` messages at `stride`; `processed` is valid for a
    /// write.
    pub(crate) unsafe extern "C" fn dgram_pair_sendmmsg(b: *mut BIO, msg: *mut BIO_MSG, stride: usize, num_msg: usize, flags: u64, processed: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        let _ = flags;
        // SAFETY: the caller's guarantee.
        unsafe { mmsg(b, msg, stride, num_msg, processed, true) }
    }
}

ffi_callback! {
    /// Receives messages with their addresses.
    ///
    /// # Safety
    /// As for `dgram_pair_sendmmsg`.
    pub(crate) unsafe extern "C" fn dgram_pair_recvmmsg(b: *mut BIO, msg: *mut BIO_MSG, stride: usize, num_msg: usize, flags: u64, processed: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        let _ = flags;
        // SAFETY: the caller's guarantee.
        unsafe { mmsg(b, msg, stride, num_msg, processed, false) }
    }
}

/// OpenSSL's `dgram_pair_ctrl_pending`: the length of the next datagram to read.
fn pending(object: &Bio, state: &Arc<Mutex<End>>) -> c_long {
    if object.init.load(Ordering::Relaxed) == 0 {
        return 0;
    }
    let readb = read_side(state);
    let mut r = lock(&readb);
    let (saved_idx, saved_count) = (r.rbuf.idx[1], r.rbuf.count);
    let mut hdr = Hdr {
        len: 0,
        src_addr: Addr::unspecified(),
        dst_addr: Addr::unspecified(),
    };
    let l = read_inner(&mut r.rbuf, (&raw mut hdr).cast(), HDR);
    r.rbuf.idx[1] = saved_idx;
    r.rbuf.count = saved_count;
    if l != HDR {
        return 0;
    }
    c_long::from_ne_bytes(hdr.len.to_ne_bytes())
}

/// Whether the reading side handles source addresses and provides destination ones
/// (`BIO_dgram_get_local_addr_cap`).
fn local_addr_cap(object: &Bio, state: &Arc<Mutex<End>>) -> bool {
    if object.init.load(Ordering::Relaxed) == 0 {
        return false;
    }
    let cap = lock(&read_side(state)).cap;
    !cap & (BIO_DGRAM_CAP_HANDLES_SRC_ADDR | BIO_DGRAM_CAP_PROVIDES_DST_ADDR) == 0
}

/// A `size_t` as C converts it to `long`.
fn long(n: usize) -> c_long {
    c_long::from_ne_bytes(n.to_ne_bytes())
}

/// The controls of a datagram memory BIO, which a pair's fall back to (OpenSSL's
/// `dgram_mem_ctrl`).
///
/// # Safety
/// `ptr` is what the command expects.
unsafe fn mem_ctrl(
    object: &Bio,
    state: &Arc<Mutex<End>>,
    cmd: c_int,
    num: c_long,
    ptr: *mut c_void,
) -> c_long {
    match cmd {
        BIO_C_SET_WRITE_BUF_SIZE => {
            let mut s = lock(state);
            if s.peer.is_some() {
                drop(s);
                err::raise(
                    ERR_LIB_BIO,
                    BIO_R_IN_USE,
                    "dgram_pair_ctrl_set_write_buf_size",
                );
                return 0;
            }
            let len = usize::from_ne_bytes(num.to_ne_bytes()).max(MIN_BUF_LEN);
            if s.rbuf.start.is_some() && !s.rbuf.resize(len) {
                return 0;
            }
            s.req_buf_len = len;
            s.grows_on_write = false;
            1
        }
        BIO_C_GET_WRITE_BUF_SIZE => long(lock(state).req_buf_len),
        BIO_CTRL_RESET => {
            lock(state).rbuf.clear();
            1
        }
        BIO_C_GET_WRITE_GUARANTEE => {
            let s = lock(state);
            let mut l = s.rbuf.len - s.rbuf.count;
            if l >= HDR {
                l -= HDR;
            }
            if l < s.mtu {
                l = 0;
            }
            long(l)
        }
        BIO_CTRL_PENDING => pending(object, state),
        BIO_CTRL_FLUSH => 1,
        BIO_CTRL_DGRAM_GET_NO_TRUNC => c_long::from(lock(state).no_trunc),
        BIO_CTRL_DGRAM_SET_NO_TRUNC => {
            lock(state).no_trunc = num > 0;
            1
        }
        BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE => {
            if !ptr.is_null() {
                // SAFETY: the caller's guarantee: an `int`.
                unsafe {
                    ptr.cast::<c_int>()
                        .write(c_int::from(lock(state).local_addr_enable))
                };
            }
            1
        }
        BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE => {
            if !local_addr_cap(object, state) {
                return 0;
            }
            lock(state).local_addr_enable = num != 0;
            1
        }
        BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP => c_long::from(local_addr_cap(object, state)),
        BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS | BIO_CTRL_DGRAM_GET_CAPS => {
            c_long::from(lock(state).cap)
        }
        BIO_CTRL_DGRAM_SET_CAPS => {
            lock(state).cap = u32::try_from(num & 0xFFFF_FFFF).unwrap_or(0);
            1
        }
        BIO_CTRL_DGRAM_GET_MTU => c_long::from(super::wrap_int(long(lock(state).mtu))),
        BIO_CTRL_DGRAM_SET_MTU => {
            let mtu = usize::try_from(num & 0xFFFF_FFFF).unwrap_or(0);
            let peer = {
                let mut s = lock(state);
                s.mtu = mtu;
                s.peer.as_ref().map(|p| Arc::clone(&p.state))
            };
            if let Some(peer) = peer {
                lock(&peer).mtu = mtu;
            }
            1
        }
        BIO_CTRL_DGRAM_SET0_LOCAL_ADDR => {
            let mut s = lock(state);
            s.free_local_addr();
            s.local_addr = ptr.cast();
            1
        }
        BIO_CTRL_EOF => c_long::from(object.init.load(Ordering::Relaxed) == 0),
        _ => 0,
    }
}

ffi_callback! {
    /// The datagram memory BIO's controls: buffer size and guarantee, what's pending, no
    /// truncation, capabilities, local addresses, the MTU, and resetting.
    ///
    /// # Safety
    /// `b` is a live BIO; `ptr` is what the command expects.
    pub(crate) unsafe extern "C" fn dgram_mem_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { end(b) }) else {
            return 0;
        };
        // SAFETY: the caller's guarantee.
        unsafe { mem_ctrl(object, &state, cmd, num, ptr) }
    }
}

ffi_callback! {
    /// A datagram pair end's controls: pairing and unpairing and the peer's capabilities, then
    /// those of a memory BIO.
    ///
    /// # Safety
    /// `b` is a live BIO; `ptr` is what the command expects.
    pub(crate) unsafe extern "C" fn dgram_pair_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((object, state)) = (unsafe { end(b) }) else {
            return 0;
        };
        match cmd {
            // SAFETY: the caller's guarantee: the other BIO.
            BIO_C_MAKE_BIO_PAIR => c_long::from(unsafe { make_pair(b, ptr.cast()) }),
            BIO_C_DESTROY_BIO_PAIR => {
                destroy_pair(object, &state);
                1
            }
            BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS => {
                let peer = lock(&state).peer.as_ref().map(|p| Arc::clone(&p.state));
                peer.map_or(0, |p| c_long::from(lock(&p).cap))
            }
            // SAFETY: the caller's guarantee.
            _ => unsafe { mem_ctrl(object, &state, cmd, num, ptr) },
        }
    }
}

static DGRAM_PAIR: Builtin = Builtin::new(BIO_TYPE_DGRAM_PAIR, c"BIO dgram pair", || Funcs {
    ctrl: Some(dgram_pair_ctrl),
    create: Some(dgram_pair_init),
    destroy: Some(dgram_pair_free),
    bsendmmsg: Some(dgram_pair_sendmmsg),
    brecvmmsg: Some(dgram_pair_recvmmsg),
    ..Funcs::classic(dgram_pair_write, dgram_pair_read)
});

static DGRAM_MEM: Builtin = Builtin::new(BIO_TYPE_DGRAM_MEM, c"BIO dgram mem", || Funcs {
    ctrl: Some(dgram_mem_ctrl),
    create: Some(dgram_mem_init),
    destroy: Some(dgram_pair_free),
    bsendmmsg: Some(dgram_pair_sendmmsg),
    brecvmmsg: Some(dgram_pair_recvmmsg),
    ..Funcs::classic(dgram_pair_write, dgram_mem_read)
});

ffi_export! {
    /// Returns the method of one end of a datagram pair.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_s_dgram_pair() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        DGRAM_PAIR.get()
    }
}

ffi_export! {
    /// Returns the datagram memory BIO's method: datagrams written are read back from the
    /// same BIO, and its buffer grows as needed.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_s_dgram_mem() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        DGRAM_MEM.get()
    }
}

ffi_export! {
    /// Makes a joined datagram pair, with write buffers of the given sizes (0 for the default).
    /// Returns 1, with the ends in `*pbio1` and `*pbio2`, or 0 with both null. Null
    /// out-pointers return 0 (OpenSSL's would crash).
    ///
    /// # Safety
    /// `pbio1` and `pbio2` are null or valid for a write.
    pub unsafe extern "C" fn BIO_new_bio_dgram_pair(pbio1: *mut *mut BIO, writebuf1: usize, pbio2: *mut *mut BIO, writebuf2: usize) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        if pbio1.is_null() || pbio2.is_null() {
            return 0;
        }
        let method = DGRAM_PAIR.get();
        // SAFETY: the built-in method.
        let mut bio1 = unsafe { super::BIO_new(method) };
        // SAFETY: as above.
        let mut bio2 = unsafe { super::BIO_new(method) };
        let set_size = |bio: *mut BIO, size: usize| {
            // SAFETY: a fresh datagram pair end.
            size == 0 || unsafe { super::BIO_ctrl(bio, BIO_C_SET_WRITE_BUF_SIZE, long(size), ptr::null_mut()) } != 0
        };
        let ok = !bio1.is_null()
            && !bio2.is_null()
            && set_size(bio1, writebuf1)
            && set_size(bio2, writebuf2)
            // SAFETY: both are fresh pair ends.
            && unsafe { super::BIO_ctrl(bio1, BIO_C_MAKE_BIO_PAIR, 0, bio2.cast()) } != 0;
        if !ok {
            // SAFETY: null or made above, freed once each.
            unsafe { super::BIO_free(bio1) };
            // SAFETY: as above.
            unsafe { super::BIO_free(bio2) };
            bio1 = ptr::null_mut();
            bio2 = ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        unsafe { pbio1.write(bio1) };
        // SAFETY: as above.
        unsafe { pbio2.write(bio2) };
        c_int::from(ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: OpenSSL frees the local address when unpairing without forgetting
    /// it, then frees it again with the BIO (Miri would catch a double free here).
    #[test]
    fn unpairing_then_freeing_frees_the_local_address_once() {
        let (mut a, mut b) = (ptr::null_mut(), ptr::null_mut());
        // SAFETY: valid out-pointers.
        let ret = unsafe { BIO_new_bio_dgram_pair(&raw mut a, 0, &raw mut b, 0) };
        assert_eq!(ret, 1);
        // SAFETY: no preconditions.
        let local = unsafe { addr::BIO_ADDR_new() };
        // SAFETY: a live end, which takes the address.
        unsafe { super::super::BIO_ctrl(a, BIO_CTRL_DGRAM_SET0_LOCAL_ADDR, 0, local.cast()) };
        // SAFETY: as above.
        unsafe { super::super::BIO_ctrl(a, BIO_C_DESTROY_BIO_PAIR, 0, ptr::null_mut()) };
        // SAFETY: live BIOs, freed once each.
        unsafe { super::super::BIO_free(a) };
        // SAFETY: as above.
        unsafe { super::super::BIO_free(b) };
        // SAFETY: null out-pointers are refused.
        let refused = unsafe { BIO_new_bio_dgram_pair(ptr::null_mut(), 0, ptr::null_mut(), 0) };
        assert_eq!(refused, 0);
    }
}
