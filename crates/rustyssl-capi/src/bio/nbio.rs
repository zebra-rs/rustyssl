//! The non-blocking IO test filter (`BIO_f_nbio_test`, `bf_nbio.c`): each read and write passes
//! at most a random 0 to 7 octets to the next BIO (a random octet of the private generator, its
//! low three bits), 0 meaning a retry; a write the next BIO asked to retry is retried with the
//! same count.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;
use std::sync::atomic::Ordering;

use rustyssl_abi::{BIO, BIO_METHOD, BIO_TYPE_NBIO_TEST, BIO_info_cb, ERR_LIB_BIO};

use super::method::{Builtin, Funcs};
use super::object;
use super::state::{self, lock};
use crate::ffi::{ffi_callback, ffi_export};
use crate::rand_lib::RAND_priv_bytes;

/// `NBIO_TEST`: the last write's count, to retry with.
#[derive(Default)]
struct Nbio {
    lwn: c_int,
}

/// The BIO after `b`, if `b` is a live BIO with one.
///
/// # Safety
/// `b` is null or a live BIO.
unsafe fn next(b: *mut BIO) -> *mut BIO {
    // SAFETY: the caller's guarantee.
    unsafe { object(b) }.map_or(ptr::null_mut(), super::Bio::next)
}

/// The count this operation may pass on: a random 0 to 7, or `None` if the generator failed.
fn random_count() -> Option<c_int> {
    let mut n = 0u8;
    // SAFETY: room for one octet.
    if unsafe { RAND_priv_bytes(&raw mut n, 1) } <= 0 {
        return None;
    }
    Some(c_int::from(n & 7))
}

ffi_callback! {
    /// `nbiof_new`.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn nbio_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(o) = (unsafe { object(b) }) else { return 0 };
        state::install(o, Nbio { lwn: -1 });
        o.init.store(1, Ordering::Relaxed);
        1
    }
}

ffi_callback! {
    /// `nbiof_free`: the state gone, and the BIO's flags cleared.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn nbio_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(o) = (unsafe { object(b) }) else { return 0 };
        state::remove::<Nbio>(o);
        o.init.store(0, Ordering::Relaxed);
        o.set_flags(0);
        1
    }
}

ffi_callback! {
    /// `nbiof_read`: at most a random count of octets from the next BIO, or a retry for 0.
    ///
    /// # Safety
    /// `b` is a live BIO; `out` is null or valid for `len` octets of writes.
    pub(crate) unsafe extern "C" fn nbio_read(b: *mut BIO, out: *mut c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if out.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let next = unsafe { next(b) };
        // SAFETY: as above.
        let Some(o) = (unsafe { object(b) }) else { return 0 };
        if next.is_null() {
            return 0;
        }
        o.clear_retry_flags();
        let Some(num) = random_count() else { return -1 };
        if num == 0 {
            o.set_retry_read();
            return -1;
        }
        // SAFETY: as above; the next BIO is live.
        let ret = unsafe { super::BIO_read(next, out.cast(), len.min(num)) };
        if ret < 0 {
            super::copy_next_retry(o);
        }
        ret
    }
}

ffi_callback! {
    /// `nbiof_write`: at most a random count of octets to the next BIO (the count a retried
    /// write had, if it was), or a retry for 0.
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is null or valid for `len` octets of reads.
    pub(crate) unsafe extern "C" fn nbio_write(b: *mut BIO, data: *const c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if data.is_null() || len <= 0 {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let next = unsafe { next(b) };
        // SAFETY: as above.
        let Some(o) = (unsafe { object(b) }) else { return 0 };
        if next.is_null() {
            return 0;
        }
        let Some(st) = state::get::<Nbio>(o) else { return 0 };
        o.clear_retry_flags();
        let last = {
            let mut s = lock(&st);
            let last = s.lwn;
            if last > 0 {
                s.lwn = 0;
            }
            last
        };
        let num = if last > 0 {
            last
        } else {
            let Some(n) = random_count() else { return -1 };
            n
        };
        let inl = len.min(num);
        if num == 0 {
            o.set_retry_write();
            return -1;
        }
        // SAFETY: as above; the next BIO is live.
        let ret = unsafe { super::BIO_write(next, data.cast(), inl) };
        if ret < 0 {
            super::copy_next_retry(o);
            lock(&st).lwn = inl;
        }
        ret
    }
}

ffi_callback! {
    /// `nbiof_ctrl`: the next BIO's, except that it can't be copied.
    ///
    /// # Safety
    /// `b` is a live BIO; `ptr` is what the command expects.
    pub(crate) unsafe extern "C" fn nbio_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { super::null::nullf_ctrl(b, cmd, num, ptr) }
    }
}

ffi_callback! {
    /// `nbiof_callback_ctrl`: the next BIO's.
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn nbio_callback_ctrl(b: *mut BIO, cmd: c_int, fp: BIO_info_cb) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { super::null::nullf_callback_ctrl(b, cmd, fp) }
    }
}

ffi_callback! {
    /// `nbiof_gets`: the next BIO's.
    ///
    /// # Safety
    /// `b` is a live BIO; `buf` is valid for `size` octets of writes.
    pub(crate) unsafe extern "C" fn nbio_gets(b: *mut BIO, buf: *mut c_char, size: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { super::null::nullf_gets(b, buf, size) }
    }
}

ffi_callback! {
    /// `nbiof_puts`: the next BIO's.
    ///
    /// # Safety
    /// `b` is a live BIO; `text` is a NUL-terminated string.
    pub(crate) unsafe extern "C" fn nbio_puts(b: *mut BIO, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { super::null::nullf_puts(b, text) }
    }
}

static NBIO: Builtin = Builtin::new(BIO_TYPE_NBIO_TEST, c"non-blocking IO test filter", || {
    Funcs {
        bputs: Some(nbio_puts),
        bgets: Some(nbio_gets),
        ctrl: Some(nbio_ctrl),
        create: Some(nbio_new),
        destroy: Some(nbio_free),
        callback_ctrl: Some(nbio_callback_ctrl),
        ..Funcs::classic(nbio_write, nbio_read)
    }
});

ffi_export! {
    /// Returns the non-blocking IO test filter's method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_f_nbio_test() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        NBIO.get()
    }
}
