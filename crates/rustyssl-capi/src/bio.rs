//! The BIO, OpenSSL's I/O abstraction (`BIO_new(3)`, `BIO_read(3)`, `BIO_ctrl(3)`,
//! `BIO_push(3)`, `BIO_set_callback_ex(3)`).
//!
//! A BIO is an opaque handle whose type is a [`method`] table of C functions. The core here does
//! what OpenSSL's `bio_lib.c` does around them: argument checks with OpenSSL's errors and return
//! values, the application's callback before and after each operation (with the old-style
//! callback's conversions), the counts of bytes read and written, chains of filters, reference
//! counts, and application data.
//!
//! As OpenSSL's, the fields are the method's to use: `ptr`, `num`, `init`, `shutdown`, and the
//! flags. They're atomics, so even a BIO misused from two threads at once is no data race on
//! the Rust side. No lock is held while a method or callback runs, and each call holds a
//! reference to its BIO, so a callback that frees the BIO doesn't free it under the call.
//!
//! The built-in types are in [`mem`], [`null`], [`file`], and [`fd`]; OpenSSL's printf is in
//! [`print`], with the hex dumps in [`dump`] and the debug callback in [`debug`].

pub(crate) mod debug;
pub(crate) mod dump;
pub(crate) mod fd;
pub(crate) mod file;
pub(crate) mod mem;
pub(crate) mod method;
pub(crate) mod null;
pub(crate) mod print;

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use rustyssl_abi::{
    BIO, BIO_CB_CTRL, BIO_CB_FREE, BIO_CB_GETS, BIO_CB_PUTS, BIO_CB_READ, BIO_CB_RECVMMSG,
    BIO_CB_RETURN, BIO_CB_SENDMMSG, BIO_CB_WRITE, BIO_CTRL_DUP, BIO_CTRL_GET_RPOLL_DESCRIPTOR,
    BIO_CTRL_GET_WPOLL_DESCRIPTOR, BIO_CTRL_PENDING, BIO_CTRL_POP, BIO_CTRL_PUSH,
    BIO_CTRL_SET_CALLBACK, BIO_CTRL_WPENDING, BIO_FLAGS_READ, BIO_FLAGS_RWS,
    BIO_FLAGS_SHOULD_RETRY, BIO_FLAGS_WRITE, BIO_METHOD, BIO_MMSG_CB_ARGS, BIO_MSG,
    BIO_POLL_DESCRIPTOR, BIO_R_INVALID_ARGUMENT, BIO_R_LENGTH_TOO_LONG, BIO_R_UNINITIALIZED,
    BIO_R_UNSUPPORTED_METHOD, BIO_TYPE_MASK, BIO_callback_fn, BIO_callback_fn_ex, BIO_info_cb,
    CRYPTO_EX_DATA, CRYPTO_EX_INDEX_BIO, ERR_LIB_BIO, ERR_R_INIT_FAIL, ERR_R_INTERNAL_ERROR,
    ERR_R_PASSED_NULL_PARAMETER, OSSL_LIB_CTX,
};

use crate::err;
use crate::ex_data::{
    CRYPTO_dup_ex_data, CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data,
    CRYPTO_set_ex_data,
};
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use method::Funcs;

/// A raw pointer stored in a BIO, which the BIO never dereferences itself.
#[derive(Clone, Copy)]
struct Pointer<T>(*mut T);

// SAFETY: the pointer is only handed back to C, whose code decides how it is shared.
unsafe impl<T> Send for Pointer<T> {}
// SAFETY: as above.
unsafe impl<T> Sync for Pointer<T> {}

/// The callbacks, set and read together.
#[derive(Clone, Copy)]
struct Callbacks {
    old: BIO_callback_fn,
    ex: BIO_callback_fn_ex,
    arg: Pointer<c_char>,
}

/// The BIO's application data, at a fixed address for the `CRYPTO_*_ex_data` functions.
struct ExData(UnsafeCell<CRYPTO_EX_DATA>);

// SAFETY: the ex_data functions are the only users, and OpenSSL leaves serializing them to the
// application, as it does for the rest of a BIO.
unsafe impl Send for ExData {}
// SAFETY: as above.
unsafe impl Sync for ExData {}

/// What a `BIO` handle points to: OpenSSL's `struct bio_st`.
pub(crate) struct Bio {
    libctx: Pointer<OSSL_LIB_CTX>,
    method: Pointer<BIO_METHOD>,
    callbacks: Mutex<Callbacks>,
    pub(crate) init: AtomicI32,
    pub(crate) shutdown: AtomicI32,
    flags: AtomicI32,
    retry_reason: AtomicI32,
    pub(crate) num: AtomicI32,
    pub(crate) ptr: AtomicPtr<c_void>,
    next: AtomicPtr<BIO>,
    prev: AtomicPtr<BIO>,
    references: AtomicI32,
    num_read: AtomicU64,
    num_write: AtomicU64,
    ex_data: ExData,
}

handle_type!(BIO => Bio);

impl Bio {
    pub(crate) fn flags(&self) -> c_int {
        self.flags.load(Ordering::Relaxed)
    }

    pub(crate) fn set_flags(&self, flags: c_int) {
        self.flags.fetch_or(flags, Ordering::Relaxed);
    }

    pub(crate) fn clear_flags(&self, flags: c_int) {
        self.flags.fetch_and(!flags, Ordering::Relaxed);
    }

    /// `BIO_clear_retry_flags`.
    pub(crate) fn clear_retry_flags(&self) {
        self.clear_flags(BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY);
    }

    /// `BIO_set_retry_read`.
    pub(crate) fn set_retry_read(&self) {
        self.set_flags(BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY);
    }

    /// `BIO_set_retry_write`.
    pub(crate) fn set_retry_write(&self) {
        self.set_flags(BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY);
    }

    pub(crate) fn next(&self) -> *mut BIO {
        self.next.load(Ordering::Relaxed)
    }

    fn callbacks(&self) -> Callbacks {
        *self
            .callbacks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn update_callbacks(&self, change: impl FnOnce(&mut Callbacks)) {
        change(
            &mut self
                .callbacks
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
    }

    /// OpenSSL's `HAS_CALLBACK`.
    fn has_callback(&self) -> bool {
        let callbacks = self.callbacks();
        callbacks.old.is_some() || callbacks.ex.is_some()
    }

    fn ex_data(&self) -> *mut CRYPTO_EX_DATA {
        self.ex_data.0.get()
    }

    /// The method's functions; none if it has no method.
    fn funcs(&self) -> Option<Funcs> {
        // SAFETY: a BIO's method outlives it (BIO_meth_free(3)).
        unsafe { method::method(self.method.0) }.map(method::Method::funcs)
    }
}

/// The BIO behind `bio`, or `None` for null.
///
/// # Safety
/// `bio` is null or a live BIO that outlives `'a`.
pub(crate) unsafe fn object<'a>(bio: *const BIO) -> Option<&'a Bio> {
    // SAFETY: the caller's guarantee.
    unsafe { BIO::get(bio) }
}

/// The functions of `bio`'s method.
///
/// # Safety
/// `bio` is null or a live BIO.
pub(crate) unsafe fn funcs(bio: *const BIO) -> Option<Funcs> {
    // SAFETY: the caller's guarantee.
    unsafe { object(bio) }?.funcs()
}

/// A C `long` as an `int`, wrapping as C's conversion does.
fn wrap_int(value: c_long) -> c_int {
    u32::try_from(value & 0xFFFF_FFFF).map_or(0, u32::cast_signed)
}

/// OpenSSL's `HAS_LEN_OPER`.
fn has_length(oper: c_int) -> bool {
    oper == BIO_CB_READ || oper == BIO_CB_WRITE || oper == BIO_CB_GETS
}

/// Calls the BIO's callback (OpenSSL's `bio_call_callback`): the `_ex` one if set, else the
/// old-style one, which gets the length in `argi` and, on return, the count in `ret`.
///
/// # Safety
/// `bio` is a live BIO; `processed` is null or valid for reads and writes.
#[expect(clippy::too_many_arguments, reason = "the callback's arguments")]
unsafe fn call_callback(
    bio: *mut BIO,
    object: &Bio,
    oper: c_int,
    argp: *const c_char,
    len: usize,
    mut argi: c_int,
    argl: c_long,
    mut inret: c_long,
    processed: *mut usize,
) -> c_long {
    let callbacks = object.callbacks();
    if let Some(ex) = callbacks.ex {
        // SAFETY: the application's callback takes these arguments.
        return unsafe { ex(bio, oper, argp, len, argi, argl, wrap_int(inret), processed) };
    }
    let Some(old) = callbacks.old else {
        return inret;
    };
    let bare = oper & !BIO_CB_RETURN;
    if has_length(bare) {
        let Ok(len) = c_int::try_from(len) else {
            return -1;
        };
        argi = len;
    }
    let returning = oper & BIO_CB_RETURN != 0 && bare != BIO_CB_CTRL;
    if inret > 0 && returning && !processed.is_null() {
        // SAFETY: the caller's guarantee.
        let done = unsafe { processed.read() };
        let Some(done) = c_long::try_from(done)
            .ok()
            .filter(|d| *d <= c_long::from(c_int::MAX))
        else {
            return -1;
        };
        inret = done;
    }
    // SAFETY: the application's callback takes these arguments.
    let mut ret = unsafe { old(bio, oper, argp, argi, argl, inret) };
    if ret > 0 && returning && !processed.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { processed.write(usize::try_from(ret).unwrap_or(0)) };
        ret = 1;
    }
    ret
}

/// OpenSSL's `bio_read_intern`.
///
/// # Safety
/// `bio` is null or a live BIO; `data` is valid for `dlen` bytes of writes; `readbytes` is
/// valid for a write.
pub(crate) unsafe fn read(
    bio: *mut BIO,
    data: *mut c_void,
    dlen: usize,
    readbytes: *mut usize,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(held) = (unsafe { BIO::hold(bio) }) else {
        err::raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER, "bio_read_intern");
        return -1;
    };
    let Some(bread) = held.funcs().and_then(|f| f.bread) else {
        err::raise(ERR_LIB_BIO, BIO_R_UNSUPPORTED_METHOD, "bio_read_intern");
        return -2;
    };
    if held.has_callback() {
        // SAFETY: the caller's guarantee about `bio`.
        let ret = unsafe {
            call_callback(
                bio,
                &held,
                BIO_CB_READ,
                data.cast(),
                dlen,
                0,
                0,
                1,
                ptr::null_mut(),
            )
        };
        if ret <= 0 {
            return wrap_int(ret);
        }
    }
    if held.init.load(Ordering::Relaxed) == 0 {
        err::raise(ERR_LIB_BIO, BIO_R_UNINITIALIZED, "bio_read_intern");
        return -1;
    }
    // SAFETY: the caller's guarantee; the method's function takes these arguments.
    let mut ret = unsafe { bread(bio, data.cast(), dlen, readbytes) };
    if ret > 0 {
        // SAFETY: the method wrote the count.
        let done = unsafe { readbytes.read() };
        held.num_read
            .fetch_add(u64::try_from(done).unwrap_or(0), Ordering::Relaxed);
    }
    if held.has_callback() {
        // SAFETY: as above.
        let r = unsafe {
            call_callback(
                bio,
                &held,
                BIO_CB_READ | BIO_CB_RETURN,
                data.cast(),
                dlen,
                0,
                0,
                c_long::from(ret),
                readbytes,
            )
        };
        ret = wrap_int(r);
    }
    // SAFETY: as above.
    if ret > 0 && unsafe { readbytes.read() } > dlen {
        err::raise(ERR_LIB_BIO, ERR_R_INTERNAL_ERROR, "bio_read_intern");
        return -1;
    }
    ret
}

/// OpenSSL's `bio_write_intern`.
///
/// # Safety
/// `bio` is null or a live BIO; `data` is valid for `dlen` bytes of reads; `written` is null or
/// valid for a write.
pub(crate) unsafe fn write(
    bio: *mut BIO,
    data: *const c_void,
    dlen: usize,
    written: *mut usize,
) -> c_int {
    if !written.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { written.write(0) };
    }
    // SAFETY: the caller's guarantee.
    let Some(held) = (unsafe { BIO::hold(bio) }) else {
        return 0;
    };
    let Some(bwrite) = held.funcs().and_then(|f| f.bwrite) else {
        err::raise(ERR_LIB_BIO, BIO_R_UNSUPPORTED_METHOD, "bio_write_intern");
        return -2;
    };
    if held.has_callback() {
        // SAFETY: the caller's guarantee about `bio`.
        let ret = unsafe {
            call_callback(
                bio,
                &held,
                BIO_CB_WRITE,
                data.cast(),
                dlen,
                0,
                0,
                1,
                ptr::null_mut(),
            )
        };
        if ret <= 0 {
            return wrap_int(ret);
        }
    }
    if held.init.load(Ordering::Relaxed) == 0 {
        err::raise(ERR_LIB_BIO, BIO_R_UNINITIALIZED, "bio_write_intern");
        return -1;
    }
    let mut done: usize = 0;
    // SAFETY: the caller's guarantee; the method's function takes these arguments.
    let mut ret = unsafe { bwrite(bio, data.cast(), dlen, &raw mut done) };
    if ret > 0 {
        held.num_write
            .fetch_add(u64::try_from(done).unwrap_or(0), Ordering::Relaxed);
    }
    if held.has_callback() {
        // SAFETY: as above.
        let r = unsafe {
            call_callback(
                bio,
                &held,
                BIO_CB_WRITE | BIO_CB_RETURN,
                data.cast(),
                dlen,
                0,
                0,
                c_long::from(ret),
                &raw mut done,
            )
        };
        ret = wrap_int(r);
    }
    if !written.is_null() {
        // SAFETY: as above.
        unsafe { written.write(done) };
    }
    ret
}

/// `BIO_ctrl`.
///
/// # Safety
/// `bio` is null or a live BIO; `parg` is what the command expects.
pub(crate) unsafe fn ctrl(bio: *mut BIO, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long {
    // SAFETY: the caller's guarantee.
    let Some(held) = (unsafe { BIO::hold(bio) }) else {
        return -1;
    };
    let Some(ctrl) = held.funcs().and_then(|f| f.ctrl) else {
        err::raise(ERR_LIB_BIO, BIO_R_UNSUPPORTED_METHOD, "BIO_ctrl");
        return -2;
    };
    if held.has_callback() {
        // SAFETY: the caller's guarantee about `bio`.
        let ret = unsafe {
            call_callback(
                bio,
                &held,
                BIO_CB_CTRL,
                parg.cast(),
                0,
                cmd,
                larg,
                1,
                ptr::null_mut(),
            )
        };
        if ret <= 0 {
            return ret;
        }
    }
    // SAFETY: the caller's guarantee; the method's function takes these arguments.
    let ret = unsafe { ctrl(bio, cmd, larg, parg) };
    if held.has_callback() {
        // SAFETY: as above.
        return unsafe {
            call_callback(
                bio,
                &held,
                BIO_CB_CTRL | BIO_CB_RETURN,
                parg.cast(),
                0,
                cmd,
                larg,
                ret,
                ptr::null_mut(),
            )
        };
    }
    ret
}

/// `BIO_puts`.
///
/// # Safety
/// `bio` is null or a live BIO; `buf` is what the method expects (a NUL-terminated string).
pub(crate) unsafe fn puts(bio: *mut BIO, buf: *const c_char) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(held) = (unsafe { BIO::hold(bio) }) else {
        err::raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER, "BIO_puts");
        return -1;
    };
    let Some(bputs) = held.funcs().and_then(|f| f.bputs) else {
        err::raise(ERR_LIB_BIO, BIO_R_UNSUPPORTED_METHOD, "BIO_puts");
        return -2;
    };
    if held.has_callback() {
        // SAFETY: the caller's guarantee about `bio`.
        let ret =
            unsafe { call_callback(bio, &held, BIO_CB_PUTS, buf, 0, 0, 0, 1, ptr::null_mut()) };
        if ret <= 0 {
            return wrap_int(ret);
        }
    }
    if held.init.load(Ordering::Relaxed) == 0 {
        err::raise(ERR_LIB_BIO, BIO_R_UNINITIALIZED, "BIO_puts");
        return -1;
    }
    // SAFETY: the caller's guarantee; the method's function takes these arguments.
    let mut ret = unsafe { bputs(bio, buf) };
    let mut written: usize = 0;
    if ret > 0 {
        written = usize::try_from(ret).unwrap_or(0);
        held.num_write
            .fetch_add(u64::try_from(written).unwrap_or(0), Ordering::Relaxed);
        ret = 1;
    }
    if held.has_callback() {
        // SAFETY: as above.
        let r = unsafe {
            call_callback(
                bio,
                &held,
                BIO_CB_PUTS | BIO_CB_RETURN,
                buf,
                0,
                0,
                0,
                c_long::from(ret),
                &raw mut written,
            )
        };
        ret = wrap_int(r);
    }
    if ret > 0 {
        let Ok(written) = c_int::try_from(written) else {
            err::raise(ERR_LIB_BIO, BIO_R_LENGTH_TOO_LONG, "BIO_puts");
            return -1;
        };
        ret = written;
    }
    ret
}

/// `BIO_gets`.
///
/// # Safety
/// `bio` is null or a live BIO; `buf` is valid for `size` bytes of writes.
pub(crate) unsafe fn gets(bio: *mut BIO, buf: *mut c_char, size: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(held) = (unsafe { BIO::hold(bio) }) else {
        err::raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER, "BIO_gets");
        return -1;
    };
    let Some(bgets) = held.funcs().and_then(|f| f.bgets) else {
        err::raise(ERR_LIB_BIO, BIO_R_UNSUPPORTED_METHOD, "BIO_gets");
        return -2;
    };
    let Ok(len) = usize::try_from(size) else {
        err::raise(ERR_LIB_BIO, BIO_R_INVALID_ARGUMENT, "BIO_gets");
        return -1;
    };
    if held.has_callback() {
        // SAFETY: the caller's guarantee about `bio`.
        let ret =
            unsafe { call_callback(bio, &held, BIO_CB_GETS, buf, len, 0, 0, 1, ptr::null_mut()) };
        if ret <= 0 {
            return wrap_int(ret);
        }
    }
    if held.init.load(Ordering::Relaxed) == 0 {
        err::raise(ERR_LIB_BIO, BIO_R_UNINITIALIZED, "BIO_gets");
        return -1;
    }
    // SAFETY: the caller's guarantee; the method's function takes these arguments.
    let mut ret = unsafe { bgets(bio, buf, size) };
    let mut readbytes: usize = 0;
    if ret > 0 {
        readbytes = usize::try_from(ret).unwrap_or(0);
        ret = 1;
    }
    if held.has_callback() {
        // SAFETY: as above.
        let r = unsafe {
            call_callback(
                bio,
                &held,
                BIO_CB_GETS | BIO_CB_RETURN,
                buf,
                len,
                0,
                0,
                c_long::from(ret),
                &raw mut readbytes,
            )
        };
        ret = wrap_int(r);
    }
    if ret > 0 {
        ret = if readbytes > len {
            -1
        } else {
            c_int::try_from(readbytes).unwrap_or(-1)
        };
    }
    ret
}

/// Creates a BIO of `method`'s type (`BIO_new_ex`): runs the ex_data new callbacks, then the
/// method's `create`; a type without one starts initialized.
///
/// # Safety
/// `method` is null or a live method handle that outlives the BIO.
pub(crate) unsafe fn new(libctx: *mut OSSL_LIB_CTX, method: *const BIO_METHOD) -> *mut BIO {
    // SAFETY: the caller's guarantee.
    let Some(m) = (unsafe { method::method(method) }) else {
        return ptr::null_mut();
    };
    let create = m.funcs().create;
    let bio = BIO::new_handle(Bio {
        libctx: Pointer(libctx),
        method: Pointer(method.cast_mut()),
        callbacks: Mutex::new(Callbacks {
            old: None,
            ex: None,
            arg: Pointer(ptr::null_mut()),
        }),
        init: AtomicI32::new(0),
        shutdown: AtomicI32::new(1),
        flags: AtomicI32::new(0),
        retry_reason: AtomicI32::new(0),
        num: AtomicI32::new(0),
        ptr: AtomicPtr::new(ptr::null_mut()),
        next: AtomicPtr::new(ptr::null_mut()),
        prev: AtomicPtr::new(ptr::null_mut()),
        references: AtomicI32::new(1),
        num_read: AtomicU64::new(0),
        num_write: AtomicU64::new(0),
        ex_data: ExData(UnsafeCell::new(CRYPTO_EX_DATA {
            ctx: ptr::null_mut(),
            sk: ptr::null_mut(),
        })),
    });
    // SAFETY: just created.
    let Some(object) = (unsafe { object(bio) }) else {
        return ptr::null_mut();
    };
    // SAFETY: the BIO's own ex_data.
    if unsafe { CRYPTO_new_ex_data(CRYPTO_EX_INDEX_BIO, bio.cast(), object.ex_data()) } == 0 {
        // SAFETY: nothing else has the new handle.
        unsafe { BIO::free(bio) };
        return ptr::null_mut();
    }
    match create {
        Some(create) => {
            // SAFETY: the method's function takes the new BIO.
            if unsafe { create(bio) } == 0 {
                err::raise(ERR_LIB_BIO, ERR_R_INIT_FAIL, "BIO_new_ex");
                // SAFETY: as above.
                unsafe { CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, bio.cast(), object.ex_data()) };
                // SAFETY: as above.
                unsafe { BIO::free(bio) };
                return ptr::null_mut();
            }
        }
        None => object.init.store(1, Ordering::Relaxed),
    }
    bio
}

/// `BIO_free`: drops a reference; with the last one, runs the callback (which may refuse with
/// 0), the method's `destroy`, and the ex_data free callbacks, then frees the BIO.
///
/// # Safety
/// `bio` is null or a live BIO whose reference the caller gives up.
pub(crate) unsafe fn free(bio: *mut BIO) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(held) = (unsafe { BIO::hold(bio) }) else {
        return 0;
    };
    let left = held.references.fetch_sub(1, Ordering::AcqRel) - 1;
    if left > 0 {
        return 1;
    }
    if left < 0 {
        return 0;
    }
    if held.has_callback() {
        // SAFETY: the caller's guarantee about `bio`.
        let ret = unsafe {
            call_callback(
                bio,
                &held,
                BIO_CB_FREE,
                ptr::null(),
                0,
                0,
                0,
                1,
                ptr::null_mut(),
            )
        };
        if wrap_int(ret) <= 0 {
            return 0;
        }
    }
    if let Some(destroy) = held.funcs().and_then(|f| f.destroy) {
        // SAFETY: the method's function takes the BIO.
        unsafe { destroy(bio) };
    }
    // SAFETY: the BIO's own ex_data.
    unsafe { CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, bio.cast(), held.ex_data()) };
    // SAFETY: the BIO's last reference; the hold keeps it alive until this returns.
    unsafe { BIO::free(bio) };
    1
}

ffi_export! {
    /// Returns a new BIO of `method`'s type in `libctx`; null for a null method (OpenSSL's would
    /// crash, docs/DEVIATIONS.md) or if the method's `create` fails.
    ///
    /// # Safety
    /// `method` is null or a live method that outlives the BIO.
    pub unsafe extern "C" fn BIO_new_ex(libctx: *mut OSSL_LIB_CTX, method: *const BIO_METHOD) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { new(libctx, method) }
    }
}

ffi_export! {
    /// `BIO_new_ex` in the default library context.
    ///
    /// # Safety
    /// As for `BIO_new_ex`.
    pub unsafe extern "C" fn BIO_new(type_: *const BIO_METHOD) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { new(ptr::null_mut(), type_) }
    }
}

ffi_export! {
    /// Drops a reference to the BIO, freeing it with the last. Returns 1, or 0 for null or if
    /// the callback refuses.
    ///
    /// # Safety
    /// `a` is null or a live BIO whose reference the caller gives up.
    pub unsafe extern "C" fn BIO_free(a: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { free(a) }
    }
}

ffi_export! {
    /// `BIO_free` without a result.
    ///
    /// # Safety
    /// As for `BIO_free`.
    pub unsafe extern "C" fn BIO_vfree(a: *mut BIO)
    where failure = (), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { free(a) };
    }
}

ffi_export! {
    /// Frees each BIO of a chain in turn, stopping after one that had another reference.
    ///
    /// # Safety
    /// `bio` is null or the first of a chain of live BIOs whose references the caller gives up.
    pub unsafe extern "C" fn BIO_free_all(bio: *mut BIO)
    where failure = (), library = ERR_LIB_BIO
    {
        let mut at = bio;
        // SAFETY: the caller's guarantee, for each BIO of the chain.
        while let Some(object) = unsafe { object(at) } {
            let references = object.references.load(Ordering::Acquire);
            let next = object.next();
            // SAFETY: as above.
            unsafe { free(at) };
            if references > 1 {
                break;
            }
            at = next;
        }
    }
}

ffi_export! {
    /// Adds a reference to the BIO. Returns 1, or 0 for null.
    ///
    /// # Safety
    /// `a` is null or a live BIO.
    pub unsafe extern "C" fn BIO_up_ref(a: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { object(a) }.map_or(0, |o| c_int::from(o.references.fetch_add(1, Ordering::AcqRel) + 1 > 1))
    }
}

/// Defines simple accessors for a BIO field. A null BIO reads as 0 and ignores writes, where
/// OpenSSL's would crash (docs/DEVIATIONS.md).
macro_rules! field_accessors {
    ($(
        $field:ident,
        pub unsafe extern "C" fn $set:ident(a: *mut BIO, value: c_int);
        pub unsafe extern "C" fn $get:ident(a: *mut BIO) -> c_int;
    )*) => {$(
        ffi_export! {
            /// Sets the field of the BIO, for its method's use.
            ///
            /// # Safety
            /// `a` is null or a live BIO.
            pub unsafe extern "C" fn $set(a: *mut BIO, value: c_int)
            where failure = (), library = ERR_LIB_BIO
            {
                // SAFETY: the caller's guarantee.
                if let Some(o) = unsafe { object(a) } {
                    o.$field.store(value, Ordering::Relaxed);
                }
            }
        }

        ffi_export! {
            /// Returns the field of the BIO.
            ///
            /// # Safety
            /// `a` is null or a live BIO.
            pub unsafe extern "C" fn $get(a: *mut BIO) -> c_int
            where failure = 0, library = ERR_LIB_BIO
            {
                // SAFETY: the caller's guarantee.
                unsafe { object(a) }.map_or(0, |o| o.$field.load(Ordering::Relaxed))
            }
        }
    )*};
}

field_accessors! {
    init,
    pub unsafe extern "C" fn BIO_set_init(a: *mut BIO, value: c_int);
    pub unsafe extern "C" fn BIO_get_init(a: *mut BIO) -> c_int;
    shutdown,
    pub unsafe extern "C" fn BIO_set_shutdown(a: *mut BIO, value: c_int);
    pub unsafe extern "C" fn BIO_get_shutdown(a: *mut BIO) -> c_int;
    retry_reason,
    pub unsafe extern "C" fn BIO_set_retry_reason(a: *mut BIO, value: c_int);
    pub unsafe extern "C" fn BIO_get_retry_reason(a: *mut BIO) -> c_int;
}

ffi_export! {
    /// Sets the BIO's data pointer, for its method's use.
    ///
    /// # Safety
    /// `a` is null or a live BIO.
    pub unsafe extern "C" fn BIO_set_data(a: *mut BIO, ptr: *mut c_void)
    where failure = (), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        if let Some(o) = unsafe { object(a) } {
            o.ptr.store(ptr, Ordering::Relaxed);
        }
    }
}

ffi_export! {
    /// Returns the BIO's data pointer.
    ///
    /// # Safety
    /// `a` is null or a live BIO.
    pub unsafe extern "C" fn BIO_get_data(a: *mut BIO) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { object(a) }.map_or(ptr::null_mut(), |o| o.ptr.load(Ordering::Relaxed))
    }
}

ffi_export! {
    /// Sets flags on the BIO.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub unsafe extern "C" fn BIO_set_flags(b: *mut BIO, flags: c_int)
    where failure = (), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        if let Some(o) = unsafe { object(b) } {
            o.set_flags(flags);
        }
    }
}

ffi_export! {
    /// Clears flags on the BIO.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub unsafe extern "C" fn BIO_clear_flags(b: *mut BIO, flags: c_int)
    where failure = (), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        if let Some(o) = unsafe { object(b) } {
            o.clear_flags(flags);
        }
    }
}

ffi_export! {
    /// Returns which of `flags` are set on the BIO.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub unsafe extern "C" fn BIO_test_flags(b: *const BIO, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { object(b) }.map_or(0, |o| o.flags() & flags)
    }
}

ffi_export! {
    /// Returns the old-style callback (deprecated).
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub unsafe extern "C" fn BIO_get_callback(b: *const BIO) -> BIO_callback_fn
    where failure = None, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { object(b) }.and_then(|o| o.callbacks().old)
    }
}

ffi_export! {
    /// Sets the old-style callback (deprecated).
    ///
    /// # Safety
    /// `b` is null or a live BIO; `cb` is null or a callback of the documented type.
    pub unsafe extern "C" fn BIO_set_callback(b: *mut BIO, cb: BIO_callback_fn)
    where failure = (), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        if let Some(o) = unsafe { object(b) } {
            o.update_callbacks(|c| c.old = cb);
        }
    }
}

ffi_export! {
    /// Returns the callback.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub unsafe extern "C" fn BIO_get_callback_ex(b: *const BIO) -> BIO_callback_fn_ex
    where failure = None, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { object(b) }.and_then(|o| o.callbacks().ex)
    }
}

ffi_export! {
    /// Sets the callback, which runs before and after each operation and takes precedence over
    /// an old-style one.
    ///
    /// # Safety
    /// `b` is null or a live BIO; `cb` is null or a callback of the documented type.
    pub unsafe extern "C" fn BIO_set_callback_ex(b: *mut BIO, cb: BIO_callback_fn_ex)
    where failure = (), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        if let Some(o) = unsafe { object(b) } {
            o.update_callbacks(|c| c.ex = cb);
        }
    }
}

ffi_export! {
    /// Sets the pointer the callback can fetch with `BIO_get_callback_arg`.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub unsafe extern "C" fn BIO_set_callback_arg(b: *mut BIO, arg: *mut c_char)
    where failure = (), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        if let Some(o) = unsafe { object(b) } {
            o.update_callbacks(|c| c.arg = Pointer(arg));
        }
    }
}

ffi_export! {
    /// Returns the callback's pointer.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub unsafe extern "C" fn BIO_get_callback_arg(b: *const BIO) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { object(b) }.map_or(ptr::null_mut(), |o| o.callbacks().arg.0)
    }
}

ffi_export! {
    /// Returns the name of the BIO's type.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub unsafe extern "C" fn BIO_method_name(b: *const BIO) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee; a BIO's method outlives it.
        unsafe { object(b) }
            .and_then(|o| unsafe { method::method(o.method.0) })
            .map_or(ptr::null(), method::Method::name)
    }
}

ffi_export! {
    /// Returns the BIO's type number (`BIO_TYPE_*`).
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub unsafe extern "C" fn BIO_method_type(b: *const BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee; a BIO's method outlives it.
        unsafe { object(b) }
            .and_then(|o| unsafe { method::method(o.method.0) })
            .map_or(0, method::Method::kind)
    }
}

ffi_export! {
    /// Reads up to `dlen` bytes. Returns the count, 0 or less for none (see
    /// `BIO_should_retry`), 0 for a negative `dlen`, or -2 if the type can't read.
    ///
    /// # Safety
    /// `b` is null or a live BIO; `data` is valid for `dlen` bytes of writes.
    pub unsafe extern "C" fn BIO_read(b: *mut BIO, data: *mut c_void, dlen: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let Ok(len) = usize::try_from(dlen) else {
            return 0;
        };
        let mut done: usize = 0;
        // SAFETY: the caller's guarantee.
        let ret = unsafe { read(b, data, len, &raw mut done) };
        if ret > 0 { c_int::try_from(done).unwrap_or(c_int::MAX) } else { ret }
    }
}

ffi_export! {
    /// Reads up to `dlen` bytes, storing the count in `*readbytes`. Returns 1 if any were read.
    ///
    /// # Safety
    /// `b` is null or a live BIO; `data` is valid for `dlen` bytes of writes; `readbytes` is
    /// null or valid for a write.
    pub unsafe extern "C" fn BIO_read_ex(b: *mut BIO, data: *mut c_void, dlen: usize, readbytes: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        let mut local: usize = 0;
        let out = if readbytes.is_null() { &raw mut local } else { readbytes };
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { read(b, data, dlen, out) } > 0)
    }
}

ffi_export! {
    /// Writes `dlen` bytes. Returns the count written, 0 or less for none (see
    /// `BIO_should_retry`), 0 for a zero or negative `dlen` or a null BIO, or -2 if the type
    /// can't write.
    ///
    /// # Safety
    /// `b` is null or a live BIO; `data` is valid for `dlen` bytes of reads.
    pub unsafe extern "C" fn BIO_write(b: *mut BIO, data: *const c_void, dlen: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let Some(len) = usize::try_from(dlen).ok().filter(|l| *l > 0) else {
            return 0;
        };
        let mut done: usize = 0;
        // SAFETY: the caller's guarantee.
        let ret = unsafe { write(b, data, len, &raw mut done) };
        if ret > 0 { c_int::try_from(done).unwrap_or(c_int::MAX) } else { ret }
    }
}

ffi_export! {
    /// Writes `dlen` bytes, storing the count in `*written`. Returns 1 if any were written, or
    /// if `dlen` is 0.
    ///
    /// # Safety
    /// `b` is null or a live BIO; `data` is valid for `dlen` bytes of reads; `written` is null
    /// or valid for a write.
    pub unsafe extern "C" fn BIO_write_ex(b: *mut BIO, data: *const c_void, dlen: usize, written: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let ok = unsafe { write(b, data, dlen, written) } > 0;
        c_int::from(ok || (!b.is_null() && dlen == 0))
    }
}

ffi_export! {
    /// Writes a NUL-terminated string. Returns its length, or 0 or less on failure.
    ///
    /// # Safety
    /// `b` is null or a live BIO; `buf` is a NUL-terminated string.
    pub unsafe extern "C" fn BIO_puts(b: *mut BIO, buf: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { puts(b, buf) }
    }
}

ffi_export! {
    /// Reads a line of at most `size - 1` bytes into `buf`, NUL-terminated. Returns its length,
    /// or 0 or less on failure.
    ///
    /// # Safety
    /// `b` is null or a live BIO; `buf` is valid for `size` bytes of writes.
    pub unsafe extern "C" fn BIO_gets(b: *mut BIO, buf: *mut c_char, size: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { gets(b, buf, size) }
    }
}

ffi_export! {
    /// Reads a line a byte at a time with `BIO_read`, up to and including the newline, into
    /// `buf` (at most `size - 1` bytes, NUL-terminated). Returns its length, or the failed read's
    /// result unless at EOF; -1 for a null BIO or buffer or a size of 0 or less.
    ///
    /// # Safety
    /// `bio` is null or a live BIO; `buf` is null or valid for `size` bytes of writes.
    pub unsafe extern "C" fn BIO_get_line(bio: *mut BIO, buf: *mut c_char, size: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if buf.is_null() {
            err::raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER, "BIO_get_line");
            return -1;
        }
        let Some(size) = usize::try_from(size).ok().filter(|s| *s > 0) else {
            err::raise(ERR_LIB_BIO, BIO_R_INVALID_ARGUMENT, "BIO_get_line");
            return -1;
        };
        // SAFETY: the caller's guarantee; at least one byte.
        unsafe { buf.write(0) };
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(bio) }) else {
            err::raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER, "BIO_get_line");
            return -1;
        };
        if object.init.load(Ordering::Relaxed) == 0 {
            err::raise(ERR_LIB_BIO, BIO_R_UNINITIALIZED, "BIO_get_line");
            return -1;
        }
        let mut used = 0;
        let mut ret = 0;
        while used + 1 < size {
            let at = buf.wrapping_add(used);
            // SAFETY: `at` is inside the caller's buffer.
            ret = unsafe { BIO_read(bio, at.cast(), 1) };
            if ret <= 0 {
                break;
            }
            used += 1;
            // SAFETY: as above; just read.
            if unsafe { at.read() } == c_char::from_ne_bytes(*b"\n") {
                break;
            }
        }
        // SAFETY: `used < size`.
        unsafe { buf.wrapping_add(used).write(0) };
        // SAFETY: the caller's guarantee.
        if ret > 0 || unsafe { ctrl(bio, rustyssl_abi::BIO_CTRL_EOF, 0, ptr::null_mut()) } != 0 {
            c_int::try_from(used).unwrap_or(c_int::MAX)
        } else {
            ret
        }
    }
}

ffi_export! {
    /// Writes `indent` spaces (at most `max`, none if negative). Returns 1, or 0 if a write
    /// failed.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub unsafe extern "C" fn BIO_indent(b: *mut BIO, indent: c_int, max: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        for _ in 0..indent.max(0).min(max) {
            // SAFETY: the caller's guarantee.
            if unsafe { puts(b, c" ".as_ptr()) } != 1 {
                return 0;
            }
        }
        1
    }
}

ffi_export! {
    /// Sends a control command to the BIO's type. Returns its result, -1 for a null BIO, or -2
    /// if the type has no controls.
    ///
    /// # Safety
    /// `b` is null or a live BIO; `parg` is what the command expects.
    pub unsafe extern "C" fn BIO_ctrl(b: *mut BIO, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctrl(b, cmd, larg, parg) }
    }
}

ffi_export! {
    /// `BIO_ctrl` with a pointer to an `int` holding `iarg`.
    ///
    /// # Safety
    /// `b` is null or a live BIO, and the command takes a pointer to an `int`.
    pub unsafe extern "C" fn BIO_int_ctrl(b: *mut BIO, cmd: c_int, larg: c_long, iarg: c_int) -> c_long
    where failure = -1, library = ERR_LIB_BIO
    {
        let mut value = iarg;
        // SAFETY: the caller's guarantee; `value` lives through the call.
        unsafe { ctrl(b, cmd, larg, (&raw mut value).cast()) }
    }
}

ffi_export! {
    /// `BIO_ctrl` storing a pointer: returns it, or null if the command fails.
    ///
    /// # Safety
    /// `b` is null or a live BIO, and the command stores a pointer.
    pub unsafe extern "C" fn BIO_ptr_ctrl(b: *mut BIO, cmd: c_int, larg: c_long) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        let mut p: *mut c_void = ptr::null_mut();
        // SAFETY: the caller's guarantee; `p` lives through the call.
        if unsafe { ctrl(b, cmd, larg, (&raw mut p).cast()) } <= 0 {
            return ptr::null_mut();
        }
        p
    }
}

ffi_export! {
    /// Sets a callback through the type's `callback_ctrl` (only `BIO_CTRL_SET_CALLBACK`). Returns
    /// its result, or -2 for a null BIO, another command, or a type without one.
    ///
    /// # Safety
    /// `b` is null or a live BIO; `fp` is null or a callback of the documented type.
    pub unsafe extern "C" fn BIO_callback_ctrl(b: *mut BIO, cmd: c_int, fp: BIO_info_cb) -> c_long
    where failure = -2, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(held) = (unsafe { BIO::hold(b) }) else {
            return -2;
        };
        let callback_ctrl = held.funcs().and_then(|f| f.callback_ctrl);
        let Some(callback_ctrl) = callback_ctrl.filter(|_| cmd == BIO_CTRL_SET_CALLBACK) else {
            err::raise(ERR_LIB_BIO, BIO_R_UNSUPPORTED_METHOD, "BIO_callback_ctrl");
            return -2;
        };
        let mut fp_copy = fp;
        let argp = (&raw mut fp_copy).cast::<c_char>();
        if held.has_callback() {
            // SAFETY: the caller's guarantee about `b`.
            let ret = unsafe { call_callback(b, &held, BIO_CB_CTRL, argp, 0, cmd, 0, 1, ptr::null_mut()) };
            if ret <= 0 {
                return ret;
            }
        }
        // SAFETY: the caller's guarantee; the method's function takes these arguments.
        let ret = unsafe { callback_ctrl(b, cmd, fp) };
        if held.has_callback() {
            // SAFETY: as above.
            return unsafe { call_callback(b, &held, BIO_CB_CTRL | BIO_CB_RETURN, argp, 0, cmd, 0, ret, ptr::null_mut()) };
        }
        ret
    }
}

ffi_export! {
    /// Returns the bytes waiting to be read (`BIO_CTRL_PENDING`), 0 if negative.
    ///
    /// # Safety
    /// `bio` is null or a live BIO.
    pub unsafe extern "C" fn BIO_ctrl_pending(bio: *mut BIO) -> usize
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        usize::try_from(unsafe { ctrl(bio, BIO_CTRL_PENDING, 0, ptr::null_mut()) }).unwrap_or(0)
    }
}

ffi_export! {
    /// Returns the bytes waiting to be written (`BIO_CTRL_WPENDING`), 0 if negative.
    ///
    /// # Safety
    /// `bio` is null or a live BIO.
    pub unsafe extern "C" fn BIO_ctrl_wpending(bio: *mut BIO) -> usize
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        usize::try_from(unsafe { ctrl(bio, BIO_CTRL_WPENDING, 0, ptr::null_mut()) }).unwrap_or(0)
    }
}

ffi_export! {
    /// Appends `bio` to the end of `b`'s chain and tells `b` (`BIO_CTRL_PUSH`). Returns `b`, or
    /// `bio` if `b` is null.
    ///
    /// # Safety
    /// `b` and `bio` are null or live BIOs.
    pub unsafe extern "C" fn BIO_push(b: *mut BIO, bio: *mut BIO) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(mut last) = (unsafe { object(b) }) else {
            return bio;
        };
        let mut last_ptr = b;
        // SAFETY: the caller's guarantee, for each BIO of the chain.
        while let Some(next) = unsafe { object(last.next()) } {
            last_ptr = last.next();
            last = next;
        }
        last.next.store(bio, Ordering::Relaxed);
        // SAFETY: as above.
        if let Some(added) = unsafe { object(bio) } {
            added.prev.store(last_ptr, Ordering::Relaxed);
        }
        // SAFETY: as above.
        unsafe { ctrl(b, BIO_CTRL_PUSH, 0, last_ptr.cast()) };
        b
    }
}

ffi_export! {
    /// Takes `b` out of its chain (after telling it, `BIO_CTRL_POP`) and returns the BIO after
    /// it.
    ///
    /// # Safety
    /// `b` is null or a live BIO in a chain of live BIOs.
    pub unsafe extern "C" fn BIO_pop(b: *mut BIO) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(held) = (unsafe { BIO::hold(b) }) else {
            return ptr::null_mut();
        };
        let ret = held.next();
        // SAFETY: as above.
        unsafe { ctrl(b, BIO_CTRL_POP, 0, b.cast()) };
        let (next, prev) = (held.next(), held.prev.load(Ordering::Relaxed));
        // SAFETY: as above, for its neighbors.
        if let Some(p) = unsafe { object(prev) } {
            p.next.store(next, Ordering::Relaxed);
        }
        // SAFETY: as above.
        if let Some(n) = unsafe { object(next) } {
            n.prev.store(prev, Ordering::Relaxed);
        }
        held.next.store(ptr::null_mut(), Ordering::Relaxed);
        held.prev.store(ptr::null_mut(), Ordering::Relaxed);
        ret
    }
}

ffi_export! {
    /// Returns the BIO after `b` in its chain, or null.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub unsafe extern "C" fn BIO_next(b: *mut BIO) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { object(b) }.map_or(ptr::null_mut(), Bio::next)
    }
}

ffi_export! {
    /// Sets the BIO after `b` (without linking back, as OpenSSL's doesn't).
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub unsafe extern "C" fn BIO_set_next(b: *mut BIO, next: *mut BIO)
    where failure = (), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        if let Some(o) = unsafe { object(b) } {
            o.next.store(next, Ordering::Relaxed);
        }
    }
}

ffi_export! {
    /// Returns the first BIO of the chain from `bio` whose type is `type_`, or, for a type with
    /// no number in its low byte, whose type has one of its category bits.
    ///
    /// # Safety
    /// `bio` is null or the first of a chain of live BIOs.
    pub unsafe extern "C" fn BIO_find_type(bio: *mut BIO, type_: c_int) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        if bio.is_null() {
            err::raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER, "BIO_find_type");
            return ptr::null_mut();
        }
        let exact = type_ & BIO_TYPE_MASK != 0;
        let mut at = bio;
        // SAFETY: the caller's guarantee, for each BIO of the chain.
        while let Some(object) = unsafe { object(at) } {
            // SAFETY: a BIO's method outlives it.
            if let Some(m) = unsafe { method::method(object.method.0) } {
                let kind = m.kind();
                if (exact && kind == type_) || (!exact && kind & type_ != 0) {
                    return at;
                }
            }
            at = object.next();
        }
        ptr::null_mut()
    }
}

ffi_export! {
    /// Follows the chain from `bio` while BIOs should retry, and returns the last one that
    /// should, with its retry reason in `*reason`.
    ///
    /// # Safety
    /// `bio` is a live BIO in a chain of live BIOs; `reason` is null or valid for a write.
    pub unsafe extern "C" fn BIO_get_retry_BIO(bio: *mut BIO, reason: *mut c_int) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        let mut last = bio;
        let mut at = bio;
        // SAFETY: the caller's guarantee, for each BIO of the chain.
        while let Some(object) = unsafe { object(at) } {
            if object.flags() & BIO_FLAGS_SHOULD_RETRY == 0 {
                break;
            }
            last = at;
            at = object.next();
        }
        if !reason.is_null() {
            // SAFETY: as above.
            let value = unsafe { object(last) }.map_or(0, |o| o.retry_reason.load(Ordering::Relaxed));
            // SAFETY: the caller's guarantee.
            unsafe { reason.write(value) };
        }
        last
    }
}

ffi_export! {
    /// Copies the next BIO's retry flags and reason onto `b`, as filters do after passing an
    /// operation on.
    ///
    /// # Safety
    /// `b` is null or a live BIO whose next BIO is null or live.
    pub unsafe extern "C" fn BIO_copy_next_retry(b: *mut BIO)
    where failure = (), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        if let Some(o) = unsafe { object(b) } {
            copy_next_retry(o);
        }
    }
}

/// `BIO_copy_next_retry` on an object.
pub(crate) fn copy_next_retry(bio: &Bio) {
    // SAFETY: a BIO's next BIO is null or live.
    if let Some(next) = unsafe { object(bio.next()) } {
        bio.set_flags(next.flags() & (BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY));
        bio.retry_reason
            .store(next.retry_reason.load(Ordering::Relaxed), Ordering::Relaxed);
    }
}

ffi_export! {
    /// Copies a chain: a new BIO of each type, with the callbacks, fields, and flags copied and
    /// each type's state copied by `BIO_CTRL_DUP`, and the application data copied. Returns
    /// the copy, or null if a BIO couldn't be copied.
    ///
    /// # Safety
    /// `in_` is null or the first of a chain of live BIOs.
    pub unsafe extern "C" fn BIO_dup_chain(in_: *mut BIO) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        let mut head: *mut BIO = ptr::null_mut();
        let mut tail: *mut BIO = ptr::null_mut();
        let mut at = in_;
        // SAFETY: the caller's guarantee, for each BIO of the chain.
        while let Some(source) = unsafe { object(at) } {
            // SAFETY: as above; a BIO's method outlives it.
            let copy = unsafe { new(source.libctx.0, source.method.0) };
            // SAFETY: just created.
            let Some(target) = (unsafe { object(copy) }) else {
                // SAFETY: the copies made so far.
                unsafe { BIO_free_all(head) };
                return ptr::null_mut();
            };
            target.update_callbacks(|c| *c = source.callbacks());
            target.init.store(source.init.load(Ordering::Relaxed), Ordering::Relaxed);
            target.shutdown.store(source.shutdown.load(Ordering::Relaxed), Ordering::Relaxed);
            target.flags.store(source.flags(), Ordering::Relaxed);
            target.num.store(source.num.load(Ordering::Relaxed), Ordering::Relaxed);
            // SAFETY: as above.
            let duplicated = unsafe { ctrl(at, BIO_CTRL_DUP, 0, copy.cast()) } > 0
                // SAFETY: both BIOs' own ex_data.
                && unsafe { CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_BIO, target.ex_data(), source.ex_data()) } != 0;
            if !duplicated {
                // SAFETY: the new BIO and the copies made so far.
                unsafe { free(copy) };
                // SAFETY: as above.
                unsafe { BIO_free_all(head) };
                return ptr::null_mut();
            }
            if head.is_null() {
                head = copy;
            } else {
                // SAFETY: the last copy made.
                unsafe { BIO_push(tail, copy) };
            }
            tail = copy;
            at = source.next();
        }
        head
    }
}

ffi_export! {
    /// Stores application data at `idx` (`BIO_get_ex_new_index`).
    ///
    /// # Safety
    /// `bio` is null or a live BIO (null fails, docs/DEVIATIONS.md).
    pub unsafe extern "C" fn BIO_set_ex_data(bio: *mut BIO, idx: c_int, data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee; the BIO's own ex_data.
        unsafe { object(bio) }.map_or(0, |o| unsafe { CRYPTO_set_ex_data(o.ex_data(), idx, data) })
    }
}

ffi_export! {
    /// Returns the application data at `idx`, or null.
    ///
    /// # Safety
    /// `bio` is null or a live BIO.
    pub unsafe extern "C" fn BIO_get_ex_data(bio: *const BIO, idx: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee; the BIO's own ex_data.
        unsafe { object(bio) }.map_or(ptr::null_mut(), |o| unsafe { CRYPTO_get_ex_data(o.ex_data(), idx) })
    }
}

ffi_export! {
    /// Returns the bytes read through the BIO so far; 0 for null.
    ///
    /// # Safety
    /// `bio` is null or a live BIO.
    pub unsafe extern "C" fn BIO_number_read(bio: *mut BIO) -> u64
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { object(bio) }.map_or(0, |o| o.num_read.load(Ordering::Relaxed))
    }
}

ffi_export! {
    /// Returns the bytes written through the BIO so far; 0 for null.
    ///
    /// # Safety
    /// `bio` is null or a live BIO.
    pub unsafe extern "C" fn BIO_number_written(bio: *mut BIO) -> u64
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { object(bio) }.map_or(0, |o| o.num_write.load(Ordering::Relaxed))
    }
}

ffi_export! {
    /// Gets the descriptor to poll for reading (`BIO_CTRL_GET_RPOLL_DESCRIPTOR`).
    ///
    /// # Safety
    /// `b` is null or a live BIO; `desc` is valid for a write.
    pub unsafe extern "C" fn BIO_get_rpoll_descriptor(b: *mut BIO, desc: *mut BIO_POLL_DESCRIPTOR) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        wrap_int(unsafe { ctrl(b, BIO_CTRL_GET_RPOLL_DESCRIPTOR, 0, desc.cast()) })
    }
}

ffi_export! {
    /// Gets the descriptor to poll for writing (`BIO_CTRL_GET_WPOLL_DESCRIPTOR`).
    ///
    /// # Safety
    /// `b` is null or a live BIO; `desc` is valid for a write.
    pub unsafe extern "C" fn BIO_get_wpoll_descriptor(b: *mut BIO, desc: *mut BIO_POLL_DESCRIPTOR) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        wrap_int(unsafe { ctrl(b, BIO_CTRL_GET_WPOLL_DESCRIPTOR, 0, desc.cast()) })
    }
}

/// `BIO_sendmmsg` and `BIO_recvmmsg`, which share their checks and callbacks.
///
/// # Safety
/// `b` is null or a live BIO; the messages are as the method expects; `processed` is valid for
/// a write.
#[expect(clippy::too_many_arguments, reason = "the messages' arguments")]
unsafe fn mmsg(
    b: *mut BIO,
    msg: *mut BIO_MSG,
    stride: usize,
    num_msg: usize,
    flags: u64,
    processed: *mut usize,
    send: bool,
    function: &str,
) -> c_int {
    let fail = |reason| {
        if !processed.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { processed.write(0) };
        }
        err::raise(ERR_LIB_BIO, reason, function);
        0
    };
    // SAFETY: the caller's guarantee.
    let Some(held) = (unsafe { BIO::hold(b) }) else {
        return fail(ERR_R_PASSED_NULL_PARAMETER);
    };
    let funcs = held.funcs().unwrap_or_default();
    let Some(f) = (if send {
        funcs.bsendmmsg
    } else {
        funcs.brecvmmsg
    }) else {
        return fail(BIO_R_UNSUPPORTED_METHOD);
    };
    let oper = if send {
        BIO_CB_SENDMMSG
    } else {
        BIO_CB_RECVMMSG
    };
    let mut args = BIO_MMSG_CB_ARGS {
        msg,
        stride,
        num_msg,
        flags,
        msgs_processed: processed,
    };
    let argp = (&raw mut args).cast::<c_char>();
    if held.has_callback() {
        // SAFETY: the caller's guarantee about `b`.
        let ret = unsafe { call_callback(b, &held, oper, argp, 0, 0, 0, 1, ptr::null_mut()) };
        if ret <= 0 {
            return 0;
        }
    }
    if held.init.load(Ordering::Relaxed) == 0 {
        return fail(BIO_R_UNINITIALIZED);
    }
    // SAFETY: the caller's guarantee; the method's function takes these arguments.
    let ret = unsafe { f(b, msg, stride, num_msg, flags, processed) };
    if held.has_callback() {
        let size = usize::try_from(ret).unwrap_or(0);
        // SAFETY: as above.
        let r = unsafe {
            call_callback(
                b,
                &held,
                oper | BIO_CB_RETURN,
                argp,
                size,
                0,
                0,
                c_long::from(ret),
                processed,
            )
        };
        return wrap_int(r);
    }
    ret
}

ffi_export! {
    /// Sends messages through the type's `sendmmsg`, storing how many went in
    /// `*msgs_processed`. Returns 1, or 0 with an error.
    ///
    /// # Safety
    /// `b` is null or a live BIO; `msg` holds `num_msg` messages `stride` bytes apart;
    /// `msgs_processed` is valid for a write.
    pub unsafe extern "C" fn BIO_sendmmsg(b: *mut BIO, msg: *mut BIO_MSG, stride: usize, num_msg: usize, flags: u64, msgs_processed: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { mmsg(b, msg, stride, num_msg, flags, msgs_processed, true, "BIO_sendmmsg") }
    }
}

ffi_export! {
    /// Receives messages through the type's `recvmmsg`, storing how many came in
    /// `*msgs_processed`. Returns 1, or 0 with an error.
    ///
    /// # Safety
    /// As for `BIO_sendmmsg`.
    pub unsafe extern "C" fn BIO_recvmmsg(b: *mut BIO, msg: *mut BIO_MSG, stride: usize, num_msg: usize, flags: u64, msgs_processed: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { mmsg(b, msg, stride, num_msg, flags, msgs_processed, false, "BIO_recvmmsg") }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyssl_abi::{BIO_C_SET_BUF_MEM, BIO_CTRL_EOF};

    fn new_mem() -> *mut BIO {
        // SAFETY: no preconditions.
        let method = unsafe { mem::BIO_s_mem() };
        // SAFETY: the built-in method.
        unsafe { BIO_new(method) }
    }

    /// docs/DEVIATIONS.md: null BIOs and methods, where OpenSSL's accessors would crash.
    #[test]
    fn null_bios_are_ignored() {
        let none = ptr::null_mut::<BIO>();
        // SAFETY: nulls are the case under test, for each call below.
        assert!(unsafe { BIO_new(ptr::null()) }.is_null());
        // SAFETY: as above.
        unsafe { BIO_set_data(none, ptr::null_mut()) };
        // SAFETY: as above.
        assert!(unsafe { BIO_get_data(none) }.is_null());
        // SAFETY: as above.
        unsafe { BIO_set_init(none, 1) };
        // SAFETY: as above.
        assert_eq!(unsafe { BIO_get_init(none) }, 0);
        // SAFETY: as above.
        unsafe { BIO_set_flags(none, 1) };
        // SAFETY: as above.
        assert_eq!(unsafe { BIO_test_flags(none, 1) }, 0);
        // SAFETY: as above.
        assert!(unsafe { BIO_method_name(none) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { BIO_set_ex_data(none, 1, ptr::null_mut()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { BIO_get_retry_reason(none) }, 0);
    }

    /// docs/DEVIATIONS.md: built-in methods, which are read-only data in OpenSSL.
    #[test]
    fn builtin_methods_cant_be_changed_or_freed() {
        // SAFETY: the built-in method.
        let m = unsafe { mem::BIO_s_mem() }.cast_mut();
        // SAFETY: as above.
        assert_eq!(unsafe { method::BIO_meth_set_write(m, None) }, 0);
        // SAFETY: as above; ignored.
        unsafe { method::BIO_meth_free(m) };
        let b = new_mem();
        // SAFETY: a live BIO, for each call below.
        assert_eq!(unsafe { BIO_write(b, c"abc".as_ptr().cast(), 3) }, 3);
        // SAFETY: as above.
        assert_eq!(unsafe { free(b) }, 1);
    }

    /// docs/DEVIATIONS.md: a negative limit, which makes OpenSSL's `BIO_indent` loop about
    /// 2^31 times.
    #[test]
    fn a_negative_indent_limit_writes_nothing() {
        let b = new_mem();
        // SAFETY: a live BIO, for each call below.
        assert_eq!(unsafe { BIO_indent(b, 3, -1) }, 1);
        // SAFETY: as above.
        assert_eq!(unsafe { BIO_ctrl_pending(b) }, 0);
        // SAFETY: as above; a null buffer is the case under test.
        assert_eq!(unsafe { ctrl(b, BIO_C_SET_BUF_MEM, 0, ptr::null_mut()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { BIO_write(b, c"x".as_ptr().cast(), 1) }, 1);
        // SAFETY: as above.
        unsafe { free(b) };
    }

    /// docs/DEVIATIONS.md: a `FILE` BIO with no `FILE` yet fails instead of passing null to
    /// stdio.
    #[test]
    fn a_file_bio_without_a_file_fails() {
        // SAFETY: no preconditions.
        let method = unsafe { file::BIO_s_file() };
        // SAFETY: the built-in method.
        let b = unsafe { BIO_new(method) };
        // SAFETY: a live, uninitialized BIO, for each call below.
        assert_eq!(unsafe { ctrl(b, BIO_CTRL_EOF, 0, ptr::null_mut()) }, 0);
        // SAFETY: as above.
        let at = unsafe { ctrl(b, rustyssl_abi::BIO_C_FILE_TELL, 0, ptr::null_mut()) };
        assert_eq!(at, -1);
        // SAFETY: as above.
        assert!(unsafe { file::BIO_new_file(ptr::null(), c"r".as_ptr()) }.is_null());
        // SAFETY: as above.
        unsafe { free(b) };
    }

    #[test]
    fn longs_wrap_into_ints_as_in_c() {
        assert_eq!(wrap_int(5), 5);
        assert_eq!(wrap_int(-1), -1);
        assert_eq!(wrap_int(0x1_0000_0002), 2);
        assert_eq!(wrap_int(c_long::from(c_int::MIN)), c_int::MIN);
    }
}
