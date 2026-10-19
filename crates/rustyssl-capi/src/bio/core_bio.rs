//! BIOs over the core's BIOs, for a provider (`BIO_s_core(3)`, `crypto/bio/bss_core.c`): a BIO
//! made with `BIO_new_from_core_bio` in a library context that `OSSL_LIB_CTX_new_from_dispatch`
//! made from a core's dispatch table passes each operation to that table's BIO functions, with
//! the `OSSL_CORE_BIO` the core gave the provider.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use rustyssl_abi::{
    BIO, BIO_METHOD, BIO_TYPE_CORE_TO_PROV, ERR_LIB_BIO, OSSL_CORE_BIO, OSSL_LIB_CTX,
};

use super::method::{Builtin, Funcs};
use crate::ffi::{ffi_callback, ffi_export};
use crate::provider::upcalls::CoreBio;

/// The core BIO functions of the library context `libctx` stands for (`get_globals`).
///
/// # Safety
/// `libctx` is NULL or a live library context.
unsafe fn globals(libctx: *mut OSSL_LIB_CTX) -> Option<CoreBio> {
    // SAFETY: the caller's guarantee.
    let ctx = unsafe { crate::libctx::resolve(libctx) }?;
    ctx.core_bio()
}

/// The BIO's context's functions and the core BIO it holds.
///
/// # Safety
/// `b` is a live BIO.
unsafe fn of(b: *mut BIO) -> Option<(CoreBio, *mut c_void)> {
    // SAFETY: the caller's guarantee.
    let object = unsafe { super::object(b) }?;
    // SAFETY: a live BIO's context.
    let g = unsafe { globals(object.libctx()) }?;
    // SAFETY: as above.
    Some((g, unsafe { super::BIO_get_data(b) }))
}

ffi_callback! {
    /// `bio_core_write_ex`.
    ///
    /// # Safety
    /// `b` is a live core BIO; `data` is valid for `len` octets.
    pub(crate) unsafe extern "C" fn core_write_ex(b: *mut BIO, data: *const c_char, len: usize, written: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((g, cb)) = (unsafe { of(b) }) else { return 0 };
        let Some(f) = g.write_ex else { return 0 };
        // SAFETY: the core's function with its own BIO and the caller's buffers.
        unsafe { f(cb, data.cast(), len, written) }
    }
}

ffi_callback! {
    /// `bio_core_read_ex`.
    ///
    /// # Safety
    /// `b` is a live core BIO; `data` is valid for `len` octets of writes.
    pub(crate) unsafe extern "C" fn core_read_ex(b: *mut BIO, data: *mut c_char, len: usize, read: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((g, cb)) = (unsafe { of(b) }) else { return 0 };
        let Some(f) = g.read_ex else { return 0 };
        // SAFETY: as above.
        unsafe { f(cb, data.cast(), len, read) }
    }
}

ffi_callback! {
    /// `bio_core_puts`.
    ///
    /// # Safety
    /// `b` is a live core BIO; `text` a string.
    pub(crate) unsafe extern "C" fn core_puts(b: *mut BIO, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((g, cb)) = (unsafe { of(b) }) else { return -1 };
        let Some(f) = g.puts else { return -1 };
        // SAFETY: as above.
        unsafe { f(cb, text) }
    }
}

ffi_callback! {
    /// `bio_core_gets`.
    ///
    /// # Safety
    /// `b` is a live core BIO; `buf` is valid for `size` octets of writes.
    pub(crate) unsafe extern "C" fn core_gets(b: *mut BIO, buf: *mut c_char, size: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((g, cb)) = (unsafe { of(b) }) else { return -1 };
        let Some(f) = g.gets else { return -1 };
        // SAFETY: as above.
        unsafe { f(cb, buf, size) }
    }
}

ffi_callback! {
    /// `bio_core_ctrl`.
    ///
    /// # Safety
    /// `b` is a live core BIO; `ptr` is what the command expects.
    pub(crate) unsafe extern "C" fn core_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((g, cb)) = (unsafe { of(b) }) else { return -1 };
        let Some(f) = g.ctrl else { return -1 };
        // SAFETY: as above.
        c_long::from(unsafe { f(cb, cmd, num, ptr) })
    }
}

ffi_callback! {
    /// `bio_core_new`.
    ///
    /// # Safety
    /// `b` is a new BIO.
    pub(crate) unsafe extern "C" fn core_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { super::BIO_set_init(b, 1) };
        1
    }
}

ffi_callback! {
    /// `bio_core_free`: gives the core back its BIO.
    ///
    /// # Safety
    /// `b` is a core BIO being freed.
    pub(crate) unsafe extern "C" fn core_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some((g, cb)) = (unsafe { of(b) }) else { return 0 };
        // SAFETY: as above.
        unsafe { super::BIO_set_init(b, 0) };
        if let Some(f) = g.free {
            // SAFETY: the core's function with the BIO it gave a reference to.
            unsafe { f(cb) };
        }
        1
    }
}

static CORE: Builtin = Builtin::new(BIO_TYPE_CORE_TO_PROV, c"BIO to Core filter", || Funcs {
    bwrite: Some(core_write_ex),
    bread: Some(core_read_ex),
    bputs: Some(core_puts),
    bgets: Some(core_gets),
    ctrl: Some(core_ctrl),
    create: Some(core_new),
    destroy: Some(core_free),
    ..Funcs::default()
});

ffi_export! {
    /// The method of BIOs over a core's BIOs.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_s_core() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        CORE.get()
    }
}

ffi_export! {
    /// A BIO of `libctx` over the core BIO `corebio`, holding a reference to it: NULL unless
    /// `libctx` was made with `OSSL_LIB_CTX_new_from_dispatch` from a table with BIO functions.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `corebio` a core BIO the core gave.
    pub unsafe extern "C" fn BIO_new_from_core_bio(libctx: *mut OSSL_LIB_CTX, corebio: *mut OSSL_CORE_BIO) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { globals(libctx) }) else { return ptr::null_mut() };
        if g.write_ex.is_none() && g.read_ex.is_none() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee; a method of ours.
        let out = unsafe { super::BIO_new_ex(libctx, CORE.get()) };
        if out.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the core's function with its own BIO.
        let held = g.up_ref.is_some_and(|f| unsafe { f(corebio.cast()) } != 0);
        if !held {
            // SAFETY: made above.
            unsafe { super::BIO_free(out) };
            return ptr::null_mut();
        }
        // SAFETY: made above.
        unsafe { super::BIO_set_data(out, corebio.cast()) };
        out
    }
}
