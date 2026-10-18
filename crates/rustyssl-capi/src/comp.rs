//! Compression (`COMP_*`, `BIO_f_zlib`/`_brotli`/`_zstd`; `crypto/comp`). OpenSSL's default
//! build has no zlib, brotli, or zstd (`no-zlib`, `no-brotli`, `no-zstd`), so, as there, every
//! method getter and compression BIO is NULL and no `COMP_CTX` can be made; the generic
//! functions keep OpenSSL's behavior for a method all the same (`comp_lib.c`).

use core::ffi::{c_char, c_int, c_uchar, c_ulong, c_void};
use core::mem::size_of;
use core::ptr;

use rustyssl_abi::{BIO_METHOD, COMP_CTX, COMP_METHOD, ERR_LIB_COMP, NID_undef};

use crate::ffi::ffi_export;
use crate::mem;

/// `struct comp_method_st` (`comp_local.h`).
#[repr(C)]
struct Method {
    type_: c_int,
    name: *const c_char,
    init: Option<unsafe extern "C" fn(*mut COMP_CTX) -> c_int>,
    finish: Option<unsafe extern "C" fn(*mut COMP_CTX)>,
    compress: Option<
        unsafe extern "C" fn(*mut COMP_CTX, *mut c_uchar, usize, *mut c_uchar, usize) -> isize,
    >,
    expand: Option<
        unsafe extern "C" fn(*mut COMP_CTX, *mut c_uchar, usize, *mut c_uchar, usize) -> isize,
    >,
}

/// `struct comp_ctx_st` (`comp_local.h`).
#[repr(C)]
struct Ctx {
    meth: *mut Method,
    compress_in: c_ulong,
    compress_out: c_ulong,
    expand_in: c_ulong,
    expand_out: c_ulong,
    data: *mut c_void,
}

/// The method behind a handle.
///
/// # Safety
/// `m` is NULL or a live method.
unsafe fn method<'a>(m: *const COMP_METHOD) -> Option<&'a Method> {
    // SAFETY: the caller's guarantee.
    unsafe { m.cast::<Method>().as_ref() }
}

/// The context behind a handle.
///
/// # Safety
/// `c` is NULL or a live context.
unsafe fn context<'a>(c: *const COMP_CTX) -> Option<&'a mut Ctx> {
    // SAFETY: the caller's guarantee.
    unsafe { c.cast::<Ctx>().cast_mut().as_mut() }
}

ffi_export! {
    /// zlib's stateful method. NULL: the library isn't in the default build.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn COMP_zlib() -> *mut COMP_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_COMP
    {
        ptr::null_mut()
    }
}

ffi_export! {
    /// zlib's one-shot method. NULL: the library isn't in the default build.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn COMP_zlib_oneshot() -> *mut COMP_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_COMP
    {
        ptr::null_mut()
    }
}

ffi_export! {
    /// brotli's stateful method. NULL: the library isn't in the default build.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn COMP_brotli() -> *mut COMP_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_COMP
    {
        ptr::null_mut()
    }
}

ffi_export! {
    /// brotli's one-shot method. NULL: the library isn't in the default build.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn COMP_brotli_oneshot() -> *mut COMP_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_COMP
    {
        ptr::null_mut()
    }
}

ffi_export! {
    /// zstd's stateful method. NULL: the library isn't in the default build.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn COMP_zstd() -> *mut COMP_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_COMP
    {
        ptr::null_mut()
    }
}

ffi_export! {
    /// zstd's one-shot method. NULL: the library isn't in the default build.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn COMP_zstd_oneshot() -> *mut COMP_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_COMP
    {
        ptr::null_mut()
    }
}

ffi_export! {
    /// The zlib filter BIO. NULL: the library isn't in the default build.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_f_zlib() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_COMP
    {
        ptr::null()
    }
}

ffi_export! {
    /// The brotli filter BIO. NULL: the library isn't in the default build.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_f_brotli() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_COMP
    {
        ptr::null()
    }
}

ffi_export! {
    /// The zstd filter BIO. NULL: the library isn't in the default build.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_f_zstd() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_COMP
    {
        ptr::null()
    }
}

ffi_export! {
    /// A context for `meth` (initialized by its `init`), or NULL (for NULL).
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn COMP_CTX_new(meth: *mut COMP_METHOD) -> *mut COMP_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_COMP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(meth) }) else { return ptr::null_mut() };
        let ret: *mut Ctx = mem::alloc_zeroed(size_of::<Ctx>()).cast();
        // SAFETY: the zeroed block made for it.
        let Some(c) = (unsafe { ret.as_mut() }) else { return ptr::null_mut() };
        c.meth = meth.cast();
        if let Some(init) = m.init
            // SAFETY: the method's own initializer, with the new context.
            && unsafe { init(ret.cast()) } == 0
        {
            // SAFETY: made here.
            unsafe { mem::release(ret.cast()) };
            return ptr::null_mut();
        }
        ret.cast()
    }
}

ffi_export! {
    /// The context's method.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context (OpenSSL crashes on NULL; here it's NULL).
    pub unsafe extern "C" fn COMP_CTX_get_method(ctx: *const COMP_CTX) -> *const COMP_METHOD
    where failure = ptr::null(), library = ERR_LIB_COMP
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(ctx) }.map_or(ptr::null(), |c| c.meth.cast_const().cast())
    }
}

ffi_export! {
    /// The method's NID, `NID_undef` for NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn COMP_get_type(meth: *const COMP_METHOD) -> c_int
    where failure = NID_undef, library = ERR_LIB_COMP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(meth) }.map_or(NID_undef, |m| m.type_)
    }
}

ffi_export! {
    /// The method's name, NULL for NULL.
    ///
    /// # Safety
    /// `meth` is NULL or a live method.
    pub unsafe extern "C" fn COMP_get_name(meth: *const COMP_METHOD) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_COMP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(meth) }.map_or(ptr::null(), |m| m.name)
    }
}

ffi_export! {
    /// The context's method's NID, `NID_undef` without one.
    ///
    /// # Safety
    /// `comp` is NULL or a live context (OpenSSL crashes on NULL).
    pub unsafe extern "C" fn COMP_CTX_get_type(comp: *const COMP_CTX) -> c_int
    where failure = NID_undef, library = ERR_LIB_COMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(comp) }) else { return NID_undef };
        // SAFETY: its method, or NULL.
        unsafe { method(c.meth.cast()) }.map_or(NID_undef, |m| m.type_)
    }
}

ffi_export! {
    /// Frees the context (its method's `finish` first); nothing for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context, not used after.
    pub unsafe extern "C" fn COMP_CTX_free(ctx: *mut COMP_CTX)
    where failure = (), library = ERR_LIB_COMP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return };
        // SAFETY: its method.
        if let Some(finish) = unsafe { method(c.meth.cast()) }.and_then(|m| m.finish) {
            // SAFETY: the method's own finisher, with its context.
            unsafe { finish(ctx) };
        }
        // SAFETY: the context itself.
        unsafe { mem::release(ctx.cast()) };
    }
}

/// Which way a block goes.
#[derive(Clone, Copy)]
enum Way {
    Compress,
    Expand,
}

/// `COMP_compress_block` and `COMP_expand_block`: the method's result, counted into the
/// context's totals when positive; -1 without the function (or for negative lengths, which
/// OpenSSL passes on as huge sizes).
///
/// # Safety
/// `ctx` is NULL or a live context; `out` holds `olen` octets and `in_` `ilen`.
unsafe fn block(
    ctx: *mut COMP_CTX,
    way: Way,
    out: *mut c_uchar,
    olen: c_int,
    in_: *mut c_uchar,
    ilen: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(ctx) }) else {
        return -1;
    };
    // SAFETY: its method.
    let Some(m) = (unsafe { method(c.meth.cast()) }) else {
        return -1;
    };
    let f = match way {
        Way::Compress => m.compress,
        Way::Expand => m.expand,
    };
    let Some(f) = f else { return -1 };
    let (Ok(ol), Ok(il)) = (usize::try_from(olen), usize::try_from(ilen)) else {
        return -1;
    };
    // SAFETY: the method's own function, with the caller's buffers.
    let ret = unsafe { f(ctx, out, ol, in_, il) };
    let Ok(r) = c_int::try_from(ret) else {
        return -1;
    };
    if r > 0 {
        // SAFETY: the caller's context, again (the method may have used it).
        if let Some(c) = unsafe { context(ctx) } {
            let (i, o) = (
                c_ulong::try_from(il).unwrap_or(0),
                c_ulong::try_from(r).unwrap_or(0),
            );
            match way {
                Way::Compress => {
                    c.compress_in = c.compress_in.wrapping_add(i);
                    c.compress_out = c.compress_out.wrapping_add(o);
                }
                Way::Expand => {
                    c.expand_in = c.expand_in.wrapping_add(i);
                    c.expand_out = c.expand_out.wrapping_add(o);
                }
            }
        }
    }
    r
}

ffi_export! {
    /// Compresses `ilen` octets of `in_` into `out` (room `olen`): the octets written, or -1/0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; the buffers hold their lengths.
    pub unsafe extern "C" fn COMP_compress_block(ctx: *mut COMP_CTX, out: *mut c_uchar, olen: c_int, in_: *mut c_uchar, ilen: c_int) -> c_int
    where failure = -1, library = ERR_LIB_COMP
    {
        // SAFETY: the caller's guarantee.
        unsafe { block(ctx, Way::Compress, out, olen, in_, ilen) }
    }
}

ffi_export! {
    /// Expands `ilen` octets of `in_` into `out` (room `olen`): the octets written, or -1/0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; the buffers hold their lengths.
    pub unsafe extern "C" fn COMP_expand_block(ctx: *mut COMP_CTX, out: *mut c_uchar, olen: c_int, in_: *mut c_uchar, ilen: c_int) -> c_int
    where failure = -1, library = ERR_LIB_COMP
    {
        // SAFETY: the caller's guarantee.
        unsafe { block(ctx, Way::Expand, out, olen, in_, ilen) }
    }
}
