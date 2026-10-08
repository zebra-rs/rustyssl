//! BIO methods (`BIO_meth_new(3)`): the table of C functions a BIO's type runs.
//!
//! A method is a table of C function pointers, for built-in types too: applications build their
//! own methods out of the built-in ones (`BIO_meth_set_write(m,
//! BIO_meth_get_write(BIO_s_socket()))`), so each built-in function is a real C function taking
//! a `BIO *`. As in OpenSSL, setting the plain `write` or `read` installs it as the "old" function
//! and a converter as the `_ex` one, and setting an `_ex` function clears the old one.
//!
//! Built-in methods are created once and never freed. OpenSSL's are read-only data, so freeing
//! or changing one would crash; here `BIO_meth_free` ignores them and the setters refuse them
//! (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::{Mutex, OnceLock, PoisonError};

use rustssl_abi::{BIO, BIO_METHOD, BIO_MSG, BIO_info_cb, ERR_LIB_BIO};

use crate::ffi::{ffi_callback, ffi_export};
use crate::handle::{Handle, handle_type};

pub(crate) type WriteEx = unsafe extern "C" fn(*mut BIO, *const c_char, usize, *mut usize) -> c_int;
pub(crate) type Write = unsafe extern "C" fn(*mut BIO, *const c_char, c_int) -> c_int;
pub(crate) type ReadEx = unsafe extern "C" fn(*mut BIO, *mut c_char, usize, *mut usize) -> c_int;
pub(crate) type Read = unsafe extern "C" fn(*mut BIO, *mut c_char, c_int) -> c_int;
pub(crate) type Puts = unsafe extern "C" fn(*mut BIO, *const c_char) -> c_int;
pub(crate) type Gets = unsafe extern "C" fn(*mut BIO, *mut c_char, c_int) -> c_int;
pub(crate) type Ctrl = unsafe extern "C" fn(*mut BIO, c_int, c_long, *mut c_void) -> c_long;
pub(crate) type Create = unsafe extern "C" fn(*mut BIO) -> c_int;
pub(crate) type CallbackCtrl = unsafe extern "C" fn(*mut BIO, c_int, BIO_info_cb) -> c_long;
pub(crate) type Mmsg =
    unsafe extern "C" fn(*mut BIO, *mut BIO_MSG, usize, usize, u64, *mut usize) -> c_int;

/// A method's functions, as OpenSSL's `struct bio_method_st` holds them.
#[derive(Clone, Copy, Default)]
pub(crate) struct Funcs {
    pub(crate) bwrite: Option<WriteEx>,
    pub(crate) bwrite_old: Option<Write>,
    pub(crate) bread: Option<ReadEx>,
    pub(crate) bread_old: Option<Read>,
    pub(crate) bputs: Option<Puts>,
    pub(crate) bgets: Option<Gets>,
    pub(crate) ctrl: Option<Ctrl>,
    pub(crate) create: Option<Create>,
    pub(crate) destroy: Option<Create>,
    pub(crate) callback_ctrl: Option<CallbackCtrl>,
    pub(crate) bsendmmsg: Option<Mmsg>,
    pub(crate) brecvmmsg: Option<Mmsg>,
}

impl Funcs {
    /// The functions of a built-in type written with the plain `write` and `read`, which the
    /// converters adapt, as OpenSSL's built-in tables do.
    pub(crate) fn classic(write: Write, read: Read) -> Self {
        Self {
            bwrite: Some(bwrite_conv),
            bwrite_old: Some(write),
            bread: Some(bread_conv),
            bread_old: Some(read),
            ..Self::default()
        }
    }
}

/// What a `BIO_METHOD` handle points to.
pub(crate) struct Method {
    kind: c_int,
    name: CString,
    builtin: bool,
    funcs: Mutex<Funcs>,
}

handle_type!(BIO_METHOD => Method);

impl Method {
    pub(crate) fn kind(&self) -> c_int {
        self.kind
    }

    pub(crate) fn name(&self) -> *const c_char {
        self.name.as_ptr()
    }

    pub(crate) fn funcs(&self) -> Funcs {
        *self.funcs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Changes the functions of an application's method; built-in ones refuse.
    fn update(&self, change: impl FnOnce(&mut Funcs)) -> c_int {
        if self.builtin {
            return 0;
        }
        change(&mut self.funcs.lock().unwrap_or_else(PoisonError::into_inner));
        1
    }
}

/// A built-in method's handle, which lives as long as the process.
struct Handle_(*mut BIO_METHOD);

// SAFETY: the handle points to a `Method`, which is `Send + Sync`, and is never freed.
unsafe impl Send for Handle_ {}
// SAFETY: as above.
unsafe impl Sync for Handle_ {}

/// A built-in method, created on first use and kept for the life of the process.
pub(crate) struct Builtin {
    cell: OnceLock<Handle_>,
    kind: c_int,
    name: &'static CStr,
    funcs: fn() -> Funcs,
}

impl Builtin {
    pub(crate) const fn new(kind: c_int, name: &'static CStr, funcs: fn() -> Funcs) -> Self {
        Self {
            cell: OnceLock::new(),
            kind,
            name,
            funcs,
        }
    }

    /// The method's handle.
    pub(crate) fn get(&'static self) -> *const BIO_METHOD {
        let handle = self.cell.get_or_init(|| {
            Handle_(BIO_METHOD::new_handle(Method {
                kind: self.kind,
                name: self.name.to_owned(),
                builtin: true,
                funcs: Mutex::new((self.funcs)()),
            }))
        });
        handle.0
    }
}

/// The method behind `method`, or `None` for null.
///
/// # Safety
/// `method` is null or a live method handle that outlives `'a`.
pub(crate) unsafe fn method<'a>(method: *const BIO_METHOD) -> Option<&'a Method> {
    // SAFETY: the caller's guarantee.
    unsafe { BIO_METHOD::get(method) }
}

ffi_callback! {
    /// OpenSSL's `bwrite_conv`: the `write_ex` of a method with a plain `write`, which it calls
    /// with at most `INT_MAX` bytes.
    ///
    /// # Safety
    /// `bio` is a live BIO whose method has a plain `write`; `written` is valid for a write.
    pub(crate) unsafe extern "C" fn bwrite_conv(bio: *mut BIO, data: *const c_char, datal: usize, written: *mut usize) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(write) = (unsafe { super::funcs(bio) }).and_then(|f| f.bwrite_old) else {
            return -2;
        };
        let len = c_int::try_from(datal).unwrap_or(c_int::MAX);
        // SAFETY: the caller's guarantee; the method's function takes these arguments.
        let ret = unsafe { write(bio, data, len) };
        let done = usize::try_from(ret).unwrap_or(0);
        if !written.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { written.write(done) };
        }
        if ret <= 0 { ret } else { 1 }
    }
}

ffi_callback! {
    /// OpenSSL's `bread_conv`: the `read_ex` of a method with a plain `read`.
    ///
    /// # Safety
    /// `bio` is a live BIO whose method has a plain `read`; `readbytes` is valid for a write.
    pub(crate) unsafe extern "C" fn bread_conv(bio: *mut BIO, data: *mut c_char, datal: usize, readbytes: *mut usize) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(read) = (unsafe { super::funcs(bio) }).and_then(|f| f.bread_old) else {
            return -2;
        };
        let len = c_int::try_from(datal).unwrap_or(c_int::MAX);
        // SAFETY: the caller's guarantee; the method's function takes these arguments.
        let ret = unsafe { read(bio, data, len) };
        let done = usize::try_from(ret).unwrap_or(0);
        if !readbytes.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { readbytes.write(done) };
        }
        if ret <= 0 { ret } else { 1 }
    }
}

/// The counter `BIO_get_new_index` hands types out from.
static NEXT_TYPE: core::sync::atomic::AtomicI32 =
    core::sync::atomic::AtomicI32::new(rustssl_abi::BIO_TYPE_START);

ffi_export! {
    /// Returns a new type number for an application's BIO method, counting up from
    /// `BIO_TYPE_START + 1`, or -1 once they run out.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_get_new_index() -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let next = NEXT_TYPE.fetch_add(1, core::sync::atomic::Ordering::Relaxed).wrapping_add(1);
        if next > rustssl_abi::BIO_TYPE_MASK { -1 } else { next }
    }
}

ffi_export! {
    /// Returns a new method of type `type_` named `name`, with no functions; null if `name` is
    /// null.
    ///
    /// # Safety
    /// `name` is null or a NUL-terminated string.
    pub unsafe extern "C" fn BIO_meth_new(type_: c_int, name: *const c_char) -> *mut BIO_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_BIO
    {
        if name.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let name = unsafe { CStr::from_ptr(name) }.to_owned();
        BIO_METHOD::new_handle(Method {
            kind: type_,
            name,
            builtin: false,
            funcs: Mutex::new(Funcs::default()),
        })
    }
}

ffi_export! {
    /// Frees a method from `BIO_meth_new`. Null and built-in methods are ignored.
    ///
    /// # Safety
    /// `biom` is null or a live method that no BIO uses any more.
    pub unsafe extern "C" fn BIO_meth_free(biom: *mut BIO_METHOD)
    where failure = (), library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        if unsafe { method(biom) }.is_some_and(|m| !m.builtin) {
            // SAFETY: as above.
            unsafe { BIO_METHOD::free(biom) };
        }
    }
}

/// Defines `BIO_meth_set_<name>`, each written with its full signature, as storing the
/// function, and `BIO_meth_get_<name>`, as returning it.
macro_rules! accessors {
    ($(
        $field:ident: $ty:ty,
        pub unsafe extern "C" fn $set:ident(biom: *mut BIO_METHOD, f: $arg:ty) -> c_int;
        pub unsafe extern "C" fn $get:ident(biom: *const BIO_METHOD) -> $ret:ty;
    )*) => {$(
        ffi_export! {
            /// Sets the method's function. Returns 1, or 0 for a built-in method or null.
            ///
            /// # Safety
            /// `biom` is null or a live method; the function is null or of the documented type.
            pub unsafe extern "C" fn $set(biom: *mut BIO_METHOD, f: $arg) -> c_int
            where failure = 0, library = ERR_LIB_BIO
            {
                // SAFETY: the caller's guarantee.
                unsafe { method(biom) }.map_or(0, |m| m.update(|funcs| funcs.$field = f))
            }
        }

        ffi_export! {
            /// Returns the method's function, or null (deprecated).
            ///
            /// # Safety
            /// `biom` is null or a live method.
            pub unsafe extern "C" fn $get(biom: *const BIO_METHOD) -> $ret
            where failure = None, library = ERR_LIB_BIO
            {
                // SAFETY: the caller's guarantee.
                unsafe { method(biom) }.and_then(|m| m.funcs().$field)
            }
        }
    )*};
}

accessors! {
    bputs: Option<Puts>,
    pub unsafe extern "C" fn BIO_meth_set_puts(biom: *mut BIO_METHOD, f: Option<Puts>) -> c_int;
    pub unsafe extern "C" fn BIO_meth_get_puts(biom: *const BIO_METHOD) -> Option<Puts>;
    bgets: Option<Gets>,
    pub unsafe extern "C" fn BIO_meth_set_gets(biom: *mut BIO_METHOD, f: Option<Gets>) -> c_int;
    pub unsafe extern "C" fn BIO_meth_get_gets(biom: *const BIO_METHOD) -> Option<Gets>;
    ctrl: Option<Ctrl>,
    pub unsafe extern "C" fn BIO_meth_set_ctrl(biom: *mut BIO_METHOD, f: Option<Ctrl>) -> c_int;
    pub unsafe extern "C" fn BIO_meth_get_ctrl(biom: *const BIO_METHOD) -> Option<Ctrl>;
    create: Option<Create>,
    pub unsafe extern "C" fn BIO_meth_set_create(biom: *mut BIO_METHOD, f: Option<Create>) -> c_int;
    pub unsafe extern "C" fn BIO_meth_get_create(biom: *const BIO_METHOD) -> Option<Create>;
    destroy: Option<Create>,
    pub unsafe extern "C" fn BIO_meth_set_destroy(biom: *mut BIO_METHOD, f: Option<Create>) -> c_int;
    pub unsafe extern "C" fn BIO_meth_get_destroy(biom: *const BIO_METHOD) -> Option<Create>;
    callback_ctrl: Option<CallbackCtrl>,
    pub unsafe extern "C" fn BIO_meth_set_callback_ctrl(biom: *mut BIO_METHOD, f: Option<CallbackCtrl>) -> c_int;
    pub unsafe extern "C" fn BIO_meth_get_callback_ctrl(biom: *const BIO_METHOD) -> Option<CallbackCtrl>;
    bsendmmsg: Option<Mmsg>,
    pub unsafe extern "C" fn BIO_meth_set_sendmmsg(biom: *mut BIO_METHOD, f: Option<Mmsg>) -> c_int;
    pub unsafe extern "C" fn BIO_meth_get_sendmmsg(biom: *const BIO_METHOD) -> Option<Mmsg>;
    brecvmmsg: Option<Mmsg>,
    pub unsafe extern "C" fn BIO_meth_set_recvmmsg(biom: *mut BIO_METHOD, f: Option<Mmsg>) -> c_int;
    pub unsafe extern "C" fn BIO_meth_get_recvmmsg(biom: *const BIO_METHOD) -> Option<Mmsg>;
}

ffi_export! {
    /// Sets the method's plain `write`, with a converter as its `write_ex`. Returns 1, or 0 for a
    /// built-in method or null.
    ///
    /// # Safety
    /// `biom` is null or a live method; `bwrite` is null or of the documented type.
    pub unsafe extern "C" fn BIO_meth_set_write(biom: *mut BIO_METHOD, bwrite: Option<Write>) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(biom) }.map_or(0, |m| {
            m.update(|funcs| {
                funcs.bwrite_old = bwrite;
                funcs.bwrite = Some(bwrite_conv);
            })
        })
    }
}

ffi_export! {
    /// Sets the method's `write_ex`, clearing its plain `write`. Returns 1, or 0 for a built-in
    /// method or null.
    ///
    /// # Safety
    /// `biom` is null or a live method; `bwrite` is null or of the documented type.
    pub unsafe extern "C" fn BIO_meth_set_write_ex(biom: *mut BIO_METHOD, bwrite: Option<WriteEx>) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(biom) }.map_or(0, |m| {
            m.update(|funcs| {
                funcs.bwrite_old = None;
                funcs.bwrite = bwrite;
            })
        })
    }
}

ffi_export! {
    /// Sets the method's plain `read`, with a converter as its `read_ex`. Returns 1, or 0 for a
    /// built-in method or null.
    ///
    /// # Safety
    /// `biom` is null or a live method; `bread` is null or of the documented type.
    pub unsafe extern "C" fn BIO_meth_set_read(biom: *mut BIO_METHOD, bread: Option<Read>) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(biom) }.map_or(0, |m| {
            m.update(|funcs| {
                funcs.bread_old = bread;
                funcs.bread = Some(bread_conv);
            })
        })
    }
}

ffi_export! {
    /// Sets the method's `read_ex`, clearing its plain `read`. Returns 1, or 0 for a built-in
    /// method or null.
    ///
    /// # Safety
    /// `biom` is null or a live method; `bread` is null or of the documented type.
    pub unsafe extern "C" fn BIO_meth_set_read_ex(biom: *mut BIO_METHOD, bread: Option<ReadEx>) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(biom) }.map_or(0, |m| {
            m.update(|funcs| {
                funcs.bread_old = None;
                funcs.bread = bread;
            })
        })
    }
}

ffi_export! {
    /// Returns the method's plain `write`, or null (deprecated).
    ///
    /// # Safety
    /// `biom` is null or a live method.
    pub unsafe extern "C" fn BIO_meth_get_write(biom: *const BIO_METHOD) -> Option<Write>
    where failure = None, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(biom) }.and_then(|m| m.funcs().bwrite_old)
    }
}

ffi_export! {
    /// Returns the method's `write_ex` (a converter for a plain `write`), or null (deprecated).
    ///
    /// # Safety
    /// `biom` is null or a live method.
    pub unsafe extern "C" fn BIO_meth_get_write_ex(biom: *const BIO_METHOD) -> Option<WriteEx>
    where failure = None, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(biom) }.and_then(|m| m.funcs().bwrite)
    }
}

ffi_export! {
    /// Returns the method's plain `read`, or null (deprecated).
    ///
    /// # Safety
    /// `biom` is null or a live method.
    pub unsafe extern "C" fn BIO_meth_get_read(biom: *const BIO_METHOD) -> Option<Read>
    where failure = None, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(biom) }.and_then(|m| m.funcs().bread_old)
    }
}

ffi_export! {
    /// Returns the method's `read_ex` (a converter for a plain `read`), or null (deprecated).
    ///
    /// # Safety
    /// `biom` is null or a live method.
    pub unsafe extern "C" fn BIO_meth_get_read_ex(biom: *const BIO_METHOD) -> Option<ReadEx>
    where failure = None, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(biom) }.and_then(|m| m.funcs().bread)
    }
}
