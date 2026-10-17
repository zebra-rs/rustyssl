//! User-interface methods (`UI_create_method(3)`; `ui_lib.c`, `ui_null.c`, `ui_openssl.c`): the
//! method objects applications build their prompting on, `UI_null`, and `UI_OpenSSL`.
//!
//! The rest of the UI (`UI_new`, its strings, `UI_process`, and the utilities) is in `ui_lib`.
//! `UI_OpenSSL`'s console functions, which read the terminal, are in `console`.

use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use rustyssl_abi::{
    CRYPTO_EX_DATA, CRYPTO_EX_INDEX_UI_METHOD, ERR_LIB_UI, ERR_R_CRYPTO_LIB, UI, UI_METHOD,
    UI_STRING,
};

use crate::err;
use crate::ex_data::{
    CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data, CRYPTO_set_ex_data,
};
use crate::ffi::ffi_export;

pub(crate) mod console;
pub(crate) mod ui_lib;

pub(crate) use ui_lib::{
    EVP_get_pw_prompt, EVP_read_pw_string_min, UI_UTIL_wrap_read_pem_callback, UI_add_input_string,
    UI_add_user_data, UI_add_verify_string, UI_construct_prompt, UI_free, UI_get_result_length,
    UI_new, UI_process, UI_set_method,
};

pub(crate) type SessionFn = unsafe extern "C" fn(*mut UI) -> c_int;
pub(crate) type StringFn = unsafe extern "C" fn(*mut UI, *mut UI_STRING) -> c_int;
pub(crate) type DupFn = unsafe extern "C" fn(*mut UI, *mut c_void) -> *mut c_void;
pub(crate) type DestroyFn = unsafe extern "C" fn(*mut UI, *mut c_void);
pub(crate) type PromptFn =
    unsafe extern "C" fn(*mut UI, *const c_char, *const c_char) -> *mut c_char;

/// A method's functions (`struct ui_method_st`).
#[derive(Clone, Copy, Default)]
pub(crate) struct Funcs {
    pub(crate) open: Option<SessionFn>,
    pub(crate) write: Option<StringFn>,
    pub(crate) flush: Option<SessionFn>,
    pub(crate) read: Option<StringFn>,
    pub(crate) close: Option<SessionFn>,
    pub(crate) duplicate: Option<DupFn>,
    pub(crate) destroy: Option<DestroyFn>,
    pub(crate) prompt: Option<PromptFn>,
}

/// The method's application data, at a fixed address for the `CRYPTO_*_ex_data` functions.
struct ExData(UnsafeCell<CRYPTO_EX_DATA>);

// SAFETY: only the ex_data functions use it, which OpenSSL leaves the application to
// serialize, as it does the rest of a method.
unsafe impl Send for ExData {}
// SAFETY: as above.
unsafe impl Sync for ExData {}

/// A `UI_METHOD`.
struct Method {
    /// Its name (never read through the API, as in OpenSSL; kept for its lifetime).
    #[expect(dead_code, reason = "OpenSSL keeps the name without a getter")]
    name: CString,
    funcs: Mutex<Funcs>,
    ex_data: ExData,
    /// One of the library's static methods, which `UI_destroy_method` leaves alone.
    builtin: bool,
}

impl Method {
    fn new(name: CString, funcs: Funcs, builtin: bool) -> Self {
        Self {
            name,
            funcs: Mutex::new(funcs),
            ex_data: ExData(UnsafeCell::new(CRYPTO_EX_DATA {
                ctx: ptr::null_mut(),
                sk: ptr::null_mut(),
            })),
            builtin,
        }
    }

    fn funcs(&self) -> MutexGuard<'_, Funcs> {
        self.funcs.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The method behind `m`.
///
/// # Safety
/// `m` is NULL or a method from `UI_create_method`, `UI_null`, or `UI_OpenSSL`, not destroyed.
unsafe fn method<'a>(m: *const UI_METHOD) -> Option<&'a Method> {
    // SAFETY: the caller's guarantee.
    unsafe { m.cast::<Method>().as_ref() }
}

/// A copy of the method's functions (none for NULL), to call with no lock held.
///
/// # Safety
/// As for [`method`].
pub(crate) unsafe fn funcs_of(m: *const UI_METHOD) -> Funcs {
    // SAFETY: the caller's guarantee.
    unsafe { method(m) }.map(|m| *m.funcs()).unwrap_or_default()
}

static NULL_METHOD: OnceLock<Method> = OnceLock::new();
static OPENSSL_METHOD: OnceLock<Method> = OnceLock::new();

ffi_export! {
    /// The method that does nothing (`"OpenSSL NULL UI"`, no functions).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn UI_null() -> *const UI_METHOD
    where failure = ptr::null(), library = ERR_LIB_UI
    {
        let m = NULL_METHOD.get_or_init(|| Method::new(c"OpenSSL NULL UI".to_owned(), Funcs::default(), true));
        ptr::from_ref(m).cast()
    }
}

ffi_export! {
    /// The console method (`"OpenSSL default user interface"`): open, write, read, and close
    /// on the terminal, with no flusher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn UI_OpenSSL() -> *mut UI_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_UI
    {
        let m = OPENSSL_METHOD.get_or_init(|| {
            let funcs = Funcs {
                open: Some(console::open_console),
                write: Some(console::write_string),
                read: Some(console::read_string),
                close: Some(console::close_console),
                ..Funcs::default()
            };
            Method::new(c"OpenSSL default user interface".to_owned(), funcs, true)
        });
        ptr::from_ref(m).cast_mut().cast()
    }
}

ffi_export! {
    /// A new method named `name` (copied), with no functions. NULL on failure.
    ///
    /// # Safety
    /// `name` is a C string.
    pub unsafe extern "C" fn UI_create_method(name: *const c_char) -> *mut UI_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_UI
    {
        if name.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let name = unsafe { CStr::from_ptr(name) }.to_owned();
        let m = Box::into_raw(Box::new(Method::new(name, Funcs::default(), false)));
        // SAFETY: the method just made.
        let ad = unsafe { &*m }.ex_data.0.get();
        // SAFETY: the new method's own ex_data.
        let made = unsafe { CRYPTO_new_ex_data(CRYPTO_EX_INDEX_UI_METHOD, m.cast(), ad) };
        if made == 0 {
            err::raise(ERR_LIB_UI, ERR_R_CRYPTO_LIB, "UI_create_method");
            // SAFETY: the method made here, not shared.
            drop(unsafe { Box::from_raw(m) });
            return ptr::null_mut();
        }
        m.cast()
    }
}

ffi_export! {
    /// Frees a method from `UI_create_method` and its application data; NULL does nothing.
    /// (OpenSSL frees the library's static methods too, and crashes; those are left alone.)
    ///
    /// # Safety
    /// `ui_method` is NULL or a live method, not used afterwards.
    pub unsafe extern "C" fn UI_destroy_method(ui_method: *mut UI_METHOD)
    where failure = (), library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(ui_method) }) else { return };
        if m.builtin {
            return;
        }
        // SAFETY: the method's own ex_data.
        unsafe { CRYPTO_free_ex_data(CRYPTO_EX_INDEX_UI_METHOD, ui_method.cast(), m.ex_data.0.get()) };
        // SAFETY: a method from UI_create_method, freed once.
        drop(unsafe { Box::from_raw(ui_method.cast::<Method>()) });
    }
}

/// Sets one of a method's functions: 0, or -1 for NULL (OpenSSL's convention here).
///
/// # Safety
/// `m` is NULL or a live method.
unsafe fn set(m: *mut UI_METHOD, f: impl FnOnce(&mut Funcs)) -> c_int {
    // SAFETY: the caller's guarantee.
    match unsafe { method(m) } {
        Some(m) => {
            f(&mut m.funcs());
            0
        }
        None => -1,
    }
}

/// One of a method's functions, or NULL.
///
/// # Safety
/// `m` is NULL or a live method.
unsafe fn get<T>(m: *const UI_METHOD, f: impl FnOnce(&Funcs) -> Option<T>) -> Option<T> {
    // SAFETY: the caller's guarantee.
    unsafe { method(m) }.and_then(|m| f(&m.funcs()))
}

ffi_export! {
    /// Sets the method's opener. Returns 0, or -1 for a NULL method.
    ///
    /// # Safety
    /// `method` is NULL or a live method; `opener` is NULL or of the documented type.
    pub unsafe extern "C" fn UI_method_set_opener(method: *mut UI_METHOD, opener: Option<SessionFn>) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { set(method, |f| f.open = opener) }
    }
}

ffi_export! {
    /// Sets the method's writer. Returns 0, or -1 for a NULL method.
    ///
    /// # Safety
    /// `method` is NULL or a live method; `writer` is NULL or of the documented type.
    pub unsafe extern "C" fn UI_method_set_writer(method: *mut UI_METHOD, writer: Option<StringFn>) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { set(method, |f| f.write = writer) }
    }
}

ffi_export! {
    /// Sets the method's flusher. Returns 0, or -1 for a NULL method.
    ///
    /// # Safety
    /// `method` is NULL or a live method; `flusher` is NULL or of the documented type.
    pub unsafe extern "C" fn UI_method_set_flusher(method: *mut UI_METHOD, flusher: Option<SessionFn>) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { set(method, |f| f.flush = flusher) }
    }
}

ffi_export! {
    /// Sets the method's reader. Returns 0, or -1 for a NULL method.
    ///
    /// # Safety
    /// `method` is NULL or a live method; `reader` is NULL or of the documented type.
    pub unsafe extern "C" fn UI_method_set_reader(method: *mut UI_METHOD, reader: Option<StringFn>) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { set(method, |f| f.read = reader) }
    }
}

ffi_export! {
    /// Sets the method's closer. Returns 0, or -1 for a NULL method.
    ///
    /// # Safety
    /// `method` is NULL or a live method; `closer` is NULL or of the documented type.
    pub unsafe extern "C" fn UI_method_set_closer(method: *mut UI_METHOD, closer: Option<SessionFn>) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { set(method, |f| f.close = closer) }
    }
}

ffi_export! {
    /// Sets the method's data duplicator and destructor. Returns 0, or -1 for a NULL method.
    ///
    /// # Safety
    /// `method` is NULL or a live method; the functions are NULL or of the documented types.
    pub unsafe extern "C" fn UI_method_set_data_duplicator(method: *mut UI_METHOD, duplicator: Option<DupFn>, destructor: Option<DestroyFn>) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe {
            set(method, |f| {
                f.duplicate = duplicator;
                f.destroy = destructor;
            })
        }
    }
}

ffi_export! {
    /// Sets the method's prompt constructor. Returns 0, or -1 for a NULL method.
    ///
    /// # Safety
    /// `method` is NULL or a live method; `prompt_constructor` is NULL or of the documented
    /// type.
    pub unsafe extern "C" fn UI_method_set_prompt_constructor(method: *mut UI_METHOD, prompt_constructor: Option<PromptFn>) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { set(method, |f| f.prompt = prompt_constructor) }
    }
}

ffi_export! {
    /// The method's opener, or NULL.
    ///
    /// # Safety
    /// `method` is NULL or a live method.
    pub unsafe extern "C" fn UI_method_get_opener(method: *const UI_METHOD) -> Option<SessionFn>
    where failure = None, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { get(method, |f| f.open) }
    }
}

ffi_export! {
    /// The method's writer, or NULL.
    ///
    /// # Safety
    /// `method` is NULL or a live method.
    pub unsafe extern "C" fn UI_method_get_writer(method: *const UI_METHOD) -> Option<StringFn>
    where failure = None, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { get(method, |f| f.write) }
    }
}

ffi_export! {
    /// The method's flusher, or NULL.
    ///
    /// # Safety
    /// `method` is NULL or a live method.
    pub unsafe extern "C" fn UI_method_get_flusher(method: *const UI_METHOD) -> Option<SessionFn>
    where failure = None, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { get(method, |f| f.flush) }
    }
}

ffi_export! {
    /// The method's reader, or NULL.
    ///
    /// # Safety
    /// `method` is NULL or a live method.
    pub unsafe extern "C" fn UI_method_get_reader(method: *const UI_METHOD) -> Option<StringFn>
    where failure = None, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { get(method, |f| f.read) }
    }
}

ffi_export! {
    /// The method's closer, or NULL.
    ///
    /// # Safety
    /// `method` is NULL or a live method.
    pub unsafe extern "C" fn UI_method_get_closer(method: *const UI_METHOD) -> Option<SessionFn>
    where failure = None, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { get(method, |f| f.close) }
    }
}

ffi_export! {
    /// The method's prompt constructor, or NULL.
    ///
    /// # Safety
    /// `method` is NULL or a live method.
    pub unsafe extern "C" fn UI_method_get_prompt_constructor(method: *const UI_METHOD) -> Option<PromptFn>
    where failure = None, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { get(method, |f| f.prompt) }
    }
}

ffi_export! {
    /// The method's data duplicator, or NULL.
    ///
    /// # Safety
    /// `method` is NULL or a live method.
    pub unsafe extern "C" fn UI_method_get_data_duplicator(method: *const UI_METHOD) -> Option<DupFn>
    where failure = None, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { get(method, |f| f.duplicate) }
    }
}

ffi_export! {
    /// The method's data destructor, or NULL.
    ///
    /// # Safety
    /// `method` is NULL or a live method.
    pub unsafe extern "C" fn UI_method_get_data_destructor(method: *const UI_METHOD) -> Option<DestroyFn>
    where failure = None, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { get(method, |f| f.destroy) }
    }
}

ffi_export! {
    /// Sets the method's application data at `idx`. Returns 1, or 0.
    ///
    /// # Safety
    /// `method` is a live method.
    pub unsafe extern "C" fn UI_method_set_ex_data(method: *mut UI_METHOD, idx: c_int, data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { self::method(method) }) else { return 0 };
        // SAFETY: the method's own ex_data.
        unsafe { CRYPTO_set_ex_data(m.ex_data.0.get(), idx, data) }
    }
}

ffi_export! {
    /// The method's application data at `idx`, or NULL.
    ///
    /// # Safety
    /// `method` is a live method.
    pub unsafe extern "C" fn UI_method_get_ex_data(method: *const UI_METHOD, idx: c_int) -> *const c_void
    where failure = ptr::null(), library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { self::method(method) }) else { return ptr::null() };
        // SAFETY: the method's own ex_data.
        unsafe { CRYPTO_get_ex_data(m.ex_data.0.get(), idx) }.cast_const()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: `UI_destroy_method` leaves the library's static methods alone (OpenSSL
    /// frees them, and crashes); they stay usable.
    #[test]
    fn destroying_a_builtin_method_does_nothing() {
        // SAFETY: no preconditions.
        let console = unsafe { UI_OpenSSL() };
        // SAFETY: a builtin method.
        unsafe { UI_destroy_method(console) };
        // SAFETY: as above, still live.
        assert!(unsafe { UI_method_get_reader(console) }.is_some());
        // SAFETY: no preconditions.
        assert_eq!(unsafe { UI_OpenSSL() }, console);
    }
}
