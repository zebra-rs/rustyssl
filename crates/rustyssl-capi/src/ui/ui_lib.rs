//! The UI itself (`UI_new(3)`; `ui_lib.c`, `ui_util.c`, and `evp_key.c`'s password prompt):
//! a UI's strings (prompts, verifications, booleans, information, errors), `UI_process` through
//! its method, results, user data, controls, the default method, and the utilities built on
//! them (`UI_UTIL_read_pw`, `UI_UTIL_wrap_read_pem_callback`, `EVP_read_pw_string`).
//!
//! As in OpenSSL, a UI isn't shared between threads, and a method's functions may call back
//! into the UI they're given (to set results, read user data, or add strings): nothing is
//! borrowed across those calls, and each string sits at a stable address for its life.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

use rustyssl_abi::{
    CRYPTO_EX_DATA, CRYPTO_EX_INDEX_UI, CRYPTO_EX_INDEX_UI_METHOD, ERR_LIB_UI,
    ERR_R_PASSED_NULL_PARAMETER, ERR_R_UI_LIB, PEM_BUFSIZE, UI, UI_CTRL_IS_REDOABLE,
    UI_CTRL_PRINT_ERRORS, UI_METHOD, UI_R_COMMON_OK_AND_CANCEL_CHARACTERS, UI_R_INDEX_TOO_LARGE,
    UI_R_INDEX_TOO_SMALL, UI_R_NO_RESULT_BUFFER, UI_R_PROCESSING_ERROR, UI_R_RESULT_TOO_LARGE,
    UI_R_RESULT_TOO_SMALL, UI_R_UNKNOWN_CONTROL_COMMAND, UI_R_USER_DATA_DUPLICATION_UNSUPPORTED,
    UI_STRING, UI_string_types, UIT_BOOLEAN, UIT_ERROR, UIT_INFO, UIT_PROMPT, UIT_VERIFY,
    pem_password_cb,
};

use super::{
    UI_OpenSSL, UI_create_method, UI_destroy_method, UI_method_get_ex_data, UI_method_set_closer,
    UI_method_set_ex_data, UI_method_set_opener, UI_method_set_reader, UI_method_set_writer,
    UI_null, funcs_of,
};
use crate::err;
use crate::ex_data::{
    CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data, CRYPTO_set_ex_data,
};
use crate::ffi::ffi_export;
use crate::mem;

/// `UI_FLAG_REDOABLE`, `UI_FLAG_DUPL_DATA`, and `UI_FLAG_PRINT_ERRORS` (`ui_local.h`).
const FLAG_REDOABLE: c_int = 0x0001;
const FLAG_DUPL_DATA: c_int = 0x0002;
const FLAG_PRINT_ERRORS: c_int = 0x0100;

/// A UI string (`struct ui_string_st`).
struct UiString {
    type_: UI_string_types,
    out_string: *const c_char,
    /// `OUT_STRING_FREEABLE`: the strings are the UI's copies (`UI_dup_*`).
    freeable: bool,
    input_flags: c_int,
    result_buf: *mut c_char,
    result_len: c_int,
    /// The input's sizes and the string to verify against (`string_data`).
    minsize: c_int,
    maxsize: c_int,
    test_buf: *const c_char,
    /// The boolean's description and characters (`boolean_data`).
    action_desc: *const c_char,
    ok_chars: *const c_char,
    cancel_chars: *const c_char,
}

impl UiString {
    const fn new(type_: UI_string_types, out_string: *const c_char) -> Self {
        Self {
            type_,
            out_string,
            freeable: false,
            input_flags: 0,
            result_buf: ptr::null_mut(),
            result_len: 0,
            minsize: 0,
            maxsize: 0,
            test_buf: ptr::null(),
            action_desc: ptr::null(),
            ok_chars: ptr::null(),
            cancel_chars: ptr::null(),
        }
    }
}

impl Drop for UiString {
    /// `free_string`: the UI's copies of its strings.
    fn drop(&mut self) {
        if self.freeable {
            for s in [
                self.out_string,
                self.action_desc,
                self.ok_chars,
                self.cancel_chars,
            ] {
                // SAFETY: the UI's copies, from `CRYPTO_malloc`, or NULL.
                unsafe { mem::release(s.cast_mut().cast()) };
            }
        }
    }
}

/// A `UI` (`struct ui_st`).
struct Ui {
    meth: *const UI_METHOD,
    /// Boxed: a method holds pointers to them while it may add more.
    #[allow(clippy::vec_box, reason = "the strings' addresses must not move")]
    strings: Vec<Box<UiString>>,
    user_data: *mut c_void,
    ex_data: CRYPTO_EX_DATA,
    flags: c_int,
}

/// The UI behind `ui`, for one access (never held across a method's function).
///
/// # Safety
/// `ui` is NULL or a live UI from `UI_new_method`.
unsafe fn ui_mut<'a>(ui: *mut UI) -> Option<&'a mut Ui> {
    // SAFETY: the caller's guarantee.
    unsafe { ui.cast::<Ui>().as_mut() }
}

/// The string behind `uis`.
///
/// # Safety
/// `uis` is NULL or a live string of a UI (or one `print_error` made).
unsafe fn uis_mut<'a>(uis: *mut UI_STRING) -> Option<&'a mut UiString> {
    // SAFETY: the caller's guarantee.
    unsafe { uis.cast::<UiString>().as_mut() }
}

/// The `i`th string of the UI, as the C pointer its method takes.
///
/// # Safety
/// As for [`ui_mut`].
unsafe fn nth(ui: *mut UI, i: usize) -> Option<*mut UI_STRING> {
    // SAFETY: the caller's guarantee; the borrow ends here.
    let u = unsafe { ui_mut(ui) }?;
    u.strings
        .get_mut(i)
        .map(|s| ptr::from_mut::<UiString>(s).cast())
}

/// The UI's method's functions.
///
/// # Safety
/// As for [`ui_mut`].
unsafe fn funcs(ui: *mut UI) -> super::Funcs {
    // SAFETY: the caller's guarantee.
    let m = unsafe { ui_mut(ui) }.map_or(ptr::null(), |u| u.meth);
    // SAFETY: the UI's method, live while the UI is (the application's contract).
    unsafe { funcs_of(m) }
}

/// The default method `UI_set_default_method` set, which may be NULL; `UI_OpenSSL` until one is
/// (`DEFAULT_SET`).
static DEFAULT_METHOD: AtomicPtr<UI_METHOD> = AtomicPtr::new(ptr::null_mut());
static DEFAULT_SET: AtomicBool = AtomicBool::new(false);

ffi_export! {
    /// Sets the method new UIs take. NULL is a method too: `UI_get_default_method` then gives
    /// NULL, and new UIs take `UI_null` (OpenSSL's `default_UI_meth`, starting at the console's).
    ///
    /// # Safety
    /// `meth` is NULL or a method that outlives its use as the default.
    pub unsafe extern "C" fn UI_set_default_method(meth: *const UI_METHOD)
    where failure = (), library = ERR_LIB_UI
    {
        DEFAULT_METHOD.store(meth.cast_mut(), Ordering::Release);
        DEFAULT_SET.store(true, Ordering::Release);
    }
}

ffi_export! {
    /// The method new UIs take: the one set (NULL if that was NULL), else `UI_OpenSSL`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn UI_get_default_method() -> *const UI_METHOD
    where failure = ptr::null(), library = ERR_LIB_UI
    {
        if DEFAULT_SET.load(Ordering::Acquire) {
            return DEFAULT_METHOD.load(Ordering::Acquire);
        }
        // SAFETY: no preconditions.
        unsafe { UI_OpenSSL() }
    }
}

ffi_export! {
    /// A new UI with the default method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn UI_new() -> *mut UI
    where failure = ptr::null_mut(), library = ERR_LIB_UI
    {
        // SAFETY: no preconditions.
        unsafe { UI_new_method(ptr::null()) }
    }
}

ffi_export! {
    /// A new UI with `method` (the default for NULL, else `UI_null`). NULL on failure.
    ///
    /// # Safety
    /// `method` is NULL or a method that outlives the UI.
    pub unsafe extern "C" fn UI_new_method(method: *const UI_METHOD) -> *mut UI
    where failure = ptr::null_mut(), library = ERR_LIB_UI
    {
        let mut meth = method;
        if meth.is_null() {
            // SAFETY: no preconditions.
            meth = unsafe { UI_get_default_method() };
        }
        if meth.is_null() {
            // SAFETY: no preconditions.
            meth = unsafe { UI_null() };
        }
        let ui = Box::into_raw(Box::new(Ui {
            meth,
            strings: Vec::new(),
            user_data: ptr::null_mut(),
            ex_data: CRYPTO_EX_DATA { ctx: ptr::null_mut(), sk: ptr::null_mut() },
            flags: 0,
        }));
        // SAFETY: the new UI's own ex_data, at a stable address.
        let ad = unsafe { &raw mut (*ui).ex_data };
        // SAFETY: the new UI and its ex_data.
        if unsafe { CRYPTO_new_ex_data(CRYPTO_EX_INDEX_UI, ui.cast(), ad) } == 0 {
            // SAFETY: made above.
            unsafe { UI_free(ui.cast()) };
            return ptr::null_mut();
        }
        ui.cast()
    }
}

ffi_export! {
    /// Frees the UI: its duplicated user data (through the method's destructor), its strings,
    /// and its application data. NULL does nothing.
    ///
    /// # Safety
    /// `ui` is NULL or a live UI, not used afterwards.
    pub unsafe extern "C" fn UI_free(ui: *mut UI)
    where failure = (), library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        let Some(u) = (unsafe { ui_mut(ui) }) else { return };
        let (dupl, data) = (u.flags & FLAG_DUPL_DATA != 0, u.user_data);
        if dupl {
            // SAFETY: the UI's method.
            if let Some(destroy) = unsafe { funcs(ui) }.destroy {
                // SAFETY: the method's destructor of the data its duplicator made.
                unsafe { destroy(ui, data) };
            }
        }
        // SAFETY: the caller's guarantee (re-borrowed after the destructor).
        let ad = unsafe { &raw mut (*ui.cast::<Ui>()).ex_data };
        // SAFETY: the UI's own ex_data.
        unsafe { CRYPTO_free_ex_data(CRYPTO_EX_INDEX_UI, ui.cast(), ad) };
        // SAFETY: a UI from `UI_new_method`, freed once.
        drop(unsafe { Box::from_raw(ui.cast::<Ui>()) });
    }
}

/// `general_allocate_prompt`: a string of `type_` for `prompt`; `None` (with an error) for no
/// prompt, or for an input without a result buffer.
fn allocate_prompt(
    prompt: *const c_char,
    freeable: bool,
    type_: UI_string_types,
    input_flags: c_int,
    result_buf: *mut c_char,
) -> Option<Box<UiString>> {
    const F: &str = "general_allocate_prompt";
    if prompt.is_null() {
        err::raise(ERR_LIB_UI, ERR_R_PASSED_NULL_PARAMETER, F);
        return None;
    }
    if matches!(type_, UIT_PROMPT | UIT_VERIFY | UIT_BOOLEAN) && result_buf.is_null() {
        err::raise(ERR_LIB_UI, UI_R_NO_RESULT_BUFFER, F);
        return None;
    }
    let mut s = Box::new(UiString::new(type_, prompt));
    s.freeable = freeable;
    s.input_flags = input_flags;
    s.result_buf = result_buf;
    Some(s)
}

/// Adds the string to the UI: its number of strings after, or -1.
///
/// # Safety
/// As for [`ui_mut`].
unsafe fn push(ui: *mut UI, s: Box<UiString>) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(u) = (unsafe { ui_mut(ui) }) else {
        return -1;
    };
    u.strings.push(s);
    c_int::try_from(u.strings.len()).unwrap_or(c_int::MAX)
}

/// `general_allocate_string`: a prompt, verification, information, or error added to the UI:
/// its number of strings, or -1 (the copies a `UI_dup_*` made are the caller's to free then).
///
/// # Safety
/// As for [`ui_mut`]; `prompt` and `test_buf` are NULL or C strings that outlive the UI (or the
/// UI's copies); `result_buf` has room for `maxsize + 1` octets.
#[allow(clippy::too_many_arguments, reason = "general_allocate_string's")]
unsafe fn allocate_string(
    ui: *mut UI,
    prompt: *const c_char,
    freeable: bool,
    type_: UI_string_types,
    input_flags: c_int,
    result_buf: *mut c_char,
    minsize: c_int,
    maxsize: c_int,
    test_buf: *const c_char,
) -> c_int {
    // (OpenSSL dereferences a NULL UI; refusing it first leaves a copy the caller's.)
    if ui.is_null() {
        return -1;
    }
    let Some(mut s) = allocate_prompt(prompt, freeable, type_, input_flags, result_buf) else {
        return -1;
    };
    s.minsize = minsize;
    s.maxsize = maxsize;
    s.test_buf = test_buf;
    // SAFETY: the caller's guarantee (a live UI: the push can't fail).
    unsafe { push(ui, s) }
}

/// A C string's copy from `CRYPTO_malloc` (`OPENSSL_strdup`), or NULL.
///
/// # Safety
/// `s` is a C string.
unsafe fn strdup(s: *const c_char) -> *mut c_char {
    // SAFETY: the caller's guarantee.
    let bytes = unsafe { CStr::from_ptr(s) }.to_bytes_with_nul();
    let p: *mut c_char = mem::malloc(bytes.len(), ptr::null(), 0).cast();
    if !p.is_null() {
        // SAFETY: a new buffer of the string's length.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr().cast(), p, bytes.len()) };
    }
    p
}

/// A copy of the optional C string: `Some(NULL)` for NULL, `None` if it can't be made.
///
/// # Safety
/// `s` is NULL or a C string.
unsafe fn dup_opt(s: *const c_char) -> Option<*mut c_char> {
    if s.is_null() {
        return Some(ptr::null_mut());
    }
    // SAFETY: the caller's guarantee.
    let p = unsafe { strdup(s) };
    (!p.is_null()).then_some(p)
}

/// A `UI_dup_*` of a string: `allocate_string` of a copy of `text` (freed if it isn't added).
///
/// # Safety
/// As for `allocate_string`.
#[allow(clippy::too_many_arguments, reason = "general_allocate_string's")]
unsafe fn dup_string(
    ui: *mut UI,
    text: *const c_char,
    type_: UI_string_types,
    input_flags: c_int,
    result_buf: *mut c_char,
    minsize: c_int,
    maxsize: c_int,
    test_buf: *const c_char,
    oom: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(copy) = (unsafe { dup_opt(text) }) else {
        return oom;
    };
    // SAFETY: as above, with the copy (which the UI frees once it holds it).
    let ret = unsafe {
        allocate_string(
            ui,
            copy,
            true,
            type_,
            input_flags,
            result_buf,
            minsize,
            maxsize,
            test_buf,
        )
    };
    if ret <= 0 {
        // Not added (refused before a string held it): the copy is ours.
        // SAFETY: made above, or NULL.
        unsafe { mem::release(copy.cast()) };
    }
    ret
}

ffi_export! {
    /// Adds a prompt for input into `result_buf` (`minsize` to `maxsize` characters): the UI's
    /// number of strings, or -1.
    ///
    /// # Safety
    /// `ui` is a live UI; `prompt` is NULL or a C string that outlives the UI; `result_buf` has
    /// room for `maxsize + 1` octets.
    pub unsafe extern "C" fn UI_add_input_string(ui: *mut UI, prompt: *const c_char, flags: c_int, result_buf: *mut c_char, minsize: c_int, maxsize: c_int) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { allocate_string(ui, prompt, false, UIT_PROMPT, flags, result_buf, minsize, maxsize, ptr::null()) }
    }
}

ffi_export! {
    /// `UI_add_input_string` with a copy of the prompt (0 if it can't be copied).
    ///
    /// # Safety
    /// As for `UI_add_input_string`, with `prompt` NULL or a C string.
    pub unsafe extern "C" fn UI_dup_input_string(ui: *mut UI, prompt: *const c_char, flags: c_int, result_buf: *mut c_char, minsize: c_int, maxsize: c_int) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup_string(ui, prompt, UIT_PROMPT, flags, result_buf, minsize, maxsize, ptr::null(), 0) }
    }
}

ffi_export! {
    /// Adds a prompt whose input must equal `test_buf`: the UI's number of strings, or -1.
    ///
    /// # Safety
    /// As for `UI_add_input_string`; `test_buf` is NULL or a buffer that outlives the UI.
    pub unsafe extern "C" fn UI_add_verify_string(ui: *mut UI, prompt: *const c_char, flags: c_int, result_buf: *mut c_char, minsize: c_int, maxsize: c_int, test_buf: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { allocate_string(ui, prompt, false, UIT_VERIFY, flags, result_buf, minsize, maxsize, test_buf) }
    }
}

ffi_export! {
    /// `UI_add_verify_string` with a copy of the prompt.
    ///
    /// # Safety
    /// As for `UI_add_verify_string`, with `prompt` NULL or a C string.
    pub unsafe extern "C" fn UI_dup_verify_string(ui: *mut UI, prompt: *const c_char, flags: c_int, result_buf: *mut c_char, minsize: c_int, maxsize: c_int, test_buf: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup_string(ui, prompt, UIT_VERIFY, flags, result_buf, minsize, maxsize, test_buf, -1) }
    }
}

/// `general_allocate_boolean`: a yes/no question (an error, but no failure, for characters both
/// in `ok_chars` and `cancel_chars`).
///
/// # Safety
/// As for `allocate_string`, with the strings NULL or C strings outliving the UI.
#[allow(clippy::too_many_arguments, reason = "general_allocate_boolean's")]
unsafe fn allocate_boolean(
    ui: *mut UI,
    prompt: *const c_char,
    action_desc: *const c_char,
    ok_chars: *const c_char,
    cancel_chars: *const c_char,
    freeable: bool,
    flags: c_int,
    result_buf: *mut c_char,
) -> c_int {
    const F: &str = "general_allocate_boolean";
    if ok_chars.is_null() || cancel_chars.is_null() {
        err::raise(ERR_LIB_UI, ERR_R_PASSED_NULL_PARAMETER, F);
        return -1;
    }
    // SAFETY: the caller's C strings.
    let ok = unsafe { CStr::from_ptr(ok_chars) }.to_bytes();
    // SAFETY: as above.
    let cancel = unsafe { CStr::from_ptr(cancel_chars) }.to_bytes();
    for c in ok {
        if cancel.contains(c) {
            err::raise(ERR_LIB_UI, UI_R_COMMON_OK_AND_CANCEL_CHARACTERS, F);
        }
    }
    if ui.is_null() {
        return -1;
    }
    let Some(mut s) = allocate_prompt(prompt, freeable, UIT_BOOLEAN, flags, result_buf) else {
        return -1;
    };
    s.action_desc = action_desc;
    s.ok_chars = ok_chars;
    s.cancel_chars = cancel_chars;
    // SAFETY: the caller's guarantee.
    unsafe { push(ui, s) }
}

ffi_export! {
    /// Adds a yes/no question: its answer, the first of `ok_chars` or of `cancel_chars`, goes
    /// into `result_buf`. The UI's number of strings, or -1.
    ///
    /// # Safety
    /// `ui` is a live UI; the strings are NULL or C strings that outlive the UI; `result_buf` has
    /// room for an octet.
    pub unsafe extern "C" fn UI_add_input_boolean(ui: *mut UI, prompt: *const c_char, action_desc: *const c_char, ok_chars: *const c_char, cancel_chars: *const c_char, flags: c_int, result_buf: *mut c_char) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { allocate_boolean(ui, prompt, action_desc, ok_chars, cancel_chars, false, flags, result_buf) }
    }
}

ffi_export! {
    /// `UI_add_input_boolean` with copies of the strings.
    ///
    /// # Safety
    /// As for `UI_add_input_boolean`, with the strings NULL or C strings.
    pub unsafe extern "C" fn UI_dup_input_boolean(ui: *mut UI, prompt: *const c_char, action_desc: *const c_char, ok_chars: *const c_char, cancel_chars: *const c_char, flags: c_int, result_buf: *mut c_char) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        let mut copies: [*mut c_char; 4] = [ptr::null_mut(); 4];
        let free = |copies: &[*mut c_char; 4]| {
            for c in copies {
                // SAFETY: copies made here, or NULL.
                unsafe { mem::release(c.cast()) };
            }
        };
        for (slot, s) in copies.iter_mut().zip([prompt, action_desc, ok_chars, cancel_chars]) {
            // SAFETY: the caller's string, or NULL.
            let Some(c) = (unsafe { dup_opt(s) }) else {
                free(&copies);
                return -1;
            };
            *slot = c;
        }
        let [p, a, o, c] = copies;
        // SAFETY: the copies; the caller's UI and buffer.
        let ret = unsafe { allocate_boolean(ui, p, a, o, c, true, flags, result_buf) };
        if ret <= 0 {
            // Not added (`allocate_boolean` drops nothing before adding): the copies are ours.
            free(&copies);
            return -1;
        }
        ret
    }
}

ffi_export! {
    /// Adds information to show: the UI's number of strings, or -1.
    ///
    /// # Safety
    /// `ui` is a live UI; `text` is NULL or a C string that outlives the UI.
    pub unsafe extern "C" fn UI_add_info_string(ui: *mut UI, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { allocate_string(ui, text, false, UIT_INFO, 0, ptr::null_mut(), 0, 0, ptr::null()) }
    }
}

ffi_export! {
    /// `UI_add_info_string` with a copy of the text.
    ///
    /// # Safety
    /// As for `UI_add_info_string`, with `text` NULL or a C string.
    pub unsafe extern "C" fn UI_dup_info_string(ui: *mut UI, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup_string(ui, text, UIT_INFO, 0, ptr::null_mut(), 0, 0, ptr::null(), -1) }
    }
}

ffi_export! {
    /// Adds an error to show: the UI's number of strings, or -1.
    ///
    /// # Safety
    /// As for `UI_add_info_string`.
    pub unsafe extern "C" fn UI_add_error_string(ui: *mut UI, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { allocate_string(ui, text, false, UIT_ERROR, 0, ptr::null_mut(), 0, 0, ptr::null()) }
    }
}

ffi_export! {
    /// `UI_add_error_string` with a copy of the text.
    ///
    /// # Safety
    /// As for `UI_dup_info_string`.
    pub unsafe extern "C" fn UI_dup_error_string(ui: *mut UI, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup_string(ui, text, UIT_ERROR, 0, ptr::null_mut(), 0, 0, ptr::null(), -1) }
    }
}

ffi_export! {
    /// The method's prompt for a passphrase-like thing, or "Enter <phrase_desc> for
    /// <object_name>:" (the object left out when NULL), from `CRYPTO_malloc`; NULL for no
    /// description.
    ///
    /// # Safety
    /// `ui` is NULL or a live UI; the strings are NULL or C strings.
    pub unsafe extern "C" fn UI_construct_prompt(ui: *mut UI, phrase_desc: *const c_char, object_name: *const c_char) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        if let Some(prompt) = unsafe { funcs(ui) }.prompt {
            // SAFETY: the method's constructor with the caller's strings.
            return unsafe { prompt(ui, phrase_desc, object_name) };
        }
        if phrase_desc.is_null() {
            return ptr::null_mut();
        }
        let mut text = b"Enter ".to_vec();
        // SAFETY: the caller's C string.
        text.extend_from_slice(unsafe { CStr::from_ptr(phrase_desc) }.to_bytes());
        if !object_name.is_null() {
            text.extend_from_slice(b" for ");
            // SAFETY: as above.
            text.extend_from_slice(unsafe { CStr::from_ptr(object_name) }.to_bytes());
        }
        text.extend_from_slice(b":\0");
        let p: *mut c_char = mem::malloc(text.len(), ptr::null(), 0).cast();
        if !p.is_null() {
            // SAFETY: a new buffer of the text's length.
            unsafe { ptr::copy_nonoverlapping(text.as_ptr().cast(), p, text.len()) };
        }
        p
    }
}

ffi_export! {
    /// Sets the UI's user data: the old data, or NULL when it was a duplicate (destroyed now).
    ///
    /// # Safety
    /// `ui` is a live UI.
    pub unsafe extern "C" fn UI_add_user_data(ui: *mut UI, user_data: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        let Some(u) = (unsafe { ui_mut(ui) }) else { return ptr::null_mut() };
        let (mut old, dupl) = (u.user_data, u.flags & FLAG_DUPL_DATA != 0);
        if dupl {
            // SAFETY: the UI's method.
            if let Some(destroy) = unsafe { funcs(ui) }.destroy {
                // SAFETY: the method's destructor of its duplicate.
                unsafe { destroy(ui, old) };
            }
            old = ptr::null_mut();
        }
        // SAFETY: the caller's guarantee (re-borrowed after the destructor).
        if let Some(u) = unsafe { ui_mut(ui) } {
            u.user_data = user_data;
            u.flags &= !FLAG_DUPL_DATA;
        }
        old
    }
}

ffi_export! {
    /// Sets the UI's user data to the method's duplicate of `user_data`: 0, or -1.
    ///
    /// # Safety
    /// `ui` is a live UI; `user_data` is what the method's duplicator takes.
    pub unsafe extern "C" fn UI_dup_user_data(ui: *mut UI, user_data: *mut c_void) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        const F: &str = "UI_dup_user_data";
        // SAFETY: the caller's guarantee.
        let f = unsafe { funcs(ui) };
        let (Some(duplicate), Some(_)) = (f.duplicate, f.destroy) else {
            err::raise(ERR_LIB_UI, UI_R_USER_DATA_DUPLICATION_UNSUPPORTED, F);
            return -1;
        };
        // SAFETY: the method's duplicator with the caller's data.
        let duplicate = unsafe { duplicate(ui, user_data) };
        if duplicate.is_null() {
            err::raise(ERR_LIB_UI, ERR_R_UI_LIB, F);
            return -1;
        }
        // SAFETY: the caller's UI.
        unsafe { UI_add_user_data(ui, duplicate) };
        // SAFETY: as above.
        if let Some(u) = unsafe { ui_mut(ui) } {
            u.flags |= FLAG_DUPL_DATA;
        }
        0
    }
}

ffi_export! {
    /// The UI's user data.
    ///
    /// # Safety
    /// `ui` is a live UI.
    pub unsafe extern "C" fn UI_get0_user_data(ui: *mut UI) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { ui_mut(ui) }.map_or(ptr::null_mut(), |u| u.user_data)
    }
}

/// The `i`th string, or `None` with `UI_R_INDEX_TOO_SMALL` or `_LARGE`.
///
/// # Safety
/// As for [`ui_mut`].
unsafe fn indexed(ui: *mut UI, i: c_int, f: &str) -> Option<*mut UI_STRING> {
    let Ok(i) = usize::try_from(i) else {
        err::raise(ERR_LIB_UI, UI_R_INDEX_TOO_SMALL, f);
        return None;
    };
    // SAFETY: the caller's guarantee.
    let s = unsafe { nth(ui, i) };
    if s.is_none() {
        err::raise(ERR_LIB_UI, UI_R_INDEX_TOO_LARGE, f);
    }
    s
}

ffi_export! {
    /// The result of the `i`th string (a prompt's or verification's), or NULL.
    ///
    /// # Safety
    /// `ui` is a live UI.
    pub unsafe extern "C" fn UI_get0_result(ui: *mut UI, i: c_int) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { indexed(ui, i, "UI_get0_result") }) else { return ptr::null() };
        // SAFETY: the UI's string.
        unsafe { UI_get0_result_string(s) }
    }
}

ffi_export! {
    /// The length of the `i`th string's result, or -1.
    ///
    /// # Safety
    /// `ui` is a live UI.
    pub unsafe extern "C" fn UI_get_result_length(ui: *mut UI, i: c_int) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { indexed(ui, i, "UI_get_result_length") }) else { return -1 };
        // SAFETY: the UI's string.
        unsafe { UI_get_result_string_length(s) }
    }
}

/// `print_error`: an error string written through the method (0, or -1 if it can't be).
unsafe extern "C" fn print_error(str_: *const c_char, _len: usize, u: *mut c_void) -> c_int {
    let ui: *mut UI = u.cast();
    // SAFETY: `UI_process`'s UI.
    let Some(write) = (unsafe { funcs(ui) }).write else {
        return 0;
    };
    let mut uis = UiString::new(UIT_ERROR, str_);
    // SAFETY: the method's writer with the UI and a string made here.
    if unsafe { write(ui, ptr::from_mut(&mut uis).cast()) } <= 0 {
        return -1;
    }
    0
}

ffi_export! {
    /// Runs the UI through its method: open, (the error queue if asked), write each string,
    /// flush, read each string, close. 0 on success, -1 on an error (`UI_R_PROCESSING_ERROR`
    /// saying where), -2 when the user cancelled.
    ///
    /// # Safety
    /// `ui` is a live UI.
    pub unsafe extern "C" fn UI_process(ui: *mut UI) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        let clear_redoable = |ui: *mut UI| {
            // SAFETY: the caller's UI.
            if let Some(u) = unsafe { ui_mut(ui) } {
                u.flags &= !FLAG_REDOABLE;
            }
        };
        let mut ok = 0;
        let mut state: Option<&str> = Some("processing");
        'run: {
            // SAFETY: the caller's guarantee.
            let f = unsafe { funcs(ui) };
            // SAFETY: the method's opener with the UI.
            if let Some(open) = f.open && unsafe { open(ui) } <= 0 {
                state = Some("opening session");
                ok = -1;
                break 'run;
            }
            // SAFETY: as above.
            let print_errors = unsafe { ui_mut(ui) }.is_some_and(|u| u.flags & FLAG_PRINT_ERRORS != 0);
            if print_errors {
                // SAFETY: the callback with the UI.
                unsafe { crate::err::strings::ERR_print_errors_cb(Some(print_error), ui.cast()) };
            }
            let mut i = 0;
            // SAFETY: as above (each string looked up afresh: the writer may add strings).
            while let Some(s) = unsafe { nth(ui, i) } {
                // SAFETY: the method's writer with the UI and its string.
                if let Some(write) = unsafe { funcs(ui) }.write && unsafe { write(ui, s) } <= 0 {
                    state = Some("writing strings");
                    ok = -1;
                    break 'run;
                }
                i = i.saturating_add(1);
            }
            // SAFETY: as above.
            if let Some(flush) = unsafe { funcs(ui) }.flush {
                // SAFETY: the method's flusher with the UI.
                match unsafe { flush(ui) } {
                    -1 => {
                        clear_redoable(ui);
                        ok = -2;
                        break 'run;
                    }
                    0 => {
                        state = Some("flushing");
                        ok = -1;
                        break 'run;
                    }
                    _ => ok = 0,
                }
            }
            let mut i = 0;
            // SAFETY: as above.
            while let Some(s) = unsafe { nth(ui, i) } {
                // SAFETY: as above.
                let Some(read) = unsafe { funcs(ui) }.read else {
                    clear_redoable(ui);
                    ok = -2;
                    break 'run;
                };
                // SAFETY: the method's reader with the UI and its string.
                match unsafe { read(ui, s) } {
                    -1 => {
                        clear_redoable(ui);
                        ok = -2;
                        break 'run;
                    }
                    0 => {
                        state = Some("reading strings");
                        ok = -1;
                        break 'run;
                    }
                    _ => ok = 0,
                }
                i = i.saturating_add(1);
            }
            state = None;
        }
        // SAFETY: as above.
        if let Some(close) = unsafe { funcs(ui) }.close && unsafe { close(ui) } <= 0 {
            if state.is_none() {
                state = Some("closing session");
            }
            ok = -1;
        }
        if ok == -1 {
            err::raise_with_text(ERR_LIB_UI, UI_R_PROCESSING_ERROR, "UI_process", &format!("while {}", state.unwrap_or("")));
        }
        ok
    }
}

ffi_export! {
    /// `UI_CTRL_PRINT_ERRORS` (sets whether `UI_process` shows the error queue, returning the
    /// old setting) and `UI_CTRL_IS_REDOABLE`; -1 otherwise.
    ///
    /// # Safety
    /// `ui` is NULL or a live UI.
    pub unsafe extern "C" fn UI_ctrl(ui: *mut UI, cmd: c_int, i: c_long, _p: *mut c_void, _f: Option<unsafe extern "C" fn()>) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        let Some(u) = (unsafe { ui_mut(ui) }) else {
            err::raise(ERR_LIB_UI, ERR_R_PASSED_NULL_PARAMETER, "UI_ctrl");
            return -1;
        };
        match cmd {
            UI_CTRL_PRINT_ERRORS => {
                let saved = c_int::from(u.flags & FLAG_PRINT_ERRORS != 0);
                if i != 0 {
                    u.flags |= FLAG_PRINT_ERRORS;
                } else {
                    u.flags &= !FLAG_PRINT_ERRORS;
                }
                saved
            }
            UI_CTRL_IS_REDOABLE => c_int::from(u.flags & FLAG_REDOABLE != 0),
            _ => {
                err::raise(ERR_LIB_UI, UI_R_UNKNOWN_CONTROL_COMMAND, "UI_ctrl");
                -1
            }
        }
    }
}

ffi_export! {
    /// Sets the UI's application data at `idx`: 1, or 0.
    ///
    /// # Safety
    /// `r` is a live UI.
    pub unsafe extern "C" fn UI_set_ex_data(r: *mut UI, idx: c_int, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_UI
    {
        if r.is_null() {
            return 0;
        }
        // SAFETY: the caller's UI's own ex_data.
        let ad = unsafe { &raw mut (*r.cast::<Ui>()).ex_data };
        // SAFETY: as above.
        unsafe { CRYPTO_set_ex_data(ad, idx, arg) }
    }
}

ffi_export! {
    /// The UI's application data at `idx`, or NULL.
    ///
    /// # Safety
    /// `r` is a live UI.
    pub unsafe extern "C" fn UI_get_ex_data(r: *const UI, idx: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_UI
    {
        if r.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's UI's own ex_data.
        let ad = unsafe { &raw const (*r.cast::<Ui>()).ex_data };
        // SAFETY: as above.
        unsafe { CRYPTO_get_ex_data(ad, idx) }
    }
}

ffi_export! {
    /// The UI's method.
    ///
    /// # Safety
    /// `ui` is a live UI.
    pub unsafe extern "C" fn UI_get_method(ui: *mut UI) -> *const UI_METHOD
    where failure = ptr::null(), library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { ui_mut(ui) }.map_or(ptr::null(), |u| u.meth)
    }
}

ffi_export! {
    /// Sets the UI's method; returns it.
    ///
    /// # Safety
    /// `ui` is a live UI; `meth` is NULL or a method that outlives its use.
    pub unsafe extern "C" fn UI_set_method(ui: *mut UI, meth: *const UI_METHOD) -> *const UI_METHOD
    where failure = ptr::null(), library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        let Some(u) = (unsafe { ui_mut(ui) }) else { return ptr::null() };
        u.meth = meth;
        meth
    }
}

ffi_export! {
    /// The string's type.
    ///
    /// # Safety
    /// `uis` is a live UI string.
    pub unsafe extern "C" fn UI_get_string_type(uis: *mut UI_STRING) -> UI_string_types
    where failure = 0, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { uis_mut(uis) }.map_or(0, |s| s.type_)
    }
}

ffi_export! {
    /// The string's input flags.
    ///
    /// # Safety
    /// `uis` is a live UI string.
    pub unsafe extern "C" fn UI_get_input_flags(uis: *mut UI_STRING) -> c_int
    where failure = 0, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { uis_mut(uis) }.map_or(0, |s| s.input_flags)
    }
}

ffi_export! {
    /// The string's text (the prompt, information, or error).
    ///
    /// # Safety
    /// `uis` is a live UI string.
    pub unsafe extern "C" fn UI_get0_output_string(uis: *mut UI_STRING) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { uis_mut(uis) }.map_or(ptr::null(), |s| s.out_string)
    }
}

ffi_export! {
    /// A boolean's action description, else NULL.
    ///
    /// # Safety
    /// `uis` is a live UI string.
    pub unsafe extern "C" fn UI_get0_action_string(uis: *mut UI_STRING) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { uis_mut(uis) }.filter(|s| s.type_ == UIT_BOOLEAN).map_or(ptr::null(), |s| s.action_desc)
    }
}

ffi_export! {
    /// A prompt's or verification's result buffer, else NULL.
    ///
    /// # Safety
    /// `uis` is a live UI string.
    pub unsafe extern "C" fn UI_get0_result_string(uis: *mut UI_STRING) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { uis_mut(uis) }
            .filter(|s| matches!(s.type_, UIT_PROMPT | UIT_VERIFY))
            .map_or(ptr::null(), |s| s.result_buf.cast_const())
    }
}

ffi_export! {
    /// A prompt's or verification's result length, else -1.
    ///
    /// # Safety
    /// `uis` is a live UI string.
    pub unsafe extern "C" fn UI_get_result_string_length(uis: *mut UI_STRING) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { uis_mut(uis) }.filter(|s| matches!(s.type_, UIT_PROMPT | UIT_VERIFY)).map_or(-1, |s| s.result_len)
    }
}

ffi_export! {
    /// A verification's string to match, else NULL.
    ///
    /// # Safety
    /// `uis` is a live UI string.
    pub unsafe extern "C" fn UI_get0_test_string(uis: *mut UI_STRING) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { uis_mut(uis) }.filter(|s| s.type_ == UIT_VERIFY).map_or(ptr::null(), |s| s.test_buf)
    }
}

ffi_export! {
    /// A prompt's or verification's minimum length, else -1.
    ///
    /// # Safety
    /// `uis` is a live UI string.
    pub unsafe extern "C" fn UI_get_result_minsize(uis: *mut UI_STRING) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { uis_mut(uis) }.filter(|s| matches!(s.type_, UIT_PROMPT | UIT_VERIFY)).map_or(-1, |s| s.minsize)
    }
}

ffi_export! {
    /// A prompt's or verification's maximum length, else -1.
    ///
    /// # Safety
    /// `uis` is a live UI string.
    pub unsafe extern "C" fn UI_get_result_maxsize(uis: *mut UI_STRING) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { uis_mut(uis) }.filter(|s| matches!(s.type_, UIT_PROMPT | UIT_VERIFY)).map_or(-1, |s| s.maxsize)
    }
}

ffi_export! {
    /// `UI_set_result_ex` of a C string.
    ///
    /// # Safety
    /// As for `UI_set_result_ex`, with `result` a C string.
    pub unsafe extern "C" fn UI_set_result(ui: *mut UI, uis: *mut UI_STRING, result: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        let len = unsafe { CStr::from_ptr(result) }.count_bytes();
        // SAFETY: as above.
        unsafe { UI_set_result_ex(ui, uis, result, c_int::try_from(len).unwrap_or(c_int::MAX)) }
    }
}

ffi_export! {
    /// Sets a string's result: a prompt's or verification's `len` octets (within its sizes,
    /// else -1 and the UI redoable), or a boolean's answer (the first of its ok or cancel
    /// characters `result` holds). 0, or -1.
    ///
    /// # Safety
    /// `ui` is a live UI; `uis` is one of its strings; `result` has `len` octets (a boolean's is
    /// a C string).
    pub unsafe extern "C" fn UI_set_result_ex(ui: *mut UI, uis: *mut UI_STRING, result: *const c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        const F: &str = "UI_set_result_ex";
        // SAFETY: the caller's guarantee.
        let Some(u) = (unsafe { ui_mut(ui) }) else { return -1 };
        u.flags &= !FLAG_REDOABLE;
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { uis_mut(uis) }) else { return -1 };
        match s.type_ {
            UIT_PROMPT | UIT_VERIFY => {
                let sizes = format!("You must type in {} to {} characters", s.minsize, s.maxsize);
                if len < s.minsize {
                    u.flags |= FLAG_REDOABLE;
                    err::raise_with_text(ERR_LIB_UI, UI_R_RESULT_TOO_SMALL, F, &sizes);
                    return -1;
                }
                if len > s.maxsize {
                    u.flags |= FLAG_REDOABLE;
                    err::raise_with_text(ERR_LIB_UI, UI_R_RESULT_TOO_LARGE, F, &sizes);
                    return -1;
                }
                if s.result_buf.is_null() {
                    err::raise(ERR_LIB_UI, UI_R_NO_RESULT_BUFFER, F);
                    return -1;
                }
                let n = usize::try_from(len).unwrap_or(0);
                // SAFETY: the caller's `len` octets; the string's buffer, with room for `maxsize
                // + 1` (`len` is no more than `maxsize`).
                unsafe { ptr::copy_nonoverlapping(result, s.result_buf, n) };
                // SAFETY: as above.
                unsafe { s.result_buf.wrapping_add(n).write(0) };
                s.result_len = len;
            }
            UIT_BOOLEAN => {
                if s.result_buf.is_null() {
                    err::raise(ERR_LIB_UI, UI_R_NO_RESULT_BUFFER, F);
                    return -1;
                }
                // SAFETY: the string's buffer, with room for an octet.
                unsafe { s.result_buf.write(0) };
                // SAFETY: the caller's C string.
                let answer = unsafe { CStr::from_ptr(result) }.to_bytes();
                // SAFETY: the string's characters, C strings.
                let ok = unsafe { CStr::from_ptr(s.ok_chars) }.to_bytes();
                // SAFETY: as above.
                let cancel = unsafe { CStr::from_ptr(s.cancel_chars) }.to_bytes();
                for c in answer {
                    let pick = if ok.contains(c) {
                        ok.first()
                    } else if cancel.contains(c) {
                        cancel.first()
                    } else {
                        continue;
                    };
                    if let Some(&p) = pick {
                        // SAFETY: as above.
                        unsafe { s.result_buf.write(c_char::from_ne_bytes([p])) };
                    }
                    break;
                }
            }
            _ => {}
        }
        0
    }
}

/// `BUFSIZ` as `ui_util.c` and `evp_key.c` take it.
const BUFSIZ: usize = 256;

ffi_export! {
    /// Reads a password into `buf` (`length` octets of room, at most `BUFSIZ`) with the default
    /// UI, asking twice when `verify`: `UI_process`'s result, or -1.
    ///
    /// # Safety
    /// `buf` has room for `length` octets; `prompt` is NULL or a C string.
    pub unsafe extern "C" fn UI_UTIL_read_pw_string(buf: *mut c_char, length: c_int, prompt: *const c_char, verify: c_int) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        let mut buff = rustyssl_crypto::bn::Zeroizing::new([0 as c_char; BUFSIZ]);
        let size = length.min(c_int::try_from(BUFSIZ).unwrap_or(c_int::MAX));
        // SAFETY: the caller's guarantee; a buffer of `BUFSIZ`.
        unsafe { UI_UTIL_read_pw(buf, buff.as_mut_ptr(), size, prompt, verify) }
    }
}

ffi_export! {
    /// Reads a password into `buf` (and, verifying, again into `buff`), each `size` octets of
    /// room: `UI_process`'s result, -1 for no room, or -2 if no UI can be made.
    ///
    /// # Safety
    /// `buf` and `buff` have room for `size` octets; `prompt` is NULL or a C string.
    pub unsafe extern "C" fn UI_UTIL_read_pw(buf: *mut c_char, buff: *mut c_char, size: c_int, prompt: *const c_char, verify: c_int) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        if size < 1 {
            return -1;
        }
        // SAFETY: no preconditions.
        let ui = unsafe { UI_new() };
        if ui.is_null() {
            return -2;
        }
        let max = size.saturating_sub(1);
        // SAFETY: the new UI; the caller's prompt and buffers.
        let mut ok = unsafe { UI_add_input_string(ui, prompt, 0, buf, 0, max) };
        if ok >= 0 && verify != 0 {
            // SAFETY: as above.
            ok = unsafe { UI_add_verify_string(ui, prompt, 0, buff, 0, max, buf) };
        }
        if ok >= 0 {
            // SAFETY: as above.
            ok = unsafe { UI_process(ui) };
        }
        // SAFETY: made above.
        unsafe { UI_free(ui) };
        ok
    }
}

/// `struct pem_password_cb_data`: the wrapped callback and the rwflag it's given.
#[repr(C)]
struct PemCbData {
    cb: unsafe extern "C" fn(*mut c_char, c_int, c_int, *mut c_void) -> c_int,
    rwflag: c_int,
}

/// `ui_dup_method_data`: a copy of the data (`OPENSSL_memdup`).
unsafe extern "C" fn dup_method_data(
    _to: *mut CRYPTO_EX_DATA,
    _from: *const CRYPTO_EX_DATA,
    pptr: *mut *mut c_void,
    _idx: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) -> c_int {
    // SAFETY: the ex_data machinery's slot.
    let from = unsafe { pptr.read() };
    if from.is_null() {
        return 0;
    }
    let to: *mut PemCbData = mem::malloc(size_of::<PemCbData>(), ptr::null(), 0).cast();
    if to.is_null() {
        // SAFETY: as above.
        unsafe { pptr.write(ptr::null_mut()) };
        return 0;
    }
    // SAFETY: the data, a `PemCbData`; the new block of its size.
    unsafe { ptr::copy_nonoverlapping(from.cast::<PemCbData>(), to, 1) };
    // SAFETY: as above.
    unsafe { pptr.write(to.cast()) };
    1
}

/// `ui_free_method_data`.
unsafe extern "C" fn free_method_data(
    _parent: *mut c_void,
    ptr_: *mut c_void,
    _ad: *mut CRYPTO_EX_DATA,
    _idx: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
    // SAFETY: the data, from `CRYPTO_malloc`, or NULL.
    unsafe { mem::release(ptr_) };
}

/// `ui_new_method_data`: nothing.
unsafe extern "C" fn new_method_data(
    _parent: *mut c_void,
    _ptr: *mut c_void,
    _ad: *mut CRYPTO_EX_DATA,
    _idx: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
}

/// `ui_method_data_index`, taken once (with OpenSSL's callbacks).
fn method_data_index() -> Option<c_int> {
    static INDEX: OnceLock<c_int> = OnceLock::new();
    static ONCE: Mutex<()> = Mutex::new(());
    if let Some(&i) = INDEX.get() {
        return Some(i);
    }
    let _g = ONCE.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(&i) = INDEX.get() {
        return Some(i);
    }
    // SAFETY: the class; the callbacks above.
    let i = unsafe {
        crate::ex_data::CRYPTO_get_ex_new_index(
            CRYPTO_EX_INDEX_UI_METHOD,
            0,
            ptr::null_mut(),
            Some(new_method_data),
            Some(dup_method_data),
            Some(free_method_data),
        )
    };
    if i < 0 {
        return None;
    }
    let _ = INDEX.set(i);
    Some(i)
}

/// `ui_open`, `ui_write`, and `ui_close` of the wrapper: nothing to do.
unsafe extern "C" fn wrapper_session(_ui: *mut UI) -> c_int {
    1
}

unsafe extern "C" fn wrapper_write(_ui: *mut UI, _uis: *mut UI_STRING) -> c_int {
    1
}

/// `ui_read`: a prompt's answer from the wrapped callback (at most `PEM_BUFSIZE`), with the
/// UI's user data; other strings are left alone.
unsafe extern "C" fn wrapper_read(ui: *mut UI, uis: *mut UI_STRING) -> c_int {
    // SAFETY: the method's caller's string.
    if unsafe { UI_get_string_type(uis) } != UIT_PROMPT {
        return 1;
    }
    let Some(idx) = method_data_index() else {
        return 0;
    };
    // SAFETY: the UI's method (the wrapper).
    let meth = unsafe { UI_get_method(ui) };
    // SAFETY: as above.
    let data: *const PemCbData = unsafe { UI_method_get_ex_data(meth, idx) }.cast();
    // SAFETY: the wrapper's data, set when it was made.
    let Some(data) = (unsafe { data.as_ref() }) else {
        return 0;
    };
    let (cb, rwflag) = (data.cb, data.rwflag);
    let mut result = rustyssl_crypto::bn::Zeroizing::new([0 as c_char; PEM_BUFSIZE as usize + 1]);
    // SAFETY: the caller's string.
    let maxsize = unsafe { UI_get_result_maxsize(uis) }.min(PEM_BUFSIZE);
    // SAFETY: the UI's user data.
    let user = unsafe { UI_get0_user_data(ui) };
    // SAFETY: the application's callback, with room for `maxsize` octets.
    let len = unsafe { cb(result.as_mut_ptr(), maxsize, rwflag, user) };
    if len > maxsize {
        return -1;
    }
    if len < 0 {
        return len;
    }
    if let Some(end) = result.get_mut(usize::try_from(len).unwrap_or(0)) {
        *end = 0;
    }
    // SAFETY: the caller's UI and string; the answer's `len` octets.
    if unsafe { UI_set_result_ex(ui, uis, result.as_ptr(), len) } >= 0 {
        return 1;
    }
    0
}

ffi_export! {
    /// A new method asking the `pem_password_cb` `cb` (`PEM_def_callback` for NULL) for each
    /// prompt, with `rwflag`; the caller destroys it. NULL on failure.
    ///
    /// # Safety
    /// `cb` is NULL or a callback taking the user data of the UIs the method is used with.
    pub unsafe extern "C" fn UI_UTIL_wrap_read_pem_callback(cb: pem_password_cb, rwflag: c_int) -> *mut UI_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_UI
    {
        let data: *mut PemCbData = mem::zalloc(size_of::<PemCbData>(), ptr::null(), 0).cast();
        // SAFETY: a static name.
        let m = if data.is_null() { ptr::null_mut() } else { unsafe { UI_create_method(c"PEM password callback wrapper".as_ptr()) } };
        let fail = |m: *mut UI_METHOD| {
            // SAFETY: made here, or NULL.
            unsafe { UI_destroy_method(m) };
            // SAFETY: as above.
            unsafe { mem::release(data.cast()) };
            ptr::null_mut()
        };
        if m.is_null() {
            return fail(m);
        }
        // SAFETY: the new method; the wrapper's functions.
        let set = unsafe { UI_method_set_opener(m, Some(wrapper_session)) } >= 0
            // SAFETY: as above.
            && unsafe { UI_method_set_reader(m, Some(wrapper_read)) } >= 0
            // SAFETY: as above.
            && unsafe { UI_method_set_writer(m, Some(wrapper_write)) } >= 0
            // SAFETY: as above.
            && unsafe { UI_method_set_closer(m, Some(wrapper_session)) } >= 0;
        let index = method_data_index();
        // SAFETY: the new method takes the data.
        let Some(idx) = index.filter(|_| set) else { return fail(m) };
        // SAFETY: as above.
        if unsafe { UI_method_set_ex_data(m, idx, data.cast()) } == 0 {
            return fail(m);
        }
        let cb = cb.unwrap_or(crate::pem_cipher::PEM_def_callback);
        // SAFETY: the data made above, now the method's.
        unsafe { data.write(PemCbData { cb, rwflag }) };
        m
    }
}

/// `evp_key.c`'s `prompt_string`: the default prompt of `EVP_read_pw_string` (empty for none).
static PROMPT: Mutex<[c_char; 80]> = Mutex::new([0; 80]);

ffi_export! {
    /// Sets the default password prompt (its first 79 characters; NULL clears it).
    ///
    /// # Safety
    /// `prompt` is NULL or a C string.
    pub unsafe extern "C" fn EVP_set_pw_prompt(prompt: *const c_char)
    where failure = (), library = ERR_LIB_UI
    {
        let mut p = PROMPT.lock().unwrap_or_else(PoisonError::into_inner);
        *p = [0; 80];
        if !prompt.is_null() {
            // SAFETY: the caller's guarantee.
            let s = unsafe { CStr::from_ptr(prompt) }.to_bytes();
            for (d, &c) in p.iter_mut().zip(s.iter().take(79)) {
                *d = c_char::from_ne_bytes([c]);
            }
        }
    }
}

ffi_export! {
    /// The default password prompt, or NULL for none. (OpenSSL's points into a static buffer;
    /// so does this one.)
    ///
    /// # Safety
    /// No preconditions; the prompt changes with `EVP_set_pw_prompt`.
    pub unsafe extern "C" fn EVP_get_pw_prompt() -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_UI
    {
        let p = PROMPT.lock().unwrap_or_else(PoisonError::into_inner);
        if p.first().is_none_or(|&c| c == 0) {
            return ptr::null_mut();
        }
        // The buffer is static: its address outlives the guard.
        p.as_ptr().cast_mut()
    }
}

ffi_export! {
    /// `EVP_read_pw_string_min` with no minimum.
    ///
    /// # Safety
    /// As for `EVP_read_pw_string_min`.
    pub unsafe extern "C" fn EVP_read_pw_string(buf: *mut c_char, len: c_int, prompt: *const c_char, verify: c_int) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_read_pw_string_min(buf, 0, len, prompt, verify) }
    }
}

ffi_export! {
    /// Reads a password of `min` to `len` characters (at most `BUFSIZ - 1`) into `buf` with the
    /// default UI and `prompt` (the default prompt for NULL), asking twice when `verify`:
    /// `UI_process`'s result (0 on success), or -1.
    ///
    /// # Safety
    /// `buf` has room for `len + 1` octets (and `BUFSIZ`, past `BUFSIZ - 1`); `prompt` is NULL or
    /// a C string.
    pub unsafe extern "C" fn EVP_read_pw_string_min(buf: *mut c_char, min: c_int, len: c_int, prompt: *const c_char, verify: c_int) -> c_int
    where failure = -1, library = ERR_LIB_UI
    {
        let mut prompt = prompt;
        if prompt.is_null() {
            // SAFETY: no preconditions.
            prompt = unsafe { EVP_get_pw_prompt() };
        }
        // SAFETY: no preconditions.
        let ui = unsafe { UI_new() };
        if ui.is_null() {
            return -1;
        }
        let mut buff = rustyssl_crypto::bn::Zeroizing::new([0 as c_char; BUFSIZ]);
        let max = if len >= c_int::try_from(BUFSIZ).unwrap_or(c_int::MAX) { c_int::try_from(BUFSIZ - 1).unwrap_or(0) } else { len };
        // SAFETY: the new UI; the caller's prompt and buffer.
        let added = unsafe { UI_add_input_string(ui, prompt, 0, buf, min, max) } >= 0
            // SAFETY: as above, with the local buffer.
            && (verify == 0 || unsafe { UI_add_verify_string(ui, prompt, 0, buff.as_mut_ptr(), min, max, buf) } >= 0);
        let ret = if added {
            // SAFETY: as above.
            unsafe { UI_process(ui) }
        } else {
            -1
        };
        // SAFETY: made above.
        unsafe { UI_free(ui) };
        ret
    }
}
