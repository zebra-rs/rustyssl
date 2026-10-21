//! The apps' user interface method (`apps/lib/apps_ui.c`): prompts go through `UI_OpenSSL()`,
//! except that a password the program already has (`-passin pass:...`, carried as the UI's
//! user data, a [`PwCbData`]) answers a "default password" prompt without asking.

use core::ffi::{c_char, c_int, c_void};
use std::ffi::CString;
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::abi::{
    UI, UI_CTRL_IS_REDOABLE, UI_CTRL_PRINT_ERRORS, UI_INPUT_FLAG_DEFAULT_PWD, UI_METHOD, UI_STRING,
    UIT_PROMPT, UIT_VERIFY,
};
use crate::ffi;

/// `PW_MIN_LENGTH` of `apps_ui.h` (the apps' own convention, not the library's).
const PW_MIN_LENGTH: c_int = 4;

/// `PW_CB_DATA` of `apps_ui.h`: the password, if known, and what the prompt names.
#[repr(C)]
pub struct PwCbData {
    pub password: *const c_void,
    pub prompt_info: *const c_char,
}

/// A [`PwCbData`] with the strings it points to, at a stable address for the C callbacks.
pub struct Passphrase {
    data: PwCbData,
    _password: Option<CString>,
    _prompt_info: Option<CString>,
}

impl Passphrase {
    /// `password` answers a prompt without asking; `prompt_info` is what the prompt names.
    pub fn new(password: Option<&str>, prompt_info: Option<&str>) -> Box<Self> {
        let password = password.and_then(crate::cstring);
        let prompt_info = prompt_info.and_then(crate::cstring);
        Box::new(Self {
            data: PwCbData {
                password: password
                    .as_ref()
                    .map_or(core::ptr::null(), |p| p.as_ptr().cast()),
                prompt_info: prompt_info
                    .as_ref()
                    .map_or(core::ptr::null(), |p| p.as_ptr()),
            },
            _password: password,
            _prompt_info: prompt_info,
        })
    }

    /// The `PW_CB_DATA *` for the C API (valid while `self` lives).
    pub fn as_ptr(&self) -> *mut c_void {
        core::ptr::from_ref(&self.data).cast_mut().cast()
    }
}

static METHOD: AtomicPtr<UI_METHOD> = AtomicPtr::new(core::ptr::null_mut());
static BASE: AtomicPtr<UI_METHOD> = AtomicPtr::new(core::ptr::null_mut());

fn base() -> *const UI_METHOD {
    BASE.load(Ordering::Acquire)
}

/// The password a "default password" prompt of `uis` is answered with, if the UI's user data
/// has one.
///
/// # Safety
/// `ui` and `uis` are the live objects of a UI callback.
unsafe fn known_password(ui: *mut UI, uis: *mut UI_STRING) -> Option<*const c_char> {
    // SAFETY: uis is live (the caller's contract).
    let flags = unsafe { ffi::UI_get_input_flags(uis) };
    // SAFETY: ui is live.
    let data = unsafe { ffi::UI_get0_user_data(ui) }.cast::<PwCbData>();
    if flags & UI_INPUT_FLAG_DEFAULT_PWD == 0 || data.is_null() {
        return None;
    }
    // SAFETY: uis is live.
    let kind = unsafe { ffi::UI_get_string_type(uis) };
    if kind != UIT_PROMPT && kind != UIT_VERIFY {
        return None;
    }
    // SAFETY: the user data of every UI this method serves is a PwCbData (the apps only ever
    // pass one, as upstream's do).
    let password = unsafe { (*data).password };
    (!password.is_null()).then_some(password.cast())
}

unsafe extern "C" fn ui_open(ui: *mut UI) -> c_int {
    // SAFETY: base is a valid method (set before this method is used).
    match unsafe { ffi::UI_method_get_opener(base()) } {
        // SAFETY: the base method's own opener, on its UI.
        Some(f) => unsafe { f(ui) },
        None => 1,
    }
}

unsafe extern "C" fn ui_read(ui: *mut UI, uis: *mut UI_STRING) -> c_int {
    // SAFETY: called by the library with live objects.
    if let Some(password) = unsafe { known_password(ui, uis) } {
        // SAFETY: password is a NUL-terminated string the Passphrase keeps alive.
        unsafe { ffi::UI_set_result(ui, uis, password) };
        return 1;
    }
    // SAFETY: base is a valid method.
    match unsafe { ffi::UI_method_get_reader(base()) } {
        // SAFETY: the base method's own reader.
        Some(f) => unsafe { f(ui, uis) },
        None => {
            // The empty password, when there is nothing better.
            // SAFETY: live objects and a static string.
            unsafe { ffi::UI_set_result(ui, uis, c"".as_ptr()) };
            1
        }
    }
}

unsafe extern "C" fn ui_write(ui: *mut UI, uis: *mut UI_STRING) -> c_int {
    // SAFETY: called by the library with live objects.
    if unsafe { known_password(ui, uis) }.is_some() {
        return 1;
    }
    // SAFETY: base is a valid method.
    match unsafe { ffi::UI_method_get_writer(base()) } {
        // SAFETY: the base method's own writer.
        Some(f) => unsafe { f(ui, uis) },
        None => 1,
    }
}

unsafe extern "C" fn ui_close(ui: *mut UI) -> c_int {
    // SAFETY: base is a valid method.
    match unsafe { ffi::UI_method_get_closer(base()) } {
        // SAFETY: the base method's own closer.
        Some(f) => unsafe { f(ui) },
        None => 1,
    }
}

unsafe extern "C" fn ui_prompt_construct(
    ui: *mut UI,
    phrase_desc: *const c_char,
    object_name: *const c_char,
) -> *mut c_char {
    // SAFETY: ui is live.
    let data = unsafe { ffi::UI_get0_user_data(ui) }.cast::<PwCbData>();
    let desc = if phrase_desc.is_null() {
        c"pass phrase".as_ptr()
    } else {
        phrase_desc
    };
    let name = if object_name.is_null() && !data.is_null() {
        // SAFETY: as in known_password, the user data is a PwCbData.
        unsafe { (*data).prompt_info }
    } else {
        object_name
    };
    // SAFETY: NULL ui is allowed; the strings are NUL-terminated or NULL.
    unsafe { ffi::UI_construct_prompt(core::ptr::null_mut(), desc, name) }
}

/// `setup_ui_method`.
pub fn setup() -> bool {
    // SAFETY: no arguments; the console method is static.
    let base = unsafe { ffi::UI_OpenSSL() };
    BASE.store(base, Ordering::Release);
    // SAFETY: a static name.
    let m = unsafe { ffi::UI_create_method(c"OpenSSL application user interface".as_ptr()) };
    if m.is_null() {
        return false;
    }
    METHOD.store(m, Ordering::Release);
    // SAFETY: m is a fresh method; each callback has the type the setter takes.
    let ok = unsafe { ffi::UI_method_set_opener(m, Some(ui_open)) } == 0;
    // SAFETY: as above.
    let ok = ok && unsafe { ffi::UI_method_set_reader(m, Some(ui_read)) } == 0;
    // SAFETY: as above.
    let ok = ok && unsafe { ffi::UI_method_set_writer(m, Some(ui_write)) } == 0;
    // SAFETY: as above.
    let ok = ok && unsafe { ffi::UI_method_set_closer(m, Some(ui_close)) } == 0;
    // SAFETY: as above.
    ok && unsafe { ffi::UI_method_set_prompt_constructor(m, Some(ui_prompt_construct)) } == 0
}

/// `set_base_ui_method(UI_null())`: prompts get no input (`-batch`).
pub fn set_base_null() {
    // SAFETY: no arguments; the method is static.
    let base = unsafe { ffi::UI_null() };
    BASE.store(base.cast_mut(), Ordering::Release);
}

/// `destroy_ui_method`.
pub fn destroy() {
    let m = METHOD.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !m.is_null() {
        // SAFETY: m came from UI_create_method and is destroyed once.
        unsafe { ffi::UI_destroy_method(m) };
    }
}

/// `get_ui_method`.
pub fn method() -> *const UI_METHOD {
    METHOD.load(Ordering::Acquire)
}

/// `password_callback` of `apps_ui.c`, as a `pem_password_cb`: `userdata` is NULL or a
/// [`PwCbData`].
///
/// # Safety
/// `buf` is writable for `bufsiz` bytes; `userdata` is NULL or a live `PwCbData`.
pub unsafe extern "C" fn password_callback(
    buf: *mut c_char,
    bufsiz: c_int,
    verify: c_int,
    userdata: *mut c_void,
) -> c_int {
    let Ok(size) = usize::try_from(bufsiz) else {
        return 0;
    };
    if size == 0 {
        return 0;
    }
    // SAFETY: the method is NULL (UI_new_method then uses the default) or ours.
    let ui = unsafe { ffi::UI_new_method(method()) };
    if ui.is_null() {
        return 0;
    }
    let data = userdata.cast::<PwCbData>();
    let prompt_info = if data.is_null() {
        core::ptr::null()
    } else {
        // SAFETY: userdata is a live PwCbData (the caller's contract).
        unsafe { (*data).prompt_info }
    };
    // SAFETY: ui is live; the strings are static or NULL.
    let prompt = unsafe { ffi::UI_construct_prompt(ui, c"pass phrase".as_ptr(), prompt_info) };
    if prompt.is_null() {
        let _ = std::io::Write::write_all(&mut std::io::stderr(), b"Out of memory\n");
        // SAFETY: ui is live and freed once.
        unsafe { ffi::UI_free(ui) };
        return 0;
    }
    // SAFETY: ui is live; the command takes no pointer.
    unsafe { ffi::UI_ctrl(ui, UI_CTRL_PRINT_ERRORS, 1, core::ptr::null_mut(), None) };
    // SAFETY: there is no previous user data; userdata outlives the UI.
    unsafe { ffi::UI_add_user_data(ui, userdata) };
    let flags = UI_INPUT_FLAG_DEFAULT_PWD;
    let max = bufsiz - 1;
    // SAFETY: buf is writable for bufsiz bytes, and the result is at most bufsiz - 1 long.
    let mut ok = unsafe { ffi::UI_add_input_string(ui, prompt, flags, buf, PW_MIN_LENGTH, max) };
    let mut verify_buf = vec![0u8; size];
    if ok >= 0 && verify != 0 {
        // SAFETY: verify_buf is writable for bufsiz bytes and lives until UI_free.
        ok = unsafe {
            ffi::UI_add_verify_string(
                ui,
                prompt,
                flags,
                verify_buf.as_mut_ptr().cast(),
                PW_MIN_LENGTH,
                max,
                buf,
            )
        };
    }
    if ok >= 0 {
        loop {
            // SAFETY: ui is live.
            ok = unsafe { ffi::UI_process(ui) };
            // SAFETY: ui is live; the command takes no pointer.
            let redo =
                unsafe { ffi::UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, core::ptr::null_mut(), None) };
            if ok >= 0 || redo == 0 {
                break;
            }
        }
    }
    // OPENSSL_clear_free of the verify buffer.
    // SAFETY: verify_buf is a valid buffer of its length.
    unsafe { ffi::OPENSSL_cleanse(verify_buf.as_mut_ptr().cast(), verify_buf.len()) };
    let mut res = 0;
    if ok >= 0 {
        // SAFETY: on success buf holds a NUL-terminated string within bufsiz bytes.
        let len = unsafe { core::ffi::CStr::from_ptr(buf) }.to_bytes().len();
        res = c_int::try_from(len).unwrap_or(0);
    }
    if ok == -1 || ok == -2 {
        let text: &[u8] = if ok == -1 {
            b"User interface error\n"
        } else {
            b"aborted!\n"
        };
        let _ = std::io::Write::write_all(&mut std::io::stderr(), text);
        if ok == -1 {
            crate::err::print_errors_fd2();
        }
        // SAFETY: buf is writable for bufsiz bytes.
        unsafe { ffi::OPENSSL_cleanse(buf.cast(), size) };
        res = 0;
    }
    // SAFETY: ui is live and freed once; prompt was allocated by the library.
    unsafe { ffi::UI_free(ui) };
    crate::util::openssl_free(prompt.cast());
    res
}

/// `EVP_read_pw_string(buf, len, prompt, verify)`: what it returns (0 on success), and the
/// password read (zeroed buffer copied out; at most `len - 1` bytes).
pub fn read_pw_string(len: usize, prompt: &str, verify: bool) -> (c_int, Vec<u8>) {
    let Some(p) = crate::cstring(prompt) else {
        return (-1, Vec::new());
    };
    let mut buf = vec![0u8; len.max(1) + 1];
    let n = c_int::try_from(len).unwrap_or(c_int::MAX);
    // SAFETY: buf has room for len bytes plus a NUL; p is a valid C string.
    let r = unsafe {
        ffi::EVP_read_pw_string(buf.as_mut_ptr().cast(), n, p.as_ptr(), c_int::from(verify))
    };
    let end = buf.iter().position(|&b| b == 0).unwrap_or(0);
    let pw = buf.get(..end).unwrap_or_default().to_vec();
    buf.fill(0);
    (r, pw)
}
