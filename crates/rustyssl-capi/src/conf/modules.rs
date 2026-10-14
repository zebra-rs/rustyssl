//! Configuration modules (`CONF_modules_load_file(3)`; `conf_mod.c`): the modules known by
//! name (the built-in ones and `CONF_module_add`'s), the instances a configuration
//! initialized, and loading: the configuration's `openssl_conf` (or an application's)
//! section names a module and a value for each line, and each module's `init` runs with them.
//!
//! The lists are behind a lock that's never held while a module's `init` or `finish` runs:
//! those may call any function, this module's too.
//!
//! A module that isn't known is, in OpenSSL, loaded from a shared library of its name (or the
//! `path` in its section) and run. rustyssl doesn't run code from shared libraries named in a
//! configuration: the load fails as OpenSSL's does when the library isn't there
//! (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_long, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU64, Ordering};
use std::ffi::CString;
use std::sync::{Mutex, MutexGuard, Once, PoisonError};

use rustyssl_abi::{
    CONF, CONF_IMODULE, CONF_MFLAGS_DEFAULT_SECTION, CONF_MFLAGS_IGNORE_ERRORS,
    CONF_MFLAGS_IGNORE_MISSING_FILE, CONF_MFLAGS_IGNORE_RETURN_CODES, CONF_MFLAGS_NO_DSO,
    CONF_MFLAGS_SILENT, CONF_MODULE, CONF_R_ERROR_LOADING_DSO, CONF_R_MODULE_INITIALIZATION_ERROR,
    CONF_R_NO_SUCH_FILE, CONF_R_OPENSSL_CONF_REFERENCES_MISSING_SECTION,
    CONF_R_UNKNOWN_MODULE_NAME, CONF_VALUE, DSO_R_LOAD_FAILED, ERR_LIB_CONF, ERR_LIB_DSO,
    ERR_REASON_MASK, OSSL_LIB_CTX,
};

use super::{
    CONF_get1_default_config_file, NCONF_free, NCONF_get_number_e, NCONF_get_section,
    NCONF_get_string, NCONF_load, NCONF_new_ex, bytes, get_string,
};
use crate::err;
use crate::ffi::ffi_export;
use crate::libctx::{OSSL_LIB_CTX_get_conf_diagnostics, OSSL_LIB_CTX_set_conf_diagnostics};
use crate::mem;
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_value};

/// A module's `init`.
pub(crate) type InitFn = unsafe extern "C" fn(*mut CONF_IMODULE, *const CONF) -> c_int;
/// A module's `finish`.
pub(crate) type FinishFn = unsafe extern "C" fn(*mut CONF_IMODULE);

/// A module (`CONF_MODULE`).
struct Module {
    name: CString,
    init: Option<InitFn>,
    finish: Option<FinishFn>,
    /// How many of its instances are initialized.
    links: AtomicI32,
    usr_data: AtomicPtr<c_void>,
}

/// An initialized instance of a module (`CONF_IMODULE`): the name and value it was run with.
struct Instance {
    module: *mut Module,
    name: CString,
    value: CString,
    flags: AtomicU64,
    usr_data: AtomicPtr<c_void>,
}

/// A pointer the lists own.
struct Owned<T>(*mut T);

// SAFETY: the modules and instances are shared as OpenSSL shares them; their mutable fields
// are atomics.
unsafe impl<T> Send for Owned<T> {}

#[derive(Default)]
struct Lists {
    /// The known modules, in the order they were added.
    supported: Vec<Owned<Module>>,
    /// The initialized instances, in order.
    initialized: Vec<Owned<Instance>>,
}

static LISTS: Mutex<Lists> = Mutex::new(Lists {
    supported: Vec::new(),
    initialized: Vec::new(),
});

/// `ossl_config_modules_free` ran (OpenSSL frees the lists' lock): finishing and unloading
/// do nothing after it.
static FREED: AtomicBool = AtomicBool::new(false);

/// The built-in modules are added once, at the first module run.
static BUILTINS: Once = Once::new();

fn lists() -> MutexGuard<'static, Lists> {
    LISTS.lock().unwrap_or_else(PoisonError::into_inner)
}

fn flag(f: c_int) -> c_ulong {
    c_ulong::from(f.cast_unsigned())
}

/// `module_add`: a new module, known from now on.
fn module_add(name: &CStr, init: Option<InitFn>, finish: Option<FinishFn>) -> *mut Module {
    let m = Box::into_raw(Box::new(Module {
        name: name.to_owned(),
        init,
        finish,
        links: AtomicI32::new(0),
        usr_data: AtomicPtr::new(ptr::null_mut()),
    }));
    lists().supported.push(Owned(m));
    m
}

/// `module_find`: the first module whose name begins with `name` up to its last `.` (so
/// `name.suffix` finds `name`, and, as in OpenSSL, a shorter name finds a longer module).
fn module_find(name: &CStr) -> Option<*mut Module> {
    let name = name.to_bytes();
    let n = name.iter().rposition(|&c| c == b'.').unwrap_or(name.len());
    let prefix = name.get(..n).unwrap_or_default();
    lists()
        .supported
        .iter()
        // SAFETY: the list's modules are live while listed.
        .find(|m| unsafe { &*m.0 }.name.to_bytes().starts_with(prefix))
        .map(|m| m.0)
}

/// `dlfcn_name_converter`: the library a module name stands for.
fn library_name(path: &[u8]) -> Vec<u8> {
    if path.contains(&b'/') {
        return path.to_vec();
    }
    let mut file = b"lib".to_vec();
    file.extend_from_slice(path);
    #[cfg(target_os = "macos")]
    file.extend_from_slice(b".dylib");
    #[cfg(not(target_os = "macos"))]
    file.extend_from_slice(b".so");
    file
}

/// `module_load_dso`: OpenSSL loads the module from a shared library; rustyssl doesn't, and
/// fails as OpenSSL does when there's no library: the DSO errors, then
/// `CONF_R_ERROR_LOADING_DSO`.
///
/// # Safety
/// `cnf` is a live configuration; `value` a C string.
unsafe fn module_load_dso(cnf: *const CONF, name: &CStr, value: &CStr) {
    // SAFETY: the caller's configuration and strings.
    let path = unsafe { get_string(cnf, value.as_ptr(), c"path".as_ptr()) };
    // SAFETY: a value of the configuration, or the name.
    let path = unsafe { bytes(path) }.unwrap_or(name.to_bytes()).to_vec();
    let mut data = b"filename(".to_vec();
    data.extend_from_slice(&library_name(&path));
    data.extend_from_slice(b"): rustyssl doesn't load configuration modules from libraries");
    err::raise_with_bytes(ERR_LIB_DSO, DSO_R_LOAD_FAILED, "dlfcn_load", &data);
    err::raise(ERR_LIB_DSO, DSO_R_LOAD_FAILED, "DSO_load");
    let mut data = b"module=".to_vec();
    data.extend_from_slice(name.to_bytes());
    data.extend_from_slice(b", path=");
    data.extend_from_slice(&path);
    err::raise_with_bytes(
        ERR_LIB_CONF,
        CONF_R_ERROR_LOADING_DSO,
        "module_load_dso",
        &data,
    );
}

/// `module_init`: runs the module's `init` with an instance of `name` and `value`, keeping the
/// instance if it succeeds; if it fails, runs `finish` and returns -1.
///
/// # Safety
/// `module` is a known module; `cnf` a live configuration.
unsafe fn module_init(module: *mut Module, name: &CStr, value: &CStr, cnf: *const CONF) -> c_int {
    let instance = Box::into_raw(Box::new(Instance {
        module,
        name: name.to_owned(),
        value: value.to_owned(),
        flags: AtomicU64::new(0),
        usr_data: AtomicPtr::new(ptr::null_mut()),
    }));
    // SAFETY: the caller's guarantee.
    let m = unsafe { &*module };
    let mut ret = 1;
    if let Some(init) = m.init {
        // SAFETY: the module's function with its instance and the configuration.
        ret = unsafe { init(instance.cast(), cnf) };
        if ret <= 0 {
            if let Some(finish) = m.finish {
                // SAFETY: the module's function with the instance it started.
                unsafe { finish(instance.cast()) };
            }
            // SAFETY: the instance made above, not kept.
            drop(unsafe { Box::from_raw(instance) });
            return -1;
        }
    }
    m.links.fetch_add(1, Ordering::AcqRel);
    lists().initialized.push(Owned(instance));
    ret
}

/// `module_run`: finds (or fails to load) the module `name` and initializes it with `value`.
///
/// # Safety
/// `cnf` is a live configuration.
unsafe fn module_run(cnf: *const CONF, name: &CStr, value: &CStr, flags: c_ulong) -> c_int {
    BUILTINS.call_once(super::builtin::add_all);
    let mut md = module_find(name);
    if md.is_none() && flags & flag(CONF_MFLAGS_NO_DSO) == 0 {
        // SAFETY: the caller's guarantee.
        unsafe { module_load_dso(cnf, name, value) };
    }
    let silent = flags & flag(CONF_MFLAGS_SILENT) != 0;
    let Some(md) = md.take() else {
        if !silent {
            let mut data = b"module=".to_vec();
            data.extend_from_slice(name.to_bytes());
            err::raise_with_bytes(
                ERR_LIB_CONF,
                CONF_R_UNKNOWN_MODULE_NAME,
                "module_run",
                &data,
            );
        }
        return -1;
    };
    // SAFETY: the caller's guarantee; a known module.
    let ret = unsafe { module_init(md, name, value, cnf) };
    if ret <= 0 && !silent {
        let mut data = b"module=".to_vec();
        data.extend_from_slice(name.to_bytes());
        data.extend_from_slice(b", value=");
        data.extend_from_slice(value.to_bytes());
        // OpenSSL's `retcode=%-8d`.
        data.extend_from_slice(format!(" retcode={ret:<8}").as_bytes());
        err::raise_with_bytes(
            ERR_LIB_CONF,
            CONF_R_MODULE_INITIALIZATION_ERROR,
            "module_run",
            &data,
        );
    }
    ret
}

/// `conf_diagnostics`: the configuration's `config_diagnostics`, which it also sets in its
/// library context; else the context's setting.
///
/// # Safety
/// `cnf` is a live configuration.
unsafe fn conf_diagnostics(cnf: *const CONF) -> bool {
    let mut result: c_long = 0;
    // SAFETY: no preconditions.
    unsafe { err::ERR_set_mark() };
    // SAFETY: the caller's configuration, a static name, and a local.
    let status = unsafe {
        NCONF_get_number_e(
            cnf,
            ptr::null(),
            c"config_diagnostics".as_ptr(),
            &raw mut result,
        )
    };
    // SAFETY: no preconditions.
    unsafe { err::ERR_pop_to_mark() };
    // SAFETY: the caller's configuration.
    let libctx = unsafe { (*cnf).libctx };
    if status > 0 {
        // SAFETY: the configuration's context (NULL for the default).
        unsafe { OSSL_LIB_CTX_set_conf_diagnostics(libctx, c_int::from(result > 0)) };
        return result > 0;
    }
    // SAFETY: as above.
    unsafe { OSSL_LIB_CTX_get_conf_diagnostics(libctx) != 0 }
}

ffi_export! {
    /// Runs the modules the configuration's section for `appname` names (or, without one, or
    /// with `CONF_MFLAGS_DEFAULT_SECTION` and none for `appname`, the `openssl_conf` section),
    /// each line a module and its value. Returns 1 (also with no such section); 0 if the
    /// section a name refers to is missing; else the first failing module's result, unless
    /// `CONF_MFLAGS_IGNORE_ERRORS`. `config_diagnostics` in the configuration turns off the
    /// flags that hide errors.
    ///
    /// # Safety
    /// `cnf` is NULL or a live configuration; `appname` is NULL or a C string.
    pub unsafe extern "C" fn CONF_modules_load(cnf: *const CONF, appname: *const c_char, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_CONF
    {
        if cnf.is_null() {
            return 1;
        }
        let mut flags = flags;
        // SAFETY: the caller's guarantee.
        if unsafe { conf_diagnostics(cnf) } {
            flags &= !(flag(CONF_MFLAGS_IGNORE_ERRORS)
                | flag(CONF_MFLAGS_IGNORE_RETURN_CODES)
                | flag(CONF_MFLAGS_SILENT)
                | flag(CONF_MFLAGS_IGNORE_MISSING_FILE));
        }
        // SAFETY: no preconditions.
        unsafe { err::ERR_set_mark() };
        let mut vsection: *const c_char = ptr::null();
        if !appname.is_null() {
            // SAFETY: the caller's guarantee.
            vsection = unsafe { NCONF_get_string(cnf, ptr::null(), appname) };
        }
        if appname.is_null() || (vsection.is_null() && flags & flag(CONF_MFLAGS_DEFAULT_SECTION) != 0) {
            // SAFETY: the caller's configuration, and a static name.
            vsection = unsafe { NCONF_get_string(cnf, ptr::null(), c"openssl_conf".as_ptr()) };
        }
        if vsection.is_null() {
            // SAFETY: no preconditions.
            unsafe { err::ERR_pop_to_mark() };
            return 1;
        }
        // SAFETY: the caller's configuration, and one of its strings.
        let values = unsafe { NCONF_get_section(cnf, vsection) };
        if values.is_null() {
            if flags & flag(CONF_MFLAGS_SILENT) == 0 {
                // SAFETY: no preconditions.
                unsafe { err::ERR_clear_last_mark() };
                let mut data = b"openssl_conf=".to_vec();
                // SAFETY: a string of the configuration.
                data.extend_from_slice(unsafe { bytes(vsection) }.unwrap_or_default());
                err::raise_with_bytes(ERR_LIB_CONF, CONF_R_OPENSSL_CONF_REFERENCES_MISSING_SECTION, "CONF_modules_load", &data);
            } else {
                // SAFETY: no preconditions.
                unsafe { err::ERR_pop_to_mark() };
            }
            return 0;
        }
        // SAFETY: no preconditions.
        unsafe { err::ERR_pop_to_mark() };
        let values = values.cast::<rustyssl_abi::OPENSSL_STACK>();
        let mut i = 0;
        // SAFETY: the section's stack, read again each time (the modules have the
        // configuration).
        while i < unsafe { OPENSSL_sk_num(values) } {
            // SAFETY: as above.
            let vl = unsafe { OPENSSL_sk_value(values, i) }.cast::<CONF_VALUE>();
            i += 1;
            // SAFETY: a value of the section.
            let Some(vl) = (unsafe { vl.as_ref() }) else { continue };
            // SAFETY: the value's strings, owned by the configuration.
            let (Some(name), Some(value)) = (unsafe { cstr(vl.name) }, unsafe { cstr(vl.value) }) else {
                continue;
            };
            // SAFETY: no preconditions.
            unsafe { err::ERR_set_mark() };
            // SAFETY: the caller's configuration, and copies of the strings.
            let ret = unsafe { module_run(cnf, &name, &value, flags) };
            if ret <= 0 && flags & flag(CONF_MFLAGS_IGNORE_ERRORS) == 0 {
                // SAFETY: no preconditions.
                unsafe { err::ERR_clear_last_mark() };
                return ret;
            }
            // SAFETY: no preconditions.
            unsafe { err::ERR_pop_to_mark() };
        }
        1
    }
}

/// A copy of a C string, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a C string.
unsafe fn cstr(s: *const c_char) -> Option<CString> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) }.to_owned())
}

ffi_export! {
    /// Loads the file `filename` (the default configuration file for NULL; an empty name
    /// loads nothing) into a configuration of `libctx` and runs its modules
    /// ([`CONF_modules_load`]). Returns that result; 1 for a missing file with
    /// `CONF_MFLAGS_IGNORE_MISSING_FILE`, or for anything with
    /// `CONF_MFLAGS_IGNORE_RETURN_CODES` (unless the context's diagnostics are on). The errors
    /// are dropped when it returns more than 0.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `filename` and `appname` are NULL or C
    /// strings.
    pub unsafe extern "C" fn CONF_modules_load_file_ex(libctx: *mut OSSL_LIB_CTX, filename: *const c_char, appname: *const c_char, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_CONF
    {
        // SAFETY: the caller's guarantee.
        unsafe { load_file(libctx, filename, appname, flags) }
    }
}

/// [`CONF_modules_load_file_ex`].
///
/// # Safety
/// As for [`CONF_modules_load_file_ex`].
pub(crate) unsafe fn load_file(
    libctx: *mut OSSL_LIB_CTX,
    filename: *const c_char,
    appname: *const c_char,
    flags: c_ulong,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let mut diagnostics = unsafe { OSSL_LIB_CTX_get_conf_diagnostics(libctx) } != 0;
    // SAFETY: no preconditions.
    unsafe { err::ERR_set_mark() };
    let mut ret = 0;
    let mut owned: *mut c_char = ptr::null_mut();
    let file = if filename.is_null() {
        // SAFETY: no preconditions.
        owned = unsafe { CONF_get1_default_config_file() };
        owned.cast_const()
    } else {
        filename
    };
    let mut conf = ptr::null_mut();
    'load: {
        if file.is_null() {
            break 'load;
        }
        // SAFETY: a C string.
        if unsafe { *file } == 0 {
            // An empty name loads nothing, without an error.
            ret = 1;
            break 'load;
        }
        // SAFETY: the caller's context and the default method.
        conf = unsafe { NCONF_new_ex(libctx, ptr::null_mut()) };
        if conf.is_null() {
            break 'load;
        }
        // SAFETY: the configuration, and a C string.
        if unsafe { NCONF_load(conf, file, ptr::null_mut()) } <= 0 {
            // SAFETY: no preconditions.
            let code = unsafe { err::ERR_peek_last_error() };
            let reason =
                c_int::try_from(code & c_ulong::from(ERR_REASON_MASK.cast_unsigned())).unwrap_or(0);
            if flags & flag(CONF_MFLAGS_IGNORE_MISSING_FILE) != 0 && reason == CONF_R_NO_SUCH_FILE {
                ret = 1;
            }
            break 'load;
        }
        // SAFETY: the loaded configuration, and the caller's string.
        ret = unsafe { CONF_modules_load(conf, appname, flags) };
        // The configuration may have changed the setting.
        // SAFETY: the caller's guarantee.
        diagnostics = unsafe { OSSL_LIB_CTX_get_conf_diagnostics(libctx) } != 0;
    }
    // SAFETY: the default file's name, if this made it.
    unsafe { mem::release(owned.cast()) };
    // SAFETY: the configuration, if made.
    unsafe { NCONF_free(conf) };
    if flags & flag(CONF_MFLAGS_IGNORE_RETURN_CODES) != 0 && !diagnostics {
        ret = 1;
    }
    if ret > 0 {
        // SAFETY: no preconditions.
        unsafe { err::ERR_pop_to_mark() };
    } else {
        // SAFETY: no preconditions.
        unsafe { err::ERR_clear_last_mark() };
    }
    ret
}

ffi_export! {
    /// [`CONF_modules_load_file_ex`] for the default library context.
    ///
    /// # Safety
    /// `filename` and `appname` are NULL or C strings.
    pub unsafe extern "C" fn CONF_modules_load_file(filename: *const c_char, appname: *const c_char, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_CONF
    {
        // SAFETY: the caller's guarantee.
        unsafe { load_file(ptr::null_mut(), filename, appname, flags) }
    }
}

ffi_export! {
    /// Loads the file `config_file` into `ctx` and runs its modules, with no flags. Returns 1
    /// if that succeeded, else 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context; `config_file` is NULL or a C string.
    pub unsafe extern "C" fn OSSL_LIB_CTX_load_config(ctx: *mut OSSL_LIB_CTX, config_file: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CONF
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { load_file(ctx, config_file, ptr::null(), 0) } > 0)
    }
}

/// `conf_modules_finish_int`: runs `finish` for every initialized instance, newest first, and
/// forgets them. False after `ossl_config_modules_free`.
fn finish_all() -> bool {
    if FREED.load(Ordering::Acquire) {
        return false;
    }
    let mut instances = core::mem::take(&mut lists().initialized);
    while let Some(Owned(instance)) = instances.pop() {
        // SAFETY: an instance the list owned, now ours.
        let i = unsafe { Box::from_raw(instance) };
        // SAFETY: its module is known while it has instances.
        let m = unsafe { &*i.module };
        if let Some(finish) = m.finish {
            // SAFETY: the module's function with its instance.
            unsafe { finish(instance.cast()) };
        }
        m.links.fetch_sub(1, Ordering::AcqRel);
        drop(i);
    }
    true
}

ffi_export! {
    /// Runs `finish` for every initialized module instance, newest first, and forgets them.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn CONF_modules_finish()
    where failure = (), library = ERR_LIB_CONF
    {
        finish_all();
    }
}

/// `CONF_modules_unload`.
fn unload(all: bool) {
    if !finish_all() {
        return;
    }
    let removed: Vec<Owned<Module>> = {
        let mut l = lists();
        // Modules from libraries go when unused; there are none here, so only `all` removes.
        if all {
            core::mem::take(&mut l.supported)
        } else {
            Vec::new()
        }
    };
    for Owned(m) in removed.into_iter().rev() {
        // SAFETY: a module the list owned, no longer known or in use.
        drop(unsafe { Box::from_raw(m) });
    }
}

ffi_export! {
    /// [`CONF_modules_finish`], then forgets the modules no instance uses that came from
    /// libraries (none here), or with `all` every module, the built-in ones too (which aren't
    /// added again).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn CONF_modules_unload(all: c_int)
    where failure = (), library = ERR_LIB_CONF
    {
        unload(all != 0);
    }
}

/// `ossl_config_modules_free`, at `OPENSSL_cleanup`: unloads every module.
pub(crate) fn free_all() {
    unload(true);
    FREED.store(true, Ordering::Release);
}

ffi_export! {
    /// Adds the module `name` with the functions `ifunc` and `ffunc` (either may be NULL).
    /// Returns 1, or 0 for a NULL name.
    ///
    /// # Safety
    /// `name` is NULL or a C string; the functions are NULL or of the documented types.
    pub unsafe extern "C" fn CONF_module_add(name: *const c_char, ifunc: Option<InitFn>, ffunc: Option<FinishFn>) -> c_int
    where failure = 0, library = ERR_LIB_CONF
    {
        // SAFETY: the caller's guarantee.
        let Some(name) = (unsafe { cstr(name) }) else { return 0 };
        c_int::from(!module_add(&name, ifunc, ffunc).is_null())
    }
}

/// A built-in module added by its function.
pub(crate) fn add_builtin(name: &CStr, init: InitFn, finish: Option<FinishFn>) {
    module_add(name, Some(init), finish);
}

/// The instance behind `md`.
///
/// # Safety
/// `md` is NULL or an instance given to a module's function, still initialized.
unsafe fn instance<'a>(md: *const CONF_IMODULE) -> Option<&'a Instance> {
    // SAFETY: the caller's guarantee.
    unsafe { md.cast::<Instance>().as_ref() }
}

/// The module behind `pmod`.
///
/// # Safety
/// `pmod` is NULL or a known module.
unsafe fn module<'a>(pmod: *const CONF_MODULE) -> Option<&'a Module> {
    // SAFETY: the caller's guarantee.
    unsafe { pmod.cast::<Module>().as_ref() }
}

ffi_export! {
    /// The name the instance was run with (the line's name).
    ///
    /// # Safety
    /// `md` is NULL or a live instance.
    pub unsafe extern "C" fn CONF_imodule_get_name(md: *const CONF_IMODULE) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_CONF
    {
        // SAFETY: the caller's guarantee.
        unsafe { instance(md) }.map_or(ptr::null(), |i| i.name.as_ptr())
    }
}

ffi_export! {
    /// The value the instance was run with (the line's value).
    ///
    /// # Safety
    /// `md` is NULL or a live instance.
    pub unsafe extern "C" fn CONF_imodule_get_value(md: *const CONF_IMODULE) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_CONF
    {
        // SAFETY: the caller's guarantee.
        unsafe { instance(md) }.map_or(ptr::null(), |i| i.value.as_ptr())
    }
}

ffi_export! {
    /// The instance's data.
    ///
    /// # Safety
    /// `md` is NULL or a live instance.
    pub unsafe extern "C" fn CONF_imodule_get_usr_data(md: *const CONF_IMODULE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CONF
    {
        // SAFETY: the caller's guarantee.
        unsafe { instance(md) }.map_or(ptr::null_mut(), |i| i.usr_data.load(Ordering::Acquire))
    }
}

ffi_export! {
    /// Sets the instance's data.
    ///
    /// # Safety
    /// `md` is NULL or a live instance.
    pub unsafe extern "C" fn CONF_imodule_set_usr_data(md: *mut CONF_IMODULE, usr_data: *mut c_void)
    where failure = (), library = ERR_LIB_CONF
    {
        // SAFETY: the caller's guarantee.
        if let Some(i) = unsafe { instance(md) } {
            i.usr_data.store(usr_data, Ordering::Release);
        }
    }
}

ffi_export! {
    /// The instance's module.
    ///
    /// # Safety
    /// `md` is NULL or a live instance.
    pub unsafe extern "C" fn CONF_imodule_get_module(md: *const CONF_IMODULE) -> *mut CONF_MODULE
    where failure = ptr::null_mut(), library = ERR_LIB_CONF
    {
        // SAFETY: the caller's guarantee.
        unsafe { instance(md) }.map_or(ptr::null_mut(), |i| i.module.cast())
    }
}

ffi_export! {
    /// The instance's flags.
    ///
    /// # Safety
    /// `md` is NULL or a live instance.
    pub unsafe extern "C" fn CONF_imodule_get_flags(md: *const CONF_IMODULE) -> c_ulong
    where failure = 0, library = ERR_LIB_CONF
    {
        // SAFETY: the caller's guarantee.
        unsafe { instance(md) }.map_or(0, |i| c_ulong::try_from(i.flags.load(Ordering::Acquire)).unwrap_or(0))
    }
}

ffi_export! {
    /// Sets the instance's flags.
    ///
    /// # Safety
    /// `md` is NULL or a live instance.
    pub unsafe extern "C" fn CONF_imodule_set_flags(md: *mut CONF_IMODULE, flags: c_ulong)
    where failure = (), library = ERR_LIB_CONF
    {
        // SAFETY: the caller's guarantee.
        if let Some(i) = unsafe { instance(md) } {
            i.flags.store(flags, Ordering::Release);
        }
    }
}

ffi_export! {
    /// The module's data.
    ///
    /// # Safety
    /// `pmod` is NULL or a known module.
    pub unsafe extern "C" fn CONF_module_get_usr_data(pmod: *mut CONF_MODULE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CONF
    {
        // SAFETY: the caller's guarantee.
        unsafe { module(pmod) }.map_or(ptr::null_mut(), |m| m.usr_data.load(Ordering::Acquire))
    }
}

ffi_export! {
    /// Sets the module's data.
    ///
    /// # Safety
    /// `pmod` is NULL or a known module.
    pub unsafe extern "C" fn CONF_module_set_usr_data(pmod: *mut CONF_MODULE, usr_data: *mut c_void)
    where failure = (), library = ERR_LIB_CONF
    {
        // SAFETY: the caller's guarantee.
        if let Some(m) = unsafe { module(pmod) } {
            m.usr_data.store(usr_data, Ordering::Release);
        }
    }
}
