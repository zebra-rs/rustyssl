//! Library initialization and teardown (`OPENSSL_init_crypto(3)`), and the small process-level
//! helpers beside them in `crypto.h`.
//!
//! As in OpenSSL's `crypto/init.c`:
//! - `OPENSSL_init_crypto(0, NULL)` does nothing. Any other call sets up the base once and, unless
//!   `OPENSSL_INIT_NO_ATEXIT` came first, registers `OPENSSL_cleanup` with `atexit`.
//! - Each subsystem a flag asks for is set up at most once, and between a flag and its `NO_`
//!   twin the first one asked for wins.
//! - `OPENSSL_cleanup` runs the `OPENSSL_atexit` handlers, newest first, once; after it, every
//!   `OPENSSL_init_crypto` fails.
//!
//! Flags whose subsystem rustyssl doesn't have yet abort, as an unimplemented export does
//! (security rule 10): `OPENSSL_INIT_ADD_ALL_CIPHERS`/`_DIGESTS` (Phase 3), `OPENSSL_INIT_ASYNC`,
//! and the `OPENSSL_INIT_ENGINE_*` flags. `OPENSSL_INIT_LOAD_CONFIG` succeeds when there is no
//! file to load, as OpenSSL's does by default, and aborts if there is one (configuration comes
//! in Phase 6).

use core::ffi::{CStr, c_char, c_int, c_long, c_ulong, c_void};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::sync::{Mutex, OnceLock};

use rustyssl_abi::{
    CONF_MFLAGS_DEFAULT_SECTION, CONF_MFLAGS_IGNORE_MISSING_FILE, CONF_MFLAGS_IGNORE_RETURN_CODES,
    CONF_R_NO_SUCH_FILE, ERR_LIB_CONF, ERR_LIB_CRYPTO, ERR_R_INIT_FAIL,
    OPENSSL_INIT_ADD_ALL_CIPHERS, OPENSSL_INIT_ADD_ALL_DIGESTS, OPENSSL_INIT_ASYNC,
    OPENSSL_INIT_ENGINE_AFALG, OPENSSL_INIT_ENGINE_ALL_BUILTIN, OPENSSL_INIT_ENGINE_CAPI,
    OPENSSL_INIT_ENGINE_CRYPTODEV, OPENSSL_INIT_ENGINE_DYNAMIC, OPENSSL_INIT_ENGINE_OPENSSL,
    OPENSSL_INIT_ENGINE_PADLOCK, OPENSSL_INIT_ENGINE_RDRAND, OPENSSL_INIT_LOAD_CONFIG,
    OPENSSL_INIT_LOAD_CRYPTO_STRINGS, OPENSSL_INIT_LOAD_SSL_STRINGS,
    OPENSSL_INIT_NO_ADD_ALL_CIPHERS, OPENSSL_INIT_NO_ADD_ALL_DIGESTS, OPENSSL_INIT_NO_ATEXIT,
    OPENSSL_INIT_NO_LOAD_CONFIG, OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS,
    OPENSSL_INIT_NO_LOAD_SSL_STRINGS, OPENSSL_INIT_SETTINGS,
};

use crate::err;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::{mem, stub, version};

/// The flags `OPENSSL_init_crypto` takes, as `u64`.
fn flag(value: c_long) -> u64 {
    value.cast_unsigned()
}

/// Every `OPENSSL_INIT_ENGINE_*` flag.
fn engine_flags() -> u64 {
    [
        OPENSSL_INIT_ENGINE_RDRAND,
        OPENSSL_INIT_ENGINE_DYNAMIC,
        OPENSSL_INIT_ENGINE_OPENSSL,
        OPENSSL_INIT_ENGINE_CRYPTODEV,
        OPENSSL_INIT_ENGINE_CAPI,
        OPENSSL_INIT_ENGINE_PADLOCK,
        OPENSSL_INIT_ENGINE_AFALG,
        OPENSSL_INIT_ENGINE_ALL_BUILTIN,
    ]
    .into_iter()
    .fold(0, |all, f| all | flag(f))
}

/// `OPENSSL_cleanup` has run.
static STOPPED: AtomicBool = AtomicBool::new(false);
/// The base is set up (OpenSSL's `base_inited`); `OPENSSL_cleanup` does nothing without it.
static BASE: AtomicBool = AtomicBool::new(false);
/// The flags already handled (OpenSSL's `optsdone`).
static DONE: AtomicU64 = AtomicU64::new(0);

/// Each subsystem's one-time setup and its outcome. Between a flag and its `NO_` twin, the
/// first one asked for decides.
static ATEXIT: OnceLock<bool> = OnceLock::new();
static PINNED: OnceLock<()> = OnceLock::new();
static CRYPTO_STRINGS: OnceLock<bool> = OnceLock::new();
static SSL_STRINGS: OnceLock<bool> = OnceLock::new();
static CIPHERS: OnceLock<bool> = OnceLock::new();
static DIGESTS: OnceLock<bool> = OnceLock::new();
static CONFIG: OnceLock<c_int> = OnceLock::new();

/// The `OPENSSL_atexit` handlers, oldest first.
static HANDLERS: Mutex<Vec<unsafe extern "C" fn()>> = Mutex::new(Vec::new());

/// Aborts for a flag whose subsystem doesn't exist yet.
fn unavailable(flag: &str) -> ! {
    stub::unimplemented(&format!("OPENSSL_init_crypto with {flag}"))
}

/// Keeps the library that contains `address` loaded for good, as OpenSSL does before
/// registering exit handlers: if it were unloaded, the process would jump into unmapped
/// memory at exit. Miri can't run `dladdr`, and its tests unload nothing.
fn pin(address: *const c_void) {
    if cfg!(miri) {
        return;
    }
    let mut info = core::mem::MaybeUninit::<libc::Dl_info>::zeroed();
    // SAFETY: dladdr only reads `address` as a number and fills `info`.
    if unsafe { libc::dladdr(address, info.as_mut_ptr()) } == 0 {
        return;
    }
    // SAFETY: dladdr succeeded, so it initialized `info`.
    let file = unsafe { info.assume_init() }.dli_fname;
    if file.is_null() {
        return;
    }
    // RTLD_NOLOAD only takes another reference to the library that's already loaded, and
    // RTLD_NODELETE keeps it loaded. The handle is never closed.
    // SAFETY: `file` is the NUL-terminated path dladdr returned.
    unsafe {
        libc::dlopen(
            file,
            libc::RTLD_NOW | libc::RTLD_NOLOAD | libc::RTLD_NODELETE,
        )
    };
}

extern "C" fn cleanup_at_exit() {
    // SAFETY: no preconditions.
    unsafe { OPENSSL_cleanup() }
}

thread_local! {
    /// Set at this thread's first `OPENSSL_INIT_LOAD_CONFIG` and never cleared, as OpenSSL's
    /// `in_init_config_local` is (it marks a load in progress, against recursion). So a later
    /// `OPENSSL_INIT_LOAD_CONFIG` on the same thread is skipped and succeeds, even after a
    /// failed load, while other threads get the failure. Reproduced for compatibility.
    static LOADED_CONFIG: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// What `OPENSSL_init_crypto(OPENSSL_INIT_BASE_ONLY, NULL)` does inside OpenSSL, which the
/// error queue and string functions start with: sets up the base, so that `OPENSSL_cleanup`
/// has work to do. False after `OPENSSL_cleanup`. OpenSSL allocates its locks here, so this
/// also ends `CRYPTO_set_mem_functions`.
pub(crate) fn base() -> bool {
    if STOPPED.load(Ordering::Acquire) {
        return false;
    }
    if !BASE.load(Ordering::Acquire) {
        mem::close_customization();
        BASE.store(true, Ordering::Release);
    }
    true
}

/// Loads libcrypto's error strings when a thread first records an error, as OpenSSL does,
/// unless `OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS` came first. A failure is ignored.
pub(crate) fn load_crypto_strings_at_first_error() {
    // SAFETY: no settings.
    unsafe { OPENSSL_init_crypto(flag(OPENSSL_INIT_LOAD_CRYPTO_STRINGS), core::ptr::null()) };
}

/// `OPENSSL_init_crypto`'s work for the flags in `opts`. Returns the flags to record as done,
/// or `None` if a subsystem failed.
fn init(opts: u64, settings: *const OPENSSL_INIT_SETTINGS) -> Option<u64> {
    let mut done = opts;
    base();

    let no_atexit = opts & flag(OPENSSL_INIT_NO_ATEXIT) != 0;
    ATEXIT.get_or_init(|| {
        // Miri can't run atexit; its tests need no cleanup at exit.
        if no_atexit || cfg!(miri) {
            return false;
        }
        pin(cleanup_at_exit as *const c_void);
        // SAFETY: `cleanup_at_exit` is a plain function, and pinning keeps it mapped.
        unsafe { libc::atexit(cleanup_at_exit) == 0 }
    });
    PINNED.get_or_init(|| pin(OPENSSL_init_crypto as *const c_void));

    let pairs: [(&OnceLock<bool>, c_long, c_long); 4] = [
        (
            &CRYPTO_STRINGS,
            OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS,
            OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
        ),
        (
            &SSL_STRINGS,
            OPENSSL_INIT_NO_LOAD_SSL_STRINGS,
            OPENSSL_INIT_LOAD_SSL_STRINGS,
        ),
        (
            &CIPHERS,
            OPENSSL_INIT_NO_ADD_ALL_CIPHERS,
            OPENSSL_INIT_ADD_ALL_CIPHERS,
        ),
        (
            &DIGESTS,
            OPENSSL_INIT_NO_ADD_ALL_DIGESTS,
            OPENSSL_INIT_ADD_ALL_DIGESTS,
        ),
    ];
    for (cell, without, with) in pairs {
        if opts & flag(without) != 0 {
            cell.get_or_init(|| false);
        }
        if opts & flag(with) != 0 {
            cell.get_or_init(|| {
                if with == OPENSSL_INIT_LOAD_CRYPTO_STRINGS {
                    return err::load_crypto_strings();
                }
                if with == OPENSSL_INIT_LOAD_SSL_STRINGS {
                    err::load_ssl_strings();
                    return true;
                }
                if with == OPENSSL_INIT_ADD_ALL_CIPHERS {
                    unavailable("OPENSSL_INIT_ADD_ALL_CIPHERS");
                }
                unavailable("OPENSSL_INIT_ADD_ALL_DIGESTS");
            });
        }
    }
    // OPENSSL_INIT_ATFORK needs nothing: OpenSSL 3's fork handlers do nothing.

    // As with OpenSSL's RUN_ONCE_ALT, either flag returns what the first configuration
    // decision did: after a failed load, even OPENSSL_INIT_NO_LOAD_CONFIG fails.
    if opts & flag(OPENSSL_INIT_NO_LOAD_CONFIG) != 0 && *CONFIG.get_or_init(|| 1) <= 0 {
        return None;
    }
    if opts & flag(OPENSSL_INIT_LOAD_CONFIG) != 0 {
        if LOADED_CONFIG.with(|loaded| loaded.replace(true)) {
            done &= !flag(OPENSSL_INIT_LOAD_CONFIG);
        } else if *CONFIG.get_or_init(|| load_config(settings)) <= 0 {
            return None;
        }
    }
    if opts & flag(OPENSSL_INIT_ASYNC) != 0 {
        unavailable("OPENSSL_INIT_ASYNC");
    }
    if opts & engine_flags() != 0 {
        unavailable("OPENSSL_INIT_ENGINE_*");
    }
    Some(done)
}

/// Loads the configuration file, as OpenSSL's `CONF_modules_load_file_ex` does, as far as
/// rustyssl can yet: the file is the one named in `settings`, else `$OPENSSL_CONF` (ignored in
/// set-user-ID programs), else `<OPENSSLDIR>/openssl.cnf`. A missing file loads nothing, with
/// the result OpenSSL gives for the settings' flags; an existing one aborts until configuration
/// files are implemented (Phase 6).
fn load_config(settings: *const OPENSSL_INIT_SETTINGS) -> c_int {
    // SAFETY: the caller passes null or a live handle from OPENSSL_INIT_new.
    let settings = unsafe { OPENSSL_INIT_SETTINGS::get(settings) };
    let flags = settings.map_or_else(default_flags, |s| s.flags.load(Ordering::Relaxed));
    let file = settings.and_then(|s| s.filename.lock().ok().and_then(|f| f.clone()));
    let file = file.or_else(|| {
        // SAFETY: getenv with a NUL-terminated name returns null or a C string we copy at once.
        let set = (issetugid() == 0)
            .then(|| unsafe { libc::getenv(c"OPENSSL_CONF".as_ptr()) })
            .filter(|value| !value.is_null())
            // SAFETY: as above.
            .map(|value| unsafe { CStr::from_ptr(value) }.to_owned());
        set.or_else(|| {
            let dir = version::config_dir().to_bytes();
            let mut path = dir.to_vec();
            path.extend_from_slice(b"/openssl.cnf");
            CString::new(path).ok()
        })
    });
    let Some(file) = file else {
        return 0;
    };
    if file.as_bytes().is_empty() {
        return 1;
    }
    match std::fs::File::open(OsStr::from_bytes(file.as_bytes())) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if flags & CONF_MFLAGS_IGNORE_MISSING_FILE.cast_unsigned() as c_ulong != 0
                || flags & CONF_MFLAGS_IGNORE_RETURN_CODES.cast_unsigned() as c_ulong != 0
            {
                1
            } else {
                err::raise(ERR_LIB_CONF, CONF_R_NO_SUCH_FILE, "OPENSSL_init_crypto");
                0
            }
        }
        _ => stub::unimplemented("OPENSSL_init_crypto loading a configuration file"),
    }
}

/// `DEFAULT_CONF_MFLAGS` from OpenSSL's `include/internal/conf.h`.
fn default_flags() -> c_ulong {
    let flags = CONF_MFLAGS_DEFAULT_SECTION
        | CONF_MFLAGS_IGNORE_MISSING_FILE
        | CONF_MFLAGS_IGNORE_RETURN_CODES;
    c_ulong::from(flags.cast_unsigned())
}

/// `OPENSSL_issetugid`: whether the process runs with privileges it didn't start with, so the
/// environment can't be trusted. glibc's `AT_SECURE` on glibc; elsewhere, OpenSSL compares the
/// real and effective IDs.
fn issetugid() -> c_int {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: getauxval has no preconditions.
    let set = unsafe { libc::getauxval(libc::AT_SECURE) } != 0;
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    let set = {
        // SAFETY: these getters have no preconditions.
        let (uid, euid) = (unsafe { libc::getuid() }, unsafe { libc::geteuid() });
        // SAFETY: as above.
        let (gid, egid) = (unsafe { libc::getgid() }, unsafe { libc::getegid() });
        uid != euid || gid != egid
    };
    c_int::from(set)
}

ffi_export! {
    /// Sets up the library and the subsystems `opts` asks for (`OPENSSL_INIT_*`), with
    /// `settings` for the configuration file. Returns 1, or 0 if a subsystem failed or
    /// `OPENSSL_cleanup` has run.
    ///
    /// # Safety
    /// `settings` is null or a live handle from `OPENSSL_INIT_new`.
    pub unsafe extern "C" fn OPENSSL_init_crypto(opts: u64, settings: *const OPENSSL_INIT_SETTINGS) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if STOPPED.load(Ordering::Acquire) {
            err::raise(ERR_LIB_CRYPTO, ERR_R_INIT_FAIL, "OPENSSL_init_crypto");
            return 0;
        }
        if DONE.load(Ordering::Acquire) & opts == opts {
            return 1;
        }
        let Some(done) = init(opts, settings) else {
            return 0;
        };
        DONE.fetch_or(done, Ordering::AcqRel);
        1
    }
}

ffi_export! {
    /// Runs the `OPENSSL_atexit` handlers, newest first, and tears down what can be; after it,
    /// `OPENSSL_init_crypto` fails. Does nothing if the library was never set up, or the
    /// second time.
    ///
    /// # Safety
    /// No other thread uses the library during or after the call.
    pub unsafe extern "C" fn OPENSSL_cleanup()
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if !BASE.load(Ordering::Acquire) || STOPPED.swap(true, Ordering::AcqRel) {
            return;
        }
        // As OpenSSL's does: the last thread may never get its thread-exit cleanup.
        crate::threads::stop_thread();
        // The handlers run without the lock held: they may call back into the library.
        let handlers = HANDLERS.lock().map(|mut h| core::mem::take(&mut *h)).unwrap_or_default();
        for handler in handlers.into_iter().rev() {
            // SAFETY: the application registered the handler to be called here.
            unsafe { handler() };
        }
        // SAFETY: no preconditions; a heap still in use stays up, as in OpenSSL.
        unsafe { crate::secure::CRYPTO_secure_malloc_done() };
        BASE.store(false, Ordering::Release);
    }
}

ffi_export! {
    /// Registers `handler` for `OPENSSL_cleanup` to call, newest first, and keeps the library
    /// it's in loaded. Returns 1, or 0 for a null handler (OpenSSL's would crash at cleanup).
    ///
    /// # Safety
    /// `handler` is null or a function that stays callable until it runs.
    pub unsafe extern "C" fn OPENSSL_atexit(handler: Option<unsafe extern "C" fn()>) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(handler) = handler else {
            return 0;
        };
        pin(handler as *const c_void);
        match HANDLERS.lock() {
            Ok(mut handlers) => {
                handlers.push(handler);
                1
            }
            Err(_) => 0,
        }
    }
}

ffi_export! {
    /// Does nothing (OpenSSL 3's is empty too).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OPENSSL_init()
    where failure = (), library = ERR_LIB_CRYPTO
    {}
}

/// The settings `OPENSSL_init_crypto` loads the configuration file with.
pub(crate) struct Settings {
    filename: Mutex<Option<CString>>,
    appname: Mutex<Option<CString>>,
    flags: core::sync::atomic::AtomicU64,
}

handle_type!(OPENSSL_INIT_SETTINGS => Settings);

impl Settings {
    /// Replaces a name with a copy of `value`, or clears it for null. Returns 1.
    ///
    /// # Safety
    /// `value` is null or a NUL-terminated string.
    unsafe fn set(slot: &Mutex<Option<CString>>, value: *const c_char) -> c_int {
        // SAFETY: the caller's guarantee.
        let value = (!value.is_null()).then(|| unsafe { CStr::from_ptr(value) }.to_owned());
        match slot.lock() {
            Ok(mut slot) => {
                *slot = value;
                1
            }
            Err(_) => 0,
        }
    }
}

ffi_export! {
    /// New settings: no file or application name, and the default flags.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OPENSSL_INIT_new() -> *mut OPENSSL_INIT_SETTINGS
    where failure = core::ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // Like OpenSSL's, outside the application's allocator: these may outlive a change of it.
        OPENSSL_INIT_SETTINGS::new_handle(Settings {
            filename: Mutex::new(None),
            appname: Mutex::new(None),
            flags: AtomicU64::new(default_flags()),
        })
    }
}

ffi_export! {
    /// Sets the configuration file, or clears it for null. Returns 1; 0 for null settings.
    ///
    /// # Safety
    /// `settings` is null or a live handle from `OPENSSL_INIT_new`; `filename` is null or a
    /// NUL-terminated string.
    pub unsafe extern "C" fn OPENSSL_INIT_set_config_filename(
        settings: *mut OPENSSL_INIT_SETTINGS,
        filename: *const c_char,
    ) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        match unsafe { OPENSSL_INIT_SETTINGS::get(settings) } {
            // SAFETY: the caller's guarantee.
            Some(settings) => unsafe { Settings::set(&settings.filename, filename) },
            None => 0,
        }
    }
}

ffi_export! {
    /// Sets the application name, whose configuration section is used, or clears it for null.
    /// Returns 1; 0 for null settings.
    ///
    /// # Safety
    /// As for `OPENSSL_INIT_set_config_filename`.
    pub unsafe extern "C" fn OPENSSL_INIT_set_config_appname(
        settings: *mut OPENSSL_INIT_SETTINGS,
        appname: *const c_char,
    ) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        match unsafe { OPENSSL_INIT_SETTINGS::get(settings) } {
            // SAFETY: the caller's guarantee.
            Some(settings) => unsafe { Settings::set(&settings.appname, appname) },
            None => 0,
        }
    }
}

ffi_export! {
    /// Sets the `CONF_MFLAGS_*` flags for loading the configuration file. Null does nothing.
    ///
    /// # Safety
    /// `settings` is null or a live handle from `OPENSSL_INIT_new`.
    pub unsafe extern "C" fn OPENSSL_INIT_set_config_file_flags(
        settings: *mut OPENSSL_INIT_SETTINGS,
        flags: c_ulong,
    )
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        if let Some(settings) = unsafe { OPENSSL_INIT_SETTINGS::get(settings) } {
            settings.flags.store(flags, Ordering::Relaxed);
        }
    }
}

ffi_export! {
    /// Frees settings. Null does nothing.
    ///
    /// # Safety
    /// `settings` is null or a live handle from `OPENSSL_INIT_new`, not used afterwards.
    pub unsafe extern "C" fn OPENSSL_INIT_free(settings: *mut OPENSSL_INIT_SETTINGS)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { OPENSSL_INIT_SETTINGS::free(settings) }
    }
}

ffi_export! {
    /// Whether the process runs with set-user-ID or set-group-ID privileges, in which case the
    /// library ignores environment variables such as `OPENSSL_CONF`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OPENSSL_issetugid() -> c_int
    where failure = 1, library = ERR_LIB_CRYPTO
    {
        issetugid()
    }
}

ffi_export! {
    /// Whether the process is a Windows service: never, elsewhere.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OPENSSL_isservice() -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        0
    }
}

ffi_export! {
    /// Does nothing: OpenSSL 3 deprecated the fork handlers and made them empty.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OPENSSL_fork_prepare()
    where failure = (), library = ERR_LIB_CRYPTO
    {}
}

ffi_export! {
    /// Does nothing (see `OPENSSL_fork_prepare`).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OPENSSL_fork_parent()
    where failure = (), library = ERR_LIB_CRYPTO
    {}
}

ffi_export! {
    /// Does nothing (see `OPENSSL_fork_prepare`).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OPENSSL_fork_child()
    where failure = (), library = ERR_LIB_CRYPTO
    {}
}

ffi_export! {
    /// Prints `file:line: OpenSSL internal error: message` to stderr and aborts, as OpenSSL's
    /// does (null strings print as `(null)`, as C's printf does on Linux and macOS).
    ///
    /// # Safety
    /// `message` and `file` are each null or a NUL-terminated string.
    pub unsafe extern "C" fn OPENSSL_die(message: *const c_char, file: *const c_char, line: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        use std::io::Write as _;
        let text = |s: *const c_char| -> Vec<u8> {
            if s.is_null() {
                b"(null)".to_vec()
            } else {
                // SAFETY: the caller passes a NUL-terminated string.
                unsafe { CStr::from_ptr(s) }.to_bytes().to_vec()
            }
        };
        let mut out = text(file);
        out.extend_from_slice(format!(":{line}: OpenSSL internal error: ").as_bytes());
        out.extend_from_slice(&text(message));
        out.push(b'\n');
        // Nothing useful can be done if stderr is closed; the process aborts either way.
        let _ = std::io::stderr().write_all(&out);
        std::process::abort()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_null_exit_handler_is_refused() {
        // SAFETY: a null handler is checked before anything else.
        let registered = unsafe { OPENSSL_atexit(None) };
        assert_eq!(registered, 0);
    }

    #[test]
    fn null_settings_are_refused() {
        let name = c"x".as_ptr();
        let null = core::ptr::null_mut();
        // SAFETY: null settings are checked before the name is read.
        let filename = unsafe { OPENSSL_INIT_set_config_filename(null, name) };
        // SAFETY: as above.
        let appname = unsafe { OPENSSL_INIT_set_config_appname(null, name) };
        assert_eq!((filename, appname), (0, 0));
        // SAFETY: null settings are ignored.
        unsafe { OPENSSL_INIT_set_config_file_flags(null, 0) };
    }

    #[test]
    fn settings_hold_copies() {
        // SAFETY: no preconditions.
        let settings = unsafe { OPENSSL_INIT_new() };
        let mut name = *b"first\0";
        // SAFETY: `settings` is live and `name` is NUL-terminated.
        let set = unsafe { OPENSSL_INIT_set_config_filename(settings, name.as_ptr().cast()) };
        assert_eq!(set, 1);
        // Changing the caller's string afterwards doesn't change the settings.
        name[0] = b'X';
        assert_eq!(&std::hint::black_box(name)[..1], b"X");
        // SAFETY: `settings` is a live handle.
        let stored = unsafe { OPENSSL_INIT_SETTINGS::get(settings) }
            .and_then(|s| s.filename.lock().ok()?.clone());
        assert_eq!(stored.as_deref(), Some(c"first"));
        // SAFETY: `settings` is live and freed once.
        unsafe { OPENSSL_INIT_free(settings) };
    }
}
