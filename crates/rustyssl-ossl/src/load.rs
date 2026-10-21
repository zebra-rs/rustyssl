//! Loading libcrypto and libssl when the program starts, and resolving each export once
//! (ADR 0007, section 2, "Linking").
//!
//! The libraries are found as a linked binary's `RUNPATH` would find them: in each directory
//! of the platform's library path variable (`LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`) when it is
//! set, so the same binary runs on rustyssl's libraries or the reference's exactly as
//! upstream's binary does; then in `../lib` next to the binary (the `target/dist` layout); then
//! by soname (install name on macOS) through the system's default search.
//!
//! **Fail closed:** a library that can't be loaded, or an export missing from it, prints a
//! message and exits with status 1. Nothing falls back to another implementation.

use core::ffi::{CStr, c_void};
use std::ffi::{CString, OsString};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::abi::OPENSSL_VERSION_MAJOR;

/// The two libraries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Library {
    Crypto,
    Ssl,
}

impl Library {
    /// The file name the loader knows it by: its soname (`libcrypto.so.3`), or install name
    /// on macOS (`libcrypto.3.dylib`), with the headers' major version.
    pub fn file_name(self) -> String {
        let base = match self {
            Library::Crypto => "libcrypto",
            Library::Ssl => "libssl",
        };
        if cfg!(target_os = "macos") {
            format!("{base}.{OPENSSL_VERSION_MAJOR}.dylib")
        } else {
            format!("{base}.so.{OPENSSL_VERSION_MAJOR}")
        }
    }
}

/// The platform's library path variable.
pub const LIBRARY_PATH: &str = if cfg!(target_os = "macos") {
    "DYLD_LIBRARY_PATH"
} else {
    "LD_LIBRARY_PATH"
};

/// A `dlopen` handle. The libraries stay loaded until the process exits.
struct Handle(*mut c_void);

// SAFETY: a dlopen handle is a process-wide token that dlsym accepts from any thread.
unsafe impl Send for Handle {}
// SAFETY: as above; the handle is never written after it is stored.
unsafe impl Sync for Handle {}

struct Loaded {
    crypto: Handle,
    ssl: Handle,
}

static LOADED: OnceLock<Result<Loaded, String>> = OnceLock::new();

/// Where to look for `file`, in order: each directory of the library path variable, `../lib`
/// next to the binary, then the bare name for the system's search.
pub fn candidates(
    file: &str,
    library_path: Option<OsString>,
    exe: Option<PathBuf>,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(dirs) = library_path {
        for dir in std::env::split_paths(&dirs) {
            if !dir.as_os_str().is_empty() {
                out.push(dir.join(file));
            }
        }
    }
    if let Some(dir) = exe.as_deref().and_then(Path::parent) {
        out.push(dir.join("../lib").join(file));
    }
    out.push(PathBuf::from(file));
    out
}

fn dlerror_text() -> String {
    // SAFETY: dlerror takes no arguments and returns NULL or a NUL-terminated string.
    let e = unsafe { libc::dlerror() };
    if e.is_null() {
        return "unknown error".to_owned();
    }
    // SAFETY: e is non-NULL and NUL-terminated, valid until the next dl* call on this thread.
    unsafe { CStr::from_ptr(e) }.to_string_lossy().into_owned()
}

/// Opens `library` from the first candidate that exists (a path), or by name.
fn open(library: Library) -> Result<Handle, String> {
    let file = library.file_name();
    let exe = std::env::current_exe().ok();
    open_first(&file, &candidates(&file, std::env::var_os(LIBRARY_PATH), exe))
}

/// Opens the first of `list` that loads. A path that exists but doesn't load (another
/// architecture's library, such as a 32-bit one in `/usr/lib` on a multilib system) is
/// skipped, as the dynamic loader skips an incompatible library on its search path; if none
/// loads, the error names the first that failed.
fn open_first(file: &str, list: &[PathBuf]) -> Result<Handle, String> {
    let mut first_error = None;
    for path in list {
        let by_name = path.as_os_str() == file;
        if !by_name && !path.exists() {
            continue;
        }
        let c = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| format!("bad library path {}", path.display()))?;
        // SAFETY: c is a NUL-terminated path; the flags are valid dlopen modes.
        let h = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if h.is_null() {
            let error = format!("cannot load {}: {}", path.display(), dlerror_text());
            first_error.get_or_insert(error);
            continue;
        }
        return Ok(Handle(h));
    }
    Err(first_error.unwrap_or_else(|| format!("cannot find {file}")))
}

fn loaded() -> &'static Loaded {
    let result = LOADED.get_or_init(|| {
        // libcrypto first: libssl's dependency on it then resolves to the same copy.
        let crypto = open(Library::Crypto)?;
        let ssl = open(Library::Ssl)?;
        Ok(Loaded { crypto, ssl })
    });
    match result {
        Ok(l) => l,
        Err(e) => fail(e),
    }
}

/// Loads both libraries now, so a missing one stops the program before it does anything.
pub fn init() {
    let _ = loaded();
}

/// Fails closed: the message, then exit status 1.
#[allow(clippy::exit)] // Fail closed (ADR 0007, section 2): the program can't continue.
fn fail(message: &str) -> ! {
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "openssl: {message}");
    let _ = err.flush();
    std::process::exit(1)
}

/// One export, resolved when first used.
pub struct Symbol {
    library: Library,
    /// The name, NUL-terminated.
    name: &'static str,
    address: AtomicPtr<c_void>,
}

impl Symbol {
    /// `name` must end with a NUL.
    pub const fn new(library: Library, name: &'static str) -> Self {
        Self {
            library,
            name,
            address: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// The export's address; exits (fail closed) if the library doesn't have it.
    pub fn get(&self) -> *mut c_void {
        let a = self.address.load(Ordering::Acquire);
        if !a.is_null() {
            return a;
        }
        let l = loaded();
        let handle = match self.library {
            Library::Crypto => l.crypto.0,
            Library::Ssl => l.ssl.0,
        };
        let Ok(name) = CStr::from_bytes_with_nul(self.name.as_bytes()) else {
            fail(&format!("bad symbol name {:?}", self.name))
        };
        // SAFETY: handle came from dlopen and is never closed; name is NUL-terminated.
        let a = unsafe { libc::dlsym(handle, name.as_ptr()) };
        if a.is_null() {
            fail(&format!(
                "{} has no function {}",
                self.library.file_name(),
                self.name.trim_end_matches('\0')
            ));
        }
        self.address.store(a, Ordering::Release);
        a
    }
}

/// Declares imports: `crate::import! { Crypto; fn NAME(a0: T0, ...) -> R; ... }`. Each
/// becomes an `unsafe fn` of that prototype that resolves the export when first called.
#[macro_export]
#[doc(hidden)]
macro_rules! import {
    ($lib:ident; $(fn $name:ident($($a:ident: $t:ty),*) $(-> $r:ty)?;)*) => { $(
        /// # Safety
        /// The C function's own contract (its man page) applies.
        #[inline]
        pub unsafe fn $name($($a: $t),*) $(-> $r)? {
            static SYM: $crate::load::Symbol =
                $crate::load::Symbol::new($crate::load::Library::$lib, concat!(stringify!($name), "\0"));
            let p = SYM.get();
            // SAFETY: p is the address of the export `$name`, whose C prototype (from the
            // vendored headers) is exactly this function pointer type.
            let f = unsafe { core::mem::transmute::<*mut core::ffi::c_void, unsafe extern "C" fn($($t),*) $(-> $r)?>(p) };
            // SAFETY: the caller upholds the C function's contract.
            unsafe { f($($a),*) }
        }
    )* };
}

/// Declares C-variadic imports: `crate::import_variadic! { Crypto; fn NAME(a0: T0, ...) -> R;
/// ... }`. Each becomes a function returning the resolved pointer, of the C-variadic type.
#[macro_export]
#[doc(hidden)]
macro_rules! import_variadic {
    ($lib:ident; $(fn $name:ident($($a:ident: $t:ty),*) $(-> $r:ty)?;)*) => { $(
        /// The C-variadic export, resolved.
        pub fn $name() -> unsafe extern "C" fn($($t),*, ...) $(-> $r)? {
            static SYM: $crate::load::Symbol =
                $crate::load::Symbol::new($crate::load::Library::$lib, concat!(stringify!($name), "\0"));
            let p = SYM.get();
            // SAFETY: p is the address of the export `$name`, whose C prototype (from the
            // vendored headers) is exactly this function pointer type.
            unsafe { core::mem::transmute::<*mut core::ffi::c_void, unsafe extern "C" fn($($t),*, ...) $(-> $r)?>(p) }
        }
    )* };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_names() {
        let (crypto, ssl) = (Library::Crypto.file_name(), Library::Ssl.file_name());
        if cfg!(target_os = "macos") {
            assert_eq!(
                (crypto.as_str(), ssl.as_str()),
                ("libcrypto.3.dylib", "libssl.3.dylib")
            );
        } else {
            assert_eq!(
                (crypto.as_str(), ssl.as_str()),
                ("libcrypto.so.3", "libssl.so.3")
            );
        }
    }

    #[test]
    fn a_library_that_does_not_load_is_skipped() {
        // A file that exists but isn't a library, then the C library by name.
        let dir = std::env::temp_dir().join(format!("rustyssl-load-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bogus = dir.join("libbogus.so.3");
        std::fs::write(&bogus, b"not a library").unwrap();
        let libc_name = if cfg!(target_os = "macos") { "libSystem.B.dylib" } else { "libc.so.6" };
        assert!(open_first(libc_name, &[bogus.clone(), PathBuf::from(libc_name)]).is_ok());
        let Err(e) = open_first("libnothing.so.3", &[bogus.clone(), dir.join("missing")]) else {
            panic!("a bogus library loaded");
        };
        assert!(e.starts_with(&format!("cannot load {}", bogus.display())), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn search_order_is_runpaths() {
        let exe = PathBuf::from("/opt/x/bin/openssl");
        let lp = std::env::join_paths(["/a", "", "/b"]).ok();
        let c = candidates("libcrypto.so.3", lp, Some(exe.clone()));
        assert_eq!(
            c,
            [
                "/a/libcrypto.so.3",
                "/b/libcrypto.so.3",
                "/opt/x/bin/../lib/libcrypto.so.3",
                "libcrypto.so.3"
            ]
            .map(PathBuf::from)
        );
        let c = candidates("libssl.so.3", None, None);
        assert_eq!(c, [PathBuf::from("libssl.so.3")]);
    }
}
