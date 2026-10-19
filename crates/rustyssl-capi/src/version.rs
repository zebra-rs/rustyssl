//! The library's version and build information (`OpenSSL_version(3)`, `OPENSSL_info(3)`).
//!
//! rustyssl reports the OpenSSL release whose ABI it implements: the same version number, the
//! same `MAJOR.MINOR.PATCH`, and the same release date, all from the vendored headers. It names
//! itself in the build metadata, the part of the version OpenSSL reserves "for other parties,
//! such as `+fips`, or `+vendor.1`": `+rustyssl.<version>`. So `OpenSSL_version(OPENSSL_VERSION)`
//! reads `OpenSSL 3.6.5+rustyssl.0.1.0 29 Sep 2026`, which version parsers accept and people and
//! vulnerability scanners can tell apart from OpenSSL (docs/DEVIATIONS.md).
//!
//! The directories are those of OpenSSL's default build for the target (`/usr/local/ssl` and
//! so on, from `config/<target>/build.toml`). Packagers override them at build time with the
//! environment variables `RUSTYSSL_OPENSSLDIR`, `RUSTYSSL_ENGINESDIR`, and `RUSTYSSL_MODULESDIR`.

use core::ffi::{CStr, c_char, c_int, c_uint, c_ulong};
use std::ffi::CString;
use std::sync::OnceLock;

use rustyssl_abi::{
    ERR_LIB_CRYPTO, OPENSSL_BUILT_ON, OPENSSL_CFLAGS, OPENSSL_CPU_INFO, OPENSSL_DIR,
    OPENSSL_ENGINES_DIR, OPENSSL_FULL_VERSION_STRING, OPENSSL_INFO_CONFIG_DIR,
    OPENSSL_INFO_CPU_SETTINGS, OPENSSL_INFO_DIR_FILENAME_SEPARATOR, OPENSSL_INFO_DSO_EXTENSION,
    OPENSSL_INFO_ENGINES_DIR, OPENSSL_INFO_LIST_SEPARATOR, OPENSSL_INFO_MODULES_DIR,
    OPENSSL_INFO_SEED_SOURCE, OPENSSL_INFO_WINDOWS_CONTEXT, OPENSSL_MODULES_DIR, OPENSSL_PLATFORM,
    OPENSSL_RELEASE_DATE, OPENSSL_VERSION, OPENSSL_VERSION_MAJOR, OPENSSL_VERSION_MINOR,
    OPENSSL_VERSION_NUMBER, OPENSSL_VERSION_PATCH, OPENSSL_VERSION_PRE_RELEASE,
    OPENSSL_VERSION_STR, OPENSSL_VERSION_STRING, OPENSSL_WINCTX, build,
};

use crate::ffi::ffi_export;

/// The build metadata: `+rustyssl.<crate version>`.
const BUILD_METADATA: &str = concat!("+rustyssl.", env!("CARGO_PKG_VERSION"));

/// A string built once and kept for the life of the process, as C callers expect.
fn kept(cell: &'static OnceLock<CString>, make: impl FnOnce() -> String) -> *const c_char {
    cell.get_or_init(|| CString::new(make()).unwrap_or_default())
        .as_ptr()
}

/// The text of a generated C string constant.
fn text(value: &CStr) -> &str {
    value.to_str().unwrap_or_default()
}

/// A build-time override from the environment, or the default build's value.
fn directory(cell: &'static OnceLock<CString>, set: Option<&str>, default: &CStr) -> &'static CStr {
    cell.get_or_init(|| {
        set.and_then(|dir| CString::new(dir).ok())
            .unwrap_or_else(|| default.to_owned())
    })
}

static OPENSSLDIR: OnceLock<CString> = OnceLock::new();
static ENGINESDIR: OnceLock<CString> = OnceLock::new();
static MODULESDIR: OnceLock<CString> = OnceLock::new();

/// The directory of the configuration, certificates, and keys (`OPENSSLDIR`).
pub(crate) fn openssldir() -> &'static CStr {
    directory(
        &OPENSSLDIR,
        option_env!("RUSTYSSL_OPENSSLDIR"),
        build::OPENSSLDIR,
    )
}

/// The directory engines are loaded from (`ENGINESDIR`).
pub(crate) fn enginesdir() -> &'static CStr {
    directory(
        &ENGINESDIR,
        option_env!("RUSTYSSL_ENGINESDIR"),
        build::ENGINESDIR,
    )
}

/// The directory providers' modules are loaded from (`MODULESDIR`).
pub(crate) fn modulesdir() -> &'static CStr {
    directory(
        &MODULESDIR,
        option_env!("RUSTYSSL_MODULESDIR"),
        build::MODULESDIR,
    )
}

/// The default configuration file's directory, which `OPENSSL_CONF` overrides.
pub(crate) fn config_dir() -> &'static CStr {
    openssldir()
}

/// `MAJOR.MINOR.PATCH`, the pre-release tag (empty for releases), and the build metadata.
fn full_version() -> String {
    format!(
        "{}{}{BUILD_METADATA}",
        text(OPENSSL_VERSION_STR),
        text(OPENSSL_VERSION_PRE_RELEASE)
    )
}

ffi_export! {
    /// The version number, `0xMNN00PP0L` (`OPENSSL_VERSION_NUMBER`).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OpenSSL_version_num() -> c_ulong
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        c_ulong::try_from(OPENSSL_VERSION_NUMBER).unwrap_or_default()
    }
}

ffi_export! {
    /// The major version.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OPENSSL_version_major() -> c_uint
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        OPENSSL_VERSION_MAJOR.cast_unsigned()
    }
}

ffi_export! {
    /// The minor version.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OPENSSL_version_minor() -> c_uint
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        OPENSSL_VERSION_MINOR.cast_unsigned()
    }
}

ffi_export! {
    /// The patch version.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OPENSSL_version_patch() -> c_uint
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        OPENSSL_VERSION_PATCH.cast_unsigned()
    }
}

ffi_export! {
    /// The pre-release tag, empty for a release.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OPENSSL_version_pre_release() -> *const c_char
    where failure = c"".as_ptr(), library = ERR_LIB_CRYPTO
    {
        OPENSSL_VERSION_PRE_RELEASE.as_ptr()
    }
}

ffi_export! {
    /// The build metadata, `+rustyssl.<version>`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OPENSSL_version_build_metadata() -> *const c_char
    where failure = c"".as_ptr(), library = ERR_LIB_CRYPTO
    {
        static METADATA: OnceLock<CString> = OnceLock::new();
        kept(&METADATA, || BUILD_METADATA.to_owned())
    }
}

ffi_export! {
    /// One line of version or build information, selected by `t` (`OPENSSL_VERSION`,
    /// `OPENSSL_DIR`, ...); `"not available"` for anything else.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OpenSSL_version(t: c_int) -> *const c_char
    where failure = c"not available".as_ptr(), library = ERR_LIB_CRYPTO
    {
        static TEXT: OnceLock<CString> = OnceLock::new();
        static FULL: OnceLock<CString> = OnceLock::new();
        static CFLAGS: OnceLock<CString> = OnceLock::new();
        static PLATFORM: OnceLock<CString> = OnceLock::new();
        static DIR: OnceLock<CString> = OnceLock::new();
        static ENGINES: OnceLock<CString> = OnceLock::new();
        static MODULES: OnceLock<CString> = OnceLock::new();
        let quoted = |label: &str, dir: &CStr| format!("{label}: \"{}\"", dir.to_string_lossy());
        match t {
            OPENSSL_VERSION => kept(&TEXT, || {
                format!("OpenSSL {} {}", full_version(), text(OPENSSL_RELEASE_DATE))
            }),
            OPENSSL_VERSION_STRING => OPENSSL_VERSION_STR.as_ptr(),
            OPENSSL_FULL_VERSION_STRING => kept(&FULL, full_version),
            OPENSSL_CFLAGS => kept(&CFLAGS, || {
                format!("compiler: rustc (rustyssl {})", env!("CARGO_PKG_VERSION"))
            }),
            // rustyssl builds are reproducible: nothing records when they were made.
            OPENSSL_BUILT_ON => c"built on: reproducible build, date unspecified".as_ptr(),
            OPENSSL_PLATFORM => kept(&PLATFORM, || format!("platform: {}", text(build::PLATFORM))),
            OPENSSL_DIR => kept(&DIR, || quoted("OPENSSLDIR", openssldir())),
            OPENSSL_ENGINES_DIR => kept(&ENGINES, || quoted("ENGINESDIR", enginesdir())),
            OPENSSL_MODULES_DIR => kept(&MODULES, || quoted("MODULESDIR", modulesdir())),
            // OpenSSL's capability vectors (OPENSSL_ia32cap, OPENSSL_armcap) steer its assembly,
            // which rustyssl doesn't have.
            OPENSSL_CPU_INFO => c"CPUINFO: N/A".as_ptr(),
            OPENSSL_WINCTX => c"OSSL_WINCTX: Undefined".as_ptr(),
            _ => c"not available".as_ptr(),
        }
    }
}

ffi_export! {
    /// One piece of build information, selected by `t` (`OPENSSL_INFO_CONFIG_DIR`, ...), or
    /// null if there is none (not an error).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OPENSSL_info(t: c_int) -> *const c_char
    where failure = core::ptr::null(), library = ERR_LIB_CRYPTO
    {
        match t {
            OPENSSL_INFO_CONFIG_DIR => openssldir().as_ptr(),
            OPENSSL_INFO_ENGINES_DIR => enginesdir().as_ptr(),
            OPENSSL_INFO_MODULES_DIR => modulesdir().as_ptr(),
            OPENSSL_INFO_DSO_EXTENSION => build::DSO_EXTENSION.as_ptr(),
            OPENSSL_INFO_DIR_FILENAME_SEPARATOR => c"/".as_ptr(),
            OPENSSL_INFO_LIST_SEPARATOR => c":".as_ptr(),
            // The random generator seeds from the operating system.
            OPENSSL_INFO_SEED_SOURCE => c"os-specific".as_ptr(),
            OPENSSL_INFO_WINDOWS_CONTEXT => c"Undefined".as_ptr(),
            // See OPENSSL_CPU_INFO above.
            OPENSSL_INFO_CPU_SETTINGS => core::ptr::null(),
            _ => core::ptr::null(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string(pointer: *const c_char) -> String {
        // SAFETY: every pointer these functions return is a static NUL-terminated string.
        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn version_text_names_rustyssl_in_the_build_metadata() {
        // SAFETY: no preconditions.
        let version = string(unsafe { OpenSSL_version(OPENSSL_VERSION) });
        // SAFETY: as above.
        let full = string(unsafe { OpenSSL_version(OPENSSL_FULL_VERSION_STRING) });
        // SAFETY: as above.
        let metadata = string(unsafe { OPENSSL_version_build_metadata() });
        let release = text(OPENSSL_VERSION_STR);
        assert_eq!(metadata, format!("+rustyssl.{}", env!("CARGO_PKG_VERSION")));
        assert_eq!(full, format!("{release}{metadata}"));
        assert_eq!(
            version,
            format!("OpenSSL {full} {}", text(OPENSSL_RELEASE_DATE))
        );
        // SAFETY: no preconditions.
        let short = string(unsafe { OpenSSL_version(OPENSSL_VERSION_STRING) });
        assert_eq!(short, release);
    }

    #[test]
    fn directories_and_platform_come_from_the_build_settings() {
        // SAFETY: no preconditions.
        let dir = string(unsafe { OpenSSL_version(OPENSSL_DIR) });
        // SAFETY: as above.
        let info = string(unsafe { OPENSSL_info(OPENSSL_INFO_CONFIG_DIR) });
        // SAFETY: as above.
        let platform = string(unsafe { OpenSSL_version(OPENSSL_PLATFORM) });
        assert_eq!(dir, format!("OPENSSLDIR: \"{info}\""));
        assert_eq!(info, text(openssldir()));
        assert_eq!(platform, format!("platform: {}", text(build::PLATFORM)));
        // SAFETY: no preconditions.
        assert_eq!(string(unsafe { OpenSSL_version(99) }), "not available");
        // SAFETY: no preconditions.
        assert!(unsafe { OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS) }.is_null());
    }
}
