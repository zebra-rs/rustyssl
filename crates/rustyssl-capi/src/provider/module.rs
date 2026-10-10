//! Providers in modules: the lookup OpenSSL's DSO loader makes for a provider that isn't built in
//! (`provider_init` in `crypto/provider_core.c`, `crypto/dso/dso_dlfcn.c`), with its errors.
//!
//! The directory is the context's search path, else `$OPENSSL_MODULES` (ignored in set-user-ID
//! programs), else `MODULESDIR`. A plain name gets the platform's extension (`.so`, or `.dylib`
//! on macOS); a name with a slash is used as it is; a relative path is joined to the
//! directory. The file is opened with `dlopen`, and a failure raises OpenSSL's errors with the
//! system's message.
//!
//! rustyssl doesn't run external providers yet (that needs the rest of the core's services): a
//! module that opens is closed again and the load fails with `ERR_R_UNSUPPORTED`.

use core::ffi::{CStr, c_char};
use std::ffi::CString;

use rustyssl_abi::{
    DSO_R_LOAD_FAILED, DSO_R_SYM_FAILURE, ERR_LIB_CRYPTO, ERR_LIB_DSO, ERR_R_DSO_LIB,
    ERR_R_UNSUPPORTED,
};

use super::Provider;
use crate::{err, init, version};

/// `DSO_EXTENSION`.
#[cfg(target_os = "macos")]
const EXTENSION: &[u8] = b".dylib";
#[cfg(not(target_os = "macos"))]
const EXTENSION: &[u8] = b".so";

/// `dlfcn_name_converter` with `DSO_FLAG_NAME_TRANSLATION_EXT_ONLY`.
fn converted(name: &[u8]) -> Vec<u8> {
    let mut file = name.to_vec();
    if !name.contains(&b'/') {
        file.extend_from_slice(EXTENSION);
    }
    file
}

/// `dlfcn_merger`: the file, absolute or joined to the directory.
fn merged(file: &[u8], dir: &[u8]) -> Vec<u8> {
    if file.first() == Some(&b'/') {
        return file.to_vec();
    }
    let dir = dir.strip_suffix(b"/").unwrap_or(dir);
    let mut path = dir.to_vec();
    path.push(b'/');
    path.extend_from_slice(file);
    path
}

/// The system's last dynamic-loading error.
fn dlerror() -> Vec<u8> {
    // SAFETY: no preconditions; the message is copied at once.
    let e: *const c_char = unsafe { libc::dlerror() };
    if e.is_null() {
        return Vec::new();
    }
    // SAFETY: a string from the loader.
    unsafe { CStr::from_ptr(e) }.to_bytes().to_vec()
}

/// Looks for the module of the provider `prov`, raising OpenSSL's errors, and fails: an
/// external provider can't run yet.
pub(super) fn load(prov: &Provider, search_path: Option<&CStr>) {
    let name = prov.name().to_bytes();
    let dir = search_path
        .map(CStr::to_owned)
        .or_else(|| init::safe_getenv(c"OPENSSL_MODULES"))
        .unwrap_or_else(|| version::modulesdir().to_owned());
    let file = prov
        .module_path()
        .map_or_else(|| converted(name), |p| p.to_bytes().to_vec());
    let path = merged(&file, dir.as_bytes());
    let mut name_data = b"name=".to_vec();
    name_data.extend_from_slice(name);
    let Ok(cpath) = CString::new(path.clone()) else {
        err::raise_with_bytes(ERR_LIB_CRYPTO, ERR_R_DSO_LIB, "provider_init", &name_data);
        return;
    };
    // SAFETY: a NUL-terminated path.
    let module = unsafe { libc::dlopen(cpath.as_ptr(), libc::RTLD_NOW) };
    if module.is_null() {
        let mut data = b"filename(".to_vec();
        data.extend_from_slice(&path);
        data.extend_from_slice(b"): ");
        data.extend_from_slice(&dlerror());
        err::raise_with_bytes(ERR_LIB_DSO, DSO_R_LOAD_FAILED, "dlfcn_load", &data);
        err::raise(ERR_LIB_DSO, DSO_R_LOAD_FAILED, "DSO_load");
        err::raise_with_bytes(ERR_LIB_CRYPTO, ERR_R_DSO_LIB, "provider_init", &name_data);
        return;
    }
    // SAFETY: an open module and a NUL-terminated name.
    let init = unsafe { libc::dlsym(module, c"OSSL_provider_init".as_ptr()) };
    let reason: &[u8] = if init.is_null() {
        let mut data = b"symname(OSSL_provider_init): ".to_vec();
        data.extend_from_slice(&dlerror());
        err::raise_with_bytes(ERR_LIB_DSO, DSO_R_SYM_FAILURE, "dlfcn_bind_func", &data);
        err::raise(ERR_LIB_DSO, DSO_R_SYM_FAILURE, "DSO_bind_func");
        b", provider has no provider init function"
    } else {
        b", rustyssl doesn't run external providers yet"
    };
    // SAFETY: the module opened above, no longer used.
    unsafe { libc::dlclose(module) };
    name_data.extend_from_slice(reason);
    err::raise_with_bytes(
        ERR_LIB_CRYPTO,
        ERR_R_UNSUPPORTED,
        "provider_init",
        &name_data,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_as_openssl_makes_them() {
        assert_eq!(
            merged(&converted(b"x"), b"/m/"),
            [b"/m/x".as_slice(), EXTENSION].concat()
        );
        assert_eq!(merged(&converted(b"a/b"), b"/m"), b"/m/a/b");
        assert_eq!(merged(&converted(b"/abs/p"), b"/m"), b"/abs/p");
        assert_eq!(merged(b"f", b""), b"/f");
    }
}
