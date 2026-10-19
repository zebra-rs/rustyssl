//! Shared-library loading as OpenSSL's DSO layer does it with `dlopen` (`dso_lib.c`,
//! `dso_dlfcn.c`): the file name rules, the merge with a directory, and the errors each step
//! raises, for the dynamic engine. (The `DSO_*` exports themselves are separate.)

use core::ffi::{CStr, c_char, c_int, c_void};
use std::ffi::CString;

use rustyssl_abi::{
    DSO_FLAG_NAME_TRANSLATION_EXT_ONLY, DSO_FLAG_NO_NAME_TRANSLATION, DSO_R_DSO_ALREADY_LOADED,
    DSO_R_LOAD_FAILED, DSO_R_NO_FILENAME, DSO_R_SYM_FAILURE, ERR_LIB_DSO,
};

use crate::err;

/// The extension a bare name gets (`DSO_EXTENSION`).
#[cfg(target_os = "macos")]
const EXTENSION: &[u8] = b".dylib";
#[cfg(not(target_os = "macos"))]
const EXTENSION: &[u8] = b".so";

/// A `dlopen` handle, closed when dropped.
struct Library(*mut c_void);

// SAFETY: a `dlopen` handle may be used and closed from any thread.
unsafe impl Send for Library {}

impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: a handle `dlopen` returned, closed once.
        unsafe { libc::dlclose(self.0) };
    }
}

/// A loaded (or to be loaded) shared library (`DSO`).
#[derive(Default)]
pub(crate) struct Dso {
    /// `DSO_FLAG_*`.
    flags: c_int,
    /// The name it was asked to load (kept after a failed load, as OpenSSL's is).
    filename: Option<CString>,
    /// The handles, newest last (`meth_data`).
    handles: Vec<Library>,
}

/// `dlerror()`'s message, or `<NULL>` if there's none.
fn dl_error() -> Vec<u8> {
    // SAFETY: no preconditions; the message is copied before any other dl call.
    let e = unsafe { libc::dlerror() };
    if e.is_null() {
        return b"<NULL>".to_vec();
    }
    // SAFETY: `dlerror` returns a C string.
    unsafe { CStr::from_ptr(e) }.to_bytes().to_vec()
}

impl Dso {
    /// `DSO_CTRL_SET_FLAGS`.
    pub(crate) fn set_flags(&mut self, flags: c_int) {
        self.flags = flags;
    }

    /// `dlfcn_name_converter` (`DSO_convert_filename`): a name with no `/` gets the
    /// extension, and the `lib` prefix unless `DSO_FLAG_NAME_TRANSLATION_EXT_ONLY`; `None`
    /// (`DSO_R_NO_FILENAME`) without a name.
    pub(crate) fn convert_filename(&self, filename: Option<&CStr>) -> Option<CString> {
        let Some(name) = filename.or(self.filename.as_deref()) else {
            err::raise(ERR_LIB_DSO, DSO_R_NO_FILENAME, "DSO_convert_filename");
            return None;
        };
        let name = name.to_bytes();
        if self.flags & DSO_FLAG_NO_NAME_TRANSLATION != 0 || name.contains(&b'/') {
            return CString::new(name).ok();
        }
        let mut out = Vec::new();
        if self.flags & DSO_FLAG_NAME_TRANSLATION_EXT_ONLY == 0 {
            out.extend_from_slice(b"lib");
        }
        out.extend_from_slice(name);
        out.extend_from_slice(EXTENSION);
        CString::new(out).ok()
    }

    /// `dlfcn_merger` (`DSO_merge`): `file` in the directory `dir`, unless it's absolute.
    pub(crate) fn merge(&self, file: &CStr, dir: &CStr) -> Option<CString> {
        if self.flags & DSO_FLAG_NO_NAME_TRANSLATION != 0 {
            return None;
        }
        let file = file.to_bytes();
        if file.first() == Some(&b'/') {
            return CString::new(file).ok();
        }
        let mut d = dir.to_bytes();
        if let Some(stripped) = d.strip_suffix(b"/") {
            d = stripped;
        }
        CString::new([d, b"/", file].concat()).ok()
    }

    /// `DSO_load(dso, filename, NULL, 0)`: loads `filename` (converted, as `dlfcn_load`
    /// does) with `RTLD_NOW`. Raises OpenSSL's errors: `DSO_R_DSO_ALREADY_LOADED` once a name
    /// is set (even after a failed load), `dlfcn_load`'s `DSO_R_LOAD_FAILED` with
    /// `filename(...): <dlerror>`, then `DSO_load`'s.
    pub(crate) fn load(&mut self, filename: &CStr) -> bool {
        if self.filename.is_some() {
            err::raise(ERR_LIB_DSO, DSO_R_DSO_ALREADY_LOADED, "DSO_load");
            return false;
        }
        self.filename = Some(filename.to_owned());
        let Some(file) = self.convert_filename(None) else {
            err::raise(ERR_LIB_DSO, DSO_R_NO_FILENAME, "dlfcn_load");
            err::raise(ERR_LIB_DSO, DSO_R_LOAD_FAILED, "DSO_load");
            return false;
        };
        // SAFETY: a C string; a library's constructors run, as with OpenSSL's dlopen.
        let h = unsafe { libc::dlopen(file.as_ptr(), libc::RTLD_NOW) };
        if h.is_null() {
            let text = [b"filename(", file.as_bytes(), b"): ", &dl_error()].concat();
            err::raise_with_bytes(ERR_LIB_DSO, DSO_R_LOAD_FAILED, "dlfcn_load", &text);
            err::raise(ERR_LIB_DSO, DSO_R_LOAD_FAILED, "DSO_load");
            return false;
        }
        self.handles.push(Library(h));
        true
    }

    /// `DSO_bind_func`: the address of `symname` in the newest loaded library, or `None`
    /// with `dlfcn_bind_func`'s and `DSO_bind_func`'s `DSO_R_SYM_FAILURE`.
    pub(crate) fn bind_func(&self, symname: &CStr) -> Option<*mut c_void> {
        let Some(h) = self.handles.last() else {
            err::raise(
                ERR_LIB_DSO,
                rustyssl_abi::DSO_R_STACK_ERROR,
                "dlfcn_bind_func",
            );
            err::raise(ERR_LIB_DSO, DSO_R_SYM_FAILURE, "DSO_bind_func");
            return None;
        };
        // SAFETY: a live handle and a C string.
        let p = unsafe { libc::dlsym(h.0, symname.as_ptr()) };
        if p.is_null() {
            let text = [b"symname(", symname.to_bytes(), b"): ", &dl_error()].concat();
            err::raise_with_bytes(ERR_LIB_DSO, DSO_R_SYM_FAILURE, "dlfcn_bind_func", &text);
            err::raise(ERR_LIB_DSO, DSO_R_SYM_FAILURE, "DSO_bind_func");
            return None;
        }
        Some(p)
    }
}

/// The C string of a `c_char` pointer, or `None` for NULL.
///
/// # Safety
/// `p` is NULL or a C string.
pub(crate) unsafe fn c_str<'a>(p: *const c_char) -> Option<&'a CStr> {
    if p.is_null() {
        None
    } else {
        // SAFETY: the caller's guarantee.
        Some(unsafe { CStr::from_ptr(p) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_converted_and_merged_as_dlfcn_does() {
        let mut d = Dso::default();
        let ext = core::str::from_utf8(EXTENSION).unwrap_or_default();
        assert_eq!(
            d.convert_filename(Some(c"foo"))
                .unwrap_or_default()
                .to_bytes(),
            format!("libfoo{ext}").as_bytes()
        );
        d.set_flags(DSO_FLAG_NAME_TRANSLATION_EXT_ONLY);
        assert_eq!(
            d.convert_filename(Some(c"foo"))
                .unwrap_or_default()
                .to_bytes(),
            format!("foo{ext}").as_bytes()
        );
        assert_eq!(
            d.convert_filename(Some(c"a/b"))
                .unwrap_or_default()
                .to_bytes(),
            b"a/b"
        );
        assert_eq!(
            d.merge(c"x.so", c"/dir/").unwrap_or_default().to_bytes(),
            b"/dir/x.so"
        );
        assert_eq!(
            d.merge(c"x.so", c"/dir").unwrap_or_default().to_bytes(),
            b"/dir/x.so"
        );
        assert_eq!(
            d.merge(c"/abs.so", c"/dir").unwrap_or_default().to_bytes(),
            b"/abs.so"
        );
    }
}
