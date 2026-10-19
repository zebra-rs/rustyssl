//! Shared objects (`internal/dso.h`, `crypto/dso/dso_lib.c` with the Unix method in
//! `dso_dlfcn.c`), which libcrypto exports although no public header declares them.
//!
//! A DSO holds a file name, the name it was loaded under, flags, and the `dlopen` handles it
//! opened. There is one method, the platform's (`DSO_METHOD_openssl`); `DSO_load` ignores the
//! one it's given, as OpenSSL's does. Names are translated as `dlfcn_name_converter` does: a
//! name without a slash becomes `lib<name><extension>` (`<name><extension>` with
//! `DSO_FLAG_NAME_TRANSLATION_EXT_ONLY`), unless `DSO_FLAG_NO_NAME_TRANSLATION`. The last
//! reference closes the handles, unless `DSO_FLAG_NO_UNLOAD_ON_FREE`.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};
use std::ffi::CString;
use std::sync::{Mutex, PoisonError};

use rustyssl_abi::{
    DSO, DSO_CTRL_GET_FLAGS, DSO_CTRL_OR_FLAGS, DSO_CTRL_SET_FLAGS, DSO_FLAG_GLOBAL_SYMBOLS,
    DSO_FLAG_NAME_TRANSLATION_EXT_ONLY, DSO_FLAG_NO_NAME_TRANSLATION, DSO_FLAG_NO_UNLOAD_ON_FREE,
    DSO_FUNC_TYPE, DSO_METHOD, DSO_R_CTRL_FAILED, DSO_R_DSO_ALREADY_LOADED, DSO_R_LOAD_FAILED,
    DSO_R_NO_FILENAME, DSO_R_SET_FILENAME_FAILED, DSO_R_STACK_ERROR, DSO_R_SYM_FAILURE,
    DSO_R_UNSUPPORTED, ERR_LIB_DSO, ERR_R_DSO_LIB, ERR_R_PASSED_NULL_PARAMETER, build,
};

use crate::err;
use crate::errno;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::objects::c_string;

/// A `dlopen` handle.
struct Library(*mut c_void);

// SAFETY: a handle from the dynamic loader, which may be used and closed from any thread.
unsafe impl Send for Library {}

/// What a `DSO` points to.
pub(crate) struct Dso {
    flags: AtomicI32,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// `DSO_set_filename`'s name.
    filename: Option<CString>,
    /// The name it was loaded under (after translation).
    loaded_filename: Option<CString>,
    /// The handles it opened (`meth_data`), the newest last.
    handles: Vec<Library>,
}

impl Dso {
    fn new() -> Self {
        Self {
            flags: AtomicI32::new(0),
            state: Mutex::new(State::default()),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn flags(&self) -> c_int {
        self.flags.load(Ordering::Relaxed)
    }
}

impl Drop for Dso {
    fn drop(&mut self) {
        if self.flags() & DSO_FLAG_NO_UNLOAD_ON_FREE != 0 {
            return;
        }
        let state = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
        // `dlfcn_unload` closes the newest; OpenSSL's free unloads once. The rest are left
        // open as OpenSSL leaves them.
        if let Some(Library(h)) = state.handles.pop() {
            // SAFETY: a handle this DSO opened, closed once.
            unsafe { libc::dlclose(h) };
        }
    }
}

handle_type!(DSO => Dso);

fn raise(reason: c_int, function: &str) {
    err::raise(ERR_LIB_DSO, reason, function);
}

/// The system's last dynamic-loading error, copied.
fn dlerror() -> Vec<u8> {
    // SAFETY: no preconditions.
    let e: *const c_char = unsafe { libc::dlerror() };
    if e.is_null() {
        return Vec::new();
    }
    // SAFETY: a string from the loader, copied at once.
    unsafe { CStr::from_ptr(e) }.to_bytes().to_vec()
}

/// `dlfcn_name_converter`.
fn converted(name: &[u8], flags: c_int) -> Vec<u8> {
    if name.contains(&b'/') {
        return name.to_vec();
    }
    let mut out = Vec::new();
    if flags & DSO_FLAG_NAME_TRANSLATION_EXT_ONLY == 0 {
        out.extend_from_slice(b"lib");
    }
    out.extend_from_slice(name);
    out.extend_from_slice(build::DSO_EXTENSION.to_bytes());
    out
}

/// `DSO_convert_filename`'s work: `name` translated unless the flags say not to.
fn convert(name: &[u8], flags: c_int) -> Vec<u8> {
    if flags & DSO_FLAG_NO_NAME_TRANSLATION == 0 {
        converted(name, flags)
    } else {
        name.to_vec()
    }
}

/// `dlfcn_merger`: `spec1` when it's absolute or `spec2` is absent, else `spec2/spec1` (one
/// trailing slash of `spec2` dropped).
fn merged(spec1: &[u8], spec2: Option<&[u8]>) -> Vec<u8> {
    match spec2 {
        Some(dir) if spec1.first() != Some(&b'/') => {
            let dir = dir.strip_suffix(b"/").unwrap_or(dir);
            let mut out = dir.to_vec();
            out.push(b'/');
            out.extend_from_slice(spec1);
            out
        }
        _ => spec1.to_vec(),
    }
}

/// The string at `s`, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a NUL-terminated string.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) }.to_bytes())
}

/// The platform's method: a static object whose address is all that's ever used.
static METHOD: u8 = 0;

ffi_export! {
    /// The platform's DSO method (`dlfcn` on Unix).
    ///
    /// # Safety
    /// None.
    pub unsafe extern "C" fn DSO_METHOD_openssl() -> *mut DSO_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_DSO
    {
        ptr::from_ref(&METHOD).cast_mut().cast()
    }
}

ffi_export! {
    /// A new DSO with one reference, no name and no flags, or NULL.
    ///
    /// # Safety
    /// None.
    pub unsafe extern "C" fn DSO_new() -> *mut DSO
    where failure = ptr::null_mut(), library = ERR_LIB_DSO
    {
        DSO::new_handle(Dso::new())
    }
}

ffi_export! {
    /// Drops a reference; the last one unloads the library (unless
    /// `DSO_FLAG_NO_UNLOAD_ON_FREE`). 1 (also for NULL).
    ///
    /// # Safety
    /// `dso` is NULL or a live DSO whose reference the caller gives up.
    pub unsafe extern "C" fn DSO_free(dso: *mut DSO) -> c_int
    where failure = 0, library = ERR_LIB_DSO
    {
        // SAFETY: the caller's guarantee.
        unsafe { DSO::free(dso) };
        1
    }
}

ffi_export! {
    /// The DSO's flags, 0 for NULL.
    ///
    /// # Safety
    /// `dso` is NULL or a live DSO.
    pub unsafe extern "C" fn DSO_flags(dso: *mut DSO) -> c_int
    where failure = 0, library = ERR_LIB_DSO
    {
        // SAFETY: the caller's guarantee.
        unsafe { DSO::get(dso) }.map_or(0, Dso::flags)
    }
}

ffi_export! {
    /// Adds a reference. 1, or 0 (NULL).
    ///
    /// # Safety
    /// `dso` is NULL or a live DSO.
    pub unsafe extern "C" fn DSO_up_ref(dso: *mut DSO) -> c_int
    where failure = 0, library = ERR_LIB_DSO
    {
        // SAFETY: the caller's guarantee.
        if unsafe { DSO::up_ref(dso) } {
            1
        } else {
            raise(ERR_R_PASSED_NULL_PARAMETER, "DSO_up_ref");
            0
        }
    }
}

ffi_export! {
    /// The flag controls (`DSO_CTRL_GET_FLAGS` gives them, `_SET_FLAGS` and `_OR_FLAGS` 0);
    /// anything else is unsupported (-1), as the method has no controls of its own.
    ///
    /// # Safety
    /// `dso` is NULL or a live DSO.
    pub unsafe extern "C" fn DSO_ctrl(dso: *mut DSO, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long
    where failure = -1, library = ERR_LIB_DSO
    {
        let _ = parg;
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { DSO::get(dso) }) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, "DSO_ctrl");
            return -1;
        };
        // OpenSSL keeps the low `int` of the argument.
        #[expect(clippy::cast_possible_truncation, reason = "OpenSSL's (int)larg")]
        let value = larg as c_int;
        match cmd {
            DSO_CTRL_GET_FLAGS => c_long::from(d.flags()),
            DSO_CTRL_SET_FLAGS => {
                d.flags.store(value, Ordering::Relaxed);
                0
            }
            DSO_CTRL_OR_FLAGS => {
                d.flags.fetch_or(value, Ordering::Relaxed);
                0
            }
            _ => {
                raise(DSO_R_UNSUPPORTED, "DSO_ctrl");
                -1
            }
        }
    }
}

ffi_export! {
    /// The DSO's file name, or NULL. Valid until it's set again or the DSO is freed.
    ///
    /// # Safety
    /// `dso` is NULL or a live DSO.
    pub unsafe extern "C" fn DSO_get_filename(dso: *mut DSO) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_DSO
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { DSO::get(dso) }) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, "DSO_get_filename");
            return ptr::null();
        };
        d.state().filename.as_ref().map_or(ptr::null(), |f| f.as_ptr())
    }
}

/// `DSO_set_filename`'s work, raising its errors.
fn set_filename(d: &Dso, filename: Option<&[u8]>) -> bool {
    const F: &str = "DSO_set_filename";
    let Some(filename) = filename else {
        raise(ERR_R_PASSED_NULL_PARAMETER, F);
        return false;
    };
    let mut st = d.state();
    if st.loaded_filename.is_some() {
        raise(DSO_R_DSO_ALREADY_LOADED, F);
        return false;
    }
    let Ok(name) = CString::new(filename) else {
        return false;
    };
    st.filename = Some(name);
    true
}

ffi_export! {
    /// Sets the file name to load. 1, or 0 (NULL arguments, or already loaded).
    ///
    /// # Safety
    /// `dso` is NULL or a live DSO; `filename` is NULL or a NUL-terminated string.
    pub unsafe extern "C" fn DSO_set_filename(dso: *mut DSO, filename: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_DSO
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { DSO::get(dso) }) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, "DSO_set_filename");
            return 0;
        };
        // SAFETY: as above.
        c_int::from(set_filename(d, unsafe { text(filename) }))
    }
}

ffi_export! {
    /// `filename` (or the DSO's own) as the platform names its libraries, a new string the
    /// caller frees, or NULL.
    ///
    /// # Safety
    /// `dso` is NULL or a live DSO; `filename` is NULL or a NUL-terminated string.
    pub unsafe extern "C" fn DSO_convert_filename(dso: *mut DSO, filename: *const c_char) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_DSO
    {
        const F: &str = "DSO_convert_filename";
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { DSO::get(dso) }) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, F);
            return ptr::null_mut();
        };
        // SAFETY: as above.
        let name = match unsafe { text(filename) } {
            Some(n) => n.to_vec(),
            None => match &d.state().filename {
                Some(f) => f.to_bytes().to_vec(),
                None => {
                    raise(DSO_R_NO_FILENAME, F);
                    return ptr::null_mut();
                }
            },
        };
        c_string(&convert(&name, d.flags()))
    }
}

ffi_export! {
    /// `filespec1` merged with the directory `filespec2` (unless `DSO_FLAG_NO_NAME_TRANSLATION`,
    /// which gives NULL), a new string the caller frees, or NULL.
    ///
    /// # Safety
    /// `dso` is NULL or a live DSO; the specs are NULL or NUL-terminated strings.
    pub unsafe extern "C" fn DSO_merge(dso: *mut DSO, filespec1: *const c_char, filespec2: *const c_char) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_DSO
    {
        // SAFETY: the caller's guarantee.
        let d = unsafe { DSO::get(dso) };
        // SAFETY: as above.
        let (Some(d), Some(spec1)) = (d, unsafe { text(filespec1) }) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, "DSO_merge");
            return ptr::null_mut();
        };
        if d.flags() & DSO_FLAG_NO_NAME_TRANSLATION != 0 {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        c_string(&merged(spec1, unsafe { text(filespec2) }))
    }
}

/// `dlfcn_load`: opens the DSO's file under its translated name. Raises its errors.
fn dlfcn_load(d: &Dso) -> bool {
    const F: &str = "dlfcn_load";
    let flags = d.flags();
    let Some(name) = d.state().filename.as_ref().map(|f| f.to_bytes().to_vec()) else {
        raise(DSO_R_NO_FILENAME, F);
        return false;
    };
    let Ok(path) = CString::new(convert(&name, flags)) else {
        raise(DSO_R_NO_FILENAME, F);
        return false;
    };
    let mut mode = libc::RTLD_NOW;
    if flags & DSO_FLAG_GLOBAL_SYMBOLS != 0 {
        mode |= libc::RTLD_GLOBAL;
    }
    let saved = errno::get();
    // SAFETY: a NUL-terminated path.
    let h = unsafe { libc::dlopen(path.as_ptr(), mode) };
    if h.is_null() {
        let mut data = b"filename(".to_vec();
        data.extend_from_slice(path.to_bytes());
        data.extend_from_slice(b"): ");
        data.extend_from_slice(&dlerror());
        err::raise_with_bytes(ERR_LIB_DSO, DSO_R_LOAD_FAILED, F, &data);
        return false;
    }
    errno::set(saved);
    let mut st = d.state();
    st.handles.push(Library(h));
    st.loaded_filename = Some(path);
    true
}

ffi_export! {
    /// Loads `filename` (as translated) into `dso`, or into a new DSO with `flags` when `dso`
    /// is NULL. The DSO, or NULL. A DSO that already has a name can't load again, even with
    /// a NULL `filename` (OpenSSL's `DSO_R_DSO_ALREADY_LOADED`). `meth` is ignored.
    ///
    /// # Safety
    /// `dso` is NULL or a live DSO; `filename` is NULL or a NUL-terminated string.
    pub unsafe extern "C" fn DSO_load(dso: *mut DSO, filename: *const c_char, meth: *mut DSO_METHOD, flags: c_int) -> *mut DSO
    where failure = ptr::null_mut(), library = ERR_LIB_DSO
    {
        const F: &str = "DSO_load";
        let _ = meth;
        let (ret, allocated) = if dso.is_null() {
            let n = DSO::new_handle(Dso::new());
            // SAFETY: the DSO just made.
            if unsafe { DSO_ctrl(n, DSO_CTRL_SET_FLAGS, c_long::from(flags), ptr::null_mut()) } < 0 {
                raise(DSO_R_CTRL_FAILED, F);
                // SAFETY: as above, released once.
                unsafe { DSO::free(n) };
                return ptr::null_mut();
            }
            (n, true)
        } else {
            (dso, false)
        };
        let fail = |reason: c_int| {
            raise(reason, F);
            if allocated {
                // SAFETY: the DSO made here, released once.
                unsafe { DSO::free(ret) };
            }
            ptr::null_mut()
        };
        // SAFETY: the caller's DSO, or the one made here.
        let Some(d) = (unsafe { DSO::get(ret) }) else {
            raise(ERR_R_DSO_LIB, F);
            return ptr::null_mut();
        };
        if d.state().filename.is_some() {
            return fail(DSO_R_DSO_ALREADY_LOADED);
        }
        // SAFETY: the caller's guarantee.
        if let Some(name) = unsafe { text(filename) }
            && !set_filename(d, Some(name))
        {
            return fail(DSO_R_SET_FILENAME_FAILED);
        }
        if d.state().filename.is_none() {
            return fail(DSO_R_NO_FILENAME);
        }
        if !dlfcn_load(d) {
            return fail(DSO_R_LOAD_FAILED);
        }
        ret
    }
}

ffi_export! {
    /// The function `symname` in the DSO's newest library, or NULL.
    ///
    /// # Safety
    /// `dso` is NULL or a live DSO; `symname` is NULL or a NUL-terminated string.
    pub unsafe extern "C" fn DSO_bind_func(dso: *mut DSO, symname: *const c_char) -> DSO_FUNC_TYPE
    where failure = None, library = ERR_LIB_DSO
    {
        const F: &str = "DSO_bind_func";
        const INNER: &str = "dlfcn_bind_func";
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { DSO::get(dso) }).filter(|_| !symname.is_null()) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, F);
            return None;
        };
        let handle = d.state().handles.last().map(|l| l.0);
        let Some(h) = handle else {
            raise(DSO_R_STACK_ERROR, INNER);
            raise(DSO_R_SYM_FAILURE, F);
            return None;
        };
        // SAFETY: the DSO's open handle; the caller's NUL-terminated name.
        let sym = unsafe { libc::dlsym(h, symname) };
        if sym.is_null() {
            let mut data = b"symname(".to_vec();
            // SAFETY: as above.
            data.extend_from_slice(unsafe { CStr::from_ptr(symname) }.to_bytes());
            data.extend_from_slice(b"): ");
            data.extend_from_slice(&dlerror());
            err::raise_with_bytes(ERR_LIB_DSO, DSO_R_SYM_FAILURE, INNER, &data);
            raise(DSO_R_SYM_FAILURE, F);
            return None;
        }
        // SAFETY: a non-NULL symbol from the loader, handed out as OpenSSL hands it out (a
        // function pointer the caller casts to the symbol's real type).
        Some(unsafe { core::mem::transmute::<*mut c_void, unsafe extern "C" fn()>(sym) })
    }
}

/// `dlfcn_pathbyaddr`'s own address, which a NULL `addr` stands for (this library's path).
fn self_address() -> *mut c_void {
    let f: unsafe extern "C" fn(*mut c_void, *mut c_char, c_int) -> c_int = DSO_pathbyaddr;
    f as *mut c_void
}

ffi_export! {
    /// The path of the shared object holding `addr` (this library for NULL) into `path`
    /// (truncated to `sz`, NUL-terminated), returning the octets written with the NUL, or for
    /// `sz` <= 0 the room it needs. -1 if no object holds it.
    ///
    /// # Safety
    /// `path` has room for `sz` octets when `sz` > 0.
    pub unsafe extern "C" fn DSO_pathbyaddr(addr: *mut c_void, path: *mut c_char, sz: c_int) -> c_int
    where failure = -1, library = ERR_LIB_DSO
    {
        let addr = if addr.is_null() { self_address() } else { addr };
        let mut info = core::mem::MaybeUninit::<libc::Dl_info>::zeroed();
        // SAFETY: any address may be asked about; the info is written on success.
        if unsafe { libc::dladdr(addr.cast_const(), info.as_mut_ptr()) } == 0 {
            let e = dlerror();
            err::add_error_data([Some(&b"dlfcn_pathbyaddr(): "[..]), Some(&e[..])]);
            return -1;
        }
        // SAFETY: filled by `dladdr`, which succeeded.
        let info = unsafe { info.assume_init() };
        if info.dli_fname.is_null() {
            return -1;
        }
        // SAFETY: the loader's NUL-terminated name.
        let name = unsafe { CStr::from_ptr(info.dli_fname) }.to_bytes();
        let Ok(len) = c_int::try_from(name.len()) else { return -1 };
        if sz <= 0 {
            return len.saturating_add(1);
        }
        let n = len.min(sz.saturating_sub(1));
        let Ok(count) = usize::try_from(n) else { return -1 };
        // SAFETY: the caller's room for `sz` octets, of which `n` + 1 are written.
        unsafe { ptr::copy_nonoverlapping(name.as_ptr(), path.cast::<u8>(), count) };
        // SAFETY: as above, the last of them.
        unsafe { path.wrapping_add(count).write(0) };
        n.saturating_add(1)
    }
}

ffi_export! {
    /// A DSO loaded from the shared object holding `addr` (this library for NULL), with
    /// `flags`, or NULL.
    ///
    /// # Safety
    /// None beyond `DSO_pathbyaddr`'s.
    pub unsafe extern "C" fn DSO_dsobyaddr(addr: *mut c_void, flags: c_int) -> *mut DSO
    where failure = ptr::null_mut(), library = ERR_LIB_DSO
    {
        // SAFETY: a size query, writing nothing.
        let len = unsafe { DSO_pathbyaddr(addr, ptr::null_mut(), 0) };
        let Ok(size) = usize::try_from(len) else { return ptr::null_mut() };
        let mut buf = vec![0u8; size.max(1)];
        // SAFETY: room for `len` octets.
        if unsafe { DSO_pathbyaddr(addr, buf.as_mut_ptr().cast(), len) } != len {
            return ptr::null_mut();
        }
        // SAFETY: a NUL-terminated path.
        unsafe { DSO_load(ptr::null_mut(), buf.as_ptr().cast(), ptr::null_mut(), flags) }
    }
}

ffi_export! {
    /// The address of the global symbol `name` in the program and its libraries, or NULL.
    ///
    /// # Safety
    /// `name` is NULL or a NUL-terminated string.
    pub unsafe extern "C" fn DSO_global_lookup(name: *const c_char) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_DSO
    {
        if name.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the program itself, lazily.
        let h = unsafe { libc::dlopen(ptr::null(), libc::RTLD_LAZY) };
        if h.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the handle; the caller's name.
        let ret = unsafe { libc::dlsym(h, name) };
        // SAFETY: the handle opened above.
        unsafe { libc::dlclose(h) };
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_translated_as_dlfcn_does() {
        let ext = build::DSO_EXTENSION.to_str().unwrap();
        assert_eq!(converted(b"foo", 0), format!("libfoo{ext}").into_bytes());
        let ext_only = DSO_FLAG_NAME_TRANSLATION_EXT_ONLY;
        assert_eq!(
            converted(b"foo", ext_only),
            format!("foo{ext}").into_bytes()
        );
        assert_eq!(converted(b"./foo", 0), b"./foo");
        assert_eq!(convert(b"foo", DSO_FLAG_NO_NAME_TRANSLATION), b"foo");
    }

    #[test]
    fn merging_joins_relative_names() {
        assert_eq!(merged(b"foo.so", Some(b"/usr/lib")), b"/usr/lib/foo.so");
        assert_eq!(merged(b"foo.so", Some(b"/usr/lib/")), b"/usr/lib/foo.so");
        assert_eq!(merged(b"foo.so", Some(b"/usr/lib//")), b"/usr/lib//foo.so");
        assert_eq!(merged(b"/abs/foo.so", Some(b"/usr/lib")), b"/abs/foo.so");
        assert_eq!(merged(b"foo.so", None), b"foo.so");
        assert_eq!(merged(b"foo.so", Some(b"")), b"/foo.so");
    }
}
