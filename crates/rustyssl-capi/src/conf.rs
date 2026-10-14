//! Configuration files (`NCONF_new(3)`, config(5); `conf_lib.c`, `conf_api.c`, `conf_def.c`):
//! a `CONF` holds what a file sets as OpenSSL keeps it, in public structures applications
//! read: a hash table of `CONF_VALUE`s, one per value and one per section, whose value is
//! the section's stack of its values in order. The methods (`NCONF_default`, `NCONF_WIN32`,
//! or an application's) are tables of functions that every `NCONF_*` call goes through; the
//! default ones read files with `rustyssl_conf`'s parser ([`load`]). The classic `CONF_*`
//! functions work on a bare hash table through a temporary `CONF`.
//!
//! Where OpenSSL's `NCONF_free_data` leaves the freed table and include directory in the
//! `CONF` (so any later use, `NCONF_free` too, reads freed memory), here it clears them
//! (docs/DEVIATIONS.md).

pub(crate) mod builtin;
mod load;
pub(crate) mod modules;

use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use libc::FILE;
use rustyssl_abi::{
    BIO, BIO_NOCLOSE, CONF, CONF_METHOD, CONF_R_LIST_CANNOT_BE_NULL, CONF_R_NO_CONF,
    CONF_R_NO_CONF_OR_ENVIRONMENT_VARIABLE, CONF_R_NO_SECTION, CONF_R_NO_VALUE,
    CONF_R_NUMBER_TOO_LARGE, CONF_VALUE, ERR_LIB_CONF, ERR_R_BUF_LIB, ERR_R_CONF_LIB,
    ERR_R_PASSED_NULL_PARAMETER, ERR_R_SYS_LIB, OPENSSL_LHASH, OPENSSL_STACK, OSSL_LIB_CTX,
    lhash_st_CONF_VALUE, stack_st_CONF_VALUE, stack_st_OPENSSL_CSTRING,
};
use rustyssl_conf::classes;

use crate::bio::BIO_free;
use crate::bio::file::{BIO_new_file, BIO_new_fp};
use crate::err;
use crate::ffi::ffi_export;
use crate::lhash::{
    OPENSSL_LH_free, OPENSSL_LH_insert, OPENSSL_LH_new, OPENSSL_LH_retrieve, OPENSSL_LH_strhash,
};
use crate::mem;
use crate::stack::{
    OPENSSL_sk_delete_ptr, OPENSSL_sk_free, OPENSSL_sk_new, OPENSSL_sk_new_null, OPENSSL_sk_num,
    OPENSSL_sk_push, OPENSSL_sk_sort, OPENSSL_sk_value,
};

/// A method table applications may write to through the pointer they're given, as they may
/// to OpenSSL's static ones.
#[repr(transparent)]
struct Method(UnsafeCell<CONF_METHOD>);

// SAFETY: OpenSSL's methods are plain static data; changes are the application's to order.
unsafe impl Sync for Method {}

/// A method's character classes, at a stable address for `meth_data`.
#[repr(transparent)]
struct Classes([u16; 128]);

static DEFAULT_CLASSES: Classes = Classes(classes::DEFAULT);
static WIN32_CLASSES: Classes = Classes(classes::WIN32);

static DEFAULT_METHOD: Method = Method(UnsafeCell::new(CONF_METHOD {
    name: c"OpenSSL default".as_ptr(),
    create: Some(def_create),
    init: Some(def_init_default),
    destroy: Some(def_destroy),
    destroy_data: Some(def_destroy_data),
    load_bio: Some(load::def_load_bio),
    dump: Some(def_dump),
    is_number: Some(def_is_number),
    to_int: Some(def_to_int),
    load: Some(load::def_load),
}));

static WIN32_METHOD: Method = Method(UnsafeCell::new(CONF_METHOD {
    name: c"WIN32".as_ptr(),
    create: Some(def_create),
    init: Some(def_init_win32),
    destroy: Some(def_destroy),
    destroy_data: Some(def_destroy_data),
    load_bio: Some(load::def_load_bio),
    dump: Some(def_dump),
    is_number: Some(def_is_number),
    to_int: Some(def_to_int),
    load: Some(load::def_load),
}));

/// The method `CONF_set_nconf` gives the classic functions' temporary configurations
/// (`CONF_set_default_method`); null until first used, then the default one.
static CLASSIC_METHOD: AtomicPtr<CONF_METHOD> = AtomicPtr::new(ptr::null_mut());

fn default_method() -> *mut CONF_METHOD {
    DEFAULT_METHOD.0.get()
}

/// A C string of `bytes` (up to any NUL) from `CRYPTO_malloc`, or null.
pub(crate) fn c_dup(bytes: &[u8]) -> *mut c_char {
    let bytes = bytes.split(|&c| c == 0).next().unwrap_or_default();
    let Some(size) = bytes.len().checked_add(1) else {
        return ptr::null_mut();
    };
    let p = mem::alloc(size).cast::<u8>();
    if !p.is_null() {
        // SAFETY: a new allocation of `size` octets.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len()) };
        // SAFETY: as above, its last octet.
        let end = unsafe { p.add(bytes.len()) };
        // SAFETY: as above.
        unsafe { end.write(0) };
    }
    p.cast()
}

/// The bytes of a C string, or `None` for null.
///
/// # Safety
/// `s` is null or a NUL-terminated string that outlives the result.
unsafe fn bytes<'a>(s: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) }.to_bytes())
}

/// `strcmp`'s sign: the C strings compared as unsigned octets.
///
/// # Safety
/// `a` and `b` are C strings.
unsafe fn strcmp(a: *const c_char, b: *const c_char) -> c_int {
    // SAFETY: the caller's guarantee.
    let a = unsafe { CStr::from_ptr(a) };
    // SAFETY: as above.
    let b = unsafe { CStr::from_ptr(b) };
    match a.to_bytes().cmp(b.to_bytes()) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// The configuration's table as the generic hash table type.
fn table(conf: &CONF) -> *mut OPENSSL_LHASH {
    conf.data.cast()
}

// --- The data (`conf_api.c`) ---

/// `conf_value_hash`: the section's string hash, shifted, with the name's.
unsafe extern "C" fn conf_value_hash(v: *const c_void) -> core::ffi::c_ulong {
    // SAFETY: the table holds CONF_VALUEs.
    let Some(v) = (unsafe { v.cast::<CONF_VALUE>().as_ref() }) else {
        return 0;
    };
    // SAFETY: C strings or null.
    let section = unsafe { OPENSSL_LH_strhash(v.section) };
    // SAFETY: as above.
    let name = unsafe { OPENSSL_LH_strhash(v.name) };
    (section << 2) ^ name
}

/// `conf_value_cmp`: by section, then name (a section's entry, with no name, first).
unsafe extern "C" fn conf_value_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the table holds CONF_VALUEs.
    let (Some(a), Some(b)) = (unsafe { a.cast::<CONF_VALUE>().as_ref() }, unsafe {
        b.cast::<CONF_VALUE>().as_ref()
    }) else {
        return 0;
    };
    if a.section != b.section {
        // SAFETY: C strings.
        let i = unsafe { strcmp(a.section, b.section) };
        if i != 0 {
            return i;
        }
    }
    if !a.name.is_null() && !b.name.is_null() {
        // SAFETY: as above.
        return unsafe { strcmp(a.name, b.name) };
    }
    if a.name == b.name {
        return 0;
    }
    if a.name.is_null() { -1 } else { 1 }
}

/// `_CONF_new_data`: the configuration's table, made if it has none. False on failure.
fn new_data(conf: &mut CONF) -> bool {
    if conf.data.is_null() {
        // SAFETY: the table's functions take its CONF_VALUEs.
        conf.data = unsafe { OPENSSL_LH_new(Some(conf_value_hash), Some(conf_value_cmp)) }.cast();
    }
    !conf.data.is_null()
}

/// `_CONF_get_section`: the section's entry, or null.
///
/// # Safety
/// `section` is null or a C string.
unsafe fn get_section(conf: &CONF, section: *const c_char) -> *mut CONF_VALUE {
    if section.is_null() || conf.data.is_null() {
        return ptr::null_mut();
    }
    let key = CONF_VALUE {
        section: section.cast_mut(),
        name: ptr::null_mut(),
        value: ptr::null_mut(),
    };
    // SAFETY: the configuration's table, and a key of its type.
    unsafe { OPENSSL_LH_retrieve(table(conf), (&raw const key).cast()) }.cast()
}

/// `_CONF_get_section_values`: the section's stack of values, or null.
///
/// # Safety
/// As for [`get_section`].
unsafe fn section_values(conf: &CONF, section: *const c_char) -> *mut stack_st_CONF_VALUE {
    // SAFETY: the caller's guarantee.
    let v = unsafe { get_section(conf, section) };
    // SAFETY: an entry of the table, or null.
    unsafe { v.as_ref() }.map_or(ptr::null_mut(), |v| v.value.cast())
}

/// `_CONF_new_section`: a new, empty section, added to the table; null if it can't be (or the
/// table already had one of the name, which the new one then replaces in it, as in
/// OpenSSL; the old one stays with the values that were in it).
///
/// # Safety
/// `section` is a C string.
unsafe fn new_section(conf: &mut CONF, section: &[u8]) -> *mut CONF_VALUE {
    // SAFETY: no preconditions.
    let sk = unsafe { OPENSSL_sk_new_null() };
    let v = mem::alloc(size_of::<CONF_VALUE>()).cast::<CONF_VALUE>();
    let name = c_dup(section);
    if sk.is_null() || v.is_null() || name.is_null() {
        // SAFETY: what was made here.
        unsafe { OPENSSL_sk_free(sk) };
        // SAFETY: as above.
        unsafe { mem::release(v.cast()) };
        // SAFETY: as above.
        unsafe { mem::release(name.cast()) };
        return ptr::null_mut();
    }
    // SAFETY: a new allocation of a CONF_VALUE.
    unsafe {
        v.write(CONF_VALUE {
            section: name,
            name: ptr::null_mut(),
            value: sk.cast(),
        });
    };
    // SAFETY: the configuration's table, and a new entry of its type.
    let old = unsafe { OPENSSL_LH_insert(table(conf), v.cast()) };
    // SAFETY: as above.
    let failed = unsafe { crate::lhash::OPENSSL_LH_error(table(conf)) } > 0;
    if !old.is_null() || failed {
        if !old.is_null() {
            // OpenSSL frees the new section while the table holds it; here the old one goes
            // back, so the table never holds freed memory.
            // SAFETY: as above.
            unsafe { OPENSSL_LH_insert(table(conf), old) };
        }
        // SAFETY: what was made here, no longer in the table.
        unsafe { OPENSSL_sk_free(sk) };
        // SAFETY: as above.
        unsafe { mem::release(name.cast()) };
        // SAFETY: as above.
        unsafe { mem::release(v.cast()) };
        return ptr::null_mut();
    }
    v
}

/// `_CONF_add_string`: `value` (allocated with its name and value) appended to the section's
/// stack and put in the table, replacing (and freeing) any value of the same name there.
///
/// # Safety
/// `section` is a section entry of the configuration; `value` a new entry it takes.
unsafe fn add_string(conf: &mut CONF, section: *mut CONF_VALUE, value: *mut CONF_VALUE) -> bool {
    // SAFETY: the caller's guarantee.
    let (Some(s), Some(v)) = (unsafe { section.as_ref() }, unsafe { value.as_mut() }) else {
        return false;
    };
    let ts = s.value.cast::<OPENSSL_STACK>();
    v.section = s.section;
    // SAFETY: the section's stack, and its new value.
    if unsafe { OPENSSL_sk_push(ts, value.cast()) } == 0 {
        return false;
    }
    // SAFETY: the configuration's table, and an entry of its type.
    let old = unsafe { OPENSSL_LH_insert(table(conf), value.cast()) }.cast::<CONF_VALUE>();
    if !old.is_null() {
        // SAFETY: the section's stack.
        unsafe { OPENSSL_sk_delete_ptr(ts, old.cast()) };
        // SAFETY: the replaced value, no longer held by the table or the stack.
        unsafe { free_value(old) };
    }
    true
}

/// Frees a value entry: its name, value, and itself.
///
/// # Safety
/// `v` is null or a value entry nothing holds any more.
unsafe fn free_value(v: *mut CONF_VALUE) {
    // SAFETY: the caller's guarantee.
    if let Some(e) = unsafe { v.as_ref() } {
        // SAFETY: the entry's strings.
        unsafe { mem::release(e.name.cast()) };
        // SAFETY: as above.
        unsafe { mem::release(e.value.cast()) };
    }
    // SAFETY: the caller's guarantee.
    unsafe { mem::release(v.cast()) };
}

/// `_CONF_get_string`: the value of `name` in `section`, else (unless found in the
/// environment for `ENV`) in `default`; with no configuration, the environment's. The pointer
/// is the table's (or the environment's).
///
/// # Safety
/// `conf` is null or a live configuration; `section` and `name` null or C strings.
pub(crate) unsafe fn get_string(
    conf: *const CONF,
    section: *const c_char,
    name: *const c_char,
) -> *const c_char {
    if name.is_null() {
        return ptr::null();
    }
    // SAFETY: the caller's guarantee.
    let Some(conf) = (unsafe { conf.as_ref() }) else {
        // SAFETY: as above.
        return crate::init::safe_getenv_ptr(unsafe { CStr::from_ptr(name) });
    };
    if conf.data.is_null() {
        return ptr::null();
    }
    let lookup = |section: *const c_char| {
        let key = CONF_VALUE {
            section: section.cast_mut(),
            name: name.cast_mut(),
            value: ptr::null_mut(),
        };
        // SAFETY: the configuration's table, and a key of its type.
        let v = unsafe { OPENSSL_LH_retrieve(table(conf), (&raw const key).cast()) };
        // SAFETY: an entry of the table, or null.
        unsafe { v.cast::<CONF_VALUE>().as_ref() }.map(|v| v.value.cast_const())
    };
    if !section.is_null() {
        if let Some(v) = lookup(section) {
            return v;
        }
        // SAFETY: the caller's C string.
        if unsafe { CStr::from_ptr(section) } == c"ENV" {
            // SAFETY: as above.
            let p = crate::init::safe_getenv_ptr(unsafe { CStr::from_ptr(name) });
            if !p.is_null() {
                return p;
            }
        }
    }
    lookup(c"default".as_ptr()).unwrap_or(ptr::null())
}

/// `_CONF_free_data`: the include directory, the table, and every section and value in it.
/// Both are cleared afterwards (OpenSSL leaves them dangling).
fn free_data(conf: &mut CONF) {
    // SAFETY: the configuration's own string.
    unsafe { mem::release(conf.includedir.cast()) };
    conf.includedir = ptr::null_mut();
    if conf.data.is_null() {
        return;
    }
    // The sections, picked out before anything is freed: values are freed through them.
    // SAFETY: the configuration's table, and its entries.
    let sections: Vec<*mut CONF_VALUE> = unsafe { crate::lhash::items(table(conf)) }
        .into_iter()
        .map(|item| item.cast::<CONF_VALUE>())
        .filter(|v| {
            // SAFETY: an entry of the table, not yet freed.
            unsafe { v.as_ref() }.is_some_and(|e| e.name.is_null())
        })
        .collect();
    for v in sections {
        // SAFETY: a section entry of the table.
        let Some(e) = (unsafe { v.as_ref() }) else {
            continue;
        };
        let sk = e.value.cast::<OPENSSL_STACK>();
        // SAFETY: the section's stack.
        let n = unsafe { OPENSSL_sk_num(sk) };
        for i in (0..n).rev() {
            // SAFETY: as above.
            let vv = unsafe { OPENSSL_sk_value(sk, i) }.cast::<CONF_VALUE>();
            // SAFETY: a value of the section, freed once.
            unsafe { free_value(vv) };
        }
        // SAFETY: the section's stack and name, and the entry.
        unsafe { OPENSSL_sk_free(sk) };
        // SAFETY: as above.
        unsafe { mem::release(e.section.cast()) };
        // SAFETY: as above.
        unsafe { mem::release(v.cast()) };
    }
    // SAFETY: the table, its entries freed.
    unsafe { OPENSSL_LH_free(table(conf)) };
    conf.data = ptr::null_mut();
}

// --- The default methods (`conf_def.c`) ---

/// The configuration behind `conf`.
///
/// # Safety
/// `conf` is null or a live configuration, not used elsewhere meanwhile.
unsafe fn conf_mut<'a>(conf: *mut CONF) -> Option<&'a mut CONF> {
    // SAFETY: the caller's guarantee.
    unsafe { conf.as_mut() }
}

/// `def_create`: a new configuration, set up by the method's `init`.
unsafe extern "C" fn def_create(meth: *mut CONF_METHOD) -> *mut CONF {
    // SAFETY: the caller's method.
    let Some(init) = (unsafe { meth.as_ref() }).and_then(|m| m.init) else {
        return ptr::null_mut();
    };
    let ret = mem::alloc(size_of::<CONF>()).cast::<CONF>();
    if ret.is_null() {
        return ret;
    }
    // SAFETY: the method's function with a new configuration.
    if unsafe { init(ret) } == 0 {
        // SAFETY: the allocation above.
        unsafe { mem::release(ret.cast()) };
        return ptr::null_mut();
    }
    ret
}

/// Clears `conf` for `meth` with `classes`.
///
/// # Safety
/// `conf` is null or valid for writes of a CONF.
unsafe fn def_init(conf: *mut CONF, meth: *mut CONF_METHOD, classes: &'static Classes) -> c_int {
    if conf.is_null() {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    unsafe {
        conf.write(CONF {
            meth,
            meth_data: (&raw const classes.0).cast_mut().cast(),
            data: ptr::null_mut(),
            flag_dollarid: 0,
            flag_abspath: 0,
            includedir: ptr::null_mut(),
            libctx: ptr::null_mut(),
        });
    };
    1
}

/// `def_init_default`.
unsafe extern "C" fn def_init_default(conf: *mut CONF) -> c_int {
    // SAFETY: the caller's configuration.
    unsafe { def_init(conf, default_method(), &DEFAULT_CLASSES) }
}

/// `def_init_WIN32`.
unsafe extern "C" fn def_init_win32(conf: *mut CONF) -> c_int {
    // SAFETY: the caller's configuration.
    unsafe { def_init(conf, WIN32_METHOD.0.get(), &WIN32_CLASSES) }
}

/// `def_destroy`: the data, then the configuration.
unsafe extern "C" fn def_destroy(conf: *mut CONF) -> c_int {
    // SAFETY: the caller's configuration.
    if unsafe { def_destroy_data(conf) } == 0 {
        return 0;
    }
    // SAFETY: a configuration from `def_create`.
    unsafe { mem::release(conf.cast()) };
    1
}

/// `def_destroy_data`.
unsafe extern "C" fn def_destroy_data(conf: *mut CONF) -> c_int {
    // SAFETY: the caller's configuration.
    let Some(conf) = (unsafe { conf_mut(conf) }) else {
        return 0;
    };
    free_data(conf);
    1
}

/// `def_dump`: each entry, in the table's order: `[section] name=value`, or `[[section]]`.
unsafe extern "C" fn def_dump(conf: *const CONF, out: *mut BIO) -> c_int {
    // SAFETY: the caller's configuration.
    let Some(conf) = (unsafe { conf.as_ref() }) else {
        return 0;
    };
    // SAFETY: the configuration's table.
    for item in unsafe { crate::lhash::items(table(conf)) } {
        // SAFETY: an entry of the table.
        let Some(v) = (unsafe { item.cast::<CONF_VALUE>().as_ref() }) else {
            continue;
        };
        let mut line = Vec::new();
        // SAFETY: the entry's strings.
        let section = unsafe { bytes(v.section) }.unwrap_or(b"(null)");
        if v.name.is_null() {
            line.extend_from_slice(b"[[");
            line.extend_from_slice(section);
            line.extend_from_slice(b"]]\n");
        } else {
            line.push(b'[');
            line.extend_from_slice(section);
            line.extend_from_slice(b"] ");
            // SAFETY: as above.
            line.extend_from_slice(unsafe { bytes(v.name) }.unwrap_or(b"(null)"));
            line.push(b'=');
            // SAFETY: as above.
            line.extend_from_slice(unsafe { bytes(v.value) }.unwrap_or(b"(null)"));
            line.push(b'\n');
        }
        let len = c_int::try_from(line.len()).unwrap_or(c_int::MAX);
        // SAFETY: the caller's BIO, and the line (BIO_printf's one write).
        unsafe { crate::bio::BIO_write(out, line.as_ptr().cast(), len) };
    }
    1
}

/// The method's classes, from the configuration's `meth_data`.
///
/// # Safety
/// `conf` is a live configuration whose `meth_data` is null or 128 classes.
pub(crate) unsafe fn classes_of<'a>(conf: &CONF) -> Option<&'a [u16; 128]> {
    // SAFETY: the caller's guarantee.
    unsafe { conf.meth_data.cast::<[u16; 128]>().as_ref() }
}

/// `def_is_number`: whether `c` is a digit by the method's classes.
unsafe extern "C" fn def_is_number(conf: *const CONF, c: c_char) -> c_int {
    // SAFETY: the caller's configuration.
    let Some(t) = (unsafe { conf.as_ref() }).and_then(|c| unsafe { classes_of(c) }) else {
        return 0;
    };
    c_int::from(rustyssl_conf::Classes(t).is(u8::from_ne_bytes(c.to_ne_bytes()), classes::NUMBER))
}

/// `def_to_int`: the digit's value.
unsafe extern "C" fn def_to_int(_conf: *const CONF, c: c_char) -> c_int {
    c_int::from(c) - c_int::from(b'0')
}

// --- The interface (`conf_lib.c`) ---

ffi_export! {
    /// The default method: OpenSSL's file format.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn NCONF_default() -> *mut CONF_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_CONF
    {
        default_method()
    }
}

ffi_export! {
    /// The WIN32 method: the file format with `;` comments at the start of a line, no
    /// escapes, and `"` quotes that double.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn NCONF_WIN32() -> *mut CONF_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_CONF
    {
        WIN32_METHOD.0.get()
    }
}

ffi_export! {
    /// A new, empty configuration of `meth` (the default for NULL), for `libctx`; NULL with
    /// `ERR_R_CONF_LIB` if the method's `create` fails.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `meth` is NULL or a method whose functions
    /// are of the documented types.
    pub unsafe extern "C" fn NCONF_new_ex(libctx: *mut OSSL_LIB_CTX, meth: *mut CONF_METHOD) -> *mut CONF
    where failure = ptr::null_mut(), library = ERR_LIB_CONF
    {
        let meth = if meth.is_null() { default_method() } else { meth };
        // SAFETY: the caller's method.
        let ret = match unsafe { meth.as_ref() }.and_then(|m| m.create) {
            // SAFETY: the method's function with itself.
            Some(create) => unsafe { create(meth) },
            None => ptr::null_mut(),
        };
        // SAFETY: a configuration the method made, or null.
        let Some(c) = (unsafe { conf_mut(ret) }) else {
            err::raise(ERR_LIB_CONF, ERR_R_CONF_LIB, "NCONF_new_ex");
            return ptr::null_mut();
        };
        c.libctx = libctx;
        ret
    }
}

ffi_export! {
    /// [`NCONF_new_ex`] for the default library context.
    ///
    /// # Safety
    /// As for [`NCONF_new_ex`].
    pub unsafe extern "C" fn NCONF_new(meth: *mut CONF_METHOD) -> *mut CONF
    where failure = ptr::null_mut(), library = ERR_LIB_CONF
    {
        // SAFETY: the caller's guarantee.
        unsafe { NCONF_new_ex(ptr::null_mut(), meth) }
    }
}

/// The configuration's method's function `f`, if it has a method with one.
///
/// # Safety
/// `conf` is a live configuration.
unsafe fn method_fn<T>(conf: *const CONF, f: impl FnOnce(&CONF_METHOD) -> Option<T>) -> Option<T> {
    // SAFETY: the caller's guarantee; the configuration's method.
    unsafe { conf.as_ref() }
        .and_then(|c| unsafe { c.meth.as_ref() })
        .and_then(f)
}

ffi_export! {
    /// Frees the configuration through its method's `destroy`; NULL does nothing.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration, not used afterwards.
    pub unsafe extern "C" fn NCONF_free(conf: *mut CONF)
    where failure = (), library = ERR_LIB_CONF
    {
        // SAFETY: the caller's guarantee.
        if let Some(destroy) = unsafe { method_fn(conf, |m| m.destroy) } {
            // SAFETY: the method's function with its configuration.
            unsafe { destroy(conf) };
        }
    }
}

ffi_export! {
    /// Frees what the configuration holds through its method's `destroy_data`, keeping the
    /// configuration; NULL does nothing.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration.
    pub unsafe extern "C" fn NCONF_free_data(conf: *mut CONF)
    where failure = (), library = ERR_LIB_CONF
    {
        // SAFETY: the caller's guarantee.
        if let Some(destroy_data) = unsafe { method_fn(conf, |m| m.destroy_data) } {
            // SAFETY: the method's function with its configuration.
            unsafe { destroy_data(conf) };
        }
    }
}

ffi_export! {
    /// The configuration's library context (NULL for NULL).
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration.
    pub unsafe extern "C" fn NCONF_get0_libctx(conf: *const CONF) -> *mut OSSL_LIB_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_CONF
    {
        // SAFETY: the caller's guarantee.
        unsafe { conf.as_ref() }.map_or(ptr::null_mut(), |c| c.libctx)
    }
}

/// `section_name_cmp`: `strcmp` of the names the stack's elements point to.
unsafe extern "C" fn section_name_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: pointers to the stack's elements, C strings.
    let a = unsafe { *a.cast::<*const c_char>() };
    // SAFETY: as above.
    let b = unsafe { *b.cast::<*const c_char>() };
    // SAFETY: as above.
    unsafe { strcmp(a.cast(), b.cast()) }
}

ffi_export! {
    /// The names of the configuration's sections, sorted, in a new stack the caller frees (the
    /// names are the configuration's).
    ///
    /// # Safety
    /// `cnf` is NULL or a live configuration.
    pub unsafe extern "C" fn NCONF_get_section_names(cnf: *const CONF) -> *mut stack_st_OPENSSL_CSTRING
    where failure = ptr::null_mut(), library = ERR_LIB_CONF
    {
        // SAFETY: the caller's guarantee.
        let Some(conf) = (unsafe { cnf.as_ref() }) else { return ptr::null_mut() };
        // SAFETY: a comparison of the stack's elements.
        let names = unsafe { OPENSSL_sk_new(Some(section_name_cmp)) };
        if names.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the configuration's table.
        for item in unsafe { crate::lhash::items(table(conf)) } {
            // SAFETY: an entry of the table.
            if let Some(v) = unsafe { item.cast::<CONF_VALUE>().as_ref() }
                && v.name.is_null()
            {
                // SAFETY: the new stack, and the section's name.
                unsafe { OPENSSL_sk_push(names, v.section.cast()) };
            }
        }
        // SAFETY: as above.
        unsafe { OPENSSL_sk_sort(names) };
        names.cast()
    }
}

ffi_export! {
    /// Loads the file `file` into the configuration through its method's `load`, the line
    /// of an error in `*eline`. Returns 1, or 0 (`CONF_R_NO_CONF` for NULL).
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `file` is a C string; `eline` is NULL or
    /// valid for a write.
    pub unsafe extern "C" fn NCONF_load(conf: *mut CONF, file: *const c_char, eline: *mut c_long) -> c_int
    where failure = 0, library = ERR_LIB_CONF
    {
        if conf.is_null() {
            err::raise(ERR_LIB_CONF, CONF_R_NO_CONF, "NCONF_load");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        match unsafe { method_fn(conf, |m| m.load) } {
            // SAFETY: the method's function with the caller's arguments.
            Some(load) => unsafe { load(conf, file, eline) },
            None => 0,
        }
    }
}

ffi_export! {
    /// [`NCONF_load_bio`] from a `FILE`, left open.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `fp` is an open `FILE`; `eline` is NULL or
    /// valid for a write.
    pub unsafe extern "C" fn NCONF_load_fp(conf: *mut CONF, fp: *mut FILE, eline: *mut c_long) -> c_int
    where failure = 0, library = ERR_LIB_CONF
    {
        // SAFETY: the caller's stream.
        let b = unsafe { BIO_new_fp(fp, BIO_NOCLOSE) };
        if b.is_null() {
            err::raise(ERR_LIB_CONF, ERR_R_BUF_LIB, "NCONF_load_fp");
            return 0;
        }
        // SAFETY: the caller's guarantee, and the BIO.
        let ret = unsafe { NCONF_load_bio(conf, b, eline) };
        // SAFETY: the BIO made here.
        unsafe { BIO_free(b) };
        ret
    }
}

ffi_export! {
    /// Loads what `bp` holds into the configuration through its method's `load_bio`, the line
    /// of an error in `*eline`. Returns 1, or 0 (`CONF_R_NO_CONF` for NULL).
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `bp` is NULL or a live BIO; `eline` is NULL or
    /// valid for a write.
    pub unsafe extern "C" fn NCONF_load_bio(conf: *mut CONF, bp: *mut BIO, eline: *mut c_long) -> c_int
    where failure = 0, library = ERR_LIB_CONF
    {
        if conf.is_null() {
            err::raise(ERR_LIB_CONF, CONF_R_NO_CONF, "NCONF_load_bio");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        match unsafe { method_fn(conf, |m| m.load_bio) } {
            // SAFETY: the method's function with the caller's arguments.
            Some(load_bio) => unsafe { load_bio(conf, bp, eline) },
            None => 0,
        }
    }
}

ffi_export! {
    /// The section's stack of values (the configuration's), or NULL; `CONF_R_NO_CONF` and
    /// `CONF_R_NO_SECTION` for NULL arguments.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `section` is NULL or a C string.
    pub unsafe extern "C" fn NCONF_get_section(conf: *const CONF, section: *const c_char) -> *mut stack_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_CONF
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { conf.as_ref() }) else {
            err::raise(ERR_LIB_CONF, CONF_R_NO_CONF, "NCONF_get_section");
            return ptr::null_mut();
        };
        if section.is_null() {
            err::raise(ERR_LIB_CONF, CONF_R_NO_SECTION, "NCONF_get_section");
            return ptr::null_mut();
        }
        // SAFETY: the caller's string.
        unsafe { section_values(c, section) }
    }
}

ffi_export! {
    /// The value of `name` in `group` (or the default section; for `ENV`, the environment; with
    /// no configuration, the environment alone), or NULL with `CONF_R_NO_VALUE` (data
    /// `group=... name=...`) or `CONF_R_NO_CONF_OR_ENVIRONMENT_VARIABLE`.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `group` and `name` are NULL or C strings.
    pub unsafe extern "C" fn NCONF_get_string(conf: *const CONF, group: *const c_char, name: *const c_char) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_CONF
    {
        // SAFETY: the caller's guarantee.
        let s = unsafe { get_string(conf, group, name) };
        if !s.is_null() {
            return s.cast_mut();
        }
        if conf.is_null() {
            err::raise(ERR_LIB_CONF, CONF_R_NO_CONF_OR_ENVIRONMENT_VARIABLE, "NCONF_get_string");
            return ptr::null_mut();
        }
        let mut data = b"group=".to_vec();
        // SAFETY: the caller's strings.
        data.extend_from_slice(unsafe { bytes(group) }.unwrap_or_default());
        data.extend_from_slice(b" name=");
        // SAFETY: as above.
        data.extend_from_slice(unsafe { bytes(name) }.unwrap_or(b"(null)"));
        err::raise_with_bytes(ERR_LIB_CONF, CONF_R_NO_VALUE, "NCONF_get_string", &data);
        ptr::null_mut()
    }
}

/// `default_is_number`: an ASCII digit.
unsafe extern "C" fn default_is_number(_conf: *const CONF, c: c_char) -> c_int {
    c_int::from(u8::from_ne_bytes(c.to_ne_bytes()).is_ascii_digit())
}

ffi_export! {
    /// The leading digits of the value of `name` in `group` as a number in `*result` (by the
    /// method's `is_number` and `to_int`). Returns 1, or 0: no value, NULL `result`, or
    /// `CONF_R_NUMBER_TOO_LARGE` past `LONG_MAX`.
    ///
    /// # Safety
    /// As for [`NCONF_get_string`]; `result` is NULL or valid for a write.
    pub unsafe extern "C" fn NCONF_get_number_e(conf: *const CONF, group: *const c_char, name: *const c_char, result: *mut c_long) -> c_int
    where failure = 0, library = ERR_LIB_CONF
    {
        if result.is_null() {
            err::raise(ERR_LIB_CONF, ERR_R_PASSED_NULL_PARAMETER, "NCONF_get_number_e");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let mut s = unsafe { NCONF_get_string(conf, group, name) }.cast_const();
        if s.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let is_number = unsafe { method_fn(conf, |m| m.is_number) }.unwrap_or(default_is_number);
        // SAFETY: as above.
        let to_int = unsafe { method_fn(conf, |m| m.to_int) }.unwrap_or(def_to_int);
        let mut res: c_long = 0;
        loop {
            // SAFETY: a C string, read up to its NUL (no digit).
            let c = unsafe { s.read() };
            // SAFETY: the method's function with the caller's configuration.
            if c == 0 || unsafe { is_number(conf, c) } == 0 {
                break;
            }
            // SAFETY: as above.
            let d = c_long::from(unsafe { to_int(conf, c) });
            let fits = c_long::MAX.checked_sub(d).is_some_and(|room| res <= room / 10);
            if !fits {
                err::raise(ERR_LIB_CONF, CONF_R_NUMBER_TOO_LARGE, "NCONF_get_number_e");
                return 0;
            }
            res = res * 10 + d;
            // SAFETY: within the string, before its NUL.
            s = unsafe { s.add(1) };
        }
        // SAFETY: the caller's guarantee.
        unsafe { result.write(res) };
        1
    }
}

ffi_export! {
    /// [`NCONF_dump_bio`] to a `FILE`.
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `out` is an open `FILE`.
    pub unsafe extern "C" fn NCONF_dump_fp(conf: *const CONF, out: *mut FILE) -> c_int
    where failure = 0, library = ERR_LIB_CONF
    {
        // SAFETY: the caller's stream.
        let b = unsafe { BIO_new_fp(out, BIO_NOCLOSE) };
        if b.is_null() {
            err::raise(ERR_LIB_CONF, ERR_R_BUF_LIB, "NCONF_dump_fp");
            return 0;
        }
        // SAFETY: the caller's guarantee, and the BIO.
        let ret = unsafe { NCONF_dump_bio(conf, b) };
        // SAFETY: the BIO made here.
        unsafe { BIO_free(b) };
        ret
    }
}

ffi_export! {
    /// Writes the configuration to `out` through its method's `dump`. Returns its result, or 0
    /// (`CONF_R_NO_CONF` for NULL).
    ///
    /// # Safety
    /// `conf` is NULL or a live configuration; `out` is a live BIO.
    pub unsafe extern "C" fn NCONF_dump_bio(conf: *const CONF, out: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_CONF
    {
        if conf.is_null() {
            err::raise(ERR_LIB_CONF, CONF_R_NO_CONF, "NCONF_dump_bio");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        match unsafe { method_fn(conf, |m| m.dump) } {
            // SAFETY: the method's function with the caller's arguments.
            Some(dump) => unsafe { dump(conf, out) },
            None => 0,
        }
    }
}

// --- The classic functions, over a bare table ---

ffi_export! {
    /// Sets the method the classic `CONF_*` functions use. Returns 1.
    ///
    /// # Safety
    /// `meth` is NULL or a method that lives as long as it's used.
    pub unsafe extern "C" fn CONF_set_default_method(meth: *mut CONF_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_CONF
    {
        CLASSIC_METHOD.store(meth, Ordering::Release);
        1
    }
}

ffi_export! {
    /// Sets `conf` up with the classic functions' method (`init`) over the table `hash`.
    ///
    /// # Safety
    /// `conf` is valid for writes of a `CONF`; `hash` is NULL or a configuration table.
    pub unsafe extern "C" fn CONF_set_nconf(conf: *mut CONF, hash: *mut lhash_st_CONF_VALUE)
    where failure = (), library = ERR_LIB_CONF
    {
        let mut meth = CLASSIC_METHOD.load(Ordering::Acquire);
        if meth.is_null() {
            meth = default_method();
            CLASSIC_METHOD.store(meth, Ordering::Release);
        }
        // SAFETY: the method (the default, or an application's).
        if let Some(init) = unsafe { meth.as_ref() }.and_then(|m| m.init) {
            // SAFETY: the method's function with the caller's configuration.
            unsafe { init(conf) };
        }
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { conf_mut(conf) } {
            c.data = hash;
        }
    }
}

/// A temporary configuration over `hash`, as the classic functions make one.
///
/// # Safety
/// `hash` is NULL or a configuration table.
unsafe fn over(hash: *mut lhash_st_CONF_VALUE) -> CONF {
    let mut c = CONF {
        meth: ptr::null_mut(),
        meth_data: ptr::null_mut(),
        data: ptr::null_mut(),
        flag_dollarid: 0,
        flag_abspath: 0,
        includedir: ptr::null_mut(),
        libctx: ptr::null_mut(),
    };
    // SAFETY: a local configuration, and the caller's table.
    unsafe { CONF_set_nconf(&raw mut c, hash) };
    c
}

ffi_export! {
    /// Loads the file `file` into the table `conf` (a new one for NULL): the table, or NULL.
    ///
    /// # Safety
    /// `conf` is NULL or a configuration table; `file` is a C string; `eline` is NULL or
    /// valid for a write.
    pub unsafe extern "C" fn CONF_load(conf: *mut lhash_st_CONF_VALUE, file: *const c_char, eline: *mut c_long) -> *mut lhash_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_CONF
    {
        // SAFETY: the caller's string.
        let b = unsafe { BIO_new_file(file, c"rb".as_ptr()) };
        if b.is_null() {
            err::raise(ERR_LIB_CONF, ERR_R_SYS_LIB, "CONF_load");
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee, and the BIO.
        let ret = unsafe { CONF_load_bio(conf, b, eline) };
        // SAFETY: the BIO made here.
        unsafe { BIO_free(b) };
        ret
    }
}

ffi_export! {
    /// [`CONF_load_bio`] from a `FILE`, left open.
    ///
    /// # Safety
    /// `conf` is NULL or a configuration table; `fp` is an open `FILE`; `eline` is NULL or
    /// valid for a write.
    pub unsafe extern "C" fn CONF_load_fp(conf: *mut lhash_st_CONF_VALUE, fp: *mut FILE, eline: *mut c_long) -> *mut lhash_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_CONF
    {
        // SAFETY: the caller's stream.
        let b = unsafe { BIO_new_fp(fp, BIO_NOCLOSE) };
        if b.is_null() {
            err::raise(ERR_LIB_CONF, ERR_R_BUF_LIB, "CONF_load_fp");
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee, and the BIO.
        let ret = unsafe { CONF_load_bio(conf, b, eline) };
        // SAFETY: the BIO made here.
        unsafe { BIO_free(b) };
        ret
    }
}

ffi_export! {
    /// Loads what `bp` holds into the table `conf` (a new one for NULL): the table, or NULL.
    /// (Into an existing table it fails, as OpenSSL's does: its `default` section exists.)
    ///
    /// # Safety
    /// `conf` is NULL or a configuration table; `bp` is NULL or a live BIO; `eline` is NULL or
    /// valid for a write.
    pub unsafe extern "C" fn CONF_load_bio(conf: *mut lhash_st_CONF_VALUE, bp: *mut BIO, eline: *mut c_long) -> *mut lhash_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_CONF
    {
        // SAFETY: the caller's table.
        let mut c = unsafe { over(conf) };
        // SAFETY: a local configuration, and the caller's BIO.
        let ret = unsafe { NCONF_load_bio(&raw mut c, bp, eline) };
        // The include directory a pragma set has nowhere to go (OpenSSL's leaks).
        // SAFETY: the local configuration's string.
        unsafe { mem::release(c.includedir.cast()) };
        if ret != 0 { c.data } else { ptr::null_mut() }
    }
}

ffi_export! {
    /// The section's stack of values in the table, or NULL.
    ///
    /// # Safety
    /// `conf` is NULL or a configuration table; `section` is NULL or a C string.
    pub unsafe extern "C" fn CONF_get_section(conf: *mut lhash_st_CONF_VALUE, section: *const c_char) -> *mut stack_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_CONF
    {
        if conf.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's table.
        let c = unsafe { over(conf) };
        // SAFETY: a local configuration, and the caller's string.
        unsafe { NCONF_get_section(&raw const c, section) }
    }
}

ffi_export! {
    /// [`NCONF_get_string`] over the table (the environment alone for NULL).
    ///
    /// # Safety
    /// `conf` is NULL or a configuration table; `group` and `name` are NULL or C strings.
    pub unsafe extern "C" fn CONF_get_string(conf: *mut lhash_st_CONF_VALUE, group: *const c_char, name: *const c_char) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_CONF
    {
        if conf.is_null() {
            // SAFETY: the caller's strings.
            return unsafe { NCONF_get_string(ptr::null(), group, name) };
        }
        // SAFETY: the caller's table.
        let c = unsafe { over(conf) };
        // SAFETY: a local configuration, and the caller's strings.
        unsafe { NCONF_get_string(&raw const c, group, name) }
    }
}

ffi_export! {
    /// [`NCONF_get_number_e`] over the table: the number, or 0, its errors dropped.
    ///
    /// # Safety
    /// `conf` is NULL or a configuration table; `group` and `name` are NULL or C strings.
    pub unsafe extern "C" fn CONF_get_number(conf: *mut lhash_st_CONF_VALUE, group: *const c_char, name: *const c_char) -> c_long
    where failure = 0, library = ERR_LIB_CONF
    {
        let mut result: c_long = 0;
        // SAFETY: no preconditions.
        unsafe { err::ERR_set_mark() };
        let status = if conf.is_null() {
            // SAFETY: the caller's strings, and a local.
            unsafe { NCONF_get_number_e(ptr::null(), group, name, &raw mut result) }
        } else {
            // SAFETY: the caller's table.
            let c = unsafe { over(conf) };
            // SAFETY: a local configuration, the caller's strings, and a local.
            unsafe { NCONF_get_number_e(&raw const c, group, name, &raw mut result) }
        };
        // SAFETY: no preconditions.
        unsafe { err::ERR_pop_to_mark() };
        if status == 0 { 0 } else { result }
    }
}

ffi_export! {
    /// Frees the table and what it holds, through the classic functions' method; NULL does
    /// nothing.
    ///
    /// # Safety
    /// `conf` is NULL or a configuration table, not used afterwards.
    pub unsafe extern "C" fn CONF_free(conf: *mut lhash_st_CONF_VALUE)
    where failure = (), library = ERR_LIB_CONF
    {
        // SAFETY: the caller's table.
        let mut c = unsafe { over(conf) };
        // SAFETY: a local configuration over the caller's table.
        unsafe { NCONF_free_data(&raw mut c) };
    }
}

ffi_export! {
    /// [`CONF_dump_bio`] to a `FILE`.
    ///
    /// # Safety
    /// `conf` is NULL or a configuration table; `out` is an open `FILE`.
    pub unsafe extern "C" fn CONF_dump_fp(conf: *mut lhash_st_CONF_VALUE, out: *mut FILE) -> c_int
    where failure = 0, library = ERR_LIB_CONF
    {
        // SAFETY: the caller's stream.
        let b = unsafe { BIO_new_fp(out, BIO_NOCLOSE) };
        if b.is_null() {
            err::raise(ERR_LIB_CONF, ERR_R_BUF_LIB, "CONF_dump_fp");
            return 0;
        }
        // SAFETY: the caller's guarantee, and the BIO.
        let ret = unsafe { CONF_dump_bio(conf, b) };
        // SAFETY: the BIO made here.
        unsafe { BIO_free(b) };
        ret
    }
}

ffi_export! {
    /// [`NCONF_dump_bio`] over the table.
    ///
    /// # Safety
    /// `conf` is NULL or a configuration table; `out` is a live BIO.
    pub unsafe extern "C" fn CONF_dump_bio(conf: *mut lhash_st_CONF_VALUE, out: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_CONF
    {
        // SAFETY: the caller's table.
        let c = unsafe { over(conf) };
        // SAFETY: a local configuration, and the caller's BIO.
        unsafe { NCONF_dump_bio(&raw const c, out) }
    }
}

ffi_export! {
    /// Calls `list_cb` with each item of `list_` split at `sep` (NULL and 0 for an empty one;
    /// the spaces around each trimmed with `nospc`), stopping at a result of 0 or less, which
    /// it returns. Returns 1 after the last item; 0 with `CONF_R_LIST_CANNOT_BE_NULL` for a
    /// NULL list.
    ///
    /// # Safety
    /// `list_` is NULL or a C string; `list_cb` is a function of the documented type, given
    /// `arg`.
    pub unsafe extern "C" fn CONF_parse_list(list_: *const c_char, sep: c_int, nospc: c_int, list_cb: Option<unsafe extern "C" fn(*const c_char, c_int, *mut c_void) -> c_int>, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CONF
    {
        // SAFETY: the caller's string.
        let Some(list) = (unsafe { bytes(list_) }) else {
            err::raise(ERR_LIB_CONF, CONF_R_LIST_CANNOT_BE_NULL, "CONF_parse_list");
            return 0;
        };
        let Some(cb) = list_cb else { return 0 };
        // `strchr`'s conversion of the separator to a char.
        let sep = sep.to_le_bytes()[0];
        for item in rustyssl_conf::list_items(list, sep, nospc != 0) {
            let ret = match item {
                // SAFETY: the caller's function with its argument.
                None => unsafe { cb(ptr::null(), 0, arg) },
                Some(item) => {
                    let offset = (item.as_ptr() as usize).wrapping_sub(list.as_ptr() as usize);
                    let len = c_int::try_from(item.len()).unwrap_or(c_int::MAX);
                    // SAFETY: the caller's function with a part of its string and its argument.
                    unsafe { cb(list_.wrapping_add(offset), len, arg) }
                }
            };
            if ret <= 0 {
                return ret;
            }
        }
        1
    }
}

ffi_export! {
    /// The configuration file OpenSSL loads by default, which the caller frees: `OPENSSL_CONF`
    /// (unless set-user-ID), else `openssl.cnf` in `OPENSSLDIR`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn CONF_get1_default_config_file() -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_CONF
    {
        if let Some(file) = crate::init::safe_getenv(c"OPENSSL_CONF") {
            return c_dup(file.as_bytes());
        }
        let mut path = crate::version::config_dir().to_bytes().to_vec();
        path.extend_from_slice(b"/openssl.cnf");
        c_dup(&path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: a second load into a configuration fails (its `default` section
    /// exists), as OpenSSL's does, and keeps what the first one set (OpenSSL's leaves the
    /// failed load's freed section in the table, which lookups then read).
    #[test]
    fn a_second_load_keeps_the_first() {
        let load = |conf: *mut CONF, text: &[u8]| {
            let len = c_int::try_from(text.len()).unwrap_or(0);
            // SAFETY: a buffer of that length.
            let b = unsafe { crate::bio::mem::BIO_new_mem_buf(text.as_ptr().cast(), len) };
            // SAFETY: the configuration and the BIO.
            let ret = unsafe { NCONF_load_bio(conf, b, ptr::null_mut()) };
            // SAFETY: the BIO.
            unsafe { BIO_free(b) };
            ret
        };
        // SAFETY: no preconditions.
        let conf = unsafe { NCONF_new(ptr::null_mut()) };
        assert_eq!(load(conf, b"a = 1\n[s]\nx = y\n"), 1);
        assert_eq!(load(conf, b"b = 2\n"), 0);
        crate::err::take_all();
        // SAFETY: the configuration, and C strings.
        let a = unsafe { NCONF_get_string(conf, ptr::null(), c"a".as_ptr()) };
        // SAFETY: a value of the configuration.
        assert_eq!(unsafe { bytes(a) }, Some(&b"1"[..]));
        // SAFETY: as above.
        assert!(!unsafe { NCONF_get_section(conf, c"default".as_ptr()) }.is_null());
        // SAFETY: the configuration, freed once.
        unsafe { NCONF_free(conf) };
    }

    /// docs/DEVIATIONS.md: `NCONF_free_data` leaves the configuration empty and usable (OpenSSL
    /// leaves the freed table in it, so a later load, lookup, or `NCONF_free` reads freed
    /// memory).
    #[test]
    fn free_data_leaves_an_empty_configuration() {
        // SAFETY: no preconditions.
        let conf = unsafe { NCONF_new(ptr::null_mut()) };
        let text = b"a = 1\n";
        // SAFETY: a static buffer of that length.
        let b = unsafe { crate::bio::mem::BIO_new_mem_buf(text.as_ptr().cast(), 6) };
        // SAFETY: the configuration and the BIO.
        assert_eq!(unsafe { NCONF_load_bio(conf, b, ptr::null_mut()) }, 1);
        // SAFETY: the configuration.
        unsafe { NCONF_free_data(conf) };
        // SAFETY: as above.
        assert!(unsafe { NCONF_get_string(conf, ptr::null(), c"a".as_ptr()) }.is_null());
        // SAFETY: the BIO, rewound.
        unsafe { crate::bio::BIO_ctrl(b, rustyssl_abi::BIO_CTRL_RESET, 0, ptr::null_mut()) };
        // SAFETY: the configuration and the BIO.
        assert_eq!(unsafe { NCONF_load_bio(conf, b, ptr::null_mut()) }, 1);
        // SAFETY: as above.
        assert!(!unsafe { NCONF_get_string(conf, ptr::null(), c"a".as_ptr()) }.is_null());
        // SAFETY: the BIO and the configuration, each freed once.
        unsafe { BIO_free(b) };
        // SAFETY: as above.
        unsafe { NCONF_free_data(conf) };
        // SAFETY: as above.
        unsafe { NCONF_free(conf) };
        crate::err::take_all();
    }
}
