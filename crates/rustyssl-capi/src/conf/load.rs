//! The default methods' loading (`def_load`, `def_load_bio`): reading lines from BIOs as
//! OpenSSL does, through included files and directories, and keeping what
//! `rustyssl_conf::parse_line` makes of each in the configuration.
//!
//! The include stack and the directory being read are kept as OpenSSL keeps them: one
//! directory at a time, whose next file comes in when any file read meanwhile ends.

use core::ffi::{CStr, c_char, c_int, c_long};
use core::ptr;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

use rustyssl_abi::{
    BIO, BIO_R_NO_SUCH_FILE, CONF, CONF_R_INVALID_PRAGMA, CONF_R_MISSING_CLOSE_SQUARE_BRACKET,
    CONF_R_MISSING_EQUAL_SIGN, CONF_R_NO_CLOSE_BRACE, CONF_R_NO_SUCH_FILE,
    CONF_R_RECURSIVE_DIRECTORY_INCLUDE, CONF_R_RELATIVE_PATH, CONF_R_UNABLE_TO_CREATE_NEW_SECTION,
    CONF_R_VARIABLE_EXPANSION_TOO_LONG, CONF_R_VARIABLE_HAS_NO_VALUE, CONF_VALUE, ERR_LIB_CONF,
    ERR_LIB_SYS, ERR_R_CONF_LIB, ERR_R_SYS_LIB, ERR_REASON_MASK, OPENSSL_DIR_CTX,
    lhash_st_CONF_VALUE,
};
use rustyssl_conf::{Classes, Error, Line, Lines, Lookup, Next, Options, Pragma, READ_SIZE};

use super::{
    CONF_free, add_string, bytes, c_dup, classes_of, conf_mut, get_section, get_string, new_data,
    new_section,
};
use crate::bio::file::BIO_new_file;
use crate::bio::{BIO_free, BIO_gets, BIO_vfree};
use crate::dir::{OPENSSL_DIR_end, OPENSSL_DIR_read};
use crate::err;
use crate::mem;

/// `def_load`: the file `name` through [`def_load_bio`]; `CONF_R_NO_SUCH_FILE` (or
/// `ERR_R_SYS_LIB`) if it can't be opened.
pub(super) unsafe extern "C" fn def_load(
    conf: *mut CONF,
    name: *const c_char,
    line: *mut c_long,
) -> c_int {
    // SAFETY: the caller's string.
    let b = unsafe { BIO_new_file(name, c"rb".as_ptr()) };
    if b.is_null() {
        // SAFETY: no preconditions.
        let code = unsafe { err::ERR_peek_last_error() };
        // ERR_GET_REASON of a library's error.
        let reason =
            c_int::try_from(code & core::ffi::c_ulong::from(ERR_REASON_MASK.cast_unsigned()))
                .unwrap_or(0);
        if reason == BIO_R_NO_SUCH_FILE {
            err::raise(ERR_LIB_CONF, CONF_R_NO_SUCH_FILE, "def_load");
        } else {
            err::raise(ERR_LIB_CONF, ERR_R_SYS_LIB, "def_load");
        }
        return 0;
    }
    // SAFETY: the caller's configuration and line, and the BIO.
    let ret = unsafe { def_load_bio(conf, b, line) };
    // SAFETY: the BIO made here.
    unsafe { BIO_free(b) };
    ret
}

/// The values set so far, for references (`_CONF_get_string`).
struct Values(*const CONF);

impl Lookup for Values {
    fn get(&self, section: Option<&[u8]>, name: &[u8]) -> Option<Vec<u8>> {
        let section =
            section.map(|s| CString::new(s.split(|&c| c == 0).next().unwrap_or_default()));
        let section = match section {
            Some(Ok(s)) => Some(s),
            Some(Err(_)) => return None,
            None => None,
        };
        let name = CString::new(name).ok()?;
        let s = section.as_ref().map_or(ptr::null(), |s| s.as_ptr());
        // SAFETY: the configuration being loaded, and local strings.
        let v = unsafe { get_string(self.0, s, name.as_ptr()) };
        // SAFETY: a C string of the table or the environment, copied at once.
        unsafe { bytes(v) }.map(<[u8]>::to_vec)
    }

    fn include_env(&self) -> Option<Vec<u8>> {
        crate::init::safe_getenv(c"OPENSSL_CONF_INCLUDE").map(CString::into_bytes)
    }
}

/// The directory an include named, as OpenSSL reads it: its context and path.
struct Directory {
    ctx: *mut OPENSSL_DIR_CTX,
    path: Option<CString>,
}

impl Directory {
    /// `get_next_file`: the next `.cnf` or `.conf` file in the directory that opens, or null
    /// once there's none (and the directory is closed).
    fn next_file(&mut self, path: &CStr) -> *mut BIO {
        loop {
            // SAFETY: the context and a C string.
            let name = unsafe { OPENSSL_DIR_read(&raw mut self.ctx, path.as_ptr()) };
            // SAFETY: a C string of the context's, or null.
            let Some(name) = (unsafe { bytes(name) }) else {
                break;
            };
            let lower = name.to_ascii_lowercase();
            if (name.len() > 5 && lower.ends_with(b".conf"))
                || (name.len() > 4 && lower.ends_with(b".cnf"))
            {
                let mut full = path.to_bytes().to_vec();
                full.push(b'/');
                full.extend_from_slice(name);
                let Ok(full) = CString::new(full) else {
                    continue;
                };
                // SAFETY: C strings.
                let b = unsafe { BIO_new_file(full.as_ptr(), c"r".as_ptr()) };
                // Errors when opening files are non-fatal.
                if !b.is_null() {
                    return b;
                }
            }
        }
        self.end();
        ptr::null_mut()
    }

    fn end(&mut self) {
        if !self.ctx.is_null() {
            // SAFETY: the open context.
            unsafe { OPENSSL_DIR_end(&raw mut self.ctx) };
        }
        self.ctx = ptr::null_mut();
    }

    /// `process_include`: the BIO of the file `path`, or of the first file of the directory
    /// `path`; null (with an error) if it isn't there, or is a directory while one is being
    /// read.
    fn open(&mut self, path: &CStr) -> *mut BIO {
        let os = std::ffi::OsStr::from_bytes(path.to_bytes());
        let meta = match std::fs::metadata(os) {
            Ok(m) => m,
            Err(e) => {
                let mut text = b"calling stat(".to_vec();
                text.extend_from_slice(path.to_bytes());
                text.push(b')');
                let errno = e.raw_os_error().unwrap_or(0);
                // A missing include isn't fatal.
                err::raise_with_bytes(ERR_LIB_SYS, errno, "process_include", &text);
                return ptr::null_mut();
            }
        };
        if meta.is_dir() {
            if !self.ctx.is_null() {
                err::raise_with_bytes(
                    ERR_LIB_CONF,
                    CONF_R_RECURSIVE_DIRECTORY_INCLUDE,
                    "process_include",
                    path.to_bytes(),
                );
                return ptr::null_mut();
            }
            let b = self.next_file(path);
            if !b.is_null() {
                self.path = Some(path.to_owned());
            }
            return b;
        }
        // SAFETY: C strings.
        unsafe { BIO_new_file(path.as_ptr(), c"r".as_ptr()) }
    }
}

/// The reason for a parse error.
fn reason(e: &Error) -> c_int {
    match e {
        Error::MissingCloseSquareBracket => CONF_R_MISSING_CLOSE_SQUARE_BRACKET,
        Error::MissingEqualSign(_) => CONF_R_MISSING_EQUAL_SIGN,
        Error::InvalidPragma | Error::InvalidPragmaValue => CONF_R_INVALID_PRAGMA,
        Error::NoCloseBrace => CONF_R_NO_CLOSE_BRACE,
        Error::VariableHasNoValue => CONF_R_VARIABLE_HAS_NO_VALUE,
        Error::VariableExpansionTooLong => CONF_R_VARIABLE_EXPANSION_TOO_LONG,
        Error::RelativePath => CONF_R_RELATIVE_PATH,
    }
}

/// How a load ended.
enum Failure {
    /// An error raised (or none, as OpenSSL raises none for some).
    Raised,
}

/// `def_load_bio`: reads what `bp` holds (and what it includes) into the configuration: its
/// sections and values, created in the `default` section first. Returns 1; or 0 with the
/// line in `*line` and `line N` added to the error, the configuration's table freed if this
/// made it.
pub(super) unsafe extern "C" fn def_load_bio(
    conf: *mut CONF,
    bp: *mut BIO,
    line: *mut c_long,
) -> c_int {
    // SAFETY: the caller's configuration.
    let Some(c) = (unsafe { conf_mut(conf) }) else {
        return 0;
    };
    let initial = c.data;
    let mut lines = Lines::new();
    let mut stack: Vec<*mut BIO> = Vec::new();
    let mut input = bp;
    let mut dir = Directory {
        ctx: ptr::null_mut(),
        path: None,
    };
    // SAFETY: the caller's configuration and BIOs.
    let result = unsafe { read_all(conf, &mut lines, &mut stack, &mut input, &mut dir) };
    if result.is_ok() {
        return 1;
    }
    // Every BIO but the caller's is freed.
    while let Some(popped) = stack.pop() {
        // SAFETY: an included file's BIO, or the caller's (which is last).
        unsafe { BIO_vfree(input) };
        input = popped;
    }
    dir.end();
    let n = lines.line();
    if !line.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { line.write(c_long::try_from(n).unwrap_or(c_long::MAX)) };
    }
    let text = n.to_string();
    err::add_error_data([Some(&b"line "[..]), Some(text.as_bytes())]);
    // SAFETY: as above.
    if let Some(c) = unsafe { conf_mut(conf) }
        && c.data != initial
    {
        // SAFETY: the table this load made.
        unsafe { CONF_free(c.data.cast::<lhash_st_CONF_VALUE>()) };
        c.data = ptr::null_mut();
    }
    0
}

/// Reads every line, through includes.
///
/// # Safety
/// `conf` is a live configuration; `input` null or a live BIO.
unsafe fn read_all(
    conf: *mut CONF,
    lines: &mut Lines,
    stack: &mut Vec<*mut BIO>,
    input: &mut *mut BIO,
    dir: &mut Directory,
) -> Result<(), Failure> {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { conf_mut(conf) }) else {
        return Err(Failure::Raised);
    };
    if !new_data(c) {
        err::raise(ERR_LIB_CONF, ERR_R_CONF_LIB, "def_load_bio");
        return Err(Failure::Raised);
    }
    let mut section = b"default".to_vec();
    // SAFETY: the configuration, and a name.
    let mut sv = unsafe { new_section(c, &section) };
    if sv.is_null() {
        err::raise(
            ERR_LIB_CONF,
            CONF_R_UNABLE_TO_CREATE_NEW_SECTION,
            "def_load_bio",
        );
        return Err(Failure::Raised);
    }
    // SAFETY: the configuration's method's classes.
    let Some(table) = (unsafe { classes_of(c) }).copied() else {
        return Err(Failure::Raised);
    };
    let classes = Classes(&table);
    let mut buf = [0u8; READ_SIZE];
    loop {
        buf[0] = 0;
        if !input.is_null() {
            // SAFETY: the BIO being read, and room for READ_SIZE octets.
            if unsafe {
                BIO_gets(
                    *input,
                    buf.as_mut_ptr().cast(),
                    c_int::try_from(READ_SIZE).unwrap_or(0),
                )
            } < 0
            {
                return Err(Failure::Raised);
            }
        }
        buf[READ_SIZE - 1] = 0;
        let len = buf.iter().position(|&b| b == 0).unwrap_or(0);
        let text = match lines.feed(classes, buf.get(..len).unwrap_or_default()) {
            Next::More => continue,
            Next::Line(text) => text,
            Next::End => {
                if !dir.ctx.is_null() {
                    let path = dir.path.clone();
                    let next = path
                        .as_deref()
                        .map_or(ptr::null_mut(), |p| dir.next_file(p));
                    if !next.is_null() {
                        // SAFETY: the finished file's BIO, replaced by the next one.
                        unsafe { BIO_vfree(*input) };
                        *input = next;
                        continue;
                    }
                    dir.path = None;
                }
                match stack.pop() {
                    None => return Ok(()),
                    Some(parent) => {
                        // SAFETY: as above.
                        unsafe { BIO_vfree(*input) };
                        *input = parent;
                        continue;
                    }
                }
            }
        };
        // SAFETY: the configuration, re-read after the reads.
        let Some(c) = (unsafe { conf_mut(conf) }) else {
            return Err(Failure::Raised);
        };
        // SAFETY: the configuration's string.
        let includedir = unsafe { bytes(c.includedir) }.map(<[u8]>::to_vec);
        let options = Options {
            classes,
            section: &section,
            dollarid: c.flag_dollarid != 0,
            abspath: c.flag_abspath != 0,
            includedir: includedir.as_deref(),
        };
        let parsed = rustyssl_conf::parse_line(&options, &text, &Values(conf));
        let parsed = match parsed {
            Ok(p) => p,
            Err(e) => {
                match &e {
                    Error::MissingEqualSign(here) => {
                        let mut data = b"HERE-->".to_vec();
                        data.extend_from_slice(here);
                        err::raise_with_bytes(ERR_LIB_CONF, reason(&e), "def_load_bio", &data);
                    }
                    // Upstream raises what value expansion finds in `str_copy`.
                    Error::NoCloseBrace
                    | Error::VariableHasNoValue
                    | Error::VariableExpansionTooLong => {
                        err::raise(ERR_LIB_CONF, reason(&e), "str_copy");
                    }
                    Error::InvalidPragmaValue => err::raise(ERR_LIB_CONF, reason(&e), "parsebool"),
                    _ => err::raise(ERR_LIB_CONF, reason(&e), "def_load_bio"),
                }
                return Err(Failure::Raised);
            }
        };
        match parsed {
            Line::Blank => {}
            Line::Section(name) => {
                let name = name.split(|&b| b == 0).next().unwrap_or_default().to_vec();
                let Ok(cname) = CString::new(name.clone()) else {
                    return Err(Failure::Raised);
                };
                // SAFETY: the configuration, and a C string.
                sv = unsafe { get_section(c, cname.as_ptr()) };
                if sv.is_null() {
                    // SAFETY: as above.
                    sv = unsafe { new_section(c, &name) };
                }
                if sv.is_null() {
                    err::raise(
                        ERR_LIB_CONF,
                        CONF_R_UNABLE_TO_CREATE_NEW_SECTION,
                        "def_load_bio",
                    );
                    return Err(Failure::Raised);
                }
                section = name;
            }
            Line::Pragma(p) => match p {
                Pragma::DollarId(on) => c.flag_dollarid = c_int::from(on),
                Pragma::AbsPath(on) => c.flag_abspath = c_int::from(on),
                Pragma::IncludeDir(d) => {
                    // SAFETY: the configuration's own string, replaced.
                    unsafe { mem::release(c.includedir.cast()) };
                    c.includedir = c_dup(&d);
                    if c.includedir.is_null() {
                        return Err(Failure::Raised);
                    }
                }
                Pragma::Unknown => {}
            },
            Line::Include(path) => {
                let path = path.split(|&b| b == 0).next().unwrap_or_default();
                let Ok(path) = CString::new(path) else {
                    return Err(Failure::Raised);
                };
                let next = dir.open(&path);
                if !next.is_null() {
                    stack.push(*input);
                    *input = next;
                }
            }
            Line::Value {
                section: psection,
                name,
                value,
            } => {
                let tv = match psection {
                    Some(ps) if ps != section => {
                        let ps = ps.split(|&b| b == 0).next().unwrap_or_default().to_vec();
                        let Ok(cps) = CString::new(ps.clone()) else {
                            return Err(Failure::Raised);
                        };
                        // SAFETY: the configuration, and a C string.
                        let mut tv = unsafe { get_section(c, cps.as_ptr()) };
                        if tv.is_null() {
                            // SAFETY: as above.
                            tv = unsafe { new_section(c, &ps) };
                        }
                        if tv.is_null() {
                            err::raise(
                                ERR_LIB_CONF,
                                CONF_R_UNABLE_TO_CREATE_NEW_SECTION,
                                "def_load_bio",
                            );
                            return Err(Failure::Raised);
                        }
                        tv
                    }
                    _ => sv,
                };
                let v = mem::alloc(size_of::<CONF_VALUE>()).cast::<CONF_VALUE>();
                let n = c_dup(&name);
                let val = c_dup(&value);
                if v.is_null() || n.is_null() || val.is_null() {
                    // SAFETY: what was made here.
                    unsafe { mem::release(v.cast()) };
                    // SAFETY: as above.
                    unsafe { mem::release(n.cast()) };
                    // SAFETY: as above.
                    unsafe { mem::release(val.cast()) };
                    return Err(Failure::Raised);
                }
                // SAFETY: a new allocation of a CONF_VALUE.
                unsafe {
                    v.write(CONF_VALUE {
                        section: ptr::null_mut(),
                        name: n,
                        value: val,
                    });
                };
                // SAFETY: a section entry of the configuration, and the new value it takes.
                if !unsafe { add_string(c, tv, v) } {
                    // SAFETY: the value, not taken.
                    unsafe { super::free_value(v) };
                    err::raise(ERR_LIB_CONF, ERR_R_CONF_LIB, "def_load_bio");
                    return Err(Failure::Raised);
                }
            }
        }
    }
}
