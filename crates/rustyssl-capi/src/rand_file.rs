//! Seed files (`RAND_load_file(3)`; `randfile.c`): a file's octets mixed into the generator
//! (`RAND_add`), 1024 octets of the private generator written to one (mode 0600), and the
//! default file's name (`$RANDFILE`, else `$HOME/.rnd`, neither for a privileged process). The
//! EGD functions aren't part of the default build (`OPENSSL_NO_EGD`), so there are none.

use core::ffi::{CStr, c_char, c_double, c_int, c_long};
use core::ptr;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use rustyssl_abi::{
    ERR_LIB_RAND, RAND_DRBG_STRENGTH, RAND_R_CANNOT_OPEN_FILE, RAND_R_INTERNAL_ERROR,
    RAND_R_NOT_A_REGULAR_FILE, RAND_R_RESEED_ERROR,
};

use crate::err;
use crate::ffi::ffi_export;
use crate::rand_lib::{RAND_add, RAND_priv_bytes, RAND_status};

/// `RAND_BUF_SIZE`.
const BUF_SIZE: usize = 1024;
/// `RAND_LOAD_BUF_SIZE`.
const LOAD_BUF_SIZE: usize = BUF_SIZE + 256;

/// The file name as the reference's `%s` prints it.
fn printed(file: Option<&CStr>) -> String {
    file.map_or_else(|| "(null)".to_owned(), |f| f.to_string_lossy().into_owned())
}

/// A path from a C string.
fn path_of(file: &CStr) -> &Path {
    use std::os::unix::ffi::OsStrExt;
    Path::new(std::ffi::OsStr::from_bytes(file.to_bytes()))
}

/// Reads up to `buf`'s length, as `fread` does: until it's full or the end (or an error).
fn read_full(f: &mut File, buf: &mut [u8]) -> usize {
    let mut got = 0;
    while got < buf.len() {
        let Some(rest) = buf.get_mut(got..) else {
            break;
        };
        match f.read(rest) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    got
}

ffi_export! {
    /// Mixes up to `bytes` octets of `file` into the generator (`RAND_add`): all of a regular
    /// file for a negative count, 256 of anything else. Returns the octets read, 0 for a count
    /// of 0, -1 if it can't be opened or the generator isn't seeded after.
    ///
    /// # Safety
    /// `file` is NULL or a string.
    pub unsafe extern "C" fn RAND_load_file(file: *const c_char, bytes: c_long) -> c_int
    where failure = -1, library = ERR_LIB_RAND
    {
        const F: &str = "RAND_load_file";
        if bytes == 0 {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let name = (!file.is_null()).then(|| unsafe { CStr::from_ptr(file) });
        let data = format!("Filename={}", printed(name));
        let Some(mut f) = name.and_then(|n| File::open(path_of(n)).ok()) else {
            err::raise_with_text(ERR_LIB_RAND, RAND_R_CANNOT_OPEN_FILE, F, &data);
            return -1;
        };
        let Ok(meta) = f.metadata() else {
            err::raise_with_text(ERR_LIB_RAND, RAND_R_INTERNAL_ERROR, F, &data);
            return -1;
        };
        let mut bytes: i64 = bytes;
        if bytes < 0 {
            bytes = if meta.is_file() { i64::try_from(meta.len()).unwrap_or(i64::MAX) } else { i64::from(RAND_DRBG_STRENGTH) };
        }
        let mut buf = [0u8; LOAD_BUF_SIZE];
        let mut ret: c_int = 0;
        let (load, block) = (i64::try_from(LOAD_BUF_SIZE).unwrap_or(0), i64::try_from(BUF_SIZE).unwrap_or(0));
        loop {
            let n = if bytes > 0 { if bytes <= load { bytes } else { block } } else { load };
            let n = usize::try_from(n).unwrap_or(0).min(LOAD_BUF_SIZE);
            let Some(part) = buf.get_mut(..n) else { break };
            let i = read_full(&mut f, part);
            if i == 0 {
                break;
            }
            let ci = c_int::try_from(i).unwrap_or(0);
            // SAFETY: the octets just read.
            unsafe { RAND_add(buf.as_ptr().cast(), ci, c_double::from(ci)) };
            ret = ret.saturating_add(ci);
            if bytes > 0 {
                bytes -= i64::from(ci);
                if bytes <= 0 {
                    break;
                }
            }
            if ret > c_int::MAX - c_int::try_from(LOAD_BUF_SIZE).unwrap_or(0) {
                break;
            }
        }
        crate::provider::macs::wipe(&mut buf);
        // SAFETY: no preconditions.
        if unsafe { RAND_status() } == 0 {
            err::raise_with_text(ERR_LIB_RAND, RAND_R_RESEED_ERROR, F, &data);
            return -1;
        }
        ret
    }
}

ffi_export! {
    /// Writes 1024 octets of the private generator to `file` (created with mode 0600, not
    /// truncated). Returns the octets written, or -1 (for something not a regular file too).
    ///
    /// # Safety
    /// `file` is NULL or a string.
    pub unsafe extern "C" fn RAND_write_file(file: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_RAND
    {
        const F: &str = "RAND_write_file";
        // SAFETY: the caller's guarantee.
        let name = (!file.is_null()).then(|| unsafe { CStr::from_ptr(file) });
        let data = format!("Filename={}", printed(name));
        let Some(name) = name else {
            err::raise_with_text(ERR_LIB_RAND, RAND_R_CANNOT_OPEN_FILE, F, &data);
            return -1;
        };
        let path = path_of(name);
        if std::fs::metadata(path).is_ok_and(|m| !m.is_file()) {
            err::raise_with_text(ERR_LIB_RAND, RAND_R_NOT_A_REGULAR_FILE, F, &data);
            return -1;
        }
        let mut buf = [0u8; BUF_SIZE];
        // SAFETY: room for the octets.
        if unsafe { RAND_priv_bytes(buf.as_mut_ptr(), c_int::try_from(BUF_SIZE).unwrap_or(0)) } != 1 {
            return -1;
        }
        // `open(O_WRONLY | O_CREAT, 0600)`: an existing file is overwritten from its start, not
        // truncated, as the reference's is.
        #[expect(clippy::suspicious_open_options, reason = "the reference doesn't truncate")]
        let out = OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .or_else(|_| {
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(path)
            });
        let Ok(mut out) = out else {
            crate::provider::macs::wipe(&mut buf);
            err::raise_with_text(ERR_LIB_RAND, RAND_R_CANNOT_OPEN_FILE, F, &data);
            return -1;
        };
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        let mut written = 0usize;
        while written < BUF_SIZE {
            let Some(rest) = buf.get(written..) else { break };
            match out.write(rest) {
                Ok(0) => break,
                Ok(n) => written += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        crate::provider::macs::wipe(&mut buf);
        c_int::try_from(written).unwrap_or(-1)
    }
}

ffi_export! {
    /// The default seed file's name into `buf`: `$RANDFILE`, else `$HOME/.rnd` (ignored in a
    /// privileged process). NULL if neither is set or it doesn't fit in `size` with its NUL.
    ///
    /// # Safety
    /// `buf` is NULL or has room for `size` octets.
    pub unsafe extern "C" fn RAND_file_name(buf: *mut c_char, size: usize) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_RAND
    {
        let (value, use_randfile) = match crate::init::safe_getenv(c"RANDFILE").filter(|s| !s.is_empty()) {
            Some(s) => (Some(s), true),
            None => (crate::init::safe_getenv(c"HOME"), false),
        };
        let Some(value) = value.filter(|s| !s.is_empty()) else { return ptr::null() };
        let mut name = value.into_bytes();
        if !use_randfile {
            name.extend_from_slice(b"/.rnd");
        }
        // The reference refuses one octet short of fitting (`len + 1 >= size`).
        if buf.is_null() || name.len() + 1 >= size {
            return ptr::null();
        }
        name.push(0);
        // SAFETY: the caller's room for `size` octets, more than the name and its NUL.
        unsafe { ptr::copy_nonoverlapping(name.as_ptr().cast(), buf, name.len()) };
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: NULL file names and buffers fail (the reference opens, or copies
    /// into, NULL).
    #[test]
    #[cfg_attr(miri, ignore = "reads the environment, which checks the process's privileges")]
    fn null_names_and_buffers_fail() {
        // SAFETY: NULL is the case under test.
        assert_eq!(unsafe { RAND_load_file(ptr::null(), -1) }, -1);
        // SAFETY: as above.
        assert_eq!(unsafe { RAND_write_file(ptr::null()) }, -1);
        // SAFETY: as above.
        assert!(unsafe { RAND_file_name(ptr::null_mut(), 100) }.is_null());
        crate::err::take_all();
    }
}
