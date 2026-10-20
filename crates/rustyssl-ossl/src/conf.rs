//! Configuration files (`NCONF_*`) and modules.

use core::ffi::{c_long, c_ulong};

use crate::abi::{CONF_VALUE, OPENSSL_STACK};
use crate::bio::Bio;
use crate::ffi;
use crate::provider::LibCtx;
use crate::util::{cstring, string_at};

crate::handle!(
    /// An owned `CONF`.
    Conf, CONF, NCONF_free
);

impl Conf {
    /// `NCONF_new_ex(libctx, NULL)`.
    pub fn new(libctx: Option<&LibCtx>) -> Option<Self> {
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: ctx is NULL or live; NULL is the default method.
        Self::from_ptr(unsafe { ffi::NCONF_new_ex(ctx, core::ptr::null_mut()) })
    }

    /// `NCONF_load_bio(conf, bio, &errorline)`: what it returns, and the line.
    pub fn load_bio(&self, bio: &Bio) -> (i32, c_long) {
        let mut line: c_long = -1;
        // SAFETY: both are live; line is a valid out-pointer.
        let r = unsafe { ffi::NCONF_load_bio(self.as_ptr(), bio.as_ptr(), &mut line) };
        (r, line)
    }

    /// `NCONF_get_string(conf, group, name)`.
    pub fn get_string(&self, group: Option<&str>, name: &str) -> Option<String> {
        let g = match group {
            Some(g) => Some(cstring(g)?),
            None => None,
        };
        let n = cstring(name)?;
        // SAFETY: the conf is live; the strings are valid or NULL; the result is owned by
        // the conf and copied at once.
        string_at(unsafe {
            ffi::NCONF_get_string(
                self.as_ptr(),
                g.as_ref().map_or(core::ptr::null(), |g| g.as_ptr()),
                n.as_ptr(),
            )
        })
    }

    /// `NCONF_get_number_e(conf, group, name, &result)`.
    pub fn get_number(&self, group: Option<&str>, name: &str) -> Option<c_long> {
        let g = match group {
            Some(g) => Some(cstring(g)?),
            None => None,
        };
        let n = cstring(name)?;
        let mut v: c_long = 0;
        // SAFETY: as above; v is a valid out-pointer.
        let ok = unsafe {
            ffi::NCONF_get_number_e(
                self.as_ptr(),
                g.as_ref().map_or(core::ptr::null(), |g| g.as_ptr()),
                n.as_ptr(),
                &mut v,
            )
        };
        (ok == 1).then_some(v)
    }

    /// `NCONF_get_section(conf, section)`: its (name, value) pairs.
    pub fn get_section(&self, section: &str) -> Option<Vec<(String, String)>> {
        let s = cstring(section)?;
        // SAFETY: the conf is live; the stack is owned by the conf.
        let sk = unsafe { ffi::NCONF_get_section(self.as_ptr(), s.as_ptr()) };
        if sk.is_null() {
            return None;
        }
        let st = sk.cast::<OPENSSL_STACK>();
        // SAFETY: st is live.
        let n = unsafe { ffi::OPENSSL_sk_num(st) };
        let mut out = Vec::new();
        for i in 0..n.max(0) {
            // SAFETY: i is in range; members are CONF_VALUEs owned by the conf.
            let v = unsafe { ffi::OPENSSL_sk_value(st, i) }.cast::<CONF_VALUE>();
            if v.is_null() {
                continue;
            }
            // SAFETY: v is live; its fields are C strings or NULL.
            let cv = unsafe { &*v };
            let (n, val) = (cv.name, cv.value);
            let (name, value) = (string_at(n), string_at(val));
            out.push((name.unwrap_or_default(), value.unwrap_or_default()));
        }
        Some(out)
    }

    /// `CONF_modules_load(conf, NULL, flags)`: what it returns.
    pub fn modules_load(&self, flags: c_ulong) -> i32 {
        // SAFETY: the conf is live; NULL is the default application name.
        unsafe { ffi::CONF_modules_load(self.as_ptr(), core::ptr::null(), flags) }
    }
}

/// The bytes of the C string at `p` (copied), or `None` for NULL.
fn bytes_at(p: *const core::ffi::c_char) -> Option<Vec<u8>> {
    if p.is_null() {
        return None;
    }
    // SAFETY: p is non-NULL and a C string the conf owns, valid for this call.
    Some(unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes().to_vec())
}

impl Conf {
    /// `NCONF_load(conf, file, &eline)`: what it returns, and the line.
    pub fn load(&self, file: &str) -> (i32, c_long) {
        let mut line: c_long = 0;
        let Some(f) = cstring(file) else {
            return (0, line);
        };
        // SAFETY: the conf is live; f is a valid C string; line is a valid out-pointer.
        let r = unsafe { ffi::NCONF_load(self.as_ptr(), f.as_ptr(), &mut line) };
        (r, line)
    }

    /// `NCONF_get_section_names(conf)`: the names, sorted as the library sorts them.
    pub fn section_names(&self) -> Option<Vec<Vec<u8>>> {
        // SAFETY: the conf is live; the stack is the caller's (freed below), its strings the
        // conf's.
        let sk = unsafe { ffi::NCONF_get_section_names(self.as_ptr()) };
        if sk.is_null() {
            return None;
        }
        let st = sk.cast::<OPENSSL_STACK>();
        // SAFETY: st is live.
        let n = unsafe { ffi::OPENSSL_sk_num(st) };
        let mut out = Vec::new();
        for i in 0..n.max(0) {
            // SAFETY: i is in range; each member is a C string owned by the conf.
            let p = unsafe { ffi::OPENSSL_sk_value(st, i) };
            out.push(bytes_at(p.cast()).unwrap_or_default());
        }
        // SAFETY: the stack (not its strings) is owned here and freed once.
        unsafe { ffi::OPENSSL_sk_free(st) };
        Some(out)
    }

    /// `NCONF_get_section(conf, section)`: its (name, value) pairs, as bytes.
    pub fn get_section_bytes(&self, section: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let Ok(s) = std::ffi::CString::new(section) else {
            return Vec::new();
        };
        // SAFETY: the conf is live; the stack is owned by the conf.
        let sk = unsafe { ffi::NCONF_get_section(self.as_ptr(), s.as_ptr()) };
        let mut out = Vec::new();
        if sk.is_null() {
            return out;
        }
        let st = sk.cast::<OPENSSL_STACK>();
        // SAFETY: st is live.
        let n = unsafe { ffi::OPENSSL_sk_num(st) };
        for i in 0..n.max(0) {
            // SAFETY: i is in range; members are CONF_VALUEs owned by the conf.
            let v = unsafe { ffi::OPENSSL_sk_value(st, i) }.cast::<CONF_VALUE>();
            if v.is_null() {
                continue;
            }
            // SAFETY: v is live; its fields are C strings or NULL.
            let cv = unsafe { &*v };
            out.push((
                bytes_at(cv.name).unwrap_or_default(),
                bytes_at(cv.value).unwrap_or_default(),
            ));
        }
        out
    }
}

/// `CONF_modules_unload(all)`.
pub fn modules_unload(all: bool) {
    // SAFETY: a plain integer argument.
    unsafe { ffi::CONF_modules_unload(core::ffi::c_int::from(all)) };
}
