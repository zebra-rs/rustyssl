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
