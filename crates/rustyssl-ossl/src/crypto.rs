//! Library-wide calls: initialization, version information, secure memory, configuration.

use core::ffi::c_int;

use crate::ffi;
use crate::util::{string_at, take_string};

/// `OPENSSL_init_ssl(opts, NULL)`.
pub fn init_ssl(opts: u64) -> bool {
    // SAFETY: NULL settings are allowed.
    unsafe { ffi::OPENSSL_init_ssl(opts, core::ptr::null()) == 1 }
}

/// `OpenSSL_version(t)`.
pub fn version(t: c_int) -> String {
    // SAFETY: OpenSSL_version returns a static string for any t.
    string_at(unsafe { ffi::OpenSSL_version(t) }).unwrap_or_default()
}

/// `OPENSSL_info(t)`.
pub fn info(t: c_int) -> Option<String> {
    // SAFETY: OPENSSL_info returns a static string or NULL for any t.
    string_at(unsafe { ffi::OPENSSL_info(t) })
}

/// `BN_options()`.
pub fn bn_options() -> String {
    // SAFETY: BN_options returns a static string.
    string_at(unsafe { ffi::BN_options() }).unwrap_or_default()
}

/// `CONF_get1_default_config_file()`.
pub fn default_config_file() -> Option<String> {
    // SAFETY: no arguments; the result is the caller's to free, which take_string does.
    take_string(unsafe { ffi::CONF_get1_default_config_file() })
}

/// `CRYPTO_secure_malloc_init(size, minsize)`: what it returns.
pub fn secure_malloc_init(size: usize, minsize: usize) -> c_int {
    // SAFETY: plain integer arguments.
    unsafe { ffi::CRYPTO_secure_malloc_init(size, minsize) }
}

/// `CRYPTO_secure_malloc_done()`.
pub fn secure_malloc_done() {
    // SAFETY: no arguments.
    unsafe { ffi::CRYPTO_secure_malloc_done() };
}

/// `OPENSSL_hexstr2buf(s, &len)`.
pub fn hexstr2buf(s: &str) -> Option<Vec<u8>> {
    let c = crate::cstring(s)?;
    let mut len: core::ffi::c_long = 0;
    // SAFETY: c is a valid C string; len is a valid out-pointer; the buffer is the caller's.
    let p = unsafe { ffi::OPENSSL_hexstr2buf(c.as_ptr(), &mut len) };
    if p.is_null() {
        return None;
    }
    let n = usize::try_from(len).unwrap_or(0);
    // SAFETY: p holds len bytes.
    let v = unsafe { core::slice::from_raw_parts(p, n) }.to_vec();
    crate::util::openssl_free(p.cast());
    Some(v)
}

/// `OPENSSL_buf2hexstr(buf, len)`: `AA:BB:...`.
pub fn buf2hexstr(buf: &[u8]) -> Option<String> {
    let n = core::ffi::c_long::try_from(buf.len()).ok()?;
    // SAFETY: buf is valid for n bytes; the string is ours to free, which take_string does.
    take_string(unsafe { ffi::OPENSSL_buf2hexstr(buf.as_ptr(), n) })
}
