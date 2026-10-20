//! EVP lookups.

use crate::ffi;
use crate::util::cstring;

/// Whether `EVP_get_digestbyname(name)` finds a digest.
pub fn digest_exists(name: &str) -> bool {
    let Some(n) = cstring(name) else {
        return false;
    };
    // SAFETY: n is a valid C string; the result is a static (or NULL), not freed.
    !unsafe { ffi::EVP_get_digestbyname(n.as_ptr()) }.is_null()
}

/// Whether `EVP_get_cipherbyname(name)` finds a cipher.
pub fn cipher_exists(name: &str) -> bool {
    let Some(n) = cstring(name) else {
        return false;
    };
    // SAFETY: as above.
    !unsafe { ffi::EVP_get_cipherbyname(n.as_ptr()) }.is_null()
}
