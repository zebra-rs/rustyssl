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

use crate::provider::LibCtx;

crate::handle!(
    /// A cipher: fetched (freed when dropped) or a legacy static one (`EVP_CIPHER_free`
    /// ignores those).
    Cipher, EVP_CIPHER, EVP_CIPHER_free
);
crate::handle!(
    /// A digest, fetched or legacy (as [`Cipher`]).
    Md, EVP_MD, EVP_MD_free
);

fn propq_c(propq: Option<&str>) -> Option<Option<std::ffi::CString>> {
    match propq {
        Some(p) => cstring(p).map(Some),
        None => Some(None),
    }
}

impl Cipher {
    /// `EVP_CIPHER_fetch(libctx, name, propq)`.
    pub fn fetch(libctx: Option<&LibCtx>, name: &str, propq: Option<&str>) -> Option<Self> {
        let n = cstring(name)?;
        let pq = propq_c(propq)?;
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: ctx is NULL or live; the strings are valid or NULL.
        Self::from_ptr(unsafe {
            ffi::EVP_CIPHER_fetch(
                ctx,
                n.as_ptr(),
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
            )
        })
    }

    /// `EVP_get_cipherbyname(name)` (a legacy, static cipher).
    pub fn by_name(name: &str) -> Option<Self> {
        let n = cstring(name)?;
        // SAFETY: n is a valid C string; EVP_CIPHER_free ignores the static result.
        Self::from_ptr(unsafe { ffi::EVP_get_cipherbyname(n.as_ptr()) }.cast_mut())
    }

    /// `EVP_CIPHER_get_mode`.
    pub fn mode(&self) -> core::ffi::c_int {
        // SAFETY: the cipher is live.
        unsafe { ffi::EVP_CIPHER_get_mode(self.as_ptr()) }
    }

    /// `EVP_CIPHER_get_flags`.
    pub fn flags(&self) -> core::ffi::c_ulong {
        // SAFETY: the cipher is live.
        unsafe { ffi::EVP_CIPHER_get_flags(self.as_ptr()) }
    }
}

impl Md {
    /// `EVP_MD_fetch(libctx, name, propq)`.
    pub fn fetch(libctx: Option<&LibCtx>, name: &str, propq: Option<&str>) -> Option<Self> {
        let n = cstring(name)?;
        let pq = propq_c(propq)?;
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: as in Cipher::fetch.
        Self::from_ptr(unsafe {
            ffi::EVP_MD_fetch(
                ctx,
                n.as_ptr(),
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
            )
        })
    }

    /// `EVP_get_digestbyname(name)` (a legacy, static digest).
    pub fn by_name(name: &str) -> Option<Self> {
        let n = cstring(name)?;
        // SAFETY: n is a valid C string; EVP_MD_free ignores the static result.
        Self::from_ptr(unsafe { ffi::EVP_get_digestbyname(n.as_ptr()) }.cast_mut())
    }
}

impl Cipher {
    /// `EVP_CIPHER_get0_name`.
    pub fn name(&self) -> Option<String> {
        // SAFETY: the cipher is live; the name is static or the cipher's, and copied.
        crate::util::string_at(unsafe { ffi::EVP_CIPHER_get0_name(self.as_ptr()) })
    }

    /// `EVP_aes_256_cbc()` (a legacy, static cipher; dropping it is a no-op).
    pub fn aes_256_cbc() -> Option<Self> {
        // SAFETY: no arguments; EVP_CIPHER_free ignores the static result.
        Self::from_ptr(unsafe { ffi::EVP_aes_256_cbc() }.cast_mut())
    }
}
