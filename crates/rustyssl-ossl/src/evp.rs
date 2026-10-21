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

crate::handle!(
    /// A fetched MAC algorithm.
    Mac, EVP_MAC, EVP_MAC_free
);
crate::handle!(
    /// A MAC context.
    MacCtx, EVP_MAC_CTX, EVP_MAC_CTX_free
);

impl Mac {
    /// `EVP_MAC_fetch(libctx, name, propq)`.
    pub fn fetch(libctx: Option<&LibCtx>, name: &str, propq: Option<&str>) -> Option<Self> {
        let n = cstring(name)?;
        let pq = propq_c(propq)?;
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: as in Cipher::fetch.
        Self::from_ptr(unsafe {
            ffi::EVP_MAC_fetch(
                ctx,
                n.as_ptr(),
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
            )
        })
    }

    /// `EVP_MAC_settable_ctx_params`.
    pub fn settable_ctx_params(&self) -> crate::params::Defs<'_> {
        // SAFETY: the MAC is live; the list (or NULL) is owned by it.
        crate::params::Defs(
            unsafe { ffi::EVP_MAC_settable_ctx_params(self.as_ptr()) },
            core::marker::PhantomData,
        )
    }
}

impl MacCtx {
    /// `EVP_MAC_CTX_new(mac)`.
    pub fn new(mac: &Mac) -> Option<Self> {
        // SAFETY: the MAC is live; the context takes its own reference.
        Self::from_ptr(unsafe { ffi::EVP_MAC_CTX_new(mac.as_ptr()) })
    }

    /// `EVP_MAC_CTX_set_params(ctx, params)`.
    pub fn set_params(&self, params: &crate::params::Params) -> bool {
        // SAFETY: the context is live; the list is END-terminated and live.
        unsafe { ffi::EVP_MAC_CTX_set_params(self.as_ptr(), params.as_ptr()) == 1 }
    }

    /// `EVP_MAC_CTX_dup(ctx)`.
    pub fn dup(&self) -> Option<Self> {
        // SAFETY: the context is live.
        Self::from_ptr(unsafe { ffi::EVP_MAC_CTX_dup(self.as_ptr()) })
    }

    /// `EVP_MAC_init(ctx, NULL, 0, NULL)`: with the key already set.
    pub fn init(&self) -> bool {
        // SAFETY: the context is live; no key and no parameters.
        unsafe { ffi::EVP_MAC_init(self.as_ptr(), core::ptr::null(), 0, core::ptr::null()) == 1 }
    }

    /// `EVP_MAC_update(ctx, data, len)`.
    pub fn update(&self, data: &[u8]) -> bool {
        // SAFETY: the context is live; data is valid for its length.
        unsafe { ffi::EVP_MAC_update(self.as_ptr(), data.as_ptr(), data.len()) == 1 }
    }

    /// `EVP_MAC_final(ctx, out, &outl, out.len())`: the length written, on success.
    pub fn finish(&self, out: &mut [u8]) -> Option<usize> {
        let mut outl = 0usize;
        // SAFETY: the context is live; out is writable for its length.
        let ok = unsafe {
            ffi::EVP_MAC_final(self.as_ptr(), out.as_mut_ptr(), &mut outl, out.len()) == 1
        };
        ok.then_some(outl.min(out.len()))
    }

    /// `EVP_MAC_CTX_get_mac_size`.
    pub fn mac_size(&self) -> usize {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_MAC_CTX_get_mac_size(self.as_ptr()) }
    }
}
