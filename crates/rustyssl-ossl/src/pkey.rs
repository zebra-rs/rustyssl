//! Keys and the signing context.

use core::ffi::c_char;

use crate::abi::{EVP_PKEY, EVP_PKEY_CTX};
use crate::ffi;
use crate::provider::LibCtx;
use crate::util::{cstring, string_at};

crate::handle!(
    /// An owned `EVP_PKEY`.
    Pkey, EVP_PKEY, EVP_PKEY_free
);

impl Pkey {
    /// Takes ownership of a key the caller got from the library.
    pub fn from_raw(p: *mut EVP_PKEY) -> Option<Self> {
        Self::from_ptr(p)
    }

    /// `EVP_PKEY_is_a`.
    pub fn is_a(&self, name: &str) -> bool {
        let Some(n) = cstring(name) else {
            return false;
        };
        // SAFETY: the key is live; n is a valid C string.
        unsafe { ffi::EVP_PKEY_is_a(self.as_ptr(), n.as_ptr()) == 1 }
    }

    /// `EVP_PKEY_get_default_digest_name`: what it returns, and the name.
    pub fn default_digest_name(&self) -> (i32, String) {
        let mut buf = [0 as c_char; 80];
        // SAFETY: the key is live; buf is writable for its length.
        let r = unsafe {
            ffi::EVP_PKEY_get_default_digest_name(self.as_ptr(), buf.as_mut_ptr(), buf.len())
        };
        let name = if r > 0 {
            string_at(buf.as_ptr()).unwrap_or_default()
        } else {
            String::new()
        };
        (r, name)
    }
}

crate::handle!(
    /// An owned `EVP_MD_CTX`.
    MdCtx, EVP_MD_CTX, EVP_MD_CTX_free
);

impl MdCtx {
    /// `EVP_MD_CTX_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::EVP_MD_CTX_new() })
    }

    /// `EVP_DigestSignInit_ex(ctx, &pctx, md, libctx, propq, pkey, NULL)`: whether it
    /// succeeded, and the key context it set up (owned by `self`).
    pub fn digest_sign_init(
        &self,
        md: Option<&str>,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
        pkey: &Pkey,
    ) -> (bool, PkeyCtxRef<'_>) {
        let md = md.map(cstring);
        let propq = propq.map(cstring);
        if md.as_ref().is_some_and(Option::is_none) || propq.as_ref().is_some_and(Option::is_none) {
            return (
                false,
                PkeyCtxRef(core::ptr::null_mut(), core::marker::PhantomData),
            );
        }
        let mdp = md
            .as_ref()
            .and_then(|m| m.as_ref())
            .map_or(core::ptr::null(), |m| m.as_ptr());
        let pqp = propq
            .as_ref()
            .and_then(|p| p.as_ref())
            .map_or(core::ptr::null(), |p| p.as_ptr());
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        let mut pctx: *mut EVP_PKEY_CTX = core::ptr::null_mut();
        // SAFETY: every pointer is live or NULL where the API allows it; pctx is a valid
        // out-pointer, and what it receives belongs to self.
        let r = unsafe {
            ffi::EVP_DigestSignInit_ex(
                self.as_ptr(),
                &mut pctx,
                mdp,
                ctx,
                pqp,
                pkey.as_ptr(),
                core::ptr::null(),
            )
        };
        (r == 1, PkeyCtxRef(pctx, core::marker::PhantomData))
    }
}

/// An `EVP_PKEY_CTX` borrowed from its owner (an `EVP_MD_CTX`'s, ...); it may be NULL.
#[derive(Clone, Copy)]
pub struct PkeyCtxRef<'a>(*mut EVP_PKEY_CTX, core::marker::PhantomData<&'a ()>);

impl PkeyCtxRef<'_> {
    /// `EVP_PKEY_CTX_ctrl_str(ctx, type, value)`: what it returns (-1 for NULL, as the
    /// library does for a context it can't use).
    pub fn ctrl_str(self, kind: &str, value: &str) -> i32 {
        let (Some(k), Some(v)) = (cstring(kind), cstring(value)) else {
            return -1;
        };
        if self.0.is_null() {
            return -1;
        }
        // SAFETY: the context is live (borrowed from its owner); the strings are valid.
        unsafe { ffi::EVP_PKEY_CTX_ctrl_str(self.0, k.as_ptr(), v.as_ptr()) }
    }
}

impl Pkey {
    /// `PEM_write_bio_PUBKEY`: what it returns.
    pub fn write_pubkey_pem(&self, out: &crate::Bio) -> core::ffi::c_int {
        // SAFETY: both are live.
        unsafe { ffi::PEM_write_bio_PUBKEY(out.as_ptr(), self.as_ptr()) }
    }
}

impl Pkey {
    /// `EVP_PKEY_print_params(out, pkey, indent, NULL)`.
    pub fn print_params(&self, out: &crate::Bio, indent: core::ffi::c_int) -> core::ffi::c_int {
        // SAFETY: both are live; no print context.
        unsafe {
            ffi::EVP_PKEY_print_params(out.as_ptr(), self.as_ptr(), indent, core::ptr::null_mut())
        }
    }

    /// `EVP_PKEY_print_public(out, pkey, indent, NULL)`.
    pub fn print_public(&self, out: &crate::Bio, indent: core::ffi::c_int) -> core::ffi::c_int {
        // SAFETY: as above.
        unsafe {
            ffi::EVP_PKEY_print_public(out.as_ptr(), self.as_ptr(), indent, core::ptr::null_mut())
        }
    }

    /// `EVP_PKEY_print_private(out, pkey, indent, NULL)`.
    pub fn print_private(&self, out: &crate::Bio, indent: core::ffi::c_int) -> core::ffi::c_int {
        // SAFETY: as above.
        unsafe {
            ffi::EVP_PKEY_print_private(out.as_ptr(), self.as_ptr(), indent, core::ptr::null_mut())
        }
    }

    /// `PEM_write_bio_Parameters`.
    pub fn write_params_pem(&self, out: &crate::Bio) -> core::ffi::c_int {
        // SAFETY: both are live.
        unsafe { ffi::PEM_write_bio_Parameters(out.as_ptr(), self.as_ptr()) }
    }

    /// `PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, NULL, NULL)`.
    pub fn write_private_pem(&self, out: &crate::Bio) -> core::ffi::c_int {
        // SAFETY: both are live; no cipher or callback.
        unsafe {
            ffi::PEM_write_bio_PrivateKey(
                out.as_ptr(),
                self.as_ptr(),
                core::ptr::null(),
                core::ptr::null_mut(),
                0,
                None,
                core::ptr::null_mut(),
            )
        }
    }
}
