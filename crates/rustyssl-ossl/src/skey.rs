//! Opaque symmetric keys (`EVP_SKEY`) and their key managers.

use crate::ffi;
use crate::params::{Params, ParamsRef};
use crate::provider::LibCtx;
use crate::util::{cstring, string_at};

crate::handle!(
    /// An owned `EVP_SKEYMGMT`.
    SkeyMgmt, EVP_SKEYMGMT, EVP_SKEYMGMT_free
);
crate::handle!(
    /// An owned `EVP_SKEY`.
    Skey, EVP_SKEY, EVP_SKEY_free
);

fn propq_ptr(p: &Option<std::ffi::CString>) -> *const core::ffi::c_char {
    p.as_ref().map_or(core::ptr::null(), |c| c.as_ptr())
}

impl SkeyMgmt {
    /// `EVP_SKEYMGMT_fetch(libctx, name, propq)`.
    pub fn fetch(libctx: Option<&LibCtx>, name: &str, propq: Option<&str>) -> Option<Self> {
        let n = cstring(name)?;
        let q = match propq {
            Some(q) => Some(cstring(q)?),
            None => None,
        };
        let lc = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: lc is NULL or live; the strings are valid or NULL.
        Self::from_ptr(unsafe { ffi::EVP_SKEYMGMT_fetch(lc, n.as_ptr(), propq_ptr(&q)) })
    }

    /// `EVP_SKEYMGMT_get0_gen_settable_params`.
    pub fn gen_settable_params(&self) -> ParamsRef<'_> {
        // SAFETY: self is live; the array belongs to it.
        ParamsRef::from_raw(unsafe { ffi::EVP_SKEYMGMT_get0_gen_settable_params(self.as_ptr()) })
    }
}

impl Skey {
    /// `EVP_SKEY_generate(libctx, name, propq, params)`.
    pub fn generate(
        libctx: Option<&LibCtx>,
        name: &str,
        propq: Option<&str>,
        params: Option<&Params>,
    ) -> Option<Self> {
        let n = cstring(name)?;
        let q = match propq {
            Some(q) => Some(cstring(q)?),
            None => None,
        };
        let lc = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        let pp = params.map_or(core::ptr::null(), Params::as_ptr);
        // SAFETY: lc is NULL or live; the strings are valid or NULL; pp is NULL or an ended
        // array.
        Self::from_ptr(unsafe { ffi::EVP_SKEY_generate(lc, n.as_ptr(), propq_ptr(&q), pp) })
    }

    /// `EVP_SKEY_get0_key_id`.
    pub fn key_id(&self) -> Option<String> {
        // SAFETY: self is live; the string belongs to it and is copied.
        string_at(unsafe { ffi::EVP_SKEY_get0_key_id(self.as_ptr()) })
    }

    /// `EVP_SKEY_get0_provider_name`.
    pub fn provider_name(&self) -> Option<String> {
        // SAFETY: as above.
        string_at(unsafe { ffi::EVP_SKEY_get0_provider_name(self.as_ptr()) })
    }

    /// `EVP_SKEY_get0_skeymgmt_name`.
    pub fn skeymgmt_name(&self) -> Option<String> {
        // SAFETY: as above.
        string_at(unsafe { ffi::EVP_SKEY_get0_skeymgmt_name(self.as_ptr()) })
    }
}
