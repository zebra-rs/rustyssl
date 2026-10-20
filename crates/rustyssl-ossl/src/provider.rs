//! Library contexts and providers.

use core::ffi::{c_int, c_void};

use crate::abi::OSSL_PROVIDER;
use crate::ffi;
use crate::util::{cstring, string_at};

crate::handle!(
    /// An owned `OSSL_LIB_CTX`.
    LibCtx, OSSL_LIB_CTX, OSSL_LIB_CTX_free
);

impl LibCtx {
    /// `OSSL_LIB_CTX_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::OSSL_LIB_CTX_new() })
    }
}

crate::handle!(
    /// A loaded provider, unloaded (`OSSL_PROVIDER_unload`) when dropped.
    Provider, OSSL_PROVIDER, OSSL_PROVIDER_unload
);

impl Provider {
    /// `OSSL_PROVIDER_load(libctx, name)`; NULL `libctx` is the default context.
    pub fn load(libctx: Option<&LibCtx>, name: &str) -> Option<Self> {
        let n = cstring(name)?;
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: ctx is NULL or live; n is a valid C string.
        Self::from_ptr(unsafe { ffi::OSSL_PROVIDER_load(ctx, n.as_ptr()) })
    }
}

/// `OSSL_PROVIDER_set_default_search_path(libctx, path)`.
pub fn set_default_search_path(libctx: Option<&LibCtx>, path: Option<&str>) -> bool {
    let p = match path {
        Some(p) => match cstring(p) {
            Some(c) => Some(c),
            None => return false,
        },
        None => None,
    };
    let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
    let pp = p.as_ref().map_or(core::ptr::null(), |c| c.as_ptr());
    // SAFETY: ctx is NULL or live; pp is NULL or a valid C string.
    unsafe { ffi::OSSL_PROVIDER_set_default_search_path(ctx, pp) == 1 }
}

/// A provider seen by [`for_each`], borrowed for the callback.
pub struct ProviderRef(*mut OSSL_PROVIDER);

impl ProviderRef {
    /// `OSSL_PROVIDER_get0_name`.
    pub fn name(&self) -> String {
        // SAFETY: the provider is live for the callback; the name is owned by it.
        string_at(unsafe { ffi::OSSL_PROVIDER_get0_name(self.0) }).unwrap_or_default()
    }

    /// `OSSL_PROVIDER_add_conf_parameter`.
    pub fn add_conf_parameter(&self, key: &str, value: &str) -> bool {
        let (Some(k), Some(v)) = (cstring(key), cstring(value)) else {
            return false;
        };
        // SAFETY: the provider is live; both strings are valid C strings (copied by the call).
        unsafe { ffi::OSSL_PROVIDER_add_conf_parameter(self.0, k.as_ptr(), v.as_ptr()) == 1 }
    }
}

type Visitor<'a> = &'a mut dyn FnMut(&ProviderRef) -> bool;

unsafe extern "C" fn visit(provider: *mut OSSL_PROVIDER, data: *mut c_void) -> c_int {
    // SAFETY: data is the `&mut Visitor` that for_each passed, live for the whole call.
    let f = unsafe { &mut *data.cast::<Visitor<'_>>() };
    // A panic must not unwind into C.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&ProviderRef(provider)))) {
        Ok(true) => 1,
        _ => 0,
    }
}

/// `OSSL_PROVIDER_do_all(libctx, cb, data)`: `f` returns whether to go on; the result is
/// what the call returns.
pub fn for_each(libctx: Option<&LibCtx>, mut f: impl FnMut(&ProviderRef) -> bool) -> bool {
    let mut visitor: Visitor<'_> = &mut f;
    let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
    let data: *mut Visitor<'_> = &mut visitor;
    // SAFETY: ctx is NULL or live; visit gets data back, which outlives the call, and doesn't
    // keep it.
    unsafe { ffi::OSSL_PROVIDER_do_all(ctx, Some(visit), data.cast()) == 1 }
}
