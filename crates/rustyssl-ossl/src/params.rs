//! `OSSL_PARAM` lists the caller builds: constructed values, and values parsed from text
//! against a list of definitions (`OSSL_PARAM_allocate_from_text`).

use core::ffi::{c_char, c_int, c_uint, c_void};
use std::ffi::CString;

use crate::abi::{OSSL_PARAM, OSSL_PARAM_UTF8_STRING};
use crate::ffi;
use crate::util::openssl_free;

/// A list of parameter definitions the library owns (`EVP_MAC_settable_ctx_params`, ...),
/// borrowed from the object that gave it; it may be NULL.
#[derive(Clone, Copy)]
pub struct Defs<'a>(
    pub(crate) *const OSSL_PARAM,
    pub(crate) core::marker::PhantomData<&'a ()>,
);

/// An owned, END-terminated `OSSL_PARAM` list. Its keys and values live as long as it does,
/// at addresses that don't move.
pub struct Params {
    list: Vec<OSSL_PARAM>,
    keys: Vec<CString>,
    bytes: Vec<Box<[u8]>>,
    /// Boxed so each value keeps its address as the list grows.
    #[allow(clippy::vec_box)]
    uints: Vec<Box<c_uint>>,
    /// Values the library allocated (`OSSL_PARAM_allocate_from_text`), freed with
    /// `OPENSSL_free`.
    allocated: Vec<*mut c_void>,
}

const END: OSSL_PARAM = OSSL_PARAM {
    key: core::ptr::null(),
    data_type: 0,
    data: core::ptr::null_mut(),
    data_size: 0,
    return_size: 0,
};

impl Default for Params {
    fn default() -> Self {
        Self::new()
    }
}

impl Params {
    /// An empty list (END only).
    pub fn new() -> Self {
        Params {
            list: vec![END],
            keys: Vec::new(),
            bytes: Vec::new(),
            uints: Vec::new(),
            allocated: Vec::new(),
        }
    }

    fn push(&mut self, k: CString, p: OSSL_PARAM) {
        self.keys.push(k);
        let at = self.list.len().saturating_sub(1);
        self.list.insert(at, p);
    }

    /// `OSSL_PARAM_construct_utf8_string(key, value, 0)`.
    pub fn utf8(mut self, key: &str, value: &str) -> Self {
        let (Ok(k), Ok(v)) = (CString::new(key), CString::new(value)) else {
            return self;
        };
        let mut b = v.into_bytes_with_nul().into_boxed_slice();
        // SAFETY: k and b (a NUL-terminated string) live as long as the list, at addresses
        // that don't move.
        let p =
            unsafe { ffi::OSSL_PARAM_construct_utf8_string(k.as_ptr(), b.as_mut_ptr().cast(), 0) };
        self.bytes.push(b);
        self.push(k, p);
        self
    }

    /// `OSSL_PARAM_construct_octet_string(key, value, len)`.
    pub fn octets(mut self, key: &str, value: &[u8]) -> Self {
        let Ok(k) = CString::new(key) else {
            return self;
        };
        let mut b = value.to_vec().into_boxed_slice();
        // SAFETY: as above; b holds len bytes.
        let p = unsafe {
            ffi::OSSL_PARAM_construct_octet_string(k.as_ptr(), b.as_mut_ptr().cast(), b.len())
        };
        self.bytes.push(b);
        self.push(k, p);
        self
    }

    /// `OSSL_PARAM_construct_uint(key, &value)`.
    pub fn uint(mut self, key: &str, value: c_uint) -> Self {
        let Ok(k) = CString::new(key) else {
            return self;
        };
        let mut b = Box::new(value);
        // SAFETY: as above; b is an aligned unsigned int.
        let p = unsafe { ffi::OSSL_PARAM_construct_uint(k.as_ptr(), &mut *b) };
        self.uints.push(b);
        self.push(k, p);
        self
    }

    /// The list, for the C API (END-terminated, owned by `self`).
    pub fn as_ptr(&self) -> *const OSSL_PARAM {
        self.list.as_ptr()
    }

    /// `app_params_new_from_opts`: each `name:value` of `opts`, parsed against `defs`
    /// (`OSSL_PARAM_allocate_from_text`). On failure, the option that failed and whether its
    /// name was found (an option without `:` counts as found).
    pub fn from_text(opts: &[String], defs: Defs<'_>) -> Result<Params, (String, bool)> {
        let mut params = Params::new();
        for opt in opts {
            let Some((key, value)) = opt.split_once(':') else {
                return Err((opt.clone(), true));
            };
            let (Ok(k), Ok(v)) = (CString::new(key), CString::new(value)) else {
                return Err((opt.clone(), true));
            };
            let mut p = END;
            let mut found: c_int = 1;
            // SAFETY: p is a valid out-parameter; defs is NULL or a live END-terminated list;
            // k and v are valid C strings of the lengths given. On success p.data is
            // allocated for the caller.
            let ok = unsafe {
                ffi::OSSL_PARAM_allocate_from_text(
                    &mut p,
                    defs.0,
                    k.as_ptr(),
                    v.as_ptr(),
                    value.len(),
                    &mut found,
                )
            };
            if ok == 0 {
                return Err((opt.clone(), found != 0));
            }
            params.allocated.push(p.data);
            // The key points into the definitions, which outlive this list's use.
            let at = params.list.len().saturating_sub(1);
            params.list.insert(at, p);
        }
        Ok(params)
    }
}

impl Drop for Params {
    fn drop(&mut self) {
        for p in self.allocated.drain(..) {
            openssl_free(p);
        }
    }
}

/// The `OSSL_PARAM_UTF8_STRING` value of `key` in the list at `params` (a callback's), as
/// `OSSL_PARAM_locate_const` finds it.
///
/// # Safety
/// `params` is NULL or a live END-terminated list.
pub(crate) unsafe fn utf8_at(params: *const OSSL_PARAM, key: &core::ffi::CStr) -> Option<String> {
    // SAFETY: the caller's contract; key is a valid C string.
    let p = unsafe { ffi::OSSL_PARAM_locate_const(params, key.as_ptr()) };
    if p.is_null() {
        return None;
    }
    // SAFETY: p points into the live list.
    let p = unsafe { &*p };
    if i64::from(p.data_type) != i64::from(OSSL_PARAM_UTF8_STRING) || p.data.is_null() {
        return None;
    }
    // SAFETY: a UTF8 string parameter's data is a NUL-terminated string.
    Some(
        unsafe { core::ffi::CStr::from_ptr(p.data.cast::<c_char>()) }
            .to_string_lossy()
            .into_owned(),
    )
}
