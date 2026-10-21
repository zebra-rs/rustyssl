//! `OSSL_PARAM` arrays: ones the caller builds ([`ParamList`]), ones made from `name:value`
//! text against the library's descriptions ([`TextParams`]), and those descriptions
//! ([`ParamDefs`]).

use core::ffi::{CStr, c_int, c_uint};
use std::ffi::CString;

use crate::abi::OSSL_PARAM;
use crate::ffi;
use crate::util::{cstring, openssl_free, string_at};

/// An `OSSL_PARAM` array with the values it points to, ended by `OSSL_PARAM_END`.
// Boxed ints: each keeps its address while the vector grows.
#[allow(clippy::vec_box)]
pub struct ParamList {
    strings: Vec<CString>,
    ints: Vec<Box<c_int>>,
    params: Vec<OSSL_PARAM>,
}

impl Default for ParamList {
    fn default() -> Self {
        Self::new()
    }
}

impl ParamList {
    /// An empty list (just the end marker).
    pub fn new() -> Self {
        // SAFETY: no arguments.
        let end = unsafe { ffi::OSSL_PARAM_construct_end() };
        Self {
            strings: Vec::new(),
            ints: Vec::new(),
            params: vec![end],
        }
    }

    fn push(&mut self, p: OSSL_PARAM) {
        let at = self.params.len().saturating_sub(1);
        self.params.insert(at, p);
    }

    /// `OSSL_PARAM_construct_utf8_string(key, value, 0)`; `false` if `value` holds a NUL.
    pub fn utf8(&mut self, key: &'static CStr, value: &str) -> bool {
        let Some(v) = cstring(value) else {
            return false;
        };
        // SAFETY: key is static; v's buffer is kept in self (a CString's heap data doesn't
        // move with the CString), so it outlives the array.
        let p = unsafe {
            ffi::OSSL_PARAM_construct_utf8_string(key.as_ptr(), v.as_ptr().cast_mut(), 0)
        };
        self.strings.push(v);
        self.push(p);
        true
    }

    /// `OSSL_PARAM_construct_int(key, &value)`.
    pub fn int(&mut self, key: &'static CStr, value: c_int) {
        let mut b = Box::new(value);
        let ptr: *mut c_int = &mut *b;
        // SAFETY: key is static; the boxed int is kept in self at a stable address.
        let p = unsafe { ffi::OSSL_PARAM_construct_int(key.as_ptr(), ptr) };
        self.ints.push(b);
        self.push(p);
    }

    /// The array, for the C API (valid while `self` lives, unmodified).
    pub fn as_ptr(&self) -> *const OSSL_PARAM {
        self.params.as_ptr()
    }

    /// The array, for functions that take it mutably (they may set `return_size`).
    pub fn as_mut_ptr(&mut self) -> *mut OSSL_PARAM {
        self.params.as_mut_ptr()
    }
}

/// A parameter description array the library owns (`*_settable_params`, ...), borrowed for
/// the life of its owner; it may be NULL.
#[derive(Clone, Copy)]
pub struct ParamDefs<'a>(
    pub(crate) *const OSSL_PARAM,
    pub(crate) core::marker::PhantomData<&'a ()>,
);

impl ParamDefs<'_> {
    /// Whether the library returned NULL.
    pub fn is_null(self) -> bool {
        self.0.is_null()
    }

    /// Each entry's key and data type, up to the end marker.
    pub fn entries(self) -> Vec<(String, c_uint)> {
        let mut out = Vec::new();
        if self.0.is_null() {
            return out;
        }
        let mut p = self.0;
        loop {
            // SAFETY: p points into an array the library ended with a NULL key; we stop at
            // that entry, so every read is in bounds.
            let e = unsafe { &*p };
            if e.key.is_null() {
                return out;
            }
            out.push((string_at(e.key).unwrap_or_default(), e.data_type));
            // SAFETY: this entry isn't the end, so the next one is in the array.
            p = unsafe { p.add(1) };
        }
    }
}

/// `app_params_new_from_opts`' array: `OSSL_PARAM_allocate_from_text` for each `name:value`,
/// the values freed (`app_params_free`) when dropped.
pub struct TextParams {
    params: Vec<OSSL_PARAM>,
}

/// Why [`TextParams::from_opts`] failed: `found` as upstream last set it (whether the name
/// was known), and the option.
pub struct TextParamError {
    pub found: bool,
    pub opt: String,
}

impl TextParams {
    /// Each `name:value` of `opts` against `defs`.
    pub fn from_opts(opts: &[String], defs: ParamDefs<'_>) -> Result<Self, TextParamError> {
        // SAFETY: no arguments.
        let end = unsafe { ffi::OSSL_PARAM_construct_end() };
        let mut this = Self {
            params: Vec::with_capacity(opts.len() + 1),
        };
        let mut found: c_int = 1;
        for opt in opts {
            let fail = |found: c_int| TextParamError {
                found: found != 0,
                opt: opt.clone(),
            };
            let Some((name, value)) = opt.split_once(':') else {
                return Err(fail(found));
            };
            let (Some(n), Some(v)) = (cstring(name), cstring(value)) else {
                return Err(fail(found));
            };
            this.params.push(end);
            let Some(slot) = this.params.last_mut() else {
                return Err(fail(found));
            };
            // SAFETY: slot is a valid OSSL_PARAM to fill; defs is NULL or a live description
            // array; n and v are valid for the call (the library copies what it keeps).
            let r = unsafe {
                ffi::OSSL_PARAM_allocate_from_text(
                    slot,
                    defs.0,
                    n.as_ptr(),
                    v.as_ptr(),
                    value.len(),
                    &mut found,
                )
            };
            if r == 0 {
                this.params.pop();
                return Err(fail(found));
            }
        }
        this.params.push(end);
        Ok(this)
    }

    /// The array, for the C API.
    pub fn as_ptr(&self) -> *const OSSL_PARAM {
        self.params.as_ptr()
    }
}

impl Drop for TextParams {
    fn drop(&mut self) {
        for p in &self.params {
            openssl_free(p.data);
        }
    }
}

/// An `OSSL_PARAM` array made by an `OSSL_PARAM_BLD` (`OSSL_PARAM_BLD_to_param`), freed with
/// `OSSL_PARAM_free`.
pub struct BuiltParams(core::ptr::NonNull<OSSL_PARAM>);

impl BuiltParams {
    /// The array, for the C API.
    pub fn as_mut_ptr(&mut self) -> *mut OSSL_PARAM {
        self.0.as_ptr()
    }
}

impl Drop for BuiltParams {
    fn drop(&mut self) {
        // SAFETY: the array is owned by self and freed once.
        unsafe { ffi::OSSL_PARAM_free(self.0.as_ptr()) };
    }
}

crate::handle!(
    /// An owned `OSSL_PARAM_BLD`.
    ParamBld, OSSL_PARAM_BLD, OSSL_PARAM_BLD_free
);

impl ParamBld {
    /// `OSSL_PARAM_BLD_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::OSSL_PARAM_BLD_new() })
    }

    /// `OSSL_PARAM_BLD_push_BN` (the number is copied when the array is made).
    pub fn push_bn(&self, key: &'static CStr, bn: &crate::bn::Bn) -> bool {
        // SAFETY: the builder and number are live; key is static.
        unsafe { ffi::OSSL_PARAM_BLD_push_BN(self.as_ptr(), key.as_ptr(), bn.as_ptr()) == 1 }
    }

    /// `OSSL_PARAM_BLD_to_param`.
    pub fn to_param(&self) -> Option<BuiltParams> {
        // SAFETY: the builder is live; the array is ours.
        core::ptr::NonNull::new(unsafe { ffi::OSSL_PARAM_BLD_to_param(self.as_ptr()) })
            .map(BuiltParams)
    }
}
