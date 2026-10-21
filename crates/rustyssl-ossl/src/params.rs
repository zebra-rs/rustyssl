//! `OSSL_PARAM` arrays: the library's descriptor tables (borrowed), lists made from text
//! (`OSSL_PARAM_allocate_from_text`), query arrays with their own buffers, lists the caller
//! builds ([`ParamList`]), and arrays from an `OSSL_PARAM_BLD` ([`ParamBld`]).

use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::ffi::CString;

use crate::abi::{
    OSSL_PARAM, OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_PTR, OSSL_PARAM_OCTET_STRING,
    OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_PTR, OSSL_PARAM_UTF8_STRING,
};
use crate::ffi;
use crate::util::{cstring, openssl_free, string_at};

/// `OSSL_PARAM_END`.
const END: OSSL_PARAM = OSSL_PARAM {
    key: core::ptr::null(),
    data_type: 0,
    data: core::ptr::null_mut(),
    data_size: 0,
    return_size: 0,
};

/// A parameter array the library owns (an algorithm's settable or gettable table, ...),
/// borrowed; it may be NULL.
#[derive(Clone, Copy)]
pub struct ParamsRef<'a>(*const OSSL_PARAM, core::marker::PhantomData<&'a ()>);

impl<'a> ParamsRef<'a> {
    /// An array the caller keeps alive for `'a` (NULL allowed).
    pub(crate) fn from_raw(p: *const OSSL_PARAM) -> Self {
        Self(p, core::marker::PhantomData)
    }

    /// The array, for the C API.
    pub fn as_ptr(self) -> *const OSSL_PARAM {
        self.0
    }

    pub fn is_null(self) -> bool {
        self.0.is_null()
    }

    /// Its entries, up to the end marker (none for NULL).
    pub fn iter(self) -> impl Iterator<Item = ParamRef<'a>> {
        let mut p = self.0;
        core::iter::from_fn(move || {
            if p.is_null() {
                return None;
            }
            // SAFETY: p points into a live array that ends with an entry whose key is NULL,
            // and is never advanced past that entry.
            let key = unsafe { (*p).key };
            if key.is_null() {
                return None;
            }
            let here = ParamRef(p, core::marker::PhantomData);
            // SAFETY: the entry isn't the end marker, so the next one is in the array.
            p = unsafe { p.add(1) };
            Some(here)
        })
    }

    /// `OSSL_PARAM_locate_const(params, key)`.
    pub fn locate(self, key: &str) -> Option<ParamRef<'a>> {
        let k = cstring(key)?;
        // SAFETY: the array is NULL or live and terminated; k is a valid C string.
        let p = unsafe { ffi::OSSL_PARAM_locate_const(self.0, k.as_ptr()) };
        (!p.is_null()).then_some(ParamRef(p, core::marker::PhantomData))
    }
}

/// One entry of a parameter array, borrowed.
#[derive(Clone, Copy)]
pub struct ParamRef<'a>(*const OSSL_PARAM, core::marker::PhantomData<&'a ()>);

/// An entry's value, as `print_param_value` reads it.
#[derive(Debug, PartialEq)]
pub enum Value {
    /// An unsigned integer (`None`: `OSSL_PARAM_get_uint64` failed).
    Unsigned(Option<u64>),
    /// A signed integer (`None`: `OSSL_PARAM_get_int64` failed).
    Signed(Option<i64>),
    /// A UTF-8 or octet string, direct or through a pointer: `Err(())` when the pointer to
    /// it is NULL, `Ok(None)` when it is NULL, else its `return_size` bytes.
    Bytes {
        utf8: bool,
        bytes: Result<Option<Vec<u8>>, ()>,
    },
    /// Another type.
    Unknown,
}

impl ParamRef<'_> {
    fn get(&self) -> &OSSL_PARAM {
        // SAFETY: the entry is live for the borrow.
        unsafe { &*self.0 }
    }

    /// The key.
    pub fn key(&self) -> String {
        string_at(self.get().key).unwrap_or_default()
    }

    pub fn data_type(&self) -> c_uint {
        self.get().data_type
    }

    pub fn data_size(&self) -> usize {
        self.get().data_size
    }

    pub fn return_size(&self) -> usize {
        self.get().return_size
    }

    /// The C string at `data` (a UTF-8 string parameter's value, as `%s` prints it).
    pub fn data_string(&self) -> Option<String> {
        string_at(self.get().data.cast_const().cast())
    }

    /// The value (of a parameter the library filled in).
    pub fn value(&self) -> Value {
        let p = self.get();
        let is = |t: c_int| c_uint::try_from(t).is_ok_and(|t| t == p.data_type);
        if is(OSSL_PARAM_UNSIGNED_INTEGER) {
            let mut u = 0u64;
            // SAFETY: the entry is live; u is a valid out-pointer.
            let ok = unsafe { ffi::OSSL_PARAM_get_uint64(self.0, &mut u) } == 1;
            return Value::Unsigned(ok.then_some(u));
        }
        if is(OSSL_PARAM_INTEGER) {
            let mut i = 0i64;
            // SAFETY: as above.
            let ok = unsafe { ffi::OSSL_PARAM_get_int64(self.0, &mut i) } == 1;
            return Value::Signed(ok.then_some(i));
        }
        let (utf8, by_ptr) = if is(OSSL_PARAM_UTF8_PTR) {
            (true, true)
        } else if is(OSSL_PARAM_UTF8_STRING) {
            (true, false)
        } else if is(OSSL_PARAM_OCTET_PTR) {
            (false, true)
        } else if is(OSSL_PARAM_OCTET_STRING) {
            (false, false)
        } else {
            return Value::Unknown;
        };
        let data: *const u8 = if by_ptr {
            if p.data.is_null() {
                return Value::Bytes {
                    utf8,
                    bytes: Err(()),
                };
            }
            // SAFETY: a pointer parameter's data is a pointer to the value.
            unsafe { *p.data.cast::<*const u8>() }
        } else {
            p.data.cast_const().cast()
        };
        if data.is_null() {
            return Value::Bytes {
                utf8,
                bytes: Ok(None),
            };
        }
        // SAFETY: the library filled return_size bytes of the value at data.
        let v = unsafe { core::slice::from_raw_parts(data, p.return_size) }.to_vec();
        Value::Bytes {
            utf8,
            bytes: Ok(Some(v)),
        }
    }
}

/// A parameter list made from `key:value` texts (`app_params_new_from_opts`), each value
/// allocated by `OSSL_PARAM_allocate_from_text` and freed with the list.
pub struct Params {
    params: Vec<OSSL_PARAM>,
    _keys: Vec<CString>,
}

/// Why [`Params::from_text`] failed: the option and its index, and `found` as upstream last
/// set it (whether a key was known; it carries over from earlier options).
#[derive(Debug)]
pub struct TextError {
    pub index: usize,
    pub found: bool,
    pub opt: String,
}

impl Params {
    /// Each `key:value` of `opts` against `defs`, as `app_params_new_from_opts` does.
    pub fn from_text(defs: ParamsRef<'_>, opts: &[String]) -> Result<Self, TextError> {
        let mut out = Params {
            params: Vec::with_capacity(opts.len() + 1),
            _keys: Vec::new(),
        };
        let mut found: c_int = 1;
        for (index, opt) in opts.iter().enumerate() {
            let fail = |found: c_int| TextError {
                index,
                found: found != 0,
                opt: opt.clone(),
            };
            let Some((key, value)) = opt.split_once(':') else {
                return Err(fail(found));
            };
            let (Some(k), Some(v)) = (cstring(key), cstring(value)) else {
                return Err(fail(found));
            };
            let mut p = END;
            // SAFETY: p is a valid entry to fill; defs is NULL or a live, terminated array;
            // k and v are valid C strings, v of the length given.
            let ok = unsafe {
                ffi::OSSL_PARAM_allocate_from_text(
                    &mut p,
                    defs.as_ptr(),
                    k.as_ptr(),
                    v.as_ptr(),
                    value.len(),
                    &mut found,
                )
            } == 1;
            if !ok {
                return Err(fail(found));
            }
            // The entry's key points into its definition (`defs`), which outlives the list;
            // keep ours anyway in case the library used it.
            out._keys.push(k);
            out.params.push(p);
        }
        out.params.push(END);
        Ok(out)
    }

    /// The array, for the C API (it stays owned by `self`).
    pub fn as_ptr(&self) -> *const OSSL_PARAM {
        self.params.as_ptr()
    }
}

impl Drop for Params {
    fn drop(&mut self) {
        for p in &self.params {
            openssl_free(p.data);
        }
    }
}

/// One slot's storage in a [`Query`]: stable for the query's life.
enum Slot {
    /// A `char *` the library sets (`OSSL_PARAM_construct_utf8_ptr`).
    Ptr(Box<*mut c_char>),
    /// An `int` (`OSSL_PARAM_construct_int`).
    Int(Box<c_int>),
    /// A buffer, aligned for any integer (kept for the array's `data` pointer into it).
    Buf(#[allow(dead_code)] Box<[u64]>),
}

/// A parameter array to be filled in by a `*_get_params` call, with its own storage.
pub struct Query {
    params: Vec<OSSL_PARAM>,
    _keys: Vec<CString>,
    slots: Vec<Slot>,
}

impl Default for Query {
    fn default() -> Self {
        Self::new()
    }
}

impl Query {
    pub fn new() -> Self {
        Query {
            params: vec![END],
            _keys: Vec::new(),
            slots: Vec::new(),
        }
    }

    fn push(&mut self, key: CString, p: OSSL_PARAM, slot: Slot) {
        let at = self.params.len() - 1;
        self.params.insert(at, p);
        self._keys.push(key);
        self.slots.push(slot);
    }

    /// `OSSL_PARAM_construct_utf8_ptr(key, &ptr, 0)`.
    pub fn utf8_ptr(mut self, key: &str) -> Self {
        let Some(k) = cstring(key) else {
            return self;
        };
        let mut slot: Box<*mut c_char> = Box::new(core::ptr::null_mut());
        // SAFETY: k and the slot live as long as the array (both are kept in self).
        let p = unsafe { ffi::OSSL_PARAM_construct_utf8_ptr(k.as_ptr(), &mut *slot, 0) };
        self.push(k, p, Slot::Ptr(slot));
        self
    }

    /// `OSSL_PARAM_construct_int(key, &i)`.
    pub fn int(mut self, key: &str) -> Self {
        let Some(k) = cstring(key) else {
            return self;
        };
        let mut slot = Box::new(0 as c_int);
        // SAFETY: as in utf8_ptr.
        let p = unsafe { ffi::OSSL_PARAM_construct_int(k.as_ptr(), &mut *slot) };
        self.push(k, p, Slot::Int(slot));
        self
    }

    /// An entry of `data_type` with a buffer of `size` bytes, `return_size` 0.
    pub fn buffer(mut self, key: &str, data_type: c_uint, size: usize) -> Self {
        let Some(k) = cstring(key) else {
            return self;
        };
        let mut buf = vec![0u64; size.div_ceil(8)].into_boxed_slice();
        let p = OSSL_PARAM {
            key: k.as_ptr(),
            data_type,
            data: buf.as_mut_ptr().cast::<c_void>(),
            data_size: size,
            return_size: 0,
        };
        self.push(k, p, Slot::Buf(buf));
        self
    }

    /// The array, for the C API to fill in.
    pub fn as_mut_ptr(&mut self) -> *mut OSSL_PARAM {
        self.params.as_mut_ptr()
    }

    /// `OSSL_PARAM_set_all_unmodified`.
    pub fn set_all_unmodified(&mut self) {
        // SAFETY: the array is live and terminated.
        unsafe { ffi::OSSL_PARAM_set_all_unmodified(self.params.as_mut_ptr()) };
    }

    /// `OSSL_PARAM_modified(&params[i])`.
    pub fn modified(&self, i: usize) -> bool {
        self.params.get(i).is_some_and(|p| {
            // SAFETY: p is a live entry.
            unsafe { ffi::OSSL_PARAM_modified(p) == 1 }
        })
    }

    /// Entry `i`, borrowed.
    pub fn get(&self, i: usize) -> Option<ParamRef<'_>> {
        self.params
            .get(i)
            .filter(|p| !p.key.is_null())
            .map(|p| ParamRef(p, core::marker::PhantomData))
    }

    /// The string a `utf8_ptr` entry points to (copied).
    pub fn ptr_string(&self, i: usize) -> Option<String> {
        match self.slots.get(i)? {
            Slot::Ptr(p) => string_at(**p),
            _ => None,
        }
    }

    /// An `int` entry's value.
    pub fn int_value(&self, i: usize) -> Option<c_int> {
        match self.slots.get(i)? {
            Slot::Int(v) => Some(**v),
            _ => None,
        }
    }
}

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
