//! ASN.1 objects, and read-only views of the values and attributes the commands print
//! (`ASN1_TYPE`, `X509_ATTRIBUTE`), copied out of the library's structures.

use core::ffi::{c_char, c_int};

use crate::abi::{
    ASN1_ITEM, ASN1_OBJECT, ASN1_STRING, ASN1_TYPE, V_ASN1_BIT_STRING, V_ASN1_BMPSTRING,
    V_ASN1_OBJECT, V_ASN1_OCTET_STRING, V_ASN1_UTF8STRING, X509_ATTRIBUTE, stack_st_X509_ATTRIBUTE,
};
use crate::bio::Bio;
use crate::ffi;
use crate::util::{cstring, string_at, take_string};

crate::handle!(
    /// An owned `ASN1_OBJECT`.
    Object, ASN1_OBJECT, ASN1_OBJECT_free
);

impl Object {
    /// A copy (`OBJ_dup`) of an object the caller borrows; `None` for NULL.
    pub(crate) fn dup_from(p: *const ASN1_OBJECT) -> Option<Self> {
        if p.is_null() {
            return None;
        }
        // SAFETY: p is a live object; the copy is owned by the result.
        Self::from_ptr(unsafe { ffi::OBJ_dup(p) })
    }

    /// `OBJ_txt2obj(s, no_name)`.
    pub fn from_txt(s: &str, no_name: bool) -> Option<Self> {
        let c = cstring(s)?;
        // SAFETY: c is a valid C string.
        Self::from_ptr(unsafe { ffi::OBJ_txt2obj(c.as_ptr(), c_int::from(no_name)) })
    }

    /// `OBJ_obj2nid`.
    pub fn nid(&self) -> c_int {
        // SAFETY: the object is live.
        unsafe { ffi::OBJ_obj2nid(self.as_ptr()) }
    }

    /// `i2a_ASN1_OBJECT(out, obj)`.
    pub fn i2a(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::i2a_ASN1_OBJECT(out.as_ptr(), self.as_ptr()) }
    }

    /// `OBJ_obj2txt(buf, size, obj, no_name)` into a buffer of `size` bytes.
    pub fn txt(&self, size: usize, no_name: bool) -> String {
        let mut buf = vec![0 as c_char; size.max(1)];
        let n = c_int::try_from(buf.len()).unwrap_or(c_int::MAX);
        // SAFETY: buf is writable for n bytes; the object is live.
        unsafe { ffi::OBJ_obj2txt(buf.as_mut_ptr(), n, self.as_ptr(), c_int::from(no_name)) };
        string_at(buf.as_ptr()).unwrap_or_default()
    }
}

/// `OBJ_nid2ln(nid)`.
pub fn nid2ln(nid: c_int) -> Option<String> {
    // SAFETY: any NID is accepted; the result is NULL or a static string.
    string_at(unsafe { ffi::OBJ_nid2ln(nid) })
}

/// `OBJ_nid2sn(nid)`.
pub fn nid2sn(nid: c_int) -> Option<String> {
    // SAFETY: as above.
    string_at(unsafe { ffi::OBJ_nid2sn(nid) })
}

/// `OBJ_txt2nid`'s twin for short names: `OBJ_sn2nid(s)`.
pub fn sn2nid(s: &str) -> c_int {
    let Some(c) = cstring(s) else {
        return 0;
    };
    // SAFETY: c is a valid C string.
    unsafe { ffi::OBJ_sn2nid(c.as_ptr()) }
}

/// The bytes of an `ASN1_STRING` the caller borrows (NULL: empty).
pub(crate) fn string_bytes(s: *const ASN1_STRING) -> Vec<u8> {
    if s.is_null() {
        return Vec::new();
    }
    // SAFETY: s is a live string.
    let data = unsafe { ffi::ASN1_STRING_get0_data(s) };
    // SAFETY: as above.
    let len = unsafe { ffi::ASN1_STRING_length(s) };
    let Ok(len) = usize::try_from(len) else {
        return Vec::new();
    };
    if data.is_null() || len == 0 {
        return Vec::new();
    }
    // SAFETY: the string holds len bytes at data while it lives.
    unsafe { core::slice::from_raw_parts(data, len) }.to_vec()
}

/// An `ASN1_TYPE`'s value, as `pkcs12`'s `print_attribute` tells them apart.
pub enum Value {
    Bmp(Vec<u8>),
    Utf8(Vec<u8>),
    Octet(Vec<u8>),
    Bit(Vec<u8>),
    Object(Option<Object>),
    /// Any other type: its tag.
    Other(c_int),
}

/// The value of an `ASN1_TYPE` the caller borrows.
pub(crate) fn value_of(p: *const ASN1_TYPE) -> Option<Value> {
    if p.is_null() {
        return None;
    }
    // SAFETY: p is a live ASN1_TYPE.
    let t = unsafe { *p };
    // For the string types, the union member is an ASN1_STRING pointer.
    let s = || {
        // SAFETY: only called for a string type, whose union member is a string pointer.
        string_bytes(unsafe { t.value.asn1_string })
    };
    Some(match t.type_ {
        V_ASN1_BMPSTRING => Value::Bmp(s()),
        V_ASN1_UTF8STRING => Value::Utf8(s()),
        V_ASN1_OCTET_STRING => Value::Octet(s()),
        V_ASN1_BIT_STRING => Value::Bit(s()),
        // SAFETY: as above.
        V_ASN1_OBJECT => Value::Object(Object::dup_from(unsafe { t.value.object })),
        other => Value::Other(other),
    })
}

/// One attribute: its type and values.
pub struct Attribute {
    pub object: Option<Object>,
    pub values: Vec<Option<Value>>,
}

/// The attributes of a stack the caller borrows; `None` for NULL.
pub(crate) fn attributes_of(sk: *const stack_st_X509_ATTRIBUTE) -> Option<Vec<Attribute>> {
    if sk.is_null() {
        return None;
    }
    let mut out = Vec::new();
    // SAFETY: sk is a live stack.
    let n = unsafe { ffi::OPENSSL_sk_num(sk.cast()) };
    for i in 0..n.max(0) {
        // SAFETY: i is in range; the member is a live attribute.
        let a = unsafe { ffi::OPENSSL_sk_value(sk.cast(), i) }.cast::<X509_ATTRIBUTE>();
        // SAFETY: a is live; the object is owned by it.
        let object = Object::dup_from(unsafe { ffi::X509_ATTRIBUTE_get0_object(a) });
        // SAFETY: a is live.
        let count = unsafe { ffi::X509_ATTRIBUTE_count(a) };
        let values = (0..count.max(0))
            // SAFETY: j is in range; the value is owned by the attribute.
            .map(|j| value_of(unsafe { ffi::X509_ATTRIBUTE_get0_type(a, j) }))
            .collect();
        out.push(Attribute { object, values });
    }
    Some(out)
}

/// `OPENSSL_uni2asc(data, len)`: `None` if it fails.
pub fn uni2asc(data: &[u8]) -> Option<Vec<u8>> {
    let len = c_int::try_from(data.len()).ok()?;
    // SAFETY: data is valid for len bytes; the result is the caller's to free.
    let p = unsafe { ffi::OPENSSL_uni2asc(data.as_ptr(), len) };
    take_string(p).map(String::into_bytes)
}

/// `ASN1_item_unpack(s, it)` and a callback over the result, which is then freed.
pub(crate) fn with_unpacked<T>(
    s: *const ASN1_STRING,
    it: *const ASN1_ITEM,
    f: impl FnOnce(*mut core::ffi::c_void) -> T,
) -> Option<T> {
    if s.is_null() {
        return None;
    }
    // SAFETY: s is a live string; it a valid item.
    let p = unsafe { ffi::ASN1_item_unpack(s, it) };
    if p.is_null() {
        return None;
    }
    let t = f(p);
    // SAFETY: p was made by ASN1_item_unpack with it, and is freed once here.
    unsafe { ffi::ASN1_item_free(p.cast(), it) };
    Some(t)
}

/// `ASN1_INTEGER_get` of an integer the caller borrows.
pub(crate) fn integer_get(p: *const crate::abi::ASN1_INTEGER) -> core::ffi::c_long {
    // SAFETY: p is NULL or a live integer (NULL gives 0).
    unsafe { ffi::ASN1_INTEGER_get(p) }
}
