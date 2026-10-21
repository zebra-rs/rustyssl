//! ASN.1: parsing and printing DER (`asn1parse`), item templates, and generated structures.

use core::ffi::{c_int, c_long};

use crate::abi::ASN1_ITEM;
use crate::bio::Bio;
use crate::conf::Conf;
use crate::ffi;
use crate::util::{cstring, openssl_free, string_at};

/// A built-in `ASN1_ITEM` (a static template).
#[derive(Clone, Copy)]
pub struct Item(*const ASN1_ITEM);

impl Item {
    /// `ASN1_ITEM_lookup(name)`.
    pub fn lookup(name: &str) -> Option<Self> {
        let n = cstring(name)?;
        // SAFETY: n is a valid C string; the result is static or NULL.
        let p = unsafe { ffi::ASN1_ITEM_lookup(n.as_ptr()) };
        (!p.is_null()).then_some(Item(p))
    }

    /// `ASN1_ITEM_get(i)`.
    pub fn get(i: usize) -> Option<Self> {
        // SAFETY: any index is allowed; the result is static or NULL.
        let p = unsafe { ffi::ASN1_ITEM_get(i) };
        (!p.is_null()).then_some(Item(p))
    }

    /// The item's `sname`.
    pub fn sname(&self) -> String {
        // SAFETY: the item is a static template; sname is a static string or NULL.
        string_at(unsafe { (*self.0).sname }).unwrap_or_default()
    }

    /// `ASN1_item_d2i` of `data`, then `ASN1_item_print(out, value, 0, it, NULL)`: false if
    /// the data doesn't parse.
    pub fn d2i_print(&self, data: &[u8], out: &Bio) -> bool {
        let Ok(len) = c_long::try_from(data.len()) else {
            return false;
        };
        let mut p = data.as_ptr();
        // SAFETY: p points to len readable bytes; the item is a static template.
        let v = unsafe { ffi::ASN1_item_d2i(core::ptr::null_mut(), &mut p, len, self.0) };
        if v.is_null() {
            return false;
        }
        // SAFETY: v is a value of this item; the BIO is live; NULL is the default context.
        unsafe { ffi::ASN1_item_print(out.as_ptr(), v, 0, self.0, core::ptr::null()) };
        // SAFETY: v is ours, of this item, freed once.
        unsafe { ffi::ASN1_item_free(v, self.0) };
        true
    }
}

crate::handle!(
    /// An owned `ASN1_TYPE`.
    Type, ASN1_TYPE, ASN1_TYPE_free
);

impl Type {
    /// `d2i_ASN1_TYPE(NULL, &p, len)`.
    pub fn d2i(data: &[u8]) -> Option<Self> {
        let len = c_long::try_from(data.len()).ok()?;
        let mut p = data.as_ptr();
        // SAFETY: p points to len readable bytes.
        Self::from_ptr(unsafe { ffi::d2i_ASN1_TYPE(core::ptr::null_mut(), &mut p, len) })
    }

    /// `ASN1_generate_nconf(str, conf)`, encoded (`i2d_ASN1_TYPE`): `None` if either
    /// step fails.
    pub fn generate_der(s: &str, conf: Option<&Conf>) -> Option<Vec<u8>> {
        let c = cstring(s)?;
        let cnf = conf.map_or(core::ptr::null_mut(), Conf::as_ptr);
        // SAFETY: c is a valid C string; cnf is NULL or live.
        let t = Self::from_ptr(unsafe { ffi::ASN1_generate_nconf(c.as_ptr(), cnf) })?;
        // SAFETY: t is live; NULL asks for the length.
        let len = unsafe { ffi::i2d_ASN1_TYPE(t.as_ptr(), core::ptr::null_mut()) };
        let n = usize::try_from(len).ok().filter(|n| *n > 0)?;
        let mut out = vec![0u8; n];
        let mut p = out.as_mut_ptr();
        // SAFETY: out holds the len bytes i2d writes.
        unsafe { ffi::i2d_ASN1_TYPE(t.as_ptr(), &mut p) };
        Some(out)
    }

    /// `ASN1_TYPE_get`.
    pub fn kind(&self) -> c_int {
        // SAFETY: the value is live.
        unsafe { ffi::ASN1_TYPE_get(self.as_ptr()) }
    }

    /// The bytes of its value's `asn1_string` (`at->value.asn1_string->data`), for a type
    /// whose value is a string (not an object, a boolean, or NULL).
    pub fn string_data(&self) -> Vec<u8> {
        // SAFETY: the value is live.
        let t = unsafe { &*self.as_ptr() };
        // SAFETY: for string types the union holds an ASN1_STRING pointer (the caller rules
        // out the others).
        let s = unsafe { t.value.asn1_string };
        if s.is_null() {
            return Vec::new();
        }
        // SAFETY: s is a live ASN1_STRING owned by the value.
        let len = usize::try_from(unsafe { ffi::ASN1_STRING_length(s) }).unwrap_or(0);
        // SAFETY: as above.
        let d = unsafe { ffi::ASN1_STRING_get0_data(s) };
        if d.is_null() {
            return Vec::new();
        }
        // SAFETY: the string holds len bytes at d.
        unsafe { core::slice::from_raw_parts(d, len) }.to_vec()
    }
}

/// `ASN1_tag2str(tag)`.
pub fn tag2str(tag: c_int) -> String {
    // SAFETY: any tag is allowed; the result is a static string.
    string_at(unsafe { ffi::ASN1_tag2str(tag) }).unwrap_or_default()
}

/// `ASN1_parse_dump(out, data, len, indent, dump)`.
pub fn parse_dump(out: &Bio, data: &[u8], indent: bool, dump: c_int) -> bool {
    let Ok(len) = c_long::try_from(data.len()) else {
        return false;
    };
    // SAFETY: the BIO is live; data is valid for len bytes.
    unsafe {
        ffi::ASN1_parse_dump(out.as_ptr(), data.as_ptr(), len, c_int::from(indent), dump) == 1
    }
}

/// `OBJ_create_objects(in)`: the number of objects created.
pub fn create_objects(input: &Bio) -> c_int {
    // SAFETY: the BIO is live.
    unsafe { ffi::OBJ_create_objects(input.as_ptr()) }
}

/// A PEM block (`PEM_read_bio`).
pub struct PemBlock {
    pub name: Vec<u8>,
    pub header: Vec<u8>,
    pub data: Vec<u8>,
}

/// `PEM_read_bio(bio, &name, &header, &data, &len)`.
pub fn pem_read(bio: &Bio) -> Option<PemBlock> {
    let mut name = core::ptr::null_mut();
    let mut header = core::ptr::null_mut();
    let mut data = core::ptr::null_mut();
    let mut len: c_long = 0;
    // SAFETY: the BIO is live; every out-pointer is a valid local.
    let r = unsafe { ffi::PEM_read_bio(bio.as_ptr(), &mut name, &mut header, &mut data, &mut len) };
    let take = |p: *mut core::ffi::c_char| {
        let v = string_at(p).map(String::into_bytes).unwrap_or_default();
        openssl_free(p.cast());
        v
    };
    let copied = (r == 1).then(|| {
        if data.is_null() {
            return Vec::new();
        }
        // SAFETY: data holds len bytes.
        unsafe { core::slice::from_raw_parts(data, usize::try_from(len).unwrap_or(0)) }.to_vec()
    });
    let (name, header) = (take(name), take(header));
    openssl_free(data.cast());
    copied.map(|data| PemBlock { name, header, data })
}
