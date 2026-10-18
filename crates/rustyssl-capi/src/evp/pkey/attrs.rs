//! A key's attributes (`evp_pkey.c`): the `X509at_*` functions over the list the key holds,
//! which PKCS#8 and PKCS#12 carry (a CSP name, key usage, and the like).

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{ASN1_OBJECT, ERR_LIB_EVP, EVP_PKEY, X509_ATTRIBUTE, stack_st_X509_ATTRIBUTE};

use super::pkey;
use crate::ffi::ffi_export;
use crate::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
};
use crate::x509::attrib::{
    X509_ATTRIBUTE_dup, X509_ATTRIBUTE_free, X509at_add1_attr, X509at_add1_attr_by_NID,
    X509at_add1_attr_by_OBJ, X509at_add1_attr_by_txt, X509at_delete_attr, X509at_get_attr,
    X509at_get_attr_by_NID, X509at_get_attr_by_OBJ, X509at_get_attr_count,
};

/// `X509_ATTRIBUTE_free` as a stack's free function.
pub(crate) unsafe extern "C" fn attribute_free(p: *mut c_void) {
    // SAFETY: an element of a list of attributes.
    unsafe { X509_ATTRIBUTE_free(p.cast()) };
}

/// `ossl_x509at_dup`: a new list of copies of the attributes, or NULL.
///
/// # Safety
/// `attrs` is a live list.
pub(crate) unsafe fn deep_copy(
    attrs: *mut stack_st_X509_ATTRIBUTE,
) -> *mut stack_st_X509_ATTRIBUTE {
    // SAFETY: no preconditions.
    let copy = unsafe { OPENSSL_sk_new_null() };
    if copy.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller's list.
    for i in 0..unsafe { OPENSSL_sk_num(attrs.cast()) } {
        // SAFETY: an index within it.
        let a = unsafe { OPENSSL_sk_value(attrs.cast(), i) };
        // SAFETY: an attribute of the list.
        let d = unsafe { X509_ATTRIBUTE_dup(a.cast()) };
        // SAFETY: the new list; the copy.
        if d.is_null() || unsafe { OPENSSL_sk_push(copy, d.cast()) } == 0 {
            // SAFETY: the copy, not taken, or NULL.
            unsafe { X509_ATTRIBUTE_free(d) };
            // SAFETY: the list made here, with its copies.
            unsafe { OPENSSL_sk_pop_free(copy, Some(attribute_free)) };
            return ptr::null_mut();
        }
    }
    copy.cast()
}

/// The key's attribute list, NULL for none.
///
/// # Safety
/// `key` is NULL or a live key.
unsafe fn list(key: *const EVP_PKEY) -> *mut stack_st_X509_ATTRIBUTE {
    // SAFETY: the caller's guarantee; the key's slot.
    unsafe { pkey(key) }.map_or(ptr::null_mut(), |k| unsafe { *k.attributes_slot() })
}

ffi_export! {
    /// The number of the key's attributes.
    ///
    /// # Safety
    /// `key` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get_attr_count(key: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let l = unsafe { list(key) };
        // SAFETY: the key's list, or NULL.
        unsafe { X509at_get_attr_count(l) }
    }
}

ffi_export! {
    /// The index of the key's next attribute `nid` after `lastpos`, or -1.
    ///
    /// # Safety
    /// `key` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get_attr_by_NID(key: *const EVP_PKEY, nid: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let l = unsafe { list(key) };
        // SAFETY: the key's list, or NULL.
        unsafe { X509at_get_attr_by_NID(l, nid, lastpos) }
    }
}

ffi_export! {
    /// The index of the key's next attribute `obj` after `lastpos`, or -1.
    ///
    /// # Safety
    /// `key` is NULL or a live key; `obj` a live object.
    pub unsafe extern "C" fn EVP_PKEY_get_attr_by_OBJ(key: *const EVP_PKEY, obj: *const ASN1_OBJECT, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let l = unsafe { list(key) };
        // SAFETY: the key's list, or NULL.
        unsafe { X509at_get_attr_by_OBJ(l, obj, lastpos) }
    }
}

ffi_export! {
    /// The key's attribute `loc`, or NULL.
    ///
    /// # Safety
    /// `key` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get_attr(key: *const EVP_PKEY, loc: c_int) -> *mut X509_ATTRIBUTE
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let l = unsafe { list(key) };
        // SAFETY: the key's list, or NULL.
        unsafe { X509at_get_attr(l, loc) }
    }
}

ffi_export! {
    /// Removes the key's attribute `loc` and gives it to the caller, or NULL.
    ///
    /// # Safety
    /// `key` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_delete_attr(key: *mut EVP_PKEY, loc: c_int) -> *mut X509_ATTRIBUTE
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let l = unsafe { list(key) };
        // SAFETY: the key's list, or NULL.
        unsafe { X509at_delete_attr(l, loc) }
    }
}

/// The key's attribute slot, or `None`.
///
/// # Safety
/// `key` is NULL or a live key.
unsafe fn slot(key: *mut EVP_PKEY) -> Option<*mut *mut stack_st_X509_ATTRIBUTE> {
    // SAFETY: the caller's guarantee.
    unsafe { pkey(key) }.map(|k| k.attributes_slot())
}

ffi_export! {
    /// Adds a copy of the attribute to the key: 1, or 0.
    ///
    /// # Safety
    /// `key` is NULL or a live key; `attr` a live attribute.
    pub unsafe extern "C" fn EVP_PKEY_add1_attr(key: *mut EVP_PKEY, attr: *mut X509_ATTRIBUTE) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { slot(key) }) else { return 0 };
        // SAFETY: the key's slot; the attribute, copied.
        c_int::from(!unsafe { X509at_add1_attr(s, attr) }.is_null())
    }
}

ffi_export! {
    /// Adds an attribute `obj` of the value to the key: 1, or 0.
    ///
    /// # Safety
    /// `key` is NULL or a live key; `obj` live; `bytes` holds `len` octets (as `type_` takes
    /// them).
    pub unsafe extern "C" fn EVP_PKEY_add1_attr_by_OBJ(key: *mut EVP_PKEY, obj: *const ASN1_OBJECT, type_: c_int, bytes: *const c_uchar, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { slot(key) }) else { return 0 };
        // SAFETY: the key's slot; the caller's value.
        c_int::from(!unsafe { X509at_add1_attr_by_OBJ(s, obj, type_, bytes, len) }.is_null())
    }
}

ffi_export! {
    /// Adds an attribute `nid` of the value to the key: 1, or 0.
    ///
    /// # Safety
    /// `key` is NULL or a live key; `bytes` holds `len` octets (as `type_` takes them).
    pub unsafe extern "C" fn EVP_PKEY_add1_attr_by_NID(key: *mut EVP_PKEY, nid: c_int, type_: c_int, bytes: *const c_uchar, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { slot(key) }) else { return 0 };
        // SAFETY: the key's slot; the caller's value.
        c_int::from(!unsafe { X509at_add1_attr_by_NID(s, nid, type_, bytes, len) }.is_null())
    }
}

ffi_export! {
    /// Adds an attribute named `attrname` of the value to the key: 1, or 0.
    ///
    /// # Safety
    /// `key` is NULL or a live key; `attrname` a C string; `bytes` holds `len` octets.
    pub unsafe extern "C" fn EVP_PKEY_add1_attr_by_txt(key: *mut EVP_PKEY, attrname: *const c_char, type_: c_int, bytes: *const c_uchar, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { slot(key) }) else { return 0 };
        // SAFETY: the key's slot; the caller's name and value.
        c_int::from(!unsafe { X509at_add1_attr_by_txt(s, attrname, type_, bytes, len) }.is_null())
    }
}
