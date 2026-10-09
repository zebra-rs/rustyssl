//! `ASN1_TYPE`, a value of any universal type (`ASN1_TYPE_get(3)`, `ASN1_TYPE_set(3)`,
//! `ASN1_TYPE_set1`, `ASN1_TYPE_cmp`, `ASN1_TYPE_set_octetstring`, `ASN1_TYPE_get_octetstring`).
//!
//! The struct is public: a type and a union holding a BOOLEAN's value or a pointer to an
//! `ASN1_OBJECT`, an `ASN1_STRING`, or (for `V_ASN1_ANY`) another `ASN1_TYPE`. Setting a value
//! frees the old one as OpenSSL's `ossl_asn1_primitive_free` does. `ASN1_TYPE_new`/`free` and
//! the functions that pack sequences come with the template engine.

use core::ffi::{c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_OBJECT, ASN1_R_DATA_IS_WRONG, ASN1_STRING, ASN1_TYPE, ERR_LIB_ASN1, V_ASN1_ANY,
    V_ASN1_BOOLEAN, V_ASN1_NULL, V_ASN1_OBJECT, V_ASN1_OCTET_STRING,
};

use super::string;
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects;

/// `ossl_asn1_primitive_free` without an item: frees the value an `ASN1_TYPE` holds by its type
/// (nothing for BOOLEAN and NULL; a string's struct even if it is marked embedded) and clears
/// the pointer.
///
/// # Safety
/// `a` is a live `ASN1_TYPE` whose value, if any, is of its type and owned by it.
unsafe fn free_value(a: *mut ASN1_TYPE) {
    // SAFETY: the caller's guarantee.
    let typ = unsafe { &mut *a };
    // SAFETY: the pointer member of the union, which a BOOLEAN's value overlaps harmlessly.
    let value = unsafe { typ.value.ptr };
    if value.is_null() {
        return;
    }
    match typ.type_ {
        V_ASN1_OBJECT => {
            // SAFETY: an OBJECT's value is an object.
            unsafe { objects::free_object(value.cast()) };
        }
        V_ASN1_BOOLEAN => {
            typ.value.boolean = -1;
            return;
        }
        V_ASN1_NULL => {}
        V_ASN1_ANY => {
            let inner: *mut ASN1_TYPE = value.cast();
            // SAFETY: an ANY's value is another ASN1_TYPE, from this allocator.
            unsafe { free_value(inner) };
            // SAFETY: as above.
            unsafe { mem::release(inner.cast()) };
        }
        _ => {
            // SAFETY: any other value is a string.
            unsafe { string::embed_free(value.cast(), false) };
        }
    }
    typ.value.ptr = ptr::null_mut();
}

ffi_export! {
    /// `a`'s type, or 0 if it holds no value (BOOLEAN and NULL always count as holding one).
    ///
    /// Unlike OpenSSL, NULL `a` is 0 rather than a crash (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `a` is NULL or a live `ASN1_TYPE`.
    pub unsafe extern "C" fn ASN1_TYPE_get(a: *const ASN1_TYPE) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if a.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let typ = unsafe { &*a };
        // SAFETY: the pointer member, read as OpenSSL reads it.
        let value = unsafe { typ.value.ptr };
        if typ.type_ == V_ASN1_BOOLEAN || typ.type_ == V_ASN1_NULL || !value.is_null() {
            typ.type_
        } else {
            0
        }
    }
}

ffi_export! {
    /// Gives `a` type `type` and value `value` (taking it), freeing the value it held. For a
    /// BOOLEAN, the value is 0xff if `value` isn't NULL, else 0.
    ///
    /// Unlike OpenSSL, NULL `a` does nothing rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `a` is NULL or a live `ASN1_TYPE`; `value` is NULL or a value of `type` it may own.
    pub unsafe extern "C" fn ASN1_TYPE_set(a: *mut ASN1_TYPE, type_: c_int, value: *mut c_void)
    where failure = (), library = ERR_LIB_ASN1
    {
        if a.is_null() {
            return;
        }
        // SAFETY: the caller's guarantee.
        let old_type = unsafe { (*a).type_ };
        if old_type != V_ASN1_BOOLEAN && old_type != V_ASN1_NULL {
            // SAFETY: as above; `free_value` skips an empty value.
            unsafe { free_value(a) };
        }
        // SAFETY: as above.
        let typ = unsafe { &mut *a };
        typ.type_ = type_;
        if type_ == V_ASN1_BOOLEAN {
            typ.value.boolean = if value.is_null() { 0 } else { 0xff };
        } else {
            typ.value.ptr = value.cast();
        }
    }
}

ffi_export! {
    /// `ASN1_TYPE_set` with a copy of `value` (an object or string; BOOLEAN and NULL values as
    /// they are). Returns 1, or 0 if the copy fails.
    ///
    /// # Safety
    /// `a` is NULL or a live `ASN1_TYPE`; `value` is NULL or a value of `type`.
    pub unsafe extern "C" fn ASN1_TYPE_set1(a: *mut ASN1_TYPE, type_: c_int, value: *const c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        let copy: *mut c_void = if value.is_null() || type_ == V_ASN1_BOOLEAN {
            value.cast_mut()
        } else if type_ == V_ASN1_OBJECT {
            // SAFETY: the caller's guarantee: an object.
            let duplicate = unsafe { objects::OBJ_dup(value.cast::<ASN1_OBJECT>()) };
            if duplicate.is_null() {
                return 0;
            }
            duplicate.cast()
        } else {
            // SAFETY: the caller's guarantee: a string.
            let duplicate = unsafe { string::ASN1_STRING_dup(value.cast::<ASN1_STRING>()) };
            if duplicate.is_null() {
                return 0;
            }
            duplicate.cast()
        };
        // SAFETY: the caller's guarantee; `copy` is ours to give.
        unsafe { ASN1_TYPE_set(a, type_, copy) };
        1
    }
}

ffi_export! {
    /// Compares two values of one type: objects with `OBJ_cmp`, BOOLEANs by value, NULLs as
    /// equal, anything else with `ASN1_STRING_cmp`. -1 for NULL or different types.
    ///
    /// # Safety
    /// `a` and `b` are NULL or live `ASN1_TYPE`s.
    pub unsafe extern "C" fn ASN1_TYPE_cmp(a: *const ASN1_TYPE, b: *const ASN1_TYPE) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        if a.is_null() || b.is_null() {
            return -1;
        }
        // SAFETY: the caller's guarantee.
        let (x, y) = (unsafe { &*a }, unsafe { &*b });
        if x.type_ != y.type_ {
            return -1;
        }
        match x.type_ {
            V_ASN1_OBJECT => {
                // SAFETY: an OBJECT's value is an object (or NULL).
                let (p, q) = (unsafe { x.value.object }, unsafe { y.value.object });
                // SAFETY: as above.
                unsafe { objects::OBJ_cmp(p, q) }
            }
            V_ASN1_BOOLEAN => {
                // SAFETY: a BOOLEAN's value is an int.
                let (p, q) = (unsafe { x.value.boolean }, unsafe { y.value.boolean });
                p.wrapping_sub(q)
            }
            V_ASN1_NULL => 0,
            _ => {
                // SAFETY: any other value is a string (or NULL).
                let (p, q) = (unsafe { x.value.asn1_string }, unsafe { y.value.asn1_string });
                // SAFETY: as above.
                unsafe { string::ASN1_STRING_cmp(p, q) }
            }
        }
    }
}

ffi_export! {
    /// Makes `a` an OCTET STRING holding a copy of `len` octets of `data`. Returns 1 or 0.
    ///
    /// # Safety
    /// `a` is NULL or a live `ASN1_TYPE`; `data` is NULL or holds `len` octets.
    pub unsafe extern "C" fn ASN1_TYPE_set_octetstring(a: *mut ASN1_TYPE, data: *mut c_uchar, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        let os = string::type_new(V_ASN1_OCTET_STRING);
        if os.is_null() {
            return 0;
        }
        // SAFETY: a new string; the caller's guarantee about `data`.
        if unsafe { string::set(os, data.cast_const().cast(), len) } == 0 {
            // SAFETY: the new string.
            unsafe { string::ASN1_STRING_free(os) };
            return 0;
        }
        // SAFETY: the caller's guarantee; the string is given to `a`.
        unsafe { ASN1_TYPE_set(a, V_ASN1_OCTET_STRING, os.cast()) };
        1
    }
}

ffi_export! {
    /// Copies up to `max_len` octets of the OCTET STRING `a` holds into `data` (if not NULL).
    /// Returns its whole length, or -1 (`ASN1_R_DATA_IS_WRONG`) if `a` isn't one.
    ///
    /// Unlike OpenSSL, NULL `a` fails rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `a` is NULL or a live `ASN1_TYPE`; `data` is NULL or valid for writes of `max_len`.
    pub unsafe extern "C" fn ASN1_TYPE_get_octetstring(a: *const ASN1_TYPE, data: *mut c_uchar, max_len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        let (kind, octets) = if a.is_null() {
            (0, ptr::null_mut())
        } else {
            // SAFETY: the caller's guarantee.
            let typ = unsafe { &*a };
            // SAFETY: the union's pointer member, read as OpenSSL reads it.
            (typ.type_, unsafe { typ.value.octet_string })
        };
        if kind != V_ASN1_OCTET_STRING || octets.is_null() {
            err::raise(ERR_LIB_ASN1, ASN1_R_DATA_IS_WRONG, "ASN1_TYPE_get_octetstring");
            return -1;
        }
        // SAFETY: a live string.
        let string = unsafe { &*octets };
        let n = string.length.min(max_len);
        if let Ok(n) = usize::try_from(n)
            && n > 0
            && !data.is_null()
        {
            // SAFETY: the string holds its length, and `data` room for `max_len`.
            unsafe { ptr::copy_nonoverlapping(string.data, data, n) };
        }
        string.length
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_arguments_are_safe() {
        // SAFETY: NULL is refused.
        assert_eq!(unsafe { ASN1_TYPE_get(ptr::null()) }, 0);
        // SAFETY: as above.
        unsafe { ASN1_TYPE_set(ptr::null_mut(), V_ASN1_NULL, ptr::null_mut()) };
        // SAFETY: as above.
        let got = unsafe { ASN1_TYPE_get_octetstring(ptr::null(), ptr::null_mut(), 0) };
        assert_eq!(got, -1);
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }
}
