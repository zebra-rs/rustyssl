//! Attributes (`x_attrib.c`, `x509_att.c`): `X509_ATTRIBUTE`, a SEQUENCE of an object and a
//! SET OF ANY (its values), with its DER and the functions that make, change, and read one;
//! and the `X509at_*` functions over a stack of them, which PKCS#8, certificate requests, and
//! PKCS#12 keep.
//!
//! As OpenSSL, adding an attribute to a stack copies it and refuses one whose object the stack
//! has already, `X509_ATTRIBUTE_set1_data` with type 0 adds no value (a SET with none), and
//! `X509at_get0_data_by_OBJ`'s position -2 asks for the only such attribute, -3 for the only
//! one with a single value.

use core::ffi::{CStr, c_char, c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_ITEM, ASN1_OBJECT, ASN1_STRING, ASN1_TFLG_SET_OF, ASN1_TYPE, ERR_LIB_ASN1, ERR_LIB_X509,
    ERR_R_ASN1_LIB, ERR_R_CRYPTO_LIB, ERR_R_PASSED_INVALID_ARGUMENT, ERR_R_PASSED_NULL_PARAMETER,
    MBSTRING_FLAG, OPENSSL_STACK, V_ASN1_BOOLEAN, V_ASN1_NULL, X509_ATTRIBUTE,
    X509_R_DUPLICATE_ATTRIBUTE, X509_R_INVALID_FIELD_NAME, X509_R_UNKNOWN_NID, X509_R_WRONG_TYPE,
    stack_st_X509_ATTRIBUTE as AttrStack,
};

use crate::asn1::any::{ASN1_TYPE_get, ASN1_TYPE_set, ASN1_TYPE_set1};
use crate::asn1::string::{ASN1_STRING_free, ASN1_STRING_set, ASN1_STRING_type_new};
use crate::asn1::text::ASN1_STRING_set_by_NID;
use crate::asn1::tpl::items::{
    ASN1_ANY_it, ASN1_OBJECT_it, ASN1_TYPE_free, ASN1_TYPE_new, d2i, i2d, new_free,
};
use crate::asn1::tpl::statics::{Templates, sequence};
use crate::asn1::tpl::util::ASN1_item_dup;
use crate::asn1::tpl::{item_fns, template_at};
use crate::err;
use crate::ffi::ffi_export;
use crate::objects::{
    ASN1_OBJECT_free, OBJ_cmp, OBJ_dup, OBJ_nid2obj, OBJ_nid2sn, OBJ_obj2nid, OBJ_txt2obj,
};
use crate::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push,
    OPENSSL_sk_value,
};

/// `X509_ATTRIBUTE` (`x509_attributes_st`): the object and the stack of its values.
#[repr(C)]
pub(crate) struct Attribute {
    pub(crate) object: *mut ASN1_OBJECT,
    /// A stack of `ASN1_TYPE`s.
    pub(crate) set: *mut OPENSSL_STACK,
}

static ATTRIBUTE_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        core::mem::offset_of!(Attribute, object),
        c"object",
        ASN1_OBJECT_it,
    ),
    template_at(
        ASN1_TFLG_SET_OF,
        0,
        core::mem::offset_of!(Attribute, set),
        c"set",
        ASN1_ANY_it,
    ),
]);

item_fns! {
    /// Attribute: SEQUENCE { type OBJECT IDENTIFIER, values SET OF ANY }.
    pub unsafe extern "C" fn X509_ATTRIBUTE_it = sequence::<Attribute, 2>(&ATTRIBUTE_TT, None, c"X509_ATTRIBUTE");
}

new_free! {
    pub unsafe extern "C" fn X509_ATTRIBUTE_new, pub unsafe extern "C" fn X509_ATTRIBUTE_free(X509_ATTRIBUTE) = X509_ATTRIBUTE_it;
}

i2d! {
    /// Encodes an attribute.
    pub unsafe extern "C" fn i2d_X509_ATTRIBUTE(X509_ATTRIBUTE) = X509_ATTRIBUTE_it;
}

d2i! {
    /// Decodes an attribute (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_X509_ATTRIBUTE(X509_ATTRIBUTE) = X509_ATTRIBUTE_it;
}

/// The attribute behind a pointer.
///
/// # Safety
/// `a` is NULL or a live attribute, which nothing else changes while the reference lives.
pub(crate) unsafe fn attr<'a>(a: *const X509_ATTRIBUTE) -> Option<&'a mut Attribute> {
    // SAFETY: the caller's guarantee; an attribute is an `Attribute`.
    unsafe { a.cast::<Attribute>().cast_mut().as_mut() }
}

/// Raises an X509 error from `func`.
#[track_caller]
fn x509(reason: c_int, func: &str) {
    err::raise(ERR_LIB_X509, reason, func);
}

ffi_export! {
    /// A copy of an attribute (`ASN1_item_dup`), or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live attribute.
    pub unsafe extern "C" fn X509_ATTRIBUTE_dup(a: *const X509_ATTRIBUTE) -> *mut X509_ATTRIBUTE
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_ATTRIBUTE_it() };
        // SAFETY: the type's item; the caller's value.
        unsafe { ASN1_item_dup(it, a.cast()) }.cast()
    }
}

ffi_export! {
    /// A new attribute of the NID's object with one value of `atrtype` (`value` taken, as
    /// `ASN1_TYPE_set` takes it), or NULL.
    ///
    /// # Safety
    /// `value` is what `ASN1_TYPE_set` takes for `atrtype`.
    pub unsafe extern "C" fn X509_ATTRIBUTE_create(nid: c_int, atrtype: c_int, value: *mut c_void) -> *mut X509_ATTRIBUTE
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let oid = unsafe { OBJ_nid2obj(nid) };
        if oid.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let ret = unsafe { X509_ATTRIBUTE_new() };
        // SAFETY: just made, or NULL.
        let Some(a) = (unsafe { attr(ret) }) else { return ptr::null_mut() };
        a.object = oid;
        // SAFETY: no preconditions.
        let val = unsafe { ASN1_TYPE_new() };
        // SAFETY: the attribute's stack; the new value, which it then owns.
        if val.is_null() || unsafe { OPENSSL_sk_push(a.set, val.cast()) } == 0 {
            // SAFETY: made above.
            unsafe { X509_ATTRIBUTE_free(ret) };
            // SAFETY: made above, or NULL.
            unsafe { ASN1_TYPE_free(val) };
            return ptr::null_mut();
        }
        // SAFETY: the value; the caller's.
        unsafe { ASN1_TYPE_set(val, atrtype, value) };
        ret
    }
}

ffi_export! {
    /// Sets the attribute's object to a copy of `obj`. 1, or 0.
    ///
    /// # Safety
    /// `attr` is NULL or a live attribute; `obj` is NULL or a live object.
    pub unsafe extern "C" fn X509_ATTRIBUTE_set1_object(attr_: *mut X509_ATTRIBUTE, obj: *const ASN1_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { attr(attr_) }) else {
            x509(ERR_R_PASSED_NULL_PARAMETER, "X509_ATTRIBUTE_set1_object");
            return 0;
        };
        if obj.is_null() {
            x509(ERR_R_PASSED_NULL_PARAMETER, "X509_ATTRIBUTE_set1_object");
            return 0;
        }
        // SAFETY: its object, or NULL.
        unsafe { ASN1_OBJECT_free(a.object) };
        // SAFETY: the caller's object.
        a.object = unsafe { OBJ_dup(obj) };
        c_int::from(!a.object.is_null())
    }
}

ffi_export! {
    /// Adds a value to the attribute: a string of the attribute's type made from `data` for an
    /// `MBSTRING_*` type; a string of `attrtype` from `len` octets; or, for `len` -1, a copy of
    /// `data` as `ASN1_TYPE_set1` takes it. Type 0 adds nothing. 1, or 0.
    ///
    /// # Safety
    /// `attr` is NULL or a live attribute; `data` is what the type and length say.
    pub unsafe extern "C" fn X509_ATTRIBUTE_set1_data(attr_: *mut X509_ATTRIBUTE, attrtype: c_int, data: *const c_void, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        const F: &str = "X509_ATTRIBUTE_set1_data";
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { attr(attr_) }) else {
            x509(ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        };
        let mut stmp: *mut ASN1_STRING = ptr::null_mut();
        let mut atype = 0;
        if attrtype & MBSTRING_FLAG != 0 {
            // SAFETY: the attribute's object.
            let nid = unsafe { OBJ_obj2nid(a.object) };
            // SAFETY: the caller's data of `len` (or NUL-terminated for -1).
            stmp = unsafe { ASN1_STRING_set_by_NID(ptr::null_mut(), data.cast(), len, attrtype, nid) };
            // SAFETY: just made, or NULL.
            let Some(s) = (unsafe { stmp.as_ref() }) else {
                x509(ERR_R_ASN1_LIB, F);
                return 0;
            };
            atype = s.type_;
        } else if len != -1 {
            // SAFETY: no preconditions.
            stmp = unsafe { ASN1_STRING_type_new(attrtype) };
            // SAFETY: the new string; the caller's `len` octets.
            if stmp.is_null() || unsafe { ASN1_STRING_set(stmp, data, len) } == 0 {
                x509(ERR_R_ASN1_LIB, F);
                // SAFETY: made above, or NULL.
                unsafe { ASN1_STRING_free(stmp) };
                return 0;
            }
            atype = attrtype;
        }
        if attrtype == 0 {
            // SAFETY: made above, or NULL.
            unsafe { ASN1_STRING_free(stmp) };
            return 1;
        }
        // SAFETY: no preconditions.
        let ttmp = unsafe { ASN1_TYPE_new() };
        let fail = |ttmp: *mut ASN1_TYPE, stmp: *mut ASN1_STRING| {
            // SAFETY: made here, or NULL.
            unsafe { ASN1_TYPE_free(ttmp) };
            // SAFETY: as above.
            unsafe { ASN1_STRING_free(stmp) };
            0
        };
        if ttmp.is_null() {
            x509(ERR_R_ASN1_LIB, F);
            return fail(ttmp, stmp);
        }
        if len == -1 && attrtype & MBSTRING_FLAG == 0 {
            // SAFETY: the new value; the caller's data of the type.
            if unsafe { ASN1_TYPE_set1(ttmp, attrtype, data) } == 0 {
                x509(ERR_R_ASN1_LIB, F);
                return fail(ttmp, stmp);
            }
        } else {
            // SAFETY: the new value takes the string.
            unsafe { ASN1_TYPE_set(ttmp, atype, stmp.cast()) };
            stmp = ptr::null_mut();
        }
        // SAFETY: the attribute's stack takes the value.
        if unsafe { OPENSSL_sk_push(a.set, ttmp.cast()) } == 0 {
            x509(ERR_R_CRYPTO_LIB, F);
            return fail(ttmp, stmp);
        }
        1
    }
}

ffi_export! {
    /// The number of the attribute's values (0 for NULL).
    ///
    /// # Safety
    /// `attr` is NULL or a live attribute.
    pub unsafe extern "C" fn X509_ATTRIBUTE_count(attr_: *const X509_ATTRIBUTE) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { attr(attr_) }) else { return 0 };
        // SAFETY: its stack.
        unsafe { OPENSSL_sk_num(a.set) }
    }
}

ffi_export! {
    /// The attribute's object.
    ///
    /// # Safety
    /// `attr` is NULL or a live attribute.
    pub unsafe extern "C" fn X509_ATTRIBUTE_get0_object(attr_: *mut X509_ATTRIBUTE) -> *mut ASN1_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { attr(attr_) }) else {
            x509(ERR_R_PASSED_NULL_PARAMETER, "X509_ATTRIBUTE_get0_object");
            return ptr::null_mut();
        };
        a.object
    }
}

ffi_export! {
    /// The attribute's value at `idx`, or NULL.
    ///
    /// # Safety
    /// `attr` is NULL or a live attribute.
    pub unsafe extern "C" fn X509_ATTRIBUTE_get0_type(attr_: *mut X509_ATTRIBUTE, idx: c_int) -> *mut ASN1_TYPE
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { attr(attr_) }) else {
            x509(ERR_R_PASSED_NULL_PARAMETER, "X509_ATTRIBUTE_get0_type");
            return ptr::null_mut();
        };
        // SAFETY: its stack.
        unsafe { OPENSSL_sk_value(a.set, idx) }.cast()
    }
}

ffi_export! {
    /// The data of the attribute's value at `idx` if it is of `atrtype` (never a BOOLEAN or a
    /// NULL), else NULL with `X509_R_WRONG_TYPE`.
    ///
    /// # Safety
    /// `attr` is NULL or a live attribute.
    pub unsafe extern "C" fn X509_ATTRIBUTE_get0_data(attr_: *mut X509_ATTRIBUTE, idx: c_int, atrtype: c_int, _data: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let ttmp = unsafe { X509_ATTRIBUTE_get0_type(attr_, idx) };
        // SAFETY: a value of the attribute, or NULL.
        let Some(t) = (unsafe { ttmp.as_ref() }) else { return ptr::null_mut() };
        // SAFETY: as above.
        if atrtype == V_ASN1_BOOLEAN || atrtype == V_ASN1_NULL || atrtype != unsafe { ASN1_TYPE_get(ttmp) } {
            x509(X509_R_WRONG_TYPE, "X509_ATTRIBUTE_get0_data");
            return ptr::null_mut();
        }
        // SAFETY: the union's pointer member, as the type says.
        unsafe { t.value.ptr }.cast()
    }
}

ffi_export! {
    /// Makes (or, with `*attr`, sets) an attribute of `obj` with one value, as
    /// `X509_ATTRIBUTE_set1_data` makes it. The attribute, or NULL.
    ///
    /// # Safety
    /// `attr` is NULL or holds NULL or a live attribute; `obj` is NULL or a live object;
    /// `data` is what `X509_ATTRIBUTE_set1_data` takes.
    pub unsafe extern "C" fn X509_ATTRIBUTE_create_by_OBJ(attr_: *mut *mut X509_ATTRIBUTE, obj: *const ASN1_OBJECT, atrtype: c_int, data: *const c_void, len: c_int) -> *mut X509_ATTRIBUTE
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let given = if attr_.is_null() { ptr::null_mut() } else { unsafe { attr_.read() } };
        let ret = if given.is_null() {
            // SAFETY: no preconditions.
            let r = unsafe { X509_ATTRIBUTE_new() };
            if r.is_null() {
                x509(ERR_R_ASN1_LIB, "X509_ATTRIBUTE_create_by_OBJ");
                return ptr::null_mut();
            }
            r
        } else {
            given
        };
        // SAFETY: the attribute; the caller's object and data.
        let ok = unsafe { X509_ATTRIBUTE_set1_object(ret, obj) } != 0
            // SAFETY: as above.
            && unsafe { X509_ATTRIBUTE_set1_data(ret, atrtype, data, len) } != 0;
        if !ok {
            if ret != given {
                // SAFETY: made above.
                unsafe { X509_ATTRIBUTE_free(ret) };
            }
            return ptr::null_mut();
        }
        if !attr_.is_null() && given.is_null() {
            // SAFETY: the caller's slot.
            unsafe { attr_.write(ret) };
        }
        ret
    }
}

ffi_export! {
    /// As `X509_ATTRIBUTE_create_by_OBJ` with the NID's object (`X509_R_UNKNOWN_NID` for an
    /// unknown NID).
    ///
    /// # Safety
    /// As for `X509_ATTRIBUTE_create_by_OBJ`.
    pub unsafe extern "C" fn X509_ATTRIBUTE_create_by_NID(attr_: *mut *mut X509_ATTRIBUTE, nid: c_int, atrtype: c_int, data: *const c_void, len: c_int) -> *mut X509_ATTRIBUTE
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let obj = unsafe { OBJ_nid2obj(nid) };
        if obj.is_null() {
            x509(X509_R_UNKNOWN_NID, "X509_ATTRIBUTE_create_by_NID");
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee; the object.
        let ret = unsafe { X509_ATTRIBUTE_create_by_OBJ(attr_, obj, atrtype, data, len) };
        if ret.is_null() {
            // SAFETY: the object (a built-in one is left alone).
            unsafe { ASN1_OBJECT_free(obj) };
        }
        ret
    }
}

ffi_export! {
    /// As `X509_ATTRIBUTE_create_by_OBJ` with the object named or given in dotted form
    /// (`X509_R_INVALID_FIELD_NAME` with the name, for neither).
    ///
    /// # Safety
    /// As for `X509_ATTRIBUTE_create_by_OBJ`; `atrname` is a string.
    pub unsafe extern "C" fn X509_ATTRIBUTE_create_by_txt(attr_: *mut *mut X509_ATTRIBUTE, atrname: *const c_char, type_: c_int, bytes: *const c_uchar, len: c_int) -> *mut X509_ATTRIBUTE
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's string.
        let obj = unsafe { OBJ_txt2obj(atrname, 0) };
        if obj.is_null() {
            let name = if atrname.is_null() {
                String::from("(null)")
            } else {
                // SAFETY: as above.
                unsafe { CStr::from_ptr(atrname) }.to_string_lossy().into_owned()
            };
            err::raise_with_text(ERR_LIB_X509, X509_R_INVALID_FIELD_NAME, "X509_ATTRIBUTE_create_by_txt", &format!("name={name}"));
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee; the object.
        let ret = unsafe { X509_ATTRIBUTE_create_by_OBJ(attr_, obj, type_, bytes.cast(), len) };
        // SAFETY: made above; the attribute holds its own copy.
        unsafe { ASN1_OBJECT_free(obj) };
        ret
    }
}

ffi_export! {
    /// The number of attributes in the stack (-1 for NULL).
    ///
    /// # Safety
    /// `x` is NULL or a live stack of attributes.
    pub unsafe extern "C" fn X509at_get_attr_count(x: *const AttrStack) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { OPENSSL_sk_num(x.cast()) }
    }
}

/// `X509at_get_attr_by_OBJ`.
///
/// # Safety
/// `sk` is NULL or a live stack of attributes; `obj` is a live object.
unsafe fn by_obj(sk: *const AttrStack, obj: *const ASN1_OBJECT, lastpos: c_int) -> c_int {
    if sk.is_null() {
        return -1;
    }
    let start = lastpos.saturating_add(1).max(0);
    // SAFETY: the caller's stack.
    let n = unsafe { OPENSSL_sk_num(sk.cast()) };
    for i in start..n {
        // SAFETY: the caller's stack.
        let v = unsafe { OPENSSL_sk_value(sk.cast(), i) };
        // SAFETY: an attribute of the stack.
        let Some(a) = (unsafe { attr(v.cast()) }) else {
            continue;
        };
        // SAFETY: its object; the caller's.
        if unsafe { OBJ_cmp(a.object, obj) } == 0 {
            return i;
        }
    }
    -1
}

ffi_export! {
    /// The position of the first attribute of `obj` after `lastpos`, or -1.
    ///
    /// # Safety
    /// `sk` is NULL or a live stack of attributes; `obj` is NULL or a live object.
    pub unsafe extern "C" fn X509at_get_attr_by_OBJ(sk: *const AttrStack, obj: *const ASN1_OBJECT, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { by_obj(sk, obj, lastpos) }
    }
}

ffi_export! {
    /// As `X509at_get_attr_by_OBJ` with the NID's object: -2 for an unknown NID.
    ///
    /// # Safety
    /// `x` is NULL or a live stack of attributes.
    pub unsafe extern "C" fn X509at_get_attr_by_NID(x: *const AttrStack, nid: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let obj = unsafe { OBJ_nid2obj(nid) };
        if obj.is_null() {
            return -2;
        }
        // SAFETY: the caller's guarantee; the object.
        unsafe { by_obj(x, obj, lastpos) }
    }
}

/// The attribute at `loc` of the stack, with the errors of OpenSSL's checks.
///
/// # Safety
/// `x` is NULL or a live stack of attributes.
unsafe fn checked_loc(x: *const AttrStack, loc: c_int, func: &str) -> bool {
    if x.is_null() {
        x509(ERR_R_PASSED_NULL_PARAMETER, func);
        return false;
    }
    // SAFETY: the caller's stack.
    if unsafe { OPENSSL_sk_num(x.cast()) } <= loc || loc < 0 {
        x509(ERR_R_PASSED_INVALID_ARGUMENT, func);
        return false;
    }
    true
}

ffi_export! {
    /// The attribute at `loc`, or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live stack of attributes.
    pub unsafe extern "C" fn X509at_get_attr(x: *const AttrStack, loc: c_int) -> *mut X509_ATTRIBUTE
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { checked_loc(x, loc, "X509at_get_attr") } {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        unsafe { OPENSSL_sk_value(x.cast(), loc) }.cast()
    }
}

ffi_export! {
    /// Removes the attribute at `loc` and returns it (the caller's), or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live stack of attributes.
    pub unsafe extern "C" fn X509at_delete_attr(x: *mut AttrStack, loc: c_int) -> *mut X509_ATTRIBUTE
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { checked_loc(x, loc, "X509at_delete_attr") } {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        unsafe { OPENSSL_sk_delete(x.cast(), loc) }.cast()
    }
}

/// `ossl_x509at_add1_attr`: a copy of `attr` pushed onto `*x` (a new stack if it's NULL). The
/// stack, or NULL.
///
/// # Safety
/// `x` is NULL or holds NULL or a live stack of attributes; `attr` is NULL or a live attribute.
pub(crate) unsafe fn add1(x: *mut *mut AttrStack, attr_: *const X509_ATTRIBUTE) -> *mut AttrStack {
    const F: &str = "ossl_x509at_add1_attr";
    if x.is_null() || attr_.is_null() {
        x509(ERR_R_PASSED_NULL_PARAMETER, F);
        return ptr::null_mut();
    }
    // SAFETY: the caller's guarantee.
    let old = unsafe { x.read() };
    let sk = if old.is_null() {
        // SAFETY: no preconditions.
        let s: *mut AttrStack = unsafe { OPENSSL_sk_new_null() }.cast();
        if s.is_null() {
            x509(ERR_R_CRYPTO_LIB, F);
            return ptr::null_mut();
        }
        s
    } else {
        old
    };
    let fail = |new_attr: *mut X509_ATTRIBUTE| {
        // SAFETY: made here, or NULL.
        unsafe { X509_ATTRIBUTE_free(new_attr) };
        if old.is_null() {
            // SAFETY: the stack made above, empty.
            unsafe { OPENSSL_sk_free(sk.cast()) };
        }
        ptr::null_mut()
    };
    // SAFETY: the caller's attribute.
    let new_attr = unsafe { X509_ATTRIBUTE_dup(attr_) };
    if new_attr.is_null() {
        return fail(new_attr);
    }
    // SAFETY: the stack takes the copy.
    if unsafe { OPENSSL_sk_push(sk.cast(), new_attr.cast()) } == 0 {
        x509(ERR_R_CRYPTO_LIB, F);
        return fail(new_attr);
    }
    if old.is_null() {
        // SAFETY: the caller's slot.
        unsafe { x.write(sk) };
    }
    sk
}

/// Raises `X509_R_DUPLICATE_ATTRIBUTE` naming the object's NID.
fn duplicate(func: &str, nid: c_int) {
    // SAFETY: no preconditions.
    let sn = unsafe { OBJ_nid2sn(nid) };
    let name = if sn.is_null() {
        String::from("(null)")
    } else {
        // SAFETY: a static name.
        unsafe { CStr::from_ptr(sn) }.to_string_lossy().into_owned()
    };
    err::raise_with_text(
        ERR_LIB_X509,
        X509_R_DUPLICATE_ATTRIBUTE,
        func,
        &format!("name={name}"),
    );
}

ffi_export! {
    /// Adds a copy of the attribute to `*x` (made if NULL), unless it has one of the same
    /// object (`X509_R_DUPLICATE_ATTRIBUTE`). The stack, or NULL.
    ///
    /// # Safety
    /// `x` is NULL or holds NULL or a live stack of attributes; `attr` is NULL or a live
    /// attribute.
    pub unsafe extern "C" fn X509at_add1_attr(x: *mut *mut AttrStack, attr_: *mut X509_ATTRIBUTE) -> *mut AttrStack
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { attr(attr_) }).filter(|_| !x.is_null()) else {
            x509(ERR_R_PASSED_NULL_PARAMETER, "X509at_add1_attr");
            return ptr::null_mut();
        };
        // SAFETY: as above.
        let sk = unsafe { x.read() };
        // SAFETY: the stack; the attribute's object.
        if !sk.is_null() && unsafe { by_obj(sk, a.object, -1) } != -1 {
            // SAFETY: its object.
            duplicate("X509at_add1_attr", unsafe { OBJ_obj2nid(a.object) });
            return ptr::null_mut();
        }
        // SAFETY: as above.
        unsafe { add1(x, attr_) }
    }
}

/// Adds a new attribute to `*x` (unchecked for duplicates), made with `make`, which is freed.
///
/// # Safety
/// `x` is as `add1` takes it.
unsafe fn add_made(x: *mut *mut AttrStack, made: *mut X509_ATTRIBUTE) -> *mut AttrStack {
    if made.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller's guarantee; the attribute.
    let ret = unsafe { add1(x, made) };
    // SAFETY: made by the caller; the stack holds a copy.
    unsafe { X509_ATTRIBUTE_free(made) };
    ret
}

/// `ossl_x509at_add1_attr_by_OBJ`: [`X509at_add1_attr_by_OBJ`] without the duplicate check.
///
/// # Safety
/// As for [`X509at_add1_attr_by_OBJ`].
pub(crate) unsafe fn add1_by_obj(
    x: *mut *mut AttrStack,
    obj: *const ASN1_OBJECT,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> *mut AttrStack {
    // SAFETY: the caller's guarantee.
    let made =
        unsafe { X509_ATTRIBUTE_create_by_OBJ(ptr::null_mut(), obj, type_, bytes.cast(), len) };
    // SAFETY: as above.
    unsafe { add_made(x, made) }
}

/// `ossl_x509at_add1_attr_by_NID`: [`X509at_add1_attr_by_NID`] without the duplicate check.
///
/// # Safety
/// As for [`X509at_add1_attr_by_NID`].
pub(crate) unsafe fn add1_by_nid(
    x: *mut *mut AttrStack,
    nid: c_int,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> *mut AttrStack {
    // SAFETY: the caller's guarantee.
    let made =
        unsafe { X509_ATTRIBUTE_create_by_NID(ptr::null_mut(), nid, type_, bytes.cast(), len) };
    // SAFETY: as above.
    unsafe { add_made(x, made) }
}

/// `ossl_x509at_add1_attr_by_txt`: [`X509at_add1_attr_by_txt`] without the duplicate check.
///
/// # Safety
/// As for [`X509at_add1_attr_by_txt`].
pub(crate) unsafe fn add1_by_txt(
    x: *mut *mut AttrStack,
    attrname: *const c_char,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> *mut AttrStack {
    // SAFETY: the caller's guarantee.
    let made =
        unsafe { X509_ATTRIBUTE_create_by_txt(ptr::null_mut(), attrname, type_, bytes, len) };
    // SAFETY: as above.
    unsafe { add_made(x, made) }
}

ffi_export! {
    /// Adds an attribute of `obj` with one value (as `X509_ATTRIBUTE_set1_data` makes it),
    /// unless `*x` has one of `obj`. The stack, or NULL.
    ///
    /// # Safety
    /// `x` is NULL or holds NULL or a live stack of attributes; `obj` is NULL or a live
    /// object; `bytes` is what `X509_ATTRIBUTE_set1_data` takes.
    pub unsafe extern "C" fn X509at_add1_attr_by_OBJ(x: *mut *mut AttrStack, obj: *const ASN1_OBJECT, type_: c_int, bytes: *const c_uchar, len: c_int) -> *mut AttrStack
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        if x.is_null() || obj.is_null() {
            x509(ERR_R_PASSED_NULL_PARAMETER, "X509at_add1_attr_by_OBJ");
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let sk = unsafe { x.read() };
        // SAFETY: as above.
        if !sk.is_null() && unsafe { by_obj(sk, obj, -1) } != -1 {
            // SAFETY: the caller's object.
            duplicate("X509at_add1_attr_by_OBJ", unsafe { OBJ_obj2nid(obj) });
            return ptr::null_mut();
        }
        // SAFETY: as above.
        let made = unsafe { X509_ATTRIBUTE_create_by_OBJ(ptr::null_mut(), obj, type_, bytes.cast(), len) };
        // SAFETY: as above.
        unsafe { add_made(x, made) }
    }
}

ffi_export! {
    /// As `X509at_add1_attr_by_OBJ` with the NID's object.
    ///
    /// # Safety
    /// As for `X509at_add1_attr_by_OBJ`.
    pub unsafe extern "C" fn X509at_add1_attr_by_NID(x: *mut *mut AttrStack, nid: c_int, type_: c_int, bytes: *const c_uchar, len: c_int) -> *mut AttrStack
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        if x.is_null() {
            x509(ERR_R_PASSED_NULL_PARAMETER, "X509at_add1_attr_by_NID");
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let sk = unsafe { x.read() };
        // SAFETY: as above.
        if !sk.is_null() && unsafe { X509at_get_attr_by_NID(sk, nid, -1) } != -1 {
            duplicate("X509at_add1_attr_by_NID", nid);
            return ptr::null_mut();
        }
        // SAFETY: as above.
        let made = unsafe { X509_ATTRIBUTE_create_by_NID(ptr::null_mut(), nid, type_, bytes.cast(), len) };
        // SAFETY: as above.
        unsafe { add_made(x, made) }
    }
}

ffi_export! {
    /// As `X509at_add1_attr_by_OBJ` with the object named or in dotted form.
    ///
    /// # Safety
    /// As for `X509at_add1_attr_by_OBJ`; `attrname` is a string.
    pub unsafe extern "C" fn X509at_add1_attr_by_txt(x: *mut *mut AttrStack, attrname: *const c_char, type_: c_int, bytes: *const c_uchar, len: c_int) -> *mut AttrStack
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let made = unsafe { X509_ATTRIBUTE_create_by_txt(ptr::null_mut(), attrname, type_, bytes, len) };
        if made.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: as above; the attribute.
        let ret = unsafe { X509at_add1_attr(x, made) };
        // SAFETY: made above; the stack holds a copy.
        unsafe { X509_ATTRIBUTE_free(made) };
        ret
    }
}

ffi_export! {
    /// The data of the value of the attribute of `obj` after `lastpos`, if it is of `type_`:
    /// for `lastpos` -2, of the only such attribute; for -3, of the only one, with one value.
    ///
    /// # Safety
    /// `x` is NULL or a live stack of attributes; `obj` is NULL or a live object.
    pub unsafe extern "C" fn X509at_get0_data_by_OBJ(x: *const AttrStack, obj: *const ASN1_OBJECT, lastpos: c_int, type_: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let i = unsafe { by_obj(x, obj, lastpos) };
        if i == -1 {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        if lastpos <= -2 && unsafe { by_obj(x, obj, i) } != -1 {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        let at = unsafe { X509at_get_attr(x, i) };
        // SAFETY: the attribute.
        if lastpos <= -3 && unsafe { X509_ATTRIBUTE_count(at) } != 1 {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        unsafe { X509_ATTRIBUTE_get0_data(at, 0, type_, ptr::null_mut()) }
    }
}

/// `PKCS12_get_attr_gen`: the first value of the first attribute of the NID, or NULL.
///
/// # Safety
/// `attrs` is NULL or a live stack of attributes.
pub(crate) unsafe fn get_attr_gen(attrs: *const AttrStack, nid: c_int) -> *mut ASN1_TYPE {
    // SAFETY: the caller's guarantee.
    let i = unsafe { X509at_get_attr_by_NID(attrs, nid, -1) };
    if i < 0 {
        return ptr::null_mut();
    }
    // SAFETY: as above.
    let at = unsafe { X509at_get_attr(attrs, i) };
    // SAFETY: the attribute.
    unsafe { X509_ATTRIBUTE_get0_type(at, 0) }
}
