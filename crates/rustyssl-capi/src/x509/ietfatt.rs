//! RFC 5755's IetfAttrSyntax (`x_ietfatt.c`): `OSSL_IETF_ATTR_SYNTAX`, an optional policy
//! authority and a SEQUENCE OF values that are all octet strings, all OIDs, or all UTF-8 strings
//! (section 4.4.2), with its accessors and its print.

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ASN1_ITEM, ASN1_OBJECT, ASN1_STRING, ASN1_TFLG_IMPLICIT, ASN1_TFLG_OPTIONAL,
    ASN1_TFLG_SEQUENCE_OF, ASN1_VALUE, BIO, ERR_LIB_ASN1, ERR_LIB_X509V3, ERR_R_CRYPTO_LIB,
    ERR_R_PASSED_INVALID_ARGUMENT, GENERAL_NAME, GENERAL_NAMES, OSSL_IETF_ATTR_SYNTAX,
    OSSL_IETF_ATTR_SYNTAX_VALUE, OSSL_IETFAS_OCTETS, OSSL_IETFAS_OID, OSSL_IETFAS_STRING,
};

use crate::asn1::text::ASN1_STRING_print;
use crate::asn1::tpl::decode::ASN1_item_d2i;
use crate::asn1::tpl::items::{
    ASN1_OBJECT_it, ASN1_OCTET_STRING_it, ASN1_UTF8STRING_it, i2d, new_free,
};
use crate::asn1::tpl::statics::{Templates, choice, sequence};
use crate::asn1::tpl::{item_fns, template_at};
use crate::bio::print::BIO_printf;
use crate::err;
use crate::ffi::ffi_export;
use crate::objects::OBJ_obj2txt;
use crate::stack::{OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value};
use crate::x509v3::genn::{GENERAL_NAME_it, GENERAL_NAMES_free};
use crate::x509v3::san::GENERAL_NAME_print;

/// `OSSL_IETF_ATTR_SYNTAX_VALUE`: a CHOICE of the three value types.
#[repr(C)]
struct Value {
    /// `OSSL_IETFAS_*`.
    type_: c_int,
    /// The octets (`ASN1_OCTET_STRING`), the OID (`ASN1_OBJECT`), or the string
    /// (`ASN1_UTF8STRING`), as `type_` says.
    u: *mut c_void,
}

/// `OSSL_IETF_ATTR_SYNTAX`.
#[repr(C)]
struct Syntax {
    policy_authority: *mut GENERAL_NAMES,
    /// The values' type, set by the first value added or decoded.
    type_: c_int,
    values: *mut c_void,
}

static VALUE_TT: Templates<3> = Templates([
    template_at(
        0,
        0,
        offset_of!(Value, u),
        c"u.octets",
        ASN1_OCTET_STRING_it,
    ),
    template_at(0, 0, offset_of!(Value, u), c"u.oid", ASN1_OBJECT_it),
    template_at(0, 0, offset_of!(Value, u), c"u.string", ASN1_UTF8STRING_it),
]);

item_fns! {
    /// CHOICE { octets OCTET STRING, oid OBJECT IDENTIFIER, string UTF8String }.
    pub unsafe extern "C" fn OSSL_IETF_ATTR_SYNTAX_VALUE_it = choice::<Value, 3>(&VALUE_TT, offset_of!(Value, type_), None, c"OSSL_IETF_ATTR_SYNTAX_VALUE");
}

static SYNTAX_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(Syntax, policy_authority),
        c"policyAuthority",
        GENERAL_NAME_it,
    ),
    template_at(
        ASN1_TFLG_SEQUENCE_OF,
        0,
        offset_of!(Syntax, values),
        c"values",
        OSSL_IETF_ATTR_SYNTAX_VALUE_it,
    ),
]);

item_fns! {
    /// IetfAttrSyntax: SEQUENCE { policyAuthority [0] GeneralNames OPTIONAL, values }.
    pub unsafe extern "C" fn OSSL_IETF_ATTR_SYNTAX_it = sequence::<Syntax, 2>(&SYNTAX_TT, None, c"OSSL_IETF_ATTR_SYNTAX");
}

new_free! {
    pub unsafe extern "C" fn OSSL_IETF_ATTR_SYNTAX_new, pub unsafe extern "C" fn OSSL_IETF_ATTR_SYNTAX_free(OSSL_IETF_ATTR_SYNTAX) = OSSL_IETF_ATTR_SYNTAX_it;
}

new_free! {
    pub unsafe extern "C" fn OSSL_IETF_ATTR_SYNTAX_VALUE_new, pub unsafe extern "C" fn OSSL_IETF_ATTR_SYNTAX_VALUE_free(OSSL_IETF_ATTR_SYNTAX_VALUE) = OSSL_IETF_ATTR_SYNTAX_VALUE_it;
}

i2d! {
    /// Encodes an IetfAttrSyntax.
    pub unsafe extern "C" fn i2d_OSSL_IETF_ATTR_SYNTAX(OSSL_IETF_ATTR_SYNTAX) = OSSL_IETF_ATTR_SYNTAX_it;
}

/// The structure behind a handle.
///
/// # Safety
/// `a` is NULL or a live `OSSL_IETF_ATTR_SYNTAX`.
unsafe fn syntax<'a>(a: *const OSSL_IETF_ATTR_SYNTAX) -> Option<&'a mut Syntax> {
    // SAFETY: the caller's guarantee; the item engine allocated it with this layout.
    unsafe { a.cast::<Syntax>().cast_mut().as_mut() }
}

/// The value at `i` of the values (NULL past the end or without values).
///
/// # Safety
/// `s` is a live structure.
unsafe fn value_at<'a>(s: &Syntax, i: c_int) -> Option<&'a Value> {
    // SAFETY: the structure's stack (or NULL, whose values are all NULL).
    let v = unsafe { OPENSSL_sk_value(s.values.cast(), i) };
    // SAFETY: a value of the stack, or NULL.
    unsafe { v.cast::<Value>().as_ref() }
}

ffi_export! {
    /// Decodes an IetfAttrSyntax, failing (and freeing what it decoded, NULL in `*a`) when its
    /// values aren't all of one type.
    ///
    /// # Safety
    /// As for `ASN1_item_d2i`, with `a` NULL or a slot for an IetfAttrSyntax.
    pub unsafe extern "C" fn d2i_OSSL_IETF_ATTR_SYNTAX(a: *mut *mut OSSL_IETF_ATTR_SYNTAX, in_: *mut *const c_uchar, len: c_long) -> *mut OSSL_IETF_ATTR_SYNTAX
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { OSSL_IETF_ATTR_SYNTAX_it() };
        // SAFETY: the caller's guarantee.
        let ias: *mut OSSL_IETF_ATTR_SYNTAX =
            unsafe { ASN1_item_d2i(a.cast::<*mut ASN1_VALUE>(), in_, len, it) }.cast();
        // SAFETY: what the decoder made, or NULL.
        let Some(s) = (unsafe { syntax(ias) }) else {
            return ptr::null_mut();
        };
        // SAFETY: the structure's stack.
        let n = unsafe { OPENSSL_sk_num(s.values.cast()) };
        for i in 0..n {
            // SAFETY: the decoded structure; an index within its values.
            let Some(v) = (unsafe { value_at(s, i) }) else {
                continue;
            };
            if i == 0 {
                s.type_ = v.type_;
            } else if v.type_ != s.type_ {
                // SAFETY: what the decoder made, freed once.
                unsafe { OSSL_IETF_ATTR_SYNTAX_free(ias) };
                if !a.is_null() {
                    // SAFETY: the caller's slot.
                    unsafe { *a = ptr::null_mut() };
                }
                err::raise(ERR_LIB_X509V3, ERR_R_PASSED_INVALID_ARGUMENT, "d2i_OSSL_IETF_ATTR_SYNTAX");
                return ptr::null_mut();
            }
        }
        ias
    }
}

ffi_export! {
    /// The number of values.
    ///
    /// # Safety
    /// `a` is a live IetfAttrSyntax.
    pub unsafe extern "C" fn OSSL_IETF_ATTR_SYNTAX_get_value_num(a: *const OSSL_IETF_ATTR_SYNTAX) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { syntax(a) }) else {
            return 0;
        };
        if s.values.is_null() {
            return 0;
        }
        // SAFETY: the structure's stack.
        unsafe { OPENSSL_sk_num(s.values.cast()) }
    }
}

ffi_export! {
    /// The policy authority's names, or NULL.
    ///
    /// # Safety
    /// `a` is a live IetfAttrSyntax.
    pub unsafe extern "C" fn OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority(a: *const OSSL_IETF_ATTR_SYNTAX) -> *const GENERAL_NAMES
    where failure = ptr::null(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { syntax(a) }.map_or(ptr::null(), |s| s.policy_authority.cast_const())
    }
}

ffi_export! {
    /// Replaces the policy authority with `names` (which it takes), freeing the old one.
    ///
    /// # Safety
    /// `a` is a live IetfAttrSyntax; `names` is NULL or a stack of names it may own.
    pub unsafe extern "C" fn OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority(a: *mut OSSL_IETF_ATTR_SYNTAX, names: *mut GENERAL_NAMES)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { syntax(a) }) else {
            return;
        };
        // SAFETY: the structure's own names, or NULL.
        unsafe { GENERAL_NAMES_free(s.policy_authority) };
        s.policy_authority = names;
    }
}

ffi_export! {
    /// The value at `ind` (its type in `*type_` when that isn't NULL), or NULL.
    ///
    /// # Safety
    /// `a` is a live IetfAttrSyntax; `type_` is NULL or writable.
    pub unsafe extern "C" fn OSSL_IETF_ATTR_SYNTAX_get0_value(a: *const OSSL_IETF_ATTR_SYNTAX, ind: c_int, type_: *mut c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { syntax(a) }) else {
            return ptr::null_mut();
        };
        // SAFETY: as above.
        let Some(v) = (unsafe { value_at(s, ind) }) else {
            return ptr::null_mut();
        };
        if !type_.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { *type_ = v.type_ };
        }
        match v.type_ {
            OSSL_IETFAS_OCTETS | OSSL_IETFAS_OID | OSSL_IETFAS_STRING => v.u,
            _ => ptr::null_mut(),
        }
    }
}

ffi_export! {
    /// Appends a value of `type_` (`OSSL_IETFAS_*`), taking `data` (an `ASN1_OCTET_STRING`,
    /// `ASN1_OBJECT`, or `ASN1_UTF8STRING`). The first value sets the type; a value of another
    /// type fails. As in OpenSSL, the value is the structure's from then on, even when the push
    /// fails (it is freed with the value then).
    ///
    /// # Safety
    /// `a` is a live IetfAttrSyntax; `data` is NULL or a value of the type that it may own.
    pub unsafe extern "C" fn OSSL_IETF_ATTR_SYNTAX_add1_value(a: *mut OSSL_IETF_ATTR_SYNTAX, type_: c_int, data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        const F: &str = "OSSL_IETF_ATTR_SYNTAX_add1_value";
        if data.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { syntax(a) }) else {
            return 0;
        };
        if s.values.is_null() {
            // SAFETY: no preconditions.
            s.values = unsafe { OPENSSL_sk_new_null() }.cast();
            if s.values.is_null() {
                err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, F);
                return 0;
            }
            s.type_ = type_;
        }
        if type_ != s.type_ {
            err::raise(ERR_LIB_X509V3, ERR_R_PASSED_INVALID_ARGUMENT, F);
            return 0;
        }
        // SAFETY: no preconditions.
        let val = unsafe { OSSL_IETF_ATTR_SYNTAX_VALUE_new() };
        // SAFETY: what the item engine allocated with this layout, or NULL.
        let Some(v) = (unsafe { val.cast::<Value>().as_mut() }) else {
            err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, F);
            return 0;
        };
        v.type_ = type_;
        if !matches!(type_, OSSL_IETFAS_OCTETS | OSSL_IETFAS_OID | OSSL_IETFAS_STRING) {
            // SAFETY: the value made above, with nothing in it, freed once.
            unsafe { OSSL_IETF_ATTR_SYNTAX_VALUE_free(val) };
            err::raise(ERR_LIB_X509V3, ERR_R_PASSED_INVALID_ARGUMENT, F);
            return 0;
        }
        v.u = data;
        // SAFETY: the structure's stack and the new value.
        if unsafe { OPENSSL_sk_push(s.values.cast(), val.cast()) } <= 0 {
            // SAFETY: the value made above, freed once (with the caller's data in it).
            unsafe { OSSL_IETF_ATTR_SYNTAX_VALUE_free(val) };
            return 0;
        }
        1
    }
}

/// `BIO_printf(bp, "%*s", indent, "")`, whose result the print checks: 0 (nothing written) for
/// an indent of 0, as in OpenSSL.
///
/// # Safety
/// `bp` is a live BIO.
unsafe fn indent(bp: *mut BIO, indent: c_int) -> c_int {
    // SAFETY: the caller's BIO; a static format and its arguments.
    unsafe { BIO_printf(bp, c"%*s".as_ptr(), indent, c"".as_ptr()) }
}

ffi_export! {
    /// Prints the policy authority's names, one a line, then the values, all on one line.
    /// Returns 1, or 0 when a write reports nothing written: as in OpenSSL, an indent of 0
    /// stops the print at its first indent.
    ///
    /// # Safety
    /// `bp` is a live BIO; `a` is a live IetfAttrSyntax.
    pub unsafe extern "C" fn OSSL_IETF_ATTR_SYNTAX_print(bp: *mut BIO, a: *mut OSSL_IETF_ATTR_SYNTAX, indent_: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { syntax(a) }) else {
            return 0;
        };
        if !s.policy_authority.is_null() {
            // SAFETY: the structure's names.
            let n = unsafe { OPENSSL_sk_num(s.policy_authority.cast()) };
            for i in 0..n {
                // SAFETY: the caller's BIO.
                if unsafe { indent(bp, indent_) } <= 0 {
                    return 0;
                }
                // SAFETY: an index within the names.
                let g = unsafe { OPENSSL_sk_value(s.policy_authority.cast(), i) };
                // SAFETY: the caller's BIO; a name of the stack.
                if unsafe { GENERAL_NAME_print(bp, g.cast::<GENERAL_NAME>()) } <= 0 {
                    return 0;
                }
                // SAFETY: the caller's BIO; a static format.
                if unsafe { BIO_printf(bp, c"\n".as_ptr()) } <= 0 {
                    return 0;
                }
            }
        }
        // SAFETY: the caller's structure.
        let n = unsafe { OSSL_IETF_ATTR_SYNTAX_get_value_num(a) };
        for i in 0..n {
            let mut t: c_int = 0;
            // SAFETY: as above.
            let value = unsafe { OSSL_IETF_ATTR_SYNTAX_get0_value(a, i, &raw mut t) };
            if value.is_null() {
                return 0;
            }
            // SAFETY: the caller's BIO.
            if unsafe { indent(bp, indent_) } <= 0 {
                return 0;
            }
            match t {
                OSSL_IETFAS_OID => {
                    let mut oid = [0 as c_char; 80];
                    // SAFETY: a local buffer of its length; the value's object.
                    unsafe { OBJ_obj2txt(oid.as_mut_ptr(), 80, value.cast::<ASN1_OBJECT>(), 0) };
                    // SAFETY: the caller's BIO; a static format and the (terminated) text.
                    unsafe { BIO_printf(bp, c"%.*s".as_ptr(), 80, oid.as_ptr()) };
                }
                OSSL_IETFAS_OCTETS | OSSL_IETFAS_STRING => {
                    // SAFETY: the caller's BIO; the value's string.
                    unsafe { ASN1_STRING_print(bp, value.cast::<ASN1_STRING>()) };
                }
                _ => {}
            }
        }
        // SAFETY: the caller's BIO; a static format.
        if unsafe { BIO_printf(bp, c"\n".as_ptr()) } <= 0 {
            return 0;
        }
        1
    }
}
