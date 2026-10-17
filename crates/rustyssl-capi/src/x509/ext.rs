//! Extensions as structures (`x_exten.c`, `x509_v3.c`): `X509_EXTENSION` (its object, its
//! critical flag, and its value's octets) and the `X509v3_*` functions over a stack of them,
//! which certificates, requests, and CRLs keep their extensions in. What an extension's value
//! means is the X509v3 methods' (step 5.2).

use core::ffi::c_int;
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ASN1_BOOLEAN, ASN1_ITEM, ASN1_ITYPE_PRIMITIVE, ASN1_OBJECT, ASN1_OCTET_STRING, ASN1_STRING,
    ASN1_TFLG_EMBED, ASN1_TFLG_OPTIONAL, ASN1_TFLG_SEQUENCE_OF, ERR_LIB_ASN1, ERR_LIB_X509,
    ERR_R_ASN1_LIB, ERR_R_CRYPTO_LIB, ERR_R_PASSED_NULL_PARAMETER, OPENSSL_STACK, X509_EXTENSION,
    X509_EXTENSIONS, X509_R_UNKNOWN_NID, stack_st_X509_EXTENSION,
};

use crate::asn1::string::ASN1_STRING_set;
use crate::asn1::tpl::items::{
    ASN1_FBOOLEAN_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_it, d2i, i2d, new_free,
};
use crate::asn1::tpl::statics::{Templates, sequence};
use crate::asn1::tpl::util::ASN1_item_dup;
use crate::asn1::tpl::{Template, item, item_fns, template, template_at};
use crate::err;
use crate::ffi::ffi_export;
use crate::objects::{ASN1_OBJECT_free, OBJ_cmp, OBJ_dup, OBJ_nid2obj};
use crate::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_free, OPENSSL_sk_insert, OPENSSL_sk_new_null, OPENSSL_sk_num,
    OPENSSL_sk_value,
};

/// `X509_EXTENSION` (`X509_extension_st`).
#[repr(C)]
pub(crate) struct Ext {
    pub(crate) object: *mut ASN1_OBJECT,
    /// 0xFF for critical, 0 (or the default -1 of a decoded absent one) for not.
    pub(crate) critical: ASN1_BOOLEAN,
    /// The value's octets, embedded.
    pub(crate) value: ASN1_STRING,
}

static EXT_TT: Templates<3> = Templates([
    template_at(0, 0, offset_of!(Ext, object), c"object", ASN1_OBJECT_it),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(Ext, critical),
        c"critical",
        ASN1_FBOOLEAN_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Ext, value),
        c"value",
        ASN1_OCTET_STRING_it,
    ),
]);

item_fns! {
    /// Extension: SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE,
    /// extnValue OCTET STRING }.
    pub unsafe extern "C" fn X509_EXTENSION_it = sequence::<Ext, 3>(&EXT_TT, None, c"X509_EXTENSION");
}

new_free! {
    pub unsafe extern "C" fn X509_EXTENSION_new, pub unsafe extern "C" fn X509_EXTENSION_free(X509_EXTENSION) = X509_EXTENSION_it;
}

i2d! {
    /// Encodes an Extension.
    pub unsafe extern "C" fn i2d_X509_EXTENSION(X509_EXTENSION) = X509_EXTENSION_it;
}

d2i! {
    /// Decodes an Extension.
    pub unsafe extern "C" fn d2i_X509_EXTENSION(X509_EXTENSION) = X509_EXTENSION_it;
}

/// The template of `X509_EXTENSIONS`.
static EXTS: Template = template(ASN1_TFLG_SEQUENCE_OF, 0, c"Extension", X509_EXTENSION_it);

item_fns! {
    /// Extensions: a SEQUENCE OF Extension, a stack of `X509_EXTENSION`s.
    pub unsafe extern "C" fn X509_EXTENSIONS_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const EXTS.0, 0, ptr::null(), 0, c"X509_EXTENSIONS");
}

i2d! {
    /// Encodes a SEQUENCE OF Extension.
    pub unsafe extern "C" fn i2d_X509_EXTENSIONS(X509_EXTENSIONS) = X509_EXTENSIONS_it;
}

d2i! {
    /// Decodes a SEQUENCE OF Extension.
    pub unsafe extern "C" fn d2i_X509_EXTENSIONS(X509_EXTENSIONS) = X509_EXTENSIONS_it;
}

ffi_export! {
    /// A copy of the extension, or NULL.
    ///
    /// # Safety
    /// `ex` is NULL or a live extension.
    pub unsafe extern "C" fn X509_EXTENSION_dup(ex: *const X509_EXTENSION) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_EXTENSION_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_dup(it, ex.cast_mut().cast()) }.cast()
    }
}

/// The structure behind a pointer.
///
/// # Safety
/// `p` is NULL or a live `X509_EXTENSION`, which nothing else changes while the reference
/// lives.
pub(crate) unsafe fn ext_of<'a>(p: *const X509_EXTENSION) -> Option<&'a mut Ext> {
    // SAFETY: the caller's guarantee; an `X509_EXTENSION` is an `Ext`.
    unsafe { p.cast::<Ext>().cast_mut().as_mut() }
}

ffi_export! {
    /// The extension's object (the extension's), or NULL.
    ///
    /// # Safety
    /// `ex` is NULL or a live extension.
    pub unsafe extern "C" fn X509_EXTENSION_get_object(ex: *mut X509_EXTENSION) -> *mut ASN1_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ext_of(ex) }.map_or(ptr::null_mut(), |e| e.object)
    }
}

ffi_export! {
    /// The extension's value (the extension's own OCTET STRING), or NULL.
    ///
    /// # Safety
    /// `ex` is NULL or a live extension.
    pub unsafe extern "C" fn X509_EXTENSION_get_data(ex: *mut X509_EXTENSION) -> *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ext_of(ex) }.map_or(ptr::null_mut(), |e| (&raw mut e.value).cast())
    }
}

ffi_export! {
    /// 1 if the extension is critical, else 0 (also for NULL).
    ///
    /// # Safety
    /// `ex` is NULL or a live extension.
    pub unsafe extern "C" fn X509_EXTENSION_get_critical(ex: *const X509_EXTENSION) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { ext_of(ex) }.map_or(0, |e| c_int::from(e.critical > 0))
    }
}

ffi_export! {
    /// Sets the extension's object (a copy): 1, or 0.
    ///
    /// # Safety
    /// `ex` is NULL or a live extension; `obj` is NULL or a live object.
    pub unsafe extern "C" fn X509_EXTENSION_set_object(ex: *mut X509_EXTENSION, obj: *const ASN1_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(e) = (unsafe { ext_of(ex) }).filter(|_| !obj.is_null()) else { return 0 };
        // SAFETY: the extension's object, given up.
        unsafe { ASN1_OBJECT_free(e.object) };
        // SAFETY: the caller's object.
        e.object = unsafe { OBJ_dup(obj) };
        c_int::from(!e.object.is_null())
    }
}

ffi_export! {
    /// Marks the extension critical (0xFF) or not: 1, or 0 for NULL.
    ///
    /// # Safety
    /// `ex` is NULL or a live extension.
    pub unsafe extern "C" fn X509_EXTENSION_set_critical(ex: *mut X509_EXTENSION, crit: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(e) = (unsafe { ext_of(ex) }) else { return 0 };
        e.critical = if crit != 0 { 0xFF } else { 0 };
        1
    }
}

ffi_export! {
    /// Sets the extension's value to a copy of the octets: 1, or 0. (OpenSSL reads through a
    /// NULL `data`; this refuses it.)
    ///
    /// # Safety
    /// `ex` is NULL or a live extension; `data` is NULL or a live string.
    pub unsafe extern "C" fn X509_EXTENSION_set_data(ex: *mut X509_EXTENSION, data: *mut ASN1_OCTET_STRING) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let (Some(e), Some(d)) = (unsafe { ext_of(ex) }, unsafe { data.cast::<ASN1_STRING>().as_ref() }) else { return 0 };
        // SAFETY: the extension's embedded string; the caller's octets.
        c_int::from(unsafe { ASN1_STRING_set(&raw mut e.value, d.data.cast(), d.length) } != 0)
    }
}

ffi_export! {
    /// The extension `*ex` (or a new one, stored in `*ex` when it was NULL) with the object,
    /// critical flag, and value; NULL on failure.
    ///
    /// # Safety
    /// `ex` is NULL or holds NULL or a live extension; `obj` is NULL or a live object; `data`
    /// is NULL or a live string.
    pub unsafe extern "C" fn X509_EXTENSION_create_by_OBJ(ex: *mut *mut X509_EXTENSION, obj: *const ASN1_OBJECT, crit: c_int, data: *mut ASN1_OCTET_STRING) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let given = if ex.is_null() { ptr::null_mut() } else { unsafe { ex.read() } };
        let ret = if given.is_null() {
            // SAFETY: no preconditions.
            let r = unsafe { X509_EXTENSION_new() };
            if r.is_null() {
                err::raise(ERR_LIB_X509, ERR_R_ASN1_LIB, "X509_EXTENSION_create_by_OBJ");
                return ptr::null_mut();
            }
            r
        } else {
            given
        };
        // SAFETY: the extension; the caller's object and value.
        let ok = unsafe { X509_EXTENSION_set_object(ret, obj) } != 0
            // SAFETY: as above.
            && unsafe { X509_EXTENSION_set_critical(ret, crit) } != 0
            // SAFETY: as above.
            && unsafe { X509_EXTENSION_set_data(ret, data) } != 0;
        if !ok {
            if given.is_null() {
                // SAFETY: made above.
                unsafe { X509_EXTENSION_free(ret) };
            }
            return ptr::null_mut();
        }
        if !ex.is_null() && given.is_null() {
            // SAFETY: the caller's slot.
            unsafe { ex.write(ret) };
        }
        ret
    }
}

ffi_export! {
    /// `X509_EXTENSION_create_by_OBJ` of a NID's object; NULL with `X509_R_UNKNOWN_NID` for
    /// an unknown NID.
    ///
    /// # Safety
    /// As for `X509_EXTENSION_create_by_OBJ`.
    pub unsafe extern "C" fn X509_EXTENSION_create_by_NID(ex: *mut *mut X509_EXTENSION, nid: c_int, crit: c_int, data: *mut ASN1_OCTET_STRING) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let obj = unsafe { OBJ_nid2obj(nid) };
        if obj.is_null() {
            err::raise(ERR_LIB_X509, X509_R_UNKNOWN_NID, "X509_EXTENSION_create_by_NID");
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee; a built-in object.
        let r = unsafe { X509_EXTENSION_create_by_OBJ(ex, obj, crit, data) };
        if r.is_null() {
            // SAFETY: a built-in object (freeing it does nothing), as OpenSSL frees it.
            unsafe { ASN1_OBJECT_free(obj) };
        }
        r
    }
}

// ---- Stacks of extensions (`x509_v3.c`) ----

/// `STACK_OF(X509_EXTENSION)`.
type Exts = stack_st_X509_EXTENSION;

/// The number of items on a stack (0 for NULL).
///
/// # Safety
/// `sk` is NULL or a live stack.
pub(crate) unsafe fn sk_count(sk: *const OPENSSL_STACK) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { OPENSSL_sk_num(sk) }.max(0)
}

ffi_export! {
    /// The number of extensions (0 for NULL).
    ///
    /// # Safety
    /// `x` is NULL or a live stack of extensions.
    pub unsafe extern "C" fn X509v3_get_ext_count(x: *const Exts) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        let x: *const OPENSSL_STACK = x.cast();
        // SAFETY: the caller's guarantee.
        unsafe { sk_count(x) }
    }
}

ffi_export! {
    /// The index of the next extension after `lastpos` of the object, or -1.
    ///
    /// # Safety
    /// `sk` is NULL or a live stack of extensions; `obj` is a live object.
    pub unsafe extern "C" fn X509v3_get_ext_by_OBJ(sk: *const Exts, obj: *const ASN1_OBJECT, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        let sk: *const OPENSSL_STACK = sk.cast();
        if sk.is_null() {
            return -1;
        }
        let start = lastpos.saturating_add(1).max(0);
        // SAFETY: the caller's guarantee.
        for i in start..unsafe { sk_count(sk) } {
            // SAFETY: as above.
            let v = unsafe { OPENSSL_sk_value(sk, i) };
            // SAFETY: an extension of the stack.
            let Some(e) = (unsafe { ext_of(v.cast()) }) else { continue };
            // SAFETY: the extension's object; the caller's.
            if unsafe { OBJ_cmp(e.object, obj) } == 0 {
                return i;
            }
        }
        -1
    }
}

ffi_export! {
    /// The index of the next extension after `lastpos` of the NID, -1 for none, or -2 for an
    /// unknown NID.
    ///
    /// # Safety
    /// `x` is NULL or a live stack of extensions.
    pub unsafe extern "C" fn X509v3_get_ext_by_NID(x: *const Exts, nid: c_int, lastpos: c_int) -> c_int
    where failure = -2, library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let obj = unsafe { OBJ_nid2obj(nid) };
        if obj.is_null() {
            return -2;
        }
        // SAFETY: the caller's guarantee; a built-in object.
        unsafe { X509v3_get_ext_by_OBJ(x, obj, lastpos) }
    }
}

ffi_export! {
    /// The index of the next extension after `lastpos` that is (or, for `crit` 0, isn't)
    /// critical, or -1.
    ///
    /// # Safety
    /// `sk` is NULL or a live stack of extensions.
    pub unsafe extern "C" fn X509v3_get_ext_by_critical(sk: *const Exts, crit: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        let sk: *const OPENSSL_STACK = sk.cast();
        if sk.is_null() {
            return -1;
        }
        let want = c_int::from(crit != 0);
        let start = lastpos.saturating_add(1).max(0);
        // SAFETY: the caller's guarantee.
        for i in start..unsafe { sk_count(sk) } {
            // SAFETY: as above.
            let e = unsafe { OPENSSL_sk_value(sk, i) };
            // SAFETY: an extension of the stack.
            if unsafe { X509_EXTENSION_get_critical(e.cast()) } == want {
                return i;
            }
        }
        -1
    }
}

ffi_export! {
    /// Extension `loc`, or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live stack of extensions.
    pub unsafe extern "C" fn X509v3_get_ext(x: *const Exts, loc: c_int) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        let x: *const OPENSSL_STACK = x.cast();
        // SAFETY: the caller's guarantee.
        if x.is_null() || loc < 0 || unsafe { sk_count(x) } <= loc {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        unsafe { OPENSSL_sk_value(x, loc) }.cast()
    }
}

ffi_export! {
    /// Removes extension `loc` and returns it (the caller's), or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live stack of extensions.
    pub unsafe extern "C" fn X509v3_delete_ext(x: *mut Exts, loc: c_int) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        let x: *mut OPENSSL_STACK = x.cast();
        // SAFETY: the caller's guarantee.
        if x.is_null() || loc < 0 || unsafe { sk_count(x) } <= loc {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        unsafe { OPENSSL_sk_delete(x, loc) }.cast()
    }
}

ffi_export! {
    /// Adds a copy of the extension at `loc` (the end for one out of range) to `*x`, made
    /// first when NULL: the stack, or NULL.
    ///
    /// # Safety
    /// `x` is NULL or holds NULL or a live stack of extensions; `ex` is a live extension.
    pub unsafe extern "C" fn X509v3_add_ext(x: *mut *mut Exts, ex: *mut X509_EXTENSION, loc: c_int) -> *mut Exts
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        let x: *mut *mut OPENSSL_STACK = x.cast();
        const F: &str = "X509v3_add_ext";
        if x.is_null() {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, F);
            return ptr::null_mut();
        }
        // SAFETY: the caller's slot.
        let given = unsafe { x.read() };
        let sk = if given.is_null() {
            // SAFETY: no preconditions.
            let s = unsafe { OPENSSL_sk_new_null() };
            if s.is_null() {
                err::raise(ERR_LIB_X509, ERR_R_CRYPTO_LIB, F);
                return ptr::null_mut();
            }
            s
        } else {
            given
        };
        let fail = || {
            if given.is_null() {
                // SAFETY: the stack made above.
                unsafe { OPENSSL_sk_free(sk) };
            }
            ptr::null_mut()
        };
        // SAFETY: the stack.
        let n = unsafe { sk_count(sk) };
        let loc = if loc > n || loc < 0 { n } else { loc };
        // SAFETY: the caller's extension.
        let copy = unsafe { X509_EXTENSION_dup(ex) };
        if copy.is_null() {
            err::raise(ERR_LIB_X509, ERR_R_ASN1_LIB, F);
            return fail();
        }
        // SAFETY: the stack; the copy.
        if unsafe { OPENSSL_sk_insert(sk, copy.cast(), loc) } == 0 {
            err::raise(ERR_LIB_X509, ERR_R_CRYPTO_LIB, F);
            // SAFETY: made above.
            unsafe { X509_EXTENSION_free(copy) };
            return fail();
        }
        if given.is_null() {
            // SAFETY: the caller's slot.
            unsafe { x.write(sk) };
        }
        sk.cast()
    }
}

ffi_export! {
    /// Adds copies of the extensions to `*target`, each replacing those of its object already
    /// there: the stack, or NULL.
    ///
    /// # Safety
    /// `target` is NULL or holds NULL or a live stack of extensions; `exts` is NULL or a live
    /// stack of extensions.
    pub unsafe extern "C" fn X509v3_add_extensions(target: *mut *mut Exts, exts: *const Exts) -> *mut Exts
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        let (target, exts): (*mut *mut OPENSSL_STACK, *const OPENSSL_STACK) = (target.cast(), exts.cast());
        if target.is_null() {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "X509v3_add_extensions");
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        for i in 0..unsafe { sk_count(exts) } {
            // SAFETY: as above.
            let e = unsafe { OPENSSL_sk_value(exts, i) }.cast::<X509_EXTENSION>();
            // SAFETY: an extension of the stack.
            let obj = unsafe { X509_EXTENSION_get_object(e) };
            loop {
                // SAFETY: the caller's slot and stack.
                let sk = unsafe { target.read() };
                // SAFETY: as above.
                let idx = unsafe { X509v3_get_ext_by_OBJ(sk.cast(), obj, -1) };
                if idx == -1 {
                    break;
                }
                // SAFETY: as above; the extension removed, freed.
                let gone = unsafe { OPENSSL_sk_delete(sk, idx) };
                // SAFETY: the extension removed, ours.
                unsafe { X509_EXTENSION_free(gone.cast()) };
            }
            // SAFETY: as above.
            if unsafe { X509v3_add_ext(target.cast(), e, -1) }.is_null() {
                return ptr::null_mut();
            }
        }
        // SAFETY: the caller's slot.
        unsafe { target.read() }.cast()
    }
}
