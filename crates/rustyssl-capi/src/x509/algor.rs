//! AlgorithmIdentifier's functions (`x_algor.c`): `X509_ALGOR_set0`, `get0`, `set_md`, `cmp`,
//! `copy`, and `dup`, and `X509_ALGORS`, a SEQUENCE OF them. The item itself is with the
//! universal types' (`asn1::tpl::items`).
//!
//! OpenSSL reads through a NULL AlgorithmIdentifier, digest, or parameter in `get0`, `set_md`,
//! and `cmp`; these do nothing or answer instead (docs/DEVIATIONS.md).

use core::ffi::{c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_ITEM, ASN1_ITYPE_PRIMITIVE, ASN1_OBJECT, ASN1_TFLG_SEQUENCE_OF, ERR_LIB_ASN1, EVP_MD,
    EVP_MD_FLAG_DIGALGID_ABSENT, V_ASN1_EOC, V_ASN1_NULL, V_ASN1_UNDEF, X509_ALGOR, X509_ALGORS,
};

use crate::asn1::any::{ASN1_TYPE_cmp, ASN1_TYPE_set, ASN1_TYPE_set1};
use crate::asn1::tpl::items::{ASN1_TYPE_free, ASN1_TYPE_new, X509_ALGOR_it, d2i, i2d};
use crate::asn1::tpl::util::ASN1_item_dup;
use crate::asn1::tpl::{Template, item, item_fns, template};
use crate::evp::digest::{EVP_MD_get_flags, EVP_MD_get_type};
use crate::ffi::ffi_export;
use crate::objects::{ASN1_OBJECT_free, OBJ_cmp, OBJ_dup, OBJ_nid2obj};

/// The template of `X509_ALGORS`.
static ALGORS: Template = template(ASN1_TFLG_SEQUENCE_OF, 0, c"algorithms", X509_ALGOR_it);

item_fns! {
    /// A SEQUENCE OF AlgorithmIdentifier, a stack of `X509_ALGOR`s.
    pub unsafe extern "C" fn X509_ALGORS_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const ALGORS.0, 0, ptr::null(), 0, c"X509_ALGORS");
}

i2d! {
    /// Encodes a SEQUENCE OF AlgorithmIdentifier.
    pub unsafe extern "C" fn i2d_X509_ALGORS(X509_ALGORS) = X509_ALGORS_it;
}

d2i! {
    /// Decodes a SEQUENCE OF AlgorithmIdentifier (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_X509_ALGORS(X509_ALGORS) = X509_ALGORS_it;
}

/// `X509_ALGOR_set0` on a live AlgorithmIdentifier.
///
/// # Safety
/// `alg` is NULL or a live AlgorithmIdentifier; `aobj` is NULL or an object it takes; `pval`
/// is what `ASN1_TYPE_set` takes for `ptype`.
pub(crate) unsafe fn set0(
    alg: *mut X509_ALGOR,
    aobj: *mut ASN1_OBJECT,
    ptype: c_int,
    pval: *mut c_void,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(a) = (unsafe { alg.as_mut() }) else {
        return 0;
    };
    if ptype != V_ASN1_UNDEF && a.parameter.is_null() {
        // SAFETY: no preconditions.
        a.parameter = unsafe { ASN1_TYPE_new() };
        if a.parameter.is_null() {
            return 0;
        }
    }
    // SAFETY: the AlgorithmIdentifier's object, or NULL.
    unsafe { ASN1_OBJECT_free(a.algorithm) };
    a.algorithm = aobj;
    if ptype == V_ASN1_EOC {
        return 1;
    }
    if ptype == V_ASN1_UNDEF {
        // SAFETY: its parameter, or NULL.
        unsafe { ASN1_TYPE_free(a.parameter) };
        a.parameter = ptr::null_mut();
    } else {
        // SAFETY: its parameter; the caller's value.
        unsafe { ASN1_TYPE_set(a.parameter, ptype, pval) };
    }
    1
}

ffi_export! {
    /// Sets the AlgorithmIdentifier's object (taken) and parameter: none for `V_ASN1_UNDEF`,
    /// the old one kept for `V_ASN1_EOC`, else `ptype` with `pval` (taken). 1, or 0.
    ///
    /// # Safety
    /// `alg` is NULL or a live AlgorithmIdentifier; `aobj` is NULL or an object it takes;
    /// `pval` is what `ASN1_TYPE_set` takes for `ptype`.
    pub unsafe extern "C" fn X509_ALGOR_set0(alg: *mut X509_ALGOR, aobj: *mut ASN1_OBJECT, ptype: c_int, pval: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { set0(alg, aobj, ptype, pval) }
    }
}

ffi_export! {
    /// The AlgorithmIdentifier's object, and its parameter's type (`V_ASN1_UNDEF` for none)
    /// and value, each where asked for (the value only with the type).
    ///
    /// # Safety
    /// `algor` is NULL or a live AlgorithmIdentifier; the out pointers are NULL or writable.
    pub unsafe extern "C" fn X509_ALGOR_get0(paobj: *mut *const ASN1_OBJECT, pptype: *mut c_int, ppval: *mut *const c_void, algor: *const X509_ALGOR)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { algor.as_ref() }) else { return };
        if !paobj.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { paobj.write(a.algorithm) };
        }
        if pptype.is_null() {
            return;
        }
        // SAFETY: the parameter, or NULL.
        let Some(p) = (unsafe { a.parameter.as_ref() }) else {
            // SAFETY: the caller's guarantee.
            unsafe { pptype.write(V_ASN1_UNDEF) };
            return;
        };
        // SAFETY: as above.
        unsafe { pptype.write(p.type_) };
        if !ppval.is_null() {
            // SAFETY: the union's pointer member, read as a pointer whatever the type.
            let v = unsafe { p.value.ptr };
            // SAFETY: the caller's guarantee.
            unsafe { ppval.write(v.cast_const().cast()) };
        }
    }
}

ffi_export! {
    /// Sets the AlgorithmIdentifier to the digest's: its object, with a NULL parameter unless
    /// the digest leaves it out (`EVP_MD_FLAG_DIGALGID_ABSENT`).
    ///
    /// # Safety
    /// `alg` is NULL or a live AlgorithmIdentifier; `md` is NULL or a live digest.
    pub unsafe extern "C" fn X509_ALGOR_set_md(alg: *mut X509_ALGOR, md: *const EVP_MD)
    where failure = (), library = ERR_LIB_ASN1
    {
        if md.is_null() {
            return;
        }
        // SAFETY: the caller's digest.
        let absent = unsafe { EVP_MD_get_flags(md) } & EVP_MD_FLAG_DIGALGID_ABSENT as core::ffi::c_ulong != 0;
        let ptype = if absent { V_ASN1_UNDEF } else { V_ASN1_NULL };
        // SAFETY: as above.
        let nid = unsafe { EVP_MD_get_type(md) };
        // SAFETY: no preconditions.
        let obj = unsafe { OBJ_nid2obj(nid) };
        // SAFETY: the caller's AlgorithmIdentifier; a static object.
        let _ = unsafe { set0(alg, obj, ptype, ptr::null_mut()) };
    }
}

ffi_export! {
    /// Compares two AlgorithmIdentifiers: their objects, then their parameters (equal if both
    /// have none). 0 if they're equal.
    ///
    /// # Safety
    /// `a` and `b` are NULL or live AlgorithmIdentifiers.
    pub unsafe extern "C" fn X509_ALGOR_cmp(a: *const X509_ALGOR, b: *const X509_ALGOR) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(y)) = (unsafe { a.as_ref() }, unsafe { b.as_ref() }) else {
            return if a == b { 0 } else { -1 };
        };
        // SAFETY: their objects.
        let rv = unsafe { OBJ_cmp(x.algorithm, y.algorithm) };
        if rv != 0 {
            return rv;
        }
        if x.parameter.is_null() && y.parameter.is_null() {
            return 0;
        }
        // SAFETY: their parameters, or NULL.
        unsafe { ASN1_TYPE_cmp(x.parameter, y.parameter) }
    }
}

ffi_export! {
    /// Copies an AlgorithmIdentifier into another, whose old object and parameter it frees.
    /// 1, or 0.
    ///
    /// # Safety
    /// `dest` and `src` are NULL or live AlgorithmIdentifiers.
    pub unsafe extern "C" fn X509_ALGOR_copy(dest: *mut X509_ALGOR, src: *const X509_ALGOR) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let (Some(d), Some(s)) = (unsafe { dest.as_mut() }, unsafe { src.as_ref() }) else {
            return 0;
        };
        // SAFETY: the destination's object, or NULL.
        unsafe { ASN1_OBJECT_free(d.algorithm) };
        d.algorithm = ptr::null_mut();
        // SAFETY: its parameter, or NULL.
        unsafe { ASN1_TYPE_free(d.parameter) };
        d.parameter = ptr::null_mut();
        if !s.algorithm.is_null() {
            // SAFETY: the source's object.
            d.algorithm = unsafe { OBJ_dup(s.algorithm) };
            if d.algorithm.is_null() {
                return 0;
            }
        }
        // SAFETY: the source's parameter, or NULL.
        if let Some(p) = unsafe { s.parameter.as_ref() } {
            // SAFETY: no preconditions.
            d.parameter = unsafe { ASN1_TYPE_new() };
            if d.parameter.is_null() {
                return 0;
            }
            // SAFETY: the new parameter; the source's value of its type.
            let ptr_val = unsafe { p.value.ptr };
            // SAFETY: as above.
            if unsafe { ASN1_TYPE_set1(d.parameter, p.type_, ptr_val.cast_const().cast()) } == 0 {
                return 0;
            }
        }
        1
    }
}

ffi_export! {
    /// A copy of an AlgorithmIdentifier (`ASN1_item_dup`), or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live AlgorithmIdentifier.
    pub unsafe extern "C" fn X509_ALGOR_dup(a: *const X509_ALGOR) -> *mut X509_ALGOR
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_ALGOR_it() };
        // SAFETY: the type's item; the caller's value.
        unsafe { ASN1_item_dup(it, a.cast()) }.cast()
    }
}
