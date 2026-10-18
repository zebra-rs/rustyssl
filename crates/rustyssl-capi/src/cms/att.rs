//! A signer's attributes (`cms_att.c`): reading, adding, and deleting signed and unsigned
//! attributes, and the checks RFC 5652 puts on which may appear, where, and how often.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_OBJECT, CMS_R_ATTRIBUTE_ERROR, CMS_SignerInfo, ERR_LIB_CMS,
    NID_id_smime_aa_receiptRequest, NID_id_smime_aa_signingCertificate,
    NID_id_smime_aa_signingCertificateV2, NID_pkcs9_contentType, NID_pkcs9_countersignature,
    NID_pkcs9_messageDigest, NID_pkcs9_signingTime, X509_ATTRIBUTE,
};

use super::{SignerInfo, Stack};
use crate::ffi::ffi_export;
use crate::x509::attrib::{
    X509_ATTRIBUTE_count, X509at_delete_attr, X509at_get_attr, X509at_get_attr_by_NID,
    X509at_get_attr_by_OBJ, X509at_get_attr_count, X509at_get0_data_by_OBJ, add1, add1_by_nid,
    add1_by_obj, add1_by_txt,
};

/// The signer info behind a pointer.
///
/// # Safety
/// `si` is NULL or a live signer info.
pub(crate) unsafe fn si_of<'a>(si: *const CMS_SignerInfo) -> Option<&'a mut SignerInfo> {
    // SAFETY: the caller's guarantee.
    unsafe { si.cast::<SignerInfo>().cast_mut().as_mut() }
}

/// The slot of the signer's signed (or unsigned) attributes, NULL for a NULL signer.
fn slot(si: *const CMS_SignerInfo, signed: bool) -> *mut *mut Stack {
    // SAFETY: NULL or a live signer info.
    match unsafe { si_of(si) } {
        None => ptr::null_mut(),
        Some(s) if signed => &raw mut s.signed_attrs,
        Some(s) => &raw mut s.unsigned_attrs,
    }
}

/// The signer's signed (or unsigned) attributes, NULL for none.
fn attrs(si: *const CMS_SignerInfo, signed: bool) -> *mut Stack {
    let p = slot(si, signed);
    // SAFETY: NULL or the signer's slot.
    unsafe { p.as_ref() }.map_or(ptr::null_mut(), |s| *s)
}

ffi_export! {
    /// The number of the attributes, or -1 for none.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info.
    pub unsafe extern "C" fn CMS_signed_get_attr_count(si: *const CMS_SignerInfo) -> c_int
    where failure = -1, library = ERR_LIB_CMS
    {
        // SAFETY: the signer's attributes, or NULL.
        unsafe { X509at_get_attr_count(attrs(si, true).cast()) }
    }
}

ffi_export! {
    /// The index of the next attribute of `nid` after `lastpos`, or -1 (or -2).
    ///
    /// # Safety
    /// `si` is NULL or a live signer info.
    pub unsafe extern "C" fn CMS_signed_get_attr_by_NID(si: *const CMS_SignerInfo, nid: c_int, lastpos: c_int) -> c_int
    where failure = -2, library = ERR_LIB_CMS
    {
        // SAFETY: as above.
        unsafe { X509at_get_attr_by_NID(attrs(si, true).cast(), nid, lastpos) }
    }
}

ffi_export! {
    /// The index of the next attribute of `obj` after `lastpos`, or -1 (or -2).
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; `obj` NULL or live.
    pub unsafe extern "C" fn CMS_signed_get_attr_by_OBJ(si: *const CMS_SignerInfo, obj: *const ASN1_OBJECT, lastpos: c_int) -> c_int
    where failure = -2, library = ERR_LIB_CMS
    {
        // SAFETY: as above.
        unsafe { X509at_get_attr_by_OBJ(attrs(si, true).cast(), obj, lastpos) }
    }
}

ffi_export! {
    /// The attribute at `loc`, or NULL.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info.
    pub unsafe extern "C" fn CMS_signed_get_attr(si: *const CMS_SignerInfo, loc: c_int) -> *mut X509_ATTRIBUTE
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: as above.
        unsafe { X509at_get_attr(attrs(si, true).cast(), loc) }
    }
}

ffi_export! {
    /// Removes the attribute at `loc` and returns it, or NULL.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info.
    pub unsafe extern "C" fn CMS_signed_delete_attr(si: *mut CMS_SignerInfo, loc: c_int) -> *mut X509_ATTRIBUTE
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: as above.
        unsafe { X509at_delete_attr(attrs(si, true).cast(), loc) }
    }
}

ffi_export! {
    /// Adds a copy of the attribute (duplicates allowed): 1, or 0.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; `attr` NULL or live.
    pub unsafe extern "C" fn CMS_signed_add1_attr(si: *mut CMS_SignerInfo, attr: *mut X509_ATTRIBUTE) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the signer's slot, or NULL; the caller's attribute.
        c_int::from(!unsafe { add1(slot(si, true).cast(), attr) }.is_null())
    }
}

ffi_export! {
    /// Adds an attribute of `obj` with one value: 1, or 0.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; the rest as `X509_ATTRIBUTE_set1_data` takes them.
    pub unsafe extern "C" fn CMS_signed_add1_attr_by_OBJ(si: *mut CMS_SignerInfo, obj: *const ASN1_OBJECT, type_: c_int, bytes: *const c_void, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: as above.
        c_int::from(!unsafe { add1_by_obj(slot(si, true).cast(), obj, type_, bytes.cast(), len) }.is_null())
    }
}

ffi_export! {
    /// Adds an attribute of `nid` with one value: 1, or 0.
    ///
    /// # Safety
    /// As for the `_by_OBJ` form.
    pub unsafe extern "C" fn CMS_signed_add1_attr_by_NID(si: *mut CMS_SignerInfo, nid: c_int, type_: c_int, bytes: *const c_void, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: as above.
        c_int::from(!unsafe { add1_by_nid(slot(si, true).cast(), nid, type_, bytes.cast(), len) }.is_null())
    }
}

ffi_export! {
    /// Adds an attribute named `attrname` with one value: 1, or 0.
    ///
    /// # Safety
    /// As for the `_by_OBJ` form; `attrname` a C string.
    pub unsafe extern "C" fn CMS_signed_add1_attr_by_txt(si: *mut CMS_SignerInfo, attrname: *const c_char, type_: c_int, bytes: *const c_void, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: as above.
        c_int::from(!unsafe { add1_by_txt(slot(si, true).cast(), attrname, type_, bytes.cast(), len) }.is_null())
    }
}

ffi_export! {
    /// The data of the attribute of `oid` after `lastpos`, if of `type_`, or NULL.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; `oid` NULL or live.
    pub unsafe extern "C" fn CMS_signed_get0_data_by_OBJ(si: *const CMS_SignerInfo, oid: *const ASN1_OBJECT, lastpos: c_int, type_: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: as above.
        unsafe { X509at_get0_data_by_OBJ(attrs(si, true).cast(), oid, lastpos, type_) }
    }
}

ffi_export! {
    /// The number of the attributes, or -1 for none.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info.
    pub unsafe extern "C" fn CMS_unsigned_get_attr_count(si: *const CMS_SignerInfo) -> c_int
    where failure = -1, library = ERR_LIB_CMS
    {
        // SAFETY: the signer's attributes, or NULL.
        unsafe { X509at_get_attr_count(attrs(si, false).cast()) }
    }
}

ffi_export! {
    /// The index of the next attribute of `nid` after `lastpos`, or -1 (or -2).
    ///
    /// # Safety
    /// `si` is NULL or a live signer info.
    pub unsafe extern "C" fn CMS_unsigned_get_attr_by_NID(si: *const CMS_SignerInfo, nid: c_int, lastpos: c_int) -> c_int
    where failure = -2, library = ERR_LIB_CMS
    {
        // SAFETY: as above.
        unsafe { X509at_get_attr_by_NID(attrs(si, false).cast(), nid, lastpos) }
    }
}

ffi_export! {
    /// The index of the next attribute of `obj` after `lastpos`, or -1 (or -2).
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; `obj` NULL or live.
    pub unsafe extern "C" fn CMS_unsigned_get_attr_by_OBJ(si: *const CMS_SignerInfo, obj: *const ASN1_OBJECT, lastpos: c_int) -> c_int
    where failure = -2, library = ERR_LIB_CMS
    {
        // SAFETY: as above.
        unsafe { X509at_get_attr_by_OBJ(attrs(si, false).cast(), obj, lastpos) }
    }
}

ffi_export! {
    /// The attribute at `loc`, or NULL.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info.
    pub unsafe extern "C" fn CMS_unsigned_get_attr(si: *const CMS_SignerInfo, loc: c_int) -> *mut X509_ATTRIBUTE
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: as above.
        unsafe { X509at_get_attr(attrs(si, false).cast(), loc) }
    }
}

ffi_export! {
    /// Removes the attribute at `loc` and returns it, or NULL.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info.
    pub unsafe extern "C" fn CMS_unsigned_delete_attr(si: *mut CMS_SignerInfo, loc: c_int) -> *mut X509_ATTRIBUTE
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: as above.
        unsafe { X509at_delete_attr(attrs(si, false).cast(), loc) }
    }
}

ffi_export! {
    /// Adds a copy of the attribute (duplicates allowed): 1, or 0.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; `attr` NULL or live.
    pub unsafe extern "C" fn CMS_unsigned_add1_attr(si: *mut CMS_SignerInfo, attr: *mut X509_ATTRIBUTE) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the signer's slot, or NULL; the caller's attribute.
        c_int::from(!unsafe { add1(slot(si, false).cast(), attr) }.is_null())
    }
}

ffi_export! {
    /// Adds an attribute of `obj` with one value: 1, or 0.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; the rest as `X509_ATTRIBUTE_set1_data` takes them.
    pub unsafe extern "C" fn CMS_unsigned_add1_attr_by_OBJ(si: *mut CMS_SignerInfo, obj: *const ASN1_OBJECT, type_: c_int, bytes: *const c_void, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: as above.
        c_int::from(!unsafe { add1_by_obj(slot(si, false).cast(), obj, type_, bytes.cast(), len) }.is_null())
    }
}

ffi_export! {
    /// Adds an attribute of `nid` with one value: 1, or 0.
    ///
    /// # Safety
    /// As for the `_by_OBJ` form.
    pub unsafe extern "C" fn CMS_unsigned_add1_attr_by_NID(si: *mut CMS_SignerInfo, nid: c_int, type_: c_int, bytes: *const c_void, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: as above.
        c_int::from(!unsafe { add1_by_nid(slot(si, false).cast(), nid, type_, bytes.cast(), len) }.is_null())
    }
}

ffi_export! {
    /// Adds an attribute named `attrname` with one value: 1, or 0.
    ///
    /// # Safety
    /// As for the `_by_OBJ` form; `attrname` a C string.
    pub unsafe extern "C" fn CMS_unsigned_add1_attr_by_txt(si: *mut CMS_SignerInfo, attrname: *const c_char, type_: c_int, bytes: *const c_void, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: as above.
        c_int::from(!unsafe { add1_by_txt(slot(si, false).cast(), attrname, type_, bytes.cast(), len) }.is_null())
    }
}

ffi_export! {
    /// The data of the attribute of `oid` after `lastpos`, if of `type_`, or NULL.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; `oid` NULL or live.
    pub unsafe extern "C" fn CMS_unsigned_get0_data_by_OBJ(si: *mut CMS_SignerInfo, oid: *mut ASN1_OBJECT, lastpos: c_int, type_: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: as above.
        unsafe { X509at_get0_data_by_OBJ(attrs(si, false).cast(), oid, lastpos, type_) }
    }
}

#[expect(dead_code, reason = "used by SignedData, step 6.4b")]
const F_SIGNED: c_int = 0x01;
#[expect(dead_code, reason = "used by SignedData, step 6.4b")]
const F_UNSIGNED: c_int = 0x02;
#[expect(dead_code, reason = "used by SignedData, step 6.4b")]
const F_REQUIRED_COND: c_int = 0x10;
#[expect(dead_code, reason = "used by SignedData, step 6.4b")]
const F_ONLY_ONE: c_int = 0x20;
#[expect(dead_code, reason = "used by SignedData, step 6.4b")]
const F_ONE_ATTR_VALUE: c_int = 0x40;

#[expect(dead_code, reason = "used by SignedData, step 6.4b")]
/// `cms_attribute_properties`.
const PROPERTIES: [(c_int, c_int); 7] = [
    (
        NID_pkcs9_contentType,
        F_SIGNED | F_ONLY_ONE | F_ONE_ATTR_VALUE | F_REQUIRED_COND,
    ),
    (
        NID_pkcs9_messageDigest,
        F_SIGNED | F_ONLY_ONE | F_ONE_ATTR_VALUE | F_REQUIRED_COND,
    ),
    (
        NID_pkcs9_signingTime,
        F_SIGNED | F_ONLY_ONE | F_ONE_ATTR_VALUE,
    ),
    (NID_pkcs9_countersignature, F_UNSIGNED),
    (
        NID_id_smime_aa_signingCertificate,
        F_SIGNED | F_ONLY_ONE | F_ONE_ATTR_VALUE,
    ),
    (
        NID_id_smime_aa_signingCertificateV2,
        F_SIGNED | F_ONLY_ONE | F_ONE_ATTR_VALUE,
    ),
    (
        NID_id_smime_aa_receiptRequest,
        F_SIGNED | F_ONLY_ONE | F_ONE_ATTR_VALUE,
    ),
];

#[expect(dead_code, reason = "used by SignedData, step 6.4b")]
/// `cms_check_attribute`.
fn check_attribute(
    nid: c_int,
    flags: c_int,
    kind: c_int,
    sk: *mut Stack,
    have_attrs: bool,
) -> bool {
    // SAFETY: the attributes, or NULL.
    let loc = unsafe { X509at_get_attr_by_NID(sk.cast(), nid, -1) };
    if loc < 0 {
        return !(have_attrs && flags & F_REQUIRED_COND != 0 && flags & kind != 0);
    }
    // SAFETY: an index within them.
    let at = unsafe { X509at_get_attr(sk.cast(), loc) };
    // SAFETY: the attribute.
    let count = unsafe { X509_ATTRIBUTE_count(at) };
    // SAFETY: as above.
    let another = unsafe { X509at_get_attr_by_NID(sk.cast(), nid, loc) } >= 0;
    !(flags & kind == 0
        || (flags & F_ONLY_ONE != 0 && another)
        || (flags & F_ONE_ATTR_VALUE != 0 && count != 1)
        || count == 0)
}

#[expect(dead_code, reason = "used by SignedData, step 6.4b")]
/// `ossl_cms_si_check_attributes`: whether the signer's attributes follow RFC 5652.
pub(crate) fn si_check_attributes(si: *const CMS_SignerInfo) -> bool {
    let signed = attrs(si, true);
    let unsigned = attrs(si, false);
    // SAFETY: the attributes, or NULL.
    let have_signed = unsafe { X509at_get_attr_count(signed.cast()) } > 0;
    // SAFETY: as above.
    let have_unsigned = unsafe { X509at_get_attr_count(unsigned.cast()) } > 0;
    for &(nid, flags) in &PROPERTIES {
        if !check_attribute(nid, flags, F_SIGNED, signed, have_signed)
            || !check_attribute(nid, flags, F_UNSIGNED, unsigned, have_unsigned)
        {
            crate::err::raise(
                ERR_LIB_CMS,
                CMS_R_ATTRIBUTE_ERROR,
                "ossl_cms_si_check_attributes",
            );
            return false;
        }
    }
    true
}
