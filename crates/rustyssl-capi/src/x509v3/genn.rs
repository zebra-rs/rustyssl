//! General names (`GENERAL_NAME_new(3)`, `GENERAL_NAME_cmp`, `GENERAL_NAME_set0_value`;
//! `v3_genn.c`): the CHOICE of an otherName, an e-mail address, a DNS name, an X.400 address,
//! a directory name, an EDI party name, a URI, an IP address, or a registered ID, over
//! OpenSSL's public `GENERAL_NAME` layout, with `OTHERNAME`, `EDIPARTYNAME`, and the SEQUENCE
//! OF them, `GENERAL_NAMES`.
//!
//! As in OpenSSL since CVE-2023-0286, an X.400 address is an `ASN1_STRING` (its SEQUENCE's
//! octets), and comparing two compares those; since CVE-2020-1971, comparing EDI party names
//! with a part missing doesn't read through it.

use core::ffi::{c_int, c_void};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ASN1_ITEM, ASN1_ITYPE_PRIMITIVE, ASN1_OBJECT, ASN1_TFLG_EXPLICIT, ASN1_TFLG_IMPLICIT,
    ASN1_TFLG_OPTIONAL, ASN1_TFLG_SEQUENCE_OF, ASN1_TYPE, EDIPARTYNAME, ERR_LIB_ASN1,
    ERR_LIB_X509V3, GEN_DIRNAME, GEN_DNS, GEN_EDIPARTY, GEN_EMAIL, GEN_IPADD, GEN_OTHERNAME,
    GEN_RID, GEN_URI, GEN_X400, GENERAL_NAME, GENERAL_NAMES, OTHERNAME, X509_NAME,
    X509V3_R_INVALID_NULL_ARGUMENT,
};

use crate::asn1::any::ASN1_TYPE_cmp;
use crate::asn1::string::{ASN1_OCTET_STRING_cmp, ASN1_STRING_cmp};
use crate::asn1::tpl::items::{
    ASN1_ANY_it, ASN1_IA5STRING_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_it, ASN1_SEQUENCE_it,
    ASN1_TYPE_free, DIRECTORYSTRING_it, d2i, i2d, new_free,
};
use crate::asn1::tpl::statics::{Templates, choice, sequence};
use crate::asn1::tpl::util::ASN1_item_dup;
use crate::asn1::tpl::{Template, item, item_fns, template, template_at};
use crate::err;
use crate::ffi::ffi_export;
use crate::objects::OBJ_cmp;
use crate::x509::name::{X509_NAME_cmp, X509_NAME_it, X509_NAME_new, X509_NAME_set};

static OTHERNAME_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(OTHERNAME, type_id),
        c"type_id",
        ASN1_OBJECT_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT,
        0,
        offset_of!(OTHERNAME, value),
        c"value",
        ASN1_ANY_it,
    ),
]);

item_fns! {
    /// OtherName: SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY }.
    pub unsafe extern "C" fn OTHERNAME_it = sequence::<OTHERNAME, 2>(&OTHERNAME_TT, None, c"OTHERNAME");
}

new_free! {
    pub unsafe extern "C" fn OTHERNAME_new, pub unsafe extern "C" fn OTHERNAME_free(OTHERNAME) = OTHERNAME_it;
}

i2d! {
    /// Encodes an OtherName.
    pub unsafe extern "C" fn i2d_OTHERNAME(OTHERNAME) = OTHERNAME_it;
}

d2i! {
    /// Decodes an OtherName (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_OTHERNAME(OTHERNAME) = OTHERNAME_it;
}

static EDIPARTY_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(EDIPARTYNAME, nameAssigner),
        c"nameAssigner",
        DIRECTORYSTRING_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT,
        1,
        offset_of!(EDIPARTYNAME, partyName),
        c"partyName",
        DIRECTORYSTRING_it,
    ),
]);

item_fns! {
    /// EDIPartyName: SEQUENCE { nameAssigner [0] DirectoryString OPTIONAL, partyName [1]
    /// DirectoryString }.
    pub unsafe extern "C" fn EDIPARTYNAME_it = sequence::<EDIPARTYNAME, 2>(&EDIPARTY_TT, None, c"EDIPARTYNAME");
}

new_free! {
    pub unsafe extern "C" fn EDIPARTYNAME_new, pub unsafe extern "C" fn EDIPARTYNAME_free(EDIPARTYNAME) = EDIPARTYNAME_it;
}

i2d! {
    /// Encodes an EDIPartyName.
    pub unsafe extern "C" fn i2d_EDIPARTYNAME(EDIPARTYNAME) = EDIPARTYNAME_it;
}

d2i! {
    /// Decodes an EDIPartyName (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_EDIPARTYNAME(EDIPARTYNAME) = EDIPARTYNAME_it;
}

/// The union's offset in a `GENERAL_NAME`: every alternative's.
const D: usize = offset_of!(GENERAL_NAME, d);

/// Each alternative's tag is its `GEN_*` type.
const fn tag(t: c_int) -> core::ffi::c_long {
    t as core::ffi::c_long
}

static GENERAL_NAME_TT: Templates<9> = Templates([
    template_at(
        ASN1_TFLG_IMPLICIT,
        tag(GEN_OTHERNAME),
        D,
        c"d.otherName",
        OTHERNAME_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT,
        tag(GEN_EMAIL),
        D,
        c"d.rfc822Name",
        ASN1_IA5STRING_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT,
        tag(GEN_DNS),
        D,
        c"d.dNSName",
        ASN1_IA5STRING_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT,
        tag(GEN_X400),
        D,
        c"d.x400Address",
        ASN1_SEQUENCE_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT,
        tag(GEN_DIRNAME),
        D,
        c"d.directoryName",
        X509_NAME_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT,
        tag(GEN_EDIPARTY),
        D,
        c"d.ediPartyName",
        EDIPARTYNAME_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT,
        tag(GEN_URI),
        D,
        c"d.uniformResourceIdentifier",
        ASN1_IA5STRING_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT,
        tag(GEN_IPADD),
        D,
        c"d.iPAddress",
        ASN1_OCTET_STRING_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT,
        tag(GEN_RID),
        D,
        c"d.registeredID",
        ASN1_OBJECT_it,
    ),
]);

item_fns! {
    /// GeneralName, a CHOICE whose selector is its `type`.
    pub unsafe extern "C" fn GENERAL_NAME_it = choice::<GENERAL_NAME, 9>(&GENERAL_NAME_TT, offset_of!(GENERAL_NAME, type_), None, c"GENERAL_NAME");
}

new_free! {
    pub unsafe extern "C" fn GENERAL_NAME_new, pub unsafe extern "C" fn GENERAL_NAME_free(GENERAL_NAME) = GENERAL_NAME_it;
}

i2d! {
    /// Encodes a GeneralName.
    pub unsafe extern "C" fn i2d_GENERAL_NAME(GENERAL_NAME) = GENERAL_NAME_it;
}

d2i! {
    /// Decodes a GeneralName (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_GENERAL_NAME(GENERAL_NAME) = GENERAL_NAME_it;
}

static GENERAL_NAMES_T: Template =
    template(ASN1_TFLG_SEQUENCE_OF, 0, c"GeneralNames", GENERAL_NAME_it);

item_fns! {
    /// GeneralNames: SEQUENCE OF GeneralName.
    pub unsafe extern "C" fn GENERAL_NAMES_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const GENERAL_NAMES_T.0, 0, ptr::null(), 0, c"GENERAL_NAMES");
}

new_free! {
    pub unsafe extern "C" fn GENERAL_NAMES_new, pub unsafe extern "C" fn GENERAL_NAMES_free(GENERAL_NAMES) = GENERAL_NAMES_it;
}

i2d! {
    /// Encodes GeneralNames.
    pub unsafe extern "C" fn i2d_GENERAL_NAMES(GENERAL_NAMES) = GENERAL_NAMES_it;
}

d2i! {
    /// Decodes GeneralNames (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_GENERAL_NAMES(GENERAL_NAMES) = GENERAL_NAMES_it;
}

ffi_export! {
    /// A copy of the name (through its encoding), or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live name.
    pub unsafe extern "C" fn GENERAL_NAME_dup(a: *const GENERAL_NAME) -> *mut GENERAL_NAME
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { GENERAL_NAME_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_dup(it, a.cast_mut().cast()) }.cast()
    }
}

ffi_export! {
    /// Replaces `*tgt` with a new directory name, a copy of `src` (an empty name for NULL):
    /// 1, or 0 (`X509V3_R_INVALID_NULL_ARGUMENT` for a NULL `tgt`).
    ///
    /// # Safety
    /// `tgt` is NULL or holds NULL or a live name it owns; `src` is NULL or a live name.
    pub unsafe extern "C" fn GENERAL_NAME_set1_X509_NAME(tgt: *mut *mut GENERAL_NAME, src: *const X509_NAME) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        if tgt.is_null() {
            err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_NULL_ARGUMENT, "GENERAL_NAME_set1_X509_NAME");
            return 0;
        }
        // SAFETY: no preconditions.
        let name = unsafe { GENERAL_NAME_new() };
        // SAFETY: new, or NULL.
        let Some(n) = (unsafe { name.as_mut() }) else { return 0 };
        n.type_ = GEN_DIRNAME;
        let ok = if src.is_null() {
            // SAFETY: no preconditions.
            n.d.directoryName = unsafe { X509_NAME_new() };
            // SAFETY: a union field just set.
            !unsafe { n.d.directoryName }.is_null()
        } else {
            // SAFETY: the new name's slot; the caller's name.
            (unsafe { X509_NAME_set(&raw mut n.d.directoryName, src) } != 0)
        };
        if !ok {
            // SAFETY: made above.
            unsafe { GENERAL_NAME_free(name) };
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let old = unsafe { tgt.read() };
        // SAFETY: the name it held, which it owned.
        unsafe { GENERAL_NAME_free(old) };
        // SAFETY: as above.
        unsafe { tgt.write(name) };
        1
    }
}

/// `edipartyname_cmp`: 0 for the same, nonzero otherwise; a missing part is -1.
///
/// # Safety
/// `a` and `b` are NULL or live EDI party names.
unsafe fn edipartyname_cmp(a: *const EDIPARTYNAME, b: *const EDIPARTYNAME) -> c_int {
    // SAFETY: the caller's guarantee.
    let (Some(a), Some(b)) = (unsafe { a.as_ref() }, unsafe { b.as_ref() }) else {
        return -1;
    };
    match (a.nameAssigner.is_null(), b.nameAssigner.is_null()) {
        (true, false) => return -1,
        (false, true) => return 1,
        (false, false) => {
            // SAFETY: both assigners.
            let r = unsafe { ASN1_STRING_cmp(a.nameAssigner, b.nameAssigner) };
            if r != 0 {
                return r;
            }
        }
        (true, true) => {}
    }
    if a.partyName.is_null() || b.partyName.is_null() {
        return -1;
    }
    // SAFETY: both party names.
    unsafe { ASN1_STRING_cmp(a.partyName, b.partyName) }
}

ffi_export! {
    /// Compares two names of the same type: 0 for the same, nonzero otherwise (-1 for NULL or
    /// different types).
    ///
    /// # Safety
    /// `a` and `b` are NULL or live names.
    pub unsafe extern "C" fn GENERAL_NAME_cmp(a: *mut GENERAL_NAME, b: *mut GENERAL_NAME) -> c_int
    where failure = -1, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let (Some(a), Some(b)) = (unsafe { a.as_ref() }, unsafe { b.as_ref() }) else { return -1 };
        if a.type_ != b.type_ {
            return -1;
        }
        // SAFETY: every alternative is a pointer at the same place.
        let pa = unsafe { a.d.ptr };
        // SAFETY: as above.
        let pb = unsafe { b.d.ptr };
        match a.type_ {
            // SAFETY: X.400 addresses, as strings.
            GEN_X400 | GEN_EMAIL | GEN_DNS | GEN_URI => unsafe { ASN1_STRING_cmp(pa.cast(), pb.cast()) },
            // SAFETY: EDI party names.
            GEN_EDIPARTY => unsafe { edipartyname_cmp(pa.cast(), pb.cast()) },
            // SAFETY: other names.
            GEN_OTHERNAME => unsafe { OTHERNAME_cmp(pa.cast(), pb.cast()) },
            // SAFETY: directory names.
            GEN_DIRNAME => unsafe { X509_NAME_cmp(pa.cast(), pb.cast()) },
            // SAFETY: IP addresses.
            GEN_IPADD => unsafe { ASN1_OCTET_STRING_cmp(pa.cast(), pb.cast()) },
            // SAFETY: registered IDs.
            GEN_RID => unsafe { OBJ_cmp(pa.cast(), pb.cast()) },
            _ => -1,
        }
    }
}

ffi_export! {
    /// Compares two other names: their types, then their values (`ASN1_TYPE_cmp`); -1 for NULL.
    ///
    /// # Safety
    /// `a` and `b` are NULL or live other names.
    pub unsafe extern "C" fn OTHERNAME_cmp(a: *mut OTHERNAME, b: *mut OTHERNAME) -> c_int
    where failure = -1, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let (Some(a), Some(b)) = (unsafe { a.as_ref() }, unsafe { b.as_ref() }) else { return -1 };
        // SAFETY: their objects.
        let r = unsafe { OBJ_cmp(a.type_id, b.type_id) };
        if r != 0 {
            return r;
        }
        // SAFETY: their values.
        unsafe { ASN1_TYPE_cmp(a.value, b.value) }
    }
}

ffi_export! {
    /// Sets the name to `value` (which it takes) of `type_`, not freeing what it had.
    ///
    /// # Safety
    /// `a` is a live name; `value` is NULL or a value of the type's kind.
    pub unsafe extern "C" fn GENERAL_NAME_set0_value(a: *mut GENERAL_NAME, type_: c_int, value: *mut c_void)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { a.as_mut() }) else { return };
        // Every alternative is a pointer at the same place.
        g.d.ptr = value.cast();
        g.type_ = type_;
    }
}

ffi_export! {
    /// The name's value and (into `*ptype`) its type, or NULL for an unknown type.
    ///
    /// # Safety
    /// `a` is a live name; `ptype` is NULL or writable.
    pub unsafe extern "C" fn GENERAL_NAME_get0_value(a: *const GENERAL_NAME, ptype: *mut c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { a.as_ref() }) else { return ptr::null_mut() };
        if !ptype.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { ptype.write(g.type_) };
        }
        match g.type_ {
            // SAFETY: every alternative is a pointer at the same place.
            GEN_X400 | GEN_EDIPARTY | GEN_OTHERNAME | GEN_EMAIL | GEN_DNS | GEN_URI | GEN_DIRNAME | GEN_IPADD | GEN_RID => unsafe { g.d.ptr }.cast(),
            _ => ptr::null_mut(),
        }
    }
}

ffi_export! {
    /// Makes the name an other name of `oid` and `value` (both taken): 1, or 0.
    ///
    /// # Safety
    /// `gname` is a live name; `oid` and `value` are NULL or values it takes.
    pub unsafe extern "C" fn GENERAL_NAME_set0_othername(gname: *mut GENERAL_NAME, oid: *mut ASN1_OBJECT, value: *mut ASN1_TYPE) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: no preconditions.
        let oth = unsafe { OTHERNAME_new() };
        // SAFETY: new, or NULL.
        let Some(o) = (unsafe { oth.as_mut() }) else { return 0 };
        // SAFETY: its own value.
        unsafe { ASN1_TYPE_free(o.value) };
        o.type_id = oid;
        o.value = value;
        // SAFETY: the caller's name; the new other name.
        unsafe { GENERAL_NAME_set0_value(gname, GEN_OTHERNAME, oth.cast()) };
        1
    }
}

ffi_export! {
    /// An other name's type and value (into `*poid` and `*pvalue` where given): 1, or 0 for
    /// another type of name.
    ///
    /// # Safety
    /// `gname` is a live name; `poid` and `pvalue` are NULL or writable.
    pub unsafe extern "C" fn GENERAL_NAME_get0_otherName(gname: *const GENERAL_NAME, poid: *mut *mut ASN1_OBJECT, pvalue: *mut *mut ASN1_TYPE) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { gname.as_ref() }) else { return 0 };
        if g.type_ != GEN_OTHERNAME {
            return 0;
        }
        // SAFETY: an other name's field.
        let op = unsafe { g.d.otherName };
        // SAFETY: the other name.
        let Some(o) = (unsafe { op.as_ref() }) else { return 0 };
        if !poid.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { poid.write(o.type_id) };
        }
        if !pvalue.is_null() {
            // SAFETY: as above.
            unsafe { pvalue.write(o.value) };
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: NULL names, which OpenSSL reads through, answer NULL, 0, or nothing.
    #[test]
    fn null_names_are_safe() {
        let mut t: c_int = 7;
        // SAFETY: NULL where OpenSSL dereferences it.
        unsafe { GENERAL_NAME_set0_value(ptr::null_mut(), GEN_DNS, ptr::null_mut()) };
        // SAFETY: as above.
        assert!(unsafe { GENERAL_NAME_get0_value(ptr::null(), &raw mut t) }.is_null());
        assert_eq!(t, 7);
        // SAFETY: as above.
        let r =
            unsafe { GENERAL_NAME_get0_otherName(ptr::null(), ptr::null_mut(), ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let p = unsafe {
            crate::x509v3::san::i2v_GENERAL_NAME(ptr::null_mut(), ptr::null_mut(), ptr::null_mut())
        };
        assert!(p.is_null());
        // SAFETY: as above.
        let r = unsafe { crate::x509v3::san::GENERAL_NAME_print(ptr::null_mut(), ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        assert!(unsafe { crate::x509v3::san::a2i_IPADDRESS(ptr::null()) }.is_null());
        // SAFETY: as above.
        let s = unsafe { crate::x509v3::ctx::X509V3_get_section(ptr::null_mut(), c"s".as_ptr()) };
        assert!(s.is_null());
        crate::err::take_all();
    }
}
