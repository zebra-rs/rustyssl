//! PKCS#8's PrivateKeyInfo (`p8_pkey.c`, with `x_all.c`'s BIO and FILE forms and two of
//! `pkcs12`'s attribute helpers): `PKCS8_PRIV_KEY_INFO`, a SEQUENCE of a version, the key's
//! AlgorithmIdentifier, the key in an OCTET STRING, optional attributes ([0] IMPLICIT SET OF
//! Attribute), and, in a version 2 (OneAsymmetricKey), an optional public key ([1] IMPLICIT
//! BIT STRING).
//!
//! As in OpenSSL, freeing one wipes the key's octets first, and a decoded one must be of
//! version 1 or 2 (0 or 1), and of version 1 without a public key.

use core::ffi::{c_int, c_uchar, c_void};
use core::mem::offset_of;
use core::ptr;

use libc::FILE;

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_INTEGER, ASN1_ITEM, ASN1_OBJECT, ASN1_OCTET_STRING, ASN1_OP_D2I_POST,
    ASN1_OP_FREE_PRE, ASN1_TFLG_IMPLICIT, ASN1_TFLG_OPTIONAL, ASN1_TFLG_SET_OF, ASN1_TYPE,
    ASN1_VALUE, BIO, ERR_LIB_ASN1, NID_key_usage, PKCS8_PRIV_KEY_INFO, V_ASN1_BIT_STRING,
    X509_ALGOR, X509_ATTRIBUTE, stack_st_X509_ATTRIBUTE,
};

use super::algor::set0;
use super::attrib::{
    X509_ATTRIBUTE_it, X509at_add1_attr, X509at_add1_attr_by_NID, X509at_add1_attr_by_OBJ,
    get_attr_gen,
};
use crate::asn1::integer::{ASN1_INTEGER_get, ASN1_INTEGER_set};
use crate::asn1::string::{ASN1_STRING_get0_data, ASN1_STRING_length, ASN1_STRING_set0};
use crate::asn1::tpl::io::{
    ASN1_item_d2i_bio, ASN1_item_d2i_fp, ASN1_item_i2d_bio, ASN1_item_i2d_fp,
};
use crate::asn1::tpl::items::{
    ASN1_BIT_STRING_it, ASN1_INTEGER_it, ASN1_OCTET_STRING_it, X509_ALGOR_it, d2i, i2d, new_free,
};
use crate::asn1::tpl::statics::{Aux, Templates, aux, sequence};
use crate::asn1::tpl::{item_fns, template_at};
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;

/// `PKCS8_PRIV_KEY_INFO` (`pkcs8_priv_key_info_st`).
#[repr(C)]
pub(crate) struct P8 {
    pub(crate) version: *mut ASN1_INTEGER,
    pub(crate) pkeyalg: *mut X509_ALGOR,
    pub(crate) pkey: *mut ASN1_OCTET_STRING,
    pub(crate) attributes: *mut stack_st_X509_ATTRIBUTE,
    pub(crate) kpub: *mut ASN1_BIT_STRING,
}

static P8_TT: Templates<5> = Templates([
    template_at(0, 0, offset_of!(P8, version), c"version", ASN1_INTEGER_it),
    template_at(0, 0, offset_of!(P8, pkeyalg), c"pkeyalg", X509_ALGOR_it),
    template_at(0, 0, offset_of!(P8, pkey), c"pkey", ASN1_OCTET_STRING_it),
    template_at(
        ASN1_TFLG_SET_OF | ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(P8, attributes),
        c"attributes",
        X509_ATTRIBUTE_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(P8, kpub),
        c"kpub",
        ASN1_BIT_STRING_it,
    ),
]);

static P8_AUX: Aux = aux(pkey_cb);

ffi_callback! {
    /// `pkey_cb`: freeing wipes the key's octets; a decoded one's version must be 0 or 1, and 0
    /// without a public key.
    ///
    /// # Safety
    /// `pval` holds NULL or a live `PKCS8_PRIV_KEY_INFO`.
    pub(crate) unsafe extern "C" fn pkey_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, _exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let v = unsafe { pval.read() };
        // SAFETY: as above.
        let Some(k) = (unsafe { v.cast::<P8>().as_ref() }) else { return 1 };
        match operation {
            ASN1_OP_FREE_PRE => {
                // SAFETY: the key's octets, or NULL.
                if let Some(s) = unsafe { k.pkey.as_ref() }
                    && !s.data.is_null()
                {
                    // SAFETY: the string's `length` octets.
                    unsafe { mem::cleanse(s.data.cast(), usize::try_from(s.length).unwrap_or(0)) };
                }
                1
            }
            ASN1_OP_D2I_POST => {
                // SAFETY: the decoded version.
                let version = unsafe { ASN1_INTEGER_get(k.version) };
                c_int::from((0..=1).contains(&version) && !(version == 0 && !k.kpub.is_null()))
            }
            _ => 1,
        }
    }
}

item_fns! {
    /// PrivateKeyInfo (OneAsymmetricKey).
    pub unsafe extern "C" fn PKCS8_PRIV_KEY_INFO_it = sequence::<P8, 5>(&P8_TT, Some(&P8_AUX), c"PKCS8_PRIV_KEY_INFO");
}

new_free! {
    pub unsafe extern "C" fn PKCS8_PRIV_KEY_INFO_new, pub unsafe extern "C" fn PKCS8_PRIV_KEY_INFO_free(PKCS8_PRIV_KEY_INFO) = PKCS8_PRIV_KEY_INFO_it;
}

i2d! {
    /// Encodes a PrivateKeyInfo.
    pub unsafe extern "C" fn i2d_PKCS8_PRIV_KEY_INFO(PKCS8_PRIV_KEY_INFO) = PKCS8_PRIV_KEY_INFO_it;
}

d2i! {
    /// Decodes a PrivateKeyInfo (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_PKCS8_PRIV_KEY_INFO(PKCS8_PRIV_KEY_INFO) = PKCS8_PRIV_KEY_INFO_it;
}

ffi_export! {
    /// Reads a PrivateKeyInfo from a BIO.
    ///
    /// # Safety
    /// `bp` is a live BIO; `p8inf` is NULL or holds NULL or a live PrivateKeyInfo.
    pub unsafe extern "C" fn d2i_PKCS8_PRIV_KEY_INFO_bio(bp: *mut BIO, p8inf: *mut *mut PKCS8_PRIV_KEY_INFO) -> *mut PKCS8_PRIV_KEY_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { PKCS8_PRIV_KEY_INFO_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_d2i_bio(it, bp, p8inf.cast()) }.cast()
    }
}

ffi_export! {
    /// Writes a PrivateKeyInfo to a BIO. 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `p8inf` is a live PrivateKeyInfo.
    pub unsafe extern "C" fn i2d_PKCS8_PRIV_KEY_INFO_bio(bp: *mut BIO, p8inf: *const PKCS8_PRIV_KEY_INFO) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { PKCS8_PRIV_KEY_INFO_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_i2d_bio(it, bp, p8inf.cast()) }
    }
}

ffi_export! {
    /// Reads a PrivateKeyInfo from a file.
    ///
    /// # Safety
    /// `fp` is a live file; `p8inf` is NULL or holds NULL or a live PrivateKeyInfo.
    pub unsafe extern "C" fn d2i_PKCS8_PRIV_KEY_INFO_fp(fp: *mut FILE, p8inf: *mut *mut PKCS8_PRIV_KEY_INFO) -> *mut PKCS8_PRIV_KEY_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { PKCS8_PRIV_KEY_INFO_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_d2i_fp(it, fp, p8inf.cast()) }.cast()
    }
}

ffi_export! {
    /// Writes a PrivateKeyInfo to a file. 1, or 0.
    ///
    /// # Safety
    /// `fp` is a live file; `p8inf` is a live PrivateKeyInfo.
    pub unsafe extern "C" fn i2d_PKCS8_PRIV_KEY_INFO_fp(fp: *mut FILE, p8inf: *const PKCS8_PRIV_KEY_INFO) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { PKCS8_PRIV_KEY_INFO_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_i2d_fp(it, fp, p8inf.cast()) }
    }
}

/// The PrivateKeyInfo behind a pointer.
///
/// # Safety
/// `p8` is NULL or a live PrivateKeyInfo, which nothing else changes while the reference lives.
pub(crate) unsafe fn p8<'a>(p8: *const PKCS8_PRIV_KEY_INFO) -> Option<&'a mut P8> {
    // SAFETY: the caller's guarantee; a PrivateKeyInfo is a `P8`.
    unsafe { p8.cast::<P8>().cast_mut().as_mut() }
}

ffi_export! {
    /// Sets the PrivateKeyInfo's version (unless negative; only 0 and 1 are taken), its
    /// AlgorithmIdentifier's object and parameter (as `X509_ALGOR_set0`, taking them), and
    /// its key's octets (taken, unless NULL). 1, or 0.
    ///
    /// # Safety
    /// `priv_` is NULL or a live PrivateKeyInfo; `aobj` and `pval` are what `X509_ALGOR_set0`
    /// takes; `penc` is NULL or `penclen` octets from the C allocator.
    pub unsafe extern "C" fn PKCS8_pkey_set0(priv_: *mut PKCS8_PRIV_KEY_INFO, aobj: *mut ASN1_OBJECT, version: c_int, ptype: c_int, pval: *mut c_void, penc: *mut c_uchar, penclen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { p8(priv_) }) else { return 0 };
        if version >= 0 {
            if version > 1 {
                return 0;
            }
            // SAFETY: the PrivateKeyInfo's version.
            if unsafe { ASN1_INTEGER_set(k.version, version.into()) } == 0 {
                return 0;
            }
        }
        // SAFETY: its AlgorithmIdentifier; the caller's object and value.
        if unsafe { set0(k.pkeyalg, aobj, ptype, pval) } == 0 {
            return 0;
        }
        if !penc.is_null() {
            // SAFETY: its key's string takes the caller's octets.
            unsafe { ASN1_STRING_set0(k.pkey, penc.cast(), penclen) };
        }
        1
    }
}

ffi_export! {
    /// The PrivateKeyInfo's algorithm's object, its key's octets and their length, and its
    /// AlgorithmIdentifier, each where asked for (the octets with their length). 1.
    ///
    /// # Safety
    /// `p8` is a live PrivateKeyInfo; the out pointers are NULL or writable (`ppklen` too when
    /// `pk` is given).
    pub unsafe extern "C" fn PKCS8_pkey_get0(ppkalg: *mut *const ASN1_OBJECT, pk: *mut *const c_uchar, ppklen: *mut c_int, pa: *mut *const X509_ALGOR, p8_: *const PKCS8_PRIV_KEY_INFO) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { p8(p8_) }) else { return 0 };
        if !ppkalg.is_null() {
            // SAFETY: its AlgorithmIdentifier.
            let obj = unsafe { k.pkeyalg.as_ref() }.map_or(ptr::null_mut(), |a| a.algorithm);
            // SAFETY: the caller's guarantee.
            unsafe { ppkalg.write(obj) };
        }
        if !pk.is_null() {
            // SAFETY: its key's string.
            let data = unsafe { ASN1_STRING_get0_data(k.pkey) };
            // SAFETY: the caller's guarantee.
            unsafe { pk.write(data) };
            if !ppklen.is_null() {
                // SAFETY: its key's string.
                let len = unsafe { ASN1_STRING_length(k.pkey) };
                // SAFETY: the caller's guarantee.
                unsafe { ppklen.write(len) };
            }
        }
        if !pa.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { pa.write(k.pkeyalg) };
        }
        1
    }
}

ffi_export! {
    /// The PrivateKeyInfo's attributes, or NULL.
    ///
    /// # Safety
    /// `p8` is NULL or a live PrivateKeyInfo.
    pub unsafe extern "C" fn PKCS8_pkey_get0_attrs(p8_: *const PKCS8_PRIV_KEY_INFO) -> *const stack_st_X509_ATTRIBUTE
    where failure = ptr::null(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { p8(p8_) }.map_or(ptr::null(), |k| k.attributes.cast_const())
    }
}

ffi_export! {
    /// Adds a copy of the attribute (`X509at_add1_attr`, which refuses a second of an object).
    /// 1, or 0.
    ///
    /// # Safety
    /// `p8` is NULL or a live PrivateKeyInfo; `attr` is NULL or a live attribute.
    pub unsafe extern "C" fn PKCS8_pkey_add1_attr(p8_: *mut PKCS8_PRIV_KEY_INFO, attr: *mut X509_ATTRIBUTE) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { p8(p8_) }) else { return 0 };
        // SAFETY: its attributes; the caller's attribute.
        c_int::from(!unsafe { X509at_add1_attr(&raw mut k.attributes, attr) }.is_null())
    }
}

ffi_export! {
    /// Adds an attribute of the NID's object with one value (`X509at_add1_attr_by_NID`, which
    /// refuses a second of an object). 1, or 0.
    ///
    /// # Safety
    /// `p8` is NULL or a live PrivateKeyInfo; `bytes` is what `X509_ATTRIBUTE_set1_data` takes.
    pub unsafe extern "C" fn PKCS8_pkey_add1_attr_by_NID(p8_: *mut PKCS8_PRIV_KEY_INFO, nid: c_int, type_: c_int, bytes: *const c_uchar, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { p8(p8_) }) else { return 0 };
        // SAFETY: its attributes; the caller's data.
        c_int::from(!unsafe { X509at_add1_attr_by_NID(&raw mut k.attributes, nid, type_, bytes, len) }.is_null())
    }
}

ffi_export! {
    /// Adds an attribute of `obj` with one value (`X509at_add1_attr_by_OBJ`, which refuses a
    /// second of an object). 1, or 0.
    ///
    /// # Safety
    /// `p8` is NULL or a live PrivateKeyInfo; `obj` is NULL or a live object; `bytes` is what
    /// `X509_ATTRIBUTE_set1_data` takes.
    pub unsafe extern "C" fn PKCS8_pkey_add1_attr_by_OBJ(p8_: *mut PKCS8_PRIV_KEY_INFO, obj: *const ASN1_OBJECT, type_: c_int, bytes: *const c_uchar, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { p8(p8_) }) else { return 0 };
        // SAFETY: its attributes; the caller's object and data.
        c_int::from(!unsafe { X509at_add1_attr_by_OBJ(&raw mut k.attributes, obj, type_, bytes, len) }.is_null())
    }
}

ffi_export! {
    /// The first value of the PrivateKeyInfo's attribute of the NID, or NULL.
    ///
    /// # Safety
    /// `p8` is NULL or a live PrivateKeyInfo.
    pub unsafe extern "C" fn PKCS8_get_attr(p8_: *mut PKCS8_PRIV_KEY_INFO, attr_nid: c_int) -> *mut ASN1_TYPE
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { p8(p8_) }) else { return ptr::null_mut() };
        // SAFETY: its attributes.
        unsafe { get_attr_gen(k.attributes, attr_nid) }
    }
}

ffi_export! {
    /// Adds a key usage attribute: a BIT STRING of the usage's low octet. 1, or 0.
    ///
    /// # Safety
    /// `p8` is NULL or a live PrivateKeyInfo.
    pub unsafe extern "C" fn PKCS8_add_keyusage(p8_: *mut PKCS8_PRIV_KEY_INFO, usage: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // OpenSSL keeps the low octet, as its cast to an unsigned char does.
        let us_val = usage.to_le_bytes()[0];
        // SAFETY: the caller's guarantee; one octet.
        unsafe { PKCS8_pkey_add1_attr_by_NID(p8_, NID_key_usage, V_ASN1_BIT_STRING, &raw const us_val, 1) }
    }
}
