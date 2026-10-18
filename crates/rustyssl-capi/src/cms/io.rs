//! CMS I/O (`cms_io.c`): streaming, the BIO forms, and S/MIME.

use core::ffi::{c_int, c_uchar};
use core::ptr;

use rustyssl_abi::{
    ASN1_STRING_FLAG_CONT, ASN1_STRING_FLAG_NDEF, BIO, CMS_ContentInfo, ERR_LIB_CMS, ERR_R_CMS_LIB,
    NID_pkcs7_signed,
};

use super::base::{
    CMS_get0_content, CMS_get0_eContentType, cms_of, content, ctx_of, ctx_parts, held_ctx, raise,
    resolve_libctx_marked, type_nid,
};
use super::{CMS_ContentInfo_it, SignedData};
use crate::asn1::mime::{
    PEM_write_bio_ASN1_stream, SMIME_read_ASN1_ex, SMIME_write_ASN1_ex, i2d_ASN1_bio_stream,
};
use crate::asn1::ndef::BIO_new_NDEF;
use crate::asn1::string::ASN1_OCTET_STRING_new;
use crate::asn1::tpl::io::{ASN1_item_d2i_bio_ex, ASN1_item_i2d_bio};
use crate::ffi::ffi_export;
use crate::objects::OBJ_obj2nid;

ffi_export! {
    /// Marks the content to be streamed (`ASN1_STRING_FLAG_NDEF`, made if absent) and points
    /// `*boundary` at its data pointer: 1, or 0.
    ///
    /// # Safety
    /// `boundary` is room for a pointer; `cms` NULL or a live object.
    pub unsafe extern "C" fn CMS_stream(boundary: *mut *mut *mut c_uchar, cms: *mut CMS_ContentInfo) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let pos = unsafe { CMS_get0_content(cms) };
        if pos.is_null() {
            return 0;
        }
        // SAFETY: the content's slot.
        if unsafe { pos.read() }.is_null() {
            // SAFETY: no preconditions.
            let n = unsafe { ASN1_OCTET_STRING_new() };
            // SAFETY: as above.
            unsafe { pos.write(n) };
        }
        // SAFETY: the content's slot.
        let os = unsafe { pos.read() };
        // SAFETY: NULL or the content's string.
        let Some(s) = (unsafe { os.as_mut() }) else {
            raise(ERR_R_CMS_LIB, "CMS_stream");
            return 0;
        };
        s.flags |= core::ffi::c_long::from(ASN1_STRING_FLAG_NDEF);
        s.flags &= !core::ffi::c_long::from(ASN1_STRING_FLAG_CONT);
        if boundary.is_null() {
            return 0;
        }
        // SAFETY: the caller's room; the string's data pointer, which encoding sets.
        unsafe { boundary.write(&raw mut s.data) };
        1
    }
}

ffi_export! {
    /// Reads a DER CMS object from `bp`, in `*cms`'s library context if it holds one.
    ///
    /// # Safety
    /// `bp` is a live BIO; `cms` as for `d2i_*`.
    pub unsafe extern "C" fn d2i_CMS_bio(bp: *mut BIO, cms: *mut *mut CMS_ContentInfo) -> *mut CMS_ContentInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's slot.
        let (libctx, propq) = unsafe { held_ctx(cms) };
        // SAFETY: no preconditions.
        let it = unsafe { CMS_ContentInfo_it() };
        // SAFETY: the caller's guarantee.
        let ci = unsafe { ASN1_item_d2i_bio_ex(it, bp, cms.cast(), libctx, propq) }.cast::<CMS_ContentInfo>();
        if !ci.is_null() {
            // SAFETY: the object read.
            unsafe { resolve_libctx_marked(ci) };
        }
        ci
    }
}

ffi_export! {
    /// Writes the object to `bp` as DER: 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `cms` a live object.
    pub unsafe extern "C" fn i2d_CMS_bio(bp: *mut BIO, cms: *mut CMS_ContentInfo) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: no preconditions.
        let it = unsafe { CMS_ContentInfo_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_bio(it, bp, cms.cast_const().cast()) }
    }
}

ffi_export! {
    /// A BIO to stream the object through to `out`, or NULL.
    ///
    /// # Safety
    /// `out` is a live BIO; `cms` a live object.
    pub unsafe extern "C" fn BIO_new_CMS(out: *mut BIO, cms: *mut CMS_ContentInfo) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: no preconditions.
        let it = unsafe { CMS_ContentInfo_it() };
        // SAFETY: the caller's guarantee.
        unsafe { BIO_new_NDEF(out, cms.cast(), it) }
    }
}

ffi_export! {
    /// Encodes the object to `out`, streaming `in_` for `CMS_STREAM`: 1, or 0.
    ///
    /// # Safety
    /// `out` is a live BIO; `cms` a live object; `in_` NULL or a live BIO.
    pub unsafe extern "C" fn i2d_CMS_bio_stream(out: *mut BIO, cms: *mut CMS_ContentInfo, in_: *mut BIO, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: no preconditions.
        let it = unsafe { CMS_ContentInfo_it() };
        // SAFETY: the caller's guarantee.
        unsafe { i2d_ASN1_bio_stream(out, cms.cast(), in_, flags, it) }
    }
}

ffi_export! {
    /// [`i2d_CMS_bio_stream`] as PEM.
    ///
    /// # Safety
    /// As for [`i2d_CMS_bio_stream`].
    pub unsafe extern "C" fn PEM_write_bio_CMS_stream(out: *mut BIO, cms: *mut CMS_ContentInfo, in_: *mut BIO, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: no preconditions.
        let it = unsafe { CMS_ContentInfo_it() };
        // SAFETY: the caller's guarantee.
        unsafe { PEM_write_bio_ASN1_stream(out, cms.cast(), in_, flags, c"CMS".as_ptr(), it) }
    }
}

ffi_export! {
    /// Writes the object as S/MIME: 1, or 0.
    ///
    /// # Safety
    /// `bio` is a live BIO; `cms` a live object; `data` NULL or a live BIO.
    pub unsafe extern "C" fn SMIME_write_CMS(bio: *mut BIO, cms: *mut CMS_ContentInfo, data: *mut BIO, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        let (libctx, propq) = ctx_parts(ctx_of(cms));
        // SAFETY: the caller's guarantee.
        if unsafe { cms_of(cms) }.is_none() {
            return 0;
        }
        let ctype_nid = type_nid(cms);
        // SAFETY: as above.
        let etype = unsafe { CMS_get0_eContentType(cms) };
        // SAFETY: the type, or NULL.
        let econt_nid = unsafe { OBJ_obj2nid(etype) };
        let mdalgs = if ctype_nid == NID_pkcs7_signed {
            // SAFETY: the content of its type.
            unsafe { content::<SignedData>(cms) }.map_or(ptr::null_mut(), |s| s.digest_algorithms)
        } else {
            ptr::null_mut()
        };
        // SAFETY: no preconditions.
        let it = unsafe { CMS_ContentInfo_it() };
        // SAFETY: the caller's guarantee.
        unsafe { SMIME_write_ASN1_ex(bio, cms.cast(), data, flags, ctype_nid, econt_nid, mdalgs.cast(), it, libctx, propq) }
    }
}

ffi_export! {
    /// Reads an S/MIME CMS object, in `*cms`'s library context if it holds one; the detached
    /// content's part to `*bcont`. The object, or NULL.
    ///
    /// # Safety
    /// `bio` is a live BIO; `bcont` NULL or room for a BIO; `cms` as for `d2i_*`.
    pub unsafe extern "C" fn SMIME_read_CMS_ex(bio: *mut BIO, flags: c_int, bcont: *mut *mut BIO, cms: *mut *mut CMS_ContentInfo) -> *mut CMS_ContentInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's slot.
        let (libctx, propq) = unsafe { held_ctx(cms) };
        // SAFETY: no preconditions.
        let it = unsafe { CMS_ContentInfo_it() };
        // SAFETY: the caller's guarantee.
        let ci = unsafe { SMIME_read_ASN1_ex(bio, flags, bcont, it, cms.cast(), libctx, propq) }.cast::<CMS_ContentInfo>();
        if !ci.is_null() {
            // SAFETY: the object read.
            unsafe { resolve_libctx_marked(ci) };
        }
        ci
    }
}

ffi_export! {
    /// [`SMIME_read_CMS_ex`] in the default library context.
    ///
    /// # Safety
    /// As for [`SMIME_read_CMS_ex`].
    pub unsafe extern "C" fn SMIME_read_CMS(bio: *mut BIO, bcont: *mut *mut BIO) -> *mut CMS_ContentInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        unsafe { SMIME_read_CMS_ex(bio, 0, bcont, ptr::null_mut()) }
    }
}
