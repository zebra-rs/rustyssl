//! PKCS#7 streaming and S/MIME (`pk7_mime.c`, `bio_pk7.c`, and `PKCS7_stream`): the generic
//! ASN.1 streaming and MIME functions of [`crate::asn1::mime`] for PKCS#7 objects.

use core::ffi::{c_char, c_int, c_uchar};
use core::ptr;

use rustyssl_abi::{
    ASN1_OCTET_STRING, ASN1_STRING_FLAG_NDEF, BIO, ERR_LIB_PKCS7, NID_pkcs7_data,
    NID_pkcs7_enveloped, NID_pkcs7_signed, NID_pkcs7_signedAndEnveloped, NID_undef, PKCS7,
    PKCS7_R_NO_CONTENT, PKCS7_R_UNSUPPORTED_CONTENT_TYPE, SMIME_OLDMIME,
};

use super::doit::ctx_parts;
use super::{
    PKCS7_get_octet_string, PKCS7_it, content_ptr, ctx_of, enveloped_of, held_ctx, nid_of, p7_of,
    raise, resolve_libctx, sign_env_of, sign_of, type_nid,
};
use crate::asn1::mime::{
    PEM_write_bio_ASN1_stream, SMIME_read_ASN1_ex, SMIME_write_ASN1_ex, i2d_ASN1_bio_stream,
};
use crate::asn1::ndef::BIO_new_NDEF;
use crate::asn1::string::ASN1_OCTET_STRING_new;
use crate::ffi::ffi_export;

ffi_export! {
    /// Marks the object's content to be streamed (`ASN1_STRING_FLAG_NDEF`) and points
    /// `*boundary` at its data pointer: 1, or 0.
    ///
    /// # Safety
    /// `boundary` is room for a pointer; `p7` NULL or a live object.
    pub unsafe extern "C" fn PKCS7_stream(boundary: *mut *mut *mut c_uchar, p7: *mut PKCS7) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        const F: &str = "PKCS7_stream";
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p7_of(p7) }) else {
            raise(rustyssl_abi::PKCS7_R_INVALID_NULL_POINTER, F);
            return 0;
        };
        let nid = nid_of(p);
        let os: *mut ASN1_OCTET_STRING = match nid {
            // SAFETY: the content of its type.
            n if n == NID_pkcs7_data => unsafe { p.d.data },
            n if n == NID_pkcs7_signedAndEnveloped || n == NID_pkcs7_enveloped => {
                let enc = if n == NID_pkcs7_enveloped {
                    enveloped_of(p).map(|e| e.enc_data)
                } else {
                    sign_env_of(p).map(|e| e.enc_data)
                };
                // SAFETY: the content's encrypted content, NULL or live.
                match enc.and_then(|e| unsafe { e.as_mut() }) {
                    None => {
                        raise(PKCS7_R_NO_CONTENT, F);
                        ptr::null_mut()
                    }
                    Some(ec) => {
                        if ec.enc_data.is_null() {
                            // SAFETY: no preconditions.
                            ec.enc_data = unsafe { ASN1_OCTET_STRING_new() };
                        }
                        ec.enc_data
                    }
                }
            }
            n if n == NID_pkcs7_signed => {
                let contents = sign_of(p).map_or(ptr::null_mut(), |s| s.contents);
                if contents.is_null() {
                    raise(PKCS7_R_NO_CONTENT, F);
                    ptr::null_mut()
                } else if type_nid(contents) != NID_pkcs7_data {
                    raise(PKCS7_R_UNSUPPORTED_CONTENT_TYPE, F);
                    ptr::null_mut()
                } else {
                    // SAFETY: the content, live.
                    unsafe { PKCS7_get_octet_string(contents) }
                }
            }
            _ => ptr::null_mut(),
        };
        // SAFETY: NULL or the content's string.
        let Some(s) = (unsafe { os.as_mut() }) else { return 0 };
        s.flags |= core::ffi::c_long::from(ASN1_STRING_FLAG_NDEF);
        if boundary.is_null() {
            return 0;
        }
        // SAFETY: the caller's room; the string's data pointer, which encoding sets.
        unsafe { boundary.write(&raw mut s.data) };
        1
    }
}

ffi_export! {
    /// A BIO to stream the object through to `out`, or NULL.
    ///
    /// # Safety
    /// `out` is a live BIO; `p7` a live object.
    pub unsafe extern "C" fn BIO_new_PKCS7(out: *mut BIO, p7: *mut PKCS7) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        // SAFETY: no preconditions.
        let it = unsafe { PKCS7_it() };
        // SAFETY: the caller's guarantee.
        unsafe { BIO_new_NDEF(out, p7.cast(), it) }
    }
}

ffi_export! {
    /// Encodes the object to `out`, streaming `in_` for `PKCS7_STREAM`: 1, or 0.
    ///
    /// # Safety
    /// `out` is a live BIO; `p7` a live object; `in_` NULL or a live BIO.
    pub unsafe extern "C" fn i2d_PKCS7_bio_stream(out: *mut BIO, p7: *mut PKCS7, in_: *mut BIO, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        // SAFETY: no preconditions.
        let it = unsafe { PKCS7_it() };
        // SAFETY: the caller's guarantee.
        unsafe { i2d_ASN1_bio_stream(out, p7.cast(), in_, flags, it) }
    }
}

ffi_export! {
    /// [`i2d_PKCS7_bio_stream`] as PEM.
    ///
    /// # Safety
    /// As for [`i2d_PKCS7_bio_stream`].
    pub unsafe extern "C" fn PEM_write_bio_PKCS7_stream(out: *mut BIO, p7: *mut PKCS7, in_: *mut BIO, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        // SAFETY: no preconditions.
        let it = unsafe { PKCS7_it() };
        // SAFETY: the caller's guarantee.
        unsafe { PEM_write_bio_ASN1_stream(out, p7.cast(), in_, flags, c"PKCS7".as_ptr(), it) }
    }
}

ffi_export! {
    /// Writes the object as S/MIME (old-style `application/x-pkcs7-*` types unless
    /// `SMIME_OLDMIME`): 1, or 0.
    ///
    /// # Safety
    /// `bio` is a live BIO; `p7` a live object; `data` NULL or a live BIO.
    pub unsafe extern "C" fn SMIME_write_PKCS7(bio: *mut BIO, p7: *mut PKCS7, data: *mut BIO, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PKCS7
    {
        let (libctx, propq) = ctx_parts(ctx_of(p7));
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p7_of(p7) }) else {
            raise(rustyssl_abi::PKCS7_R_INVALID_NULL_POINTER, "SMIME_write_PKCS7");
            return 0;
        };
        let ctype_nid = nid_of(p);
        let mdalgs = if ctype_nid == NID_pkcs7_signed {
            if content_ptr(p).is_null() {
                return 0;
            }
            sign_of(p).map_or(ptr::null_mut(), |s| s.md_algs)
        } else {
            ptr::null_mut()
        };
        // SAFETY: no preconditions.
        let it = unsafe { PKCS7_it() };
        // SAFETY: the caller's guarantee.
        unsafe { SMIME_write_ASN1_ex(bio, p7.cast(), data, flags ^ SMIME_OLDMIME, ctype_nid, NID_undef, mdalgs, it, libctx, propq) }
    }
}

ffi_export! {
    /// Reads an S/MIME PKCS#7 object, in `*p7`'s library context if it holds one; the
    /// detached content's part to `*bcont`. The object, or NULL.
    ///
    /// # Safety
    /// `bio` is a live BIO; `bcont` NULL or room for a BIO; `p7` as for `d2i_*`.
    pub unsafe extern "C" fn SMIME_read_PKCS7_ex(bio: *mut BIO, bcont: *mut *mut BIO, p7: *mut *mut PKCS7) -> *mut PKCS7
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's slot, holding NULL or a live object.
        let (libctx, propq): (_, *const c_char) = unsafe { held_ctx(p7) };
        // SAFETY: no preconditions.
        let it = unsafe { PKCS7_it() };
        // SAFETY: the caller's guarantee.
        let ret = unsafe { SMIME_read_ASN1_ex(bio, 0, bcont, it, p7.cast(), libctx, propq) }.cast::<PKCS7>();
        if !ret.is_null() {
            // SAFETY: the object read.
            unsafe { resolve_libctx(ret) };
        }
        ret
    }
}

ffi_export! {
    /// [`SMIME_read_PKCS7_ex`] in the default library context.
    ///
    /// # Safety
    /// As for [`SMIME_read_PKCS7_ex`].
    pub unsafe extern "C" fn SMIME_read_PKCS7(bio: *mut BIO, bcont: *mut *mut BIO) -> *mut PKCS7
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS7
    {
        // SAFETY: the caller's guarantee.
        unsafe { SMIME_read_PKCS7_ex(bio, bcont, ptr::null_mut()) }
    }
}
