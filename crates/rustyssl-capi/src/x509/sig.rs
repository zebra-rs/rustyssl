//! `X509_SIG` (`x_sig.c`): a SEQUENCE of an AlgorithmIdentifier and an OCTET STRING, PKCS#1's
//! DigestInfo and PKCS#8's EncryptedPrivateKeyInfo, with its DER and its two getters.

use core::mem::offset_of;

use rustyssl_abi::{ASN1_ITEM, ASN1_OCTET_STRING, ERR_LIB_ASN1, X509_ALGOR, X509_SIG};

use crate::asn1::tpl::items::{ASN1_OCTET_STRING_it, X509_ALGOR_it, d2i, i2d, new_free};
use crate::asn1::tpl::statics::{Templates, sequence};
use crate::asn1::tpl::{item_fns, template_at};
use crate::ffi::ffi_export;

/// `X509_SIG` (`X509_sig_st`).
#[repr(C)]
pub(crate) struct Sig {
    pub(crate) algor: *mut X509_ALGOR,
    pub(crate) digest: *mut ASN1_OCTET_STRING,
}

static SIG_TT: Templates<2> = Templates([
    template_at(0, 0, offset_of!(Sig, algor), c"algor", X509_ALGOR_it),
    template_at(
        0,
        0,
        offset_of!(Sig, digest),
        c"digest",
        ASN1_OCTET_STRING_it,
    ),
]);

item_fns! {
    /// SEQUENCE { algorithm AlgorithmIdentifier, digest OCTET STRING }.
    pub unsafe extern "C" fn X509_SIG_it = sequence::<Sig, 2>(&SIG_TT, None, c"X509_SIG");
}

new_free! {
    pub unsafe extern "C" fn X509_SIG_new, pub unsafe extern "C" fn X509_SIG_free(X509_SIG) = X509_SIG_it;
}

i2d! {
    /// Encodes an `X509_SIG`.
    pub unsafe extern "C" fn i2d_X509_SIG(X509_SIG) = X509_SIG_it;
}

d2i! {
    /// Decodes an `X509_SIG` (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_X509_SIG(X509_SIG) = X509_SIG_it;
}

/// Writes the `X509_SIG`'s fields where asked for.
///
/// # Safety
/// `sig` is NULL or a live `X509_SIG`; the out pointers are NULL or writable.
unsafe fn get(
    sig: *const X509_SIG,
    palg: *mut *mut X509_ALGOR,
    pdigest: *mut *mut ASN1_OCTET_STRING,
) {
    // SAFETY: the caller's guarantee; an `X509_SIG` is a `Sig`.
    let Some(s) = (unsafe { sig.cast::<Sig>().as_ref() }) else {
        return;
    };
    if !palg.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { palg.write(s.algor) };
    }
    if !pdigest.is_null() {
        // SAFETY: as above.
        unsafe { pdigest.write(s.digest) };
    }
}

ffi_export! {
    /// The `X509_SIG`'s AlgorithmIdentifier and OCTET STRING, each where asked for.
    ///
    /// # Safety
    /// `sig` is NULL or a live `X509_SIG`; the out pointers are NULL or writable.
    pub unsafe extern "C" fn X509_SIG_get0(sig: *const X509_SIG, palg: *mut *const X509_ALGOR, pdigest: *mut *const ASN1_OCTET_STRING)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { get(sig, palg.cast(), pdigest.cast()) }
    }
}

ffi_export! {
    /// As `X509_SIG_get0`, the fields to change.
    ///
    /// # Safety
    /// As for `X509_SIG_get0`.
    pub unsafe extern "C" fn X509_SIG_getm(sig: *mut X509_SIG, palg: *mut *mut X509_ALGOR, pdigest: *mut *mut ASN1_OCTET_STRING)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { get(sig, palg, pdigest) }
    }
}

ffi_export! {
    /// Writes an `X509_SIG` (an EncryptedPrivateKeyInfo) to a BIO. 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `p8` is a live `X509_SIG`.
    pub unsafe extern "C" fn i2d_PKCS8_bio(bp: *mut rustyssl_abi::BIO, p8: *const X509_SIG) -> core::ffi::c_int
    where failure = 0, library = rustyssl_abi::ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_SIG_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { crate::asn1::tpl::io::ASN1_item_i2d_bio(it, bp, p8.cast()) }
    }
}

ffi_export! {
    /// Writes an `X509_SIG` to a `FILE`. 1, or 0.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `p8` is a live `X509_SIG`.
    pub unsafe extern "C" fn i2d_PKCS8_fp(fp: *mut libc::FILE, p8: *const X509_SIG) -> core::ffi::c_int
    where failure = 0, library = rustyssl_abi::ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_SIG_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { crate::asn1::tpl::io::ASN1_item_i2d_fp(it, fp, p8.cast()) }
    }
}

ffi_export! {
    /// Reads an `X509_SIG` (an EncryptedPrivateKeyInfo) from a BIO (`ASN1_d2i_bio_of`), into
    /// `*p8` too when given. NULL on failure.
    ///
    /// # Safety
    /// `bp` is a live BIO; `p8` is NULL or holds NULL or a live `X509_SIG`.
    pub unsafe extern "C" fn d2i_PKCS8_bio(bp: *mut rustyssl_abi::BIO, p8: *mut *mut X509_SIG) -> *mut X509_SIG
    where failure = core::ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_SIG_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { crate::asn1::tpl::io::ASN1_item_d2i_bio(it, bp, p8.cast()) }.cast()
    }
}

ffi_export! {
    /// Reads an `X509_SIG` from a `FILE`, as `d2i_PKCS8_bio`.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `p8` as for `d2i_PKCS8_bio`.
    pub unsafe extern "C" fn d2i_PKCS8_fp(fp: *mut libc::FILE, p8: *mut *mut X509_SIG) -> *mut X509_SIG
    where failure = core::ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_SIG_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { crate::asn1::tpl::io::ASN1_item_d2i_fp(it, fp, p8.cast()) }.cast()
    }
}
