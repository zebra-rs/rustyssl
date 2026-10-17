//! Streaming an ASN.1 structure with indefinite lengths (`BIO_new_NDEF`, OpenSSL's
//! `bio_ndef.c`): an ASN.1 filter whose prefix is the structure's encoding up to its streamed
//! content and whose suffix is the rest, after the type's callback has finished the structure.
//!
//! The streamed OCTET STRING marks where the content goes: encoding the structure points the
//! string's data at its place in the output (the boundary). The prefix and suffix are cut at
//! that point only when it lies within the encoding just made.

use core::ffi::{c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_ITEM, ASN1_ITYPE_CHOICE, ASN1_ITYPE_NDEF_SEQUENCE, ASN1_ITYPE_SEQUENCE,
    ASN1_OP_STREAM_POST, ASN1_OP_STREAM_PRE, ASN1_R_STREAMING_NOT_SUPPORTED, ASN1_STREAM_ARG,
    ASN1_VALUE, BIO, BIO_C_SET_EX_ARG, ERR_LIB_ASN1, ERR_R_BIO_LIB,
};

use super::bio_asn1::{BIO_asn1_set_prefix, BIO_asn1_set_suffix, BIO_f_asn1};
use crate::asn1::tpl::encode::ASN1_item_ndef_i2d;
use crate::asn1::tpl::new::aux_callback;
use crate::bio::{BIO_ctrl, BIO_free, BIO_new, BIO_pop, BIO_push};
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;

/// What the prefix and suffix functions share (OpenSSL's `NDEF_SUPPORT`).
struct Ndef {
    val: *mut ASN1_VALUE,
    it: *const ASN1_ITEM,
    ndef_bio: *mut BIO,
    out: *mut BIO,
    boundary: *mut *mut c_uchar,
    derbuf: *mut c_uchar,
}

/// The aux callback of an item that can have one: SEQUENCEs and CHOICEs. OpenSSL reads any
/// item's functions as aux data (docs/DEVIATIONS.md).
pub(crate) fn stream_callback(it: *const ASN1_ITEM) -> rustyssl_abi::ASN1_aux_cb {
    // SAFETY: NULL or a live item.
    let itype = unsafe { it.as_ref() }.map(|i| c_int::from(i.itype))?;
    if ![
        ASN1_ITYPE_SEQUENCE,
        ASN1_ITYPE_NDEF_SEQUENCE,
        ASN1_ITYPE_CHOICE,
    ]
    .contains(&itype)
    {
        return None;
    }
    // SAFETY: a SEQUENCE or CHOICE item.
    unsafe { aux_callback(it) }
}

/// The structure encoded with indefinite lengths into a new buffer, and where its boundary
/// falls in it: (buffer, length, boundary offset).
///
/// # Safety
/// `aux` is a live `Ndef` whose value and boundary are live.
unsafe fn encode(aux: &mut Ndef) -> Option<(*mut c_uchar, usize, usize)> {
    // SAFETY: the caller's guarantee.
    let derlen = unsafe { ASN1_item_ndef_i2d(aux.val, ptr::null_mut(), aux.it) };
    let len = usize::try_from(derlen).ok()?;
    let p = mem::alloc(len).cast::<c_uchar>();
    if p.is_null() {
        return None;
    }
    aux.derbuf = p;
    let mut q = p;
    // SAFETY: room for the encoding just measured.
    let written = unsafe { ASN1_item_ndef_i2d(aux.val, &mut q, aux.it) };
    let written = usize::try_from(written).ok().filter(|&w| w <= len)?;
    if aux.boundary.is_null() {
        return None;
    }
    // SAFETY: the streamed string's data pointer, which the encoding just set.
    let bound = unsafe { *aux.boundary };
    let at = bound
        .addr()
        .checked_sub(p.addr())
        .filter(|&a| a <= written)?;
    Some((p, written, at))
}

/// The `Ndef` behind a prefix or suffix function's argument.
///
/// # Safety
/// `parg` is NULL or the ASN.1 filter's argument slot.
unsafe fn ndef_of<'a>(parg: *mut c_void) -> Option<&'a mut Ndef> {
    // SAFETY: the caller's guarantee.
    let slot = unsafe { parg.cast::<*mut Ndef>().as_ref() }?;
    // SAFETY: NULL or the `Ndef` `BIO_new_NDEF` made.
    unsafe { slot.as_mut() }
}

ffi_callback! {
    /// `ndef_prefix`: the encoding up to the content.
    ///
    /// # Safety
    /// As the ASN.1 filter calls it.
    pub(crate) unsafe extern "C" fn ndef_prefix(_b: *mut BIO, pbuf: *mut *mut c_uchar, plen: *mut c_int, parg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the filter's argument.
        let Some(aux) = (unsafe { ndef_of(parg) }) else { return 0 };
        // SAFETY: a live `Ndef`.
        let Some((p, _, at)) = (unsafe { encode(aux) }) else { return 0 };
        let Ok(n) = c_int::try_from(at) else { return 0 };
        // SAFETY: the filter's slots.
        unsafe { pbuf.write(p) };
        // SAFETY: as above.
        unsafe { plen.write(n) };
        1
    }
}

ffi_callback! {
    /// `ndef_prefix_free`: frees the encoding.
    ///
    /// # Safety
    /// As the ASN.1 filter calls it.
    pub(crate) unsafe extern "C" fn ndef_prefix_free(_b: *mut BIO, pbuf: *mut *mut c_uchar, plen: *mut c_int, parg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the filter's argument.
        let Some(aux) = (unsafe { ndef_of(parg) }) else { return 0 };
        // SAFETY: the encoding, from CRYPTO_malloc, or NULL.
        unsafe { mem::release(aux.derbuf.cast()) };
        aux.derbuf = ptr::null_mut();
        // SAFETY: the filter's slots.
        unsafe { pbuf.write(ptr::null_mut()) };
        // SAFETY: as above.
        unsafe { plen.write(0) };
        1
    }
}

ffi_callback! {
    /// `ndef_suffix`: the structure finished by its callback, then its encoding after the
    /// content.
    ///
    /// # Safety
    /// As the ASN.1 filter calls it.
    pub(crate) unsafe extern "C" fn ndef_suffix(_b: *mut BIO, pbuf: *mut *mut c_uchar, plen: *mut c_int, parg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the filter's argument.
        let Some(aux) = (unsafe { ndef_of(parg) }) else { return 0 };
        let Some(cb) = stream_callback(aux.it) else { return 0 };
        let mut sarg = ASN1_STREAM_ARG { out: aux.out, ndef_bio: aux.ndef_bio, boundary: aux.boundary };
        // SAFETY: the type's callback, with its value and the stream.
        if unsafe { cb(ASN1_OP_STREAM_POST, &mut aux.val, aux.it, (&raw mut sarg).cast()) } <= 0 {
            return 0;
        }
        // SAFETY: a live `Ndef`.
        let Some((p, len, at)) = (unsafe { encode(aux) }) else { return 0 };
        let Some(n) = len.checked_sub(at).and_then(|n| c_int::try_from(n).ok()) else { return 0 };
        let start = p.wrapping_add(at);
        // SAFETY: the filter's slot; the suffix starts within the encoding.
        unsafe { pbuf.write(start) };
        // SAFETY: as above.
        unsafe { plen.write(n) };
        1
    }
}

ffi_callback! {
    /// `ndef_suffix_free`: frees the encoding and the shared state.
    ///
    /// # Safety
    /// As the ASN.1 filter calls it.
    pub(crate) unsafe extern "C" fn ndef_suffix_free(b: *mut BIO, pbuf: *mut *mut c_uchar, plen: *mut c_int, parg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: as the filter calls it.
        if unsafe { ndef_prefix_free(b, pbuf, plen, parg) } == 0 {
            return 0;
        }
        let slot = parg.cast::<*mut Ndef>();
        // SAFETY: the filter's argument slot.
        let ndef = unsafe { slot.read() };
        // SAFETY: the `Ndef` `BIO_new_NDEF` boxed, freed once.
        drop(unsafe { Box::from_raw(ndef) });
        // SAFETY: as above.
        unsafe { slot.write(ptr::null_mut()) };
        1
    }
}

ffi_export! {
    /// A BIO to stream `val` through to `out` with indefinite lengths: the type's callback's
    /// chain over an ASN.1 filter, or NULL.
    ///
    /// # Safety
    /// `out` is a live BIO; `val` a live value of `it`.
    pub unsafe extern "C" fn BIO_new_NDEF(out: *mut BIO, val: *mut ASN1_VALUE, it: *const ASN1_ITEM) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        const F: &str = "BIO_new_NDEF";
        let Some(cb) = stream_callback(it) else {
            err::raise(ERR_LIB_ASN1, ASN1_R_STREAMING_NOT_SUPPORTED, F);
            return ptr::null_mut();
        };
        let ndef = Box::into_raw(Box::new(Ndef {
            val: ptr::null_mut(),
            it: ptr::null(),
            ndef_bio: ptr::null_mut(),
            out: ptr::null_mut(),
            boundary: ptr::null_mut(),
            derbuf: ptr::null_mut(),
        }));
        // SAFETY: no preconditions.
        let method = unsafe { BIO_f_asn1() };
        // SAFETY: the built-in method.
        let asn_bio = unsafe { BIO_new(method) };
        let mut owned = true;
        let mut pop_bio = ptr::null_mut();
        'err: {
            if asn_bio.is_null() {
                err::raise(ERR_LIB_ASN1, ERR_R_BIO_LIB, F);
                break 'err;
            }
            // SAFETY: live BIOs; the filter goes in front of the caller's.
            let out = unsafe { BIO_push(asn_bio, out) };
            if out.is_null() {
                break 'err;
            }
            pop_bio = asn_bio;
            // SAFETY: the filter; this module's functions.
            if unsafe { BIO_asn1_set_prefix(asn_bio, Some(ndef_prefix), Some(ndef_prefix_free)) } <= 0
                // SAFETY: as above.
                || unsafe { BIO_asn1_set_suffix(asn_bio, Some(ndef_suffix), Some(ndef_suffix_free)) } <= 0
                // SAFETY: as above; the filter takes the state.
                || unsafe { BIO_ctrl(asn_bio, BIO_C_SET_EX_ARG, 0, ndef.cast()) } <= 0
            {
                break 'err;
            }
            // The filter's suffix free function owns the state from here.
            owned = false;
            let mut sarg = ASN1_STREAM_ARG { out, ndef_bio: ptr::null_mut(), boundary: ptr::null_mut() };
            let mut v = val;
            // SAFETY: the type's callback, with the caller's value and the stream.
            if unsafe { cb(ASN1_OP_STREAM_PRE, &mut v, it, (&raw mut sarg).cast()) } <= 0 {
                break 'err;
            }
            // SAFETY: the state, which the filter keeps.
            let n = unsafe { &mut *ndef };
            n.val = v;
            n.it = it;
            n.ndef_bio = sarg.ndef_bio;
            n.boundary = sarg.boundary;
            n.out = out;
            return sarg.ndef_bio;
        }
        // SAFETY: NULL or the filter, in front of the caller's BIO.
        unsafe { BIO_pop(pop_bio) };
        // SAFETY: NULL or the filter, which frees the state it took.
        unsafe { BIO_free(asn_bio) };
        if owned {
            // SAFETY: the state boxed here, not handed on.
            drop(unsafe { Box::from_raw(ndef) });
        }
        ptr::null_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::tpl::items::ASN1_OCTET_STRING_it;

    /// docs/DEVIATIONS.md: OpenSSL reads a primitive item's functions as aux data; a type that
    /// isn't a SEQUENCE or CHOICE can't be streamed.
    #[test]
    fn primitives_have_no_stream_callback() {
        // SAFETY: no preconditions.
        let it = unsafe { ASN1_OCTET_STRING_it() };
        assert!(stream_callback(it).is_none());
        // SAFETY: as above.
        let p7 = unsafe { crate::pkcs7::PKCS7_it() };
        assert!(stream_callback(p7).is_some());
    }
}
