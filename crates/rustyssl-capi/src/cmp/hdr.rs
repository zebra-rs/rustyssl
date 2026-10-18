//! CMP's PKIHeader (`cmp_hdr.c`): its version, sender and recipient, message time, key IDs,
//! transaction ID and nonces, free text, and general info (implicit confirmation among it).
//!
//! The internal functions' `ossl_assert`s are plain checks: the reference build is NDEBUG, so a
//! failed one raises nothing.

use core::ffi::{CStr, c_int, c_uchar};
use core::ptr;

use rustyssl_abi::{
    ASN1_OCTET_STRING, ASN1_TYPE, ASN1_UTF8STRING, CMP_R_FAILURE_OBTAINING_RANDOM,
    CMP_R_NULL_ARGUMENT, ERR_LIB_CMP, GEN_DIRNAME, GENERAL_NAME, NID_id_it_implicitConfirm,
    NID_undef, OSSL_CMP_CTX, OSSL_CMP_ITAV, OSSL_CMP_LOG_DEBUG, OSSL_CMP_PKIHEADER, OSSL_CMP_PVNO,
    X509_NAME, stack_st_OSSL_CMP_ITAV,
};

use super::asn::{
    Itav, OSSL_CMP_ITAV_create, OSSL_CMP_ITAV_dup, OSSL_CMP_ITAV_free,
    OSSL_CMP_ITAV_push0_stack_item, PkiHeader, SENDERNONCE_LENGTH, Stack, TRANSACTIONID_LENGTH, of,
};
use super::ctx::{Ctx, OSSL_CMP_CTX_set1_senderNonce, ctx_of, print_log};
use super::util::{
    asn1_octet_string_set1, asn1_octet_string_set1_bytes, sk_ASN1_UTF8STRING_push_str,
};
use crate::asn1::integer::{ASN1_INTEGER_get_int64, ASN1_INTEGER_set};
use crate::asn1::string::ASN1_GENERALIZEDTIME_new;
use crate::asn1::time::ASN1_GENERALIZEDTIME_set;
use crate::asn1::tpl::items::{ASN1_NULL_new, ASN1_TYPE_free};
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::{OBJ_nid2obj, OBJ_obj2nid};
use crate::rand_lib::RAND_bytes_ex;
use crate::stack::{OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_value};
use crate::x509::cert::{X509_get_issuer_name, X509_get_subject_name};
use crate::x509::name::X509_NAME_get_entry;
use crate::x509::req::X509_REQ_get_subject_name;
use crate::x509v3::genn::GENERAL_NAME_set1_X509_NAME;
use crate::x509v3::i2s_ASN1_OCTET_STRING;

/// The header behind a handle.
///
/// # Safety
/// `hdr` is NULL or a live header, not otherwise borrowed mutably.
unsafe fn hdr_of<'a>(hdr: *const OSSL_CMP_PKIHEADER) -> Option<&'a mut PkiHeader> {
    // SAFETY: the caller's guarantee.
    unsafe { of::<PkiHeader, _>(hdr) }
}

/// `ossl_cmp_hdr_set_pvno`: 1, or 0.
///
/// # Safety
/// `hdr` is NULL or a live header.
pub(crate) unsafe fn hdr_set_pvno(hdr: *mut OSSL_CMP_PKIHEADER, pvno: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(h) = (unsafe { hdr_of(hdr) }) else {
        return 0;
    };
    // SAFETY: the header's version.
    unsafe { ASN1_INTEGER_set(h.pvno, pvno.into()) }
}

/// `ossl_cmp_hdr_get_pvno`: the version, or -1.
///
/// # Safety
/// `hdr` is NULL or a live header.
pub(crate) unsafe fn hdr_get_pvno(hdr: *const OSSL_CMP_PKIHEADER) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(h) = (unsafe { hdr_of(hdr) }) else {
        return -1;
    };
    let mut pvno = 0i64;
    // SAFETY: the room; the header's version.
    if unsafe { ASN1_INTEGER_get_int64(&raw mut pvno, h.pvno) } == 0 {
        return -1;
    }
    match c_int::try_from(pvno) {
        Ok(v) if v >= 0 => v,
        _ => -1,
    }
}

/// `ossl_cmp_hdr_get_protection_nid`: the protection algorithm's NID, or `NID_undef`.
///
/// # Safety
/// `hdr` is NULL or a live header.
pub(crate) unsafe fn hdr_get_protection_nid(hdr: *const OSSL_CMP_PKIHEADER) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(h) = (unsafe { hdr_of(hdr) }) else {
        return NID_undef;
    };
    // SAFETY: its algorithm, or NULL.
    let Some(alg) = (unsafe { h.protectionAlg.as_ref() }) else {
        return NID_undef;
    };
    // SAFETY: the algorithm's object.
    unsafe { OBJ_obj2nid(alg.algorithm) }
}

ffi_export! {
    /// The header's transaction ID, or NULL (raising for a NULL header).
    ///
    /// # Safety
    /// `hdr` is NULL or a live header.
    pub unsafe extern "C" fn OSSL_CMP_HDR_get0_transactionID(hdr: *const OSSL_CMP_PKIHEADER) -> *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(h) = (unsafe { hdr_of(hdr) }) else {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, "OSSL_CMP_HDR_get0_transactionID");
            return ptr::null_mut();
        };
        h.transactionID
    }
}

ffi_export! {
    /// The header's recipient nonce, or NULL (raising for a NULL header).
    ///
    /// # Safety
    /// `hdr` is NULL or a live header.
    pub unsafe extern "C" fn OSSL_CMP_HDR_get0_recipNonce(hdr: *const OSSL_CMP_PKIHEADER) -> *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(h) = (unsafe { hdr_of(hdr) }) else {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, "OSSL_CMP_HDR_get0_recipNonce");
            return ptr::null_mut();
        };
        h.recipNonce
    }
}

ffi_export! {
    /// The header's general info, or NULL (raising for a NULL header).
    ///
    /// # Safety
    /// `hdr` is NULL or a live header.
    pub unsafe extern "C" fn OSSL_CMP_HDR_get0_geninfo_ITAVs(hdr: *const OSSL_CMP_PKIHEADER) -> *mut stack_st_OSSL_CMP_ITAV
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(h) = (unsafe { hdr_of(hdr) }) else {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, "OSSL_CMP_HDR_get0_geninfo_ITAVs");
            return ptr::null_mut();
        };
        h.generalInfo.cast()
    }
}

/// `IS_NULL_DN`: a name without entries.
///
/// # Safety
/// `name` is a live name.
pub(crate) unsafe fn is_null_dn(name: *const X509_NAME) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { X509_NAME_get_entry(name, 0) }.is_null()
}

/// `ossl_cmp_general_name_is_NULL_DN`: no name, or a directory name without entries.
///
/// # Safety
/// `name` is NULL or a live name.
pub(crate) unsafe fn general_name_is_NULL_DN(name: *const GENERAL_NAME) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(n) = (unsafe { name.as_ref() }) else {
        return 1;
    };
    if n.type_ != GEN_DIRNAME {
        return 0;
    }
    // SAFETY: a directory name's member of the union.
    let dn = unsafe { n.d.directoryName };
    // SAFETY: the name's directory name.
    c_int::from(unsafe { is_null_dn(dn) })
}

/// `ossl_cmp_hdr_set1_sender`: a copy of `nm` (the NULL-DN for NULL) as the sender; 1, or 0.
///
/// # Safety
/// `hdr` is NULL or a live header; `nm` NULL or a live name.
pub(crate) unsafe fn hdr_set1_sender(hdr: *mut OSSL_CMP_PKIHEADER, nm: *const X509_NAME) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(h) = (unsafe { hdr_of(hdr) }) else {
        return 0;
    };
    // SAFETY: the header's slot; the caller's name.
    unsafe { GENERAL_NAME_set1_X509_NAME(&raw mut h.sender, nm) }
}

/// `ossl_cmp_hdr_set1_recipient`: as [`hdr_set1_sender`], for the recipient.
///
/// # Safety
/// As for [`hdr_set1_sender`].
pub(crate) unsafe fn hdr_set1_recipient(
    hdr: *mut OSSL_CMP_PKIHEADER,
    nm: *const X509_NAME,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(h) = (unsafe { hdr_of(hdr) }) else {
        return 0;
    };
    // SAFETY: the header's slot; the caller's name.
    unsafe { GENERAL_NAME_set1_X509_NAME(&raw mut h.recipient, nm) }
}

/// `ossl_cmp_hdr_update_messageTime`: the current time as the message time; 1, or 0.
///
/// # Safety
/// `hdr` is NULL or a live header.
pub(crate) unsafe fn hdr_update_messageTime(hdr: *mut OSSL_CMP_PKIHEADER) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(h) = (unsafe { hdr_of(hdr) }) else {
        return 0;
    };
    if h.messageTime.is_null() {
        // SAFETY: no preconditions.
        h.messageTime = unsafe { ASN1_GENERALIZEDTIME_new() };
        if h.messageTime.is_null() {
            return 0;
        }
    }
    // SAFETY: NULL asks for the time only.
    let now = unsafe { libc::time(ptr::null_mut()) };
    // SAFETY: the header's time.
    c_int::from(!unsafe { ASN1_GENERALIZEDTIME_set(h.messageTime, now) }.is_null())
}

/// `set_random`: `len` random octets into `*tgt`; 1, or 0.
///
/// # Safety
/// `*tgt` is NULL or a live string.
unsafe fn set_random(tgt: &mut *mut ASN1_OCTET_STRING, ctx: &Ctx, len: c_int) -> c_int {
    const F: &str = "set_random";
    let Ok(n) = usize::try_from(len) else {
        err::raise(ERR_LIB_CMP, CMP_R_FAILURE_OBTAINING_RANDOM, F);
        return 0;
    };
    let bytes: *mut c_uchar = mem::alloc(n).cast();
    // SAFETY: the room made here; the context's library context.
    if bytes.is_null() || unsafe { RAND_bytes_ex(ctx.libctx, bytes, n, 0) } <= 0 {
        err::raise(ERR_LIB_CMP, CMP_R_FAILURE_OBTAINING_RANDOM, F);
        // SAFETY: made here, or NULL.
        unsafe { mem::release(bytes.cast()) };
        return 0;
    }
    // SAFETY: the caller's slot; the octets made here.
    let res = unsafe { asn1_octet_string_set1_bytes(tgt, bytes, len) };
    // SAFETY: made here.
    unsafe { mem::release(bytes.cast()) };
    res
}

/// `ossl_cmp_hdr_set1_senderKID`: a copy of `senderKID` (none for NULL); 1, or 0.
///
/// # Safety
/// `hdr` is NULL or a live header; `senderKID` NULL or a live string.
pub(crate) unsafe fn hdr_set1_senderKID(
    hdr: *mut OSSL_CMP_PKIHEADER,
    senderKID: *const ASN1_OCTET_STRING,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(h) = (unsafe { hdr_of(hdr) }) else {
        return 0;
    };
    // SAFETY: the header's slot; the caller's string.
    unsafe { asn1_octet_string_set1(&mut h.senderKID, senderKID) }
}

/// The header's free text, made if need be.
fn free_text(h: &mut PkiHeader) -> *mut Stack {
    if h.freeText.is_null() {
        // SAFETY: no preconditions.
        h.freeText = unsafe { OPENSSL_sk_new_null() };
    }
    h.freeText
}

/// `ossl_cmp_hdr_push1_freeText`: a copy of `text` onto the free text; 1, or 0.
///
/// # Safety
/// As for [`hdr_push0_freeText`].
pub(crate) unsafe fn hdr_push1_freeText(
    hdr: *mut OSSL_CMP_PKIHEADER,
    text: *mut ASN1_UTF8STRING,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(h) = (unsafe { hdr_of(hdr) }) else {
        return 0;
    };
    // SAFETY: the caller's string, or NULL.
    let Some(t) = (unsafe { text.as_ref() }) else {
        return 0;
    };
    let ft = free_text(h);
    if ft.is_null() {
        return 0;
    }
    // SAFETY: the header's list; the string's data and length.
    unsafe { sk_ASN1_UTF8STRING_push_str(ft.cast(), t.data.cast(), t.length) }
}

/// `ossl_cmp_hdr_generalInfo_push0_item`: `itav` (taken) onto the general info; 1, or 0.
///
/// # Safety
/// `hdr` is NULL or a live header; `itav` NULL or a live item.
pub(crate) unsafe fn hdr_generalInfo_push0_item(
    hdr: *mut OSSL_CMP_PKIHEADER,
    itav: *mut OSSL_CMP_ITAV,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(h) = (unsafe { hdr_of(hdr) }) else {
        return 0;
    };
    if itav.is_null() {
        return 0;
    }
    // SAFETY: the header's slot; the caller's item.
    unsafe { OSSL_CMP_ITAV_push0_stack_item((&raw mut h.generalInfo).cast(), itav) }
}

/// `ossl_cmp_hdr_generalInfo_push1_items`: copies of `itavs` onto the general info; 1, or 0.
///
/// # Safety
/// `hdr` is NULL or a live header; `itavs` NULL or a live list of items.
pub(crate) unsafe fn hdr_generalInfo_push1_items(
    hdr: *mut OSSL_CMP_PKIHEADER,
    itavs: *const Stack,
) -> c_int {
    if hdr.is_null() {
        return 0;
    }
    // SAFETY: the caller's list, or NULL (0).
    let n = unsafe { OPENSSL_sk_num(itavs) };
    for i in 0..n {
        // SAFETY: an index in range.
        let item = unsafe { OPENSSL_sk_value(itavs, i) };
        // SAFETY: an item of the list.
        let itav = unsafe { OSSL_CMP_ITAV_dup(item.cast()) };
        if itav.is_null() {
            return 0;
        }
        // SAFETY: the caller's header; the copy, which it takes.
        if unsafe { hdr_generalInfo_push0_item(hdr, itav) } == 0 {
            // SAFETY: the copy, not taken.
            unsafe { OSSL_CMP_ITAV_free(itav) };
            return 0;
        }
    }
    1
}

/// `ossl_cmp_hdr_set_implicitConfirm`: an implicitConfirm item in the general info; 1, or 0.
///
/// # Safety
/// `hdr` is NULL or a live header.
pub(crate) unsafe fn hdr_set_implicitConfirm(hdr: *mut OSSL_CMP_PKIHEADER) -> c_int {
    if hdr.is_null() {
        return 0;
    }
    // SAFETY: no preconditions.
    let asn1null: *mut ASN1_TYPE = unsafe { ASN1_NULL_new() }.cast();
    if asn1null.is_null() {
        return 0;
    }
    // SAFETY: a known NID.
    let obj = unsafe { OBJ_nid2obj(NID_id_it_implicitConfirm) };
    // SAFETY: the static object; the value, which it takes.
    let itav = unsafe { OSSL_CMP_ITAV_create(obj, asn1null) };
    // SAFETY: the caller's header; the item, which it takes on success.
    if !itav.is_null() && unsafe { hdr_generalInfo_push0_item(hdr, itav) } != 0 {
        return 1;
    }
    // As OpenSSL does, the value is freed and then the item holding it: a double free when
    // the push fails. Here the item is freed only when the push failed, after taking its value
    // back, so each is freed once.
    // SAFETY: the item made here, or NULL.
    if let Some(i) = unsafe { of::<Itav, _>(itav) } {
        i.infoValue = ptr::null_mut();
    }
    // SAFETY: the value made here.
    unsafe { ASN1_TYPE_free(asn1null) };
    // SAFETY: the item made here, or NULL.
    unsafe { OSSL_CMP_ITAV_free(itav) };
    0
}

/// `ossl_cmp_hdr_has_implicitConfirm`: 1 if the general info has an implicitConfirm item.
///
/// # Safety
/// `hdr` is NULL or a live header.
pub(crate) unsafe fn hdr_has_implicitConfirm(hdr: *const OSSL_CMP_PKIHEADER) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(h) = (unsafe { hdr_of(hdr) }) else {
        return 0;
    };
    // SAFETY: the header's list, or NULL (0).
    let n = unsafe { OPENSSL_sk_num(h.generalInfo) };
    for i in 0..n {
        // SAFETY: an index in range.
        let itav: *mut Itav = unsafe { OPENSSL_sk_value(h.generalInfo, i) }.cast();
        // SAFETY: an item of the list, or NULL.
        if let Some(it) = unsafe { itav.as_ref() }
            // SAFETY: its type.
            && unsafe { OBJ_obj2nid(it.infoType) } == NID_id_it_implicitConfirm
        {
            return 1;
        }
    }
    0
}

/// `ossl_cmp_hdr_set_transactionID`: the context's transaction ID (a random one made first if
/// there is none) into the header; 1, or 0.
///
/// # Safety
/// `ctx` is a live context; `hdr` a live header.
pub(crate) unsafe fn hdr_set_transactionID(
    ctx: *mut OSSL_CMP_CTX,
    hdr: *mut OSSL_CMP_PKIHEADER,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return 0;
    };
    if c.transactionID.is_null() {
        let mut tid = ptr::null_mut();
        // SAFETY: a fresh slot.
        if unsafe { set_random(&mut tid, c, TRANSACTIONID_LENGTH) } == 0 {
            return 0;
        }
        c.transactionID = tid;
        // SAFETY: the new ID.
        let text = unsafe { i2s_ASN1_OCTET_STRING(ptr::null_mut(), tid) };
        if !text.is_null() {
            // SAFETY: the NUL-terminated text made above.
            let s = unsafe { CStr::from_ptr(text) }
                .to_string_lossy()
                .into_owned();
            let msg = format!("Starting new transaction with ID={s}");
            // SAFETY: the caller's context.
            unsafe {
                print_log(
                    OSSL_CMP_LOG_DEBUG,
                    ctx,
                    c"ossl_cmp_hdr_set_transactionID",
                    &msg,
                )
            };
        }
        // SAFETY: made above, or NULL.
        unsafe { mem::release(text.cast()) };
    }
    // SAFETY: the caller's guarantee, looked up again after the log callback.
    let c = unsafe { ctx_of(ctx) };
    // SAFETY: the caller's header.
    let h = unsafe { hdr_of(hdr) };
    let (Some(c), Some(h)) = (c, h) else {
        return 0;
    };
    // SAFETY: the header's slot; the context's ID.
    unsafe { asn1_octet_string_set1(&mut h.transactionID, c.transactionID) }
}

/// `ossl_cmp_hdr_init`: every field of the header from the context; 1, or 0.
///
/// # Safety
/// `ctx` is NULL or a live context; `hdr` NULL or a live header.
pub(crate) unsafe fn hdr_init(ctx: *mut OSSL_CMP_CTX, hdr: *mut OSSL_CMP_PKIHEADER) -> c_int {
    if ctx.is_null() || hdr.is_null() {
        return 0;
    }
    // SAFETY: the caller's header.
    if unsafe { hdr_set_pvno(hdr, OSSL_CMP_PVNO) } == 0 {
        return 0;
    }
    // SAFETY: the caller's context.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return 0;
    };
    // The sender: the protection certificate's subject, else the old certificate's, else the
    // CSR's, else the subject name (the NULL-DN when that's NULL too).
    let sender = if !c.cert.is_null() {
        // SAFETY: the context's certificate.
        unsafe { X509_get_subject_name(c.cert) }
    } else if !c.oldCert.is_null() {
        // SAFETY: the context's old certificate.
        unsafe { X509_get_subject_name(c.oldCert) }
    } else if !c.p10CSR.is_null() {
        // SAFETY: the context's CSR.
        unsafe { X509_REQ_get_subject_name(c.p10CSR) }
    } else {
        c.subjectName
    };
    // SAFETY: the caller's header; a live name, or NULL.
    if unsafe { hdr_set1_sender(hdr, sender) } == 0 {
        return 0;
    }
    let rcp: *const X509_NAME = if !c.recipient.is_null() {
        c.recipient
    } else if !c.srvCert.is_null() {
        // SAFETY: the context's server certificate.
        unsafe { X509_get_subject_name(c.srvCert) }
    } else if !c.issuer.is_null() {
        c.issuer
    } else if !c.oldCert.is_null() {
        // SAFETY: the context's old certificate.
        unsafe { X509_get_issuer_name(c.oldCert) }
    } else if !c.cert.is_null() {
        // SAFETY: the context's certificate.
        unsafe { X509_get_issuer_name(c.cert) }
    } else {
        ptr::null()
    };
    // SAFETY: as above.
    if unsafe { hdr_set1_recipient(hdr, rcp) } == 0 {
        return 0;
    }
    // SAFETY: the caller's header.
    if unsafe { hdr_update_messageTime(hdr) } == 0 {
        return 0;
    }
    if !c.recipNonce.is_null() {
        // SAFETY: the caller's header.
        let Some(h) = (unsafe { hdr_of(hdr) }) else {
            return 0;
        };
        // SAFETY: the header's slot; the context's nonce.
        if unsafe { asn1_octet_string_set1(&mut h.recipNonce, c.recipNonce) } == 0 {
            return 0;
        }
    }
    // SAFETY: the caller's context and header.
    if unsafe { hdr_set_transactionID(ctx, hdr) } == 0 {
        return 0;
    }
    // SAFETY: the caller's context and header, looked up again after the log callback.
    let c = unsafe { ctx_of(ctx) };
    // SAFETY: the caller's header.
    let h = unsafe { hdr_of(hdr) };
    let (Some(c), Some(h)) = (c, h) else {
        return 0;
    };
    // SAFETY: the header's slot.
    if unsafe { set_random(&mut h.senderNonce, c, SENDERNONCE_LENGTH) } == 0 {
        return 0;
    }
    // SAFETY: the caller's context; the header's nonce.
    if unsafe { OSSL_CMP_CTX_set1_senderNonce(ctx, h.senderNonce) } == 0 {
        return 0;
    }
    // SAFETY: the caller's context.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return 0;
    };
    // SAFETY: the caller's header; the context's text.
    if !c.freeText.is_null() && unsafe { hdr_push1_freeText(hdr, c.freeText) } == 0 {
        return 0;
    }
    1
}
