//! Receipt requests (`cms_ess.c`, RFC 2634): making, encoding, adding, and reading them.

use core::ffi::{c_int, c_uchar};
use core::ptr;

use rustyssl_abi::{
    ASN1_STRING, CMS_ReceiptRequest, CMS_SignerInfo, ERR_LIB_CMS, ERR_R_ASN1_LIB, ERR_R_CMS_LIB,
    NID_id_smime_aa_receiptRequest, OSSL_LIB_CTX, V_ASN1_SEQUENCE, stack_st_GENERAL_NAMES,
};

use super::att::{CMS_signed_add1_attr_by_NID, CMS_signed_get0_data_by_OBJ};
use super::base::{nid_obj, raise};
use super::{CMS_ReceiptRequest_it, ReceiptRequest};
use crate::asn1::string::{ASN1_STRING_set, ASN1_STRING_set0};
use crate::asn1::tpl::items::{d2i, i2d, new_free};
use crate::asn1::tpl::util::ASN1_item_unpack;
use crate::ffi::ffi_export;
use crate::mem;
use crate::rand_lib::RAND_bytes_ex;
use crate::stack::OPENSSL_sk_pop_free;
use crate::x509v3::genn::GENERAL_NAMES_free;

new_free! {
    pub unsafe extern "C" fn CMS_ReceiptRequest_new, pub unsafe extern "C" fn CMS_ReceiptRequest_free(CMS_ReceiptRequest) = CMS_ReceiptRequest_it;
}

i2d! {
    /// Encodes a receipt request.
    pub unsafe extern "C" fn i2d_CMS_ReceiptRequest(CMS_ReceiptRequest) = CMS_ReceiptRequest_it;
}

d2i! {
    /// Decodes a receipt request.
    pub unsafe extern "C" fn d2i_CMS_ReceiptRequest(CMS_ReceiptRequest) = CMS_ReceiptRequest_it;
}

ffi_export! {
    /// The signer's receipt request, decoded into `*prr` (or freed): 1, 0 for none, or -1.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; `prr` NULL or room for a pointer.
    pub unsafe extern "C" fn CMS_get1_ReceiptRequest(si: *mut CMS_SignerInfo, prr: *mut *mut CMS_ReceiptRequest) -> c_int
    where failure = -1, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's room, or NULL.
        if let Some(p) = unsafe { prr.as_mut() } {
            *p = ptr::null_mut();
        }
        let obj = nid_obj(NID_id_smime_aa_receiptRequest);
        // SAFETY: the caller's guarantee; a static object.
        let s = unsafe { CMS_signed_get0_data_by_OBJ(si, obj, -3, V_ASN1_SEQUENCE) }.cast::<ASN1_STRING>();
        if s.is_null() {
            return 0;
        }
        // SAFETY: no preconditions.
        let it = unsafe { super::CMS_ReceiptRequest_it() };
        // SAFETY: the attribute's encoding; the item.
        let rr = unsafe { ASN1_item_unpack(s, it) }.cast::<CMS_ReceiptRequest>();
        if rr.is_null() {
            return -1;
        }
        // SAFETY: as above.
        match unsafe { prr.as_mut() } {
            Some(p) => *p = rr,
            // SAFETY: the request decoded here.
            None => unsafe { CMS_ReceiptRequest_free(rr) },
        }
        1
    }
}

unsafe extern "C" fn names_free(p: *mut core::ffi::c_void) {
    // SAFETY: a list of names of the stack.
    unsafe { GENERAL_NAMES_free(p.cast()) };
}

ffi_export! {
    /// A receipt request for content `id` (32 random octets if NULL), from all or the first
    /// tier (or `receipt_list`), to `receipts_to`; it takes `id` and both lists. NULL on failure.
    ///
    /// # Safety
    /// `id` is NULL or `idlen` octets from CRYPTO_malloc; the lists NULL or live.
    pub unsafe extern "C" fn CMS_ReceiptRequest_create0_ex(id: *mut c_uchar, idlen: c_int, allorfirst: c_int, receipt_list: *mut stack_st_GENERAL_NAMES, receipts_to: *mut stack_st_GENERAL_NAMES, libctx: *mut OSSL_LIB_CTX) -> *mut CMS_ReceiptRequest
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        const F: &str = "CMS_ReceiptRequest_create0_ex";
        // SAFETY: no preconditions.
        let rr = unsafe { CMS_ReceiptRequest_new() };
        // SAFETY: the new request, or NULL.
        let Some(r) = (unsafe { rr.cast::<ReceiptRequest>().as_mut() }) else {
            raise(ERR_R_CMS_LIB, F);
            return ptr::null_mut();
        };
        let ok = 'err: {
            if id.is_null() {
                // SAFETY: the request's string; room for 32 octets.
                if unsafe { ASN1_STRING_set(r.signed_content_identifier.cast(), ptr::null(), 32) } == 0 {
                    raise(ERR_R_ASN1_LIB, F);
                    break 'err false;
                }
                // SAFETY: the request's string, just set.
                let data = unsafe { (*r.signed_content_identifier).data };
                // SAFETY: the string's 32 octets.
                if unsafe { RAND_bytes_ex(libctx, data, 32, 0) } <= 0 {
                    break 'err false;
                }
            } else {
                // SAFETY: the string takes the caller's octets.
                unsafe { ASN1_STRING_set0(r.signed_content_identifier.cast(), id.cast(), idlen) };
            }
            // SAFETY: the request's list, made with it.
            unsafe { OPENSSL_sk_pop_free(r.receipts_to.cast(), Some(names_free)) };
            r.receipts_to = receipts_to.cast();
            // SAFETY: the request's choice, made with it.
            let Some(from) = (unsafe { r.receipts_from.as_mut() }) else { break 'err false };
            if receipt_list.is_null() {
                from.type_ = 0;
                from.d.all_or_first_tier = allorfirst;
            } else {
                from.type_ = 1;
                from.d.receipt_list = receipt_list.cast();
            }
            true
        };
        if ok {
            return rr;
        }
        // SAFETY: the request made here.
        unsafe { CMS_ReceiptRequest_free(rr) };
        ptr::null_mut()
    }
}

ffi_export! {
    /// [`CMS_ReceiptRequest_create0_ex`] in the default library context.
    ///
    /// # Safety
    /// As for [`CMS_ReceiptRequest_create0_ex`].
    pub unsafe extern "C" fn CMS_ReceiptRequest_create0(id: *mut c_uchar, idlen: c_int, allorfirst: c_int, receipt_list: *mut stack_st_GENERAL_NAMES, receipts_to: *mut stack_st_GENERAL_NAMES) -> *mut CMS_ReceiptRequest
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        unsafe { CMS_ReceiptRequest_create0_ex(id, idlen, allorfirst, receipt_list, receipts_to, ptr::null_mut()) }
    }
}

ffi_export! {
    /// Adds the request, encoded, as a signed attribute: 1, or 0.
    ///
    /// # Safety
    /// `si` is NULL or a live signer info; `rr` NULL or live.
    pub unsafe extern "C" fn CMS_add1_ReceiptRequest(si: *mut CMS_SignerInfo, rr: *mut CMS_ReceiptRequest) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        const F: &str = "CMS_add1_ReceiptRequest";
        let mut der: *mut c_uchar = ptr::null_mut();
        // SAFETY: the caller's request; room for the encoding's pointer.
        let n = unsafe { i2d_CMS_ReceiptRequest(rr, &mut der) };
        let r = 'err: {
            if n < 0 {
                raise(ERR_R_CMS_LIB, F);
                break 'err 0;
            }
            // SAFETY: the caller's signer info; the encoding's `n` octets.
            if unsafe { CMS_signed_add1_attr_by_NID(si, NID_id_smime_aa_receiptRequest, V_ASN1_SEQUENCE, der.cast(), n) } == 0 {
                raise(ERR_R_CMS_LIB, F);
                break 'err 0;
            }
            1
        };
        // SAFETY: the encoding, from CRYPTO_malloc, or NULL.
        unsafe { mem::release(der.cast()) };
        r
    }
}

ffi_export! {
    /// The request's values: its content identifier, all-or-first-tier (-1 with a list), the
    /// list of senders, and the recipients of receipts.
    ///
    /// # Safety
    /// `rr` is NULL or live; the others NULL or room for a value.
    pub unsafe extern "C" fn CMS_ReceiptRequest_get0_values(rr: *mut CMS_ReceiptRequest, pcid: *mut *mut ASN1_STRING, pallorfirst: *mut c_int, plist: *mut *mut stack_st_GENERAL_NAMES, prto: *mut *mut stack_st_GENERAL_NAMES)
    where failure = (), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { rr.cast::<ReceiptRequest>().as_ref() }) else { return };
        // SAFETY: the caller's room, or NULL.
        if let Some(p) = unsafe { pcid.as_mut() } {
            *p = r.signed_content_identifier.cast();
        }
        // SAFETY: the request's choice.
        if let Some(from) = unsafe { r.receipts_from.as_ref() } {
            if from.type_ == 0 {
                // SAFETY: as above; the choice's member.
                if let Some(p) = unsafe { pallorfirst.as_mut() } {
                    // SAFETY: the choice's member.
                    *p = unsafe { from.d.all_or_first_tier };
                }
                // SAFETY: as above.
                if let Some(p) = unsafe { plist.as_mut() } {
                    *p = ptr::null_mut();
                }
            } else {
                // SAFETY: as above.
                if let Some(p) = unsafe { pallorfirst.as_mut() } {
                    *p = -1;
                }
                // SAFETY: as above; the choice's member.
                if let Some(p) = unsafe { plist.as_mut() } {
                    // SAFETY: the choice's member.
                    *p = unsafe { from.d.receipt_list }.cast();
                }
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { prto.as_mut() } {
            *p = r.receipts_to.cast();
        }
    }
}
