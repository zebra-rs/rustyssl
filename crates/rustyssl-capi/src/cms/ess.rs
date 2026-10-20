//! Receipt requests (`cms_ess.c`, RFC 2634): making, encoding, adding, and reading them.

use core::ffi::{c_int, c_uchar, c_uint};
use core::ptr;

use rustyssl_abi::{
    ASN1_OBJECT, ASN1_OCTET_STRING, ASN1_STRING, CMS_ContentInfo, CMS_R_CONTENT_TYPE_MISMATCH,
    CMS_R_CONTENTIDENTIFIER_MISMATCH, CMS_R_MSGSIGDIGEST_ERROR,
    CMS_R_MSGSIGDIGEST_VERIFICATION_FAILURE, CMS_R_MSGSIGDIGEST_WRONG_LENGTH,
    CMS_R_NEED_ONE_SIGNER, CMS_R_NO_CONTENT, CMS_R_NO_CONTENT_TYPE, CMS_R_NO_MATCHING_SIGNATURE,
    CMS_R_NO_MSGSIGDIGEST, CMS_R_NO_RECEIPT_REQUEST, CMS_R_NOT_A_SIGNED_RECEIPT,
    CMS_R_RECEIPT_DECODE_ERROR, CMS_ReceiptRequest, CMS_SignerInfo, ERR_LIB_CMS, ERR_R_ASN1_LIB,
    ERR_R_CMS_LIB, EVP_MAX_MD_SIZE, NID_id_smime_aa_msgSigDigest, NID_id_smime_aa_receiptRequest,
    NID_id_smime_aa_signingCertificate, NID_id_smime_aa_signingCertificateV2,
    NID_id_smime_ct_receipt, NID_pkcs9_contentType, OSSL_LIB_CTX, V_ASN1_OBJECT,
    V_ASN1_OCTET_STRING, V_ASN1_SEQUENCE, stack_st_GENERAL_NAMES, stack_st_X509,
};

use super::att::{CMS_signed_add1_attr_by_NID, CMS_signed_get0_data_by_OBJ};
use super::base::{nid_obj, raise};
use super::{CMS_ReceiptRequest_it, Receipt, ReceiptRequest, SignerInfo, Stack, sk_get};
use crate::asn1::string::ASN1_STRING_cmp;
use crate::asn1::string::{ASN1_STRING_set, ASN1_STRING_set0};
use crate::asn1::tpl::free::ASN1_item_free;
use crate::asn1::tpl::items::{d2i, i2d, new_free};
use crate::asn1::tpl::util::ASN1_item_unpack;
use crate::asn1::tpl::util::{ASN1_item_pack, item_digest_ex};
use crate::evp::legacy_md::EVP_get_digestbyname;
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::{OBJ_cmp, OBJ_nid2sn, OBJ_obj2nid};
use crate::rand_lib::RAND_bytes_ex;
use crate::stack::OPENSSL_sk_num;
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

/// `ossl_cms_signerinfo_get_signing_cert(_v2)`: the signer's ESS signing-certificate
/// attribute, decoded: 1, 0 for none, or -1.
///
/// # Safety
/// `si` is a live signer info.
unsafe fn signing_cert(
    si: *const CMS_SignerInfo,
    v2: bool,
    out: &mut *mut core::ffi::c_void,
) -> c_int {
    *out = ptr::null_mut();
    let nid = if v2 {
        NID_id_smime_aa_signingCertificateV2
    } else {
        NID_id_smime_aa_signingCertificate
    };
    // SAFETY: the caller's guarantee; a static object.
    let s = unsafe { CMS_signed_get0_data_by_OBJ(si, nid_obj(nid), -3, V_ASN1_SEQUENCE) }
        .cast::<ASN1_STRING>();
    if s.is_null() {
        return 0;
    }
    let it = if v2 {
        // SAFETY: no preconditions.
        unsafe { crate::ess::ESS_SIGNING_CERT_V2_it() }
    } else {
        // SAFETY: no preconditions.
        unsafe { crate::ess::ESS_SIGNING_CERT_it() }
    };
    // SAFETY: the attribute's encoding; the item.
    let v = unsafe { ASN1_item_unpack(s, it) };
    if v.is_null() {
        return -1;
    }
    *out = v.cast();
    1
}

/// `ossl_cms_check_signing_certs`: the signer's ESS signing-certificate attributes checked
/// against its verified chain (one is required).
///
/// # Safety
/// `si` is a live signer info; `chain` NULL or a live list.
pub(crate) unsafe fn check_signing_certs(
    si: *const CMS_SignerInfo,
    chain: *const stack_st_X509,
) -> bool {
    use crate::ess::{
        ESS_SIGNING_CERT_V2_free, ESS_SIGNING_CERT_free, OSSL_ESS_check_signing_certs,
    };
    let mut ss = ptr::null_mut();
    let mut ssv2 = ptr::null_mut();
    // SAFETY: the caller's guarantee.
    let ret = unsafe { signing_cert(si, false, &mut ss) } >= 0
        // SAFETY: as above.
        && unsafe { signing_cert(si, true, &mut ssv2) } >= 0
        // SAFETY: the attributes decoded, or NULL; the caller's chain.
        && unsafe { OSSL_ESS_check_signing_certs(ss.cast(), ssv2.cast(), chain, 1) } > 0;
    // SAFETY: the values decoded here, or NULL.
    unsafe { ESS_SIGNING_CERT_free(ss.cast()) };
    // SAFETY: as above.
    unsafe { ESS_SIGNING_CERT_V2_free(ssv2.cast()) };
    ret
}

/// `cms_msgSigDigest`: the digest of the signer's signed attributes (as received) with its
/// digest algorithm.
///
/// # Safety
/// `si` is a live signer info.
unsafe fn msg_sig_digest(
    si: &SignerInfo,
    dig: &mut [u8; EVP_MAX_MD_SIZE as usize],
    diglen: &mut c_uint,
) -> bool {
    // SAFETY: the signer's algorithm, live with it.
    let obj =
        unsafe { si.digest_algorithm.as_ref() }.map_or(ptr::null(), |a| a.algorithm.cast_const());
    // SAFETY: the object, or NULL.
    let nid = unsafe { OBJ_obj2nid(obj) };
    // SAFETY: any NID.
    let sn = unsafe { OBJ_nid2sn(nid) };
    // SAFETY: NULL or a static name.
    let md = unsafe { EVP_get_digestbyname(sn) };
    if md.is_null() {
        return false;
    }
    // SAFETY: no preconditions.
    let it = unsafe { super::attributes_verify_it() };
    // The digest is fetched in the signer's library context, with its properties.
    // SAFETY: NULL or the signer's object's context, live with it.
    let (libctx, propq) = unsafe { si.cms_ctx.as_ref() }
        .map_or((ptr::null_mut(), ptr::null()), |c| {
            (c.libctx, c.propq.cast_const())
        });
    // SAFETY: the item; a live digest; the signer's attributes; room for any digest; the
    // context and properties.
    unsafe {
        item_digest_ex(
            it,
            md,
            si.signed_attrs.cast(),
            dig.as_mut_ptr(),
            diglen,
            libctx,
            propq,
        ) != 0
    }
}

/// `ossl_cms_msgSigDigest_add1`: the digest of `src`'s signed attributes as `dest`'s
/// msgSigDigest attribute.
///
/// # Safety
/// `dest` and `src` are live signer infos.
pub(crate) unsafe fn msg_sig_digest_add1(dest: *mut CMS_SignerInfo, src: &SignerInfo) -> bool {
    let mut dig = [0u8; EVP_MAX_MD_SIZE as usize];
    let mut diglen: c_uint = 0;
    // SAFETY: the caller's guarantee.
    if !unsafe { msg_sig_digest(src, &mut dig, &mut diglen) } {
        raise(CMS_R_MSGSIGDIGEST_ERROR, "ossl_cms_msgSigDigest_add1");
        return false;
    }
    let n = c_int::try_from(diglen).unwrap_or(0);
    // SAFETY: as above; the digest's octets.
    if unsafe {
        CMS_signed_add1_attr_by_NID(
            dest,
            NID_id_smime_aa_msgSigDigest,
            V_ASN1_OCTET_STRING,
            dig.as_ptr().cast(),
            n,
        )
    } == 0
    {
        raise(ERR_R_CMS_LIB, "ossl_cms_msgSigDigest_add1");
        return false;
    }
    true
}

/// `ossl_cms_Receipt_verify`: a signed receipt checked against the request it answers.
///
/// # Safety
/// `cms` and `req_cms` are live objects.
pub(crate) unsafe fn receipt_verify(
    cms: *mut CMS_ContentInfo,
    req_cms: *mut CMS_ContentInfo,
) -> c_int {
    const F: &str = "ossl_cms_Receipt_verify";
    // SAFETY: no preconditions.
    let rct_it = unsafe { super::receipt_it() };
    let mut rr: *mut CMS_ReceiptRequest = ptr::null_mut();
    let mut rct: *mut Receipt = ptr::null_mut();
    let r = 'err: {
        // SAFETY: the caller's objects.
        let osis = unsafe { super::base::CMS_get0_SignerInfos(req_cms) }.cast::<Stack>();
        // SAFETY: as above.
        let sis = unsafe { super::base::CMS_get0_SignerInfos(cms) }.cast::<Stack>();
        if osis.is_null() || sis.is_null() {
            break 'err 0;
        }
        // SAFETY: a live list.
        if unsafe { OPENSSL_sk_num(sis.cast()) } != 1 {
            raise(CMS_R_NEED_ONE_SIGNER, F);
            break 'err 0;
        }
        // SAFETY: a live object.
        let etype = unsafe { super::base::CMS_get0_eContentType(cms) };
        // SAFETY: its type, or NULL.
        if unsafe { OBJ_obj2nid(etype) } != NID_id_smime_ct_receipt {
            raise(CMS_R_NOT_A_SIGNED_RECEIPT, F);
            break 'err 0;
        }
        // SAFETY: as above.
        let pcont = unsafe { super::base::CMS_get0_content(cms) };
        // SAFETY: NULL or the content's slot.
        let Some(&cont) = (unsafe { pcont.as_ref() }).filter(|c| !c.is_null()) else {
            raise(CMS_R_NO_CONTENT, F);
            break 'err 0;
        };
        // SAFETY: the content; the receipt's item.
        rct = unsafe { ASN1_item_unpack(cont.cast(), rct_it) }.cast();
        // SAFETY: the receipt decoded, or NULL.
        let Some(receipt) = (unsafe { rct.as_ref() }) else {
            raise(CMS_R_RECEIPT_DECODE_ERROR, F);
            break 'err 0;
        };
        // SAFETY: the request's signer infos.
        let n = unsafe { OPENSSL_sk_num(osis.cast()) };
        let osi = (0..n).find_map(|i| {
            // SAFETY: an index within them.
            let o = unsafe { sk_get::<SignerInfo>(osis, i) }?;
            // SAFETY: live strings.
            (unsafe {
                ASN1_STRING_cmp(
                    o.signature.cast(),
                    receipt.originator_signature_value.cast(),
                )
            } == 0)
                .then_some(o)
        });
        let Some(osi) = osi else {
            raise(CMS_R_NO_MATCHING_SIGNATURE, F);
            break 'err 0;
        };
        // SAFETY: the receipt's only signer.
        let si = unsafe { crate::stack::OPENSSL_sk_value(sis.cast(), 0) }.cast::<CMS_SignerInfo>();
        let msd_obj = nid_obj(NID_id_smime_aa_msgSigDigest);
        // SAFETY: the signer info; a static object.
        let msig = unsafe { CMS_signed_get0_data_by_OBJ(si, msd_obj, -3, V_ASN1_OCTET_STRING) }
            .cast::<ASN1_OCTET_STRING>();
        if msig.is_null() {
            raise(CMS_R_NO_MSGSIGDIGEST, F);
            break 'err 0;
        }
        let mut dig = [0u8; EVP_MAX_MD_SIZE as usize];
        let mut diglen: c_uint = 0;
        // SAFETY: the request's signer.
        if !unsafe { msg_sig_digest(osi, &mut dig, &mut diglen) } {
            raise(CMS_R_MSGSIGDIGEST_ERROR, F);
            break 'err 0;
        }
        // SAFETY: the attribute's string.
        let got = unsafe { super::base::octets(msig) };
        let computed = dig
            .get(..usize::try_from(diglen).unwrap_or(0))
            .unwrap_or_default();
        if got.len() != computed.len() {
            raise(CMS_R_MSGSIGDIGEST_WRONG_LENGTH, F);
            break 'err 0;
        }
        // SAFETY: two buffers of `computed.len()` octets.
        if unsafe {
            crate::mem::CRYPTO_memcmp(
                got.as_ptr().cast(),
                computed.as_ptr().cast(),
                computed.len(),
            )
        } != 0
        {
            raise(CMS_R_MSGSIGDIGEST_VERIFICATION_FAILURE, F);
            break 'err 0;
        }
        let osi_c: *mut CMS_SignerInfo = core::ptr::from_ref(osi).cast_mut().cast();
        let ct_obj = nid_obj(NID_pkcs9_contentType);
        // SAFETY: the request's signer; a static object.
        let octype = unsafe { CMS_signed_get0_data_by_OBJ(osi_c, ct_obj, -3, V_ASN1_OBJECT) }
            .cast::<ASN1_OBJECT>();
        if octype.is_null() {
            raise(CMS_R_NO_CONTENT_TYPE, F);
            break 'err 0;
        }
        // SAFETY: live objects.
        if unsafe { OBJ_cmp(octype, receipt.content_type) } != 0 {
            raise(CMS_R_CONTENT_TYPE_MISMATCH, F);
            break 'err 0;
        }
        // SAFETY: the request's signer; room for the request.
        if unsafe { CMS_get1_ReceiptRequest(osi_c, &mut rr) } <= 0 {
            raise(CMS_R_NO_RECEIPT_REQUEST, F);
            break 'err 0;
        }
        // SAFETY: the request decoded.
        let req = unsafe { &*rr.cast::<ReceiptRequest>() };
        // SAFETY: live strings.
        if unsafe {
            ASN1_STRING_cmp(
                req.signed_content_identifier.cast(),
                receipt.signed_content_identifier.cast(),
            )
        } != 0
        {
            raise(CMS_R_CONTENTIDENTIFIER_MISMATCH, F);
            break 'err 0;
        }
        1
    };
    // SAFETY: the values decoded here, or NULL.
    unsafe { CMS_ReceiptRequest_free(rr) };
    // SAFETY: as above.
    unsafe { ASN1_item_free(rct.cast(), rct_it) };
    r
}

/// `ossl_cms_encode_Receipt`: the receipt answering the signer's request, encoded, or NULL.
///
/// # Safety
/// `si` is a live signer info.
pub(crate) unsafe fn encode_receipt(si: *mut CMS_SignerInfo) -> *mut ASN1_OCTET_STRING {
    const F: &str = "ossl_cms_encode_Receipt";
    let mut rr: *mut CMS_ReceiptRequest = ptr::null_mut();
    let os = 'err: {
        // SAFETY: the caller's guarantee; room for the request.
        if unsafe { CMS_get1_ReceiptRequest(si, &mut rr) } <= 0 {
            raise(CMS_R_NO_RECEIPT_REQUEST, F);
            break 'err ptr::null_mut();
        }
        let ct_obj = nid_obj(NID_pkcs9_contentType);
        // SAFETY: as above; a static object.
        let ctype = unsafe { CMS_signed_get0_data_by_OBJ(si, ct_obj, -3, V_ASN1_OBJECT) }
            .cast::<ASN1_OBJECT>();
        if ctype.is_null() {
            raise(CMS_R_NO_CONTENT_TYPE, F);
            break 'err ptr::null_mut();
        }
        // SAFETY: the request decoded.
        let req = unsafe { &*rr.cast::<ReceiptRequest>() };
        // SAFETY: the caller's signer info.
        let s = unsafe { &*si.cast::<SignerInfo>() };
        let rct = Receipt {
            version: 1,
            content_type: ctype,
            signed_content_identifier: req.signed_content_identifier,
            originator_signature_value: s.signature,
        };
        // SAFETY: no preconditions.
        let it = unsafe { super::receipt_it() };
        // SAFETY: a local value of the item.
        unsafe { ASN1_item_pack((&raw const rct).cast_mut().cast(), it, ptr::null_mut()) }.cast()
    };
    // SAFETY: the request decoded here, or NULL.
    unsafe { CMS_ReceiptRequest_free(rr) };
    os
}
