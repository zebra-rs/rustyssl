//! The CMS library (`cms_lib.c`): objects, their content and its type, certificates and CRLs,
//! the data path's dispatch, and the identifiers shared by signers and recipients.

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_OBJECT, ASN1_OCTET_STRING, ASN1_PCTX, ASN1_STRING_FLAG_CONT, BIO, BIO_C_GET_MD_CTX,
    BIO_C_SET_BUF_MEM_EOF_RETURN, BIO_C_SET_MD, BIO_CTRL_INFO, BIO_TYPE_MD, BIO_TYPE_MEM,
    CMS_CertificateChoices, CMS_ContentInfo, CMS_EnvelopedData, CMS_R_CERTIFICATE_HAS_NO_KEYID,
    CMS_R_CONTENT_NOT_FOUND, CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA,
    CMS_R_CONTENT_TYPE_NOT_SIGNED_DATA, CMS_R_MD_BIO_INIT_ERROR, CMS_R_NO_CONTENT,
    CMS_R_NO_MATCHING_DIGEST, CMS_R_UNKNOWN_DIGEST_ALGORITHM, CMS_R_UNSUPPORTED_CONTENT_TYPE,
    CMS_R_UNSUPPORTED_TYPE, CMS_RECIPINFO_AGREE, CMS_RECIPINFO_KEK, CMS_RECIPINFO_PASS,
    CMS_RECIPINFO_TRANS, CMS_RevocationInfoChoice, ERR_LIB_CMS, ERR_R_ASN1_LIB,
    ERR_R_PASSED_NULL_PARAMETER, ERR_R_X509_LIB, EVP_MD, EVP_MD_CTX, NID_id_smime_ct_authData,
    NID_id_smime_ct_authEnvelopedData, NID_id_smime_ct_compressedData, NID_pkcs7_data,
    NID_pkcs7_digest, NID_pkcs7_encrypted, NID_pkcs7_enveloped, NID_pkcs7_signed, NID_undef,
    OSSL_DIGEST_PARAM_XOFLEN, OSSL_LIB_CTX, OSSL_PARAM, SN_shake128, SN_shake256,
    V_ASN1_OCTET_STRING, X509, X509_ADD_FLAG_UP_REF, X509_ALGOR, X509_CRL, stack_st_X509,
    stack_st_X509_CRL,
};

use super::{
    CERTCHOICE_CERT, CertificateChoices, CmsCtx, ContentInfo, IssuerAndSerialNumber,
    KekRecipientInfo, KeyAgreeRecipientInfo, KeyTransRecipientInfo, PasswordRecipientInfo,
    REVCHOICE_CRL, RecipientInfo, RevocationInfoChoice, SignerInfo, Stack, enc, ias_it,
};
use crate::asn1::integer::ASN1_INTEGER_cmp;
use crate::asn1::string::{
    ASN1_OCTET_STRING_cmp, ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_STRING_copy,
    ASN1_STRING_dup, ASN1_STRING_set,
};
use crate::asn1::tpl::decode::ASN1_item_d2i_ex;
use crate::asn1::tpl::encode::ASN1_item_i2d;
use crate::asn1::tpl::free::ASN1_item_free;
use crate::asn1::tpl::new::{ASN1_item_new, ASN1_item_new_ex};
use crate::asn1::tpl::print::ASN1_item_print;
use crate::asn1::tpl::util::ASN1_item_dup;
use crate::bio::evp::BIO_f_md;
use crate::bio::mem::BIO_new_mem_buf;
use crate::bio::mem::BIO_s_mem;
use crate::bio::null::BIO_s_null;
use crate::bio::{BIO_ctrl, BIO_find_type, BIO_free, BIO_new, BIO_next, BIO_push};
use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::digest::{
    EVP_MD_fetch, EVP_MD_free, EVP_MD_get_pkey_type, EVP_MD_get_type, EVP_MD_is_a,
};
use crate::evp::legacy_md::EVP_get_digestbyname;
use crate::evp::md_ctx::{
    EVP_MD_CTX_copy_ex, EVP_MD_CTX_get0_md, EVP_MD_CTX_set_params, EVP_MD_xof,
};
use crate::ffi::ffi_export;
use crate::objects::{
    ASN1_OBJECT_free, OBJ_dup, OBJ_nid2obj, OBJ_nid2sn, OBJ_obj2nid, OBJ_obj2txt,
};
use crate::params::{OSSL_PARAM_construct_end, OSSL_PARAM_construct_size_t};
use crate::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_new_reserve, OPENSSL_sk_num,
    OPENSSL_sk_pop_free, OPENSSL_sk_push,
};
use crate::string::CRYPTO_strdup;
use crate::x509::cert::{
    OSSL_STACK_OF_X509_free, X509_free, X509_get_issuer_name, X509_get0_serialNumber, X509_up_ref,
    cert_of, set0_libctx,
};
use crate::x509::crl::{X509_CRL_free, X509_CRL_up_ref};
use crate::x509::name::{X509_NAME_cmp, X509_NAME_set};
use crate::x509::purpose::{X509_add_cert, X509_cmp, X509_get0_subject_key_id};

pub(super) fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_CMS, reason, f);
}

/// `OSSL_MAX_NAME_SIZE`, the room for an algorithm's name.
const NAME_LEN: usize = 50;

/// The object behind a pointer.
///
/// # Safety
/// `cms` is NULL or a live CMS object.
pub(crate) unsafe fn cms_of<'a>(cms: *const CMS_ContentInfo) -> Option<&'a mut ContentInfo> {
    // SAFETY: the caller's guarantee.
    unsafe { cms.cast::<ContentInfo>().cast_mut().as_mut() }
}

/// The NID of the object's content type (`NID_undef` for NULL).
pub(crate) fn type_nid(cms: *const CMS_ContentInfo) -> c_int {
    // SAFETY: NULL or a live object.
    unsafe { cms.cast::<ContentInfo>().as_ref() }.map_or(NID_undef, |c| {
        // SAFETY: its type, or NULL.
        unsafe { OBJ_obj2nid(c.content_type) }
    })
}

/// The content of the object's type, as `T`: `d`'s pointer.
///
/// # Safety
/// `cms` is NULL or a live object whose content is a `T`, NULL or live.
pub(crate) unsafe fn content<'a, T>(cms: *const CMS_ContentInfo) -> Option<&'a mut T> {
    // SAFETY: the caller's guarantee.
    let c = unsafe { cms.cast::<ContentInfo>().as_ref() }?;
    // SAFETY: as above.
    unsafe { c.d.cast::<T>().as_mut() }
}

/// The content as a `T`, for callers that have checked the object's type.
fn typed<'a, T>(cms: *const CMS_ContentInfo) -> Option<&'a mut T> {
    // SAFETY: NULL or a live object whose content, of the type its callers checked, is NULL or
    // live.
    unsafe { content::<T>(cms) }
}

/// An enveloped content's originator info.
fn originator<'a>(o: *mut super::OriginatorInfo) -> Option<&'a mut super::OriginatorInfo> {
    // SAFETY: NULL or the content's originator info.
    unsafe { o.as_mut() }
}

/// `ossl_cms_get0_cmsctx`.
pub(crate) fn ctx_of(cms: *const CMS_ContentInfo) -> *const CmsCtx {
    if cms.is_null() {
        return ptr::null();
    }
    // SAFETY: a live object's field.
    unsafe { &raw const (*cms.cast::<ContentInfo>()).ctx }
}

/// `ossl_cms_ctx_get0_libctx` and `_propq`.
pub(crate) fn ctx_parts(ctx: *const CmsCtx) -> (*mut OSSL_LIB_CTX, *const c_char) {
    // SAFETY: NULL or a live context.
    unsafe { ctx.as_ref() }.map_or((ptr::null_mut(), ptr::null()), |c| {
        (c.libctx, c.propq.cast_const())
    })
}

/// The libctx and properties held by `*a`'s object, if any.
///
/// # Safety
/// `a` is NULL or holds NULL or a live object.
pub(crate) unsafe fn held_ctx(a: *mut *mut CMS_ContentInfo) -> (*mut OSSL_LIB_CTX, *const c_char) {
    // SAFETY: the caller's guarantee.
    let held = unsafe { a.as_ref() }.map_or(ptr::null_mut(), |p| *p);
    ctx_parts(ctx_of(held))
}

ffi_export! {
    /// Decodes a CMS object, in `*a`'s library context if it holds one.
    ///
    /// # Safety
    /// As for `d2i_*`.
    pub unsafe extern "C" fn d2i_CMS_ContentInfo(a: *mut *mut CMS_ContentInfo, in_: *mut *const c_uchar, len: core::ffi::c_long) -> *mut CMS_ContentInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let (libctx, propq) = unsafe { held_ctx(a) };
        // SAFETY: no preconditions.
        let it = unsafe { super::CMS_ContentInfo_it() };
        // SAFETY: the caller's guarantee; the type's item.
        let ci = unsafe { ASN1_item_d2i_ex(a.cast(), in_, len, it, libctx, propq) }.cast::<CMS_ContentInfo>();
        if !ci.is_null() {
            // SAFETY: the object decoded.
            unsafe { resolve_libctx_marked(ci) };
        }
        ci
    }
}

ffi_export! {
    /// Encodes a CMS object.
    ///
    /// # Safety
    /// As for `i2d_*`.
    pub unsafe extern "C" fn i2d_CMS_ContentInfo(a: *const CMS_ContentInfo, out: *mut *mut c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_CMS
    {
        // SAFETY: no preconditions.
        let it = unsafe { super::CMS_ContentInfo_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d(a.cast(), out, it) }
    }
}

ffi_export! {
    /// A new, empty CMS object, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn CMS_ContentInfo_new() -> *mut CMS_ContentInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: as above.
        unsafe { CMS_ContentInfo_new_ex(ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// A new, empty CMS object in `libctx` with `propq`, or NULL.
    ///
    /// # Safety
    /// `libctx` is NULL or live; `propq` NULL or a C string.
    pub unsafe extern "C" fn CMS_ContentInfo_new_ex(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut CMS_ContentInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: no preconditions.
        let it = unsafe { super::CMS_ContentInfo_it() };
        // SAFETY: the type's item; the caller's context.
        let ci = unsafe { ASN1_item_new_ex(it, libctx, propq) }.cast::<CMS_ContentInfo>();
        // SAFETY: the new object.
        let Some(c) = (unsafe { cms_of(ci) }) else { return ptr::null_mut() };
        c.ctx.libctx = libctx;
        c.ctx.propq = ptr::null_mut();
        if !propq.is_null() {
            // SAFETY: the caller's string.
            c.ctx.propq = unsafe { CRYPTO_strdup(propq, c"cms_lib.c".as_ptr(), 0) };
            if c.ctx.propq.is_null() {
                // SAFETY: the object made here.
                unsafe { CMS_ContentInfo_free(ci) };
                return ptr::null_mut();
            }
        }
        ci
    }
}

ffi_export! {
    /// Frees a CMS object (NULL is a no-op).
    ///
    /// # Safety
    /// `cms` is NULL or a live object, not used afterwards.
    pub unsafe extern "C" fn CMS_ContentInfo_free(cms: *mut CMS_ContentInfo)
    where failure = (), library = ERR_LIB_CMS
    {
        // SAFETY: no preconditions.
        let it = unsafe { super::CMS_ContentInfo_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_free(cms.cast(), it) };
    }
}

ffi_export! {
    /// Prints the object's structure.
    ///
    /// # Safety
    /// `out` is a live BIO; `x` NULL or a live object; `pctx` NULL or live.
    pub unsafe extern "C" fn CMS_ContentInfo_print_ctx(out: *mut BIO, x: *const CMS_ContentInfo, indent: c_int, pctx: *const ASN1_PCTX) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: no preconditions.
        let it = unsafe { super::CMS_ContentInfo_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_print(out, x.cast(), indent, it, pctx) }
    }
}

ffi_export! {
    /// A copy of EnvelopedData, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or live.
    pub unsafe extern "C" fn CMS_EnvelopedData_dup(a: *const CMS_EnvelopedData) -> *mut CMS_EnvelopedData
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: no preconditions.
        let it = unsafe { super::CMS_EnvelopedData_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_dup(it, a.cast()) }.cast()
    }
}

/// The signer infos of SignedData, or NULL (with no error).
pub(crate) fn signer_infos(cms: *const CMS_ContentInfo) -> *mut Stack {
    if type_nid(cms) != NID_pkcs7_signed {
        return ptr::null_mut();
    }
    // SAFETY: the content of its type.
    unsafe { content::<super::SignedData>(cms) }.map_or(ptr::null_mut(), |s| s.signer_infos)
}

/// The recipient infos of (Auth)EnvelopedData, or NULL (with no error).
pub(crate) fn recipient_infos(cms: *const CMS_ContentInfo) -> *mut Stack {
    match type_nid(cms) {
        // SAFETY: the content of its type.
        n if n == NID_pkcs7_enveloped => {
            typed::<super::EnvelopedData>(cms).map_or(ptr::null_mut(), |e| e.recipient_infos)
        }
        // SAFETY: as above.
        n if n == NID_id_smime_ct_authEnvelopedData => {
            typed::<super::AuthEnvelopedData>(cms).map_or(ptr::null_mut(), |e| e.recipient_infos)
        }
        _ => ptr::null_mut(),
    }
}

ffi_export! {
    /// SignedData's signer infos, or NULL (`CMS_R_CONTENT_TYPE_NOT_SIGNED_DATA`).
    ///
    /// # Safety
    /// `cms` is NULL or a live object.
    pub unsafe extern "C" fn CMS_get0_SignerInfos(cms: *mut CMS_ContentInfo) -> *mut rustyssl_abi::stack_st_CMS_SignerInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        if type_nid(cms) != NID_pkcs7_signed {
            raise(CMS_R_CONTENT_TYPE_NOT_SIGNED_DATA, "cms_get0_signed");
            return ptr::null_mut();
        }
        signer_infos(cms).cast()
    }
}

ffi_export! {
    /// (Auth)EnvelopedData's recipient infos, or NULL (`CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA`).
    ///
    /// # Safety
    /// `cms` is NULL or a live object.
    pub unsafe extern "C" fn CMS_get0_RecipientInfos(cms: *mut CMS_ContentInfo) -> *mut rustyssl_abi::stack_st_CMS_RecipientInfo
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        let nid = type_nid(cms);
        if nid != NID_pkcs7_enveloped && nid != NID_id_smime_ct_authEnvelopedData {
            raise(CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA, "cms_get_enveloped_type");
            return ptr::null_mut();
        }
        recipient_infos(cms).cast()
    }
}

/// `ossl_cms_resolve_libctx` between an error mark and its pop, as the decoders call it.
///
/// # Safety
/// `ci` is a live object.
pub(crate) unsafe fn resolve_libctx_marked(ci: *mut CMS_ContentInfo) {
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: the caller's guarantee.
    unsafe { resolve_libctx(ci) };
    // SAFETY: no preconditions.
    unsafe { ERR_pop_to_mark() };
}

/// `ossl_cms_resolve_libctx`: the object's context into its signer and recipient infos and
/// its certificates.
///
/// # Safety
/// `ci` is a live object.
pub(crate) unsafe fn resolve_libctx(ci: *mut CMS_ContentInfo) {
    let ctx = ctx_of(ci);
    let (libctx, propq) = ctx_parts(ctx);
    let sinfos = signer_infos(ci);
    // SAFETY: the object's signer infos, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(sinfos.cast()) } {
        // SAFETY: an index within them; a signer info, or NULL.
        if let Some(si) = unsafe { super::sk_get::<SignerInfo>(sinfos, i) } {
            si.cms_ctx = ctx;
        }
    }
    let rinfos = recipient_infos(ci);
    if rinfos.is_null() {
        // As `CMS_get0_RecipientInfos` reports for other types.
        raise(
            CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA,
            "cms_get_enveloped_type",
        );
    }
    // SAFETY: the object's recipient infos, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(rinfos.cast()) } {
        // SAFETY: an index within them; a recipient info, or NULL.
        let Some(ri) = (unsafe { super::sk_get::<RecipientInfo>(rinfos, i) }) else {
            continue;
        };
        match ri.type_ {
            CMS_RECIPINFO_AGREE => {
                // SAFETY: the choice's member, NULL or live.
                if let Some(k) = unsafe { ri.d.cast::<KeyAgreeRecipientInfo>().as_mut() } {
                    k.cms_ctx = ctx
                }
            }
            CMS_RECIPINFO_TRANS => {
                // SAFETY: as above.
                if let Some(k) = unsafe { ri.d.cast::<KeyTransRecipientInfo>().as_mut() } {
                    k.cms_ctx = ctx;
                    // SAFETY: the recipient's certificate, or NULL.
                    if let Some(c) = unsafe { cert_of(k.recip) } {
                        // SAFETY: the object's properties, or NULL.
                        unsafe { set0_libctx(&mut c.libctx, &mut c.propq, libctx, propq) };
                    }
                }
            }
            CMS_RECIPINFO_KEK => {
                // SAFETY: the choice's member, NULL or live.
                if let Some(k) = unsafe { ri.d.cast::<KekRecipientInfo>().as_mut() } {
                    k.cms_ctx = ctx
                }
            }
            CMS_RECIPINFO_PASS => {
                // SAFETY: the choice's member, NULL or live.
                if let Some(k) = unsafe { ri.d.cast::<PasswordRecipientInfo>().as_mut() } {
                    k.cms_ctx = ctx
                }
            }
            rustyssl_abi::CMS_RECIPINFO_KEM => {
                if let Some(k) = super::kemri::kemri_of(ri, "", false) {
                    k.cms_ctx = ctx;
                }
            }
            _ => {}
        }
    }
    // SAFETY: the caller's guarantee.
    let pcerts = unsafe { certificate_choices(ci) };
    // SAFETY: the slot, NULL or live, holding NULL or a stack.
    let certs = unsafe { pcerts.as_ref() }.map_or(ptr::null_mut(), |p| *p);
    // SAFETY: the certificates, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(certs.cast()) } {
        // SAFETY: an index within them; a choice, or NULL.
        let Some(cch) = (unsafe { super::sk_get::<CertificateChoices>(certs, i) }) else {
            continue;
        };
        if cch.type_ == CERTCHOICE_CERT {
            // SAFETY: the choice's certificate, or NULL.
            if let Some(c) = unsafe { cert_of(cch.d.cast()) } {
                // SAFETY: as above.
                unsafe { set0_libctx(&mut c.libctx, &mut c.propq, libctx, propq) };
            }
        }
    }
}

ffi_export! {
    /// The object's content type.
    ///
    /// # Safety
    /// `cms` is NULL or a live object.
    pub unsafe extern "C" fn CMS_get0_type(cms: *const CMS_ContentInfo) -> *const ASN1_OBJECT
    where failure = ptr::null(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        unsafe { cms_of(cms) }.map_or(ptr::null(), |c| c.content_type.cast_const())
    }
}

/// `ossl_cms_Data_create`: a Data object with an empty, created content.
///
/// # Safety
/// As for [`CMS_ContentInfo_new_ex`].
pub(crate) unsafe fn data_create(
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> *mut CMS_ContentInfo {
    // SAFETY: the caller's guarantee.
    let cms = unsafe { CMS_ContentInfo_new_ex(libctx, propq) };
    // SAFETY: the new object.
    if let Some(c) = unsafe { cms_of(cms) } {
        c.content_type = nid_obj(NID_pkcs7_data);
        // SAFETY: as above.
        unsafe { CMS_set_detached(cms, 0) };
    }
    cms
}

pub(crate) fn nid_obj(nid: c_int) -> *mut ASN1_OBJECT {
    // SAFETY: any NID.
    unsafe { OBJ_nid2obj(nid) }
}

/// The octets of a string, empty for NULL.
///
/// # Safety
/// `os` is NULL or a live string, unchanged while the slice lives.
pub(crate) unsafe fn octets<'a>(os: *const ASN1_OCTET_STRING) -> &'a [u8] {
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { os.as_ref() }) else {
        return &[];
    };
    match usize::try_from(s.length) {
        // SAFETY: a live string's `length` octets.
        Ok(n) if n > 0 && !s.data.is_null() => unsafe { core::slice::from_raw_parts(s.data, n) },
        _ => &[],
    }
}

/// A new memory BIO that reads as EOF when empty, or NULL.
pub(crate) fn mem_bio() -> *mut BIO {
    crate::pkcs7::doit::mem_bio()
}

/// `ossl_cms_content_bio`: a BIO for the content: null if detached, memory if created, the
/// content's octets otherwise.
///
/// # Safety
/// `cms` is a live object.
pub(crate) unsafe fn content_bio(cms: *mut CMS_ContentInfo) -> *mut BIO {
    // SAFETY: the caller's guarantee.
    let pos = unsafe { CMS_get0_content(cms) };
    // SAFETY: NULL or the content's slot.
    let Some(&os) = (unsafe { pos.as_ref() }) else {
        return ptr::null_mut();
    };
    if os.is_null() {
        // SAFETY: no preconditions.
        let method = unsafe { BIO_s_null() };
        // SAFETY: the built-in method.
        return unsafe { BIO_new(method) };
    }
    // SAFETY: the content's string.
    if unsafe { (*os).flags } == core::ffi::c_long::from(ASN1_STRING_FLAG_CONT) {
        // SAFETY: no preconditions.
        let method = unsafe { BIO_s_mem() };
        // SAFETY: the built-in method.
        return unsafe { BIO_new(method) };
    }
    // SAFETY: as above.
    let s = unsafe { &*os };
    // SAFETY: the content's octets, which outlive the BIO's use of them.
    unsafe { BIO_new_mem_buf(s.data.cast(), s.length) }
}

ffi_export! {
    /// Starts the object's data path over `icont` or its own content: the content type's
    /// filter (digests, ciphers) over it. NULL on failure.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; `icont` NULL or a live BIO.
    pub unsafe extern "C" fn CMS_dataInit(cms: *mut CMS_ContentInfo, icont: *mut BIO) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        const F: &str = "CMS_dataInit";
        if cms.is_null() {
            raise(ERR_R_PASSED_NULL_PARAMETER, F);
            return ptr::null_mut();
        }
        let cont = if icont.is_null() {
            // SAFETY: a live object.
            unsafe { content_bio(cms) }
        } else {
            icont
        };
        if cont.is_null() {
            raise(CMS_R_NO_CONTENT, F);
            return ptr::null_mut();
        }
        let cmsbio = match type_nid(cms) {
            n if n == NID_pkcs7_data => return cont,
            // SAFETY: a live object.
            n if n == NID_pkcs7_signed => unsafe { super::sd::signed_data_init_bio(cms) },
            // SAFETY: a live DigestedData object.
            n if n == NID_pkcs7_digest => unsafe { digested_init_bio(cms) },
            // SAFETY: a live EncryptedData object.
            n if n == NID_pkcs7_encrypted => unsafe { enc::encrypted_data_init_bio(cms) },
            // SAFETY: a live EnvelopedData object.
            n if n == NID_pkcs7_enveloped => unsafe { super::env::enveloped_init_bio(cms) },
            // SAFETY: a live AuthEnvelopedData object.
            n if n == NID_id_smime_ct_authEnvelopedData => unsafe {
                super::env::auth_enveloped_init_bio(cms)
            },
            _ => {
                raise(CMS_R_UNSUPPORTED_TYPE, F);
                ptr::null_mut()
            }
        };
        if !cmsbio.is_null() {
            // SAFETY: live BIOs; the chain takes the content's.
            return unsafe { BIO_push(cmsbio, cont) };
        }
        if icont.is_null() {
            // SAFETY: the BIO made here.
            unsafe { BIO_free(cont) };
        }
        ptr::null_mut()
    }
}

ffi_export! {
    /// Finishes the object from its data path's chain: 1, or 0.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; `cmsbio` its chain.
    pub unsafe extern "C" fn CMS_dataFinal(cms: *mut CMS_ContentInfo, cmsbio: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        unsafe { data_final(cms, cmsbio, &[]) }
    }
}

/// `ossl_cms_DataFinal`: stores a created content (copied out of its memory BIO; OpenSSL takes
/// the BIO's buffer, docs/DEVIATIONS.md), then finishes the content type.
///
/// # Safety
/// `cms` is NULL or a live object; `cmsbio` its chain.
pub(crate) unsafe fn data_final(
    cms: *mut CMS_ContentInfo,
    cmsbio: *mut BIO,
    precomp_md: &[u8],
) -> c_int {
    const F: &str = "ossl_cms_DataFinal";
    if cms.is_null() {
        return 0;
    }
    // SAFETY: a live object.
    let pos = unsafe { CMS_get0_content(cms) };
    // SAFETY: NULL or the content's slot.
    let Some(&os) = (unsafe { pos.as_ref() }) else {
        return 0;
    };
    // SAFETY: NULL or the content's string.
    if let Some(s) = unsafe { os.as_mut() }
        && s.flags & core::ffi::c_long::from(ASN1_STRING_FLAG_CONT) != 0
    {
        // SAFETY: the chain.
        let mbio = unsafe { BIO_find_type(cmsbio, BIO_TYPE_MEM) };
        if mbio.is_null() {
            raise(CMS_R_CONTENT_NOT_FOUND, F);
            return 0;
        }
        let mut cont: *mut c_char = ptr::null_mut();
        // SAFETY: a live memory BIO; room for the pointer.
        let len = unsafe { BIO_ctrl(mbio, BIO_CTRL_INFO, 0, (&raw mut cont).cast()) };
        let Ok(n) = c_int::try_from(len) else {
            return 0;
        };
        // SAFETY: the BIO's `len` octets, copied into the string.
        if unsafe { ASN1_STRING_set(os.cast(), cont.cast(), n) } == 0 {
            return 0;
        }
        // SAFETY: a live memory BIO.
        unsafe { BIO_ctrl(mbio, BIO_C_SET_BUF_MEM_EOF_RETURN, 0, ptr::null_mut()) };
        s.flags &= !core::ffi::c_long::from(ASN1_STRING_FLAG_CONT);
    }
    match type_nid(cms) {
        n if [
            NID_pkcs7_data,
            NID_pkcs7_encrypted,
            NID_id_smime_ct_compressedData,
        ]
        .contains(&n) =>
        {
            1
        }
        // SAFETY: a live object and its chain.
        n if n == NID_pkcs7_enveloped => unsafe { super::env::enveloped_final(cms, cmsbio) },
        // SAFETY: as above.
        n if n == NID_id_smime_ct_authEnvelopedData => unsafe {
            super::env::auth_enveloped_final(cms, cmsbio)
        },
        // SAFETY: a live SignedData object and its chain.
        n if n == NID_pkcs7_signed => unsafe {
            super::sd::signed_data_final(cms, cmsbio, precomp_md)
        },
        // SAFETY: a live DigestedData object.
        n if n == NID_pkcs7_digest => unsafe { digested_do_final(cms, cmsbio, false) },
        _ => {
            raise(CMS_R_UNSUPPORTED_TYPE, F);
            0
        }
    }
}

/// The slot of the content's octets for each type.
///
/// # Safety
/// `cms` is a live object.
unsafe fn content_slot(cms: *mut CMS_ContentInfo) -> Option<*mut *mut ASN1_OCTET_STRING> {
    // SAFETY: the caller's guarantee.
    let c = unsafe { cms_of(cms) }?;
    let d = c.d;
    let encap = |e: *mut super::EncapContentInfo| {
        // SAFETY: NULL or the content's encapsulated content.
        unsafe { e.as_mut() }.map(|e| &raw mut e.e_content)
    };
    let enc = |e: *mut super::EncryptedContentInfo| {
        // SAFETY: NULL or the content's encrypted content.
        unsafe { e.as_mut() }.map(|e| &raw mut e.encrypted_content)
    };
    match type_nid(cms) {
        n if n == NID_pkcs7_data => Some(&raw mut c.d).map(|p| p.cast()),
        n if n == NID_pkcs7_signed => typed::<super::SignedData>(cms).and_then(|s| encap(s.encap)),
        n if n == NID_pkcs7_enveloped => {
            typed::<super::EnvelopedData>(cms).and_then(|e| enc(e.encrypted_content_info))
        }
        n if n == NID_pkcs7_digest => {
            typed::<super::DigestedData>(cms).and_then(|e| encap(e.encap))
        }
        n if n == NID_pkcs7_encrypted => {
            typed::<super::EncryptedData>(cms).and_then(|e| enc(e.encrypted_content_info))
        }
        n if n == NID_id_smime_ct_authEnvelopedData => {
            typed::<super::AuthEnvelopedData>(cms).and_then(|e| enc(e.auth_encrypted_content_info))
        }
        n if n == NID_id_smime_ct_authData => {
            typed::<super::AuthenticatedData>(cms).and_then(|e| encap(e.encap))
        }
        n if n == NID_id_smime_ct_compressedData => {
            typed::<super::CompressedData>(cms).and_then(|e| encap(e.encap))
        }
        _ => {
            let other = d.cast::<rustyssl_abi::ASN1_TYPE>();
            // SAFETY: an other type's ANY, NULL or live.
            match unsafe { other.as_mut() } {
                Some(t) if t.type_ == V_ASN1_OCTET_STRING => Some((&raw mut t.value).cast()),
                _ => None,
            }
        }
    }
}

ffi_export! {
    /// The slot of the object's content octets (the encapsulated or encrypted content), or
    /// NULL (`CMS_R_UNSUPPORTED_CONTENT_TYPE`).
    ///
    /// # Safety
    /// `cms` is NULL or a live object.
    pub unsafe extern "C" fn CMS_get0_content(cms: *mut CMS_ContentInfo) -> *mut *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        match unsafe { content_slot(cms) } {
            Some(p) => p,
            None => {
                raise(CMS_R_UNSUPPORTED_CONTENT_TYPE, "CMS_get0_content");
                ptr::null_mut()
            }
        }
    }
}

/// `cms_get0_econtent_type`: the slot of the encapsulated content's type.
///
/// # Safety
/// `cms` is NULL or a live object.
unsafe fn econtent_type(cms: *mut CMS_ContentInfo) -> *mut *mut ASN1_OBJECT {
    let encap = |e: *mut super::EncapContentInfo| {
        // SAFETY: NULL or the content's encapsulated content.
        unsafe { e.as_mut() }.map(|e| &raw mut e.e_content_type)
    };
    let enc = |e: *mut super::EncryptedContentInfo| {
        // SAFETY: NULL or the content's encrypted content.
        unsafe { e.as_mut() }.map(|e| &raw mut e.content_type)
    };
    let r = match type_nid(cms) {
        n if n == NID_pkcs7_signed => typed::<super::SignedData>(cms).and_then(|s| encap(s.encap)),
        n if n == NID_pkcs7_enveloped => {
            typed::<super::EnvelopedData>(cms).and_then(|e| enc(e.encrypted_content_info))
        }
        n if n == NID_pkcs7_digest => {
            typed::<super::DigestedData>(cms).and_then(|e| encap(e.encap))
        }
        n if n == NID_pkcs7_encrypted => {
            typed::<super::EncryptedData>(cms).and_then(|e| enc(e.encrypted_content_info))
        }
        n if n == NID_id_smime_ct_authEnvelopedData => {
            typed::<super::AuthEnvelopedData>(cms).and_then(|e| enc(e.auth_encrypted_content_info))
        }
        n if n == NID_id_smime_ct_authData => {
            typed::<super::AuthenticatedData>(cms).and_then(|e| encap(e.encap))
        }
        n if n == NID_id_smime_ct_compressedData => {
            typed::<super::CompressedData>(cms).and_then(|e| encap(e.encap))
        }
        _ => None,
    };
    r.unwrap_or_else(|| {
        raise(CMS_R_UNSUPPORTED_CONTENT_TYPE, "cms_get0_econtent_type");
        ptr::null_mut()
    })
}

ffi_export! {
    /// The type of the encapsulated content, or NULL.
    ///
    /// # Safety
    /// `cms` is NULL or a live object.
    pub unsafe extern "C" fn CMS_get0_eContentType(cms: *mut CMS_ContentInfo) -> *const ASN1_OBJECT
    where failure = ptr::null(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let p = unsafe { econtent_type(cms) };
        // SAFETY: NULL or the slot.
        unsafe { p.as_ref() }.map_or(ptr::null(), |o| o.cast_const())
    }
}

ffi_export! {
    /// Sets the type of the encapsulated content to a copy of `oid` (NULL changes nothing):
    /// 1, or 0.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; `oid` NULL or live.
    pub unsafe extern "C" fn CMS_set1_eContentType(cms: *mut CMS_ContentInfo, oid: *const ASN1_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let p = unsafe { econtent_type(cms) };
        if p.is_null() {
            return 0;
        }
        if oid.is_null() {
            return 1;
        }
        // SAFETY: a live object.
        let etype = unsafe { OBJ_dup(oid) };
        if etype.is_null() {
            return 0;
        }
        // SAFETY: the slot.
        let old = unsafe { p.read() };
        // SAFETY: the object's own type, or NULL.
        unsafe { ASN1_OBJECT_free(old) };
        // SAFETY: as above.
        unsafe { p.write(etype) };
        1
    }
}

ffi_export! {
    /// Whether the object's content is detached: 1, 0, or -1.
    ///
    /// # Safety
    /// `cms` is NULL or a live object.
    pub unsafe extern "C" fn CMS_is_detached(cms: *mut CMS_ContentInfo) -> c_int
    where failure = -1, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let pos = unsafe { CMS_get0_content(cms) };
        // SAFETY: NULL or the content's slot.
        match unsafe { pos.as_ref() } {
            None => -1,
            Some(p) => c_int::from(p.is_null()),
        }
    }
}

ffi_export! {
    /// Detaches the content (freeing it) or marks it to be created: 1, or 0.
    ///
    /// # Safety
    /// `cms` is NULL or a live object.
    pub unsafe extern "C" fn CMS_set_detached(cms: *mut CMS_ContentInfo, detached: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let pos = unsafe { CMS_get0_content(cms) };
        if pos.is_null() {
            return 0;
        }
        // SAFETY: the content's slot.
        let os = unsafe { pos.read() };
        if detached != 0 {
            // SAFETY: the object's own string, or NULL.
            unsafe { ASN1_OCTET_STRING_free(os) };
            // SAFETY: as above.
            unsafe { pos.write(ptr::null_mut()) };
            return 1;
        }
        let os = if os.is_null() {
            // SAFETY: no preconditions.
            let n = unsafe { ASN1_OCTET_STRING_new() };
            // SAFETY: the slot.
            unsafe { pos.write(n) };
            n
        } else {
            os
        };
        // SAFETY: NULL or the content's string.
        let Some(s) = (unsafe { os.as_mut() }) else {
            raise(ERR_R_ASN1_LIB, "CMS_set_detached");
            return 0;
        };
        s.flags |= core::ffi::c_long::from(ASN1_STRING_FLAG_CONT);
        1
    }
}

/// `ossl_cms_DigestAlgorithm_init_bio`: a digest BIO for the algorithm (SHAKE with its usual
/// output length).
///
/// # Safety
/// `alg` is a live algorithm identifier; `ctx` NULL or live.
pub(crate) unsafe fn digest_algorithm_init_bio(
    alg: *const X509_ALGOR,
    ctx: *const CmsCtx,
) -> *mut BIO {
    const F: &str = "ossl_cms_DigestAlgorithm_init_bio";
    let (libctx, propq) = ctx_parts(ctx);
    // SAFETY: the caller's guarantee.
    let oid = unsafe { alg.as_ref() }.map_or(ptr::null_mut(), |a| a.algorithm);
    let mut name = [0 as c_char; NAME_LEN];
    let len = c_int::try_from(NAME_LEN).unwrap_or(0);
    // SAFETY: room for the name; the object, or NULL.
    unsafe { OBJ_obj2txt(name.as_mut_ptr(), len, oid, 0) };
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: a NUL-terminated name; the object's context and properties.
    let fetched = unsafe { EVP_MD_fetch(libctx, name.as_ptr(), propq) };
    let digest: *const EVP_MD = if fetched.is_null() {
        // SAFETY: the object, or NULL.
        let nid = unsafe { OBJ_obj2nid(oid) };
        // SAFETY: any NID.
        let sn = unsafe { OBJ_nid2sn(nid) };
        // SAFETY: NULL or a static name.
        unsafe { EVP_get_digestbyname(sn) }
    } else {
        fetched.cast_const()
    };
    let mut mdbio = ptr::null_mut();
    let ok = 'err: {
        if digest.is_null() {
            // SAFETY: no preconditions.
            unsafe { ERR_clear_last_mark() };
            raise(CMS_R_UNKNOWN_DIGEST_ALGORITHM, F);
            break 'err false;
        }
        // SAFETY: no preconditions.
        unsafe { ERR_pop_to_mark() };
        // SAFETY: no preconditions.
        let method = unsafe { BIO_f_md() };
        // SAFETY: the built-in method.
        mdbio = unsafe { BIO_new(method) };
        if mdbio.is_null()
            // SAFETY: a live digest BIO; a live digest.
            || unsafe { BIO_ctrl(mdbio, BIO_C_SET_MD, 0, digest.cast_mut().cast()) } <= 0
        {
            raise(CMS_R_MD_BIO_INIT_ERROR, F);
            break 'err false;
        }
        // SAFETY: a live digest.
        if unsafe { EVP_MD_xof(digest) } != 0 {
            // SAFETY: as above; static names.
            let xof_len: usize = if unsafe { EVP_MD_is_a(digest, SN_shake128.as_ptr()) } != 0 {
                32
            // SAFETY: as above.
            } else if unsafe { EVP_MD_is_a(digest, SN_shake256.as_ptr()) } != 0 {
                64
            } else {
                0
            };
            if xof_len > 0 {
                let mut mdctx: *mut EVP_MD_CTX = ptr::null_mut();
                // SAFETY: the digest BIO; room for its context.
                if unsafe { BIO_ctrl(mdbio, BIO_C_GET_MD_CTX, 0, (&raw mut mdctx).cast()) } <= 0
                    || mdctx.is_null()
                {
                    break 'err false;
                }
                let mut value = xof_len;
                // SAFETY: a static key; the length, alive for the call.
                let params: [OSSL_PARAM; 2] = [
                    unsafe {
                        OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_XOFLEN.as_ptr(), &mut value)
                    },
                    unsafe { OSSL_PARAM_construct_end() },
                ];
                // SAFETY: the BIO's context; the parameters.
                if unsafe { EVP_MD_CTX_set_params(mdctx, params.as_ptr()) } == 0 {
                    break 'err false;
                }
            }
        }
        true
    };
    // SAFETY: the fetched digest, or NULL; the BIO holds its own reference.
    unsafe { EVP_MD_free(fetched) };
    if ok {
        return mdbio;
    }
    // SAFETY: the BIO made here, or NULL.
    unsafe { BIO_free(mdbio) };
    ptr::null_mut()
}

/// `ossl_cms_DigestAlgorithm_find_ctx`: a copy into `mctx` of the chain's digest for `mdalg`
/// (or its signature algorithm, for broken senders).
///
/// # Safety
/// `mctx` is a live context; `chain` a live chain; `mdalg` a live algorithm identifier.
pub(crate) unsafe fn digest_algorithm_find_ctx(
    mctx: *mut EVP_MD_CTX,
    chain: *mut BIO,
    mdalg: *const X509_ALGOR,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let oid = unsafe { mdalg.as_ref() }.map_or(ptr::null(), |a| a.algorithm.cast_const());
    // SAFETY: its object, or NULL.
    let nid = unsafe { OBJ_obj2nid(oid) };
    let mut chain = chain;
    loop {
        // SAFETY: a live chain.
        chain = unsafe { BIO_find_type(chain, BIO_TYPE_MD) };
        if chain.is_null() {
            raise(
                CMS_R_NO_MATCHING_DIGEST,
                "ossl_cms_DigestAlgorithm_find_ctx",
            );
            return 0;
        }
        let mut mtmp: *mut EVP_MD_CTX = ptr::null_mut();
        // SAFETY: a digest BIO; room for its context.
        unsafe { BIO_ctrl(chain, BIO_C_GET_MD_CTX, 0, (&raw mut mtmp).cast()) };
        // SAFETY: its context, or NULL.
        let md = unsafe { EVP_MD_CTX_get0_md(mtmp) };
        // SAFETY: its digest, or NULL.
        if unsafe { EVP_MD_get_type(md) } == nid || unsafe { EVP_MD_get_pkey_type(md) } == nid {
            // SAFETY: live contexts.
            return unsafe { EVP_MD_CTX_copy_ex(mctx, mtmp) };
        }
        // SAFETY: a live BIO.
        chain = unsafe { BIO_next(chain) };
    }
}

/// `cms_get0_certificate_choices`: the slot of the certificates, or NULL.
///
/// # Safety
/// `cms` is NULL or a live object.
unsafe fn certificate_choices(cms: *mut CMS_ContentInfo) -> *mut *mut Stack {
    let r = match type_nid(cms) {
        n if n == NID_pkcs7_signed => {
            typed::<super::SignedData>(cms).map(|s| &raw mut s.certificates)
        }
        n if n == NID_pkcs7_enveloped => typed::<super::EnvelopedData>(cms)
            .and_then(|e| originator(e.originator_info))
            .map(|o| &raw mut o.certificates),
        n if n == NID_id_smime_ct_authEnvelopedData => typed::<super::AuthEnvelopedData>(cms)
            .and_then(|e| originator(e.originator_info))
            .map(|o| &raw mut o.certificates),
        _ => {
            raise(
                CMS_R_UNSUPPORTED_CONTENT_TYPE,
                "cms_get0_certificate_choices",
            );
            None
        }
    };
    r.unwrap_or(ptr::null_mut())
}

/// `cms_get0_revocation_choices`: the slot of the CRLs, or NULL.
///
/// # Safety
/// `cms` is NULL or a live object.
unsafe fn revocation_choices(cms: *mut CMS_ContentInfo) -> *mut *mut Stack {
    let r = match type_nid(cms) {
        n if n == NID_pkcs7_signed => typed::<super::SignedData>(cms).map(|s| &raw mut s.crls),
        n if n == NID_pkcs7_enveloped => typed::<super::EnvelopedData>(cms)
            .and_then(|e| originator(e.originator_info))
            .map(|o| &raw mut o.crls),
        n if n == NID_id_smime_ct_authEnvelopedData => typed::<super::AuthEnvelopedData>(cms)
            .and_then(|e| originator(e.originator_info))
            .map(|o| &raw mut o.crls),
        _ => {
            raise(
                CMS_R_UNSUPPORTED_CONTENT_TYPE,
                "cms_get0_revocation_choices",
            );
            None
        }
    };
    r.unwrap_or(ptr::null_mut())
}

/// Pushes a new element of `it` onto `*slot` (made if NULL): the element, or NULL.
///
/// # Safety
/// `slot` is a live slot holding NULL or a stack of `it`'s values.
unsafe fn push_new(slot: *mut *mut Stack, it: *const rustyssl_abi::ASN1_ITEM) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    if unsafe { slot.read() }.is_null() {
        // SAFETY: no preconditions.
        let sk = unsafe { OPENSSL_sk_new_null() };
        // SAFETY: the slot.
        unsafe { slot.write(sk.cast()) };
    }
    // SAFETY: as above.
    let sk = unsafe { slot.read() };
    if sk.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the item.
    let v = unsafe { ASN1_item_new(it) };
    if v.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the stack; the new value.
    if unsafe { OPENSSL_sk_push(sk.cast(), v.cast()) } == 0 {
        // SAFETY: the value made here.
        unsafe { ASN1_item_free(v, it) };
        return ptr::null_mut();
    }
    v.cast()
}

ffi_export! {
    /// A new, empty certificate choice in the object's certificates, or NULL.
    ///
    /// # Safety
    /// `cms` is NULL or a live object.
    pub unsafe extern "C" fn CMS_add0_CertificateChoices(cms: *mut CMS_ContentInfo) -> *mut CMS_CertificateChoices
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let pcerts = unsafe { certificate_choices(cms) };
        if pcerts.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let it = unsafe { super::certificate_choices_it() };
        // SAFETY: the slot; the choice's item.
        unsafe { push_new(pcerts, it) }.cast()
    }
}

ffi_export! {
    /// Adds `cert` to the object's certificates, taking the caller's reference (dropping it if
    /// the certificate is there already): 1, or 0.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; `cert` a live certificate.
    pub unsafe extern "C" fn CMS_add0_cert(cms: *mut CMS_ContentInfo, cert: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let pcerts = unsafe { certificate_choices(cms) };
        if pcerts.is_null() {
            return 0;
        }
        // SAFETY: the slot.
        let certs = unsafe { pcerts.read() };
        // SAFETY: the certificates, or NULL.
        for i in 0..unsafe { OPENSSL_sk_num(certs.cast()) } {
            // SAFETY: an index within them; a choice.
            let Some(cch) = (unsafe { super::sk_get::<CertificateChoices>(certs, i) }) else { continue };
            // SAFETY: live certificates.
            if cch.type_ == CERTCHOICE_CERT && unsafe { X509_cmp(cch.d.cast(), cert) } == 0 {
                // SAFETY: the caller's reference, dropped.
                unsafe { X509_free(cert) };
                return 1;
            }
        }
        // SAFETY: as above.
        let cch = unsafe { CMS_add0_CertificateChoices(cms) }.cast::<CertificateChoices>();
        // SAFETY: the new choice, or NULL.
        let Some(c) = (unsafe { cch.as_mut() }) else { return 0 };
        c.type_ = CERTCHOICE_CERT;
        c.d = cert.cast();
        1
    }
}

ffi_export! {
    /// [`CMS_add0_cert`] with a new reference: 1, or 0.
    ///
    /// # Safety
    /// As for [`CMS_add0_cert`].
    pub unsafe extern "C" fn CMS_add1_cert(cms: *mut CMS_ContentInfo, cert: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's certificate.
        if unsafe { X509_up_ref(cert) } == 0 {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        if unsafe { CMS_add0_cert(cms, cert) } != 0 {
            return 1;
        }
        // SAFETY: the reference taken above.
        unsafe { X509_free(cert) };
        0
    }
}

ffi_export! {
    /// A new, empty revocation choice in the object's CRLs, or NULL.
    ///
    /// # Safety
    /// `cms` is NULL or a live object.
    pub unsafe extern "C" fn CMS_add0_RevocationInfoChoice(cms: *mut CMS_ContentInfo) -> *mut CMS_RevocationInfoChoice
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let pcrls = unsafe { revocation_choices(cms) };
        if pcrls.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let it = unsafe { super::revocation_info_choice_it() };
        // SAFETY: the slot; the choice's item.
        unsafe { push_new(pcrls, it) }.cast()
    }
}

ffi_export! {
    /// Adds `crl` to the object's CRLs, taking the caller's reference: 1, or 0.
    ///
    /// # Safety
    /// `cms` is NULL or a live object; `crl` a live CRL.
    pub unsafe extern "C" fn CMS_add0_crl(cms: *mut CMS_ContentInfo, crl: *mut X509_CRL) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let rch = unsafe { CMS_add0_RevocationInfoChoice(cms) }.cast::<RevocationInfoChoice>();
        // SAFETY: the new choice, or NULL.
        let Some(r) = (unsafe { rch.as_mut() }) else { return 0 };
        r.type_ = REVCHOICE_CRL;
        r.d = crl.cast();
        1
    }
}

ffi_export! {
    /// [`CMS_add0_crl`] with a new reference: 1, or 0.
    ///
    /// # Safety
    /// As for [`CMS_add0_crl`].
    pub unsafe extern "C" fn CMS_add1_crl(cms: *mut CMS_ContentInfo, crl: *mut X509_CRL) -> c_int
    where failure = 0, library = ERR_LIB_CMS
    {
        // SAFETY: the caller's CRL.
        if unsafe { X509_CRL_up_ref(crl) } == 0 {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        if unsafe { CMS_add0_crl(cms, crl) } != 0 {
            return 1;
        }
        // SAFETY: the reference taken above.
        unsafe { X509_CRL_free(crl) };
        0
    }
}

/// `ossl_cms_get1_certs_ex`: the object's certificates, with new references, in a new stack
/// (empty if it has none). `None` on failure.
///
/// # Safety
/// `cms` is NULL or a live object.
pub(crate) unsafe fn get1_certs_ex(cms: *mut CMS_ContentInfo) -> Option<*mut stack_st_X509> {
    // SAFETY: the caller's guarantee.
    let pcerts = unsafe { certificate_choices(cms) };
    if pcerts.is_null() {
        return None;
    }
    // SAFETY: the slot.
    let certs = unsafe { pcerts.read() };
    // SAFETY: the certificates, or NULL.
    let n = unsafe { OPENSSL_sk_num(certs.cast()) };
    // SAFETY: no preconditions.
    let out = unsafe { OPENSSL_sk_new_reserve(None, n) }.cast::<stack_st_X509>();
    if out.is_null() {
        return None;
    }
    for i in 0..n {
        // SAFETY: an index within them; a choice.
        let Some(cch) = (unsafe { super::sk_get::<CertificateChoices>(certs, i) }) else {
            continue;
        };
        if cch.type_ == CERTCHOICE_CERT
            // SAFETY: the new stack; the choice's certificate.
            && unsafe { X509_add_cert(out, cch.d.cast(), X509_ADD_FLAG_UP_REF) } == 0
        {
            // SAFETY: the stack made here, with its references.
            unsafe { OSSL_STACK_OF_X509_free(out) };
            return None;
        }
    }
    Some(out)
}

ffi_export! {
    /// The object's certificates with new references, or NULL if it has none.
    ///
    /// # Safety
    /// `cms` is NULL or a live object.
    pub unsafe extern "C" fn CMS_get1_certs(cms: *mut CMS_ContentInfo) -> *mut stack_st_X509
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(certs) = (unsafe { get1_certs_ex(cms) }) else { return ptr::null_mut() };
        // SAFETY: the stack made.
        if unsafe { OPENSSL_sk_num(certs.cast()) } == 0 {
            // SAFETY: as above, empty.
            unsafe { OPENSSL_sk_free(certs.cast()) };
            return ptr::null_mut();
        }
        certs
    }
}

unsafe extern "C" fn crl_free(p: *mut c_void) {
    // SAFETY: a CRL of the stack.
    unsafe { X509_CRL_free(p.cast()) };
}

/// `ossl_cms_get1_crls_ex`: the object's CRLs, with new references, in a new stack (empty if it
/// has none). `None` on failure.
///
/// # Safety
/// `cms` is NULL or a live object.
pub(crate) unsafe fn get1_crls_ex(cms: *mut CMS_ContentInfo) -> Option<*mut stack_st_X509_CRL> {
    // SAFETY: the caller's guarantee.
    let pcrls = unsafe { revocation_choices(cms) };
    if pcrls.is_null() {
        return None;
    }
    // SAFETY: the slot.
    let crls = unsafe { pcrls.read() };
    // SAFETY: the CRLs, or NULL.
    let n = unsafe { OPENSSL_sk_num(crls.cast()) };
    // SAFETY: no preconditions.
    let out = unsafe { OPENSSL_sk_new_reserve(None, n) };
    if out.is_null() {
        return None;
    }
    for i in 0..n {
        // SAFETY: an index within them.
        let Some(rch) = (unsafe { super::sk_get::<RevocationInfoChoice>(crls, i) }) else {
            continue;
        };
        if rch.type_ != REVCHOICE_CRL {
            continue;
        }
        // SAFETY: the choice's CRL; the new stack.
        if unsafe { X509_CRL_up_ref(rch.d.cast()) } == 0
            // SAFETY: the new stack; a CRL with its reference.
            || unsafe { OPENSSL_sk_push(out, rch.d) } == 0
        {
            // SAFETY: the stack made here, with its references.
            unsafe { OPENSSL_sk_pop_free(out, Some(crl_free)) };
            return None;
        }
    }
    Some(out.cast())
}

ffi_export! {
    /// The object's CRLs with new references, or NULL if it has none.
    ///
    /// # Safety
    /// `cms` is NULL or a live object.
    pub unsafe extern "C" fn CMS_get1_crls(cms: *mut CMS_ContentInfo) -> *mut stack_st_X509_CRL
    where failure = ptr::null_mut(), library = ERR_LIB_CMS
    {
        // SAFETY: the caller's guarantee.
        let Some(out) = (unsafe { get1_crls_ex(cms) }) else { return ptr::null_mut() };
        // SAFETY: the stack made.
        if unsafe { OPENSSL_sk_num(out.cast()) } == 0 {
            // SAFETY: as above, empty.
            unsafe { OPENSSL_sk_free(out.cast()) };
            return ptr::null_mut();
        }
        out
    }
}

/// `ossl_cms_ias_cert_cmp`: 0 if the issuer and serial are the certificate's.
///
/// # Safety
/// `ias` and `cert` are live.
pub(crate) unsafe fn ias_cert_cmp(ias: &IssuerAndSerialNumber, cert: *mut X509) -> c_int {
    // SAFETY: the caller's certificate.
    let issuer = unsafe { X509_get_issuer_name(cert) };
    // SAFETY: live names.
    let r = unsafe { X509_NAME_cmp(ias.issuer, issuer) };
    if r != 0 {
        return r;
    }
    // SAFETY: as above.
    let serial = unsafe { X509_get0_serialNumber(cert) };
    // SAFETY: live integers.
    unsafe { ASN1_INTEGER_cmp(ias.serial_number, serial) }
}

/// `ossl_cms_keyid_cert_cmp`: 0 if the key identifier is the certificate's (-1 if it has
/// none).
///
/// # Safety
/// `keyid` and `cert` are live.
pub(crate) unsafe fn keyid_cert_cmp(keyid: *const ASN1_OCTET_STRING, cert: *mut X509) -> c_int {
    // SAFETY: the caller's certificate.
    let ck = unsafe { X509_get0_subject_key_id(cert) };
    if ck.is_null() {
        return -1;
    }
    // SAFETY: live strings.
    unsafe { ASN1_OCTET_STRING_cmp(keyid, ck) }
}

/// `ossl_cms_set1_ias`: `*pias` replaced by the certificate's issuer and serial.
///
/// # Safety
/// `pias` is a live slot holding NULL or a live value; `cert` a live certificate.
pub(crate) unsafe fn set1_ias(pias: *mut *mut IssuerAndSerialNumber, cert: *mut X509) -> bool {
    const F: &str = "ossl_cms_set1_ias";
    // SAFETY: no preconditions.
    let it = unsafe { ias_it() };
    // SAFETY: the item.
    let ias = unsafe { ASN1_item_new(it) }.cast::<IssuerAndSerialNumber>();
    // SAFETY: the new value, or NULL.
    let Some(i) = (unsafe { ias.as_mut() }) else {
        raise(ERR_R_ASN1_LIB, F);
        return false;
    };
    // SAFETY: the caller's certificate.
    let issuer = unsafe { X509_get_issuer_name(cert) };
    // SAFETY: its issuer; the value's slot.
    if unsafe { X509_NAME_set(&mut i.issuer, issuer) } == 0 {
        raise(ERR_R_X509_LIB, F);
        // SAFETY: the value made here.
        unsafe { ASN1_item_free(ias.cast(), it) };
        return false;
    }
    // SAFETY: the caller's certificate.
    let serial = unsafe { X509_get0_serialNumber(cert) };
    // SAFETY: the value's serial; the certificate's.
    if unsafe { ASN1_STRING_copy(i.serial_number, serial) } == 0 {
        raise(ERR_R_ASN1_LIB, F);
        // SAFETY: as above.
        unsafe { ASN1_item_free(ias.cast(), it) };
        return false;
    }
    // SAFETY: the caller's slot.
    let old = unsafe { pias.read() };
    // SAFETY: its value, or NULL.
    unsafe { ASN1_item_free(old.cast(), it) };
    // SAFETY: as above.
    unsafe { pias.write(ias) };
    true
}

/// `ossl_cms_set1_keyid`: `*pkeyid` replaced by a copy of the certificate's key identifier.
///
/// # Safety
/// `pkeyid` is a live slot holding NULL or a live string; `cert` a live certificate.
pub(crate) unsafe fn set1_keyid(pkeyid: *mut *mut ASN1_OCTET_STRING, cert: *mut X509) -> bool {
    const F: &str = "ossl_cms_set1_keyid";
    // SAFETY: the caller's certificate.
    let ck = unsafe { X509_get0_subject_key_id(cert) };
    if ck.is_null() {
        raise(CMS_R_CERTIFICATE_HAS_NO_KEYID, F);
        return false;
    }
    // SAFETY: a live string.
    let keyid = unsafe { ASN1_STRING_dup(ck) };
    if keyid.is_null() {
        raise(ERR_R_ASN1_LIB, F);
        return false;
    }
    // SAFETY: the caller's slot.
    let old = unsafe { pkeyid.read() };
    // SAFETY: its string, or NULL.
    unsafe { ASN1_OCTET_STRING_free(old) };
    // SAFETY: as above.
    unsafe { pkeyid.write(keyid) };
    true
}

/// `ossl_cms_DigestedData_create`: DigestedData with `md`, its content Data.
///
/// # Safety
/// `md` is a live digest; the others as for [`CMS_ContentInfo_new_ex`].
pub(crate) unsafe fn digested_create(
    md: *const EVP_MD,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> *mut CMS_ContentInfo {
    // SAFETY: the caller's guarantee.
    let cms = unsafe { CMS_ContentInfo_new_ex(libctx, propq) };
    // SAFETY: the new object, or NULL.
    let Some(c) = (unsafe { cms_of(cms) }) else {
        return ptr::null_mut();
    };
    // SAFETY: no preconditions.
    let it = unsafe { super::digested_data_it() };
    // SAFETY: the item.
    let dd = unsafe { ASN1_item_new(it) }.cast::<super::DigestedData>();
    // SAFETY: the new content, or NULL.
    let Some(d) = (unsafe { dd.as_mut() }) else {
        // SAFETY: the object made here.
        unsafe { CMS_ContentInfo_free(cms) };
        return ptr::null_mut();
    };
    c.content_type = nid_obj(NID_pkcs7_digest);
    c.d = dd.cast();
    d.version = 0;
    // SAFETY: the content's encapsulated content, made with it.
    if let Some(e) = unsafe { d.encap.as_mut() } {
        e.e_content_type = nid_obj(NID_pkcs7_data);
    }
    // SAFETY: the content's algorithm; the caller's digest.
    unsafe { crate::x509::algor::X509_ALGOR_set_md(d.digest_algorithm, md) };
    cms
}

/// `ossl_cms_DigestedData_init_bio`.
///
/// # Safety
/// `cms` is a live DigestedData object.
unsafe fn digested_init_bio(cms: *mut CMS_ContentInfo) -> *mut BIO {
    // SAFETY: the content of its type.
    let Some(dd) = (unsafe { content::<super::DigestedData>(cms) }) else {
        return ptr::null_mut();
    };
    // SAFETY: the content's algorithm; the object's context.
    unsafe { digest_algorithm_init_bio(dd.digest_algorithm, ctx_of(cms)) }
}

/// `ossl_cms_DigestedData_do_final`: sets the digest, or (for `verify`) compares it, in
/// constant time.
///
/// # Safety
/// `cms` is a live DigestedData object; `chain` its chain.
pub(crate) unsafe fn digested_do_final(
    cms: *mut CMS_ContentInfo,
    chain: *mut BIO,
    verify: bool,
) -> c_int {
    use rustyssl_abi::{
        CMS_R_MESSAGEDIGEST_WRONG_LENGTH, CMS_R_VERIFICATION_FAILURE, ERR_R_EVP_LIB,
        EVP_MAX_MD_SIZE,
    };
    // SAFETY: no preconditions.
    let mctx = unsafe { crate::evp::md_ctx::EVP_MD_CTX_new() };
    if mctx.is_null() {
        raise(ERR_R_EVP_LIB, "ossl_cms_DigestedData_do_final");
        return 0;
    }
    let r = 'err: {
        // SAFETY: the content of its type.
        let Some(dd) = (unsafe { content::<super::DigestedData>(cms) }) else {
            break 'err 0;
        };
        // SAFETY: the context; the chain; the content's algorithm.
        if unsafe { digest_algorithm_find_ctx(mctx, chain, dd.digest_algorithm) } == 0 {
            break 'err 0;
        }
        let mut md = [0u8; EVP_MAX_MD_SIZE as usize];
        let mut mdlen: c_uint = 0;
        // SAFETY: as above; room for any digest.
        if unsafe { crate::evp::md_ctx::EVP_DigestFinal_ex(mctx, md.as_mut_ptr(), &mut mdlen) } <= 0
        {
            break 'err 0;
        }
        let computed = md
            .get(..usize::try_from(mdlen).unwrap_or(0))
            .unwrap_or_default();
        if verify {
            // SAFETY: the content's digest.
            let stored = unsafe { octets(dd.digest) };
            if stored.len() != computed.len() {
                raise(
                    CMS_R_MESSAGEDIGEST_WRONG_LENGTH,
                    "ossl_cms_DigestedData_do_final",
                );
                break 'err 0;
            }
            // SAFETY: two buffers of `computed.len()` octets.
            if unsafe {
                crate::mem::CRYPTO_memcmp(
                    stored.as_ptr().cast(),
                    computed.as_ptr().cast(),
                    computed.len(),
                )
            } != 0
            {
                raise(CMS_R_VERIFICATION_FAILURE, "ossl_cms_DigestedData_do_final");
                break 'err 0;
            }
            1
        } else {
            let n = c_int::try_from(computed.len()).unwrap_or(0);
            // SAFETY: the content's digest string; the digest's octets.
            c_int::from(
                unsafe { ASN1_STRING_set(dd.digest.cast(), computed.as_ptr().cast(), n) } != 0,
            )
        }
    };
    // SAFETY: the context made here.
    unsafe { crate::evp::md_ctx::EVP_MD_CTX_free(mctx) };
    r
}

ffi_export! {
    /// Encodes the ECC-CMS-SharedInfo for a key-agreement KDF (RFC 5753): the KEK algorithm,
    /// the UKM, and the key length in bits. The length, or -1.
    ///
    /// # Safety
    /// `pder` is as for `i2d_*`; `kekalg` a live algorithm identifier; `ukm` NULL or live.
    pub unsafe extern "C" fn CMS_SharedInfo_encode(pder: *mut *mut c_uchar, kekalg: *mut X509_ALGOR, ukm: *mut ASN1_OCTET_STRING, keylen: c_int) -> c_int
    where failure = -1, library = ERR_LIB_CMS
    {
        // OpenSSL's `keylen <<= 3`, in 32 bits.
        let bits = keylen.wrapping_shl(3).to_be_bytes();
        let mut kl = bits;
        let mut oklen = rustyssl_abi::ASN1_STRING { length: 4, type_: V_ASN1_OCTET_STRING, data: kl.as_mut_ptr(), flags: 0 };
        let si = super::SharedInfo { key_info: kekalg, entity_u_info: ukm, supp_pub_info: &raw mut oklen };
        // SAFETY: no preconditions.
        let it = unsafe { super::shared_info_it() };
        // SAFETY: the caller's guarantee; a local value of the item, alive for the call.
        unsafe { ASN1_item_i2d((&raw const si).cast(), pder, it) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: an object with no content type has no content, where OpenSSL reads
    /// its (NULL) content as an ANY.
    #[test]
    fn an_empty_object_has_no_content() {
        // SAFETY: no preconditions.
        let cms = unsafe { CMS_ContentInfo_new() };
        // SAFETY: the new object.
        assert!(unsafe { CMS_get0_content(cms) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { CMS_is_detached(cms) }, -1);
        // SAFETY: as above.
        assert!(unsafe { CMS_dataInit(cms, ptr::null_mut()) }.is_null());
        // SAFETY: the object, freed once.
        unsafe { CMS_ContentInfo_free(cms) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }
}
