//! CMP messages (`cmp_msg.c`): making one of each body type from the context (requests,
//! responses, revocation, confirmation, polling, general messages, errors), reading their parts,
//! the certificate in a response, and their DER and file I/O.
//!
//! The internal functions' `ossl_assert`s are plain checks: the reference build is NDEBUG, so a
//! failed one raises nothing.

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_OCTET_STRING, ASN1_TIME, ASN1_TYPE, BIO, CMP_R_BAD_REQUEST_ID, CMP_R_CERTID_NOT_FOUND,
    CMP_R_CERTIFICATE_NOT_FOUND, CMP_R_CERTREQMSG_NOT_FOUND, CMP_R_CERTRESPONSE_NOT_FOUND,
    CMP_R_ERROR_CREATING_CERTCONF, CMP_R_ERROR_CREATING_CERTREP, CMP_R_ERROR_CREATING_CERTREQ,
    CMP_R_ERROR_CREATING_ERROR, CMP_R_ERROR_CREATING_GENM, CMP_R_ERROR_CREATING_GENP,
    CMP_R_ERROR_CREATING_PKICONF, CMP_R_ERROR_CREATING_POLLREP, CMP_R_ERROR_CREATING_POLLREQ,
    CMP_R_ERROR_CREATING_RP, CMP_R_ERROR_CREATING_RR, CMP_R_FAIL_INFO_OUT_OF_RANGE,
    CMP_R_FAILED_EXTRACTING_CENTRAL_GEN_KEY, CMP_R_INVALID_ARGS, CMP_R_MISSING_CENTRAL_GEN_KEY,
    CMP_R_MISSING_P10CSR, CMP_R_MISSING_PRIVATE_KEY, CMP_R_MISSING_PRIVATE_KEY_FOR_POPO,
    CMP_R_MISSING_PUBLIC_KEY, CMP_R_MISSING_REFERENCE_CERT, CMP_R_NULL_ARGUMENT,
    CMP_R_PKISTATUSINFO_NOT_FOUND, CMP_R_UNEXPECTED_CENTRAL_GEN_KEY, CMP_R_UNEXPECTED_PKIBODY,
    CMP_R_UNKNOWN_CERT_TYPE, CMS_BINARY, CMS_EnvelopedData, CRL_REASON_NONE,
    CRMF_R_POPO_MISSING_PUBLIC_KEY, ERR_LIB_CMP, ERR_LIB_CMS, ERR_R_CMP_LIB,
    ERR_R_PASSED_NULL_PARAMETER, ERR_R_UNSUPPORTED, ERR_SYSTEM_FLAG, EVP_MD, EVP_PKEY,
    NID_certificate_policies, NID_crl_reason, NID_subject_alt_name, OSSL_CMP_CERTREPMESSAGE,
    OSSL_CMP_CERTRESPONSE, OSSL_CMP_CERTSTATUS, OSSL_CMP_CTX, OSSL_CMP_ITAV, OSSL_CMP_MSG,
    OSSL_CMP_OPT_POPO_METHOD, OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN, OSSL_CMP_PKIHEADER,
    OSSL_CMP_PKISI, OSSL_CMP_PKISTATUS_accepted, OSSL_CMP_PKISTATUS_rejection,
    OSSL_CMP_PKISTATUS_waiting, OSSL_CMP_POLLREP, OSSL_CMP_POLLREPCONTENT, OSSL_CMP_PVNO_3,
    OSSL_CMP_REVREPCONTENT, OSSL_CRMF_CERTID, OSSL_CRMF_ENCRYPTEDKEY, OSSL_CRMF_MSG,
    OSSL_CRMF_POPO_NONE, OSSL_CRMF_POPO_SIGNATURE, OSSL_LIB_CTX, SN_aes_256_cbc, V_ASN1_NULL, X509,
    X509_ADD_FLAG_NO_DUP, X509_ADD_FLAG_UP_REF, X509_NAME, X509_PUBKEY,
};

use super::asn::{
    CERTORENCCERT_CERTIFICATE, CERTORENCCERT_ENCRYPTEDCERT, CERTREQID, CERTREQID_INVALID,
    CERTREQID_NONE, CertRepMessage, CertResponse, CertStatus, CertifiedKeyPair, Choice,
    ErrorMsgContent, Msg, OSSL_CMP_ITAV_dup, OSSL_CMP_ITAV_free, OSSL_CMP_ITAV_push0_stack_item,
    OSSL_CMP_MSG_it, OSSL_CMP_PKISI_dup, OSSL_CMP_PKISI_free, PKIBODY_CERTCONF, PKIBODY_CP,
    PKIBODY_CR, PKIBODY_ERROR, PKIBODY_GENM, PKIBODY_GENP, PKIBODY_IP, PKIBODY_IR, PKIBODY_KUP,
    PKIBODY_KUR, PKIBODY_P10CR, PKIBODY_PKICONF, PKIBODY_POLLREP, PKIBODY_POLLREQ, PKIBODY_RP,
    PKIBODY_RR, PKIBODY_TYPE_MAX, PollRep, PollReq, RevDetails, RevRepContent, Stack, asn1_get_int,
    certifiedkeypair_it, certrepmessage_it, certresponse_it, certstatus_it, errormsgcontent_it, of,
    pollrep_it, pollreq_it, revdetails_it, revrepcontent_it,
};
use super::ctx::{
    Ctx, OSSL_CMP_CTX_get_option, OSSL_CMP_CTX_get0_newPkey, OSSL_CMP_CTX_reqExtensions_have_SAN,
    OSSL_CMP_CTX_set0_newPkey, ctx_get0_newPubkey, ctx_of,
};
use super::hdr::{
    hdr_generalInfo_push1_items, hdr_init, hdr_set_implicitConfirm, hdr_set_pvno,
    hdr_set_transactionID, is_null_dn,
};
use super::protect::{add_certs_new, msg_protect, set_own_chain};
use super::status::{OSSL_CMP_STATUSINFO_new, pkisi_get_status};
use super::util::{asn1_octet_string_set1, sk_ASN1_UTF8STRING_push_str};
use crate::asn1::any::ASN1_TYPE_set;
use crate::asn1::integer::{ASN1_ENUMERATED_set, ASN1_INTEGER_set, ASN1_INTEGER_set_int64};
use crate::asn1::string::{
    ASN1_ENUMERATED_free, ASN1_ENUMERATED_new, ASN1_INTEGER_new, ASN1_OCTET_STRING_free,
};
use crate::asn1::time::ASN1_TIME_adj;
use crate::asn1::tpl::decode::ASN1_item_d2i_ex;
use crate::asn1::tpl::encode::ASN1_item_i2d;
use crate::asn1::tpl::free::ASN1_item_free;
use crate::asn1::tpl::io::{ASN1_item_d2i_bio_ex, ASN1_item_i2d_bio};
use crate::asn1::tpl::items::{ASN1_TIME_free, ASN1_TYPE_new, X509_ALGOR_new};
use crate::asn1::tpl::new::ASN1_item_new_ex;
use crate::bio::file::BIO_new_file;
use crate::bio::mem::BIO_s_mem;
use crate::bio::{BIO_free, BIO_new};
use crate::cms::base::{CMS_ContentInfo_free, CMS_EnvelopedData_dup};
use crate::cms::smime::{CMS_encrypt_ex, CMS_sign_ex};
use crate::cms::{CMS_EnvelopedData_it, ContentInfo, signed_data_it};
use crate::crmf::asn::{
    OSSL_CRMF_CERTID_dup, OSSL_CRMF_CERTID_free, OSSL_CRMF_MSG_dup, OSSL_CRMF_MSG_free,
    OSSL_CRMF_MSG_new, OSSL_CRMF_MSGS_new, free_of, new_of,
};
use crate::crmf::msg::{
    OSSL_CRMF_CERTID_gen, OSSL_CRMF_CERTTEMPLATE_fill, OSSL_CRMF_CERTTEMPLATE_get0_publicKey,
    OSSL_CRMF_ENCRYPTEDKEY_get1_encCert, OSSL_CRMF_ENCRYPTEDKEY_get1_pkey,
    OSSL_CRMF_ENCRYPTEDKEY_init_envdata, OSSL_CRMF_MSG_create_popo, OSSL_CRMF_MSG_get0_tmpl,
    OSSL_CRMF_MSG_set_certReqId, OSSL_CRMF_MSG_set0_extensions, OSSL_CRMF_MSG_set0_validity,
    OSSL_CRMF_MSG_set1_regCtrl_oldCertID,
};
use crate::err;
use crate::err::strings::{ERR_lib_error_string, ERR_reason_error_string};
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free};
use crate::evp::digest::EVP_MD_free;
use crate::evp::pkey::i2d::i2d_PrivateKey_bio;
use crate::ffi::ffi_export;
use crate::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_pop_free,
    OPENSSL_sk_push, OPENSSL_sk_value,
};
use crate::x509::algor::X509_ALGOR_set_md;
use crate::x509::cert::{
    X509_chain_up_ref, X509_digest_sig, X509_dup, X509_free, X509_get_issuer_name,
    X509_get_subject_name, X509_get0_extensions, X509_get0_serialNumber, X509_up_ref, cert_of,
    set0_libctx,
};
use crate::x509::ext::{X509_EXTENSION_free, X509v3_add_ext, X509v3_add_extensions};
use crate::x509::pubkey::X509_PUBKEY_set0_public_key;
use crate::x509::purpose::X509_add_cert;
use crate::x509::req::{
    X509_REQ_dup, X509_REQ_get_extensions, X509_REQ_get_subject_name, X509_REQ_get0_pubkey,
};
use crate::x509v3::genn::GENERAL_NAME_free;
use crate::x509v3::registry::{X509V3_EXT_i2d, X509V3_get_d2i};

/// The message behind a handle.
///
/// # Safety
/// `msg` is NULL or a live message, not otherwise borrowed mutably.
unsafe fn msg_of<'a>(msg: *const OSSL_CMP_MSG) -> Option<&'a mut Msg> {
    // SAFETY: the caller's guarantee.
    unsafe { of::<Msg, _>(msg) }
}

/// The message's body, if it has one.
///
/// # Safety
/// As for [`msg_of`].
unsafe fn body_of<'a>(msg: *const OSSL_CMP_MSG) -> Option<&'a mut Choice> {
    // SAFETY: the caller's guarantee.
    let m = unsafe { msg_of(msg) }?;
    // SAFETY: the message's body, or NULL.
    unsafe { m.body.as_mut() }
}

/// `X509_free` as a stack's free function.
unsafe extern "C" fn free_cert(p: *mut c_void) {
    // SAFETY: a certificate of a list, which the list owned.
    unsafe { X509_free(p.cast()) };
}

/// `X509_EXTENSION_free` as a stack's free function.
unsafe extern "C" fn free_ext(p: *mut c_void) {
    // SAFETY: an extension of a list, which the list owned.
    unsafe { X509_EXTENSION_free(p.cast()) };
}

/// `GENERAL_NAME_free` as a stack's free function.
unsafe extern "C" fn free_gen(p: *mut c_void) {
    // SAFETY: a name of a list, which the list owned.
    unsafe { GENERAL_NAME_free(p.cast()) };
}

/// `OSSL_CMP_MSG_new` (not exported): an empty message with the library context and (copied)
/// properties; or NULL.
///
/// # Safety
/// `propq` is NULL or a NUL-terminated string.
pub(crate) unsafe fn msg_new(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut OSSL_CMP_MSG {
    // SAFETY: no preconditions.
    let it = unsafe { OSSL_CMP_MSG_it() };
    // SAFETY: the item; the caller's context and properties.
    let msg: *mut OSSL_CMP_MSG = unsafe { ASN1_item_new_ex(it, libctx, propq) }.cast();
    // SAFETY: the new message, or NULL; the caller's properties.
    if unsafe { msg_set0_libctx(msg, libctx, propq) } == 0 {
        // SAFETY: the message made here.
        unsafe { OSSL_CMP_MSG_free(msg) };
        return ptr::null_mut();
    }
    msg
}

ffi_export! {
    /// Frees a message (nothing for NULL).
    ///
    /// # Safety
    /// `msg` is NULL or a live message, not used after.
    pub unsafe extern "C" fn OSSL_CMP_MSG_free(msg: *mut OSSL_CMP_MSG)
    where failure = (), library = ERR_LIB_CMP
    {
        // SAFETY: no preconditions.
        let it = unsafe { OSSL_CMP_MSG_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_free(msg.cast(), it) };
    }
}

/// `ossl_cmp_msg_set0_libctx`: the message's library context and a copy of `propq`; 1, or 0.
/// Nothing (and 1) for NULL.
///
/// # Safety
/// `msg` is NULL or a live message; `propq` NULL or a NUL-terminated string.
pub(crate) unsafe fn msg_set0_libctx(
    msg: *mut OSSL_CMP_MSG,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the caller's guarantee.
    if let Some(m) = unsafe { msg_of(msg) } {
        // SAFETY: the message's slots; the caller's properties.
        if !unsafe { set0_libctx(&mut m.libctx, &mut m.propq, libctx, propq) } {
            return 0;
        }
    }
    1
}

ffi_export! {
    /// The message's header, or NULL (raising for a NULL message).
    ///
    /// # Safety
    /// `msg` is NULL or a live message.
    pub unsafe extern "C" fn OSSL_CMP_MSG_get0_header(msg: *const OSSL_CMP_MSG) -> *mut OSSL_CMP_PKIHEADER
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { msg_of(msg) }) else {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, "OSSL_CMP_MSG_get0_header");
            return ptr::null_mut();
        };
        m.header.cast()
    }
}

/// `ossl_cmp_bodytype_to_string`: a body type's name, or "illegal body type".
pub(crate) fn bodytype_to_string(type_: c_int) -> &'static CStr {
    const NAMES: [&CStr; 27] = [
        c"IR",
        c"IP",
        c"CR",
        c"CP",
        c"P10CR",
        c"POPDECC",
        c"POPDECR",
        c"KUR",
        c"KUP",
        c"KRR",
        c"KRP",
        c"RR",
        c"RP",
        c"CCR",
        c"CCP",
        c"CKUANN",
        c"CANN",
        c"RANN",
        c"CRLANN",
        c"PKICONF",
        c"NESTED",
        c"GENM",
        c"GENP",
        c"ERROR",
        c"CERTCONF",
        c"POLLREQ",
        c"POLLREP",
    ];
    if !(0..=PKIBODY_TYPE_MAX).contains(&type_) {
        return c"illegal body type";
    }
    usize::try_from(type_)
        .ok()
        .and_then(|i| NAMES.get(i).copied())
        .unwrap_or(c"illegal body type")
}

/// `ossl_cmp_msg_set_bodytype`: 1, or 0.
///
/// # Safety
/// `msg` is NULL or a live message.
pub(crate) unsafe fn msg_set_bodytype(msg: *mut OSSL_CMP_MSG, type_: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(b) = (unsafe { body_of(msg) }) else {
        return 0;
    };
    b.type_ = type_;
    1
}

ffi_export! {
    /// The message's body type, or -1.
    ///
    /// # Safety
    /// `msg` is NULL or a live message.
    pub unsafe extern "C" fn OSSL_CMP_MSG_get_bodytype(msg: *const OSSL_CMP_MSG) -> c_int
    where failure = -1, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        unsafe { body_of(msg) }.map_or(-1, |b| b.type_)
    }
}

ffi_export! {
    /// The public key of the first request in an IR, CR, or KUR, or NULL.
    ///
    /// # Safety
    /// `msg` is NULL or a live message.
    pub unsafe extern "C" fn OSSL_CMP_MSG_get0_certreq_publickey(msg: *const OSSL_CMP_MSG) -> *mut X509_PUBKEY
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        const F: &str = "OSSL_CMP_MSG_get0_certreq_publickey";
        // SAFETY: the caller's guarantee.
        match unsafe { OSSL_CMP_MSG_get_bodytype(msg) } {
            PKIBODY_IR | PKIBODY_CR | PKIBODY_KUR => {
                // SAFETY: a message with a body (its type was read).
                let Some(b) = (unsafe { body_of(msg) }) else {
                    return ptr::null_mut();
                };
                let reqs: *const Stack = b.value.cast();
                // SAFETY: the body's requests (the same for ir, cr, and kur), or NULL.
                let crm: *const OSSL_CRMF_MSG = unsafe { OPENSSL_sk_value(reqs, 0) }.cast();
                if crm.is_null() {
                    err::raise(ERR_LIB_CMP, CMP_R_CERTREQMSG_NOT_FOUND, F);
                    return ptr::null_mut();
                }
                // SAFETY: the request.
                let tmpl = unsafe { OSSL_CRMF_MSG_get0_tmpl(crm) };
                let pubkey = if tmpl.is_null() {
                    ptr::null_mut()
                } else {
                    // SAFETY: its template.
                    unsafe { OSSL_CRMF_CERTTEMPLATE_get0_publicKey(tmpl) }
                };
                if pubkey.is_null() {
                    err::raise(ERR_LIB_CMP, CRMF_R_POPO_MISSING_PUBLIC_KEY, F);
                    return ptr::null_mut();
                }
                pubkey
            }
            _ => {
                err::raise(ERR_LIB_CMP, CMP_R_UNEXPECTED_PKIBODY, F);
                ptr::null_mut()
            }
        }
    }
}

/// `add1_extension`: the extension `nid` of `ex` added to `*pexts` (made if NULL); true on
/// success.
///
/// # Safety
/// `*pexts` is NULL or a live list of extensions; `ex` the extension's live value.
unsafe fn add1_extension(pexts: &mut *mut Stack, nid: c_int, crit: c_int, ex: *mut c_void) -> bool {
    // SAFETY: the caller's value.
    let ext = unsafe { X509V3_EXT_i2d(nid, crit, ex) };
    if ext.is_null() {
        return false;
    }
    // SAFETY: the caller's list slot; the extension, which it copies.
    let res = !unsafe { X509v3_add_ext(ptr::from_mut(pexts).cast(), ext, 0) }.is_null();
    // SAFETY: made here.
    unsafe { X509_EXTENSION_free(ext) };
    res
}

/// `add_crl_reason_extension`: a CRL reason extension of `reason_code` added to `*pexts`.
///
/// # Safety
/// As for [`add1_extension`].
unsafe fn add_crl_reason_extension(pexts: &mut *mut Stack, reason_code: c_int) -> bool {
    // SAFETY: no preconditions.
    let val = unsafe { ASN1_ENUMERATED_new() };
    let mut res = false;
    // SAFETY: the new value, checked first.
    if !val.is_null() && unsafe { ASN1_ENUMERATED_set(val, reason_code.into()) } != 0 {
        // SAFETY: the caller's slot; the value.
        res = unsafe { add1_extension(pexts, NID_crl_reason, 0, val.cast()) };
    }
    // SAFETY: made here, or NULL.
    unsafe { ASN1_ENUMERATED_free(val) };
    res
}

/// `ossl_cmp_msg_create`: a message of `bodytype` with its header from the context and an
/// empty body; or NULL.
///
/// # Safety
/// `ctx` is NULL or a live context.
pub(crate) unsafe fn msg_create(ctx: *mut OSSL_CMP_CTX, bodytype: c_int) -> *mut OSSL_CMP_MSG {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return ptr::null_mut();
    };
    // SAFETY: the context's library context and properties.
    let msg = unsafe { msg_new(c.libctx, c.propq) };
    if msg.is_null() {
        return ptr::null_mut();
    }
    let ok = 'm: {
        // SAFETY: the message made here.
        let Some(m) = (unsafe { msg_of(msg) }) else {
            break 'm false;
        };
        // SAFETY: the caller's context; the message's header.
        if unsafe { hdr_init(ctx, m.header.cast()) } == 0
            // SAFETY: the message made here.
            || unsafe { msg_set_bodytype(msg, bodytype) } == 0
        {
            break 'm false;
        }
        // SAFETY: the caller's context, looked up again after the header's log callback.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            break 'm false;
        };
        if !c.geninfo_ITAVs.is_null()
            // SAFETY: the message's header; the context's items.
            && unsafe { hdr_generalInfo_push1_items(m.header.cast(), c.geninfo_ITAVs) } == 0
        {
            break 'm false;
        }
        // SAFETY: the message's body.
        let Some(b) = (unsafe { m.body.as_mut() }) else {
            break 'm false;
        };
        let value: *mut c_void = match bodytype {
            // SAFETY: no preconditions.
            PKIBODY_IR | PKIBODY_CR | PKIBODY_KUR => unsafe { OSSL_CRMF_MSGS_new() }.cast(),
            PKIBODY_P10CR => {
                if c.p10CSR.is_null() {
                    err::raise(ERR_LIB_CMP, CMP_R_MISSING_P10CSR, "ossl_cmp_msg_create");
                    break 'm false;
                }
                // SAFETY: the context's CSR.
                unsafe { X509_REQ_dup(c.p10CSR) }.cast()
            }
            PKIBODY_IP | PKIBODY_CP | PKIBODY_KUP => new_of(certrepmessage_it),
            // SAFETY: no preconditions, for each of the lists.
            PKIBODY_RR | PKIBODY_CERTCONF | PKIBODY_POLLREQ | PKIBODY_POLLREP | PKIBODY_GENM
            | PKIBODY_GENP => {
                // SAFETY: no preconditions.
                unsafe { OPENSSL_sk_new_null() }.cast()
            }
            PKIBODY_RP => new_of(revrepcontent_it),
            PKIBODY_PKICONF => {
                // SAFETY: no preconditions.
                let t: *mut ASN1_TYPE = unsafe { ASN1_TYPE_new() };
                if !t.is_null() {
                    // SAFETY: the new value.
                    unsafe { ASN1_TYPE_set(t, V_ASN1_NULL, ptr::null_mut()) };
                }
                t.cast()
            }
            PKIBODY_ERROR => new_of(errormsgcontent_it),
            _ => {
                err::raise(ERR_LIB_CMP, CMP_R_UNEXPECTED_PKIBODY, "ossl_cmp_msg_create");
                break 'm false;
            }
        };
        b.value = value;
        !value.is_null()
    };
    if ok {
        return msg;
    }
    // SAFETY: the message made here.
    unsafe { OSSL_CMP_MSG_free(msg) };
    ptr::null_mut()
}

/// `HAS_SAN`: subject alternative names to add, or among the requested extensions.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn has_san(ctx: *mut OSSL_CMP_CTX, c: &Ctx) -> bool {
    // SAFETY: the context's names, or NULL (0).
    (unsafe { OPENSSL_sk_num(c.subjectAltNames) }) > 0
        // SAFETY: the caller's context.
        || unsafe { OSSL_CMP_CTX_reqExtensions_have_SAN(ctx) } == 1
}

/// `IS_NULL_DN` of a name that may be NULL (a NULL name has no entries).
///
/// # Safety
/// `name` is NULL or a live name.
unsafe fn null_dn(name: *const X509_NAME) -> bool {
    // SAFETY: the caller's guarantee.
    name.is_null() || unsafe { is_null_dn(name) }
}

/// `determine_subj`: the template's subject.
///
/// # Safety
/// `ctx` is a live context; `ref_subj` NULL or a live name.
unsafe fn determine_subj(
    ctx: *mut OSSL_CMP_CTX,
    c: &Ctx,
    for_kur: bool,
    ref_subj: *const X509_NAME,
) -> *const X509_NAME {
    if !c.subjectName.is_null() {
        // SAFETY: the context's name.
        return if unsafe { null_dn(c.subjectName) } {
            ptr::null()
        } else {
            c.subjectName
        };
    }
    if !c.p10CSR.is_null() {
        // SAFETY: the context's CSR.
        return unsafe { X509_REQ_get_subject_name(c.p10CSR) };
    }
    // SAFETY: the caller's context.
    if for_kur || !unsafe { has_san(ctx, c) } {
        return ref_subj;
    }
    ptr::null()
}

ffi_export! {
    /// A certificate request message from the context (its new key, subject, issuer,
    /// validity, extensions, and for a KUR the old certificate's ID), with request ID `rid`;
    /// or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_CMP_CTX_setup_CRM(ctx: *mut OSSL_CMP_CTX, for_KUR: c_int, rid: c_int) -> *mut OSSL_CRMF_MSG
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        const F: &str = "OSSL_CMP_CTX_setup_CRM";
        // SAFETY: the caller's context.
        let central_keygen = unsafe { OSSL_CMP_CTX_get_option(ctx, OSSL_CMP_OPT_POPO_METHOD) } == OSSL_CRMF_POPO_NONE;
        // SAFETY: as above (OpenSSL dereferences it unchecked).
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            return ptr::null_mut();
        };
        let for_kur = for_KUR != 0;
        let refcert = if c.oldCert.is_null() { c.cert } else { c.oldCert };
        // SAFETY: the caller's context.
        let rkey = unsafe { ctx_get0_newPubkey(ctx) };
        let ref_subj = if refcert.is_null() {
            ptr::null()
        } else {
            // SAFETY: the reference certificate.
            unsafe { X509_get_subject_name(refcert) }
        };
        // SAFETY: the caller's context; a live name or NULL.
        let subject = unsafe { determine_subj(ctx, c, for_kur, ref_subj) };
        let issuer: *const X509_NAME = if !c.issuer.is_null() || refcert.is_null() {
            // SAFETY: the context's issuer, or NULL.
            if unsafe { null_dn(c.issuer) } { ptr::null() } else { c.issuer }
        } else {
            // SAFETY: the reference certificate.
            unsafe { X509_get_issuer_name(refcert) }
        };
        // RFC 5280: subjectAltName MUST be critical if the subject is empty.
        let crit = c_int::from(c.setSubjectAltNameCritical != 0 || subject.is_null());

        if rkey.is_null() && !central_keygen {
            err::raise(ERR_LIB_CMP, CMP_R_MISSING_PUBLIC_KEY, F);
            return ptr::null_mut();
        }
        if for_kur && refcert.is_null() && c.p10CSR.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_MISSING_REFERENCE_CERT, F);
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let mut crm = unsafe { OSSL_CRMF_MSG_new() };
        if crm.is_null() {
            return ptr::null_mut();
        }
        let mut exts: *mut Stack = ptr::null_mut();
        let mut default_sans: *mut Stack = ptr::null_mut();
        let ok = 'm: {
            // SAFETY: the request made here.
            let tmpl = unsafe { OSSL_CRMF_MSG_get0_tmpl(crm) };
            // SAFETY: as above.
            if unsafe { OSSL_CRMF_MSG_set_certReqId(crm, rid) } == 0
                // SAFETY: its template; the key, names (live or NULL).
                || unsafe { OSSL_CRMF_CERTTEMPLATE_fill(tmpl, rkey, subject, issuer, ptr::null()) } == 0
            {
                break 'm false;
            }
            if !rkey.is_null() && central_keygen {
                // SAFETY: the template's key.
                let pk = unsafe { OSSL_CRMF_CERTTEMPLATE_get0_publicKey(tmpl) };
                // SAFETY: the template's key.
                unsafe { X509_PUBKEY_set0_public_key(pk, ptr::null_mut(), 0) };
            }
            if c.days != 0 {
                // SAFETY: NULL asks for the time only.
                let now = unsafe { libc::time(ptr::null_mut()) };
                // SAFETY: a new time.
                let not_before: *mut ASN1_TIME = unsafe { ASN1_TIME_adj(ptr::null_mut(), now, 0, 0) };
                // SAFETY: as above.
                let not_after: *mut ASN1_TIME = unsafe { ASN1_TIME_adj(ptr::null_mut(), now, c.days, 0) };
                if not_before.is_null()
                    || not_after.is_null()
                    // SAFETY: the request; the times, which it takes.
                    || unsafe { OSSL_CRMF_MSG_set0_validity(crm, not_before, not_after) } == 0
                {
                    // SAFETY: made here, or NULL.
                    unsafe { ASN1_TIME_free(not_before) };
                    // SAFETY: as above.
                    unsafe { ASN1_TIME_free(not_after) };
                    break 'm false;
                }
            }
            if !c.p10CSR.is_null() {
                // SAFETY: the context's CSR.
                exts = unsafe { X509_REQ_get_extensions(c.p10CSR) }.cast();
                if exts.is_null() {
                    break 'm false;
                }
            }
            // SAFETY: the caller's context.
            if c.SubjectAltName_nodefault == 0 && !unsafe { has_san(ctx, c) } && !refcert.is_null() {
                // SAFETY: the reference certificate's extensions.
                let rexts = unsafe { X509_get0_extensions(refcert) };
                // SAFETY: as above.
                default_sans = unsafe { X509V3_get_d2i(rexts, NID_subject_alt_name, ptr::null_mut(), ptr::null_mut()) }.cast();
                if !default_sans.is_null()
                    // SAFETY: the list slot; the names.
                    && !unsafe { add1_extension(&mut exts, NID_subject_alt_name, crit, default_sans.cast()) }
                {
                    break 'm false;
                }
            }
            // SAFETY: the context's extensions, or NULL (0).
            if unsafe { OPENSSL_sk_num(c.reqExtensions) } > 0
                // SAFETY: the list slot; the context's extensions.
                && unsafe { X509v3_add_extensions((&raw mut exts).cast(), c.reqExtensions.cast()) }.is_null()
            {
                break 'm false;
            }
            // SAFETY: the context's names, or NULL (0).
            if unsafe { OPENSSL_sk_num(c.subjectAltNames) } > 0
                // SAFETY: the list slot; the context's names.
                && !unsafe { add1_extension(&mut exts, NID_subject_alt_name, crit, c.subjectAltNames.cast()) }
            {
                break 'm false;
            }
            if !c.policies.is_null()
                // SAFETY: the list slot; the context's policies.
                && !unsafe { add1_extension(&mut exts, NID_certificate_policies, c.setPoliciesCritical, c.policies.cast()) }
            {
                break 'm false;
            }
            // SAFETY: the request; the extensions, which it takes.
            if unsafe { OSSL_CRMF_MSG_set0_extensions(crm, exts.cast()) } == 0 {
                break 'm false;
            }
            exts = ptr::null_mut();
            if for_kur && !refcert.is_null() {
                // SAFETY: the reference certificate.
                let iss = unsafe { X509_get_issuer_name(refcert) };
                // SAFETY: as above.
                let serial = unsafe { X509_get0_serialNumber(refcert) };
                // SAFETY: its issuer and serial number.
                let cid = unsafe { OSSL_CRMF_CERTID_gen(iss, serial) };
                if cid.is_null() {
                    break 'm false;
                }
                // SAFETY: the request; the ID, which it copies.
                let ret = unsafe { OSSL_CRMF_MSG_set1_regCtrl_oldCertID(crm, cid) };
                // SAFETY: made here.
                unsafe { OSSL_CRMF_CERTID_free(cid) };
                if ret == 0 {
                    break 'm false;
                }
            }
            true
        };
        if !ok {
            // SAFETY: made here.
            unsafe { OSSL_CRMF_MSG_free(crm) };
            crm = ptr::null_mut();
        }
        // SAFETY: the extensions not taken, or NULL.
        unsafe { OPENSSL_sk_pop_free(exts, Some(free_ext)) };
        // SAFETY: the names decoded here, or NULL.
        unsafe { OPENSSL_sk_pop_free(default_sans, Some(free_gen)) };
        crm
    }
}

/// `ossl_cmp_certreq_new`: an IR, CR, KUR, or P10CR with `crm` (a copy) or one from the
/// context, protected; or NULL.
///
/// # Safety
/// `ctx` is NULL or a live context; `crm` NULL or a live request.
pub(crate) unsafe fn certreq_new(
    ctx: *mut OSSL_CMP_CTX,
    type_: c_int,
    crm: *const OSSL_CRMF_MSG,
) -> *mut OSSL_CMP_MSG {
    const F: &str = "ossl_cmp_certreq_new";
    if ctx.is_null() {
        return ptr::null_mut();
    }
    if !matches!(type_, PKIBODY_IR | PKIBODY_CR | PKIBODY_KUR | PKIBODY_P10CR)
        || (type_ == PKIBODY_P10CR && !crm.is_null())
    {
        err::raise(ERR_LIB_CMP, CMP_R_INVALID_ARGS, F);
        return ptr::null_mut();
    }
    let msg: *mut OSSL_CMP_MSG;
    let mut local_crm: *mut OSSL_CRMF_MSG = ptr::null_mut();
    let ok = 'm: {
        // SAFETY: the caller's context.
        msg = unsafe { msg_create(ctx, type_) };
        // SAFETY: the message made here, or NULL.
        let Some(m) = (unsafe { msg_of(msg) }) else {
            break 'm false;
        };
        // SAFETY: the caller's context.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            break 'm false;
        };
        // SAFETY: the message's header.
        if c.implicitConfirm != 0 && unsafe { hdr_set_implicitConfirm(m.header.cast()) } == 0 {
            break 'm false;
        }
        // For P10CR the body has its content from msg_create.
        if type_ != PKIBODY_P10CR {
            // SAFETY: the caller's context.
            let privkey = unsafe { OSSL_CMP_CTX_get0_newPkey(ctx, 1) };
            // SAFETY: as above.
            let Some(c) = (unsafe { ctx_of(ctx) }) else {
                break 'm false;
            };
            if c.popoMethod >= OSSL_CRMF_POPO_SIGNATURE && privkey.is_null() {
                err::raise(ERR_LIB_CMP, CMP_R_MISSING_PRIVATE_KEY_FOR_POPO, F);
                break 'm false;
            }
            if crm.is_null() {
                // SAFETY: the caller's context.
                local_crm = unsafe {
                    OSSL_CMP_CTX_setup_CRM(ctx, c_int::from(type_ == PKIBODY_KUR), CERTREQID)
                };
                // SAFETY: as above.
                let Some(c) = (unsafe { ctx_of(ctx) }) else {
                    break 'm false;
                };
                if local_crm.is_null()
                    // SAFETY: the request; the key; the context's digest and library context.
                    || unsafe { OSSL_CRMF_MSG_create_popo(c.popoMethod, local_crm, privkey, c.digest, c.libctx, c.propq) } == 0
                {
                    break 'm false;
                }
            } else {
                // SAFETY: the caller's request.
                local_crm = unsafe { OSSL_CRMF_MSG_dup(crm) };
                if local_crm.is_null() {
                    break 'm false;
                }
            }
            // SAFETY: the message's body.
            let Some(b) = (unsafe { m.body.as_ref() }) else {
                break 'm false;
            };
            // SAFETY: the body's requests (ir, cr, and kur alike); the request, which it takes.
            if unsafe { OPENSSL_sk_push(b.value.cast(), local_crm.cast()) } == 0 {
                break 'm false;
            }
            local_crm = ptr::null_mut();
        }
        // SAFETY: the caller's context; the message.
        (unsafe { msg_protect(ctx, msg) }) != 0
    };
    if ok {
        return msg;
    }
    err::raise(ERR_LIB_CMP, CMP_R_ERROR_CREATING_CERTREQ, F);
    // SAFETY: made here and not taken, or NULL.
    unsafe { OSSL_CRMF_MSG_free(local_crm) };
    // SAFETY: made here, or NULL.
    unsafe { OSSL_CMP_MSG_free(msg) };
    ptr::null_mut()
}

/// `ossl_cms_sign_encrypt` (`cms_lib.c`, internal): `data` signed with `sign_key` and
/// `sign_cert` (with `certs`), the SignedData's DER enveloped for `enc_recip`; or NULL.
///
/// # Safety
/// Each argument is NULL or live.
#[allow(clippy::too_many_arguments)]
unsafe fn cms_sign_encrypt(
    data: *mut BIO,
    sign_cert: *mut X509,
    certs: *mut Stack,
    sign_key: *mut EVP_PKEY,
    sign_flags: c_uint,
    enc_recip: *mut Stack,
    cipher: *const rustyssl_abi::EVP_CIPHER,
    enc_flags: c_uint,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> *mut CMS_EnvelopedData {
    if data.is_null() || sign_key.is_null() || sign_cert.is_null() || enc_recip.is_null() {
        err::raise(
            ERR_LIB_CMS,
            ERR_R_PASSED_NULL_PARAMETER,
            "ossl_cms_sign_encrypt",
        );
        return ptr::null_mut();
    }
    let mut evd = ptr::null_mut();
    let mut signbio = ptr::null_mut();
    let mut evpcms = ptr::null_mut();
    // SAFETY: the caller's objects.
    let signcms = unsafe {
        CMS_sign_ex(
            sign_cert,
            sign_key,
            certs.cast(),
            data,
            sign_flags,
            libctx,
            propq,
        )
    };
    'e: {
        // SAFETY: the structure made here, or NULL.
        let Some(sc) = (unsafe { signcms.cast::<ContentInfo>().as_ref() }) else {
            break 'e;
        };
        // SAFETY: no preconditions.
        let m = unsafe { BIO_s_mem() };
        // SAFETY: the built-in method.
        signbio = unsafe { BIO_new(m) };
        if signbio.is_null() {
            break 'e;
        }
        // SAFETY: no preconditions.
        let it = unsafe { signed_data_it() };
        // SAFETY: the item; the BIO; the structure's SignedData.
        if unsafe { ASN1_item_i2d_bio(it, signbio, sc.d.cast_const()) } <= 0 {
            break 'e;
        }
        // SAFETY: the caller's recipients and cipher; the BIO.
        evpcms =
            unsafe { CMS_encrypt_ex(enc_recip.cast(), signbio, cipher, enc_flags, libctx, propq) };
        // SAFETY: the structure made here, or NULL.
        let Some(ec) = (unsafe { evpcms.cast::<ContentInfo>().as_ref() }) else {
            break 'e;
        };
        // SAFETY: its EnvelopedData.
        evd = unsafe { CMS_EnvelopedData_dup(ec.d.cast()) };
    }
    // SAFETY: made here, or NULL.
    unsafe { BIO_free(signbio) };
    // SAFETY: as above.
    unsafe { CMS_ContentInfo_free(signcms) };
    // SAFETY: as above.
    unsafe { CMS_ContentInfo_free(evpcms) };
    evd
}

/// `enc_privkey`: `pkey` signed with the context's credentials and enveloped for the validated
/// server certificate (the client's, on the server side); or NULL.
///
/// # Safety
/// `ctx` is a live context; `pkey` a live key.
unsafe fn enc_privkey(
    ctx: *mut OSSL_CMP_CTX,
    pkey: *const EVP_PKEY,
) -> *mut OSSL_CRMF_ENCRYPTEDKEY {
    let mut ek = ptr::null_mut();
    let mut env_data: *mut CMS_EnvelopedData = ptr::null_mut();
    let mut privbio = ptr::null_mut();
    // SAFETY: no preconditions.
    let encryption_recips = unsafe { OPENSSL_sk_new_reserve(None, 1) };
    'e: {
        // SAFETY: the caller's context.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            break 'e;
        };
        let recip = c.validatedSrvCert;
        if encryption_recips.is_null()
            // SAFETY: the new list; the certificate (NULL raises).
            || unsafe { X509_add_cert(encryption_recips.cast(), recip, X509_ADD_FLAG_UP_REF) } == 0
        {
            break 'e;
        }
        // SAFETY: no preconditions.
        let m = unsafe { BIO_s_mem() };
        // SAFETY: the built-in method.
        privbio = unsafe { BIO_new(m) };
        // SAFETY: the BIO, checked first; the caller's key.
        if privbio.is_null() || unsafe { i2d_PrivateKey_bio(privbio, pkey) } <= 0 {
            break 'e;
        }
        // SAFETY: the caller's context.
        unsafe { set_own_chain(ctx) };
        // SAFETY: as above, looked up again.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            break 'e;
        };
        // SAFETY: the context's library context; a static name.
        let cipher = unsafe { EVP_CIPHER_fetch(c.libctx, SN_aes_256_cbc.as_ptr(), c.propq) };
        let binary = c_uint::try_from(CMS_BINARY).unwrap_or(0);
        // SAFETY: the BIO; the context's credentials; the recipients; the cipher, or NULL.
        env_data = unsafe {
            cms_sign_encrypt(
                privbio,
                c.cert,
                c.chain,
                c.pkey,
                binary,
                encryption_recips,
                cipher,
                binary,
                c.libctx,
                c.propq,
            )
        };
        // SAFETY: fetched here, or NULL.
        unsafe { EVP_CIPHER_free(cipher) };
        if env_data.is_null() {
            break 'e;
        }
        // SAFETY: the EnvelopedData, which it takes.
        ek = unsafe { OSSL_CRMF_ENCRYPTEDKEY_init_envdata(env_data) };
    }
    // SAFETY: the list made here, or NULL.
    unsafe { OPENSSL_sk_pop_free(encryption_recips, Some(free_cert)) };
    // SAFETY: made here, or NULL.
    unsafe { BIO_free(privbio) };
    if ek.is_null() && !env_data.is_null() {
        // SAFETY: no preconditions.
        let it = unsafe { CMS_EnvelopedData_it() };
        // SAFETY: the EnvelopedData made here and not taken.
        unsafe { ASN1_item_free(env_data.cast(), it) };
    }
    ek
}

/// `ossl_cmp_certrep_new`: an IP, CP, or KUP answering request `certReqId` with a copy of
/// `si` and, unless rejected or waiting, `cert` (and a centrally generated `pkey`, enveloped),
/// `chain` in the extra certificates and for an IP `caPubs`; protected unless it's an
/// unprotected rejection. Or NULL.
///
/// # Safety
/// `ctx` is NULL or a live context; the others NULL or live.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn certrep_new(
    ctx: *mut OSSL_CMP_CTX,
    bodytype: c_int,
    certReqId: c_int,
    si: *const OSSL_CMP_PKISI,
    cert: *mut X509,
    pkey: *const EVP_PKEY,
    encryption_recip: *const X509,
    chain: *mut Stack,
    caPubs: *mut Stack,
    unprotectedErrors: c_int,
) -> *mut OSSL_CMP_MSG {
    const F: &str = "ossl_cmp_certrep_new";
    if ctx.is_null() || si.is_null() {
        return ptr::null_mut();
    }
    let msg: *mut OSSL_CMP_MSG;
    let mut resp: *mut CertResponse = ptr::null_mut();
    let ok = 'm: {
        // SAFETY: the caller's context.
        msg = unsafe { msg_create(ctx, bodytype) };
        // SAFETY: the message made here, or NULL.
        let Some(m) = (unsafe { msg_of(msg) }) else {
            break 'm false;
        };
        // SAFETY: the message's body.
        let body = unsafe { m.body.as_ref() };
        // SAFETY: its value, the CertRepMessage (value.ip is the same for cp and kup).
        let Some(rep_msg) = body.and_then(|b| unsafe { b.value.cast::<CertRepMessage>().as_mut() })
        else {
            break 'm false;
        };
        // SAFETY: the caller's context.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            break 'm false;
        };
        // SAFETY: the message's header.
        if c.implicitConfirm != 0 && unsafe { hdr_set_implicitConfirm(m.header.cast()) } == 0 {
            break 'm false;
        }
        resp = new_of(certresponse_it).cast();
        // SAFETY: the response made here, or NULL.
        let Some(r) = (unsafe { resp.as_mut() }) else {
            break 'm false;
        };
        // SAFETY: its default status.
        unsafe { OSSL_CMP_PKISI_free(r.status.cast()) };
        // SAFETY: the caller's status.
        r.status = unsafe { OSSL_CMP_PKISI_dup(si) }.cast();
        if r.status.is_null()
            // SAFETY: its request ID.
            || unsafe { ASN1_INTEGER_set(r.certReqId, certReqId.into()) } == 0
        {
            break 'm false;
        }
        // SAFETY: its status.
        let status = unsafe { pkisi_get_status(r.status.cast()) };
        if status != OSSL_CMP_PKISTATUS_rejection
            && status != OSSL_CMP_PKISTATUS_waiting
            && !cert.is_null()
        {
            if !encryption_recip.is_null() {
                err::raise(ERR_LIB_CMP, ERR_R_UNSUPPORTED, F);
                break 'm false;
            }
            r.certifiedKeyPair = new_of(certifiedkeypair_it).cast();
            // SAFETY: the pair made here, or NULL.
            let Some(kp) = (unsafe { r.certifiedKeyPair.as_mut() }) else {
                break 'm false;
            };
            // SAFETY: its certOrEncCert, which the template made.
            let Some(coec) = (unsafe { kp.certOrEncCert.as_mut() }) else {
                break 'm false;
            };
            coec.type_ = CERTORENCCERT_CERTIFICATE;
            // SAFETY: the caller's certificate.
            if unsafe { X509_up_ref(cert) } == 0 {
                break 'm false;
            }
            coec.value = cert.cast();
            if !pkey.is_null() {
                // SAFETY: the caller's context and key.
                kp.privateKey = unsafe { enc_privkey(ctx, pkey) };
                if kp.privateKey.is_null() {
                    break 'm false;
                }
            }
        }
        // SAFETY: the message's responses; the response, which it takes.
        if unsafe { OPENSSL_sk_push(rep_msg.response, resp.cast()) } == 0 {
            break 'm false;
        }
        resp = ptr::null_mut();
        if bodytype == PKIBODY_IP && !caPubs.is_null() {
            // SAFETY: the caller's certificates.
            rep_msg.caPubs = unsafe { X509_chain_up_ref(caPubs.cast()) }.cast();
            if rep_msg.caPubs.is_null() {
                break 'm false;
            }
        }
        // SAFETY: the caller's chain, or NULL (0).
        if unsafe { OPENSSL_sk_num(chain) } > 0
            // SAFETY: the message's slot; the caller's chain.
            && !unsafe { add_certs_new(&mut m.extraCerts, chain, X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP) }
        {
            break 'm false;
        }
        // SAFETY: the caller's status.
        if (unprotectedErrors == 0 || unsafe { pkisi_get_status(si) } != OSSL_CMP_PKISTATUS_rejection)
            // SAFETY: the caller's context; the message.
            && unsafe { msg_protect(ctx, msg) } == 0
        {
            break 'm false;
        }
        true
    };
    if ok {
        return msg;
    }
    err::raise(ERR_LIB_CMP, CMP_R_ERROR_CREATING_CERTREP, F);
    // SAFETY: made here and not taken, or NULL.
    unsafe { free_of(resp.cast(), certresponse_it) };
    // SAFETY: made here, or NULL.
    unsafe { OSSL_CMP_MSG_free(msg) };
    ptr::null_mut()
}

/// `ossl_cmp_rr_new`: a revocation request for the context's certificate (by issuer and serial
/// number, the old certificate, or the CSR's key and subject), protected; or NULL.
///
/// # Safety
/// `ctx` is NULL or a live context.
pub(crate) unsafe fn rr_new(ctx: *mut OSSL_CMP_CTX) -> *mut OSSL_CMP_MSG {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return ptr::null_mut();
    };
    if c.oldCert.is_null() && c.p10CSR.is_null() && (c.serialNumber.is_null() || c.issuer.is_null())
    {
        return ptr::null_mut();
    }
    let mut msg = ptr::null_mut();
    let mut rd: *mut RevDetails = new_of(revdetails_it).cast();
    let ok = 'm: {
        // SAFETY: the details made here, or NULL.
        let Some(d) = (unsafe { rd.as_mut() }) else {
            break 'm false;
        };
        let mut issuer: *const X509_NAME = ptr::null();
        let mut subject: *const X509_NAME = ptr::null();
        let mut serial: *const rustyssl_abi::ASN1_INTEGER = ptr::null();
        let mut pubkey: *mut EVP_PKEY = ptr::null_mut();
        if !c.serialNumber.is_null() && !c.issuer.is_null() {
            issuer = c.issuer;
            serial = c.serialNumber;
        } else if !c.oldCert.is_null() {
            // SAFETY: the context's old certificate.
            issuer = unsafe { X509_get_issuer_name(c.oldCert) };
            // SAFETY: as above.
            serial = unsafe { X509_get0_serialNumber(c.oldCert) };
        } else if !c.p10CSR.is_null() {
            // SAFETY: the context's CSR.
            pubkey = unsafe { X509_REQ_get0_pubkey(c.p10CSR) };
            // SAFETY: as above.
            subject = unsafe { X509_REQ_get_subject_name(c.p10CSR) };
        } else {
            break 'm false;
        }
        // SAFETY: the details' template; live values or NULL.
        if unsafe { OSSL_CRMF_CERTTEMPLATE_fill(d.certDetails, pubkey, subject, issuer, serial) }
            == 0
        {
            break 'm false;
        }
        if c.revocationReason != CRL_REASON_NONE
            // SAFETY: the details' extensions slot.
            && !unsafe { add_crl_reason_extension(&mut d.crlEntryDetails, c.revocationReason) }
        {
            break 'm false;
        }
        // SAFETY: the caller's context.
        msg = unsafe { msg_create(ctx, PKIBODY_RR) };
        // SAFETY: the message's body, or NULL.
        let Some(b) = (unsafe { body_of(msg) }) else {
            break 'm false;
        };
        // SAFETY: the body's list; the details, which it takes.
        if unsafe { OPENSSL_sk_push(b.value.cast(), rd.cast()) } == 0 {
            break 'm false;
        }
        rd = ptr::null_mut();
        // SAFETY: the caller's context; the message.
        (unsafe { msg_protect(ctx, msg) }) != 0
    };
    if ok {
        return msg;
    }
    err::raise(ERR_LIB_CMP, CMP_R_ERROR_CREATING_RR, "ossl_cmp_rr_new");
    // SAFETY: made here, or NULL.
    unsafe { OSSL_CMP_MSG_free(msg) };
    // SAFETY: made here and not taken, or NULL.
    unsafe { free_of(rd.cast(), revdetails_it) };
    ptr::null_mut()
}

/// `ossl_cmp_rp_new`: a revocation response with a copy of `si` and of `cid` (if not NULL),
/// protected unless it's an unprotected rejection; or NULL.
///
/// # Safety
/// `ctx` is NULL or a live context; `si` NULL or a live PKIStatusInfo; `cid` NULL or a live ID.
pub(crate) unsafe fn rp_new(
    ctx: *mut OSSL_CMP_CTX,
    si: *const OSSL_CMP_PKISI,
    cid: *const OSSL_CRMF_CERTID,
    unprotectedErrors: c_int,
) -> *mut OSSL_CMP_MSG {
    if ctx.is_null() || si.is_null() {
        return ptr::null_mut();
    }
    let msg: *mut OSSL_CMP_MSG;
    let mut si1: *mut OSSL_CMP_PKISI = ptr::null_mut();
    let mut cid_copy: *mut OSSL_CRMF_CERTID = ptr::null_mut();
    let ok = 'm: {
        // SAFETY: the caller's context.
        msg = unsafe { msg_create(ctx, PKIBODY_RP) };
        // SAFETY: the message's body, or NULL.
        let Some(b) = (unsafe { body_of(msg) }) else {
            break 'm false;
        };
        // SAFETY: the body's content, made by msg_create.
        let Some(rep) = (unsafe { b.value.cast::<RevRepContent>().as_mut() }) else {
            break 'm false;
        };
        // SAFETY: the caller's status.
        si1 = unsafe { OSSL_CMP_PKISI_dup(si) };
        // SAFETY: the content's list; the copy, which it takes.
        if si1.is_null() || unsafe { OPENSSL_sk_push(rep.status, si1.cast()) } == 0 {
            break 'm false;
        }
        si1 = ptr::null_mut();
        // SAFETY: no preconditions.
        rep.revCerts = unsafe { OPENSSL_sk_new_null() };
        if rep.revCerts.is_null() {
            break 'm false;
        }
        if !cid.is_null() {
            // SAFETY: the caller's ID.
            cid_copy = unsafe { OSSL_CRMF_CERTID_dup(cid) };
            // SAFETY: the content's list; the copy, which it takes.
            if cid_copy.is_null() || unsafe { OPENSSL_sk_push(rep.revCerts, cid_copy.cast()) } == 0
            {
                break 'm false;
            }
            cid_copy = ptr::null_mut();
        }
        // SAFETY: the caller's status.
        if (unprotectedErrors == 0 || unsafe { pkisi_get_status(si) } != OSSL_CMP_PKISTATUS_rejection)
            // SAFETY: the caller's context; the message.
            && unsafe { msg_protect(ctx, msg) } == 0
        {
            break 'm false;
        }
        true
    };
    if ok {
        return msg;
    }
    err::raise(ERR_LIB_CMP, CMP_R_ERROR_CREATING_RP, "ossl_cmp_rp_new");
    // SAFETY: made here and not taken, or NULL.
    unsafe { OSSL_CMP_PKISI_free(si1) };
    // SAFETY: as above.
    unsafe { OSSL_CRMF_CERTID_free(cid_copy) };
    // SAFETY: made here, or NULL.
    unsafe { OSSL_CMP_MSG_free(msg) };
    ptr::null_mut()
}

/// `ossl_cmp_pkiconf_new`: a protected PKIConf; or NULL.
///
/// # Safety
/// `ctx` is NULL or a live context.
pub(crate) unsafe fn pkiconf_new(ctx: *mut OSSL_CMP_CTX) -> *mut OSSL_CMP_MSG {
    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller's context.
    let msg = unsafe { msg_create(ctx, PKIBODY_PKICONF) };
    // SAFETY: the caller's context; the message, checked first.
    if !msg.is_null() && unsafe { msg_protect(ctx, msg) } != 0 {
        return msg;
    }
    err::raise(
        ERR_LIB_CMP,
        CMP_R_ERROR_CREATING_PKICONF,
        "ossl_cmp_pkiconf_new",
    );
    // SAFETY: made here, or NULL.
    unsafe { OSSL_CMP_MSG_free(msg) };
    ptr::null_mut()
}

/// `ossl_cmp_msg_gen_push0_ITAV`: `itav` (taken) onto a GENM's or GENP's items; 1, or 0.
///
/// # Safety
/// `msg` is NULL or a live message; `itav` NULL or a live item.
pub(crate) unsafe fn msg_gen_push0_ITAV(msg: *mut OSSL_CMP_MSG, itav: *mut OSSL_CMP_ITAV) -> c_int {
    if msg.is_null() || itav.is_null() {
        return 0;
    }
    // SAFETY: the caller's message.
    let bodytype = unsafe { OSSL_CMP_MSG_get_bodytype(msg) };
    if bodytype != PKIBODY_GENM && bodytype != PKIBODY_GENP {
        err::raise(
            ERR_LIB_CMP,
            CMP_R_INVALID_ARGS,
            "ossl_cmp_msg_gen_push0_ITAV",
        );
        return 0;
    }
    // SAFETY: the message's body (it has a type).
    let Some(b) = (unsafe { body_of(msg) }) else {
        return 0;
    };
    // SAFETY: the body's list slot (genm and genp alike); the caller's item.
    unsafe { OSSL_CMP_ITAV_push0_stack_item((&raw mut b.value).cast(), itav) }
}

/// `ossl_cmp_msg_gen_push1_ITAVs`: copies of `itavs` onto a GENM's or GENP's items; 1, or 0.
///
/// # Safety
/// `msg` is NULL or a live message; `itavs` NULL or a live list of items.
pub(crate) unsafe fn msg_gen_push1_ITAVs(msg: *mut OSSL_CMP_MSG, itavs: *const Stack) -> c_int {
    if msg.is_null() {
        return 0;
    }
    // SAFETY: the caller's list, or NULL (0).
    let n = unsafe { OPENSSL_sk_num(itavs) };
    for i in 0..n {
        // SAFETY: an index in range.
        let item = unsafe { OPENSSL_sk_value(itavs, i) };
        // SAFETY: an item of the list.
        let itav = unsafe { OSSL_CMP_ITAV_dup(item.cast()) };
        // SAFETY: the caller's message; the copy, checked first, which it takes.
        if itav.is_null() || unsafe { msg_gen_push0_ITAV(msg, itav) } == 0 {
            // SAFETY: the copy, not taken, or NULL.
            unsafe { OSSL_CMP_ITAV_free(itav) };
            return 0;
        }
    }
    1
}

/// `gen_new`: a protected GENM or GENP with copies of `itavs`; or NULL (raising `err_code`).
///
/// # Safety
/// `ctx` is NULL or a live context; `itavs` NULL or a live list of items.
unsafe fn gen_new(
    ctx: *mut OSSL_CMP_CTX,
    itavs: *const Stack,
    body_type: c_int,
    err_code: c_int,
) -> *mut OSSL_CMP_MSG {
    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller's context.
    let msg = unsafe { msg_create(ctx, body_type) };
    if msg.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the message; the caller's items.
    if (itavs.is_null() || unsafe { msg_gen_push1_ITAVs(msg, itavs) } != 0)
        // SAFETY: the caller's context; the message.
        && unsafe { msg_protect(ctx, msg) } != 0
    {
        return msg;
    }
    err::raise(ERR_LIB_CMP, err_code, "gen_new");
    // SAFETY: made here.
    unsafe { OSSL_CMP_MSG_free(msg) };
    ptr::null_mut()
}

/// `ossl_cmp_genm_new`: a GENM with the context's items.
///
/// # Safety
/// `ctx` is a live context.
pub(crate) unsafe fn genm_new(ctx: *mut OSSL_CMP_CTX) -> *mut OSSL_CMP_MSG {
    // SAFETY: the caller's guarantee (OpenSSL dereferences it unchecked).
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return ptr::null_mut();
    };
    let items = c.genm_ITAVs;
    // SAFETY: the caller's context; its items.
    unsafe { gen_new(ctx, items, PKIBODY_GENM, CMP_R_ERROR_CREATING_GENM) }
}

/// `ossl_cmp_genp_new`: a GENP with copies of `itavs`.
///
/// # Safety
/// `ctx` is NULL or a live context; `itavs` NULL or a live list of items.
pub(crate) unsafe fn genp_new(ctx: *mut OSSL_CMP_CTX, itavs: *const Stack) -> *mut OSSL_CMP_MSG {
    // SAFETY: the caller's guarantee.
    unsafe { gen_new(ctx, itavs, PKIBODY_GENP, CMP_R_ERROR_CREATING_GENP) }
}

/// `ossl_cmp_error_new`: an error message with a copy of `si`, `errorCode`, and as details the
/// code's library and reason strings and `details`; protected unless `unprotected`. Or NULL.
///
/// # Safety
/// `ctx` is NULL or a live context; `si` NULL or a live PKIStatusInfo; `details` NULL or a
/// NUL-terminated string.
pub(crate) unsafe fn error_new(
    ctx: *mut OSSL_CMP_CTX,
    si: *const OSSL_CMP_PKISI,
    errorCode: i64,
    details: *const c_char,
    unprotected: c_int,
) -> *mut OSSL_CMP_MSG {
    if ctx.is_null() || si.is_null() {
        return ptr::null_mut();
    }
    let msg: *mut OSSL_CMP_MSG;
    let ok = 'm: {
        // SAFETY: the caller's context.
        msg = unsafe { msg_create(ctx, PKIBODY_ERROR) };
        // SAFETY: the message's body, or NULL.
        let Some(b) = (unsafe { body_of(msg) }) else {
            break 'm false;
        };
        // SAFETY: the body's content, made by msg_create.
        let Some(e) = (unsafe { b.value.cast::<ErrorMsgContent>().as_mut() }) else {
            break 'm false;
        };
        // SAFETY: its default status.
        unsafe { OSSL_CMP_PKISI_free(e.pKIStatusInfo.cast()) };
        // SAFETY: the caller's status.
        e.pKIStatusInfo = unsafe { OSSL_CMP_PKISI_dup(si) }.cast();
        if e.pKIStatusInfo.is_null() {
            break 'm false;
        }
        // SAFETY: no preconditions.
        e.errorCode = unsafe { ASN1_INTEGER_new() };
        // SAFETY: the new integer, checked first.
        if e.errorCode.is_null() || unsafe { ASN1_INTEGER_set_int64(e.errorCode, errorCode) } == 0 {
            break 'm false;
        }
        let (mut lib, mut reason) = (ptr::null(), ptr::null());
        let limit = u64::from(ERR_SYSTEM_FLAG) << 1;
        if let Ok(code) = u64::try_from(errorCode)
            && code > 0
            && code < limit
            && let Ok(code) = c_ulong::try_from(code)
        {
            // SAFETY: no preconditions.
            lib = unsafe { ERR_lib_error_string(code) };
            // SAFETY: as above.
            reason = unsafe { ERR_reason_error_string(code) };
        }
        if !lib.is_null() || !reason.is_null() || !details.is_null() {
            // SAFETY: no preconditions.
            let ft = unsafe { OPENSSL_sk_new_null() };
            if ft.is_null() {
                break 'm false;
            }
            e.errorDetails = ft;
            for text in [lib, reason] {
                // SAFETY: a static NUL-terminated string, checked first.
                if !text.is_null() && unsafe { text.read() } != 0
                    // SAFETY: the details; the string.
                    && unsafe { sk_ASN1_UTF8STRING_push_str(ft.cast(), text, -1) } == 0
                {
                    break 'm false;
                }
            }
            // SAFETY: the details; the caller's string, checked first.
            if !details.is_null()
                // SAFETY: the details; the caller's string, checked first.
                && unsafe { sk_ASN1_UTF8STRING_push_str(ft.cast(), details, -1) } == 0
            {
                break 'm false;
            }
        }
        // SAFETY: the caller's context; the message.
        unprotected != 0 || unsafe { msg_protect(ctx, msg) } != 0
    };
    if ok {
        return msg;
    }
    err::raise(
        ERR_LIB_CMP,
        CMP_R_ERROR_CREATING_ERROR,
        "ossl_cmp_error_new",
    );
    // SAFETY: made here, or NULL.
    unsafe { OSSL_CMP_MSG_free(msg) };
    ptr::null_mut()
}

/// `ossl_cmp_certstatus_set0_certHash`: `hash` (taken) as the status's certificate hash,
/// freeing the old one; 1, or 0.
///
/// # Safety
/// `certStatus` is NULL or a live status; `hash` NULL or a live string.
pub(crate) unsafe fn certstatus_set0_certHash(
    certStatus: *mut OSSL_CMP_CERTSTATUS,
    hash: *mut ASN1_OCTET_STRING,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(cs) = (unsafe { of::<CertStatus, _>(certStatus) }) else {
        return 0;
    };
    // SAFETY: its old hash, or NULL.
    unsafe { ASN1_OCTET_STRING_free(cs.certHash) };
    cs.certHash = hash;
    1
}

/// `ossl_cmp_certConf_new`: a protected certConf for the context's new certificate (its hash
/// with its signature's digest, or a fallback one named in `hashAlg` with version 3), accepting
/// it, or rejecting it with `fail_info`; with `text`. Or NULL.
///
/// # Safety
/// `ctx` is NULL or a live context; `text` NULL or a NUL-terminated string.
pub(crate) unsafe fn certConf_new(
    ctx: *mut OSSL_CMP_CTX,
    certReqId: c_int,
    fail_info: c_int,
    text: *const c_char,
) -> *mut OSSL_CMP_MSG {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return ptr::null_mut();
    };
    if c.newCert.is_null() || (certReqId != CERTREQID && certReqId != CERTREQID_NONE) {
        return ptr::null_mut();
    }
    // OpenSSL compares `(unsigned)fail_info`: a negative one is out of range too.
    if !(0..=OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN).contains(&fail_info) {
        err::raise(
            ERR_LIB_CMP,
            CMP_R_FAIL_INFO_OUT_OF_RANGE,
            "ossl_cmp_certConf_new",
        );
        return ptr::null_mut();
    }
    let msg: *mut OSSL_CMP_MSG;
    let mut cert_hash: *mut ASN1_OCTET_STRING = ptr::null_mut();
    let ok = 'm: {
        // SAFETY: the caller's context.
        msg = unsafe { msg_create(ctx, PKIBODY_CERTCONF) };
        // SAFETY: the message made here, or NULL.
        let Some(m) = (unsafe { msg_of(msg) }) else {
            break 'm false;
        };
        // SAFETY: its body.
        let Some(b) = (unsafe { m.body.as_ref() }) else {
            break 'm false;
        };
        let cert_status: *mut CertStatus = new_of(certstatus_it).cast();
        if cert_status.is_null() {
            break 'm false;
        }
        // Into the message right away, to go with it.
        // SAFETY: the body's list; the status, which it takes.
        if unsafe { OPENSSL_sk_push(b.value.cast(), cert_status.cast()) } < 1 {
            // SAFETY: made here and not taken.
            unsafe { free_of(cert_status.cast(), certstatus_it) };
            break 'm false;
        }
        // SAFETY: the status, now the message's.
        let Some(cs) = (unsafe { cert_status.as_mut() }) else {
            break 'm false;
        };
        // SAFETY: its request ID.
        if unsafe { ASN1_INTEGER_set(cs.certReqId, certReqId.into()) } == 0 {
            break 'm false;
        }
        cs.hashAlg = ptr::null_mut();
        // SAFETY: the caller's context, looked up again after the header's log callback.
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            break 'm false;
        };
        let mut md: *mut EVP_MD = ptr::null_mut();
        let mut is_fallback = 0;
        // SAFETY: the context's new certificate; the rooms.
        cert_hash = unsafe { X509_digest_sig(c.newCert, &raw mut md, &raw mut is_fallback) };
        if cert_hash.is_null() {
            break 'm false;
        }
        if is_fallback != 0 {
            // SAFETY: the message's header.
            let ok = unsafe { hdr_set_pvno(m.header.cast(), OSSL_CMP_PVNO_3) } != 0 && {
                // SAFETY: no preconditions.
                cs.hashAlg = unsafe { X509_ALGOR_new() };
                !cs.hashAlg.is_null()
            };
            if !ok {
                // SAFETY: fetched by the digest.
                unsafe { EVP_MD_free(md) };
                break 'm false;
            }
            // SAFETY: the new algorithm; the digest.
            unsafe { X509_ALGOR_set_md(cs.hashAlg, md) };
        }
        // SAFETY: fetched by the digest, or NULL.
        unsafe { EVP_MD_free(md) };
        // SAFETY: the status; the hash, which it takes.
        if unsafe { certstatus_set0_certHash(cert_status.cast(), cert_hash) } == 0 {
            break 'm false;
        }
        cert_hash = ptr::null_mut();
        // No statusInfo would mean acceptance too; OpenSSL always gives one.
        let sinfo = if fail_info != 0 {
            // SAFETY: the caller's text.
            unsafe { OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_rejection, fail_info, text) }
        } else {
            // SAFETY: as above.
            unsafe { OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_accepted, 0, text) }
        };
        if sinfo.is_null() {
            break 'm false;
        }
        cs.statusInfo = sinfo.cast();
        // SAFETY: the caller's context; the message.
        (unsafe { msg_protect(ctx, msg) }) != 0
    };
    if ok {
        return msg;
    }
    err::raise(
        ERR_LIB_CMP,
        CMP_R_ERROR_CREATING_CERTCONF,
        "ossl_cmp_certConf_new",
    );
    // SAFETY: made here, or NULL.
    unsafe { OSSL_CMP_MSG_free(msg) };
    // SAFETY: made here and not taken, or NULL.
    unsafe { ASN1_OCTET_STRING_free(cert_hash) };
    ptr::null_mut()
}

/// `ossl_cmp_pollReq_new`: a protected pollReq for request `crid`; or NULL.
///
/// # Safety
/// `ctx` is NULL or a live context.
pub(crate) unsafe fn pollReq_new(ctx: *mut OSSL_CMP_CTX, crid: c_int) -> *mut OSSL_CMP_MSG {
    if ctx.is_null() {
        return ptr::null_mut();
    }
    let msg: *mut OSSL_CMP_MSG;
    let mut preq: *mut PollReq = ptr::null_mut();
    let ok = 'm: {
        // SAFETY: the caller's context.
        msg = unsafe { msg_create(ctx, PKIBODY_POLLREQ) };
        // SAFETY: the message's body, or NULL.
        let Some(b) = (unsafe { body_of(msg) }) else {
            break 'm false;
        };
        preq = new_of(pollreq_it).cast();
        // SAFETY: made here, or NULL.
        let Some(p) = (unsafe { preq.as_mut() }) else {
            break 'm false;
        };
        // SAFETY: its request ID.
        if unsafe { ASN1_INTEGER_set(p.certReqId, crid.into()) } == 0
            // SAFETY: the body's list; the request, which it takes.
            || unsafe { OPENSSL_sk_push(b.value.cast(), preq.cast()) } == 0
        {
            break 'm false;
        }
        preq = ptr::null_mut();
        // SAFETY: the caller's context; the message.
        (unsafe { msg_protect(ctx, msg) }) != 0
    };
    if ok {
        return msg;
    }
    err::raise(
        ERR_LIB_CMP,
        CMP_R_ERROR_CREATING_POLLREQ,
        "ossl_cmp_pollReq_new",
    );
    // SAFETY: made here and not taken, or NULL.
    unsafe { free_of(preq.cast(), pollreq_it) };
    // SAFETY: made here, or NULL.
    unsafe { OSSL_CMP_MSG_free(msg) };
    ptr::null_mut()
}

/// `ossl_cmp_pollRep_new`: a protected pollRep for request `crid`, to check after `poll_after`
/// seconds; or NULL.
///
/// # Safety
/// `ctx` is NULL or a live context.
pub(crate) unsafe fn pollRep_new(
    ctx: *mut OSSL_CMP_CTX,
    crid: c_int,
    poll_after: i64,
) -> *mut OSSL_CMP_MSG {
    if ctx.is_null() {
        return ptr::null_mut();
    }
    let msg: *mut OSSL_CMP_MSG;
    let ok = 'm: {
        // SAFETY: the caller's context.
        msg = unsafe { msg_create(ctx, PKIBODY_POLLREP) };
        // SAFETY: the message's body, or NULL.
        let Some(b) = (unsafe { body_of(msg) }) else {
            break 'm false;
        };
        let prep: *mut PollRep = new_of(pollrep_it).cast();
        if prep.is_null() {
            break 'm false;
        }
        // SAFETY: the body's list; the response, which it takes.
        if unsafe { OPENSSL_sk_push(b.value.cast(), prep.cast()) } == 0 {
            // OpenSSL leaks it here.
            // SAFETY: made here and not taken.
            unsafe { free_of(prep.cast(), pollrep_it) };
            break 'm false;
        }
        // SAFETY: the response, now the message's.
        let Some(p) = (unsafe { prep.as_mut() }) else {
            break 'm false;
        };
        // SAFETY: its request ID.
        if unsafe { ASN1_INTEGER_set(p.certReqId, crid.into()) } == 0
            // SAFETY: its time to check after.
            || unsafe { ASN1_INTEGER_set_int64(p.checkAfter, poll_after) } == 0
        {
            break 'm false;
        }
        // SAFETY: the caller's context; the message.
        (unsafe { msg_protect(ctx, msg) }) != 0
    };
    if ok {
        return msg;
    }
    err::raise(
        ERR_LIB_CMP,
        CMP_R_ERROR_CREATING_POLLREP,
        "ossl_cmp_pollRep_new",
    );
    // SAFETY: made here, or NULL.
    unsafe { OSSL_CMP_MSG_free(msg) };
    ptr::null_mut()
}

/// `ossl_cmp_revrepcontent_get_pkisi`: the status at `rsid`, or NULL (raising).
///
/// # Safety
/// `rrep` is NULL or a live content.
pub(crate) unsafe fn revrepcontent_get_pkisi(
    rrep: *mut OSSL_CMP_REVREPCONTENT,
    rsid: c_int,
) -> *mut OSSL_CMP_PKISI {
    // SAFETY: the caller's guarantee.
    let Some(r) = (unsafe { of::<RevRepContent, _>(rrep) }) else {
        return ptr::null_mut();
    };
    // SAFETY: its list, or NULL; any index.
    let status: *mut OSSL_CMP_PKISI = unsafe { OPENSSL_sk_value(r.status, rsid) }.cast();
    if status.is_null() {
        err::raise(
            ERR_LIB_CMP,
            CMP_R_PKISTATUSINFO_NOT_FOUND,
            "ossl_cmp_revrepcontent_get_pkisi",
        );
    }
    status
}

/// `ossl_cmp_revrepcontent_get_CertId`: the certificate ID at `rsid`, or NULL (raising).
///
/// # Safety
/// `rrep` is NULL or a live content.
pub(crate) unsafe fn revrepcontent_get_CertId(
    rrep: *mut OSSL_CMP_REVREPCONTENT,
    rsid: c_int,
) -> *mut OSSL_CRMF_CERTID {
    // SAFETY: the caller's guarantee.
    let Some(r) = (unsafe { of::<RevRepContent, _>(rrep) }) else {
        return ptr::null_mut();
    };
    // SAFETY: its list, or NULL; any index.
    let cid: *mut OSSL_CRMF_CERTID = unsafe { OPENSSL_sk_value(r.revCerts, rsid) }.cast();
    if cid.is_null() {
        err::raise(
            ERR_LIB_CMP,
            CMP_R_CERTID_NOT_FOUND,
            "ossl_cmp_revrepcontent_get_CertId",
        );
    }
    cid
}

/// `suitable_rid`: whether `certReqId` is `rid` (any for `CERTREQID_NONE`).
///
/// # Safety
/// `certReqId` is NULL or a live integer.
unsafe fn suitable_rid(certReqId: *const rustyssl_abi::ASN1_INTEGER, rid: c_int) -> bool {
    if rid == CERTREQID_NONE {
        return true;
    }
    // SAFETY: the caller's guarantee.
    let trid = unsafe { asn1_get_int(certReqId) };
    if trid <= CERTREQID_INVALID {
        err::raise(ERR_LIB_CMP, CMP_R_BAD_REQUEST_ID, "suitable_rid");
        return false;
    }
    rid == trid
}

/// `ossl_cmp_pollrepcontent_get0_pollrep`: the poll response for `rid` (the first for -1), or
/// NULL (raising).
///
/// # Safety
/// `prc` is NULL or a live list of poll responses.
pub(crate) unsafe fn pollrepcontent_get0_pollrep(
    prc: *const OSSL_CMP_POLLREPCONTENT,
    rid: c_int,
) -> *mut OSSL_CMP_POLLREP {
    if prc.is_null() {
        return ptr::null_mut();
    }
    let list: *const Stack = prc.cast();
    // SAFETY: the caller's list.
    let n = unsafe { OPENSSL_sk_num(list) };
    for i in 0..n {
        // SAFETY: an index in range.
        let p: *mut PollRep = unsafe { OPENSSL_sk_value(list, i) }.cast();
        // SAFETY: a response of the list (OpenSSL dereferences it unchecked).
        let Some(pr) = (unsafe { p.as_ref() }) else {
            continue;
        };
        // SAFETY: its request ID.
        if unsafe { suitable_rid(pr.certReqId, rid) } {
            return p.cast();
        }
    }
    err::raise_with_text(
        ERR_LIB_CMP,
        CMP_R_CERTRESPONSE_NOT_FOUND,
        "ossl_cmp_pollrepcontent_get0_pollrep",
        &format!("expected certReqId = {rid}"),
    );
    ptr::null_mut()
}

/// `ossl_cmp_certrepmessage_get0_certresponse`: the response for `rid` (the first for -1), or
/// NULL (raising).
///
/// # Safety
/// `crm` is NULL or a live message.
pub(crate) unsafe fn certrepmessage_get0_certresponse(
    crm: *const OSSL_CMP_CERTREPMESSAGE,
    rid: c_int,
) -> *mut OSSL_CMP_CERTRESPONSE {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { of::<CertRepMessage, _>(crm) }) else {
        return ptr::null_mut();
    };
    if c.response.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: its responses.
    let n = unsafe { OPENSSL_sk_num(c.response) };
    for i in 0..n {
        // SAFETY: an index in range.
        let r: *mut CertResponse = unsafe { OPENSSL_sk_value(c.response, i) }.cast();
        // SAFETY: a response of the list (OpenSSL dereferences it unchecked).
        let Some(cr) = (unsafe { r.as_ref() }) else {
            continue;
        };
        // SAFETY: its request ID.
        if unsafe { suitable_rid(cr.certReqId, rid) } {
            return r.cast();
        }
    }
    err::raise_with_text(
        ERR_LIB_CMP,
        CMP_R_CERTRESPONSE_NOT_FOUND,
        "ossl_cmp_certrepmessage_get0_certresponse",
        &format!("expected certReqId = {rid}"),
    );
    ptr::null_mut()
}

/// `ossl_cmp_certresponse_get1_cert`: a copy of the response's certificate (decrypted with the
/// new or current private key when encrypted for indirect POPO), storing a centrally generated
/// key in the context; or NULL (raising).
///
/// # Safety
/// `ctx` is NULL or a live context; `crep` NULL or a live response.
pub(crate) unsafe fn certresponse_get1_cert(
    ctx: *const OSSL_CMP_CTX,
    crep: *const OSSL_CMP_CERTRESPONSE,
) -> *mut X509 {
    const F: &str = "ossl_cmp_certresponse_get1_cert";
    // SAFETY: the caller's context.
    let central_keygen =
        unsafe { OSSL_CMP_CTX_get_option(ctx, OSSL_CMP_OPT_POPO_METHOD) } == OSSL_CRMF_POPO_NONE;
    // SAFETY: the caller's response (OpenSSL dereferences it unchecked).
    let Some(r) = (unsafe { of::<CertResponse, _>(crep) }) else {
        return ptr::null_mut();
    };
    // SAFETY: its pair, or NULL.
    let Some(kp) = (unsafe { r.certifiedKeyPair.cast::<CertifiedKeyPair>().as_ref() }) else {
        err::raise(ERR_LIB_CMP, CMP_R_CERTIFICATE_NOT_FOUND, F);
        return ptr::null_mut();
    };
    let encr_key = kp.privateKey;
    if encr_key.is_null() && central_keygen {
        err::raise(ERR_LIB_CMP, CMP_R_MISSING_CENTRAL_GEN_KEY, F);
        return ptr::null_mut();
    }
    if !encr_key.is_null() {
        if !central_keygen {
            err::raise(ERR_LIB_CMP, CMP_R_UNEXPECTED_CENTRAL_GEN_KEY, F);
            return ptr::null_mut();
        }
        // SAFETY: the caller's context (central key generation was read from it).
        let Some(c) = (unsafe { ctx_of(ctx) }) else {
            return ptr::null_mut();
        };
        // SAFETY: the encrypted key; the context's trust, credentials, and secret.
        let pkey = unsafe {
            OSSL_CRMF_ENCRYPTEDKEY_get1_pkey(
                encr_key,
                c.trusted,
                c.untrusted.cast(),
                c.pkey,
                c.cert,
                c.secretValue,
                c.libctx,
                c.propq,
            )
        };
        if pkey.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_FAILED_EXTRACTING_CENTRAL_GEN_KEY, F);
            return ptr::null_mut();
        }
        // SAFETY: the context, which OpenSSL casts to mutable; the key, which it takes.
        unsafe { OSSL_CMP_CTX_set0_newPkey(ctx.cast_mut(), 1, pkey) };
    }
    // SAFETY: the caller's context.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return ptr::null_mut();
    };
    let mut crt: *mut X509 = ptr::null_mut();
    // SAFETY: its certOrEncCert, or NULL.
    if let Some(coec) = unsafe { kp.certOrEncCert.as_ref() } {
        match coec.type_ {
            CERTORENCCERT_CERTIFICATE => {
                // SAFETY: the response's certificate.
                crt = unsafe { X509_dup(coec.value.cast()) };
            }
            CERTORENCCERT_ENCRYPTEDCERT => {
                // The certificate encrypted for indirect POPO (RFC 9810, 5.2.8.3.2).
                // SAFETY: the caller's context.
                let pkey = unsafe { OSSL_CMP_CTX_get0_newPkey(ctx, 1) };
                if pkey.is_null() {
                    err::raise(ERR_LIB_CMP, CMP_R_MISSING_PRIVATE_KEY, F);
                    return ptr::null_mut();
                }
                // SAFETY: the encrypted certificate; the context's library context; the key.
                crt = unsafe {
                    OSSL_CRMF_ENCRYPTEDKEY_get1_encCert(
                        coec.value.cast(),
                        c.libctx,
                        c.propq,
                        pkey,
                        0,
                    )
                };
            }
            _ => {
                err::raise(ERR_LIB_CMP, CMP_R_UNKNOWN_CERT_TYPE, F);
                return ptr::null_mut();
            }
        }
    }
    if crt.is_null() {
        err::raise(ERR_LIB_CMP, CMP_R_CERTIFICATE_NOT_FOUND, F);
        return crt;
    }
    // SAFETY: the copy made here.
    if let Some(x) = unsafe { cert_of(crt) } {
        // SAFETY: its slots; the context's properties. OpenSSL ignores a failure here.
        unsafe { set0_libctx(&mut x.libctx, &mut x.propq, c.libctx, c.propq) };
    }
    crt
}

ffi_export! {
    /// The context's transaction ID (a new one if it has none) into the message, protecting it
    /// again if it was protected: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `msg` NULL or a live message.
    pub unsafe extern "C" fn OSSL_CMP_MSG_update_transactionID(ctx: *mut OSSL_CMP_CTX, msg: *mut OSSL_CMP_MSG) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { msg_of(msg) }) else {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, "OSSL_CMP_MSG_update_transactionID");
            return 0;
        };
        if ctx.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, "OSSL_CMP_MSG_update_transactionID");
            return 0;
        }
        // SAFETY: the caller's context; the message's header.
        if unsafe { hdr_set_transactionID(ctx, m.header.cast()) } == 0 {
            return 0;
        }
        // SAFETY: the message's header (OpenSSL dereferences it unchecked).
        let protected = unsafe { m.header.as_ref() }.is_some_and(|h| !h.protectionAlg.is_null());
        // SAFETY: the caller's context and message.
        c_int::from(!protected || unsafe { msg_protect(ctx, msg) } != 0)
    }
}

ffi_export! {
    /// The context's recipient nonce (if any) into the message, protecting it again if it was
    /// protected: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `msg` NULL or a live message.
    pub unsafe extern "C" fn OSSL_CMP_MSG_update_recipNonce(ctx: *mut OSSL_CMP_CTX, msg: *mut OSSL_CMP_MSG) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: the caller's guarantee.
        let c = unsafe { ctx_of(ctx) };
        // SAFETY: as above.
        let m = unsafe { msg_of(msg) };
        // SAFETY: the message's header, or NULL.
        let (Some(c), Some(h)) = (c, m.and_then(|m| unsafe { m.header.as_mut() })) else {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, "OSSL_CMP_MSG_update_recipNonce");
            return 0;
        };
        // Nothing to do for a transaction's first message.
        if c.recipNonce.is_null() {
            return 1;
        }
        // SAFETY: the header's slot; the context's nonce.
        if unsafe { asn1_octet_string_set1(&mut h.recipNonce, c.recipNonce) } == 0 {
            return 0;
        }
        let protected = !h.protectionAlg.is_null();
        // SAFETY: the caller's context and message.
        c_int::from(!protected || unsafe { msg_protect(ctx, msg) } != 0)
    }
}

ffi_export! {
    /// The message in DER file `file`, with the library context and properties; or NULL.
    ///
    /// # Safety
    /// `file` is NULL or a NUL-terminated name; `propq` NULL or a NUL-terminated string.
    pub unsafe extern "C" fn OSSL_CMP_MSG_read(file: *const c_char, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut OSSL_CMP_MSG
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        if file.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, "OSSL_CMP_MSG_read");
            return ptr::null_mut();
        }
        // SAFETY: the caller's properties.
        let mut msg = unsafe { msg_new(libctx, propq) };
        if msg.is_null() {
            err::raise(ERR_LIB_CMP, ERR_R_CMP_LIB, "OSSL_CMP_MSG_read");
            return ptr::null_mut();
        }
        // SAFETY: the caller's name; a static mode.
        let bio = unsafe { BIO_new_file(file, c"rb".as_ptr()) };
        // SAFETY: the BIO, checked first; the message's slot.
        if bio.is_null() || unsafe { d2i_OSSL_CMP_MSG_bio(bio, &raw mut msg) }.is_null() {
            // SAFETY: the message, or NULL when the decoding freed it.
            unsafe { OSSL_CMP_MSG_free(msg) };
            msg = ptr::null_mut();
        }
        // SAFETY: made here, or NULL.
        unsafe { BIO_free(bio) };
        msg
    }
}

ffi_export! {
    /// The message's DER into file `file`: 1, 0 on an encoding error, -1 for NULL arguments,
    /// -2 if the file can't be opened.
    ///
    /// # Safety
    /// `file` is NULL or a NUL-terminated name; `msg` NULL or a live message.
    pub unsafe extern "C" fn OSSL_CMP_MSG_write(file: *const c_char, msg: *const OSSL_CMP_MSG) -> c_int
    where failure = -1, library = ERR_LIB_CMP
    {
        if file.is_null() || msg.is_null() {
            err::raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT, "OSSL_CMP_MSG_write");
            return -1;
        }
        // SAFETY: the caller's name; a static mode.
        let bio = unsafe { BIO_new_file(file, c"wb".as_ptr()) };
        if bio.is_null() {
            return -2;
        }
        // SAFETY: the BIO; the caller's message.
        let res = unsafe { i2d_OSSL_CMP_MSG_bio(bio, msg) };
        // SAFETY: made here.
        unsafe { BIO_free(bio) };
        res
    }
}

/// The library context and properties of `*msg`, if there is one.
///
/// # Safety
/// `msg` is NULL or points to NULL or a live message.
unsafe fn existing_libctx(msg: *mut *mut OSSL_CMP_MSG) -> (*mut OSSL_LIB_CTX, *const c_char) {
    // SAFETY: the caller's slot, or NULL.
    let Some(&old) = (unsafe { msg.as_ref() }) else {
        return (ptr::null_mut(), ptr::null());
    };
    // SAFETY: the message in it, or NULL.
    unsafe { msg_of(old) }.map_or((ptr::null_mut(), ptr::null()), |m| {
        (m.libctx, m.propq.cast_const())
    })
}

ffi_export! {
    /// Decodes a message from `len` octets at `*in_` (reusing `*msg`'s library context and
    /// properties); or NULL.
    ///
    /// # Safety
    /// As for `d2i_X509`.
    pub unsafe extern "C" fn d2i_OSSL_CMP_MSG(msg: *mut *mut OSSL_CMP_MSG, in_: *mut *const c_uchar, len: c_long) -> *mut OSSL_CMP_MSG
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's slot.
        let (libctx, propq) = unsafe { existing_libctx(msg) };
        // SAFETY: no preconditions.
        let it = unsafe { OSSL_CMP_MSG_it() };
        // SAFETY: the caller's guarantee; the item.
        unsafe { ASN1_item_d2i_ex(msg.cast(), in_, len, it, libctx, propq) }.cast()
    }
}

ffi_export! {
    /// Encodes the message (see `i2d_X509`).
    ///
    /// # Safety
    /// As for `i2d_X509`.
    pub unsafe extern "C" fn i2d_OSSL_CMP_MSG(msg: *const OSSL_CMP_MSG, out: *mut *mut c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_CMP
    {
        // SAFETY: no preconditions.
        let it = unsafe { OSSL_CMP_MSG_it() };
        // SAFETY: the caller's guarantee; the item.
        unsafe { ASN1_item_i2d(msg.cast(), out, it) }
    }
}

ffi_export! {
    /// Decodes a message from the BIO (reusing `*msg`'s library context and properties); or
    /// NULL.
    ///
    /// # Safety
    /// `bio` is NULL or a live BIO; `msg` NULL or points to NULL or a live message.
    pub unsafe extern "C" fn d2i_OSSL_CMP_MSG_bio(bio: *mut BIO, msg: *mut *mut OSSL_CMP_MSG) -> *mut OSSL_CMP_MSG
    where failure = ptr::null_mut(), library = ERR_LIB_CMP
    {
        // SAFETY: the caller's slot.
        let (libctx, propq) = unsafe { existing_libctx(msg) };
        // SAFETY: no preconditions.
        let it = unsafe { OSSL_CMP_MSG_it() };
        // SAFETY: the item; the caller's BIO and slot.
        unsafe { ASN1_item_d2i_bio_ex(it, bio, msg.cast(), libctx, propq) }.cast()
    }
}

ffi_export! {
    /// The message's DER to the BIO: 1, or 0.
    ///
    /// # Safety
    /// `bio` is NULL or a live BIO; `msg` NULL or a live message.
    pub unsafe extern "C" fn i2d_OSSL_CMP_MSG_bio(bio: *mut BIO, msg: *const OSSL_CMP_MSG) -> c_int
    where failure = 0, library = ERR_LIB_CMP
    {
        // SAFETY: no preconditions.
        let it = unsafe { OSSL_CMP_MSG_it() };
        // SAFETY: the item; the caller's BIO and message.
        unsafe { ASN1_item_i2d_bio(it, bio, msg.cast()) }
    }
}

/// `ossl_cmp_is_error_with_waiting`: whether the message is an error with status waiting.
///
/// # Safety
/// `msg` is NULL or a live message.
pub(crate) unsafe fn is_error_with_waiting(msg: *const OSSL_CMP_MSG) -> c_int {
    if msg.is_null() {
        return 0;
    }
    // SAFETY: the caller's message.
    if unsafe { OSSL_CMP_MSG_get_bodytype(msg) } != PKIBODY_ERROR {
        return 0;
    }
    // SAFETY: an error message's body and content.
    let e =
        unsafe { body_of(msg) }.and_then(|b| unsafe { b.value.cast::<ErrorMsgContent>().as_ref() });
    let Some(e) = e else {
        return 0;
    };
    // SAFETY: its status.
    c_int::from(unsafe { pkisi_get_status(e.pKIStatusInfo.cast()) } == OSSL_CMP_PKISTATUS_waiting)
}
