//! Certificate requests (`X509_REQ_new(3)`, `X509_REQ_get_extensions(3)`, `X509_REQ_sign(3)`;
//! `x_req.c`, `x509_req.c`, `x509rset.c`, `x509_r2x.c`, and the request parts of `x_all.c`):
//! `X509_REQ` as OpenSSL's reference-counted SEQUENCE over its own structure, its
//! CertificationRequestInfo (`X509_REQ_INFO`) keeping the DER it was decoded from until it
//! changes, with its attributes and the extensions requested in them.
//!
//! As in OpenSSL:
//! - A new request has an empty attribute set, which is encoded (`[0] {}`), and version 1.
//! - Requests only have version 1: `X509_REQ_set_version` refuses another, and verifying one of
//!   another version fails with `X509_R_UNSUPPORTED_VERSION`.
//! - The extensions are an `extensionRequest` attribute (or Microsoft's), its value a
//!   SEQUENCE OF Extension; adding more merges them into it.
//! - A copy has its own copy of the public key.
//!
//! Where OpenSSL reads through a NULL request, these answer NULL or 0 (docs/DEVIATIONS.md).

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::mem::offset_of;
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicPtr, Ordering};

use libc::FILE;
use rustyssl_abi::{
    ASN1_AFLG_ENCODING, ASN1_AFLG_REFCOUNT, ASN1_BIT_STRING, ASN1_ENCODING, ASN1_INTEGER,
    ASN1_ITEM, ASN1_OBJECT, ASN1_OCTET_STRING, ASN1_OP_D2I_PRE, ASN1_OP_DUP_POST,
    ASN1_OP_FREE_POST, ASN1_OP_GET0_LIBCTX, ASN1_OP_GET0_PROPQ, ASN1_OP_NEW_POST, ASN1_TFLG_EMBED,
    ASN1_TFLG_IMPLICIT, ASN1_TFLG_OPTIONAL, ASN1_TFLG_SET_OF, ASN1_VALUE, BIO, CRYPTO_RWLOCK,
    ERR_LIB_ASN1, ERR_LIB_X509, ERR_R_ASN1_LIB, ERR_R_EVP_LIB, ERR_R_INTERNAL_ERROR,
    ERR_R_PASSED_INVALID_ARGUMENT, ERR_R_PASSED_NULL_PARAMETER, EVP_MD, EVP_MD_CTX, EVP_PKEY,
    NID_ext_req, NID_ms_ext_req, NID_undef, OSSL_LIB_CTX, V_ASN1_SEQUENCE, X509, X509_ALGOR,
    X509_ATTRIBUTE, X509_NAME, X509_PUBKEY, X509_R_UNSUPPORTED_VERSION, X509_R_WRONG_TYPE,
    X509_REQ, X509_REQ_INFO, X509_REQ_VERSION_1, stack_st_X509_ATTRIBUTE, stack_st_X509_EXTENSION,
};

use super::algor::X509_ALGOR_copy;
use super::attrib::{
    X509_ATTRIBUTE_free, X509_ATTRIBUTE_get0_type, X509_ATTRIBUTE_it, X509at_add1_attr,
    X509at_add1_attr_by_NID, X509at_add1_attr_by_OBJ, X509at_add1_attr_by_txt, X509at_delete_attr,
    X509at_get_attr, X509at_get_attr_by_NID, X509at_get_attr_by_OBJ, X509at_get_attr_count,
};
use super::cert::{
    X509_free, X509_get0_pubkey, X509_gmtime_adj, X509_new, X509_set_issuer_name, X509_set_pubkey,
    X509_set_subject_name, X509_sign, cert_of, check_private_key, set0_libctx,
};
use super::ext::{X509_EXTENSION_free, X509_EXTENSIONS_it, X509v3_add_extensions};
use super::name::{X509_NAME_it, X509_NAME_set};
use super::pubkey::{X509_PUBKEY_get, X509_PUBKEY_get0, X509_PUBKEY_it, X509_PUBKEY_set};
use crate::asn1::integer::{ASN1_INTEGER_get, ASN1_INTEGER_set};
use crate::asn1::sign::{ASN1_item_sign_ctx, ASN1_item_sign_ex, ASN1_item_verify_ex};
use crate::asn1::string::{
    ASN1_BIT_STRING_free, ASN1_INTEGER_new, ASN1_OCTET_STRING_free, ASN1_STRING_set,
};
use crate::asn1::tpl::decode::ASN1_item_d2i;
use crate::asn1::tpl::encode::ASN1_item_i2d;
use crate::asn1::tpl::io::{
    ASN1_item_d2i_bio_ex, ASN1_item_d2i_fp, ASN1_item_i2d_bio, ASN1_item_i2d_fp,
};
use crate::asn1::tpl::items::{
    ASN1_BIT_STRING_it, ASN1_INTEGER_it, X509_ALGOR_it, d2i, i2d, new_free,
};
use crate::asn1::tpl::new::ASN1_item_new;
use crate::asn1::tpl::statics::{Aux, Templates, aux_ex, sequence};
use crate::asn1::tpl::util::{ASN1_item_dup, item_digest_ex};
use crate::asn1::tpl::{item_fns, template_at};
use crate::err;
use crate::evp::legacy_md::EVP_md5;
use crate::evp::pkey::{EVP_PKEY_dup, EVP_PKEY_free};
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::objects::OBJ_obj2nid;
use crate::stack::{OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free};

/// `X509_REQ_INFO` (`X509_req_info_st`): the CertificationRequestInfo.
#[repr(C)]
pub(crate) struct ReqInfo {
    /// The DER it was decoded from, until it changes (`modified`).
    pub(crate) enc: ASN1_ENCODING,
    pub(crate) version: *mut ASN1_INTEGER,
    pub(crate) subject: *mut X509_NAME,
    pub(crate) pubkey: *mut X509_PUBKEY,
    pub(crate) attributes: *mut stack_st_X509_ATTRIBUTE,
}

/// `X509_REQ` (`X509_req_st`).
#[repr(C)]
pub(crate) struct Req {
    pub(crate) req_info: ReqInfo,
    pub(crate) sig_alg: X509_ALGOR,
    pub(crate) signature: *mut ASN1_BIT_STRING,
    references: c_int,
    lock: *mut CRYPTO_RWLOCK,
    pub(crate) distinguishing_id: *mut ASN1_OCTET_STRING,
    pub(crate) libctx: *mut OSSL_LIB_CTX,
    pub(crate) propq: *mut c_char,
}

static INFO_TT: Templates<4> = Templates([
    template_at(
        0,
        0,
        offset_of!(ReqInfo, version),
        c"version",
        ASN1_INTEGER_it,
    ),
    template_at(0, 0, offset_of!(ReqInfo, subject), c"subject", X509_NAME_it),
    template_at(0, 0, offset_of!(ReqInfo, pubkey), c"pubkey", X509_PUBKEY_it),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(ReqInfo, attributes),
        c"attributes",
        X509_ATTRIBUTE_it,
    ),
]);

ffi_callback! {
    /// `rinf_cb`: a new CertificationRequestInfo has an empty attribute set.
    ///
    /// # Safety
    /// `pval` holds NULL or a live CertificationRequestInfo.
    pub(crate) unsafe extern "C" fn rinf_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, _exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let v = unsafe { pval.read() };
        // SAFETY: as above.
        let Some(r) = (unsafe { v.cast::<ReqInfo>().as_mut() }) else { return 1 };
        if operation == ASN1_OP_NEW_POST {
            // SAFETY: no preconditions.
            r.attributes = unsafe { OPENSSL_sk_new_null() }.cast();
            if r.attributes.is_null() {
                return 0;
            }
        }
        1
    }
}

/// `ASN1_SEQUENCE_enc` with `rinf_cb`.
static INFO_AUX: Aux = aux_ex(
    ASN1_AFLG_ENCODING,
    0,
    0,
    Some(rinf_cb),
    offset_of!(ReqInfo, enc),
);

item_fns! {
    /// CertificationRequestInfo.
    pub unsafe extern "C" fn X509_REQ_INFO_it = sequence::<ReqInfo, 4>(&INFO_TT, Some(&INFO_AUX), c"X509_REQ_INFO");
}

new_free! {
    pub unsafe extern "C" fn X509_REQ_INFO_new, pub unsafe extern "C" fn X509_REQ_INFO_free(X509_REQ_INFO) = X509_REQ_INFO_it;
}

i2d! {
    /// Encodes a CertificationRequestInfo (as it was decoded, unless it changed).
    pub unsafe extern "C" fn i2d_X509_REQ_INFO(X509_REQ_INFO) = X509_REQ_INFO_it;
}

d2i! {
    /// Decodes a CertificationRequestInfo (`ASN1_item_d2i`), keeping its encoding.
    pub unsafe extern "C" fn d2i_X509_REQ_INFO(X509_REQ_INFO) = X509_REQ_INFO_it;
}

static REQ_TT: Templates<3> = Templates([
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Req, req_info),
        c"req_info",
        X509_REQ_INFO_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Req, sig_alg),
        c"sig_alg",
        X509_ALGOR_it,
    ),
    template_at(
        0,
        0,
        offset_of!(Req, signature),
        c"signature",
        ASN1_BIT_STRING_it,
    ),
]);

/// `ASN1_SEQUENCE_ref` with `req_cb`.
static REQ_AUX: Aux = aux_ex(
    ASN1_AFLG_REFCOUNT,
    offset_of!(Req, references),
    offset_of!(Req, lock),
    Some(req_cb),
    0,
);

ffi_callback! {
    /// `req_cb`: a new or re-decoded request has no distinguishing ID; freeing frees it and
    /// the properties; a copy takes the original's library context and its own copy of the
    /// public key; the library context and properties are given to the decoder and encoder.
    ///
    /// # Safety
    /// `pval` holds NULL or a live request; `exarg` is the operation's.
    pub(crate) unsafe extern "C" fn req_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let v = unsafe { pval.read() };
        // SAFETY: as above.
        let Some(r) = (unsafe { v.cast::<Req>().as_mut() }) else { return 1 };
        match operation {
            ASN1_OP_D2I_PRE | ASN1_OP_NEW_POST => {
                if operation == ASN1_OP_D2I_PRE {
                    // SAFETY: its own, or NULL.
                    unsafe { ASN1_OCTET_STRING_free(r.distinguishing_id) };
                }
                r.distinguishing_id = ptr::null_mut();
                1
            }
            ASN1_OP_FREE_POST => {
                // SAFETY: as above.
                unsafe { ASN1_OCTET_STRING_free(r.distinguishing_id) };
                r.distinguishing_id = ptr::null_mut();
                // SAFETY: its own copy, or NULL.
                unsafe { mem::release(r.propq.cast()) };
                r.propq = ptr::null_mut();
                1
            }
            ASN1_OP_DUP_POST => {
                // SAFETY: the original, which the copy was made from.
                let Some(old) = (unsafe { exarg.cast::<Req>().as_ref() }) else { return 1 };
                // SAFETY: its properties, NULL or a string.
                if !unsafe { set0_libctx(&mut r.libctx, &mut r.propq, old.libctx, old.propq) } {
                    return 0;
                }
                // SAFETY: the original's key, or NULL.
                let pkey = unsafe { X509_PUBKEY_get0(old.req_info.pubkey) };
                if pkey.is_null() {
                    return 1;
                }
                // SAFETY: the original's key.
                let pkey = unsafe { EVP_PKEY_dup(pkey) };
                if pkey.is_null() {
                    err::raise(ERR_LIB_X509, ERR_R_EVP_LIB, "req_cb");
                    return 0;
                }
                // SAFETY: the copy's slot; the key's copy.
                let ok = unsafe { X509_PUBKEY_set(&raw mut r.req_info.pubkey, pkey) } != 0;
                // SAFETY: made above, kept by the SubjectPublicKeyInfo if set.
                unsafe { EVP_PKEY_free(pkey) };
                if !ok {
                    err::raise(ERR_LIB_X509, ERR_R_INTERNAL_ERROR, "req_cb");
                    return 0;
                }
                1
            }
            ASN1_OP_GET0_LIBCTX => {
                // SAFETY: the operation's output.
                unsafe { exarg.cast::<*mut OSSL_LIB_CTX>().write(r.libctx) };
                1
            }
            ASN1_OP_GET0_PROPQ => {
                // SAFETY: as above.
                unsafe { exarg.cast::<*const c_char>().write(r.propq) };
                1
            }
            _ => 1,
        }
    }
}

item_fns! {
    /// CertificationRequest: SEQUENCE { certificationRequestInfo, signatureAlgorithm,
    /// signature }.
    pub unsafe extern "C" fn X509_REQ_it = sequence::<Req, 3>(&REQ_TT, Some(&REQ_AUX), c"X509_REQ");
}

new_free! {
    pub unsafe extern "C" fn X509_REQ_new, pub unsafe extern "C" fn X509_REQ_free(X509_REQ) = X509_REQ_it;
}

i2d! {
    /// Encodes a certificate request.
    pub unsafe extern "C" fn i2d_X509_REQ(X509_REQ) = X509_REQ_it;
}

d2i! {
    /// Decodes a certificate request (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_X509_REQ(X509_REQ) = X509_REQ_it;
}

/// The request behind a pointer, or `None` for NULL.
///
/// # Safety
/// `x` is NULL or a live request.
pub(crate) unsafe fn req_of<'a>(x: *const X509_REQ) -> Option<&'a mut Req> {
    // SAFETY: the caller's guarantee; a request is a `Req`.
    unsafe { x.cast::<Req>().cast_mut().as_mut() }
}

ffi_export! {
    /// A copy of the request (through its encoding, with its library context and its own copy
    /// of the key), or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live request.
    pub unsafe extern "C" fn X509_REQ_dup(x: *const X509_REQ) -> *mut X509_REQ
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_REQ_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_dup(it, x.cast_mut().cast()) }.cast()
    }
}

ffi_export! {
    /// A new request in `libctx`, with `propq` (copied) for what it fetches, or NULL.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `propq` is NULL or a string.
    pub unsafe extern "C" fn X509_REQ_new_ex(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut X509_REQ
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_REQ_it() };
        // SAFETY: the type's item.
        let x: *mut X509_REQ = unsafe { ASN1_item_new(it) }.cast();
        // SAFETY: just made, or NULL.
        if let Some(r) = unsafe { req_of(x) }
            // SAFETY: the caller's guarantee.
            && !unsafe { set0_libctx(&mut r.libctx, &mut r.propq, libctx, propq) }
        {
            // SAFETY: made above.
            unsafe { X509_REQ_free(x) };
            return ptr::null_mut();
        }
        x
    }
}

ffi_export! {
    /// Gives the request the distinguishing ID (SM2's) it's verified with, freeing the old.
    ///
    /// # Safety
    /// `x` is NULL or a live request; `d_id` is NULL or a string it takes.
    pub unsafe extern "C" fn X509_REQ_set0_distinguishing_id(x: *mut X509_REQ, d_id: *mut ASN1_OCTET_STRING)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { req_of(x) }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { ASN1_OCTET_STRING_free(r.distinguishing_id) };
        r.distinguishing_id = d_id;
    }
}

ffi_export! {
    /// The request's distinguishing ID, or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live request.
    pub unsafe extern "C" fn X509_REQ_get0_distinguishing_id(x: *mut X509_REQ) -> *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { req_of(x) }.map_or(ptr::null_mut(), |r| r.distinguishing_id)
    }
}

ffi_export! {
    /// A request for the certificate's subject and key (version 1, no attributes), signed with
    /// `pkey` and `md` if `pkey` is given; NULL on failure.
    ///
    /// # Safety
    /// `x` is NULL or a live certificate; `pkey` is NULL or a live key; `md` is NULL or a
    /// digest.
    pub unsafe extern "C" fn X509_to_X509_REQ(x: *mut X509, pkey: *mut EVP_PKEY, md: *const EVP_MD) -> *mut X509_REQ
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(x) }) else { return ptr::null_mut() };
        // SAFETY: the certificate's library context and properties.
        let ret = unsafe { X509_REQ_new_ex(c.libctx, c.propq) };
        // SAFETY: just made, or NULL.
        let Some(r) = (unsafe { req_of(ret) }) else {
            err::raise(ERR_LIB_X509, ERR_R_ASN1_LIB, "X509_to_X509_REQ");
            return ptr::null_mut();
        };
        // SAFETY: the new request's version INTEGER; the octets of 0.
        let ok = unsafe { ASN1_STRING_set(r.req_info.version, c"".as_ptr().cast(), 1) } != 0
            // SAFETY: the new request; the certificate's subject.
            && unsafe { X509_REQ_set_subject_name(ret, c.cert_info.subject) } != 0
            && {
                // SAFETY: the certificate.
                let pktmp = unsafe { X509_get0_pubkey(x) };
                // SAFETY: the new request; the certificate's key.
                !pktmp.is_null() && unsafe { X509_REQ_set_pubkey(ret, pktmp) } != 0
            }
            // SAFETY: as above; the caller's key and digest.
            && (pkey.is_null() || unsafe { X509_REQ_sign(ret, pkey, md) } != 0);
        if !ok {
            // SAFETY: made above.
            unsafe { X509_REQ_free(ret) };
            return ptr::null_mut();
        }
        ret
    }
}

ffi_export! {
    /// The request's public key with a reference for the caller, or NULL.
    ///
    /// # Safety
    /// `req` is NULL or a live request.
    pub unsafe extern "C" fn X509_REQ_get_pubkey(req: *mut X509_REQ) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { req_of(req) }) else { return ptr::null_mut() };
        // SAFETY: its SubjectPublicKeyInfo.
        unsafe { X509_PUBKEY_get(r.req_info.pubkey) }
    }
}

ffi_export! {
    /// The request's public key (the request keeps it), or NULL.
    ///
    /// # Safety
    /// `req` is NULL or a live request.
    pub unsafe extern "C" fn X509_REQ_get0_pubkey(req: *const X509_REQ) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { req_of(req) }) else { return ptr::null_mut() };
        // SAFETY: its SubjectPublicKeyInfo.
        unsafe { X509_PUBKEY_get0(r.req_info.pubkey) }
    }
}

ffi_export! {
    /// The request's SubjectPublicKeyInfo.
    ///
    /// # Safety
    /// `req` is NULL or a live request.
    pub unsafe extern "C" fn X509_REQ_get_X509_PUBKEY(req: *mut X509_REQ) -> *mut X509_PUBKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { req_of(req) }.map_or(ptr::null_mut(), |r| r.req_info.pubkey)
    }
}

ffi_export! {
    /// Whether `pkey` is the private key of the request's public key: 1, or 0 with the reason.
    ///
    /// # Safety
    /// `req` is NULL or a live request; `pkey` is NULL or a live key.
    pub unsafe extern "C" fn X509_REQ_check_private_key(req: *const X509_REQ, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let k = unsafe { X509_REQ_get0_pubkey(req) };
        // SAFETY: the request's key, or NULL; the caller's.
        unsafe { check_private_key(k, pkey) }
    }
}

/// `ext_nid_list`: the attributes whose values are requested extensions, ended by `NID_undef`.
static EXT_NID_LIST: [AtomicI32; 3] = [
    AtomicI32::new(NID_ext_req),
    AtomicI32::new(NID_ms_ext_req),
    AtomicI32::new(NID_undef),
];

/// `ext_nids`: the list in use, [`EXT_NID_LIST`] or the application's.
static EXT_NIDS: AtomicPtr<c_int> = AtomicPtr::new(EXT_NID_LIST.as_ptr().cast_mut().cast());

/// The NIDs of the list in use, up to its `NID_undef`.
///
/// # Safety
/// The list is [`EXT_NID_LIST`] or an application's, ended by `NID_undef`.
unsafe fn ext_nids() -> impl Iterator<Item = c_int> {
    let list = EXT_NIDS.load(Ordering::Acquire);
    let mut i = 0usize;
    core::iter::from_fn(move || {
        if list.is_null() {
            return None;
        }
        // SAFETY: the caller's guarantee: within the list, which ends at `NID_undef`.
        let nid = unsafe { list.wrapping_add(i).read() };
        i += 1;
        (nid != NID_undef).then_some(nid)
    })
}

ffi_export! {
    /// Whether `req_nid` is an attribute whose value is requested extensions.
    ///
    /// # Safety
    /// The list set by `X509_REQ_set_extension_nids`, if any, is live and ends with
    /// `NID_undef`.
    pub unsafe extern "C" fn X509_REQ_extension_nid(req_nid: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { ext_nids() }.any(|n| n == req_nid))
    }
}

ffi_export! {
    /// The list of the attributes whose values are requested extensions (`NID_ext_req` and
    /// `NID_ms_ext_req`, ended by `NID_undef`, unless changed).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn X509_REQ_get_extension_nids() -> *mut c_int
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        EXT_NIDS.load(Ordering::Acquire)
    }
}

ffi_export! {
    /// Replaces that list with `nids` (kept, not copied), ended by `NID_undef`.
    ///
    /// # Safety
    /// `nids` is NULL or a list ended by `NID_undef` that outlives its use.
    pub unsafe extern "C" fn X509_REQ_set_extension_nids(nids: *mut c_int)
    where failure = (), library = ERR_LIB_X509
    {
        EXT_NIDS.store(nids, Ordering::Release);
    }
}

/// `get_extensions_by_nid`: the extensions in the request's first attribute of `nid` (a new
/// empty stack without one), or NULL with `X509_R_WRONG_TYPE` if its value isn't a SEQUENCE.
///
/// # Safety
/// `req` is a live request.
unsafe fn extensions_by_nid(req: *const X509_REQ, nid: c_int) -> *mut stack_st_X509_EXTENSION {
    // SAFETY: the caller's guarantee.
    let idx = unsafe { X509_REQ_get_attr_by_NID(req, nid, -1) };
    if idx < 0 {
        // SAFETY: no preconditions.
        return unsafe { OPENSSL_sk_new_null() }.cast();
    }
    // SAFETY: as above; an index within its attributes.
    let attr = unsafe { X509_REQ_get_attr(req, idx) };
    // SAFETY: the attribute.
    let ext = unsafe { X509_ATTRIBUTE_get0_type(attr, 0) };
    // SAFETY: its first value, or NULL.
    let seq = match unsafe { ext.as_ref() } {
        // SAFETY: a SEQUENCE's value is a string.
        Some(t) if t.type_ == V_ASN1_SEQUENCE => unsafe { t.value.sequence },
        _ => ptr::null_mut(),
    };
    // SAFETY: the SEQUENCE's string, or NULL.
    let Some(s) = (unsafe { seq.as_ref() }) else {
        err::raise(ERR_LIB_X509, X509_R_WRONG_TYPE, "get_extensions_by_nid");
        return ptr::null_mut();
    };
    let mut p = s.data.cast_const();
    // SAFETY: no preconditions.
    let it = unsafe { X509_EXTENSIONS_it() };
    // SAFETY: the SEQUENCE's `length` octets.
    unsafe { ASN1_item_d2i(ptr::null_mut(), &raw mut p, c_long::from(s.length), it) }.cast()
}

ffi_export! {
    /// The extensions the request asks for (in the first attribute of the list that has any; a
    /// new empty stack without), for the caller to free; NULL on failure.
    ///
    /// # Safety
    /// `req` is NULL or a live request.
    pub unsafe extern "C" fn X509_REQ_get_extensions(req: *mut X509_REQ) -> *mut stack_st_X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        if req.is_null() || EXT_NIDS.load(Ordering::Acquire).is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the list's guarantee.
        for nid in unsafe { ext_nids() } {
            // SAFETY: the caller's request.
            let exts = unsafe { extensions_by_nid(req, nid) };
            if exts.is_null() {
                return ptr::null_mut();
            }
            // SAFETY: the stack made above.
            if unsafe { OPENSSL_sk_num(exts.cast()) } > 0 {
                return exts;
            }
            // SAFETY: as above, empty.
            unsafe { OPENSSL_sk_free(exts.cast()) };
        }
        // SAFETY: no preconditions.
        unsafe { OPENSSL_sk_new_null() }.cast()
    }
}

/// `X509_EXTENSION_free` as a stack's free function.
unsafe extern "C" fn free_ext(e: *mut c_void) {
    // SAFETY: an extension of the stack, which the stack owned.
    unsafe { X509_EXTENSION_free(e.cast()) };
}

ffi_export! {
    /// Adds the extensions to the request's attribute `nid` (merged into what it has, the
    /// attribute replaced by one at the end): 1 (also for none to add), or 0.
    ///
    /// # Safety
    /// `req` is a live request; `exts` is NULL or a live stack of extensions.
    pub unsafe extern "C" fn X509_REQ_add_extensions_nid(req: *mut X509_REQ, exts: *const stack_st_X509_EXTENSION, nid: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if unsafe { OPENSSL_sk_num(exts.cast()) } <= 0 {
            return 1;
        }
        // SAFETY: as above.
        let Some(r) = (unsafe { req_of(req) }) else { return 0 };
        // SAFETY: the request's attributes.
        let loc = unsafe { X509at_get_attr_by_NID(r.req_info.attributes, nid, -1) };
        let mut mod_exts: *mut stack_st_X509_EXTENSION = ptr::null_mut();
        let rv = 'add: {
            if loc != -1 {
                // SAFETY: the caller's request.
                mod_exts = unsafe { extensions_by_nid(req, nid) };
                if mod_exts.is_null() {
                    return 0;
                }
                // SAFETY: the stack made above; the caller's extensions.
                if unsafe { X509v3_add_extensions(&raw mut mod_exts, exts) }.is_null() {
                    break 'add 0;
                }
            }
            let mut ext: *mut c_uchar = ptr::null_mut();
            let all = if mod_exts.is_null() { exts } else { mod_exts.cast_const() };
            // SAFETY: no preconditions.
            let it = unsafe { X509_EXTENSIONS_it() };
            // SAFETY: a stack of extensions; a place for the encoding.
            let extlen = unsafe { ASN1_item_i2d(all.cast(), &raw mut ext, it) };
            if extlen <= 0 {
                break 'add 0;
            }
            if !mod_exts.is_null() {
                // SAFETY: the request's attributes; the attribute's index.
                let att = unsafe { X509at_delete_attr(r.req_info.attributes, loc) };
                if att.is_null() {
                    // SAFETY: the encoding.
                    unsafe { mem::release(ext.cast()) };
                    break 'add 0;
                }
                // SAFETY: taken out above.
                unsafe { X509_ATTRIBUTE_free(att) };
            }
            // SAFETY: the request; the encoding's `extlen` octets.
            let rv = unsafe { X509_REQ_add1_attr_by_NID(req, nid, V_ASN1_SEQUENCE, ext, extlen) };
            // SAFETY: as above.
            unsafe { mem::release(ext.cast()) };
            rv
        };
        // SAFETY: the stack made above, or NULL.
        unsafe { OPENSSL_sk_pop_free(mod_exts.cast(), Some(free_ext)) };
        rv
    }
}

ffi_export! {
    /// [`X509_REQ_add_extensions_nid`] for `extensionRequest`.
    ///
    /// # Safety
    /// As for [`X509_REQ_add_extensions_nid`].
    pub unsafe extern "C" fn X509_REQ_add_extensions(req: *mut X509_REQ, exts: *const stack_st_X509_EXTENSION) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_REQ_add_extensions_nid(req, exts, NID_ext_req) }
    }
}

/// The request's attributes, or NULL.
///
/// # Safety
/// `req` is NULL or a live request.
unsafe fn attributes(req: *const X509_REQ) -> *mut stack_st_X509_ATTRIBUTE {
    // SAFETY: the caller's guarantee.
    unsafe { req_of(req) }.map_or(ptr::null_mut(), |r| r.req_info.attributes)
}

ffi_export! {
    /// The number of attributes.
    ///
    /// # Safety
    /// `req` is NULL or a live request.
    pub unsafe extern "C" fn X509_REQ_get_attr_count(req: *const X509_REQ) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let attrs = unsafe { attributes(req) };
        // SAFETY: its attributes, or NULL.
        unsafe { X509at_get_attr_count(attrs) }
    }
}

ffi_export! {
    /// The index of the next attribute after `lastpos` with the NID, -1 for none, or -2 for an
    /// unknown NID.
    ///
    /// # Safety
    /// `req` is NULL or a live request.
    pub unsafe extern "C" fn X509_REQ_get_attr_by_NID(req: *const X509_REQ, nid: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let attrs = unsafe { attributes(req) };
        // SAFETY: its attributes, or NULL.
        unsafe { X509at_get_attr_by_NID(attrs, nid, lastpos) }
    }
}

ffi_export! {
    /// The index of the next attribute after `lastpos` with the object, or -1.
    ///
    /// # Safety
    /// `req` is NULL or a live request; `obj` is NULL or a live object.
    pub unsafe extern "C" fn X509_REQ_get_attr_by_OBJ(req: *const X509_REQ, obj: *const ASN1_OBJECT, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let attrs = unsafe { attributes(req) };
        // SAFETY: its attributes, or NULL.
        unsafe { X509at_get_attr_by_OBJ(attrs, obj, lastpos) }
    }
}

ffi_export! {
    /// The attribute at `loc` (the request keeps it), or NULL.
    ///
    /// # Safety
    /// `req` is NULL or a live request.
    pub unsafe extern "C" fn X509_REQ_get_attr(req: *const X509_REQ, loc: c_int) -> *mut X509_ATTRIBUTE
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let attrs = unsafe { attributes(req) };
        // SAFETY: its attributes, or NULL.
        unsafe { X509at_get_attr(attrs, loc) }
    }
}

ffi_export! {
    /// Takes the attribute at `loc` out (for the caller to free), marking the request changed;
    /// NULL if there's none.
    ///
    /// # Safety
    /// `req` is NULL or a live request.
    pub unsafe extern "C" fn X509_REQ_delete_attr(req: *mut X509_REQ, loc: c_int) -> *mut X509_ATTRIBUTE
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { req_of(req) }) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "X509_REQ_delete_attr");
            return ptr::null_mut();
        };
        // SAFETY: its attributes.
        let attr = unsafe { X509at_delete_attr(r.req_info.attributes, loc) };
        if !attr.is_null() {
            r.req_info.enc.modified = 1;
        }
        attr
    }
}

/// The request for an attribute setter, or `None` raising `ERR_R_PASSED_NULL_PARAMETER`.
///
/// # Safety
/// `req` is NULL or a live request.
unsafe fn req_for<'a>(req: *mut X509_REQ, f: &str) -> Option<&'a mut Req> {
    // SAFETY: the caller's guarantee.
    let r = unsafe { req_of(req) };
    if r.is_none() {
        err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, f);
    }
    r
}

/// Marks the request changed if `added` is a stack: 1, or 0.
fn mark_added(r: &mut Req, added: *mut stack_st_X509_ATTRIBUTE) -> c_int {
    if added.is_null() {
        return 0;
    }
    r.req_info.enc.modified = 1;
    1
}

ffi_export! {
    /// Adds a copy of `attr`: 1, or 0.
    ///
    /// # Safety
    /// `req` is NULL or a live request; `attr` is NULL or a live attribute.
    pub unsafe extern "C" fn X509_REQ_add1_attr(req: *mut X509_REQ, attr: *mut X509_ATTRIBUTE) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { req_for(req, "X509_REQ_add1_attr") }) else { return 0 };
        // SAFETY: its attributes; the caller's.
        let added = unsafe { X509at_add1_attr(&raw mut r.req_info.attributes, attr) };
        mark_added(r, added)
    }
}

ffi_export! {
    /// Adds an attribute of the object with a value of `type_` from `bytes`: 1, or 0.
    ///
    /// # Safety
    /// `req` is NULL or a live request; `obj` is NULL or a live object; `bytes` as for
    /// `X509_ATTRIBUTE_set1_data`.
    pub unsafe extern "C" fn X509_REQ_add1_attr_by_OBJ(req: *mut X509_REQ, obj: *const ASN1_OBJECT, type_: c_int, bytes: *const c_uchar, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { req_for(req, "X509_REQ_add1_attr_by_OBJ") }) else { return 0 };
        // SAFETY: its attributes; the caller's.
        let added = unsafe { X509at_add1_attr_by_OBJ(&raw mut r.req_info.attributes, obj, type_, bytes, len) };
        mark_added(r, added)
    }
}

ffi_export! {
    /// Adds an attribute of the NID with a value of `type_` from `bytes`: 1, or 0.
    ///
    /// # Safety
    /// `req` is NULL or a live request; `bytes` as for `X509_ATTRIBUTE_set1_data`.
    pub unsafe extern "C" fn X509_REQ_add1_attr_by_NID(req: *mut X509_REQ, nid: c_int, type_: c_int, bytes: *const c_uchar, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { req_for(req, "X509_REQ_add1_attr_by_NID") }) else { return 0 };
        // SAFETY: its attributes; the caller's.
        let added = unsafe { X509at_add1_attr_by_NID(&raw mut r.req_info.attributes, nid, type_, bytes, len) };
        mark_added(r, added)
    }
}

ffi_export! {
    /// Adds an attribute named `attrname` with a value of `type_` from `bytes`: 1, or 0.
    ///
    /// # Safety
    /// `req` is NULL or a live request; `attrname` is NULL or a string; `bytes` as for
    /// `X509_ATTRIBUTE_set1_data`.
    pub unsafe extern "C" fn X509_REQ_add1_attr_by_txt(req: *mut X509_REQ, attrname: *const c_char, type_: c_int, bytes: *const c_uchar, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { req_for(req, "X509_REQ_add1_attr_by_txt") }) else { return 0 };
        // SAFETY: its attributes; the caller's.
        let added = unsafe { X509at_add1_attr_by_txt(&raw mut r.req_info.attributes, attrname, type_, bytes, len) };
        mark_added(r, added)
    }
}

ffi_export! {
    /// The version (0 for version 1).
    ///
    /// # Safety
    /// `req` is NULL or a live request.
    pub unsafe extern "C" fn X509_REQ_get_version(req: *const X509_REQ) -> c_long
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { req_of(req) }) else { return 0 };
        // SAFETY: its version.
        unsafe { ASN1_INTEGER_get(r.req_info.version) }
    }
}

ffi_export! {
    /// The subject.
    ///
    /// # Safety
    /// `req` is NULL or a live request.
    pub unsafe extern "C" fn X509_REQ_get_subject_name(req: *const X509_REQ) -> *mut X509_NAME
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { req_of(req) }.map_or(ptr::null_mut(), |r| r.req_info.subject)
    }
}

ffi_export! {
    /// The signature and its AlgorithmIdentifier, into `*psig` and `*palg` where given.
    ///
    /// # Safety
    /// `req` is NULL or a live request; `psig` and `palg` are NULL or writable.
    pub unsafe extern "C" fn X509_REQ_get0_signature(req: *const X509_REQ, psig: *mut *const ASN1_BIT_STRING, palg: *mut *const X509_ALGOR)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { req_of(req) }) else { return };
        if !psig.is_null() {
            // SAFETY: as above.
            unsafe { psig.write(r.signature) };
        }
        if !palg.is_null() {
            // SAFETY: as above.
            unsafe { palg.write(&raw const r.sig_alg) };
        }
    }
}

ffi_export! {
    /// Replaces the signature with `psig`, which the request takes.
    ///
    /// # Safety
    /// `req` is NULL or a live request; `psig` is NULL or a BIT STRING it takes.
    pub unsafe extern "C" fn X509_REQ_set0_signature(req: *mut X509_REQ, psig: *mut ASN1_BIT_STRING)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { req_of(req) }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { ASN1_BIT_STRING_free(r.signature) };
        r.signature = psig;
    }
}

ffi_export! {
    /// Sets the signature's AlgorithmIdentifier to a copy of `palg`: 1, or 0.
    ///
    /// # Safety
    /// `req` is NULL or a live request; `palg` is NULL or a live AlgorithmIdentifier.
    pub unsafe extern "C" fn X509_REQ_set1_signature_algo(req: *mut X509_REQ, palg: *mut X509_ALGOR) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { req_of(req) }) else { return 0 };
        // SAFETY: its AlgorithmIdentifier; the caller's.
        unsafe { X509_ALGOR_copy(&raw mut r.sig_alg, palg) }
    }
}

ffi_export! {
    /// The NID of the signature algorithm.
    ///
    /// # Safety
    /// `req` is NULL or a live request.
    pub unsafe extern "C" fn X509_REQ_get_signature_nid(req: *const X509_REQ) -> c_int
    where failure = NID_undef, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { req_of(req) }) else { return NID_undef };
        // SAFETY: its object.
        unsafe { OBJ_obj2nid(r.sig_alg.algorithm) }
    }
}

ffi_export! {
    /// Encodes the CertificationRequestInfo afresh, `i2d` conventions; 0 for a NULL request.
    ///
    /// # Safety
    /// `req` is NULL or a live request; `pp` as for `i2d_X509_REQ_INFO`.
    pub unsafe extern "C" fn i2d_re_X509_REQ_tbs(req: *mut X509_REQ, pp: *mut *mut c_uchar) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { req_of(req) }) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "i2d_re_X509_REQ_tbs");
            return 0;
        };
        r.req_info.enc.modified = 1;
        // SAFETY: as above.
        unsafe { i2d_X509_REQ_INFO((&raw const r.req_info).cast(), pp) }
    }
}

ffi_export! {
    /// Sets the version, which must be `X509_REQ_VERSION_1`: 1, or 0 with
    /// `ERR_R_PASSED_INVALID_ARGUMENT`.
    ///
    /// # Safety
    /// `x` is NULL or a live request.
    pub unsafe extern "C" fn X509_REQ_set_version(x: *mut X509_REQ, version: c_long) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let r = unsafe { req_of(x) };
        let Some(r) = r.filter(|_| version == c_long::from(X509_REQ_VERSION_1)) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_INVALID_ARGUMENT, "X509_REQ_set_version");
            return 0;
        };
        r.req_info.enc.modified = 1;
        // SAFETY: its version.
        unsafe { ASN1_INTEGER_set(r.req_info.version, version) }
    }
}

ffi_export! {
    /// Sets the subject to a copy of `name`: 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live request; `name` is NULL or a live name.
    pub unsafe extern "C" fn X509_REQ_set_subject_name(x: *mut X509_REQ, name: *const X509_NAME) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { req_of(x) }) else { return 0 };
        r.req_info.enc.modified = 1;
        // SAFETY: its slot; the caller's name.
        unsafe { X509_NAME_set(&raw mut r.req_info.subject, name) }
    }
}

ffi_export! {
    /// Sets the public key to `pkey`'s: 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live request; `pkey` is NULL or a live key.
    pub unsafe extern "C" fn X509_REQ_set_pubkey(x: *mut X509_REQ, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { req_of(x) }) else { return 0 };
        r.req_info.enc.modified = 1;
        // SAFETY: its slot; the caller's key.
        unsafe { X509_PUBKEY_set(&raw mut r.req_info.pubkey, pkey) }
    }
}

ffi_export! {
    /// Checks the request's signature with `r` (fetching from `libctx` with `propq`): 1, 0 if
    /// it doesn't verify, -1 if it can't be checked (another version: `X509_R_UNSUPPORTED_VERSION`).
    ///
    /// # Safety
    /// `a` is NULL or a live request; `r` is NULL or a live key; `propq` is NULL or a string.
    pub unsafe extern "C" fn X509_REQ_verify_ex(a: *mut X509_REQ, r: *mut EVP_PKEY, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(q) = (unsafe { req_of(a) }) else { return -1 };
        // SAFETY: as above.
        if unsafe { X509_REQ_get_version(a) } != c_long::from(X509_REQ_VERSION_1) {
            err::raise(ERR_LIB_X509, X509_R_UNSUPPORTED_VERSION, "X509_REQ_verify_ex");
            return -1;
        }
        // SAFETY: no preconditions.
        let it = unsafe { X509_REQ_INFO_it() };
        // SAFETY: the request's CertificationRequestInfo, signature, and ID; the caller's key.
        unsafe {
            ASN1_item_verify_ex(it, &raw const q.sig_alg, q.signature, (&raw const q.req_info).cast(), q.distinguishing_id, r, libctx, propq)
        }
    }
}

ffi_export! {
    /// [`X509_REQ_verify_ex`] without a library context.
    ///
    /// # Safety
    /// `a` is NULL or a live request; `r` is NULL or a live key.
    pub unsafe extern "C" fn X509_REQ_verify(a: *mut X509_REQ, r: *mut EVP_PKEY) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_REQ_verify_ex(a, r, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Signs the request with `pkey` and `md`: the signature's length, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live request; `pkey` is a live key; `md` is NULL or a digest.
    pub unsafe extern "C" fn X509_REQ_sign(x: *mut X509_REQ, pkey: *mut EVP_PKEY, md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { req_of(x) }) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "X509_REQ_sign");
            return 0;
        };
        r.req_info.enc.modified = 1;
        // SAFETY: no preconditions.
        let it = unsafe { X509_REQ_INFO_it() };
        // SAFETY: the request's fields; the caller's key and digest.
        unsafe {
            ASN1_item_sign_ex(it, &raw mut r.sig_alg, ptr::null_mut(), r.signature, (&raw const r.req_info).cast(), ptr::null(), pkey, md, r.libctx, r.propq)
        }
    }
}

ffi_export! {
    /// Signs the request through `ctx`, initialised for signing: the signature's length, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live request; `ctx` is a live digest context with a key context.
    pub unsafe extern "C" fn X509_REQ_sign_ctx(x: *mut X509_REQ, ctx: *mut EVP_MD_CTX) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { req_of(x) }) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "X509_REQ_sign_ctx");
            return 0;
        };
        r.req_info.enc.modified = 1;
        // SAFETY: no preconditions.
        let it = unsafe { X509_REQ_INFO_it() };
        // SAFETY: the request's fields; the caller's context.
        unsafe { ASN1_item_sign_ctx(it, &raw mut r.sig_alg, ptr::null_mut(), r.signature, (&raw const r.req_info).cast(), ctx) }
    }
}

ffi_export! {
    /// Decodes a request from a `FILE` (`ASN1_item_d2i_fp`).
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `req` is NULL or holds NULL or a live request.
    pub unsafe extern "C" fn d2i_X509_REQ_fp(fp: *mut FILE, req: *mut *mut X509_REQ) -> *mut X509_REQ
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_REQ_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_d2i_fp(it, fp, req.cast()) }.cast()
    }
}

ffi_export! {
    /// Encodes a request to a `FILE`: 1, or 0.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `req` is a live request.
    pub unsafe extern "C" fn i2d_X509_REQ_fp(fp: *mut FILE, req: *const X509_REQ) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_REQ_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_fp(it, fp, req.cast()) }
    }
}

ffi_export! {
    /// Decodes a request from a BIO, in the library context of the request at `*req` if given.
    ///
    /// # Safety
    /// `bp` is a live BIO; `req` is NULL or holds NULL or a live request.
    pub unsafe extern "C" fn d2i_X509_REQ_bio(bp: *mut BIO, req: *mut *mut X509_REQ) -> *mut X509_REQ
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        let given = if req.is_null() {
            None
        } else {
            // SAFETY: the caller's guarantee.
            let given = unsafe { req.read() };
            // SAFETY: as above.
            unsafe { req_of(given) }
        };
        let (libctx, propq) = given.map_or((ptr::null_mut(), ptr::null()), |r| (r.libctx, r.propq.cast_const()));
        // SAFETY: no preconditions.
        let it = unsafe { X509_REQ_it() };
        // SAFETY: the caller's guarantee; the request's library context and properties.
        unsafe { ASN1_item_d2i_bio_ex(it, bp, req.cast(), libctx, propq) }.cast()
    }
}

ffi_export! {
    /// Encodes a request to a BIO: 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `req` is a live request.
    pub unsafe extern "C" fn i2d_X509_REQ_bio(bp: *mut BIO, req: *const X509_REQ) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_REQ_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_bio(it, bp, req.cast()) }
    }
}

ffi_export! {
    /// The digest of the request's DER: 1, or 0.
    ///
    /// # Safety
    /// `data` is NULL or a live request; `type_` is a live digest; `md` has room for its
    /// output; `len` is NULL or writable.
    pub unsafe extern "C" fn X509_REQ_digest(data: *const X509_REQ, type_: *const EVP_MD, md: *mut c_uchar, len: *mut c_uint) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { req_of(data) }) else { return 0 };
        // SAFETY: no preconditions.
        let it = unsafe { X509_REQ_it() };
        // SAFETY: the request, of the item; the caller's digest and room.
        unsafe { item_digest_ex(it, type_, data.cast_mut().cast(), md, len, r.libctx, r.propq) }
    }
}

ffi_export! {
    /// A self-issued certificate for the request's subject and key, valid from now for `days`
    /// days, version 3 if the request has attributes, signed with `pkey` and MD5; NULL on
    /// failure.
    ///
    /// # Safety
    /// `r` is NULL or a live request; `pkey` is a live key.
    pub unsafe extern "C" fn X509_REQ_to_X509(r: *mut X509_REQ, days: c_int, pkey: *mut EVP_PKEY) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(q) = (unsafe { req_of(r) }) else { return ptr::null_mut() };
        // SAFETY: no preconditions.
        let ret = unsafe { X509_new() };
        // SAFETY: just made, or NULL.
        let Some(c) = (unsafe { cert_of(ret) }) else {
            err::raise(ERR_LIB_X509, ERR_R_ASN1_LIB, "X509_REQ_to_X509");
            return ptr::null_mut();
        };
        let ok = 'make: {
            // SAFETY: the request's attributes.
            if unsafe { OPENSSL_sk_num(q.req_info.attributes.cast()) } != 0 {
                // SAFETY: no preconditions.
                c.cert_info.version = unsafe { ASN1_INTEGER_new() };
                // SAFETY: the new INTEGER.
                if c.cert_info.version.is_null() || unsafe { ASN1_INTEGER_set(c.cert_info.version, 2) } == 0 {
                    break 'make false;
                }
            }
            let xn = q.req_info.subject;
            let secs = c_long::from(days).saturating_mul(60 * 60 * 24);
            // SAFETY: the new certificate; the request's subject.
            (unsafe { X509_set_subject_name(ret, xn) } != 0)
                // SAFETY: as above.
                && unsafe { X509_set_issuer_name(ret, xn) } != 0
                // SAFETY: the certificate's times.
                && !unsafe { X509_gmtime_adj(c.cert_info.validity.notBefore, 0) }.is_null()
                // SAFETY: as above.
                && !unsafe { X509_gmtime_adj(c.cert_info.validity.notAfter, secs) }.is_null()
                && {
                    // SAFETY: the request.
                    let pubkey = unsafe { X509_REQ_get0_pubkey(r) };
                    // SAFETY: the certificate; the request's key.
                    !pubkey.is_null() && unsafe { X509_set_pubkey(ret, pubkey) } != 0
                }
                && {
                    // SAFETY: no preconditions.
                    let md5 = unsafe { EVP_md5() };
                    // SAFETY: the certificate; the caller's key; MD5.
                    (unsafe { X509_sign(ret, pkey, md5) } != 0)
                }
        };
        if !ok {
            // SAFETY: made above.
            unsafe { X509_free(ret) };
            return ptr::null_mut();
        }
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: the getters, setters, and attribute functions of a NULL request,
    /// which OpenSSL reads through, answer NULL, 0, or -1.
    #[test]
    fn null_requests_are_safe() {
        let x: *mut X509_REQ = ptr::null_mut();
        // SAFETY: NULL where OpenSSL dereferences it.
        assert!(unsafe { X509_REQ_get_subject_name(x) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { X509_REQ_get_X509_PUBKEY(x) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { X509_REQ_get_version(x) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_REQ_get_signature_nid(x) }, NID_undef);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_REQ_get_attr_count(x) }, -1);
        // SAFETY: as above.
        assert!(unsafe { X509_REQ_get_attr(x, 0) }.is_null());
        // SAFETY: as above.
        let r = unsafe { X509_REQ_set1_signature_algo(x, ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_REQ_verify(x, ptr::null_mut()) }, -1);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_REQ_add_extensions(x, ptr::null()) }, 1);
        // SAFETY: as above.
        unsafe { X509_REQ_set0_signature(x, ptr::null_mut()) };
        crate::err::take_all();
    }
}
