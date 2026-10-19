//! Certificate revocation lists (`X509_CRL_new(3)`, `X509_CRL_get0_by_serial(3)`; `x_crl.c`,
//! `x509cset.c`, and the CRL parts of `x509_ext.c`, `x509_cmp.c`, `x_all.c`, and
//! `x509_vfy.c`): `X509_CRL` as OpenSSL's reference-counted SEQUENCE over its own structure,
//! its TBSCertList (`X509_CRL_INFO`) keeping the DER it was decoded from until it changes, and
//! its entries (`X509_REVOKED`).
//!
//! As OpenSSL's:
//! - Decoding a CRL caches what path validation reads: its SHA-1 fingerprint, the issuing
//!   distribution point (as flags and reasons, its relative name made full), the authority key
//!   identifier, the CRL and delta CRL numbers, each entry's certificate issuer (carried to the
//!   entries after it) and reason, and the flags (`EXFLAG_INVALID` for an undecodable or
//!   impossible extension, `EXFLAG_CRITICAL` for one it doesn't know). A CRL built rather than
//!   decoded has none of this.
//! - Lookups sort the entries by serial number first (under the CRL's lock), and an entry
//!   matches a certificate if its issuer (or the CRL's) is the certificate's.
//! - The lookup and verification go through an `X509_CRL_METHOD`, the default one or an
//!   application's, whose `crl_init` and `crl_free` run as CRLs are decoded and freed.
//! - Printing comes with step 5.6, and `X509_CRL_load_http` with the HTTP client (6.8).

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void};
use core::mem::offset_of;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use libc::FILE;
use rustyssl_abi::{
    ASN1_AFLG_ENCODING, ASN1_AFLG_REFCOUNT, ASN1_BIT_STRING, ASN1_ENCODING, ASN1_INTEGER,
    ASN1_ITEM, ASN1_OBJECT, ASN1_OP_D2I_POST, ASN1_OP_D2I_PRE, ASN1_OP_DUP_POST, ASN1_OP_FREE_POST,
    ASN1_OP_NEW_POST, ASN1_STRING, ASN1_TFLG_EMBED, ASN1_TFLG_EXPLICIT, ASN1_TFLG_OPTIONAL,
    ASN1_TFLG_SEQUENCE_OF, ASN1_TIME, ASN1_VALUE, AUTHORITY_KEYID, BIO, CRL_REASON_NONE,
    CRL_REASON_REMOVE_FROM_CRL, CRLDP_ALL_REASONS, CRYPTO_RWLOCK, ERR_LIB_ASN1, ERR_LIB_X509,
    ERR_R_ASN1_LIB, ERR_R_CRYPTO_LIB, ERR_R_PASSED_NULL_PARAMETER, ERR_R_X509_LIB, EVP_MD,
    EVP_MD_CTX, EVP_PKEY, EXFLAG_CRITICAL, EXFLAG_FRESHEST, EXFLAG_INVALID, EXFLAG_NO_FINGERPRINT,
    EXFLAG_SET, GEN_DIRNAME, GENERAL_NAME, GENERAL_NAMES, IDP_INDIRECT, IDP_INVALID, IDP_ONLYATTR,
    IDP_ONLYCA, IDP_ONLYUSER, IDP_PRESENT, IDP_REASONS, ISSUING_DIST_POINT,
    NID_authority_key_identifier, NID_certificate_issuer, NID_crl_number, NID_crl_reason,
    NID_delta_crl, NID_freshest_crl, NID_issuing_distribution_point, NID_undef, OSSL_LIB_CTX, X509,
    X509_ALGOR, X509_CRL, X509_CRL_INFO, X509_CRL_METHOD, X509_CRL_VERSION_2, X509_EXTENSION,
    X509_NAME, X509_R_AKID_MISMATCH, X509_R_CRL_ALREADY_DELTA,
    X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH, X509_R_CRL_VERIFY_FAILURE, X509_R_IDP_MISMATCH,
    X509_R_ISSUER_MISMATCH, X509_R_NEWER_CRL_NOT_NEWER, X509_R_NO_CRL_NUMBER, X509_REVOKED,
    X509_V_FLAG_SUITEB_128_LOS, X509_V_OK, stack_st_X509_EXTENSION, stack_st_X509_REVOKED,
};

use super::algor::X509_ALGOR_cmp;
use super::cert::{
    X509_get_issuer_name, X509_get0_serialNumber, check_suite_b, set0_libctx, set1_time,
};
use super::ext::{
    X509_EXTENSION_get_critical, X509_EXTENSION_get_data, X509_EXTENSION_get_object,
    X509_EXTENSION_it, X509v3_add_ext, X509v3_delete_ext, X509v3_get_ext, X509v3_get_ext_by_NID,
    X509v3_get_ext_by_OBJ, X509v3_get_ext_by_critical, X509v3_get_ext_count,
};
use super::name::{X509_NAME_cmp, X509_NAME_it, X509_NAME_set};
use crate::asn1::integer::{
    ASN1_ENUMERATED_get, ASN1_INTEGER_cmp, ASN1_INTEGER_get, ASN1_INTEGER_set,
};
use crate::asn1::sign::{ASN1_item_sign_ctx, ASN1_item_sign_ex, ASN1_item_verify_ex};
use crate::asn1::string::{
    ASN1_ENUMERATED_free, ASN1_INTEGER_free, ASN1_INTEGER_new, ASN1_OCTET_STRING_cmp,
    ASN1_STRING_cmp, ASN1_STRING_copy,
};
use crate::asn1::tpl::io::{
    ASN1_item_d2i_bio, ASN1_item_d2i_fp, ASN1_item_i2d_bio, ASN1_item_i2d_fp,
};
use crate::asn1::tpl::items::{
    ASN1_BIT_STRING_it, ASN1_INTEGER_it, ASN1_TIME_it, X509_ALGOR_it, d2i, i2d, new_free,
};
use crate::asn1::tpl::new::ASN1_item_new;
use crate::asn1::tpl::statics::{Aux, Templates, aux_ex, sequence};
use crate::asn1::tpl::util::{ASN1_item_dup, item_digest_ex};
use crate::asn1::tpl::{item_fns, template_at};
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::objects::OBJ_obj2nid;
use crate::stack::{
    OPENSSL_sk_find, OPENSSL_sk_is_sorted, OPENSSL_sk_new, OPENSSL_sk_new_null, OPENSSL_sk_num,
    OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_set_cmp_func, OPENSSL_sk_sort,
    OPENSSL_sk_value,
};
use crate::threads::{CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock};
use crate::x509v3::akid::AUTHORITY_KEYID_free;
use crate::x509v3::crld::{DIST_POINT_set_dpname, ISSUING_DIST_POINT_free};
use crate::x509v3::genn::GENERAL_NAMES_free;
use crate::x509v3::registry::{X509V3_add1_i2d, X509V3_get_d2i};

/// `X509_CRL_METHOD_DYNAMIC` (`x509_local.h`, not public): a method `X509_CRL_METHOD_new`
/// made, which `X509_CRL_METHOD_free` frees.
const METHOD_DYNAMIC: c_int = 1;

/// A flag as `flags` holds it.
const fn f(x: c_int) -> c_int {
    x
}

/// `X509_REVOKED` (`x509_revoked_st`).
#[repr(C)]
pub(crate) struct Revoked {
    pub(crate) serial_number: ASN1_INTEGER,
    pub(crate) revocation_date: *mut ASN1_TIME,
    pub(crate) extensions: *mut stack_st_X509_EXTENSION,
    /// The certificate issuer it's for (its own, or the last entry's before it), or NULL.
    pub(crate) issuer: *mut GENERAL_NAMES,
    /// Its reason (`CRL_REASON_*`).
    pub(crate) reason: c_int,
    /// Its place, as `X509_CRL_sort` numbered it.
    pub(crate) sequence: c_int,
}

/// `X509_CRL_INFO` (`X509_crl_info_st`): the TBSCertList.
#[repr(C)]
pub(crate) struct CrlInfo {
    pub(crate) version: *mut ASN1_INTEGER,
    pub(crate) sig_alg: X509_ALGOR,
    pub(crate) issuer: *mut X509_NAME,
    pub(crate) last_update: *mut ASN1_TIME,
    pub(crate) next_update: *mut ASN1_TIME,
    pub(crate) revoked: *mut stack_st_X509_REVOKED,
    pub(crate) extensions: *mut stack_st_X509_EXTENSION,
    /// The DER it was decoded from, until it changes (`modified`).
    pub(crate) enc: ASN1_ENCODING,
}

/// `X509_CRL_METHOD` (`x509_crl_method_st`).
#[repr(C)]
pub(crate) struct CrlMethod {
    flags: c_int,
    crl_init: Option<unsafe extern "C" fn(*mut X509_CRL) -> c_int>,
    crl_free: Option<unsafe extern "C" fn(*mut X509_CRL) -> c_int>,
    crl_lookup: Option<
        unsafe extern "C" fn(
            *mut X509_CRL,
            *mut *mut X509_REVOKED,
            *const ASN1_INTEGER,
            *const X509_NAME,
        ) -> c_int,
    >,
    crl_verify: Option<unsafe extern "C" fn(*mut X509_CRL, *mut EVP_PKEY) -> c_int>,
}

/// `X509_CRL` (`X509_crl_st`).
#[repr(C)]
pub(crate) struct Crl {
    pub(crate) crl: CrlInfo,
    pub(crate) sig_alg: X509_ALGOR,
    pub(crate) signature: ASN1_BIT_STRING,
    references: c_int,
    pub(crate) flags: c_int,
    pub(crate) akid: *mut AUTHORITY_KEYID,
    pub(crate) idp: *mut ISSUING_DIST_POINT,
    pub(crate) idp_flags: c_int,
    pub(crate) idp_reasons: c_int,
    pub(crate) crl_number: *mut ASN1_INTEGER,
    pub(crate) base_crl_number: *mut ASN1_INTEGER,
    pub(crate) issuers: *mut c_void,
    pub(crate) sha1_hash: [u8; 20],
    meth: *const CrlMethod,
    meth_data: *mut c_void,
    lock: *mut CRYPTO_RWLOCK,
    pub(crate) libctx: *mut OSSL_LIB_CTX,
    pub(crate) propq: *mut c_char,
}

/// The CRL behind a pointer, or `None` for NULL.
///
/// # Safety
/// `x` is NULL or a live CRL.
pub(crate) unsafe fn crl_of<'a>(x: *const X509_CRL) -> Option<&'a mut Crl> {
    // SAFETY: the caller's guarantee; a CRL is a `Crl`.
    unsafe { x.cast::<Crl>().cast_mut().as_mut() }
}

/// The entry behind a pointer, or `None` for NULL.
///
/// # Safety
/// `x` is NULL or a live entry.
pub(crate) unsafe fn revoked_of<'a>(x: *const X509_REVOKED) -> Option<&'a mut Revoked> {
    // SAFETY: the caller's guarantee; an entry is a `Revoked`.
    unsafe { x.cast::<Revoked>().cast_mut().as_mut() }
}

// The entries.

static REVOKED_TT: Templates<3> = Templates([
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Revoked, serial_number),
        c"serialNumber",
        ASN1_INTEGER_it,
    ),
    template_at(
        0,
        0,
        offset_of!(Revoked, revocation_date),
        c"revocationDate",
        ASN1_TIME_it,
    ),
    template_at(
        ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(Revoked, extensions),
        c"extensions",
        X509_EXTENSION_it,
    ),
]);

item_fns! {
    /// A revokedCertificates entry: SEQUENCE { userCertificate, revocationDate,
    /// crlEntryExtensions OPTIONAL }.
    pub unsafe extern "C" fn X509_REVOKED_it = sequence::<Revoked, 3>(&REVOKED_TT, None, c"X509_REVOKED");
}

new_free! {
    pub unsafe extern "C" fn X509_REVOKED_new, pub unsafe extern "C" fn X509_REVOKED_free(X509_REVOKED) = X509_REVOKED_it;
}

i2d! {
    /// Encodes a CRL entry.
    pub unsafe extern "C" fn i2d_X509_REVOKED(X509_REVOKED) = X509_REVOKED_it;
}

d2i! {
    /// Decodes a CRL entry (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_X509_REVOKED(X509_REVOKED) = X509_REVOKED_it;
}

ffi_export! {
    /// A copy of the entry (through its encoding), or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live entry.
    pub unsafe extern "C" fn X509_REVOKED_dup(a: *const X509_REVOKED) -> *mut X509_REVOKED
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_REVOKED_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_dup(it, a.cast_mut().cast()) }.cast()
    }
}

/// `X509_REVOKED_cmp`: by serial number (`ASN1_STRING_cmp`).
unsafe extern "C" fn revoked_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: pointers to the stack's elements, entries.
    let a = unsafe { *a.cast::<*const Revoked>() };
    // SAFETY: as above.
    let b = unsafe { *b.cast::<*const Revoked>() };
    // SAFETY: an entry's serial number.
    let sa = unsafe { &raw const (*a).serial_number };
    // SAFETY: as above.
    let sb = unsafe { &raw const (*b).serial_number };
    // SAFETY: as above.
    unsafe { ASN1_STRING_cmp(sa.cast(), sb.cast()) }
}

// The TBSCertList.

static INFO_TT: Templates<7> = Templates([
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(CrlInfo, version),
        c"version",
        ASN1_INTEGER_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(CrlInfo, sig_alg),
        c"sig_alg",
        X509_ALGOR_it,
    ),
    template_at(0, 0, offset_of!(CrlInfo, issuer), c"issuer", X509_NAME_it),
    template_at(
        0,
        0,
        offset_of!(CrlInfo, last_update),
        c"lastUpdate",
        ASN1_TIME_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(CrlInfo, next_update),
        c"nextUpdate",
        ASN1_TIME_it,
    ),
    template_at(
        ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(CrlInfo, revoked),
        c"revoked",
        X509_REVOKED_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(CrlInfo, extensions),
        c"extensions",
        X509_EXTENSION_it,
    ),
]);

ffi_callback! {
    /// `crl_inf_cb`: a decoded list of entries is sorted by serial number for lookups.
    ///
    /// # Safety
    /// `pval` holds NULL or a live TBSCertList.
    pub(crate) unsafe extern "C" fn crl_inf_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, _exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let v = unsafe { pval.read() };
        // SAFETY: as above.
        let Some(a) = (unsafe { v.cast::<CrlInfo>().as_mut() }) else { return 1 };
        if operation == ASN1_OP_D2I_POST && !a.revoked.is_null() {
            // SAFETY: its entries; their comparison.
            unsafe { OPENSSL_sk_set_cmp_func(a.revoked.cast(), Some(revoked_cmp)) };
        }
        1
    }
}

/// `ASN1_SEQUENCE_enc` with `crl_inf_cb`.
static INFO_AUX: Aux = aux_ex(
    ASN1_AFLG_ENCODING,
    0,
    0,
    Some(crl_inf_cb),
    offset_of!(CrlInfo, enc),
);

item_fns! {
    /// TBSCertList.
    pub unsafe extern "C" fn X509_CRL_INFO_it = sequence::<CrlInfo, 7>(&INFO_TT, Some(&INFO_AUX), c"X509_CRL_INFO");
}

new_free! {
    pub unsafe extern "C" fn X509_CRL_INFO_new, pub unsafe extern "C" fn X509_CRL_INFO_free(X509_CRL_INFO) = X509_CRL_INFO_it;
}

i2d! {
    /// Encodes a TBSCertList (as it was decoded, unless it changed).
    pub unsafe extern "C" fn i2d_X509_CRL_INFO(X509_CRL_INFO) = X509_CRL_INFO_it;
}

d2i! {
    /// Decodes a TBSCertList (`ASN1_item_d2i`), keeping its encoding.
    pub unsafe extern "C" fn d2i_X509_CRL_INFO(X509_CRL_INFO) = X509_CRL_INFO_it;
}

// The method.

/// A method in a static.
struct Method(CrlMethod);

// SAFETY: immutable, with only function pointers.
unsafe impl Sync for Method {}

static INT_CRL_METH: Method = Method(CrlMethod {
    flags: 0,
    crl_init: None,
    crl_free: None,
    crl_lookup: Some(def_crl_lookup),
    crl_verify: Some(def_crl_verify),
});

/// `default_crl_method`.
static DEFAULT_CRL_METHOD: AtomicPtr<CrlMethod> =
    AtomicPtr::new((&raw const INT_CRL_METH.0).cast_mut());

ffi_export! {
    /// Makes `meth` (or, for NULL, the built-in one) the method of CRLs made from now on.
    ///
    /// # Safety
    /// `meth` is NULL or a method that outlives its use.
    pub unsafe extern "C" fn X509_CRL_set_default_method(meth: *const X509_CRL_METHOD)
    where failure = (), library = ERR_LIB_X509
    {
        let m = if meth.is_null() { (&raw const INT_CRL_METH.0).cast_mut() } else { meth.cast::<CrlMethod>().cast_mut() };
        DEFAULT_CRL_METHOD.store(m, Ordering::Release);
    }
}

ffi_export! {
    /// A new method with these functions, or NULL.
    ///
    /// # Safety
    /// The functions are NULL or of their kinds.
    pub unsafe extern "C" fn X509_CRL_METHOD_new(crl_init: Option<unsafe extern "C" fn(*mut X509_CRL) -> c_int>, crl_free: Option<unsafe extern "C" fn(*mut X509_CRL) -> c_int>, crl_lookup: Option<unsafe extern "C" fn(*mut X509_CRL, *mut *mut X509_REVOKED, *const ASN1_INTEGER, *const X509_NAME) -> c_int>, crl_verify: Option<unsafe extern "C" fn(*mut X509_CRL, *mut EVP_PKEY) -> c_int>) -> *mut X509_CRL_METHOD
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        let m = mem::alloc(core::mem::size_of::<CrlMethod>()).cast::<CrlMethod>();
        if m.is_null() {
            return ptr::null_mut();
        }
        let flags = METHOD_DYNAMIC;
        // SAFETY: new memory for a method.
        unsafe { m.write(CrlMethod { flags, crl_init, crl_free, crl_lookup, crl_verify }) };
        m.cast()
    }
}

ffi_export! {
    /// Frees a method `X509_CRL_METHOD_new` made (nothing else).
    ///
    /// # Safety
    /// `m` is NULL or a live method.
    pub unsafe extern "C" fn X509_CRL_METHOD_free(m: *mut X509_CRL_METHOD)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(mm) = (unsafe { m.cast::<CrlMethod>().as_ref() }) else { return };
        if mm.flags & METHOD_DYNAMIC != 0 {
            // SAFETY: made by `X509_CRL_METHOD_new`.
            unsafe { mem::release(m.cast()) };
        }
    }
}

ffi_export! {
    /// Sets the method's data in the CRL.
    ///
    /// # Safety
    /// `crl` is NULL or a live CRL.
    pub unsafe extern "C" fn X509_CRL_set_meth_data(crl: *mut X509_CRL, dat: *mut c_void)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { crl_of(crl) } {
            c.meth_data = dat;
        }
    }
}

ffi_export! {
    /// The method's data in the CRL.
    ///
    /// # Safety
    /// `crl` is NULL or a live CRL.
    pub unsafe extern "C" fn X509_CRL_get_meth_data(crl: *mut X509_CRL) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { crl_of(crl) }.map_or(ptr::null_mut(), |c| c.meth_data)
    }
}

/// The CRL's method's functions, read before calling any.
fn meth(c: &Crl) -> Option<&CrlMethod> {
    // SAFETY: the built-in method or an application's live one.
    unsafe { c.meth.as_ref() }
}

// The CRL.

static CRL_TT: Templates<3> = Templates([
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Crl, crl),
        c"crl",
        X509_CRL_INFO_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Crl, sig_alg),
        c"sig_alg",
        X509_ALGOR_it,
    ),
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Crl, signature),
        c"signature",
        ASN1_BIT_STRING_it,
    ),
]);

/// `ASN1_SEQUENCE_ref` with `crl_cb`.
static CRL_AUX: Aux = aux_ex(
    ASN1_AFLG_REFCOUNT,
    offset_of!(Crl, references),
    offset_of!(Crl, lock),
    Some(crl_cb),
    0,
);

/// `GENERAL_NAMES_free` as a stack's free function.
unsafe extern "C" fn free_names(p: *mut c_void) {
    // SAFETY: an element of the stack, which the stack owned.
    unsafe { GENERAL_NAMES_free(p.cast()) };
}

/// Frees what decoding cached.
fn free_cached(c: &mut Crl) {
    // SAFETY: its own, or NULL.
    unsafe { AUTHORITY_KEYID_free(c.akid) };
    // SAFETY: as above.
    unsafe { ISSUING_DIST_POINT_free(c.idp) };
    // SAFETY: as above.
    unsafe { ASN1_INTEGER_free(c.crl_number) };
    // SAFETY: as above.
    unsafe { ASN1_INTEGER_free(c.base_crl_number) };
    // SAFETY: as above, with its names.
    unsafe { OPENSSL_sk_pop_free(c.issuers.cast(), Some(free_names)) };
}

/// The CRL's extension of `nid`, decoded (see `X509V3_get_d2i`).
fn ext_d2i(c: &Crl, nid: c_int, i: &mut c_int) -> *mut c_void {
    // SAFETY: the CRL's extensions, or NULL; a slot.
    unsafe { X509V3_get_d2i(c.crl.extensions, nid, i, ptr::null_mut()) }
}

/// A bit string's first two octets as reason flags.
fn reasons(bs: &ASN1_BIT_STRING) -> c_int {
    let n = usize::try_from(bs.length).unwrap_or(0);
    if n == 0 || bs.data.is_null() {
        return 0;
    }
    // SAFETY: a string's data holds its length.
    let d = unsafe { core::slice::from_raw_parts(bs.data, n) };
    let mut v = c_int::from(d.first().copied().unwrap_or(0));
    if let Some(&b) = d.get(1) {
        v |= c_int::from(b) << 8;
    }
    v
}

/// `setup_idp`.
///
/// # Safety
/// `crl` is the live CRL `c` is.
unsafe fn setup_idp(crl: *mut X509_CRL, c: &mut Crl) -> bool {
    // SAFETY: the CRL's issuing distribution point, decoded.
    let Some(idp) = (unsafe { c.idp.as_ref() }) else {
        return true;
    };
    let mut only = 0;
    c.idp_flags |= IDP_PRESENT;
    for (v, flag) in [
        (idp.onlyuser, IDP_ONLYUSER),
        (idp.onlyCA, IDP_ONLYCA),
        (idp.onlyattr, IDP_ONLYATTR),
    ] {
        if v > 0 {
            only += 1;
            c.idp_flags |= flag;
        }
    }
    if only > 1 {
        c.idp_flags |= IDP_INVALID;
    }
    if idp.indirectCRL > 0 {
        c.idp_flags |= IDP_INDIRECT;
    }
    // SAFETY: its reasons, or NULL.
    if let Some(r) = unsafe { idp.onlysomereasons.as_ref() } {
        c.idp_flags |= IDP_REASONS;
        let v = reasons(r);
        if r.length > 0 {
            c.idp_reasons = v;
        }
        c.idp_reasons &= CRLDP_ALL_REASONS;
    }
    // SAFETY: the point's name, or NULL; the CRL's issuer.
    let issuer = unsafe { X509_CRL_get_issuer(crl) };
    // SAFETY: the point's name, or NULL; the issuer.
    let ret = unsafe { DIST_POINT_set_dpname(idp.distpoint, issuer) } != 0;
    if c.idp_flags == IDP_PRESENT && idp.distpoint.is_null() {
        c.idp_flags |= IDP_INVALID;
    }
    ret
}

/// `crl_set_issuers`: each entry's certificate issuer and reason; `false` only when memory
/// runs out.
fn set_issuers(c: &mut Crl) -> bool {
    let revoked = c.crl.revoked;
    let mut gens: *mut GENERAL_NAMES = ptr::null_mut();
    // SAFETY: the entries, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(revoked.cast()) } {
        // SAFETY: an index within them.
        let rp = unsafe { OPENSSL_sk_value(revoked.cast(), i) }.cast::<X509_REVOKED>();
        // SAFETY: an entry of them.
        let Some(rev) = (unsafe { revoked_of(rp) }) else {
            continue;
        };
        let mut j: c_int = 0;
        // SAFETY: the entry's extensions; a slot.
        let gtmp: *mut GENERAL_NAMES = unsafe {
            X509V3_get_d2i(
                rev.extensions,
                NID_certificate_issuer,
                &raw mut j,
                ptr::null_mut(),
            )
        }
        .cast();
        if gtmp.is_null() && j != -1 {
            c.flags |= f(EXFLAG_INVALID);
            return true;
        }
        if !gtmp.is_null() {
            if c.issuers.is_null() {
                // SAFETY: no preconditions.
                c.issuers = unsafe { OPENSSL_sk_new_null() }.cast();
                if c.issuers.is_null() {
                    // SAFETY: decoded above.
                    unsafe { GENERAL_NAMES_free(gtmp) };
                    return false;
                }
            }
            // SAFETY: the list; the names, which it takes.
            if unsafe { OPENSSL_sk_push(c.issuers.cast(), gtmp.cast()) } == 0 {
                // SAFETY: as above.
                unsafe { GENERAL_NAMES_free(gtmp) };
                return false;
            }
            gens = gtmp;
        }
        rev.issuer = gens;
        // SAFETY: as above.
        let reason =
            unsafe { X509V3_get_d2i(rev.extensions, NID_crl_reason, &raw mut j, ptr::null_mut()) }
                .cast::<ASN1_STRING>();
        if reason.is_null() && j != -1 {
            c.flags |= f(EXFLAG_INVALID);
            return true;
        }
        if reason.is_null() {
            rev.reason = CRL_REASON_NONE;
        } else {
            // SAFETY: the decoded reason.
            let v = unsafe { ASN1_ENUMERATED_get(reason) };
            rev.reason = c_int::try_from(v).unwrap_or(-1);
            // SAFETY: as above.
            unsafe { ASN1_ENUMERATED_free(reason) };
        }
        // SAFETY: the entry's extensions, or NULL.
        for k in 0..unsafe { OPENSSL_sk_num(rev.extensions.cast()) } {
            // SAFETY: an index within them.
            let ext =
                unsafe { OPENSSL_sk_value(rev.extensions.cast(), k) }.cast::<X509_EXTENSION>();
            // SAFETY: an extension of them.
            if unsafe { X509_EXTENSION_get_critical(ext) } != 0 {
                // SAFETY: as above.
                let obj = unsafe { X509_EXTENSION_get_object(ext) };
                // SAFETY: its object.
                if unsafe { OBJ_obj2nid(obj) } == NID_certificate_issuer {
                    continue;
                }
                c.flags |= f(EXFLAG_CRITICAL);
                break;
            }
        }
    }
    true
}

/// `crl_cb`'s `ASN1_OP_D2I_POST`: what decoding caches.
///
/// # Safety
/// `crl` is the live CRL `c` is.
unsafe fn decoded(crl: *mut X509_CRL, c: &mut Crl) -> c_int {
    // SAFETY: no preconditions.
    let sha1 = unsafe { crate::evp::legacy_md::EVP_sha1() };
    // SAFETY: the CRL; its fingerprint's buffer.
    if unsafe { X509_CRL_digest(crl, sha1, c.sha1_hash.as_mut_ptr(), ptr::null_mut()) } == 0 {
        c.flags |= f(EXFLAG_NO_FINGERPRINT);
    }
    let mut i: c_int = 0;
    c.idp = ext_d2i(c, NID_issuing_distribution_point, &mut i).cast();
    if !c.idp.is_null() {
        // SAFETY: the caller's guarantee.
        if !unsafe { setup_idp(crl, c) } {
            c.flags |= f(EXFLAG_INVALID);
        }
    } else if i != -1 {
        c.flags |= f(EXFLAG_INVALID);
    }
    c.akid = ext_d2i(c, NID_authority_key_identifier, &mut i).cast();
    if c.akid.is_null() && i != -1 {
        c.flags |= f(EXFLAG_INVALID);
    }
    c.crl_number = ext_d2i(c, NID_crl_number, &mut i).cast();
    if c.crl_number.is_null() && i != -1 {
        c.flags |= f(EXFLAG_INVALID);
    }
    c.base_crl_number = ext_d2i(c, NID_delta_crl, &mut i).cast();
    if c.base_crl_number.is_null() && i != -1 {
        c.flags |= f(EXFLAG_INVALID);
    }
    if !c.base_crl_number.is_null() && c.crl_number.is_null() {
        c.flags |= f(EXFLAG_INVALID);
    }
    let exts = c.crl.extensions;
    // SAFETY: the CRL's extensions, or NULL.
    for idx in 0..unsafe { OPENSSL_sk_num(exts.cast()) } {
        // SAFETY: an index within them.
        let ext = unsafe { OPENSSL_sk_value(exts.cast(), idx) }.cast::<X509_EXTENSION>();
        // SAFETY: an extension of them.
        let obj = unsafe { X509_EXTENSION_get_object(ext) };
        // SAFETY: its object.
        let nid = unsafe { OBJ_obj2nid(obj) };
        if nid == NID_freshest_crl {
            c.flags |= f(EXFLAG_FRESHEST);
        }
        // SAFETY: as above.
        if unsafe { X509_EXTENSION_get_critical(ext) } != 0 {
            if nid == NID_issuing_distribution_point
                || nid == NID_authority_key_identifier
                || nid == NID_delta_crl
            {
                continue;
            }
            c.flags |= f(EXFLAG_CRITICAL);
            break;
        }
    }
    if !set_issuers(c) {
        return 0;
    }
    if let Some(init) = meth(c).and_then(|m| m.crl_init) {
        // SAFETY: the method's function, given the CRL (no lock held).
        if unsafe { init(crl) } == 0 {
            return 0;
        }
    }
    c.flags |= f(EXFLAG_SET);
    1
}

ffi_callback! {
    /// `crl_cb`: a new or re-decoded CRL has nothing cached and the default method (a
    /// re-decoded one first runs its method's `crl_free`); decoding caches what path validation
    /// reads; freeing runs the method's `crl_free` and frees the cache and properties; a copy
    /// takes the original's library context.
    ///
    /// # Safety
    /// `pval` holds NULL or a live CRL; `exarg` is the operation's.
    pub(crate) unsafe extern "C" fn crl_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let v = unsafe { pval.read() };
        let crl = v.cast::<X509_CRL>();
        // SAFETY: as above.
        let Some(c) = (unsafe { crl_of(crl) }) else { return 1 };
        match operation {
            ASN1_OP_D2I_PRE | ASN1_OP_NEW_POST => {
                if operation == ASN1_OP_D2I_PRE {
                    if let Some(free) = meth(c).and_then(|m| m.crl_free) {
                        // SAFETY: the method's function, given the CRL.
                        if unsafe { free(crl) } == 0 {
                            return 0;
                        }
                    }
                    free_cached(c);
                }
                c.idp = ptr::null_mut();
                c.akid = ptr::null_mut();
                c.flags = 0;
                c.idp_flags = 0;
                c.idp_reasons = CRLDP_ALL_REASONS;
                c.meth = DEFAULT_CRL_METHOD.load(Ordering::Acquire);
                c.meth_data = ptr::null_mut();
                c.issuers = ptr::null_mut();
                c.crl_number = ptr::null_mut();
                c.base_crl_number = ptr::null_mut();
                1
            }
            // SAFETY: the CRL.
            ASN1_OP_D2I_POST => unsafe { decoded(crl, c) },
            ASN1_OP_FREE_POST => {
                if let Some(free) = meth(c).and_then(|m| m.crl_free) {
                    // SAFETY: as above.
                    if unsafe { free(crl) } == 0 {
                        return 0;
                    }
                }
                free_cached(c);
                // SAFETY: its own copy, or NULL.
                unsafe { mem::release(c.propq.cast()) };
                c.propq = ptr::null_mut();
                1
            }
            ASN1_OP_DUP_POST => {
                // SAFETY: the original, which the copy was made from.
                let Some(old) = (unsafe { exarg.cast::<Crl>().as_ref() }) else { return 1 };
                // SAFETY: its properties, NULL or a string.
                c_int::from(unsafe { set0_libctx(&mut c.libctx, &mut c.propq, old.libctx, old.propq) })
            }
            _ => 1,
        }
    }
}

item_fns! {
    /// CertificateList: SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }.
    pub unsafe extern "C" fn X509_CRL_it = sequence::<Crl, 3>(&CRL_TT, Some(&CRL_AUX), c"X509_CRL");
}

new_free! {
    pub unsafe extern "C" fn X509_CRL_new, pub unsafe extern "C" fn X509_CRL_free(X509_CRL) = X509_CRL_it;
}

i2d! {
    /// Encodes a CRL.
    pub unsafe extern "C" fn i2d_X509_CRL(X509_CRL) = X509_CRL_it;
}

d2i! {
    /// Decodes a CRL (`ASN1_item_d2i`), caching its extensions.
    pub unsafe extern "C" fn d2i_X509_CRL(X509_CRL) = X509_CRL_it;
}

ffi_export! {
    /// A copy of the CRL (through its encoding, so with its cache), or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live CRL.
    pub unsafe extern "C" fn X509_CRL_dup(x: *const X509_CRL) -> *mut X509_CRL
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_CRL_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_dup(it, x.cast_mut().cast()) }.cast()
    }
}

ffi_export! {
    /// A new CRL in `libctx`, with `propq` (copied) for what it fetches, or NULL.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `propq` is NULL or a string.
    pub unsafe extern "C" fn X509_CRL_new_ex(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut X509_CRL
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_CRL_it() };
        // SAFETY: the type's item.
        let x: *mut X509_CRL = unsafe { ASN1_item_new(it) }.cast();
        // SAFETY: just made, or NULL.
        if let Some(c) = unsafe { crl_of(x) }
            // SAFETY: the caller's guarantee.
            && !unsafe { set0_libctx(&mut c.libctx, &mut c.propq, libctx, propq) }
        {
            // SAFETY: made above.
            unsafe { X509_CRL_free(x) };
            return ptr::null_mut();
        }
        x
    }
}

ffi_export! {
    /// Takes another reference to the CRL: 1, or 0.
    ///
    /// # Safety
    /// `crl` is NULL or a live CRL.
    pub unsafe extern "C" fn X509_CRL_up_ref(crl: *mut X509_CRL) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if crl.is_null() {
            return 0;
        }
        let mut v = crl.cast::<ASN1_VALUE>();
        // SAFETY: no preconditions.
        let it = unsafe { X509_CRL_it() };
        // SAFETY: a live CRL of the item.
        c_int::from(unsafe { crate::asn1::tpl::do_lock(&raw mut v, 1, it) } > 1)
    }
}

ffi_export! {
    /// Adds the entry (which the CRL takes) to the CRL's list: 1, or 0.
    ///
    /// # Safety
    /// `crl` is NULL or a live CRL; `rev` is a live entry.
    pub unsafe extern "C" fn X509_CRL_add0_revoked(crl: *mut X509_CRL, rev: *mut X509_REVOKED) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { crl_of(crl) }) else { return 0 };
        let inf = &mut c.crl;
        if inf.revoked.is_null() {
            // SAFETY: the entries' comparison.
            inf.revoked = unsafe { OPENSSL_sk_new(Some(revoked_cmp)) }.cast();
        }
        // SAFETY: the list, or NULL; the entry, which it takes.
        if inf.revoked.is_null() || unsafe { OPENSSL_sk_push(inf.revoked.cast(), rev.cast()) } == 0 {
            err::raise(ERR_LIB_ASN1, ERR_R_CRYPTO_LIB, "X509_CRL_add0_revoked");
            return 0;
        }
        inf.enc.modified = 1;
        1
    }
}

ffi_export! {
    /// Checks the CRL's signature with `r` through its method: 1, or 0 (or what the method
    /// says).
    ///
    /// # Safety
    /// `crl` is NULL or a live CRL; `r` is NULL or a live key.
    pub unsafe extern "C" fn X509_CRL_verify(crl: *mut X509_CRL, r: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { crl_of(crl) }) else { return 0 };
        let Some(verify) = meth(c).and_then(|m| m.crl_verify) else { return 0 };
        // SAFETY: the method's function, given the CRL and key.
        unsafe { verify(crl, r) }
    }
}

ffi_export! {
    /// Looks up the entry of `serial` (of the CRL's issuer): 1 (into `*ret`, if not NULL), 2
    /// if it says the certificate was removed from the CRL, or 0.
    ///
    /// # Safety
    /// `crl` is NULL or a live CRL; `ret` is NULL or writable; `serial` is a live INTEGER.
    pub unsafe extern "C" fn X509_CRL_get0_by_serial(crl: *mut X509_CRL, ret: *mut *mut X509_REVOKED, serial: *const ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { crl_of(crl) }) else { return 0 };
        let Some(lookup) = meth(c).and_then(|m| m.crl_lookup) else { return 0 };
        // SAFETY: the method's function, given the CRL and the caller's arguments.
        unsafe { lookup(crl, ret, serial, ptr::null()) }
    }
}

ffi_export! {
    /// Looks up the entry of the certificate (its serial number and issuer): as
    /// [`X509_CRL_get0_by_serial`].
    ///
    /// # Safety
    /// `crl` is NULL or a live CRL; `ret` is NULL or writable; `x` is a live certificate.
    pub unsafe extern "C" fn X509_CRL_get0_by_cert(crl: *mut X509_CRL, ret: *mut *mut X509_REVOKED, x: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { crl_of(crl) }) else { return 0 };
        let Some(lookup) = meth(c).and_then(|m| m.crl_lookup) else { return 0 };
        // SAFETY: the certificate.
        let serial = unsafe { X509_get0_serialNumber(x) };
        // SAFETY: as above.
        let issuer = unsafe { X509_get_issuer_name(x) };
        // SAFETY: the method's function, given the CRL and the certificate's serial and issuer.
        unsafe { lookup(crl, ret, serial, issuer) }
    }
}

ffi_callback! {
    /// `def_crl_verify`: the signature, if both AlgorithmIdentifiers agree.
    ///
    /// # Safety
    /// `crl` is a live CRL; `r` is NULL or a live key.
    pub(crate) unsafe extern "C" fn def_crl_verify(crl: *mut X509_CRL, r: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { crl_of(crl) }) else { return 0 };
        // SAFETY: its AlgorithmIdentifiers.
        if unsafe { X509_ALGOR_cmp(&raw const c.sig_alg, &raw const c.crl.sig_alg) } != 0 {
            err::raise(ERR_LIB_X509, X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH, "def_crl_verify");
            return 0;
        }
        // SAFETY: no preconditions.
        let it = unsafe { X509_CRL_INFO_it() };
        // SAFETY: the CRL's TBSCertList, algorithm, and signature; the caller's key.
        unsafe { ASN1_item_verify_ex(it, &raw const c.sig_alg, &raw const c.signature, (&raw const c.crl).cast(), ptr::null(), r, c.libctx, c.propq) }
    }
}

/// `crl_revoked_issuer_match`.
///
/// # Safety
/// `crl` is a live CRL; `nm` is NULL or a live name.
unsafe fn issuer_match(crl: *const X509_CRL, nm: *const X509_NAME, rev: &Revoked) -> bool {
    // SAFETY: the caller's guarantee.
    let crl_issuer = unsafe { X509_CRL_get_issuer(crl) }.cast_const();
    if rev.issuer.is_null() {
        // SAFETY: the names.
        return nm.is_null() || unsafe { X509_NAME_cmp(nm, crl_issuer) } == 0;
    }
    let nm = if nm.is_null() { crl_issuer } else { nm };
    // SAFETY: the entry's names.
    for i in 0..unsafe { OPENSSL_sk_num(rev.issuer.cast()) } {
        // SAFETY: an index within them.
        let g = unsafe { OPENSSL_sk_value(rev.issuer.cast(), i) }.cast::<GENERAL_NAME>();
        // SAFETY: a name of them.
        let Some(g) = (unsafe { g.as_ref() }) else {
            continue;
        };
        if g.type_ != GEN_DIRNAME {
            continue;
        }
        // SAFETY: a directory name's member.
        let dn = unsafe { g.d.directoryName };
        // SAFETY: the names.
        if unsafe { X509_NAME_cmp(nm, dn) } == 0 {
            return true;
        }
    }
    false
}

ffi_callback! {
    /// `def_crl_lookup`: the entries sorted by serial number (once, under the CRL's lock), then
    /// the first of `serial` whose issuer matches.
    ///
    /// # Safety
    /// `crl` is a live CRL; `ret` is NULL or writable; `serial` is a live INTEGER; `issuer` is
    /// NULL or a live name.
    pub(crate) unsafe extern "C" fn def_crl_lookup(crl: *mut X509_CRL, ret: *mut *mut X509_REVOKED, serial: *const ASN1_INTEGER, issuer: *const X509_NAME) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { crl_of(crl) }) else { return 0 };
        let revoked = c.crl.revoked;
        if revoked.is_null() || serial.is_null() {
            return 0;
        }
        // SAFETY: the entries.
        if unsafe { OPENSSL_sk_is_sorted(revoked.cast()) } == 0 {
            // SAFETY: the CRL's lock.
            if unsafe { CRYPTO_THREAD_write_lock(c.lock) } == 0 {
                return 0;
            }
            // SAFETY: the entries.
            unsafe { OPENSSL_sk_sort(revoked.cast()) };
            // SAFETY: as above.
            unsafe { CRYPTO_THREAD_unlock(c.lock) };
        }
        // SAFETY: all-zero is a valid entry to search with; its serial number a shallow copy.
        let mut rtmp: Revoked = unsafe { core::mem::zeroed() };
        // SAFETY: the caller's INTEGER.
        rtmp.serial_number = unsafe { serial.read() };
        let key = (&raw mut rtmp).cast::<c_void>();
        // SAFETY: the entries; the key.
        let mut idx = unsafe { OPENSSL_sk_find(revoked.cast(), key) };
        if idx < 0 {
            return 0;
        }
        // SAFETY: as above.
        let num = unsafe { OPENSSL_sk_num(revoked.cast()) };
        while idx < num {
            // SAFETY: an index within them.
            let rp = unsafe { OPENSSL_sk_value(revoked.cast(), idx) }.cast::<X509_REVOKED>();
            // SAFETY: an entry of them.
            let Some(rev) = (unsafe { revoked_of(rp) }) else { return 0 };
            // SAFETY: its serial number; the caller's.
            if unsafe { ASN1_INTEGER_cmp(&raw const rev.serial_number, serial) } != 0 {
                return 0;
            }
            // SAFETY: the CRL; the caller's name, or NULL.
            if unsafe { issuer_match(crl, issuer, rev) } {
                if !ret.is_null() {
                    // SAFETY: the caller's guarantee.
                    unsafe { ret.write(rp) };
                }
                return if rev.reason == CRL_REASON_REMOVE_FROM_CRL { 2 } else { 1 };
            }
            idx = idx.wrapping_add(1);
        }
        0
    }
}

// Getters and setters (`x509cset.c`).

macro_rules! crl_getters {
    ($(
        $(#[$attr:meta])*
        pub unsafe extern "C" fn $name:ident($x:ident: *$m:ident X509_CRL) -> $ret:ty = $fail:expr, |$c:ident| $body:expr;
    )*) => {$(
        ffi_export! {
            $(#[$attr])*
            ///
            /// # Safety
            /// `crl` is NULL or a live CRL.
            pub unsafe extern "C" fn $name($x: *$m X509_CRL) -> $ret
            where failure = $fail, library = ERR_LIB_X509
            {
                // SAFETY: the caller's guarantee.
                let Some($c) = (unsafe { crl_of($x) }) else { return $fail };
                $body
            }
        }
    )*};
}

crl_getters! {
    /// The version (0, version 1, when it's left out).
    pub unsafe extern "C" fn X509_CRL_get_version(crl: *const X509_CRL) -> c_long = 0, |c| {
        // SAFETY: its version, or NULL.
        unsafe { ASN1_INTEGER_get(c.crl.version) }
    };
    /// The time it was issued.
    pub unsafe extern "C" fn X509_CRL_get0_lastUpdate(crl: *const X509_CRL) -> *const ASN1_TIME = ptr::null(), |c| c.crl.last_update;
    /// The time the next is due, or NULL.
    pub unsafe extern "C" fn X509_CRL_get0_nextUpdate(crl: *const X509_CRL) -> *const ASN1_TIME = ptr::null(), |c| c.crl.next_update;
    /// The time it was issued (deprecated form).
    pub unsafe extern "C" fn X509_CRL_get_lastUpdate(crl: *mut X509_CRL) -> *mut ASN1_TIME = ptr::null_mut(), |c| c.crl.last_update;
    /// The time the next is due (deprecated form).
    pub unsafe extern "C" fn X509_CRL_get_nextUpdate(crl: *mut X509_CRL) -> *mut ASN1_TIME = ptr::null_mut(), |c| c.crl.next_update;
    /// The issuer, which the CRL keeps.
    pub unsafe extern "C" fn X509_CRL_get_issuer(crl: *const X509_CRL) -> *mut X509_NAME = ptr::null_mut(), |c| c.crl.issuer;
    /// The extensions, which the CRL keeps.
    pub unsafe extern "C" fn X509_CRL_get0_extensions(crl: *const X509_CRL) -> *const stack_st_X509_EXTENSION = ptr::null(), |c| c.crl.extensions;
    /// The TBSCertList's signature AlgorithmIdentifier (3.6), which the CRL keeps. NULL for a
    /// NULL CRL (OpenSSL's reads through it).
    pub unsafe extern "C" fn X509_CRL_get0_tbs_sigalg(crl: *const X509_CRL) -> *const X509_ALGOR = ptr::null(), |c| &raw const c.crl.sig_alg;
    /// The entries, which the CRL keeps.
    pub unsafe extern "C" fn X509_CRL_get_REVOKED(crl: *mut X509_CRL) -> *mut stack_st_X509_REVOKED = ptr::null_mut(), |c| c.crl.revoked;
    /// The NID of the signature algorithm.
    pub unsafe extern "C" fn X509_CRL_get_signature_nid(crl: *const X509_CRL) -> c_int = NID_undef, |c| {
        // SAFETY: its object.
        unsafe { OBJ_obj2nid(c.sig_alg.algorithm) }
    };
    /// The number of extensions.
    pub unsafe extern "C" fn X509_CRL_get_ext_count(crl: *const X509_CRL) -> c_int = 0, |c| {
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_count(c.crl.extensions) }
    };
}

ffi_export! {
    /// Sets the version (making it if absent): 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live CRL.
    pub unsafe extern "C" fn X509_CRL_set_version(x: *mut X509_CRL, version: c_long) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { crl_of(x) }) else { return 0 };
        if c.crl.version.is_null() {
            // SAFETY: no preconditions.
            c.crl.version = unsafe { ASN1_INTEGER_new() };
            if c.crl.version.is_null() {
                return 0;
            }
        }
        // SAFETY: its version.
        if unsafe { ASN1_INTEGER_set(c.crl.version, version) } == 0 {
            return 0;
        }
        c.crl.enc.modified = 1;
        1
    }
}

ffi_export! {
    /// Sets the issuer to a copy of `name`: 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live CRL; `name` is NULL or a live name.
    pub unsafe extern "C" fn X509_CRL_set_issuer_name(x: *mut X509_CRL, name: *const X509_NAME) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { crl_of(x) }) else { return 0 };
        // SAFETY: its slot; the caller's name.
        if unsafe { X509_NAME_set(&raw mut c.crl.issuer, name) } == 0 {
            return 0;
        }
        c.crl.enc.modified = 1;
        1
    }
}

ffi_export! {
    /// Sets the time it was issued to a copy of `tm`: 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live CRL; `tm` is NULL or a live time.
    pub unsafe extern "C" fn X509_CRL_set1_lastUpdate(x: *mut X509_CRL, tm: *const ASN1_TIME) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { crl_of(x) }) else { return 0 };
        if tm.is_null() {
            return 0;
        }
        // SAFETY: its slot; the caller's time.
        unsafe { set1_time(Some(&mut c.crl.enc.modified), &raw mut c.crl.last_update, tm) }
    }
}

ffi_export! {
    /// Sets the time the next is due to a copy of `tm` (none for NULL): 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live CRL; `tm` is NULL or a live time.
    pub unsafe extern "C" fn X509_CRL_set1_nextUpdate(x: *mut X509_CRL, tm: *const ASN1_TIME) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { crl_of(x) }) else { return 0 };
        // SAFETY: its slot; the caller's time, or NULL.
        unsafe { set1_time(Some(&mut c.crl.enc.modified), &raw mut c.crl.next_update, tm) }
    }
}

ffi_export! {
    /// Sorts the entries by serial number, numbering them: 1.
    ///
    /// # Safety
    /// `c` is NULL or a live CRL.
    pub unsafe extern "C" fn X509_CRL_sort(c: *mut X509_CRL) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(cr) = (unsafe { crl_of(c) }) else { return 0 };
        let revoked = cr.crl.revoked;
        // SAFETY: the entries, or NULL.
        unsafe { OPENSSL_sk_sort(revoked.cast()) };
        // SAFETY: as above.
        for i in 0..unsafe { OPENSSL_sk_num(revoked.cast()) } {
            // SAFETY: an index within them.
            let rp = unsafe { OPENSSL_sk_value(revoked.cast(), i) }.cast::<X509_REVOKED>();
            // SAFETY: an entry of them.
            if let Some(r) = unsafe { revoked_of(rp) } {
                r.sequence = i;
            }
        }
        cr.crl.enc.modified = 1;
        1
    }
}

ffi_export! {
    /// The signature and its AlgorithmIdentifier (the CRL keeps them), into `*psig` and
    /// `*palg` where given.
    ///
    /// # Safety
    /// `crl` is NULL or a live CRL; `psig` and `palg` are NULL or writable.
    pub unsafe extern "C" fn X509_CRL_get0_signature(crl: *const X509_CRL, psig: *mut *const ASN1_BIT_STRING, palg: *mut *const X509_ALGOR)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { crl_of(crl) }) else { return };
        if !psig.is_null() {
            // SAFETY: as above.
            unsafe { psig.write(&raw const c.signature) };
        }
        if !palg.is_null() {
            // SAFETY: as above.
            unsafe { palg.write(&raw const c.sig_alg) };
        }
    }
}

ffi_export! {
    /// Encodes the TBSCertList afresh, `i2d` conventions.
    ///
    /// # Safety
    /// `crl` is NULL or a live CRL; `pp` as for `i2d_X509_CRL_INFO`.
    pub unsafe extern "C" fn i2d_re_X509_CRL_tbs(crl: *mut X509_CRL, pp: *mut *mut c_uchar) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { crl_of(crl) }) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "i2d_re_X509_CRL_tbs");
            return 0;
        };
        c.crl.enc.modified = 1;
        // SAFETY: as above.
        unsafe { i2d_X509_CRL_INFO((&raw const c.crl).cast(), pp) }
    }
}

macro_rules! revoked_getters {
    ($(
        $(#[$attr:meta])*
        pub unsafe extern "C" fn $name:ident($x:ident: *$m:ident X509_REVOKED) -> $ret:ty = $fail:expr, |$c:ident| $body:expr;
    )*) => {$(
        ffi_export! {
            $(#[$attr])*
            ///
            /// # Safety
            /// `x` is NULL or a live entry.
            pub unsafe extern "C" fn $name($x: *$m X509_REVOKED) -> $ret
            where failure = $fail, library = ERR_LIB_X509
            {
                // SAFETY: the caller's guarantee.
                let Some($c) = (unsafe { revoked_of($x) }) else { return $fail };
                $body
            }
        }
    )*};
}

revoked_getters! {
    /// The time of revocation.
    pub unsafe extern "C" fn X509_REVOKED_get0_revocationDate(x: *const X509_REVOKED) -> *const ASN1_TIME = ptr::null(), |r| r.revocation_date;
    /// The serial number, which the entry keeps.
    pub unsafe extern "C" fn X509_REVOKED_get0_serialNumber(x: *const X509_REVOKED) -> *const ASN1_INTEGER = ptr::null(), |r| &raw const r.serial_number;
    /// The extensions, which the entry keeps.
    pub unsafe extern "C" fn X509_REVOKED_get0_extensions(x: *const X509_REVOKED) -> *const stack_st_X509_EXTENSION = ptr::null(), |r| r.extensions;
    /// The number of extensions.
    pub unsafe extern "C" fn X509_REVOKED_get_ext_count(x: *const X509_REVOKED) -> c_int = 0, |r| {
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_count(r.extensions) }
    };
}

ffi_export! {
    /// Sets the time of revocation to a copy of `tm`: 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live entry; `tm` is NULL or a live time.
    pub unsafe extern "C" fn X509_REVOKED_set_revocationDate(x: *mut X509_REVOKED, tm: *mut ASN1_TIME) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { revoked_of(x) }) else { return 0 };
        if tm.is_null() {
            return 0;
        }
        // SAFETY: its slot; the caller's time.
        unsafe { set1_time(None, &raw mut r.revocation_date, tm) }
    }
}

ffi_export! {
    /// Sets the serial number to a copy of `serial`: 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live entry; `serial` is NULL or a live INTEGER.
    pub unsafe extern "C" fn X509_REVOKED_set_serialNumber(x: *mut X509_REVOKED, serial: *mut ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { revoked_of(x) }) else { return 0 };
        let inn = &raw mut r.serial_number;
        if inn == serial {
            return 1;
        }
        // SAFETY: its serial number; the caller's.
        unsafe { ASN1_STRING_copy(inn.cast(), serial.cast()) }
    }
}

// Extensions (`x509_ext.c`).

/// `delete_ext`: the extension at `loc` taken out, the list freed once empty.
///
/// # Safety
/// `sk` holds NULL or a live list.
unsafe fn delete_ext(sk: &mut *mut stack_st_X509_EXTENSION, loc: c_int) -> *mut X509_EXTENSION {
    // SAFETY: the caller's guarantee.
    let ret = unsafe { X509v3_delete_ext(*sk, loc) };
    // SAFETY: as above.
    if !sk.is_null() && unsafe { OPENSSL_sk_num(sk.cast()) } == 0 {
        // SAFETY: as above, empty.
        unsafe { OPENSSL_sk_pop_free(sk.cast(), Some(crate::x509v3::registry::free_ext)) };
        *sk = ptr::null_mut();
    }
    ret
}

/// The CRL's TBSCertList fields, for the extension functions.
///
/// # Safety
/// `x` is NULL or a live CRL.
unsafe fn info_of<'a>(x: *const X509_CRL) -> Option<&'a mut CrlInfo> {
    // SAFETY: the caller's guarantee.
    unsafe { crl_of(x) }.map(|c| &mut c.crl)
}

ffi_export! {
    /// The index of the CRL's next extension of `nid` after `lastpos`, or -1 (-2 for an unknown
    /// NID).
    ///
    /// # Safety
    /// `x` is NULL or a live CRL.
    pub unsafe extern "C" fn X509_CRL_get_ext_by_NID(x: *const X509_CRL, nid: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let exts = unsafe { info_of(x) }.map_or(ptr::null_mut(), |c| c.extensions);
        // SAFETY: the extensions, or NULL.
        unsafe { X509v3_get_ext_by_NID(exts, nid, lastpos) }
    }
}

ffi_export! {
    /// The index of the CRL's next extension of `obj` after `lastpos`, or -1.
    ///
    /// # Safety
    /// `x` is NULL or a live CRL; `obj` is NULL or a live object.
    pub unsafe extern "C" fn X509_CRL_get_ext_by_OBJ(x: *const X509_CRL, obj: *const ASN1_OBJECT, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let exts = unsafe { info_of(x) }.map_or(ptr::null_mut(), |c| c.extensions);
        // SAFETY: the extensions, or NULL; the caller's object.
        unsafe { X509v3_get_ext_by_OBJ(exts, obj, lastpos) }
    }
}

ffi_export! {
    /// The index of the CRL's next extension after `lastpos` that is (or isn't) critical, or -1.
    ///
    /// # Safety
    /// `x` is NULL or a live CRL.
    pub unsafe extern "C" fn X509_CRL_get_ext_by_critical(x: *const X509_CRL, crit: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let exts = unsafe { info_of(x) }.map_or(ptr::null_mut(), |c| c.extensions);
        // SAFETY: the extensions, or NULL.
        unsafe { X509v3_get_ext_by_critical(exts, crit, lastpos) }
    }
}

ffi_export! {
    /// The CRL's extension at `loc` (it keeps it), or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live CRL.
    pub unsafe extern "C" fn X509_CRL_get_ext(x: *const X509_CRL, loc: c_int) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let exts = unsafe { info_of(x) }.map_or(ptr::null_mut(), |c| c.extensions);
        // SAFETY: the extensions, or NULL.
        unsafe { X509v3_get_ext(exts, loc) }
    }
}

ffi_export! {
    /// Takes the CRL's extension at `loc` out (the caller frees it), or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live CRL.
    pub unsafe extern "C" fn X509_CRL_delete_ext(x: *mut X509_CRL, loc: c_int) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { info_of(x) }) else { return ptr::null_mut() };
        // SAFETY: its list.
        unsafe { delete_ext(&mut c.extensions, loc) }
    }
}

ffi_export! {
    /// The CRL's extension of `nid`, decoded (see `X509V3_get_d2i`), or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live CRL; `crit` and `idx` are NULL or writable.
    pub unsafe extern "C" fn X509_CRL_get_ext_d2i(x: *const X509_CRL, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let exts = unsafe { info_of(x) }.map_or(ptr::null_mut(), |c| c.extensions);
        // SAFETY: the extensions, or NULL; the caller's slots.
        unsafe { X509V3_get_d2i(exts, nid, crit, idx) }
    }
}

ffi_export! {
    /// Adds `value` encoded as an extension of `nid` to the CRL (see `X509V3_add1_i2d`).
    ///
    /// # Safety
    /// `x` is NULL or a live CRL; `value` is a value of the NID's method.
    pub unsafe extern "C" fn X509_CRL_add1_ext_i2d(x: *mut X509_CRL, nid: c_int, value: *mut c_void, crit: c_int, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { info_of(x) }) else { return 0 };
        // SAFETY: its list; the caller's value.
        unsafe { X509V3_add1_i2d(&raw mut c.extensions, nid, value, crit, flags) }
    }
}

ffi_export! {
    /// Adds a copy of the extension to the CRL at `loc` (-1 for the end): 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live CRL; `ex` is NULL or a live extension.
    pub unsafe extern "C" fn X509_CRL_add_ext(x: *mut X509_CRL, ex: *mut X509_EXTENSION, loc: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { info_of(x) }) else { return 0 };
        // SAFETY: its list; the caller's extension.
        c_int::from(!unsafe { X509v3_add_ext(&raw mut c.extensions, ex, loc) }.is_null())
    }
}

ffi_export! {
    /// The index of the entry's next extension of `nid` after `lastpos`, or -1 (-2 for an unknown
    /// NID).
    ///
    /// # Safety
    /// `x` is NULL or a live entry.
    pub unsafe extern "C" fn X509_REVOKED_get_ext_by_NID(x: *const X509_REVOKED, nid: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let exts = unsafe { revoked_of(x) }.map_or(ptr::null_mut(), |c| c.extensions);
        // SAFETY: the extensions, or NULL.
        unsafe { X509v3_get_ext_by_NID(exts, nid, lastpos) }
    }
}

ffi_export! {
    /// The index of the entry's next extension of `obj` after `lastpos`, or -1.
    ///
    /// # Safety
    /// `x` is NULL or a live entry; `obj` is NULL or a live object.
    pub unsafe extern "C" fn X509_REVOKED_get_ext_by_OBJ(x: *const X509_REVOKED, obj: *const ASN1_OBJECT, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let exts = unsafe { revoked_of(x) }.map_or(ptr::null_mut(), |c| c.extensions);
        // SAFETY: the extensions, or NULL; the caller's object.
        unsafe { X509v3_get_ext_by_OBJ(exts, obj, lastpos) }
    }
}

ffi_export! {
    /// The index of the entry's next extension after `lastpos` that is (or isn't) critical, or -1.
    ///
    /// # Safety
    /// `x` is NULL or a live entry.
    pub unsafe extern "C" fn X509_REVOKED_get_ext_by_critical(x: *const X509_REVOKED, crit: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let exts = unsafe { revoked_of(x) }.map_or(ptr::null_mut(), |c| c.extensions);
        // SAFETY: the extensions, or NULL.
        unsafe { X509v3_get_ext_by_critical(exts, crit, lastpos) }
    }
}

ffi_export! {
    /// The entry's extension at `loc` (it keeps it), or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live entry.
    pub unsafe extern "C" fn X509_REVOKED_get_ext(x: *const X509_REVOKED, loc: c_int) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let exts = unsafe { revoked_of(x) }.map_or(ptr::null_mut(), |c| c.extensions);
        // SAFETY: the extensions, or NULL.
        unsafe { X509v3_get_ext(exts, loc) }
    }
}

ffi_export! {
    /// Takes the entry's extension at `loc` out (the caller frees it), or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live entry.
    pub unsafe extern "C" fn X509_REVOKED_delete_ext(x: *mut X509_REVOKED, loc: c_int) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { revoked_of(x) }) else { return ptr::null_mut() };
        // SAFETY: its list.
        unsafe { delete_ext(&mut c.extensions, loc) }
    }
}

ffi_export! {
    /// The entry's extension of `nid`, decoded (see `X509V3_get_d2i`), or NULL.
    ///
    /// # Safety
    /// `x` is NULL or a live entry; `crit` and `idx` are NULL or writable.
    pub unsafe extern "C" fn X509_REVOKED_get_ext_d2i(x: *const X509_REVOKED, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let exts = unsafe { revoked_of(x) }.map_or(ptr::null_mut(), |c| c.extensions);
        // SAFETY: the extensions, or NULL; the caller's slots.
        unsafe { X509V3_get_d2i(exts, nid, crit, idx) }
    }
}

ffi_export! {
    /// Adds `value` encoded as an extension of `nid` to the entry (see `X509V3_add1_i2d`).
    ///
    /// # Safety
    /// `x` is NULL or a live entry; `value` is a value of the NID's method.
    pub unsafe extern "C" fn X509_REVOKED_add1_ext_i2d(x: *mut X509_REVOKED, nid: c_int, value: *mut c_void, crit: c_int, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { revoked_of(x) }) else { return 0 };
        // SAFETY: its list; the caller's value.
        unsafe { X509V3_add1_i2d(&raw mut c.extensions, nid, value, crit, flags) }
    }
}

ffi_export! {
    /// Adds a copy of the extension to the entry at `loc` (-1 for the end): 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live entry; `ex` is NULL or a live extension.
    pub unsafe extern "C" fn X509_REVOKED_add_ext(x: *mut X509_REVOKED, ex: *mut X509_EXTENSION, loc: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { revoked_of(x) }) else { return 0 };
        // SAFETY: its list; the caller's extension.
        c_int::from(!unsafe { X509v3_add_ext(&raw mut c.extensions, ex, loc) }.is_null())
    }
}

// Comparisons, signing, digests, and I/O.

ffi_export! {
    /// Compares the CRLs' issuers (`X509_NAME_cmp`).
    ///
    /// # Safety
    /// `a` and `b` are NULL or live CRLs.
    pub unsafe extern "C" fn X509_CRL_cmp(a: *const X509_CRL, b: *const X509_CRL) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let ia = unsafe { crl_of(a) }.map_or(ptr::null_mut(), |c| c.crl.issuer);
        // SAFETY: as above.
        let ib = unsafe { crl_of(b) }.map_or(ptr::null_mut(), |c| c.crl.issuer);
        // SAFETY: the issuers, or NULL.
        unsafe { X509_NAME_cmp(ia, ib) }
    }
}

ffi_export! {
    /// Compares the CRLs' SHA-1 fingerprints: -1, 0, or 1, or -2 if either has none.
    ///
    /// # Safety
    /// `a` and `b` are NULL or live CRLs.
    pub unsafe extern "C" fn X509_CRL_match(a: *const X509_CRL, b: *const X509_CRL) -> c_int
    where failure = -2, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(y)) = (unsafe { crl_of(a) }, unsafe { crl_of(b) }) else { return -2 };
        let nofp = f(EXFLAG_NO_FINGERPRINT);
        if x.flags & nofp != 0 || y.flags & nofp != 0 {
            return -2;
        }
        match x.sha1_hash.cmp(&y.sha1_hash) {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 1,
        }
    }
}

ffi_export! {
    /// Signs the CRL with `pkey` and `md`: the signature's length, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live CRL; `pkey` is a live key; `md` is NULL or a digest.
    pub unsafe extern "C" fn X509_CRL_sign(x: *mut X509_CRL, pkey: *mut EVP_PKEY, md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { crl_of(x) }) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "X509_CRL_sign");
            return 0;
        };
        c.crl.enc.modified = 1;
        // SAFETY: no preconditions.
        let it = unsafe { X509_CRL_INFO_it() };
        // SAFETY: the CRL's fields; the caller's key and digest.
        unsafe {
            ASN1_item_sign_ex(it, &raw mut c.crl.sig_alg, &raw mut c.sig_alg, &raw mut c.signature, (&raw const c.crl).cast(), ptr::null(), pkey, md, c.libctx, c.propq)
        }
    }
}

ffi_export! {
    /// Signs the CRL through `ctx`, initialised for signing: the signature's length, or 0.
    ///
    /// # Safety
    /// `x` is NULL or a live CRL; `ctx` is a live digest context with a key context.
    pub unsafe extern "C" fn X509_CRL_sign_ctx(x: *mut X509_CRL, ctx: *mut EVP_MD_CTX) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { crl_of(x) }) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "X509_CRL_sign_ctx");
            return 0;
        };
        c.crl.enc.modified = 1;
        // SAFETY: no preconditions.
        let it = unsafe { X509_CRL_INFO_it() };
        // SAFETY: the CRL's fields; the caller's context.
        unsafe { ASN1_item_sign_ctx(it, &raw mut c.crl.sig_alg, &raw mut c.sig_alg, &raw mut c.signature, (&raw const c.crl).cast(), ctx) }
    }
}

ffi_export! {
    /// The digest of the CRL's DER (the cached SHA-1 fingerprint for SHA-1 once decoded): 1, or
    /// 0.
    ///
    /// # Safety
    /// `data` is NULL or a live CRL; `type_` is NULL or a digest; `md` has room for its output;
    /// `len` is NULL or writable.
    pub unsafe extern "C" fn X509_CRL_digest(data: *const X509_CRL, type_: *const EVP_MD, md: *mut c_uchar, len: *mut c_uint) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if type_.is_null() {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "X509_CRL_digest");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { crl_of(data) }) else { return 0 };
        // SAFETY: the caller's digest.
        let sha1 = unsafe { crate::evp::digest::EVP_MD_is_a(type_, c"SHA1".as_ptr()) } != 0;
        if sha1 && c.flags & f(EXFLAG_SET) != 0 && c.flags & f(EXFLAG_NO_FINGERPRINT) == 0 {
            if !len.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { len.write(20) };
            }
            // SAFETY: the caller's room for a SHA-1 digest.
            unsafe { ptr::copy_nonoverlapping(c.sha1_hash.as_ptr(), md, c.sha1_hash.len()) };
            return 1;
        }
        // SAFETY: no preconditions.
        let it = unsafe { X509_CRL_it() };
        // SAFETY: the CRL, of the item; the caller's digest and room.
        unsafe { item_digest_ex(it, type_, data.cast_mut().cast(), md, len, c.libctx, c.propq) }
    }
}

ffi_export! {
    /// Decodes a CRL from a `FILE` (`ASN1_item_d2i_fp`).
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `crl` is NULL or holds NULL or a live CRL.
    pub unsafe extern "C" fn d2i_X509_CRL_fp(fp: *mut FILE, crl: *mut *mut X509_CRL) -> *mut X509_CRL
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_CRL_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_d2i_fp(it, fp, crl.cast()) }.cast()
    }
}

ffi_export! {
    /// Encodes a CRL to a `FILE`: 1, or 0.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `crl` is a live CRL.
    pub unsafe extern "C" fn i2d_X509_CRL_fp(fp: *mut FILE, crl: *const X509_CRL) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_CRL_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_fp(it, fp, crl.cast()) }
    }
}

ffi_export! {
    /// Decodes a CRL from a BIO (`ASN1_item_d2i_bio`).
    ///
    /// # Safety
    /// `bp` is a live BIO; `crl` is NULL or holds NULL or a live CRL.
    pub unsafe extern "C" fn d2i_X509_CRL_bio(bp: *mut BIO, crl: *mut *mut X509_CRL) -> *mut X509_CRL
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_CRL_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_d2i_bio(it, bp, crl.cast()) }.cast()
    }
}

ffi_export! {
    /// Encodes a CRL to a BIO: 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `crl` is a live CRL.
    pub unsafe extern "C" fn i2d_X509_CRL_bio(bp: *mut BIO, crl: *const X509_CRL) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_CRL_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_bio(it, bp, crl.cast()) }
    }
}

ffi_export! {
    /// The Suite B check of the CRL's signature algorithm against `pk` (`X509_V_OK` without
    /// `X509_V_FLAG_SUITEB_128_LOS`), an `X509_V_ERR_*`.
    ///
    /// # Safety
    /// `crl` is NULL or a live CRL; `pk` is NULL or a live key.
    pub unsafe extern "C" fn X509_CRL_check_suiteb(crl: *mut X509_CRL, pk: *mut EVP_PKEY, flags: c_ulong) -> c_int
    where failure = X509_V_OK, library = ERR_LIB_X509
    {
        let mut flags = flags;
        if flags & c_ulong::from(X509_V_FLAG_SUITEB_128_LOS.cast_unsigned()) == 0 {
            return X509_V_OK;
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { crl_of(crl) }) else { return X509_V_OK };
        // SAFETY: its TBSCertList's algorithm.
        let sign_nid = unsafe { OBJ_obj2nid(c.crl.sig_alg.algorithm) };
        // SAFETY: the caller's key, or NULL.
        unsafe { check_suite_b(pk, sign_nid, &mut flags) }
    }
}

/// `crl_extension_match`: whether both CRLs have at most one extension of `nid` and its value
/// is the same (or neither has it).
///
/// # Safety
/// `a` and `b` are live CRLs.
unsafe fn extension_match(a: *mut X509_CRL, b: *mut X509_CRL, nid: c_int) -> bool {
    let data = |x: *mut X509_CRL| -> Option<*mut rustyssl_abi::ASN1_OCTET_STRING> {
        // SAFETY: the caller's guarantee.
        let i = unsafe { X509_CRL_get_ext_by_NID(x, nid, -1) };
        if i < 0 {
            return Some(ptr::null_mut());
        }
        // SAFETY: as above.
        if unsafe { X509_CRL_get_ext_by_NID(x, nid, i) } != -1 {
            return None;
        }
        // SAFETY: as above; an index within its extensions.
        let ext = unsafe { X509_CRL_get_ext(x, i) };
        // SAFETY: an extension of it.
        Some(unsafe { X509_EXTENSION_get_data(ext) })
    };
    let (Some(ea), Some(eb)) = (data(a), data(b)) else {
        return false;
    };
    if ea.is_null() && eb.is_null() {
        return true;
    }
    if ea.is_null() || eb.is_null() {
        return false;
    }
    // SAFETY: the values.
    (unsafe { ASN1_OCTET_STRING_cmp(ea, eb) }) == 0
}

ffi_export! {
    /// A delta CRL of what `newer` adds to `base` (both of one issuer with CRL numbers, not
    /// deltas, the same key identifier and distribution point, `newer` newer), verified with
    /// and signed by `skey` with `md` if given; NULL on failure.
    ///
    /// # Safety
    /// `base` and `newer` are live CRLs; `skey` is NULL or a live key; `md` is NULL or a digest.
    pub unsafe extern "C" fn X509_CRL_diff(base: *mut X509_CRL, newer: *mut X509_CRL, skey: *mut EVP_PKEY, md: *const EVP_MD, _flags: c_uint) -> *mut X509_CRL
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        const F: &str = "X509_CRL_diff";
        // SAFETY: the caller's guarantee.
        let (Some(b), Some(n)) = (unsafe { crl_of(base) }, unsafe { crl_of(newer) }) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, F);
            return ptr::null_mut();
        };
        if !b.base_crl_number.is_null() || !n.base_crl_number.is_null() {
            err::raise(ERR_LIB_X509, X509_R_CRL_ALREADY_DELTA, F);
            return ptr::null_mut();
        }
        if b.crl_number.is_null() || n.crl_number.is_null() {
            err::raise(ERR_LIB_X509, X509_R_NO_CRL_NUMBER, F);
            return ptr::null_mut();
        }
        // SAFETY: their issuers.
        if unsafe { X509_NAME_cmp(b.crl.issuer, n.crl.issuer) } != 0 {
            err::raise(ERR_LIB_X509, X509_R_ISSUER_MISMATCH, F);
            return ptr::null_mut();
        }
        // SAFETY: the CRLs.
        if !unsafe { extension_match(base, newer, NID_authority_key_identifier) } {
            err::raise(ERR_LIB_X509, X509_R_AKID_MISMATCH, F);
            return ptr::null_mut();
        }
        // SAFETY: as above.
        if !unsafe { extension_match(base, newer, NID_issuing_distribution_point) } {
            err::raise(ERR_LIB_X509, X509_R_IDP_MISMATCH, F);
            return ptr::null_mut();
        }
        // SAFETY: their numbers.
        if unsafe { ASN1_INTEGER_cmp(n.crl_number, b.crl_number) } <= 0 {
            err::raise(ERR_LIB_X509, X509_R_NEWER_CRL_NOT_NEWER, F);
            return ptr::null_mut();
        }
        // SAFETY: the CRLs; the caller's key.
        if !skey.is_null() && (unsafe { X509_CRL_verify(base, skey) } <= 0 || unsafe { X509_CRL_verify(newer, skey) } <= 0) {
            err::raise(ERR_LIB_X509, X509_R_CRL_VERIFY_FAILURE, F);
            return ptr::null_mut();
        }
        // SAFETY: the base's library context and properties.
        let crl = unsafe { X509_CRL_new_ex(b.libctx, b.propq) };
        let ok = 'build: {
            let lib = || err::raise(ERR_LIB_X509, ERR_R_X509_LIB, F);
            // SAFETY: the new CRL, or NULL.
            if crl.is_null() || unsafe { X509_CRL_set_version(crl, c_long::from(X509_CRL_VERSION_2)) } == 0 {
                lib();
                break 'build false;
            }
            // SAFETY: the new CRL; the newer's fields.
            if unsafe { X509_CRL_set_issuer_name(crl, n.crl.issuer) } == 0
                // SAFETY: as above.
                || unsafe { X509_CRL_set1_lastUpdate(crl, n.crl.last_update) } == 0
                // SAFETY: as above.
                || unsafe { X509_CRL_set1_nextUpdate(crl, n.crl.next_update) } == 0
                // SAFETY: as above; the base's number.
                || unsafe { X509_CRL_add1_ext_i2d(crl, NID_delta_crl, b.crl_number.cast(), 1, 0) } <= 0
            {
                lib();
                break 'build false;
            }
            // SAFETY: the newer CRL.
            for i in 0..unsafe { X509_CRL_get_ext_count(newer) } {
                // SAFETY: an index within its extensions.
                let ext = unsafe { X509_CRL_get_ext(newer, i) };
                // SAFETY: the new CRL; an extension of the newer.
                if unsafe { X509_CRL_add_ext(crl, ext, -1) } == 0 {
                    lib();
                    break 'build false;
                }
            }
            let revs = n.crl.revoked;
            // SAFETY: the newer's entries, or NULL.
            for i in 0..unsafe { OPENSSL_sk_num(revs.cast()) } {
                // SAFETY: an index within them.
                let rvn = unsafe { OPENSSL_sk_value(revs.cast(), i) }.cast::<X509_REVOKED>();
                // SAFETY: an entry of them.
                let Some(rv) = (unsafe { revoked_of(rvn) }) else { continue };
                let mut rvtmp: *mut X509_REVOKED = ptr::null_mut();
                // SAFETY: the base CRL; its serial number.
                if unsafe { X509_CRL_get0_by_serial(base, &raw mut rvtmp, &raw const rv.serial_number) } == 0 {
                    // SAFETY: the newer's entry.
                    let copy = unsafe { X509_REVOKED_dup(rvn) };
                    if copy.is_null() {
                        err::raise(ERR_LIB_X509, ERR_R_ASN1_LIB, F);
                        break 'build false;
                    }
                    // SAFETY: the new CRL; the copy, which it takes.
                    if unsafe { X509_CRL_add0_revoked(crl, copy) } == 0 {
                        // SAFETY: not taken.
                        unsafe { X509_REVOKED_free(copy) };
                        lib();
                        break 'build false;
                    }
                }
            }
            // SAFETY: the new CRL; the caller's key and digest.
            if !skey.is_null() && !md.is_null() && unsafe { X509_CRL_sign(crl, skey, md) } == 0 {
                lib();
                break 'build false;
            }
            true
        };
        if !ok {
            // SAFETY: made above, or NULL.
            unsafe { X509_CRL_free(crl) };
            return ptr::null_mut();
        }
        crl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: the getters, setters, lookups, and extension functions of a NULL
    /// CRL or entry, which OpenSSL reads through, answer NULL, 0, or -1.
    #[test]
    fn null_crls_are_safe() {
        let c: *mut X509_CRL = ptr::null_mut();
        let r: *mut X509_REVOKED = ptr::null_mut();
        // SAFETY: NULL where OpenSSL dereferences it.
        assert_eq!(unsafe { X509_CRL_get_version(c) }, 0);
        // SAFETY: as above.
        assert!(unsafe { X509_CRL_get_issuer(c) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { X509_CRL_get_ext_count(c) }, 0);
        // SAFETY: as above.
        let i = unsafe { X509_CRL_get_ext_by_NID(c, NID_crl_number, -1) };
        assert_eq!(i, -1);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_CRL_verify(c, ptr::null_mut()) }, 0);
        // SAFETY: as above.
        let found = unsafe { X509_CRL_get0_by_serial(c, ptr::null_mut(), ptr::null()) };
        assert_eq!(found, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_CRL_sort(c) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_CRL_match(c, c) }, -2);
        // SAFETY: as above.
        assert!(unsafe { X509_REVOKED_get0_serialNumber(r) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { X509_REVOKED_get_ext_count(r) }, 0);
        // SAFETY: as above.
        let d = unsafe { X509_CRL_diff(c, c, ptr::null_mut(), ptr::null(), 0) };
        assert!(d.is_null());
        crate::err::take_all();
    }
}
