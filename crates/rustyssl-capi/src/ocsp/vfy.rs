//! Verifying (`ocsp_vfy.c`): a basic response's signer (by key hash or name), signature, and
//! chain, and that the signer is the CA of the certificates it speaks for or delegated by it;
//! and a request's signature.
//!
//! The responder's key hash is compared in constant time.

use core::ffi::{c_char, c_int, c_ulong};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_OCSP, ERR_R_X509_LIB, EVP_MAX_MD_SIZE, EXFLAG_XKUSAGE, GEN_DIRNAME, NID_OCSP_sign,
    NID_id_pkix_OCSP_noCheck, OCSP_BASICRESP, OCSP_NOCHAIN, OCSP_NOCHECKS, OCSP_NOEXPLICIT,
    OCSP_NOINTERN, OCSP_NOSIGS, OCSP_NOVERIFY, OCSP_PARTIAL_CHAIN, OCSP_R_CERTIFICATE_VERIFY_ERROR,
    OCSP_R_DIGEST_ERR, OCSP_R_DIGEST_SIZE_ERR, OCSP_R_MISSING_OCSPSIGNING_USAGE,
    OCSP_R_NO_CERTIFICATES_IN_CHAIN, OCSP_R_NO_SIGNER_KEY, OCSP_R_REQUEST_NOT_SIGNED,
    OCSP_R_RESPONSE_CONTAINS_NO_REVOCATION_DATA, OCSP_R_ROOT_CA_NOT_TRUSTED,
    OCSP_R_SIGNATURE_FAILURE, OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND, OCSP_R_UNKNOWN_MESSAGE_DIGEST,
    OCSP_R_UNSUPPORTED_REQUESTORNAME_TYPE, OCSP_REQUEST, OCSP_TRUSTOTHER, SHA_DIGEST_LENGTH,
    SN_sha1, V_OCSP_RESPID_NAME, X509, X509_ADD_FLAG_DEFAULT, X509_NAME, X509_PURPOSE_OCSP_HELPER,
    X509_STORE, X509_TRUST_OCSP_REQUEST, X509_TRUST_TRUSTED, X509_V_FLAG_CRL_CHECK,
    X509_V_FLAG_PARTIAL_CHAIN, XKU_OCSP_SIGN, stack_st_X509,
};
use subtle::ConstantTimeEq;

use super::asn::{
    BasicResp, CertId, OCSP_REQINFO_it, OCSP_RESPDATA_it, Request, RespId, SingleResp, Stack, of,
};
use super::cl::basic;
use super::id::OCSP_id_issuer_cmp;
use crate::asn1::sign::ASN1_item_verify_ex;
use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_get_size};
use crate::evp::legacy_md::EVP_get_digestbyname;
use crate::ffi::ffi_export;
use crate::objects::{OBJ_cmp, OBJ_obj2txt};
use crate::stack::{OPENSSL_sk_dup, OPENSSL_sk_free, OPENSSL_sk_num, OPENSSL_sk_value};
use crate::x509::cert::{
    OSSL_STACK_OF_X509_free, X509_find_by_subject, X509_get_ext_by_NID, X509_get_subject_name,
    X509_get0_pubkey, X509_pubkey_digest, cert_of,
};
use crate::x509::ctx::{
    X509_STORE_CTX_free, X509_STORE_CTX_get_error, X509_STORE_CTX_get0_param,
    X509_STORE_CTX_get1_chain, X509_STORE_CTX_init, X509_STORE_CTX_new, X509_STORE_CTX_set_purpose,
    X509_STORE_CTX_set_trust, X509_verify_cert_error_string,
};
use crate::x509::name::X509_NAME_digest;
use crate::x509::purpose::{X509_add_certs, X509_get_extended_key_usage, X509_get_extension_flags};
use crate::x509::trust::X509_check_trust;
use crate::x509::verify::X509_verify_cert;
use crate::x509::vpm::{X509_VERIFY_PARAM_clear_flags, X509_VERIFY_PARAM_set_flags};

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_OCSP, reason, f);
}

fn has(flags: c_ulong, f: c_int) -> bool {
    flags & c_ulong::from(f.cast_unsigned()) != 0
}

/// `ocsp_verify_signer`: the signer's chain to the store, as an OCSP helper (with no CRL check
/// for a responder with id-pkix-ocsp-nocheck). 1, or <= 0.
///
/// # Safety
/// `signer` is a live certificate; `st` a live store; `untrusted` NULL or a live list; `chain`
/// NULL or room for the chain.
unsafe fn verify_signer(
    signer: *mut X509,
    response: bool,
    st: *mut X509_STORE,
    flags: c_ulong,
    untrusted: *mut stack_st_X509,
    chain: *mut *mut stack_st_X509,
) -> c_int {
    const F: &str = "ocsp_verify_signer";
    // SAFETY: no preconditions.
    let ctx = unsafe { X509_STORE_CTX_new() };
    let ret = 'end: {
        if ctx.is_null() {
            raise(ERR_R_X509_LIB, F);
            break 'end -1;
        }
        // SAFETY: the new context; the caller's store, signer, and certificates.
        if unsafe { X509_STORE_CTX_init(ctx, st, signer, untrusted) } == 0 {
            raise(ERR_R_X509_LIB, F);
            break 'end -1;
        }
        // SAFETY: a live context.
        let vp = unsafe { X509_STORE_CTX_get0_param(ctx) };
        if vp.is_null() {
            break 'end -1;
        }
        if has(flags, OCSP_PARTIAL_CHAIN) {
            // SAFETY: its parameters.
            unsafe {
                X509_VERIFY_PARAM_set_flags(
                    vp,
                    c_ulong::from(X509_V_FLAG_PARTIAL_CHAIN.cast_unsigned()),
                )
            };
        }
        // SAFETY: the caller's signer.
        if response && unsafe { X509_get_ext_by_NID(signer, NID_id_pkix_OCSP_noCheck, -1) } >= 0 {
            // No revocation check for the responder's certificate, here for CRLs.
            // SAFETY: as above.
            unsafe {
                X509_VERIFY_PARAM_clear_flags(
                    vp,
                    c_ulong::from(X509_V_FLAG_CRL_CHECK.cast_unsigned()),
                )
            };
        }
        // SAFETY: a live context.
        unsafe { X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_OCSP_HELPER) };
        // SAFETY: as above.
        unsafe { X509_STORE_CTX_set_trust(ctx, X509_TRUST_OCSP_REQUEST) };
        // SAFETY: as above.
        let ret = unsafe { X509_verify_cert(ctx) };
        if ret <= 0 {
            // SAFETY: as above.
            let e = unsafe { X509_STORE_CTX_get_error(ctx) };
            // SAFETY: any error.
            let text = unsafe { X509_verify_cert_error_string(c_long_of(e)) };
            // SAFETY: a static string.
            let s = unsafe { core::ffi::CStr::from_ptr(text) };
            err::raise_with_text(
                ERR_LIB_OCSP,
                OCSP_R_CERTIFICATE_VERIFY_ERROR,
                F,
                &format!("Verify error: {}", s.to_string_lossy()),
            );
            break 'end ret;
        }
        // SAFETY: the caller's room, or NULL.
        if let Some(c) = unsafe { chain.as_mut() } {
            // SAFETY: as above.
            *c = unsafe { X509_STORE_CTX_get1_chain(ctx) };
        }
        ret
    };
    // SAFETY: the context made here, or NULL.
    unsafe { X509_STORE_CTX_free(ctx) };
    ret
}

fn c_long_of(e: c_int) -> core::ffi::c_long {
    core::ffi::c_long::from(e)
}

/// The signer's library context and properties.
fn signer_ctx(signer: *mut X509) -> (*mut rustyssl_abi::OSSL_LIB_CTX, *const c_char) {
    // SAFETY: a live certificate.
    unsafe { cert_of(signer) }.map_or((ptr::null_mut(), ptr::null()), |c| {
        (c.libctx, c.propq.cast_const())
    })
}

/// `ocsp_verify`: the request's or basic response's signature by the signer's key, unless
/// `OCSP_NOSIGS`.
///
/// # Safety
/// `req` is NULL or a live request, else `bs` a live basic response; `signer` live.
unsafe fn verify_sig(
    req: *mut OCSP_REQUEST,
    bs: *mut OCSP_BASICRESP,
    signer: *mut X509,
    flags: c_ulong,
) -> c_int {
    if has(flags, OCSP_NOSIGS) {
        return 1;
    }
    // SAFETY: the caller's signer.
    let skey = unsafe { X509_get0_pubkey(signer) };
    if skey.is_null() {
        raise(OCSP_R_NO_SIGNER_KEY, "ocsp_verify");
        return -1;
    }
    let (libctx, propq) = signer_ctx(signer);
    // SAFETY: the caller's request, or NULL.
    let ret = if let Some(r) = unsafe { of::<Request, _>(req) } {
        // SAFETY: a signed request's signature.
        let Some(s) = (unsafe { r.optional_signature.as_ref() }) else {
            return -1;
        };
        // SAFETY: no preconditions.
        let it = unsafe { OCSP_REQINFO_it() };
        // SAFETY: the item; the signature's algorithm and value; the request's TBS part; the key.
        unsafe {
            ASN1_item_verify_ex(
                it,
                &s.signature_algorithm,
                s.signature,
                (&raw const r.tbs_request).cast(),
                ptr::null(),
                skey,
                libctx,
                propq,
            )
        }
    } else {
        // SAFETY: the caller's basic response.
        let Some(b) = (unsafe { basic(bs) }) else {
            return -1;
        };
        // SAFETY: no preconditions.
        let it = unsafe { OCSP_RESPDATA_it() };
        // SAFETY: as above, for the response.
        unsafe {
            ASN1_item_verify_ex(
                it,
                &b.signature_algorithm,
                b.signature,
                (&raw const b.tbs_response_data).cast(),
                ptr::null(),
                skey,
                libctx,
                propq,
            )
        }
    };
    if ret <= 0 {
        raise(OCSP_R_SIGNATURE_FAILURE, "ocsp_verify");
    }
    ret
}

/// `ocsp_find_signer_sk`: the certificate the ResponderID names, by name or SHA-1 key hash.
///
/// # Safety
/// `certs` is NULL or a live list.
unsafe fn find_signer_sk(certs: *mut Stack, id: &RespId) -> *mut X509 {
    if id.type_ == V_OCSP_RESPID_NAME {
        // SAFETY: the list, or NULL; the choice's name.
        return unsafe { X509_find_by_subject(certs.cast(), id.value.cast()) };
    }
    // By key hash: forget one that isn't SHA-1's length.
    // SAFETY: the choice's key hash, NULL or live.
    let Some(k) = (unsafe { id.value.cast::<rustyssl_abi::ASN1_OCTET_STRING>().as_ref() }) else {
        return ptr::null_mut();
    };
    // SAFETY: its octets.
    let keyhash = unsafe { crate::asn1::text::octets(k.data, k.length) };
    if keyhash.len() != SHA_DIGEST_LENGTH as usize {
        return ptr::null_mut();
    }
    // SAFETY: the list, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(certs) } {
        // SAFETY: an index within it.
        let x = unsafe { OPENSSL_sk_value(certs, i) }.cast::<X509>();
        if x.is_null() {
            continue;
        }
        let (libctx, propq) = signer_ctx(x);
        // SAFETY: a static name; the certificate's context.
        let md = unsafe { EVP_MD_fetch(libctx, SN_sha1.as_ptr(), propq) };
        if md.is_null() {
            break;
        }
        let mut tmphash = [0u8; SHA_DIGEST_LENGTH as usize];
        // SAFETY: the certificate; the digest; room for it.
        let r = unsafe { X509_pubkey_digest(x, md, tmphash.as_mut_ptr(), ptr::null_mut()) };
        // SAFETY: the digest fetched here.
        unsafe { EVP_MD_free(md) };
        if r == 0 {
            break;
        }
        if bool::from(keyhash.ct_eq(&tmphash)) {
            return x;
        }
    }
    ptr::null_mut()
}

/// `ocsp_find_signer`: the signer among `certs` (2) or, unless `OCSP_NOINTERN`, the
/// response's own (1); 0 if not found.
///
/// # Safety
/// `b` is a live basic response; `certs` NULL or a live list.
unsafe fn find_signer(
    psigner: &mut *mut X509,
    b: &BasicResp,
    certs: *mut stack_st_X509,
    flags: c_ulong,
) -> c_int {
    let rid = &b.tbs_response_data.responder_id;
    // SAFETY: the caller's list, or NULL.
    let s = unsafe { find_signer_sk(certs.cast(), rid) };
    if !s.is_null() {
        *psigner = s;
        return 2;
    }
    if !has(flags, OCSP_NOINTERN) {
        // SAFETY: the response's certificates, or NULL.
        let s = unsafe { find_signer_sk(b.certs, rid) };
        if !s.is_null() {
            *psigner = s;
            return 1;
        }
    }
    *psigner = ptr::null_mut();
    0
}

/// A single response's CertID.
fn cert_id<'a>(sresp: *mut Stack, i: c_int) -> Option<&'a mut CertId> {
    // SAFETY: the responses; an index within them.
    let sp = unsafe { OPENSSL_sk_value(sresp, i) };
    // SAFETY: a single response of the list.
    let s = unsafe { of::<SingleResp, _>(sp) }?;
    // SAFETY: its CertID, made with it.
    unsafe { of::<CertId, _>(s.cert_id) }
}

/// `ocsp_check_ids`: whether all the CertIDs have one issuer (1, with it), differ (0), or
/// differ in hash algorithm (2); -1 for no responses.
///
/// # Safety
/// `sresp` is NULL or a live list of single responses.
unsafe fn check_ids(sresp: *mut Stack, ret: &mut *mut CertId) -> c_int {
    // SAFETY: the list, or NULL.
    let idcount = unsafe { OPENSSL_sk_num(sresp) };
    if idcount <= 0 {
        raise(
            OCSP_R_RESPONSE_CONTAINS_NO_REVOCATION_DATA,
            "ocsp_check_ids",
        );
        return -1;
    }
    let Some(cid) = cert_id(sresp, 0) else {
        return -1;
    };
    *ret = ptr::null_mut();
    let cidp: *mut CertId = cid;
    for i in 1..idcount {
        let Some(tmpid) = cert_id(sresp, i) else {
            return -1;
        };
        // SAFETY: both CertIDs.
        if unsafe { OCSP_id_issuer_cmp(cidp.cast(), ptr::from_mut(tmpid).cast()) } != 0 {
            // A mismatch of algorithms is the caller's to deal with.
            // SAFETY: the first CertID, live with the responses.
            let first = unsafe { (*cidp).hash_algorithm.algorithm };
            // SAFETY: their algorithms.
            if unsafe { OBJ_cmp(tmpid.hash_algorithm.algorithm, first) } != 0 {
                return 2;
            }
            return 0;
        }
    }
    // All the same: one is checked.
    *ret = cidp;
    1
}

/// `ocsp_match_issuerid`: whether the certificate is the issuer the CertID (or, for NULL,
/// each single response's) names: 1, 0, or -1.
///
/// # Safety
/// `cert` is a live certificate; `cid` NULL or live; `sresp` NULL or a live list.
unsafe fn match_issuerid(cert: *mut X509, cid: *mut CertId, sresp: *mut Stack) -> c_int {
    const F: &str = "ocsp_match_issuerid";
    // SAFETY: the caller's CertID, or NULL.
    let Some(c) = (unsafe { cid.as_mut() }) else {
        // All of them must match.
        // SAFETY: the list, or NULL.
        for i in 0..unsafe { OPENSSL_sk_num(sresp) } {
            let Some(tmpid) = cert_id(sresp, i) else {
                return -1;
            };
            // SAFETY: the caller's certificate; a CertID.
            let ret = unsafe { match_issuerid(cert, tmpid, ptr::null_mut()) };
            if ret <= 0 {
                return ret;
            }
        }
        return 1;
    };
    let mut name = [0 as c_char; 50];
    // SAFETY: room for the name; the algorithm's object.
    unsafe { OBJ_obj2txt(name.as_mut_ptr(), 50, c.hash_algorithm.algorithm, 0) };
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: the name.
    let mut dgst = unsafe { EVP_MD_fetch(ptr::null_mut(), name.as_ptr(), ptr::null()) };
    let fetched = !dgst.is_null();
    if dgst.is_null() {
        // SAFETY: as above.
        dgst = unsafe { EVP_get_digestbyname(name.as_ptr()) }.cast_mut();
    }
    if dgst.is_null() {
        // SAFETY: no preconditions.
        unsafe { ERR_clear_last_mark() };
        raise(OCSP_R_UNKNOWN_MESSAGE_DIGEST, F);
        return -1;
    }
    // SAFETY: no preconditions.
    unsafe { ERR_pop_to_mark() };
    let ret = 'end: {
        // SAFETY: a live digest.
        let mdlen = unsafe { EVP_MD_get_size(dgst) };
        let Some(n) = usize::try_from(mdlen).ok().filter(|&n| n > 0) else {
            raise(OCSP_R_DIGEST_SIZE_ERR, F);
            break 'end -1;
        };
        if c.issuer_name_hash.length != mdlen || c.issuer_key_hash.length != mdlen {
            break 'end 0;
        }
        let mut md = [0u8; EVP_MAX_MD_SIZE as usize];
        // SAFETY: the caller's certificate.
        let name = unsafe { X509_get_subject_name(cert) };
        // SAFETY: the certificate's name; the digest; room for it.
        if unsafe { X509_NAME_digest(name, dgst, md.as_mut_ptr(), ptr::null_mut()) } == 0 {
            break 'end -1;
        }
        // SAFETY: the CertID's hash, of `mdlen` octets.
        let want = unsafe { crate::asn1::text::octets(c.issuer_name_hash.data, mdlen) };
        if md.get(..n) != Some(want) {
            break 'end 0;
        }
        // SAFETY: as above.
        if unsafe { X509_pubkey_digest(cert, dgst, md.as_mut_ptr(), ptr::null_mut()) } == 0 {
            raise(OCSP_R_DIGEST_ERR, F);
            break 'end -1;
        }
        // SAFETY: as above.
        let want = unsafe { crate::asn1::text::octets(c.issuer_key_hash.data, mdlen) };
        c_int::from(md.get(..n) == Some(want))
    };
    if fetched {
        // SAFETY: the digest fetched here.
        unsafe { EVP_MD_free(dgst) };
    }
    ret
}

/// `ocsp_check_delegated`: whether the certificate has the OCSPSigning extended key usage.
///
/// # Safety
/// `x` is a live certificate.
unsafe fn check_delegated(x: *mut X509) -> bool {
    // SAFETY: the caller's guarantee.
    let ok = unsafe { X509_get_extension_flags(x) } & EXFLAG_XKUSAGE.cast_unsigned() != 0
        // SAFETY: as above.
        && unsafe { X509_get_extended_key_usage(x) } & XKU_OCSP_SIGN.cast_unsigned() != 0;
    if !ok {
        raise(OCSP_R_MISSING_OCSPSIGNING_USAGE, "ocsp_check_delegated");
    }
    ok
}

/// `ocsp_check_issuer`: whether the chain's signer may speak for the response's
/// certificates: their CA itself, or delegated by it. 1, 0, or -1.
///
/// # Safety
/// `b` is a live basic response; `chain` a live chain.
unsafe fn check_issuer(b: &BasicResp, chain: *mut stack_st_X509) -> c_int {
    let sresp = b.tbs_response_data.responses;
    // SAFETY: the chain.
    let n = unsafe { OPENSSL_sk_num(chain.cast()) };
    if n <= 0 {
        raise(OCSP_R_NO_CERTIFICATES_IN_CHAIN, "ocsp_check_issuer");
        return -1;
    }
    let mut caid = ptr::null_mut();
    // See if the issuers' IDs match.
    // SAFETY: the responses.
    let ret = unsafe { check_ids(sresp, &mut caid) };
    if ret <= 0 {
        return ret;
    }
    // SAFETY: the chain's first certificate.
    let signer = unsafe { OPENSSL_sk_value(chain.cast(), 0) }.cast::<X509>();
    // Is the responder's CA the requests' CA?
    if n > 1 {
        // SAFETY: as above, its second.
        let sca = unsafe { OPENSSL_sk_value(chain.cast(), 1) }.cast::<X509>();
        // SAFETY: the CA; the CertID, or NULL; the responses.
        let ret = unsafe { match_issuerid(sca, caid, sresp) };
        if ret < 0 {
            return ret;
        }
        if ret != 0 {
            // A match: success if delegated.
            // SAFETY: the signer.
            return c_int::from(unsafe { check_delegated(signer) });
        }
    }
    // Else did the requests' CA sign directly?
    // SAFETY: as above.
    unsafe { match_issuerid(signer, caid, sresp) }
}

ffi_export! {
    /// Verifies the basic response: its signer (from `certs` or its own), signature, chain to
    /// the store (with its certificates and `certs`), and authority for the certificates; as
    /// the `OCSP_*` flags allow. 1, or <= 0.
    ///
    /// # Safety
    /// `bs` is a live basic response; `certs` NULL or a live list; `st` a live store (unless
    /// `OCSP_NOVERIFY`).
    pub unsafe extern "C" fn OCSP_basic_verify(bs: *mut OCSP_BASICRESP, certs: *mut stack_st_X509, st: *mut X509_STORE, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { basic(bs) }) else { return 0 };
        let mut flags = flags;
        let mut signer = ptr::null_mut();
        let mut chain: *mut stack_st_X509 = ptr::null_mut();
        let mut untrusted: *mut Stack = ptr::null_mut();
        let ret = 'end: {
            // SAFETY: the response; the caller's certificates.
            let ret = unsafe { find_signer(&mut signer, b, certs, flags) };
            if ret == 0 {
                raise(OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND, "OCSP_basic_verify");
                break 'end 0;
            }
            if ret == 2 && has(flags, OCSP_TRUSTOTHER) {
                flags |= c_ulong::from(OCSP_NOVERIFY.cast_unsigned());
            }
            // SAFETY: the response; the signer.
            let ret = unsafe { verify_sig(ptr::null_mut(), bs, signer, flags) };
            if ret <= 0 {
                break 'end ret;
            }
            if has(flags, OCSP_NOVERIFY) {
                break 'end ret;
            }
            if !has(flags, OCSP_NOCHAIN) {
                // SAFETY: the response's certificates, or NULL.
                untrusted = unsafe { OPENSSL_sk_dup(b.certs) };
                if untrusted.is_null() {
                    break 'end -1;
                }
                // SAFETY: the copy; the caller's certificates.
                if unsafe { X509_add_certs(untrusted.cast(), certs, X509_ADD_FLAG_DEFAULT) } == 0 {
                    break 'end -1;
                }
            }
            // SAFETY: the signer; the store; the untrusted certificates; room for the chain.
            let ret = unsafe { verify_signer(signer, true, st, flags, untrusted.cast(), &mut chain) };
            if ret <= 0 {
                break 'end ret;
            }
            if has(flags, OCSP_NOCHECKS) {
                break 'end 1;
            }
            // A valid chain: now the OCSP issuer criteria.
            // SAFETY: the response; the chain.
            let ret = unsafe { check_issuer(b, chain) };
            // A fatal error or a match finishes it.
            if ret != 0 {
                break 'end ret;
            }
            // Explicit trust of the root.
            if has(flags, OCSP_NOEXPLICIT) {
                break 'end ret;
            }
            // SAFETY: the chain.
            let n = unsafe { OPENSSL_sk_num(chain.cast()) };
            // SAFETY: as above, its last certificate.
            let x = unsafe { OPENSSL_sk_value(chain.cast(), n - 1) }.cast::<X509>();
            // SAFETY: the root.
            if unsafe { X509_check_trust(x, NID_OCSP_sign, 0) } != X509_TRUST_TRUSTED {
                raise(OCSP_R_ROOT_CA_NOT_TRUSTED, "OCSP_basic_verify");
                break 'end 0;
            }
            1
        };
        // SAFETY: the chain, or NULL.
        unsafe { OSSL_STACK_OF_X509_free(chain.cast()) };
        // SAFETY: the copy, or NULL.
        unsafe { OPENSSL_sk_free(untrusted) };
        ret
    }
}

ffi_export! {
    /// The basic response's signer, from `extra_certs` or its own: 1, or 0.
    ///
    /// # Safety
    /// `bs` is a live basic response; `signer` room for a pointer; `extra_certs` NULL or live.
    pub unsafe extern "C" fn OCSP_resp_get0_signer(bs: *mut OCSP_BASICRESP, signer: *mut *mut X509, extra_certs: *mut stack_st_X509) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { basic(bs) }) else { return 0 };
        let mut s = ptr::null_mut();
        // SAFETY: the response; the caller's certificates.
        let r = unsafe { find_signer(&mut s, b, extra_certs, 0) };
        // SAFETY: the caller's room, or NULL.
        if let Some(p) = unsafe { signer.as_mut() } {
            *p = s;
        }
        c_int::from(r > 0)
    }
}

/// `ocsp_req_find_signer`: the request's signer among its own certificates (1, unless
/// `OCSP_NOINTERN`) or `certs` (2); 0 if not found.
///
/// # Safety
/// `r` is a signed request; `nm` a live name; `certs` NULL or a live list.
unsafe fn req_find_signer(
    psigner: &mut *mut X509,
    r: &Request,
    nm: *const X509_NAME,
    certs: *mut stack_st_X509,
    flags: c_ulong,
) -> c_int {
    if !has(flags, OCSP_NOINTERN) {
        // SAFETY: the request's signature, made with it.
        let own = unsafe { r.optional_signature.as_ref() }.map_or(ptr::null_mut(), |s| s.certs);
        // SAFETY: its certificates, or NULL; the name.
        let s = unsafe { X509_find_by_subject(own.cast(), nm) };
        if !s.is_null() {
            *psigner = s;
            return 1;
        }
    }
    // SAFETY: the caller's certificates, or NULL; the name.
    let s = unsafe { X509_find_by_subject(certs, nm) };
    if !s.is_null() {
        *psigner = s;
        return 2;
    }
    0
}

ffi_export! {
    /// Verifies the request's signature by its named signer, and the signer's chain to the
    /// store unless `OCSP_NOVERIFY`: 1, or 0.
    ///
    /// # Safety
    /// `req` is a live request; `certs` NULL or a live list; `store` a live store (unless
    /// `OCSP_NOVERIFY`).
    pub unsafe extern "C" fn OCSP_request_verify(req: *mut OCSP_REQUEST, certs: *mut stack_st_X509, store: *mut X509_STORE, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        const F: &str = "OCSP_request_verify";
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Request, _>(req) }) else { return 0 };
        if r.optional_signature.is_null() {
            raise(OCSP_R_REQUEST_NOT_SIGNED, F);
            return 0;
        }
        // SAFETY: its requestor name, or NULL.
        let Some(gname) = (unsafe { r.tbs_request.requestor_name.as_ref() }).filter(|g| g.type_ == GEN_DIRNAME) else {
            raise(OCSP_R_UNSUPPORTED_REQUESTORNAME_TYPE, F);
            return 0;
        };
        // SAFETY: the name's directory name.
        let nm = unsafe { gname.d.directoryName };
        let mut signer = ptr::null_mut();
        let mut flags = flags;
        // SAFETY: the request; the name; the caller's certificates.
        let ret = unsafe { req_find_signer(&mut signer, r, nm, certs, flags) };
        if ret <= 0 {
            raise(OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND, F);
            return 0;
        }
        if ret == 2 && has(flags, OCSP_TRUSTOTHER) {
            flags |= c_ulong::from(OCSP_NOVERIFY.cast_unsigned());
        }
        // SAFETY: the request; the signer.
        if unsafe { verify_sig(req, ptr::null_mut(), signer, flags) } <= 0 {
            return 0;
        }
        if has(flags, OCSP_NOVERIFY) {
            return 1;
        }
        let untrusted = if has(flags, OCSP_NOCHAIN) {
            ptr::null_mut()
        } else {
            // SAFETY: the request's signature.
            unsafe { (*r.optional_signature).certs }
        };
        // SAFETY: the signer; the store; the certificates.
        c_int::from(unsafe { verify_signer(signer, false, store, flags, untrusted.cast(), ptr::null_mut()) } > 0)
    }
}
