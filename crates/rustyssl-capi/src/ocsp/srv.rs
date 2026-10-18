//! The responder side (`ocsp_srv.c`): reading requests, and building, identifying, and
//! signing responses.
//!
//! Setting a ResponderID frees its old value as what it is: OpenSSL frees a key hash as a
//! name, or leaks it (docs/DEVIATIONS.md).

use core::ffi::{c_char, c_int, c_ulong};
use core::ptr;

use rustyssl_abi::{
    ASN1_INTEGER, ASN1_OBJECT, ASN1_OCTET_STRING, ASN1_TIME, ERR_LIB_OCSP, EVP_MD, EVP_MD_CTX,
    EVP_PKEY, NID_id_pkix_OCSP_basic, OCSP_BASICRESP, OCSP_CERTID, OCSP_NOCERTS, OCSP_NOTIME,
    OCSP_ONEREQ, OCSP_R_NO_REVOKED_TIME, OCSP_R_NO_SIGNER_KEY,
    OCSP_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE, OCSP_REQUEST, OCSP_RESPID, OCSP_RESPID_KEY,
    OCSP_RESPONSE, OCSP_REVOKED_STATUS_NOSTATUS, OCSP_SINGLERESP, OSSL_LIB_CTX, SHA_DIGEST_LENGTH,
    V_OCSP_CERTSTATUS_GOOD, V_OCSP_CERTSTATUS_REVOKED, V_OCSP_CERTSTATUS_UNKNOWN,
    V_OCSP_RESPID_KEY, V_OCSP_RESPID_NAME, X509, X509_ADD_FLAG_UP_REF, stack_st_X509,
};

use super::asn::{
    CertId, CertStatus, OCSP_BASICRESP_it, OCSP_CERTID_dup, OCSP_CERTID_free, OCSP_RESPBYTES_new,
    OCSP_RESPDATA_it, OCSP_RESPONSE_free, OCSP_RESPONSE_new, OCSP_REVOKEDINFO_new,
    OCSP_SINGLERESP_free, OCSP_SINGLERESP_new, OneReq, Request, RespBytes, RespId, Response,
    RevokedInfo, SingleResp, of,
};
use super::cl::{add_cert_new, basic};
use crate::asn1::integer::ASN1_ENUMERATED_set;
use crate::asn1::sign::ASN1_item_sign_ctx;
use crate::asn1::string::{
    ASN1_ENUMERATED_new, ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set,
};
use crate::asn1::time::ASN1_TIME_to_generalizedtime;
use crate::asn1::tpl::items::ASN1_NULL_new;
use crate::asn1::tpl::util::ASN1_item_pack;
use crate::err;
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_get0_name};
use crate::evp::md_ctx::{EVP_MD_CTX_free, EVP_MD_CTX_new};
use crate::evp::pkey_ctx::EVP_PKEY_CTX_get0_pkey;
use crate::evp::sigver::EVP_DigestSignInit_ex;
use crate::evp::sigver::EVP_MD_CTX_get_pkey_ctx;
use crate::ffi::ffi_export;
use crate::objects::OBJ_nid2obj;
use crate::stack::{OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value};
use crate::x509::cert::{
    X509_check_private_key, X509_get_subject_name, X509_gmtime_adj, X509_pubkey_digest, cert_of,
};
use crate::x509::name::{X509_NAME_cmp, X509_NAME_free, X509_NAME_set};
use crate::x509::purpose::X509_add_certs;

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_OCSP, reason, f);
}

ffi_export! {
    /// The number of requests in the OCSP request.
    ///
    /// # Safety
    /// `req` is a live request.
    pub unsafe extern "C" fn OCSP_request_onereq_count(req: *mut OCSP_REQUEST) -> c_int
    where failure = -1, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Request, _>(req) }) else { return -1 };
        // SAFETY: its list.
        unsafe { OPENSSL_sk_num(r.tbs_request.request_list) }
    }
}

ffi_export! {
    /// Request `i` of the OCSP request, or NULL.
    ///
    /// # Safety
    /// `req` is a live request.
    pub unsafe extern "C" fn OCSP_request_onereq_get0(req: *mut OCSP_REQUEST, i: c_int) -> *mut OCSP_ONEREQ
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Request, _>(req) }) else { return ptr::null_mut() };
        // SAFETY: its list.
        unsafe { OPENSSL_sk_value(r.tbs_request.request_list, i) }.cast()
    }
}

ffi_export! {
    /// The request's CertID.
    ///
    /// # Safety
    /// `one` is a live request.
    pub unsafe extern "C" fn OCSP_onereq_get0_id(one: *mut OCSP_ONEREQ) -> *mut OCSP_CERTID
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<OneReq, _>(one) }.map_or(ptr::null_mut(), |o| o.req_cert.cast())
    }
}

ffi_export! {
    /// The CertID's issuer name hash, hash algorithm, issuer key hash, and serial number: 1,
    /// or 0 for NULL.
    ///
    /// # Safety
    /// `cid` is NULL or a live CertID; the others NULL or room for a pointer.
    pub unsafe extern "C" fn OCSP_id_get0_info(pi_name_hash: *mut *mut ASN1_OCTET_STRING, pmd: *mut *mut ASN1_OBJECT, pikey_hash: *mut *mut ASN1_OCTET_STRING, pserial: *mut *mut ASN1_INTEGER, cid: *mut OCSP_CERTID) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { of::<CertId, _>(cid) }) else { return 0 };
        // SAFETY: the caller's room, or NULL.
        if let Some(p) = unsafe { pmd.as_mut() } {
            *p = c.hash_algorithm.algorithm;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { pi_name_hash.as_mut() } {
            *p = &raw mut c.issuer_name_hash;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { pikey_hash.as_mut() } {
            *p = &raw mut c.issuer_key_hash;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { pserial.as_mut() } {
            *p = &raw mut c.serial_number;
        }
        1
    }
}

ffi_export! {
    /// Whether the request is signed.
    ///
    /// # Safety
    /// `req` is a live request.
    pub unsafe extern "C" fn OCSP_request_is_signed(req: *mut OCSP_REQUEST) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { of::<Request, _>(req) }.is_some_and(|r| !r.optional_signature.is_null()))
    }
}

ffi_export! {
    /// A new OCSPResponse of the status, with the basic response (if any) as its bytes. NULL
    /// on failure.
    ///
    /// # Safety
    /// `bs` is NULL or a live basic response.
    pub unsafe extern "C" fn OCSP_response_create(status: c_int, bs: *mut OCSP_BASICRESP) -> *mut OCSP_RESPONSE
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: no preconditions.
        let rsp = unsafe { OCSP_RESPONSE_new() };
        let ok = 'err: {
            // SAFETY: the new response, or NULL.
            let Some(r) = (unsafe { of::<Response, _>(rsp) }) else { break 'err false };
            // SAFETY: its status.
            if unsafe { ASN1_ENUMERATED_set(r.response_status, status.into()) } == 0 {
                break 'err false;
            }
            if bs.is_null() {
                break 'err true;
            }
            // SAFETY: no preconditions.
            r.response_bytes = unsafe { OCSP_RESPBYTES_new() }.cast();
            // SAFETY: the new bytes, or NULL.
            let Some(rb) = (unsafe { of::<RespBytes, _>(r.response_bytes) }) else { break 'err false };
            // SAFETY: a built-in NID.
            rb.response_type = unsafe { OBJ_nid2obj(NID_id_pkix_OCSP_basic) };
            // SAFETY: no preconditions.
            let it = unsafe { OCSP_BASICRESP_it() };
            // SAFETY: the caller's response; the bytes' slot.
            !unsafe { ASN1_item_pack(bs.cast(), it, (&raw mut rb.response).cast()) }.is_null()
        };
        if ok {
            return rsp;
        }
        // SAFETY: the response made here, or NULL.
        unsafe { OCSP_RESPONSE_free(rsp) };
        ptr::null_mut()
    }
}

ffi_export! {
    /// Adds a single response for (a copy of) the CertID with the status (and, if revoked,
    /// the time and reason) and update times. The new single response, or NULL.
    ///
    /// # Safety
    /// `rsp` is a live basic response; `cid` a live CertID; `thisupd` a live time; the others
    /// NULL or live.
    pub unsafe extern "C" fn OCSP_basic_add1_status(rsp: *mut OCSP_BASICRESP, cid: *mut OCSP_CERTID, status: c_int, reason: c_int, revtime: *mut ASN1_TIME, thisupd: *mut ASN1_TIME, nextupd: *mut ASN1_TIME) -> *mut OCSP_SINGLERESP
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { basic(rsp) }) else { return ptr::null_mut() };
        let mut single = ptr::null_mut();
        let ok = 'err: {
            let rd = &mut b.tbs_response_data;
            if rd.responses.is_null() {
                // SAFETY: no preconditions.
                rd.responses = unsafe { OPENSSL_sk_new_null() };
                if rd.responses.is_null() {
                    break 'err false;
                }
            }
            // SAFETY: no preconditions.
            single = unsafe { OCSP_SINGLERESP_new() };
            // SAFETY: the new response, or NULL.
            let Some(s) = (unsafe { of::<SingleResp, _>(single) }) else { break 'err false };
            // SAFETY: the caller's time; the response's slot.
            if unsafe { ASN1_TIME_to_generalizedtime(thisupd, &mut s.this_update) }.is_null() {
                break 'err false;
            }
            // SAFETY: as above.
            if !nextupd.is_null() && unsafe { ASN1_TIME_to_generalizedtime(nextupd, &mut s.next_update) }.is_null() {
                break 'err false;
            }
            // SAFETY: its empty CertID.
            unsafe { OCSP_CERTID_free(s.cert_id.cast()) };
            // SAFETY: the caller's CertID.
            s.cert_id = unsafe { OCSP_CERTID_dup(cid) }.cast();
            if s.cert_id.is_null() {
                break 'err false;
            }
            // SAFETY: its status, made with it.
            let Some(cs) = (unsafe { of::<CertStatus, _>(s.cert_status) }) else { break 'err false };
            cs.type_ = status;
            match status {
                V_OCSP_CERTSTATUS_REVOKED => {
                    if revtime.is_null() {
                        raise(OCSP_R_NO_REVOKED_TIME, "OCSP_basic_add1_status");
                        break 'err false;
                    }
                    // SAFETY: no preconditions.
                    cs.value = unsafe { OCSP_REVOKEDINFO_new() }.cast();
                    // SAFETY: the new info, or NULL.
                    let Some(ri) = (unsafe { of::<RevokedInfo, _>(cs.value) }) else { break 'err false };
                    // SAFETY: the caller's time; the info's slot.
                    if unsafe { ASN1_TIME_to_generalizedtime(revtime, &mut ri.revocation_time) }.is_null() {
                        break 'err false;
                    }
                    if reason != OCSP_REVOKED_STATUS_NOSTATUS {
                        // SAFETY: no preconditions.
                        ri.revocation_reason = unsafe { ASN1_ENUMERATED_new() };
                        // SAFETY: the new ENUMERATED.
                        if ri.revocation_reason.is_null() || unsafe { ASN1_ENUMERATED_set(ri.revocation_reason, reason.into()) } == 0 {
                            break 'err false;
                        }
                    }
                }
                V_OCSP_CERTSTATUS_GOOD | V_OCSP_CERTSTATUS_UNKNOWN => {
                    // SAFETY: no preconditions.
                    cs.value = unsafe { ASN1_NULL_new() }.cast();
                    if cs.value.is_null() {
                        break 'err false;
                    }
                }
                _ => break 'err false,
            }
            // SAFETY: the responses; the new one.
            (unsafe { OPENSSL_sk_push(rd.responses, single.cast()) }) != 0
        };
        if ok {
            return single.cast();
        }
        // SAFETY: the response made here, or NULL.
        unsafe { OCSP_SINGLERESP_free(single.cast()) };
        ptr::null_mut()
    }
}

ffi_export! {
    /// Adds a certificate (with a reference) to the basic response: 1, or 0.
    ///
    /// # Safety
    /// `resp` is a live basic response; `cert` a live certificate.
    pub unsafe extern "C" fn OCSP_basic_add1_cert(resp: *mut OCSP_BASICRESP, cert: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { basic(resp) }) else { return 0 };
        // SAFETY: its certificates' slot; the caller's certificate.
        c_int::from(unsafe { add_cert_new(&mut b.certs, cert, X509_ADD_FLAG_UP_REF) })
    }
}

/// The ResponderID behind a pointer.
///
/// # Safety
/// `respid` is NULL or a live ResponderID.
unsafe fn rid_of<'a>(r: *mut OCSP_RESPID) -> Option<&'a mut RespId> {
    // SAFETY: the caller's guarantee.
    unsafe { of(r) }
}

/// Frees the ResponderID's value, as what it is.
fn clear(r: &mut RespId) {
    match r.type_ {
        // SAFETY: the choice's name.
        V_OCSP_RESPID_NAME => unsafe { X509_NAME_free(r.value.cast()) },
        // SAFETY: the choice's key hash.
        V_OCSP_RESPID_KEY => unsafe { ASN1_OCTET_STRING_free(r.value.cast()) },
        _ => {}
    }
    r.value = ptr::null_mut();
}

ffi_export! {
    /// Sets the basic response's signature by `ctx` (whose key must be `signer`'s), its
    /// responder (by key hash with `OCSP_RESPID_KEY`, else by name), the signer and `certs`
    /// unless `OCSP_NOCERTS`, and the time produced unless `OCSP_NOTIME`: 1, or 0.
    ///
    /// # Safety
    /// `brsp` is a live basic response; `signer` a live certificate; `ctx` NULL or a context
    /// set up to sign; `certs` NULL or live.
    pub unsafe extern "C" fn OCSP_basic_sign_ctx(brsp: *mut OCSP_BASICRESP, signer: *mut X509, ctx: *mut EVP_MD_CTX, certs: *mut stack_st_X509, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        const F: &str = "OCSP_basic_sign_ctx";
        // SAFETY: the caller's context, or NULL.
        let pctx = if ctx.is_null() { ptr::null_mut() } else { unsafe { EVP_MD_CTX_get_pkey_ctx(ctx) } };
        if pctx.is_null() {
            raise(OCSP_R_NO_SIGNER_KEY, F);
            return 0;
        }
        // SAFETY: its key context.
        let pkey: *mut EVP_PKEY = unsafe { EVP_PKEY_CTX_get0_pkey(pctx) };
        // SAFETY: the caller's signer; the key.
        if pkey.is_null() || unsafe { X509_check_private_key(signer, pkey) } == 0 {
            raise(OCSP_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE, F);
            return 0;
        }
        let has = |f: c_int| flags & c_ulong::from(f.cast_unsigned()) != 0;
        if !has(OCSP_NOCERTS) {
            // SAFETY: the caller's response and signer.
            if unsafe { OCSP_basic_add1_cert(brsp, signer) } == 0 {
                return 0;
            }
            // SAFETY: as above; its certificates; the caller's.
            let Some(b) = (unsafe { basic(brsp) }) else { return 0 };
            // SAFETY: the response's list; the caller's certificates.
            if unsafe { X509_add_certs(b.certs.cast(), certs, X509_ADD_FLAG_UP_REF) } == 0 {
                return 0;
            }
        }
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { basic(brsp) }) else { return 0 };
        let rid: *mut OCSP_RESPID = (&raw mut b.tbs_response_data.responder_id).cast();
        let set = if has(OCSP_RESPID_KEY) {
            // SAFETY: the response's ResponderID; the signer.
            unsafe { OCSP_RESPID_set_by_key(rid, signer) }
        } else {
            // SAFETY: as above.
            unsafe { OCSP_RESPID_set_by_name(rid, signer) }
        };
        if set == 0 {
            return 0;
        }
        // SAFETY: the response's time.
        if !has(OCSP_NOTIME) && unsafe { X509_gmtime_adj(b.tbs_response_data.produced_at, 0) }.is_null() {
            return 0;
        }
        // SAFETY: no preconditions.
        let it = unsafe { OCSP_RESPDATA_it() };
        // SAFETY: the item; the response's algorithm, signature, and data; the context.
        c_int::from(unsafe { ASN1_item_sign_ctx(it, &mut b.signature_algorithm, ptr::null_mut(), b.signature, (&raw const b.tbs_response_data).cast(), ctx) } != 0)
    }
}

ffi_export! {
    /// Signs the basic response as `signer` with the key and digest (see
    /// `OCSP_basic_sign_ctx`): 1, or 0.
    ///
    /// # Safety
    /// `brsp` is a live basic response; `signer` and `key` live; `dgst` and `certs` NULL or
    /// live.
    pub unsafe extern "C" fn OCSP_basic_sign(brsp: *mut OCSP_BASICRESP, signer: *mut X509, key: *mut EVP_PKEY, dgst: *const EVP_MD, certs: *mut stack_st_X509, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: no preconditions.
        let ctx = unsafe { EVP_MD_CTX_new() };
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: the signer, NULL or live.
        let (libctx, propq) = unsafe { cert_of(signer) }.map_or((ptr::null_mut(), ptr::null()), |c| (c.libctx, c.propq.cast_const()));
        // SAFETY: the caller's digest, or NULL.
        let mdname = if dgst.is_null() { ptr::null() } else { unsafe { EVP_MD_get0_name(dgst) } };
        let mut pkctx = ptr::null_mut();
        // SAFETY: the new context; room for its key context; the digest's name; the key.
        if unsafe { EVP_DigestSignInit_ex(ctx, &mut pkctx, mdname, libctx, propq, key, ptr::null()) } == 0 {
            // SAFETY: the context made here.
            unsafe { EVP_MD_CTX_free(ctx) };
            return 0;
        }
        // SAFETY: the caller's guarantee; the context.
        let i = unsafe { OCSP_basic_sign_ctx(brsp, signer, ctx, certs, flags) };
        // SAFETY: as above.
        unsafe { EVP_MD_CTX_free(ctx) };
        i
    }
}

ffi_export! {
    /// Sets the ResponderID to the certificate's subject name: 1, or 0.
    ///
    /// # Safety
    /// `respid` is a live ResponderID; `cert` a live certificate.
    pub unsafe extern "C" fn OCSP_RESPID_set_by_name(respid: *mut OCSP_RESPID, cert: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { rid_of(respid) }) else { return 0 };
        if r.type_ != V_OCSP_RESPID_NAME {
            clear(r);
        }
        // SAFETY: the caller's certificate.
        let name = unsafe { X509_get_subject_name(cert) };
        // SAFETY: the name's slot; the certificate's name.
        if unsafe { X509_NAME_set((&raw mut r.value).cast(), name) } == 0 {
            return 0;
        }
        r.type_ = V_OCSP_RESPID_NAME;
        1
    }
}

/// The SHA-1 hash of the certificate's key, or `None`.
///
/// # Safety
/// `cert` is a live certificate; `libctx` NULL or live; `propq` NULL or a C string.
unsafe fn key_hash(
    cert: *mut X509,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> Option<[u8; SHA_DIGEST_LENGTH as usize]> {
    // SAFETY: a static name; the caller's context and properties.
    let sha1 = unsafe { EVP_MD_fetch(libctx, c"SHA1".as_ptr(), propq) };
    if sha1.is_null() {
        return None;
    }
    let mut md = [0u8; SHA_DIGEST_LENGTH as usize];
    // RFC 2560 requires SHA-1.
    // SAFETY: the certificate; the digest; room for it.
    let ok = unsafe { X509_pubkey_digest(cert, sha1, md.as_mut_ptr(), ptr::null_mut()) } != 0;
    // SAFETY: the digest fetched here.
    unsafe { EVP_MD_free(sha1) };
    ok.then_some(md)
}

ffi_export! {
    /// Sets the ResponderID to the SHA-1 hash of the certificate's key, in a library
    /// context: 1, or 0.
    ///
    /// # Safety
    /// `respid` is a live ResponderID; `cert` a live certificate; `libctx` NULL or live;
    /// `propq` NULL or a C string.
    pub unsafe extern "C" fn OCSP_RESPID_set_by_key_ex(respid: *mut OCSP_RESPID, cert: *mut X509, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { rid_of(respid) }) else { return 0 };
        // SAFETY: as above.
        let Some(md) = (unsafe { key_hash(cert, libctx, propq) }) else { return 0 };
        // SAFETY: no preconditions.
        let by_key = unsafe { ASN1_OCTET_STRING_new() };
        if by_key.is_null() {
            return 0;
        }
        let Ok(n) = c_int::try_from(md.len()) else { return 0 };
        // SAFETY: the new string; the hash.
        if unsafe { ASN1_OCTET_STRING_set(by_key, md.as_ptr(), n) } == 0 {
            // SAFETY: the string made here.
            unsafe { ASN1_OCTET_STRING_free(by_key) };
            return 0;
        }
        clear(r);
        r.type_ = V_OCSP_RESPID_KEY;
        r.value = by_key.cast();
        1
    }
}

ffi_export! {
    /// Sets the ResponderID to the SHA-1 hash of the certificate's key: 1, or 0.
    ///
    /// # Safety
    /// `respid` is a live ResponderID; `cert` NULL or a live certificate.
    pub unsafe extern "C" fn OCSP_RESPID_set_by_key(respid: *mut OCSP_RESPID, cert: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(cert) }) else { return 0 };
        // SAFETY: as above; the certificate's context.
        unsafe { OCSP_RESPID_set_by_key_ex(respid, cert, c.libctx, c.propq) }
    }
}

ffi_export! {
    /// Whether the ResponderID names the certificate (by its key's hash or its subject), in a
    /// library context.
    ///
    /// # Safety
    /// `respid` is a live ResponderID; `cert` a live certificate; `libctx` NULL or live;
    /// `propq` NULL or a C string.
    pub unsafe extern "C" fn OCSP_RESPID_match_ex(respid: *mut OCSP_RESPID, cert: *mut X509, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { rid_of(respid) }) else { return 0 };
        match r.type_ {
            V_OCSP_RESPID_KEY => {
                // SAFETY: the choice's key hash, NULL or live.
                let Some(k) = (unsafe { r.value.cast::<ASN1_OCTET_STRING>().as_ref() }) else { return 0 };
                // SAFETY: the caller's certificate and context.
                let Some(md) = (unsafe { key_hash(cert, libctx, propq) }) else { return 0 };
                // SAFETY: the key hash's octets.
                let have = unsafe { crate::asn1::text::octets(k.data, k.length) };
                c_int::from(have == md)
            }
            V_OCSP_RESPID_NAME => {
                if r.value.is_null() {
                    return 0;
                }
                // SAFETY: the caller's certificate.
                let name = unsafe { X509_get_subject_name(cert) };
                // SAFETY: the choice's name; the certificate's.
                c_int::from(unsafe { X509_NAME_cmp(r.value.cast(), name) } == 0)
            }
            _ => 0,
        }
    }
}

ffi_export! {
    /// Whether the ResponderID names the certificate.
    ///
    /// # Safety
    /// `respid` is a live ResponderID; `cert` NULL or a live certificate.
    pub unsafe extern "C" fn OCSP_RESPID_match(respid: *mut OCSP_RESPID, cert: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { cert_of(cert) }) else { return 0 };
        // SAFETY: as above; the certificate's context.
        unsafe { OCSP_RESPID_match_ex(respid, cert, c.libctx, c.propq) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::name::X509_NAME_new;

    #[test]
    fn a_responder_id_frees_its_value_as_what_it_is() {
        // SAFETY: no preconditions.
        let by_key = unsafe { ASN1_OCTET_STRING_new() };
        let mut r = RespId {
            type_: V_OCSP_RESPID_KEY,
            value: by_key.cast(),
        };
        // The reference frees the key hash as a name to set a name.
        clear(&mut r);
        assert!(r.value.is_null());
        // SAFETY: no preconditions.
        let name = unsafe { X509_NAME_new() };
        let mut r = RespId {
            type_: V_OCSP_RESPID_NAME,
            value: name.cast(),
        };
        clear(&mut r);
        assert!(r.value.is_null());
    }
}
