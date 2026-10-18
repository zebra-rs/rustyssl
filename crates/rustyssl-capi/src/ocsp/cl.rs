//! The client side (`ocsp_cl.c`): building and signing requests, and reading responses (the
//! basic response, its single responses, their status and validity).

use core::ffi::{c_int, c_long, c_ulong};
use core::ptr;

use rustyssl_abi::{
    ASN1_GENERALIZEDTIME, ASN1_OCTET_STRING, ERR_LIB_OCSP, EVP_MD, EVP_PKEY, GEN_DIRNAME,
    NID_id_pkix_OCSP_basic, OCSP_BASICRESP, OCSP_CERTID, OCSP_NOCERTS, OCSP_ONEREQ,
    OCSP_R_ERROR_IN_NEXTUPDATE_FIELD, OCSP_R_ERROR_IN_THISUPDATE_FIELD,
    OCSP_R_NEXTUPDATE_BEFORE_THISUPDATE, OCSP_R_NO_RESPONSE_DATA, OCSP_R_NOT_BASIC_RESPONSE,
    OCSP_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE, OCSP_R_STATUS_EXPIRED,
    OCSP_R_STATUS_NOT_YET_VALID, OCSP_R_STATUS_TOO_OLD, OCSP_REQUEST, OCSP_RESPDATA, OCSP_RESPONSE,
    OCSP_SINGLERESP, V_OCSP_CERTSTATUS_REVOKED, V_OCSP_RESPID_KEY, V_OCSP_RESPID_NAME, X509,
    X509_ADD_FLAG_UP_REF, X509_ALGOR, X509_NAME, stack_st_X509,
};

use super::asn::{
    BasicResp, CertStatus, OCSP_BASICRESP_it, OCSP_CERTID_free, OCSP_ONEREQ_free, OCSP_ONEREQ_new,
    OCSP_REQINFO_it, OCSP_SIGNATURE_free, OCSP_SIGNATURE_new, OneReq, Request, Response,
    RevokedInfo, SingleResp, Stack, of,
};
use super::id::OCSP_id_cmp;
use crate::asn1::integer::ASN1_ENUMERATED_get;
use crate::asn1::sign::ASN1_item_sign_ex;
use crate::asn1::string::{ASN1_OCTET_STRING_dup, ASN1_STRING_cmp};
use crate::asn1::time::ASN1_GENERALIZEDTIME_check;
use crate::asn1::tpl::util::ASN1_item_unpack;
use crate::err;
use crate::ffi::ffi_export;
use crate::objects::OBJ_obj2nid;
use crate::stack::{OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value};
use crate::x509::cert::{X509_check_private_key, X509_cmp_time, X509_get_subject_name, cert_of};
use crate::x509::name::{X509_NAME_dup, X509_NAME_set};
use crate::x509::purpose::{X509_add_cert, X509_add_certs};
use crate::x509v3::genn::{GENERAL_NAME_free, GENERAL_NAME_new};

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_OCSP, reason, f);
}

ffi_export! {
    /// Adds a request for the CertID (taken) to the request (if any): the new request, or NULL.
    ///
    /// # Safety
    /// `req` is NULL or a live request; `cid` a live CertID, taken on success.
    pub unsafe extern "C" fn OCSP_request_add0_id(req: *mut OCSP_REQUEST, cid: *mut OCSP_CERTID) -> *mut OCSP_ONEREQ
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: no preconditions.
        let one = unsafe { OCSP_ONEREQ_new() };
        // SAFETY: the new request, or NULL.
        let Some(o) = (unsafe { of::<OneReq, _>(one) }) else { return ptr::null_mut() };
        // SAFETY: its empty CertID.
        unsafe { OCSP_CERTID_free(o.req_cert.cast()) };
        o.req_cert = cid.cast();
        // SAFETY: the caller's request, or NULL.
        if let Some(r) = unsafe { of::<Request, _>(req) }
            // SAFETY: its list; the new request.
            && unsafe { OPENSSL_sk_push(r.tbs_request.request_list, one.cast()) } == 0
        {
            // Not freed on failure.
            o.req_cert = ptr::null_mut();
            // SAFETY: the request made here.
            unsafe { OCSP_ONEREQ_free(one) };
            return ptr::null_mut();
        }
        one
    }
}

ffi_export! {
    /// Sets the requestor name to a copy of the directory name: 1, or 0.
    ///
    /// # Safety
    /// `req` is a live request; `nm` a live name.
    pub unsafe extern "C" fn OCSP_request_set1_name(req: *mut OCSP_REQUEST, nm: *const X509_NAME) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Request, _>(req) }) else { return 0 };
        // SAFETY: no preconditions.
        let gname = unsafe { GENERAL_NAME_new() };
        // SAFETY: the new name, or NULL.
        let Some(g) = (unsafe { gname.as_mut() }) else { return 0 };
        // SAFETY: the name's slot; the caller's name.
        if unsafe { X509_NAME_set((&raw mut g.d).cast(), nm) } == 0 {
            // SAFETY: the name made here.
            unsafe { GENERAL_NAME_free(gname) };
            return 0;
        }
        g.type_ = GEN_DIRNAME;
        // SAFETY: the request's own name, or NULL.
        unsafe { GENERAL_NAME_free(r.tbs_request.requestor_name) };
        r.tbs_request.requestor_name = gname;
        1
    }
}

/// `ossl_x509_add_cert_new`: the certificate onto `*slot`, made if NULL.
///
/// # Safety
/// `slot` holds NULL or a live list; `cert` is live.
pub(crate) unsafe fn add_cert_new(slot: &mut *mut Stack, cert: *mut X509, flags: c_int) -> bool {
    if slot.is_null() {
        // SAFETY: no preconditions.
        *slot = unsafe { OPENSSL_sk_new_null() };
        if slot.is_null() {
            err::raise(
                rustyssl_abi::ERR_LIB_X509,
                rustyssl_abi::ERR_R_CRYPTO_LIB,
                "ossl_x509_add_cert_new",
            );
            return false;
        }
    }
    // SAFETY: the list; the caller's certificate.
    unsafe { X509_add_cert((*slot).cast(), cert, flags) != 0 }
}

ffi_export! {
    /// Adds a certificate (with a reference) to the request's signature (made if absent): 1,
    /// or 0.
    ///
    /// # Safety
    /// `req` is a live request; `cert` NULL or live.
    pub unsafe extern "C" fn OCSP_request_add1_cert(req: *mut OCSP_REQUEST, cert: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Request, _>(req) }) else { return 0 };
        if r.optional_signature.is_null() {
            // SAFETY: no preconditions.
            r.optional_signature = unsafe { OCSP_SIGNATURE_new() }.cast();
            if r.optional_signature.is_null() {
                return 0;
            }
        }
        if cert.is_null() {
            return 1;
        }
        // SAFETY: the signature, made with it or above.
        let s = unsafe { &mut *r.optional_signature };
        // SAFETY: its certificates' slot; the caller's certificate.
        c_int::from(unsafe { add_cert_new(&mut s.certs, cert, X509_ADD_FLAG_UP_REF) })
    }
}

ffi_export! {
    /// Signs the request as `signer` with the key (if any) and digest, naming the signer and
    /// adding it and `certs` unless `OCSP_NOCERTS`: 1, or 0.
    ///
    /// # Safety
    /// `req` is a live request; `signer` a live certificate; `key`, `dgst`, and `certs` NULL or
    /// live.
    pub unsafe extern "C" fn OCSP_request_sign(req: *mut OCSP_REQUEST, signer: *mut X509, key: *mut EVP_PKEY, dgst: *const EVP_MD, certs: *mut stack_st_X509, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Request, _>(req) }) else { return 0 };
        let ok = 'err: {
            // SAFETY: the caller's signer.
            let name = unsafe { X509_get_subject_name(signer) };
            // SAFETY: the caller's request; the signer's name.
            if unsafe { OCSP_request_set1_name(req, name) } == 0 {
                break 'err false;
            }
            // SAFETY: no preconditions.
            r.optional_signature = unsafe { OCSP_SIGNATURE_new() }.cast();
            // SAFETY: the new signature, or NULL.
            let Some(s) = (unsafe { r.optional_signature.as_mut() }) else { break 'err false };
            if !key.is_null() {
                // SAFETY: the caller's signer and key.
                if unsafe { X509_check_private_key(signer, key) } == 0 {
                    raise(OCSP_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE, "OCSP_request_sign");
                    break 'err false;
                }
                // SAFETY: the signer, NULL or live.
                let (libctx, propq) = unsafe { cert_of(signer) }.map_or((ptr::null_mut(), ptr::null()), |c| (c.libctx, c.propq.cast_const()));
                // SAFETY: no preconditions.
                let it = unsafe { OCSP_REQINFO_it() };
                // SAFETY: the item; the signature's algorithm and string; the request's TBS part;
                // the caller's key and digest.
                if unsafe { ASN1_item_sign_ex(it, &mut s.signature_algorithm, ptr::null_mut(), s.signature, (&raw const r.tbs_request).cast(), ptr::null(), key, dgst, libctx, propq) } == 0 {
                    break 'err false;
                }
            }
            if flags & c_ulong::from(OCSP_NOCERTS.cast_unsigned()) == 0 {
                // SAFETY: the request; the signer.
                if unsafe { OCSP_request_add1_cert(req, signer) } == 0 {
                    break 'err false;
                }
                // SAFETY: the signature's certificates; the caller's.
                if unsafe { X509_add_certs(s.certs.cast(), certs, X509_ADD_FLAG_UP_REF) } == 0 {
                    break 'err false;
                }
            }
            true
        };
        if !ok {
            // SAFETY: the request's signature, or NULL.
            unsafe { OCSP_SIGNATURE_free(r.optional_signature.cast()) };
            r.optional_signature = ptr::null_mut();
        }
        c_int::from(ok)
    }
}

ffi_export! {
    /// The response's status (`OCSP_RESPONSE_STATUS_*`).
    ///
    /// # Safety
    /// `resp` is a live response.
    pub unsafe extern "C" fn OCSP_response_status(resp: *mut OCSP_RESPONSE) -> c_int
    where failure = -1, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Response, _>(resp) }) else { return -1 };
        // SAFETY: its status.
        c_int::try_from(unsafe { ASN1_ENUMERATED_get(r.response_status) }).unwrap_or(-1)
    }
}

ffi_export! {
    /// The response's basic response, decoded anew, or NULL.
    ///
    /// # Safety
    /// `resp` is a live response.
    pub unsafe extern "C" fn OCSP_response_get1_basic(resp: *mut OCSP_RESPONSE) -> *mut OCSP_BASICRESP
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        const F: &str = "OCSP_response_get1_basic";
        // SAFETY: the caller's guarantee; its bytes.
        let Some(rb) = (unsafe { of::<Response, _>(resp) }).and_then(|r| unsafe { r.response_bytes.as_ref() }) else {
            raise(OCSP_R_NO_RESPONSE_DATA, F);
            return ptr::null_mut();
        };
        // SAFETY: its type.
        if unsafe { OBJ_obj2nid(rb.response_type) } != NID_id_pkix_OCSP_basic {
            raise(OCSP_R_NOT_BASIC_RESPONSE, F);
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let it = unsafe { OCSP_BASICRESP_it() };
        // SAFETY: its OCTET STRING.
        unsafe { ASN1_item_unpack(rb.response, it) }.cast()
    }
}

/// The basic response behind a pointer.
///
/// # Safety
/// `bs` is NULL or a live basic response.
pub(crate) unsafe fn basic<'a>(bs: *const OCSP_BASICRESP) -> Option<&'a mut BasicResp> {
    // SAFETY: the caller's guarantee.
    unsafe { of(bs) }
}

ffi_export! {
    /// The basic response's signature.
    ///
    /// # Safety
    /// `bs` is a live basic response.
    pub unsafe extern "C" fn OCSP_resp_get0_signature(bs: *const OCSP_BASICRESP) -> *const ASN1_OCTET_STRING
    where failure = ptr::null(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        unsafe { basic(bs) }.map_or(ptr::null(), |b| b.signature.cast_const())
    }
}

ffi_export! {
    /// The basic response's signature algorithm.
    ///
    /// # Safety
    /// `bs` is a live basic response.
    pub unsafe extern "C" fn OCSP_resp_get0_tbs_sigalg(bs: *const OCSP_BASICRESP) -> *const X509_ALGOR
    where failure = ptr::null(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        unsafe { basic(bs) }.map_or(ptr::null(), |b| &raw const b.signature_algorithm)
    }
}

ffi_export! {
    /// The basic response's ResponseData.
    ///
    /// # Safety
    /// `bs` is a live basic response.
    pub unsafe extern "C" fn OCSP_resp_get0_respdata(bs: *const OCSP_BASICRESP) -> *const OCSP_RESPDATA
    where failure = ptr::null(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        unsafe { basic(bs) }.map_or(ptr::null(), |b| (&raw const b.tbs_response_data).cast())
    }
}

ffi_export! {
    /// The number of single responses; -1 for NULL.
    ///
    /// # Safety
    /// `bs` is NULL or a live basic response.
    pub unsafe extern "C" fn OCSP_resp_count(bs: *mut OCSP_BASICRESP) -> c_int
    where failure = -1, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { basic(bs) }) else { return -1 };
        // SAFETY: its responses.
        unsafe { OPENSSL_sk_num(b.tbs_response_data.responses) }
    }
}

ffi_export! {
    /// Single response `idx`, or NULL.
    ///
    /// # Safety
    /// `bs` is NULL or a live basic response.
    pub unsafe extern "C" fn OCSP_resp_get0(bs: *mut OCSP_BASICRESP, idx: c_int) -> *mut OCSP_SINGLERESP
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { basic(bs) }) else { return ptr::null_mut() };
        // SAFETY: its responses.
        unsafe { OPENSSL_sk_value(b.tbs_response_data.responses, idx) }.cast()
    }
}

ffi_export! {
    /// When the basic response was produced.
    ///
    /// # Safety
    /// `bs` is a live basic response.
    pub unsafe extern "C" fn OCSP_resp_get0_produced_at(bs: *const OCSP_BASICRESP) -> *const ASN1_GENERALIZEDTIME
    where failure = ptr::null(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        unsafe { basic(bs) }.map_or(ptr::null(), |b| b.tbs_response_data.produced_at.cast_const())
    }
}

ffi_export! {
    /// The basic response's certificates, or NULL.
    ///
    /// # Safety
    /// `bs` is a live basic response.
    pub unsafe extern "C" fn OCSP_resp_get0_certs(bs: *const OCSP_BASICRESP) -> *const stack_st_X509
    where failure = ptr::null(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        unsafe { basic(bs) }.map_or(ptr::null(), |b| b.certs.cast_const().cast())
    }
}

ffi_export! {
    /// The responder's key hash or name (the other NULL): 1, or 0.
    ///
    /// # Safety
    /// `bs` is a live basic response; `pid` and `pname` room for a pointer.
    pub unsafe extern "C" fn OCSP_resp_get0_id(bs: *const OCSP_BASICRESP, pid: *mut *const ASN1_OCTET_STRING, pname: *mut *const X509_NAME) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { basic(bs) }) else { return 0 };
        let rid = &b.tbs_response_data.responder_id;
        let (id, name) = match rid.type_ {
            V_OCSP_RESPID_NAME => (ptr::null(), rid.value.cast_const().cast()),
            V_OCSP_RESPID_KEY => (rid.value.cast_const().cast(), ptr::null()),
            _ => return 0,
        };
        // SAFETY: the caller's room, or NULL.
        if let Some(p) = unsafe { pid.as_mut() } {
            *p = id;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { pname.as_mut() } {
            *p = name;
        }
        1
    }
}

ffi_export! {
    /// Copies of the responder's key hash or name (the other NULL): 1, or 0.
    ///
    /// # Safety
    /// `bs` is a live basic response; `pid` and `pname` room for a pointer.
    pub unsafe extern "C" fn OCSP_resp_get1_id(bs: *const OCSP_BASICRESP, pid: *mut *mut ASN1_OCTET_STRING, pname: *mut *mut X509_NAME) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { basic(bs) }) else { return 0 };
        let rid = &b.tbs_response_data.responder_id;
        let (id, name) = match rid.type_ {
            // SAFETY: the choice's name.
            V_OCSP_RESPID_NAME => (ptr::null_mut(), unsafe { X509_NAME_dup(rid.value.cast()) }),
            // SAFETY: the choice's key hash.
            V_OCSP_RESPID_KEY => (unsafe { ASN1_OCTET_STRING_dup(rid.value.cast()) }, ptr::null_mut()),
            _ => return 0,
        };
        // SAFETY: the caller's room, or NULL.
        if let Some(p) = unsafe { pid.as_mut() } {
            *p = id;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { pname.as_mut() } {
            *p = name;
        }
        c_int::from(!(id.is_null() && name.is_null()))
    }
}

/// The single response behind a pointer.
///
/// # Safety
/// `s` is NULL or a live single response.
pub(crate) unsafe fn single<'a>(s: *const OCSP_SINGLERESP) -> Option<&'a mut SingleResp> {
    // SAFETY: the caller's guarantee.
    unsafe { of(s) }
}

ffi_export! {
    /// The index of the next single response for the CertID after `last` (from the start for
    /// a negative one), or -1.
    ///
    /// # Safety
    /// `bs` is NULL or a live basic response; `id` a live CertID.
    pub unsafe extern "C" fn OCSP_resp_find(bs: *mut OCSP_BASICRESP, id: *mut OCSP_CERTID, last: c_int) -> c_int
    where failure = -1, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { basic(bs) }) else { return -1 };
        let start = if last < 0 { 0 } else { last.saturating_add(1) };
        let sresp = b.tbs_response_data.responses;
        // SAFETY: its responses.
        for i in start..unsafe { OPENSSL_sk_num(sresp) } {
            // SAFETY: an index within them.
            let sp = unsafe { OPENSSL_sk_value(sresp, i) };
            // SAFETY: a single response of the list.
            let Some(s) = (unsafe { single(sp.cast()) }) else { continue };
            // SAFETY: the caller's CertID; the response's.
            if unsafe { OCSP_id_cmp(id, s.cert_id.cast()) } == 0 {
                return i;
            }
        }
        -1
    }
}

ffi_export! {
    /// The single response's status (`V_OCSP_CERTSTATUS_*`), with the revocation's reason (-1
    /// for none) and time, and the update times; -1 for NULL.
    ///
    /// # Safety
    /// `single_` is NULL or a live single response; the others NULL or room for their value.
    pub unsafe extern "C" fn OCSP_single_get0_status(single_: *mut OCSP_SINGLERESP, reason: *mut c_int, revtime: *mut *mut ASN1_GENERALIZEDTIME, thisupd: *mut *mut ASN1_GENERALIZEDTIME, nextupd: *mut *mut ASN1_GENERALIZEDTIME) -> c_int
    where failure = -1, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { single(single_) }) else { return -1 };
        // SAFETY: its status, made with it.
        let Some(cst) = (unsafe { of::<CertStatus, _>(s.cert_status) }) else { return -1 };
        let ret = cst.type_;
        if ret == V_OCSP_CERTSTATUS_REVOKED {
            // SAFETY: the choice's value.
            if let Some(rev) = unsafe { of::<RevokedInfo, _>(cst.value) } {
                // SAFETY: the caller's room, or NULL.
                if let Some(p) = unsafe { revtime.as_mut() } {
                    *p = rev.revocation_time;
                }
                // SAFETY: as above.
                if let Some(p) = unsafe { reason.as_mut() } {
                    *p = if rev.revocation_reason.is_null() {
                        -1
                    } else {
                        // SAFETY: its reason.
                        c_int::try_from(unsafe { ASN1_ENUMERATED_get(rev.revocation_reason) }).unwrap_or(-1)
                    };
                }
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { thisupd.as_mut() } {
            *p = s.this_update;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { nextupd.as_mut() } {
            *p = s.next_update;
        }
        ret
    }
}

ffi_export! {
    /// The status of the CertID's first single response, as `OCSP_single_get0_status` gives
    /// it: 1, or 0 if there is none.
    ///
    /// # Safety
    /// `bs` is NULL or a live basic response; `id` a live CertID; the others NULL or room.
    pub unsafe extern "C" fn OCSP_resp_find_status(bs: *mut OCSP_BASICRESP, id: *mut OCSP_CERTID, status: *mut c_int, reason: *mut c_int, revtime: *mut *mut ASN1_GENERALIZEDTIME, thisupd: *mut *mut ASN1_GENERALIZEDTIME, nextupd: *mut *mut ASN1_GENERALIZEDTIME) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let i = unsafe { OCSP_resp_find(bs, id, -1) };
        if i < 0 {
            return 0;
        }
        // SAFETY: as above.
        let s = unsafe { OCSP_resp_get0(bs, i) };
        // SAFETY: the response's; the caller's room.
        let st = unsafe { OCSP_single_get0_status(s, reason, revtime, thisupd, nextupd) };
        // SAFETY: as above.
        if let Some(p) = unsafe { status.as_mut() } {
            *p = st;
        }
        1
    }
}

/// `X509_cmp_time` against now plus `delta` seconds.
fn cmp_now(t: *const ASN1_GENERALIZEDTIME, delta: c_long) -> c_int {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let mut at: libc::time_t = now.saturating_add(delta);
    // SAFETY: the caller's time; the moment.
    unsafe { X509_cmp_time(t, &mut at) }
}

ffi_export! {
    /// Whether the update times are valid now, within `nsec` seconds of slack, with thisUpdate
    /// at most `maxsec` seconds old (unless negative): 1, or 0 with errors.
    ///
    /// # Safety
    /// `thisupd` is a live time; `nextupd` NULL or live.
    pub unsafe extern "C" fn OCSP_check_validity(thisupd: *mut ASN1_GENERALIZEDTIME, nextupd: *mut ASN1_GENERALIZEDTIME, nsec: c_long, maxsec: c_long) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        const F: &str = "OCSP_check_validity";
        let mut ret = 1;
        // SAFETY: the caller's time.
        if unsafe { ASN1_GENERALIZEDTIME_check(thisupd) } == 0 {
            raise(OCSP_R_ERROR_IN_THISUPDATE_FIELD, F);
            ret = 0;
        } else {
            // Not more than `nsec` in the future.
            let cmp = cmp_now(thisupd, nsec);
            if cmp == 0 {
                raise(OCSP_R_ERROR_IN_THISUPDATE_FIELD, F);
                ret = 0;
            } else if cmp > 0 {
                raise(OCSP_R_STATUS_NOT_YET_VALID, F);
                ret = 0;
            }
            // Not more than `maxsec` in the past, if it could be compared.
            if cmp != 0 && maxsec >= 0 && cmp_now(thisupd, maxsec.saturating_neg()) < 0 {
                raise(OCSP_R_STATUS_TOO_OLD, F);
                ret = 0;
            }
        }
        if nextupd.is_null() {
            return ret;
        }
        // SAFETY: the caller's time.
        if unsafe { ASN1_GENERALIZEDTIME_check(nextupd) } == 0 {
            raise(OCSP_R_ERROR_IN_NEXTUPDATE_FIELD, F);
            ret = 0;
        } else {
            // Not more than `nsec` in the past.
            let cmp = cmp_now(nextupd, nsec.saturating_neg());
            if cmp == 0 {
                raise(OCSP_R_ERROR_IN_NEXTUPDATE_FIELD, F);
                ret = 0;
            } else if cmp < 0 {
                raise(OCSP_R_STATUS_EXPIRED, F);
                ret = 0;
            }
        }
        // Nor nextUpdate before thisUpdate.
        // SAFETY: the caller's times.
        if unsafe { ASN1_STRING_cmp(nextupd, thisupd) } < 0 {
            raise(OCSP_R_NEXTUPDATE_BEFORE_THISUPDATE, F);
            ret = 0;
        }
        ret
    }
}

ffi_export! {
    /// The single response's CertID.
    ///
    /// # Safety
    /// `single_` is a live single response.
    pub unsafe extern "C" fn OCSP_SINGLERESP_get0_id(single_: *const OCSP_SINGLERESP) -> *const OCSP_CERTID
    where failure = ptr::null(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        unsafe { single(single_) }.map_or(ptr::null(), |s| s.cert_id.cast_const().cast())
    }
}
