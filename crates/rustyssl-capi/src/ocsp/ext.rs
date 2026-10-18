//! Extensions (`ocsp_ext.c`): those of requests, single requests, basic responses, and single
//! responses; nonces; and the CrlID, archive cutoff, acceptable responses, and service
//! locator extensions.

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_OBJECT, ERR_LIB_OCSP, GEN_URI, NID_ad_OCSP, NID_id_pkix_OCSP_CrlID,
    NID_id_pkix_OCSP_Nonce, NID_id_pkix_OCSP_acceptableResponses, NID_id_pkix_OCSP_archiveCutoff,
    NID_id_pkix_OCSP_serviceLocator, NID_undef, OCSP_BASICRESP, OCSP_DEFAULT_NONCE_LENGTH,
    OCSP_ONEREQ, OCSP_REQUEST, OCSP_SINGLERESP, V_ASN1_OCTET_STRING, V_ASN1_UNIVERSAL,
    X509_EXTENSION, X509_NAME, X509V3_ADD_REPLACE, stack_st_X509_EXTENSION,
};

use super::asn::{
    BasicResp, CrlId, OCSP_CRLID_free, OCSP_CRLID_new, OCSP_SERVICELOC_free, OCSP_SERVICELOC_new,
    OneReq, Request, ServiceLoc, SingleResp, Stack, of,
};
use crate::asn1::integer::ASN1_INTEGER_set;
use crate::asn1::string::{
    ASN1_GENERALIZEDTIME_free, ASN1_GENERALIZEDTIME_new, ASN1_IA5STRING_free, ASN1_IA5STRING_new,
    ASN1_INTEGER_new, ASN1_OCTET_STRING_cmp, ASN1_STRING_set,
};
use crate::asn1::time::ASN1_GENERALIZEDTIME_set_string;
use crate::asn1::{ASN1_object_size, ASN1_put_object};
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::{OBJ_nid2obj, OBJ_txt2nid};
use crate::rand_lib::RAND_bytes;
use crate::stack::{OPENSSL_sk_new_null, OPENSSL_sk_push};
use crate::x509::ext::{
    X509_EXTENSION_get_data, X509v3_add_ext, X509v3_delete_ext, X509v3_get_ext,
    X509v3_get_ext_by_NID, X509v3_get_ext_by_OBJ, X509v3_get_ext_by_critical, X509v3_get_ext_count,
};
use crate::x509::name::{X509_NAME_dup, X509_NAME_free};
use crate::x509v3::info::{ACCESS_DESCRIPTION_free, ACCESS_DESCRIPTION_new};
use crate::x509v3::registry::{X509V3_EXT_i2d, X509V3_add1_i2d, X509V3_get_d2i};

/// An object's extensions' slot.
fn slot(p: &mut *mut Stack) -> *mut *mut stack_st_X509_EXTENSION {
    ptr::from_mut(p).cast()
}

ffi_export! {
    /// The number of the request's extensions.
    ///
    /// # Safety
    /// `x` is a live request.
    pub unsafe extern "C" fn OCSP_REQUEST_get_ext_count(x: *mut OCSP_REQUEST) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Request, _>(x) }) else { return 0 };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_count(r.tbs_request.request_extensions.cast()) }
    }
}

ffi_export! {
    /// The index of the request's next extension `nid` after `lastpos`, or -1.
    ///
    /// # Safety
    /// `x` is a live request.
    pub unsafe extern "C" fn OCSP_REQUEST_get_ext_by_NID(x: *mut OCSP_REQUEST, nid: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Request, _>(x) }) else { return -1 };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_by_NID(r.tbs_request.request_extensions.cast(), nid, lastpos) }
    }
}

ffi_export! {
    /// The index of the request's next extension `obj` after `lastpos`, or -1.
    ///
    /// # Safety
    /// `x` is a live request; `obj` a live object.
    pub unsafe extern "C" fn OCSP_REQUEST_get_ext_by_OBJ(x: *mut OCSP_REQUEST, obj: *const ASN1_OBJECT, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Request, _>(x) }) else { return -1 };
        // SAFETY: its extensions, or NULL; the caller's object.
        unsafe { X509v3_get_ext_by_OBJ(r.tbs_request.request_extensions.cast(), obj, lastpos) }
    }
}

ffi_export! {
    /// The index of the request's next extension of the criticality after `lastpos`, or -1.
    ///
    /// # Safety
    /// `x` is a live request.
    pub unsafe extern "C" fn OCSP_REQUEST_get_ext_by_critical(x: *mut OCSP_REQUEST, crit: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Request, _>(x) }) else { return -1 };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_by_critical(r.tbs_request.request_extensions.cast(), crit, lastpos) }
    }
}

ffi_export! {
    /// The request's extension `loc`, or NULL.
    ///
    /// # Safety
    /// `x` is a live request.
    pub unsafe extern "C" fn OCSP_REQUEST_get_ext(x: *mut OCSP_REQUEST, loc: c_int) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Request, _>(x) }) else { return ptr::null_mut() };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext(r.tbs_request.request_extensions.cast(), loc) }
    }
}

ffi_export! {
    /// Removes the request's extension `loc` and gives it to the caller, or NULL.
    ///
    /// # Safety
    /// `x` is a live request.
    pub unsafe extern "C" fn OCSP_REQUEST_delete_ext(x: *mut OCSP_REQUEST, loc: c_int) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Request, _>(x) }) else { return ptr::null_mut() };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_delete_ext(r.tbs_request.request_extensions.cast(), loc) }
    }
}

ffi_export! {
    /// The request's extension `nid`, decoded (see `X509V3_get_d2i`), or NULL.
    ///
    /// # Safety
    /// `x` is a live request; `crit` and `idx` NULL or room for an `int`.
    pub unsafe extern "C" fn OCSP_REQUEST_get1_ext_d2i(x: *mut OCSP_REQUEST, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Request, _>(x) }) else { return ptr::null_mut() };
        // SAFETY: its extensions, or NULL; the caller's room.
        unsafe { X509V3_get_d2i(r.tbs_request.request_extensions.cast(), nid, crit, idx) }
    }
}

ffi_export! {
    /// Adds the value as the request's extension `nid` (see `X509V3_add1_i2d`): 1, 0, or -1.
    ///
    /// # Safety
    /// `x` is a live request; `value` a live value of the extension.
    pub unsafe extern "C" fn OCSP_REQUEST_add1_ext_i2d(x: *mut OCSP_REQUEST, nid: c_int, value: *mut c_void, crit: c_int, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Request, _>(x) }) else { return 0 };
        // SAFETY: its extensions' slot; the caller's value.
        unsafe { X509V3_add1_i2d(slot(&mut r.tbs_request.request_extensions), nid, value, crit, flags) }
    }
}

ffi_export! {
    /// Adds a copy of the extension at `loc` (-1 for the end): 1, or 0.
    ///
    /// # Safety
    /// `x` is a live request; `ex` a live extension.
    pub unsafe extern "C" fn OCSP_REQUEST_add_ext(x: *mut OCSP_REQUEST, ex: *mut X509_EXTENSION, loc: c_int) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Request, _>(x) }) else { return 0 };
        // SAFETY: its extensions' slot; the caller's extension.
        c_int::from(!unsafe { X509v3_add_ext(slot(&mut r.tbs_request.request_extensions).cast(), ex, loc) }.is_null())
    }
}

ffi_export! {
    /// The number of the single request's extensions.
    ///
    /// # Safety
    /// `x` is a live single request.
    pub unsafe extern "C" fn OCSP_ONEREQ_get_ext_count(x: *mut OCSP_ONEREQ) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<OneReq, _>(x) }) else { return 0 };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_count(r.single_request_extensions.cast()) }
    }
}

ffi_export! {
    /// The index of the single request's next extension `nid` after `lastpos`, or -1.
    ///
    /// # Safety
    /// `x` is a live single request.
    pub unsafe extern "C" fn OCSP_ONEREQ_get_ext_by_NID(x: *mut OCSP_ONEREQ, nid: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<OneReq, _>(x) }) else { return -1 };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_by_NID(r.single_request_extensions.cast(), nid, lastpos) }
    }
}

ffi_export! {
    /// The index of the single request's next extension `obj` after `lastpos`, or -1.
    ///
    /// # Safety
    /// `x` is a live single request; `obj` a live object.
    pub unsafe extern "C" fn OCSP_ONEREQ_get_ext_by_OBJ(x: *mut OCSP_ONEREQ, obj: *const ASN1_OBJECT, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<OneReq, _>(x) }) else { return -1 };
        // SAFETY: its extensions, or NULL; the caller's object.
        unsafe { X509v3_get_ext_by_OBJ(r.single_request_extensions.cast(), obj, lastpos) }
    }
}

ffi_export! {
    /// The index of the single request's next extension of the criticality after `lastpos`, or -1.
    ///
    /// # Safety
    /// `x` is a live single request.
    pub unsafe extern "C" fn OCSP_ONEREQ_get_ext_by_critical(x: *mut OCSP_ONEREQ, crit: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<OneReq, _>(x) }) else { return -1 };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_by_critical(r.single_request_extensions.cast(), crit, lastpos) }
    }
}

ffi_export! {
    /// The single request's extension `loc`, or NULL.
    ///
    /// # Safety
    /// `x` is a live single request.
    pub unsafe extern "C" fn OCSP_ONEREQ_get_ext(x: *mut OCSP_ONEREQ, loc: c_int) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<OneReq, _>(x) }) else { return ptr::null_mut() };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext(r.single_request_extensions.cast(), loc) }
    }
}

ffi_export! {
    /// Removes the single request's extension `loc` and gives it to the caller, or NULL.
    ///
    /// # Safety
    /// `x` is a live single request.
    pub unsafe extern "C" fn OCSP_ONEREQ_delete_ext(x: *mut OCSP_ONEREQ, loc: c_int) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<OneReq, _>(x) }) else { return ptr::null_mut() };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_delete_ext(r.single_request_extensions.cast(), loc) }
    }
}

ffi_export! {
    /// The single request's extension `nid`, decoded (see `X509V3_get_d2i`), or NULL.
    ///
    /// # Safety
    /// `x` is a live single request; `crit` and `idx` NULL or room for an `int`.
    pub unsafe extern "C" fn OCSP_ONEREQ_get1_ext_d2i(x: *mut OCSP_ONEREQ, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<OneReq, _>(x) }) else { return ptr::null_mut() };
        // SAFETY: its extensions, or NULL; the caller's room.
        unsafe { X509V3_get_d2i(r.single_request_extensions.cast(), nid, crit, idx) }
    }
}

ffi_export! {
    /// Adds the value as the single request's extension `nid` (see `X509V3_add1_i2d`): 1, 0, or -1.
    ///
    /// # Safety
    /// `x` is a live single request; `value` a live value of the extension.
    pub unsafe extern "C" fn OCSP_ONEREQ_add1_ext_i2d(x: *mut OCSP_ONEREQ, nid: c_int, value: *mut c_void, crit: c_int, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<OneReq, _>(x) }) else { return 0 };
        // SAFETY: its extensions' slot; the caller's value.
        unsafe { X509V3_add1_i2d(slot(&mut r.single_request_extensions), nid, value, crit, flags) }
    }
}

ffi_export! {
    /// Adds a copy of the extension at `loc` (-1 for the end): 1, or 0.
    ///
    /// # Safety
    /// `x` is a live single request; `ex` a live extension.
    pub unsafe extern "C" fn OCSP_ONEREQ_add_ext(x: *mut OCSP_ONEREQ, ex: *mut X509_EXTENSION, loc: c_int) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<OneReq, _>(x) }) else { return 0 };
        // SAFETY: its extensions' slot; the caller's extension.
        c_int::from(!unsafe { X509v3_add_ext(slot(&mut r.single_request_extensions).cast(), ex, loc) }.is_null())
    }
}

ffi_export! {
    /// The number of the basic response's extensions.
    ///
    /// # Safety
    /// `x` is a live basic response.
    pub unsafe extern "C" fn OCSP_BASICRESP_get_ext_count(x: *mut OCSP_BASICRESP) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<BasicResp, _>(x) }) else { return 0 };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_count(r.tbs_response_data.response_extensions.cast()) }
    }
}

ffi_export! {
    /// The index of the basic response's next extension `nid` after `lastpos`, or -1.
    ///
    /// # Safety
    /// `x` is a live basic response.
    pub unsafe extern "C" fn OCSP_BASICRESP_get_ext_by_NID(x: *mut OCSP_BASICRESP, nid: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<BasicResp, _>(x) }) else { return -1 };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_by_NID(r.tbs_response_data.response_extensions.cast(), nid, lastpos) }
    }
}

ffi_export! {
    /// The index of the basic response's next extension `obj` after `lastpos`, or -1.
    ///
    /// # Safety
    /// `x` is a live basic response; `obj` a live object.
    pub unsafe extern "C" fn OCSP_BASICRESP_get_ext_by_OBJ(x: *mut OCSP_BASICRESP, obj: *const ASN1_OBJECT, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<BasicResp, _>(x) }) else { return -1 };
        // SAFETY: its extensions, or NULL; the caller's object.
        unsafe { X509v3_get_ext_by_OBJ(r.tbs_response_data.response_extensions.cast(), obj, lastpos) }
    }
}

ffi_export! {
    /// The index of the basic response's next extension of the criticality after `lastpos`, or -1.
    ///
    /// # Safety
    /// `x` is a live basic response.
    pub unsafe extern "C" fn OCSP_BASICRESP_get_ext_by_critical(x: *mut OCSP_BASICRESP, crit: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<BasicResp, _>(x) }) else { return -1 };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_by_critical(r.tbs_response_data.response_extensions.cast(), crit, lastpos) }
    }
}

ffi_export! {
    /// The basic response's extension `loc`, or NULL.
    ///
    /// # Safety
    /// `x` is a live basic response.
    pub unsafe extern "C" fn OCSP_BASICRESP_get_ext(x: *mut OCSP_BASICRESP, loc: c_int) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<BasicResp, _>(x) }) else { return ptr::null_mut() };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext(r.tbs_response_data.response_extensions.cast(), loc) }
    }
}

ffi_export! {
    /// Removes the basic response's extension `loc` and gives it to the caller, or NULL.
    ///
    /// # Safety
    /// `x` is a live basic response.
    pub unsafe extern "C" fn OCSP_BASICRESP_delete_ext(x: *mut OCSP_BASICRESP, loc: c_int) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<BasicResp, _>(x) }) else { return ptr::null_mut() };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_delete_ext(r.tbs_response_data.response_extensions.cast(), loc) }
    }
}

ffi_export! {
    /// The basic response's extension `nid`, decoded (see `X509V3_get_d2i`), or NULL.
    ///
    /// # Safety
    /// `x` is a live basic response; `crit` and `idx` NULL or room for an `int`.
    pub unsafe extern "C" fn OCSP_BASICRESP_get1_ext_d2i(x: *mut OCSP_BASICRESP, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<BasicResp, _>(x) }) else { return ptr::null_mut() };
        // SAFETY: its extensions, or NULL; the caller's room.
        unsafe { X509V3_get_d2i(r.tbs_response_data.response_extensions.cast(), nid, crit, idx) }
    }
}

ffi_export! {
    /// Adds the value as the basic response's extension `nid` (see `X509V3_add1_i2d`): 1, 0, or -1.
    ///
    /// # Safety
    /// `x` is a live basic response; `value` a live value of the extension.
    pub unsafe extern "C" fn OCSP_BASICRESP_add1_ext_i2d(x: *mut OCSP_BASICRESP, nid: c_int, value: *mut c_void, crit: c_int, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<BasicResp, _>(x) }) else { return 0 };
        // SAFETY: its extensions' slot; the caller's value.
        unsafe { X509V3_add1_i2d(slot(&mut r.tbs_response_data.response_extensions), nid, value, crit, flags) }
    }
}

ffi_export! {
    /// Adds a copy of the extension at `loc` (-1 for the end): 1, or 0.
    ///
    /// # Safety
    /// `x` is a live basic response; `ex` a live extension.
    pub unsafe extern "C" fn OCSP_BASICRESP_add_ext(x: *mut OCSP_BASICRESP, ex: *mut X509_EXTENSION, loc: c_int) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<BasicResp, _>(x) }) else { return 0 };
        // SAFETY: its extensions' slot; the caller's extension.
        c_int::from(!unsafe { X509v3_add_ext(slot(&mut r.tbs_response_data.response_extensions).cast(), ex, loc) }.is_null())
    }
}

ffi_export! {
    /// The number of the single response's extensions.
    ///
    /// # Safety
    /// `x` is a live single response.
    pub unsafe extern "C" fn OCSP_SINGLERESP_get_ext_count(x: *mut OCSP_SINGLERESP) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<SingleResp, _>(x) }) else { return 0 };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_count(r.single_extensions.cast()) }
    }
}

ffi_export! {
    /// The index of the single response's next extension `nid` after `lastpos`, or -1.
    ///
    /// # Safety
    /// `x` is a live single response.
    pub unsafe extern "C" fn OCSP_SINGLERESP_get_ext_by_NID(x: *mut OCSP_SINGLERESP, nid: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<SingleResp, _>(x) }) else { return -1 };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_by_NID(r.single_extensions.cast(), nid, lastpos) }
    }
}

ffi_export! {
    /// The index of the single response's next extension `obj` after `lastpos`, or -1.
    ///
    /// # Safety
    /// `x` is a live single response; `obj` a live object.
    pub unsafe extern "C" fn OCSP_SINGLERESP_get_ext_by_OBJ(x: *mut OCSP_SINGLERESP, obj: *const ASN1_OBJECT, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<SingleResp, _>(x) }) else { return -1 };
        // SAFETY: its extensions, or NULL; the caller's object.
        unsafe { X509v3_get_ext_by_OBJ(r.single_extensions.cast(), obj, lastpos) }
    }
}

ffi_export! {
    /// The index of the single response's next extension of the criticality after `lastpos`, or -1.
    ///
    /// # Safety
    /// `x` is a live single response.
    pub unsafe extern "C" fn OCSP_SINGLERESP_get_ext_by_critical(x: *mut OCSP_SINGLERESP, crit: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<SingleResp, _>(x) }) else { return -1 };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_by_critical(r.single_extensions.cast(), crit, lastpos) }
    }
}

ffi_export! {
    /// The single response's extension `loc`, or NULL.
    ///
    /// # Safety
    /// `x` is a live single response.
    pub unsafe extern "C" fn OCSP_SINGLERESP_get_ext(x: *mut OCSP_SINGLERESP, loc: c_int) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<SingleResp, _>(x) }) else { return ptr::null_mut() };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext(r.single_extensions.cast(), loc) }
    }
}

ffi_export! {
    /// Removes the single response's extension `loc` and gives it to the caller, or NULL.
    ///
    /// # Safety
    /// `x` is a live single response.
    pub unsafe extern "C" fn OCSP_SINGLERESP_delete_ext(x: *mut OCSP_SINGLERESP, loc: c_int) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<SingleResp, _>(x) }) else { return ptr::null_mut() };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_delete_ext(r.single_extensions.cast(), loc) }
    }
}

ffi_export! {
    /// The single response's extension `nid`, decoded (see `X509V3_get_d2i`), or NULL.
    ///
    /// # Safety
    /// `x` is a live single response; `crit` and `idx` NULL or room for an `int`.
    pub unsafe extern "C" fn OCSP_SINGLERESP_get1_ext_d2i(x: *mut OCSP_SINGLERESP, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<SingleResp, _>(x) }) else { return ptr::null_mut() };
        // SAFETY: its extensions, or NULL; the caller's room.
        unsafe { X509V3_get_d2i(r.single_extensions.cast(), nid, crit, idx) }
    }
}

ffi_export! {
    /// Adds the value as the single response's extension `nid` (see `X509V3_add1_i2d`): 1, 0, or -1.
    ///
    /// # Safety
    /// `x` is a live single response; `value` a live value of the extension.
    pub unsafe extern "C" fn OCSP_SINGLERESP_add1_ext_i2d(x: *mut OCSP_SINGLERESP, nid: c_int, value: *mut c_void, crit: c_int, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<SingleResp, _>(x) }) else { return 0 };
        // SAFETY: its extensions' slot; the caller's value.
        unsafe { X509V3_add1_i2d(slot(&mut r.single_extensions), nid, value, crit, flags) }
    }
}

ffi_export! {
    /// Adds a copy of the extension at `loc` (-1 for the end): 1, or 0.
    ///
    /// # Safety
    /// `x` is a live single response; `ex` a live extension.
    pub unsafe extern "C" fn OCSP_SINGLERESP_add_ext(x: *mut OCSP_SINGLERESP, ex: *mut X509_EXTENSION, loc: c_int) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<SingleResp, _>(x) }) else { return 0 };
        // SAFETY: its extensions' slot; the caller's extension.
        c_int::from(!unsafe { X509v3_add_ext(slot(&mut r.single_extensions).cast(), ex, loc) }.is_null())
    }
}

/// `ocsp_add1_nonce`: a nonce extension (replacing any) of `val` or, for NULL, random
/// octets, `len` of them (16 for none), as an OCTET STRING inside the extension's.
///
/// # Safety
/// `exts` holds NULL or a live list; `val` NULL or holding `len` octets.
unsafe fn add1_nonce(exts: *mut *mut stack_st_X509_EXTENSION, val: *const u8, len: c_int) -> c_int {
    let len = if len <= 0 {
        OCSP_DEFAULT_NONCE_LENGTH as c_int
    } else {
        len
    };
    // SAFETY: no preconditions.
    let total = unsafe { ASN1_object_size(0, len, V_ASN1_OCTET_STRING) };
    let Ok(n) = usize::try_from(total) else {
        return 0;
    };
    let Ok(body) = usize::try_from(len) else {
        return 0;
    };
    let data = mem::alloc(n).cast::<u8>();
    if data.is_null() {
        return 0;
    }
    let mut os = rustyssl_abi::ASN1_STRING {
        length: total,
        type_: V_ASN1_OCTET_STRING,
        data,
        flags: 0,
    };
    let mut p = data;
    // SAFETY: room for the header and `len` octets.
    unsafe { ASN1_put_object(&mut p, 0, len, V_ASN1_OCTET_STRING, V_ASN1_UNIVERSAL) };
    let ok = 'err: {
        if !val.is_null() {
            // SAFETY: the caller's octets; the room after the header.
            unsafe { ptr::copy_nonoverlapping(val, p, body) };
        // SAFETY: as above.
        } else if unsafe { RAND_bytes(p, len) } <= 0 {
            break 'err false;
        }
        // SAFETY: the caller's slot; the OCTET STRING, as the nonce's method encodes it.
        (unsafe {
            X509V3_add1_i2d(
                exts,
                NID_id_pkix_OCSP_Nonce,
                (&raw mut os).cast(),
                0,
                c_ulong::from(X509V3_ADD_REPLACE.cast_unsigned()),
            )
        }) > 0
    };
    // SAFETY: the buffer made here.
    unsafe { mem::release(os.data.cast()) };
    c_int::from(ok)
}

ffi_export! {
    /// Adds a nonce to the request (random if `val` is NULL): 1, or 0.
    ///
    /// # Safety
    /// `req` is a live request; `val` NULL or holding `len` octets.
    pub unsafe extern "C" fn OCSP_request_add1_nonce(req: *mut OCSP_REQUEST, val: *mut u8, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Request, _>(req) }) else { return 0 };
        // SAFETY: its extensions' slot; the caller's octets.
        unsafe { add1_nonce(slot(&mut r.tbs_request.request_extensions), val, len) }
    }
}

ffi_export! {
    /// Adds a nonce to the basic response (random if `val` is NULL): 1, or 0.
    ///
    /// # Safety
    /// `resp` is a live basic response; `val` NULL or holding `len` octets.
    pub unsafe extern "C" fn OCSP_basic_add1_nonce(resp: *mut OCSP_BASICRESP, val: *mut u8, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<BasicResp, _>(resp) }) else { return 0 };
        // SAFETY: its extensions' slot; the caller's octets.
        unsafe { add1_nonce(slot(&mut r.tbs_response_data.response_extensions), val, len) }
    }
}

ffi_export! {
    /// Compares the request's and the response's nonces: 1 if equal, 0 if not, 2 if both are
    /// absent, 3 if only the response has one, -1 if only the request has one.
    ///
    /// # Safety
    /// `req` is a live request; `bs` a live basic response.
    pub unsafe extern "C" fn OCSP_check_nonce(req: *mut OCSP_REQUEST, bs: *mut OCSP_BASICRESP) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let req_idx = unsafe { OCSP_REQUEST_get_ext_by_NID(req, NID_id_pkix_OCSP_Nonce, -1) };
        // SAFETY: as above.
        let resp_idx = unsafe { OCSP_BASICRESP_get_ext_by_NID(bs, NID_id_pkix_OCSP_Nonce, -1) };
        match (req_idx >= 0, resp_idx >= 0) {
            (false, false) => return 2,
            (true, false) => return -1,
            (false, true) => return 3,
            (true, true) => {}
        }
        // SAFETY: as above; the index found.
        let req_ext = unsafe { OCSP_REQUEST_get_ext(req, req_idx) };
        // SAFETY: as above.
        let resp_ext = unsafe { OCSP_BASICRESP_get_ext(bs, resp_idx) };
        // SAFETY: the request's extension.
        let a = unsafe { X509_EXTENSION_get_data(req_ext) };
        // SAFETY: the response's.
        let b = unsafe { X509_EXTENSION_get_data(resp_ext) };
        // SAFETY: their values.
        c_int::from(unsafe { ASN1_OCTET_STRING_cmp(a, b) } == 0)
    }
}

ffi_export! {
    /// Copies the request's nonce into the basic response: 1, 0, or 2 if there is none.
    ///
    /// # Safety
    /// `resp` is a live basic response; `req` a live request.
    pub unsafe extern "C" fn OCSP_copy_nonce(resp: *mut OCSP_BASICRESP, req: *mut OCSP_REQUEST) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let req_idx = unsafe { OCSP_REQUEST_get_ext_by_NID(req, NID_id_pkix_OCSP_Nonce, -1) };
        // That there's none is fine.
        if req_idx < 0 {
            return 2;
        }
        // SAFETY: as above; the index found.
        let req_ext = unsafe { OCSP_REQUEST_get_ext(req, req_idx) };
        // SAFETY: as above.
        unsafe { OCSP_BASICRESP_add_ext(resp, req_ext, -1) }
    }
}

ffi_export! {
    /// A CrlID extension of the URL, CRL number, and time (each if given), or NULL.
    ///
    /// # Safety
    /// `url` and `tim` are NULL or C strings; `n` NULL or a live `long`.
    pub unsafe extern "C" fn OCSP_crlID_new(url: *const c_char, n: *mut c_long, tim: *mut c_char) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: no preconditions.
        let cid = unsafe { OCSP_CRLID_new() };
        let x = 'err: {
            // SAFETY: the new CrlID, or NULL.
            let Some(c) = (unsafe { of::<CrlId, _>(cid) }) else { break 'err ptr::null_mut() };
            if !url.is_null() {
                // SAFETY: no preconditions.
                c.crl_url = unsafe { ASN1_IA5STRING_new() };
                // SAFETY: the new string; the caller's C string.
                if c.crl_url.is_null() || unsafe { ASN1_STRING_set(c.crl_url, url.cast(), -1) } == 0 {
                    break 'err ptr::null_mut();
                }
            }
            // SAFETY: the caller's number, or NULL.
            if let Some(&num) = unsafe { n.as_ref() } {
                // SAFETY: no preconditions.
                c.crl_num = unsafe { ASN1_INTEGER_new() };
                // SAFETY: the new INTEGER.
                if c.crl_num.is_null() || unsafe { ASN1_INTEGER_set(c.crl_num, num) } == 0 {
                    break 'err ptr::null_mut();
                }
            }
            if !tim.is_null() {
                // SAFETY: no preconditions.
                c.crl_time = unsafe { ASN1_GENERALIZEDTIME_new() };
                // SAFETY: the new time; the caller's C string.
                if c.crl_time.is_null() || unsafe { ASN1_GENERALIZEDTIME_set_string(c.crl_time, tim) } == 0 {
                    break 'err ptr::null_mut();
                }
            }
            // SAFETY: the CrlID, as its method encodes it.
            unsafe { X509V3_EXT_i2d(NID_id_pkix_OCSP_CrlID, 0, cid.cast()) }
        };
        // SAFETY: the CrlID made here, or NULL.
        unsafe { OCSP_CRLID_free(cid) };
        x
    }
}

/// `ASN1_OBJECT_free`, which leaves built-in objects alone, as a stack's free function.
unsafe extern "C" fn object_free(p: *mut c_void) {
    // SAFETY: an element of a list of objects.
    unsafe { crate::objects::ASN1_OBJECT_free(p.cast()) };
}

ffi_export! {
    /// An acceptable-responses extension of the named response types (unknown names
    /// skipped), or NULL.
    ///
    /// # Safety
    /// `oids` is NULL or a NULL-terminated array of C strings.
    pub unsafe extern "C" fn OCSP_accept_responses_new(oids: *mut *mut c_char) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: no preconditions.
        let sk = unsafe { OPENSSL_sk_new_null() };
        let x = 'err: {
            if sk.is_null() {
                break 'err ptr::null_mut();
            }
            let mut p = oids;
            // SAFETY: the caller's array, up to its NULL.
            while let Some(&name) = (!p.is_null()).then(|| unsafe { &*p }).filter(|n| !n.is_null()) {
                // SAFETY: a C string.
                let nid = unsafe { OBJ_txt2nid(name) };
                if nid != NID_undef {
                    // SAFETY: any NID.
                    let o = unsafe { OBJ_nid2obj(nid) };
                    // SAFETY: the list; a built-in object.
                    if !o.is_null() && unsafe { OPENSSL_sk_push(sk, o.cast()) } == 0 {
                        break 'err ptr::null_mut();
                    }
                }
                // SAFETY: the next element, within the array.
                p = unsafe { p.add(1) };
            }
            // SAFETY: the list, as the extension's method encodes it.
            unsafe { X509V3_EXT_i2d(NID_id_pkix_OCSP_acceptableResponses, 0, sk.cast()) }
        };
        // SAFETY: the list made here, or NULL.
        unsafe { crate::stack::OPENSSL_sk_pop_free(sk, Some(object_free)) };
        x
    }
}

ffi_export! {
    /// An archive-cutoff extension of the time, or NULL.
    ///
    /// # Safety
    /// `tim` is a C string.
    pub unsafe extern "C" fn OCSP_archive_cutoff_new(tim: *mut c_char) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: no preconditions.
        let gt = unsafe { ASN1_GENERALIZEDTIME_new() };
        // SAFETY: the new time; the caller's C string.
        let x = if gt.is_null() || unsafe { ASN1_GENERALIZEDTIME_set_string(gt, tim) } == 0 {
            ptr::null_mut()
        } else {
            // SAFETY: the time, as the extension's method encodes it.
            unsafe { X509V3_EXT_i2d(NID_id_pkix_OCSP_archiveCutoff, 0, gt.cast()) }
        };
        // SAFETY: the time made here, or NULL.
        unsafe { ASN1_GENERALIZEDTIME_free(gt) };
        x
    }
}

ffi_export! {
    /// A service-locator extension of (a copy of) the issuer and the OCSP URLs, or NULL.
    ///
    /// # Safety
    /// `issuer` is a live name; `urls` NULL or a NULL-terminated array of C strings.
    pub unsafe extern "C" fn OCSP_url_svcloc_new(issuer: *const X509_NAME, urls: *mut *const c_char) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: no preconditions.
        let sloc = unsafe { OCSP_SERVICELOC_new() };
        let x = 'err: {
            // SAFETY: the new locator, or NULL.
            let Some(s) = (unsafe { of::<ServiceLoc, _>(sloc) }) else { break 'err ptr::null_mut() };
            // SAFETY: its empty name.
            unsafe { X509_NAME_free(s.issuer) };
            // SAFETY: the caller's name.
            s.issuer = unsafe { X509_NAME_dup(issuer) };
            if s.issuer.is_null() {
                break 'err ptr::null_mut();
            }
            let mut p = urls;
            // SAFETY: the caller's array, up to its NULL.
            let next = |p: *mut *const c_char| (!p.is_null()).then(|| unsafe { *p }).filter(|u| !u.is_null());
            if next(p).is_some() {
                // SAFETY: no preconditions.
                s.locator = unsafe { OPENSSL_sk_new_null() };
                if s.locator.is_null() {
                    break 'err ptr::null_mut();
                }
            }
            while let Some(url) = next(p) {
                // SAFETY: no preconditions.
                let ad = unsafe { ACCESS_DESCRIPTION_new() };
                // SAFETY: the new description, or NULL.
                let Some(a) = (unsafe { ad.as_mut() }) else { break 'err ptr::null_mut() };
                // SAFETY: a built-in NID.
                a.method = unsafe { OBJ_nid2obj(NID_ad_OCSP) };
                // SAFETY: no preconditions.
                let ia5 = unsafe { ASN1_IA5STRING_new() };
                // SAFETY: the new string; the caller's C string.
                if ia5.is_null() || unsafe { ASN1_STRING_set(ia5, url.cast(), -1) } == 0 {
                    // SAFETY: made here, or NULL.
                    unsafe { ASN1_IA5STRING_free(ia5) };
                    // SAFETY: as above.
                    unsafe { ACCESS_DESCRIPTION_free(ad) };
                    break 'err ptr::null_mut();
                }
                // The location is made with the description.
                // SAFETY: its location, made with it.
                let loc = unsafe { &mut *a.location };
                loc.type_ = GEN_URI;
                loc.d.ia5 = ia5;
                // SAFETY: the list; the description.
                if unsafe { OPENSSL_sk_push(s.locator, ad.cast()) } == 0 {
                    // SAFETY: the description, not taken.
                    unsafe { ACCESS_DESCRIPTION_free(ad) };
                    break 'err ptr::null_mut();
                }
                // SAFETY: the next element, within the array.
                p = unsafe { p.add(1) };
            }
            // SAFETY: the locator, as the extension's method encodes it.
            unsafe { X509V3_EXT_i2d(NID_id_pkix_OCSP_serviceLocator, 0, sloc.cast()) }
        };
        // SAFETY: the locator made here, or NULL.
        unsafe { OCSP_SERVICELOC_free(sloc) };
        x
    }
}
