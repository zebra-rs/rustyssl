//! Getting and setting the request's and the response's fields (`ts_req_utils.c`,
//! `ts_rsp_utils.c`): each setter takes a copy, and each extension function is the `X509v3_*`
//! one over the object's extensions.

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_GENERALIZEDTIME, ASN1_INTEGER, ASN1_OBJECT, ASN1_OCTET_STRING,
    ERR_LIB_TS, ERR_R_ASN1_LIB, ERR_R_OBJ_LIB, ERR_R_TS_LIB, GENERAL_NAME, PKCS7, TS_ACCURACY,
    TS_MSG_IMPRINT, TS_REQ, TS_RESP, TS_STATUS_INFO, TS_TST_INFO, X509_ALGOR, X509_EXTENSION,
    stack_st_ASN1_UTF8STRING, stack_st_X509_EXTENSION,
};

use super::asn::{
    Accuracy, MsgImprint, Req, Resp, Stack, StatusInfo, TS_ACCURACY_dup, TS_ACCURACY_free,
    TS_MSG_IMPRINT_dup, TS_MSG_IMPRINT_free, TS_STATUS_INFO_dup, TS_STATUS_INFO_free,
    TS_TST_INFO_free, TstInfo,
};
use crate::asn1::integer::{ASN1_INTEGER_dup, ASN1_INTEGER_get, ASN1_INTEGER_set};
use crate::asn1::string::{
    ASN1_GENERALIZEDTIME_free, ASN1_INTEGER_free, ASN1_OCTET_STRING_set, ASN1_STRING_dup,
};
use crate::asn1::tpl::items::X509_ALGOR_free;
use crate::err;
use crate::ffi::ffi_export;
use crate::objects::{ASN1_OBJECT_free, OBJ_dup};
use crate::pkcs7::PKCS7_free;
use crate::stack::OPENSSL_sk_pop_free;
use crate::x509::algor::X509_ALGOR_dup;
use crate::x509::ext::{
    X509_EXTENSION_free, X509v3_add_ext, X509v3_delete_ext, X509v3_get_ext, X509v3_get_ext_by_NID,
    X509v3_get_ext_by_OBJ, X509v3_get_ext_by_critical, X509v3_get_ext_count,
};
use crate::x509v3::genn::{GENERAL_NAME_dup, GENERAL_NAME_free};
use crate::x509v3::registry::X509V3_get_d2i;

/// The object behind a pointer as its `T`.
///
/// # Safety
/// `p` is NULL or a live object `T` mirrors, not otherwise borrowed.
pub(crate) unsafe fn of<'a, T, U>(p: *const U) -> Option<&'a mut T> {
    // SAFETY: the caller's guarantee.
    unsafe { p.cast::<T>().cast_mut().as_mut() }
}

/// Replaces `*slot` with a copy of `v` made by `dup` (unless it is already `v`), freeing the
/// old one: 1, or 0 with `reason`. With `optional`, a NULL `v` empties the slot.
///
/// # Safety
/// `slot` is valid and holds NULL or a live value; `v` is NULL or live; `dup` and `free` are
/// the type's.
unsafe fn set_copy<T>(
    slot: *mut *mut T,
    v: *const T,
    dup: unsafe extern "C" fn(*const T) -> *mut T,
    free: unsafe extern "C" fn(*mut T),
    (optional, reason): (bool, c_int),
    f: &str,
) -> c_int {
    // SAFETY: the caller's slot.
    let old = unsafe { *slot };
    if old.cast_const() == v {
        return 1;
    }
    let new = if optional && v.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: the caller's value.
        let new = unsafe { dup(v) };
        if new.is_null() {
            err::raise(ERR_LIB_TS, reason, f);
            return 0;
        }
        new
    };
    // SAFETY: the old value, or NULL.
    unsafe { free(old) };
    // SAFETY: the caller's slot.
    unsafe { *slot = new };
    1
}

/// `X509_EXTENSION_free` as a stack's free function.
unsafe extern "C" fn ext_free(p: *mut c_void) {
    // SAFETY: an element of a list of extensions.
    unsafe { X509_EXTENSION_free(p.cast()) };
}

/// An object's extensions' slot.
fn slot(p: &mut *mut Stack) -> *mut *mut stack_st_X509_EXTENSION {
    ptr::from_mut(p).cast()
}

ffi_export! {
    /// Sets the object's version: 1, or 0.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_REQ_set_version(a: *mut TS_REQ, version: c_long) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Req, _>(a) }) else { return 0 };
        // SAFETY: its version.
        unsafe { ASN1_INTEGER_set(r.version, version) }
    }
}

ffi_export! {
    /// The object's version, or 0 (-1 when it has none).
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_REQ_get_version(a: *const TS_REQ) -> c_long
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Req, _>(a) }) else { return 0 };
        // SAFETY: its version.
        unsafe { ASN1_INTEGER_get(r.version) }
    }
}

ffi_export! {
    /// Sets the object's `msg_imprint` to a copy of `v`: 1, or 0.
    ///
    /// # Safety
    /// `a` is a live object; `v` a live value.
    pub unsafe extern "C" fn TS_REQ_set_msg_imprint(a: *mut TS_REQ, v: *mut TS_MSG_IMPRINT) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Req, _>(a) }) else { return 0 };
        let slot = ptr::from_mut(&mut r.msg_imprint).cast();
        // SAFETY: its slot; the caller's value; the type's functions.
        unsafe { set_copy(slot, v.cast(), TS_MSG_IMPRINT_dup, TS_MSG_IMPRINT_free, (false, ERR_R_TS_LIB), "TS_REQ_set_msg_imprint") }
    }
}

ffi_export! {
    /// The object's `msg_imprint`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_REQ_get_msg_imprint(a: *mut TS_REQ) -> *mut TS_MSG_IMPRINT
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<Req, _>(a) }.map_or(ptr::null_mut(), |r| r.msg_imprint.cast())
    }
}

ffi_export! {
    /// Sets the object's `hash_algo` to a copy of `v`: 1, or 0.
    ///
    /// # Safety
    /// `a` is a live object; `v` a live value.
    pub unsafe extern "C" fn TS_MSG_IMPRINT_set_algo(a: *mut TS_MSG_IMPRINT, v: *mut X509_ALGOR) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<MsgImprint, _>(a) }) else { return 0 };
        let slot = ptr::from_mut(&mut r.hash_algo).cast();
        // SAFETY: its slot; the caller's value; the type's functions.
        unsafe { set_copy(slot, v.cast(), X509_ALGOR_dup, X509_ALGOR_free, (false, ERR_R_ASN1_LIB), "TS_MSG_IMPRINT_set_algo") }
    }
}

ffi_export! {
    /// The object's `hash_algo`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_MSG_IMPRINT_get_algo(a: *mut TS_MSG_IMPRINT) -> *mut X509_ALGOR
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<MsgImprint, _>(a) }.map_or(ptr::null_mut(), |r| r.hash_algo.cast())
    }
}

ffi_export! {
    /// Sets the imprint's hash to the `len` bytes at `d`: 1, or 0.
    ///
    /// # Safety
    /// `a` is a live imprint; `d` points to `len` bytes.
    pub unsafe extern "C" fn TS_MSG_IMPRINT_set_msg(a: *mut TS_MSG_IMPRINT, d: *mut c_uchar, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<MsgImprint, _>(a) }) else { return 0 };
        // SAFETY: its hash; the caller's bytes.
        unsafe { ASN1_OCTET_STRING_set(r.hashed_msg, d, len) }
    }
}

ffi_export! {
    /// The object's `hashed_msg`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_MSG_IMPRINT_get_msg(a: *mut TS_MSG_IMPRINT) -> *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<MsgImprint, _>(a) }.map_or(ptr::null_mut(), |r| r.hashed_msg.cast())
    }
}

ffi_export! {
    /// Sets the object's `policy_id` to a copy of `v`: 1, or 0.
    ///
    /// # Safety
    /// `a` is a live object; `v` a live value.
    pub unsafe extern "C" fn TS_REQ_set_policy_id(a: *mut TS_REQ, v: *const ASN1_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Req, _>(a) }) else { return 0 };
        let slot = ptr::from_mut(&mut r.policy_id).cast();
        // SAFETY: its slot; the caller's value; the type's functions.
        unsafe { set_copy(slot, v.cast(), OBJ_dup, ASN1_OBJECT_free, (false, ERR_R_OBJ_LIB), "TS_REQ_set_policy_id") }
    }
}

ffi_export! {
    /// The object's `policy_id`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_REQ_get_policy_id(a: *mut TS_REQ) -> *mut ASN1_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<Req, _>(a) }.map_or(ptr::null_mut(), |r| r.policy_id.cast())
    }
}

ffi_export! {
    /// Sets the object's `nonce` to a copy of `v`: 1, or 0.
    ///
    /// # Safety
    /// `a` is a live object; `v` a live value.
    pub unsafe extern "C" fn TS_REQ_set_nonce(a: *mut TS_REQ, v: *const ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Req, _>(a) }) else { return 0 };
        let slot = ptr::from_mut(&mut r.nonce).cast();
        // SAFETY: its slot; the caller's value; the type's functions.
        unsafe { set_copy(slot, v.cast(), ASN1_INTEGER_dup, ASN1_INTEGER_free, (false, ERR_R_ASN1_LIB), "TS_REQ_set_nonce") }
    }
}

ffi_export! {
    /// The object's `nonce`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_REQ_get_nonce(a: *const TS_REQ) -> *const ASN1_INTEGER
    where failure = ptr::null(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<Req, _>(a) }.map_or(ptr::null(), |r| r.nonce.cast_const().cast())
    }
}

ffi_export! {
    /// Sets the object's `cert_req` flag: 1.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_REQ_set_cert_req(a: *mut TS_REQ, on: c_int) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Req, _>(a) }) else { return 0 };
        r.cert_req = if on != 0 { 0xFF } else { 0 };
        1
    }
}

ffi_export! {
    /// The object's `cert_req` flag: 1 or 0.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_REQ_get_cert_req(a: *const TS_REQ) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<Req, _>(a) }.map_or(0, |r| c_int::from(r.cert_req != 0))
    }
}

ffi_export! {
    /// Sets the object's `status_info` to a copy of `v`: 1, or 0.
    ///
    /// # Safety
    /// `a` is a live object; `v` a live value.
    pub unsafe extern "C" fn TS_RESP_set_status_info(a: *mut TS_RESP, v: *mut TS_STATUS_INFO) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Resp, _>(a) }) else { return 0 };
        let slot = ptr::from_mut(&mut r.status_info).cast();
        // SAFETY: its slot; the caller's value; the type's functions.
        unsafe { set_copy(slot, v.cast(), TS_STATUS_INFO_dup, TS_STATUS_INFO_free, (false, ERR_R_TS_LIB), "TS_RESP_set_status_info") }
    }
}

ffi_export! {
    /// The object's `status_info`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_RESP_get_status_info(a: *mut TS_RESP) -> *mut TS_STATUS_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<Resp, _>(a) }.map_or(ptr::null_mut(), |r| r.status_info.cast())
    }
}

ffi_export! {
    /// Gives the response the token and its TSTInfo, freeing the old ones.
    ///
    /// # Safety
    /// `a` is a live response; `p7` and `tst_info` NULL or live objects the caller gives up.
    pub unsafe extern "C" fn TS_RESP_set_tst_info(a: *mut TS_RESP, p7: *mut PKCS7, tst_info: *mut TS_TST_INFO)
    where failure = (), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Resp, _>(a) }) else { return };
        // SAFETY: its token, or NULL.
        unsafe { PKCS7_free(r.token) };
        r.token = p7;
        // SAFETY: its TSTInfo, or NULL.
        unsafe { TS_TST_INFO_free(r.tst_info.cast()) };
        r.tst_info = tst_info.cast();
    }
}

ffi_export! {
    /// The object's `token`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_RESP_get_token(a: *mut TS_RESP) -> *mut PKCS7
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<Resp, _>(a) }.map_or(ptr::null_mut(), |r| r.token.cast())
    }
}

ffi_export! {
    /// The object's `tst_info`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_RESP_get_tst_info(a: *mut TS_RESP) -> *mut TS_TST_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<Resp, _>(a) }.map_or(ptr::null_mut(), |r| r.tst_info.cast())
    }
}

ffi_export! {
    /// Sets the object's version: 1, or 0.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_TST_INFO_set_version(a: *mut TS_TST_INFO, version: c_long) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<TstInfo, _>(a) }) else { return 0 };
        // SAFETY: its version.
        unsafe { ASN1_INTEGER_set(r.version, version) }
    }
}

ffi_export! {
    /// The object's version, or 0 (-1 when it has none).
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_TST_INFO_get_version(a: *const TS_TST_INFO) -> c_long
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<TstInfo, _>(a) }) else { return 0 };
        // SAFETY: its version.
        unsafe { ASN1_INTEGER_get(r.version) }
    }
}

ffi_export! {
    /// Sets the object's `policy_id` to a copy of `v`: 1, or 0.
    ///
    /// # Safety
    /// `a` is a live object; `v` a live value.
    pub unsafe extern "C" fn TS_TST_INFO_set_policy_id(a: *mut TS_TST_INFO, v: *mut ASN1_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<TstInfo, _>(a) }) else { return 0 };
        let slot = ptr::from_mut(&mut r.policy_id).cast();
        // SAFETY: its slot; the caller's value; the type's functions.
        unsafe { set_copy(slot, v.cast(), OBJ_dup, ASN1_OBJECT_free, (false, ERR_R_OBJ_LIB), "TS_TST_INFO_set_policy_id") }
    }
}

ffi_export! {
    /// The object's `policy_id`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_TST_INFO_get_policy_id(a: *mut TS_TST_INFO) -> *mut ASN1_OBJECT
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<TstInfo, _>(a) }.map_or(ptr::null_mut(), |r| r.policy_id.cast())
    }
}

ffi_export! {
    /// Sets the object's `msg_imprint` to a copy of `v`: 1, or 0.
    ///
    /// # Safety
    /// `a` is a live object; `v` a live value.
    pub unsafe extern "C" fn TS_TST_INFO_set_msg_imprint(a: *mut TS_TST_INFO, v: *mut TS_MSG_IMPRINT) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<TstInfo, _>(a) }) else { return 0 };
        let slot = ptr::from_mut(&mut r.msg_imprint).cast();
        // SAFETY: its slot; the caller's value; the type's functions.
        unsafe { set_copy(slot, v.cast(), TS_MSG_IMPRINT_dup, TS_MSG_IMPRINT_free, (false, ERR_R_TS_LIB), "TS_TST_INFO_set_msg_imprint") }
    }
}

ffi_export! {
    /// The object's `msg_imprint`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_TST_INFO_get_msg_imprint(a: *mut TS_TST_INFO) -> *mut TS_MSG_IMPRINT
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<TstInfo, _>(a) }.map_or(ptr::null_mut(), |r| r.msg_imprint.cast())
    }
}

ffi_export! {
    /// Sets the object's `serial` to a copy of `v`: 1, or 0.
    ///
    /// # Safety
    /// `a` is a live object; `v` a live value.
    pub unsafe extern "C" fn TS_TST_INFO_set_serial(a: *mut TS_TST_INFO, v: *const ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<TstInfo, _>(a) }) else { return 0 };
        let slot = ptr::from_mut(&mut r.serial).cast();
        // SAFETY: its slot; the caller's value; the type's functions.
        unsafe { set_copy(slot, v.cast(), ASN1_INTEGER_dup, ASN1_INTEGER_free, (false, ERR_R_ASN1_LIB), "TS_TST_INFO_set_serial") }
    }
}

ffi_export! {
    /// The object's `serial`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_TST_INFO_get_serial(a: *const TS_TST_INFO) -> *const ASN1_INTEGER
    where failure = ptr::null(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<TstInfo, _>(a) }.map_or(ptr::null(), |r| r.serial.cast_const().cast())
    }
}

ffi_export! {
    /// Sets the object's `time` to a copy of `v`: 1, or 0.
    ///
    /// # Safety
    /// `a` is a live object; `v` a live value.
    pub unsafe extern "C" fn TS_TST_INFO_set_time(a: *mut TS_TST_INFO, v: *const ASN1_GENERALIZEDTIME) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<TstInfo, _>(a) }) else { return 0 };
        let slot = ptr::from_mut(&mut r.time).cast();
        // SAFETY: its slot; the caller's value; the type's functions.
        unsafe { set_copy(slot, v.cast(), ASN1_STRING_dup, ASN1_GENERALIZEDTIME_free, (false, ERR_R_ASN1_LIB), "TS_TST_INFO_set_time") }
    }
}

ffi_export! {
    /// The object's `time`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_TST_INFO_get_time(a: *const TS_TST_INFO) -> *const ASN1_GENERALIZEDTIME
    where failure = ptr::null(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<TstInfo, _>(a) }.map_or(ptr::null(), |r| r.time.cast_const().cast())
    }
}

ffi_export! {
    /// Sets the object's `accuracy` to a copy of `v`: 1, or 0.
    ///
    /// # Safety
    /// `a` is a live object; `v` a live value.
    pub unsafe extern "C" fn TS_TST_INFO_set_accuracy(a: *mut TS_TST_INFO, v: *mut TS_ACCURACY) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<TstInfo, _>(a) }) else { return 0 };
        let slot = ptr::from_mut(&mut r.accuracy).cast();
        // SAFETY: its slot; the caller's value; the type's functions.
        unsafe { set_copy(slot, v.cast(), TS_ACCURACY_dup, TS_ACCURACY_free, (false, ERR_R_TS_LIB), "TS_TST_INFO_set_accuracy") }
    }
}

ffi_export! {
    /// The object's `accuracy`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_TST_INFO_get_accuracy(a: *mut TS_TST_INFO) -> *mut TS_ACCURACY
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<TstInfo, _>(a) }.map_or(ptr::null_mut(), |r| r.accuracy.cast())
    }
}

ffi_export! {
    /// Sets the object's `seconds` to a copy of `v`: 1, or 0.
    ///
    /// # Safety
    /// `a` is a live object; `v` a live value.
    pub unsafe extern "C" fn TS_ACCURACY_set_seconds(a: *mut TS_ACCURACY, v: *const ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Accuracy, _>(a) }) else { return 0 };
        let slot = ptr::from_mut(&mut r.seconds).cast();
        // SAFETY: its slot; the caller's value; the type's functions.
        unsafe { set_copy(slot, v.cast(), ASN1_INTEGER_dup, ASN1_INTEGER_free, (false, ERR_R_ASN1_LIB), "TS_ACCURACY_set_seconds") }
    }
}

ffi_export! {
    /// The object's `seconds`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_ACCURACY_get_seconds(a: *const TS_ACCURACY) -> *const ASN1_INTEGER
    where failure = ptr::null(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<Accuracy, _>(a) }.map_or(ptr::null(), |r| r.seconds.cast_const().cast())
    }
}

ffi_export! {
    /// Sets the object's `millis` to a copy of `v`: 1, or 0.
    ///
    /// # Safety
    /// `a` is a live object; `v` NULL or a live value.
    pub unsafe extern "C" fn TS_ACCURACY_set_millis(a: *mut TS_ACCURACY, v: *const ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Accuracy, _>(a) }) else { return 0 };
        let slot = ptr::from_mut(&mut r.millis).cast();
        // SAFETY: its slot; the caller's value; the type's functions.
        unsafe { set_copy(slot, v.cast(), ASN1_INTEGER_dup, ASN1_INTEGER_free, (true, ERR_R_ASN1_LIB), "TS_ACCURACY_set_millis") }
    }
}

ffi_export! {
    /// The object's `millis`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_ACCURACY_get_millis(a: *const TS_ACCURACY) -> *const ASN1_INTEGER
    where failure = ptr::null(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<Accuracy, _>(a) }.map_or(ptr::null(), |r| r.millis.cast_const().cast())
    }
}

ffi_export! {
    /// Sets the object's `micros` to a copy of `v`: 1, or 0.
    ///
    /// # Safety
    /// `a` is a live object; `v` NULL or a live value.
    pub unsafe extern "C" fn TS_ACCURACY_set_micros(a: *mut TS_ACCURACY, v: *const ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Accuracy, _>(a) }) else { return 0 };
        let slot = ptr::from_mut(&mut r.micros).cast();
        // SAFETY: its slot; the caller's value; the type's functions.
        unsafe { set_copy(slot, v.cast(), ASN1_INTEGER_dup, ASN1_INTEGER_free, (true, ERR_R_ASN1_LIB), "TS_ACCURACY_set_micros") }
    }
}

ffi_export! {
    /// The object's `micros`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_ACCURACY_get_micros(a: *const TS_ACCURACY) -> *const ASN1_INTEGER
    where failure = ptr::null(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<Accuracy, _>(a) }.map_or(ptr::null(), |r| r.micros.cast_const().cast())
    }
}

ffi_export! {
    /// Sets the object's `ordering` flag: 1.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_TST_INFO_set_ordering(a: *mut TS_TST_INFO, on: c_int) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<TstInfo, _>(a) }) else { return 0 };
        r.ordering = if on != 0 { 0xFF } else { 0 };
        1
    }
}

ffi_export! {
    /// The object's `ordering` flag: 1 or 0.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_TST_INFO_get_ordering(a: *const TS_TST_INFO) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<TstInfo, _>(a) }.map_or(0, |r| c_int::from(r.ordering != 0))
    }
}

ffi_export! {
    /// Sets the object's `nonce` to a copy of `v`: 1, or 0.
    ///
    /// # Safety
    /// `a` is a live object; `v` a live value.
    pub unsafe extern "C" fn TS_TST_INFO_set_nonce(a: *mut TS_TST_INFO, v: *const ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<TstInfo, _>(a) }) else { return 0 };
        let slot = ptr::from_mut(&mut r.nonce).cast();
        // SAFETY: its slot; the caller's value; the type's functions.
        unsafe { set_copy(slot, v.cast(), ASN1_INTEGER_dup, ASN1_INTEGER_free, (false, ERR_R_ASN1_LIB), "TS_TST_INFO_set_nonce") }
    }
}

ffi_export! {
    /// The object's `nonce`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_TST_INFO_get_nonce(a: *const TS_TST_INFO) -> *const ASN1_INTEGER
    where failure = ptr::null(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<TstInfo, _>(a) }.map_or(ptr::null(), |r| r.nonce.cast_const().cast())
    }
}

ffi_export! {
    /// Sets the object's `tsa` to a copy of `v`: 1, or 0.
    ///
    /// # Safety
    /// `a` is a live object; `v` a live value.
    pub unsafe extern "C" fn TS_TST_INFO_set_tsa(a: *mut TS_TST_INFO, v: *mut GENERAL_NAME) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<TstInfo, _>(a) }) else { return 0 };
        let slot = ptr::from_mut(&mut r.tsa).cast();
        // SAFETY: its slot; the caller's value; the type's functions.
        unsafe { set_copy(slot, v.cast(), GENERAL_NAME_dup, GENERAL_NAME_free, (false, ERR_R_ASN1_LIB), "TS_TST_INFO_set_tsa") }
    }
}

ffi_export! {
    /// The object's `tsa`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_TST_INFO_get_tsa(a: *mut TS_TST_INFO) -> *mut GENERAL_NAME
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<TstInfo, _>(a) }.map_or(ptr::null_mut(), |r| r.tsa.cast())
    }
}

ffi_export! {
    /// Sets the status info's status: 1, or 0.
    ///
    /// # Safety
    /// `a` is a live status info.
    pub unsafe extern "C" fn TS_STATUS_INFO_set_status(a: *mut TS_STATUS_INFO, i: c_int) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<StatusInfo, _>(a) }) else { return 0 };
        // SAFETY: its status.
        unsafe { ASN1_INTEGER_set(r.status, c_long::from(i)) }
    }
}

ffi_export! {
    /// The object's `status`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_STATUS_INFO_get0_status(a: *const TS_STATUS_INFO) -> *const ASN1_INTEGER
    where failure = ptr::null(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<StatusInfo, _>(a) }.map_or(ptr::null(), |r| r.status.cast_const().cast())
    }
}

ffi_export! {
    /// The object's `text`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_STATUS_INFO_get0_text(a: *const TS_STATUS_INFO) -> *const stack_st_ASN1_UTF8STRING
    where failure = ptr::null(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<StatusInfo, _>(a) }.map_or(ptr::null(), |r| r.text.cast_const().cast())
    }
}

ffi_export! {
    /// The object's `failure_info`, or NULL.
    ///
    /// # Safety
    /// `a` is a live object.
    pub unsafe extern "C" fn TS_STATUS_INFO_get0_failure_info(a: *const TS_STATUS_INFO) -> *const ASN1_BIT_STRING
    where failure = ptr::null(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<StatusInfo, _>(a) }.map_or(ptr::null(), |r| r.failure_info.cast_const().cast())
    }
}

ffi_export! {
    /// The request's extensions, or NULL.
    ///
    /// # Safety
    /// `a` is a live request.
    pub unsafe extern "C" fn TS_REQ_get_exts(a: *mut TS_REQ) -> *mut stack_st_X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<Req, _>(a) }.map_or(ptr::null_mut(), |r| r.extensions.cast())
    }
}

ffi_export! {
    /// Frees the request's extensions.
    ///
    /// # Safety
    /// `a` is NULL or a live request.
    pub unsafe extern "C" fn TS_REQ_ext_free(a: *mut TS_REQ)
    where failure = (), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Req, _>(a) }) else { return };
        // SAFETY: its extensions, or NULL.
        unsafe { OPENSSL_sk_pop_free(r.extensions, Some(ext_free)) };
        r.extensions = ptr::null_mut();
    }
}

ffi_export! {
    /// The number of the request's extensions.
    ///
    /// # Safety
    /// `a` is a live request.
    pub unsafe extern "C" fn TS_REQ_get_ext_count(a: *mut TS_REQ) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Req, _>(a) }) else { return 0 };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_count(r.extensions.cast()) }
    }
}

ffi_export! {
    /// The index of the request's next extension `nid` after `lastpos`, or -1.
    ///
    /// # Safety
    /// `a` is a live request.
    pub unsafe extern "C" fn TS_REQ_get_ext_by_NID(a: *mut TS_REQ, nid: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Req, _>(a) }) else { return -1 };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_by_NID(r.extensions.cast(), nid, lastpos) }
    }
}

ffi_export! {
    /// The index of the request's next extension `obj` after `lastpos`, or -1.
    ///
    /// # Safety
    /// `a` is a live request; `obj` a live object.
    pub unsafe extern "C" fn TS_REQ_get_ext_by_OBJ(a: *mut TS_REQ, obj: *const ASN1_OBJECT, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Req, _>(a) }) else { return -1 };
        // SAFETY: its extensions, or NULL; the caller's object.
        unsafe { X509v3_get_ext_by_OBJ(r.extensions.cast(), obj, lastpos) }
    }
}

ffi_export! {
    /// The index of the request's next extension of the criticality after `lastpos`, or -1.
    ///
    /// # Safety
    /// `a` is a live request.
    pub unsafe extern "C" fn TS_REQ_get_ext_by_critical(a: *mut TS_REQ, crit: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Req, _>(a) }) else { return -1 };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_by_critical(r.extensions.cast(), crit, lastpos) }
    }
}

ffi_export! {
    /// The request's extension `loc`, or NULL.
    ///
    /// # Safety
    /// `a` is a live request.
    pub unsafe extern "C" fn TS_REQ_get_ext(a: *mut TS_REQ, loc: c_int) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Req, _>(a) }) else { return ptr::null_mut() };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext(r.extensions.cast(), loc) }
    }
}

ffi_export! {
    /// Removes the request's extension `loc` and gives it to the caller, or NULL.
    ///
    /// # Safety
    /// `a` is a live request.
    pub unsafe extern "C" fn TS_REQ_delete_ext(a: *mut TS_REQ, loc: c_int) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Req, _>(a) }) else { return ptr::null_mut() };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_delete_ext(r.extensions.cast(), loc) }
    }
}

ffi_export! {
    /// Adds a copy of the extension at `loc` (-1 for the end): 1, or 0.
    ///
    /// # Safety
    /// `a` is a live request; `ex` a live extension.
    pub unsafe extern "C" fn TS_REQ_add_ext(a: *mut TS_REQ, ex: *mut X509_EXTENSION, loc: c_int) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Req, _>(a) }) else { return 0 };
        // SAFETY: its extensions' slot; the caller's extension.
        c_int::from(!unsafe { X509v3_add_ext(slot(&mut r.extensions).cast(), ex, loc) }.is_null())
    }
}

ffi_export! {
    /// The request's extension `nid`, decoded (see `X509V3_get_d2i`), or NULL.
    ///
    /// # Safety
    /// `a` is a live request; `crit` and `idx` NULL or room for an `int`.
    pub unsafe extern "C" fn TS_REQ_get_ext_d2i(a: *mut TS_REQ, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Req, _>(a) }) else { return ptr::null_mut() };
        // SAFETY: its extensions, or NULL; the caller's room.
        unsafe { X509V3_get_d2i(r.extensions.cast(), nid, crit, idx) }
    }
}

ffi_export! {
    /// The TSTInfo's extensions, or NULL.
    ///
    /// # Safety
    /// `a` is a live TSTInfo.
    pub unsafe extern "C" fn TS_TST_INFO_get_exts(a: *mut TS_TST_INFO) -> *mut stack_st_X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { of::<TstInfo, _>(a) }.map_or(ptr::null_mut(), |r| r.extensions.cast())
    }
}

ffi_export! {
    /// Frees the TSTInfo's extensions.
    ///
    /// # Safety
    /// `a` is NULL or a live TSTInfo.
    pub unsafe extern "C" fn TS_TST_INFO_ext_free(a: *mut TS_TST_INFO)
    where failure = (), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<TstInfo, _>(a) }) else { return };
        // SAFETY: its extensions, or NULL.
        unsafe { OPENSSL_sk_pop_free(r.extensions, Some(ext_free)) };
        r.extensions = ptr::null_mut();
    }
}

ffi_export! {
    /// The number of the TSTInfo's extensions.
    ///
    /// # Safety
    /// `a` is a live TSTInfo.
    pub unsafe extern "C" fn TS_TST_INFO_get_ext_count(a: *mut TS_TST_INFO) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<TstInfo, _>(a) }) else { return 0 };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_count(r.extensions.cast()) }
    }
}

ffi_export! {
    /// The index of the TSTInfo's next extension `nid` after `lastpos`, or -1.
    ///
    /// # Safety
    /// `a` is a live TSTInfo.
    pub unsafe extern "C" fn TS_TST_INFO_get_ext_by_NID(a: *mut TS_TST_INFO, nid: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<TstInfo, _>(a) }) else { return -1 };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_by_NID(r.extensions.cast(), nid, lastpos) }
    }
}

ffi_export! {
    /// The index of the TSTInfo's next extension `obj` after `lastpos`, or -1.
    ///
    /// # Safety
    /// `a` is a live TSTInfo; `obj` a live object.
    pub unsafe extern "C" fn TS_TST_INFO_get_ext_by_OBJ(a: *mut TS_TST_INFO, obj: *const ASN1_OBJECT, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<TstInfo, _>(a) }) else { return -1 };
        // SAFETY: its extensions, or NULL; the caller's object.
        unsafe { X509v3_get_ext_by_OBJ(r.extensions.cast(), obj, lastpos) }
    }
}

ffi_export! {
    /// The index of the TSTInfo's next extension of the criticality after `lastpos`, or -1.
    ///
    /// # Safety
    /// `a` is a live TSTInfo.
    pub unsafe extern "C" fn TS_TST_INFO_get_ext_by_critical(a: *mut TS_TST_INFO, crit: c_int, lastpos: c_int) -> c_int
    where failure = -1, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<TstInfo, _>(a) }) else { return -1 };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext_by_critical(r.extensions.cast(), crit, lastpos) }
    }
}

ffi_export! {
    /// The TSTInfo's extension `loc`, or NULL.
    ///
    /// # Safety
    /// `a` is a live TSTInfo.
    pub unsafe extern "C" fn TS_TST_INFO_get_ext(a: *mut TS_TST_INFO, loc: c_int) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<TstInfo, _>(a) }) else { return ptr::null_mut() };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_get_ext(r.extensions.cast(), loc) }
    }
}

ffi_export! {
    /// Removes the TSTInfo's extension `loc` and gives it to the caller, or NULL.
    ///
    /// # Safety
    /// `a` is a live TSTInfo.
    pub unsafe extern "C" fn TS_TST_INFO_delete_ext(a: *mut TS_TST_INFO, loc: c_int) -> *mut X509_EXTENSION
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<TstInfo, _>(a) }) else { return ptr::null_mut() };
        // SAFETY: its extensions, or NULL.
        unsafe { X509v3_delete_ext(r.extensions.cast(), loc) }
    }
}

ffi_export! {
    /// Adds a copy of the extension at `loc` (-1 for the end): 1, or 0.
    ///
    /// # Safety
    /// `a` is a live TSTInfo; `ex` a live extension.
    pub unsafe extern "C" fn TS_TST_INFO_add_ext(a: *mut TS_TST_INFO, ex: *mut X509_EXTENSION, loc: c_int) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<TstInfo, _>(a) }) else { return 0 };
        // SAFETY: its extensions' slot; the caller's extension.
        c_int::from(!unsafe { X509v3_add_ext(slot(&mut r.extensions).cast(), ex, loc) }.is_null())
    }
}

ffi_export! {
    /// The TSTInfo's extension `nid`, decoded (see `X509V3_get_d2i`), or NULL.
    ///
    /// # Safety
    /// `a` is a live TSTInfo; `crit` and `idx` NULL or room for an `int`.
    pub unsafe extern "C" fn TS_TST_INFO_get_ext_d2i(a: *mut TS_TST_INFO, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<TstInfo, _>(a) }) else { return ptr::null_mut() };
        // SAFETY: its extensions, or NULL; the caller's room.
        unsafe { X509V3_get_d2i(r.extensions.cast(), nid, crit, idx) }
    }
}
